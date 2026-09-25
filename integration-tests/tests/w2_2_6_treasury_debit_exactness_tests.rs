// =============================================================================
// STSH — W2 2-6: treasury debit exactness + bucket-level admission (PocketIC)
// =============================================================================
//
// DEFECT (SSA-S1S4-001, launch-gating HIGH). At pin a2a3b14, in
// `canisters/treasury/src/lib.rs`:
//   · `debit_subaccount` clamped with `saturating_sub` — a debit exceeding the
//     balance silently vanished in part;
//   · admission checked the proposal against the then-current balance ONLY, and
//     the durable reservation recorded neither amount nor bucket — so DIFFERENT
//     proposals on the same bucket could both pass the precheck against the SAME
//     funds and both reach the pool.
// The pool debits each full `total_debit` exactly and checked, so a concurrent
// over-admission settles as a treasury UNDER-debit: S4 diverges upward, a real
// undelivered-fee residual can read zero, and the history is not
// reconstructable afterwards. No funds move wrongly — the harm is accounting
// integrity, and it is launch-gating.
//
// FIX (packet chain V1-V5, SSA countersign GREEN ae75eafb…):
//   §2(1)  exact debit + durable per-bucket shortfall record, never a trap
//   §2(2)  bucket-level admission via per-reservation encumbrance, committed in
//          the same await-free segment that reads the balance
//   §2(4)  one ungated integrity query
//   §2(5a) legacy (pre-change) active records fail-CLOSE their bucket
//   §2(6a) rejection refuses on every ACTIVE reservation status
//   §2(7)  CHECKED admission arithmetic; saturate-with-flag counters
//   §2(9)  attempt classes, the `RetryingUnknown` marker, frozen retry args,
//          retain-on-every-pool-error for unknown-retries
//   §2(9g) terminal `RetiredNotExecuted` marker, checked FIRST, zero-mutation
//          replay, inactive everywhere, upgrade-stable
//
// WHY POCKETIC AND NOT NATIVE: native tests keep thread-locals alive
// in-process, so a native "upgrade" never re-runs the real `post_upgrade`
// across a Wasm boundary — a KNOWN BLIND SPOT of this repo. Acceptance 3, 17
// and 22 are cross-Wasm claims and are discharged here with REAL
// `pic.upgrade_canister` calls. The pure state-machine halves (exact debit,
// counter saturation, checked admission arithmetic, legacy-blocker scoping,
// migration decode) are covered natively in `canisters/treasury/src/lib.rs`.
//
// REFUSAL CODES under test (the stable operator contract, per the CTO ruling
// that `execute_withdrawal` keeps its `Result<(), String>` surface — "typed" is
// load-bearing on the INBOUND side, where pool errors are matched as Candid
// VARIANTS and never as text):
//   W226-LEGACY-BLOCKED  W226-ADMISSION-OVERFLOW  W226-BUCKET-ENCUMBERED
//   W226-RETIRED         W226-RETIRED-NO-RERESERVE
//
// PREREQUISITES: ./run_gate.sh builds the testing-feature Wasms and copies them
// to the _test names before running the suites.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first with ./run_gate.sh (it builds the testing-feature Wasms \
             and copies them to the _test names before running the suites).",
            pkg, path, e
        )
    })
}

fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn treasury_test_wasm() -> Vec<u8> { load_wasm(env!("TREASURY_TEST_WASM"), "treasury_test") }

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;
const TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

/// Treasury-local upgrade-scan cap (`MAX_UPGRADE_SCAN`), mirrored from the pool.
const MAX_UPGRADE_SCAN: u64 = 1_000;

/// `stage_reservation_for_test` status tags.
const ST_RESERVED: u8 = 0;
const ST_FAILED: u8 = 2;
const ST_OUTCOME_UNKNOWN: u8 = 3;
const ST_RETRYING_UNKNOWN: u8 = 4;
const ST_RETIRED_NOT_EXECUTED: u8 = 5;

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String,
    category_name: String,
    amount: u128,
    recipient: Principal,
    subaccount: Option<[u8; 32]>,
    lock_policy: LockPolicy,
    vesting_policy: Option<VestingPolicy>,
    created_at_genesis: bool,
    genesis_timestamp_ns: u64,
}

#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
}

fn all_to(recipient: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
    }
}

#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum FeeSource { ShieldFee, PrivateTransferFee, UnshieldFee, DexRevenue }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus { Pending, Executed, Rejected, Expired }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct WithdrawalProposal {
    id: u64,
    proposer: Principal,
    subaccount_name: String,
    recipient: Principal,
    amount: u128,
    description: String,
    created_at_ns: u64,
    execute_after_ns: u64,
    status: ProposalStatus,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum RejectProposalError {
    NotFound,
    NotPending { current: ProposalStatus },
    InFlight,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum TreasuryReserveBucket { Operations, Insurance, StakingRewards }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TreasuryDisbursementStatus {
    Pending,
    PendingValidation,
    PendingTransfer,
    Executed { block_index: Nat },
    TransportUnknown,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum DisburseOutcome { Executed { block_index: u64 }, NotExecuted }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcileDisburseResult {
    Recorded { block_index: Nat },
    Reverted,
    AlreadyExecuted { block_index: Nat },
}

/// Partial PoolError mirror. Candid decodes variants by NAME hash, so omitting
/// variants this suite never receives is safe.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    TransferFailed(String),
    IdempotencyKeyConflict,
    NotInitialised,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    DisbursementProposalIdRetired,
}

/// W2 2-6 §2(4): the new ungated integrity query's row type.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct BucketIntegrity {
    subaccount_name: String,
    shortfall_total: u128,
    shortfall_events: u64,
    shortfall_overflowed: bool,
    encumbered_total: u128,
    legacy_active_count: u64,
    retired_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal { Principal::anonymous() }

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 20_000_000_000_000u128);
    cid
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

struct Stack {
    /// Wired into the pool + treasury at install; the suite drives balances
    /// through the treasury's own accounting surface rather than the ledger.
    #[allow(dead_code)]
    token: Principal,
    pool: Principal,
    treasury: Principal,
    controller: Principal,
}

/// Token + pool(test) + treasury(test), wired together, with the treasury's
/// `operations` bucket and the pool's OPERATIONS_RESERVE both funded and the
/// pool holding real ledger balance so a transfer can genuinely be attempted.
fn deploy(pic: &PocketIc, controller: Principal, funded: u128) -> Stack {
    let token = create_canister(pic);
    let pool = create_canister(pic);
    let treasury = create_canister(pic);

    pic.install_canister(token, token_wasm(), candid::encode_one(all_to(pool)).unwrap(), None);
    pic.install_canister(
        pool,
        pool_test_wasm(),
        candid::encode_one(PoolInitArgs {
            token_canister: token,
            nullifier_canister: p(0x07),
            merkle_canister: p(0x08),
            treasury_canister: treasury,
            staking_canister: p(0x09),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .unwrap(),
        None,
    );
    pic.install_canister(
        treasury,
        treasury_test_wasm(),
        candid::encode_args((token, pool, controller)).unwrap(),
        None,
    );

    let s = Stack { token, pool, treasury, controller };
    seed_ops_reserve(pic, &s, funded);
    credit_bucket(pic, &s, funded);
    s
}

fn seed_ops_reserve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: () = decode(
        "inject_operations_reserve_for_test",
        pic.update_call(
            s.pool, s.controller, "inject_operations_reserve_for_test",
            candid::encode_one(amount).unwrap(),
        ),
    );
}

/// Credit the treasury's `operations` accounting bucket via the normal
/// pool→treasury fee-split path.
fn credit_bucket(pic: &PocketIc, s: &Stack, amount: u128) {
    let r: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(
            s.treasury, s.pool, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, amount, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );
    assert!(r.is_ok(), "receive_fee_split setup must succeed; got {:?}", r);
}

fn propose(pic: &PocketIc, s: &Stack, recipient: Principal, amount: u128, desc: &str) -> u64 {
    let pid: u64 = decode(
        "propose_withdrawal",
        pic.update_call(
            s.treasury, s.controller, "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(), recipient, amount, desc.to_string(),
            )).unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));
    pid
}

fn execute(pic: &PocketIc, s: &Stack, pid: u64) -> Result<(), String> {
    decode(
        "execute_withdrawal",
        pic.update_call(
            s.treasury, s.controller, "execute_withdrawal",
            candid::encode_one(pid).unwrap(),
        ),
    )
}

fn reject(pic: &PocketIc, s: &Stack, pid: u64) -> Result<(), RejectProposalError> {
    decode(
        "reject_proposal",
        pic.update_call(
            s.treasury, s.controller, "reject_proposal",
            candid::encode_one(pid).unwrap(),
        ),
    )
}

fn bucket_balance(pic: &PocketIc, s: &Stack, name: &str) -> u128 {
    let opt: Option<u128> = decode(
        "get_subaccount_balance",
        pic.query_call(
            s.treasury, anon(), "get_subaccount_balance",
            candid::encode_one(name.to_string()).unwrap(),
        ),
    );
    opt.unwrap_or(0)
}

fn integrity(pic: &PocketIc, s: &Stack, name: &str) -> BucketIntegrity {
    let rows: Vec<BucketIntegrity> = decode(
        "get_treasury_admission_integrity",
        pic.query_call(
            s.treasury, anon(), "get_treasury_admission_integrity",
            candid::encode_args(()).unwrap(),
        ),
    );
    rows.into_iter()
        .find(|r| r.subaccount_name == name)
        .unwrap_or_else(|| panic!("no integrity row for bucket '{name}'"))
}

fn proposal_status(pic: &PocketIc, s: &Stack, pid: u64) -> ProposalStatus {
    let proposals: Vec<WithdrawalProposal> = decode(
        "list_proposals",
        pic.query_call(s.treasury, anon(), "list_proposals", candid::encode_args(()).unwrap()),
    );
    proposals.into_iter().find(|p| p.id == pid)
        .unwrap_or_else(|| panic!("proposal {} not found", pid))
        .status
}

/// `(Reserved, Executed, Failed, OutcomeUnknown, RetryingUnknown, RetiredNotExecuted)`.
fn status_counts(pic: &PocketIc, s: &Stack) -> (u64, u64, u64, u64, u64, u64) {
    let bytes = pic
        .query_call(
            s.treasury, s.controller, "reservation_status_counts_v2_for_test",
            candid::encode_args(()).unwrap(),
        )
        .unwrap_or_else(|e| panic!("reservation_status_counts_v2_for_test rejected: {e:?}"));
    candid::decode_args(&bytes).unwrap_or_else(|e| panic!("decode failed: {e}"))
}

fn stage_reservation(
    pic: &PocketIc,
    s: &Stack,
    pid: u64,
    status_tag: u8,
    bucket: Option<&str>,
    encumbered: Option<u128>,
) {
    let _: () = decode(
        "stage_reservation_for_test",
        pic.update_call(
            s.treasury, s.controller, "stage_reservation_for_test",
            candid::encode_args((
                pid, status_tag, bucket.map(|b| b.to_string()), encumbered,
            )).unwrap(),
        ),
    );
}

fn inject_reserved(pic: &PocketIc, s: &Stack, ids: impl Iterator<Item = u64>) {
    for id in ids {
        let _: () = decode(
            "inject_inflight_proposal_for_test",
            pic.update_call(
                s.treasury, s.controller, "inject_inflight_proposal_for_test",
                candid::encode_one(id).unwrap(),
            ),
        );
    }
}

fn force_transport_unknown(pic: &PocketIc, s: &Stack, on: bool) {
    let _: () = decode(
        "force_treasury_transport_unknown_for_test",
        pic.update_call(
            s.pool, s.controller, "force_treasury_transport_unknown_for_test",
            candid::encode_one(on).unwrap(),
        ),
    );
}

fn reconcile(
    pic: &PocketIc,
    s: &Stack,
    pid: u64,
    outcome: DisburseOutcome,
) -> Result<ReconcileDisburseResult, PoolError> {
    decode(
        "reconcile_treasury_disburse",
        pic.update_call(
            s.pool, s.controller, "reconcile_treasury_disburse",
            candid::encode_args((pid, outcome)).unwrap(),
        ),
    )
}

/// Pool disbursement status tag: 0 none, 1 Pending(legacy), 2 Executed,
/// 3 TransportUnknown, 4 PendingValidation, 5 PendingTransfer.
fn disb_tag(pic: &PocketIc, s: &Stack, pid: u64) -> u8 {
    decode(
        "treasury_disbursement_status_tag_for_test",
        pic.query_call(
            s.pool, s.controller, "treasury_disbursement_status_tag_for_test",
            candid::encode_one(pid).unwrap(),
        ),
    )
}

fn upgrade_treasury(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.upgrade_canister(s.treasury, treasury_test_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

fn assert_code(err: &str, code: &str) {
    assert!(
        err.starts_with(&format!("{code}:")),
        "expected refusal code `{code}`; got: {err}",
    );
}

// =============================================================================
// ACCEPTANCE 1 — the SSA-S1S4-001 schedule is REFUSED
// =============================================================================
//
// Balance covers P or Q alone, not both. Deliberately staged rather than raced:
// the criterion says explicitly that no test may need the pool to actually run
// both to completion to prove refusal, and staging makes the refusal
// deterministic instead of dependent on message interleaving.

#[test]
fn w226_a1_second_proposal_on_the_same_bucket_is_refused_while_the_first_is_outstanding() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let q = propose(&pic, &s, recipient, 600 * STSH, "w226-a1-q");
    // P holds a live reservation encumbering 600 STSH of the same 1_000.
    stage_reservation(&pic, &s, 9_001, ST_RESERVED, Some("operations"), Some(600 * STSH));

    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 600 * STSH,
        "P's encumbrance must be visible before Q is attempted",
    );

    let err = execute(&pic, &s, q).expect_err(
        "Q must be REFUSED: the balance covers each of P and Q alone but not both, and \
         the pin's balance-only precheck would have admitted it",
    );
    assert_code(&err, "W226-BUCKET-ENCUMBERED");
    assert!(
        err.contains(&(600 * STSH).to_string()),
        "the refusal must state the encumbrance; got: {err}",
    );

    // Refused ⇒ nothing disbursed, nothing debited, proposal still Pending.
    assert_eq!(bucket_balance(&pic, &s, "operations"), 1_000 * STSH);
    assert_eq!(proposal_status(&pic, &s, q), ProposalStatus::Pending);
    assert_eq!(disb_tag(&pic, &s, q), 0, "Q must never have reached the pool");

    // After P settles Failed its encumbrance is released and Q admits.
    stage_reservation(&pic, &s, 9_001, ST_FAILED, Some("operations"), Some(600 * STSH));
    assert_eq!(integrity(&pic, &s, "operations").encumbered_total, 0);
    execute(&pic, &s, q).expect("once P is settled, Q must admit");
    assert_eq!(proposal_status(&pic, &s, q), ProposalStatus::Executed);
    assert_eq!(
        bucket_balance(&pic, &s, "operations"), 400 * STSH,
        "exactly one debit of total_debit (600 STSH + fee 0)",
    );
}

#[test]
fn w226_a1_concurrent_execution_debits_exactly_once_and_never_over_admits() {
    // The same schedule under REAL concurrency: two turns submitted before
    // either completes. Whichever refusal fires, the invariant is the same —
    // the bucket is never debited beyond what it held.
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let a = propose(&pic, &s, recipient, 600 * STSH, "w226-a1-conc-a");
    let b = propose(&pic, &s, recipient, 600 * STSH, "w226-a1-conc-b");

    let m1 = pic
        .submit_call(s.treasury, s.controller, "execute_withdrawal", candid::encode_one(a).unwrap())
        .expect("submit a");
    let m2 = pic
        .submit_call(s.treasury, s.controller, "execute_withdrawal", candid::encode_one(b).unwrap())
        .expect("submit b");
    let r1: Result<(), String> = decode("execute a", pic.await_call(m1));
    let r2: Result<(), String> = decode("execute b", pic.await_call(m2));

    assert_ne!(
        r1.is_ok(), r2.is_ok(),
        "EXACTLY one of two 600-STSH withdrawals against a 1_000-STSH bucket may \
         succeed; got {:?} / {:?}",
        r1, r2,
    );
    assert_eq!(
        bucket_balance(&pic, &s, "operations"), 400 * STSH,
        "the bucket must be debited exactly once — over-admission is the defect",
    );
    let row = integrity(&pic, &s, "operations");
    assert_eq!(
        row.shortfall_events, 0,
        "no under-debit may occur: a shortfall here would BE the SSA-S1S4-001 divergence",
    );
    assert_eq!(row.shortfall_total, 0);
}

// =============================================================================
// ACCEPTANCE 2 — the shortfall path is recorded (cross-Wasm half)
// =============================================================================

#[test]
fn w226_a2_debit_beyond_balance_records_a_durable_shortfall_and_never_traps() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 100);

    let _: () = decode(
        "debit_subaccount_for_test",
        pic.update_call(
            s.treasury, s.controller, "debit_subaccount_for_test",
            candid::encode_args(("operations".to_string(), 250u128)).unwrap(),
        ),
    );

    assert_eq!(bucket_balance(&pic, &s, "operations"), 0, "applied = min(balance, amount)");
    let row = integrity(&pic, &s, "operations");
    assert_eq!(row.shortfall_total, 150, "the missing 150 is RECORDED, not silently clamped");
    assert_eq!(row.shortfall_events, 1);
    assert!(!row.shortfall_overflowed, "an exact value must not carry the flag");
}

#[test]
fn w226_a10_shortfall_counters_saturate_with_a_truthful_flag() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 0);

    // Seed near the ceiling, then drive one more event past it.
    let _: () = decode(
        "seed_bucket_shortfall_for_test",
        pic.update_call(
            s.treasury, s.controller, "seed_bucket_shortfall_for_test",
            candid::encode_args(("operations".to_string(), u128::MAX - 5, 3u64, false)).unwrap(),
        ),
    );
    let _: () = decode(
        "debit_subaccount_for_test",
        pic.update_call(
            s.treasury, s.controller, "debit_subaccount_for_test",
            candid::encode_args(("operations".to_string(), 10u128)).unwrap(),
        ),
    );

    let row = integrity(&pic, &s, "operations");
    assert_eq!(row.shortfall_total, u128::MAX, "saturates — never wraps");
    assert_eq!(row.shortfall_events, 4);
    assert!(
        row.shortfall_overflowed,
        "the query must report the flag: with it set the value means 'at least this much'",
    );
}

// =============================================================================
// ACCEPTANCE 3 — encumbrance durability across a REAL cross-Wasm upgrade
// =============================================================================

#[test]
fn w226_a3_encumbrance_survives_a_real_upgrade_and_still_blocks_admission() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let q = propose(&pic, &s, recipient, 600 * STSH, "w226-a3-q");
    stage_reservation(&pic, &s, 9_101, ST_RESERVED, Some("operations"), Some(600 * STSH));

    // REAL cross-Wasm upgrade. Native durability does NOT discharge this.
    upgrade_treasury(&pic, &s).expect("the upgrade must succeed");

    // The sweep folds the Reserved record to OutcomeUnknown — which RETAINS the
    // encumbrance, because the pool may yet have executed.
    let c = status_counts(&pic, &s);
    assert_eq!((c.0, c.3), (0, 1), "the Reserved record was swept to OutcomeUnknown");
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 600 * STSH,
        "the ENCUMBRANCE must survive the upgrade intact, not just the record",
    );

    let err = execute(&pic, &s, q)
        .expect_err("the surviving encumbrance must still block a conflicting admission");
    assert_code(&err, "W226-BUCKET-ENCUMBERED");
}

// =============================================================================
// ACCEPTANCE 8 — legacy fail-closed blocker (SSA-W226-001)
// =============================================================================

#[test]
fn w226_a8_legacy_active_record_blocks_its_bucket_until_it_resolves() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    // A pre-W2-2-6 shaped record: ACTIVE, with NO recorded encumbrance. Its
    // bucket is derivable from the proposal map. It must never be read as zero
    // encumbrance — that reading is exactly what SSA-W226-001 rejected.
    let blocker = propose(&pic, &s, recipient, 10 * STSH, "w226-a8-legacy");
    stage_reservation(&pic, &s, blocker, ST_OUTCOME_UNKNOWN, None, None);

    let q = propose(&pic, &s, recipient, 10 * STSH, "w226-a8-q");
    let err = execute(&pic, &s, q).expect_err("the legacy active record must fail-close the bucket");
    assert_code(&err, "W226-LEGACY-BLOCKED");
    assert!(
        err.contains(&blocker.to_string()),
        "the refusal must name the blocking proposal id; got: {err}",
    );
    assert_eq!(
        disb_tag(&pic, &s, q), 0,
        "the refusal must land BEFORE the pool call — decode success alone does not \
         discharge this criterion",
    );
    assert!(integrity(&pic, &s, "operations").legacy_active_count >= 1);

    // Resolution through a defined transition unblocks the bucket.
    stage_reservation(&pic, &s, blocker, ST_FAILED, None, None);
    assert_eq!(integrity(&pic, &s, "operations").legacy_active_count, 0);
    execute(&pic, &s, q).expect("once the legacy record resolves, admission proceeds");
}

// =============================================================================
// ACCEPTANCE 9 — rejection fails closed on OutcomeUnknown (SSA-W226-002)
// =============================================================================

#[test]
fn w226_a9_rejection_is_refused_while_the_outcome_is_unknown() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a9");
    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(100 * STSH));

    assert_eq!(
        reject(&pic, &s, pid), Err(RejectProposalError::InFlight),
        "rejecting an OutcomeUnknown proposal would make it non-Pending, so \
         execute_withdrawal would refuse it and the retry that alone can resolve the \
         attempt becomes unreachable — the encumbrance would be PERMANENT",
    );
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 100 * STSH,
        "the encumbrance must remain: silently releasing on rejection is ruled OUT \
         (the pool may have executed, so release = over-admission)",
    );

    // The retry reaches a claiming outcome, and exactly ONE release path fires.
    execute(&pic, &s, pid).expect("the retry must reach the pool and claim");
    assert_eq!(proposal_status(&pic, &s, pid), ProposalStatus::Executed);
    assert_eq!(bucket_balance(&pic, &s, "operations"), 900 * STSH);
    assert_eq!(integrity(&pic, &s, "operations").encumbered_total, 0, "released exactly once");

    // And rejection of a genuinely unexecuted proposal still works as today.
    let other = propose(&pic, &s, recipient, 1 * STSH, "w226-a9-clean");
    assert_eq!(reject(&pic, &s, other), Ok(()));
}

// =============================================================================
// ACCEPTANCE 11/12/19 — exactly-once commit; OutcomeUnknown → AlreadyExecuted
// =============================================================================

#[test]
fn w226_a19_reconciled_executed_retry_commits_one_debit_and_one_release() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    // The pool's transfer executes but its callback is lost → TransportUnknown.
    force_transport_unknown(&pic, &s, true);
    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a19");
    assert!(execute(&pic, &s, pid).is_err(), "the lost callback must surface as an error");
    assert_eq!(disb_tag(&pic, &s, pid), 3, "pool: TransportUnknown");
    assert_eq!(
        bucket_balance(&pic, &s, "operations"), 1_000 * STSH,
        "no debit while the outcome is unknown",
    );

    // The treasury side is put in the state the modern flow reaches: an
    // OutcomeUnknown reservation holding its frozen encumbrance.
    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(100 * STSH));

    // The operator reconciles the pool as Executed.
    force_transport_unknown(&pic, &s, false);
    let r = reconcile(&pic, &s, pid, DisburseOutcome::Executed { block_index: 4_242 });
    assert!(matches!(r, Ok(ReconcileDisburseResult::Recorded { .. })), "got {:?}", r);

    // The next retry gets AlreadyExecuted → ONE debit + shortfall + status flip
    // + release, in the await-free success segment.
    execute(&pic, &s, pid).expect("the retry must observe AlreadyExecuted and commit");
    assert_eq!(proposal_status(&pic, &s, pid), ProposalStatus::Executed);
    assert_eq!(bucket_balance(&pic, &s, "operations"), 900 * STSH);
    let row = integrity(&pic, &s, "operations");
    assert_eq!(row.encumbered_total, 0, "released");
    assert_eq!(row.shortfall_events, 0, "an exact debit records no shortfall");

    // A replay must NOT debit again: claim_execution is the exactly-once witness.
    let replay = execute(&pic, &s, pid);
    assert!(replay.is_err(), "the proposal is no longer Pending; got {:?}", replay);
    assert_eq!(
        bucket_balance(&pic, &s, "operations"), 900 * STSH,
        "exactly ONE debit across the whole sequence",
    );
}

// =============================================================================
// ACCEPTANCE 13/15/9f — an unknown-retry RETAINS on every ambiguous pool error
// =============================================================================

#[test]
fn w226_a13_unknown_retry_retains_on_an_in_progress_pool_error() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    // Leave a PendingTransfer record at the pool: any retry now gets a generic
    // `TransferFailed("... already in progress ...")`, which does NOT prove
    // non-execution — and the builder is forbidden from string-matching it.
    force_transport_unknown(&pic, &s, true);
    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a13");
    let _ = execute(&pic, &s, pid);
    force_transport_unknown(&pic, &s, false);

    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(100 * STSH));

    let err = execute(&pic, &s, pid).expect_err("an ambiguous pool error must surface as an error");
    assert!(
        err.contains("unknown-retry") && err.contains("OutcomeUnknown"),
        "the message must say the reservation was RETAINED; got: {err}",
    );

    let c = status_counts(&pic, &s);
    assert_eq!(
        (c.2, c.3), (0, 1),
        "NO release: the record must be back at OutcomeUnknown, never Failed — none of \
         the pin's ambiguous pool errors prove non-execution",
    );
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 100 * STSH,
        "the encumbrance is retained through the ambiguous error",
    );
    // Conflicting admission is still refused while it is retained.
    let q = propose(&pic, &s, recipient, 950 * STSH, "w226-a13-q");
    assert_code(
        &execute(&pic, &s, q).expect_err("conflicting admission must still be refused"),
        "W226-BUCKET-ENCUMBERED",
    );
}

#[test]
fn w226_a15_legacy_blocker_survives_an_ambiguous_unknown_retry_error() {
    // §2(9f): a LEGACY unknown-retry (no frozen total) re-derives the fee, but
    // its classification is unchanged — an error retains, and the legacy
    // blocker never clears merely because a retry returned an error.
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    force_transport_unknown(&pic, &s, true);
    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a15");
    let _ = execute(&pic, &s, pid);
    force_transport_unknown(&pic, &s, false);

    // Legacy-shaped: active, NO recorded encumbrance.
    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, None, None);
    assert_eq!(integrity(&pic, &s, "operations").legacy_active_count, 1);

    let err = execute(&pic, &s, pid).expect_err("the ambiguous pool error must surface");
    assert!(err.contains("unknown-retry"), "got: {err}");

    let c = status_counts(&pic, &s);
    assert_eq!(c.3, 1, "restored to OutcomeUnknown, not Failed — NO release on an error");
    assert_eq!(c.2, 0, "specifically: never Failed");

    // ── PACKET TENSION, FLAGGED FOR CTO/SSA — §2(5a) vs §2(9f) ───────────────
    //
    // V2 §2(5a) says a retry "re-reserves and writes bucket + total_debit
    // (record stops being legacy)". V3 §2(9f) says that on an error "the LEGACY
    // BLOCKER REMAINS … it never clears merely because retry returned an
    // error". On THIS path both fire: admission succeeds (writing the bucket
    // and total, so the record stops being legacy) and THEN the pool errors.
    //
    // The implementation follows §2(5a). What the assertions below pin is the
    // SAFETY property both clauses exist to protect — the bucket's protection
    // is never reduced to zero by an errored retry — while recording honestly
    // that the MECHANISM changed from the coarse legacy block (whole bucket) to
    // a precise recorded encumbrance (exactly the disputed amount). That IS a
    // relaxation in the strictest reading of §2(9f), and it is the builder's
    // reading of §2(5a) that produced it. Not builder-clearable: filed in the
    // evidence packet for adjudication.
    let row = integrity(&pic, &s, "operations");
    assert_eq!(
        row.legacy_active_count + u64::from(row.encumbered_total > 0), 1,
        "the bucket must still be protected after the errored retry — by the legacy \
         blocker or by an equivalent recorded encumbrance, never by nothing",
    );
    assert_eq!(
        row.encumbered_total, 100 * STSH,
        "and the protected amount is the full disputed total_debit, not a reduced one",
    );
}

// =============================================================================
// ACCEPTANCE 14 — frozen retry arguments (§2(9c))
// =============================================================================

#[test]
fn w226_a14_unknown_retry_uses_the_frozen_total_debit_not_a_live_fee() {
    // The token's ledger fee is fixed at DEFAULT_FEE = 0 in this build with no
    // runtime update path, so the DRIFT is staged from the reservation side
    // instead: the frozen encumbrance carries a ledger fee of 7 while the live
    // `icrc1_fee` is 0. If the retry re-derived the fee, the pool would receive
    // expected_ledger_fee = 0; because the args are FROZEN it receives 7, which
    // the pool rejects against its own icrc1_fee — an observable proof that the
    // frozen value, not the live one, entered the arguments.
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let amount = 100 * STSH;
    let pid = propose(&pic, &s, recipient, amount, "w226-a14");
    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(amount + 7));

    let err = execute(&pic, &s, pid)
        .expect_err("the pool must reject the frozen fee against its own live fee");
    assert!(
        !err.contains("IdempotencyKeyConflict"),
        "no conflict may be MANUFACTURED by fee drift; got: {err}",
    );
    assert!(err.contains("unknown-retry"), "and the retry must be classified as such; got: {err}");

    let c = status_counts(&pic, &s);
    assert_eq!(
        (c.2, c.3), (0, 1),
        "NO Failed release occurs on fee drift — the record returns to OutcomeUnknown",
    );
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, amount + 7,
        "the frozen encumbrance is unchanged by the retry",
    );
}

// =============================================================================
// ACCEPTANCE 16 — FRESH-attempt handling is unchanged
// =============================================================================

#[test]
fn w226_a16_fresh_attempt_error_handling_is_unchanged() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    // A fresh attempt whose pool call fails definitively still settles Failed
    // and releases: a pool `Err` before any record existed is non-execution by
    // construction. Drain the pool-side reserve so the disburse is rejected.
    seed_ops_reserve(&pic, &s, 0);
    // Credit BEFORE proposing: `propose_withdrawal`'s advisory balance assert
    // traps otherwise, and this test is about the pool-side rejection.
    credit_bucket(&pic, &s, 5_000 * STSH);
    let pid = propose(&pic, &s, recipient, 5_000 * STSH, "w226-a16");
    let err = execute(&pic, &s, pid).expect_err("the pool must reject an underfunded disburse");
    assert!(!err.starts_with("W226-"), "this is an ordinary pool failure; got: {err}");

    let c = status_counts(&pic, &s);
    assert_eq!(
        (c.2, c.3, c.4, c.5), (1, 0, 0, 0),
        "a FRESH attempt settles Failed — not OutcomeUnknown, not RetryingUnknown",
    );
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 0,
        "and the encumbrance is released, so a retry can re-reserve",
    );
    assert_eq!(proposal_status(&pic, &s, pid), ProposalStatus::Pending);
}

// =============================================================================
// ACCEPTANCE 17 — RetryingUnknown is swept and counts toward the scan cap
// =============================================================================

#[test]
fn w226_a17_retrying_unknown_is_swept_like_reserved_across_a_real_upgrade() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);

    stage_reservation(&pic, &s, 9_201, ST_RETRYING_UNKNOWN, Some("operations"), Some(50 * STSH));
    assert_eq!(status_counts(&pic, &s).4, 1, "precondition: one RetryingUnknown record");

    upgrade_treasury(&pic, &s).expect("the upgrade must succeed");

    let c = status_counts(&pic, &s);
    assert_eq!(
        (c.3, c.4), (1, 0),
        "RetryingUnknown must be folded to OutcomeUnknown exactly as Reserved is — its \
         turn died with the old Wasm",
    );
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 50 * STSH,
        "the encumbrance rides the record through the sweep",
    );
}

#[test]
fn w226_a17_retrying_unknown_records_count_toward_the_upgrade_scan_cap() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);

    // One over the cap, entirely from in-flight records of BOTH qualifying
    // statuses: the cap must not be evadable by being in the newer state.
    inject_reserved(&pic, &s, 1..=(MAX_UPGRADE_SCAN / 2));
    for id in (MAX_UPGRADE_SCAN / 2 + 1)..=(MAX_UPGRADE_SCAN + 1) {
        stage_reservation(&pic, &s, id, ST_RETRYING_UNKNOWN, Some("operations"), Some(1));
    }
    let c = status_counts(&pic, &s);
    assert_eq!(c.0 + c.4, MAX_UPGRADE_SCAN + 1, "precondition: one in-flight record over the cap");

    let err = upgrade_treasury(&pic, &s).expect_err("over the cap the upgrade must trap");
    assert!(
        err.contains("INFLIGHT_RESERVATIONS") && err.contains("upgrade-scan cap"),
        "the trap must name the map and the cap; got: {err}",
    );

    let after = status_counts(&pic, &s);
    assert_eq!(after, c, "a trapped upgrade must write NOTHING — no partial migration");
}

// =============================================================================
// ACCEPTANCE 18/20/23 — terminal RetiredNotExecuted (SSA-W226-006)
// =============================================================================

#[test]
fn w226_a18_terminal_retired_releases_once_and_every_replay_is_inert() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    // Modern flow: TransportUnknown at the pool, OutcomeUnknown at the treasury.
    force_transport_unknown(&pic, &s, true);
    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a18");
    let _ = execute(&pic, &s, pid);
    force_transport_unknown(&pic, &s, false);
    assert_eq!(disb_tag(&pic, &s, pid), 3, "pool: TransportUnknown");
    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(100 * STSH));

    // The operator reconciles NotExecuted: the pool writes an immutable
    // tombstone, re-credits its reserve, and removes the record — the id is
    // permanently reserved.
    assert_eq!(
        reconcile(&pic, &s, pid, DisburseOutcome::NotExecuted),
        Ok(ReconcileDisburseResult::Reverted),
    );
    assert_eq!(disb_tag(&pic, &s, pid), 0, "the pool record is gone; the tombstone remains");

    // The retry receives the typed DisbursementProposalIdRetired — matched as a
    // VARIANT, never as text — and settles ONCE.
    let err = execute(&pic, &s, pid).expect_err("a retired id must never execute");
    assert_code(&err, "W226-RETIRED");

    let c_after_first = status_counts(&pic, &s);
    assert_eq!(c_after_first.5, 1, "exactly one RetiredNotExecuted record");
    let row = integrity(&pic, &s, "operations");
    assert_eq!(row.encumbered_total, 0, "the encumbrance is released exactly once");
    assert_eq!(row.retired_count, 1, "and the dead reservation is surfaced to operators");
    assert_eq!(row.legacy_active_count, 0, "never counted as legacy active");
    assert_eq!(bucket_balance(&pic, &s, "operations"), 1_000 * STSH, "nothing was debited");

    // A SECOND execution returns the SAME typed error with NO state mutation.
    let err2 = execute(&pic, &s, pid).expect_err("the replay must be refused");
    assert_eq!(err2, err, "deterministically the same error, every time");
    assert_eq!(status_counts(&pic, &s), c_after_first, "no state churn on replay");
    assert_eq!(
        integrity(&pic, &s, "operations"), row,
        "no fee query, no encumbrance change, no reservation mutation, no pool call",
    );

    // CONCURRENT later executions: same error, still no mutation.
    let m1 = pic
        .submit_call(s.treasury, s.controller, "execute_withdrawal", candid::encode_one(pid).unwrap())
        .expect("submit 1");
    let m2 = pic
        .submit_call(s.treasury, s.controller, "execute_withdrawal", candid::encode_one(pid).unwrap())
        .expect("submit 2");
    let c1: Result<(), String> = decode("concurrent 1", pic.await_call(m1));
    let c2: Result<(), String> = decode("concurrent 2", pic.await_call(m2));
    assert_eq!(c1.clone().unwrap_err(), err, "concurrent replay: same typed error");
    assert_eq!(c2.unwrap_err(), err, "concurrent replay: same typed error");
    assert_eq!(status_counts(&pic, &s), c_after_first, "concurrent replay is state-free too");

    // The proposal is still Pending and is now REJECTABLE — the expected
    // operator action. Paying the recipient needs a NEW proposal with a NEW id.
    assert_eq!(proposal_status(&pic, &s, pid), ProposalStatus::Pending);
    assert_eq!(reject(&pic, &s, pid), Ok(()), "a retired reservation must not block rejection");
    assert_eq!(proposal_status(&pic, &s, pid), ProposalStatus::Rejected);
}

#[test]
fn w226_a20_no_retired_return_can_correspond_to_an_executed_with_index_disbursement() {
    // The tombstone-writer invariant, demonstrated rather than only cited: an
    // Executed reconcile ALWAYS records a block index, and the pool's tombstone
    // gate returns AlreadyExecuted — never DisbursementProposalIdRetired — for
    // exactly that case. So a `Retired` return provably implies the pool
    // terminally decided NON-execution, which is what makes the one-variant
    // treasury release symmetric and correct.
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    force_transport_unknown(&pic, &s, true);
    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a20");
    let _ = execute(&pic, &s, pid);
    force_transport_unknown(&pic, &s, false);

    // Reconcile EXECUTED — the writer that always carries a block index.
    assert!(matches!(
        reconcile(&pic, &s, pid, DisburseOutcome::Executed { block_index: 77 }),
        Ok(ReconcileDisburseResult::Recorded { .. }),
    ));

    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(100 * STSH));
    execute(&pic, &s, pid).expect(
        "an Executed tombstone must yield AlreadyExecuted and CLAIM — if this ever \
         returned Retired instead, the treasury would release an encumbrance for a \
         disbursement that really happened",
    );
    assert_eq!(proposal_status(&pic, &s, pid), ProposalStatus::Executed);
    assert_eq!(
        status_counts(&pic, &s).5, 0,
        "no RetiredNotExecuted record may exist on an executed-with-index path",
    );
    assert_eq!(bucket_balance(&pic, &s, "operations"), 900 * STSH, "the debit is applied");
}

#[test]
fn w226_a23_a_retired_reservation_is_never_re_reservable() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let pid = propose(&pic, &s, recipient, 10 * STSH, "w226-a23");
    stage_reservation(&pic, &s, pid, ST_RETIRED_NOT_EXECUTED, Some("operations"), Some(10 * STSH));

    // The terminal gate is checked FIRST, so `execute_withdrawal` never even
    // reaches `reserve_withdrawal`.
    assert_code(&execute(&pic, &s, pid).expect_err("must refuse"), "W226-RETIRED");
    let row = integrity(&pic, &s, "operations");
    assert_eq!(row.retired_count, 1, "retired_count reflects it");
    assert_eq!(row.encumbered_total, 0, "with zero encumbrance");
    assert_eq!(status_counts(&pic, &s).5, 1, "and the record is unchanged");
}

// =============================================================================
// ACCEPTANCE 21 — legacy pool `Pending`: the RULED posture, not a fix
// =============================================================================

#[test]
fn w226_a21_legacy_pool_pending_is_a_permanent_fail_closed_ops_blocker() {
    // §2(9e′)(v): the pool's reconcile endpoint REFUSES a legacy ambiguous
    // `Pending` record, and NOTHING at this pin can settle it. The treasury
    // reservation stays encumbered indefinitely. Resolving it requires a
    // separately authorized manual/migration lane that this packet neither
    // builds nor promises — this test pins the posture so nobody later mistakes
    // it for an oversight.
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let pid = propose(&pic, &s, recipient, 100 * STSH, "w226-a21");
    let _: () = decode(
        "inject_treasury_disbursement_for_test",
        pic.update_call(
            s.pool, s.controller, "inject_treasury_disbursement_for_test",
            candid::encode_args((
                pid,
                TreasuryReserveBucket::Operations,
                recipient,
                100 * STSH,
                0u128,
                TreasuryDisbursementStatus::Pending,
            )).unwrap(),
        ),
    );
    assert_eq!(disb_tag(&pic, &s, pid), 1, "precondition: a legacy ambiguous Pending record");

    // The pool refuses to auto-reconcile it, in BOTH directions.
    for outcome in [DisburseOutcome::NotExecuted, DisburseOutcome::Executed { block_index: 1 }] {
        assert_eq!(
            reconcile(&pic, &s, pid, outcome),
            Err(PoolError::DisbursementNotReconcilable),
            "a legacy Pending record is never auto-reconciled — manual ledger inspection \
             (memo = proposal_id) is required",
        );
    }

    // Treasury side: the reservation is stuck and its encumbrance is retained.
    stage_reservation(&pic, &s, pid, ST_OUTCOME_UNKNOWN, Some("operations"), Some(100 * STSH));
    let err = execute(&pic, &s, pid).expect_err("the retry cannot resolve a legacy Pending record");
    assert!(err.contains("unknown-retry"), "and it RETAINS; got: {err}");
    assert_eq!(
        integrity(&pic, &s, "operations").encumbered_total, 100 * STSH,
        "PERMANENT FAIL-CLOSED OPS BLOCKER: the encumbrance is retained indefinitely",
    );
    assert_eq!(
        reject(&pic, &s, pid), Err(RejectProposalError::InFlight),
        "and the proposal cannot be rejected out from under it",
    );
}

// =============================================================================
// ACCEPTANCE 22 — RetiredNotExecuted survives a REAL cross-Wasm upgrade
// =============================================================================

#[test]
fn w226_a22_retired_marker_survives_a_real_upgrade_inactive_and_uncounted() {
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);
    let recipient = p(0x41);

    let pid = propose(&pic, &s, recipient, 10 * STSH, "w226-a22");
    stage_reservation(&pic, &s, pid, ST_RETIRED_NOT_EXECUTED, Some("operations"), Some(10 * STSH));

    upgrade_treasury(&pic, &s).expect("the upgrade must succeed");

    assert_eq!(
        status_counts(&pic, &s).5, 1,
        "the marker survives cross-Wasm AS RetiredNotExecuted — it must NOT be swept to \
         OutcomeUnknown, which would resurrect a dead reservation",
    );
    let row = integrity(&pic, &s, "operations");
    assert_eq!(row.retired_count, 1);
    assert_eq!(row.encumbered_total, 0, "still inactive after the upgrade");

    // Post-upgrade the terminal error is still returned, with no mutation.
    let before = status_counts(&pic, &s);
    assert_code(&execute(&pic, &s, pid).expect_err("still terminal"), "W226-RETIRED");
    assert_eq!(status_counts(&pic, &s), before, "no mutation post-upgrade either");
}

#[test]
fn w226_a22_retired_records_do_not_count_toward_the_upgrade_scan_cap() {
    // A canister carrying more dead reservations than the cap must still be
    // upgradeable: they are inert history, and counting them would let old
    // records brick the canister.
    let pic = PocketIc::new();
    let s = deploy(&pic, p(0xA6), 1_000 * STSH);

    for id in 1..=(MAX_UPGRADE_SCAN + 50) {
        stage_reservation(&pic, &s, id, ST_RETIRED_NOT_EXECUTED, Some("operations"), Some(1));
    }
    assert_eq!(status_counts(&pic, &s).5, MAX_UPGRADE_SCAN + 50);

    upgrade_treasury(&pic, &s)
        .expect("RetiredNotExecuted records are inactive and must not count toward the cap");
    assert_eq!(
        status_counts(&pic, &s).5, MAX_UPGRADE_SCAN + 50,
        "and all of them survive the upgrade unchanged",
    );
}

// =============================================================================
// ACCEPTANCE 7 (support) — the staging probes cannot reach production
// =============================================================================
//
// The whole W2 2-6 suite leans on `stage_reservation_for_test`,
// `debit_subaccount_for_test` and `seed_bucket_shortfall_for_test`, all of
// which WRITE state. A leak into a deployable Wasm would hand any controller a
// way to forge reservations and shortfall counters — strictly worse than the
// read-only probes the existing isolation test covers. Proved by scanning the
// shipped binary, not asserted.

const WRITE_PROBES: [&[u8]; 3] = [
    b"stage_reservation_for_test",
    b"debit_subaccount_for_test",
    b"seed_bucket_shortfall_for_test",
];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn w226_state_writing_probes_are_absent_from_the_production_treasury_wasm() {
    let production = load_wasm(env!("TREASURY_WASM"), "treasury");
    let testing = treasury_test_wasm();
    for probe in WRITE_PROBES {
        let name = String::from_utf8_lossy(probe).to_string();
        assert!(
            !contains(&production, probe),
            "treasury: PRODUCTION Wasm contains the STATE-WRITING test export `{name}`. \
             The `testing` feature has leaked into a deployable artifact — do NOT ship \
             this build.",
        );
        // The positive control: without it the scan above proves nothing.
        assert!(
            contains(&testing, probe),
            "treasury_test: the testing Wasm is MISSING `{name}`, so the production scan \
             above is silently void.",
        );
    }
}
