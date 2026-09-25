// =============================================================================
// RB-SWARM-A2 — Treasury double-disburse witness-erasure guard
// =============================================================================
//
// Covers the compound finding L7-C2 (= L8-F2 + L3-2) from
// SSA_ADVERSARIAL_SWARM_ADJUDICATION_2026-07-31, built to the CORRECTED
// remediation model (tombstone / evidence preservation), not the withdrawn
// "Executed→Rejected guard closes it" framing.
//
// The corrected failure sequence the compound test models:
//   1. the pool's ledger transfer executes but its callback is lost
//   2. the pool records TransportUnknown (reserve debited, outcome unknown)
//   3. the treasury sees the error and leaves its proposal **Pending**
//      — note: Pending, NOT Executed. There is normally NO treasury `Executed`
//        witness anywhere in this sequence, which is exactly why the L3-2
//        status guard does not close the compound on its own.
//   4. a false `NotExecuted` reconcile re-credits the reserve and DELETES the
//      pool's disbursement record
//   5. `reject_proposal` legally moves the treasury proposal Pending → Rejected
//
// Before the fix, step 4+5 left the protocol with no internal record that a real
// ledger transfer had ever been attempted for that proposal id — and the id was
// reusable, so a second attempt would mint a FRESH created_at_time that the
// token's dedup could not catch. (The external ledger still held the payment;
// what was erased was the protocol's own attribution state.)
//
// Tests:
//   a2_compound  — the full corrected sequence: tombstone exists, is immutable,
//                  and the proposal id is permanently reserved.
//   a2_l3_2      — SEPARATE standalone guard test: reject_proposal on an
//                  Executed proposal is refused, status unchanged.
//   a2_inflight  — reject_proposal is refused while INFLIGHT_PROPOSALS is held.
//   a2_regression— reject_proposal on a genuinely Pending proposal still works.
//   a2_insert_once — a second reconciliation never overwrites the tombstone.
//
// Wasms: POOL_TEST_WASM (needs force_treasury_transport_unknown_for_test and
// inject_operations_reserve_for_test) and TREASURY_TEST_WASM (needs
// inject_inflight_proposal_for_test).

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

fn token_wasm() -> Vec<u8> {
    load_wasm(env!("TOKEN_WASM"), "stsh_token")
}
fn pool_test_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test")
}
fn treasury_test_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_TEST_WASM"), "treasury_test")
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch
const STSH: u128 = 100_000_000;
const TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy {
    cliff_end_ns: u64,
    vesting_end_ns: u64,
}

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
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

/// Partial PoolError mirror. Candid decodes variants by NAME hash, so omitting
/// variants this suite never receives is safe; every variant it CAN receive is
/// present.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    TransferFailed(String),
    EscrowUnderfunded { required: u128, available: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    IdempotencyKeyConflict,
    NotInitialised,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    /// RB-SWARM-A2: the id is permanently reserved by a tombstone.
    DisbursementProposalIdRetired,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum TreasuryReserveBucket {
    Operations,
    Insurance,
    StakingRewards,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TreasuryDisburseArgs {
    proposal_id: u64,
    bucket: TreasuryReserveBucket,
    recipient: Principal,
    recipient_subaccount: Option<[u8; 32]>,
    amount: u128,
    expected_ledger_fee: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TreasuryDisburseResult {
    Executed { block_index: Nat },
    AlreadyExecuted { block_index: Nat },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum DisburseOutcome {
    Executed { block_index: u64 },
    NotExecuted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcileDisburseResult {
    Recorded { block_index: Nat },
    Reverted,
    AlreadyExecuted { block_index: Nat },
}

// ── RB-SWARM-A2 tombstone mirrors ────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TreasuryDisbursementStatus {
    Pending,
    PendingValidation,
    PendingTransfer,
    Executed { block_index: Nat },
    TransportUnknown,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum ReconciliationDecision {
    Executed,
    NotExecuted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TreasuryReconciliationTombstone {
    proposal_id: u64,
    bucket: TreasuryReserveBucket,
    recipient: Principal,
    recipient_subaccount: Option<[u8; 32]>,
    amount: u128,
    expected_ledger_fee: u128,
    memo: Vec<u8>,
    ledger_created_at_time_ns: Option<u64>,
    pre_reconcile_status: TreasuryDisbursementStatus,
    decision: ReconciliationDecision,
    asserted_block_index: Option<u64>,
    reconciler: Principal,
    reconciled_at_ns: u64,
}

// ── Treasury mirrors ─────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum FeeSource {
    ShieldFee,
    PrivateTransferFee,
    UnshieldFee,
    DexRevenue,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus {
    Pending,
    Executed,
    Rejected,
    Expired,
}

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

/// RB-SWARM-A2 (L3-2): typed reject_proposal failures.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum RejectProposalError {
    NotFound,
    NotPending { current: ProposalStatus },
    InFlight,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal {
    Principal::anonymous()
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn to_u128(n: Nat) -> u128 {
    n.0.to_string().parse::<u128>().unwrap_or(0)
}

fn token_balance(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    to_u128(decode(
        "icrc1_balance_of",
        pic.query_call(
            token,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap(),
        ),
    ))
}

fn treasury_bucket(pic: &PocketIc, treasury: Principal, name: &str) -> u128 {
    let opt: Option<u128> = decode(
        "get_subaccount_balance",
        pic.query_call(
            treasury,
            anon(),
            "get_subaccount_balance",
            candid::encode_one(name.to_string()).unwrap(),
        ),
    );
    opt.unwrap_or(0)
}

fn get_proposal(pic: &PocketIc, treasury: Principal, id: u64) -> WithdrawalProposal {
    let proposals: Vec<WithdrawalProposal> = decode(
        "list_proposals",
        pic.query_call(treasury, anon(), "list_proposals", candid::encode_args(()).unwrap()),
    );
    proposals
        .into_iter()
        .find(|p| p.id == id)
        .unwrap_or_else(|| panic!("proposal {} not found", id))
}

/// Pool status tag: 0 = none, 1 = Pending, 2 = Executed, 3 = TransportUnknown.
fn disb_status_tag(pic: &PocketIc, pool: Principal, controller: Principal, proposal_id: u64) -> u8 {
    decode(
        "treasury_disbursement_status_tag_for_test",
        pic.query_call(
            pool,
            controller,
            "treasury_disbursement_status_tag_for_test",
            candid::encode_one(proposal_id).unwrap(),
        ),
    )
}

fn tombstone(
    pic: &PocketIc,
    pool: Principal,
    controller: Principal,
    proposal_id: u64,
) -> Option<TreasuryReconciliationTombstone> {
    decode(
        "get_treasury_reconciliation_tombstone",
        pic.query_call(
            pool,
            controller,
            "get_treasury_reconciliation_tombstone",
            candid::encode_one(proposal_id).unwrap(),
        ),
    )
}

fn force_transport_unknown(pic: &PocketIc, pool: Principal, controller: Principal, on: bool) {
    let _: () = decode(
        "force_treasury_transport_unknown_for_test",
        pic.update_call(
            pool,
            controller,
            "force_treasury_transport_unknown_for_test",
            candid::encode_one(on).unwrap(),
        ),
    );
}

fn seed_ops_reserve(pic: &PocketIc, pool: Principal, controller: Principal, amount: u128) {
    let _: () = decode(
        "inject_operations_reserve_for_test",
        pic.update_call(
            pool,
            controller,
            "inject_operations_reserve_for_test",
            candid::encode_one(amount).unwrap(),
        ),
    );
}

fn reconcile(
    pic: &PocketIc,
    pool: Principal,
    controller: Principal,
    proposal_id: u64,
    outcome: DisburseOutcome,
) -> Result<ReconcileDisburseResult, PoolError> {
    decode(
        "reconcile_treasury_disburse",
        pic.update_call(
            pool,
            controller,
            "reconcile_treasury_disburse",
            candid::encode_args((proposal_id, outcome)).unwrap(),
        ),
    )
}

fn reject_proposal(
    pic: &PocketIc,
    treasury: Principal,
    controller: Principal,
    proposal_id: u64,
) -> Result<(), RejectProposalError> {
    decode(
        "reject_proposal",
        pic.update_call(
            treasury,
            controller,
            "reject_proposal",
            candid::encode_one(proposal_id).unwrap(),
        ),
    )
}

/// A full token + pool(test) + treasury(test) stack wired to each other, with the
/// treasury's "operations" bucket and the pool's OPERATIONS_RESERVE both funded,
/// and the pool holding real ledger balance so a transfer can genuinely be
/// attempted. Deliberately avoids the deposit/fee-params route: this suite is
/// about reconciliation, and seeding directly keeps it independent of fee policy.
struct Stack {
    token: Principal,
    pool: Principal,
    treasury: Principal,
    controller: Principal,
}

fn deploy(pic: &PocketIc, controller: Principal) -> Stack {
    let token = create_canister(pic);
    let pool = create_canister(pic);
    let treasury = create_canister(pic);

    // All supply to the POOL: it custodies escrow and performs the real transfer.
    install(pic, token, token_wasm(), &all_to(pool));
    install(
        pic,
        pool,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token,
            nullifier_canister: p(0x07),
            merkle_canister: p(0x08),
            treasury_canister: treasury,
            staking_canister: p(0x09),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.install_canister(
        treasury,
        treasury_test_wasm(),
        candid::encode_args((token, pool, controller)).unwrap(),
        None,
    );

    // Pool-side reserve to debit.
    seed_ops_reserve(pic, pool, controller, 500 * STSH);
    // Treasury-side accounting bucket — credited by the pool via receive_fee_split.
    let credited: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(
            treasury,
            pool,
            "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, 500 * STSH, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );
    assert!(credited.is_ok(), "receive_fee_split setup must succeed; got {:?}", credited);

    Stack { token, pool, treasury, controller }
}

fn propose(pic: &PocketIc, s: &Stack, recipient: Principal, amount: u128, desc: &str) -> u64 {
    let pid: u64 = decode(
        "propose_withdrawal",
        pic.update_call(
            s.treasury,
            s.controller,
            "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(),
                recipient,
                amount,
                desc.to_string(),
            ))
            .unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));
    pid
}

fn execute_withdrawal(pic: &PocketIc, s: &Stack, pid: u64) -> Result<(), String> {
    decode(
        "execute_withdrawal",
        pic.update_call(
            s.treasury,
            s.controller,
            "execute_withdrawal",
            candid::encode_one(pid).unwrap(),
        ),
    )
}

// =============================================================================
// PRIMARY — the full compound, corrected: TransportUnknown + treasury Pending
// =============================================================================
//
// This is the test the brief requires: it starts from TransportUnknown with the
// treasury proposal **Pending**, NOT from an already-Executed proposal.
#[test]
fn test_a2_compound_not_executed_reconcile_leaves_immutable_tombstone() {
    let pic = PocketIc::new();
    let controller = p(0xA2);
    let recipient = p(0x41);
    let s = deploy(&pic, controller);

    let amount = 5 * STSH;

    // ── (1)+(2) the transfer executes but the callback is lost → TransportUnknown
    force_transport_unknown(&pic, s.pool, controller, true);
    let pid = propose(&pic, &s, recipient, amount, "a2-compound");
    let exec = execute_withdrawal(&pic, &s, pid);

    // ── (3) the treasury sees the error and leaves the proposal PENDING ──────
    assert!(exec.is_err(), "transport-unknown disburse must surface as an error; got {:?}", exec);
    assert_eq!(
        get_proposal(&pic, s.treasury, pid).status,
        ProposalStatus::Pending,
        "PRECONDITION OF THE CORRECTED MODEL: the treasury proposal is Pending, \
         not Executed — there is no treasury Executed witness in this sequence"
    );
    assert_eq!(
        disb_status_tag(&pic, s.pool, controller, pid),
        3,
        "pool record must be TransportUnknown (debited, outcome unknown)"
    );
    assert!(
        tombstone(&pic, s.pool, controller, pid).is_none(),
        "no tombstone before any reconciliation"
    );

    // ── (4) the false NotExecuted assertion: re-credit + delete the record ───
    let r = reconcile(&pic, s.pool, controller, pid, DisburseOutcome::NotExecuted);
    assert_eq!(r, Ok(ReconcileDisburseResult::Reverted), "reconcile must revert; got {:?}", r);
    assert_eq!(
        disb_status_tag(&pic, s.pool, controller, pid),
        0,
        "the disbursement record itself is still removed (accounting is reverted)"
    );

    // ── THE FIX: an immutable witness survives the erasure ──────────────────
    let t = tombstone(&pic, s.pool, controller, pid)
        .expect("PRIMARY: a NotExecuted reconcile of an ambiguous disbursement MUST \
                 leave an immutable tombstone");
    assert_eq!(t.proposal_id, pid);
    assert_eq!(t.bucket, TreasuryReserveBucket::Operations);
    assert_eq!(t.recipient, recipient, "tombstone proves who the payment was for");
    assert_eq!(t.recipient_subaccount, None);
    assert_eq!(t.amount, amount, "tombstone proves how much");
    assert_eq!(t.expected_ledger_fee, DEFAULT_FEE);
    assert_eq!(
        t.memo,
        pid.to_be_bytes().to_vec(),
        "EXACT canonical memo bytes — half of the ledger dedup identity"
    );
    assert!(
        t.ledger_created_at_time_ns.is_some(),
        "the ORIGINAL frozen ledger created_at_time must be preserved — it is the \
         other half of the ledger identity an auditor needs to settle the ambiguity"
    );
    assert_eq!(
        t.pre_reconcile_status,
        TreasuryDisbursementStatus::TransportUnknown,
        "tombstone records the status at the instant of reconciliation"
    );
    assert_eq!(t.decision, ReconciliationDecision::NotExecuted);
    assert_eq!(
        t.asserted_block_index, None,
        "NotExecuted asserts no block exists"
    );
    assert_eq!(t.reconciler, controller, "tombstone names the actor who asserted");
    assert!(t.reconciled_at_ns > 0, "tombstone records when");

    // ── (5) reject_proposal legally moves the treasury proposal Pending→Rejected
    // This is ALLOWED and still allowed after the fix — the compound is not closed
    // by preventing this transition (the proposal was never Executed), it is closed
    // by the pool-side tombstone that this transition can no longer erase.
    let rej = reject_proposal(&pic, s.treasury, controller, pid);
    assert_eq!(rej, Ok(()), "Pending → Rejected is a legal transition; got {:?}", rej);
    assert_eq!(get_proposal(&pic, s.treasury, pid).status, ProposalStatus::Rejected);

    // ── THE WITNESS SURVIVES the privileged path that erased everything else ──
    let after = tombstone(&pic, s.pool, controller, pid)
        .expect("the tombstone must survive reject_proposal — an audit witness the \
                 auditee can erase is not a witness");
    assert_eq!(after, t, "tombstone is byte-identical after the full compound sequence");

    // ── THE ID IS PERMANENTLY RESERVED ───────────────────────────────────────
    // The exploit's second half was re-using the proposal id for a second payment
    // attempt, which the ledger's own dedup could not stop because the retry would
    // carry a FRESH created_at_time. Re-disbursement must now be impossible.
    let recipient_balance_before = token_balance(&pic, s.token, recipient);
    force_transport_unknown(&pic, s.pool, controller, false);
    let reuse: Result<TreasuryDisburseResult, PoolError> = decode(
        "treasury_disburse reuse",
        pic.update_call(
            s.pool,
            s.treasury,
            "treasury_disburse",
            candid::encode_one(TreasuryDisburseArgs {
                proposal_id: pid,
                bucket: TreasuryReserveBucket::Operations,
                recipient,
                recipient_subaccount: None,
                amount,
                expected_ledger_fee: DEFAULT_FEE,
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        reuse,
        Err(PoolError::DisbursementProposalIdRetired),
        "a tombstoned proposal id must be permanently reserved — never a fresh \
         ledger identity; got {:?}",
        reuse
    );
    assert_eq!(
        token_balance(&pic, s.token, recipient),
        recipient_balance_before,
        "the reuse attempt must not move any funds"
    );
    assert_eq!(
        disb_status_tag(&pic, s.pool, controller, pid),
        0,
        "the rejected reuse must not create a new disbursement record (which would \
         carry a fresh ledger identity)"
    );
}

// =============================================================================
// SECONDARY / standalone L3-2 — reject_proposal on an Executed proposal
// =============================================================================
//
// A SEPARATE test, as the brief requires. This is the standalone bug: before the
// fix `reject_proposal` called `update_proposal_status` unconditionally, so an
// Executed proposal — the record that real funds moved — could be overwritten to
// Rejected. Note this does NOT close the compound above (no Executed witness
// exists there); it is its own defect.
#[test]
fn test_a2_l3_2_reject_proposal_refuses_executed_proposal() {
    let pic = PocketIc::new();
    let controller = p(0xA3);
    let recipient = p(0x42);
    let s = deploy(&pic, controller);

    // A genuinely successful disbursement → proposal Executed.
    let pid = propose(&pic, &s, recipient, 5 * STSH, "a2-l3-2");
    let exec = execute_withdrawal(&pic, &s, pid);
    assert!(exec.is_ok(), "happy-path execute must succeed; got {:?}", exec);
    assert_eq!(get_proposal(&pic, s.treasury, pid).status, ProposalStatus::Executed);

    let rej = reject_proposal(&pic, s.treasury, controller, pid);
    assert_eq!(
        rej,
        Err(RejectProposalError::NotPending { current: ProposalStatus::Executed }),
        "rejecting an Executed proposal must be refused with a clear typed error; got {:?}",
        rej
    );
    assert_eq!(
        get_proposal(&pic, s.treasury, pid).status,
        ProposalStatus::Executed,
        "status must be UNCHANGED after the refused rejection"
    );
}

// =============================================================================
// L3-2 — reject_proposal is refused while INFLIGHT_PROPOSALS is occupied
// =============================================================================
#[test]
fn test_a2_l3_2_reject_proposal_refuses_while_inflight() {
    let pic = PocketIc::new();
    let controller = p(0xA4);
    let recipient = p(0x43);
    let s = deploy(&pic, controller);

    let pid = propose(&pic, &s, recipient, 5 * STSH, "a2-inflight");
    let _: () = decode(
        "inject_inflight_proposal_for_test",
        pic.update_call(
            s.treasury,
            controller,
            "inject_inflight_proposal_for_test",
            candid::encode_one(pid).unwrap(),
        ),
    );

    let rej = reject_proposal(&pic, s.treasury, controller, pid);
    assert_eq!(
        rej,
        Err(RejectProposalError::InFlight),
        "an in-flight proposal's outcome is unsettled — rejection must be refused; got {:?}",
        rej
    );
    assert_eq!(
        get_proposal(&pic, s.treasury, pid).status,
        ProposalStatus::Pending,
        "status unchanged while in flight"
    );
}

// =============================================================================
// REGRESSION — legitimate rejection of a genuinely non-executed proposal
// =============================================================================
#[test]
fn test_a2_regression_reject_pending_proposal_still_works() {
    let pic = PocketIc::new();
    let controller = p(0xA5);
    let recipient = p(0x44);
    let s = deploy(&pic, controller);

    let pid = propose(&pic, &s, recipient, 5 * STSH, "a2-regression");
    assert_eq!(get_proposal(&pic, s.treasury, pid).status, ProposalStatus::Pending);

    let rej = reject_proposal(&pic, s.treasury, controller, pid);
    assert_eq!(rej, Ok(()), "a Pending proposal must still be rejectable; got {:?}", rej);
    assert_eq!(get_proposal(&pic, s.treasury, pid).status, ProposalStatus::Rejected);

    // And rejecting twice is refused rather than silently re-writing.
    let again = reject_proposal(&pic, s.treasury, controller, pid);
    assert_eq!(
        again,
        Err(RejectProposalError::NotPending { current: ProposalStatus::Rejected }),
        "a second rejection must be refused, not a silent no-op; got {:?}",
        again
    );

    // An id that never existed is reported, not silently ignored.
    let missing = reject_proposal(&pic, s.treasury, controller, 9_999);
    assert_eq!(
        missing,
        Err(RejectProposalError::NotFound),
        "an unknown proposal id must be reported; got {:?}",
        missing
    );
}

// =============================================================================
// INSERT-ONCE — a later reconciliation never overwrites an existing tombstone
// =============================================================================
#[test]
fn test_a2_tombstone_is_insert_once() {
    let pic = PocketIc::new();
    let controller = p(0xA6);
    let recipient = p(0x45);
    let s = deploy(&pic, controller);

    force_transport_unknown(&pic, s.pool, controller, true);
    let pid = propose(&pic, &s, recipient, 5 * STSH, "a2-insert-once");
    let _ = execute_withdrawal(&pic, &s, pid);
    assert_eq!(disb_status_tag(&pic, s.pool, controller, pid), 3, "precondition: TransportUnknown");

    // First reconciliation: Executed, block 42 → tombstone records 42.
    let r1 = reconcile(
        &pic,
        s.pool,
        controller,
        pid,
        DisburseOutcome::Executed { block_index: 42 },
    );
    assert_eq!(r1, Ok(ReconcileDisburseResult::Recorded { block_index: Nat::from(42u64) }));
    let first = tombstone(&pic, s.pool, controller, pid)
        .expect("an Executed reconcile of an ambiguous disbursement is also tombstoned");
    assert_eq!(first.decision, ReconciliationDecision::Executed);
    assert_eq!(
        first.asserted_block_index,
        Some(42),
        "Executed carries the asserted block index"
    );

    // A second reconciliation asserting a DIFFERENT block index must not rewrite
    // history — neither the record nor the tombstone.
    let r2 = reconcile(
        &pic,
        s.pool,
        controller,
        pid,
        DisburseOutcome::Executed { block_index: 99 },
    );
    assert!(
        matches!(r2, Ok(ReconcileDisburseResult::AlreadyExecuted { .. })),
        "second reconcile is idempotent; got {:?}",
        r2
    );
    let second = tombstone(&pic, s.pool, controller, pid).expect("tombstone still present");
    assert_eq!(
        second, first,
        "INSERT-ONCE: an existing tombstone is never overwritten (block index must \
         still be 42, not 99)"
    );

    // The id stays reserved on the Executed branch too — but as the recorded
    // TERMINAL RESULT rather than a conflict, so treasury retries stay idempotent.
    force_transport_unknown(&pic, s.pool, controller, false);
    let reuse: Result<TreasuryDisburseResult, PoolError> = decode(
        "treasury_disburse after executed tombstone",
        pic.update_call(
            s.pool,
            s.treasury,
            "treasury_disburse",
            candid::encode_one(TreasuryDisburseArgs {
                proposal_id: pid,
                bucket: TreasuryReserveBucket::Operations,
                recipient,
                recipient_subaccount: None,
                amount: 5 * STSH,
                expected_ledger_fee: DEFAULT_FEE,
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        reuse,
        Ok(TreasuryDisburseResult::AlreadyExecuted { block_index: Nat::from(42u64) }),
        "a tombstoned-Executed id returns the RECORDED terminal result, never a new \
         ledger identity; got {:?}",
        reuse
    );
}
