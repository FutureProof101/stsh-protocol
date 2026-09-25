// =============================================================================
// STSH — Deposit retry / double-credit tests (PocketIC)
// Pass 4 remediation: QA-DEF-017
// =============================================================================
//
// shield_deposit / retry_deposit_commitment four-phase state machine:
//   TransferPending -> TransferConfirmedCommitmentPending
//                   -> CommitmentAppendInFlight
//                   -> CommitmentAppended            (credit exactly once)
//                   -> CommitmentAppendUnknown       (transport-unknown, no credit)
//
// These tests prove:
//   - a retry cannot credit before the token transfer is confirmed,
//   - two concurrent retries credit at most once (CommitmentAppendInFlight guard),
//   - a full deposit + retry credits exactly once,
//   - the in-flight claim blocks a concurrent retry.
//
// ─────────────────────────────────────────────────────────────────────────────
// ADVERSARIAL SELF-TRACE (charter Item 1) — walk of the original attack through
// the new code:
//
//   Attack variant 1 — credit before transfer success:
//     1. Attacker approves the pool for LESS than public_amount + fee.
//     2. shield_deposit writes TransferPending FIRST (no await before it).
//     3. Attacker immediately calls retry_deposit_commitment.
//     4. retry sees TransferPending -> Err(DepositTransferNotConfirmed) (it does
//        NOT see TransferConfirmedCommitmentPending), so it cannot append/credit.
//     5. The icrc2_transfer_from fails (Ok(Err)); shield_deposit removes the
//        record (definite rejection, clean state).
//     6. Net: no accounting credit, no Merkle leaf.  (test_t1, test_t4)
//
//   Attack variant 2 — concurrent retry double-credit:
//     1. Deposit reaches TransferConfirmedCommitmentPending (transfer confirmed).
//     2. Two concurrent retry_deposit_commitment calls arrive.
//     3. First caller: claim_deposit_append() transitions
//        TransferConfirmedCommitmentPending -> CommitmentAppendInFlight (atomic,
//        no await) and proceeds to append.
//     4. Second caller: claim_deposit_append() reads CommitmentAppendInFlight ->
//        Err(DepositAppendInProgress); it never appends.
//     5. Exactly one append, exactly one credit.  (test_t2, test_t5)
// ─────────────────────────────────────────────────────────────────────────────
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token -p shielded_pool \
//       -p nullifier_registry -p merkle_tree -p treasury -p staking -p stsh-verifier
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test deposit_retry_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }

// ── Constants ───────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;
const DENOM: u128 = 1_000 * 100_000_000; // 1,000 STSH — DENOMINATIONS[0] (A6.6)
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch

// ── Token mirrors ───────────────────────────────────────────────────────────

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

fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All".to_string(),
            amount: TOTAL_SUPPLY,
            recipient,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: staking,
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: u128,
    expected_allowance: Option<u128>,
    expires_at: Option<u64>,
    fee: Option<u128>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

// ── Pool mirrors ────────────────────────────────────────────────────────────

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending,
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
    CommitmentReconcileInFlight, // DEF-098 transient claim marker
    // DEF-040 terminal: leaf appended AND resulting root accepted.
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingDeposit {
    note_commitment: [u8; 32],
    private_balance: u128,
    ops_amount: u128,
    insurance_amount: u128,
    encrypted_payload: Vec<u8>,
    depositor: Option<Principal>,  // F2-REDACT: opt principal
    status: DepositStatus,
    created_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

// Full PoolError mirror (superset is fine; decode matches by variant name).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    EscrowUnderfunded { required: u128, available: u128 },
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    CircuitVersionMismatch { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch { inputs: u128, outputs: u128 },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateSpendId,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    PrivateSpendFeeMismatch { expected: u128, got: u128 },
    InsufficientPrivateLiability { required: u128, available: u128 },
    WithdrawalBelowMinimum { withdraw_gross_amount: u128, minimum_withdrawal_gross: u128 },
    GrossAmountBelowFees { withdraw_gross_amount: u128, total_fee: u128 },
    RecipientBelowMinimum { recipient_net_amount: u128, minimum_recipient_amount: u128 },
    IdempotencyKeyConflict,
    EncryptedPayloadTooLarge { len: u64, max: u64 },
    EncryptedOutputTooLarge { index: u32, len: u64, max: u64 },
    InvalidProofLength { len: u64, expected: u64 },
    DepositTransferNotConfirmed,
    DepositAppendInProgress,
    DepositAppendUnknown,
    DepositAlreadyCompleted,
    // DEF-041 / DEF-040 additions.
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    // DEF-050A: reconcile_deposit_append_unknown ambiguous-slot outcome.
    AmbiguousMerkleState,
    // HARDEN-03-SETTLEMENT (D-10, Option B): the fail-closed guard on
    // `reconcile_deposit_transfer_not_executed` reuses `DepositNotReconcilable`
    // above rather than adding a dedicated variant — see `SettlementError` in
    // `canisters/shielded-pool/src/lib.rs` for why. Nothing to mirror here.
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal { Principal::anonymous() }

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
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

struct Stack {
    pool: Principal,
    token: Principal,
    merkle: Principal,
    controller: Principal,
    user: Principal,
}

/// Deploy token + nullifier + merkle + pool (testing wasm). All supply to `user`.
fn deploy_stack(pic: &PocketIc) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);

    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    install(pic, token, token_wasm(), &all_to(user, p(0x02)));
    install(
        pic,
        pool,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token,
            nullifier_canister: null,
            merkle_canister: merkle,
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    Stack { pool, token, merkle, controller, user }
}

fn inject_deposit(pic: &PocketIc, s: &Stack, commitment: [u8; 32], balance: u128, status: DepositStatus) {
    let _: () = decode(
        "inject_pending_deposit_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_pending_deposit_for_test",
            candid::encode_args((commitment, balance, status)).unwrap(),
        ),
    );
}

fn deposit_status(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> Option<DepositStatus> {
    let rec: Option<PendingDeposit> = decode(
        "get_deposit_status",
        // DEF-070: get_deposit_status is owner-or-controller gated — poll as the
        // pool controller (controller may read any record; anonymous can no longer).
        pic.query_call(s.pool, s.controller, "get_deposit_status", candid::encode_one(commitment).unwrap()),
    );
    rec.map(|r| r.status)
}

fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode(
        "get_accounting_state",
        // DEF-076: get_accounting_state is controller-gated — read as controller.
        pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()),
    )
}

fn leaf_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "leaf_count",
        pic.query_call(s.merkle, anon(), "leaf_count", candid::encode_args(()).unwrap()),
    )
}

fn retry(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> Result<Nat, PoolError> {
    decode(
        "retry_deposit_commitment",
        pic.update_call(s.pool, anon(), "retry_deposit_commitment", candid::encode_one(commitment).unwrap()),
    )
}

fn commitment(tag: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0] = tag;
    c[31] = 0x01;
    c
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t1 — retry blocked while TransferPending
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_deposit_retry_blocked_while_transfer_pending() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x11);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferPending);
    let before = accounting(&pic, &s);
    let leaves_before = leaf_count(&pic, &s);

    let r = retry(&pic, &s, c);
    assert_eq!(
        r,
        Err(PoolError::DepositTransferNotConfirmed),
        "retry on TransferPending must be rejected (transfer not confirmed)"
    );

    let after = accounting(&pic, &s);
    assert_eq!(after.private_liability, before.private_liability, "PRIVATE_LIABILITY unchanged");
    assert_eq!(after.escrow_backing, before.escrow_backing, "ESCROW_BACKING unchanged");
    assert_eq!(leaf_count(&pic, &s), leaves_before, "leaf count unchanged");
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferPending),
        "status remains TransferPending"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t2 — two concurrent retries credit exactly once
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_deposit_retry_concurrent_retries_credit_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x22);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(accounting(&pic, &s).private_liability, 0, "precondition: no credit yet");
    assert_eq!(leaf_count(&pic, &s), 0, "precondition: no leaves yet");

    // Submit both retries before awaiting either → both in flight in the same
    // round, interleaving at the append await point.
    let m1 = pic
        .submit_call(s.pool, anon(), "retry_deposit_commitment", candid::encode_one(c).unwrap())
        .expect("submit retry 1");
    let m2 = pic
        .submit_call(s.pool, anon(), "retry_deposit_commitment", candid::encode_one(c).unwrap())
        .expect("submit retry 2");
    let r1: Result<Nat, PoolError> = decode("retry 1", pic.await_call(m1));
    let r2: Result<Nat, PoolError> = decode("retry 2", pic.await_call(m2));

    let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "exactly one retry may credit; got r1={:?} r2={:?}", r1, r2);
    let loser = [&r1, &r2].into_iter().find(|r| r.is_err()).unwrap();
    // P-ROOT: the loser may now also be turned away at the pool-wide append lease
    // (CommitmentAppendFailed "lease held") before it ever reaches the claim.
    assert!(
        matches!(
            loser,
            Err(PoolError::DepositAppendInProgress)
                | Err(PoolError::DepositAlreadyCompleted)
                | Err(PoolError::CommitmentAppendFailed(_))
        ),
        "losing retry must be lease-blocked, in-progress, or idempotent-complete; got {:?}",
        loser
    );

    assert_eq!(
        accounting(&pic, &s).private_liability,
        DENOM,
        "PRIVATE_LIABILITY credited by exactly one denomination"
    );
    assert_eq!(leaf_count(&pic, &s), 1, "exactly one Merkle leaf appended");
    // P-ROOT: the winner finalizes through the accepted-root head to the terminal state.
    assert!(
        matches!(
            deposit_status(&pic, &s, c),
            Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })
        ),
        "deposit finalized as CommitmentRootAccepted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t3 — full deposit + retry credits exactly once
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_deposit_and_retry_same_commitment_accounting_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x33);

    // Approve the pool to pull DENOM + fee from the user, then shield_deposit.
    let _: Result<Nat, ApproveErr> = decode(
        "icrc2_approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
                amount: DENOM + DEFAULT_FEE,
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee: None,
                memo: None,
                created_at_time: None,
            })
            .unwrap(),
        ),
    );

    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: c,
                encrypted_payload: vec![1, 2, 3],
                public_amount: DENOM,
            })
            .unwrap(),
        ),
    );
    assert!(dep.is_ok(), "shield_deposit must succeed; got {:?}", dep);
    assert_eq!(accounting(&pic, &s).private_liability, DENOM, "single credit after deposit");
    assert_eq!(leaf_count(&pic, &s), 1, "single leaf after deposit");
    // P-ROOT: shield_deposit finalizes to the terminal CommitmentRootAccepted.
    assert!(
        matches!(
            deposit_status(&pic, &s, c),
            Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })
        ),
        "deposit is CommitmentRootAccepted"
    );

    // Retry on a completed deposit is idempotent — no second credit, no second leaf.
    let r1 = retry(&pic, &s, c);
    assert!(r1.is_ok(), "retry on completed deposit is idempotent Ok; got {:?}", r1);
    let r2 = retry(&pic, &s, c);
    assert!(r2.is_ok(), "second retry also idempotent Ok; got {:?}", r2);

    assert_eq!(accounting(&pic, &s).private_liability, DENOM, "still exactly one credit");
    assert_eq!(leaf_count(&pic, &s), 1, "still exactly one leaf");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t4 — retry only allowed after transfer confirmed (typed error, no panic)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_deposit_retry_only_allowed_after_transfer_confirmed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x44);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferPending);
    let r = retry(&pic, &s, c);
    assert_eq!(
        r,
        Err(PoolError::DepositTransferNotConfirmed),
        "retry before transfer confirmation must return a typed error, not panic"
    );
    assert_eq!(accounting(&pic, &s).private_liability, 0, "no credit");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t5 — CommitmentAppendInFlight blocks a concurrent retry
// ─────────────────────────────────────────────────────────────────────────────
//
// Injecting CommitmentAppendInFlight is a deterministic proxy for "another caller
// has already claimed the append slot and is mid-await": claim_deposit_append must
// reject any further retry with DepositAppendInProgress and never append.
#[test]
fn test_deposit_commit_in_flight_blocks_concurrent_retry() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x55);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::CommitmentAppendInFlight);
    let leaves_before = leaf_count(&pic, &s);

    let r = retry(&pic, &s, c);
    assert_eq!(
        r,
        Err(PoolError::DepositAppendInProgress),
        "retry against an in-flight append must be rejected"
    );
    assert_eq!(accounting(&pic, &s).private_liability, 0, "no credit while append in flight");
    assert_eq!(leaf_count(&pic, &s), leaves_before, "no leaf appended by the blocked retry");
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentAppendInFlight),
        "status unchanged"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-040 — reconcile_deposit_commitment closes the accepted-root gap
// ─────────────────────────────────────────────────────────────────────────────

fn merkle_root(pic: &PocketIc, s: &Stack) -> Vec<u8> {
    decode(
        "get_root",
        pic.query_call(s.merkle, anon(), "get_root", candid::encode_args(()).unwrap()),
    )
}
fn accepted_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "accepted_spend_root_count",
        pic.query_call(s.pool, anon(), "accepted_spend_root_count", candid::encode_args(()).unwrap()),
    )
}
fn is_accepted(pic: &PocketIc, s: &Stack, root: Vec<u8>) -> bool {
    decode(
        "is_accepted_spend_root",
        pic.query_call(s.pool, anon(), "is_accepted_spend_root", candid::encode_one(root).unwrap()),
    )
}
fn reconcile_deposit(
    pic: &PocketIc,
    s: &Stack,
    commitment: [u8; 32],
    caller: Principal,
) -> Result<(), PoolError> {
    decode(
        "reconcile_deposit_commitment",
        pic.update_call(
            s.pool,
            caller,
            "reconcile_deposit_commitment",
            candid::encode_one(commitment).unwrap(),
        ),
    )
}

// P-ROOT rework: the accepted-root gap now exists ONLY as interrupted
// finalization — the deposit credits, the scan-head fetch fails, and the
// pool-wide lease is RETAINED at AppendConfirmedRootPending. The reconcile
// continues finalization under that lease: it accepts the scan-head root,
// advances the deposit to the terminal CommitmentRootAccepted, writes the head,
// and releases; a second reconcile is rejected.
#[test]
fn test_reconcile_deposit_commitment_accepts_root_and_is_idempotent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x6A);

    // Stage the gap with a REAL deposit whose scan-head fetch is forced to fail.
    let _: () = decode(
        "force_scan_head_unavailable_for_test",
        pic.update_call(s.pool, s.controller, "force_scan_head_unavailable_for_test",
            candid::encode_one(true).unwrap()),
    );
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "credit applied; finality pending");
    let _: () = decode(
        "force_scan_head_unavailable_for_test",
        pic.update_call(s.pool, s.controller, "force_scan_head_unavailable_for_test",
            candid::encode_one(false).unwrap()),
    );
    assert_eq!(deposit_status(&pic, &s, c), Some(DepositStatus::CommitmentAppended { leaf_index: 0 }));
    assert_eq!(accepted_count(&pic, &s), 0, "no accepted root before reconcile");

    let root = merkle_root(&pic, &s); // a genuine current Merkle root (valid anchor under A2)
    assert!(!is_accepted(&pic, &s, root.clone()), "root must not be accepted yet");

    let r = reconcile_deposit(&pic, &s, c, s.controller);
    assert_eq!(r, Ok(()), "controller reconcile must succeed; got {:?}", r);
    assert!(is_accepted(&pic, &s, root.clone()), "the current root must now be accepted");
    assert_eq!(accepted_count(&pic, &s), 1, "exactly one root accepted");

    let root32 = <[u8; 32]>::try_from(root).expect("32-byte root");
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, root: root32 }),
        "deposit advanced to the terminal CommitmentRootAccepted"
    );

    // Second reconcile on the terminal state is rejected (idempotency).
    let r2 = reconcile_deposit(&pic, &s, c, s.controller);
    assert_eq!(
        r2,
        Err(PoolError::DepositAlreadyCompleted),
        "a second reconcile must be rejected"
    );
    assert_eq!(accepted_count(&pic, &s), 1, "no duplicate accepted root from the rejected reconcile");
}

// reconcile_deposit_commitment guards: not-found, wrong-state, append-unknown, and
// controller-only authorization.
#[test]
fn test_reconcile_deposit_commitment_guards() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Unknown commitment → DepositNotFound.
    assert_eq!(
        reconcile_deposit(&pic, &s, commitment(0x6B), s.controller),
        Err(PoolError::DepositNotFound),
        "reconcile of a non-existent deposit must be DepositNotFound"
    );

    // A pre-append state is not reconcilable here.
    let c = commitment(0x6C);
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(
        reconcile_deposit(&pic, &s, c, s.controller),
        Err(PoolError::DepositNotReconcilable),
        "a pre-append deposit must not be reconcilable"
    );

    // CommitmentAppendUnknown is out of scope (the leaf may not exist).
    let cu = commitment(0x6D);
    inject_deposit(&pic, &s, cu, DENOM, DepositStatus::CommitmentAppendUnknown);
    assert_eq!(
        reconcile_deposit(&pic, &s, cu, s.controller),
        Err(PoolError::DepositAppendUnknown),
        "an unknown-append deposit must not be reconcilable here"
    );

    // A non-controller caller is rejected (assert_controller traps → call rejected),
    // and the deposit state is unchanged.
    let c2 = commitment(0x6E);
    inject_deposit(&pic, &s, c2, DENOM, DepositStatus::CommitmentAppended { leaf_index: 0 });
    let rejected = pic.update_call(
        s.pool,
        s.user,
        "reconcile_deposit_commitment",
        candid::encode_one(c2).unwrap(),
    );
    assert!(rejected.is_err(), "a non-controller caller must be rejected");
    assert_eq!(
        deposit_status(&pic, &s, c2),
        Some(DepositStatus::CommitmentAppended { leaf_index: 0 }),
        "a rejected reconcile must not mutate deposit state"
    );
    assert_eq!(accepted_count(&pic, &s), 0, "no root accepted by the rejected reconcile");
}

// Minimal mirror of the token's ApproveError (decode target for icrc2_approve).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveErr {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-050A — reconcile_deposit_append_unknown: Merkle-verified CommitmentAppendUnknown
//
// The endpoint compares get_leaf(expected_leaf_index) against the stored commitment and
// either finalizes (single credit via the shared finish path), reverts to retryable
// (slot empty), or reports AmbiguousMerkleState (a different commitment at the slot).
// Credit only at a confirmed leaf; never on controller word; never via a full-tree scan.
//
// Setup note: a real Merkle leaf is seeded via inject_deposit(TransferConfirmed…) + retry
// (which appends + credits). inject_append_unknown then OVERWRITES the pool record to
// CommitmentAppendUnknown — the Merkle leaf persists — so the reconcile's get_leaf sees
// it. Each test measures the reconcile's accounting DELTA (credit-exactly-once).
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositAppendReconcileResult {
    Finalized,
    RevertedRetryable,
}

// ── P-ROOT (C-ROOT-1): an injected CommitmentAppendUnknown record must hold the
// pool-wide append lease at AppendUnknown for reconcile_deposit_append_unknown to
// admit it (the real transport-unknown path retains the lease). ──
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum LeasePhase { Snapshotting, AppendInFlight, AppendUnknown, ReconcileInFlight, AppendConfirmedRootPending }
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum AppendLeaseOwner {
    Deposit { commitment: [u8; 32] },
    Spend { spend_id: u64 },
}
fn lease_deposit_unknown(pic: &PocketIc, s: &Stack, c: [u8; 32]) {
    let _: u64 = decode(
        "set_append_lease_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "set_append_lease_for_test",
            candid::encode_args((AppendLeaseOwner::Deposit { commitment: c }, LeasePhase::AppendUnknown)).unwrap(),
        ),
    );
}

/// Inject a CommitmentAppendUnknown deposit with a specific expected_leaf_index
/// (None simulates a pre-DEF-050A record with no stored index).
fn inject_append_unknown(
    pic: &PocketIc,
    s: &Stack,
    commitment: [u8; 32],
    balance: u128,
    expected_leaf_index: Option<u64>,
) {
    let _: () = decode(
        "inject_append_unknown_deposit_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_append_unknown_deposit_for_test",
            candid::encode_args((commitment, balance, expected_leaf_index)).unwrap(),
        ),
    );
}

fn reconcile_append_unknown(
    pic: &PocketIc,
    s: &Stack,
    commitment: [u8; 32],
    caller: Principal,
) -> Result<DepositAppendReconcileResult, PoolError> {
    decode(
        "reconcile_deposit_append_unknown",
        pic.update_call(
            s.pool,
            caller,
            "reconcile_deposit_append_unknown",
            candid::encode_one(commitment).unwrap(),
        ),
    )
}

// DEF050A-A — leaf confirmed at the expected index → credit exactly once, idempotent.
#[test]
fn test_def050a_reconcile_append_unknown_leaf_confirmed_credits_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x50);

    // Seed a real Merkle leaf at index 0 (transfer already confirmed → retry appends).
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "seed append must succeed");
    assert_eq!(leaf_count(&pic, &s), 1, "commitment appended at index 0");
    // P-ROOT: the seed finalizes to the terminal CommitmentRootAccepted.
    assert!(matches!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })
    ));

    // Drive that record into CommitmentAppendUnknown with expected_leaf_index = 0 (the
    // leaf IS present at 0). Overwrites the pool record; the Merkle leaf is untouched.
    inject_append_unknown(&pic, &s, c, DENOM, Some(0));
    // P-ROOT: a transport-unknown deposit holds the pool-wide lease at AppendUnknown.
    lease_deposit_unknown(&pic, &s, c);
    assert_eq!(deposit_status(&pic, &s, c), Some(DepositStatus::CommitmentAppendUnknown));

    let before = accounting(&pic, &s);
    let r = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert_eq!(r, Ok(DepositAppendReconcileResult::Finalized), "leaf confirmed → finalize; got {:?}", r);
    // P-ROOT: the reconcile finalization runs through the accepted-root head to
    // the terminal CommitmentRootAccepted.
    assert!(
        matches!(
            deposit_status(&pic, &s, c),
            Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })
        ),
        "deposit advances to CommitmentRootAccepted"
    );
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing + DENOM, "escrow credited exactly once");
    assert_eq!(after.private_liability, before.private_liability + DENOM, "private liability credited exactly once");

    // Idempotent: a second reconcile (now CommitmentAppended) is rejected, no double-credit.
    let r2 = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert_eq!(r2, Err(PoolError::DepositNotReconcilable), "second reconcile rejected; got {:?}", r2);
    let after2 = accounting(&pic, &s);
    assert_eq!(after2.escrow_backing, after.escrow_backing, "no double-credit on second reconcile");
    assert_eq!(after2.private_liability, after.private_liability, "no double-credit on second reconcile");
}

// DEF050A-B — leaf absent (leaf_count <= expected) → revert to retryable; retry re-appends.
#[test]
fn test_def050a_reconcile_append_unknown_leaf_absent_reverts_to_retryable() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x51);

    // Fresh tree (leaf_count = 0); inject CommitmentAppendUnknown expecting index 0.
    inject_append_unknown(&pic, &s, c, DENOM, Some(0));
    // P-ROOT: a transport-unknown deposit holds the pool-wide lease at AppendUnknown.
    lease_deposit_unknown(&pic, &s, c);
    assert_eq!(leaf_count(&pic, &s), 0, "no leaves yet");
    let before = accounting(&pic, &s);

    let r = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert_eq!(r, Ok(DepositAppendReconcileResult::RevertedRetryable), "absent leaf → revert; got {:?}", r);
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferConfirmedCommitmentPending),
        "deposit reverts to the retryable state"
    );
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing, "no credit on revert");
    assert_eq!(after.private_liability, before.private_liability, "no credit on revert");

    // The retry path can now re-append and credit (finalizing to the terminal state).
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "retry re-appends after revert");
    assert!(matches!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })
    ));
    assert_eq!(accounting(&pic, &s).escrow_backing, before.escrow_backing + DENOM, "retry credits once");
}

// DEF050A-C — wrong state (not CommitmentAppendUnknown) → reject cleanly, no mutation.
#[test]
fn test_def050a_reconcile_append_unknown_wrong_state_rejected() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x52);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    let before = accounting(&pic, &s);

    let r = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert_eq!(r, Err(PoolError::DepositNotReconcilable), "non-Unknown state rejected; got {:?}", r);
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferConfirmedCommitmentPending),
        "status unchanged"
    );
    assert_eq!(accounting(&pic, &s).escrow_backing, before.escrow_backing, "no accounting change");

    // Unknown commitment → DepositNotFound (still no mutation).
    assert_eq!(
        reconcile_append_unknown(&pic, &s, commitment(0x5F), s.controller),
        Err(PoolError::DepositNotFound),
        "reconcile of a non-existent deposit must be DepositNotFound"
    );
}

// DEF050A-D — bytes mismatch at the expected index → AmbiguousMerkleState; no credit, no revert.
#[test]
fn test_def050a_reconcile_append_unknown_bytes_mismatch_is_ambiguous() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c1 = commitment(0x53);
    let c2 = commitment(0x54);

    // Seed c1 at index 0.
    inject_deposit(&pic, &s, c1, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c1), Ok(Nat::from(DENOM)));
    assert_eq!(leaf_count(&pic, &s), 1);

    // Inject CommitmentAppendUnknown for c2 expecting index 0 — but get_leaf(0) == c1.
    inject_append_unknown(&pic, &s, c2, DENOM, Some(0));
    // P-ROOT: a transport-unknown deposit holds the pool-wide lease at AppendUnknown.
    lease_deposit_unknown(&pic, &s, c2);
    let before = accounting(&pic, &s);

    let r = reconcile_append_unknown(&pic, &s, c2, s.controller);
    assert_eq!(r, Err(PoolError::AmbiguousMerkleState), "different commitment at slot → ambiguous; got {:?}", r);
    assert_eq!(
        deposit_status(&pic, &s, c2),
        Some(DepositStatus::CommitmentAppendUnknown),
        "ambiguous: status stays CommitmentAppendUnknown (no credit, no revert)"
    );
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing, "no credit on ambiguous");
    assert_eq!(after.private_liability, before.private_liability, "no credit on ambiguous");
}

// DEF050A-E — pre-fix record (expected_leaf_index == None) → not self-reconcilable; no mutation.
#[test]
fn test_def050a_reconcile_append_unknown_none_index_not_self_reconcilable() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x55);

    inject_append_unknown(&pic, &s, c, DENOM, None);
    let before = accounting(&pic, &s);

    let r = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert_eq!(r, Err(PoolError::DepositNotReconcilable), "no stored index → not self-reconcilable; got {:?}", r);
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentAppendUnknown),
        "status stays CommitmentAppendUnknown (no mutation)"
    );
    assert_eq!(accounting(&pic, &s).escrow_backing, before.escrow_backing, "no accounting change");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-050B-2 — reconcile_deposit_transfer_not_executed (NotExecuted-only)
// ─────────────────────────────────────────────────────────────────────────────
//
// A shield_deposit whose icrc2_transfer_from returns a transport-unknown outcome is
// left at TransferPending with no recovery path. The controller-only
// reconcile_deposit_transfer_not_executed endpoint applies the NotExecuted decision
// (operator asserts the transfer did NOT execute) and cancels the stuck record cleanly.
// It is protocol-solvency-safe: a TransferPending deposit is never credited, so no
// private liability is minted, no Merkle leaf is appended, and no outbound/refund
// transfer is issued. There is NO Executed path (shield_deposit uses created_at_time=None,
// so the token dedup cannot prove execution and there is no on-chain escrow proof binding
// a transfer to the commitment — see the endpoint's RECONCILE TRUST note).
//
// Proves: controller-only; a TransferPending deposit is cancelled; wrong-state/not-found
// guards; no Merkle leaf created; no private liability credited; no outbound transfer.
fn reconcile_not_executed(
    pic: &PocketIc,
    s: &Stack,
    commitment: [u8; 32],
    caller: Principal,
) -> Result<(), PoolError> {
    decode(
        "reconcile_deposit_transfer_not_executed",
        pic.update_call(
            s.pool,
            caller,
            "reconcile_deposit_transfer_not_executed",
            candid::encode_one(commitment).unwrap(),
        ),
    )
}

fn balance_of(pic: &PocketIc, s: &Stack, owner: Principal) -> Nat {
    decode(
        "icrc1_balance_of",
        pic.query_call(
            s.token,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap(),
        ),
    )
}

#[test]
fn test_deposit_transfer_pending_reconcile_not_executed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x5B);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferPending);

    // ── Controller-only: a non-controller caller is rejected; deposit unchanged. ──
    let rejected = pic.update_call(
        s.pool,
        s.user, // not the controller
        "reconcile_deposit_transfer_not_executed",
        candid::encode_one(c).unwrap(),
    );
    assert!(
        rejected.is_err(),
        "a non-controller caller must be rejected (assert_controller traps → call rejected)"
    );
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferPending),
        "a rejected non-controller call must not change deposit state"
    );

    // ── Guards: only TransferPending is reconcilable here. ──
    let c_wrong = commitment(0x5C);
    inject_deposit(&pic, &s, c_wrong, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(
        reconcile_not_executed(&pic, &s, c_wrong, s.controller),
        Err(PoolError::DepositNotReconcilable),
        "a non-TransferPending deposit must not be cancellable by this endpoint"
    );
    assert_eq!(
        reconcile_not_executed(&pic, &s, commitment(0x5D), s.controller),
        Err(PoolError::DepositNotFound),
        "reconcile of a non-existent deposit must be DepositNotFound"
    );

    // Capture pre-reconcile state for the TransferPending deposit `c` (the guard
    // injections above touch neither accounting, the Merkle tree, nor balances).
    let acct_before = accounting(&pic, &s);
    let leaves_before = leaf_count(&pic, &s);
    let pool_bal_before = balance_of(&pic, &s, s.pool);
    let user_bal_before = balance_of(&pic, &s, s.user);

    // ── Controller NotExecuted: the TransferPending record is cancelled cleanly. ──
    let r = reconcile_not_executed(&pic, &s, c, s.controller);
    assert_eq!(r, Ok(()), "controller NotExecuted reconcile must succeed; got {:?}", r);

    // a) the deposit record is cancelled (no longer queryable).
    assert_eq!(
        deposit_status(&pic, &s, c),
        None,
        "the TransferPending record must be cancelled (removed)"
    );
    // b) no Merkle leaf was appended.
    assert_eq!(leaf_count(&pic, &s), leaves_before, "no Merkle leaf may be created");
    // c) no private liability credited (and no other accounting bucket moved).
    let acct_after = accounting(&pic, &s);
    assert_eq!(acct_after.private_liability, acct_before.private_liability, "PRIVATE_LIABILITY unchanged");
    assert_eq!(acct_after.escrow_backing, acct_before.escrow_backing, "ESCROW_BACKING unchanged");
    assert_eq!(acct_after.operations_reserve, acct_before.operations_reserve, "OPERATIONS_RESERVE unchanged");
    assert_eq!(acct_after.insurance_reserve, acct_before.insurance_reserve, "INSURANCE_RESERVE unchanged");
    // d) no outbound/refund transfer issued (pool and user token balances unchanged).
    assert_eq!(balance_of(&pic, &s, s.pool), pool_bal_before, "pool token balance unchanged (no transfer)");
    assert_eq!(balance_of(&pic, &s, s.user), user_bal_before, "user token balance unchanged (no refund)");
}

// ═════════════════════════════════════════════════════════════════════════════
// HARDEN-03-SETTLEMENT (D-10, AC-14) — `reconcile_deposit_transfer_not_executed`
// is now FAIL-CLOSED on the settlement sidecar.
//
// THE TEST ABOVE IS UNEDITED, AND THAT IS THE POINT (AC-13). It drives
// `inject_pending_deposit_for_test`, which writes a `PendingDeposit` and nothing
// else — no nonce, no sidecar — so every record it injects takes D-10's
// SIDECAR-ABSENT legacy arm verbatim and keeps today's behaviour, including the
// destructive cancel. That hook is frozen (D-13): teaching it to write a sidecar
// would silently flip the test above onto the new refusal arm, which would read
// as a regression and would not be one.
//
// These two tests use the SIBLING hooks instead, and assert the new arm.
// ═════════════════════════════════════════════════════════════════════════════

/// AC-14a: a record whose settlement sidecar SURVIVES cannot be destroyed.
///
/// The destructive button described in `docs/POOL_OPERATOR_RECONCILE_RULES.md`
/// §1.1 is gone for every deposit a post-lane pool created. The operator must
/// run `settle_deposit_transfer`, which decides on EVIDENCE — a durable receipt,
/// a `Duplicate{block}`, or a durable fence — rather than destroying a record on
/// a bare assertion that may be wrong.
///
/// The predicate is "a sidecar survives", not "disposition == Unresolved". A
/// fence-confirmed close is the only thing that removes a sidecar, so on a
/// `TransferPending` record a surviving sidecar means the deposit was never
/// objectively resolved — under every disposition, including the `Anomaly` one
/// reached when an `Applied` receipt exists but disagrees with the sidecar. In
/// THAT case the transfer provably executed, and permitting a cancel would
/// strand a confirmed depositor's funds: exactly the gap this lane closes,
/// re-opened by the endpoint it was meant to disarm.
#[test]
fn test_harden03_reconcile_not_executed_is_fail_closed_on_a_surviving_sidecar() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x5E);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferPending);
    // Control: WITHOUT a sidecar this record is the legacy shape, and the
    // endpoint's behaviour is unchanged. Asserted first so the refusal below
    // cannot be mistaken for some unrelated precondition.
    assert_eq!(
        reconcile_not_executed(&pic, &s, c, s.controller),
        Ok(()),
        "control: a legacy (sidecar-absent) record keeps today's behaviour exactly"
    );
    assert_eq!(deposit_status(&pic, &s, c), None, "control: and is cancelled");

    // Now the post-lane shape: the same record, plus a sidecar.
    let c2 = commitment(0x5F);
    inject_deposit(&pic, &s, c2, DENOM, DepositStatus::TransferPending);
    let _: () = decode(
        "inject_deposit_settlement_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_deposit_settlement_for_test",
            candid::encode_args((c2, [0x9Au8; 32], DENOM + DEFAULT_FEE, DEFAULT_FEE, s.token))
                .unwrap(),
        ),
    );

    let acct_before = accounting(&pic, &s);
    let r = reconcile_not_executed(&pic, &s, c2, s.controller);
    assert_eq!(
        r,
        Err(PoolError::DepositNotReconcilable),
        "a sidecar-covered record must be refused — settle on evidence first \
         (Option B: reuses the existing DepositNotReconcilable, not a dedicated \
         variant); got {:?}",
        r
    );
    assert_eq!(
        deposit_status(&pic, &s, c2),
        Some(DepositStatus::TransferPending),
        "and the record must SURVIVE the refused cancel"
    );
    let acct_after = accounting(&pic, &s);
    assert_eq!(
        acct_after.private_liability, acct_before.private_liability,
        "a refusal credits nothing"
    );
    assert_eq!(
        acct_after.escrow_backing, acct_before.escrow_backing,
        "and moves no escrow"
    );
}

/// AC-14b: a record with a LIVE settlement claim is refused exactly like a
/// stale-claim/no-claim sidecar-covered record — `DepositNotReconcilable` in
/// both cases, so an operator cannot race an in-flight settlement.
///
/// Option B (CTO ruling 2026-09-17) deliberately DROPPED the distinct
/// "in progress" vs "settle this first" signal AC-14b originally specified —
/// two dedicated `PoolError` variants would have broken the drift-locked
/// `custody-types`/`treasury` mirrors and re-pinned three Wasms beyond what
/// this lane costed. The money-safety property (the destructive path stays
/// refused) is identical either way; an operator who needs the distinction
/// reads it from the sidecar via `get_deposit_status` instead. This test now
/// asserts that BOTH the live-claim and the stale-claim case are refused with
/// the same error, not that they're told apart.
#[test]
fn test_harden03_reconcile_not_executed_refuses_while_a_settlement_claim_is_live() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x6E);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferPending);
    let _: () = decode(
        "inject_deposit_settlement_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_deposit_settlement_for_test",
            candid::encode_args((c, [0x9Bu8; 32], DENOM + DEFAULT_FEE, DEFAULT_FEE, s.token))
                .unwrap(),
        ),
    );
    let now = pic.get_time().as_nanos_since_unix_epoch() as u64;
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c, now, 1u32)).unwrap(),
        ),
    );

    assert_eq!(
        reconcile_not_executed(&pic, &s, c, s.controller),
        Err(PoolError::DepositNotReconcilable),
        "a live claim must still be refused (Option B: same variant as the \
         settle-first case, distinction moved to the runbook)"
    );
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferPending),
        "and the record survives"
    );

    // A STALE claim falls through to the settle-first refusal — it must not
    // block the operator forever, and it must not open the destructive path
    // either. Both halves matter.
    let stale = now.saturating_sub(300 * 1_000_000_000 + 1_000_000_000);
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c, stale, 1u32)).unwrap(),
        ),
    );
    assert_eq!(
        reconcile_not_executed(&pic, &s, c, s.controller),
        Err(PoolError::DepositNotReconcilable),
        "a stale claim is refused with the same error as the live-claim case above; \
         the record is still not destroyable either way"
    );
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferPending),
        "still alive"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Reconcile Hardening Lane — DEF-098 (claim-before-await in
// reconcile_deposit_append_unknown)
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// DEF-098 — two CONCURRENT reconciles credit exactly once. True interleaving via
// paired submit_call before either await_call — the same harness pattern as
// pool_recovery_tests' concurrent-retry payout test. The loser is rejected by
// the claim marker (DepositAppendInProgress) if it interleaves mid-flight, or by
// the terminal state (DepositNotReconcilable) if it runs after the winner
// completed — either way it must NOT credit.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_def098_concurrent_reconcile_append_unknown_credits_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x60);

    // Seed a real Merkle leaf at index 0, then drive the record into
    // CommitmentAppendUnknown with the matching expected_leaf_index (the
    // established DEF-050A setup).
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "seed append must succeed");
    inject_append_unknown(&pic, &s, c, DENOM, Some(0));
    // P-ROOT: a transport-unknown deposit holds the pool-wide lease at AppendUnknown.
    lease_deposit_unknown(&pic, &s, c);

    let before = accounting(&pic, &s);

    // Two concurrent reconciles, both submitted before either is awaited.
    let m1 = pic
        .submit_call(s.pool, s.controller, "reconcile_deposit_append_unknown", candid::encode_one(c).unwrap())
        .expect("submit reconcile 1");
    let m2 = pic
        .submit_call(s.pool, s.controller, "reconcile_deposit_append_unknown", candid::encode_one(c).unwrap())
        .expect("submit reconcile 2");
    let r1: Result<DepositAppendReconcileResult, PoolError> = decode("reconcile 1", pic.await_call(m1));
    let r2: Result<DepositAppendReconcileResult, PoolError> = decode("reconcile 2", pic.await_call(m2));

    let finalized = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Ok(DepositAppendReconcileResult::Finalized)))
        .count();
    assert_eq!(finalized, 1, "exactly one reconcile may finalize (r1={:?} r2={:?})", r1, r2);
    let loser = if matches!(r1, Ok(_)) { &r2 } else { &r1 };
    assert!(
        matches!(
            loser,
            Err(PoolError::DepositAppendInProgress) | Err(PoolError::DepositNotReconcilable)
        ),
        "the losing reconcile must be rejected by the claim or the terminal state; got {:?}",
        loser
    );

    // ESCROW_BACKING / PRIVATE_LIABILITY credited EXACTLY once (the DEF-098 defect
    // was a double credit here).
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing + DENOM, "escrow credited exactly once");
    assert_eq!(after.private_liability, before.private_liability + DENOM, "liability credited exactly once");
    // P-ROOT: the winner finalizes to the terminal CommitmentRootAccepted.
    assert!(matches!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-098 — Merkle transport failure restores the retriable status: the claim
// marker never strands, no credit is applied, and the reconcile succeeds once
// the Merkle canister is reachable again
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_def098_reconcile_restores_on_merkle_transport_failure() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x61);

    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "seed append must succeed");
    inject_append_unknown(&pic, &s, c, DENOM, Some(0));
    // P-ROOT: a transport-unknown deposit holds the pool-wide lease at AppendUnknown.
    lease_deposit_unknown(&pic, &s, c);

    let before = accounting(&pic, &s);

    // Kill the Merkle canister: leaf_count/get_leaf reject (transport failure).
    pic.stop_canister(s.merkle, None).expect("stop merkle");
    let r = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert!(
        matches!(r, Err(PoolError::TransferFailed(_))),
        "Merkle transport failure must propagate as TransferFailed; got {:?}", r
    );
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::CommitmentAppendUnknown),
        "status must be RESTORED to CommitmentAppendUnknown — the claim marker never strands"
    );
    let mid = accounting(&pic, &s);
    assert_eq!(mid.escrow_backing, before.escrow_backing, "no credit on transport failure");
    assert_eq!(mid.private_liability, before.private_liability, "no liability on transport failure");

    // Retriability end-to-end: Merkle back up → the same reconcile finalizes.
    pic.start_canister(s.merkle, None).expect("restart merkle");
    let r2 = reconcile_append_unknown(&pic, &s, c, s.controller);
    assert_eq!(
        r2,
        Ok(DepositAppendReconcileResult::Finalized),
        "restored record must be reconcilable on retry"
    );
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing + DENOM, "credited exactly once after retry");
}
