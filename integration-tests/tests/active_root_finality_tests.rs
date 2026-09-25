// =============================================================================
// STSH — A2 Active-Only Merkle Tree finality tests (PocketIC)
// Closes QA-DEF-034 (orphan output spendability) + QA-DEF-036 (finalization liveness)
// =============================================================================
//
// Non-negotiable rule under test:
//   raw Merkle root exists       != accepted spend root
//   pending root exists          != accepted spend root
//   post-upgrade Merkle history  != accepted spend root
//   A root enters accepted_spend_roots ONLY through finalized A2 promotion logic.
//
// These tests use the stub verifier (accepts any proof) so they exercise the pool
// STATE MACHINE and anchor/promotion logic, not the ZK layer. Output commitments
// and nullifiers are canonical small BN254 Fr values (low byte only).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): build shielded_pool with
// --features testing, copy to shielded_pool_test.wasm, then build all production
// wasms + stsh-stub-verifier. POCKET_IC_BIN must be set.
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
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

// ── Constants ───────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM_1000: u128 = 1_000 * 100_000_000; // DENOMINATIONS[3]
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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version: u32,
    proof_system_id: String,
    verifying_key_hash: [u8; 32],
    root_reference: [u8; 32],
    pool_version: u32,
    proof_bytes: Vec<u8>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendPublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PrivateSpendPublicPayout>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingPublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
    protocol_fee: u128,
    block_index: Option<Nat>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SpendStatus {
    Requested,
    OutputsStaged,
    Finalized,
    FailedBeforeStateChange { reason: String },
    FailedAfterOutputsStaged { reason: String },
    VerificationPending,
    NullifierReserved,
    PayoutPending { reason: String },
    PayoutSubmitting,
    PayoutUnknown { reason: String },
    NullifierInsertUnknown { reason: String },
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpend {
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    public_payout: Option<PendingPublicPayout>,
    outputs_committed: u32,
    status: SpendStatus,
    created_at_ns: u64,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcilePendingSpendResult {
    PromotedFinalized,
    PromotedPayoutPending,
    AppendRetryScheduled,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcileNullifierResult {
    CommittedFinalized,
    CommittedPayoutPending,
    NotCommittedFailed,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum RecommendedAction {
    ReconcileNullifierInsert,
    ReconcilePendingSpend,
    RetryPrivateSpendPayout,
    ReconcilePrivateSpendPayout,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingPromotionRecord {
    spend_id: u64,
    status: SpendStatus,
    created_at_ns: u64,
    output_commitment_count: u32,
    expected_first_leaf_index: Option<u64>,
    resulting_root: Option<[u8; 32]>,
    recommended_action: RecommendedAction,
}
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
    PayoutNotPending,
    PayoutOutcomeUnknown,
    SpendNotFound,
    WrongSpendStatus,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal { Principal::anonymous() }
/// Canonical small BN254 Fr value: low byte set, high bytes zero (well below modulus).
fn fr(b: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = b;
    a
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
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

struct Stack {
    pool: Principal,
    token: Principal,
    null: Principal,
    merkle: Principal,
    controller: Principal,
    user: Principal,
}

/// Standard healthy stack: nullifier registry authorized for the pool.
fn deploy_stack(pic: &PocketIc) -> Stack {
    deploy_stack_inner(pic, true)
}
/// Stack whose nullifier registry is authorized to a WRONG principal, so the pool's
/// insert_batch traps (definite non-commit) — used to exercise FailedAfterOutputsStaged.
fn deploy_stack_broken_registry(pic: &PocketIc) -> Stack {
    deploy_stack_inner(pic, false)
}
fn deploy_stack_inner(pic: &PocketIc, registry_ok: bool) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let verifier = create_canister(pic);
    let pool = create_canister(pic);
    let null_authority = if registry_ok { pool } else { p(0xBA) };
    install(pic, null, nullifier_wasm(), &null_authority);
    install(pic, merkle, merkle_wasm(), &pool);
    pic.install_canister(verifier, stub_verifier_wasm(), candid::encode_one(None::<[u8; 32]>).unwrap(), None);
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
    pic.update_call(pool, controller, "set_verifier_canister", candid::encode_args((verifier, vec![0u8; 32])).unwrap())
        .expect("set_verifier_canister");
    Stack { pool, token, null, merkle, controller, user }
}

fn root_of(pic: &PocketIc, merkle: Principal) -> [u8; 32] {
    let v: Vec<u8> = decode(
        "get_root",
        pic.query_call(merkle, anon(), "get_root", candid::encode_args(()).unwrap()),
    );
    let mut r = [0u8; 32];
    r.copy_from_slice(&v);
    r
}
fn merkle_root(pic: &PocketIc, s: &Stack) -> [u8; 32] { root_of(pic, s.merkle) }
fn merkle_leaf_count(pic: &PocketIc, merkle: Principal) -> u64 {
    decode("leaf_count", pic.query_call(merkle, anon(), "leaf_count", candid::encode_args(()).unwrap()))
}

fn approve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: Result<Nat, ApproveErr> = decode(
        "approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
                amount,
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
}

/// Perform a real 1000-STSH deposit with the given commitment; returns the accepted
/// Merkle root (the deposit finalizes: confirmed transfer + append + accounting →
/// root accepted).
fn deposit(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> [u8; 32] {
    approve(pic, s, DENOM_1000 + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![],
                public_amount: DENOM_1000,
            })
            .unwrap(),
        ),
    );
    assert!(dep.is_ok(), "deposit must succeed; got {:?}", dep);
    merkle_root(pic, s)
}

/// A no-payout private_spend (stub verifier). input 100 == outputs 60 + 40, fee 0.
fn spend_args(anchor: [u8; 32], spend_id: u64, nullifier: [u8; 32]) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: anchor,
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![nullifier],
        output_commitments: vec![fr(0x21), fr(0x22)],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: None,
    }
}
fn run_spend(pic: &PocketIc, s: &Stack, anchor: [u8; 32], spend_id: u64, nullifier: [u8; 32]) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(spend_args(anchor, spend_id, nullifier)).unwrap()),
    )
}

fn spend_status(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<SpendStatus> {
    let rec: Option<PendingSpend> = decode(
        "get_spend_status",
        // DEF-069: get_spend_status is owner-or-controller gated — poll as the pool
        // controller (controller may read any record; anonymous can no longer).
        pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    );
    rec.map(|r| r.status)
}
fn is_accepted(pic: &PocketIc, s: &Stack, root: [u8; 32]) -> bool {
    decode(
        "is_accepted_spend_root",
        pic.query_call(s.pool, anon(), "is_accepted_spend_root", candid::encode_one(root.to_vec()).unwrap()),
    )
}
fn accepted_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "accepted_spend_root_count",
        pic.query_call(s.pool, anon(), "accepted_spend_root_count", candid::encode_args(()).unwrap()),
    )
}
fn promotions(pic: &PocketIc, s: &Stack) -> Vec<PendingPromotionRecord> {
    decode(
        "list_pending_output_promotions",
        // DEF-075: list_pending_output_promotions is controller-gated — read as controller.
        pic.query_call(s.pool, s.controller, "list_pending_output_promotions", candid::encode_args(()).unwrap()),
    )
}
fn null_contains(pic: &PocketIc, s: &Stack, nf: [u8; 32]) -> bool {
    decode(
        "contains_nullifier",
        pic.query_call(s.null, anon(), "contains_nullifier", candid::encode_one(nf.to_vec()).unwrap()),
    )
}
fn force_active_append_unknown(pic: &PocketIc, s: &Stack, mode: u8) {
    let _: () = decode(
        "force_active_append_unknown_for_test",
        pic.update_call(s.pool, s.controller, "force_active_append_unknown_for_test", candid::encode_one(mode).unwrap()),
    );
}
fn force_nullifier_unknown(pic: &PocketIc, s: &Stack, mode: u8) {
    let _: () = decode(
        "force_nullifier_insert_unknown_for_test",
        pic.update_call(s.pool, s.controller, "force_nullifier_insert_unknown_for_test", candid::encode_one(mode).unwrap()),
    );
}
fn reconcile_pending(pic: &PocketIc, s: &Stack, caller: Principal, spend_id: u64) -> Result<ReconcilePendingSpendResult, PoolError> {
    decode(
        "reconcile_pending_spend",
        pic.update_call(s.pool, caller, "reconcile_pending_spend", candid::encode_one(spend_id).unwrap()),
    )
}
fn reconcile_nullifier(pic: &PocketIc, s: &Stack, caller: Principal, spend_id: u64) -> Result<ReconcileNullifierResult, PoolError> {
    decode(
        "reconcile_nullifier_insert",
        pic.update_call(s.pool, caller, "reconcile_nullifier_insert", candid::encode_one(spend_id).unwrap()),
    )
}
fn upgrade_pool(pic: &PocketIc, s: &Stack) {
    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade must succeed");
}

/// Build a standalone Merkle canister authorized to `user`, append one commitment
/// directly, and return (canister, resulting_root). The root is a genuine Merkle
/// root produced OUTSIDE the pool's promotion logic.
fn standalone_merkle_append(pic: &PocketIc) -> [u8; 32] {
    let user = p(0xAA);
    let m = create_canister(pic);
    install(pic, m, merkle_wasm(), &user);
    let r: Result<u64, String> = decode(
        "append_commitment",
        pic.update_call(m, user, "append_commitment", candid::encode_args((fr(0x77).to_vec(), Vec::<u8>::new())).unwrap()),
    );
    assert!(r.is_ok(), "standalone append must succeed; got {:?}", r);
    root_of(pic, m)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1 — private_spend rejects an anchor not in accepted_spend_roots
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_private_spend_rejects_anchor_not_in_accepted_spend_roots() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let _accepted = deposit(&pic, &s, fr(0x01));

    // A root that was never accepted by any finalized promotion.
    let bogus = fr(0xEE);
    assert!(!is_accepted(&pic, &s, bogus), "bogus root must not be accepted");

    let r = run_spend(&pic, &s, bogus, 1, fr(0x31));
    assert_eq!(r, Err(PoolError::AnchorNotFound), "spend with non-accepted anchor must be rejected; got {:?}", r);
    assert!(spend_status(&pic, &s, 1).is_none(), "no spend record for an anchor rejected at precheck");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2 — a raw Merkle append does NOT make the root an accepted anchor
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_merkle_append_does_not_accept_root() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // A genuine Merkle root produced by a direct append outside the pool.
    let raw_root = standalone_merkle_append(&pic);
    assert_ne!(raw_root, [0u8; 32], "raw Merkle root must exist (non-zero)");
    assert!(!is_accepted(&pic, &s, raw_root), "a raw Merkle root must NOT be an accepted spend anchor");

    // The pool's own freshly-initialised Merkle empty root is likewise not accepted.
    let empty_root = merkle_root(&pic, &s);
    assert!(!is_accepted(&pic, &s, empty_root), "the empty-tree root must not be an accepted anchor");
    assert_eq!(accepted_count(&pic, &s), 0, "no roots accepted before any finalized promotion");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3 — accepted_spend_roots grows ONLY via finalized A2 promotion
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_only_finalized_promotion_adds_accepted_spend_root() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    assert_eq!(accepted_count(&pic, &s), 0, "fresh pool: no accepted roots");

    // Deposit finality → exactly one new accepted root.
    let r_dep = deposit(&pic, &s, fr(0x01));
    assert_eq!(accepted_count(&pic, &s), 1, "deposit finality adds exactly one accepted root");
    assert!(is_accepted(&pic, &s, r_dep), "the deposit's resulting root is accepted");

    // A rejected spend (bad anchor) must NOT add any root.
    let _ = run_spend(&pic, &s, fr(0xEE), 30, fr(0x33));
    assert_eq!(accepted_count(&pic, &s), 1, "a rejected spend must not add an accepted root");

    // Successful spend promotion → exactly one more accepted root.
    let r = run_spend(&pic, &s, r_dep, 31, fr(0x34));
    assert!(r.is_ok(), "spend must finalize; got {:?}", r);
    assert_eq!(spend_status(&pic, &s, 31), Some(SpendStatus::Finalized), "spend must be Finalized");
    assert_eq!(accepted_count(&pic, &s), 2, "spend promotion adds exactly one accepted root");
    assert!(is_accepted(&pic, &s, merkle_root(&pic, &s)), "the spend's resulting root is accepted");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4 — promotion (reconcile_pending_spend) rejects a spend without parent finality
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_promotion_requires_parent_nullifier_finality() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = deposit(&pic, &s, fr(0x01));
    let count_before = accepted_count(&pic, &s);

    // Drive a spend to NullifierInsertUnknown (registry outcome unresolved) — outputs
    // are staged, parent finality is NOT confirmed.
    force_nullifier_unknown(&pic, &s, 2); // registry did NOT commit, response lost
    let _ = run_spend(&pic, &s, root, 40, fr(0x40));
    assert!(matches!(spend_status(&pic, &s, 40), Some(SpendStatus::NullifierInsertUnknown { .. })), "precondition: NullifierInsertUnknown");

    // The promotion endpoint must refuse to promote a spend whose parent finality is
    // unresolved (NullifierInsertUnknown is handled by reconcile_nullifier_insert).
    let r = reconcile_pending(&pic, &s, s.controller, 40);
    assert_eq!(r, Err(PoolError::WrongSpendStatus), "promotion must be rejected without parent finality; got {:?}", r);
    assert_eq!(accepted_count(&pic, &s), count_before, "no accepted root may be published");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5 — reconcile cannot publish a root while parent finality is unresolved
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_reconcile_cannot_promote_without_parent_finality() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = deposit(&pic, &s, fr(0x01));
    let count_before = accepted_count(&pic, &s);

    force_nullifier_unknown(&pic, &s, 2); // registry did NOT commit
    let _ = run_spend(&pic, &s, root, 50, fr(0x50));
    assert!(matches!(spend_status(&pic, &s, 50), Some(SpendStatus::NullifierInsertUnknown { .. })), "precondition");

    // reconcile_nullifier_insert queries the registry: not committed → no promotion,
    // staged outputs discarded, spend failed — NO accepted root.
    let r = reconcile_nullifier(&pic, &s, s.controller, 50);
    assert_eq!(r, Ok(ReconcileNullifierResult::NotCommittedFailed), "not-committed reconcile must fail cleanly; got {:?}", r);
    assert!(matches!(spend_status(&pic, &s, 50), Some(SpendStatus::FailedAfterOutputsStaged { .. })), "spend must be FailedAfterOutputsStaged");
    assert_eq!(accepted_count(&pic, &s), count_before, "no accepted root published while parent finality unresolved");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6 — post_upgrade does NOT rebuild accepted_spend_roots from Merkle history
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_post_upgrade_does_not_rebuild_accepted_roots_from_merkle_history() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // The empty-tree root exists in Merkle history but is never accepted.
    let empty_root = merkle_root(&pic, &s);
    let r_dep = deposit(&pic, &s, fr(0x01)); // accepts exactly one root
    assert_eq!(accepted_count(&pic, &s), 1);
    assert!(!is_accepted(&pic, &s, empty_root), "pre-deposit empty root must not be accepted");

    upgrade_pool(&pic, &s);

    // Accepted set is restored from its own stable state — not rebuilt from Merkle history.
    assert_eq!(accepted_count(&pic, &s), 1, "accepted_spend_roots must survive upgrade unchanged (not rebuilt)");
    assert!(is_accepted(&pic, &s, r_dep), "the deposit root remains accepted after upgrade");
    assert!(!is_accepted(&pic, &s, empty_root), "the empty Merkle-history root must STILL not be accepted post-upgrade");

    // A spend anchored to the never-accepted empty root is rejected after upgrade.
    let r = run_spend(&pic, &s, empty_root, 60, fr(0x60));
    assert_eq!(r, Err(PoolError::AnchorNotFound), "private_spend(empty root) must reject post-upgrade; got {:?}", r);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7 — pending/limbo roots are never exposed as accepted anchors
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_pending_limbo_roots_never_exposed_as_accepted_anchors() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01));
    assert_eq!(accepted_count(&pic, &s), 1);

    // Force the promotion append to a transport-unknown outcome AFTER it commits: the
    // outputs ARE in the Merkle tree (root advanced) but the spend has NOT accepted it.
    force_active_append_unknown(&pic, &s, 1);
    let r = run_spend(&pic, &s, r_dep, 70, fr(0x70));
    assert_eq!(r, Err(PoolError::OutputAppendUnknown), "append-unknown spend returns OutputAppendUnknown; got {:?}", r);
    assert!(matches!(spend_status(&pic, &s, 70), Some(SpendStatus::ActiveAppendUnknown { .. })), "spend must be ActiveAppendUnknown");

    // The new (limbo) Merkle root must NOT be an accepted anchor, and the accepted
    // count must be unchanged (only the deposit's root is accepted).
    let limbo_root = merkle_root(&pic, &s);
    assert_ne!(limbo_root, r_dep, "the append advanced the Merkle root");
    assert!(!is_accepted(&pic, &s, limbo_root), "a pending/limbo root must NOT be an accepted spend anchor");
    assert_eq!(accepted_count(&pic, &s), 1, "no accepted root while the spend is in limbo");

    // The spend is surfaced for operator reconciliation.
    let promos = promotions(&pic, &s);
    let rec = promos.iter().find(|r| r.spend_id == 70).expect("limbo spend must be listed");
    assert_eq!(rec.recommended_action, RecommendedAction::ReconcilePendingSpend, "limbo spend recommends reconcile_pending_spend");
}

// ─────────────────────────────────────────────────────────────────────────────
// 8 — a failed parent spend's outputs never enter an accepted root (unspendable)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_failed_parent_spend_outputs_cannot_be_spent() {
    let pic = PocketIc::new();
    let s = deploy_stack_broken_registry(&pic); // insert_batch traps (definite non-commit)
    let root = deposit(&pic, &s, fr(0x01));
    let count_before = accepted_count(&pic, &s);
    let leaves_before = merkle_leaf_count(&pic, s.merkle);

    // Parent spend: outputs staged, then insert_batch definitely rejected → outputs
    // discarded, NOTHING appended, parent note NOT consumed.
    let r = run_spend(&pic, &s, root, 80, fr(0x80));
    assert!(matches!(r, Err(PoolError::TransferFailed(_))), "insert_batch trap → TransferFailed; got {:?}", r);
    assert!(matches!(spend_status(&pic, &s, 80), Some(SpendStatus::FailedAfterOutputsStaged { .. })), "spend must be FailedAfterOutputsStaged");

    // Security property: no accepted root was created, and the parent's output
    // commitments are in NO Merkle leaf — so no accepted root can ever contain them.
    assert_eq!(accepted_count(&pic, &s), count_before, "failed parent must not add an accepted root");
    assert_eq!(merkle_leaf_count(&pic, s.merkle), leaves_before, "no output leaves appended for a failed parent (no orphans)");
    assert!(!null_contains(&pic, &s, fr(0x80)), "parent nullifier must NOT be consumed (note stays spendable)");
    // (With the real verifier, a child spend of these outputs is rejected at proof
    // time because no accepted root proves their membership; at the canister layer
    // their absence from every accepted root is what guarantees that.)
}

// ─────────────────────────────────────────────────────────────────────────────
// 9 — reconcile_nullifier_insert(NotExecuted) discards staged outputs
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_nullifier_insert_unknown_not_executed_discards_staged_outputs() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = deposit(&pic, &s, fr(0x01));
    let count_before = accepted_count(&pic, &s);
    let leaves_before = merkle_leaf_count(&pic, s.merkle);

    force_nullifier_unknown(&pic, &s, 2); // registry did NOT commit, response lost
    let _ = run_spend(&pic, &s, root, 90, fr(0x90));
    assert!(matches!(spend_status(&pic, &s, 90), Some(SpendStatus::NullifierInsertUnknown { .. })), "precondition: NullifierInsertUnknown");
    // While unknown, the spend is surfaced for nullifier-insert reconciliation.
    assert!(
        promotions(&pic, &s).iter().any(|r| r.spend_id == 90 && r.recommended_action == RecommendedAction::ReconcileNullifierInsert),
        "unknown spend recommends reconcile_nullifier_insert"
    );

    let r = reconcile_nullifier(&pic, &s, s.controller, 90);
    assert_eq!(r, Ok(ReconcileNullifierResult::NotCommittedFailed), "registry did not commit → NotCommittedFailed; got {:?}", r);

    // Staged outputs discarded: the spend is terminal (FailedAfterOutputsStaged) and
    // no longer appears as a pending promotion; nothing was appended; no root accepted.
    assert!(matches!(spend_status(&pic, &s, 90), Some(SpendStatus::FailedAfterOutputsStaged { .. })), "spend must be FailedAfterOutputsStaged");
    assert!(!promotions(&pic, &s).iter().any(|r| r.spend_id == 90), "discarded spend must not be a pending promotion");
    assert_eq!(merkle_leaf_count(&pic, s.merkle), leaves_before, "no outputs appended (staged outputs discarded)");
    assert_eq!(accepted_count(&pic, &s), count_before, "no accepted root for the discarded spend");
}

// ─────────────────────────────────────────────────────────────────────────────
// 10 — ActiveAppendUnknown (committed) rolls forward to root accepted (idempotent)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_active_append_unknown_committed_rolls_forward_to_root_accepted() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01));
    assert_eq!(accepted_count(&pic, &s), 1);

    // Append committed but the response was "lost" → ActiveAppendUnknown, outputs IN tree.
    force_active_append_unknown(&pic, &s, 1);
    let r = run_spend(&pic, &s, r_dep, 100, fr(0xA0));
    assert_eq!(r, Err(PoolError::OutputAppendUnknown));
    assert!(matches!(spend_status(&pic, &s, 100), Some(SpendStatus::ActiveAppendUnknown { .. })), "precondition: ActiveAppendUnknown");
    assert_eq!(accepted_count(&pic, &s), 1, "no root accepted while in limbo");

    // Reconcile confirms via get_leaf that the exact staged outputs committed → accept
    // the resulting root and finalize.
    let rec = reconcile_pending(&pic, &s, s.controller, 100);
    assert_eq!(rec, Ok(ReconcilePendingSpendResult::PromotedFinalized), "confirmed-committed reconcile finalizes; got {:?}", rec);
    assert_eq!(spend_status(&pic, &s, 100), Some(SpendStatus::Finalized), "spend must be Finalized");
    assert_eq!(accepted_count(&pic, &s), 2, "exactly one root accepted by the promotion");
    assert!(is_accepted(&pic, &s, merkle_root(&pic, &s)), "the resulting root is accepted");

    // Idempotent: a second reconcile is a no-op (no double-accept).
    let rec2 = reconcile_pending(&pic, &s, s.controller, 100);
    assert_eq!(rec2, Err(PoolError::WrongSpendStatus), "second reconcile on a Finalized spend is a no-op error; got {:?}", rec2);
    assert_eq!(accepted_count(&pic, &s), 2, "root accepted exactly once (idempotent)");
}

// ─────────────────────────────────────────────────────────────────────────────
// 11 — ActiveAppendUnknown (NOT committed) returns to retryable; no root published
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_active_append_unknown_not_committed_returns_to_append_retryable() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01));
    assert_eq!(accepted_count(&pic, &s), 1);

    // Append NOT committed and the response was lost → ActiveAppendUnknown, outputs absent.
    force_active_append_unknown(&pic, &s, 2);
    let r = run_spend(&pic, &s, r_dep, 110, fr(0xB0));
    assert_eq!(r, Err(PoolError::OutputAppendUnknown));
    assert!(matches!(spend_status(&pic, &s, 110), Some(SpendStatus::ActiveAppendUnknown { .. })), "precondition: ActiveAppendUnknown");

    // Reconcile: get_leaf shows the outputs did NOT commit → return to retryable; NO
    // root published; parent nullifier remains finalized (never rolled back).
    let rec = reconcile_pending(&pic, &s, s.controller, 110);
    assert_eq!(rec, Ok(ReconcilePendingSpendResult::AppendRetryScheduled), "not-committed reconcile reschedules the append; got {:?}", rec);
    assert_eq!(spend_status(&pic, &s, 110), Some(SpendStatus::NullifierFinalizedOutputsPending), "spend returns to the retryable state");
    assert_eq!(accepted_count(&pic, &s), 1, "no accepted root published");
    assert!(null_contains(&pic, &s, fr(0xB0)), "parent nullifier remains finalized (never rolled back)");

    // Clearing the fault and reconciling again rolls forward to finalization.
    force_active_append_unknown(&pic, &s, 0);
    let rec2 = reconcile_pending(&pic, &s, s.controller, 110);
    assert_eq!(rec2, Ok(ReconcilePendingSpendResult::PromotedFinalized), "retry now promotes; got {:?}", rec2);
    assert_eq!(spend_status(&pic, &s, 110), Some(SpendStatus::Finalized));
    assert_eq!(accepted_count(&pic, &s), 2, "exactly one root accepted by the eventual promotion");
}

// ─────────────────────────────────────────────────────────────────────────────
// 12 — ActiveAppendUnknown with ambiguous Merkle state does NOT accept a root
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_active_append_unknown_ambiguous_does_not_accept_root() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01)); // leaf 0; expected_first for the spend = 1

    // Spend's append is forced not-committed → ActiveAppendUnknown, expected_first = 1.
    // P-ROOT: the pool-wide append lease is RETAINED at AppendUnknown.
    force_active_append_unknown(&pic, &s, 2);
    let r = run_spend(&pic, &s, r_dep, 120, fr(0xC0));
    assert_eq!(r, Err(PoolError::OutputAppendUnknown));
    assert!(matches!(spend_status(&pic, &s, 120), Some(SpendStatus::ActiveAppendUnknown { .. })), "precondition: ActiveAppendUnknown");
    force_active_append_unknown(&pic, &s, 0);

    // P-ROOT rework: a live interleaving append can no longer land while this
    // spend's append is unresolved (the pool-wide lease forbids it — that
    // interleaving WAS C-ROOT-1), so the ambiguous Merkle shape is STAGED: the
    // spend's staged-outputs record is overwritten to claim leaf 0 with output
    // bytes that differ from the deposit leaf actually occupying slot 0. The
    // reconcile's get_leaf(0) then sees a foreign leaf with the count advanced
    // past expected_first — the ambiguous shape.
    let _: () = decode(
        "inject_staged_outputs_for_test",
        pic.update_call(s.pool, s.controller, "inject_staged_outputs_for_test",
            candid::encode_args((120u64, vec![fr(0xC1), fr(0xC2)], Some(0u64))).unwrap()),
    );
    let count_before_reconcile = accepted_count(&pic, &s);

    let rec = reconcile_pending(&pic, &s, s.controller, 120);
    assert_eq!(rec, Err(PoolError::AmbiguousMerkleState), "ambiguous Merkle state must not promote; got {:?}", rec);
    // No root accepted for the ambiguous spend; the spend stays ActiveAppendUnknown.
    assert!(matches!(spend_status(&pic, &s, 120), Some(SpendStatus::ActiveAppendUnknown { .. })), "spend stays ActiveAppendUnknown (operator escalation)");
    assert_eq!(accepted_count(&pic, &s), count_before_reconcile, "no root accepted from the ambiguous spend");
    assert!(null_contains(&pic, &s, fr(0xC0)), "parent nullifier remains finalized");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-049 — promote_finalized_outputs claim-before-await + finalization idempotency
//
// The promotion claim (ActiveAppendInFlight) is now written synchronously between the
// eligibility gate and the first `.await` (previously two read-only Merkle snapshot
// fetches sat in that window, so two concurrent controller calls could both pass the
// gate, both append, and double-count accounting). finalize_promotion additionally
// guards accounting so it can never apply twice for one spend_id.
//
// PocketIC is single-threaded (no true concurrency), so these are state-machine tests:
// each proves the *guarantee* the fix provides — a second promotion attempt for the
// same spend_id cannot append a second root or apply accounting a second time, and
// ineligible states reject cleanly.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode(
        "get_accounting_state",
        // DEF-076: get_accounting_state is controller-gated — read as controller.
        pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()),
    )
}

/// A payout private_spend (stub verifier): input == out + public_amount; fee 0.
/// public_amount must exceed DEFAULT_FEE so the payout precondition passes, and gives a
/// non-zero escrow/liability debit so "accounting applied exactly once" is observable.
fn payout_spend_args(
    anchor: [u8; 32],
    spend_id: u64,
    nullifier: [u8; 32],
    recipient: Principal,
    public_amount: u128,
) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: anchor,
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![nullifier],
        output_commitments: vec![fr(0x31), fr(0x32)],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: recipient,
            destination_subaccount: None,
            public_amount,
        }),
    }
}
fn run_payout_spend(pic: &PocketIc, s: &Stack, args: PrivateSpendArgs) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()),
    )
}

// DEF049-A — a second promotion attempt for a spend whose append is in flight/confirmed
// cannot append or apply accounting twice. Uses a payout spend so the escrow/liability
// debit is non-zero and observable.
#[test]
fn def049_a_second_promotion_cannot_double_append_or_account() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01));
    assert_eq!(accepted_count(&pic, &s), 1);
    let recipient = p(0xD9);
    let public_amount: u128 = 60_000; // > DEFAULT_FEE so the payout precondition passes

    // Append committed but the pool's response was lost → ActiveAppendUnknown (an
    // in-flight promotion whose outcome the pool cannot directly observe). No accounting
    // has been applied yet (that happens at finalize, not reached here).
    force_active_append_unknown(&pic, &s, 1);
    let r = run_payout_spend(&pic, &s, payout_spend_args(r_dep, 200, fr(0xD0), recipient, public_amount));
    assert_eq!(r, Err(PoolError::OutputAppendUnknown));
    assert!(
        matches!(spend_status(&pic, &s, 200), Some(SpendStatus::ActiveAppendUnknown { .. })),
        "precondition: in-flight/unknown promotion"
    );
    let acct_pre = accounting(&pic, &s);

    // First reconcile confirms via get_leaf that the staged outputs committed → finalize.
    // Accounting (escrow_backing / private_liability debit by public_amount) is applied
    // EXACTLY here; the outstanding payout leaves the spend PayoutPending.
    let rec1 = reconcile_pending(&pic, &s, s.controller, 200);
    assert_eq!(
        rec1,
        Ok(ReconcilePendingSpendResult::PromotedPayoutPending),
        "first reconcile promotes + applies accounting; got {:?}",
        rec1
    );
    assert!(
        matches!(spend_status(&pic, &s, 200), Some(SpendStatus::PayoutPending { .. })),
        "spend is PayoutPending after promotion"
    );
    let acct_after_first = accounting(&pic, &s);
    let roots_after_first = accepted_count(&pic, &s);
    let leaves_after_first = merkle_leaf_count(&pic, s.merkle);
    assert_eq!(roots_after_first, 2, "exactly one root accepted by the promotion");
    assert_eq!(
        acct_after_first.escrow_backing,
        acct_pre.escrow_backing - public_amount,
        "escrow debited by public_amount exactly once"
    );
    assert_eq!(
        acct_after_first.private_liability,
        acct_pre.private_liability - public_amount,
        "private liability debited by public_amount exactly once"
    );

    // Second promotion attempt for the same spend_id: the spend is past finality
    // (PayoutPending), so the promotion gate rejects it — no second append, no second
    // accounting debit.
    let rec2 = reconcile_pending(&pic, &s, s.controller, 200);
    assert_eq!(
        rec2,
        Err(PoolError::WrongSpendStatus),
        "second promotion attempt rejected cleanly; got {:?}",
        rec2
    );
    assert_eq!(
        accounting(&pic, &s),
        acct_after_first,
        "accounting identical after the second attempt (applied exactly once)"
    );
    assert_eq!(accepted_count(&pic, &s), roots_after_first, "no second root accepted");
    assert_eq!(merkle_leaf_count(&pic, s.merkle), leaves_after_first, "no second append");
}

// DEF049-B — a completed promotion is idempotent: re-driving promotion on a Finalized
// spend is a clean no-op with no second root, no second append, no second accounting.
#[test]
fn def049_b_completed_promotion_is_idempotent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01));

    // A normal (no-payout) spend finalizes inline (promote → finalize; accounting once).
    let r = run_spend(&pic, &s, r_dep, 210, fr(0xE0));
    assert_eq!(r, Ok(()), "normal spend finalizes; got {:?}", r);
    assert_eq!(spend_status(&pic, &s, 210), Some(SpendStatus::Finalized));
    let acct_after = accounting(&pic, &s);
    let roots_after = accepted_count(&pic, &s);
    let leaves_after = merkle_leaf_count(&pic, s.merkle);

    let rec = reconcile_pending(&pic, &s, s.controller, 210);
    assert_eq!(
        rec,
        Err(PoolError::WrongSpendStatus),
        "completed promotion re-attempt rejects cleanly; got {:?}",
        rec
    );
    assert_eq!(spend_status(&pic, &s, 210), Some(SpendStatus::Finalized), "status unchanged");
    assert_eq!(accounting(&pic, &s), acct_after, "accounting identical (applied exactly once)");
    assert_eq!(accepted_count(&pic, &s), roots_after, "no second root accepted");
    assert_eq!(merkle_leaf_count(&pic, s.merkle), leaves_after, "no second append");
}

// DEF049-C — promotion on an ineligible (non-promotion) state rejects cleanly with no
// mutation. NullifierInsertUnknown is a pre-promotion state handled by
// reconcile_nullifier_insert, never by the promotion path.
#[test]
fn def049_c_ineligible_state_rejected_cleanly() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let r_dep = deposit(&pic, &s, fr(0x01));
    let roots_before = accepted_count(&pic, &s);
    let leaves_before = merkle_leaf_count(&pic, s.merkle);

    // Registry did NOT commit and the response was lost → NullifierInsertUnknown.
    force_nullifier_unknown(&pic, &s, 2);
    let _ = run_spend(&pic, &s, r_dep, 220, fr(0xF0));
    assert!(
        matches!(spend_status(&pic, &s, 220), Some(SpendStatus::NullifierInsertUnknown { .. })),
        "precondition: NullifierInsertUnknown"
    );
    let acct_before = accounting(&pic, &s);

    let rec = reconcile_pending(&pic, &s, s.controller, 220);
    assert_eq!(
        rec,
        Err(PoolError::WrongSpendStatus),
        "ineligible state rejected by promotion; got {:?}",
        rec
    );
    assert!(
        matches!(spend_status(&pic, &s, 220), Some(SpendStatus::NullifierInsertUnknown { .. })),
        "status unchanged"
    );
    assert_eq!(accounting(&pic, &s), acct_before, "no accounting change");
    assert_eq!(accepted_count(&pic, &s), roots_before, "no root accepted");
    assert_eq!(merkle_leaf_count(&pic, s.merkle), leaves_before, "no outputs appended");
}
