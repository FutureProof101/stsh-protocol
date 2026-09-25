// =============================================================================
// STSH — Query privacy hardening tests (PocketIC)
// Phase A: DEF-069 (get_spend_status), DEF-070 (get_deposit_status),
//          DEF-071 (get_withdrawal_status)
// =============================================================================
//
// These prove the access-control contract for the pool's status queries:
//   - get_spend_status / get_deposit_status return Some(record) ONLY to the
//     originating principal (submitter / depositor) or a stored controller.
//   - Any other caller — including anonymous — gets None, indistinguishable from
//     record-not-found (no distinct "unauthorized" error).
//   - get_withdrawal_status is controller-only (DEF-071 pre-enable blocker).
//   - private_spend / shield_deposit reject anonymous callers at the entry point.
//
// Only the pool (testing Wasm) is deployed: inject endpoints seed PENDING_SPENDS /
// PENDING_DEPOSITS directly, and the gated queries / anonymous-rejection checks
// never touch the token / merkle / nullifier canisters, so dummy principals for
// those dependencies are sufficient.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release <all production canisters>
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test privacy_query_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn pool_test_wasm() -> Vec<u8> {
    let path = env!("POOL_TEST_WASM");
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("Cannot read shielded_pool_test Wasm at {}: {}", path, e))
}

const DENOM: u128 = 1_000 * 100_000_000; // 1,000 STSH — DENOMINATIONS[0] (A6.6)

// ── PocketIC helpers ────────────────────────────────────────────────────────

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
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

// ── Mirrors (field names/order must match the canister Candid types) ──────────

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
    fee: Option<u128>,
    status: SpendStatus,
    created_at_ns: u64,
    submitter: Option<Principal>, // DEF-069
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending,
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
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
    expected_leaf_index: Option<u64>,
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
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
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
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    AnonymousCaller, // DEF-069/070/071
}

// ── Deploy + harness ──────────────────────────────────────────────────────────

/// Deploy ONLY the pool (testing Wasm). Dependency principals are dummies — they
/// are never called by inject / status-query / anonymous-rejection paths.
fn deploy_pool(pic: &PocketIc) -> (Principal, Principal) {
    let controller = p(0xC0);
    let pool = create_canister(pic);
    install(
        pic,
        pool,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: p(0x10),
            nullifier_canister: p(0x11),
            merkle_canister: p(0x12),
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    (pool, controller)
}

fn make_spend(spend_id: u64, submitter: Option<Principal>) -> PendingSpend {
    PendingSpend {
        spend_id,
        nullifiers: vec![[1u8; 32]],
        output_commitments: vec![[2u8; 32], [3u8; 32]],
        public_payout: None,
        outputs_committed: 0,
        fee: None,
        status: SpendStatus::Finalized,
        created_at_ns: 0,
        submitter,
    }
}

fn inject_spend(pic: &PocketIc, pool: Principal, controller: Principal, spend: &PendingSpend) -> u64 {
    decode(
        "inject_pending_spend_for_test",
        pic.update_call(
            pool,
            controller,
            "inject_pending_spend_for_test",
            candid::encode_one(spend).unwrap(),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn inject_deposit_owner(
    pic: &PocketIc,
    pool: Principal,
    controller: Principal,
    note_commitment: [u8; 32],
    private_balance: u128,
    // The INJECTOR's owner argument stays a bare Principal — only the RECORD's
    // `depositor` field widened to `opt principal`. Passing an Option here is a
    // Candid subtyping error at the boundary, not a type error in Rust, so it
    // only shows up as a canister trap at runtime.
    depositor: Principal,
    status: DepositStatus,
) {
    let _: () = decode(
        "inject_pending_deposit_with_owner_for_test",
        pic.update_call(
            pool,
            controller,
            "inject_pending_deposit_with_owner_for_test",
            candid::encode_args((note_commitment, private_balance, depositor, status)).unwrap(),
        ),
    );
}

fn spend_status_as(pic: &PocketIc, pool: Principal, caller: Principal, spend_id: u64) -> Option<PendingSpend> {
    decode(
        "get_spend_status",
        pic.query_call(pool, caller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    )
}

fn deposit_status_as(pic: &PocketIc, pool: Principal, caller: Principal, commitment: [u8; 32]) -> Option<PendingDeposit> {
    decode(
        "get_deposit_status",
        pic.query_call(pool, caller, "get_deposit_status", candid::encode_one(commitment).unwrap()),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-069 — get_spend_status access control
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_spend_status_submitter_can_see_own_record() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    inject_spend(&pic, pool, controller, &make_spend(1, Some(alice)));

    let rec = spend_status_as(&pic, pool, alice, 1);
    assert!(rec.is_some(), "submitter must see own spend record");
    assert_eq!(rec.unwrap().submitter, Some(alice));
}

#[test]
fn test_spend_status_controller_can_see_any_record() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    inject_spend(&pic, pool, controller, &make_spend(2, Some(alice)));

    // Controller-authorized read of another principal's record.
    let rec = spend_status_as(&pic, pool, controller, 2);
    assert!(rec.is_some(), "controller must be able to read any spend record");
}

#[test]
fn test_spend_status_third_party_gets_none() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    let bob = p(0xB2);
    inject_spend(&pic, pool, controller, &make_spend(3, Some(alice)));

    assert!(
        spend_status_as(&pic, pool, bob, 3).is_none(),
        "a non-owner, non-controller caller must get None (indistinguishable from not-found)"
    );
}

#[test]
fn test_spend_status_anonymous_gets_none() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    inject_spend(&pic, pool, controller, &make_spend(4, Some(alice)));

    assert!(
        spend_status_as(&pic, pool, anon(), 4).is_none(),
        "anonymous caller must get None"
    );
}

#[test]
fn test_spend_status_none_submitter_controller_only() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    // Pre-migration record: submitter == None.
    inject_spend(&pic, pool, controller, &make_spend(5, None));

    assert!(
        spend_status_as(&pic, pool, controller, 5).is_some(),
        "controller must read a submitter:None record"
    );
    assert!(
        spend_status_as(&pic, pool, alice, 5).is_none(),
        "a user principal must NOT read a submitter:None record"
    );
}

#[test]
fn test_spend_status_none_submitter_anonymous_gets_none() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    inject_spend(&pic, pool, controller, &make_spend(6, None));

    // Guards against an unwrap_or(anonymous) bug: None must not match anonymous.
    assert!(
        spend_status_as(&pic, pool, anon(), 6).is_none(),
        "anonymous must NOT read a submitter:None record"
    );
}

#[test]
fn test_spend_status_anonymous_submitter_is_not_public() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    // Edge case: a record whose submitter is literally the anonymous principal.
    inject_spend(&pic, pool, controller, &make_spend(7, Some(anon())));

    // The is_authenticated guard inside can_read_owned_or_controller must reject this.
    assert!(
        spend_status_as(&pic, pool, anon(), 7).is_none(),
        "anonymous must NOT read a submitter:Some(anonymous) record"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-070 — get_deposit_status access control
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_deposit_status_depositor_can_see_own_record() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    let c = [0x11u8; 32];
    inject_deposit_owner(&pic, pool, controller, c, 100, alice, DepositStatus::TransferConfirmedCommitmentPending);

    let rec = deposit_status_as(&pic, pool, alice, c);
    assert!(rec.is_some(), "depositor must see own deposit record");
    assert_eq!(rec.unwrap().depositor, Some(alice));
}

#[test]
fn test_deposit_status_controller_can_see_any_record() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    let c = [0x12u8; 32];
    inject_deposit_owner(&pic, pool, controller, c, 100, alice, DepositStatus::TransferConfirmedCommitmentPending);

    assert!(
        deposit_status_as(&pic, pool, controller, c).is_some(),
        "controller must be able to read any deposit record"
    );
}

#[test]
fn test_deposit_status_third_party_gets_none() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let alice = p(0xA1);
    let bob = p(0xB2);
    let c = [0x13u8; 32];
    inject_deposit_owner(&pic, pool, controller, c, 100, alice, DepositStatus::TransferConfirmedCommitmentPending);

    assert!(
        deposit_status_as(&pic, pool, bob, c).is_none(),
        "a non-depositor, non-controller caller must get None"
    );
}

#[test]
fn test_deposit_status_anonymous_depositor_is_not_public() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let c = [0x14u8; 32];
    // Edge case: depositor field is the anonymous principal.
    inject_deposit_owner(&pic, pool, controller, c, 100, anon(), DepositStatus::TransferConfirmedCommitmentPending);

    assert!(
        deposit_status_as(&pic, pool, anon(), c).is_none(),
        "anonymous must NOT read a deposit whose depositor is anonymous"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-069 / DEF-070 — anonymous rejection at the update-call creation paths
// ─────────────────────────────────────────────────────────────────────────────

fn anon_spend_args() -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id: 100,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: [0u8; 32],
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![[9u8; 32]],
        output_commitments: vec![[8u8; 32], [7u8; 32]],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: None,
    }
}

#[test]
fn test_private_spend_rejects_anonymous_caller() {
    let pic = PocketIc::new();
    let (pool, _controller) = deploy_pool(&pic);

    let r: Result<(), PoolError> = decode(
        "private_spend",
        pic.update_call(pool, anon(), "private_spend", candid::encode_one(anon_spend_args()).unwrap()),
    );
    assert!(
        matches!(r, Err(PoolError::AnonymousCaller)),
        "private_spend must reject the anonymous caller with AnonymousCaller; got {:?}",
        r
    );
}

#[test]
fn test_shield_deposit_rejects_anonymous_caller() {
    let pic = PocketIc::new();
    let (pool, _controller) = deploy_pool(&pic);

    let args = ShieldDepositArgs {
        note_commitment: [0u8; 32],
        encrypted_payload: vec![],
        public_amount: DENOM,
    };
    let r: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(pool, anon(), "shield_deposit", candid::encode_one(args).unwrap()),
    );
    assert!(
        matches!(r, Err(PoolError::AnonymousCaller)),
        "shield_deposit must reject the anonymous caller with AnonymousCaller; got {:?}",
        r
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-071 — get_withdrawal_status is controller-only
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_get_withdrawal_status_non_controller_gets_none() {
    let pic = PocketIc::new();
    let (pool, _controller) = deploy_pool(&pic);
    let bob = p(0xB2);

    // Withdraw is fail-closed (WITHDRAWALS is empty); the controller-only gate keeps
    // it None for a non-controller. `opt u64` leniently decodes the null `opt
    // PendingWithdrawal` reply as None.
    let r: Option<u64> = decode(
        "get_withdrawal_status",
        pic.query_call(pool, bob, "get_withdrawal_status", candid::encode_one(0u64).unwrap()),
    );
    assert!(r.is_none(), "non-controller must get None from get_withdrawal_status");
}
