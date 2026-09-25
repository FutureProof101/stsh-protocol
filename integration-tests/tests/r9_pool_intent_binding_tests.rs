// =============================================================================
// STSH — R-9 pool intent binding (PocketIC)
// =============================================================================
//
// Three properties, all previously unbound:
//
//   B-3-INTENT-DESTINATION / B-3-INTENT-SUBACCOUNT — a private_spend retry that
//     reuses a live spend_id but carries a DIFFERENT payout destination (resp.
//     destination_subaccount) must be refused as a conflicting intent
//     (IdempotencyKeyConflict), NOT folded into the in-flight record's own
//     duplicate arm (DuplicateSpendId). The existing unit test
//     `test_prec_spend_intent_fingerprint` hardcodes both fields and is
//     structurally blind to deleting either comparison in `spend_intent_matches`.
//
//   B-6-STAGE-BEFORE-FINALIZE — ARCHITECTURE.md law 3. Output commitments stay STAGED
//     until the parent nullifier reservation reaches finality via insert_batch;
//     the Merkle append happens only after that. Driven from code against the
//     real Merkle leaf count, not asserted in a comment.
//
//   Source-side testing-surface census — every `#[cfg(feature = "testing")]`
//     `#[query]`/`#[update]` in the pool must carry the `_for_test` marker the
//     production-leak sweep in eager_cell_feature_isolation_tests.rs relies on.
//
// Harness: `integration-tests` has NO shared harness module, so the PocketIC
// helpers/type mirrors below are PORTED BY COPY from the only other suite that
// drives the same deposit → anchor → stub-verifier → private_spend → insert_batch
// path (integration-tests/tests/active_root_finality_tests.rs), with two
// deliberate corrections noted at their definitions (full PendingSpend mirror,
// six-field PendingPublicPayout).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): run_gate.sh phase 1 +
// phase 2. POCKET_IC_BIN must be set.
// =============================================================================

#![allow(dead_code)]


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
    /// B1/QA-DEF-023 ledger-transfer dedup identity (lib.rs:2578).
    ledger_created_at_time_ns: Option<u64>,
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
/// FULL mirror of the production `PendingSpend` (canisters/shielded-pool/src/lib.rs),
/// field-for-field — this suite ENCODES it for `inject_pending_spend_for_test`, so
/// unlike the decode-only mirror in active_root_finality_tests.rs it cannot omit fields.
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
    submitter: Option<Principal>,
    finalized_at_ns: Option<u64>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
    spend_fee_mode: Option<SpendFeeMode>,
    fee_split_ops: Option<u128>,
    fee_split_insurance: Option<u128>,
    fee_split_staking: Option<u128>,
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
fn run_spend_no_payout(pic: &PocketIc, s: &Stack, anchor: [u8; 32], spend_id: u64, nullifier: [u8; 32]) -> Result<(), PoolError> {
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

// ── SpendFeeMode mirror (fee snapshot field of PendingSpend) ─────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode {
    FixedStsh,
}

// ── AC-1 / AC-2: B-3 intent binding ─────────────────────────────────────────

/// Drives one private_spend retry through the REAL entrypoint. Returns whatever
/// private_spend returns; the caller varies destination / destination_subaccount
/// across two calls and asserts on the divergence.
///
/// Named `spend_intent_matches` per house convention: `property` in
/// BINDING_REGISTRY.toml names the symbol the TEST invokes, not the
/// canister-internal fn under study (precedent: a7_exit_fee_symmetry_tests.rs:510).
/// This deliberately shadows the canister-internal fn's name — it is not a
/// collision to "fix".
fn spend_intent_matches(
    pic: &PocketIc,
    s: &Stack,
    spend_id: u64,
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(
            s.pool,
            s.user,
            "private_spend",
            candid::encode_one(spend_args_no_anchor(spend_id, destination, destination_subaccount)).unwrap(),
        ),
    )
}

/// AC-1/AC-2 never reach insert_batch — the idempotency check short-circuits
/// before any anchor/verifier logic runs — so anchor/nullifier are placeholders.
fn spend_args_no_anchor(
    spend_id: u64,
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: [0u8; 32],
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
        nullifiers: vec![[0u8; 32]],
        output_commitments: vec![fr(0x21), fr(0x22)],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout { destination, destination_subaccount, public_amount: 1 }),
    }
}

/// Seeds an in-flight (VerificationPending) PendingSpend owned by `s.user`,
/// whose payout intent is (destination, subaccount).
fn seed_pending_spend(
    pic: &PocketIc,
    s: &Stack,
    spend_id: u64,
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
) {
    let seed = PendingSpend {
        spend_id,
        nullifiers: vec![[0u8; 32]],
        output_commitments: vec![fr(0x21), fr(0x22)],
        public_payout: Some(PendingPublicPayout {
            destination,
            destination_subaccount,
            public_amount: 1,
            protocol_fee: 0,
            block_index: None,
            ledger_created_at_time_ns: None,
        }),
        outputs_committed: 0,
        fee: Some(0),
        status: SpendStatus::VerificationPending,
        created_at_ns: 0,
        submitter: Some(s.user),
        finalized_at_ns: None,
        fee_model_version: None,
        params_epoch: None,
        spend_fee_mode: None,
        fee_split_ops: None,
        fee_split_insurance: None,
        fee_split_staking: None,
    };
    let _: u64 = decode(
        "inject_pending_spend_for_test",
        pic.update_call(s.pool, s.controller, "inject_pending_spend_for_test", candid::encode_one(seed).unwrap()),
    );
}

fn pending_spend_intent(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<(Principal, Option<[u8; 32]>)> {
    decode(
        "pending_spend_intent_for_test",
        pic.query_call(s.pool, s.controller, "pending_spend_intent_for_test", candid::encode_one(spend_id).unwrap()),
    )
}

// BINDING: B-3-INTENT-DESTINATION
#[test]
fn b3_intent_destination_divergence_retry_rejected() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let spend_id = 900u64;

    seed_pending_spend(&pic, &s, spend_id, p(0xA1), None);

    // The identical retry from VerificationPending is NOT "accepted as
    // idempotent": it falls into the status catch-all (lib.rs, the
    // `_ => Err(DuplicateSpendId)` arm) and returns DuplicateSpendId. That is
    // the code's actual behaviour, asserted directly.
    let err_identical = spend_intent_matches(&pic, &s, spend_id, p(0xA1), None).unwrap_err();

    // The RED arm: a DIFFERENT destination under the same spend_id must be
    // refused as a conflicting intent — a DIFFERENT error variant.
    let err_diverging = spend_intent_matches(&pic, &s, spend_id, p(0xA2), None).unwrap_err();

    assert_eq!(
        err_diverging,
        PoolError::IdempotencyKeyConflict,
        "a different destination under the same spend_id must be refused as a conflicting intent"
    );
    assert_ne!(
        err_identical, err_diverging,
        "an identical retry (DuplicateSpendId) and a diverging retry (IdempotencyKeyConflict) \
         must land in DIFFERENT error arms — under the mutation (destination comparison \
         deleted) both collapse to DuplicateSpendId and this assertion REDs"
    );

    // Consistency tripwire, not this row's RED arm: both refusal paths return
    // before any write to PENDING_SPENDS.
    let (stored_dest, _) =
        pending_spend_intent(&pic, &s, spend_id).expect("record must still exist and carry a public_payout");
    assert_eq!(stored_dest, p(0xA1), "stored intent must remain p(0xA1) (consistency check)");
}

// BINDING: B-3-INTENT-SUBACCOUNT
#[test]
fn b3_intent_subaccount_divergence_retry_rejected() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let spend_id = 901u64;

    seed_pending_spend(&pic, &s, spend_id, p(0xA1), None);

    let err_identical = spend_intent_matches(&pic, &s, spend_id, p(0xA1), None).unwrap_err();
    let err_diverging = spend_intent_matches(&pic, &s, spend_id, p(0xA1), Some([1u8; 32])).unwrap_err();

    assert_eq!(
        err_diverging,
        PoolError::IdempotencyKeyConflict,
        "a different destination_subaccount under the same spend_id must be refused as a conflicting intent"
    );
    assert_ne!(
        err_identical, err_diverging,
        "identical vs. diverging retries must land in different error arms; the mutation \
         (subaccount comparison deleted) collapses both to DuplicateSpendId"
    );

    let (_, stored_sub) =
        pending_spend_intent(&pic, &s, spend_id).expect("record must still exist and carry a public_payout");
    assert_eq!(stored_sub, None, "stored intent must remain None (consistency check)");
}

// ── AC-3: B-6-STAGE-BEFORE-FINALIZE (ARCHITECTURE.md law 3) ───────────────────────

/// A no-payout spend whose output commitments are caller-chosen, so the two legs
/// of the order test stage DISTINCT commitments (CTO AMBER-O) rather than relying
/// on an argument that identical values cannot collide.
fn spend_args_with_outputs(
    anchor: [u8; 32],
    spend_id: u64,
    nullifier: [u8; 32],
    outputs: [[u8; 32]; 2],
) -> PrivateSpendArgs {
    let mut a = spend_args(anchor, spend_id, nullifier);
    a.output_commitments = vec![outputs[0], outputs[1]];
    a
}

/// Runs one full deposit-backed spend under a forced `insert_batch` outcome
/// (mode 0 = real registry call, succeeds; mode 2 = call skipped, so the registry
/// provably never sees it) and returns the Merkle tree's leaf count afterward.
///
/// Named per house convention: `property` in BINDING_REGISTRY.toml names this
/// local helper, which the bound test invokes twice with differing `mode`.
fn spend_under_finality_mode(
    pic: &PocketIc,
    s: &Stack,
    anchor: [u8; 32],
    mode: u8,
    spend_id: u64,
    nullifier: [u8; 32],
    outputs: [[u8; 32]; 2],
) -> u64 {
    force_nullifier_unknown(pic, s, mode);
    let _: Result<(), PoolError> = decode(
        "private_spend",
        pic.update_call(
            s.pool,
            s.user,
            "private_spend",
            candid::encode_one(spend_args_with_outputs(anchor, spend_id, nullifier, outputs)).unwrap(),
        ),
    );
    // Reset the hook to its default (real registry call) for hygiene.
    force_nullifier_unknown(pic, s, 0);
    merkle_leaf_count(pic, s.merkle)
}

// BINDING: B-6-STAGE-BEFORE-FINALIZE
#[test]
fn test_merkle_append_only_after_nullifier_finality() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let anchor = deposit(&pic, &s, fr(0x01));

    let leaves_before = merkle_leaf_count(&pic, s.merkle);

    // Mode 2 FIRST: insert_batch is skipped entirely (the registry provably never
    // runs it) — under correct code no Merkle append can have occurred.
    let leaves_after_mode2 =
        spend_under_finality_mode(&pic, &s, anchor, 2, 950, fr(0x40), [fr(0x21), fr(0x22)]);
    assert!(
        matches!(spend_status(&pic, &s, 950), Some(SpendStatus::NullifierInsertUnknown { .. })),
        "precondition: parent nullifier finality must be UNRESOLVED under mode 2; got {:?}",
        spend_status(&pic, &s, 950)
    );

    // Mode 0 SECOND: a different spend_id / nullifier and DISTINCT output
    // commitments (AMBER-O) — the real insert_batch call succeeds, so this spend
    // finalizes and its 2 outputs are appended.
    let leaves_after_mode0 =
        spend_under_finality_mode(&pic, &s, anchor, 0, 951, fr(0x41), [fr(0x31), fr(0x32)]);

    // Order arm: the mode-2 spend, whose parent finality never resolved, added
    // NOTHING to the Merkle tree — this is law 3 itself. Reordering the append
    // ahead of insert_batch (the CLOSED QA-DEF-034 regression) REDs this.
    assert_eq!(
        leaves_after_mode2, leaves_before,
        "the Merkle tree's leaf count must be UNCHANGED after a spend whose parent \
         nullifier finality is unresolved (NullifierInsertUnknown) — output commitments \
         are staged, never appended ahead of insert_batch success (law 3)"
    );
    // Inequality/rejection arm (bindings-lint `asserts_inequality` predicate):
    // a finalized spend (mode 0) must differ from an unresolved one (mode 2).
    assert_ne!(
        leaves_after_mode0, leaves_after_mode2,
        "a spend whose parent nullifier DID finalize (mode 0) must show a DIFFERENT \
         leaf count from one whose finality is still unresolved (mode 2)"
    );
}

// ── AC-6 (dispatch §9): source-side testing-surface census ──────────────────
//
// `POOL_TEST_EXPORTS` (eager_cell_feature_isolation_tests.rs) is a CURATED list,
// and the production-leak sweep next to it keys off the `_for_test` marker in
// the symbol name. Both therefore depend on a naming convention that nothing
// enforces at the source. This test does: every `#[cfg(feature = "testing")]`
// `#[query]` / `#[update]` fn in the pool must end in `_for_test`. Drop the
// suffix on any one of them and the marker sweep silently stops covering it.

const POOL_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../canisters/shielded-pool/src/lib.rs");

#[test]
fn pool_testing_gated_endpoints_all_carry_the_for_test_marker() {
    let src = std::fs::read_to_string(POOL_SRC).unwrap_or_else(|e| panic!("cannot read {POOL_SRC}: {e}"));
    let lines: Vec<&str> = src.lines().collect();

    let mut endpoints: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() != "#[cfg(feature = \"testing\")]" {
            continue;
        }
        // Walk forward over attributes / comments / blank lines to the item.
        let mut j = i + 1;
        let mut is_endpoint = false;
        while j < lines.len() {
            let t = lines[j].trim();
            if t == "#[query]" || t == "#[update]" {
                is_endpoint = true;
            } else if !(t.starts_with("#[") || t.starts_with("//") || t.is_empty()) {
                break;
            }
            j += 1;
        }
        if !is_endpoint || j >= lines.len() {
            continue;
        }
        let mut item = lines[j].trim();
        for kw in ["pub ", "async "] {
            if let Some(rest) = item.strip_prefix(kw) {
                item = rest.trim_start();
            }
        }
        if let Some(rest) = item.strip_prefix("fn ") {
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if !name.is_empty() {
                endpoints.push(name);
            }
        }
    }

    // Non-vacuity: the scan must actually find the pool's testing surface, and it
    // must include the hook R-9 itself adds.
    assert!(
        endpoints.len() >= 50,
        "census scan found only {} testing-gated endpoints in the pool — the scan, not the \
         pool, is what broke (the parse no longer matches the source shape)",
        endpoints.len()
    );
    // Anchored on a LONG-STANDING hook, deliberately not on the one R-9 adds: the
    // anchor proves the scan reaches real pool source, and must not itself fire when
    // the mutation under test is a dropped suffix on the new query.
    assert!(
        endpoints.iter().any(|n| n == "inject_pending_spend_for_test"),
        "census scan did not find inject_pending_spend_for_test — the scan is not reading \
         the real pool source, so a missing suffix elsewhere would also go unseen. \
         Found: {endpoints:?}"
    );

    let unmarked: Vec<&String> = endpoints.iter().filter(|n| !n.ends_with("_for_test")).collect();
    assert!(
        unmarked.is_empty(),
        "pool testing-gated endpoint(s) {unmarked:?} do NOT end in `_for_test`. The production \
         leak sweep (production_pool_wasm_contains_no_test_only_naming_convention_at_all) is \
         marker-based, so an unmarked testing endpoint is invisible to it — rename it, do not \
         relax this test."
    );
}
