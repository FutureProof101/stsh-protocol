// =============================================================================
// STSH — W2 2-1: pool pause completeness (DEF-096 quiescence) — PocketIC
// =============================================================================
//
// A1 C3 §3.3 (CONFIRMED-A1, HIGH): at the read baseline the pause flags gated
// only the two PRIMARY entry points (`shield_deposit`, `private_spend`), while
// the two PUBLIC RETRY endpoints (`retry_deposit_commitment`,
// `retry_private_spend_payout`) stayed open and made inter-canister calls by
// design. An operator following the bootstrap runbook could therefore believe
// the pool was quiescent while a third party kept driving Merkle appends and
// ledger payouts out of it.
//
// These tests prove BOTH halves of the fix:
//
//   Half 1 — all four public entry points respect the corresponding pause flag,
//            with a typed `Paused` rejection raised BEFORE any state write and
//            BEFORE any inter-canister call.
//   Half 2 — the endpoint names the runbook cites actually exist and toggle the
//            flags (the runbook was corrected to the real names; see
//            `test_w2_21_runbook_cited_endpoints_exist_and_toggle`).
//
// HOW "ZERO INTER-CANISTER CALL" IS ASSERTED (call-recorder equivalent):
// the quiescence sweep STOPS the merkle and token canisters first. A stopped
// callee rejects every inter-canister call, so any outbound call on these paths
// would surface as a transport/`CommitmentAppendFailed`/`TransferFailed` error
// — never as `Paused`. Observing `Paused` from all four entry points against a
// stopped downstream is therefore positive proof that no call was originated.
//
// A second, independent ORDERING probe uses a NONEXISTENT record: unpaused, the
// retry endpoints return a not-found `TransferFailed`; paused, they return
// `Paused`. The rejection therefore precedes even the record read — hence every
// state write and every call.
//
// REPLAY SAFETY: each retry regression asserts the injected record's status is
// byte-identical after the paused call, i.e. the record stays in exactly the
// state its retry resumes from. Pausing defers a retry; it never strands one.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token -p shielded_pool \
//       -p nullifier_registry -p merkle_tree -p treasury -p staking -p stsh-verifier
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test w2_2_1_pause_completeness_tests -- --test-threads=1
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
const DENOM: u128 = 1_000 * 100_000_000; // 1,000 STSH — DENOMINATIONS[0] (A6.6)

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

// ── Pool mirrors ────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
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
    expected_deployment_config_hash: Option<[u8; 32]>,
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
struct PrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<()>,
    expected_deployment_config_hash: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
    CommitmentPending,
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
    CommitmentReconcileInFlight,
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
    NullifierReconcileInFlight,
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct PendingPublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
    protocol_fee: u128,
    block_index: Option<Nat>,
    ledger_created_at_time_ns: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode { FixedStsh, XdrPegged }

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

// Full mirror of the pool's PoolError — a Candid variant decode fails on any
// arriving variant the mirror does not declare, and these tests decode real
// (non-Paused) errors on the post-unpause resume paths.
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
    ProofSystemMismatch,
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
    DuplicateOutputCommitment,
    InvalidOutputCommitment,
    DuplicateSpendId,
    DeploymentConfigMismatch,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    InvalidVerifierKeyHashLength { len: u64 },
    VerifierKeyHashMismatch,
    VerifierKeyHashChangedDuringAttestation,
    VerifierConfigInProgress,
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
    PayoutOutcomePrivate,
    PayoutExecutorBusy,
    PayoutMemoKeyNotReady,
    PayoutLegacyHold,
    PayoutStateInvalid,
    SpendNotFound,
    WrongSpendStatus,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    DisbursementProposalIdRetired,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    AnonymousCaller,
    WithdrawalNotFound,
    WrongWithdrawalStatus,
    Unauthorized,
    WithdrawalPayoutObligation,
    SecurityEpochChanged,
}

/// `settle_deposit_transfer`'s own error type (Option B — not `PoolError`
/// variants; see `canisters/shielded-pool/src/lib.rs` for why). `Pool` wraps
/// the complete `PoolError` mirror above, so the same full-mirror rule applies.
#[derive(CandidType, Serialize, Deserialize, Debug, PartialEq)]
enum SettlementError {
    Pool(PoolError),
    NotSettleable,
    Unavailable,
    TooEarly,
    InProgress,
    IdentityMismatch,
    EvidenceAmbiguous,
}

// ── Harness ─────────────────────────────────────────────────────────────────

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

// ── Pause controls (the REAL endpoints — the ones the runbook now cites) ─────

fn pause_deposits(pic: &PocketIc, s: &Stack) {
    let _: () = decode(
        "emergency_pause_deposits",
        pic.update_call(s.pool, s.controller, "emergency_pause_deposits", candid::encode_args(()).unwrap()),
    );
}

fn pause_spends(pic: &PocketIc, s: &Stack) {
    let r: Result<(), String> = decode(
        "emergency_pause_spends",
        pic.update_call(s.pool, s.controller, "emergency_pause_spends", candid::encode_args(()).unwrap()),
    );
    r.expect("emergency_pause_spends must succeed for the pool controller");
}

fn unpause_deposits(pic: &PocketIc, s: &Stack) {
    let _: () = decode(
        "unpause_deposits",
        pic.update_call(s.pool, s.controller, "unpause_deposits", candid::encode_args(()).unwrap()),
    );
}

fn unpause_spends(pic: &PocketIc, s: &Stack) {
    let _: () = decode(
        "unpause_spends",
        pic.update_call(s.pool, s.controller, "unpause_spends", candid::encode_args(()).unwrap()),
    );
}

fn deposits_paused(pic: &PocketIc, s: &Stack) -> bool {
    decode("is_deposits_paused", pic.query_call(s.pool, anon(), "is_deposits_paused", candid::encode_args(()).unwrap()))
}

fn spends_paused(pic: &PocketIc, s: &Stack) -> bool {
    decode("is_spends_paused", pic.query_call(s.pool, anon(), "is_spends_paused", candid::encode_args(()).unwrap()))
}

// ── Entry points under test ─────────────────────────────────────────────────

fn retry_deposit(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> Result<Nat, PoolError> {
    decode(
        "retry_deposit_commitment",
        pic.update_call(s.pool, anon(), "retry_deposit_commitment", candid::encode_one(commitment).unwrap()),
    )
}

fn retry_payout(pic: &PocketIc, s: &Stack, spend_id: u64) -> Result<Nat, PoolError> {
    decode(
        "retry_private_spend_payout",
        // R-15: detailed pause/financial results are owner-or-controller only.
        pic.update_call(s.pool, s.controller, "retry_private_spend_payout", candid::encode_one(spend_id).unwrap()),
    )
}

fn shield_deposit(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> Result<Nat, PoolError> {
    decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user, // DEF-070: shield_deposit rejects anonymous before the pause gate
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![1, 2, 3],
                public_amount: DENOM,
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    )
}

fn private_spend(pic: &PocketIc, s: &Stack, spend_id: u64) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(
            s.pool,
            s.user, // DEF-069: private_spend rejects anonymous before the pause gate
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id,
                envelope: ProofEnvelope {
                    circuit_version: 1,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: [0u8; 32],
                    root_reference: [0u8; 32],
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![nullifier(0x51)],
                output_commitments: vec![commitment(0x61), commitment(0x62)],
                encrypted_outputs: vec![vec![1], vec![2]],
                fee: 0,
                public_payout: None,
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    )
}

// ── Record injection / observation ──────────────────────────────────────────

fn inject_deposit(pic: &PocketIc, s: &Stack, commitment: [u8; 32], status: DepositStatus) {
    let _: () = decode(
        "inject_pending_deposit_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_pending_deposit_for_test",
            candid::encode_args((commitment, DENOM, status)).unwrap(),
        ),
    );
}

fn deposit_status(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> Option<DepositStatus> {
    let rec: Option<PendingDeposit> = decode(
        "get_deposit_status",
        // DEF-070: owner-or-controller gated — poll as the pool controller.
        pic.query_call(s.pool, s.controller, "get_deposit_status", candid::encode_one(commitment).unwrap()),
    );
    rec.map(|r| r.status)
}

fn payout_pending_spend(spend_id: u64, destination: Principal) -> PendingSpend {
    PendingSpend {
        spend_id,
        nullifiers: vec![nullifier(0x71)],
        output_commitments: vec![commitment(0x81)],
        public_payout: Some(PendingPublicPayout {
            destination,
            destination_subaccount: None,
            public_amount: DENOM,
            protocol_fee: 0,
            block_index: None,
            ledger_created_at_time_ns: None,
        }),
        outputs_committed: 1,
        fee: Some(0),
        status: SpendStatus::PayoutPending { reason: "transport failure".to_string() },
        created_at_ns: 0,
        submitter: Some(p(0xAA)),
        finalized_at_ns: None,
        fee_model_version: None,
        params_epoch: None,
        spend_fee_mode: None,
        fee_split_ops: None,
        fee_split_insurance: None,
        fee_split_staking: None,
    }
}

fn inject_spend(pic: &PocketIc, s: &Stack, spend: PendingSpend) -> u64 {
    decode(
        "inject_pending_spend_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_pending_spend_for_test",
            candid::encode_one(spend).unwrap(),
        ),
    )
}

fn spend_record(pic: &PocketIc, s: &Stack, spend_id: u64) -> PendingSpend {
    let rec: Option<PendingSpend> = decode(
        "get_spend_status",
        // DEF-069: submitter-or-controller gated — poll as the pool controller.
        pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    );
    rec.expect("injected spend record must be readable by the controller")
}

fn leaf_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode("leaf_count", pic.query_call(s.merkle, anon(), "leaf_count", candid::encode_args(()).unwrap()))
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

fn commitment(tag: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0] = tag;
    c[31] = 0x01;
    c
}

fn nullifier(tag: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = tag;
    n[31] = 0x02;
    n
}

// =============================================================================
// Half 1 — regression per endpoint (4)
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-R1 — retry_deposit_commitment respects the DEPOSITS pause
//
// The record is injected at TransferConfirmedCommitmentPending — the one status
// from which this endpoint proceeds to claim + append. Paused, it must be a
// typed `Paused` rejection with no status transition (no claim to
// CommitmentAppendInFlight) and no Merkle leaf.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_retry_deposit_commitment_rejects_when_deposits_paused() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x11);

    inject_deposit(&pic, &s, c, DepositStatus::TransferConfirmedCommitmentPending);
    let leaves_before = leaf_count(&pic, &s);

    pause_deposits(&pic, &s);
    assert!(deposits_paused(&pic, &s), "deposits must be paused");

    let r = retry_deposit(&pic, &s, c);
    assert_eq!(r, Err(PoolError::Paused), "paused deposit-retry must return the typed Paused rejection");

    // Zero state mutation: the record stays in the exact status its retry resumes from.
    assert_eq!(
        deposit_status(&pic, &s, c),
        Some(DepositStatus::TransferConfirmedCommitmentPending),
        "a paused retry must not transition the deposit (no claim, no stranding)"
    );
    // Zero inter-canister call: no leaf was appended.
    assert_eq!(leaf_count(&pic, &s), leaves_before, "a paused retry must not append a Merkle leaf");

    // And the deferral is exactly that — after unpause the retry resumes normally.
    unpause_deposits(&pic, &s);
    assert!(
        !matches!(retry_deposit(&pic, &s, c), Err(PoolError::Paused)),
        "after unpause the same retry must no longer be Paused"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-R2 — retry_private_spend_payout respects the SPENDS pause
//
// The record is injected at PayoutPending — the one status from which this
// endpoint proceeds to claim + pay. Paused, it must be a typed `Paused`
// rejection with no transition to PayoutSubmitting, no frozen ledger identity,
// and no token movement.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_retry_private_spend_payout_rejects_when_spends_paused() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let dest = p(0xD1);
    let spend_id = inject_spend(&pic, &s, payout_pending_spend(7, dest));

    let dest_before = balance_of(&pic, &s, dest);

    pause_spends(&pic, &s);
    assert!(spends_paused(&pic, &s), "spends must be paused");

    let r = retry_payout(&pic, &s, spend_id);
    assert_eq!(r, Err(PoolError::Paused), "paused payout-retry must return the typed Paused rejection");
    let foreign: Result<Nat, PoolError> = decode(
        "foreign paused retry",
        pic.update_call(s.pool, anon(), "retry_private_spend_payout", candid::encode_one(spend_id).unwrap()),
    );
    assert_eq!(foreign, Err(PoolError::PayoutOutcomePrivate));


    // Zero state mutation: still PayoutPending, no claim, no frozen ledger identity.
    let rec = spend_record(&pic, &s, spend_id);
    assert!(
        matches!(rec.status, SpendStatus::PayoutPending { .. }),
        "a paused payout-retry must leave the spend at PayoutPending; got {:?}",
        rec.status
    );
    let payout = rec.public_payout.expect("payout record must survive the paused call");
    assert_eq!(
        payout.ledger_created_at_time_ns, None,
        "a paused payout-retry must not freeze the ledger-transfer identity (B1)"
    );
    assert_eq!(payout.block_index, None, "a paused payout-retry must not record a block index");

    // Zero inter-canister call: no ledger transfer reached the destination.
    assert_eq!(balance_of(&pic, &s, dest), dest_before, "a paused payout-retry must not move tokens");

    // Deferral, not stranding: after unpause the retry proceeds again.
    unpause_spends(&pic, &s);
    assert!(
        !matches!(retry_payout(&pic, &s, spend_id), Err(PoolError::Paused)),
        "after unpause the same payout-retry must no longer be Paused"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-R3 — shield_deposit respects the DEPOSITS pause (baseline behaviour,
// pinned here so the sweep covers all four entry points in one place).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_shield_deposit_rejects_when_deposits_paused() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let leaves_before = leaf_count(&pic, &s);

    pause_deposits(&pic, &s);
    assert_eq!(shield_deposit(&pic, &s, commitment(0x21)), Err(PoolError::Paused));
    assert_eq!(deposit_status(&pic, &s, commitment(0x21)), None, "no deposit record may be written while paused");
    assert_eq!(leaf_count(&pic, &s), leaves_before, "a paused shield_deposit must not append a Merkle leaf");
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-R4 — private_spend respects the SPENDS pause (baseline behaviour,
// pinned here alongside the other three).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_private_spend_rejects_when_spends_paused() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    pause_spends(&pic, &s);
    assert_eq!(private_spend(&pic, &s, 99), Err(PoolError::Paused));

    let rec: Option<PendingSpend> = decode(
        "get_spend_status",
        pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(99u64).unwrap()),
    );
    assert!(rec.is_none(), "no spend record may be written while paused");
}

// =============================================================================
// Ordering probe — pause precedes claim mutation and every outbound call
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-ORD — for BOTH retry endpoints, a NONEXISTENT record returns a
// not-found error while unpaused but `Paused` while paused. The pause check is
// therefore ahead of claim mutation and every inter-canister call. R-15 first
// reads ownership to shape the response; that read does not claim or dispatch.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_pause_gate_precedes_record_lookup_on_both_retries() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let ghost_commitment = commitment(0x31);
    let ghost_spend_id = 4242u64;

    // Unpaused: the endpoints reach the lookup and report not-found.
    assert!(
        matches!(retry_deposit(&pic, &s, ghost_commitment), Err(PoolError::TransferFailed(_))),
        "unpaused deposit-retry on a missing record must reach the lookup (not-found)"
    );
    assert!(
        matches!(retry_payout(&pic, &s, ghost_spend_id), Err(PoolError::SpendNotFound)),
        "unpaused payout-retry on a missing record must reach the lookup (not-found)"
    );

    // Paused: the same calls stop earlier, at the pause gate.
    pause_deposits(&pic, &s);
    pause_spends(&pic, &s);
    assert_eq!(
        retry_deposit(&pic, &s, ghost_commitment),
        Err(PoolError::Paused),
        "paused deposit-retry must reject BEFORE the record lookup"
    );
    assert_eq!(
        retry_payout(&pic, &s, ghost_spend_id),
        Err(PoolError::Paused),
        "paused payout-retry must reject BEFORE claim mutation or dispatch"
    );
}

// =============================================================================
// Quiescence proof (DEF-096) — the runbook's operator-visible guarantee
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-Q — with BOTH flags set, a full sweep of the four public entry points
// produces no outbound call.
//
// CALL-RECORDER EQUIVALENT: the merkle and token canisters are STOPPED before
// the sweep. A stopped callee rejects every inter-canister call, so any call
// originated by the pool would surface as a transport error variant
// (CommitmentAppendFailed / MerkleAppendFailed / TransferFailed / ...) rather
// than `Paused`. All four returning `Paused` is positive proof that the pool
// originated no outbound call on any of these paths.
//
// Records are injected in the retryable states first, so the retry endpoints
// are genuinely on their proceed-path and would call out but for the pause.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_both_flags_set_quiesce_all_four_entry_points() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let c = commitment(0x41);
    inject_deposit(&pic, &s, c, DepositStatus::TransferConfirmedCommitmentPending);
    let spend_id = inject_spend(&pic, &s, payout_pending_spend(11, p(0xD2)));

    // Operator follows the runbook: pause both.
    pause_deposits(&pic, &s);
    pause_spends(&pic, &s);
    assert!(deposits_paused(&pic, &s) && spends_paused(&pic, &s), "both flags must be set");

    // Arm the recorder: any outbound call from here on cannot succeed silently.
    pic.stop_canister(s.merkle, None).expect("stop merkle");
    pic.stop_canister(s.token, None).expect("stop token");

    assert_eq!(
        shield_deposit(&pic, &s, commitment(0x42)),
        Err(PoolError::Paused),
        "shield_deposit must quiesce (no outbound call to the stopped token)"
    );
    assert_eq!(
        retry_deposit(&pic, &s, c),
        Err(PoolError::Paused),
        "retry_deposit_commitment must quiesce (no outbound call to the stopped merkle)"
    );
    assert_eq!(
        private_spend(&pic, &s, 12),
        Err(PoolError::Paused),
        "private_spend must quiesce (no outbound call)"
    );
    assert_eq!(
        retry_payout(&pic, &s, spend_id),
        Err(PoolError::Paused),
        "retry_private_spend_payout must quiesce (no outbound call to the stopped token)"
    );
}

// =============================================================================
// Half 2 — runbook-path test
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-RB — the endpoint names the bootstrap runbook cites EXIST and toggle
// the flags, walked in the runbook's own order: pause both → confirm both →
// (prune/upgrade) → unpause both → confirm both.
//
// The runbook previously cited `set_deposits_paused` / `set_spends_paused`,
// which never existed in the pool. The fix corrected the runbook to the real
// endpoints (see UPGRADE_BOOTSTRAP_RUNBOOK.md §1 PAUSE and §4 RESUME); this
// test is the executable form of those four lines. If a future edit
// reintroduces a name the pool does not export, this test fails.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_runbook_cited_endpoints_exist_and_toggle() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    assert!(!deposits_paused(&pic, &s) && !spends_paused(&pic, &s), "flags start clear");

    // Runbook §1 PAUSE
    pause_deposits(&pic, &s);
    pause_spends(&pic, &s);
    assert!(deposits_paused(&pic, &s), "runbook confirm: is_deposits_paused -> true");
    assert!(spends_paused(&pic, &s), "runbook confirm: is_spends_paused -> true");

    // Runbook §4 RESUME
    unpause_deposits(&pic, &s);
    unpause_spends(&pic, &s);
    assert!(!deposits_paused(&pic, &s), "runbook resume: is_deposits_paused -> false");
    assert!(!spends_paused(&pic, &s), "runbook resume: is_spends_paused -> false");
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-RB-NEG — the names the runbook USED to cite are genuinely absent, so
// this test also documents WHY the doc had to change rather than the code.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_stale_runbook_endpoint_names_do_not_exist() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    for name in ["set_deposits_paused", "set_spends_paused"] {
        let r = pic.update_call(s.pool, s.controller, name, candid::encode_one(true).unwrap());
        assert!(r.is_err(), "{} must not exist on the pool (the runbook no longer cites it)", name);
    }
}

// =============================================================================
// Upgrade coverage — the pause flags are stable-memory-backed
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// W2-21-UP — the pool persists deposits_paused / spends_paused across upgrade.
// The runbook's whole procedure is pause → prune → UPGRADE → resume, so an
// upgrade that silently cleared the flags would reopen all four entry points
// mid-procedure. Real PocketIC upgrade (native tests cannot catch this).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_w2_21_pause_flags_and_retry_gates_survive_upgrade() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let c = commitment(0x51);
    inject_deposit(&pic, &s, c, DepositStatus::TransferConfirmedCommitmentPending);
    let spend_id = inject_spend(&pic, &s, payout_pending_spend(13, p(0xD3)));

    pause_deposits(&pic, &s);
    pause_spends(&pic, &s);

    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade must succeed");

    assert!(deposits_paused(&pic, &s), "deposits_paused must survive upgrade");
    assert!(spends_paused(&pic, &s), "spends_paused must survive upgrade");

    // The gates are still enforced against the surviving flags.
    assert_eq!(retry_deposit(&pic, &s, c), Err(PoolError::Paused), "deposit-retry still gated post-upgrade");
    assert_eq!(retry_payout(&pic, &s, spend_id), Err(PoolError::Paused), "payout-retry still gated post-upgrade");
}

// =============================================================================
// NEW-3 (HARDEN-01, lane TEST-T1 §3.3) — ONE ASSERTION PER PUBLISHED MATRIX CELL
// =============================================================================
//
// `docs/PAUSE_MATRIX.md` publishes ten user-visible paths x two flags and is
// declared the single source for pause behaviour ("if another page disagrees
// with this table, this table is right and the other page is a defect"). This
// section is that table's executable form, extending THIS suite rather than
// starting a new one (brief §2 invariant 3) because rows 1-4 already live here.
//
// TWO ASSERTION SHAPES, DELIBERATELY NOT CONFLATED (brief §3.3):
//
//   * PAUSE-GATED cells (rows 1-4): flag set -> the `Paused` error; flag clear
//     -> the call proceeds, or fails for a different, NAMED reason. Already
//     covered above by W2-21-R1..R4, W2-21-ORD and W2-21-Q; the rows are mapped
//     onto those tests in `test_new3_matrix_rows_1_to_4_are_covered_above`, so
//     the table's coverage is legible from the table's own row numbers.
//
//   * NOT-PAUSE-GATED cells (rows 5-10): the refusal (or acceptance) is
//     IDENTICAL under every one of the four flag combinations. It is not enough
//     to show the call is not `Paused` while paused — the claim in the table is
//     that the flags are not read on this path at all, and the executable form
//     of "not read" is "the answer does not move when the flags move".
//
// ROW 5 IS THE ONE THAT MATTERS MOST. The external review overclaimed that
// pausing the pool stops withdrawals. Both halves of the table's row 5 are
// false-in-the-other-direction: `withdraw` is not pause-gated, AND `withdraw`
// is closed anyway — by `reject_unbound_withdrawal_proof()` (pool lib.rs:7471,
// "Decision 7: removed only in Phase 5"), which returns `InvalidProof`
// unconditionally. `test_new3_row5_withdraw_is_pause_INDEPENDENT_in_all_four_
// flag_combinations` is the assertion that would have caught the overclaim, in
// either direction: it reddens if a pause ever starts changing withdraw's
// answer, and it reddens if the fail-closed guard is removed without one.

// ── Additional Candid mirrors for the row 5-10 endpoints ────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct WithdrawArgs {
    withdrawal_id: u64,
    envelope: ProofEnvelope,
    nullifier: [u8; 32],
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    gross_withdraw_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum PayoutOutcome {
    Executed { block_index: u64 },
    NotExecuted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum DisburseOutcome {
    Executed { block_index: u64 },
    NotExecuted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
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

/// The four flag combinations, named the way the matrix names them.
const FLAG_COMBINATIONS: [(bool, bool); 4] =
    [(false, false), (true, false), (false, true), (true, true)];

fn set_flags(pic: &PocketIc, s: &Stack, deposits: bool, spends: bool) {
    if deposits { pause_deposits(pic, s) } else { unpause_deposits(pic, s) }
    if spends { pause_spends(pic, s) } else { unpause_spends(pic, s) }
    assert_eq!(deposits_paused(pic, s), deposits, "DEPOSITS_PAUSED must be {}", deposits);
    assert_eq!(spends_paused(pic, s), spends, "SPENDS_PAUSED must be {}", spends);
}

fn withdraw_args(id: u64) -> WithdrawArgs {
    WithdrawArgs {
        withdrawal_id: id,
        envelope: ProofEnvelope {
            circuit_version: 1,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: [0u8; 32],
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
        nullifier: nullifier(0x91),
        destination: p(0xD9),
        destination_subaccount: None,
        gross_withdraw_amount: DENOM,
    }
}

fn withdraw(pic: &PocketIc, s: &Stack, caller: Principal, id: u64) -> Result<Nat, PoolError> {
    decode(
        "withdraw",
        pic.update_call(s.pool, caller, "withdraw", candid::encode_one(withdraw_args(id)).unwrap()),
    )
}

/// Call `method` with `args` and decode only the ERROR arm precisely; the Ok
/// arm is `reserved`, so one helper serves endpoints with five different
/// success payloads. Every row 5-10 call in this section is expected to fail
/// (the stack holds no matching record and the caller is not the treasury) —
/// what is under test is WHICH failure, and whether it moves with the flags.
fn call_err(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    method: &str,
    args: Vec<u8>,
) -> Result<candid::Reserved, PoolError> {
    decode(method, pic.update_call(s.pool, caller, method, args))
}

/// Run `f` under all four flag combinations and assert every answer is the
/// same one. The returned value is that common answer.
fn same_under_all_flag_combinations<T, F>(pic: &PocketIc, s: &Stack, label: &str, mut f: F) -> T
where
    T: std::fmt::Debug + PartialEq,
    F: FnMut(&PocketIc, &Stack) -> T,
{
    let mut baseline: Option<T> = None;
    for (deposits, spends) in FLAG_COMBINATIONS {
        set_flags(pic, s, deposits, spends);
        let got = f(pic, s);
        match &baseline {
            None => baseline = Some(got),
            Some(b) => assert_eq!(
                &got, b,
                "{}: the answer changed under DEPOSITS_PAUSED={} SPENDS_PAUSED={} — \
                 this path reads a pause flag, which the matrix says it does not",
                label, deposits, spends
            ),
        }
    }
    baseline.expect("four combinations were walked")
}

// ─────────────────────────────────────────────────────────────────────────────
// Rows 1-4 — the pause-GATED cells. Mapped, not re-asserted.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_matrix_rows_1_to_4_are_covered_above() {
    // Row 1 shield_deposit           -> test_w2_21_shield_deposit_rejects_when_deposits_paused
    // Row 2 retry_deposit_commitment -> test_w2_21_retry_deposit_commitment_rejects_when_deposits_paused
    // Row 3 private_spend            -> test_w2_21_private_spend_rejects_when_spends_paused
    // Row 4 retry_private_spend_payout -> test_w2_21_retry_private_spend_payout_rejects_when_spends_paused
    //
    // What is NOT covered by those four is the matrix's §4 note: on rows 1 and
    // 3 the ANONYMOUS-caller check precedes the pause check, so an anonymous
    // call against a paused pool reports `AnonymousCaller`, not `Paused`. A
    // test that called anonymously could not observe the pause at all — which
    // is precisely how a pause test can pass while proving nothing. Asserted
    // here so the note is executable rather than advisory.
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    set_flags(&pic, &s, true, true);

    let anon_deposit: Result<Nat, PoolError> = decode(
        "shield_deposit(anon)",
        pic.update_call(
            s.pool,
            anon(),
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment(0x61),
                encrypted_payload: vec![1],
                public_amount: DENOM,
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        anon_deposit,
        Err(PoolError::AnonymousCaller),
        "matrix §4 note: the anonymous check precedes the pause check on shield_deposit"
    );

    // And the authenticated caller on the same paused pool DOES see the pause —
    // so the assertion above is about ordering, not about the pause being absent.
    assert_eq!(shield_deposit(&pic, &s, commitment(0x62)), Err(PoolError::Paused));
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 5 — fresh `withdraw`: NOT pause-gated, and closed by Decision 7.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_row5_withdraw_is_pause_independent_in_all_four_flag_combinations() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // A fresh withdrawal_id per combination: an idempotency-key collision would
    // make later combinations answer from the stored record instead of the
    // guard, and the four answers would agree for the wrong reason.
    let mut id = 1_000u64;
    let answer = same_under_all_flag_combinations(&pic, &s, "withdraw", |pic, s| {
        id += 1;
        withdraw(pic, s, s.user, id)
    });

    assert_eq!(
        answer,
        Err(PoolError::InvalidProof),
        "row 5: withdraw is fail-closed by reject_unbound_withdrawal_proof (Decision 7), \
         which returns InvalidProof — not Paused, in any flag combination"
    );
    assert_ne!(answer, Err(PoolError::Paused), "row 5: withdraw must never report Paused");
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 6 — completion of an already-verified payout. Dormant, not absent.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_row6_withdrawal_completion_paths_are_pause_independent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    for method in [
        "resume_blocked_withdrawal",
        "reconcile_withdrawal_registry_insert",
        "reconcile_withdrawal_ledger_transfer",
    ] {
        let answer = same_under_all_flag_combinations(&pic, &s, method, |pic, s| {
            let r: Result<Nat, PoolError> = decode(
                method,
                pic.update_call(s.pool, s.controller, method, candid::encode_one(77u64).unwrap()),
            );
            r
        });
        assert_ne!(answer, Err(PoolError::Paused), "row 6 {}: must never report Paused", method);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 2 — HARDEN-03-SETTLEMENT: `settle_deposit_transfer` joins the deposit
// pause, and it joins ROW 2 rather than row 7.
//
// It resolves a stuck record the way a reconcile does, so row 7 is the intuitive
// home and the wrong one. Two reasons it belongs in row 2:
//
//   • It ORIGINATES AN OUTBOUND TOKEN CALL from the deposit path (a receipt read,
//     and possibly a transfer re-submission). W2 2-1/DEF-096's whole rule is that
//     a paused pool originates no such call. A row-7 endpoint originates none.
//   • It is OPEN — caller-agnostic, with no `assert_operator_controller()` — so it
//     could not sit in row 7 on authority grounds either.
//
// Replay-safe, and that is why the pause is allowed to be this blunt: the record
// stays `TransferPending`, which is precisely the state the endpoint resumes
// from, so a pause DEFERS a settlement and can never strand one.
//
// A pause-gated endpoint absent from `docs/PAUSE_MATRIX.md` is exactly the
// completeness gap this suite exists to prevent, which is why the matrix row was
// edited in the same change.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_harden03_row2_settle_deposit_transfer_respects_the_deposits_pause() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let ghost = commitment(0x21);

    // Unpaused: the call reaches the record lookup and reports not-found.
    let unpaused: Result<candid::Reserved, SettlementError> = decode(
        "settle_deposit_transfer",
        pic.update_call(
            s.pool,
            anon(),
            "settle_deposit_transfer",
            candid::encode_one(ghost).unwrap(),
        ),
    );
    assert_eq!(
        unpaused,
        Err(SettlementError::Pool(PoolError::DepositNotFound)),
        "unpaused, settlement must reach the record lookup"
    );

    // Paused: the same call stops EARLIER, at the pause gate — before the lookup
    // and therefore before anything that could originate an outbound call.
    pause_deposits(&pic, &s);
    let paused: Result<candid::Reserved, SettlementError> = decode(
        "settle_deposit_transfer",
        pic.update_call(
            s.pool,
            anon(),
            "settle_deposit_transfer",
            candid::encode_one(ghost).unwrap(),
        ),
    );
    assert_eq!(
        paused,
        Err(SettlementError::Pool(PoolError::Paused)),
        "paused, settlement must reject BEFORE the record lookup — row 2, not row 7"
    );

    // And the spends pause alone does NOT gate it: this is a deposit-path
    // endpoint, so a spends-only pause must leave it open.
    unpause_deposits(&pic, &s);
    pause_spends(&pic, &s);
    let spends_only: Result<candid::Reserved, SettlementError> = decode(
        "settle_deposit_transfer",
        pic.update_call(
            s.pool,
            anon(),
            "settle_deposit_transfer",
            candid::encode_one(ghost).unwrap(),
        ),
    );
    assert_eq!(
        spends_only,
        Err(SettlementError::Pool(PoolError::DepositNotFound)),
        "SPENDS_PAUSED must not gate a deposit-path endpoint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 7 — deposit-path admin / recovery reconciles.
//
// HARDEN-03-SETTLEMENT changed `reconcile_deposit_transfer_not_executed`'s
// BEHAVIOUR (it is now fail-closed on the settlement sidecar) but not its PAUSE
// POSTURE, its authority, or its gate ordering. This loop is unchanged and must
// stay unchanged: a ghost commitment has no sidecar, so it reaches the same
// `DepositNotFound` under every flag combination it always did.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_row7_deposit_reconciles_are_pause_independent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let ghost = commitment(0x71);

    for method in [
        "reconcile_deposit_commitment",
        "reconcile_deposit_append_unknown",
        "reconcile_deposit_transfer_not_executed",
    ] {
        let answer = same_under_all_flag_combinations(&pic, &s, method, |pic, s| {
            call_err(pic, s, s.controller, method, candid::encode_one(ghost).unwrap())
        });
        assert_ne!(answer, Err(PoolError::Paused), "row 7 {}: must never report Paused", method);
        assert_eq!(
            answer,
            Err(PoolError::DepositNotFound),
            "row 7 {}: the operator sees the record's own error, unchanged by the pause",
            method
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 8 — spend-path admin / recovery reconciles.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_row8_spend_reconciles_are_pause_independent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    for (method, args) in [
        ("reconcile_nullifier_insert", candid::encode_one(88u64).unwrap()),
        ("reconcile_pending_spend", candid::encode_one(88u64).unwrap()),
        (
            "reconcile_private_spend_payout",
            candid::encode_args((88u64, PayoutOutcome::NotExecuted)).unwrap(),
        ),
    ] {
        let answer = same_under_all_flag_combinations(&pic, &s, method, |pic, s| {
            call_err(pic, s, s.controller, method, args.clone())
        });
        assert_ne!(answer, Err(PoolError::Paused), "row 8 {}: must never report Paused", method);
        assert_eq!(
            answer,
            Err(PoolError::SpendNotFound),
            "row 8 {}: the operator sees the record's own error, unchanged by the pause",
            method
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 9 — treasury disbursement (Option 2: the pool disburses, not the treasury).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_row9_treasury_disbursement_is_pause_independent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let args = TreasuryDisburseArgs {
        proposal_id: 99,
        bucket: TreasuryReserveBucket::Operations,
        recipient: p(0xE1),
        recipient_subaccount: None,
        amount: DENOM,
        expected_ledger_fee: 0,
    };

    let disburse = same_under_all_flag_combinations(&pic, &s, "treasury_disburse", |pic, s| {
        call_err(pic, s, s.controller, "treasury_disburse", candid::encode_one(args.clone()).unwrap())
    });
    assert_ne!(disburse, Err(PoolError::Paused), "row 9: treasury_disburse must never report Paused");

    let reconcile =
        same_under_all_flag_combinations(&pic, &s, "reconcile_treasury_disburse", |pic, s| {
            call_err(
                pic,
                s,
                s.controller,
                "reconcile_treasury_disburse",
                candid::encode_args((99u64, DisburseOutcome::NotExecuted)).unwrap(),
            )
        });
    assert_ne!(
        reconcile,
        Err(PoolError::Paused),
        "row 9: reconcile_treasury_disburse must never report Paused"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 10 — the pause controls themselves are never self-gated.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_new3_row10_pause_controls_are_never_self_gated() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Pausing an already-paused pool is accepted (idempotent), and — the part
    // that matters operationally — UNPAUSING a fully paused pool works. A
    // self-gated unpause would be an unrecoverable pool.
    set_flags(&pic, &s, true, true);
    pause_deposits(&pic, &s);
    pause_spends(&pic, &s);
    assert!(deposits_paused(&pic, &s) && spends_paused(&pic, &s), "re-pausing stays paused");

    unpause_deposits(&pic, &s);
    unpause_spends(&pic, &s);
    assert!(
        !deposits_paused(&pic, &s) && !spends_paused(&pic, &s),
        "a fully paused pool must still be re-openable — the controls are not self-gated"
    );

    // The circuit kill switch is likewise not pause-gated: under both flags it
    // still reports its OWN argument error, not Paused.
    set_flags(&pic, &s, true, true);
    let r: Result<(), String> = decode(
        "emergency_disable_circuit_version",
        pic.update_call(
            s.pool,
            s.controller,
            "emergency_disable_circuit_version",
            candid::encode_one(4242u32).unwrap(),
        ),
    );
    assert_eq!(
        r,
        Err("Can only disable the currently active circuit version".to_string()),
        "row 10: the kill switch answers on its own terms while the pool is paused"
    );
}

// =============================================================================
// HARDEN-02 (AB-8 / L-02a) — §2's SIDE-EFFECT column, as a drift-lock
// =============================================================================
//
// `docs/PAUSE_MATRIX.md` §2 published `unpause_spends`'s side effect as "none"
// while the pool bumps the security epoch in that call's body
// (`bump_security_epoch()`, with the comment "P-VK (POOL-04): spend unpause is a
// security-epoch event"). `unpause_deposits` really is "none". HARDEN-01's
// `784c2b0` did not close this: its PAUSE_MATRIX.md change was one line in §1's
// table, row 10's "Never self-gated" -> "Not self-gated", to clear an
// unmeasured-claims lint false positive. §2 was untouched.
//
// Prose is not the fix — NEW-3's precedent above is that a published matrix cell
// gets an assertion. The ASYMMETRY is what an operator acts on, so it is asserted
// as an asymmetry: the same observable, read across both calls, must move for one
// and not for the other. A test that only checked the spend side would still pass
// if someone "harmonised" the two by bumping on both.
fn security_epoch(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "get_security_epoch",
        pic.query_call(s.pool, anon(), "get_security_epoch", candid::encode_args(()).unwrap()),
    )
}

#[test]
fn test_ab8_unpause_spends_bumps_the_security_epoch_and_unpause_deposits_does_not() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // ── unpause_deposits: side effect "none" ──────────────────────────────────
    pause_deposits(&pic, &s);
    let before = security_epoch(&pic, &s);
    unpause_deposits(&pic, &s);
    assert_eq!(
        security_epoch(&pic, &s),
        before,
        "PAUSE_MATRIX.md §2 records `unpause_deposits` side effects as `none`, and the \
         security epoch is the observable that would contradict it"
    );
    assert!(!deposits_paused(&pic, &s), "and the flag really was cleared");

    // ── unpause_spends: bumps the epoch (P-VK / POOL-04) ──────────────────────
    pause_spends(&pic, &s);
    let before = security_epoch(&pic, &s);
    unpause_spends(&pic, &s);
    let after = security_epoch(&pic, &s);
    assert!(
        after > before,
        "PAUSE_MATRIX.md §2 records `unpause_spends` as bumping the security epoch \
         (P-VK / POOL-04). The epoch did not move: {before} -> {after}. A bump \
         invalidates in-flight material, so an operator reading a `none` here would \
         unpause believing the call is inert"
    );
    assert!(!spends_paused(&pic, &s), "and the flag really was cleared");
}
