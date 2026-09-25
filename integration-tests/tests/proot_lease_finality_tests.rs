// =============================================================================
// STSH — P-ROOT (C-ROOT-1): pool-wide append lease + finality-bound root head
// =============================================================================
//
// Closes C-ROOT-1: the accepted-root insert previously used a get_root read that
// could cover ANOTHER operation's unfinalized leaf (appended but not yet
// credited/accounted), because nothing serialized appends pool-wide and the root
// was fetched while records still read *AppendInFlight.
//
// Under test (BRIEF_WALLET_B_PHASE2_FINISH §7.5/§7.5.1/§7.5.2):
//   - durable pool-wide append lease: CAS acquire (only if free), owner+generation
//     compare on every transition/release, five-phase closed LeasePhase enum;
//   - at most ONE unresolved Merkle append pool-wide (deposit + spend paths);
//   - transport-unknown RETAINS the lease until operator reconciliation; definite
//     rejection releases it in the same no-await step as the status write;
//   - AcceptedRootHead written atomically from one get_scan_head read at all
//     three acceptance sites; monotonic (equal-count fork / lower count → trap);
//   - append success writes (AppendConfirmedRootPending, ActiveRootPending)
//     BEFORE the scan-head fetch — no root fetch while ActiveAppendInFlight;
//   - lease released after RootAccepted+accounting and BEFORE the payout await
//     (a stuck PayoutUnknown never blocks appends);
//   - post_upgrade verifies the persisted lease against the owner record
//     (normative tuple tables) and TRAPS on disagreement; pre-head deployments
//     with a non-empty accepted set are REJECTED (pin rejection);
//   - CF-1: normal deposit completion reaches CommitmentRootAccepted and leaves
//     the P-REC active recovery index; interrupted finalization stays indexed;
//     roll-forward reconcile deindexes.
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
fn pool_prod_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }
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
fn all_to(recipient: Principal) -> TokenInitArgs {
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
        staking_canister: p(0x02),
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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending,
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
    CommitmentReconcileInFlight,
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
    finalized_at_ns: Option<u64>,
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
enum ReconcilePendingSpendResult {
    PromotedFinalized,
    PromotedPayoutPending,
    AppendRetryScheduled,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositAppendReconcileResult {
    Finalized,
    RevertedRetryable,
}
// P-ROOT candid mirrors
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum LeasePhase {
    Snapshotting,
    AppendInFlight,
    AppendUnknown,
    ReconcileInFlight,
    AppendConfirmedRootPending,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum AppendLeaseOwner {
    Deposit { commitment: [u8; 32] },
    Spend { spend_id: u64 },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseAgeBucket {
    UnderMinute,
    UnderTenMinutes,
    UnderHour,
    OverHour,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AppendLeaseStatus {
    held: bool,
    phase: Option<LeasePhase>,
    age_bucket: Option<LeaseAgeBucket>,
}
/// R2 shape probe: candid fills ABSENT record fields declared `opt` with None —
/// so decoding the public reply into this widened mirror proves the value
/// carries NO generation and NO exact timestamps.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AppendLeaseStatusProbe {
    held: bool,
    phase: Option<LeasePhase>,
    age_bucket: Option<LeaseAgeBucket>,
    generation: Option<u64>,
    acquired_at_ns: Option<u64>,
    phase_started_at_ns: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AppendLeaseOwnerView {
    owner: AppendLeaseOwner,
    phase: LeasePhase,
    generation: u64,
    acquired_at_ns: u64,
    phase_started_at_ns: u64,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
struct AcceptedRootHead {
    root: [u8; 32],
    leaf_count: u64,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ActiveDepositsPage {
    deposits: Vec<PendingDeposit>,
    next_cursor: Option<[u8; 32]>,
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
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    AnonymousCaller,
    WithdrawalNotFound,
    WrongWithdrawalStatus,
    Unauthorized,
    WithdrawalPayoutObligation,
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal { Principal::anonymous() }
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
    let verifier = create_canister(pic);
    let pool = create_canister(pic);
    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    pic.install_canister(verifier, stub_verifier_wasm(), candid::encode_one(None::<[u8; 32]>).unwrap(), None);
    install(pic, token, token_wasm(), &all_to(user));
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
    Stack { pool, token, merkle, controller, user }
}

/// Real upgrade to the PRODUCTION Pool Wasm. Err = pre/post_upgrade trapped.
/// Advances the simulated clock first: two back-to-back install_code messages of
/// the ~1.5 MB Wasm can otherwise trip PocketIC's per-canister install rate
/// limit (a harness budget, not a canister defect — same pattern as the H-1
/// suite's upgrade_to_test helper).
fn upgrade_to_prod(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}
/// Re-upgrade to the testing Wasm (same install-rate-limit handling).
fn upgrade_to_test(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
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

fn try_deposit(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) -> Result<Nat, PoolError> {
    approve(pic, s, DENOM_1000 + DEFAULT_FEE);
    decode(
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
    )
}

fn deposit_ok(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) {
    let dep = try_deposit(pic, s, commitment);
    assert!(dep.is_ok(), "deposit must succeed; got {:?}", dep);
}

fn spend_args(anchor: [u8; 32], spend_id: u64, nullifier: [u8; 32], outs: (u8, u8)) -> PrivateSpendArgs {
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
        output_commitments: vec![fr(outs.0), fr(outs.1)],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: None,
    }
}
fn run_spend(pic: &PocketIc, s: &Stack, anchor: [u8; 32], spend_id: u64, nullifier: [u8; 32], outs: (u8, u8)) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(spend_args(anchor, spend_id, nullifier, outs)).unwrap()),
    )
}

fn merkle_root(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    let v: Vec<u8> = decode(
        "get_root",
        pic.query_call(s.merkle, anon(), "get_root", candid::encode_args(()).unwrap()),
    );
    let mut r = [0u8; 32];
    r.copy_from_slice(&v);
    r
}
fn merkle_leaf_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode("leaf_count", pic.query_call(s.merkle, anon(), "leaf_count", candid::encode_args(()).unwrap()))
}
fn is_accepted(pic: &PocketIc, s: &Stack, root: [u8; 32]) -> bool {
    decode(
        "is_accepted_spend_root",
        pic.query_call(s.pool, anon(), "is_accepted_spend_root", candid::encode_one(root.to_vec()).unwrap()),
    )
}
fn head(pic: &PocketIc, s: &Stack) -> Option<AcceptedRootHead> {
    decode(
        "get_accepted_root_head",
        pic.query_call(s.pool, anon(), "get_accepted_root_head", candid::encode_args(()).unwrap()),
    )
}
fn lease_status(pic: &PocketIc, s: &Stack) -> AppendLeaseStatus {
    decode(
        "get_append_lease_status",
        pic.query_call(s.pool, anon(), "get_append_lease_status", candid::encode_args(()).unwrap()),
    )
}
fn lease_held(pic: &PocketIc, s: &Stack) -> bool {
    lease_status(pic, s).held
}
fn lease_phase(pic: &PocketIc, s: &Stack) -> Option<LeasePhase> {
    lease_status(pic, s).phase
}
fn lease_owner_view(pic: &PocketIc, s: &Stack) -> Option<AppendLeaseOwnerView> {
    decode(
        "get_append_lease_owner",
        pic.query_call(s.pool, s.controller, "get_append_lease_owner", candid::encode_args(()).unwrap()),
    )
}
fn deposit_status(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Option<PendingDeposit> {
    decode("get_deposit_status", pic.query_call(s.pool, s.controller, "get_deposit_status", candid::encode_one(c).unwrap()))
}
fn spend_status(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<SpendStatus> {
    #[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
    struct PendingSpendView {
        spend_id: u64,
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
        outputs_committed: u32,
        status: SpendStatus,
        created_at_ns: u64,
    }
    let rec: Option<PendingSpendView> = decode(
        "get_spend_status",
        pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    );
    rec.map(|r| r.status)
}
fn list_my_deposits(pic: &PocketIc, s: &Stack) -> Vec<[u8; 32]> {
    let page: ActiveDepositsPage = decode(
        "list_my_active_deposits",
        pic.query_call(
            s.pool,
            s.user,
            "list_my_active_deposits",
            candid::encode_args((None::<[u8; 32]>, 100u64)).unwrap(),
        ),
    );
    page.deposits.iter().map(|d| d.note_commitment).collect()
}
fn retry_deposit(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<Nat, PoolError> {
    decode("retry_deposit_commitment", pic.update_call(s.pool, s.user, "retry_deposit_commitment", candid::encode_one(c).unwrap()))
}
fn reconcile_deposit(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<(), PoolError> {
    decode("reconcile_deposit_commitment", pic.update_call(s.pool, s.controller, "reconcile_deposit_commitment", candid::encode_one(c).unwrap()))
}
fn reconcile_deposit_unknown(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<DepositAppendReconcileResult, PoolError> {
    decode("reconcile_deposit_append_unknown", pic.update_call(s.pool, s.controller, "reconcile_deposit_append_unknown", candid::encode_one(c).unwrap()))
}
fn reconcile_spend(pic: &PocketIc, s: &Stack, spend_id: u64) -> Result<ReconcilePendingSpendResult, PoolError> {
    decode("reconcile_pending_spend", pic.update_call(s.pool, s.controller, "reconcile_pending_spend", candid::encode_one(spend_id).unwrap()))
}
fn ctl_unit(pic: &PocketIc, s: &Stack, method: &str, args: Vec<u8>) {
    let _: () = decode(method, pic.update_call(s.pool, s.controller, method, args));
}
fn force_deposit_append_unknown(pic: &PocketIc, s: &Stack, mode: u8) {
    ctl_unit(pic, s, "force_deposit_append_unknown_for_test", candid::encode_one(mode).unwrap());
}
fn force_active_append_unknown(pic: &PocketIc, s: &Stack, mode: u8) {
    ctl_unit(pic, s, "force_active_append_unknown_for_test", candid::encode_one(mode).unwrap());
}
fn force_scan_head_unavailable(pic: &PocketIc, s: &Stack, enable: bool) {
    ctl_unit(pic, s, "force_scan_head_unavailable_for_test", candid::encode_one(enable).unwrap());
}
fn force_payout_unknown(pic: &PocketIc, s: &Stack, enable: bool) {
    ctl_unit(pic, s, "force_payout_transport_unknown_for_test", candid::encode_one(enable).unwrap());
}
fn set_lease(pic: &PocketIc, s: &Stack, owner: AppendLeaseOwner, phase: LeasePhase) -> u64 {
    decode(
        "set_append_lease_for_test",
        pic.update_call(s.pool, s.controller, "set_append_lease_for_test", candid::encode_args((owner, phase)).unwrap()),
    )
}
fn clear_lease(pic: &PocketIc, s: &Stack) {
    ctl_unit(pic, s, "clear_append_lease_for_test", candid::encode_args(()).unwrap());
}
fn try_release(pic: &PocketIc, s: &Stack, owner: AppendLeaseOwner, generation: u64) -> bool {
    decode(
        "try_release_append_lease_for_test",
        pic.update_call(s.pool, s.controller, "try_release_append_lease_for_test", candid::encode_args((owner, generation)).unwrap()),
    )
}
fn inject_deposit_with_index(pic: &PocketIc, s: &Stack, c: [u8; 32], status: DepositStatus, idx: Option<u64>) {
    ctl_unit(
        pic,
        s,
        "inject_pending_deposit_with_index_for_test",
        candid::encode_args((c, DENOM_1000, status, idx)).unwrap(),
    );
}
fn inject_spend(pic: &PocketIc, s: &Stack, spend_id: u64, status: SpendStatus) {
    ctl_unit(
        pic,
        s,
        "inject_spend_with_nullifiers_for_test",
        candid::encode_args((spend_id, vec![fr(0x77)], status)).unwrap(),
    );
}
fn inject_staged_outputs(pic: &PocketIc, s: &Stack, spend_id: u64, outs: Vec<[u8; 32]>, idx: Option<u64>) {
    ctl_unit(
        pic,
        s,
        "inject_staged_outputs_for_test",
        candid::encode_args((spend_id, outs, idx)).unwrap(),
    );
}
fn commit_head_call(pic: &PocketIc, s: &Stack, root: [u8; 32], leaf_count: u64, expected: u64) -> Result<Vec<u8>, String> {
    pic.update_call(
        s.pool,
        s.controller,
        "commit_accepted_root_head_for_test",
        candid::encode_args((root, leaf_count, expected)).unwrap(),
    )
    .map_err(|e| format!("{:?}", e))
}

fn expect_lease_blocked<T: std::fmt::Debug>(label: &str, r: Result<T, PoolError>) {
    match r {
        Err(PoolError::CommitmentAppendFailed(msg)) => {
            assert!(msg.contains("append lease held"), "{label}: expected lease-held error, got: {msg}");
        }
        other => panic!("{label}: expected CommitmentAppendFailed(lease held), got {:?}", other),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. CAS acquire + stale-generation release (RED/GREEN)
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_cas_acquire_and_stale_generation_release() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Install a lease directly and try to break it with stale credentials.
    let owner = AppendLeaseOwner::Spend { spend_id: 99 };
    let g = set_lease(&pic, &s, owner, LeasePhase::AppendUnknown);

    // RED-shape attempts: stale generation / wrong owner must NOT release.
    assert!(!try_release(&pic, &s, owner, g + 1000), "stale generation must not release");
    assert!(
        !try_release(&pic, &s, AppendLeaseOwner::Deposit { commitment: fr(0x01) }, g),
        "wrong owner must not release"
    );
    assert!(lease_held(&pic, &s), "lease must survive stale release attempts");

    // Acquire is CAS-only-if-free: a real deposit is blocked while the lease is held.
    let blocked = try_deposit(&pic, &s, fr(0x02));
    expect_lease_blocked("deposit while lease held", blocked);

    // GREEN: exact (owner, generation) releases; the pool is live again.
    assert!(try_release(&pic, &s, owner, g), "matching owner+generation must release");
    assert!(!lease_held(&pic, &s));
    let ok = retry_deposit(&pic, &s, fr(0x02));
    assert!(ok.is_ok(), "deposit retry after release must succeed; got {:?}", ok);
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. At most ONE unresolved append pool-wide; transport-unknown retains;
//    reconcile resolves; blocked operations recover (deposit + spend paths)
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_single_unresolved_append_pool_wide() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Healthy deposit → anchor + escrow.
    deposit_ok(&pic, &s, fr(0x11));
    let anchor = head(&pic, &s).expect("head after deposit").root;

    // Deposit 2 hits a transport-unknown append (not committed) → lease RETAINED.
    force_deposit_append_unknown(&pic, &s, 2);
    let d2 = try_deposit(&pic, &s, fr(0x12));
    assert!(matches!(d2, Err(PoolError::CommitmentAppendFailed(_))), "got {:?}", d2);
    force_deposit_append_unknown(&pic, &s, 0);
    let l = lease_owner_view(&pic, &s).expect("lease retained on transport-unknown");
    assert_eq!(l.phase, LeasePhase::AppendUnknown);
    assert_eq!(l.owner, AppendLeaseOwner::Deposit { commitment: fr(0x12) });
    assert_eq!(
        deposit_status(&pic, &s, fr(0x12)).map(|d| d.status),
        Some(DepositStatus::CommitmentAppendUnknown)
    );

    // Deposit 3: transfer confirms, append BLOCKED pool-wide.
    let d3 = try_deposit(&pic, &s, fr(0x13));
    expect_lease_blocked("second deposit while unknown append unresolved", d3);
    assert_eq!(
        deposit_status(&pic, &s, fr(0x13)).map(|d| d.status),
        Some(DepositStatus::TransferConfirmedCommitmentPending)
    );

    // Spend promotion also BLOCKED (same pool-wide lease); nullifier stays
    // finalized and the spend parks in the retryable promotion state.
    let sp = run_spend(&pic, &s, anchor, 21, fr(0x21), (0x31, 0x32));
    expect_lease_blocked("spend promotion while unknown append unresolved", sp);
    assert_eq!(
        spend_status(&pic, &s, 21),
        Some(SpendStatus::NullifierFinalizedOutputsPending)
    );
    // The lease is untouched by the blocked attempts.
    let l2 = lease_owner_view(&pic, &s).expect("lease still held");
    assert_eq!(l2.generation, l.generation, "blocked attempts must not touch the lease");

    // Operator resolves: mode-2 means the leaf was never appended → RevertedRetryable
    // + release (retry gets a NEW generation).
    let rec = reconcile_deposit_unknown(&pic, &s, fr(0x12));
    assert_eq!(rec, Ok(DepositAppendReconcileResult::RevertedRetryable));
    assert!(!lease_held(&pic, &s), "definite non-commit must release");

    // Everything drains: deposit 2 retry, spend promotion, deposit 3 retry.
    assert!(retry_deposit(&pic, &s, fr(0x12)).is_ok());
    assert_eq!(reconcile_spend(&pic, &s, 21), Ok(ReconcilePendingSpendResult::PromotedFinalized));
    assert!(retry_deposit(&pic, &s, fr(0x13)).is_ok());
    assert!(!lease_held(&pic, &s));

    // Head is finality-bound and matches the tree exactly.
    let h = head(&pic, &s).expect("head");
    assert_eq!(h.leaf_count, merkle_leaf_count(&pic, &s));
    assert_eq!(h.root, merkle_root(&pic, &s));
    assert!(is_accepted(&pic, &s, h.root));
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Head getter semantics + accepted-count correctness on both paths + CF-1 #1
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_head_getter_and_accepted_counts() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // None ONLY pre-acceptance.
    assert_eq!(head(&pic, &s), None);

    // Deposit path: expected post-append count = leaf_index + 1.
    deposit_ok(&pic, &s, fr(0x11));
    let h1 = head(&pic, &s).expect("head after first deposit");
    assert_eq!(h1.leaf_count, 1);
    assert_eq!(h1.root, merkle_root(&pic, &s));
    assert!(is_accepted(&pic, &s, h1.root), "head root must be an accepted anchor");

    // CF-1 regression 1: normal completion reaches the terminal
    // CommitmentRootAccepted AND leaves the P-REC active recovery index.
    match deposit_status(&pic, &s, fr(0x11)).map(|d| d.status) {
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, root }) => {
            assert_eq!(root, h1.root);
        }
        other => panic!("normal deposit completion must be CommitmentRootAccepted; got {:?}", other),
    }
    assert!(
        list_my_deposits(&pic, &s).is_empty(),
        "a completed deposit must be deindexed from the active recovery index"
    );

    deposit_ok(&pic, &s, fr(0x12));
    let h2 = head(&pic, &s).expect("head after second deposit");
    assert_eq!(h2.leaf_count, 2);

    // Spend path: expected post-append count = first_index + output_count.
    let ok = run_spend(&pic, &s, h2.root, 31, fr(0x21), (0x41, 0x42));
    assert!(ok.is_ok(), "spend must succeed; got {:?}", ok);
    let h3 = head(&pic, &s).expect("head after spend");
    assert_eq!(h3.leaf_count, 4, "2 deposits + 2 spend outputs");
    assert_eq!(h3.leaf_count, merkle_leaf_count(&pic, &s));
    assert_eq!(h3.root, merkle_root(&pic, &s));
    assert!(is_accepted(&pic, &s, h3.root));
    assert_eq!(spend_status(&pic, &s, 31), Some(SpendStatus::Finalized));
    assert!(!lease_held(&pic, &s));
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Monotonic-head pins: equal-count fork traps; lower count traps;
//    expected-count mismatch traps; idempotent same-head re-write allowed
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_monotonic_head_traps() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    let h = head(&pic, &s).expect("head");
    assert_eq!(h.leaf_count, 1);

    // Idempotent same-value re-write (roll-forward retry shape) is allowed.
    commit_head_call(&pic, &s, h.root, 1, 1).expect("idempotent same-head re-write must succeed");

    // Equal count, DIFFERENT root → fork → trap.
    let fork = commit_head_call(&pic, &s, fr(0xEE), 1, 1);
    assert!(fork.is_err(), "equal-count different-root must trap");

    // Lower count → regression → trap (not only the equal-count case).
    let regress = commit_head_call(&pic, &s, h.root, 0, 0);
    assert!(regress.is_err(), "lower leaf_count must trap");

    // Scan-head count != expected post-append count → trap.
    let mismatch = commit_head_call(&pic, &s, fr(0xEF), 3, 2);
    assert!(mismatch.is_err(), "expected-count mismatch must trap");

    // The head survives all trapped attempts unchanged.
    assert_eq!(head(&pic, &s), Some(h));
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Append-success ordering + interrupted spend finalization roll-forward
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_append_success_ordering_and_spend_rollforward() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    let anchor = head(&pic, &s).unwrap().root;

    // Interrupt finalization AFTER the append, at the scan-head fetch.
    force_scan_head_unavailable(&pic, &s, true);
    let r = run_spend(&pic, &s, anchor, 41, fr(0x21), (0x51, 0x52));
    assert!(matches!(r, Err(PoolError::TransferFailed(_))), "got {:?}", r);

    // ORDERING PIN: the durable record reads ActiveRootPending — it was written
    // BEFORE the scan-head fetch (never ActiveAppendInFlight during a root fetch).
    assert_eq!(spend_status(&pic, &s, 41), Some(SpendStatus::ActiveRootPending));
    let l = lease_owner_view(&pic, &s).expect("lease retained");
    assert_eq!(l.phase, LeasePhase::AppendConfirmedRootPending);
    assert_eq!(l.owner, AppendLeaseOwner::Spend { spend_id: 41 });

    // Pool-wide block while finalization is pending.
    let blocked = try_deposit(&pic, &s, fr(0x12));
    expect_lease_blocked("deposit while spend finalization pending", blocked);

    // Roll-forward: reconcile continues finalization under the SAME lease.
    force_scan_head_unavailable(&pic, &s, false);
    assert_eq!(reconcile_spend(&pic, &s, 41), Ok(ReconcilePendingSpendResult::PromotedFinalized));
    assert_eq!(spend_status(&pic, &s, 41), Some(SpendStatus::Finalized));
    assert!(!lease_held(&pic, &s));
    let h = head(&pic, &s).unwrap();
    assert_eq!(h.leaf_count, 3);
    assert!(is_accepted(&pic, &s, h.root));

    // The blocked deposit drains.
    assert!(retry_deposit(&pic, &s, fr(0x12)).is_ok());
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 4);
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. CF-1 (all three regressions) + deposit interrupted finalization, with a
//    REAL production-Wasm upgrade cycle in the middle
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_cf1_deposit_interrupted_finalization_upgrade_cycle() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Interrupt deposit finalization at the scan-head fetch: credit applied,
    // record CommitmentAppended, lease RETAINED at AppendConfirmedRootPending.
    force_scan_head_unavailable(&pic, &s, true);
    let d = try_deposit(&pic, &s, fr(0x11));
    assert!(d.is_ok(), "deposit reports success (credit applied); got {:?}", d);
    assert!(matches!(
        deposit_status(&pic, &s, fr(0x11)).map(|x| x.status),
        Some(DepositStatus::CommitmentAppended { leaf_index: 0 })
    ));
    let l = lease_owner_view(&pic, &s).expect("lease retained");
    assert_eq!(l.phase, LeasePhase::AppendConfirmedRootPending);

    // CF-1 regression 2: interrupted finalization STAYS recovery-indexed.
    assert_eq!(list_my_deposits(&pic, &s), vec![fr(0x11)]);
    assert_eq!(head(&pic, &s), None, "no head/root published before finality");
    assert!(!is_accepted(&pic, &s, merkle_root(&pic, &s)), "raw root must not be accepted");

    // REAL upgrade to the PRODUCTION Wasm: legal tuple
    // (AppendConfirmedRootPending, CommitmentAppended) → retain-continue-finalization.
    upgrade_to_prod(&pic, &s).expect("legal retained tuple must upgrade");
    let l2 = lease_owner_view(&pic, &s).expect("lease must survive upgrade");
    assert_eq!(l2.phase, LeasePhase::AppendConfirmedRootPending);
    assert_eq!(l2.generation, l.generation, "generation must survive upgrade");
    assert_eq!(list_my_deposits(&pic, &s), vec![fr(0x11)], "still indexed after upgrade");

    // Blocked pool-wide on the production Wasm too.
    let blocked = try_deposit(&pic, &s, fr(0x12));
    expect_lease_blocked("deposit while finalization pending (prod)", blocked);

    // CF-1 regression 3: roll-forward reconcile (production endpoint) reaches
    // CommitmentRootAccepted, deindexes, releases.
    reconcile_deposit(&pic, &s, fr(0x11)).expect("continue-finalization must succeed");
    match deposit_status(&pic, &s, fr(0x11)).map(|x| x.status) {
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, root }) => {
            assert!(is_accepted(&pic, &s, root));
            assert_eq!(head(&pic, &s), Some(AcceptedRootHead { root, leaf_count: 1 }));
        }
        other => panic!("expected CommitmentRootAccepted, got {:?}", other),
    }
    // fr(0x12)'s blocked attempt legitimately created a pending (indexed) record;
    // the roll-forward pin is that fr(0x11) itself left the index.
    assert!(
        !list_my_deposits(&pic, &s).contains(&fr(0x11)),
        "roll-forward must deindex the finalized deposit"
    );
    assert!(!lease_held(&pic, &s));

    // A second reconcile is idempotently rejected (terminal).
    assert_eq!(reconcile_deposit(&pic, &s, fr(0x12)), Err(PoolError::DepositNotReconcilable));

    // CF-1 regression 1 on the production Wasm: a clean deposit never rests in
    // the index.
    assert!(retry_deposit(&pic, &s, fr(0x12)).is_ok());
    assert!(matches!(
        deposit_status(&pic, &s, fr(0x12)).map(|x| x.status),
        Some(DepositStatus::CommitmentRootAccepted { .. })
    ));
    assert!(list_my_deposits(&pic, &s).is_empty());
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 2);
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. RED/GREEN unfinalized-leaf regression (C-ROOT-1) — SPEND path, with a real
//    production-Wasm upgrade cycle proving lease survival
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_unfinalized_leaf_regression_spend_path() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    let anchor = head(&pic, &s).unwrap().root;

    // Spend whose outputs LAND in the tree but whose response is lost: the tree
    // now contains unfinalized (unaccounted) leaves.
    force_active_append_unknown(&pic, &s, 1);
    let r = run_spend(&pic, &s, anchor, 51, fr(0x21), (0x61, 0x62));
    assert_eq!(r, Err(PoolError::OutputAppendUnknown));
    force_active_append_unknown(&pic, &s, 0);
    assert!(matches!(spend_status(&pic, &s, 51), Some(SpendStatus::ActiveAppendUnknown { .. })));
    assert_eq!(merkle_leaf_count(&pic, &s), 3, "outputs really landed");

    // C-ROOT-1 pin: the root covering the unfinalized leaves is NOT accepted.
    let unfinalized_root = merkle_root(&pic, &s);
    assert!(!is_accepted(&pic, &s, unfinalized_root));
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 1, "head still covers only finalized state");

    // GREEN (the RED scenario on pre-P-ROOT code): a concurrent deposit would
    // have fetched get_root and ACCEPTED a root covering the unfinalized spend
    // outputs. Now it is blocked by the pool-wide lease.
    let blocked = try_deposit(&pic, &s, fr(0x12));
    expect_lease_blocked("deposit while spend append unresolved", blocked);
    assert!(!is_accepted(&pic, &s, unfinalized_root), "still unaccepted after blocked deposit");

    // Production-Wasm upgrade cycle: the (AppendUnknown, ActiveAppendUnknown)
    // tuple survives verification; the lease persists.
    upgrade_to_prod(&pic, &s).expect("retained AppendUnknown tuple must upgrade");
    assert_eq!(lease_phase(&pic, &s), Some(LeasePhase::AppendUnknown), "lease survives upgrade");
    let blocked2 = retry_deposit(&pic, &s, fr(0x12));
    expect_lease_blocked("deposit still blocked on prod Wasm", blocked2);

    // Operator resolves on the production Wasm: outputs confirmed → finalize.
    assert_eq!(reconcile_spend(&pic, &s, 51), Ok(ReconcilePendingSpendResult::PromotedFinalized));
    assert_eq!(spend_status(&pic, &s, 51), Some(SpendStatus::Finalized));
    assert!(!lease_held(&pic, &s));
    let h = head(&pic, &s).unwrap();
    assert_eq!(h.leaf_count, 3);
    assert_eq!(h.root, unfinalized_root, "the root is accepted ONLY once the spend finalized");
    assert!(is_accepted(&pic, &s, unfinalized_root));

    // The blocked deposit drains.
    assert!(retry_deposit(&pic, &s, fr(0x12)).is_ok());
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 4);
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. RED/GREEN unfinalized-leaf regression (C-ROOT-1) — DEPOSIT path, with a
//    real production-Wasm upgrade cycle
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_unfinalized_leaf_regression_deposit_path() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    let anchor = head(&pic, &s).unwrap().root;

    // Deposit whose leaf LANDS but whose response is lost: uncredited leaf in tree.
    force_deposit_append_unknown(&pic, &s, 1);
    let d = try_deposit(&pic, &s, fr(0x12));
    assert!(matches!(d, Err(PoolError::CommitmentAppendFailed(_))), "got {:?}", d);
    force_deposit_append_unknown(&pic, &s, 0);
    assert_eq!(merkle_leaf_count(&pic, &s), 2, "leaf really landed");
    let unfinalized_root = merkle_root(&pic, &s);
    assert!(!is_accepted(&pic, &s, unfinalized_root));
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 1);

    // GREEN: a spend promotion (which on pre-P-ROOT code would accept a root
    // covering the uncredited deposit leaf) is blocked pool-wide.
    let sp = run_spend(&pic, &s, anchor, 61, fr(0x21), (0x71, 0x72));
    expect_lease_blocked("spend while deposit append unresolved", sp);
    assert!(!is_accepted(&pic, &s, unfinalized_root));

    // Production-Wasm upgrade cycle: lease survives.
    upgrade_to_prod(&pic, &s).expect("retained AppendUnknown tuple must upgrade");
    assert_eq!(lease_phase(&pic, &s), Some(LeasePhase::AppendUnknown));

    // Operator resolves: leaf present → finalize (credit exactly once) → head
    // advances over the now-finalized leaf.
    assert_eq!(reconcile_deposit_unknown(&pic, &s, fr(0x12)), Ok(DepositAppendReconcileResult::Finalized));
    assert!(!lease_held(&pic, &s));
    let h = head(&pic, &s).unwrap();
    assert_eq!(h.leaf_count, 2);
    assert_eq!(h.root, unfinalized_root);
    assert!(is_accepted(&pic, &s, unfinalized_root));
    assert!(matches!(
        deposit_status(&pic, &s, fr(0x12)).map(|x| x.status),
        Some(DepositStatus::CommitmentRootAccepted { leaf_index: 1, .. })
    ));

    // The blocked spend drains.
    assert_eq!(reconcile_spend(&pic, &s, 61), Ok(ReconcilePendingSpendResult::PromotedFinalized));
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 4);
}

// ═════════════════════════════════════════════════════════════════════════════
// 9. Definite rejection: status + compare-and-release in one step; retry gets a
//    NEW generation (both paths)
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_definite_rejection_releases_and_retry_gets_new_generation() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    let anchor = head(&pic, &s).unwrap().root;

    // Deposit-side definite rejection → revert + release.
    force_deposit_append_unknown(&pic, &s, 3);
    let d = try_deposit(&pic, &s, fr(0x12));
    assert!(matches!(d, Err(PoolError::CommitmentAppendFailed(_))), "got {:?}", d);
    force_deposit_append_unknown(&pic, &s, 0);
    assert_eq!(
        deposit_status(&pic, &s, fr(0x12)).map(|x| x.status),
        Some(DepositStatus::TransferConfirmedCommitmentPending)
    );
    assert!(!lease_held(&pic, &s), "definite rejection must release");
    assert!(retry_deposit(&pic, &s, fr(0x12)).is_ok());

    // Spend-side definite rejection → ActiveAppendRejected + release.
    force_active_append_unknown(&pic, &s, 3);
    let r = run_spend(&pic, &s, anchor, 71, fr(0x21), (0x81, 0x82));
    assert!(matches!(r, Err(PoolError::OutputAppendRejected(_))), "got {:?}", r);
    force_active_append_unknown(&pic, &s, 0);
    assert!(matches!(spend_status(&pic, &s, 71), Some(SpendStatus::ActiveAppendRejected { .. })));
    assert!(!lease_held(&pic, &s), "definite rejection must release");

    // Retry re-enters promote and acquires a NEW generation: interrupt the retry
    // at the scan-head fetch so the held lease (and its generation) is observable.
    force_scan_head_unavailable(&pic, &s, true);
    let rr = reconcile_spend(&pic, &s, 71);
    assert!(matches!(rr, Err(PoolError::TransferFailed(_))), "got {:?}", rr);
    let held = lease_owner_view(&pic, &s).expect("lease held at interrupted finalization");
    assert_eq!(held.phase, LeasePhase::AppendConfirmedRootPending);
    // Generations are handed out by a monotonic counter: the retry's generation
    // must be STRICTLY newer than every generation used before it in this test
    // (deposit 0x11 = g0, rejected deposit = g1, deposit retry = g2, rejected
    // spend = g3 → this retry must be at least g4).
    assert!(held.generation >= 4, "retry must run under a NEW generation; got {}", held.generation);

    force_scan_head_unavailable(&pic, &s, false);
    assert_eq!(reconcile_spend(&pic, &s, 71), Ok(ReconcilePendingSpendResult::PromotedFinalized));
    assert!(!lease_held(&pic, &s));
}

// ═════════════════════════════════════════════════════════════════════════════
// 10. Lease-release boundary: a stuck PayoutUnknown never blocks appends
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_stuck_payout_unknown_does_not_block_appends() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    let anchor = head(&pic, &s).unwrap().root;

    // Payout spend whose ledger transfer goes transport-unknown.
    force_payout_unknown(&pic, &s, true);
    let payout = 1_00000000u128; // 1 STSH
    let args = PrivateSpendArgs {
        spend_id: 81,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: anchor,
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![fr(0x21)],
        output_commitments: vec![fr(0x91), fr(0x92)],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: s.user,
            destination_subaccount: None,
            public_amount: payout,
        }),
    };
    let r: Result<(), PoolError> = decode(
        "private_spend",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()),
    );
    assert_eq!(r, Err(PoolError::PayoutOutcomeUnknown));
    force_payout_unknown(&pic, &s, false);
    assert!(matches!(spend_status(&pic, &s, 81), Some(SpendStatus::PayoutUnknown { .. })));

    // THE PIN: the lease was released BEFORE the payout await — the stuck payout
    // holds nothing, and fresh appends proceed.
    assert!(!lease_held(&pic, &s), "stuck PayoutUnknown must not hold the lease");
    let h_before = head(&pic, &s).unwrap();
    assert_eq!(h_before.leaf_count, 3, "spend outputs accepted before payout");
    deposit_ok(&pic, &s, fr(0x12));
    assert_eq!(head(&pic, &s).unwrap().leaf_count, 4, "appends live despite stuck payout");
}

// ═════════════════════════════════════════════════════════════════════════════
// 11. Reconcile admission: rejected during AppendInFlight; admitted only from
//     (AppendUnknown, ActiveAppendUnknown); deposit reconcile needs the lease
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_reconcile_admission_gates() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Spend record ActiveAppendInFlight + lease AppendInFlight (a live append):
    // reconcile REJECTED — the original callback may still be in flight.
    inject_spend(&pic, &s, 91, SpendStatus::ActiveAppendInFlight);
    inject_staged_outputs(&pic, &s, 91, vec![fr(0x61), fr(0x62)], Some(0));
    set_lease(&pic, &s, AppendLeaseOwner::Spend { spend_id: 91 }, LeasePhase::AppendInFlight);
    assert_eq!(reconcile_spend(&pic, &s, 91), Err(PoolError::WrongSpendStatus));
    assert_eq!(lease_phase(&pic, &s), Some(LeasePhase::AppendInFlight), "rejected reconcile must not mutate");

    // Move to the ADMITTED tuple: (AppendUnknown, ActiveAppendUnknown). The
    // staged outputs point at an empty tree slot → definite non-commit →
    // AppendRetryScheduled + release.
    clear_lease(&pic, &s);
    set_lease(&pic, &s, AppendLeaseOwner::Spend { spend_id: 91 }, LeasePhase::AppendUnknown);
    ctl_unit(
        &pic,
        &s,
        "set_spend_status_for_test",
        candid::encode_args((91u64, SpendStatus::ActiveAppendUnknown { reason: "t".into() })).unwrap(),
    );
    assert_eq!(reconcile_spend(&pic, &s, 91), Ok(ReconcilePendingSpendResult::AppendRetryScheduled));
    assert_eq!(spend_status(&pic, &s, 91), Some(SpendStatus::NullifierFinalizedOutputsPending));
    assert!(!lease_held(&pic, &s));

    // Deposit reconcile-unknown admission: record CommitmentAppendUnknown WITHOUT
    // the lease → rejected (invariant breach surfaced as not-reconcilable).
    inject_deposit_with_index(&pic, &s, fr(0x31), DepositStatus::CommitmentAppendUnknown, Some(0));
    assert_eq!(reconcile_deposit_unknown(&pic, &s, fr(0x31)), Err(PoolError::DepositNotReconcilable));

    // With the correct lease tuple it is admitted (empty slot → RevertedRetryable
    // + release).
    set_lease(&pic, &s, AppendLeaseOwner::Deposit { commitment: fr(0x31) }, LeasePhase::AppendUnknown);
    assert_eq!(reconcile_deposit_unknown(&pic, &s, fr(0x31)), Ok(DepositAppendReconcileResult::RevertedRetryable));
    assert!(!lease_held(&pic, &s));

    // reconcile_deposit_commitment on CommitmentAppended WITHOUT the lease →
    // rejected (continue-finalization requires the retained lease).
    inject_deposit_with_index(&pic, &s, fr(0x32), DepositStatus::CommitmentAppended { leaf_index: 0 }, Some(0));
    assert_eq!(reconcile_deposit(&pic, &s, fr(0x32)), Err(PoolError::DepositNotReconcilable));
}

// ═════════════════════════════════════════════════════════════════════════════
// 12. Upgrade tuple matrix — LEGAL deposit tuples hit their pinned actions
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_upgrade_legal_deposit_tuples() {
    // (phase, injected status, expected post-upgrade record, expected lease phase)
    struct Case {
        phase: LeasePhase,
        status: DepositStatus,
        expect_status: DepositStatus,
        expect_lease: Option<LeasePhase>,
    }
    let cases = vec![
        Case {
            phase: LeasePhase::Snapshotting,
            status: DepositStatus::TransferConfirmedCommitmentPending,
            expect_status: DepositStatus::TransferConfirmedCommitmentPending,
            expect_lease: None, // release-retryable
        },
        Case {
            phase: LeasePhase::AppendInFlight,
            status: DepositStatus::CommitmentAppendInFlight,
            expect_status: DepositStatus::CommitmentAppendUnknown,
            expect_lease: Some(LeasePhase::AppendUnknown), // normalize, retain
        },
        Case {
            phase: LeasePhase::AppendUnknown,
            status: DepositStatus::CommitmentAppendUnknown,
            expect_status: DepositStatus::CommitmentAppendUnknown,
            expect_lease: Some(LeasePhase::AppendUnknown), // retain-for-reconciliation
        },
        Case {
            phase: LeasePhase::ReconcileInFlight,
            status: DepositStatus::CommitmentReconcileInFlight,
            expect_status: DepositStatus::CommitmentAppendUnknown,
            expect_lease: Some(LeasePhase::AppendUnknown), // lost callback → retain
        },
        Case {
            phase: LeasePhase::AppendConfirmedRootPending,
            status: DepositStatus::CommitmentAppended { leaf_index: 0 },
            expect_status: DepositStatus::CommitmentAppended { leaf_index: 0 },
            expect_lease: Some(LeasePhase::AppendConfirmedRootPending), // continue-finalization
        },
    ];
    for case in cases {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = fr(0x21);
        inject_deposit_with_index(&pic, &s, c, case.status.clone(), Some(0));
        set_lease(&pic, &s, AppendLeaseOwner::Deposit { commitment: c }, case.phase);
        upgrade_to_prod(&pic, &s).unwrap_or_else(|e| {
            panic!("legal tuple ({:?}, {:?}) must upgrade; got {}", case.phase, case.status, e)
        });
        assert_eq!(
            deposit_status(&pic, &s, c).map(|d| d.status),
            Some(case.expect_status.clone()),
            "tuple ({:?}, {:?})",
            case.phase,
            case.status
        );
        assert_eq!(
            lease_phase(&pic, &s),
            case.expect_lease,
            "tuple ({:?}, {:?})",
            case.phase,
            case.status
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 13. Upgrade tuple matrix — LEGAL spend tuples hit their pinned actions
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_upgrade_legal_spend_tuples() {
    struct Case {
        phase: LeasePhase,
        status: SpendStatus,
        expect_status: SpendStatus,
        expect_lease: Option<LeasePhase>,
        expect_status_kind_only: bool, // ActiveAppendUnknown carries a reason string
    }
    let cases = vec![
        Case {
            phase: LeasePhase::Snapshotting,
            status: SpendStatus::NullifierFinalizedOutputsPending,
            expect_status: SpendStatus::NullifierFinalizedOutputsPending,
            expect_lease: None,
            expect_status_kind_only: false,
        },
        Case {
            phase: LeasePhase::Snapshotting,
            status: SpendStatus::ActiveAppendRejected { reason: "r".into() },
            expect_status: SpendStatus::ActiveAppendRejected { reason: "r".into() },
            expect_lease: None,
            expect_status_kind_only: false,
        },
        Case {
            phase: LeasePhase::AppendInFlight,
            status: SpendStatus::ActiveAppendInFlight,
            expect_status: SpendStatus::ActiveAppendUnknown { reason: String::new() },
            expect_lease: Some(LeasePhase::AppendUnknown),
            expect_status_kind_only: true,
        },
        Case {
            phase: LeasePhase::AppendUnknown,
            status: SpendStatus::ActiveAppendUnknown { reason: "u".into() },
            expect_status: SpendStatus::ActiveAppendUnknown { reason: "u".into() },
            expect_lease: Some(LeasePhase::AppendUnknown),
            expect_status_kind_only: false,
        },
        Case {
            phase: LeasePhase::ReconcileInFlight,
            status: SpendStatus::ActiveAppendUnknown { reason: "u".into() },
            expect_status: SpendStatus::ActiveAppendUnknown { reason: "u".into() },
            expect_lease: Some(LeasePhase::AppendUnknown), // record UNCHANGED, lease returns
            expect_status_kind_only: false,
        },
        Case {
            phase: LeasePhase::AppendConfirmedRootPending,
            status: SpendStatus::ActiveRootPending,
            expect_status: SpendStatus::ActiveRootPending,
            expect_lease: Some(LeasePhase::AppendConfirmedRootPending),
            expect_status_kind_only: false,
        },
    ];
    for case in cases {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        inject_spend(&pic, &s, 5, case.status.clone());
        inject_staged_outputs(&pic, &s, 5, vec![fr(0x61)], Some(0));
        set_lease(&pic, &s, AppendLeaseOwner::Spend { spend_id: 5 }, case.phase);
        upgrade_to_prod(&pic, &s).unwrap_or_else(|e| {
            panic!("legal tuple ({:?}, {:?}) must upgrade; got {}", case.phase, case.status, e)
        });
        let got = spend_status(&pic, &s, 5).expect("spend record must survive");
        if case.expect_status_kind_only {
            assert!(
                matches!(got, SpendStatus::ActiveAppendUnknown { .. }),
                "tuple ({:?}, {:?}) → got {:?}",
                case.phase,
                case.status,
                got
            );
        } else {
            assert_eq!(got, case.expect_status, "tuple ({:?}, {:?})", case.phase, case.status);
        }
        assert_eq!(
            lease_phase(&pic, &s),
            case.expect_lease,
            "tuple ({:?}, {:?})",
            case.phase,
            case.status
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 14. Upgrade tuple matrix — ILLEGAL tuples TRAP (upgrade rejected, state kept)
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_upgrade_illegal_tuples_trap() {
    // Deposit: lease phase × record status pairs OUTSIDE the normative table.
    let deposit_cases = vec![
        (LeasePhase::Snapshotting, DepositStatus::CommitmentAppended { leaf_index: 0 }),
        (LeasePhase::AppendUnknown, DepositStatus::CommitmentAppendInFlight),
        (
            LeasePhase::AppendConfirmedRootPending,
            DepositStatus::CommitmentRootAccepted { leaf_index: 0, root: [9u8; 32] },
        ),
    ];
    for (phase, status) in deposit_cases {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = fr(0x22);
        inject_deposit_with_index(&pic, &s, c, status.clone(), Some(0));
        set_lease(&pic, &s, AppendLeaseOwner::Deposit { commitment: c }, phase);
        let r = upgrade_to_prod(&pic, &s);
        assert!(r.is_err(), "illegal deposit tuple ({:?}, {:?}) must trap", phase, status);
        // Trap rolled the upgrade back: the (test) canister still answers.
        assert!(deposit_status(&pic, &s, c).is_some(), "state preserved after rejected upgrade");
    }

    // Spend: post-release states with a held lease, and phase/record mismatches.
    let spend_cases = vec![
        (LeasePhase::AppendConfirmedRootPending, SpendStatus::RootAccepted),
        (LeasePhase::AppendInFlight, SpendStatus::NullifierFinalizedOutputsPending),
        (LeasePhase::AppendUnknown, SpendStatus::PayoutPending { reason: "x".into() }),
        (LeasePhase::Snapshotting, SpendStatus::Finalized),
    ];
    for (phase, status) in spend_cases {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        inject_spend(&pic, &s, 6, status.clone());
        set_lease(&pic, &s, AppendLeaseOwner::Spend { spend_id: 6 }, phase);
        let r = upgrade_to_prod(&pic, &s);
        assert!(r.is_err(), "illegal spend tuple ({:?}, {:?}) must trap", phase, status);
    }

    // Lease owner with NO record at all → trap.
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    set_lease(&pic, &s, AppendLeaseOwner::Spend { spend_id: 404 }, LeasePhase::AppendUnknown);
    assert!(upgrade_to_prod(&pic, &s).is_err(), "lease with missing owner record must trap");
}

// ═════════════════════════════════════════════════════════════════════════════
// 15. First-install sweep: lease-free unresolved records TRAP; pre-head
//     deployment with accepted roots is REJECTED; empty + populated upgrades OK
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_upgrade_first_install_and_head_migration_pins() {
    // Empty pool: upgrade succeeds; head stays None.
    {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        upgrade_to_prod(&pic, &s).expect("empty pool upgrade must succeed");
        assert_eq!(head(&pic, &s), None);
    }

    // Populated pool (real deposit + spend): upgrade succeeds; head PRESERVED.
    {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        deposit_ok(&pic, &s, fr(0x11));
        let anchor = head(&pic, &s).unwrap().root;
        assert!(run_spend(&pic, &s, anchor, 3, fr(0x21), (0x41, 0x42)).is_ok());
        let before = head(&pic, &s).unwrap();
        upgrade_to_prod(&pic, &s).expect("populated pool upgrade must succeed");
        assert_eq!(head(&pic, &s), Some(before), "head must be preserved across upgrade");
    }

    // Lease-free unresolved deposit record → TRAP (first-install sweep).
    for status in [
        DepositStatus::CommitmentAppendUnknown,
        DepositStatus::CommitmentAppended { leaf_index: 0 },
        DepositStatus::CommitmentAppendInFlight,
        DepositStatus::CommitmentReconcileInFlight,
    ] {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        inject_deposit_with_index(&pic, &s, fr(0x23), status.clone(), Some(0));
        assert!(
            upgrade_to_prod(&pic, &s).is_err(),
            "lease-free deposit {:?} must trap the upgrade",
            status
        );
    }

    // Lease-free unresolved spend record → TRAP.
    for status in [
        SpendStatus::ActiveAppendUnknown { reason: "u".into() },
        SpendStatus::ActiveAppendInFlight,
        SpendStatus::ActiveRootPending,
    ] {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        inject_spend(&pic, &s, 7, status.clone());
        inject_staged_outputs(&pic, &s, 7, vec![fr(0x61)], Some(0));
        assert!(
            upgrade_to_prod(&pic, &s).is_err(),
            "lease-free spend {:?} must trap the upgrade",
            status
        );
    }

    // Pre-head deployment shape: accepted roots exist but no head → REJECTED.
    {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let _: Result<(), String> = decode(
            "accept_spend_root_for_test",
            pic.update_call(
                s.pool,
                s.controller,
                "accept_spend_root_for_test",
                candid::encode_one(fr(0x55).to_vec()).unwrap(),
            ),
        );
        assert_eq!(head(&pic, &s), None, "test-only root insert does not write a head");
        assert!(
            upgrade_to_prod(&pic, &s).is_err(),
            "pre-head deployment with accepted roots must be rejected"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 16. get_accepted_root_head consistency with is_accepted_spend_root
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_head_matches_accepted_set() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    assert_eq!(head(&pic, &s), None, "None only pre-acceptance");

    deposit_ok(&pic, &s, fr(0x11));
    deposit_ok(&pic, &s, fr(0x12));
    let anchor = head(&pic, &s).unwrap().root;
    assert!(run_spend(&pic, &s, anchor, 4, fr(0x21), (0x43, 0x44)).is_ok());

    let h = head(&pic, &s).unwrap();
    assert!(is_accepted(&pic, &s, h.root), "the head root is always an accepted anchor");
    assert_eq!(h.leaf_count, merkle_leaf_count(&pic, &s), "head is bound to the exact tree size");
}

// ═════════════════════════════════════════════════════════════════════════════
// R2-17. Public lease surface: ONLY {held, phase, age_bucket}; no generation,
//        no exact timestamps; owner view is controller-gated
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_r2_public_lease_status_shape_and_owner_gate() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Free lease → held=false and nothing else.
    let free: AppendLeaseStatusProbe = decode(
        "get_append_lease_status",
        pic.query_call(s.pool, anon(), "get_append_lease_status", candid::encode_args(()).unwrap()),
    );
    assert!(!free.held);
    assert_eq!(free.phase, None);
    assert_eq!(free.age_bucket, None);

    // Held lease → held/phase/age_bucket present; the widened probe mirror
    // proves the reply carries NO generation and NO exact timestamps (candid
    // fills genuinely absent opt fields with None).
    let owner = AppendLeaseOwner::Spend { spend_id: 5 };
    let g = set_lease(&pic, &s, owner, LeasePhase::AppendUnknown);
    let held: AppendLeaseStatusProbe = decode(
        "get_append_lease_status",
        pic.query_call(s.pool, anon(), "get_append_lease_status", candid::encode_args(()).unwrap()),
    );
    assert!(held.held);
    assert_eq!(held.phase, Some(LeasePhase::AppendUnknown));
    assert_eq!(held.age_bucket, Some(LeaseAgeBucket::UnderMinute));
    assert_eq!(held.generation, None, "generation must NOT be public");
    assert_eq!(held.acquired_at_ns, None, "acquired_at_ns must NOT be public");
    assert_eq!(held.phase_started_at_ns, None, "phase_started_at_ns must NOT be public");

    // The bucket coarsens with age — after two simulated hours it reads OverHour.
    pic.advance_time(std::time::Duration::from_secs(2 * 3600));
    pic.tick();
    let aged: AppendLeaseStatusProbe = decode(
        "get_append_lease_status",
        pic.query_call(s.pool, anon(), "get_append_lease_status", candid::encode_args(()).unwrap()),
    );
    assert_eq!(aged.age_bucket, Some(LeaseAgeBucket::OverHour));

    // Owner view: rejected for anonymous AND for a plain user; served with the
    // exact generation for the controller.
    assert!(
        pic.query_call(s.pool, anon(), "get_append_lease_owner", candid::encode_args(()).unwrap())
            .is_err(),
        "anonymous get_append_lease_owner must be rejected"
    );
    assert!(
        pic.query_call(s.pool, s.user, "get_append_lease_owner", candid::encode_args(()).unwrap())
            .is_err(),
        "non-controller get_append_lease_owner must be rejected"
    );
    let view = lease_owner_view(&pic, &s).expect("controller sees the owner view");
    assert_eq!(view.generation, g);
    assert_eq!(view.owner, owner);

    assert!(try_release(&pic, &s, owner, g));
}

// ═════════════════════════════════════════════════════════════════════════════
// R2-18. S-45: after the P-REC stamp, upgrade verification is INDEX-only —
//        >1000 terminal records in each main map cannot block the upgrade,
//        and the retained lease tuple still verifies + roll-forwards
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_r2_upgrade_terminal_volume_does_not_block_after_stamp() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Version-0 upgrade with a tiny state: one-shot build + STAMP.
    deposit_ok(&pic, &s, fr(0x11));
    upgrade_to_prod(&pic, &s).expect("version-0 upgrade must succeed");
    let h1 = head(&pic, &s).expect("head preserved");
    upgrade_to_test(&pic, &s).expect("back to test wasm (stamped path)");

    // Flood BOTH main maps past the 1,000-record scan cap with TERMINAL records
    // (indexed in the retention indexes only — never in the ACTIVE indexes).
    for i in 0..1010u32 {
        let mut c = [0u8; 32];
        c[0] = 0xE0;
        c[1..5].copy_from_slice(&i.to_be_bytes());
        let _: () = decode(
            "inject_terminal_deposit_for_test",
            pic.update_call(s.pool, s.controller, "inject_terminal_deposit_for_test",
                candid::encode_args((c, i as u64 + 100, i as u64 + 1)).unwrap()),
        );
        let _: () = decode(
            "inject_terminal_spend_for_test",
            pic.update_call(s.pool, s.controller, "inject_terminal_spend_for_test",
                candid::encode_args((10_000u64 + i as u64, SpendStatus::Finalized, i as u64 + 1)).unwrap()),
        );
    }

    // Small ACTIVE set: one real interrupted deposit finalization — record
    // CommitmentAppended, lease RETAINED at AppendConfirmedRootPending, indexed.
    force_scan_head_unavailable(&pic, &s, true);
    assert!(try_deposit(&pic, &s, fr(0x12)).is_ok());
    force_scan_head_unavailable(&pic, &s, false);
    assert_eq!(lease_phase(&pic, &s), Some(LeasePhase::AppendConfirmedRootPending));

    // THE PIN: the stamped upgrade inspects only the active indexes — the
    // >1000-record terminal volume in each main map cannot hold it hostage.
    upgrade_to_prod(&pic, &s)
        .expect("stamped upgrade must succeed regardless of terminal-record volume");
    assert_eq!(lease_phase(&pic, &s), Some(LeasePhase::AppendConfirmedRootPending), "lease tuple survives");
    assert!(matches!(
        deposit_status(&pic, &s, fr(0x12)).map(|d| d.status),
        Some(DepositStatus::CommitmentAppended { .. })
    ));

    // Roll-forward completes on the production Wasm.
    reconcile_deposit(&pic, &s, fr(0x12)).expect("continue-finalization");
    assert!(!lease_held(&pic, &s));
    assert_eq!(head(&pic, &s).unwrap().leaf_count, h1.leaf_count + 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// R2-19. Complement: at a STAMPED version the index-driven sweep still catches
//        an (indexed) illegal lease-free tuple and REJECTS the upgrade
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn proot_r2_stamped_illegal_tuple_still_traps() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    deposit_ok(&pic, &s, fr(0x11));
    upgrade_to_prod(&pic, &s).expect("version-0 upgrade must succeed");
    upgrade_to_test(&pic, &s).expect("back to test wasm (stamped path)");

    // A REAL deposit attempt whose append is definitively rejected leaves an
    // indexed TransferConfirmedCommitmentPending record (lease released)…
    force_deposit_append_unknown(&pic, &s, 3);
    let d = try_deposit(&pic, &s, fr(0x12));
    assert!(matches!(d, Err(PoolError::CommitmentAppendFailed(_))), "got {:?}", d);
    force_deposit_append_unknown(&pic, &s, 0);
    // …which is then corrupted into a lease-REQUIRING status with the lease free
    // (the index entry from the real flow persists).
    inject_deposit_with_index(&pic, &s, fr(0x12), DepositStatus::CommitmentAppendUnknown, Some(1));

    let r = upgrade_to_prod(&pic, &s);
    assert!(r.is_err(), "stamped index-driven sweep must still reject the illegal tuple");
    // Trap rolled back: the canister still answers with the staged state intact.
    assert_eq!(
        deposit_status(&pic, &s, fr(0x12)).map(|x| x.status),
        Some(DepositStatus::CommitmentAppendUnknown)
    );
}
