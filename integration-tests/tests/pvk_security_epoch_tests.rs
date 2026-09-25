// =============================================================================
// STSH — P-VK (POOL-04): security-epoch revalidation in private_spend
// =============================================================================
//
// Closes POOL-04 (Medium security-boundary race, externally confirmed, SSA-adjudicated
// v2.1; BRIEF_WALLET_B_PHASE2_FINISH §7.8, ruling V3.8 + C2a/V3.8.2):
//
//   private_spend makes an async inter-canister call to the verifier. During
//   that await the pool's security configuration can change underneath it —
//   VK activation, verifier-principal replacement, spend pause/unpause. The
//   durable monotonic SECURITY_EPOCH (stable cell, MemoryId 16) is captured
//   after static envelope validation, before the FIRST await, and revalidated
//   EXACTLY ONCE, in the same no-await segment as the first irreversible
//   transition (15a nullifier reservation):
//     (1) maybe_activate_pending_vk() FIRST (forces any overdue lazy
//         time-gated activation — the C2a cutoff-crossing fix),
//     (2) compare the captured epoch,
//     (3) verify record/status ownership,
//     (4) enter NullifierReserved.
//   Mismatch → the pre-mutation record + recovery locator are REMOVED
//   atomically and the typed, retryable PoolError::SecurityEpochChanged is
//   returned (a same-spend_id retry does NOT hit DuplicateSpendId). Past 15a
//   the epoch is never re-checked — roll-forward law governs.
//   Fee/params changes are NOT epoch events (snapshotted per-spend) and must
//   never abort a spend.
//
// The no-await property of the C2a segment is a source invariant: there is no
// .await between the C2a block at the top of commit_private_spend and the 15a
// reservation write (15-pre checks are synchronous). Tests (a′)/(a″) prove the
// behavior that depends on it end-to-end.
//
// HARNESS (P-VK harness ruling, Option 3): REAL async interleaving via the
// test-only nested-action stub verifier plus a testing-only CLOCK-BOUNDARY
// INJECTION. A enters the real production private_spend path and suspends at
// the real verifier await; the stub's one-shot nested action fires DURING
// that await: controller-authorized pause/unpause (b), verifier replacement
// (c), fee-params mutation (fee test), or — for (a′)/(a″) — the
// controller-gated #[cfg(feature="testing")] backdate endpoint that moves the
// scheduled VK activation to "due now" WITHOUT activating the VK, changing
// any pin, or bumping the epoch (substituting only the passage of time
// PocketIC cannot perform: measured 1 ns per block, and reply-less executions
// are auto-completed, so no held-reply construction is possible here). For
// (a′) the stub then fires a wrong-version nested spend whose real C1a
// applies the overdue activation; for (a″) nothing triggers activation — A's
// own real C2a segment must. Controller-authorized nested actions use the
// dedicated deploy_elevated_controller_stub_stack fixture, where the stub
// principal IS the pool's configured controller — never the default stack.
// (d) uses the established inject + real upgrade_canister pattern.
//
// RED/GREEN: (a) and (a″) are the RED/GREEN pair — (a) RED on the pre-P-VK
// build (pins were read BEFORE activating → VerifyingKeyMismatch); (a″) RED
// with C2a's activation-first step removed (nothing applies the overdue
// activation → the compare passes → A FINALIZES under the retired VK).
// Decoding Err(SecurityEpochChanged) off the wire in (a′)/(a″)/(b)/(c) is the
// candid round-trip proof for the new DID variant (no didc in this env).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): POOL_WASM (production),
// POOL_TEST_WASM (for (d)'s injection), STUB_VERIFIER_WASM with the P-VK
// nested-action surface; POCKET_IC_BIN must be set.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(w) => w,
        Err(e) => panic!(
            "read {} wasm at {} failed: {:?} — run the Law-#7 two-phase build first",
            pkg, path, e
        ),
    }
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_prod_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

/// Pre-P-VK production pool Wasm, built from the 71491f8 base this lane was
/// cut from. Not committed — produce it with:
///   git worktree add --detach /tmp/stsh-base-71491f8 71491f8 && \
///   (cd /tmp/stsh-base-71491f8 && \
///    cargo build --target wasm32-unknown-unknown --release -p shielded_pool) && \
///   cp /tmp/stsh-base-71491f8/target/wasm32-unknown-unknown/release/shielded_pool.wasm \
///      target/wasm32-unknown-unknown/release/shielded_pool_base_71491f8.wasm
/// (P-MRK/P-REC base-Wasm precedent; a missing prerequisite fails loudly.)
fn pool_base_71491f8_wasm() -> Vec<u8> {
    let default = std::path::PathBuf::from(env!("POOL_WASM"))
        .with_file_name("shielded_pool_base_71491f8.wasm");
    let path = std::env::var("POOL_BASE_71491F8_WASM")
        .map(std::path::PathBuf::from)
        .unwrap_or(default);
    assert!(
        path.exists(),
        "Missing the pre-P-VK (71491f8) base shielded_pool Wasm at {} — see the \
         build instructions on pool_base_71491f8_wasm (mandatory P-VK gate prerequisite)",
        path.display()
    );
    std::fs::read(&path).expect("read base pool wasm")
}

// ── Constants ───────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM_1000: u128 = 1_000 * 100_000_000; // DENOMINATIONS[3]
const DEFAULT_FEE: u128 = 0; // token transfers free at launch
const DAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const NEW_VK: [u8; 32] = [0x77u8; 32];

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
#[allow(dead_code)]
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

#[derive(CandidType, Serialize)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
    /// Optional for Candid-subtyping compat with pre-A2-2 callers (absent → None).
    verifier_canister: Option<Principal>,
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
/// Decode-compatible view of PendingSpend (candid record subtyping drops the
/// fields we do not declare; we only read `status` / `spend_id`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpendView {
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    outputs_committed: u32,
    status: SpendStatus,
    created_at_ns: u64,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ActiveSpendsPage {
    spends: Vec<PendingSpendView>,
    next_cursor: Option<u64>,
}
/// Decode-compatible superset mirror of the pool's PoolError (variant names +
/// payload types byte-identical to shielded_pool.did; same mechanism as the
/// treasury mirror). Includes SecurityEpochChanged so this file also compiles
/// and runs against the pre-P-VK build for RED evidence (never emitted there).
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
    SecurityEpochChanged,
}
/// Mirror of the stub verifier's P-VK nested-action surface.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum NestedAction {
    PauseThenUnpause { pool: Principal },
    VerifierRoundTrip { pool: Principal, other: Principal },
    MutateFeeParams { pool: Principal },
    BackdateOnly { pool: Principal },
    BackdateAndTriggerActivation { pool: Principal, spend_id: u64, expected_new_version: u32 },
    DisableCircuitVersion { pool: Principal, version: u32 },
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal { Principal::anonymous() }
fn fr(b: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = b;
    out
}
fn nf(b: u8) -> [u8; 32] { fr(b) }

struct Stack {
    pool: Principal,
    token: Principal,
    merkle: Principal,
    verifier: Principal,
    controller: Principal,
    staking: Principal,
    user: Principal,
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}
fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).unwrap(), None);
}
fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: candid::CandidType + for<'de> Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {:?}", label, e))
}

/// The DEFAULT P-VK stack: production pool Wasm, controller = ordinary test
/// principal, stub verifier wired via set_verifier_canister.
fn deploy_stack(pic: &PocketIc) -> Stack {
    deploy_stack_with(pic, pool_prod_wasm(), p(0xC0), None)
}

/// ELEVATED fixture (P-VK harness ruling §3): the STUB VERIFIER's principal is
/// the pool's configured controller, so its nested actions (pause/unpause,
/// verifier replacement, fee-params mutation, and the testing-only backdate
/// endpoint) are controller-authorized during a parked spend's verifier
/// await. NEVER the default stack; only tests (a′)/(a″)/(b)/(c) and the fee
/// test use it. The verifier is wired via InitArgs (the harness cannot sign
/// as the stub to call set_verifier_canister). (a′)/(a″) need the TEST Wasm
/// (the backdate endpoint is #[cfg(feature = "testing")]).
fn deploy_elevated_controller_stub_stack(pic: &PocketIc) -> Stack {
    deploy_elevated_controller_stub_stack_with(pic, pool_prod_wasm())
}

fn deploy_elevated_controller_stub_stack_with(pic: &PocketIc, pool_wasm: Vec<u8>) -> Stack {
    let verifier = create_canister(pic);
    pic.install_canister(
        verifier,
        stub_verifier_wasm(),
        candid::encode_one(None::<[u8; 32]>).unwrap(),
        None,
    );
    deploy_stack_with(pic, pool_wasm, verifier, Some(verifier))
}

fn deploy_stack_with(
    pic: &PocketIc,
    pool_wasm: Vec<u8>,
    controller: Principal,
    init_verifier: Option<Principal>,
) -> Stack {
    let staking = p(0x02);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);
    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    let verifier = match init_verifier {
        Some(v) => v,
        None => {
            let v = create_canister(pic);
            pic.install_canister(
                v,
                stub_verifier_wasm(),
                candid::encode_one(None::<[u8; 32]>).unwrap(),
                None,
            );
            v
        }
    };
    install(pic, token, token_wasm(), &all_to(user));
    install(
        pic,
        pool,
        pool_wasm,
        &PoolInitArgs {
            token_canister: token,
            nullifier_canister: null,
            merkle_canister: merkle,
            treasury_canister: p(0x01),
            staking_canister: staking,
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
            verifier_canister: init_verifier,
        },
    );
    if init_verifier.is_none() {
        // Wire the stub verifier (pin attestation: stub reports [0;32] = init pin).
        let _: Result<(), PoolError> = decode(
            "set_verifier_canister",
            pic.update_call(
                pool,
                controller,
                "set_verifier_canister",
                candid::encode_args((verifier, vec![0u8; 32])).unwrap(),
            ),
        );
    }
    Stack { pool, token, merkle, verifier, controller, staking, user }
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

fn deposit_ok(pic: &PocketIc, s: &Stack, commitment: [u8; 32]) {
    approve(pic, s, DENOM_1000 + DEFAULT_FEE);
    let r: Result<Nat, PoolError> = decode(
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
    assert!(r.is_ok(), "deposit must succeed; got {:?}", r);
}

/// One deposit seeds the accepted-root anchor every spend in a test shares
/// (accepted roots are append-only — a once-accepted anchor stays valid).
fn fund_and_anchor(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    deposit_ok(pic, s, fr(0xF1));
    let root = merkle_root(pic, s);
    assert!(is_accepted(pic, s, root), "deposit root must be accepted");
    root
}

fn spend_args_vk(
    anchor: [u8; 32],
    spend_id: u64,
    nullifier: [u8; 32],
    outs: (u8, u8),
    circuit_version: u32,
    vk_hash: [u8; 32],
) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: vk_hash,
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
/// The PRE-F1-PRIV argument shape, for calls made against the PINNED BASE Wasm
/// (`shielded_pool_base_71491f8`). Lane F1-PRIV deleted the cleartext
/// `input_amounts`/`output_amounts` fields from `PrivateSpendArgs`; the base
/// build predates that and its candid type declares them NON-OPTIONAL, so it
/// traps on an argument that omits them. The base build's interface is a fact
/// about a pinned artifact, not something this lane can change — so the calls
/// that target it speak its shape, explicitly, here.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct LegacyPrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    input_amounts: Vec<u128>,
    output_amounts: Vec<u128>,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PrivateSpendPublicPayout>,
}

/// Same spend as `spend_args`, in the base build's shape. The declared amounts
/// are balanced so the base build's (now-deleted) sum check passes.
fn legacy_spend_args(
    anchor: [u8; 32],
    spend_id: u64,
    nullifier: [u8; 32],
    outs: (u8, u8),
) -> LegacyPrivateSpendArgs {
    let a = spend_args(anchor, spend_id, nullifier, outs);
    LegacyPrivateSpendArgs {
        spend_id: a.spend_id,
        envelope: a.envelope,
        input_amounts: vec![0],
        output_amounts: vec![0, 0],
        nullifiers: a.nullifiers,
        output_commitments: a.output_commitments,
        encrypted_outputs: a.encrypted_outputs,
        fee: a.fee,
        public_payout: a.public_payout,
    }
}

fn run_legacy_spend_args(
    pic: &PocketIc,
    s: &Stack,
    args: LegacyPrivateSpendArgs,
) -> Result<(), PoolError> {
    decode(
        "private_spend (base build shape)",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()),
    )
}

/// Envelope pinned to the CURRENT (pre-activation) VK: version 0, [0;32].
fn spend_args(anchor: [u8; 32], spend_id: u64, nullifier: [u8; 32], outs: (u8, u8)) -> PrivateSpendArgs {
    spend_args_vk(anchor, spend_id, nullifier, outs, 0, [0u8; 32])
}

fn run_spend_args(pic: &PocketIc, s: &Stack, args: PrivateSpendArgs) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()),
    )
}
fn run_spend_args_as(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    args: PrivateSpendArgs,
) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(s.pool, caller, "private_spend", candid::encode_one(args).unwrap()),
    )
}

fn configure_stub(pic: &PocketIc, stub: Principal, action: NestedAction) {
    let _: () = decode(
        "configure_nested_action",
        pic.update_call(stub, anon(), "configure_nested_action", candid::encode_one(Some(action)).unwrap()),
    );
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
fn is_accepted(pic: &PocketIc, s: &Stack, root: [u8; 32]) -> bool {
    decode(
        "is_accepted_spend_root",
        pic.query_call(s.pool, anon(), "is_accepted_spend_root", candid::encode_one(root.to_vec()).unwrap()),
    )
}
fn spend_status_as(pic: &PocketIc, s: &Stack, caller: Principal, spend_id: u64) -> Option<SpendStatus> {
    let rec: Option<PendingSpendView> = decode(
        "get_spend_status",
        pic.query_call(s.pool, caller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    );
    rec.map(|r| r.status)
}
fn spend_status(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<SpendStatus> {
    spend_status_as(pic, s, s.controller, spend_id)
}
fn active_spend_ids_as(pic: &PocketIc, s: &Stack, caller: Principal) -> Vec<u64> {
    let page: ActiveSpendsPage = decode(
        "list_my_active_spends",
        pic.query_call(s.pool, caller, "list_my_active_spends", candid::encode_args((None::<u64>, 100u64)).unwrap()),
    );
    page.spends.iter().map(|v| v.spend_id).collect()
}
fn active_spend_ids(pic: &PocketIc, s: &Stack) -> Vec<u64> {
    active_spend_ids_as(pic, s, s.user)
}
/// Advisory epoch read. Option<u64> so this file also RUNS against the
/// pre-P-VK build (method absent → None) for RED evidence.
fn epoch(pic: &PocketIc, s: &Stack) -> Option<u64> {
    pic.query_call(s.pool, anon(), "get_security_epoch", candid::encode_args(()).unwrap())
        .ok()
        .map(|bytes| candid::decode_one(&bytes).expect("decode get_security_epoch"))
}
fn pinned_vk(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    decode(
        "get_pinned_vk_hash",
        pic.query_call(s.pool, anon(), "get_pinned_vk_hash", candid::encode_args(()).unwrap()),
    )
}
fn is_spends_paused(pic: &PocketIc, s: &Stack) -> bool {
    decode(
        "is_spends_paused",
        pic.query_call(s.pool, anon(), "is_spends_paused", candid::encode_args(()).unwrap()),
    )
}
fn verifier_of(pic: &PocketIc, s: &Stack) -> Option<Principal> {
    decode(
        "get_verifier_canister",
        pic.query_call(s.pool, anon(), "get_verifier_canister", candid::encode_args(()).unwrap()),
    )
}
fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

/// schedule_vk_activation is governance-gated (caller must be the staking
/// canister principal recorded at init).
fn schedule_activation(pic: &PocketIc, s: &Stack, new_version: u32, new_hash: [u8; 32], activation_ns: u64, cutoff_ns: u64) {
    let r: Result<(), String> = decode(
        "schedule_vk_activation",
        pic.update_call(
            s.pool,
            s.staking,
            "schedule_vk_activation",
            candid::encode_args((new_version, new_hash.to_vec(), activation_ns, cutoff_ns)).unwrap(),
        ),
    );
    assert_eq!(r, Ok(()), "schedule_vk_activation must succeed");
}

/// LAUNCH-HARDEN-04 O-5: a VK activation swaps the pool's pin, which misses
/// its (verifier, pin) attestation cache — the pool then re-attests the
/// verifier's LIVE `vk_hash` against the NEW pin and refuses a mismatch
/// (`VerifierKeyHashMismatch`). The production counterpart of a VK activation
/// is therefore an upgrade of the verifier to the new VK; here the stub is
/// REINSTALLED at the same principal reporting `vk`.
fn stub_reports(pic: &PocketIc, s: &Stack, vk: [u8; 32]) {
    pic.reinstall_canister(s.verifier, stub_verifier_wasm(), candid::encode_one(Some(vk)).unwrap(), None)
        .expect("reinstall the stub verifier reporting the new VK");
}

fn upgrade_to_prod(pic: &PocketIc, s: &Stack) {
    // Same install-rate-limit handling as the H-1/P-ROOT suites: two
    // back-to-back install_code messages of the ~1.5 MB Wasm can trip
    // PocketIC's per-canister install rate limit (a harness budget).
    pic.advance_time(Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade must succeed");
}

// =============================================================================
// (a) BOUNDARY — the request that ITSELF triggers VK activation validates
// against the NEW pin, captures the NEW epoch, and succeeds (its final epoch
// comparison succeeds — nothing changed afterward).
//
// RED on the pre-P-VK build: verify_proof_envelope read the pins BEFORE
// activating, so this request is rejected VerifyingKeyMismatch.
// =============================================================================
#[test]
fn pvk_a_boundary_request_validates_against_new_pin() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = fund_and_anchor(&pic, &s);

    let e0 = epoch(&pic, &s);
    let activation = now_ns(&pic) + 60 * 1_000_000_000;
    schedule_activation(&pic, &s, 1, NEW_VK, activation, activation + 7 * DAY_NS);
    assert_eq!(epoch(&pic, &s), e0, "scheduling is not an epoch event — activation is");
    assert_eq!(pinned_vk(&pic, &s), [0u8; 32], "VK not yet activated");

    pic.advance_time(Duration::from_secs(61));
    // LAUNCH-HARDEN-04 O-5: the verifier must report the NEW VK once it activates.
    stub_reports(&pic, &s, NEW_VK);

    // The boundary request carries the NEW pin and arrives after the
    // activation timestamp: C1a activates first, then validates.
    let b = run_spend_args(&pic, &s, spend_args_vk(root, 2, nf(0x21), (0x22, 0x23), 1, NEW_VK));
    // RED marker: pre-P-VK this is Err(VerifyingKeyMismatch).
    assert_eq!(b, Ok(()), "boundary request must validate against the NEW pin and succeed; got {:?}", b);

    assert_eq!(pinned_vk(&pic, &s), NEW_VK, "the boundary request itself triggered activation");
    assert_eq!(epoch(&pic, &s).unwrap(), e0.unwrap() + 1, "exactly one epoch event (the activation)");
    assert_eq!(spend_status(&pic, &s, 2), Some(SpendStatus::Finalized),
        "captured the NEW epoch; nothing changed afterward → final comparison succeeds");
}

// =============================================================================
// (a′) MID-FLIGHT activation — A is admitted under the OLD pin (the scheduled
// activation is still in the future), captures the OLD epoch, and suspends in
// the REAL verifier await. The stub's one-shot nested action then (1) calls
// the testing-only clock-boundary injection (backdate the scheduled activation
// to "due now" — the returned before/after probe proves NOTHING else changed:
// pin untouched, epoch untouched) and (2) fires a well-formed but wrong-version
// private_spend whose REAL C1a applies the now-overdue activation (asserted:
// CircuitVersionMismatch carries the NEW version). A resumes → its real C2a
// segment detects the changed epoch → SecurityEpochChanged BEFORE the
// nullifier reservation; record + recovery locator REMOVED; same-spend_id
// retry under the new pin does NOT hit DuplicateSpendId.
//
// The injection substitutes ONLY PocketIC's unavailable passage of time; the
// admission, verifier await, nested activation, resume, C2a, cleanup, and
// retry are all the real production path.
// =============================================================================
#[test]
fn pvk_a_prime_midflight_activation_aborts_stale_spend() {
    let pic = PocketIc::new();
    // ELEVATED fixture on the TEST Wasm: the backdate endpoint is
    // controller-gated (the stub must be the pool's controller) and
    // #[cfg(feature = "testing")].
    let s = deploy_elevated_controller_stub_stack_with(&pic, pool_test_wasm());
    let root = fund_and_anchor(&pic, &s);

    let activation = now_ns(&pic) + 60 * 1_000_000_000;
    schedule_activation(&pic, &s, 1, NEW_VK, activation, activation + 7 * DAY_NS);
    let e0 = epoch(&pic, &s);

    configure_stub(
        &pic,
        s.verifier,
        NestedAction::BackdateAndTriggerActivation { pool: s.pool, spend_id: 900, expected_new_version: 1 },
    );

    let a = run_spend_args(&pic, &s, spend_args(root, 10, nf(0x31), (0x32, 0x33)));
    // This is also the candid round-trip proof for the new DID variant.
    assert_eq!(a, Err(PoolError::SecurityEpochChanged),
        "A must abort with SecurityEpochChanged before any irreversible transition; got {:?}", a);

    assert_eq!(pinned_vk(&pic, &s), NEW_VK, "the nested C1a applied the overdue activation");
    assert_eq!(epoch(&pic, &s).unwrap(), e0.unwrap() + 1,
        "exactly one epoch event: the mid-flight activation (the backdate itself bumps nothing)");
    assert_eq!(spend_status(&pic, &s, 10), None, "the pre-mutation record must be removed");
    assert!(!active_spend_ids(&pic, &s).contains(&10), "the recovery locator must be removed");

    // Same-spend_id retry under the new pin: NOT DuplicateSpendId — it runs
    // fresh and finalizes (stub verifier accepts; nullifier never reserved).
    // LAUNCH-HARDEN-04 O-5: the verifier must report the NEW VK to be re-attested.
    stub_reports(&pic, &s, NEW_VK);
    let retry = run_spend_args(&pic, &s, spend_args_vk(root, 10, nf(0x31), (0x32, 0x33), 1, NEW_VK));
    assert_eq!(retry, Ok(()), "same-spend_id retry must succeed under the new epoch; got {:?}", retry);
    assert_eq!(spend_status(&pic, &s, 10), Some(SpendStatus::Finalized));
}

// =============================================================================
// (a″) CUTOFF-CROSSING with NO request B (the tenth-pass Critical) — A is
// admitted under the OLD pin (activation still in the future), captures the
// OLD epoch, and suspends in the REAL verifier await. The stub's one-shot
// nested action calls ONLY the testing-only clock-boundary injection (the
// scheduled activation becomes "due now" — the returned before/after probe
// proves the pin and epoch are STILL OLD immediately after backdating) and
// replies; NO activation-triggering pool request occurs. A resumes → its own
// real C2a segment calls maybe_activate_pending_vk() FIRST, the overdue
// activation applies, the epoch increments, and A aborts with
// SecurityEpochChanged BEFORE the nullifier reservation — it never finalizes
// under the retired VK past its due time.
//
// SOURCE NOTE (R4 clarification): OLD_VK_CUTOFF_AT is set by
// schedule_vk_activation and persisted, but is NEVER consulted by the
// verification logic — there is no dual-key grace window. The canonical
// semantics are an immediate fail-closed hard-swap at activation_timestamp;
// the brief's "old-key cutoff" phrasing names the scheduled value only. The
// normative boundary this test exercises is the activation timestamp.
//
// RED: with C2a's activation-first step removed, nothing applies the overdue
// activation — the epoch compare passes and A FINALIZES under the retired VK
// (demonstrated during the lane by re-running this test against a build with
// the maybe_activate_pending_vk() call removed from commit_private_spend).
// =============================================================================
#[test]
fn pvk_a_double_prime_cutoff_crossing_without_traffic_aborts() {
    let pic = PocketIc::new();
    // ELEVATED fixture on the TEST Wasm: the backdate endpoint is
    // controller-gated (the stub must be the pool's controller) and
    // #[cfg(feature = "testing")].
    let s = deploy_elevated_controller_stub_stack_with(&pic, pool_test_wasm());
    let root = fund_and_anchor(&pic, &s);

    let activation = now_ns(&pic) + 60 * 1_000_000_000;
    schedule_activation(&pic, &s, 1, NEW_VK, activation, activation + 7 * DAY_NS);
    let e0 = epoch(&pic, &s);

    configure_stub(&pic, s.verifier, NestedAction::BackdateOnly { pool: s.pool });

    let a = run_spend_args(&pic, &s, spend_args(root, 20, nf(0x51), (0x52, 0x53)));
    // RED marker: without C2a's activation-first step this is Ok(()).
    assert_eq!(a, Err(PoolError::SecurityEpochChanged),
        "C2a must force the overdue activation and abort A before the reservation; got {:?}", a);

    assert_eq!(pinned_vk(&pic, &s), NEW_VK,
        "the C2a boundary call applied the overdue activation (step 1 of the segment)");
    assert_eq!(epoch(&pic, &s).unwrap(), e0.unwrap() + 1,
        "the forced activation bumped the epoch — and NOTHING else did (the backdate bumps nothing)");
    assert_eq!(spend_status(&pic, &s, 20), None, "the pre-mutation record must be removed");
    assert!(!active_spend_ids(&pic, &s).contains(&20), "the recovery locator must be removed");

    // Retry under the newly active pin does NOT hit DuplicateSpendId.
    // LAUNCH-HARDEN-04 O-5: the verifier must report the NEW VK to be re-attested.
    stub_reports(&pic, &s, NEW_VK);
    let retry = run_spend_args(&pic, &s, spend_args_vk(root, 20, nf(0x51), (0x52, 0x53), 1, NEW_VK));
    assert_eq!(retry, Ok(()), "same-spend_id retry must succeed; got {:?}", retry);
    assert_eq!(spend_status(&pic, &s, 20), Some(SpendStatus::Finalized));
}

// =============================================================================
// (b) pause→unpause ABA (ELEVATED fixture) — during A's REAL verifier await the
// stub performs an authorized pause then unpause. The pause flag returns to an
// IDENTICAL value (structural equality would miss it), but the epoch
// incremented twice and A's stale capture is detected.
// =============================================================================
#[test]
fn pvk_b_pause_unpause_aba_detected() {
    let pic = PocketIc::new();
    let s = deploy_elevated_controller_stub_stack(&pic);
    let root = fund_and_anchor(&pic, &s);

    configure_stub(&pic, s.verifier, NestedAction::PauseThenUnpause { pool: s.pool });
    let e0 = epoch(&pic, &s);

    let a = run_spend_args(&pic, &s, spend_args(root, 30, nf(0x61), (0x62, 0x63)));
    assert_eq!(a, Err(PoolError::SecurityEpochChanged),
        "the ABA change must be detected despite the identical structure; got {:?}", a);
    assert!(!is_spends_paused(&pic, &s), "ABA: the pause flag is back to its original value");
    assert_eq!(epoch(&pic, &s).unwrap(), e0.unwrap() + 2, "pause AND unpause are each epoch events");
    assert_eq!(spend_status(&pic, &s, 30), None, "the pre-mutation record must be removed");
    assert!(!active_spend_ids(&pic, &s).contains(&30), "the recovery locator must be removed");

    // Spends are unpaused now: the retry runs under the new epoch and succeeds.
    let retry = run_spend_args(&pic, &s, spend_args(root, 30, nf(0x61), (0x62, 0x63)));
    assert_eq!(retry, Ok(()), "retry after pause→unpause must succeed; got {:?}", retry);
}

// =============================================================================
// (c) verifier A→B→A ABA (ELEVATED fixture) — during A's REAL verifier await,
// two successful attested replacements (stub→other→stub). The authoritative
// verifier returns to A (identical structure) but the epoch incremented on
// each transition and A's stale capture is detected.
// =============================================================================
#[test]
fn pvk_c_verifier_replacement_aba_detected() {
    let pic = PocketIc::new();
    let s = deploy_elevated_controller_stub_stack(&pic);
    let root = fund_and_anchor(&pic, &s);

    let other = create_canister(&pic);
    pic.install_canister(
        other,
        stub_verifier_wasm(),
        candid::encode_one(None::<[u8; 32]>).unwrap(),
        None,
    );

    configure_stub(&pic, s.verifier, NestedAction::VerifierRoundTrip { pool: s.pool, other });
    let e0 = epoch(&pic, &s);

    let a = run_spend_args(&pic, &s, spend_args(root, 40, nf(0x71), (0x72, 0x73)));
    assert_eq!(a, Err(PoolError::SecurityEpochChanged),
        "the A→B→A replacement round trip must be detected; got {:?}", a);
    assert_eq!(verifier_of(&pic, &s), Some(s.verifier),
        "ABA: verifier principal is back to the original (both replacements succeeded)");
    assert_eq!(epoch(&pic, &s).unwrap(), e0.unwrap() + 2, "each successful replacement is an epoch event");
    assert_eq!(spend_status(&pic, &s, 40), None);
    assert!(!active_spend_ids(&pic, &s).contains(&40));

    let retry = run_spend_args(&pic, &s, spend_args(root, 40, nf(0x71), (0x72, 0x73)));
    assert_eq!(retry, Ok(()), "retry under the new epoch must succeed; got {:?}", retry);
}

// =============================================================================
// (kill-switch regression) emergency_disable_circuit_version IS a ruled epoch
// event — during A's REAL verifier await (ELEVATED fixture) the stub invokes
// the kill switch: exactly ONE epoch increment, spends paused, and the
// in-flight spend rejects with SecurityEpochChanged BEFORE the nullifier
// reservation (record + locator removed).
// =============================================================================
#[test]
fn pvk_emergency_disable_circuit_version_is_epoch_event() {
    let pic = PocketIc::new();
    let s = deploy_elevated_controller_stub_stack(&pic);
    let root = fund_and_anchor(&pic, &s);

    configure_stub(&pic, s.verifier, NestedAction::DisableCircuitVersion { pool: s.pool, version: 0 });
    let e0 = epoch(&pic, &s);

    let a = run_spend_args(&pic, &s, spend_args(root, 80, nf(0xB1), (0xB2, 0xB3)));
    assert_eq!(a, Err(PoolError::SecurityEpochChanged),
        "the kill switch mid-flight must abort the spend before reservation; got {:?}", a);
    assert_eq!(epoch(&pic, &s).unwrap(), e0.unwrap() + 1,
        "emergency_disable_circuit_version increments the epoch exactly once");
    assert!(is_spends_paused(&pic, &s), "the kill switch pauses spends");
    assert_eq!(spend_status(&pic, &s, 80), None, "the pre-mutation record must be removed");
    assert!(!active_spend_ids(&pic, &s).contains(&80), "the recovery locator must be removed");
    // SecurityEpochChanged is only producible before 15a — the reservation
    // never began (spends are paused now, so no retry in this test).
}

// =============================================================================
// Upgrade lifecycle — a REAL pre-P-VK (71491f8) → P-VK upgrade: the new
// MemoryId-16 cell must initialize safely (epoch 0, not garbage), existing
// security state (pinned VK, pending activation, verifier wiring) must
// survive, a pending activation scheduled on the BASE build must still apply
// post-upgrade, and subsequent epoch changes must persist across ANOTHER
// upgrade (P-VK → P-VK).
// =============================================================================
#[test]
fn pvk_base_71491f8_upgrade_is_refused_because_the_boundary_is_a_reinstall() {
    // ── RE-PINNED (RB-SWARM-A1 sentinel fix, Fix A, RULED 2026-08-01) ─────────
    //
    // This test used to drive a full base -> P-VK epoch lifecycle THROUGH an
    // in-place upgrade. That upgrade is now refused, by ruling: the 71491f8
    // build predates the fee-governance eager cell (MemoryId 18), so the region
    // reads as the impossible sentinel on arrival, and the sentinel traps
    // unconditionally. The migration-on-inference arm that used to carry such a
    // pool across is gone — SSA showed the inference is forgeable by a
    // corrupted current checkpoint (Candid record-width subtyping), and on that
    // ambiguity it substituted fee-free defaults for real governance params.
    //
    // COVERAGE NOTE, stated plainly rather than quietly dropped: the post-
    // boundary lifecycle assertions this test used to make (pending activation
    // applies, epoch increments, second-upgrade persistence) are NOT re-created
    // here — they are unreachable across a boundary that no longer opens. They
    // remain covered on the current build by `pvk_security_epoch_survives_
    // upgrade` and the (a)-(d) fixtures. What this test now pins is the
    // boundary itself: refused, and refused CLEANLY.
    let pic = PocketIc::new();
    let s = deploy_stack_with(&pic, pool_base_71491f8_wasm(), p(0xC0), None);
    let root = fund_and_anchor(&pic, &s);

    // Real pre-upgrade security state on the BASE build, so the rejection is
    // exercised against a populated pool rather than an empty one.
    let activation = now_ns(&pic) + 60 * 1_000_000_000;
    schedule_activation(&pic, &s, 1, NEW_VK, activation, activation + 7 * DAY_NS);
    assert_eq!(pinned_vk(&pic, &s), [0u8; 32]);

    // Same install-rate-limit handling as `upgrade_to_prod` (harness budget).
    pic.advance_time(Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    let r = pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(
        r.is_err(),
        "the pre-A1 boundary must be REFUSED — recovery is reinstall (init), not an \
         in-place upgrade; got {:?}",
        r
    );

    // TRAP-NO-STAMP: rolled back to the BASE Wasm, still running, state intact.
    assert_eq!(
        pinned_vk(&pic, &s),
        [0u8; 32],
        "the refused upgrade must not have mutated the pinned VK"
    );
    assert_eq!(
        verifier_of(&pic, &s),
        Some(s.verifier),
        "the refused upgrade must not have mutated the verifier wiring"
    );

    // And the pool still SPENDS on the previous build — the operator has lost
    // nothing by attempting the boundary, which is the whole point of failing
    // closed at post_upgrade rather than half-migrating.
    // The pool is still the BASE Wasm here (the upgrade was refused and rolled
    // back), so this call speaks the base build's argument shape — see
    // `LegacyPrivateSpendArgs`.
    let a = run_legacy_spend_args(&pic, &s, legacy_spend_args(root, 90, nf(0xC1), (0xC2, 0xC3)));
    assert_eq!(a, Ok(()), "the base build must keep working after the refusal; got {:?}", a);
}

// =============================================================================
// (d) mid-verifier UPGRADE — established injection + real upgrade_canister
// pattern (P-VK harness ruling §4): inject a VerificationPending record AND its
// recovery locator, prove both exist, upgrade with the call class genuinely
// pre-mutation, then prove post_upgrade removed BOTH and a same-spend_id retry
// passes the idempotency boundary and succeeds.
// =============================================================================
#[test]
fn pvk_d_mid_verifier_upgrade_drops_callback_and_frees_spend_id() {
    let pic = PocketIc::new();
    // TEST wasm for the inject hooks; the upgrade target is the PRODUCTION wasm.
    let s = deploy_stack_with(&pic, pool_test_wasm(), p(0xC0), None);
    let root = fund_and_anchor(&pic, &s);

    // Inject the exact pre-mutation state private_spend step 12 produces:
    // VerificationPending record (submitter = controller caller) + locator.
    let _: () = decode(
        "inject_spend_with_nullifiers_for_test",
        pic.update_call(s.pool, s.controller, "inject_spend_with_nullifiers_for_test",
            candid::encode_args((50u64, vec![nf(0x81)], SpendStatus::VerificationPending)).unwrap()),
    );
    let _: () = decode(
        "inject_active_spend_locator_for_test",
        pic.update_call(s.pool, s.controller, "inject_active_spend_locator_for_test",
            candid::encode_args((s.controller, 50u64)).unwrap()),
    );
    // Prove BOTH exist before the upgrade.
    assert_eq!(spend_status(&pic, &s, 50), Some(SpendStatus::VerificationPending),
        "injected record must exist pre-upgrade");
    assert!(active_spend_ids_as(&pic, &s, s.controller).contains(&50),
        "injected recovery locator must exist pre-upgrade");

    upgrade_to_prod(&pic, &s);

    // The production post_upgrade removes the pre-mutation record AND locator.
    assert_eq!(spend_status(&pic, &s, 50), None,
        "post_upgrade must remove the VerificationPending record");
    assert!(!active_spend_ids_as(&pic, &s, s.controller).contains(&50),
        "post_upgrade must remove the recovery locator");

    // A same-spend_id retry passes the idempotency boundary and succeeds.
    let retry = run_spend_args_as(&pic, &s, s.controller, spend_args(root, 50, nf(0x81), (0x82, 0x83)));
    assert_eq!(retry, Ok(()), "same-spend_id retry after the upgrade must succeed; got {:?}", retry);
    assert_eq!(spend_status(&pic, &s, 50), Some(SpendStatus::Finalized));
}

// =============================================================================
// Fee/params changes are NOT epoch events (ELEVATED fixture) — a mid-flight
// governance fee change during A's REAL verifier await must not move the
// epoch and must not abort the spend: the existing entry-snapshot fee
// semantics govern the in-flight spend.
// =============================================================================
#[test]
fn pvk_fee_params_change_midflight_does_not_abort() {
    let pic = PocketIc::new();
    // RB-SWARM-A1: the `_test` Wasm, because the stub's mid-flight mutation now
    // goes through the test-only unguarded setter (see the stub's MutateFeeParams
    // arm). The epoch semantics under test are identical on both modules.
    let s = deploy_elevated_controller_stub_stack_with(&pic, pool_test_wasm());
    let root = fund_and_anchor(&pic, &s);

    configure_stub(&pic, s.verifier, NestedAction::MutateFeeParams { pool: s.pool });
    let e0 = epoch(&pic, &s);

    let a = run_spend_args(&pic, &s, spend_args(root, 60, nf(0x91), (0x92, 0x93)));
    assert_eq!(a, Ok(()), "a mid-flight fee/params change must not abort the spend; got {:?}", a);
    assert_eq!(epoch(&pic, &s), e0, "fee/params changes must NOT move the security epoch");
    assert_eq!(spend_status(&pic, &s, 60), Some(SpendStatus::Finalized));
}

// =============================================================================
// Upgrade preservation — the durable SECURITY_EPOCH cell survives an upgrade
// untouched (stable cell outside PoolStableState, same pattern as P-ROOT's).
// =============================================================================
#[test]
fn pvk_security_epoch_survives_upgrade() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Two epoch events (pause + unpause) on top of whatever setup already did.
    let _: Result<(), String> = decode(
        "emergency_pause_spends",
        pic.update_call(s.pool, s.controller, "emergency_pause_spends", candid::encode_args(()).unwrap()),
    );
    let _: () = decode(
        "unpause_spends",
        pic.update_call(s.pool, s.controller, "unpause_spends", candid::encode_args(()).unwrap()),
    );
    let e = epoch(&pic, &s);

    upgrade_to_prod(&pic, &s);

    assert_eq!(epoch(&pic, &s), e, "SECURITY_EPOCH must survive the upgrade unchanged");
}
