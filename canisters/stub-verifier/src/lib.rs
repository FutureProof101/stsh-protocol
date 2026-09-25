// Test-only stub verifier. Exports verify_spend_canister matching the interface the
// shielded-pool calls (always returns Ok(()) without any cryptographic check), PLUS a
// CONFIGURABLE vk_hash() so the pool's set-time VK attestation (DEF-003/#155) can be
// exercised in integration tests against an arbitrary pinned hash.
//
// NEVER deploy to production. publish = false in Cargo.toml; absent from dfx.json and
// every production deployment surface.
//
// AR1-14 — WHY "absent from dfx.json" is not by itself a control. This crate is a
// workspace member (`Cargo.toml`), so a release build of the workspace drops
// `stub_verifier.wasm` beside the real canister Wasms, with nothing at the deploy step
// distinguishing them by name. Installed as the verifier, it would PASS the pool's only
// automated set-time check: `set_verifier_canister` compares the verifier's self-reported
// `vk_hash()` against `PINNED_VK_HASH`, and this stub's `vk_hash()` is configurable, so it
// can report whatever is pinned while verifying nothing. That is the concrete instance of
// the TCB boundary the pool already documents at its `set_verifier_canister` (DEF-078):
// a self-reported hash is a deployment cross-reference, not a runtime guarantee.
//
// The required backstop is the BEHAVIOURAL post-deploy check in MAINNET_DEPLOYMENT.md
// ("tampered proof/public-signal rejects"), which this stub fails by construction. Other
// surfaces reduce the chance of getting here at all — absence from dfx.json, distinct
// artifact naming, the recorded Wasm hash and controller-parity rows — and this comment
// does not claim the behavioural check is the only conceivable detection. What it is, is
// the only one that catches a verifier which reports the EXPECTED hash and verifies
// nothing, which is exactly what this crate would do. Run it.
//
// NOT done here, and deliberately (AR1-14 is a LOW record row, not a build-system lane):
// removing this crate from the workspace, gating it out of release builds, or adding an
// automated deploy-set check that rejects an unexpected Wasm. Each is defensible; each is
// a build-system change and needs its own lane.
//
// P-VK (POOL-04) harness expansion — TEST SCAFFOLDING ONLY. Adds a configurable
// ONE-SHOT "nested action" the stub performs inside verify_spend_canister (i.e. while
// a real private_spend is genuinely suspended at its verifier await): controller-
// authorized pause/unpause, verifier replacement, and fee-params mutations, plus the
// clock-boundary injection (backdate a scheduled VK activation to "due now") that
// substitutes only the passage of time PocketIC cannot perform. The default behavior
// for every caller that does not configure an action is unchanged (immediate Ok(())).
// The init signature is unchanged.
//
// Safety properties (lane ruling §2):
//   - The configured action is consumed ATOMICALLY (take) before any nested call, so a
//     nested call path that re-entered this stub would find no action and reply with
//     the default Ok(()) — no recursive verifier callbacks are possible.
//   - Every nested call is awaited and its result asserted; an unexpected nested
//     outcome traps the stub (the parked spend then fails loudly with
//     VerifierUnavailable instead of silently testing nothing).
//   - Configuration is heap-only and per-canister; each test installs/configures its
//     own instance, so no state can leak between tests.
//
// NOTE: the optional init arg is `Option<[u8; 32]>` (a raw 32-byte hash) rather than a
// named `StubVerifierInit` record. A `#[derive(Deserialize)]` record would require
// serde as a direct dependency of this crate, i.e. a Cargo.toml change — which is
// outside that lane's allowed file set. `Option<[u8; 32]>` uses candid's built-in
// impls (no derive), is functionally identical (a single configurable hash), and keeps
// the change to src/lib.rs + the .did only.

use candid::{CandidType, Principal};
use ic_cdk::api::call::call;
use ic_cdk_macros::{init, query, update};
use serde::Deserialize;
use std::cell::RefCell;

thread_local! {
    // The VK hash this stub reports from vk_hash(). Defaults to all-zeros; configured via
    // the optional init arg. Heap-only (RefCell) — the stub is a test fixture and needs no
    // upgrade persistence, so no StableCell / MemoryId / stable memory is used.
    static CONFIGURED_VK_HASH: RefCell<[u8; 32]> = RefCell::new([0u8; 32]);

    // P-VK: the configured ONE-SHOT nested action. `take()`n (atomically cleared)
    // at the top of verify_spend_canister, before any nested call is made.
    static NESTED_ACTION: RefCell<Option<NestedAction>> = RefCell::new(None);
}

// ── P-VK nested-action surface (test scaffolding) ────────────────────────────

/// The one-shot action performed inside verify_spend_canister, while the
/// calling private_spend is suspended at its verifier await.
#[derive(CandidType, Deserialize, Clone, Debug)]
enum NestedAction {
    /// (b) ELEVATED-fixture only (the stub's principal is the pool's
    /// controller): pause spends, then unpause — an ABA pair the epoch must
    /// still detect.
    PauseThenUnpause { pool: Principal },
    /// (c) ELEVATED-fixture only: replace the pool's verifier with `other`,
    /// then back to this stub — two successful attested replacements (A→B→A).
    VerifierRoundTrip { pool: Principal, other: Principal },
    /// Fee/params: read the governance fee params, change a harmless field,
    /// set them back — must NOT be a security-epoch event.
    MutateFeeParams { pool: Principal },
    /// (a″) ELEVATED-fixture only: call the pool's testing-only
    /// backdate_pending_vk_activation_for_test (makes the scheduled VK
    /// activation "due now" WITHOUT activating it, changing any pin, or
    /// bumping the epoch), assert the returned before/after probe is
    /// unchanged, then reply. NO activation-triggering pool request is made —
    /// the parked spend's own C2a segment must force the overdue activation
    /// when it resumes.
    BackdateOnly { pool: Principal },
    /// (a′) ELEVATED-fixture only: backdate (as BackdateOnly, with the same
    /// unchanged-probe assertion), then fire a nested private_spend whose
    /// envelope carries a deliberately WRONG circuit version: the pool's C1a
    /// activate-before-read applies the now-overdue activation FIRST (a real
    /// security-epoch event, during the parked spend's verifier await), then
    /// rejects the nested call with CircuitVersionMismatch carrying the NEW
    /// version as `expected` — asserted against expected_new_version below.
    BackdateAndTriggerActivation { pool: Principal, spend_id: u64, expected_new_version: u32 },
    /// (kill-switch regression) ELEVATED-fixture only:
    /// emergency_disable_circuit_version — the circuit kill switch pauses
    /// spends and is a ruled security-epoch event (exactly one increment).
    DisableCircuitVersion { pool: Principal, version: u32 },
}

// ── Candid mirrors for the nested calls ──────────────────────────────────────
//
// PoolErrorMirror is a decode-compatible SUPERSET of the pool's PoolError
// (same mechanism as the treasury mirror, proven by
// test_treasury_poolerror_mirror_covers_pool_did). Unexpected variants decode
// fine and are then rejected by the explicit match below — an unexpected pool
// reply can never be mistaken for the expected one.

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
enum PoolErrorMirror {
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

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
enum SpendFeeModeMirror {
    FixedStsh,
    XdrPegged,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct GovernanceFeeParamsMirror {
    protocol_shielding_fee_stsh: u128,
    protocol_unshielding_fee_stsh: u128,
    protocol_private_spend_fee_stsh: u128,
    minimum_withdrawal_gross: u128,
    minimum_recipient_amount: u128,
    minimum_private_credit: u128,
    fee_reference_price_stsh_per_icp_e8s: u128,
    fee_safety_margin_bps: u32,
    max_fee_change_bps_per_update: u32,
    fee_update_cooldown_ns: u64,
    operations_split_bps: u32,
    insurance_split_bps: u32,
    staking_rewards_split_bps: u32,
    staking_rewards_enabled: bool,
    minimum_treasury_runway_months: u32,
    target_treasury_runway_months: u32,
    shield_fee_bps: Option<u16>,
    unshield_fee_bps: Option<u16>,
    shield_flat_minimum_fee_e8s: Option<u128>,
    unshield_flat_minimum_fee_e8s: Option<u128>,
    spend_fee_mode: Option<SpendFeeModeMirror>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct ProofEnvelopeMirror {
    circuit_version: u32,
    proof_system_id: String,
    verifying_key_hash: [u8; 32],
    root_reference: [u8; 32],
    pool_version: u32,
    proof_bytes: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct PrivateSpendArgsMirror {
    spend_id: u64,
    envelope: ProofEnvelopeMirror,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PrivateSpendPublicPayoutMirror>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct PrivateSpendPublicPayoutMirror {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct BackdateProbeMirror {
    pinned_vk_hash: [u8; 32],
    security_epoch: u64,
}

/// Configure (or clear, with None) the one-shot nested action. Heap-only, so a
/// fresh install/upgrade starts with no action — configuration cannot leak
/// between tests or across an upgrade.
#[update]
fn configure_nested_action(action: Option<NestedAction>) {
    NESTED_ACTION.with(|a| *a.borrow_mut() = action);
}

/// Init handler. Installing with no init arg (or `None`) leaves the reported hash at
/// `[0u8; 32]`; `Some(hash)` configures it. Optional so existing test installs that pass
/// no init arg remain compatible (proven by the Phase 2-A compatibility test).
#[init]
fn init(vk_hash: Option<[u8; 32]>) {
    if let Some(h) = vk_hash {
        CONFIGURED_VK_HASH.with(|c| *c.borrow_mut() = h);
    }
}

#[update]
async fn verify_spend_canister(
    _proof_bytes: Vec<u8>,
    _signals: Vec<Vec<u8>>,
) -> Result<(), String> {
    // ONE-SHOT: consume the configured action atomically BEFORE any nested
    // call — a nested path that re-entered this stub finds None and gets the
    // default Ok(()), so recursive verifier callbacks are impossible.
    let action = NESTED_ACTION.with(|a| a.borrow_mut().take());
    match action {
        None => Ok(()),
        Some(action) => run_nested_action(action).await,
    }
}

async fn run_nested_action(action: NestedAction) -> Result<(), String> {
    match action {
        NestedAction::PauseThenUnpause { pool } => {
            let r1: Result<(Result<(), String>,), _> =
                call(pool, "emergency_pause_spends", ()).await;
            match r1 {
                Ok((Ok(()),)) => {}
                other => ic_cdk::trap(&format!(
                    "stub nested pause failed: {:?}",
                    other.map(|_| ())
                )),
            }
            let r2: Result<((),), _> = call(pool, "unpause_spends", ()).await;
            match r2 {
                Ok(((),)) => Ok(()),
                other => ic_cdk::trap(&format!(
                    "stub nested unpause failed: {:?}",
                    other.map(|_| ())
                )),
            }
        }
        NestedAction::VerifierRoundTrip { pool, other } => {
            let expected = CONFIGURED_VK_HASH.with(|h| h.borrow().to_vec());
            let r1: Result<(Result<(), PoolErrorMirror>,), _> =
                call(pool, "set_verifier_canister", (other, expected.clone())).await;
            match r1 {
                Ok((Ok(()),)) => {}
                other => ic_cdk::trap(&format!(
                    "stub nested set_verifier_canister(other) failed: {:?}",
                    other.map(|_| ())
                )),
            }
            let self_id = ic_cdk::id();
            let r2: Result<(Result<(), PoolErrorMirror>,), _> =
                call(pool, "set_verifier_canister", (self_id, expected)).await;
            match r2 {
                Ok((Ok(()),)) => Ok(()),
                other => ic_cdk::trap(&format!(
                    "stub nested set_verifier_canister(self) failed: {:?}",
                    other.map(|_| ())
                )),
            }
        }
        NestedAction::MutateFeeParams { pool } => {
            let r1: Result<(GovernanceFeeParamsMirror,), _> =
                call(pool, "get_governance_fee_params", ()).await;
            let mut params = match r1 {
                Ok((p,)) => p,
                other => ic_cdk::trap(&format!(
                    "stub nested get_governance_fee_params failed: {:?}",
                    other.map(|_| ())
                )),
            };
            params.minimum_recipient_amount += 1; // arbitrary, split-neutral change
            // RB-SWARM-A1: the guarded `set_governance_fee_params` now enforces
            // the ruled floors, so a tweak built from the pool's fee-free launch
            // defaults is (correctly) refused. The subject here is re-entrancy
            // during a verifier await, not fee policy, so the stub drives the
            // test-only unguarded setter — the pool under test is the `_test`
            // Wasm for exactly this reason.
            let r2: Result<(Result<(), String>,), _> =
                call(pool, "set_governance_fee_params_unchecked_for_test", (params,)).await;
            match r2 {
                Ok((Ok(()),)) => Ok(()),
                other => ic_cdk::trap(&format!(
                    "stub nested set_governance_fee_params_unchecked_for_test failed: {:?}",
                    other.map(|_| ())
                )),
            }
        }
        NestedAction::BackdateOnly { pool } => {
            backdate_and_assert_unchanged(pool).await;
            Ok(())
        }
        NestedAction::DisableCircuitVersion { pool, version } => {
            let r: Result<(Result<(), String>,), _> =
                call(pool, "emergency_disable_circuit_version", (version,)).await;
            match r {
                Ok((Ok(()),)) => Ok(()),
                other => ic_cdk::trap(&format!(
                    "stub nested emergency_disable_circuit_version failed: {:?}",
                    other.map(|_| ())
                )),
            }
        }
        NestedAction::BackdateAndTriggerActivation { pool, spend_id, expected_new_version } => {
            backdate_and_assert_unchanged(pool).await;
            // Well-formed args, deliberately WRONG circuit version: the pool's
            // C1a activates the now-overdue pending VK FIRST, then rejects
            // with CircuitVersionMismatch carrying the NEW version as
            // `expected` — the proof that activation really happened.
            let args = PrivateSpendArgsMirror {
                spend_id,
                envelope: ProofEnvelopeMirror {
                    circuit_version: u32::MAX,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: [0u8; 32],
                    root_reference: [0u8; 32],
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![[0xEE; 32]],
                output_commitments: vec![[0xE1; 32], [0xE2; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            };
            let res: Result<(Result<(), PoolErrorMirror>,), _> =
                call(pool, "private_spend", (args,)).await;
            match res {
                Ok((Err(PoolErrorMirror::CircuitVersionMismatch { expected, .. }),))
                    if expected == expected_new_version =>
                {
                    Ok(())
                }
                other => ic_cdk::trap(&format!(
                    "stub nested BackdateAndTriggerActivation: expected CircuitVersionMismatch \
                     carrying the NEW version {}, got {:?}",
                    expected_new_version,
                    other.map(|_| ())
                )),
            }
        }
    }
}

/// Call the pool's testing-only clock-boundary injection and assert the
/// returned before/after probe is UNCHANGED — the backdate must not activate
/// the VK, change the pin, or bump the epoch. Traps (loud test failure)
/// otherwise.
async fn backdate_and_assert_unchanged(pool: Principal) {
    let res: Result<(BackdateProbeMirror, BackdateProbeMirror), _> =
        call(pool, "backdate_pending_vk_activation_for_test", ()).await;
    match res {
        Ok((before, after)) => {
            if before.pinned_vk_hash != after.pinned_vk_hash
                || before.security_epoch != after.security_epoch
            {
                ic_cdk::trap(&format!(
                    "stub backdate: probe changed across the backdate (before {:?}, after {:?}) — \
                     the injection must substitute only the passage of time",
                    before, after
                ));
            }
        }
        other => ic_cdk::trap(&format!(
            "stub backdate call failed: {:?}",
            other.map(|_| ())
        )),
    }
}

/// Reports the configured VK hash. Uses the SAME annotation (`#[query]`) and return type
/// (`Vec<u8>`) as the production verifier's `vk_hash()` (canisters/verifier/src/lib.rs), so
/// the pool's inter-canister attestation call behaves identically against the stub.
#[query]
fn vk_hash() -> Vec<u8> {
    CONFIGURED_VK_HASH.with(|h| h.borrow().to_vec())
}
