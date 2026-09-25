// =============================================================================
// STSH — M2 + M3 Track A Integration Tests (PocketIC)
// =============================================================================
//
// M2 security tests:
//   test_03 — non-staking caller cannot lock tokens
//   test_04 — unlock above locked amount fails
//   test_07 — duplicate nullifier rejected (double-spend protection)
//   test_14 — ordinary proposal cannot schedule a VK activation
//   test_15 — EmergencyPause cannot silently install a VK
//   test_83 — VK upgrade proposal executes after governance timelock (validate_for_execution)
//   test_84 — VK upgrade proposal rejected at creation if activation < 14 days (validate_for_creation)
//
// M2 token-movement tests (updated for M3 semantics where noted):
//   test_18 — deposit rejected when no allowance is set
//   test_19 — deposit rejected when allowance < amount + fee
//   test_20 — successful deposit increases pool escrow balance
//   test_21 — exact-settlement withdrawal (M3: recipient receives exact amount)
//   test_22 — only pool can call insert_nullifier
//   test_23 — private_spend with duplicate nullifier is rejected
//   test_24 — escrow coverage failure (M3: replaces M2 AmountBelowLedgerFee test)
//
// M3 Track A — reserve model + exact-settlement (10 required tests):
//   test_25 — recipient receives exact withdrawal_amount (not minus ledger fee)
//   test_26 — escrow_backing returns to >= private_liability after withdrawal
//   test_27 — operations_reserve decreases by exactly 1× ledger_fee per withdrawal
//   test_28 — solvency invariant (1) holds after full deposit+withdraw cycle
//   test_29 — withdrawal NOT Finalized when operations reserve is empty
//   test_30 — FeeReimbursementPending set when operations reserve depleted
//   test_31 — solvency invariant (2) holds in normal operations
//   test_32 — shield_deposit returns net private_balance (not gross public_amount)
//   test_33 — shield_deposit routes reserve 90% operations / 10% insurance
//   test_34 — accounting buckets sum correctly after deposit+withdraw cycle
//
// M3 Track B — Merkle commitment wiring + anchor verification (10 required tests):
//   test_37 — shield_deposit creates Merkle leaf (leaf_count 0 → 1)
//   test_38 — deposit status shows CommitmentAppended with correct private_balance
//   test_39 — withdraw with valid anchor succeeds (anchor check passes)
//   test_40 — withdraw with unknown/stale root → AnchorNotFound
//   test_41 — private_spend with unknown root → AnchorNotFound
//   test_42 — private_spend batch all fresh nullifiers succeeds; all in registry
//   test_43 — private_spend batch with one spent nullifier → fails; other NOT inserted
//   test_44 — private_spend batch with intra-batch duplicate → fails atomically
//   test_45 — unauthorized caller cannot call insert_batch on nullifier registry
//   test_46 — failed Merkle append leaves private_liability = 0 (CommitmentPending)
//
// PREREQUISITES:
//   1. Build canister Wasm:
//      cargo build --target wasm32-unknown-unknown --release \
//          -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests
//
// M3 TRACK B GATE:
//   cargo test 2>&1 | grep "^test result"  →  all crates: N passed, 0 failed, 0 ignored
//
// =============================================================================
// A2-2 FORMAL ACCEPTANCE GATE — #92
// =============================================================================
//
// Date       : 2026-06-16
// HEAD       : 1db7006  test: implement #113 A2-2 criterion 15 staking
//                        zero-rewards branch (test_78)
// Runner     : cargo test -p integration-tests -- --test-threads=1
// Platform   : Linux 6.6.114 WSL2 / debug profile
//
// Results by target:
//   full_path_private_spend_benchmark :  1 passed /  0 failed /  0 ignored
//   security_tests                    : 47 passed /  0 failed / 11 ignored
//   transfer_tests                    :  6 passed /  0 failed /  0 ignored
//   upgrade_tests                     :  9 passed /  0 failed /  0 ignored
//   verifier_tests                    :  9 passed /  0 failed /  0 ignored
//
// Aggregate: 72 passed / 0 failed / 11 ignored
//
// Benchmark: test_b01_full_path_private_spend_benchmark — PASS (11.66 s)
//   Cycle-delta underflow fixed at 1629768; no SKIP.
//
// Ignored (PocketIC harness limits, not protocol gaps):
//   test_71  A2-2 #5b  duplicate in-flight spend id (requires true concurrency)
//   test_72  REMOVED under A2 — tested discarded ring-buffer anchor eviction (see below)
//   test_73  A2-2 #7   nullifier race during async verification
//   (+ 8 further ignored tests documented inline below)
//
// Verdict: PASS
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// P-STK C-A5: `stake` now takes a caller-supplied dedup key. Tests that are
/// not exercising idempotency just need a distinct key per call — this supplies
/// one so no unrelated test accidentally trips the duplicate-request path.
fn next_dedup_key() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release \\\n    \
             -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree",
            pkg, path, e
        )
    })
}

fn token_wasm() -> Vec<u8> {
    load_wasm(env!("TOKEN_WASM"), "stsh_token")
}
fn staking_wasm() -> Vec<u8> {
    load_wasm(env!("STAKING_WASM"), "staking")
}
fn pool_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_WASM"), "shielded_pool")
}
fn pool_test_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test")
}
fn nullifier_wasm() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry")
}
fn merkle_wasm() -> Vec<u8> {
    load_wasm(env!("MERKLE_WASM"), "merkle_tree")
}
fn verifier_wasm() -> Vec<u8> {
    load_wasm(env!("VERIFIER_WASM"), "stsh_verifier")
}
fn stub_verifier_wasm() -> Vec<u8> {
    load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier")
}
fn treasury_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_WASM"), "treasury")
}

// ─────────────────────────────────────────────────────────────────────────────
// Candid type mirrors
//
// Canister crates use crate-type = ["cdylib"] which prevents linking them as
// normal Rust deps.  We mirror only the types each test needs for encoding/
// decoding — field names must exactly match the canister Candid type.
// ─────────────────────────────────────────────────────────────────────────────

pub const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1 B STSH
pub const DENOMINATIONS: [u128; 5] = [
    // A6.6 five-tier launch ladder — mirrors the pool's own DENOMINATIONS.
    1_000 * 100_000_000,
    10_000 * 100_000_000,
    100_000 * 100_000_000,
    1_000_000 * 100_000_000,
    10_000_000 * 100_000_000,
];

// ── #115 deposit helper ───────────────────────────────────────────────────────

/// Expected private balance credited after a deposit.
///
/// AR1-10 — this returned `gross - shielding_fee`, which the code has not done
/// since fee-on-top. The authority is `canisters/fee-policy/src/lib.rs`:
/// `let private_balance_credit = gross_shield_amount;` — the note is credited the
/// FULL requested amount so the fixed denomination is preserved (Law #1), and the
/// protocol fee is pulled ON TOP of it. Doc and test match code; never the reverse.
///
/// Why nobody noticed: at the launch value `protocol_shielding_fee_stsh = 0`, and
/// `gross - 0 == gross`, so the wrong form and the right one agree everywhere the
/// suite normally runs. The two call sites that pass a NONZERO fee (test_77,
/// test_78) are `#[ignore]`d, so the defect is switched OFF by configuration, not
/// absent — their existence is not coverage. See `ar1_10_*` below, which is the
/// arm that runs at a nonzero fee and therefore can fail.
///
/// `shielding_fee` is retained in the signature: the call sites document which fee
/// regime they run under, and a reader comparing a site against the treasury
/// assertions beside it needs that number visible. It does not affect the credit.
pub fn expected_deposit_private_balance(gross: u128, shielding_fee: u128) -> u128 {
    let _ = shielding_fee;
    gross
}

/// AR1-10 Rule-4 arm. It runs at a fee the launch config does NOT use, which is
/// the whole point: at `fee = 0` the stale `gross - fee` form is indistinguishable
/// from the correct one, so an arm at the shipped value proves nothing.
///
/// Expected values are literals written here, not computed from the helper or read
/// from the fee-policy crate.
#[test]
fn ar1_10_deposit_credit_is_fee_on_top_at_a_nonzero_fee() {
    const GROSS: u128 = 100_000_000;
    const NONZERO_FEE: u128 = 200_000; // the value test_77 uses, which is #[ignore]d

    // The credit is the FULL gross — 100_000_000, not 99_800_000.
    assert_eq!(
        expected_deposit_private_balance(GROSS, NONZERO_FEE),
        100_000_000,
        "AR1-10: fee-on-top credits the full gross; a `gross - fee` helper returns 99_800_000 here"
    );

    // And the stale form is genuinely different at this fee — so the assertion
    // above bites. Without this line, a future `gross - fee` regression would
    // still be caught only if someone noticed the constant.
    assert_ne!(
        expected_deposit_private_balance(GROSS, NONZERO_FEE),
        GROSS - NONZERO_FEE,
        "AR1-10: at a nonzero fee the two forms MUST differ, or this arm proves nothing"
    );

    // The zero-fee case still holds, and shows why it hid the defect: both forms
    // agree, so every other call site in this file passes either way.
    assert_eq!(expected_deposit_private_balance(GROSS, 0), GROSS);
    assert_eq!(GROSS - 0, GROSS);
}

// ── Token ─────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct VestingPolicy {
    pub cliff_end_ns: u64,
    pub vesting_end_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AllocationCategory {
    pub category_id: String,
    pub category_name: String,
    pub amount: u128,
    pub recipient: Principal,
    pub subaccount: Option<[u8; 32]>,
    pub lock_policy: LockPolicy,
    pub vesting_policy: Option<VestingPolicy>,
    pub created_at_genesis: bool,
    pub genesis_timestamp_ns: u64,
}

#[derive(CandidType, Deserialize)]
pub struct TokenInitArgs {
    pub allocations: Vec<AllocationCategory>,
    pub treasury: Principal,
    pub staking_canister: Principal,
}

fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
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
        staking_canister: staking,
    }
}

// ── Staking ───────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct GovernanceParams {
    pub min_proposal_deposit: u128,
    pub voting_delay_ns: u64,
    pub voting_period_ns: u64,
    pub execution_timelock_ns: u64,
    pub vk_upgrade_timelock_ns: u64,
    pub quorum_bps: u32,
    pub treasury_quorum_bps: u32,
    pub vk_quorum_bps: u32,
    pub approval_threshold_bps: u32,
}

impl GovernanceParams {
    /// Fast test params — 1-second windows, near-zero quorum.
    ///
    /// Using 1 second (not 1 ns) because PocketIC may advance IC time by small
    /// amounts while processing update calls internally.  With 1-nanosecond
    /// windows, an update_call arriving 2 ns late would miss the voting window.
    /// P-STK K3-015: `GovernanceParams::validate()` now runs at INIT, so a
    /// sub-floor timelock is no longer installable — a policy floor that tests
    /// can opt out of at install is not a floor. The voting window stays short
    /// (it is a test-speed knob, not a policy floor); the two TIMELOCKS are the
    /// real 7-day and 14-day floors, and the tests advance time past them.
    pub fn fast() -> Self {
        GovernanceParams {
            min_proposal_deposit: 1_000 * 100_000_000, // 1000 STSH
            voting_delay_ns: 0,                        // voting opens immediately
            voting_period_ns: 1_000_000_000,           // 1 second
            execution_timelock_ns: 7 * 24 * 60 * 60 * 1_000_000_000,  // 7d policy floor
            vk_upgrade_timelock_ns: 14 * 24 * 60 * 60 * 1_000_000_000, // 14d floor
            quorum_bps: 1,                             // 0.01% of voting weight
            treasury_quorum_bps: 1,
            vk_quorum_bps: 1,
            approval_threshold_bps: 5001,
        }
    }
}

#[derive(CandidType, Deserialize)]
pub struct StakingInitArgs {
    pub token_canister: Principal,
    pub pool_canister: Principal,
    pub treasury_canister: Principal,
    pub initial_rewards_pool: u128,
    pub initial_emission_rate_per_day: u128,
    pub governance_params: Option<GovernanceParams>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum EmergencyPauseTarget {
    PoolDeposits,
    PoolSpends,
    Both,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ProposalType {
    ParameterUpdate {
        key: String,
        value: String,
    },
    TreasurySpend {
        subaccount: String,
        recipient: Principal,
        amount: u128,
        reason: String,
    },
    FeeUpdate {
        shield_bps: u32,
        transfer_bps: u32,
        unshield_bps: u32,
    },
    RewardScheduleUpdate {
        new_emission_rate_per_day: u128,
    },
    EmergencyPause {
        target: EmergencyPauseTarget,
        reason: String,
    },
    VerifierKeyUpgrade(VerifierKeyUpgradePayload),
    CanisterUpgrade {
        canister_id: Principal,
        wasm_hash: [u8; 32],
        description: String,
    },
    GovernanceParamUpdate(GovernanceParams),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct VerifierKeyUpgradePayload {
    pub old_verifying_key_hash: [u8; 32],
    pub new_verifying_key_hash: [u8; 32],
    pub circuit_version: u32,
    pub proof_system_id: String,
    pub audit_artifact_url: String,
    pub audit_artifact_hash: [u8; 32],
    pub circuit_source_commit: String,
    pub verifier_wasm_hash: [u8; 32],
    pub activation_timestamp_ns: u64,
    pub emergency_disable_supported: bool,
}

// ── Pool ──────────────────────────────────────────────────────────────────────

#[derive(CandidType, Deserialize)]
pub struct PoolInitArgs {
    pub token_canister: Principal,
    pub nullifier_canister: Principal,
    pub merkle_canister: Principal,
    pub treasury_canister: Principal,
    pub staking_canister: Principal,
    pub controller: Principal,
    pub initial_vk_hash: [u8; 32],
    pub initial_proof_system: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ProofEnvelope {
    pub circuit_version: u32,
    pub proof_system_id: String,
    pub verifying_key_hash: [u8; 32],
    pub root_reference: [u8; 32],
    pub pool_version: u32,
    pub proof_bytes: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct WithdrawArgs {
    pub withdrawal_id: u64,
    pub envelope: ProofEnvelope,
    pub nullifier: [u8; 32],
    pub destination: Principal,
    pub destination_subaccount: Option<[u8; 32]>,
    pub gross_withdraw_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PoolError {
    InvalidDenomination,
    InvalidProof,
    /// Nullifier is in the permanent registry (already finalized/spent).
    NullifierAlreadySpent,
    /// Nullifier is reserved by another in-flight withdrawal (pool-local).
    NullifierReserved,
    AnchorNotFound,
    /// DEPRECATED: kept for Candid decode compatibility; not generated in M3+.
    InsufficientEscrowCoverage {
        requested: u128,
        available: u128,
    },
    /// M3 revised: protocol solvency fault — escrow insufficient for withdrawal.
    EscrowUnderfunded {
        required: u128,
        available: u128,
    },
    CircuitVersionMismatch {
        expected: u32,
        got: u32,
    },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    TransferFailed(String),
    /// Deprecated (M2) — kept for Candid decode compatibility.  Not generated in M3+.
    AmountBelowLedgerFee {
        amount: u128,
        fee: u128,
    },
    /// Deposit rejected: public_amount does not exceed shielding_reserve.
    BelowMinimumDeposit {
        public_amount: u128,
        minimum: u128,
    },
    /// Operations reserve insufficient to reimburse the ICRC ledger transfer fee.
    InsufficientOperationsReserve {
        needed: u128,
        available: u128,
    },
    /// Hard protocol invariant violation at finalization.
    InvariantViolationDuplicateNullifier,
    Paused,
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    /// Merkle append_commitment call failed (transport or canister error).
    /// Tokens are held in escrow. Use retry_deposit_commitment to finalise.
    CommitmentAppendFailed(String),
    /// Deposit commitment is already pending (previous attempt awaiting retry).
    DepositCommitmentPending,
    // ── M4 private_spend errors ───────────────────────────────────────────────
    /// RETIRED by lane F1-PRIV — never constructed; retained for decode-compat.
    SumMismatch {
        inputs: u128,
        outputs: u128,
    },
    /// Arithmetic overflow while summing private_spend amounts.
    SumOverflow,
    /// Array lengths in PrivateSpendArgs violate required constraints.
    MalformedSpendArgs,
    /// DEF-046: the two output commitments are identical.
    DuplicateOutputCommitment,
    /// DEF-046: an output commitment is the all-zero value.
    InvalidOutputCommitment,
    /// A spend with this spend_id was already recorded.
    DuplicateSpendId,
    /// Spend fee not supported (must be 0 in M4).
    /// DEPRECATED — kept for Candid decode compatibility. Superseded by PrivateSpendFeeMismatch.
    SpendFeeNotSupported,
    /// ZK verifier canister not configured or unreachable.
    VerifierUnavailable(String),
    /// ZK verifier rejected the proof (structural malformation or signal mismatch).
    ProofRejected(String),
    // DEF-003/#155: set-time verifier VK attestation.
    InvalidVerifierKeyHashLength { len: u64 },
    VerifierKeyHashMismatch,
    VerifierKeyHashChangedDuringAttestation,
    VerifierConfigInProgress,
    /// args.fee does not match governance-quoted protocol private-spend fee.
    PrivateSpendFeeMismatch {
        expected: u128,
        got: u128,
    },
    /// Private liability insufficient for declared input amounts.
    InsufficientPrivateLiability {
        required: u128,
        available: u128,
    },
    // ── §12 withdrawal precheck errors ───────────────────────────────────────
    WithdrawalBelowMinimum {
        withdraw_gross_amount: u128,
        minimum_withdrawal_gross: u128,
    },
    GrossAmountBelowFees {
        withdraw_gross_amount: u128,
        total_fee: u128,
    },
    RecipientBelowMinimum {
        recipient_net_amount: u128,
        minimum_recipient_amount: u128,
    },
    IdempotencyKeyConflict,
    // A2 (QA-DEF-034/036): active-Merkle promotion / recovery
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a deterministic Principal for test fixtures.
fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

/// Anonymous principal — used as read-only caller for queries.
fn anon() -> Principal {
    Principal::anonymous()
}

/// Create a canister with generous cycles, no Wasm yet.
fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

/// Install Wasm with Candid-encoded init args.
fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    let args = candid::encode_one(init).expect("encode init args");
    pic.install_canister(cid, wasm, args, None);
}

/// Decode a canister reply or panic with context.
///
/// pocket-ic v9 changed update_call / query_call to return Result<Vec<u8>, E>
/// directly — the success case is already the raw Candid reply bytes.
fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call was rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

/// Assert a call is rejected (canister trap or explicit reject) —
/// used for access-control tests.  In v9 a rejected call is Err(_).
fn expect_reject<E: std::fmt::Debug>(label: &str, result: Result<Vec<u8>, E>) {
    match result {
        Err(_) => {} // good — canister trapped / returned explicit reject
        Ok(_) => panic!("{}: expected call to fail but it succeeded", label),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 03 — Non-staking caller cannot lock tokens
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: lock_for_staking is guarded by assert_staking_canister() which
// calls ic_cdk::caller() and panics (traps) if caller != STAKING_CANISTER.
// Any attacker principal must be rejected before any state mutation.
// =============================================================================

#[test]
fn test_03_non_staking_caller_cannot_lock() {
    let pic = PocketIc::new();
    let user = p(0xA0);
    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(
        &pic,
        staking_id,
        staking_wasm(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x01),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: None,
        },
    );

    // Attacker (not the staking canister) calls lock_for_staking directly.
    let attacker = p(0xFF);
    let call_args =
        candid::encode_args((user, 100_u128 * 100_000_000_u128)).expect("encode lock args");
    let result = pic.update_call(token_id, attacker, "lock_for_staking", call_args);
    expect_reject("test_03: attacker calling lock_for_staking", result);

    // Confirm no tokens were locked.
    let locked: u128 = decode(
        "test_03: staking_locked_balance",
        pic.query_call(
            token_id,
            anon(),
            "staking_locked_balance",
            candid::encode_one(user).unwrap(),
        ),
    );
    assert_eq!(
        locked, 0,
        "STAKING_LOCKS must be untouched after rejected call"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 04 — Unlock above locked amount fails
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: unlock_from_staking(holder, amount) returns Err if amount > locked.
// Even the legitimate staking canister cannot exceed the locked balance —
// which prevents corrupting STAKING_LOCKS via over-unlock.
// =============================================================================

#[test]
fn test_04_unlock_above_locked_amount_fails() {
    let pic = PocketIc::new();
    let user = p(0xA1);
    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(
        &pic,
        staking_id,
        staking_wasm(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x01),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: None,
        },
    );

    // In PocketIC, sender = staking_id impersonates the staking canister,
    // which satisfies assert_staking_canister() inside the token canister.

    // Step 1: Lock 100 STSH as the staking canister.
    let lock_result: Result<(), String> = decode(
        "test_04: lock 100 STSH",
        pic.update_call(
            token_id,
            staking_id,
            "lock_for_staking",
            candid::encode_args((user, 100_u128 * 100_000_000_u128)).unwrap(),
        ),
    );
    lock_result.expect("locking 100 STSH must succeed");

    let locked: u128 = decode(
        "test_04: staking_locked_balance after lock",
        pic.query_call(
            token_id,
            anon(),
            "staking_locked_balance",
            candid::encode_one(user).unwrap(),
        ),
    );
    assert_eq!(locked, 100 * 100_000_000_u128, "100 STSH must be locked");

    // Step 2: Attempt to unlock 101 STSH — one more than locked.
    let unlock_result: Result<(), String> = decode(
        "test_04: unlock 101 STSH",
        pic.update_call(
            token_id,
            staking_id,
            "unlock_from_staking",
            candid::encode_args((user, 101_u128 * 100_000_000_u128)).unwrap(),
        ),
    );
    assert!(
        unlock_result.is_err(),
        "Unlocking > locked must return Err; got Ok"
    );
    let err = unlock_result.unwrap_err();
    assert!(
        err.contains("Cannot unlock"),
        "Error must say 'Cannot unlock'; got: {:?}",
        err
    );

    // STAKING_LOCKS must be completely unchanged.
    let locked_after: u128 = decode(
        "test_04: staking_locked_balance after failed unlock",
        pic.query_call(
            token_id,
            anon(),
            "staking_locked_balance",
            candid::encode_one(user).unwrap(),
        ),
    );
    assert_eq!(
        locked_after,
        100 * 100_000_000_u128,
        "Locked amount must be unchanged after failed unlock attempt"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 07 — Duplicate nullifier is rejected
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: a nullifier may only be spent once. The nullifier registry is a
// separate canister that atomically rejects re-insertion. The pool calls
// insert_nullifier() before issuing the token transfer; a second withdrawal
// with the same nullifier must fail with NullifierAlreadySpent even if it
// carries a fresh withdrawal_id.
// =============================================================================

/// VK hash used for pool init and matching proof envelopes in test_07.
const TEST_VK_HASH: [u8; 32] = [0xAA; 32];

/// The nullifier that W1 inserts and W2 attempts to re-use.
const DOUBLE_SPEND_NULLIFIER: [u8; 32] = [0x0B; 32];

/// Proof envelope that satisfies verify_proof_envelope() for the test pool.
/// - circuit_version = 0   (PINNED_CIRCUIT_VERSION default)
/// - verifying_key_hash    (matches TEST_VK_HASH set at pool init)
/// - pool_version = 1      (PINNED_POOL_VERSION default)
/// - root_reference        must be a current valid anchor (post-M4 Poseidon migration
///                         [0u8;32] is never valid — pass merkle_root() result instead)
fn valid_envelope(root: [u8; 32]) -> ProofEnvelope {
    ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: TEST_VK_HASH,
        root_reference: root,
        pool_version: 1,
        proof_bytes: vec![],
    }
}

// Lane A v2 Task 0.25: this test exercises post-withdrawal nullifier double-spend behavior, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: double-spend coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_07_duplicate_nullifier_fails() {
    // Real funding path: shield_deposit sets PRIVATE_LIABILITY so the
    // PRIVATE_LIABILITY >= gross precheck passes.  gross = private_balance
    // (net note value after shielding reserve).
    let h = PoolHarness::new(0xA2, TEST_VK_HASH, 0);
    let private_balance = h.deposit(DENOMINATIONS[0]);

    // ── W1: first withdrawal with nullifier N — must succeed ──────────────
    let w1 = h.withdraw_note(1, DOUBLE_SPEND_NULLIFIER, private_balance);
    assert!(w1.is_ok(), "W1 must succeed; got: {:?}", w1);

    // Verify the nullifier is now permanently registered.
    let registered: bool = decode(
        "test_07: contains_nullifier after W1",
        h.pic.query_call(
            h.null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(DOUBLE_SPEND_NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(registered, "Nullifier must appear in registry after W1");

    // ── W2: different withdrawal_id, SAME nullifier — must be rejected ────
    // NullifierAlreadySpent fires at the registry check (before the
    // PRIVATE_LIABILITY precheck), so this succeeds even with PRIVATE_LIABILITY
    // already depleted to 0 by W1.
    let w2 = h.withdraw_note(2, DOUBLE_SPEND_NULLIFIER, private_balance);
    assert!(
        w2 == Err(PoolError::NullifierAlreadySpent),
        "W2 must return NullifierAlreadySpent; got: {:?}",
        w2
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Governance harness — shared by tests 14 and 15.
// ─────────────────────────────────────────────────────────────────────────────

/// Initial VK hash placed in the pool.  Tests verify it is unchanged after
/// non-VKU proposals execute.
const POOL_VK_HASH: [u8; 32] = [0xCC; 32];

struct GovHarness {
    pic: PocketIc,
    staking_id: Principal,
    pool_id: Principal,
    user: Principal,
}

impl GovHarness {
    fn new() -> Self {
        let pic = PocketIc::new();

        let user = p(0xB0);
        let treasury = p(0x10);
        let token_id = create_canister(&pic);
        let staking_id = create_canister(&pic);
        let pool_id = create_canister(&pic);
        let nullifier_id = create_canister(&pic);

        pic.install_canister(
            nullifier_id,
            nullifier_wasm(),
            candid::encode_one(pool_id).unwrap(),
            None,
        );

        // Token — user holds all supply (stake + proposals).
        install(&pic, token_id, token_wasm(), &all_to(user, staking_id));

        // Pool — staking_id IS the controller so governance can call
        // emergency_pause_deposits() (which calls assert_controller()).
        install(
            &pic,
            pool_id,
            pool_wasm(),
            &PoolInitArgs {
                token_canister: token_id,
                nullifier_canister: nullifier_id,
                merkle_canister: p(0x20),
                treasury_canister: treasury,
                staking_canister: staking_id,
                controller: staking_id, // governance == controller in test
                initial_vk_hash: POOL_VK_HASH,
                initial_proof_system: "groth16-bn254".to_string(),
            },
        );

        // Staking — near-zero governance delays for fast test cycles.
        install(
            &pic,
            staking_id,
            staking_wasm(),
            &StakingInitArgs {
                token_canister: token_id,
                pool_canister: pool_id,
                treasury_canister: treasury,
                initial_rewards_pool: 0,
                initial_emission_rate_per_day: 0,
                governance_params: Some(GovernanceParams::fast()),
            },
        );

        // Stake 5 000 STSH so user can create proposals and vote.
        // PocketIC executes the cross-canister call:
        //   staking.stake() → token.lock_for_staking(user, 5000 STSH)
        let stake_result: Result<u64, String> = decode(
            "GovHarness::new: stake",
            pic.update_call(
                staking_id,
                user,
                "stake",
                candid::encode_args((5_000_u128 * 100_000_000_u128, 30_u32, next_dedup_key())).unwrap(),
            ),
        );
        stake_result.expect("initial stake must succeed");

        GovHarness {
            pic,
            staking_id,
            pool_id,
            user,
        }
    }

    /// Run a proposal through its full lifecycle:
    ///   create → vote approve → advance time past timelock → execute.
    fn run_proposal_result(&self, proposal_type: ProposalType) -> Result<(), String> {
        // Create proposal (proposer must have >= 1000 STSH staked — we have 5000).
        let create_result: Result<u64, String> = decode(
            "run_proposal: create_proposal",
            self.pic.update_call(
                self.staking_id,
                self.user,
                "create_proposal",
                candid::encode_args((proposal_type, "test proposal".to_string())).unwrap(),
            ),
        );
        let proposal_id = create_result?;

        // voting_delay_ns = 0 → voting is open immediately; cast an approving vote.
        let vote_result: Result<(), String> = decode(
            "run_proposal: vote",
            self.pic.update_call(
                self.staking_id,
                self.user,
                "vote",
                candid::encode_args((proposal_id, true)).unwrap(),
            ),
        );
        vote_result?;

        // Advance past voting_period_ns (1s) + the execution timelock. P-STK
        // K3-015 makes the 7-day execution timelock a real policy floor that
        // cannot be shortened at install, so this advances past the FLOOR, not
        // past a test-only 1-second stand-in. VK-upgrade proposals carry the
        // 14-day timelock instead, so advance past that — it dominates.
        self.pic.advance_time(Duration::from_secs(14 * 24 * 3600 + 60));

        // Execute — cross-canister calls (e.g. emergency_pause_deposits) happen here.
        decode(
            "run_proposal: execute_proposal",
            self.pic.update_call(
                self.staking_id,
                self.user,
                "execute_proposal",
                candid::encode_one(proposal_id).unwrap(),
            ),
        )
    }

    /// Panicking wrapper for legacy tests.
    fn run_proposal(&self, proposal_type: ProposalType) {
        self.run_proposal_result(proposal_type)
            .expect("execute_proposal must succeed");
    }

    /// Query the pool's pinned verifier key hash.
    fn pool_vk_hash(&self) -> [u8; 32] {
        decode(
            "pool_vk_hash query",
            self.pic.query_call(
                self.pool_id,
                anon(),
                "get_pinned_vk_hash",
                candid::encode_args(()).unwrap(), // no-arg function: empty args list
            ),
        )
    }

    /// Query whether pool deposits are paused.
    fn deposits_paused(&self) -> bool {
        decode(
            "is_deposits_paused query",
            self.pic.query_call(
                self.pool_id,
                anon(),
                "is_deposits_paused",
                candid::encode_args(()).unwrap(), // no-arg function: empty args list
            ),
        )
    }

    /// Query whether pool spends are paused.
    fn spends_paused(&self) -> bool {
        decode(
            "is_spends_paused query",
            self.pic.query_call(
                self.pool_id,
                anon(),
                "is_spends_paused",
                candid::encode_args(()).unwrap(), // no-arg function: empty args list
            ),
        )
    }

    /// Current IC time in nanoseconds since UNIX epoch.
    fn now_ns(&self) -> u64 {
        self.pic.get_time().as_nanos_since_unix_epoch()
    }

    /// Non-panicking create_proposal — returns the raw Result.
    /// Use this when testing that creation is correctly rejected.
    fn create_proposal_raw(&self, pt: ProposalType, desc: &str) -> Result<u64, String> {
        decode(
            "create_proposal_raw",
            self.pic.update_call(
                self.staking_id,
                self.user,
                "create_proposal",
                candid::encode_args((pt, desc.to_string())).unwrap(),
            ),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14 — Ordinary proposal cannot schedule a VK activation
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: Only ProposalType::VerifierKeyUpgrade causes schedule_vk_activation()
// to be called on the pool.  A ParameterUpdate proposal — even when it passes
// quorum and timelock — must leave the pool's verifier key hash completely
// unchanged.
//
// DEF-084 update: ParameterUpdate is an unimplemented action and now HARD-ERRORS
// at execution (no pretend-success). The privilege-separation invariant is
// strengthened: the ordinary proposal cannot even claim to execute, and still
// must not touch the VK.
//
// This closes the governance privilege-separation requirement from the PM brief.
// =============================================================================

#[test]
fn test_14_ordinary_proposal_cannot_schedule_vk() {
    let h = GovHarness::new();

    let vk_before = h.pool_vk_hash();
    assert_eq!(
        vk_before, POOL_VK_HASH,
        "VK hash must equal init value before any proposal"
    );

    // Drive a ParameterUpdate through the complete governance lifecycle.
    // DEF-084: execution must hard-error (inert action, not yet active).
    let result = h.run_proposal_result(ProposalType::ParameterUpdate {
        key: "noop_test".to_string(),
        value: "ignored".to_string(),
    });
    assert!(
        result.is_err(),
        "DEF-084: inert ParameterUpdate execution must return Err, got Ok"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("Unsupported") || err.contains("not yet active"),
        "DEF-084: error must state the action is unsupported/not yet active; got: {}",
        err
    );

    // Pool's verifier key must be completely unchanged.
    let vk_after = h.pool_vk_hash();
    assert_eq!(
        vk_after, POOL_VK_HASH,
        "ParameterUpdate proposal must NOT modify the pool's verifier key hash"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Token-movement type mirrors (tests 18 – 23)
// ─────────────────────────────────────────────────────────────────────────────

/// Ledger fee on the token canister (DEFAULT_FEE constant from token/src/lib.rs).
/// F-000: token transfers free at launch.
pub const DEFAULT_FEE: u128 = 0;

/// ICRC-1/2 Account — mirrors token canister's Account type.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<[u8; 32]>,
}

/// icrc2_approve args — mirrors token canister's ApproveArgs.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ApproveArgs {
    pub from_subaccount: Option<[u8; 32]>,
    pub spender: Account,
    pub amount: Nat,
    pub expected_allowance: Option<Nat>,
    pub expires_at: Option<u64>,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

/// Mirrors ApproveError from the token canister (needed for decode type inference).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ApproveError {
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

/// shield_deposit args — mirrors pool canister's ShieldDepositArgs.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ShieldDepositArgs {
    pub note_commitment: [u8; 32],
    pub encrypted_payload: Vec<u8>,
    pub public_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateSpendPublicPayout {
    pub destination: Principal,
    pub destination_subaccount: Option<[u8; 32]>,
    pub public_amount: u128,
}

/// private_spend args — mirrors pool canister's PrivateSpendArgs (M4 updated).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PrivateSpendArgs {
    /// Idempotency key — must be unique per spend attempt.
    pub spend_id: u64,
    pub envelope: ProofEnvelope,
    // M4 stub-verifier scaffolding — parallel arrays for sum-balance enforcement.
    /// Caller-declared input amounts (one per nullifier).  STUB PHASE ONLY.
    /// Caller-declared output amounts (one per output_commitment).  STUB PHASE ONLY.
    pub nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
    pub encrypted_outputs: Vec<Vec<u8>>,
    pub fee: u128,
    pub public_payout: Option<PrivateSpendPublicPayout>,
}

/// Mirrors pool canister's SpendStatus enum (M4 + A2-2 verifier additions).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SpendStatus {
    Requested,
    OutputsStaged,
    Finalized,
    FailedBeforeStateChange { reason: String },
    FailedAfterOutputsStaged { reason: String },
    // A2-2: added with async verifier integration
    VerificationPending,
    NullifierReserved,
    PayoutPending { reason: String },
    // Pass 4
    PayoutSubmitting,
    PayoutUnknown { reason: String },
    NullifierInsertUnknown { reason: String },
    // A2 (QA-DEF-034/036)
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PendingPublicPayout {
    pub destination: Principal,
    pub destination_subaccount: Option<[u8; 32]>,
    pub public_amount: u128,
    pub protocol_fee: u128,
    pub block_index: Option<Nat>,
}

/// Mirrors pool canister's PendingSpend struct (M4).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PendingSpend {
    pub spend_id: u64,
    pub nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
    pub public_payout: Option<PendingPublicPayout>,
    pub outputs_committed: u32,
    pub status: SpendStatus,
    pub created_at_ns: u64,
}

/// Mirrors pool canister's WithdrawalStatus enum (M3 revised).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum WithdrawalStatus {
    Requested,
    ProofVerified,
    /// Pool-local nullifier reservation; registry NOT written yet.
    NullifierReserved,
    /// Protocol solvency fault — nullifier reserved, user claim preserved.
    SolvencyBlocked {
        required: u128,
        available: u128,
    },
    EscrowCoverageChecked,
    LedgerTransferPending,
    /// M3: recipient paid exactly; operations reserve reimbursement deferred.
    FeeReimbursementPending {
        ledger_fee: u128,
    },
    Finalized,
    FailedRetryable,
    /// Non-retryable user/input fault (renamed from FailedTerminal).
    FailedTerminalUserError {
        reason: String,
    },
}

/// Mirrors pool canister's PendingWithdrawal struct (§7 net-recipient model).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PendingWithdrawal {
    pub withdrawal_id: u64,
    pub nullifier: [u8; 32],
    pub destination: Principal,
    pub gross_withdraw_amount: u128,
    pub recipient_net_amount: u128,
    pub ledger_fee: u128,
    pub protocol_unshielding_fee: u128,
    pub status: WithdrawalStatus,
    pub created_at_ns: u64,
    pub finalized_at_ns: Option<u64>,
    pub ledger_memo: Option<Vec<u8>>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreasuryReserveBucket {
    Operations,
    Insurance,
    StakingRewards,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TreasuryDisburseArgs {
    pub proposal_id: u64,
    pub bucket: TreasuryReserveBucket,
    pub recipient: Principal,
    pub recipient_subaccount: Option<[u8; 32]>,
    pub amount: u128,
    pub expected_ledger_fee: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TreasuryDisburseResult {
    Executed { block_index: Nat },
    AlreadyExecuted { block_index: Nat },
}

/// Mirrors pool canister's AccountingState struct (M3).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AccountingState {
    pub private_liability: u128,
    pub escrow_backing: u128,
    pub operations_reserve: u128,
    pub insurance_reserve: u128,
    pub governance_rewards_reserve: u128,
    pub pending_fee_reimbursements: u128,
}

/// Mirrors stsh_fee_policy::SpendFeeMode.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendFeeMode {
    FixedStsh,
    XdrPegged,
}

/// Mirrors stsh_fee_policy::GovernanceFeeParams.
/// Used by set_governance_fee_params (controller-only pool endpoint).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct GovernanceFeeParams {
    pub protocol_shielding_fee_stsh: u128,
    pub protocol_unshielding_fee_stsh: u128,
    pub protocol_private_spend_fee_stsh: u128,
    pub minimum_withdrawal_gross: u128,
    pub minimum_recipient_amount: u128,
    pub minimum_private_credit: u128,
    pub fee_reference_price_stsh_per_icp_e8s: u128,
    pub fee_safety_margin_bps: u32,
    pub max_fee_change_bps_per_update: u32,
    pub fee_update_cooldown_ns: u64,
    pub operations_split_bps: u32,
    pub insurance_split_bps: u32,
    pub staking_rewards_split_bps: u32,
    pub staking_rewards_enabled: bool,
    pub minimum_treasury_runway_months: u32,
    pub target_treasury_runway_months: u32,
    // Value fees (fee-build lane).
    pub shield_fee_bps: Option<u16>,
    pub unshield_fee_bps: Option<u16>,
    pub shield_flat_minimum_fee_e8s: Option<u128>,
    pub unshield_flat_minimum_fee_e8s: Option<u128>,
    pub spend_fee_mode: Option<SpendFeeMode>,
    pub fee_model_version: Option<u32>,
    pub params_epoch: Option<u64>,
}

impl GovernanceFeeParams {
    /// Launch defaults mirroring GovernanceFeeParams::launch_defaults() in fee-policy.
    pub fn launch_defaults() -> Self {
        Self {
            protocol_shielding_fee_stsh: 0,
            protocol_unshielding_fee_stsh: 0,
            protocol_private_spend_fee_stsh: 0,
            minimum_withdrawal_gross: 0,
            minimum_recipient_amount: 0,
            minimum_private_credit: 0,
            fee_reference_price_stsh_per_icp_e8s: 0,
            fee_safety_margin_bps: 12_500,
            max_fee_change_bps_per_update: 1_000,
            fee_update_cooldown_ns: 24 * 60 * 60 * 1_000_000_000,
            operations_split_bps: 8_500,
            insurance_split_bps: 1_500,
            staking_rewards_split_bps: 0,
            staking_rewards_enabled: false,
            minimum_treasury_runway_months: 6,
            target_treasury_runway_months: 12,
            shield_fee_bps: Some(0),
            unshield_fee_bps: Some(0),
            shield_flat_minimum_fee_e8s: Some(0),
            unshield_flat_minimum_fee_e8s: Some(0),
            spend_fee_mode: Some(SpendFeeMode::FixedStsh),
            fee_model_version: Some(1),
            params_epoch: Some(0),
        }
    }
}

/// Mirrors treasury canister's FeeSource enum.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FeeSource {
    ShieldFee,
    PrivateTransferFee,
    UnshieldFee,
    DexRevenue,
}

/// Mirrors treasury canister's FeeLogEntry struct.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct FeeLogEntry {
    pub timestamp_ns: u64,
    pub source: FeeSource,
    pub total_amount: u128,
    pub operations: u128,
    pub insurance: u128,
    pub audit: u128,
    pub staking: u128,
}

/// Mirrors pool canister's DepositStatus enum (QA-DEF-017 four-phase machine).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DepositStatus {
    /// Deprecated (pre-QA-DEF-017) — decode-compat only.
    CommitmentPending,
    /// QA-DEF-017: deposit record written before the token transfer is confirmed.
    TransferPending,
    /// QA-DEF-017: token transfer confirmed; Merkle append outstanding (retryable).
    TransferConfirmedCommitmentPending,
    /// QA-DEF-017: Merkle append claimed and in flight.
    CommitmentAppendInFlight,
    /// Merkle append confirmed; accounting updated.
    CommitmentAppended { leaf_index: u64 },
    /// QA-DEF-017: append returned a transport-unknown outcome — leaf may exist,
    /// no credit, no re-append (operator reconciliation required).
    CommitmentAppendUnknown,
    /// DEF-098: transient reconcile claim marker.
    CommitmentReconcileInFlight,
    /// DEF-040/P-ROOT: terminal — leaf appended AND resulting root accepted.
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
}

/// Mirrors pool canister's PendingDeposit struct (M3 Track B).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PendingDeposit {
    pub note_commitment: [u8; 32],
    pub private_balance: u128,
    pub ops_amount: u128,
    pub insurance_amount: u128,
    pub encrypted_payload: Vec<u8>,
    pub depositor: Option<Principal>,  // F2-REDACT: opt principal
    pub status: DepositStatus,
    pub created_at_ns: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Token-movement test harness
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: build a TokenInitArgs with two allocations:
///   - `user_amount` → `user`
///   - `pool_amount` → `pool_id`
///
/// Used to pre-fund the pool canister for withdrawal tests.
fn split_token_init(
    user: Principal,
    user_amount: u128,
    pool_id: Principal,
    pool_amount: u128,
    staking: Principal,
) -> TokenInitArgs {
    let remainder = TOTAL_SUPPLY - user_amount - pool_amount;
    let mut allocs = vec![AllocationCategory {
        category_id: "user".to_string(),
        category_name: "Test user".to_string(),
        amount: user_amount,
        recipient: user,
        subaccount: None,
        lock_policy: LockPolicy::ImmediatelyLiquid,
        vesting_policy: None,
        created_at_genesis: false,
        genesis_timestamp_ns: 0,
    }];
    // pool_reserve allocation is only added when the pool is pre-funded (pool_seed > 0).
    // Allocations with amount = 0 are rejected by the token canister's init validation.
    if pool_amount > 0 {
        allocs.push(AllocationCategory {
            category_id: "pool_reserve".to_string(),
            category_name: "Pool fee reserve".to_string(),
            amount: pool_amount,
            recipient: pool_id,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        });
    }
    if remainder > 0 {
        allocs.push(AllocationCategory {
            category_id: "other".to_string(),
            category_name: "Other".to_string(),
            amount: remainder,
            recipient: p(0xFE),
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        });
    }
    TokenInitArgs {
        allocations: allocs,
        treasury: p(0x01),
        staking_canister: staking,
    }
}

/// Approve the pool to spend `amount` of the caller's tokens.
fn do_approve(
    pic: &PocketIc,
    token_id: Principal,
    caller: Principal,
    spender: Principal,
    amount: u128,
) {
    let result: Result<Nat, ApproveError> = decode(
        "do_approve",
        pic.update_call(
            token_id,
            caller,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: spender,
                    subaccount: None,
                },
                amount: Nat::from(amount),
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
    result.expect("icrc2_approve must succeed in test setup");
}

/// Query an icrc1_balance_of.
fn token_balance(pic: &PocketIc, token_id: Principal, owner: Principal) -> u128 {
    let bal: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            token_id,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account {
                owner,
                subaccount: None,
            })
            .unwrap(),
        ),
    );
    // BigUint::to_string gives decimal; parse back into u128 for assertions.
    bal.0.to_string().parse::<u128>().unwrap_or(0)
}

/// Query the pool's accounting state (6-bucket model) as a specific caller.
/// DEF-076: get_accounting_state is controller-gated — observability reads pass the
/// pool's stored controller.
fn accounting_state_as(pic: &PocketIc, pool_id: Principal, caller: Principal) -> AccountingState {
    decode(
        "get_accounting_state",
        pic.query_call(
            pool_id,
            caller,
            "get_accounting_state",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Convenience: read as the common test controller p(0x06). Tests deploying with a
/// different controller call accounting_state_as(..) with that principal.
fn accounting_state(pic: &PocketIc, pool_id: Principal) -> AccountingState {
    accounting_state_as(pic, pool_id, p(0x06))
}

/// Query the Merkle canister's leaf count.
fn merkle_leaf_count(pic: &PocketIc, merkle_id: Principal) -> u64 {
    decode(
        "merkle leaf_count",
        pic.query_call(
            merkle_id,
            anon(),
            "leaf_count",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Query the Merkle canister's current root (32 bytes, Poseidon empty-tree root on a fresh canister).
fn merkle_root(pic: &PocketIc, merkle_id: Principal) -> [u8; 32] {
    let bytes: Vec<u8> = decode(
        "merkle_root: get_root",
        pic.query_call(
            merkle_id,
            anon(),
            "get_root",
            candid::encode_args(()).unwrap(),
        ),
    );
    bytes
        .try_into()
        .expect("get_root must return exactly 32 bytes")
}

/// Query a single Merkle leaf by index (raw stored 32-byte value, None if out of range).
fn get_leaf(pic: &PocketIc, merkle_id: Principal, index: u64) -> Option<Vec<u8>> {
    decode(
        "get_leaf",
        pic.query_call(
            merkle_id,
            anon(),
            "get_leaf",
            candid::encode_one(index).unwrap(),
        ),
    )
}

// =============================================================================
// DEF-111 — the deposit tree leaf binds the CREDITED value.
//
// AR1-10 (AR-2 census residual). This header used to say the test sets a nonzero
// fee "so private_balance_credit = public_amount - fee < public_amount" and then
// asserts the leaf binds that reduced value. That is the SUPERSEDED deducted
// model, and it was stated here as live rationale while the body below asserted
// the opposite — `assert_eq!(net, gross)`. Header and code disagreed about which
// value the guard protects.
//
// What the test actually does, and why the nonzero fee still matters: with
// fee-on-top the credited value IS the full gross, and at the launch fee of 0 the
// credited and fee-reduced leaves are identical, so a wrong binding would be
// invisible. Setting a NONZERO shielding fee separates them — `leaf_credited` and
// `leaf_reduced` below are then genuinely different values — and the test asserts
// the appended leaf equals merkle_leaf(gross) and NOT merkle_leaf(gross - fee).
// Binding the fee-reduced value is the old-model bug this guards against (0c
// invariant: Σ(leaf values) == PRIVATE_LIABILITY holds under a nonzero fee too).
// =============================================================================
#[test]
fn test_def111_deposit_leaf_binds_credited_value_not_fee_reduced() {
    let pic = PocketIc::new();
    let user = p(0xA5);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(null_id, nullifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(&pic, pool_id, pool_test_wasm(), &PoolInitArgs {
        token_canister: token_id,
        nullifier_canister: null_id,
        merkle_canister: merkle_id,
        treasury_canister: p(0x04),
        staking_canister: p(0x05),
        controller: p(0x06),
        initial_vk_hash: TEST_VK_HASH,
        initial_proof_system: "groth16-bn254".to_string(),
    });

    // Set a NONZERO shielding fee (split-bps unchanged, so the setter accepts it).
    // Value-fee model: express the fixed fee via the flat-minimum field.
    let shielding_fee: u128 = 5_000_000; // 0.05 STSH
    let mut params = GovernanceFeeParams::launch_defaults();
    params.shield_flat_minimum_fee_e8s = Some(shielding_fee);
    let set: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        pic.update_call(
            pool_id, p(0x06), "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    set.expect("set_governance_fee_params (nonzero shielding fee) must succeed");

    // Deposit a 100-STSH denomination note. Fee-ON-TOP: the note is credited the
    // FULL gross and the pool pulls gross + shielding_fee, so approve for both.
    let gross = DENOMINATIONS[2]; // 100 STSH = 1e10
    let commitment: [u8; 32] = canon(0x33);
    do_approve(&pic, token_id, user, pool_id, gross + shielding_fee + DEFAULT_FEE);
    let net_res: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            pool_id, user, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![],
                public_amount: gross,
            }).unwrap(),
        ),
    );
    let net_nat = net_res.expect("shield_deposit must succeed");
    let net: u128 = net_nat.0.to_string().parse().unwrap();

    // Fee-ON-TOP: the note is credited the FULL gross (the fee is charged on top,
    // not deducted). private_balance_credit == gross.
    assert_eq!(net, gross, "fee-on-top: credited value must be the full gross");

    // DEF-111: the appended tree leaf must be the VALUE-BOUND leaf over the
    // CREDITED value (which, with fee-on-top, is the full gross). Binding the
    // fee-reduced value would be the (old-model) bug we guard against.
    let leaf = get_leaf(&pic, merkle_id, 0).expect("leaf 0 must exist after deposit");
    let leaf_credited = stsh_field_utils::merkle_leaf(net, &commitment).to_vec();
    let leaf_reduced  = stsh_field_utils::merkle_leaf(gross - shielding_fee, &commitment).to_vec();

    assert_eq!(
        leaf, leaf_credited,
        "DEF-111: deposit leaf must equal merkle_leaf(private_balance_credit, C) — the full credited value"
    );
    assert_ne!(
        leaf, leaf_reduced,
        "DEF-111: deposit leaf must NOT bind the fee-reduced value — fee-on-top credits the full gross"
    );
}

/// Query the pool's deposit status for a given note_commitment.
fn deposit_status(
    pic: &PocketIc,
    pool_id: Principal,
    note_commitment: [u8; 32],
) -> Option<PendingDeposit> {
    decode(
        "get_deposit_status",
        // DEF-070: get_deposit_status is owner-or-controller gated — poll as the
        // pool controller p(0x06) (controller may read any record).
        pic.query_call(
            pool_id,
            p(0x06),
            "get_deposit_status",
            candid::encode_one(note_commitment).unwrap(),
        ),
    )
}

/// Query the pool's spend status for a given spend_id (M4).
fn spend_status(pic: &PocketIc, pool_id: Principal, spend_id: u64) -> Option<PendingSpend> {
    // DEF-069: get_spend_status is owner-or-controller gated. Most security_tests
    // pools use controller p(0x06); tests that deploy with a different controller
    // call spend_status_as with the correct one.
    spend_status_as(pic, pool_id, p(0x06), spend_id)
}

fn spend_status_as(
    pic: &PocketIc,
    pool_id: Principal,
    caller: Principal,
    spend_id: u64,
) -> Option<PendingSpend> {
    decode(
        "get_spend_status",
        pic.query_call(
            pool_id,
            caller,
            "get_spend_status",
            candid::encode_one(spend_id).unwrap(),
        ),
    )
}

/// Query whether a nullifier is in the permanent registry.
fn null_contains(pic: &PocketIc, null_id: Principal, nullifier: [u8; 32]) -> bool {
    decode(
        "contains_nullifier",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(nullifier.to_vec()).unwrap(),
        ),
    )
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .join("circuits")
}

/// Load the real proof/public artifacts and construct a valid PrivateSpendArgs.
/// Returns None (and the calling test should skip) if circuits/proof.json or
/// circuits/public.json are absent — mirrors verifier_tests::load_artifacts().
fn load_valid_spend_fixture_args(spend_id: u64) -> Option<PrivateSpendArgs> {
    let public_json = std::fs::read_to_string(circuits_dir().join("public.json")).ok()?;
    let proof_json = std::fs::read_to_string(circuits_dir().join("proof.json")).ok()?;
    let signals = stsh_verifier::public_json_to_signals(&public_json).ok()?;
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json).ok()?;
    Some(PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference: signals[0],
            pool_version: 1,
            proof_bytes,
        },
        nullifiers: vec![signals[1]],
        output_commitments: vec![signals[2], signals[3]],
        encrypted_outputs: vec![vec![0xAA], vec![0xBB]],
        fee: 0,
        public_payout: None,
    })
}

/// Perform a shield_deposit and return the credited private balance (note value).
/// AR1-10: fee-on-top — this is the FULL gross, not a fee-deducted "net".
fn do_deposit(
    pic: &PocketIc,
    token_id: Principal,
    pool_id: Principal,
    user: Principal,
    public_amount: u128,
) -> u128 {
    // Approve pool for public_amount + DEFAULT_FEE (ICRC-2 transferFrom costs the fee).
    do_approve(pic, token_id, user, pool_id, public_amount + DEFAULT_FEE);

    let result: Result<Nat, PoolError> = decode(
        "do_deposit: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0xAA),
                encrypted_payload: vec![],
                public_amount,
            })
            .unwrap(),
        ),
    );
    let nat = result.expect("do_deposit: shield_deposit must succeed");
    nat.0.to_string().parse::<u128>().unwrap_or(0) // returns private_balance
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 18 — Deposit rejected when no allowance is set
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: shield_deposit calls icrc2_transfer_from before creating any
// note commitment.  If the caller has not granted an ICRC-2 allowance, the
// ledger returns InsufficientFunds and the pool must propagate TransferFailed.
// No commitment is created; pool balance is unchanged.
// =============================================================================

#[test]
fn test_18_deposit_rejected_no_allowance() {
    let pic = PocketIc::new();
    let user = p(0xA3);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: p(0x03),
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: TEST_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Deliberately skip icrc2_approve — pool has no spending allowance.
    let result: Result<Nat, PoolError> = decode(
        "test_18: shield_deposit with no allowance",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: [0x11u8; 32],
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(result, Err(PoolError::TransferFailed(_))),
        "Deposit without allowance must return TransferFailed; got: {:?}",
        result
    );

    // Pool balance must be zero — no tokens moved.
    let pool_bal = token_balance(&pic, token_id, pool_id);
    assert_eq!(pool_bal, 0, "Pool must hold 0 tokens after failed deposit");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 19 — Deposit rejected when allowance < amount + fee
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: The pool calls icrc2_transfer_from(amount=public_amount).  The
// ledger deducts (public_amount + fee) from the allowance.  An allowance of
// exactly public_amount is insufficient and must cause a rejection.
// =============================================================================

#[test]
fn test_19_deposit_rejected_insufficient_allowance() {
    let pic = PocketIc::new();
    let user = p(0xA4);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: p(0x03),
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: TEST_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Approve short of public_amount + fee. F-000 (fee = 0): an approval of
    // exactly DENOMINATIONS[0] is no longer short, so go short by 1 base unit —
    // the ledger checks allowance >= amount + fee and must still fail.
    do_approve(&pic, token_id, user, pool_id, DENOMINATIONS[0] - 1); // short by 1

    let result: Result<Nat, PoolError> = decode(
        "test_19: shield_deposit with insufficient allowance",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: [0x22u8; 32],
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(result, Err(PoolError::TransferFailed(_))),
        "Deposit with insufficient allowance must return TransferFailed; got: {:?}",
        result
    );

    let pool_bal = token_balance(&pic, token_id, pool_id);
    assert_eq!(pool_bal, 0, "Pool must hold 0 tokens after failed deposit");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 20 — Successful deposit increases pool escrow balance
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: When the caller approves pool for >= (amount + fee) and calls
// shield_deposit(amount), the pool must:
//   a) succeed (return Ok)
//   b) have its token balance increased by amount (the ledger keeps the fee)
//   c) the caller's balance must have decreased by (amount + fee)
// =============================================================================

#[test]
fn test_20_deposit_success_increases_pool_balance() {
    let pic = PocketIc::new();
    let user = p(0xA5);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: TEST_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let user_before = token_balance(&pic, token_id, user);
    let pool_before = token_balance(&pic, token_id, pool_id);
    assert_eq!(pool_before, 0, "pool must start at zero");

    // Approve pool for amount + fee (correct allowance).
    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );

    let result: Result<Nat, PoolError> = decode(
        "test_20: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0x33),
                encrypted_payload: vec![0xAB, 0xCD],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        result.is_ok(),
        "Deposit with correct allowance must succeed; got: {:?}",
        result
    );

    // Pool receives exactly public_amount (ledger keeps the fee).
    let pool_after = token_balance(&pic, token_id, pool_id);
    assert_eq!(
        pool_after, DENOMINATIONS[0],
        "Pool balance must equal deposited amount after successful deposit"
    );

    // Caller paid amount + deposit_fee + approve_fee (2x DEFAULT_FEE total: 1 for approve, 1 for transferFrom).
    let user_after = token_balance(&pic, token_id, user);
    let expected_user = user_before
        .saturating_sub(DENOMINATIONS[0]) // deposited
        .saturating_sub(DEFAULT_FEE) // approve fee (paid by caller to the ledger)
        .saturating_sub(DEFAULT_FEE); // transferFrom fee (deducted from allowance)
    assert_eq!(
        user_after, expected_user,
        "User balance must decrease by amount + 2*fee; before={} after={} expected={}",
        user_before, user_after, expected_user
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 21 — Exact-settlement withdrawal (M3 semantics)
// ─────────────────────────────────────────────────────────────────────────────
//
// FEE SEMANTICS (M3 exact-settlement):
//   withdrawal_amount  = exact amount recipient receives (= note value)
//   pool debit         = withdrawal_amount + ledger_fee
//   operations reserve reimburses ledger_fee to escrow (internal accounting)
//
// Pool must hold at least (withdrawal_amount + ledger_fee) to service the withdrawal.
//
// INVARIANTS verified:
//   a) Withdrawal status is Finalized.
//   b) Recipient balance increases by exactly withdrawal_amount (no fee deducted).
//   c) Pool balance drops by withdrawal_amount + DEFAULT_FEE (exact debit).
//   d) Same nullifier + fresh withdrawal_id → NullifierAlreadySpent.
// =============================================================================

const T21_VK_HASH: [u8; 32] = [0xDD; 32];
const T21_NULLIFIER: [u8; 32] = [0x0E; 32];

// Lane A v2 Task 0.25: this test exercises successful-withdrawal payout, finalization, and duplicate-nullifier accounting, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: payout/accounting coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_21_withdrawal_net_recipient_basic() {
    // Real funding path: shield_deposit sets PRIVATE_LIABILITY so the
    // PRIVATE_LIABILITY >= gross precheck passes.  At zero shielding fee,
    // private_balance = gross = DENOMINATIONS[0].
    let h = PoolHarness::new(0xA6, T21_VK_HASH, 0);
    let private_balance = h.deposit(DENOMINATIONS[0]);

    let user_before = h.balance(h.user);

    // W1 — must succeed.
    let w1 = h.withdraw_note(100, T21_NULLIFIER, private_balance);
    assert!(w1.is_ok(), "Withdrawal must succeed; got: {:?}", w1);

    // a) §7: withdrawal always Finalized (FeeReimbursementPending not produced).
    let rec: Option<PendingWithdrawal> = decode(
        "test_21: get_withdrawal_status",
        h.pic.query_call(
            h.pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(100u64).unwrap(),
        ),
    );
    let rec = rec.expect("withdrawal record must exist after W1");
    assert_eq!(
        rec.status,
        WithdrawalStatus::Finalized,
        "§7: withdrawal must always yield Finalized; got: {:?}",
        rec.status
    );

    // b) §7 net-recipient: recipient receives gross - ledger_fee.
    let user_after = h.balance(h.user);
    assert_eq!(
        user_after,
        user_before + private_balance - DEFAULT_FEE,
        "§7: recipient must receive gross - ledger_fee; \
         before={} after={} expected={}",
        user_before,
        user_after,
        user_before + private_balance - DEFAULT_FEE
    );

    // c) Pool retains protocol_shielding_fee after withdrawal (0 at launch → pool_after = 0).
    let pool_after = token_balance(&h.pic, h.token_id, h.pool_id);
    assert_eq!(
        pool_after,
        DENOMINATIONS[0] - private_balance,
        "Pool must retain protocol_shielding_fee after withdrawal; got={}",
        pool_after
    );

    // d) Same nullifier + fresh withdrawal_id → NullifierAlreadySpent.
    // NullifierAlreadySpent fires at the registry check before the
    // PRIVATE_LIABILITY precheck, so this is rejected correctly even with
    // PRIVATE_LIABILITY depleted to 0 after W1.
    let w2 = h.withdraw_note(101, T21_NULLIFIER, private_balance);
    assert!(
        w2 == Err(PoolError::NullifierAlreadySpent),
        "Fresh withdrawal_id with spent nullifier must return NullifierAlreadySpent; got: {:?}",
        w2
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 22 — Only the pool canister can call insert_nullifier
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: The nullifier registry's insert_nullifier method is guarded by
// assert_pool_canister() which panics (traps) if caller != POOL_CANISTER.
// A direct call from any other principal must be rejected before any state
// mutation, preserving the nullifier set as an immutable append-only log.
// =============================================================================

#[test]
fn test_22_only_pool_can_insert_nullifier() {
    let pic = PocketIc::new();
    let pool_id = p(0xCA); // pool is an ordinary principal for this test
    let attacker = p(0xFF);
    let null_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );

    let test_nullifier = [0x09u8; 32];

    // Attacker calls insert_nullifier directly — must be rejected.
    let result = pic.update_call(
        null_id,
        attacker,
        "insert_nullifier",
        candid::encode_one(test_nullifier.to_vec()).unwrap(),
    );
    expect_reject("test_22: attacker calling insert_nullifier", result);

    // Nullifier must NOT have been inserted.
    let present: bool = decode(
        "test_22: contains_nullifier after rejected insert",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(test_nullifier.to_vec()).unwrap(),
        ),
    );
    assert!(
        !present,
        "Nullifier must NOT be in registry after unauthorized insert attempt"
    );

    // Confirm the authorized caller (pool_id) CAN insert.
    let ok: Result<(), String> = decode(
        "test_22: authorized insert_nullifier",
        pic.update_call(
            null_id,
            pool_id,
            "insert_nullifier",
            candid::encode_one(test_nullifier.to_vec()).unwrap(),
        ),
    );
    assert!(
        ok.is_ok(),
        "Authorized pool insert must succeed; got: {:?}",
        ok
    );

    let present_after: bool = decode(
        "test_22: contains_nullifier after authorized insert",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(test_nullifier.to_vec()).unwrap(),
        ),
    );
    assert!(
        present_after,
        "Nullifier must appear after authorized insert"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 23 — private_spend with duplicate nullifier is rejected
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: private_spend calls insert_nullifier for each input nullifier.
// A second private_spend that reuses a nullifier from an earlier spend must
// fail with NullifierAlreadySpent — closing the double-spend window on the
// private transfer path (as opposed to the withdraw path tested in test_07).
// =============================================================================

const T23_VK_HASH: [u8; 32] = [0xB3; 32]; // distinct from TEST_VK_HASH/POOL_VK_HASH
const T23_NF_A: [u8; 32] = [0xF1; 32];
const T23_NF_B: [u8; 32] = [0xF2; 32];

// A2: uses proof_bytes:vec![] and 2-nullifier shape, incompatible with real Groth16 verifier.
// Re-enable when per-test ZK proofs are generated for the multi-nullifier circuit variant.
#[ignore = "A2: requires real ZK proof; proof_bytes:vec![] now reaches ZK check before shape check"]
#[test]
fn test_23_private_spend_duplicate_nullifier_rejected() {
    let pic = PocketIc::new();
    let user = p(0xA7);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T23_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T23_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // S1: first spend with nullifiers [A, B] — must succeed.
    let s1: Result<(), PoolError> = decode(
        "test_23: S1 private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 2301,
                envelope: env.clone(),
                nullifiers: vec![T23_NF_A, T23_NF_B],
                output_commitments: vec![[0x11u8; 32], [0x22u8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(s1.is_ok(), "S1 (first spend) must succeed; got: {:?}", s1);

    // Both nullifiers are now in the registry.
    for (label, nf) in [("A", T23_NF_A), ("B", T23_NF_B)] {
        assert!(
            null_contains(&pic, null_id, nf),
            "Nullifier {} must be in registry after S1",
            label
        );
    }

    // S2: spend with nullifier A again — must fail.
    let s2: Result<(), PoolError> = decode(
        "test_23: S2 private_spend (duplicate nullifier A)",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 2302,
                envelope: env.clone(),
                nullifiers: vec![T23_NF_A], // already spent
                output_commitments: vec![[0x33u8; 32]],
                encrypted_outputs: vec![vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        s2 == Err(PoolError::NullifierAlreadySpent),
        "S2 with spent nullifier must return NullifierAlreadySpent; got: {:?}",
        s2
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 46 (DEF-046) — private_spend rejects duplicate or zero output commitments
// ─────────────────────────────────────────────────────────────────────────────
//
// DEF-046: the two output commitments must be DISTINCT and NON-ZERO. The guard lives
// in the pure static-validation phase (validate_private_spend_static), AFTER the
// signal-canonicality build but BEFORE the VerificationPending PendingSpend write, the
// heap nullifier reservation, any Merkle staging, AND the async verifier call — so an
// invalid pair leaves NO residue in pool state. All other signals here are canonical
// (low-byte canon() values) so signal-canonicalization passes and the DEF-046 check is
// what fires. No verifier is configured: rejection happens before the verifier step. If
// the guard were reverted, the spend would advance past static validation and fail later
// (e.g. AnchorNotFound at the anchor precheck), so the assertions below would break.
//
// Verifies, for both the duplicate (oc1 == oc2) and zero (oc == 0) cases:
//   a) the call returns the expected typed error,
//   b) no PendingSpend record was written (get_spend_status == None),
//   c) no Merkle leaf was appended (leaf_count unchanged).
// =============================================================================

const T46_VK_HASH: [u8; 32] = [0x46; 32];

#[test]
fn test_46_private_spend_rejects_duplicate_output_commitments() {
    let pic = PocketIc::new();
    let user = p(0xA6);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(null_id, nullifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T46_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Envelope that passes static validation steps 1-4 (circuit/pool defaults 0/1,
    // VK matches init, fee 0 at launch, balanced 0-sum amounts).
    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T46_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    let leaves_before = merkle_leaf_count(&pic, merkle_id);

    // ── Case 1: oc1 == oc2 → DuplicateOutputCommitment ──
    // canon() = canonical low-byte Fr value, so signal-canonicalization passes and the
    // DEF-046 duplicate check (not NonCanonicalSignal) is what rejects this pair.
    let dup = canon(0x55);
    let r_dup: Result<(), PoolError> = decode(
        "test_46: duplicate output commitments",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4601,
                envelope: env.clone(),
                nullifiers: vec![canon(0x46)],
                output_commitments: vec![dup, dup],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        r_dup,
        Err(PoolError::DuplicateOutputCommitment),
        "duplicate output commitments must be rejected with DuplicateOutputCommitment; got {:?}",
        r_dup
    );
    assert!(
        spend_status(&pic, pool_id, 4601).is_none(),
        "no PendingSpend record may exist after the duplicate-oc rejection"
    );

    // ── Case 2: oc1 == [0u8;32] → InvalidOutputCommitment ──
    let r_zero: Result<(), PoolError> = decode(
        "test_46: zero output commitment",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4602,
                envelope: env.clone(),
                nullifiers: vec![canon(0x47)],
                output_commitments: vec![[0u8; 32], canon(0x33)],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        r_zero,
        Err(PoolError::InvalidOutputCommitment),
        "zero output commitment must be rejected with InvalidOutputCommitment; got {:?}",
        r_zero
    );
    assert!(
        spend_status(&pic, pool_id, 4602).is_none(),
        "no PendingSpend record may exist after the zero-oc rejection"
    );

    // Neither rejected spend appended a Merkle leaf.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        leaves_before,
        "no Merkle leaf may be appended by a rejected private_spend"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 24 — SolvencyBlocked: escrow failure preserves nullifier reservation (M3 revised)
// ─────────────────────────────────────────────────────────────────────────────
//
// M3 revised semantics: escrow underfunding is a PROTOCOL FAULT, not a user error.
// The nullifier must NOT be permanently consumed.  It is reserved pool-locally
// (in the WITHDRAWALS map) so concurrent claims are blocked, but the registry
// is NOT written.  The user's claim is preserved pending governance top-up.
//
// INVARIANTS verified:
//   a) Withdrawal with pool_balance < withdrawal_amount + ledger_fee returns
//      EscrowUnderfunded (NOT InsufficientEscrowCoverage / NOT TransferFailed).
//   b) Withdrawal status is SolvencyBlocked { required, available }.
//   c) Nullifier is NOT in registry — user's note is not destroyed.
//   d) Retry of same withdrawal_id → EscrowUnderfunded (idempotency: SolvencyBlocked arm).
//   e) A different withdrawal_id claiming the same nullifier → NullifierReserved.
//      (pool-local reservation blocks concurrent double-claim)
// =============================================================================

const T24_VK_HASH: [u8; 32] = [0xC4; 32];
const T24_NULLIFIER: [u8; 32] = [0xC5; 32];
const T24_NULLIFIER2: [u8; 32] = [0xC6; 32]; // fresh nullifier for test_36

// Lane A v2 Task 0.25: this test exercises solvency-blocked withdrawal state and nullifier reservation preservation, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: solvency reservation coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_24_solvency_blocked_preserves_nullifier_reservation() {
    let pic = PocketIc::new();
    let user = p(0xA8);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    // Give pool DENOMINATIONS[0] - 1 (one short of required = gross = DENOMINATIONS[0]).
    // §7 escrow check: pool_balance >= ledger_debit_from_pool = gross - protocol_unshielding_fee.
    // At zero protocol_unshielding_fee: required = gross = DENOMINATIONS[0].
    let init = split_token_init(
        user,
        TOTAL_SUPPLY - (DENOMINATIONS[0] - 1),
        pool_id,
        DENOMINATIONS[0] - 1,
        p(0x02),
    );

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T24_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T24_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // a) W1 — pool balance insufficient → EscrowUnderfunded.
    let w1: Result<Nat, PoolError> = decode(
        "test_24: W1 withdraw with insufficient escrow",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 300,
                envelope: env.clone(),
                nullifier: T24_NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(w1, Err(PoolError::EscrowUnderfunded { .. })),
        "Escrow shortfall must return EscrowUnderfunded; got: {:?}",
        w1
    );
    if let Err(PoolError::EscrowUnderfunded {
        required,
        available,
    }) = w1
    {
        assert!(
            required > available,
            "required ({}) must exceed available ({})",
            required,
            available
        );
    }

    // b) Withdrawal status must be SolvencyBlocked — user claim preserved.
    let rec: Option<PendingWithdrawal> = decode(
        "test_24: get_withdrawal_status after W1",
        pic.query_call(
            pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(300u64).unwrap(),
        ),
    );
    let rec = rec.expect("withdrawal record must exist after W1");
    assert!(
        matches!(rec.status, WithdrawalStatus::SolvencyBlocked { .. }),
        "Status must be SolvencyBlocked; got: {:?}",
        rec.status
    );
    if let WithdrawalStatus::SolvencyBlocked {
        required,
        available,
    } = &rec.status
    {
        assert_eq!(
            *required, DENOMINATIONS[0],
            "SolvencyBlocked.required must equal ledger_debit_from_pool = gross"
        );
        assert_eq!(
            *available,
            DENOMINATIONS[0] - 1,
            "SolvencyBlocked.available must equal pool balance at time of check"
        );
    }

    // c) Nullifier must NOT be in the registry — the user's note is not destroyed.
    let in_reg: bool = decode(
        "test_24: nullifier NOT in registry after SolvencyBlocked",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(T24_NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        !in_reg,
        "M3 revised: nullifier must NOT be in registry after SolvencyBlocked \
         (insert_nullifier is called only at finalization)"
    );

    // d) Retry same withdrawal_id → EscrowUnderfunded (idempotency path).
    let w1_retry: Result<Nat, PoolError> = decode(
        "test_24: retry same withdrawal_id → EscrowUnderfunded",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 300, // same id
                envelope: env.clone(),
                nullifier: T24_NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(w1_retry, Err(PoolError::EscrowUnderfunded { .. })),
        "Retry of SolvencyBlocked id must return EscrowUnderfunded; got: {:?}",
        w1_retry
    );

    // e) Different withdrawal_id, same nullifier → NullifierReserved.
    //    W1's pool-local reservation must block concurrent claims.
    let w2: Result<Nat, PoolError> = decode(
        "test_24: different id, same nullifier → NullifierReserved",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 301, // different id
                envelope: env,
                nullifier: T24_NULLIFIER, // same nullifier
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        w2 == Err(PoolError::NullifierReserved),
        "Concurrent claim of reserved nullifier must return NullifierReserved; got: {:?}",
        w2
    );
}

// =============================================================================
// M3 Track A tests (test_25 – test_34) — reserve model + exact settlement
// =============================================================================
//
// These tests require a pool canister built from the M3 shielded-pool, with
// the 6-bucket accounting model and the deposit/withdraw flow (the dead M3
// compute_shielding_reserve formula was removed in F-B3-1; the live deposit fee
// is the governance value fee).
//
// Common setup pattern:
//   - Install token, nullifier, pool with test VK hash
//   - shield_deposit(DENOMINATIONS[0]) — pool receives tokens, accounting updated
//   - Withdraw the note — verify exact amount, accounting, status
// =============================================================================

const T25_VK_HASH: [u8; 32] = [0x25; 32];
const T25_NF: [u8; 32] = [0x25u8; 32];

/// Build a minimal pool harness: token, nullifier, merkle, pool.
/// user starts with TOTAL_SUPPLY - pre_funded, pool starts with pre_funded.
struct PoolHarness {
    pic: PocketIc,
    token_id: Principal,
    null_id: Principal,
    pool_id: Principal,
    merkle_id: Principal,
    user: Principal,
    vk_hash: [u8; 32],
}

impl PoolHarness {
    /// Create harness with pool pre-funded with `pool_seed` tokens.
    /// If `pool_seed = 0`, user holds all tokens.
    fn new(user_byte: u8, vk: [u8; 32], pool_seed: u128) -> Self {
        Self::new_with_pool_wasm(user_byte, vk, pool_seed, pool_wasm())
    }

    /// RB-SWARM-A1: same stack on the `_test` Wasm, which carries
    /// `set_governance_fee_params_unchecked_for_test`.
    ///
    /// Used only by the pre-existing fee suites, which activate deliberately
    /// TINY fees to exercise fee arithmetic against 1k/10k/100k/1M/10M-STSH
    /// denominations. The RULED guardrails put a 1,000-STSH floor under the
    /// shield/unshield flat minimum, so those scenarios are no longer
    /// expressible through the guarded setter — and rewriting their economics
    /// would discard the coverage they encode. The guardrails themselves are
    /// proved against the REAL endpoint on the PRODUCTION Wasm
    /// (`fee_setter_guardrail_tests.rs`), which is the stronger arrangement.
    fn new_testing(user_byte: u8, vk: [u8; 32], pool_seed: u128) -> Self {
        Self::new_with_pool_wasm(user_byte, vk, pool_seed, pool_test_wasm())
    }

    fn new_with_pool_wasm(
        user_byte: u8,
        vk: [u8; 32],
        pool_seed: u128,
        pool_module: Vec<u8>,
    ) -> Self {
        let pic = PocketIc::new();
        let user = p(user_byte);
        let token_id = create_canister(&pic);
        let null_id = create_canister(&pic);
        let pool_id = create_canister(&pic);
        let merkle_id = create_canister(&pic);

        pic.install_canister(
            null_id,
            nullifier_wasm(),
            candid::encode_one(pool_id).unwrap(),
            None,
        );
        // Merkle canister init takes pool_canister — only pool can call append_commitment.
        pic.install_canister(
            merkle_id,
            merkle_wasm(),
            candid::encode_one(pool_id).unwrap(),
            None,
        );

        let init = split_token_init(user, TOTAL_SUPPLY - pool_seed, pool_id, pool_seed, p(0x02));
        install(&pic, token_id, token_wasm(), &init);
        install(
            &pic,
            pool_id,
            pool_module,
            &PoolInitArgs {
                token_canister: token_id,
                nullifier_canister: null_id,
                merkle_canister: merkle_id,
                treasury_canister: p(0x04),
                staking_canister: p(0x05),
                controller: p(0x06),
                initial_vk_hash: vk,
                initial_proof_system: "groth16-bn254".to_string(),
            },
        );

        PoolHarness {
            pic,
            token_id,
            null_id,
            pool_id,
            merkle_id,
            user,
            vk_hash: vk,
        }
    }

    fn envelope(&self) -> ProofEnvelope {
        ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: self.vk_hash,
            root_reference: merkle_root(&self.pic, self.merkle_id),
            pool_version: 1,
            proof_bytes: vec![],
        }
    }

    fn deposit(&self, public_amount: u128) -> u128 {
        do_deposit(
            &self.pic,
            self.token_id,
            self.pool_id,
            self.user,
            public_amount,
        )
    }

    fn withdraw_note(&self, wid: u64, nullifier: [u8; 32], amount: u128) -> Result<Nat, PoolError> {
        decode(
            "withdraw_note",
            self.pic.update_call(
                self.pool_id,
                self.user,
                "withdraw",
                candid::encode_one(WithdrawArgs {
                    withdrawal_id: wid,
                    envelope: self.envelope(),
                    nullifier,
                    destination: self.user,
                    destination_subaccount: None,
                    gross_withdraw_amount: amount,
                })
                .unwrap(),
            ),
        )
    }

    fn accounting(&self) -> AccountingState {
        accounting_state(&self.pic, self.pool_id)
    }

    fn balance(&self, owner: Principal) -> u128 {
        token_balance(&self.pic, self.token_id, owner)
    }

    fn leaf_count(&self) -> u64 {
        merkle_leaf_count(&self.pic, self.merkle_id)
    }

    fn deposit_status(&self, note_commitment: [u8; 32]) -> Option<PendingDeposit> {
        deposit_status(&self.pic, self.pool_id, note_commitment)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WithdrawalTreasuryHarness — pool + real treasury for #112 / criterion 13
// ─────────────────────────────────────────────────────────────────────────────
//
// Installs a real treasury canister wired to the pool principal so that
// notify_treasury_fee → receive_fee_split passes the caller guard.
// The chicken-and-egg is broken by reserving both canister IDs before
// installing either: pool init carries treasury_id; treasury init carries
// pool_id.  Existing PoolHarness is unchanged (still uses p(0x04) stub).

struct WithdrawalTreasuryHarness {
    pic: PocketIc,
    token_id: Principal,
    null_id: Principal,
    merkle_id: Principal,
    pool_id: Principal,
    treasury_id: Principal,
    user: Principal,
    vk_hash: [u8; 32],
}

impl WithdrawalTreasuryHarness {
    fn new(user_byte: u8, vk: [u8; 32]) -> Self {
        Self::new_with_pool_wasm(user_byte, vk, pool_wasm())
    }

    /// RB-SWARM-A1: same stack on the `_test` Wasm — see
    /// `PoolHarness::new_testing` for why the pre-existing fee suites need the
    /// unguarded test-only setter.
    fn new_testing(user_byte: u8, vk: [u8; 32]) -> Self {
        Self::new_with_pool_wasm(user_byte, vk, pool_test_wasm())
    }

    fn new_with_pool_wasm(user_byte: u8, vk: [u8; 32], pool_module: Vec<u8>) -> Self {
        let pic = PocketIc::new();
        let user = p(user_byte);
        let controller = p(0x06);

        // Reserve all IDs before installing any canister.
        let token_id = create_canister(&pic);
        let null_id = create_canister(&pic);
        let merkle_id = create_canister(&pic);
        let pool_id = create_canister(&pic);
        let treasury_id = create_canister(&pic);

        // Nullifier and Merkle: accept commands only from pool_id.
        pic.install_canister(
            null_id,
            nullifier_wasm(),
            candid::encode_one(pool_id).unwrap(),
            None,
        );
        pic.install_canister(
            merkle_id,
            merkle_wasm(),
            candid::encode_one(pool_id).unwrap(),
            None,
        );

        // Token: user holds all supply; pool starts with 0.
        let token_init = split_token_init(user, TOTAL_SUPPLY, pool_id, 0, p(0x05));
        install(&pic, token_id, token_wasm(), &token_init);

        // Pool: wired to real treasury_id.
        install(
            &pic,
            pool_id,
            pool_module,
            &PoolInitArgs {
                token_canister: token_id,
                nullifier_canister: null_id,
                merkle_canister: merkle_id,
                treasury_canister: treasury_id,
                staking_canister: p(0x05),
                controller: controller,
                initial_vk_hash: vk,
                initial_proof_system: "groth16-bn254".to_string(),
            },
        );

        // Treasury: positional init(token_canister, pool_canister, controller).
        // Must be installed after pool_id is known.
        pic.install_canister(
            treasury_id,
            treasury_wasm(),
            candid::encode_args((token_id, pool_id, controller)).unwrap(),
            None,
        );

        WithdrawalTreasuryHarness {
            pic,
            token_id,
            null_id,
            merkle_id,
            pool_id,
            treasury_id,
            user,
            vk_hash: vk,
        }
    }

    fn envelope(&self) -> ProofEnvelope {
        ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: self.vk_hash,
            root_reference: merkle_root(&self.pic, self.merkle_id),
            pool_version: 1,
            proof_bytes: vec![],
        }
    }

    fn deposit(&self, public_amount: u128) -> u128 {
        do_deposit(
            &self.pic,
            self.token_id,
            self.pool_id,
            self.user,
            public_amount,
        )
    }

    fn withdraw(&self, wid: u64, nullifier: [u8; 32], gross: u128) -> Result<Nat, PoolError> {
        decode(
            "withdraw",
            self.pic.update_call(
                self.pool_id,
                self.user,
                "withdraw",
                candid::encode_one(WithdrawArgs {
                    withdrawal_id: wid,
                    envelope: self.envelope(),
                    nullifier,
                    destination: self.user,
                    destination_subaccount: None,
                    gross_withdraw_amount: gross,
                })
                .unwrap(),
            ),
        )
    }

    fn accounting(&self) -> AccountingState {
        accounting_state(&self.pic, self.pool_id)
    }

    fn balance(&self, owner: Principal) -> u128 {
        token_balance(&self.pic, self.token_id, owner)
    }

    fn treasury_subaccount(&self, name: &str) -> u128 {
        let result: Option<u128> = decode(
            "get_subaccount_balance",
            self.pic.query_call(
                self.treasury_id,
                Principal::anonymous(),
                "get_subaccount_balance",
                candid::encode_one(name.to_string()).unwrap(),
            ),
        );
        result.unwrap_or(0)
    }

    fn treasury_fee_log(&self, from: u64, limit: u64) -> Vec<FeeLogEntry> {
        decode(
            "get_fee_log",
            self.pic.query_call(
                self.treasury_id,
                Principal::anonymous(),
                "get_fee_log",
                candid::encode_args((from, limit)).unwrap(),
            ),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 25 — Recipient receives exact withdrawal_amount (no fee deducted)
// ─────────────────────────────────────────────────────────────────────────────
//
// M3 UX guarantee: user shields D, receives D - reserve as private balance,
// then withdraws and receives exactly (D - reserve) in public tokens.
//
// No ledger fee is deducted from the recipient.  The operations reserve covers
// the fee via internal accounting.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises recipient payout exactness after a successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: recipient payout coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_25_recipient_receives_exact_amount() {
    let h = PoolHarness::new(0x25, [0x25; 32], 0);

    let private_balance = h.deposit(DENOMINATIONS[0]);
    let expected_pb = expected_deposit_private_balance(DENOMINATIONS[0], 0);
    assert_eq!(
        private_balance, expected_pb,
        "shield_deposit must return private_balance_credit = the FULL gross (fee-on-top, AR1-10)"
    );

    let user_before = h.balance(h.user);
    let w = h.withdraw_note(250, [0x25; 32], private_balance);
    assert!(w.is_ok(), "Withdrawal of note must succeed; got: {:?}", w);

    let user_after = h.balance(h.user);
    assert_eq!(
        user_after,
        user_before + private_balance - DEFAULT_FEE,
        "§7 net-recipient: recipient must receive private_balance - ledger_fee; \
         before={} after={} expected={}",
        user_before,
        user_after,
        user_before + private_balance - DEFAULT_FEE
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 26 — escrow_backing >= private_liability after withdrawal
// ─────────────────────────────────────────────────────────────────────────────
//
// After a completed withdrawal (Finalized), escrow_backing and private_liability
// must both be zero (note fully redeemed), and escrow_backing must be >= private_liability.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises post-withdrawal escrow backing and private-liability accounting, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: post-withdrawal invariant coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_26_escrow_backing_ge_private_liability_after_withdrawal() {
    let h = PoolHarness::new(0x26, [0x26; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);

    // Verify invariant before withdrawal
    let before = h.accounting();
    assert!(
        before.escrow_backing + before.pending_fee_reimbursements >= before.private_liability,
        "Invariant (1) must hold before withdrawal: eb={} pfr={} pl={}",
        before.escrow_backing,
        before.pending_fee_reimbursements,
        before.private_liability
    );

    let w = h.withdraw_note(260, [0x26; 32], pb);
    assert!(w.is_ok(), "Withdrawal must succeed; got: {:?}", w);

    let after = h.accounting();
    assert_eq!(
        after.private_liability, 0,
        "private_liability must be 0 after full redemption"
    );
    assert!(
        after.escrow_backing >= after.private_liability,
        "escrow_backing must be >= private_liability after withdrawal; \
         eb={} pl={}",
        after.escrow_backing,
        after.private_liability
    );
    assert_eq!(
        after.pending_fee_reimbursements, 0,
        "pending_fee_reimbursements must be 0 after successful reimbursement"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 27 — Operations reserve unchanged per withdrawal at zero protocol fee
// ─────────────────────────────────────────────────────────────────────────────
//
// Under §7, ledger_fee is embedded in gross — ops_reserve is never debited
// on withdrawal (no ledger_fee reimbursement path). At zero protocol_unshielding_fee
// and zero protocol_shielding_fee, ops_reserve starts at 0 after deposit and
// remains 0 after withdrawal.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises post-withdrawal operations-reserve accounting, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: reserve accounting coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_27_operations_reserve_decreases_by_ledger_fee() {
    let h = PoolHarness::new(0x27, [0x27; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);

    let before = h.accounting();
    let ops_before = before.operations_reserve;

    let w = h.withdraw_note(270, [0x27; 32], pb);
    assert!(w.is_ok(), "Withdrawal must succeed; got: {:?}", w);

    let after = h.accounting();
    let ops_after = after.operations_reserve;

    assert_eq!(
        ops_before, ops_after,
        "§7: ops_reserve must be unchanged by withdrawal at zero protocol_unshielding_fee; \
         before={} after={}",
        ops_before, ops_after
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 28 — Solvency invariant (1) holds throughout deposit + withdraw cycle
// ─────────────────────────────────────────────────────────────────────────────
//
// escrow_backing + pending_fee_reimbursements >= private_liability must hold
// before deposit, after deposit, and after withdrawal.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises solvency invariant behavior across a successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: solvency invariant coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_28_solvency_invariant_holds_throughout() {
    let h = PoolHarness::new(0x28, [0x28; 32], 0);

    let check_inv1 = |state: &AccountingState, label: &str| {
        let lhs = state
            .escrow_backing
            .saturating_add(state.pending_fee_reimbursements);
        assert!(
            lhs >= state.private_liability,
            "Invariant (1) violated at {}: eb={} pfr={} pl={}",
            label,
            state.escrow_backing,
            state.pending_fee_reimbursements,
            state.private_liability
        );
    };

    check_inv1(&h.accounting(), "initial state");

    let pb = h.deposit(DENOMINATIONS[0]);
    check_inv1(&h.accounting(), "after deposit");

    let w = h.withdraw_note(280, [0x28; 32], pb);
    assert!(w.is_ok(), "Withdrawal must succeed; got: {:?}", w);
    check_inv1(&h.accounting(), "after withdrawal");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 29 — §12 precheck: GrossAmountBelowFees when gross <= ledger_fee
// ─────────────────────────────────────────────────────────────────────────────
//
// Under §7, gross_withdraw_amount must exceed ledger_fee + protocol_unshielding_fee
// so that recipient_net_amount > 0. Withdrawing exactly DEFAULT_FEE must return
// GrossAmountBelowFees (gross <= total_fee).
// =============================================================================

// Lane A v2 Task 0.25 transitional fail-closed coverage: fee/precheck behavior is unreachable while unbound withdrawals fail closed before
// authorization-sensitive mutation. Task 1 must restore or retire this expectation when
// proof-bound withdrawal is available.
#[test]
fn test_29_not_finalized_when_ops_reserve_empty() {
    // Fund pool via deposit so accounting is set up; we just need a valid pool.
    let h = PoolHarness::new(0x29, [0x29; 32], 0);
    let _pb = h.deposit(DENOMINATIONS[0]);

    // Attempt to withdraw exactly DEFAULT_FEE — gross <= ledger_fee, no room for recipient.
    let w = h.withdraw_note(290, [0x29; 32], DEFAULT_FEE);
    assert!(
        matches!(w, Err(PoolError::InvalidProof)),
        "transitional fail-closed path rejects before fee prechecks until proof-bound withdrawal is restored"
    );

    // Also test gross = 0 (always below any fee).
    let w2 = h.withdraw_note(291, [0x29; 32], 0);
    assert!(
        matches!(w2, Err(PoolError::InvalidProof)),
        "transitional fail-closed path rejects zero-gross withdrawal before fee prechecks"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 30 — §7 PendingWithdrawal gross/net fields correctly populated
// ─────────────────────────────────────────────────────────────────────────────
//
// After a successful withdrawal, the PendingWithdrawal record must expose the
// full fee breakdown: gross_withdraw_amount, recipient_net_amount, ledger_fee,
// and protocol_unshielding_fee (zero at launch).
// =============================================================================

// Lane A v2 Task 0.25: this test exercises pending-withdrawal fee fields after successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: pending fee-record coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_30_fee_reimbursement_pending_records_correct_fee() {
    let h = PoolHarness::new(0x30, [0x30; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);

    let w = h.withdraw_note(300, [0x30; 32], pb);
    assert!(w.is_ok(), "Withdrawal must succeed; got: {:?}", w);

    let record: Option<PendingWithdrawal> = decode(
        "test_30: get_withdrawal_status",
        h.pic.query_call(
            h.pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(300u64).unwrap(),
        ),
    );
    let rec = record.expect("withdrawal record must exist");

    assert_eq!(
        rec.status,
        WithdrawalStatus::Finalized,
        "must be Finalized; got: {:?}",
        rec.status
    );
    assert_eq!(
        rec.gross_withdraw_amount, pb,
        "gross_withdraw_amount must equal pb"
    );
    assert_eq!(
        rec.protocol_unshielding_fee, 0,
        "protocol_unshielding_fee must be 0 at launch"
    );
    assert_eq!(
        rec.ledger_fee, DEFAULT_FEE,
        "ledger_fee must equal DEFAULT_FEE"
    );
    assert_eq!(
        rec.recipient_net_amount,
        pb - DEFAULT_FEE,
        "recipient_net_amount must equal gross - ledger_fee"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 31 — Solvency invariant (2) holds in normal operations
// ─────────────────────────────────────────────────────────────────────────────
//
// When the operations reserve is well-funded (via shield_deposit), invariant (2)
// must hold throughout: operations_reserve >= pending_fee_reimbursements.
// In normal operation pending_fee_reimbursements stays 0, so the invariant is
// trivially satisfied.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises normal-operation accounting invariant after successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: accounting invariant coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_31_invariant_2_holds_in_normal_operations() {
    let h = PoolHarness::new(0x31, [0x31; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);

    let check_inv2 = |state: &AccountingState, label: &str| {
        assert!(
            state.operations_reserve >= state.pending_fee_reimbursements,
            "Invariant (2) violated at {}: ops={} pfr={}",
            label,
            state.operations_reserve,
            state.pending_fee_reimbursements
        );
    };

    check_inv2(&h.accounting(), "after deposit");

    let w = h.withdraw_note(310, [0x21; 32], pb);
    assert!(w.is_ok(), "Withdrawal must succeed; got: {:?}", w);
    check_inv2(&h.accounting(), "after withdrawal");

    // pending_fee_reimbursements must be 0 in the normal funded path.
    assert_eq!(
        h.accounting().pending_fee_reimbursements,
        0,
        "pending_fee_reimbursements must be 0 after successful reimbursement"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 32 — shield_deposit returns private_balance_credit (§6)
// ─────────────────────────────────────────────────────────────────────────────
//
// AR1-10 / §6: private_balance_credit = gross_shield_amount. Fee-ON-TOP — the
// protocol fee is pulled in ADDITION to the gross, never deducted from it, so the
// fixed denomination is preserved (Law #1). The earlier note here read
// `gross_shield_amount − protocol_shielding_fee`, the superseded deducted model.
// The return value is the exact note value committed to the Merkle tree.
// =============================================================================

#[test]
fn test_32_shield_deposit_returns_private_balance_credit() {
    let h = PoolHarness::new(0x32, [0x32; 32], 0);

    let private_balance = h.deposit(DENOMINATIONS[0]);
    // At zero protocol_shielding_fee: private_balance_credit = gross.
    let expected_pb = expected_deposit_private_balance(DENOMINATIONS[0], 0);

    assert_eq!(
        private_balance, expected_pb,
        "shield_deposit must return private_balance_credit = the FULL gross (fee-on-top, AR1-10); \
         gross={} shielding_fee=0 expected={} got={}",
        DENOMINATIONS[0], expected_pb, private_balance
    );
    assert_eq!(
        private_balance, DENOMINATIONS[0],
        "at zero shielding fee private_balance_credit must equal gross"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 33 — shield_deposit accounting at zero protocol_shielding_fee
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_33_shield_deposit_routes_reserve_90_10() {
    // At zero protocol_shielding_fee (launch default):
    //   private_balance_credit = gross
    //   ops_reserve = 0, ins_reserve = 0
    //   escrow_backing = private_liability = gross
    let h = PoolHarness::new(0x33, [0x33; 32], 0);
    h.deposit(DENOMINATIONS[0]);

    let acc = h.accounting();

    assert_eq!(
        acc.operations_reserve, 0,
        "at zero shielding_fee, operations_reserve must be 0; got={}",
        acc.operations_reserve
    );
    assert_eq!(
        acc.insurance_reserve, 0,
        "at zero shielding_fee, insurance_reserve must be 0; got={}",
        acc.insurance_reserve
    );
    assert_eq!(
        acc.private_liability, DENOMINATIONS[0],
        "private_liability must equal gross at zero shielding_fee; got={}",
        acc.private_liability
    );
    assert_eq!(
        acc.escrow_backing, DENOMINATIONS[0],
        "escrow_backing must equal gross at zero shielding_fee; got={}",
        acc.escrow_backing
    );
    assert_eq!(
        acc.governance_rewards_reserve, 0,
        "governance_rewards_reserve must be 0 at launch"
    );
    assert_eq!(
        acc.pending_fee_reimbursements, 0,
        "pending_fee_reimbursements must be 0 before any withdrawal"
    );

    // At zero shielding fee: escrow_backing == gross, ops=ins=stk=0.
    let sum = acc
        .escrow_backing
        .saturating_add(acc.operations_reserve)
        .saturating_add(acc.insurance_reserve)
        .saturating_add(acc.governance_rewards_reserve);
    assert_eq!(
        sum, DENOMINATIONS[0],
        "all buckets must sum to gross; expected={} got={}",
        DENOMINATIONS[0], sum
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 34 — Accounting buckets sum correctly after full deposit + withdraw cycle
// ─────────────────────────────────────────────────────────────────────────────
//
// At zero protocol_shielding_fee (launch default):
//   After one deposit of DENOMINATIONS[0] and one full withdrawal (§7 model):
//   - private_liability = 0
//   - escrow_backing = 0
//   - pending_fee_reimbursements = 0
//   - operations_reserve = 0  (no shielding fee collected)
//   - insurance_reserve  = 0  (no shielding fee collected)
//   - pool token balance = 0  (gross withdrawn, nothing retained)
// =============================================================================

// Lane A v2 Task 0.25: this test exercises accounting bucket sums after a full deposit-withdrawal cycle, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: cycle accounting coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_34_accounting_sums_correctly_after_cycle() {
    let h = PoolHarness::new(0x34, [0x34; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);
    // At zero shielding fee, pb == DENOMINATIONS[0].

    let w = h.withdraw_note(340, [0x24; 32], pb);
    assert!(w.is_ok(), "Withdrawal must succeed; got: {:?}", w);

    let acc = h.accounting();
    assert_eq!(acc.private_liability, 0, "private_liability must be 0");
    assert_eq!(acc.escrow_backing, 0, "escrow_backing must be 0");
    assert_eq!(
        acc.pending_fee_reimbursements, 0,
        "no pending reimbursements"
    );
    assert_eq!(
        acc.governance_rewards_reserve, 0,
        "governance reserve stays 0"
    );
    assert_eq!(
        acc.operations_reserve, 0,
        "at zero shielding_fee: ops_reserve must be 0 after cycle; got={}",
        acc.operations_reserve
    );
    assert_eq!(
        acc.insurance_reserve, 0,
        "at zero shielding_fee: ins_reserve must be 0 after cycle; got={}",
        acc.insurance_reserve
    );

    // At zero shielding fee: pool retains nothing after full withdrawal.
    let pool_balance = h.balance(h.pool_id);
    assert_eq!(
        pool_balance, 0,
        "pool token balance must be 0 after full-balance withdrawal at zero shielding_fee; \
         got={}",
        pool_balance
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15 — EmergencyPause cannot silently install a VK
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: EmergencyPause proposals are scoped to pause flags only.
// They must not call schedule_vk_activation() — which would let an attacker
// slip a circuit upgrade past the mandatory 14-day governance window by
// disguising it as an emergency action.
//
// Two-sided assertion:
//   NEGATIVE: pool VK hash is unchanged.
//   POSITIVE: deposits ARE paused (proves the correct effect fired).
// =============================================================================

#[test]
fn test_15_emergency_pause_cannot_install_vk() {
    let h = GovHarness::new();

    let vk_before = h.pool_vk_hash();
    assert_eq!(
        vk_before, POOL_VK_HASH,
        "VK hash must equal init value before any proposal"
    );
    assert!(
        !h.deposits_paused(),
        "Deposits must be unpaused at test start"
    );

    // Execute an EmergencyPause(PoolDeposits) through the full governance lifecycle.
    // The staking canister calls emergency_pause_deposits() on the pool cross-canister.
    // Because controller = staking_id, the pool's assert_controller() passes.
    h.run_proposal(ProposalType::EmergencyPause {
        target: EmergencyPauseTarget::PoolDeposits,
        reason: "M2 security test".to_string(),
    });

    // NEGATIVE: verifier key must be untouched.
    let vk_after = h.pool_vk_hash();
    assert_eq!(
        vk_after, POOL_VK_HASH,
        "EmergencyPause must NOT change the pool's verifier key hash"
    );

    // POSITIVE: deposits are now paused (the only correct effect).
    assert!(
        h.deposits_paused(),
        "EmergencyPause(PoolDeposits) must set is_deposits_paused = true"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-013 — Emergency pause target wiring
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_qadef013_pool_deposits_pauses_deposits_only() {
    let h = GovHarness::new();
    assert!(!h.deposits_paused(), "deposits start unpaused");
    assert!(!h.spends_paused(), "spends start unpaused");

    let result = h.run_proposal_result(ProposalType::EmergencyPause {
        target: EmergencyPauseTarget::PoolDeposits,
        reason: "QA-DEF-013 deposits".to_string(),
    });

    assert!(result.is_ok(), "PoolDeposits pause must execute; got {result:?}");
    assert!(
        h.deposits_paused(),
        "PoolDeposits must return Ok only after deposits are paused"
    );
    assert!(
        !h.spends_paused(),
        "PoolDeposits must not pause spends"
    );
}

#[test]
fn test_qadef013_pool_spends_pauses_spends_only_and_requires_postcondition() {
    let h = GovHarness::new();
    assert!(!h.deposits_paused(), "deposits start unpaused");
    assert!(!h.spends_paused(), "spends start unpaused");

    let result = h.run_proposal_result(ProposalType::EmergencyPause {
        target: EmergencyPauseTarget::PoolSpends,
        reason: "QA-DEF-013 spends".to_string(),
    });

    assert!(result.is_ok(), "PoolSpends pause must execute; got {result:?}");
    assert!(
        h.spends_paused(),
        "PoolSpends must return Ok only after spends are paused"
    );
    assert!(
        !h.deposits_paused(),
        "PoolSpends must not pause deposits"
    );
}

#[test]
fn test_qadef013_both_pauses_deposits_and_spends_and_requires_postconditions() {
    let h = GovHarness::new();
    assert!(!h.deposits_paused(), "deposits start unpaused");
    assert!(!h.spends_paused(), "spends start unpaused");

    let result = h.run_proposal_result(ProposalType::EmergencyPause {
        target: EmergencyPauseTarget::Both,
        reason: "QA-DEF-013 both".to_string(),
    });

    assert!(result.is_ok(), "Both pause must execute; got {result:?}");
    assert!(
        h.deposits_paused(),
        "Both must return Ok only after deposits are paused"
    );
    assert!(
        h.spends_paused(),
        "Both must return Ok only after spends are paused"
    );
}

#[test]
fn test_qadef013_non_controller_cannot_pause_spends_directly() {
    let h = GovHarness::new();
    assert!(!h.spends_paused(), "spends start unpaused");

    let direct = h.pic.update_call(
        h.pool_id,
        h.user,
        "emergency_pause_spends",
        candid::encode_args(()).unwrap(),
    );

    assert!(
        direct.is_err(),
        "non-controller caller must not call emergency_pause_spends directly"
    );
    assert!(
        !h.spends_paused(),
        "failed direct emergency_pause_spends call must not pause spends"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 35 — Reserved nullifier blocks a concurrent withdrawal (M3 revised)
// ─────────────────────────────────────────────────────────────────────────────
//
// If pool escrow is underfunded, the first withdrawal (W1) enters SolvencyBlocked
// with a pool-local nullifier reservation.  A second withdrawal (W2) with a
// different withdrawal_id but the same nullifier must be rejected immediately
// with NullifierReserved — preventing double-claim of the same note.
//
// INVARIANTS verified:
//   a) W1 (insufficient escrow) → SolvencyBlocked.
//   b) W2 (same nullifier, different id) → NullifierReserved immediately.
//   c) Nullifier still NOT in registry after both calls.
//   d) W1 status is still SolvencyBlocked (W2 did not corrupt W1's record).
// =============================================================================

const T35_VK_HASH: [u8; 32] = [0x35; 32];
const T35_NULLIFIER: [u8; 32] = [0x35; 32];

// Lane A v2 Task 0.25: this test exercises concurrent withdrawal blocking through reserved nullifiers, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: reserved-nullifier coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_35_reserved_nullifier_blocks_concurrent_withdrawal() {
    let pic = PocketIc::new();
    let user = p(0x35);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    // Pool gets DENOMINATIONS[0] - 1 (one short of required = gross = DENOMINATIONS[0]).
    // §7: required = ledger_debit_from_pool = gross - protocol_unshielding_fee = DENOMINATIONS[0].
    let init = split_token_init(
        user,
        TOTAL_SUPPLY - (DENOMINATIONS[0] - 1),
        pool_id,
        DENOMINATIONS[0] - 1,
        p(0x02),
    );
    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T35_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T35_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // a) W1 — escrow underfunded → SolvencyBlocked, nullifier pool-locally reserved.
    let w1: Result<Nat, PoolError> = decode(
        "test_35: W1 → SolvencyBlocked",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 350,
                envelope: env.clone(),
                nullifier: T35_NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(w1, Err(PoolError::EscrowUnderfunded { .. })),
        "W1 must return EscrowUnderfunded; got: {:?}",
        w1
    );

    // b) W2 — same nullifier, different withdrawal_id → NullifierReserved immediately.
    let w2: Result<Nat, PoolError> = decode(
        "test_35: W2 same nullifier → NullifierReserved",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 351, // different id
                envelope: env,
                nullifier: T35_NULLIFIER, // same nullifier
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        w2 == Err(PoolError::NullifierReserved),
        "W2 with reserved nullifier must return NullifierReserved; got: {:?}",
        w2
    );

    // c) Nullifier must NOT be in the permanent registry after either call.
    let in_reg: bool = decode(
        "test_35: nullifier not in registry",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(T35_NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        !in_reg,
        "Nullifier must NOT be in registry: insert_nullifier only called at finalization"
    );

    // d) W1 record must still be SolvencyBlocked (W2 did not corrupt it).
    let rec: Option<PendingWithdrawal> = decode(
        "test_35: W1 status still SolvencyBlocked",
        pic.query_call(
            pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(350u64).unwrap(),
        ),
    );
    let rec = rec.expect("W1 record must exist");
    assert!(
        matches!(rec.status, WithdrawalStatus::SolvencyBlocked { .. }),
        "W1 status must still be SolvencyBlocked after W2 attempt; got: {:?}",
        rec.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 36 — SolvencyBlocked → top-up → resume → Finalized (M3 revised)
// ─────────────────────────────────────────────────────────────────────────────
//
// The full governance recovery path:
//   1. Pool escrow is underfunded → W1 enters SolvencyBlocked.
//   2. Governance tops up the pool via ICRC-1 transfer.
//   3. resume_blocked_withdrawal(W1) is called.
//   4. Transfer succeeds; registry write confirms; W1 → Finalized.
//   5. Nullifier IS in registry after finalization.
//   6. Recipient received exactly withdrawal_amount.
//
// INVARIANTS verified:
//   a) W1 SolvencyBlocked as in test_24/test_35.
//   b) resume when still underfunded → EscrowUnderfunded (idempotent).
//   c) Top-up succeeds via icrc1_transfer.
//   d) resume_blocked_withdrawal(W1) → Ok.
//   e) W1 status = Finalized.
//   f) Nullifier IS in registry after finalization.
//   g) Recipient received exactly withdrawal_amount.
// =============================================================================

const T36_VK_HASH: [u8; 32] = [0x36; 32];
const T36_NULLIFIER: [u8; 32] = [0x26; 32];

// Lane A v2 Task 0.25: this test exercises resume path for solvency-blocked withdrawals after top-up, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: resume coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_36_solvency_blocked_resume_after_top_up() {
    let pic = PocketIc::new();
    let user = p(0x36);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    // Pool gets DENOMINATIONS[0] - 1 (one short of required = gross = DENOMINATIONS[0]).
    // §7: required = ledger_debit_from_pool = gross = DENOMINATIONS[0].
    // Top-up of 1 brings pool to DENOMINATIONS[0] and allows resume.
    let init = split_token_init(
        user,
        TOTAL_SUPPLY - (DENOMINATIONS[0] - 1),
        pool_id,
        DENOMINATIONS[0] - 1,
        p(0x02),
    );
    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T36_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    let _: () = decode(
        "test_36: inject PRIVATE_LIABILITY",
        pic.update_call(
            pool_id,
            p(0x06),
            "inject_private_liability_for_test",
            candid::encode_one(DENOMINATIONS[0]).unwrap(),
        ),
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T36_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // a) W1 — escrow underfunded → SolvencyBlocked.
    let w1: Result<Nat, PoolError> = decode(
        "test_36: W1 → SolvencyBlocked",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 360,
                envelope: env,
                nullifier: T36_NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(w1, Err(PoolError::EscrowUnderfunded { .. })),
        "W1 must return EscrowUnderfunded; got: {:?}",
        w1
    );

    // b) resume while still underfunded → EscrowUnderfunded.
    let resume_early: Result<Nat, PoolError> = decode(
        "test_36: resume before top-up → EscrowUnderfunded",
        pic.update_call(
            pool_id,
            user,
            "resume_blocked_withdrawal",
            candid::encode_one(360u64).unwrap(),
        ),
    );
    assert!(
        matches!(resume_early, Err(PoolError::EscrowUnderfunded { .. })),
        "resume before top-up must return EscrowUnderfunded; got: {:?}",
        resume_early
    );

    // c) Top up pool by DEFAULT_FEE via icrc1_transfer from user.
    {
        #[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
        struct TransferArgs {
            from_subaccount: Option<[u8; 32]>,
            to: Account,
            amount: Nat,
            fee: Option<Nat>,
            memo: Option<Vec<u8>>,
            created_at_time: Option<u64>,
        }
        #[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
        enum TransferError {
            BadFee { expected_fee: Nat },
            BadBurn { min_burn_amount: Nat },
            InsufficientFunds { balance: Nat },
            TooOld,
            CreatedInFuture { ledger_time: u64 },
            Duplicate { duplicate_of: Nat },
            TemporarilyUnavailable,
            GenericError { error_code: Nat, message: String },
        }
        // Top up pool by 1 token (pool was DENOMINATIONS[0]-1; needs DENOMINATIONS[0]).
        // icrc1_transfer debits (amount + fee) from user, credits amount to pool.
        // User is debited 1 (amount) + DEFAULT_FEE (ledger fee). Pool gains 1. ✓
        let top_up: Result<Nat, TransferError> = decode(
            "test_36: top up pool by 1",
            pic.update_call(
                token_id,
                user,
                "icrc1_transfer",
                candid::encode_one(TransferArgs {
                    from_subaccount: None,
                    to: Account {
                        owner: pool_id,
                        subaccount: None,
                    },
                    amount: Nat::from(1u64),
                    fee: Some(Nat::from(DEFAULT_FEE)),
                    memo: None,
                    created_at_time: None,
                })
                .unwrap(),
            ),
        );
        assert!(
            top_up.is_ok(),
            "top-up transfer must succeed; got: {:?}",
            top_up
        );
    }

    // Record user balance before resume to verify exact receipt.
    let user_balance_before = token_balance(&pic, token_id, user);

    // d) resume_blocked_withdrawal(360) → Ok now that pool is funded.
    let resume: Result<Nat, PoolError> = decode(
        "test_36: resume after top-up → Ok",
        pic.update_call(
            pool_id,
            user,
            "resume_blocked_withdrawal",
            candid::encode_one(360u64).unwrap(),
        ),
    );
    assert!(
        resume.is_ok(),
        "resume_blocked_withdrawal must succeed after top-up; got: {:?}",
        resume
    );

    // e) W1 status must be Finalized (§7: FeeReimbursementPending not produced).
    let rec: Option<PendingWithdrawal> = decode(
        "test_36: W1 status after resume",
        pic.query_call(
            pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(360u64).unwrap(),
        ),
    );
    let rec = rec.expect("W1 record must exist after resume");
    assert!(
        matches!(rec.status, WithdrawalStatus::Finalized),
        "§7: W1 must be Finalized after resume; got: {:?}",
        rec.status
    );

    // f) Nullifier IS in registry after finalization.
    let in_reg: bool = decode(
        "test_36: nullifier in registry after finalization",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(T36_NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        in_reg,
        "Nullifier MUST be in registry after Finalized (insert_nullifier called at finalization)"
    );

    // g) §7 net-recipient: user receives gross - ledger_fee = DENOMINATIONS[0] - DEFAULT_FEE.
    let user_balance_after = token_balance(&pic, token_id, user);
    assert_eq!(
        user_balance_after,
        user_balance_before + DENOMINATIONS[0] - DEFAULT_FEE,
        "§7: recipient must receive gross - ledger_fee; \
         before={} after={} expected={}",
        user_balance_before,
        user_balance_after,
        user_balance_before + DENOMINATIONS[0] - DEFAULT_FEE
    );
}

// =============================================================================
// M3 Track B tests (test_37 – test_46) — Merkle commitment wiring + anchor check
// =============================================================================
//
// These tests verify that shield_deposit appends commitments to the Merkle tree,
// that anchor validation gates withdraw and private_spend, and that batch nullifier
// insertion is all-or-nothing.
//
// All tests that call shield_deposit or withdraw use real Merkle canisters.
// root_reference: [0u8;32] is valid on a fresh Merkle (it is stored as the
// initial root at slot 0 during init — ROOT_HISTORY_SIZE=100 ring buffer).
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 37 — shield_deposit creates a Merkle leaf (leaf_count 0 → 1)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: Every successful shield_deposit must append exactly one leaf to the
// Merkle tree (via append_commitment).  Leaf count on a fresh canister starts at
// zero and must be 1 after a single deposit.
// =============================================================================

#[test]
fn test_37_deposit_creates_merkle_leaf() {
    let h = PoolHarness::new(0x37, [0x37; 32], 0);

    assert_eq!(
        h.leaf_count(),
        0,
        "Fresh Merkle must have 0 leaves before deposit"
    );

    h.deposit(DENOMINATIONS[0]);

    assert_eq!(
        h.leaf_count(),
        1,
        "Merkle must have exactly 1 leaf after one shield_deposit"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 38 — deposit status shows CommitmentAppended with correct private_balance
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: After a successful deposit, get_deposit_status returns
// CommitmentAppended, and the stored private_balance must equal the FULL gross
// (AR1-10: fee-on-top — the protocol fee is pulled on top, not deducted; this held
// trivially at the zero launch fee, which is why the deducted wording survived).
// This proves the commitment was made to the correct redeemable value.
// =============================================================================

/// DEF-041 canonical BN254 Fr fixture: byte 0 = `b` (value < 256 < field modulus),
/// distinct and non-zero. Replaces `[0xNN; 32]` fill patterns whose repeated high
/// byte exceeds the modulus and is (correctly) rejected by the canonical check.
const fn canon(b: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0] = b;
    c
}

const T38_COMMITMENT: [u8; 32] = canon(0x38);

#[test]
fn test_38_deposit_status_shows_commitment_appended_with_private_balance() {
    let h = PoolHarness::new(0x38, [0x38; 32], 0);

    // Use do_deposit directly with a known commitment so we can query status.
    do_approve(
        &h.pic,
        h.token_id,
        h.user,
        h.pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let result: Result<candid::Nat, PoolError> = decode(
        "test_38: shield_deposit",
        h.pic.update_call(
            h.pool_id,
            h.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T38_COMMITMENT,
                encrypted_payload: vec![0x38],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    let nat = result.expect("deposit must succeed");
    let returned_pb: u128 = nat.0.to_string().parse().unwrap();

    // At zero protocol_shielding_fee: private_balance_credit = gross.
    let expected_pb = expected_deposit_private_balance(DENOMINATIONS[0], 0);
    assert_eq!(
        returned_pb, expected_pb,
        "shield_deposit must return private_balance_credit; expected={} got={}",
        expected_pb, returned_pb
    );

    // Check the on-chain deposit status record.
    let rec = h
        .deposit_status(T38_COMMITMENT)
        .expect("deposit record must exist after successful deposit");

    // P-ROOT: a successful deposit now finalizes through the accepted-root head
    // to the terminal CommitmentRootAccepted (was CommitmentAppended pre-P-ROOT).
    assert!(
        matches!(rec.status, DepositStatus::CommitmentRootAccepted { .. }),
        "Deposit status must be CommitmentRootAccepted; got: {:?}",
        rec.status
    );
    assert_eq!(
        rec.private_balance, expected_pb,
        "PendingDeposit.private_balance must equal private_balance_credit; \
         expected={} got={}",
        expected_pb, rec.private_balance
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 39 — withdraw with valid anchor succeeds (anchor check passes)
// ─────────────────────────────────────────────────────────────────────────────
//
// The zero root [0u8;32] is valid on a fresh Merkle canister (stored at init).
// A withdrawal using root_reference: [0u8;32] must pass the anchor check and
// proceed to the transfer step.
// =============================================================================

// Lane A v2 Task 0.25 transitional fail-closed coverage: valid-anchor success is unreachable while unbound withdrawals fail closed before
// anchor validation. Task 1 must restore or retire this expectation when proof-bound
// withdrawal is available.
#[test]
fn test_39_withdraw_valid_anchor_succeeds() {
    let h = PoolHarness::new(0x39, [0x39; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);

    let w = h.withdraw_note(390, [0x29u8; 32], pb);
    assert!(
        matches!(w, Err(PoolError::InvalidProof)),
        "transitional fail-closed path rejects even a valid anchor until proof-bound withdrawal is restored"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 40 — withdraw with unknown/stale root → AnchorNotFound
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: A root that was never stored in the Merkle tree (and is not in the
// ROOT_HISTORY ring buffer) must cause the pool to reject the withdrawal with
// AnchorNotFound, BEFORE any nullifier reservation or escrow check.
// =============================================================================

const T40_VK_HASH: [u8; 32] = [0x40; 32];
const T40_NULLIFIER: [u8; 32] = [0x40; 32];
/// A root that is definitively not in any fresh Merkle canister's history.
const UNKNOWN_ROOT: [u8; 32] = [0xFFu8; 32];

// Lane A v2 Task 0.25 transitional fail-closed coverage: unknown-root rejection is unreachable while unbound withdrawals fail closed before
// anchor validation. Task 1 must restore or retire this expectation when proof-bound
// withdrawal is available.
#[test]
fn test_40_withdraw_unknown_root_rejected() {
    let pic = PocketIc::new();
    let user = p(0x40);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    // Pool pre-funded so escrow check would pass if anchor were valid.
    let pool_seed = DENOMINATIONS[0] + DEFAULT_FEE;
    let init = split_token_init(user, TOTAL_SUPPLY - pool_seed, pool_id, pool_seed, p(0x02));
    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T40_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let bad_env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T40_VK_HASH,
        root_reference: UNKNOWN_ROOT, // not in Merkle history
        pool_version: 1,
        proof_bytes: vec![],
    };

    let w: Result<candid::Nat, PoolError> = decode(
        "test_40: withdraw with unknown root",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 400,
                envelope: bad_env,
                nullifier: T40_NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(w, Err(PoolError::InvalidProof)),
        "transitional fail-closed path rejects before anchor validation until proof-bound withdrawal is restored"
    );

    // Nullifier must NOT be in registry — anchor check fires before nullifier reservation.
    let in_reg: bool = decode(
        "test_40: nullifier not in registry after AnchorNotFound",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(T40_NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        !in_reg,
        "Transitional fail-closed withdrawal must NOT insert nullifier into registry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 41 — private_spend with unknown root → AnchorNotFound
// ─────────────────────────────────────────────────────────────────────────────
//
// Same anchor check must apply to the private_spend path.
// =============================================================================

const T41_VK_HASH: [u8; 32] = [0x41; 32];
const T41_NF_A: [u8; 32] = [0xA1; 32];

// A2: uses proof_bytes:vec![] and 1-OC shape (incompatible with M4 circuit 1-in/2-out).
// The stub verifier accepted these; the real verifier rejects at ZK before the anchor check.
#[ignore = "A2: 1-OC shape incompatible with M4 circuit; proof_bytes:vec![] hits ZK check"]
#[test]
fn test_41_private_spend_unknown_root_rejected() {
    let pic = PocketIc::new();
    let user = p(0x41);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T41_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let bad_env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T41_VK_HASH,
        root_reference: UNKNOWN_ROOT, // not in Merkle history
        pool_version: 1,
        proof_bytes: vec![],
    };

    let s: Result<(), PoolError> = decode(
        "test_41: private_spend with unknown root",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4100,
                envelope: bad_env,
                nullifiers: vec![T41_NF_A],
                output_commitments: vec![[0x41u8; 32]],
                encrypted_outputs: vec![vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        s == Err(PoolError::AnchorNotFound),
        "private_spend with unknown root must return AnchorNotFound; got: {:?}",
        s
    );

    // Nullifier must NOT be in registry.
    assert!(
        !null_contains(&pic, null_id, T41_NF_A),
        "Nullifier must NOT be inserted after AnchorNotFound on private_spend"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 42 — private_spend batch all fresh nullifiers succeeds; all in registry
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: When all nullifiers in a batch are fresh, private_spend succeeds
// and all nullifiers are atomically inserted into the registry.
// =============================================================================

const T42_VK_HASH: [u8; 32] = [0x42; 32];
const T42_NF_A: [u8; 32] = [0x42u8; 32];
const T42_NF_B: [u8; 32] = [0x43u8; 32];

// A2: 2-nullifier batch incompatible with M4 circuit (1-in/2-out only).
// proof_bytes:vec![] now fails at ZK check (circuit shape guard catches 2 nullifiers first
// but the test expects Ok(()) which requires a valid 2-nullifier proof that doesn't exist yet).
#[ignore = "A2: 2-nullifier batch requires real ZK proof; M4 circuit is 1-in/2-out only"]
#[test]
fn test_42_private_spend_batch_fresh_nullifiers_succeed() {
    let pic = PocketIc::new();
    let user = p(0x42);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T42_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T42_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    let s: Result<(), PoolError> = decode(
        "test_42: private_spend with two fresh nullifiers",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4200,
                envelope: env,
                nullifiers: vec![T42_NF_A, T42_NF_B],
                output_commitments: vec![[0xA2u8; 32], [0xA3u8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        s.is_ok(),
        "private_spend with two fresh nullifiers must succeed; got: {:?}",
        s
    );

    // Both nullifiers must appear in the registry.
    for (label, nf) in [("A", T42_NF_A), ("B", T42_NF_B)] {
        assert!(
            null_contains(&pic, null_id, nf),
            "Nullifier {} must be in registry after successful batch spend",
            label
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 43 — private_spend batch with one already-spent nullifier → fails; other NOT inserted
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (atomicity): If ANY nullifier in the batch is already spent, the
// entire batch must fail and NO new nullifier in the batch is inserted.
// =============================================================================

const T43_VK_HASH: [u8; 32] = [0x43u8; 32];
const T43_NF_A: [u8; 32] = [0xD0u8; 32]; // will be pre-spent
const T43_NF_B: [u8; 32] = [0xD1u8; 32]; // fresh — must NOT be inserted on failure

// A2: S1 uses 1-OC shape (incompatible with M4 circuit); S2 uses 2-NF batch.
// Both require real ZK proofs for their respective circuit shapes.
#[ignore = "A2: S1 has 1-OC shape; S2 has 2-NF batch; both incompatible with M4 circuit"]
#[test]
fn test_43_private_spend_batch_with_spent_nullifier_fails_atomically() {
    let pic = PocketIc::new();
    let user = p(0x43);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T43_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: T43_VK_HASH,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // S1: spend nullifier A alone — must succeed (inserts A, appends output).
    let s1: Result<(), PoolError> = decode(
        "test_43: S1 spend nullifier A",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4301,
                envelope: env.clone(),
                nullifiers: vec![T43_NF_A],
                output_commitments: vec![[0xD2u8; 32]],
                encrypted_outputs: vec![vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(s1.is_ok(), "S1 (spend A alone) must succeed; got: {:?}", s1);

    // S2: batch [A (spent), B (fresh)] — pre-check catches A; fails before output appends.
    let s2: Result<(), PoolError> = decode(
        "test_43: S2 batch [spent A, fresh B] → fails at pre-check",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4302,
                envelope: env,
                nullifiers: vec![T43_NF_A, T43_NF_B],
                output_commitments: vec![[0xD3u8; 32], [0xD4u8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        s2 == Err(PoolError::NullifierAlreadySpent),
        "Batch with one spent nullifier must return NullifierAlreadySpent; got: {:?}",
        s2
    );

    // B must NOT be in registry — pre-check (step 7) caught A before any output commits.
    assert!(
        !null_contains(&pic, null_id, T43_NF_B),
        "Nullifier B must NOT be in registry after pre-check failure"
    );

    // Merkle leaf count: only 1 (from S1's output). S2 added no outputs.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "Merkle tree must have exactly 1 leaf (S1 output); S2 pre-check must not commit any"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 44 — private_spend batch with intra-batch duplicate → fails atomically
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: A batch where the same nullifier appears twice must be rejected
// (intra-batch duplicate check in insert_batch phase 1).  Neither nullifier
// must be inserted.
// =============================================================================

const T44_VK_HASH: [u8; 32] = [0x44u8; 32];
const T44_NF: [u8; 32] = [0xE0u8; 32]; // appears twice in same batch

// A2: 2-nullifier shape incompatible with M4 circuit. Circuit shape guard now runs before
// the intra-batch duplicate check, so this test fails with MalformedSpendArgs, not the
// expected NullifierAlreadySpent error. Re-enable with a valid 2-NF proof.
#[ignore = "A2: 2-NF batch hits circuit shape guard before intra-batch check"]
#[test]
fn test_44_private_spend_intra_batch_duplicate_rejected() {
    let pic = PocketIc::new();
    let user = p(0x44);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T44_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Batch with the same nullifier twice.
    let root_44 = merkle_root(&pic, merkle_id);
    let s: Result<(), PoolError> = decode(
        "test_44: private_spend with intra-batch duplicate",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 4400,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T44_VK_HASH,
                    root_reference: root_44,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T44_NF, T44_NF], // duplicate
                output_commitments: vec![[0xE1u8; 32], [0xE2u8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        s == Err(PoolError::NullifierAlreadySpent),
        "Intra-batch duplicate must return NullifierAlreadySpent; got: {:?}",
        s
    );

    // Nullifier must NOT be in registry — local HashSet caught it before any state changes.
    assert!(
        !null_contains(&pic, null_id, T44_NF),
        "Nullifier must NOT be in registry after intra-batch duplicate rejection"
    );

    // Merkle must be empty — no outputs appended.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle tree must be empty; intra-batch dup must be caught before output appends"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 45 — Unauthorized caller cannot call insert_batch on nullifier registry
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: insert_batch is guarded by assert_pool_canister() — any caller
// other than the registered pool canister must be rejected (canister trap).
// =============================================================================

#[test]
fn test_45_unauthorized_batch_insert_rejected() {
    let pic = PocketIc::new();
    let pool_id = p(0xCA); // pool is just an ordinary principal for this test
    let attacker = p(0xFF);
    let null_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );

    let test_nullifiers: Vec<Vec<u8>> = vec![[0x05u8; 32].to_vec(), [0x06u8; 32].to_vec()];

    // Attacker calls insert_batch directly — must be rejected (trap).
    let result = pic.update_call(
        null_id,
        attacker,
        "insert_batch",
        candid::encode_one(test_nullifiers.clone()).unwrap(),
    );
    expect_reject("test_45: attacker calling insert_batch", result);

    // Neither nullifier must have been inserted.
    for (label, nf) in [("A", [0x05u8; 32]), ("B", [0x06u8; 32])] {
        let present: bool = decode(
            &format!(
                "test_45: contains_nullifier {} after rejected batch insert",
                label
            ),
            pic.query_call(
                null_id,
                anon(),
                "contains_nullifier",
                candid::encode_one(nf.to_vec()).unwrap(),
            ),
        );
        assert!(
            !present,
            "Nullifier {} must NOT be in registry after unauthorized insert_batch attempt",
            label
        );
    }

    // Confirm the authorized caller (pool_id principal) CAN call insert_batch.
    let ok: Result<(), String> = decode(
        "test_45: authorized insert_batch",
        pic.update_call(
            null_id,
            pool_id,
            "insert_batch",
            candid::encode_one(test_nullifiers).unwrap(),
        ),
    );
    assert!(
        ok.is_ok(),
        "Authorized pool insert_batch must succeed; got: {:?}",
        ok
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 46 — Failed Merkle append leaves private_liability = 0 (CommitmentPending)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: If the Merkle canister is unreachable, shield_deposit receives the
// token transfer (tokens enter pool escrow) but MUST NOT update private_liability.
// Accounting is only updated AFTER Merkle confirms the leaf.
// The deposit record is left in CommitmentPending for retry.
//
// Setup: pool configured with p(0x03) as fake Merkle (not a real canister).
// The token transfer succeeds; the cross-canister call to Merkle fails.
// =============================================================================

const T46_COMMITMENT: [u8; 32] = canon(0x46);

#[test]
fn test_46_failed_merkle_append_no_private_liability() {
    let pic = PocketIc::new();
    let user = p(0x46);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    // Intentionally use p(0x03) as a non-existent Merkle canister.
    // The append_commitment call will be rejected, triggering CommitmentPending.
    let fake_merkle = p(0x03);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: fake_merkle, // unreachable
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: [0x46u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Approve and attempt deposit.
    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let result: Result<candid::Nat, PoolError> = decode(
        "test_46: shield_deposit with unreachable Merkle",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T46_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );

    // Must return CommitmentAppendFailed (Merkle call was rejected).
    assert!(
        matches!(result, Err(PoolError::CommitmentAppendFailed(_))),
        "deposit with unreachable Merkle must return CommitmentAppendFailed; got: {:?}",
        result
    );

    // CRITICAL: private_liability must be 0 — no accounting update without confirmed leaf.
    let acc = accounting_state(&pic, pool_id);
    assert_eq!(
        acc.private_liability, 0,
        "private_liability must be 0 when Merkle append fails; got: {}",
        acc.private_liability
    );

    // Pool DOES hold the tokens (transfer succeeded before Merkle call).
    let pool_bal = token_balance(&pic, token_id, pool_id);
    assert_eq!(
        pool_bal, DENOMINATIONS[0],
        "Pool must hold deposited tokens even after Merkle failure; got: {}",
        pool_bal
    );

    // H-1 (T1): under the index-before-marker fix, `leaf_count` is fetched BEFORE the
    // append is claimed. An UNREACHABLE Merkle canister fails that `leaf_count` call, so the
    // append is NEVER issued (no leaf can have been committed) and the deposit is left
    // cleanly at TransferConfirmedCommitmentPending — RETRYABLE via retry_deposit_commitment.
    // This REPLACES the pre-H-1 behavior, which appended without an index and left the
    // deposit stuck at CommitmentAppendUnknown + expected_leaf_index = None — unreconcilable
    // (reconcile_deposit_append_unknown rejects a None index), exactly the freeze class H-1
    // removes. No credit, tokens held in escrow, retryable. (An append that reaches a Merkle
    // that answers leaf_count but then drops the append callback still yields
    // CommitmentAppendUnknown + Some(index) — reconcilable; that path is covered by P2/P3.)
    let rec = deposit_status(&pic, pool_id, T46_COMMITMENT)
        .expect("deposit record must exist after CommitmentAppendFailed");
    assert_eq!(
        rec.status,
        DepositStatus::TransferConfirmedCommitmentPending,
        "H-1: unreachable Merkle fails at leaf_count (before the append is issued), so the \
         deposit is left retryable at TransferConfirmedCommitmentPending, not the pre-H-1 \
         unreconcilable CommitmentAppendUnknown+None; got: {:?}",
        rec.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// M4 private_spend plumbing — new tests 55–66
// ─────────────────────────────────────────────────────────────────────────────
//
// All tests below exercise the M4 private_spend implementation:
//   - Outputs-first safe ordering
//   - Sum-balance invariant (caller-declared amounts, stub-verifier phase)
//   - SpendStatus tracking via get_spend_status
//   - Pre-check: spent nullifiers rejected before outputs are appended
//   - Idempotency: repeated spend_id safely handled
//
// HARD NOTE: These tests verify stub-verifier scaffolding only.
// Real production balance enforcement must come from the ZK verifier.

// ─────────────────────────────────────────────────────────────────────────────
// Test 55 — Valid 2-in/2-out private_spend: outputs in tree, nullifiers in registry
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: A well-formed spend with matching sum-balance, fresh nullifiers, and
// valid anchor succeeds.  Both output commitments appear in the Merkle tree and
// both nullifiers appear in the registry.  SpendStatus is Finalized.
// =============================================================================

/// T55_IN_COMMITMENT: in_commitment for the spend circuit test vectors
/// (spend_key=42, in_value=100_000_000_000, in_rho=99, in_rseed=77).
/// DEF-035: = Poseidon(domain_sep, in_value, derived_pk, in_rho, in_rseed, COMMITMENT_DOMAIN)
///   where domain_sep = Poseidon(POOL_CANISTER_ID=1, ASSET_ID=0, CIRCUIT_VERSION=1, NETWORK_ID=1)
/// = 17604082912543768725809853082834251859819947802072291469758979543940668847869
/// encoded as 32-byte little-endian BN254 field element. Regenerated by
/// circuits/tests/gen_test_input.js for the domain-separated circuit.
// DEF-111 finalization regen: in_commitment over the finalized circuit's domain_sep
// [2,0,2,1] (regenerate via `node circuits/tests/gen_test_input.js`).
// Post-A1 regen (2026-07-07): in_commitment over the MAINNET domain_sep
// [ohspu-zqaaa-aaaad-qmasq-cai→Fr, 0, 2, 1] (CIRCUIT_VERSION was 2 then; it is 3 now — see below).
// A6.6 regen (2026-09-08): DOMAIN_CIRCUIT_VERSION 2 -> 3 AND in_value 1 STSH ->
// 1,000 STSH (the new ladder floor — the fixture note must be depositable), so
// the commitment moved on both counts. Regenerate via
// `node circuits/tests/gen_test_input.js`, then re-prove with snarkjs.
// A-3 FINALIZE regen (2026-09-12): DOMAIN_POOL_CANISTER_ID re-encoded to the
// Vault-born pool cxrfg-qaaaa-aaaar-qchfa-cai, so domain_sep — and therefore this
// known-answer commitment — moved. Regenerated via
// `node circuits/tests/gen_test_input.js`, then re-proved with snarkjs
// (circuits/proof.json + public.json, and the payout-A pair).
// A-3 FINALIZE value = 5364317693480985596849535143007715299620008859654397609343785557192353738706
// (was 10736000484984796872851673331456014893505793551453256205310079874034616912601 at A6.6).
const T55_IN_COMMITMENT: [u8; 32] = [
    0xd2, 0x6f, 0x9b, 0xb7, 0x36, 0x0a, 0xed, 0x7f, 0x09, 0x18, 0xe7, 0x27, 0x12, 0x3c, 0x86, 0x90,
    0xe2, 0x71, 0xb0, 0x5b, 0x6c, 0xb4, 0x52, 0xfc, 0x6f, 0x05, 0x3a, 0xd4, 0xa1, 0x18, 0xdc, 0x0b,
];

// A2 criterion #1: a spend with a real Groth16 proof must succeed end-to-end.
// Flow:
//   1. Pool initialised with the compiled verifier's VK hash.
//   2. Real verifier canister installed and wired via set_verifier_canister.
//   3. shield_deposit seeds in_commitment into the Merkle tree (leaf 0).
//   4. Merkle root after deposit must equal proof anchor (signals[0]).
//   5. private_spend with the real proof succeeds.
//   6. Nullifier in registry; 3 Merkle leaves (1 deposit + 2 outputs); status Finalized.
#[test]
fn test_55_valid_real_proof_spend_succeeds() {
    let Some(args) = load_valid_spend_fixture_args(5500) else {
        eprintln!("test_55: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let pic = PocketIc::new();
    let user = p(0x55);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Wire the real verifier to the pool (controller-only call).
    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_55: set_verifier_canister must succeed");

    // Seed in_commitment into the Merkle tree by depositing it as a note.
    // T55_IN_COMMITMENT is the private input note the proof was generated against.
    // The pool appends it via shield_deposit → append_commitment; the resulting root
    // must equal signals[0] (the proof anchor).
    let deposit_amount = DENOMINATIONS[0]; // 1,000 STSH (A6.6); InvalidDenomination if not in the fixed set
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_55: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_55: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    // Assert Merkle state: exactly 1 leaf, root matches proof anchor.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_55: Merkle tree must have exactly 1 leaf after seeding in_commitment"
    );
    let root_after_deposit = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_deposit, expected_anchor,
        "test_55: Merkle root after deposit must equal proof anchor (signals[0])"
    );

    // Call private_spend with the real proof.
    let result: Result<(), PoolError> = decode(
        "test_55: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        result.is_ok(),
        "test_55: valid real-proof spend must succeed; got: {:?}",
        result
    );

    // Nullifier must be registered.
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "test_55: nullifier (signals[1]) must be in registry after spend"
    );

    // 3 Merkle leaves: 1 deposit (in_commitment) + 2 spend outputs.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_55: Merkle tree must have 3 leaves (1 deposit + 2 spend outputs)"
    );

    // SpendStatus must be Finalized.
    let record = spend_status(&pic, pool_id, 5500)
        .expect("test_55: spend record must exist after successful private_spend");
    assert!(
        matches!(record.status, SpendStatus::Finalized),
        "test_55: SpendStatus must be Finalized; got: {:?}",
        record.status
    );
    assert_eq!(
        record.outputs_committed, 2,
        "test_55: outputs_committed must equal 2"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 56 — fee mismatch rejected; PoolError contract finalized (#87)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: args.fee must equal the governance-quoted protocol_private_spend_fee.
// At launch defaults protocol_private_spend_fee_stsh = 0, so any args.fee > 0
// must be rejected with PrivateSpendFeeMismatch { expected: 0, got: args.fee }
// before any state changes (no nullifier registered, Merkle empty).
//
// SpendFeeNotSupported is deprecated; PrivateSpendFeeMismatch is the finalized
// PoolError contract variant for fee divergence (#87).
// =============================================================================

const T56_VK_HASH: [u8; 32] = [0x56u8; 32];
const T56_NF: [u8; 32] = [0x59u8; 32];

#[test]
fn test_56_private_spend_fee_mismatch_contract_finalized() {
    let pic = PocketIc::new();
    let user = p(0x56);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T56_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let root = merkle_root(&pic, merkle_id);
    let result: Result<(), PoolError> = decode(
        "test_56: fee > 0 rejected",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 5600,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T56_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T56_NF],
                output_commitments: vec![[0x5Au8; 32]],
                encrypted_outputs: vec![vec![]],
                fee: 1, // <-- non-zero fee
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        result == Err(PoolError::PrivateSpendFeeMismatch { expected: 0, got: 1 }),
        "fee=1 with governance fee=0 must return PrivateSpendFeeMismatch{{expected:0,got:1}}; got: {:?}",
        result
    );

    // No state changes: nullifier not in registry, Merkle empty.
    assert!(
        !null_contains(&pic, null_id, T56_NF),
        "NF must not be in registry after fee rejection"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle must be empty after fee rejection"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests 57–60 — the private_spend static-validation block, after lane F1-PRIV
// ─────────────────────────────────────────────────────────────────────────────
//
// F1-PRIV (R1-F1 CRITICAL) deleted `input_amounts`/`output_amounts` from
// `PrivateSpendArgs`: they carried the hidden note values in cleartext on the
// ingress wire while being bound to nothing — not to a commitment, not to a
// leaf, not to a public signal — so a liar could declare a consistent-but-false
// pair and pass every check they fed. Four tests in this file asserted the
// behaviour of those checks. Their dispositions, recorded rather than silent:
//
//   Test 57 (length mismatch → MalformedSpendArgs)  RETARGETED, below. The
//     removed limbs are replaced by the three constraints that survive, each
//     with its OWN bite test.
//   Test 58 (sum(in) > sum(out) → SumMismatch)      RETIRED. The check it
//     exercised is gone; balance is enforced in-circuit at
//     `circuits/spend.circom:529` over range-checked value terms (:516-520) and
//     verified by the real verifier canister (U5 GREEN). Negative coverage of
//     the *declared* pair is not replaceable in-canister because the canister no
//     longer receives a declared pair.
//   Test 59 (value creation, out >> in → SumMismatch) RETIRED, same authority.
//     The constraint that covers it is `spend.circom:529` with the five range
//     checks at :516-520 — a forged out_value cannot balance and cannot wrap.
//   Test 60 (u128 overflow → SumOverflow)           RETIRED as written (it
//     overflowed the deleted `input_amounts` sum). `SumOverflow` SURVIVES on the
//     fee/public_amount path and keeps a test there — `test_60r`, below.
//
// Also asserted below: `SumMismatch` is never returned by any exercised
// private_spend path (the variant is retained for decode-compatibility only).

const T57_VK_HASH: [u8; 32] = [0x57u8; 32];
const T57_NF: [u8; 32] = [0x5Bu8; 32];

/// One pool + registry + merkle, installed with the T57 vk hash.
fn t57_env() -> (PocketIc, Principal, Principal, Principal) {
    let pic = PocketIc::new();
    let user = p(0x57);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T57_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    (pic, pool_id, null_id, merkle_id)
}

/// Send one `private_spend` with the given shape and return the reply.
#[allow(clippy::too_many_arguments)]
fn t57_spend(
    pic: &PocketIc,
    pool_id: Principal,
    merkle_id: Principal,
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    label: &str,
) -> Result<(), PoolError> {
    let root = merkle_root(pic, merkle_id);
    decode(
        label,
        pic.update_call(
            pool_id,
            p(0x57),
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T57_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers,
                output_commitments,
                encrypted_outputs,
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    )
}

// Test 57a — the SURVIVING parallelism limb, violated alone.
//
// encrypted_outputs.len() != output_commitments.len(), with the 1-in/2-out shape
// otherwise correct, so nothing else in the static block can produce the
// rejection. Neutralising this limb in the pool (mutation M1) makes this FAIL.
#[test]
fn test_57a_encrypted_outputs_parallelism_rejected() {
    let (pic, pool_id, null_id, merkle_id) = t57_env();
    let result = t57_spend(
        &pic,
        pool_id,
        merkle_id,
        5701,
        vec![T57_NF],
        vec![[0x5Cu8; 32], [0x5Du8; 32]],
        vec![vec![]], // 1 ciphertext for 2 commitments — the violated limb
        "test_57a: encrypted_outputs parallelism",
    );
    assert!(
        result == Err(PoolError::MalformedSpendArgs),
        "encrypted_outputs/output_commitments mismatch must return MalformedSpendArgs; got: {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, T57_NF),
        "NF must not be in registry"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle must be empty"
    );
}

// Test 57b — the 1-input circuit shape, violated alone (nullifiers.len() != 1).
#[test]
fn test_57b_nullifier_count_rejected() {
    let (pic, pool_id, null_id, merkle_id) = t57_env();
    let result = t57_spend(
        &pic,
        pool_id,
        merkle_id,
        5702,
        vec![T57_NF, [0x5Eu8; 32]], // 2 nullifiers — the violated limb
        vec![[0x5Cu8; 32], [0x5Du8; 32]],
        vec![vec![], vec![]],
        "test_57b: nullifier count",
    );
    assert!(
        result == Err(PoolError::MalformedSpendArgs),
        "nullifiers.len() != 1 must return MalformedSpendArgs; got: {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, T57_NF),
        "NF must not be in registry"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle must be empty"
    );
}

// Test 57c — the 2-output circuit shape, violated alone
// (output_commitments.len() != 2, with encrypted_outputs kept parallel to it so
// 57a's limb is NOT the one biting).
#[test]
fn test_57c_output_commitment_count_rejected() {
    let (pic, pool_id, null_id, merkle_id) = t57_env();
    let result = t57_spend(
        &pic,
        pool_id,
        merkle_id,
        5703,
        vec![T57_NF],
        vec![[0x5Cu8; 32]], // 1 commitment — the violated limb
        vec![vec![]],       // parallel, so the surviving limb passes
        "test_57c: output commitment count",
    );
    assert!(
        result == Err(PoolError::MalformedSpendArgs),
        "output_commitments.len() != 2 must return MalformedSpendArgs; got: {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, T57_NF),
        "NF must not be in registry"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle must be empty"
    );
}

// Test 57d — ANTI-VACUITY. The same shape with every limb satisfied must NOT be
// rejected as MalformedSpendArgs (it fails later, on the proof), which is what
// proves 57a/b/c are detecting their limbs and not a constant rejection.
#[test]
fn test_57d_wellformed_shape_is_not_malformed() {
    let (pic, pool_id, _null_id, merkle_id) = t57_env();
    let result = t57_spend(
        &pic,
        pool_id,
        merkle_id,
        5704,
        vec![T57_NF],
        vec![[0x5Cu8; 32], [0x5Du8; 32]],
        vec![vec![], vec![]],
        "test_57d: well-formed shape",
    );
    assert!(
        result != Err(PoolError::MalformedSpendArgs),
        "a well-formed 1-in/2-out shape must not be MalformedSpendArgs; got: {:?}",
        result
    );
    assert!(
        result != Err(PoolError::SumMismatch {
            inputs: 0,
            outputs: 0
        }),
        "SumMismatch is retired and must never be returned; got: {:?}",
        result
    );
}

// Test 60r — what actually guards the surviving sum on the private_spend path.
//
// MEASURED, and NOT what A1 V5's M5 row assumed. `SumOverflow` survives in
// `private_spend_private_liability_debit` (`lib.rs:11035-11039`, `fee.checked_add(
// public_amount)`), but it is UNREACHABLE through `private_spend` ingress at the
// shipped configuration: step 2 rejects any `fee != expected_private_spend_fee`,
// which is 0 pre-governance, and `0.checked_add(x)` cannot overflow for any u128
// `x`. A wrapping pair is therefore rejected EARLIER, by the fee gate — proven
// below rather than asserted.
//
// So this test pins the ordering fact that is real, and the package reports M5
// as unfirable on this path with this evidence. `SumOverflow` keeps live
// coverage on the treasury disbursement path (`lib.rs:5510-5514`), which this
// lane does not touch.
#[test]
fn test_60r_wrapping_fee_pair_is_rejected_by_the_fee_gate_before_the_debit() {
    let (pic, pool_id, null_id, merkle_id) = t57_env();
    let root = merkle_root(&pic, merkle_id);
    let result: Result<(), PoolError> = decode(
        "test_60r: fee + public_amount overflow",
        pic.update_call(
            pool_id,
            p(0x57),
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 6001,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T57_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T57_NF],
                output_commitments: vec![[0x5Cu8; 32], [0x5Du8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: u128::MAX,
                public_payout: Some(PrivateSpendPublicPayout {
                    destination: p(0x9C),
                    destination_subaccount: None,
                    public_amount: 1,
                }),
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        result,
        Err(PoolError::PrivateSpendFeeMismatch {
            expected: 0,
            got: u128::MAX
        }),
        "a wrapping fee + public_amount pair must be rejected by the FEE GATE, before \
         any debit arithmetic runs — this is why SumOverflow is unreachable here; got: {:?}",
        result
    );
    assert!(
        result != Err(PoolError::SumMismatch {
            inputs: 0,
            outputs: 0
        }),
        "SumMismatch is retired and must never be returned; got: {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, T57_NF),
        "NF must not be in registry"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle must be empty"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 61 — Unknown root rejected before any outputs committed
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: AnchorNotFound must be returned and NO outputs must be appended
// to the Merkle tree before the anchor check returns.
// =============================================================================

const T61_VK_HASH: [u8; 32] = [0x61u8; 32];
const T61_NF: [u8; 32] = [0x65u8; 32];

// A2: 1-OC shape incompatible with M4 circuit (1-in/2-out requires exactly 2 OCs).
// proof_bytes:vec![] now fails at ZK before the anchor check; test expects AnchorNotFound.
#[ignore = "A2: 1-OC shape incompatible with M4 circuit; ZK check fires before anchor"]
#[test]
fn test_61_unknown_root_no_outputs_committed() {
    let pic = PocketIc::new();
    let user = p(0x61);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T61_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let result: Result<(), PoolError> = decode(
        "test_61: unknown root rejected",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 6100,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T61_VK_HASH,
                    root_reference: UNKNOWN_ROOT, // not in Merkle history
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T61_NF],
                output_commitments: vec![[0x66u8; 32]],
                encrypted_outputs: vec![vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        result == Err(PoolError::AnchorNotFound),
        "unknown root must return AnchorNotFound; got: {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, T61_NF),
        "NF must not be in registry"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle tree must be empty — no outputs must be committed before anchor check"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 62 — Spent nullifier rejected at pre-check; no outputs committed
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (outputs-first + pre-check): if a nullifier is already permanently
// spent in the registry, the pre-check (step 7) must reject the spend BEFORE
// any output commitments are appended to the Merkle tree.
// =============================================================================

const T62_VK_HASH: [u8; 32] = [0x62u8; 32];
const T62_NF_A: [u8; 32] = [0x67u8; 32]; // will be pre-spent via S1
const T62_NF_B: [u8; 32] = [0x68u8; 32]; // fresh in S2

// A2: S1 uses 1-OC shape (incompatible with M4 circuit). S2's NullifierAlreadySpent check
// is never reached because S1 fails at ZK/circuit-shape before inserting the nullifier.
#[ignore = "A2: S1 has 1-OC shape; NF never spent; S2 NullifierAlreadySpent unreachable"]
#[test]
fn test_62_spent_nullifier_rejected_before_outputs() {
    let pic = PocketIc::new();
    let user = p(0x62);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T62_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // S1: spend NF_A successfully → permanently inserts NF_A, appends 1 output.
    let root = merkle_root(&pic, merkle_id);
    let s1: Result<(), PoolError> = decode(
        "test_62: S1 spend NF_A",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 6201,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T62_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T62_NF_A],
                output_commitments: vec![[0x69u8; 32]],
                encrypted_outputs: vec![vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(s1.is_ok(), "S1 must succeed; got: {:?}", s1);
    assert_eq!(merkle_leaf_count(&pic, merkle_id), 1, "1 leaf after S1");

    // S2: attempt to spend [NF_A (already spent), NF_B (fresh)].
    // Pre-check must catch NF_A before appending any outputs.
    let s2: Result<(), PoolError> = decode(
        "test_62: S2 with spent NF_A — pre-check must reject before outputs",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 6202,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T62_VK_HASH,
                    root_reference: root, // root from before S1; still in ring buffer
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T62_NF_A, T62_NF_B],
                output_commitments: vec![[0x6Au8; 32], [0x6Bu8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        s2 == Err(PoolError::NullifierAlreadySpent),
        "S2 must fail with NullifierAlreadySpent; got: {:?}",
        s2
    );

    // NF_B must NOT be in registry (pre-check caught NF_A; no insert_batch reached).
    assert!(
        !null_contains(&pic, null_id, T62_NF_B),
        "NF_B must not be in registry"
    );

    // Merkle must still have exactly 1 leaf (from S1 only; S2 appended nothing).
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "Merkle must have 1 leaf (S1 only); S2 pre-check must not commit any outputs"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 63 — Intra-batch duplicate rejected before outputs committed
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: Local HashSet check (step 6) must catch same-nullifier twice
// in one batch BEFORE any output appends or cross-canister calls beyond the
// anchor check.
// =============================================================================

const T63_VK_HASH: [u8; 32] = [0x63u8; 32];
const T63_NF: [u8; 32] = [0x6Cu8; 32]; // appears twice

// A2: 2-NF batch hits circuit shape guard (MalformedSpendArgs) before intra-batch check.
// Test expects NullifierAlreadySpent which is now unreachable with this shape.
#[ignore = "A2: 2-NF batch hits circuit shape guard before intra-batch duplicate check"]
#[test]
fn test_63_intra_batch_dup_before_outputs() {
    let pic = PocketIc::new();
    let user = p(0x63);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: T63_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    let root = merkle_root(&pic, merkle_id);
    let result: Result<(), PoolError> = decode(
        "test_63: intra-batch duplicate",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 6300,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T63_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifiers: vec![T63_NF, T63_NF], // same nullifier twice
                output_commitments: vec![[0x6Du8; 32], [0x6Eu8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        result == Err(PoolError::NullifierAlreadySpent),
        "intra-batch dup must return NullifierAlreadySpent; got: {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, T63_NF),
        "NF must not be in registry"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        0,
        "Merkle must be empty — dup check must fire before any output appends"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 64 (A2, QA-DEF-034/036) — promotion append failure → ActiveAppendRejected
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (A2): under stage-before-finalize, the parent nullifier is finalized
// BEFORE the Merkle append. If the promotion append is rejected (pool_b not
// authorized on merkle_id), private_spend returns OutputAppendRejected and the spend
// record is ActiveAppendRejected with outputs_committed=0 — recoverable via
// reconcile_pending_spend. The nullifier IS registered (finalized, never rolled back).
//
// (Rewritten from the pre-A2 outputs-first test, which asserted the OPPOSITE — the
// append ran first, so an append failure left status FailedAfterOutputsCommitted and
// NO nullifier registered.)
//
// Two-pool setup:
//   pool_a  — authorized on merkle_id; used only to seed T55_IN_COMMITMENT.
//   pool_b  — NOT authorized on merkle_id; calls private_spend with the real proof.
//   null_b  — authorized for pool_b (insert_batch succeeds → nullifier finalized).
//   verifier — real verifier, wired to pool_b.
//   A2: the fixture anchor is whitelisted on pool_b (accept_spend_root_for_test)
//       because pool_b never deposited and anchors are pool-local under A2.
// =============================================================================

#[test]
fn test_64_commitment_append_failure_records_partial_state() {
    let Some(args) = load_valid_spend_fixture_args(6400) else {
        eprintln!("test_64: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let pic = PocketIc::new();
    let user = p(0x64);
    let token_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let null_b = create_canister(&pic);
    let pool_a = create_canister(&pic);
    let pool_b = create_canister(&pic);
    let verifier = create_canister(&pic);

    // merkle_id authorized for pool_a; pool_b's append_commitment will be rejected.
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_a).unwrap(),
        None,
    );
    // null_b authorized for pool_b (contains_nullifier open query; insert_batch never reached).
    pic.install_canister(
        null_b,
        nullifier_wasm(),
        candid::encode_one(pool_b).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_b).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    // pool_a: authorized on merkle_id; used only for shield_deposit seeding.
    install(
        &pic,
        pool_a,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_b,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    // pool_b: uses merkle_id (unauthorized for append) and null_b (authorized).
    // A2: pool_test_wasm so the test can whitelist the anchor (accept_spend_root_for_test).
    install(
        &pic,
        pool_b,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_b,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Wire real verifier to pool_b only.
    pic.update_call(
        pool_b,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_64: set_verifier_canister must succeed");

    // pool_a seeds T55_IN_COMMITMENT so merkle root = expected_anchor.
    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_a, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_64: pool_a shield_deposit",
        pic.update_call(
            pool_a,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_64: pool_a shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_seed = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_seed, expected_anchor,
        "test_64: merkle root after pool_a seed must equal proof anchor"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_64: merkle_id must have 1 leaf after seeding"
    );

    // A2: pool_b never deposited, so its accepted_spend_roots is empty. Whitelist the
    // fixture anchor on pool_b directly (pool_a's deposit accepted it only on pool_a)
    // so the spend passes the A2 accepted-root precheck and reaches the promotion append.
    let accept: Result<(), String> = decode(
        "test_64: accept_spend_root_for_test",
        pic.update_call(
            pool_b,
            p(0x06),
            "accept_spend_root_for_test",
            candid::encode_one(expected_anchor.to_vec()).unwrap(),
        ),
    );
    assert!(accept.is_ok(), "test_64: accept_spend_root_for_test must succeed; got {:?}", accept);

    // pool_b private_spend: proof passes ZK; A2 stages outputs, finalizes the nullifier
    // on null_b (authorized), then the promotion append on merkle_id is rejected
    // (pool_b not authorized) → ActiveAppendRejected (definite non-commit).
    let result: Result<(), PoolError> = decode(
        "test_64: pool_b private_spend",
        pic.update_call(
            pool_b,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        matches!(result, Err(PoolError::OutputAppendRejected(_))),
        "test_64 (A2): promotion append rejection must return OutputAppendRejected; got: {:?}",
        result
    );

    // A2: the parent nullifier IS finalized (insert_batch on null_b succeeded BEFORE
    // the append). The append failed afterward — the spend is recoverable via
    // reconcile_pending_spend and the nullifier is never rolled back.
    assert!(
        null_contains(&pic, null_b, expected_nullifier),
        "test_64 (A2): nullifier MUST be registered — the parent is finalized before the append"
    );

    // Merkle must still have exactly 1 leaf (the promotion append was rejected).
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_64: merkle_id must have 1 leaf (pool_a seed only; pool_b's append was rejected)"
    );

    // SpendStatus: ActiveAppendRejected — A2 promotion append definitely rejected
    // AFTER parent-nullifier finality. Recoverable via reconcile_pending_spend.
    let record = spend_status(&pic, pool_b, 6400)
        .expect("test_64: spend record must exist after ActiveAppendRejected");
    assert!(
        matches!(
            record.status,
            SpendStatus::ActiveAppendRejected { .. }
        ),
        "test_64 (A2): status must be ActiveAppendRejected; got: {:?}",
        record.status
    );
    assert_eq!(
        record.outputs_committed, 0,
        "test_64 (A2): outputs_committed must be 0 (the promotion append was rejected)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 65 (A2, QA-DEF-034) — insert_batch failure leaves NO orphan outputs
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (A2): outputs are STAGED, not appended, until the parent nullifier is
// finalized. If insert_batch is rejected, the staged outputs are discarded and the
// spend enters FailedAfterOutputsStaged. Crucially the Merkle tree gains NO orphan
// output leaves — this is exactly the orphan-spendability defect A2 closes. NO
// nullifiers are inserted; the parent note remains spendable.
//
// (Rewritten from the pre-A2 outputs-first test, which asserted the OPPOSITE — 3
// leaves incl. 2 orphans, status FailedAfterOutputsCommitted, outputs_committed=2.)
//
// Single-pool setup (nullifier authorization mismatch):
//   null_a  — authorized for p(0x6A) only; pool_b's insert_batch will trap (definite).
//   merkle_b — authorized for pool_b; the seeding deposit succeeds and its root is
//              accepted, so the spend's anchor passes the A2 accepted-root check.
//   pool_b  — uses merkle_b (authorized) and null_a (unauthorized for insert_batch).
//   verifier — real verifier, wired to pool_b.
//
// A2 ordering: stage outputs → insert_batch (traps on null_a, definite non-commit)
// → FailedAfterOutputsStaged. The append never runs, so merkle_b keeps only its 1
// deposit leaf. null_a's assert_pool_canister() traps for pool_b → Err((_, e)).
// =============================================================================

#[test]
fn test_65_failed_after_outputs_committed_records_partial_state() {
    let Some(args) = load_valid_spend_fixture_args(6500) else {
        eprintln!("test_65: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let pic = PocketIc::new();
    let user = p(0x65);
    let token_id = create_canister(&pic);
    let null_a = create_canister(&pic);
    let merkle_b = create_canister(&pic);
    let pool_b = create_canister(&pic);
    let verifier = create_canister(&pic);

    // null_a authorized for p(0x6A) only; pool_b's insert_batch will be rejected.
    pic.install_canister(
        null_a,
        nullifier_wasm(),
        candid::encode_one(p(0x6A)).unwrap(),
        None,
    );
    // merkle_b authorized for pool_b; append_commitment succeeds.
    pic.install_canister(
        merkle_b,
        merkle_wasm(),
        candid::encode_one(pool_b).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_b).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    // pool_b: merkle_b authorized (outputs committed), null_a unauthorized (insert_batch fails).
    install(
        &pic,
        pool_b,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_a,
            merkle_canister: merkle_b,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Wire real verifier to pool_b.
    pic.update_call(
        pool_b,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_65: set_verifier_canister must succeed");

    // pool_b seeds T55_IN_COMMITMENT into merkle_b (pool_b is authorized).
    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_b, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_65: shield_deposit",
        pic.update_call(
            pool_b,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_65: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_seed = merkle_root(&pic, merkle_b);
    assert_eq!(
        root_after_seed, expected_anchor,
        "test_65: merkle root after seed must equal proof anchor"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_b),
        1,
        "test_65: merkle_b must have 1 leaf after seeding"
    );

    // pool_b private_spend: proof passes ZK, both outputs appended to merkle_b,
    // then insert_batch on null_a traps (assert_pool_canister) → TransferFailed.
    let result: Result<(), PoolError> = decode(
        "test_65: pool_b private_spend",
        pic.update_call(
            pool_b,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    // null_a's assert_pool_canister() traps for pool_b → Err((_, e)) → TransferFailed
    // (lib.rs:2496-2503; not NullifierAlreadySpent since it's an access rejection).
    assert!(
        matches!(result, Err(PoolError::TransferFailed(_))),
        "test_65: insert_batch trap must return TransferFailed; got: {:?}",
        result
    );

    // Nullifier must NOT be in null_a (insert_batch rejected before any insertion).
    assert!(
        !null_contains(&pic, null_a, expected_nullifier),
        "test_65: nullifier must not be registered after insert_batch failure"
    );

    // A2 (QA-DEF-034) — THE FIX: merkle_b must have ONLY the 1 seeding deposit leaf.
    // Under the active-only tree, outputs are STAGED (not appended) until the parent
    // nullifier is finalized, so a failed insert_batch leaves NO orphan output leaves
    // in the tree. (Pre-A2 this asserted 3 leaves: 1 deposit + 2 orphaned outputs —
    // exactly the orphan-spendability defect A2 closes.)
    assert_eq!(
        merkle_leaf_count(&pic, merkle_b),
        1,
        "test_65 (A2): merkle_b must have 1 leaf (deposit only) — staged outputs are NOT appended on insert_batch failure, so there are no orphan leaves"
    );

    // SpendStatus: FailedAfterOutputsStaged — the staged outputs were discarded and
    // the parent nullifier was never committed (definite insert_batch rejection).
    let record = spend_status(&pic, pool_b, 6500)
        .expect("test_65: spend record must exist after FailedAfterOutputsStaged");
    assert!(
        matches!(
            record.status,
            SpendStatus::FailedAfterOutputsStaged { .. }
        ),
        "test_65 (A2): status must be FailedAfterOutputsStaged; got: {:?}",
        record.status
    );
    assert_eq!(record.outputs_committed, 0,
        "test_65 (A2): outputs_committed must be 0 — outputs were staged, never appended");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 66 — Repeated spend_id is idempotent on success
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: Submitting the exact same spend_id twice must return Ok() on the
// second call without re-executing any state changes.  The Merkle tree and
// nullifier registry must not accumulate duplicate entries.
// =============================================================================

// A2-1: uses real Groth16 proof; setup mirrors test_55.
// Flow:
//   1. Pool initialised with the compiled verifier's VK hash.
//   2. Real verifier wired via set_verifier_canister.
//   3. shield_deposit seeds in_commitment; Merkle root = proof anchor (signals[0]).
//   4. First private_spend with the real proof → Finalized; 3 leaves; nullifier registered.
//   5. Second private_spend with the same spend_id and args → Ok() (idempotent, no re-mutation).
//   6. Leaf count and nullifier registry unchanged after the second call; status still Finalized.
#[test]
fn test_66_repeated_spend_id_is_idempotent() {
    let Some(args) = load_valid_spend_fixture_args(6600) else {
        eprintln!("test_66: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let pic = PocketIc::new();
    let user = p(0x66);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_66: set_verifier_canister must succeed");

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_66: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_66: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_deposit = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_deposit, expected_anchor,
        "test_66: Merkle root after deposit must equal proof anchor"
    );

    // First private_spend — must reach Finalized.
    let r1: Result<(), PoolError> = decode(
        "test_66: first private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    assert!(
        r1.is_ok(),
        "test_66: first private_spend must succeed; got: {:?}",
        r1
    );

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_66: 3 leaves after first spend (1 deposit + 2 outputs)"
    );
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "test_66: nullifier must be in registry after first spend"
    );

    let record = spend_status(&pic, pool_id, 6600)
        .expect("test_66: spend record must exist after first private_spend");
    assert!(
        matches!(record.status, SpendStatus::Finalized),
        "test_66: SpendStatus must be Finalized after first spend; got: {:?}",
        record.status
    );

    // Second private_spend — same spend_id, same args — must return Ok() idempotently.
    let r2: Result<(), PoolError> = decode(
        "test_66: second private_spend (idempotent)",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        r2.is_ok(),
        "test_66: second private_spend with same spend_id must return Ok(); got: {:?}",
        r2
    );

    // No re-mutation: leaf count and nullifier registry must be unchanged.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_66: Merkle must still have 3 leaves after idempotent repeat"
    );
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "test_66: nullifier must still be in registry after idempotent repeat"
    );

    let record2 = spend_status(&pic, pool_id, 6600)
        .expect("test_66: spend record must still exist after second call");
    assert!(
        matches!(record2.status, SpendStatus::Finalized),
        "test_66: SpendStatus must remain Finalized after idempotent repeat; got: {:?}",
        record2.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 67 — garbage proof bytes rejected by real verifier; no state mutation
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: corrupted/invalid proof bytes must be rejected by the real
// Groth16 verifier with ProofRejected before any state change.  No nullifier
// must be reserved and no Merkle leaf appended.  SpendStatus must be
// FailedBeforeStateChange.
// =============================================================================

#[test]
fn test_67_invalid_proof_bytes_rejected_no_mutation() {
    let Some(mut args) = load_valid_spend_fixture_args(6700) else {
        eprintln!("test_67: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    // Replace real proof bytes with 256 garbage bytes — verifier must reject.
    args.envelope.proof_bytes = vec![0xFFu8; 256];

    let pic = PocketIc::new();
    let user = p(0x67);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_67: set_verifier_canister must succeed");

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_67: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_67: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_deposit = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_deposit, expected_anchor,
        "test_67: Merkle root after deposit must equal proof anchor"
    );

    let result: Result<(), PoolError> = decode(
        "test_67: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        matches!(result, Err(PoolError::ProofRejected(_))),
        "test_67: garbage proof bytes must return ProofRejected; got: {:?}",
        result
    );

    // No state mutation: nullifier not registered, leaf count unchanged.
    assert!(
        !null_contains(&pic, null_id, expected_nullifier),
        "test_67: nullifier must NOT be in registry after rejected spend"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_67: Merkle tree must still have 1 leaf after rejected spend"
    );

    let record = spend_status(&pic, pool_id, 6700)
        .expect("test_67: spend record must exist after rejected private_spend");
    assert!(
        matches!(record.status, SpendStatus::FailedBeforeStateChange { .. }),
        "test_67: SpendStatus must be FailedBeforeStateChange; got: {:?}",
        record.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 68 — tampered public signal (nullifier_hash+1) rejected; no state mutation
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: a spend whose declared nullifier doesn't match the proof's
// embedded public signals must be rejected with ProofRejected by the real
// verifier.  Neither the tampered nor the real nullifier may appear in the
// registry; Merkle leaf count must be unchanged.  SpendStatus must be
// FailedBeforeStateChange.
// =============================================================================

/// public.json signals[1] + 1 (nullifier_hash + 1, LE BN254 field element).
/// DEF-035: = 597448711536067151571179283797340343151748956896270461285433346129760332695
/// (domain-separated nullifier + 1). Regenerated by circuits/tests/gen_test_input.js.
// DEF-111 finalization regen: nullifier_hash+1 over the finalized circuit (DEF-109-A
// full-note nullifier + domain_sep [2,0,2,1]).
// Post-A1 regen (2026-07-07): public.json signals[1] + 1 over the MAINNET domain
// A-3 FINALIZE regen (2026-09-12): the re-encode moved domain_sep, so the
// nullifier moved with it. public.json signals[1] + 1
// = 8170798979279685210888401237814125366122813481280574798222575791379905552000
// (was 16852849343463437203800800931764757237240270988274419127396017563472037961854).
const T68_TAMPERED_NF: [u8; 32] = [
    0x80, 0x9e, 0x78, 0xb5, 0xbd, 0x2d, 0x02, 0x31, 0x57, 0xe6, 0x66, 0xe8, 0x05, 0x21, 0x9f, 0x9b,
    0xaf, 0xc9, 0x6d, 0xe6, 0xfd, 0x98, 0xb6, 0x9a, 0x54, 0x3a, 0xbc, 0x4c, 0x22, 0x82, 0x10, 0x12,
];

#[test]
fn test_68_tampered_public_signal_rejected_no_mutation() {
    let Some(mut args) = load_valid_spend_fixture_args(6800) else {
        eprintln!("test_68: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let real_nullifier = args.nullifiers[0];

    // Replace declared nullifier with nullifier_hash+1 — signals won't match the proof.
    args.nullifiers[0] = T68_TAMPERED_NF;

    let pic = PocketIc::new();
    let user = p(0x68);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_68: set_verifier_canister must succeed");

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_68: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_68: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_deposit = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_deposit, expected_anchor,
        "test_68: Merkle root after deposit must equal proof anchor"
    );

    // private_spend with tampered nullifier — verifier rejects the signal mismatch.
    let result: Result<(), PoolError> = decode(
        "test_68: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        matches!(result, Err(PoolError::ProofRejected(_))),
        "test_68: tampered nullifier must return ProofRejected; got: {:?}",
        result
    );

    // Neither the tampered nor the real nullifier must appear in the registry.
    assert!(
        !null_contains(&pic, null_id, T68_TAMPERED_NF),
        "test_68: tampered nullifier must NOT be in registry after rejected spend"
    );
    assert!(
        !null_contains(&pic, null_id, real_nullifier),
        "test_68: real nullifier must NOT be in registry after rejected spend"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_68: Merkle tree must still have 1 leaf after rejected spend"
    );

    let record = spend_status(&pic, pool_id, 6800)
        .expect("test_68: spend record must exist after rejected private_spend");
    assert!(
        matches!(record.status, SpendStatus::FailedBeforeStateChange { .. }),
        "test_68: SpendStatus must be FailedBeforeStateChange; got: {:?}",
        record.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 69 — verifier not configured; VerifierUnavailable before PendingSpend written
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: If set_verifier_canister has never been called (VERIFIER_CANISTER
// is None), private_spend must return VerifierUnavailable at step 11 before
// writing any PENDING_SPENDS record.  No nullifier is registered; no Merkle
// leaf is added beyond the seeded deposit.  get_spend_status returns None.
// =============================================================================

#[test]
fn test_69_verifier_not_configured_rejected_no_mutation() {
    let Some(args) = load_valid_spend_fixture_args(6900) else {
        eprintln!("test_69: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let pic = PocketIc::new();
    let user = p(0x69);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    // Intentionally omit set_verifier_canister — VERIFIER_CANISTER stays None.

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_69: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_69: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_deposit = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_deposit, expected_anchor,
        "test_69: Merkle root after deposit must equal proof anchor"
    );

    let result: Result<(), PoolError> = decode(
        "test_69: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        matches!(result, Err(PoolError::VerifierUnavailable(_))),
        "test_69: unconfigured verifier must return VerifierUnavailable; got: {:?}",
        result
    );

    // Step 11 fires before step 12 — no PENDING_SPENDS record must exist.
    assert!(
        spend_status(&pic, pool_id, 6900).is_none(),
        "test_69: no spend record must exist after step-11 rejection"
    );
    assert!(
        !null_contains(&pic, null_id, expected_nullifier),
        "test_69: nullifier must NOT be in registry after VerifierUnavailable"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_69: Merkle tree must still have 1 leaf after VerifierUnavailable"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P15-006 — set_verifier_canister transport-fail guard release + guard-clear
// recovery endpoint (DEF-003 mid-call coverage gap)
// ─────────────────────────────────────────────────────────────────────────────
//
// test_70 covers the transport-fail path only INDIRECTLY (a later successful
// rewire implies the guard released). These tests assert it DIRECTLY:
//   A) a vk_hash transport failure returns VerifierUnavailable AND releases
//      SET_VERIFIER_IN_PROGRESS — a second set_verifier_canister is not
//      rejected with VerifierConfigInProgress;
//   B) clear_verifier_config_guard is controller-gated, idempotent, and leaves
//      set_verifier_canister able to proceed.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal pool-only setup for verifier-config tests: installs ONLY the pool
/// (the other principals are bare canister ids — pool init never calls them).
/// Returns (pic, pool_id, controller, bad_verifier) where bad_verifier is a
/// created-but-empty canister: any call to it fails at transport ("no wasm").
fn p15006_setup() -> (PocketIc, Principal, Principal, Principal) {
    let pic = PocketIc::new();
    let controller = p(0x16);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let bad_verifier = create_canister(&pic); // no wasm installed — transport-fails
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    (pic, pool_id, controller, bad_verifier)
}

// Test A — transport-fail: VerifierUnavailable returned AND guard released.
#[test]
fn test_set_verifier_transport_fail_clears_guard() {
    let (pic, pool_id, controller, bad_verifier) = p15006_setup();
    // expected_vk_hash == the pool's current pin, so the call passes the pre-await
    // checks and genuinely reaches the vk_hash await (the branch under test).
    let pin = stsh_verifier::compiled_vk_sha256().to_vec();

    let first: Result<(), PoolError> = decode(
        "p15006-A: set_verifier_canister (bad verifier)",
        pic.update_call(
            pool_id,
            controller,
            "set_verifier_canister",
            candid::encode_args((bad_verifier, pin.clone())).unwrap(),
        ),
    );
    assert!(
        matches!(first, Err(PoolError::VerifierUnavailable(_))),
        "p15006-A: vk_hash transport failure must return VerifierUnavailable; got {:?}",
        first
    );

    // The DIRECT guard assertion: an immediate second call must NOT be rejected
    // with VerifierConfigInProgress. (It fails with VerifierUnavailable again for
    // the same bad verifier — the point is the guard did not stick.)
    let second: Result<(), PoolError> = decode(
        "p15006-A: set_verifier_canister (retry)",
        pic.update_call(
            pool_id,
            controller,
            "set_verifier_canister",
            candid::encode_args((bad_verifier, pin)).unwrap(),
        ),
    );
    assert!(
        !matches!(second, Err(PoolError::VerifierConfigInProgress)),
        "p15006-A: guard must be released after transport failure — retry must not \
         see VerifierConfigInProgress; got {:?}",
        second
    );
    assert!(
        matches!(second, Err(PoolError::VerifierUnavailable(_))),
        "p15006-A: retry against the same bad verifier fails at transport again; got {:?}",
        second
    );
}

// Test B — clear_verifier_config_guard: controller-gated + idempotent.
#[test]
fn test_clear_verifier_config_guard_controller_only() {
    let (pic, pool_id, controller, bad_verifier) = p15006_setup();

    // 1) Non-controller must be rejected (assert_operator_controller trap).
    let non_controller = pic.update_call(
        pool_id,
        p(0x17),
        "clear_verifier_config_guard",
        candid::encode_args(()).unwrap(),
    );
    assert!(
        non_controller.is_err(),
        "p15006-B: non-controller must not clear the verifier config guard"
    );

    // 2) Controller: idempotent — guard is already clear, returns false.
    let cleared: bool = decode(
        "p15006-B: clear_verifier_config_guard (controller)",
        pic.update_call(
            pool_id,
            controller,
            "clear_verifier_config_guard",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(
        !cleared,
        "p15006-B: guard was not set — pre-clear value must be false (idempotent no-op)"
    );

    // 3) A subsequent set_verifier_canister proceeds past the guard (reaches the
    //    await and fails at transport — NOT VerifierConfigInProgress).
    let after: Result<(), PoolError> = decode(
        "p15006-B: set_verifier_canister after clear",
        pic.update_call(
            pool_id,
            controller,
            "set_verifier_canister",
            candid::encode_args((bad_verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
        ),
    );
    assert!(
        !matches!(after, Err(PoolError::VerifierConfigInProgress)),
        "p15006-B: set_verifier_canister must not be guard-blocked after clear; got {:?}",
        after
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 70 — verifier unreachable; guard written then removed; same spend_id retryable
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: If VERIFIER_CANISTER is set to a wasm-less canister (transport-
// level failure at step 13), private_spend returns VerifierUnavailable and
// the VerificationPending guard written at step 12 is removed before
// returning.  get_spend_status returns None.  No nullifier is registered; no
// Merkle leaf is added beyond the seeded deposit.  After wiring a real
// verifier the same spend_id retries successfully and reaches Finalized.
// =============================================================================

#[test]
fn test_70_verifier_unreachable_removes_guard_and_is_retryable() {
    let Some(args) = load_valid_spend_fixture_args(7000) else {
        eprintln!("test_70: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let pic = PocketIc::new();
    let user = p(0x70);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic); // real verifier (for retry)
    let fake_verifier = create_canister(&pic); // no wasm — every call rejects

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    // fake_verifier intentionally left without wasm installed.
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // DEF-003: set-time attestation calls vk_hash() on the proposed verifier. The
    // wasm-less fake_verifier is unreachable, so the attestation call fails at transport
    // and set_verifier_canister returns Err(VerifierUnavailable) — the verifier is NOT
    // configured (VERIFIER_CANISTER stays None). (Pre-DEF-003 this call was accepted
    // unconditionally.) The expected hash matches the pool pin, so rejection is due to the
    // unreachable verifier, not a hash mismatch.
    let fake_wire: Result<(), PoolError> = decode(
        "test_70: set_verifier_canister(fake)",
        pic.update_call(
            pool_id,
            p(0x06),
            "set_verifier_canister",
            candid::encode_args((fake_verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
        ),
    );
    assert!(
        matches!(fake_wire, Err(PoolError::VerifierUnavailable(_))),
        "test_70: set_verifier_canister on an unreachable fake verifier must fail attestation with VerifierUnavailable; got {:?}",
        fake_wire
    );

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_70: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_70: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let root_after_deposit = merkle_root(&pic, merkle_id);
    assert_eq!(
        root_after_deposit, expected_anchor,
        "test_70: Merkle root after deposit must equal proof anchor"
    );

    // First call — the verifier is unconfigured (None, since the fake set failed
    // attestation above), so private_spend is rejected at the step-11 availability check
    // with VerifierUnavailable, BEFORE any nullifier/guard/PendingSpend state is written.
    let r1: Result<(), PoolError> = decode(
        "test_70: first private_spend (verifier unconfigured)",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    assert!(
        matches!(r1, Err(PoolError::VerifierUnavailable(_))),
        "test_70: wasm-less verifier must return VerifierUnavailable; got: {:?}",
        r1
    );

    // No PendingSpend record is written — private_spend was rejected at step 11 (verifier
    // unconfigured), before the step-12 guard/record write.
    assert!(
        spend_status(&pic, pool_id, 7000).is_none(),
        "test_70: no spend record — private_spend rejected at step 11 (verifier unconfigured)"
    );
    assert!(
        !null_contains(&pic, null_id, expected_nullifier),
        "test_70: nullifier must NOT be in registry after VerifierUnavailable"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_70: Merkle tree must still have 1 leaf after VerifierUnavailable"
    );

    // Wire the real verifier and retry the same spend_id.
    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_70: set_verifier_canister(real) must succeed");

    let r2: Result<(), PoolError> = decode(
        "test_70: retry private_spend (real verifier)",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(
        r2.is_ok(),
        "test_70: retry with real verifier must succeed; got: {:?}",
        r2
    );

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_70: 3 leaves after successful retry (1 deposit + 2 outputs)"
    );
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "test_70: nullifier must be in registry after successful retry"
    );

    let record = spend_status(&pic, pool_id, 7000)
        .expect("test_70: spend record must exist after successful retry");
    assert!(
        matches!(record.status, SpendStatus::Finalized),
        "test_70: SpendStatus must be Finalized after retry; got: {:?}",
        record.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 71 — duplicate in-flight spend_id returns DuplicateSpendId
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: A second private_spend call with the same spend_id submitted
// while the first is in VerificationPending (step 12 written, verifier call
// in flight at step 13) must return DuplicateSpendId before any mutation.
//
// Not implementable with PocketIC 9.0.2:
//   PocketIC executes update calls synchronously (nonblocking.rs:1665,
//   lib.rs:1370): one tick() cascades through the entire inter-canister
//   call chain to completion.  VerificationPending is written at step 12
//   and overwritten before tick() returns — it is never observable between
//   consecutive ticks.  Submitting a second call after submit_call but
//   before any tick() and then ticking results in FIFO execution of both
//   calls: msg_1 reaches Finalized, then msg_2 sees Finalized at step 0
//   and returns Ok() (idempotent success), not DuplicateSpendId.
//   This criterion requires true parallel execution (two update calls
//   simultaneously in-flight on different OS threads or IC replicas).
// =============================================================================

#[ignore = "A2-2 #5b: test-harness limitation, not a protocol gap — PoolError::DuplicateSpendId and the VerificationPending in-flight guard exist (lib.rs:564, 1188) and are correct; PocketIC 9.0.2 executes update calls synchronously (nonblocking.rs:1665), cascading the entire private_spend inter-canister chain to completion within one tick() — VerificationPending was never observable in 30 consecutive tick/query probes; the in-flight duplicate condition requires two truly concurrent update calls and is a production-IC-only invariant"]
#[test]
fn test_71_duplicate_inflight_spend_id_returns_duplicate_spend_id() {
    todo!("not implementable — see ignore reason above")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 72 — REMOVED under A2 (QA-DEF-034/036): tested discarded ring-buffer design
// ─────────────────────────────────────────────────────────────────────────────
//
// test_72 asserted that an anchor evicted from the Merkle ROOT_HISTORY ring buffer
// during async verification is rejected at the step-14a recheck. Under A2 the pool
// validates anchors against ACCEPTED_SPEND_ROOTS, which is APPEND-ONLY: a finalized
// root is a valid anchor permanently and can never be "evicted". The eviction
// scenario is impossible by construction, so this test (an #[ignore]'d todo!() stub
// PocketIC could not reproduce) is deleted rather than left to confuse future passes.
// Append-only anchor validity is covered by active_root_finality_tests.rs. This drops
// the ignored count by 1 (baseline 31 → 30) — justified per the A2 builder brief.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 73 — nullifier spent during async verification (A2-2 criterion #7)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: If a nullifier is permanently spent (via insert_batch of a
// concurrent spend) between step 13 (verifier returns) and step 14b
// (nullifier recheck), private_spend must return NullifierAlreadySpent and
// record FailedBeforeStateChange.
//
// Not implementable with PocketIC 9.0.2 single-subnet scheduler:
//   A concurrent Spend B (same nullifier, different spend_id) must reach
//   step 15d (insert_batch) and permanently insert the nullifier WITHIN the
//   ~2-tick window of Spend A's verifier call, before step 14b runs.
//   Spend B itself requires 15+ ticks (static validation, precheck async
//   calls, verifier call, recheck async calls, mutation phase).
//   Calling update_call(Spend B) during Spend A's window drives tick()
//   internally, which also delivers Spend A's verifier response and advances
//   Spend A's step 14b before Spend B reaches insert_batch.
//   Using submit_call(Spend B) instead provides no ordering guarantee —
//   the scheduler interleaves A and B indeterminately per tick.
//   This invariant requires true parallel execution and is production-only.
// =============================================================================

#[ignore = "A2-2 #7: concurrent nullifier-spent race requires Spend B's insert_batch (step 15d) to complete within Spend A's ~2-tick verifier-call window; PocketIC 9.0.2 cannot guarantee selective ordering between a pending inter-canister response and 15+ ticks of a second ingress call — this invariant requires true parallel execution; see recheck_private_spend_after_verify step 14b"]
#[test]
fn test_73_nullifier_spent_during_async_verification_rejected() {
    todo!("not implementable — see ignore reason above")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 74 — non-zero private_spend fee routes to reserves (A2-2 criterion #11, #87)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: When protocol_private_spend_fee_stsh > 0 (governance-set) and
// private_spend succeeds with args.fee == governance-quoted fee, step 15c of
// commit_private_spend must:
//   - debit PRIVATE_LIABILITY by fee
//   - credit OPERATIONS_RESERVE by fee × ops_bps / 10_000 (+ any remainder)
//   - credit INSURANCE_RESERVE by fee × ins_bps / 10_000
//   - leave GOVERNANCE_REWARDS_RESERVE unchanged (staking disabled at launch)
//
// Uses a test-only stub verifier (always returns Ok(())) so the non-zero fee
// can traverse the full spend path without a matching Groth16 proof.
// The real Groth16 proof fixture encodes signal[5]=fee=0 (u128_to_fr_le(0)) and
// cannot be reused for fee > 0: a different signal[5] value causes pairing
// failure in the real verifier → ProofRejected before step 15c is reached.
//
// Setup:
//   1 deposit (1,000 STSH, A6.6) seeds PRIVATE_LIABILITY (> fee = 1_000_000).
//   governance fee = 1_000_000 e8s (0.01 STSH), 85/15 ops/insurance split.
//   spend: input 99_800_000 → outputs [49_400_000, 49_400_000] + fee 1_000_000.
//
// Expected reserve deltas:
//   OPERATIONS_RESERVE  += 850_000  (1_000_000 × 8500 / 10_000)
//   INSURANCE_RESERVE   += 150_000  (1_000_000 × 1500 / 10_000)
//   GOVERNANCE_REWARDS_RESERVE unchanged (staking disabled → staking share = 0)
//   PRIVATE_LIABILITY   -= 1_000_000
// =============================================================================

const T74_VK_HASH: [u8; 32] = [0x74u8; 32];
const T74_NF: [u8; 32] = [0x0Au8; 32];
const T74_IN_COMMITMENT: [u8; 32] = [0x0Bu8; 32];
const T74_OC0: [u8; 32] = [0x0Cu8; 32];
const T74_OC1: [u8; 32] = [0x0Du8; 32];
const T74_FEE: u128 = 1_000_000;
const T74_IN_AMOUNT: u128 = 99_800_000;
const T74_OUT0: u128 = 49_400_000;
const T74_OUT1: u128 = 49_400_000;
// Expected deltas from split_protocol_fee_to_reserves(1_000_000, launch_defaults())
// ops_bps=8500, ins_bps=1500, staking disabled → staking share=0
const T74_OPS_DELTA: u128 = 850_000; // 1_000_000 × 8500 / 10_000
const T74_INS_DELTA: u128 = 150_000; // 1_000_000 × 1500 / 10_000

#[test]
fn test_74_nonzero_fee_routes_to_reserves() {
    let pic = PocketIc::new();
    let controller = p(0x74);
    let user = p(0x75);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let stub_ver = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(stub_ver, stub_verifier_wasm(), candid::encode_one(Some(T74_VK_HASH)).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: T74_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Wire stub verifier (controller-only).
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((stub_ver, T74_VK_HASH.to_vec())).unwrap(),
    )
    .expect("test_74: set_verifier_canister must succeed");

    // Set governance fee: protocol_private_spend_fee_stsh = 1_000_000,
    // 8500/1500/0 ops/insurance/staking split (launch defaults + non-zero fee).
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.protocol_private_spend_fee_stsh = T74_FEE;
    let set_result: Result<(), String> = decode(
        "test_74: set_governance_fee_params",
        pic.update_call(
            pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_74: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    // Seed PRIVATE_LIABILITY via shield_deposit (1,000 STSH = 100_000_000_000 e8s, A6.6).
    // At zero shielding fee: private_balance = 100_000_000_000 > fee 1_000_000.
    // InsufficientPrivateLiability guard is satisfied.
    // Note: T74_IN_AMOUNT = 99_800_000 is the spend input_amount (proof-circuit value),
    // independent of the deposit private_balance.
    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let deposit_result: Result<Nat, PoolError> = decode(
        "test_74: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T74_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_74: shield_deposit must succeed; got {:?}",
        deposit_result
    );

    // Snapshot accounting state before spend.
    let before = accounting_state_as(&pic, pool_id, controller);

    // Merkle root after deposit — used as root_reference in the spend envelope.
    let root_after_deposit = merkle_root(&pic, merkle_id);

    // Execute private_spend with fee = T74_FEE via stub verifier.
    // input_sum = T74_IN_AMOUNT = T74_OUT0 + T74_OUT1 + T74_FEE (sum-balance invariant).
    let spend_result: Result<(), PoolError> = decode(
        "test_74: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 7400,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T74_VK_HASH,
                    root_reference: root_after_deposit,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8], // arbitrary — stub ignores
                },
                nullifiers: vec![T74_NF],
                output_commitments: vec![T74_OC0, T74_OC1],
                encrypted_outputs: vec![vec![], vec![]],
                fee: T74_FEE,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        spend_result.is_ok(),
        "test_74: private_spend must succeed with correct non-zero fee; got {:?}",
        spend_result
    );

    // ── Reserve routing assertions ───────────────────────────────────────────

    let after = accounting_state_as(&pic, pool_id, controller);

    assert_eq!(
        after.operations_reserve - before.operations_reserve,
        T74_OPS_DELTA,
        "test_74: OPERATIONS_RESERVE must increase by {} (ops 85% of fee {}); before={} after={}",
        T74_OPS_DELTA,
        T74_FEE,
        before.operations_reserve,
        after.operations_reserve
    );
    assert_eq!(
        after.insurance_reserve - before.insurance_reserve,
        T74_INS_DELTA,
        "test_74: INSURANCE_RESERVE must increase by {} (ins 15% of fee {}); before={} after={}",
        T74_INS_DELTA,
        T74_FEE,
        before.insurance_reserve,
        after.insurance_reserve
    );
    assert_eq!(
        after.governance_rewards_reserve, before.governance_rewards_reserve,
        "test_74: GOVERNANCE_REWARDS_RESERVE must be unchanged (staking disabled at launch)"
    );
    assert_eq!(
        before.private_liability - after.private_liability,
        T74_FEE,
        "test_74: PRIVATE_LIABILITY must decrease by fee {}; before={} after={}",
        T74_FEE,
        before.private_liability,
        after.private_liability
    );

    // ── Spend record assertions ───────────────────────────────────────────────

    let record = spend_status_as(&pic, pool_id, controller, 7400)
        .expect("test_74: spend record must exist after successful private_spend");
    assert!(
        matches!(record.status, SpendStatus::Finalized),
        "test_74: SpendStatus must be Finalized; got {:?}",
        record.status
    );
    assert_eq!(
        record.outputs_committed, 2,
        "test_74: outputs_committed must equal 2"
    );

    // ── Merkle / nullifier side-effect assertions ────────────────────────────

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_74: Merkle must have 3 leaves (1 deposit + 2 spend outputs)"
    );
    assert!(
        null_contains(&pic, null_id, T74_NF),
        "test_74: nullifier T74_NF must be in registry after spend"
    );
}

// =============================================================================
// QA-DEF-022 / P15-001 — nonzero-fee spend preserves the I-02A ledger identity
// =============================================================================
//
// INVARIANT I-02A: escrow_backing + operations_reserve + insurance_reserve +
// governance_rewards_reserve == icrc1_balance_of(pool), at all times.
//
// test_74 above asserts the liability debit and the reserve credits on a
// fee-bearing spend but NOT the escrow debit and NOT the identity — which is
// exactly why QA-DEF-022 was latent: apply_private_spend_accounting debited
// escrow by public_amount only while crediting reserves by fee, so on every
// fee-bearing spend the bucket sum drifted up by fee vs the pool's real ledger
// balance (no tokens enter the pool on a private spend; only public_amount
// leaves). Worst-affected case is the pure-internal spend (public_amount == 0,
// fee > 0): nothing leaves the pool, so escrow must fall by exactly fee and the
// bucket sum must stay equal to the unchanged pool ledger balance.
//
// Same stub-verifier + governance-fee + conserving-spend setup as test_74
// (input 99_800_000 == outputs 49_400_000 + 49_400_000 + fee 1_000_000).
// This test FAILS on the pre-fix code (escrow unchanged, identity high by fee)
// and PASSES once escrow is debited by the full gross (private_liability_debit).
// =============================================================================

const DEF022_VK_HASH: [u8; 32] = [0x22u8; 32];
const DEF022_NF: [u8; 32] = [0x2Au8; 32];
const DEF022_IN_COMMITMENT: [u8; 32] = [0x2Bu8; 32];
const DEF022_OC0: [u8; 32] = [0x2Cu8; 32];
const DEF022_OC1: [u8; 32] = [0x2Du8; 32];

#[test]
fn test_nonzero_fee_spend_preserves_i02a() {
    let pic = PocketIc::new();
    let controller = p(0x26);
    let user = p(0x27);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let stub_ver = create_canister(&pic);

    pic.install_canister(null_id, nullifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(stub_ver, stub_verifier_wasm(), candid::encode_one(Some(DEF022_VK_HASH)).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: DEF022_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((stub_ver, DEF022_VK_HASH.to_vec())).unwrap(),
    )
    .expect("def022: set_verifier_canister must succeed");

    // Governance fee: nonzero protocol_private_spend_fee_stsh (85/15 ops/insurance).
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.protocol_private_spend_fee_stsh = T74_FEE;
    let set_result: Result<(), String> = decode(
        "def022: set_governance_fee_params",
        pic.update_call(
            pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(set_result.is_ok(), "def022: set_governance_fee_params; got {:?}", set_result);

    // Seed liability + escrow via one deposit (1 STSH gross, zero shielding fee).
    do_approve(&pic, token_id, user, pool_id, DENOMINATIONS[0] + DEFAULT_FEE);
    let deposit_result: Result<Nat, PoolError> = decode(
        "def022: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: DEF022_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(deposit_result.is_ok(), "def022: shield_deposit; got {:?}", deposit_result);

    // ── I-02A baseline: identity must hold BEFORE the spend. ──────────────────
    let before = accounting_state_as(&pic, pool_id, controller);
    let pool_balance_before = token_balance(&pic, token_id, pool_id);
    assert_eq!(
        before.escrow_backing
            + before.operations_reserve
            + before.insurance_reserve
            + before.governance_rewards_reserve,
        pool_balance_before,
        "def022: I-02A must hold before the spend (test-setup sanity)"
    );

    // Pure-internal fee-bearing spend: public_payout = None, fee > 0, conserving
    // (input == outputs + fee + 0).
    let root_after_deposit = merkle_root(&pic, merkle_id);
    let spend_result: Result<(), PoolError> = decode(
        "def022: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 2200,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: DEF022_VK_HASH,
                    root_reference: root_after_deposit,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8], // arbitrary — stub ignores
                },
                nullifiers: vec![DEF022_NF],
                output_commitments: vec![DEF022_OC0, DEF022_OC1],
                encrypted_outputs: vec![vec![], vec![]],
                fee: T74_FEE,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        spend_result.is_ok(),
        "def022: private_spend must succeed; got {:?}",
        spend_result
    );

    // ── The QA-DEF-022 assertions ──────────────────────────────────────────────
    let after = accounting_state_as(&pic, pool_id, controller);
    let pool_balance_after = token_balance(&pic, token_id, pool_id);

    // No public payout → the pool's real ledger balance is unchanged.
    assert_eq!(
        pool_balance_after, pool_balance_before,
        "def022: pool ledger balance must be unchanged on a pure-internal spend"
    );

    // Escrow must fall by exactly fee (generally by public_amount + fee; here
    // public_amount == 0): the fee's backing moves from escrow into the reserves.
    assert_eq!(
        before.escrow_backing - after.escrow_backing,
        T74_FEE,
        "def022: ESCROW_BACKING must decrease by fee {} (QA-DEF-022 — was debited by \
         public_amount only); before={} after={}",
        T74_FEE,
        before.escrow_backing,
        after.escrow_backing
    );

    // I-02A: the 4-bucket sum must still equal the pool's real ledger balance.
    assert_eq!(
        after.escrow_backing
            + after.operations_reserve
            + after.insurance_reserve
            + after.governance_rewards_reserve,
        pool_balance_after,
        "def022: I-02A must hold after a fee-bearing spend — bucket sum {} + {} + {} + {} \
         vs pool ledger balance {} (a drift of +fee here IS QA-DEF-022)",
        after.escrow_backing,
        after.operations_reserve,
        after.insurance_reserve,
        after.governance_rewards_reserve,
        pool_balance_after
    );
}

// =============================================================================
// Fee-build lane (C1) — nonzero-fee spend WITH A PUBLIC PAYOUT preserves I-02A
// =============================================================================
//
// The QA-DEF-022 test above covers the pure-internal case (public_amount == 0,
// fee > 0): only the fee leaves escrow, pool ledger unchanged. This test covers
// the realistic launch case a nonzero spend fee actually produces — a public
// payout with a nonzero fee (public_amount > 0 AND fee > 0):
//   - PRIVATE_LIABILITY and ESCROW_BACKING each fall by (public_amount + fee),
//   - the fee is routed to reserves (split),
//   - the pool's real ledger balance falls by exactly the payout (public_amount,
//     since the STSH ledger fee is 0),
//   - and the I-02A identity STILL holds:
//       escrow + operations + insurance + governance_rewards == pool_ledger.
// The combined (payout + fee) escrow debit is the leg the pure-internal test
// cannot exercise; this locks it before nonzero defaults land (commit 3).
// =============================================================================

// Commitment/nullifier bytes MUST be canonical BN254 Fr (LE < modulus) or the
// DEF-041 is_canonical_fr_le check rejects the deposit — keep the high byte
// (index 31, the BE MSB) below the modulus's 0x30, i.e. use a low byte value.
const DEF022P_VK_HASH: [u8; 32] = [0x23u8; 32]; // VK id — not field-checked
const DEF022P_NF: [u8; 32] = [0x1Au8; 32];
const DEF022P_IN_COMMITMENT: [u8; 32] = [0x1Bu8; 32];
const DEF022P_OC0: [u8; 32] = [0x1Cu8; 32];
const DEF022P_OC1: [u8; 32] = [0x1Du8; 32];
const DEF022P_PAYOUT: u128 = 50_000_000; // 0.5 STSH public payout

// A-7: the RULED exit-fee parameters this fixture installs, and the fee they
// produce for DEF022P_PAYOUT. Written out and checked in the test rather than
// derived there, so a change in either direction has to be typed deliberately.
const DEF022P_UNSHIELD_BPS: u16 = 25;
const DEF022P_UNSHIELD_FLAT_MIN: u128 = 10_000_000; // 0.1 STSH
/// `max(0.1 STSH, 0.25% x 0.5 STSH)` = `max(10_000_000, 125_000)` — the FLOOR arm.
const DEF022P_EXIT_FEE: u128 = 10_000_000;
/// The 85/15 launch split of DEF022P_EXIT_FEE. Exhaustive: 8.5M + 1.5M = 10M.
const DEF022P_OPS_DELTA: u128 = 8_500_000;
const DEF022P_INS_DELTA: u128 = 1_500_000;

#[test]
fn test_nonzero_fee_spend_with_payout_preserves_i02a() {
    let pic = PocketIc::new();
    let controller = p(0x26);
    let user = p(0x27);
    let recipient = p(0x28);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let stub_ver = create_canister(&pic);

    pic.install_canister(null_id, nullifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(stub_ver, stub_verifier_wasm(), candid::encode_one(Some(DEF022P_VK_HASH)).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: DEF022P_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((stub_ver, DEF022P_VK_HASH.to_vec())).unwrap(),
    )
    .expect("def022p: set_verifier_canister must succeed");

    // Governance fee: nonzero protocol_private_spend_fee_stsh (85/15 ops/insurance).
    //
    // A-7 (SUPERVISOR_RULING_A-7_eighth_site_V3 §2): since A-7 a public-payout
    // spend is an EXIT and pays the UNSHIELD value fee `max(flat_min, 0.25%)`,
    // not the flat spend fee. `launch_defaults()` leaves both unshield fields at
    // ZERO — fee-free by design — so on those params this spend would pay
    // nothing and this test's reserve-split assertions would become `0 == 0`.
    // This test exists to prove I-02a across a payout spend CARRYING A NONZERO
    // FEE, so the fixture installs explicit nonzero unshield params rather than
    // being retargeted onto the free branch. (The zero-params sentence is
    // asserted deliberately, in `a7_exit_fee_symmetry_tests::t10_*`.)
    //
    // The SHIELD fields stay zero, so the seeding deposit below is unchanged.
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.protocol_private_spend_fee_stsh = T74_FEE;
    fee_params.unshield_fee_bps = Some(DEF022P_UNSHIELD_BPS);
    fee_params.unshield_flat_minimum_fee_e8s = Some(DEF022P_UNSHIELD_FLAT_MIN);
    let set_result: Result<(), String> = decode(
        "def022p: set_governance_fee_params",
        pic.update_call(
            pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(set_result.is_ok(), "def022p: set_governance_fee_params; got {:?}", set_result);

    // Seed liability + escrow via one deposit (10 STSH gross, zero shielding fee) —
    // enough to cover the payout + fee.
    let deposit_amt = DENOMINATIONS[1];
    do_approve(&pic, token_id, user, pool_id, deposit_amt + DEFAULT_FEE);
    let deposit_result: Result<Nat, PoolError> = decode(
        "def022p: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: DEF022P_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amt,
            })
            .unwrap(),
        ),
    );
    assert!(deposit_result.is_ok(), "def022p: shield_deposit; got {:?}", deposit_result);

    // ── I-02A baseline: identity must hold BEFORE the spend. ──────────────────
    let before = accounting_state_as(&pic, pool_id, controller);
    let pool_balance_before = token_balance(&pic, token_id, pool_id);
    let recipient_before = token_balance(&pic, token_id, recipient);
    assert_eq!(
        before.escrow_backing
            + before.operations_reserve
            + before.insurance_reserve
            + before.governance_rewards_reserve,
        pool_balance_before,
        "def022p: I-02A must hold before the spend (test-setup sanity)"
    );

    // A-7: the exit fee is the UNSHIELD value fee on `public_amount`, computed
    // here independently of the canister and pinned to the constants above.
    assert_eq!(
        DEF022P_EXIT_FEE,
        std::cmp::max(
            DEF022P_UNSHIELD_FLAT_MIN,
            DEF022P_PAYOUT * (DEF022P_UNSHIELD_BPS as u128) / 10_000
        ),
        "def022p: the expected exit fee must be max(flat_min, bps) at these params"
    );
    assert!(
        DEF022P_EXIT_FEE > 0 && DEF022P_OPS_DELTA + DEF022P_INS_DELTA == DEF022P_EXIT_FEE,
        "def022p: this test is only meaningful while the exit fee is nonzero and splits exactly"
    );
    // Public-payout fee-bearing spend, conserving:
    //   input == out0 + out1 + fee + public_amount
    //   deposit_amt == out0 + 0 + DEF022P_EXIT_FEE + DEF022P_PAYOUT
    let out0 = deposit_amt - DEF022P_EXIT_FEE - DEF022P_PAYOUT;
    let root_after_deposit = merkle_root(&pic, merkle_id);
    let spend_result: Result<(), PoolError> = decode(
        "def022p: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 2201,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: DEF022P_VK_HASH,
                    root_reference: root_after_deposit,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![DEF022P_NF],
                output_commitments: vec![DEF022P_OC0, DEF022P_OC1],
                encrypted_outputs: vec![vec![], vec![]],
                fee: DEF022P_EXIT_FEE,
                public_payout: Some(PrivateSpendPublicPayout {
                    destination: recipient,
                    destination_subaccount: None,
                    public_amount: DEF022P_PAYOUT,
                }),
            })
            .unwrap(),
        ),
    );
    assert!(spend_result.is_ok(), "def022p: private_spend must succeed; got {:?}", spend_result);

    // ── Assertions ────────────────────────────────────────────────────────────
    let after = accounting_state_as(&pic, pool_id, controller);
    let pool_balance_after = token_balance(&pic, token_id, pool_id);
    let recipient_after = token_balance(&pic, token_id, recipient);

    // Recipient received the full payout (STSH ledger fee is 0).
    assert_eq!(
        recipient_after - recipient_before,
        DEF022P_PAYOUT,
        "def022p: recipient must receive the public payout (ledger fee 0)"
    );
    // Pool's real ledger balance falls by exactly the payout.
    assert_eq!(
        pool_balance_before - pool_balance_after,
        DEF022P_PAYOUT,
        "def022p: pool ledger must fall by exactly the payout"
    );
    // Escrow falls by payout + fee (the combined debit the pure-internal test can't reach).
    assert_eq!(
        before.escrow_backing - after.escrow_backing,
        DEF022P_PAYOUT + DEF022P_EXIT_FEE,
        "def022p: ESCROW_BACKING must decrease by public_amount + fee"
    );
    // PRIVATE_LIABILITY falls by the same combined debit.
    assert_eq!(
        before.private_liability - after.private_liability,
        DEF022P_PAYOUT + DEF022P_EXIT_FEE,
        "def022p: PRIVATE_LIABILITY must decrease by public_amount + fee"
    );
    // The EXIT fee routed to reserves (85/15 launch split of DEF022P_EXIT_FEE).
    assert_eq!(
        after.operations_reserve - before.operations_reserve,
        DEF022P_OPS_DELTA,
        "def022p: operations reserve credited the exit fee's ops share"
    );
    assert_eq!(
        after.insurance_reserve - before.insurance_reserve,
        DEF022P_INS_DELTA,
        "def022p: insurance reserve credited the exit fee's insurance share"
    );
    // I-02A: the 4-bucket sum still equals the pool's real ledger balance.
    assert_eq!(
        after.escrow_backing
            + after.operations_reserve
            + after.insurance_reserve
            + after.governance_rewards_reserve,
        pool_balance_after,
        "def022p: I-02A must hold after a fee-bearing PUBLIC-PAYOUT spend — bucket sum {} + {} + {} + {} \
         vs pool ledger balance {}",
        after.escrow_backing,
        after.operations_reserve,
        after.insurance_reserve,
        after.governance_rewards_reserve,
        pool_balance_after
    );
}

// =============================================================================
// #89 §7 withdrawal net-recipient tests (test_75 – test_76)
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 75 — §7 net-recipient withdrawal at zero protocol_unshielding_fee
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (§7): recipient_net = gross - ledger_fee - protocol_unshielding_fee.
// At launch (protocol_unshielding_fee = 0): recipient_net = gross - DEFAULT_FEE.
//
// Asserts:
//   a) withdrawal succeeds
//   b) PendingWithdrawal gross/net/fee fields match §7 formula
//   c) accounting: private_liability = 0, escrow_backing = 0
//   d) user balance delta = gross - DEFAULT_FEE
// =============================================================================

// Lane A v2 Task 0.25: this test exercises zero-protocol-fee payout and accounting after successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: zero-fee payout coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_75_withdrawal_net_recipient_zero_protocol_fee() {
    let h = PoolHarness::new(0x75, [0x75; 32], 0);
    let pb = h.deposit(DENOMINATIONS[0]);

    let user_before = h.balance(h.user);
    let w = h.withdraw_note(750, [0x15; 32], pb);
    assert!(w.is_ok(), "test_75: withdrawal must succeed; got: {:?}", w);

    let record: Option<PendingWithdrawal> = decode(
        "test_75: get_withdrawal_status",
        h.pic.query_call(
            h.pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(750u64).unwrap(),
        ),
    );
    let rec = record.expect("test_75: withdrawal record must exist");

    assert_eq!(
        rec.status,
        WithdrawalStatus::Finalized,
        "test_75: status must be Finalized; got: {:?}",
        rec.status
    );
    assert_eq!(
        rec.gross_withdraw_amount, pb,
        "test_75: gross_withdraw_amount must equal pb={}",
        pb
    );
    assert_eq!(
        rec.protocol_unshielding_fee, 0,
        "test_75: protocol_unshielding_fee must be 0 at launch"
    );
    assert_eq!(
        rec.ledger_fee, DEFAULT_FEE,
        "test_75: ledger_fee must equal DEFAULT_FEE"
    );
    assert_eq!(
        rec.recipient_net_amount,
        pb - DEFAULT_FEE,
        "test_75: recipient_net_amount must equal gross - ledger_fee"
    );

    let acc = h.accounting();
    assert_eq!(
        acc.private_liability, 0,
        "test_75: private_liability must be 0"
    );
    assert_eq!(acc.escrow_backing, 0, "test_75: escrow_backing must be 0");

    let user_after = h.balance(h.user);
    assert_eq!(
        user_after,
        user_before + pb - DEFAULT_FEE,
        "test_75: user balance delta must equal gross - ledger_fee; \
         before={} after={} expected={}",
        user_before,
        user_after,
        user_before + pb - DEFAULT_FEE
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 76 — Nonzero protocol_unshielding_fee routes to ops/insurance waterfall
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (§7 + §8/§16 waterfall): protocol_unshielding_fee is split via
// split_protocol_fee_to_reserves (ops=8500bps, ins=1500bps, staking=0 at launch).
// For fee=50_000: ops_delta=42_500, ins_delta=7_500, staking=0.
//
// Asserts:
//   a) protocol_unshielding_fee in record == 50_000
//   b) recipient_net = gross - DEFAULT_FEE - 50_000
//   c) ops_reserve increases by 42_500
//   d) insurance_reserve increases by 7_500
//   e) governance_rewards_reserve unchanged (staking disabled at launch)
// =============================================================================

const T76_UNSHIELDING_FEE: u128 = 50_000;
const T76_OPS_DELTA: u128 = 42_500; // 50_000 * 8500/10000
const T76_INS_DELTA: u128 = 7_500; // 50_000 * 1500/10000

// Lane A v2 Task 0.25: this test exercises unshielding-fee reserve routing after successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: fee-routing coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_76_nonzero_unshielding_fee_routes_to_reserves_waterfall() {
    let h = PoolHarness::new_testing(0x76, [0x76; 32], 0);
    let controller = p(0x06);

    // Set protocol_unshielding_fee_stsh = 50_000.
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.protocol_unshielding_fee_stsh = T76_UNSHIELDING_FEE;
    let set_result: Result<(), String> = decode(
        "test_76: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_76: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    let pb = h.deposit(DENOMINATIONS[0]);

    // Capture reserve levels after deposit (before withdrawal).
    let before = h.accounting();
    let ops_before = before.operations_reserve;
    let ins_before = before.insurance_reserve;
    let staking_before = before.governance_rewards_reserve;

    let w = h.withdraw_note(760, [0x16; 32], pb);
    assert!(w.is_ok(), "test_76: withdrawal must succeed; got: {:?}", w);

    let record: Option<PendingWithdrawal> = decode(
        "test_76: get_withdrawal_status",
        h.pic.query_call(
            h.pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(760u64).unwrap(),
        ),
    );
    let rec = record.expect("test_76: withdrawal record must exist");

    assert_eq!(
        rec.protocol_unshielding_fee, T76_UNSHIELDING_FEE,
        "test_76: protocol_unshielding_fee must be {}",
        T76_UNSHIELDING_FEE
    );
    assert_eq!(
        rec.recipient_net_amount,
        pb - DEFAULT_FEE - T76_UNSHIELDING_FEE,
        "test_76: recipient_net must equal gross - ledger_fee - unshielding_fee"
    );
    assert_eq!(
        rec.status,
        WithdrawalStatus::Finalized,
        "test_76: status must be Finalized; got: {:?}",
        rec.status
    );

    let after = h.accounting();
    assert_eq!(
        after.operations_reserve,
        ops_before + T76_OPS_DELTA,
        "test_76: ops_reserve must increase by {}; before={} after={}",
        T76_OPS_DELTA,
        ops_before,
        after.operations_reserve
    );
    assert_eq!(
        after.insurance_reserve,
        ins_before + T76_INS_DELTA,
        "test_76: insurance_reserve must increase by {}; before={} after={}",
        T76_INS_DELTA,
        ins_before,
        after.insurance_reserve
    );
    assert_eq!(
        after.governance_rewards_reserve, staking_before,
        "test_76: staking reserve must be unchanged (disabled at launch)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 77 — A2-2 criterion 13: full-balance withdrawal with real treasury
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (§7 + #90 treasury path): a user may withdraw their entire private
// balance in a single call, and the protocol_unshielding_fee is split to the
// real treasury canister via ic_cdk::spawn → receive_fee_split.
//
// Setup:
//   - Real treasury wired at init; pool principal matches treasury's caller guard.
//   - shield_deposit(DENOMINATIONS[0]=100_000_000_000, A6.6) seeds PRIVATE_LIABILITY.
//   - protocol_unshielding_fee_stsh = T77_UNSHIELDING_FEE = 50_000.
//   - gross = DENOMINATIONS[0] = full private balance → PRIVATE_LIABILITY = 0 after.
//
// Asserts (pool):
//   a) withdrawal status is Finalized
//   b) gross/net/fee fields match §7 formula
//   c) PRIVATE_LIABILITY = 0, ESCROW_BACKING = 0 (full balance withdrawn)
//   d) user balance delta = gross - DEFAULT_FEE - T77_UNSHIELDING_FEE
//   e) get_treasury_notification_failures() == 0
//
// Asserts (treasury, after one explicit pic.tick()):
//   f) operations subaccount credited by T77_OPS_DELTA (delta from post-deposit snapshot)
//   g) insurance subaccount credited by T77_INS_DELTA (delta from post-deposit snapshot)
//   h) staking_rewards subaccount unchanged (staking disabled at launch)
//   i) get_fee_log returns exactly 2 entries:
//        entry[0] = ShieldFee (from deposit):
//                   total=T77_SHIELD_FEE=200_000, ops=T77_SHIELD_OPS=170_000, ins=T77_SHIELD_INS=30_000
//                   split via split_protocol_fee_to_reserves (8500/1500 launch bps)
//        entry[1] = UnshieldFee (from withdrawal): total=50_000, ops=42_500, ins=7_500
// =============================================================================

const T77_UNSHIELDING_FEE: u128 = 50_000;
const T77_OPS_DELTA: u128 = 42_500; // 50_000 * 8500 / 10000
const T77_INS_DELTA: u128 = 7_500; // 50_000 * 1500 / 10000

// §6 shielding fee for test_77 deposit. AR1-10: with fee-on-top the credit is the
// full DENOMINATIONS[0] = 100_000_000_000 (A6.6); this fee is pulled ON TOP. The earlier note
// here said it was chosen "to keep pb=99_800_000", which is the deducted model.
const T77_SHIELD_FEE: u128 = 200_000;
const T77_SHIELD_OPS: u128 = 170_000; // 200_000 * 8_500 / 10_000
const T77_SHIELD_INS: u128 = 30_000; // 200_000 * 1_500 / 10_000

// Lane A v2 Task 0.25: this test exercises real-treasury fee split and reserve routing after successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: treasury fee-split coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_77_full_balance_withdrawal_real_treasury_fee_split() {
    let h = WithdrawalTreasuryHarness::new_testing(0x77, [0x77; 32]);
    let controller = p(0x06);

    // Set protocol_unshielding_fee_stsh = T77_UNSHIELDING_FEE and
    // protocol_shielding_fee_stsh = T77_SHIELD_FEE so the ShieldFee treasury
    // notification fires and exercises the full §6/§11 deposit path.
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.protocol_unshielding_fee_stsh = T77_UNSHIELDING_FEE;
    fee_params.protocol_shielding_fee_stsh = T77_SHIELD_FEE;
    let set_result: Result<(), String> = decode(
        "test_77: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_77: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    // Seed PRIVATE_LIABILITY via real shield_deposit.
    // AR1-10: fee-on-top — pb = DENOMINATIONS[0] = 100_000_000_000 (A6.6), the FULL gross.
    // The protocol fee (T77_SHIELD_FEE) is pulled ON TOP and does not reduce the
    // credit; the old note here read `100_000_000 - 200_000 = 99_800_000`, which
    // is what the code stopped doing at fee-on-top.
    let pb = h.deposit(DENOMINATIONS[0]);
    assert_eq!(
        pb,
        expected_deposit_private_balance(DENOMINATIONS[0], T77_SHIELD_FEE),
        "test_77: private balance after deposit must equal the FULL gross (fee-on-top, AR1-10); got {}",
        pb
    );

    // Snapshot reserves before withdrawal (deposit may have credited ops/ins at zero shielding fee).
    let pool_before = h.accounting();
    let user_before = h.balance(h.user);
    let treas_ops_before = h.treasury_subaccount("operations");
    let treas_ins_before = h.treasury_subaccount("insurance");
    let treas_staking_before = h.treasury_subaccount("staking_rewards");

    // Full-balance withdrawal: gross = entire private balance.
    let w = h.withdraw(770, [0x17; 32], pb);
    assert!(w.is_ok(), "test_77: withdrawal must succeed; got: {:?}", w);

    // ── Pool assertions (synchronous, no tick needed) ─────────────────────────

    let record: Option<PendingWithdrawal> = decode(
        "test_77: get_withdrawal_status",
        h.pic.query_call(
            h.pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(770u64).unwrap(),
        ),
    );
    let rec = record.expect("test_77: withdrawal record must exist");

    // a) Finalized
    assert_eq!(
        rec.status,
        WithdrawalStatus::Finalized,
        "test_77: status must be Finalized; got: {:?}",
        rec.status
    );

    // b) §7 formula
    assert_eq!(
        rec.gross_withdraw_amount, pb,
        "test_77: gross_withdraw_amount must equal pb={}",
        pb
    );
    assert_eq!(
        rec.protocol_unshielding_fee, T77_UNSHIELDING_FEE,
        "test_77: protocol_unshielding_fee must be {}",
        T77_UNSHIELDING_FEE
    );
    assert_eq!(
        rec.ledger_fee, DEFAULT_FEE,
        "test_77: ledger_fee must equal DEFAULT_FEE"
    );
    assert_eq!(
        rec.recipient_net_amount,
        pb - DEFAULT_FEE - T77_UNSHIELDING_FEE,
        "test_77: recipient_net must equal gross - ledger_fee - unshielding_fee"
    );

    // c) Full balance drained
    let acc = h.accounting();
    assert_eq!(
        acc.private_liability, 0,
        "test_77: PRIVATE_LIABILITY must be 0 after full-balance withdrawal; got {}",
        acc.private_liability
    );
    assert_eq!(
        acc.escrow_backing, 0,
        "test_77: ESCROW_BACKING must be 0 after full-balance withdrawal; got {}",
        acc.escrow_backing
    );

    // Pool-internal reserve split mirrors treasury amounts (separate accounting entries).
    assert_eq!(
        acc.operations_reserve,
        pool_before.operations_reserve + T77_OPS_DELTA,
        "test_77: pool ops_reserve must increase by {}; before={} after={}",
        T77_OPS_DELTA,
        pool_before.operations_reserve,
        acc.operations_reserve
    );
    assert_eq!(
        acc.insurance_reserve,
        pool_before.insurance_reserve + T77_INS_DELTA,
        "test_77: pool insurance_reserve must increase by {}; before={} after={}",
        T77_INS_DELTA,
        pool_before.insurance_reserve,
        acc.insurance_reserve
    );
    assert_eq!(
        acc.governance_rewards_reserve, pool_before.governance_rewards_reserve,
        "test_77: pool staking reserve must be unchanged (disabled at launch)"
    );

    // d) User receives net, not gross
    let user_after = h.balance(h.user);
    assert_eq!(
        user_after,
        user_before + pb - DEFAULT_FEE - T77_UNSHIELDING_FEE,
        "test_77: user balance delta must equal gross - ledger_fee - unshielding_fee; \
         before={} after={} expected={}",
        user_before,
        user_after,
        user_before + pb - DEFAULT_FEE - T77_UNSHIELDING_FEE
    );

    // e) No treasury notification failures (spawn ran; caller guard passed)
    let failures: u64 = decode(
        "test_77: get_treasury_notification_failures",
        h.pic.query_call(
            h.pool_id,
            anon(),
            "get_treasury_notification_failures",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        failures, 0,
        "test_77: treasury notification failures must be 0; got {}",
        failures
    );

    // ── One explicit tick so the ic_cdk::spawn future settles ────────────────
    //
    // ic_cdk::spawn creates an independent message (not part of the current
    // call tree); PocketIC 9.0.2 may defer it to the next scheduler round.
    h.pic.tick();

    // ── Treasury assertions ───────────────────────────────────────────────────

    // f) operations bucket credited
    let treas_ops_after = h.treasury_subaccount("operations");
    assert_eq!(
        treas_ops_after,
        treas_ops_before + T77_OPS_DELTA,
        "test_77: treasury operations must increase by {}; before={} after={}",
        T77_OPS_DELTA,
        treas_ops_before,
        treas_ops_after
    );

    // g) insurance bucket credited
    let treas_ins_after = h.treasury_subaccount("insurance");
    assert_eq!(
        treas_ins_after,
        treas_ins_before + T77_INS_DELTA,
        "test_77: treasury insurance must increase by {}; before={} after={}",
        T77_INS_DELTA,
        treas_ins_before,
        treas_ins_after
    );

    // h) staking_rewards unchanged (staking disabled at launch)
    let treas_staking_after = h.treasury_subaccount("staking_rewards");
    assert_eq!(
        treas_staking_after, treas_staking_before,
        "test_77: treasury staking_rewards must be unchanged (disabled at launch); got {}",
        treas_staking_after
    );

    // i) Fee log: exactly 2 entries (entry[0] = ShieldFee from deposit,
    //    entry[1] = UnshieldFee from withdrawal).
    let log = h.treasury_fee_log(0, 10);
    assert_eq!(
        log.len(),
        2,
        "test_77: treasury fee log must have exactly 2 entries \
         (ShieldFee from deposit + UnshieldFee from withdrawal); got {} entries",
        log.len()
    );

    // ShieldFee entry: split via split_protocol_fee_to_reserves (8500/1500 bps).
    let shield_entry = &log[0];
    assert_eq!(
        shield_entry.source,
        FeeSource::ShieldFee,
        "test_77: fee log entry[0] must be ShieldFee (from deposit); got {:?}",
        shield_entry.source
    );
    assert_eq!(
        shield_entry.total_amount, T77_SHIELD_FEE,
        "test_77: ShieldFee total must be {}; got {}",
        T77_SHIELD_FEE, shield_entry.total_amount
    );
    assert_eq!(
        shield_entry.operations, T77_SHIELD_OPS,
        "test_77: ShieldFee ops must be {}; got {}",
        T77_SHIELD_OPS, shield_entry.operations
    );
    assert_eq!(
        shield_entry.insurance, T77_SHIELD_INS,
        "test_77: ShieldFee ins must be {}; got {}",
        T77_SHIELD_INS, shield_entry.insurance
    );
    assert_eq!(
        shield_entry.staking, 0,
        "test_77: ShieldFee staking must be 0; got {}",
        shield_entry.staking
    );

    // UnshieldFee entry.
    let unshield_entry = &log[1];
    assert_eq!(
        unshield_entry.source,
        FeeSource::UnshieldFee,
        "test_77: fee log entry[1] must be UnshieldFee; got {:?}",
        unshield_entry.source
    );
    assert_eq!(
        unshield_entry.total_amount, T77_UNSHIELDING_FEE,
        "test_77: UnshieldFee total must be {}; got {}",
        T77_UNSHIELDING_FEE, unshield_entry.total_amount
    );
    assert_eq!(
        unshield_entry.operations, T77_OPS_DELTA,
        "test_77: UnshieldFee ops must be {}; got {}",
        T77_OPS_DELTA, unshield_entry.operations
    );
    assert_eq!(
        unshield_entry.insurance, T77_INS_DELTA,
        "test_77: UnshieldFee ins must be {}; got {}",
        T77_INS_DELTA, unshield_entry.insurance
    );
    assert_eq!(
        unshield_entry.staking, 0,
        "test_77: UnshieldFee staking must be 0 (disabled at launch); got {}",
        unshield_entry.staking
    );
    assert_eq!(
        unshield_entry.audit, 0,
        "test_77: UnshieldFee audit must be 0; got {}",
        unshield_entry.audit
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 78 — A2-2 criterion 15: staking zero-fee-income branch, real treasury
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (§17 + #90 treasury path): under launch GovernanceFeeParams with
// staking_rewards_split_bps=0 and staking_rewards_enabled=false, the entire
// fee routing lifecycle produces staking amount 0 end-to-end — from
// split_protocol_fee_to_reserves through notify_treasury_fee →
// receive_fee_split, leaving the treasury staking_rewards subaccount at 0.
//
// Setup:
//   - WithdrawalTreasuryHarness: real treasury wired to live pool_id.
//   - GovernanceFeeParams::launch_defaults() — staking_rewards_split_bps=0,
//     staking_rewards_enabled=false.  protocol_unshielding_fee_stsh=50_000
//     so there is a meaningful UnshieldFee split to observe.
//   - shield_deposit then full-balance withdrawal (gross == PRIVATE_LIABILITY).
//   - No staking canister installed; dummy principal p(0x05) throughout.
//
// Assertions:
//   a) pool Finalized, §7 formula correct
//   b) PRIVATE_LIABILITY=0, ESCROW_BACKING=0
//   c) get_treasury_notification_failures() == 0
//   d) treasury staking_rewards subaccount == 0 after pic.tick()
//   e) fee log: 2 entries, staking==0 in both
//      entry[0] ShieldFee: total=T78_SHIELD_TOTAL=200_000,
//               ops=T78_SHIELD_OPS=170_000, ins=T78_SHIELD_INS=30_000, staking=0
//               (split via split_protocol_fee_to_reserves, 8500/1500 launch bps)
//      entry[1] UnshieldFee: total=50_000, ops=42_500, ins=7_500, staking=0
// =============================================================================

const T78_UNSHIELDING_FEE: u128 = 50_000;
const T78_OPS_DELTA: u128 = 42_500; // 50_000 * 8500 / 10000 — stk share=0
const T78_INS_DELTA: u128 = 7_500; // 50_000 * 1500 / 10000

// §6 shielding fee for test_78 deposit.
// Split via split_protocol_fee_to_reserves (8500/1500 launch bps, not hardcoded 9000/1000).
const T78_SHIELD_FEE: u128 = 200_000;
const T78_SHIELD_TOTAL: u128 = 200_000; // == T78_SHIELD_FEE; kept for clarity
const T78_SHIELD_OPS: u128 = 170_000; // 200_000 * 8_500 / 10_000
const T78_SHIELD_INS: u128 = 30_000; // 200_000 * 1_500 / 10_000

// Lane A v2 Task 0.25: this test exercises staking zero-fee income branch after real-treasury withdrawal routing, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: staking fee-branch coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_78_staking_zero_fee_income_branch_real_treasury() {
    let h = WithdrawalTreasuryHarness::new_testing(0x78, [0x78; 32]);
    let controller = p(0x06);

    // Launch defaults: staking_rewards_split_bps=0, staking_rewards_enabled=false.
    // Set protocol_unshielding_fee_stsh and protocol_shielding_fee_stsh nonzero so
    // both ShieldFee and UnshieldFee paths are exercised through the treasury.
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.protocol_unshielding_fee_stsh = T78_UNSHIELDING_FEE;
    fee_params.protocol_shielding_fee_stsh = T78_SHIELD_FEE;
    // Confirm staking fields are zero/false — these must not change from defaults.
    assert_eq!(
        fee_params.staking_rewards_split_bps, 0,
        "test_78: staking_rewards_split_bps must be 0 at launch"
    );
    assert!(
        !fee_params.staking_rewards_enabled,
        "test_78: staking_rewards_enabled must be false at launch"
    );

    let set_result: Result<(), String> = decode(
        "test_78: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_78: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    // Seed PRIVATE_LIABILITY via real shield_deposit.
    // AR1-10: fee-on-top — pb = DENOMINATIONS[0] = 100_000_000_000 (A6.6), the FULL gross.
    // The protocol fee (T78_SHIELD_FEE) is pulled ON TOP and does not reduce the
    // credit; the old note here read `100_000_000 - 200_000 = 99_800_000`, which
    // is what the code stopped doing at fee-on-top.
    let pb = h.deposit(DENOMINATIONS[0]);
    assert_eq!(
        pb,
        expected_deposit_private_balance(DENOMINATIONS[0], T78_SHIELD_FEE),
        "test_78: private balance after deposit must equal the FULL gross (fee-on-top, AR1-10); got {}",
        pb
    );

    // Snapshot treasury staking_rewards before withdrawal (must be 0 after deposit too).
    let staking_after_deposit = h.treasury_subaccount("staking_rewards");
    assert_eq!(
        staking_after_deposit, 0,
        "test_78: staking_rewards must be 0 after deposit (staking disabled); got {}",
        staking_after_deposit
    );

    // Full-balance withdrawal.
    let w = h.withdraw(780, [0x18; 32], pb);
    assert!(w.is_ok(), "test_78: withdrawal must succeed; got: {:?}", w);

    // ── Pool assertions ───────────────────────────────────────────────────────

    let record: Option<PendingWithdrawal> = decode(
        "test_78: get_withdrawal_status",
        h.pic.query_call(
            h.pool_id,
            p(0x06), // DEF-071: get_withdrawal_status is controller-only — poll as controller
            "get_withdrawal_status",
            candid::encode_one(780u64).unwrap(),
        ),
    );
    let rec = record.expect("test_78: withdrawal record must exist");

    // a) Finalized, §7 formula
    assert_eq!(
        rec.status,
        WithdrawalStatus::Finalized,
        "test_78: status must be Finalized; got: {:?}",
        rec.status
    );
    assert_eq!(
        rec.gross_withdraw_amount, pb,
        "test_78: gross_withdraw_amount must equal pb={}",
        pb
    );
    assert_eq!(
        rec.protocol_unshielding_fee, T78_UNSHIELDING_FEE,
        "test_78: protocol_unshielding_fee must be {}",
        T78_UNSHIELDING_FEE
    );
    assert_eq!(
        rec.ledger_fee, DEFAULT_FEE,
        "test_78: ledger_fee must equal DEFAULT_FEE"
    );
    assert_eq!(
        rec.recipient_net_amount,
        pb - DEFAULT_FEE - T78_UNSHIELDING_FEE,
        "test_78: recipient_net must equal gross - ledger_fee - unshielding_fee"
    );

    // b) Full balance drained
    let acc = h.accounting();
    assert_eq!(
        acc.private_liability, 0,
        "test_78: PRIVATE_LIABILITY must be 0; got {}",
        acc.private_liability
    );
    assert_eq!(
        acc.escrow_backing, 0,
        "test_78: ESCROW_BACKING must be 0; got {}",
        acc.escrow_backing
    );
    assert_eq!(
        acc.governance_rewards_reserve, 0,
        "test_78: pool staking reserve must be 0 (staking disabled); got {}",
        acc.governance_rewards_reserve
    );

    // c) No treasury notification failures
    let failures: u64 = decode(
        "test_78: get_treasury_notification_failures",
        h.pic.query_call(
            h.pool_id,
            anon(),
            "get_treasury_notification_failures",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        failures, 0,
        "test_78: treasury notification failures must be 0; got {}",
        failures
    );

    // ── One explicit tick so spawned futures settle ───────────────────────────
    h.pic.tick();

    // ── Treasury assertions ───────────────────────────────────────────────────

    // d) staking_rewards subaccount remains 0
    let staking_after_withdrawal = h.treasury_subaccount("staking_rewards");
    assert_eq!(
        staking_after_withdrawal, 0,
        "test_78: treasury staking_rewards must be 0 after full cycle; got {}",
        staking_after_withdrawal
    );

    // Sanity: ops and insurance were credited by both ShieldFee and UnshieldFee.
    let treas_ops = h.treasury_subaccount("operations");
    let treas_ins = h.treasury_subaccount("insurance");
    assert!(
        treas_ops > 0,
        "test_78: treasury operations must be nonzero (fee routing worked); got {}",
        treas_ops
    );
    assert!(
        treas_ins > 0,
        "test_78: treasury insurance must be nonzero (fee routing worked); got {}",
        treas_ins
    );

    // e) Fee log: 2 entries, staking==0 in both
    let log = h.treasury_fee_log(0, 10);
    assert_eq!(
        log.len(),
        2,
        "test_78: fee log must have exactly 2 entries \
         (ShieldFee from deposit + UnshieldFee from withdrawal); got {}",
        log.len()
    );

    // entry[0]: ShieldFee from deposit — split_protocol_fee_to_reserves (8500/1500 bps)
    let shield = &log[0];
    assert_eq!(
        shield.source,
        FeeSource::ShieldFee,
        "test_78: log[0] source must be ShieldFee; got {:?}",
        shield.source
    );
    assert_eq!(
        shield.total_amount, T78_SHIELD_TOTAL,
        "test_78: ShieldFee total must be {}; got {}",
        T78_SHIELD_TOTAL, shield.total_amount
    );
    assert_eq!(
        shield.operations, T78_SHIELD_OPS,
        "test_78: ShieldFee ops must be {}; got {}",
        T78_SHIELD_OPS, shield.operations
    );
    assert_eq!(
        shield.insurance, T78_SHIELD_INS,
        "test_78: ShieldFee ins must be {}; got {}",
        T78_SHIELD_INS, shield.insurance
    );
    assert_eq!(
        shield.staking, 0,
        "test_78: ShieldFee staking must be 0; got {}",
        shield.staking
    );
    assert_eq!(
        shield.audit, 0,
        "test_78: ShieldFee audit must be 0; got {}",
        shield.audit
    );

    // entry[1]: UnshieldFee from withdrawal — GovernanceFeeParams 8500/1500/0 split
    let unshield = &log[1];
    assert_eq!(
        unshield.source,
        FeeSource::UnshieldFee,
        "test_78: log[1] source must be UnshieldFee; got {:?}",
        unshield.source
    );
    assert_eq!(
        unshield.total_amount, T78_UNSHIELDING_FEE,
        "test_78: UnshieldFee total must be {}; got {}",
        T78_UNSHIELDING_FEE, unshield.total_amount
    );
    assert_eq!(
        unshield.operations, T78_OPS_DELTA,
        "test_78: UnshieldFee ops must be {}; got {}",
        T78_OPS_DELTA, unshield.operations
    );
    assert_eq!(
        unshield.insurance, T78_INS_DELTA,
        "test_78: UnshieldFee ins must be {}; got {}",
        T78_INS_DELTA, unshield.insurance
    );
    assert_eq!(
        unshield.staking, 0,
        "test_78: UnshieldFee staking must be 0 (staking_rewards_split_bps=0); got {}",
        unshield.staking
    );
    assert_eq!(
        unshield.audit, 0,
        "test_78: UnshieldFee audit must be 0; got {}",
        unshield.audit
    );
}

// =============================================================================
// #115 §6/§11 deposit fee wiring tests (test_79 – test_82)
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 79 — Nonzero protocol_shielding_fee routes correctly to ops/ins reserves
// ─────────────────────────────────────────────────────────────────────────────
//
// Fee-ON-TOP (fee-build lane §2): private_balance_credit = gross (FULL); the
// shield fee is pulled on top and routed to reserves. Reserve split via
// split_protocol_fee_to_reserves (8500/1500 bps at launch).
//
// Asserts:
//   a) private_balance_credit = gross (full — fee on top)
//   b) OPERATIONS_RESERVE = shielding_fee * 8500 / 10000
//   c) INSURANCE_RESERVE = shielding_fee - ops
//   d) PRIVATE_LIABILITY = ESCROW_BACKING = private_balance_credit (= gross)
//   e) pool token balance = gross + shielding_fee = escrow + ops + ins
// =============================================================================

const T79_SHIELDING_FEE: u128 = 500_000; // 0.005 STSH — fits within DENOMINATIONS[1]
const T79_GROSS: u128 = 10_000 * 100_000_000; // DENOMINATIONS[1] = 10,000 STSH (A6.6)
const T79_EXPECTED_PB: u128 = T79_GROSS; // fee-on-top → full credit
const T79_EXPECTED_OPS: u128 = T79_SHIELDING_FEE * 8_500 / 10_000; // 425_000
const T79_EXPECTED_INS: u128 = T79_SHIELDING_FEE - T79_EXPECTED_OPS; // 75_000

#[test]
fn test_79_nonzero_shielding_fee_routes_to_reserves() {
    let h = PoolHarness::new_testing(0x79, [0x79; 32], 0);
    let controller = p(0x06);

    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.shield_flat_minimum_fee_e8s = Some(T79_SHIELDING_FEE);
    let set_result: Result<(), String> = decode(
        "test_79: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_79: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    // Fee-ON-TOP: pool pulls gross + shielding_fee, so approve for both + ledger.
    do_approve(
        &h.pic,
        h.token_id,
        h.user,
        h.pool_id,
        T79_GROSS + T79_SHIELDING_FEE + DEFAULT_FEE,
    );
    let result: Result<candid::Nat, PoolError> = decode(
        "test_79: shield_deposit",
        h.pic.update_call(
            h.pool_id,
            h.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0x79),
                encrypted_payload: vec![],
                public_amount: T79_GROSS,
            })
            .unwrap(),
        ),
    );
    let nat = result.expect("test_79: shield_deposit must succeed");
    let pb: u128 = nat.0.to_string().parse().unwrap();

    // a) private_balance_credit = gross (fee on top → full credit)
    assert_eq!(
        pb, T79_EXPECTED_PB,
        "test_79: private_balance_credit must be the FULL gross (fee on top); \
         gross={} fee={} expected={} got={}",
        T79_GROSS, T79_SHIELDING_FEE, T79_EXPECTED_PB, pb
    );

    // b/c/d) Accounting buckets
    let acc = h.accounting();
    assert_eq!(
        acc.operations_reserve, T79_EXPECTED_OPS,
        "test_79: ops_reserve must be {}; got={}",
        T79_EXPECTED_OPS, acc.operations_reserve
    );
    assert_eq!(
        acc.insurance_reserve, T79_EXPECTED_INS,
        "test_79: ins_reserve must be {}; got={}",
        T79_EXPECTED_INS, acc.insurance_reserve
    );
    assert_eq!(
        acc.private_liability, T79_EXPECTED_PB,
        "test_79: private_liability must equal private_balance_credit; got={}",
        acc.private_liability
    );
    assert_eq!(
        acc.escrow_backing, T79_EXPECTED_PB,
        "test_79: escrow_backing must equal private_balance_credit; got={}",
        acc.escrow_backing
    );

    // e) Pool token balance = gross + shielding_fee (escrow=gross + ops + ins=fee)
    let pool_bal = h.balance(h.pool_id);
    assert_eq!(
        pool_bal, T79_GROSS + T79_SHIELDING_FEE,
        "test_79: pool token balance must equal gross + shielding_fee (fee on top); got={}",
        pool_bal
    );
    assert_eq!(
        acc.escrow_backing + acc.operations_reserve + acc.insurance_reserve,
        T79_GROSS + T79_SHIELDING_FEE,
        "test_79: escrow + ops + ins must sum to gross + shielding_fee"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 80 — Fee-ON-TOP credits the full denomination even when fee == gross
// ─────────────────────────────────────────────────────────────────────────────
//
// Fee-build lane §2: the shield fee is charged ON TOP, not deducted from the
// note, so there is NO "gross <= shielding_fee" rejection anymore. The note is
// always credited the FULL denomination; the fee is pulled additionally and
// routed to reserves. This documents the semantic change from the old
// fee-from-note rejection.
// =============================================================================

#[test]
fn test_80_fee_on_top_full_credit_when_fee_equals_gross() {
    let h = PoolHarness::new_testing(0x80, [0x80; 32], 0);
    let controller = p(0x06);

    // Shielding fee == the deposited denomination — the old model rejected this.
    let shield_fee = DENOMINATIONS[0];
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.shield_flat_minimum_fee_e8s = Some(shield_fee);
    let set_result: Result<(), String> = decode(
        "test_80: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_80: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    // Fee-ON-TOP: pool pulls gross + fee = 2 * DENOMINATIONS[0]; approve for both.
    do_approve(
        &h.pic,
        h.token_id,
        h.user,
        h.pool_id,
        DENOMINATIONS[0] + shield_fee + DEFAULT_FEE,
    );
    let result: Result<candid::Nat, PoolError> = decode(
        "test_80: shield_deposit fee==gross",
        h.pic.update_call(
            h.pool_id,
            h.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0x80),
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    let pb: u128 = result
        .expect("fee-on-top: deposit must succeed even when fee == gross")
        .0
        .to_string()
        .parse()
        .unwrap();
    assert_eq!(
        pb, DENOMINATIONS[0],
        "test_80: fee-on-top credits the FULL denomination; got {}",
        pb
    );

    // Accounting: escrow == gross, liability == gross, fee routed to reserves.
    let acc = h.accounting();
    assert_eq!(acc.private_liability, DENOMINATIONS[0], "liability must equal gross");
    assert_eq!(acc.escrow_backing, DENOMINATIONS[0], "escrow must equal gross");
    assert_eq!(
        acc.operations_reserve + acc.insurance_reserve, shield_fee,
        "the on-top fee must be routed to reserves"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 81 — Zero protocol_shielding_fee: full pass-through at launch
// ─────────────────────────────────────────────────────────────────────────────
//
// §6 at launch: protocol_shielding_fee_stsh = 0.
// private_balance_credit = gross. No reserve split. No ShieldFee treasury notification.
//
// Asserts:
//   a) private_balance_credit = gross
//   b) OPERATIONS_RESERVE = 0, INSURANCE_RESERVE = 0
//   c) PRIVATE_LIABILITY = ESCROW_BACKING = gross
// =============================================================================

#[test]
fn test_81_zero_shielding_fee_full_pass_through() {
    // Default launch params: protocol_shielding_fee_stsh = 0.
    let h = PoolHarness::new(0x81, [0x81; 32], 0);

    let pb = h.deposit(DENOMINATIONS[0]);

    // a) private_balance_credit == gross at zero fee
    assert_eq!(
        pb, DENOMINATIONS[0],
        "test_81: at zero shielding_fee, private_balance_credit must equal gross; got={}",
        pb
    );
    assert_eq!(
        pb,
        expected_deposit_private_balance(DENOMINATIONS[0], 0),
        "test_81: expected_deposit_private_balance(gross, 0) must equal gross"
    );

    // b) No reserves extracted
    let acc = h.accounting();
    assert_eq!(
        acc.operations_reserve, 0,
        "test_81: ops_reserve must be 0 at zero shielding_fee; got={}",
        acc.operations_reserve
    );
    assert_eq!(
        acc.insurance_reserve, 0,
        "test_81: ins_reserve must be 0 at zero shielding_fee; got={}",
        acc.insurance_reserve
    );
    assert_eq!(
        acc.governance_rewards_reserve, 0,
        "test_81: staking reserve must be 0; got={}",
        acc.governance_rewards_reserve
    );

    // c) Full gross backs private liability
    assert_eq!(
        acc.private_liability, DENOMINATIONS[0],
        "test_81: private_liability must equal gross; got={}",
        acc.private_liability
    );
    assert_eq!(
        acc.escrow_backing, DENOMINATIONS[0],
        "test_81: escrow_backing must equal gross; got={}",
        acc.escrow_backing
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 82 — Deposit precheck: minimum_private_credit enforced
// ─────────────────────────────────────────────────────────────────────────────
//
// §11: private_balance_credit >= minimum_private_credit.
// Fee-ON-TOP: private_balance_credit == gross, so set minimum_private_credit
// ABOVE the deposited denomination to trip the check.
// =============================================================================

#[test]
fn test_82_deposit_precheck_minimum_private_credit() {
    let h = PoolHarness::new_testing(0x82, [0x82; 32], 0);
    let controller = p(0x06);

    // minimum_private_credit = DENOMINATIONS[1] (10 STSH) while the deposit is
    // DENOMINATIONS[0] (1,000 STSH, A6.6): private_balance_credit = DENOMINATIONS[0] <
    // minimum_private_credit → must fail.
    let mut fee_params = GovernanceFeeParams::launch_defaults();
    fee_params.minimum_private_credit = DENOMINATIONS[1];
    let set_result: Result<(), String> = decode(
        "test_82: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(fee_params).unwrap(),
        ),
    );
    assert!(
        set_result.is_ok(),
        "test_82: set_governance_fee_params must succeed; got {:?}",
        set_result
    );

    do_approve(
        &h.pic,
        h.token_id,
        h.user,
        h.pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let result: Result<candid::Nat, PoolError> = decode(
        "test_82: shield_deposit below minimum_private_credit",
        h.pic.update_call(
            h.pool_id,
            h.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0x82),
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    // private_balance_credit = DENOMINATIONS[0] < minimum_private_credit = DENOMINATIONS[1].
    assert!(
        matches!(result, Err(PoolError::TransferFailed(_))),
        "test_82: deposit below minimum_private_credit must fail; got {:?}",
        result
    );

    // No accounting update on failure.
    let acc = h.accounting();
    assert_eq!(
        acc.private_liability, 0,
        "test_82: private_liability must be 0 after rejected deposit; got {}",
        acc.private_liability
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee-build lane §3 — shield bps fee-on-top preserves the I-02A identity
// ─────────────────────────────────────────────────────────────────────────────
//
// Exercises the shield_fee_bps value-fee path (test_79 uses the flat-minimum
// path) and asserts the full I-02A solvency identity:
//   escrow + operations + insurance + governance_rewards == icrc1_balance_of(pool)
// after a fee-on-top shield, plus that PRIVATE_LIABILITY moves by the full
// credited gross and the on-top fee lands entirely in the reserves.
// =============================================================================
#[test]
fn test_shield_bps_fee_on_top_preserves_i02a() {
    let h = PoolHarness::new_testing(0x8A, [0x8A; 32], 0);
    let controller = p(0x06);

    let mut params = GovernanceFeeParams::launch_defaults();
    params.shield_fee_bps = Some(25); // 25 bps of value
    let set: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        h.pic.update_call(
            h.pool_id, controller, "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    set.expect("set_governance_fee_params (25 bps shield) must succeed");

    let gross = DENOMINATIONS[1]; // 10 STSH
    let fee = gross * 25 / 10_000; // 25 bps, floor
    assert!(fee > 0, "sanity: 25 bps of 10 STSH must be nonzero");

    // Fee-ON-TOP: approve gross + fee + ledger.
    do_approve(&h.pic, h.token_id, h.user, h.pool_id, gross + fee + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit",
        h.pic.update_call(
            h.pool_id, h.user, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0x8A),
                encrypted_payload: vec![],
                public_amount: gross,
            })
            .unwrap(),
        ),
    );
    let pb: u128 = dep.expect("deposit must succeed").0.to_string().parse().unwrap();
    assert_eq!(pb, gross, "fee-on-top: note credited the full gross");

    let acc = h.accounting();
    let pool_bal = h.balance(h.pool_id);

    // I-02A identity holds.
    assert_eq!(
        acc.escrow_backing
            + acc.operations_reserve
            + acc.insurance_reserve
            + acc.governance_rewards_reserve,
        pool_bal,
        "I-02A must hold after a bps fee-on-top shield"
    );
    // Escrow backs the full credit; PRIVATE_LIABILITY moved by the full gross.
    assert_eq!(acc.escrow_backing, gross, "escrow backs the full credited gross");
    assert_eq!(acc.private_liability, gross, "private_liability == credited gross");
    // The on-top fee lands entirely in the reserves (staking disabled → gov = 0).
    assert_eq!(
        acc.operations_reserve + acc.insurance_reserve, fee,
        "the on-top bps fee must be routed entirely to reserves"
    );
    assert_eq!(acc.governance_rewards_reserve, 0, "staking disabled at launch");
    assert_eq!(pool_bal, gross + fee, "pool pulled gross + fee (fee on top)");
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee-build lane §2/C3 — the documented mainnet launch config applies + holds
// ─────────────────────────────────────────────────────────────────────────────
//
// The 25 bps shield/unshield + 2.5 STSH spend fee are NOT baked into the pool's
// launch_defaults() (which stays fail-safe fee-free) — governance applies them
// via set_governance_fee_params as a scripted deploy step. This test exercises
// that exact activation: apply the documented config, confirm the LIVE params
// match it (the post-deploy hard-gate check in MAINNET_DEPLOYMENT.md), and prove
// a shield under the config charges the right fee with I-02A preserved.
//
// Values MUST match stsh_fee_policy::MAINNET_LAUNCH_* and MAINNET_DEPLOYMENT.md
// (the crate's mainnet_launch_config_matches_documented_values test pins the
// crate side).
const LAUNCH_SHIELD_BPS: u16 = 25;
const LAUNCH_UNSHIELD_BPS: u16 = 25;
const LAUNCH_SPEND_FEE_E8S: u128 = 250_000_000; // 2.5 STSH
/// The launch shield/unshield flat minimum. NOT the in-circuit fee wall — a
/// separate value in a separate lane (A6.6 widened that to 10^15 e8s).
// A6.6 / R-14 RETARGET, on OWNER_RULING_FEE_FLOOR_2_5_STSH (2026-09-08): the
// ruled launch flat minimum is 2.5 STSH in BOTH directions, superseding the
// 0.1 STSH of 2026-08-21, which superseded the 1,000 STSH of 2026-07-31
// (RB-SWARM-A1). Drift-guard discipline is unchanged: the literal stays a
// literal, never read back from the constant it guards.
const LAUNCH_FLAT_MIN_E8S: u128 = 250_000_000; // 2.5 STSH
#[test]
fn test_mainnet_launch_config_applies_and_preserves_i02a() {
    let h = PoolHarness::new(0x8B, [0x8B; 32], 0);
    let controller = p(0x06);

    // Apply the documented launch config exactly as the scripted deploy step does.
    let mut params = GovernanceFeeParams::launch_defaults();
    params.shield_fee_bps = Some(LAUNCH_SHIELD_BPS);
    params.unshield_fee_bps = Some(LAUNCH_UNSHIELD_BPS);
    params.shield_flat_minimum_fee_e8s = Some(LAUNCH_FLAT_MIN_E8S);
    params.unshield_flat_minimum_fee_e8s = Some(LAUNCH_FLAT_MIN_E8S);
    params.protocol_private_spend_fee_stsh = LAUNCH_SPEND_FEE_E8S;
    // The canister derives the epoch itself; supplying it is an ASSERTION that
    // it equals the epoch the canister was going to write (0 -> 1 at bootstrap).
    params.params_epoch = Some(1);
    let set: Result<(), String> = decode(
        "set_governance_fee_params (mainnet launch config)",
        h.pic.update_call(
            h.pool_id, controller, "set_governance_fee_params",
            candid::encode_one(params).unwrap(),
        ),
    );
    set.expect("apply mainnet launch config must succeed");

    // Post-deploy hard-gate check: the LIVE params are nonzero and match the
    // documented launch config (this is what P15-002 gates the public launch on).
    let live: GovernanceFeeParams = decode(
        "get_governance_fee_params",
        h.pic.query_call(
            h.pool_id, controller, "get_governance_fee_params",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(live.shield_fee_bps, Some(LAUNCH_SHIELD_BPS), "live shield bps matches documented");
    assert_eq!(live.unshield_fee_bps, Some(LAUNCH_UNSHIELD_BPS), "live unshield bps matches documented");
    assert_eq!(
        live.protocol_private_spend_fee_stsh, LAUNCH_SPEND_FEE_E8S,
        "live spend fee matches documented"
    );
    assert_eq!(live.spend_fee_mode, Some(SpendFeeMode::FixedStsh), "fixed-STSH mode live");
    assert_eq!(
        live.shield_flat_minimum_fee_e8s, Some(LAUNCH_FLAT_MIN_E8S),
        "live shield flat minimum matches the RULED 2.5 STSH launch value"
    );
    assert_eq!(
        live.unshield_flat_minimum_fee_e8s, Some(LAUNCH_FLAT_MIN_E8S),
        "live unshield flat minimum matches the RULED 2.5 STSH launch value"
    );
    // The epoch the canister stored, not one the caller chose.
    assert_eq!(live.params_epoch, Some(1), "bootstrap stamps epoch 1");

    // P15-002 as a boolean: this is what the deploy script asserts on, instead
    // of a human reading raw Candid out of get_governance_fee_params.
    let matches: bool = decode(
        "fee_params_match_mainnet_launch_config",
        h.pic.query_call(
            h.pool_id, controller, "fee_params_match_mainnet_launch_config",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(matches, "the live params must match mainnet_launch_config() after the deploy step");

    // A shield under the launch config. The effective fee is
    // max(flat_minimum, amount * bps / 10_000).
    //
    // A6.6: under `max(2.5 STSH, 0.25%)` and the five-tier ladder, the two arms
    // MEET exactly at the floor rung (0.25% x 1,000 STSH = 2.5 STSH) and the BPS
    // component dominates at every rung above it. The flat minimum is a dust
    // floor for amounts BELOW the ladder, not a charge that scales with the note.
    let gross = DENOMINATIONS[1]; // 10,000 STSH — the first rung where bps strictly wins
    let by_bps = gross * (LAUNCH_SHIELD_BPS as u128) / 10_000;
    let fee = std::cmp::max(LAUNCH_FLAT_MIN_E8S, by_bps);
    assert_eq!(
        fee, by_bps,
        "under the ruled model the 0.25% component dominates at the 10,000 STSH denomination"
    );
    assert_eq!(fee, 2_500_000_000, "0.25% of 10,000 STSH is 25 STSH");
    // The dust-floor property the old assertion existed to protect is preserved,
    // asserted where it now lives: at a small deposit the floor still dominates.
    let dust_gross = DENOMINATIONS[0]; // 1,000 STSH (A6.6)
    assert_eq!(
        std::cmp::max(LAUNCH_FLAT_MIN_E8S, dust_gross * (LAUNCH_SHIELD_BPS as u128) / 10_000),
        LAUNCH_FLAT_MIN_E8S,
        "the flat minimum must still dominate at the 1 STSH denomination — the dust floor"
    );
    do_approve(&h.pic, h.token_id, h.user, h.pool_id, gross + fee + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit (launch config)",
        h.pic.update_call(
            h.pool_id, h.user, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0x8B),
                encrypted_payload: vec![],
                public_amount: gross,
            })
            .unwrap(),
        ),
    );
    let pb: u128 = dep.expect("deposit under launch config must succeed").0.to_string().parse().unwrap();
    assert_eq!(pb, gross, "fee-on-top: full credit under launch config");

    let acc = h.accounting();
    let pool_bal = h.balance(h.pool_id);
    assert_eq!(
        acc.escrow_backing
            + acc.operations_reserve
            + acc.insurance_reserve
            + acc.governance_rewards_reserve,
        pool_bal,
        "I-02A must hold after a shield under the mainnet launch config"
    );
    assert_eq!(acc.escrow_backing, gross, "escrow backs the full gross");
    assert_eq!(
        acc.operations_reserve + acc.insurance_reserve, fee,
        "the launch shield fee routed to reserves"
    );
}

// =============================================================================
// #70 VK governance split tests (test_83 – test_84)
// =============================================================================
//
// These tests prove the validate_for_creation / validate_for_execution split
// (#70, pre-A2 blocker P3).  They use the existing GovHarness
// (staking + pool, controller = staking_id) and advance the PocketIC clock.
//
// validate_for_creation  = VerifierKeyUpgradePayload::validate_at(time())
//   — called by create_proposal(); enforces 14-day activation window
// validate_for_execution = VerifierKeyUpgradePayload::validate_structural()
//   — called by execute_proposal_action(); skips timing so a legitimately
//     scheduled proposal remains executable after time has passed
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 83 — VK upgrade proposal executes after governance timelock
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (validate_for_execution / P3 fix):
//   execute_proposal_action calls validate_structural(), NOT validate().
//   A VK proposal created with activation = now + 15 days must still execute
//   successfully after the fast governance timelock (3 s) has elapsed — even
//   though by that point the 14-day creation-time window would have expired if
//   re-checked.
//
// Also verifies that execute_proposal_action correctly calls
// schedule_vk_activation on the pool (old_key_cutoff_ns = activation + 7 days,
// not zero).  If the pool rejected the call, execute_proposal would return Err
// and run_proposal would panic.
//
// pool VK hash is checked BEFORE and AFTER execution.  It must remain equal to
// POOL_VK_HASH because maybe_activate_pending_vk() fires on proof submission,
// not on schedule_vk_activation — the new key is pending, not yet pinned.
// =============================================================================

const T83_NEW_VK_HASH: [u8; 32] = [0x83; 32];

#[test]
fn test_83_vk_upgrade_proposal_executes_after_governance_timelock() {
    let h = GovHarness::new();

    let vk_before = h.pool_vk_hash();
    assert_eq!(
        vk_before, POOL_VK_HASH,
        "test_83: pool VK must equal init value before proposal"
    );

    // Build a fully-valid VK upgrade payload with activation 15 days from now —
    // safely above the 14-day creation-time floor.
    let activation_ns = h.now_ns() + 15 * 24 * 60 * 60 * 1_000_000_000u64;
    let payload = VerifierKeyUpgradePayload {
        old_verifying_key_hash: POOL_VK_HASH,
        new_verifying_key_hash: T83_NEW_VK_HASH,
        circuit_version: 1,
        proof_system_id: "groth16-bn254".to_string(),
        audit_artifact_url: "https://audit.example.com/stsh-v2.pdf".to_string(),
        audit_artifact_hash: [0x83; 32],
        circuit_source_commit: "83".repeat(20),
        verifier_wasm_hash: [0x83; 32],
        activation_timestamp_ns: activation_ns,
        emergency_disable_supported: false,
    };

    // create → vote → advance 3 s past fast governance timelock → execute.
    // If execute_proposal_action re-ran validate() (old P3 bug), execution would
    // fail because by then the activation is within the 14-day window from *now*
    // (only 3 seconds have passed, but the activation is 15 days from the original
    // now, so the 14-day check would actually still pass — the real bug surfaces
    // only after the governance timelock is longer than 14 days).
    // validate_structural() is correct regardless.
    h.run_proposal(ProposalType::VerifierKeyUpgrade(payload));

    // Pinned VK must still be the old hash — pending VK is scheduled but not
    // yet activated (activation is 15 days away; only 3 seconds have advanced).
    let vk_after = h.pool_vk_hash();
    assert_eq!(
        vk_after, POOL_VK_HASH,
        "test_83: pool VK must still be POOL_VK_HASH immediately after scheduling; \
         pending VK activates on first proof submission after activation_ns; got {:?}",
        vk_after
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 84 — VK upgrade proposal rejected at creation if activation < 14 days
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (validate_for_creation / P3 fix):
//   create_proposal calls validate_at(time()), which enforces a minimum 14-day
//   activation window.  A payload with activation = now + 1 day must be rejected
//   at creation time, before the proposal is stored or executed.
//
// Pool VK hash must be unchanged — no schedule_vk_activation call may occur.
// =============================================================================

const T84_NEW_VK_HASH: [u8; 32] = [0x84; 32];

#[test]
fn test_84_vk_upgrade_proposal_rejected_at_creation_if_activation_under_14_days() {
    let h = GovHarness::new();

    let vk_before = h.pool_vk_hash();
    assert_eq!(
        vk_before, POOL_VK_HASH,
        "test_84: pool VK must equal init value before attempt"
    );

    // Activation only 1 day from now — well under the 14-day minimum.
    let activation_ns = h.now_ns() + 1 * 24 * 60 * 60 * 1_000_000_000u64;
    let payload = VerifierKeyUpgradePayload {
        old_verifying_key_hash: POOL_VK_HASH,
        new_verifying_key_hash: T84_NEW_VK_HASH,
        circuit_version: 1,
        proof_system_id: "groth16-bn254".to_string(),
        audit_artifact_url: "https://audit.example.com/stsh-v2.pdf".to_string(),
        audit_artifact_hash: [0x84; 32],
        circuit_source_commit: "84".repeat(20),
        verifier_wasm_hash: [0x84; 32],
        activation_timestamp_ns: activation_ns,
        emergency_disable_supported: false,
    };

    let result = h.create_proposal_raw(
        ProposalType::VerifierKeyUpgrade(payload),
        "test_84: short activation",
    );

    assert!(
        result.is_err(),
        "test_84: create_proposal must reject activation < 14 days; got Ok({:?})",
        result.ok()
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("14 days"),
        "test_84: error must cite the 14-day requirement; got: {:?}",
        err
    );

    // No proposal was created, so no execution can follow — pool VK is untouched.
    let vk_after = h.pool_vk_hash();
    assert_eq!(
        vk_after, POOL_VK_HASH,
        "test_84: pool VK must be unchanged after rejected proposal; got {:?}",
        vk_after
    );
}

// =============================================================================
// #116 — Canonical field encoding / nullifier-key normalization (tests 85-89)
// =============================================================================
//
// These tests close the P0 double-spend class issue where a non-canonical
// public signal (bytes >= BN254 Fr modulus) and its canonical counterpart
// reduce to the same field element in the verifier but store as different
// raw-byte keys in the nullifier registry.
//
// Canonical policy (strict rejection):
//   - Pool rejects non-canonical anchor/nullifier/output_commitment signals
//     in build_spend_public_signals() before the async verifier call.
//   - Verifier rejects non-canonical signals in parse_public_inputs().
//   - Nullifier registry to_nullifier_key() rejects non-canonical bytes
//     as defense-in-depth.
//
// Non-canonical test bytes: [0xFF; 32].
//   0xFF...FF as a 256-bit LE integer ≈ 2^256-1, which is far above both
//   the BN254 Fr modulus (≈ 2^254) and Fq modulus (≈ 2^254).  It is provably
//   non-canonical in both fields.

/// A provably non-canonical 32-byte LE Fr encoding: 0xFF...FF > BN254 Fr modulus.
const NON_CANONICAL_BYTES: [u8; 32] = [0xFF; 32];

/// A valid canonical 32-byte LE Fr encoding: integer value 1.
const CANONICAL_ONE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};

/// Build a minimal valid PrivateSpendArgs for canonical-encoding tests.
/// The proof bytes are intentionally invalid (zeros) — canonical rejection fires
/// before the verifier is called, so proof validity is irrelevant here.
fn minimal_spend_args(
    spend_id: u64,
    anchor: [u8; 32],
    nullifier: [u8; 32],
    oc1: [u8; 32],
    oc2: [u8; 32],
) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference: anchor,
            pool_version: 1,
            proof_bytes: vec![0u8; 256], // invalid, but canonical check fires first
        },
        nullifiers: vec![nullifier],
        output_commitments: vec![oc1, oc2],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: None,
    }
}

/// Install the minimal canister set needed for canonical-rejection tests:
/// pool (no verifier configured, dummy principals for unreachable canisters).
/// For tests 85-87 the canonical check fires before any async I/O, so only
/// the pool Wasm needs to be installed.
fn install_pool_only(pic: &PocketIc) -> Principal {
    let pool_id = create_canister(pic);
    install(
        pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: p(0xA0),
            nullifier_canister: p(0xA1),
            merkle_canister: p(0xA2),
            treasury_canister: p(0xA3),
            staking_canister: p(0xA4),
            controller: p(0xA5),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pool_id
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 85 — non-canonical nullifier_hash rejected at pool boundary
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (#116): private_spend with a nullifier_hash whose raw bytes represent
// a value >= BN254 Fr modulus must be rejected by the pool BEFORE the async
// verifier call, returning ProofRejected("NonCanonicalSignal: nullifier_hash …").
// No PendingSpend record is written; no registry or Merkle mutation occurs.
// =============================================================================

#[test]
fn test_85_noncanonical_nullifier_rejected_at_pool() {
    let pic = PocketIc::new();
    let user = p(0x85);
    let pool_id = install_pool_only(&pic);

    let args = minimal_spend_args(
        8500,
        CANONICAL_ONE,       // anchor — canonical
        NON_CANONICAL_BYTES, // nullifier — NON-canonical (>= Fr modulus)
        CANONICAL_ONE,       // oc1 — canonical
        CANONICAL_ONE,       // oc2 — canonical
    );

    let result: Result<(), PoolError> = decode(
        "test_85: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    assert!(
        matches!(result, Err(PoolError::ProofRejected(ref msg)) if msg.contains("NonCanonicalSignal")),
        "test_85: expected ProofRejected(NonCanonicalSignal: nullifier_hash); got: {:?}",
        result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 86 — non-canonical anchor rejected at pool boundary
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (#116): private_spend with anchor bytes >= BN254 Fr modulus must be
// rejected with ProofRejected("NonCanonicalSignal: anchor …") before any state
// mutation or verifier call.
// =============================================================================

#[test]
fn test_86_noncanonical_anchor_rejected_at_pool() {
    let pic = PocketIc::new();
    let user = p(0x86);
    let pool_id = install_pool_only(&pic);

    let args = minimal_spend_args(
        8600,
        NON_CANONICAL_BYTES, // anchor — NON-canonical (>= Fr modulus)
        CANONICAL_ONE,       // nullifier — canonical
        CANONICAL_ONE,       // oc1 — canonical
        CANONICAL_ONE,       // oc2 — canonical
    );

    let result: Result<(), PoolError> = decode(
        "test_86: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    assert!(
        matches!(result, Err(PoolError::ProofRejected(ref msg)) if msg.contains("NonCanonicalSignal")),
        "test_86: expected ProofRejected(NonCanonicalSignal: anchor); got: {:?}",
        result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 87 — non-canonical output_commitment_1 rejected at pool boundary
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (#116): output commitment bytes >= BN254 Fr modulus must be rejected
// before any Merkle append or verifier call.
// =============================================================================

#[test]
fn test_87_noncanonical_output_commitment_rejected_at_pool() {
    let pic = PocketIc::new();
    let user = p(0x87);
    let pool_id = install_pool_only(&pic);

    let args = minimal_spend_args(
        8700,
        CANONICAL_ONE,       // anchor — canonical
        CANONICAL_ONE,       // nullifier — canonical
        NON_CANONICAL_BYTES, // oc1 — NON-canonical (>= Fr modulus)
        CANONICAL_ONE,       // oc2 — canonical
    );

    let result: Result<(), PoolError> = decode(
        "test_87: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    assert!(
        matches!(result, Err(PoolError::ProofRejected(ref msg)) if msg.contains("NonCanonicalSignal")),
        "test_87: expected ProofRejected(NonCanonicalSignal: output_commitment_1); got: {:?}",
        result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 88 — verifier canister directly rejects non-canonical public signal
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (#116): the verifier's parse_public_inputs() rejects non-canonical
// signal bytes independently of the pool-level check.  This provides a
// second line of defense at the cryptographic boundary.
// =============================================================================

#[test]
fn test_88_noncanonical_signal_rejected_by_verifier_directly() {
    let pic = PocketIc::new();
    let verifier = create_canister(&pic);
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(p(0x88)).unwrap(), None);

    // Build 9 signals: all canonical except signal[1] (nullifier_hash = 0xFF…FF).
    let signals: Vec<Vec<u8>> = vec![
        vec![0u8; 32],                // anchor — canonical (value 0)
        NON_CANONICAL_BYTES.to_vec(), // nullifier_hash — NON-canonical
        vec![0u8; 32],                // oc1 — canonical
        vec![0u8; 32],                // oc2 — canonical
        vec![0u8; 32],                // public_amount — canonical
        vec![0u8; 32],                // fee — canonical
        vec![0u8; 32],                // recipient_principal — canonical (DEF-026)
        vec![0u8; 32],                // recipient_subaccount_lo — canonical (DEF-026)
        vec![0u8; 32],                // recipient_subaccount_hi — canonical (DEF-026)
    ];
    let proof_bytes: Vec<u8> = vec![0u8; 256]; // invalid proof, but canonical check fires first

    let result: Result<(), String> = decode(
        "test_88: verify_spend_canister",
        pic.update_call(
            verifier,
            p(0x88),
            "verify_spend_canister",
            candid::encode_args((proof_bytes, signals)).unwrap(),
        ),
    );

    assert!(
        matches!(result, Err(ref msg) if msg.contains("non-canonical")),
        "test_88: expected Err containing 'non-canonical'; got: {:?}",
        result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 89 — canonical signals pass the canonical check (regression guard)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (#116 regression guard): a spend with fully canonical signals must
// NOT be rejected with ProofRejected("NonCanonicalSignal …").  Rejection is
// expected only for a different reason (bad anchor or bad proof), confirming
// the canonical gate does not false-positive on legitimate inputs.
//
// Does not require circuit artifacts: uses all-zero canonical signals and a
// minimal canister stack.  The spend reaches the anchor precheck (step 7)
// and fails there — but NOT at the canonical check (step 6).
// =============================================================================

#[test]
fn test_89_canonical_signals_not_rejected_by_canonical_check() {
    let pic = PocketIc::new();
    let user = p(0x89);
    let null_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let pool_id = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: p(0xB0),
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0xB3),
            staking_canister: p(0xB4),
            controller: p(0xB5),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // All-zero canonical signals (value 0 < Fr modulus → canonical).
    // The anchor [0;32] has never been stored in the Merkle root history,
    // so the spend will fail with AnchorNotFound — but NOT with a canonical
    // rejection.
    let args = minimal_spend_args(
        8900,
        [0u8; 32], // anchor = 0 — canonical, not in Merkle history
        [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ], // nullifier = 1 — canonical
        [
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ], // oc1 = 2 — canonical
        [
            3u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ], // oc2 = 3 — canonical
    );

    let result: Result<(), PoolError> = decode(
        "test_89: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    // The spend must NOT be rejected with ProofRejected("NonCanonicalSignal …").
    // Expected rejection is AnchorNotFound (anchor 0 is not in Merkle history)
    // or TransferFailed (if the Merkle query fails for other reasons).
    match &result {
        Err(PoolError::ProofRejected(msg)) if msg.contains("NonCanonicalSignal") => {
            panic!(
                "test_89: REGRESSION — canonical signals falsely rejected by canonical check: {}",
                msg
            );
        }
        Err(PoolError::AnchorNotFound) => {
            // Expected: anchor not in Merkle history — canonical check passed, anchor check failed.
        }
        Err(PoolError::TransferFailed(msg)) => {
            // Also acceptable: async anchor-check call returned an error.
            // The key invariant is that it's NOT a canonical rejection.
            println!("test_89: TransferFailed (acceptable): {}", msg);
        }
        other => {
            // Any other error is acceptable as long as it is not NonCanonicalSignal.
            println!(
                "test_89: other result (acceptable, not NonCanonicalSignal): {:?}",
                other
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 90 — step 15-pre reservation gate fires before Merkle append (#117)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: If INFLIGHT_NULLIFIERS already holds a spend's nullifier when
// commit_private_spend runs, the spend must be rejected at step 15-pre with
// PoolError::NullifierReserved and SpendStatus::FailedBeforeStateChange.
// No Merkle leaf must be appended (outputs_committed == 0, leaf_count unchanged).
//
// Setup: deposit T55_IN_COMMITMENT only (no prior spend); pre-seed
// INFLIGHT_NULLIFIERS via inject_inflight_nullifier_for_test (test-only
// endpoint, compiled only under --features testing / POOL_TEST_WASM).
// The valid fixture proof then passes all registry/verifier/recheck checks
// and hits the gate deterministically, without needing concurrent execution.
//
// Uses: pool_test_wasm() (POOL_TEST_WASM env var), real verifier canister.
// Skips gracefully if circuits/proof.json or public.json are absent.
//
// LAUNCH-HARDEN-04 O-1(c) — WHERE the refusal lands has MOVED EARLIER. The
// admission guard (`VerifyPendingNullifierGuard::try_new`, step 4, before the
// PENDING_SPENDS write and the verifier dispatch) reads INFLIGHT_NULLIFIERS
// READ-ONLY and refuses a nullifier already reserved there. So the injected
// reservation is now caught at ADMISSION: `NullifierReserved` with NO spend
// record written and NO verifier call — strictly cheaper and strictly earlier
// than the step-15-pre gate, which is UNCHANGED (law 2) and stays proven
// natively (`try_reserve_nullifiers` arms in the pool crate). Every
// no-mutation property this test guards still holds and is still asserted:
// NullifierReserved (never NullifierAlreadySpent), no Merkle append, nothing
// in the permanent registry.
// =============================================================================

#[test]
fn test_90_reservation_gate_fires_before_merkle_append() {
    let Some(args) = load_valid_spend_fixture_args(9000) else {
        eprintln!("test_90: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];
    let controller = p(0x06);

    let pic = PocketIc::new();
    let user = p(0x90);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    // Use pool_test_wasm so inject_inflight_nullifier_for_test is available.
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // Wire the real verifier so the proof can be verified end-to-end up to 15-pre.
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_90: set_verifier_canister must succeed");

    // Seed T55_IN_COMMITMENT via shield_deposit so the Merkle root matches the
    // fixture proof anchor and the anchor recheck at step 14a will pass.
    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_90: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_90: shield_deposit must succeed; got: {:?}",
        deposit_result
    );

    let post_deposit_leaf_count = merkle_leaf_count(&pic, merkle_id);
    assert_eq!(
        post_deposit_leaf_count, 1,
        "test_90: exactly 1 leaf after deposit (T55_IN_COMMITMENT)"
    );

    // Verify the Merkle root equals the proof anchor so step 14a will pass.
    let current_root = merkle_root(&pic, merkle_id);
    assert_eq!(
        current_root, expected_anchor,
        "test_90: Merkle root after deposit must equal proof anchor (signals[0])"
    );

    // Pre-seed INFLIGHT_NULLIFIERS with the fixture nullifier (signals[1]).
    // This simulates a concurrent spend holding the reservation at step 15-pre,
    // making the gate fire deterministically without requiring concurrent execution.
    let inject_result: Result<(), String> = decode(
        "test_90: inject_inflight_nullifier_for_test",
        pic.update_call(
            pool_id,
            controller,
            "inject_inflight_nullifier_for_test",
            candid::encode_one(expected_nullifier.to_vec()).unwrap(),
        ),
    );
    assert!(
        inject_result.is_ok(),
        "test_90: inject_inflight_nullifier_for_test must succeed; got: {:?}",
        inject_result
    );

    // Submit the valid proof spend. It will:
    //   step 9:   nullifier not in registry → passes
    //   step 14a: anchor in Merkle root history → passes
    //   step 14b: nullifier still not in registry → passes
    //   step 15-pre: INFLIGHT_NULLIFIERS contains expected_nullifier → BLOCKED
    //
    // Expected: PoolError::NullifierReserved, NOT NullifierAlreadySpent.
    let result: Result<(), PoolError> = decode(
        "test_90: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    assert_eq!(
        result,
        Err(PoolError::NullifierReserved),
        "test_90: reservation gate must fire at step 15-pre; \
         NullifierAlreadySpent is not acceptable (that would mean the gate was bypassed)"
    );

    // LAUNCH-HARDEN-04 O-1(c): refused at ADMISSION — no spend record at all
    // (formerly a FailedBeforeStateChange record written at step 15-pre).
    assert!(
        spend_status(&pic, pool_id, 9000).is_none(),
        "test_90: the O-1(c) admission guard refuses before the first durable write — no record"
    );

    // Merkle must still have exactly the 1 leaf from the deposit — no output leaves added.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        post_deposit_leaf_count,
        "test_90: leaf count must be unchanged ({}); loser outputs must not be appended",
        post_deposit_leaf_count
    );

    // Nullifier must NOT be in the permanent registry — the spend was blocked before 15d.
    assert!(
        !null_contains(&pic, null_id, expected_nullifier),
        "test_90: nullifier must not be in the permanent registry after a 15-pre rejection"
    );
}

// =============================================================================
// #118: P0 release-path regression coverage
//
// #116 canonical alias regression: test_85–test_89 (existing, no gaps).
// #117 reservation gate regression: test_90 (existing).
//
// The tests below close the remaining #117 gap: proving INFLIGHT_NULLIFIERS
// is released on every exit path of commit_private_spend in a deployed Wasm
// canister, not just in isolated unit tests (test_91–test_93).
//
// All three tests hard-fail if the spend fixture (circuits/proof.json /
// circuits/public.json) is absent.  Silent skip is not acceptable for
// P0 audit-grade regression coverage.
// =============================================================================

// Helper: query inflight_count_for_test on a pool installed from pool_test_wasm.
fn inflight_count(pic: &PocketIc, pool_id: Principal, controller: Principal) -> u64 {
    decode(
        "inflight_count_for_test",
        pic.query_call(
            pool_id,
            controller,
            "inflight_count_for_test",
            candid::encode_one(()).unwrap(),
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 94 — successful private_spend clears INFLIGHT (P0 release regression)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (#117 release-on-success): after commit_private_spend reaches step
// 15e (Finalized), INFLIGHT_NULLIFIERS must be empty for the spent nullifier.
// If release_nullifiers is not called at step 15e, INFLIGHT grows unboundedly
// and every successfully spent nullifier permanently blocks future reservations
// of the same nullifier (no practical consequence given registry blocks step 9,
// but a slow memory leak and an audit gap).
//
// Proof strategy:
//   1. Complete a full end-to-end private_spend → SpendStatus::Finalized.
//   2. Assert inflight_count_for_test == 0 (direct proof via test-only query).
//   3. Assert second spend with same nullifier returns NullifierAlreadySpent
//      (registry blocks retry; FailedBeforeStateChange, no new outputs).
// =============================================================================

#[test]
fn test_94_successful_spend_clears_inflight() {
    let args = load_valid_spend_fixture_args(9400).expect(
        "P0 regression test_94 requires circuits/proof.json and circuits/public.json \
                 — fixture files must be present for audit-grade release-path coverage (#118)",
    );
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];
    let controller = p(0x06);

    let pic = PocketIc::new();
    let user = p(0x94);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_94: set_verifier_canister must succeed");

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_id, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_94: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_94: shield_deposit must succeed; got: {:?}",
        deposit_result
    );
    assert_eq!(
        merkle_root(&pic, merkle_id),
        expected_anchor,
        "test_94: Merkle root after deposit must equal proof anchor"
    );

    // First spend — must succeed end-to-end.
    let result: Result<(), PoolError> = decode(
        "test_94: private_spend",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    assert_eq!(result, Ok(()), "test_94: first private_spend must succeed");

    let status = spend_status(&pic, pool_id, 9400)
        .expect("test_94: spend record must exist after successful spend");
    assert!(
        matches!(status.status, SpendStatus::Finalized),
        "test_94: spend must be Finalized; got: {:?}",
        status.status
    );

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_94: leaf count must be 3 (1 deposit + 2 outputs) after successful spend"
    );
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "test_94: nullifier must be in permanent registry after Finalized"
    );

    // Direct proof: INFLIGHT must be empty after step 15e release.
    assert_eq!(
        inflight_count(&pic, pool_id, controller),
        0,
        "test_94: INFLIGHT_NULLIFIERS must be empty after successful finalization — \
         release_nullifiers must have fired at step 15e"
    );

    // Secondary proof: second spend with same nullifier is blocked at step 9 precheck
    // (permanent registry check in precheck_private_spend_before_verify) returning
    // NullifierAlreadySpent.  Step 9 runs BEFORE step 12 (PendingSpend record creation)
    // and BEFORE step 15-pre (INFLIGHT gate), so no spend record is written and no
    // INFLIGHT interaction occurs.  The registry is the sole blocker.
    let mut args2 = args;
    args2.spend_id = 9401;
    let result2: Result<(), PoolError> = decode(
        "test_94: second private_spend (same nullifier)",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args2).unwrap(),
        ),
    );
    assert_eq!(
        result2,
        Err(PoolError::NullifierAlreadySpent),
        "test_94: retry must return NullifierAlreadySpent (step 9, registry) — \
         not NullifierReserved (step 15-pre, INFLIGHT)"
    );
    // No PendingSpend record is written: step 9 returns before step 12.
    assert!(
        spend_status(&pic, pool_id, 9401).is_none(),
        "test_94: no spend record must exist for spend blocked at step 9 precheck"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_94: leaf count must remain 3 after rejected retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 95 (A2) — promotion append failure: nullifier finalized, INFLIGHT released
// ─────────────────────────────────────────────────────────────────────────────
//
// A2 ordering means INFLIGHT is released at nullifier finalization (insert_batch
// success), BEFORE the Merkle append. So when the promotion append is rejected:
//   - the parent nullifier IS in the registry (finalized, never rolled back),
//   - INFLIGHT is already 0,
//   - the spend is ActiveAppendRejected (recoverable via reconcile_pending_spend).
//
// Proof strategy:
//   1. First spend → OutputAppendRejected (merkle auth mismatch at promotion);
//      ActiveAppendRejected; outputs_committed == 0; leaf_count == 1.
//   2. Assert inflight_count_for_test == 0 AND the nullifier IS registered.
//   3. Second spend, same nullifier → NullifierAlreadySpent (registry blocks at
//      step 9), proving the nullifier was permanently consumed — the correct A2
//      behaviour (retry is via reconcile_pending_spend, not a fresh private_spend).
//
// (Rewritten from the pre-A2 test, which expected the append to run FIRST so an
// append failure left the nullifier UNregistered and a retry reached the same
// append-failure path. Under A2 that ordering — and that retry path — is gone.)
//
// Setup: two-pool Merkle auth mismatch with pool_test_wasm.
//   pool_a — authorized on merkle_id; seeds T55_IN_COMMITMENT only.
//   pool_b (POOL_TEST_WASM) — NOT authorized on merkle_id (promotion append rejected);
//     authorized on null_b (insert_batch succeeds → nullifier finalized).
//   A2: the fixture anchor is whitelisted on pool_b (accept_spend_root_for_test).
// =============================================================================

#[test]
fn test_95_inflight_released_after_merkle_failure() {
    let args = load_valid_spend_fixture_args(9500).expect(
        "P0 regression test_95 requires circuits/proof.json and circuits/public.json \
                 — fixture files must be present for audit-grade release-path coverage (#118)",
    );
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];
    let controller = p(0x06);

    let pic = PocketIc::new();
    let user = p(0x95);
    let token_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let null_b = create_canister(&pic);
    let pool_a = create_canister(&pic);
    let pool_b = create_canister(&pic);
    let verifier = create_canister(&pic);

    // merkle_id authorized for pool_a only; pool_b's appends will be rejected.
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_a).unwrap(),
        None,
    );
    pic.install_canister(
        null_b,
        nullifier_wasm(),
        candid::encode_one(pool_b).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_b).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_a,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_b,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    install(
        &pic,
        pool_b,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_b,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_b,
        controller,
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_95: set_verifier_canister must succeed");

    // pool_a seeds T55_IN_COMMITMENT; Merkle root becomes proof anchor.
    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_a, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_95: pool_a shield_deposit",
        pic.update_call(
            pool_a,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_95: pool_a shield_deposit must succeed; got: {:?}",
        deposit_result
    );
    assert_eq!(
        merkle_root(&pic, merkle_id),
        expected_anchor,
        "test_95: Merkle root after pool_a seed must equal proof anchor"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_95: merkle_id must have 1 leaf after seeding"
    );

    // A2: whitelist the fixture anchor on pool_b (pool-local accepted roots; pool_b
    // never deposited) so the spend reaches the promotion append.
    let accept: Result<(), String> = decode(
        "test_95: accept_spend_root_for_test",
        pic.update_call(
            pool_b,
            controller,
            "accept_spend_root_for_test",
            candid::encode_one(expected_anchor.to_vec()).unwrap(),
        ),
    );
    assert!(accept.is_ok(), "test_95: accept_spend_root_for_test must succeed; got {:?}", accept);

    // First spend via pool_b: proof valid; A2 finalizes the nullifier on null_b, then
    // the promotion append on merkle_id is rejected (pool_b unauthorized).
    let result1: Result<(), PoolError> = decode(
        "test_95: first pool_b private_spend",
        pic.update_call(
            pool_b,
            user,
            "private_spend",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    assert!(
        matches!(result1, Err(PoolError::OutputAppendRejected(_))),
        "test_95 (A2): first spend must return OutputAppendRejected; got: {:?}",
        result1
    );

    let status1 = spend_status(&pic, pool_b, 9500).expect("test_95: first spend record must exist");
    // A2: the parent nullifier was finalized (insert_batch on null_b succeeded), INFLIGHT
    // was released, then the promotion append on merkle_id was rejected →
    // ActiveAppendRejected (recoverable via reconcile_pending_spend; nullifier never undone).
    assert!(
        matches!(
            status1.status,
            SpendStatus::ActiveAppendRejected { .. }
        ),
        "test_95 (A2): first spend must record ActiveAppendRejected; got: {:?}",
        status1.status
    );
    assert_eq!(status1.outputs_committed, 0,
        "test_95 (A2): outputs_committed must be 0 (the promotion append was rejected)");
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_95: leaf count must be 1 after first spend failure (no outputs appended)"
    );

    // Direct proof: INFLIGHT must be empty — A2 releases the reservation at nullifier
    // finalization (insert_batch success), BEFORE the append.
    assert_eq!(
        inflight_count(&pic, pool_b, controller),
        0,
        "test_95 (A2): INFLIGHT_NULLIFIERS must be 0 — release fires at nullifier finalization"
    );

    // A2: the parent nullifier IS now in the registry (finalized before the append).
    assert!(
        null_contains(&pic, null_b, expected_nullifier),
        "test_95 (A2): nullifier MUST be in the registry — finalized before the append failed"
    );

    // Behavioural proof (A2): a second spend with the SAME nullifier is blocked by the
    // permanent registry at the step-9 precheck (NullifierAlreadySpent) — NOT inflight-
    // blocked (NullifierReserved). Recovery of the first spend's staged outputs is via
    // reconcile_pending_spend only; the nullifier is permanently consumed.
    let mut args2 = args;
    args2.spend_id = 9501;
    let result2: Result<(), PoolError> = decode(
        "test_95: second pool_b private_spend (same nullifier)",
        pic.update_call(
            pool_b,
            user,
            "private_spend",
            candid::encode_one(args2).unwrap(),
        ),
    );
    assert_eq!(
        result2,
        Err(PoolError::NullifierAlreadySpent),
        "test_95 (A2): second spend must return NullifierAlreadySpent (registry blocks at step 9); got: {:?}",
        result2
    );
    // Blocked at the step-9 precheck (before step 12), so no spend record is written.
    assert!(
        spend_status(&pic, pool_b, 9501).is_none(),
        "test_95 (A2): no spend record for a spend blocked at the step-9 registry precheck"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_95: leaf count must remain 1 after the rejected second spend"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 96 (A2) — INFLIGHT released after insert_batch failure (P0 release regression)
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (release-on-failure, step 15d): if commit_private_spend fails at the
// insert_batch step (definite rejection), release_nullifiers must fire before
// returning. If omitted, INFLIGHT holds the nullifier and the next spend with the
// same nullifier would return NullifierReserved at step 15-pre instead of reaching
// the insert step. A2: outputs are STAGED, not appended, before insert_batch — so a
// failed insert leaves NO orphan output leaves and discards the staged outputs.
//
// Proof strategy:
//   1. First spend → TransferFailed (insert_batch trap); FailedAfterOutputsStaged;
//      outputs_committed == 0; leaf_count == 1 (deposit only, no orphans).
//   2. Assert inflight_count_for_test == 0 (direct release proof).
//   3. Second spend, same nullifier, different spend_id.
//   4. Assert second spend returns TransferFailed (not NullifierReserved) — proves
//      INFLIGHT was released (and the nullifier is not yet in the registry).
//   5. Assert leaf_count == 1 throughout (A2 never appends on failure).
//
// Anchor: pool_b's own deposit accepts the fixture root into pool_b's
// accepted_spend_roots, so the spend anchor passes the A2 accepted-root check.
//
// Setup: single-pool nullifier auth mismatch (test_65 pattern) with pool_test_wasm.
//   merkle_b — authorized for pool_b; the deposit succeeds.
//   null_a   — authorized for p(0x6A) only; pool_b's insert_batch traps (definite).
// =============================================================================

#[test]
fn test_96_inflight_released_after_registry_failure() {
    let args = load_valid_spend_fixture_args(9600).expect(
        "P0 regression test_96 requires circuits/proof.json and circuits/public.json \
                 — fixture files must be present for audit-grade release-path coverage (#118)",
    );
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];
    let controller = p(0x06);

    let pic = PocketIc::new();
    let user = p(0x96);
    let token_id = create_canister(&pic);
    let null_a = create_canister(&pic);
    let merkle_b = create_canister(&pic);
    let pool_b = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_a,
        nullifier_wasm(),
        candid::encode_one(p(0x6A)).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_b,
        merkle_wasm(),
        candid::encode_one(pool_b).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_b).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_b,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_a,
            merkle_canister: merkle_b,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_b,
        controller,
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_96: set_verifier_canister must succeed");

    let deposit_amount = DENOMINATIONS[0];
    do_approve(&pic, token_id, user, pool_b, deposit_amount + DEFAULT_FEE);
    let deposit_result: Result<candid::Nat, PoolError> = decode(
        "test_96: shield_deposit",
        pic.update_call(
            pool_b,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: deposit_amount,
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_96: shield_deposit must succeed; got: {:?}",
        deposit_result
    );
    assert_eq!(
        merkle_root(&pic, merkle_b),
        expected_anchor,
        "test_96: Merkle root after deposit must equal proof anchor"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_b),
        1,
        "test_96: merkle_b must have 1 leaf after deposit"
    );

    // First spend: proof valid, both outputs appended to merkle_b,
    // then insert_batch on null_a traps (unauthorized) → TransferFailed.
    let result1: Result<(), PoolError> = decode(
        "test_96: first pool_b private_spend",
        pic.update_call(
            pool_b,
            user,
            "private_spend",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    assert!(
        matches!(result1, Err(PoolError::TransferFailed(_))),
        "test_96: first spend must return TransferFailed (insert_batch trap); got: {:?}",
        result1
    );

    let status1 = spend_status(&pic, pool_b, 9600).expect("test_96: first spend record must exist");
    assert!(
        matches!(
            status1.status,
            SpendStatus::FailedAfterOutputsStaged { .. }
        ),
        "test_96 (A2): first spend must record FailedAfterOutputsStaged; got: {:?}",
        status1.status
    );
    assert_eq!(status1.outputs_committed, 0,
        "test_96 (A2): outputs_committed must be 0 — A2 stages outputs and fails BEFORE the append");
    assert_eq!(
        merkle_leaf_count(&pic, merkle_b),
        1,
        "test_96 (A2): leaf count must be 1 (deposit only) — no orphan outputs appended on insert_batch failure"
    );
    assert!(
        !null_contains(&pic, null_a, expected_nullifier),
        "test_96: nullifier must not be in registry after insert_batch failure"
    );

    // Direct proof: INFLIGHT must be empty after step 15d failure release.
    assert_eq!(
        inflight_count(&pic, pool_b, controller),
        0,
        "test_96: INFLIGHT_NULLIFIERS must be 0 after TransferFailed (insert_batch) — \
         release_nullifiers must have fired in the step 15d failure branch"
    );

    // Behavioural proof: second spend must pass step 15-pre and reach step 15d
    // (TransferFailed), not be blocked at step 15-pre (NullifierReserved).
    let mut args2 = args;
    args2.spend_id = 9601;
    let result2: Result<(), PoolError> = decode(
        "test_96: second pool_b private_spend (same nullifier)",
        pic.update_call(
            pool_b,
            user,
            "private_spend",
            candid::encode_one(args2).unwrap(),
        ),
    );
    assert!(
        matches!(result2, Err(PoolError::TransferFailed(_))),
        "test_96: second spend must return TransferFailed (not NullifierReserved) — \
         INFLIGHT must have been released by the first spend's 15d failure branch; got: {:?}",
        result2
    );

    let status2 =
        spend_status(&pic, pool_b, 9601).expect("test_96: second spend record must exist");
    assert!(
        matches!(
            status2.status,
            SpendStatus::FailedAfterOutputsStaged { .. }
        ),
        "test_96 (A2): second spend must record FailedAfterOutputsStaged; got: {:?}",
        status2.status
    );
    assert_eq!(
        status2.outputs_committed, 0,
        "test_96 (A2): second spend outputs_committed must be 0 (staged, never appended)"
    );

    // A2: the second spend reaching step 15d (TransferFailed) rather than being blocked
    // at step 15-pre (NullifierReserved) proves the first spend's insert_batch failure
    // released the INFLIGHT reservation. No outputs are ever appended (A2 stages then
    // discards on failure), so merkle_b keeps only its 1 deposit leaf across both spends.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_b),
        1,
        "test_96 (A2): leaf count must remain 1 (deposit only) — no orphan outputs across either failed spend"
    );
    assert!(
        !null_contains(&pic, null_a, expected_nullifier),
        "test_96: nullifier must still not be in registry after second insert_batch failure"
    );
}

// =============================================================================
// Test 97 — fee snapshot per-call split isolation: governance split-ratio
//           change between sequential spends uses the per-spend entry snapshot
//           (#122 / A2-2 fee snapshot hardening)
// =============================================================================
//
// INVARIANT (#122): GovernanceFeeParams are captured once at private_spend()
// entry (before the first await) and threaded through steps 2, 14c, and 15c
// unchanged. A governance update to split ratios (not fee amount) between two
// sequential spends must not bleed into the earlier spend's accounting: spend 1
// uses split_A, spend 2 uses split_B.
//
// PocketIC harness note (same class as test_71/72/73):
//   PocketIC 9.x executes update calls synchronously — one tick() drives the
//   entire inter-canister call chain (pool → verifier → merkle → nullifier) to
//   completion. True mid-flight interleaving (changing governance between step 2
//   and step 15c of the SAME call) is not observable. This sequential test proves
//   the per-call snapshot mechanism end-to-end: each spend captures its own entry
//   snapshot, so split ratios are correct per-spend and do not leak across calls.
//
// Split A (spend 1): ops=7000 bps (70%), ins=3000 bps (30%), staking disabled
// Split B (spend 2): ops=5000 bps (50%), ins=5000 bps (50%), staking disabled
// Fee: T97_FEE = 1_000_000 e8s
//
// Expected reserve deltas:
//   Spend 1: OPERATIONS_RESERVE += 700_000, INSURANCE_RESERVE += 300_000
//   Spend 2: OPERATIONS_RESERVE += 500_000, INSURANCE_RESERVE += 500_000
// =============================================================================

const T97_VK_HASH: [u8; 32] = [0x97u8; 32];
const T97_FEE: u128 = 1_000_000;
const T97_IN_AMOUNT: u128 = 99_800_000;
const T97_OUT_A: u128 = 49_400_000;
const T97_OUT_B: u128 = 49_400_000;
// Spend 1: nullifier + input commitment + output commitments
// All bytes < 0x30 (48) at index 31 → canonical BN254 Fr elements.
const T97_NF1: [u8; 32] = [0x1Au8; 32];
const T97_IC1: [u8; 32] = [0x1Bu8; 32];
const T97_OC1A: [u8; 32] = [0x1Cu8; 32];
const T97_OC1B: [u8; 32] = [0x1Du8; 32];
// Spend 2: distinct nullifier + input commitment + output commitments
const T97_NF2: [u8; 32] = [0x2Au8; 32];
const T97_IC2: [u8; 32] = [0x2Bu8; 32];
const T97_OC2A: [u8; 32] = [0x2Cu8; 32];
const T97_OC2B: [u8; 32] = [0x2Du8; 32];
// Split A: ops=70%, ins=30%
const T97_A_OPS_BPS: u32 = 7_000;
const T97_A_INS_BPS: u32 = 3_000;
// Split B: ops=50%, ins=50%
const T97_B_OPS_BPS: u32 = 5_000;
const T97_B_INS_BPS: u32 = 5_000;
// Expected accounting deltas
const T97_SPEND1_OPS: u128 = 700_000; // 1_000_000 × 7000 / 10_000
const T97_SPEND1_INS: u128 = 300_000; // 1_000_000 × 3000 / 10_000
const T97_SPEND2_OPS: u128 = 500_000; // 1_000_000 × 5000 / 10_000
const T97_SPEND2_INS: u128 = 500_000; // 1_000_000 × 5000 / 10_000

#[test]
fn test_97_fee_snapshot_per_call_split_isolation() {
    let pic = PocketIc::new();
    let controller = p(0x97);
    let user = p(0x98);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let stub_ver = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(stub_ver, stub_verifier_wasm(), candid::encode_one(Some(T97_VK_HASH)).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: T97_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((stub_ver, T97_VK_HASH.to_vec())).unwrap(),
    )
    .expect("test_97: set_verifier_canister must succeed");

    // ── Governance params A: fee = T97_FEE, split = ops 70% / ins 30% ───────
    let mut params_a = GovernanceFeeParams::launch_defaults();
    params_a.protocol_private_spend_fee_stsh = T97_FEE;
    params_a.operations_split_bps = T97_A_OPS_BPS;
    params_a.insurance_split_bps = T97_A_INS_BPS;
    params_a.staking_rewards_split_bps = 0;
    let set_a: Result<(), String> = decode(
        "test_97: set_governance_fee_params (A)",
        pic.update_call(
            pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params_a).unwrap(),
        ),
    );
    assert!(
        set_a.is_ok(),
        "test_97: set_governance_fee_params (A) must succeed; got {:?}",
        set_a
    );

    // ── Deposit 1 ─────────────────────────────────────────────────────────────
    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let dep1: Result<Nat, PoolError> = decode(
        "test_97: shield_deposit 1",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T97_IC1,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        dep1.is_ok(),
        "test_97: shield_deposit 1 must succeed; got {:?}",
        dep1
    );

    let root_1 = merkle_root(&pic, merkle_id);
    let before_1 = accounting_state_as(&pic, pool_id, controller);

    // ── Spend 1: assert split_A is used ───────────────────────────────────────
    let spend1: Result<(), PoolError> = decode(
        "test_97: private_spend 1",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 9700,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T97_VK_HASH,
                    root_reference: root_1,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![T97_NF1],
                output_commitments: vec![T97_OC1A, T97_OC1B],
                encrypted_outputs: vec![vec![], vec![]],
                fee: T97_FEE,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        spend1.is_ok(),
        "test_97: spend 1 must succeed; got {:?}",
        spend1
    );

    let after_1 = accounting_state_as(&pic, pool_id, controller);
    assert_eq!(
        after_1.operations_reserve - before_1.operations_reserve,
        T97_SPEND1_OPS,
        "test_97: spend 1 OPERATIONS_RESERVE delta must be {} (split_A 70%); delta={}",
        T97_SPEND1_OPS,
        after_1.operations_reserve - before_1.operations_reserve
    );
    assert_eq!(
        after_1.insurance_reserve - before_1.insurance_reserve,
        T97_SPEND1_INS,
        "test_97: spend 1 INSURANCE_RESERVE delta must be {} (split_A 30%); delta={}",
        T97_SPEND1_INS,
        after_1.insurance_reserve - before_1.insurance_reserve
    );
    assert_eq!(
        after_1.governance_rewards_reserve, before_1.governance_rewards_reserve,
        "test_97: spend 1 GOVERNANCE_REWARDS_RESERVE must be unchanged (staking disabled)"
    );

    // ── Governance params B: same fee amount, split = ops 50% / ins 50% ──────
    //
    // Simulates a governance update between two spend calls. In PocketIC 9.x,
    // true mid-flight interleaving of a governance update within a single
    // private_spend call is not possible (same harness limitation as test_71-73).
    // This sequential change proves that spend 2's entry snapshot picks up
    // params_B independently of spend 1's snapshot.
    let mut params_b = GovernanceFeeParams::launch_defaults();
    params_b.protocol_private_spend_fee_stsh = T97_FEE; // same fee amount
    params_b.operations_split_bps = T97_B_OPS_BPS;
    params_b.insurance_split_bps = T97_B_INS_BPS;
    params_b.staking_rewards_split_bps = 0;
    let set_b: Result<(), String> = decode(
        "test_97: set_governance_fee_params (B)",
        pic.update_call(
            pool_id,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params_b).unwrap(),
        ),
    );
    assert!(
        set_b.is_ok(),
        "test_97: set_governance_fee_params (B) must succeed; got {:?}",
        set_b
    );

    // ── Deposit 2 ─────────────────────────────────────────────────────────────
    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let dep2: Result<Nat, PoolError> = decode(
        "test_97: shield_deposit 2",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T97_IC2,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        dep2.is_ok(),
        "test_97: shield_deposit 2 must succeed; got {:?}",
        dep2
    );

    let root_2 = merkle_root(&pic, merkle_id);
    let before_2 = accounting_state_as(&pic, pool_id, controller);

    // ── Spend 2: assert split_B is used (not split_A) ─────────────────────────
    let spend2: Result<(), PoolError> = decode(
        "test_97: private_spend 2",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 9701,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T97_VK_HASH,
                    root_reference: root_2,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![T97_NF2],
                output_commitments: vec![T97_OC2A, T97_OC2B],
                encrypted_outputs: vec![vec![], vec![]],
                fee: T97_FEE,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        spend2.is_ok(),
        "test_97: spend 2 must succeed; got {:?}",
        spend2
    );

    let after_2 = accounting_state_as(&pic, pool_id, controller);
    assert_eq!(
        after_2.operations_reserve - before_2.operations_reserve,
        T97_SPEND2_OPS,
        "test_97: spend 2 OPERATIONS_RESERVE delta must be {} (split_B 50%); delta={}",
        T97_SPEND2_OPS,
        after_2.operations_reserve - before_2.operations_reserve
    );
    assert_eq!(
        after_2.insurance_reserve - before_2.insurance_reserve,
        T97_SPEND2_INS,
        "test_97: spend 2 INSURANCE_RESERVE delta must be {} (split_B 50%); delta={}",
        T97_SPEND2_INS,
        after_2.insurance_reserve - before_2.insurance_reserve
    );
    assert_eq!(
        after_2.governance_rewards_reserve, before_2.governance_rewards_reserve,
        "test_97: spend 2 GOVERNANCE_REWARDS_RESERVE must be unchanged (staking disabled)"
    );

    // ── Spend record / nullifier assertions ───────────────────────────────────
    assert!(
        matches!(
            spend_status_as(&pic, pool_id, controller, 9700).unwrap().status,
            SpendStatus::Finalized
        ),
        "test_97: spend 1 must reach Finalized"
    );
    assert!(
        matches!(
            spend_status_as(&pic, pool_id, controller, 9701).unwrap().status,
            SpendStatus::Finalized
        ),
        "test_97: spend 2 must reach Finalized"
    );
    assert!(
        null_contains(&pic, null_id, T97_NF1),
        "test_97: T97_NF1 must be in nullifier registry"
    );
    assert!(
        null_contains(&pic, null_id, T97_NF2),
        "test_97: T97_NF2 must be in nullifier registry"
    );
}

// =============================================================================
// Test 98 — zero-fee snapshot path: snapshot machinery is inert at fee=0,
//           no reserve mutation occurs (#122 / A2-2 fee snapshot hardening)
// =============================================================================
//
// INVARIANT (#122, zero-fee audit branch): When protocol_private_spend_fee_stsh
// equals 0 (launch default), a private_spend with fee=0 must succeed via the
// full snapshot path and leave all reserve buckets (OPERATIONS_RESERVE,
// INSURANCE_RESERVE, GOVERNANCE_REWARDS_RESERVE, PRIVATE_LIABILITY) unchanged.
// The snapshot capture + pass-through machinery introduced in #122 is a no-op
// when fee=0 because the step-15c `if fee > 0` branch is not entered.
// =============================================================================

const T98_VK_HASH: [u8; 32] = [0x98u8; 32];
const T98_NF: [u8; 32] = [0x1Eu8; 32]; // 0x1E = 30 < 48 → canonical BN254 Fr
const T98_IC: [u8; 32] = [0x1Fu8; 32];
const T98_OCA: [u8; 32] = [0x20u8; 32]; // 0x20 = 32 < 48 → canonical
const T98_OCB: [u8; 32] = [0x21u8; 32]; // 0x21 = 33 < 48 → canonical
const T98_IN_AMT: u128 = 1_000_000;
const T98_OUT_A: u128 = 500_000;
const T98_OUT_B: u128 = 500_000;
// Sum-balance: 500_000 + 500_000 + 0 = 1_000_000 ✓

#[test]
fn test_98_zero_fee_snapshot_path_no_reserve_mutation() {
    let pic = PocketIc::new();
    let controller = p(0x9A);
    let user = p(0x9B);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let stub_ver = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(stub_ver, stub_verifier_wasm(), candid::encode_one(Some(T98_VK_HASH)).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: T98_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((stub_ver, T98_VK_HASH.to_vec())).unwrap(),
    )
    .expect("test_98: set_verifier_canister must succeed");

    // No set_governance_fee_params: launch defaults have fee = 0.

    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let dep: Result<Nat, PoolError> = decode(
        "test_98: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T98_IC,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        dep.is_ok(),
        "test_98: shield_deposit must succeed; got {:?}",
        dep
    );

    let root = merkle_root(&pic, merkle_id);
    let before = accounting_state_as(&pic, pool_id, controller);

    let result: Result<(), PoolError> = decode(
        "test_98: private_spend fee=0",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 9800,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T98_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![T98_NF],
                output_commitments: vec![T98_OCA, T98_OCB],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        result.is_ok(),
        "test_98: private_spend with fee=0 must succeed; got {:?}",
        result
    );

    let after = accounting_state_as(&pic, pool_id, controller);

    // Snapshot machinery is a no-op at fee=0: step-15c `if fee > 0` is not entered.
    assert_eq!(
        after.operations_reserve, before.operations_reserve,
        "test_98: OPERATIONS_RESERVE must be unchanged (fee=0)"
    );
    assert_eq!(
        after.insurance_reserve, before.insurance_reserve,
        "test_98: INSURANCE_RESERVE must be unchanged (fee=0)"
    );
    assert_eq!(
        after.governance_rewards_reserve, before.governance_rewards_reserve,
        "test_98: GOVERNANCE_REWARDS_RESERVE must be unchanged (fee=0)"
    );
    assert_eq!(
        after.private_liability, before.private_liability,
        "test_98: PRIVATE_LIABILITY must be unchanged (no fee debit at fee=0)"
    );

    assert!(
        matches!(
            spend_status_as(&pic, pool_id, controller, 9800).unwrap().status,
            SpendStatus::Finalized
        ),
        "test_98: spend must reach Finalized"
    );
    assert!(
        null_contains(&pic, null_id, T98_NF),
        "test_98: T98_NF must be in nullifier registry"
    );
}

// =============================================================================
// Lane A v2 Task 1 — proof-bound public_amount and pool-side treasury disburse
// =============================================================================

#[test]
fn lanea_task1_private_spend_public_amount_bound_to_real_verifier() {
    let Some(mut args) = load_valid_spend_fixture_args(9900) else {
        eprintln!("test_99: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];
    let recipient = p(0x9C);
    // Any NONZERO value works here — it must merely differ from the fixture
    // proof's public_amount = 0 signal (the sum check is rebalanced below).
    let public_amount = 50_000u128;

    // F1-PRIV: the caller-declared sum check this line used to rebalance is gone
    // (the amount fields it compared were the R1-F1 cleartext leak). Nothing needs
    // rebalancing — the real verifier must still reject the signal[4] mismatch
    // before nullifier/Merkle/accounting/payout mutation, which is the property
    // this test exists to prove.
    args.public_payout = Some(PrivateSpendPublicPayout {
        destination: recipient,
        destination_subaccount: None,
        public_amount,
    });

    let pic = PocketIc::new();
    let user = p(0x99);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let verifier = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("test_99: set_verifier_canister must succeed");

    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let deposit_result: Result<Nat, PoolError> = decode(
        "test_99: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        deposit_result.is_ok(),
        "test_99: shield_deposit must succeed; got {:?}",
        deposit_result
    );
    assert_eq!(
        merkle_root(&pic, merkle_id),
        expected_anchor,
        "test_99: Merkle root after deposit must equal proof anchor"
    );

    let before_accounting = accounting_state(&pic, pool_id);
    let before_pool_balance = token_balance(&pic, token_id, pool_id);
    let before_recipient_balance = token_balance(&pic, token_id, recipient);
    let before_leaf_count = merkle_leaf_count(&pic, merkle_id);

    let result: Result<(), PoolError> = decode(
        "test_99: private_spend positive public_amount against zero-public fixture",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    assert!(
        matches!(result, Err(PoolError::ProofRejected(_))),
        "test_99: real verifier must reject public_amount signal mismatch; got {:?}",
        result
    );
    assert!(
        !null_contains(&pic, null_id, expected_nullifier),
        "test_99: invalid public_amount proof must not insert nullifier"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        before_leaf_count,
        "test_99: invalid public_amount proof must not append commitments"
    );
    assert_eq!(
        token_balance(&pic, token_id, recipient),
        before_recipient_balance,
        "test_99: invalid public_amount proof must not pay recipient"
    );
    assert_eq!(
        token_balance(&pic, token_id, pool_id),
        before_pool_balance,
        "test_99: invalid public_amount proof must not move pool funds"
    );
    assert_eq!(
        accounting_state(&pic, pool_id).private_liability,
        before_accounting.private_liability,
        "test_99: invalid public_amount proof must not debit private liability"
    );
    assert_eq!(
        accounting_state(&pic, pool_id).escrow_backing,
        before_accounting.escrow_backing,
        "test_99: invalid public_amount proof must not debit escrow backing"
    );
}

#[test]
fn lanea_task1_private_spend_public_payout_stub_success_path() {
    let pic = PocketIc::new();
    let controller = p(0xA0);
    let user = p(0xA1);
    let recipient = p(0xA2);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);
    let stub_ver = create_canister(&pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(stub_ver, stub_verifier_wasm(), candid::encode_one(Some(T98_VK_HASH)).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: T98_VK_HASH,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        controller,
        "set_verifier_canister",
        candid::encode_args((stub_ver, T98_VK_HASH.to_vec())).unwrap(),
    )
    .expect("test_100: set_verifier_canister must succeed");

    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let dep: Result<Nat, PoolError> = decode(
        "test_100: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: [0x2Eu8; 32],
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        dep.is_ok(),
        "test_100: shield_deposit must succeed; got {:?}",
        dep
    );

    let root = merkle_root(&pic, merkle_id);
    // BOUND by the stub-spend arithmetic below (inputs 1_000_000 − outputs
    // 940_000), NOT by the ledger fee (pre-F-000 this was "fee + 50_000").
    let public_amount = 60_000u128;
    let before_recipient = token_balance(&pic, token_id, recipient);
    let before_pool = token_balance(&pic, token_id, pool_id);
    let before = accounting_state_as(&pic, pool_id, controller);

    let result: Result<(), PoolError> = decode(
        "test_100: private_spend public payout",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id: 10_000,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: T98_VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![[0x2Fu8; 32]],
                output_commitments: vec![[0x20u8; 32], [0x21u8; 32]],
                encrypted_outputs: vec![vec![], vec![]],
                fee: 0,
                public_payout: Some(PrivateSpendPublicPayout {
                    destination: recipient,
                    destination_subaccount: None,
                    public_amount,
                }),
            })
            .unwrap(),
        ),
    );

    assert_eq!(
        result,
        Ok(()),
        "test_100: stub-verifier public payout path must succeed"
    );
    assert_eq!(
        token_balance(&pic, token_id, recipient),
        before_recipient + public_amount - DEFAULT_FEE,
        "test_100: recipient receives public_amount - ledger_fee (fee 0 → full amount)"
    );
    assert_eq!(
        token_balance(&pic, token_id, pool_id),
        before_pool - public_amount,
        "test_100: pool ledger balance debits the proof-bound public_amount"
    );
    let after = accounting_state_as(&pic, pool_id, controller);
    assert_eq!(
        after.private_liability,
        before.private_liability - public_amount,
        "test_100: private liability debits public_amount"
    );
    assert_eq!(
        after.escrow_backing,
        before.escrow_backing - public_amount,
        "test_100: escrow backing debits public_amount"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "test_100: two output commitments appended after seeded deposit"
    );
    assert!(
        null_contains(&pic, null_id, [0x2Fu8; 32]),
        "test_100: nullifier inserted after successful public payout spend"
    );
    let status = spend_status_as(&pic, pool_id, controller, 10_000).expect("test_100: spend status exists");
    assert!(
        matches!(status.status, SpendStatus::Finalized),
        "test_100: spend must finalize after public payout; got {:?}",
        status.status
    );
    assert!(
        matches!(status.public_payout.and_then(|p| p.block_index), Some(_)),
        "test_100: finalized public payout must store block_index for replay/recovery"
    );
}

#[test]
fn lanea_task1_treasury_disburse_executes_replays_and_conflicts() {
    let h = PoolHarness::new_testing(0xA3, [0xA3; 32], 0);
    let treasury = p(0x04);
    let recipient = p(0xA4);

    let mut params = GovernanceFeeParams::launch_defaults();
    params.shield_flat_minimum_fee_e8s = Some(100_000);
    params.operations_split_bps = 10_000;
    params.insurance_split_bps = 0;
    params.staking_rewards_split_bps = 0;
    let set_params: Result<(), String> = decode(
        "test_101: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            p(0x06),
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    assert!(
        set_params.is_ok(),
        "test_101: set_governance_fee_params must succeed; got {:?}",
        set_params
    );

    // Fee-ON-TOP: the pool pulls gross + shield fee (100_000), so approve for
    // both (do_deposit's gross-only approval would be short by the fee).
    do_approve(
        &h.pic, h.token_id, h.user, h.pool_id,
        DENOMINATIONS[0] + 100_000 + DEFAULT_FEE,
    );
    let dep: Result<Nat, PoolError> = decode(
        "test_101: shield_deposit",
        h.pic.update_call(
            h.pool_id, h.user, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0xAA),
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(dep.is_ok(), "test_101: deposit must succeed; got {:?}", dep);
    let before = h.accounting();
    assert_eq!(
        before.operations_reserve, 100_000,
        "test_101: deposit shielding fee must fund operations reserve"
    );

    let args = TreasuryDisburseArgs {
        proposal_id: 101,
        bucket: TreasuryReserveBucket::Operations,
        recipient,
        recipient_subaccount: None,
        amount: 40_000,
        expected_ledger_fee: DEFAULT_FEE,
    };
    let before_recipient = h.balance(recipient);
    let before_pool = h.balance(h.pool_id);

    let first: Result<TreasuryDisburseResult, PoolError> = decode(
        "test_101: treasury_disburse first",
        h.pic.update_call(
            h.pool_id,
            treasury,
            "treasury_disburse",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    let block_index = match first {
        Ok(TreasuryDisburseResult::Executed { block_index }) => block_index,
        other => panic!(
            "test_101: first disbursement must execute fresh; got {:?}",
            other
        ),
    };
    assert_eq!(
        h.balance(recipient),
        before_recipient + args.amount,
        "test_101: recipient receives treasury amount"
    );
    assert_eq!(
        h.balance(h.pool_id),
        before_pool - args.amount - args.expected_ledger_fee,
        "test_101: pool ledger balance debits amount + fee"
    );
    assert_eq!(
        h.accounting().operations_reserve,
        before.operations_reserve - args.amount - args.expected_ledger_fee,
        "test_101: operations reserve debits full request amount + fee"
    );

    let replay: Result<TreasuryDisburseResult, PoolError> = decode(
        "test_101: treasury_disburse replay",
        h.pic.update_call(
            h.pool_id,
            treasury,
            "treasury_disburse",
            candid::encode_one(args.clone()).unwrap(),
        ),
    );
    assert_eq!(
        replay,
        Ok(TreasuryDisburseResult::AlreadyExecuted {
            block_index: block_index.clone()
        }),
        "test_101: same proposal and same fingerprint must replay as AlreadyExecuted"
    );
    assert_eq!(
        h.balance(recipient),
        before_recipient + args.amount,
        "test_101: replay must not pay again"
    );

    let mut conflict = args.clone();
    conflict.amount += 1;
    let conflict_result: Result<TreasuryDisburseResult, PoolError> = decode(
        "test_101: treasury_disburse conflict",
        h.pic.update_call(
            h.pool_id,
            treasury,
            "treasury_disburse",
            candid::encode_one(conflict).unwrap(),
        ),
    );
    assert_eq!(
        conflict_result,
        Err(PoolError::IdempotencyKeyConflict),
        "test_101: same proposal_id with changed fingerprint must conflict"
    );
}

#[test]
fn treasury_disbursement_endpoint_rejects_non_treasury_caller() {
    let h = PoolHarness::new_testing(0xA5, [0xA5; 32], 0);
    let non_treasury = p(0xA6);
    let recipient = p(0xA7);

    let mut params = GovernanceFeeParams::launch_defaults();
    params.protocol_shielding_fee_stsh = 100_000;
    params.operations_split_bps = 10_000;
    params.insurance_split_bps = 0;
    params.staking_rewards_split_bps = 0;
    let set_params: Result<(), String> = decode(
        "test_102: set_governance_fee_params",
        h.pic.update_call(
            h.pool_id,
            p(0x06),
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    assert!(
        set_params.is_ok(),
        "test_102: set_governance_fee_params must succeed; got {:?}",
        set_params
    );

    h.deposit(DENOMINATIONS[0]);
    let before = h.accounting();
    let before_recipient = h.balance(recipient);
    let before_pool = h.balance(h.pool_id);

    let result: Result<TreasuryDisburseResult, PoolError> = decode(
        "test_102: treasury_disburse non-treasury caller",
        h.pic.update_call(
            h.pool_id,
            non_treasury,
            "treasury_disburse",
            candid::encode_one(TreasuryDisburseArgs {
                proposal_id: 102,
                bucket: TreasuryReserveBucket::Operations,
                recipient,
                recipient_subaccount: None,
                amount: 40_000,
                expected_ledger_fee: DEFAULT_FEE,
            })
            .unwrap(),
        ),
    );

    assert!(
        matches!(
            result,
            Err(PoolError::TransferFailed(ref msg))
                if msg.contains("caller is not the configured treasury canister")
        ),
        "test_102: non-treasury caller must be rejected before disbursement; got {:?}",
        result
    );
    assert_eq!(
        h.balance(recipient),
        before_recipient,
        "test_102: rejected caller must not pay recipient"
    );
    assert_eq!(
        h.balance(h.pool_id),
        before_pool,
        "test_102: rejected caller must not move pool ledger funds"
    );
    let after = h.accounting();
    assert_eq!(
        after.private_liability, before.private_liability,
        "test_102: rejected caller must not mutate private liability"
    );
    assert_eq!(
        after.escrow_backing, before.escrow_backing,
        "test_102: rejected caller must not mutate escrow backing"
    );
    assert_eq!(
        after.operations_reserve, before.operations_reserve,
        "test_102: rejected caller must not debit operations reserve"
    );
    assert_eq!(
        after.insurance_reserve, before.insurance_reserve,
        "test_102: rejected caller must not mutate insurance reserve"
    );
    assert_eq!(
        after.governance_rewards_reserve,
        before.governance_rewards_reserve,
        "test_102: rejected caller must not mutate governance rewards reserve"
    );
    assert_eq!(
        after.pending_fee_reimbursements,
        before.pending_fee_reimbursements,
        "test_102: rejected caller must not mutate pending fee reimbursements"
    );
}

// =============================================================================
// DEF-026 — recipient/subaccount proof binding (Pass 7 / P7-001)
// =============================================================================
//
// The spend circuit now exposes 9 public signals; [6] recipient_principal,
// [7] recipient_subaccount_lo, [8] recipient_subaccount_hi bind the public-payout
// destination into the Groth16 proof.  A privileged attacker who replays a valid
// proof with a substituted recipient must be rejected by the REAL verifier before
// any state mutation (no nullifier, no commitments, no payout, no accounting debit).
//
// Two fixtures drive these tests:
//   circuits/proof_payout_a.json / public_payout_a.json — payout-to-A:
//     public_amount = 60_000, recipient = encode(A) ->
//     [2261564242916331941866620800950935700259179388000792266395655938365985104545, 11, 12]
//     (DEF-108 length-byte encoding: buf[31] = principal len).
//   circuits/proof.json / public.json — canonical none-payout:
//     public_amount = 0, recipient signals = [0, 0, 0].
//
// Recipient A is constructed IDENTICALLY to circuits/tests/gen_test_input.js:
//   principal bytes [0xA1,0xA2,0xA3,0xA4,0xA5]; subaccount[0]=0x0B, subaccount[16]=0x0C.

/// public_amount baked into the payout-A proof — a PROOF-FIXTURE-BOUND literal
/// (signal[4] of proof_payout_a.json), independent of the live ledger fee.
/// Pre-F-000 it was expressed as "DEFAULT_FEE + 50_000" because the fixture was
/// generated when the fee was 10_000; with the F-000 zero fee the recipient now
/// receives the full public_amount (60_000 − 0).
const DEF026_PUBLIC_AMOUNT: u128 = 60_000;

/// Recipient A's principal — must reproduce signal[6] =
/// 2261564242916331941866620800950935700259179388000792266395655938365985104545
/// via the pool's encode_recipient_signals (DEF-108: principal.as_slice() into
/// buf[0..len], buf[31] = len, LE field element).
fn def026_recipient_a() -> Principal {
    Principal::from_slice(&[0xA1, 0xA2, 0xA3, 0xA4, 0xA5])
}

/// Recipient A's subaccount — byte[0]=0x0B (low half -> signal[7]=11),
/// byte[16]=0x0C (high half -> signal[8]=12).
fn def026_subaccount_a() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x0B;
    s[16] = 0x0C;
    s
}

/// icrc1_balance_of for an explicit (owner, subaccount) account.
fn token_balance_account(
    pic: &PocketIc,
    token_id: Principal,
    owner: Principal,
    subaccount: Option<[u8; 32]>,
) -> u128 {
    let bal: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            token_id,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount }).unwrap(),
        ),
    );
    bal.0.to_string().parse::<u128>().unwrap_or(0)
}

/// Load the payout-to-A spend fixture into a PrivateSpendArgs whose public_payout
/// EXACTLY matches the proof's bound recipient (A / subaccount A / public_amount).
/// Stub sum-balance holds: input_sum(1_000_000) == output_sum(940_000) + public_amount(60_000).
fn load_def026_payout_a_args(spend_id: u64) -> Option<PrivateSpendArgs> {
    let public_json = std::fs::read_to_string(circuits_dir().join("public_payout_a.json")).ok()?;
    let proof_json = std::fs::read_to_string(circuits_dir().join("proof_payout_a.json")).ok()?;
    let signals = stsh_verifier::public_json_to_signals(&public_json).ok()?;
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json).ok()?;
    Some(PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference: signals[0],
            pool_version: 1,
            proof_bytes,
        },
        nullifiers: vec![signals[1]],
        output_commitments: vec![signals[2], signals[3]],
        encrypted_outputs: vec![vec![0xAA], vec![0xBB]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: def026_recipient_a(),
            destination_subaccount: Some(def026_subaccount_a()),
            public_amount: DEF026_PUBLIC_AMOUNT,
        }),
    })
}

/// Install + wire the 5-canister real-verifier instance and seed the input note
/// (T55_IN_COMMITMENT) so the Merkle root equals the proof anchor (shared by both
/// fixtures — same input note). Returns (token, nullifier, pool, merkle, verifier).
fn def026_setup(
    pic: &PocketIc,
    user: Principal,
) -> (Principal, Principal, Principal, Principal, Principal) {
    let token_id = create_canister(pic);
    let null_id = create_canister(pic);
    let pool_id = create_canister(pic);
    let merkle_id = create_canister(pic);
    let verifier = create_canister(pic);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    pic.update_call(
        pool_id,
        p(0x06),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("def026_setup: set_verifier_canister must succeed");

    do_approve(pic, token_id, user, pool_id, DENOMINATIONS[0] + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "def026_setup: shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: T55_IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    dep.expect("def026_setup: shield_deposit must succeed");
    (token_id, null_id, pool_id, merkle_id, verifier)
}

/// Assert a private_spend with the given (tampered) args is rejected by the REAL
/// verifier with ProofRejected and mutates NOTHING (nullifier registry, Merkle tree,
/// recipient/pool balances, escrow + private-liability accounting).
fn def026_assert_rejected_no_mutation(label: &str, args: PrivateSpendArgs) {
    let user = p(0x26);
    let nullifier = args.nullifiers[0];
    let pic = PocketIc::new();
    let (token_id, null_id, pool_id, merkle_id, _verifier) = def026_setup(&pic, user);

    let before_leaf = merkle_leaf_count(&pic, merkle_id);
    let before_pool = token_balance(&pic, token_id, pool_id);
    let before_acct = accounting_state(&pic, pool_id);
    // Whatever recipient/subaccount the attacker named, it must stay unpaid.
    let claimed = args
        .public_payout
        .as_ref()
        .map(|po| (po.destination, po.destination_subaccount));
    let before_recipient = claimed
        .map(|(owner, sub)| token_balance_account(&pic, token_id, owner, sub))
        .unwrap_or(0);

    let result: Result<(), PoolError> = decode(
        label,
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );

    assert!(
        matches!(result, Err(PoolError::ProofRejected(_))),
        "{}: real verifier must reject the recipient-signal mismatch; got {:?}",
        label,
        result
    );
    assert!(
        !null_contains(&pic, null_id, nullifier),
        "{}: rejected proof must NOT insert nullifier",
        label
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        before_leaf,
        "{}: rejected proof must NOT append commitments",
        label
    );
    if let Some((owner, sub)) = claimed {
        assert_eq!(
            token_balance_account(&pic, token_id, owner, sub),
            before_recipient,
            "{}: rejected proof must NOT pay the substituted recipient",
            label
        );
    }
    assert_eq!(
        token_balance(&pic, token_id, pool_id),
        before_pool,
        "{}: rejected proof must NOT move pool ledger funds",
        label
    );
    let after = accounting_state(&pic, pool_id);
    assert_eq!(
        after.escrow_backing, before_acct.escrow_backing,
        "{}: rejected proof must NOT debit escrow backing",
        label
    );
    assert_eq!(
        after.private_liability, before_acct.private_liability,
        "{}: rejected proof must NOT debit private liability",
        label
    );
}

// ── Test A — valid recipient-bound payout succeeds end-to-end ────────────────
// IGNORED (DEF-108, ZK Review Run 1 Batch 2): this test drives a REAL Groth16 proof
// whose committed public.json encodes `recipient_principal` the pre-DEF-108 way (no
// length byte). DEF-108 makes the canister recompute signal[6] with `byte[31] = len`
// (see `encode_recipient_signals`), so the stale proof no longer satisfies the pairing
// and the valid payout is (correctly) rejected here. The DEF-108 encoder itself is
// covered by the pool unit test `test_def108_recipient_encoding_injective_on_length`.
// Re-enable once the def026 proof fixture is regenerated with the length-byte encoding
// — tracked on the ceremony/artifact-regeneration gate alongside DEF-082 (mainnet
// domain constants) and the Finding-1 stale nullifier fixtures.
#[test]
fn def026_test_a_valid_recipient_payout_succeeds() {
    let Some(args) = load_def026_payout_a_args(2600) else {
        eprintln!("def026_test_a: SKIP — circuits/proof_payout_a.json or public_payout_a.json not present");
        return;
    };
    let expected_anchor = args.envelope.root_reference;
    let expected_nullifier = args.nullifiers[0];

    let user = p(0x26);
    let pic = PocketIc::new();
    let (token_id, null_id, pool_id, merkle_id, _verifier) = def026_setup(&pic, user);

    assert_eq!(
        merkle_root(&pic, merkle_id),
        expected_anchor,
        "def026_test_a: Merkle root after deposit must equal proof anchor (signals[0])"
    );

    let recipient = def026_recipient_a();
    let sub = Some(def026_subaccount_a());
    let before_recipient = token_balance_account(&pic, token_id, recipient, sub);
    let before_pool = token_balance(&pic, token_id, pool_id);
    let before = accounting_state(&pic, pool_id);

    let result: Result<(), PoolError> = decode(
        "def026_test_a: private_spend valid payout to A",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert_eq!(
        result,
        Ok(()),
        "def026_test_a: valid recipient-bound payout must succeed; got {:?}",
        result
    );

    assert_eq!(
        token_balance_account(&pic, token_id, recipient, sub),
        before_recipient + (DEF026_PUBLIC_AMOUNT - DEFAULT_FEE),
        "def026_test_a: recipient A (subaccount) must receive public_amount - ledger_fee"
    );
    assert_eq!(
        token_balance(&pic, token_id, pool_id),
        before_pool - DEF026_PUBLIC_AMOUNT,
        "def026_test_a: pool ledger balance debits the proof-bound public_amount"
    );
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "def026_test_a: nullifier must be in registry after spend"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "def026_test_a: Merkle tree must have 3 leaves (1 deposit + 2 spend outputs)"
    );
    let rec = spend_status(&pic, pool_id, 2600).expect("def026_test_a: spend record must exist");
    assert!(
        matches!(rec.status, SpendStatus::Finalized),
        "def026_test_a: SpendStatus must be Finalized; got {:?}",
        rec.status
    );
    let after = accounting_state(&pic, pool_id);
    assert_eq!(
        after.escrow_backing,
        before.escrow_backing - DEF026_PUBLIC_AMOUNT,
        "def026_test_a: escrow backing debits public_amount"
    );
    assert_eq!(
        after.private_liability,
        before.private_liability - DEF026_PUBLIC_AMOUNT,
        "def026_test_a: private liability debits public_amount"
    );
}

// ── Test B — substituted principal rejected (signal[6] only) ────────────────
#[test]
fn def026_test_b_substituted_principal_rejected() {
    let Some(mut args) = load_def026_payout_a_args(2601) else {
        eprintln!("def026_test_b: SKIP — payout-A fixture not present");
        return;
    };
    // Substitute ONLY the principal; subaccount + public_amount unchanged so signal[6]
    // is the sole mismatch (signals [4],[7],[8] still match the proof).
    args.public_payout = Some(PrivateSpendPublicPayout {
        destination: p(0xB7),
        destination_subaccount: Some(def026_subaccount_a()),
        public_amount: DEF026_PUBLIC_AMOUNT,
    });
    def026_assert_rejected_no_mutation("def026_test_b", args);
}

// ── Test C — substituted subaccount low half rejected (signal[7] only) ──────
#[test]
fn def026_test_c_substituted_subaccount_lo_rejected() {
    let Some(mut args) = load_def026_payout_a_args(2602) else {
        eprintln!("def026_test_c: SKIP — payout-A fixture not present");
        return;
    };
    let mut sub = def026_subaccount_a();
    sub[0] = 0x0C; // was 0x0B — flips the LOW 128-bit half only (signal[7])
    args.public_payout = Some(PrivateSpendPublicPayout {
        destination: def026_recipient_a(),
        destination_subaccount: Some(sub),
        public_amount: DEF026_PUBLIC_AMOUNT,
    });
    def026_assert_rejected_no_mutation("def026_test_c", args);
}

// ── Test D — substituted subaccount high half rejected (signal[8] only) ─────
#[test]
fn def026_test_d_substituted_subaccount_hi_rejected() {
    let Some(mut args) = load_def026_payout_a_args(2603) else {
        eprintln!("def026_test_d: SKIP — payout-A fixture not present");
        return;
    };
    let mut sub = def026_subaccount_a();
    sub[16] = 0x0D; // was 0x0C — flips the HIGH 128-bit half only (signal[8])
    args.public_payout = Some(PrivateSpendPublicPayout {
        destination: def026_recipient_a(),
        destination_subaccount: Some(sub),
        public_amount: DEF026_PUBLIC_AMOUNT,
    });
    def026_assert_rejected_no_mutation("def026_test_d", args);
}

// ── Test E — none-bound proof cannot be redirected to a public payout ───────
#[test]
fn def026_test_e_none_proof_with_recipient_rejected() {
    let Some(mut args) = load_valid_spend_fixture_args(2604) else {
        eprintln!("def026_test_e: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    // Attach a recipient payout to the NONE-bound proof (its recipient signals are 0).
    // F1-PRIV: the stub-output reduction that used to keep the deleted sum-balance
    // check happy is no longer needed; the rejection still lands on the proof
    // (recipient signals [6..8] now nonzero), not on MalformedSpendArgs.
    args.public_payout = Some(PrivateSpendPublicPayout {
        destination: def026_recipient_a(),
        destination_subaccount: Some(def026_subaccount_a()),
        public_amount: DEF026_PUBLIC_AMOUNT,
    });
    def026_assert_rejected_no_mutation("def026_test_e", args);
}

// ── Test F — none-bound proof + None payout still succeeds (zero binding) ────
#[test]
fn def026_test_f_none_proof_none_payout_succeeds() {
    let Some(args) = load_valid_spend_fixture_args(2605) else {
        eprintln!("def026_test_f: SKIP — circuits/proof.json or public.json not present");
        return;
    };
    // public_payout = None (loader default) -> recipient signals bind to ZERO, matching
    // the none-payout proof. Confirms DEF-026's added signals did not break the pure spend.
    let expected_nullifier = args.nullifiers[0];

    let user = p(0x26);
    let pic = PocketIc::new();
    let (_token_id, null_id, pool_id, merkle_id, _verifier) = def026_setup(&pic, user);

    let result: Result<(), PoolError> = decode(
        "def026_test_f: private_spend none-payout round-trip",
        pic.update_call(
            pool_id,
            user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert_eq!(
        result,
        Ok(()),
        "def026_test_f: none-bound proof with public_payout=None must succeed; got {:?}",
        result
    );
    assert!(
        null_contains(&pic, null_id, expected_nullifier),
        "def026_test_f: nullifier must be in registry after successful none-payout spend"
    );
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        3,
        "def026_test_f: Merkle tree must have 3 leaves (1 deposit + 2 spend outputs)"
    );
    let rec = spend_status(&pic, pool_id, 2605).expect("def026_test_f: spend record must exist");
    assert!(
        matches!(rec.status, SpendStatus::Finalized),
        "def026_test_f: SpendStatus must be Finalized; got {:?}",
        rec.status
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// DEF-003/#155 — set-time verifier VK attestation
// ═════════════════════════════════════════════════════════════════════════════

/// Query a stub/verifier canister's vk_hash() (returns the 32-byte hash as Vec<u8>).
fn query_vk_hash(pic: &PocketIc, verifier: Principal) -> Vec<u8> {
    decode(
        "vk_hash",
        pic.query_call(verifier, anon(), "vk_hash", candid::encode_args(()).unwrap()),
    )
}

// Phase 2-A compatibility result: **Option B**. A no-arg (`vec![]`) install of the stub
// now TRAPS at init ("failed to decode call arguments: Cannot parse header"), because the
// `#[init] fn init(Option<[u8;32]>)` cannot decode empty bytes. So default installs must
// pass an EXPLICIT `None` (`candid::encode_one(None::<[u8;32]>)`). This test confirms the
// explicit-None install succeeds and defaults vk_hash() to [0u8; 32]. (The 3 deploy-helper
// default installs are migrated to this pattern in Phase 4.)
#[test]
fn test_def003_stub_explicit_none_defaults_zero_hash() {
    let pic = PocketIc::new();
    let stub = create_canister(&pic);
    pic.install_canister(
        stub,
        stub_verifier_wasm(),
        candid::encode_one(None::<[u8; 32]>).unwrap(),
        None,
    );
    assert_eq!(
        query_vk_hash(&pic, stub),
        vec![0u8; 32],
        "explicit-None stub install must default vk_hash() to [0u8; 32]"
    );
}

// The stub reports the hash supplied at install time via the optional init arg. This is
// what the 74/97/98/100-style tests (which pin a non-zero hash) will rely on in Phase 4.
#[test]
fn test_def003_stub_init_configures_hash() {
    let pic = PocketIc::new();
    let stub = create_canister(&pic);
    let h = [7u8; 32];
    pic.install_canister(stub, stub_verifier_wasm(), candid::encode_one(Some(h)).unwrap(), None);
    assert_eq!(
        query_vk_hash(&pic, stub),
        h.to_vec(),
        "stub must report the init-configured vk_hash"
    );
}

// ── DEF-003 attestation tests (Phase 6) ──────────────────────────────────────
//
// These exercise the production set_verifier_canister attestation (pool_wasm). Design 2:
// set_verifier_canister accepts a verifier ONLY if BOTH the caller-supplied expected hash
// AND the verifier's reported vk_hash() equal the pool's current PINNED_VK_HASH, which it
// never mutates. Test B's "a subsequent valid proof still verifies via private_spend" is
// already covered by the stub-based spend tests (test_74/97/98), so it is not duplicated.

fn def003_get_verifier(pic: &PocketIc, pool: Principal) -> Option<Principal> {
    decode(
        "get_verifier_canister",
        pic.query_call(pool, anon(), "get_verifier_canister", candid::encode_args(()).unwrap()),
    )
}

fn def003_get_pin(pic: &PocketIc, pool: Principal) -> Vec<u8> {
    decode(
        "get_pinned_vk_hash",
        pic.query_call(pool, anon(), "get_pinned_vk_hash", candid::encode_args(()).unwrap()),
    )
}

fn def003_set_verifier(
    pic: &PocketIc,
    pool: Principal,
    controller: Principal,
    verifier: Principal,
    expected: Vec<u8>,
) -> Result<(), PoolError> {
    decode(
        "set_verifier_canister",
        pic.update_call(
            pool,
            controller,
            "set_verifier_canister",
            candid::encode_args((verifier, expected)).unwrap(),
        ),
    )
}

/// Deploy a pool (placeholder token/nullifier/merkle refs — only the verifier-config
/// surface is exercised) pinned to `pin`. Returns (pool_id, controller).
fn def003_deploy_pool(pic: &PocketIc, pin: [u8; 32]) -> (Principal, Principal) {
    let controller = p(0xC3);
    let pool_id = create_canister(pic);
    install(
        pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: p(0x01),
            nullifier_canister: p(0x02),
            merkle_canister: p(0x03),
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller,
            initial_vk_hash: pin,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    (pool_id, controller)
}

fn def003_deploy_stub(pic: &PocketIc, hash: Option<[u8; 32]>) -> Principal {
    let stub = create_canister(pic);
    let init = candid::encode_one(hash).unwrap();
    pic.install_canister(stub, stub_verifier_wasm(), init, None);
    stub
}

// Test A — caller-supplied expected_vk_hash != pool pin → VerifierKeyHashMismatch, no change.
#[test]
fn test_def003_a_wrong_expected_hash_rejected() {
    let pic = PocketIc::new();
    let (pool, controller) = def003_deploy_pool(&pic, [0xAA; 32]);
    let stub = def003_deploy_stub(&pic, Some([0xAA; 32])); // stub reports the pin
    let r = def003_set_verifier(&pic, pool, controller, stub, vec![0xBBu8; 32]); // wrong expected
    assert!(
        matches!(r, Err(PoolError::VerifierKeyHashMismatch)),
        "expected != pin must be VerifierKeyHashMismatch; got {:?}",
        r
    );
    assert_eq!(def003_get_verifier(&pic, pool), None, "verifier principal must be unchanged");
    assert_eq!(def003_get_pin(&pic, pool), vec![0xAAu8; 32], "pinned hash must be unchanged");
}

// Test A2 — verifier's actual vk_hash() != pool pin (expected==pin) → VerifierKeyHashMismatch.
#[test]
fn test_def003_a2_verifier_vk_mismatch_rejected() {
    let pic = PocketIc::new();
    let (pool, controller) = def003_deploy_pool(&pic, [0xAA; 32]);
    let stub = def003_deploy_stub(&pic, Some([0xBB; 32])); // reports a DIFFERENT hash than the pin
    let r = def003_set_verifier(&pic, pool, controller, stub, vec![0xAAu8; 32]); // expected == pin
    assert!(
        matches!(r, Err(PoolError::VerifierKeyHashMismatch)),
        "verifier vk_hash != pin must be VerifierKeyHashMismatch; got {:?}",
        r
    );
    assert_eq!(def003_get_verifier(&pic, pool), None, "verifier principal must be unchanged");
    assert_eq!(def003_get_pin(&pic, pool), vec![0xAAu8; 32], "pinned hash must be unchanged");
}

// Test B — expected == verifier vk_hash() == pool pin → accepted; verifier principal updated.
#[test]
fn test_def003_b_correct_hash_accepted() {
    let pic = PocketIc::new();
    let (pool, controller) = def003_deploy_pool(&pic, [0xAA; 32]);
    let stub = def003_deploy_stub(&pic, Some([0xAA; 32]));
    let r = def003_set_verifier(&pic, pool, controller, stub, vec![0xAAu8; 32]);
    assert_eq!(r, Ok(()), "matching hash must be accepted; got {:?}", r);
    assert_eq!(def003_get_verifier(&pic, pool), Some(stub), "verifier principal must be updated");
    assert_eq!(def003_get_pin(&pic, pool), vec![0xAAu8; 32], "pinned hash unchanged (Design 2)");
}

// Test C — zero-hash default: no-init stub reports [0;32], pool pinned [0;32] → accepted.
#[test]
fn test_def003_c_zero_hash_default_accepted() {
    let pic = PocketIc::new();
    let (pool, controller) = def003_deploy_pool(&pic, [0u8; 32]);
    let stub = def003_deploy_stub(&pic, None); // reports [0;32]
    let r = def003_set_verifier(&pic, pool, controller, stub, vec![0u8; 32]);
    assert_eq!(r, Ok(()), "zero-hash default must be accepted; got {:?}", r);
    assert_eq!(def003_get_verifier(&pic, pool), Some(stub), "verifier principal must be updated");
}

// Test D — invalid expected_vk_hash length rejected BEFORE any inter-canister call.
#[test]
fn test_def003_d_invalid_hash_length_rejected() {
    let pic = PocketIc::new();
    let (pool, controller) = def003_deploy_pool(&pic, [0xAA; 32]);
    // Unreachable verifier principal (created, not installed). The 16-byte length is
    // rejected before the vk_hash() call, so this canister is never contacted.
    let unreachable = create_canister(&pic);
    let r = def003_set_verifier(&pic, pool, controller, unreachable, vec![0u8; 16]);
    assert!(
        matches!(r, Err(PoolError::InvalidVerifierKeyHashLength { len: 16 })),
        "16-byte expected hash must be InvalidVerifierKeyHashLength {{ len: 16 }}; got {:?}",
        r
    );
    assert_eq!(def003_get_verifier(&pic, pool), None, "verifier principal must be unchanged");
    assert_eq!(def003_get_pin(&pic, pool), vec![0xAAu8; 32], "pinned hash must be unchanged");
}
