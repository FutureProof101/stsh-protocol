// =============================================================================
// STSH — R-2 (C-30): per-spend fee-marker batching (PocketIC)
// BRIEF_R2_C30_FEE_MARKER_V3_2026-09-04. HOLD-LAUNCH H-2.
// =============================================================================
//
// THE DEFECT. Both terminal arms of `promote_pending_spend` fired one
// `notify_treasury_fee(PrivateTransferFee, …)` per private spend, and
// `receive_fee_split` writes a durable, source-labelled `FeeLogEntry` that
// `get_fee_log` publishes to anyone. Every private spend therefore carried a
// canonical, retroactively readable wall-clock timestamp on a public surface.
//
// THE FIX UNDER TEST. Spends ACCRUE into a pool-side stable cell (MemoryId 23);
// one boundary-armed one-shot timer publishes the window aggregate at absolute
// wall-clock multiples of the flush window `W` (MemoryId 24, governance
// parameter, default 1 h, bounds [300 s, 24 h]).
//
// WHAT THESE TESTS DO NOT CLAIM. The published row still reveals the window's
// aggregate fee revenue, which under the fixed launch fee is the exact COUNT of
// private spends in the window — already inferable from the ungated
// `merkle-tree::leaf_count()`. What is removed is per-spend timing.
//
// TWO NAMED SPEND PATHS are used throughout, because the two terminal arms are
// independent code sites and a test that reaches only one cannot bind both:
//   P-A  a fee-bearing private spend with NO public payout (finalizes inline)
//   P-B  a fee-bearing private spend whose public payout executes to Finalized
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): ./run_gate.sh
// =============================================================================

// The two R-2 suites share one harness (mirrors, deploy, spend drivers). Each
// suite uses the part of it that it needs, so the unused half is expected.
#![allow(dead_code)]

use candid::{CandidType, Nat, Principal};
use pocket_ic::{PocketIc, Time};
use serde::{Deserialize, Serialize};

// ── Wasm loading ─────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn pool_prod_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn treasury_wasm() -> Vec<u8> { load_wasm(env!("TREASURY_WASM"), "treasury") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

// ── The shipped numbers, transcribed. NEVER imported from the crate under test:
//    a check that reads the constant it checks cannot fail. ─────────────────────

const E8S: u128 = 100_000_000;
const TOTAL_SUPPLY: u128 = 1_000_000_000 * E8S;
const DENOMINATIONS: [u128; 5] =
    // A6.6 five-tier launch ladder — mirrors the pool's own DENOMINATIONS.
    [1_000 * E8S, 10_000 * E8S, 100_000 * E8S, 1_000_000 * E8S, 10_000_000 * E8S];
const DEFAULT_LEDGER_FEE: u128 = 10_000;
const COOLDOWN_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// The flat protocol private-spend fee used by these tests: 0.1 STSH.
const SPEND_FEE: u128 = E8S / 10;
/// 25 bps value fee, both directions.
const BPS: u16 = 25;
/// 0.1 STSH flat minimum, both directions.
const FLAT_MIN: u128 = E8S / 10;

/// The split used by these tests. The two LIVE shares are deliberately DISTINCT
/// (70/30, not 50/50): a split with duplicated shares cannot distinguish
/// "credited the right bucket" from "credited the right total", which is exactly
/// what AC-5 / SI-01 must catch.
///
/// Staking is 0 because `staking_rewards_enabled: true` is REFUSED by the pool
/// at this posture — `set_governance_fee_params_unchecked_for_test` returns
/// `StakingEnableBlockedRunwayUnwired`, the launch guard that keeps the staking
/// reserve unwired until the runway is. So the shipped launch split is exactly
/// two live buckets, and that is what these tests exercise.
const OPS_BPS: u128 = 7_000;
const INS_BPS: u128 = 3_000;
const STK_BPS: u128 = 0;

/// `ATTESTATION_BUCKET_NS` — the flush-window FLOOR, by reference in the pool.
/// Transcribed here so a test expectation never derives from the setter it tests.
const ATTESTATION_BUCKET_NS: u64 = 300_000_000_000;
const WINDOW_CEILING_NS: u64 = 86_400_000_000_000;
const WINDOW_DEFAULT_NS: u64 = 3_600_000_000_000;
const HALF_HOUR_NS: u64 = 1_800_000_000_000;

/// The split of `fee`, computed independently of the canister and of the
/// fee-policy crate — never re-derived from `GovernanceFeeParams` inside an
/// assertion (invariant 2: value, not conservation).
fn expected_split(fee: u128) -> (u128, u128, u128) {
    (fee * OPS_BPS / 10_000, fee * INS_BPS / 10_000, fee * STK_BPS / 10_000)
}

/// The exit (payout) fee model: `max(flat_minimum, bps)`.
fn expected_exit_fee(public_amount: u128) -> u128 {
    let by_bps = public_amount * (BPS as u128) / 10_000;
    if by_bps > FLAT_MIN { by_bps } else { FLAT_MIN }
}

// ── Token mirrors ────────────────────────────────────────────────────────────

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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveError {
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

// ── Treasury mirrors ─────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum FeeSource { ShieldFee, PrivateTransferFee, UnshieldFee, DexRevenue }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct FeeLogEntry {
    timestamp_ns: u64,
    source: FeeSource,
    total_amount: u128,
    operations: u128,
    insurance: u128,
    audit: u128,
    staking: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct SubaccountBalance { name: String, balance: u128 }

// ── Pool mirrors ─────────────────────────────────────────────────────────────

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
    verifier_canister: Option<Principal>,
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
    expected_deployment_config_hash: Option<[u8; 32]>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode { FixedStsh, XdrPegged }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceFeeParams {
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
    spend_fee_mode: Option<SpendFeeMode>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
}

/// NONZERO fee parameters with three DISTINCT split shares. Written out rather
/// than derived — a fixture that follows a constant cannot detect a change to it.
fn nonzero_params() -> GovernanceFeeParams {
    GovernanceFeeParams {
        protocol_shielding_fee_stsh: 0,
        protocol_unshielding_fee_stsh: 0,
        protocol_private_spend_fee_stsh: SPEND_FEE,
        minimum_withdrawal_gross: 0,
        minimum_recipient_amount: 0,
        minimum_private_credit: 0,
        fee_reference_price_stsh_per_icp_e8s: 0,
        fee_safety_margin_bps: 12_500,
        max_fee_change_bps_per_update: 1_000,
        fee_update_cooldown_ns: COOLDOWN_NS,
        operations_split_bps: OPS_BPS as u32,
        insurance_split_bps: INS_BPS as u32,
        staking_rewards_split_bps: STK_BPS as u32,
        staking_rewards_enabled: false,
        minimum_treasury_runway_months: 6,
        target_treasury_runway_months: 12,
        shield_fee_bps: Some(BPS),
        unshield_fee_bps: Some(BPS),
        shield_flat_minimum_fee_e8s: Some(FLAT_MIN),
        unshield_flat_minimum_fee_e8s: Some(FLAT_MIN),
        spend_fee_mode: Some(SpendFeeMode::FixedStsh),
        fee_model_version: Some(1),
        params_epoch: None,
    }
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TreasuryNotificationStats {
    in_flight: u64,
    returned_failures: u64,
    upgrade_dropped: u64,
}

// ── Harness ──────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

/// A canonical BN254 Fr element: tag in the low byte, zeros above.
fn fe(tag: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = tag;
    b
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 20_000_000_000_000u128);
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
    treasury: Principal,
    controller: Principal,
    user: Principal,
    recipient: Principal,
}

const VK_HASH: [u8; 32] = [0x7Au8; 32];

/// A wall-clock instant that is NOT a multiple of any window used here, so a
/// timer armed at `now + W` and a timer armed at the next absolute boundary land
/// at visibly different instants (AC-3, AC-16a).
///
/// 2026-01-01T00:17:00Z: 17 minutes past the hour, so it is 17 min past a 1 h
/// boundary and 17 min past a 30 min boundary.
const T_10_17: u64 = 1_767_225_600_000_000_000 + 17 * 60 * 1_000_000_000;

fn set_time_ns(pic: &PocketIc, ns: u64) {
    pic.set_time(Time::from_nanos_since_unix_epoch(ns));
    pic.tick();
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

/// The absolute boundary strictly after `now` for window `w` — the SAME
/// arithmetic the pool uses, restated here so a test never asks the pool where
/// its own boundary is.
fn next_boundary(now: u64, w: u64) -> u64 {
    ((now / w) + 1) * w
}

/// Move to `t` and let every timer that was due in between actually fire.
///
/// PocketIC does not run timers on `set_time` alone; each round executes what is
/// due. The flush chain re-arms itself, so several ticks are taken.
fn advance_to(pic: &PocketIc, t: u64) {
    set_time_ns(pic, t);
    for _ in 0..6 {
        pic.tick();
    }
}

/// Deploy the full stack, with a REAL treasury canister (the fee log under test
/// is the treasury's) and the stub verifier (so the spend STATE MACHINE runs,
/// not the ZK layer). Installed at `install_at_ns` wall-clock.
fn deploy_at(pic: &PocketIc, install_at_ns: u64) -> Stack {
    deploy_inner(pic, install_at_ns, true)
}

/// `treasury_accepts == false` installs the treasury bound to a DIFFERENT pool
/// principal, so `receive_fee_split` always returns Err. An Err is a COMPLETED
/// notification (ruling V2 §3(2)) — that is what AC-7 needs to observe.
fn deploy_inner(pic: &PocketIc, install_at_ns: u64, treasury_accepts: bool) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let recipient = p(0xBB);

    set_time_ns(pic, install_at_ns);

    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);
    let treasury = create_canister(pic);
    let verifier = create_canister(pic);

    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    pic.install_canister(
        verifier,
        stub_verifier_wasm(),
        candid::encode_one(Some(VK_HASH)).unwrap(),
        None,
    );
    install(pic, token, token_wasm(), &TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: user,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury,
        staking_canister: p(0x02),
    });
    pic.install_canister(
        treasury,
        treasury_wasm(),
        candid::encode_args((
            token,
            if treasury_accepts { pool } else { p(0xDE) },
            controller,
        ))
        .unwrap(),
        None,
    );
    install(pic, pool, pool_test_wasm(), &PoolInitArgs {
        token_canister: token,
        nullifier_canister: null,
        merkle_canister: merkle,
        treasury_canister: treasury,
        staking_canister: p(0x02),
        controller,
        initial_vk_hash: VK_HASH,
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: None,
    });
    pic.update_call(
        pool,
        controller,
        "set_verifier_canister",
        candid::encode_args((verifier, VK_HASH.to_vec())).unwrap(),
    )
    .expect("set_verifier_canister must succeed");

    // NONZERO params. At launch defaults every fee is zero, and a zero fee makes
    // `notify_treasury_fee` return early — so a batching test written at the
    // defaults would pass on a completely unbatched implementation.
    let set: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        pic.update_call(
            pool,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(nonzero_params()).unwrap(),
        ),
    );
    set.expect("nonzero fee params must install");

    Stack { pool, token, merkle, treasury, controller, user, recipient }
}

fn deploy(pic: &PocketIc) -> Stack {
    deploy_at(pic, T_10_17)
}

fn approve(pic: &PocketIc, s: &Stack, amount: u128) {
    let r: Result<Nat, ApproveError> = decode(
        "icrc2_approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
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
    r.expect("approve must succeed");
}

fn merkle_root(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    let root: Vec<u8> = decode(
        "get_root",
        pic.query_call(s.merkle, s.user, "get_root", candid::encode_args(()).unwrap()),
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&root);
    out
}

/// Deposit one note of `denomination`. Returns the merkle root afterwards.
fn deposit(pic: &PocketIc, s: &Stack, denomination: u128, commitment: [u8; 32]) -> [u8; 32] {
    approve(pic, s, denomination + expected_exit_fee(denomination) + DEFAULT_LEDGER_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![],
                public_amount: denomination,
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    );
    dep.unwrap_or_else(|e| panic!("shield_deposit({denomination}) failed: {e:?}"));
    merkle_root(pic, s)
}

#[allow(clippy::too_many_arguments)]
fn spend(
    pic: &PocketIc,
    s: &Stack,
    spend_id: u64,
    root: [u8; 32],
    payout: Option<u128>,
    fee: u128,
    nullifier: u8,
    commitments: (u8, u8),
) -> Result<(), PoolError> {
    decode(
        "private_spend",
        pic.update_call(
            s.pool,
            s.user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                nullifiers: vec![fe(nullifier)],
                output_commitments: vec![fe(commitments.0), fe(commitments.1)],
                encrypted_outputs: vec![vec![], vec![]],
                fee,
                public_payout: payout.map(|public_amount| PrivateSpendPublicPayout {
                    destination: s.recipient,
                    destination_subaccount: None,
                    public_amount,
                }),
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    )
}

/// P-A — a fee-bearing private spend with NO public payout. Finalizes inline
/// through the `public_payout.is_none()` terminal arm.
fn spend_pa(pic: &PocketIc, s: &Stack, id: u64, root: [u8; 32], n: u8, c: (u8, u8)) {
    let r = spend(pic, s, id, root, None, SPEND_FEE, n, c);
    assert_eq!(r, Ok(()), "P-A spend {id} must finalize; got {r:?}");
}

/// P-B — a fee-bearing private spend whose public payout EXECUTES to Finalized,
/// through the second (DEF-072) terminal arm.
fn spend_pb(pic: &PocketIc, s: &Stack, id: u64, root: [u8; 32], n: u8, c: (u8, u8)) -> u128 {
    let public_amount = 100 * E8S;
    let fee = expected_exit_fee(public_amount);
    let r = spend(pic, s, id, root, Some(public_amount), fee, n, c);
    assert_eq!(r, Ok(()), "P-B spend {id} must finalize; got {r:?}");
    fee
}

// ── Public reads (ANONYMOUS — the observer this lane models has no identity) ──

fn anon() -> Principal { Principal::anonymous() }

fn fee_log(pic: &PocketIc, s: &Stack) -> Vec<FeeLogEntry> {
    decode(
        "get_fee_log",
        pic.query_call(s.treasury, anon(), "get_fee_log", candid::encode_args((0u64, 200u64)).unwrap()),
    )
}

fn private_rows(pic: &PocketIc, s: &Stack) -> Vec<FeeLogEntry> {
    fee_log(pic, s).into_iter().filter(|e| e.source == FeeSource::PrivateTransferFee).collect()
}

fn subaccount_balances(pic: &PocketIc, s: &Stack) -> Vec<SubaccountBalance> {
    decode(
        "get_subaccount_balances",
        pic.query_call(s.treasury, anon(), "get_subaccount_balances", candid::encode_args(()).unwrap()),
    )
}

fn subaccount_balance(pic: &PocketIc, s: &Stack, name: &str) -> Option<u128> {
    decode(
        "get_subaccount_balance",
        pic.query_call(
            s.treasury,
            anon(),
            "get_subaccount_balance",
            candid::encode_one(name.to_string()).unwrap(),
        ),
    )
}

fn notification_stats(pic: &PocketIc, s: &Stack) -> TreasuryNotificationStats {
    decode(
        "get_treasury_notification_stats",
        pic.query_call(s.pool, anon(), "get_treasury_notification_stats", candid::encode_args(()).unwrap()),
    )
}

fn notification_failures(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "get_treasury_notification_failures",
        pic.query_call(s.pool, anon(), "get_treasury_notification_failures", candid::encode_args(()).unwrap()),
    )
}

fn window_ns(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "get_fee_flush_window_ns",
        pic.query_call(s.pool, anon(), "get_fee_flush_window_ns", candid::encode_args(()).unwrap()),
    )
}

fn set_window(pic: &PocketIc, s: &Stack, caller: Principal, ns: u64) -> Result<(), String> {
    decode(
        "set_fee_flush_window_ns",
        pic.update_call(s.pool, caller, "set_fee_flush_window_ns", candid::encode_one(ns).unwrap()),
    )
}

/// THE SEVEN publicly readable surfaces AC-4 snapshots, as one comparable blob.
///
/// All seven are read ANONYMOUSLY. If any one of them moves inside a window in
/// response to a private spend, the spend is individually observable and the
/// batching has not achieved its outcome.
#[derive(Debug, PartialEq, Eq)]
struct PublicSurfaces {
    balances: Vec<SubaccountBalance>,
    operations: Option<u128>,
    insurance: Option<u128>,
    staking_rewards: Option<u128>,
    fee_log: Vec<FeeLogEntry>,
    stats: TreasuryNotificationStats,
    failures: u64,
}

fn public_surfaces(pic: &PocketIc, s: &Stack) -> PublicSurfaces {
    PublicSurfaces {
        balances: subaccount_balances(pic, s),
        operations: subaccount_balance(pic, s, "operations"),
        insurance: subaccount_balance(pic, s, "insurance"),
        staking_rewards: subaccount_balance(pic, s, "staking_rewards"),
        fee_log: fee_log(pic, s),
        stats: notification_stats(pic, s),
        failures: notification_failures(pic, s),
    }
}

// =============================================================================
// AC-1 — a single spend is not individually recoverable from the log.
// Two tests, ONE PER TERMINAL SITE. A test that reaches only one arm cannot
// satisfy this criterion: the two sites are independent code, and reverting one
// leaves the other's test green (M1a / M1b show exactly that).
// =============================================================================

/// The shared body of AC-1A/AC-1B: `n` spends at IRREGULAR intra-window offsets,
/// then the boundary. Returns the single published row.
fn one_window_of_spends(
    pic: &PocketIc,
    s: &Stack,
    offsets_ns: &[u64],
    payout: bool,
    base_id: u64,
    base_tag: u8,
) -> FeeLogEntry {
    let w = window_ns(pic, s);
    let start = now_ns(pic);
    let boundary = next_boundary(start, w);

    for (k, off) in offsets_ns.iter().enumerate() {
        let at = start + off;
        assert!(at < boundary, "test offsets must stay inside one window");
        set_time_ns(pic, at);
        let root = deposit(pic, s, DENOMINATIONS[3], fe(base_tag + k as u8));
        let id = base_id + k as u64;
        let n = base_tag + 0x20 + k as u8;
        let c = (base_tag + 0x40 + 2 * k as u8, base_tag + 0x41 + 2 * k as u8);
        if payout {
            spend_pb(pic, s, id, root, n, c);
        } else {
            spend_pa(pic, s, id, root, n, c);
        }
    }

    // Inside the window: NOTHING published yet.
    assert!(
        private_rows(pic, s).is_empty(),
        "no PrivateTransferFee row may exist before the boundary"
    );

    advance_to(pic, boundary + 1);
    let rows = private_rows(pic, s);
    assert_eq!(
        rows.len(),
        1,
        "exactly ONE PrivateTransferFee row per window; got {}: {rows:#?}",
        rows.len()
    );
    let row = rows.into_iter().next().unwrap();
    assert_eq!(
        row.timestamp_ns, boundary,
        "the row's timestamp must be the ARMED BOUNDARY exactly, not the callback's time()"
    );
    row
}

#[test]
fn ac1a_pa_spends_are_not_individually_recoverable_from_the_fee_log() {
    // Run 1: three P-A spends at irregular offsets.
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let row1 = one_window_of_spends(&pic, &s, &[1_000_000_000, 137_000_000_000, 901_000_000_000], false, 100, 0x01);

    // Run 2: the same COUNT at DIFFERENT offsets, on a fresh stack installed at
    // the same wall-clock instant. If any per-spend timing survived into the row,
    // the two rows would differ.
    let pic2 = PocketIc::new();
    let s2 = deploy(&pic2);
    let row2 = one_window_of_spends(&pic2, &s2, &[5_000_000_000, 611_000_000_000, 1_499_000_000_000], false, 100, 0x01);

    assert_eq!(
        row1, row2,
        "two windows with the same spend count must publish BYTE-IDENTICAL rows; \
         a difference is per-spend timing surviving into the public log"
    );
    let (ops, ins, stk) = expected_split(SPEND_FEE);
    assert_eq!(row1.operations, 3 * ops);
    assert_eq!(row1.insurance, 3 * ins);
    assert_eq!(row1.staking, 3 * stk);
}

#[test]
fn ac1b_pb_spends_are_not_individually_recoverable_from_the_fee_log() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let row1 = one_window_of_spends(&pic, &s, &[1_000_000_000, 137_000_000_000, 901_000_000_000], true, 200, 0x51);

    let pic2 = PocketIc::new();
    let s2 = deploy(&pic2);
    let row2 = one_window_of_spends(&pic2, &s2, &[5_000_000_000, 611_000_000_000, 1_499_000_000_000], true, 200, 0x51);

    assert_eq!(
        row1, row2,
        "two windows with the same P-B spend count must publish BYTE-IDENTICAL rows"
    );
    let (ops, ins, stk) = expected_split(expected_exit_fee(100 * E8S));
    assert_eq!(row1.operations, 3 * ops);
    assert_eq!(row1.insurance, 3 * ins);
    assert_eq!(row1.staking, 3 * stk);
}

// =============================================================================
// AC-2 — the log does NOT go quiet.
//
// If empty windows were skipped, the OCCURRENCE of a flush would itself be the
// signal, and the batching would have moved the leak rather than removed it.
// The test spans TWO consecutive empty boundaries, which also catches a callback
// that flushes but forgets to re-arm the one-shot timer.
// =============================================================================

#[test]
fn ac2_two_consecutive_empty_windows_each_publish_one_zero_row() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let b1 = next_boundary(now_ns(&pic), w);
    let b2 = b1 + w;

    advance_to(&pic, b1 + 1);
    let after_first = private_rows(&pic, &s);
    assert_eq!(after_first.len(), 1, "the FIRST empty window must publish exactly one row");
    assert_eq!(after_first[0].timestamp_ns, b1);
    assert_eq!(
        (after_first[0].operations, after_first[0].insurance, after_first[0].staking, after_first[0].total_amount),
        (0, 0, 0, 0),
        "an empty window publishes a row with all amounts zero"
    );

    advance_to(&pic, b2 + 1);
    let after_second = private_rows(&pic, &s);
    assert_eq!(
        after_second.len(),
        2,
        "the SECOND empty window must publish its own row — a one-shot timer that \
         does not re-arm goes quiet here, and silence is the signal"
    );
    assert_eq!(after_second[1].timestamp_ns, b2);
}

// =============================================================================
// AC-3 — cadence is independent of install and upgrade time.
// =============================================================================

#[test]
fn ac3_boundaries_are_absolute_and_independent_of_install_time() {
    // Two pools installed at instants that are NOT multiples of W, and NOT the
    // same offset into the hour. If the timer were armed at `now + W` the two
    // would publish at different absolute instants.
    let a_at = T_10_17;                              // :17 past the hour
    let b_at = T_10_17 + 23 * 60 * 1_000_000_000;    // :40 past the hour

    let pic_a = PocketIc::new();
    let s_a = deploy_at(&pic_a, a_at);
    let pic_b = PocketIc::new();
    let s_b = deploy_at(&pic_b, b_at);

    let w = WINDOW_DEFAULT_NS;
    assert_eq!(window_ns(&pic_a, &s_a), w);
    let boundary = next_boundary(b_at, w);
    assert_eq!(boundary, next_boundary(a_at, w), "both installs share the next absolute boundary");

    advance_to(&pic_a, boundary + 1);
    advance_to(&pic_b, boundary + 1);

    let ra = private_rows(&pic_a, &s_a);
    let rb = private_rows(&pic_b, &s_b);
    assert_eq!(ra.len(), 1, "pool A publishes one row");
    assert_eq!(rb.len(), 1, "pool B publishes one row");
    assert_eq!(
        ra[0].timestamp_ns, rb[0].timestamp_ns,
        "two pools installed at different offsets must publish at the SAME absolute instant"
    );
    assert_eq!(ra[0].timestamp_ns, boundary);
}

#[test]
fn ac3_an_upgrade_mid_window_does_not_move_the_next_boundary() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    // Upgrade at an arbitrary mid-window instant, between two DIFFERENT modules.
    set_time_ns(&pic, boundary - 11 * 60 * 1_000_000_000);
    pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("mid-window upgrade must succeed");

    advance_to(&pic, boundary + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "one row at the boundary after a mid-window upgrade");
    assert_eq!(
        rows[0].timestamp_ns, boundary,
        "an upgrade must not re-phase the schedule — a re-phased boundary reveals the upgrade"
    );
}

// =============================================================================
// AC-4 — no publicly readable surface moves within the window; at the boundary
// exactly the fee surfaces move. Two tests, ONE PER SITE.
//
// This is the criterion that discharges the ruling to leave the treasury balance
// queries PUBLIC (brief §4.2). If it cannot pass, gating them returns.
// =============================================================================

fn ac4_body(pic: &PocketIc, s: &Stack, payout: bool, base_id: u64, base_tag: u8) {
    let w = window_ns(pic, s);
    let boundary = next_boundary(now_ns(pic), w);

    // The deposit fires its OWN immediate ShieldFee notification (AC-11a), which
    // legitimately moves several of these surfaces. Snapshot AFTER it has landed,
    // so what the comparison below measures is the PRIVATE SPEND and nothing else.
    let root = deposit(pic, s, DENOMINATIONS[3], fe(base_tag));
    for _ in 0..4 { pic.tick(); }
    let before = public_surfaces(pic, s);

    if payout {
        spend_pb(pic, s, base_id, root, base_tag + 0x20, (base_tag + 0x40, base_tag + 0x41));
    } else {
        spend_pa(pic, s, base_id, root, base_tag + 0x20, (base_tag + 0x40, base_tag + 0x41));
    }

    let mid = public_surfaces(pic, s);
    assert_eq!(
        before, mid,
        "ALL SEVEN public surfaces must be byte-identical before the boundary. \
         Any difference is the private spend showing through."
    );

    advance_to(pic, boundary + 1);
    let after = public_surfaces(pic, s);

    assert_ne!(after.balances, before.balances, "the plural balance read must move at the boundary");
    assert_ne!(after.operations, before.operations, "operations must move at the boundary");
    assert_ne!(after.insurance, before.insurance, "insurance must move at the boundary");
    assert_eq!(
        after.staking_rewards, before.staking_rewards,
        "staking_rewards must NOT move — the launch split gives it zero bps and the \
         pool refuses to enable it (StakingEnableBlockedRunwayUnwired). Asserted \
         rather than omitted: a bucket that silently started moving here would be a \
         change to the split, not to this lane."
    );
    assert_ne!(after.fee_log, before.fee_log, "the fee log must move at the boundary");
    assert_eq!(
        after.failures, before.failures,
        "an accepted flush must not raise the failure counter"
    );
    assert_eq!(after.stats.in_flight, 0, "the flush must have resolved");
    assert_eq!(after.stats.upgrade_dropped, before.stats.upgrade_dropped, "nothing was dropped");
}

#[test]
fn ac4a_pa_no_public_surface_moves_inside_the_window() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    ac4_body(&pic, &s, false, 300, 0x02);
}

#[test]
fn ac4b_pb_no_public_surface_moves_inside_the_window() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    ac4_body(&pic, &s, true, 400, 0x62);
}

// =============================================================================
// AC-5 — value-level split coverage (SI-01 guard).
//
// A flush that accumulates (a+a', b+b', c+c') passes CONSERVATION while getting
// every bucket wrong. The expectations here are literals computed in the test
// from transcribed bps, never re-derived from GovernanceFeeParams.
// =============================================================================

#[test]
fn ac5_the_flushed_row_carries_the_correct_per_bucket_values_not_just_the_right_total() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    const N: u128 = 4;
    for k in 0..N as u8 {
        let root = deposit(&pic, &s, DENOMINATIONS[3], fe(0x03 + k));
        spend_pa(&pic, &s, 500 + k as u64, root, 0x83 + k, (0xA0 + 2 * k, 0xA1 + 2 * k));
    }

    for _ in 0..4 { pic.tick(); }
    let bal_before = (
        subaccount_balance(&pic, &s, "operations").unwrap(),
        subaccount_balance(&pic, &s, "insurance").unwrap(),
        subaccount_balance(&pic, &s, "staking_rewards").unwrap(),
    );

    advance_to(&pic, boundary + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];

    // Independent literals. 0.1 STSH at 7000/3000 bps is 7_000_000 / 3_000_000 —
    // two DISTINCT values, so a transposition or a misdirected share cannot hide
    // behind an equal one. Staking is structurally zero at this posture (see
    // OPS_BPS/INS_BPS/STK_BPS) and is asserted as zero, not omitted.
    let per_spend_ops: u128 = 7_000_000;
    let per_spend_ins: u128 = 3_000_000;
    let per_spend_stk: u128 = 0;
    assert_eq!(expected_split(SPEND_FEE), (per_spend_ops, per_spend_ins, per_spend_stk));

    assert_eq!(row.operations, N * per_spend_ops, "operations share");
    assert_eq!(row.insurance, N * per_spend_ins, "insurance share");
    assert_eq!(row.staking, N * per_spend_stk, "staking share");

    // The conservation-only assertion, stated explicitly so the packet can show
    // it survives M5 while the three above do not.
    assert_eq!(
        row.total_amount,
        row.operations + row.insurance + row.staking,
        "conservation holds — and would STILL hold if the insurance share had \
         been credited to operations, which is why the three assertions above exist"
    );
    assert_eq!(row.total_amount, N * SPEND_FEE);

    // The treasury buckets moved by the same per-bucket amounts. Measured as a
    // DELTA across the boundary: the four deposits above each fired their own
    // immediate ShieldFee credit into these same buckets, so an absolute
    // comparison would be measuring the deposits as well as the flush.
    assert_eq!(
        subaccount_balance(&pic, &s, "operations").unwrap() - bal_before.0,
        N * per_spend_ops
    );
    assert_eq!(
        subaccount_balance(&pic, &s, "insurance").unwrap() - bal_before.1,
        N * per_spend_ins
    );
    assert_eq!(
        subaccount_balance(&pic, &s, "staking_rewards").unwrap() - bal_before.2,
        N * per_spend_stk
    );
}

// =============================================================================
// AC-11 — over-batching guard: ShieldFee and UnshieldFee stay IMMEDIATE.
// Each is accompanied by a public ICRC transfer whose timing is already public,
// so batching them would buy nothing and would strand revenue.
// =============================================================================

#[test]
fn ac11a_shield_fee_is_published_immediately_not_at_the_boundary() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    deposit(&pic, &s, DENOMINATIONS[3], fe(0x04));
    // Let the fire-and-forget notification land.
    for _ in 0..4 { pic.tick(); }

    assert!(now_ns(&pic) < boundary, "still inside the window");
    let shield_rows: Vec<_> = fee_log(&pic, &s)
        .into_iter()
        .filter(|e| e.source == FeeSource::ShieldFee)
        .collect();
    assert_eq!(
        shield_rows.len(),
        1,
        "a ShieldFee row must appear IMMEDIATELY, before the boundary; routing it \
         through the accrual would delay a fee whose ICRC transfer is already public"
    );
    assert!(
        private_rows(&pic, &s).is_empty(),
        "and no PrivateTransferFee row before the boundary"
    );
}

// ── AC-11b — the UNSHIELD arm stays immediate ────────────────────────────────
//
// Public `withdraw` is fail-closed at base (`reject_unbound_withdrawal_proof`)
// and stays so, which is exactly why the `UnshieldFee` arm is otherwise
// unreachable from outside. A `testing`-only driver calls the PRODUCTION
// `finalize_confirmed_withdrawal_payout`, whose UnshieldFee arm is the site
// under test — the driver adds no fee logic of its own.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum WithdrawalStatus {
    Requested,
    ProofVerified,
    NullifierReserved,
    SolvencyBlocked { required: u128, available: u128 },
    EscrowCoverageChecked,
    RegistryInsertPending,
    RegistryInsertUnknown,
    RegistryInserted,
    LedgerTransferPending,
    LedgerTransferUnknown,
    LedgerTransferConfirmed,
    AccountingApplied,
    PayoutObligationPending,
    Finalized,
    FailedTerminalUserError { reason: String },
    FeeReimbursementPending { ledger_fee: u128 },
    FailedRetryable,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingWithdrawal {
    withdrawal_id: u64,
    nullifier: [u8; 32],
    destination: Principal,
    gross_withdraw_amount: u128,
    recipient_net_amount: u128,
    ledger_fee: u128,
    protocol_unshielding_fee: u128,
    status: WithdrawalStatus,
    created_at_ns: u64,
    finalized_at_ns: Option<u64>,
    ledger_memo: Option<Vec<u8>>,
    submitter: Option<Principal>,
    ledger_created_at_time_ns: Option<u64>,
    destination_subaccount: Option<[u8; 32]>,
}

#[test]
fn ac11b_unshield_fee_is_published_immediately_not_at_the_boundary() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    // Fund liability/escrow so the accounting debits are real.
    deposit(&pic, &s, DENOMINATIONS[3], fe(0x05));
    for _ in 0..4 { pic.tick(); }

    let unshield_fee = 25_000_000u128;
    let record = PendingWithdrawal {
        withdrawal_id: 9_001,
        nullifier: fe(0xE1),
        destination: s.recipient,
        gross_withdraw_amount: 10 * E8S,
        recipient_net_amount: 10 * E8S - unshield_fee - DEFAULT_LEDGER_FEE,
        ledger_fee: DEFAULT_LEDGER_FEE,
        protocol_unshielding_fee: unshield_fee,
        status: WithdrawalStatus::LedgerTransferConfirmed,
        created_at_ns: now_ns(&pic),
        finalized_at_ns: None,
        ledger_memo: None,
        submitter: Some(s.user),
        ledger_created_at_time_ns: Some(now_ns(&pic)),
        destination_subaccount: None,
    };
    let r: Result<Nat, PoolError> = decode(
        "finalize_confirmed_withdrawal_payout_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "finalize_confirmed_withdrawal_payout_for_test",
            candid::encode_one(record).unwrap(),
        ),
    );
    r.expect("the production finalize path must succeed");
    for _ in 0..4 { pic.tick(); }

    assert!(now_ns(&pic) < boundary, "still inside the window");
    let unshield_rows: Vec<_> = fee_log(&pic, &s)
        .into_iter()
        .filter(|e| e.source == FeeSource::UnshieldFee)
        .collect();
    assert_eq!(
        unshield_rows.len(),
        1,
        "an UnshieldFee row must appear IMMEDIATELY, before the boundary"
    );
    let (ops, ins, stk) = expected_split(unshield_fee);
    assert_eq!(
        (unshield_rows[0].operations, unshield_rows[0].insurance, unshield_rows[0].staking),
        (ops, ins, stk)
    );
    assert!(
        private_rows(&pic, &s).is_empty(),
        "and no PrivateTransferFee row before the boundary"
    );
}

// =============================================================================
// AC-12 / AC-13 / AC-14 — the window is a LIVE, BOUNDED, AUTHORISED parameter.
// =============================================================================

#[test]
fn ac12_the_window_is_read_live_and_the_next_row_lands_on_the_new_boundary() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    assert_eq!(window_ns(&pic, &s), WINDOW_DEFAULT_NS, "a fresh install reads the 1 h default");

    let t = now_ns(&pic);
    set_window(&pic, &s, s.controller, HALF_HOUR_NS).expect("30 min is inside the bounds");
    assert_eq!(window_ns(&pic, &s), HALF_HOUR_NS);

    let new_boundary = next_boundary(t, HALF_HOUR_NS);
    let old_boundary = next_boundary(t, WINDOW_DEFAULT_NS);
    assert_ne!(new_boundary, old_boundary, "the fixture must distinguish the two windows");

    advance_to(&pic, new_boundary + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "one row at the NEW 30-min boundary");
    assert_eq!(
        rows[0].timestamp_ns, new_boundary,
        "arming must read the window from the CELL, not from a constant"
    );
}

#[test]
fn ac13_the_setter_enforces_the_floor_and_the_ceiling() {
    let pic = PocketIc::new();
    let s = deploy(&pic);

    // Every expectation derives from the transcribed ATTESTATION_BUCKET_NS, not
    // from the setter's own error text.
    assert!(
        set_window(&pic, &s, s.controller, ATTESTATION_BUCKET_NS - 1).is_err(),
        "one ns below the floor must be refused"
    );
    assert!(
        set_window(&pic, &s, s.controller, 0).is_err(),
        "zero must be refused"
    );
    assert!(
        set_window(&pic, &s, s.controller, ATTESTATION_BUCKET_NS).is_ok(),
        "the floor itself is INCLUSIVE"
    );
    assert_eq!(window_ns(&pic, &s), ATTESTATION_BUCKET_NS);
    assert!(
        set_window(&pic, &s, s.controller, WINDOW_CEILING_NS).is_ok(),
        "the ceiling itself is INCLUSIVE"
    );
    assert_eq!(window_ns(&pic, &s), WINDOW_CEILING_NS);
    assert!(
        set_window(&pic, &s, s.controller, WINDOW_CEILING_NS + 1).is_err(),
        "one ns above the ceiling must be refused"
    );
    assert_eq!(
        window_ns(&pic, &s),
        WINDOW_CEILING_NS,
        "a refused set must not move the stored value"
    );
}

#[test]
fn ac14_only_the_operator_controller_may_set_the_window_the_getter_is_open() {
    let pic = PocketIc::new();
    let s = deploy(&pic);

    for (caller, label) in [(anon(), "anonymous"), (s.user, "a non-controller user")] {
        let raw = pic.update_call(
            s.pool,
            caller,
            "set_fee_flush_window_ns",
            candid::encode_one(HALF_HOUR_NS).unwrap(),
        );
        assert!(
            raw.is_err(),
            "{label} must be rejected by set_fee_flush_window_ns"
        );
    }
    assert_eq!(
        window_ns(&pic, &s),
        WINDOW_DEFAULT_NS,
        "an unauthorised call must not move the window"
    );
    // The getter is deliberately OPEN — the cadence is published, not secret.
    assert_eq!(window_ns(&pic, &s), WINDOW_DEFAULT_NS);
}

// =============================================================================
// AC-16 — changing W is deterministic and leaves EXACTLY ONE live timer.
// =============================================================================

#[test]
fn ac16a_changing_the_window_rearms_to_the_next_boundary_of_the_new_window() {
    let pic = PocketIc::new();
    let s = deploy(&pic); // installed at :17 past the hour
    let t = now_ns(&pic);
    let hour = (t / WINDOW_DEFAULT_NS) * WINDOW_DEFAULT_NS;
    // Installed at :17 past the hour, plus the handful of nanoseconds PocketIC
    // spends executing the install rounds. What the fixture needs is only that
    // `now` sits strictly inside the FIRST half hour, so 10:30 is genuinely
    // earlier than now+30min — asserting the exact nanosecond would make this a
    // test of PocketIC's round timing.
    let offset = t - hour;
    assert!(
        offset > 0 && offset < HALF_HOUR_NS,
        "fixture: install must land strictly inside the first half hour; got {offset} ns"
    );

    set_window(&pic, &s, s.controller, HALF_HOUR_NS).expect("30 min accepted");

    let at_10_30 = hour + HALF_HOUR_NS;
    let at_10_47 = t + HALF_HOUR_NS;   // what `now + W` would produce
    let at_11_00 = hour + WINDOW_DEFAULT_NS;
    assert!(at_10_30 < at_10_47 && at_10_47 < at_11_00);

    advance_to(&pic, at_10_30 + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "the first row after the change lands at 10:30");
    assert_eq!(
        rows[0].timestamp_ns, at_10_30,
        "re-arm must target the next ABSOLUTE boundary of the new window \
         (10:30), not now+W (10:47) and not the old chain's 11:00"
    );
}

#[test]
fn ac16b_the_old_timer_is_cleared_so_a_shared_boundary_publishes_exactly_one_row() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let t = now_ns(&pic);
    let hour = (t / WINDOW_DEFAULT_NS) * WINDOW_DEFAULT_NS;

    // 1 h → 30 min at :17. The OLD one-shot was armed for 11:00, and 11:00 is
    // ALSO a 30-min boundary — so the callback guard cannot save this case.
    // Only `clear_timer` can.
    set_window(&pic, &s, s.controller, HALF_HOUR_NS).expect("30 min accepted");

    let b_10_30 = hour + HALF_HOUR_NS;
    let b_11_00 = hour + WINDOW_DEFAULT_NS;
    let b_11_30 = b_11_00 + HALF_HOUR_NS;

    advance_to(&pic, b_10_30 + 1);
    let after_1030 = private_rows(&pic, &s);
    assert_eq!(after_1030.len(), 1, "exactly one row at 10:30");

    advance_to(&pic, b_11_00 + 1);
    let at_1100: Vec<_> = private_rows(&pic, &s).into_iter().filter(|r| r.timestamp_ns == b_11_00).collect();
    assert_eq!(
        at_1100.len(),
        1,
        "exactly ONE row at the SHARED 11:00 boundary. Two rows means the old \
         1 h one-shot was never cleared and fired alongside the new chain."
    );

    advance_to(&pic, b_11_30 + 1);
    let at_1130: Vec<_> = private_rows(&pic, &s).into_iter().filter(|r| r.timestamp_ns == b_11_30).collect();
    assert_eq!(
        at_1130.len(),
        1,
        "exactly ONE row at 11:30 — a surviving stale timer re-arms itself and \
         doubles the cadence from the shared boundary onwards"
    );
    assert_eq!(private_rows(&pic, &s).len(), 3, "10:30, 11:00, 11:30 — three rows total");
}

#[test]
fn ac16c_the_callback_guard_refuses_a_boundary_that_is_not_a_boundary_of_the_live_window() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let t = now_ns(&pic);
    let hour = (t / WINDOW_DEFAULT_NS) * WINDOW_DEFAULT_NS;
    assert_eq!(window_ns(&pic, &s), WINDOW_DEFAULT_NS);

    // 10:30 is a 30-min boundary but NOT a 1 h boundary. On the real timer path
    // `clear_timer` means such a callback never exists — which is exactly why the
    // guard needs a driver to be falsifiable at all.
    let off_boundary = hour + HALF_HOUR_NS;
    assert_ne!(off_boundary % WINDOW_DEFAULT_NS, 0);
    let _: () = decode(
        "fire_fee_flush_timer_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "fire_fee_flush_timer_for_test",
            candid::encode_one(off_boundary).unwrap(),
        ),
    );
    for _ in 0..4 { pic.tick(); }
    assert!(
        private_rows(&pic, &s).is_empty(),
        "an off-boundary callback must write NO row"
    );

    // The next REAL boundary still flushes — the guard re-arms rather than dying.
    let b_11_00 = hour + WINDOW_DEFAULT_NS;
    advance_to(&pic, b_11_00 + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "the real boundary still publishes");
    assert_eq!(rows[0].timestamp_ns, b_11_00);
}

#[test]
fn ac16c_widening_the_window_skips_the_old_narrow_boundaries() {
    // The reverse direction on the TIMER path: 30 min → 1 h at :17 must produce
    // rows at 11:00 and 12:00 and NOTHING at 10:30 or 11:30.
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let t = now_ns(&pic);
    let hour = (t / WINDOW_DEFAULT_NS) * WINDOW_DEFAULT_NS;

    set_window(&pic, &s, s.controller, HALF_HOUR_NS).expect("30 min accepted");
    set_window(&pic, &s, s.controller, WINDOW_DEFAULT_NS).expect("back to 1 h");

    let b_10_30 = hour + HALF_HOUR_NS;
    let b_11_00 = hour + WINDOW_DEFAULT_NS;
    let b_11_30 = b_11_00 + HALF_HOUR_NS;
    let b_12_00 = hour + 2 * WINDOW_DEFAULT_NS;

    advance_to(&pic, b_10_30 + 1);
    assert!(private_rows(&pic, &s).is_empty(), "no row at 10:30 once the window is 1 h");
    advance_to(&pic, b_11_00 + 1);
    assert_eq!(private_rows(&pic, &s).len(), 1, "one row at 11:00");
    advance_to(&pic, b_11_30 + 1);
    assert_eq!(private_rows(&pic, &s).len(), 1, "still one row — 11:30 is not a 1 h boundary");
    advance_to(&pic, b_12_00 + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 2, "12:00 publishes the second row");
    assert_eq!(
        rows.iter().map(|r| r.timestamp_ns).collect::<Vec<_>>(),
        vec![b_11_00, b_12_00]
    );
}

// =============================================================================
// AC-7 (behavioural half) — spawn-then-count is preserved on the FLUSH path.
//
// `note_notification_resolved` is `saturating_sub` BY RULING, so a missing
// increment leaves NO trace in the gauge: the decrement floors at zero and the
// pairing still looks intact. The `testing`-only high-water mark is the missing
// witness — it only ever rises.
// =============================================================================

fn hwm(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "get_treasury_notifications_in_flight_hwm_for_test",
        pic.query_call(
            s.pool,
            s.controller,
            "get_treasury_notifications_in_flight_hwm_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

#[test]
fn ac7_the_flush_spawns_exactly_one_counted_notification_and_resolves_it() {
    // A treasury that REJECTS: it is bound to a different pool principal, so
    // `receive_fee_split` returns Err. An Err is a COMPLETED notification
    // (ruling V2 §3(2)), so `in_flight` must still return to zero and the
    // failure counter must rise by exactly one — which is what distinguishes a
    // missing `note_notification_resolved` from a missing spawn.
    let pic = PocketIc::new();
    let s = deploy_inner(&pic, T_10_17, false);

    let hwm_before = hwm(&pic, &s);
    let failures_before = notification_failures(&pic, &s);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    // No shield/unshield notification happens in this interval, so the delta
    // below belongs to the flush and to nothing else.
    advance_to(&pic, boundary + 1);

    assert_eq!(
        hwm(&pic, &s) - hwm_before,
        1,
        "the flush must raise the in-flight high-water mark by exactly one — a \
         zero delta means the spawn was not counted"
    );
    assert_eq!(
        notification_stats(&pic, &s).in_flight,
        0,
        "the resolved notification must have been decremented"
    );
    assert_eq!(
        notification_failures(&pic, &s) - failures_before,
        1,
        "a rejecting treasury is an Err, which is a COMPLETED notification"
    );
}

// =============================================================================
// AC-8 — the accrual has NO public read path.
// REWRITTEN for SSA_LANDED_DIFF_R-2_V1_2026-09-05 RED-1
// (CTO_TRIAGE_SSA_LANDED_DIFF_ROUND1_2026-09-05 §2).
// =============================================================================
//
// WHAT THE SSA SHOWED. The previous version of this test forbade THREE hard-coded
// endpoint names and queried those same three. The SSA added a production
// `#[query] fn window_status()` returning `read_fee_accrual()[0].to_le_bytes()`,
// declared it in the DID, rebuilt, and read 7,000,000 operations accrual as an
// anonymous caller mid-window. This test did not move. A criterion that says
// "no endpoint exposes the accrual" cannot be discharged by a list of three
// names nobody is obliged to extend.
//
// WHAT THIS VERSION DOES. It ENUMERATES the pool's published interface — every
// entry in the `service` block of `shielded_pool.did`, parsed, not listed — and
// for every NULLARY QUERY it compares the raw Candid response bytes an ANONYMOUS
// caller gets immediately BEFORE and immediately AFTER a fee-bearing private
// spend, inside one window. This is AC-4's seven-surface discipline extended to
// the whole interface. Any endpoint whose answer moves is the private spend
// showing through, and the SSA's `window_status` — a nullary query — is probed
// automatically, with no list to update.
//
// THE ENDPOINTS THIS LEG CANNOT DRIVE, AND WHAT COVERS THEM INSTEAD.
//   * UPDATES. An update cannot be probed by calling it: the call itself changes
//     state, so a before/after comparison would measure the probe. Updates are
//     covered by the SOURCE closure in `r2_c30_spawn_order_tests.rs`
//     (`ac8_no_canister_entry_point_reads_the_accrual_cell` and
//     `ac8_the_set_of_functions_naming_the_accrual_is_exactly_the_pinned_closure`),
//     which proves that NO entry point — of any shape — names the accrual cell or
//     its accessors, in a function body OR in a macro token stream, and that the
//     set of functions that do is a pinned closure of private helpers. That is
//     the "stated structural argument" half.
//     ARG-TAKING QUERIES ARE NO LONGER EXCLUDED (SSA round 2, RED-1): each is
//     driven with an argument DEFAULT-CONSTRUCTED FROM ITS DID TYPE. See
//     `probed_endpoints` below.
//   * The three nullary queries in `VOLATILE_BY_CONSTRUCTION` below, each with
//     its reason at the entry.
//
// NON-VACUITY. The test asserts (a) that the accrual was genuinely NON-ZERO while
// the probes were taken — the boundary afterwards publishes exactly one row with
// a non-zero total — and (b) that the probe MECHANISM can see movement at all, by
// requiring at least one probed endpoint to differ at the boundary. A probe that
// could not observe a change would pass this criterion for the wrong reason.

/// Nullary queries excluded from the before/after comparison, each because it
/// moves for a reason that is not the accrual. Excluded from the BEHAVIOURAL leg
/// only — the source closure still forbids all three from naming the accrual.
const VOLATILE_BY_CONSTRUCTION: &[(&str, &str)] = &[
    (
        "cycle_balance",
        "the canister's own cycle balance, which every executed message lowers; it \
         moves for ANY call, carries no fee quantity, and is a fleet-monitor surface \
         that pre-dates C-30",
    ),
    (
        "get_solvency_attestation",
        "a CERTIFIED response — the IC certificate and the attestation timestamp \
         differ on every call regardless of state. Its payload is the CLAMPED reserve \
         figure, bucketed at ATTESTATION_BUCKET_NS, which is exactly the floor of the \
         flush window (AC-13): it cannot resolve a fee more finely than the window \
         already does",
    ),
    (
        "get_deployment_attestation",
        "advisory deployment wiring (canister IDs, config hash, VK/verifier/circuit) \
         plus a call-time timestamp; no accounting quantity is in it",
    ),
];

/// Nullary queries excluded because they are the A2 accepted-anchor surface,
/// which moves when a spend FINALIZES for reasons that pre-date C-30 and are
/// required by the protocol: a spender must be able to learn the anchor its next
/// proof binds to. Neither carries a fee quantity — one is a `nat64` COUNT of
/// accepted roots, the other the accepted-root HEAD (a root plus its index) —
/// and neither is derived from the accrual cell, which the source closure in
/// `r2_c30_spawn_order_tests.rs` proves for the whole interface. C-30 hides the
/// FEE signal, not the existence of shielded activity; hiding the latter is the
/// anonymity-set property the pool has by construction, not this lane.
const SPEND_ANCHOR_SURFACES: &[(&str, &str)] = &[
    (
        "accepted_spend_root_count",
        "nat64 count of accepted spend anchors; +1 per finalized spend, no amount in it",
    ),
    (
        "get_accepted_root_head",
        "the accepted-root head (root + index) a spender needs to build its next proof",
    ),
];

/// Arg-taking queries excluded from the DRIVEN comparison because the default
/// argument makes them a per-spend STATUS lookup: they answer about the very
/// spend the probe performs, so they move by definition of what they are, and
/// what they move by is a lifecycle state, never a fee quantity. Each is still
/// bound by the source closure in `r2_c30_spawn_order_tests.rs`, which forbids
/// EVERY entry point — of any shape — from naming the accrual or its accessors.
/// Empty is the strong position; every entry here is a hole and must be argued.
const CALLER_SCOPED_OR_ID_KEYED: &[(&str, &str)] = &[];

/// The raw pool DID text with `//` comments stripped.
fn pool_did_text() -> String {
    let did = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../canisters/shielded-pool/shielded_pool.did"
    ))
    .expect("the pool DID must be readable");
    did.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse the `service` block of the pool DID into
/// `(name, is_query, is_nullary, args)`.
/// A parser, not a list: an endpoint added to the interface is enumerated here
/// the moment it is declared, which is the property RED-1 says was missing.
fn pool_did_endpoints() -> Vec<(String, bool, bool, String)> {
    // Strip `//` comments — they contain method names and arrows.
    let stripped: String = pool_did_text();

    let svc = stripped
        .find("service")
        .expect("the pool DID must declare a `service`");
    let open = stripped[svc..]
        .find("-> {")
        .expect("the service must declare a method block")
        + svc
        + 4;

    let bytes: Vec<char> = stripped[open..].chars().collect();
    let mut depth = 1usize;
    let mut end = bytes.len();
    for (i, c) in bytes.iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body: String = bytes[..end].iter().collect();

    // Split on top-level `;`.
    let mut entries: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut d = 0i32;
    for c in body.chars() {
        match c {
            '(' | '{' => d += 1,
            ')' | '}' => d -= 1,
            _ => {}
        }
        if c == ';' && d == 0 {
            entries.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }

    let mut out = Vec::new();
    for e in entries {
        let e = e.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(colon) = e.find(" : ").or_else(|| e.find(':')) else {
            continue;
        };
        let name = e[..colon].trim().to_string();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let rest = e[colon..].trim().trim_start_matches(':').trim();
        let Some(arrow) = rest.find("->") else { continue };
        let args = rest[..arrow].trim().to_string();
        let is_nullary = args == "()";
        out.push((name, rest.trim_end().ends_with("query"), is_nullary, args));
    }
    assert!(
        out.len() > 40,
        "AC-8: the DID parser found only {} endpoints — the interface has far more. \
         A parser that silently finds nothing enumerates nothing, so this is RED.",
        out.len()
    );
    out
}

// -----------------------------------------------------------------------------
// SSA landed-diff round 2, RED-1 — ARGUMENT-TAKING queries are now DRIVEN.
// CTO_TRIAGE_SSA_LANDED_DIFF_ROUND2_2026-09-05.md, R-2 row;
// SSA_LANDED_DIFF_R-2_V2_2026-09-05.md RED-1.
//
// Round 1 filtered arg-taking queries out of this probe and leaned entirely on
// the source closure to cover them. The SSA's counterexample was an arg-taking
// query — `window_status(_arg: u8)` — whose accrual read sat inside a `vec!`,
// invisible to the source walk. Both halves failed at once, so the leak was
// live on a real canister with every AC-8 check green. The source walk is fixed
// (macro token streams, `r2_c30_spawn_order_tests.rs`); this leg removes the
// filter, so the two are now genuinely independent: an arg-taking leak has to
// beat a syntax scan AND a running-canister probe, not one of them.
//
// The argument is DERIVED FROM THE DID TYPE, not hand-written per endpoint: a
// new arg-taking query is driven the moment it is declared. An endpoint whose
// argument type this constructor cannot build is not silently dropped — it must
// be named in `UNDRIVABLE_ARGS` with its reason, and that list is asserted to be
// exactly the set that actually failed to construct.

/// Arg-taking queries this leg cannot drive, each with the reason and the check
/// that covers it instead. Asserted below to be EXACTLY the set of endpoints
/// whose DID argument type has no default construction — a stale entry fails,
/// and an undrivable endpoint missing from the list fails.
const UNDRIVABLE_ARGS: &[(&str, &str)] = &[];

/// `type NAME = ...;` aliases declared in the pool DID, so a named argument type
/// resolves to the structure it stands for.
fn did_type_aliases() -> std::collections::BTreeMap<String, String> {
    let did = pool_did_text();
    let mut out = std::collections::BTreeMap::new();
    for (i, _) in did.match_indices("type ") {
        // A `type` keyword at the start of a line only.
        if i > 0 && !matches!(did.as_bytes()[i - 1], b'\n' | b'\r') {
            continue;
        }
        let rest = &did[i + 5..];
        let Some(eq) = rest.find('=') else { continue };
        let name = rest[..eq].trim().to_string();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        // Body runs to the top-level `;`.
        let mut d = 0i32;
        let mut end = None;
        for (j, c) in rest[eq + 1..].char_indices() {
            match c {
                '{' | '(' => d += 1,
                '}' | ')' => d -= 1,
                ';' if d == 0 => {
                    end = Some(j);
                    break;
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        out.insert(
            name,
            rest[eq + 1..eq + 1 + end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    out
}

/// A default value of a DID type, or `None` if this constructor cannot build one.
fn did_default_value(
    ty: &str,
    aliases: &std::collections::BTreeMap<String, String>,
    depth: usize,
) -> Option<candid::types::value::IDLValue> {
    use candid::types::value::IDLValue;
    if depth > 8 {
        return None;
    }
    let ty = ty.trim();
    let ty = ty.strip_prefix('(').and_then(|t| t.strip_suffix(')')).unwrap_or(ty).trim();
    Some(match ty {
        "nat" => IDLValue::Nat(0u8.into()),
        "nat8" => IDLValue::Nat8(0),
        "nat16" => IDLValue::Nat16(0),
        "nat32" => IDLValue::Nat32(0),
        "nat64" => IDLValue::Nat64(0),
        "int" => IDLValue::Int(0u8.into()),
        "int8" => IDLValue::Int8(0),
        "int16" => IDLValue::Int16(0),
        "int32" => IDLValue::Int32(0),
        "int64" => IDLValue::Int64(0),
        "float32" => IDLValue::Float32(0.0),
        "float64" => IDLValue::Float64(0.0),
        "bool" => IDLValue::Bool(false),
        "text" => IDLValue::Text(String::new()),
        "null" => IDLValue::Null,
        "reserved" => IDLValue::Reserved,
        "principal" => IDLValue::Principal(anon()),
        "blob" => IDLValue::Blob(Vec::new()),
        _ => {
            if let Some(rest) = ty.strip_prefix("opt ") {
                let _ = rest;
                // `null` is the default of every `opt`.
                IDLValue::None
            } else if ty.starts_with("vec ") {
                IDLValue::Vec(Vec::new())
            } else if let Some(alias) = aliases.get(ty) {
                return did_default_value(alias, aliases, depth + 1);
            } else {
                return None;
            }
        }
    })
}

/// Split a DID argument list `(a, b)` on TOP-LEVEL commas.
fn split_did_args(args: &str) -> Vec<String> {
    let inner = args.trim();
    let inner = inner.strip_prefix('(').unwrap_or(inner);
    let inner = inner.strip_suffix(')').unwrap_or(inner);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut d = 0i32;
    for c in inner.chars() {
        match c {
            '{' | '(' => d += 1,
            '}' | ')' => d -= 1,
            ',' if d == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out.into_iter()
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect()
}

/// Encoded Candid bytes for a default-constructed argument tuple, or `None`.
fn default_args_bytes(
    args: &str,
    aliases: &std::collections::BTreeMap<String, String>,
) -> Option<Vec<u8>> {
    let mut vals = Vec::new();
    for a in split_did_args(args) {
        vals.push(did_default_value(&a, aliases, 0)?);
    }
    candid::types::value::IDLArgs::new(&vals).to_bytes().ok()
}

/// Every public QUERY an anonymous caller may ask — nullary AND arg-taking —
/// paired with the encoded argument this leg drives it with.
fn probed_endpoints() -> Vec<(String, Vec<u8>)> {
    let aliases = did_type_aliases();
    let mut out = Vec::new();
    for (name, is_query, _nullary, args) in pool_did_endpoints() {
        if !is_query {
            continue;
        }
        if VOLATILE_BY_CONSTRUCTION.iter().any(|(v, _)| *v == name)
            || SPEND_ANCHOR_SURFACES.iter().any(|(v, _)| *v == name)
            || CALLER_SCOPED_OR_ID_KEYED.iter().any(|(v, _)| *v == name)
        {
            continue;
        }
        match default_args_bytes(&args, &aliases) {
            Some(bytes) => out.push((name, bytes)),
            None => assert!(
                UNDRIVABLE_ARGS.iter().any(|(u, _)| *u == name),
                "AC-8 (SSA round 2): `{name}` takes `{args}`, which this leg cannot \
                 default-construct, and it is NOT recorded in UNDRIVABLE_ARGS. An \
                 endpoint that is neither driven nor declared undrivable is simply \
                 unprobed — that is the coverage hole RED-1 was about. Either extend \
                 `did_default_value` or record the endpoint WITH ITS REASON."
            ),
        }
    }
    out
}

/// Raw Candid response bytes per endpoint, read ANONYMOUSLY. A rejection is a
/// value too: an endpoint that starts or stops rejecting has also moved.
fn probe_all(
    pic: &PocketIc,
    s: &Stack,
    probes: &[(String, Vec<u8>)],
) -> Vec<(String, Result<Vec<u8>, String>)> {
    probes
        .iter()
        .map(|(n, arg)| {
            let r = pic
                .query_call(s.pool, anon(), n, arg.clone())
                .map_err(|e| format!("{e:?}"));
            (n.clone(), r)
        })
        .collect()
}

/// Every entry in `UNDRIVABLE_ARGS` must name a real arg-taking query that this
/// leg genuinely cannot construct an argument for, and the source closure in
/// `r2_c30_spawn_order_tests.rs` covers it. A stale entry is a silent hole.
#[test]
fn ac8_every_undrivable_endpoint_is_real_and_really_undrivable() {
    let aliases = did_type_aliases();
    let did = pool_did_endpoints();
    for (name, reason) in UNDRIVABLE_ARGS {
        let e = did
            .iter()
            .find(|(n, _, _, _)| n == name)
            .unwrap_or_else(|| panic!("AC-8: `{name}` is declared undrivable (\"{reason}\") but is not in the pool DID"));
        assert!(e.1, "AC-8: `{name}` is declared undrivable but is not a query");
        assert!(
            default_args_bytes(&e.3, &aliases).is_none(),
            "AC-8: `{name}` is listed in UNDRIVABLE_ARGS but its argument `{}` CAN now \
             be default-constructed. Drive it instead of excusing it.",
            e.3
        );
    }
}

#[test]
fn ac8_no_public_pool_query_moves_inside_the_window() {
    let probes = probed_endpoints();
    let names: Vec<&str> = probes.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        probes.len() >= 25,
        "AC-8: only {} public queries were enumerated from the DID and driven; the \
         pool publishes many more, arg-taking ones included. Probing a handful is \
         what RED-1 was about: {names:?}",
        probes.len()
    );
    let arg_taking = pool_did_endpoints()
        .into_iter()
        .filter(|(n, q, nullary, _)| *q && !*nullary && names.contains(&n.as_str()))
        .count();
    assert!(
        arg_taking > 0,
        "AC-8 (SSA round 2): the probe set contains NO argument-taking query. RED-1 \
         was an argument-taking query; a probe that drives only nullary endpoints \
         has the same blind spot this fix exists to close."
    );

    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    // The deposit's IMMEDIATE ShieldFee notification (AC-11a) legitimately moves
    // fee surfaces; snapshot only once it has settled, so what the comparison
    // measures is the PRIVATE SPEND alone.
    let root = deposit(&pic, &s, DENOMINATIONS[3], fe(0x06));
    for _ in 0..4 {
        pic.tick();
    }
    let before = probe_all(&pic, &s, &probes);

    spend_pa(&pic, &s, 600, root, 0x86, (0xC0, 0xC1));
    for _ in 0..4 {
        pic.tick();
    }
    let after = probe_all(&pic, &s, &probes);

    let moved: Vec<&str> = before
        .iter()
        .zip(after.iter())
        .filter(|((_, b), (_, a))| b != a)
        .map(|((n, _), _)| n.as_str())
        .collect();
    assert!(
        moved.is_empty(),
        "AC-8 (SSA RED-1): {moved:?} answered DIFFERENTLY to an anonymous caller \
         before and after one fee-bearing private spend, inside the window. Whatever \
         that difference encodes, it is a per-spend signal on a public surface, which \
         is the leak C-30 closes. Endpoints probed: {names:?}"
    );

    // NON-VACUITY (a): the accrual was genuinely non-zero the whole time.
    assert!(
        private_rows(&pic, &s).is_empty(),
        "no PrivateTransferFee row may exist before the boundary"
    );
    advance_to(&pic, boundary + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "exactly one row at the boundary; got {rows:#?}");
    assert!(
        rows[0].total_amount > 0,
        "the probes above are only meaningful if a NON-ZERO accrual was pending \
         while they were taken; the boundary published {rows:#?}"
    );

    // NON-VACUITY (b): the probe MECHANISM can see a pool-side change, and sees
    // it on exactly the endpoint that changed.
    //
    // The positive control is deliberately NOT the boundary. Nothing on the POOL
    // moves at the boundary either — the batch is published to the TREASURY, and
    // the pool's own notification counters return to their baseline once the
    // flush resolves. That is the design, but it means a boundary-based control
    // would prove nothing about the probe. So the control is an unrelated,
    // controller-only state change with a known public reader: setting the flush
    // window must move `get_fee_flush_window_ns` and NOTHING else.
    let control_before = probe_all(&pic, &s, &probes);
    let new_window = w * 2;
    set_window(&pic, &s, s.controller, new_window).expect("doubling the window is in bounds");
    let control_after = probe_all(&pic, &s, &probes);
    let control_moved: Vec<&str> = control_before
        .iter()
        .zip(control_after.iter())
        .filter(|((_, b), (_, a))| b != a)
        .map(|((n, _), _)| n.as_str())
        .collect();
    assert_eq!(
        control_moved,
        vec!["get_fee_flush_window_ns"],
        "AC-8 positive control: changing the flush window must move EXACTLY \
         `get_fee_flush_window_ns` in this probe. If nothing moved, the probe is \
         blind and its silence inside the window proves nothing; if something else \
         moved too, the probe is not per-endpoint precise."
    );
}

#[test]
fn ac8_every_exemption_names_a_real_endpoint_and_is_a_nullary_query() {
    let did = pool_did_endpoints();
    for (name, reason) in VOLATILE_BY_CONSTRUCTION
        .iter()
        .chain(SPEND_ANCHOR_SURFACES.iter())
    {
        let found = did.iter().find(|(n, _, _, _)| n == name).unwrap_or_else(|| {
            panic!(
                "AC-8: `{name}` is exempted from the probe (\"{reason}\") but is not \
                 declared in the pool DID at all. A stale exemption silently unprobes \
                 any future endpoint that reuses the name."
            )
        });
        assert!(
            found.1 && found.2,
            "AC-8: `{name}` is exempted as a nullary query but the DID declares it as \
             {} / {}. Only nullary queries are in the probe set, so only nullary \
             queries can be exempted FROM it.",
            if found.1 { "query" } else { "update" },
            if found.2 { "nullary" } else { "arg-taking" }
        );
    }
    // The arg-taking exemptions are checked separately: they are NOT nullary.
    for (name, reason) in CALLER_SCOPED_OR_ID_KEYED {
        let found = did.iter().find(|(n, _, _, _)| n == name).unwrap_or_else(|| {
            panic!(
                "AC-8: `{name}` is exempted from the driven probe (\"{reason}\") but is \
                 not declared in the pool DID at all."
            )
        });
        assert!(
            found.1 && !found.2,
            "AC-8: `{name}` is exempted as an ARG-TAKING query but the DID declares it \
             otherwise."
        );
    }
    assert_eq!(
        VOLATILE_BY_CONSTRUCTION.len() + SPEND_ANCHOR_SURFACES.len(),
        5,
        "AC-8: the exemption lists have changed size. Every exemption is a hole in \
         this criterion and must be argued in the packet, not added quietly."
    );
}
