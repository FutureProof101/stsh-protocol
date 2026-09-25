// =============================================================================
// STSH — R-2 (C-30): cross-Wasm durability + the fail-closed region-24 gate
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

// ── Scalars<1> encoding, reproduced independently of the crate under test ────
//
// `stsh_eager_cell::Scalars` layout: byte 0 = layout version (1), then N
// big-endian u128 words. Written out here rather than imported: a plant that
// used the encoder would be unable to produce the malformed regions AC-15d needs,
// and a check that borrows its subject's encoder is not independent of it.

const EAGER_LAYOUT_VERSION: u8 = 1;

fn scalars1_bytes(word: u128) -> Vec<u8> {
    let mut b = vec![0u8; 1 + 16];
    b[0] = EAGER_LAYOUT_VERSION;
    b[1..].copy_from_slice(&word.to_be_bytes());
    b
}

fn plant_window_bytes(pic: &PocketIc, s: &Stack, bytes: Vec<u8>) {
    let _: () = decode(
        "plant_fee_flush_window_bytes_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "plant_fee_flush_window_bytes_for_test",
            candid::encode_one(bytes).unwrap(),
        ),
    );
}

/// Upgrade the pool between TWO DIFFERENT MODULES.
///
/// A same-Wasm install→upgrade does NOT satisfy the cross-Wasm contract: heap
/// thread-locals survive in-process, so a heap-only implementation passes such a
/// test and fails on a real replica. The `testing` build and the production build
/// are genuinely different modules.
fn upgrade_to_prod(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{e:?}"))
}

fn upgrade_to_test(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{e:?}"))
}

// =============================================================================
// AC-6 — the ACCRUAL survives a REAL cross-Wasm upgrade.
// =============================================================================

#[test]
fn ac6_the_accrual_survives_a_real_cross_wasm_upgrade_and_flushes_in_full() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let w = window_ns(&pic, &s);
    let boundary = next_boundary(now_ns(&pic), w);

    const N: u128 = 3;
    for k in 0..N as u8 {
        let root = deposit(&pic, &s, DENOMINATIONS[3], fe(0x07 + k));
        spend_pa(&pic, &s, 700 + k as u64, root, 0x97 + k, (0xD0 + 2 * k, 0xD1 + 2 * k));
    }
    assert!(private_rows(&pic, &s).is_empty(), "nothing published yet");

    // Upgrade BEFORE the boundary, between two genuinely different modules.
    upgrade_to_prod(&pic, &s).expect("cross-Wasm upgrade must succeed");

    advance_to(&pic, boundary + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "the post-upgrade boundary still publishes exactly one row");
    let (ops, ins, stk) = expected_split(SPEND_FEE);
    assert_eq!(
        (rows[0].operations, rows[0].insurance, rows[0].staking),
        (N * ops, N * ins, N * stk),
        "the row must carry the FULL accrual. A thread-local accrual passes a \
         native durability test and loses everything here."
    );
    assert_eq!(rows[0].timestamp_ns, boundary);
}

// =============================================================================
// AC-15a — the WINDOW survives a REAL cross-Wasm upgrade.
// =============================================================================

#[test]
fn ac15a_the_window_survives_a_real_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let t = now_ns(&pic);
    let hour = (t / WINDOW_DEFAULT_NS) * WINDOW_DEFAULT_NS;

    set_window(&pic, &s, s.controller, HALF_HOUR_NS).expect("30 min accepted");
    upgrade_to_prod(&pic, &s).expect("cross-Wasm upgrade must succeed");

    assert_eq!(
        window_ns(&pic, &s),
        HALF_HOUR_NS,
        "the window must be read back from stable memory after the upgrade"
    );

    let b_10_30 = hour + HALF_HOUR_NS;
    advance_to(&pic, b_10_30 + 1);
    let rows = private_rows(&pic, &s);
    assert_eq!(rows.len(), 1, "the post-upgrade re-arm lands on the 30-min boundary");
    assert_eq!(rows[0].timestamp_ns, b_10_30);
}

// =============================================================================
// AC-15a — a PRE-R-2 pool (region 24 ABSENT) upgrades CLEANLY onto the default.
//
// `CTO_RULING_R2_REGION24_ABSENT_VS_INVALID_2026-09-05.md` §2, replacing V3's
// AC-15 "absent → trap" leg. The pinned `shielded_pool_pre_f2redact_test.wasm`
// fixture predates MemoryId 24 entirely, so its region 24 is genuinely empty —
// the only honest source of an absent region available. `Cell::init` must create
// the cell with the REAL default (1 h) rather than the sentinel, so the upgrade
// must succeed and the getter must read 1 h.
//
// This is the cross-Wasm leg that a same-Wasm install→upgrade cannot prove: only
// a module that never allocated region 24 can leave it absent.
// =============================================================================

/// The pre-R-2 (pre-F2-REDACT) pool fixture. Its `PoolInitArgs` predates
/// `verifier_canister`; candid ignores the extra field, so the current struct
/// encodes an init argument the old module accepts.
fn pool_pre_r2_wasm() -> Vec<u8> {
    let path = env!("POOL_PRE_F2REDACT_TEST_WASM");
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("Cannot read pre-F2-REDACT Wasm at {}: {}", path, e))
}

#[test]
fn ac15a_a_pre_r2_pool_upgrades_cleanly_onto_the_default_window() {
    let pic = PocketIc::new();
    set_time_ns(&pic, T_10_17);
    let controller = p(0xC0);
    let pool = create_canister(&pic);

    // Install a module that has NEVER heard of MemoryId 24.
    install(&pic, pool, pool_pre_r2_wasm(), &PoolInitArgs {
        token_canister: p(0x10),
        nullifier_canister: p(0x11),
        merkle_canister: p(0x12),
        treasury_canister: p(0x01),
        staking_canister: p(0x02),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: None,
    });

    // Let the install_code instruction budget recover. The fixture is a full pool
    // module, and installing then immediately upgrading two of them in one round
    // trips the replica's `CanisterInstallCodeRateLimited` — a harness limit, not
    // a property of the code under test.
    advance_to(&pic, T_10_17 + 10 * 60 * 1_000_000_000);

    // Upgrade to the R-2 module. Region 24 is absent, so `Cell::init` seeds it
    // with the default — `post_upgrade`'s gate must never see the sentinel here.
    pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect(
            "a pre-R-2 pool must upgrade CLEANLY: an absent region 24 is created with \
             the default window by Cell::init and never reaches Scalars::from_bytes. \
             A sentinel init default would trap here.",
        );

    let s = Stack {
        pool,
        token: p(0x10),
        merkle: p(0x12),
        treasury: p(0x01),
        controller,
        user: p(0xAA),
        recipient: p(0xBB),
    };
    assert_eq!(
        window_ns(&pic, &s),
        WINDOW_DEFAULT_NS,
        "an absent region 24 must come up on the REAL default (1 h) — a bounded, \
         in-bounds value at or above the attestation floor, not a fail-open"
    );
}

// =============================================================================
// AC-15b/c/d — the region-24 gate FAILS CLOSED on every PRESENT-BUT-INVALID
// state.
//
// Scope (`CTO_RULING_R2_REGION24_ABSENT_VS_INVALID_2026-09-05.md` §2): these
// plants all write a region that is PRESENT and carries the cell header, so
// `Scalars::from_bytes` actually runs on them. An ABSENT region never reaches
// `from_bytes` — `Cell::init` creates the cell with its default value — and is
// covered by `ac15a_a_pre_r2_pool_upgrades_cleanly_onto_the_default_window`
// instead. Everything below is corruption, not an honest absence: each must
// TRAP, and the trap message must name the cell.
// =============================================================================

/// Plant `bytes` into region 24 and attempt the upgrade. Returns the trap text
/// if it trapped, or `None` if the upgrade succeeded.
fn upgrade_with_planted_window(bytes: Vec<u8>) -> Option<String> {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    plant_window_bytes(&pic, &s, bytes);
    // The plant is applied by `pre_upgrade`, so the upgrade must be TO the
    // testing build (which carries the plant hook) — the region it writes is
    // then read back by the SAME upgrade's `post_upgrade`.
    match upgrade_to_test(&pic, &s) {
        Ok(()) => None,
        Err(e) => Some(e),
    }
}

fn assert_traps_naming_the_cell(bytes: Vec<u8>, case: &str) {
    let trap = upgrade_with_planted_window(bytes).unwrap_or_else(|| {
        panic!(
            "AC-15 ({case}): the upgrade SUCCEEDED on a bad region 24. \
             These bytes are PRESENT and headered, so they cannot be an honest \
             absence — anything that is not a valid in-range window must fail \
             CLOSED. A default here is a fail-OPEN onto the published flush cadence."
        )
    });
    assert!(
        trap.contains("MemoryId 24") || trap.contains("FEE_FLUSH_WINDOW_CELL"),
        "AC-15 ({case}): the trap must NAME the cell so an operator knows what to \
         reinstall. Got: {trap}"
    );
}

#[test]
fn ac15b_a_window_below_the_floor_traps_at_load() {
    assert_traps_naming_the_cell(
        scalars1_bytes((ATTESTATION_BUCKET_NS - 1) as u128),
        "below the floor",
    );
}

#[test]
fn ac15c_a_window_above_the_ceiling_traps_at_load() {
    assert_traps_naming_the_cell(
        scalars1_bytes((WINDOW_CEILING_NS + 1) as u128),
        "above the ceiling",
    );
}

#[test]
fn ac15c_a_window_that_does_not_fit_u64_traps_at_load() {
    assert_traps_naming_the_cell(scalars1_bytes(u128::MAX), "wider than u64");
}

#[test]
fn ac15d_an_undecodable_present_region_traps_at_load() {
    // (i) wrong length — `Scalars<1>` is exactly 17 bytes.
    assert_traps_naming_the_cell(vec![EAGER_LAYOUT_VERSION, 0, 0, 0, 0], "wrong length");

    // (ii) correct length, WRONG layout byte.
    let mut wrong_layout = scalars1_bytes(WINDOW_DEFAULT_NS as u128);
    wrong_layout[0] = 0x02;
    assert_traps_naming_the_cell(wrong_layout, "wrong layout byte");

    // (iii) a present, headered region of all-0xFF — `from_bytes` decodes it to
    // the sentinel. NOT "never written": an unwritten region has no cell header
    // and is created with the default by `Cell::init` (AC-15a). This is a wiped
    // or garbled region that still LOOKS like a cell, and it must trap.
    assert_traps_naming_the_cell(vec![0xFFu8; 17], "all-0xFF sentinel");
}

/// The control: a VALID in-range plant must upgrade cleanly. Without this the
/// three assertions above could all be passing because the plant hook itself
/// breaks every upgrade, which would make the gate look green while proving
/// nothing about the region-24 check.
#[test]
fn ac15d_control_a_valid_planted_window_upgrades_cleanly() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    plant_window_bytes(&pic, &s, scalars1_bytes(HALF_HOUR_NS as u128));
    upgrade_to_test(&pic, &s).expect("a VALID planted region must upgrade cleanly");
    assert_eq!(
        window_ns(&pic, &s),
        HALF_HOUR_NS,
        "the planted value is what the pool came up with — so the plant reaches \
         the region the gate reads, and the trap cases above are real"
    );
}
