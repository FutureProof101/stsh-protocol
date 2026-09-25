// =============================================================================
// STSH — W4 G-FEESPLIT: fee-split launch posture, encoded as an EXECUTABLE gate
// =============================================================================
//
// Resolve campaign 2026-08-13 lane W4 (items 4-1 / 4-2 / 4-3), dispatched
// 2026-08-18. Ruling context: staking is EXCLUDED at launch (Owner, D1,
// 2026-08-14). W4's job is to make that exclusion ENFORCED, not commented.
//
// The V2 correction that shapes this file: **the gate must be a FAILING TEST,
// not prose.** A gate written as a paragraph in a runbook is one that a future
// builder can satisfy by not reading it. Every rule below is therefore an
// assertion that goes RED the day someone tries to enable staking without
// closing the conditions the D1 ruling attached to it.
//
// What each item is:
//
//   4-3  `staking_rewards_split_bps` MUST be 0 while `staking_rewards_enabled`
//        is false (fee policy section 17: "No fee income routes to staking
//        rewards at launch"). Before W4 that rule existed ONLY as a doc comment
//        on the field — governance could store exactly the configuration that
//        starts routing fee income to staking the instant the switch flips.
//        Now rejected at every setter boundary with a typed error.
//
//   4-1  The shield path destructured 2 of the 3 buckets
//        `split_protocol_fee_to_reserves` returns and dropped
//        `staking_rewards_reserve`, reporting a hardcoded 0 to the treasury.
//        Inert while staking is disabled (the split redistributes that share),
//        but with the switch true and a nonzero split it books strictly LESS
//        than the fee it charged. Now routed explicitly, matching the unshield
//        and private-spend paths, which were already correct.
//
//   4-2  "Distributions pause below 6 months runway" — the RULE is implemented
//        and fail-closed in `stsh_fee_policy`, but its input
//        (`monthly_runway_cost`) has no on-chain storage and the predicate has
//        no production call site. Launch posture is DOCUMENT-AND-GATE: the
//        runway engine is deliberately NOT built (it is post-launch by D1).
//        See `g_feesplit_enabling_staking_is_gated` for the executable form.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): POOL_WASM (production —
// carries the real setter) and POOL_TEST_WASM (carries the build-gated
// `set_governance_fee_params_unchecked_for_test`). The binding is proved on
// BOTH: a rule the `_test` Wasm can bypass is not a gate.
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}

fn pool_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_WASM"), "shielded_pool")
}
fn pool_test_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test")
}

// ── The RULED numeric policy, transcribed (see fee_setter_guardrail_tests) ────

const E8S: u128 = 100_000_000;
// A-7: RULED 2026-08-21 — flat-minimum floor is 0.1 STSH
// (OWNER_RULING_FEE_MODEL_CONSOLIDATED), superseding 1,000 STSH.
const FLAT_MIN_FLOOR: u128 = E8S / 10;
const SPEND_FEE_FLOOR: u128 = E8S / 10;
const COOLDOWN_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const LAUNCH_BPS: u16 = 25;

// ── Candid mirrors (field/variant names must match the canister exactly) ──────

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

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum SpendFeeMode {
    FixedStsh,
    XdrPegged,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
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

/// Mirrors `GovernanceFeeParams::mainnet_launch_config()`.
fn mainnet_launch_config() -> GovernanceFeeParams {
    GovernanceFeeParams {
        protocol_shielding_fee_stsh: 0,
        protocol_unshielding_fee_stsh: 0,
        protocol_private_spend_fee_stsh: SPEND_FEE_FLOOR,
        minimum_withdrawal_gross: 0,
        minimum_recipient_amount: 0,
        minimum_private_credit: 0,
        fee_reference_price_stsh_per_icp_e8s: 0,
        fee_safety_margin_bps: 12_500,
        max_fee_change_bps_per_update: 1_000,
        fee_update_cooldown_ns: COOLDOWN_NS,
        operations_split_bps: 8_500,
        insurance_split_bps: 1_500,
        staking_rewards_split_bps: 0,
        staking_rewards_enabled: false,
        minimum_treasury_runway_months: 6,
        target_treasury_runway_months: 12,
        shield_fee_bps: Some(LAUNCH_BPS),
        unshield_fee_bps: Some(LAUNCH_BPS),
        shield_flat_minimum_fee_e8s: Some(FLAT_MIN_FLOOR),
        unshield_flat_minimum_fee_e8s: Some(FLAT_MIN_FLOOR),
        spend_fee_mode: Some(SpendFeeMode::FixedStsh),
        fee_model_version: Some(1),
        params_epoch: Some(1),
    }
}

// ── PocketIC helpers ──────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

const CONTROLLER: u8 = 0x06;

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

fn setup_pool_with(pic: &PocketIc, module: Vec<u8>) -> Principal {
    let pool_id = pic.create_canister();
    pic.add_cycles(pool_id, 2_000_000_000_000u128);
    pic.install_canister(
        pool_id,
        module,
        candid::encode_one(&PoolInitArgs {
            token_canister: p(0x10),
            nullifier_canister: p(0x11),
            merkle_canister: p(0x12),
            treasury_canister: p(0x04),
            staking_canister: p(0x02),
            controller: p(CONTROLLER),
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .unwrap(),
        None,
    );
    pool_id
}

fn setup_pool(pic: &PocketIc) -> Principal {
    setup_pool_with(pic, pool_wasm())
}

fn set_params_via(
    pic: &PocketIc,
    pool: Principal,
    method: &str,
    params: &GovernanceFeeParams,
) -> Result<(), String> {
    decode(
        method,
        pic.update_call(
            pool,
            p(CONTROLLER),
            method,
            candid::encode_one(params).unwrap(),
        ),
    )
}

fn set_params(
    pic: &PocketIc,
    pool: Principal,
    params: &GovernanceFeeParams,
) -> Result<(), String> {
    set_params_via(pic, pool, "set_governance_fee_params", params)
}

fn live_params(pic: &PocketIc, pool: Principal) -> GovernanceFeeParams {
    decode(
        "get_governance_fee_params",
        pic.query_call(
            pool,
            p(CONTROLLER),
            "get_governance_fee_params",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Apply the launch config (the one-shot bootstrap) and clear the cooldown, so
/// a test starts from "routine tuning is now in force".
fn bootstrap_and_arm(pic: &PocketIc, pool: Principal) -> GovernanceFeeParams {
    let launch = mainnet_launch_config();
    set_params(pic, pool, &launch).expect("bootstrap with the launch config must succeed");
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();
    launch
}

/// The next routine-tuning candidate: live params with the epoch cleared,
/// since the canister derives the epoch itself.
fn tuning_base(pic: &PocketIc, pool: Principal) -> GovernanceFeeParams {
    let mut params = live_params(pic, pool);
    params.params_epoch = None;
    params
}

/// The typed error W4 4-3 introduced. Asserted by name: a generic "call failed"
/// would also pass if the setter started rejecting for an unrelated reason.
fn assert_posture_error(err: &str, bps: u32) {
    assert!(
        err.contains("StakingSplitNonzeroWhileDisabled"),
        "expected the typed posture error, got: {err}"
    );
    assert!(
        err.contains(&bps.to_string()),
        "the error must name the offending split bps ({bps}), got: {err}"
    );
}

// =============================================================================
// 4-3 — the binding, on the PRODUCTION Wasm
// =============================================================================

#[test]
fn g_feesplit_staking_split_nonzero_while_disabled_is_rejected() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    let before = live_params(&pic, pool);

    // A split that is perfectly VALID as a sum (8000 + 1000 + 1000 = 10 000) —
    // so this cannot pass or fail for the pre-existing InvalidFeeSplitBps
    // reason. The only thing wrong with it is the posture.
    let mut bad = tuning_base(&pic, pool);
    bad.operations_split_bps = 8_000;
    bad.insurance_split_bps = 1_000;
    bad.staking_rewards_split_bps = 1_000;
    bad.staking_rewards_enabled = false;

    let err = set_params(&pic, pool, &bad).expect_err("4-3: must be rejected");
    assert_posture_error(&err, 1_000);

    // Atomicity: a rejected update mutates NOTHING (SSA fold v3 property).
    assert_eq!(
        live_params(&pic, pool),
        before,
        "a rejected posture must leave the live parameters untouched"
    );
}

#[test]
fn g_feesplit_zero_split_while_disabled_is_accepted() {
    // The negative control. If this failed, the binding would be rejecting the
    // launch posture itself and the test above would prove nothing.
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    let mut good = tuning_base(&pic, pool);
    good.operations_split_bps = 9_000;
    good.insurance_split_bps = 1_000;
    good.staking_rewards_split_bps = 0;
    good.staking_rewards_enabled = false;

    set_params(&pic, pool, &good).expect("a zero staking split must remain settable");
    assert_eq!(live_params(&pic, pool).operations_split_bps, 9_000);
}

#[test]
fn g_feesplit_binding_applies_to_the_bootstrap_set_too() {
    // The posture is a property of the SUBMITTED value alone, so — unlike the
    // per-call movement cap and the cooldown — the one-shot bootstrap is NOT
    // exempt. There is no legitimate reason to bootstrap into a posture that
    // routine tuning may not set.
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    let mut bad = mainnet_launch_config();
    bad.operations_split_bps = 8_000;
    bad.insurance_split_bps = 1_000;
    bad.staking_rewards_split_bps = 1_000;
    bad.staking_rewards_enabled = false;

    let err = set_params(&pic, pool, &bad).expect_err("bootstrap must not be exempt from 4-3");
    assert_posture_error(&err, 1_000);
}

#[test]
fn g_feesplit_same_binding_holds_on_the_test_endpoint() {
    // The build-gated setter exists to permit launch-UNREPRESENTABLE FEE SCALES
    // for the pool's fee-arithmetic suites — not to permit a staking posture the
    // production endpoint refuses. If this endpoint could install one, the gate
    // would be bypassable on the _test Wasm and would not be a gate.
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());

    let mut bad = mainnet_launch_config();
    bad.operations_split_bps = 8_000;
    bad.insurance_split_bps = 1_000;
    bad.staking_rewards_split_bps = 1_000;
    bad.staking_rewards_enabled = false;

    let err = set_params_via(
        &pic,
        pool,
        "set_governance_fee_params_unchecked_for_test",
        &bad,
    )
    .expect_err("the _test setter must enforce 4-3 as well");
    assert_posture_error(&err, 1_000);
}

// =============================================================================
// THE GATE — 4-2 / S8: enabling staking is blocked until the runway is wired
// =============================================================================

/// **THIS IS THE G-FEESPLIT GATE. Read this before "fixing" a failure here.**
///
/// Today `staking_rewards_enabled = true` is unconditionally rejectable
/// pre-launch, because the runway condition it depends on is not configurable
/// on-chain at all: `monthly_runway_cost` has no storage and
/// `staking_distribution_allowed` has no production call site. **That is the
/// INTENDED launch posture, not a defect** — staking is excluded at launch by
/// the D1 ruling (Owner, 2026-08-14), and W4 was explicitly scoped to document
/// and gate the runway rather than build the engine.
///
/// So this test asserts the CURRENT, RULED posture in both directions:
///   - the launch configuration (staking off) is settable, and
///   - the switch cannot be flipped true while a nonzero split accompanies it,
///     which is the only shape in which flipping it would actually route fee
///     income anywhere.
///
/// **To a future builder enabling staking:** this test is the checklist. Before
/// you change it, these G-FEESPLIT items must close, and closing them is a
/// CTO/SSA-adjudicated change, not a test edit:
///   1. `monthly_runway_cost` stored on-chain and governable.
///   2. `stsh_fee_policy::staking_distribution_allowed` wired to a real call
///      site on the distribution path — it is fail-closed today but unreachable.
///   3. The 6-month minimum-runway pause enforced at that call site.
///   4. 4-1's third-bucket routing exercised END-TO-END with the switch TRUE.
///      The native `w4_shield_path_*` tests already prove the caller carries,
///      persists, credits and reports the third bucket in that posture; what
///      is still missing is an endpoint-level run, which is blocked precisely
///      by this gate and becomes possible only once it lifts.
/// Deleting or weakening this test is NOT how any of those get closed.
#[test]
fn g_feesplit_enabling_staking_is_gated() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    // The launch posture is live and staking is off.
    let live = live_params(&pic, pool);
    assert!(
        !live.staking_rewards_enabled,
        "G-FEESPLIT: staking must be OFF at launch (D1 ruling)"
    );
    assert_eq!(
        live.staking_rewards_split_bps, 0,
        "G-FEESPLIT: no fee income may route to staking at launch (section 17)"
    );

    // The runway gate is unreachable: nothing on-chain stores a monthly runway
    // cost, so no runway can be computed and no distribution may be permitted.
    // The switch may therefore not be turned on together with a live share.
    let mut enable = tuning_base(&pic, pool);
    enable.staking_rewards_enabled = true;
    enable.operations_split_bps = 8_000;
    enable.insurance_split_bps = 1_000;
    enable.staking_rewards_split_bps = 1_000;

    let err = set_params(&pic, pool, &enable).expect_err(
        "G-FEESPLIT GATE: staking was enabled with a live fee share while the \
         runway conditions are unmet and unenforceable on-chain. If you are \
         here because you are enabling staking, close G-FEESPLIT items 1-4 in \
         this test's doc comment first — under CTO/SSA adjudication.",
    );
    assert!(
        err.contains("StakingEnableBlockedRunwayUnwired"),
        "the gate must reject with its own typed reason, not incidentally: {err}"
    );

    // The switch is equally blocked with a ZERO split: enabling it is itself
    // the gated act, not merely enabling it alongside a live share.
    let mut enable_only = tuning_base(&pic, pool);
    enable_only.staking_rewards_enabled = true;
    let err = set_params(&pic, pool, &enable_only)
        .expect_err("G-FEESPLIT GATE: the master switch must not flip while the runway is unwired");
    assert!(err.contains("StakingEnableBlockedRunwayUnwired"), "got: {err}");

    // Rejected either way, the live posture is untouched.
    assert!(!live_params(&pic, pool).staking_rewards_enabled);
}

#[test]
fn g_feesplit_launch_config_has_staking_off_and_split_zero() {
    // 4-2's document-and-gate assertion, on the deployed binary rather than on
    // the crate constant: the configuration the deploy chain actually installs
    // carries the launch posture.
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    set_params(&pic, pool, &mainnet_launch_config())
        .expect("the documented mainnet launch config must be settable");

    let live = live_params(&pic, pool);
    assert!(!live.staking_rewards_enabled);
    assert_eq!(live.staking_rewards_split_bps, 0);
    assert_eq!(
        live.minimum_treasury_runway_months, 6,
        "the 6-month minimum from section 18 must survive into the live params, \
         even though nothing consumes it yet — it is the gate's stored intent"
    );
}

// =============================================================================
// 4-1 — no silently discarded bucket
// =============================================================================

/// The LIVE SPLIT CONFIGURATION accounts for 100% of any protocol fee, with
/// staking excluded, on the deployed binary.
///
/// **Scope, stated exactly — this is configuration arithmetic, not caller-level
/// conservation evidence.** It reads the live parameters back from the pool and
/// checks the three shares sum to 10 000 bps with the staking share at zero. It
/// does NOT call `shield_deposit`, drive deposit confirmation, read any reserve,
/// or observe a treasury receipt.
///
/// An earlier revision of this test was named for shield-path conservation and
/// claimed to assert it "through the reserve accounting". It did not, and SSA
/// (SSA-W4-LD-005) correctly found that the pre-W4 broken caller — the one that
/// discarded `staking_rewards_reserve` and reported a hardcoded zero — would
/// have passed it unchanged. It has been renamed and rescoped to what it
/// actually executes.
///
/// Caller-level conservation (carried / persisted / credited / reported, at
/// BOTH switch positions, with each of the four 4-1 regressions mutation-
/// verified to fail) lives in the native `w4_shield_path_*` tests in
/// `canisters/shielded-pool/src/lib.rs`. It is native because the switch-true
/// case is deliberately unreachable through any endpoint: the ratified 4-3
/// binding refuses `staking_rewards_enabled = true` at both setters, and
/// neither weakening it nor adding a test-only seeding endpoint was acceptable.
#[test]
fn g_feesplit_launch_split_bps_account_for_the_whole_fee() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    let live = live_params(&pic, pool);

    // The launch posture as CONFIGURED on the deployed binary.
    assert!(!live.staking_rewards_enabled);
    assert_eq!(live.staking_rewards_split_bps, 0);
    assert_eq!(
        live.operations_split_bps + live.insurance_split_bps + live.staking_rewards_split_bps,
        10_000,
        "the configured shares must leave no part of a protocol fee unassigned; \
         whether the shield CALLER then books all three is asserted natively by \
         the w4_shield_path_* tests, not here"
    );
}
