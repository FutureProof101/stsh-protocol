// =============================================================================
// STSH — RB-SWARM-A1: pool protocol fee floor + setter guardrails
// =============================================================================
//
// Findings closed: L1-F2, L7-C1, L8-F1, E1
// (`docs/SSA_ADVERSARIAL_SWARM_ADJUDICATION_2026-07-31.md`).
//
// Before this lane, `set_governance_fee_params` validated exactly one thing:
// that the reserve split summed to 10 000 bps. A single controller call could
// zero every protocol fee, or set a confiscatory one, instantly and as often as
// it liked — and `u16` bps accepted values above 100%.
//
// This suite proves the guardrails on the PRODUCTION Wasm, which is the point:
// the pre-existing fee suites moved to the build-gated
// `set_governance_fee_params_unchecked_for_test` on the `_test` Wasm (their
// deliberately tiny fees are below the ruled floors), so the guarded endpoint is
// exercised here against the binary that actually ships.
//
// The numeric policy is RULED (CTO + Owner, 2026-07-31) and is NOT re-derived
// here — the constants below are transcribed from the ruling and pinned on the
// crate side by `stsh_fee_policy`'s `ruled_guardrail_constants_are_the_ruled_values`.
//
// Structure of the guardrails under test:
//   1. ABSOLUTE bounds   — every accepted set, bootstrap included.
//   2. PER-CALL movement — routine tuning only.
//   3. COOLDOWN (24h)    — routine tuning only, canister-owned clock.
//   4. EPOCH             — server-derived; a caller value is an assertion only.
//   5. ATOMICITY         — a rejected update mutates nothing at all.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): POOL_WASM (production,
// carries the guardrails) and POOL_TEST_WASM (carries the eager-cell probe).
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

// ── The RULED numeric policy, transcribed ────────────────────────────────────

const E8S: u128 = 100_000_000;
const BPS_FLOOR: u16 = 1;
const BPS_CEILING: u16 = 500;
const MAX_ABS_BPS_CHANGE: u16 = 100;
// A-7: RULED 2026-08-21 — floor 0.1 STSH
// (OWNER_RULING_FEE_MODEL_CONSOLIDATED), ceiling 5 STSH
// (CTO_RULING_A-7_flatmin_ceiling), superseding 1,000 / 5,000 STSH.
// Transcribed literals, deliberately NOT imported from fee-policy: a guard that
// reads the constant it guards cannot fail.
const FLAT_MIN_FLOOR: u128 = E8S / 10;
const FLAT_MIN_CEILING: u128 = 5 * E8S;
const SPEND_FEE_FLOOR: u128 = E8S / 10;
const SPEND_FEE_CEILING: u128 = 5 * E8S;
const COOLDOWN_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
// A6.6 / R-14 (OWNER_RULING_FEE_FLOOR_2_5_STSH 2026-09-08): the LAUNCH values
// moved to 2.5 STSH. The guardrail FLOORS above are UNCHANGED at 0.1 STSH — the
// launch value now sits strictly inside the band rather than on its floor, which
// is the substance of that ruling. Transcribed literal, for the same reason.
const LAUNCH_FLAT_MIN: u128 = 5 * E8S / 2;
const LAUNCH_SPEND_FEE: u128 = 5 * E8S / 2;

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

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
struct FeeGovernanceState {
    last_fee_update_ns: u64,
    params_epoch: u64,
    launch_fee_activated: bool,
    fee_update_cooldown_ns: u64,
}

/// Mirrors `GovernanceFeeParams::mainnet_launch_config()` — the documented
/// deploy-step configuration, INCLUDING the RULED 2.5-STSH flat minimum (A6.6).
fn mainnet_launch_config() -> GovernanceFeeParams {
    GovernanceFeeParams {
        protocol_shielding_fee_stsh: 0,
        protocol_unshielding_fee_stsh: 0,
        protocol_private_spend_fee_stsh: LAUNCH_SPEND_FEE, // 2.5 STSH (A6.6)
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
        shield_flat_minimum_fee_e8s: Some(LAUNCH_FLAT_MIN),
        unshield_flat_minimum_fee_e8s: Some(LAUNCH_FLAT_MIN),
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

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

/// A bare pool. The fee setter is entirely pool-local — no token, merkle or
/// nullifier traffic — so placeholder principals are sufficient and keep the
/// suite fast enough to cover the whole guardrail matrix.
fn setup_pool_with(pic: &PocketIc, module: Vec<u8>) -> Principal {
    let pool_id = create_canister(pic);
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

fn set_params(
    pic: &PocketIc,
    pool: Principal,
    params: &GovernanceFeeParams,
) -> Result<(), String> {
    decode(
        "set_governance_fee_params",
        pic.update_call(
            pool,
            p(CONTROLLER),
            "set_governance_fee_params",
            candid::encode_one(params).unwrap(),
        ),
    )
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

fn fee_gov_state(pic: &PocketIc, pool: Principal) -> FeeGovernanceState {
    decode(
        "get_fee_governance_state",
        pic.query_call(
            pool,
            p(CONTROLLER),
            "get_fee_governance_state",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn matches_launch_config(pic: &PocketIc, pool: Principal) -> bool {
    decode(
        "fee_params_match_mainnet_launch_config",
        pic.query_call(
            pool,
            p(CONTROLLER),
            "fee_params_match_mainnet_launch_config",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Apply the launch config (the one-shot bootstrap) and clear the cooldown, so
/// a test can start from "routine tuning is now in force".
fn bootstrap_and_arm(pic: &PocketIc, pool: Principal) -> GovernanceFeeParams {
    let launch = mainnet_launch_config();
    set_params(pic, pool, &launch).expect("bootstrap with the launch config must succeed");
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();
    launch
}

/// The next routine-tuning candidate: the live params with the epoch cleared,
/// since the canister derives the epoch itself.
fn tuning_base(pic: &PocketIc, pool: Principal) -> GovernanceFeeParams {
    let mut p = live_params(pic, pool);
    p.params_epoch = None;
    p
}

// =============================================================================
// (a) The queryable launch-config check — brief §3 / §1a component 1
// =============================================================================
//
// THREAD-B INTERLOCK, flagged not owned: this query is the canister half of
// P15-002. The other half is the deploy chain — the A7 script that runs
// `set_governance_fee_params` must, in the same script, call
// `fee_params_match_mainnet_launch_config` and FAIL THE DEPLOY on `false`,
// rather than leaving a human to eyeball `get_governance_fee_params`. That
// runbook edit belongs to Thread B (`MAINNET_DEPLOYMENT.md` L97-105) and is
// deliberately NOT duplicated here.

#[test]
fn launch_config_match_query_reports_false_before_and_true_after_the_deploy_step() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    // A fresh pool sits on the fee-free code default, which is NOT the launch
    // config. This is the state P15-002 exists to catch.
    assert!(
        !matches_launch_config(&pic, pool),
        "a fresh pool on launch_defaults() must NOT report as the mainnet launch config"
    );

    set_params(&pic, pool, &mainnet_launch_config()).expect("the deploy step must succeed");

    assert!(
        matches_launch_config(&pic, pool),
        "after the scripted deploy step the live params must match mainnet_launch_config()"
    );
}

/// SSA gate 7: the predicate proves the INITIAL launch config only. It goes
/// false after legitimate tuning, and that is correct behaviour, not a fault —
/// which is why it must not be wired up as a permanent health check.
#[test]
fn launch_config_match_query_is_not_a_permanent_health_predicate() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);
    assert!(matches_launch_config(&pic, pool));

    let mut tuned = tuning_base(&pic, pool);
    // LAUNCH-HARDEN-04 O-6: a legitimate INCREASE is now at most +10% of current
    // (25 bps → 27; 25 × 1000 / 10000 floors to 2).
    tuned.shield_fee_bps = Some(LAUNCH_BPS + 2);
    set_params(&pic, pool, &tuned).expect("a legitimate tuning step must succeed");

    assert!(
        !matches_launch_config(&pic, pool),
        "after legitimate tuning the predicate is false — expected, not a fault"
    );
}

// =============================================================================
// (b) Layer 1 — absolute bounds
// =============================================================================

#[test]
fn bps_above_one_hundred_percent_is_rejected_outright() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    for bps in [10_001u16, 20_000, u16::MAX] {
        let mut params = mainnet_launch_config();
        params.shield_fee_bps = Some(bps);
        let err = set_params(&pic, pool, &params)
            .expect_err(&format!("{bps} bps (>100%) must be rejected"));
        assert!(
            err.contains("BpsAboveOneHundredPercent"),
            "{bps} bps must be named as above 100%, not merely out of range; got {err}"
        );
    }
}

#[test]
fn fee_rates_outside_the_ruled_range_are_rejected() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    // The zeroing case — the whole point of a nonzero floor.
    for bad in [0u16, BPS_CEILING + 1, 10_000] {
        for shield in [true, false] {
            let mut params = mainnet_launch_config();
            if shield {
                params.shield_fee_bps = Some(bad);
            } else {
                params.unshield_fee_bps = Some(bad);
            }
            let err = set_params(&pic, pool, &params)
                .expect_err(&format!("{bad} bps must be rejected (shield={shield})"));
            assert!(
                err.contains("FeeRateOutOfRange") || err.contains("BpsAboveOneHundredPercent"),
                "unexpected error for {bad} bps: {err}"
            );
        }
    }

    // Both ends of the range are INCLUSIVE and must be settable at bootstrap.
    for good in [BPS_FLOOR, BPS_CEILING] {
        let pic = PocketIc::new();
        let pool = setup_pool(&pic);
        let mut params = mainnet_launch_config();
        params.shield_fee_bps = Some(good);
        params.unshield_fee_bps = Some(good);
        set_params(&pic, pool, &params)
            .unwrap_or_else(|e| panic!("{good} bps is inside the ruled range: {e}"));
    }
}

#[test]
fn stsh_denominated_fees_outside_the_ruled_absolute_bounds_are_rejected() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    for bad in [0u128, FLAT_MIN_FLOOR - 1, FLAT_MIN_CEILING + 1] {
        let mut params = mainnet_launch_config();
        params.shield_flat_minimum_fee_e8s = Some(bad);
        let err = set_params(&pic, pool, &params)
            .expect_err(&format!("flat minimum {bad} must be rejected"));
        assert!(err.contains("FeeAmountOutOfRange"), "unexpected error: {err}");
    }

    for bad in [0u128, SPEND_FEE_FLOOR - 1, SPEND_FEE_CEILING + 1] {
        let mut params = mainnet_launch_config();
        params.protocol_private_spend_fee_stsh = bad;
        let err = set_params(&pic, pool, &params)
            .expect_err(&format!("spend fee {bad} must be rejected"));
        assert!(err.contains("FeeAmountOutOfRange"), "unexpected error: {err}");
    }
}

/// The RULING: zeroing is not a routine `set`, and no path in A-1 performs one.
/// Handing the setter the fee-free code default must fail.
#[test]
fn resetting_to_the_fee_free_code_default_is_not_a_reachable_governance_action() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    // launch_defaults() as the caller would have to express it: everything zero.
    let mut zeroing = tuning_base(&pic, pool);
    zeroing.shield_fee_bps = Some(0);
    zeroing.unshield_fee_bps = Some(0);
    zeroing.shield_flat_minimum_fee_e8s = Some(0);
    zeroing.unshield_flat_minimum_fee_e8s = Some(0);
    zeroing.protocol_private_spend_fee_stsh = 0;

    set_params(&pic, pool, &zeroing).expect_err("zeroing must not be a routine governance set");
    assert!(
        matches_launch_config(&pic, pool),
        "the refused zeroing must have left the launch config live"
    );
}

/// The advertised cooldown must be the enforced one — a governance surface that
/// lies about its own rate limit is worse than one without a limit.
#[test]
fn cooldown_field_must_match_the_enforced_constant() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    let mut params = mainnet_launch_config();
    params.fee_update_cooldown_ns = 1;
    let err = set_params(&pic, pool, &params).expect_err("a mismatched cooldown must be rejected");
    assert!(err.contains("FeeUpdateCooldownFieldMismatch"), "unexpected error: {err}");
}

// =============================================================================
// (b) Layer 2 — per-call movement caps
// =============================================================================

/// ABSOLUTE basis points (the fee-policy layer, unchanged).
///
/// LAUNCH-HARDEN-04 O-6: a SEPARATE, tighter layer now bounds INCREASES to
/// +10% of current (`max_fee_change_bps_per_update` must be 1000, and is
/// enforced). The ±100-bps absolute layer runs FIRST and keeps its own error
/// text, so +101 is still refused as `FeeRateChangeTooLarge`; its inclusive
/// edge is now observable only as a DECREASE (an increase of 100 bps from any
/// in-band rate exceeds +10%), so the "exactly at cap" arm moves to −100 from a
/// 125-bps rate planted with the `_test` Wasm's unchecked setter.
#[test]
fn rate_change_cap_is_one_hundred_absolute_basis_points_per_call() {
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());
    bootstrap_and_arm(&pic, pool);

    let mut too_far = tuning_base(&pic, pool);
    too_far.shield_fee_bps = Some(LAUNCH_BPS + MAX_ABS_BPS_CHANGE + 1);
    let err = set_params(&pic, pool, &too_far).expect_err("+101 absolute points must be rejected");
    assert!(err.contains("FeeRateChangeTooLarge"), "unexpected error: {err}");

    // Plant 125 bps (test-only), then clear the cooldown the planting stamped.
    let mut planted = tuning_base(&pic, pool);
    planted.shield_fee_bps = Some(LAUNCH_BPS + MAX_ABS_BPS_CHANGE);
    set_unchecked(&pic, pool, &planted);
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();

    let mut past_cap = tuning_base(&pic, pool);
    past_cap.shield_fee_bps = Some(LAUNCH_BPS - 1); // −101
    let err = set_params(&pic, pool, &past_cap).expect_err("−101 absolute points must be rejected");
    assert!(err.contains("FeeRateChangeTooLarge"), "unexpected error: {err}");
    assert!(!err.contains("FeeChangeExceedsAdvertisedBound"), "the layers are distinct: {err}");

    let mut exactly_at_cap = tuning_base(&pic, pool);
    exactly_at_cap.shield_fee_bps = Some(LAUNCH_BPS); // −100
    set_params(&pic, pool, &exactly_at_cap).expect("−100 absolute points is permitted");
    assert_eq!(live_params(&pic, pool).shield_fee_bps, Some(LAUNCH_BPS));
}

/// The test-only unchecked setter (`_test` Wasm), for planting a live value the
/// routine path cannot reach in one step.
fn set_unchecked(pic: &PocketIc, pool: Principal, params: &GovernanceFeeParams) {
    let r: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        pic.update_call(
            pool,
            p(CONTROLLER),
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    r.expect("unchecked plant");
}

/// Bidirectional `[0.5x, 2x]` on the STSH-denominated fees, and — the L8-F1
/// point — the ratio does NOT license escaping the absolute ceiling.
#[test]
fn stsh_fee_ratio_is_bidirectional_and_still_bounded_absolutely() {
    // The upward half of the bound. It needs headroom BELOW the absolute ceiling
    // to be observable at all — A6.6 moved the launch spend fee to 2.5 STSH, and
    // 2x of that is 5 STSH, exactly the ceiling, so a test bootstrapped at the
    // launch value would have the absolute layer answering for the ratio layer.
    // Bootstrap at 1 STSH instead, where 2 STSH is ratio-legal and comfortably
    // inside the absolute range — the same construction the downward half below
    // has always used, and for the same reason.
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    let mut at_one_up = mainnet_launch_config();
    at_one_up.protocol_private_spend_fee_stsh = E8S;
    set_params(&pic, pool, &at_one_up).expect("bootstrap at 1 STSH is in bounds");
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();

    let mut too_far_up = tuning_base(&pic, pool);
    too_far_up.protocol_private_spend_fee_stsh = 2 * E8S + 1;
    let err = set_params(&pic, pool, &too_far_up).expect_err(">2x must be rejected");
    assert!(err.contains("FeeAmountChangeOutOfRatio"), "unexpected error: {err}");

    // Exactly 2x passes the fee-policy ratio layer — and is now refused by the
    // SEPARATE LAUNCH-HARDEN-04 O-6 increase layer (+10% of current per update),
    // which runs after it; +10% is what the routine path admits upward.
    let mut doubled = tuning_base(&pic, pool);
    doubled.protocol_private_spend_fee_stsh = 2 * E8S;
    let err = set_params(&pic, pool, &doubled).expect_err("2x exceeds the advertised +10% increase bound");
    assert!(err.contains("FeeChangeExceedsAdvertisedBound"), "unexpected error: {err}");
    let mut plus_ten = tuning_base(&pic, pool);
    plus_ten.protocol_private_spend_fee_stsh = E8S + E8S / 10;
    set_params(&pic, pool, &plus_ten).expect("+10% is permitted");

    // The downward half of the bound. It needs headroom above the absolute
    // floor to be observable at all: at a live fee of 0.1 STSH (the floor),
    // every sub-0.5x value is ALSO below the floor, so the absolute layer would
    // fire first and the ratio's lower bound would never be exercised. Bootstrap
    // a separate pool at 1 STSH, where 0.4 STSH is ratio-illegal but comfortably
    // inside the absolute range.
    let pic_down = PocketIc::new();
    let pool_down = setup_pool(&pic_down);
    let mut at_one = mainnet_launch_config();
    at_one.protocol_private_spend_fee_stsh = E8S;
    set_params(&pic_down, pool_down, &at_one).expect("bootstrap at 1 STSH is in bounds");
    pic_down.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic_down.tick();

    let mut too_far_down = tuning_base(&pic_down, pool_down);
    too_far_down.protocol_private_spend_fee_stsh = 4 * E8S / 10; // 0.4 STSH < 0.5x
    let err = set_params(&pic_down, pool_down, &too_far_down).expect_err("<0.5x must be rejected");
    assert!(err.contains("FeeAmountChangeOutOfRatio"), "unexpected error: {err}");

    // Exactly 0.5x is permitted — the bound is inclusive on both sides.
    let mut halved = tuning_base(&pic_down, pool_down);
    halved.protocol_private_spend_fee_stsh = E8S / 2;
    set_params(&pic_down, pool_down, &halved).expect("exactly 0.5x is permitted");

    // The absolute ceiling still binds a ratio-legal move: from the 5,000 STSH
    // ceiling a 2x step is arithmetically legal and must still be refused.
    let pic2 = PocketIc::new();
    let pool2 = setup_pool_with(&pic2, pool_wasm());
    let mut at_ceiling = mainnet_launch_config();
    at_ceiling.shield_flat_minimum_fee_e8s = Some(FLAT_MIN_CEILING);
    at_ceiling.unshield_flat_minimum_fee_e8s = Some(FLAT_MIN_CEILING);
    set_params(&pic2, pool2, &at_ceiling).expect("bootstrapping at the ceiling is in bounds");
    pic2.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic2.tick();

    let mut over = tuning_base(&pic2, pool2);
    over.shield_flat_minimum_fee_e8s = Some(FLAT_MIN_CEILING * 2);
    let err = set_params(&pic2, pool2, &over)
        .expect_err("a 2x step out of the absolute ceiling must be refused");
    assert!(
        err.contains("FeeAmountOutOfRange"),
        "the ABSOLUTE bound must be what stops it, not the ratio; got {err}"
    );
}

// =============================================================================
// (b) Layer 3 — the canister-owned cooldown, and the bootstrap exemption
// =============================================================================

#[test]
fn routine_tuning_is_rate_limited_to_one_call_per_twenty_four_hours() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    let mut first = tuning_base(&pic, pool);
    // LAUNCH-HARDEN-04 O-6: routine increases are ≤ +10% of current (25 → 27).
    first.shield_fee_bps = Some(LAUNCH_BPS + 2);
    set_params(&pic, pool, &first).expect("the first tuning call after the cooldown must succeed");

    // Just short of the window. Not literally one nanosecond short: PocketIC
    // also advances its clock per round, so a 1 ns margin is smaller than the
    // harness's own granularity and would flake.
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS - 1_000_000_000));
    pic.tick();
    let mut second = tuning_base(&pic, pool);
    second.shield_fee_bps = Some(LAUNCH_BPS + 4); // 27 → 29, within +10%
    let err = set_params(&pic, pool, &second).expect_err("inside the window must be rejected");
    assert!(err.contains("FeeUpdateCooldownActive"), "unexpected error: {err}");

    // Crossing it opens the window again.
    pic.advance_time(Duration::from_nanos(1_000_000_000));
    pic.tick();
    set_params(&pic, pool, &second).expect("past the window the same call must succeed");
}

/// The bootstrap exemption exists because the zero -> launch move is exactly
/// what the per-call cap forbids. It is ONE-SHOT: once activated it is closed
/// permanently, and the very next call is fully guarded.
#[test]
fn bootstrap_is_exempt_once_and_then_permanently_closed() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    let before = fee_gov_state(&pic, pool);
    assert!(!before.launch_fee_activated, "a fresh pool has not bootstrapped");
    assert_eq!(before.params_epoch, 0);
    assert_eq!(before.last_fee_update_ns, 0);
    assert_eq!(before.fee_update_cooldown_ns, COOLDOWN_NS);

    // 0 -> 25 bps and 0 -> 1,000 STSH would both blow the per-call caps many
    // times over. Bootstrap accepts it anyway.
    set_params(&pic, pool, &mainnet_launch_config()).expect("bootstrap must succeed");

    let after = fee_gov_state(&pic, pool);
    assert!(after.launch_fee_activated, "the marker is set by the first accepted set");
    assert_eq!(after.params_epoch, 1, "the canister stamps epoch 1");
    assert!(after.last_fee_update_ns > 0, "the cooldown clock is armed");

    // The exemption is now closed: an immediate second call is refused by the
    // cooldown even though it is otherwise a perfectly legal tuning step.
    let mut small = tuning_base(&pic, pool);
    small.shield_fee_bps = Some(LAUNCH_BPS + 1);
    let err = set_params(&pic, pool, &small)
        .expect_err("the bootstrap exemption must not survive its own use");
    assert!(err.contains("FeeUpdateCooldownActive"), "unexpected error: {err}");

    // And once past the cooldown, the CHANGE CAP applies too — proving the
    // exemption did not merely expire from the clock.
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();
    let mut huge = tuning_base(&pic, pool);
    huge.shield_fee_bps = Some(BPS_CEILING); // 25 -> 500 = 475 points
    let err = set_params(&pic, pool, &huge)
        .expect_err("a bootstrap-sized move must be refused once activated");
    assert!(err.contains("FeeRateChangeTooLarge"), "unexpected error: {err}");
}

// =============================================================================
// (b) Layer 4 — the epoch is the canister's, not the caller's
// =============================================================================

#[test]
fn caller_cannot_choose_the_stored_epoch() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    // A stale, a skipped, and a wildly-ahead epoch are all refused.
    for supplied in [0u64, 2, 99, u64::MAX] {
        let mut params = mainnet_launch_config();
        params.params_epoch = Some(supplied);
        let err = set_params(&pic, pool, &params)
            .expect_err(&format!("caller-selected epoch {supplied} must be refused"));
        assert!(err.contains("InvalidParamsEpoch"), "unexpected error: {err}");
    }

    // Omitting it entirely is fine — the canister supplies its own.
    let mut params = mainnet_launch_config();
    params.params_epoch = None;
    set_params(&pic, pool, &params).expect("an omitted epoch is filled in by the canister");
    assert_eq!(live_params(&pic, pool).params_epoch, Some(1));
    assert_eq!(fee_gov_state(&pic, pool).params_epoch, 1);

    // And it advances monotonically, by one, per accepted call.
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();
    let mut next = tuning_base(&pic, pool);
    next.shield_fee_bps = Some(LAUNCH_BPS + 1);
    set_params(&pic, pool, &next).expect("routine tuning must succeed");
    assert_eq!(live_params(&pic, pool).params_epoch, Some(2));
    assert_eq!(fee_gov_state(&pic, pool).params_epoch, 2);
}

// =============================================================================
// (b) Layer 5 — ATOMICITY of a rejected update (SSA fold v3)
// =============================================================================
//
// The gate is explicit: a rejected update changes NEITHER the fee params, NOR
// the epoch, NOR the cooldown timestamp, NOR the activation marker. All four
// are checked, for a rejection arising from EACH guardrail layer — a rejection
// that fires late (after some field had already been written) would be exactly
// the bug this asserts against.

#[test]
fn a_rejected_update_mutates_nothing() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);

    let params_before = live_params(&pic, pool);
    let state_before = fee_gov_state(&pic, pool);

    // One rejection per layer, plus the pre-existing split invariant.
    let mut bad_split = tuning_base(&pic, pool);
    bad_split.operations_split_bps = 9_000; // sum != 10 000

    let mut bad_bounds = tuning_base(&pic, pool);
    bad_bounds.shield_fee_bps = Some(0);

    let mut bad_over_100 = tuning_base(&pic, pool);
    bad_over_100.unshield_fee_bps = Some(50_000);

    let mut bad_change = tuning_base(&pic, pool);
    bad_change.shield_fee_bps = Some(BPS_CEILING);

    let mut bad_ratio = tuning_base(&pic, pool);
    // A6.6: the live spend fee is now 2.5 STSH, so the old choice here
    // (SPEND_FEE_CEILING = 5 STSH) became EXACTLY 2x — ratio-LEGAL, and this row
    // stopped testing the ratio layer at all. 1 STSH is 0.4x, which is
    // ratio-illegal while staying comfortably inside the absolute band
    // [0.1, 5] STSH, so the rejection is still attributable to the ratio layer
    // rather than to the absolute one answering for it.
    bad_ratio.protocol_private_spend_fee_stsh = E8S;

    let mut bad_epoch = tuning_base(&pic, pool);
    bad_epoch.params_epoch = Some(42);

    let mut bad_cooldown_field = tuning_base(&pic, pool);
    bad_cooldown_field.fee_update_cooldown_ns = 7;

    for (label, candidate) in [
        ("split", bad_split),
        ("absolute bounds", bad_bounds),
        ("above 100%", bad_over_100),
        ("change cap", bad_change),
        ("ratio", bad_ratio),
        ("epoch", bad_epoch),
        ("cooldown field", bad_cooldown_field),
    ] {
        set_params(&pic, pool, &candidate)
            .unwrap_err_or_else_panic(&format!("the {label} rejection must be an Err"));

        assert_eq!(
            live_params(&pic, pool),
            params_before,
            "{label}: a rejected update must not change the fee parameters"
        );
        let now = fee_gov_state(&pic, pool);
        assert_eq!(
            now.params_epoch, state_before.params_epoch,
            "{label}: a rejected update must not bump the epoch"
        );
        assert_eq!(
            now.last_fee_update_ns, state_before.last_fee_update_ns,
            "{label}: a rejected update must not move the cooldown clock"
        );
        assert_eq!(
            now.launch_fee_activated, state_before.launch_fee_activated,
            "{label}: a rejected update must not touch the activation marker"
        );
    }

    // The rejections must not have consumed the cooldown either: a legitimate
    // call still succeeds immediately afterwards.
    let mut good = tuning_base(&pic, pool);
    good.shield_fee_bps = Some(LAUNCH_BPS + 1);
    set_params(&pic, pool, &good)
        .expect("a valid call after a run of rejections must still succeed");
}

/// A rejected update on a FRESH pool must leave the bootstrap exemption intact —
/// a failed first attempt must not silently spend the one-shot.
#[test]
fn a_rejected_bootstrap_does_not_consume_the_one_shot() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    let mut bad = mainnet_launch_config();
    bad.shield_flat_minimum_fee_e8s = Some(0);
    set_params(&pic, pool, &bad).expect_err("an out-of-bounds bootstrap must be rejected");

    let state = fee_gov_state(&pic, pool);
    assert!(!state.launch_fee_activated, "the one-shot must be untouched");
    assert_eq!(state.params_epoch, 0);
    assert_eq!(state.last_fee_update_ns, 0);

    // The real bootstrap still works, exemption and all.
    set_params(&pic, pool, &mainnet_launch_config())
        .expect("the retry must still be treated as the bootstrap");
    assert!(fee_gov_state(&pic, pool).launch_fee_activated);
}

// =============================================================================
// Authorisation — unchanged, but the guardrails must not have widened it
// =============================================================================

#[test]
fn non_controller_cannot_set_fee_params() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);

    let res = pic.update_call(
        pool,
        p(0xEE),
        "set_governance_fee_params",
        candid::encode_one(mainnet_launch_config()).unwrap(),
    );
    assert!(res.is_err(), "a non-controller call must be rejected at the boundary");
    assert!(!fee_gov_state(&pic, pool).launch_fee_activated);
}

// =============================================================================
// Durability — the eager cell (MemoryId 18) and the fail-closed sentinel
// =============================================================================
//
// The cell is the authority for a security-relevant clock. If it were lost on
// upgrade, the cooldown would reset to zero AND the bootstrap exemption would
// reopen — handing the next call an immediate, change-cap-exempt fee set. That
// is precisely the vulnerability this lane closes, so `post_upgrade` traps on
// an absent or corrupt region rather than resuming on defaults.
//
// These use the `_test` Wasm for `eager_cell_probe_for_test`, which exposes the
// RAW encoded bytes so persistence is asserted against the DURABLE layout
// rather than inferred from a downstream getter.

fn probe(pic: &PocketIc, pool: Principal) -> Vec<u8> {
    decode(
        "eager_cell_probe_for_test",
        pic.query_call(
            pool,
            p(CONTROLLER),
            "eager_cell_probe_for_test",
            candid::encode_one("fee_governance".to_string()).unwrap(),
        ),
    )
}

#[test]
fn fee_governance_cell_is_written_at_init_and_is_not_the_sentinel() {
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());

    let bytes = probe(&pic, pool);
    // Scalars<3>: 1 version byte + 3 * 16-byte big-endian words.
    assert_eq!(bytes.len(), 1 + 3 * 16, "the Scalars<3> layout width is fixed");
    assert!(
        !bytes.iter().all(|b| *b == 0xFF),
        "init must clear the all-0xFF sentinel — otherwise post_upgrade would trap on a \
         canister that was in fact initialised"
    );
    assert_eq!(bytes[0], 1, "layout version byte is pinned");
    assert!(
        bytes[1..].iter().all(|b| *b == 0),
        "a fresh pool is [0, 0, 0]: no update, epoch 0, not activated"
    );
}

#[test]
fn fee_governance_state_survives_an_upgrade_byte_exactly() {
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());

    set_params(&pic, pool, &mainnet_launch_config()).expect("bootstrap must succeed");
    pic.advance_time(Duration::from_nanos(COOLDOWN_NS));
    pic.tick();
    let mut tuned = tuning_base(&pic, pool);
    tuned.shield_fee_bps = Some(LAUNCH_BPS + 2); // O-6: ≤ +10% of current
    set_params(&pic, pool, &tuned).expect("tuning must succeed");

    let bytes_before = probe(&pic, pool);
    let state_before = fee_gov_state(&pic, pool);
    assert_eq!(state_before.params_epoch, 2);
    assert!(state_before.launch_fee_activated);

    pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade must succeed");

    assert_eq!(probe(&pic, pool), bytes_before, "the durable bytes are unchanged");
    assert_eq!(
        fee_gov_state(&pic, pool),
        state_before,
        "the cooldown clock, epoch and activation marker all survive the upgrade"
    );

    // The restored clock is real, not a zeroed default: the cooldown is still
    // in force immediately after the upgrade.
    let mut next = tuning_base(&pic, pool);
    next.shield_fee_bps = Some(LAUNCH_BPS + 3); // within +10% of 27
    let err = set_params(&pic, pool, &next)
        .expect_err("the cooldown must still be in force across an upgrade");
    assert!(err.contains("FeeUpdateCooldownActive"), "unexpected error: {err}");
}

// =============================================================================
// LAUNCH-HARDEN-04 O-6 — the advertised +10% INCREASE bound, on the PRODUCTION
// Wasm (the native arms in the pool crate cover the full matrix)
// =============================================================================

#[test]
fn o6_plus_ten_percent_increase_is_accepted() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);
    let mut up = tuning_base(&pic, pool);
    assert_eq!(up.protocol_private_spend_fee_stsh, LAUNCH_SPEND_FEE);
    up.protocol_private_spend_fee_stsh = 275_000_000;
    set_params(&pic, pool, &up).expect("+10% exactly (2.5 → 2.75 STSH) is accepted");
    assert_eq!(live_params(&pic, pool).protocol_private_spend_fee_stsh, 275_000_000);
}

#[test]
fn o6_plus_ten_percent_plus_one_e8s_is_refused() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);
    let mut up = tuning_base(&pic, pool);
    up.protocol_private_spend_fee_stsh = 275_000_001;
    let err = set_params(&pic, pool, &up).expect_err("+10% + 1 e8s is refused");
    assert!(err.contains("FeeChangeExceedsAdvertisedBound"), "unexpected error: {err}");
    assert!(err.contains("protocol_private_spend_fee_stsh"), "unexpected error: {err}");
    assert_eq!(live_params(&pic, pool).protocol_private_spend_fee_stsh, LAUNCH_SPEND_FEE);
}

#[test]
fn o6_minus_twenty_percent_decrease_is_accepted() {
    let pic = PocketIc::new();
    let pool = setup_pool(&pic);
    bootstrap_and_arm(&pic, pool);
    let mut down = tuning_base(&pic, pool);
    down.protocol_private_spend_fee_stsh = 200_000_000;
    set_params(&pic, pool, &down).expect("−20% passes the increase-only layer and the ÷2 layer");
    assert_eq!(live_params(&pic, pool).protocol_private_spend_fee_stsh, 200_000_000);
}

// ── Small ergonomics helper ───────────────────────────────────────────────────

trait UnwrapErrOrPanic {
    fn unwrap_err_or_else_panic(self, msg: &str);
}

impl UnwrapErrOrPanic for Result<(), String> {
    fn unwrap_err_or_else_panic(self, msg: &str) {
        if self.is_ok() {
            panic!("{msg}");
        }
    }
}


// =============================================================================
// The sentinel is UNCONDITIONAL — SSA HOLD on 0e1b4f2, closed by Fix A
// =============================================================================
//
// 0e1b4f2 shipped a two-armed sentinel: an absent fee-governance region either
// TRAPPED (if a checkpoint marker said the cell had been live) or took a
// "conservative" one-time MIGRATION (if it said the pool predated A-1). SSA
// broke it, and the break is structural rather than a coding slip:
//
//   `post_upgrade` decoded the checkpoint as V2 and, on ANY decode error, fell
//   back to the narrower frozen V1 shape. Candid record-width subtyping means
//   the V1 decoder ACCEPTS blobs the V2 decoder rejects — so corrupting the
//   wire type of a field that exists only in V2 makes a CURRENT checkpoint
//   present as a genuine historical one. The fallback then discarded the
//   governance parameters it had failed to decode and substituted
//   `launch_defaults()` (every protocol fee zero), set the marker to `None`,
//   and — with region 18 also lost — selected the migration arm and persisted
//   `epoch 0` + `launch_fee_activated = false`, REOPENING the one-shot
//   bootstrap exemption.
//
// "Never more permissive than the truth" was true of the migration's arithmetic
// and false of the system, because the truth had already been thrown away one
// step earlier.
//
// Fix A (RULED by Owner/CTO 2026-08-01): the pre-A1 boundary is a REINSTALL
// boundary. A V2 decode failure traps, there is no legacy fallback, and there
// is no migration arm for the compound to select.
//
// These tests use the `_test` Wasm for the corruption hooks — planting a
// hostile checkpoint and dropping a stable region are not otherwise reachable
// from outside the canister, and paraphrasing the counterexample would prove
// nothing.

fn settle_install_budget(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
}

/// A checkpoint mirror whose ONLY deviation from the real `PoolStableState` is
/// the wire type of `governance_fee_params` — a field that exists in V2 and NOT
/// in the frozen V1 shape.
///
/// That single change is the whole counterexample. Candid identifies fields by
/// hashed name, so the V2 decoder finds `governance_fee_params` with the wrong
/// type and fails; the V1 decoder has no such field, ignores it under
/// record-width subtyping, and succeeds. Before Fix A that divergence was
/// enough to reclassify a corrupted current checkpoint as a genuine legacy one.
///
/// WHY THIS FIELD AND NOT `verifier_canister`: the other V2-only field is an
/// `opt`, and Candid's opt-subtyping rule decodes a type-mismatched `opt` as
/// `null` INSTEAD of failing. Corrupting it does not produce a decode error at
/// all. Only a NON-optional V2-only field yields the hard V2 failure the
/// counterexample needs — which narrows the exploitable surface but does not
/// remove it, and is worth knowing when reasoning about future schema additions.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct CorruptCheckpoint {
    state_version: u32,
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
    pinned_circuit_version: u32,
    pinned_pool_version: u32,
    pinned_vk_hash: [u8; 32],
    pinned_proof_system: String,
    pending_vk_hash: Option<[u8; 32]>,
    pending_vk_version: Option<u32>,
    pending_vk_active_at: Option<u64>,
    old_vk_cutoff_at: Option<u64>,
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    deposits_paused: bool,
    spends_paused: bool,
    next_withdrawal_id: u64,
    verifier_canister: Option<Principal>,
    /// THE CORRUPTION: `GovernanceFeeParams` (a non-optional record) in the
    /// real struct. A wrong type here is a HARD V2 decode failure.
    governance_fee_params: u64,
    treasury_notification_failures: Option<u64>,
}

fn corrupt_checkpoint_bytes() -> Vec<u8> {
    candid::encode_one(CorruptCheckpoint {
        state_version: 2,
        private_liability: 0,
        escrow_backing: 0,
        operations_reserve: 0,
        insurance_reserve: 0,
        governance_rewards_reserve: 0,
        pending_fee_reimbursements: 0,
        pinned_circuit_version: 0,
        pinned_pool_version: 1,
        pinned_vk_hash: [0u8; 32],
        pinned_proof_system: "groth16-bn254".to_string(),
        pending_vk_hash: None,
        pending_vk_version: None,
        pending_vk_active_at: None,
        old_vk_cutoff_at: None,
        token_canister: p(0x10),
        nullifier_canister: p(0x11),
        merkle_canister: p(0x12),
        treasury_canister: p(0x04),
        staking_canister: p(0x02),
        controller: p(CONTROLLER),
        deposits_paused: false,
        spends_paused: false,
        next_withdrawal_id: 1,
        verifier_canister: None,
        governance_fee_params: 7, // wrong wire type — V2 fails hard, V1 ignores

        treasury_notification_failures: Some(0),
    })
    .unwrap()
}

fn plant(pic: &PocketIc, pool: Principal, bytes: Vec<u8>) {
    let _: () = decode(
        "plant_corrupt_checkpoint_for_test",
        pic.update_call(
            pool,
            p(CONTROLLER),
            "plant_corrupt_checkpoint_for_test",
            candid::encode_one(bytes).unwrap(),
        ),
    );
}

fn drop_region_18(pic: &PocketIc, pool: Principal) {
    let _: () = decode(
        "drop_fee_governance_region_for_test",
        pic.update_call(
            pool,
            p(CONTROLLER),
            "drop_fee_governance_region_for_test",
            candid::encode_args(()).unwrap(),
        ),
    );
}

/// **The SSA counterexample, built exactly.** V2 decode fails, V1 decode would
/// have succeeded, region 18 is gone. It must TRAP — not migrate, not reopen
/// the bootstrap, not zero the fees.
#[test]
fn ssa_counterexample_v2_fail_v1_pass_with_region_18_lost_must_trap() {
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());

    // A pool in the state worth stealing: launch fees live, bootstrap spent.
    set_params(&pic, pool, &mainnet_launch_config()).expect("bootstrap must succeed");
    let live_before = live_params(&pic, pool);
    let state_before = fee_gov_state(&pic, pool);
    assert!(state_before.launch_fee_activated);
    assert_eq!(state_before.params_epoch, 1);

    // Both halves of the compound.
    plant(&pic, pool, corrupt_checkpoint_bytes());
    drop_region_18(&pic, pool);

    settle_install_budget(&pic);
    let r = pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(
        r.is_err(),
        "a checkpoint that fails V2 decode must TRAP, never be reclassified as legacy V1; \
         got {:?}",
        r
    );
    let msg = format!("{:?}", r.unwrap_err());
    assert!(
        msg.contains("Candid decode of PoolStableState failed"),
        "the trap must come from the decode, i.e. BEFORE anything can be manufactured \
         from the ambiguous blob; got {msg}"
    );

    // The upgrade rolled back, so the pool is still on the previous Wasm with
    // everything intact. These are the three things the fail-open would have
    // destroyed, asserted individually.
    assert_eq!(
        live_params(&pic, pool),
        live_before,
        "fees must NOT have been replaced by launch_defaults()"
    );
    assert!(
        !matches_launch_config(&pic, pool) || live_params(&pic, pool) == live_before,
        "the live params are unchanged"
    );
    let state_after = fee_gov_state(&pic, pool);
    assert!(
        state_after.launch_fee_activated,
        "the one-shot bootstrap exemption must NOT have reopened"
    );
    assert_eq!(state_after.params_epoch, 1, "the epoch must NOT have been reset to 0");

    // The clincher. Asserting on the cooldown here would prove nothing —
    // `settle_install_budget` advances the clock by seven days, so the window
    // has legitimately expired. What DOES distinguish the two worlds is the
    // per-call change cap: it applies only to routine tuning, and a reopened
    // bootstrap would waive it. So attempt a bootstrap-sized move (25 -> 500
    // bps, 475 absolute points) and require the cap to refuse it.
    let mut bootstrap_sized = tuning_base(&pic, pool);
    bootstrap_sized.shield_fee_bps = Some(BPS_CEILING);
    let err = set_params(&pic, pool, &bootstrap_sized)
        .expect_err("a bootstrap-sized move must be refused — the exemption must stay spent");
    assert!(
        err.contains("FeeRateChangeTooLarge"),
        "the CHANGE CAP must be what refuses it; a cooldown error here would mean the \
         bootstrap exemption had reopened. got {err}"
    );

    // And the fees themselves are still un-zeroable.
    let mut zeroing = tuning_base(&pic, pool);
    zeroing.shield_fee_bps = Some(0);
    zeroing.unshield_fee_bps = Some(0);
    zeroing.shield_flat_minimum_fee_e8s = Some(0);
    zeroing.unshield_flat_minimum_fee_e8s = Some(0);
    zeroing.protocol_private_spend_fee_stsh = 0;
    set_params(&pic, pool, &zeroing)
        .expect_err("zeroing must still be unreachable after the refused upgrade");
}

/// The decode arm alone: a corrupt checkpoint traps even with region 18 fully
/// intact. Proves the trap is the DECODE failing closed, not the sentinel
/// picking up the slack.
#[test]
fn corrupt_checkpoint_traps_even_with_the_eager_region_intact() {
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());
    set_params(&pic, pool, &mainnet_launch_config()).expect("bootstrap must succeed");
    let live_before = live_params(&pic, pool);

    plant(&pic, pool, corrupt_checkpoint_bytes());
    // region 18 deliberately NOT dropped.

    settle_install_budget(&pic);
    let r = pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(r.is_err(), "a corrupt checkpoint must trap on its own; got {:?}", r);
    assert!(
        format!("{:?}", r.unwrap_err()).contains("Candid decode of PoolStableState failed"),
        "the decode must be what refuses it"
    );
    assert_eq!(live_params(&pic, pool), live_before, "params intact after the refusal");
}

/// The sentinel arm alone, now UNCONDITIONAL: a lost region 18 traps even
/// though the checkpoint is perfectly valid. Under 0e1b4f2 the outcome here
/// depended on a marker inside that same checkpoint; it no longer does.
#[test]
fn lost_eager_region_traps_unconditionally_with_a_valid_checkpoint() {
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, pool_test_wasm());
    set_params(&pic, pool, &mainnet_launch_config()).expect("bootstrap must succeed");
    let state_before = fee_gov_state(&pic, pool);

    drop_region_18(&pic, pool);

    settle_install_budget(&pic);
    let r = pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(r.is_err(), "a lost fee-governance region must trap; got {:?}", r);
    assert!(
        format!("{:?}", r.unwrap_err()).contains("FEE_GOVERNANCE sentinel survived"),
        "the sentinel must be what refuses it"
    );
    assert_eq!(fee_gov_state(&pic, pool), state_before, "state intact after the refusal");
}

/// A genuinely pre-A1 pool is now REFUSED, not migrated — the ruling made
/// explicit and pinned. Recovery is reinstall.
#[test]
fn pre_a1_pool_upgrade_is_refused_because_the_boundary_is_a_reinstall() {
    let Some(v1) = pool_pre_a1_wasm() else {
        eprintln!("skipping: pre-A1 pool Wasm artifact not present");
        return;
    };
    let pic = PocketIc::new();
    let pool = setup_pool_with(&pic, v1);

    settle_install_budget(&pic);
    let r = pic.upgrade_canister(pool, pool_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(
        r.is_err(),
        "the pre-A1 boundary must be refused — it is a reinstall boundary, not an upgrade \
         boundary; got {:?}",
        r
    );
}

/// The pre-P-ROOT (P-REC v1, `20a6fb3`) pool TEST Wasm — the same gate
/// prerequisite `prec_recovery_index_tests` requires, and the only in-tree Wasm
/// that genuinely predates the A-1 eager cell.
fn pool_pre_a1_wasm() -> Option<Vec<u8>> {
    let path = std::path::PathBuf::from(env!("POOL_WASM"))
        .parent()?
        .join("shielded_pool_prec_v1_test.wasm");
    std::fs::read(path).ok()
}
