// =============================================================================
// STSH — P-ARITH GTM Arithmetic Hardening regression suite
// BRIEF_GTM_ARITHMETIC_HARDENING.md V1.5 (K3-002a / K3-002b / K3-003)
// =============================================================================
//
// RED→GREEN discipline (§2): these tests assert the FIXED behavior on the
// RELEASE Wasm via PocketIC. Run against the pinned PARENT release Wasm they
// fail at exactly the assertions that demonstrate the defect (genesis accepts
// a wrapping manifest; the invariant reports healthy off a wrapped fold) —
// that failing run is the recorded RED evidence; this suite green at head is
// the GREEN. A debug unit test panicking on overflow proves nothing about the
// shipped binary, hence release-Wasm PocketIC here.
//
// T-1  genesis validation checked sums     (wrapping manifest → typed reject)
// T-2  invariant checked folds + EXACT additive arithmetic_error contract
//      (+ legacy-decoder compatibility on the additive field)
// V-1  vesting schedule-init exact validation (cap / zero rules / duplicate
//      beneficiary typed reject / no wrapped timestamps)
//
// PREREQUISITES:
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing
//   cp target/.../stsh_token.wasm target/.../stsh_token_test.wasm   (Law #7 phase 1)
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token -p vesting
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test arith_hardening_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use ic_management_canister_types::{CanisterInstallMode, InstallCodeArgs};
use pocket_ic::common::rest::RawEffectivePrincipal;
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loaders ──────────────────────────────────────────────────────────────

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read stsh_token Wasm at {}: {}", path, e))
}

/// Token built with `--features testing` — exposes debug_credit_balance_for_test
/// (token/lib.rs:1079), the §2-pinned seeding endpoint for the invariant RED.
fn token_test_wasm() -> Vec<u8> {
    let path = env!("TOKEN_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token TEST Wasm at {}: {}.\nLaw #7 phase 1 first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing\n  \
             cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
             target/wasm32-unknown-unknown/release/stsh_token_test.wasm",
            path, e
        )
    })
}

fn vesting_wasm() -> Vec<u8> {
    let path = env!("VESTING_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read vesting Wasm at {}: {}", path, e))
}

// ── Constants — must match canisters/token + canisters/vesting ───────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 10^17 base units
const NS_PER_MONTH: u64 = 30 * 24 * 60 * 60 * 1_000_000_000;
const MAX_SCHEDULE_MONTHS: u32 = 480;

// ── Wire-type mirrors ────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy {
    cliff_end_ns: u64,
    vesting_end_ns: u64,
}

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
    fee_collector: Option<Principal>,
}

/// CURRENT report shape (T-2): includes the additive arithmetic_error field.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SupplyInvariantReport {
    fixed_max_supply: u128,
    sum_all_balances: u128,
    staking_locked_total: u128,
    fee_reserve_total: u128,
    invariant_holds: bool,
    checked_at_ns: u64,
    violation_detail: Option<String>,
    arithmetic_error: Option<ArithmeticErrorReport>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ArithmeticErrorReport {
    balances_overflow: bool,
    staking_locks_overflow: bool,
    balances_plus_fee_overflow: bool,
}

/// PRE-P-ARITH report shape — exactly what an old, not-yet-updated consumer
/// decodes with. The T-2 compatibility contract: the additive opt field must
/// be safely ignored by this decoder.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct LegacySupplyInvariantReport {
    fixed_max_supply: u128,
    sum_all_balances: u128,
    staking_locked_total: u128,
    fee_reserve_total: u128,
    invariant_holds: bool,
    checked_at_ns: u64,
    violation_detail: Option<String>,
}

#[derive(CandidType, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal,
    controller: Principal,
    schedules: Vec<NewSchedule>,
}

#[derive(CandidType, Deserialize, Clone)]
struct NewSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_months: u32,
    linear_months: u32,
}

/// Mirror of the vesting canister's stored VestingSchedule (get_schedule).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_end_ns: u64,
    vesting_end_ns: u64,
    claimed: u128,
    start_ns: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}

fn alloc(id: &str, amount: u128, recipient: Principal) -> AllocationCategory {
    AllocationCategory {
        category_id: id.to_string(),
        category_name: format!("Cat {}", id),
        amount,
        recipient,
        subaccount: None,
        lock_policy: LockPolicy::GovernanceLocked,
        vesting_policy: None,
        created_at_genesis: false,
        genesis_timestamp_ns: 0,
    }
}

fn token_init(allocations: Vec<AllocationCategory>) -> Vec<u8> {
    candid::encode_one(&TokenInitArgs {
        allocations,
        treasury: p(0x01),
        staking_canister: p(0x02),
        fee_collector: Some(p(0xF1)),
    })
    .unwrap()
}

fn vesting_init(schedules: Vec<NewSchedule>) -> Vec<u8> {
    candid::encode_one(&VestingInitArgs {
        token_canister: p(0x03),
        controller: p(0x04),
        schedules,
    })
    .unwrap()
}

/// Raw management-canister fresh install — unlike `pic.install_canister` this
/// RETURNS the rejection, so a trapped init (typed validation failure) is a
/// clean assertable Err. Fresh canister per attempt (install_code rate limit).
fn try_install(pic: &PocketIc, wasm: Vec<u8>, arg: Vec<u8>) -> Result<Principal, String> {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 10_000_000_000_000);
    let args = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: cid,
        wasm_module: wasm,
        arg,
        sender_canister_version: None,
    };
    pic.update_call_with_effective_principal(
        Principal::management_canister(),
        RawEffectivePrincipal::CanisterId(cid.as_slice().to_vec()),
        anon(), // controller
        "install_code",
        candid::encode_one(&args).unwrap(),
    )
    .map(|_| cid)
    .map_err(|e| format!("{:?}", e))
}

fn supply_report(pic: &PocketIc, cid: Principal) -> SupplyInvariantReport {
    let bytes = pic
        .query_call(cid, anon(), "verify_supply_invariant", candid::encode_args(()).unwrap())
        .expect("verify_supply_invariant query");
    candid::decode_one(&bytes).unwrap()
}

fn debug_credit(pic: &PocketIc, cid: Principal, owner: Principal, amount: u128) {
    let account = Account { owner, subaccount: None };
    pic.update_call(
        cid,
        anon(),
        "debug_credit_balance_for_test",
        candid::encode_args((account, amount)).unwrap(),
    )
    .expect("debug_credit_balance_for_test");
}

fn get_schedule(pic: &PocketIc, cid: Principal, beneficiary: Principal) -> Option<VestingSchedule> {
    let bytes = pic
        .query_call(cid, anon(), "get_schedule", candid::encode_one(beneficiary).unwrap())
        .expect("get_schedule query");
    candid::decode_one(&bytes).unwrap()
}

// =============================================================================
// T-1 — genesis validation checked sums (K3-002a)
// =============================================================================

/// The §2-pinned RED manifest: u128::MAX + (TOTAL_SUPPLY + 1) ≡ TOTAL_SUPPLY
/// (mod 2^128). Distinct recipients so no per-account credit traps — on the
/// parent Wasm this install SUCCEEDS (RED); fixed it is a typed reject (GREEN).
#[test]
fn test_t1_wrapping_genesis_manifest_rejected_typed() {
    let pic = PocketIc::new();
    let wrapping = vec![
        alloc("wrap_a", u128::MAX, p(0x11)),
        alloc("wrap_b", TOTAL_SUPPLY + 1, p(0x12)),
    ];
    let err = try_install(&pic, token_wasm(), token_init(wrapping))
        .expect_err("RED-CLASS DEFECT: wrapping genesis manifest was ACCEPTED (K3-002a)");
    assert!(
        err.contains("overflows u128"),
        "rejection must be the typed overflow message, got: {}",
        err
    );

    // Control: the honest manifest still installs.
    try_install(&pic, token_wasm(), token_init(vec![alloc("genesis", TOTAL_SUPPLY, p(0x11))]))
        .expect("valid manifest must install");
}

// =============================================================================
// T-2 — invariant reporting can never wrap to healthy (K3-002b)
// =============================================================================

/// R-1 EXPLAINED DELTA (brief §3 S4(d), pre-declared).
///
/// WAS: seed balances whose MATHEMATICAL sum is u128::MAX + TOTAL_SUPPLY + 1 and
///      assert the invariant FOLD reports a typed `balances_overflow` instead of
///      wrapping to healthy. That fold was the public path.
///
/// NOW: R-1 removed the fold from the public path (the totals are MAINTAINED),
///      and moved the arithmetic refusal EARLIER, to write time: the injection
///      itself cannot be represented by SUM_BALANCES, so `write_balance` TRAPS.
///      The K3-002b property this test exists for — "a wrapped total can never
///      land back on TOTAL_SUPPLY and read as healthy" — is now enforced by
///      construction rather than by attribution after the fact, and the test
///      asserts the write-time refusal that replaced it.
///
/// This is a REWRITE, not a deletion: the seeded values, the ordering, and the
/// K3-002b claim are unchanged; only the observable the claim is asserted
/// through moved from a report field to a trap.
#[test]
fn test_t2_wrapped_balance_fold_reports_arithmetic_error_not_healthy() {
    let pic = PocketIc::new();
    let cid = try_install(
        &pic,
        token_test_wasm(),
        token_init(vec![alloc("genesis", TOTAL_SUPPLY, p(0x11))]),
    )
    .expect("install test-feature token");

    // First injection: TOTAL_SUPPLY + u128::MAX is not representable either, so
    // the very first credit is already the refusal — assert on it directly.
    let account = Account { owner: p(0xE1), subaccount: None };
    let err = pic
        .update_call(
            cid,
            anon(),
            "debug_credit_balance_for_test",
            candid::encode_args((account, u128::MAX)).unwrap(),
        )
        .expect_err(
            "RED-CLASS DEFECT: an unrepresentable balance credit was ACCEPTED              (K3-002b, now enforced at write time by R-1)",
        );
    let text = format!("{:?}", err);
    assert!(
        text.contains("SUM_BALANCES: running total cannot represent the ledger"),
        "the refusal must be the running-total trap, got: {}",
        text
    );

    // And the ledger is UNCHANGED: a trap rolls the message back, so the
    // invariant still holds. A wrapped total could never produce this.
    let r = supply_report(&pic, cid);
    assert!(r.invariant_holds, "a trapped write leaves the ledger untouched");
    assert_eq!(r.sum_all_balances, TOTAL_SUPPLY);
    assert!(r.arithmetic_error.is_none());
}

/// Boundary: a MAINTAINED total of EXACTLY u128::MAX is representable, so the
/// write succeeds and no arithmetic error is reported — the invariant then fails
/// on the honest numeric mismatch instead. (R-1: the same boundary, one layer
/// earlier — it is now the write funnel's `checked_add`, not a fold, that has to
/// get u128::MAX right.)
#[test]
fn test_t2_exact_u128_max_fold_is_not_an_arithmetic_error() {
    let pic = PocketIc::new();
    let cid = try_install(
        &pic,
        token_test_wasm(),
        token_init(vec![alloc("genesis", TOTAL_SUPPLY, p(0x11))]),
    )
    .expect("install test-feature token");

    // sum(BALANCES) = TOTAL_SUPPLY + (u128::MAX - TOTAL_SUPPLY) = exactly u128::MAX.
    debug_credit(&pic, cid, p(0xE1), u128::MAX - TOTAL_SUPPLY);

    let r = supply_report(&pic, cid);
    assert!(r.arithmetic_error.is_none(), "exact u128::MAX fold is valid arithmetic");
    assert!(!r.invariant_holds, "sum != TOTAL_SUPPLY must still fail the invariant");
    assert_eq!(r.sum_all_balances, u128::MAX, "the exact fold result must be reported");
    assert!(
        r.violation_detail.expect("numeric mismatch detail").contains("!= TOTAL_SUPPLY"),
        "non-arithmetic failure keeps the numeric mismatch message"
    );
}

/// T-2 compatibility contract: an OLD decoder (pre-P-ARITH report shape,
/// without arithmetic_error) must decode the new wire report unchanged.
#[test]
fn test_t2_legacy_decoder_safely_ignores_additive_field() {
    let pic = PocketIc::new();
    let cid = try_install(
        &pic,
        token_wasm(),
        token_init(vec![alloc("genesis", TOTAL_SUPPLY, p(0x11))]),
    )
    .expect("install production token");

    let bytes = pic
        .query_call(cid, anon(), "verify_supply_invariant", candid::encode_args(()).unwrap())
        .expect("verify_supply_invariant query");

    // Old consumer: decodes into the 7-field record, additive field skipped.
    let legacy: LegacySupplyInvariantReport =
        candid::decode_one(&bytes).expect("old decoder must safely ignore the additive field");
    assert!(legacy.invariant_holds, "healthy ledger decodes healthy for old consumers");
    assert_eq!(legacy.fixed_max_supply, TOTAL_SUPPLY);
    assert_eq!(legacy.sum_all_balances, TOTAL_SUPPLY);

    // And the new decoder sees arithmetic_error = null on the same reply.
    let current: SupplyInvariantReport = candid::decode_one(&bytes).unwrap();
    assert!(current.arithmetic_error.is_none());
}

// =============================================================================
// V-1 — vesting schedule-init exact validation (K3-003)
// =============================================================================

fn schedule(n: u8, amount: u128, cliff: u32, linear: u32) -> NewSchedule {
    NewSchedule { beneficiary: p(n), total_amount: amount, cliff_months: cliff, linear_months: linear }
}

#[test]
fn test_v1_vesting_init_rejections_typed() {
    let pic = PocketIc::new();

    // Duplicate beneficiary → typed reject (closes the silent overwrite).
    let err = try_install(
        &pic,
        vesting_wasm(),
        vesting_init(vec![schedule(0x21, 10, 6, 30), schedule(0x21, 20, 0, 12)]),
    )
    .expect_err("RED-CLASS DEFECT: duplicate beneficiary silently overwrote (K3-003)");
    assert!(err.contains("duplicate vesting beneficiary"), "typed dup message, got: {}", err);

    // Over-cap: 481 months.
    let err = try_install(
        &pic,
        vesting_wasm(),
        vesting_init(vec![schedule(0x22, 10, 1, MAX_SCHEDULE_MONTHS)]),
    )
    .expect_err("cap+1 must be rejected");
    assert!(err.contains("exceeds MAX_SCHEDULE_MONTHS"), "typed cap message, got: {}", err);

    // u32::MAX months: the old code wrapped the ns conversion — now capped.
    let err = try_install(
        &pic,
        vesting_wasm(),
        vesting_init(vec![schedule(0x23, 10, u32::MAX, u32::MAX)]),
    )
    .expect_err("RED-CLASS DEFECT: u32::MAX months accepted with wrapped timestamps (K3-003)");
    assert!(err.contains("exceeds MAX_SCHEDULE_MONTHS"), "typed cap message, got: {}", err);

    // Both-zero duration.
    let err = try_install(&pic, vesting_wasm(), vesting_init(vec![schedule(0x24, 10, 0, 0)]))
        .expect_err("both-zero duration must be rejected");
    assert!(err.contains("zero total duration"), "typed zero-duration message, got: {}", err);

    // Zero amount.
    let err = try_install(&pic, vesting_wasm(), vesting_init(vec![schedule(0x25, 0, 6, 30)]))
        .expect_err("zero amount must be rejected");
    assert!(err.contains("zero amount"), "typed zero-amount message, got: {}", err);
}

#[test]
fn test_v1_vesting_accepts_valid_shapes_with_sane_timestamps() {
    let pic = PocketIc::new();

    // Founders shape (6+30), zero-cliff (0+12), and the exact cap (0+480).
    let cid = try_install(
        &pic,
        vesting_wasm(),
        vesting_init(vec![
            schedule(0x31, 9_000_000_000_000_000, 6, 30),
            schedule(0x32, 9_000_000_000_000_000, 6, 30),
            schedule(0x33, 1_000, 0, 12),
            schedule(0x34, 1_000, 0, MAX_SCHEDULE_MONTHS),
        ]),
    )
    .expect("valid schedule set must install (zero-cliff allowed, cap accepted)");

    let founders = get_schedule(&pic, cid, p(0x31)).expect("founder schedule stored");
    assert_eq!(founders.cliff_end_ns, founders.start_ns + 6 * NS_PER_MONTH);
    assert_eq!(founders.vesting_end_ns, founders.start_ns + 36 * NS_PER_MONTH);
    assert!(
        founders.start_ns < founders.cliff_end_ns && founders.cliff_end_ns < founders.vesting_end_ns,
        "no wrapped timestamp: start < cliff < end"
    );

    let zero_cliff = get_schedule(&pic, cid, p(0x33)).expect("zero-cliff schedule stored");
    assert_eq!(zero_cliff.cliff_end_ns, zero_cliff.start_ns, "zero cliff starts vesting immediately");
    assert_eq!(zero_cliff.vesting_end_ns, zero_cliff.start_ns + 12 * NS_PER_MONTH);

    let capped = get_schedule(&pic, cid, p(0x34)).expect("cap-boundary schedule stored");
    assert_eq!(
        capped.vesting_end_ns,
        capped.start_ns + MAX_SCHEDULE_MONTHS as u64 * NS_PER_MONTH,
        "480-month schedule computes without wrap"
    );
}
