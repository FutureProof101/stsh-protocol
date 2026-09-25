// =============================================================================
// STSH — R-1 token supply integrity
// BRIEF_R1_TOKEN_SUPPLY_INTEGRITY_V14_2026-09-04.md
// =============================================================================
//
// What this suite binds, and what it deliberately does NOT:
//
//   * AC-1/AC-2   the NARROW zero-approve guard, and that revocation survives it
//                 (the dev006 conformance trio lives in
//                 token_icrc_conformance_tests.rs, beside its siblings)
//   * AC-4a/4b    the first law on BOTH paths, and that maintained-vs-folded
//                 drift is visible to reconcile ONLY — the public path is blind
//                 to it BY CONSTRUCTION, which is why AC-4b asserts
//                 `invariant_holds == true` on a drifted ledger
//   * AC-5        one named test per production write call, so a per-call-site
//                 mutation (M5-(n)) has exactly one test to drive RED
//   * AC-6/6c     the ONE PocketIC-callable seam, including R-4's exact overflow
//                 scenario reaching a QUERYABLE report with no trap anywhere
//   * AC-7a/b/d/e the real CROSS-Wasm upgrade paths (base production Wasm from
//                 115526d → fixed test Wasm), the seed bound, the v3-None
//                 refusal, and the v1 chain
//   * AC-8        the public path is O(1) at a row count that would trap a fold
//   * AC-9        reconcile is controller-only
//   * AC-10       the hot-path cost ceiling
//   * AC-12       the reconcile row budget, DERIVED not guessed
//   * AC-13       no test-only symbol ships
//
// NOT bound here, deliberately: AC-5(x)/(x2)/(7f-7o) are structural — a compile
// failure or a lint RED, not a runtime behaviour — and their evidence is the
// compiler's and the lints' own output, recorded in the packet.

use candid::{CandidType, Nat, Principal};
use ic_management_canister_types::{CanisterInstallMode, InstallCodeArgs};
use pocket_ic::common::rest::RawEffectivePrincipal;
use pocket_ic::{ErrorCode, PocketIc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Wasm loaders ─────────────────────────────────────────────────────────────

fn token_wasm() -> Vec<u8> {
    read_wasm(env!("TOKEN_WASM"), "stsh_token")
}
fn token_test_wasm() -> Vec<u8> {
    read_wasm(env!("TOKEN_TEST_WASM"), "stsh_token_test")
}
/// The PRE-fix production Wasm from master 115526d. Its checkpoint has NO
/// `sum_balances` / `sum_staking_locks` fields at all — that absence is what
/// AC-7a actually tests.
fn token_base_wasm() -> Vec<u8> {
    read_wasm(env!("TOKEN_BASE_115526D_WASM"), "stsh_token_base_115526d")
}
/// The AC-10 "before" side: the SAME base source at 115526d, built with
/// `--features testing` and the two `performance_counter(0)` wrappers appended
/// verbatim from the fixed tree. Built by
/// `scripts/build_token_base_measure_wasm.sh`; see integration-tests/build.rs.
fn token_base_measure_wasm() -> Vec<u8> {
    read_wasm(env!("TOKEN_BASE_MEASURE_TEST_WASM"), "stsh_token_base_115526d_measure_test")
}
fn token_d068_wasm() -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
        .join("wasm32-unknown-unknown/release/stsh_token_pre_hardening_d068_prod.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("d068 production token fixture missing at {}: {e}", path.display())
    });
    let actual = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        actual,
        "35c5b17240eccca9e46203b8ded5fb737914e573757cb000bd1579c7dad14032",
        "d068 token fixture must match the committed release_hashes.toml production pin"
    );
    bytes
}

fn read_wasm(path: &str, what: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {what} Wasm at {path}: {e}\n\
             Law #7 two-phase build first — ./run_gate.sh, or see \
             integration-tests/build.rs for the exact recipe for this artifact."
        )
    })
}

// ── Constants — must match canisters/token ───────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const ERR_CODE_ZERO_AMOUNT: u32 = 5;
/// `MAX_MIGRATION_ENTRIES` under `--features testing` (token lib.rs).
const MAX_MIGRATION_ENTRIES_TESTING: u64 = 8;

// ── Wire mirrors ─────────────────────────────────────────────────────────────

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct SupplyReconciliation {
    maintained_sum_balances: u128,
    folded_sum_balances: u128,
    maintained_sum_staking_locks: u128,
    folded_sum_staking_locks: u128,
    fee_reserve: u128,
    rows_examined: u64,
    totals_consistent: bool,
    folded_first_law_holds: bool,
    detail: Option<String>,
}

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
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>,
    from: Account,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

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
struct AllowanceArgs {
    account: Account,
    spender: Account,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Allowance {
    allowance: Nat,
    expires_at: Option<u64>,
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TransferFromError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

// ── Principals ───────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}
/// The genesis holder — the whole supply lands here.
fn alice() -> Principal {
    p(0x11)
}
fn bob() -> Principal {
    p(0x12)
}
fn carol() -> Principal {
    p(0x13)
}
/// The staking canister principal pinned in `token_init`.
fn staking() -> Principal {
    p(0x02)
}
/// NOT a controller of the canisters this suite creates (PocketIC makes the
/// `install_code` sender — anonymous — the controller).
fn stranger() -> Principal {
    p(0x77)
}

fn acct(owner: Principal) -> Account {
    Account { owner, subaccount: None }
}

// ── Install / call helpers ───────────────────────────────────────────────────

fn alloc(id: &str, amount: u128, recipient: Principal) -> AllocationCategory {
    AllocationCategory {
        category_id: id.to_string(),
        category_name: format!("Cat {id}"),
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
        staking_canister: staking(),
        fee_collector: Some(p(0xF1)),
    })
    .unwrap()
}

fn genesis_one() -> Vec<u8> {
    token_init(vec![alloc("genesis", TOTAL_SUPPLY, alice())])
}

fn try_install(pic: &PocketIc, wasm: Vec<u8>, arg: Vec<u8>) -> Result<Principal, String> {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 100_000_000_000_000);
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
        anon(),
        "install_code",
        candid::encode_one(&args).unwrap(),
    )
    .map(|_| cid)
    .map_err(|e| format!("{e:?}"))
}

fn install(pic: &PocketIc, wasm: Vec<u8>, arg: Vec<u8>) -> Principal {
    try_install(pic, wasm, arg).expect("install must succeed")
}

/// Upgrade in place, RETURNING the rejection so a trapping `post_upgrade` is an
/// assertable Err rather than a panic inside the harness.
fn try_upgrade(pic: &PocketIc, cid: Principal, wasm: Vec<u8>) -> Result<(), String> {
    let args = InstallCodeArgs {
        mode: CanisterInstallMode::Upgrade(None),
        canister_id: cid,
        wasm_module: wasm,
        arg: candid::encode_args(()).unwrap(),
        sender_canister_version: None,
    };
    pic.update_call_with_effective_principal(
        Principal::management_canister(),
        RawEffectivePrincipal::CanisterId(cid.as_slice().to_vec()),
        anon(),
        "install_code",
        candid::encode_one(&args).unwrap(),
    )
    .map(|_| ())
    .map_err(|e| format!("{e:?}"))
}

fn report(pic: &PocketIc, cid: Principal) -> SupplyInvariantReport {
    let bytes = pic
        .query_call(cid, anon(), "verify_supply_invariant", candid::encode_args(()).unwrap())
        .expect("verify_supply_invariant query");
    candid::decode_one(&bytes).unwrap()
}

/// Reconcile AS A CONTROLLER (anonymous is the install_code sender, hence the
/// controller of every canister this suite creates).
fn reconcile(pic: &PocketIc, cid: Principal) -> SupplyReconciliation {
    let bytes = pic
        .update_call(cid, anon(), "reconcile_supply_invariant", candid::encode_args(()).unwrap())
        .expect("reconcile_supply_invariant as controller");
    candid::decode_one(&bytes).unwrap()
}

fn balance_of(pic: &PocketIc, cid: Principal, who: Principal) -> u128 {
    let bytes = pic
        .query_call(cid, anon(), "icrc1_balance_of", candid::encode_one(acct(who)).unwrap())
        .expect("icrc1_balance_of");
    let n: Nat = candid::decode_one(&bytes).unwrap();
    nat_u128(&n)
}

fn nat_u128(n: &Nat) -> u128 {
    let d = n.0.to_u32_digits();
    let mut out: u128 = 0;
    for (i, w) in d.iter().enumerate() {
        assert!(i < 4, "nat does not fit u128");
        out |= (*w as u128) << (32 * i);
    }
    out
}

fn transfer(
    pic: &PocketIc,
    cid: Principal,
    from: Principal,
    to: Principal,
    amount: u128,
) -> Result<Nat, TransferError> {
    let args = TransferArgs {
        from_subaccount: None,
        to: acct(to),
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, from, "icrc1_transfer", candid::encode_one(&args).unwrap())
        .expect("icrc1_transfer call");
    candid::decode_one(&bytes).unwrap()
}

fn approve(
    pic: &PocketIc,
    cid: Principal,
    from: Principal,
    spender: Principal,
    amount: u128,
    expected: Option<u128>,
    expires_at: Option<u64>,
) -> Result<Nat, ApproveError> {
    // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that WRITES a
    // row, so a `None` from a case that does not care about expiry is filled with a
    // bounded default — 1 h, well inside the 24 h MAX_APPROVAL_TTL_NS cap — and those
    // cases keep testing supply integrity rather than the admission rule. Cases that
    // DO care pass an explicit `Some(..)` and are untouched.
    //
    // A ZERO-amount approve keeps `None`: it is revocation, it writes no row, and it
    // is exempt from the rule (I-A1). r1_ac2's two halves depend on that — the live
    // half must succeed with no expiry supplied, and the expired half must still be
    // refused by the dev006 guard.
    let expires_at = match (expires_at, amount) {
        (Some(e), _) => Some(e),
        (None, 0) => None,
        (None, _) => {
            Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000)
        }
    };
    let args = ApproveArgs {
        from_subaccount: None,
        spender: acct(spender),
        amount: Nat::from(amount),
        expected_allowance: expected.map(Nat::from),
        expires_at,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, from, "icrc2_approve", candid::encode_one(&args).unwrap())
        .expect("icrc2_approve call");
    candid::decode_one(&bytes).unwrap()
}

fn allowance(pic: &PocketIc, cid: Principal, owner: Principal, spender: Principal) -> Allowance {
    let args = AllowanceArgs { account: acct(owner), spender: acct(spender) };
    let bytes = pic
        .query_call(cid, anon(), "icrc2_allowance", candid::encode_one(&args).unwrap())
        .expect("icrc2_allowance");
    candid::decode_one(&bytes).unwrap()
}

fn transfer_from(
    pic: &PocketIc,
    cid: Principal,
    spender: Principal,
    from: Principal,
    to: Principal,
    amount: u128,
) -> Result<Nat, TransferFromError> {
    let args = TransferFromArgs {
        spender_subaccount: None,
        from: acct(from),
        to: acct(to),
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, spender, "icrc2_transfer_from", candid::encode_one(&args).unwrap())
        .expect("icrc2_transfer_from call");
    candid::decode_one(&bytes).unwrap()
}

fn lock(pic: &PocketIc, cid: Principal, holder: Principal, amount: u128) -> Result<(), String> {
    let bytes = pic
        .update_call(cid, staking(), "lock_for_staking", candid::encode_args((holder, amount)).unwrap())
        .expect("lock_for_staking");
    candid::decode_one(&bytes).unwrap()
}

fn unlock(pic: &PocketIc, cid: Principal, holder: Principal, amount: u128) -> Result<(), String> {
    let bytes = pic
        .update_call(cid, staking(), "unlock_from_staking", candid::encode_args((holder, amount)).unwrap())
        .expect("unlock_from_staking");
    candid::decode_one(&bytes).unwrap()
}

fn set_totals(pic: &PocketIc, cid: Principal, sb: u128, sl: u128, fr: u128) {
    pic.update_call(
        cid,
        anon(),
        "set_supply_totals_for_test",
        candid::encode_args((sb, sl, fr)).unwrap(),
    )
    .expect("set_supply_totals_for_test");
}

fn debug_credit(pic: &PocketIc, cid: Principal, owner: Principal, amount: u128) {
    pic.update_call(
        cid,
        anon(),
        "debug_credit_balance_for_test",
        candid::encode_args((acct(owner), amount)).unwrap(),
    )
    .expect("debug_credit_balance_for_test");
}

// =============================================================================
// L03A — canonical zero rows through the production endpoint and d068 upgrade.

fn approve_account(
    pic: &PocketIc,
    cid: Principal,
    owner: Principal,
    from_subaccount: [u8; 32],
    spender: Principal,
    amount: u128,
    expected: Option<u128>,
    created_at_time: Option<u64>,
) -> Result<Nat, ApproveError> {
    let args = ApproveArgs {
        from_subaccount: Some(from_subaccount),
        spender: acct(spender),
        amount: Nat::from(amount),
        expected_allowance: expected.map(Nat::from),
        // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that WRITES a
        // row — a bounded 1 h default, well inside the 24 h cap. A ZERO-amount approve
        // keeps `None`: it is revocation, writes no row, and is exempt (I-A1), which is
        // what the L03A canonical-zero-row cases drive through this helper.
        //
        // DERIVED FROM `created_at_time` WHEN ONE IS SUPPLIED, the way the shipped
        // wallet derives it. `approve_dedup_key` hashes the WHOLE argument, and the
        // L03A d068-upgrade case re-issues a byte-identical approve after an upgrade to
        // prove the old dedup identity survives. An expiry read from the clock per call
        // would differ between the original and the retry, so the retry would be a new
        // approve rather than a `Duplicate` — which is exactly how this read as a
        // failure before the derivation was fixed.
        expires_at: match (amount, created_at_time) {
            (0, _) => None,
            (_, Some(t)) => Some(t + 3_600_000_000_000),
            (_, None) => {
                Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000)
            }
        },
        fee: None,
        memo: Some(vec![from_subaccount[0]]),
        created_at_time,
    };
    let bytes = pic
        .update_call(cid, owner, "icrc2_approve", candid::encode_one(&args).unwrap())
        .expect("icrc2_approve subaccount call");
    candid::decode_one(&bytes).unwrap()
}

fn allowance_account(
    pic: &PocketIc,
    cid: Principal,
    owner: Principal,
    subaccount: [u8; 32],
    spender: Principal,
) -> Allowance {
    let args = AllowanceArgs {
        account: Account { owner, subaccount: Some(subaccount) },
        spender: acct(spender),
    };
    let bytes = pic
        .query_call(cid, anon(), "icrc2_allowance", candid::encode_one(&args).unwrap())
        .expect("icrc2_allowance subaccount");
    candid::decode_one(&bytes).unwrap()
}

#[test]
fn l03a_production_64_unfunded_subaccount_approve_revoke_has_zero_balance_row_delta() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_wasm(), genesis_one());
    let before = reconcile(&pic, cid);
    assert!(before.totals_consistent && before.folded_first_law_holds);

    for i in 0u8..64 {
        let sub = [i.wrapping_add(1); 32];
        approve_account(&pic, cid, carol(), sub, bob(), 1, None, None)
            .unwrap_or_else(|e| panic!("approve subaccount {i}: {e:?}"));
        let approved = reconcile(&pic, cid);
        assert_eq!(approved.rows_examined, before.rows_examined, "approve {i} added a BALANCES row");
        assert_eq!(approved.maintained_sum_balances, approved.folded_sum_balances);
        assert_eq!(approved.maintained_sum_staking_locks, approved.folded_sum_staking_locks);
        assert!(approved.totals_consistent && approved.folded_first_law_holds);

        approve_account(&pic, cid, carol(), sub, bob(), 0, Some(1), None)
            .unwrap_or_else(|e| panic!("revoke subaccount {i}: {e:?}"));
        assert_eq!(nat_u128(&allowance_account(&pic, cid, carol(), sub, bob()).allowance), 0);
        let revoked = reconcile(&pic, cid);
        assert_eq!(revoked.rows_examined, before.rows_examined, "revoke {i} changed BALANCES rows");
        assert_eq!(revoked.maintained_sum_balances, revoked.folded_sum_balances);
        assert_eq!(revoked.maintained_sum_staking_locks, revoked.folded_sum_staking_locks);
        assert!(revoked.totals_consistent && revoked.folded_first_law_holds);
    }

    let after = reconcile(&pic, cid);
    assert_eq!(after.rows_examined, before.rows_examined, "64 unfunded subaccounts add zero BALANCES rows");
    assert_eq!(after.maintained_sum_balances, before.maintained_sum_balances);
    assert_eq!(after.folded_sum_balances, before.folded_sum_balances);
    assert!(after.totals_consistent && after.folded_first_law_holds);
}

#[test]
fn l03a_populated_d068_upgrade_preserves_rows_authorization_dedup_and_totals() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_d068_wasm(), genesis_one());
    let untouched = [0xA1; 32];
    let rewritten = [0xA2; 32];
    let created_at = pic.get_time().as_nanos_since_unix_epoch();

    let old_block = approve_account(&pic, cid, carol(), untouched, bob(), 7, None, Some(created_at))
        .expect("old deduplicated allowance");
    approve_account(&pic, cid, carol(), rewritten, bob(), 9, None, None)
        .expect("old second allowance");
    let lock_raw = pic.update_call(
        cid, staking(), "lock_for_staking",
        candid::encode_args((alice(), 123u128)).unwrap(),
    ).expect("old lock call");
    assert!(candid::decode_one::<Result<(), String>>(&lock_raw).unwrap().is_ok());

    let old = reconcile(&pic, cid);
    assert_eq!(old.rows_examined, 4, "genesis positive + two historical zero balances + one lock");
    assert!(old.totals_consistent && old.folded_first_law_holds);
    assert_eq!(nat_u128(&allowance_account(&pic, cid, carol(), untouched, bob()).allowance), 7);

    try_upgrade(&pic, cid, token_wasm()).expect("d068 production token upgrades");
    let after_upgrade = reconcile(&pic, cid);
    assert_eq!(after_upgrade.rows_examined, old.rows_examined, "upgrade does not sweep historical zero rows");
    assert_eq!(after_upgrade.maintained_sum_balances, old.maintained_sum_balances);
    assert_eq!(after_upgrade.folded_sum_balances, old.folded_sum_balances);
    assert_eq!(after_upgrade.maintained_sum_staking_locks, old.maintained_sum_staking_locks);
    assert_eq!(after_upgrade.folded_sum_staking_locks, old.folded_sum_staking_locks);
    assert!(after_upgrade.totals_consistent && after_upgrade.folded_first_law_holds);
    assert_eq!(nat_u128(&allowance_account(&pic, cid, carol(), untouched, bob()).allowance), 7);
    assert_eq!(nat_u128(&allowance_account(&pic, cid, carol(), rewritten, bob()).allowance), 9);

    let duplicate = approve_account(&pic, cid, carol(), untouched, bob(), 7, None, Some(created_at))
        .expect_err("old dedup identity must survive");
    assert!(matches!(duplicate, ApproveError::Duplicate { duplicate_of } if duplicate_of == old_block));

    approve_account(&pic, cid, carol(), rewritten, bob(), 10, Some(9), None)
        .expect("rewriting historical zero-balance owner succeeds");
    let after_rewrite = reconcile(&pic, cid);
    assert_eq!(after_rewrite.rows_examined, old.rows_examined - 1, "only the rewritten historical zero row is removed");
    assert_eq!(after_rewrite.maintained_sum_balances, old.maintained_sum_balances);
    assert_eq!(after_rewrite.folded_sum_balances, old.folded_sum_balances);
    assert!(after_rewrite.totals_consistent && after_rewrite.folded_first_law_holds);
    assert_eq!(nat_u128(&allowance_account(&pic, cid, carol(), untouched, bob()).allowance), 7);
    assert_eq!(nat_u128(&allowance_account(&pic, cid, carol(), rewritten, bob()).allowance), 10);
}

// AC-1 / AC-2 — the NARROW zero-approve guard (S1)
// =============================================================================

/// AC-1: zero approve with NO live allowance is refused with the pinned code.
#[test]
fn r1_ac1_zero_approve_without_live_allowance_is_refused() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_wasm(), genesis_one());

    // A caller with no balance at all — the guard must not depend on funds.
    let err = approve(&pic, cid, carol(), bob(), 0, None, None)
        .expect_err("zero approve with no live allowance must be refused");
    match err {
        ApproveError::GenericError { error_code, message } => {
            assert_eq!(error_code, Nat::from(ERR_CODE_ZERO_AMOUNT), "pinned R10-1 code");
            assert!(message.contains("greater than zero"), "message: {message}");
        }
        other => panic!("expected the zero-amount refusal, got {other:?}"),
    }
    assert!(report(&pic, cid).invariant_holds, "a refused approve writes nothing");
}

/// AC-2: revocation — the reason the guard is narrow rather than blanket.
#[test]
fn r1_ac2_zero_approve_revokes_a_live_allowance() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_wasm(), genesis_one());

    approve(&pic, cid, alice(), bob(), 5_000, None, None).expect("approve A>0");
    assert_eq!(nat_u128(&allowance(&pic, cid, alice(), bob()).allowance), 5_000);

    // The wallet's own revocation shape: approve(0) with expected_allowance = A.
    approve(&pic, cid, alice(), bob(), 0, Some(5_000), None)
        .expect("approve(0) against a LIVE allowance is revocation and must succeed");
    assert_eq!(
        nat_u128(&allowance(&pic, cid, alice(), bob()).allowance),
        0,
        "the allowance must read 0 after revocation"
    );
}

/// AC-2, second half: an EXPIRED allowance is not live, so there is nothing to
/// revoke and the zero approve is refused. Binds the guard to
/// `icrc2_allowance`'s own INCLUSIVE boundary.
#[test]
fn r1_ac2_zero_approve_against_an_expired_allowance_is_refused() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_wasm(), genesis_one());

    let now = pic.get_time().as_nanos_since_unix_epoch();
    approve(&pic, cid, alice(), bob(), 5_000, None, Some(now + 60_000_000_000))
        .expect("approve with a future expiry");

    // Advance past the expiry.
    pic.advance_time(std::time::Duration::from_secs(120));
    pic.tick();
    assert_eq!(
        nat_u128(&allowance(&pic, cid, alice(), bob()).allowance),
        0,
        "an expired allowance already reads as 0"
    );

    let err = approve(&pic, cid, alice(), bob(), 0, None, None)
        .expect_err("an expired allowance is not live — nothing to revoke");
    assert!(
        matches!(err, ApproveError::GenericError { ref error_code, .. }
                 if *error_code == Nat::from(ERR_CODE_ZERO_AMOUNT)),
        "got {err:?}"
    );
}

// =============================================================================
// AC-4a — the first law on BOTH paths, independently
// =============================================================================

/// The two booleans are INDEPENDENT results of independent computations. On the
/// healthy tree both hold; under M4a (a one-base-unit perturbation applied
/// THROUGH the funnel, so maintained == folded) `invariant_holds` and
/// `folded_first_law_holds` both go false while `totals_consistent` stays TRUE —
/// and that last assertion is what proves they are not derived from each other.
#[test]
fn r1_ac4a_first_law_holds_on_both_paths() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    transfer(&pic, cid, alice(), bob(), 1_000).expect("transfer");

    let r = report(&pic, cid);
    assert!(r.invariant_holds, "O(1) public path: {:?}", r.violation_detail);
    assert_eq!(r.sum_all_balances, TOTAL_SUPPLY);

    let rc = reconcile(&pic, cid);
    assert!(rc.folded_first_law_holds, "O(N) audit path, computed from the FOLD");
    assert!(rc.totals_consistent, "maintained == folded, both pairs");
    assert_eq!(rc.maintained_sum_balances, TOTAL_SUPPLY);
    assert_eq!(rc.folded_sum_balances, TOTAL_SUPPLY);
    assert!(rc.rows_examined >= 2, "genesis row + bob's row at minimum");
}

// =============================================================================
// AC-4b — drift is visible to reconcile ONLY
// =============================================================================

/// On the FIXED tree: one transfer, then `true / true / 0`. Under M4b (a
/// `write_balance_no_sum` helper wired into the phase-2 credit) the SAME
/// assertions read `invariant_holds == true` — the public path lying green is
/// the point — with `totals_consistent == false`, `folded_first_law_holds ==
/// false`, and a maintained−folded difference of exactly 1.
#[test]
fn r1_ac4b_public_path_is_blind_to_maintained_vs_folded_drift() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    transfer(&pic, cid, alice(), bob(), 1).expect("transfer");

    assert!(report(&pic, cid).invariant_holds, "public path");
    let rc = reconcile(&pic, cid);
    assert!(rc.totals_consistent, "no drift on the fixed tree");
    assert!(rc.folded_first_law_holds);
    assert_eq!(
        rc.maintained_sum_balances as i128 - rc.folded_sum_balances as i128,
        0,
        "maintained − folded must be exactly 0 on the fixed tree"
    );
}

// =============================================================================
// AC-5 — one named test per production write call
// =============================================================================

/// (i) genesis mint.
#[test]
fn r1_ac5_i_genesis_mint_moves_the_total() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_wasm(), genesis_one());
    let r = report(&pic, cid);
    assert!(r.invariant_holds, "genesis must land the running total on TOTAL_SUPPLY");
    assert_eq!(r.sum_all_balances, TOTAL_SUPPLY);
}

/// (ii) + (iii) `icrc1_transfer` debit and credit. The mutation is PER WRITE
/// CALL precisely because skipping BOTH halves of a balanced pair is invisible.
#[test]
fn r1_ac5_ii_iii_icrc1_transfer_debit_and_credit_move_the_total() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    transfer(&pic, cid, alice(), bob(), 777).expect("transfer");

    assert_eq!(balance_of(&pic, cid, bob()), 777);
    assert!(report(&pic, cid).invariant_holds, "one skipped half leaves the total off by amount");
    let rc = reconcile(&pic, cid);
    assert!(rc.totals_consistent);
    assert!(rc.folded_first_law_holds);
}

/// (v) + (vi) `icrc2_transfer_from` debit and credit.
#[test]
fn r1_ac5_v_vi_icrc2_transfer_from_debit_and_credit_move_the_total() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    approve(&pic, cid, alice(), bob(), 10_000, None, None).expect("approve");
    transfer_from(&pic, cid, bob(), alice(), carol(), 4_242).expect("transfer_from");

    assert_eq!(balance_of(&pic, cid, carol()), 4_242);
    assert!(report(&pic, cid).invariant_holds);
    let rc = reconcile(&pic, cid);
    assert!(rc.totals_consistent);
    assert!(rc.folded_first_law_holds);
}

/// (viii) `lock_for_staking`.
#[test]
fn r1_ac5_viii_lock_for_staking_moves_the_locks_total() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    const X: u128 = 9_000;
    lock(&pic, cid, alice(), X).expect("lock_for_staking");

    let rc = reconcile(&pic, cid);
    assert_eq!(rc.maintained_sum_staking_locks, X, "maintained locks total");
    assert_eq!(rc.folded_sum_staking_locks, X, "folded locks total");
    assert!(rc.totals_consistent);
    assert_eq!(
        report(&pic, cid).staking_locked_total,
        X,
        "the public report reads the MAINTAINED locks total"
    );
}

/// (ix) `unlock_from_staking`.
#[test]
fn r1_ac5_ix_unlock_from_staking_moves_the_locks_total() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    const X: u128 = 9_000;
    const Y: u128 = 3_500;
    lock(&pic, cid, alice(), X).expect("lock");
    unlock(&pic, cid, alice(), Y).expect("unlock");

    let rc = reconcile(&pic, cid);
    assert_eq!(rc.maintained_sum_staking_locks, X - Y);
    assert_eq!(rc.folded_sum_staking_locks, X - Y);
    assert!(rc.totals_consistent);
}

// (iv) and (vii) carry a structurally ZERO delta on the launch Wasm
// (`DEFAULT_FEE = 0`, no setter — DEF-085), so no PocketIC behaviour
// distinguishes them:
//   * (vii) `route_fee_to_treasury` is bound by the NATIVE unit test
//     `tests::test_r1_route_fee_to_treasury_moves_the_maintained_total`
//     (canisters/token/src/lib.rs), which calls it directly with fee = 7.
//   * (iv) `icrc2_approve`'s fee debit CANNOT be reached with a nonzero fee
//     off-canister at all — the endpoint reads `caller()` — so it is bound by
//     AC-5(x)/(x2) ONLY: it is on the funnel because `BALANCES` is not nameable
//     from that call site, which the COMPILER enforces, not a test.

// =============================================================================
// AC-6 / AC-6c — the ONE PocketIC-callable seam
// =============================================================================

/// AC-6: a corrupted MAINTAINED total with the maps untouched is detected by
/// reconcile, and the two booleans separate cleanly.
#[test]
fn r1_ac6_reconcile_detects_a_corrupted_maintained_total() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    let before = reconcile(&pic, cid);
    assert!(before.totals_consistent && before.folded_first_law_holds);

    // Balances operand.
    set_totals(&pic, cid, before.maintained_sum_balances + 1, before.maintained_sum_staking_locks, before.fee_reserve);
    let rc = reconcile(&pic, cid);
    assert!(!rc.totals_consistent, "a maintained total that never came from a write");
    assert!(rc.folded_first_law_holds, "the FOLD is untouched, so the first law still holds");

    // Revert.
    set_totals(&pic, cid, before.maintained_sum_balances, before.maintained_sum_staking_locks, before.fee_reserve);
    let rc = reconcile(&pic, cid);
    assert!(rc.totals_consistent && rc.folded_first_law_holds, "revert restores both");

    // Staking-locks operand — same assertion pair.
    set_totals(&pic, cid, before.maintained_sum_balances, before.maintained_sum_staking_locks + 1, before.fee_reserve);
    let rc = reconcile(&pic, cid);
    assert!(!rc.totals_consistent, "the locks pair must be compared too");
    assert!(rc.folded_first_law_holds);
}

/// AC-6c: R-4's exact overflow scenario is reachable through the landed seam and
/// produces a QUERYABLE report, with NO TRAP anywhere in the call chain — the
/// query path never calls `write_balance`, so the seam's direct total-set
/// bypasses the funnel's `checked_add`/`.expect` entirely, by design.
#[test]
fn r1_ac6c_overflow_is_queryable_not_a_trap() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    set_totals(&pic, cid, u128::MAX, 0, 1);

    let r = report(&pic, cid);
    assert!(!r.invariant_holds, "an arithmetic error forces invariant_holds = false");
    let ae = r.arithmetic_error.expect("arithmetic_error must be attributed");
    assert_eq!(
        ae,
        ArithmeticErrorReport {
            balances_overflow: false,
            staking_locks_overflow: false,
            balances_plus_fee_overflow: true,
        },
        "exactly the ONE remaining checked add is attributed"
    );
    // Reaching this line at all IS the "no trap" assertion: a trapped query
    // would have made `report` panic on the rejection.
    assert!(r.violation_detail.unwrap().contains("balances_plus_fee_overflow"));
}

// =============================================================================
// AC-7a / AC-7b / AC-7d / AC-7e — the real CROSS-Wasm upgrade paths
// =============================================================================

/// AC-7a: a genuine v2 checkpoint — written by the BASE production Wasm, in
/// which the two `sum_*` fields are literally ABSENT — decodes under the fixed
/// Wasm and seeds both totals by the one-shot fold.
///
/// Row budget: `MAX_MIGRATION_ENTRIES` is 8 under `testing`, and genesis
/// allocation accounts are BALANCES rows too, so the seeded state is kept at
/// 1 genesis row + 2 seeded balances + 1 lock = 4 rows, comfortably under.
#[test]
fn r1_ac7a_v2_checkpoint_seeds_the_totals_across_a_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_base_wasm(), genesis_one());

    // 2 non-genesis balance rows + 1 lock, all written by the BASE Wasm.
    transfer(&pic, cid, alice(), bob(), 5_000).expect("transfer to bob");
    transfer(&pic, cid, alice(), carol(), 2_500).expect("transfer to carol");
    lock(&pic, cid, alice(), 1_000).expect("lock");

    try_upgrade(&pic, cid, token_test_wasm()).expect("v2 → v3 upgrade must succeed");

    let r = report(&pic, cid);
    assert!(r.invariant_holds, "the seed fold must land on TOTAL_SUPPLY: {:?}", r.violation_detail);
    assert_eq!(r.sum_all_balances, TOTAL_SUPPLY);
    assert_eq!(r.staking_locked_total, 1_000);

    let rc = reconcile(&pic, cid);
    assert!(rc.totals_consistent, "seeded totals must equal the fold they came from");
    assert!(rc.folded_first_law_holds);
    assert_eq!(rc.rows_examined, 4, "1 genesis + bob + carol balance rows, 1 lock row");
}

/// AC-7b: the seed fold is BOUNDED. With `testing`'s
/// `MAX_MIGRATION_ENTRIES = 8`, a state of ≥ 9 rows must trap the upgrade with
/// the migration message rather than half-seed.
#[test]
fn r1_ac7b_the_seed_fold_is_bounded() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_base_wasm(), genesis_one());

    // 1 genesis row + 8 recipients = 9 BALANCES rows > MAX_MIGRATION_ENTRIES (8).
    for n in 0x20u8..0x28 {
        transfer(&pic, cid, alice(), p(n), 10).expect("seed a row");
    }

    let err = try_upgrade(&pic, cid, token_test_wasm())
        .expect_err("a seed fold over the bound must TRAP, never half-seed");
    assert!(
        err.contains("supply-total seed ABORTED") && err.contains("MAX_MIGRATION_ENTRIES"),
        "the trap must name the bound it refused: {err}"
    );
    assert!(
        MAX_MIGRATION_ENTRIES_TESTING == 8,
        "this test's row arithmetic is written against the testing bound"
    );
}

/// AC-7d: a v3 checkpoint carrying `None` is REFUSED — never read as zero — and
/// the refusal happens INSIDE `restore_from_checkpoint`, not in a caller-side
/// check a different call site could skip.
#[test]
fn r1_ac7d_a_v3_checkpoint_with_a_missing_total_is_refused() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    pic.update_call(cid, anon(), "force_v3_none_checkpoint_for_test", candid::encode_args(()).unwrap())
        .expect("arm the v3-None fixture");

    let err = try_upgrade(&pic, cid, token_test_wasm())
        .expect_err("a v3 checkpoint missing a total must trap");
    assert!(
        err.contains("v3 checkpoint missing sum_balances")
            && err.contains("refusing to guess"),
        "the trap must NAME the missing field: {err}"
    );
}

/// AC-7e: a v1 checkpoint chains 1 → 2 → 3 — the dedup back-fill runs AND the
/// totals are seeded.
#[test]
fn r1_ac7e_a_v1_checkpoint_chains_through_to_v3() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    // A dedup row, so the v1→v2 back-fill has something to do.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let args = TransferArgs {
        from_subaccount: None,
        to: acct(bob()),
        amount: Nat::from(50u32),
        fee: None,
        memo: None,
        created_at_time: Some(now),
    };
    let bytes = pic
        .update_call(cid, alice(), "icrc1_transfer", candid::encode_one(&args).unwrap())
        .expect("dedup-writing transfer");
    let res: Result<Nat, TransferError> = candid::decode_one(&bytes).unwrap();
    res.expect("transfer with created_at_time");

    pic.update_call(cid, anon(), "force_v1_legacy_state_for_test", candid::encode_args(()).unwrap())
        .expect("arm the v1 fixture");

    try_upgrade(&pic, cid, token_test_wasm()).expect("v1 → v2 → v3 must chain");

    let r = report(&pic, cid);
    assert!(r.invariant_holds, "the v1 arm must reach the same seed: {:?}", r.violation_detail);
    assert!(reconcile(&pic, cid).totals_consistent);
}

// =============================================================================
// AC-8 — the public path is O(1)
// =============================================================================

/// The public query answers at a row count well past anything a fold could
/// carry inside a query's instruction budget. The seeded count is a LITERAL,
/// not a number read back from the thing under test.
#[test]
fn r1_ac8_the_public_query_is_o1_at_scale() {
    // Seeded PAST the measured trap point, as AC-8 requires. Measured bracket
    // with M8 applied (the old O(N) fold restored on the public path):
    // 300_000 rows still ANSWER; 1_500_000 rows are REJECTED with
    // CanisterInstructionLimitExceeded (5_000_000_000 instructions, query).
    // At 60_000 — the count this constant used to carry — M8 stayed GREEN, so
    // the O(1) claim was not falsifiable by this test at all.
    const ROWS: u32 = 1_500_000;
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    seed_rows(&pic, cid, ROWS);

    // The O(1) query answers. Under M8 (the old fold restored) the same call
    // exceeds the query instruction limit and is rejected.
    let r = report(&pic, cid);
    assert!(r.invariant_holds, "{:?}", r.violation_detail);
    assert_eq!(r.sum_all_balances, TOTAL_SUPPLY);
}

/// Seed `n` extra BALANCES rows through the production funnel, in batches, so
/// no single message runs out of instructions.
fn seed_rows(pic: &PocketIc, cid: Principal, n: u32) {
    seed_rows_from(pic, cid, 0, n)
}

/// Seed `n` further rows starting at index `start` — used to top a canister up
/// across the budget boundary without reinstalling and reseeding from zero.
fn seed_rows_from(pic: &PocketIc, cid: Principal, start: u32, n: u32) {
    const BATCH: u32 = 2_000;
    let mut done = start;
    let end = start.checked_add(n).expect("fixture row range overflow");
    while done < end {
        let take = BATCH.min(end - done);
        let cardinality = seed_row_batch(pic, cid, acct(alice()), done, take)
            .unwrap_or_else(|e| panic!("seed_balance_rows_for_test({done}, {take}): {e}"));
        done += take;
        assert_eq!(
            cardinality,
            u64::from(done) + 1,
            "fixture guard: physical BALANCES cardinality must equal seeded rows plus the still-positive genesis donor"
        );
    }
}

fn seed_row_batch(
    pic: &PocketIc,
    cid: Principal,
    funding: Account,
    start: u32,
    count: u32,
) -> Result<u64, String> {
    let bytes = pic
        .update_call(
            cid,
            anon(),
            "seed_balance_rows_for_test",
            candid::encode_args((funding, start, count)).unwrap(),
        )
        .map_err(|e| format!("{e:?}"))?;
    candid::decode_one(&bytes).expect("decode seed_balance_rows_for_test result")
}

fn synthetic_seed_account(index: u32) -> Account {
    let mut raw = [0u8; 29];
    raw[0] = 0x90;
    raw[1..5].copy_from_slice(&index.to_le_bytes());
    Account {
        owner: Principal::from_slice(&raw),
        subaccount: None,
    }
}

#[test]
fn r1_seed_rows_are_real_idempotent_and_supply_preserving() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    seed_rows_from(&pic, cid, 0, 32);
    assert_eq!(balance_of(&pic, cid, alice()), TOTAL_SUPPLY - 32);
    assert!(report(&pic, cid).invariant_holds);
    let rc = reconcile(&pic, cid);
    assert_eq!(rc.rows_examined, 33);
    assert!(rc.totals_consistent && rc.folded_first_law_holds);

    assert_eq!(seed_row_batch(&pic, cid, acct(alice()), 8, 16), Ok(33));
    assert_eq!(balance_of(&pic, cid, alice()), TOTAL_SUPPLY - 32);

    assert_eq!(seed_row_batch(&pic, cid, acct(alice()), 24, 16), Ok(41));
    assert_eq!(balance_of(&pic, cid, alice()), TOTAL_SUPPLY - 40);
    let rc = reconcile(&pic, cid);
    assert_eq!(rc.rows_examined, 41);
    assert!(rc.totals_consistent && rc.folded_first_law_holds);

    assert!(seed_row_batch(&pic, cid, acct(alice()), u32::MAX, 2).is_err());
    assert!(seed_row_batch(&pic, cid, synthetic_seed_account(0), 100, 1).is_err());
    assert_eq!(
        seed_row_batch(&pic, cid, synthetic_seed_account(0), 0, 1),
        Err("seed balance target aliases funding account".to_string())
    );
    assert_eq!(reconcile(&pic, cid).rows_examined, 41);
    assert_eq!(balance_of(&pic, cid, alice()), TOTAL_SUPPLY - 40);
}

// =============================================================================
// AC-9 — reconcile is controller-only
// =============================================================================

#[test]
fn r1_ac9_reconcile_is_controller_only() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_wasm(), genesis_one());

    // The controller (the install_code sender) is served.
    let _ = reconcile(&pic, cid);

    for who in [stranger(), bob()] {
        let err = pic
            .update_call(cid, who, "reconcile_supply_invariant", candid::encode_args(()).unwrap())
            .expect_err("a non-controller must be refused");
        assert!(
            format!("{err:?}").contains("controller-only"),
            "the rejection must name the rule: {err:?}"
        );
    }
}

// =============================================================================
// AC-12 — the reconcile row budget is real
// =============================================================================

/// The pinned reconciliation budget, bound on BOTH sides at ±1 row.
///
/// AT `RECONCILE_ROW_BUDGET - 1` and AT exactly `RECONCILE_ROW_BUDGET` the audit
/// path ANSWERS with `totals_consistent == true` and `rows_examined` equal to the
/// real row count; at `RECONCILE_ROW_BUDGET + 1` it returns honest incompleteness
/// — both booleans false, `rows_examined == 0`, and a detail string that says the
/// fold did not run. Never a trap, and never a healthy-looking answer.
///
/// SSA_LANDED_DIFF_R-1_V1 RED-3 (`cto-triage-ssa-landed-diff-round1-2026-09-05`
/// §2): the V2 form asserted ONLY the over-budget refusal, so lowering
/// `RECONCILE_ROW_BUDGET` from 60,000 to 1 left this test GREEN.
///
/// SSA_LANDED_DIFF_R-1_V3 RED-3: the V3 form added an IN-budget arm, but seeded
/// it at a hardcoded 20,001 rows — a full 40,000 rows below the pin. Lowering the
/// production constant to 30,000 therefore still left this test GREEN: 20,001 is
/// under 30,000 and 60,001 is over it, so both arms passed an almost-halved
/// budget. A range that wide binds nothing but its own endpoints.
///
/// This form binds the VALUE. Every seeded count below is computed FROM `BUDGET`,
/// so the three probes sit at `BUDGET - 1`, `BUDGET` and `BUDGET + 1` rows and
/// track the pin wherever it moves:
///
///   * `BUDGET - 1` and `BUDGET + 1` bracket the boundary at ±1, so ANY change to
///     the production constant — up or down, by one row — falsifies one of them;
///   * the exact-`BUDGET` probe binds the COMPARISON: production refuses on
///     `rows > budget`, so flipping that to `rows >= budget` (or to `<`/`<=` on
///     the answering side) fails here and nowhere else;
///   * the literal pin below asserts the constant's VALUE as production reports
///     it, so a re-tuned budget cannot pass by simply moving the probes with it.
#[test]
fn r1_ac12_reconcile_is_honestly_incomplete_past_its_budget() {
    // canisters/token/src/lib.rs: RECONCILE_ROW_BUDGET.
    const BUDGET: u64 = 60_000;

    // Every probe is derived from BUDGET — none is a standalone literal — so the
    // test follows the pin instead of bracketing a fixed, ever-widening range.
    // `rows_examined` counts the genesis row too, so seeding N extra rows yields
    // N + 1 examined rows.
    const SEED_UNDER: u32 = BUDGET as u32 - 2; // -> BUDGET - 1 rows
    const SEED_AT: u32 = BUDGET as u32 - 1; // -> BUDGET     rows
    const SEED_OVER: u32 = BUDGET as u32; // -> BUDGET + 1 rows

    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    // ── arm 1: one row UNDER the budget the fold RUNS and agrees ─────────────
    seed_rows(&pic, cid, SEED_UNDER);
    let rc = reconcile(&pic, cid);
    assert_eq!(
        rc.rows_examined,
        BUDGET - 1,
        "at BUDGET - 1 rows the fold must examine every row, not report 0. A \
         `rows_examined` of 0 here means the pinned RECONCILE_ROW_BUDGET is below \
         {} — i.e. the audit path has been lowered or disabled, not tuned.",
        BUDGET - 1
    );
    assert!(
        rc.totals_consistent,
        "under the budget the reconciliation must ANSWER true: {:?}",
        rc.detail
    );
    assert!(rc.folded_first_law_holds, "detail: {:?}", rc.detail);
    assert!(
        rc.detail.is_none(),
        "a complete, healthy reconciliation carries no detail: {:?}",
        rc.detail
    );

    // ── arm 2: AT exactly the budget it still ANSWERS ────────────────────────
    // This arm exists for the comparison operator alone: production refuses on
    // `rows > budget`, so `>=` would refuse here while arms 1 and 3 stayed green.
    seed_rows_from(&pic, cid, SEED_UNDER, SEED_AT - SEED_UNDER);
    let rc = reconcile(&pic, cid);
    assert_eq!(
        rc.rows_examined, BUDGET,
        "the budget is INCLUSIVE: at exactly {BUDGET} rows the fold must still \
         run. `rows_examined == 0` here means the production comparison rejects \
         its own budget (`rows >= budget` instead of `rows > budget`)."
    );
    assert!(
        rc.totals_consistent,
        "at exactly the budget the reconciliation must ANSWER true: {:?}",
        rc.detail
    );
    assert!(rc.folded_first_law_holds, "detail: {:?}", rc.detail);
    assert!(rc.detail.is_none(), "detail: {:?}", rc.detail);

    // ── arm 3: one row PAST the budget it is honestly incomplete, never a trap ─
    seed_rows_from(&pic, cid, SEED_AT, SEED_OVER - SEED_AT);
    let rc = reconcile(&pic, cid);
    assert_eq!(
        rc.rows_examined, 0,
        "at BUDGET + 1 rows no fold may be run — the budget is EXCLUSIVE above \
         itself (`rows > budget`)."
    );
    assert!(!rc.totals_consistent, "UNKNOWN is reported as false, not as healthy");
    assert!(!rc.folded_first_law_holds);
    let d = rc.detail.expect("an incomplete reconciliation must say so");
    assert!(d.contains("INCOMPLETE") && d.contains("UNKNOWN"), "detail: {d}");

    // ── the literal pin: the constant itself is 60,000 ───────────────────────
    // The three arms above bind the BOUNDARY relative to whatever the constant
    // is; this binds the constant's VALUE, so re-tuning the pin cannot pass by
    // moving the probes along with it. Production's incompleteness detail
    // reports the budget it actually applied, which is the only place the value
    // is observable from outside the canister.
    //
    // 60,000 is the value the measured bracket justifies —
    // `r1_ac12_the_row_budget_bracket_is_real` (`#[ignore]`, below) grew one
    // canister's map with the budget disabled and found:
    //     4,000,001 rows ANSWERED (28.36e9 instructions, ~7,089/row)
    //     8,000,001 rows TRAPPED  (CanisterInstructionLimitExceeded, 40e9 limit)
    // so the pin sits ~133x below the lowest KNOWN trap point and ~67x below the
    // highest KNOWN answering point. Raising it needs a fresh bracket run;
    // lowering it needs a reason, and either way this assertion must be updated
    // deliberately rather than drifting.
    // Exact pin (SSA round 4 AMBER-5): `d.contains("budget 60000")` also matched
    // "budget 600000", so parse the digits after "budget " out of the detail
    // and compare the parsed number, not a substring.
    let parsed: u64 = d
        .split("budget ")
        .nth(1)
        .expect("detail must contain 'budget <n>'")
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .expect("a digit run must follow 'budget '")
        .parse()
        .expect("the budget digits must parse as u64");
    assert_eq!(
        parsed, 60_000u64,
        "RECONCILE_ROW_BUDGET must be pinned at 60,000 — the value the measured \
         bracket justifies. Production reported a different budget in: {d}"
    );

    // The public O(1) path is unaffected by the audit path's budget.
    assert!(report(&pic, cid).invariant_holds);
}

/// AC-12 (RED-3 round 2) — the bracket, measured rather than extrapolated.
///
/// SSA_LANDED_DIFF_R-1_V2_2026-09-05.md RED-3 / CTO triage
/// `cto-triage-ssa-landed-diff-round2-2026-09-05`: the pinned budget was
/// justified by a cycles slope converted through the AC-10 calibration that
/// RED-2 refuted, and by an admittedly ONE-SIDED bracket — no trap point was
/// ever reached, so "80x headroom" was an extrapolation, not a measurement.
///
/// This test locates the real thing. With the budget taken out of the way
/// (`set_reconcile_row_budget_for_test`), it grows ONE canister's map until
/// `reconcile_supply_invariant` stops answering, and reports:
///
///   * `highest_answering` — the largest row count at which the fold still
///     returned, with its measured instruction count;
///   * `lowest_trapping`   — the smallest row count at which the message was
///     rejected instead;
///
/// and then asserts the pinned `RECONCILE_ROW_BUDGET` sits BELOW
/// `lowest_trapping`, reporting the margin as a number.
///
/// RESOLUTION, stated because a bracket is only as good as it: the row counts
/// are grown by DOUBLING on a single canister, so the bracket is
/// `[highest_answering, 2 * highest_answering]` and no tighter. It is not
/// bisected, and that is a cost decision, not an oversight — rows are seeded
/// through the production write funnel and every near-trap measurement burns
/// most of a message's instruction limit, so refining the bracket costs hours
/// per halving while the margin against the pinned budget is two orders of
/// magnitude. What matters for AC-12 is that a trap point was REACHED and the
/// pin sits far below it, which the numbers below establish without any
/// extrapolation.
///
/// `#[ignore]` because it seeds millions of rows and runs for a long time: it
/// is a MEASUREMENT, re-run when the fold or the pin changes, and its output is
/// what the packet quotes. The cheap `r1_ac12_…_past_its_budget` test above is
/// what runs on every gate and binds the pinned value day to day.
///
///   cargo test -p integration-tests --test r1_supply_integrity_tests -- \
///     --ignored --nocapture r1_ac12_the_row_budget_bracket_is_real
#[test]
#[ignore = "R-1 AC-12 bracket: seeds millions of rows (~minutes); run on demand when the fold or RECONCILE_ROW_BUDGET changes — see PACKET_R1 §AC-12"]
fn r1_ac12_the_row_budget_bracket_is_real() {
    const BUDGET: u64 = 60_000; // canisters/token: RECONCILE_ROW_BUDGET
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());
    disable_row_budget(&pic, cid);

    // ── phase 1: double until it stops answering ─────────────────────────────
    let mut seeded: u32 = 0;
    let mut highest_answering: Option<(u32, u64)> = None;
    let mut lowest_trapping: Option<u32> = None;
    let mut next: u32 = 500_000;

    while lowest_trapping.is_none() {
        seed_rows_from(&pic, cid, seeded, next - seeded);
        seeded = next;
        match measure_reconcile(&pic, cid) {
            Some((instructions, rows)) => {
                assert_eq!(
                    rows,
                    u64::from(seeded) + 1,
                    "with the budget disabled the fold must examine every row"
                );
                println!(
                    "AC-12 bracket: {rows} rows ANSWERED, {instructions} instructions \
                     ({:.1} instructions/row)",
                    instructions as f64 / rows as f64
                );
                highest_answering = Some((seeded, instructions));
                next = seeded.checked_mul(2).expect("row count overflow");
            }
            None => {
                println!("AC-12 bracket: {} rows TRAPPED", u64::from(seeded) + 1);
                lowest_trapping = Some(seeded);
            }
        }
    }

    let (answer_rows, answer_instructions) =
        highest_answering.expect("no row count answered at all");
    let trap_rows = lowest_trapping.expect("no row count trapped");
    let margin = trap_rows as f64 / BUDGET as f64;

    println!(
        "\nAC-12 BRACKET (measured, budget disabled):\n\
         \x20 highest ANSWERING : {answer_rows} rows, {answer_instructions} instructions \
         ({:.1} instructions/row)\n\
         \x20 lowest  TRAPPING  : {trap_rows} rows (message rejected, no answer)\n\
         \x20 pinned budget     : {BUDGET} rows\n\
         \x20 margin            : the trap point is {margin:.1}x the pinned budget\n",
        answer_instructions as f64 / (u64::from(answer_rows) + 1) as f64
    );

    assert!(
        BUDGET < u64::from(trap_rows),
        "the pinned budget {BUDGET} is at or above the measured trap point \
         {trap_rows} — the audit path would trap at its own budget"
    );
    assert!(
        u64::from(answer_rows) > BUDGET,
        "the fold must be measured ANSWERING above the pinned budget, otherwise \
         the pin is not shown to be reachable: highest answering {answer_rows}"
    );
}

fn disable_row_budget(pic: &PocketIc, cid: Principal) {
    pic.update_call(
        cid,
        anon(),
        "set_reconcile_row_budget_for_test",
        candid::encode_one(Some(u64::MAX)).unwrap(),
    )
    .expect("set_reconcile_row_budget_for_test");
}

/// `Some((instructions, rows_examined))` when the fold answered; `None` when the
/// message was rejected with the instruction-limit error class — which, with
/// the budget disabled, is the trap the bracket is looking for. Any other
/// rejection (a real trap, a candid error, a canister-not-found, etc.) is a
/// distinct failure mode from "hit the instruction limit" and is not silently
/// folded into the same bucket — it fails the test loudly instead. The
/// instruction-limit half rests on the STRUCTURAL IC-runtime guarantee (the
/// replica aborts the message), not on an executed measurement: the bracket
/// test that would exercise it, `r1_ac12_the_row_budget_bracket_is_real`, is
/// `#[ignore]`d and never runs in the gate.
fn measure_reconcile(pic: &PocketIc, cid: Principal) -> Option<(u64, u64)> {
    match pic.update_call(
        cid,
        anon(),
        "measure_reconcile_instructions_for_test",
        candid::encode_args(()).unwrap(),
    ) {
        Ok(bytes) => Some(candid::decode_args(&bytes).unwrap()),
        Err(e) if e.error_code == ErrorCode::CanisterInstructionLimitExceeded => {
            println!("AC-12 bracket: rejected — {e:?}");
            None
        }
        Err(e) => panic!(
            "AC-12 bracket: rejected with a non-instruction-limit error, this is not \
             the trap the bracket is looking for: {e:?}"
        ),
    }
}

// =============================================================================
// AC-13 — no test-only symbol ships
// =============================================================================

#[test]
fn r1_ac13_test_only_symbols_are_absent_from_the_production_wasm() {
    let prod = token_wasm();
    let test = token_test_wasm();
    let hooks = [
        "set_supply_totals_for_test",
        "force_v3_none_checkpoint_for_test",
        "seed_balance_rows_for_test",
        "measure_icrc1_transfer_instructions_for_test",
        "measure_icrc2_transfer_from_instructions_for_test",
        "set_reconcile_row_budget_for_test",
        "measure_reconcile_instructions_for_test",
        "measure_verify_supply_invariant_instructions_for_test",
    ];
    for h in hooks {
        assert_eq!(
            count_occurrences(&prod, h.as_bytes()),
            0,
            "`{h}` MUST NOT appear in the production Wasm"
        );
        assert!(
            count_occurrences(&test, h.as_bytes()) > 0,
            "`{h}` must appear in the TEST Wasm — a 0/0 result proves nothing"
        );
    }
}

fn count_occurrences(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

// =============================================================================
// AC-10 / S4(f) — the hot-path cost ceiling
// =============================================================================
//
// METHOD (rewritten for RED-2 round 2 — SSA_LANDED_DIFF_R-1_V2_2026-09-05.md,
// CTO triage `cto-triage-ssa-landed-diff-round2-2026-09-05`):
//
//   DIRECT `performance_counter(0)` deltas on BOTH sides. Nothing is derived,
//   converted, calibrated or extrapolated. There is no cycles term anywhere in
//   this test any more.
//
//   * before — `stsh_token_base_115526d_measure_test.wasm`: the base source at
//     115526d, unchanged, built `--features testing` with the two measurement
//     wrappers appended VERBATIM from this tree
//     (scripts/build_token_base_measure_wasm.sh).
//   * after  — `stsh_token_test.wasm` from this tree.
//   * both sides run the SAME wrapper (two counter reads and one real call to
//     the production endpoint), so the wrapper's own cost is identical and
//     cancels in the difference; both are `--features testing` builds, so any
//     testing-gated constant is identical on both sides too.
//   * 5 samples per endpoint per side, first (warm-up) sample discarded, same
//     genesis state, same principals, same arguments, one call per message
//     (instruction counters reset per message). Medians compared.
//
// WHY THE OLD METHOD WAS WITHDRAWN. V3 measured cycles burned per update
// message on the two PRODUCTION Wasms and converted the delta to instructions
// through a cycles-per-instruction slope fitted between two DIFFERENT endpoints
// (different message, payload and stable-map access pattern). Its own comment
// conceded the slope was an over-estimate and the converted delta therefore an
// under-estimate — the wrong direction for an upper limit. The SSA then built
// the direct comparison and found the real deltas roughly four times the
// converted ones, with AC-10 still green. A ceiling test that under-estimates
// is not conservative; it is blind. The conversion is gone.
//
// CEILING (unchanged, per CTO ruling
// `cto-ruling-r1-hotpath-ceiling-rerule-2026-09-05` and re-affirmed by the
// round-2 triage): 6,000 instructions or 6 %, whichever is LARGER.
//
// CARRIED NOTE (the ruling's): any future change to `write_balance` re-measures
// against THIS pin, by this method.
//
// If the direct delta exceeds the pin, this test FAILS and the builder STOPS
// and returns the numbers — it does not tune the measurement, the pin, or the
// design. That is the brief's S4(f) disposition and the round-2 triage's
// explicit instruction.

const COST_SAMPLES: usize = 5;
const COST_CEILING_INSTRUCTIONS: u64 = 6_000;
const COST_CEILING_FRACTION: f64 = 0.06;

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}

/// The measurement itself, asserted against the ceiling. It PRINTS every
/// sample, so the packet's table is the test's own output rather than a retyped
/// number.
#[test]
fn r1_ac10_hot_path_cost_is_within_the_ceiling() {
    let (base_xfer, base_tf) = sample_instructions(token_base_measure_wasm(), "BASE 115526d");
    let (fixed_xfer, fixed_tf) = sample_instructions(token_test_wasm(), "FIXED");

    // BOTH endpoints are evaluated before anything fails: a STOP-and-return has
    // to carry the complete measurement, not the first arm that happened to
    // break. Half a table is not a returnable measurement.
    let mut over: Vec<String> = Vec::new();
    over.extend(check_ceiling("icrc1_transfer", base_xfer, fixed_xfer));
    over.extend(check_ceiling("icrc2_transfer_from", base_tf, fixed_tf));
    assert!(over.is_empty(), "{}", over.join("\n"));
}

/// Both ceiling arms, in INSTRUCTIONS, from directly measured medians. Returns
/// the ceiling breach for this endpoint, if any, rather than panicking, so the
/// caller can report every endpoint before it stops.
fn check_ceiling(endpoint: &str, base: u64, fixed: u64) -> Option<String> {
    let delta = fixed as i64 - base as i64;
    let rel = delta as f64 / base as f64;

    println!(
        "AC-10 {endpoint}: base = {base} instructions, fixed = {fixed} \
         instructions, delta = {delta:+} ({:+.3} % of base). Measured directly \
         on both sides with performance_counter(0); nothing derived.",
        rel * 100.0
    );

    // A cost REDUCTION is trivially inside the ceiling.
    if delta <= 0 {
        return None;
    }
    if delta as u64 <= COST_CEILING_INSTRUCTIONS || rel <= COST_CEILING_FRACTION {
        return None;
    }
    Some(format!(
        "AC-10 CEILING EXCEEDED for {endpoint}: {delta:+} instructions ({:+.3} % \
         of the {base} measured on the base Wasm), against a ceiling of {} \
         instructions OR {:.1} %, whichever is larger. Per brief S4(f) and the \
         round-2 triage this is a STOP-and-return for re-ruling: report these \
         numbers, do not tune the measurement, the pin, or the design.",
        rel * 100.0,
        COST_CEILING_INSTRUCTIONS,
        COST_CEILING_FRACTION * 100.0
    ))
}

/// `(icrc1_transfer, icrc2_transfer_from)` median instruction counts for one
/// Wasm, measured inside the canister across one real call per message.
///
/// HARDEN-03 (CAPACITY lane): both arms are driven at the REALIZABLE WORST-CASE
/// KEY SHAPE rather than the default-subaccount shape this harness carried
/// through HARDEN-02. `alice`/`bob`/`carol` were already 29-byte principals, so
/// the previous run keyed balances at 30 bytes and the allowance compound key at
/// 4+30+4+30 = 68. Giving each account a NONZERO 32-byte subaccount — a zero one
/// normalizes to `None` under QA-DEF-021 and would silently shorten the key back
/// — takes each balance key to 62 bytes and the allowance key to
/// 4+62+4+62 = 132, which is the largest `compound_key` can actually produce
/// (`MAX_ALLOWANCE_KEY_LEN` = 136 carries 2 bytes of slack per half).
///
/// This does NOT change what AC-10 compares: both sides run identical arguments,
/// so the key shape cancels in the difference exactly as the wrapper's own cost
/// does. It changes the OPERATING POINT at which the delta is taken, from a
/// mid-range key to the worst case the production path can be driven to.
fn sample_instructions(wasm: Vec<u8>, label: &str) -> (u64, u64) {
    const FROM_SUB: [u8; 32] = [0x11; 32];
    const TO_SUB: [u8; 32] = [0x22; 32];
    const SPENDER_SUB: [u8; 32] = [0x33; 32];
    let from = Account { owner: alice(), subaccount: Some(FROM_SUB) };
    let to = Account { owner: carol(), subaccount: Some(TO_SUB) };
    let spender = Account { owner: bob(), subaccount: Some(SPENDER_SUB) };

    let pic = PocketIc::new();
    let cid = install(&pic, wasm, genesis_one());

    // Genesis credits alice's DEFAULT account, so the subaccount the measured
    // calls debit is seeded through the production endpoint first. This runs
    // before the counters are read and is not part of any sample.
    let seed = TransferArgs {
        from_subaccount: None,
        to: from.clone(),
        amount: Nat::from(1_000_000u32),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, alice(), "icrc1_transfer", candid::encode_one(&seed).unwrap())
        .expect("seed icrc1_transfer call");
    let seeded: Result<Nat, TransferError> = candid::decode_one(&bytes).unwrap();
    seeded.expect("seeding the worst-case from-subaccount must succeed");

    // The allowance the transfer_from arm spends, written at the 132-byte key.
    let approve_args = ApproveArgs {
        from_subaccount: Some(FROM_SUB),
        spender: spender.clone(),
        amount: Nat::from(1_000_000u32),
        expected_allowance: None,
        // Bounded 1 h, well inside the 24 h dev007 cap this tree enforces and
        // accepted by the 115526d base, which has no cap.
        expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, alice(), "icrc2_approve", candid::encode_one(&approve_args).unwrap())
        .expect("icrc2_approve call");
    let approved: Result<Nat, ApproveError> = candid::decode_one(&bytes).unwrap();
    approved.expect("worst-case-key approve must succeed");

    let xfer_args = TransferArgs {
        from_subaccount: Some(FROM_SUB),
        to: to.clone(),
        amount: Nat::from(1u32),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let mut xfer: Vec<u64> = Vec::new();
    for _ in 0..COST_SAMPLES + 1 {
        let bytes = pic
            .update_call(
                cid,
                alice(),
                "measure_icrc1_transfer_instructions_for_test",
                candid::encode_one(&xfer_args).unwrap(),
            )
            .expect("measure icrc1_transfer");
        let (n, ok): (u64, bool) = candid::decode_args(&bytes).unwrap();
        assert!(ok, "the measured transfer must succeed");
        xfer.push(n);
    }
    // Drop the warm-up sample: the first message on a fresh canister pays
    // one-off costs.
    let xfer = xfer.split_off(1);
    println!("AC-10 icrc1_transfer {label} instruction samples: {xfer:?}");

    let tf_args = TransferFromArgs {
        spender_subaccount: Some(SPENDER_SUB),
        from: from.clone(),
        to: to.clone(),
        amount: Nat::from(1u32),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let mut tf: Vec<u64> = Vec::new();
    for _ in 0..COST_SAMPLES + 1 {
        let bytes = pic
            .update_call(
                cid,
                bob(),
                "measure_icrc2_transfer_from_instructions_for_test",
                candid::encode_one(&tf_args).unwrap(),
            )
            .expect("measure icrc2_transfer_from");
        let (n, ok): (u64, bool) = candid::decode_args(&bytes).unwrap();
        assert!(ok, "the measured transfer_from must succeed");
        tf.push(n);
    }
    let tf = tf.split_off(1);
    println!("AC-10 icrc2_transfer_from {label} instruction samples: {tf:?}");

    (median(xfer), median(tf))
}

// =============================================================================
// BR-35 (lane R-11) — the public supply query is O(1) and bounded
//
// `canisters/token/src/lib.rs`'s `evaluate_supply_invariant` claims the query
// (MEASURED: h1_public_supply_query_cost_is_o1_and_bounded)
// "can never trap on the instruction limit (H-1)". Structurally that is true by
// construction — `ledger_maps::sum_balances()` / `sum_locks()` return MAINTAINED
// running totals, so there is no fold over BALANCES on the public path — but
// nothing in the tree MEASURED it, and the regression the claim guards against
// (reintroducing a fold) is invisible at any fixture size a normal test uses.
//
// This measures the query's instruction cost at three balance-map sizes and
// asserts the cost does not track the size. Distinct from BR-07/08/09, which are
// about the post_upgrade MIGRATION fold, not the steady-state query.
// =============================================================================

/// The O(1) tolerance band: the delta between any measured fixture size and the
/// smallest one is at most 5% of the smallest one's cost. A literal, not derived
/// from the measurements it judges.
///
/// Deliberately a BAND, not an ordering. `cost(1) <= cost(1_001) <=
/// cost(10_001)` orders three quantities the O(1) claim says are EQUAL, and a
/// correct implementation can put the midpoint one instruction below the
/// smallest on branch/encoding noise alone — which would RED a correct
/// implementation deterministically under PocketIC's exact instruction counting.
const O1_TOLERANCE_NUM: u64 = 5;
const O1_TOLERANCE_DEN: u64 = 100;

fn measure_supply_query(pic: &PocketIc, cid: Principal) -> u64 {
    let bytes = pic
        .update_call(
            cid,
            anon(),
            "measure_verify_supply_invariant_instructions_for_test",
            candid::encode_args(()).unwrap(),
        )
        .expect("measure_verify_supply_invariant_instructions_for_test");
    candid::decode_one::<u64>(&bytes).expect("decode instruction count")
}

#[test]
fn h1_public_supply_query_cost_is_o1_and_bounded() {
    let pic = PocketIc::new();
    let cid = install(&pic, token_test_wasm(), genesis_one());

    // N = 1 (the genesis row alone), then 1,001, then 10,001. Seeded
    // incrementally so each measurement is taken on the SAME canister — a fresh
    // install per size would fold install-to-install variation into the deltas.
    let cost_1 = measure_supply_query(&pic, cid);
    assert!(
        cost_1 > 0,
        "fixture guard: the measurement must report real instructions consumed"
    );

    seed_rows_from(&pic, cid, 0, 1_000);
    let cost_1k = measure_supply_query(&pic, cid);

    seed_rows_from(&pic, cid, 1_000, 9_000);
    let cost_10k = measure_supply_query(&pic, cid);

    let band = cost_1 * O1_TOLERANCE_NUM / O1_TOLERANCE_DEN;
    println!(
        "BR-35 supply query: cost(1)={cost_1} cost(1_001)={cost_1k} cost(10_001)={cost_10k}; \
         5% band on cost(1) = {band}"
    );

    assert!(
        cost_10k.abs_diff(cost_1) <= band,
        "H-1 VIOLATED: the public supply query's cost tracks the balance-map size. \
         cost(1)={cost_1}, cost(10_001)={cost_10k}, delta={} exceeds the 5% band {band}. \
         The query is no longer O(1) — a fold over the balance map has come back.",
        cost_10k.abs_diff(cost_1)
    );
    assert!(
        cost_1k.abs_diff(cost_1) <= band,
        "H-1 VIOLATED at the midpoint fixture: cost(1)={cost_1}, cost(1_001)={cost_1k}, \
         delta={} exceeds the 5% band {band}",
        cost_1k.abs_diff(cost_1)
    );

    // And an absolute ceiling: the O(1) cost must sit far under the message
    // instruction limit, which is the trap-freedom half of the claim.
    const MESSAGE_INSTRUCTION_LIMIT: u64 = 5_000_000_000;
    assert!(
        cost_10k * 1_000 < MESSAGE_INSTRUCTION_LIMIT,
        "the supply query costs {cost_10k} instructions — within 1000x of the message \
         instruction limit {MESSAGE_INSTRUCTION_LIMIT}. The trap-freedom claim no longer has \
         three orders of magnitude behind it."
    );
}
