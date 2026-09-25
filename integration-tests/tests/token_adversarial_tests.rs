// =============================================================================
// STSH — Adversarial ICRC Suite (GTM Step 2) · BRIEF_ADVERSARIAL_ICRC_SUITE.md V2.1
// =============================================================================
//
// Live attack tests over the token canister, layered ALONGSIDE the 69-test
// conformance suite (token_icrc_conformance_tests.rs). Each asserts a SAFETY
// INVARIANT: GREEN = attack defended. A RED that reflects a real defect is a
// FINDING — halt + report, never weaken the assertion to force green.
//
// IC concurrency (SSA-confirmed): the token has NO `.await` — every update is a
// single atomic message; there is no intra-call TOCTOU. Every "race" here is an
// explicit SERIAL message ordering with a pinned post-state, never an interleave.
//
// Angles: (A) custom staking endpoints [highest priority], (B) allowance
// interleaving/dedup, (C) arithmetic boundaries (production-reachable ingress),
// (D) reachable zero-fee policy [incl. the SSA-predicted oversized-Nat fee RED].
// Plus residuals: F-DBR-1 (expiry-boundary regression), EXT-DBR-001
// (supported_standards normative strings).
//
// Public ingress + production Wasm only (no `#[cfg(feature="testing")]` mutator
// establishes a live finding — reachability rule §C).
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read stsh_token Wasm at {}: {}", path, e))
}

// ── Constants (must match canisters/token/src/lib.rs) ─────────────────────────
const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;
const LIVE_FEE: u128 = 0; // DEFAULT_FEE — asserted at setup
const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const PERMITTED_DRIFT_NS: u64 = 5 * 60 * 1_000_000_000;

// ── Wire mirrors ──────────────────────────────────────────────────────────────
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferArgs {
    from_subaccount: Option<[u8; 32]>, to: Account, amount: Nat, fee: Option<Nat>,
    memo: Option<Vec<u8>>, created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TransferError {
    BadFee { expected_fee: Nat }, BadBurn { min_burn_amount: Nat }, InsufficientFunds { balance: Nat },
    TooOld, CreatedInFuture { ledger_time: u64 }, Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable, GenericError { error_code: Nat, message: String },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>, spender: Account, amount: Nat, expected_allowance: Option<Nat>,
    expires_at: Option<u64>, fee: Option<Nat>, memo: Option<Vec<u8>>, created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ApproveError {
    BadFee { expected_fee: Nat }, InsufficientFunds { balance: Nat }, AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 }, TooOld, CreatedInFuture { ledger_time: u64 }, Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable, GenericError { error_code: Nat, message: String },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>, from: Account, to: Account, amount: Nat, fee: Option<Nat>,
    memo: Option<Vec<u8>>, created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TransferFromError {
    BadFee { expected_fee: Nat }, BadBurn { min_burn_amount: Nat }, InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat }, TooOld, CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat }, TemporarilyUnavailable, GenericError { error_code: Nat, message: String },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllowanceArgs { account: Account, spender: Account }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Allowance { allowance: Nat, expires_at: Option<u64> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct StandardRecord { name: String, url: String }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String, category_name: String, amount: u128, recipient: Principal,
    subaccount: Option<[u8; 32]>, lock_policy: LockPolicy, vesting_policy: Option<VestingPolicy>,
    created_at_genesis: bool, genesis_timestamp_ns: u64,
}
#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>, treasury: Principal, staking_canister: Principal,
    fee_collector: Option<Principal>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SupplyInvariantReport {
    fixed_max_supply: u128, sum_all_balances: u128, staking_locked_total: u128,
    fee_reserve_total: u128, invariant_holds: bool, checked_at_ns: u64, violation_detail: Option<String>,
    // K3-002b (P-ARITH): additive per-site overflow attribution.
    arithmetic_error: Option<ArithmeticErrorReport>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ArithmeticErrorReport {
    balances_overflow: bool, staking_locks_overflow: bool, balances_plus_fee_overflow: bool,
}

// ── Principals ────────────────────────────────────────────────────────────────
fn p(n: u8) -> Principal { let mut b = [0u8; 29]; b[0] = n; Principal::from_slice(&b) }
fn anon() -> Principal { Principal::anonymous() }
fn alice() -> Principal { p(0xA1) }
fn bob() -> Principal { p(0xB2) }
fn dexp() -> Principal { p(0xD4) }
fn feecol() -> Principal { p(0xF1) }
/// The init-configured staking canister — the ONLY principal allowed to lock/unlock.
fn staker() -> Principal { p(0x02) }
fn acct(owner: Principal) -> Account { Account { owner, subaccount: None } }
fn acct_sub(owner: Principal, tag: u8) -> Account {
    let mut s = [0u8; 32]; s[31] = tag; Account { owner, subaccount: Some(s) }
}

// ── Plumbing ──────────────────────────────────────────────────────────────────
fn create_canister(pic: &PocketIc) -> Principal { let c = pic.create_canister(); pic.add_cycles(c, 4_000_000_000_000u128); c }
fn raw_update(pic: &PocketIc, cid: Principal, caller: Principal, m: &str, a: Vec<u8>) -> Result<Vec<u8>, String> {
    pic.update_call(cid, caller, m, a).map_err(|e| format!("{:?}", e))
}
fn raw_query(pic: &PocketIc, cid: Principal, caller: Principal, m: &str, a: Vec<u8>) -> Result<Vec<u8>, String> {
    pic.query_call(cid, caller, m, a).map_err(|e| format!("{:?}", e))
}
fn decode<T>(label: &str, bytes: Vec<u8>) -> T where T: CandidType + for<'de> serde::Deserialize<'de> {
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}
fn q<T>(pic: &PocketIc, cid: Principal, m: &str, a: Vec<u8>) -> T where T: CandidType + for<'de> serde::Deserialize<'de> {
    decode(m, raw_query(pic, cid, anon(), m, a).unwrap_or_else(|e| panic!("{}: query rejected: {}", m, e)))
}
fn to_u128(n: &Nat) -> u128 { n.0.to_string().parse::<u128>().expect("Nat exceeds u128") }
fn now_ns(pic: &PocketIc) -> u64 { pic.get_time().as_nanos_since_unix_epoch() as u64 }
fn live_fee(pic: &PocketIc, cid: Principal) -> u128 { to_u128(&q::<Nat>(pic, cid, "icrc1_fee", candid::encode_args(()).unwrap())) }
fn balance_of(pic: &PocketIc, cid: Principal, a: &Account) -> u128 {
    to_u128(&q::<Nat>(pic, cid, "icrc1_balance_of", candid::encode_one(a).unwrap()))
}
fn liquid_balance(pic: &PocketIc, cid: Principal, holder: Principal) -> u128 {
    q::<u128>(pic, cid, "liquid_balance", candid::encode_one(holder).unwrap())
}
fn staking_locked_balance(pic: &PocketIc, cid: Principal, holder: Principal) -> u128 {
    q::<u128>(pic, cid, "staking_locked_balance", candid::encode_one(holder).unwrap())
}
fn supply_report(pic: &PocketIc, cid: Principal) -> SupplyInvariantReport {
    q::<SupplyInvariantReport>(pic, cid, "verify_supply_invariant", candid::encode_args(()).unwrap())
}

fn transfer(pic: &PocketIc, cid: Principal, caller: Principal, a: &TransferArgs) -> Result<Nat, TransferError> {
    decode("icrc1_transfer", raw_update(pic, cid, caller, "icrc1_transfer", candid::encode_one(a).unwrap())
        .unwrap_or_else(|e| panic!("icrc1_transfer rejected (trap): {}", e)))
}
fn approve(pic: &PocketIc, cid: Principal, caller: Principal, a: &ApproveArgs) -> Result<Nat, ApproveError> {
    decode("icrc2_approve", raw_update(pic, cid, caller, "icrc2_approve", candid::encode_one(a).unwrap())
        .unwrap_or_else(|e| panic!("icrc2_approve rejected (trap): {}", e)))
}
fn transfer_from(pic: &PocketIc, cid: Principal, caller: Principal, a: &TransferFromArgs) -> Result<Nat, TransferFromError> {
    decode("icrc2_transfer_from", raw_update(pic, cid, caller, "icrc2_transfer_from", candid::encode_one(a).unwrap())
        .unwrap_or_else(|e| panic!("icrc2_transfer_from rejected (trap): {}", e)))
}
fn allowance(pic: &PocketIc, cid: Principal, owner: Principal, spender: Principal) -> Allowance {
    q::<Allowance>(pic, cid, "icrc2_allowance",
        candid::encode_one(AllowanceArgs { account: acct(owner), spender: acct(spender) }).unwrap())
}
/// lock_for_staking called AS the staking canister (the authorised caller).
fn lock(pic: &PocketIc, cid: Principal, holder: Principal, amount: u128) -> Result<(), String> {
    decode("lock_for_staking", raw_update(pic, cid, staker(), "lock_for_staking",
        candid::encode_args((holder, amount)).unwrap()).unwrap_or_else(|e| panic!("lock trap: {}", e)))
}
fn unlock(pic: &PocketIc, cid: Principal, holder: Principal, amount: u128) -> Result<(), String> {
    decode("unlock_from_staking", raw_update(pic, cid, staker(), "unlock_from_staking",
        candid::encode_args((holder, amount)).unwrap()).unwrap_or_else(|e| panic!("unlock trap: {}", e)))
}

fn simple_transfer(pic: &PocketIc, cid: Principal, from: Principal, to: Principal, amount: u128) -> Result<Nat, TransferError> {
    transfer(pic, cid, from, &TransferArgs {
        from_subaccount: None, to: acct(to), amount: Nat::from(amount), fee: None, memo: None, created_at_time: None,
    })
}

/// Deploy STSH with full supply to alice, staking_canister = staker().
fn deploy(pic: &PocketIc) -> Principal {
    let cid = create_canister(pic);
    let init = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".into(), category_name: "All".into(), amount: TOTAL_SUPPLY, recipient: alice(),
            subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid, vesting_policy: None,
            created_at_genesis: false, genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01), staking_canister: staker(), fee_collector: Some(feecol()),
    };
    pic.install_canister(cid, token_wasm(), candid::encode_one(&init).unwrap(), None);
    assert_eq!(live_fee(pic, cid), LIVE_FEE, "live fee != LIVE_FEE (0) — update suite");
    cid
}
fn setup() -> (PocketIc, Principal) { let pic = PocketIc::new(); let cid = deploy(&pic); (pic, cid) }

/// Conservation oracle (SSA-corrected): default-account identity + the public
/// system supply invariant. No balance-map enumeration.
fn assert_conservation(pic: &PocketIc, cid: Principal, owner: Principal) {
    let liquid = liquid_balance(pic, cid, owner);
    let locked = staking_locked_balance(pic, cid, owner);
    let bal = balance_of(pic, cid, &acct(owner));
    assert_eq!(liquid + locked, bal, "default-account: liquid+locked must == icrc1_balance_of");
    let rep = supply_report(pic, cid);
    assert!(rep.invariant_holds, "system supply invariant must hold: {:?}", rep.violation_detail);
}

// =============================================================================
// ANGLE A — custom staking endpoint attacks (HIGHEST PRIORITY; no reference oracle)
// =============================================================================

// A1 — transfer must respect the lock: debit against LIQUID, never total.
#[test]
fn adv_a1_transfer_respects_staking_lock() {
    let (pic, cid) = setup();
    let start = balance_of(&pic, cid, &acct(alice()));
    let lock_amt = 400 * STSH;
    lock(&pic, cid, alice(), lock_amt).expect("lock ok");
    assert_eq!(staking_locked_balance(&pic, cid, alice()), lock_amt);
    assert_eq!(liquid_balance(&pic, cid, alice()), start - lock_amt);
    assert_conservation(&pic, cid, alice());

    // Attempt to move MORE than liquid (would spend locked tokens) — must fail,
    // no partial move, locked + balances unchanged.
    let liquid = start - lock_amt;
    let over = liquid + 1;
    let r = simple_transfer(&pic, cid, alice(), bob(), over);
    assert!(matches!(r, Err(TransferError::InsufficientFunds { .. })),
        "moving > liquid must be InsufficientFunds (locked tokens not transferable); got {:?}", r);
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start, "no partial debit");
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 0, "recipient not credited");
    assert_eq!(staking_locked_balance(&pic, cid, alice()), lock_amt, "lock intact");
    assert_conservation(&pic, cid, alice());

    // A transfer WITHIN liquid succeeds; the lock stays intact.
    let ok = simple_transfer(&pic, cid, alice(), bob(), liquid);
    assert!(ok.is_ok(), "transfer within liquid must succeed; got {:?}", ok);
    assert_eq!(staking_locked_balance(&pic, cid, alice()), lock_amt, "lock still intact after a liquid transfer");
    assert_eq!(liquid_balance(&pic, cid, alice()), 0, "all liquid spent");
    assert_conservation(&pic, cid, alice());
    assert_conservation(&pic, cid, bob());
}

// A2 — the two SERIAL orderings (no interleave; token has no .await).
#[test]
fn adv_a2_lock_transfer_serial_orders() {
    // Order 1: lock(L) → transfer(T).
    {
        let (pic, cid) = setup();
        let start = balance_of(&pic, cid, &acct(alice()));
        let l = 600 * STSH;
        lock(&pic, cid, alice(), l).unwrap();
        let liquid = start - l;
        // T > liquid rejected, unchanged.
        assert!(matches!(simple_transfer(&pic, cid, alice(), bob(), liquid + STSH), Err(TransferError::InsufficientFunds { .. })));
        assert_eq!(staking_locked_balance(&pic, cid, alice()), l);
        assert_eq!(balance_of(&pic, cid, &acct(alice())), start);
        // T <= liquid succeeds, lock intact.
        assert!(simple_transfer(&pic, cid, alice(), bob(), liquid).is_ok());
        assert_eq!(staking_locked_balance(&pic, cid, alice()), l);
        assert_conservation(&pic, cid, alice());
    }
    // Order 2: transfer(T) → lock(L). After the transfer lowers total, lock is
    // bounded by the NEW liquid — cannot lock more than remains.
    {
        let (pic, cid) = setup();
        let start = balance_of(&pic, cid, &acct(alice()));
        let t = 700 * STSH;
        assert!(simple_transfer(&pic, cid, alice(), bob(), t).is_ok());
        let remaining = start - t;
        assert_eq!(balance_of(&pic, cid, &acct(alice())), remaining);
        // Lock more than remains → rejected.
        assert!(lock(&pic, cid, alice(), remaining + STSH).is_err(), "cannot lock more than the reduced liquid");
        assert_eq!(staking_locked_balance(&pic, cid, alice()), 0, "no lock recorded on the failed over-lock");
        // Lock exactly what remains → ok.
        assert!(lock(&pic, cid, alice(), remaining).is_ok());
        assert_eq!(liquid_balance(&pic, cid, alice()), 0);
        assert_conservation(&pic, cid, alice());
    }
}

// A3 — double-unlock / unlock > locked: Err, no underflow / no spurious liquid.
#[test]
fn adv_a3_unlock_over_and_double() {
    let (pic, cid) = setup();
    let start = balance_of(&pic, cid, &acct(alice()));
    let l = 300 * STSH;
    lock(&pic, cid, alice(), l).unwrap();
    // Unlock MORE than locked → Err, unchanged.
    assert!(unlock(&pic, cid, alice(), l + 1).is_err(), "unlock > locked must Err");
    assert_eq!(staking_locked_balance(&pic, cid, alice()), l, "locked unchanged after failed over-unlock");
    assert_eq!(liquid_balance(&pic, cid, alice()), start - l, "no spurious liquid inflation");
    // Full unlock, then a SECOND unlock → Err, no underflow / no minting.
    assert!(unlock(&pic, cid, alice(), l).is_ok());
    assert_eq!(staking_locked_balance(&pic, cid, alice()), 0);
    assert_eq!(liquid_balance(&pic, cid, alice()), start, "liquid restored exactly, not more");
    assert!(unlock(&pic, cid, alice(), 1).is_err(), "second unlock (nothing locked) must Err");
    assert_eq!(staking_locked_balance(&pic, cid, alice()), 0);
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start, "balance never inflated by unlock underflow");
    assert_conservation(&pic, cid, alice());
}

// A4 — lock > liquid rejects UNCHANGED (no saturate / partial lock / mutation).
#[test]
fn adv_a4_lock_over_liquid_rejects_unchanged() {
    let (pic, cid) = setup();
    let start = balance_of(&pic, cid, &acct(alice()));
    assert!(lock(&pic, cid, alice(), start + 1).is_err(), "lock > liquid must Err");
    assert_eq!(staking_locked_balance(&pic, cid, alice()), 0, "no lock recorded (no partial/saturating lock)");
    assert_eq!(liquid_balance(&pic, cid, alice()), start, "liquid unchanged");
    assert_conservation(&pic, cid, alice());
}

// A5 — no locked double-count / double-spend across lock → unlock → transfer.
#[test]
fn adv_a5_lock_unlock_transfer_no_doublecount() {
    let (pic, cid) = setup();
    let start = balance_of(&pic, cid, &acct(alice()));
    let l = 500 * STSH;
    lock(&pic, cid, alice(), l).unwrap();
    unlock(&pic, cid, alice(), l).unwrap();
    // After lock+unlock, the FULL balance is liquid again and transferable exactly once.
    assert_eq!(liquid_balance(&pic, cid, alice()), start);
    assert!(simple_transfer(&pic, cid, alice(), bob(), start).is_ok(), "full balance transferable after unlock");
    assert_eq!(balance_of(&pic, cid, &acct(alice())), 0);
    assert_eq!(balance_of(&pic, cid, &acct(bob())), start, "recipient got exactly the balance, no double-count");
    // No residual lock left dangling on a zero balance.
    assert_eq!(staking_locked_balance(&pic, cid, alice()), 0);
    assert_conservation(&pic, cid, alice());
    assert_conservation(&pic, cid, bob());
}

// A6 — caller guard: ONLY the staking canister may lock/unlock.
#[test]
fn adv_a6_lock_unlock_caller_guard() {
    let (pic, cid) = setup();
    // A non-staking principal calling lock/unlock must be rejected (guard traps).
    let l = raw_update(&pic, cid, alice(), "lock_for_staking", candid::encode_args((alice(), STSH)).unwrap());
    assert!(l.is_err(), "non-staking principal must NOT be able to lock; got {:?}", l);
    let u = raw_update(&pic, cid, bob(), "unlock_from_staking", candid::encode_args((alice(), STSH)).unwrap());
    assert!(u.is_err(), "non-staking principal must NOT be able to unlock; got {:?}", u);
    // Anonymous too.
    let an = raw_update(&pic, cid, anon(), "lock_for_staking", candid::encode_args((alice(), STSH)).unwrap());
    assert!(an.is_err(), "anonymous must NOT be able to lock; got {:?}", an);
    // Nothing was locked by the rejected calls.
    assert_eq!(staking_locked_balance(&pic, cid, alice()), 0);
    assert_conservation(&pic, cid, alice());
}

// =============================================================================
// ANGLE B — allowance interleaving / dedup (serial ordering; token has no .await)
// =============================================================================

/// H-01: the lifetime this suite's approves request when a case does not care —
/// 1 h, well inside the 24 h `MAX_APPROVAL_TTL_NS` cap.
const APPROVAL_TTL_NS: u64 = 60 * 60 * 1_000_000_000;

/// H-01 / dev007: `expires_at` is MANDATORY on `icrc2_approve` for any approve
/// that WRITES a row, so a `None` from a case that does not care about the expiry
/// is filled with a bounded default here and the case keeps testing what it was
/// written to test. Cases that DO care — the F-006 already-expired arm, the
/// boundary arm — pass an explicit `Some(..)` and are untouched.
///
/// The default is DERIVED FROM `created_at_time` when one is supplied, the way the
/// shipped wallet derives it, because `approve_dedup_key` hashes the whole
/// argument: an expiry read from the clock per attempt would differ between an
/// original and its replay and break dedup on the very path the replay case tests.
///
/// A ZERO-amount approve keeps `None`: it is revocation, writes no row, and is
/// exempt from the rule (I-A1).
fn approve_args(pic: &PocketIc, spender: Principal, amount: u128, expires_at: Option<u64>, created_at_time: Option<u64>) -> ApproveArgs {
    let expires_at = match (expires_at, amount) {
        (Some(e), _) => Some(e),
        (None, 0) => None,
        (None, _) => Some(created_at_time.unwrap_or_else(|| now_ns(pic)) + APPROVAL_TTL_NS),
    };
    ApproveArgs {
        from_subaccount: None, spender: acct(spender), amount: Nat::from(amount), expected_allowance: None,
        expires_at, fee: None, memo: None, created_at_time,
    }
}
fn tf_args(from: Principal, to: Principal, amount: u128, created_at_time: Option<u64>) -> TransferFromArgs {
    TransferFromArgs {
        spender_subaccount: None, from: acct(from), to: acct(to), amount: Nat::from(amount),
        fee: None, memo: None, created_at_time,
    }
}

// B1 — no over-draw: Σ successful transfer_from ≤ approved allowance, always.
#[test]
fn adv_b1_allowance_no_overdraw() {
    let (pic, cid) = setup();
    let approved = 100 * STSH;
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), approved, None, None)).unwrap();
    // Three serial draws of 40 each: 40, 40 succeed (80); the third (→120) fails.
    let d = 40 * STSH;
    let mut drawn = 0u128;
    for i in 0..3 {
        let r = transfer_from(&pic, cid, dexp(), &tf_args(alice(), bob(), d, None));
        match r {
            Ok(_) => drawn += d,
            Err(TransferFromError::InsufficientAllowance { allowance }) => {
                assert_eq!(to_u128(&allowance), approved - drawn, "reported allowance == remaining");
                assert!(i == 2, "only the third draw should exhaust the allowance");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }
    assert!(drawn <= approved, "Σ successful ({}) must be ≤ approved ({})", drawn, approved);
    assert_eq!(drawn, 80 * STSH);
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), approved - drawn, "remaining allowance exact");
    assert_eq!(balance_of(&pic, cid, &acct(bob())), drawn, "bob received exactly the drawn amount");
    assert_conservation(&pic, cid, alice());
}

// B2 — dedup-window replay: identical approve / transfer_from is deduped.
#[test]
fn adv_b2_dedup_window_replay() {
    let (pic, cid) = setup();
    let t = now_ns(&pic);
    // approve dedup
    let a = approve_args(&pic, dexp(), 50 * STSH, None, Some(t));
    let blk1 = approve(&pic, cid, alice(), &a).unwrap();
    match approve(&pic, cid, alice(), &a) {
        Err(ApproveError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, blk1, "approve replay → original block"),
        other => panic!("approve replay must be Duplicate; got {:?}", other),
    }
    // allowance applied exactly once (not doubled)
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 50 * STSH, "allowance applied once");
    // transfer_from dedup
    let tf = tf_args(alice(), bob(), 10 * STSH, Some(t));
    let tblk = transfer_from(&pic, cid, dexp(), &tf).unwrap();
    match transfer_from(&pic, cid, dexp(), &tf) {
        Err(TransferFromError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, tblk, "tf replay → original block"),
        other => panic!("transfer_from replay must be Duplicate; got {:?}", other),
    }
    // exactly ONE 10-STSH move happened (not two)
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 10 * STSH, "transfer applied once");
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 40 * STSH, "allowance decremented once");
    assert_conservation(&pic, cid, alice());
}

// B3 — expired allowance cannot be drawn (inclusive boundary).
#[test]
fn adv_b3_expired_allowance_undrawable() {
    let (pic, cid) = setup();
    let exp = now_ns(&pic) + 60 * 1_000_000_000; // +60s
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), 100 * STSH, Some(exp), None)).unwrap();
    // Advance past expiry.
    pic.advance_time(std::time::Duration::from_secs(120));
    pic.tick();
    // allowance() reads 0; draw fails with InsufficientAllowance { 0 }.
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 0, "expired allowance reads 0");
    match transfer_from(&pic, cid, dexp(), &tf_args(alice(), bob(), STSH, None)) {
        Err(TransferFromError::InsufficientAllowance { allowance }) => assert_eq!(to_u128(&allowance), 0),
        other => panic!("expired draw must be InsufficientAllowance{{0}}; got {:?}", other),
    }
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 0, "no funds moved on expired allowance");
    assert_conservation(&pic, cid, alice());
}

// B4 — hostile-DEX patterns: self-recipient, zero-amount, set→drain→re-set churn.
#[test]
fn adv_b4_hostile_dex_patterns() {
    let (pic, cid) = setup();
    let start = balance_of(&pic, cid, &acct(alice()));
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), 100 * STSH, None, None)).unwrap();

    // Self-referential recipient: spender moves alice→alice; balance net-unchanged
    // (fee 0), allowance decremented by the amount.
    transfer_from(&pic, cid, dexp(), &tf_args(alice(), alice(), 30 * STSH, None)).unwrap();
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start, "self-transfer net-unchanged at fee 0");
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 70 * STSH, "allowance still decremented on self-transfer");

    // R10-1 RETARGET (lane A-3, CTO_RULING_A-3_fence_third_site — Option A).
    //
    // WAS: "Zero-amount spam: succeeds, decrements allowance by 0, no invariant
    //      break." Five zero-amount draws were `.unwrap()`ed as successes.
    // NOW: the ledger REFUSES zero-amount transfers on both write paths
    //      (GenericError, error_code 5). The hostile-DEX property this block
    //      exists to test is UNCHANGED in substance — zero-amount spam still
    //      cannot move funds or shift the allowance — but the mechanism is now a
    //      refusal instead of a free no-op, which is strictly stronger: the spam
    //      no longer writes a dedup entry either.
    // CAUSE: R10-1. This site was found at GATE TIME by a failing test, not by
    //      the brief; the fence was widened by ruling to cover exactly this block.
    for _ in 0..5 {
        match transfer_from(&pic, cid, dexp(), &tf_args(alice(), bob(), 0, None)) {
            Err(TransferFromError::GenericError { error_code, .. }) => {
                assert_eq!(to_u128(&error_code), 5, "R10-1 pinned zero-amount error code");
            }
            other => panic!("zero-amount draw must be refused by R10-1; got {:?}", other),
        }
    }
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 70 * STSH, "zero-amount draws don't change allowance");
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 0);
    assert_conservation(&pic, cid, alice());

    // set → drain → re-set churn: re-approve REPLACES (not accumulates).
    transfer_from(&pic, cid, dexp(), &tf_args(alice(), bob(), 70 * STSH, None)).unwrap(); // drain to 0
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 0);
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), 25 * STSH, None, None)).unwrap(); // re-set
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 25 * STSH, "re-approve replaces, not adds");
    // Cannot draw more than the re-set amount.
    assert!(matches!(transfer_from(&pic, cid, dexp(), &tf_args(alice(), bob(), 26 * STSH, None)),
        Err(TransferFromError::InsufficientAllowance { .. })), "cannot over-draw the re-set allowance");
    assert_conservation(&pic, cid, alice());
    assert_conservation(&pic, cid, bob());
}

// =============================================================================
// ANGLE C — arithmetic boundaries (PRODUCTION-REACHABLE ingress only)
// =============================================================================
// NOTE (reachability rule §C): the internal checked_credit balance-overflow
// branch is UNREACHABLE through public ingress — sum(balances) == TOTAL_SUPPLY
// == 1e17 << u128::MAX, so no account can approach the overflow edge. It is
// covered only by the #[cfg(feature="testing")] debug_credit injector (branch
// coverage, NOT a live finding) and is deliberately NOT manufactured here.
// These tests exercise the boundaries reachable from valid init state.

fn nat_over_u128() -> Nat {
    // u128::MAX + 1 — larger than any u128, forcing the to_u128() None path.
    "340282366920938463463374607431768211456".parse::<Nat>().unwrap()
}

// C1 — an amount larger than u128::MAX is rejected (GenericError), no state change.
#[test]
fn adv_c1_oversized_amount_rejected() {
    let (pic, cid) = setup();
    let start_a = balance_of(&pic, cid, &acct(alice()));
    let r = transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: acct(bob()), amount: nat_over_u128(), fee: None, memo: None, created_at_time: None,
    });
    assert!(matches!(r, Err(TransferError::GenericError { .. })),
        "amount > u128::MAX must be rejected (no wrap); got {:?}", r);
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start_a, "no debit on rejected oversized amount");
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 0);
    assert_conservation(&pic, cid, alice());
}

// C2 — amount > balance is InsufficientFunds; no partial debit / underflow.
#[test]
fn adv_c2_underflow_prevented() {
    let (pic, cid) = setup();
    // bob has 0; any positive transfer from bob must fail cleanly.
    let r = simple_transfer(&pic, cid, bob(), alice(), 1);
    assert!(matches!(&r, Err(TransferError::InsufficientFunds { balance }) if to_u128(balance) == 0),
        "0-balance debit must be InsufficientFunds{{0}} (no underflow); got {:?}", r);
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 0, "no negative/wrapped balance");
    // alice sends more than she holds.
    let start = balance_of(&pic, cid, &acct(alice()));
    let r2 = simple_transfer(&pic, cid, alice(), bob(), start + 1);
    assert!(matches!(r2, Err(TransferError::InsufficientFunds { .. })), "over-balance debit rejected; got {:?}", r2);
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start, "no partial debit");
    assert_conservation(&pic, cid, alice());
}

// C3 — self-transfer (a→a): net-unchanged at fee 0 (no minting via credit-after-debit).
#[test]
fn adv_c3_self_transfer_net_unchanged() {
    let (pic, cid) = setup();
    let start = balance_of(&pic, cid, &acct(alice()));
    transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: acct(alice()), amount: Nat::from(123 * STSH), fee: None, memo: None, created_at_time: None,
    }).unwrap();
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start, "self-transfer must leave the balance exactly unchanged");
    assert_conservation(&pic, cid, alice());
}

// C4 — self-approve (a approves a): allowed, allowance recorded, no anomaly.
#[test]
fn adv_c4_self_approve() {
    let (pic, cid) = setup();
    approve(&pic, cid, alice(), &approve_args(&pic, alice(), 42 * STSH, None, None)).unwrap();
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), alice()).allowance), 42 * STSH);
    // A self-spend via the self-allowance moves nothing net and decrements the allowance.
    let start = balance_of(&pic, cid, &acct(alice()));
    transfer_from(&pic, cid, alice(), &tf_args(alice(), alice(), 10 * STSH, None)).unwrap();
    assert_eq!(balance_of(&pic, cid, &acct(alice())), start);
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), alice()).allowance), 32 * STSH);
    assert_conservation(&pic, cid, alice());
}

// C5 — subaccount edges: None == all-zero (QA-DEF-021); distinct subaccounts isolated; max subaccount.
#[test]
fn adv_c5_subaccount_edges() {
    let (pic, cid) = setup();
    // Move funds INTO alice's explicit all-zero subaccount; it must land in the
    // SAME (default) account — None and Some([0;32]) are one account.
    let start = balance_of(&pic, cid, &acct(alice()));
    let zero = Account { owner: alice(), subaccount: Some([0u8; 32]) };
    assert_eq!(balance_of(&pic, cid, &zero), start, "Some([0;32]) reads as the default account");
    // Fund bob's subaccount #1 from alice; it must NOT appear in bob's default or subaccount #2.
    transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: acct_sub(bob(), 1), amount: Nat::from(50 * STSH), fee: None, memo: None, created_at_time: None,
    }).unwrap();
    assert_eq!(balance_of(&pic, cid, &acct_sub(bob(), 1)), 50 * STSH);
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 0, "default account isolated from subaccount #1");
    assert_eq!(balance_of(&pic, cid, &acct_sub(bob(), 2)), 0, "subaccount #2 isolated from #1");
    // Max subaccount is a valid, distinct account.
    let max_sub = Account { owner: bob(), subaccount: Some([0xFFu8; 32]) };
    assert_eq!(balance_of(&pic, cid, &max_sub), 0);
    transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: max_sub.clone(), amount: Nat::from(7 * STSH), fee: None, memo: None, created_at_time: None,
    }).unwrap();
    assert_eq!(balance_of(&pic, cid, &max_sub), 7 * STSH);
    assert_eq!(balance_of(&pic, cid, &acct_sub(bob(), 1)), 50 * STSH, "max-subaccount funding isolated");
    assert_conservation(&pic, cid, alice());
}

// =============================================================================
// ANGLE D — REACHABLE zero-fee policy (nonzero fee is not expressible; DEFERRED)
// =============================================================================
// Nonzero-fee activation is a MANDATORY future-fee-lane gate (record, not built):
// fee-change griefing between approve and transfer_from, rounding, ICRC-21 consent
// reflecting the active fee, memo/dedup under nonzero fee. `DEFAULT_FEE = 0` with
// no runtime/init/testing setter (lib.rs:47/:463), so none of that is expressible
// against the current canister.

// D1 — supplied-fee rejection: fee=Some(nonzero)→BadFee{0}; fee=Some(0)/None accepted.
#[test]
fn adv_d1_supplied_fee_rejection() {
    let (pic, cid) = setup();
    // transfer
    let r = transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: acct(bob()), amount: Nat::from(STSH), fee: Some(Nat::from(1u8)), memo: None, created_at_time: None,
    });
    assert!(matches!(&r, Err(TransferError::BadFee { expected_fee }) if to_u128(expected_fee) == 0),
        "transfer fee=Some(1) must be BadFee{{0}}; got {:?}", r);
    // approve
    let ra = approve(&pic, cid, alice(), &ApproveArgs {
        from_subaccount: None, spender: acct(dexp()), amount: Nat::from(STSH), expected_allowance: None,
        // H-01/dev007: a bounded expiry, so the BadFee refusal under test is the one
        // that fires rather than the mandatory-expiry refusal. BadFee is validated
        // first either way; the expiry is supplied so that stays true by argument
        // rather than by ordering luck.
        expires_at: Some(now_ns(&pic) + APPROVAL_TTL_NS), fee: Some(Nat::from(1u8)), memo: None, created_at_time: None,
    });
    assert!(matches!(&ra, Err(ApproveError::BadFee { expected_fee }) if to_u128(expected_fee) == 0),
        "approve fee=Some(1) must be BadFee{{0}}; got {:?}", ra);
    // transfer_from (needs an allowance first)
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), 10 * STSH, None, None)).unwrap();
    let rtf = transfer_from(&pic, cid, dexp(), &TransferFromArgs {
        spender_subaccount: None, from: acct(alice()), to: acct(bob()), amount: Nat::from(STSH), fee: Some(Nat::from(1u8)), memo: None, created_at_time: None,
    });
    assert!(matches!(&rtf, Err(TransferFromError::BadFee { expected_fee }) if to_u128(expected_fee) == 0),
        "transfer_from fee=Some(1) must be BadFee{{0}}; got {:?}", rtf);

    // fee=Some(0) and fee=None accepted.
    assert!(transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: acct(bob()), amount: Nat::from(STSH), fee: Some(Nat::from(0u8)), memo: None, created_at_time: None,
    }).is_ok(), "fee=Some(0) must be accepted");
    assert!(simple_transfer(&pic, cid, alice(), bob(), STSH).is_ok(), "fee=None must be accepted");
    assert_conservation(&pic, cid, alice());
}

// D2 — F-ADV-D2 REMEDIATED (token remediation lane): a fee > u128::MAX must be
// BadFee. The old `provided.0.to_u128().unwrap_or(0)` coerced it to 0, passed the
// `!= fee` check, and ACCEPTED the operation (confirmed RED at c4fc761, then-
// anchors lib.rs:710/:814/:924). All three fee-validation sites now fail on the
// conversion itself via `to_u128().map_or(true, |v| v != fee)`. This test is the
// permanent regression lock — the assertion is the original normative one,
// preserved verbatim, never weakened. See also the site-4 companion below
// (expected_allowance sentinel collision).
#[test]
fn adv_d2_oversized_nat_fee_must_be_badfee() {
    let (pic, cid) = setup();
    let big = nat_over_u128();
    // Cover ALL THREE fee-bearing entrypoints (:710/:814/:924) with independent
    // state, so a partial remediation (e.g. fixing only icrc1_transfer) cannot make
    // this test go green while the other paths stay broken. Collect the offenders.
    let mut still_broken: Vec<&str> = Vec::new();

    let rt = transfer(&pic, cid, alice(), &TransferArgs {
        from_subaccount: None, to: acct(bob()), amount: Nat::from(STSH), fee: Some(big.clone()), memo: None, created_at_time: None,
    });
    if !matches!(&rt, Err(TransferError::BadFee { .. })) { still_broken.push("icrc1_transfer"); }

    let ra = approve(&pic, cid, alice(), &ApproveArgs {
        from_subaccount: None, spender: acct(dexp()), amount: Nat::from(STSH), expected_allowance: None,
        // H-01/dev007: see the note on the fee=Some(1) case above.
        expires_at: Some(now_ns(&pic) + APPROVAL_TTL_NS), fee: Some(big.clone()), memo: None, created_at_time: None,
    });
    if !matches!(&ra, Err(ApproveError::BadFee { .. })) { still_broken.push("icrc2_approve"); }

    // Fund an allowance with a VALID fee, then draw with the oversized fee.
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), 10 * STSH, None, None)).unwrap();
    let rtf = transfer_from(&pic, cid, dexp(), &TransferFromArgs {
        spender_subaccount: None, from: acct(alice()), to: acct(bob()), amount: Nat::from(STSH), fee: Some(big.clone()), memo: None, created_at_time: None,
    });
    if !matches!(&rtf, Err(TransferFromError::BadFee { .. })) { still_broken.push("icrc2_transfer_from"); }

    assert!(still_broken.is_empty(),
        "SECURITY F-ADV-D2: a fee > u128::MAX must return BadFee on ALL entrypoints, NOT be coerced to 0 and \
         accepted. Still accepting the oversized fee on: {:?}\n  transfer={:?}\n  approve={:?}\n  transfer_from={:?}",
        still_broken, rt, ra, rtf);
}

// D2 site 4 — F-ADV-D2 expected_allowance sentinel collision (icrc2_approve CAS
// guard). The old code compared `current != expected.0.to_u128().unwrap_or(u128::MAX)`:
// for ordinary allowances the sentinel happened to fail closed, but when the
// stored allowance is EXACTLY u128::MAX — publicly reachable, an approve may
// legitimately set amount = u128::MAX — an oversized expected_allowance coerced
// to u128::MAX, falsely MATCHED, and silently bypassed the AllowanceChanged
// guard. The fix makes the rejection deliberate: an expected_allowance that does
// not fit u128 can never match a real allowance → AllowanceChanged, always.
#[test]
fn adv_d2_oversized_expected_allowance_must_fire_allowance_changed() {
    let (pic, cid) = setup();

    // (1) Establish the collision state: stored allowance == exactly u128::MAX.
    approve(&pic, cid, alice(), &approve_args(&pic, dexp(), u128::MAX, None, None))
        .expect("establishing allowance = u128::MAX must succeed (fee 0, amount is not balance-checked)");
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), u128::MAX,
        "precondition: stored allowance must be exactly u128::MAX");
    let alice_before = balance_of(&pic, cid, &acct(alice()));
    let bob_before   = balance_of(&pic, cid, &acct(bob()));
    let dexp_before  = balance_of(&pic, cid, &acct(dexp()));

    // (2) Attack: approve with expected_allowance = u128::MAX + 1 (does not fit
    // u128). Old sentinel: coerced to u128::MAX == current → guard bypassed and
    // the allowance silently overwritten. Required: the CAS guard FIRES.
    let r = approve(&pic, cid, alice(), &ApproveArgs {
        from_subaccount: None, spender: acct(dexp()), amount: Nat::from(STSH),
        // H-01/dev007: a bounded expiry is now MANDATORY on an approve that writes a
        // row, and the mandatory-expiry refusal is evaluated before the CAS — so
        // without this the call would be refused for the wrong reason and the CAS
        // guard under test would never be reached.
        expected_allowance: Some(nat_over_u128()), expires_at: Some(now_ns(&pic) + APPROVAL_TTL_NS), fee: None,
        memo: None, created_at_time: None,
    });

    // (3) Deterministic correct error: AllowanceChanged carrying the REAL current
    // allowance (u128::MAX) — not an acceptance, not any other variant.
    match &r {
        Err(ApproveError::AllowanceChanged { current_allowance }) => {
            assert_eq!(current_allowance, &Nat::from(u128::MAX),
                "AllowanceChanged must report the real current allowance (u128::MAX)");
        }
        other => panic!(
            "SECURITY F-ADV-D2 site 4: expected_allowance > u128::MAX with stored allowance \
             u128::MAX must be Err(AllowanceChanged {{ u128::MAX }}) — the sentinel collision \
             must not bypass the CAS guard; got {:?}", other),
    }

    // (4) No state mutation on the rejected path: allowance NOT overwritten to
    // the attack's amount, and no party's balance moved.
    assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), u128::MAX,
        "rejected approve must not overwrite the stored allowance");
    assert_eq!(balance_of(&pic, cid, &acct(alice())), alice_before, "owner balance unchanged");
    assert_eq!(balance_of(&pic, cid, &acct(dexp())),  dexp_before,  "spender balance unchanged");
    assert_eq!(balance_of(&pic, cid, &acct(bob())),   bob_before,   "bystander balance unchanged");
    assert_conservation(&pic, cid, alice());
}

// D3 — dedup identity at zero fee: identical (from,to,amount,memo,created_at,fee) deduped.
#[test]
fn adv_d3_dedup_identity_zero_fee() {
    let (pic, cid) = setup();
    let t = now_ns(&pic);
    let args = TransferArgs {
        from_subaccount: None, to: acct(bob()), amount: Nat::from(5 * STSH), fee: Some(Nat::from(0u8)),
        memo: Some(vec![7, 7]), created_at_time: Some(t),
    };
    let blk = transfer(&pic, cid, alice(), &args).unwrap();
    match transfer(&pic, cid, alice(), &args) {
        Err(TransferError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, blk, "identical zero-fee transfer → original block"),
        other => panic!("identical zero-fee transfer must dedup; got {:?}", other),
    }
    assert_eq!(balance_of(&pic, cid, &acct(bob())), 5 * STSH, "transfer applied exactly once");
    assert_conservation(&pic, cid, alice());
}

// =============================================================================
// PART 2 — RESIDUAL: F-DBR-1 — allowance-expiry boundary is uniformly INCLUSIVE
// (now == expires_at → expired) across approve / transfer_from / allowance.
// No production change (SSA-confirmed uniform; verified at c4fc761 :855/:984/:1059).
// A 1-nanosecond boundary regression test that locks the boundary in place.
// =============================================================================

fn set_time_ns(pic: &PocketIc, nanos: u64) {
    // set_time is pending until a round executes; tick makes the certified time
    // (what queries read) exactly `nanos`.
    pic.set_time(pocket_ic::Time::from_nanos_since_unix_epoch(nanos));
    pic.tick();
}

#[test]
fn residual_fdbr1_expiry_boundary_inclusive_1ns() {
    // ── (1) approve CREATION boundary: exp <= now → Expired (inclusive). ──
    {
        let (pic, cid) = setup();
        let now = now_ns(&pic);
        // exp == now → rejected (present is already expired).
        let r = approve(&pic, cid, alice(), &approve_args(&pic, dexp(), STSH, Some(now), None));
        assert!(matches!(&r, Err(ApproveError::Expired { .. })),
            "approve exp == now must be Expired (inclusive); got {:?}", r);
        // exp strictly in the future → accepted.
        assert!(approve(&pic, cid, alice(), &approve_args(&pic, dexp(), STSH, Some(now + 10_000_000_000), None)).is_ok(),
            "approve with a future exp must be accepted");
    }
    // ── (2)+(3) READ boundary (allowance + transfer_from): time() >= exp → expired. ──
    {
        let (pic, cid) = setup();
        let now0 = now_ns(&pic);
        let exp = now0 + 10_000_000_000; // +10s
        approve(&pic, cid, alice(), &approve_args(&pic, dexp(), 100 * STSH, Some(exp), None)).unwrap();

        // now == exp - 1  →  VALID. The allowance query reads the certified time
        // exactly (no round advance), giving the precise 1ns lower boundary.
        set_time_ns(&pic, exp - 1);
        assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 100 * STSH,
            "allowance at now==exp-1 must be VALID (full amount)");

        // now == exp  →  EXPIRED on both read paths (INCLUSIVE boundary). The
        // allowance query proves the precise 1ns upper boundary; transfer_from
        // confirms the same `time() >= exp` logic behaviourally.
        set_time_ns(&pic, exp);
        assert_eq!(to_u128(&allowance(&pic, cid, alice(), dexp()).allowance), 0,
            "allowance at now==exp must read 0 (inclusive)");
        assert!(matches!(transfer_from(&pic, cid, dexp(), &tf_args(alice(), bob(), STSH, None)),
            Err(TransferFromError::InsufficientAllowance { allowance }) if to_u128(&allowance) == 0),
            "transfer_from at now==exp must be InsufficientAllowance{{0}} (inclusive)");
        assert_conservation(&pic, cid, alice());
    }
}

// =============================================================================
// PART 2 — RESIDUAL: EXT-DBR-001 — supported_standards normative-string pin.
// icrc1_supported_standards and icrc10_supported_standards serve the SAME 4
// entries; each URL is pinned so silent drift fails this test. Normative sources
// recorded in ADVERSARIAL_ICRC_RESULTS.md (internal).
//
// Normative sources (recorded in ADVERSARIAL_ICRC_RESULTS.md):
//   ICRC-1  → the ICRC-1 spec's icrc1_supported_standards example advertises the
//             REPOSITORY ROOT — pinned to github.com/dfinity/ICRC-1 (lib.rs updated
//             this lane; the authorized EXT-DBR-001 change).
//   ICRC-2  → its spec does not give the URL normative status; the accurate subpath
//             to the ICRC-2 standard is retained.
//   ICRC-10 → ICRC-10.md §icrc10_supported_standards MUST-string.
//   ICRC-21 → the entry mandated by the ICRC-21 spec's own .did.
// =============================================================================

const EXPECTED_STANDARDS: [(&str, &str); 4] = [
    ("ICRC-1", "https://github.com/dfinity/ICRC-1"),
    ("ICRC-2", "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2"),
    ("ICRC-10", "https://github.com/dfinity/ICRCs/ICRC-10"),
    ("ICRC-21", "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md"),
];

fn assert_expected_standards(got: &[StandardRecord], via: &str) {
    assert_eq!(got.len(), EXPECTED_STANDARDS.len(), "{}: entry count", via);
    for (name, url) in EXPECTED_STANDARDS {
        let rec = got.iter().find(|r| r.name == name)
            .unwrap_or_else(|| panic!("{}: missing standard {}", via, name));
        assert_eq!(rec.url, url, "{}: {} URL pinned to the recorded normative string", via, name);
    }
}

#[test]
fn residual_ext_dbr001_supported_standards_pinned() {
    let (pic, cid) = setup();
    let s1: Vec<StandardRecord> = q(&pic, cid, "icrc1_supported_standards", candid::encode_args(()).unwrap());
    let s10: Vec<StandardRecord> = q(&pic, cid, "icrc10_supported_standards", candid::encode_args(()).unwrap());
    assert_expected_standards(&s1, "icrc1_supported_standards");
    assert_expected_standards(&s10, "icrc10_supported_standards");
    // The two discovery methods must serve an identical set (single source of truth).
    assert_eq!(s1, s10, "icrc1_ and icrc10_supported_standards must be identical");
}
