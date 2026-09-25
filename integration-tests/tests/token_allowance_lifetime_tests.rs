// =============================================================================
// STSH — H-01 / MD-01 (HARDEN-02): allowance lifetime, reclamation, and the one
// effective-allowance notion. Behavioural PocketIC suite.
// =============================================================================
//
// WHAT THIS SUITE IS FOR.
//
// H-01: `ALLOWANCES` grew monotonically. No path ever removed a row — revoke
// overwrote with `amount: 0`, a drain wrote back the reduced record, and expiry
// was read-side only — while `icrc2_approve` admitted a new row from a
// zero-balance caller at `DEFAULT_FEE = 0` for ingress cost alone. Both halves of
// the row key are caller-supplied and IC principals are free to generate, so the
// number of distinct rows one attacker could write was limited by nothing in the
// canister.
//
// MD-01: `icrc2_allowance` and `icrc2_transfer_from` applied expiry; the
// `expected_allowance` CAS in `icrc2_approve` compared against the RAW stored
// amount. The shipped shield flow always sends `expected_allowance` sourced from
// its own `allowance()` query, so after an unspent 15-minute expiry the query
// returned 0, the CAS compared 0 against the stale stored amount, and every
// re-approval was refused `AllowanceChanged` — permanently, because nothing on
// any path could rewrite the row.
//
// The fix is a mandatory, capped approval lifetime (deviation dev007) plus
// reclamation on three independent triggers, and ONE shared notion of effective
// allowance used by the query, the CAS and `transfer_from`.
//
// WHAT THIS SUITE DELIBERATELY DOES NOT DO. No mainnet call. The throughput and
// storage figures below are measured on a LOCAL PocketIC replica, and every
// projection from them to `pzp6e` is labelled as a projection at the point it is
// made. Loading the production token canister to size a bound is not on the table:
// the brief prohibits mainnet calls, and a benchmark against live supply is not a
// benchmark, it is an incident.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md law 7; the fixture arms need the
// --features testing Wasm, which carries the inject/measure hooks that do not
// exist in production):
//   # 1. test Wasm first:
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing
//   cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
//      target/wasm32-unknown-unknown/release/stsh_token_test.wasm
//   # 2. production Wasms (overwrites stsh_token.wasm):
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token
//   # 3. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test token_allowance_lifetime_tests -- --test-threads=1
//
// Use ./run_gate.sh. Hand-assembling the sequence is the failure law 7 exists to
// prevent.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm loaders — FAIL LOUD, naming the command that produces the file ──────

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token Wasm at {}: {}.\nBuild first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token",
            path, e
        )
    })
}

fn token_test_wasm() -> Vec<u8> {
    let path = env!("TOKEN_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token TEST Wasm at {}: {}.\nBuild first (the H-01 \
             inject/measure fixtures exist only under --features testing):\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing\n  \
             cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
             target/wasm32-unknown-unknown/release/stsh_token_test.wasm",
            path, e
        )
    })
}

// ── Constants — must match canisters/token/src/lib.rs exactly ────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH, 8 decimals
const STSH: u128 = 100_000_000;
/// `MAX_APPROVAL_TTL_NS` — duplicated here because this suite drives the canister
/// over PocketIC and cannot link the constant. A change to the canister value
/// REDs this suite, which is the intended coupling.
const MAX_APPROVAL_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
/// `ALLOWANCE_MAINTENANCE_INTERVAL_NS` — 300 s.
const MAINTENANCE_INTERVAL_NS: u64 = 300 * 1_000_000_000;
/// `MAX_ALLOWANCE_PRUNE_PER_CALL` — the write-path cap.
const PRUNE_PER_CALL: u64 = 100;
/// `MAX_ALLOWANCE_PRUNE_PER_TIMER_TICK` — the timer's own cap.
const PRUNE_PER_TICK: u64 = 1_000;
/// The wallet's own approval lifetime (`APPROVAL_TTL_NS`, wallet/src/actors/token.ts).
/// Three orders of magnitude inside the cap, which is what makes dev007
/// compatible with the shipped call shape.
const WALLET_APPROVAL_TTL_NS: u64 = 15 * 60 * 1_000_000_000;
/// dev007's RETIRED refusal codes (`ERR_CODE_APPROVAL_EXPIRY_REQUIRED` /
/// `_TTL_TOO_LONG`, TOKEN-APPROVE-TTL). No path raises them any more; the moved
/// AA-2 tests assert their ABSENCE, so the tests state what disappeared.
const ERR_CODE_APPROVAL_EXPIRY_REQUIRED: u32 = 7;
const ERR_CODE_APPROVAL_TTL_TOO_LONG: u32 = 8;
/// dev006's pinned zero-amount refusal code (`ERR_CODE_ZERO_AMOUNT`).
const ERR_CODE_ZERO_AMOUNT: u32 = 5;

// ── Wire-type mirrors (names/variants must match the canister exactly) ────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
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
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>,
    from: Account,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllowanceArgs {
    account: Account,
    spender: Account,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Allowance {
    allowance: Nat,
    expires_at: Option<u64>,
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

// ── Principals + plumbing ────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}
fn acct(owner: Principal) -> Account {
    Account { owner, subaccount: None }
}
fn sub(owner: Principal, tag: u8) -> Account {
    Account { owner, subaccount: Some([tag; 32]) }
}

fn deploy(pic: &PocketIc, wasm: Vec<u8>, owner: Principal) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 40_000_000_000_000u128);
    let init = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: owner,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
        fee_collector: Some(p(0xF1)),
    };
    pic.install_canister(cid, wasm, candid::encode_one(&init).unwrap(), None);
    cid
}

fn upgrade(pic: &PocketIc, cid: Principal, wasm: Vec<u8>) -> Result<(), String> {
    pic.upgrade_canister(cid, wasm, candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() as u64
}

// ── Endpoint helpers ─────────────────────────────────────────────────────────

/// The FULL approve argument surface, because dev007 and the CAS both turn on
/// fields a convenience wrapper would hide.
#[allow(clippy::too_many_arguments)]
fn approve_full(
    pic: &PocketIc,
    cid: Principal,
    caller: Principal,
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: u128,
    expected_allowance: Option<u128>,
    expires_at: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<Nat, ApproveError> {
    let args = ApproveArgs {
        from_subaccount,
        spender,
        amount: Nat::from(amount),
        expected_allowance: expected_allowance.map(Nat::from),
        expires_at,
        fee: None,
        memo: None,
        created_at_time,
    };
    let bytes = pic
        .update_call(cid, caller, "icrc2_approve", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc2_approve rejected at the ingress layer: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

/// The shipped wallet's exact call shape: `expected_allowance` ALWAYS present,
/// `from_subaccount` always `[]` (None on the wire), `expires_at` always
/// `created_at_time + APPROVAL_TTL_NS` (derived from the dedup stamp so a retry
/// reproduces the argument byte-for-byte), `created_at_time` always present.
fn approve_wallet_shape(
    pic: &PocketIc,
    cid: Principal,
    caller: Principal,
    spender: Principal,
    amount: u128,
    expected_allowance: u128,
) -> Result<Nat, ApproveError> {
    let created = now_ns(pic);
    approve_full(
        pic,
        cid,
        caller,
        None,
        acct(spender),
        amount,
        Some(expected_allowance),
        Some(created + WALLET_APPROVAL_TTL_NS),
        Some(created),
    )
}

fn transfer_from_acct(
    pic: &PocketIc,
    cid: Principal,
    caller: Principal,
    from_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: u128,
) -> Result<Nat, TransferError> {
    let args = TransferArgs {
        from_subaccount,
        to,
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, caller, "icrc1_transfer", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc1_transfer rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

fn transfer_from(
    pic: &PocketIc,
    cid: Principal,
    spender: Principal,
    from: Account,
    to: Account,
    amount: u128,
) -> Result<Nat, TransferFromError> {
    let args = TransferFromArgs {
        spender_subaccount: None,
        from,
        to,
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, spender, "icrc2_transfer_from", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc2_transfer_from rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

fn allowance(pic: &PocketIc, cid: Principal, account: Account, spender: Account) -> Allowance {
    let args = AllowanceArgs { account, spender };
    let bytes = pic
        .query_call(cid, anon(), "icrc2_allowance", candid::encode_one(&args).unwrap())
        .expect("icrc2_allowance");
    candid::decode_one(&bytes).unwrap()
}

fn balance_of(pic: &PocketIc, cid: Principal, account: Account) -> u128 {
    let bytes = pic
        .query_call(cid, anon(), "icrc1_balance_of", candid::encode_one(&account).unwrap())
        .expect("icrc1_balance_of");
    let n: Nat = candid::decode_one(&bytes).unwrap();
    n.0.to_string().parse().unwrap()
}

// ── test-feature fixtures (token_test_wasm only) ─────────────────────────────

/// (primary_len, index_len, bijective) — the bijection evaluated by the
/// PRODUCTION predicate, never re-implemented here.
fn index_stats(pic: &PocketIc, cid: Principal) -> (u64, u64, bool) {
    let bytes = pic
        .query_call(cid, anon(), "allowance_index_stats_for_test", candid::encode_args(()).unwrap())
        .expect("allowance_index_stats_for_test");
    candid::decode_args(&bytes).unwrap()
}

/// Bulk-write `count` allowance rows THROUGH the production writer.
fn inject_allowances(pic: &PocketIc, cid: Principal, count: u64, expires_at: u64, amount: u128) {
    pic.update_call(
        cid,
        anon(),
        "inject_allowances_for_test",
        candid::encode_args((count, expires_at, amount)).unwrap(),
    )
    .expect("inject_allowances_for_test");
}

/// (rows_removed, instructions_consumed) for one prune at a chosen `now`/cap.
fn measure_prune(pic: &PocketIc, cid: Principal, now: u64, cap: u64) -> (u64, u64) {
    let bytes = pic
        .update_call(
            cid,
            anon(),
            "measure_allowance_prune_instructions_for_test",
            candid::encode_args((now, cap)).unwrap(),
        )
        .expect("measure_allowance_prune_instructions_for_test");
    candid::decode_args(&bytes).unwrap()
}

/// Allocated stable memory, in 64 KiB pages — the real footprint, not
/// `len() * record_size`.
fn stable_pages(pic: &PocketIc, cid: Principal) -> u64 {
    let bytes = pic
        .query_call(cid, anon(), "stable_pages_for_test", candid::encode_args(()).unwrap())
        .expect("stable_pages_for_test");
    candid::decode_one(&bytes).unwrap()
}

fn timer_armed(pic: &PocketIc, cid: Principal) -> bool {
    let bytes = pic
        .query_call(cid, anon(), "maintenance_timer_armed_for_test", candid::encode_args(()).unwrap())
        .expect("maintenance_timer_armed_for_test");
    candid::decode_one(&bytes).unwrap()
}

/// Advance the replica clock and run a round, so timers due in the new window fire.
fn travel(pic: &PocketIc, by: Duration) {
    pic.advance_time(by);
    pic.tick();
}

// =============================================================================
// AA-2 — (f1): the approval lifetime is DEFAULTED and CAPPED (TOKEN-APPROVE-TTL;
// before that lane, absent and over-cap were REFUSED), and the shipped wallet's
// exact call shape is stored as sent.
// =============================================================================

/// True iff `r` is one of dev007's RETIRED refusals (code 7 or 8).
fn is_retired_dev007_refusal(r: &Result<Nat, ApproveError>) -> bool {
    matches!(r, Err(ApproveError::GenericError { error_code, .. })
        if *error_code == Nat::from(ERR_CODE_APPROVAL_EXPIRY_REQUIRED)
            || *error_code == Nat::from(ERR_CODE_APPROVAL_TTL_TOO_LONG))
}

/// MOVED by TOKEN-APPROVE-TTL from `test_aa2_dev007_refuses_absent_expiry` (which
/// asserted code 7 and no row). An approve with no `expires_at` — the shape every
/// standard ICRC-2 client (ICPSwap, wallets) sends — is now ACCEPTED and stored
/// with the cap applied: `icrc2_allowance` reads back `Some(now + 24 h)`, the row
/// is indexed (so it is reclaimable), the spender can use it, it expires on time,
/// and the timer reclaims it. H-01 is still met: the row has a stated end.
///
/// The expiry is bracketed rather than pinned to the nanosecond: the replica
/// advances its clock per round, so the `now` the update saw lies between the two
/// harness reads. The nanosecond-exact arms live in the canister's unit suite
/// (`approval_lifetime_boundaries_are_exact`).
#[test]
fn test_aa2_dev007_absent_expiry_is_stored_with_the_cap() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_test_wasm(), owner);

    let t_before = now_ns(&pic);
    let r = approve_full(&pic, token, owner, None, acct(spender), 5 * STSH, None, None, None);
    let t_after = now_ns(&pic);
    assert!(!is_retired_dev007_refusal(&r), "code 7 is retired, got {r:?}");
    r.expect("dev007 (TOKEN-APPROVE-TTL): an approve with no expires_at is accepted");

    // icrc2_allowance reads back the EFFECTIVE expiry — now + 24 h.
    let a = allowance(&pic, token, acct(owner), acct(spender));
    assert_eq!(a.allowance, Nat::from(5 * STSH));
    let e = a.expires_at.expect("the stored row carries the defaulted expiry, never None");
    assert!(
        t_before + MAX_APPROVAL_TTL_NS <= e && e <= t_after + MAX_APPROVAL_TTL_NS,
        "expires_at must be now + MAX_APPROVAL_TTL_NS: {e} not in [{}, {}]",
        t_before + MAX_APPROVAL_TTL_NS,
        t_after + MAX_APPROVAL_TTL_NS
    );
    // The row is indexed, so both reclamation triggers can reach it.
    assert_eq!(index_stats(&pic, token), (1, 1, true), "one row, indexed, bijective");

    // The spender can use it, and the write-back keeps the stored expiry.
    transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), 2 * STSH)
        .expect("transfer_from against a defaulted-expiry allowance");
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(spender)),
        Allowance { allowance: Nat::from(3 * STSH), expires_at: Some(e) },
        "transfer_from reduces the amount and never moves the expiry"
    );

    // SSA R-5: the dedup key hashes the CALLER-SENT expires_at (None), not the
    // effective value. A byte-identical retry at a later replica time must return
    // Duplicate and must NOT re-stamp the expiry — if the key hashed now + 24 h,
    // the retry would miss the cache and re-execute with a later expiry.
    let spender2 = p(0xB3);
    let created = now_ns(&pic);
    let first = approve_full(&pic, token, owner, None, acct(spender2), STSH, None, None, Some(created))
        .expect("expiry-less approve with created_at_time");
    let e2 = allowance(&pic, token, acct(owner), acct(spender2)).expires_at.expect("defaulted");
    travel(&pic, Duration::from_secs(10));
    assert_eq!(
        approve_full(&pic, token, owner, None, acct(spender2), STSH, None, None, Some(created)),
        Err(ApproveError::Duplicate { duplicate_of: first }),
        "a byte-identical retry of an expiry-less approve is a Duplicate, not a re-execution"
    );
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(spender2)).expires_at,
        Some(e2),
        "the retry did not re-stamp the defaulted expiry"
    );

    // It expires on time: past the cap the spender is refused and the query reads
    // {0, null} ...
    travel(&pic, Duration::from_nanos(MAX_APPROVAL_TTL_NS + 60 * 1_000_000_000));
    assert_eq!(
        transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), 1),
        Err(TransferFromError::InsufficientAllowance { allowance: Nat::from(0u32) }),
        "a defaulted-expiry allowance is unspendable once its 24 h are up"
    );
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(spender)),
        Allowance { allowance: Nat::from(0u32), expires_at: None }
    );
    // ... and the maintenance timer reclaims both rows (H-01 (f2)).
    travel(&pic, Duration::from_nanos(MAINTENANCE_INTERVAL_NS + 1_000_000_000));
    assert_eq!(index_stats(&pic, token), (0, 0, true), "the defaulted rows are reclaimed");
}

/// MOVED by TOKEN-APPROVE-TTL from `aa2_approve_refuses_an_over_cap_expiry` (which
/// asserted code 8 for an over-cap expiry). An expiry past the cap is now CLAMPED
/// to `now + MAX_APPROVAL_TTL_NS` and stored; one inside it is stored as given.
///
/// WHY THIS TEST IS NOT WRITTEN AT THE NANOSECOND. A PocketIC replica advances its
/// clock as it executes rounds, so the `now` an update observes is strictly later
/// than the `now` this harness read when it computed `expires_at`. An assertion at
/// `now + CAP + 1` would execute at something UNDER the cap. The nanosecond-exact
/// boundaries (`CAP` as given, `CAP + 1` clamped) are pinned by
/// `approval_lifetime_boundaries_are_exact` against `effective_approval_lifetime`
/// with `now` supplied. This test establishes the behavioural half: the clamp is
/// really wired into the endpoint's write, and F-006 is still distinct.
#[test]
fn aa2_approve_clamps_an_over_cap_expiry() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_wasm(), owner);

    // Well inside the cap: stored exactly as given.
    let t = now_ns(&pic);
    let inside = t + MAX_APPROVAL_TTL_NS / 2;
    approve_full(&pic, token, owner, None, acct(p(0xB2)), STSH, None, Some(inside), None)
        .expect("an expiry well inside MAX_APPROVAL_TTL_NS must be accepted");
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(p(0xB2))).expires_at,
        Some(inside),
        "an in-cap expiry is stored as given, not clamped"
    );

    // Clearly past it — an hour of slack, far more than any clock advance a round
    // can contribute, so the verdict cannot be an artefact of the harness.
    let t_before = now_ns(&pic);
    let over = t_before + MAX_APPROVAL_TTL_NS + 60 * 60 * 1_000_000_000;
    let r = approve_full(&pic, token, owner, None, acct(p(0xB3)), STSH, None, Some(over), None);
    let t_after = now_ns(&pic);
    assert!(!is_retired_dev007_refusal(&r), "code 8 is retired, got {r:?}");
    r.expect("an expiry past the cap is accepted and clamped");
    let e = allowance(&pic, token, acct(owner), acct(p(0xB3)))
        .expires_at
        .expect("the clamped row carries an expiry");
    assert!(
        t_before + MAX_APPROVAL_TTL_NS <= e && e <= t_after + MAX_APPROVAL_TTL_NS && e < over,
        "an over-cap expiry is clamped to now + MAX_APPROVAL_TTL_NS: {e} (requested {over})"
    );

    // A century out — the shape that made a row unreclaimable while looking
    // compliant — is clamped the same way.
    let t_before = now_ns(&pic);
    let century = t_before + 100 * 365 * 24 * 60 * 60 * 1_000_000_000u64;
    approve_full(&pic, token, owner, None, acct(p(0xB4)), STSH, None, Some(century), None)
        .expect("an approval expiring a century out is accepted and clamped");
    let t_after = now_ns(&pic);
    let e = allowance(&pic, token, acct(owner), acct(p(0xB4)))
        .expires_at
        .expect("clamped");
    assert!(
        t_before + MAX_APPROVAL_TTL_NS <= e && e <= t_after + MAX_APPROVAL_TTL_NS,
        "a century-out expiry is stored at most 24 h out: {e}"
    );

    // F-006 is unchanged: already expired at creation is still `Expired`, never
    // clamped into a stillborn row. An expiry in the PAST is safe from the clock
    // race — time only moves forward.
    assert!(
        matches!(
            approve_full(
                &pic,
                token,
                owner,
                None,
                acct(p(0xB5)),
                STSH,
                None,
                Some(now_ns(&pic) - 1_000_000_000),
                None
            ),
            Err(ApproveError::Expired { .. })
        ),
        "F-006 must still return Expired for an already-expired expires_at"
    );
}

/// The compatibility proof, and it is a test rather than a comment (G-A3). The
/// shipped wallet always sends `expected_allowance`, always `from_subaccount = []`,
/// and always a 15-minute `expires_at` derived from `created_at_time`. If dev007
/// were incompatible with that shape, the shield flow would be dead on arrival.
#[test]
fn test_aa2_dev007_accepts_the_shipped_wallet_shape() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let pool = p(0xB2);
    let token = deploy(&pic, token_wasm(), owner);

    // The wallet's shield approve: CAS against the observed 0, 15-minute expiry.
    approve_wallet_shape(&pic, token, owner, pool, 10 * STSH, 0)
        .expect("the shipped wallet's approve shape must be accepted");
    let a = allowance(&pic, token, acct(owner), acct(pool));
    assert_eq!(a.allowance, Nat::from(10 * STSH));
    assert!(a.expires_at.is_some(), "the bounded expiry is stored");

    // I-A1: the wallet's REVOKE — `approve(0)` under the same CAS discipline and
    // through the same actor, so it carries an expiry too. dev007 must not sit in
    // front of it. Verified here rather than assumed compatible.
    approve_wallet_shape(&pic, token, owner, pool, 0, 10 * STSH)
        .expect("revocation via approve(0) must keep working under dev007");
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(pool)),
        Allowance { allowance: Nat::from(0u32), expires_at: None },
        "AA-3: a revoked allowance now reads {{0, null}} — the row is RECLAIMED, not \
         overwritten with {{0, expires_at}}. This is the pinned observable change"
    );
}

/// I-A1, the exemption spelled out: dev007's mandatory-expiry refusal must NOT
/// sit in front of a revoking zero approve, and dev006's refusal must stay
/// reachable on the commonest shape.
///
/// A zero approve admits no row — it removes one, or is refused by dev006 with
/// nothing live to remove — so (f1) has nothing to bound there. Without the
/// exemption a zero approve omitting `expires_at` would be refused by dev007
/// first, with dev007's code, and dev006's register row would quietly stop
/// describing reachable behaviour.
#[test]
fn revocation_is_exempt_from_the_mandatory_expiry_and_dev006_stays_reachable() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_test_wasm(), owner);

    // (1) Nothing live, zero amount, NO expires_at → dev006's code, NOT dev007's.
    match approve_full(&pic, token, owner, None, acct(spender), 0, None, None, None) {
        Err(ApproveError::GenericError { error_code, .. }) => assert_eq!(
            error_code,
            Nat::from(ERR_CODE_ZERO_AMOUNT),
            "dev006 must still own this refusal — if dev007's mandatory expiry ran \
             first, the dev006 outcome would be unreachable on this shape"
        ),
        other => panic!("expected the dev006 refusal, got {other:?}"),
    }

    // (2) A LIVE allowance, then revoke with NO expires_at → accepted, and the row
    // is reclaimed.
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        5 * STSH,
        None,
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None,
    )
    .expect("setup approve");
    assert_eq!(index_stats(&pic, token).0, 1);

    approve_full(&pic, token, owner, None, acct(spender), 0, None, None, None)
        .expect("revocation must not be blocked by the mandatory-expiry rule (I-A1)");
    assert_eq!(
        index_stats(&pic, token),
        (0, 0, true),
        "and the revoked row is reclaimed, not left behind as {{0, null}}"
    );

    // (3) An expiry the caller DID supply is still validated on the revoke path:
    // a past one is still F-006's `Expired`, not silently accepted.
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        5 * STSH,
        None,
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None,
    )
    .expect("re-approve");
    assert!(
        matches!(
            approve_full(
                &pic,
                token,
                owner,
                None,
                acct(spender),
                0,
                None,
                Some(now_ns(&pic) - 1_000_000_000),
                None
            ),
            Err(ApproveError::Expired { .. })
        ),
        "the exemption covers ONLY an absent expiry; a supplied one is still checked"
    );
}

// =============================================================================
// AA-4 / AA-5 / AA-6 — MD-01: one effective-allowance notion.
// =============================================================================

/// AA-4: the §1.2(a) scenario end to end. This test FAILS at the base — the
/// re-approval is refused `AllowanceChanged { current_allowance: <stale amount> }`
/// forever — and passes after the fix. Written against the shipped wallet's call
/// shape, because that is the caller the lockout actually bricked.
#[test]
fn aa4_reapproval_after_an_unspent_expiry_succeeds() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let pool = p(0xB2);
    let token = deploy(&pic, token_wasm(), owner);

    approve_wallet_shape(&pic, token, owner, pool, 10 * STSH, 0).expect("first approve");

    // Let it expire unspent. The wallet's 15-minute lifetime, plus a second.
    pic.advance_time(Duration::from_nanos(WALLET_APPROVAL_TTL_NS + 1_000_000_000));
    pic.tick();

    // The wallet's own pre-check now reads zero (F-005).
    let observed = allowance(&pic, token, acct(owner), acct(pool));
    assert_eq!(observed.allowance, Nat::from(0u32), "an expired allowance queries as 0");
    assert_eq!(observed.expires_at, None);

    // And the re-approval it derives from that reading is ACCEPTED. Before MD-01
    // the CAS compared the observed 0 against the raw stored 10 STSH and refused,
    // with no path anywhere able to rewrite the row — a permanent lockout of the
    // primary flow, not a transient error.
    // The CAS value is the one the wallet itself observed above — 0 — passed in as
    // the wallet passes it, rather than a literal chosen by the test.
    assert_eq!(observed.allowance, Nat::from(0u32));
    approve_wallet_shape(&pic, token, owner, pool, 7 * STSH, 0)
        .expect("re-approval after an unspent expiry must succeed — this is MD-01");
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(pool)).allowance,
        Nat::from(7 * STSH),
        "the new allowance is live"
    );
}

/// AA-5 (REPLACES V1's unfalsifiable version). The boundary table: the query, the
/// `expected_allowance` CAS and `icrc2_transfer_from` must report the SAME
/// effective allowance at each point. V1 asked for "a test that fails if any of the
/// three stops routing through the shared notion" — routing is a source property no
/// behavioural harness can observe, so what is asserted here is AGREEMENT, which is
/// the property that actually matters.
///
/// HOW THE POINTS ARE REACHED, AND WHICH ONE CANNOT BE REACHED HERE. `now == exp`
/// is the discriminator for the inclusive boundary, and NO endpoint of this
/// canister can be driven at that instant from a PocketIC harness: an update
/// executes a round and the clock the canister observes is strictly later than the
/// one the harness placed it at, while a query executes no round at all and so
/// observes the last round's time rather than an advanced one. Both were tried;
/// both are recorded here rather than worked around.
///
/// So the inclusive boundary is asserted at an exactly-named instant in the two
/// places where `now` is a PARAMETER rather than a clock read: the canister's own
/// unit suite, over the shared notion every one of the three surfaces calls
/// (`effective_allowance_is_zero_from_the_expiry_instant_inclusive`), and — over
/// the real Wasm, in the block below — the production prune, driven at exactly
/// `now == exp`. The three ENDPOINTS are then asserted to agree at the first
/// observable instant at or after `exp`, which is the reading a real caller can
/// actually obtain.
///
/// The `>= exp` column is the one that is RED at the base: the query and
/// `transfer_from` reported 0 there while the CAS compared the raw stored amount
/// and demanded it.
#[test]
fn aa5_query_cas_and_transfer_from_agree_across_the_expiry_boundary() {
    let amount = 10 * STSH;

    // ── Point 1: strictly BEFORE expiry. All three must see the full amount. ───
    {
        let pic = PocketIc::new();
        let owner = p(0xA1);
        let spender = p(0xB2);
        let token = deploy(&pic, token_wasm(), owner);
        let exp = now_ns(&pic) + 10 * 60 * 1_000_000_000;
        approve_full(&pic, token, owner, None, acct(spender), amount, None, Some(exp), None)
            .expect("setup approve");

        // Stay a minute clear of the boundary so no round's clock advance can cross it.
        travel(&pic, Duration::from_nanos(9 * 60 * 1_000_000_000));
        assert!(now_ns(&pic) < exp, "still live");

        // (1) query
        assert_eq!(
            allowance(&pic, token, acct(owner), acct(spender)).allowance,
            Nat::from(amount),
            "before expiry: the query reports the full amount"
        );
        // (3) transfer_from — driven before the CAS, because the CAS rewrites the row.
        assert!(
            transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), STSH).is_ok(),
            "before expiry: transfer_from must succeed"
        );
        // (2) the CAS, against the amount the query would now report.
        let remaining = allowance(&pic, token, acct(owner), acct(spender)).allowance;
        let remaining_u128: u128 = amount - STSH;
        assert_eq!(remaining, Nat::from(remaining_u128), "the two readings agree");
        approve_full(
            &pic,
            token,
            owner,
            None,
            acct(spender),
            2 * STSH,
            Some(remaining_u128),
            Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
            None,
        )
        .expect("before expiry: a CAS against the effective allowance must pass");
    }

    // ── Point 2: EXACTLY at expiry, over the real Wasm, where `now` is a
    //            PARAMETER — the inclusive boundary, named to the nanosecond. ────
    {
        let pic = PocketIc::new();
        let owner = p(0xA1);
        let token = deploy(&pic, token_test_wasm(), owner);
        let exp = now_ns(&pic) + 10 * 60 * 1_000_000_000;

        // Three rows sharing ONE expiry instant, plus one a nanosecond later.
        inject_allowances(&pic, token, 3, exp, amount);
        assert_eq!(index_stats(&pic, token).0, 3);

        // At exp - 1: nothing is expired.
        let (removed, _) = measure_prune(&pic, token, exp - 1, PRUNE_PER_CALL);
        assert_eq!(removed, 0, "one nanosecond BEFORE the expiry instant, nothing is expired");

        // At exactly exp: ALL THREE go. An exclusive cutoff copied from
        // `prune_expired_dedup` would remove ZERO here — that is the whole
        // difference between the two maps' boundaries, and this is the assertion
        // that catches it. It also covers the tie case: several distinct rows at
        // one instant, not just one.
        let (removed, _) = measure_prune(&pic, token, exp, PRUNE_PER_CALL);
        assert_eq!(
            removed, 3,
            "AT the expiry instant every row sharing it is expired — the boundary is \
             INCLUSIVE (F-DBR-1), unlike the dedup prune's deliberately exclusive one"
        );
        assert_eq!(index_stats(&pic, token), (0, 0, true));
    }

    // ── Point 3: at or after expiry, all three surfaces. The RED column at base. ─
    {
        let pic = PocketIc::new();
        let owner = p(0xA1);
        let spender = p(0xB2);
        let token = deploy(&pic, token_wasm(), owner);
        let exp = now_ns(&pic) + 10 * 60 * 1_000_000_000;
        approve_full(&pic, token, owner, None, acct(spender), amount, None, Some(exp), None)
            .expect("setup approve");

        travel(&pic, Duration::from_nanos(11 * 60 * 1_000_000_000));
        assert!(now_ns(&pic) >= exp, "past expiry");

        // (1) query
        assert_eq!(
            allowance(&pic, token, acct(owner), acct(spender)),
            Allowance { allowance: Nat::from(0u32), expires_at: None },
            "past expiry: the query reports zero"
        );
        // (3) transfer_from — same reading, expressed as its spec-shaped refusal.
        assert_eq!(
            transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), STSH),
            Err(TransferFromError::InsufficientAllowance { allowance: Nat::from(0u32) }),
            "past expiry: transfer_from refuses with allowance 0, the SAME reading"
        );
        // (2) the CAS. Both halves of the agreement are asserted: a CAS against 0
        // must PASS, and a CAS against the stale stored amount must FAIL reporting
        // 0. At the base the first of these was impossible and the second
        // succeeded — that inversion IS MD-01.
        let stale_cas = approve_full(
            &pic,
            token,
            owner,
            None,
            acct(spender),
            STSH,
            Some(amount),
            Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
            None,
        );
        assert_eq!(
            stale_cas,
            Err(ApproveError::AllowanceChanged { current_allowance: Nat::from(0u32) }),
            "past expiry: a CAS against the RAW stored amount must be refused, and \
             must report the effective 0 — not the stale amount"
        );
        approve_full(
            &pic,
            token,
            owner,
            None,
            acct(spender),
            STSH,
            Some(0),
            Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
            None,
        )
        .expect("past expiry: a CAS against 0 must pass — the three surfaces agree");
    }
}

/// AA-6 / I-A3: a PROTOCOL-LEVEL test — no shipped-wallet caller exists for it,
/// because `revokeShieldAllowance` queries first and returns "nothing to revoke"
/// when the query reads 0, so the wallet never issues this call. It is pinned
/// anyway: after the MD-01 refactor the CAS now PASSES against an expired row
/// (both sides are 0), so the dev006 guard is the ONLY thing still refusing. If it
/// were lost, the free-row-write vector dev006 exists to close would re-open in
/// the same file and the same lane as H-01.
#[test]
fn aa6_zero_approve_against_an_expired_allowance_is_still_refused() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_wasm(), owner);

    let t = now_ns(&pic);
    let exp = t + 10 * 60 * 1_000_000_000;
    approve_full(&pic, token, owner, None, acct(spender), 5 * STSH, None, Some(exp), None)
        .expect("setup approve");

    pic.advance_time(Duration::from_nanos(11 * 60 * 1_000_000_000));
    pic.tick();
    assert_eq!(allowance(&pic, token, acct(owner), acct(spender)).allowance, Nat::from(0u32));

    // expected_allowance = 0 now MATCHES the effective allowance, so the CAS is
    // satisfied; dev006 must still refuse.
    let r = approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        0,
        Some(0),
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None,
    );
    match r {
        Err(ApproveError::GenericError { error_code, .. }) => assert_eq!(
            error_code,
            Nat::from(ERR_CODE_ZERO_AMOUNT),
            "dev006's refusal, unchanged in OUTCOME by the MD-01 refactor"
        ),
        other => panic!("a zero approve with nothing live to revoke must be refused, got {other:?}"),
    }
}

// =============================================================================
// §2.7 — enforcement is INDEPENDENT of cleanup.
// =============================================================================

/// The timer reclaims storage. It must never be what decides whether an allowance
/// is spendable. Here nothing ever prunes — no further approve, no transfer_from,
/// and the clock is moved without letting a maintenance interval elapse — and all
/// three authorisation surfaces still treat the expired allowance as zero.
#[test]
fn expiry_is_enforced_even_though_nothing_has_pruned() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_test_wasm(), owner);

    let t = now_ns(&pic);
    let exp = t + 60 * 1_000_000_000; // 60 s, comfortably inside one 300 s interval
    approve_full(&pic, token, owner, None, acct(spender), 5 * STSH, None, Some(exp), None)
        .expect("setup approve");

    // Past expiry, but NOT past a maintenance interval, and with no further writes.
    pic.advance_time(Duration::from_nanos(61 * 1_000_000_000));
    pic.tick();

    // The row is still resident — cleanup has not run.
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(primary, 1, "the expired row is still stored: nothing has reclaimed it");
    assert_eq!(index, 1);
    assert!(bijective);

    // And it is nonetheless unspendable, on all three surfaces.
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(spender)),
        Allowance { allowance: Nat::from(0u32), expires_at: None },
        "the query enforces expiry regardless of reclamation"
    );
    assert_eq!(
        transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), STSH),
        Err(TransferFromError::InsufficientAllowance { allowance: Nat::from(0u32) }),
        "transfer_from enforces expiry regardless of reclamation"
    );
    let cas = approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        STSH,
        Some(5 * STSH), // the RAW stored amount — must now be refused
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None,
    );
    assert!(
        matches!(cas, Err(ApproveError::AllowanceChanged { ref current_allowance })
            if *current_allowance == Nat::from(0u32)),
        "the CAS enforces expiry regardless of reclamation, and reports 0; got {cas:?}"
    );
}

// =============================================================================
// AA-3 — (f2): reclamation on each implemented trigger, and the pinned observable.
// =============================================================================

/// SSA N-1, the case that would pass on a broken implementation without it: the
/// approve carries NO `created_at_time`, so `record_dedup` is never called and any
/// prune hung off that call site never fires. Reclamation must still occur.
#[test]
fn aa3_reclamation_fires_on_an_approve_with_no_created_at_time() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);

    let t = now_ns(&pic);
    let short = t + 30 * 1_000_000_000;
    // A batch of rows that will all be expired shortly. Injected through the
    // production writer so the index is real.
    inject_allowances(&pic, token, 10, short, STSH);
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!((primary, index, bijective), (10, 10, true), "fixture: 10 indexed rows");

    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();

    // The trigger: one approve with created_at_time = None. This is the attacker's
    // cheaper call shape and the one that used to switch reclamation off.
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(p(0xB2)),
        STSH,
        None,
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None, // ← no created_at_time
    )
    .expect("approve with no created_at_time");

    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(
        primary, 1,
        "the 10 expired rows were reclaimed and only the new approval remains — an \
         implementation that pruned only inside the created_at_time branch would \
         report 11 here"
    );
    assert_eq!(index, 1);
    assert!(bijective);
}

/// `icrc2_transfer_from` MAINTAINS the index for the row it touches, and does NOT
/// prune anybody else's — a drift-lock in the direction the design was ruled to.
///
/// An earlier revision of this lane pruned here too (SSA N-2's second trigger
/// site). It was removed after `r1_ac10_hot_path_cost_is_within_the_ceiling`
/// measured +34,526 instructions (+37.896 %) on this endpoint against a ceiling of
/// 6,000 instructions or 6 % — a permanent tax on the ledger's highest-volume call
/// (CTO ruling `cto-ruling-harden02-ac10-and-residuals-2026-09-17`, AC-10 Option 2).
///
/// This test is deliberately written so that RE-ADDING the prune turns it RED,
/// rather than being deleted along with the code. AC-10 would also catch a
/// re-addition, but only on a machine that runs it with the base measure Wasm
/// present; this one catches it anywhere the suite runs, and says why in its own
/// failure message. The two halves are asserted separately because they are
/// different claims: "does not prune others" is the ruling, and "still maintains
/// its own row's index entry" is the invariant that must survive it (I-A10).
#[test]
fn aa3_transfer_from_maintains_its_own_row_but_does_not_prune_others() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_test_wasm(), owner);

    let t = now_ns(&pic);
    // A live allowance for the spender, plus a batch that will expire.
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        100 * STSH,
        None,
        Some(t + MAX_APPROVAL_TTL_NS),
        None,
    )
    .expect("setup approve");
    inject_allowances(&pic, token, 10, t + 30 * 1_000_000_000, STSH);
    assert_eq!(index_stats(&pic, token).0, 11);

    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();

    transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), STSH)
        .expect("transfer_from against the live allowance");

    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(
        primary, 11,
        "icrc2_transfer_from must NOT run the bounded prune: the 10 expired rows are          still resident and only the timer or a later approve reclaims them. Seeing 1          here means the hot-path trigger was re-added — which is a +37.9 % AC-10          ceiling breach on this endpoint, not an improvement"
    );
    assert_eq!(index, 11, "and the index still mirrors them");
    assert!(
        bijective,
        "the row transfer_from DID touch must still have its index entry maintained —          dropping the prune must not drop the single-writer discipline with it"
    );

    // The touched row really was rewritten, so the maintenance that DOES belong on
    // this path happened: 100 STSH - 1 STSH spent, expiry preserved.
    let a = allowance(&pic, token, acct(owner), acct(spender));
    assert_eq!(a.allowance, Nat::from(99 * STSH));
    assert!(a.expires_at.is_some(), "and kept its expiry");

    // One approve now reclaims the backlog, proving the surviving write-path trigger
    // still works and that the rows above were merely waiting, not stranded.
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(p(0xFB)),
        STSH,
        None,
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None,
    )
    .expect("an approve still prunes");
    assert_eq!(
        index_stats(&pic, token).0,
        2,
        "the 10 expired rows go on the next approve; the spender's live row and the          new one remain"
    );
}

/// Drain-to-zero reclaims, and the pinned observable is `{0, null}`.
#[test]
fn aa3_drain_to_zero_reclaims_the_row() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_test_wasm(), owner);

    let t = now_ns(&pic);
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        3 * STSH,
        None,
        Some(t + MAX_APPROVAL_TTL_NS),
        None,
    )
    .expect("setup approve");
    assert_eq!(index_stats(&pic, token).0, 1);

    // Spend it down to EXACTLY zero.
    transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), 3 * STSH)
        .expect("drain the whole allowance");

    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(primary, 0, "an allowance drained to zero authorises nothing, so the row goes");
    assert_eq!(index, 0);
    assert!(bijective);
    assert_eq!(
        allowance(&pic, token, acct(owner), acct(spender)),
        Allowance { allowance: Nat::from(0u32), expires_at: None },
        "AA-3 pinned observable: {{0, null}}, the same shape an expired row reports"
    );

    // A partial drain does NOT reclaim — the residual allowance is still live.
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(spender),
        5 * STSH,
        None,
        Some(now_ns(&pic) + MAX_APPROVAL_TTL_NS),
        None,
    )
    .expect("re-approve");
    transfer_from(&pic, token, spender, acct(owner), acct(p(0xC3)), 2 * STSH)
        .expect("partial drain");
    let a = allowance(&pic, token, acct(owner), acct(spender));
    assert_eq!(a.allowance, Nat::from(3 * STSH), "the remainder stays spendable");
    assert!(a.expires_at.is_some(), "and keeps its original expiry");
    assert_eq!(index_stats(&pic, token).0, 1);
}

// =============================================================================
// AA-3a — the prune is BOUNDED under an adversarial fresh flood (G-A1).
// =============================================================================

/// The H-3 regression test applied to a second map. N unexpired rows, nothing
/// expired: the per-call work must show no term in N. A test that merely shows
/// expired rows disappear does not discharge this — that is why the observable is
/// the instruction counter and not the row count.
#[test]
fn aa3a_prune_cost_does_not_scale_with_the_number_of_live_rows() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);
    let far = t + MAX_APPROVAL_TTL_NS; // nothing expires during this test

    inject_allowances(&pic, token, 100, far, STSH);
    let (removed_small, cost_small) = measure_prune(&pic, token, t, PRUNE_PER_CALL);
    assert_eq!(removed_small, 0, "nothing is expired — this is the adversarial flood");

    // Keys are derived from the loop index, so this RENEWS rows 0..100 and adds
    // 100..5000 — 5,000 distinct rows, a ~50x larger resident set.
    inject_allowances(&pic, token, 5_000, far, STSH);
    let (removed_large, cost_large) = measure_prune(&pic, token, t, PRUNE_PER_CALL);
    assert_eq!(removed_large, 0);

    println!(
        "AA-3a allowance prune instructions: live N=100 -> {}, N=5000 -> {} (ratio {:.2})",
        cost_small,
        cost_large,
        cost_large as f64 / (cost_small.max(1)) as f64
    );

    // A 50x larger resident set must not cost anywhere near 50x. The ceiling is
    // deliberately generous (4x + fixed slack): it passes a bounded range scan and
    // fails a reintroduced full walk, which would be ~50x.
    assert!(
        cost_large <= cost_small.saturating_mul(4).saturating_add(500_000),
        "prune cost scaled with the LIVE row count — an O(N) walk has been \
         reintroduced: N=100 {cost_small} vs N=5000 {cost_large}"
    );

    // The flood left the bijection intact, evaluated by the production predicate.
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(primary, 5_000);
    assert_eq!(index, 5_000);
    assert!(bijective, "I-A10: the index stays in bijection with ALLOWANCES under load");
}

/// The bijection drift-lock, driving the PRODUCTION writer (SI-10). The H-3
/// suite's original assertions were vacuous because they went through a local
/// helper; `inject_allowances_for_test` calls `put_allowance` itself, so deleting
/// either half of its dual write REDs this.
#[test]
fn aa3a_bijection_holds_across_write_renew_and_prune_through_the_production_writer() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    inject_allowances(&pic, token, 50, t + 30 * 1_000_000_000, STSH);
    assert!(index_stats(&pic, token).2, "after writes");

    // Renewal of the SAME keys to a later expiry: the count must not double.
    inject_allowances(&pic, token, 50, t + MAX_APPROVAL_TTL_NS, 2 * STSH);
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(primary, 50, "renewal rewrites rows, it does not add them");
    assert_eq!(index, 50, "and it must not leave a stale index entry per row");
    assert!(bijective, "after renewals");

    // The renewed rows survive a pass that reaches the OLD expiry.
    let (removed, _) = measure_prune(&pic, token, t + 31 * 1_000_000_000, PRUNE_PER_CALL);
    assert_eq!(removed, 0, "a pass reaching E1 must not touch rows renewed to E2");
    assert_eq!(index_stats(&pic, token).0, 50);

    // And they go at their own expiry.
    let (removed, _) = measure_prune(&pic, token, t + MAX_APPROVAL_TTL_NS, 100);
    assert_eq!(removed, 50);
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!((primary, index, bijective), (0, 0, true), "after pruning");
}

// =============================================================================
// AA-1 — the exposure at the base, across BOTH attacker-chosen key halves, and
// the zero-marginal-cost subaccount shuffle that refutes a minimum-balance bound.
// =============================================================================

/// Admission is not capped per approver, per spender, or globally — and it must
/// not be (option (d): a ceiling an attacker can fill locks out honest approvals).
/// What bounds the map is the lifetime plus reclamation, not a refusal at the door.
/// This test demonstrates the admission side is open on both halves of the key and
/// then shows the reclamation side closing it.
#[test]
fn aa1_admission_is_uncapped_on_both_key_halves_and_reclamation_is_what_bounds_it() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let attacker = p(0x77);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);
    let exp = t + 30 * 1_000_000_000;

    assert_eq!(balance_of(&pic, token, acct(attacker)), 0, "the attacker holds nothing");

    // Half 1 — the SPENDER account is attacker-chosen: many distinct spenders from
    // one zero-balance approver.
    let n_spenders = 12u8;
    for i in 0..n_spenders {
        approve_full(&pic, token, attacker, None, acct(p(0xC0 + i)), STSH, None, Some(exp), None)
            .unwrap_or_else(|e| panic!("zero-balance approve {i} refused: {e:?}"));
    }
    // Half 2 — the APPROVER's subaccount is caller-chosen: many distinct rows for
    // ONE spender, from one principal.
    let n_subs = 12u8;
    for i in 0..n_subs {
        approve_full(
            &pic,
            token,
            attacker,
            Some([0xD0 + i; 32]),
            acct(p(0xEE)),
            STSH,
            None,
            Some(exp),
            None,
        )
        .unwrap_or_else(|e| panic!("subaccount-keyed approve {i} refused: {e:?}"));
    }
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(
        primary,
        (n_spenders + n_subs) as u64,
        "both halves of the key are attacker-supplied, and nothing caps the count"
    );
    assert!(bijective);
    assert_eq!(index, primary);
    assert_eq!(
        balance_of(&pic, token, acct(attacker)),
        0,
        "and it cost the attacker nothing: TRANSFER_FEE is 0 and no fee was debited"
    );

    // Now the half that actually closes it: let everything expire, then apply ONE
    // trigger, and watch the resident set collapse.
    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();
    approve_full(
        &pic,
        token,
        owner,
        None,
        acct(p(0xFA)),
        STSH,
        None,
        Some(now_ns(&pic) + WALLET_APPROVAL_TTL_NS),
        None,
    )
    .expect("one honest approve as the trigger");
    let (primary, _, bijective) = index_stats(&pic, token);
    assert_eq!(
        primary, 1,
        "reclamation, not refusal, is what bounds the map — and no honest approval \
         was ever refused to achieve it"
    );
    assert!(bijective);
}

/// The refutation of option (c), minimum-balance admission, made EXECUTABLE so no
/// future lane re-proposes it: one X, held once, funds unboundedly many rows.
/// `icrc1_transfer` carries the same `TRANSFER_FEE = 0`, so the balance simply
/// walks from subaccount to subaccount and approves from each, at zero marginal
/// cost. A bound that checks a MOBILE resource at admission time bounds nothing.
#[test]
fn aa1_the_subaccount_shuffle_defeats_a_minimum_balance_bound_at_zero_marginal_cost()
{
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let attacker = p(0x77);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);
    let exp = t + MAX_APPROVAL_TTL_NS;

    // Fund the attacker's first subaccount ONCE with a notional "minimum balance".
    let stake = 10 * STSH;
    transfer_from_acct(&pic, token, owner, None, sub(attacker, 1), stake).expect("fund once");
    assert_eq!(balance_of(&pic, token, sub(attacker, 1)), stake);

    // Walk it: approve from the funded subaccount, move the WHOLE balance to the
    // next subaccount for free, repeat. Every hop leaves a fresh allowance row
    // behind while the attacker's total holding never changes.
    let hops = 8u8;
    for i in 1..=hops {
        assert_eq!(
            balance_of(&pic, token, sub(attacker, i)),
            stake,
            "hop {i}: the same X, moved, never spent"
        );
        approve_full(
            &pic,
            token,
            attacker,
            Some([i; 32]),
            acct(p(0xEE)),
            STSH,
            None,
            Some(exp),
            None,
        )
        .unwrap_or_else(|e| panic!("hop {i} approve refused: {e:?}"));
        transfer_from_acct(&pic, token, attacker, Some([i; 32]), sub(attacker, i + 1), stake)
            .unwrap_or_else(|e| panic!("hop {i} shuffle refused: {e:?}"));
    }

    assert_eq!(
        index_stats(&pic, token).0,
        hops as u64,
        "{hops} rows from ONE stake, held once — a minimum-balance admission rule \
         would have admitted every one of them"
    );
    assert_eq!(
        balance_of(&pic, token, sub(attacker, hops + 1)),
        stake,
        "and the stake is intact at the end, ready for the next hop"
    );
}

// =============================================================================
// The timer: autonomy, upgrade lifecycle, and no stacking (addendum §2.2/§2.3).
// =============================================================================

/// A burst followed by SILENCE. No further approve and no further transfer_from, so
/// neither write-path trigger runs at all. The backlog must still drain, which is
/// the whole reason the timer exists (SSA N-2).
/// MEASURED: timer_drains_a_backlog_larger_than_one_tick_over_successive_ticks
#[test]
fn timer_drains_a_backlog_with_no_further_calls() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    assert!(timer_armed(&pic, token), "init must arm the maintenance timer");

    // A burst of rows, all expiring shortly, then nothing.
    let burst = 250u64;
    inject_allowances(&pic, token, burst, t + 30 * 1_000_000_000, STSH);
    assert_eq!(index_stats(&pic, token).0, burst);

    // Past expiry, and past one maintenance interval.
    travel(&pic, Duration::from_nanos(30 * 1_000_000_000 + MAINTENANCE_INTERVAL_NS + 1));

    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!(
        primary, 0,
        "the timer must reclaim a burst that no later call touches; {burst} rows expired \
         and {primary} are still resident"
    );
    assert_eq!(index, 0);
    assert!(bijective, "the timer maintains the same bijection the write paths do");
}

/// A backlog LARGER than one tick's cap drains over successive ticks, and
/// terminates. This is the (iii) figure AA-8 owes: worst-case burst residency is a
/// function of elapsed intervals, not of organic traffic.
#[test]
fn timer_drains_a_backlog_larger_than_one_tick_over_successive_ticks() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    let burst = PRUNE_PER_TICK * 2 + 250;
    inject_allowances(&pic, token, burst, t + 30 * 1_000_000_000, STSH);
    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();

    let mut ticks = 0u32;
    loop {
        let before = index_stats(&pic, token).0;
        if before == 0 {
            break;
        }
        travel(&pic, Duration::from_nanos(MAINTENANCE_INTERVAL_NS + 1));
        ticks += 1;
        let after = index_stats(&pic, token).0;
        assert!(after < before, "tick {ticks} made no progress: {before} -> {after}");
        assert!(ticks <= 10, "a bounded backlog must drain in bounded ticks");
    }
    println!(
        "timer residency: a burst of {burst} expired rows drained in {ticks} ticks of \
         {} s each (cap {PRUNE_PER_TICK}/tick)",
        MAINTENANCE_INTERVAL_NS / 1_000_000_000
    );
    assert!(index_stats(&pic, token).2);
}

/// IC timers DO NOT survive an upgrade. `post_upgrade` must re-arm, and the proof
/// is behavioural: after the upgrade, a backlog that only the timer can reach must
/// still drain. Asserting `timer_armed` alone would not discharge this — a stored
/// id proves a variable was set, not that a timer fires.
#[test]
fn timer_is_rearmed_after_an_upgrade_and_still_fires() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    inject_allowances(&pic, token, 50, t + 30 * 1_000_000_000, STSH);
    upgrade(&pic, token, token_test_wasm()).expect("upgrade must succeed");
    assert!(timer_armed(&pic, token), "post_upgrade must re-arm the timer");

    // The durable index carried the backlog across the upgrade.
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!((primary, index, bijective), (50, 50, true), "the backlog survived the upgrade");

    travel(&pic, Duration::from_nanos(30 * 1_000_000_000 + MAINTENANCE_INTERVAL_NS + 1));
    assert_eq!(
        index_stats(&pic, token).0,
        0,
        "an upgrade must not silently remove the only trigger that works when \
         traffic has stopped"
    );
}

/// Repeated initialisation must not accumulate stacked timers. The observable is
/// the amount ONE interval reclaims: `ic-cdk-timers` cancels only by id, so if
/// `arm_allowance_maintenance_timer` did not clear the stored id first, three arms
/// (init + two upgrades) would leave three interval timers and one interval would
/// reclaim up to three caps instead of one.
#[test]
fn timer_does_not_stack_across_repeated_upgrades() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);

    // init armed one. Two upgrades would arm two more if arming were not idempotent.
    // The clock advances between installs because the replica rate-limits
    // back-to-back install_code messages ("executed too many instructions in the
    // previous install_code messages"), which is a harness constraint and not a
    // property of the canister.
    travel(&pic, Duration::from_secs(86_400));
    upgrade(&pic, token, token_test_wasm()).expect("upgrade 1");
    travel(&pic, Duration::from_secs(86_400));
    upgrade(&pic, token, token_test_wasm()).expect("upgrade 2");
    assert!(timer_armed(&pic, token));

    // A backlog strictly larger than one cap but smaller than two, so "one timer"
    // and "more than one timer" give different answers after exactly one interval.
    let t = now_ns(&pic);
    let burst = PRUNE_PER_TICK + 500;
    inject_allowances(&pic, token, burst, t + 30 * 1_000_000_000, STSH);
    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();
    assert_eq!(index_stats(&pic, token).0, burst, "fixture: the whole burst is expired");

    travel(&pic, Duration::from_nanos(MAINTENANCE_INTERVAL_NS + 1));
    let remaining = index_stats(&pic, token).0;
    assert_eq!(
        remaining,
        burst - PRUNE_PER_TICK,
        "exactly ONE tick's worth was reclaimed in one interval. A larger reduction \
         means arming stacked timers across the two upgrades: {burst} - {remaining} \
         reclaimed against a per-tick cap of {PRUNE_PER_TICK}"
    );
}

// =============================================================================
// AA-8 / §2.8 — the measured envelope. LOCAL measurement, labelled projections.
// =============================================================================

/// Storage, measured as ALLOCATED STABLE PAGES rather than `len() * record_size`.
///
/// Why the distinction matters: under dev007 every row is the 25-byte
/// `AllowanceRecord` case (an `expires_at` is always present), so a "17 bytes"
/// figure understates the payload by ~50 % — but the payload is not the cost
/// either. The real row cost is the composite primary key (bounded at 136 bytes),
/// the index entry (8 bytes plus the same key), and `StableBTreeMap`'s own node
/// overhead in both maps. This test reports the figure the canister is actually
/// charged for.
///
/// It also reports the flood → prune → reflood shape honestly. The IC
/// stable-memory API only ever GROWS: removing rows returns pages to each map's
/// free list for reuse, never to the system, so the canister keeps paying for its
/// peak. The residual footprint after a drained flood is the honest number, and it
/// is printed whether or not it is the one anybody hoped for.
#[test]
fn allowance_storage_envelope_measured_in_allocated_pages() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);
    const PAGE: u64 = 64 * 1024;

    let baseline_pages = stable_pages(&pic, token);

    // FLOOD.
    let n = 20_000u64;
    inject_allowances(&pic, token, n, t + 30 * 1_000_000_000, STSH);
    let flood_pages = stable_pages(&pic, token);
    let (primary, index, bijective) = index_stats(&pic, token);
    assert_eq!((primary, index, bijective), (n, n, true));
    let grown = flood_pages - baseline_pages;

    // PRUNE the whole flood.
    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();
    let mut passes = 0u64;
    loop {
        let (removed, _) = measure_prune(&pic, token, now_ns(&pic), 5_000);
        if removed == 0 {
            break;
        }
        passes += 1;
        assert!(passes < 100, "the flood must drain in bounded passes");
    }
    assert_eq!(index_stats(&pic, token).0, 0, "flood drained");
    let pruned_pages = stable_pages(&pic, token);

    // REFLOOD the same volume.
    let t2 = now_ns(&pic);
    inject_allowances(&pic, token, n, t2 + 30 * 1_000_000_000, STSH);
    let reflood_pages = stable_pages(&pic, token);

    println!(
        "AA-8 storage envelope (LOCAL PocketIC, not mainnet):\n  \
         rows                  : {n}\n  \
         baseline pages        : {baseline_pages} ({} B)\n  \
         after flood           : {flood_pages} ({} B) — grew {grown} pages, {} B/row\n  \
         after full prune      : {pruned_pages} pages — stable memory does NOT shrink; \
         deletion returns pages to each map's free list, never to the system\n  \
         after reflood         : {reflood_pages} pages — growth over the pruned figure is \
         {} pages, which is the page-REUSE measurement\n  \
         AllowanceRecord case  : 25 bytes (every row under dev007), key bounded at 136 B, \
         index entry 8 B + key — the per-row payload is a fraction of the allocated cost above",
        baseline_pages * PAGE,
        flood_pages * PAGE,
        (grown * PAGE) / n,
        reflood_pages.saturating_sub(pruned_pages),
    );

    // The falsifiable part: refilling the same volume must reuse the pages the
    // prune freed rather than allocating a second copy. If it did not, a
    // flood/prune cycle would ratchet the footprint up without bound.
    let reflood_growth = reflood_pages.saturating_sub(pruned_pages);
    assert!(
        reflood_growth * 4 <= grown.max(1),
        "refilling {n} rows after a full prune grew allocation by {reflood_growth} pages \
         against the original {grown} — the freed pages are not being reused, so a \
         flood/prune cycle ratchets the footprint"
    );
    assert!(index_stats(&pic, token).2, "bijection intact through flood/prune/reflood");
}

/// AA-8 (AA-8 CONTRADICTION FIXED — the brief's V2 text targeted mainnet `pzp6e`,
/// which its own §6 prohibits). This measures approve throughput and prune
/// throughput on a LOCAL PocketIC replica and states the projection explicitly as
/// a projection.
///
/// `#[ignore]`: this is a measurement harness, not an invariant — it reports
/// figures for the packet and would otherwise add minutes to every gate run. Run
/// it deliberately with `--ignored`. Reason required by the no-skips lint and given
/// here: nothing about correctness depends on it, and the figures it produces are
/// transcribed into the HARDEN-02 packet rather than asserted.
#[test]
#[ignore = "measurement harness for the AA-8 envelope; run with --ignored and transcribe into the packet"]
fn allowance_prune_throughput_local_measurement() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    // Real ingress approves, timed, so the "sustained approve rate" figure is a
    // measurement of this endpoint and not of the fixture.
    let real_approves = 200u32;
    let started = std::time::Instant::now();
    for i in 0..real_approves {
        approve_full(
            &pic,
            token,
            p(0x77),
            Some([(i % 250) as u8; 32]),
            acct(p(0xEE)),
            STSH,
            None,
            Some(t + MAX_APPROVAL_TTL_NS),
            None,
        )
        .expect("approve");
    }
    let approve_elapsed = started.elapsed();

    // Prune cost per row, at a realistic backlog.
    inject_allowances(&pic, token, 50_000, t + 30 * 1_000_000_000, STSH);
    pic.advance_time(Duration::from_nanos(31 * 1_000_000_000));
    pic.tick();
    let (removed, instr) = measure_prune(&pic, token, now_ns(&pic), PRUNE_PER_TICK);
    assert!(removed > 0, "fixture guard: the prune must report real work");

    println!(
        "AA-8 throughput (LOCAL PocketIC — NOT mainnet, no mainnet call was made):\n  \
         approves              : {real_approves} in {:?} ({:.1}/s on this replica)\n  \
         prune                 : {removed} rows for {instr} instructions ({} instr/row)\n  \
         PROJECTION, stated as a projection: a PocketIC replica is a single-node, \
         in-process execution environment, so its wall-clock rate is an upper bound on \
         nothing and a lower bound on nothing with respect to a 34-node subnet. The \
         figure that DOES transfer is instructions/row, because the instruction cost of \
         a message is a property of the Wasm and not of the subnet size; subnet size \
         enters only through the cycle PRICE per instruction and per byte-second of \
         stable memory. Any rows-per-day bound derived from this must be derived from \
         ingress capacity and the instruction figure, and labelled as derived.\n  \
         WHAT THIS DOES NOT ESTABLISH: (f) bounds the resident set, not peak burn. An \
         attacker still makes the canister carry a TTL of rows and pay to prune them. \
         Only a nonzero approve fee would move that cost onto the attacker, and that is \
         barred without a fee-model ruling.",
        approve_elapsed,
        real_approves as f64 / approve_elapsed.as_secs_f64(),
        instr / removed.max(1),
    );
}

// =============================================================================
// G-A2 / §4.4 — the format boundary and the migration-free premise.
// =============================================================================

/// `(f1)` is migration-free if and only if this lands before the `stsh_token`
/// install: with mandatory expiry there are no legacy `expires_at: None` rows to
/// reclaim, ever. The premise is that a fresh install starts with no allowance
/// rows, and it is asserted rather than assumed — including that the new index
/// starts empty, which is what makes the bijection true from the first block.
#[test]
fn fresh_install_starts_with_no_allowance_rows_or_index_entries() {
    let pic = PocketIc::new();
    let token = deploy(&pic, token_test_wasm(), p(0xA1));
    assert_eq!(
        index_stats(&pic, token),
        (0, 0, true),
        "a fresh install carries no allowance rows and no index entries, so there is \
         nothing to migrate and the bijection holds from block zero"
    );
}

/// The stored `AllowanceRecord` format is UNCHANGED by this lane (G-A2):
/// `expires_at` is still `Option<u64>` on the wire and in stable memory, and only
/// the admission rule moved. An allowance written before an upgrade must read back
/// identically after it.
#[test]
fn allowance_record_format_survives_an_upgrade_unchanged() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xB2);
    let token = deploy(&pic, token_wasm(), owner);

    let t = now_ns(&pic);
    let exp = t + MAX_APPROVAL_TTL_NS;
    approve_full(&pic, token, owner, None, acct(spender), 42 * STSH, None, Some(exp), None)
        .expect("approve");
    let before = allowance(&pic, token, acct(owner), acct(spender));

    upgrade(&pic, token, token_wasm()).expect("upgrade");

    assert_eq!(
        allowance(&pic, token, acct(owner), acct(spender)),
        before,
        "the stored allowance format is untouched by this lane"
    );
    assert_eq!(before.expires_at, Some(exp), "and the expiry is the one that was stored");
}
