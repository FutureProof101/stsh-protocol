// =============================================================================
// STSH — H-3 (EXT-2) Token Dedup DoS Remediation: behavioural PocketIC suite
// BRIEF_TOKEN_DEDUP.md §6 — the production-Wasm half of the test matrix.
// =============================================================================
//
// The DoS: the pre-H-3 prune walked the ENTIRE TRANSFER_DEDUP map on every
// created_at_time op; a fresh flood (nothing expired) never broke early, so a
// zero-fee attacker forced an O(N) scan per call. H-3 adds a time-keyed secondary
// index (TRANSFER_DEDUP_BY_TIME) so prune is a bounded range scan over the expired
// prefix, and a one-shot STATE_VERSION 1→2 migration back-fills that index from a
// legacy map.
//
// This suite exercises the PRODUCTION Wasm (real ingress + real upgrades). The
// exact prune arithmetic and the migration logic are additionally proven, with
// zero timing dependence, by the direct unit tests in canisters/token/src/lib.rs
// (mod h3_dedup_index_tests).
//
// PREREQUISITES (two-phase build — Law #7; the migration/observer tests need the
// --features testing Wasm, which carries a LOW MAX_MIGRATION_ENTRIES override and
// the inject/force-v1/observer fixtures that never exist in production):
//   # 1. test Wasm first:
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing
//   cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
//      target/wasm32-unknown-unknown/release/stsh_token_test.wasm
//   # 2. production Wasms (overwrites stsh_token.wasm):
//   cargo build --target wasm32-unknown-unknown --release \
//     -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree \
//     -p treasury -p vesting
//   # 3. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test token_dedup_dos_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm loaders ─────────────────────────────────────────────────────────────

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
            "Cannot read stsh_token TEST Wasm at {}: {}.\nBuild first (with the H-3 \
             fixtures + low migration-limit override):\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing\n  \
             cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
             target/wasm32-unknown-unknown/release/stsh_token_test.wasm",
            path, e
        )
    })
}

// ── Constants — must match canisters/token/src/lib.rs ────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH, 8 decimals
const STSH: u128 = 100_000_000; // 1 STSH in base units
const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000; // 24h
const PERMITTED_DRIFT_NS: u64 = 5 * 60 * 1_000_000_000; // 5 min
/// H-01: the lifetime this suite's approves request — 1 h, well inside the 24 h
/// `MAX_APPROVAL_TTL_NS` cap.
const APPROVAL_TTL_NS: u64 = 60 * 60 * 1_000_000_000;
/// The low `#[cfg(feature = "testing")]` override baked into token_test_wasm.
const TEST_MIGRATION_LIMIT: u64 = 8;

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

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    cid
}

/// Install a token Wasm with the full supply allocated to `owner`.
fn deploy(pic: &PocketIc, wasm: Vec<u8>, owner: Principal) -> Principal {
    let cid = create_canister(pic);
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

/// Upgrade; returns Err (formatted) if pre/post_upgrade trapped — used to assert
/// the over-limit migration aborts the upgrade.
fn upgrade(pic: &PocketIc, cid: Principal, wasm: Vec<u8>) -> Result<(), String> {
    pic.upgrade_canister(cid, wasm, candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() as u64
}

fn balance_of(pic: &PocketIc, cid: Principal, owner: Principal) -> u128 {
    let bytes = pic
        .query_call(cid, anon(), "icrc1_balance_of", candid::encode_one(acct(owner)).unwrap())
        .expect("icrc1_balance_of");
    let n: Nat = candid::decode_one(&bytes).unwrap();
    n.0.to_string().parse().unwrap()
}

fn transfer(
    pic: &PocketIc,
    cid: Principal,
    caller: Principal,
    to: Principal,
    amount: u128,
    created_at_time: Option<u64>,
) -> Result<Nat, TransferError> {
    let args = TransferArgs {
        from_subaccount: None,
        to: acct(to),
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time,
    };
    let bytes = pic
        .update_call(cid, caller, "icrc1_transfer", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc1_transfer rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

fn approve(
    pic: &PocketIc,
    cid: Principal,
    caller: Principal,
    spender: Principal,
    amount: u128,
    created_at_time: Option<u64>,
) -> Result<Nat, ApproveError> {
    let args = ApproveArgs {
        from_subaccount: None,
        spender: acct(spender),
        amount: Nat::from(amount),
        expected_allowance: None,
        // H-01 / dev007: `expires_at` is MANDATORY on icrc2_approve for any approve
        // that writes a row. DERIVED FROM `created_at_time` when one is supplied,
        // exactly as the shipped wallet derives it (wallet/src/actors/token.ts,
        // `approvalExpiresAt`), because this suite's whole subject is idempotent
        // retry: `approve_dedup_key` hashes the argument, so a retry must reproduce
        // every field BYTE-FOR-BYTE. An expiry read from the clock per attempt would
        // break dedup on precisely the path dedup exists to protect.
        expires_at: Some(created_at_time.unwrap_or_else(|| now_ns(pic)) + APPROVAL_TTL_NS),
        fee: None,
        memo: None,
        created_at_time,
    };
    let bytes = pic
        .update_call(cid, caller, "icrc2_approve", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc2_approve rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

fn transfer_from(
    pic: &PocketIc,
    cid: Principal,
    spender: Principal,
    from: Principal,
    to: Principal,
    amount: u128,
    created_at_time: Option<u64>,
) -> Result<Nat, TransferFromError> {
    let args = TransferFromArgs {
        spender_subaccount: None,
        from: acct(from),
        to: acct(to),
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time,
    };
    let bytes = pic
        .update_call(cid, spender, "icrc2_transfer_from", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc2_transfer_from rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

// ── test-feature fixtures / observer (token_test_wasm only) ───────────────────

/// Inject one PRIMARY-ONLY entry (a legacy v1 residue), keyed off `seed`.
fn inject_legacy(pic: &PocketIc, cid: Principal, seed: u64, created_at: u64) {
    let mut key = [0u8; 32];
    key[0..8].copy_from_slice(&seed.to_be_bytes());
    pic.update_call(
        cid,
        anon(),
        "inject_legacy_dedup_entry_for_test",
        candid::encode_args((key, seed, created_at)).unwrap(),
    )
    .expect("inject_legacy_dedup_entry_for_test");
}

/// Bulk-insert `count` fresh entries into BOTH maps (for the P1 perf gate).
fn inject_live(pic: &PocketIc, cid: Principal, count: u64, created_at: u64) {
    pic.update_call(
        cid,
        anon(),
        "inject_live_dedup_entries_for_test",
        candid::encode_args((count, created_at)).unwrap(),
    )
    .expect("inject_live_dedup_entries_for_test");
}

/// Strip the time index + arm the v1 checkpoint (simulate a legacy v1 canister).
fn force_v1(pic: &PocketIc, cid: Principal) {
    pic.update_call(
        cid,
        anon(),
        "force_v1_legacy_state_for_test",
        candid::encode_args(()).unwrap(),
    )
    .expect("force_v1_legacy_state_for_test");
}

/// Observer: (primary_len, index_len, maps_bijective, stored_checkpoint_version).
fn stats(pic: &PocketIc, cid: Principal) -> (u64, u64, bool, u32) {
    let bytes = pic
        .query_call(cid, anon(), "dedup_index_stats_for_test", candid::encode_args(()).unwrap())
        .expect("dedup_index_stats_for_test");
    candid::decode_args(&bytes).unwrap()
}

/// Instructions consumed by one prune over the current resident map.
fn measure_prune(pic: &PocketIc, cid: Principal) -> u64 {
    let bytes = pic
        .update_call(
            cid,
            anon(),
            "measure_prune_instructions_for_test",
            candid::encode_args(()).unwrap(),
        )
        .expect("measure_prune_instructions_for_test");
    candid::decode_one(&bytes).unwrap()
}

/// Instructions consumed by the migration back-fill over the current primary map.
fn measure_migration(pic: &PocketIc, cid: Principal, now: u64) -> u64 {
    let bytes = pic
        .update_call(
            cid,
            anon(),
            "measure_migration_instructions_for_test",
            candid::encode_args((now,)).unwrap(),
        )
        .expect("measure_migration_instructions_for_test");
    candid::decode_one(&bytes).unwrap()
}

fn tick_after_time_travel(pic: &PocketIc) {
    // advance_time alone does not execute a round — tick so the new time is seen.
    pic.tick();
}

// =============================================================================
// P1 — the linear-scan slope is gone (release-blocking) + the None control
// =============================================================================
#[test]
fn test_h3_p1_prune_cost_no_linear_term_and_none_control() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    // N_small resident FRESH entries → measure prune cost.
    inject_live(&pic, token, 100, t);
    let cost_small = measure_prune(&pic, token);

    // N_large resident FRESH entries (50x) → measure prune cost again. An all-fresh
    // map is exactly the adversarial flood: nothing is expired, so the bounded range
    // scan must return without walking any live entry.
    inject_live(&pic, token, 5_000, t);
    let cost_large = measure_prune(&pic, token);

    println!(
        "P1 prune instructions: N=100 -> {}, N=5000 -> {} (ratio {:.2})",
        cost_small,
        cost_large,
        cost_large as f64 / (cost_small.max(1)) as f64
    );

    // No linear term: a 50x larger resident set must NOT cost anywhere near 50x.
    // Generous ceiling (4x + fixed slack) passes the O(log N) fix and fails a
    // reintroduced O(N) full scan (which would be ~50x).
    assert!(
        cost_large <= cost_small.saturating_mul(4).saturating_add(500_000),
        "prune cost scaled with N — O(N) full-scan regression: N=100 {} vs N=5000 {}",
        cost_small,
        cost_large
    );

    // None control: a created_at_time = None transfer takes the non-idempotent path
    // and touches NEITHER dedup map, so it is N-independent by construction.
    let (p_before, i_before, bij_before, _) = stats(&pic, token);
    assert!(bij_before, "maps bijective before the None-path transfer");
    let _ = transfer(&pic, token, owner, p(0xB2), 1_000 * STSH, None).expect("None transfer ok");
    let (p_after, i_after, bij_after, _) = stats(&pic, token);
    assert_eq!(p_before, p_after, "created_at=None must NOT create a dedup entry (control)");
    assert_eq!(i_before, i_after, "created_at=None must NOT touch the time index (control)");
    assert!(bij_after, "maps still bijective after the None-path transfer");
}

// =============================================================================
// P2 — all three writers dedup within window; distinct domain keys coexist
// =============================================================================
#[test]
fn test_h3_p2_three_writers_dedup_and_coexist() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let spender = p(0xD4);
    let recip = p(0xB2);
    let token = deploy(&pic, token_wasm(), owner);
    let t = now_ns(&pic);
    let amt = 1_000 * STSH;

    // First occurrence of each writer, all sharing the SAME created_at_time so their
    // (domain-separated) entries coexist in the shared maps.
    let b1 = transfer(&pic, token, owner, recip, amt, Some(t)).expect("icrc1_transfer ok");
    let b2 = approve(&pic, token, owner, spender, amt, Some(t)).expect("icrc2_approve ok");
    // transfer_from consumes the allowance the approve just set (amt).
    let b3 = transfer_from(&pic, token, spender, owner, recip, amt, Some(t)).expect("transfer_from ok");

    // Every retry hits the dedup (Duplicate), proving all three entries coexist —
    // and that transfer_from returns Duplicate, not InsufficientAllowance, even
    // though its allowance is now exhausted (dedup precedes the allowance check).
    match transfer(&pic, token, owner, recip, amt, Some(t)) {
        Err(TransferError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, b1),
        other => panic!("icrc1_transfer retry must be Duplicate: {:?}", other),
    }
    match approve(&pic, token, owner, spender, amt, Some(t)) {
        Err(ApproveError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, b2),
        other => panic!("icrc2_approve retry must be Duplicate: {:?}", other),
    }
    match transfer_from(&pic, token, spender, owner, recip, amt, Some(t)) {
        Err(TransferFromError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, b3),
        other => panic!("icrc2_transfer_from retry must be Duplicate: {:?}", other),
    }
}

// =============================================================================
// P3 — window behaviour: within → Duplicate; past → TooOld; future-within-drift
//      accepted + deduped. (The exact prune cutoff arithmetic is unit-tested.)
// =============================================================================
#[test]
fn test_h3_p3_window_behaviour() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let recip = p(0xB2);
    let token = deploy(&pic, token_wasm(), owner);
    let amt = 1_000 * STSH;

    // (a) within window → the retry is recognised as a Duplicate (retained).
    let t = now_ns(&pic);
    let b = transfer(&pic, token, owner, recip, amt, Some(t)).expect("ok");
    pic.advance_time(Duration::from_secs(3_600)); // 1h << window
    tick_after_time_travel(&pic);
    match transfer(&pic, token, owner, recip, amt, Some(t)) {
        Err(TransferError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, b),
        other => panic!("within-window retry must be Duplicate: {:?}", other),
    }

    // (b) past window → the same created_at is now older than the window: TooOld.
    pic.advance_time(Duration::from_nanos(TX_DEDUP_WINDOW_NS + 1_000_000_000));
    tick_after_time_travel(&pic);
    match transfer(&pic, token, owner, recip, amt, Some(t)) {
        Err(TransferError::TooOld) => {}
        other => panic!("past-window retry must be TooOld: {:?}", other),
    }

    // (c) future-within-drift → accepted, and its retry is deduped.
    let now2 = now_ns(&pic);
    let future = now2 + PERMITTED_DRIFT_NS / 2;
    let bf = transfer(&pic, token, owner, recip, amt, Some(future)).expect("future-within-drift accepted");
    match transfer(&pic, token, owner, recip, amt, Some(future)) {
        Err(TransferError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, bf),
        other => panic!("future-within-drift retry must be Duplicate: {:?}", other),
    }
}

// =============================================================================
// P4a — legacy v1 → v2 migration at the REAL production limit, observer-proven
// =============================================================================
#[test]
fn test_h3_p4a_legacy_migration_observer_proof() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);
    let amt = 1_000 * STSH;

    // Populate via REAL ingress (writes both maps): 3 live entries.
    let _ = transfer(&pic, token, owner, p(0xB2), amt, Some(t)).expect("ok");
    let _ = transfer(&pic, token, owner, p(0xB3), amt, Some(t)).expect("ok");
    let _ = approve(&pic, token, owner, p(0xD4), amt, Some(t)).expect("ok");

    // Inject 2 already-expired legacy residues (real ingress can't — TooOld).
    let expired = t.saturating_sub(2 * TX_DEDUP_WINDOW_NS);
    inject_legacy(&pic, token, 9_001, expired);
    inject_legacy(&pic, token, 9_002, expired);

    let (p0, i0, _, v0) = stats(&pic, token);
    assert_eq!(p0, 5, "primary = 3 real + 2 injected legacy");
    assert_eq!(i0, 3, "index has only the 3 real-ingress entries");
    assert_eq!(v0, 0, "no checkpoint written yet (fresh init, not a pre_upgrade)");

    // Strip the index + force a v1 checkpoint → legacy shape.
    force_v1(&pic, token);
    let (_, i1, _, _) = stats(&pic, token);
    assert_eq!(i1, 0, "index stripped → v1 shape (primary-only)");

    // Upgrade to PRODUCTION v2 (real MAX_MIGRATION_ENTRIES) → runs the migration.
    upgrade(&pic, token, token_wasm()).expect("production upgrade + migration must succeed");

    // Public dedup still works on the migrated index: a live retry → Duplicate.
    match transfer(&pic, token, owner, p(0xB2), amt, Some(t)) {
        Err(TransferError::Duplicate { .. }) => {}
        other => panic!("post-migration dedup must recognise the live retry: {:?}", other),
    }

    // Upgrade to the observer (test Wasm). Production already stamped v2, so the
    // observer skips migration and cannot mask a failed first back-fill.
    pic.advance_time(Duration::from_secs(86_400)); // clear the install rate limit
    tick_after_time_travel(&pic);
    upgrade(&pic, token, token_test_wasm()).expect("observer upgrade ok");

    let (pf, iff, bij, vf) = stats(&pic, token);
    // R-1 S4(a) bumped STATE_VERSION 2 -> 3 (the two supply totals joined the
    // checkpoint). The property under test is unchanged: the upgrade advanced the
    // checkpoint to the CURRENT version, so the migration arm ran and stamped it.
    assert_eq!(vf, 3, "checkpoint advanced to the current STATE_VERSION");
    assert!(bij, "maps bijective post-migration");
    assert_eq!(pf, iff, "primary and index agree post-migration");
    assert_eq!(pf, 3, "3 live entries migrated; both expired legacy entries dropped");
}

// =============================================================================
// P4b — steady state: a v2 → v2 upgrade preserves both maps and does NOT re-migrate
// =============================================================================
#[test]
fn test_h3_p4b_steady_state_no_remigration() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);
    let amt = 1_000 * STSH;

    let _ = transfer(&pic, token, owner, p(0xB2), amt, Some(t)).expect("ok");
    let _ = transfer(&pic, token, owner, p(0xB3), amt, Some(t)).expect("ok");
    let _ = approve(&pic, token, owner, p(0xD4), amt, Some(t)).expect("ok");
    let (p0, i0, bij0, v0) = stats(&pic, token);
    assert_eq!((p0, i0, bij0, v0), (3, 3, true, 0), "3 entries in both maps; no checkpoint yet");

    // Upgrade v2 → v2 (production, no force_v1) → checkpoint stays v2 → the migration
    // arm is NOT taken; both maps must survive untouched.
    upgrade(&pic, token, token_wasm()).expect("v2→v2 upgrade ok");
    match transfer(&pic, token, owner, p(0xB2), amt, Some(t)) {
        Err(TransferError::Duplicate { .. }) => {}
        other => panic!("dedup must survive a steady-state upgrade: {:?}", other),
    }

    pic.advance_time(Duration::from_secs(86_400));
    tick_after_time_travel(&pic);
    upgrade(&pic, token, token_test_wasm()).expect("observer upgrade ok");
    let (pf, iff, bij, vf) = stats(&pic, token);
    // vf: R-1 S4(a) STATE_VERSION 2 -> 3; see P4a.
    assert_eq!((pf, iff, bij, vf), (3, 3, true, 3), "both maps persisted; migration did not re-run");
}

// =============================================================================
// Migration limit — exactly-at-limit succeeds / over-limit rolls back (both use
// the LOW test-feature override, never the production limit)
// =============================================================================
#[test]
fn test_h3_migration_exactly_at_limit_succeeds() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    // Exactly TEST_MIGRATION_LIMIT live legacy entries.
    for i in 0..TEST_MIGRATION_LIMIT {
        inject_legacy(&pic, token, 1_000 + i, t);
    }
    force_v1(&pic, token);

    // Upgrade test→test (override limit): total == limit, not > limit → migrate.
    upgrade(&pic, token, token_test_wasm()).expect("exactly-at-limit migration succeeds");

    let (pf, iff, bij, _) = stats(&pic, token);
    assert_eq!(pf, TEST_MIGRATION_LIMIT, "all live entries retained");
    assert_eq!(iff, TEST_MIGRATION_LIMIT, "index back-filled to the limit (migration ran)");
    assert!(bij, "maps bijective after an at-limit migration");
}

#[test]
fn test_h3_migration_over_limit_traps_and_v1_survives() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    // One over the override limit.
    for i in 0..(TEST_MIGRATION_LIMIT + 1) {
        inject_legacy(&pic, token, 2_000 + i, t);
    }
    force_v1(&pic, token);

    // Migration traps → the whole upgrade is aborted (rolled back).
    let res = upgrade(&pic, token, token_test_wasm());
    assert!(res.is_err(), "over-limit migration must trap and abort the upgrade");

    // v1 module keeps running with state intact: responsive + no partial back-fill.
    assert_eq!(
        balance_of(&pic, token, owner),
        TOTAL_SUPPLY,
        "v1 state intact after the aborted upgrade"
    );
    let (pf, iff, _, _) = stats(&pic, token);
    assert_eq!(pf, TEST_MIGRATION_LIMIT + 1, "all legacy entries still present (rolled back)");
    assert_eq!(iff, 0, "no partial index back-fill occurred");
}

// =============================================================================
// Discriminator — the production binary EXCLUDES the low override: migrating a
// count > override but << production limit through the PRODUCTION Wasm succeeds.
// =============================================================================
#[test]
fn test_h3_discriminator_production_excludes_override() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    // 32 entries: comfortably > the test override (8), far below the production limit.
    let count = 32u64;
    assert!(count > TEST_MIGRATION_LIMIT, "must exceed the test override to be a discriminator");
    for i in 0..count {
        inject_legacy(&pic, token, 3_000 + i, t);
    }
    force_v1(&pic, token);

    // If the production binary carried the override (8), 32 > 8 would trap. It
    // succeeds → the production limit (generous) is what shipped.
    upgrade(&pic, token, token_wasm())
        .expect("production migration of 32 entries must succeed (override excluded from release)");

    pic.advance_time(Duration::from_secs(86_400));
    tick_after_time_travel(&pic);
    upgrade(&pic, token, token_test_wasm()).expect("observer upgrade ok");
    let (pf, iff, bij, vf) = stats(&pic, token);
    // vf: R-1 S4(a) STATE_VERSION 2 -> 3; see P4a.
    assert_eq!((pf, iff, bij, vf), (count, count, true, 3), "all 32 migrated under the production limit");
}

// =============================================================================
// Offline measurement (NOT part of the gate — #[ignore]) — sizes
// MAX_MIGRATION_ENTRIES_PRODUCTION against the worst-path (all-live) post_upgrade
// back-fill cost. Run explicitly:
//   cargo test -p integration-tests --test token_dedup_dos_tests \
//     measure_h3_migration_budget -- --ignored --nocapture --test-threads=1
// =============================================================================
#[test]
#[ignore = "SI-X-01: offline MEASUREMENT, not a check — it sizes \
            MAX_MIGRATION_ENTRIES_PRODUCTION and costs minutes. Its output feeds a \
            constant that IS gate-checked; the measurement itself is run by hand."]
fn measure_h3_migration_budget() {
    // All-live back-fill is the worst path: every entry becomes a B-tree insert into
    // the time index. Measure instructions/entry across N, then size the production
    // ceiling under the post_upgrade budget with margin.
    for n in [1_000u64, 5_000, 10_000, 20_000] {
        let pic = PocketIc::new();
        let owner = p(0xA1);
        let token = deploy(&pic, token_test_wasm(), owner);
        let t = now_ns(&pic);
        inject_live(&pic, token, n, t); // both maps, all fresh
        force_v1(&pic, token); // strip the index → primary-only (v1 shape)
        let instr = measure_migration(&pic, token, t); // all live → N index inserts
        println!(
            "MIGRATION N={:>6} -> {:>14} instr  ({:>7} instr/entry)",
            n,
            instr,
            instr / n
        );
    }
}

// =============================================================================
// BR-07 / BR-08 / BR-09 (lane R-11) — the post_upgrade migration budget claim,
// MEASURED IN THE GATE
//
// Three separate comments in `canisters/token/src/lib.rs` assert that the dedup
// (MEASURED: h3_post_upgrade_migration_budget_is_bounded_in_gate)
// migration cannot blow the `post_upgrade` instruction budget. Until this test
// the only evidence was `measure_h3_migration_budget` above — `#[ignore]`d,
// minutes long, and never run by the gate. A budget claim backed only by a
// measurement nobody runs is an unbacked claim.
//
// This is a cheap gate-run sibling: ONE fixture size instead of the offline
// sweep's four, deriving the per-entry cost from that run and checking the real
// production ceiling against the real post_upgrade limit.
// =============================================================================

/// The IC's per-message instruction limit for an upgrade (`post_upgrade`).
const POST_UPGRADE_INSTRUCTION_LIMIT: u64 = 200_000_000_000;

/// Gate fixture size. Small enough to run every gate, large enough that the
/// per-entry cost derived from it is not dominated by fixed call overhead.
const GATE_MIGRATION_FIXTURE_ROWS: u64 = 2_000;

/// Mutation multiplier, applied to the MEASURED per-entry cost (see the test's
/// own comment). Not a production constant and not part of the assertion's
/// right-hand side.
const R11_PER_ROW_COST_MULTIPLIER: u64 = 1;

#[test]
fn h3_post_upgrade_migration_budget_is_bounded_in_gate() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let token = deploy(&pic, token_test_wasm(), owner);
    let t = now_ns(&pic);

    // All-live back-fill is the WORST path: every entry becomes a B-tree insert
    // into the time index. Same helper chain as the offline sweep, one size.
    inject_live(&pic, token, GATE_MIGRATION_FIXTURE_ROWS, t);
    force_v1(&pic, token);
    let instr = measure_migration(&pic, token, t);
    assert!(
        instr > 0,
        "fixture guard: the migration must report real instructions consumed — a zero \
         reading makes every bound below vacuous"
    );

    let per_row_cost = instr / GATE_MIGRATION_FIXTURE_ROWS;
    let worst_case = per_row_cost
        .saturating_mul(R11_PER_ROW_COST_MULTIPLIER)
        .saturating_mul(MAX_MIGRATION_ENTRIES_PRODUCTION_MIRROR);

    println!(
        "BR-07/08/09 migration budget: {instr} instructions over \
         {GATE_MIGRATION_FIXTURE_ROWS} rows = {per_row_cost} instr/entry; \
         at MAX_MIGRATION_ENTRIES_PRODUCTION={MAX_MIGRATION_ENTRIES_PRODUCTION_MIRROR} that is \
         {worst_case} against a post_upgrade limit of {POST_UPGRADE_INSTRUCTION_LIMIT} \
         (headroom {:.2}x)",
        POST_UPGRADE_INSTRUCTION_LIMIT as f64 / worst_case.max(1) as f64
    );

    assert!(
        worst_case <= POST_UPGRADE_INSTRUCTION_LIMIT,
        "the dedup migration at the production ceiling costs {worst_case} instructions, over \
         the post_upgrade limit of {POST_UPGRADE_INSTRUCTION_LIMIT}. Measured \
         {per_row_cost} instr/entry from a {GATE_MIGRATION_FIXTURE_ROWS}-row all-live fixture. \
         A large dedup map WOULD turn post_upgrade into an instruction-limit brick."
    );
}

/// The production ceiling, mirrored as an INDEPENDENT literal.
///
/// The token crate does not export `MAX_MIGRATION_ENTRIES_PRODUCTION`, and the
/// integration suite deliberately does not link it: `production_migration_limit_
/// is_measured_value` (`canisters/token/src/lib.rs`) is the change-detector that
/// keeps the two in step, and it fires on ANY edit to the constant.
const MAX_MIGRATION_ENTRIES_PRODUCTION_MIRROR: u64 = 200_000;
