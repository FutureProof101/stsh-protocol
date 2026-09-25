// =============================================================================
// STSH — W2 2-3-C: treasury-notification in-flight / dropped counter (PocketIC)
// =============================================================================
//
// SPEC: CTO_RULING_W2_2-3_TREASURY_NOTIFY_V2_2026-08-14 §3, as made
// build-binding by addendum A (2026-08-16). The five semantics are pre-decided;
// this suite proves the two of them that a native test structurally cannot.
//
// WHY POCKETIC AND NOT NATIVE. Native tests keep the pool's thread-locals alive
// in-process, so a native "upgrade" never re-runs `post_upgrade` across a Wasm
// boundary and would pass even if the counters were never serialized at all.
// That is a KNOWN blind spot in this codebase, not a hypothetical. Only a real
// cross-Wasm upgrade proves:
//
//   §3(1) the in-flight count SURVIVES the upgrade through the existing
//         `PoolStableState` serialization (no new MemoryId, no new region), and
//   §3(3) `post_upgrade` folds the survivors into `dropped` and resets
//         in-flight to zero.
//
// WHAT IS COVERED ELSEWHERE, AND WHY.
//   - §3(2) increment-before-spawn / unconditional-decrement-on-both-outcomes:
//     native, in `shielded_pool::w2_23c_notification_counter_tests`. It cannot
//     be driven from here — see the staging note below.
//   - §3(5) migration from a checkpoint predating this change: native, at the
//     Candid layer (a blob encoded from the exact pre-change record shape
//     decodes with both new fields `None` → restored as 0). A cross-Wasm
//     version would need the pre-change pool Wasm as a build artifact, which it
//     is not; the Candid record-width-subtyping contract IS the mechanism under
//     test and is proved directly.
//
// HOW IN-FLIGHT IS STAGED, AND THE LIMIT OF THAT.
// The state under test is "a spawned future the upgrade discarded before it
// ran". It cannot be reached deterministically from outside the canister:
// EVERY reachable treasury target — live, stopped, uninstalled, frozen —
// RESOLVES the call, and a resolved call decrements. Holding one in flight
// means winning a race inside a single PocketIC round. So these tests use the
// build-gated, controller-gated `inject_inflight_notifications_for_test`, which
// calls the SAME helper (`note_notification_spawned`) the live path calls
// immediately before `ic_cdk::spawn`. The staged heap state is therefore
// byte-for-byte what `pre_upgrade` would observe with real spawns outstanding.
//
// DISCLOSURE: consequently no test in this repo drives a REAL dropped spawn
// end-to-end. The seam is the single line `note_notification_spawned()` in
// `notify_treasury_fee`, which is read-verifiable; everything downstream of it
// is proved here, and the pairing upstream is proved natively.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release \
//       -p stsh_token -p shielded_pool -p nullifier_registry -p merkle_tree
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test w2_2_3c_inflight_counter_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
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
fn treasury_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_WASM"), "treasury")
}

// ── Mirrors ─────────────────────────────────────────────────────────────────

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
}

/// Wire mirror of the pool's `TreasuryNotificationStats` (§3(4)).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TreasuryNotificationStats {
    in_flight: u64,
    returned_failures: u64,
    upgrade_dropped: u64,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}

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

struct Stack {
    pool: Principal,
    controller: Principal,
}

fn deploy(pic: &PocketIc) -> Stack {
    let controller = p(0xC0);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);
    // R-2 (C-30): a REAL treasury, not the dummy principal this suite used to
    // pass. The pool now flushes one `PrivateTransferFee` notification at every
    // wall-clock window boundary, unconditionally — including empty windows —
    // and `upgrade_pool` below advances the clock seven days to clear PocketIC's
    // install_code rate limit. Against a dummy principal those flushes return
    // Err, and `returned_failures` would climb for reasons that have nothing to
    // do with the drop/return distinction this suite exists to prove. A treasury
    // that ACCEPTS keeps every assertion below literally `== 0`.
    let treasury = create_canister(pic);

    pic.install_canister(
        null,
        nullifier_wasm(),
        candid::encode_one(pool).expect("encode nullifier init"),
        None,
    );
    pic.install_canister(
        merkle,
        merkle_wasm(),
        candid::encode_one(pool).expect("encode merkle init"),
        None,
    );
    pic.install_canister(
        pool,
        pool_test_wasm(),
        candid::encode_one(PoolInitArgs {
            token_canister: p(0x03),
            nullifier_canister: null,
            merkle_canister: merkle,
            treasury_canister: treasury,
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .expect("encode pool init"),
        None,
    );
    pic.install_canister(
        treasury,
        treasury_wasm(),
        candid::encode_args((p(0x03), pool, controller)).expect("encode treasury init"),
        None,
    );
    Stack { pool, controller }
}

fn stats(pic: &PocketIc, s: &Stack) -> TreasuryNotificationStats {
    decode(
        "get_treasury_notification_stats",
        pic.query_call(
            s.pool,
            anon(),
            "get_treasury_notification_stats",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn failures(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "get_treasury_notification_failures",
        pic.query_call(
            s.pool,
            anon(),
            "get_treasury_notification_failures",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn inject_inflight(pic: &PocketIc, s: &Stack, n: u64) {
    let _: () = decode(
        "inject_inflight_notifications_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_inflight_notifications_for_test",
            candid::encode_one(n).unwrap(),
        ),
    );
}

/// A REAL cross-Wasm upgrade of the pool — the whole point of this suite.
///
/// Advances the simulated clock first: back-to-back installs of the ~1.4 MB
/// pool Wasm otherwise trip PocketIC's `install_code` rate limit, which is a
/// replica-side throttle, not a canister defect. Nothing on the path under test
/// has time-window semantics, so the advance is inert to the assertions.
fn upgrade_pool(pic: &PocketIc, s: &Stack) {
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(
        s.pool,
        pool_test_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    )
    .expect("pool upgrade must succeed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — §3(1) + §3(3): survivors fold into `dropped`, in-flight resets
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_w2_23c_upgrade_folds_inflight_into_dropped() {
    let pic = PocketIc::new();
    let s = deploy(&pic);

    // A fresh pool starts clean on all three quantities.
    assert_eq!(
        stats(&pic, &s),
        TreasuryNotificationStats { in_flight: 0, returned_failures: 0, upgrade_dropped: 0 },
        "test_w2_23c: a freshly installed pool must report all three counters zero"
    );

    inject_inflight(&pic, &s, 3);
    let before = stats(&pic, &s);
    assert_eq!(before.in_flight, 3, "test_w2_23c: staged in-flight must be visible pre-upgrade");
    assert_eq!(before.upgrade_dropped, 0, "test_w2_23c: nothing dropped before any upgrade");

    // The upgrade discards those futures. Cross-Wasm, not in-process.
    upgrade_pool(&pic, &s);

    let after = stats(&pic, &s);
    assert_eq!(
        after.upgrade_dropped, 3,
        "test_w2_23c: §3(3) — every in-flight notification at pre_upgrade must be folded \
         into `dropped`; got {:?}",
        after
    );
    assert_eq!(
        after.in_flight, 0,
        "test_w2_23c: §3(3) — in-flight must reset to zero after the fold; got {:?}",
        after
    );
    assert_eq!(
        after.returned_failures, 0,
        "test_w2_23c: a dropped spawn is NOT a returned failure — the two must never be \
         conflated; got {:?}",
        after
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — `dropped` is cumulative and survives upgrades that drop nothing
// ─────────────────────────────────────────────────────────────────────────────
//
// This is the property that makes `dropped` a receipt rather than a gauge: an
// operator who upgrades again before reading it must still see the earlier
// drops. It is also the direct proof that `dropped` itself rides the
// serialization, not just `in_flight`.

#[test]
fn test_w2_23c_dropped_is_cumulative_across_upgrades() {
    let pic = PocketIc::new();
    let s = deploy(&pic);

    inject_inflight(&pic, &s, 2);
    upgrade_pool(&pic, &s);
    assert_eq!(stats(&pic, &s).upgrade_dropped, 2);

    // An upgrade with nothing in flight must neither reset nor inflate it.
    upgrade_pool(&pic, &s);
    let quiet = stats(&pic, &s);
    assert_eq!(
        quiet.upgrade_dropped, 2,
        "test_w2_23c: `dropped` must persist across an upgrade that dropped nothing; got {:?}",
        quiet
    );
    assert_eq!(quiet.in_flight, 0);

    // A later drop ADDS to the running total.
    inject_inflight(&pic, &s, 5);
    upgrade_pool(&pic, &s);
    let total = stats(&pic, &s);
    assert_eq!(
        total.upgrade_dropped, 7,
        "test_w2_23c: `dropped` must accumulate (2 then 5); got {:?}",
        total
    );
    assert_eq!(total.in_flight, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — §3(4): the legacy query is unchanged and the three are distinct
// ─────────────────────────────────────────────────────────────────────────────
//
// SSA's explicit requirement: `get_treasury_notification_failures` keeps
// meaning "returned Err" and its consumers are not broken. Proving that the new
// query did not quietly redefine it means showing the two agree on the failure
// count while the OTHER two quantities move independently underneath.

#[test]
fn test_w2_23c_legacy_failures_query_unchanged_and_quantities_distinct() {
    let pic = PocketIc::new();
    let s = deploy(&pic);

    assert_eq!(failures(&pic, &s), 0);
    assert_eq!(stats(&pic, &s).returned_failures, failures(&pic, &s));

    // Move in-flight and dropped; the failure count must not follow either.
    inject_inflight(&pic, &s, 4);
    assert_eq!(
        failures(&pic, &s),
        0,
        "test_w2_23c: an in-flight notification is not a returned failure"
    );
    upgrade_pool(&pic, &s);

    let after = stats(&pic, &s);
    assert_eq!(after.upgrade_dropped, 4);
    assert_eq!(
        failures(&pic, &s),
        0,
        "test_w2_23c: a DROPPED notification must not increment the returned-Err counter — \
         the gap this lane closes is precisely that these were indistinguishable"
    );
    assert_eq!(
        after.returned_failures,
        failures(&pic, &s),
        "test_w2_23c: §3(4) — the new query's `returned_failures` must report exactly what \
         the unchanged legacy query reports"
    );
}
