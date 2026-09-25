// =============================================================================
// Upgrade-persistence hardening Phase 1 — CROSS-WASM sentinel contract
// =============================================================================
//
// BRIEF_UPGRADE_PERSISTENCE_HARDENING_V2, "Sentinel construction contract".
//
// The encoding half of the contract (sentinel round-trips; no valid state can
// collide with it; malformed regions decode as sentinel) is proved natively in
// `canisters/eager-cell`. It CANNOT establish the two properties that matter
// operationally, because both require a real replica and two DIFFERENT Wasm
// modules:
//
//   (a) target cell ABSENT  → `post_upgrade` MUST trap
//   (b) legitimate retained state → passes through UNCHANGED
//
// The brief is explicit that a same-Wasm install→upgrade→assert test does NOT
// satisfy this. Both cases below are genuinely cross-Wasm:
//
//   (a) install the PRE-CONVERSION Wasm built from f2d9ee7 (it still has the
//       `pre_upgrade` checkpoint and never allocates the eager cell's
//       MemoryId), then upgrade to the converted production Wasm. The eager
//       cell's region is fresh, `Cell::init` stores the sentinel, and
//       `post_upgrade` must trap on it.
//
//   (b) install the converted PRODUCTION Wasm, mutate, then upgrade to the
//       converted TESTING Wasm — a distinct module carrying the read-only
//       `eager_cell_probe_for_test` export. State must survive byte-identically.
//       The probe lets the assertion read the DURABLE bytes rather than
//       inferring persistence from a downstream getter.
//
// PREREQUISITES (preflighted by run_gate.sh — do not run this suite by hand
// without them):
//   nullifier_registry_base_f2d9ee7.wasm / merkle_tree_base_f2d9ee7.wasm /
//   vesting_base_f2d9ee7.wasm   — built from a detached worktree at f2d9ee7
//   *_test.wasm for the same three — built with --features testing

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use std::time::Duration;
use serde::{Deserialize, Serialize};

// ── Wasm loaders ─────────────────────────────────────────────────────────────

fn load_wasm(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "{label}: cannot read {path}: {e}\n\
             Build artifacts are missing — run ./run_gate.sh (law #7 two-phase build)."
        )
    })
}

fn nullifier_prod() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry")
}
fn nullifier_test() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_TEST_WASM"), "nullifier_registry_test")
}
fn nullifier_base() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_BASE_F2D9EE7_WASM"), "nullifier_registry_base")
}
fn merkle_prod() -> Vec<u8> {
    load_wasm(env!("MERKLE_WASM"), "merkle_tree")
}
fn merkle_test() -> Vec<u8> {
    load_wasm(env!("MERKLE_TEST_WASM"), "merkle_tree_test")
}
fn merkle_base() -> Vec<u8> {
    load_wasm(env!("MERKLE_BASE_F2D9EE7_WASM"), "merkle_tree_base")
}
fn vesting_prod() -> Vec<u8> {
    load_wasm(env!("VESTING_WASM"), "vesting")
}
fn vesting_test() -> Vec<u8> {
    load_wasm(env!("VESTING_TEST_WASM"), "vesting_test")
}
fn vesting_base() -> Vec<u8> {
    load_wasm(env!("VESTING_BASE_F2D9EE7_WASM"), "vesting_base")
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn new_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    cid
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
struct NewSchedule {
    beneficiary: Principal,
    total_amount: candid::Nat,
    cliff_months: u32,
    linear_months: u32,
}

#[derive(CandidType, Serialize, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal,
    controller: Principal,
    schedules: Vec<NewSchedule>,
}

fn vesting_init() -> VestingInitArgs {
    VestingInitArgs {
        token_canister: p(11),
        controller: p(12),
        schedules: vec![],
    }
}

/// Clear the replica's install_code rate limiter between an install and the
/// upgrade that follows it.
///
/// This is NOT cosmetic. An expensive `init` (merkle-tree does 33 Poseidon
/// hashes building its zero-value table) makes the very next `install_code`
/// message come back `CanisterInstallCodeRateLimited` — a SysTransient reject
/// that never executes `post_upgrade` at all. A trap test that only asserted
/// "the upgrade failed" would PASS on that error while proving nothing about
/// the sentinel. That is precisely the false green the brief warns about, so
/// every negative test below asserts on the trap MESSAGE, and this helper
/// removes the transient error that would otherwise mask it.
fn settle_install_rate_limit(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs(600));
    for _ in 0..2 {
        pic.tick();
    }
}

/// Read the RAW durable bytes of the eager cell. Only the testing Wasm exports
/// this — that is the point: it forces (b) to be a cross-Wasm upgrade.
fn probe(pic: &PocketIc, cid: Principal) -> Vec<u8> {
    let raw = pic
        .query_call(
            cid,
            Principal::anonymous(),
            "eager_cell_probe_for_test",
            candid::encode_args(()).unwrap(),
        )
        .expect("eager_cell_probe_for_test: query rejected");
    candid::decode_one(&raw).expect("eager_cell_probe_for_test: decode failed")
}

/// The sentinel encoding, shared by every converted canister: all-0xFF over the
/// cell's fixed width. Mirrors `stsh-eager-cell` (1 + 30*N bytes).
fn sentinel_bytes(n: usize) -> Vec<u8> {
    vec![0xFFu8; 1 + 30 * n]
}

// =============================================================================
// (a) ABSENT CELL → post_upgrade MUST trap   [cross-Wasm: f2d9ee7 → converted]
// =============================================================================
//
// This is the case the brief flags as the one that gets faked. It is real here:
// the installed module is a genuinely different binary, built from a different
// commit, that never allocated the eager cell's MemoryId.
//
// The trap is INTENDED, not a defect. Nothing is on mainnet, so there is no
// legacy state to migrate, and a silent reset of the canister refs to None
// would be far worse than a blocked upgrade. Operationally this means a
// rehearsal/local canister must be WIPED and reinstalled, never upgraded
// across the conversion boundary.

#[test]
fn nullifier_registry_absent_eager_cell_traps_on_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);

    // Pre-conversion module: pre_upgrade checkpoint at MemoryId 1, no MemoryId 2.
    pic.install_canister(
        cid,
        nullifier_base(),
        candid::encode_one(p(1)).unwrap(),
        None,
    );

    settle_install_rate_limit(&pic);

    let result = pic.upgrade_canister(
        cid,
        nullifier_prod(),
        candid::encode_args(()).unwrap(),
        None,
    );

    let err = result.expect_err(
        "nullifier-registry: upgrading from the pre-conversion f2d9ee7 Wasm MUST trap — \
         the eager cell region is absent, so the sentinel survives. A success here means \
         the fail-closed gate has become fail-open.",
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("POOL_REF sentinel survived"),
        "must trap on the SENTINEL specifically, not incidentally. Got: {msg}"
    );
}

#[test]
fn merkle_tree_absent_eager_cell_traps_on_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);

    pic.install_canister(cid, merkle_base(), candid::encode_one(p(1)).unwrap(), None);

    settle_install_rate_limit(&pic);

    let err = pic
        .upgrade_canister(cid, merkle_prod(), candid::encode_args(()).unwrap(), None)
        .expect_err(
            "merkle-tree: upgrading from the pre-conversion f2d9ee7 Wasm MUST trap on the \
             surviving sentinel.",
        );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("POOL_REF sentinel survived"),
        "must trap on the SENTINEL specifically. Got: {msg}"
    );
}

#[test]
fn vesting_absent_eager_cell_traps_on_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);

    pic.install_canister(
        cid,
        vesting_base(),
        candid::encode_one(vesting_init()).unwrap(),
        None,
    );

    settle_install_rate_limit(&pic);

    let err = pic
        .upgrade_canister(cid, vesting_prod(), candid::encode_args(()).unwrap(), None)
        .expect_err(
            "vesting: upgrading from the pre-conversion f2d9ee7 Wasm MUST trap on the \
             surviving sentinel.",
        );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("CANISTER_REFS sentinel survived"),
        "must trap on the SENTINEL specifically. Got: {msg}"
    );
}

// =============================================================================
// (b) LEGITIMATE RETAINED STATE PASSES UNCHANGED  [cross-Wasm: prod → testing]
// =============================================================================
//
// Asserted on the DURABLE bytes via the probe, not on a downstream getter, so
// the test cannot pass by accident if the heap mirror were repopulated from
// somewhere other than the cell.

#[test]
fn nullifier_registry_retained_state_survives_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    let pool = p(42);

    pic.install_canister(
        cid,
        nullifier_prod(),
        candid::encode_one(pool).unwrap(),
        None,
    );

    settle_install_rate_limit(&pic);

    // Cross-Wasm: production module → testing module (distinct binaries).
    pic.upgrade_canister(cid, nullifier_test(), candid::encode_args(()).unwrap(), None)
        .expect("legitimate retained state must upgrade cleanly, not trap");

    let durable = probe(&pic, cid);
    assert_ne!(
        durable,
        sentinel_bytes(1),
        "retained state must NOT read back as the sentinel"
    );
    assert_eq!(durable[0], 1, "layout version byte must be 1");
    assert_eq!(
        durable[1] as usize,
        pool.as_slice().len(),
        "stored principal length must be unchanged"
    );
    assert_eq!(
        &durable[2..2 + pool.as_slice().len()],
        pool.as_slice(),
        "stored principal bytes must be unchanged across the upgrade"
    );

    // And the restored value is actually in force: the pool ref still gates writes.
    let rejected = pic.update_call(
        cid,
        p(99),
        "insert_nullifier",
        candid::encode_one(vec![1u8; 32]).unwrap(),
    );
    assert!(
        rejected.is_err(),
        "restored POOL_CANISTER must still reject a non-pool caller"
    );
}

#[test]
fn merkle_tree_retained_state_survives_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    let pool = p(43);

    pic.install_canister(cid, merkle_prod(), candid::encode_one(pool).unwrap(), None);

    settle_install_rate_limit(&pic);

    pic.upgrade_canister(cid, merkle_test(), candid::encode_args(()).unwrap(), None)
        .expect("legitimate retained state must upgrade cleanly, not trap");

    let durable = probe(&pic, cid);
    assert_ne!(durable, sentinel_bytes(1), "must not read back as sentinel");
    assert_eq!(durable[0], 1, "layout version byte must be 1");
    assert_eq!(
        &durable[2..2 + pool.as_slice().len()],
        pool.as_slice(),
        "stored principal bytes must be unchanged across the upgrade"
    );
}

#[test]
fn vesting_retained_state_survives_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    let args = vesting_init();
    let (token, controller) = (args.token_canister, args.controller);

    pic.install_canister(cid, vesting_prod(), candid::encode_one(args).unwrap(), None);

    settle_install_rate_limit(&pic);

    pic.upgrade_canister(cid, vesting_test(), candid::encode_args(()).unwrap(), None)
        .expect("legitimate retained state must upgrade cleanly, not trap");

    let durable = probe(&pic, cid);
    assert_ne!(
        durable,
        sentinel_bytes(2),
        "grouped cell must not read back as sentinel"
    );
    assert_eq!(durable[0], 1, "layout version byte must be 1");

    // BOTH grouped refs must survive — the whole point of grouping them is that
    // they are durable together or not at all.
    assert_eq!(
        &durable[2..2 + token.as_slice().len()],
        token.as_slice(),
        "token_canister must be unchanged"
    );
    assert_eq!(
        &durable[32..32 + controller.as_slice().len()],
        controller.as_slice(),
        "controller must be unchanged (slot 2 begins at byte 1 + 30)"
    );
}

// =============================================================================
// Grouped-cell atomicity — vesting's two refs are one durable write
// =============================================================================

#[test]
fn vesting_grouped_refs_are_never_half_applied() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    let args = vesting_init();
    let (token, controller) = (args.token_canister, args.controller);

    pic.install_canister(cid, vesting_test(), candid::encode_one(args).unwrap(), None);

    let durable = probe(&pic, cid);
    // Either BOTH slots hold their principal, or the cell is the sentinel.
    // A half-applied state — one slot written, one still 0xFF — is exactly what
    // grouping into a single Cell::set makes unrepresentable.
    let slot1 = &durable[1..31];
    let slot2 = &durable[31..61];
    assert!(
        slot1.iter().any(|b| *b != 0xFF) && slot2.iter().any(|b| *b != 0xFF),
        "both grouped slots must be populated together — no half-applied cell"
    );
    assert_eq!(&durable[2..2 + token.as_slice().len()], token.as_slice());
    assert_eq!(
        &durable[32..32 + controller.as_slice().len()],
        controller.as_slice()
    );
}
