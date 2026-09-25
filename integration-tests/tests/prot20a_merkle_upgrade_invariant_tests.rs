// =============================================================================
// STSH — PROT-20a (HARDEN-01, lane TEST-T1 §3.1): the merkle-tree DEF-044 L3
// post_upgrade invariants, exercised across a REAL PocketIC upgrade.
// =============================================================================
//
// THE CODE UNDER TEST. `canisters/merkle-tree/src/lib.rs` post_upgrade
// re-derives LEAF_COUNT from `COMMITMENTS.len()` and ROOT_INDEX from
// `leaf_count + 1`, then asserts the three invariants that reconstruction
// depends on (the block at :849-874):
//
//   L3-1  COMMITMENTS holds the tail key `leaf_count - 1` when leaf_count > 0
//         -> "post_upgrade invariant violated: COMMITMENTS missing tail key"
//   L3-2  COMMITMENTS holds NO key at `leaf_count` (dense 0..leaf_count)
//         -> "post_upgrade invariant violated: COMMITMENTS has a key at leaf_count"
//   L3-3  ROOT_HISTORY occupancy == root_index.min(ROOT_HISTORY_SIZE)
//         -> "post_upgrade invariant violated: ROOT_HISTORY occupancy"
//
// WHAT WAS MISSING. All three are `assert!`s that only run inside a canister
// upgrade. Nothing in the suite drove a real upgrade of a POPULATED tree, so
// neither the happy path (a populated tree upgrades and reads back identical)
// nor any of the three trap messages had ever executed. A drift-lock that has
// never fired is a claim, not a check.
//
// INSTRUMENT. `remove_scan_pair_member_for_test` (lib.rs:507, feature =
// "testing", the P-MRK stable-map corruption hook) is the only sanctioned way
// to corrupt COMMITMENTS. Per brief §3.1 no new hook is added — this suite
// reaches all THREE asserts with the existing one, by choosing WHICH indices to
// remove:
//
//   remove a NON-tail index          -> len drops by one, so a key now sits at
//                                       the new leaf_count               -> L3-2
//   remove two ADJACENT interior     -> len drops by two; the new tail key is
//   indices below the top            -> itself one of the removed ones   -> L3-1
//   remove the TAIL index            -> COMMITMENTS stays dense, but the ring
//                                       buffer still holds the old root count
//                                                                        -> L3-3
//
// Each negative asserts the panic MESSAGE SUBSTRING, not merely that the
// upgrade failed: the point is proving the SPECIFIC invariant fired.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p merkle_tree --features testing
//   cp .../merkle_tree.wasm .../merkle_tree_test.wasm
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test prot20a_merkle_upgrade_invariant_tests -- --test-threads=1
// =============================================================================

use candid::Principal;
use pocket_ic::PocketIc;

const CYCLES: u128 = 2_000_000_000_000;

fn merkle_test_wasm() -> Vec<u8> {
    let path = env!("MERKLE_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "read merkle_tree_test Wasm {}: {} — build it first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p merkle_tree --features testing\n  \
             cp target/wasm32-unknown-unknown/release/merkle_tree.wasm \\\n     \
                target/wasm32-unknown-unknown/release/merkle_tree_test.wasm",
            path, e
        )
    })
}

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}

/// The merkle canister's `pool` — `assert_pool()` gates append and the P-MRK
/// corruption hook on exactly this principal.
fn pool() -> Principal {
    p(0x10)
}

fn deploy_merkle(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, CYCLES);
    pic.install_canister(cid, merkle_test_wasm(), candid::encode_one(pool()).unwrap(), None);
    cid
}

/// A canonical BN254 field element (little-endian small value) — the commitment
/// validator rejects anything >= the modulus.
fn commitment(tag: u8) -> Vec<u8> {
    let mut c = vec![0u8; 32];
    c[0] = tag;
    c[1] = 0x0A;
    c
}

fn append(pic: &PocketIc, m: Principal, tag: u8) -> u64 {
    let bytes = pic
        .update_call(
            m,
            pool(),
            "append_commitment",
            candid::encode_args((commitment(tag), vec![tag, 0xEE])).unwrap(),
        )
        .expect("append_commitment call");
    let res: Result<u64, String> = candid::decode_one(&bytes).expect("decode append result");
    res.expect("append_commitment must succeed for the pool principal")
}

fn populate(pic: &PocketIc, m: Principal, n: u8) {
    for i in 0..n {
        append(pic, m, 0x20 + i);
    }
}

fn leaf_count(pic: &PocketIc, m: Principal) -> u64 {
    candid::decode_one(
        &pic.query_call(m, anon(), "leaf_count", candid::encode_args(()).unwrap())
            .expect("leaf_count"),
    )
    .expect("decode leaf_count")
}

fn current_root(pic: &PocketIc, m: Principal) -> Vec<u8> {
    candid::decode_one(
        &pic.query_call(m, anon(), "get_root", candid::encode_args(()).unwrap())
            .expect("get_root"),
    )
    .expect("decode get_root")
}

/// The per-leaf root history, read back through the public surface. There is no
/// occupancy query, so this reads every retained slot: an equal vector before
/// and after an upgrade is the observable form of "the ring buffer survived".
fn root_history(pic: &PocketIc, m: Principal) -> Vec<Option<Vec<u8>>> {
    (0..leaf_count(pic, m))
        .map(|i| {
            candid::decode_one(
                &pic.query_call(m, anon(), "get_root_at_index", candid::encode_one(i).unwrap())
                    .expect("get_root_at_index"),
            )
            .expect("decode get_root_at_index")
        })
        .collect()
}

/// P-MRK corruption hook (feature = "testing"). Removes the COMMITMENTS entry
/// at `index`, leaving the payload in place.
fn remove_commitment(pic: &PocketIc, m: Principal, index: u64) {
    let bytes = pic
        .update_call(
            m,
            pool(),
            "remove_scan_pair_member_for_test",
            candid::encode_args((index, true, false)).unwrap(),
        )
        .expect("remove_scan_pair_member_for_test call");
    let res: Result<(), String> = candid::decode_one(&bytes).expect("decode hook result");
    res.unwrap_or_else(|e| panic!("corruption hook refused index {}: {}", index, e));
}

/// Upgrade to the same testing Wasm and return the trap message, if any.
///
/// The clock advance is a HARNESS limit, not a canister property: back-to-back
/// installs of the same Wasm trip PocketIC's per-canister `install_code` rate
/// limit (`CanisterInstallCodeRateLimited`), which surfaces as a SysTransient
/// reject and would masquerade as a post_upgrade failure. Same window the
/// pool's upgrade suites use (`h1_upgrade_safety_tests.rs:249-256`, widened for
/// `overflow-checks = true`). No test here has time-window semantics.
fn upgrade(pic: &PocketIc, m: Principal) -> Result<(), String> {
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(m, merkle_test_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

// =============================================================================
// Positive — a populated tree upgrades cleanly and reads back IDENTICAL
// =============================================================================

#[test]
fn test_prot20a_populated_tree_survives_a_real_upgrade_unchanged() {
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);
    populate(&pic, m, 5);

    let leaves_before = leaf_count(&pic, m);
    let root_before = current_root(&pic, m);
    let history_before = root_history(&pic, m);
    assert_eq!(leaves_before, 5, "harness precondition: five leaves appended");
    assert!(
        history_before.iter().all(|r| r.is_some()),
        "harness precondition: every appended leaf has a retained root"
    );

    upgrade(&pic, m).expect("a consistent populated tree must upgrade cleanly");

    // LEAF_COUNT and ROOT_INDEX are NOT serialized — post_upgrade re-derives
    // both. This is the assertion that the re-derivation is faithful.
    assert_eq!(leaf_count(&pic, m), leaves_before, "leaf count must survive the upgrade");
    assert_eq!(current_root(&pic, m), root_before, "the current root must survive the upgrade");
    assert_eq!(root_history(&pic, m), history_before, "the root history must survive the upgrade");

    // And the re-derived counter is still usable: the next append lands at the
    // right index rather than overwriting a live leaf.
    assert_eq!(append(&pic, m, 0x40), 5, "the next append must continue at index 5");
    assert_eq!(leaf_count(&pic, m), 6);
}

#[test]
fn test_prot20a_empty_tree_survives_a_real_upgrade() {
    // leaf_count == 0 skips L3-1 entirely (it is guarded by `if leaf_count > 0`)
    // and must still satisfy L3-2 and L3-3 — the ring buffer holds exactly the
    // init root. A tree that cannot upgrade before its first deposit would
    // strand the install sequence.
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);
    assert_eq!(leaf_count(&pic, m), 0);
    let root_before = current_root(&pic, m);

    upgrade(&pic, m).expect("an empty tree must upgrade cleanly");

    assert_eq!(leaf_count(&pic, m), 0);
    assert_eq!(current_root(&pic, m), root_before, "the empty-tree root must survive");
    assert_eq!(append(&pic, m, 0x41), 0, "the first post-upgrade append is still leaf 0");
}

// =============================================================================
// Negatives — each of the three asserts, by message
// =============================================================================

#[test]
fn test_prot20a_l3_2_key_at_leaf_count_traps_the_upgrade() {
    // Remove an INTERIOR index: COMMITMENTS.len() drops to 4, so keys {0,1,3,4}
    // now have a member sitting exactly at the new leaf_count (4). The tail-key
    // check passes first (key 3 is present), so this is unambiguously L3-2.
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);
    populate(&pic, m, 5);
    remove_commitment(&pic, m, 2);

    let err = upgrade(&pic, m).expect_err("a sparse COMMITMENTS map must trap in post_upgrade");
    assert!(
        err.contains("COMMITMENTS has a key at leaf_count"),
        "the L3-2 invariant must be the one that fired; got: {}",
        err
    );
    assert!(
        err.contains("post_upgrade invariant violated"),
        "the trap must identify itself as a post_upgrade invariant; got: {}",
        err
    );
}

#[test]
fn test_prot20a_l3_1_missing_tail_key_traps_the_upgrade() {
    // Remove indices 2 AND 3 of five: len drops to 3, keys are {0,1,4}. The new
    // tail key (leaf_count - 1 == 2) is one of the removed ones, so L3-1 fires
    // BEFORE L3-2 gets a chance (key 3 is absent, so L3-2 would have passed).
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);
    populate(&pic, m, 5);
    remove_commitment(&pic, m, 2);
    remove_commitment(&pic, m, 3);

    let err = upgrade(&pic, m).expect_err("a missing tail key must trap in post_upgrade");
    assert!(
        err.contains("COMMITMENTS missing tail key"),
        "the L3-1 invariant must be the one that fired; got: {}",
        err
    );
}

#[test]
fn test_prot20a_l3_3_root_history_occupancy_traps_the_upgrade() {
    // Remove the TAIL index: COMMITMENTS stays a dense 0..4, so L3-1 and L3-2
    // both pass. But the ring buffer still holds six roots (init + five
    // appends) while the re-derived root_index says five — exactly the drift
    // the third assert exists to catch, and the only one of the three that is
    // invisible to a COMMITMENTS-only inspection.
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);
    populate(&pic, m, 5);
    remove_commitment(&pic, m, 4);

    let err = upgrade(&pic, m).expect_err("a ring-buffer/leaf-count mismatch must trap");
    assert!(
        err.contains("ROOT_HISTORY occupancy"),
        "the L3-3 invariant must be the one that fired; got: {}",
        err
    );
}

#[test]
fn test_prot20a_a_trapped_upgrade_leaves_the_canister_on_the_OLD_state() {
    // The operator-visible consequence: trapping in post_upgrade aborts the
    // whole upgrade message, so the canister keeps serving its pre-upgrade
    // state rather than coming up with a silently wrong leaf count. This is
    // why trapping is the right behaviour and not merely a loud one.
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);
    populate(&pic, m, 5);
    let root_before = current_root(&pic, m);

    remove_commitment(&pic, m, 2);
    upgrade(&pic, m).expect_err("the corrupted upgrade must fail");

    assert_eq!(
        leaf_count(&pic, m),
        5,
        "the aborted upgrade must not install a re-derived leaf count"
    );
    assert_eq!(current_root(&pic, m), root_before, "the aborted upgrade must not move the root");
}
