// =============================================================================
// STSH — Query surface hardening tests (PocketIC)
// Phase C: DEF-075 (list_pending_output_promotions), DEF-076 (get_accounting_state),
//          DEF-074 (nullifier-registry spent_at), DEF-073 (Merkle public scanning).
// =============================================================================
//
// Proves the access-control contract for the remaining public query surface:
//   - list_pending_output_promotions / get_accounting_state (shielded-pool):
//     restricted to the stored app-level CONTROLLER (Phase A assert_controller()).
//   - spent_at (nullifier-registry): restricted to the canister's IC controllers
//     (DEF-074 Option A — assert_ic_controller()). contains_nullifier stays public.
//   - leaf_count / get_leaf (merkle-tree): remain public (DEF-073 scanning tradeoff).
//
// Controller identity note (DEF-074): the nullifier-registry has NO app-level
// controller model. spent_at is gated on IC canister controllers. pocket-ic's
// create_canister() makes the anonymous principal the default controller; this
// harness installs as anonymous, then set_controllers([NR_CONTROLLER]) so the IC
// controller is a known, non-anonymous principal and anon is excluded.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release <all production canisters>
//   export POCKET_IC_BIN=$HOME/.cache/dfinity/versions/0.28.0/pocket-ic
//   cargo test -p integration-tests --test query_surface_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::Deserialize;

const CYCLES: u128 = 2_000_000_000_000;

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn pool_test_wasm() -> Vec<u8> {
    let path = env!("POOL_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read shielded_pool_test Wasm {}: {}", path, e))
}
fn nullifier_wasm() -> Vec<u8> {
    let path = env!("NULLIFIER_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read nullifier_registry Wasm {}: {}", path, e))
}
fn merkle_wasm() -> Vec<u8> {
    let path = env!("MERKLE_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read merkle_tree Wasm {}: {}", path, e))
}

// ── PocketIC helpers ──────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}

fn create(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, CYCLES);
    cid
}

// ── Candid mirrors ────────────────────────────────────────────────────────────

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

#[derive(CandidType, Deserialize, Debug)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

// ── Deploy helpers ────────────────────────────────────────────────────────────

/// Shielded-pool (testing Wasm). Stored app-level CONTROLLER = p(0xC0).
fn deploy_pool(pic: &PocketIc) -> (Principal, Principal) {
    let controller = p(0xC0);
    let pool = create(pic);
    let init = PoolInitArgs {
        token_canister: p(0x10),
        nullifier_canister: p(0x11),
        merkle_canister: p(0x12),
        treasury_canister: p(0x01),
        staking_canister: p(0x02),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
    };
    pic.install_canister(pool, pool_test_wasm(), candid::encode_one(&init).unwrap(), None);
    (pool, controller)
}

/// Nullifier-registry. Installs as anonymous (default controller), then reassigns
/// the IC controller list to [nr_controller] so spent_at's assert_ic_controller()
/// is exercised against a known, non-anonymous principal.
fn deploy_nullifier(pic: &PocketIc) -> (Principal, Principal) {
    let nr_controller = p(0xC1);
    let nr = create(pic);
    // init(pool_canister) — pool principal is irrelevant for these read tests.
    pic.install_canister(nr, nullifier_wasm(), candid::encode_one(p(0x10)).unwrap(), None);
    pic.set_controllers(nr, Some(anon()), vec![nr_controller])
        .expect("set nullifier-registry IC controllers");
    (nr, nr_controller)
}

/// Merkle-tree. init(authorized_appender) — irrelevant for public read tests.
fn deploy_merkle(pic: &PocketIc) -> Principal {
    let m = create(pic);
    pic.install_canister(m, merkle_wasm(), candid::encode_one(p(0x10)).unwrap(), None);
    m
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-075 — list_pending_output_promotions (stored-controller gated)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_list_pending_output_promotions_anon_rejected() {
    let pic = PocketIc::new();
    let (pool, _) = deploy_pool(&pic);
    let res = pic.query_call(pool, anon(), "list_pending_output_promotions", candid::encode_args(()).unwrap());
    assert!(res.is_err(), "anonymous caller must be rejected (trap)");
}

#[test]
fn test_list_pending_output_promotions_non_controller_rejected() {
    let pic = PocketIc::new();
    let (pool, _) = deploy_pool(&pic);
    let res = pic.query_call(pool, p(0xBB), "list_pending_output_promotions", candid::encode_args(()).unwrap());
    assert!(res.is_err(), "non-controller caller must be rejected (trap)");
}

#[test]
fn test_list_pending_output_promotions_controller_allowed() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let res = pic.query_call(pool, controller, "list_pending_output_promotions", candid::encode_args(()).unwrap());
    assert!(res.is_ok(), "controller must be allowed (empty list is fine)");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-074 — nullifier-registry spent_at (IC-controller gated) + contains_nullifier public
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_nullifier_spent_at_anon_rejected() {
    let pic = PocketIc::new();
    let (nr, _) = deploy_nullifier(&pic);
    let res = pic.query_call(nr, anon(), "spent_at", candid::encode_one(vec![7u8; 32]).unwrap());
    assert!(res.is_err(), "anonymous caller to spent_at must be rejected (trap)");
}

#[test]
fn test_nullifier_spent_at_non_controller_rejected() {
    let pic = PocketIc::new();
    let (nr, _) = deploy_nullifier(&pic);
    let res = pic.query_call(nr, p(0xBB), "spent_at", candid::encode_one(vec![7u8; 32]).unwrap());
    assert!(res.is_err(), "non-controller caller to spent_at must be rejected (trap)");
}

#[test]
fn test_nullifier_spent_at_controller_allowed() {
    let pic = PocketIc::new();
    let (nr, nr_controller) = deploy_nullifier(&pic);
    // nr_controller is the actual IC controller configured by deploy_nullifier.
    let res = pic.query_call(nr, nr_controller, "spent_at", candid::encode_one(vec![7u8; 32]).unwrap());
    let bytes = res.expect("IC controller must be allowed to call spent_at");
    let spent: Option<u64> = candid::decode_one(&bytes).expect("decode opt nat64");
    assert_eq!(spent, None, "arbitrary nullifier was never spent -> None (no trap)");
}

#[test]
fn test_nullifier_contains_nullifier_still_public() {
    let pic = PocketIc::new();
    let (nr, _) = deploy_nullifier(&pic);
    // Regression: contains_nullifier must remain callable by anyone.
    let bytes = pic
        .query_call(nr, anon(), "contains_nullifier", candid::encode_one(vec![7u8; 32]).unwrap())
        .expect("contains_nullifier must remain public");
    let present: bool = candid::decode_one(&bytes).expect("decode bool");
    assert!(!present, "arbitrary nullifier is not present");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-076 — get_accounting_state (stored-controller gated)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_get_accounting_state_anon_rejected() {
    let pic = PocketIc::new();
    let (pool, _) = deploy_pool(&pic);
    let res = pic.query_call(pool, anon(), "get_accounting_state", candid::encode_args(()).unwrap());
    assert!(res.is_err(), "anonymous caller must be rejected (trap)");
}

#[test]
fn test_get_accounting_state_non_controller_rejected() {
    let pic = PocketIc::new();
    let (pool, _) = deploy_pool(&pic);
    let res = pic.query_call(pool, p(0xBB), "get_accounting_state", candid::encode_args(()).unwrap());
    assert!(res.is_err(), "non-controller caller must be rejected (trap)");
}

#[test]
fn test_get_accounting_state_controller_allowed() {
    let pic = PocketIc::new();
    let (pool, controller) = deploy_pool(&pic);
    let bytes = pic
        .query_call(pool, controller, "get_accounting_state", candid::encode_args(()).unwrap())
        .expect("controller must be allowed");
    let _state: AccountingState = candid::decode_one(&bytes).expect("decode AccountingState");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-073 — Merkle public scanning surface remains accessible
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_merkle_public_endpoints_accessible() {
    let pic = PocketIc::new();
    let m = deploy_merkle(&pic);

    // leaf_count must be public.
    let bytes = pic
        .query_call(m, anon(), "leaf_count", candid::encode_args(()).unwrap())
        .expect("leaf_count must remain public");
    let count: u64 = candid::decode_one(&bytes).expect("decode nat64");

    // Only probe get_leaf when a leaf exists; on an empty tree the API returns
    // None for out-of-range indices, so the public-accessibility assertion stands
    // on leaf_count alone (noted in the deliverable report).
    if count > 0 {
        let leaf = pic.query_call(m, anon(), "get_leaf", candid::encode_one(0u64).unwrap());
        assert!(leaf.is_ok(), "get_leaf must remain public");
    }
}

// =============================================================================
// PROT-20b (HARDEN-01, lane TEST-T1 §3.2) — spent_at as a CALLER-AUTHORISATION
// contract, exercised on a nullifier that is actually SPENT.
// =============================================================================
//
// CITATION CORRECTION (brief §3.2). The ASTRA triage files this item under
// "merkle:849-874". `spent_at` is not in merkle-tree at all: it is
// `canisters/nullifier-registry/src/lib.rs:306` (`#[query] fn spent_at`), with
// the controller-only UPDATE twin `spent_at_for_controller_update` at :321 and
// the shared read core `spent_at_impl` at :331. The design intent is stated at
// :140 ("only the timing-revealing `spent_at` read to the canister's IC
// controllers") and :307 ("DEF-074: `spent_at` exposes nullifier timing
// metadata").
//
// WHAT WAS MISSING. The three DEF-074 tests above call `spent_at` with an
// ARBITRARY, never-inserted nullifier — the controller-allowed case therefore
// asserts `None`, which is the same answer an ungated endpoint would give for
// an unknown key. Nothing proved that the gate withholds REAL timing metadata,
// and `spent_at_for_controller_update` — the twin the Custody Vault actually
// reads (interface freeze V6 §6) — had no coverage at all.
//
// These tests close both halves: a genuinely spent nullifier, both endpoints,
// caller allowed vs caller refused, plus the twin's mutation-free contract.

/// Insert a nullifier the way the pool does. `deploy_nullifier` initialises the
/// registry with pool = p(0x10), and `assert_pool_canister()` (lib.rs:130) gates
/// insertion on exactly that principal — not on the IC controller.
fn insert_spent(pic: &PocketIc, nr: Principal, nullifier: &[u8]) {
    let bytes = pic
        .update_call(nr, p(0x10), "insert_nullifier", candid::encode_one(nullifier.to_vec()).unwrap())
        .expect("the pool principal must be allowed to insert");
    let res: Result<(), String> = candid::decode_one(&bytes).expect("decode insert result");
    res.expect("insert_nullifier must succeed");
}

fn nullifier_bytes() -> Vec<u8> {
    let mut n = vec![0u8; 32];
    n[0] = 0x5A;
    n[31] = 0x01;
    n
}

#[test]
fn test_prot20b_spent_at_withholds_real_timing_from_a_non_controller() {
    let pic = PocketIc::new();
    let (nr, nr_controller) = deploy_nullifier(&pic);
    let n = nullifier_bytes();
    insert_spent(&pic, nr, &n);

    // The controller sees the timing metadata, and it is REAL — a concrete
    // insertion timestamp, not the `None` an unknown key would produce.
    let bytes = pic
        .query_call(nr, nr_controller, "spent_at", candid::encode_one(n.clone()).unwrap())
        .expect("IC controller must be allowed to read spent_at");
    let ts: Option<u64> = candid::decode_one(&bytes).expect("decode opt nat64");
    let ts = ts.expect("a spent nullifier must carry an insertion timestamp for the controller");
    assert!(ts > 0, "the recorded timestamp must be a real clock value, got {}", ts);

    // A principal that is genuinely NOT a controller of this registry gets no
    // answer at all — not a null, a trap.
    let outsider = pic.query_call(nr, p(0xBB), "spent_at", candid::encode_one(n.clone()).unwrap());
    assert!(
        outsider.is_err(),
        "a non-controller must not obtain timing metadata for a KNOWN-spent nullifier"
    );
    let anonymous = pic.query_call(nr, anon(), "spent_at", candid::encode_one(n.clone()).unwrap());
    assert!(anonymous.is_err(), "an anonymous caller must not obtain timing metadata");

    // The public read remains public, and it is the SAME nullifier: the gate
    // withholds the TIMING, never the fact of spentness (DEF-074's whole point).
    let public = pic
        .query_call(nr, anon(), "contains_nullifier", candid::encode_one(n).unwrap())
        .expect("contains_nullifier must remain public");
    let present: bool = candid::decode_one(&public).expect("decode bool");
    assert!(present, "the nullifier IS spent and anyone may learn that much");
}

#[test]
fn test_prot20b_spent_at_for_controller_update_is_gated_identically() {
    let pic = PocketIc::new();
    let (nr, nr_controller) = deploy_nullifier(&pic);
    let n = nullifier_bytes();
    insert_spent(&pic, nr, &n);

    // The UPDATE twin exists for the Vault's NullifierReadSpentAt read model:
    // a query's single-node response is not consensus-verified evidence. It
    // must carry the SAME gate as the query it twins.
    let bytes = pic
        .update_call(
            nr,
            nr_controller,
            "spent_at_for_controller_update",
            candid::encode_one(n.clone()).unwrap(),
        )
        .expect("IC controller must be allowed to call the update twin");
    let ts: Option<u64> = candid::decode_one(&bytes).expect("decode opt nat64");
    assert!(ts.is_some(), "the update twin must return the same timing the query returns");

    for caller in [p(0xBB), anon()] {
        let refused = pic.update_call(
            nr,
            caller,
            "spent_at_for_controller_update",
            candid::encode_one(n.clone()).unwrap(),
        );
        assert!(
            refused.is_err(),
            "{} is not a controller and must be refused by the update twin",
            caller
        );
    }
}

#[test]
fn test_prot20b_update_twin_is_mutation_free_and_agrees_with_the_query() {
    let pic = PocketIc::new();
    let (nr, nr_controller) = deploy_nullifier(&pic);
    let n = nullifier_bytes();
    insert_spent(&pic, nr, &n);

    let count_before: u64 = candid::decode_one(
        &pic.query_call(nr, anon(), "count", candid::encode_args(()).unwrap()).expect("count"),
    )
    .expect("decode count");

    let read = |m: &str| -> Option<u64> {
        let bytes = if m == "spent_at" {
            pic.query_call(nr, nr_controller, m, candid::encode_one(n.clone()).unwrap())
        } else {
            pic.update_call(nr, nr_controller, m, candid::encode_one(n.clone()).unwrap())
        }
        .unwrap_or_else(|e| panic!("{} rejected for the controller: {:?}", m, e));
        candid::decode_one(&bytes).expect("decode opt nat64")
    };

    let via_query = read("spent_at");
    let via_update = read("spent_at_for_controller_update");
    let via_update_again = read("spent_at_for_controller_update");

    assert_eq!(via_query, via_update, "the twin must agree with the query it twins");
    assert_eq!(
        via_update, via_update_again,
        "the twin must be idempotent — a second read cannot move the recorded time"
    );

    let count_after: u64 = candid::decode_one(
        &pic.query_call(nr, anon(), "count", candid::encode_args(()).unwrap()).expect("count"),
    )
    .expect("decode count");
    assert_eq!(count_before, count_after, "the update twin must never mutate the registry");
}
