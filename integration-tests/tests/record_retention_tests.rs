// =============================================================================
// STSH — Terminal-record retention / pruning tests (PocketIC)
// Phase B: DEF-072 (finalized_at_ns + terminal indexes + prune_terminal_records),
//          DEF-056 (post_upgrade nullifier rebuild skips terminal records).
// =============================================================================
//
// These prove the controller-gated `prune_terminal_records` endpoint:
//   - INDEX pruning removes terminal spends/deposits finalized strictly before
//     `older_than_ns` (and removes the matching index entry), bounded by
//     `max_records` shared across spends + deposits.
//   - LEGACY scanning finds pre-Phase-B terminal records (finalized_at_ns == None,
//     never indexed) via a resumable cursor bounded by `max_scan_records`, using
//     created_at_ns as the retention proxy. Cursor semantics: Some = paused,
//     None+complete = done, None+!complete = not reached.
//   - Hard per-call caps are enforced by trap; the endpoint is controller-only.
//
// Only the pool (testing Wasm) is deployed — inject endpoints seed PENDING_SPENDS /
// PENDING_DEPOSITS + the terminal indexes directly, so no token/merkle/nullifier
// canister is required.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release <all production canisters>
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test record_retention_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn pool_test_wasm() -> Vec<u8> {
    let path = env!("POOL_TEST_WASM");
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("Cannot read shielded_pool_test Wasm at {}: {}", path, e))
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn c(n: u8) -> [u8; 32] {
    [n; 32]
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

// ── Candid mirrors (field names / variant names must match the canister) ──────

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SpendStatus {
    Requested,
    OutputsStaged,
    Finalized,
    FailedBeforeStateChange { reason: String },
    FailedAfterOutputsStaged { reason: String },
    VerificationPending,
    NullifierReserved,
    PayoutPending { reason: String },
    PayoutSubmitting,
    PayoutUnknown { reason: String },
    NullifierInsertUnknown { reason: String },
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PruneRequest {
    older_than_ns: u64,
    max_records: u64,
    prune_spends: bool,
    prune_deposits: bool,
    scan_legacy_spends: bool,
    scan_legacy_deposits: bool,
    max_scan_records: u64,
    legacy_spend_cursor: Option<u64>,
    legacy_deposit_cursor: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PruneResult {
    spends_pruned: u64,
    deposits_pruned: u64,
    legacy_spends_pruned: u64,
    legacy_deposits_pruned: u64,
    stopped_due_to_record_limit: bool,
    next_legacy_spend_cursor: Option<u64>,
    legacy_spend_scan_complete: bool,
    next_legacy_deposit_cursor: Option<[u8; 32]>,
    legacy_deposit_scan_complete: bool,
}

/// DEF-091: mirror of the pool's 6-bucket accounting snapshot (canonical names).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

// ── Deploy + harness ──────────────────────────────────────────────────────────

fn deploy_pool(pic: &PocketIc) -> (Principal, Principal) {
    let controller = p(0xC0);
    let pool = create_canister(pic);
    install(
        pic,
        pool,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: p(0x10),
            nullifier_canister: p(0x11),
            merkle_canister: p(0x12),
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    (pool, controller)
}

fn base_req() -> PruneRequest {
    PruneRequest {
        older_than_ns: 0,
        max_records: 1000,
        prune_spends: false,
        prune_deposits: false,
        scan_legacy_spends: false,
        scan_legacy_deposits: false,
        max_scan_records: 10_000,
        legacy_spend_cursor: None,
        legacy_deposit_cursor: None,
    }
}

fn inject_terminal_spend(pic: &PocketIc, pool: Principal, ctrl: Principal, id: u64, status: SpendStatus, finalized_at_ns: u64) {
    let _: () = decode(
        "inject_terminal_spend_for_test",
        pic.update_call(pool, ctrl, "inject_terminal_spend_for_test", candid::encode_args((id, status, finalized_at_ns)).unwrap()),
    );
}

fn inject_terminal_deposit(pic: &PocketIc, pool: Principal, ctrl: Principal, commitment: [u8; 32], leaf_index: u64, finalized_at_ns: u64) {
    let _: () = decode(
        "inject_terminal_deposit_for_test",
        pic.update_call(pool, ctrl, "inject_terminal_deposit_for_test", candid::encode_args((commitment, leaf_index, finalized_at_ns)).unwrap()),
    );
}

fn inject_legacy_spend(pic: &PocketIc, pool: Principal, ctrl: Principal, id: u64, status: SpendStatus, created_at_ns: u64) {
    let _: () = decode(
        "inject_legacy_terminal_spend_for_test",
        pic.update_call(pool, ctrl, "inject_legacy_terminal_spend_for_test", candid::encode_args((id, status, created_at_ns)).unwrap()),
    );
}

fn inject_legacy_deposit(pic: &PocketIc, pool: Principal, ctrl: Principal, commitment: [u8; 32], leaf_index: u64, created_at_ns: u64) {
    let _: () = decode(
        "inject_legacy_terminal_deposit_for_test",
        pic.update_call(pool, ctrl, "inject_legacy_terminal_deposit_for_test", candid::encode_args((commitment, leaf_index, created_at_ns)).unwrap()),
    );
}

// Non-terminal in-flight spend (finalized_at_ns None, no index) for skip tests.
fn inject_nonterminal_spend(pic: &PocketIc, pool: Principal, ctrl: Principal, id: u64, status: SpendStatus) {
    let _: () = decode(
        "inject_spend_with_nullifiers_for_test",
        pic.update_call(pool, ctrl, "inject_spend_with_nullifiers_for_test", candid::encode_args((id, Vec::<[u8; 32]>::new(), status)).unwrap()),
    );
}

fn index_sizes(pic: &PocketIc, pool: Principal, ctrl: Principal) -> (u64, u64) {
    // Tuple return = candid multi-value -> decode_args (not decode_one).
    let bytes = pic
        .query_call(pool, ctrl, "terminal_index_sizes_for_test", candid::encode_args(()).unwrap())
        .expect("terminal_index_sizes_for_test rejected");
    candid::decode_args(&bytes).expect("decode terminal_index_sizes_for_test")
}

fn spend_exists(pic: &PocketIc, pool: Principal, ctrl: Principal, id: u64) -> bool {
    decode(
        "spend_record_exists_for_test",
        pic.query_call(pool, ctrl, "spend_record_exists_for_test", candid::encode_one(id).unwrap()),
    )
}

fn deposit_exists(pic: &PocketIc, pool: Principal, ctrl: Principal, commitment: [u8; 32]) -> bool {
    decode(
        "deposit_record_exists_for_test",
        pic.query_call(pool, ctrl, "deposit_record_exists_for_test", candid::encode_one(commitment).unwrap()),
    )
}

fn prune(pic: &PocketIc, pool: Principal, caller: Principal, req: &PruneRequest) -> PruneResult {
    decode(
        "prune_terminal_records",
        pic.update_call(pool, caller, "prune_terminal_records", candid::encode_one(req).unwrap()),
    )
}

// DEF-091: get_accounting_state is controller-gated (DEF-076) — query as ctrl.
fn accounting_state(pic: &PocketIc, pool: Principal, ctrl: Principal) -> AccountingState {
    decode(
        "get_accounting_state",
        pic.query_call(pool, ctrl, "get_accounting_state", candid::encode_args(()).unwrap()),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Index pruning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_index_prune_spends_respects_cutoff() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 1_000);
    inject_terminal_spend(&pic, pool, ctrl, 2, SpendStatus::FailedBeforeStateChange { reason: "x".into() }, 2_000);
    inject_terminal_spend(&pic, pool, ctrl, 3, SpendStatus::Finalized, 3_000);

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 2_500, prune_spends: true, ..base_req() });

    assert_eq!(res.spends_pruned, 2, "records finalized before 2500 pruned");
    assert!(!spend_exists(&pic, pool, ctrl, 1));
    assert!(!spend_exists(&pic, pool, ctrl, 2));
    assert!(spend_exists(&pic, pool, ctrl, 3), "record finalized at 3000 retained");
}

#[test]
fn test_index_prune_deposits_respects_cutoff() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_deposit(&pic, pool, ctrl, c(1), 0, 1_000);
    inject_terminal_deposit(&pic, pool, ctrl, c(2), 1, 2_000);
    inject_terminal_deposit(&pic, pool, ctrl, c(3), 2, 3_000);

    // F2-REDACT: the manual controller override is UNCHANGED — one call still
    // removes an eligible record. INVARIANT L binds the unattended timer path
    // only (see `PrunePath`), which is what keeps this row exactly as it was.
    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 2_500, prune_deposits: true, ..base_req() });

    assert_eq!(res.deposits_pruned, 2);
    assert!(!deposit_exists(&pic, pool, ctrl, c(1)));
    assert!(!deposit_exists(&pic, pool, ctrl, c(2)));
    assert!(deposit_exists(&pic, pool, ctrl, c(3)), "deposit finalized at 3000 retained");
}

// DEF-091: pruning terminal RECORDS must never touch live ACCOUNTING — the
// buckets track value, the records track history. Snapshot the 6-bucket state
// before a prune that removes both spend and deposit records, and assert the
// snapshot is bit-identical afterwards.
#[test]
fn test_prune_preserves_accounting_state() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 1_000);
    inject_terminal_spend(&pic, pool, ctrl, 2, SpendStatus::FailedBeforeStateChange { reason: "x".into() }, 1_500);
    inject_terminal_deposit(&pic, pool, ctrl, c(41), 0, 1_000);
    inject_terminal_deposit(&pic, pool, ctrl, c(42), 1, 1_500);

    let accounting_before = accounting_state(&pic, pool, ctrl);

    let res = prune(&pic, pool, ctrl, &PruneRequest {
        older_than_ns: 2_000,
        prune_spends: true,
        prune_deposits: true,
        ..base_req()
    });
    assert_eq!(res.spends_pruned, 2, "both terminal spends pruned");
    assert_eq!(res.deposits_pruned, 2, "both terminal deposits pruned");

    let accounting_after = accounting_state(&pic, pool, ctrl);
    assert_eq!(
        accounting_after, accounting_before,
        "DEF-091: prune_terminal_records must not change any accounting bucket"
    );
}

#[test]
fn test_index_prune_cutoff_is_strict() {
    // older_than_ns == finalized_at_ns must RETAIN (strictly-less comparison).
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 2_000);

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 2_000, prune_spends: true, ..base_req() });

    assert_eq!(res.spends_pruned, 0, "finalized exactly at the cutoff is retained");
    assert!(spend_exists(&pic, pool, ctrl, 1));
}

#[test]
fn test_index_prune_record_budget_partial_then_resume() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    for i in 1..=5u64 {
        inject_terminal_spend(&pic, pool, ctrl, i, SpendStatus::Finalized, i * 100);
    }

    let res1 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, max_records: 2, prune_spends: true, ..base_req() });
    assert_eq!(res1.spends_pruned, 2);
    assert!(res1.stopped_due_to_record_limit, "budget hit with more eligible");
    // Oldest first: ids 1 and 2 gone.
    assert!(!spend_exists(&pic, pool, ctrl, 1));
    assert!(!spend_exists(&pic, pool, ctrl, 2));
    assert!(spend_exists(&pic, pool, ctrl, 3));

    let res2 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, max_records: 1000, prune_spends: true, ..base_req() });
    assert_eq!(res2.spends_pruned, 3, "remaining drained");
    let (s, _) = index_sizes(&pic, pool, ctrl);
    assert_eq!(s, 0, "spend index fully drained");
}

#[test]
fn test_index_prune_shared_budget_across_spends_and_deposits() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    for i in 1..=3u64 {
        inject_terminal_spend(&pic, pool, ctrl, i, SpendStatus::Finalized, i * 100);
    }
    inject_terminal_deposit(&pic, pool, ctrl, c(9), 0, 100);

    // Budget of 3 consumed entirely by spends -> deposits get none, stopped=true.
    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, max_records: 3, prune_spends: true, prune_deposits: true, ..base_req() });
    assert_eq!(res.spends_pruned, 3);
    assert_eq!(res.deposits_pruned, 0, "shared budget exhausted by spends");
    assert!(deposit_exists(&pic, pool, ctrl, c(9)));
}

#[test]
fn test_index_prune_removes_index_entries() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 100);
    inject_terminal_deposit(&pic, pool, ctrl, c(1), 0, 100);
    let (s0, d0) = index_sizes(&pic, pool, ctrl);
    assert_eq!((s0, d0), (1, 1), "indexes seeded");

    prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, prune_spends: true, prune_deposits: true, ..base_req() });

    let (s1, d1) = index_sizes(&pic, pool, ctrl);
    assert_eq!((s1, d1), (0, 0), "index entries removed alongside records");
}

#[test]
fn test_index_prune_idempotent_second_call_noop() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 100);

    let r1 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, prune_spends: true, ..base_req() });
    assert_eq!(r1.spends_pruned, 1);
    let r2 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, prune_spends: true, ..base_req() });
    assert_eq!(r2.spends_pruned, 0, "nothing left to prune");
    assert!(!r2.stopped_due_to_record_limit);
}

#[test]
fn test_index_prune_empty_is_zeroed() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 10_000, prune_spends: true, prune_deposits: true, ..base_req() });
    assert_eq!(res.spends_pruned, 0);
    assert_eq!(res.deposits_pruned, 0);
    assert!(!res.stopped_due_to_record_limit);
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy (unindexed) scanning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_legacy_scan_spends_prunes_and_completes() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    for i in 1..=3u64 {
        inject_legacy_spend(&pic, pool, ctrl, i, SpendStatus::Finalized, 100);
    }

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 1_000, scan_legacy_spends: true, ..base_req() });

    assert_eq!(res.legacy_spends_pruned, 3);
    assert!(res.legacy_spend_scan_complete, "scan reached the end");
    assert_eq!(res.next_legacy_spend_cursor, None, "None + complete == done");
    for i in 1..=3u64 {
        assert!(!spend_exists(&pic, pool, ctrl, i));
    }
}

#[test]
fn test_legacy_scan_deposits_prunes_and_completes() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_legacy_deposit(&pic, pool, ctrl, c(1), 0, 100);
    inject_legacy_deposit(&pic, pool, ctrl, c(2), 1, 100);

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 1_000, scan_legacy_deposits: true, ..base_req() });

    assert_eq!(res.legacy_deposits_pruned, 2);
    assert!(res.legacy_deposit_scan_complete);
    assert_eq!(res.next_legacy_deposit_cursor, None);
}

#[test]
fn test_legacy_scan_cursor_pagination() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    for i in 1..=5u64 {
        inject_legacy_spend(&pic, pool, ctrl, i, SpendStatus::Finalized, 100);
    }

    // Budget 2 -> examine ids 1,2; pause at cursor=2.
    let r1 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 1_000, scan_legacy_spends: true, max_scan_records: 2, ..base_req() });
    assert_eq!(r1.legacy_spends_pruned, 2);
    assert!(!r1.legacy_spend_scan_complete);
    assert_eq!(r1.next_legacy_spend_cursor, Some(2), "paused after spend_id 2");

    // Resume from 2 -> examine 3,4; pause at 4.
    let r2 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 1_000, scan_legacy_spends: true, max_scan_records: 2, legacy_spend_cursor: Some(2), ..base_req() });
    assert_eq!(r2.legacy_spends_pruned, 2);
    assert_eq!(r2.next_legacy_spend_cursor, Some(4));

    // Resume from 4 -> examine 5, reach end -> complete.
    let r3 = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 1_000, scan_legacy_spends: true, max_scan_records: 2, legacy_spend_cursor: Some(4), ..base_req() });
    assert_eq!(r3.legacy_spends_pruned, 1);
    assert!(r3.legacy_spend_scan_complete);
    assert_eq!(r3.next_legacy_spend_cursor, None);
}

#[test]
fn test_legacy_scan_created_at_cutoff() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_legacy_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 1_000); // < cutoff -> pruned
    inject_legacy_spend(&pic, pool, ctrl, 2, SpendStatus::Finalized, 5_000); // >= cutoff -> retained

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 3_000, scan_legacy_spends: true, ..base_req() });

    assert_eq!(res.legacy_spends_pruned, 1, "only created_at < cutoff pruned");
    assert!(res.legacy_spend_scan_complete, "both examined, end reached");
    assert!(!spend_exists(&pic, pool, ctrl, 1));
    assert!(spend_exists(&pic, pool, ctrl, 2), "created_at 5000 retained under cutoff 3000");
}

#[test]
fn test_legacy_scan_skips_indexed_terminal() {
    // A record with finalized_at_ns = Some(..) is indexed, NOT legacy: the legacy
    // scan must never prune it.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 100); // indexed (finalized_at_ns Some)

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: u64::MAX, scan_legacy_spends: true, ..base_req() });

    assert_eq!(res.legacy_spends_pruned, 0, "indexed terminal record skipped by legacy scan");
    assert!(spend_exists(&pic, pool, ctrl, 1));
}

#[test]
fn test_legacy_scan_skips_non_terminal() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_nonterminal_spend(&pic, pool, ctrl, 1, SpendStatus::NullifierReserved); // in-flight

    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: u64::MAX, scan_legacy_spends: true, ..base_req() });

    assert_eq!(res.legacy_spends_pruned, 0, "non-terminal record never pruned");
    assert!(spend_exists(&pic, pool, ctrl, 1));
}

#[test]
fn test_legacy_scan_deposit_not_reached_when_spend_consumes_budget() {
    // Shared examined-budget: spends first. If they exhaust it, the deposit scan is
    // "not reached" -> next cursor None AND complete == false.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    for i in 1..=3u64 {
        inject_legacy_spend(&pic, pool, ctrl, i, SpendStatus::Finalized, 100);
    }
    inject_legacy_deposit(&pic, pool, ctrl, c(9), 0, 100);

    let res = prune(&pic, pool, ctrl, &PruneRequest {
        older_than_ns: 1_000,
        scan_legacy_spends: true,
        scan_legacy_deposits: true,
        max_scan_records: 2, // < 3 spends -> deposit scan never reached
        ..base_req()
    });

    assert!(!res.legacy_spend_scan_complete, "spends not finished");
    assert_eq!(res.next_legacy_spend_cursor, Some(2));
    assert_eq!(res.legacy_deposits_pruned, 0);
    assert_eq!(res.next_legacy_deposit_cursor, None);
    assert!(!res.legacy_deposit_scan_complete, "None + false == not reached");
    assert!(deposit_exists(&pic, pool, ctrl, c(9)), "deposit untouched");
}

// ─────────────────────────────────────────────────────────────────────────────
// Authorization + hard caps (trap)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_prune_is_controller_only() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 1, SpendStatus::Finalized, 100);

    let attacker = p(0xBB);
    let res = pic.update_call(pool, attacker, "prune_terminal_records",
        candid::encode_one(&PruneRequest { older_than_ns: 10_000, prune_spends: true, ..base_req() }).unwrap());
    assert!(res.is_err(), "non-controller caller must be rejected (trap)");
    assert!(spend_exists(&pic, pool, ctrl, 1), "no records pruned by rejected call");
}

#[test]
fn test_prune_max_records_over_cap_traps() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let res = pic.update_call(pool, ctrl, "prune_terminal_records",
        candid::encode_one(&PruneRequest { older_than_ns: 10_000, max_records: 1_001, prune_spends: true, ..base_req() }).unwrap());
    assert!(res.is_err(), "max_records above MAX_PRUNE_RECORDS_PER_CALL must trap");
}

#[test]
fn test_prune_max_scan_records_over_cap_traps() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let res = pic.update_call(pool, ctrl, "prune_terminal_records",
        candid::encode_one(&PruneRequest { older_than_ns: 10_000, max_scan_records: 10_001, scan_legacy_spends: true, ..base_req() }).unwrap());
    assert!(res.is_err(), "max_scan_records above MAX_LEGACY_SCAN_RECORDS_PER_CALL must trap");
}

// =============================================================================
// F2-REDACT — enforced retention + redaction (R1-F2 / R1-F3)
// =============================================================================
//
// R1-F3 found that the 30-day destruction promise B-1 makes to users was
// enforced by NOTHING: `prune_terminal_records` was controller-only with a
// caller-supplied cutoff and nothing scheduled it, so with zero controller
// action records persisted indefinitely and no test failed. R1-F2 found that a
// terminal record still named its depositor, keeping a durable
// principal→leaf→value binding.
//
// Owner ruled ENFORCE. These tests drive the SHIPPED timer with ZERO controller
// calls — calling a helper that performs redaction directly would not be
// evidence that the promise holds, which is precisely how the `post_upgrade`
// re-arm gap would have shipped green.

use std::time::Duration;

const DAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const REDACTION_AGE_NS: u64 = 7 * DAY_NS;
const RECORD_RETENTION_NS: u64 = 30 * DAY_NS;

/// The deposit-status mirror. Only the fields these tests read are declared —
/// Candid ignores the rest — but `depositor` MUST be `Option<Principal>` or the
/// decode fails, which is itself part of the evidence that the wire type moved.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
enum DepositStatusMirror {
    CommitmentPending,
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
    CommitmentReconcileInFlight,
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct RedactedDeposit {
    note_commitment: [u8; 32],
    private_balance: candid::Nat,
    ops_amount: candid::Nat,
    insurance_amount: candid::Nat,
    staking_amount: Option<candid::Nat>,
    encrypted_payload: Vec<u8>,
    depositor: Option<Principal>,
    status: DepositStatusMirror,
    created_at_ns: u64,
    expected_leaf_index: Option<u64>,
    finalized_at_ns: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct RedactedSpend {
    spend_id: u64,
    submitter: Option<Principal>,
    status: SpendStatus,
    finalized_at_ns: Option<u64>,
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

fn inject_terminal_deposit_owned(
    pic: &PocketIc,
    pool: Principal,
    ctrl: Principal,
    commitment: [u8; 32],
    finalized_at_ns: u64,
    owner: Principal,
) {
    let _: () = decode(
        "inject_terminal_deposit_with_owner_for_test",
        pic.update_call(
            pool,
            ctrl,
            "inject_terminal_deposit_with_owner_for_test",
            candid::encode_args((commitment, 0u64, finalized_at_ns, owner)).unwrap(),
        ),
    );
}

fn inject_terminal_spend_owned(
    pic: &PocketIc,
    pool: Principal,
    ctrl: Principal,
    id: u64,
    finalized_at_ns: u64,
    submitter: Principal,
) {
    let _: () = decode(
        "inject_terminal_spend_with_submitter_for_test",
        pic.update_call(
            pool,
            ctrl,
            "inject_terminal_spend_with_submitter_for_test",
            candid::encode_args((id, SpendStatus::Finalized, finalized_at_ns, submitter)).unwrap(),
        ),
    );
}

fn deposit_as(
    pic: &PocketIc,
    pool: Principal,
    caller: Principal,
    commitment: [u8; 32],
) -> Option<RedactedDeposit> {
    decode(
        "get_deposit_status",
        pic.query_call(pool, caller, "get_deposit_status", candid::encode_one(commitment).unwrap()),
    )
}

fn spend_as(pic: &PocketIc, pool: Principal, caller: Principal, id: u64) -> Option<RedactedSpend> {
    decode(
        "get_spend_status",
        pic.query_call(pool, caller, "get_spend_status", candid::encode_one(id).unwrap()),
    )
}

/// Advance time by `d` and let the interval timer fire. NOTHING here calls a
/// controller endpoint — that is the whole point of "zero operator action".
/// Advance `days` days of SIMULATED TIME, giving the timer machinery enough
/// ROUNDS to actually run what became due.
///
/// FOUR ticks per day, not one (R-2 / C-30). `ic_cdk_timers` does not run a due
/// task inline: `canister_global_timer` issues one SELF-CALL per due task and
/// awaits them (`ic-cdk-timers-0.10.1/src/lib.rs:113-123`), so every armed timer
/// costs additional rounds before its work actually happens. The pool carries
/// three timers now — the retention sweep, the 300 s attestation heartbeat, and
/// R-2's fee-flush boundary timer — and at one tick per day the sweep's
/// self-call was being crowded out, so a 25-day fixture delivered materially
/// fewer sweeps than it names.
///
/// This changes ROUNDS, never SIMULATED TIME: the day count, and therefore every
/// age/window semantic these tests assert (7-day redaction, 30-day retention), is
/// untouched. It is a harness correction, not a relaxation — the alternative,
/// advancing more time, WOULD change what the tests mean.
fn tick_days(pic: &PocketIc, days: u64) {
    for _ in 0..days {
        pic.advance_time(Duration::from_nanos(DAY_NS));
        for _ in 0..4 {
            pic.tick();
        }
    }
}

/// A real upgrade of the pool onto the SAME testing Wasm. `upgrade_canister`
/// runs the genuine `pre_upgrade`/`post_upgrade` pair — a native in-process
/// call would prove nothing (R3's cross-Wasm blind-spot rule).
fn real_upgrade(pic: &PocketIc, pool: Principal) {
    // Sender `None` = the canister's IC controller (its creator). The pool's
    // APP-level `controller` principal is a different thing and cannot call
    // `install_code`.
    //
    // The replica rate-limits `install_code` by instructions recently spent on
    // it, and installing a ~1.7 MB pool then upgrading it immediately trips
    // that. Let the limiter drain first — this is an environment property, not
    // a property of the code under test, so it is waited out rather than
    // worked around.
    for _ in 0..5 {
        pic.advance_time(Duration::from_secs(600));
        pic.tick();
    }
    pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("real upgrade must succeed");
}

// ── B9 — the ordering invariant ──────────────────────────────────────────────

#[test]
fn test_b9_redaction_age_is_strictly_less_than_retention() {
    // The load-bearing rule, not either number: if they were equal, pruning
    // would delete a record at the same moment redaction became due and every
    // redaction probe would pass VACUOUSLY against an absent record. The
    // canister asserts this at compile time; this row pins the shipped values so
    // a change to either is visible here too.
    assert!(REDACTION_AGE_NS < RECORD_RETENTION_NS);
    assert_eq!(REDACTION_AGE_NS, 7 * DAY_NS);
    assert_eq!(RECORD_RETENTION_NS, 30 * DAY_NS);
}

// ── B10 / B11 — redaction with ZERO operator action, through the shipped timer ─

#[test]
fn test_b10_b11_redaction_is_reached_through_the_shipped_timer() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(1), start, alice);
    inject_terminal_spend_owned(&pic, pool, ctrl, 1, start, alice);

    // Both principals are present to begin with — otherwise the assertion below
    // proves nothing.
    assert_eq!(deposit_as(&pic, pool, ctrl, c(1)).unwrap().depositor, Some(alice));
    assert_eq!(spend_as(&pic, pool, ctrl, 1).unwrap().submitter, Some(alice));

    // Past day 7, with NO controller call at any point.
    tick_days(&pic, 8);

    let dep = deposit_as(&pic, pool, ctrl, c(1)).expect("record still EXISTS at day 8");
    assert_eq!(dep.depositor, None, "B10: depositor stripped by the timer");
    // Redaction removes WHO, never HOW MUCH.
    assert_eq!(dep.note_commitment, c(1));
    assert_eq!(
        dep.status,
        DepositStatusMirror::CommitmentRootAccepted { leaf_index: 0, root: [0u8; 32] }
    );
}

// ── B14 — anti-vacuity: not-yet-eligible keeps its principal ─────────────────

#[test]
fn test_b14_inside_the_window_the_principal_is_untouched() {
    // Without this, a canister that redacted everything unconditionally would
    // satisfy B10 and ship.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(2), start, alice);

    tick_days(&pic, 5); // still inside the 7-day window

    assert_eq!(
        deposit_as(&pic, pool, ctrl, c(2)).unwrap().depositor,
        Some(alice),
        "B14: redaction is TIME-DRIVEN, not unconditional"
    );
}

// ── §4.4 — per-field causal probes + the access-gate consequence ─────────────

#[test]
fn test_redacted_record_becomes_controller_only() {
    // The failure mode this rules out is the one that would make the lane a
    // WORSE leak than it closes: a gate that compares against an absent
    // principal and defaults OPEN.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(3), start, alice);

    // Before: alice can read her own record.
    assert!(deposit_as(&pic, pool, alice, c(3)).is_some(), "owner reads her own record");

    tick_days(&pic, 8);

    // After: the record EXISTS (controller sees it) but alice no longer can, and
    // what the controller sees carries no principal.
    let seen_by_ctrl = deposit_as(&pic, pool, ctrl, c(3)).expect("record still exists");
    assert_eq!(seen_by_ctrl.depositor, None);
    assert!(
        deposit_as(&pic, pool, alice, c(3)).is_none(),
        "a redacted record is CONTROLLER-ONLY — never world-readable"
    );
}

// ── B4 / B13 / U4 — the timer and the redacted state survive a REAL upgrade ──

#[test]
fn test_b13_u4_redaction_fires_and_stays_after_a_real_upgrade() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(4), start, alice);

    // U2 — no premature redaction: an upgrade must not advance the clock.
    real_upgrade(&pic, pool);
    assert_eq!(
        deposit_as(&pic, pool, ctrl, c(4)).unwrap().depositor,
        Some(alice),
        "U2: upgrading must not redact a record that is not yet eligible"
    );

    // B13 — the timer was RE-ARMED in post_upgrade, so redaction still fires.
    tick_days(&pic, 8);
    assert_eq!(
        deposit_as(&pic, pool, ctrl, c(4)).unwrap().depositor,
        None,
        "B13: a timer armed only in init would have stopped at the upgrade"
    );

    // U4 — a further real upgrade: redaction is DURABLE.
    real_upgrade(&pic, pool);
    let after = deposit_as(&pic, pool, ctrl, c(4)).expect("record still exists");
    assert_eq!(after.depositor, None, "U4: redacted state survives an upgrade");
}

// ── B1 / B7 — zero-operator-action pruning, and its anti-vacuity twin ────────

#[test]
fn test_b1_b7_zero_operator_prune_of_an_already_redacted_record() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(5), start, alice);
    // B7 anti-vacuity: a much younger record that must SURVIVE the same ticks.
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(6), start + 25 * DAY_NS, alice);

    // Day 8: redacted, still present (the ORDINARY population).
    tick_days(&pic, 8);
    assert_eq!(deposit_as(&pic, pool, ctrl, c(5)).unwrap().depositor, None);

    // Advance to just BEFORE expiry, then take exactly ONE more tick. The
    // ordinary population's bound is `RECORD_RETENTION_NS + ONE cadence` — the
    // tick that notices expiry — so removal must happen on that single tick.
    // Ticking 24 days at once would also pass if removal took two, which is the
    // fail-closed population's bound and NOT this row's (M11l bites here).
    tick_days(&pic, 21); // day 29
    assert!(
        deposit_exists(&pic, pool, ctrl, c(5)),
        "B1 anti-vacuity: still inside the retention window at day 29"
    );
    tick_days(&pic, 2); // crosses day 30, then ONE tick that sees it expired

    assert!(
        !deposit_exists(&pic, pool, ctrl, c(5)),
        "B1: an ALREADY-REDACTED record is gone on the FIRST expired tick — the \
         two-cadence allowance belongs only to the redact-then-remove path"
    );
    assert!(
        deposit_exists(&pic, pool, ctrl, c(6)),
        "B7: a record inside the window is NOT pruned — B1 alone is satisfied by \
         a canister that deletes everything"
    );
}

// ── B12c / B15 — INVARIANT L: never destroy a record that still names someone ─

#[test]
fn test_b12c_b15_expired_unredacted_is_redacted_and_retained_then_removed() {
    // BRANCH 2, the fail-closed population. If the redaction backlog ever
    // exceeded scan capacity a record could reach day 30 still carrying its
    // principal; destroying it then would mean the ruled stripping never
    // happened for it, and — the record being gone — nothing could notice.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    // Finalized 31 days in the PAST: already expired, and never redacted,
    // because no tick has run since it was written.
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(7), start - 31 * DAY_NS, alice);

    // Anti-vacuity: verify it is unredacted AT the moment of expiry.
    assert_eq!(
        deposit_as(&pic, pool, ctrl, c(7)).unwrap().depositor,
        Some(alice),
        "the fixture must be expired AND unredacted, or this proves nothing"
    );

    // TICK 1 — redacted in place and RETAINED.
    tick_days(&pic, 1);
    let after_tick1 = deposit_as(&pic, pool, ctrl, c(7))
        .expect("B12c: INVARIANT L — the record is RETAINED on the tick that redacts it");
    assert_eq!(after_tick1.depositor, None, "B12c: redacted in place");

    // B15 — a real upgrade between the two ticks observes the durable redaction.
    real_upgrade(&pic, pool);
    assert_eq!(
        deposit_as(&pic, pool, ctrl, c(7)).unwrap().depositor,
        None,
        "B15: the retained-and-redacted state is durable across a real upgrade"
    );

    // TICK 2 — now it is removed. A third tick must not be needed.
    tick_days(&pic, 1);
    assert!(
        !deposit_exists(&pic, pool, ctrl, c(7)),
        "B15: removed on tick 2 — the deferral condition is false once redacted, \
         so no record can defer twice"
    );
}

// ── B12 / B12a — backlog drains, and the already-redacted prefix is not re-read ─

#[test]
fn test_b12_backlog_drains_oldest_first_without_starvation() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    // A backlog of eligible records spread across the window.
    for i in 0..25u8 {
        inject_terminal_deposit_owned(&pic, pool, ctrl, c(100 + i), start, alice);
    }
    tick_days(&pic, 8);
    for i in 0..25u8 {
        assert_eq!(
            deposit_as(&pic, pool, ctrl, c(100 + i)).unwrap().depositor,
            None,
            "B12: every record in the backlog is redacted"
        );
    }
}

fn bulk_inject(
    pic: &PocketIc,
    pool: Principal,
    ctrl: Principal,
    start_index: u32,
    count: u32,
    finalized_at_ns: u64,
    owner: Principal,
) {
    let _: () = decode(
        "inject_terminal_deposits_bulk_for_test",
        pic.update_call(
            pool,
            ctrl,
            "inject_terminal_deposits_bulk_for_test",
            candid::encode_args((start_index, count, finalized_at_ns, owner)).unwrap(),
        ),
    );
}

fn bulk_commitment(idx: u32) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0..4].copy_from_slice(&idx.to_be_bytes());
    c[4] = 0xBB;
    c
}

fn has_principal(pic: &PocketIc, pool: Principal, ctrl: Principal, commitment: [u8; 32]) -> Option<bool> {
    decode(
        "deposit_has_principal_for_test",
        pic.query_call(pool, ctrl, "deposit_has_principal_for_test", candid::encode_one(commitment).unwrap()),
    )
}

fn cursor_generation(pic: &PocketIc, pool: Principal, ctrl: Principal) -> u64 {
    decode(
        "get_redaction_cursor_generation_for_test",
        pic.query_call(pool, ctrl, "get_redaction_cursor_generation_for_test", candid::encode_args(()).unwrap()),
    )
}

/// MAX_REDACT_SCAN_PER_TICK, mirrored. The prefix MUST exceed this or the
/// starvation the test probes cannot appear — with a small fixture a
/// cursor-free sweep reaches the record anyway and the row passes vacuously.
const SCAN_CAP: u32 = 10_000;

#[test]
fn test_b12a_an_eligible_record_behind_a_redacted_prefix_is_still_reached() {
    // THE case a cursor-free design fails, and the case B12 alone cannot detect.
    //
    // The construction matters, and my first attempt at it was WRONG: I placed
    // the target record LATER IN TIME than the prefix, so as the 30-day window
    // slid forward the prefix eventually fell out of it and even a cursor-free
    // walk reached the target. The mutation survived. The fixture has to keep
    // the prefix INSIDE the window for the whole test.
    //
    // So: prefix and target share the same `finalized_at_ns`, and the target's
    // commitment sorts AFTER every prefix key. The index is ordered by
    // `(finalized_at_ns, commitment)`, so the target sits genuinely behind the
    // prefix in walk order, and the only way to reach it is to walk past the
    // prefix — which is what the cursor does once per sweep and a cursor-free
    // walk never does, because it re-examines the same first
    // `MAX_REDACT_RECORDS_PER_TICK` keys every tick forever.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);

    let prefix = SCAN_CAP + 50;
    let batch = 2_000u32;
    let mut done = 0u32;
    while done < prefix {
        let n = batch.min(prefix - done);
        bulk_inject(&pic, pool, ctrl, done, n, start, alice);
        done += n;
    }
    // The target: same timestamp, a commitment that sorts after all of them.
    let target = [0xFFu8; 32];
    inject_terminal_deposit_owned(&pic, pool, ctrl, target, start, alice);
    assert_eq!(has_principal(&pic, pool, ctrl, target), Some(true));

    // Enough ticks to walk the whole prefix at MAX_REDACT_RECORDS_PER_TICK, and
    // few enough that the prefix is still inside the 30-day window throughout.
    tick_days(&pic, 25);

    assert_eq!(
        has_principal(&pic, pool, ctrl, bulk_commitment(0)),
        Some(false),
        "the prefix itself is redacted"
    );
    assert_eq!(
        has_principal(&pic, pool, ctrl, target),
        Some(false),
        "B12a: the sweep walked PAST an already-redacted prefix larger than one \
         tick's budget and reached the record behind it"
    );
}

#[test]
fn test_b12a_sweep_restarts_so_later_arrivals_are_caught() {
    // The sweep-restart half, observed directly on the cursor rather than
    // inferred: when the walk passes the eligible edge the generation advances
    // and the next sweep begins at the window's oldest edge. A sweep that never
    // restarts would strand every record that became eligible after it ran.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(80), start, alice);

    tick_days(&pic, 8);
    let gen_after_first = cursor_generation(&pic, pool, ctrl);
    assert!(gen_after_first >= 1, "a completed sweep advances the generation");
    assert_eq!(has_principal(&pic, pool, ctrl, c(80)), Some(false));

    // A LATER arrival, after the first sweep completed.
    let later = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(81), later, alice);
    tick_days(&pic, 8);

    assert_eq!(
        has_principal(&pic, pool, ctrl, c(81)),
        Some(false),
        "a record that became eligible AFTER the first sweep is caught by the next"
    );
    assert!(
        cursor_generation(&pic, pool, ctrl) > gen_after_first,
        "the sweep restarted rather than sitting at the end of the window"
    );
}

// ── B6 — the FU1-1 recovery gate holds on the TIMER path ────────────────────

#[test]
fn test_b6_timer_does_not_run_while_recovery_is_pending() {
    // Redacting or pruning during post-upgrade recovery is as operationally
    // wrong as pruning during it, and the gate is the same one. Without this
    // row, dropping `recovery_pending()` from the timer changes nothing
    // observable.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(70), start, alice);

    // Force the recovery cursor back to a PENDING phase.
    let _: () = decode(
        "set_recovery_cursor_phase_for_test",
        pic.update_call(pool, ctrl, "set_recovery_cursor_phase_for_test", candid::encode_one(0u8).unwrap()),
    );

    tick_days(&pic, 10); // well past day 7

    assert_eq!(
        has_principal(&pic, pool, ctrl, c(70)),
        Some(true),
        "B6: the timer must not redact while post-upgrade recovery is pending"
    );

    // …and once recovery completes, the same record redacts — so the row above
    // is a GATE, not a broken timer.
    //
    // NOTE: the COMPLETE phase is 6 (`CURSOR_PHASE_COMPLETE`), not 2. The
    // `RecoveryCursor` doc comment still says "2 = COMPLETE", which is stale —
    // reported as an observation, not fixed here (out of this lane's fence).
    let _: () = decode(
        "set_recovery_cursor_phase_for_test",
        pic.update_call(pool, ctrl, "set_recovery_cursor_phase_for_test", candid::encode_one(6u8).unwrap()),
    );
    tick_days(&pic, 4);
    assert_eq!(
        has_principal(&pic, pool, ctrl, c(70)),
        Some(false),
        "B6 anti-vacuity: with recovery complete the same record IS redacted"
    );
}

// ── B8 — the manual override is unchanged ────────────────────────────────────

#[test]
fn test_b8_manual_prune_override_still_controller_only_and_caller_cutoff() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    inject_terminal_spend(&pic, pool, ctrl, 77, SpendStatus::Finalized, 1_000);

    // A non-controller is still refused.
    let refused = pic.update_call(
        pool,
        p(0xEE),
        "prune_terminal_records",
        candid::encode_one(base_req()).unwrap(),
    );
    assert!(refused.is_err(), "B8: prune_terminal_records stays controller-only");

    // The controller's caller-supplied cutoff still works exactly as before.
    let res = prune(&pic, pool, ctrl, &PruneRequest { older_than_ns: 2_000, prune_spends: true, ..base_req() });
    assert_eq!(res.spends_pruned, 1);
}

// ── U1 / U3 — the real cross-Wasm decode-compatibility legs ─────────────────
//
// These are the legs a same-Wasm upgrade CANNOT prove. The pre-F2-REDACT pool
// wrote `depositor : principal` — PRESENT, not absent — and the new Wasm reads
// it as `opt principal`. A1's V1 had this backwards; the risk is not "an absent
// field decodes as None", it is "a present principal must widen to Some".

fn pool_pre_f2redact_wasm() -> Vec<u8> {
    let path = env!("POOL_PRE_F2REDACT_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read pre-F2-REDACT Wasm at {}: {}", path, e))
}

#[test]
fn test_u1_u3_old_record_widens_to_some_then_redacts_on_schedule() {
    let pic = PocketIc::new();
    let controller = p(0xC0);
    let pool = create_canister(&pic);
    // Install the OLD Wasm and write a record with it.
    install(
        &pic,
        pool,
        pool_pre_f2redact_wasm(),
        &PoolInitArgs {
            token_canister: p(0x10),
            nullifier_canister: p(0x11),
            merkle_canister: p(0x12),
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    let start = now_ns(&pic);
    // The OLD Wasm has no owner-bearing injector; its plain one sets
    // depositor = the controller caller, which is exactly what U1 needs — a
    // record written as a BARE principal by the old code.
    inject_terminal_deposit(&pic, pool, controller, c(50), 0, start);

    // ── the real upgrade, old Wasm → new Wasm ────────────────────────────────
    for _ in 0..5 {
        pic.advance_time(Duration::from_secs(600));
        pic.tick();
    }
    pic.upgrade_canister(pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("U1: upgrading the OLD Wasm to the NEW one must not trap");

    // U1 — the old bare `principal` decodes as `Some(old_principal)`.
    let after = deposit_as(&pic, pool, controller, c(50))
        .expect("U1: the record must still decode after the upgrade");
    assert_eq!(
        after.depositor,
        Some(controller),
        "U1: a PRESENT principal written by the old Wasm must widen to Some — \
         not decode as None, and not trap"
    );

    // U2 — and the upgrade alone did not redact it.
    assert!(after.depositor.is_some(), "U2: no premature redaction on upgrade");

    // U3 — eligibility reached AFTER the upgrade yields None.
    tick_days(&pic, 8);
    assert_eq!(
        deposit_as(&pic, pool, controller, c(50)).unwrap().depositor,
        None,
        "U3: a record carried across the upgrade redacts on schedule"
    );
}

// ── M11b — the SUBMITTER probe, independent of the depositor probe ───────────

#[test]
fn test_b10_submitter_is_stripped_by_the_shipped_timer() {
    // A SEPARATE test, not a second assertion inside the depositor one. Two
    // fields are redacted and each needs its own causal probe: if both lived in
    // one test, M11a and M11b would RED the same row and neither would prove
    // the other field is independently covered.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);
    inject_terminal_spend_owned(&pic, pool, ctrl, 5, start, alice);
    assert_eq!(spend_as(&pic, pool, ctrl, 5).unwrap().submitter, Some(alice));

    tick_days(&pic, 8);

    let sp = spend_as(&pic, pool, ctrl, 5).expect("the record still EXISTS at day 8");
    assert_eq!(sp.submitter, None, "the submitter is stripped by the shipped timer");
    assert_eq!(sp.spend_id, 5, "redaction removes WHO, never the record");
}

// ── B12b — BRANCH 1: capacity / normal load (M11i) ──────────────────────────

#[test]
fn test_b12b_branch1_last_record_is_redacted_before_it_becomes_prune_eligible() {
    // The ORDINARY population, and its own fixture. A backlog sized at the
    // shipped scan cap must be fully redacted BEFORE its oldest members reach
    // prune eligibility, so they take the ordinary path — removed on the first
    // expired tick, `retention + 1` cadence, with NO deferral occurring and
    // none asserted. That is what distinguishes branch 1 from branch 2.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);

    let backlog = SCAN_CAP;
    let batch = 2_000u32;
    let mut done = 0u32;
    while done < backlog {
        let n = batch.min(backlog - done);
        bulk_inject(&pic, pool, ctrl, done, n, start, alice);
        done += n;
    }

    // Day 25: past redaction (7) and BEFORE retention (30).
    tick_days(&pic, 25);
    let last = bulk_commitment(backlog - 1);
    assert_eq!(
        has_principal(&pic, pool, ctrl, last),
        Some(false),
        "B12b: the LAST record of a shipped-cap backlog is redacted before it \
         becomes prune-eligible — this is what the capacity target buys"
    );
    assert!(
        deposit_exists(&pic, pool, ctrl, last),
        "B12b: and it still EXISTS — redaction precedes removal"
    );

    // Now past retention: removed on the ordinary path. A backlog of SCAN_CAP
    // records drains at MAX_PRUNE_RECORDS_PER_CALL per tick, so this needs
    // enough ticks to reach the last one — the bound is the PRUNE cap here, not
    // the scan cap.
    tick_days(&pic, 20);
    assert!(
        !deposit_exists(&pic, pool, ctrl, last),
        "B12b: removed normally once expired — no deferral was needed"
    );
}

// ── M11j — the sweep-duration / overshoot formula uses the SCAN cap ─────────

#[test]
fn test_sweep_duration_and_overshoot_are_derived_from_the_scan_cap() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);

    // A Candid query returning `(u64, u64)` encodes TWO arguments, not a
    // record, so it needs `decode_args` rather than `decode_one`.
    let bounds = |w: u64| -> (u64, u64) {
        let bytes = pic
            .query_call(pool, ctrl, "redaction_bounds_for_test", candid::encode_one(w).unwrap())
            .expect("redaction_bounds_for_test");
        candid::decode_args(&bytes).expect("decode (u64, u64)")
    };

    // A window of exactly one scan budget is one tick; one more entry is two.
    let cap = SCAN_CAP as u64;
    assert_eq!(bounds(cap).0, 1, "a full scan budget sweeps in one tick");
    assert_eq!(bounds(cap + 1).0, 2, "one entry more needs a second tick");
    assert_eq!(bounds(0).0, 0);

    // The MUTATION cap is 1_000 and the SCAN cap is 10_000, so a window of
    // 10_000 distinguishes them: derived from the scan cap it is 1 tick, from
    // the mutation cap it would be 10. This is the row M11j bites.
    assert_ne!(
        bounds(cap).0,
        cap / 1_000,
        "the duration must NOT be derived from MAX_REDACT_RECORDS_PER_TICK"
    );

    // The stripping bound: REDACTION_AGE + one cadence + the sweep.
    let (ticks, worst) = bounds(cap + 1);
    assert_eq!(worst, REDACTION_AGE_NS + DAY_NS + ticks * DAY_NS);
}

// ── M11g — the cursor is KEY-based, so a prune mid-sweep cannot skip a record ─

#[test]
fn test_cursor_is_key_based_so_a_prune_mid_sweep_skips_nothing() {
    // `CTO_RULING_A-5_cursor_keyed`: pruning REMOVES index entries, so an OFFSET
    // cursor would shift later records back past it and they would never be
    // examined — a silent skip. A key cursor is unaffected, and
    // `range((Excluded(k), Unbounded))` stays well-defined even when `k` has
    // itself been pruned.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool(&pic);
    let alice = p(0xA1);
    let start = now_ns(&pic);

    // Old records that pruning will remove mid-sweep, and a younger one that
    // must still be redacted afterwards.
    for i in 0..8u8 {
        inject_terminal_deposit_owned(&pic, pool, ctrl, c(120 + i), start - 31 * DAY_NS, alice);
    }
    inject_terminal_deposit_owned(&pic, pool, ctrl, c(140), start, alice);

    // Ticks here BOTH redact and prune: the expired eight are redacted and
    // retained (INVARIANT L), then removed, while the walk continues.
    tick_days(&pic, 12);

    for i in 0..8u8 {
        assert!(
            !deposit_exists(&pic, pool, ctrl, c(120 + i)),
            "the expired records are gone"
        );
    }
    assert_eq!(
        has_principal(&pic, pool, ctrl, c(140)),
        Some(false),
        "the younger record was still reached after removals shifted the index"
    );
}
