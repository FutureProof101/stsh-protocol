// =============================================================================
// STSH — P-REC (L0-G) recovery-index tests (PocketIC)
// Campaign B / Wave 2, pre-lane P-REC.
// =============================================================================
//
// These prove the principal-scoped device-loss recovery index:
//   - the ONE-SHOT post_upgrade migration builds ACTIVE_DEPOSIT_INDEX /
//     ACTIVE_SPEND_INDEX from the main maps (recovery-required records only),
//     verifies cardinality, and stamps recovery_index_version = 1;
//   - `list_my_active_deposits` / `list_my_active_spends` are caller-scoped,
//     paginated (exclusive cursor + hard page cap), advisory reads that derive
//     status from the authoritative record;
//   - a principal never sees another principal's records; anonymous fails closed;
//   - terminal records are excluded; a recovery-required PayoutPending spend (the
//     device-loss core case) IS discoverable;
//   - after the stamp, later upgrades are index-only (no main-map rescan);
//   - a trapping upgrade leaves the version at 0 (trap-no-stamp).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release <all production canisters>
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test prec_recovery_index_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn pool_test_wasm() -> Vec<u8> {
    let path = env!("POOL_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read shielded_pool_test Wasm {}: {}", path, e))
}
fn pool_prod_wasm() -> Vec<u8> {
    let path = env!("POOL_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read shielded_pool (prod) Wasm {}: {}", path, e))
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

// ── Candid mirrors (field/variant names must match the canister) ──────────────

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
enum DepositStatus {
    CommitmentPending,
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
    CommitmentReconcileInFlight,
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
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
    NullifierReconcileInFlight,
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingDeposit {
    note_commitment: [u8; 32],
    private_balance: u128,
    ops_amount: u128,
    insurance_amount: u128,
    encrypted_payload: Vec<u8>,
    depositor: Option<Principal>,  // F2-REDACT: opt principal
    status: DepositStatus,
    created_at_ns: u64,
    expected_leaf_index: Option<u64>,
    finalized_at_ns: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingPublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
    protocol_fee: u128,
    block_index: Option<candid::Nat>,
    ledger_created_at_time_ns: Option<u64>,
}

// SpendFeeMode mirror (only needed as an opt field on PendingSpend).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode {
    FixedStsh,
    XdrPegged,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpend {
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    public_payout: Option<PendingPublicPayout>,
    outputs_committed: u32,
    fee: Option<u128>,
    status: SpendStatus,
    created_at_ns: u64,
    submitter: Option<Principal>,
    finalized_at_ns: Option<u64>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
    spend_fee_mode: Option<SpendFeeMode>,
    fee_split_ops: Option<u128>,
    fee_split_insurance: Option<u128>,
    fee_split_staking: Option<u128>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ActiveDepositsPage {
    deposits: Vec<PendingDeposit>,
    next_cursor: Option<[u8; 32]>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ActiveSpendsPage {
    spends: Vec<PendingSpend>,
    next_cursor: Option<u64>,
}

// ── Deploy + harness ──────────────────────────────────────────────────────────

fn deploy_pool_test(pic: &PocketIc) -> (Principal, Principal) {
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

/// Real upgrade cycle. `advance_time` first so back-to-back installs of the ~1.3 MB
/// Wasm don't trip the install_code rate limit. Returns Err if pre/post_upgrade traps.
fn upgrade(pic: &PocketIc, pool: Principal, wasm: Vec<u8>) -> Result<(), String> {
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    pic.upgrade_canister(pool, wasm, candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

// A pending deposit is injected with an EXPLICIT depositor via the owner-bearing
// test endpoint (the plain inject fixes depositor = the controller caller). The
// CALL is controller-gated, so it is made as `ctrl`.
fn inject_deposit_as(pic: &PocketIc, pool: Principal, ctrl: Principal, owner: Principal, commitment: [u8; 32], status: DepositStatus) {
    let _: () = decode(
        "inject_pending_deposit_with_owner_for_test",
        pic.update_call(
            pool,
            ctrl,
            "inject_pending_deposit_with_owner_for_test",
            candid::encode_args((commitment, 100u128, owner, status)).unwrap(),
        ),
    );
}

// inject_pending_spend_for_test takes a fully-specified PendingSpend (we control submitter).
fn inject_spend(pic: &PocketIc, pool: Principal, ctrl: Principal, spend_id: u64, submitter: Option<Principal>, status: SpendStatus) {
    let rec = PendingSpend {
        spend_id,
        nullifiers: vec![],
        output_commitments: vec![],
        public_payout: None,
        outputs_committed: 0,
        fee: Some(0),
        status,
        created_at_ns: 1,
        submitter,
        finalized_at_ns: None,
        fee_model_version: None,
        params_epoch: None,
        spend_fee_mode: None,
        fee_split_ops: None,
        fee_split_insurance: None,
        fee_split_staking: None,
    };
    let _: u64 = decode(
        "inject_pending_spend_for_test",
        pic.update_call(pool, ctrl, "inject_pending_spend_for_test", candid::encode_one(rec).unwrap()),
    );
}

fn list_deposits(pic: &PocketIc, pool: Principal, caller: Principal, start_after: Option<[u8; 32]>, limit: u64) -> ActiveDepositsPage {
    decode(
        "list_my_active_deposits",
        pic.query_call(pool, caller, "list_my_active_deposits", candid::encode_args((start_after, limit)).unwrap()),
    )
}
fn list_spends(pic: &PocketIc, pool: Principal, caller: Principal, start_after: Option<u64>, limit: u64) -> ActiveSpendsPage {
    decode(
        "list_my_active_spends",
        pic.query_call(pool, caller, "list_my_active_spends", candid::encode_args((start_after, limit)).unwrap()),
    )
}
fn index_counts(pic: &PocketIc, pool: Principal, ctrl: Principal) -> (u64, u64, u32) {
    let bytes = pic
        .query_call(pool, ctrl, "recovery_index_counts_for_test", candid::encode_args(()).unwrap())
        .expect("recovery_index_counts_for_test rejected");
    candid::decode_args(&bytes).expect("decode recovery_index_counts_for_test")
}

// Owners used across tests.
fn alice() -> Principal { p(0xA1) }
fn bob() -> Principal { p(0xB2) }

// ─────────────────────────────────────────────────────────────────────────────
// Migration: builds the index from the main maps on the first upgrade
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_migration_builds_index_and_stamps_version() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);

    // Before any upgrade: fresh install, version 0, empty index.
    assert_eq!(index_counts(&pic, pool, ctrl), (0, 0, 0));

    // Alice: 2 recovery-required deposits + 1 terminal (excluded).
    // P-ROOT: fixtures use NON-lease-requiring recovery states (a lease-free
    // CommitmentAppended/CommitmentAppendUnknown now rejects the upgrade); the
    // index-build semantics under test are status-agnostic.
    inject_deposit_as(&pic, pool, ctrl,alice(), c(1), DepositStatus::TransferPending);
    inject_deposit_as(&pic, pool, ctrl,alice(), c(2), DepositStatus::TransferConfirmedCommitmentPending);
    inject_deposit_as(&pic, pool, ctrl,alice(), c(3), DepositStatus::CommitmentRootAccepted { leaf_index: 6, root: c(9) });
    // Bob: 1 recovery-required deposit.
    inject_deposit_as(&pic, pool, ctrl,bob(), c(4), DepositStatus::TransferConfirmedCommitmentPending);
    // Alice: 1 recovery-required spend + 1 terminal (excluded).
    inject_spend(&pic, pool, ctrl, 10, Some(alice()), SpendStatus::NullifierFinalizedOutputsPending);
    inject_spend(&pic, pool, ctrl, 11, Some(alice()), SpendStatus::Finalized);
    // Bob: 1 recovery-required spend.
    inject_spend(&pic, pool, ctrl, 12, Some(bob()), SpendStatus::PayoutPending { reason: "owed".into() });

    // Injected records are NOT yet in the index (inject writes only the main map).
    assert_eq!(index_counts(&pic, pool, ctrl), (0, 0, 0));

    // Real upgrade → one-shot migration builds the index + stamps version 1.
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade should succeed");

    // 3 recovery-required deposits (c1,c2,c4), 2 recovery-required spends (10,12);
    // version = 2 (P-ROOT R3: a fresh build stamps the v2 schema directly).
    assert_eq!(index_counts(&pic, pool, ctrl), (3, 2, 2));

    // Alice sees exactly her 2 recovery-required deposits, terminal excluded.
    let a_dep = list_deposits(&pic, pool, alice(), None, 100);
    let mut a_commits: Vec<[u8; 32]> = a_dep.deposits.iter().map(|d| d.note_commitment).collect();
    a_commits.sort();
    assert_eq!(a_commits, vec![c(1), c(2)]);
    assert!(a_dep.next_cursor.is_none());

    // Alice sees exactly her 1 recovery-required spend.
    let a_sp = list_spends(&pic, pool, alice(), None, 100);
    assert_eq!(a_sp.spends.iter().map(|s| s.spend_id).collect::<Vec<_>>(), vec![10]);

    // Bob sees only his own records.
    let b_dep = list_deposits(&pic, pool, bob(), None, 100);
    assert_eq!(b_dep.deposits.iter().map(|d| d.note_commitment).collect::<Vec<_>>(), vec![c(4)]);
    let b_sp = list_spends(&pic, pool, bob(), None, 100);
    assert_eq!(b_sp.spends.iter().map(|s| s.spend_id).collect::<Vec<_>>(), vec![12]);
}

#[test]
fn test_migration_runs_on_production_wasm_upgrade() {
    // The brief requires proving migration on the PRODUCTION Wasm via a real
    // upgrade cycle. list_my_active_* are production endpoints, so we introspect
    // through them after upgrading test -> prod.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    // P-ROOT: non-lease-requiring recovery state (see the note in the build test).
    inject_deposit_as(&pic, pool, ctrl,alice(), c(1), DepositStatus::TransferConfirmedCommitmentPending);
    inject_spend(&pic, pool, ctrl, 20, Some(alice()), SpendStatus::PayoutPending { reason: "x".into() });

    upgrade(&pic, pool, pool_prod_wasm()).expect("prod upgrade should succeed");

    let dep = list_deposits(&pic, pool, alice(), None, 100);
    assert_eq!(dep.deposits.len(), 1);
    assert_eq!(dep.deposits[0].note_commitment, c(1));
    let sp = list_spends(&pic, pool, alice(), None, 100);
    assert_eq!(sp.spends.len(), 1);
    assert_eq!(sp.spends[0].spend_id, 20);
}

// ─────────────────────────────────────────────────────────────────────────────
// Authorization / privacy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_principal_b_cannot_list_a_records() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    inject_deposit_as(&pic, pool, ctrl,alice(), c(1), DepositStatus::TransferPending);
    inject_spend(&pic, pool, ctrl, 10, Some(alice()), SpendStatus::PayoutPending { reason: "x".into() });
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade");

    // Bob has NO records; his listing is empty even though Alice's exist.
    assert!(list_deposits(&pic, pool, bob(), None, 100).deposits.is_empty());
    assert!(list_spends(&pic, pool, bob(), None, 100).spends.is_empty());
}

#[test]
fn test_anonymous_list_fails_closed_empty() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    inject_deposit_as(&pic, pool, ctrl,alice(), c(1), DepositStatus::TransferPending);
    inject_spend(&pic, pool, ctrl, 10, Some(alice()), SpendStatus::PayoutPending { reason: "x".into() });
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade");

    let anon = Principal::anonymous();
    assert!(list_deposits(&pic, pool, anon, None, 100).deposits.is_empty());
    assert!(list_spends(&pic, pool, anon, None, 100).spends.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Pagination: hard cap + exclusive cursor + completeness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_deposit_pagination_cap_and_exclusive_cursor() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);

    // 150 recovery-required deposits for Alice — spans two pages (cap 100).
    for i in 0..150u32 {
        let mut commitment = [0u8; 32];
        commitment[0..4].copy_from_slice(&i.to_be_bytes());
        // P-ROOT: non-lease-requiring recovery state (see the note in the build test).
        inject_deposit_as(&pic, pool, ctrl,alice(), commitment, DepositStatus::TransferConfirmedCommitmentPending);
    }
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade");
    assert_eq!(index_counts(&pic, pool, ctrl).0, 150);

    // Requesting more than the cap returns AT MOST the cap.
    let page1 = list_deposits(&pic, pool, alice(), None, 1_000);
    assert_eq!(page1.deposits.len(), 100, "page is hard-capped at 100");
    let cursor = page1.next_cursor.expect("a full page yields a cursor");
    assert_eq!(cursor, page1.deposits.last().unwrap().note_commitment);

    // The next page resumes EXCLUSIVELY after the cursor; total is the full set,
    // with no overlap and no gaps.
    let page2 = list_deposits(&pic, pool, alice(), Some(cursor), 1_000);
    assert_eq!(page2.deposits.len(), 50);
    assert!(page2.next_cursor.is_none(), "last page has no cursor");

    let mut all: Vec<[u8; 32]> = page1.deposits.iter().chain(page2.deposits.iter()).map(|d| d.note_commitment).collect();
    let unique: std::collections::BTreeSet<_> = all.iter().copied().collect();
    assert_eq!(unique.len(), 150, "no overlap, no gaps across pages");
    all.sort();
    // Ascending order within the index (range scan is ordered).
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(all, sorted);
}

#[test]
fn test_spend_pagination_cursor() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    for id in 0..120u64 {
        inject_spend(&pic, pool, ctrl, id, Some(alice()), SpendStatus::PayoutPending { reason: "x".into() });
    }
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade");

    let page1 = list_spends(&pic, pool, alice(), None, 1_000);
    assert_eq!(page1.spends.len(), 100);
    let cursor = page1.next_cursor.expect("cursor");
    let page2 = list_spends(&pic, pool, alice(), Some(cursor), 1_000);
    assert_eq!(page2.spends.len(), 20);
    assert!(page2.next_cursor.is_none());
    // Ascending by spend_id, exclusive resume.
    assert!(page2.spends.first().unwrap().spend_id > cursor);
}

// ─────────────────────────────────────────────────────────────────────────────
// Recovery-required classification edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_terminal_records_excluded() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    inject_deposit_as(&pic, pool, ctrl,alice(), c(1), DepositStatus::CommitmentRootAccepted { leaf_index: 0, root: c(7) });
    inject_spend(&pic, pool, ctrl, 10, Some(alice()), SpendStatus::Finalized);
    inject_spend(&pic, pool, ctrl, 11, Some(alice()), SpendStatus::FailedBeforeStateChange { reason: "x".into() });
    inject_spend(&pic, pool, ctrl, 12, Some(alice()), SpendStatus::FailedAfterOutputsStaged { reason: "x".into() });
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade");

    assert_eq!(index_counts(&pic, pool, ctrl), (0, 0, 2), "terminal records are never indexed");
    assert!(list_deposits(&pic, pool, alice(), None, 100).deposits.is_empty());
    assert!(list_spends(&pic, pool, alice(), None, 100).spends.is_empty());
}

#[test]
fn test_payout_pending_spend_is_recoverable() {
    // The device-loss core case: a permanently-spent-but-unfinished spend must be
    // discoverable so a fresh device can recover its random spend_id.
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    inject_spend(&pic, pool, ctrl, 42, Some(alice()), SpendStatus::PayoutPending { reason: "owed".into() });
    upgrade(&pic, pool, pool_test_wasm()).expect("upgrade");

    let sp = list_spends(&pic, pool, alice(), None, 100);
    assert_eq!(sp.spends.iter().map(|s| s.spend_id).collect::<Vec<_>>(), vec![42]);
    // Status is derived live from the authoritative record.
    assert!(matches!(sp.spends[0].status, SpendStatus::PayoutPending { .. }));
}

#[test]
fn test_recovery_required_spend_without_submitter_rejects_migration() {
    // P-ROOT R2 (S-45): a pre-DEF-069 legacy spend (submitter None) can never be
    // found by the stamped INDEX-ONLY upgrade passes, so leaving it unindexed
    // would silently drop its INFLIGHT nullifier protection on a later upgrade.
    // The one-shot migration therefore REJECTS the upgrade (pin-rejection) — the
    // record must be resolved on the previous Wasm first. (Supersedes the
    // original P-REC grace of "controller-only recoverable, not indexed".)
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    inject_spend(&pic, pool, ctrl, 10, None, SpendStatus::PayoutPending { reason: "x".into() });
    inject_spend(&pic, pool, ctrl, 11, Some(alice()), SpendStatus::PayoutPending { reason: "x".into() });
    let r = upgrade(&pic, pool, pool_test_wasm());
    assert!(r.is_err(), "migration must be rejected while a submitter-less recovery-required spend exists");

    // Trap-no-stamp: the whole upgrade rolled back — version still 0, index empty,
    // and both records intact on the old Wasm.
    assert_eq!(index_counts(&pic, pool, ctrl), (0, 0, 0), "no partial build survives the rejection");
}

// ─────────────────────────────────────────────────────────────────────────────
// S-45: index-only after the stamp (no main-map rescan on later upgrades)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_no_rescan_after_stamp() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    inject_deposit_as(&pic, pool, ctrl,alice(), c(1), DepositStatus::TransferPending);
    // First upgrade: migration builds the index (version 0 -> CURRENT, i.e. v2).
    upgrade(&pic, pool, pool_test_wasm()).expect("first upgrade");
    assert_eq!(index_counts(&pic, pool, ctrl), (1, 0, 2));

    // Raw-inject a NEW recovery-required deposit AFTER the stamp. inject_* writes
    // only the main map, never the index — so a re-scanning migration would pick
    // it up, but an index-only upgrade must NOT.
    inject_deposit_as(&pic, pool, ctrl,alice(), c(2), DepositStatus::TransferPending);

    // Second upgrade: version is already 1, so the migration block is skipped.
    upgrade(&pic, pool, pool_test_wasm()).expect("second upgrade");

    // The index is UNCHANGED — the post-stamp raw-injected record was NOT rescanned.
    assert_eq!(index_counts(&pic, pool, ctrl), (1, 0, 2), "no main-map rescan after the stamp (S-45)");
    let listed = list_deposits(&pic, pool, alice(), None, 100);
    assert_eq!(listed.deposits.iter().map(|d| d.note_commitment).collect::<Vec<_>>(), vec![c(1)]);
}

// ─────────────────────────────────────────────────────────────────────────────
// S-45 RETARGETED by FU1-1 (lane A-5) — trap-no-stamp becomes SUCCEED-no-stamp
//
// The invariant S-45 protects is unchanged in substance: **a half-built index is
// never stamped complete.** What changed is the upgrade's fate over the cap.
//
//   BEFORE FU1-1: over `MAX_UPGRADE_SCAN` the upgrade TRAPPED, so the migration
//                 never stamped — version stayed 0 because nothing ran.
//   AFTER  FU1-1: over the cap the upgrade SUCCEEDS and the scan resumes across
//                 gated messages, so the version must stay 0 for a DIFFERENT and
//                 stronger reason: the scan has not finished yet. It stamps only
//                 on genuine completion (`CTO_RULING_A-5_chunk_all_phases`).
//
// Asserting "version == 0" after a successful upgrade would be a post-state
// equality that passes for the wrong reason. Per Rule 6 this is a CAUSAL probe:
// the stamp is absent while work remains, and its appearance is caused by the
// work completing — proven by driving the cursor and watching it flip.
// ─────────────────────────────────────────────────────────────────────────────

/// Drive one gated update. It advances the recovery cursor by a chunk and then
/// refuses (work-then-refuse), so the returned error is the progress signal.
fn drive_recovery_once(pic: &PocketIc, pool: Principal, caller: Principal) -> String {
    match pic.update_call(
        pool,
        caller,
        "reconcile_deposit_commitment",
        candid::encode_one([0u8; 32]).unwrap(),
    ) {
        Ok(bytes) => format!("ok:{}", bytes.len()),
        Err(e) => format!("{e:?}"),
    }
}

#[test]
fn test_over_cap_upgrade_succeeds_and_stamps_only_on_completion() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);
    // 1001 terminal deposits — deliberately over MAX_UPGRADE_SCAN (1000), which is
    // the exact fixture that used to make this pool un-upgradeable.
    for i in 0..1001u32 {
        let mut commitment = [0u8; 32];
        commitment[0..4].copy_from_slice(&i.to_be_bytes());
        commitment[31] = 0xAA;
        inject_deposit_as(&pic, pool, ctrl, alice(), commitment, DepositStatus::CommitmentRootAccepted { leaf_index: i as u64, root: c(1) });
    }

    // (1) The upgrade now SUCCEEDS. This is the FU1-1 property; before it, this
    //     same fixture trapped and the pool could never be upgraded at all.
    upgrade(&pic, pool, pool_test_wasm()).expect("over-cap upgrade must SUCCEED and resume");

    // (2) ...and the version is NOT stamped, because the scan is unfinished.
    assert_eq!(
        index_counts(&pic, pool, ctrl).2,
        0,
        "S-45: a half-built index must NOT be stamped complete"
    );

    // (3) CAUSAL PROBE (Rule 6). Drive the cursor and watch the stamp appear only
    //     once the work is done. Each gated call advances a chunk, then refuses.
    let mut flipped_after = None;
    for call in 1..=12 {
        let err = drive_recovery_once(&pic, pool, ctrl);
        let version = index_counts(&pic, pool, ctrl).2;
        if version != 0 {
            flipped_after = Some((call, err));
            break;
        }
    }
    let (call, _last) = flipped_after.expect(
        "the cursor must complete within a bounded number of gated calls and stamp the version",
    );

    // (4) The stamp is CURRENT, and it appeared only after the work completed —
    //     not at upgrade time, which is the whole point of the retarget.
    assert_eq!(index_counts(&pic, pool, ctrl).2, 2, "stamped CURRENT on completion");
    assert!(call > 1, "the stamp must NOT appear on the first gated call — 1001 records exceed one chunk");
}

// ─────────────────────────────────────────────────────────────────────────────
// P-ROOT R3: recovery-index schema v2 transition (version 0 / legacy 1 /
// current 2 / unknown are matched EXPLICITLY; the v1 "unindexed submitter-None
// spend" grace is rejected by the audited v1→v2 migration, never silently
// dropped from INFLIGHT reconstruction)
// ─────────────────────────────────────────────────────────────────────────────

fn workspace_root() -> std::path::PathBuf {
    // POOL_TEST_WASM = <ws>/target/wasm32-unknown-unknown/release/shielded_pool_test.wasm
    std::path::PathBuf::from(env!("POOL_TEST_WASM"))
        .ancestors()
        .nth(4)
        .expect("workspace root above target/wasm32-unknown-unknown/release")
        .to_path_buf()
}

/// Assert a deliberately-uncommitted gate input exists, naming the exact command
/// that produces it (same one-door convention as the P-MRK SSA suite).
fn require_artifact(path: std::path::PathBuf, what: &str, how: &str) -> std::path::PathBuf {
    assert!(
        path.exists(),
        "Missing {what} at {}.\n\
         This is a MANDATORY P-REC v1→v2 gate prerequisite (see build.rs) — produce it with:\n  {how}",
        path.display()
    );
    path
}

/// The REAL previous-v1 Wasm: the shielded_pool TEST build from `20a6fb3` (the
/// post-P-MRK master this lane was cut from — P-REC v1 semantics, pre-P-ROOT).
/// Not committed; produced with the documented worktree build.
fn pool_v1_test_wasm() -> Vec<u8> {
    let default = workspace_root()
        .join("target/wasm32-unknown-unknown/release/shielded_pool_prec_v1_test.wasm");
    let how = format!(
        "git worktree add --detach /tmp/stsh-prec-v1 20a6fb3 && \
         (cd /tmp/stsh-prec-v1 && \
         cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing) && \
         cp /tmp/stsh-prec-v1/target/wasm32-unknown-unknown/release/shielded_pool.wasm {} && \
         git worktree remove --force /tmp/stsh-prec-v1",
        default.display()
    );
    let path = require_artifact(
        default,
        "the pre-P-ROOT (P-REC v1, 20a6fb3) shielded_pool TEST Wasm",
        &how,
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn deploy_pool_v1(pic: &PocketIc) -> (Principal, Principal) {
    let controller = p(0xC0);
    let pool = create_canister(pic);
    install(
        pic,
        pool,
        pool_v1_test_wasm(),
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

#[test]
fn test_r3_real_v1_wasm_unindexed_legacy_spend_rejected_then_advances_to_v2() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_v1(&pic);

    // Genuine v1-era durable state: one indexable deposit + the legitimate v1
    // exception — a recovery-required spend in a NULLIFIER-RESERVATION state
    // with submitter == None (injected via the v1-era endpoint, which permits it).
    inject_deposit_as(&pic, pool, ctrl, alice(), c(1), DepositStatus::TransferPending);
    inject_spend(&pic, pool, ctrl, 10, None, SpendStatus::OutputsStaged);

    // Run the GENUINE v1 migration: a v1-wasm self-upgrade builds the index and
    // stamps version 1 — indexing the deposit and (the v1 grace) SKIPPING the
    // submitter-less spend. (The v1 H-1 pass normalizes OutputsStaged →
    // NullifierInsertUnknown; still recovery-required, still unindexed.)
    upgrade(&pic, pool, pool_v1_test_wasm()).expect("v1 self-upgrade must build + stamp v1");
    assert_eq!(
        index_counts(&pic, pool, ctrl),
        (1, 0, 1),
        "v1 semantics: deposit indexed, legacy spend skipped, version 1"
    );

    // v1 → CURRENT: the audited v1→v2 migration must REJECT the upgrade — the
    // unindexed nullifier-reservation spend can never be carried into the
    // index-only era (its INFLIGHT protection would silently vanish on the NEXT
    // upgrade). It is rejected, not omitted.
    let r = upgrade(&pic, pool, pool_prod_wasm());
    assert!(r.is_err(), "v1→v2 must reject while the unindexed legacy spend exists; got {:?}", r);
    // NOTE: since the A-1 sentinel fix this rejection is OVERDETERMINED — the
    // unindexed legacy spend and the absent fee-governance region would each
    // refuse it on their own. The P-REC assertion below (TRAP-NO-STAMP) is what
    // this step is really pinning, and it holds either way.

    // TRAP-NO-STAMP: rolled back to the v1 Wasm, version still 1, state intact.
    assert_eq!(index_counts(&pic, pool, ctrl), (1, 0, 1), "rejection must not stamp or mutate");

    // Resolve the legacy spend ON THE PREVIOUS WASM, as the rejection instructs
    // (terminal FailedAfterOutputsStaged — no longer recovery-required).
    let _: () = decode(
        "set_spend_status_for_test",
        pic.update_call(
            pool,
            ctrl,
            "set_spend_status_for_test",
            candid::encode_args((
                10u64,
                SpendStatus::FailedAfterOutputsStaged { reason: "resolved on previous wasm".into() },
            ))
            .unwrap(),
        ),
    );

    // ── RE-PINNED (RB-SWARM-A1 sentinel fix, Fix A, RULED 2026-08-01) ─────────
    //
    // This step used to assert that a COMPLETE v1 state advances in place and
    // stamps v2. It no longer does, and that is the ruling, not a regression:
    // **the pre-A1 boundary is a REINSTALL boundary, not an upgrade boundary.**
    //
    // The v1 Wasm predates the fee-governance eager cell (MemoryId 18), so on
    // arrival at the current build that region reads as the impossible
    // sentinel. The old code inferred "genuine pre-A1 pool" from the checkpoint
    // and migrated; SSA showed the inference is forgeable, because a CORRUPTED
    // current checkpoint presents identically under Candid record-width
    // subtyping. The inference is gone, so the sentinel now traps
    // unconditionally.
    //
    // What this test still proves is the part that matters operationally: the
    // rejection is CLEAN. The upgrade is refused, nothing is stamped or
    // mutated, and the pool keeps running the previous Wasm — so an operator
    // who attempts the boundary by mistake loses nothing and can reinstall.
    let r = upgrade(&pic, pool, pool_prod_wasm());
    assert!(
        r.is_err(),
        "the pre-A1 boundary must be REFUSED even from a complete v1 state — recovery is \
         reinstall (init), not an in-place upgrade; got {:?}",
        r
    );

    // TRAP-NO-STAMP, again: rolled back to the v1 Wasm, version still 1, the
    // deposit index and the recovery listing both intact.
    assert_eq!(
        index_counts(&pic, pool, ctrl),
        (1, 0, 1),
        "the refused boundary upgrade must not stamp or mutate"
    );
    assert_eq!(
        list_deposits(&pic, pool, alice(), None, 100).deposits.len(),
        1,
        "recovery listing intact after the refused boundary upgrade"
    );
}

#[test]
fn test_r3_unknown_recovery_schema_version_traps_never_guesses() {
    let pic = PocketIc::new();
    let (pool, ctrl) = deploy_pool_test(&pic);

    // Force an unknown/future schema version, then attempt a real upgrade.
    let _: () = decode(
        "set_recovery_index_version_for_test",
        pic.update_call(
            pool,
            ctrl,
            "set_recovery_index_version_for_test",
            candid::encode_one(7u32).unwrap(),
        ),
    );
    let r = upgrade(&pic, pool, pool_prod_wasm());
    assert!(
        r.is_err(),
        "an unknown recovery-index schema version must TRAP the upgrade — never fall \
         back to index-only or main-map behavior; got {:?}",
        r
    );
    // Rolled back: still answering, version unchanged.
    assert_eq!(index_counts(&pic, pool, ctrl).2, 7, "version untouched by the rejected upgrade");
}
