// =============================================================================
// STSH — W2 2-2: treasury post_upgrade cap-and-trap (PocketIC, REAL upgrades)
// =============================================================================
//
// DEFECT (2-2): `sweep_reserved_reservations_on_upgrade()` collected
// `INFLIGHT_RESERVATIONS.iter()` filtered to `Reserved` with NO bound, and is
// invoked from `post_upgrade`. On a large map the upgrade exceeds the
// instruction limit and the canister is BRICKED.
//
// FIX: the pool's cap-and-trap discipline (`canisters/shielded-pool/src/lib.rs`
// ACTIVE_DEPOSIT_INDEX / TREASURY_DISBURSEMENTS): take at most
// `MAX_UPGRADE_SCAN + 1` qualifying entries, and if the count exceeds the cap,
// `ic_cdk::trap` with an operator-actionable message BEFORE any record is
// rewritten. `MAX_UPGRADE_SCAN` is a treasury-local copy of the EXACT pool
// value (1_000).
//
// WHY POCKETIC AND NOT NATIVE: native tests keep thread-locals alive in-process,
// so a native "upgrade" never re-runs the real post_upgrade across a Wasm
// boundary. Only a real cross-Wasm upgrade exercises this path.
//
// PROBE: there is no public reservation-status query. `reject_proposal` is the
// behavioral probe — it returns `InFlight` while a reservation is `Reserved`
// and proceeds once the sweep has moved it to `OutcomeUnknown`. No new
// endpoint is introduced by this lane.
//
// PREREQUISITES:
//   1. cargo build --target wasm32-unknown-unknown --release -p stsh_token -p treasury
//      (plus the --features testing treasury build — see integration-tests/build.rs)
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Treasury-local upgrade-scan cap under test (canisters/treasury/src/lib.rs),
/// itself an exact copy of the pool's `MAX_UPGRADE_SCAN`.
const MAX_UPGRADE_SCAN: u64 = 1_000;

/// 7 days in seconds — treasury withdrawal timelock.
const TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token -p treasury",
            pkg, path, e
        )
    })
}

fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn treasury_test_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_TEST_WASM"), "treasury_test")
}

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors (token init + treasury surface)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id:          String,
    category_name:        String,
    amount:               u128,
    recipient:            Principal,
    subaccount:           Option<[u8; 32]>,
    lock_policy:          LockPolicy,
    vesting_policy:       Option<VestingPolicy>,
    created_at_genesis:   bool,
    genesis_timestamp_ns: u64,
}

#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations:      Vec<AllocationCategory>,
    treasury:         Principal,
    staking_canister: Principal,
}

fn all_to(recipient: Principal) -> TokenInitArgs {
    const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id:          "all".to_string(),
            category_name:        "All tokens".to_string(),
            amount:               TOTAL_SUPPLY,
            recipient,
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }],
        treasury:         p(0x01),
        staking_canister: p(0x02),
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum FeeSource {
    ShieldFee,
    PrivateTransferFee,
    UnshieldFee,
    DexRevenue,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus { Pending, Executed, Rejected, Expired }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum RejectProposalError {
    NotFound,
    NotPending { current: ProposalStatus },
    InFlight,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct WithdrawalProposal {
    id:               u64,
    proposer:         Principal,
    subaccount_name:  String,
    recipient:        Principal,
    amount:           u128,
    description:      String,
    created_at_ns:    u64,
    execute_after_ns: u64,
    status:           ProposalStatus,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal { Principal::anonymous() }

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 20_000_000_000_000u128);
    cid
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result
        .unwrap_or_else(|e| panic!("{}: call was rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes)
        .unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

/// A REAL cross-Wasm treasury upgrade. Err iff pre/post_upgrade traps.
fn upgrade_treasury(pic: &PocketIc, treasury_id: Principal) -> Result<(), String> {
    pic.upgrade_canister(treasury_id, treasury_test_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

struct Stack {
    treasury:   Principal,
    controller: Principal,
    pool:       Principal,
}

/// Treasury (testing build) + token, with `operations` funded and one real
/// Pending proposal past its timelock. Returns the stack and the proposal id.
fn deploy_treasury(pic: &PocketIc) -> (Stack, u64) {
    let controller = p(0x22);
    let pool       = p(0xE0);
    let recipient  = p(0xE1);

    let token_id    = create_canister(pic);
    let treasury_id = create_canister(pic);

    let init = candid::encode_one(all_to(treasury_id)).unwrap();
    pic.install_canister(token_id, token_wasm(), init, None);
    let treasury_init = candid::encode_args((token_id, pool, controller)).unwrap();
    pic.install_canister(treasury_id, treasury_test_wasm(), treasury_init, None);

    const AMOUNT: u128 = 4_000_000;
    let _: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(
            treasury_id, pool, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, AMOUNT, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );

    let proposal_id: u64 = decode(
        "propose_withdrawal",
        pic.update_call(
            treasury_id, controller, "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(), recipient, AMOUNT, "w2-2-2".to_string(),
            )).unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    (Stack { treasury: treasury_id, controller, pool: pool }, proposal_id)
}

/// Seed `n` durable `Reserved` reservations. `inject_inflight_proposal_for_test`
/// falls back to fingerprint 0 when no proposal exists, so synthetic ids are
/// fine — the sweep filters on status alone.
fn inject_reserved(pic: &PocketIc, s: &Stack, ids: impl Iterator<Item = u64>) {
    for id in ids {
        let _: () = decode(
            "inject_inflight_proposal_for_test",
            pic.update_call(
                s.treasury, s.controller, "inject_inflight_proposal_for_test",
                candid::encode_one(id).unwrap(),
            ),
        );
    }
}

fn reservation_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "inflight_proposals_count_for_test",
        pic.query_call(
            s.treasury, s.controller, "inflight_proposals_count_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Per-status durable reservation counts, as
/// `(Reserved, Executed, Failed, OutcomeUnknown)`.
///
/// `reservation_count` above is status-INSENSITIVE: it proves nothing was
/// removed, not that anything was swept. Only these exact counts can show the
/// sweep is UNIVERSAL (every seeded record converted, none skipped) and that a
/// trapped upgrade wrote NOTHING at all.
fn status_counts(pic: &PocketIc, s: &Stack) -> (u64, u64, u64, u64) {
    let bytes = pic
        .query_call(
            s.treasury, s.controller, "reservation_status_counts_for_test",
            candid::encode_args(()).unwrap(),
        )
        .unwrap_or_else(|e| panic!("reservation_status_counts_for_test rejected: {e:?}"));
    candid::decode_args(&bytes)
        .unwrap_or_else(|e| panic!("reservation_status_counts_for_test decode failed: {e}"))
}

/// Behavioral status probe: `Reserved` ⇒ `Err(InFlight)`; swept
/// (`OutcomeUnknown`) ⇒ the Pending-only rejection proceeds.
fn try_reject(pic: &PocketIc, s: &Stack, id: u64) -> Result<(), RejectProposalError> {
    decode(
        "reject_proposal",
        pic.update_call(
            s.treasury, s.controller, "reject_proposal",
            candid::encode_one(id).unwrap(),
        ),
    )
}

fn proposal_status(pic: &PocketIc, s: &Stack, id: u64) -> ProposalStatus {
    let proposals: Vec<WithdrawalProposal> = decode(
        "list_proposals",
        pic.query_call(s.treasury, anon(), "list_proposals", candid::encode_args(()).unwrap()),
    );
    proposals.into_iter().find(|p| p.id == id)
        .unwrap_or_else(|| panic!("proposal {} not found", id))
        .status
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-2-2-C — the status probe cannot reach production
// ─────────────────────────────────────────────────────────────────────────────
//
// `reservation_status_counts_for_test` is `#[cfg(feature = "testing")]`, and
// the treasury's `testing` feature is never enabled for the deployable build
// (`canisters/treasury/Cargo.toml`: `[features] testing = []`, off by default;
// `treasury.wasm` is built without it, `treasury_test.wasm` with it).
//
// That is an ASSERTION about the build. This test makes it a PROOF, the same
// way `eager_cell_feature_isolation_tests.rs` does for the eager-cell probe:
// scan the shipped binary for the export name. The negative half is void
// without the positive half — if the marker were absent from both Wasms the
// scan would be silently vacuous — so both are asserted.

const STATUS_PROBE_EXPORT: &[u8] = b"reservation_status_counts_for_test";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn w2_2_2_c_status_probe_is_absent_from_the_production_treasury_wasm() {
    let production = load_wasm(env!("TREASURY_WASM"), "treasury");
    assert!(
        !contains(&production, STATUS_PROBE_EXPORT),
        "treasury: PRODUCTION Wasm contains the test-only export \
         `reservation_status_counts_for_test`. The `testing` feature has leaked \
         into a deployable artifact — do NOT ship this build.",
    );

    // The positive control: without this, the scan above proves nothing.
    let testing = treasury_test_wasm();
    assert!(
        contains(&testing, STATUS_PROBE_EXPORT),
        "treasury_test: the testing Wasm is MISSING \
         `reservation_status_counts_for_test`, so the production scan above is \
         silently void. Either the probe was renamed or the feature build broke.",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-2-2-A — AT the cap: the upgrade completes and every Reserved record is swept
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn w2_2_2_a_sweep_completes_at_the_cap() {
    let pic = PocketIc::new();
    let (s, proposal_id) = deploy_treasury(&pic);

    // The real proposal's reservation, plus synthetic ones, to EXACTLY the cap.
    inject_reserved(&pic, &s, std::iter::once(proposal_id));
    let synthetic_start = proposal_id + 1;
    inject_reserved(&pic, &s, synthetic_start..(synthetic_start + MAX_UPGRADE_SCAN - 1));
    assert_eq!(
        reservation_count(&pic, &s), MAX_UPGRADE_SCAN,
        "precondition: exactly MAX_UPGRADE_SCAN Reserved records",
    );

    // Pre-condition: every seeded record is Reserved, none yet swept.
    assert_eq!(
        status_counts(&pic, &s), (MAX_UPGRADE_SCAN, 0, 0, 0),
        "precondition: all MAX_UPGRADE_SCAN records Reserved, none OutcomeUnknown",
    );

    // Pre-condition: Reserved blocks rejection.
    assert_eq!(
        try_reject(&pic, &s, proposal_id), Err(RejectProposalError::InFlight),
        "a Reserved reservation must block reject_proposal before the upgrade",
    );

    // REAL cross-Wasm upgrade — at the cap it must NOT trap.
    upgrade_treasury(&pic, s.treasury).expect("upgrade at the scan cap must succeed");

    // No record is ever removed by the sweep.
    assert_eq!(
        reservation_count(&pic, &s), MAX_UPGRADE_SCAN,
        "the sweep is forward-only — it must not remove records",
    );

    // THE UNIVERSAL CLAIM, asserted as exact counts rather than inferred from a
    // single probed proposal: EVERY Reserved record became OutcomeUnknown.
    // Zero Reserved remaining is what rules out a sweep that converted one
    // record and silently skipped the other 999.
    assert_eq!(
        status_counts(&pic, &s), (0, 0, 0, MAX_UPGRADE_SCAN),
        "the at-cap sweep must leave exactly 0 Reserved and MAX_UPGRADE_SCAN \
         OutcomeUnknown — every seeded reservation swept, none skipped",
    );

    // ── CONTRACT CHANGE, W2 2-6 §2(6a) (SSA-W226-002) ────────────────────────
    //
    // This test previously asserted that the swept record no longer blocks
    // rejection — a behavioural proxy for "no longer `Reserved`", valid when
    // `reservation_is_inflight` matched `Reserved` alone.
    //
    // W2 2-6 deliberately WIDENS that guard to every ACTIVE status, which
    // includes `OutcomeUnknown`: rejecting an `OutcomeUnknown` proposal makes it
    // non-`Pending`, `execute_withdrawal` then refuses it, and the retry that
    // alone can resolve the attempt becomes unreachable — the encumbrance would
    // be permanent. Silently releasing on rejection is ruled OUT, because the
    // pool may in fact have executed.
    //
    // So the proxy is no longer sound and is replaced by its direct form: the
    // universal-sweep claim is already proven by the exact status counts above.
    // What is asserted here is the NEW, stricter contract.
    assert_eq!(
        try_reject(&pic, &s, proposal_id), Err(RejectProposalError::InFlight),
        "W2 2-6 §2(6a): a swept OutcomeUnknown reservation is still ACTIVE and must \
         keep refusing rejection — its outcome is unresolved, so releasing it would \
         over-admit funds the pool may already have disbursed",
    );
    assert_eq!(
        proposal_status(&pic, &s, proposal_id), ProposalStatus::Pending,
        "and the proposal stays Pending, so the resolving retry remains reachable",
    );
    let _ = s.pool;
}

// ─────────────────────────────────────────────────────────────────────────────
// W2-2-2-B — OVER the cap: the upgrade traps, with no partial migration
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn w2_2_2_b_upgrade_traps_over_the_cap_without_partial_migration() {
    let pic = PocketIc::new();
    let (s, proposal_id) = deploy_treasury(&pic);

    inject_reserved(&pic, &s, std::iter::once(proposal_id));
    let synthetic_start = proposal_id + 1;
    inject_reserved(&pic, &s, synthetic_start..(synthetic_start + MAX_UPGRADE_SCAN));
    assert_eq!(
        reservation_count(&pic, &s), MAX_UPGRADE_SCAN + 1,
        "precondition: one Reserved record over the cap",
    );
    assert_eq!(
        status_counts(&pic, &s), (MAX_UPGRADE_SCAN + 1, 0, 0, 0),
        "precondition: all records Reserved, none OutcomeUnknown",
    );

    // REAL cross-Wasm upgrade — over the cap post_upgrade must trap.
    let err = upgrade_treasury(&pic, s.treasury)
        .expect_err("upgrade over the scan cap must trap, not proceed");
    assert!(
        err.contains("INFLIGHT_RESERVATIONS") && err.contains("upgrade-scan cap"),
        "the trap must name the map and the cap; got: {err}",
    );
    assert!(
        err.contains("retry the upgrade"),
        "the trap must be operator-actionable; got: {err}",
    );

    // Trapped ⇒ rolled back ⇒ NO partial migration: the reservation is still
    // Reserved, so rejection is still refused.
    assert_eq!(
        reservation_count(&pic, &s), MAX_UPGRADE_SCAN + 1,
        "a trapping upgrade must leave the map untouched",
    );

    // THE MIRROR PROOF. This is what turns "traps before any partial
    // migration" from a code-reading inference into an OBSERVED fact: after
    // the trap, exactly MAX_UPGRADE_SCAN + 1 records are still Reserved and
    // ZERO are OutcomeUnknown. Not one record was written.
    assert_eq!(
        status_counts(&pic, &s), (MAX_UPGRADE_SCAN + 1, 0, 0, 0),
        "a trapped over-cap upgrade must leave exactly MAX_UPGRADE_SCAN + 1 \
         Reserved and 0 OutcomeUnknown — no partial migration whatsoever",
    );

    assert_eq!(
        try_reject(&pic, &s, proposal_id), Err(RejectProposalError::InFlight),
        "a trapping upgrade must not have applied a partial sweep",
    );
    assert_eq!(
        proposal_status(&pic, &s, proposal_id), ProposalStatus::Pending,
        "the proposal must be untouched by the trapped upgrade",
    );
}
