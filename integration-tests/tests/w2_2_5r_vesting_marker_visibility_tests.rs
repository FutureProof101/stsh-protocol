// =============================================================================
// W2 2-5R — the vesting outstanding-claim-marker surface (DEF-096)
// =============================================================================
//
// The §2.4a behaviour floor. Schema equality is proved natively in the vesting
// crate's field-lock test; what is proved HERE is the query's SEMANTICS, which
// only a canister boundary can show: real markers, a real controller identity,
// and a real in-flight claim parked at its await.
//
// Note on the two staging shapes:
//   * STUCK  (unknown == true)  — stop the token canister, so the claim's
//     transfer returns a transport-unknown outcome and the marker flips.
//   * IN-FLIGHT (unknown == false) — park the claim at its await with
//     submit_call + one tick on a TWO-SUBNET topology. On a single subnet the
//     induced message is delivered in the same round and the claim completes,
//     so no in-flight marker is ever observable. This is the SSA-sanctioned
//     technique; no injection hook, production Wasm.

use candid::{CandidType, Nat, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;

fn load_wasm(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {label} wasm at {path}: {e}"))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn vesting_wasm() -> Vec<u8> { load_wasm(env!("VESTING_WASM"), "vesting") }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String, category_name: String, amount: u128, recipient: Principal,
    subaccount: Option<[u8; 32]>, lock_policy: LockPolicy,
    vesting_policy: Option<VestingPolicy>, created_at_genesis: bool, genesis_timestamp_ns: u64,
}
#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>, treasury: Principal, staking_canister: Principal,
}
#[derive(CandidType, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal, controller: Principal, schedules: Vec<NewSchedule>,
}
#[derive(CandidType, Deserialize, Clone)]
struct NewSchedule {
    beneficiary: Principal, total_amount: u128, cliff_months: u32, linear_months: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ClaimMarkerState { InFlight, Stuck }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct OutstandingClaimMarker {
    beneficiary: Principal,
    state: ClaimMarkerState,
    pending_amount: Option<u128>,
    claim_seq: Option<u64>,
    created_at_time_ns: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum OutstandingClaimMarkerError { NotController, ControllerNotConfigured }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

/// R3: the schedule itself is an observable, and it is the one a masked value
/// cannot speak for. `claimable_amount` is forced to 0 whenever a marker
/// exists, so it cannot reveal a mutation of `claimed` — the same masking
/// property that disqualified it as marker evidence.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct VestingSchedule {
    beneficiary: Principal, total_amount: u128, cliff_end_ns: u64,
    vesting_end_ns: u64, claimed: u128, start_ns: u64,
}

fn p(n: u8) -> Principal { let mut b = [0u8; 29]; b[0] = n; Principal::from_slice(&b) }
fn anon() -> Principal { Principal::anonymous() }

fn decode<T, E>(label: &str, r: Result<Vec<u8>, E>) -> T
where T: CandidType + for<'de> Deserialize<'de>, E: std::fmt::Debug {
    let b = r.unwrap_or_else(|e| panic!("{label}: call rejected/failed: {e:?}"));
    candid::decode_one(&b).unwrap_or_else(|e| panic!("{label}: candid decode failed: {e}"))
}

struct Fleet { pic: PocketIc, token: Principal, vesting: Principal, controller: Principal }

/// Token on subnet A, vesting on subnet B, so a claim can be parked at its
/// await. `beneficiaries` each get a fully-vested schedule.
fn deploy(beneficiaries: &[Principal]) -> Fleet {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let subnets = pic.topology().get_app_subnets();
    assert_eq!(subnets.len(), 2);
    let controller = p(0x10);

    let token = pic.create_canister_on_subnet(Some(controller), None, subnets[0]);
    pic.add_cycles(token, 2_000_000_000_000u128);
    let vesting = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    pic.add_cycles(vesting, 2_000_000_000_000u128);
    assert_ne!(pic.get_subnet(token), pic.get_subnet(vesting), "must differ or nothing parks");

    pic.install_canister(token, token_wasm(), candid::encode_one(&TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".into(), category_name: "All".into(), amount: TOTAL_SUPPLY,
            recipient: vesting, subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None, created_at_genesis: false, genesis_timestamp_ns: 0,
        }], treasury: p(0x01), staking_canister: p(0x99),
    }).unwrap(), Some(controller));

    pic.install_canister(vesting, vesting_wasm(), candid::encode_one(&VestingInitArgs {
        token_canister: token, controller,
        schedules: beneficiaries.iter().map(|b| NewSchedule {
            beneficiary: *b, total_amount: 5 * STSH, cliff_months: 0, linear_months: 1,
        }).collect(),
    }).unwrap(), Some(controller));

    pic.advance_time(Duration::from_secs(31 * 24 * 3600));
    pic.tick();
    Fleet { pic, token, vesting, controller }
}

fn markers(f: &Fleet, sender: Principal)
    -> Result<Vec<OutstandingClaimMarker>, OutstandingClaimMarkerError>
{
    decode("list_outstanding_claim_markers",
        f.pic.query_call(f.vesting, sender, "list_outstanding_claim_markers",
            candid::encode_args(()).unwrap()))
}

fn ok_markers(f: &Fleet) -> Vec<OutstandingClaimMarker> {
    markers(f, f.controller).expect("controller must be authorized")
}

fn schedules(f: &Fleet) -> Vec<VestingSchedule> {
    decode("list_schedules",
        f.pic.query_call(f.vesting, anon(), "list_schedules", candid::encode_args(()).unwrap()))
}

fn balance(f: &Fleet, owner: Principal) -> u128 {
    let n: Nat = decode("icrc1_balance_of",
        f.pic.query_call(f.token, anon(), "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap()));
    n.0.to_string().parse().unwrap()
}

/// Drive `who` into a STUCK marker: the token is stopped, so the transfer
/// returns a transport-unknown outcome.
fn make_stuck(f: &Fleet, who: Principal) {
    f.pic.stop_canister(f.token, Some(f.controller)).expect("stop token");
    let r: Result<Nat, String> = decode("claim",
        f.pic.update_call(f.vesting, who, "claim", candid::encode_args(()).unwrap()));
    assert!(r.unwrap_err().contains("TransferOutcomeUnknown"));
    f.pic.start_canister(f.token, Some(f.controller)).expect("start token");
}

// ─────────────────────────────────────────────────────────────────────────────
// §2.4a floor
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn case_1_and_8_no_marker_returns_an_empty_vector_not_an_error() {
    let f = deploy(&[p(0x11)]);
    let rows = ok_markers(&f);
    assert!(rows.is_empty(), "nothing outstanding must be an EMPTY LIST, got {rows:?}");
}

#[test]
fn case_2_an_in_flight_claim_reads_as_inflight() {
    let who = p(0x11);
    let f = deploy(&[who]);

    let msg = f.pic.submit_call(f.vesting, who, "claim", candid::encode_args(()).unwrap())
        .expect("submit_call accepted");
    f.pic.tick(); // parked at the await; the cross-subnet reply cannot arrive yet

    // Decisive: the transfer has NOT executed while parked.
    assert_eq!(balance(&f, who), 0, "must be parked at the await, not completed");

    let rows = ok_markers(&f);
    assert_eq!(rows.len(), 1, "exactly one outstanding marker");
    assert_eq!(rows[0].beneficiary, who);
    assert_eq!(rows[0].state, ClaimMarkerState::InFlight, "unknown == false must read as InFlight");

    let _ = f.pic.await_call(msg);
}

#[test]
fn case_3_a_stuck_claim_reads_as_stuck() {
    let who = p(0x11);
    let f = deploy(&[who]);
    make_stuck(&f, who);

    let rows = ok_markers(&f);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].beneficiary, who);
    assert_eq!(rows[0].state, ClaimMarkerState::Stuck, "unknown == true must read as Stuck");
}

#[test]
fn case_4_identity_fields_are_returned_as_stored() {
    let who = p(0x11);
    let f = deploy(&[who]);
    make_stuck(&f, who);

    let row = ok_markers(&f).remove(0);
    // The marker is written with the full claimable amount, the operation's
    // claim_seq, and a one-time created_at stamp. None of the three may be
    // defaulted away or invented.
    assert_eq!(row.pending_amount, Some(5 * STSH), "pending_amount must be as stored");
    // claim_seq is the count of this beneficiary's existing terminal tombstones
    // (next_claim_seq), so the FIRST claim is seq 0 — asserted as the canister
    // actually defines it, not as a 1-based guess.
    assert_eq!(row.claim_seq, Some(0), "first claim for this beneficiary is seq 0");
    assert!(row.created_at_time_ns.is_some(), "the frozen created_at stamp must be reported");
    assert!(row.created_at_time_ns.unwrap() > 0);
}

/// LAUNCH-HARDEN-04 O-7: the listing is ANONYMOUS-READABLE (every field is
/// already public via the schedule queries and the ledger). Any caller —
/// including anonymous and a non-controller — gets `Ok` with the same rows,
/// and the read mutates nothing. (Formerly: a non-controller got the typed
/// `NotController`; that variant is retained for decode compatibility only.)
#[test]
fn case_5_any_caller_including_anonymous_reads_the_same_rows_and_mutates_nothing() {
    let who = p(0x11);
    let f = deploy(&[who]);
    make_stuck(&f, who);

    let before = ok_markers(&f);
    let schedules_before = schedules(&f);
    assert_eq!(markers(&f, p(0x77)), Ok(before.clone()), "a non-controller now reads Ok");
    assert_eq!(markers(&f, anon()), Ok(before.clone()), "anonymous now reads Ok");
    assert!(!before.is_empty(), "non-vacuity: the stuck marker is listed");

    assert_eq!(ok_markers(&f), before, "a read must leave the marker list unchanged");
    // R3: `claimed` and every other schedule field must be unchanged too. The
    // marker list and the balance alone cannot see a schedule mutation.
    assert_eq!(schedules(&f), schedules_before, "a read must not mutate any schedule");
    assert_eq!(balance(&f, who), 0);
}

#[test]
fn case_6_and_7_every_marker_appears_exactly_once_in_a_deterministic_order() {
    let a = p(0x11);
    let b = p(0x12);
    let c = p(0x13);
    let f = deploy(&[a, b, c]);
    make_stuck(&f, a);
    make_stuck(&f, b);
    make_stuck(&f, c);

    let rows = ok_markers(&f);
    assert_eq!(rows.len(), 3, "all outstanding markers must be returned");

    let mut seen: Vec<Principal> = rows.iter().map(|r| r.beneficiary).collect();
    let unique = { seen.sort(); seen.dedup(); seen.len() };
    assert_eq!(unique, 3, "each marker exactly once, no duplicates");

    // Deterministic order: stable-map key order = ascending raw principal bytes.
    let order: Vec<Vec<u8>> = rows.iter().map(|r| r.beneficiary.as_slice().to_vec()).collect();
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(order, sorted, "rows must come out in ascending key order");

    // Repeated reads return the SAME sequence, so a diff shows real change.
    assert_eq!(ok_markers(&f), rows, "repeated reads must be identical");
    assert_eq!(ok_markers(&f), rows);
}

#[test]
fn the_query_is_read_only_across_repeated_calls() {
    let who = p(0x11);
    let f = deploy(&[who]);
    make_stuck(&f, who);

    let first = ok_markers(&f);
    // R3: snapshot the SCHEDULES, not `claimable_amount`. With a marker present
    // claimable_amount is pinned to 0, so it would report "unchanged" even if
    // `claimed` moved underneath it — the exact masking that disqualified it as
    // marker evidence elsewhere in this lane.
    let schedules_before = schedules(&f);
    let balance_before = balance(&f, who);

    for _ in 0..3 { let _ = ok_markers(&f); }

    assert_eq!(ok_markers(&f), first, "reading must not change what is read");
    assert_eq!(schedules(&f), schedules_before, "no schedule field may move across repeated reads");
    assert_eq!(balance(&f, who), balance_before, "no transfer may be issued by a read");
}
