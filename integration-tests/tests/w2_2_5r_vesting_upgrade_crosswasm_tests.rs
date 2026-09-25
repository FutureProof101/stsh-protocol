// =============================================================================
// W2 2-5R §3 — the two cross-Wasm vesting-upgrade tests
// =============================================================================
//
// WHAT WAS MISSING AT THE PIN. `sweep_inflight_markers_on_upgrade()` is called
// from `post_upgrade` and promotes any in-flight marker to stuck BEFORE ingress
// resumes; `claim()` then blocks on ANY surviving marker. Coverage was an
// in-crate NATIVE test only — a repo-wide search of integration-tests/ for the
// sweep and for L3-INT-02 returned zero hits. Native cannot establish the
// ordering property (the sweep completes before ingress resumes), which is the
// standing native/cross-Wasm blind spot: heap-only state passes natively
// because thread-locals survive an in-process post_upgrade.
//
// EVIDENCE SHAPE — binding, per SSA checkpoint 1 and the CTO phase-1 confirm:
//   * token and vesting on DISTINCT application subnets, asserted in the harness;
//   * the install budget settled BEFORE parking (settling it after executes
//     rounds, which would let the parked call finish and silently make this a
//     test of nothing);
//   * suspension proved by a ZERO token-balance DELTA from a recorded baseline,
//     never by `claimable_amount`, which returns 0 both when a marker exists and
//     when `claimed == total` and so cannot discriminate;
//   * marker state observed through the NEW §2 query — InFlight before the
//     upgrade, Stuck after — which is what makes that surface's own correctness
//     cross-Wasm evidence rather than an assertion about itself.
//
// Production Wasm throughout. No injection hook and no testing-only surface.

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
#[derive(CandidType, Deserialize, Clone)]
struct VestingInitArgs {
    token_canister: Principal, controller: Principal, schedules: Vec<NewSchedule>,
}
#[derive(CandidType, Deserialize, Clone)]
struct NewSchedule {
    beneficiary: Principal, total_amount: u128, cliff_months: u32, linear_months: u32,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingSchedule {
    beneficiary: Principal, total_amount: u128, cliff_end_ns: u64,
    vesting_end_ns: u64, claimed: u128, start_ns: u64,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ClaimMarkerState { InFlight, Stuck }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct OutstandingClaimMarker {
    beneficiary: Principal, state: ClaimMarkerState, pending_amount: Option<u128>,
    claim_seq: Option<u64>, created_at_time_ns: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum OutstandingClaimMarkerError { NotController, ControllerNotConfigured }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ClaimDecision { Executed, NotExecuted }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

fn p(n: u8) -> Principal { let mut b = [0u8; 29]; b[0] = n; Principal::from_slice(&b) }
fn anon() -> Principal { Principal::anonymous() }

fn decode<T, E>(label: &str, r: Result<Vec<u8>, E>) -> T
where T: CandidType + for<'de> Deserialize<'de>, E: std::fmt::Debug {
    let b = r.unwrap_or_else(|e| panic!("{label}: call rejected/failed: {e:?}"));
    candid::decode_one(&b).unwrap_or_else(|e| panic!("{label}: candid decode failed: {e}"))
}

struct Fleet {
    pic: PocketIc,
    token: Principal,
    vesting: Principal,
    controller: Principal,
    init: VestingInitArgs,
}

fn deploy(who: Principal, total: u128) -> Fleet {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let subnets = pic.topology().get_app_subnets();
    assert_eq!(subnets.len(), 2, "the staging technique REQUIRES two application subnets");
    let controller = p(0x10);

    let token = pic.create_canister_on_subnet(Some(controller), None, subnets[0]);
    pic.add_cycles(token, 2_000_000_000_000u128);
    let vesting = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    pic.add_cycles(vesting, 2_000_000_000_000u128);
    // Binding: assert the DISTINCTION, do not merely arrange it.
    assert_ne!(
        pic.get_subnet(token), pic.get_subnet(vesting),
        "token and vesting MUST be on different subnets or the claim never parks"
    );

    pic.install_canister(token, token_wasm(), candid::encode_one(&TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".into(), category_name: "All".into(), amount: TOTAL_SUPPLY,
            recipient: vesting, subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None, created_at_genesis: false, genesis_timestamp_ns: 0,
        }], treasury: p(0x01), staking_canister: p(0x99),
    }).unwrap(), Some(controller));

    let init = VestingInitArgs {
        token_canister: token, controller,
        schedules: vec![NewSchedule {
            beneficiary: who, total_amount: total, cliff_months: 0, linear_months: 1,
        }],
    };
    pic.install_canister(vesting, vesting_wasm(), candid::encode_one(&init).unwrap(), Some(controller));
    pic.advance_time(Duration::from_secs(31 * 24 * 3600));
    pic.tick();

    Fleet { pic, token, vesting, controller, init }
}

fn markers(f: &Fleet) -> Vec<OutstandingClaimMarker> {
    let r: Result<Vec<OutstandingClaimMarker>, OutstandingClaimMarkerError> =
        decode("list_outstanding_claim_markers",
            f.pic.query_call(f.vesting, f.controller, "list_outstanding_claim_markers",
                candid::encode_args(()).unwrap()));
    r.expect("controller is authorized")
}

fn balance(f: &Fleet, owner: Principal) -> u128 {
    let n: Nat = decode("icrc1_balance_of",
        f.pic.query_call(f.token, anon(), "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap()));
    n.0.to_string().parse().unwrap()
}

fn schedule(f: &Fleet, who: Principal) -> VestingSchedule {
    let o: Option<VestingSchedule> = decode("get_schedule",
        f.pic.query_call(f.vesting, anon(), "get_schedule", candid::encode_one(who).unwrap()));
    o.expect("schedule exists")
}

fn upgrade(f: &Fleet) {
    f.pic.upgrade_canister(f.vesting, vesting_wasm(),
        candid::encode_one(&f.init).unwrap(), Some(f.controller))
        .expect("vesting upgrade must succeed");
}

/// Park a claim at its `icrc1_transfer` await. Returns the message id and the
/// beneficiary's token balance BASELINE recorded before the claim was submitted.
fn park_claim(f: &Fleet, who: Principal) -> (pocket_ic::common::rest::RawMessageId, u128) {
    // Settle the install_code throttle BEFORE parking.
    f.pic.advance_time(Duration::from_secs(7 * 86_400));
    for _ in 0..5 { f.pic.tick(); }

    let baseline = balance(f, who);

    let msg = f.pic
        .submit_call(f.vesting, who, "claim", candid::encode_args(()).unwrap())
        .expect("submit_call must be accepted");
    f.pic.tick(); // entry segment runs; the cross-subnet transfer is now in flight

    // DECISIVE suspension proof: zero balance DELTA from the baseline.
    assert_eq!(
        balance(f, who) - baseline, 0,
        "SUSPENSION NOT ACHIEVED: the transfer already executed before the upgrade"
    );
    (msg, baseline)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — the L3-INT-02 sweep, cross-Wasm
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sweep_promotes_an_inflight_marker_to_stuck_across_a_real_upgrade_and_blocks_claim() {
    let who = p(0x11);
    let total = 5 * STSH;
    let f = deploy(who, total);

    let (msg, baseline) = park_claim(&f, who);

    // BEFORE the upgrade: durably in flight, observed through the new surface.
    let before = markers(&f);
    assert_eq!(before.len(), 1, "exactly one outstanding marker while parked");
    assert_eq!(before[0].beneficiary, who);
    assert_eq!(
        before[0].state, ClaimMarkerState::InFlight,
        "the marker must be durably unknown == false before the upgrade"
    );
    assert_eq!(before[0].pending_amount, Some(total));

    upgrade(&f);
    let _ = f.pic.await_call(msg); // the continuation died with the old code

    // AFTER the upgrade: the sweep ran before ingress resumed.
    let after = markers(&f);
    assert_eq!(after.len(), 1, "the marker must survive the upgrade — it is the sole witness");
    assert_eq!(
        after[0].state, ClaimMarkerState::Stuck,
        "post_upgrade sweep must promote the in-flight marker to stuck"
    );
    // Identity is preserved across the upgrade, not re-minted.
    assert_eq!(after[0].beneficiary, before[0].beneficiary);
    assert_eq!(after[0].pending_amount, before[0].pending_amount);
    assert_eq!(after[0].claim_seq, before[0].claim_seq);
    assert_eq!(after[0].created_at_time_ns, before[0].created_at_time_ns);

    // ...and a new claim is blocked by the surviving marker.
    let blocked: Result<Nat, String> = decode("claim after upgrade",
        f.pic.update_call(f.vesting, who, "claim", candid::encode_args(()).unwrap()));
    assert!(
        blocked.unwrap_err().contains("TransferOutcomeUnknown"),
        "a surviving marker must block a new claim"
    );

    // The transfer itself DID land — this is the "outcome unknown but actually
    // executed" class, and exactly why the operator, not the canister, decides.
    assert_eq!(balance(&f, who) - baseline, total, "the transfer landed despite the lost reply");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — end-to-end, both reconcile arms
// ─────────────────────────────────────────────────────────────────────────────

fn stage_stuck(f: &Fleet, who: Principal) -> u128 {
    let (msg, baseline) = park_claim(f, who);
    assert_eq!(markers(f)[0].state, ClaimMarkerState::InFlight);
    upgrade(f);
    let _ = f.pic.await_call(msg);
    assert_eq!(markers(f)[0].state, ClaimMarkerState::Stuck);
    let blocked: Result<Nat, String> = decode("claim",
        f.pic.update_call(f.vesting, who, "claim", candid::encode_args(()).unwrap()));
    assert!(blocked.unwrap_err().contains("TransferOutcomeUnknown"));
    baseline
}

fn reconcile(f: &Fleet, who: Principal, d: ClaimDecision) -> Result<(), String> {
    decode("reconcile_claim",
        f.pic.update_call(f.vesting, f.controller, "reconcile_claim",
            candid::encode_args((who, d)).unwrap()))
}

#[test]
fn end_to_end_reconcile_executed_clears_the_marker_and_leaves_claimed_settled() {
    let who = p(0x11);
    let total = 5 * STSH;
    let f = deploy(who, total);
    let baseline = stage_stuck(&f, who);

    let pending = markers(&f)[0].pending_amount.expect("stuck marker records its amount");
    let claimed_before = schedule(&f, who).claimed;
    assert_eq!(claimed_before, total, "claimed was pre-incremented before the await");

    reconcile(&f, who, ClaimDecision::Executed).expect("reconcile must succeed");

    // Marker CLEARED — observed through the new surface, not inferred.
    assert!(markers(&f).is_empty(), "an Executed reconcile must clear the marker");
    // Executed: `claimed` stays settled.
    assert_eq!(schedule(&f, who).claimed, claimed_before, "Executed must leave claimed unchanged");
    assert_eq!(pending, total);
    // The transfer really did land, so the beneficiary holds the tokens.
    assert_eq!(balance(&f, who) - baseline, total);
}

#[test]
fn end_to_end_reconcile_not_executed_clears_the_marker_and_reverts_claimed_by_pending_amount() {
    let who = p(0x11);
    let total = 5 * STSH;
    let f = deploy(who, total);
    let _baseline = stage_stuck(&f, who);

    let pending = markers(&f)[0].pending_amount.expect("stuck marker records its amount");
    let claimed_before = schedule(&f, who).claimed;

    reconcile(&f, who, ClaimDecision::NotExecuted).expect("reconcile must succeed");

    assert!(markers(&f).is_empty(), "a NotExecuted reconcile must clear the marker");
    // Reverted by EXACTLY the marker's pending_amount — not zeroed, not guessed.
    assert_eq!(
        schedule(&f, who).claimed,
        claimed_before - pending,
        "NotExecuted must revert claimed by exactly the marker's pending_amount"
    );
}
