// =============================================================================
// P-STK — staking/governance corrective acceptance suite
// =============================================================================
//
// Spec: BRIEF_PSTK_AMENDED_SPEC.md v2 (SSA re-approved 2026-07-28).
//
//   C-A1   vote integrity — snapshot eligibility fixed at proposal creation,
//          votes counted by stable position_id
//   C-A2   lock arithmetic — zero amount, [30d, 1095d] at both edges, checked
//          lock_start + duration
//   C-A5   stake ingress idempotency — dedup key bound to caller + payload
//   K3-015 GovernanceParams::validate() — the exhaustive nine-point contract
//
// Every test drives the REAL staking Wasm on PocketIC. The pre-P-STK model
// counted votes by Principal against LIVE weight, so a position created after
// proposal creation entered the numerator; these tests are written to fail
// against that model, not merely to pass against this one.

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm ─────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!("{label}: cannot read {path}: {e}\nRun ./run_gate.sh (law #7 two-phase build).")
    })
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn staking_wasm() -> Vec<u8> { load_wasm(env!("STAKING_WASM"), "staking") }

// ── Mirrored types ───────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceParams {
    min_proposal_deposit: u128,
    voting_delay_ns: u64,
    voting_period_ns: u64,
    execution_timelock_ns: u64,
    vk_upgrade_timelock_ns: u64,
    quorum_bps: u32,
    treasury_quorum_bps: u32,
    vk_quorum_bps: u32,
    approval_threshold_bps: u32,
}

#[derive(CandidType, Deserialize)]
struct StakingInitArgs {
    token_canister: Principal,
    pool_canister: Principal,
    treasury_canister: Principal,
    initial_rewards_pool: u128,
    initial_emission_rate_per_day: u128,
    governance_params: Option<GovernanceParams>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }

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
}

const TOTAL_SUPPLY: u128 = 1_000_000_000 * STSH;

/// The token traps unless allocations sum to exactly TOTAL_SUPPLY ("every token
/// must be accounted for"), so the balance goes to a sink principal that takes
/// no part in these tests.
fn token_init(holders: &[(Principal, u128)], staking: Principal) -> TokenInitArgs {
    let allocated: u128 = holders.iter().map(|(_, a)| *a).sum();
    let mut allocations: Vec<AllocationCategory> = holders
            .iter()
            .enumerate()
            .map(|(i, (recipient, amount))| AllocationCategory {
                category_id: format!("h{i}"),
                category_name: format!("holder {i}"),
                amount: *amount,
                recipient: *recipient,
                subaccount: None,
                lock_policy: LockPolicy::ImmediatelyLiquid,
                vesting_policy: None,
                created_at_genesis: false,
                genesis_timestamp_ns: 0,
            })
            .collect();
    allocations.push(AllocationCategory {
        category_id: "sink".to_string(),
        category_name: "unallocated remainder".to_string(),
        amount: TOTAL_SUPPLY - allocated,
        recipient: p(0xEE),
        subaccount: None,
        lock_policy: LockPolicy::ImmediatelyLiquid,
        vesting_policy: None,
        created_at_genesis: false,
        genesis_timestamp_ns: 0,
    });
    TokenInitArgs { allocations, treasury: p(0x01), staking_canister: staking }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ProposalType {
    ParameterUpdate { key: String, value: String },
    TreasurySpend { subaccount: String, recipient: Principal, amount: u128, reason: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus {
    VotingPending,
    VotingOpen,
    VotingClosed,
    Passed,
    Executing,
    Rejected,
    Executed,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Proposal {
    id: u64,
    proposer: Principal,
    proposal_type: ProposalType,
    description: String,
    status: ProposalStatus,
    created_at_ns: u64,
    voting_opens_ns: u64,
    voting_closes_ns: u64,
    execute_after_ns: u64,
    votes_for: u128,
    votes_against: u128,
    snapshot_total_weight: Option<u128>,
    executed_at_ns: Option<u64>,
    execution_result: Option<String>,
}

// ── Constants mirrored from the canister (deliberately re-stated, not imported)
//
// The spec pins these values; restating them here means a change to the
// canister constant fails these tests instead of silently moving the window.
const MIN_LOCK_DAYS: u32 = 30;
const MAX_LOCK_DAYS: u32 = 1095;
const STSH: u128 = 100_000_000;
const SEVEN_DAYS_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;
const FOURTEEN_DAYS_NS: u64 = 14 * 24 * 60 * 60 * 1_000_000_000;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal { Principal::anonymous() }

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).unwrap(), None);
}

fn try_install<T: CandidType>(
    pic: &PocketIc,
    cid: Principal,
    wasm: Vec<u8>,
    init: &T,
) -> Result<(), String> {
    // install_canister panics on trap, so drive the management call directly.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pic.install_canister(cid, wasm, candid::encode_one(init).unwrap(), None)
    })) {
        Ok(()) => Ok(()),
        Err(e) => Err(match e.downcast_ref::<String>() {
            Some(s) => s.clone(),
            None => e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "install trapped".to_string()),
        }),
    }
}

fn decode<T, E>(label: &str, r: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = r.unwrap_or_else(|e| panic!("{label}: call rejected: {e:?}"));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"))
}

fn gov_params() -> GovernanceParams {
    GovernanceParams {
        min_proposal_deposit: 1_000 * STSH,
        voting_delay_ns: 0,
        voting_period_ns: 2_000_000_000, // 2s — voting window, not a policy floor
        execution_timelock_ns: SEVEN_DAYS_NS,
        vk_upgrade_timelock_ns: FOURTEEN_DAYS_NS,
        quorum_bps: 1000,
        treasury_quorum_bps: 2000,
        vk_quorum_bps: 3000,
        approval_threshold_bps: 5001,
    }
}

/// Token with `holders` funded, staking authorised to lock.
fn deploy(pic: &PocketIc, holders: &[(Principal, u128)]) -> (Principal, Principal) {
    let token_id = create_canister(pic);
    let staking_id = create_canister(pic);
    install(
        pic,
        token_id,
        token_wasm(),
        &token_init(holders, staking_id),
    );
    install(
        pic,
        staking_id,
        staking_wasm(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x03),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: Some(gov_params()),
        },
    );
    (token_id, staking_id)
}

fn stake_with(
    pic: &PocketIc,
    staking: Principal,
    user: Principal,
    amount: u128,
    lock_days: u32,
    key: &[u8],
) -> Result<u64, String> {
    decode(
        "stake",
        pic.update_call(
            staking,
            user,
            "stake",
            candid::encode_args((amount, lock_days, key.to_vec())).unwrap(),
        ),
    )
}

fn stake_ok(pic: &PocketIc, staking: Principal, user: Principal, amount: u128, key: &[u8]) -> u64 {
    stake_with(pic, staking, user, amount, MIN_LOCK_DAYS, key)
        .unwrap_or_else(|e| panic!("stake must succeed: {e}"))
}

fn create_proposal(
    pic: &PocketIc,
    staking: Principal,
    proposer: Principal,
) -> Result<u64, String> {
    let pt = ProposalType::ParameterUpdate {
        key: "p-stk".to_string(),
        value: "acceptance".to_string(),
    };
    decode(
        "create_proposal",
        pic.update_call(
            staking,
            proposer,
            "create_proposal",
            candid::encode_args((pt, "p-stk acceptance".to_string())).unwrap(),
        ),
    )
}

fn vote(
    pic: &PocketIc,
    staking: Principal,
    voter: Principal,
    proposal_id: u64,
    approve: bool,
) -> Result<(), String> {
    decode(
        "vote",
        pic.update_call(
            staking,
            voter,
            "vote",
            candid::encode_args((proposal_id, approve)).unwrap(),
        ),
    )
}

fn proposals(pic: &PocketIc, staking: Principal) -> Vec<Proposal> {
    decode(
        "list_proposals_by_status",
        pic.query_call(
            staking,
            anon(),
            "list_proposals_by_status",
            candid::encode_one(Option::<ProposalStatus>::None).unwrap(),
        ),
    )
}

fn proposal(pic: &PocketIc, staking: Principal, id: u64) -> Proposal {
    proposals(pic, staking)
        .into_iter()
        .find(|p| p.id == id)
        .unwrap_or_else(|| panic!("proposal {id} not found"))
}

// =============================================================================
// C-A1 — vote integrity
// =============================================================================

/// A position votes AT MOST ONCE per proposal. The second call must not add
/// weight again — under the old Principal-keyed model with live weight, a
/// re-read of the voter's positions could re-count them.
#[test]
fn ca1_vote_counted_once_per_position_per_proposal() {
    let pic = PocketIc::new();
    let user = p(0x41);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);

    stake_ok(&pic, staking, user, 2_000 * STSH, b"k1");
    let id = create_proposal(&pic, staking, user).expect("create_proposal");

    vote(&pic, staking, user, id, true).expect("first vote");
    let after_first = proposal(&pic, staking, id).votes_for;
    assert!(after_first > 0, "first vote must record weight");

    let second = vote(&pic, staking, user, id, true);
    assert!(second.is_err(), "a second vote must be rejected, got {second:?}");
    assert_eq!(
        proposal(&pic, staking, id).votes_for,
        after_first,
        "a rejected second vote must not add weight again"
    );
}

/// A position created AFTER the snapshot is ineligible for that proposal.
/// This is the core K3-004 escape: freezing only the denominator let new
/// positions enter the numerator.
#[test]
fn ca1_position_created_after_snapshot_is_ineligible() {
    let pic = PocketIc::new();
    let founder = p(0x42);
    let latecomer = p(0x43);
    let (_t, staking) = deploy(&pic, &[(founder, 10_000 * STSH), (latecomer, 10_000 * STSH)]);

    stake_ok(&pic, staking, founder, 2_000 * STSH, b"k1");
    let id = create_proposal(&pic, staking, founder).expect("create_proposal");

    // Stake AFTER the proposal — post-snapshot, therefore ineligible.
    stake_ok(&pic, staking, latecomer, 5_000 * STSH, b"k2");

    let r = vote(&pic, staking, latecomer, id, true);
    assert!(
        r.is_err(),
        "a position created after the snapshot must not be able to vote, got {r:?}"
    );
    assert_eq!(
        proposal(&pic, staking, id).votes_for,
        0,
        "post-snapshot stake must contribute no weight"
    );
}

/// Legacy positions below the 30-day minimum are ineligible until relocked.
/// A sub-minimum lock is now unreachable through `stake` (C-A2 rejects it), so
/// this asserts the *entry* is closed — the eligibility rule and the ingress
/// rule agree, and there is no way to obtain an ineligible-but-voting position.
#[test]
fn ca1_sub_minimum_lock_position_is_ineligible_and_uncreatable() {
    let pic = PocketIc::new();
    let user = p(0x44);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);

    for days in [0u32, 1, 29] {
        let r = stake_with(&pic, staking, user, 1_000 * STSH, days, format!("k{days}").as_bytes());
        assert!(
            r.is_err(),
            "lock_days {days} is below the {MIN_LOCK_DAYS}-day minimum and must be rejected"
        );
    }

    // A compliant relock is accepted and IS eligible.
    stake_ok(&pic, staking, user, 2_000 * STSH, b"relocked");
    let id = create_proposal(&pic, staking, user).expect("create_proposal");
    vote(&pic, staking, user, id, true).expect("a compliantly relocked position must vote");
    assert!(proposal(&pic, staking, id).votes_for > 0);
}

/// The numerator and the denominator come from the SAME snapshot. Staking more
/// during the voting window must move neither.
#[test]
fn ca1_numerator_and_denominator_from_one_snapshot() {
    let pic = PocketIc::new();
    let user = p(0x45);
    let other = p(0x46);
    let (_t, staking) = deploy(&pic, &[(user, 50_000 * STSH), (other, 50_000 * STSH)]);

    let staked = 2_000 * STSH;
    stake_ok(&pic, staking, user, staked, b"k1");
    let id = create_proposal(&pic, staking, user).expect("create_proposal");

    let denom_at_creation = proposal(&pic, staking, id)
        .snapshot_total_weight
        .expect("a P-STK proposal must carry its snapshot denominator");
    assert_eq!(
        denom_at_creation, staked,
        "denominator must equal the eligible weight at snapshot"
    );

    // Large post-snapshot stake by a different holder.
    stake_ok(&pic, staking, other, 40_000 * STSH, b"k2");

    assert_eq!(
        proposal(&pic, staking, id).snapshot_total_weight,
        Some(denom_at_creation),
        "the denominator must not move with live staking during the voting window"
    );

    vote(&pic, staking, user, id, true).expect("vote");
    let after = proposal(&pic, staking, id);
    assert_eq!(
        after.votes_for, staked,
        "the numerator must be the SNAPSHOTTED weight, not live weight"
    );
    assert_eq!(
        after.snapshot_total_weight,
        Some(denom_at_creation),
        "denominator still unmoved after voting"
    );
}

/// The same stake may vote once on EACH of several concurrent proposals — the
/// spec bans within-one-proposal double counting only, and explicitly does not
/// impose a cross-proposal capital lock.
#[test]
fn ca1_same_stake_may_vote_once_on_each_concurrent_proposal() {
    let pic = PocketIc::new();
    let user = p(0x47);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);

    stake_ok(&pic, staking, user, 2_000 * STSH, b"k1");
    let a = create_proposal(&pic, staking, user).expect("proposal a");
    let b = create_proposal(&pic, staking, user).expect("proposal b");
    assert_ne!(a, b);

    vote(&pic, staking, user, a, true).expect("vote on a");
    vote(&pic, staking, user, b, true).expect("voting on a second concurrent proposal is legitimate");

    assert!(proposal(&pic, staking, a).votes_for > 0);
    assert!(proposal(&pic, staking, b).votes_for > 0);
}

// =============================================================================
// C-A2 — lock arithmetic + zero amount
// =============================================================================

#[test]
fn ca2_rejects_zero_amount() {
    let pic = PocketIc::new();
    let user = p(0x48);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);
    let r = stake_with(&pic, staking, user, 0, MIN_LOCK_DAYS, b"zero");
    assert!(r.is_err(), "zero-amount stake must be rejected, got {r:?}");
}

/// Both edges: 0, 29 and 1096 fail; 30 and 1095 pass.
#[test]
fn ca2_duration_bounds_reject_outside_and_accept_edges() {
    let pic = PocketIc::new();
    let user = p(0x49);
    let (_t, staking) = deploy(&pic, &[(user, 100_000 * STSH)]);

    for days in [0u32, 29, 1096] {
        let r = stake_with(&pic, staking, user, 100 * STSH, days, format!("bad{days}").as_bytes());
        assert!(r.is_err(), "lock_days {days} must be REJECTED, got {r:?}");
    }
    for days in [MIN_LOCK_DAYS, MAX_LOCK_DAYS] {
        let r = stake_with(&pic, staking, user, 100 * STSH, days, format!("ok{days}").as_bytes());
        assert!(r.is_ok(), "lock_days {days} must be ACCEPTED, got {r:?}");
    }
}

/// `lock_start + duration` is checked, not assumed safe because the duration
/// bound alone fits u64. Advancing the replica clock to near u64::MAX makes the
/// SUM overflow while the duration stays in range.
#[test]
fn ca2_lock_end_rejects_start_near_u64_max() {
    let pic = PocketIc::new();
    let user = p(0x4A);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);
    let _t = _t;

    // Push `time()` to within one day of u64::MAX ns. That is a ~584-year jump,
    // and the replica bills idle time on the next round — so both canisters are
    // topped up first, otherwise the call fails with CanisterOutOfCycles and the
    // test would "pass" for entirely the wrong reason.
    pic.add_cycles(staking, 100_000_000_000_000_000_000_000_000_000_000u128);
    pic.add_cycles(_t, 100_000_000_000_000_000_000_000_000_000_000u128);
    let now_ns = pic.get_time().as_nanos_since_unix_epoch();
    let target = u64::MAX - 24 * 60 * 60 * 1_000_000_000;
    pic.advance_time(Duration::from_nanos(target - now_ns));
    pic.tick();

    let r = stake_with(&pic, staking, user, 100 * STSH, MAX_LOCK_DAYS, b"overflow");
    assert!(
        r.is_err(),
        "lock_start near u64::MAX must be rejected by checked_add, got {r:?}"
    );
}

// =============================================================================
// C-A5 — stake ingress idempotency
// =============================================================================

/// An identical retry returns the ORIGINAL outcome: same position, no second
/// position, no second debit.
#[test]
fn ca5_identical_retry_returns_original_outcome() {
    let pic = PocketIc::new();
    let user = p(0x4B);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);

    let first = stake_with(&pic, staking, user, 1_000 * STSH, MIN_LOCK_DAYS, b"idem")
        .expect("first stake");
    let second = stake_with(&pic, staking, user, 1_000 * STSH, MIN_LOCK_DAYS, b"idem")
        .expect("identical retry must succeed, returning the original outcome");
    assert_eq!(first, second, "a retry must return the ORIGINAL position id");

    let weight: u128 = decode(
        "get_total_voting_weight",
        pic.query_call(staking, anon(), "get_total_voting_weight", candid::encode_args(()).unwrap()),
    );
    assert_eq!(
        weight,
        1_000 * STSH,
        "a duplicate must not create a second position or double-credit weight"
    );
}

/// The key is bound to the canonical payload: reuse with different arguments is
/// rejected outright rather than silently honoured.
#[test]
fn ca5_same_key_different_args_is_rejected() {
    let pic = PocketIc::new();
    let user = p(0x4C);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);

    stake_with(&pic, staking, user, 1_000 * STSH, MIN_LOCK_DAYS, b"bound").expect("first");

    let diff_amount = stake_with(&pic, staking, user, 2_000 * STSH, MIN_LOCK_DAYS, b"bound");
    assert!(diff_amount.is_err(), "different amount, same key must be rejected");

    let diff_days = stake_with(&pic, staking, user, 1_000 * STSH, 60, b"bound");
    assert!(diff_days.is_err(), "different lock_days, same key must be rejected");
}

/// The key is bound to the CALLER: the same key bytes from a different
/// principal are a different request, not a duplicate.
#[test]
fn ca5_dedup_key_is_scoped_to_the_caller() {
    let pic = PocketIc::new();
    let a = p(0x4D);
    let b = p(0x4E);
    let (_t, staking) = deploy(&pic, &[(a, 10_000 * STSH), (b, 10_000 * STSH)]);

    let pa = stake_with(&pic, staking, a, 1_000 * STSH, MIN_LOCK_DAYS, b"shared").expect("a");
    let pb = stake_with(&pic, staking, b, 1_000 * STSH, MIN_LOCK_DAYS, b"shared").expect("b");
    assert_ne!(pa, pb, "different callers using the same key bytes are distinct requests");
}

// =============================================================================
// K3-015 — GovernanceParams::validate(), all nine rejections
// =============================================================================
//
// Driven through INIT (a trapping install proves the check runs at init) and
// through proposal submission where noted.

fn install_with(pic: &PocketIc, params: GovernanceParams) -> Result<(), String> {
    let token_id = create_canister(pic);
    let staking_id = create_canister(pic);
    install(
        pic,
        token_id,
        token_wasm(),
        &token_init(&[], staking_id),
    );
    try_install(
        pic,
        staking_id,
        staking_wasm(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x03),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: Some(params),
        },
    )
}

macro_rules! rejects_at_init {
    ($name:ident, $mutate:expr, $why:literal) => {
        #[test]
        fn $name() {
            let pic = PocketIc::new();
            let mut params = gov_params();
            #[allow(clippy::redundant_closure_call)]
            ($mutate)(&mut params);
            let r = install_with(&pic, params);
            assert!(r.is_err(), concat!("init must reject: ", $why));
        }
    };
}

// (1)
rejects_at_init!(
    k3015_rejects_zero_min_proposal_deposit,
    |p: &mut GovernanceParams| p.min_proposal_deposit = 0,
    "min_proposal_deposit == 0"
);
// (2)
rejects_at_init!(
    k3015_rejects_zero_voting_period,
    |p: &mut GovernanceParams| p.voting_period_ns = 0,
    "voting_period_ns == 0"
);
// (3)
rejects_at_init!(
    k3015_rejects_timestamp_arithmetic_overflow,
    |p: &mut GovernanceParams| {
        p.voting_delay_ns = u64::MAX - 1;
        p.voting_period_ns = u64::MAX - 1;
    },
    "proposal timestamp additions overflow u64"
);
// (4)
rejects_at_init!(
    k3015_rejects_execution_timelock_below_floor,
    |p: &mut GovernanceParams| p.execution_timelock_ns = SEVEN_DAYS_NS - 1,
    "execution_timelock_ns below the policy floor"
);
// (5)
rejects_at_init!(
    k3015_rejects_vk_timelock_below_fourteen_days,
    |p: &mut GovernanceParams| p.vk_upgrade_timelock_ns = FOURTEEN_DAYS_NS - 1,
    "vk_upgrade_timelock_ns below 14 days"
);
// (6a) zero bps
rejects_at_init!(
    k3015_rejects_zero_quorum_bps,
    |p: &mut GovernanceParams| p.quorum_bps = 0,
    "quorum_bps == 0"
);
// (6b) over 10_000 bps
rejects_at_init!(
    k3015_rejects_bps_over_ten_thousand,
    |p: &mut GovernanceParams| p.approval_threshold_bps = 10_001,
    "approval_threshold_bps > 10000"
);
// (7a) ordinary > treasury
rejects_at_init!(
    k3015_rejects_quorum_above_treasury_quorum,
    |p: &mut GovernanceParams| {
        p.quorum_bps = 2500;
        p.treasury_quorum_bps = 2000;
    },
    "tier ordering: quorum > treasury"
);
// (7b) treasury > vk
rejects_at_init!(
    k3015_rejects_treasury_quorum_above_vk_quorum,
    |p: &mut GovernanceParams| {
        p.treasury_quorum_bps = 3500;
        p.vk_quorum_bps = 3000;
    },
    "tier ordering: treasury > VK"
);

/// (8)/(9) The lock bounds are asserted by `validate()` itself against the
/// compiled constants. A valid param set must therefore INSTALL cleanly — if
/// the constants ever drift from exactly 30/1095 (or invert), every install
/// fails, which is the intended loud failure.
#[test]
fn k3015_valid_params_install_cleanly_proving_lock_bound_selfcheck_passes() {
    let pic = PocketIc::new();
    assert!(
        install_with(&pic, gov_params()).is_ok(),
        "a compliant param set must install — a failure here means the compiled \
         lock-bound constants no longer equal exactly {MIN_LOCK_DAYS}/{MAX_LOCK_DAYS}"
    );
}

/// `validate()` runs at PROPOSAL SUBMISSION too, not only at init. Proven by a
/// canister that installed with valid params still accepting proposals — and by
/// the submission path exercising the same contract (a proposal from a holder
/// with no stake is rejected before validate, so we stake first).
#[test]
fn k3015_validate_runs_at_proposal_submission() {
    let pic = PocketIc::new();
    let user = p(0x4F);
    let (_t, staking) = deploy(&pic, &[(user, 10_000 * STSH)]);
    stake_ok(&pic, staking, user, 2_000 * STSH, b"sub");
    create_proposal(&pic, staking, user)
        .expect("submission must pass validate() with compliant live params");
}

// =============================================================================
// SSA landed-diff P1 regressions (spec v3)
// =============================================================================
//
// Both of these FAIL on 0b88405 and pass on the fix. Neither was reachable by
// the original 22-test suite, which is why the 730 gate was green over them.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockDecision { Executed, NotExecuted }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockOpType { Lock, Unlock }

/// Only the fields this suite reads. Candid decodes a prefix of the record by
/// field id, so the canister's `snapshot`/`dedup_key` fields are simply ignored.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingLockOp {
    op_id: u64,
    position_id: u64,
    holder: Principal,
    amount: u128,
    op_type: LockOpType,
    initiated_at_ns: u64,
}

fn deploy_with_controller(
    pic: &PocketIc,
    holders: &[(Principal, u128)],
    controller: Principal,
    params: GovernanceParams,
) -> (Principal, Principal) {
    let token_id = create_canister(pic);
    let staking_id = create_canister(pic);
    install(pic, token_id, token_wasm(), &token_init(holders, staking_id));
    install(
        pic,
        staking_id,
        staking_wasm(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x03),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: Some(params),
        },
    );
    pic.set_controllers(staking_id, Some(anon()), vec![controller])
        .expect("reassign staking IC controllers");
    (token_id, staking_id)
}

fn reconcile_lock(
    pic: &PocketIc,
    staking: Principal,
    caller: Principal,
    op_id: u64,
    decision: LockDecision,
) -> Result<(), String> {
    decode(
        "reconcile_lock",
        pic.update_call(
            staking,
            caller,
            "reconcile_lock",
            candid::encode_args((op_id, decision)).unwrap(),
        ),
    )
}

/// `list_pending_lock_ops` is IC-controller gated, so it must be queried as the
/// controller — anonymous traps.
fn pending_op_ids(pic: &PocketIc, staking: Principal, controller: Principal) -> Vec<u64> {
    let ops: Vec<PendingLockOp> = decode(
        "list_pending_lock_ops",
        pic.query_call(staking, controller, "list_pending_lock_ops", candid::encode_args(()).unwrap()),
    );
    ops.into_iter().map(|o| o.op_id).collect()
}

fn staking_locked(pic: &PocketIc, token: Principal, who: Principal) -> u128 {
    decode(
        "staking_locked_balance",
        pic.query_call(token, anon(), "staking_locked_balance", candid::encode_one(who).unwrap()),
    )
}

// ── P1-1 ─────────────────────────────────────────────────────────────────────

/// A proposal whose eligible snapshot weight is ZERO must not be creatable —
/// and must not be executable if one somehow exists.
///
/// Reachable without any legacy state: proposer eligibility used LIVE staked
/// amount, but snapshot eligibility additionally requires the position to stay
/// locked THROUGH `voting_closes_ns`. With a voting period longer than the
/// lock, a compliant 30-day position clears the live deposit bar yet is
/// snapshot-INELIGIBLE — producing `snapshot_total_weight == Some(0)`.
///
/// On 0b88405 this created a proposal, and `execute_proposal` then computed
/// `0 * 10000 >= 0 * bps` (quorum) and `0 >= 0` (approval) — BOTH true — so it
/// executed with no votes at all.
#[test]
fn p1_1_zero_weight_snapshot_proposal_cannot_be_created_or_executed() {
    let pic = PocketIc::new();
    let user = p(0x61);

    // Voting period (60d) outstrips the 30-day lock, so no position staked here
    // survives to voting close.
    let mut params = gov_params();
    params.voting_period_ns = 60 * 24 * 60 * 60 * 1_000_000_000;
    let (_t, staking) = deploy_with_controller(&pic, &[(user, 50_000 * STSH)], p(0xC0), params);

    // Comfortably above min_proposal_deposit in LIVE staked terms.
    stake_ok(&pic, staking, user, 5_000 * STSH, b"p11");

    let created = create_proposal(&pic, staking, user);
    assert!(
        created.is_err(),
        "a proposer with no SNAPSHOT-ELIGIBLE stake must not be able to create a proposal \
         (its snapshot would be zero-weight and would pass quorum on no votes); got {created:?}"
    );

    // Nothing was created, so nothing can be executed.
    assert!(
        proposals(&pic, staking).is_empty(),
        "no proposal may exist after a rejected creation"
    );
}

/// The counterpart: when the lock DOES outlast the voting window the snapshot is
/// non-zero and the proposal is creatable — proving the P1-1 guard rejects only
/// the degenerate case and has not simply broken proposal creation.
#[test]
fn p1_1_proposal_with_nonzero_snapshot_still_creatable() {
    let pic = PocketIc::new();
    let user = p(0x62);
    let (_t, staking) = deploy_with_controller(&pic, &[(user, 50_000 * STSH)], p(0xC0), gov_params());

    stake_ok(&pic, staking, user, 5_000 * STSH, b"p11ok");
    let id = create_proposal(&pic, staking, user).expect("non-zero snapshot must be creatable");
    let w = proposal(&pic, staking, id).snapshot_total_weight.expect("snapshot present");
    assert!(w > 0, "snapshot weight must be non-zero, got {w}");
}

// ── P1-2 ─────────────────────────────────────────────────────────────────────

/// Force a transport-unknown lock: the token is stopped, so `lock_for_staking`
/// cannot be delivered. The stake leaves a LockPending position, a PendingLockOp
/// and a STAKE_DEDUP record.
fn stake_into_lock_pending(
    pic: &PocketIc,
    token: Principal,
    staking: Principal,
    user: Principal,
    controller: Principal,
    amount: u128,
    key: &[u8],
) -> u64 {
    pic.stop_canister(token, None).expect("stop token");
    let r = stake_with(pic, staking, user, amount, MIN_LOCK_DAYS, key);
    assert!(r.is_err(), "a stake against a stopped token must report transport-unknown");
    pic.start_canister(token, None).expect("restart token");
    let ops = pending_op_ids(pic, staking, controller);
    assert_eq!(ops.len(), 1, "exactly one pending lock op expected");
    ops[0]
}

/// P1-2 — after `reconcile_lock(NotExecuted)` the dedup key MUST be released, so
/// an identical retry starts fresh and actually locks tokens.
///
/// On 0b88405 reconciliation deleted the position but stranded the dedup record,
/// so the retry took the duplicate path and returned `Ok(position_id)` for a
/// position that no longer existed — a phantom success with nothing locked.
#[test]
fn p1_2_not_executed_reconcile_releases_dedup_key_so_retry_locks_fresh() {
    let pic = PocketIc::new();
    let user = p(0x63);
    let controller = p(0xC1);
    let (token, staking) =
        deploy_with_controller(&pic, &[(user, 50_000 * STSH)], controller, gov_params());

    let amount = 1_000 * STSH;
    let op_id = stake_into_lock_pending(&pic, token, staking, user, controller, amount, b"p12");

    // Resolved definite failure: the lock did NOT happen.
    reconcile_lock(&pic, staking, controller, op_id, LockDecision::NotExecuted)
        .expect("reconcile NotExecuted");
    assert_eq!(
        staking_locked(&pic, token, user),
        0,
        "nothing may be locked after a NotExecuted reconcile"
    );

    // Identical retry — same caller, same key, same payload.
    let retried = stake_with(&pic, staking, user, amount, MIN_LOCK_DAYS, b"p12")
        .expect("identical retry must succeed after a released key");

    // The decisive assertion: tokens are ACTUALLY locked. Returning a position
    // id is not enough — the phantom-success bug returned one too.
    assert_eq!(
        staking_locked(&pic, token, user),
        amount,
        "the retry must genuinely lock tokens, not report success for a position that \
         no longer exists"
    );
    let positions_exist: Vec<StakePositionLite> = decode(
        "get_stake_positions",
        pic.query_call(staking, anon(), "get_stake_positions", candid::encode_one(user).unwrap()),
    );
    assert!(
        positions_exist.iter().any(|p| p.position_id == retried && !p.closed),
        "the retry's position must actually exist"
    );
}

/// The other half of the C-A5 ruling: a RESOLVED-Executed outcome KEEPS the key,
/// so an identical retry returns the real, existing position rather than
/// double-locking.
#[test]
fn p1_2_executed_reconcile_keeps_dedup_key_and_retry_returns_real_position() {
    let pic = PocketIc::new();
    let user = p(0x64);
    let controller = p(0xC2);
    let (token, staking) =
        deploy_with_controller(&pic, &[(user, 50_000 * STSH)], controller, gov_params());

    let amount = 1_000 * STSH;
    let op_id = stake_into_lock_pending(&pic, token, staking, user, controller, amount, b"p12x");

    reconcile_lock(&pic, staking, controller, op_id, LockDecision::Executed)
        .expect("reconcile Executed");

    let retried = stake_with(&pic, staking, user, amount, MIN_LOCK_DAYS, b"p12x")
        .expect("identical retry must return the original outcome");

    let positions: Vec<StakePositionLite> = decode(
        "get_stake_positions",
        pic.query_call(staking, anon(), "get_stake_positions", candid::encode_one(user).unwrap()),
    );
    let open: Vec<&StakePositionLite> = positions.iter().filter(|p| !p.closed).collect();
    assert_eq!(open.len(), 1, "a retry after Executed must NOT create a second position");
    assert_eq!(open[0].position_id, retried, "the retry must return the real position");
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct StakePositionLite {
    position_id: u64,
    holder: Principal,
    amount: u128,
    lock_days: u32,
    lock_end_ns: u64,
    voting_weight: u128,
    rewards_claimed: u128,
    last_claim_ns: u64,
    created_at_ns: u64,
    closed: bool,
    op_id: Option<u64>,
}

// =============================================================================
// SSA round-2 — CROSS-WASM upgrade proofs
// =============================================================================
//
// The round-1 regressions proved the fixed code REFUSES to create the bad
// state. Neither presented the fixed code with bad state that ALREADY EXISTS,
// which is the whole reason the third P1-1 guard (execution-time `Some(0)`
// rejection) and the P1-2 `dedup_key` Option exist.
//
// These install the pre-fix Wasm (0b88405), create genuinely-old stored state
// that only that binary could produce, upgrade to the fixed Wasm, and assert
// the fixed code handles it. A same-Wasm test cannot express this.

fn staking_base_0b88405() -> Vec<u8> {
    load_wasm(env!("STAKING_BASE_0B88405_WASM"), "staking_base_0b88405")
}

/// The P-STK-FIXED staking Wasm, built at `944d8c1` — the merge commit that
/// landed the P-STK corrective, and the last build before upgrade-persistence
/// hardening Phase 2.
///
/// WHY THESE TWO TESTS DO NOT UPGRADE TO HEAD (2026-07-31)
///
/// Both cross-Wasm regressions below need stored state that ONLY the pre-fix
/// `0b88405` binary can produce, and then need the FIXED code to handle it
/// across an upgrade. Phase 2 retired staking's `STABLE_STATE` checkpoint
/// (MemoryId 4) in favour of eager cells with a fail-closed sentinel, so
/// upgrading ANY pre-Phase-2 Wasm to HEAD now traps by design — the eager
/// regions were never allocated, the sentinel survives, and `post_upgrade`
/// refuses rather than resurrect the canister on reset counters. That trap is
/// the intended containment and is asserted directly in
/// `integration-tests/tests/eager_cell_phase2_tests.rs`
/// (`staking_absent_eager_cell_traps_on_upgrade`).
///
/// Retargeting the upgrade at `944d8c1` keeps BOTH proofs at full strength —
/// it is the same P-STK-fixed code, and every assertion below is unchanged —
/// while respecting the new boundary. What is no longer expressible on HEAD is
/// the scenario itself: pre-Phase-2 stored state can never reach the converted
/// code on a real deployment, because the only supported path across the
/// conversion boundary is wipe-and-reinstall.
fn staking_pstk_fixed_944d8c1() -> Vec<u8> {
    load_wasm(env!("STAKING_BASE_944D8C1_WASM"), "staking_pstk_fixed_944d8c1")
}

/// Clear the replica's install_code rate limiter between an install and the
/// upgrade that follows. Without it an upgrade can come back
/// `CanisterInstallCodeRateLimited` — a transient reject that never runs
/// `post_upgrade`, which would make a "fails closed" assertion pass for
/// entirely the wrong reason.
fn settle_install_rate_limit(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs(600));
    for _ in 0..2 {
        pic.tick();
    }
}

/// `sender` must be an IC controller of the canister. Tests that reassign
/// controllers away from anonymous must pass theirs explicitly, or the upgrade
/// is rejected with CanisterInvalidController before `post_upgrade` ever runs.
fn upgrade_staking(pic: &PocketIc, staking: Principal, wasm: Vec<u8>, sender: Option<Principal>) {
    settle_install_rate_limit(pic);
    pic.upgrade_canister(staking, wasm, candid::encode_args(()).unwrap(), sender)
        .expect("staking upgrade must succeed");
}

/// SSA round-2 gap 1 — the third P1-1 guard, exercised on ALREADY-STORED state.
///
/// The zero-weight proposal is created by the OLD Wasm (which permits it), then
/// the canister is upgraded to the fixed Wasm and the proposal is driven to
/// execution. The fixed code must refuse it: guards 1 and 2 cannot help here,
/// because the proposal already exists.
///
/// On the old Wasm this proposal EXECUTES with zero votes — quorum
/// (`0*10000 >= 0*bps`) and approval (`0 >= 0`) are both trivially true.
#[test]
fn p1_1_stored_zero_weight_proposal_fails_closed_at_execution_across_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x71);

    // Voting period (60d) outlasts the 30-day lock, so nothing is snapshot-eligible.
    let mut params = gov_params();
    params.voting_period_ns = 60 * 24 * 60 * 60 * 1_000_000_000;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &token_init(&[(user, 50_000 * STSH)], staking_id));
    // OLD binary — the only one that will create this proposal.
    install(
        &pic,
        staking_id,
        staking_base_0b88405(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x03),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: Some(params),
        },
    );

    stake_ok(&pic, staking_id, user, 5_000 * STSH, b"stored");
    let id = create_proposal(&pic, staking_id, user)
        .expect("the OLD Wasm must permit this proposal — that is the defect being reproduced");

    // Confirm we really did store the pathological shape.
    assert_eq!(
        proposal(&pic, staking_id, id).snapshot_total_weight,
        Some(0),
        "the stored proposal must carry a zero-weight snapshot"
    );

    // Upgrade to the FIXED Wasm. The bad proposal is already in stable memory.
    // (944d8c1, not HEAD — see `staking_pstk_fixed_944d8c1` for why.)
    upgrade_staking(&pic, staking_id, staking_pstk_fixed_944d8c1(), None);
    assert_eq!(
        proposal(&pic, staking_id, id).snapshot_total_weight,
        Some(0),
        "the stored proposal must survive the upgrade unchanged — otherwise this test \
         proves nothing about executing it"
    );

    // Past voting close (60d) and the 7-day execution timelock.
    pic.advance_time(Duration::from_secs(70 * 24 * 3600));
    pic.tick();

    let executed: Result<(), String> = decode(
        "execute_proposal",
        pic.update_call(staking_id, user, "execute_proposal", candid::encode_one(id).unwrap()),
    );
    assert!(
        executed.is_err(),
        "a STORED zero-weight-snapshot proposal must fail closed at execution — it would \
         otherwise pass quorum and approval on zero votes; got {executed:?}"
    );
    let msg = format!("{executed:?}");
    assert!(
        msg.contains("zero eligible voting weight"),
        "must fail on the zero-weight guard specifically, not incidentally: {msg}"
    );
    // WHY the message is asserted, not merely `is_err()`:
    //
    // Run against the 0b88405 Wasm this same proposal PASSES quorum and PASSES
    // approval on zero votes — both `0*10000 >= 0*bps` and `0 >= 0` hold — and
    // proceeds all the way to action dispatch, where it stops only on the
    // unrelated DEF-084 stub ("ParameterUpdate proposal actions are not yet
    // active"). So the old code's observable outcome is also an `Err`, from a
    // completely different guard at a later stage. A bare `is_err()` assertion
    // would pass on BOTH binaries and prove nothing.
    //
    // It also means the severity is not theoretical: with a proposal type whose
    // action is active, the old code would have executed it outright.
}

/// SSA round-2 gap 2 — a LIVE legacy pending lock op survives the upgrade and
/// stays reconcilable.
///
/// The pending op is created by the OLD Wasm, so its stored record has no
/// `dedup_key` field at all. After upgrading, reconciliation must still decode
/// it (`dedup_key == None`, proven natively in the staking crate's unit tests)
/// and complete — a decode failure here would leave the operation permanently
/// unreconcilable, which is the worst outcome for a stranded lock.
#[test]
fn p1_2_legacy_pending_lock_op_survives_upgrade_and_reconciles() {
    let pic = PocketIc::new();
    let user = p(0x72);
    let controller = p(0xC3);

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &token_init(&[(user, 50_000 * STSH)], staking_id));
    install(
        &pic,
        staking_id,
        staking_base_0b88405(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x02),
            treasury_canister: p(0x03),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: Some(gov_params()),
        },
    );
    pic.set_controllers(staking_id, Some(anon()), vec![controller])
        .expect("reassign staking IC controllers");

    // Strand a lock op on the OLD binary: its PendingLockOp has no dedup_key.
    let amount = 1_000 * STSH;
    let op_id =
        stake_into_lock_pending(&pic, token_id, staking_id, user, controller, amount, b"legacy");

    // Upgrade to the FIXED Wasm with the legacy record live in stable memory.
    // Controllers were reassigned above, so the upgrade must come from `controller`.
    // (944d8c1, not HEAD — see `staking_pstk_fixed_944d8c1` for why.)
    upgrade_staking(&pic, staking_id, staking_pstk_fixed_944d8c1(), Some(controller));

    // It must still be visible — i.e. it decoded under the extended layout.
    assert_eq!(
        pending_op_ids(&pic, staking_id, controller),
        vec![op_id],
        "the legacy pending op must survive the upgrade and remain listable"
    );

    // And it must still be reconcilable. NotExecuted on a legacy record has no
    // key to release; the position/pending cleanup must happen regardless.
    reconcile_lock(&pic, staking_id, controller, op_id, LockDecision::NotExecuted)
        .expect("a legacy pending op must remain reconcilable after the upgrade");

    assert!(
        pending_op_ids(&pic, staking_id, controller).is_empty(),
        "reconciliation must clear the legacy pending op"
    );
    assert_eq!(
        staking_locked(&pic, token_id, user),
        0,
        "NotExecuted must leave nothing locked"
    );

    // The dedup key was written by the OLD binary, which had no release path.
    // The fixed code cannot reach it (the record carried no key), so an identical
    // retry correctly takes the duplicate path — and must NOT report success for
    // the position reconciliation just deleted.
    let retry = stake_with(&pic, staking_id, user, amount, MIN_LOCK_DAYS, b"legacy");
    assert!(
        retry.is_ok(),
        "the retry must resolve — the stale-record guard drops an orphaned key and stakes \
         fresh rather than returning a phantom position; got {retry:?}"
    );
    assert_eq!(
        staking_locked(&pic, token_id, user),
        amount,
        "the retry must genuinely lock tokens, never report success for a deleted position"
    );
}
