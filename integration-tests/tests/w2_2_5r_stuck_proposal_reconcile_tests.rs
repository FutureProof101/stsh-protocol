// =============================================================================
// W2 2-5R — the no-retry property of `reconcile_stuck_proposal`, cross-Wasm
// =============================================================================
//
// WHY THIS CANNOT BE A NATIVE TEST. A proposal is only stuck in `Executing` if
// a continuation DIED after the pre-await write — a trap, or an upgrade across
// the await. Producing that state needs a real canister and a real upgrade, and
// the property under test (`execute_proposal` refuses afterwards) is an async
// entry point. The pure decision core is unit-tested in the staking crate; what
// is proved HERE is the part only a canister boundary can show:
//
//   after a reconcile, the proposal CANNOT execute — and it is the
//   `executed_at_ns.is_some()` guard that stops it.
//
// That guard is the whole of finding R2: an arm that wrote only `status` would
// leave `executed_at_ns == None`, and a later public `execute_proposal` would
// pass BOTH guards and issue the outbound action a SECOND time — breaking the
// no-retry property this endpoint exists to honour.
//
// HOW THE STUCK STATE IS STAGED. `submit_call` enqueues without awaiting; ONE
// `tick()` runs the entry segment and sends the inter-canister call. Token and
// staking sit on one application subnet and the pool on a SECOND one, so the
// reply cannot arrive in the same round and the proposal is deterministically
// parked at its await. A real `upgrade_canister` then kills the continuation.
// No injection hook and no testing feature: this runs the PRODUCTION Wasm.
//
// The two-subnet requirement is not cosmetic. On a single subnet the induced
// message is delivered in the SAME round, the whole call tree completes, and
// nothing is ever parked — a test written that way silently proves nothing.

use candid::{CandidType, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const STSH: u128 = 100_000_000;
const TOTAL_SUPPLY: u128 = 1_000_000_000 * STSH;
const MIN_LOCK_DAYS: u32 = 30;
const SEVEN_DAYS_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;
const FOURTEEN_DAYS_NS: u64 = 14 * 24 * 60 * 60 * 1_000_000_000;
/// The ratified threshold (CTO 2026-08-19). Mirrored, not imported: the test
/// must fail if the canister's value drifts from the ruled one.
const THRESHOLD_NS: u64 = 86_400_000_000_000; // 24 h

fn load_wasm(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {label} wasm at {path}: {e}"))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn staking_wasm() -> Vec<u8> { load_wasm(env!("STAKING_WASM"), "staking") }

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
    category_id: String, category_name: String, amount: u128, recipient: Principal,
    subaccount: Option<[u8; 32]>, lock_policy: LockPolicy,
    vesting_policy: Option<VestingPolicy>, created_at_genesis: bool, genesis_timestamp_ns: u64,
}
#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>, treasury: Principal, staking_canister: Principal,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum EmergencyPauseTarget { PoolDeposits, PoolSpends, Both }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ProposalType {
    ParameterUpdate { key: String, value: String },
    EmergencyPause { target: EmergencyPauseTarget, reason: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus {
    VotingPending, VotingOpen, VotingClosed, Passed, Executing,
    Rejected, Executed, Expired, Cancelled,
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
    // W2 2-5R
    execution_started_at_ns: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalReconcileDecision { Executed, NotExecuted }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProposalReconciled { status: ProposalStatus, executed_at_ns: u64 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProposalTerminalReplay { status: ProposalStatus, execution_result: Option<String> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ProposalReconcileResult {
    Reconciled(ProposalReconciled),
    TerminalReplay(ProposalTerminalReplay),
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ProposalReconcileError {
    NotController,
    ProposalNotFound,
    NotStuck { status: ProposalStatus },
    TooYoung { age_ns: u64, threshold_ns: u64 },
    LegacyClockInitialized { observed_at_ns: u64, threshold_ns: u64 },
}

fn p(n: u8) -> Principal { let mut b = [0u8; 29]; b[0] = n; Principal::from_slice(&b) }
fn anon() -> Principal { Principal::anonymous() }

fn decode<T, E>(label: &str, r: Result<Vec<u8>, E>) -> T
where T: CandidType + for<'de> Deserialize<'de>, E: std::fmt::Debug {
    let b = r.unwrap_or_else(|e| panic!("{label}: call rejected/failed: {e:?}"));
    candid::decode_one(&b).unwrap_or_else(|e| panic!("{label}: candid decode failed: {e}"))
}

fn gov_params() -> GovernanceParams {
    GovernanceParams {
        min_proposal_deposit: 1_000 * STSH,
        voting_delay_ns: 0,
        voting_period_ns: 2_000_000_000,
        execution_timelock_ns: SEVEN_DAYS_NS,
        vk_upgrade_timelock_ns: FOURTEEN_DAYS_NS,
        quorum_bps: 1000,
        treasury_quorum_bps: 2000,
        vk_quorum_bps: 3000,
        approval_threshold_bps: 5001,
    }
}

fn token_init(holder: Principal, amount: u128, staking: Principal) -> TokenInitArgs {
    let sink = p(0xEE);
    TokenInitArgs {
        allocations: vec![
            AllocationCategory {
                category_id: "holder".into(), category_name: "Holder".into(), amount,
                recipient: holder, subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid,
                vesting_policy: None, created_at_genesis: false, genesis_timestamp_ns: 0,
            },
            AllocationCategory {
                category_id: "sink".into(), category_name: "Sink".into(),
                amount: TOTAL_SUPPLY - amount,
                recipient: sink, subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid,
                vesting_policy: None, created_at_genesis: false, genesis_timestamp_ns: 0,
            },
        ],
        treasury: p(0x01),
        staking_canister: staking,
    }
}

struct Fleet {
    pic: PocketIc,
    staking: Principal,
    controller: Principal,
    holder: Principal,
}

/// Token + staking on subnet A, the pool on subnet B.
///
/// The pool is a bare canister with no Wasm: the reconcile path never needs it
/// to answer. All that matters is that the outbound call is IN FLIGHT across a
/// round boundary, which the subnet split guarantees; the reply is then thrown
/// away by the upgrade, which is precisely the real-world stranding.
fn deploy() -> Fleet {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let subnets = pic.topology().get_app_subnets();
    assert_eq!(subnets.len(), 2, "the staging technique REQUIRES two application subnets");
    assert_ne!(subnets[0], subnets[1], "the two subnets must be distinct");

    let controller = p(0x10);
    let holder = p(0x11);

    let token = pic.create_canister_on_subnet(Some(controller), None, subnets[0]);
    pic.add_cycles(token, 2_000_000_000_000u128);
    let staking = pic.create_canister_on_subnet(Some(controller), None, subnets[0]);
    pic.add_cycles(staking, 2_000_000_000_000u128);
    let pool = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    pic.add_cycles(pool, 2_000_000_000_000u128);

    assert_ne!(
        pic.get_subnet(staking), pic.get_subnet(pool),
        "staking and pool MUST be on different subnets or nothing ever parks"
    );

    pic.install_canister(
        token, token_wasm(),
        candid::encode_one(&token_init(holder, 10_000 * STSH, staking)).unwrap(),
        Some(controller),
    );
    pic.install_canister(
        staking, staking_wasm(),
        candid::encode_one(&StakingInitArgs {
            token_canister: token,
            pool_canister: pool,
            treasury_canister: p(0x03),
            initial_rewards_pool: 0,
            initial_emission_rate_per_day: 0,
            governance_params: Some(gov_params()),
        }).unwrap(),
        Some(controller),
    );

    Fleet { pic, staking, controller, holder }
}

fn proposal(f: &Fleet, id: u64) -> Proposal {
    let all: Vec<Proposal> = decode(
        "list_proposals_by_status",
        f.pic.query_call(f.staking, anon(), "list_proposals_by_status",
            candid::encode_one(Option::<ProposalStatus>::None).unwrap()),
    );
    all.into_iter().find(|p| p.id == id).expect("proposal must exist")
}

/// Drive a proposal to `Passed`, then park its execution at the pool await and
/// kill the continuation with a real upgrade. Returns the proposal id.
fn stage_stuck_proposal(f: &Fleet) -> u64 {
    let staked: Result<u64, String> = decode(
        "stake",
        f.pic.update_call(f.staking, f.holder, "stake",
            candid::encode_args((5_000 * STSH, MIN_LOCK_DAYS, vec![1u8, 2, 3])).unwrap()),
    );
    staked.expect("stake must succeed");

    let pt = ProposalType::EmergencyPause {
        target: EmergencyPauseTarget::PoolDeposits,
        reason: "2-5R staging".into(),
    };
    let id: Result<u64, String> = decode(
        "create_proposal",
        f.pic.update_call(f.staking, f.holder, "create_proposal",
            candid::encode_args((pt, "2-5R staging".to_string())).unwrap()),
    );
    let id = id.expect("create_proposal must succeed");

    let voted: Result<(), String> = decode(
        "vote",
        f.pic.update_call(f.staking, f.holder, "vote",
            candid::encode_args((id, true)).unwrap()),
    );
    voted.expect("vote must succeed");

    // Past the voting window and the execution timelock.
    f.pic.advance_time(Duration::from_secs(8 * 24 * 3600));
    f.pic.tick();

    // Pay the install_code throttle BEFORE parking: settling it afterwards
    // executes rounds, which would let the parked call finish and silently turn
    // this into a test of nothing.
    f.pic.advance_time(Duration::from_secs(7 * 86_400));
    for _ in 0..5 { f.pic.tick(); }

    let msg = f.pic
        .submit_call(f.staking, f.holder, "execute_proposal", candid::encode_one(id).unwrap())
        .expect("submit_call must be accepted");
    f.pic.tick(); // entry segment runs; the pool call is now in flight

    let parked = proposal(f, id);
    assert_eq!(parked.status, ProposalStatus::Executing, "must be parked mid-execution");
    assert!(
        parked.execution_started_at_ns.is_some(),
        "the start stamp must be written in the same await-free segment as the Executing status"
    );
    assert!(parked.executed_at_ns.is_none(), "executed_at_ns is only written after the await");

    // Kill the continuation. This is the real stranding.
    f.pic.upgrade_canister(f.staking, staking_wasm(), candid::encode_args(()).unwrap(), Some(f.controller))
        .expect("upgrade while parked must succeed");
    let _ = f.pic.await_call(msg); // the continuation is gone; the reply is discarded

    let stuck = proposal(f, id);
    assert_eq!(stuck.status, ProposalStatus::Executing, "the proposal must survive the upgrade STUCK");
    assert!(stuck.executed_at_ns.is_none(), "a stuck proposal has no executed_at_ns — that is the trap");
    assert!(
        stuck.execution_started_at_ns.is_some(),
        "the start stamp must ride the upgrade, or the age can never be computed"
    );
    id
}

fn reconcile(
    f: &Fleet,
    id: u64,
    decision: ProposalReconcileDecision,
    sender: Principal,
) -> Result<ProposalReconcileResult, ProposalReconcileError> {
    decode(
        "reconcile_stuck_proposal",
        f.pic.update_call(f.staking, sender, "reconcile_stuck_proposal",
            candid::encode_args((id, decision)).unwrap()),
    )
}

fn execute_again(f: &Fleet, id: u64) -> Result<(), String> {
    decode(
        "execute_proposal",
        f.pic.update_call(f.staking, f.holder, "execute_proposal", candid::encode_one(id).unwrap()),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// R2 — the no-retry proof, per decision arm
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn reconciled_executed_proposal_cannot_be_executed_again() {
    let f = deploy();
    let id = stage_stuck_proposal(&f);

    f.pic.advance_time(Duration::from_nanos(THRESHOLD_NS));
    f.pic.tick();

    match reconcile(&f, id, ProposalReconcileDecision::Executed, f.controller) {
        Ok(ProposalReconcileResult::Reconciled(r)) => {
            assert_eq!(r.status, ProposalStatus::Executed);
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }

    let after = proposal(&f, id);
    assert_eq!(after.status, ProposalStatus::Executed);
    // The load-bearing write: without it the record passes BOTH guards below.
    assert!(after.executed_at_ns.is_some(), "executed_at_ns MUST be written by the reconcile");
    assert!(
        after.execution_result.as_deref().unwrap_or("").starts_with("RECONCILED:"),
        "provenance must be on the record, got {:?}", after.execution_result
    );

    // THE PROPERTY: it cannot execute, and it is the executed_at_ns guard that
    // fires — not merely the status tag.
    let err = execute_again(&f, id).expect_err("a reconciled proposal must not execute");
    assert!(
        err.contains("Already executed"),
        "the executed_at_ns guard must be the one that fires, got: {err}"
    );

    // And the action was never re-issued: the status/result are unchanged.
    let unchanged = proposal(&f, id);
    assert_eq!(unchanged.executed_at_ns, after.executed_at_ns, "the refused call must not mutate");
    assert_eq!(unchanged.execution_result, after.execution_result);
}

#[test]
fn reconciled_not_executed_proposal_is_terminal_and_cannot_be_retried() {
    let f = deploy();
    let id = stage_stuck_proposal(&f);

    f.pic.advance_time(Duration::from_nanos(THRESHOLD_NS));
    f.pic.tick();

    match reconcile(&f, id, ProposalReconcileDecision::NotExecuted, f.controller) {
        Ok(ProposalReconcileResult::Reconciled(r)) => {
            // Rejected, NOT re-openable: the outbound action may have landed.
            assert_eq!(r.status, ProposalStatus::Rejected);
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }

    let after = proposal(&f, id);
    assert_eq!(after.status, ProposalStatus::Rejected);
    assert!(
        after.executed_at_ns.is_some(),
        "the NotExecuted arm must ALSO write executed_at_ns, or the action can be re-issued"
    );

    let err = execute_again(&f, id).expect_err("a NotExecuted reconcile must not re-open for retry");
    assert!(err.contains("Already executed"), "got: {err}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Gating, age, and terminal replay across the canister boundary
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_non_controller_is_refused_with_a_typed_error_and_mutates_nothing() {
    let f = deploy();
    let id = stage_stuck_proposal(&f);
    f.pic.advance_time(Duration::from_nanos(THRESHOLD_NS));
    f.pic.tick();

    let before = proposal(&f, id);
    match reconcile(&f, id, ProposalReconcileDecision::Executed, p(0x77)) {
        Err(ProposalReconcileError::NotController) => {}
        other => panic!("expected NotController, got {other:?}"),
    }
    let after = proposal(&f, id);
    assert_eq!(after.status, before.status, "a refused call must not mutate status");
    assert_eq!(after.executed_at_ns, before.executed_at_ns);
    assert_eq!(after.execution_started_at_ns, before.execution_started_at_ns);
}

#[test]
fn a_stuck_proposal_below_the_threshold_is_refused_with_both_numbers_named() {
    let f = deploy();
    let id = stage_stuck_proposal(&f);

    // Deliberately do NOT advance a full threshold.
    match reconcile(&f, id, ProposalReconcileDecision::Executed, f.controller) {
        Err(ProposalReconcileError::TooYoung { age_ns, threshold_ns }) => {
            assert_eq!(threshold_ns, THRESHOLD_NS, "the canister's threshold must be the ratified one");
            assert!(age_ns < THRESHOLD_NS, "age {age_ns} must be below the threshold");
        }
        other => panic!("expected TooYoung, got {other:?}"),
    }
    assert_eq!(proposal(&f, id).status, ProposalStatus::Executing, "a refusal must not mutate");
}

#[test]
fn terminal_replay_returns_history_without_mutating_and_ignores_the_decision() {
    let f = deploy();
    let id = stage_stuck_proposal(&f);
    f.pic.advance_time(Duration::from_nanos(THRESHOLD_NS));
    f.pic.tick();

    reconcile(&f, id, ProposalReconcileDecision::Executed, f.controller)
        .expect("first reconcile must succeed");
    let settled = proposal(&f, id);

    // Replay with the OPPOSITE decision: history must be reported, not re-decided.
    match reconcile(&f, id, ProposalReconcileDecision::NotExecuted, f.controller) {
        Ok(ProposalReconcileResult::TerminalReplay(r)) => {
            assert_eq!(r.status, ProposalStatus::Executed, "replay must not flip the outcome");
            assert_eq!(r.execution_result, settled.execution_result);
        }
        other => panic!("expected TerminalReplay, got {other:?}"),
    }

    let after = proposal(&f, id);
    assert_eq!(after.status, settled.status, "terminal replay must mutate nothing");
    assert_eq!(after.executed_at_ns, settled.executed_at_ns);
    assert_eq!(after.execution_result, settled.execution_result);
}
