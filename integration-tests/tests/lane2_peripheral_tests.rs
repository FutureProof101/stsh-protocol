// =============================================================================
// STSH — Lane 2 peripheral-canister remediation tests
// =============================================================================
//
// Targeted integration tests for the Lane 2 DEF remediation:
//   DEF-059      — staking TOTAL_VOTING_WEIGHT stable persistence
//   DEF-055      — execute_proposal double-execution guard
//   DEF-054      — treasury fee-receipt logging (regression; already implemented)
//   DEF-051 / QA-DEF-005 — vesting claim reconcile + transport-unknown liveness
//   DEF-052      — staking lock/unlock reconcile with operation IDs
//
// Transport-unknown is simulated with the established PocketIC pattern used in
// vesting_staking_retry_tests.rs: stop the token canister, make the call (the
// caller observes an outer transport-level Err), then start it again.
// PocketIC executes update calls synchronously, so "double execution" /
// "double reconcile" is exercised as a repeated call rather than a true parallel
// ingress race — the entry guards must still reject the second call.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// P-STK C-A5: `stake` now takes a caller-supplied dedup key. Tests that are
/// not exercising idempotency just need a distinct key per call — this supplies
/// one so no unrelated test accidentally trips the duplicate-request path.
fn next_dedup_key() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec()
}

// ── Wasm loading ────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}. Build canister Wasms before running integration tests.",
            pkg, path, e
        )
    })
}

fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn staking_wasm() -> Vec<u8> { load_wasm(env!("STAKING_WASM"), "staking") }
fn vesting_wasm() -> Vec<u8> { load_wasm(env!("VESTING_WASM"), "vesting") }
fn treasury_wasm() -> Vec<u8> { load_wasm(env!("TREASURY_WASM"), "treasury") }

// ── Constants ─────────────────────────────────────────────────────────────────

const STSH: u128 = 100_000_000;
const TOTAL_SUPPLY: u128 = 1_000_000_000 * STSH;

// ── Token init mirror ───────────────────────────────────────────────────────────

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

// ── Staking init mirror ─────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
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
struct StakePosition {
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
    op_id: Option<u64>,   // DEF-052
}

// ── Generic helpers ─────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal { Principal::anonymous() }

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).unwrap(), None);
}

fn upgrade(pic: &PocketIc, cid: Principal, wasm: Vec<u8>) {
    pic.upgrade_canister(cid, wasm, candid::encode_args(()).unwrap(), None)
        .expect("upgrade_canister: pre/post_upgrade hooks trapped or controller check failed");
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn all_to(recipient: Principal, staking_canister: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister,
    }
}

fn staking_init(token: Principal) -> StakingInitArgs {
    StakingInitArgs {
        token_canister: token,
        pool_canister: p(0x02),
        treasury_canister: p(0x03),
        initial_rewards_pool: 0,
        initial_emission_rate_per_day: 0,
        governance_params: None,
    }
}

fn total_voting_weight(pic: &PocketIc, staking: Principal) -> u128 {
    decode(
        "get_total_voting_weight",
        pic.query_call(staking, anon(), "get_total_voting_weight", candid::encode_args(()).unwrap()),
    )
}

fn positions(pic: &PocketIc, staking: Principal, holder: Principal) -> Vec<StakePosition> {
    decode(
        "get_stake_positions",
        pic.query_call(staking, anon(), "get_stake_positions", candid::encode_one(holder).unwrap()),
    )
}

fn stake(pic: &PocketIc, staking: Principal, user: Principal, amount: u128, lock_days: u32) -> Result<u64, String> {
    decode(
        "stake",
        pic.update_call(staking, user, "stake", candid::encode_args((amount, lock_days, next_dedup_key())).unwrap()),
    )
}

/// P-STK C-A2: `lock_days = 0` is rejected at the entry point, so the shortest
/// legal lock is 30 days. Tests that previously relied on "stake now, unstake
/// immediately" advance past the minimum lock instead — the position is
/// unlockable at `lock_end_ns`, which no longer coincides with creation.
fn advance_past_min_lock(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs((MIN_LOCK_DAYS as u64 + 1) * 24 * 3600));
    pic.tick();
}

fn unstake(pic: &PocketIc, staking: Principal, user: Principal, position_id: u64) -> Result<(), String> {
    decode(
        "unstake",
        pic.update_call(staking, user, "unstake", candid::encode_one(position_id).unwrap()),
    )
}

// =============================================================================
// DEF-059 — TOTAL_VOTING_WEIGHT survives upgrade via the stable cell, including
//           the total == 0 (positions still present) case the zero-sentinel
//           detection would have mishandled.
// =============================================================================

#[test]
fn test_staking_voting_weight_survives_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x59);
    let amount = 100 * STSH;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id));

    // The 30-day minimum lock also sits at the 1.0x multiplier, so
    // voting_weight == amount still holds; the position becomes unlockable once
    // time is advanced past lock_end_ns (P-STK C-A2 — zero-day locks rejected).
    let position_id = stake(&pic, staking_id, user, amount, MIN_LOCK_DAYS).expect("stake must succeed");
    let weight_before = total_voting_weight(&pic, staking_id);
    assert_eq!(weight_before, amount, "weight must equal staked amount at 1.0x");

    // ── Phase 1: non-zero weight survives a first upgrade ─────────────────────
    upgrade(&pic, staking_id, staking_wasm());
    assert_eq!(
        total_voting_weight(&pic, staking_id), weight_before,
        "DEF-059: voting weight must survive upgrade from the stable cell"
    );

    // ── Phase 2: and a SECOND upgrade (cell is authoritative, not re-scanned) ──
    upgrade(&pic, staking_id, staking_wasm());
    assert_eq!(
        total_voting_weight(&pic, staking_id), weight_before,
        "DEF-059: voting weight must remain correct across repeated upgrades"
    );

    // ── Phase 3: unstake to zero, leaving a CLOSED position in the map ────────
    // This is the exact state the brief warns about: total == 0 while a historical
    // position still exists. A zero-sentinel migration trigger would wrongly
    // re-backfill here; the explicit `initialized` marker must keep it at 0.
    advance_past_min_lock(&pic);
    unstake(&pic, staking_id, user, position_id)
        .expect("unstake must succeed once past the 30-day minimum lock");
    assert_eq!(total_voting_weight(&pic, staking_id), 0, "weight must be 0 after unstake");
    let ps = positions(&pic, staking_id, user);
    assert_eq!(ps.len(), 1, "closed position must remain in the map");
    assert!(ps[0].closed, "position must be closed after unstake");

    upgrade(&pic, staking_id, staking_wasm());
    assert_eq!(
        total_voting_weight(&pic, staking_id), 0,
        "DEF-059: total == 0 with a closed position present must survive upgrade as 0, \
         not be resurrected by a backfill scan"
    );
    let ps_after = positions(&pic, staking_id, user);
    assert_eq!(ps_after.len(), 1, "closed position must still be present after upgrade");
    assert!(ps_after[0].closed, "position must remain closed after upgrade");
}

// =============================================================================
// DEF-055 — execute_proposal double-execution guard
// =============================================================================
//
// PocketIC runs update calls synchronously, so a true concurrent interleave
// during execute_proposal_action's await is not reproducible here. We instead
// prove the guard: execute once (success), then call execute_proposal again on
// the same proposal and confirm it is rejected and no state changed. The
// reentrancy-safety mechanism (status == Executing persisted before the first
// await) is what makes the concurrent case safe; this test pins the observable
// guard behaviour.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VerifierKeyUpgradePayload {
    old_verifying_key_hash: Vec<u8>,
    new_verifying_key_hash: Vec<u8>,
    circuit_version: u32,
    proof_system_id: String,
    audit_artifact_url: String,
    audit_artifact_hash: Vec<u8>,
    circuit_source_commit: String,
    verifier_wasm_hash: Vec<u8>,
    activation_timestamp_ns: u64,
    emergency_disable_supported: bool,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum EmergencyPauseTarget { PoolDeposits, PoolSpends, Both }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ProposalType {
    ParameterUpdate { key: String, value: String },
    TreasurySpend { subaccount: String, recipient: Principal, amount: u128, reason: String },
    FeeUpdate { shield_bps: u32, transfer_bps: u32, unshield_bps: u32 },
    RewardScheduleUpdate { new_emission_rate_per_day: u128 },
    EmergencyPause { target: EmergencyPauseTarget, reason: String },
    VerifierKeyUpgrade(VerifierKeyUpgradePayload),
    CanisterUpgrade { canister_id: Principal, wasm_hash: Vec<u8>, description: String },
    GovernanceParamUpdate(GovernanceParams),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus {
    VotingPending,
    VotingOpen,
    VotingClosed,
    Passed,
    Executing,   // DEF-055
    Rejected,
    Executed,
    Expired,
    Cancelled,
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
    executed_at_ns: Option<u64>,
    execution_result: Option<String>,
}

/// P-STK C-A2: the ruled 30-day minimum lock.
const MIN_LOCK_DAYS: u32 = 30;

const FOURTEEN_DAYS_NS: u64 = 14 * 24 * 60 * 60 * 1_000_000_000;
/// P-STK K3-015: the execution-timelock POLICY FLOOR. `validate()` now runs at
/// init, so a canister can no longer be installed with a sub-floor timelock —
/// tests advance time past the real floor instead of shortening it.
const SEVEN_DAYS_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

// Fast governance params: voting opens immediately and the voting period is
// short so the test runs quickly. The execution timelock is the REAL 7-day
// policy floor and vk_upgrade_timelock_ns the real 14-day floor — P-STK K3-015
// validates params at init, so a shortened timelock is no longer installable.
// Tests advance time past the timelock instead (free in PocketIC).
fn gov_fast(min_proposal_deposit: u128) -> GovernanceParams {
    GovernanceParams {
        min_proposal_deposit,
        voting_delay_ns: 0,
        voting_period_ns: 2_000_000_000,        // 2s
        execution_timelock_ns: SEVEN_DAYS_NS,   // policy floor
        vk_upgrade_timelock_ns: FOURTEEN_DAYS_NS,
        quorum_bps: 1000,
        treasury_quorum_bps: 2000,
        vk_quorum_bps: 3000,
        approval_threshold_bps: 5001,
    }
}

fn staking_init_gov(token: Principal, gov: GovernanceParams) -> StakingInitArgs {
    StakingInitArgs {
        token_canister: token,
        pool_canister: p(0x02),
        treasury_canister: p(0x03),
        initial_rewards_pool: 0,
        initial_emission_rate_per_day: 0,
        governance_params: Some(gov),
    }
}

fn create_proposal(pic: &PocketIc, staking: Principal, proposer: Principal, pt: &ProposalType, desc: &str) -> Result<u64, String> {
    decode(
        "create_proposal",
        pic.update_call(staking, proposer, "create_proposal", candid::encode_args((pt.clone(), desc.to_string())).unwrap()),
    )
}

fn vote(pic: &PocketIc, staking: Principal, voter: Principal, proposal_id: u64, approve: bool) -> Result<(), String> {
    decode(
        "vote",
        pic.update_call(staking, voter, "vote", candid::encode_args((proposal_id, approve)).unwrap()),
    )
}

fn execute_proposal(pic: &PocketIc, staking: Principal, caller: Principal, proposal_id: u64) -> Result<(), String> {
    decode(
        "execute_proposal",
        pic.update_call(staking, caller, "execute_proposal", candid::encode_one(proposal_id).unwrap()),
    )
}

fn get_governance_params(pic: &PocketIc, staking: Principal) -> GovernanceParams {
    decode(
        "get_governance_params",
        pic.query_call(staking, anon(), "get_governance_params", candid::encode_args(()).unwrap()),
    )
}

fn list_proposals(pic: &PocketIc, staking: Principal) -> Vec<Proposal> {
    decode(
        "list_proposals_by_status",
        pic.query_call(staking, anon(), "list_proposals_by_status", candid::encode_one(None::<ProposalStatus>).unwrap()),
    )
}

fn proposal_by_id(pic: &PocketIc, staking: Principal, id: u64) -> Proposal {
    list_proposals(pic, staking).into_iter().find(|p| p.id == id).expect("proposal must exist")
}

// ── QA-DEF-004 (governance → pool authority) — documentation reference ──────────
//
// QA-DEF-004 is a documentation/clarity fix, not a behaviour change, so it has no
// dedicated integration test. The governance→pool authority model is documented in
// the `GOVERNANCE SCOPE` comment on execute_proposal_action in
// canisters/staking/src/lib.rs: a passed, timelocked VerifierKeyUpgrade /
// EmergencyPause proposal is the ONLY way staking governance reaches pool admin
// endpoints (schedule_vk_activation, emergency_pause_*), and that path was already
// guarded (quorum + approval + timelock). The behavioural witness for the VK path
// is security_tests::test_83_vk_upgrade_proposal_executes_after_governance_timelock;
// the DEF-055 double-execution guard test below is the closest Lane 2-owned
// exercise of the execute_proposal path.
#[test]
fn test_execute_proposal_double_execution_rejected() {
    let pic = PocketIc::new();
    let user = p(0x55);
    let stake_amount = 10_000 * STSH;
    let min_deposit = 1_000 * STSH;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init_gov(token_id, gov_fast(min_deposit)));

    // Stake → voting weight + proposal eligibility (30 days = 1.0x → weight == amount).
    stake(&pic, staking_id, user, stake_amount, 30).expect("stake must succeed");

    // A GovernanceParamUpdate is local + synchronous and its effect is observable
    // via get_governance_params. The new params carry a recognizable sentinel
    // min_proposal_deposit so we can confirm the action ran exactly once.
    const SENTINEL_DEPOSIT: u128 = 777 * 100_000_000;
    let mut target = gov_fast(SENTINEL_DEPOSIT);
    // keep vk timelock at the 14-day floor so execution is accepted
    target.vk_upgrade_timelock_ns = FOURTEEN_DAYS_NS;
    let pt = ProposalType::GovernanceParamUpdate(target.clone());

    let pid = create_proposal(&pic, staking_id, user, &pt, "DEF-055 double-execution test")
        .expect("create_proposal must succeed");

    vote(&pic, staking_id, user, pid, true).expect("vote must succeed");

    // Advance past voting_period (2s) + execution_timelock (2s).
    // Past the 2s voting period AND the 7-day execution timelock.
    pic.advance_time(Duration::from_secs(7 * 24 * 3600 + 30));
    pic.tick();

    // ── First execution: succeeds, params updated, status Executed ────────────
    execute_proposal(&pic, staking_id, user, pid).expect("first execute_proposal must succeed");
    assert_eq!(
        get_governance_params(&pic, staking_id).min_proposal_deposit, SENTINEL_DEPOSIT,
        "first execution must apply the GovernanceParamUpdate"
    );
    let after_first = proposal_by_id(&pic, staking_id, pid);
    assert_eq!(after_first.status, ProposalStatus::Executed, "status must be Executed after first execute");
    assert!(after_first.executed_at_ns.is_some(), "executed_at_ns must be set after first execute");

    // ── Second execution: rejected by the guard, no state change ──────────────
    let second = execute_proposal(&pic, staking_id, user, pid);
    assert!(second.is_err(), "second execute_proposal must be rejected");
    assert!(
        second.as_ref().unwrap_err().contains("Already executed"),
        "second execute must report already executed; got {:?}", second
    );

    // State unchanged: params still the sentinel, proposal still Executed.
    assert_eq!(
        get_governance_params(&pic, staking_id).min_proposal_deposit, SENTINEL_DEPOSIT,
        "second (rejected) execute must not change governance params"
    );
    let after_second = proposal_by_id(&pic, staking_id, pid);
    assert_eq!(after_second.status, ProposalStatus::Executed, "status must remain Executed after rejected second execute");
    assert_eq!(
        after_second.executed_at_ns, after_first.executed_at_ns,
        "executed_at_ns must not change on the rejected second execute"
    );
}

// =============================================================================
// DEF-054 — treasury fee-receipt logging (regression)
// =============================================================================
//
// PM adjudication: DEF-054 is already implemented — receive_fee_split pushes a
// structured FeeLogEntry (timestamp, source, total, per-bucket) to FEE_LOG, which
// get_fee_log exposes. No production change. The only test that proved this
// (security_tests::test_77) is #[ignore]d (blocked on proof-bound withdraw), so
// active coverage was absent; this is the standalone regression that keeps it.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum FeeSource { ShieldFee, PrivateTransferFee, UnshieldFee, DexRevenue }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct FeeLogEntry {
    timestamp_ns: u64,
    source: FeeSource,
    total_amount: u128,
    operations: u128,
    insurance: u128,
    audit: u128,
    staking: u128,
}

fn get_fee_log(pic: &PocketIc, treasury: Principal, from: u64, limit: u64) -> Vec<FeeLogEntry> {
    decode(
        "get_fee_log",
        pic.query_call(treasury, anon(), "get_fee_log", candid::encode_args((from, limit)).unwrap()),
    )
}

#[test]
fn test_treasury_fee_receipt_logged() {
    let pic = PocketIc::new();
    let token = p(0x5A);
    let pool = p(0x54);        // the only principal allowed to call receive_fee_split
    let controller = p(0x5C);

    let treasury_id = create_canister(&pic);
    // Treasury init takes three positional principals: (token, pool, controller).
    pic.install_canister(
        treasury_id,
        treasury_wasm(),
        candid::encode_args((token, pool, controller)).unwrap(),
        None,
    );

    assert!(
        get_fee_log(&pic, treasury_id, 0, 10).is_empty(),
        "fee log must start empty"
    );

    let ops = 170_000u128;
    let ins = 30_000u128;
    let staking = 12_500u128;
    // R-2 (C-30): the row's `timestamp_ns` is now SUPPLIED BY THE POOL, not read
    // from `time()` on arrival — for the batched PrivateTransferFee source it is
    // the flush window boundary, and a `time()` read here would stamp the row
    // with whenever the inter-canister call happened to land. This test's claim
    // therefore sharpens from "non-zero" to "exactly what the caller passed".
    const RECEIPT_TS_NS: u64 = 1_767_225_600_000_000_000;

    let r: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(
            treasury_id,
            pool,
            "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, ops, ins, staking, RECEIPT_TS_NS))
                .unwrap(),
        ),
    );
    assert!(r.is_ok(), "receive_fee_split must succeed from the pool principal; got {:?}", r);

    let log = get_fee_log(&pic, treasury_id, 0, 10);
    assert_eq!(log.len(), 1, "exactly one fee-receipt entry must be logged");
    let e = &log[0];
    assert_eq!(e.source, FeeSource::ShieldFee, "logged source must match");
    assert_eq!(e.total_amount, ops + ins + staking, "total must equal the bucket sum");
    assert_eq!(e.operations, ops, "operations bucket must be recorded");
    assert_eq!(e.insurance, ins, "insurance bucket must be recorded");
    assert_eq!(e.staking, staking, "staking bucket must be recorded");
    assert_eq!(
        e.timestamp_ns, RECEIPT_TS_NS,
        "the fee-receipt entry must carry the timestamp the POOL supplied, verbatim"
    );
}

// =============================================================================
// DEF-051 / QA-DEF-005 — vesting claim reconcile + transport-unknown liveness
// =============================================================================
//
// Transport-unknown is forced with the proven PocketIC pattern: stop the token
// canister so icrc1_transfer returns an outer transport-level Err, then start it
// again. A stuck claim has claimed pre-incremented, marker unknown=true (which
// blocks further claims and zeroes claimable_amount). reconcile_claim is the only
// way out: Executed settles with no transfer; NotExecuted reverts `claimed` by
// exactly the recorded amount so the beneficiary can re-claim.

#[derive(CandidType, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal,
    controller: Principal,
    schedules: Vec<NewSchedule>,
}

#[derive(CandidType, Deserialize)]
struct NewSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_months: u32,
    linear_months: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_end_ns: u64,
    vesting_end_ns: u64,
    claimed: u128,
    start_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ClaimDecision { Executed, NotExecuted }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

fn to_u128(n: Nat) -> u128 { n.0.to_string().parse::<u128>().unwrap() }

fn vesting_init(token: Principal, controller: Principal, beneficiary: Principal, total: u128) -> VestingInitArgs {
    VestingInitArgs {
        token_canister: token,
        controller,
        schedules: vec![NewSchedule { beneficiary, total_amount: total, cliff_months: 0, linear_months: 1 }],
    }
}

fn advance_past_vesting(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs(31 * 24 * 3600));
}

fn vest_claim(pic: &PocketIc, vesting: Principal, beneficiary: Principal) -> Result<Nat, String> {
    decode(
        "claim",
        pic.update_call(vesting, beneficiary, "claim", candid::encode_args(()).unwrap()),
    )
}

fn vest_claimable(pic: &PocketIc, vesting: Principal, beneficiary: Principal) -> u128 {
    to_u128(decode(
        "claimable_amount",
        pic.query_call(vesting, anon(), "claimable_amount", candid::encode_one(beneficiary).unwrap()),
    ))
}

fn vest_schedule(pic: &PocketIc, vesting: Principal, beneficiary: Principal) -> VestingSchedule {
    let opt: Option<VestingSchedule> = decode(
        "get_schedule",
        pic.query_call(vesting, anon(), "get_schedule", candid::encode_one(beneficiary).unwrap()),
    );
    opt.expect("vesting schedule must exist")
}

fn reconcile_claim(pic: &PocketIc, vesting: Principal, caller: Principal, beneficiary: Principal, decision: ClaimDecision) -> Result<(), String> {
    decode(
        "reconcile_claim",
        pic.update_call(vesting, caller, "reconcile_claim", candid::encode_args((beneficiary, decision)).unwrap()),
    )
}

fn token_balance(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    to_u128(decode(
        "icrc1_balance_of",
        pic.query_call(token, anon(), "icrc1_balance_of", candid::encode_one(Account { owner, subaccount: None }).unwrap()),
    ))
}

#[test]
fn test_vesting_claim_reconcile_executed() {
    let pic = PocketIc::new();
    let controller = p(0xC1);
    let beneficiary = p(0xB1);
    let total = 5 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(vesting_id, p(0x91)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    // Force transport-unknown.
    pic.stop_canister(token_id, None).expect("stop token");
    let stuck = vest_claim(&pic, vesting_id, beneficiary);
    assert!(stuck.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", stuck);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, total, "claimed pre-incremented and kept while stuck");
    assert_eq!(vest_claimable(&pic, vesting_id, beneficiary), 0, "stuck claim must block claimable_amount");
    pic.start_canister(token_id, None).expect("start token");

    // Only the controller may reconcile.
    let not_ctrl = reconcile_claim(&pic, vesting_id, p(0xDD), beneficiary, ClaimDecision::Executed);
    assert!(not_ctrl.as_ref().unwrap_err().contains("controller"), "non-controller must be rejected; got {:?}", not_ctrl);

    // Controller reconciles Executed → settled, no transfer issued.
    let r = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::Executed);
    assert!(r.is_ok(), "reconcile Executed must succeed; got {:?}", r);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, total, "Executed keeps claimed (settled, no revert)");
    assert_eq!(token_balance(&pic, token_id, beneficiary), 0, "reconcile must NOT issue a token transfer");

    // Second reconcile rejected — schedule no longer stuck.
    let second = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::Executed);
    assert!(second.is_err(), "second reconcile must be rejected");
    assert!(second.as_ref().unwrap_err().contains("not in a transport-unknown"), "got {:?}", second);
}

#[test]
fn test_vesting_claim_reconcile_not_executed() {
    let pic = PocketIc::new();
    let controller = p(0xC2);
    let beneficiary = p(0xB2);
    let total = 7 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(vesting_id, p(0x92)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    pic.stop_canister(token_id, None).expect("stop token");
    let stuck = vest_claim(&pic, vesting_id, beneficiary);
    assert!(stuck.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", stuck);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, total);
    pic.start_canister(token_id, None).expect("start token");

    // Controller reconciles NotExecuted → revert claimed by the stuck amount.
    let r = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::NotExecuted);
    assert!(r.is_ok(), "reconcile NotExecuted must succeed; got {:?}", r);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, 0, "NotExecuted reverts claimed by exactly the stuck amount");
    assert_eq!(vest_claimable(&pic, vesting_id, beneficiary), total, "full amount claimable again after revert");

    // Beneficiary re-claims successfully — exactly once, no double-pay.
    let paid = vest_claim(&pic, vesting_id, beneficiary);
    assert_eq!(to_u128(paid.expect("re-claim must pay")), total, "re-claim must pay the full amount");
    assert_eq!(token_balance(&pic, token_id, beneficiary), total, "beneficiary paid exactly total — no double-pay");
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, total);
}

#[test]
fn test_vesting_claim_reconcile_rejects_non_stuck_schedule() {
    let pic = PocketIc::new();
    let controller = p(0xC3);
    let beneficiary = p(0xB3);
    let total = 4 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(vesting_id, p(0x93)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    // Unclaimed (never stuck): reconcile rejected, state unchanged.
    let r_unclaimed = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::Executed);
    assert!(r_unclaimed.is_err(), "reconcile on an Unclaimed schedule must be rejected");
    assert!(r_unclaimed.as_ref().unwrap_err().contains("not in a transport-unknown"), "got {:?}", r_unclaimed);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, 0, "Unclaimed state must be unchanged");

    // Settle with a normal successful claim (token alive).
    let paid = vest_claim(&pic, vesting_id, beneficiary);
    assert_eq!(to_u128(paid.expect("claim must pay")), total);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, total);

    // Settled (not stuck): reconcile still rejected, no double-pay possible.
    let r_settled = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::NotExecuted);
    assert!(r_settled.is_err(), "reconcile on a Settled schedule must be rejected");
    assert!(r_settled.as_ref().unwrap_err().contains("not in a transport-unknown"), "got {:?}", r_settled);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, total, "Settled state must be unchanged");
    assert_eq!(token_balance(&pic, token_id, beneficiary), total, "rejected reconcile must not move tokens");
}

#[test]
fn test_vesting_claim_reconcile_idempotency_rejects_second_reconcile() {
    let pic = PocketIc::new();
    let controller = p(0xC4);
    let beneficiary = p(0xB4);
    let total = 6 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(vesting_id, p(0x94)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    pic.stop_canister(token_id, None).expect("stop token");
    let stuck = vest_claim(&pic, vesting_id, beneficiary);
    assert!(stuck.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", stuck);
    pic.start_canister(token_id, None).expect("start token");

    // First reconcile (NotExecuted direction) resolves the stuck claim.
    let first = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::NotExecuted);
    assert!(first.is_ok(), "first reconcile must succeed; got {:?}", first);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, 0, "NotExecuted reverted claimed");

    // Second reconcile on the same schedule is rejected — no longer stuck.
    let second = reconcile_claim(&pic, vesting_id, controller, beneficiary, ClaimDecision::Executed);
    assert!(second.is_err(), "second reconcile must be rejected (schedule no longer stuck)");
    assert!(second.as_ref().unwrap_err().contains("not in a transport-unknown"), "got {:?}", second);
    assert_eq!(vest_schedule(&pic, vesting_id, beneficiary).claimed, 0, "rejected second reconcile must not change state");
}

// =============================================================================
// DEF-052 — staking lock/unlock reconcile with operation IDs
// =============================================================================
//
// Transport-unknown is forced by stopping the token canister during stake/unstake;
// that physically means the token call did NOT land, which models the NotExecuted
// case directly. For the Executed-case tests we additionally perform the token
// lock/unlock OUT OF BAND (as the staking canister principal, exactly as the
// existing retry suite does) so the token ledger reflects "the call landed but the
// response was lost" — the other half of transport-unknown — and the operator's
// Executed assertion matches reality.
//
// reconcile endpoints are gated to the canister's IC controllers, so the staking
// canister is reassigned to a known controller via pic.set_controllers (the token
// stays anon-controlled so stop/start still work).

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum LockOpType { Lock, Unlock }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockDecision { Executed, NotExecuted }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingLockOp {
    op_id: u64,
    position_id: u64,
    holder: Principal,
    amount: u128,
    op_type: LockOpType,
    initiated_at_ns: u64,
    snapshot: StakePosition,
}

fn staking_locked(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    decode(
        "staking_locked_balance",
        pic.query_call(token, anon(), "staking_locked_balance", candid::encode_one(owner).unwrap()),
    )
}

fn reconcile_lock(pic: &PocketIc, staking: Principal, caller: Principal, op_id: u64, decision: LockDecision) -> Result<(), String> {
    decode(
        "reconcile_lock",
        pic.update_call(staking, caller, "reconcile_lock", candid::encode_args((op_id, decision)).unwrap()),
    )
}

fn reconcile_unlock(pic: &PocketIc, staking: Principal, caller: Principal, op_id: u64, decision: LockDecision) -> Result<(), String> {
    decode(
        "reconcile_unlock",
        pic.update_call(staking, caller, "reconcile_unlock", candid::encode_args((op_id, decision)).unwrap()),
    )
}

fn list_pending_lock_ops(pic: &PocketIc, staking: Principal, caller: Principal) -> Vec<PendingLockOp> {
    decode(
        "list_pending_lock_ops",
        pic.query_call(staking, caller, "list_pending_lock_ops", candid::encode_args(()).unwrap()),
    )
}

/// Out-of-band token lock as the staking canister principal — simulates "the lock
/// landed at the token but the staking-side response was lost".
fn token_lock_oob(pic: &PocketIc, token: Principal, staking_id: Principal, holder: Principal, amount: u128) -> Result<(), String> {
    decode(
        "lock_for_staking (oob)",
        pic.update_call(token, staking_id, "lock_for_staking", candid::encode_args((holder, amount)).unwrap()),
    )
}

/// Out-of-band token unlock as the staking canister principal.
fn token_unlock_oob(pic: &PocketIc, token: Principal, staking_id: Principal, holder: Principal, amount: u128) -> Result<(), String> {
    decode(
        "unlock_from_staking (oob)",
        pic.update_call(token, staking_id, "unlock_from_staking", candid::encode_args((holder, amount)).unwrap()),
    )
}

/// Deploy token + staking, give all tokens to `user`, reassign staking's IC
/// controller to `controller`. Returns (token_id, staking_id).
fn deploy_staking_with_controller(pic: &PocketIc, user: Principal, controller: Principal) -> (Principal, Principal) {
    let token_id = create_canister(pic);
    let staking_id = create_canister(pic);
    install(pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(pic, staking_id, staking_wasm(), &staking_init(token_id));
    pic.set_controllers(staking_id, Some(anon()), vec![controller])
        .expect("reassign staking IC controllers");
    (token_id, staking_id)
}

#[test]
fn test_lock_reconcile_executed() {
    let pic = PocketIc::new();
    let user = p(0x40);
    let controller = p(0xC0);
    let amount = 100 * STSH;
    let (token_id, staking_id) = deploy_staking_with_controller(&pic, user, controller);

    // Force a LockPending op: token stopped → stake sees transport-unknown.
    pic.stop_canister(token_id, None).expect("stop token");
    let r = stake(&pic, staking_id, user, amount, 30);
    assert!(r.as_ref().unwrap_err().contains("LockPending"), "got {:?}", r);
    pic.start_canister(token_id, None).expect("start token");

    // No weight credited during pending.
    assert_eq!(total_voting_weight(&pic, staking_id), 0, "no weight during LockPending");

    // Operator confirms (out of band) the lock actually landed at the token.
    token_lock_oob(&pic, token_id, staking_id, user, amount).expect("oob lock must succeed");
    assert_eq!(staking_locked(&pic, token_id, user), amount, "token reflects the lock");

    // Find the pending op and reconcile Executed.
    let ops = list_pending_lock_ops(&pic, staking_id, controller);
    assert_eq!(ops.len(), 1, "exactly one pending op");
    assert_eq!(ops[0].op_type, LockOpType::Lock);
    assert_eq!(ops[0].holder, user);
    assert_eq!(ops[0].amount, amount);
    let op_id = ops[0].op_id;

    reconcile_lock(&pic, staking_id, controller, op_id, LockDecision::Executed).expect("reconcile Executed");

    // Position is active with full weight; TOTAL increased; op cleared.
    let ps = positions(&pic, staking_id, user);
    assert_eq!(ps.len(), 1);
    assert!(!ps[0].closed, "position must be active");
    assert_eq!(ps[0].voting_weight, amount, "active position carries full weight");
    assert_eq!(total_voting_weight(&pic, staking_id), amount, "TOTAL increased by the position weight");
    assert!(list_pending_lock_ops(&pic, staking_id, controller).is_empty(), "op_id cleared after reconcile");
}

#[test]
fn test_lock_reconcile_not_executed() {
    let pic = PocketIc::new();
    let user = p(0x41);
    let controller = p(0xC0);
    let amount = 100 * STSH;
    let (token_id, staking_id) = deploy_staking_with_controller(&pic, user, controller);

    pic.stop_canister(token_id, None).expect("stop token");
    let r = stake(&pic, staking_id, user, amount, 30);
    assert!(r.as_ref().unwrap_err().contains("LockPending"), "got {:?}", r);
    pic.start_canister(token_id, None).expect("start token");

    // The lock truly did not land (token was stopped) → NotExecuted.
    let op_id = list_pending_lock_ops(&pic, staking_id, controller)[0].op_id;
    reconcile_lock(&pic, staking_id, controller, op_id, LockDecision::NotExecuted).expect("reconcile NotExecuted");

    // Position cancelled, no weight, balance untouched, op cleared.
    assert!(positions(&pic, staking_id, user).is_empty(), "cancelled lock removes the position");
    assert_eq!(total_voting_weight(&pic, staking_id), 0, "TOTAL unchanged (no weight was credited)");
    assert_eq!(staking_locked(&pic, token_id, user), 0, "no token lock");
    assert!(list_pending_lock_ops(&pic, staking_id, controller).is_empty(), "op_id cleared after reconcile");
}

#[test]
fn test_unlock_reconcile_executed() {
    let pic = PocketIc::new();
    let user = p(0x50);
    let controller = p(0xC0);
    let amount = 125 * STSH;
    let (token_id, staking_id) = deploy_staking_with_controller(&pic, user, controller);

    // Stake at the 30-day minimum (still 1.0x weight), then advance past the
    // lock so the unstake path below is reachable (P-STK C-A2).
    let position_id = stake(&pic, staking_id, user, amount, MIN_LOCK_DAYS).expect("stake must succeed");
    assert_eq!(total_voting_weight(&pic, staking_id), amount);
    assert_eq!(staking_locked(&pic, token_id, user), amount);

    // Force UnlockPending.
    pic.stop_canister(token_id, None).expect("stop token");
    advance_past_min_lock(&pic);
    let r = unstake(&pic, staking_id, user, position_id);
    assert!(r.as_ref().unwrap_err().contains("UnlockPending"), "got {:?}", r);
    pic.start_canister(token_id, None).expect("start token");
    assert_eq!(total_voting_weight(&pic, staking_id), 0, "weight removed on entering UnlockPending");

    // Operator confirms (out of band) the unlock actually landed.
    token_unlock_oob(&pic, token_id, staking_id, user, amount).expect("oob unlock must succeed");
    assert_eq!(staking_locked(&pic, token_id, user), 0, "token reflects the unlock");

    let op_id = list_pending_lock_ops(&pic, staking_id, controller)[0].op_id;
    reconcile_unlock(&pic, staking_id, controller, op_id, LockDecision::Executed).expect("reconcile Executed");

    // Position closed; TOTAL stays 0 (already removed); op cleared.
    let ps = positions(&pic, staking_id, user);
    let pos = ps.iter().find(|p| p.position_id == position_id).expect("position must exist");
    assert!(pos.closed, "position must be closed after unlock Executed");
    assert_eq!(total_voting_weight(&pic, staking_id), 0, "TOTAL decreased by the unlocked weight (already at entry)");
    assert!(list_pending_lock_ops(&pic, staking_id, controller).is_empty(), "op_id cleared after reconcile");
}

#[test]
fn test_unlock_reconcile_not_executed() {
    let pic = PocketIc::new();
    let user = p(0x51);
    let controller = p(0xC0);
    let amount = 80 * STSH;
    let (token_id, staking_id) = deploy_staking_with_controller(&pic, user, controller);

    // 30-day minimum (P-STK C-A2) — still 1.0x weight.
    let position_id = stake(&pic, staking_id, user, amount, MIN_LOCK_DAYS).expect("stake must succeed");
    assert_eq!(total_voting_weight(&pic, staking_id), amount);

    // Force UnlockPending; the unlock truly does not land (token stopped).
    pic.stop_canister(token_id, None).expect("stop token");
    advance_past_min_lock(&pic);
    let r = unstake(&pic, staking_id, user, position_id);
    assert!(r.as_ref().unwrap_err().contains("UnlockPending"), "got {:?}", r);
    pic.start_canister(token_id, None).expect("start token");
    assert_eq!(total_voting_weight(&pic, staking_id), 0, "weight removed on entering UnlockPending");

    let op_id = list_pending_lock_ops(&pic, staking_id, controller)[0].op_id;
    reconcile_unlock(&pic, staking_id, controller, op_id, LockDecision::NotExecuted).expect("reconcile NotExecuted");

    // Position reverts to exactly its pre-unlock active state; weight restored.
    let ps = positions(&pic, staking_id, user);
    let pos = ps.iter().find(|p| p.position_id == position_id).expect("position must exist");
    assert!(!pos.closed, "position reverts to active");
    assert_eq!(pos.voting_weight, amount, "voting weight restored exactly");
    assert_eq!(total_voting_weight(&pic, staking_id), amount, "TOTAL is exactly the pre-unlock value");
    assert_eq!(staking_locked(&pic, token_id, user), amount, "token lock intact (unlock never landed)");
    assert!(list_pending_lock_ops(&pic, staking_id, controller).is_empty(), "op_id cleared after reconcile");
}

#[test]
fn test_list_pending_lock_ops() {
    let pic = PocketIc::new();
    let user = p(0x42);
    let controller = p(0xC0);
    let (token_id, staking_id) = deploy_staking_with_controller(&pic, user, controller);

    // Two LockPending ops (two positions) while the token is stopped.
    pic.stop_canister(token_id, None).expect("stop token");
    assert!(stake(&pic, staking_id, user, 100 * STSH, 30).is_err());
    assert!(stake(&pic, staking_id, user, 200 * STSH, 30).is_err());
    pic.start_canister(token_id, None).expect("start token");

    let ops = list_pending_lock_ops(&pic, staking_id, controller);
    assert_eq!(ops.len(), 2, "operator can enumerate both pending ops");
    let amounts: Vec<u128> = ops.iter().map(|o| o.amount).collect();
    assert!(amounts.contains(&(100 * STSH)) && amounts.contains(&(200 * STSH)), "both amounts present");

    // Reconcile the first → it disappears from the list; the other remains.
    let op0 = ops[0].op_id;
    let op1 = ops[1].op_id;
    reconcile_lock(&pic, staking_id, controller, op0, LockDecision::NotExecuted).expect("reconcile op0");
    let remaining = list_pending_lock_ops(&pic, staking_id, controller);
    assert_eq!(remaining.len(), 1, "one op remains after first reconcile");
    assert!(!remaining.iter().any(|o| o.op_id == op0), "reconciled op0 must be absent");
    assert!(remaining.iter().any(|o| o.op_id == op1), "op1 still present");

    // Reconcile the second → list empty.
    reconcile_lock(&pic, staking_id, controller, op1, LockDecision::NotExecuted).expect("reconcile op1");
    assert!(list_pending_lock_ops(&pic, staking_id, controller).is_empty(), "no unresolved ops remain");
}

#[test]
fn test_staking_reconcile_rejects_mismatched_or_stale_op() {
    let pic = PocketIc::new();
    let user = p(0x43);
    let controller = p(0xC0);
    let amount = 100 * STSH;
    let (token_id, staking_id) = deploy_staking_with_controller(&pic, user, controller);

    pic.stop_canister(token_id, None).expect("stop token");
    assert!(stake(&pic, staking_id, user, amount, 30).is_err());
    pic.start_canister(token_id, None).expect("start token");

    let op_id = list_pending_lock_ops(&pic, staking_id, controller)[0].op_id;

    // Non-controller is rejected.
    let not_ctrl = reconcile_lock(&pic, staking_id, p(0xDD), op_id, LockDecision::NotExecuted);
    assert!(not_ctrl.as_ref().unwrap_err().contains("controller"), "non-controller must be rejected; got {:?}", not_ctrl);

    // (a) Wrong endpoint: reconcile_unlock on a Lock op is rejected.
    let wrong_kind = reconcile_unlock(&pic, staking_id, controller, op_id, LockDecision::Executed);
    assert!(wrong_kind.is_err(), "reconcile_unlock on a Lock op must be rejected");
    assert!(wrong_kind.as_ref().unwrap_err().contains("Lock op, not Unlock"), "got {:?}", wrong_kind);

    // Resolve it correctly.
    reconcile_lock(&pic, staking_id, controller, op_id, LockDecision::NotExecuted).expect("resolve the op");

    // (b) Stale: reconciling the same (now-removed) op_id again is rejected.
    let stale = reconcile_lock(&pic, staking_id, controller, op_id, LockDecision::Executed);
    assert!(stale.is_err(), "already-reconciled op must be rejected");
    assert!(stale.as_ref().unwrap_err().contains("No pending lock op"), "got {:?}", stale);
}
