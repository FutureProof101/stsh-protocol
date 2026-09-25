// =============================================================================
// STSH — Lane A Pass 3 retry/idempotency safety tests
// =============================================================================
//
// These tests cover QA-DEF-015 and QA-DEF-016 transport-unknown handling for
// vesting claims and staking lock/unlock calls. PocketIC 9.0.2 executes update
// calls synchronously, so the vesting double-call guard is tested as a repeated
// call after an ambiguous transport failure rather than a true parallel ingress
// race.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// P-STK C-A5: `stake` now takes a caller-supplied dedup key. Tests that are
/// not exercising idempotency just need a distinct key per call — this supplies
/// one so no unrelated test accidentally trips the duplicate-request path.
/// P-STK C-A2: the ruled 30-day minimum lock. Tests that previously used
/// `lock_days = 0` for "immediately unlockable" now use the minimum and
/// advance time instead — zero is rejected at the entry point by design.
const MIN_LOCK_DAYS: u32 = 30;

/// P-STK C-A2: zero-day locks are rejected, so the shortest legal lock is 30
/// days and a freshly-staked position is no longer immediately unlockable.
/// Tests that exercise the unstake path advance past the minimum instead.
fn advance_past_min_lock(pic: &PocketIc) {
    pic.advance_time(std::time::Duration::from_secs((MIN_LOCK_DAYS as u64 + 1) * 24 * 3600));
    pic.tick();
}

fn next_dedup_key() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec()
}

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

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch
const STSH: u128 = 100_000_000;

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferArgs {
    from_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TransferError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

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
}

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

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn to_u128(n: Nat) -> u128 { n.0.to_string().parse::<u128>().unwrap() }

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

fn vesting_init(token: Principal, controller: Principal, beneficiary: Principal, total: u128) -> VestingInitArgs {
    VestingInitArgs {
        token_canister: token,
        controller,
        schedules: vec![NewSchedule {
            beneficiary,
            total_amount: total,
            cliff_months: 0,
            linear_months: 1,
        }],
    }
}

fn advance_past_vesting(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs(31 * 24 * 3600));
}

fn token_balance(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    to_u128(decode(
        "icrc1_balance_of",
        pic.query_call(
            token,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap(),
        ),
    ))
}

fn transfer(pic: &PocketIc, token: Principal, from: Principal, to: Principal, amount: u128) -> Result<Nat, TransferError> {
    decode(
        "icrc1_transfer",
        pic.update_call(
            token,
            from,
            "icrc1_transfer",
            candid::encode_one(TransferArgs {
                from_subaccount: None,
                to: Account { owner: to, subaccount: None },
                amount: Nat::from(amount),
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap(),
        ),
    )
}

fn schedule(pic: &PocketIc, vesting: Principal, beneficiary: Principal) -> VestingSchedule {
    let opt: Option<VestingSchedule> = decode(
        "get_schedule",
        pic.query_call(vesting, anon(), "get_schedule", candid::encode_one(beneficiary).unwrap()),
    );
    opt.expect("vesting schedule must exist")
}

fn claimable(pic: &PocketIc, vesting: Principal, beneficiary: Principal) -> u128 {
    to_u128(decode(
        "claimable_amount",
        pic.query_call(vesting, anon(), "claimable_amount", candid::encode_one(beneficiary).unwrap()),
    ))
}

fn positions(pic: &PocketIc, staking: Principal, holder: Principal) -> Vec<StakePosition> {
    decode(
        "get_stake_positions",
        pic.query_call(staking, anon(), "get_stake_positions", candid::encode_one(holder).unwrap()),
    )
}

fn total_voting_weight(pic: &PocketIc, staking: Principal) -> u128 {
    decode(
        "get_total_voting_weight",
        pic.query_call(staking, anon(), "get_total_voting_weight", candid::encode_args(()).unwrap()),
    )
}

fn staking_locked(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    decode(
        "staking_locked_balance",
        pic.query_call(token, anon(), "staking_locked_balance", candid::encode_one(owner).unwrap()),
    )
}

#[test]
fn vesting_transport_unknown_marks_claimed_and_blocks_second_transfer() {
    let pic = PocketIc::new();
    let controller = p(0x10);
    let beneficiary = p(0x11);
    let total = 5 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(vesting_id, p(0x99)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    pic.stop_canister(token_id, None).expect("stop token canister");
    let first: Result<Nat, String> = decode(
        "claim transport unknown",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert!(first.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", first);

    let sched = schedule(&pic, vesting_id, beneficiary);
    assert_eq!(sched.claimed, total, "ambiguous transfer must not revert claimed");
    assert_eq!(claimable(&pic, vesting_id, beneficiary), 0, "unknown outcome blocks claimable amount");

    pic.start_canister(token_id, None).expect("start token canister");
    let second: Result<Nat, String> = decode(
        "second claim after unknown",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert!(second.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", second);
    assert_eq!(token_balance(&pic, token_id, beneficiary), 0, "second claim must not transfer after unknown outcome");
}

#[test]
fn vesting_definite_ledger_rejection_reverts_and_next_claim_pays() {
    let pic = PocketIc::new();
    let controller = p(0x20);
    let funder = p(0x21);
    let beneficiary = p(0x22);
    let total = 7 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(funder, p(0x98)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    let rejected: Result<Nat, String> = decode(
        "claim with unfunded vesting canister",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert!(rejected.as_ref().unwrap_err().contains("InsufficientFunds"), "got {:?}", rejected);
    assert_eq!(schedule(&pic, vesting_id, beneficiary).claimed, 0, "definite rejection must revert claimed");

    let funding = transfer(&pic, token_id, funder, vesting_id, total + DEFAULT_FEE);
    assert!(funding.is_ok(), "funding vesting canister must succeed: {:?}", funding);

    let paid: Result<Nat, String> = decode(
        "claim after funding",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert_eq!(to_u128(paid.expect("claim should pay")), total);
    assert_eq!(token_balance(&pic, token_id, beneficiary), total);
    assert_eq!(schedule(&pic, vesting_id, beneficiary).claimed, total);
}

#[test]
fn vesting_double_call_guard_blocks_reclaim_after_unknown() {
    let pic = PocketIc::new();
    let controller = p(0x30);
    let beneficiary = p(0x31);
    let total = 3 * STSH;

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(vesting_id, p(0x97)));
    install(&pic, vesting_id, vesting_wasm(), &vesting_init(token_id, controller, beneficiary, total));
    advance_past_vesting(&pic);

    pic.stop_canister(token_id, None).expect("stop token canister");
    let first: Result<Nat, String> = decode(
        "first claim unknown",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert!(first.is_err());

    let second: Result<Nat, String> = decode(
        "second claim while unknown pending",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert!(second.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", second);
    assert_eq!(schedule(&pic, vesting_id, beneficiary).claimed, total);

    pic.start_canister(token_id, None).expect("start token canister");
    let third: Result<Nat, String> = decode(
        "third claim after token recovers",
        pic.update_call(vesting_id, beneficiary, "claim", candid::encode_args(()).unwrap()),
    );
    assert!(third.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {:?}", third);
    assert!(token_balance(&pic, token_id, beneficiary) <= total, "beneficiary must never receive more than vested amount");
}

#[test]
fn staking_lock_transport_unknown_records_pending_without_voting_weight() {
    let pic = PocketIc::new();
    let user = p(0x40);
    let amount = 100 * STSH;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id));

    pic.stop_canister(token_id, None).expect("stop token canister");
    let stake: Result<u64, String> = decode(
        "stake transport unknown",
        pic.update_call(staking_id, user, "stake", candid::encode_args((amount, 30u32, next_dedup_key())).unwrap()),
    );
    assert!(stake.as_ref().unwrap_err().contains("LockPending"), "got {:?}", stake);

    let ps = positions(&pic, staking_id, user);
    assert_eq!(ps.len(), 1, "unknown lock outcome must leave a reconciliation position");
    assert!(!ps[0].closed, "pending lock position must not be closed");
    assert_eq!(ps[0].amount, amount);
    assert_eq!(ps[0].voting_weight, 0, "pending lock must not grant voting weight");
    assert_eq!(total_voting_weight(&pic, staking_id), 0);

    pic.start_canister(token_id, None).expect("start token canister");
    assert_eq!(staking_locked(&pic, token_id, user), 0, "stopped-token unknown path did not lock funds, and no active weight was granted");
}

#[test]
fn staking_unlock_transport_unknown_freezes_position_without_voting_weight() {
    let pic = PocketIc::new();
    let user = p(0x50);
    let amount = 125 * STSH;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id));

    let stake: Result<u64, String> = decode(
        "stake success",
        pic.update_call(staking_id, user, "stake", candid::encode_args((amount, MIN_LOCK_DAYS, next_dedup_key())).unwrap()),
    );
    let position_id = stake.expect("stake should succeed");
    assert_eq!(total_voting_weight(&pic, staking_id), amount);
    assert_eq!(staking_locked(&pic, token_id, user), amount);

    pic.stop_canister(token_id, None).expect("stop token canister");
    advance_past_min_lock(&pic);
    let unstake: Result<(), String> = decode(
        "unstake transport unknown",
        pic.update_call(staking_id, user, "unstake", candid::encode_one(position_id).unwrap()),
    );
    assert!(unstake.as_ref().unwrap_err().contains("UnlockPending"), "got {:?}", unstake);

    let ps = positions(&pic, staking_id, user);
    let pos = ps.iter().find(|p| p.position_id == position_id).expect("position must exist");
    assert!(!pos.closed, "ambiguous unlock must not finalize as withdrawn");
    assert_eq!(pos.voting_weight, 0, "ambiguous unlock must remove active voting weight");
    assert_eq!(total_voting_weight(&pic, staking_id), 0);

    pic.start_canister(token_id, None).expect("start token canister");
    assert_eq!(staking_locked(&pic, token_id, user), amount, "stopped-token unknown path left token lock intact for reconciliation");
}

#[test]
fn staking_definite_lock_rejection_creates_no_position_or_weight() {
    let pic = PocketIc::new();
    let funded = p(0x60);
    let user = p(0x61);
    let amount = 50 * STSH;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(funded, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id));

    let stake: Result<u64, String> = decode(
        "definite lock rejection",
        pic.update_call(staking_id, user, "stake", candid::encode_args((amount, 30u32, next_dedup_key())).unwrap()),
    );
    assert!(stake.as_ref().unwrap_err().contains("Insufficient liquid balance"), "got {:?}", stake);
    assert!(positions(&pic, staking_id, user).is_empty(), "definite lock rejection must create no position");
    assert_eq!(total_voting_weight(&pic, staking_id), 0);
    assert_eq!(staking_locked(&pic, token_id, user), 0);
}

#[test]
fn staking_definite_unlock_rejection_leaves_position_active() {
    let pic = PocketIc::new();
    let user = p(0x70);
    let amount = 80 * STSH;

    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id));

    let stake: Result<u64, String> = decode(
        "stake success before unlock rejection",
        pic.update_call(staking_id, user, "stake", candid::encode_args((amount, MIN_LOCK_DAYS, next_dedup_key())).unwrap()),
    );
    let position_id = stake.expect("stake should succeed");
    assert_eq!(total_voting_weight(&pic, staking_id), amount);
    assert_eq!(staking_locked(&pic, token_id, user), amount);

    let drain: Result<(), String> = decode(
        "out-of-band token unlock",
        pic.update_call(token_id, staking_id, "unlock_from_staking", candid::encode_args((user, amount)).unwrap()),
    );
    assert!(drain.is_ok(), "authorized out-of-band unlock should succeed: {:?}", drain);
    assert_eq!(staking_locked(&pic, token_id, user), 0);

    advance_past_min_lock(&pic);
    let unstake: Result<(), String> = decode(
        "definite unlock rejection",
        pic.update_call(staking_id, user, "unstake", candid::encode_one(position_id).unwrap()),
    );
    assert!(unstake.as_ref().unwrap_err().contains("Cannot unlock"), "got {:?}", unstake);

    let ps = positions(&pic, staking_id, user);
    let pos = ps.iter().find(|p| p.position_id == position_id).expect("position must exist");
    assert!(!pos.closed, "definite unlock rejection must leave position open");
    assert_eq!(pos.voting_weight, amount, "definite unlock rejection must leave voting weight active");
    assert_eq!(total_voting_weight(&pic, staking_id), amount);
}
