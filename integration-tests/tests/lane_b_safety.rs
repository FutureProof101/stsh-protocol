// =============================================================================
// STSH — Lane B token/staking safety tests (PocketIC)
// =============================================================================
//
// Cross-canister tests for the Lane B (fix/laneB-token-safety) changes that
// require real caller identity / inter-canister calls and therefore cannot run
// as host unit tests. The pure-arithmetic tests (u128_overflow_safe,
// supply_invariant) live as unit tests in canisters/token/src/lib.rs.
//
//   test_lb01 — stake with insufficient liquid balance creates NO position and
//               leaves TOTAL_VOTING_WEIGHT unchanged (inner-Result handling).
//   test_lb02 — a failing inner unlock_from_staking does not corrupt position /
//               voting-weight state (position stays open, weight unchanged).
//   test_lb03 — an approval fee cannot erode locked stake (approve checks LIQUID).
//   test_lb04 — transfer_from fails when the owner's LIQUID balance is
//               insufficient at transfer time, even if the allowance is larger.
//   test_lb05 — claim_rewards does not silently debit the reward pool when the
//               token-transfer path is gated (NotImplemented; pool unchanged).
//
// PREREQUISITES:
//   1. Build canister Wasm:
//      cargo build --target wasm32-unknown-unknown --release \
//          -p stsh_token -p staking
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests --test lane_b_safety -- --test-threads=1
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

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token -p staking",
            pkg, path, e
        )
    })
}

fn token_wasm()   -> Vec<u8> { load_wasm(env!("TOKEN_WASM"),   "stsh_token") }
fn staking_wasm() -> Vec<u8> { load_wasm(env!("STAKING_WASM"), "staking") }

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH
const DEFAULT_FEE:  u128 = 0;                            // token DEFAULT_FEE (F-000: free transfers at launch)
const STSH:         u128 = 100_000_000;                  // 1 STSH in base units

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — field names/order must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

// ── Token ─────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }

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

/// Token init: all supply to `recipient`; `staking` is the authorized staking caller.
fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
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
        staking_canister: staking,
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount:    Option<[u8; 32]>,
    spender:            Account,
    amount:             u128,
    expected_allowance: Option<u128>,
    expires_at:         Option<u64>,
    fee:                Option<u128>,
    memo:               Option<Vec<u8>>,
    created_at_time:    Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>,
    from:               Account,
    to:                 Account,
    amount:             u128,
    fee:                Option<u128>,
    memo:               Option<Vec<u8>>,
    created_at_time:    Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TransferError {
    BadFee             { expected_fee: Nat },
    BadBurn            { min_burn_amount: Nat },
    InsufficientFunds  { balance: Nat },
    TooOld,
    CreatedInFuture    { ledger_time: u64 },
    Duplicate          { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError       { error_code: Nat, message: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveError {
    BadFee            { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged  { current_allowance: Nat },
    Expired           { ledger_time: u64 },
    TooOld,
    CreatedInFuture   { ledger_time: u64 },
    Duplicate         { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError      { error_code: Nat, message: String },
}

// ── Staking ─────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceParams {
    min_proposal_deposit:   u128,
    voting_delay_ns:        u64,
    voting_period_ns:       u64,
    execution_timelock_ns:  u64,
    vk_upgrade_timelock_ns: u64,
    quorum_bps:             u32,
    treasury_quorum_bps:    u32,
    vk_quorum_bps:          u32,
    approval_threshold_bps: u32,
}

#[derive(CandidType, Deserialize)]
struct StakingInitArgs {
    token_canister:                Principal,
    pool_canister:                 Principal,
    treasury_canister:             Principal,
    initial_rewards_pool:          u128,
    initial_emission_rate_per_day: u128,
    governance_params:             Option<GovernanceParams>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct StakePosition {
    position_id:     u64,
    holder:          Principal,
    amount:          u128,
    lock_days:       u32,
    lock_end_ns:     u64,
    voting_weight:   u128,
    rewards_claimed: u128,
    last_claim_ns:   u64,
    created_at_ns:   u64,
    closed:          bool,
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
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    let args = candid::encode_one(init).expect("encode init args");
    pic.install_canister(cid, wasm, args, None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn to_u128(n: Nat) -> u128 { n.0.to_string().parse::<u128>().unwrap_or(0) }

fn token_balance(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    to_u128(decode(
        "icrc1_balance_of",
        pic.query_call(token, anon(), "icrc1_balance_of",
                       candid::encode_one(Account { owner, subaccount: None }).unwrap()),
    ))
}

fn staking_locked(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    to_u128(decode(
        "staking_locked_balance",
        pic.query_call(token, anon(), "staking_locked_balance",
                       candid::encode_one(owner).unwrap()),
    ))
}

fn positions(pic: &PocketIc, staking: Principal, holder: Principal) -> Vec<StakePosition> {
    decode(
        "get_stake_positions",
        pic.query_call(staking, anon(), "get_stake_positions",
                       candid::encode_one(holder).unwrap()),
    )
}

fn total_voting_weight(pic: &PocketIc, staking: Principal) -> u128 {
    to_u128(decode(
        "get_total_voting_weight",
        pic.query_call(staking, anon(), "get_total_voting_weight",
                       candid::encode_args(()).unwrap()),
    ))
}

fn rewards_pool_balance(pic: &PocketIc, staking: Principal) -> u128 {
    to_u128(decode(
        "get_rewards_pool_balance",
        pic.query_call(staking, anon(), "get_rewards_pool_balance",
                       candid::encode_args(()).unwrap()),
    ))
}

fn staking_init(token: Principal, rewards_pool: u128, emission_per_day: u128) -> StakingInitArgs {
    StakingInitArgs {
        token_canister:                token,
        pool_canister:                 p(0x02),
        treasury_canister:             p(0x03),
        initial_rewards_pool:          rewards_pool,
        initial_emission_rate_per_day: emission_per_day,
        governance_params:             None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// test_lb01 — stake with insufficient liquid balance creates no position
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 2): stake() awaits token.lock_for_staking and must decode the
// INNER Result. With an unfunded caller the inner result is
// Err("Insufficient liquid balance"); stake must abort — NO position created and
// TOTAL_VOTING_WEIGHT unchanged. (Before the fix the inner Err was discarded and
// a position + voting weight were created against tokens that were never locked.)
// =============================================================================

#[test]
fn test_lb01_stake_insufficient_balance_no_position() {
    let pic = PocketIc::new();
    let funded = p(0xA0);          // holds all supply (not the staker)
    let user   = p(0xA1);          // zero balance — cannot fund a stake

    let token_id   = create_canister(&pic);
    let staking_id = create_canister(&pic);

    // All supply to `funded`; staking canister authorized as `staking_id`.
    install(&pic, token_id, token_wasm(), &all_to(funded, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id, 0, 0));

    assert_eq!(total_voting_weight(&pic, staking_id), 0, "precondition: weight starts at 0");

    // user (0 balance) tries to stake 100 STSH.
    let stake_result: Result<u64, String> = decode(
        "test_lb01: stake",
        pic.update_call(staking_id, user, "stake",
                        candid::encode_args((100u128 * STSH, 30u32, next_dedup_key())).unwrap()),
    );

    assert!(stake_result.is_err(),
        "test_lb01: stake must fail when caller has no liquid balance; got {:?}", stake_result);

    // No position created, voting weight untouched.
    assert!(positions(&pic, staking_id, user).is_empty(),
        "test_lb01: a failed lock must NOT create a stake position");
    assert_eq!(total_voting_weight(&pic, staking_id), 0,
        "test_lb01: TOTAL_VOTING_WEIGHT must remain 0 after a failed stake");
    assert_eq!(staking_locked(&pic, token_id, user), 0,
        "test_lb01: no tokens may be locked for an unfunded staker");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_lb02 — a failing inner unlock does not corrupt position / weight state
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 2): unstake() awaits token.unlock_from_staking and must decode
// the INNER Result. We drain the lock out-of-band (the authorized staking caller
// unlocks it directly) so the position's unlock returns
// Err("Cannot unlock ... only 0 locked"). unstake must abort BEFORE subtracting
// voting weight or closing the position. (Before the fix the inner Err was
// discarded: weight was subtracted and the position closed despite the failure.)
// =============================================================================

#[test]
fn test_lb02_unstake_inner_err_handled() {
    let pic = PocketIc::new();
    let user = p(0xB0);

    let token_id   = create_canister(&pic);
    let staking_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(&pic, staking_id, staking_wasm(), &staking_init(token_id, 0, 0));

    // Stake 100 STSH with lock_days = 0 (immediately unlockable).
    let amount = 100u128 * STSH;
    let stake_res: Result<u64, String> = decode(
        "test_lb02: stake",
        pic.update_call(staking_id, user, "stake",
                        candid::encode_args((amount, MIN_LOCK_DAYS, next_dedup_key())).unwrap()),
    );
    let position_id = stake_res
        .unwrap_or_else(|e| panic!("test_lb02: stake must succeed; got {:?}", e));

    let weight_after_stake = total_voting_weight(&pic, staking_id);
    assert_eq!(weight_after_stake, amount, "test_lb02: 1.0x weight at the 30-day minimum");
    assert_eq!(staking_locked(&pic, token_id, user), amount, "test_lb02: tokens locked after stake");

    // Drain the lock out-of-band: the authorized staking canister unlocks it all,
    // leaving the position open but with 0 locked at the token level.
    let drain: Result<(), String> = decode(
        "test_lb02: out-of-band unlock",
        pic.update_call(token_id, staking_id, "unlock_from_staking",
                        candid::encode_args((user, amount)).unwrap()),
    );
    assert!(drain.is_ok(), "test_lb02: out-of-band unlock must succeed; got {:?}", drain);
    assert_eq!(staking_locked(&pic, token_id, user), 0, "test_lb02: lock drained to 0");

    // Ensure the position is unlockable, then attempt unstake — the inner unlock
    // now fails because there is nothing left to unlock. P-STK C-A2: the lock is
    // the 30-day minimum, so advancing 2s is no longer enough.
    advance_past_min_lock(&pic);
    let unstake_result: Result<(), String> = decode(
        "test_lb02: unstake",
        pic.update_call(staking_id, user, "unstake",
                        candid::encode_one(position_id).unwrap()),
    );
    assert!(unstake_result.is_err(),
        "test_lb02: unstake must fail when the inner unlock fails; got {:?}", unstake_result);
    assert!(unstake_result.as_ref().unwrap_err().contains("Cannot unlock"),
        "test_lb02: error must surface the inner unlock failure; got {:?}", unstake_result);

    // State must be intact: position still open, voting weight unchanged.
    let ps = positions(&pic, staking_id, user);
    let pos = ps.iter().find(|p| p.position_id == position_id)
        .expect("test_lb02: position must still exist");
    assert!(!pos.closed,
        "test_lb02: position must remain OPEN after a failed inner unlock");
    assert_eq!(total_voting_weight(&pic, staking_id), weight_after_stake,
        "test_lb02: TOTAL_VOTING_WEIGHT must be unchanged after a failed unstake");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_lb03 — an approval fee cannot erode locked stake
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 3): icrc2_approve must check/debit the fee against LIQUID
// balance (total − staking_locked), not raw BALANCES — the fee debit must never
// push locked above total balance.
//
// F-000 UPDATE (fee = 0 at launch): with a zero fee there is nothing to debit,
// so a fully-staked holder's approve now SUCCEEDS — and the invariant holds by
// the stronger property asserted below: balance and locked are BOTH unchanged
// (no debit occurred at all). The fee>0 liquid-check code path itself remains
// covered by the token unit tests and would re-arm automatically if the fee
// ever becomes nonzero (this test then reverts to the rejection expectation).
// =============================================================================

#[test]
fn test_lb03_approve_fee_respects_locked() {
    let pic = PocketIc::new();
    let user    = p(0xC0);
    let spender = p(0xC1);
    let staking = p(0x02);          // bare principal acts as the authorized lock caller

    let token_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(user, staking));

    // Fully stake the holder: lock the entire balance → liquid == 0.
    let lock: Result<(), String> = decode(
        "test_lb03: lock_for_staking",
        pic.update_call(token_id, staking, "lock_for_staking",
                        candid::encode_args((user, TOTAL_SUPPLY)).unwrap()),
    );
    assert!(lock.is_ok(), "test_lb03: full lock must succeed; got {:?}", lock);
    assert_eq!(staking_locked(&pic, token_id, user), TOTAL_SUPPLY, "test_lb03: fully locked");

    // Approve with default fee (fee: None → DEFAULT_FEE = 0, F-000). With a
    // zero fee nothing is debited, so the approve succeeds even at liquid == 0.
    let approve_args = ApproveArgs {
        from_subaccount: None,
        spender: Account { owner: spender, subaccount: None },
        amount: 1_000 * STSH,
        expected_allowance: None,
        // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
        // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
        // exercise expiry, so the value only has to be present and in range.
        expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let approve: Result<Nat, ApproveError> = decode(
        "test_lb03: icrc2_approve",
        pic.update_call(token_id, user, "icrc2_approve",
                        candid::encode_one(approve_args).unwrap()),
    );
    assert!(
        approve.is_ok(),
        "test_lb03 (F-000): zero-fee approve with zero liquid must succeed; got {:?}",
        approve
    );

    // THE INVARIANT: locked stake is not eroded — balance and locked both
    // unchanged (no debit of any kind occurred).
    assert_eq!(token_balance(&pic, token_id, user), TOTAL_SUPPLY,
        "test_lb03: approver balance must be unchanged (no fee debited)");
    assert_eq!(staking_locked(&pic, token_id, user), TOTAL_SUPPLY,
        "test_lb03: locked stake must be unchanged (not eroded by approval fee)");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_lb04 — transfer_from fails on insufficient LIQUID at transfer time
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 3 / liquid enforcement): approving more than liquid is itself
// valid under ICRC-2, but EXECUTION must fail if the owner's liquid balance is
// insufficient at transfer time, even when the allowance is larger. Staked
// tokens are not transferable via an approved spender.
// =============================================================================

#[test]
fn test_lb04_transfer_from_respects_locked_balance() {
    let pic = PocketIc::new();
    let owner     = p(0xD0);
    let spender   = p(0xD1);
    let recipient = p(0xD2);
    let staking   = p(0x02);

    let token_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(owner, staking));

    // Lock almost everything, leaving a small liquid buffer (enough for the
    // approve fee but far less than the transfer amount).
    let lock_amount = TOTAL_SUPPLY - 100_000;
    let lock: Result<(), String> = decode(
        "test_lb04: lock_for_staking",
        pic.update_call(token_id, staking, "lock_for_staking",
                        candid::encode_args((owner, lock_amount)).unwrap()),
    );
    assert!(lock.is_ok(), "test_lb04: lock must succeed; got {:?}", lock);

    // Approve a LARGE allowance — valid even though it exceeds liquid balance.
    let big_allowance = 10_000_000u128; // >> liquid, >> transfer amount
    let approve: Result<Nat, ApproveError> = decode(
        "test_lb04: icrc2_approve",
        pic.update_call(token_id, owner, "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: spender, subaccount: None },
                amount: big_allowance,
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()),
    );
    assert!(approve.is_ok(),
        "test_lb04: approving more than liquid is valid under ICRC-2; got {:?}", approve);

    let owner_bal_after_approve = token_balance(&pic, token_id, owner);
    assert_eq!(owner_bal_after_approve, TOTAL_SUPPLY - DEFAULT_FEE,
        "test_lb04: only the approve fee should have been debited");

    // transfer_from for an amount that exceeds liquid (but is within allowance)
    // must FAIL at execution time.
    let transfer_amount = 1_000_000u128; // total_debit 1_010_000 >> liquid (~90_000)
    let xfer: Result<Nat, TransferError> = decode(
        "test_lb04: icrc2_transfer_from",
        pic.update_call(token_id, spender, "icrc2_transfer_from",
            candid::encode_one(TransferFromArgs {
                spender_subaccount: None,
                from: Account { owner, subaccount: None },
                to:   Account { owner: recipient, subaccount: None },
                amount: transfer_amount,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()),
    );
    assert!(
        matches!(xfer, Err(TransferError::InsufficientFunds { .. })),
        "test_lb04: transfer_from against insufficient liquid must return InsufficientFunds; got {:?}",
        xfer
    );

    // No tokens moved; locked stake intact.
    assert_eq!(token_balance(&pic, token_id, recipient), 0,
        "test_lb04: recipient must receive nothing");
    assert_eq!(token_balance(&pic, token_id, owner), owner_bal_after_approve,
        "test_lb04: owner balance must be unchanged by the failed transfer_from");
    assert_eq!(staking_locked(&pic, token_id, owner), lock_amount,
        "test_lb04: locked stake must be unchanged (not transferable)");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_lb05 — claim_rewards does not silently debit the reward pool
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 5): claim_rewards is gated to NotImplemented until the reward
// token-transfer path is wired. Even with a funded reward pool and accrued
// rewards, a claim must NOT debit rewards_pool_balance or mutate the position's
// rewards_claimed, and must NOT transfer tokens to the holder. (Before the fix
// the pool was debited while the token transfer was a TODO — a silent loss.)
// =============================================================================

#[test]
fn test_lb05_rewards_claim_no_silent_debit() {
    let pic = PocketIc::new();
    let user = p(0xE0);

    let token_id   = create_canister(&pic);
    let staking_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));

    // Funded reward pool + non-zero emission so rewards genuinely accrue.
    let rewards_pool = 1_000_000u128 * STSH;
    let emission     = 1_000u128 * STSH; // per day
    install(&pic, staking_id, staking_wasm(),
            &staking_init(token_id, rewards_pool, emission));

    // Stake so the holder accrues a share of emissions.
    let amount = 1_000u128 * STSH;
    let stake_res: Result<u64, String> = decode(
        "test_lb05: stake",
        pic.update_call(staking_id, user, "stake",
                        candid::encode_args((amount, MIN_LOCK_DAYS, next_dedup_key())).unwrap()),
    );
    let position_id = stake_res
        .unwrap_or_else(|e| panic!("test_lb05: stake must succeed; got {:?}", e));

    // Accrue ~2 days of rewards. The claim below is an update call and therefore
    // observes the advanced time. A claim with nothing accrued returns Ok(0), so
    // the NotImplemented Err asserted below ALSO proves rewards genuinely accrued
    // (claimable > 0) — i.e. the gate fired on a non-trivial claim.
    pic.advance_time(Duration::from_secs(2 * 24 * 3600 + 10));

    let user_bal_before = token_balance(&pic, token_id, user);

    // Claim must be gated OFF (NotImplemented) — no debit, no transfer.
    let claim: Result<Nat, String> = decode(
        "test_lb05: claim_rewards",
        pic.update_call(staking_id, user, "claim_rewards",
                        candid::encode_one(position_id).unwrap()),
    );
    assert!(claim.is_err(),
        "test_lb05: claim_rewards must be gated (return Err) while transfer is unwired; got {:?}", claim);
    assert!(claim.as_ref().unwrap_err().contains("NotImplemented"),
        "test_lb05: claim error must be NotImplemented (also proves claimable > 0); got {:?}", claim);

    // Reward pool unchanged — NO silent debit.
    assert_eq!(rewards_pool_balance(&pic, staking_id), rewards_pool,
        "test_lb05: rewards_pool_balance must be unchanged after a gated claim");

    // Position rewards_claimed unchanged (still 0).
    let pos = positions(&pic, staking_id, user).into_iter()
        .find(|p| p.position_id == position_id)
        .expect("test_lb05: position must exist");
    assert_eq!(pos.rewards_claimed, 0,
        "test_lb05: rewards_claimed must remain 0 after a gated claim");

    // No tokens transferred to the holder.
    assert_eq!(token_balance(&pic, token_id, user), user_bal_before,
        "test_lb05: holder balance must be unchanged (no reward transfer)");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_lb06 — successful approve + transfer_from (checked-arithmetic happy path)
// ─────────────────────────────────────────────────────────────────────────────
//
// Regression guard for the Task 1 checked_sub/checked_credit rewrite: a normal
// approve + transfer_from (within allowance and liquid balance) must still
// succeed, move exactly `amount` to the recipient, and debit amount + fee from
// the owner. This is the path the shielded pool's deposit flow depends on, so a
// break here would surface as pool deposit failures.
// =============================================================================

#[test]
fn test_lb06_transfer_from_success_happy_path() {
    let pic = PocketIc::new();
    let owner     = p(0xF0);
    let spender   = p(0xF1);
    let recipient = p(0xF2);

    let token_id = create_canister(&pic);
    install(&pic, token_id, token_wasm(), &all_to(owner, p(0x02)));

    // Approve spender for 5000 STSH (no lock; full liquid available).
    let allowance = 5_000u128 * STSH;
    let approve: Result<Nat, ApproveError> = decode(
        "test_lb06: icrc2_approve",
        pic.update_call(token_id, owner, "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: spender, subaccount: None },
                amount: allowance,
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()),
    );
    assert!(approve.is_ok(), "test_lb06: approve must succeed; got {:?}", approve);

    let owner_after_approve = token_balance(&pic, token_id, owner);
    assert_eq!(owner_after_approve, TOTAL_SUPPLY - DEFAULT_FEE,
        "test_lb06: approve debits exactly one fee");

    // transfer_from 1000 STSH — within allowance and liquid balance → success.
    let amount = 1_000u128 * STSH;
    let xfer: Result<Nat, TransferError> = decode(
        "test_lb06: icrc2_transfer_from",
        pic.update_call(token_id, spender, "icrc2_transfer_from",
            candid::encode_one(TransferFromArgs {
                spender_subaccount: None,
                from: Account { owner, subaccount: None },
                to:   Account { owner: recipient, subaccount: None },
                amount,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()),
    );
    assert!(xfer.is_ok(),
        "test_lb06: transfer_from within allowance/liquid must succeed; got {:?}", xfer);

    // Recipient receives exactly `amount`; owner debited amount + ledger fee.
    assert_eq!(token_balance(&pic, token_id, recipient), amount,
        "test_lb06: recipient must receive exactly the transfer amount");
    assert_eq!(token_balance(&pic, token_id, owner), owner_after_approve - amount - DEFAULT_FEE,
        "test_lb06: owner must be debited amount + ledger fee");
}
