// =============================================================================
// STSH — Treasury + Vesting real icrc1_transfer tests (PocketIC)
// =============================================================================
//
// vesting.claim performs a real on-ledger icrc1_transfer (M4 wiring). The treasury
// withdrawal tests for the OLD Option-1 self-transfer (67/69/73/76) are RETIRED by
// the Lane B v2 Option 2 custody migration — treasury no longer self-transfers; it
// disburses via the pool. That behavior is now covered by
// integration-tests/tests/lane_b_v2_custody.rs. The remaining treasury tests here
// exercise timelock / precheck / INFLIGHT, which are unchanged by the migration.
//
// Tests 67–77:
//   test_67 — RETIRED (Option 2) → lane_b_v2_custody::test_v2c03
//   test_68 — treasury timelock is enforced (execute before 7 days → Err)
//   test_69 — RETIRED (Option 2) → lane_b_v2_custody::test_v2c03 (idempotency)
//   test_70 — vesting claim before cliff returns "Nothing claimable"
//   test_71 — vesting claim after cliff sends tokens to beneficiary
//   test_72 — second vesting claim sends only the newly-vested delta
//   test_73 — RETIRED (Option 2) → lane_b_v2_custody::test_v2c03 (debit amount+fee)
//   test_74 — balance == amount < total_debit fails precheck; Pending not Rejected (#120)
//   test_75 — execute failure releases INFLIGHT; proposal stays Pending for retry (#120)
//   test_76 — RETIRED (Option 2) → lane_b_v2_custody::test_v2c02/04/05 (no-debit-on-failure)
//   test_77 — INFLIGHT concurrent guard: same-proposal second call returns already-executing (#120)
//
// PREREQUISITES:
//   1. Build canister Wasm:
//      cargo build --target wasm32-unknown-unknown --release \
//          -p stsh_token -p treasury -p vesting
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release \\\n    \
             -p stsh_token -p treasury -p vesting",
            pkg, path, e
        )
    })
}

fn token_wasm()    -> Vec<u8> { load_wasm(env!("TOKEN_WASM"),    "stsh_token") }
fn treasury_wasm() -> Vec<u8> { load_wasm(env!("TREASURY_WASM"), "treasury") }
fn vesting_wasm()  -> Vec<u8> { load_wasm(env!("VESTING_WASM"),  "vesting") }
fn treasury_test_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_TEST_WASM"), "treasury_test")
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Ledger fee on the token canister (DEFAULT_FEE in token/src/lib.rs).
/// F-000: token transfers free at launch.
const DEFAULT_FEE: u128 = 0;

/// 7 days in seconds — treasury withdrawal timelock.
const TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors
// ─────────────────────────────────────────────────────────────────────────────

// ── Token ─────────────────────────────────────────────────────────────────────

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

/// Init the token with all supply given to `recipient`, no staking or treasury used.
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

/// ICRC-1/2 Account — mirrors token canister Account type.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner:      Principal,
    subaccount: Option<[u8; 32]>,
}

// ── Treasury ──────────────────────────────────────────────────────────────────

/// treasury::FeeSource — mirrors canister enum.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum FeeSource {
    ShieldFee,
    PrivateTransferFee,
    UnshieldFee,
    DexRevenue,
}

/// treasury::ProposalStatus — mirrors canister enum.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus { Pending, Executed, Rejected, Expired }

/// treasury::WithdrawalProposal — mirrors canister struct (query only).
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

// ── Vesting ───────────────────────────────────────────────────────────────────

#[derive(CandidType, Deserialize, Clone, Debug)]
struct NewSchedule {
    beneficiary:   Principal,
    total_amount:  u128,
    cliff_months:  u32,
    linear_months: u32,
}

#[derive(CandidType, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal,
    controller:     Principal,
    schedules:      Vec<NewSchedule>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a deterministic Principal for test fixtures.
fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

/// Anonymous principal — used for query calls.
fn anon() -> Principal { Principal::anonymous() }

/// Create a canister with generous cycles, no Wasm yet.
fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

/// Install Wasm with a single Candid-encoded init arg.
fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    let args = candid::encode_one(init).expect("encode init args");
    pic.install_canister(cid, wasm, args, None);
}

/// Install Wasm with raw pre-encoded init bytes (for multi-arg init functions).
fn install_raw(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init_bytes: Vec<u8>) {
    pic.install_canister(cid, wasm, init_bytes, None);
}

/// Decode a canister reply or panic with context.
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

/// Query the ICRC-1 balance of an account.
fn token_balance(pic: &PocketIc, token_id: Principal, owner: Principal) -> u128 {
    let bal: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            token_id, anon(), "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap(),
        ),
    );
    bal.0.to_string().parse::<u128>().unwrap_or(0)
}

/// Query the treasury's internal subaccount balance (not the on-ledger balance).
fn treasury_balance(pic: &PocketIc, treasury_id: Principal, subaccount: &str) -> u128 {
    let opt: Option<u128> = decode(
        "get_subaccount_balance",
        pic.query_call(
            treasury_id, anon(), "get_subaccount_balance",
            candid::encode_one(subaccount.to_string()).unwrap(),
        ),
    );
    opt.unwrap_or(0)
}

/// Fetch the treasury's proposal list and find by id.
fn get_proposal(pic: &PocketIc, treasury_id: Principal, id: u64) -> WithdrawalProposal {
    let proposals: Vec<WithdrawalProposal> = decode(
        "list_proposals",
        pic.query_call(treasury_id, anon(), "list_proposals",
                       candid::encode_args(()).unwrap()),
    );
    proposals.into_iter().find(|p| p.id == id)
        .unwrap_or_else(|| panic!("proposal {} not found in list_proposals", id))
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 67 — RETIRED (Lane B v2, Option 2 custody migration)
// ─────────────────────────────────────────────────────────────────────────────
//
// Asserted the removed Option-1 behavior: treasury sends tokens via its OWN
// icrc1_transfer. Under Option 2 the pool disburses; the success path (recipient
// credited, proposal Executed) is covered by
// lane_b_v2_custody::test_v2c03_execute_withdrawal_disburses_via_pool.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 68 — treasury timelock is enforced
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: execute_withdrawal called before execute_after_ns must return Err
// containing "Timelock active". No tokens are transferred, proposal stays Pending.
// =============================================================================

#[test]
fn test_68_treasury_timelock_enforced() {
    let pic        = PocketIc::new();
    let controller = p(0x68);
    let pool_id    = p(0xD0);
    let recipient  = p(0xD1);

    let token_id    = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(treasury_id));
    let treasury_init = candid::encode_args((token_id, pool_id, controller)).unwrap();
    install_raw(&pic, treasury_id, treasury_wasm(), treasury_init);

    // Populate "operations" via receive_fee_split.
    let receive_fee_args = candid::encode_args((FeeSource::ShieldFee, 10_000_000_000u128, 0u128, 0u128, 0u64)).unwrap();
    let _: Result<(), String> = decode(
        "test_68: receive_fee_split",
        pic.update_call(treasury_id, pool_id, "receive_fee_split", receive_fee_args),
    );

    // Propose withdrawal.
    let propose_args = candid::encode_args((
        "operations".to_string(), recipient, 1_000_000_000u128, "test_68".to_string(),
    )).unwrap();
    let proposal_id: u64 = decode(
        "test_68: propose_withdrawal",
        pic.update_call(treasury_id, controller, "propose_withdrawal", propose_args),
    );

    // Execute IMMEDIATELY — timelock not expired yet.
    let exec_args = candid::encode_one(proposal_id).unwrap();
    let exec_result: Result<(), String> = decode(
        "test_68: execute before timelock",
        pic.update_call(treasury_id, controller, "execute_withdrawal", exec_args),
    );
    assert!(
        exec_result.is_err(),
        "test_68: execute_withdrawal before timelock must return Err; got Ok"
    );
    let err_msg = exec_result.unwrap_err();
    assert!(
        err_msg.contains("Timelock active"),
        "test_68: error must mention 'Timelock active'; got: {:?}", err_msg
    );

    // Proposal must remain Pending (no state mutation from failed execute).
    let proposal = get_proposal(&pic, treasury_id, proposal_id);
    assert_eq!(
        proposal.status, ProposalStatus::Pending,
        "test_68: proposal status must stay Pending after timelock rejection"
    );

    // Recipient must have 0 tokens (no transfer happened).
    let bal = token_balance(&pic, token_id, recipient);
    assert_eq!(bal, 0, "test_68: no tokens must be transferred when timelock is active");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 69 — RETIRED (Lane B v2, Option 2 custody migration)
// ─────────────────────────────────────────────────────────────────────────────
//
// Asserted double-execute rejection over the removed Option-1 self-transfer.
// The idempotency guarantee (second execute → not Pending, no double pay/debit)
// is covered by lane_b_v2_custody::test_v2c03_execute_withdrawal_disburses_via_pool.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 70 — vesting claim before cliff returns "Nothing claimable"
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: with a non-zero cliff, calling claim() before cliff_end_ns
// must return Err("Nothing claimable"). No transfer is made.
// =============================================================================

#[test]
fn test_70_vesting_before_cliff_nothing_claimable() {
    let pic         = PocketIc::new();
    let controller  = p(0x70);
    let beneficiary = p(0xF0);

    let token_id   = create_canister(&pic);
    let vesting_id = create_canister(&pic);

    // Vesting canister gets all supply so it can transfer on claim.
    install(&pic, token_id, token_wasm(), &all_to(vesting_id));

    // 6-month cliff, 6-month linear. No time advance → before cliff.
    install(&pic, vesting_id, vesting_wasm(), &VestingInitArgs {
        token_canister: token_id,
        controller,
        schedules: vec![NewSchedule {
            beneficiary,
            total_amount:  1_000_000_000,
            cliff_months:  6,
            linear_months: 6,
        }],
    });

    // Call claim immediately — still before cliff.
    let claim_result: Result<Nat, String> = decode(
        "test_70: claim before cliff",
        pic.update_call(vesting_id, beneficiary, "claim",
                        candid::encode_args(()).unwrap()),
    );
    assert!(
        claim_result.is_err(),
        "test_70: claim before cliff must return Err; got Ok"
    );
    assert_eq!(
        claim_result.unwrap_err(), "Nothing claimable",
        "test_70: error message must be 'Nothing claimable'"
    );

    // Beneficiary must have 0 tokens.
    let bal = token_balance(&pic, token_id, beneficiary);
    assert_eq!(bal, 0, "test_70: beneficiary must have 0 tokens before cliff");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 71 — vesting claim after cliff sends tokens to beneficiary
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: after the vesting period completes, claim() transfers the full
// total_amount to the beneficiary on the token ledger.
//
// Uses cliff_months=0, linear_months=1. After advancing 31 days (> 1 month),
// all tokens are vested and the claim transfers them.
// =============================================================================

#[test]
fn test_71_vesting_after_cliff_sends_tokens() {
    let pic         = PocketIc::new();
    let controller  = p(0x71);
    let beneficiary = p(0xF1);

    let token_id   = create_canister(&pic);
    let vesting_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(vesting_id));

    const TOTAL_AMOUNT: u128 = 500_000_000; // 5 STSH

    // No cliff (cliff_months=0), 1-month linear vesting.
    install(&pic, vesting_id, vesting_wasm(), &VestingInitArgs {
        token_canister: token_id,
        controller,
        schedules: vec![NewSchedule {
            beneficiary,
            total_amount:  TOTAL_AMOUNT,
            cliff_months:  0,
            linear_months: 1,
        }],
    });

    // Advance 31 days — past the 1-month (30-day) linear period.
    pic.advance_time(Duration::from_secs(31 * 24 * 3600));

    // Claim — must succeed and transfer full TOTAL_AMOUNT.
    let claim_result: Result<Nat, String> = decode(
        "test_71: claim after vesting",
        pic.update_call(vesting_id, beneficiary, "claim",
                        candid::encode_args(()).unwrap()),
    );
    assert!(
        claim_result.is_ok(),
        "test_71: claim after vesting period must succeed; got {:?}", claim_result
    );
    let claimed_nat = claim_result.unwrap();
    let claimed: u128 = claimed_nat.0.to_string().parse().unwrap();
    assert_eq!(
        claimed, TOTAL_AMOUNT,
        "test_71: claimed amount must equal total_amount after full vesting"
    );

    // Beneficiary token balance must equal TOTAL_AMOUNT.
    let bal = token_balance(&pic, token_id, beneficiary);
    assert_eq!(
        bal, TOTAL_AMOUNT,
        "test_71: beneficiary ledger balance must equal total vested amount"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 72 — second vesting claim sends only the newly-vested delta
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: the pre-increment/revert concurrency pattern correctly tracks
// already-claimed amounts. A second claim after more time elapses must
// transfer only the incremental (newly vested since last claim) amount.
// The two claims together must sum to total_amount.
//
// Setup: cliff_months=0, linear_months=2.
//   Advance 31 days → first claim ≈ half of total_amount.
//   Advance 35 more days (total > 2 months = fully vested) → second claim = remainder.
//   first + second == total_amount.
// =============================================================================

#[test]
fn test_72_vesting_second_claim_sends_only_delta() {
    let pic         = PocketIc::new();
    let controller  = p(0x72);
    let beneficiary = p(0xF2);

    let token_id   = create_canister(&pic);
    let vesting_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(vesting_id));

    const TOTAL_AMOUNT: u128 = 1_000_000_000; // 10 STSH — clean for integer math

    // No cliff, 2-month linear vesting.
    install(&pic, vesting_id, vesting_wasm(), &VestingInitArgs {
        token_canister: token_id,
        controller,
        schedules: vec![NewSchedule {
            beneficiary,
            total_amount:  TOTAL_AMOUNT,
            cliff_months:  0,
            linear_months: 2,
        }],
    });

    // ── First claim: advance 31 days (slightly past 1 of 2 months) ──────────────
    pic.advance_time(Duration::from_secs(31 * 24 * 3600));

    let first_result: Result<Nat, String> = decode(
        "test_72: first claim",
        pic.update_call(vesting_id, beneficiary, "claim",
                        candid::encode_args(()).unwrap()),
    );
    assert!(
        first_result.is_ok(),
        "test_72: first claim must succeed; got {:?}", first_result
    );
    let first_claimed: u128 = first_result.unwrap().0.to_string().parse().unwrap();
    assert!(
        first_claimed > 0,
        "test_72: first claim must transfer > 0 tokens; got {}", first_claimed
    );
    assert!(
        first_claimed < TOTAL_AMOUNT,
        "test_72: first claim must be partial (< total), got {}", first_claimed
    );

    // ── Second claim: advance 35 more days (total > 2 months = fully vested) ───
    pic.advance_time(Duration::from_secs(35 * 24 * 3600));

    let second_result: Result<Nat, String> = decode(
        "test_72: second claim",
        pic.update_call(vesting_id, beneficiary, "claim",
                        candid::encode_args(()).unwrap()),
    );
    assert!(
        second_result.is_ok(),
        "test_72: second claim must succeed; got {:?}", second_result
    );
    let second_claimed: u128 = second_result.unwrap().0.to_string().parse().unwrap();
    assert!(
        second_claimed > 0,
        "test_72: second claim must transfer > 0 tokens (the delta)"
    );

    // The two claims must cover the full vesting schedule.
    assert_eq!(
        first_claimed + second_claimed, TOTAL_AMOUNT,
        "test_72: first ({}) + second ({}) must equal total_amount ({})",
        first_claimed, second_claimed, TOTAL_AMOUNT
    );

    // Beneficiary ledger balance must equal total_amount (both transfers landed).
    let final_bal = token_balance(&pic, token_id, beneficiary);
    assert_eq!(
        final_bal, TOTAL_AMOUNT,
        "test_72: final beneficiary balance must equal total vested amount"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 73 — RETIRED (Lane B v2, Option 2 custody migration)
// ─────────────────────────────────────────────────────────────────────────────
//
// Asserted Option-1 debit of amount + ledger_fee on treasury's own transfer.
// Under Option 2 the post-success-debit of amount + ledger_fee is covered by
// lane_b_v2_custody::test_v2c03_execute_withdrawal_disburses_via_pool.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 74 — balance == amount < total_debit fails precheck; Pending, no debit
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: when the subaccount balance equals proposal.amount but is less than
// total_debit = amount + ledger_fee, execute_withdrawal must fail the precheck,
// leave the proposal Pending (NOT Rejected), and make no accounting change.
//
// Before #120 the precheck only checked balance >= amount; with balance == amount
// the old code would PASS the precheck and proceed to the ledger transfer (which
// would fail with InsufficientFunds since the ledger also needs the fee deducted).
// After #120 the precheck catches the shortfall before any mutation.
// =============================================================================

// F-000 (ledger fee = 0): total_debit == amount, so "balance == amount but
// balance < total_debit" cannot be constructed through the public interface —
// the propose-time check (balance >= amount) and the execute-time precheck
// (balance >= amount + fee) now bound the same quantity. The #120 precheck code
// in treasury execute_withdrawal is unchanged and fee-agnostic; re-enable this
// test if a nonzero ledger fee ever returns.
#[ignore = "F-000: fee=0 makes balance==amount<total_debit unconstructible; precheck code unchanged"]
#[test]
fn test_74_precheck_amount_only_insufficient_for_total_debit() {
    let pic        = PocketIc::new();
    let controller = p(0x74);
    let pool_id    = p(0xB0);
    let recipient  = p(0xB1);

    let token_id    = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    // Token: all supply to treasury_id (ledger has plenty; internal accounting is the constraint).
    install(&pic, token_id, token_wasm(), &all_to(treasury_id));
    let treasury_init = candid::encode_args((token_id, pool_id, controller)).unwrap();
    install_raw(&pic, treasury_id, treasury_wasm(), treasury_init);

    // Seed operations with exactly AMOUNT — no room for the ledger fee.
    const AMOUNT: u128 = 5_000_000;
    let _: Result<(), String> = decode(
        "test_74: receive_fee_split",
        pic.update_call(
            treasury_id, pool_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, AMOUNT, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );

    let proposal_id: u64 = decode(
        "test_74: propose_withdrawal",
        pic.update_call(
            treasury_id, controller, "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(), recipient, AMOUNT, "test_74".to_string(),
            )).unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    let exec: Result<(), String> = decode(
        "test_74: execute_withdrawal",
        pic.update_call(
            treasury_id, controller, "execute_withdrawal",
            candid::encode_one(proposal_id).unwrap(),
        ),
    );
    assert!(
        exec.is_err(),
        "test_74: execute_withdrawal must fail when balance < total_debit; got Ok",
    );
    let err_msg = exec.unwrap_err();
    assert!(
        err_msg.contains("balance") || err_msg.contains("Insufficient"),
        "test_74: error must mention balance shortfall; got: {:?}", err_msg,
    );

    // Proposal must stay Pending — old code auto-Rejected here (the bug).
    let proposal = get_proposal(&pic, treasury_id, proposal_id);
    assert_eq!(
        proposal.status, ProposalStatus::Pending,
        "test_74: proposal must remain Pending (not Rejected) after precheck failure; \
         old code would have set Rejected, blocking retry without a new proposal",
    );

    // No accounting change — precheck fires before any debit.
    let ops_balance = treasury_balance(&pic, treasury_id, "operations");
    assert_eq!(
        ops_balance, AMOUNT,
        "test_74: operations balance must be unchanged after precheck failure",
    );

    // Recipient receives nothing.
    let rcpt_balance = token_balance(&pic, token_id, recipient);
    assert_eq!(rcpt_balance, 0, "test_74: recipient must receive 0 tokens after precheck failure");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 75 — execute failure releases INFLIGHT; proposal stays Pending for retry
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: when icrc1_transfer fails (InsufficientFunds — treasury has no
// tokens on the ledger), execute_withdrawal must:
//   - re-credit total_debit to the subaccount
//   - leave the proposal Pending
//   - release INFLIGHT_PROPOSALS so a retry does not see "already executing"
//
// INFLIGHT release proof: the second execute_withdrawal call returns
// InsufficientFunds again (NOT "already executing"), proving INFLIGHT was cleared
// after the first failure.
//
// PocketIC note: PocketIC 9.0.2 cascades inter-canister calls to completion
// within a single tick() — two truly concurrent calls cannot be interleaved.
// The concurrent-entry guard (synchronous check-insert before the first yield)
// is a structural guarantee from the IC's single-threaded execution model;
// see security_tests.rs test_71 for the established precedent on why this
// class of test is not implementable in PocketIC.
// =============================================================================

#[test]
fn test_75_execute_failure_releases_inflight_and_leaves_pending() {
    let pic        = PocketIc::new();
    let controller = p(0x75);
    let pool_id    = p(0xC0);
    let recipient  = p(0xC1);

    let token_id    = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    // Token: ALL supply to an unrelated principal — treasury has 0 on-ledger.
    // Internal accounting is seeded separately via receive_fee_split.
    install(&pic, token_id, token_wasm(), &all_to(p(0xFE)));
    let treasury_init = candid::encode_args((token_id, pool_id, controller)).unwrap();
    install_raw(&pic, treasury_id, treasury_wasm(), treasury_init);

    // Seed operations with AMOUNT + DEFAULT_FEE so the internal precheck passes.
    // The transfer will still fail (treasury has 0 on the actual ledger).
    const AMOUNT: u128 = 3_000_000;
    const TOTAL_SEED: u128 = AMOUNT + DEFAULT_FEE;
    let _: Result<(), String> = decode(
        "test_75: receive_fee_split",
        pic.update_call(
            treasury_id, pool_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, TOTAL_SEED, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );

    let proposal_id: u64 = decode(
        "test_75: propose_withdrawal",
        pic.update_call(
            treasury_id, controller, "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(), recipient, AMOUNT, "test_75".to_string(),
            )).unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    // First execute — transfer fails (InsufficientFunds on ledger).
    let exec1: Result<(), String> = decode(
        "test_75: first execute",
        pic.update_call(
            treasury_id, controller, "execute_withdrawal",
            candid::encode_one(proposal_id).unwrap(),
        ),
    );
    assert!(exec1.is_err(), "test_75: first execute must fail (treasury has no tokens)");

    // Proposal must stay Pending.
    let proposal = get_proposal(&pic, treasury_id, proposal_id);
    assert_eq!(
        proposal.status, ProposalStatus::Pending,
        "test_75: proposal must remain Pending after transfer failure",
    );

    // total_debit must be re-credited — balance restored to TOTAL_SEED.
    let ops_after_first = treasury_balance(&pic, treasury_id, "operations");
    assert_eq!(
        ops_after_first, TOTAL_SEED,
        "test_75: operations balance must be restored after first failure (re-credited total_debit)",
    );

    // Recipient receives nothing.
    assert_eq!(
        token_balance(&pic, token_id, recipient), 0,
        "test_75: recipient must have 0 tokens after failed transfer",
    );

    // Second execute — must return transfer failure (NOT "already executing").
    // This proves INFLIGHT_PROPOSALS was cleared after the first failure.
    let exec2: Result<(), String> = decode(
        "test_75: second execute",
        pic.update_call(
            treasury_id, controller, "execute_withdrawal",
            candid::encode_one(proposal_id).unwrap(),
        ),
    );
    assert!(exec2.is_err(), "test_75: second execute must also fail (still no tokens)");
    let err2 = exec2.unwrap_err();
    assert!(
        !err2.contains("already executing"),
        "test_75: second execute must NOT see 'already executing' — INFLIGHT must have been \
         cleared after the first failure; got: {:?}", err2,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 76 — RETIRED (Lane B v2, Option 2 custody migration)
// ─────────────────────────────────────────────────────────────────────────────
//
// Asserted BadFee re-credit on treasury's OWN icrc1_transfer (Option 1). Under
// Option 2 treasury performs no self-transfer: post-success-debit means there is
// no pre-debit/re-credit path at all, so a fee-mismatch/failure simply yields
// no debit. That no-debit-on-failure guarantee is covered by
// lane_b_v2_custody::test_v2c02 / test_v2c04 / test_v2c05.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// Test 77 — INFLIGHT concurrent guard: same-proposal second call returns
//            "already executing"; proposal not Rejected; accounting unchanged
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: INFLIGHT_PROPOSALS is an exclusive reservation gate. A second
// execute_withdrawal call for the same proposal_id must:
//   - return an error containing "already executing"
//   - NOT change the proposal's status (leave it Pending)
//   - NOT mutate the subaccount balance (no debit on the second call)
//
// Deterministic simulation approach (same pattern as test_90/test_94 for
// INFLIGHT_NULLIFIERS — see security_tests.rs):
//   inject_inflight_proposal_for_test(proposal_id) pre-seeds INFLIGHT_PROPOSALS
//   to simulate the state that would exist while a first execute_withdrawal is
//   suspended at YIELD 1 (waiting for icrc1_fee).  The second call is then
//   issued synchronously and must be turned away by the gate.
//
// PocketIC note: PocketIC 9.0.2 cascades inter-canister calls to completion
// within a single tick — two genuinely concurrent update calls cannot be
// interleaved for the same canister.  The inject pattern is the established
// workaround; see security_tests.rs test_90 for the established precedent.
//
// Uses TREASURY_TEST_WASM (treasury built with --features testing, which adds
// inject_inflight_proposal_for_test and inflight_proposals_count_for_test
// controller-gated endpoints absent from the production build).
// =============================================================================

#[test]
fn test_77_inflight_gate_same_proposal_returns_already_executing() {
    let pic        = PocketIc::new();
    let controller = p(0x77);
    let pool_id    = p(0xE0);
    let recipient  = p(0xE1);

    let token_id    = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    // Use TREASURY_TEST_WASM — has inject_inflight_proposal_for_test.
    install(&pic, token_id, token_wasm(), &all_to(treasury_id));
    let treasury_init = candid::encode_args((token_id, pool_id, controller)).unwrap();
    install_raw(&pic, treasury_id, treasury_test_wasm(), treasury_init);

    // Seed operations with enough for total_debit.
    const AMOUNT: u128 = 4_000_000;
    const TOTAL_SEED: u128 = AMOUNT + DEFAULT_FEE;
    let _: Result<(), String> = decode(
        "test_77: receive_fee_split",
        pic.update_call(
            treasury_id, pool_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, TOTAL_SEED, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );

    let proposal_id: u64 = decode(
        "test_77: propose_withdrawal",
        pic.update_call(
            treasury_id, controller, "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(), recipient, AMOUNT, "test_77".to_string(),
            )).unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    // ── Pre-condition: INFLIGHT is empty ─────────────────────────────────────
    let inflight_before: u64 = decode(
        "test_77: inflight_proposals_count_for_test (before inject)",
        pic.query_call(
            treasury_id, controller, "inflight_proposals_count_for_test",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(inflight_before, 0, "test_77: INFLIGHT must be empty before inject");

    // ── Inject proposal_id to simulate first call suspended at YIELD 1 ───────
    let _: () = decode(
        "test_77: inject_inflight_proposal_for_test",
        pic.update_call(
            treasury_id, controller, "inject_inflight_proposal_for_test",
            candid::encode_one(proposal_id).unwrap(),
        ),
    );

    let inflight_after_inject: u64 = decode(
        "test_77: inflight_proposals_count_for_test (after inject)",
        pic.query_call(
            treasury_id, controller, "inflight_proposals_count_for_test",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(inflight_after_inject, 1, "test_77: INFLIGHT must contain 1 entry after inject");

    // ── Second call — must be turned away by the INFLIGHT gate ───────────────
    let exec: Result<(), String> = decode(
        "test_77: execute_withdrawal (second call)",
        pic.update_call(
            treasury_id, controller, "execute_withdrawal",
            candid::encode_one(proposal_id).unwrap(),
        ),
    );
    assert!(exec.is_err(), "test_77: second execute_withdrawal must fail (proposal in INFLIGHT)");
    let err_msg = exec.unwrap_err();
    assert!(
        err_msg.contains("already executing"),
        "test_77: error must contain 'already executing'; got: {:?}", err_msg,
    );

    // ── Proposal must remain Pending — gate must not mutate status ────────────
    let proposal = get_proposal(&pic, treasury_id, proposal_id);
    assert_eq!(
        proposal.status, ProposalStatus::Pending,
        "test_77: proposal must remain Pending after INFLIGHT rejection (no status mutation \
         by the concurrent guard)",
    );

    // ── Balance must be unchanged — gate must not debit ──────────────────────
    let ops_balance = treasury_balance(&pic, treasury_id, "operations");
    assert_eq!(
        ops_balance, TOTAL_SEED,
        "test_77: operations balance must be unchanged after INFLIGHT rejection; \
         expected {} (no debit by second call), got {}", TOTAL_SEED, ops_balance,
    );

    // ── Recipient receives nothing ────────────────────────────────────────────
    let rcpt_balance = token_balance(&pic, token_id, recipient);
    assert_eq!(
        rcpt_balance, 0,
        "test_77: recipient must receive 0 tokens when proposal is in INFLIGHT",
    );
}
