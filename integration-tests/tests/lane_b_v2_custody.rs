// =============================================================================
// STSH — Lane B v2 Option 2 custody migration tests (PocketIC)
// =============================================================================
//
// Covers treasury.execute_withdrawal after the Option 2 migration: treasury holds
// no real STSH and disburses via the pool's treasury_disburse entrypoint instead
// of transferring from its own ledger account.
//
//   test_v2c01 — treasury_holds_no_real_balance: treasury's own icrc1_balance_of
//                stays 0 across receive_fee_split + execute_withdrawal.
//   test_v2c02 — execute_withdrawal_disbursement_failure_no_double_debit: when the
//                pool disbursement call fails, the treasury bucket is NOT debited
//                (post-success-debit), the proposal stays Pending, recipient gets
//                nothing, treasury holds no real STSH.
//   test_v2c03 — execute_withdrawal_disburses_via_pool (happy path): full disburse
//                via the pool — recipient credited, bucket debited amount+fee,
//                proposal Executed, treasury holds 0, idempotent re-execute.
//   test_v2c04 — pool returns EscrowUnderfunded → treasury decodes it cleanly, no debit.
//   test_v2c05 — pool returns InsufficientOperationsReserve → clean decode, no debit.
//   test_v2c06 — pool returns IdempotencyKeyConflict → clean decode (conflicting reuse).
//
// All six run on origin/master now that Lane A's treasury_disburse pool is merged.
// v2c01/02 use a pool that lacks treasury_disburse (failure path); v2c03–06 deploy
// the real shielded-pool. v2c03/06 fund OPERATIONS_RESERVE via a shielding-fee deposit.
//
// PREREQUISITES (build the pool stack first, then run single-threaded):
//   cargo build --target wasm32-unknown-unknown --release \
//       -p stsh_token -p treasury -p shielded_pool -p merkle_tree -p nullifier_registry
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test lane_b_v2_custody -- --test-threads=1
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
             cargo build --target wasm32-unknown-unknown --release -p stsh_token -p treasury",
            pkg, path, e
        )
    })
}

fn token_wasm()    -> Vec<u8> { load_wasm(env!("TOKEN_WASM"),    "stsh_token") }
fn treasury_wasm() -> Vec<u8> { load_wasm(env!("TREASURY_WASM"), "treasury") }
fn pool_wasm()     -> Vec<u8> { load_wasm(env!("POOL_WASM"),     "shielded_pool") }
// RB-SWARM-A1: carries `set_governance_fee_params_unchecked_for_test`. The two
// custody tests below activate a 100-STSH shield fee, which sits BELOW the ruled
// 1,000-STSH floor and so is not settable through the guarded endpoint. Their
// subject is treasury custody, not fee policy, so they keep their economics.
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn merkle_wasm()   -> Vec<u8> { load_wasm(env!("MERKLE_WASM"),   "merkle_tree") }

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DEFAULT_FEE:  u128 = 0; // F-000: token transfers free at launch
const STSH:         u128 = 100_000_000; // 1 STSH in base units
const TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

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

/// Token init: all supply to `recipient` (never the treasury, so treasury holds 0).
fn all_to(recipient: Principal) -> TokenInitArgs {
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
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

/// shielded-pool init args (Lane A). nullifier/merkle/staking are only stored at
/// init and are NOT touched by treasury_disburse, so bare principals are fine for
/// the disbursement tests.
#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister:       Principal,
    nullifier_canister:   Principal,
    merkle_canister:      Principal,
    treasury_canister:    Principal,
    staking_canister:     Principal,
    controller:           Principal,
    initial_vk_hash:      [u8; 32],
    initial_proof_system: String,
}

// ── Deposit / fee-param mirrors (for the happy-path reserve funding) ───────────

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
enum ApproveError {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment:   [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount:     u128,
}

/// Mirror of stsh_fee_policy::SpendFeeMode.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum SpendFeeMode {
    FixedStsh,
    XdrPegged,
}

/// Mirrors shielded-pool GovernanceFeeParams (Lane A). Only used to set a nonzero
/// shielding fee so a deposit routes revenue into OPERATIONS_RESERVE.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceFeeParams {
    protocol_shielding_fee_stsh:          u128,
    protocol_unshielding_fee_stsh:        u128,
    protocol_private_spend_fee_stsh:      u128,
    minimum_withdrawal_gross:             u128,
    minimum_recipient_amount:             u128,
    minimum_private_credit:               u128,
    fee_reference_price_stsh_per_icp_e8s: u128,
    fee_safety_margin_bps:                u32,
    max_fee_change_bps_per_update:        u32,
    fee_update_cooldown_ns:               u64,
    operations_split_bps:                 u32,
    insurance_split_bps:                  u32,
    staking_rewards_split_bps:            u32,
    staking_rewards_enabled:              bool,
    minimum_treasury_runway_months:       u32,
    target_treasury_runway_months:        u32,
    // Value fees (fee-build lane).
    shield_fee_bps:                       Option<u16>,
    unshield_fee_bps:                     Option<u16>,
    shield_flat_minimum_fee_e8s:          Option<u128>,
    unshield_flat_minimum_fee_e8s:        Option<u128>,
    spend_fee_mode:                       Option<SpendFeeMode>,
    fee_model_version:                    Option<u32>,
    params_epoch:                         Option<u64>,
}

impl GovernanceFeeParams {
    fn launch_defaults() -> Self {
        Self {
            protocol_shielding_fee_stsh: 0,
            protocol_unshielding_fee_stsh: 0,
            protocol_private_spend_fee_stsh: 0,
            minimum_withdrawal_gross: 0,
            minimum_recipient_amount: 0,
            minimum_private_credit: 0,
            fee_reference_price_stsh_per_icp_e8s: 0,
            fee_safety_margin_bps: 12_500,
            max_fee_change_bps_per_update: 1_000,
            fee_update_cooldown_ns: 24 * 60 * 60 * 1_000_000_000,
            operations_split_bps: 8_500,
            insurance_split_bps: 1_500,
            staking_rewards_split_bps: 0,
            staking_rewards_enabled: false,
            minimum_treasury_runway_months: 6,
            target_treasury_runway_months: 12,
            shield_fee_bps: Some(0),
            unshield_fee_bps: Some(0),
            shield_flat_minimum_fee_e8s: Some(0),
            unshield_flat_minimum_fee_e8s: Some(0),
            spend_fee_mode: Some(SpendFeeMode::FixedStsh),
            fee_model_version: Some(1),
            params_epoch: Some(0),
        }
    }
}

/// Full mirror of shielded-pool PoolError — needed to decode shield_deposit's reply.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum PoolError {
    InvalidDenomination, InvalidProof, NullifierAlreadySpent, NullifierReserved, AnchorNotFound,
    EscrowUnderfunded { required: u128, available: u128 },
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    CircuitVersionMismatch { expected: u32, got: u32 },
    VerifyingKeyMismatch, PoolVersionMismatch, TransferFailed(String),
    AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier, Paused, SolvencyCheckFailed, DuplicateWithdrawalId,
    NotInitialised, CommitmentAppendFailed(String), DepositCommitmentPending,
    SumMismatch { inputs: u128, outputs: u128 },
    SumOverflow, MalformedSpendArgs, DuplicateSpendId, SpendFeeNotSupported,
    VerifierUnavailable(String), ProofRejected(String),
    PrivateSpendFeeMismatch { expected: u128, got: u128 },
    InsufficientPrivateLiability { required: u128, available: u128 },
    WithdrawalBelowMinimum { withdraw_gross_amount: u128, minimum_withdrawal_gross: u128 },
    GrossAmountBelowFees { withdraw_gross_amount: u128, total_fee: u128 },
    RecipientBelowMinimum { recipient_net_amount: u128, minimum_recipient_amount: u128 },
    IdempotencyKeyConflict,
}

// Mirrors of the pool's treasury_disburse args/result — used by the direct-call
// idempotency-conflict test (v2c06).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TreasuryReserveBucket { Operations, Insurance, StakingRewards }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TreasuryDisburseArgs {
    proposal_id:          u64,
    bucket:               TreasuryReserveBucket,
    recipient:            Principal,
    recipient_subaccount: Option<[u8; 32]>,
    amount:               u128,
    expected_ledger_fee:  u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TreasuryDisburseResult {
    Executed        { block_index: Nat },
    AlreadyExecuted { block_index: Nat },
}

fn do_approve(pic: &PocketIc, token: Principal, owner: Principal, spender: Principal, amount: u128) {
    let r: Result<Nat, ApproveError> = decode(
        "icrc2_approve",
        pic.update_call(token, owner, "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: spender, subaccount: None },
                amount,
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
    r.expect("icrc2_approve must succeed in test setup");
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum FeeSource { ShieldFee, PrivateTransferFee, UnshieldFee, DexRevenue }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ProposalStatus { Pending, Executed, Rejected, Expired }

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
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
}

fn install_raw(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init_bytes: Vec<u8>) {
    pic.install_canister(cid, wasm, init_bytes, None);
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

fn treasury_bucket(pic: &PocketIc, treasury: Principal, name: &str) -> u128 {
    let opt: Option<u128> = decode(
        "get_subaccount_balance",
        pic.query_call(treasury, anon(), "get_subaccount_balance",
                       candid::encode_one(name.to_string()).unwrap()),
    );
    opt.unwrap_or(0)
}

fn get_proposal(pic: &PocketIc, treasury: Principal, id: u64) -> WithdrawalProposal {
    let proposals: Vec<WithdrawalProposal> = decode(
        "list_proposals",
        pic.query_call(treasury, anon(), "list_proposals", candid::encode_args(()).unwrap()),
    );
    proposals.into_iter().find(|p| p.id == id)
        .unwrap_or_else(|| panic!("proposal {} not found", id))
}

/// Install treasury with (token, pool, controller). Using `token_id` as the pool
/// is deliberate for the failure-path tests: it is a live canister that does NOT
/// implement `treasury_disburse`, so the disbursement call rejects cleanly.
fn install_treasury(pic: &PocketIc, treasury_id: Principal, token: Principal, pool: Principal, controller: Principal) {
    install_raw(pic, treasury_id, treasury_wasm(), candid::encode_args((token, pool, controller)).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// test_v2c01 — treasury holds no real STSH balance
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 1): under Option 2 the treasury never custodies real STSH. Its
// own icrc1_balance_of must be 0 across receive_fee_split (accounting only) and
// execute_withdrawal (which disburses via the pool, not from treasury's account).
// =============================================================================

#[test]
fn test_v2c01_treasury_holds_no_real_balance() {
    let pic = PocketIc::new();
    let controller = p(0xC1);
    let holder     = p(0x10); // token supply holder — NOT the treasury
    let recipient  = p(0x11);

    let token_id    = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(holder));
    // pool == token_id: a canister lacking treasury_disburse (failure path); the
    // assertion here is purely that treasury never holds real STSH.
    install_treasury(&pic, treasury_id, token_id, token_id, controller);

    assert_eq!(token_balance(&pic, token_id, treasury_id), 0, "treasury starts with 0 real STSH");

    // Accounting-only fee receipt (caller must be the configured pool == token_id).
    let _: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(treasury_id, token_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, 50_000_000u128, 0u128, 0u128, 0u64)).unwrap()),
    );
    assert_eq!(token_balance(&pic, token_id, treasury_id), 0,
        "receive_fee_split must not give treasury real STSH (accounting only)");

    // Propose + attempt to execute (disbursement fails: pool lacks treasury_disburse).
    let pid: u64 = decode(
        "propose_withdrawal",
        pic.update_call(treasury_id, controller, "propose_withdrawal",
            candid::encode_args(("operations".to_string(), recipient, 5_000_000u128, "v2c01".to_string())).unwrap()),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));
    let exec: Result<(), String> = decode(
        "execute_withdrawal",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()),
    );
    assert!(exec.is_err(), "execute must fail when pool lacks treasury_disburse; got {:?}", exec);

    // The core invariant after the full sequence.
    assert_eq!(token_balance(&pic, token_id, treasury_id), 0,
        "treasury must hold zero real STSH after receive_fee_split + execute_withdrawal");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_v2c02 — disbursement failure does not debit treasury buckets
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (Task 1, post-success-debit): if the pool disbursement call fails,
// the treasury bucket must NOT be debited (no debit without a confirmed
// disbursement), the proposal stays Pending (retryable), and recipient gets
// nothing. Mirrors v1's rewards_claim_no_silent_debit principle.
// =============================================================================

#[test]
fn test_v2c02_execute_withdrawal_disbursement_failure_no_double_debit() {
    let pic = PocketIc::new();
    let controller = p(0xC2);
    let holder     = p(0x20);
    let recipient  = p(0x21);

    let token_id    = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(holder));
    // pool == token_id (lacks treasury_disburse → the disbursement call rejects).
    install_treasury(&pic, treasury_id, token_id, token_id, controller);

    const AMOUNT: u128 = 5_000_000;
    let seed = AMOUNT + DEFAULT_FEE + 1_000; // enough to pass the local precheck
    let _: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(treasury_id, token_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, seed, 0u128, 0u128, 0u64)).unwrap()),
    );
    let ops_before = treasury_bucket(&pic, treasury_id, "operations");
    assert_eq!(ops_before, seed, "operations bucket seeded");

    let pid: u64 = decode(
        "propose_withdrawal",
        pic.update_call(treasury_id, controller, "propose_withdrawal",
            candid::encode_args(("operations".to_string(), recipient, AMOUNT, "v2c02".to_string())).unwrap()),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    let exec: Result<(), String> = decode(
        "execute_withdrawal",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()),
    );
    assert!(exec.is_err(), "disbursement must fail (pool lacks treasury_disburse); got {:?}", exec);

    // No debit on failure — the bucket is unchanged (post-success-debit).
    assert_eq!(treasury_bucket(&pic, treasury_id, "operations"), ops_before,
        "operations bucket must be UNCHANGED after a failed disbursement (no debit without success)");
    // Proposal stays Pending (retryable), recipient got nothing, treasury holds no real STSH.
    assert_eq!(get_proposal(&pic, treasury_id, pid).status, ProposalStatus::Pending,
        "proposal must remain Pending after a failed disbursement");
    assert_eq!(token_balance(&pic, token_id, recipient), 0, "recipient must receive nothing");
    assert_eq!(token_balance(&pic, token_id, treasury_id), 0, "treasury holds no real STSH");

    // A second execute must also fail cleanly (INFLIGHT released, not "already executing").
    let exec2: Result<(), String> = decode(
        "execute_withdrawal#2",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()),
    );
    assert!(exec2.is_err(), "second execute must also fail");
    assert!(!exec2.unwrap_err().contains("already executing"),
        "INFLIGHT must have been released after the first failure");
    assert_eq!(treasury_bucket(&pic, treasury_id, "operations"), ops_before,
        "still no debit after the second failed attempt");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_v2c03 — happy path: execute_withdrawal disburses via the pool
// ─────────────────────────────────────────────────────────────────────────────
//
// End-to-end happy path against the real shielded-pool treasury_disburse:
//   - deploy token (supply to depositor), the pool (treasury = treasury_id), and
//     treasury (pool = pool_id); fund OPERATIONS_RESERVE via a shielding-fee deposit;
//   - propose_withdrawal from "operations"; advance past the timelock;
//   - execute_withdrawal -> Ok(()); the POOL (not the treasury) transfers to recipient;
//   - recipient credited by exactly `amount`; treasury "operations" debited by
//     amount + ledger_fee exactly once; proposal Executed; treasury icrc1_balance == 0;
//   - a second execute returns "not Pending" (idempotent — no double pay/debit).
/// DEF-041 canonical BN254 Fr fixture: byte 0 = `b` (value < 256 < field modulus),
/// distinct and non-zero. Replaces `[0xNN; 32]` fill patterns whose repeated high
/// byte exceeds the modulus and is (correctly) rejected by the canonical check.
const fn canon(b: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0] = b;
    c
}

#[test]
fn test_v2c03_execute_withdrawal_disburses_via_pool() {
    let pic = PocketIc::new();
    let controller = p(0xC3);
    let depositor  = p(0x30);
    let recipient  = p(0x31);

    let token_id    = create_canister(&pic);
    let merkle_id   = create_canister(&pic);
    let pool_id     = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    // Merkle owned by the pool (the pool calls append_commitment during a deposit).
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool_id).unwrap(), None);
    // Token supply to the depositor, who funds the pool's escrow via a deposit.
    install(&pic, token_id, token_wasm(), &all_to(depositor));
    install(&pic, pool_id, pool_test_wasm(), &PoolInitArgs {
        token_canister: token_id,
        nullifier_canister: p(0x07),
        merkle_canister: merkle_id,
        treasury_canister: treasury_id,
        staking_canister: p(0x09),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
    });
    install_treasury(&pic, treasury_id, token_id, pool_id, controller);

    // Nonzero shielding fee so a deposit routes revenue into OPERATIONS_RESERVE and
    // notifies the treasury via receive_fee_split. Value-fee model (fee-build
    // lane): the flat-minimum field expresses a fixed shield fee.
    let shield_fee = 100 * STSH;
    let mut params = GovernanceFeeParams::launch_defaults();
    params.shield_flat_minimum_fee_e8s = Some(shield_fee);
    let set_res: Result<(), String> = decode("set_governance_fee_params_unchecked_for_test",
        pic.update_call(pool_id, controller, "set_governance_fee_params_unchecked_for_test",
                        candid::encode_one(params).unwrap()));
    assert!(set_res.is_ok(), "unchecked fee-params set must succeed; got {:?}", set_res);

    // Deposit a 1000-STSH denomination → funds pool escrow + OPERATIONS_RESERVE.
    // Fee-ON-TOP: the pool pulls deposit + shield fee, so approve for both.
    let deposit_amt = 1_000 * STSH;
    do_approve(&pic, token_id, depositor, pool_id, deposit_amt + shield_fee + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode("shield_deposit",
        pic.update_call(pool_id, depositor, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0xAB),
                encrypted_payload: vec![],
                public_amount: deposit_amt,
            }).unwrap()));
    assert!(dep.is_ok(), "shield_deposit must succeed; got {:?}", dep);

    // Let the pool's fire-and-forget receive_fee_split notification reach the treasury.
    for _ in 0..5 { pic.tick(); }

    // Observe the funded operations bucket and withdraw safely within it.
    let ops = treasury_bucket(&pic, treasury_id, "operations");
    assert!(ops > 2 * DEFAULT_FEE,
        "deposit must fund treasury's operations bucket via receive_fee_split; got {}", ops);
    let amount = ops / 2;

    let pid: u64 = decode("propose_withdrawal",
        pic.update_call(treasury_id, controller, "propose_withdrawal",
            candid::encode_args(("operations".to_string(), recipient, amount, "v2c03".to_string())).unwrap()));
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    // Happy path: the pool disburses; treasury performs NO self-transfer.
    let exec: Result<(), String> = decode("execute_withdrawal",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()));
    assert!(exec.is_ok(), "happy-path execute_withdrawal must succeed; got {:?}", exec);

    // Recipient credited by the POOL, exactly `amount`.
    assert_eq!(token_balance(&pic, token_id, recipient), amount,
        "recipient must receive exactly the withdrawal amount (from the pool, not treasury)");
    // Treasury bucket debited by amount + ledger_fee (post-success-debit).
    assert_eq!(treasury_bucket(&pic, treasury_id, "operations"), ops - amount - DEFAULT_FEE,
        "treasury operations bucket must be debited by amount + ledger_fee");
    // Proposal Executed; treasury never custodied real STSH.
    assert_eq!(get_proposal(&pic, treasury_id, pid).status, ProposalStatus::Executed, "proposal must be Executed");
    assert_eq!(token_balance(&pic, token_id, treasury_id), 0, "treasury holds no real STSH");

    // Idempotency: a second execute short-circuits at "not Pending" — no double pay, no double debit.
    let bal_after = token_balance(&pic, token_id, recipient);
    let ops_after = treasury_bucket(&pic, treasury_id, "operations");
    let exec2: Result<(), String> = decode("execute_withdrawal#2",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()));
    assert!(exec2.is_err(), "second execute must fail (proposal already Executed)");
    assert_eq!(token_balance(&pic, token_id, recipient), bal_after, "no double pay");
    assert_eq!(treasury_bucket(&pic, treasury_id, "operations"), ops_after, "no double debit");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_v2c04 — pool returns EscrowUnderfunded; treasury decodes it cleanly, no debit
// ─────────────────────────────────────────────────────────────────────────────
//
// DECODE CHECK (the hard one): drives the REAL Lane A treasury_disburse with a pool
// that holds no STSH, so the pool returns a STRUCTURED PoolError::EscrowUnderfunded.
// The treasury-side mirrored PoolError must DECODE it (the variant name appears in
// the surfaced error), proving a rejected disbursement is a clean failure path, not
// a Candid decode trap. And no treasury bucket is debited.
//
// Runs in the normal gate (the real shielded_pool with treasury_disburse is on base).
// =============================================================================

#[test]
fn test_v2c04_pool_error_decodes_cleanly_escrow_underfunded() {
    let pic = PocketIc::new();
    let controller = p(0xC4);
    let holder     = p(0x40); // token supply holder — the pool gets NO tokens
    let recipient  = p(0x41);

    let token_id    = create_canister(&pic);
    let pool_id     = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    install(&pic, token_id, token_wasm(), &all_to(holder));
    install(&pic, pool_id, pool_wasm(), &PoolInitArgs {
        token_canister: token_id,
        nullifier_canister: p(0x07),
        merkle_canister: p(0x08),
        treasury_canister: treasury_id, // so the pool's caller check accepts treasury
        staking_canister: p(0x09),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
    });
    install_treasury(&pic, treasury_id, token_id, pool_id, controller);

    // Fund treasury's local bucket so its precheck passes and the pool is reached.
    const AMOUNT: u128 = 5_000_000;
    let seed = AMOUNT + DEFAULT_FEE + 1_000;
    let _: Result<(), String> = decode("receive_fee_split",
        pic.update_call(treasury_id, pool_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, seed, 0u128, 0u128, 0u64)).unwrap()));
    let ops_before = treasury_bucket(&pic, treasury_id, "operations");

    let pid: u64 = decode("propose_withdrawal",
        pic.update_call(treasury_id, controller, "propose_withdrawal",
            candid::encode_args(("operations".to_string(), recipient, AMOUNT, "v2c04".to_string())).unwrap()));
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    let exec: Result<(), String> = decode("execute_withdrawal",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()));

    assert!(exec.is_err(), "execute must fail (pool holds no STSH); got {:?}", exec);
    let e = exec.unwrap_err();
    assert!(e.contains("EscrowUnderfunded"),
        "treasury must cleanly DECODE the pool's EscrowUnderfunded PoolError (not trap); got: {}", e);
    assert_eq!(treasury_bucket(&pic, treasury_id, "operations"), ops_before,
        "no debit on a decoded PoolError failure");
    assert_eq!(token_balance(&pic, token_id, recipient), 0, "recipient receives nothing");
    assert_eq!(get_proposal(&pic, treasury_id, pid).status, ProposalStatus::Pending, "proposal stays Pending");
    assert_eq!(token_balance(&pic, token_id, treasury_id), 0, "treasury holds no real STSH");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_v2c05 — pool returns InsufficientOperationsReserve; clean decode, no debit
// ─────────────────────────────────────────────────────────────────────────────
//
// Second real PoolError variant for decode coverage: here the pool HOLDS STSH
// (passes the escrow/available check) but its OPERATIONS_RESERVE is empty (no
// deposit funded it), so treasury_disburse returns
// PoolError::InsufficientOperationsReserve. Treasury must decode it cleanly and
// make no debit. Together with v2c04 this exercises two distinct structured
// PoolError replies through the treasury-side mirror.
// =============================================================================

#[test]
fn test_v2c05_pool_error_decodes_cleanly_insufficient_reserve() {
    let pic = PocketIc::new();
    let controller = p(0xC5);
    let recipient  = p(0x51);

    let token_id    = create_canister(&pic);
    let pool_id     = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    // Supply to the POOL so it has real STSH (passes the available check), but its
    // OPERATIONS_RESERVE accounting bucket is still 0 (no deposit funded it).
    install(&pic, token_id, token_wasm(), &all_to(pool_id));
    install(&pic, pool_id, pool_wasm(), &PoolInitArgs {
        token_canister: token_id,
        nullifier_canister: p(0x07),
        merkle_canister: p(0x08),
        treasury_canister: treasury_id,
        staking_canister: p(0x09),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
    });
    install_treasury(&pic, treasury_id, token_id, pool_id, controller);

    const AMOUNT: u128 = 5_000_000;
    let seed = AMOUNT + DEFAULT_FEE + 1_000;
    let _: Result<(), String> = decode("receive_fee_split",
        pic.update_call(treasury_id, pool_id, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, seed, 0u128, 0u128, 0u64)).unwrap()));
    let ops_before = treasury_bucket(&pic, treasury_id, "operations");

    let pid: u64 = decode("propose_withdrawal",
        pic.update_call(treasury_id, controller, "propose_withdrawal",
            candid::encode_args(("operations".to_string(), recipient, AMOUNT, "v2c05".to_string())).unwrap()));
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));

    let exec: Result<(), String> = decode("execute_withdrawal",
        pic.update_call(treasury_id, controller, "execute_withdrawal", candid::encode_one(pid).unwrap()));

    assert!(exec.is_err(), "execute must fail (pool operations reserve empty); got {:?}", exec);
    let e = exec.unwrap_err();
    assert!(e.contains("InsufficientOperationsReserve"),
        "treasury must cleanly DECODE the pool's InsufficientOperationsReserve PoolError; got: {}", e);
    assert_eq!(treasury_bucket(&pic, treasury_id, "operations"), ops_before,
        "no debit on a decoded PoolError failure");
    assert_eq!(token_balance(&pic, token_id, recipient), 0, "recipient receives nothing");
    assert_eq!(get_proposal(&pic, treasury_id, pid).status, ProposalStatus::Pending, "proposal stays Pending");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_v2c06 — IdempotencyKeyConflict decodes (the emphasized variant)
// ─────────────────────────────────────────────────────────────────────────────
//
// Directly proves the treasury-side PoolError mirror decodes IdempotencyKeyConflict.
// Fund the pool reserve via a deposit, call treasury_disburse DIRECTLY (as the
// treasury principal) with proposal_id=N → Executed; then call again with the SAME
// proposal_id but a DIFFERENT amount (fingerprint mismatch) → the pool returns
// PoolError::IdempotencyKeyConflict. If the mirror could not decode that variant,
// `decode()` would panic with a Candid error; matching Err(IdempotencyKeyConflict)
// proves a conflicting reuse is a clean, decodable failure.
// =============================================================================

#[test]
fn test_v2c06_idempotency_key_conflict_decodes() {
    let pic = PocketIc::new();
    let controller = p(0xC6);
    let depositor  = p(0x60);
    let recipient  = p(0x61);

    let token_id    = create_canister(&pic);
    let merkle_id   = create_canister(&pic);
    let pool_id     = create_canister(&pic);
    let treasury_id = create_canister(&pic);

    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool_id).unwrap(), None);
    install(&pic, token_id, token_wasm(), &all_to(depositor));
    install(&pic, pool_id, pool_test_wasm(), &PoolInitArgs {
        token_canister: token_id,
        nullifier_canister: p(0x07),
        merkle_canister: merkle_id,
        treasury_canister: treasury_id,
        staking_canister: p(0x09),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
    });
    install_treasury(&pic, treasury_id, token_id, pool_id, controller);

    // Fund the pool's OPERATIONS_RESERVE via a shielding-fee deposit. Value-fee
    // model: the flat-minimum field expresses a fixed shield fee; fee-ON-TOP so
    // approve for deposit + shield fee.
    let shield_fee = 100 * STSH;
    let mut params = GovernanceFeeParams::launch_defaults();
    params.shield_flat_minimum_fee_e8s = Some(shield_fee);
    let _: Result<(), String> = decode("set_governance_fee_params_unchecked_for_test",
        pic.update_call(pool_id, controller, "set_governance_fee_params_unchecked_for_test", candid::encode_one(params).unwrap()));
    do_approve(&pic, token_id, depositor, pool_id, 1_000 * STSH + shield_fee + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode("shield_deposit",
        pic.update_call(pool_id, depositor, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: canon(0xCD), encrypted_payload: vec![], public_amount: 1_000 * STSH,
            }).unwrap()));
    assert!(dep.is_ok(), "shield_deposit must succeed; got {:?}", dep);
    for _ in 0..5 { pic.tick(); }

    // First DIRECT disbursement (as the treasury principal): proposal_id = 999, amount = a.
    let a: u128 = 5 * STSH;
    let args1 = TreasuryDisburseArgs {
        proposal_id: 999, bucket: TreasuryReserveBucket::Operations,
        recipient, recipient_subaccount: None, amount: a, expected_ledger_fee: DEFAULT_FEE,
    };
    let r1: Result<TreasuryDisburseResult, PoolError> = decode("treasury_disburse#1",
        pic.update_call(pool_id, treasury_id, "treasury_disburse", candid::encode_one(args1).unwrap()));
    assert!(matches!(r1, Ok(TreasuryDisburseResult::Executed { .. })),
        "first direct disbursement must be Executed; got {:?}", r1);

    // Second call: SAME proposal_id, DIFFERENT amount → fingerprint mismatch.
    let args2 = TreasuryDisburseArgs {
        proposal_id: 999, bucket: TreasuryReserveBucket::Operations,
        recipient, recipient_subaccount: None, amount: a + 1, expected_ledger_fee: DEFAULT_FEE,
    };
    let r2: Result<TreasuryDisburseResult, PoolError> = decode("treasury_disburse#2",
        pic.update_call(pool_id, treasury_id, "treasury_disburse", candid::encode_one(args2).unwrap()));
    assert!(matches!(r2, Err(PoolError::IdempotencyKeyConflict)),
        "conflicting reuse of proposal_id must decode to IdempotencyKeyConflict; got {:?}", r2);
}
