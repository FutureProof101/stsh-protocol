// =============================================================================
// STSH — M3 Track C Upgrade Survival Tests (PocketIC)
// =============================================================================
//
// These tests verify that the pre/post_upgrade hooks correctly preserve all
// heap-only state across canister upgrades.  All state that lives only in
// thread_local heap variables must be serialised in pre_upgrade and fully
// restored in post_upgrade — never falling back to thread_local defaults.
//
// PM requirement (non-negotiable):
//   "Do not rely on default thread_local initializers for protocol state after
//    post_upgrade. Defaults are only valid for fresh init, never for upgrade
//    recovery."
//
// Track C acceptance criteria (7 required tests):
//   test_47 — CommitmentPending deposit record survives pool upgrade
//   test_48 — SolvencyBlocked withdrawal survives upgrade → resumes → Finalized
//   test_49 — FeeReimbursementPending record + accounting buckets survive upgrade
//   test_50 — Merkle root history survives merkle upgrade (anchor still valid)
//   test_51 — Nullifier spent set survives nullifier-registry upgrade
//   test_52 — All 6 accounting buckets survive pool upgrade exactly
//   test_53 — Staking governance params + voting weight survive staking upgrade
//
// M4 Poseidon migration regression (1 required test):
//   test_54 — Poseidon zero-root regression: [0u8;32] is never a valid anchor
//
// P4 upgrade persistence (2 required tests):
//   test_55 — Treasury proposals + subaccount balances survive treasury upgrade
//   test_56 — Vesting schedule + claimed amount survive vesting upgrade
//
// PREREQUISITES:
//   1. Build canister Wasm:
//      cargo build --target wasm32-unknown-unknown --release \
//          -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree \
//          -p treasury -p vesting
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests
//
// TRACK C GATE:
//   cargo test 2>&1 | grep "^test result"  →  all crates: N passed, 0 failed, 0 ignored
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

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release \\\n    \
             -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree",
            pkg, path, e
        )
    })
}

fn token_wasm() -> Vec<u8> {
    load_wasm(env!("TOKEN_WASM"), "stsh_token")
}
fn staking_wasm() -> Vec<u8> {
    load_wasm(env!("STAKING_WASM"), "staking")
}
fn pool_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_WASM"), "shielded_pool")
}
fn pool_test_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test")
}
fn nullifier_wasm() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry")
}
fn merkle_wasm() -> Vec<u8> {
    load_wasm(env!("MERKLE_WASM"), "merkle_tree")
}
fn treasury_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_WASM"), "treasury")
}
fn vesting_wasm() -> Vec<u8> {
    load_wasm(env!("VESTING_WASM"), "vesting")
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants (mirrored from canister source)
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOMINATIONS: [u128; 5] = [
    // A6.6 five-tier launch ladder — mirrors the pool's own DENOMINATIONS.
    1_000 * 100_000_000,
    10_000 * 100_000_000,
    100_000 * 100_000_000,
    1_000_000 * 100_000_000,
    10_000_000 * 100_000_000,
];
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch

// ─────────────────────────────────────────────────────────────────────────────
// Candid type mirrors
//
// Canister crates use crate-type = ["cdylib"] which prevents linking them as
// normal Rust deps.  We mirror only the types each test needs for encoding/
// decoding — field names must exactly match the canister Candid type.
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
struct VestingPolicy {
    cliff_end_ns: u64,
    vesting_end_ns: u64,
}

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
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
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

// For test_36 / test_48 top-up via icrc1_transfer
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

// ── Staking ───────────────────────────────────────────────────────────────────

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

impl GovernanceParams {
    /// P-STK K3-015: `GovernanceParams::validate()` now runs at INIT, so a
    /// sub-floor timelock is no longer installable — a policy floor that tests
    /// can opt out of at install is not a floor. The voting window stays short
    /// (it is a test-speed knob, not a policy floor); the two TIMELOCKS are the
    /// real 7-day and 14-day floors, and the tests advance time past them.
    fn fast() -> Self {
        GovernanceParams {
            min_proposal_deposit: 1_000 * 100_000_000,
            voting_delay_ns: 0,
            voting_period_ns: 1_000_000_000,
            execution_timelock_ns: 7 * 24 * 60 * 60 * 1_000_000_000,  // 7d policy floor
            vk_upgrade_timelock_ns: 14 * 24 * 60 * 60 * 1_000_000_000, // 14d floor
            quorum_bps: 1,
            treasury_quorum_bps: 1,
            vk_quorum_bps: 1,
            approval_threshold_bps: 5001,
        }
    }
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

// ── Pool ──────────────────────────────────────────────────────────────────────

#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version: u32,
    proof_system_id: String,
    verifying_key_hash: [u8; 32],
    root_reference: [u8; 32],
    pool_version: u32,
    proof_bytes: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct WithdrawArgs {
    withdrawal_id: u64,
    envelope: ProofEnvelope,
    nullifier: [u8; 32],
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    gross_withdraw_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    InsufficientEscrowCoverage {
        requested: u128,
        available: u128,
    },
    EscrowUnderfunded {
        required: u128,
        available: u128,
    },
    CircuitVersionMismatch {
        expected: u32,
        got: u32,
    },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee {
        amount: u128,
        fee: u128,
    },
    BelowMinimumDeposit {
        public_amount: u128,
        minimum: u128,
    },
    InsufficientOperationsReserve {
        needed: u128,
        available: u128,
    },
    InvariantViolationDuplicateNullifier,
    Paused,
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch {
        inputs: u128,
        outputs: u128,
    },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateSpendId,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    PrivateSpendFeeMismatch {
        expected: u128,
        got: u128,
    },
    InsufficientPrivateLiability {
        required: u128,
        available: u128,
    },
    WithdrawalBelowMinimum {
        withdraw_gross_amount: u128,
        minimum_withdrawal_gross: u128,
    },
    GrossAmountBelowFees {
        withdraw_gross_amount: u128,
        total_fee: u128,
    },
    RecipientBelowMinimum {
        recipient_net_amount: u128,
        minimum_recipient_amount: u128,
    },
    // QA-DEF-017 deposit state-machine guards (subset needed by test_47).
    DepositTransferNotConfirmed,
    DepositAppendInProgress,
    DepositAppendUnknown,
    DepositAlreadyCompleted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum WithdrawalStatus {
    Requested,
    ProofVerified,
    NullifierReserved,
    SolvencyBlocked { required: u128, available: u128 },
    EscrowCoverageChecked,
    LedgerTransferPending,
    FeeReimbursementPending { ledger_fee: u128 },
    Finalized,
    FailedRetryable,
    FailedTerminalUserError { reason: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingWithdrawal {
    withdrawal_id: u64,
    nullifier: [u8; 32],
    destination: Principal,
    gross_withdraw_amount: u128,
    recipient_net_amount: u128,
    ledger_fee: u128,
    protocol_unshielding_fee: u128,
    status: WithdrawalStatus,
    created_at_ns: u64,
    finalized_at_ns: Option<u64>,
    ledger_memo: Option<Vec<u8>>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending, // deprecated (pre-QA-DEF-017) — decode-compat only
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown, // QA-DEF-017: transport-unknown append outcome
    CommitmentReconcileInFlight, // DEF-098: transient reconcile claim
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] }, // DEF-040/P-ROOT terminal
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingDeposit {
    note_commitment: [u8; 32],
    private_balance: u128,
    ops_amount: u128,
    insurance_amount: u128,
    encrypted_payload: Vec<u8>,
    depositor: Option<Principal>,  // F2-REDACT: opt principal
    status: DepositStatus,
    created_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
}

// ── Vesting ───────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_end_ns: u64,
    vesting_end_ns: u64,
    claimed: u128,
    start_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize)]
struct NewSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_months: u32,
    linear_months: u32,
}

#[derive(CandidType, Serialize, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal,
    controller: Principal,
    schedules: Vec<NewSchedule>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal {
    Principal::anonymous()
}

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
    let bytes = result.unwrap_or_else(|e| panic!("{}: call was rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

/// Upgrade a canister in-place.  pre_upgrade runs on old wasm → wasm replaced
/// → post_upgrade runs on new wasm.  post_upgrade takes no arguments, so we
/// pass the empty Candid argument tuple.
///
/// IMPORTANT: the installed code must already have pre_upgrade implemented
/// (i.e. this is NOT the first upgrade from empty pre_upgrade).  All upgrade
/// tests install the current wasm (which has pre/post_upgrade), so this holds.
fn upgrade_canister(pic: &PocketIc, cid: Principal, wasm: Vec<u8>) {
    pic.upgrade_canister(cid, wasm, candid::encode_args(()).unwrap(), None)
        .expect("upgrade_canister: pre/post_upgrade hooks trapped or controller check failed");
}

// ── Query helpers ─────────────────────────────────────────────────────────────

fn token_balance(pic: &PocketIc, token_id: Principal, owner: Principal) -> u128 {
    let bal: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            token_id,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account {
                owner,
                subaccount: None,
            })
            .unwrap(),
        ),
    );
    bal.0.to_string().parse::<u128>().unwrap_or(0)
}

fn accounting_state(pic: &PocketIc, pool_id: Principal) -> AccountingState {
    decode(
        "get_accounting_state",
        // DEF-076: get_accounting_state is controller-gated; these tests deploy with p(0x06).
        pic.query_call(
            pool_id,
            p(0x06),
            "get_accounting_state",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn deposit_status(pic: &PocketIc, pool_id: Principal, nc: [u8; 32]) -> Option<PendingDeposit> {
    decode(
        "get_deposit_status",
        pic.query_call(
            pool_id,
            // DEF-070: get_deposit_status is owner-or-controller gated — poll as controller.
            p(0x06),
            "get_deposit_status",
            candid::encode_one(nc).unwrap(),
        ),
    )
}

fn withdrawal_status(pic: &PocketIc, pool_id: Principal, wid: u64) -> Option<PendingWithdrawal> {
    decode(
        "get_withdrawal_status",
        pic.query_call(
            pool_id,
            // DEF-071: get_withdrawal_status is controller-only in Phase A — poll as controller.
            p(0x06),
            "get_withdrawal_status",
            candid::encode_one(wid).unwrap(),
        ),
    )
}

fn merkle_leaf_count(pic: &PocketIc, merkle_id: Principal) -> u64 {
    decode(
        "leaf_count",
        pic.query_call(
            merkle_id,
            anon(),
            "leaf_count",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Query the Merkle canister's current root (Poseidon empty-tree root on a fresh canister).
fn merkle_root(pic: &PocketIc, merkle_id: Principal) -> [u8; 32] {
    let bytes: Vec<u8> = decode(
        "merkle_root: get_root",
        pic.query_call(
            merkle_id,
            anon(),
            "get_root",
            candid::encode_args(()).unwrap(),
        ),
    );
    bytes
        .try_into()
        .expect("get_root must return exactly 32 bytes")
}

fn merkle_is_valid_anchor(pic: &PocketIc, merkle_id: Principal, root: Vec<u8>) -> bool {
    decode(
        "is_valid_anchor",
        pic.query_call(
            merkle_id,
            anon(),
            "is_valid_anchor",
            candid::encode_one(root).unwrap(),
        ),
    )
}

fn pool_vk_hash(pic: &PocketIc, pool_id: Principal) -> [u8; 32] {
    decode(
        "get_pinned_vk_hash",
        pic.query_call(
            pool_id,
            anon(),
            "get_pinned_vk_hash",
            candid::encode_args(()).unwrap(),
        ),
    )
}

// ── Write helpers ─────────────────────────────────────────────────────────────

fn do_approve(
    pic: &PocketIc,
    token_id: Principal,
    caller: Principal,
    spender: Principal,
    amount: u128,
) {
    let r: Result<Nat, ApproveError> = decode(
        "do_approve",
        pic.update_call(
            token_id,
            caller,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: spender,
                    subaccount: None,
                },
                amount: Nat::from(amount),
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee: None,
                memo: None,
                created_at_time: None,
            })
            .unwrap(),
        ),
    );
    r.expect("icrc2_approve must succeed in test setup");
}

/// shield_deposit with an explicit note_commitment.  Returns net private_balance.
fn do_deposit(
    pic: &PocketIc,
    token_id: Principal,
    pool_id: Principal,
    user: Principal,
    commitment: [u8; 32],
    public_amount: u128,
) -> u128 {
    do_approve(pic, token_id, user, pool_id, public_amount + DEFAULT_FEE);
    let result: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![],
                public_amount,
            })
            .unwrap(),
        ),
    );
    let nat = result.expect("shield_deposit must succeed");
    nat.0.to_string().parse::<u128>().unwrap_or(0)
}

// ── Token init helpers ────────────────────────────────────────────────────────

fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
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
        staking_canister: staking,
    }
}

/// Two-allocation init: user_amount to user, pool_amount to pool, remainder to p(0xFE).
fn split_token_init(
    user: Principal,
    user_amount: u128,
    pool_id: Principal,
    pool_amount: u128,
    staking: Principal,
) -> TokenInitArgs {
    let remainder = TOTAL_SUPPLY
        .saturating_sub(user_amount)
        .saturating_sub(pool_amount);
    let mut allocs = vec![AllocationCategory {
        category_id: "user".to_string(),
        category_name: "Test user".to_string(),
        amount: user_amount,
        recipient: user,
        subaccount: None,
        lock_policy: LockPolicy::ImmediatelyLiquid,
        vesting_policy: None,
        created_at_genesis: false,
        genesis_timestamp_ns: 0,
    }];
    if pool_amount > 0 {
        allocs.push(AllocationCategory {
            category_id: "pool_reserve".to_string(),
            category_name: "Pool fee reserve".to_string(),
            amount: pool_amount,
            recipient: pool_id,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        });
    }
    if remainder > 0 {
        allocs.push(AllocationCategory {
            category_id: "other".to_string(),
            category_name: "Other".to_string(),
            amount: remainder,
            recipient: p(0xFE),
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        });
    }
    TokenInitArgs {
        allocations: allocs,
        treasury: p(0x01),
        staking_canister: staking,
    }
}

// =============================================================================
// Test 47 — CommitmentPending deposit record survives pool upgrade
// =============================================================================
//
// A shield_deposit whose Merkle append fails enters CommitmentPending.  The
// deposit record is stored in PENDING_DEPOSITS (StableBTreeMap — survives the
// upgrade automatically).  The pool's heap-only configuration (token/nullifier/
// merkle canister refs, vk_hash, etc.) is serialised in pre_upgrade and
// restored in post_upgrade.
//
// INVARIANTS verified:
//   a) CommitmentPending record exists before upgrade.
//   b) Pool upgrade succeeds (neither pre_upgrade nor post_upgrade trap).
//   c) CommitmentPending record is accessible after upgrade with identical data.
//   d) Pool configuration (vk_hash, canister refs) survived — pool is functional.
//   e) retry_deposit_commitment is still routable after upgrade (doesn't panic
//      with "pool not initialised"; returns CommitmentAppendFailed because
//      the fake merkle is still unreachable — proving heap config was restored).
// =============================================================================

/// DEF-041 canonical BN254 Fr fixture: a distinct, non-zero commitment that is < the
/// field modulus. Only byte 0 is set, so the little-endian value equals `b` (< 256).
/// Replaces `[0xNN; 32]` fill patterns whose repeated high byte exceeds the modulus
/// and is (correctly) rejected by the canonical-commitment check.
const fn canon(b: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0] = b;
    c
}

#[test]
fn test_47_commitment_pending_survives_pool_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x47);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    // Use a non-existent Merkle principal — append_commitment call will fail,
    // leaving the deposit in CommitmentPending state.
    let fake_merkle = p(0x03);

    const VK: [u8; 32] = [0x47u8; 32];
    const COMMITMENT: [u8; 32] = canon(0x47);

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: fake_merkle,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: VK,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // ── a) Create CommitmentPending state ─────────────────────────────────────
    do_approve(
        &pic,
        token_id,
        user,
        pool_id,
        DENOMINATIONS[0] + DEFAULT_FEE,
    );
    let deposit_result: Result<Nat, PoolError> = decode(
        "test_47: shield_deposit with unreachable Merkle",
        pic.update_call(
            pool_id,
            user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: COMMITMENT,
                encrypted_payload: vec![],
                public_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(deposit_result, Err(PoolError::CommitmentAppendFailed(_))),
        "test_47: expected CommitmentAppendFailed from unreachable Merkle; got {:?}",
        deposit_result
    );

    // H-1 (T1): the unreachable Merkle fails the `leaf_count` snapshot that now precedes
    // the append claim, so the append is NEVER issued and the deposit lands cleanly at the
    // RETRYABLE TransferConfirmedCommitmentPending (not the pre-H-1 unreconcilable
    // CommitmentAppendUnknown+None). The point of this test — that the pending deposit
    // record survives a pool upgrade in a recoverable state — is unchanged.
    let pre = deposit_status(&pic, pool_id, COMMITMENT)
        .expect("test_47: deposit record must exist before upgrade");
    assert_eq!(
        pre.status,
        DepositStatus::TransferConfirmedCommitmentPending,
        "test_47: deposit must be TransferConfirmedCommitmentPending before upgrade (H-1); got {:?}",
        pre.status
    );

    // ── b) Upgrade pool ───────────────────────────────────────────────────────
    upgrade_canister(&pic, pool_id, pool_wasm());

    // ── c) Pending deposit record survives ─────────────────────────────────────
    let post = deposit_status(&pic, pool_id, COMMITMENT)
        .expect("test_47: deposit record must survive pool upgrade");
    assert_eq!(
        post.status,
        DepositStatus::TransferConfirmedCommitmentPending,
        "test_47: TransferConfirmedCommitmentPending must survive pool upgrade (H-1 Preserve); got {:?}",
        post.status
    );
    assert_eq!(
        post.private_balance, pre.private_balance,
        "test_47: private_balance must be unchanged after upgrade"
    );
    assert_eq!(
        post.note_commitment, COMMITMENT,
        "test_47: note_commitment must be unchanged after upgrade"
    );

    // ── d) Pool configuration survived ───────────────────────────────────────
    let vk_after = pool_vk_hash(&pic, pool_id);
    assert_eq!(
        vk_after, VK,
        "test_47: vk_hash must survive pool upgrade (heap scalar restoration)"
    );

    // ── e) retry_deposit_commitment still routes correctly after upgrade ───────
    //
    // H-1 (T1): the deposit survived the upgrade RETRYABLE (TransferConfirmedCommitmentPending).
    // retry_deposit_commitment re-runs snapshot_claim_and_append; the Merkle is still the
    // unreachable p(0x03), so the `leaf_count` snapshot fails again → CommitmentAppendFailed,
    // with the deposit left pending (no append issued, no credit). This proves the record is
    // recoverable — liveness preserved (once a reachable Merkle exists, retry credits) — in
    // contrast to the pre-H-1 CommitmentAppendUnknown dead-end (DepositAppendUnknown).
    let retry: Result<Nat, PoolError> = decode(
        "test_47: retry_deposit_commitment after upgrade",
        pic.update_call(
            pool_id,
            user,
            "retry_deposit_commitment",
            candid::encode_one(COMMITMENT).unwrap(),
        ),
    );
    assert!(
        matches!(retry, Err(PoolError::CommitmentAppendFailed(_))),
        "test_47: retry of the surviving pending deposit re-attempts the append and fails on \
         the still-unreachable Merkle (CommitmentAppendFailed), leaving it retryable; got {:?}",
        retry
    );
    // And the record remains recoverable (still pending), not stuck.
    let after_retry = deposit_status(&pic, pool_id, COMMITMENT)
        .expect("test_47: deposit record must persist after a failed retry");
    assert_eq!(
        after_retry.status,
        DepositStatus::TransferConfirmedCommitmentPending,
        "test_47: deposit stays retryable after a failed retry (H-1); got {:?}",
        after_retry.status
    );
}

// =============================================================================
// Test 48 — SolvencyBlocked withdrawal survives pool upgrade → resumes → Finalized
// =============================================================================
//
// A withdrawal that found escrow insufficient enters SolvencyBlocked with its
// nullifier reserved in the pool-local map.  The WITHDRAWALS StableBTreeMap
// carries the record through the upgrade automatically; the heap-only state
// (accounting buckets, canister refs) is restored via pre/post_upgrade hooks.
//
// §7: required = ledger_debit_from_pool = gross - protocol_unshielding_fee = gross.
// Pool must hold DENOMINATIONS[0] - 1 (one short) to trigger SolvencyBlocked.
// Top-up of 1 brings pool to DENOMINATIONS[0] and allows resume.
//
// INVARIANTS verified:
//   a) W1 enters SolvencyBlocked before upgrade.
//   b) Pool upgrade succeeds.
//   c) W1 is still SolvencyBlocked after upgrade.
//   d) Top-up pool by 1 via icrc1_transfer.
//   e) resume_blocked_withdrawal(W1) succeeds after upgrade.
//   f) W1 reaches Finalized (§7: FeeReimbursementPending not produced).
//   g) Nullifier IS in the permanent registry after resumption.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises solvency-blocked withdrawal records, resume, and nullifier finalization across pool upgrade, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: solvency-blocked upgrade coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_48_solvency_blocked_survives_pool_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x48);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    const VK: [u8; 32] = [0x48u8; 32];
    const NULLIFIER: [u8; 32] = [0x18u8; 32];
    const WID: u64 = 4800;

    // Pool pre-funded with DENOMINATIONS[0] - 1 (one short of required = gross).
    // §7 escrow check: required = gross = DENOMINATIONS[0] > available = DENOMINATIONS[0]-1.
    let init = split_token_init(
        user,
        TOTAL_SUPPLY - (DENOMINATIONS[0] - 1),
        pool_id,
        DENOMINATIONS[0] - 1,
        p(0x02),
    );
    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: VK,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    let _: () = decode(
        "test_48: inject PRIVATE_LIABILITY",
        pic.update_call(
            pool_id,
            p(0x06),
            "inject_private_liability_for_test",
            candid::encode_one(DENOMINATIONS[0]).unwrap(),
        ),
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: VK,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // ── a) W1 → SolvencyBlocked ───────────────────────────────────────────────
    let w1: Result<Nat, PoolError> = decode(
        "test_48: W1 → SolvencyBlocked",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: WID,
                envelope: env,
                nullifier: NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        matches!(w1, Err(PoolError::EscrowUnderfunded { .. })),
        "test_48: W1 must return EscrowUnderfunded; got {:?}",
        w1
    );

    // ── b) Upgrade pool ───────────────────────────────────────────────────────
    upgrade_canister(&pic, pool_id, pool_wasm());

    // ── c) W1 still SolvencyBlocked after upgrade ─────────────────────────────
    let rec_post_upgrade = withdrawal_status(&pic, pool_id, WID)
        .expect("test_48: withdrawal record must survive pool upgrade");
    assert!(
        matches!(
            rec_post_upgrade.status,
            WithdrawalStatus::SolvencyBlocked { .. }
        ),
        "test_48: W1 must still be SolvencyBlocked after pool upgrade; got {:?}",
        rec_post_upgrade.status
    );
    assert_eq!(
        rec_post_upgrade.nullifier, NULLIFIER,
        "test_48: nullifier in record must be unchanged after upgrade"
    );

    // ── d) Top up pool by 1 ───────────────────────────────────────────────────
    //
    // icrc1_transfer debits (amount + fee) from user and credits amount to pool.
    // Pool was DENOMINATIONS[0]-1; needs DENOMINATIONS[0]. Top-up by 1.
    let top_up: Result<Nat, TransferError> = decode(
        "test_48: top-up pool by 1",
        pic.update_call(
            token_id,
            user,
            "icrc1_transfer",
            candid::encode_one(TransferArgs {
                from_subaccount: None,
                to: Account {
                    owner: pool_id,
                    subaccount: None,
                },
                amount: Nat::from(1u64),
                fee: Some(Nat::from(DEFAULT_FEE)),
                memo: None,
                created_at_time: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        top_up.is_ok(),
        "test_48: top-up transfer must succeed; got {:?}",
        top_up
    );

    // ── e) resume_blocked_withdrawal after upgrade ────────────────────────────
    let resume: Result<Nat, PoolError> = decode(
        "test_48: resume_blocked_withdrawal after upgrade",
        pic.update_call(
            pool_id,
            user,
            "resume_blocked_withdrawal",
            candid::encode_one(WID).unwrap(),
        ),
    );
    assert!(
        resume.is_ok(),
        "test_48: resume must succeed after top-up + upgrade; got {:?}",
        resume
    );

    // ── f) W1 reaches Finalized (§7: FeeReimbursementPending not produced) ────
    let final_rec =
        withdrawal_status(&pic, pool_id, WID).expect("test_48: final withdrawal record must exist");
    assert!(
        matches!(final_rec.status, WithdrawalStatus::Finalized),
        "test_48: §7: W1 must be Finalized after resume; got {:?}",
        final_rec.status
    );

    // ── g) Nullifier IS in the permanent registry ─────────────────────────────
    let in_reg: bool = decode(
        "test_48: contains_nullifier after finalization",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        in_reg,
        "test_48: nullifier must be in registry after successful resume + finalization"
    );
}

// =============================================================================
// Test 49 — Finalized withdrawal record + accounting survive pool upgrade
// =============================================================================
//
// After a successful §7 withdrawal (always Finalized), both the WITHDRAWALS
// StableBTreeMap record and the 6-bucket accounting heap scalars must survive
// the pool upgrade unchanged.
//
// INVARIANTS verified:
//   a) Withdrawal succeeds → Finalized before upgrade.
//   b) All 6 accounting buckets recorded before upgrade.
//   c) Pool upgrade succeeds.
//   d) Finalized record still exists after upgrade with correct fields.
//   e) All 6 accounting buckets match exactly after upgrade.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises finalized withdrawal records and accounting buckets across pool upgrade, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: finalized-withdrawal upgrade coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_49_fee_reimbursement_pending_survives_pool_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x49);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    const VK: [u8; 32] = [0x49u8; 32];
    const NULLIFIER: [u8; 32] = [0x19u8; 32];
    const WID: u64 = 4900;

    // Fund pool directly with DENOMINATIONS[0] (sufficient for gross = DENOMINATIONS[0]).
    // §7: required = gross = DENOMINATIONS[0] = available → withdrawal succeeds.
    let init = split_token_init(
        user,
        TOTAL_SUPPLY - DENOMINATIONS[0],
        pool_id,
        DENOMINATIONS[0],
        p(0x02),
    );
    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: VK,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    let _: () = decode(
        "test_49: inject PRIVATE_LIABILITY",
        pic.update_call(
            pool_id,
            p(0x06),
            "inject_private_liability_for_test",
            candid::encode_one(DENOMINATIONS[0]).unwrap(),
        ),
    );

    // ── a) Withdraw → Finalized ───────────────────────────────────────────────
    let root_49 = merkle_root(&pic, merkle_id);
    let w: Result<Nat, PoolError> = decode(
        "test_49: withdraw",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: WID,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: VK,
                    root_reference: root_49,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifier: NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(w.is_ok(), "test_49: withdrawal must succeed; got {:?}", w);

    let rec_before =
        withdrawal_status(&pic, pool_id, WID).expect("test_49: withdrawal record must exist");
    assert_eq!(
        rec_before.status,
        WithdrawalStatus::Finalized,
        "test_49: §7: status must be Finalized before upgrade; got {:?}",
        rec_before.status
    );
    assert_eq!(
        rec_before.gross_withdraw_amount, DENOMINATIONS[0],
        "test_49: gross_withdraw_amount must equal DENOMINATIONS[0]"
    );
    assert_eq!(
        rec_before.ledger_fee, DEFAULT_FEE,
        "test_49: ledger_fee must equal DEFAULT_FEE"
    );
    assert_eq!(
        rec_before.recipient_net_amount,
        DENOMINATIONS[0] - DEFAULT_FEE,
        "test_49: recipient_net_amount must equal gross - ledger_fee"
    );

    // ── b) Record all 6 accounting buckets before upgrade ─────────────────────
    let acc_before = accounting_state(&pic, pool_id);
    assert_eq!(
        acc_before.pending_fee_reimbursements, 0,
        "test_49: §7: pending_fee_reimbursements must be 0 (no FeeReimbursementPending path)"
    );

    // ── c) Upgrade pool ───────────────────────────────────────────────────────
    upgrade_canister(&pic, pool_id, pool_wasm());

    // ── d) Finalized record still exists after upgrade ────────────────────────
    let rec_after = withdrawal_status(&pic, pool_id, WID)
        .expect("test_49: withdrawal record must survive pool upgrade");
    assert_eq!(
        rec_after.status,
        WithdrawalStatus::Finalized,
        "test_49: Finalized record must survive pool upgrade; got {:?}",
        rec_after.status
    );
    assert_eq!(
        rec_after.gross_withdraw_amount, rec_before.gross_withdraw_amount,
        "test_49: gross_withdraw_amount must survive upgrade"
    );
    assert_eq!(
        rec_after.ledger_fee, rec_before.ledger_fee,
        "test_49: ledger_fee must survive upgrade"
    );
    assert_eq!(
        rec_after.recipient_net_amount, rec_before.recipient_net_amount,
        "test_49: recipient_net_amount must survive upgrade"
    );

    // ── e) All 6 accounting buckets match exactly ─────────────────────────────
    //
    // These are heap scalars (thread_local RefCell<u128>), serialised in
    // pre_upgrade and restored in post_upgrade.  Any mismatch indicates a
    // field was silently defaulted to 0 instead of being restored.
    let acc_after = accounting_state(&pic, pool_id);
    assert_eq!(
        acc_after.private_liability, acc_before.private_liability,
        "test_49: private_liability must survive upgrade exactly"
    );
    assert_eq!(
        acc_after.escrow_backing, acc_before.escrow_backing,
        "test_49: escrow_backing must survive upgrade exactly"
    );
    assert_eq!(
        acc_after.operations_reserve, acc_before.operations_reserve,
        "test_49: operations_reserve must survive upgrade exactly"
    );
    assert_eq!(
        acc_after.insurance_reserve, acc_before.insurance_reserve,
        "test_49: insurance_reserve must survive upgrade exactly"
    );
    assert_eq!(
        acc_after.governance_rewards_reserve, acc_before.governance_rewards_reserve,
        "test_49: governance_rewards_reserve must survive upgrade exactly"
    );
    assert_eq!(
        acc_after.pending_fee_reimbursements, acc_before.pending_fee_reimbursements,
        "test_49: pending_fee_reimbursements must survive upgrade exactly"
    );
}

// =============================================================================
// Test 50 — Merkle root history survives merkle upgrade (anchor still valid)
// =============================================================================
//
// ROOT_HISTORY is a StableBTreeMap — it survives the upgrade automatically.
// LEAF_COUNT and ROOT_INDEX are heap-only counters re-derived in post_upgrade
// from the stable structures (COMMITMENTS.len() and leaf_count + 1).
// POOL_CANISTER is heap-only and serialised in pre_upgrade.
//
// INVARIANTS verified:
//   a) shield_deposit creates one Merkle leaf (leaf_count 0→1) and a new root.
//   b) get_root() returns a valid anchor before upgrade.
//   c) Merkle upgrade succeeds.
//   d) is_valid_anchor(pre-upgrade root) = true after upgrade.
//   e) leaf_count() is correctly re-derived = 1 after upgrade.
//   f) POOL_CANISTER survived — a second shield_deposit (which calls
//      append_commitment) succeeds after upgrade, proving pool access control
//      was correctly restored.
// =============================================================================

#[test]
fn test_50_merkle_root_history_survives_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x50);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    const VK: [u8; 32] = [0x50u8; 32];
    const NC1: [u8; 32] = canon(0x51); // first deposit commitment
    const NC2: [u8; 32] = canon(0x52); // second deposit commitment (post-upgrade)

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: VK,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // ── a) shield_deposit creates a Merkle leaf ───────────────────────────────
    do_deposit(&pic, token_id, pool_id, user, NC1, DENOMINATIONS[0]);

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_50: leaf_count must be 1 after one deposit"
    );

    // ── b) Record current root ────────────────────────────────────────────────
    let root_before: Vec<u8> = decode(
        "test_50: get_root before upgrade",
        pic.query_call(
            merkle_id,
            anon(),
            "get_root",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(
        merkle_is_valid_anchor(&pic, merkle_id, root_before.clone()),
        "test_50: root must be valid anchor before upgrade"
    );

    // ── c) Upgrade merkle ─────────────────────────────────────────────────────
    upgrade_canister(&pic, merkle_id, merkle_wasm());

    // ── d) is_valid_anchor still true after upgrade ───────────────────────────
    //
    // ROOT_HISTORY is a StableBTreeMap — entries survive the upgrade.
    assert!(
        merkle_is_valid_anchor(&pic, merkle_id, root_before.clone()),
        "test_50: pre-upgrade root must still be a valid anchor after merkle upgrade \
         (ROOT_HISTORY StableBTreeMap must survive)"
    );

    // ── e) leaf_count correctly re-derived ────────────────────────────────────
    //
    // post_upgrade: LEAF_COUNT = COMMITMENTS.len() = 1.
    // If LEAF_COUNT were silently reset to 0, leaf_count() would return 0.
    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        1,
        "test_50: leaf_count must be 1 after upgrade (re-derived from COMMITMENTS.len())"
    );

    // ── f) POOL_CANISTER survived — append_commitment still works ─────────────
    //
    // shield_deposit → pool calls append_commitment on the merkle canister.
    // The merkle canister's assert_pool() checks caller == POOL_CANISTER.
    // If POOL_CANISTER was reset to None, the call would trap with "unwrap on None".
    do_deposit(&pic, token_id, pool_id, user, NC2, DENOMINATIONS[0]);

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        2,
        "test_50: leaf_count must be 2 after second deposit post-upgrade"
    );

    // The root must have changed (new leaf → new root).
    let root_after: Vec<u8> = decode(
        "test_50: get_root after second deposit",
        pic.query_call(
            merkle_id,
            anon(),
            "get_root",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_ne!(
        root_after, root_before,
        "test_50: root must change after a new deposit post-upgrade"
    );
    assert!(
        merkle_is_valid_anchor(&pic, merkle_id, root_after),
        "test_50: new root after post-upgrade deposit must be a valid anchor"
    );
}

// =============================================================================
// Test 51 — Nullifier spent set survives nullifier-registry upgrade
// =============================================================================
//
// NULLIFIERS is a StableBTreeMap — it survives upgrades automatically.
// POOL_CANISTER is heap-only and serialised in pre_upgrade.
//
// INVARIANTS verified:
//   a) Nullifier N is in the registry after a successful withdrawal.
//   b) Nullifier-registry upgrade succeeds.
//   c) contains_nullifier(N) = true after upgrade.
//   d) A second withdrawal attempt with nullifier N → NullifierAlreadySpent,
//      proving the spent set is intact and the POOL_CANISTER ref was restored
//      (the pool can still call insert_nullifier).
// =============================================================================

// Lane A v2 Task 0.25: this test exercises nullifier-registry persistence after a successful withdrawal, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: withdrawal-spent-nullifier upgrade coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_51_nullifier_spent_set_survives_registry_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x51);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    const VK: [u8; 32] = [0x51u8; 32];
    const NULLIFIER: [u8; 32] = [0x21u8; 32];

    // Fund pool with exactly DENOMINATIONS[0] + DEFAULT_FEE — enough for one withdrawal.
    let pool_seed = DENOMINATIONS[0] + DEFAULT_FEE;
    let init = split_token_init(user, TOTAL_SUPPLY - pool_seed, pool_id, pool_seed, p(0x02));
    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &init);
    install(
        &pic,
        pool_id,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: VK,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    let _: () = decode(
        "test_51: inject PRIVATE_LIABILITY",
        pic.update_call(
            pool_id,
            p(0x06),
            "inject_private_liability_for_test",
            candid::encode_one(DENOMINATIONS[0]).unwrap(),
        ),
    );

    let env = ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: VK,
        root_reference: merkle_root(&pic, merkle_id),
        pool_version: 1,
        proof_bytes: vec![],
    };

    // ── a) W1 — successful withdrawal inserts nullifier ───────────────────────
    let w1: Result<Nat, PoolError> = decode(
        "test_51: W1 withdraw",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 5100,
                envelope: env.clone(),
                nullifier: NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(w1.is_ok(), "test_51: W1 must succeed; got {:?}", w1);

    let in_reg_before: bool = decode(
        "test_51: contains_nullifier before upgrade",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        in_reg_before,
        "test_51: nullifier must be in registry after W1"
    );

    // ── b) Upgrade nullifier registry ────────────────────────────────────────
    upgrade_canister(&pic, null_id, nullifier_wasm());

    // ── c) contains_nullifier still true after upgrade ────────────────────────
    let in_reg_after: bool = decode(
        "test_51: contains_nullifier after upgrade",
        pic.query_call(
            null_id,
            anon(),
            "contains_nullifier",
            candid::encode_one(NULLIFIER.to_vec()).unwrap(),
        ),
    );
    assert!(
        in_reg_after,
        "test_51: nullifier spent set must survive registry upgrade \
         (NULLIFIERS StableBTreeMap must persist)"
    );

    // ── d) W2 with same nullifier → NullifierAlreadySpent ────────────────────
    //
    // For W2 to reach the registry check, the pool's NULLIFIER_CANISTER ref
    // must be intact.  If POOL_CANISTER on the nullifier registry was reset to
    // None, insert_nullifier would panic with "unwrap on None", producing a
    // different error.  NullifierAlreadySpent confirms both:
    //   i)  the spent set is intact in stable memory, and
    //   ii) the POOL_CANISTER ref was correctly restored in post_upgrade.
    let w2: Result<Nat, PoolError> = decode(
        "test_51: W2 with same nullifier → NullifierAlreadySpent",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 5101, // different id — bypasses idempotency key
                envelope: env,
                nullifier: NULLIFIER, // same nullifier
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOMINATIONS[0],
            })
            .unwrap(),
        ),
    );
    assert!(
        w2 == Err(PoolError::NullifierAlreadySpent),
        "test_51: W2 must return NullifierAlreadySpent after registry upgrade; \
         got {:?}",
        w2
    );
}

// =============================================================================
// Test 52 — All 6 accounting buckets survive pool upgrade exactly
// =============================================================================
//
// After a complete deposit + partial-withdraw cycle, all 6 accounting buckets
// have non-trivial values.  The pool upgrade must preserve ALL of them exactly.
//
// Buckets tested (all heap-only thread_local scalars):
//   private_liability, escrow_backing, operations_reserve,
//   insurance_reserve, governance_rewards_reserve, pending_fee_reimbursements
//
// This is the primary test for the pool's PoolStableState serialisation in
// pre_upgrade / restoration in post_upgrade.
//
// INVARIANTS verified:
//   a) After shield_deposit + withdrawal: all 6 buckets have expected values.
//   b) Pool upgrade succeeds.
//   c) All 6 buckets match exactly after upgrade.
//   d) Solvency invariants (1) and (2) hold after upgrade.
// =============================================================================

// Lane A v2 Task 0.25: this test exercises post-withdrawal accounting bucket persistence across pool upgrade, not proof
// authorization itself. It cannot reach its subject while withdraw intentionally
// fails closed with InvalidProof; restore after Task 1 proof-bound withdrawal.
#[ignore = "Lane A v2: post-withdrawal accounting upgrade coverage blocked until proof-bound withdraw is restored"]
#[test]
fn test_52_accounting_buckets_survive_pool_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x52);
    let token_id = create_canister(&pic);
    let null_id = create_canister(&pic);
    let pool_id = create_canister(&pic);
    let merkle_id = create_canister(&pic);

    const VK: [u8; 32] = [0x52u8; 32];
    const NC: [u8; 32] = [0x52u8; 32]; // note commitment
    const NULLIFIER: [u8; 32] = [0x22u8; 32];
    const WID: u64 = 5200;

    pic.install_canister(
        null_id,
        nullifier_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );
    install(&pic, token_id, token_wasm(), &all_to(user, p(0x02)));
    install(
        &pic,
        pool_id,
        pool_wasm(),
        &PoolInitArgs {
            token_canister: token_id,
            nullifier_canister: null_id,
            merkle_canister: merkle_id,
            treasury_canister: p(0x04),
            staking_canister: p(0x05),
            controller: p(0x06),
            initial_vk_hash: VK,
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    // ── a) Deposit to populate all buckets ───────────────────────────────────
    //
    // At launch, protocol_shielding_fee = 0 and protocol_unshielding_fee = 0.
    // Protocol reserves (ops/ins) remain 0. escrow_backing and private_liability
    // are non-zero from the second deposit. governance_rewards_reserve = 0.
    // All 6 buckets (including zero-valued ones) must survive the upgrade unchanged.
    //
    // At zero shielding fee: private_balance_credit == gross.
    let private_bal = DENOMINATIONS[0];

    let pb = do_deposit(&pic, token_id, pool_id, user, NC, DENOMINATIONS[0]);
    assert_eq!(
        pb, private_bal,
        "test_52: deposit returned unexpected private_balance"
    );

    // Withdraw the note. Query current Merkle root after the deposit (deposit added a leaf).
    let root_52 = merkle_root(&pic, merkle_id);
    let w: Result<Nat, PoolError> = decode(
        "test_52: withdraw",
        pic.update_call(
            pool_id,
            user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: WID,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: VK,
                    root_reference: root_52,
                    pool_version: 1,
                    proof_bytes: vec![],
                },
                nullifier: NULLIFIER,
                destination: user,
                destination_subaccount: None,
                gross_withdraw_amount: private_bal,
            })
            .unwrap(),
        ),
    );
    assert!(w.is_ok(), "test_52: withdrawal must succeed; got {:?}", w);

    // Do a second deposit to leave private_liability and escrow_backing non-zero
    // before the upgrade, so all 6 buckets can be meaningfully compared.
    const NC2: [u8; 32] = [0x53u8; 32];
    do_deposit(&pic, token_id, pool_id, user, NC2, DENOMINATIONS[1]);

    let acc_before = accounting_state(&pic, pool_id);

    // Verify all buckets have non-trivial values we care about
    assert!(
        acc_before.private_liability > 0,
        "test_52: private_liability must be > 0 before upgrade"
    );
    assert!(
        acc_before.escrow_backing > 0,
        "test_52: escrow_backing must be > 0 before upgrade"
    );
    assert_eq!(
        acc_before.operations_reserve, 0,
        "test_52: operations_reserve must be 0 at launch fees"
    );
    assert_eq!(
        acc_before.insurance_reserve, 0,
        "test_52: insurance_reserve must be 0 at launch fees"
    );
    // governance_rewards_reserve = 0 (correct — no treasury allocation)
    assert_eq!(acc_before.governance_rewards_reserve, 0);

    // ── b) Upgrade pool ───────────────────────────────────────────────────────
    upgrade_canister(&pic, pool_id, pool_wasm());

    // ── c) All 6 buckets match exactly ────────────────────────────────────────
    let acc_after = accounting_state(&pic, pool_id);

    assert_eq!(
        acc_after.private_liability, acc_before.private_liability,
        "test_52: private_liability must survive upgrade; before={} after={}",
        acc_before.private_liability, acc_after.private_liability
    );
    assert_eq!(
        acc_after.escrow_backing, acc_before.escrow_backing,
        "test_52: escrow_backing must survive upgrade; before={} after={}",
        acc_before.escrow_backing, acc_after.escrow_backing
    );
    assert_eq!(
        acc_after.operations_reserve, acc_before.operations_reserve,
        "test_52: operations_reserve must survive upgrade; before={} after={}",
        acc_before.operations_reserve, acc_after.operations_reserve
    );
    assert_eq!(
        acc_after.insurance_reserve, acc_before.insurance_reserve,
        "test_52: insurance_reserve must survive upgrade; before={} after={}",
        acc_before.insurance_reserve, acc_after.insurance_reserve
    );
    assert_eq!(
        acc_after.governance_rewards_reserve, acc_before.governance_rewards_reserve,
        "test_52: governance_rewards_reserve must survive upgrade; before={} after={}",
        acc_before.governance_rewards_reserve, acc_after.governance_rewards_reserve
    );
    assert_eq!(
        acc_after.pending_fee_reimbursements, acc_before.pending_fee_reimbursements,
        "test_52: pending_fee_reimbursements must survive upgrade; before={} after={}",
        acc_before.pending_fee_reimbursements, acc_after.pending_fee_reimbursements
    );

    // ── d) Solvency invariants hold after upgrade ─────────────────────────────
    //
    // If any bucket was silently defaulted to 0, one of these would fail.
    assert!(
        acc_after.escrow_backing + acc_after.pending_fee_reimbursements
            >= acc_after.private_liability,
        "test_52: invariant (1) must hold after upgrade: \
         escrow_backing({}) + pending_fee_reimbursements({}) >= private_liability({})",
        acc_after.escrow_backing,
        acc_after.pending_fee_reimbursements,
        acc_after.private_liability
    );
    assert!(
        acc_after.operations_reserve >= acc_after.pending_fee_reimbursements,
        "test_52: invariant (2) must hold after upgrade: \
         operations_reserve({}) >= pending_fee_reimbursements({})",
        acc_after.operations_reserve,
        acc_after.pending_fee_reimbursements
    );
}

// =============================================================================
// Test 53 — Staking governance params + voting weight survive staking upgrade
// =============================================================================
//
// The staking canister has two distinct state recovery paths on post_upgrade:
//
//   SERIALISED in pre_upgrade / RESTORED in post_upgrade:
//     GOV_PARAMS, REWARD_STATE (including rewards_pool_balance and
//     emission_rate_per_day), TOKEN_CANISTER, POOL_CANISTER,
//     TREASURY_CANISTER, NEXT_POSITION_ID, NEXT_PROPOSAL_ID.
//
//   RECOMPUTED in post_upgrade (NOT serialised — derived from stable maps):
//     TOTAL_VOTING_WEIGHT = sum of voting_weight over all open POSITIONS.
//
// INVARIANTS verified:
//   a) Custom governance params set at init survive the upgrade unchanged.
//   b) rewards_pool_balance (REWARD_STATE heap field) survives the upgrade.
//   c) TOTAL_VOTING_WEIGHT is correctly re-derived from POSITIONS after upgrade.
//   d) Stake positions themselves survive (POSITIONS is StableBTreeMap).
//   e) Staking is operational after upgrade — a query for stake positions works.
// =============================================================================

#[test]
fn test_53_staking_governance_state_survives_upgrade() {
    let pic = PocketIc::new();
    let user = p(0x53);
    let token_id = create_canister(&pic);
    let staking_id = create_canister(&pic);

    const STAKE_AMOUNT: u128 = 5_000 * 100_000_000; // 5 000 STSH
    const STAKE_DAYS: u32 = 30;
    const REWARDS_POOL: u128 = 500_000; // non-zero initial rewards pool

    // User holds all tokens; staking_id is the authorized staking canister.
    install(&pic, token_id, token_wasm(), &all_to(user, staking_id));
    install(
        &pic,
        staking_id,
        staking_wasm(),
        &StakingInitArgs {
            token_canister: token_id,
            pool_canister: p(0x20),
            treasury_canister: p(0x21),
            initial_rewards_pool: REWARDS_POOL,
            initial_emission_rate_per_day: 1_000,
            governance_params: Some(GovernanceParams::fast()),
        },
    );

    // ── Pre-upgrade: stake to create a POSITIONS entry ────────────────────────
    let stake_result: Result<u64, String> = decode(
        "test_53: stake",
        pic.update_call(
            staking_id,
            user,
            "stake",
            candid::encode_args((STAKE_AMOUNT, STAKE_DAYS, next_dedup_key())).unwrap(),
        ),
    );
    let position_id = stake_result.expect("test_53: stake must succeed");

    // ── Record state before upgrade ───────────────────────────────────────────
    let gov_before: GovernanceParams = decode(
        "test_53: get_governance_params before upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_governance_params",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        gov_before,
        GovernanceParams::fast(),
        "test_53: governance params must equal init value before upgrade"
    );

    let voting_weight_before: u128 = decode(
        "test_53: get_total_voting_weight before upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_total_voting_weight",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(
        voting_weight_before > 0,
        "test_53: total_voting_weight must be > 0 after staking"
    );

    let rewards_pool_before: u128 = decode(
        "test_53: get_rewards_pool_balance before upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_rewards_pool_balance",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        rewards_pool_before, REWARDS_POOL,
        "test_53: rewards_pool_balance must equal initial value before upgrade"
    );

    // ── b/c/d) Upgrade staking ────────────────────────────────────────────────
    upgrade_canister(&pic, staking_id, staking_wasm());

    // ── a) Governance params survived ────────────────────────────────────────
    let gov_after: GovernanceParams = decode(
        "test_53: get_governance_params after upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_governance_params",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        gov_after, gov_before,
        "test_53: governance params must survive staking upgrade unchanged"
    );

    // ── b) rewards_pool_balance (REWARD_STATE heap field) survived ─────────────
    let rewards_pool_after: u128 = decode(
        "test_53: get_rewards_pool_balance after upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_rewards_pool_balance",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        rewards_pool_after, rewards_pool_before,
        "test_53: rewards_pool_balance must survive upgrade; \
         before={} after={}",
        rewards_pool_before, rewards_pool_after
    );

    // ── c) TOTAL_VOTING_WEIGHT survives upgrade (DEF-059) ──────────────────────
    //
    // post_upgrade now restores TOTAL_VOTING_WEIGHT from its stable Cell
    // (VOTING_WEIGHT_CELL) instead of re-scanning POSITIONS. It must match the
    // value before upgrade.
    let voting_weight_after: u128 = decode(
        "test_53: get_total_voting_weight after upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_total_voting_weight",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(
        voting_weight_after, voting_weight_before,
        "test_53: TOTAL_VOTING_WEIGHT must survive upgrade via the stable cell (DEF-059); \
         before={} after={}",
        voting_weight_before, voting_weight_after
    );

    // ── d/e) Stake positions survived + canister is functional ───────────────
    let positions: Vec<StakePosition> = decode(
        "test_53: get_stake_positions after upgrade",
        pic.query_call(
            staking_id,
            anon(),
            "get_stake_positions",
            candid::encode_one(user).unwrap(),
        ),
    );
    assert_eq!(
        positions.len(),
        1,
        "test_53: must have exactly 1 stake position after upgrade"
    );
    assert_eq!(
        positions[0].position_id, position_id,
        "test_53: position_id must match"
    );
    assert_eq!(
        positions[0].amount, STAKE_AMOUNT,
        "test_53: staked amount must survive upgrade"
    );
    assert_eq!(
        positions[0].voting_weight, voting_weight_after,
        "test_53: position voting_weight must equal total (only one position exists)"
    );
    assert!(
        !positions[0].closed,
        "test_53: position must not be closed after upgrade"
    );
}

// =============================================================================
// test_54 — M4 Poseidon zero-root regression
// =============================================================================
//
// Verifies that [0u8;32] is NEVER a valid anchor on a Poseidon-enabled merkle
// canister — neither immediately after init(), nor after ROOT_HISTORY_SIZE
// deposits cause the ring buffer to roll over.
//
// Prior to M4 (SHA-256/zero-byte stub):
//   - zero_value(TREE_DEPTH) returned [0u8;32] at every level
//   - init() stored [0u8;32] as the initial root in ROOT_HISTORY
//   - is_valid_anchor([0u8;32]) returned true on a fresh canister
//   This was not a bypass — [0u8;32] was a legitimately stored root.
//   It was still wrong because real ZK proofs would never produce this root.
//
// After M4 (real circomlib Poseidon over BN254/Fr):
//   - zero_value(TREE_DEPTH) = ZERO_VALUES[32] = Poseidon(Poseidon(…)) ≠ [0u8;32]
//   - is_valid_anchor([0u8;32]) returns false immediately on init
//   - After ROOT_HISTORY_SIZE deposits, even ZERO_VALUES[32] is evicted
//   - [0u8;32] remains invalid throughout
//
// Steps:
//   a) Fresh canister: is_valid_anchor([0u8;32]) == false
//   b) Fresh canister: is_valid_anchor(ZERO_VALUES[32]) == true
//   c) Append ROOT_HISTORY_SIZE+1 = 101 commitments (directly via pool_id sender)
//   d) After rollover: is_valid_anchor([0u8;32]) == false
//   e) After rollover: is_valid_anchor(ZERO_VALUES[32]) == false (evicted)
//   f) After rollover: is_valid_anchor(latest_root) == true
// =============================================================================

#[test]
fn test_54_poseidon_zero_root_regression() {
    let pic = PocketIc::new();
    // pool_id is used only as a caller principal matching POOL_CANISTER.
    // No pool canister Wasm needs to be installed — PocketIC allows any
    // principal as a sender in update_call.
    let pool_id = p(0x54);
    let merkle_id = create_canister(&pic);

    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool_id).unwrap(),
        None,
    );

    // ── a) Fresh canister: [0u8;32] must NOT be a valid anchor ───────────────
    //
    // The SHA-256 stub init'd ROOT_HISTORY with [0u8;32] (zero_value returned
    // [0u8;32] at every level).  Poseidon init() stores ZERO_VALUES[32] ≠ [0u8;32].
    assert!(
        !merkle_is_valid_anchor(&pic, merkle_id, vec![0u8; 32]),
        "test_54: [0u8;32] must NOT be a valid anchor immediately after init \
         (M4 regression: SHA-256 stub stored [0u8;32] as init root)"
    );

    // ── b) Fresh canister: Poseidon empty-tree root IS a valid anchor ─────────
    let empty_root: Vec<u8> = decode(
        "test_54: get_root on fresh canister",
        pic.query_call(
            merkle_id,
            anon(),
            "get_root",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_ne!(
        empty_root,
        vec![0u8; 32],
        "test_54: get_root must not return [0u8;32] — Poseidon empty root must be non-zero"
    );
    assert!(
        merkle_is_valid_anchor(&pic, merkle_id, empty_root.clone()),
        "test_54: Poseidon empty-tree root (ZERO_VALUES[32]) must be a valid anchor on fresh canister"
    );

    // ── c) Append ROOT_HISTORY_SIZE + 1 = 101 commitments ────────────────────
    //
    // After ROOT_HISTORY_SIZE (100) deposits the ring buffer is full.
    // The 101st deposit overwrites slot 0 — the slot that held the init root.
    // Commitments are [1u8;32], [2u8;32], …, [101u8;32] — all distinct and non-zero.
    const ROOT_HISTORY_SIZE: usize = 100;

    for i in 0u8..=(ROOT_HISTORY_SIZE as u8) {
        // DEF-041: canonical commitments (only byte 0 set) — distinct, non-zero,
        // and < the BN254 modulus. The previous `[i+1; 32]` fill became non-canonical
        // for i+1 > 0x30 and is now (correctly) rejected by the canonical check.
        let commitment: Vec<u8> = canon(i.wrapping_add(1)).to_vec();
        let result: Result<u64, String> = decode(
            "test_54: append_commitment",
            pic.update_call(
                merkle_id,
                pool_id,
                "append_commitment",
                candid::encode_args((commitment, Vec::<u8>::new())).unwrap(),
            ),
        );
        assert!(
            result.is_ok(),
            "test_54: append_commitment #{i} failed: {:?}",
            result
        );
    }

    assert_eq!(
        merkle_leaf_count(&pic, merkle_id),
        ROOT_HISTORY_SIZE as u64 + 1,
        "test_54: leaf_count must be 101 after 101 appends"
    );

    // ── d) After rollover: [0u8;32] still NOT a valid anchor ─────────────────
    assert!(
        !merkle_is_valid_anchor(&pic, merkle_id, vec![0u8; 32]),
        "test_54: [0u8;32] must NOT be a valid anchor after ROOT_HISTORY_SIZE rollover"
    );

    // ── e) After rollover: Poseidon empty-tree root is evicted ────────────────
    //
    // ZERO_VALUES[32] was stored at ROOT_HISTORY slot 0 during init().
    // After ROOT_HISTORY_SIZE + 1 = 101 append_commitment calls, slot 0 is
    // overwritten.  The empty-tree root should no longer be a valid anchor.
    assert!(
        !merkle_is_valid_anchor(&pic, merkle_id, empty_root.clone()),
        "test_54: Poseidon empty-tree root (ZERO_VALUES[32]) must be evicted \
         from ROOT_HISTORY after ROOT_HISTORY_SIZE rollover (slot 0 overwritten)"
    );

    // ── f) The most recent root IS still a valid anchor ───────────────────────
    let latest_root: Vec<u8> = decode(
        "test_54: get_root after 101 deposits",
        pic.query_call(
            merkle_id,
            anon(),
            "get_root",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_ne!(
        latest_root,
        vec![0u8; 32],
        "test_54: latest root after 101 deposits must not be [0u8;32]"
    );
    assert!(
        merkle_is_valid_anchor(&pic, merkle_id, latest_root),
        "test_54: latest root after 101 deposits must be a valid anchor"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 55 — Treasury subaccount balances and proposal counter survive upgrade
// ─────────────────────────────────────────────────────────────────────────────
//
// INVARIANT: treasury SUBACCOUNTS (StableBTreeMap, MemoryId 0), PROPOSALS
// (StableBTreeMap, MemoryId 1), FEE_LOG (StableBTreeMap, MemoryId 2) survive
// automatically.  NEXT_PROPOSAL_ID and FEE_LOG_INDEX are serialised via
// TreasuryStableState in pre/post_upgrade (MEM_STABLE_STATE, MemoryId 3).
//
// Verifies:
//   a) Subaccount balances populated before upgrade are intact after upgrade.
//   b) NEXT_PROPOSAL_ID counter survived (second proposal gets id = first + 1).
//   c) Pre-upgrade pending proposal remains Pending after upgrade.
// =============================================================================

/// treasury::FeeSource mirror — Candid variant names must match exactly.
#[derive(CandidType)]
enum TreasuryFeeSource {
    ShieldFee,
    PrivateTransferFee,
    UnshieldFee,
}

/// Minimal mirror for treasury::ProposalStatus — only Pending needed here.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TreasuryProposalStatus {
    Pending,
    Executed,
    Rejected,
    Expired,
}

/// Minimal mirror for treasury::WithdrawalProposal — only id and status needed.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TreasuryWithdrawalProposal {
    id: u64,
    proposer: Principal,
    subaccount_name: String,
    recipient: Principal,
    amount: u128,
    description: String,
    created_at_ns: u64,
    execute_after_ns: u64,
    status: TreasuryProposalStatus,
}

#[test]
fn test_55_treasury_state_survives_upgrade() {
    let pic = PocketIc::new();
    let pool_id = p(0x55);
    let controller = p(0x56);
    let token_id = p(0x57); // fake token — no icrc1_transfer in this test

    let treasury_id = create_canister(&pic);

    // Install treasury: (token_canister, pool_canister, controller)
    let treasury_init = candid::encode_args((token_id, pool_id, controller)).unwrap();
    pic.install_canister(treasury_id, treasury_wasm(), treasury_init, None);

    // ── a) Populate subaccounts via receive_fee_split ─────────────────────────
    const OPS_AMOUNT: u128 = 6_000_000_000;
    const INS_AMOUNT: u128 = 2_000_000_000;
    let _: Result<(), String> = decode(
        "test_55: receive_fee_split",
        pic.update_call(
            treasury_id,
            pool_id,
            "receive_fee_split",
            candid::encode_args((TreasuryFeeSource::ShieldFee, OPS_AMOUNT, INS_AMOUNT, 0u128, 0u64))
                .unwrap(),
        ),
    );

    // Verify balances before upgrade
    let ops_before: Option<u128> = decode(
        "test_55: operations balance before upgrade",
        pic.query_call(
            treasury_id,
            anon(),
            "get_subaccount_balance",
            candid::encode_one("operations".to_string()).unwrap(),
        ),
    );
    assert_eq!(
        ops_before,
        Some(OPS_AMOUNT),
        "test_55: operations balance must equal OPS_AMOUNT before upgrade"
    );

    // ── b) Create a pending proposal ─────────────────────────────────────────
    let proposal_id: u64 = decode(
        "test_55: propose_withdrawal",
        pic.update_call(
            treasury_id,
            controller,
            "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(),
                p(0x58),
                1_000_000_000u128,
                "test_55".to_string(),
            ))
            .unwrap(),
        ),
    );

    // ── c) Upgrade treasury in-place ──────────────────────────────────────────
    upgrade_canister(&pic, treasury_id, treasury_wasm());

    // ── d) Verify subaccount balances survived ────────────────────────────────
    let ops_after: Option<u128> = decode(
        "test_55: operations balance after upgrade",
        pic.query_call(
            treasury_id,
            anon(),
            "get_subaccount_balance",
            candid::encode_one("operations".to_string()).unwrap(),
        ),
    );
    assert_eq!(
        ops_after,
        Some(OPS_AMOUNT),
        "test_55: operations balance must survive treasury upgrade"
    );

    let ins_after: Option<u128> = decode(
        "test_55: insurance balance after upgrade",
        pic.query_call(
            treasury_id,
            anon(),
            "get_subaccount_balance",
            candid::encode_one("insurance".to_string()).unwrap(),
        ),
    );
    assert_eq!(
        ins_after,
        Some(INS_AMOUNT),
        "test_55: insurance balance must survive treasury upgrade"
    );

    // ── e) Verify NEXT_PROPOSAL_ID counter survived ───────────────────────────
    //
    // If the counter survived upgrade, the next proposal gets id = proposal_id + 1.
    // If it was reset to 1 (counter lost), the next proposal would also get id = 1
    // (or conflict).  A sequential id proves the counter was restored.
    let second_proposal_id: u64 = decode(
        "test_55: second propose_withdrawal post-upgrade",
        pic.update_call(
            treasury_id,
            controller,
            "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(),
                p(0x59),
                500_000_000u128,
                "test_55b".to_string(),
            ))
            .unwrap(),
        ),
    );
    assert_eq!(
        second_proposal_id,
        proposal_id + 1,
        "test_55: NEXT_PROPOSAL_ID must be sequential after upgrade (counter must survive)"
    );

    // ── f) Verify original proposal survived and is still Pending ─────────────
    let proposals: Vec<TreasuryWithdrawalProposal> = decode(
        "test_55: list_proposals after upgrade",
        pic.query_call(
            treasury_id,
            anon(),
            "list_proposals",
            candid::encode_args(()).unwrap(),
        ),
    );
    let original = proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .unwrap_or_else(|| panic!("test_55: proposal {} not found after upgrade", proposal_id));
    assert_eq!(
        original.status,
        TreasuryProposalStatus::Pending,
        "test_55: pre-upgrade proposal must remain Pending after upgrade"
    );
}

// =============================================================================
// Test 56 — Vesting schedule + claimed amount survive vesting upgrade
// =============================================================================
//
// INVARIANT: VestingSchedule (including claimed) persists across upgrade via the
// SCHEDULES StableBTreeMap (MemoryId 0). If claimed resets to 0 after upgrade,
// a second claim would re-transfer tokens already sent — violating the
// `claimed_1 + claimed_2 <= T56_TOTAL` bound.
//
// Also validates that token_canister is restored from serialized heap state so
// the claim() call after upgrade can still reach the ledger.
//
// Setup: cliff=6mo, linear=6mo, total=1000 STSH.
//   Advance 7 months (past cliff, mid-linear).
//   First claim → claimed_1 > 0.
//   Read schedule pre-upgrade: pre.claimed == claimed_1.
//   Upgrade vesting in-place.
//   Read schedule post-upgrade: post.claimed == claimed_1 (must not reset).
//   Advance to vesting_end + 1s (fully vested).
//   Second claim → claimed_2 > 0.
//   Invariant: claimed_1 + claimed_2 <= T56_TOTAL.
// =============================================================================

#[test]
fn test_56_vesting_claimed_survives_upgrade() {
    const T56_TOTAL: u128 = 1_000 * 100_000_000; // 1000 STSH

    let pic = PocketIc::new();
    let controller = p(0x56);
    let beneficiary = p(0xB6);

    let token_id = create_canister(&pic);
    let vesting_id = create_canister(&pic);

    // Give all supply to the vesting canister so claim() can transfer.
    let token_init = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: vesting_id,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
    };
    install(&pic, token_id, token_wasm(), &token_init);

    // Install vesting with one schedule: 6-month cliff, 6-month linear.
    install(
        &pic,
        vesting_id,
        vesting_wasm(),
        &VestingInitArgs {
            token_canister: token_id,
            controller,
            schedules: vec![NewSchedule {
                beneficiary,
                total_amount: T56_TOTAL,
                cliff_months: 6,
                linear_months: 6,
            }],
        },
    );

    // ── a) Advance 7 months (past 6-month cliff, mid-way through linear) ─────
    pic.advance_time(Duration::from_secs(7 * 31 * 24 * 3600));

    // ── b) First claim ─────────────────────────────────────────────────────────
    let first_result: Result<Nat, String> = decode(
        "test_56: first claim",
        pic.update_call(
            vesting_id,
            beneficiary,
            "claim",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(
        first_result.is_ok(),
        "test_56: first claim must succeed after cliff; got {:?}",
        first_result
    );
    let claimed_1: u128 = first_result.unwrap().0.to_string().parse().unwrap();
    assert!(
        claimed_1 > 0,
        "test_56: first claim must transfer > 0 tokens; got {}",
        claimed_1
    );

    // ── c) Read schedule before upgrade ───────────────────────────────────────
    let pre: VestingSchedule = decode::<Option<VestingSchedule>, _>(
        "test_56: get_schedule pre-upgrade",
        pic.query_call(
            vesting_id,
            anon(),
            "get_schedule",
            candid::encode_one(beneficiary).unwrap(),
        ),
    )
    .unwrap_or_else(|| panic!("test_56: schedule not found pre-upgrade"));
    assert_eq!(
        pre.claimed, claimed_1,
        "test_56: pre-upgrade schedule.claimed must equal first claim amount"
    );

    // ── d) Upgrade vesting in-place ───────────────────────────────────────────
    upgrade_canister(&pic, vesting_id, vesting_wasm());

    // ── e) Read schedule after upgrade ────────────────────────────────────────
    let post: VestingSchedule = decode::<Option<VestingSchedule>, _>(
        "test_56: get_schedule post-upgrade",
        pic.query_call(
            vesting_id,
            anon(),
            "get_schedule",
            candid::encode_one(beneficiary).unwrap(),
        ),
    )
    .unwrap_or_else(|| panic!("test_56: schedule not found post-upgrade"));
    assert_eq!(
        post.claimed, claimed_1,
        "test_56: post-upgrade schedule.claimed must equal pre-upgrade value (must not reset)"
    );
    assert_eq!(
        post.total_amount, T56_TOTAL,
        "test_56: post-upgrade total_amount must be unchanged"
    );
    assert_eq!(
        post.cliff_end_ns, pre.cliff_end_ns,
        "test_56: post-upgrade cliff_end_ns must be unchanged"
    );

    // ── f) Advance to vesting_end + 1 second (fully vested) ──────────────────
    let now_ns = pic.get_time().as_nanos_since_unix_epoch();
    let remaining_ns = post.vesting_end_ns.saturating_sub(now_ns);
    pic.advance_time(Duration::from_nanos(remaining_ns + 1_000_000_000));

    // ── g) Second claim after upgrade ─────────────────────────────────────────
    let second_result: Result<Nat, String> = decode(
        "test_56: second claim after upgrade",
        pic.update_call(
            vesting_id,
            beneficiary,
            "claim",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(
        second_result.is_ok(),
        "test_56: second claim after upgrade must succeed; got {:?}",
        second_result
    );
    let claimed_2: u128 = second_result.unwrap().0.to_string().parse().unwrap();
    assert!(
        claimed_2 > 0,
        "test_56: second claim after upgrade must transfer > 0 tokens; got {}",
        claimed_2
    );
    assert!(
        claimed_1 + claimed_2 <= T56_TOTAL,
        "test_56: claimed_1 ({}) + claimed_2 ({}) must not exceed T56_TOTAL ({}); \
         claimed reset to 0 after upgrade would cause this to fail",
        claimed_1,
        claimed_2,
        T56_TOTAL
    );
}
