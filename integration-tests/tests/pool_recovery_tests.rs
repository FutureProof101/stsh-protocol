// =============================================================================
// STSH — Pool recovery tests (PocketIC)
// Pass 4 remediation: QA-DEF-025 (payout double-pay), QA-DEF-027 (treasury
// disburse race + transport-unknown), QA-DEF-028 (nullifier-insert reconcile)
// =============================================================================
//
// Shared harness for the three recovery items. Item 2's validation test is
// written and run FIRST (charter) to decide whether the payout-retry race
// reproduces in PocketIC before any fix is implemented.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): build shielded_pool with
// --features testing, copy to shielded_pool_test.wasm, then build all production
// wasms + stsh-stub-verifier + stub_bad_fee_token. POCKET_IC_BIN must be set.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_TEST_WASM"), "stsh_token_test") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

// ── Constants ───────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;
const DENOM_1000: u128 = 1_000 * 100_000_000; // DENOMINATIONS[3]
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch
/// public_amount for the stub private-spend used throughout this file. BOUND
/// by the spend arithmetic (inputs 1_000_000 − outputs 940_000 = 60_000), NOT
/// by the ledger fee — pre-F-000 it was expressed as "ledger fee + 50_000",
/// which silently coupled the fixture math to the (then 10_000) ledger fee.
const SPEND_PUBLIC_AMOUNT: u128 = 60_000;

// ── Token mirrors ───────────────────────────────────────────────────────────

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
fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All".to_string(),
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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: u128,
    expected_allowance: Option<u128>,
    expires_at: Option<u64>,
    fee: Option<u128>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveErr {
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

// ── Pool mirrors ────────────────────────────────────────────────────────────

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
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingPublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
    protocol_fee: u128,
    block_index: Option<Nat>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SpendStatus {
    Requested,
    OutputsStaged,
    Finalized,
    FailedBeforeStateChange { reason: String },
    FailedAfterOutputsStaged { reason: String },
    VerificationPending,
    NullifierReserved,
    PayoutPending { reason: String },
    PayoutSubmitting,
    PayoutUnknown { reason: String },
    NullifierInsertUnknown { reason: String },
    NullifierReconcileInFlight, // DEF-099 transient claim marker
    // A2 (QA-DEF-034/036)
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpend {
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    public_payout: Option<PendingPublicPayout>,
    outputs_committed: u32,
    status: SpendStatus,
    created_at_ns: u64,
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
enum PoolError {
    RecoveryInProgress(String), PayoutOutcomePrivate, PayoutExecutorBusy, PayoutMemoKeyNotReady, PayoutLegacyHold, PayoutStateInvalid,
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    EscrowUnderfunded { required: u128, available: u128 },
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    CircuitVersionMismatch { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch { inputs: u128, outputs: u128 },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateSpendId,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    PrivateSpendFeeMismatch { expected: u128, got: u128 },
    InsufficientPrivateLiability { required: u128, available: u128 },
    WithdrawalBelowMinimum { withdraw_gross_amount: u128, minimum_withdrawal_gross: u128 },
    GrossAmountBelowFees { withdraw_gross_amount: u128, total_fee: u128 },
    RecipientBelowMinimum { recipient_net_amount: u128, minimum_recipient_amount: u128 },
    IdempotencyKeyConflict,
    EncryptedPayloadTooLarge { len: u64, max: u64 },
    EncryptedOutputTooLarge { index: u32, len: u64, max: u64 },
    InvalidProofLength { len: u64, expected: u64 },
    DepositTransferNotConfirmed,
    DepositAppendInProgress,
    DepositAppendUnknown,
    DepositAlreadyCompleted,
    PayoutNotPending,
    PayoutOutcomeUnknown,
    SpendNotFound,
    WrongSpendStatus,
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

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
fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

struct Stack {
    pool: Principal,
    token: Principal,
    merkle: Principal,
    null: Principal, // DEF-099: exposed so tests can stop/start the registry
    controller: Principal,
    user: Principal,
}

fn deploy_stack(pic: &PocketIc) -> Stack { deploy_stack_with_pool(pic, pool_test_wasm(), true) }
fn deploy_stack_with_pool(pic: &PocketIc, pool_wasm: Vec<u8>, provision: bool) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let verifier = create_canister(pic);
    let pool = create_canister(pic);
    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    pic.install_canister(verifier, stub_verifier_wasm(), candid::encode_one(None::<[u8; 32]>).unwrap(), None);
    install(pic, token, token_wasm(), &all_to(user, p(0x02)));
    install(
        pic,
        pool,
        pool_wasm,
        &PoolInitArgs {
            token_canister: token,
            nullifier_canister: null,
            merkle_canister: merkle,
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    // Wire the stub verifier so a real private_spend can run (stub accepts any proof).
    pic.update_call(pool, controller, "set_verifier_canister", candid::encode_args((verifier, vec![0u8; 32])).unwrap())
        .expect("set_verifier_canister");
    if provision {
    let ready: Result<bool, PoolError> = decode("initialize payout key", pic.update_call(pool, controller,
        "initialize_payout_memo_key", candid::encode_args(()).unwrap()));
    assert_eq!(ready, Ok(true));
    }
    Stack { pool, token, merkle, null, controller, user }
}

fn merkle_root(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    let v: Vec<u8> = decode(
        "get_root",
        pic.query_call(s.merkle, anon(), "get_root", candid::encode_args(()).unwrap()),
    );
    let mut r = [0u8; 32];
    r.copy_from_slice(&v);
    r
}

fn set_spend_status(pic: &PocketIc, s: &Stack, spend_id: u64, status: SpendStatus) {
    let _: () = decode(
        "set_spend_status_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "set_spend_status_for_test",
            candid::encode_args((spend_id, status)).unwrap(),
        ),
    );
}

fn reconcile_payout(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    spend_id: u64,
    outcome: PayoutOutcome,
) -> Result<Vec<u8>, pocket_ic::RejectResponse> {
    pic.update_call(
        s.pool,
        caller,
        "reconcile_private_spend_payout",
        candid::encode_args((spend_id, outcome)).unwrap(),
    )
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
struct PrivateSpendPublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PrivateSpendPublicPayout>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum PayoutOutcome {
    Executed { block_index: u64 },
    NotExecuted,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcilePayoutResult {
    Finalized { block_index: Nat },
    RevertedToPending,
    AlreadyExecuted { block_index: Nat },
}

fn token_balance(pic: &PocketIc, s: &Stack, owner: Principal) -> u128 {
    let n: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            s.token,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap(),
        ),
    );
    n.0.to_string().parse().unwrap()
}

fn spend_status(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<SpendStatus> {
    let rec: Option<PendingSpend> = decode(
        "get_spend_status",
        // DEF-069: get_spend_status is owner-or-controller gated — poll as the pool
        // controller (controller may read any record; anonymous can no longer).
        pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    );
    rec.map(|r| r.status)
}

/// Fund the pool's escrow + ledger balance by performing a real 1000 STSH deposit.
fn fund_pool_1000(pic: &PocketIc, s: &Stack) {
    let _: Result<Nat, ApproveErr> = decode(
        "approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
                amount: DENOM_1000 + DEFAULT_FEE,
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
    let mut c = [0u8; 32];
    c[0] = 0xDE;
    c[31] = 0x01;
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit fund",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: c,
                encrypted_payload: vec![],
                public_amount: DENOM_1000,
            })
            .unwrap(),
        ),
    );
    assert!(dep.is_ok(), "fund deposit must succeed; got {:?}", dep);
}

fn inject_payout_pending(pic: &PocketIc, s: &Stack, spend_id: u64, dest: Principal, public_amount: u128) {
    let _: () = decode(
        "inject_payout_pending_spend_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_payout_pending_spend_for_test",
            candid::encode_args((spend_id, dest, public_amount)).unwrap(),
        ),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-025 validation test — written and run FIRST (charter), before any fix.
//
// Drive a spend to PayoutPending with a 100 STSH public payout against a pool
// funded with 1000 STSH (so the ledger can satisfy TWO payouts if the race
// fires). Launch two concurrent retry_private_spend_payout(spend_id) calls. If
// the payout transfer runs twice the recipient receives 2×; the assertion that
// the recipient received exactly one payout therefore fails iff the race
// reproduces.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_retry_private_spend_payout_concurrent_retries_pay_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xB1);
    let payout = 100 * STSH;

    fund_pool_1000(&pic, &s);
    inject_payout_pending(&pic, &s, 1, recipient, payout);
    assert_eq!(token_balance(&pic, &s, recipient), 0, "recipient starts at 0");

    // Two concurrent retries, both submitted before either is awaited.
    let m1 = pic
        .submit_call(s.pool, s.controller, "retry_private_spend_payout", candid::encode_one(1u64).unwrap())
        .expect("submit retry 1");
    let m2 = pic
        .submit_call(s.pool, s.controller, "retry_private_spend_payout", candid::encode_one(1u64).unwrap())
        .expect("submit retry 2");
    let r1: Result<Nat, PoolError> = decode("retry 1", pic.await_call(m1));
    let r2: Result<Nat, PoolError> = decode("retry 2", pic.await_call(m2));

    // The recipient must have received EXACTLY one payout (100 STSH − ledger fee).
    let bal = token_balance(&pic, &s, recipient);
    assert_eq!(
        bal,
        payout - DEFAULT_FEE,
        "recipient must receive exactly one payout; got {} (r1={:?} r2={:?})",
        bal, r1, r2
    );
    assert_eq!(
        spend_status(&pic, &s, 1),
        Some(SpendStatus::Finalized),
        "spend must be Finalized after payout"
    );
}

fn retry(pic: &PocketIc, s: &Stack, spend_id: u64) -> Result<Nat, PoolError> {
    decode(
        "retry_private_spend_payout",
        pic.update_call(
            s.pool,
            s.controller,
            "retry_private_spend_payout",
            candid::encode_one(spend_id).unwrap(),
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-025 — real commit payout concurrent with a retry pays exactly once
// ─────────────────────────────────────────────────────────────────────────────
//
// Run a real private_spend (commit path, stub verifier) and a retry of the same
// spend_id concurrently. commit claims PayoutSubmitting before its transfer; the
// concurrent retry can only observe SpendNotFound / a pre-payout status /
// PayoutSubmitting / Finalized — never a second PayoutPending to act on — so it
// can never produce a second transfer.
#[test]
fn test_private_spend_commit_payout_and_concurrent_retry_pay_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xB2);
    fund_pool_1000(&pic, &s);
    let root = merkle_root(&pic, &s);
    let public_amount = SPEND_PUBLIC_AMOUNT;
    let spend_id = 10_000u64;

    let args = PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: root,
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![[0x2Fu8; 32]],
        output_commitments: vec![[0x20u8; 32], [0x21u8; 32]],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: recipient,
            destination_subaccount: None,
            public_amount,
        }),
    };

    let mc = pic
        .submit_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap())
        .expect("submit private_spend");
    let mr = pic
        .submit_call(s.pool, s.controller, "retry_private_spend_payout", candid::encode_one(spend_id).unwrap())
        .expect("submit retry");
    let commit: Result<(), PoolError> = decode("private_spend", pic.await_call(mc));
    let _retry: Result<Nat, PoolError> = decode("retry", pic.await_call(mr));

    assert_eq!(commit, Ok(()), "commit private_spend must succeed; retry={:?}", _retry);
    assert_eq!(
        token_balance(&pic, &s, recipient),
        public_amount - DEFAULT_FEE,
        "recipient must receive EXACTLY one payout despite the concurrent retry"
    );
    assert_eq!(
        spend_status(&pic, &s, spend_id),
        Some(SpendStatus::Finalized),
        "spend must be Finalized"
    );

    // A retry after Finalized is idempotent (returns the block index, no second pay).
    let again = retry(&pic, &s, spend_id);
    assert!(again.is_ok(), "post-finalize retry is idempotent Ok; got {:?}", again);
    assert_eq!(
        token_balance(&pic, &s, recipient),
        public_amount - DEFAULT_FEE,
        "still exactly one payout after idempotent retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-025 — retry rejected while a submission is already in flight
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_retry_private_spend_payout_rejected_if_submitting() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xB3);
    fund_pool_1000(&pic, &s);
    inject_payout_pending(&pic, &s, 2, recipient, 100 * STSH);
    set_spend_status(&pic, &s, 2, SpendStatus::PayoutSubmitting);

    let r = retry(&pic, &s, 2);
    assert_eq!(
        r,
        Err(PoolError::PayoutStateInvalid),
        "unregistered synthetic Submitting must fail closed; real live cases are in r15"
    );
    assert_eq!(token_balance(&pic, &s, recipient), 0, "no payout while a submission is in flight");
    assert_eq!(
        spend_status(&pic, &s, 2),
        Some(SpendStatus::PayoutSubmitting),
        "status unchanged by the rejected retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-025 — reconcile Executed finalizes without a second transfer
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_reconcile_private_spend_payout_executed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xB4);
    fund_pool_1000(&pic, &s);
    inject_payout_pending(&pic, &s, 3, recipient, 100 * STSH);
    set_spend_status(&pic, &s, 3, SpendStatus::PayoutUnknown { reason: "transport".to_string() });

    let r: Result<ReconcilePayoutResult, PoolError> = decode(
        "reconcile executed",
        reconcile_payout(&pic, &s, s.controller, 3, PayoutOutcome::Executed { block_index: 99 }),
    );
    assert_eq!(
        r,
        Ok(ReconcilePayoutResult::Finalized { block_index: Nat::from(99u64) }),
        "reconcile Executed must finalize with the given block index"
    );
    assert_eq!(spend_status(&pic, &s, 3), Some(SpendStatus::Finalized), "spend Finalized");
    assert_eq!(
        token_balance(&pic, &s, recipient),
        0,
        "reconcile must NOT issue a second transfer"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-025 — reconcile NotExecuted reverts to PayoutPending; retry then pays
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_reconcile_private_spend_payout_not_executed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xB5);
    let payout = 100 * STSH;
    fund_pool_1000(&pic, &s);
    inject_payout_pending(&pic, &s, 4, recipient, payout);
    let _:()=decode("force frozen unknown",pic.update_call(s.pool,s.controller,"force_payout_transport_unknown_for_test",candid::encode_one(true).unwrap()));
    assert!(retry(&pic,&s,4).is_err());
    let _:()=decode("clear frozen unknown",pic.update_call(s.pool,s.controller,"force_payout_transport_unknown_for_test",candid::encode_one(false).unwrap()));

    let r: Result<ReconcilePayoutResult, PoolError> = decode(
        "reconcile not executed",
        reconcile_payout(&pic, &s, s.controller, 4, PayoutOutcome::NotExecuted),
    );
    assert_eq!(r, Ok(ReconcilePayoutResult::RevertedToPending), "must revert to PayoutPending");
    assert!(
        matches!(spend_status(&pic, &s, 4), Some(SpendStatus::PayoutPending { .. })),
        "status must be PayoutPending after NotExecuted reconcile"
    );

    // Now a retry is permitted and pays exactly once.
    let rr = retry(&pic, &s, 4);
    assert!(rr.is_ok(), "retry after NotExecuted reconcile must succeed; got {:?}", rr);
    assert_eq!(
        token_balance(&pic, &s, recipient),
        payout - DEFAULT_FEE,
        "retry pays exactly one payout"
    );
    assert_eq!(spend_status(&pic, &s, 4), Some(SpendStatus::Finalized), "spend Finalized after retry");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-025 — reconcile rejects a non-controller before any state read
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_reconcile_private_spend_payout_rejects_non_controller() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xB6);
    inject_payout_pending(&pic, &s, 5, recipient, 100 * STSH);
    set_spend_status(&pic, &s, 5, SpendStatus::PayoutUnknown { reason: "transport".to_string() });

    let attacker = p(0xFF);
    let res = reconcile_payout(&pic, &s, attacker, 5, PayoutOutcome::NotExecuted);
    assert!(res.is_err(), "non-controller reconcile must be rejected (trap)");
    assert!(
        matches!(spend_status(&pic, &s, 5), Some(SpendStatus::PayoutUnknown { .. })),
        "status must be unchanged after a rejected reconcile"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// QA-DEF-027 — treasury_disburse race (Mode A) + transport-unknown (Mode B)
// ═════════════════════════════════════════════════════════════════════════════

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TreasuryReserveBucket { Operations, Insurance, StakingRewards }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TreasuryDisburseArgs {
    proposal_id: u64,
    bucket: TreasuryReserveBucket,
    recipient: Principal,
    recipient_subaccount: Option<[u8; 32]>,
    amount: u128,
    expected_ledger_fee: u128,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TreasuryDisburseResult {
    Executed { block_index: Nat },
    AlreadyExecuted { block_index: Nat },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum DisburseOutcome {
    Executed { block_index: u64 },
    NotExecuted,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcileDisburseResult {
    Recorded { block_index: Nat },
    Reverted,
    AlreadyExecuted { block_index: Nat },
}

fn treasury_principal() -> Principal { p(0x01) } // matches deploy_stack treasury_canister

fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode(
        "get_accounting_state",
        // DEF-076: get_accounting_state is controller-gated — read as controller.
        pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()),
    )
}

fn seed_ops_reserve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: () = decode(
        "inject_operations_reserve_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_operations_reserve_for_test",
            candid::encode_one(amount).unwrap(),
        ),
    );
}

fn force_transport_unknown(pic: &PocketIc, s: &Stack, enable: bool) {
    let _: () = decode(
        "force_treasury_transport_unknown_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_treasury_transport_unknown_for_test",
            candid::encode_one(enable).unwrap(),
        ),
    );
}

fn disb_status_tag(pic: &PocketIc, s: &Stack, proposal_id: u64) -> u8 {
    decode(
        "treasury_disbursement_status_tag_for_test",
        pic.query_call(
            s.pool,
            s.controller,
            "treasury_disbursement_status_tag_for_test",
            candid::encode_one(proposal_id).unwrap(),
        ),
    )
}

fn treasury_disburse(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    args: TreasuryDisburseArgs,
) -> Result<TreasuryDisburseResult, PoolError> {
    decode(
        "treasury_disburse",
        pic.update_call(s.pool, caller, "treasury_disburse", candid::encode_one(args).unwrap()),
    )
}

fn reconcile_disburse(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    proposal_id: u64,
    outcome: DisburseOutcome,
) -> Result<Vec<u8>, pocket_ic::RejectResponse> {
    pic.update_call(
        s.pool,
        caller,
        "reconcile_treasury_disburse",
        candid::encode_args((proposal_id, outcome)).unwrap(),
    )
}

fn disburse_args(proposal_id: u64, recipient: Principal, amount: u128) -> TreasuryDisburseArgs {
    TreasuryDisburseArgs {
        proposal_id,
        bucket: TreasuryReserveBucket::Operations,
        recipient,
        recipient_subaccount: None,
        amount,
        expected_ledger_fee: DEFAULT_FEE,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 Mode A — two concurrent calls with the same proposal_id pay once
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_treasury_disburse_concurrent_same_proposal_executes_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD1);
    let amount = 5 * STSH;
    fund_pool_1000(&pic, &s); // pool ledger balance
    seed_ops_reserve(&pic, &s, 500 * STSH); // reserve to debit
    let ops_before = accounting(&pic, &s).operations_reserve;

    let treasury = treasury_principal();
    let a = disburse_args(1, recipient, amount);
    let m1 = pic
        .submit_call(s.pool, treasury, "treasury_disburse", candid::encode_one(a.clone()).unwrap())
        .expect("submit disburse 1");
    let m2 = pic
        .submit_call(s.pool, treasury, "treasury_disburse", candid::encode_one(a).unwrap())
        .expect("submit disburse 2");
    let r1: Result<TreasuryDisburseResult, PoolError> = decode("disburse 1", pic.await_call(m1));
    let r2: Result<TreasuryDisburseResult, PoolError> = decode("disburse 2", pic.await_call(m2));

    let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "exactly one disbursement may execute; r1={:?} r2={:?}", r1, r2);
    assert_eq!(token_balance(&pic, &s, recipient), amount, "recipient debited exactly once");
    assert_eq!(
        accounting(&pic, &s).operations_reserve,
        ops_before - (amount + DEFAULT_FEE),
        "reserve debited exactly once (amount + fee)"
    );
    assert_eq!(disb_status_tag(&pic, &s, 1), 2, "record is Executed");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 Mode A — validation failure leaves no in-progress record
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_treasury_disburse_validation_failure_clears_pending_record() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD2);
    let amount = 5 * STSH;
    // Seed the reserve but DO NOT fund the pool ledger → the post-claim balance
    // check fails, exercising the abort (re-credit + remove) path.
    seed_ops_reserve(&pic, &s, 500 * STSH);
    let ops_before = accounting(&pic, &s).operations_reserve;

    let r = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(7, recipient, amount));
    assert!(
        matches!(r, Err(PoolError::EscrowUnderfunded { .. })),
        "underfunded pool must fail validation; got {:?}", r
    );
    assert_eq!(disb_status_tag(&pic, &s, 7), 0, "no in-progress record may persist");
    assert_eq!(
        accounting(&pic, &s).operations_reserve, ops_before,
        "reserve must be restored after the aborted claim"
    );

    // A subsequent legitimate call with the SAME proposal_id is not blocked.
    fund_pool_1000(&pic, &s);
    let r2 = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(7, recipient, amount));
    assert!(matches!(r2, Ok(TreasuryDisburseResult::Executed { .. })), "retry must execute; got {:?}", r2);
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 Mode B — transport-unknown enters TransportUnknown status
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_treasury_disburse_transport_unknown_enters_transport_unknown_status() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD3);
    let amount = 5 * STSH;
    fund_pool_1000(&pic, &s);
    seed_ops_reserve(&pic, &s, 500 * STSH);
    let ops_before = accounting(&pic, &s).operations_reserve;

    force_transport_unknown(&pic, &s, true);
    let r = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(8, recipient, amount));
    assert!(matches!(r, Err(PoolError::TransferFailed(_))), "transport-unknown returns TransferFailed; got {:?}", r);
    assert_eq!(disb_status_tag(&pic, &s, 8), 3, "record must be TransportUnknown (recoverable)");
    assert_eq!(token_balance(&pic, &s, recipient), 0, "no observed transfer in the simulated transport error");
    assert_eq!(
        accounting(&pic, &s).operations_reserve,
        ops_before - (amount + DEFAULT_FEE),
        "reserve remains debited under transport-unknown (no re-credit)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 Mode B — reconcile NotExecuted re-credits the reserve
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_treasury_disburse_reconcile_not_executed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD4);
    let amount = 5 * STSH;
    fund_pool_1000(&pic, &s);
    seed_ops_reserve(&pic, &s, 500 * STSH);
    let ops_before = accounting(&pic, &s).operations_reserve;
    force_transport_unknown(&pic, &s, true);
    let _ = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(9, recipient, amount));
    assert_eq!(disb_status_tag(&pic, &s, 9), 3, "precondition: TransportUnknown");

    let r: Result<ReconcileDisburseResult, PoolError> = decode(
        "reconcile not executed",
        reconcile_disburse(&pic, &s, s.controller, 9, DisburseOutcome::NotExecuted),
    );
    assert_eq!(r, Ok(ReconcileDisburseResult::Reverted), "must revert");
    assert_eq!(disb_status_tag(&pic, &s, 9), 0, "record removed after revert");
    assert_eq!(
        accounting(&pic, &s).operations_reserve, ops_before,
        "reserve must be re-credited on NotExecuted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 Mode B — reconcile Executed records without re-crediting
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_treasury_disburse_reconcile_executed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD5);
    let amount = 5 * STSH;
    fund_pool_1000(&pic, &s);
    seed_ops_reserve(&pic, &s, 500 * STSH);
    force_transport_unknown(&pic, &s, true);
    let _ = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(10, recipient, amount));
    let ops_after_unknown = accounting(&pic, &s).operations_reserve;
    assert_eq!(disb_status_tag(&pic, &s, 10), 3, "precondition: TransportUnknown");

    let r: Result<ReconcileDisburseResult, PoolError> = decode(
        "reconcile executed",
        reconcile_disburse(&pic, &s, s.controller, 10, DisburseOutcome::Executed { block_index: 42 }),
    );
    assert_eq!(
        r,
        Ok(ReconcileDisburseResult::Recorded { block_index: Nat::from(42u64) }),
        "must record Executed with the given block index"
    );
    assert_eq!(disb_status_tag(&pic, &s, 10), 2, "record is Executed");
    assert_eq!(
        accounting(&pic, &s).operations_reserve, ops_after_unknown,
        "reserve must NOT be re-credited on Executed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 Mode B — reconcile is idempotent once Executed
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_treasury_disburse_reconcile_idempotent_on_executed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD6);
    let amount = 5 * STSH;
    fund_pool_1000(&pic, &s);
    seed_ops_reserve(&pic, &s, 500 * STSH);
    // A real successful disbursement → Executed.
    let r = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(11, recipient, amount));
    assert!(matches!(r, Ok(TreasuryDisburseResult::Executed { .. })), "must execute; got {:?}", r);

    let again: Result<ReconcileDisburseResult, PoolError> = decode(
        "reconcile idempotent",
        reconcile_disburse(&pic, &s, s.controller, 11, DisburseOutcome::Executed { block_index: 7 }),
    );
    assert!(
        matches!(again, Ok(ReconcileDisburseResult::AlreadyExecuted { .. })),
        "reconcile on an already-Executed record returns AlreadyExecuted; got {:?}", again
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-027 — reconcile rejects a non-controller before any state read
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_reconcile_treasury_disburse_rejects_non_controller() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xD7);
    let amount = 5 * STSH;
    fund_pool_1000(&pic, &s);
    seed_ops_reserve(&pic, &s, 500 * STSH);
    force_transport_unknown(&pic, &s, true);
    let _ = treasury_disburse(&pic, &s, treasury_principal(), disburse_args(12, recipient, amount));
    assert_eq!(disb_status_tag(&pic, &s, 12), 3, "precondition: TransportUnknown");

    let res = reconcile_disburse(&pic, &s, p(0xFF), 12, DisburseOutcome::NotExecuted);
    assert!(res.is_err(), "non-controller reconcile must be rejected (trap)");
    assert_eq!(disb_status_tag(&pic, &s, 12), 3, "status unchanged after rejected reconcile");
}

// ═════════════════════════════════════════════════════════════════════════════
// QA-DEF-028 — nullifier-insert transport-unknown + reconcile
// ═════════════════════════════════════════════════════════════════════════════

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcileNullifierResult { CommittedFinalized, CommittedPayoutPending, NotCommittedFailed }

fn force_nullifier_unknown(pic: &PocketIc, s: &Stack, mode: u8) {
    let _: () = decode(
        "force_nullifier_insert_unknown_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_nullifier_insert_unknown_for_test",
            candid::encode_one(mode).unwrap(),
        ),
    );
}

/// Run a real private_spend with a public payout (stub verifier). Mirrors the
/// security_tests test_100 construction.
fn private_spend_payout(pic: &PocketIc, s: &Stack, spend_id: u64, recipient: Principal, public_amount: u128) -> Result<(), PoolError> {
    let root = merkle_root(pic, s);
    let args = PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: root,
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![[0x2Fu8; 32]],
        output_commitments: vec![[0x20u8; 32], [0x21u8; 32]],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: recipient,
            destination_subaccount: None,
            public_amount,
        }),
    };
    decode("private_spend", pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()))
}

fn reconcile_nullifier(pic: &PocketIc, s: &Stack, caller: Principal, spend_id: u64) -> Result<Vec<u8>, pocket_ic::RejectResponse> {
    pic.update_call(s.pool, caller, "reconcile_nullifier_insert", candid::encode_one(spend_id).unwrap())
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-028 — transport-unknown insert_batch enters NullifierInsertUnknown
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_nullifier_insert_transport_unknown_enters_unknown_status() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xE1);
    let public_amount = SPEND_PUBLIC_AMOUNT;
    fund_pool_1000(&pic, &s);
    let liability_before = accounting(&pic, &s).private_liability;

    force_nullifier_unknown(&pic, &s, 1); // registry commits, response "lost"
    let r = private_spend_payout(&pic, &s, 700, recipient, public_amount);
    assert!(matches!(r, Err(PoolError::TransferFailed(_))), "transport-unknown returns TransferFailed; got {:?}", r);

    assert!(
        matches!(spend_status(&pic, &s, 700), Some(SpendStatus::NullifierInsertUnknown { .. })),
        "spend must be NullifierInsertUnknown, not FailedAfterOutputsStaged; got {:?}",
        spend_status(&pic, &s, 700)
    );
    // No accounting applied, no payout attempted (recipient unpaid).
    assert_eq!(accounting(&pic, &s).private_liability, liability_before, "no accounting applied");
    assert_eq!(token_balance(&pic, &s, recipient), 0, "no payout attempted");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-028 — reconcile (registry committed) completes the spend
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_nullifier_insert_reconcile_committed_completes_spend() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xE2);
    let public_amount = SPEND_PUBLIC_AMOUNT;
    fund_pool_1000(&pic, &s);
    let liability_before = accounting(&pic, &s).private_liability;

    force_nullifier_unknown(&pic, &s, 1); // registry DID commit
    let _ = private_spend_payout(&pic, &s, 701, recipient, public_amount);
    assert!(matches!(spend_status(&pic, &s, 701), Some(SpendStatus::NullifierInsertUnknown { .. })), "precondition");

    let rec: Result<ReconcileNullifierResult, PoolError> =
        decode("reconcile committed", reconcile_nullifier(&pic, &s, s.controller, 701));
    assert_eq!(rec, Ok(ReconcileNullifierResult::CommittedPayoutPending), "committed payout spend → PayoutPending");
    assert!(
        matches!(spend_status(&pic, &s, 701), Some(SpendStatus::PayoutPending { .. })),
        "status must be PayoutPending after reconcile"
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        liability_before - public_amount,
        "accounting applied exactly once on reconcile (liability debited by public_amount)"
    );

    // Full recovery: the deferred payout can now be completed.
    let pay: Result<Nat, PoolError> = decode(
        "retry payout",
        pic.update_call(s.pool, s.controller, "retry_private_spend_payout", candid::encode_one(701u64).unwrap()),
    );
    assert!(pay.is_ok(), "deferred payout completes; got {:?}", pay);
    assert_eq!(token_balance(&pic, &s, recipient), public_amount - DEFAULT_FEE, "recipient paid once");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-028 — reconcile (registry did NOT commit) fails cleanly
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_nullifier_insert_reconcile_not_committed_fails_cleanly() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xE3);
    let public_amount = SPEND_PUBLIC_AMOUNT;
    fund_pool_1000(&pic, &s);
    let liability_before = accounting(&pic, &s).private_liability;

    force_nullifier_unknown(&pic, &s, 2); // registry did NOT commit, response lost
    let _ = private_spend_payout(&pic, &s, 702, recipient, public_amount);
    assert!(matches!(spend_status(&pic, &s, 702), Some(SpendStatus::NullifierInsertUnknown { .. })), "precondition");

    let rec: Result<ReconcileNullifierResult, PoolError> =
        decode("reconcile not committed", reconcile_nullifier(&pic, &s, s.controller, 702));
    assert_eq!(rec, Ok(ReconcileNullifierResult::NotCommittedFailed), "not committed → fail cleanly");
    assert!(
        matches!(spend_status(&pic, &s, 702), Some(SpendStatus::FailedAfterOutputsStaged { .. })),
        "status must be FailedAfterOutputsStaged"
    );
    assert_eq!(accounting(&pic, &s).private_liability, liability_before, "no accounting applied");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-028 — reconcile rejects a non-controller before any state read
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_nullifier_insert_reconcile_rejects_non_controller() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let recipient = p(0xE4);
    fund_pool_1000(&pic, &s);
    force_nullifier_unknown(&pic, &s, 1);
    let _ = private_spend_payout(&pic, &s, 703, recipient, SPEND_PUBLIC_AMOUNT);
    assert!(matches!(spend_status(&pic, &s, 703), Some(SpendStatus::NullifierInsertUnknown { .. })), "precondition");

    let res = reconcile_nullifier(&pic, &s, p(0xFF), 703);
    assert!(res.is_err(), "non-controller reconcile must be rejected (trap)");
    assert!(
        matches!(spend_status(&pic, &s, 703), Some(SpendStatus::NullifierInsertUnknown { .. })),
        "status unchanged after rejected reconcile"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-028 — reconcile rejects a wrong (non-NullifierInsertUnknown) status
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_nullifier_insert_reconcile_rejects_wrong_status() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    // A spend in Finalized status (injected) — reconcile must reject it.
    inject_payout_pending(&pic, &s, 704, p(0xE5), 100 * STSH);
    set_spend_status(&pic, &s, 704, SpendStatus::Finalized);

    let rec: Result<ReconcileNullifierResult, PoolError> =
        decode("reconcile wrong status", reconcile_nullifier(&pic, &s, s.controller, 704));
    assert_eq!(rec, Err(PoolError::WrongSpendStatus), "reconcile on a non-NullifierInsertUnknown spend must be rejected");
    assert_eq!(spend_status(&pic, &s, 704), Some(SpendStatus::Finalized), "status unchanged");
}

// ═════════════════════════════════════════════════════════════════════════════
// Reconcile Hardening Lane — DEF-097 / DEF-099
// ═════════════════════════════════════════════════════════════════════════════

/// Inject a pending spend with explicit nullifiers + status (pool testing endpoint,
/// same as record_retention_tests).
fn inject_spend_with_nullifiers(
    pic: &PocketIc,
    s: &Stack,
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    status: SpendStatus,
) {
    let _: () = decode(
        "inject_spend_with_nullifiers_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_spend_with_nullifiers_for_test",
            candid::encode_args((spend_id, nullifiers, status)).unwrap(),
        ),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-099 — the in-flight claim marker rejects a second reconcile IMMEDIATELY
// (deterministic wrong-status guard test — brief-approved fallback pattern)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_def099_reconcile_inflight_marker_rejected_immediately() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    // A spend already claimed by a (simulated) in-flight reconcile.
    inject_spend_with_nullifiers(
        &pic, &s, 705,
        vec![[0x71u8; 32]],
        SpendStatus::NullifierReconcileInFlight,
    );

    let rec: Result<ReconcileNullifierResult, PoolError> =
        decode("reconcile vs marker", reconcile_nullifier(&pic, &s, s.controller, 705));
    assert_eq!(
        rec,
        Err(PoolError::WrongSpendStatus),
        "a second reconcile must be rejected immediately while the claim is held"
    );
    // The gate rejects BEFORE claiming, so the injected marker is untouched —
    // proving the rejection happened with no state mutation at all.
    assert_eq!(
        spend_status(&pic, &s, 705),
        Some(SpendStatus::NullifierReconcileInFlight),
        "rejected call must not mutate the record"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-099 — registry transport failure restores the retriable status; the claim
// marker never strands, and the reconcile succeeds after the registry returns
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_def099_reconcile_restores_unknown_on_registry_transport_failure() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    inject_spend_with_nullifiers(
        &pic, &s, 706,
        vec![[0x72u8; 32]],
        SpendStatus::NullifierInsertUnknown { reason: "seed".to_string() },
    );

    // Kill the registry: the contains_nullifier query rejects (transport failure).
    pic.stop_canister(s.null, None).expect("stop nullifier registry");
    let rec: Result<ReconcileNullifierResult, PoolError> =
        decode("reconcile vs stopped registry", reconcile_nullifier(&pic, &s, s.controller, 706));
    assert!(
        matches!(rec, Err(PoolError::TransferFailed(_))),
        "query transport failure must propagate as TransferFailed; got {:?}", rec
    );
    assert!(
        matches!(
            spend_status(&pic, &s, 706),
            Some(SpendStatus::NullifierInsertUnknown { .. })
        ),
        "status must be RESTORED to NullifierInsertUnknown — the claim marker never strands; got {:?}",
        spend_status(&pic, &s, 706)
    );

    // Retriability end-to-end: registry back up (empty) → objective negative path.
    pic.start_canister(s.null, None).expect("restart nullifier registry");
    let rec2: Result<ReconcileNullifierResult, PoolError> =
        decode("reconcile after restart", reconcile_nullifier(&pic, &s, s.controller, 706));
    assert_eq!(
        rec2,
        Ok(ReconcileNullifierResult::NotCommittedFailed),
        "restored record must be reconcilable on retry (registry empty → not committed)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-097 — disbursement lifecycle proven by its observable debit-state
// consequences (PendingValidation/PendingTransfer are transient within one
// message by design; tests assert observable state, not internals)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_def097_disbursement_lifecycle_by_debit_state() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let treasury = treasury_principal();
    let recipient = p(0xE8);
    let amount = 10 * STSH;
    fund_pool_1000(&pic, &s);
    seed_ops_reserve(&pic, &s, 500 * STSH);

    // (a) PendingValidation contract: a pre-debit validation failure (fee
    // mismatch) removes the claim entirely — no record persists, no debit.
    let mut bad = disburse_args(910, recipient, amount);
    bad.expected_ledger_fee = DEFAULT_FEE + 1;
    let r = treasury_disburse(&pic, &s, treasury, bad);
    assert!(matches!(r, Err(PoolError::TransferFailed(_))), "fee mismatch must reject; got {:?}", r);
    assert_eq!(disb_status_tag(&pic, &s, 910), 0, "PendingValidation claim removed on validation failure");
    assert_eq!(
        accounting(&pic, &s).operations_reserve,
        500 * STSH,
        "no reserve debit may be recorded during validation"
    );

    // (b) PendingTransfer contract: the debit is recorded BEFORE the transfer
    // await, so a transport-unknown outcome persists TransportUnknown (tag 3)
    // with the debit kept.
    force_transport_unknown(&pic, &s, true);
    let r = treasury_disburse(&pic, &s, treasury, disburse_args(911, recipient, amount));
    assert!(matches!(r, Err(PoolError::TransferFailed(_))), "transport-unknown must reject; got {:?}", r);
    assert_eq!(disb_status_tag(&pic, &s, 911), 3, "TransportUnknown after the lost transfer");
    assert_eq!(
        accounting(&pic, &s).operations_reserve,
        500 * STSH - amount - DEFAULT_FEE,
        "the reserve debit recorded before the transfer await must persist"
    );

    // (c) objective NotExecuted reconcile: re-credit + remove (proposal reusable).
    let rec: Result<ReconcileDisburseResult, PoolError> = decode(
        "reconcile NotExecuted",
        reconcile_disburse(&pic, &s, s.controller, 911, DisburseOutcome::NotExecuted),
    );
    assert_eq!(rec, Ok(ReconcileDisburseResult::Reverted), "NotExecuted must revert");
    assert_eq!(disb_status_tag(&pic, &s, 911), 0, "record removed after revert");
    assert_eq!(accounting(&pic, &s).operations_reserve, 500 * STSH, "reserve re-credited");

    // (d) terminal Executed: happy path debits once and pays once.
    force_transport_unknown(&pic, &s, false);
    let r = treasury_disburse(&pic, &s, treasury, disburse_args(912, recipient, amount));
    assert!(
        matches!(r, Ok(TreasuryDisburseResult::Executed { .. })),
        "happy-path disburse must execute; got {:?}", r
    );
    assert_eq!(disb_status_tag(&pic, &s, 912), 2, "Executed");
    assert_eq!(
        accounting(&pic, &s).operations_reserve,
        500 * STSH - amount - DEFAULT_FEE,
        "reserve debited exactly once"
    );
    assert_eq!(token_balance(&pic, &s, recipient), amount, "recipient paid exactly once");
}

#[path = "r15/mod.rs"]
mod r15;
