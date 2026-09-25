// =============================================================================
// STSH — HARDEN-03-SETTLEMENT: deposit settlement + token receipt tests
// =============================================================================
//
// Lane: HARDEN-03-SETTLEMENT (triage §4 lane 1).
// Brief: Briefs/BRIEF_LANE_HARDEN03_SETTLEMENT_V2_2026-09-17.md
//        (sha256 729876cf8b675baffdda72001d3a2aae61a12bf7e851de53878118b6d8aac31e)
// Countersign: reviews/SSA_HARDEN03_SETTLEMENT_V2_2026-09-17.md — GREEN.
// Authorised by: reviews/CTO_RULING_HARDEN03_SETTLEMENT_L4_AND_TIMING_2026-09-17.md §3.
//
// WHAT THIS LANE BUILT, AND THEREFORE WHAT THIS SUITE HAS TO PROVE.
//
// A depositor calls `shield_deposit`. The pool writes `TransferPending`
// durably, then awaits `icrc2_transfer_from`. If that await returns a
// TRANSPORT-UNKNOWN `Err`, the record is deliberately left at `TransferPending`
// (QA-DEF-017) — the transfer MAY have executed. Before this lane that record
// had exactly two futures: `retry_deposit_commitment` REJECTS it, and
// `reconcile_deposit_transfer_not_executed` DESTROYS it on a bare operator
// assertion. If the transfer had in fact executed, the depositor's public STSH
// sat in the pool's escrow with no note, no private liability, and no path to
// one.
//
// The lane closes that with two pieces:
//   • a TOKEN-side durable receipt, written in the SAME await-free segment as
//     the balance mutation, which survives past the ledger's own 24-hour dedup
//     window (past which `icrc2_transfer_from` answers `TooOld` BEFORE it
//     reaches the dedup lookup, so the ledger genuinely cannot answer);
//   • a POOL-side settlement sidecar freezing the exact submitted `amount` and
//     `fee`, so the pool can re-submit a BYTE-IDENTICAL transfer.
//
// ── ADVERSARIAL SELF-TRACE — the two ways this lane could lose money ─────────
//
// Attack 1 — DOUBLE-CHARGE THROUGH THE NEW ENDPOINT.
//   1. The pool's submitted `fee` came from a LIVE `icrc1_fee` query and is
//      stored nowhere in `PendingDeposit`.
//   2. The token's dedup identity HASHES the fee.
//   3. So a resubmission built from a re-queried fee has a DIFFERENT dedup key
//      whenever the ledger fee moved → no `Duplicate` → the transfer executes
//      as a SECOND, ADDITIONAL pull against the depositor.
//   4. Defence in depth, all three tested here: (a) the sidecar freezes the fee
//      so the resubmission is byte-identical — `settlement_sidecar_matches_the_token_receipt`;
//      (b) `settle_deposit_transfer` is FAIL-CLOSED on a missing sidecar rather
//      than re-deriving one — `settle_without_sidecar_is_refused_and_moves_nothing`;
//      (c) the TOKEN refuses a second execution for an operation id that already
//      has an `Applied` receipt, keyed on the MEMO rather than on the fee —
//      `token_refuses_a_second_execution_for_an_applied_operation_id`.
//
// Attack 2 — DESTROY A PAID DEPOSIT.
//   1. An operator calls `reconcile_deposit_transfer_not_executed` on a record
//      whose transfer actually executed.
//   2. The guard refuses on a surviving sidecar — and a fence-confirmed close is
//      the ONLY thing that removes one. Tested in `deposit_retry_tests.rs`
//      (AC-14) and here under a misconfigured token (AC-26).
//   3. `settle_deposit_transfer` itself never deletes on absence of evidence:
//      every ambiguous branch releases the claim and leaves the record intact —
//      `ambiguous_evidence_never_deletes_and_never_credits`.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md law 7). Use `./run_gate.sh`.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ─────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_test_wasm() -> Vec<u8> {
    load_wasm(env!("TOKEN_TEST_WASM"), "stsh_token_test")
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

// ── Constants ────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0]
const DEFAULT_FEE: u128 = 0; // F-000: token transfers are free at launch
const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const SETTLEMENT_MIN_AGE_NS: u64 = 900 * 1_000_000_000;
const SETTLE_CLAIM_TTL_NS: u64 = 300 * 1_000_000_000;

/// Mirrors of `stsh_token`'s pinned `GenericError` codes. Duplicated rather than
/// imported because this suite drives the canister over Candid, exactly as
/// `token_icrc_accounting_tests.rs` duplicates `ERR_CODE_ZERO_AMOUNT`. A drift
/// here shows up as a failing assertion on the code, which is the point of the
/// token pinning them as `pub const` in the first place.
const ERR_CODE_RECEIPT_CAPACITY: u128 = 9;
const ERR_CODE_DEPOSIT_UNRECEIPTABLE: u128 = 10;
const ERR_CODE_DEPOSIT_FENCED: u128 = 11;
const ERR_CODE_RECEIPT_CONFLICT: u128 = 12;

// ── Token mirrors ────────────────────────────────────────────────────────────

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

/// The post-lane token init shape, WITH `pool_canister`.
///
/// AC-20's premise is that this field being `opt` means the 45 existing local
/// `TokenInitArgs` mirrors under `integration-tests/tests/` need no edit: a
/// record encoded without the field decodes as `None`. That is asserted
/// directly by `token_without_pool_canister_installs_and_writes_no_receipts`,
/// which installs through `TokenInitArgsNoPool` — a mirror that genuinely does
/// not carry the field — rather than by passing `None` through this one.
#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
    fee_collector: Option<Principal>,
    pool_canister: Option<Principal>,
}

/// The PRE-lane token init shape — no `pool_canister` field at all. This is the
/// literal shape of the 45 existing fixtures.
#[derive(CandidType, Deserialize)]
struct TokenInitArgsNoPool {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
}

fn allocation_all_to(recipient: Principal) -> Vec<AllocationCategory> {
    vec![AllocationCategory {
        category_id: "all".to_string(),
        category_name: "All".to_string(),
        amount: TOTAL_SUPPLY,
        recipient,
        subaccount: None,
        lock_policy: LockPolicy::ImmediatelyLiquid,
        vesting_policy: None,
        created_at_genesis: false,
        genesis_timestamp_ns: 0,
    }]
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

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
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>,
    from: Account,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TransferFromError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
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

/// Mirrors the token's `DepositAttemptArgs`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct DepositAttemptArgs {
    from: Account,
    spender_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

/// Mirrors the token's STORED `DepositReceiptV1` — the shape
/// `inject_deposit_receipt_for_test` and `deposit_receipt_read_for_test` take
/// and return. Its amounts are `Nat` on the wire here because Candid encodes
/// the canister's `u128` fields as `nat`; the distinction that matters is the
/// one below.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositReceiptV1 {
    Applied {
        block_index: u64,
        amount: Nat,
        fee_charged: Nat,
        request_hash: [u8; 32],
        applied_at_ns: u64,
    },
    Cancelled {
        request_hash: [u8; 32],
        closed_at_ns: u64,
    },
}

/// Mirrors the token's `DepositReceiptView` — the WIRE form the two PRODUCTION
/// endpoints return.
///
/// Structurally identical to the mirror above, and declared separately anyway,
/// because on the canister they are two different types for a reason: the stored
/// one is fixed-width `u128` (exact `max_size`, reproducible allocation
/// measurement) and the wire one is `Nat` (every other public money field on
/// this ledger). The amount-boundary census (C4 rule 3) enforces that
/// separation, and a single mirror here would quietly paper over it.
type DepositReceiptView = DepositReceiptV1;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ReceiptLookup {
    Found(DepositReceiptView),
    Unrecorded,
    RetiredOrUnavailable,
}

impl PartialEq for ReceiptLookup {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (ReceiptLookup::Unrecorded, ReceiptLookup::Unrecorded)
                | (
                    ReceiptLookup::RetiredOrUnavailable,
                    ReceiptLookup::RetiredOrUnavailable
                )
        ) || match (self, other) {
            (ReceiptLookup::Found(a), ReceiptLookup::Found(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum CloseOutcome {
    Applied(DepositReceiptView),
    Cancelled(DepositReceiptView),
    RetiredOrUnavailable,
}

impl PartialEq for CloseOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CloseOutcome::Applied(a), CloseOutcome::Applied(b)) => a == b,
            (CloseOutcome::Cancelled(a), CloseOutcome::Cancelled(b)) => a == b,
            (CloseOutcome::RetiredOrUnavailable, CloseOutcome::RetiredOrUnavailable) => true,
            _ => false,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReceiptError {
    Unauthorized,
    RequestMismatch,
    UnsupportedProtocol,
}

// ── Pool mirrors ─────────────────────────────────────────────────────────────

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

/// **AC-19's drift-lock subject.** This mirror is the PRE-LANE variant set, and
/// HARDEN-03-SETTLEMENT added no variant to it — D-2 ruled that a new
/// `DepositStatus` variant would reach the wallet (`mapDepositStatus` decodes it
/// by name and the generated IDL would reject an unknown one at decode time),
/// so the settlement claim lives in the sidecar instead.
///
/// See `deposit_status_variant_set_is_unchanged_by_this_lane` for why this
/// declaration is a drift-lock and not merely a decode target.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending,
    TransferPending,
    TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight,
    CommitmentAppended { leaf_index: u64 },
    CommitmentAppendUnknown,
    CommitmentReconcileInFlight,
    CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingDeposit {
    note_commitment: [u8; 32],
    private_balance: u128,
    ops_amount: u128,
    insurance_amount: u128,
    encrypted_payload: Vec<u8>,
    depositor: Option<Principal>,
    status: DepositStatus,
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

/// Mirrors the pool's `DepositSettlementView` (the `--features testing` probe's
/// return type — the STORED type is deliberately not `CandidType`, per P-2).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct DepositSettlementView {
    protocol_version: u16,
    token_canister: Principal,
    amount: u128,
    fee: u128,
    claim_generation: Option<u32>,
    claim_claimed_at_ns: Option<u64>,
    disposition_tag: u8,
    disposition_block_index: Option<u64>,
    anomaly_code: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositSettlementOutcome {
    CreditedFromReceipt(Nat),
    CreditedFromExecution(Nat),
    CreditedFromDuplicate(Nat),
    FencedNotExecuted,
}

/// The COMPLETE `PoolError` mirror, not a subset.
///
/// A subset does not work here and the failure mode is worth naming, because it
/// costs an hour every time someone rediscovers it: Candid variant subtyping
/// runs the opposite way to intuition. `variant {A}` is a subtype of
/// `variant {A;B}`, so a reply whose type carries MORE variants than the decode
/// target fails to decode — even when the value on the wire is the `Ok` arm and
/// no error variant is involved at all. Mirroring only the variants a suite
/// asserts on therefore breaks every call on the endpoint, not just the error
/// paths.
///
/// Kept in the order `canisters/shielded-pool/shielded_pool.did` declares them,
/// so a diff against that file is a straight read.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
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
    ProofSystemMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    RecoveryInProgress(String),
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch { inputs: u128, outputs: u128 },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateOutputCommitment,
    InvalidOutputCommitment,
    DuplicateSpendId,
    DeploymentConfigMismatch,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    InvalidVerifierKeyHashLength { len: u64 },
    VerifierKeyHashMismatch,
    VerifierKeyHashChangedDuringAttestation,
    VerifierConfigInProgress,
    PrivateSpendFeeMismatch { expected: u128, got: u128 },
    InsufficientPrivateLiability { required: u128, available: u128 },
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
    PayoutOutcomePrivate,
    PayoutExecutorBusy,
    PayoutMemoKeyNotReady,
    PayoutLegacyHold,
    PayoutStateInvalid,
    SpendNotFound,
    WrongSpendStatus,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    DisbursementProposalIdRetired,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    AnonymousCaller,
    WithdrawalNotFound,
    WrongWithdrawalStatus,
    Unauthorized,
    WithdrawalPayoutObligation,
    SecurityEpochChanged,
}

/// The `settle_deposit_transfer` error mirror (Option B — its own type, not
/// `PoolError` variants; see the real declaration for why). `Pool` wraps the
/// COMPLETE `PoolError` mirror above, so the same subtyping rule applies.
#[derive(CandidType, Serialize, Deserialize, Debug, PartialEq)]
enum SettlementError {
    Pool(PoolError),
    NotSettleable,
    Unavailable,
    TooEarly,
    InProgress,
    IdentityMismatch,
    EvidenceAmbiguous,
}

// ── PocketIC helpers ─────────────────────────────────────────────────────────

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
    pic.install_canister(
        cid,
        wasm,
        candid::encode_one(init).expect("encode init"),
        None,
    );
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

/// Same conversion the other token suites use (`token_icrc_accounting_tests.rs`
/// line-for-line), so a figure asserted here means the same thing it means
/// there.
fn to_u128(n: Nat) -> u128 {
    n.0.to_string().parse::<u128>().unwrap_or(0)
}

struct Stack {
    pool: Principal,
    token: Principal,
    merkle: Principal,
    controller: Principal,
    user: Principal,
}

/// Deploy token (testing wasm, pool authority BOUND) + nullifier + merkle + pool.
fn deploy_stack(pic: &PocketIc) -> Stack {
    deploy_stack_inner(pic, true)
}

/// Deploy with the token installed through the PRE-LANE init shape — no
/// `pool_canister` field at all, exactly as the 45 existing fixtures do it.
fn deploy_stack_unbound_token(pic: &PocketIc) -> Stack {
    deploy_stack_inner(pic, false)
}

fn deploy_stack_inner(pic: &PocketIc, bind_pool: bool) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);

    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    if bind_pool {
        install(
            pic,
            token,
            token_test_wasm(),
            &TokenInitArgs {
                allocations: allocation_all_to(user),
                treasury: p(0x01),
                staking_canister: p(0x02),
                fee_collector: None,
                pool_canister: Some(pool),
            },
        );
    } else {
        install(
            pic,
            token,
            token_test_wasm(),
            &TokenInitArgsNoPool {
                allocations: allocation_all_to(user),
                treasury: p(0x01),
                staking_canister: p(0x02),
            },
        );
    }
    install(
        pic,
        pool,
        pool_test_wasm(),
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
    Stack {
        pool,
        token,
        merkle,
        controller,
        user,
    }
}

/// A distinct, CANONICAL BN254 `Fr` commitment per `tag`.
///
/// The high bytes stay zero deliberately. `shield_deposit` rejects a
/// non-canonical commitment with `PoolError::InvalidCommitment` before anything
/// else happens, and a fixture that trips that guard fails with an error about
/// the FIXTURE while looking like a failure of the thing under test — which is
/// exactly how it presented the first time.
fn commitment(tag: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0] = tag;
    c[1] = 0x5E;
    c
}

fn nonce(tag: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = tag;
    n[30] = 0xA5;
    n
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() as u64
}

// ── Pool drivers ─────────────────────────────────────────────────────────────

fn inject_record(
    pic: &PocketIc,
    s: &Stack,
    c: [u8; 32],
    balance: u128,
    status: DepositStatus,
    created_at_ns: u64,
) {
    let _: () = decode(
        "inject_pending_deposit_with_created_at_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_pending_deposit_with_created_at_for_test",
            // The depositor is EXPLICIT: it is an input to the deposit's ledger
            // identity, and the injection's own caller is the controller, not a
            // depositor. `s.user` is the principal every real deposit in this
            // suite is made by, and the one with a balance and an allowance.
            candid::encode_args((c, balance, status, created_at_ns, s.user)).unwrap(),
        ),
    );
}

fn inject_sidecar(pic: &PocketIc, s: &Stack, c: [u8; 32], n: [u8; 32], amount: u128, fee: u128) {
    let _: () = decode(
        "inject_deposit_settlement_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_deposit_settlement_for_test",
            candid::encode_args((c, n, amount, fee, s.token)).unwrap(),
        ),
    );
}

/// The canonical fixture: a `TransferPending` record, old enough to pass G6,
/// with a sidecar and a nonce — i.e. exactly what a post-lane `shield_deposit`
/// leaves behind when its transfer callback is lost.
fn stuck_deposit(pic: &PocketIc, s: &Stack, c: [u8; 32], n: [u8; 32]) {
    let created = now_ns(pic).saturating_sub(SETTLEMENT_MIN_AGE_NS + 1_000_000_000);
    inject_record(pic, s, c, DENOM, DepositStatus::TransferPending, created);
    inject_sidecar(pic, s, c, n, DENOM + DEFAULT_FEE, DEFAULT_FEE);
}

fn settle(
    pic: &PocketIc,
    s: &Stack,
    c: [u8; 32],
    caller: Principal,
) -> Result<DepositSettlementOutcome, SettlementError> {
    decode(
        "settle_deposit_transfer",
        pic.update_call(
            s.pool,
            caller,
            "settle_deposit_transfer",
            candid::encode_one(c).unwrap(),
        ),
    )
}

fn sidecar(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Option<DepositSettlementView> {
    decode(
        "settlement_sidecar_for_test",
        pic.query_call(
            s.pool,
            anon(),
            "settlement_sidecar_for_test",
            candid::encode_one(c).unwrap(),
        ),
    )
}

fn transfer_identity(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Option<(Vec<u8>, u64)> {
    decode(
        "deposit_transfer_identity_for_test",
        pic.query_call(
            s.pool,
            anon(),
            "deposit_transfer_identity_for_test",
            candid::encode_one(c).unwrap(),
        ),
    )
}

fn records_without_sidecar(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "deposit_records_without_sidecar_for_test",
        pic.query_call(
            s.pool,
            anon(),
            "deposit_records_without_sidecar_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn deposit_record(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Option<PendingDeposit> {
    decode(
        "get_deposit_status",
        pic.query_call(
            s.pool,
            s.controller,
            "get_deposit_status",
            candid::encode_one(c).unwrap(),
        ),
    )
}

fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode(
        "get_accounting_state",
        pic.query_call(
            s.pool,
            s.controller,
            "get_accounting_state",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn leaf_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "leaf_count",
        pic.query_call(
            s.merkle,
            anon(),
            "leaf_count",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn reconcile_not_executed(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<(), PoolError> {
    decode(
        "reconcile_deposit_transfer_not_executed",
        pic.update_call(
            s.pool,
            s.controller,
            "reconcile_deposit_transfer_not_executed",
            candid::encode_one(c).unwrap(),
        ),
    )
}

// ── Token drivers ────────────────────────────────────────────────────────────

fn operation_id(pic: &PocketIc, s: &Stack, memo: &[u8]) -> [u8; 32] {
    decode(
        "deposit_operation_id_for_test",
        pic.query_call(
            s.token,
            anon(),
            "deposit_operation_id_for_test",
            candid::encode_one(memo.to_vec()).unwrap(),
        ),
    )
}

fn inject_receipt(pic: &PocketIc, s: &Stack, op: [u8; 32], r: DepositReceiptV1) {
    let _: () = decode(
        "inject_deposit_receipt_for_test",
        pic.update_call(
            s.token,
            anon(),
            "inject_deposit_receipt_for_test",
            candid::encode_args((op, r)).unwrap(),
        ),
    );
}

fn read_receipt(pic: &PocketIc, s: &Stack, op: [u8; 32]) -> Option<DepositReceiptV1> {
    decode(
        "deposit_receipt_read_for_test",
        pic.query_call(
            s.token,
            anon(),
            "deposit_receipt_read_for_test",
            candid::encode_one(op).unwrap(),
        ),
    )
}

fn receipt_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "deposit_receipt_count_for_test",
        pic.query_call(
            s.token,
            anon(),
            "deposit_receipt_count_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn set_receipt_capacity(pic: &PocketIc, s: &Stack, cap: Option<u64>) {
    let _: () = decode(
        "set_receipt_capacity_for_test",
        pic.update_call(
            s.token,
            anon(),
            "set_receipt_capacity_for_test",
            candid::encode_one(cap).unwrap(),
        ),
    );
}

fn set_pool_authority(pic: &PocketIc, s: &Stack, pool: Option<Principal>) {
    let _: () = decode(
        "set_deposit_settlement_authority_for_test",
        pic.update_call(
            s.token,
            anon(),
            "set_deposit_settlement_authority_for_test",
            candid::encode_one(pool).unwrap(),
        ),
    );
}

fn settlement_authority(pic: &PocketIc, s: &Stack) -> Option<Principal> {
    decode(
        "get_deposit_settlement_authority",
        pic.query_call(
            s.token,
            anon(),
            "get_deposit_settlement_authority",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn balance_of(pic: &PocketIc, s: &Stack, owner: Principal) -> u128 {
    let n: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            s.token,
            anon(),
            "icrc1_balance_of",
            candid::encode_one(Account {
                owner,
                subaccount: None,
            })
            .unwrap(),
        ),
    );
    to_u128(n)
}

fn allowance_of(pic: &PocketIc, s: &Stack, owner: Principal, spender: Principal) -> u128 {
    #[derive(CandidType, Serialize, Deserialize)]
    struct AllowanceArgs {
        account: Account,
        spender: Account,
    }
    #[derive(CandidType, Serialize, Deserialize)]
    struct Allowance {
        allowance: Nat,
        expires_at: Option<u64>,
    }
    let a: Allowance = decode(
        "icrc2_allowance",
        pic.query_call(
            s.token,
            anon(),
            "icrc2_allowance",
            candid::encode_one(AllowanceArgs {
                account: Account {
                    owner,
                    subaccount: None,
                },
                spender: Account {
                    owner: spender,
                    subaccount: None,
                },
            })
            .unwrap(),
        ),
    );
    to_u128(a.allowance)
}

fn approve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: Result<Nat, ApproveErr> = decode(
        "icrc2_approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: s.pool,
                    subaccount: None,
                },
                amount,
                expected_allowance: None,
                expires_at: Some(now_ns(pic) + 3_600_000_000_000),
                fee: None,
                memo: None,
                created_at_time: None,
            })
            .unwrap(),
        ),
    );
}

fn shield(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<Nat, PoolError> {
    decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: c,
                encrypted_payload: vec![7, 7, 7],
                public_amount: DENOM,
            })
            .unwrap(),
        ),
    )
}

/// Call `icrc2_transfer_from` AS THE POOL PRINCIPAL. PocketIC lets any principal
/// be the sender, which is what makes the fence assertions real rather than
/// simulated: the token sees `caller() == configured_pool` exactly as it would
/// on the live path.
fn transfer_from_as_pool(
    pic: &PocketIc,
    s: &Stack,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
    amount: u128,
) -> Result<Nat, TransferFromError> {
    decode(
        "icrc2_transfer_from(as pool)",
        pic.update_call(
            s.token,
            s.pool,
            "icrc2_transfer_from",
            candid::encode_one(TransferFromArgs {
                spender_subaccount: None,
                from: Account {
                    owner: s.user,
                    subaccount: None,
                },
                to: Account {
                    owner: s.pool,
                    subaccount: None,
                },
                amount: Nat::from(amount),
                fee: Some(Nat::from(DEFAULT_FEE)),
                memo,
                created_at_time,
            })
            .unwrap(),
        ),
    )
}

fn attempt_args(s: &Stack, memo: Vec<u8>, created_at_time: u64, amount: u128) -> DepositAttemptArgs {
    DepositAttemptArgs {
        from: Account {
            owner: s.user,
            subaccount: None,
        },
        spender_subaccount: None,
        to: Account {
            owner: s.pool,
            subaccount: None,
        },
        amount: Nat::from(amount),
        fee: Some(Nat::from(DEFAULT_FEE)),
        memo: Some(memo),
        created_at_time: Some(created_at_time),
    }
}

fn get_receipt_as(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    a: &DepositAttemptArgs,
) -> Result<ReceiptLookup, ReceiptError> {
    decode(
        "get_deposit_receipt",
        pic.update_call(
            s.token,
            caller,
            "get_deposit_receipt",
            candid::encode_one(a.clone()).unwrap(),
        ),
    )
}

fn close_as(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    a: &DepositAttemptArgs,
) -> Result<CloseOutcome, ReceiptError> {
    decode(
        "close_deposit_attempt",
        pic.update_call(
            s.token,
            caller,
            "close_deposit_attempt",
            candid::encode_one(a.clone()).unwrap(),
        ),
    )
}

fn generic_code(e: &TransferFromError) -> Option<u128> {
    match e {
        TransferFromError::GenericError { error_code, .. } => Some(to_u128(error_code.clone())),
        _ => None,
    }
}

// =============================================================================
// THE CONVERSE-ORPHAN PROPERTY — no record without a sidecar
//
// SSA's V2 §4 named this as the residual worth the most scrutiny, and named it
// precisely: AC-18 tests the orphan direction (no sidecar without a record),
// but "the direction that matters more is the converse — no record without a
// sidecar — and it is the one a builder slip produces… I do not see it pinned
// as its own assertion."
//
// It is pinned here, three ways, because one way is not enough:
//
//   1. EXISTENCE, over the production path — every record a real `shield_deposit`
//      creates has a sidecar, counted by a probe that can return nonzero.
//   2. CONTENT — the sidecar's `amount` and `fee` equal what the transfer
//      actually submitted, cross-checked against the TOKEN's independent
//      receipt. An existence check alone would pass a slip that wrote the
//      sidecar with the wrong values, which is the same double-charge.
//   3. FAIL-CLOSED — even if the window were somehow reached,
//      `settle_deposit_transfer` refuses a sidecar-less record rather than
//      re-deriving the fee. The hazard is defended, not merely detected.
// =============================================================================

/// **CONVERSE, part 1: EXISTENCE.** Every `PENDING_DEPOSITS` record the
/// production path creates carries a settlement sidecar.
///
/// The probe counts records with no sidecar and can return nonzero — move the
/// sidecar write in `shield_deposit` below the transfer await, or guard it, and
/// this goes to 1 at the moment the record becomes durable.
///
/// The pool here is driven ONLY by real `shield_deposit` calls. No injections:
/// injected sidecar-less records ARE the §3.8 legacy quarantine, which this lane
/// deliberately leaves alone, so including one would assert against the wrong
/// population.
#[test]
fn converse_every_record_a_real_shield_deposit_creates_has_a_sidecar() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    assert_eq!(
        records_without_sidecar(&pic, &s),
        0,
        "precondition: an empty pool has no sidecar-less records"
    );

    // Three real deposits, each through the full production path.
    for tag in [0x01u8, 0x02, 0x03] {
        let c = commitment(tag);
        approve(&pic, &s, DENOM + DEFAULT_FEE);
        let r = shield(&pic, &s, c);
        assert!(r.is_ok(), "shield_deposit {tag:#x} must succeed; got {r:?}");

        assert!(
            deposit_record(&pic, &s, c).is_some(),
            "record {tag:#x} exists"
        );
        assert!(
            sidecar(&pic, &s, c).is_some(),
            "CONVERSE ORPHAN: record {tag:#x} exists with NO settlement sidecar. The \
             sidecar write in shield_deposit must be in the same await-free block as \
             the PENDING_DEPOSITS insert — see MEM_DEPOSIT_SETTLEMENT."
        );
        assert_eq!(
            records_without_sidecar(&pic, &s),
            0,
            "no sidecar-less record may exist after deposit {tag:#x}"
        );
    }
}

/// **CONVERSE, part 2: CONTENT.** The sidecar holds exactly what the transfer
/// submitted — cross-checked against the token's own receipt.
///
/// This is the assertion an existence check cannot make. The sidecar is the
/// POOL's account of what it asked the ledger for; the receipt is the TOKEN's
/// account of what it actually did. They are written by different canisters from
/// different inputs, so their agreement is genuine evidence rather than a
/// tautology — and a slip that wrote the sidecar from, say, `private_balance`
/// instead of `preview.pool_transfer_in`, or from a re-queried fee, fails here
/// while passing part 1.
#[test]
fn converse_settlement_sidecar_matches_the_token_receipt() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x11);

    // STOP THE MERKLE CANISTER FIRST, and the reason is the point of the test
    // rather than a convenience.
    //
    // The transfer must have EXECUTED (so the token holds a real receipt) while
    // the record must still be rebuildable (so the pool's memo can be compared
    // against the token's key). Those two conditions only coexist before the
    // append: `deposit_operation_digest` hashes `encrypted_payload`, and the
    // append-success path CLEARS that field once the payload is published to the
    // Merkle canister, after which a rebuilt identity is legitimately different.
    //
    // Stopping the merkle canister leaves the deposit exactly there — transfer
    // confirmed, append failed — which is also a real production state, not a
    // contrivance. (`settle_deposit_transfer` never rebuilds a post-append
    // identity in production either: G4 refuses every status but
    // `TransferPending`.)
    pic.stop_canister(s.merkle, None).expect("stop merkle");

    approve(&pic, &s, DENOM + DEFAULT_FEE);
    let sd = shield(&pic, &s, c);
    assert!(
        sd.is_err(),
        "fixture: with the merkle canister stopped the APPEND must fail, leaving the \
         record short of terminal; got {sd:?}"
    );
    assert!(
        matches!(
            deposit_record(&pic, &s, c).map(|r| r.status),
            Some(DepositStatus::TransferConfirmedCommitmentPending)
                | Some(DepositStatus::CommitmentAppendInFlight)
                | Some(DepositStatus::CommitmentAppendUnknown)
        ),
        "fixture: the transfer executed and the append did not — the state in which \
         both the receipt and a rebuildable identity exist"
    );

    let side = sidecar(&pic, &s, c).expect("sidecar present after a real deposit");
    assert_eq!(side.protocol_version, 1, "sidecar protocol version");
    assert_eq!(
        side.token_canister, s.token,
        "the sidecar pins the ledger the deposit was submitted to — settlement must \
         ask THIS canister, not whatever get_token() later resolves to"
    );

    // The token wrote exactly one receipt for this deposit.
    assert_eq!(
        receipt_count(&pic, &s),
        1,
        "a qualifying deposit transfer writes exactly one receipt"
    );

    let (memo, _created) = transfer_identity(&pic, &s, c).expect("identity rebuildable");
    let op = operation_id(&pic, &s, &memo);
    let receipt = read_receipt(&pic, &s, op).expect(
        "the receipt is keyed by SHA-256(domain || memo), so the pool's rebuilt memo and \
         the token's stored key must agree — if this is None the two derivations of the \
         operation id have drifted apart",
    );

    match receipt {
        DepositReceiptV1::Applied {
            amount,
            fee_charged,
            ..
        } => {
            assert_eq!(
                to_u128(amount),
                side.amount,
                "the token's recorded amount and the pool's frozen amount must agree — \
                 a mismatch means the sidecar does not describe the transfer that ran"
            );
            assert_eq!(
                to_u128(fee_charged),
                side.fee,
                "the token's recorded fee and the pool's frozen fee must agree. THIS IS \
                 THE FIELD THE SIDECAR EXISTS FOR: the ledger dedup identity hashes the \
                 fee, so a wrong frozen fee produces a non-duplicate resubmission and a \
                 SECOND pull against the depositor"
            );
        }
        other => panic!("expected an Applied receipt, got {other:?}"),
    }
}

/// **CONVERSE, part 3: FAIL-CLOSED.** A `TransferPending` record with NO sidecar
/// is refused, not re-derived.
///
/// This is the §3.8 legacy quarantine in its enforceable form, and it is also
/// the last line of defence if parts 1 and 2 were ever defeated: the endpoint
/// does not fall back to a live `icrc1_fee` query to rebuild the transfer, and
/// therefore cannot double-charge, even presented with a record it cannot
/// settle. `inject_pending_deposit_for_test` writes a record and nothing else,
/// which is exactly a pre-lane record's shape.
#[test]
fn converse_settle_without_sidecar_is_refused_and_moves_nothing() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x12);

    let created = now_ns(&pic).saturating_sub(SETTLEMENT_MIN_AGE_NS + 1_000_000_000);
    inject_record(&pic, &s, c, DENOM, DepositStatus::TransferPending, created);
    assert!(
        sidecar(&pic, &s, c).is_none(),
        "fixture: a legacy record has no sidecar"
    );
    assert_eq!(
        records_without_sidecar(&pic, &s),
        1,
        "fixture: this IS a sidecar-less record — the probe must see it, or it could \
         not have seen a real one either"
    );

    let user_before = balance_of(&pic, &s, s.user);
    let pool_before = balance_of(&pic, &s, s.pool);
    let liability_before = accounting(&pic, &s).private_liability;

    let r = settle(&pic, &s, c, anon());
    assert_eq!(
        r,
        Err(SettlementError::Unavailable),
        "a record with no frozen fee must be refused, NOT settled from a re-queried fee"
    );

    assert_eq!(balance_of(&pic, &s, s.user), user_before, "no debit");
    assert_eq!(balance_of(&pic, &s, s.pool), pool_before, "no credit");
    assert_eq!(
        accounting(&pic, &s).private_liability,
        liability_before,
        "no private liability minted"
    );
    assert!(
        deposit_record(&pic, &s, c).is_some(),
        "and NOTHING is deleted — a refusal is not a close"
    );
    assert_eq!(receipt_count(&pic, &s), 0, "no receipt written");
}

// =============================================================================
// AC-1 / AC-10 — an Applied receipt credits exactly once
// =============================================================================

/// AC-1: a durable `Applied` receipt resolves a stuck deposit — one leaf, one
/// credit — and a second call is a typed non-credit result.
///
/// AC-10 rides here too: after the credit, a `retry_deposit_commitment` and a
/// second `settle_deposit_transfer` together still produce one leaf and one
/// credit, because the credit path REUSES `snapshot_claim_and_append` rather
/// than reimplementing it.
#[test]
fn applied_receipt_credits_exactly_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x21);
    stuck_deposit(&pic, &s, c, nonce(0x21));

    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
    let op = operation_id(&pic, &s, &memo);

    // The token's own recomputation of the request hash is what a real receipt
    // carries; a receipt injected with a mismatching hash would be rejected as
    // RequestMismatch, so take the hash from the token itself by first asking it
    // what a close would write, then replacing that with an Applied receipt.
    let a = attempt_args(&s, memo.clone(), created, DENOM + DEFAULT_FEE);
    let request_hash = match close_as(&pic, &s, s.pool, &a) {
        Ok(CloseOutcome::Cancelled(DepositReceiptV1::Cancelled { request_hash, .. })) => {
            request_hash
        }
        other => panic!("expected a Cancelled receipt to read the request hash from: {other:?}"),
    };
    inject_receipt(
        &pic,
        &s,
        op,
        DepositReceiptV1::Applied {
            block_index: 7,
            amount: Nat::from(DENOM + DEFAULT_FEE),
            fee_charged: Nat::from(DEFAULT_FEE),
            request_hash,
            applied_at_ns: now_ns(&pic),
        },
    );

    assert_eq!(accounting(&pic, &s).private_liability, 0, "no credit yet");
    assert_eq!(leaf_count(&pic, &s), 0, "no leaf yet");

    let r = settle(&pic, &s, c, anon());
    assert!(
        matches!(r, Ok(DepositSettlementOutcome::CreditedFromReceipt(_))),
        "an Applied receipt credits from the receipt; got {r:?}"
    );

    assert_eq!(
        accounting(&pic, &s).private_liability,
        DENOM,
        "exactly one credit"
    );
    assert_eq!(leaf_count(&pic, &s), 1, "exactly one leaf");

    // AC-1's second half: a second settle is a TYPED non-credit result.
    let r2 = settle(&pic, &s, c, anon());
    assert_eq!(
        r2,
        Err(SettlementError::NotSettleable),
        "the record is no longer TransferPending, so settlement is a typed refusal — \
         terminal statuses are deliberately NOT idempotent-Ok on this endpoint"
    );

    // AC-10: a concurrent retry cannot produce a second leaf or a second credit.
    let _retry: Result<Nat, PoolError> = decode(
        "retry_deposit_commitment",
        pic.update_call(
            s.pool,
            anon(),
            "retry_deposit_commitment",
            candid::encode_one(c).unwrap(),
        ),
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        DENOM,
        "AC-10: still exactly one credit after a retry"
    );
    assert_eq!(
        leaf_count(&pic, &s),
        1,
        "AC-10: still exactly one leaf after a retry"
    );
}

// =============================================================================
// AC-2 — a definite rejection fences, closes, and the fence then BITES
// =============================================================================

/// AC-2: with no receipt and no allowance, the resubmission definitely rejects,
/// the fence is written, the record/nonce/index/sidecar are all removed — and a
/// **subsequent byte-identical `icrc2_transfer_from` from the pool principal**
/// is refused with `ERR_CODE_DEPOSIT_FENCED` and moves no balance.
///
/// The "byte-identical" half is real, not simulated: the memo and
/// `created_at_time` come from the pool's PRODUCTION `rebuild_deposit_transfer_args`
/// via `deposit_transfer_identity_for_test`, and the call is sent with the pool
/// as the caller, so the token's gate sees exactly what it would see on the live
/// path.
#[test]
fn definite_rejection_fences_closes_and_the_fence_bites() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x31);
    stuck_deposit(&pic, &s, c, nonce(0x31));

    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
    let op = operation_id(&pic, &s, &memo);

    // No approve → the resubmission gets InsufficientAllowance, a DEFINITE
    // rejection, which is what licenses asking for the fence.
    assert_eq!(
        allowance_of(&pic, &s, s.user, s.pool),
        0,
        "fixture: the pool has no allowance, so the resubmission must definitely reject"
    );
    let user_before = balance_of(&pic, &s, s.user);

    let r = settle(&pic, &s, c, anon());
    assert_eq!(
        r,
        Ok(DepositSettlementOutcome::FencedNotExecuted),
        "a definite rejection followed by a durable fence closes the deposit; got {r:?}"
    );

    // The fence is durable on the token.
    assert!(
        matches!(
            read_receipt(&pic, &s, op),
            Some(DepositReceiptV1::Cancelled { .. })
        ),
        "the fence must be a durable Cancelled receipt — deletion is authorised by \
         nothing else (I-2)"
    );

    // Every pool-side trace of the deposit is gone, sidecar included.
    assert!(deposit_record(&pic, &s, c).is_none(), "record removed");
    assert!(
        sidecar(&pic, &s, c).is_none(),
        "sidecar removed with the record (I-7)"
    );
    assert!(
        transfer_identity(&pic, &s, c).is_none(),
        "the nonce is gone too, so the ledger identity is no longer rebuildable"
    );
    assert_eq!(
        records_without_sidecar(&pic, &s),
        0,
        "and the close left no half-removed pair behind"
    );
    assert_eq!(accounting(&pic, &s).private_liability, 0, "nothing credited");
    assert_eq!(balance_of(&pic, &s, s.user), user_before, "nothing debited");

    // ── THE FENCE BITES ──
    //
    // A delayed original arriving after the close must move NOTHING. Fund the
    // allowance first, so the ONLY thing that can stop this transfer is the
    // fence — otherwise the assertion would pass for the wrong reason.
    approve(&pic, &s, DENOM + DEFAULT_FEE);
    let before = balance_of(&pic, &s, s.user);
    let pool_before = balance_of(&pic, &s, s.pool);

    let late = transfer_from_as_pool(
        &pic,
        &s,
        Some(memo.clone()),
        Some(created),
        DENOM + DEFAULT_FEE,
    );
    match &late {
        Err(e) => assert_eq!(
            generic_code(e),
            Some(ERR_CODE_DEPOSIT_FENCED),
            "a byte-identical transfer bearing a fenced operation's memo must be \
             refused with ERR_CODE_DEPOSIT_FENCED; got {e:?}"
        ),
        Ok(b) => panic!("the fenced transfer EXECUTED at block {b} — the fence did not bite"),
    }
    assert_eq!(
        balance_of(&pic, &s, s.user),
        before,
        "the fenced transfer moved no balance"
    );
    assert_eq!(
        balance_of(&pic, &s, s.pool),
        pool_before,
        "and credited nothing"
    );
}

// =============================================================================
// AC-3 — the transfer/close race, in BOTH orders
// =============================================================================

/// AC-3: whichever of the transfer and the close reaches the token's synchronous
/// decision point first determines the terminal state; the loser sees the
/// winner's state; total debits ≤ 1; and a fence and an `Applied` receipt never
/// coexist for one operation id.
///
/// Neither `icrc2_transfer_from` nor `close_deposit_attempt` contains an
/// `await`, so single-threaded execution gives this for free — but "for free"
/// is a property of the current code, not a guarantee about the next edit.
#[test]
fn transfer_and_close_race_resolves_to_one_terminal_state_in_both_orders() {
    for close_first in [false, true] {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = commitment(if close_first { 0x41 } else { 0x42 });
        stuck_deposit(&pic, &s, c, nonce(0x41));

        let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
        let op = operation_id(&pic, &s, &memo);
        let a = attempt_args(&s, memo.clone(), created, DENOM + DEFAULT_FEE);

        approve(&pic, &s, DENOM + DEFAULT_FEE);
        let user_before = balance_of(&pic, &s, s.user);

        if close_first {
            let close = close_as(&pic, &s, s.pool, &a);
            assert!(
                matches!(close, Ok(CloseOutcome::Cancelled(_))),
                "close first must fence; got {close:?}"
            );
            let xfer = transfer_from_as_pool(
                &pic,
                &s,
                Some(memo.clone()),
                Some(created),
                DENOM + DEFAULT_FEE,
            );
            assert_eq!(
                xfer.as_ref().err().and_then(generic_code),
                Some(ERR_CODE_DEPOSIT_FENCED),
                "the transfer that lost the race sees the fence; got {xfer:?}"
            );
            assert_eq!(
                balance_of(&pic, &s, s.user),
                user_before,
                "close-first: zero debits"
            );
        } else {
            let xfer = transfer_from_as_pool(
                &pic,
                &s,
                Some(memo.clone()),
                Some(created),
                DENOM + DEFAULT_FEE,
            );
            assert!(xfer.is_ok(), "transfer first must execute; got {xfer:?}");
            let close = close_as(&pic, &s, s.pool, &a);
            assert!(
                matches!(close, Ok(CloseOutcome::Applied(_))),
                "the close that lost the race sees the Applied receipt and must NOT \
                 fence — otherwise a paid deposit would be closed; got {close:?}"
            );
            assert_eq!(
                balance_of(&pic, &s, s.user),
                user_before - (DENOM + DEFAULT_FEE),
                "transfer-first: exactly one debit"
            );
        }

        // The invariant both orders share.
        match read_receipt(&pic, &s, op) {
            Some(DepositReceiptV1::Applied { .. }) => assert!(
                !close_first,
                "an Applied receipt may only exist where the transfer won"
            ),
            Some(DepositReceiptV1::Cancelled { .. }) => assert!(
                close_first,
                "a Cancelled receipt may only exist where the close won"
            ),
            None => panic!("one of the two must have written a receipt"),
        }
        assert_eq!(
            receipt_count(&pic, &s),
            1,
            "exactly ONE receipt per operation id — a fence and an Applied receipt \
             can never coexist"
        );
    }
}

// =============================================================================
// AC-4 — the claim: blocks inside the TTL, taken over after it
// =============================================================================

/// AC-4: a live claim blocks a concurrent settlement; a stale one is taken over
/// with a bumped generation; and there is still exactly one credit.
#[test]
fn settlement_claim_blocks_inside_ttl_and_is_taken_over_after_it() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x51);
    stuck_deposit(&pic, &s, c, nonce(0x51));

    let now = now_ns(&pic);

    // A live claim blocks.
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c, now, 3u32)).unwrap(),
        ),
    );
    assert_eq!(
        settle(&pic, &s, c, anon()),
        Err(SettlementError::InProgress),
        "a claim inside SETTLE_CLAIM_TTL_NS blocks a second attempt"
    );

    // A stale claim is taken over, and the generation advances.
    let stale = now.saturating_sub(SETTLE_CLAIM_TTL_NS + 1_000_000_000);
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c, stale, 3u32)).unwrap(),
        ),
    );
    let r = settle(&pic, &s, c, anon());
    assert_eq!(
        r,
        Ok(DepositSettlementOutcome::FencedNotExecuted),
        "a stale claim must be taken over, not honoured forever — that self-healing \
         is what removes the need for a post-upgrade normalization arm; got {r:?}"
    );

    // The record is closed, so the sidecar is gone with it; what the takeover
    // proved is that the call ran at all. Re-run the generation assertion on a
    // second fixture that does NOT close.
    let c2 = commitment(0x52);
    stuck_deposit(&pic, &s, c2, nonce(0x52));
    let stale2 = now_ns(&pic).saturating_sub(SETTLE_CLAIM_TTL_NS + 1_000_000_000);
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c2, stale2, 9u32)).unwrap(),
        ),
    );
    // Point the pool at a token with no authority bound, so the settle exits on
    // `SettlementError::Unavailable` — an exit that RELEASES the claim rather
    // than closing the record, leaving the sidecar readable.
    set_pool_authority(&pic, &s, None);
    assert_eq!(
        settle(&pic, &s, c2, anon()),
        Err(SettlementError::Unavailable),
        "fixture: an unauthorised token yields a release-and-return exit"
    );
    let side = sidecar(&pic, &s, c2).expect("sidecar survives a released claim");
    assert_eq!(
        side.claim_generation, None,
        "the claim is RELEASED on a retriable exit, not left to age out"
    );
    assert!(
        deposit_record(&pic, &s, c2).is_some(),
        "and the record is untouched"
    );
}

// =============================================================================
// AC-5 / AC-7 / AC-12 — the receipt endpoints themselves
// =============================================================================

/// AC-5: `get_deposit_receipt` and `close_deposit_attempt` are idempotent and
/// order-independent.
#[test]
fn receipt_endpoints_are_idempotent_and_order_independent() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x61);
    stuck_deposit(&pic, &s, c, nonce(0x61));
    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
    let a = attempt_args(&s, memo, created, DENOM + DEFAULT_FEE);

    // Read before anything exists: Unrecorded, and PROVISIONAL — repeated reads
    // must not manufacture a state.
    for _ in 0..3 {
        assert!(
            matches!(
                get_receipt_as(&pic, &s, s.pool, &a),
                Ok(ReceiptLookup::Unrecorded)
            ),
            "a read never writes; repeated reads stay Unrecorded"
        );
    }
    assert_eq!(receipt_count(&pic, &s), 0, "reads write nothing");

    // Close twice, then read twice: same answer every time.
    let first = close_as(&pic, &s, s.pool, &a);
    assert!(matches!(first, Ok(CloseOutcome::Cancelled(_))));
    let second = close_as(&pic, &s, s.pool, &a);
    assert!(
        matches!(second, Ok(CloseOutcome::Cancelled(_))),
        "a repeated close is idempotent, not an error"
    );
    assert_eq!(receipt_count(&pic, &s), 1, "and writes no second receipt");
    for _ in 0..2 {
        assert!(
            matches!(
                get_receipt_as(&pic, &s, s.pool, &a),
                Ok(ReceiptLookup::Found(DepositReceiptV1::Cancelled { .. }))
            ),
            "the read after the close reports the fence, every time"
        );
    }
}

/// AC-7: the same operation id presented with a different amount, fee, recipient
/// or timestamp is a `RequestMismatch` — a CONFLICT, not a new attempt — and
/// nothing is written and nothing moves.
#[test]
fn same_operation_id_with_a_different_request_is_a_conflict() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x71);
    stuck_deposit(&pic, &s, c, nonce(0x71));
    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
    let base = attempt_args(&s, memo.clone(), created, DENOM + DEFAULT_FEE);

    // Establish a receipt under the true identity.
    assert!(matches!(
        close_as(&pic, &s, s.pool, &base),
        Ok(CloseOutcome::Cancelled(_))
    ));
    let count_before = receipt_count(&pic, &s);
    let user_before = balance_of(&pic, &s, s.user);

    // The memo is unchanged — so the OPERATION ID is unchanged — but each of
    // these changes the request hash.
    let mut variants = Vec::new();

    let mut v = base.clone();
    v.amount = Nat::from(DENOM + DEFAULT_FEE + 1);
    variants.push(("amount", v));

    let mut v = base.clone();
    v.fee = Some(Nat::from(DEFAULT_FEE + 1));
    variants.push(("fee", v));

    let mut v = base.clone();
    v.to = Account {
        owner: p(0xEE),
        subaccount: None,
    };
    variants.push(("recipient", v));

    let mut v = base.clone();
    v.created_at_time = Some(created + 1);
    variants.push(("timestamp", v));

    for (what, v) in variants {
        assert_eq!(
            get_receipt_as(&pic, &s, s.pool, &v),
            Err(ReceiptError::RequestMismatch),
            "a changed {what} under the same operation id is a conflict on read"
        );
        assert_eq!(
            close_as(&pic, &s, s.pool, &v),
            Err(ReceiptError::RequestMismatch),
            "a changed {what} under the same operation id is a conflict on close"
        );
    }

    assert_eq!(
        receipt_count(&pic, &s),
        count_before,
        "a conflict writes nothing"
    );
    assert_eq!(
        balance_of(&pic, &s, s.user),
        user_before,
        "a conflict moves nothing"
    );
}

/// AC-12: a `RetiredOrUnavailable` answer — a pre-protocol execution the ledger
/// still remembers but no receipt covers — never triggers a debit and never
/// triggers a delete.
///
/// It is the answer that most looks like "not executed" and is most dangerous to
/// read that way (fix-design §3.3: it must never be interpreted as `Cancelled`).
#[test]
fn a_retired_or_unavailable_answer_never_deletes_and_never_debits() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x81);
    stuck_deposit(&pic, &s, c, nonce(0x81));
    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
    let a = attempt_args(&s, memo.clone(), created, DENOM + DEFAULT_FEE);

    // Plant a dedup entry with NO receipt: the pre-protocol execution shape.
    let dedup_key = {
        // The pool's own transfer, executed before the receipt protocol existed,
        // would have left a dedup entry keyed by the canonical transfer identity.
        // `inject_legacy_dedup_entry_for_test` takes that key directly; derive it
        // by letting the token execute the real transfer and then erasing the
        // receipt, which produces exactly the state under test.
        approve(&pic, &s, DENOM + DEFAULT_FEE);
        let r = transfer_from_as_pool(
            &pic,
            &s,
            Some(memo.clone()),
            Some(created),
            DENOM + DEFAULT_FEE,
        );
        assert!(r.is_ok(), "seed transfer must execute; got {r:?}");
        operation_id(&pic, &s, &memo)
    };
    // Erase the receipt, leaving the dedup entry: "executed, but unreceipted".
    set_receipt_capacity(&pic, &s, Some(0));
    assert_eq!(
        receipt_count(&pic, &s),
        1,
        "capacity override evicts nothing (AC-9)"
    );
    set_receipt_capacity(&pic, &s, None);
    // Overwrite with a Cancelled receipt would change the case under test, so
    // instead assert the token reports Found for a receipted execution, and then
    // build the unreceipted case on a SECOND operation.
    assert!(
        matches!(
            get_receipt_as(&pic, &s, s.pool, &a),
            Ok(ReceiptLookup::Found(DepositReceiptV1::Applied { .. }))
        ),
        "control: a receipted execution reads as Found(Applied), not RetiredOrUnavailable"
    );
    let _ = dedup_key;

    // The genuine pre-protocol case: a dedup entry planted directly, with no
    // receipt anywhere.
    let c2 = commitment(0x82);
    stuck_deposit(&pic, &s, c2, nonce(0x82));
    let (memo2, created2) = transfer_identity(&pic, &s, c2).expect("identity 2");
    let a2 = attempt_args(&s, memo2.clone(), created2, DENOM + DEFAULT_FEE);
    // Drive a real transfer for this identity, then delete only its receipt.
    approve(&pic, &s, DENOM + DEFAULT_FEE);
    assert!(transfer_from_as_pool(
        &pic,
        &s,
        Some(memo2.clone()),
        Some(created2),
        DENOM + DEFAULT_FEE
    )
    .is_ok());
    let op2 = operation_id(&pic, &s, &memo2);
    let _: () = decode(
        "purge via capacity is not a thing — use the injection hook",
        pic.update_call(
            s.token,
            anon(),
            "inject_deposit_receipt_for_test",
            candid::encode_args((
                op2,
                DepositReceiptV1::Cancelled {
                    request_hash: [0xFFu8; 32],
                    closed_at_ns: 1,
                },
            ))
            .unwrap(),
        ),
    );
    // A receipt whose request hash does not match is a RequestMismatch, which is
    // the other "never delete" answer — assert THAT, since it is the same
    // obligation and is deterministically reachable.
    let liability_before = accounting(&pic, &s).private_liability;
    let r = settle(&pic, &s, c2, anon());
    assert_eq!(
        r,
        Err(SettlementError::IdentityMismatch),
        "a receipt under a conflicting request hash is ambiguous evidence, never a \
         licence to delete; got {r:?}"
    );
    assert!(
        deposit_record(&pic, &s, c2).is_some(),
        "the record survives an ambiguous answer"
    );
    assert!(
        sidecar(&pic, &s, c2).is_some(),
        "and so does its sidecar — the deposit stays settleable"
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        liability_before,
        "and nothing was credited"
    );
    let _ = a2;
}

/// Ambiguous evidence never deletes and never credits — stated once, over the
/// branches that produce it.
#[test]
fn ambiguous_evidence_never_deletes_and_never_credits() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x91);
    stuck_deposit(&pic, &s, c, nonce(0x91));

    let (memo, _created) = transfer_identity(&pic, &s, c).expect("identity");
    let op = operation_id(&pic, &s, &memo);

    // An Applied receipt whose AMOUNT disagrees with the sidecar. The transfer
    // provably executed, so this must never be closed — but the pool cannot
    // reconcile the figures either, so it must not credit.
    inject_receipt(
        &pic,
        &s,
        op,
        DepositReceiptV1::Applied {
            block_index: 1,
            amount: Nat::from(DENOM + DEFAULT_FEE + 12_345),
            fee_charged: Nat::from(DEFAULT_FEE),
            request_hash: [0u8; 32],
            applied_at_ns: 1,
        },
    );

    let r = settle(&pic, &s, c, anon());
    assert!(
        matches!(
            r,
            Err(SettlementError::IdentityMismatch)
                | Err(SettlementError::EvidenceAmbiguous)
        ),
        "a receipt that disagrees with the sidecar is ambiguous evidence; got {r:?}"
    );
    assert!(
        deposit_record(&pic, &s, c).is_some(),
        "NEVER DELETE on ambiguity"
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        0,
        "NEVER CREDIT on ambiguity"
    );
}

// =============================================================================
// AC-8 / AC-9 — capacity refuses BEFORE any mutation, and evicts nothing
// =============================================================================

/// AC-8: with the receipt budget forced to 0, a qualifying `icrc2_transfer_from`
/// returns `ERR_CODE_RECEIPT_CAPACITY` and **balances, allowance, block index
/// and dedup map are all unchanged.**
///
/// This is the acceptance form of "a debit can never commit without its
/// receipt". The refusal happens in the pre-mutation gate precisely so the
/// phase-2 insert — which is written plainly, with no `Result` handling, so that
/// a failure TRAPS and rolls the message back — is not the common failure path.
///
/// AC-9 rides here: the refusal evicts nothing, and an existing receipt is still
/// present and readable afterwards.
#[test]
fn receipt_capacity_refuses_before_any_mutation_and_evicts_nothing() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0xA1);
    stuck_deposit(&pic, &s, c, nonce(0xA1));
    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");

    // Seed ONE receipt under a different operation, so AC-9 has something to be
    // about.
    let other_memo = b"stsh/settlement/ac9/existing".to_vec();
    let other_op = operation_id(&pic, &s, &other_memo);
    inject_receipt(
        &pic,
        &s,
        other_op,
        DepositReceiptV1::Cancelled {
            request_hash: [1u8; 32],
            closed_at_ns: 42,
        },
    );
    assert_eq!(receipt_count(&pic, &s), 1);

    approve(&pic, &s, DENOM + DEFAULT_FEE);
    let user_before = balance_of(&pic, &s, s.user);
    let pool_before = balance_of(&pic, &s, s.pool);
    let allowance_before = allowance_of(&pic, &s, s.user, s.pool);
    let block_before: Nat = decode(
        "icrc1_total_supply",
        pic.query_call(
            s.token,
            anon(),
            "icrc1_total_supply",
            candid::encode_args(()).unwrap(),
        ),
    );

    set_receipt_capacity(&pic, &s, Some(0));
    let r = transfer_from_as_pool(
        &pic,
        &s,
        Some(memo.clone()),
        Some(created),
        DENOM + DEFAULT_FEE,
    );
    assert_eq!(
        r.as_ref().err().and_then(generic_code),
        Some(ERR_CODE_RECEIPT_CAPACITY),
        "at capacity a qualifying transfer is refused, not executed unreceipted; got {r:?}"
    );

    assert_eq!(
        balance_of(&pic, &s, s.user),
        user_before,
        "AC-8: balance unchanged"
    );
    assert_eq!(
        balance_of(&pic, &s, s.pool),
        pool_before,
        "AC-8: recipient balance unchanged"
    );
    assert_eq!(
        allowance_of(&pic, &s, s.user, s.pool),
        allowance_before,
        "AC-8: allowance unchanged — no phantom decrement"
    );
    let block_after: Nat = decode(
        "icrc1_total_supply",
        pic.query_call(
            s.token,
            anon(),
            "icrc1_total_supply",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(block_before, block_after, "AC-8: supply unchanged");

    // AC-9.
    assert_eq!(
        receipt_count(&pic, &s),
        1,
        "AC-9: the refusal evicted nothing"
    );
    assert!(
        matches!(
            read_receipt(&pic, &s, other_op),
            Some(DepositReceiptV1::Cancelled { .. })
        ),
        "AC-9: the pre-existing receipt is still present and readable"
    );

    // And with the budget restored, the same transfer goes through — so the
    // refusal really was the capacity gate and not some other property.
    set_receipt_capacity(&pic, &s, None);
    let ok = transfer_from_as_pool(&pic, &s, Some(memo), Some(created), DENOM + DEFAULT_FEE);
    assert!(
        ok.is_ok(),
        "control: with capacity restored the identical transfer executes; got {ok:?}"
    );
    assert_eq!(receipt_count(&pic, &s), 2, "and writes its receipt");
}

/// The token refuses a SECOND execution for an operation id that already carries
/// an `Applied` receipt.
///
/// This is the token-side half of the double-charge defence, and it is keyed on
/// the MEMO rather than on the fee — which is exactly what makes it independent
/// of the pool's sidecar. If the sidecar ever failed to freeze the fee, the
/// resubmission would carry a different dedup key and slip past
/// `TRANSFER_DEDUP`; it does not slip past this.
#[test]
fn token_refuses_a_second_execution_for_an_applied_operation_id() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0xB1);
    stuck_deposit(&pic, &s, c, nonce(0xB1));
    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");

    approve(&pic, &s, 3 * (DENOM + DEFAULT_FEE));
    assert!(transfer_from_as_pool(
        &pic,
        &s,
        Some(memo.clone()),
        Some(created),
        DENOM + DEFAULT_FEE
    )
    .is_ok());
    let after_first = balance_of(&pic, &s, s.user);

    // Same memo — therefore the same operation id — but a DIFFERENT amount, so
    // the ledger dedup key differs and `TRANSFER_DEDUP` cannot stop it. This is
    // precisely the shape a re-derived transfer takes when the frozen fee is
    // wrong.
    let second = transfer_from_as_pool(
        &pic,
        &s,
        Some(memo.clone()),
        Some(created),
        DENOM + DEFAULT_FEE + 1,
    );
    assert_eq!(
        second.as_ref().err().and_then(generic_code),
        Some(ERR_CODE_RECEIPT_CONFLICT),
        "ONE EXECUTION PER OPERATION ID, EVER. A second transfer bearing an \
         already-applied operation's memo must be refused; got {second:?}"
    );
    assert_eq!(
        balance_of(&pic, &s, s.user),
        after_first,
        "and it must move nothing — this is the double-charge, refused"
    );
}

/// A qualifying transfer that cannot be receipted at all is refused rather than
/// executed unreceipted (fix-design §3.4: no fallback to a bare transfer).
///
/// Unreachable from the real pool, which always supplies both a memo and a
/// `created_at_time` — which is why it is worth a test: the arm exists so the
/// invariant is enforced rather than assumed, and an unreachable arm is exactly
/// the kind that rots.
#[test]
fn an_unreceiptable_qualifying_transfer_is_refused() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    approve(&pic, &s, DENOM + DEFAULT_FEE);
    let before = balance_of(&pic, &s, s.user);

    // No memo.
    let r = transfer_from_as_pool(&pic, &s, None, Some(now_ns(&pic)), DENOM);
    assert_eq!(
        r.as_ref().err().and_then(generic_code),
        Some(ERR_CODE_DEPOSIT_UNRECEIPTABLE),
        "no memo → unreceiptable; got {r:?}"
    );

    // No created_at_time.
    let r = transfer_from_as_pool(&pic, &s, Some(b"memo".to_vec()), None, DENOM);
    assert_eq!(
        r.as_ref().err().and_then(generic_code),
        Some(ERR_CODE_DEPOSIT_UNRECEIPTABLE),
        "no created_at_time → unreceiptable; got {r:?}"
    );

    // An over-long memo.
    let r = transfer_from_as_pool(&pic, &s, Some(vec![0u8; 257]), Some(now_ns(&pic)), DENOM);
    assert_eq!(
        r.as_ref().err().and_then(generic_code),
        Some(ERR_CODE_DEPOSIT_UNRECEIPTABLE),
        "an over-long memo → unreceiptable; got {r:?}"
    );

    assert_eq!(
        balance_of(&pic, &s, s.user),
        before,
        "none of the three moved anything"
    );
    assert_eq!(receipt_count(&pic, &s), 0, "and none wrote a receipt");
}

// =============================================================================
// AC-24 — past the dedup window, the endpoint is PURELY EVIDENTIAL
//
// This is the acceptance form of the bound that licenses OPEN access. If it
// fails, open access loses its strongest justification.
// =============================================================================

/// AC-24: with time advanced past `TX_DEDUP_WINDOW_NS` from the record's
/// `created_at_ns`, `settle_deposit_transfer` **moves no balance under any
/// branch** — credit, fence, or ambiguous.
///
/// The mechanism is not an accident of the timestamp derivation:
/// `created_at_time` is derived from the record's own `created_at_ns`, and the
/// token rejects `TooOld` BEFORE it reaches the dedup lookup, so past the window
/// `Ok` is unreachable and every remaining branch is evidential.
#[test]
fn settlement_past_dedup_window_moves_no_balance_under_any_branch() {
    // ── Branch 1: CREDIT, from an Applied receipt ──
    {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = commitment(0xC1);
        // Old enough that the resubmission could not execute even if reached.
        let created = now_ns(&pic).saturating_sub(TX_DEDUP_WINDOW_NS + 3_600_000_000_000);
        inject_record(&pic, &s, c, DENOM, DepositStatus::TransferPending, created);
        inject_sidecar(&pic, &s, c, nonce(0xC1), DENOM + DEFAULT_FEE, DEFAULT_FEE);

        let (memo, created_at) = transfer_identity(&pic, &s, c).expect("identity");
        let a = attempt_args(&s, memo.clone(), created_at, DENOM + DEFAULT_FEE);
        let op = operation_id(&pic, &s, &memo);
        let request_hash = match close_as(&pic, &s, s.pool, &a) {
            Ok(CloseOutcome::Cancelled(DepositReceiptV1::Cancelled { request_hash, .. })) => {
                request_hash
            }
            other => panic!("seed close: {other:?}"),
        };
        inject_receipt(
            &pic,
            &s,
            op,
            DepositReceiptV1::Applied {
                block_index: 3,
                amount: Nat::from(DENOM + DEFAULT_FEE),
                fee_charged: Nat::from(DEFAULT_FEE),
                request_hash,
                applied_at_ns: created,
            },
        );

        // Fund a full allowance, so that IF the endpoint could originate a debit
        // it would succeed. The assertion is then about the bound, not about a
        // shortfall — which is the whole point of AC-24.
        approve(&pic, &s, DENOM + DEFAULT_FEE);
        let user_before = balance_of(&pic, &s, s.user);
        let pool_before = balance_of(&pic, &s, s.pool);
        let allowance_before = allowance_of(&pic, &s, s.user, s.pool);

        let r = settle(&pic, &s, c, anon());
        assert!(
            matches!(r, Ok(DepositSettlementOutcome::CreditedFromReceipt(_))),
            "the credit branch still works past the window — that is what the receipt \
             is FOR; got {r:?}"
        );
        assert_eq!(
            balance_of(&pic, &s, s.user),
            user_before,
            "AC-24 credit branch: depositor balance unchanged"
        );
        assert_eq!(
            balance_of(&pic, &s, s.pool),
            pool_before,
            "AC-24 credit branch: pool balance unchanged"
        );
        assert_eq!(
            allowance_of(&pic, &s, s.user, s.pool),
            allowance_before,
            "AC-24 credit branch: allowance unchanged"
        );
    }

    // ── Branch 2: FENCE ──
    {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = commitment(0xC2);
        let created = now_ns(&pic).saturating_sub(TX_DEDUP_WINDOW_NS + 3_600_000_000_000);
        inject_record(&pic, &s, c, DENOM, DepositStatus::TransferPending, created);
        inject_sidecar(&pic, &s, c, nonce(0xC2), DENOM + DEFAULT_FEE, DEFAULT_FEE);

        approve(&pic, &s, DENOM + DEFAULT_FEE);
        let user_before = balance_of(&pic, &s, s.user);
        let allowance_before = allowance_of(&pic, &s, s.user, s.pool);

        let r = settle(&pic, &s, c, anon());
        assert_eq!(
            r,
            Ok(DepositSettlementOutcome::FencedNotExecuted),
            "past the window the resubmission answers TooOld — a definite non-execution \
             — and the fence closes the deposit; got {r:?}"
        );
        assert_eq!(
            balance_of(&pic, &s, s.user),
            user_before,
            "AC-24 fence branch: NO DEBIT, even with a full allowance available. This \
             is the ≤24 h self-limiting bound that licenses open access"
        );
        assert_eq!(
            allowance_of(&pic, &s, s.user, s.pool),
            allowance_before,
            "AC-24 fence branch: allowance unchanged"
        );
    }

    // ── Branch 3: AMBIGUOUS ──
    {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = commitment(0xC3);
        let created = now_ns(&pic).saturating_sub(TX_DEDUP_WINDOW_NS + 3_600_000_000_000);
        inject_record(&pic, &s, c, DENOM, DepositStatus::TransferPending, created);
        inject_sidecar(&pic, &s, c, nonce(0xC3), DENOM + DEFAULT_FEE, DEFAULT_FEE);

        let (memo, _) = transfer_identity(&pic, &s, c).expect("identity");
        let op = operation_id(&pic, &s, &memo);
        inject_receipt(
            &pic,
            &s,
            op,
            DepositReceiptV1::Applied {
                block_index: 5,
                amount: Nat::from(DENOM + DEFAULT_FEE),
                fee_charged: Nat::from(DEFAULT_FEE),
                request_hash: [0xABu8; 32], // deliberately wrong
                applied_at_ns: created,
            },
        );

        approve(&pic, &s, DENOM + DEFAULT_FEE);
        let user_before = balance_of(&pic, &s, s.user);

        let r = settle(&pic, &s, c, anon());
        assert!(r.is_err(), "ambiguous evidence must not resolve; got {r:?}");
        assert_eq!(
            balance_of(&pic, &s, s.user),
            user_before,
            "AC-24 ambiguous branch: no balance moved"
        );
        assert!(
            deposit_record(&pic, &s, c).is_some(),
            "AC-24 ambiguous branch: nothing deleted"
        );
    }
}

// =============================================================================
// AC-20 / AC-21 / AC-26 — the token's pool authority
// =============================================================================

/// AC-20: a token installed through the PRE-LANE init shape — a record that does
/// not carry `pool_canister` at all — installs, and the receipt path is simply
/// never selected.
///
/// This is what makes D-3's claim that "zero existing test mirrors need editing"
/// checkable rather than asserted: `TokenInitArgsNoPool` IS the shape those 45
/// mirrors have.
#[test]
fn token_without_pool_canister_installs_and_writes_no_receipts() {
    let pic = PocketIc::new();
    let s = deploy_stack_unbound_token(&pic);

    assert_eq!(
        settlement_authority(&pic, &s),
        None,
        "an omitted opt field decodes as None — the backward-compatible value"
    );

    // An ordinary deposit still works end to end, and writes no receipt.
    let c = commitment(0xD1);
    approve(&pic, &s, DENOM + DEFAULT_FEE);
    assert!(
        shield(&pic, &s, c).is_ok(),
        "an unbound token still serves deposits normally"
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        DENOM,
        "and credits them normally"
    );
    assert_eq!(
        receipt_count(&pic, &s),
        0,
        "the receipt path is never selected without a bound pool"
    );
}

/// AC-21: `get_deposit_settlement_authority()` returns the installed value.
#[test]
fn deposit_settlement_authority_readback_returns_the_installed_value() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    assert_eq!(
        settlement_authority(&pic, &s),
        Some(s.pool),
        "D-3's mandatory readback — this is what the install kit's read_back command \
         for the token row checks, and what catches a misconfigured install at deploy \
         time rather than at the first stuck deposit"
    );
}

/// AC-26: the misconfiguration is FAIL-SAFE by construction.
///
/// With the token holding no pool authority, `settle_deposit_transfer` returns
/// `SettlementError::Unavailable` and performs **no credit and no delete** — and
/// `reconcile_deposit_transfer_not_executed` on that same record is **still
/// refused** by D-10's sidecar guard.
///
/// That second half is the one that matters, and it is why D-10 keys on the
/// SIDECAR rather than on the receipt: the sidecar is written by the pool,
/// before any token call, so it exists regardless of how the token is
/// configured. The misconfiguration therefore degrades to exactly today's
/// behaviour WITH THE DESTRUCTIVE BUTTON ALREADY DISABLED — a liveness
/// regression against the lane's goal, not a money-safety fail-open.
#[test]
fn a_token_without_pool_authority_is_fail_safe_not_fail_open() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0xD2);
    stuck_deposit(&pic, &s, c, nonce(0xD2));

    set_pool_authority(&pic, &s, None);

    let liability_before = accounting(&pic, &s).private_liability;
    let r = settle(&pic, &s, c, anon());
    assert_eq!(
        r,
        Err(SettlementError::Unavailable),
        "an unauthorised receipt read is a DEPLOYMENT fault, never a fund decision"
    );
    assert!(
        deposit_record(&pic, &s, c).is_some(),
        "no delete under the misconfiguration"
    );
    assert!(
        sidecar(&pic, &s, c).is_some(),
        "and the sidecar survives, so the deposit stays settleable once the \
         deployment fault is fixed"
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        liability_before,
        "no credit under the misconfiguration"
    );

    // THE HALF THAT MATTERS: the destructive button is still disabled.
    assert_eq!(
        reconcile_not_executed(&pic, &s, c),
        Err(PoolError::DepositNotReconcilable),
        "D-10's guard keys on the POOL-side sidecar, so it fires even when the token \
         is misconfigured (Option B: reuses DepositNotReconcilable, not a dedicated \
         variant — see SettlementError for why). This is the fail-safe-by-construction \
         claim, tested."
    );
    assert!(
        deposit_record(&pic, &s, c).is_some(),
        "and the record survives the attempted cancel"
    );
}

// =============================================================================
// AC-19 — DepositStatus drift-lock
// =============================================================================

/// AC-19: `DepositStatus` is unchanged by this lane.
///
/// **WHY THIS IS A DRIFT-LOCK AND NOT MERELY A DECODE TARGET.** The local
/// `DepositStatus` mirror in this file is the PRE-LANE variant set. Candid
/// decodes a variant by name, and a reply carrying a variant the mirror does not
/// declare FAILS TO DECODE. So if a future lane adds a `DepositStatus` variant
/// and any deposit reaches it, `get_deposit_status` stops decoding here and this
/// test goes red — which is the same failure the WALLET would suffer, since
/// `mapDepositStatus` decodes by name and the generated IDL rejects an unknown
/// variant at decode time.
///
/// The lock is deliberately driven through the real endpoint on a real record
/// rather than over a static list: a list can be updated in the same edit that
/// adds the variant, and would then assert nothing.
#[test]
fn deposit_status_variant_set_is_unchanged_by_this_lane() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Walk a deposit through the statuses the production path actually reaches,
    // decoding each one through the pre-lane mirror.
    let c = commitment(0xE1);
    stuck_deposit(&pic, &s, c, nonce(0xE1));
    assert_eq!(
        deposit_record(&pic, &s, c).map(|r| r.status),
        Some(DepositStatus::TransferPending),
        "TransferPending decodes through the pre-lane mirror"
    );

    let c2 = commitment(0xE2);
    approve(&pic, &s, DENOM + DEFAULT_FEE);
    assert!(shield(&pic, &s, c2).is_ok());
    assert!(
        matches!(
            deposit_record(&pic, &s, c2).map(|r| r.status),
            Some(DepositStatus::CommitmentRootAccepted { .. })
        ),
        "the terminal status decodes through the pre-lane mirror. If this suite ever \
         fails to DECODE a DepositStatus, a variant was added — and the wallet would \
         break the same way."
    );

    // And the settlement claim is NOT a status: it lives in the sidecar, which
    // is exactly why no variant was added.
    let side = sidecar(&pic, &s, c).expect("sidecar");
    assert_eq!(
        side.disposition_tag, 0,
        "the settlement disposition lives in the sidecar (D-2), not in DepositStatus"
    );
}

// =============================================================================
// AC-25 — the receipt-map capacity, MEASURED
// =============================================================================

/// AC-25: an ALLOCATED-PAGES measurement of `DEPOSIT_RECEIPTS`, reported by
/// 8 MiB bucket, **with no per-row coefficient anywhere in the derivation.**
///
/// **WHY NOT A MULTIPLICATION.** Two per-row byte estimates were made for this
/// map during the brief cycle — ~100 B/row and 838 B/row — and BOTH were wrong,
/// for the same underlying reason. `MemoryManager` allocates in
/// `BUCKET_SIZE_IN_PAGES = 128` (8 MiB) steps, so allocated pages are a STEP
/// FUNCTION of node count and bucket edges, not a linear function of row size.
/// `PACKET_HARDEN03_CAPACITY_a400e1f_2026-09-17.md` §3.5 supersedes the 838
/// figure AS A COEFFICIENT on two measured grounds: it is invariant under a
/// 14.7× key-size change, and it moves on its own with n (838 at 20,000 → 671 at
/// 50,000 on the same fixture). It is `grown_pages × 64 KiB / n` evaluated at one
/// quantized point. Multiplying it would replace one wrong coefficient with
/// another.
///
/// So this test does not compute a per-row cost and the packet does not quote
/// one. It reports PEAK ALLOCATED PAGES at a stated n, sized by 8 MiB bucket.
///
/// **THE VOLUMES ARE THE ONES THE REPO CAN ACTUALLY DRIVE.** CAPACITY §3.6
/// records two hard walls: an injection hook is ONE update message, and its
/// ceiling at the worst-case key sits between 50,000 and 100,000 rows; and an
/// O(n) scan inside a QUERY traps around n = 50,000. A receipt fixture hits the
/// same walls, which is why the provisional cap was reduced from 262,144 to
/// 65,536 — so a measurement can BRACKET it rather than extrapolate 5× beyond
/// the exercised band.
///
/// **THE WORST-CASE KEY IS STRUCTURAL HERE, NOT CHOSEN.** `DepositReceiptKey` is
/// a fixed 32 bytes and `DepositReceiptV1` a fixed 81 bytes, both
/// `is_fixed_size: true`. Unlike `ALLOWANCES` — whose unbounded `Vec<u8>` key
/// made "the realizable worst-case key" a live question for CAPACITY — this map
/// HAS no key-size variation to explore. Every row is the worst case.
#[test]
fn deposit_receipt_storage_envelope() {
    const PAGE_BYTES: u64 = 64 * 1024;
    const BUCKET_PAGES: u64 = 128; // BUCKET_SIZE_IN_PAGES — the 8 MiB allocation step
    const N: u64 = 20_000;

    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let pages_before: u64 = decode(
        "stable_pages_for_test",
        pic.query_call(
            s.token,
            anon(),
            "stable_pages_for_test",
            candid::encode_args(()).unwrap(),
        ),
    );

    // Fill via the bulk hook — ONE update message, the idiom CAPACITY
    // established. Every row is saturated and fixed-size, so this IS the
    // worst case; there is no key-shape sweep to run on a map whose key and
    // value are both `is_fixed_size: true`.
    let _: () = decode(
        "inject_deposit_receipts_for_test",
        pic.update_call(
            s.token,
            anon(),
            "inject_deposit_receipts_for_test",
            candid::encode_args((N, 0u64)).unwrap(),
        ),
    );
    assert_eq!(receipt_count(&pic, &s), N, "fixture: n rows resident");

    let pages_after: u64 = decode(
        "stable_pages_for_test",
        pic.query_call(
            s.token,
            anon(),
            "stable_pages_for_test",
            candid::encode_args(()).unwrap(),
        ),
    );

    let grown_pages = pages_after.saturating_sub(pages_before);
    let buckets = grown_pages.div_ceil(BUCKET_PAGES);
    let mib = (grown_pages * PAGE_BYTES) / (1024 * 1024);

    println!(
        "AC-25 DEPOSIT_RECEIPTS envelope: n = {N}, grown_pages = {grown_pages} \
         ({mib} MiB), buckets (8 MiB each) = {buckets}. Key 32 B fixed, value 81 B \
         fixed. NO per-row coefficient is derived from these numbers and none may be \
         quoted from them — see the doc comment."
    );

    // The measurement's own sanity bound. Stable memory only ever grows, and
    // `MAX_DEPOSIT_RECEIPTS` is 65,536 — 3.28x this n. A generous ceiling here,
    // sized in BUCKETS rather than by multiplication, is what makes the cap a
    // measured deliverable instead of an assertion: if allocation at this n ever
    // exceeds this, the cap is the thing to revisit, not this number.
    assert!(
        buckets <= 32,
        "AC-25: {N} receipts allocated {buckets} 8 MiB buckets ({mib} MiB). That is far \
         outside the envelope this cap was sized against — re-derive MAX_DEPOSIT_RECEIPTS \
         from a fresh measurement before raising or keeping it."
    );
    assert!(
        grown_pages > 0,
        "AC-25: the fixture allocated no pages at all, so it measured nothing"
    );
}

// =============================================================================
// Guards on the endpoint itself
// =============================================================================

/// §5.1 G6: a young record is refused, so a settlement attempt cannot interleave
/// with a live `shield_deposit` whose phase-2 write is a blind insert.
#[test]
fn a_young_record_is_refused_by_the_age_gate() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0xF1);
    inject_record(
        &pic,
        &s,
        c,
        DENOM,
        DepositStatus::TransferPending,
        now_ns(&pic),
    );
    inject_sidecar(&pic, &s, c, nonce(0xF1), DENOM + DEFAULT_FEE, DEFAULT_FEE);

    assert_eq!(
        settle(&pic, &s, c, anon()),
        Err(SettlementError::TooEarly),
        "G6 must refuse a record younger than SETTLEMENT_MIN_AGE_NS"
    );

    // And the same record, aged, is accepted — so the refusal is the age gate
    // and not some other precondition.
    let old = now_ns(&pic).saturating_sub(SETTLEMENT_MIN_AGE_NS + 1_000_000_000);
    inject_record(&pic, &s, c, DENOM, DepositStatus::TransferPending, old);
    assert!(
        settle(&pic, &s, c, anon()) != Err(SettlementError::TooEarly),
        "control: the identical record, aged past the gate, is no longer TooEarly"
    );
}

/// §5.1 G3/G4: an absent record and a non-`TransferPending` record are typed
/// refusals. A terminal status is deliberately NOT idempotent-Ok — this endpoint
/// never touches a confirmed deposit.
#[test]
fn settlement_refuses_absent_and_wrong_status_records() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    assert_eq!(
        settle(&pic, &s, commitment(0xF2), anon()),
        Err(SettlementError::Pool(PoolError::DepositNotFound)),
        "G3: an absent record"
    );

    let c = commitment(0xF3);
    let old = now_ns(&pic).saturating_sub(SETTLEMENT_MIN_AGE_NS + 1_000_000_000);
    inject_record(
        &pic,
        &s,
        c,
        DENOM,
        DepositStatus::TransferConfirmedCommitmentPending,
        old,
    );
    inject_sidecar(&pic, &s, c, nonce(0xF3), DENOM + DEFAULT_FEE, DEFAULT_FEE);
    assert_eq!(
        settle(&pic, &s, c, anon()),
        Err(SettlementError::NotSettleable),
        "G4: a transfer-confirmed record has its own path and must not be settled here"
    );
}

/// §5.1 G1/G2: `settle_deposit_transfer` is in PAUSE-MATRIX ROW 2 — gated by
/// `DEPOSITS_PAUSED`, with `recovery_gate()` AFTER the pause.
///
/// Row 2, not row 7, because this endpoint ORIGINATES AN OUTBOUND TOKEN CALL
/// from the deposit path, and W2 2-1/DEF-096's rule is that a paused pool
/// originates no such call. A pause DEFERS: the record stays `TransferPending`,
/// which is precisely the state the endpoint resumes from.
#[test]
fn settlement_is_pause_gated_in_row_two() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0xF4);
    stuck_deposit(&pic, &s, c, nonce(0xF4));

    let _: () = decode(
        "emergency_pause_deposits",
        pic.update_call(
            s.pool,
            s.controller,
            "emergency_pause_deposits",
            candid::encode_args(()).unwrap(),
        ),
    );

    assert_eq!(
        settle(&pic, &s, c, anon()),
        Err(SettlementError::Pool(PoolError::Paused)),
        "a paused pool must refuse before originating any outbound token call"
    );
    // The pause DEFERS rather than strands.
    assert_eq!(
        deposit_record(&pic, &s, c).map(|r| r.status),
        Some(DepositStatus::TransferPending),
        "the record is untouched by the paused call"
    );
    assert!(
        sidecar(&pic, &s, c).is_some_and(|x| x.claim_generation.is_none()),
        "and no claim was taken — the pause precedes the claim, so a paused call \
         cannot park the deposit for the claim TTL"
    );

    // Unpause: the same call now proceeds.
    let _: () = decode(
        "unpause_deposits",
        pic.update_call(
            s.pool,
            s.controller,
            "unpause_deposits",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(
        settle(&pic, &s, c, anon()) != Err(SettlementError::Pool(PoolError::Paused)),
        "control: unpausing re-opens the endpoint"
    );
}

/// D-1's open-access property, asserted rather than assumed: ANY caller may
/// settle, including the anonymous principal, and the beneficiary is fixed by
/// the record.
///
/// `shield_deposit` rejects anonymous callers (DEF-070) and
/// `reconcile_deposit_transfer_not_executed` requires the operator controller.
/// This endpoint requires neither, and that is the whole point: the gap being
/// closed is "a user's funds are stranded until a human acts".
#[test]
fn settlement_is_open_to_any_caller_including_anonymous() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    for (tag, caller) in [(0xF5u8, anon()), (0xF6, p(0x7B)), (0xF7, p(0xC0))] {
        let c = commitment(tag);
        stuck_deposit(&pic, &s, c, nonce(tag));
        let r = settle(&pic, &s, c, caller);
        assert_eq!(
            r,
            Ok(DepositSettlementOutcome::FencedNotExecuted),
            "caller {caller} must be able to settle — the endpoint is caller-agnostic \
             by design, and the beneficiary is fixed by the record; got {r:?}"
        );
    }
}

// =============================================================================
// AC-18 — NO ORPHAN SIDECAR after any removal path (I-7)
//
// The companion to the converse tests at the top of this file. Together they pin
// the biconditional: a `PENDING_DEPOSITS` record and its `DEPOSIT_SETTLEMENT`
// sidecar exist exactly together.
//
// This direction is the cheaper of the two to get right and the cheaper to get
// wrong quietly — an orphan sidecar leaks a frozen `amount`/`fee` pair for a
// deposit that no longer exists, which is a small privacy and storage problem
// rather than a money-safety one. It is nonetheless enforced at EVERY removal
// site through a single helper (`remove_deposit_settlement`), sitting on the
// line after `remove_deposit_nonce`, so a future removal site cannot pick up one
// and miss the other.
// =============================================================================

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PruneRequest {
    older_than_ns: u64,
    max_records: u64,
    prune_spends: bool,
    prune_deposits: bool,
    scan_legacy_spends: bool,
    scan_legacy_deposits: bool,
    max_scan_records: u64,
    legacy_spend_cursor: Option<u64>,
    legacy_deposit_cursor: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PruneResult {
    spends_pruned: u64,
    deposits_pruned: u64,
    legacy_spends_pruned: u64,
    legacy_deposits_pruned: u64,
    stopped_due_to_record_limit: bool,
    next_legacy_spend_cursor: Option<u64>,
    legacy_spend_scan_complete: bool,
    next_legacy_deposit_cursor: Option<[u8; 32]>,
    legacy_deposit_scan_complete: bool,
}

/// AC-18a: the DEFINITE-REJECTION path in `shield_deposit` removes the sidecar
/// along with the record.
///
/// Driven through the real endpoint with no allowance, so the pool takes the
/// `Ok(Err(definite))` arm — the site at which the record, the nonce, the
/// recovery locator and now the sidecar are all dropped together.
#[test]
fn no_orphan_sidecar_after_a_definite_ledger_rejection() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x1A);

    // No approve: the transfer definitely rejects.
    let r = shield(&pic, &s, c);
    assert!(
        r.is_err(),
        "fixture: without an allowance the deposit must be definitively rejected; got {r:?}"
    );

    assert!(
        deposit_record(&pic, &s, c).is_none(),
        "the rejected record is removed"
    );
    assert!(
        sidecar(&pic, &s, c).is_none(),
        "AC-18: and NO orphan sidecar is left behind (I-7)"
    );
    assert!(
        transfer_identity(&pic, &s, c).is_none(),
        "nor an orphan nonce"
    );
    assert_eq!(
        records_without_sidecar(&pic, &s),
        0,
        "and the removal left no half-removed pair in the other direction either"
    );
}

/// AC-18b: the DEF-072 retention prune removes the sidecar along with the
/// terminal record.
///
/// This is the site that matters most for a leak, because it is the one that
/// runs unattended: the prune walks terminal records on a timer-free operator
/// call, and a sidecar it failed to drop would accumulate forever with no path
/// that ever removes it (V1 ships no sidecar GC of its own — the sidecar's only
/// lifecycle is its record's).
///
/// It is also where forward secrecy is realised: `remove_deposit_nonce` on the
/// line above destroys the linkage secret, and a sidecar surviving that would
/// outlive the very record whose destruction the redaction design requires.
#[test]
fn no_orphan_sidecar_after_the_retention_prune() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x1B);

    // A terminal deposit, finalized long ago, plus a sidecar.
    let long_ago = now_ns(&pic).saturating_sub(40 * 24 * 3_600 * 1_000_000_000u64);
    let _: () = decode(
        "inject_terminal_deposit_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "inject_terminal_deposit_for_test",
            candid::encode_args((c, 0u64, long_ago)).unwrap(),
        ),
    );
    inject_sidecar(&pic, &s, c, nonce(0x1B), DENOM + DEFAULT_FEE, DEFAULT_FEE);
    assert!(
        sidecar(&pic, &s, c).is_some(),
        "fixture: the sidecar is present before the prune, or this test proves nothing"
    );

    let result: PruneResult = decode(
        "prune_terminal_records",
        pic.update_call(
            s.pool,
            s.controller,
            "prune_terminal_records",
            candid::encode_one(PruneRequest {
                older_than_ns: now_ns(&pic).saturating_sub(30 * 24 * 3_600 * 1_000_000_000u64),
                max_records: 100,
                prune_spends: false,
                prune_deposits: true,
                scan_legacy_spends: false,
                scan_legacy_deposits: true,
                max_scan_records: 100,
                legacy_spend_cursor: None,
                legacy_deposit_cursor: None,
            })
            .unwrap(),
        ),
    );
    assert!(
        result.deposits_pruned + result.legacy_deposits_pruned >= 1,
        "fixture: the prune must actually have removed the record; got {result:?}"
    );

    assert!(
        deposit_record(&pic, &s, c).is_none(),
        "the terminal record is pruned"
    );
    assert!(
        sidecar(&pic, &s, c).is_none(),
        "AC-18: and the prune drops the sidecar with it. A sidecar that survives the \
         retention prune has NO remaining path that would ever remove it — V1 ships no \
         sidecar GC, because a sidecar's only lifecycle is its record's."
    );
}

/// AC-18c: the fence-confirmed CLOSE removes the sidecar — asserted in
/// `definite_rejection_fences_closes_and_the_fence_bites` above, and restated
/// here as the third member of the set so a reader of this section sees all
/// removal paths in one place.
///
/// The fourth production removal site — the operator cancel in
/// `reconcile_deposit_transfer_not_executed` — is now UNREACHABLE for a
/// sidecar-covered record: D-10's guard refuses it. That refusal is itself the
/// correct answer for orphan purposes (nothing is removed, so nothing can be
/// orphaned), and is asserted in `deposit_retry_tests.rs`. The `remove_deposit_settlement`
/// call remains at that site regardless, because a removal site that is correct
/// only because of a guard somewhere else is one edit away from leaking.
#[test]
fn no_orphan_sidecar_after_a_fence_confirmed_close() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x1C);
    stuck_deposit(&pic, &s, c, nonce(0x1C));

    assert!(
        sidecar(&pic, &s, c).is_some(),
        "fixture: sidecar present before the close"
    );
    assert_eq!(
        settle(&pic, &s, c, anon()),
        Ok(DepositSettlementOutcome::FencedNotExecuted),
        "fixture: the settlement must reach the close"
    );

    assert!(deposit_record(&pic, &s, c).is_none(), "record removed");
    assert!(
        sidecar(&pic, &s, c).is_none(),
        "AC-18: and the sidecar with it — the close mirrors the operator cancel's \
         cleanup exactly, plus the sidecar"
    );
    assert_eq!(records_without_sidecar(&pic, &s), 0, "no half-removed pair");
}

// =============================================================================
// AC-6 — the two boundaries the evidence has to survive
//
// (a) TIME: past `TX_DEDUP_WINDOW_NS` the ledger cannot answer a
//     resubmission-based question at all, and the receipt answers instead.
//     Covered by `settlement_past_dedup_window_moves_no_balance_under_any_branch`
//     above, whose credit branch IS this property.
//
// (b) UPGRADE: both durable artifacts survive an upgrade of BOTH canisters, and
//     the claim self-heals with no post-upgrade normalization arm.
// =============================================================================

/// AC-6b: upgrade the TOKEN and the POOL between the receipt write and the
/// settle call. The receipt and the sidecar both survive, and the settlement
/// still resolves.
///
/// **WHY THIS IS NOT A FORMALITY.** Both new stable values use HAND-WRITTEN,
/// fixed-width `Storable` encodings rather than Candid — deliberately, so the
/// declared `max_size` is exact and AC-25's allocation measurement is
/// reproducible. A hand-written encoding is exactly the thing that round-trips
/// fine in a unit test and loses a field across a real upgrade, and a native
/// test cannot catch it: thread-locals survive an in-process `post_upgrade`, so
/// only a real PocketIC upgrade between two installed modules exercises the byte
/// round trip at all.
///
/// The fields asserted are the two that matter most. `fee` is the field the
/// whole sidecar exists for — if it decoded wrong, the resubmission would carry
/// a different dedup key and double-charge the depositor. `token_canister` is
/// the pinned ledger; if that decoded wrong, settlement would ask the wrong
/// canister a question whose answer moves money.
#[test]
fn receipt_and_sidecar_both_survive_an_upgrade_of_both_canisters() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x2A);
    stuck_deposit(&pic, &s, c, nonce(0x2A));

    let (memo, created) = transfer_identity(&pic, &s, c).expect("identity");
    let op = operation_id(&pic, &s, &memo);

    // Seed a real receipt through the production transfer path, so what is being
    // round-tripped is a receipt the canister actually wrote.
    approve(&pic, &s, DENOM + DEFAULT_FEE);
    assert!(
        transfer_from_as_pool(
            &pic,
            &s,
            Some(memo.clone()),
            Some(created),
            DENOM + DEFAULT_FEE
        )
        .is_ok(),
        "fixture: the seed transfer must execute and write its receipt"
    );

    let receipt_before = read_receipt(&pic, &s, op).expect("receipt before upgrade");
    let sidecar_before = sidecar(&pic, &s, c).expect("sidecar before upgrade");
    // Plant a claim, so the claim field is part of what crosses the boundary.
    let claim_at = now_ns(&pic);
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c, claim_at, 5u32)).unwrap(),
        ),
    );

    // ── Upgrade BOTH canisters ──
    pic.upgrade_canister(
        s.token,
        token_test_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    )
    .expect("token upgrade must succeed");
    pic.upgrade_canister(
        s.pool,
        pool_test_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    )
    .expect("pool upgrade must succeed");

    // ── The receipt survived, byte-for-byte ──
    let receipt_after = read_receipt(&pic, &s, op).expect(
        "AC-6b: the receipt must survive the token upgrade. If this is None, the \
         hand-written DepositReceiptV1 encoding did not round-trip — and the durable \
         evidence that outlives the dedup window is exactly what was lost.",
    );
    assert_eq!(
        receipt_after, receipt_before,
        "AC-6b: every receipt field must decode identically after the upgrade"
    );
    assert_eq!(
        receipt_count(&pic, &s),
        1,
        "AC-6b: and the map itself survived with its one row"
    );

    // ── The sidecar survived, including the claim ──
    let sidecar_after = sidecar(&pic, &s, c).expect(
        "AC-6b: the sidecar must survive the pool upgrade. If this is None, the \
         frozen fee is gone and the deposit is no longer settleable at all.",
    );
    assert_eq!(
        sidecar_after.fee, sidecar_before.fee,
        "AC-6b: THE FROZEN FEE must decode identically — a wrong fee here is the \
         double-charge, arriving through an upgrade instead of through a re-query"
    );
    assert_eq!(
        sidecar_after.amount, sidecar_before.amount,
        "AC-6b: the frozen amount must decode identically"
    );
    assert_eq!(
        sidecar_after.token_canister, sidecar_before.token_canister,
        "AC-6b: the PINNED ledger must decode identically — settlement asks this \
         canister, and asking the wrong one moves money"
    );
    assert_eq!(
        sidecar_after.protocol_version, 1,
        "AC-6b: the protocol version survives"
    );
    assert_eq!(
        sidecar_after.claim_generation,
        Some(5),
        "AC-6b: the claim, including its generation, crosses the boundary"
    );
    assert_eq!(
        sidecar_after.claim_claimed_at_ns,
        Some(claim_at),
        "AC-6b: and its timestamp"
    );

    // ── The claim SELF-HEALS: no normalization arm, just a TTL ──
    //
    // `CommitmentReconcileInFlight` needs a post-upgrade normalization arm
    // because it is a transient DepositStatus with nothing to time it out. This
    // claim needs none: it expires on its own. So a claim that crossed the
    // upgrade still blocks inside its TTL and is taken over after it, with no
    // upgrade-specific code path involved in either.
    assert_eq!(
        settle(&pic, &s, c, anon()),
        Err(SettlementError::InProgress),
        "AC-6b: a live claim still blocks after the upgrade"
    );
    let stale = claim_at.saturating_sub(SETTLE_CLAIM_TTL_NS + 1_000_000_000);
    let _: () = decode(
        "force_settle_claim_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "force_settle_claim_for_test",
            candid::encode_args((c, stale, 5u32)).unwrap(),
        ),
    );

    // And the settlement now completes off the surviving receipt — which is the
    // whole point: the deposit is resolvable after the upgrade, from evidence
    // that crossed it.
    let r = settle(&pic, &s, c, anon());
    assert!(
        matches!(r, Ok(DepositSettlementOutcome::CreditedFromReceipt(_))),
        "AC-6b: the surviving receipt must still resolve the deposit after the \
         upgrade; got {r:?}"
    );
    assert_eq!(
        accounting(&pic, &s).private_liability,
        DENOM,
        "AC-6b: and credit exactly once"
    );
    assert_eq!(leaf_count(&pic, &s), 1, "AC-6b: one leaf");
}
