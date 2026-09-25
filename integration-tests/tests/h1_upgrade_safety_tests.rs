// =============================================================================
// STSH — H-1 Pool Upgrade-Safety tests (PocketIC)
// Pre-Launch Hardening · Lane H-1 · BRIEF_POOL_REMEDIATION.md (expanded)
// =============================================================================
//
// The EXT-1 defect class: a durable pre-await status written before an
// inter-canister call, with NO post_upgrade reconstruction arm, permanently
// freezes the record if an upgrade drops the callback. H-1 (a) reorders the
// deposit + spend append so the in-flight marker is never durable without a
// usable index (T1), (b) normalizes every pre-await durable status in
// post_upgrade from an exhaustive classifier (T2/T4), and (c) guards the invalid
// legacy shape in pre_upgrade (T2).
//
// TEST DISCIPLINE (shared H-1 gate):
//   Every upgrade test performs a REAL `upgrade_canister` to the PRODUCTION Pool
//   Wasm (POOL_WASM), then asserts reconstruction via PRODUCTION query endpoints
//   (get_deposit_status / get_spend_status / get_accounting_state) and real
//   recovery endpoints (retry / reconcile). Setup uses the testing Wasm's
//   inject_* endpoints as a deterministic proxy for the mid-flight state (the
//   established deposit_retry_tests technique) + real Merkle-leaf seeding where a
//   landed leaf is required.
//
// ── P11 — CAMPAIGN-WIDE UPGRADE MATRIX (checked-in) ───────────────────────────
// Every durable pre-await Pool status, its post_upgrade reconstruction rule, and
// the covering test. Withdrawal states are EXCLUDED (dormant behind
// reject_unbound_withdrawal_proof(); audited under withdrawal re-enable).
//
//   DEPOSIT (DepositStatus)                    → rule                                   → test
//   TransferPending                            → Preserve (reconcile_transfer_not_exec) → P10
//   TransferConfirmedCommitmentPending         → Preserve (retryable; mid-leaf_count)   → P1
//   CommitmentAppendInFlight + Some(index)     → CommitmentAppendUnknown (get_leaf)     → P2, P3
//   CommitmentAppendInFlight + None            → TRAP upgrade (invalid shape)           → P6
//   CommitmentAppendUnknown                    → Preserve (reconcile_append_unknown)    → (DEF-050A)
//   CommitmentReconcileInFlight                → CommitmentAppendUnknown (index intact) → P4
//   CommitmentAppended                         → Preserve (credited; reconcile_commit)  → P5, P10
//   CommitmentRootAccepted                     → Preserve (terminal)                    → (matrix)
//
//   SPEND (SpendStatus)                        → rule                                   → test
//   Requested / VerificationPending            → RemoveRecord (free spend_id)           → P8a
//   NullifierReserved / OutputsStaged          → NullifierInsertUnknown (INFLIGHT kept) → P8b
//   NullifierReconcileInFlight                 → NullifierInsertUnknown                  → (DEF-099)
//   NullifierInsertUnknown                     → Preserve (reconcile_nullifier_insert)  → (matrix)
//   NullifierFinalizedOutputsPending           → Preserve (reconcile_pending_spend)     → P7a
//   ActiveAppendInFlight + Some(index)         → ActiveAppendUnknown                    → P7b
//   ActiveAppendInFlight + None                → NullifierFinalizedOutputsPending       → P7a
//   ActiveAppendUnknown / ActiveAppendRejected → Preserve (reconcile_pending_spend)     → P10
//   ActiveRootPending / RootAccepted           → Preserve (finalize_promotion)          → P10
//   PayoutPending / PayoutSubmitting / PayoutUnknown → Preserve (NEVER auto-retried)    → P10
//   Finalized / FailedBeforeStateChange / FailedAfterOutputsStaged → Preserve (terminal)→ (matrix)
//
//   TREASURY (TreasuryDisbursementStatus)      → rule                                   → test
//   PendingValidation                          → RemoveRecord (reserve intact)          → P9
//   PendingTransfer / TransportUnknown         → Preserve (reconcile_treasury_disburse) → (matrix)
//   Executed / Pending(legacy)                 → Preserve (terminal / manual)           → (matrix)
//
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
// H-1: the PRODUCTION Pool Wasm — the upgrade target of every gate test.
fn pool_prod_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0] = 1,000 STSH (A6.6)
const DEFAULT_FEE: u128 = 0;

// ── Token mirrors ─────────────────────────────────────────────────────────────
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String, category_name: String, amount: u128, recipient: Principal,
    subaccount: Option<[u8; 32]>, lock_policy: LockPolicy, vesting_policy: Option<VestingPolicy>,
    created_at_genesis: bool, genesis_timestamp_ns: u64,
}
#[derive(CandidType, Deserialize)]
struct TokenInitArgs { allocations: Vec<AllocationCategory>, treasury: Principal, staking_canister: Principal }
fn all_to(recipient: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(), category_name: "All".to_string(), amount: TOTAL_SUPPLY,
            recipient, subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None, created_at_genesis: false, genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01), staking_canister: p(0x02),
    }
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>, spender: Account, amount: u128, expected_allowance: Option<u128>,
    expires_at: Option<u64>, fee: Option<u128>, memo: Option<Vec<u8>>, created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveErr {
    BadFee { expected_fee: Nat }, InsufficientFunds { balance: Nat }, AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 }, TooOld, CreatedInFuture { ledger_time: u64 }, Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable, GenericError { error_code: Nat, message: String },
}

// ── Pool mirrors ──────────────────────────────────────────────────────────────
#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister: Principal, nullifier_canister: Principal, merkle_canister: Principal,
    treasury_canister: Principal, staking_canister: Principal, controller: Principal,
    initial_vk_hash: [u8; 32], initial_proof_system: String,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs { note_commitment: [u8; 32], encrypted_payload: Vec<u8>, public_amount: u128 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version: u32, proof_system_id: String, verifying_key_hash: [u8; 32],
    root_reference: [u8; 32], pool_version: u32, proof_bytes: Vec<u8>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id: u64, envelope: ProofEnvelope,     nullifiers: Vec<[u8; 32]>, output_commitments: Vec<[u8; 32]>, encrypted_outputs: Vec<Vec<u8>>,
    fee: u128, public_payout: Option<()>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending, TransferPending, TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight, CommitmentAppended { leaf_index: u64 }, CommitmentAppendUnknown,
    CommitmentReconcileInFlight, CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SpendStatus {
    Requested, OutputsStaged, Finalized,
    FailedBeforeStateChange { reason: String }, FailedAfterOutputsStaged { reason: String },
    VerificationPending, NullifierReserved, PayoutPending { reason: String },
    PayoutSubmitting, PayoutUnknown { reason: String }, NullifierInsertUnknown { reason: String },
    NullifierReconcileInFlight, NullifierFinalizedOutputsPending, ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String }, ActiveAppendRejected { reason: String },
    ActiveRootPending, RootAccepted,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TreasuryReserveBucket { Operations, Insurance, StakingRewards }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TreasuryDisbursementStatus {
    Pending, PendingValidation, PendingTransfer, Executed { block_index: Nat }, TransportUnknown,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositAppendReconcileResult { Finalized, RevertedRetryable }
// Full deposit-record mirror (matches lib.rs PendingDeposit; reads status + index).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingDeposit {
    note_commitment: [u8; 32], private_balance: u128, ops_amount: u128, insurance_amount: u128,
    encrypted_payload: Vec<u8>, depositor: Option<Principal>, status: DepositStatus, created_at_ns: u64,
    expected_leaf_index: Option<u64>, finalized_at_ns: Option<u64>,
}
// Partial spend-record view (candid record subtyping skips the unread fields).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpendView { spend_id: u64, nullifiers: Vec<[u8; 32]>, status: SpendStatus }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AccountingState {
    private_liability: u128, escrow_backing: u128, operations_reserve: u128,
    insurance_reserve: u128, governance_rewards_reserve: u128, pending_fee_reimbursements: u128,
}
// Full PoolError mirror (superset ok; decode matches by variant name).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination, InvalidProof, NullifierAlreadySpent, NullifierReserved, AnchorNotFound,
    EscrowUnderfunded { required: u128, available: u128 }, InsufficientEscrowCoverage { requested: u128, available: u128 },
    CircuitVersionMismatch { expected: u32, got: u32 }, VerifyingKeyMismatch, PoolVersionMismatch,
    TransferFailed(String), AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 }, InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier, Paused, SolvencyCheckFailed, DuplicateWithdrawalId, NotInitialised,
    CommitmentAppendFailed(String), DepositCommitmentPending, SumMismatch { inputs: u128, outputs: u128 }, SumOverflow,
    MalformedSpendArgs, DuplicateSpendId, SpendFeeNotSupported, VerifierUnavailable(String), ProofRejected(String),
    PrivateSpendFeeMismatch { expected: u128, got: u128 }, InsufficientPrivateLiability { required: u128, available: u128 },
    WithdrawalBelowMinimum { withdraw_gross_amount: u128, minimum_withdrawal_gross: u128 },
    GrossAmountBelowFees { withdraw_gross_amount: u128, total_fee: u128 },
    RecipientBelowMinimum { recipient_net_amount: u128, minimum_recipient_amount: u128 },
    IdempotencyKeyConflict, EncryptedPayloadTooLarge { len: u64, max: u64 },
    EncryptedOutputTooLarge { index: u32, len: u64, max: u64 }, InvalidProofLength { len: u64, expected: u64 },
    DepositTransferNotConfirmed, DepositAppendInProgress, DepositAppendUnknown, DepositAlreadyCompleted,
    InvalidCommitment, DepositNotFound, DepositNotReconcilable, AmbiguousMerkleState,
    PayoutNotPending, PayoutOutcomeUnknown, SpendNotFound, WrongSpendStatus,
    DisbursementNotFound, DisbursementNotReconcilable, StagedOutputsMissing,
    OutputAppendRejected(String), OutputAppendUnknown,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
}

// ── PocketIC helpers ──────────────────────────────────────────────────────────
fn p(n: u8) -> Principal { let mut b = [0u8; 29]; b[0] = n; Principal::from_slice(&b) }
fn anon() -> Principal { Principal::anonymous() }
fn create_canister(pic: &PocketIc) -> Principal { let c = pic.create_canister(); pic.add_cycles(c, 2_000_000_000_000u128); c }
fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
}
fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where T: CandidType + for<'de> serde::Deserialize<'de>, E: std::fmt::Debug {
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

struct Stack { pool: Principal, token: Principal, merkle: Principal, controller: Principal, user: Principal }

fn deploy_stack(pic: &PocketIc) -> Stack {
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
    install(pic, token, token_wasm(), &all_to(user));
    install(pic, pool, pool_test_wasm(), &PoolInitArgs {
        token_canister: token, nullifier_canister: null, merkle_canister: merkle,
        treasury_canister: p(0x01), staking_canister: p(0x02), controller,
        initial_vk_hash: [0u8; 32], initial_proof_system: "groth16-bn254".to_string(),
    });
    pic.update_call(pool, controller, "set_verifier_canister", candid::encode_args((verifier, vec![0u8; 32])).unwrap())
        .expect("set_verifier_canister");
    Stack { pool, token, merkle, controller, user }
}

/// H-1: a REAL upgrade to the PRODUCTION Pool Wasm. Returns Err if pre/post_upgrade traps.
fn upgrade_to_prod(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}
/// Re-upgrade to the testing Wasm to introspect test-only state (e.g. the treasury tag)
/// AFTER the production upgrade has already performed the reconstruction. The production
/// post_upgrade did the work; the second post_upgrade is idempotent on normalized state.
/// Advances the simulated clock first: three back-to-back installs of the ~1.4 MB Wasm
/// (initial + prod upgrade + this) would otherwise trip the install_code rate limit.
/// P-ARITH R-1 widened this from 1 day + 1 tick to the pdom-established 7 days +
/// 5 ticks: `overflow-checks = true` raises the instructions executed per install
/// enough that the old window no longer clears the per-canister budget — a harness
/// limit, not a canister defect. Callers are introspection-only (no time-window
/// semantics).
fn upgrade_to_test(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

fn commitment(tag: u8) -> [u8; 32] { let mut c = [0u8; 32]; c[0] = tag; c[1] = 0xDE; c }
fn nf(tag: u8) -> [u8; 32] { let mut n = [0u8; 32]; n[0] = tag; n[1] = 0x2F; n }

/// Real deposit (approve + shield_deposit) so the Merkle tree has a real accepted anchor.
fn fund_and_anchor(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    let _: Result<Nat, ApproveErr> = decode("approve", pic.update_call(s.token, s.user, "icrc2_approve",
        candid::encode_one(ApproveArgs {
            from_subaccount: None, spender: Account { owner: s.pool, subaccount: None },
            // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
            // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
            // exercise expiry, so the value only has to be present and in range.
            amount: DENOM + DEFAULT_FEE, expected_allowance: None, expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000), fee: None, memo: None, created_at_time: None,
        }).unwrap()));
    let c = commitment(0xF0);
    let dep: Result<Nat, PoolError> = decode("shield_deposit", pic.update_call(s.pool, s.user, "shield_deposit",
        candid::encode_one(ShieldDepositArgs { note_commitment: c, encrypted_payload: vec![], public_amount: DENOM }).unwrap()));
    assert!(dep.is_ok(), "fund deposit must succeed; got {:?}", dep);
    let v: Vec<u8> = decode("get_root", pic.query_call(s.merkle, anon(), "get_root", candid::encode_args(()).unwrap()));
    let mut r = [0u8; 32]; r.copy_from_slice(&v); r
}

fn inject_deposit(pic: &PocketIc, s: &Stack, c: [u8; 32], bal: u128, status: DepositStatus) {
    let _: () = decode("inject_pending_deposit_for_test", pic.update_call(s.pool, s.controller,
        "inject_pending_deposit_for_test", candid::encode_args((c, bal, status)).unwrap()));
}
fn inject_deposit_with_index(pic: &PocketIc, s: &Stack, c: [u8; 32], bal: u128, status: DepositStatus, idx: Option<u64>) {
    let _: () = decode("inject_pending_deposit_with_index_for_test", pic.update_call(s.pool, s.controller,
        "inject_pending_deposit_with_index_for_test", candid::encode_args((c, bal, status, idx)).unwrap()));
}
fn inject_spend(pic: &PocketIc, s: &Stack, spend_id: u64, nullifiers: Vec<[u8; 32]>, status: SpendStatus) {
    let _: () = decode("inject_spend_with_nullifiers_for_test", pic.update_call(s.pool, s.controller,
        "inject_spend_with_nullifiers_for_test", candid::encode_args((spend_id, nullifiers, status)).unwrap()));
}
fn inject_staged_outputs(pic: &PocketIc, s: &Stack, spend_id: u64, outs: Vec<[u8; 32]>, idx: Option<u64>) {
    let _: () = decode("inject_staged_outputs_for_test", pic.update_call(s.pool, s.controller,
        "inject_staged_outputs_for_test", candid::encode_args((spend_id, outs, idx)).unwrap()));
}
fn inject_treasury_disbursement(pic: &PocketIc, s: &Stack, proposal_id: u64, bucket: TreasuryReserveBucket, amount: u128, status: TreasuryDisbursementStatus) {
    let _: () = decode("inject_treasury_disbursement_for_test", pic.update_call(s.pool, s.controller,
        "inject_treasury_disbursement_for_test", candid::encode_args((proposal_id, bucket, s.user, amount, DEFAULT_FEE, status)).unwrap()));
}
fn set_ops_reserve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: () = decode("inject_operations_reserve_for_test", pic.update_call(s.pool, s.controller,
        "inject_operations_reserve_for_test", candid::encode_args((amount,)).unwrap()));
}

// ── P-ROOT (C-ROOT-1) mirrors: injected unresolved append states now need the
// pool-wide append lease installed alongside, or post_upgrade traps them as
// pre-lease unresolved records. ──
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum LeasePhase { Snapshotting, AppendInFlight, AppendUnknown, ReconcileInFlight, AppendConfirmedRootPending }
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum AppendLeaseOwner {
    Deposit { commitment: [u8; 32] },
    Spend { spend_id: u64 },
}
fn set_lease(pic: &PocketIc, s: &Stack, owner: AppendLeaseOwner, phase: LeasePhase) -> u64 {
    decode("set_append_lease_for_test", pic.update_call(s.pool, s.controller,
        "set_append_lease_for_test", candid::encode_args((owner, phase)).unwrap()))
}
fn lease_deposit(pic: &PocketIc, s: &Stack, c: [u8; 32], phase: LeasePhase) {
    let _ = set_lease(pic, s, AppendLeaseOwner::Deposit { commitment: c }, phase);
}
fn lease_spend(pic: &PocketIc, s: &Stack, spend_id: u64, phase: LeasePhase) {
    let _ = set_lease(pic, s, AppendLeaseOwner::Spend { spend_id }, phase);
}

fn deposit_status(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Option<PendingDeposit> {
    decode("get_deposit_status", pic.query_call(s.pool, s.controller, "get_deposit_status", candid::encode_one(c).unwrap()))
}
fn spend_status(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<PendingSpendView> {
    decode("get_spend_status", pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(spend_id).unwrap()))
}
fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode("get_accounting_state", pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()))
}
fn disbursement_tag(pic: &PocketIc, s: &Stack, proposal_id: u64) -> u8 {
    decode("treasury_disbursement_status_tag_for_test", pic.query_call(s.pool, s.controller,
        "treasury_disbursement_status_tag_for_test", candid::encode_one(proposal_id).unwrap()))
}
fn retry(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<Nat, PoolError> {
    decode("retry_deposit_commitment", pic.update_call(s.pool, s.user, "retry_deposit_commitment", candid::encode_one(c).unwrap()))
}
fn reconcile_append_unknown(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<DepositAppendReconcileResult, PoolError> {
    decode("reconcile_deposit_append_unknown", pic.update_call(s.pool, s.controller, "reconcile_deposit_append_unknown", candid::encode_one(c).unwrap()))
}
/// Real no-payout private_spend with the given nullifier (stub verifier → Ok).
fn run_spend(pic: &PocketIc, s: &Stack, root: [u8; 32], spend_id: u64, nullifier: [u8; 32]) -> Result<(), PoolError> {
    let mut c1 = [0u8; 32]; c1[0] = 0x40;
    let mut c2 = [0u8; 32]; c2[0] = 0x41;
    let args = PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0, proof_system_id: "groth16-bn254".to_string(), verifying_key_hash: [0u8; 32],
            root_reference: root, pool_version: 1, proof_bytes: vec![0u8; 8],
        },
                nullifiers: vec![nullifier], output_commitments: vec![c1, c2],
        encrypted_outputs: vec![vec![], vec![]], fee: 0, public_payout: None,
    };
    decode("private_spend", pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()))
}

// ═════════════════════════════════════════════════════════════════════════════
// P1 — upgrade during preliminary leaf_count: record stays pending, retry succeeds
// ═════════════════════════════════════════════════════════════════════════════
// Under H-1 T1 the leaf_count snapshot precedes the claim, so a mid-leaf_count
// upgrade leaves the deposit at TransferConfirmedCommitmentPending — never a
// half-claimed CommitmentAppendInFlight. Assert: preserved pending, no append,
// no credit; then a real retry credits exactly once.
#[test]
fn p1_upgrade_during_leaf_count_stays_pending_then_retry_credits_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x11);
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    let before = accounting(&pic, &s);

    upgrade_to_prod(&pic, &s).expect("upgrade must succeed for a pending deposit");

    assert_eq!(deposit_status(&pic, &s, c).map(|d| d.status),
        Some(DepositStatus::TransferConfirmedCommitmentPending), "still pending after upgrade");
    let mid = accounting(&pic, &s);
    assert_eq!(mid.escrow_backing, before.escrow_backing, "no credit on upgrade");
    assert_eq!(mid.private_liability, before.private_liability, "no liability on upgrade");

    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "retry credits after upgrade");
    // P-ROOT: a completed deposit now finalizes through the accepted-root head to
    // the terminal CommitmentRootAccepted (was CommitmentAppended pre-P-ROOT).
    assert!(matches!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::CommitmentRootAccepted { .. })));
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing + DENOM, "credited exactly once");
    assert_eq!(after.private_liability, before.private_liability + DENOM, "liability exactly once");
}

// ═════════════════════════════════════════════════════════════════════════════
// P2 — upgrade during append, leaf landed → AppendUnknown → reconcile → credit once
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p2_upgrade_during_append_leaf_landed_reconciles_and_credits_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x22);
    // Seed a real Merkle leaf at index 0 (transfer confirmed → retry appends + credits).
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "seed append succeeds");
    // Overwrite to CommitmentAppendInFlight + Some(0): the mid-append pre-upgrade shape.
    inject_deposit_with_index(&pic, &s, c, DENOM, DepositStatus::CommitmentAppendInFlight, Some(0));
    // P-ROOT: a mid-append record holds the pool-wide lease at AppendInFlight.
    lease_deposit(&pic, &s, c, LeasePhase::AppendInFlight);

    upgrade_to_prod(&pic, &s).expect("valid InFlight+Some(index) must upgrade");

    // T2: InFlight+Some → CommitmentAppendUnknown, index intact.
    let d = deposit_status(&pic, &s, c).expect("record present");
    assert_eq!(d.status, DepositStatus::CommitmentAppendUnknown, "normalized to AppendUnknown");
    assert_eq!(d.expected_leaf_index, Some(0), "expected_leaf_index survived the upgrade");

    // Reconcile finds the leaf → Finalized; credit delta is exactly one DENOM.
    let before = accounting(&pic, &s);
    assert_eq!(reconcile_append_unknown(&pic, &s, c), Ok(DepositAppendReconcileResult::Finalized));
    // P-ROOT: the reconcile finalization now runs through the accepted-root head
    // to the terminal CommitmentRootAccepted.
    assert!(matches!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::CommitmentRootAccepted { .. })));
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, before.escrow_backing + DENOM, "reconcile credits exactly once");

    // Idempotent: a second reconcile cannot credit again.
    assert_eq!(reconcile_append_unknown(&pic, &s, c), Err(PoolError::DepositNotReconcilable));
    assert_eq!(accounting(&pic, &s).escrow_backing, after.escrow_backing, "no double-credit");
}

// ═════════════════════════════════════════════════════════════════════════════
// P3 — upgrade during append, leaf absent → AppendUnknown → reconcile revert → retry
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p3_upgrade_during_append_leaf_absent_reverts_then_retry_credits_once() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x33);
    // Fresh tree (leaf_count = 0); inject InFlight+Some(0) with NO leaf actually at 0.
    inject_deposit_with_index(&pic, &s, c, DENOM, DepositStatus::CommitmentAppendInFlight, Some(0));
    // P-ROOT: a mid-append record holds the pool-wide lease at AppendInFlight.
    lease_deposit(&pic, &s, c, LeasePhase::AppendInFlight);
    let before = accounting(&pic, &s);

    upgrade_to_prod(&pic, &s).expect("valid InFlight+Some(index) must upgrade");
    assert_eq!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::CommitmentAppendUnknown));

    // Reconcile: slot empty → revert to retryable; no credit.
    assert_eq!(reconcile_append_unknown(&pic, &s, c), Ok(DepositAppendReconcileResult::RevertedRetryable));
    assert_eq!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::TransferConfirmedCommitmentPending));
    assert_eq!(accounting(&pic, &s).escrow_backing, before.escrow_backing, "no credit on revert");

    // Retry now appends + credits exactly once.
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)));
    assert_eq!(accounting(&pic, &s).escrow_backing, before.escrow_backing + DENOM, "retry credits once");
}

// ═════════════════════════════════════════════════════════════════════════════
// P4 — upgrade during reconciliation → CommitmentAppendUnknown, index intact
// ═════════════════════════════════════════════════════════════════════════════
// P-ROOT rework: only ONE unresolved append can exist pool-wide (the lease), so
// the two fixtures now run in two separate instances, each holding the lease at
// ReconcileInFlight. Normalization target is unchanged: CommitmentAppendUnknown,
// index intact, lease retained at AppendUnknown.
#[test]
fn p4_upgrade_during_reconcile_in_flight_normalizes_index_intact() {
    for idx in [7u64, 9u64] {
        let pic = PocketIc::new();
        let s = deploy_stack(&pic);
        let c = commitment(0x44);
        inject_deposit_with_index(&pic, &s, c, DENOM, DepositStatus::CommitmentReconcileInFlight, Some(idx));
        lease_deposit(&pic, &s, c, LeasePhase::ReconcileInFlight);

        upgrade_to_prod(&pic, &s).expect("reconcile-in-flight marker must upgrade");

        let d = deposit_status(&pic, &s, c).expect("record present");
        assert_eq!(d.status, DepositStatus::CommitmentAppendUnknown, "reconcile-in-flight → AppendUnknown");
        assert_eq!(d.expected_leaf_index, Some(idx), "index intact");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// P5 — upgrade after credit, before root callback: CommitmentAppended survives
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p5_upgrade_after_credit_before_root_survives_no_double_credit() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x55);
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::TransferConfirmedCommitmentPending);
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "real append + credit");
    let credited = accounting(&pic, &s);
    // P-ROOT: a completed retry finalizes through the accepted-root head to the
    // terminal CommitmentRootAccepted (was CommitmentAppended pre-P-ROOT).
    assert!(matches!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::CommitmentRootAccepted { .. })));

    upgrade_to_prod(&pic, &s).expect("CommitmentRootAccepted must upgrade");

    assert!(matches!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::CommitmentRootAccepted { .. })),
        "terminal CommitmentRootAccepted preserved across upgrade");
    let after = accounting(&pic, &s);
    assert_eq!(after.escrow_backing, credited.escrow_backing, "accounting survives exactly");
    assert_eq!(after.private_liability, credited.private_liability, "liability survives exactly");
    // A retry on an already-appended deposit is idempotent (no double-credit).
    assert_eq!(retry(&pic, &s, c), Ok(Nat::from(DENOM)), "retry idempotent");
    assert_eq!(accounting(&pic, &s).escrow_backing, credited.escrow_backing, "no double-credit");
}

// ═════════════════════════════════════════════════════════════════════════════
// P6 — invalid CommitmentAppendInFlight + None traps the upgrade; preflight detects it
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p6_invalid_inflight_none_traps_upgrade_and_preflight_detects() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let c = commitment(0x66);
    // The invalid legacy shape: CommitmentAppendInFlight with expected_leaf_index = None
    // (inject_pending_deposit_for_test forces None).
    inject_deposit(&pic, &s, c, DENOM, DepositStatus::CommitmentAppendInFlight);

    // Deployment preflight: the same shape is detectable pre-upgrade via the status query.
    let d = deposit_status(&pic, &s, c).expect("record present");
    assert_eq!(d.status, DepositStatus::CommitmentAppendInFlight);
    assert_eq!(d.expected_leaf_index, None, "preflight-detectable invalid shape (InFlight + None)");

    // The pre_upgrade guard rejects the upgrade before checkpointing.
    let r = upgrade_to_prod(&pic, &s);
    assert!(r.is_err(), "upgrade must TRAP on CommitmentAppendInFlight + None; got {:?}", r);
    // The canister is still on the (un-upgraded) test wasm and still serves queries.
    assert_eq!(deposit_status(&pic, &s, c).map(|d| d.status), Some(DepositStatus::CommitmentAppendInFlight),
        "record unchanged after the rejected upgrade");
}

// ═════════════════════════════════════════════════════════════════════════════
// P7 — spend ActiveAppendInFlight: index None → NullifierFinalizedOutputsPending;
//      index Some → ActiveAppendUnknown
// ═════════════════════════════════════════════════════════════════════════════
// P-ROOT rework: an ActiveAppendInFlight record now always coexists with the
// pool-wide lease at AppendInFlight (claim + lease transition are one no-await
// segment), and post_upgrade normalizes the PAIR to (AppendUnknown,
// ActiveAppendUnknown) per the normative tuple table — the old index-None →
// NullifierFinalizedOutputsPending resolution is unreachable (the index and the
// marker are written atomically), and a lease-FREE ActiveAppendInFlight is now a
// pre-lease unresolved record that REJECTS the upgrade (covered in the P-ROOT
// suite).
#[test]
fn p7_spend_active_append_in_flight_index_resolution() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    inject_spend(&pic, &s, 701, vec![nf(0x72)], SpendStatus::ActiveAppendInFlight);
    let mut o1 = [0u8; 32]; o1[0] = 0x50;
    inject_staged_outputs(&pic, &s, 701, vec![o1], Some(3));
    lease_spend(&pic, &s, 701, LeasePhase::AppendInFlight);

    upgrade_to_prod(&pic, &s).expect("ActiveAppendInFlight fixture must upgrade");

    assert!(matches!(spend_status(&pic, &s, 701).map(|v| v.status), Some(SpendStatus::ActiveAppendUnknown { .. })),
        "lost append callback → ActiveAppendUnknown (lease retained at AppendUnknown)");
}

// ═════════════════════════════════════════════════════════════════════════════
// P8 — VerificationPending removed (slot freed); OutputsStaged → NullifierInsertUnknown
//      with the nullifier still INFLIGHT-protected
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p8_verification_pending_removed_and_outputs_staged_insert_unknown() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = fund_and_anchor(&pic, &s);

    // (a) VerificationPending → removed on upgrade (free the spend_id).
    inject_spend(&pic, &s, 800, vec![nf(0x81)], SpendStatus::VerificationPending);
    // (b) OutputsStaged → NullifierInsertUnknown; nullifier stays INFLIGHT-protected.
    let staged_nf = nf(0x82);
    inject_spend(&pic, &s, 801, vec![staged_nf], SpendStatus::OutputsStaged);

    upgrade_to_prod(&pic, &s).expect("spend fixtures must upgrade");

    // (a) record gone → slot retryable (a fresh spend at 800 is not DuplicateSpendId).
    assert!(spend_status(&pic, &s, 800).is_none(), "VerificationPending record removed");
    let fresh = run_spend(&pic, &s, root, 800, nf(0x8A));
    assert_ne!(fresh, Err(PoolError::DuplicateSpendId), "spend_id 800 freed for reuse; got {:?}", fresh);

    // (b) normalized to NullifierInsertUnknown, and the nullifier is still reserved
    // (a fresh spend carrying it is heap-blocked → NullifierReserved).
    assert!(matches!(spend_status(&pic, &s, 801).map(|v| v.status), Some(SpendStatus::NullifierInsertUnknown { .. })),
        "OutputsStaged → NullifierInsertUnknown");
    assert_eq!(run_spend(&pic, &s, root, 810, staged_nf), Err(PoolError::NullifierReserved),
        "the OutputsStaged nullifier stays INFLIGHT-protected across the upgrade");
}

// ═════════════════════════════════════════════════════════════════════════════
// P9 — treasury PendingValidation cleared on upgrade; reserve intact; slot freed
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p9_treasury_pending_validation_cleared_reserve_intact() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    set_ops_reserve(&pic, &s, 5 * DENOM);
    inject_treasury_disbursement(&pic, &s, 900, TreasuryReserveBucket::Operations, DENOM, TreasuryDisbursementStatus::PendingValidation);
    assert_eq!(disbursement_tag(&pic, &s, 900), 4, "injected as PendingValidation (tag 4)");
    let ops_before = accounting(&pic, &s).operations_reserve;

    upgrade_to_prod(&pic, &s).expect("treasury PendingValidation must upgrade");
    // Production query: the reserve is untouched (PendingValidation had no debit).
    assert_eq!(accounting(&pic, &s).operations_reserve, ops_before,
        "reserve untouched (PendingValidation had no debit)");
    // The production post_upgrade removed the record; re-upgrade to the testing Wasm to
    // read the test-only tag (the removal persists — it is durable state, not test state).
    upgrade_to_test(&pic, &s).expect("re-upgrade to test wasm for introspection");
    assert_eq!(disbursement_tag(&pic, &s, 900), 0,
        "PendingValidation removed by the production post_upgrade (tag 0 = none) → proposal_id freed");
}

// ═════════════════════════════════════════════════════════════════════════════
// P10 — preserve-class: injected → real upgrade → asserted UNCHANGED
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn p10_preserve_class_states_survive_upgrade_unchanged() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Deposit preserve-class. (P-ROOT: CommitmentAppended is now lease-requiring
    // — its retained-with-lease upgrade is covered in the P-ROOT suite; a
    // lease-free one rejects the upgrade, so it left this cohort.)
    let tp = commitment(0xA1);
    inject_deposit(&pic, &s, tp, DENOM, DepositStatus::TransferPending);

    // Spend preserve-class (incl. PayoutSubmitting — MUST never be auto-retried).
    // (P-ROOT: ActiveAppendUnknown / ActiveRootPending are lease-requiring and
    // left this cohort for the same reason.)
    inject_spend(&pic, &s, 1003, vec![nf(0xB3)], SpendStatus::RootAccepted);
    inject_spend(&pic, &s, 1004, vec![], SpendStatus::PayoutSubmitting);

    upgrade_to_prod(&pic, &s).expect("preserve-class fixtures must upgrade");

    assert_eq!(deposit_status(&pic, &s, tp).map(|d| d.status), Some(DepositStatus::TransferPending));
    assert_eq!(spend_status(&pic, &s, 1003).map(|v| v.status), Some(SpendStatus::RootAccepted));
    assert_eq!(spend_status(&pic, &s, 1004).map(|v| v.status), Some(SpendStatus::PayoutSubmitting),
        "PayoutSubmitting preserved — NEVER auto-retried by post_upgrade");
}

// ═════════════════════════════════════════════════════════════════════════════
// P11 — campaign-wide matrix guard: the invalid deposit shape traps; everything
//       else in one mixed cohort survives a single real upgrade and reconstructs.
// ═════════════════════════════════════════════════════════════════════════════
// The full state→rule→test matrix is the checked-in header block above. This test
// is its executable cross-check: a mixed cohort of the H-1-relevant states driven
// through ONE real upgrade to the production Wasm, asserting each reconstructs to
// its matrix rule. The invalid InFlight+None shape is proven separately in P6
// (it traps, so it cannot share a cohort).
#[test]
fn p11_mixed_cohort_reconstructs_per_matrix() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // P-ROOT: at most ONE unresolved append can exist pool-wide, so the cohort
    // carries exactly one lease-owned record (the mid-append deposit, with its
    // lease); the second reconcile-in-flight deposit and the ActiveAppendInFlight
    // spend of the pre-P-ROOT cohort are covered by P4/P7 and the P-ROOT suite.
    let inflight = commitment(0xC1);
    inject_deposit_with_index(&pic, &s, inflight, DENOM, DepositStatus::CommitmentAppendInFlight, Some(2));
    lease_deposit(&pic, &s, inflight, LeasePhase::AppendInFlight);
    let pending = commitment(0xC3);
    inject_deposit(&pic, &s, pending, DENOM, DepositStatus::TransferConfirmedCommitmentPending);

    inject_spend(&pic, &s, 1102, vec![nf(0xD2)], SpendStatus::OutputsStaged);
    inject_spend(&pic, &s, 1103, vec![nf(0xD3)], SpendStatus::VerificationPending);

    inject_treasury_disbursement(&pic, &s, 1104, TreasuryReserveBucket::Insurance, DENOM, TreasuryDisbursementStatus::PendingValidation);

    upgrade_to_prod(&pic, &s).expect("mixed cohort (all valid) must upgrade");

    assert_eq!(deposit_status(&pic, &s, inflight).map(|d| d.status), Some(DepositStatus::CommitmentAppendUnknown));
    assert_eq!(deposit_status(&pic, &s, pending).map(|d| d.status), Some(DepositStatus::TransferConfirmedCommitmentPending));
    assert!(matches!(spend_status(&pic, &s, 1102).map(|v| v.status), Some(SpendStatus::NullifierInsertUnknown { .. })));
    assert!(spend_status(&pic, &s, 1103).is_none(), "VerificationPending removed");
    // Treasury introspection needs the test-only tag; re-upgrade to the testing Wasm (the
    // production post_upgrade already removed the record — the removal persists).
    upgrade_to_test(&pic, &s).expect("re-upgrade to test wasm for treasury introspection");
    assert_eq!(disbursement_tag(&pic, &s, 1104), 0, "treasury PendingValidation removed by the production post_upgrade");
}
