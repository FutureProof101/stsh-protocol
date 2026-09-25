// =============================================================================
// STSH — R-13 pool accounting write-through (PocketIC + AST lock)
// =============================================================================
//
// Two independent locks on the same defect class:
//
//   AC-1  `r13_accounting_cell_writer_set_is_the_funnel_only` — a `syn` AST
//         visitor over `canisters/shielded-pool/src/lib.rs` that resolves every
//         write to one of the six accounting cells to its OWNING fn, and asserts
//         that set is exactly {commit_pool_accounting}. No text is scanned
//         anywhere: the only read of the source is `syn::parse_file`, and every
//         classification is a match on AST node kinds (R-L RED-5 precedent,
//         master 48787cd). The alias resolver is DEPTH-AWARE (R-L RED-8, master
//         111154d): a `let g = &GOVERNANCE_REWARDS_RESERVE;` written inside a
//         nested `match` arm is collected just as a top-level one is.
//
//   AC-2  `b7_accounting_writethrough_spend_survives_upgrade` — a real
//         cross-Wasm PocketIC durability test: a zero-fee `private_spend` with a
//         NONZERO public payout, accounting read before and after a real pool
//         canister upgrade.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): build shielded_pool with
// --features testing, copy to shielded_pool_test.wasm, then build all production
// wasms + stsh-stub-verifier. POCKET_IC_BIN must be set.
// =============================================================================

#![allow(dead_code)]

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

// ── Constants ───────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM_1000: u128 = 1_000 * 100_000_000; // DENOMINATIONS[3]
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch
/// Local mirror of the pool's `DENOMINATIONS` (ARCHITECTURE.md law 1,
/// `canisters/shielded-pool/src/lib.rs:83-88`). `integration-tests` does not
/// depend on the pool crate — every pool type in this harness is a Candid
/// mirror, and this constant is mirrored the same way.
const DENOMINATIONS: [u128; 5] = [
    // A6.6 five-tier launch ladder — mirrors the pool's own DENOMINATIONS.
    1_000 * 100_000_000,
    10_000 * 100_000_000,
    100_000 * 100_000_000,
    1_000_000 * 100_000_000,
    10_000_000 * 100_000_000,
];

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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcilePendingSpendResult {
    PromotedFinalized,
    PromotedPayoutPending,
    AppendRetryScheduled,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum ReconcileNullifierResult {
    CommittedFinalized,
    CommittedPayoutPending,
    NotCommittedFailed,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum RecommendedAction {
    ReconcileNullifierInsert,
    ReconcilePendingSpend,
    RetryPrivateSpendPayout,
    ReconcilePrivateSpendPayout,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingPromotionRecord {
    spend_id: u64,
    status: SpendStatus,
    created_at_ns: u64,
    output_commitment_count: u32,
    expected_first_leaf_index: Option<u64>,
    resulting_root: Option<[u8; 32]>,
    recommended_action: RecommendedAction,
}
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
    DisbursementNotFound,
    DisbursementNotReconcilable,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal { Principal::anonymous() }
/// Canonical small BN254 Fr value: low byte set, high bytes zero (well below modulus).
fn fr(b: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = b;
    a
}
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
    null: Principal,
    merkle: Principal,
    controller: Principal,
    user: Principal,
}

/// Standard healthy stack: nullifier registry authorized for the pool.
fn deploy_stack(pic: &PocketIc) -> Stack {
    deploy_stack_inner(pic, true)
}
/// Stack whose nullifier registry is authorized to a WRONG principal, so the pool's
/// insert_batch traps (definite non-commit) — used to exercise FailedAfterOutputsStaged.
fn deploy_stack_broken_registry(pic: &PocketIc) -> Stack {
    deploy_stack_inner(pic, false)
}
fn deploy_stack_inner(pic: &PocketIc, registry_ok: bool) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let verifier = create_canister(pic);
    let pool = create_canister(pic);
    let null_authority = if registry_ok { pool } else { p(0xBA) };
    install(pic, null, nullifier_wasm(), &null_authority);
    install(pic, merkle, merkle_wasm(), &pool);
    pic.install_canister(verifier, stub_verifier_wasm(), candid::encode_one(None::<[u8; 32]>).unwrap(), None);
    install(pic, token, token_wasm(), &all_to(user, p(0x02)));
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
    pic.update_call(pool, controller, "set_verifier_canister", candid::encode_args((verifier, vec![0u8; 32])).unwrap())
        .expect("set_verifier_canister");
    Stack { pool, token, null, merkle, controller, user }
}

fn root_of(pic: &PocketIc, merkle: Principal) -> [u8; 32] {
    let v: Vec<u8> = decode(
        "get_root",
        pic.query_call(merkle, anon(), "get_root", candid::encode_args(()).unwrap()),
    );
    let mut r = [0u8; 32];
    r.copy_from_slice(&v);
    r
}
fn merkle_root(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    root_of(pic, s.merkle)
}

fn approve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: Result<Nat, ApproveErr> = decode(
        "approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
                amount,
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
}

/// A real fixed-denomination deposit (ARCHITECTURE.md law 1) of `amount`, with the
/// given commitment; returns the accepted Merkle root.
fn deposit(pic: &PocketIc, s: &Stack, amount: u128, commitment: [u8; 32]) -> [u8; 32] {
    approve(pic, s, amount + DEFAULT_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![],
                public_amount: amount,
            })
            .unwrap(),
        ),
    );
    assert!(dep.is_ok(), "deposit of {} must succeed; got {:?}", amount, dep);
    merkle_root(pic, s)
}

/// A zero-fee `private_spend` carrying a NONZERO public payout. Ported from
/// `active_root_finality_tests.rs`'s `payout_spend_args` (same shape, same
/// stub-verifier arrangement). The payout is what makes
/// `private_liability_debit = fee.saturating_add(public_amount)` nonzero at
/// `fee == 0` — the launch config.
fn spend_args_with_payout(
    anchor: [u8; 32],
    spend_id: u64,
    nullifier: [u8; 32],
    recipient: Principal,
    payout: u128,
) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: anchor,
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
        nullifiers: vec![nullifier],
        output_commitments: vec![fr(0x30 + spend_id as u8), fr(0x40 + spend_id as u8)],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: recipient,
            destination_subaccount: None,
            public_amount: payout,
        }),
    }
}

fn spend_status(pic: &PocketIc, s: &Stack, spend_id: u64) -> Option<SpendStatus> {
    let rec: Option<PendingSpend> = decode(
        "get_spend_status",
        pic.query_call(s.pool, s.controller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
    );
    rec.map(|r| r.status)
}

// ── Accounting + attestation read surfaces ──────────────────────────────────

const ACCT_W_PRIVATE_LIABILITY: usize = 0;
const ACCT_W_ESCROW_BACKING: usize = 1;
const ACCT_W_OPERATIONS_RESERVE: usize = 2;
const ACCT_W_INSURANCE_RESERVE: usize = 3;
const ACCT_W_GOVERNANCE_REWARDS_RESERVE: usize = 4;
const ACCT_W_PENDING_FEE_REIMBURSEMENTS: usize = 5;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

/// `get_accounting_state` is controller-gated (DEF-076) — read as controller.
fn accounting_words_via_controller(pic: &PocketIc, s: &Stack) -> [u128; 6] {
    let st: AccountingState = decode(
        "get_accounting_state",
        pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()),
    );
    [
        st.private_liability,
        st.escrow_backing,
        st.operations_reserve,
        st.insurance_reserve,
        st.governance_rewards_reserve,
        st.pending_fee_reimbursements,
    ]
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct SolvencyAttestation {
    public_delta_e8s: candid::Int,
    healthy: bool,
    attested_at_ns: u64,
    schema_version: u32,
}

/// The `CertifiedSolvencyAttestation` wrapper the query actually returns
/// (`shielded_pool.did:690-695`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct SolvencyAttestationView {
    attestation: SolvencyAttestation,
    canonical_bytes: Vec<u8>,
    certificate: Option<Vec<u8>>,
    witness: Vec<u8>,
}

fn get_solvency_attestation(pic: &PocketIc, pool: Principal) -> SolvencyAttestationView {
    decode(
        "get_solvency_attestation",
        pic.query_call(pool, anon(), "get_solvency_attestation", candid::encode_args(()).unwrap()),
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// AC-2 — B-7-ACCOUNTING-WRITETHROUGH-SPEND
// ═════════════════════════════════════════════════════════════════════════════

/// Deposits `amount`, spends it via a real `private_spend` at fee = 0 (the launch
/// config) with a NONZERO PUBLIC PAYOUT (`payout = amount / 2`), reads the
/// accounting words AND the attestation BEFORE the upgrade, upgrades the pool
/// canister (SAME Wasm), reads both AGAIN after.
/// `private_liability_debit = fee.saturating_add(public_amount)` is therefore
/// `> 0` regardless of `fee`.
fn spend_with_payout_and_read_across_upgrade(
    pic: &PocketIc,
    s: &Stack,
    spend_id: u64,
    amount: u128,
) -> ([u128; 6], [u128; 6], SolvencyAttestationView, SolvencyAttestationView) {
    let commitment = fr(0x80 + spend_id as u8);
    let anchor = deposit(pic, s, amount, commitment);
    for _ in 0..4 {
        pic.tick();
    }
    let nullifier = fr(0x10 + spend_id as u8);
    let payout = amount / 2;
    let args = spend_args_with_payout(anchor, spend_id, nullifier, p(0xD9), payout);
    let r: Result<(), PoolError> = decode(
        "private_spend",
        pic.update_call(s.pool, s.user, "private_spend", candid::encode_one(args).unwrap()),
    );
    // The payout leg may leave the spend PayoutPending (the ledger transfer is a
    // separate step); what matters here is that the ACCOUNTING debit has been
    // applied, which happens at finalize, before the payout leg.
    assert!(
        matches!(
            spend_status(pic, s, spend_id),
            Some(SpendStatus::Finalized)
                | Some(SpendStatus::PayoutPending { .. })
                | Some(SpendStatus::PayoutSubmitting)
        ),
        "spend {} must reach finality (accounting applied); got {:?} / call {:?}",
        spend_id,
        spend_status(pic, s, spend_id),
        r
    );
    for _ in 0..4 {
        pic.tick();
    }

    let words_before = accounting_words_via_controller(pic, s);
    let attested_before = get_solvency_attestation(pic, s.pool);

    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade must succeed");

    let words_after = accounting_words_via_controller(pic, s);
    let attested_after = get_solvency_attestation(pic, s.pool);

    (words_before, words_after, attested_before, attested_after)
}

// BINDING: B-7-ACCOUNTING-WRITETHROUGH-SPEND
#[test]
fn b7_accounting_writethrough_spend_survives_upgrade() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    // Rule (c): invoke the bound property TWICE with DIFFERING arguments —
    // different deposit denominations, hence different payouts and different
    // liability debits — and assert an inequality on the result.
    let (before_a, after_a, att_before_a, att_after_a) =
        spend_with_payout_and_read_across_upgrade(&pic, &s, 1, DENOMINATIONS[0]);
    let (before_b, after_b, att_before_b, att_after_b) =
        spend_with_payout_and_read_across_upgrade(&pic, &s, 2, DENOMINATIONS[1]);
    assert_ne!(
        before_a[ACCT_W_PRIVATE_LIABILITY], before_b[ACCT_W_PRIVATE_LIABILITY],
        "the two spends (distinct denominations, distinct nonzero payouts) must leave \
         genuinely different liability, or this binding is vacuous"
    );

    // The actual defect proof: durability across a real upgrade, per spend. This
    // is the assertion that carries AC-2 AND — folded per the brief's §3.4 —
    // AC-4's word-level half; it is the ONLY assertion here the AC-2 mutation REDs.
    assert_eq!(before_a, after_a, "spend 1: accounting must survive the upgrade byte-for-byte");
    assert_eq!(before_b, after_b, "spend 2: accounting must survive the upgrade byte-for-byte");

    // AC-4 — SANITY, not an independent RED source for the AC-2 mutation. The
    // attestation's derived fields are ALGEBRAICALLY invariant under this path's
    // symmetric liability/escrow debit: raw_solvency_delta = escrow + pending -
    // liability, and both escrow and liability move by the same d, so delta' =
    // (escrow - d) + pending - (liability - d) = delta. `healthy` and
    // `public_delta_e8s` are pure functions of delta alone, so no spend through
    // this path can move either field in ANY build, correct or mutated.
    // Recorded honestly as a sanity check rather than a durability proof.
    assert!(
        att_after_a.attestation.healthy,
        "post-upgrade re-certification must report healthy on a spend that did not \
         drive the pool insolvent — sanity check, not a durability proof"
    );
    assert!(att_after_b.attestation.healthy);
    let _ = (att_before_a, att_before_b); // read but not asserted on — see above
}

// ═════════════════════════════════════════════════════════════════════════════
// AC-1 — the lane's no-raw-writes lock: a DEPTH-AWARE `syn` AST visitor
// ═════════════════════════════════════════════════════════════════════════════
//
// Placement (the brief leaves this to the builder): an `integration-tests`
// `#[test]` linking a local `syn` visitor module. `syn` with the `visit` feature
// is already a dev-dependency of this crate (R-2/C-30 precedent), so this adds
// no dependency and needs no run_gate.sh wiring — `cargo test --workspace`
// invokes it, satisfying BINDING_REGISTRY rule (e).
//
// NO TEXT IS SCANNED ANYWHERE. The only read of the source is
// `syn::parse_file`; every classification is a match on AST node kinds, so
// source formatting, line wrapping and comments are irrelevant by construction
// (R-L RED-5, master 48787cd).

mod accounting_funnel_lock {
    use std::collections::HashMap;
    use syn::visit::{self, Visit};
    use syn::{Expr, ExprMethodCall, ExprReference, ImplItemFn, ItemFn, Local, Pat};

    pub const CELLS: [&str; 6] = [
        "PRIVATE_LIABILITY",
        "ESCROW_BACKING",
        "OPERATIONS_RESERVE",
        "INSURANCE_RESERVE",
        "GOVERNANCE_REWARDS_RESERVE",
        "PENDING_FEE_REIMBURSEMENTS",
    ];

    /// Method names that mutate a `RefCell<T>` when called DIRECTLY on a
    /// resolved cell receiver (no closure to inspect — each of these hands back
    /// the old value or replaces the contents outright: unconditionally a write).
    const DIRECT_WRITE_METHODS: [&str; 5] = ["replace", "replace_with", "set", "take", "swap"];

    /// One finding: a write to `cell`, attributed to the fn that contains it.
    #[derive(Debug, Clone)]
    pub struct Offender {
        pub owner_fn: String,
        pub cell: &'static str,
        pub method: String,
    }

    /// Per-fn local-alias resolution, DEPTH-AWARE (R-L RED-8, master 111154d):
    /// built by a single `Visit` walk over the WHOLE fn body — every `Local`, at
    /// ANY nesting depth, in traversal order. Never crosses a fn boundary; a
    /// local is not visible outside its own fn, so that bound is not an
    /// under-approximation.
    pub struct AliasIndex(HashMap<String, &'static str>);

    impl AliasIndex {
        fn build(body: &syn::Block) -> Self {
            let mut map = HashMap::new();
            let mut collector = LocalCollector { map: &mut map };
            // `visit_block`'s default implementation descends into every nested
            // Expr::Block / Expr::If / Expr::Match arm / loop body / closure body
            // on its own — that is the depth-aware property, not a manual
            // recursion this lock has to get right by hand.
            visit::visit_block(&mut collector, body);
            AliasIndex(map)
        }
    }

    /// Visits every `Local` in a fn body regardless of nesting depth.
    ///
    /// Resolution is TWO-PHASE, not source-order: `AliasIndex::build` runs this
    /// collector to completion first, and `FnVisitor` only ever queries the FINAL
    /// map afterward — so a receiver used textually before its own `let` still
    /// resolves, unlike Rust's own define-before-use local scoping. Shadowing is
    /// last-write-wins IN TRAVERSAL ORDER (a later `Local` for an already-present
    /// identifier overwrites its entry, including across mutually exclusive
    /// `match` arms): over-approximating — at worst the WRONG cell name is
    /// attributed, never no cell at all — and `owner_fn`, the only field the
    /// assertion below consumes, is unaffected either way.
    struct LocalCollector<'m> {
        map: &'m mut HashMap<String, &'static str>,
    }

    impl<'ast> Visit<'ast> for LocalCollector<'_> {
        fn visit_local(&mut self, node: &'ast Local) {
            if let Local { pat: Pat::Ident(pi), init: Some(init), .. } = node {
                if let Some(cell) = resolve_expr(&init.expr, self.map) {
                    self.map.insert(pi.ident.to_string(), cell);
                }
            }
            // Keep descending: a `let` initializer can itself contain nested
            // `let`s (a block expression used as the initializer) — stopping here
            // would reintroduce a depth limit by another name.
            visit::visit_local(self, node);
        }
    }

    /// Resolve a single expression to a cell name.
    ///
    ///   1. direct path — `GOVERNANCE_REWARDS_RESERVE`;
    ///   2. `&STATIC` reference — `&GOVERNANCE_REWARDS_RESERVE`;
    ///   3. transitive local rebind of either — `let a = &CELL; let b = a;`.
    ///
    /// Any other receiver shape (a field access, an index, a call result, an
    /// identifier with no matching `Local`) is conservatively NOT a cell
    /// reference — the one place this design under-approximates, disclosed in the
    /// test's own doc comment rather than silently.
    fn resolve_expr(e: &Expr, aliases: &HashMap<String, &'static str>) -> Option<&'static str> {
        match e {
            Expr::Path(p) => {
                let last = p.path.segments.last()?.ident.to_string();
                if let Some(&c) = CELLS.iter().find(|c| **c == last) {
                    return Some(c);
                }
                aliases.get(&last).copied()
            }
            Expr::Reference(ExprReference { expr, .. }) => resolve_expr(expr, aliases),
            _ => None,
        }
    }

    /// Struct lifetime and AST lifetime kept DISTINCT ('out vs 'ast): `out`
    /// accumulates findings across the whole file; `'ast` borrows the parsed
    /// source for the duration of one `visit_*` call only.
    struct FnVisitor<'out> {
        owner_fn: String,
        aliases: AliasIndex,
        out: &'out mut Vec<Offender>,
    }

    impl<'ast, 'out> Visit<'ast> for FnVisitor<'out> {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            let method = node.method.to_string();
            if matches!(method.as_str(), "with" | "with_borrow_mut" | "with_borrow") {
                if let Some(cell) = resolve_expr(&node.receiver, &self.aliases.0) {
                    // `with_borrow_mut` is ALWAYS a write. `with_borrow` is NEVER
                    // a write. `with` is a write iff the closure body performs a
                    // mutable borrow, an assignment through the closure's own
                    // parameter, or one of the five direct RefCell mutator calls
                    // on that parameter.
                    let is_write =
                        method == "with_borrow_mut" || (method == "with" && closure_body_writes(node));
                    if is_write {
                        self.out.push(Offender {
                            owner_fn: self.owner_fn.clone(),
                            cell,
                            method: method.clone(),
                        });
                    }
                }
            } else if DIRECT_WRITE_METHODS.contains(&method.as_str()) {
                // A direct mutator called ON A RESOLVED CELL RECEIVER with no
                // `.with(...)` closure at all — e.g. `CELL.replace(0)`. Always a
                // write; there is no closure body to classify.
                if let Some(cell) = resolve_expr(&node.receiver, &self.aliases.0) {
                    self.out.push(Offender {
                        owner_fn: self.owner_fn.clone(),
                        cell,
                        method: method.clone(),
                    });
                }
            }
            // Continue INTO the receiver and the closure argument too — R-L
            // RED-8's "the traversal must follow every call form".
            visit::visit_expr_method_call(self, node);
        }
    }

    /// True iff the single closure argument of a `.with(...)` call contains a
    /// `borrow_mut()` call, a plain `Expr::Assign` (`*r = …`) whose left side
    /// derefs the closure's own parameter, OR a call to one of the five
    /// `DIRECT_WRITE_METHODS` on that parameter. Walked via a nested `Visit`,
    /// never a string search.
    ///
    /// This visitor does NOT match a compound assignment (`*v += x`) via
    /// `visit_expr_assign`: under the workspace's pinned syn 2, `ExprAssignOp` is
    /// gone and `*v += x` parses as `Expr::Binary` with `BinOp::AddAssign`, which
    /// `visit_expr_assign` never sees. Not exploitable for these six statics
    /// today — every mutation of a `RefCell<u128>` reached through a `.with`
    /// closure parameter must pass through `borrow_mut`, `replace`,
    /// `replace_with`, `set`, `take` or `swap`, all caught by the method-call arm
    /// — so no compound-assign-only bypass exists. Stated rather than silently
    /// assumed.
    struct ClosureBodyVisitor<'p> {
        param: &'p str,
        found_write: bool,
    }

    impl<'ast> Visit<'ast> for ClosureBodyVisitor<'_> {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            let m = node.method.to_string();
            let receiver_is_param =
                matches!(&*node.receiver, Expr::Path(p) if p.path.is_ident(self.param));
            if receiver_is_param && (m == "borrow_mut" || DIRECT_WRITE_METHODS.contains(&m.as_str()))
            {
                self.found_write = true;
            }
            visit::visit_expr_method_call(self, node);
        }
        fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
            if let Expr::Unary(syn::ExprUnary { op: syn::UnOp::Deref(_), expr, .. }) = &*node.left {
                if matches!(&**expr, Expr::Path(p) if p.path.is_ident(self.param)) {
                    self.found_write = true;
                }
            }
            visit::visit_expr_assign(self, node);
        }
    }

    fn closure_body_writes(call: &ExprMethodCall) -> bool {
        let Some(Expr::Closure(cl)) = call.args.first() else { return false };
        let Some(Pat::Ident(pi)) = cl.inputs.first() else { return false };
        let param = pi.ident.to_string();
        let mut v = ClosureBodyVisitor { param: &param, found_write: false };
        v.visit_expr(&cl.body);
        v.found_write
    }

    /// Collects every free fn and every impl-method in the file, at any module
    /// depth, and runs the writer analysis over each body independently.
    struct FileVisitor {
        out: Vec<Offender>,
    }

    impl<'ast> Visit<'ast> for FileVisitor {
        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            self.scan(node.sig.ident.to_string(), &node.block);
            visit::visit_item_fn(self, node);
        }
        fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
            self.scan(node.sig.ident.to_string(), &node.block);
            visit::visit_impl_item_fn(self, node);
        }
    }

    impl FileVisitor {
        fn scan(&mut self, name: String, body: &syn::Block) {
            let aliases = AliasIndex::build(body);
            let mut out = Vec::new();
            let mut fv = FnVisitor { owner_fn: name, aliases, out: &mut out };
            visit::visit_block(&mut fv, body);
            self.out.extend(out);
        }
    }

    /// Parse `src` and return every accounting-cell write it contains,
    /// attributed to its owning fn.
    pub fn offenders(src: &str) -> Vec<Offender> {
        let file = syn::parse_file(src).expect("shielded-pool lib.rs must parse as Rust");
        let mut fv = FileVisitor { out: Vec::new() };
        fv.visit_file(&file);
        fv.out
    }
}

fn pool_lib_rs_path() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is `<workspace>/integration-tests`.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests has a parent (the workspace root)")
        .join("canisters/shielded-pool/src/lib.rs")
}

/// AC-1 — the writer set for the six accounting cells is EXACTLY the funnel.
///
/// `post_upgrade` needs no exemption: its restore calls `commit_pool_accounting`
/// directly and contains no `.with`/`.with_borrow`/`.with_borrow_mut`/direct
/// mutator call on any of the six cells, so it contributes zero offenders
/// without any name-based carve-out.
///
/// DISCLOSED GAPS (all safe-direction — they can only cause a real write to go
/// unreported, never flag a non-write): an indirect accessor fn returning
/// `&'static RefCell<u128>` (the receiver is an `Expr::Call`, unresolvable by
/// design); a write inside a `macro_rules!` definition or invocation (`syn::visit`
/// does not walk macro bodies); a `.with(...)` whose single argument is not an
/// `Expr::Closure` (a function passed by name); a closure whose first parameter
/// is not a bare `Pat::Ident` (`|&r|`, a tuple pattern). None of these shapes
/// exists anywhere in the pool today.
#[test]
fn r13_accounting_cell_writer_set_is_the_funnel_only() {
    let path = pool_lib_rs_path();
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let offenders = accounting_funnel_lock::offenders(&src);

    let writer_fns: std::collections::BTreeSet<&str> =
        offenders.iter().map(|o| o.owner_fn.as_str()).collect();

    assert_eq!(
        writer_fns,
        std::collections::BTreeSet::from(["commit_pool_accounting"]),
        "R-13 lock: every write to one of the six accounting cells outside \
         commit_pool_accounting is a divergence risk (the heap moves, the stable \
         cell does not, and the figure is lost on upgrade). Offending fns: {:?}\n\
         Detail: {:#?}",
        writer_fns,
        offenders
    );

    // Non-vacuity: the visitor must actually be finding the funnel's own six
    // writes, not returning an empty set for a reason unrelated to the property.
    assert_eq!(
        offenders.len(),
        6,
        "commit_pool_accounting writes all six cells exactly once; a different \
         count means the visitor is not resolving what it is claimed to resolve. \
         Detail: {:#?}",
        offenders
    );
}
