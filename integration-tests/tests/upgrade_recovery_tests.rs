// =============================================================================
// STSH — Upgrade recovery tests (PocketIC)
// Pass 4 remediation: QA-DEF-029 (INFLIGHT_NULLIFIERS upgrade reconstruction)
// =============================================================================
//
// INFLIGHT_NULLIFIERS is heap-only and cleared on upgrade. post_upgrade rebuilds
// it from PENDING_SPENDS for statuses where a nullifier is claimed locally but not
// yet permanently in the registry (NullifierReserved, OutputsCommitted,
// NullifierInsertUnknown). It must NOT reconstruct from VerificationPending
// (pre-proof) or terminal/registry-protected statuses (Finalized, PayoutPending,
// FailedAfterOutputsCommitted, ...).
//
// ── ADVERSARIAL SELF-TRACE (charter Item 5) ──────────────────────────────────
//   1. Spend A reaches NullifierReserved; the canister is upgraded.
//   2. New post_upgrade reconstructs A's nullifier into INFLIGHT_NULLIFIERS.
//   3. Spend B (same nullifier, new spend_id) reaches commit step 15-pre and finds
//      A's nullifier already reserved → rejected with NullifierReserved (test_t1/t2).
//   VerificationPending variant:
//   1. Spend C is VerificationPending (pre-proof); canister upgraded.
//   2. post_upgrade does NOT reconstruct from VerificationPending.
//   3. Spend D (same nullifier) passes the heap check and proceeds (test_t3) — safe,
//      because the nullifier is derived from the note secret, so any genuine
//      double-spend of the same note is still caught at insert_batch in the registry.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): build shielded_pool with
// --features testing, copy to shielded_pool_test.wasm, then build the production
// wasms + stsh-stub-verifier. POCKET_IC_BIN must be set. The pool is UPGRADED with
// the testing wasm so inflight_count_for_test / inject_* remain available.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;
const DENOM_1: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0] = 1,000 STSH (A6.6)
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch

// ── Token mirrors ───────────────────────────────────────────────────────────
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
fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
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

// ── Pool mirrors ────────────────────────────────────────────────────────────
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
enum SpendStatus {
    Requested, OutputsStaged, Finalized,
    FailedBeforeStateChange { reason: String }, FailedAfterOutputsStaged { reason: String },
    VerificationPending, NullifierReserved, PayoutPending { reason: String },
    PayoutSubmitting, PayoutUnknown { reason: String }, NullifierInsertUnknown { reason: String },
    // A2 (QA-DEF-034/036)
    NullifierFinalizedOutputsPending, ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String }, ActiveAppendRejected { reason: String },
    ActiveRootPending, RootAccepted,
}
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
    PayoutNotPending, PayoutOutcomeUnknown, SpendNotFound, WrongSpendStatus,
    DisbursementNotFound, DisbursementNotReconcilable,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
}

// ── Helpers ─────────────────────────────────────────────────────────────────
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
    install(pic, token, token_wasm(), &all_to(user, p(0x02)));
    install(pic, pool, pool_test_wasm(), &PoolInitArgs {
        token_canister: token, nullifier_canister: null, merkle_canister: merkle,
        treasury_canister: p(0x01), staking_canister: p(0x02), controller,
        initial_vk_hash: [0u8; 32], initial_proof_system: "groth16-bn254".to_string(),
    });
    pic.update_call(pool, controller, "set_verifier_canister", candid::encode_args((verifier, vec![0u8; 32])).unwrap())
        .expect("set_verifier_canister");
    Stack { pool, token, merkle, controller, user }
}

/// Fund the pool with a 1,000 STSH deposit (DENOMINATIONS[0], A6.6) so the Merkle tree has a real anchor for
/// subsequent private_spend attempts.
fn fund_and_anchor(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    let _: Result<Nat, ApproveErr> = decode("approve", pic.update_call(s.token, s.user, "icrc2_approve",
        candid::encode_one(ApproveArgs {
            from_subaccount: None, spender: Account { owner: s.pool, subaccount: None },
            // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
            // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
            // exercise expiry, so the value only has to be present and in range.
            amount: DENOM_1 + DEFAULT_FEE, expected_allowance: None, expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000), fee: None, memo: None, created_at_time: None,
        }).unwrap()));
    let mut c = [0u8; 32]; c[0] = 0xDE; c[31] = 0x01;
    let dep: Result<Nat, PoolError> = decode("shield_deposit", pic.update_call(s.pool, s.user, "shield_deposit",
        candid::encode_one(ShieldDepositArgs { note_commitment: c, encrypted_payload: vec![], public_amount: DENOM_1 }).unwrap()));
    assert!(dep.is_ok(), "fund deposit must succeed; got {:?}", dep);
    let v: Vec<u8> = decode("get_root", pic.query_call(s.merkle, anon(), "get_root", candid::encode_args(()).unwrap()));
    let mut r = [0u8; 32]; r.copy_from_slice(&v); r
}

fn inject_spend(pic: &PocketIc, s: &Stack, spend_id: u64, nullifiers: Vec<[u8; 32]>, status: SpendStatus) {
    let _: () = decode("inject_spend_with_nullifiers_for_test", pic.update_call(s.pool, s.controller,
        "inject_spend_with_nullifiers_for_test", candid::encode_args((spend_id, nullifiers, status)).unwrap()));
}
fn inflight_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode("inflight_count_for_test", pic.query_call(s.pool, s.controller, "inflight_count_for_test", candid::encode_args(()).unwrap()))
}
fn upgrade_pool(pic: &PocketIc, s: &Stack) {
    pic.upgrade_canister(s.pool, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade (pre/post_upgrade) must succeed");
}
fn leaf_count(pic: &PocketIc, s: &Stack) -> u64 {
    decode("leaf_count", pic.query_call(s.merkle, anon(), "leaf_count", candid::encode_args(()).unwrap()))
}

/// A canonical BN254 Fr nullifier (small values are canonical). Distinct per `tag`.
fn nf(tag: u8) -> [u8; 32] { let mut n = [0u8; 32]; n[0] = tag; n[1] = 0x2F; n }

/// Run a real no-payout private_spend with the given nullifier (stub verifier).
fn run_spend(pic: &PocketIc, s: &Stack, root: [u8; 32], spend_id: u64, nullifier: [u8; 32]) -> Result<(), PoolError> {
    // Output commitments must be canonical BN254 Fr (little-endian) — set only the
    // low byte so the value is small and below the field modulus.
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

// ─────────────────────────────────────────────────────────────────────────────
// test_t1 — NullifierReserved is reconstructed; same-nullifier spend is blocked
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_post_upgrade_reconstructs_inflight_nullifiers_for_nullifier_reserved() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = fund_and_anchor(&pic, &s);
    let nullifier = nf(0xA1);

    inject_spend(&pic, &s, 800, vec![nullifier], SpendStatus::NullifierReserved);
    upgrade_pool(&pic, &s);

    assert_eq!(inflight_count(&pic, &s), 1, "NullifierReserved nullifier must be reconstructed into INFLIGHT");

    // Behavioral: a fresh spend with the same nullifier is rejected at step 15-pre.
    let r = run_spend(&pic, &s, root, 900, nullifier);
    assert_eq!(r, Err(PoolError::NullifierReserved), "same-nullifier spend must be blocked post-upgrade; got {:?}", r);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t2 — OutputsCommitted is reconstructed; same-nullifier spend is blocked
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_post_upgrade_blocks_same_nullifier_when_outputs_committed() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = fund_and_anchor(&pic, &s);
    let nullifier = nf(0xB2);

    inject_spend(&pic, &s, 801, vec![nullifier], SpendStatus::OutputsStaged);
    upgrade_pool(&pic, &s);

    assert_eq!(inflight_count(&pic, &s), 1, "OutputsStaged nullifier must be reconstructed");
    let r = run_spend(&pic, &s, root, 901, nullifier);
    assert_eq!(r, Err(PoolError::NullifierReserved), "same-nullifier spend must be blocked; got {:?}", r);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t3 — VerificationPending is NOT reconstructed; spend proceeds (not locked)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_post_upgrade_does_not_reconstruct_from_verification_pending() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let root = fund_and_anchor(&pic, &s);
    let nullifier = nf(0xC3);

    inject_spend(&pic, &s, 802, vec![nullifier], SpendStatus::VerificationPending);
    upgrade_pool(&pic, &s);

    assert_eq!(inflight_count(&pic, &s), 0, "VerificationPending must NOT be reconstructed");
    // Behavioral: a spend with that nullifier is NOT blocked on heap grounds — it
    // proceeds and completes via the stub verifier (the registry would catch any
    // genuine double-spend, but here the note was never actually spent).
    let r = run_spend(&pic, &s, root, 902, nullifier);
    assert!(r.is_ok(), "spend must proceed (not heap-blocked) after VerificationPending exclusion; got {:?}", r);
    assert_ne!(r, Err(PoolError::NullifierReserved), "must not be rejected on heap grounds");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t4 — Finalized is NOT reconstructed (registry already protects it)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_post_upgrade_does_not_reconstruct_from_finalized() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let _ = fund_and_anchor(&pic, &s);
    inject_spend(&pic, &s, 803, vec![nf(0xD4)], SpendStatus::Finalized);
    upgrade_pool(&pic, &s);
    assert_eq!(inflight_count(&pic, &s), 0, "Finalized must NOT be reconstructed (registry is the source of truth)");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_t5 — reconstruction is O(n) and bounded; canister responds immediately
// ─────────────────────────────────────────────────────────────────────────────
//
// Reconstruction is a single O(n) pass over PENDING_SPENDS in post_upgrade (each
// spend's nullifier vec is tiny). Practical ceiling: the number of non-terminal
// pending spends (interrupted mid-flight), expected small; prune on finalization
// if that ever grows large.
#[test]
fn test_upgrade_reconstruction_scale_bound() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let _ = fund_and_anchor(&pic, &s);

    const N: u64 = 100;
    for i in 0..N {
        inject_spend(&pic, &s, 1000 + i, vec![nf(i as u8)], SpendStatus::OutputsStaged);
    }
    upgrade_pool(&pic, &s);

    // Canister responds to a query immediately post-upgrade (did not trap/time out).
    let _ = leaf_count(&pic, &s);
    assert_eq!(inflight_count(&pic, &s), N, "all {} non-terminal nullifiers reconstructed", N);
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-058 — post_upgrade INFLIGHT reconstruction match is EXHAUSTIVE
// ─────────────────────────────────────────────────────────────────────────────
//
// rebuild_inflight_nullifiers (called by post_upgrade) previously ended in a
// `_ => {}` catch-all. DEF-058 replaced it with an exhaustive SpendStatus match so
// that a FUTURE variant added without classifying it here fails to compile rather
// than being silently dropped from reconstruction (an upgrade-time double-spend
// window). Exhaustiveness itself is enforced by the compiler — reverting to a
// wildcard would not change today's runtime behaviour — so this test is a
// behavioural REGRESSION GUARD on the classification: it pins exactly which
// statuses are reconstructed (INCLUDE) versus skipped (EXCLUDE) across one upgrade.
// If a future change miscategorises a variant (e.g. moves an INCLUDE status under
// the EXCLUDE arm), the inflight_count assertion below fails.
#[test]
fn test_post_upgrade_match_exhaustive_def058() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    let _ = fund_and_anchor(&pic, &s);

    // INCLUDE — nullifier claimed locally, not yet permanently in the registry.
    inject_spend(&pic, &s, 1200, vec![nf(0xE1)], SpendStatus::NullifierReserved);
    inject_spend(&pic, &s, 1201, vec![nf(0xE2)], SpendStatus::OutputsStaged);
    inject_spend(&pic, &s, 1202, vec![nf(0xE3)],
        SpendStatus::NullifierInsertUnknown { reason: "transport".to_string() });

    // EXCLUDE — pre-reservation (no nullifier claimed).
    inject_spend(&pic, &s, 1203, vec![nf(0xE4)], SpendStatus::Requested);
    inject_spend(&pic, &s, 1204, vec![nf(0xE5)], SpendStatus::VerificationPending);
    // EXCLUDE — registry already holds the nullifier (insert_batch succeeded).
    inject_spend(&pic, &s, 1205, vec![nf(0xE6)], SpendStatus::NullifierFinalizedOutputsPending);
    inject_spend(&pic, &s, 1206, vec![nf(0xE7)], SpendStatus::RootAccepted);
    inject_spend(&pic, &s, 1207, vec![nf(0xE8)],
        SpendStatus::PayoutPending { reason: "owed".to_string() });
    // EXCLUDE — terminal (also short-circuited by is_terminal_spend_status).
    inject_spend(&pic, &s, 1208, vec![nf(0xE9)], SpendStatus::Finalized);

    upgrade_pool(&pic, &s);

    // Exactly the three INCLUDE statuses contribute their (distinct) nullifiers.
    assert_eq!(
        inflight_count(&pic, &s), 3,
        "exactly NullifierReserved + OutputsStaged + NullifierInsertUnknown must be reconstructed"
    );
    // Canister answered a query post-upgrade — post_upgrade did not trap.
    let _ = leaf_count(&pic, &s);
}
