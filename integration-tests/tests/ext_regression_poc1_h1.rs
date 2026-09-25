// =============================================================================
// EXT REGRESSION PROOF — PoC-1 (H-1, EXT-1): pool deposit upgrade-safety
// =============================================================================
//
// GTM Step 1 regression proof. Test-only; zero production/DID/circuit/VK diff.
// Proves the H-1 (EXT-1) pre-await deposit freeze reproduces RED at the pre-fix
// parent `7f817a9` and is closed GREEN at current master.
//
// Construction — SSA-mandated (DISPATCH_SIGNOFF_2 §8), deterministic, PURE PUBLIC
// INGRESS (no inject_* endpoints — they don't exist at the parent, and the
// production Pool Wasm is installed at BOTH anchors so no two-phase build):
//
//   1. Stop the Merkle canister.
//   2. Real `shield_deposit` (approve + shield). The token transfer_from lands
//      (funds pulled) BEFORE the Merkle append, which then fails on the stopped
//      Merkle. Merkle unavailability CREATES the wedge.
//   3. Durable status after the failed append:
//        parent  → CommitmentAppendUnknown + expected_leaf_index=None (unrescuable)
//        fixed   → TransferConfirmedCommitmentPending (append never issued; retryable)
//      Same trigger, different terminal status — that asymmetry IS the fix.
//   4. Real production Pool `upgrade_canister` — proves the wedge's DURABLE
//      PERSISTENCE across an upgrade (H-1's upgrade-safety dimension). The upgrade
//      does NOT create the wedge; step 2 did.
//   5. Restart the Merkle canister.
//   6. parent: both retry_deposit_commitment AND reconcile_deposit_append_unknown
//      stay blocked; the accounting gap (funds pulled, no credit) persists.
//   7. fixed: retry credits EXACTLY ONCE; a second retry cannot credit again;
//      the final accounting identity == the real pool ledger balance.
//
// The hard assertions encode the FIXED (green) behavior; at the parent they fail
// (valid RED). Every step is printed first, so the parent's full wedge behavior
// is captured in the console even though the run fails.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loaders (production only — no POOL_TEST_WASM) ────────────────────────
fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_prod_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0] = 1,000 STSH (A6.6)
const DEFAULT_FEE: u128 = 0;

// ── Token candid mirrors ──────────────────────────────────────────────────────
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

// ── Pool candid mirrors ───────────────────────────────────────────────────────
#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister: Principal, nullifier_canister: Principal, merkle_canister: Principal,
    treasury_canister: Principal, staking_canister: Principal, controller: Principal,
    initial_vk_hash: [u8; 32], initial_proof_system: String,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs { note_commitment: [u8; 32], encrypted_payload: Vec<u8>, public_amount: u128 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositStatus {
    CommitmentPending, TransferPending, TransferConfirmedCommitmentPending,
    CommitmentAppendInFlight, CommitmentAppended { leaf_index: u64 }, CommitmentAppendUnknown,
    CommitmentReconcileInFlight, CommitmentRootAccepted { leaf_index: u64, root: [u8; 32] },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingDeposit {
    note_commitment: [u8; 32], private_balance: u128, ops_amount: u128, insurance_amount: u128,
    encrypted_payload: Vec<u8>, depositor: Option<Principal>, status: DepositStatus, created_at_ns: u64,
    expected_leaf_index: Option<u64>, finalized_at_ns: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AccountingState {
    private_liability: u128, escrow_backing: u128, operations_reserve: u128,
    insurance_reserve: u128, governance_rewards_reserve: u128, pending_fee_reimbursements: u128,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum DepositAppendReconcileResult { Finalized, RevertedRetryable }
// Superset PoolError mirror — candid decodes by variant name; extra arms are fine.
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

/// Deploy the full deposit topology on the PRODUCTION Pool Wasm (public ingress only).
fn deploy_stack_prod(pic: &PocketIc) -> Stack {
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
    install(pic, pool, pool_prod_wasm(), &PoolInitArgs {
        token_canister: token, nullifier_canister: null, merkle_canister: merkle,
        treasury_canister: p(0x01), staking_canister: p(0x02), controller,
        initial_vk_hash: [0u8; 32], initial_proof_system: "groth16-bn254".to_string(),
    });
    pic.update_call(pool, controller, "set_verifier_canister",
        candid::encode_args((verifier, vec![0u8; 32])).unwrap()).expect("set_verifier_canister");
    Stack { pool, token, merkle, controller, user }
}

fn commitment(tag: u8) -> [u8; 32] { let mut c = [0u8; 32]; c[0] = tag; c[1] = 0xDE; c }

fn token_balance(pic: &PocketIc, s: &Stack, owner: Principal) -> u128 {
    let n: Nat = decode("icrc1_balance_of", pic.query_call(s.token, anon(), "icrc1_balance_of",
        candid::encode_one(Account { owner, subaccount: None }).unwrap()));
    n.0.try_into().unwrap()
}
fn approve_pool(pic: &PocketIc, s: &Stack, amount: u128) {
    let r: Result<Nat, ApproveErr> = decode("icrc2_approve", pic.update_call(s.token, s.user, "icrc2_approve",
        candid::encode_one(ApproveArgs {
            from_subaccount: None, spender: Account { owner: s.pool, subaccount: None }, amount,
            // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
            // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
            // exercise expiry, so the value only has to be present and in range.
            expected_allowance: None, expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000), fee: None, memo: None, created_at_time: None,
        }).unwrap()));
    assert!(r.is_ok(), "icrc2_approve must succeed; got {:?}", r);
}
fn shield_deposit(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<Nat, PoolError> {
    decode("shield_deposit", pic.update_call(s.pool, s.user, "shield_deposit",
        candid::encode_one(ShieldDepositArgs { note_commitment: c, encrypted_payload: vec![], public_amount: DENOM }).unwrap()))
}
fn deposit_status(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Option<PendingDeposit> {
    // get_deposit_status is originator+controller-gated (DEF-070) — query as controller.
    decode("get_deposit_status", pic.query_call(s.pool, s.controller, "get_deposit_status", candid::encode_one(c).unwrap()))
}
fn retry(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<Nat, PoolError> {
    decode("retry_deposit_commitment", pic.update_call(s.pool, s.user, "retry_deposit_commitment", candid::encode_one(c).unwrap()))
}
fn reconcile(pic: &PocketIc, s: &Stack, c: [u8; 32]) -> Result<DepositAppendReconcileResult, PoolError> {
    decode("reconcile_deposit_append_unknown", pic.update_call(s.pool, s.controller,
        "reconcile_deposit_append_unknown", candid::encode_one(c).unwrap()))
}
fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    // get_accounting_state is controller-gated (DEF-076) — query as controller.
    decode("get_accounting_state", pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()))
}
fn bucket_sum(a: &AccountingState) -> u128 {
    a.escrow_backing + a.operations_reserve + a.insurance_reserve + a.governance_rewards_reserve
}
fn upgrade_pool_prod(pic: &PocketIc, s: &Stack) -> Result<(), String> {
    pic.upgrade_canister(s.pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

// =============================================================================
// PoC-1 — H-1 deposit upgrade-safety regression proof.
//   GREEN (current master): PASSES.
//   RED   (parent 7f817a9): FAILS at the final recovery/accounting assertion
//   (the deposit is wedged at CommitmentAppendUnknown+None and can never credit).
// =============================================================================
#[test]
fn poc1_h1_unreachable_merkle_deposit_wedge() {
    let pic = PocketIc::new();
    let s = deploy_stack_prod(&pic);
    let c = commitment(0xE1);

    let user_before = token_balance(&pic, &s, s.user);
    let acct_before = accounting(&pic, &s);
    println!("[PoC-1] user balance before = {}", user_before);
    println!("[PoC-1] accounting bucket-sum before = {}", bucket_sum(&acct_before));

    // (1) Stop Merkle — the append target is now unreachable.
    pic.stop_canister(s.merkle, None).expect("stop merkle");

    // (2) Real shield_deposit: approve then deposit. transfer_from lands (funds
    //     pulled); the Merkle append then fails on the stopped canister.
    approve_pool(&pic, &s, DENOM + DEFAULT_FEE);
    let dep = shield_deposit(&pic, &s, c);
    println!("[PoC-1] shield_deposit returned = {:?}", dep);

    // Funds pulled regardless of the append outcome (transfer precedes append).
    let user_after_deposit = token_balance(&pic, &s, s.user);
    let pool_ledger = token_balance(&pic, &s, s.pool);
    println!("[PoC-1] user balance after deposit = {} (delta {})", user_after_deposit, user_before - user_after_deposit);
    println!("[PoC-1] pool LEDGER balance = {}", pool_ledger);
    assert_eq!(user_before - user_after_deposit, DENOM, "the token transfer must have landed (funds pulled)");
    assert_eq!(pool_ledger, DENOM, "pool holds the pulled funds");

    // (3) Durable status. parent → CommitmentAppendUnknown + None (unrescuable);
    //     fixed → TransferConfirmedCommitmentPending (append never issued).
    let st3 = deposit_status(&pic, &s, c);
    println!("[PoC-1] STEP-3 durable status = {:?}", st3);

    // (4) Real production Pool upgrade — proves durable persistence of the state
    //     across an upgrade (the wedge was created by Merkle unavailability in
    //     step 2, NOT by this upgrade).
    let up = upgrade_pool_prod(&pic, &s);
    println!("[PoC-1] STEP-4 production pool upgrade result = {:?}", up);
    assert!(up.is_ok(), "the production pool upgrade must not trap for this state; got {:?}", up);
    let st4 = deposit_status(&pic, &s, c);
    println!("[PoC-1] post-upgrade durable status = {:?}", st4);

    // (5) Restart Merkle — the append target is reachable again.
    pic.start_canister(s.merkle, None).expect("restart merkle");

    // (6)/(7) Attempt BOTH recovery paths, printing each. GREEN: retry credits
    //     once. parent: retry + reconcile both blocked (wedge persists).
    let retry_r = retry(&pic, &s, c);
    println!("[PoC-1] STEP-6/7 retry_deposit_commitment = {:?}", retry_r);
    let reconcile_r = reconcile(&pic, &s, c);
    println!("[PoC-1] STEP-6/7 reconcile_deposit_append_unknown = {:?}", reconcile_r);

    let acct_after = accounting(&pic, &s);
    let pool_ledger_final = token_balance(&pic, &s, s.pool);
    let sum_after = bucket_sum(&acct_after);
    let st_final = deposit_status(&pic, &s, c).map(|d| d.status);
    println!("[PoC-1] final status = {:?}", st_final);
    println!("[PoC-1] final accounting bucket-sum = {}  (escrow={}, ops={}, ins={}, gov={})",
        sum_after, acct_after.escrow_backing, acct_after.operations_reserve,
        acct_after.insurance_reserve, acct_after.governance_rewards_reserve);
    println!("[PoC-1] final pool LEDGER balance = {}", pool_ledger_final);

    // ── FINAL SECURITY ASSERTIONS (the FIXED behavior) ────────────────────────
    // At the parent these fail: retry stays blocked, no credit is ever applied,
    // and the accounting identity stays violated (bucket-sum 0 ≠ ledger DENOM).
    assert_eq!(retry_r, Ok(Nat::from(DENOM)),
        "GREEN: the deposit must recover exactly once via retry_deposit_commitment (parent: BLOCKED)");
    // P-ROOT: recovery now finalizes through the accepted-root head to the
    // terminal CommitmentRootAccepted (was CommitmentAppended pre-P-ROOT).
    assert!(matches!(st_final, Some(DepositStatus::CommitmentRootAccepted { leaf_index: 0, .. })),
        "GREEN: the deposit reaches CommitmentRootAccepted after recovery (parent: stuck at CommitmentAppendUnknown); got {:?}", st_final);
    assert_eq!(sum_after, pool_ledger_final,
        "GREEN: accounting identity (bucket-sum) == real pool ledger balance (parent: gap persists)");
    assert_eq!(sum_after, acct_before_sum(&acct_before) + DENOM,
        "GREEN: exactly DENOM credited across the whole flow");

    // No double credit: a second retry MUST NOT credit again (retry is idempotent —
    // it may return Ok, but the credited amount must not change).
    let retry2 = retry(&pic, &s, c);
    println!("[PoC-1] second retry (idempotent; must not double-credit) = {:?}", retry2);
    let sum_after2 = bucket_sum(&accounting(&pic, &s));
    println!("[PoC-1] bucket-sum after redundant retry = {}", sum_after2);
    assert_eq!(sum_after2, sum_after, "GREEN: bucket-sum unchanged after the redundant retry (NO double credit)");
}

fn acct_before_sum(a: &AccountingState) -> u128 { bucket_sum(a) }
