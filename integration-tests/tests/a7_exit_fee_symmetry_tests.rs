// =============================================================================
// STSH — A-7: exit-fee symmetry (PocketIC)
// Automated remediation campaign wave 2, lane A-7.
// =============================================================================
//
// The live exit (`private_spend` carrying a `public_payout`) used to charge the
// flat protocol private-spend fee, while the 25-bps unshield value fee that the
// fee-policy crate already implements sat stranded on the dead `withdraw` path.
// This lane routes the exit through `unshield_protocol_fee`, so the model is
// `max(flat_minimum, 0.25%)` in BOTH directions
// (OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21).
//
//   T1  an exit ABOVE the crossover pays the value fee; carrying the old flat
//       fee is rejected with `PrivateSpendFeeMismatch { expected, got }`
//   T2  a shielded->shielded spend (`public_payout == None`) is UNCHANGED
//   T3  both preview sites agree: the accepted exit runs through the
//       post-verification recheck (step 14c) and settles, so an exit cannot
//       pass entry and die after the expensive half of the spend
//   T6a the CANISTER's own answer, obtained BY CALL across both arms of the
//       `max()` and the crossover +/-1 e8s, checked against the shared fixture
//       the wallet mirror is also checked against
//
// THE TRAP every test here clears: at `launch_defaults` every value-fee field is
// ZERO, so the new formula and the old one both return 0 and a bite test written
// at launch defaults passes on a broken implementation. Every test below first
// installs NONZERO parameters through the testing-only setter and states which.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   ./run_gate.sh   (canonical; it does both phases and both suites)
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ─────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

// ── The shipped numbers (transcribed literals, never imported from the crate
//    under test — a check that reads the constant it checks cannot fail) ──────

const E8S: u128 = 100_000_000;
/// RULED 2026-09-08 (OWNER_RULING_FEE_FLOOR_2_5_STSH, A6.6/R-14): 2.5 STSH flat
/// minimum, both directions — superseding the 0.1 STSH of 2026-08-21.
const FLAT_MIN: u128 = 5 * E8S / 2;
/// RULED: 25 bps both directions.
const BPS: u16 = 25;
/// The flat protocol private-spend fee at launch: 2.5 STSH (same ruling).
const SPEND_FEE: u128 = 5 * E8S / 2;
/// `flat_min == amount * bps / 10_000` exactly here: 2.5 STSH == 0.25% of 1,000
/// STSH. A6.6 lands the crossover exactly ON the ladder's floor rung, so the flat
/// minimum binds only BELOW the ladder and the bps arm governs every rung.
const CROSSOVER: u128 = 1_000 * E8S;
const COOLDOWN_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const TOTAL_SUPPLY: u128 = 1_000_000_000 * E8S;
const DENOMINATIONS: [u128; 5] =
    // A6.6 five-tier launch ladder — mirrors the pool's own DENOMINATIONS.
    [1_000 * E8S, 10_000 * E8S, 100_000 * E8S, 1_000_000 * E8S, 10_000_000 * E8S];
const DEFAULT_LEDGER_FEE: u128 = 10_000;

/// The model, computed independently of the canister and of the wallet.
fn expected_exit_fee(public_amount: u128) -> u128 {
    let by_bps = public_amount * (BPS as u128) / 10_000;
    if by_bps > FLAT_MIN { by_bps } else { FLAT_MIN }
}

// ── Token mirrors ────────────────────────────────────────────────────────────

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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
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

// ── Pool mirrors ─────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
    verifier_canister: Option<Principal>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
    expected_deployment_config_hash: Option<[u8; 32]>,
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
    expected_deployment_config_hash: Option<[u8; 32]>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode { FixedStsh, XdrPegged }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceFeeParams {
    protocol_shielding_fee_stsh: u128,
    protocol_unshielding_fee_stsh: u128,
    protocol_private_spend_fee_stsh: u128,
    minimum_withdrawal_gross: u128,
    minimum_recipient_amount: u128,
    minimum_private_credit: u128,
    fee_reference_price_stsh_per_icp_e8s: u128,
    fee_safety_margin_bps: u32,
    max_fee_change_bps_per_update: u32,
    fee_update_cooldown_ns: u64,
    operations_split_bps: u32,
    insurance_split_bps: u32,
    staking_rewards_split_bps: u32,
    staking_rewards_enabled: bool,
    minimum_treasury_runway_months: u32,
    target_treasury_runway_months: u32,
    shield_fee_bps: Option<u16>,
    unshield_fee_bps: Option<u16>,
    shield_flat_minimum_fee_e8s: Option<u128>,
    unshield_flat_minimum_fee_e8s: Option<u128>,
    spend_fee_mode: Option<SpendFeeMode>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
}

/// NONZERO value-fee parameters — the shipped launch configuration. Written out
/// rather than derived, so this fixture cannot silently follow a constant.
fn nonzero_launch_params() -> GovernanceFeeParams {
    GovernanceFeeParams {
        protocol_shielding_fee_stsh: 0,
        protocol_unshielding_fee_stsh: 0,
        protocol_private_spend_fee_stsh: SPEND_FEE,
        minimum_withdrawal_gross: 0,
        minimum_recipient_amount: 0,
        minimum_private_credit: 0,
        fee_reference_price_stsh_per_icp_e8s: 0,
        fee_safety_margin_bps: 12_500,
        max_fee_change_bps_per_update: 1_000,
        fee_update_cooldown_ns: COOLDOWN_NS,
        operations_split_bps: 8_500,
        insurance_split_bps: 1_500,
        staking_rewards_split_bps: 0,
        staking_rewards_enabled: false,
        minimum_treasury_runway_months: 6,
        target_treasury_runway_months: 12,
        shield_fee_bps: Some(BPS),
        unshield_fee_bps: Some(BPS),
        shield_flat_minimum_fee_e8s: Some(FLAT_MIN),
        unshield_flat_minimum_fee_e8s: Some(FLAT_MIN),
        spend_fee_mode: Some(SpendFeeMode::FixedStsh),
        fee_model_version: Some(1),
        params_epoch: None,
    }
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
    ProofSystemMismatch,
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

// ── Harness ──────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

/// A canonical BN254 Fr element: the tag in the low byte, zeros above. Filling
/// all 32 bytes with a tag byte produces a value >= the field modulus, which the
/// pool rejects as `NonCanonicalSignal` long before any fee question.
fn fe(tag: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = tag;
    b
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 20_000_000_000_000u128);
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
    controller: Principal,
    user: Principal,
    recipient: Principal,
}

const VK_HASH: [u8; 32] = [0x7Au8; 32];

/// Deploys the stack with the STUB verifier (accepts any proof, so the spend
/// path itself is exercised) and installs the NONZERO value-fee parameters.
fn deploy(pic: &PocketIc) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let recipient = p(0xBB);

    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);
    let verifier = create_canister(pic);

    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    pic.install_canister(
        verifier,
        stub_verifier_wasm(),
        candid::encode_one(Some(VK_HASH)).unwrap(),
        None,
    );
    install(pic, token, token_wasm(), &TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: user,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
    });
    install(pic, pool, pool_test_wasm(), &PoolInitArgs {
        token_canister: token,
        nullifier_canister: null,
        merkle_canister: merkle,
        treasury_canister: p(0x04),
        staking_canister: p(0x02),
        controller,
        initial_vk_hash: VK_HASH,
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: None,
    });
    pic.update_call(
        pool,
        controller,
        "set_verifier_canister",
        candid::encode_args((verifier, VK_HASH.to_vec())).unwrap(),
    )
    .expect("set_verifier_canister must succeed");

    // NONZERO params — without this every assertion below would hold on a
    // broken implementation, because launch defaults zero the value fee.
    let set: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        pic.update_call(
            pool,
            controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(nonzero_launch_params()).unwrap(),
        ),
    );
    set.expect("nonzero fee params must install");

    Stack { pool, token, merkle, controller, user, recipient }
}

fn approve(pic: &PocketIc, s: &Stack, amount: u128) {
    let r: Result<Nat, ApproveError> = decode(
        "icrc2_approve",
        pic.update_call(
            s.token,
            s.user,
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
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
    r.expect("approve must succeed");
}

/// Deposits one note of `denomination` and returns the merkle root afterwards.
///
/// The allowance is `denomination + shield fee + ledger fee`: the shield side
/// charges `max(flat_minimum, bps)` FEE-ON-TOP, and at these nonzero parameters
/// that is not zero. (Before this lane's floor change it would have been 1,000
/// STSH on every deposit, whatever the size.)
fn deposit(pic: &PocketIc, s: &Stack, denomination: u128, commitment: [u8; 32]) -> [u8; 32] {
    approve(pic, s, denomination + expected_exit_fee(denomination) + DEFAULT_LEDGER_FEE);
    let dep: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: commitment,
                encrypted_payload: vec![],
                public_amount: denomination,
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    );
    dep.unwrap_or_else(|e| panic!("shield_deposit({denomination}) failed: {e:?}"));
    merkle_root(pic, s)
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

fn accounting_state(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode(
        "get_accounting_state",
        pic.query_call(s.pool, s.controller, "get_accounting_state", candid::encode_args(()).unwrap()),
    )
}

fn balance(pic: &PocketIc, s: &Stack, owner: Principal) -> u128 {
    let bal: Nat = decode(
        "icrc1_balance_of",
        pic.query_call(
            s.token,
            owner,
            "icrc1_balance_of",
            candid::encode_one(Account { owner, subaccount: None }).unwrap(),
        ),
    );
    bal.0.to_string().parse().expect("balance fits u128")
}

fn merkle_root(pic: &PocketIc, s: &Stack) -> [u8; 32] {
    let root: Vec<u8> = decode(
        "get_root",
        pic.query_call(s.merkle, s.user, "get_root", candid::encode_args(()).unwrap()),
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&root);
    out
}

#[allow(clippy::too_many_arguments)]
fn spend(
    pic: &PocketIc,
    s: &Stack,
    spend_id: u64,
    root: [u8; 32],
    note: u128,
    payout: Option<u128>,
    fee: u128,
    nullifier: u8,
    commitments: (u8, u8),
) -> Result<(), PoolError> {
    let public_amount = payout.unwrap_or(0);
    let change = note - fee - public_amount;
    decode(
        "private_spend",
        pic.update_call(
            s.pool,
            s.user,
            "private_spend",
            candid::encode_one(PrivateSpendArgs {
                spend_id,
                envelope: ProofEnvelope {
                    circuit_version: 0,
                    proof_system_id: "groth16-bn254".to_string(),
                    verifying_key_hash: VK_HASH,
                    root_reference: root,
                    pool_version: 1,
                    proof_bytes: vec![0u8; 8],
                },
                                nullifiers: vec![fe(nullifier)],
                output_commitments: vec![fe(commitments.0), fe(commitments.1)],
                encrypted_outputs: vec![vec![], vec![]],
                fee,
                public_payout: payout.map(|public_amount| PrivateSpendPublicPayout {
                    destination: s.recipient,
                    destination_subaccount: None,
                    public_amount,
                }),
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// T1 — the exit pays the VALUE fee, and the old flat fee is rejected by name
// ─────────────────────────────────────────────────────────────────────────────

// BINDING: B-2 — the verifier's public_amount/fee public signals bind the fee the
// pool settles. Registered in tests/BINDING_REGISTRY.toml; `verify_gate_lints
// bindings` checks this test still calls spend twice with differing fees and
// still asserts the mismatch rejection.
#[test]
fn t1_exit_above_the_crossover_pays_the_value_fee_and_names_the_mismatch() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let note = DENOMINATIONS[3]; // 1,000,000 STSH
    let root = deposit(&pic, &s, note, fe(0x11));

    // A6.6: the crossover is 1,000 STSH, so the bps arm needs an amount above it.
    // 100,000 STSH out: 0.25% = 250 STSH, well above the 2.5 STSH floor.
    let public_amount = 100_000 * E8S;
    let value_fee = expected_exit_fee(public_amount);
    assert_eq!(value_fee, 25_000_000_000, "0.25% of 100,000 STSH is 250 STSH");
    assert!(value_fee > SPEND_FEE, "this case must exercise the bps arm");

    // The OLD behaviour — the flat private-spend fee on an exit — is rejected,
    // and the error carries both numbers.
    let rejected = spend(&pic, &s, 1, root, note, Some(public_amount), SPEND_FEE, 0x21, (0x31, 0x32));
    assert_eq!(
        rejected,
        Err(PoolError::PrivateSpendFeeMismatch { expected: value_fee, got: SPEND_FEE }),
        "an exit carrying the flat spend fee must be rejected naming expected={value_fee} got={SPEND_FEE}"
    );

    // The value fee is accepted, and the spend settles.
    let accepted = spend(&pic, &s, 2, root, note, Some(public_amount), value_fee, 0x22, (0x33, 0x34));
    assert_eq!(accepted, Ok(()), "an exit carrying max(flat, 0.25%) must be accepted");
}

#[test]
fn t1b_exit_below_the_crossover_pays_the_flat_minimum() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let note = DENOMINATIONS[1]; // 10,000 STSH
    let root = deposit(&pic, &s, note, fe(0x12));

    // 100 STSH out: 0.25% = 0.25 STSH, so the 2.5 STSH floor binds. A6.6 put the
    // crossover on the ladder's 1,000-STSH floor rung, so the floor arm is only
    // reachable below the ladder.
    let public_amount = 100 * E8S;
    let fee = expected_exit_fee(public_amount);
    assert_eq!(fee, FLAT_MIN, "below the crossover the floor binds");

    // A fee of the raw 0.25% (floor ignored) is rejected...
    let by_bps_only = public_amount * (BPS as u128) / 10_000;
    let rejected = spend(&pic, &s, 3, root, note, Some(public_amount), by_bps_only, 0x23, (0x35, 0x36));
    assert_eq!(
        rejected,
        Err(PoolError::PrivateSpendFeeMismatch { expected: fee, got: by_bps_only }),
        "dropping the floor must be rejected"
    );
    // ...and the floor is accepted.
    assert_eq!(
        spend(&pic, &s, 4, root, note, Some(public_amount), fee, 0x24, (0x37, 0x38)),
        Ok(()),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T2 — the shielded->shielded branch is UNCHANGED
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t2_private_spend_without_a_payout_still_pays_the_flat_spend_fee() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let note = DENOMINATIONS[3]; // 1,000 STSH — big enough that the value fee
                                 // would differ wildly if the branch leaked
    let root = deposit(&pic, &s, note, fe(0x13));

    // If the None branch had been routed through the value fee it would charge
    // max(0.1, 0.25% of 0) = 0.1 — identical. So the test must use a fee that
    // DISTINGUISHES the branches: the value fee on the note's own size is what a
    // payout-shaped implementation might charge, and it must be rejected here.
    let wrong = expected_exit_fee(note);
    assert_ne!(wrong, SPEND_FEE, "the distinguishing fee must differ from the flat fee");
    let rejected = spend(&pic, &s, 5, root, note, None, wrong, 0x25, (0x39, 0x3A));
    assert_eq!(
        rejected,
        Err(PoolError::PrivateSpendFeeMismatch { expected: SPEND_FEE, got: wrong }),
        "a shielded->shielded spend must still expect the flat protocol spend fee"
    );

    assert_eq!(
        spend(&pic, &s, 6, root, note, None, SPEND_FEE, 0x26, (0x3B, 0x3C)),
        Ok(()),
        "the unchanged branch must still accept the flat spend fee"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T3 — both preview sites agree
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t3_an_accepted_exit_survives_the_post_verification_recheck() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let note = DENOMINATIONS[2]; // 100,000 STSH
    let root = deposit(&pic, &s, note, fe(0x14));

    // 50,000 STSH out — above the A6.6 crossover of 1,000 STSH, so entry expects
    // the VALUE fee. The post-verification recheck (step 14c) runs on the same
    // spend after the verifier answers; if that second site were still
    // payout-blind it would expect the flat 2.5 STSH and fail the spend AFTER the
    // expensive half, which is precisely the failure this test exists to exclude.
    let public_amount = 50_000 * E8S;
    let fee = expected_exit_fee(public_amount);
    assert!(fee > SPEND_FEE, "the two sites must disagree if either is payout-blind");

    let result = spend(&pic, &s, 7, root, note, Some(public_amount), fee, 0x27, (0x3D, 0x3E));
    assert_eq!(
        result,
        Ok(()),
        "the exit passed entry but did not survive the post-verification recheck"
    );
}


// ─────────────────────────────────────────────────────────────────────────────
// T4 — the SHIELD side at the new floor (Owner item 1 landed on both directions)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t4_shield_side_charges_the_new_flat_minimum_fee_on_top() {
    let pic = PocketIc::new();
    let s = deploy(&pic);

    // A 1,000-STSH deposit — DENOMINATIONS[0], the ladder's floor rung, and the
    // ONLY amount at which a real deposit can exercise the flat minimum at all.
    // A6.6 raised the floor to 2.5 STSH and put the crossover exactly here, so
    // the two arms of max() are EQUAL at this rung: 0.25% x 1,000 STSH = 2.5 STSH.
    // Below the ladder the flat arm would strictly dominate, but no such deposit
    // is admissible — `shield_deposit` rejects anything off the ladder — so this
    // boundary IS the floor arm's reachable case, and asserting BOTH forms is
    // what makes that concrete rather than a coincidence nobody checked.
    let amount = DENOMINATIONS[0];
    let shield_fee = expected_exit_fee(amount);
    assert_eq!(shield_fee, 250_000_000, "a 1,000 STSH deposit pays 2.5 STSH");
    assert_eq!(shield_fee, FLAT_MIN, "at the floor rung the flat minimum is the fee");
    assert_eq!(
        shield_fee,
        amount * (BPS as u128) / 10_000,
        "and the value fee is the SAME number there — the arms meet on the rung"
    );

    // Measured at the ledger, not inferred from an allowance: what actually
    // leaves the depositor's account.
    let before = balance(&pic, &s, s.user);
    approve(&pic, &s, amount + shield_fee + 10 * DEFAULT_LEDGER_FEE);
    let after_approve = balance(&pic, &s, s.user);
    let ok: Result<Nat, PoolError> = decode(
        "shield_deposit",
        pic.update_call(
            s.pool,
            s.user,
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: fe(0x51),
                encrypted_payload: vec![],
                public_amount: amount,
                expected_deployment_config_hash: None,
            })
            .unwrap(),
        ),
    );
    assert!(ok.is_ok(), "the deposit must succeed: {ok:?}");
    let after = balance(&pic, &s, s.user);

    // The approve itself costs one ledger fee; the deposit transfer costs the
    // principal, the protocol fee and one more ledger fee.
    let approve_cost = before - after_approve;
    let deposit_cost = after_approve - after;
    // Measured, not assumed: this ledger charges nothing for `icrc2_approve`
    // itself, so the whole debit belongs to the deposit transfer.
    assert_eq!(approve_cost, 0, "icrc2_approve is free on this ledger");
    // The debit is EXACTLY principal + protocol fee. Measured, and reported as
    // measured: this ledger charges no transfer fee in this configuration, so
    // there is no ledger-fee component to attribute here.
    assert_eq!(
        deposit_cost,
        amount + shield_fee,
        "a {amount}-e8s deposit must debit amount + the 2.5 STSH protocol fee"
    );
    // The fee charged IS the flat minimum. A6.6 note: at this rung it is ALSO
    // the bps arm, because the crossover sits exactly on the ladder floor — so
    // "the floor was applied" and "the value fee was applied" are the same
    // statement here, and the pre-A6.6 form of this assertion (bps strictly
    // smaller, "forty times smaller than what was charged") is now false rather
    // than merely differently-numbered. What still bites is the STRICT
    // inequality one rung down, off the ladder, which is the only place the two
    // arms disagree at all under the ruled parameters.
    assert_eq!(deposit_cost - amount, FLAT_MIN);
    let one_rung_down = amount / 10;
    assert!(
        one_rung_down * (BPS as u128) / 10_000 < FLAT_MIN,
        "below the ladder the flat minimum must strictly dominate, or it is not a floor"
    );
    println!(
        "A-7 T4 measured: {amount}-e8s deposit debited {deposit_cost} e8s = {amount} principal \
         + {shield_fee} protocol fee (the crossover rung: flat minimum == 0.25% == 2.5 STSH)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T6a — the canister's own answer, BY CALL, across both arms and the crossover
// ─────────────────────────────────────────────────────────────────────────────

/// The canister is not asked to *report* a fee (no preview query exists on the
/// pool, and adding one would move a `.did` this lane may not touch). It is
/// asked to ACCEPT or REJECT, which is a stronger answer: for each amount the
/// pool accepts exactly one fee value and rejects its neighbours, and the
/// rejection names the number it wanted. That named number IS the canister's
/// answer, obtained by call.
#[test]
fn t6a_canister_fee_answers_by_call_across_both_arms_and_the_crossover() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let note = DENOMINATIONS[4]; // 10,000,000 STSH — covers every row below
    let root = deposit(&pic, &s, note, fe(0x15));

    // Both arms of max(), the crossover itself, one e8s either side of it, and
    // the first amount at which the bps arm STRICTLY exceeds the floor.
    //
    // A6.6 redesign: the flat minimum is 2.5 STSH and the crossover therefore sits
    // at 1,000 STSH — exactly the ladder's floor rung — instead of 40 STSH. The
    // SHAPE of the table is unchanged; every row is re-derived at the new
    // parameters rather than rescaled from the old ones.
    //
    // Measured, and worth stating because it is not what "crossover +/- 1 e8s"
    // suggests: the fee is integer floor division (`amount * 25 / 10_000`), so one
    // e8s above 1,000 STSH the bps arm is still 250_000_000 — identical to the
    // floor. The first amount where it strictly wins is 1,000.000004 STSH
    // (100_000_000_400 e8s), 400 e8s further on, because 400 e8s of amount buys
    // one e8s of fee at 25 bps.
    let amounts: [u128; 7] = [
        100 * E8S,           // 100 STSH — floor arm
        CROSSOVER - 1,       // 1,000 STSH - 1 e8s — floor arm, by one unit
        CROSSOVER,           // 1,000 STSH — the arms are equal here
        CROSSOVER + 1,       // 1,000 STSH + 1 e8s — STILL the floor (floor division)
        100_000_000_400,     // the first amount whose bps fee strictly exceeds the floor
        10_000 * E8S,        // 10,000 STSH — bps arm
        997_506_234_413_966, // the largest exit that fits the circuit bound
    ];

    let mut table = Vec::new();
    let mut spend_id = 100u64;
    let mut tag = 0x40u8;
    for amount in amounts {
        let expected = expected_exit_fee(amount);
        // Ask the canister by call: a deliberately wrong fee makes it state the
        // number it wanted.
        let answer = spend(&pic, &s, spend_id, root, note, Some(amount), expected - 1, tag, (tag + 1, tag + 2));
        spend_id += 1;
        tag += 3;
        match answer {
            Err(PoolError::PrivateSpendFeeMismatch { expected: canister, got }) => {
                assert_eq!(got, expected - 1);
                assert_eq!(
                    canister, expected,
                    "canister's fee for public_amount={amount} is {canister}, the model says {expected}"
                );
                table.push((amount, canister));
            }
            other => panic!("expected a fee mismatch for {amount}, got {other:?}"),
        }
    }

    // The crossover really is the crossover: equal at 1,000 STSH, floor-bound one
    // e8s below, still floor-bound one e8s above (integer floor division).
    assert_eq!(table[2].1, FLAT_MIN, "at the crossover the two arms coincide");
    assert_eq!(table[1].1, FLAT_MIN, "one e8s below the crossover the floor binds");
    assert_eq!(
        table[3].1, FLAT_MIN,
        "one e8s ABOVE the crossover the floor still binds — integer floor division"
    );
    assert_eq!(
        table[4].1,
        FLAT_MIN + 1,
        "100_000_000_400 e8s is the first amount whose bps fee strictly exceeds the floor"
    );
    assert!(table[5].1 > FLAT_MIN, "well above the crossover the bps arm binds");

    // The shared cross-surface fixture: the wallet mirror is asserted against
    // these same numbers in `wallet/tests/a7_exit_fee_mirror.test.ts`, so the
    // two implementations are compared against ONE table rather than against
    // each other's arithmetic.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("wallet/tests/fixtures/a7_exit_fee_table.json");
    let text = std::fs::read_to_string(&fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    for (amount, fee) in &table {
        let row = format!("{{ \"public_amount_e8s\": \"{amount}\", \"fee_e8s\": \"{fee}\" }}");
        assert!(
            text.contains(&row),
            "the shared fixture is missing the canister's answer {row}\n{text}"
        );
    }
    println!("A-7 T6a canister answers by call: {table:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// T9 — the exit fee reaches the reserves at the RULED model
// ─────────────────────────────────────────────────────────────────────────────

/// The exit fee reaching the reserves on the **bps arm**, at 50,000 STSH out.
///
/// `security_tests::test_nonzero_fee_spend_with_payout_preserves_i02a` keeps its
/// own fee-bearing coverage per `SUPERVISOR_RULING_A-7_eighth_site_V3` §2, on the
/// FLOOR arm (a small payout, where `max()` selects the flat minimum).
/// This test is the other arm: a payout large enough that the 0.25% component
/// wins, so the split is computed from a fee that scales with the amount rather
/// than from a constant. Two arms, two files, neither redundant.
#[test]
fn t9_exit_fee_splits_to_the_reserves_at_the_ruled_model() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let note = DENOMINATIONS[2]; // 100,000 STSH
    let root = deposit(&pic, &s, note, fe(0x16));

    // 50,000 STSH out — the bps arm (A6.6 crossover is 1,000 STSH), so the fee is
    // unmistakably the value fee.
    let public_amount = 50_000 * E8S;
    let fee = expected_exit_fee(public_amount);
    assert_eq!(fee, 12_500_000_000, "0.25% of 50,000 STSH is 125 STSH");

    let before = accounting_state(&pic, &s);
    assert_eq!(
        spend(&pic, &s, 40, root, note, Some(public_amount), fee, 0x28, (0x3F, 0x41)),
        Ok(()),
    );
    let after = accounting_state(&pic, &s);

    // The 85/15 launch split of the EXIT fee, computed from the fee this test
    // independently derived — not read back from the canister.
    let ops_share = fee * 8_500 / 10_000;
    let ins_share = fee * 1_500 / 10_000;
    assert_eq!(ops_share + ins_share, fee, "the split must be exhaustive at these shares");
    assert_eq!(
        after.operations_reserve - before.operations_reserve,
        ops_share,
        "the operations reserve must be credited the exit fee's ops share"
    );
    assert_eq!(
        after.insurance_reserve - before.insurance_reserve,
        ins_share,
        "the insurance reserve must be credited the exit fee's insurance share"
    );
    // ...and the combined debit leaves the shielded side by payout + fee.
    assert_eq!(
        before.escrow_backing - after.escrow_backing,
        public_amount + fee,
        "ESCROW_BACKING must fall by public_amount + the exit fee"
    );
    assert_eq!(
        before.private_liability - after.private_liability,
        public_amount + fee,
        "PRIVATE_LIABILITY must fall by public_amount + the exit fee"
    );
    // ── R4-1 (sweep fold, test-only): the file's own I-02A identity lock ─────
    //
    // Until this fold NO test in this file ever read the POOL's balance — the
    // `balance()` helper was used only for the user's, in the shield test. So the
    // suite that OWNS exit-fee accounting could not assert I-02A, and its safety
    // net for a ledger-vs-buckets divergence lived in another file, at a
    // different fee arm (`def022p` in security_tests.rs).
    //
    // The delta assertions above cannot see this class: R4 mutated the pool to
    // over-pay every recipient by a constant while keeping every bucket delta
    // correct, and the shipped suite still passed 8/8 — this identity is what
    // failed, short by exactly the over-payment. Proven to bite before it was
    // proposed; it is not a passing assertion nobody has tried to break.
    let pool_ledger = balance(&pic, &s, s.pool);
    assert_eq!(
        after.escrow_backing
            + after.operations_reserve
            + after.insurance_reserve
            + after.governance_rewards_reserve,
        pool_ledger,
        "I-02A must hold after a BPS-ARM public-payout exit: the pool's ledger \
         balance must equal escrow + the three reserves"
    );

    println!(
        "A-7 T9 measured: exit fee {fee} e8s split ops {ops_share} / insurance {ins_share}; \
         I-02A identity held at {pool_ledger} e8s"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T10 — the ratified zero-params sentence, asserted where it belongs
// ─────────────────────────────────────────────────────────────────────────────

/// **RATIFIED** by `SUPERVISOR_RULING_A-7_eighth_site_V3` §2:
///
/// > a public-payout exit at launch-DEFAULT params (`launch_defaults()`,
/// > fee-free by design) pays zero protocol fee; the ruled
/// > `max(0.1 STSH, 0.25%)` model is carried by `mainnet_launch_config`, the
/// > genesis config.
///
/// The two configs are different objects by design. This is the deliberate
/// assertion of that sentence: it is a real property of the shipped model, it is
/// asserted in the file that owns the exit-fee behaviour, and it is NOT allowed
/// to displace fee-bearing coverage in a test whose subject is fee accounting.
#[test]
fn t10_at_zero_unshield_params_a_public_payout_exit_is_free() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    // Install the fee-free posture explicitly: both unshield fields at the
    // launch DEFAULT of zero, spend fee nonzero so the two branches are
    // distinguishable.
    let mut params = nonzero_launch_params();
    params.unshield_fee_bps = Some(0);
    params.unshield_flat_minimum_fee_e8s = Some(0);
    let set: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        pic.update_call(
            s.pool,
            s.controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    set.expect("the fee-free posture must install");

    let note = DENOMINATIONS[1]; // 10 STSH
    let root = deposit(&pic, &s, note, fe(0x17));
    let public_amount = E8S; // 1 STSH out

    // The flat spend fee is REJECTED on an exit — the branch is chosen by the
    // presence of a payout, not by which number happens to be nonzero.
    assert_eq!(
        spend(&pic, &s, 50, root, note, Some(public_amount), SPEND_FEE, 0x29, (0x42, 0x43)),
        Err(PoolError::PrivateSpendFeeMismatch { expected: 0, got: SPEND_FEE }),
        "at zero unshield params the exit expects ZERO, not the flat spend fee"
    );
    // A zero fee is accepted, and the exit settles.
    assert_eq!(
        spend(&pic, &s, 51, root, note, Some(0_u128.max(public_amount)), 0, 0x2A, (0x44, 0x45)),
        Ok(()),
        "a free exit must settle under the fee-free posture"
    );
    // ...while a shielded->shielded spend on the SAME params still pays the flat
    // spend fee: the two configs differ in the exit arm only.
    let note2 = DENOMINATIONS[0];
    let root2 = deposit(&pic, &s, note2, fe(0x18));
    assert_eq!(
        spend(&pic, &s, 52, root2, note2, None, SPEND_FEE, 0x2B, (0x46, 0x47)),
        Ok(()),
        "the None branch is unaffected by the unshield fields"
    );
}
