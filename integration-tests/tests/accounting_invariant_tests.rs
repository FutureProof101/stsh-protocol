// =============================================================================
// STSH — DEF-087: Pool accounting invariant tests (PocketIC)
// =============================================================================
//
// Verifies the canonical 6-bucket accounting model against the pool's REAL
// ledger balance (icrc1_balance_of), not a stub:
//
//   I-02A  ledger identity — escrow_backing + operations_reserve
//          + insurance_reserve + governance_rewards_reserve
//          == icrc1_balance_of(pool)
//   I-02B  solvency — escrow_backing + pending_fee_reimbursements
//          >= private_liability;  operations_reserve >= pending_fee_reimbursements
//   I-02C  launch model (§7 not activated) — pending_fee_reimbursements == 0
//
// Assertions use plain `+` deliberately (NO saturating_add/saturating_sub):
// these tests exist to expose overflow/drift, not mask it.
//
// SKIP behaviour: test_accounting_solvency_after_spend requires
// circuits/proof.json + circuits/public.json (real Groth16 artifacts). If
// either is absent it prints SKIP and returns — not a failure. The deposit
// and upgrade tests have no fixture dependency and always run.
//
// Gate:
//   cargo test -p integration-tests --test accounting_invariant_tests \
//       -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading (same env! vars as security_tests / full_path benchmark)
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release \\\n    \
             -p stsh_token -p shielded_pool -p nullifier_registry \\\n    \
             -p merkle_tree -p stsh-verifier",
            pkg, path, e
        )
    })
}

fn token_wasm()     -> Vec<u8> { load_wasm(env!("TOKEN_WASM"),     "stsh_token") }
fn pool_wasm()      -> Vec<u8> { load_wasm(env!("POOL_WASM"),      "shielded_pool") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm()    -> Vec<u8> { load_wasm(env!("MERKLE_WASM"),    "merkle_tree") }
fn verifier_wasm()  -> Vec<u8> { load_wasm(env!("VERIFIER_WASM"),  "stsh_verifier") }

// ─────────────────────────────────────────────────────────────────────────────
// Candid type mirrors (canister crates are cdylib — types mirrored per repo
// pattern; field names must match the live canister code exactly)
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DEFAULT_FEE:  u128 = 0; // F-000: token transfers free at launch
// DENOMINATIONS[0] = 1,000 STSH (must be in the pool's fixed denomination set; A6.6)
const DEPOSIT_AMOUNT: u128 = 1_000 * 100_000_000;

/// in_commitment for the spend circuit test vectors
/// (spend_key=42, in_value=100_000_000_000, in_rho=99, in_rseed=77).
/// Same fixture as full_path_private_spend_benchmark.rs.
// DEF-111 finalization regen: in_commitment over the finalized circuit's domain_sep [2,0,2,1].
// Post-A1 regen (2026-07-07): in_commitment over the MAINNET domain_sep
// [ohspu-zqaaa-aaaad-qmasq-cai→Fr, 0, 2, 1].
// A6.6 regen (2026-09-08): DOMAIN_CIRCUIT_VERSION 2 -> 3 AND in_value 1 STSH ->
// 1,000 STSH (the new ladder floor — the fixture note must be depositable), so
// the commitment moved on both counts. Regenerate via
// `node circuits/tests/gen_test_input.js`, then re-prove with snarkjs.
// A-3 FINALIZE regen (2026-09-12): DOMAIN_POOL_CANISTER_ID re-encoded to the
// Vault-born pool cxrfg-qaaaa-aaaar-qchfa-cai, so domain_sep — and therefore this
// known-answer commitment — moved. Regenerated via
// `node circuits/tests/gen_test_input.js`, then re-proved with snarkjs
// (circuits/proof.json + public.json, and the payout-A pair).
// A-3 FINALIZE value = 5364317693480985596849535143007715299620008859654397609343785557192353738706
// (was 10736000484984796872851673331456014893505793551453256205310079874034616912601 at A6.6).
const IN_COMMITMENT: [u8; 32] = [
    0xd2, 0x6f, 0x9b, 0xb7, 0x36, 0x0a, 0xed, 0x7f,
    0x09, 0x18, 0xe7, 0x27, 0x12, 0x3c, 0x86, 0x90,
    0xe2, 0x71, 0xb0, 0x5b, 0x6c, 0xb4, 0x52, 0xfc,
    0x6f, 0x05, 0x3a, 0xd4, 0xa1, 0x18, 0xdc, 0x0b,
];

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version:    u32,
    proof_system_id:    String,
    verifying_key_hash: [u8; 32],
    root_reference:     [u8; 32],
    pool_version:       u32,
    proof_bytes:        Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment:   [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount:     u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id:           u64,
    envelope:           ProofEnvelope,
    nullifiers:         Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs:  Vec<Vec<u8>>,
    fee:                u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    EscrowUnderfunded          { required: u128, available: u128 },
    CircuitVersionMismatch     { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee       { amount: u128, fee: u128 },
    BelowMinimumDeposit        { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch                { inputs: u128, outputs: u128 },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateSpendId,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    InsufficientPrivateLiability { required: u128, available: u128 },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner:      Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount:    Option<[u8; 32]>,
    spender:            Account,
    amount:             Nat,
    expected_allowance: Option<Nat>,
    expires_at:         Option<u64>,
    fee:                Option<Nat>,
    memo:               Option<Vec<u8>>,
    created_at_time:    Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveError {
    BadFee            { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged  { current_allowance: Nat },
    Expired           { ledger_time: u64 },
    TooOld,
    CreatedInFuture   { ledger_time: u64 },
    Duplicate         { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError      { error_code: Nat, message: String },
}

/// Mirror of the pool's 6-bucket accounting snapshot (canonical bucket names —
/// exactly as in canisters/shielded-pool/src/lib.rs AccountingState).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct AccountingState {
    private_liability:          u128,
    escrow_backing:             u128,
    operations_reserve:         u128,
    insurance_reserve:          u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers (same pattern as full_path_private_spend_benchmark.rs)
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
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
    let bytes = result
        .unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes)
        .unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn to_u128(n: Nat) -> u128 { n.0.to_string().parse::<u128>().unwrap_or(0) }

fn do_approve(pic: &PocketIc, token_id: Principal, caller: Principal,
              spender: Principal, amount: u128) {
    let result: Result<Nat, ApproveError> = decode(
        "icrc2_approve",
        pic.update_call(
            token_id, caller, "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount:    None,
                spender:            Account { owner: spender, subaccount: None },
                amount:             Nat::from(amount),
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at:         Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee:                None,
                memo:               None,
                created_at_time:    None,
            }).unwrap(),
        ),
    );
    result.expect("icrc2_approve must succeed in test setup");
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .join("circuits")
}

/// Load the real proof/public artifacts and build a PrivateSpendArgs template.
/// Returns None if circuits/proof.json or circuits/public.json are absent.
fn load_fixture_args() -> Option<PrivateSpendArgs> {
    let public_json = std::fs::read_to_string(circuits_dir().join("public.json")).ok()?;
    let proof_json  = std::fs::read_to_string(circuits_dir().join("proof.json")).ok()?;
    let signals     = stsh_verifier::public_json_to_signals(&public_json).ok()?;
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json).ok()?;
    Some(PrivateSpendArgs {
        spend_id:    0, // overridden per test
        envelope: ProofEnvelope {
            circuit_version:    0,
            proof_system_id:    "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference:     signals[0],
            pool_version:       1,
            proof_bytes,
        },
                nullifiers:         vec![signals[1]],
        output_commitments: vec![signals[2], signals[3]],
        encrypted_outputs:  vec![vec![0xAA], vec![0xBB]],
        fee:                0,
    })
}

/// Create and fully configure a fresh 5-canister full-path instance.
/// Returns (token_id, pool_id). Controller of the pool is p(0x06).
fn setup_instance(pic: &PocketIc) -> (Principal, Principal) {
    let user      = p(0xB0);
    let token_id  = create_canister(pic);
    let null_id   = create_canister(pic);
    let pool_id   = create_canister(pic);
    let merkle_id = create_canister(pic);
    let verifier  = create_canister(pic);

    pic.install_canister(null_id,   nullifier_wasm(), candid::encode_one(pool_id).unwrap(), None);
    pic.install_canister(merkle_id, merkle_wasm(),    candid::encode_one(pool_id).unwrap(), None);
    // DEF-083: the verifier is pool-caller-gated — bind it to this instance's pool.
    pic.install_canister(verifier,  verifier_wasm(),  candid::encode_one(pool_id).unwrap(), None);

    install(pic, token_id, token_wasm(), &TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id:          "all".to_string(),
            category_name:        "All tokens".to_string(),
            amount:               TOTAL_SUPPLY,
            recipient:            user,
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }],
        treasury:         p(0x01),
        staking_canister: p(0x02),
    });

    install(pic, pool_id, pool_wasm(), &PoolInitArgs {
        token_canister:       token_id,
        nullifier_canister:   null_id,
        merkle_canister:      merkle_id,
        treasury_canister:    p(0x04),
        staking_canister:     p(0x02),
        controller:           p(0x06),
        initial_vk_hash:      stsh_verifier::compiled_vk_sha256(),
        initial_proof_system: "groth16-bn254".to_string(),
    });

    // Wire the real verifier to the pool (operator-controller call).
    pic.update_call(
        pool_id, p(0x06), "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    ).expect("set_verifier_canister must succeed");

    (token_id, pool_id)
}

/// Seed IN_COMMITMENT into the Merkle tree via shield_deposit.
fn seed_deposit(pic: &PocketIc, token_id: Principal, pool_id: Principal) {
    let user = p(0xB0);
    do_approve(pic, token_id, user, pool_id, DEPOSIT_AMOUNT + DEFAULT_FEE);
    let result: Result<Nat, PoolError> = decode(
        "seed shield_deposit",
        pic.update_call(
            pool_id, user, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment:   IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount:     DEPOSIT_AMOUNT,
            }).unwrap(),
        ),
    );
    result.expect("seed shield_deposit must succeed");
}

/// Query the pool's 6-bucket snapshot. get_accounting_state is
/// controller-gated (DEF-076) — query as the pool controller p(0x06).
fn accounting_state(pic: &PocketIc, pool_id: Principal) -> AccountingState {
    decode(
        "get_accounting_state",
        pic.query_call(
            pool_id, p(0x06), "get_accounting_state",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// Query the pool's REAL ledger balance from the token canister.
fn pool_ledger_balance(pic: &PocketIc, token_id: Principal, pool_id: Principal) -> u128 {
    to_u128(decode(
        "icrc1_balance_of(pool)",
        pic.query_call(
            token_id, p(0xB0), "icrc1_balance_of",
            candid::encode_one(Account { owner: pool_id, subaccount: None }).unwrap(),
        ),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-087 invariant helper
// ─────────────────────────────────────────────────────────────────────────────

/// Assert the canonical accounting invariants against the pool's REAL ledger
/// balance. `pool_ledger_balance` must come from an icrc1_balance_of(pool)
/// query made by the caller — never stubbed or hardcoded.
///
/// Plain `+` on purpose: an overflow here is a bug the test must expose,
/// not mask with saturating arithmetic.
fn assert_pool_accounting_invariants(
    state: &AccountingState,
    pool_ledger_balance: u128, // from icrc1_balance_of(pool), queried by the caller
) {
    // I-02A: ledger identity — must actually assert against the real balance
    let ledger_sum = state.escrow_backing
        + state.operations_reserve
        + state.insurance_reserve
        + state.governance_rewards_reserve;
    assert_eq!(ledger_sum, pool_ledger_balance, "I-02A: ledger_sum != pool_ledger_balance");

    // I-02B: solvency conditions
    assert!(
        state.escrow_backing + state.pending_fee_reimbursements >= state.private_liability,
        "I-02B: escrow_backing + pending_fee_reimbursements < private_liability"
    );
    assert!(
        state.operations_reserve >= state.pending_fee_reimbursements,
        "I-02B: operations_reserve < pending_fee_reimbursements"
    );

    // I-02C: pending_fee_reimbursements == 0 at launch (§7 not activated)
    assert_eq!(
        state.pending_fee_reimbursements, 0,
        "I-02C: pending_fee_reimbursements expected 0 under §7 launch model"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — I-02A/B/C hold after a shield deposit
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_accounting_identity_after_deposit() {
    let pic = PocketIc::new();
    let (token_id, pool_id) = setup_instance(&pic);
    seed_deposit(&pic, token_id, pool_id);

    let state   = accounting_state(&pic, pool_id);
    let balance = pool_ledger_balance(&pic, token_id, pool_id);

    // The deposit must actually have registered: finalize_deposit_credit adds
    // the note's private balance to BOTH escrow_backing and private_liability.
    assert!(state.private_liability > 0, "deposit did not register private_liability");
    assert_eq!(
        state.private_liability, state.escrow_backing,
        "after a single deposit, escrow_backing must equal private_liability \
         (both credited with the note's private balance)"
    );

    assert_pool_accounting_invariants(&state, balance);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — I-02B solvency holds after a private spend
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_accounting_solvency_after_spend() {
    let Some(fixture) = load_fixture_args() else {
        // R4-2 (sweep fold): this used to `println!("SKIP: …")` and return, and a
        // skipped test reports as `ok`.
        panic!("circuits/proof.json and circuits/public.json are TRACKED files, so their absence means they were DELETED, not that this environment lacks an optional artifact. A silent SKIP reported as ok, which left the gate line unable to distinguish a verified real-proof path from a missing fixture (R4-2). Restore them: git checkout -- circuits/proof.json circuits/public.json");
    };

    let pic = PocketIc::new();
    let (token_id, pool_id) = setup_instance(&pic);
    seed_deposit(&pic, token_id, pool_id);

    let state_before = accounting_state(&pic, pool_id);

    let args = PrivateSpendArgs { spend_id: 8700, ..fixture };
    let result: Result<(), PoolError> = decode(
        "private_spend",
        pic.update_call(
            pool_id, p(0xB0), "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert!(result.is_ok(), "private_spend must succeed: {:?}", result);

    let state_after = accounting_state(&pic, pool_id);
    let balance     = pool_ledger_balance(&pic, token_id, pool_id);

    // I-02A/B/C must all hold after the spend.
    assert_pool_accounting_invariants(&state_after, balance);

    // Grounded bucket semantics for THIS fixture: the spend is fully shielded
    // (sum(inputs) == sum(outputs), fee == 0, no public/unshield component).
    // The input note is replaced by two output notes of equal total value, so
    // private_liability and escrow_backing are PRESERVED — not decremented —
    // and the fee-split path (which credits operations/insurance/governance
    // reserves from a nonzero spend fee) never fires. A liability decrement
    // only occurs on an unshield/withdrawal component, which this lane's
    // fixture does not exercise (withdrawals are WRL scope).
    assert_eq!(
        state_after, state_before,
        "a fully-shielded fee-0 spend must leave all six buckets unchanged"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — all 6 buckets survive a pool canister upgrade
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_accounting_buckets_survive_upgrade() {
    let pic = PocketIc::new();
    let (token_id, pool_id) = setup_instance(&pic);
    seed_deposit(&pic, token_id, pool_id);

    let state_before   = accounting_state(&pic, pool_id);
    let balance_before = pool_ledger_balance(&pic, token_id, pool_id);

    // Upgrade the pool canister in place (pre_upgrade → post_upgrade round trip).
    pic.upgrade_canister(pool_id, pool_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade (pre/post_upgrade) must succeed");

    let state_after   = accounting_state(&pic, pool_id);
    let balance_after = pool_ledger_balance(&pic, token_id, pool_id);

    // All 6 bucket values must be identical pre/post upgrade — field by field
    // so a failure names the drifted bucket.
    assert_eq!(state_after.private_liability,          state_before.private_liability,          "private_liability drifted across upgrade");
    assert_eq!(state_after.escrow_backing,             state_before.escrow_backing,             "escrow_backing drifted across upgrade");
    assert_eq!(state_after.operations_reserve,         state_before.operations_reserve,         "operations_reserve drifted across upgrade");
    assert_eq!(state_after.insurance_reserve,          state_before.insurance_reserve,          "insurance_reserve drifted across upgrade");
    assert_eq!(state_after.governance_rewards_reserve, state_before.governance_rewards_reserve, "governance_rewards_reserve drifted across upgrade");
    assert_eq!(state_after.pending_fee_reimbursements, state_before.pending_fee_reimbursements, "pending_fee_reimbursements drifted across upgrade");

    // The ledger balance is untouched by an upgrade, and the invariants must
    // still hold against it.
    assert_eq!(balance_after, balance_before, "pool ledger balance changed across upgrade");
    assert_pool_accounting_invariants(&state_after, balance_after);
}
