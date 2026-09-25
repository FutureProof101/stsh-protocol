// =============================================================================
// STSH — Lane B QA-DEF-008/009: public input size caps (PocketIC)
// =============================================================================
//
// Proves the shielded-pool size caps reject oversized public inputs BEFORE any
// storage mutation / clone / Merkle append / nullifier reservation / verifier
// call. Every cap fires in a pure/sync path before the pool touches any other
// canister, so these tests need only the pool itself deployed (its dependency
// principals can be bare — they are never reached on the rejection path).
//
//   test_sc01 — oversized encrypted_payload rejected before mutation (shield_deposit)
//   test_sc02 — oversized encrypted_outputs rejected before mutation (private_spend)
//   test_sc03 — oversized proof_bytes rejected (private_spend)
//   test_sc04 — verifier NOT invoked for oversized proof_bytes (error precedes the
//               verifier-availability check + verify_spend_canister call)
//   test_sc05 — in-bounds payload / proof / outputs are NOT rejected by the caps
//               (execution proceeds past them); plus exact-boundary checks.
//
// "Existing valid-size fixtures still pass unchanged" is covered by the full gate
// (security_tests / transfer_tests etc.): the caps reject only OVERSIZED inputs,
// so the existing sub-canonical stub fixtures (proof_bytes vec![] / vec![0u8;8],
// empty payloads) are unaffected.
//
// PREREQUISITES:
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test lane_b_size_caps -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Constants mirrored from canisters/shielded-pool/src/lib.rs
// ─────────────────────────────────────────────────────────────────────────────

const DENOM_1_STSH: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0] = 1,000 STSH (A6.6)
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 1024;
const MAX_ENCRYPTED_OUTPUT_BYTES: usize = 1024;
const EXPECTED_GROTH16_PROOF_BYTES: usize = 256;

fn pool_wasm() -> Vec<u8> {
    let path = env!("POOL_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read shielded_pool Wasm at {}: {}.\n  \
             cargo build --target wasm32-unknown-unknown --release -p shielded_pool",
            path, e
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — field names/order must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

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
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
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
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

impl AccountingState {
    fn is_zero(&self) -> bool {
        self.private_liability == 0
            && self.escrow_backing == 0
            && self.operations_reserve == 0
            && self.insurance_reserve == 0
            && self.governance_rewards_reserve == 0
            && self.pending_fee_reimbursements == 0
    }
}

/// Full mirror of shielded-pool PoolError (incl. the QA-DEF-008/009 variants).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
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
    // QA-DEF-008/009
    EncryptedPayloadTooLarge { len: u64, max: u64 },
    EncryptedOutputTooLarge { index: u32, len: u64, max: u64 },
    InvalidProofLength { len: u64, expected: u64 },
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

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

/// Deploy the pool with bare dependency principals — never reached on the
/// rejection paths under test (every cap fires before any cross-canister call).
/// VERIFIER_CANISTER is left unset (no set_verifier_canister), so any path that
/// actually reaches the verifier-availability check returns VerifierUnavailable —
/// used by test_sc04 to prove the size cap short-circuits before that point.
fn deploy_pool(pic: &PocketIc, controller: Principal) -> Principal {
    let pool_id = create_canister(pic);
    let init = PoolInitArgs {
        token_canister: p(0x11),
        nullifier_canister: p(0x12),
        merkle_canister: p(0x13),
        treasury_canister: p(0x14),
        staking_canister: p(0x15),
        controller,
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
    };
    pic.install_canister(pool_id, pool_wasm(), candid::encode_one(&init).unwrap(), None);
    pool_id
}

fn accounting_state(pic: &PocketIc, pool_id: Principal, controller: Principal) -> AccountingState {
    decode(
        "get_accounting_state",
        // DEF-076: get_accounting_state is controller-gated — read as the pool controller.
        pic.query_call(pool_id, controller, "get_accounting_state", candid::encode_args(()).unwrap()),
    )
}

/// A minimal PrivateSpendArgs with controllable proof_bytes / encrypted_outputs.
/// The envelope is intentionally not valid (zero VK hash) — it never matters on
/// the size-cap rejection paths, which fire before envelope verification.
fn spend_args(spend_id: u64, proof_bytes: Vec<u8>, encrypted_outputs: Vec<Vec<u8>>) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: [0u8; 32],
            pool_version: 1,
            proof_bytes,
        },
                nullifiers: vec![[1u8; 32]],
        output_commitments: vec![[2u8; 32], [3u8; 32]],
        encrypted_outputs,
        fee: 0,
        public_payout: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// test_sc01 — oversized encrypted_payload rejected before any mutation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_sc01_oversized_encrypted_payload_rejected_before_mutation() {
    let pic = PocketIc::new();
    let pool_id = deploy_pool(&pic, p(0x01));

    let oversized = (MAX_ENCRYPTED_PAYLOAD_BYTES + 1) as u64; // 1025
    let r: Result<Nat, PoolError> = decode(
        "shield_deposit (oversized payload)",
        pic.update_call(pool_id, p(0xAA), "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: [9u8; 32],
                encrypted_payload: vec![0u8; oversized as usize],
                public_amount: DENOM_1_STSH,
            }).unwrap()),
    );
    match r {
        Err(PoolError::EncryptedPayloadTooLarge { len, max }) => {
            assert_eq!(len, oversized, "reported len");
            assert_eq!(max, MAX_ENCRYPTED_PAYLOAD_BYTES as u64, "reported max");
        }
        other => panic!("expected EncryptedPayloadTooLarge; got {:?}", other),
    }

    // Rejected before any storage mutation / cross-canister call: accounting is
    // untouched (the cap fires before the icrc1_fee query and the pre-reserve).
    assert!(accounting_state(&pic, pool_id, p(0x01)).is_zero(),
        "no accounting mutation may occur on an oversized-payload rejection");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_sc02 — oversized encrypted_outputs rejected before any mutation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_sc02_oversized_encrypted_outputs_rejected_before_mutation() {
    let pic = PocketIc::new();
    let pool_id = deploy_pool(&pic, p(0x02));

    let oversized = (MAX_ENCRYPTED_OUTPUT_BYTES + 1) as u64; // 1025
    // proof_bytes empty (<= cap) so the proof check passes and we reach the
    // per-output check; output[0] is oversized.
    let args = spend_args(1, vec![], vec![vec![0u8; oversized as usize], vec![]]);
    let r: Result<(), PoolError> = decode(
        "private_spend (oversized output)",
        pic.update_call(pool_id, p(0xAA), "private_spend", candid::encode_one(args).unwrap()),
    );
    match r {
        Err(PoolError::EncryptedOutputTooLarge { index, len, max }) => {
            assert_eq!(index, 0, "first output is the oversized one");
            assert_eq!(len, oversized, "reported len");
            assert_eq!(max, MAX_ENCRYPTED_OUTPUT_BYTES as u64, "reported max");
        }
        other => panic!("expected EncryptedOutputTooLarge; got {:?}", other),
    }

    // Rejected before PENDING_SPENDS insert / verifier / Merkle / nullifier:
    // accounting is untouched (the cap fires in validate before any mutation).
    assert!(accounting_state(&pic, pool_id, p(0x02)).is_zero(),
        "no mutation may occur on an oversized-output rejection");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_sc03 — oversized proof_bytes rejected (before the verifier)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_sc03_oversized_proof_bytes_rejected() {
    let pic = PocketIc::new();
    let pool_id = deploy_pool(&pic, p(0x03));

    let oversized = (EXPECTED_GROTH16_PROOF_BYTES + 1) as u64; // 257
    let args = spend_args(1, vec![0u8; oversized as usize], vec![vec![], vec![]]);
    let r: Result<(), PoolError> = decode(
        "private_spend (oversized proof)",
        pic.update_call(pool_id, p(0xAA), "private_spend", candid::encode_one(args).unwrap()),
    );
    match r {
        Err(PoolError::InvalidProofLength { len, expected }) => {
            assert_eq!(len, oversized, "reported len");
            assert_eq!(expected, EXPECTED_GROTH16_PROOF_BYTES as u64, "reported expected");
        }
        other => panic!("expected InvalidProofLength; got {:?}", other),
    }
    assert!(accounting_state(&pic, pool_id, p(0x03)).is_zero(),
        "no mutation may occur on an oversized-proof rejection");
}

// ─────────────────────────────────────────────────────────────────────────────
// test_sc04 — verifier is NOT invoked for oversized proof_bytes
// ─────────────────────────────────────────────────────────────────────────────
//
// The harness has no verifier call-count spy (limitation reported). Strongest
// available proof, two parts:
//  (a) The pool is deployed with NO verifier configured. The InvalidProofLength
//      error is produced in validate_private_spend_static (step 0), which is
//      ordered BEFORE the verifier-availability check (get_verifier) and the
//      verify_spend_canister inter-canister call. If execution had reached the
//      verifier path, the error would be VerifierUnavailable, not InvalidProofLength.
//  (b) Contrast: a CANONICAL-length (256) proof with the same (invalid) envelope
//      passes the length gate and proceeds into envelope verification (a later
//      step), yielding a DIFFERENT error (not InvalidProofLength) — confirming the
//      gate is length-specific and that only non-oversized proofs continue toward
//      the verifier.
// =============================================================================

#[test]
fn test_sc04_verifier_not_invoked_for_oversized_proof() {
    let pic = PocketIc::new();
    let pool_id = deploy_pool(&pic, p(0x04));

    // (a) Oversized proof → InvalidProofLength, and explicitly NOT a verifier error.
    let oversized = spend_args(1, vec![0u8; EXPECTED_GROTH16_PROOF_BYTES + 4096], vec![vec![], vec![]]);
    let r1: Result<(), PoolError> = decode(
        "private_spend (oversized proof, no verifier)",
        pic.update_call(pool_id, p(0xAA), "private_spend", candid::encode_one(oversized).unwrap()),
    );
    assert!(matches!(r1, Err(PoolError::InvalidProofLength { .. })),
        "oversized proof must short-circuit with InvalidProofLength; got {:?}", r1);
    assert!(
        !matches!(r1, Err(PoolError::VerifierUnavailable(_)) | Err(PoolError::ProofRejected(_))),
        "must NOT reach the verifier path (no VerifierUnavailable/ProofRejected); got {:?}", r1
    );

    // (b) Canonical-length proof passes the length gate and proceeds to a LATER
    //     check (envelope verification), so the error is NOT InvalidProofLength.
    let canonical = spend_args(2, vec![0u8; EXPECTED_GROTH16_PROOF_BYTES], vec![vec![], vec![]]);
    let r2: Result<(), PoolError> = decode(
        "private_spend (canonical-length proof)",
        pic.update_call(pool_id, p(0xAA), "private_spend", candid::encode_one(canonical).unwrap()),
    );
    assert!(!matches!(r2, Err(PoolError::InvalidProofLength { .. })),
        "a 256-byte proof must pass the length gate (different/later error expected); got {:?}", r2);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_sc05 — in-bounds inputs are NOT rejected by the caps (+ exact boundaries)
// ─────────────────────────────────────────────────────────────────────────────
//
// The caps must not reject valid-size inputs. We show execution proceeds PAST
// each cap (to a later, unrelated error) for in-bounds inputs, and verify the
// exact boundary (==MAX passes, MAX+1 rejected).
// =============================================================================

#[test]
fn test_sc05_in_bounds_inputs_pass_the_caps() {
    let pic = PocketIc::new();
    let pool_id = deploy_pool(&pic, p(0x05));

    // Payload exactly at the cap is accepted by the cap (proceeds past it — the
    // bare token principal then makes icrc1_fee fail with TransferFailed, which
    // proves the payload check did NOT reject a 1024-byte payload).
    let at_cap: Result<Nat, PoolError> = decode(
        "shield_deposit (payload == cap)",
        pic.update_call(pool_id, p(0xAA), "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: [7u8; 32],
                encrypted_payload: vec![0u8; MAX_ENCRYPTED_PAYLOAD_BYTES],
                public_amount: DENOM_1_STSH,
            }).unwrap()),
    );
    assert!(!matches!(at_cap, Err(PoolError::EncryptedPayloadTooLarge { .. })),
        "a payload of exactly MAX must NOT be rejected by the cap; got {:?}", at_cap);

    // Canonical proof + in-bounds outputs pass BOTH spend caps and proceed to a
    // later check (envelope verification), so neither size error is returned.
    let in_bounds = spend_args(
        1,
        vec![0u8; EXPECTED_GROTH16_PROOF_BYTES],
        vec![vec![0u8; MAX_ENCRYPTED_OUTPUT_BYTES], vec![0u8; 16]],
    );
    let r: Result<(), PoolError> = decode(
        "private_spend (in-bounds)",
        pic.update_call(pool_id, p(0xAA), "private_spend", candid::encode_one(in_bounds).unwrap()),
    );
    assert!(
        !matches!(r, Err(PoolError::InvalidProofLength { .. }) | Err(PoolError::EncryptedOutputTooLarge { .. })),
        "in-bounds proof/outputs must pass both caps (later error expected); got {:?}", r
    );
}
