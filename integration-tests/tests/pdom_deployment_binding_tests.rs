// =============================================================================
// STSH — P-DOM (C-DOM-2) deployment-binding gate tests (PocketIC)
// Campaign B / Wave 2, pre-lane P-DOM.
// =============================================================================
//
// These prove the update-side deployment-config gate:
//   - shield_deposit / private_spend fail closed with DeploymentConfigMismatch
//     when the caller's expected hash does not match the pool's live wiring;
//   - the hash binds the pool's OWN principal FIRST — a DIFFERENT pool wired to
//     the SAME token/merkle/nullifier is rejected (the self-binding test);
//   - each wiring dependency mismatch (token/merkle/nullifier) is rejected
//     INDEPENDENTLY;
//   - a legitimate VK activation / verifier replacement leaves the hash UNCHANGED
//     (VK/verifier/circuit are excluded from the gate);
//   - the encoding matches a pinned byte-vector fixture (domain-separated,
//     u32_be version, u8-length-prefixed principals, pool first);
//   - the matching hash proceeds; a None hash skips the gate (decode-compat);
//   - the advisory attestation getter matches the enforced wiring;
//   - the config hash is preserved across a real upgrade.
//
// The gate runs BEFORE the first await, so a mismatch is observable WITHOUT any
// token/merkle/verifier canister deployed — only the pool (test Wasm) is needed.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release <all production canisters>
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test pdom_deployment_binding_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn pool_test_wasm() -> Vec<u8> {
    let path = env!("POOL_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read shielded_pool_test Wasm {}: {}", path, e))
}
fn pool_prod_wasm() -> Vec<u8> {
    let path = env!("POOL_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read shielded_pool (prod) Wasm {}: {}", path, e))
}
fn stub_verifier_wasm() -> Vec<u8> {
    let path = env!("STUB_VERIFIER_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("read stub_verifier Wasm {}: {}", path, e))
}

// ── PocketIC helpers ────────────────────────────────────────────────────────

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

// ── Candid mirrors ────────────────────────────────────────────────────────────

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
struct PrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<()>, // never a payout in these tests
    expected_deployment_config_hash: Option<[u8; 32]>,
}

// Minimal PendingSpend mirror — only used to inject a pre-existing record via the
// testing endpoint (proving the gate runs BEFORE the idempotency lookup).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendStatus {
    VerificationPending,
    // (only the injected status is needed; other variants are never constructed here)
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpend {
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    public_payout: Option<()>,
    outputs_committed: u32,
    fee: Option<u128>,
    status: SpendStatus,
    created_at_ns: u64,
    submitter: Option<Principal>,
    finalized_at_ns: Option<u64>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
    spend_fee_mode: Option<()>,
    fee_split_ops: Option<u128>,
    fee_split_insurance: Option<u128>,
    fee_split_staking: Option<u128>,
}

// Only the PoolError variants reachable in these tests need to decode: the gate's
// DeploymentConfigMismatch, plus the downstream error a gate-PASS hits because no
// token canister is installed (TransferFailed), and the entry guards.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    DeploymentConfigMismatch,
    InvalidDenomination,
    NotInitialised,
    AnonymousCaller,
    Paused,
    TransferFailed(String),
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InvalidCommitment,
    EncryptedPayloadTooLarge { len: u64, max: u64 },
    // Reachable on the private_spend path once the gate passes (invalid envelope):
    CircuitVersionMismatch { expected: u32, got: u32 },
    AnchorNotFound,
    VerifierUnavailable(String),
    MalformedSpendArgs,
    DuplicateSpendId,
    IdempotencyKeyConflict,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct DeploymentAttestation {
    pool: Principal,
    token: Principal,
    merkle: Principal,
    nullifier: Principal,
    config_version: u32,
    config_hash: [u8; 32],
    verifier: Option<Principal>,
    vk_hash: [u8; 32],
    circuit_version: u32,
    pool_version: u32,
    proof_system: String,
}

// Fixed wiring principals for the deployed pool.
fn token() -> Principal { Principal::from_slice(&[0x10; 10]) }
fn nullifier() -> Principal { Principal::from_slice(&[0x11; 10]) }
fn merkle() -> Principal { Principal::from_slice(&[0x12; 10]) }
fn controller() -> Principal { Principal::from_slice(&[0xC0; 10]) }
fn depositor() -> Principal { Principal::from_slice(&[0xA1; 10]) }

fn deploy_pool(pic: &PocketIc) -> Principal {
    let pool = create_canister(pic);
    install(
        pic,
        pool,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token(),
            nullifier_canister: nullifier(),
            merkle_canister: merkle(),
            treasury_canister: Principal::from_slice(&[0x01; 10]),
            staking_canister: Principal::from_slice(&[0x02; 10]),
            controller: controller(),
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
            verifier_canister: None,
        },
    );
    pool
}

// Re-implementation of the pool's canonical deployment-config hash, so the tests
// can construct a matching (or deliberately wrong) expected hash.
//   SHA-256( "stsh.deployment-config.v1" ‖ u32_be(1) ‖ P(pool) ‖ P(token) ‖ P(merkle) ‖ P(nullifier) )
//   P(x) = u8(len) ‖ raw principal bytes
fn deployment_hash(pool: Principal, token: Principal, merkle: Principal, nullifier: Principal) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"stsh.deployment-config.v1");
    h.update(1u32.to_be_bytes());
    for p in [pool, token, merkle, nullifier] {
        let bytes = p.as_slice();
        h.update([bytes.len() as u8]);
        h.update(bytes);
    }
    h.finalize().into()
}

fn attestation(pic: &PocketIc, pool: Principal) -> DeploymentAttestation {
    let bytes = pic
        .query_call(pool, controller(), "get_deployment_attestation", candid::encode_args(()).unwrap())
        .expect("get_deployment_attestation rejected");
    let res: Result<DeploymentAttestation, PoolError> = candid::decode_one(&bytes).expect("decode attestation");
    res.expect("attestation Ok")
}

// shield_deposit as `depositor` with an explicit expected hash. Returns the
// Result so tests can assert Ok vs the specific PoolError.
fn shield(pic: &PocketIc, pool: Principal, expected: Option<[u8; 32]>) -> Result<u128, PoolError> {
    let args = ShieldDepositArgs {
        note_commitment: [3u8; 32],
        encrypted_payload: vec![],
        public_amount: 1, // a valid denomination — so the gate, not the denom check, is what fails
        expected_deployment_config_hash: expected,
    };
    decode("shield_deposit", pic.update_call(pool, depositor(), "shield_deposit", candid::encode_one(args).unwrap()))
}

/// PocketIC instance clock (ns) — timestamps handed to the canister must derive
/// from here, not the host clock.
fn pic_now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

/// A private_spend with an explicit deployment hash and a deliberately-INVALID
/// circuit_version (99). If the P-DOM gate is bypassed, this reaches
/// verify_proof_envelope and fails with CircuitVersionMismatch — so a wrong-hash
/// call returning DeploymentConfigMismatch proves the gate runs BEFORE proof /
/// verifier / idempotency handling and before any record write. It also fires
/// maybe_activate_pending_vk (at the top of verify_proof_envelope) whenever the
/// gate passes, which the VK-activation test relies on.
fn spend(pic: &PocketIc, pool: Principal, spend_id: u64, expected: Option<[u8; 32]>) -> Result<(), PoolError> {
    let args = PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version: 99, // != pinned — CircuitVersionMismatch if the gate is bypassed
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: [9u8; 32],
            pool_version: 1,
            proof_bytes: vec![0u8; 256],
        },
                nullifiers: vec![[7u8; 32]],
        output_commitments: vec![[8u8; 32], [10u8; 32]],
        encrypted_outputs: vec![vec![0xAA], vec![0xBB]],
        fee: 0,
        public_payout: None,
        expected_deployment_config_hash: expected,
    };
    decode("private_spend", pic.update_call(pool, depositor(), "private_spend", candid::encode_one(args).unwrap()))
}

/// Inject a pre-existing spend record (testing endpoint) under `spend_id`, owned by
/// `submitter`. Lets the gate-ordering test place a record the idempotency lookup
/// WOULD short-circuit on, so a wrong-hash call returning DeploymentConfigMismatch
/// proves the gate runs ahead of that lookup.
fn inject_spend(pic: &PocketIc, pool: Principal, spend_id: u64, submitter: Principal) {
    let rec = PendingSpend {
        spend_id,
        nullifiers: vec![],
        output_commitments: vec![],
        public_payout: None,
        outputs_committed: 0,
        fee: Some(0),
        status: SpendStatus::VerificationPending,
        created_at_ns: 1,
        submitter: Some(submitter),
        finalized_at_ns: None,
        fee_model_version: None,
        params_epoch: None,
        spend_fee_mode: None,
        fee_split_ops: None,
        fee_split_insurance: None,
        fee_split_staking: None,
    };
    let _: u64 = decode(
        "inject_pending_spend_for_test",
        pic.update_call(pool, controller(), "inject_pending_spend_for_test", candid::encode_one(rec).unwrap()),
    );
}

fn deploy_stub_verifier(pic: &PocketIc, reported_hash: Option<[u8; 32]>) -> Principal {
    let stub = create_canister(pic);
    pic.install_canister(stub, stub_verifier_wasm(), candid::encode_one(reported_hash).unwrap(), None);
    stub
}

fn set_verifier(pic: &PocketIc, pool: Principal, verifier: Principal, expected: Vec<u8>) -> Result<(), PoolError> {
    decode(
        "set_verifier_canister",
        pic.update_call(pool, controller(), "set_verifier_canister", candid::encode_args((verifier, expected)).unwrap()),
    )
}

fn schedule_vk(pic: &PocketIc, pool: Principal, new_version: u32, new_hash: [u8; 32], activation_ns: u64, cutoff_ns: u64) -> Result<(), String> {
    // Governance-gated: the staking canister principal is the governance authority.
    decode(
        "schedule_vk_activation",
        pic.update_call(
            pool,
            Principal::from_slice(&[0x02; 10]), // staking() = governance authority
            "schedule_vk_activation",
            candid::encode_args((new_version, new_hash, activation_ns, cutoff_ns)).unwrap(),
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-closed on mismatch; proceed on match / None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_matching_hash_passes_the_gate() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let good = deployment_hash(pool, token(), merkle(), nullifier());
    // The gate passes; the deposit then fails LATER (no token canister to call),
    // but NOT with DeploymentConfigMismatch — that's the point.
    let res = shield(&pic, pool, Some(good));
    assert_ne!(res, Err(PoolError::DeploymentConfigMismatch), "a matching hash must pass the gate");
}

#[test]
fn test_none_hash_skips_the_gate_decode_compat() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let res = shield(&pic, pool, None);
    assert_ne!(res, Err(PoolError::DeploymentConfigMismatch), "None skips the gate (decode-compat)");
}

#[test]
fn test_self_binding_wrong_pool_same_deps_rejected() {
    // THE self-binding test (V3.8.3 Critical): a hash computed for a DIFFERENT pool
    // principal but the SAME token/merkle/nullifier must be rejected — the pool's
    // OWN principal is bound FIRST, so a different pool cannot pass with matching deps.
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let wrong_pool = Principal::from_slice(&[0xEE; 10]);
    let wrong = deployment_hash(wrong_pool, token(), merkle(), nullifier());
    assert_eq!(shield(&pic, pool, Some(wrong)), Err(PoolError::DeploymentConfigMismatch));
}

#[test]
fn test_each_wiring_dependency_mismatch_rejected_independently() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let other = Principal::from_slice(&[0xDD; 10]);
    // wrong token
    assert_eq!(
        shield(&pic, pool, Some(deployment_hash(pool, other, merkle(), nullifier()))),
        Err(PoolError::DeploymentConfigMismatch),
        "wrong token"
    );
    // wrong merkle
    assert_eq!(
        shield(&pic, pool, Some(deployment_hash(pool, token(), other, nullifier()))),
        Err(PoolError::DeploymentConfigMismatch),
        "wrong merkle"
    );
    // wrong nullifier
    assert_eq!(
        shield(&pic, pool, Some(deployment_hash(pool, token(), merkle(), other))),
        Err(PoolError::DeploymentConfigMismatch),
        "wrong nullifier"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// private_spend is gated too (BOTH entrypoints — brief requirement)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_private_spend_gate_rejects_wrong_hash_before_any_effect() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let wrong = deployment_hash(Principal::from_slice(&[0xEE; 10]), token(), merkle(), nullifier());

    let good = deployment_hash(pool, token(), merkle(), nullifier());

    // The spend carries a deliberately-invalid circuit_version (99). If the gate ran
    // AFTER proof-envelope validation we would see CircuitVersionMismatch; if after
    // the verifier path, VerifierUnavailable (no verifier configured). Getting
    // DeploymentConfigMismatch proves the gate fires FIRST.
    assert_eq!(
        spend(&pic, pool, 1, Some(wrong)),
        Err(PoolError::DeploymentConfigMismatch),
        "private_spend must fail closed on a wrong deployment hash, ahead of everything else"
    );

    // (1) The rejected call left NO record: retry the SAME spend_id=1 with the
    // CORRECT hash. It passes the gate and fails at proof-envelope validation
    // (CircuitVersionMismatch). If the wrong-hash call had written a record (i.e. the
    // gate ran after record creation), this retry would instead short-circuit at the
    // idempotency check with DuplicateSpendId / IdempotencyKeyConflict.
    let retry = spend(&pic, pool, 1, Some(good));
    assert!(
        matches!(retry, Err(PoolError::CircuitVersionMismatch { got: 99, .. })),
        "retrying id=1 after a gate rejection must proceed fresh (no prior record), got {:?}",
        retry
    );

    // (2) Gate is AHEAD of the idempotency lookup: inject a pre-existing spend under
    // id=500 owned by ANOTHER principal, then call id=500 with a WRONG hash. If the
    // gate ran after the idempotency lookup, the foreign record would short-circuit
    // with DuplicateSpendId; getting DeploymentConfigMismatch proves the gate runs
    // BEFORE the lookup.
    inject_spend(&pic, pool, 500, Principal::from_slice(&[0xF0; 10]));
    assert_eq!(
        spend(&pic, pool, 500, Some(wrong)),
        Err(PoolError::DeploymentConfigMismatch),
        "the gate must reject a wrong hash BEFORE the idempotency lookup finds the injected record"
    );
    // Control: the SAME injected id with a CORRECT hash DOES reach the idempotency
    // lookup and short-circuits on the foreign record (DuplicateSpendId) — confirming
    // the record is really there and only the gate ordering, not its absence, drove
    // the DeploymentConfigMismatch above.
    assert_eq!(
        spend(&pic, pool, 500, Some(good)),
        Err(PoolError::DuplicateSpendId),
        "a matching hash reaches the idempotency lookup and sees the injected foreign record"
    );

    // None (decode-compat) also passes the gate.
    assert_ne!(spend(&pic, pool, 3, None), Err(PoolError::DeploymentConfigMismatch));
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation getter + pinned byte-vector fixture
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_attestation_matches_enforced_wiring() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let att = attestation(&pic, pool);
    assert_eq!(att.pool, pool);
    assert_eq!(att.token, token());
    assert_eq!(att.merkle, merkle());
    assert_eq!(att.nullifier, nullifier());
    assert_eq!(att.config_version, 1);
    // The attested config_hash equals the independently-recomputed hash AND the
    // hash the gate enforces (shield with it passes the gate).
    let recomputed = deployment_hash(pool, token(), merkle(), nullifier());
    assert_eq!(att.config_hash, recomputed, "attested hash == canonical recomputation");
    assert_ne!(shield(&pic, pool, Some(att.config_hash)), Err(PoolError::DeploymentConfigMismatch));
    // Mutable fields ARE surfaced (advisory) but are not part of the hash — see the
    // VK-swap test below.
    assert_eq!(att.proof_system, "groth16-bn254");
}

#[test]
fn test_encoding_matches_literal_pinned_digest() {
    // A LITERAL pinned digest (independently computed once, hardcoded) for a fully-
    // known principal set — pool=[0xAB;10], token=[0xCD;10], merkle=[0xEF;10],
    // nullifier=[0x01;10]. A silent change to the domain / version width /
    // length-prefix / field order breaks this exact-byte assertion.
    const PINNED: [u8; 32] = [
        0x5a, 0x0d, 0x4a, 0xbd, 0x89, 0x24, 0x9e, 0xa6, 0xb0, 0x96, 0x51, 0xf7, 0x10, 0xb1, 0xd0, 0xfe,
        0x90, 0x68, 0x97, 0xa3, 0xb8, 0xdd, 0x59, 0xb6, 0xce, 0xe5, 0x0d, 0xd5, 0x3e, 0x1d, 0x8e, 0x44,
    ];
    let got = deployment_hash(
        Principal::from_slice(&[0xAB; 10]),
        Principal::from_slice(&[0xCD; 10]),
        Principal::from_slice(&[0xEF; 10]),
        Principal::from_slice(&[0x01; 10]),
    );
    assert_eq!(got, PINNED, "the encoding must match the pinned literal digest byte-for-byte");
}

#[test]
fn test_field_boundary_ambiguity_defeated_by_length_prefix() {
    // Second-preimage probe across the token|merkle boundary: two DIFFERENT wirings
    // whose RAW principal-byte concatenation is IDENTICAL but whose length-prefixed
    // canonical encodings differ. Without the u8 length prefix these would collide;
    // with it, the canonical hashes MUST differ.
    let pool = Principal::from_slice(&[0x09; 10]);
    let nul = Principal::from_slice(&[0x08; 10]);
    // token|merkle raw bytes are [0x01,0x02,0x03] in BOTH tuples, split differently.
    let a = deployment_hash(pool, Principal::from_slice(&[0x01, 0x02]), Principal::from_slice(&[0x03]), nul);
    let b = deployment_hash(pool, Principal::from_slice(&[0x01]), Principal::from_slice(&[0x02, 0x03]), nul);

    // Sanity: the raw (unprefixed) concatenations really do collide — so only the
    // length prefix distinguishes them.
    let raw_a: Vec<u8> = [[0x01u8, 0x02].as_slice(), [0x03].as_slice()].concat();
    let raw_b: Vec<u8> = [[0x01u8].as_slice(), [0x02, 0x03].as_slice()].concat();
    assert_eq!(raw_a, raw_b, "the token|merkle raw byte streams are identical by construction");

    assert_ne!(a, b, "length-prefixed canonical hashes must differ across the field boundary");
}

// ─────────────────────────────────────────────────────────────────────────────
// VK/verifier/circuit are EXCLUDED — a legitimate swap leaves the hash unchanged
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_successful_verifier_replacement_and_real_vk_activation_leave_config_hash_unchanged() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic); // initial pin = [0u8;32], circuit version = 0
    let before = attestation(&pic, pool);
    let config_hash = before.config_hash;
    assert_eq!(before.vk_hash, [0u8; 32]);
    assert_eq!(before.circuit_version, 0);
    assert!(before.verifier.is_none());

    // ── (1) SUCCESSFUL verifier replacement ────────────────────────────────────
    // A stub verifier that reports the pool's pin ([0;32]) so the attestation check
    // in set_verifier_canister PASSES. Assert Ok, and that the attestation reflects
    // the new verifier — a real replacement, not a failed one.
    let stub = deploy_stub_verifier(&pic, Some([0u8; 32]));
    assert_eq!(set_verifier(&pic, pool, stub, vec![0u8; 32]), Ok(()), "verifier replacement must succeed");
    let after_verifier = attestation(&pic, pool);
    assert_eq!(after_verifier.verifier, Some(stub), "attestation reflects the replaced verifier");
    assert_eq!(after_verifier.config_hash, config_hash, "verifier replacement leaves the config hash unchanged");

    // ── (2) ACTUAL VK activation ───────────────────────────────────────────────
    // Governance schedules a new key; after the activation timestamp a proof-
    // envelope validation actually promotes it (maybe_activate_pending_vk). Assert
    // the attested MUTABLE state (vk_hash + circuit_version) genuinely changes.
    let new_vk = [0x55u8; 32];
    let new_version = 5u32;
    let now = pic_now_ns(&pic);
    let activation = now + 3_600_000_000_000; // +1h
    let cutoff = now + 172_800_000_000_000; // +48h
    assert_eq!(schedule_vk(&pic, pool, new_version, new_vk, activation, cutoff), Ok(()), "schedule must succeed");
    // Not yet active — scheduling alone does not promote.
    assert_eq!(attestation(&pic, pool).vk_hash, [0u8; 32], "scheduling does not activate immediately");

    // Advance past the activation timestamp, then trigger a proof-envelope validation
    // (a doomed private_spend that passes the P-DOM gate with the correct hash and
    // runs maybe_activate_pending_vk at the top of verify_proof_envelope).
    pic.advance_time(std::time::Duration::from_secs(2 * 3_600));
    pic.tick();
    let triggered = spend(&pic, pool, 1, Some(config_hash));
    assert_ne!(triggered, Err(PoolError::DeploymentConfigMismatch), "the activation trigger must pass the gate");

    let after_activation = attestation(&pic, pool);
    assert_eq!(after_activation.vk_hash, new_vk, "the VK was actually activated (attested vk_hash changed)");
    assert_eq!(after_activation.circuit_version, new_version, "the circuit version was actually activated");
    assert_ne!(after_activation.vk_hash, before.vk_hash, "mutable VK state genuinely changed");

    // ── (3) config hash UNCHANGED across BOTH the replacement AND the activation ──
    assert_eq!(
        after_activation.config_hash, config_hash,
        "neither a verifier replacement nor a real VK activation may change the deployment-config hash"
    );
    // And the original hash still passes the gate after both events.
    assert_ne!(shield(&pic, pool, Some(config_hash)), Err(PoolError::DeploymentConfigMismatch));
}

// ─────────────────────────────────────────────────────────────────────────────
// Upgrade-preservation of the wiring + hash
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_config_hash_preserved_across_upgrade() {
    let pic = PocketIc::new();
    let pool = deploy_pool(&pic);
    let before = attestation(&pic, pool).config_hash;

    // Advance the simulated clock well past the install_code rate-limit window
    // (the ~1.3 MB Wasm install + upgrade back-to-back would otherwise trip it).
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(pool, pool_prod_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("prod upgrade should succeed");

    // After a real upgrade to the PRODUCTION Wasm the wiring is preserved, so the
    // recomputed hash is identical and still gates shield.
    let after = attestation(&pic, pool).config_hash;
    assert_eq!(before, after, "the deployment-config hash is preserved across upgrade");
    assert_eq!(shield(&pic, pool, Some(before)).is_err(), true); // (no token canister) but not a gate mismatch:
    assert_ne!(shield(&pic, pool, Some(before)), Err(PoolError::DeploymentConfigMismatch));
    // A stale/wrong hash still fails closed after the upgrade.
    let wrong = deployment_hash(Principal::from_slice(&[0xEE; 10]), token(), merkle(), nullifier());
    assert_eq!(shield(&pic, pool, Some(wrong)), Err(PoolError::DeploymentConfigMismatch));
}
