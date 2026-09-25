// =============================================================================
// STSH — Consolidated DEF lane: denomination rejection + upgrade persistence
// DEF-090 (shield denomination), DEF-103 (VK-window / verifier / fee-params
// persistence across pool upgrade).
// =============================================================================
//
// Harness: production pool Wasm + real verifier canister (DEF-083 pool-gated).
// Token/nullifier/merkle refs are inert placeholder principals — every test
// here either rejects before any cross-canister call (DEF-090, the DEF-103
// dummy-spend triggers) or touches only pool-local state (DEF-103 setters).
//
// DEF-103 test 1 observability note: the pool has NO query for the pending VK
// window (deliberately). Persistence is proven behaviourally instead:
// maybe_activate_pending_vk() runs at the top of every proof-envelope
// validation (private_spend step 1, before any cross-canister call), and a
// returned Err does not roll back state. So a well-formed-but-doomed spend
// attempt is a state-safe activation trigger, and the PUBLIC get_pinned_vk_hash
// query observes the outcome: if the scheduled window survived the upgrade, the
// pinned hash flips to the scheduled hash once time passes activation — if the
// window had been lost, it never could.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm loading ──────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}

fn pool_wasm()     -> Vec<u8> { load_wasm(env!("POOL_WASM"),     "shielded_pool") }
// RB-SWARM-A1: carries `set_governance_fee_params_unchecked_for_test`, which the
// fee-params upgrade test needs — the guarded setter's RULED floors make the
// arbitrary split-neutral tweak that test performs unrepresentable.
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn verifier_wasm() -> Vec<u8> { load_wasm(env!("VERIFIER_WASM"), "stsh_verifier") }

// ── Candid mirrors (field/variant names must match the canister exactly) ──────

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
struct ShieldDepositArgs {
    note_commitment:   [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount:     u128,
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
struct PrivateSpendArgs {
    spend_id:           u64,
    envelope:           ProofEnvelope,
    nullifiers:         Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs:  Vec<Vec<u8>>,
    fee:                u128,
}

// Only the variants a test in THIS file can actually receive need to decode;
// the full production enum is a superset (candid decodes by variant name).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination,
    Paused,
    AnonymousCaller,
    InvalidCommitment,
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    TransferFailed(String),
    NotInitialised,
}

/// Mirror of stsh_fee_policy::SpendFeeMode.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum SpendFeeMode {
    FixedStsh,
    XdrPegged,
}

/// Mirror of GovernanceFeeParams (docs/STSH_FEE_POLICY.md §20; field names per
/// shielded_pool.did).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct GovernanceFeeParams {
    protocol_shielding_fee_stsh:          u128,
    protocol_unshielding_fee_stsh:        u128,
    protocol_private_spend_fee_stsh:      u128,
    minimum_withdrawal_gross:             u128,
    minimum_recipient_amount:             u128,
    minimum_private_credit:               u128,
    fee_reference_price_stsh_per_icp_e8s: u128,
    fee_safety_margin_bps:                u32,
    max_fee_change_bps_per_update:        u32,
    fee_update_cooldown_ns:               u64,
    operations_split_bps:                 u32,
    insurance_split_bps:                  u32,
    staking_rewards_split_bps:            u32,
    staking_rewards_enabled:              bool,
    minimum_treasury_runway_months:       u32,
    target_treasury_runway_months:        u32,
    // Value fees (fee-build lane).
    shield_fee_bps:                       Option<u16>,
    unshield_fee_bps:                     Option<u16>,
    shield_flat_minimum_fee_e8s:          Option<u128>,
    unshield_flat_minimum_fee_e8s:        Option<u128>,
    spend_fee_mode:                       Option<SpendFeeMode>,
    fee_model_version:                    Option<u32>,
    params_epoch:                         Option<u64>,
}

// ── PocketIC helpers ──────────────────────────────────────────────────────────

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

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

/// Pool (production Wasm) + real verifier. Controller p(0x06), governance
/// (staking) p(0x02), user p(0xB0). Returns (pool_id, verifier_id).
fn setup_pool(pic: &PocketIc) -> (Principal, Principal) {
    setup_pool_with(pic, pool_wasm())
}

/// Same stack on the `_test` Wasm (RB-SWARM-A1).
fn setup_pool_testing(pic: &PocketIc) -> (Principal, Principal) {
    setup_pool_with(pic, pool_test_wasm())
}

fn setup_pool_with(pic: &PocketIc, pool_module: Vec<u8>) -> (Principal, Principal) {
    let pool_id  = create_canister(pic);
    let verifier = create_canister(pic);

    // DEF-083: verifier is pool-caller-gated — bind to this pool at install.
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool_id).unwrap(), None);

    pic.install_canister(
        pool_id,
        pool_module,
        candid::encode_one(&PoolInitArgs {
            token_canister:       p(0x10),
            nullifier_canister:   p(0x11),
            merkle_canister:      p(0x12),
            treasury_canister:    p(0x04),
            staking_canister:     p(0x02),
            controller:           p(0x06),
            initial_vk_hash:      stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .unwrap(),
        None,
    );

    // Wire the verifier (operator-controller; runs the vk_hash attestation).
    pic.update_call(
        pool_id, p(0x06), "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    ).expect("set_verifier_canister must succeed");

    (pool_id, verifier)
}

fn upgrade_pool(pic: &PocketIc, pool_id: Principal) {
    pic.upgrade_canister(pool_id, pool_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade (pre/post_upgrade) must succeed");
}

/// Upgrade `_test` -> `_test`. A pool installed from the `_test` Wasm must be
/// upgraded to the same one: the two differ only by the build-gated test
/// endpoints, but an upgrade must not silently swap the module under a test.
fn upgrade_pool_testing(pic: &PocketIc, pool_id: Principal) {
    pic.upgrade_canister(pool_id, pool_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade (pre/post_upgrade) must succeed");
}

fn pinned_vk_hash(pic: &PocketIc, pool_id: Principal) -> Vec<u8> {
    decode(
        "get_pinned_vk_hash",
        pic.query_call(pool_id, p(0xB0), "get_pinned_vk_hash", candid::encode_args(()).unwrap()),
    )
}

/// Well-formed-but-doomed private_spend: passes the size caps, reaches the
/// proof-envelope check (step 1 — which runs maybe_activate_pending_vk), then
/// fails locally (unaccepted anchor) BEFORE any cross-canister call. The reply
/// bytes are deliberately not decoded — only the state side effect matters.
/// `spend_id` must be unique per call: a failed attempt still writes a terminal
/// record (DEF-072), and a reused id short-circuits at the duplicate-id check
/// BEFORE the envelope validation this trigger exists to reach.
fn trigger_envelope_validation(pic: &PocketIc, pool_id: Principal, spend_id: u64) {
    let args = PrivateSpendArgs {
        spend_id,
        envelope: ProofEnvelope {
            circuit_version:    0,
            proof_system_id:    "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference:     [9u8; 32], // canonical, never accepted
            pool_version:       1,
            proof_bytes:        vec![0u8; 256],
        },
                nullifiers:         vec![[7u8; 32]],
        output_commitments: vec![[8u8; 32], [10u8; 32]],
        encrypted_outputs:  vec![vec![0xAA], vec![0xBB]],
        fee:                0,
    };
    // An Err REPLY still lands as Ok(bytes) here; only a canister trap would be
    // Err — and a trap would mean the trigger design is broken, so surface it.
    pic.update_call(pool_id, p(0xB0), "private_spend", candid::encode_one(args).unwrap())
        .expect("trigger spend must reply (Err(PoolError) expected), not trap");
}

/// PocketIC instance clock — NOT SystemTime. The instance's genesis time is not
/// tied to the host clock, and advance_time moves only the instance clock, so
/// every timestamp given to the canister must be derived from here.
fn pic_now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-090 — shield_deposit rejects a non-denomination amount
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_shield_invalid_denomination() {
    let pic = PocketIc::new();
    let (pool_id, _verifier) = setup_pool(&pic);

    // 5 is not in DENOMINATIONS ([1k, 10k, 100k, 1M, 10M] STSH in base units). The
    // denomination gate fires before any token interaction, so the placeholder
    // token principal is never called.
    let result: Result<Nat, PoolError> = decode(
        "shield_deposit (invalid denomination)",
        pic.update_call(
            pool_id, p(0xB0), "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment:   [1u8; 32],
                encrypted_payload: vec![],
                public_amount:     5,
            }).unwrap(),
        ),
    );
    assert_eq!(
        result, Err(PoolError::InvalidDenomination),
        "amount 5 must be rejected as InvalidDenomination"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-103 — upgrade persistence: VK activation window
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_vk_activation_window_survives_upgrade() {
    let pic = PocketIc::new();
    let (pool_id, _verifier) = setup_pool(&pic);

    let h0 = stsh_verifier::compiled_vk_sha256().to_vec();
    let scheduled_hash = [0xABu8; 32];
    let base_ns = pic_now_ns(&pic);
    let activation_ns = base_ns + 24 * 3600 * 1_000_000_000;
    let cutoff_ns     = base_ns + 48 * 3600 * 1_000_000_000;

    // Governance (the staking canister principal) schedules the VK window.
    let scheduled: Result<(), String> = decode(
        "schedule_vk_activation",
        pic.update_call(
            pool_id, p(0x02), "schedule_vk_activation",
            candid::encode_args((0u32, scheduled_hash, activation_ns, cutoff_ns)).unwrap(),
        ),
    );
    scheduled.expect("schedule_vk_activation must succeed");
    assert_eq!(pinned_vk_hash(&pic, pool_id), h0, "scheduling must not activate immediately");

    // Upgrade the pool MID-WINDOW.
    upgrade_pool(&pic, pool_id);

    // Still inside the window: an envelope validation must NOT activate — this
    // also proves PENDING_VK_ACTIVE_AT survived (a lost/zeroed timestamp would
    // fire here).
    trigger_envelope_validation(&pic, pool_id, 10_300);
    assert_eq!(
        pinned_vk_hash(&pic, pool_id), h0,
        "pending window fired before its activation timestamp after upgrade"
    );

    // Advance past activation and trigger again: the scheduled hash must
    // activate — possible ONLY if the pending window survived the upgrade.
    pic.advance_time(Duration::from_secs(72 * 3600));
    pic.tick();
    trigger_envelope_validation(&pic, pool_id, 10_301);
    assert_eq!(
        pinned_vk_hash(&pic, pool_id),
        scheduled_hash.to_vec(),
        "DEF-103: pending VK activation window was lost across the pool upgrade"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-103 — upgrade persistence: verifier canister principal
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_verifier_canister_survives_upgrade() {
    let pic = PocketIc::new();
    let (pool_id, verifier) = setup_pool(&pic);

    let before: Option<Principal> = decode(
        "get_verifier_canister (pre-upgrade)",
        pic.query_call(pool_id, p(0xB0), "get_verifier_canister", candid::encode_args(()).unwrap()),
    );
    assert_eq!(before, Some(verifier), "setup must have wired the verifier");

    // Advance the simulated clock past the install_code rate-limit window
    // before the back-to-back upgrade (established pattern from
    // pdom_deployment_binding_tests). Under the P-ARITH R-1 release profile
    // (overflow-checks) the pool install + upgrade in one window executes
    // enough extra instructions to trip PocketIC's per-canister install_code
    // budget — a harness limit, not a canister defect. This test has no
    // time-window semantics (unlike test_vk_activation_window_survives_upgrade,
    // whose 24h/48h VK window must NOT be fast-forwarded).
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }

    upgrade_pool(&pic, pool_id);

    let after: Option<Principal> = decode(
        "get_verifier_canister (post-upgrade)",
        pic.query_call(pool_id, p(0xB0), "get_verifier_canister", candid::encode_args(()).unwrap()),
    );
    assert_eq!(
        after, Some(verifier),
        "DEF-103: verifier principal was lost across the pool upgrade"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-103 — upgrade persistence: governance fee params
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_governance_fee_params_survive_upgrade() {
    let pic = PocketIc::new();
    let (pool_id, _verifier) = setup_pool_testing(&pic);

    // Read-modify-write: change non-split fields only, so validate_split_bps
    // (splits must sum to 10_000) keeps passing without knowing launch values.
    // RB-SWARM-A1: this goes through the test-only unguarded setter. The point
    // under test is upgrade PERSISTENCE of whatever is live, not the guardrails
    // — and the guarded setter would (correctly) refuse a params record built
    // from the fee-free launch defaults.
    let mut params: GovernanceFeeParams = decode(
        "get_governance_fee_params (launch)",
        pic.query_call(pool_id, p(0xB0), "get_governance_fee_params", candid::encode_args(()).unwrap()),
    );
    params.fee_reference_price_stsh_per_icp_e8s += 12_345;
    params.minimum_private_credit += 7;

    let set: Result<(), String> = decode(
        "set_governance_fee_params_unchecked_for_test",
        pic.update_call(
            pool_id, p(0x06), "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(&params).unwrap(),
        ),
    );
    set.expect("set_governance_fee_params_unchecked_for_test must succeed");

    // The canister stamps the epoch itself — the caller never chooses it.
    params.params_epoch = Some(params.params_epoch.unwrap_or(0) + 1);

    let before: GovernanceFeeParams = decode(
        "get_governance_fee_params (pre-upgrade)",
        pic.query_call(pool_id, p(0xB0), "get_governance_fee_params", candid::encode_args(()).unwrap()),
    );
    assert_eq!(before, params, "setter must persist the modified params");

    upgrade_pool_testing(&pic, pool_id);

    let after: GovernanceFeeParams = decode(
        "get_governance_fee_params (post-upgrade)",
        pic.query_call(pool_id, p(0xB0), "get_governance_fee_params", candid::encode_args(()).unwrap()),
    );
    assert_eq!(
        after, params,
        "DEF-103: governance fee params were lost/reset across the pool upgrade"
    );
}
