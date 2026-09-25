//! STSH ZK Spend Verifier — Production Groth16/BN254
//!
//! Provides `verify_spend()` for the shielded_pool canister, replacing
//! `verify_proof_stub()` as the M4-ZK-A2 deliverable.
//!
//! The verifying key is compiled into the binary at build time via `include_str!`.
//! The file `circuits/verification_key.json` **must exist** when running
//! `cargo build --target wasm32-unknown-unknown` (generated during the trusted setup;
//! available in WSL2 at ~/stsh/circuits/verification_key.json after A0).
//!
//! HARD CONSTRAINTS (from M4-ZK-A2 scope):
//!   - VK is NEVER supplied by the caller — compiled-in or governance-controlled only.
//!   - No raw proof JSON over Candid in production — proof_bytes (256-byte compact) only.
//!   - verify_proof_stub() must not exist in production build.
//!
//! Public API:
//!   verify_spend(proof_bytes, signals) -> Result<bool, VerifierError>
//!   compiled_vk_sha256()              -> [u8; 32]   (for hash-pin check at init/gate)
//!
//! Signal order (PUBLIC_SIGNALS_BINDING.md) — 9 public signals:
//!   [0] anchor                  BN254 Fr → 32-byte LE
//!   [1] nullifier_hash          BN254 Fr → 32-byte LE
//!   [2] output_merkle_leaf_1    BN254 Fr → 32-byte LE (B-prime value-bound outer leaf)
//!   [3] output_merkle_leaf_2    BN254 Fr → 32-byte LE (B-prime value-bound outer leaf)
//!   [4] public_amount           BN254 Fr → u128 LE (0 for a pure private transfer; >0 for a public payout — DEF-045)
//!   [5] fee                     BN254 Fr → u128 LE (0 at launch — SpendFeeNotSupported)
//!   [6] recipient_principal     BN254 Fr → 32-byte LE (DEF-026; 0 when no public payout)
//!   [7] recipient_subaccount_lo BN254 Fr → 32-byte LE (DEF-026; low 16 bytes of the subaccount)
//!   [8] recipient_subaccount_hi BN254 Fr → 32-byte LE (DEF-026; high 16 bytes of the subaccount)
//!
//! Proof byte layout (SNARKJS_TO_CANDID_ENCODING.md §"Compact Binary"):
//!   [  0.. 64) G1 pi_a:  x_LE(32) || y_LE(32)
//!   [ 64..192) G2 pi_b:  x_c0_LE(32) || x_c1_LE(32) || y_c0_LE(32) || y_c1_LE(32)
//!   [192..256) G1 pi_c:  x_LE(32) || y_LE(32)
//!   Total: 256 bytes

#![forbid(unsafe_code)]

use ark_bn254::{Bn254, Fr, Fq, Fq2, G1Affine, G2Affine};
use stsh_field_utils::{is_canonical_fq_le, is_canonical_fr_le};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, PreparedVerifyingKey, VerifyingKey, prepare_verifying_key};
use num_bigint::BigUint;
use sha2::{Sha256, Digest};

// ─────────────────────────────────────────────────────────────────────────────
// Compiled-in VK
// ─────────────────────────────────────────────────────────────────────────────
//
// REQUIREMENT: circuits/verification_key.json must exist at cargo build time.
// Produced by the production trusted-setup ceremony (M5, 2026-07-07) and
// committed at circuits/verification_key.json.

const VK_JSON: &str = include_str!("../../../circuits/verification_key.json");

// ─────────────────────────────────────────────────────────────────────────────
// PreparedVerifyingKey cache
// ─────────────────────────────────────────────────────────────────────────────
//
// Parsing VK JSON + calling prepare_verifying_key() is done once per canister
// instantiation (thread_local! init is lazy in Wasm — runs on first access).
// Subsequent calls to get_pvk() return the already-prepared key at near-zero cost.

thread_local! {
    static CACHED_PVK: PreparedVerifyingKey<Bn254> = {
        parse_vk_json(VK_JSON)
            .expect("BUG: compiled-in VK_JSON is not a valid snarkjs verification_key.json — \
                     regenerate circuits/verification_key.json and rebuild")
    };

    /// DEF-083: the shielded-pool principal authorized to call the proof-verification
    /// endpoints. Set at init, persisted across upgrades via pre/post_upgrade
    /// (stable_save/stable_restore — this canister has no other stable state).
    static AUTHORIZED_POOL: std::cell::RefCell<Option<candid::Principal>> =
        std::cell::RefCell::new(None);
}

fn get_pvk() -> PreparedVerifyingKey<Bn254> {
    CACHED_PVK.with(|pvk| pvk.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-083: authorized-pool caller guard + init / upgrade persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Trap unless the caller is the authorized shielded-pool principal set at init.
/// Applied to every proof-verification entrypoint (verify_spend_canister and the
/// A2-1 benchmark endpoint). vk_hash stays public — it is a read-only binding
/// check with no verification cost to abuse.
fn assert_pool_caller() {
    let authorized = AUTHORIZED_POOL.with(|p| *p.borrow());
    match authorized {
        Some(p) if ic_cdk::caller() == p => {}
        _ => ic_cdk::trap("unauthorized: only the authorized shielded-pool may call proof verification"),
    }
}

/// DEF-083: bind the authorized shielded-pool principal at install time.
/// The mainnet deployment manifest asserts AUTHORIZED_POOL == shielded_pool
/// principal post-deploy (DEF-081).
#[ic_cdk_macros::init]
fn init(pool_principal: candid::Principal) {
    AUTHORIZED_POOL.with(|p| *p.borrow_mut() = Some(pool_principal));
}

/// DEF-083: AUTHORIZED_POOL is heap-only and would be wiped by an upgrade —
/// persist it explicitly. This canister has no other mutable state (the VK is
/// compiled in), so classic stable_save/restore of the single value suffices.
#[ic_cdk_macros::pre_upgrade]
fn pre_upgrade() {
    let p = AUTHORIZED_POOL.with(|a| *a.borrow());
    ic_cdk::storage::stable_save((p,))
        .expect("pre_upgrade: failed to stable_save AUTHORIZED_POOL");
}

#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    let (p,): (Option<candid::Principal>,) = ic_cdk::storage::stable_restore()
        .expect("post_upgrade: failed to stable_restore AUTHORIZED_POOL — \
                 upgrading a verifier deployed before DEF-083 requires reinstall-with-init, \
                 not upgrade (no pre-DEF-083 deployment exists as of this change)");
    AUTHORIZED_POOL.with(|a| *a.borrow_mut() = p);
}

/// L3e (CUSTODY_VAULT_INTERFACE_FREEZE_V6 §6): canonical read-back of the stored
/// AUTHORIZED_POOL principal. Fails closed — returns Err rather than ever
/// substituting a launch default or echoing a caller expectation:
///   - `None`              → uninitialized (init never ran / not yet restored)
///   - anonymous principal → sentinel value, treated as corrupt
/// Genuine storage corruption fails closed one level down: `post_upgrade`'s
/// `stable_restore` traps on undecodable stable data, so a corrupt value can
/// never reach this function.
fn authorized_pool_readback() -> Result<candid::Principal, String> {
    match AUTHORIZED_POOL.with(|p| *p.borrow()) {
        Some(p) if p == candid::Principal::anonymous() => Err(
            "get_authorized_pool: stored AUTHORIZED_POOL is the anonymous sentinel — \
             refusing read-back (fail-closed)".to_string()
        ),
        Some(p) => Ok(p),
        None => Err(
            "get_authorized_pool: AUTHORIZED_POOL is uninitialized — \
             refusing read-back (fail-closed)".to_string()
        ),
    }
}

/// L3e canonical authority read-back. PUBLIC (freeze §6: the principal is public
/// post-launch; the endpoint's purpose is externally verifiable proof of the
/// born-under-vault wiring). Mutation-free, no caller gate, no rebind counterpart.
/// Traps on uninitialized/sentinel state — never returns a substitute default.
#[ic_cdk_macros::query]
fn get_authorized_pool() -> candid::Principal {
    match authorized_pool_readback() {
        Ok(p) => p,
        Err(e) => ic_cdk::trap(&e),
    }
}

/// The canister's own cycle balance — the interface CONTRACT lane A-6's fleet
/// monitor consumes (GAP-U9-1). Additive query; no state read, no caller check
/// (the value is not sensitive and the monitor may be unauthenticated).
///
/// API: ic-cdk 0.16 — `canister_balance128()` returns u128 -> Candid `nat`.
/// (vetkeys' `canister_cycle_balance()` is 0.20-only; see brief A-6b §1.)
#[ic_cdk_macros::query]
fn cycle_balance() -> u128 {
    ic_cdk::api::canister_balance128()
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum VerifierError {
    /// Input data is malformed (wrong length, bad encoding, point not on curve, etc.)
    ParseError(String),
    /// Proof is structurally valid but does not satisfy the Groth16 verifier equation.
    VerificationFailed,
}

impl core::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifierError::ParseError(s) => write!(f, "VerifierError::ParseError({})", s),
            VerifierError::VerificationFailed => write!(f, "VerifierError::VerificationFailed"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a STSH private_spend Groth16/BN254 proof.
///
/// Replaces `verify_proof_stub()` in `shielded_pool::private_spend`.
///
/// # Arguments
/// - `proof_bytes` — 256-byte compact proof (see SNARKJS_TO_CANDID_ENCODING.md)
/// - `signals`     — 9 × 32-byte LE Fr elements in PUBLIC_SIGNALS_BINDING.md order
///
/// # Returns
/// - `Ok(true)`  — proof is valid; caller should proceed with state mutations
/// - `Ok(false)` — proof is invalid; caller must return `PoolError::InvalidProof`
/// - `Err(e)`    — proof bytes or signals are malformed; treat as InvalidProof
pub fn verify_spend(
    proof_bytes: &[u8],
    signals: &[[u8; 32]; 9],
) -> Result<bool, VerifierError> {
    let inputs = parse_public_inputs(signals)?;
    let proof  = parse_proof_bytes(proof_bytes)?;
    let pvk    = get_pvk();

    // ── Hard binding check: VK must have exactly 10 gamma_abc_g1 entries ─────
    //
    // gamma_abc_g1.len() == number_of_public_inputs + 1.
    // Our circuit has exactly 9 public signals (PUBLIC_SIGNALS_BINDING.md):
    // 6 spend signals + 3 DEF-026 recipient/subaccount signals.
    // If this does not hold, the VK was compiled for a different circuit and
    // we would silently ignore or mismap public inputs.
    let n_ic = pvk.vk.gamma_abc_g1.len();
    if n_ic != 10 {
        return Err(VerifierError::ParseError(format!(
            "VK binding mismatch: expected gamma_abc_g1.len()==10 (9 public signals + 1), \
             got {}. VK was compiled for a circuit with {} public input(s). \
             Regenerate circuits/verification_key.json from the correct spend.circom.",
            n_ic,
            n_ic.saturating_sub(1),
        )));
    }

    // inputs is [Fr; 9] — all 9 signals; zip inside ark consumes all entries.
    let inputs_slice: &[Fr] = &inputs;
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, inputs_slice)
        .map_err(|_| VerifierError::VerificationFailed)?;
    Ok(ok)
}

/// SHA-256 of the compiled-in VK JSON bytes.
///
/// Returned value must match `PINNED_VK_HASH` in the shielded_pool canister.
/// Used by integration tests and governance to confirm the correct VK is active.
pub fn compiled_vk_sha256() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VK_JSON.as_bytes());
    h.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Field element parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a decimal string to BN254 Fq (base field, for G1/G2 coordinates).
fn parse_fq(s: &str) -> Result<Fq, VerifierError> {
    let big = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| VerifierError::ParseError(format!("invalid Fq decimal: {}", s)))?;
    let bytes = {
        let mut b = big.to_bytes_le();
        b.resize(32, 0);
        b
    };
    Ok(Fq::from_le_bytes_mod_order(&bytes))
}

// ─────────────────────────────────────────────────────────────────────────────
// G1 / G2 helpers with explicit curve checks (never panics)
// ─────────────────────────────────────────────────────────────────────────────

/// Construct a G1Affine with an explicit on-curve check.
/// Returns Err instead of panicking when the point is not on the curve.
fn g1_checked(x: Fq, y: Fq, label: &str) -> Result<G1Affine, VerifierError> {
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(VerifierError::ParseError(
            format!("{}: point not on BN254 G1", label)
        ));
    }
    // DEF-113: prime-order subgroup check, kept symmetric with g2_checked. BN254
    // G1 has cofactor 1 so every on-curve point is already in-subgroup (this can
    // never fire), but enforcing it keeps the parse policy correct-by-inspection
    // and robust to any future curve/cofactor change.
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifierError::ParseError(
            format!("{}: G1 point not in prime-order subgroup", label)
        ));
    }
    Ok(p)
}

/// Construct a G2Affine with an explicit on-curve check.
/// Returns Err instead of panicking when the point is not on the curve.
fn g2_checked(x: Fq2, y: Fq2, label: &str) -> Result<G2Affine, VerifierError> {
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(VerifierError::ParseError(
            format!("{}: point not on BN254 G2", label)
        ));
    }
    // DEF-113: reject on-curve points outside the prime-order subgroup. G2 has a
    // large cofactor, so an on-curve check alone admits torsion points; a small-
    // subgroup element in pi_b could otherwise be used to forge/malleate proofs.
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifierError::ParseError(
            format!("{}: G2 point not in prime-order subgroup", label)
        ));
    }
    Ok(p)
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON parsing (snarkjs verification_key.json format)
// ─────────────────────────────────────────────────────────────────────────────

fn parse_g1_json(v: &serde_json::Value) -> Result<G1Affine, VerifierError> {
    let arr = v.as_array()
        .ok_or_else(|| VerifierError::ParseError(
            format!("G1: expected JSON array, got {:?}", v)
        ))?;
    if arr.len() < 2 {
        return Err(VerifierError::ParseError(
            format!("G1: array too short (len={})", arr.len())
        ));
    }
    let x_str = arr[0].as_str()
        .ok_or_else(|| VerifierError::ParseError(
            format!("G1[0]: not a string, got {:?}", arr[0])
        ))?;
    let y_str = arr[1].as_str()
        .ok_or_else(|| VerifierError::ParseError(
            format!("G1[1]: not a string, got {:?}", arr[1])
        ))?;
    let x = parse_fq(x_str)?;
    let y = parse_fq(y_str)?;
    g1_checked(x, y, &format!(
        "G1(x={}…, y={}…)",
        &x_str[..x_str.len().min(12)],
        &y_str[..y_str.len().min(12)],
    ))
}

/// Parse a snarkjs G2 point from a serde_json Value.
///
/// snarkjs format (verified 2026-06-09 by on-curve diagnostic):
///   [[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]]  — c0 at index 0, c1 at index 1
///
/// arkworks: Fq2::new(c0, c1) — ordering matches snarkjs directly.  NO swap.
/// See SNARKJS_TO_CANDID_ENCODING.md §"G2 Coefficient Ordering".
fn parse_g2_json(v: &serde_json::Value) -> Result<G2Affine, VerifierError> {
    let arr = v.as_array()
        .ok_or_else(|| VerifierError::ParseError(
            format!("G2: expected JSON array, got {:?}", v)
        ))?;
    if arr.len() < 2 {
        return Err(VerifierError::ParseError(
            format!("G2: array too short (len={})", arr.len())
        ));
    }
    let x_arr = arr[0].as_array()
        .ok_or_else(|| VerifierError::ParseError(
            format!("G2[0]: expected inner array, got {:?}", arr[0])
        ))?;
    let y_arr = arr[1].as_array()
        .ok_or_else(|| VerifierError::ParseError(
            format!("G2[1]: expected inner array, got {:?}", arr[1])
        ))?;
    if x_arr.len() < 2 || y_arr.len() < 2 {
        return Err(VerifierError::ParseError(
            format!("G2: inner arrays too short (x={}, y={})", x_arr.len(), y_arr.len())
        ));
    }
    // snarkjs: arr[i][0] = c0, arr[i][1] = c1  — verified 2026-06-09
    let x_c0 = parse_fq(x_arr[0].as_str()
        .ok_or_else(|| VerifierError::ParseError(format!("G2 x[0]: not string")))?)?;
    let x_c1 = parse_fq(x_arr[1].as_str()
        .ok_or_else(|| VerifierError::ParseError(format!("G2 x[1]: not string")))?)?;
    let y_c0 = parse_fq(y_arr[0].as_str()
        .ok_or_else(|| VerifierError::ParseError(format!("G2 y[0]: not string")))?)?;
    let y_c1 = parse_fq(y_arr[1].as_str()
        .ok_or_else(|| VerifierError::ParseError(format!("G2 y[1]: not string")))?)?;
    // Fq2::new(c0, c1) — direct mapping, no swap
    g2_checked(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1), "G2")
}

/// Parse a snarkjs `verification_key.json` string into a `PreparedVerifyingKey<Bn254>`.
///
/// Field mapping (snarkjs → arkworks):
///   vk_alpha_1  → alpha_g1  (G1)
///   vk_beta_2   → beta_g2   (G2)
///   vk_gamma_2  → gamma_g2  (G2)
///   vk_delta_2  → delta_g2  (G2)
///   IC          → gamma_abc_g1 (Vec<G1>, nPublic+1 points)
pub fn parse_vk_json(json: &str) -> Result<PreparedVerifyingKey<Bn254>, VerifierError> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| VerifierError::ParseError(format!("VK JSON parse error: {}", e)))?;

    let alpha_g1 = parse_g1_json(&v["vk_alpha_1"])?;
    let beta_g2  = parse_g2_json(&v["vk_beta_2"])?;
    let gamma_g2 = parse_g2_json(&v["vk_gamma_2"])?;
    let delta_g2 = parse_g2_json(&v["vk_delta_2"])?;

    let ic = v["IC"].as_array()
        .ok_or_else(|| VerifierError::ParseError("IC field: not an array".into()))?;
    let gamma_abc_g1: Result<Vec<G1Affine>, _> =
        ic.iter().map(|pt| parse_g1_json(pt)).collect();

    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: gamma_abc_g1?,
    };

    Ok(prepare_verifying_key(&vk))
}

// ─────────────────────────────────────────────────────────────────────────────
// Compact binary proof parsing (256 bytes)
// ─────────────────────────────────────────────────────────────────────────────
//
// Layout (all coordinates LE 32-byte Fq elements):
//   [  0.. 64) G1 pi_a:  x || y
//   [ 64..192) G2 pi_b:  x_c0 || x_c1 || y_c0 || y_c1  (c0-first, matches snarkjs)
//   [192..256) G1 pi_c:  x || y

fn parse_g1_bytes(bytes: &[u8], label: &str) -> Result<G1Affine, VerifierError> {
    if bytes.len() < 64 {
        return Err(VerifierError::ParseError(
            format!("{}: G1 bytes too short ({})", label, bytes.len())
        ));
    }
    // #116: reject non-canonical Fq coordinate encodings to prevent proof malleability.
    // Fq::from_le_bytes_mod_order silently reduces non-canonical inputs; a non-canonical
    // encoding that reduces to a valid on-curve point would produce a different byte
    // representation of the same proof that passes verification (malleability).
    let x_bytes: &[u8; 32] = bytes[0..32].try_into().unwrap();
    let y_bytes: &[u8; 32] = bytes[32..64].try_into().unwrap();
    if !is_canonical_fq_le(x_bytes) {
        return Err(VerifierError::ParseError(
            format!("{}: non-canonical Fq x-coordinate (value >= BN254 Fq modulus)", label)
        ));
    }
    if !is_canonical_fq_le(y_bytes) {
        return Err(VerifierError::ParseError(
            format!("{}: non-canonical Fq y-coordinate (value >= BN254 Fq modulus)", label)
        ));
    }
    let x = Fq::from_le_bytes_mod_order(x_bytes);
    let y = Fq::from_le_bytes_mod_order(y_bytes);
    g1_checked(x, y, label)
}

fn parse_g2_bytes(bytes: &[u8], label: &str) -> Result<G2Affine, VerifierError> {
    if bytes.len() < 128 {
        return Err(VerifierError::ParseError(
            format!("{}: G2 bytes too short ({})", label, bytes.len())
        ));
    }
    // c0-first layout — see SNARKJS_TO_CANDID_ENCODING.md §"Compact Binary"
    // #116: reject non-canonical Fq coordinate encodings (see parse_g1_bytes comment).
    let xc0_bytes: &[u8; 32] = bytes[0..32].try_into().unwrap();
    let xc1_bytes: &[u8; 32] = bytes[32..64].try_into().unwrap();
    let yc0_bytes: &[u8; 32] = bytes[64..96].try_into().unwrap();
    let yc1_bytes: &[u8; 32] = bytes[96..128].try_into().unwrap();
    for (coord_bytes, coord_label) in [
        (xc0_bytes, "x_c0"), (xc1_bytes, "x_c1"),
        (yc0_bytes, "y_c0"), (yc1_bytes, "y_c1"),
    ] {
        if !is_canonical_fq_le(coord_bytes) {
            return Err(VerifierError::ParseError(format!(
                "{}: non-canonical Fq {} (value >= BN254 Fq modulus)", label, coord_label
            )));
        }
    }
    let x_c0 = Fq::from_le_bytes_mod_order(xc0_bytes);
    let x_c1 = Fq::from_le_bytes_mod_order(xc1_bytes);
    let y_c0 = Fq::from_le_bytes_mod_order(yc0_bytes);
    let y_c1 = Fq::from_le_bytes_mod_order(yc1_bytes);
    g2_checked(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1), label)
}

/// Parse a 256-byte proof_bytes blob (from PrivateSpendArgs.envelope.proof_bytes).
pub fn parse_proof_bytes(proof_bytes: &[u8]) -> Result<Proof<Bn254>, VerifierError> {
    if proof_bytes.len() != 256 {
        return Err(VerifierError::ParseError(
            format!("proof_bytes: expected 256 bytes, got {}", proof_bytes.len())
        ));
    }
    Ok(Proof {
        a: parse_g1_bytes(&proof_bytes[0..64],   "pi_a")?,
        b: parse_g2_bytes(&proof_bytes[64..192],  "pi_b")?,
        c: parse_g1_bytes(&proof_bytes[192..256], "pi_c")?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public signal parsing
// ─────────────────────────────────────────────────────────────────────────────
//
// 9 signals, each a 32-byte LE-encoded BN254 Fr element (see PUBLIC_SIGNALS_BINDING.md).

/// Parse 9 × 32-byte LE signal arrays into ark Fr elements.
///
/// Returns `Err` if any signal byte array is non-canonical (>= BN254 Fr modulus).
/// Non-canonical inputs are rejected rather than silently reduced to prevent
/// aliasing attacks: two different byte arrays that differ by Fr::MODULUS would
/// otherwise map to the same field element, enabling the same note to be spent
/// twice via distinct registry keys. (#116)
pub fn parse_public_inputs(signals: &[[u8; 32]; 9]) -> Result<[Fr; 9], VerifierError> {
    let mut out = [Fr::default(); 9];
    for (i, s) in signals.iter().enumerate() {
        if !is_canonical_fr_le(s) {
            return Err(VerifierError::ParseError(format!(
                "signal[{}]: non-canonical Fr bytes (value >= BN254 Fr modulus)", i
            )));
        }
        out[i] = Fr::from_le_bytes_mod_order(s);
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers — snarkjs JSON → compact binary conversion
// ─────────────────────────────────────────────────────────────────────────────
//
// These are public so that integration-tests/ can consume real snarkjs artifacts
// (circuits/proof.json, circuits/public.json) without duplicating parsing logic.
//
// NOT used in canister production paths — the canister always receives
// pre-encoded proof_bytes (compact binary) over the Candid interface.

/// Convert a snarkjs `proof.json` to the 256-byte compact proof format.
///
/// Expected JSON shape (groth16, bn128/bn254):
/// ```json
/// {
///   "pi_a": ["x_decimal", "y_decimal", "1"],
///   "pi_b": [["x_c0", "x_c1"], ["y_c0", "y_c1"], ["1", "0"]],
///   "pi_c": ["x_decimal", "y_decimal", "1"],
///   "protocol": "groth16",
///   "curve": "bn128"
/// }
/// ```
///
/// Output layout (all coordinates 32-byte LE Fq):
/// - [  0.. 64) G1 pi_a:  x_LE || y_LE
/// - [ 64..192) G2 pi_b:  x_c0_LE || x_c1_LE || y_c0_LE || y_c1_LE
/// - [192..256) G1 pi_c:  x_LE || y_LE
pub fn proof_json_to_bytes(json: &str) -> Result<Vec<u8>, VerifierError> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| VerifierError::ParseError(format!("proof JSON: {}", e)))?;

    let g1_to_bytes = |field: &str| -> Result<Vec<u8>, VerifierError> {
        let pt = parse_g1_json(&v[field])?;
        use ark_serialize::CanonicalSerialize;
        let mut x_be = vec![];
        let mut y_be = vec![];
        pt.x.serialize_uncompressed(&mut x_be)
            .map_err(|e| VerifierError::ParseError(format!("{} x serialize: {}", field, e)))?;
        pt.y.serialize_uncompressed(&mut y_be)
            .map_err(|e| VerifierError::ParseError(format!("{} y serialize: {}", field, e)))?;
        // ark serializes Fq in LE (little-endian) already — no reversal needed
        let mut out = vec![0u8; 64];
        out[0..32].copy_from_slice(&x_be[..32]);
        out[32..64].copy_from_slice(&y_be[..32]);
        Ok(out)
    };

    let g2_to_bytes = |field: &str| -> Result<Vec<u8>, VerifierError> {
        let pt = parse_g2_json(&v[field])?;
        use ark_serialize::CanonicalSerialize;
        let mut xc0_be = vec![];
        let mut xc1_be = vec![];
        let mut yc0_be = vec![];
        let mut yc1_be = vec![];
        pt.x.c0.serialize_uncompressed(&mut xc0_be)
            .map_err(|e| VerifierError::ParseError(format!("{} x.c0 serialize: {}", field, e)))?;
        pt.x.c1.serialize_uncompressed(&mut xc1_be)
            .map_err(|e| VerifierError::ParseError(format!("{} x.c1 serialize: {}", field, e)))?;
        pt.y.c0.serialize_uncompressed(&mut yc0_be)
            .map_err(|e| VerifierError::ParseError(format!("{} y.c0 serialize: {}", field, e)))?;
        pt.y.c1.serialize_uncompressed(&mut yc1_be)
            .map_err(|e| VerifierError::ParseError(format!("{} y.c1 serialize: {}", field, e)))?;
        // c0-first: [x_c0 | x_c1 | y_c0 | y_c1]
        let mut out = vec![0u8; 128];
        out[0..32].copy_from_slice(&xc0_be[..32]);
        out[32..64].copy_from_slice(&xc1_be[..32]);
        out[64..96].copy_from_slice(&yc0_be[..32]);
        out[96..128].copy_from_slice(&yc1_be[..32]);
        Ok(out)
    };

    let mut proof_bytes = vec![0u8; 256];
    let a_bytes = g1_to_bytes("pi_a")?;
    let b_bytes = g2_to_bytes("pi_b")?;
    let c_bytes = g1_to_bytes("pi_c")?;
    proof_bytes[0..64].copy_from_slice(&a_bytes);
    proof_bytes[64..192].copy_from_slice(&b_bytes);
    proof_bytes[192..256].copy_from_slice(&c_bytes);
    Ok(proof_bytes)
}

/// Convert a snarkjs `public.json` (array of 9 decimal strings) to 9 × 32-byte LE signals.
///
/// Expected JSON shape:
/// ```json
/// ["signal_0_decimal", "signal_1_decimal", "signal_2_decimal",
///  "signal_3_decimal", "signal_4_decimal", "signal_5_decimal"]
/// ```
///
/// Signal order is per PUBLIC_SIGNALS_BINDING.md:
///   [0] anchor, [1] nullifier_hash, [2] oc1, [3] oc2, [4] public_amount, [5] fee,
///   [6] recipient_principal, [7] recipient_subaccount_lo, [8] recipient_subaccount_hi (DEF-026)
pub fn public_json_to_signals(json: &str) -> Result<[[u8; 32]; 9], VerifierError> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| VerifierError::ParseError(format!("public JSON: {}", e)))?;
    let arr = v.as_array()
        .ok_or_else(|| VerifierError::ParseError("public.json: expected array".into()))?;
    if arr.len() != 9 {
        return Err(VerifierError::ParseError(
            format!("public.json: expected 9 signals, got {}", arr.len())
        ));
    }
    let mut out = [[0u8; 32]; 9];
    for (i, val) in arr.iter().enumerate() {
        let s = val.as_str().ok_or_else(|| VerifierError::ParseError(
            format!("public.json[{}]: not a string", i)
        ))?;
        let big = BigUint::parse_bytes(s.as_bytes(), 10)
            .ok_or_else(|| VerifierError::ParseError(
                format!("public.json[{}]: invalid decimal: {}", i, s)
            ))?;
        let bytes = {
            let mut b = big.to_bytes_le();
            b.resize(32, 0);
            b
        };
        out[i].copy_from_slice(&bytes);
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Canister interface (IC endpoints)
// ─────────────────────────────────────────────────────────────────────────────
//
// The verifier is a dedicated canister — shielded_pool calls these endpoints
// via async inter-canister call (A2-2).  No custody state lives here.
//
// verify_spend:
//   proof_bytes  — 256-byte compact proof (see module-level layout doc)
//   signals      — 9 × 32-byte LE Fr elements (PUBLIC_SIGNALS_BINDING.md order)
//
// Returns Ok(()) on valid proof, Err(String) carrying the VerifierError message
// on failure.  String is used so Candid encoding needs no shared error type
// between pool and verifier canisters.

/// Canister update method: verify a Groth16 proof against the compiled-in VK.
///
/// Called by shielded_pool as an async inter-canister call.
/// No custody state lives here. DEF-083: restricted to the authorized
/// shielded-pool principal — an open verification endpoint is a free
/// compute/cycles oracle and widens the attack surface for no benefit.
#[ic_cdk_macros::update]
fn verify_spend_canister(
    proof_bytes: Vec<u8>,
    signals: Vec<Vec<u8>>,
) -> Result<(), String> {
    assert_pool_caller(); // DEF-083
    // Convert caller-supplied signals to fixed-size array.
    if signals.len() != 9 {
        return Err(format!(
            "VerifierError: expected 9 public signals, got {}",
            signals.len()
        ));
    }
    let mut sig_array = [[0u8; 32]; 9];
    for (i, s) in signals.iter().enumerate() {
        if s.len() != 32 {
            return Err(format!(
                "VerifierError: signal[{}] must be 32 bytes, got {}",
                i,
                s.len()
            ));
        }
        sig_array[i].copy_from_slice(s);
    }

    let proof_arr: [u8; 256] = proof_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "VerifierError: proof_bytes must be 256 bytes, got {}",
            v.len()
        )
    })?;

    // CRITICAL: verify_spend returns Ok(true) | Ok(false) | Err.
    // Ok(false) means the proof is parseable but does NOT satisfy the Groth16
    // equation (e.g. wrong public signals, tampered proof elements).
    // We must NOT map Ok(false) → Ok(()) — that would accept invalid proofs.
    match verify_spend(&proof_arr, &sig_array) {
        Ok(true)  => Ok(()),
        Ok(false) => Err(
            "VerifierError::InvalidProof: proof does not satisfy Groth16 \
             verification equation (wrong public signals or tampered proof)".to_string()
        ),
        Err(e) => Err(format!("{:?}", e)),
    }
}

/// Canister query: return the SHA-256 of the compiled-in VK JSON.
/// Used by shielded_pool to verify VK binding at init / governance upgrade.
#[ic_cdk_macros::query]
fn vk_hash() -> Vec<u8> {
    compiled_vk_sha256().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// A2-1: Benchmark endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A2-1 ONLY: identical to verify_spend_canister, but additionally returns the
/// IC instruction count consumed by this call (via ic_cdk::api::instruction_counter()).
///
/// Used by the A2-1 benchmark gate to measure Groth16 verification cost in
/// instructions, which can be converted to cycles (1 instruction == 1 cycle
/// on application subnets per the IC instruction-to-cycle conversion).
///
/// Not part of the production interface — shielded_pool calls
/// verify_spend_canister, not this endpoint. Intentionally absent from
/// verifier.did. DEF-083: additionally guarded to the authorized pool caller
/// (also enforced transitively via the verify_spend_canister call below) so it
/// cannot be used as a public verification/cycle-burn oracle.
#[ic_cdk_macros::update]
fn verify_spend_canister_benchmark(
    proof_bytes: Vec<u8>,
    signals: Vec<Vec<u8>>,
) -> (Result<(), String>, u64) {
    assert_pool_caller(); // DEF-083
    let result = verify_spend_canister(proof_bytes, signals);
    let instructions = ic_cdk::api::instruction_counter();
    (result, instructions)
}

// ─────────────────────────────────────────────────────────────────────────────
// Native unit tests — VK binding + tamper rejection
// ─────────────────────────────────────────────────────────────────────────────
//
// These run natively (no Wasm, no PocketIC) using circuits/ proof artifacts.
// Gate: every public signal tamper must return Ok(false).
// Run: cargo test -p stsh-verifier -- --nocapture
//
// Artifacts required: circuits/proof.json + circuits/public.json
// (generated during A0 trusted setup + A1 proof generation).
// load_artifacts() PANICS, naming the absent fixture, if proof.json/public.json
// are missing — it does not skip (see R-L, G-d).

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn circuits_dir() -> std::path::PathBuf {
        // CARGO_MANIFEST_DIR = canisters/verifier/
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()  // canisters/
            .parent().unwrap()  // workspace root
            .join("circuits")
    }

    struct Artifacts {
        proof_bytes: Vec<u8>,
        signals: [[u8; 32]; 9],
    }

    // G-d (remediation lane R-L): this loader used to print `SKIP: …` and return
    // `None`, and every caller was `let art = load_artifacts();`
    // — a missing fixture produced a PASSING test run indistinguishable from a
    // genuine one. It now returns `Artifacts` and PANICS, naming the absent file
    // and the command that produces it. A fixture the gate needs and does not
    // have must stop the gate, not quietly excuse itself.
    fn load_artifacts() -> Artifacts {
        let proof_path  = circuits_dir().join("proof.json");
        let public_path = circuits_dir().join("public.json");
        for path in [&proof_path, &public_path] {
            assert!(
                path.exists(),
                "REQUIRED FIXTURE MISSING: {}\n  \
                 Produce it with the A0 trusted setup followed by A1 proof generation \
                 (see run_gate.sh's circuit-artifact prerequisites). This test does NOT \
                 skip when the fixture is absent — a skipped proof test is not evidence \
                 the verifier works.",
                path.display()
            );
        }
        let proof_json  = std::fs::read_to_string(&proof_path).expect("read proof.json");
        let public_json = std::fs::read_to_string(&public_path).expect("read public.json");
        let proof_bytes = proof_json_to_bytes(&proof_json).expect("proof_json_to_bytes");
        let signals     = public_json_to_signals(&public_json).expect("public_json_to_signals");
        Artifacts { proof_bytes, signals }
    }

    // ── Diagnostic: VK must bind exactly 9 public inputs ────────────────────

    #[test]
    fn test_vk_binding_check() {
        let pvk = get_pvk();
        let n_ic = pvk.vk.gamma_abc_g1.len();
        println!("gamma_abc_g1.len() = {} (expected 10 = 9 public inputs + 1 constant)", n_ic);
        assert_eq!(n_ic, 10,
            "VK has {} gamma_abc_g1 entries but expected 10 (9 public signals + 1 base). \
             The VK was compiled for a circuit with {} public input(s). \
             Regenerate circuits/verification_key.json from the correct spend.circom.",
            n_ic, n_ic.saturating_sub(1)
        );
    }

    // ── Valid proof verifies ─────────────────────────────────────────────────

    #[test]
    fn test_valid_proof_verifies() {
        let art = load_artifacts();
        let proof_arr: [u8; 256] = art.proof_bytes.try_into().expect("256 bytes");
        let result = verify_spend(&proof_arr, &art.signals).expect("verify_spend");
        println!("Valid proof result: {}", result);
        assert!(result, "Expected valid proof to verify, got false");
    }

    // ── Each tampered signal must produce Ok(false) ──────────────────────────
    //
    // We XOR every byte of one signal with 0xFF to guarantee a different Fr element.
    // The proof is unchanged (valid G1/G2 points), only the public input differs.
    // A correct Groth16 verifier must return Ok(false) — not Err, not Ok(true).

    fn tamper(signals: &[[u8; 32]; 9], idx: usize) -> [[u8; 32]; 9] {
        let mut s = *signals;
        s[idx] = s[idx].map(|b| b ^ 0xFF);
        // Guarantee the tampered value is non-zero (avoid accidental no-op)
        s[idx][0] |= 0x01;
        s
    }

    fn assert_tamper_rejects(art: &Artifacts, idx: usize, label: &str) {
        // Use from_le_bytes_mod_order directly (not parse_public_inputs) so the comparison
        // works even when the tampered bytes are non-canonical.
        let original_fr = parse_public_inputs(&art.signals)
            .expect("fixture signals must be canonical");
        let tampered_ = tamper(&art.signals, idx);
        // Reduce tampered bytes mod Fr for comparison (bypasses canonical check intentionally).
        let modified_fr: Fr = Fr::from_le_bytes_mod_order(&tampered_[idx]);

        // Confirm the Fr values differ (tamper must not be a no-op after reduction).
        assert_ne!(
            original_fr[idx], modified_fr,
            "SETUP BUG: tampered signal[{}] ({}) Fr value is identical to original after \
             mod-reduction — tamper is a no-op. Original bytes: {:?}",
            idx, label, art.signals[idx]
        );

        let proof_arr: [u8; 256] = art.proof_bytes.clone().try_into().expect("256 bytes");
        let result = verify_spend(&proof_arr, &tampered_);
        // #116: After the canonical check, tampered signals may be rejected as Err(ParseError)
        // (when XOR makes them non-canonical) OR as Ok(false) (when the tampered value is
        // canonical but not the one embedded in the proof).  Both are valid rejections.
        match result {
            Err(VerifierError::ParseError(ref msg)) => {
                println!("Tampered signal[{}] ({}) → rejected at canonical check: {}", idx, label, msg);
            }
            Err(VerifierError::VerificationFailed) => {
                println!("Tampered signal[{}] ({}) → VerificationFailed", idx, label);
            }
            Ok(false) => {
                println!("Tampered signal[{}] ({}) → verify_spend = false (Groth16 rejected)", idx, label);
            }
            Ok(true) => {
                panic!(
                    "SECURITY BUG: valid proof verified with tampered {} (signal[{}]). \
                     The verifier is NOT binding public input {}.",
                    label, idx, idx
                );
            }
        }
    }

    // ── B-2 (R-6, G4): the tamper suite reaches the PAIRING, not just the
    //    canonical-encoding guard ──────────────────────────────────────────────
    //
    // The XOR-0xFF form above is weak wherever the XOR'd value happens to be
    // non-canonical: `is_canonical_fr_le` rejects it inside `parse_public_inputs`
    // BEFORE `verify_spend` ever reaches the Groth16 pairing (:513), so
    // `assert_tamper_rejects`'s `Err(ParseError)` arm accepts a "rejection" that
    // proves nothing about whether the proof binds that signal at all. The
    // fixture's signals 4-8 are all zero, so XOR 0xFF makes every one of them
    // non-canonical — those tests would pass with the IC vector at infinity.
    //
    // Signals 1-8 are therefore tested by CANONICAL substitution (the DEF-102
    // precedent, :1079 below, which already covers 6/7/8 and is kept unmodified):
    // substituting the canonical Fr value 1 forces the rejection to come from the
    // pairing itself — `Ok(false)` is the ONLY accepted outcome, never `Err`.
    //
    // Signal 0 (the anchor) stays the one EXPLICIT non-canonical case, named as
    // such, so the canonical-guard path keeps deliberate coverage too.

    /// Substitute the canonical Fr value 1 for `signals[idx]` and require the
    /// verifier to reject at the PAIRING: `Ok(false)`, never `Err`, never `Ok(true)`.
    ///
    /// Each caller also runs the untampered positive control, so a fixture that
    /// stopped verifying at all could not be mistaken for a passing tamper test.
    fn assert_canonical_substitution_rejects(art: &Artifacts, idx: usize, label: &str) {
        let proof_arr: [u8; 256] = art.proof_bytes.clone().try_into().expect("256 bytes");

        // Invocation 1 — untampered, positive control. `VerifierError` derives
        // Debug only, so `assert_eq!` on the Result does not compile; `matches!`
        // needs no trait on the compared type.
        let baseline = verify_spend(&proof_arr, &art.signals);
        assert!(
            matches!(baseline, Ok(true)),
            "SETUP BUG: the untampered fixture must verify: {baseline:?}"
        );

        let one = { let mut b = [0u8; 32]; b[0] = 1; b };
        assert!(is_canonical_fr_le(&one), "SETUP BUG: substitution value must be canonical");
        assert_ne!(
            art.signals[idx], one,
            "SETUP BUG: fixture signal[{idx}] ({label}) already equals the substitution \
             value — the tamper would be a no-op"
        );
        let mut tampered = art.signals;
        tampered[idx] = one;

        // Invocation 2 — canonically tampered, differing argument.
        match verify_spend(&proof_arr, &tampered) {
            Ok(false) => {
                println!(
                    "Canonical substitution signal[{idx}] ({label}) → verify_spend = false \
                     (Groth16 pairing rejected)"
                );
            }
            Ok(true) => panic!(
                "SECURITY BUG: valid proof verified with canonical tampered {label} \
                 (signal[{idx}]). The verifier is NOT binding this public input."
            ),
            Err(e) => panic!(
                "DEF-102-style REGRESSION: canonical substitution on signal[{idx}] ({label}) \
                 must reach the Groth16 pairing and return Ok(false), got Err: {e:?}"
            ),
        }
    }

    /// The ONE explicit non-canonical case: XOR-0xFF on the anchor produces a
    /// value the canonical guard rejects before the pairing. Named
    /// `_noncanonical_` so that outcome reads as the point of the test rather
    /// than as accidentally-weak pairing coverage.
    #[test] fn test_tamper_signal_0_anchor_noncanonical_rejected() {
        let art = load_artifacts();
        assert_tamper_rejects(&art, 0, "anchor");
    }
    #[test] fn test_tamper_signal_1_nullifier_hash_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 1, "nullifier_hash");
    }
    #[test] fn test_tamper_signal_2_oc1_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 2, "output_commitment_1");
    }
    #[test] fn test_tamper_signal_3_oc2_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 3, "output_commitment_2");
    }

    // BINDING: B-2-VERIFIER-PAIRING — this is the test tests/BINDING_REGISTRY.toml's
    // B-2-VERIFIER-PAIRING row names in `bound`. The two `verify_spend(...)` call
    // sites below are written out INLINE rather than delegated to
    // `assert_canonical_substitution_rejects` on purpose: the bindings lint's rule
    // (c) scans THIS function's own rendered token stream for ≥2 invocations of the
    // bound entrypoint with differing arguments, and a call made inside a helper is
    // invisible to it.
    #[test]
    fn test_tamper_signal_4_public_amount_canonical_substitution_rejected() {
        let art = load_artifacts();
        let proof_arr: [u8; 256] = art.proof_bytes.clone().try_into().expect("256 bytes");

        // Invocation 1 — untampered, positive control.
        let baseline = verify_spend(&proof_arr, &art.signals);
        assert!(
            matches!(baseline, Ok(true)),
            "SETUP BUG: the untampered fixture must verify: {baseline:?}"
        );

        // Substitution value: canonical Fr, != the fixture's own signal[4].
        let one = { let mut b = [0u8; 32]; b[0] = 1; b };
        assert!(is_canonical_fr_le(&one), "SETUP BUG: substitution value must be canonical");
        assert_ne!(
            art.signals[4], one,
            "SETUP BUG: fixture signal[4] already equals the substitution value"
        );
        let mut tampered = art.signals;
        tampered[4] = one;

        // Invocation 2 — canonically tampered, differing argument.
        match verify_spend(&proof_arr, &tampered) {
            Ok(false) => {}
            Ok(true) => panic!("SECURITY BUG: valid proof verified with tampered public_amount"),
            Err(e) => panic!(
                "DEF-102-style REGRESSION: canonical substitution on signal[4] (public_amount) \
                 must reach the Groth16 pairing and return Ok(false), got Err: {e:?}"
            ),
        }
    }

    #[test] fn test_tamper_signal_5_fee_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 5, "fee");
    }
    // DEF-026: the three recipient/subaccount public signals must also be bound.
    // These are ALSO covered, canonically, by
    // test_tamper_recipient_signals_canonical_substitution_rejected (:1079 at base),
    // which is kept unmodified — these per-signal tests name each one individually
    // so a deletion there is a named, single-signal regression.
    #[test] fn test_tamper_signal_6_recipient_principal_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 6, "recipient_principal");
    }
    #[test] fn test_tamper_signal_7_recipient_subaccount_lo_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 7, "recipient_subaccount_lo");
    }
    #[test] fn test_tamper_signal_8_recipient_subaccount_hi_canonical_substitution_rejected() {
        let art = load_artifacts();
        assert_canonical_substitution_rejects(&art, 8, "recipient_subaccount_hi");
    }

    /// R-6 (G4) build-freshness check — NOT a property binding, so it has no
    /// binding-registry row of its own. The compiled-in VK (`include_str!` of
    /// circuits/verification_key.json) and the committed pin must agree, so a
    /// stale rebuild or a pin updated in a different commit than the artifact is
    /// caught host-side rather than at deploy time.
    #[test]
    fn compiled_vk_hash_matches_committed_pin() {
        let pin_toml = include_str!("../../../scripts/verify_genesis_manifest/VK_PIN.toml");
        let pin: toml::Value = toml::from_str(pin_toml).expect("VK_PIN.toml must parse");
        let expected = pin["sha256"].as_str().expect("sha256 field");
        assert_eq!(
            hex::encode(compiled_vk_sha256()),
            expected,
            "compiled-in VK hash no longer matches scripts/verify_genesis_manifest/VK_PIN.toml — \
             rebuild is stale, or the pin was not updated in the same commit as the artifact"
        );
    }

    // DEF-067: deterministic G2 c0/c1 limb-order regression guard.
    //
    // The only other swap coverage is test_valid_proof_verifies, which SKIPS
    // when circuits/proof.json / public.json are absent — detection there is
    // environmental, not deterministic. This test needs no fixtures: the base
    // blob is built from the BN254 generator points (canonical coordinates,
    // on-curve, prime-order subgroup), which is structurally valid enough to
    // clear the FULL parse path — including the c0-first G2 decode — and be
    // rejected only at the pairing (Ok(false): generator points satisfy no
    // real proof equation for any VK). The swapped copy transposes the G2
    // c0/c1 limbs for both x and y inside pi_b and must never verify. If a
    // refactor ever flips parse_g2_bytes to c1-first, the BASE assertion
    // fails (the correctly-ordered blob would then decode as a transposed —
    // off-curve — point), so both directions of the ordering are pinned.
    #[test]
    fn test_g2_c0_c1_swap_rejected_deterministic() {
        use ark_ec::AffineRepr;
        use ark_ff::BigInteger;

        fn fq_le(x: &Fq) -> [u8; 32] {
            let bytes = x.into_bigint().to_bytes_le();
            let mut out = [0u8; 32];
            out[..bytes.len()].copy_from_slice(&bytes);
            out
        }

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        // Layout per the module header: pi_a[0..64) | pi_b[64..192) | pi_c[192..256)
        let mut base = [0u8; 256];
        base[0..32].copy_from_slice(&fq_le(&g1.x));
        base[32..64].copy_from_slice(&fq_le(&g1.y));
        base[64..96].copy_from_slice(&fq_le(&g2.x.c0));   // x_c0 (c0-first)
        base[96..128].copy_from_slice(&fq_le(&g2.x.c1));  // x_c1
        base[128..160].copy_from_slice(&fq_le(&g2.y.c0)); // y_c0
        base[160..192].copy_from_slice(&fq_le(&g2.y.c1)); // y_c1
        base[192..224].copy_from_slice(&fq_le(&g1.x));
        base[224..256].copy_from_slice(&fq_le(&g1.y));

        let signals = [[0u8; 32]; 9]; // canonical (zero) public signals

        // Setup guard: base must clear parsing entirely — proving this test
        // genuinely exercises the G2 decode with the production limb order —
        // and fail only at the pairing.
        let base_result = verify_spend(&base, &signals);
        assert!(
            matches!(base_result, Ok(false)),
            "SETUP BUG: generator-point base blob must parse cleanly (c0-first) and be \
             rejected by the pairing as Ok(false); got {:?}",
            base_result
        );

        // Transpose the G2 c0/c1 limbs for both coordinates inside pi_b.
        let mut swapped = base;
        swapped[64..96].copy_from_slice(&base[96..128]);
        swapped[96..128].copy_from_slice(&base[64..96]);
        swapped[128..160].copy_from_slice(&base[160..192]);
        swapped[160..192].copy_from_slice(&base[128..160]);
        assert_ne!(swapped, base, "SETUP BUG: c0/c1 transposition was a no-op");

        let swapped_result = verify_spend(&swapped, &signals);
        assert!(
            !matches!(swapped_result, Ok(true)),
            "SECURITY BUG: G2 c0/c1-swapped proof must never verify"
        );
        println!(
            "G2 c0/c1 swap: base (correct order) -> {:?}; swapped -> {:?} (rejected)",
            base_result, swapped_result
        );
    }

    // DEF-113: a G2 point that is ON the curve but NOT in the prime-order subgroup
    // must be rejected by g2_checked's new subgroup guard. Fixture-independent — it
    // does NOT read circuits/proof.json (no load_artifacts), so it can never SKIP.
    // Construction: obtain a raw on-curve G2 point Q (via get_point_from_x_unchecked,
    // which solves y from x with NO subgroup check) and loop until it lands outside
    // the subgroup — trivial, since G2's large cofactor makes almost every on-curve
    // point a non-subgroup point. Q is used DIRECTLY as pi_b (a raw non-subgroup
    // point already satisfies both setup guards; no cofactor/torsion arithmetic).
    // pi_a/pi_c are generator G1 points, mirroring test_g2_c0_c1_swap_rejected_*.
    #[test]
    fn test_g2_subgroup_check_rejects_torsion_point() {
        use ark_ec::AffineRepr;
        use ark_ff::{BigInteger, One};

        fn fq_le(x: &Fq) -> [u8; 32] {
            let bytes = x.into_bigint().to_bytes_le();
            let mut out = [0u8; 32];
            out[..bytes.len()].copy_from_slice(&bytes);
            out
        }

        // Raw on-curve G2 point that is NOT in the prime-order subgroup.
        let q = {
            let mut x = Fq2::one();
            loop {
                if let Some(p) = G2Affine::get_point_from_x_unchecked(x, true) {
                    if p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve() {
                        break p;
                    }
                }
                x += Fq2::one();
            }
        };

        // Setup guards — the point must satisfy BOTH or the test proves nothing.
        assert!(q.is_on_curve(), "SETUP BUG: Q must be on-curve");
        assert!(
            !q.is_in_correct_subgroup_assuming_on_curve(),
            "SETUP BUG: Q must NOT be in the prime-order subgroup"
        );

        // 256-byte blob: generator G1 for pi_a/pi_c, torsion Q as pi_b (c0-first).
        let g1 = G1Affine::generator();
        let mut blob = [0u8; 256];
        blob[0..32].copy_from_slice(&fq_le(&g1.x));
        blob[32..64].copy_from_slice(&fq_le(&g1.y));
        blob[64..96].copy_from_slice(&fq_le(&q.x.c0));
        blob[96..128].copy_from_slice(&fq_le(&q.x.c1));
        blob[128..160].copy_from_slice(&fq_le(&q.y.c0));
        blob[160..192].copy_from_slice(&fq_le(&q.y.c1));
        blob[192..224].copy_from_slice(&fq_le(&g1.x));
        blob[224..256].copy_from_slice(&fq_le(&g1.y));

        let signals = [[0u8; 32]; 9]; // canonical (zero) public signals

        // The new subgroup guard must reject pi_b at parse time — an Err whose
        // message names the subgroup (proving it came from the NEW check, not the
        // pre-existing on-curve check nor the pairing).
        match verify_spend(&blob, &signals) {
            Err(VerifierError::ParseError(msg)) => {
                assert!(
                    msg.contains("subgroup"),
                    "expected a subgroup rejection, got ParseError: {msg}"
                );
                println!("DEF-113: torsion G2 pi_b rejected -> ParseError: {msg}");
            }
            other => panic!(
                "SECURITY BUG: non-subgroup G2 pi_b must be rejected by the subgroup \
                 guard with a ParseError naming the subgroup; got {other:?}"
            ),
        }
    }

    // DEF-102: canonical-value substitution for the recipient signals 6–8.
    //
    // The XOR-based tamper tests above are weak for signals 6–8: the fixture's
    // recipient signals are all-zero, so XOR with 0xFF produces a NON-canonical
    // value that is_canonical_fr_le rejects before the Groth16 pairing is
    // exercised at all — they would pass even if the IC vector were at infinity.
    // Substituting the canonical value 1 (LE) forces the rejection to come from
    // the pairing itself: the verifier must return Ok(false) — real Groth16
    // rejection — never Err (no canonical bail-out) and never Ok(true).
    // Independently confirmed via snarkjs that this canonical value is genuinely
    // rejected for each of signals 6/7/8; it is fixed here as the fixture.
    //
    // BINDING: B-2-VERIFIER-PAIRING-678 - this is the test
    // tests/BINDING_REGISTRY.toml's B-2-VERIFIER-PAIRING-678 row names in `bound`.
    // The untampered positive control below is written INLINE (not delegated to a
    // helper) because the bindings lint's rule (c) scans THIS function's own
    // rendered token stream for >=2 invocations of `verify_spend` with differing
    // arguments; a call made inside a helper is invisible to it.
    #[test]
    fn test_tamper_recipient_signals_canonical_substitution_rejected() {
        let art = load_artifacts();
        let proof_arr: [u8; 256] = art.proof_bytes.clone().try_into().expect("256 bytes");

        // Invocation 1 - untampered, positive control: a fixture that stopped
        // verifying at all must not be mistaken for a passing tamper test.
        let baseline = verify_spend(&proof_arr, &art.signals);
        assert!(
            matches!(baseline, Ok(true)),
            "SETUP BUG: the untampered fixture must verify: {baseline:?}"
        );

        // Canonical Fr value 1, little-endian.
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(is_canonical_fr_le(&one), "SETUP BUG: substitution value must be canonical");

        for (idx, label) in [
            (6usize, "recipient_principal"),
            (7, "recipient_subaccount_lo"),
            (8, "recipient_subaccount_hi"),
        ] {
            assert_ne!(
                art.signals[idx], one,
                "SETUP BUG: fixture signal[{idx}] ({label}) already equals the \
                 substitution value — tamper would be a no-op"
            );
            let mut tampered = art.signals;
            tampered[idx] = one;

            // Invocation 2 (per signal) - canonically tampered, differing argument.
            let result = verify_spend(&proof_arr, &tampered);
            match result {
                Ok(false) => {
                    println!(
                        "Canonical substitution signal[{idx}] ({label}) → \
                         verify_spend = false (Groth16 pairing rejected)"
                    );
                }
                Ok(true) => panic!(
                    "SECURITY BUG: valid proof verified with canonical tampered {label} \
                     (signal[{idx}]). The verifier is NOT binding this public input."
                ),
                Err(e) => panic!(
                    "DEF-102 REGRESSION: canonical substitution on signal[{idx}] ({label}) \
                     must reach the Groth16 pairing and return Ok(false), but the verifier \
                     errored before/at verification: {e:?}"
                ),
            }
        }
    }
    #[test] fn test_tamper_all_signals_rejected() {
        let art = load_artifacts();
        let all_xor: [[u8; 32]; 9] = art.signals.map(|s| {
            let mut t = s.map(|b| b ^ 0xFF);
            t[0] |= 0x01;
            t
        });
        let proof_arr: [u8; 256] = art.proof_bytes.clone().try_into().expect("256 bytes");
        let result = verify_spend(&proof_arr, &all_xor);
        // #116: all-XOR signals are non-canonical, so expect Err(ParseError).
        // Ok(false) (Groth16 rejection) is also acceptable if the tampered values happen
        // to be canonical.  Ok(true) is a security bug in either case.
        match result {
            Ok(true) => panic!("SECURITY BUG: proof verified with all signals inverted"),
            Ok(false) => println!("All signals XOR'd → verify_spend = false"),
            Err(VerifierError::ParseError(ref msg)) => {
                println!("All signals XOR'd → canonical check rejected: {}", msg);
            }
            Err(VerifierError::VerificationFailed) => {
                println!("All signals XOR'd → VerificationFailed");
            }
        }
    }

    // ── L3e: get_authorized_pool canonical read-back ─────────────────────────
    //
    // AUTHORIZED_POOL is a thread_local, so each test (its own thread) starts
    // from None and sets exactly the state it exercises.

    fn set_authorized_pool(p: Option<candid::Principal>) {
        AUTHORIZED_POOL.with(|a| *a.borrow_mut() = p);
    }

    fn test_principal(byte: u8) -> candid::Principal {
        candid::Principal::from_slice(&[byte; 29])
    }

    /// Positive: the read-back returns exactly the stored AUTHORIZED_POOL and
    /// performs no mutation.
    #[test]
    fn test_get_authorized_pool_returns_stored_value_no_mutation() {
        let pool = test_principal(0xAB);
        set_authorized_pool(Some(pool));
        assert_eq!(authorized_pool_readback(), Ok(pool));
        assert_eq!(get_authorized_pool(), pool, "query must return the stored principal verbatim");
        // No-mutation: value unchanged after the read.
        assert_eq!(AUTHORIZED_POOL.with(|a| *a.borrow()), Some(pool));
    }

    /// Fail-closed on uninitialized state: no default substitution, no
    /// caller-expectation echo — the query must trap.
    #[test]
    fn test_get_authorized_pool_fails_closed_uninitialized() {
        set_authorized_pool(None);
        let err = authorized_pool_readback().expect_err("uninit must fail closed");
        assert!(err.contains("uninitialized"), "unexpected error: {err}");
        let trapped = std::panic::catch_unwind(|| get_authorized_pool());
        assert!(trapped.is_err(), "query must trap on uninitialized AUTHORIZED_POOL");
    }

    /// Fail-closed on the anonymous-principal sentinel.
    #[test]
    fn test_get_authorized_pool_fails_closed_anonymous_sentinel() {
        set_authorized_pool(Some(candid::Principal::anonymous()));
        let err = authorized_pool_readback().expect_err("anonymous sentinel must fail closed");
        assert!(err.contains("sentinel"), "unexpected error: {err}");
        let trapped = std::panic::catch_unwind(|| get_authorized_pool());
        assert!(trapped.is_err(), "query must trap on anonymous-sentinel AUTHORIZED_POOL");
    }

    /// Upgrade persistence: pre_upgrade/post_upgrade persist AUTHORIZED_POOL as a
    /// candid `(Option<Principal>,)` tuple via stable_save/stable_restore. Simulate
    /// the round-trip at the candid layer: bytes saved by the old instance must
    /// restore into the new instance and read back byte-identically — and a
    /// persisted `None` must still fail closed after the upgrade.
    #[test]
    fn test_get_authorized_pool_survives_upgrade_roundtrip() {
        let pool = test_principal(0x42);

        // Old instance: value set at init, saved at pre_upgrade.
        let saved = candid::encode_one((Some(pool),)).expect("stable_save encoding");

        // New instance: post_upgrade restores, then the read-back serves it.
        let (restored,): (Option<candid::Principal>,) =
            candid::decode_one(&saved).expect("stable_restore decoding");
        set_authorized_pool(restored);
        assert_eq!(authorized_pool_readback(), Ok(pool));
        assert_eq!(get_authorized_pool(), pool, "stored pool must survive an upgrade verbatim");

        // A persisted None (uninitialized at pre_upgrade) restores to None and
        // the read-back still fails closed — an upgrade must not invent a default.
        let saved_none = candid::encode_one((None::<candid::Principal>,)).expect("encoding");
        let (restored_none,): (Option<candid::Principal>,) =
            candid::decode_one(&saved_none).expect("decoding");
        set_authorized_pool(restored_none);
        assert!(authorized_pool_readback().is_err(),
            "persisted None must still fail closed after upgrade");
    }
}
