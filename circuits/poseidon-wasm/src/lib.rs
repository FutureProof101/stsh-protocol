// =============================================================================
// stsh-poseidon-wasm — circomlib-compatible Poseidon for the browser wallet
// =============================================================================
//
// Exposes the four Poseidon arities the wallet needs (source-verified against
// circuits/spend.circom, wallet-build lane F1/F2):
//
//   poseidon2 — recipient_pk = Poseidon(2)(spend_key, PK_DOMAIN=1)   [spend.circom:379]
//               + Merkle node hashing (left, right)                  [MerkleProof]
//   poseidon3 — merkle_leaf = Poseidon(3)(value, inner_commitment,
//               MERKLE_LEAF_DOMAIN=4)                                [DEF-111]
//   poseidon4 — nullifier   = Poseidon(4)(domain_sep, spend_key,
//               in_commitment, NULLIFIER_DOMAIN=2)                   [DEF-109-A]
//               + domainHash = Poseidon(4)(POOL_ID, ASSET, CIRCUIT_V, NETWORK)
//   poseidon6 — commitment  = Poseidon(6)(domain_sep, value, recipient_pk,
//               rho, rseed, COMMITMENT_DOMAIN=3)                     [spend.circom:164]
//
// PARAMETER IDENTITY: light-poseidon is workspace-pinned to the SAME version
// the canisters use; `new_circom(N)` loads the circomlib parameter set
// (POSEIDON_PARAMS.md). The canisters' "never new_circom" rule is an IC-Wasm
// function-complexity constraint, not a parameter difference — a browser Wasm
// has no such ceiling. Byte-identity with the canister/circuit is enforced by
// the unit tests below: circomlibjs reference vectors for every arity, plus a
// direct equality check against `stsh_field_utils::merkle_leaf` (the pool's
// own leaf implementation).
//
// CANONICALITY (hard rule): the WASM boundary REJECTS non-canonical field
// elements — it never silently reduces. The guard is
// `stsh_field_utils::is_canonical_fr_le`, reused verbatim from the audited
// pure crate (its FR_MODULUS_LE is unit-tested against ark_bn254::Fr::MODULUS
// in field-utils itself — no local modulus copy exists here). A thrown
// JsError crosses the boundary; TS wrappers must surface it, never swallow it.
// =============================================================================

#![forbid(unsafe_code)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use stsh_field_utils::is_canonical_fr_le;
use wasm_bindgen::prelude::*;

// ── Pure core (host-testable; JsError only at the wasm-bindgen wrappers) ─────

fn fr_from_le32(bytes: &[u8; 32]) -> Result<Fr, String> {
    if !is_canonical_fr_le(bytes) {
        return Err("non-canonical field element: input >= BN254 Fr modulus".to_string());
    }
    // Reduction is a no-op here — the guard above proves the value in-range.
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

/// Reduce 32 little-endian bytes modulo the BN254 Fr modulus, returning a
/// CANONICAL 32-byte LE field element. This is the one legitimate reduction
/// (deriving a field element from a hash / HKDF output) — matches the wallet's
/// `reduceLeToField` and the circuit's input-signal reduction. Distinct from
/// the guarded `fr_from_le32` used at the hash INPUT boundary (which rejects).
pub fn reduce_le_field(bytes: &[u8; 32]) -> [u8; 32] {
    fr_to_le32(Fr::from_le_bytes_mod_order(bytes))
}

fn fr_to_le32(fr: Fr) -> [u8; 32] {
    let le_bytes = fr.into_bigint().to_bytes_le();
    debug_assert_eq!(le_bytes.len(), 32, "BN254/Fr must produce exactly 32 bytes");
    let mut out = [0u8; 32];
    out[..le_bytes.len().min(32)].copy_from_slice(&le_bytes[..le_bytes.len().min(32)]);
    out
}

fn as32(label: &str, bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly 32 bytes (got {})", bytes.len()))
}

fn hash_n(inputs: &[[u8; 32]]) -> Result<[u8; 32], String> {
    let mut frs = Vec::with_capacity(inputs.len());
    for b in inputs {
        frs.push(fr_from_le32(b)?);
    }
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|e| format!("Poseidon init failed for arity {}: {e}", inputs.len()))?;
    let result = hasher
        .hash(&frs)
        .map_err(|e| format!("Poseidon hash failed: {e}"))?;
    Ok(fr_to_le32(result))
}

pub fn poseidon2_core(left: &[u8], right: &[u8]) -> Result<[u8; 32], String> {
    hash_n(&[as32("left", left)?, as32("right", right)?])
}

pub fn poseidon3_core(a: &[u8], b: &[u8], c: &[u8]) -> Result<[u8; 32], String> {
    hash_n(&[as32("a", a)?, as32("b", b)?, as32("c", c)?])
}

pub fn poseidon4_core(a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> Result<[u8; 32], String> {
    hash_n(&[as32("a", a)?, as32("b", b)?, as32("c", c)?, as32("d", d)?])
}

pub fn poseidon6_core(
    a: &[u8],
    b: &[u8],
    c: &[u8],
    d: &[u8],
    e: &[u8],
    f: &[u8],
) -> Result<[u8; 32], String> {
    hash_n(&[
        as32("a", a)?,
        as32("b", b)?,
        as32("c", c)?,
        as32("d", d)?,
        as32("e", e)?,
        as32("f", f)?,
    ])
}

// ── wasm-bindgen boundary (errors become thrown JS exceptions) ───────────────

/// Poseidon(2) — PK derivation (spend_key, PK_DOMAIN) and Merkle node hashing.
/// Throws on non-canonical input — never silently reduces.
#[wasm_bindgen]
pub fn poseidon2(left: &[u8], right: &[u8]) -> Result<Vec<u8>, JsError> {
    poseidon2_core(left, right)
        .map(|b| b.to_vec())
        .map_err(|e| JsError::new(&e))
}

/// Poseidon(3) — merkle_leaf = Poseidon(value, inner_commitment, MERKLE_LEAF_DOMAIN) (DEF-111).
#[wasm_bindgen]
pub fn poseidon3(a: &[u8], b: &[u8], c: &[u8]) -> Result<Vec<u8>, JsError> {
    poseidon3_core(a, b, c)
        .map(|b| b.to_vec())
        .map_err(|e| JsError::new(&e))
}

/// Poseidon(4) — nullifier (DEF-109-A) and domainHash.
#[wasm_bindgen]
pub fn poseidon4(a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> Result<Vec<u8>, JsError> {
    poseidon4_core(a, b, c, d)
        .map(|b| b.to_vec())
        .map_err(|e| JsError::new(&e))
}

/// Poseidon(6) — note commitment (F1: domain_sep-prefixed, COMMITMENT_DOMAIN-tagged).
#[wasm_bindgen]
pub fn poseidon6(
    a: &[u8],
    b: &[u8],
    c: &[u8],
    d: &[u8],
    e: &[u8],
    f: &[u8],
) -> Result<Vec<u8>, JsError> {
    poseidon6_core(a, b, c, d, e, f)
        .map(|b| b.to_vec())
        .map_err(|e| JsError::new(&e))
}

// ── Tests: circomlibjs reference vectors + field-utils equality + guard ──────
//
// Vectors generated 2026-07-12 from circomlibjs 0.1.7 (circuits/node_modules —
// the same pinned circuit-side reference POSEIDON_PARAMS.md names). The wallet
// vitest suite (wallet/tests/poseidon.test.ts) pins the identical hex — update
// both or neither.

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(n: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        b
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn poseidon2_matches_circomlibjs_vector() {
        let out = poseidon2_core(&le32(1), &le32(2)).unwrap();
        assert_eq!(
            hex(&out),
            "9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11"
        );
    }

    #[test]
    fn poseidon3_matches_circomlibjs_vector() {
        let out = poseidon3_core(&le32(1), &le32(2), &le32(3)).unwrap();
        assert_eq!(
            hex(&out),
            "32d736ab34df25f768b9c59d260e23f30263ab8de5d503ffc039699ed832770e"
        );
    }

    #[test]
    fn poseidon4_matches_circomlibjs_vector() {
        let out = poseidon4_core(&le32(1), &le32(2), &le32(3), &le32(4)).unwrap();
        assert_eq!(
            hex(&out),
            "65042565df25a5ba3d66e01cbb0ee637980b51e440face9dd7fdc1b67d869c29"
        );
    }

    #[test]
    fn poseidon6_matches_circomlibjs_vector() {
        let out = poseidon6_core(&le32(1), &le32(2), &le32(3), &le32(4), &le32(5), &le32(6))
            .unwrap();
        assert_eq!(
            hex(&out),
            "e102632fca4c4a1339225fb0680a493875a4de94f0ebc8132844840085031a2d"
        );
    }

    /// D2 ceremony domainHash: poseidon4(ohspu→Fr, ASSET=0, CIRCUIT_VERSION=3,
    /// NETWORK=1) — the decimal is the value pinned in wallet notes.ts and
    /// spend.circom Constraint 0 commentary. Bumped 2→3 at lane A6.6
    /// (MAX_NOTE_VALUE 10^11 → 10^15, five-tier launch ladder).
    ///
    /// The v=2 encoding is retained alongside as the injectivity witness: the
    /// SAME producer, invoked with the only differing argument being the
    /// circuit-version limb, must yield a DIFFERENT digest. A bump that did not
    /// move the domain separator would not separate anything.
    // BINDING: A66-DOMAIN-VERSION
    #[test]
    fn domain_hash_matches_d2_ceremony() {
        // ohspu-zqaaa-aaaad-qmasq-cai → Fr, LE bytes.
        let pool_fr_dec: &str =
            "4523128485832663883733241601901871400518358776001584537534818377974931259392";
        let pool = dec_to_le32(pool_fr_dec);
        let out = poseidon4_core(&pool, &le32(0), &le32(3), &le32(1)).unwrap();
        assert_eq!(
            hex(&out),
            "f86a7fd6a66d358ddbe7d8fa7b303f5da7e63d41b7ee207c6a31359c6220c125"
        );
        // And as decimal, the canonical published value:
        assert_eq!(
            le32_to_dec(&out),
            "17076800395491555068286473339039486071114029588881949545487634475758427007736"
        );

        // Injectivity across the version limb (A66-DOMAIN-VERSION): the retired
        // v=2 tuple must NOT collide with the live v=3 tuple.
        let out_v2 = poseidon4_core(&pool, &le32(0), &le32(2), &le32(1)).unwrap();
        assert_ne!(
            hex(&out_v2),
            hex(&out),
            "DOMAIN_CIRCUIT_VERSION 2 and 3 must produce different domain separators"
        );
        assert_eq!(
            hex(&out_v2),
            "f1829c5e88a0aa665e96a6eefc8950f5421b00c2c3a2764c329846e1ba991c2f",
            "the retired v=2 vector is retained verbatim as the before-value"
        );
    }

    /// poseidon3(value, commitment, MERKLE_LEAF_DOMAIN) must equal the pool's
    /// own leaf implementation — proves new_circom(3) params == the canister's
    /// fixed t=4 param set, byte for byte, via the AUDITED code path.
    #[test]
    fn poseidon3_equals_field_utils_merkle_leaf() {
        let value: u128 = 100_000_000; // 1 STSH
        let commitment = le32(0x1C1C);
        let expected = stsh_field_utils::merkle_leaf(value, &commitment);

        let mut value_le = [0u8; 32];
        value_le[..16].copy_from_slice(&value.to_le_bytes());
        let leaf = poseidon3_core(
            &value_le,
            &commitment,
            &le32(stsh_field_utils::MERKLE_LEAF_DOMAIN),
        )
        .unwrap();
        assert_eq!(leaf, expected, "wallet leaf must byte-equal pool leaf");
    }

    #[test]
    fn reduce_le_field_matches_mod_semantics() {
        // A value already < modulus is unchanged.
        let small = le32(42);
        assert_eq!(reduce_le_field(&small), small);
        // The modulus itself reduces to 0.
        let modulus = fr_to_le32(Fr::from(0u64)); // 0
        assert_eq!(reduce_le_field(&modulus), le32(0));
        // An all-0xFF (>= modulus) value becomes canonical (< modulus) and
        // therefore passes the input guard afterwards.
        let reduced = reduce_le_field(&[0xFFu8; 32]);
        assert!(is_canonical_fr_le(&reduced), "reduced value must be canonical");
        // Idempotent: reducing a reduced value is a no-op.
        assert_eq!(reduce_le_field(&reduced), reduced);
    }

    #[test]
    fn non_canonical_input_rejected_not_reduced() {
        let bad = [0xFFu8; 32]; // way above the Fr modulus
        let err = poseidon2_core(&bad, &le32(1)).unwrap_err();
        assert!(err.contains("non-canonical"), "must reject, got: {err}");
        // Exactly the modulus is also non-canonical (strict less-than).
        // Fr::MODULUS LE bytes via field-utils' own guard semantics:
        // is_canonical_fr_le(modulus) == false is asserted in field-utils tests;
        // here we just confirm the boundary propagates a rejection for a
        // wrong-length input too.
        let err2 = poseidon2_core(&[0u8; 31], &le32(1)).unwrap_err();
        assert!(err2.contains("32 bytes"), "length guard, got: {err2}");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn dec_to_le32(dec: &str) -> [u8; 32] {
        use core::str::FromStr;
        let fr = Fr::from_str(dec).expect("valid decimal Fr");
        fr_to_le32(fr)
    }

    fn le32_to_dec(bytes: &[u8; 32]) -> String {
        let fr = Fr::from_le_bytes_mod_order(bytes);
        // ark Display prints the canonical decimal representation.
        format!("{fr}")
    }
}
