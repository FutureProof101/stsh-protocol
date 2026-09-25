//! BN254 field canonicality helpers (#116).
//!
//! A 32-byte little-endian encoding is *canonical* when the 256-bit integer
//! value it represents is strictly less than the field modulus.  Both
//! `Fr::from_le_bytes_mod_order` and `Fq::from_le_bytes_mod_order` silently
//! reduce non-canonical inputs, which enables aliasing attacks: two different
//! 32-byte arrays that differ by exactly the field modulus reduce to the same
//! field element.  Enforcing canonicality at every boundary prevents this.
//!
//! Public signals (nullifier_hash, anchor, output commitments) must be
//! canonical before they are used as registry/Merkle keys.  Proof coordinates
//! must be canonical to prevent proof-malleability.

#![forbid(unsafe_code)]

mod poseidon_params;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

/// DEF-111 within-deployment purpose tag for the value-bound Merkle leaf hash.
/// Continues the circuit's purpose-tag sequence: PK_DOMAIN=1, NULLIFIER_DOMAIN=2,
/// COMMITMENT_DOMAIN=3, MERKLE_LEAF_DOMAIN=4. It is the LAST Poseidon input.
pub const MERKLE_LEAF_DOMAIN: u64 = 4;

/// DEF-111 / B-prime value-bound outer Merkle leaf hash.
///
/// `leaf = Poseidon(value, inner_note_commitment, MERKLE_LEAF_DOMAIN)`  (Poseidon(3), t=4)
///
/// This MUST match `circuits/spend.circom` `MerkleLeaf` byte-for-byte (same params,
/// arity, field order, domain tag) — the leaf-agreement test guards it. `domain_sep`
/// is intentionally omitted (0b ruling): `inner_commitment` already binds it.
///
/// - `value` is the note's spendable value (on deposit: `private_balance_credit`,
///   the exact amount booked to `PRIVATE_LIABILITY`).
/// - `inner_commitment` is the canonical little-endian 32-byte inner note commitment.
/// - Output is the leaf as canonical little-endian 32 bytes.
///
/// Uses the hardcoded fixed t=4 param set (never `new_circom`) to stay under the
/// IC Wasm function-complexity ceiling. Panics only on Poseidon init failure
/// (impossible with the pinned fixed parameters).
pub fn merkle_leaf(value: u128, inner_commitment: &[u8; 32]) -> [u8; 32] {
    let value_fr = Fr::from(value);
    let inner_fr = Fr::from_le_bytes_mod_order(inner_commitment);
    let domain_fr = Fr::from(MERKLE_LEAF_DOMAIN);

    let mut hasher = Poseidon::<Fr>::new(poseidon_params::fixed_poseidon_t4_params());
    let result = hasher
        .hash(&[value_fr, inner_fr, domain_fr])
        .expect("Poseidon t=4 leaf hash failed");

    let bytes = result.into_bigint().to_bytes_le();
    debug_assert_eq!(bytes.len(), 32, "BN254/Fr must produce exactly 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

// BN254 Fr (scalar field) modulus in little-endian bytes.
// = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
// Verified in test_fr_modulus_bytes_match_arkworks below — the exact mirror of
// the Fq pin.
//
// U5-4 (lane A-3): the previous comment here asserted that ark_ff 0.4's
// BigInt::to_bytes_le() iterates limbs 0..3 with index 0 holding a Montgomery
// constant, so that these bytes were "NOT the canonical little-endian
// representation of the integer — it is a mix". THAT CLAIM IS FALSE, and it was
// measured rather than argued: these committed bytes are byte-identical to
// <ark_bn254::Fr as PrimeField>::MODULUS.to_bytes_le(), which the new test now
// pins. It was also self-refuting against the tree, since the Fq pin below
// asserts exactly that equality through the same generic to_bytes_le() path and
// has always passed.
//
// The comment additionally claimed verification "by
// test_fr_modulus_bytes_match_arkworks below" while no such test existed. It
// exists now.
const FR_MODULUS_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43,
    0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

// BN254 Fq (base field) modulus in little-endian bytes.
// = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
// Verified in test_fq_modulus_bytes_match_arkworks below.
const FQ_MODULUS_LE: [u8; 32] = [
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c,
    0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// Returns `true` if `bytes` is a canonical little-endian BN254 Fr (scalar
/// field) encoding, i.e. the 256-bit integer it represents is strictly less
/// than the Fr modulus.
///
/// Call this before `Fr::from_le_bytes_mod_order` to ensure the input is
/// canonical and prevent aliasing attacks on registry/Merkle keys.
#[inline]
pub fn is_canonical_fr_le(bytes: &[u8; 32]) -> bool {
    le_lt(bytes, &FR_MODULUS_LE)
}

/// Audit-explicit alias for [`is_canonical_fr_le`] naming the curve explicitly.
/// Use this in security-sensitive endpoints where BN254 context must be
/// unambiguous to a reader unfamiliar with the crate's scope.
pub use is_canonical_fr_le as is_canonical_bn254_fr;

/// Returns `true` if `bytes` is a canonical little-endian BN254 Fq (base
/// field) encoding, i.e. the 256-bit integer it represents is strictly less
/// than the Fq modulus.
///
/// Call this before `Fq::from_le_bytes_mod_order` to prevent proof
/// malleability via non-canonical G1/G2 coordinate encodings.
#[inline]
pub fn is_canonical_fq_le(bytes: &[u8; 32]) -> bool {
    le_lt(bytes, &FQ_MODULUS_LE)
}

/// Little-endian byte-array comparison: returns `true` iff `a < b`.
/// Iterates from the most-significant byte (index 31) down to index 0.
#[inline]
fn le_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Less    => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal   => continue,
        }
    }
    false // equal → not strictly less → not canonical (field elements are 0..modulus-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{PrimeField, BigInteger};

    // ── DEF-111 MerkleLeaf ↔ circuit agreement (the load-bearing test) ────────
    //
    // Vector computed by circomlibjs `poseidon([value, inner, 4])` — circomlibjs
    // IS the reference implementation of the circuit's Poseidon(3) `MerkleLeaf`.
    // Proving the Rust fixed-t4 helper reproduces this byte-for-byte proves the
    // generated t=4 params match circomlib (the "single Poseidon both sides"
    // guarantee, DEF-111 §5.1). A param/arity/order mismatch fails HERE.
    #[test]
    fn test_merkle_leaf_agrees_with_circomlib_vector() {
        // value = 100_000_000 (1 STSH); inner = 12345 (0x3039), little-endian.
        let mut inner = [0u8; 32];
        inner[0] = 0x39;
        inner[1] = 0x30;
        // circomlibjs poseidon([100000000, 12345, 4]) as canonical little-endian 32 bytes.
        let expected: [u8; 32] = [
            0x30, 0x2d, 0xfd, 0x38, 0x03, 0x1c, 0xc4, 0x53,
            0xe7, 0x35, 0x00, 0x7f, 0xb3, 0x48, 0x9b, 0x4a,
            0x99, 0xfb, 0x28, 0x1a, 0xa7, 0xf2, 0x82, 0x80,
            0xe8, 0x05, 0xc8, 0x8f, 0xf6, 0xc0, 0xe5, 0x2a,
        ];
        let got = merkle_leaf(100_000_000u128, &inner);
        assert_eq!(
            got, expected,
            "Rust merkle_leaf must byte-equal circomlib Poseidon(3)[value, inner, 4] \
             — a mismatch is a circuit↔pool leaf-agreement break (DEF-111)"
        );
    }

    #[test]
    fn test_merkle_leaf_deterministic_and_nonzero() {
        let inner = [7u8; 32];
        let a = merkle_leaf(42, &inner);
        let b = merkle_leaf(42, &inner);
        assert_eq!(a, b, "merkle_leaf must be deterministic");
        assert_ne!(a, [0u8; 32], "a real MerkleLeaf output is never all-zero (domain-separated)");
        // Value binds: a different value yields a different leaf (this is the DEF-111 property).
        let c = merkle_leaf(43, &inner);
        assert_ne!(a, c, "leaf must change when the bound value changes");
    }

    // ── A4: circuit-arity Poseidon byte-equality vectors ──────────────────────
    //
    // Poseidon(4) (DEF-109-A nullifier / DEF-035 domain hash) and Poseidon(6)
    // (inner note commitment) are circuit-only in production — no canister
    // recomputes them, so there are deliberately NO fixed_poseidon_t5/t7
    // production param sets. These tests close the POSEIDON_PARAMS.md
    // audit-completeness item by proving light-poseidon's circom
    // parameterisation byte-equals the repo-pinned circomlibjs 0.1.7 reference
    // (the implementation behind the circuit's Poseidon) at both arities, and
    // — for Poseidon(4) — the circuit's own recorded domainHash vector.
    //
    // `new_circom` here is TEST-ONLY: poseidon_params.rs forbids
    // `new_circom`/`get_poseidon_parameters` in production/runtime paths
    // because they compile to a multi-MB function that breaks the IC Wasm
    // function-complexity ceiling. A #[cfg(test)] native test binary has no
    // such ceiling and never reaches canister Wasm.

    /// TEST-ONLY: circomlib-parameter Poseidon over `inputs`, canonical LE-32 output.
    fn poseidon_circom_le32(inputs: &[Fr]) -> [u8; 32] {
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
            .expect("new_circom must support this arity");
        let out = hasher.hash(inputs).expect("Poseidon hash failed");
        let bytes = out.into_bigint().to_bytes_le();
        let mut le = [0u8; 32];
        le.copy_from_slice(&bytes);
        le
    }

    #[test]
    fn test_poseidon4_agrees_with_circomlib_vector() {
        // Vector 1 — THE circuit-recorded value (ground truth), POSEIDON_PARAMS.md
        // "Canonical domainHash.out for the staging vector [2, 0, 2, 1]":
        // circomlib Poseidon(4) of the staging domain tuple
        // [DOMAIN_POOL_CANISTER_ID=2, DOMAIN_ASSET_ID=0, DOMAIN_CIRCUIT_VERSION=2,
        //  DOMAIN_NETWORK_ID=1]. Decimal:
        // 15322108636650179001747904453574416725467746941237171169185376291227768775020.
        // A fixed input→output math fact — stays valid after A1 real-principal
        // injection (A1 changes which tuple the circuit uses, not this hash).
        let expected_recorded: [u8; 32] = [
            0x6c, 0xe1, 0x24, 0x45, 0x53, 0x69, 0xd7, 0xaf,
            0x3f, 0x1b, 0x92, 0x50, 0x4d, 0xe9, 0x8c, 0xb5,
            0x27, 0x08, 0xf2, 0xda, 0xe2, 0x0c, 0x30, 0x38,
            0x48, 0xfd, 0x33, 0xf7, 0x93, 0x01, 0xe0, 0x21,
        ];
        assert_eq!(
            poseidon_circom_le32(&[Fr::from(2u64), Fr::from(0u64), Fr::from(2u64), Fr::from(1u64)]),
            expected_recorded,
            "Poseidon(4)([2,0,2,1]) must byte-equal the circuit-recorded \
             POSEIDON_PARAMS.md domainHash vector — a mismatch means light-poseidon \
             and the circuit's circomlib Poseidon disagree at t=5 (soundness issue)"
        );

        // Vector 2 — circomlibjs 0.1.7 poseidon([0, 0, 0, 0]). Decimal:
        // 2351654555892372227640888372176282444150254868378439619268573230312091195718.
        let expected_zeros: [u8; 32] = [
            0x46, 0x99, 0x3e, 0xb7, 0x6d, 0x20, 0xc1, 0x88,
            0x04, 0x06, 0x79, 0x8b, 0x1b, 0x92, 0x37, 0x09,
            0x25, 0x15, 0xc2, 0xd9, 0x94, 0x96, 0x20, 0x51,
            0x0e, 0xc7, 0x19, 0x6e, 0x43, 0xfd, 0x32, 0x05,
        ];
        assert_eq!(
            poseidon_circom_le32(&[Fr::from(0u64); 4]),
            expected_zeros,
            "Poseidon(4)([0,0,0,0]) must byte-equal the circomlibjs 0.1.7 reference"
        );

        // Vector 3 — circomlibjs 0.1.7 poseidon([1, 2, 3, 4]). Decimal:
        // 18821383157269793795438455681495246036402687001665670618754263018637548127333.
        let expected_seq: [u8; 32] = [
            0x65, 0x04, 0x25, 0x65, 0xdf, 0x25, 0xa5, 0xba,
            0x3d, 0x66, 0xe0, 0x1c, 0xbb, 0x0e, 0xe6, 0x37,
            0x98, 0x0b, 0x51, 0xe4, 0x40, 0xfa, 0xce, 0x9d,
            0xd7, 0xfd, 0xc1, 0xb6, 0x7d, 0x86, 0x9c, 0x29,
        ];
        assert_eq!(
            poseidon_circom_le32(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]),
            expected_seq,
            "Poseidon(4)([1,2,3,4]) must byte-equal the circomlibjs 0.1.7 reference"
        );

        // Vector 4 — circomlibjs 0.1.7 poseidon([p-1, p-1, p-1, p-1]), the largest
        // canonical Fr element at every position (full-range check). Decimal:
        // 6787226826147679890210956261533278127703365090202917080879592273165705475059.
        let p_minus_1 = -Fr::from(1u64);
        let expected_max: [u8; 32] = [
            0xf3, 0xf3, 0x3a, 0xfb, 0x4c, 0xed, 0xae, 0x6a,
            0x3d, 0x9a, 0xcb, 0xbe, 0x92, 0x78, 0x80, 0xf9,
            0x3b, 0x77, 0x31, 0x1c, 0x45, 0xa2, 0x16, 0x3c,
            0xe9, 0x07, 0x86, 0xe5, 0x2a, 0x6f, 0x01, 0x0f,
        ];
        assert_eq!(
            poseidon_circom_le32(&[p_minus_1; 4]),
            expected_max,
            "Poseidon(4)([p-1; 4]) must byte-equal the circomlibjs 0.1.7 reference"
        );
    }

    #[test]
    fn test_poseidon6_agrees_with_circomlib_vector() {
        // Vector 1 — circomlibjs 0.1.7 poseidon([0, 0, 0, 0, 0, 0]). Decimal:
        // 14408838593220040598588012778523101864903887657864399481915450526643617223637.
        let expected_zeros: [u8; 32] = [
            0xd5, 0x53, 0xb3, 0x2e, 0xb0, 0x2b, 0x48, 0xb3,
            0xd5, 0x73, 0xa0, 0xb8, 0x42, 0xf4, 0xa4, 0x86,
            0xae, 0x47, 0xc0, 0xab, 0x84, 0x70, 0xec, 0x2b,
            0x50, 0xa3, 0xa3, 0x57, 0x17, 0x1d, 0xdb, 0x1f,
        ];
        assert_eq!(
            poseidon_circom_le32(&[Fr::from(0u64); 6]),
            expected_zeros,
            "Poseidon(6)([0;6]) must byte-equal the circomlibjs 0.1.7 reference \
             — a mismatch means light-poseidon and the circuit's circomlib Poseidon \
             disagree at t=7 (soundness issue)"
        );

        // Vector 2 — circomlibjs 0.1.7 poseidon([1, 2, 3, 4, 5, 6]). Decimal:
        // 20400040500897583745843009878988256314335038853985262692600694741116813247201.
        let expected_seq: [u8; 32] = [
            0xe1, 0x02, 0x63, 0x2f, 0xca, 0x4c, 0x4a, 0x13,
            0x39, 0x22, 0x5f, 0xb0, 0x68, 0x0a, 0x49, 0x38,
            0x75, 0xa4, 0xde, 0x94, 0xf0, 0xeb, 0xc8, 0x13,
            0x28, 0x44, 0x84, 0x00, 0x85, 0x03, 0x1a, 0x2d,
        ];
        assert_eq!(
            poseidon_circom_le32(&[
                Fr::from(1u64), Fr::from(2u64), Fr::from(3u64),
                Fr::from(4u64), Fr::from(5u64), Fr::from(6u64),
            ]),
            expected_seq,
            "Poseidon(6)([1..6]) must byte-equal the circomlibjs 0.1.7 reference"
        );

        // Vector 3 — circomlibjs 0.1.7 poseidon([6, 5, 4, 3, 2, 1]) (order-sensitivity:
        // reversed inputs must give a different, specific value). Decimal:
        // 12472382259357866781095149111237885640997695367169664731358145683235794062643.
        let expected_rev: [u8; 32] = [
            0x33, 0x0d, 0xf4, 0xd7, 0x36, 0xbe, 0xe0, 0xcf,
            0xe3, 0xf2, 0x1d, 0x74, 0x2d, 0xca, 0x6e, 0xb4,
            0x5f, 0x9f, 0xee, 0x38, 0x4f, 0x08, 0x2a, 0x57,
            0xf9, 0xca, 0xbe, 0xe6, 0x41, 0x1e, 0x93, 0x1b,
        ];
        assert_eq!(
            poseidon_circom_le32(&[
                Fr::from(6u64), Fr::from(5u64), Fr::from(4u64),
                Fr::from(3u64), Fr::from(2u64), Fr::from(1u64),
            ]),
            expected_rev,
            "Poseidon(6)([6..1]) must byte-equal the circomlibjs 0.1.7 reference"
        );

        // Vector 4 — circomlibjs 0.1.7 poseidon([p-1, 0, p-1, 0, p-1, 0]), largest
        // canonical Fr element interleaved with zero (full-range check). Decimal:
        // 19320279253501630092982531011347938793230922775465623968840970280917650920688.
        let p_minus_1 = -Fr::from(1u64);
        let zero = Fr::from(0u64);
        let expected_max: [u8; 32] = [
            0xf0, 0x54, 0x0c, 0x99, 0x01, 0x9d, 0x6c, 0x10,
            0x71, 0x7d, 0x81, 0x38, 0x6a, 0x96, 0x2a, 0xd4,
            0xee, 0x9c, 0xd0, 0x6c, 0xdf, 0x57, 0xf6, 0xa3,
            0xce, 0x4d, 0x9f, 0x66, 0xfa, 0xe3, 0xb6, 0x2a,
        ];
        assert_eq!(
            poseidon_circom_le32(&[p_minus_1, zero, p_minus_1, zero, p_minus_1, zero]),
            expected_max,
            "Poseidon(6)([p-1,0,p-1,0,p-1,0]) must byte-equal the circomlibjs 0.1.7 reference"
        );
    }

    // ── Modulus constant sanity checks ────────────────────────────────────────
    //
    // These tests guard against transcription errors in the hardcoded byte
    // arrays.  They must pass before any canonical-encoding enforcement is
    // trusted.

    // Verify FR_MODULUS_LE is the correct canonical threshold by testing the
    // from_le_bytes_mod_order boundary directly.
    //
    // DEFINITION: a 32-byte LE array is canonical iff from_le_bytes_mod_order
    // does NOT reduce it (i.e. the array already represents an element in
    // 0..modulus-1).  So:
    //   from_le_bytes_mod_order(modulus_le) == 0   (modulus reduces to zero)
    //   from_le_bytes_mod_order(modulus_le - 1) != 0  (largest canonical value)
    //
    // U5-4 (lane A-3): a NOTE here previously claimed MODULUS.to_bytes_le() and
    // FR_MODULUS_LE "differ in bytes 0–7" because of Montgomery limb ordering.
    // Refuted by measurement — they are byte-identical, and
    // test_fr_modulus_bytes_match_arkworks now pins that. This test is retained
    // unchanged because it proves a genuinely DIFFERENT property: the reduction
    // boundary. Only the inaccurate comment was removed.
    #[test]
    fn test_fr_modulus_bytes_is_reduction_boundary() {
        // FR_MODULUS_LE must reduce to zero (it IS the modulus)
        let fr_at_modulus = ark_bn254::Fr::from_le_bytes_mod_order(&FR_MODULUS_LE);
        assert_eq!(
            fr_at_modulus,
            ark_bn254::Fr::from(0u64),
            "FR_MODULUS_LE must reduce to Fr::zero() — the modulus maps to the additive identity"
        );
        // FR_MODULUS_LE − 1 must NOT reduce (it is the largest canonical value)
        let mut modulus_minus_one = FR_MODULUS_LE;
        for i in 0..32 {
            if modulus_minus_one[i] > 0 {
                modulus_minus_one[i] -= 1;
                break;
            }
            modulus_minus_one[i] = 0xFF;
        }
        let fr_minus_one = ark_bn254::Fr::from_le_bytes_mod_order(&modulus_minus_one);
        assert_ne!(
            fr_minus_one,
            ark_bn254::Fr::from(0u64),
            "FR_MODULUS_LE - 1 must not reduce to zero; it is the largest canonical Fr element"
        );
    }

    /// U5-4 (lane A-3) — the exact Fr mirror of `test_fq_modulus_bytes_match_arkworks`.
    ///
    /// This test is what the constant's doc comment claimed existed and did not:
    /// `FR_MODULUS_LE` was documented as "verified by
    /// test_fr_modulus_bytes_match_arkworks below" while no such test was in the
    /// tree. It exists now, and it MEASURES the claim rather than inheriting it.
    #[test]
    fn test_fr_modulus_bytes_match_arkworks() {
        let ark_le = <ark_bn254::Fr as PrimeField>::MODULUS.to_bytes_le();
        let ark_bytes: [u8; 32] = ark_le.try_into()
            .expect("ark_bn254::Fr::MODULUS must be exactly 32 bytes");
        assert_eq!(
            ark_bytes, FR_MODULUS_LE,
            "FR_MODULUS_LE does not match ark_bn254::Fr::MODULUS — transcription error"
        );
    }

    #[test]
    fn test_fq_modulus_bytes_match_arkworks() {
        let ark_le = <ark_bn254::Fq as PrimeField>::MODULUS.to_bytes_le();
        let ark_bytes: [u8; 32] = ark_le.try_into()
            .expect("ark_bn254::Fq::MODULUS must be exactly 32 bytes");
        assert_eq!(
            ark_bytes, FQ_MODULUS_LE,
            "FQ_MODULUS_LE does not match ark_bn254::Fq::MODULUS — transcription error"
        );
    }

    // ── Fr canonicality ───────────────────────────────────────────────────────

    #[test]
    fn test_zero_is_canonical_fr() {
        assert!(is_canonical_fr_le(&[0u8; 32]), "zero must be canonical Fr");
    }

    #[test]
    fn test_one_is_canonical_fr() {
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(is_canonical_fr_le(&one), "one must be canonical Fr");
    }

    #[test]
    fn test_modulus_minus_one_is_canonical_fr() {
        let mut m_minus_1 = FR_MODULUS_LE;
        // Subtract 1 from a little-endian number
        for i in 0..32 {
            if m_minus_1[i] > 0 {
                m_minus_1[i] -= 1;
                break;
            }
            m_minus_1[i] = 0xFF;
        }
        assert!(is_canonical_fr_le(&m_minus_1),
            "Fr modulus - 1 must be canonical");
    }

    #[test]
    fn test_modulus_is_not_canonical_fr() {
        assert!(!is_canonical_fr_le(&FR_MODULUS_LE),
            "Fr modulus itself must NOT be canonical");
    }

    #[test]
    fn test_modulus_plus_one_is_not_canonical_fr() {
        let mut m_plus_1 = FR_MODULUS_LE;
        for i in 0..32 {
            m_plus_1[i] = m_plus_1[i].wrapping_add(1);
            if m_plus_1[i] != 0 { break; }
        }
        assert!(!is_canonical_fr_le(&m_plus_1),
            "Fr modulus + 1 must NOT be canonical");
    }

    #[test]
    fn test_all_ff_is_not_canonical_fr() {
        assert!(!is_canonical_fr_le(&[0xFFu8; 32]),
            "0xFF...FF must NOT be canonical Fr (exceeds both Fr and Fq moduli)");
    }

    // ── Fq canonicality ───────────────────────────────────────────────────────

    #[test]
    fn test_zero_is_canonical_fq() {
        assert!(is_canonical_fq_le(&[0u8; 32]), "zero must be canonical Fq");
    }

    #[test]
    fn test_modulus_minus_one_is_canonical_fq() {
        let mut m_minus_1 = FQ_MODULUS_LE;
        for i in 0..32 {
            if m_minus_1[i] > 0 {
                m_minus_1[i] -= 1;
                break;
            }
            m_minus_1[i] = 0xFF;
        }
        assert!(is_canonical_fq_le(&m_minus_1),
            "Fq modulus - 1 must be canonical");
    }

    #[test]
    fn test_modulus_is_not_canonical_fq() {
        assert!(!is_canonical_fq_le(&FQ_MODULUS_LE),
            "Fq modulus itself must NOT be canonical");
    }

    #[test]
    fn test_all_ff_is_not_canonical_fq() {
        assert!(!is_canonical_fq_le(&[0xFFu8; 32]),
            "0xFF...FF must NOT be canonical Fq");
    }

    // ── Fr vs Fq modulus relationship ─────────────────────────────────────────
    //
    // BN254: Fr < Fq.  A value canonical in Fr is also canonical in Fq.

    #[test]
    fn test_fr_modulus_is_canonical_fq() {
        // Fr::MODULUS < Fq::MODULUS — so Fr modulus bytes are canonical in Fq.
        assert!(is_canonical_fq_le(&FR_MODULUS_LE),
            "Fr modulus must be a canonical Fq element (Fr::MODULUS < Fq::MODULUS)");
    }
}
