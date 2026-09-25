// =============================================================================
// W-VETKEYS §C — P-256 ECDSA TRANSCRIPT VERIFICATION (brief V2)
// =============================================================================
//
// Verification ONLY. The purpose fence from CTO adjudication 7cd63a14… item B:
// this module checks signatures over `transcript::ApprovalV1` / `RevokeV1`
// bytes and does nothing else — no signing, no key generation, no other
// canister. (The `p256` feature set that exposes the verifier also compiles the
// signer type; we never construct one, which is a review-visible property of
// this file rather than something the feature flags can enforce.)
//
// PINNED WIRE FORMATS, both refused if they differ by a byte:
//   * the public key is SPKI DER (`SubjectPublicKeyInfo`) — the encoding
//     WebCrypto's `exportKey("spki", …)` produces, so the wallet exports and
//     the canister parses the same bytes with no re-encoding step in between,
//     and `SHA-256(SPKI)` in the transcript commits to exactly what is stored;
//   * the signature is FIXED 64-byte `r || s`, big-endian, NOT DER. DER is a
//     malleable container (length forms, leading zeros) and two encodings of
//     one signature would defeat the point of binding it; the fixed form is
//     also what WebCrypto's `sign("ECDSA", …)` emits natively.
//
// LOW-S IS ENFORCED BY REJECTION, NOT NORMALIZATION (adjudication item B,
// brief V2 §C). Normalizing a high-S signature and then accepting it would
// make TWO distinct byte strings verify against one transcript — signature
// malleability, which is a replay surface wherever a signature is treated as
// an identifier. So a high-S signature is REFUSED and says so.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

/// The fixed ECDSA-P256 signature width: `r || s`, 32 bytes each.
pub const SIGNATURE_BYTES: usize = 64;

/// Why a transcript signature was refused. Each variant is a distinct,
/// separately-tested refusal — collapsing them into one "bad signature" would
/// make the negative arms unable to prove WHICH guard bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureRejection {
    /// The stored SPKI is not a parseable P-256 public key.
    MalformedPublicKey,
    /// Not exactly 64 bytes, or not a valid `(r, s)` pair.
    MalformedSignature,
    /// `s > n/2`. Refused, never normalized-and-accepted.
    HighS,
    /// Well-formed, correctly encoded, and simply does not verify.
    DoesNotVerify,
}

impl SignatureRejection {
    pub fn reason(&self) -> &'static str {
        match self {
            SignatureRejection::MalformedPublicKey => {
                "the approving device's signing key is not a parseable P-256 SPKI public key"
            }
            SignatureRejection::MalformedSignature => {
                "the approval signature is not a 64-byte P-256 (r || s) signature"
            }
            SignatureRejection::HighS => {
                "the approval signature has a high-S scalar and is REFUSED (low-S is required; \
                 accepting a normalized high-S signature would make two byte strings verify \
                 against one transcript)"
            }
            SignatureRejection::DoesNotVerify => {
                "the approval signature does not verify against the approving device's key \
                 over the canonical transcript"
            }
        }
    }
}

/// Verify `signature` over the canonical `transcript` bytes under the SPKI
/// public key `spki`.
///
/// The caller passes the transcript it INTENDS to act on — built from the very
/// fields being written — so a signature can never be verified against one set
/// of bytes and applied to another.
pub fn verify_transcript(
    spki: &[u8],
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), SignatureRejection> {
    let key = VerifyingKey::from_public_key_der(spki)
        .map_err(|_| SignatureRejection::MalformedPublicKey)?;

    // Length first: `from_slice` would also refuse, but an explicit width check
    // keeps "we accept exactly one signature encoding" a property of this file
    // rather than of a dependency's internals.
    if signature.len() != SIGNATURE_BYTES {
        return Err(SignatureRejection::MalformedSignature);
    }
    let sig = Signature::from_slice(signature).map_err(|_| SignatureRejection::MalformedSignature)?;

    // `normalize_s` returns `Some` exactly when the scalar WAS high. We use it
    // as a detector and throw the normalized value away.
    if sig.normalize_s().is_some() {
        return Err(SignatureRejection::HighS);
    }

    key.verify(transcript, &sig)
        .map_err(|_| SignatureRejection::DoesNotVerify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    /// A deterministic test device key. Tests SIGN — production never does.
    fn device(seed: u8) -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("a valid P-256 scalar");
        let spki = sk
            .verifying_key()
            .to_public_key_der()
            .expect("SPKI encode")
            .as_bytes()
            .to_vec();
        (sk, spki)
    }

    fn sign(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = sk.sign(msg);
        sig.to_bytes().to_vec()
    }

    #[test]
    fn a_genuine_signature_verifies() {
        let (sk, spki) = device(0x11);
        let msg = b"canonical transcript bytes";
        assert_eq!(verify_transcript(&spki, msg, &sign(&sk, msg)), Ok(()));
    }

    /// The signature binds the MESSAGE: one flipped byte and it is refused.
    /// This is what makes every per-field tamper arm in `transcript` bite at
    /// the verification boundary too.
    #[test]
    fn a_signature_over_different_bytes_does_not_verify() {
        let (sk, spki) = device(0x22);
        let sig = sign(&sk, b"transcript A");
        assert_eq!(
            verify_transcript(&spki, b"transcript B", &sig),
            Err(SignatureRejection::DoesNotVerify)
        );
    }

    /// The signature binds the KEY: another device's signature is refused.
    #[test]
    fn another_devices_signature_does_not_verify() {
        let (sk_a, _) = device(0x33);
        let (_, spki_b) = device(0x44);
        let msg = b"transcript";
        assert_eq!(
            verify_transcript(&spki_b, msg, &sign(&sk_a, msg)),
            Err(SignatureRejection::DoesNotVerify)
        );
    }

    /// HIGH-S IS REFUSED, not normalized. Constructed by taking a genuine
    /// low-S signature and negating `s` (`s' = n - s`), which is the classic
    /// malleability transform: the pair still satisfies the ECDSA equation, so
    /// a verifier without this check ACCEPTS it — that is exactly what makes
    /// the arm load-bearing rather than decorative.
    #[test]
    fn a_high_s_signature_is_refused_rather_than_normalized() {
        let (sk, spki) = device(0x55);
        let msg = b"transcript to malleate";
        // NOTE, load-bearing for the wallet: P-256 signers do NOT emit low-S
        // by convention (that is a secp256k1 habit) — neither RustCrypto's nor
        // WebCrypto's. Roughly half of all honest signatures are high-S. The
        // canister still REFUSES them per the ruling, so the WALLET must
        // normalize `s` to `n - s` before sending. This fixture therefore
        // normalizes explicitly rather than assuming the signer did.
        let raw = Signature::from_slice(&sign(&sk, msg)).unwrap();
        let low = raw.normalize_s().unwrap_or(raw);
        assert!(low.normalize_s().is_none(), "`low` must genuinely be low-S");
        assert_eq!(
            verify_transcript(&spki, msg, &low.to_bytes()),
            Ok(()),
            "the normalized signature is what a correct wallet sends, and it must verify"
        );

        // s' = n - s, r unchanged.
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -s).expect("the negated scalar is a valid signature");
        assert!(high.normalize_s().is_some(), "the fixture must genuinely be high-S");

        assert_eq!(
            verify_transcript(&spki, msg, &high.to_bytes()),
            Err(SignatureRejection::HighS),
            "a high-S signature must be REFUSED — normalizing and accepting it would let two \
             distinct byte strings verify against one transcript"
        );
        // Non-vacuity: the SAME signature verifies once normalized, so the
        // refusal is our POLICY and not a broken fixture — and the two byte
        // strings are genuinely different, which is the malleability being
        // closed.
        let normalized = high.normalize_s().expect("it is high-S");
        assert_ne!(normalized.to_bytes(), high.to_bytes());
        assert_eq!(verify_transcript(&spki, msg, &normalized.to_bytes()), Ok(()));
    }

    #[test]
    fn a_wrong_width_signature_is_refused_before_any_curve_work() {
        let (sk, spki) = device(0x66);
        let msg = b"transcript";
        let mut sig = sign(&sk, msg);
        sig.push(0x00);
        assert_eq!(
            verify_transcript(&spki, msg, &sig),
            Err(SignatureRejection::MalformedSignature),
            "trailing bytes on the signature must be refused, not ignored"
        );
        assert_eq!(
            verify_transcript(&spki, msg, &sig[..SIGNATURE_BYTES - 1]),
            Err(SignatureRejection::MalformedSignature)
        );
        assert_eq!(
            verify_transcript(&spki, msg, &[]),
            Err(SignatureRejection::MalformedSignature)
        );
    }

    #[test]
    fn a_malformed_public_key_is_refused() {
        let (sk, _) = device(0x77);
        let msg = b"transcript";
        assert_eq!(
            verify_transcript(b"not an spki", msg, &sign(&sk, msg)),
            Err(SignatureRejection::MalformedPublicKey)
        );
    }

    /// DER-encoded signatures are NOT accepted: one signature must have exactly
    /// one accepted encoding.
    #[test]
    fn a_der_encoded_signature_is_refused() {
        let (sk, spki) = device(0x88);
        let msg = b"transcript";
        let sig = Signature::from_slice(&sign(&sk, msg)).unwrap();
        let der = sig.to_der();
        assert_eq!(
            verify_transcript(&spki, msg, der.as_bytes()),
            Err(SignatureRejection::MalformedSignature),
            "DER is a malleable container; the fixed 64-byte form is the only accepted one"
        );
    }
}
