// =============================================================================
// W-VETKEYS Layer-1 — CANONICAL APPROVAL TRANSCRIPTS (brief V2 §C)
// =============================================================================
//
// COMMIT-1 FREEZE. This module is the byte-exact encoding of the two signed
// transcripts and NOTHING ELSE: no signature verification, no state, no
// endpoint. Verification (P-256 ECDSA, low-S, nonce consumption) lands in a
// later commit and consumes `encode()` unchanged.
//
// WHY AN EXPLICIT ENCODER RATHER THAN CANDID/SERDE. The signed bytes are a
// security boundary: an attacker who can make two DIFFERENT field assignments
// produce the SAME bytes gets a signature transplant for free. Candid's
// encoding is a serialization format, not a frozen injective commitment — it
// carries type tables, admits field reordering at the type level, and is
// allowed to change across candid releases. So the transcript is written out
// byte by byte here, frozen against fixture vectors, and never derived.
//
// THE ENCODING RULE (brief V2 §C, "length-prefixed injective encoding"):
//
//   * every VARIABLE-length field is `u32-LE length || bytes`;
//   * every FIXED-width field is emitted raw at its pinned width
//     (version `u16-LE`, hashes 32 B, nonce 16 B, expiry `u64-LE`);
//   * field order is FIXED, there are NO optional fields, and nothing else is
//     appended.
//
// That is injective: at every point in the stream the decoder knows the next
// field's width — either from the pinned width or from the immediately
// preceding u32-LE prefix — so no two distinct field assignments can produce
// the same byte string. The `collision_*` vectors below prove the specific
// failure this closes: moving a byte across the boundary between two ADJACENT
// variable-length fields (`issuer_device_id` / `new_device_id`), which a naive
// concatenating encoder would collapse to identical bytes.
//
// ACTION SEPARATION. `ApprovalV1` and `RevokeV1` are distinct schemas with
// distinct `action` tags INSIDE the signed bytes, and are never field-
// compatible: the approval carries three hashes the revoke does not, so a
// revoke transcript can never be re-read as an approval (its length alone
// refuses), and the action tag refuses the reverse.

use candid::Principal;

/// Protocol tag — PINNED (brief V2 §C). Present in BOTH transcripts: it binds
/// the bytes to this protocol, while `action` separates the two operations.
pub const TRANSCRIPT_PROTOCOL: &[u8] = b"stsh.vetkeys.device-approval";

/// Transcript version — PINNED at 1. An unknown version is rejected BEFORE any
/// cryptographic work (brief V2 §C).
pub const TRANSCRIPT_VERSION: u16 = 1;

/// Action tag for `register_device`.
pub const ACTION_REGISTER_DEVICE: &[u8] = b"register_device";

/// Action tag for `revoke_device`.
pub const ACTION_REVOKE_DEVICE: &[u8] = b"revoke_device";

/// Action tag for `replace_envelope` (D-1b v3 §2).
pub const ACTION_REPLACE_ENVELOPE: &[u8] = b"replace_envelope";

/// L04-07 — the action label for `authorize_re_bootstrap`. Its OWN label, so a
/// captured `RevokeV1` or `ApprovalV1` signature can never be replayed as an
/// authorization to re-open the bootstrap path: the action is inside the
/// signed bytes, immediately after the canister id.
pub const ACTION_AUTHORIZE_RE_BOOTSTRAP: &[u8] = b"authorize_re_bootstrap";

/// LAUNCH-HARDEN-04 O-8 — the action label for `set_device_approval_policy`.
/// Its OWN label, so no other signed operation's transcript can be replayed as
/// a policy change.
pub const ACTION_SET_DEVICE_APPROVAL_POLICY: &[u8] = b"set_device_approval_policy";

/// A SHA-256 digest of a transcript input (SPKI public key, wrapped envelope).
pub type Hash32 = [u8; 32];

/// A single-use approval nonce, scoped to `(principal, issuer_device_id)`.
pub type Nonce16 = [u8; 16];

/// Append a variable-length field: `u32-LE length || bytes`.
///
/// The cast is `u32::try_from`, not `as`: an `as` truncation would let a
/// >4 GiB field wrap its own length prefix, which is precisely the injectivity
/// break this prefix exists to prevent. Nothing in this canister can reach that
/// size (device ids are bounded by `pins::MAX_DEVICE_ID_BYTES` and principals
/// by their own 29-byte cap), so the panic is unreachable-by-bound rather than
/// a runtime path — but it is written as a refusal, not an assumption.
fn push_var(out: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len())
        .expect("transcript field length must fit in u32 — bounded by construction");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
}

/// `ApprovalV1` — the transcript an ACTIVE device signs to authorize the
/// registration of a NEW device (brief V2 §C).
///
/// `canister_id` is the vetkeys canister's OWN principal, checked against
/// `ic_cdk::api::canister_self()` at verification time: it closes cross-
/// canister and cross-deployment transcript reuse.
///
/// `wrapped_secret_hash` is what closes the envelope-substitution hole SSA
/// named in RED-3 — the wrapped blob written by the registration is committed
/// to by the signature, so a valid signature cannot be paired with a swapped
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalV1 {
    pub canister_id: Principal,
    pub principal: Principal,
    pub issuer_device_id: String,
    pub new_device_id: String,
    pub enc_pubkey_hash: Hash32,
    pub sign_pubkey_hash: Hash32,
    pub wrapped_secret_hash: Hash32,
    pub nonce: Nonce16,
    pub expiry_ns: u64,
}

impl ApprovalV1 {
    /// The canonical signed bytes. Field order is the brief's, verbatim, and is
    /// FROZEN by the fixture vectors in this module's tests.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_var(&mut out, TRANSCRIPT_PROTOCOL);
        out.extend_from_slice(&TRANSCRIPT_VERSION.to_le_bytes());
        push_var(&mut out, self.canister_id.as_slice());
        push_var(&mut out, ACTION_REGISTER_DEVICE);
        push_var(&mut out, self.principal.as_slice());
        push_var(&mut out, self.issuer_device_id.as_bytes());
        push_var(&mut out, self.new_device_id.as_bytes());
        out.extend_from_slice(&self.enc_pubkey_hash);
        out.extend_from_slice(&self.sign_pubkey_hash);
        out.extend_from_slice(&self.wrapped_secret_hash);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expiry_ns.to_le_bytes());
        out
    }
}

/// `RevokeV1` — the transcript an ACTIVE device signs to revoke a device.
/// Same header fields as `ApprovalV1`, then the revoke-specific tail. Its own
/// schema; never field-compatible with the approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeV1 {
    pub canister_id: Principal,
    pub principal: Principal,
    pub issuer_device_id: String,
    pub target_device_id: String,
    pub nonce: Nonce16,
    pub expiry_ns: u64,
}

impl RevokeV1 {
    /// The canonical signed bytes. Frozen by fixture vector below.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_var(&mut out, TRANSCRIPT_PROTOCOL);
        out.extend_from_slice(&TRANSCRIPT_VERSION.to_le_bytes());
        push_var(&mut out, self.canister_id.as_slice());
        push_var(&mut out, ACTION_REVOKE_DEVICE);
        push_var(&mut out, self.principal.as_slice());
        push_var(&mut out, self.issuer_device_id.as_bytes());
        push_var(&mut out, self.target_device_id.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expiry_ns.to_le_bytes());
        out
    }
}

/// `ReBootstrapV1` — the transcript an ACTIVE device signs to authorize its
/// principal to re-open the bootstrap path after a revocation to zero devices
/// (L04-07).
///
/// It carries no target device and no key material: the capability it grants
/// is "one future bootstrap registration for this principal", and the device
/// being registered does not exist yet at signing time. The nonce and expiry
/// are what keep it single-use and short-lived, exactly as on the other three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReBootstrapV1 {
    pub canister_id: Principal,
    pub principal: Principal,
    pub issuer_device_id: String,
    pub nonce: Nonce16,
    pub expiry_ns: u64,
}

impl ReBootstrapV1 {
    /// The canonical signed bytes — same encoding rule as the other three.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_var(&mut out, TRANSCRIPT_PROTOCOL);
        out.extend_from_slice(&TRANSCRIPT_VERSION.to_le_bytes());
        push_var(&mut out, self.canister_id.as_slice());
        push_var(&mut out, ACTION_AUTHORIZE_RE_BOOTSTRAP);
        push_var(&mut out, self.principal.as_slice());
        push_var(&mut out, self.issuer_device_id.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expiry_ns.to_le_bytes());
        out
    }
}

/// `SetDeviceApprovalPolicyV1` — the transcript an ACTIVE device signs to set
/// (`require_device_approval = true`) or clear (`false`) its principal's
/// "require device approval" flag (LAUNCH-HARDEN-04 O-8).
///
/// The flag value is a FIXED 1-byte field (0 | 1) directly after the issuer id,
/// so a signature over "set" can never be replayed as "clear" or vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDeviceApprovalPolicyV1 {
    pub canister_id: Principal,
    pub principal: Principal,
    pub issuer_device_id: String,
    pub require_device_approval: bool,
    pub nonce: Nonce16,
    pub expiry_ns: u64,
}

impl SetDeviceApprovalPolicyV1 {
    /// The canonical signed bytes — same encoding rule as the others, frozen by
    /// its own fixture vector below.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_var(&mut out, TRANSCRIPT_PROTOCOL);
        out.extend_from_slice(&TRANSCRIPT_VERSION.to_le_bytes());
        push_var(&mut out, self.canister_id.as_slice());
        push_var(&mut out, ACTION_SET_DEVICE_APPROVAL_POLICY);
        push_var(&mut out, self.principal.as_slice());
        push_var(&mut out, self.issuer_device_id.as_bytes());
        out.push(self.require_device_approval as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expiry_ns.to_le_bytes());
        out
    }
}

/// `ReplaceV1` — the transcript a device signs to replace its OWN stored
/// envelope (D-1b v3 §2). Self-service: the signer and the subject are the same
/// device, which is why there is no separate issuer field.
///
/// `old_envelope_hash` is what closes ROLLBACK and lost-update: the canister
/// refuses unless it hashes to exactly what is stored right now, so a captured
/// older envelope cannot be re-installed and two concurrent replacements cannot
/// silently overwrite each other. `new_envelope_hash` binds the bytes being
/// written, exactly as `ApprovalV1::wrapped_secret_hash` does at registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceV1 {
    pub canister_id: Principal,
    pub principal: Principal,
    pub device_id: String,
    pub old_envelope_hash: Hash32,
    pub new_envelope_hash: Hash32,
    pub nonce: Nonce16,
    pub expiry_ns: u64,
}

impl ReplaceV1 {
    /// The canonical signed bytes — same encoding rule as the other two, and
    /// frozen by its own fixture vector below.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_var(&mut out, TRANSCRIPT_PROTOCOL);
        out.extend_from_slice(&TRANSCRIPT_VERSION.to_le_bytes());
        push_var(&mut out, self.canister_id.as_slice());
        push_var(&mut out, ACTION_REPLACE_ENVELOPE);
        push_var(&mut out, self.principal.as_slice());
        push_var(&mut out, self.device_id.as_bytes());
        out.extend_from_slice(&self.old_envelope_hash);
        out.extend_from_slice(&self.new_envelope_hash);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expiry_ns.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Deterministic fixture principals. Written from raw bytes so the vectors
    /// below do not depend on any textual principal parser.
    fn canister() -> Principal {
        Principal::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x01])
    }
    fn owner() -> Principal {
        Principal::from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x02, 0x01])
    }

    fn h(fill: u8) -> Hash32 {
        [fill; 32]
    }
    fn n(fill: u8) -> Nonce16 {
        [fill; 16]
    }

    fn approval_fixture() -> ApprovalV1 {
        ApprovalV1 {
            canister_id: canister(),
            principal: owner(),
            issuer_device_id: "device-issuer".to_string(),
            new_device_id: "device-new".to_string(),
            enc_pubkey_hash: h(0x11),
            sign_pubkey_hash: h(0x22),
            wrapped_secret_hash: h(0x33),
            nonce: n(0x44),
            expiry_ns: 1_700_000_000_000_000_000,
        }
    }

    fn replace_fixture() -> ReplaceV1 {
        ReplaceV1 {
            canister_id: canister(),
            principal: owner(),
            device_id: "device-issuer".to_string(),
            old_envelope_hash: h(0x66),
            new_envelope_hash: h(0x77),
            nonce: n(0x88),
            expiry_ns: 1_700_000_000_000_000_000,
        }
    }

    fn revoke_fixture() -> RevokeV1 {
        RevokeV1 {
            canister_id: canister(),
            principal: owner(),
            issuer_device_id: "device-issuer".to_string(),
            target_device_id: "device-target".to_string(),
            nonce: n(0x55),
            expiry_ns: 1_700_000_000_000_000_000,
        }
    }

    // ── FROZEN VECTORS ───────────────────────────────────────────────────────
    //
    // These are the commit-1 freeze. They are literal expected bytes, NOT
    // recomputations of `encode()`: a test that re-ran the encoder would pass
    // for any encoder, including a broken one. Moving a field order, a prefix
    // width, or an endianness moves these vectors to RED.

    const APPROVAL_V1_VECTOR_HEX: &str = "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a000000010203040506070801010f00000072656769737465725f6465766963650a000000aabbccddeeff001102010d0000006465766963652d6973737565720a0000006465766963652d6e65771111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444400002a36fe9c9717";
    const REPLACE_V1_VECTOR_HEX: &str = "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a00000001020304050607080101100000007265706c6163655f656e76656c6f70650a000000aabbccddeeff001102010d0000006465766963652d697373756572666666666666666666666666666666666666666666666666666666666666666677777777777777777777777777777777777777777777777777777777777777778888888888888888888888888888888800002a36fe9c9717";
    const REVOKE_V1_VECTOR_HEX: &str = "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a000000010203040506070801010d0000007265766f6b655f6465766963650a000000aabbccddeeff001102010d0000006465766963652d6973737565720d0000006465766963652d7461726765745555555555555555555555555555555500002a36fe9c9717";

    #[test]
    fn approval_v1_frozen_vector() {
        assert_eq!(hex(&approval_fixture().encode()), APPROVAL_V1_VECTOR_HEX);
    }

    #[test]
    fn revoke_v1_frozen_vector() {
        assert_eq!(hex(&revoke_fixture().encode()), REVOKE_V1_VECTOR_HEX);
    }

    /// The encoded length is fully determined by the variable field lengths.
    /// Written out as the sum of the pinned widths so a silently added or
    /// dropped field REDs here even if someone regenerates the hex vectors.
    #[test]
    fn replace_v1_frozen_vector() {
        assert_eq!(hex(&replace_fixture().encode()), REPLACE_V1_VECTOR_HEX);
    }

    #[test]
    fn replace_v1_length_is_the_sum_of_its_pinned_widths() {
        let r = replace_fixture();
        let expected = (4 + TRANSCRIPT_PROTOCOL.len())
            + 2
            + (4 + r.canister_id.as_slice().len())
            + (4 + ACTION_REPLACE_ENVELOPE.len())
            + (4 + r.principal.as_slice().len())
            + (4 + r.device_id.len())
            + 32
            + 32
            + 16
            + 8;
        assert_eq!(r.encode().len(), expected);
    }

    /// Every field of the replacement is bound — including the OLD envelope
    /// hash, which is the anti-rollback field: if a signature did not commit to
    /// which envelope is being replaced, a captured older one could be
    /// re-installed under a valid signature.
    #[test]
    fn replace_v1_every_field_is_bound() {
        let base = replace_fixture().encode();
        let cases: Vec<(&str, ReplaceV1)> = vec![
            ("canister_id", ReplaceV1 { canister_id: owner(), ..replace_fixture() }),
            ("principal", ReplaceV1 { principal: canister(), ..replace_fixture() }),
            (
                "device_id",
                ReplaceV1 { device_id: "device-issueR".to_string(), ..replace_fixture() },
            ),
            ("old_envelope_hash", ReplaceV1 { old_envelope_hash: h(0x67), ..replace_fixture() }),
            ("new_envelope_hash", ReplaceV1 { new_envelope_hash: h(0x78), ..replace_fixture() }),
            ("nonce", ReplaceV1 { nonce: n(0x89), ..replace_fixture() }),
            (
                "expiry_ns",
                ReplaceV1 { expiry_ns: 1_700_000_000_000_000_001, ..replace_fixture() },
            ),
        ];
        for (field, mutated) in cases {
            assert_ne!(mutated.encode(), base, "mutating {field} must move the signed bytes");
        }
    }

    /// Swapping the two envelope hashes must NOT produce the same bytes —
    /// otherwise a replacement could be run backwards (rollback) under one
    /// signature. Two fixed-width fields adjacent to each other is exactly the
    /// place an encoder can accidentally make order irrelevant.
    #[test]
    fn replace_v1_old_and_new_hashes_are_not_interchangeable() {
        let forward = replace_fixture();
        let backward = ReplaceV1 {
            old_envelope_hash: forward.new_envelope_hash,
            new_envelope_hash: forward.old_envelope_hash,
            ..replace_fixture()
        };
        assert_ne!(forward.encode(), backward.encode());
    }

    /// A replacement transcript is never field-compatible with the other two:
    /// distinct action tag, distinct length, and neither prefixes the other.
    #[test]
    fn collision_replace_does_not_alias_the_other_actions() {
        let replace = replace_fixture().encode();
        let approval = approval_fixture().encode();
        let revoke = revoke_fixture().encode();
        for (name, other) in [("approval", &approval), ("revoke", &revoke)] {
            assert_ne!(&replace, other, "replace must not equal the {name} transcript");
            assert!(
                !replace.starts_with(other) && !other.starts_with(&replace),
                "neither replace nor {name} may prefix the other"
            );
        }
    }

    #[test]
    fn approval_v1_length_is_the_sum_of_its_pinned_widths() {
        let a = approval_fixture();
        let expected = (4 + TRANSCRIPT_PROTOCOL.len())
            + 2
            + (4 + a.canister_id.as_slice().len())
            + (4 + ACTION_REGISTER_DEVICE.len())
            + (4 + a.principal.as_slice().len())
            + (4 + a.issuer_device_id.len())
            + (4 + a.new_device_id.len())
            + 32
            + 32
            + 32
            + 16
            + 8;
        assert_eq!(a.encode().len(), expected);
    }

    #[test]
    fn revoke_v1_length_is_the_sum_of_its_pinned_widths() {
        let r = revoke_fixture();
        let expected = (4 + TRANSCRIPT_PROTOCOL.len())
            + 2
            + (4 + r.canister_id.as_slice().len())
            + (4 + ACTION_REVOKE_DEVICE.len())
            + (4 + r.principal.as_slice().len())
            + (4 + r.issuer_device_id.len())
            + (4 + r.target_device_id.len())
            + 16
            + 8;
        assert_eq!(r.encode().len(), expected);
    }

    // ── TAMPER NEGATIVES — every field is load-bearing ───────────────────────
    //
    // One arm per field: mutate it minimally, assert the bytes MOVE. A field
    // that could be changed without moving the signed bytes is a field the
    // signature does not actually bind.

    #[test]
    fn approval_v1_every_field_is_bound() {
        let base = approval_fixture().encode();
        let cases: Vec<(&str, ApprovalV1)> = vec![
            ("canister_id", ApprovalV1 { canister_id: owner(), ..approval_fixture() }),
            ("principal", ApprovalV1 { principal: canister(), ..approval_fixture() }),
            (
                "issuer_device_id",
                ApprovalV1 {
                    issuer_device_id: "device-issueR".to_string(),
                    ..approval_fixture()
                },
            ),
            (
                "new_device_id",
                ApprovalV1 { new_device_id: "device-neW".to_string(), ..approval_fixture() },
            ),
            ("enc_pubkey_hash", ApprovalV1 { enc_pubkey_hash: h(0x12), ..approval_fixture() }),
            ("sign_pubkey_hash", ApprovalV1 { sign_pubkey_hash: h(0x23), ..approval_fixture() }),
            (
                "wrapped_secret_hash",
                ApprovalV1 { wrapped_secret_hash: h(0x34), ..approval_fixture() },
            ),
            ("nonce", ApprovalV1 { nonce: n(0x45), ..approval_fixture() }),
            (
                "expiry_ns",
                ApprovalV1 { expiry_ns: 1_700_000_000_000_000_001, ..approval_fixture() },
            ),
        ];
        for (field, mutated) in cases {
            assert_ne!(
                mutated.encode(),
                base,
                "mutating {field} must move the signed bytes — otherwise the signature does \
                 not bind it and it can be substituted under a valid signature"
            );
        }
    }

    #[test]
    fn revoke_v1_every_field_is_bound() {
        let base = revoke_fixture().encode();
        let cases: Vec<(&str, RevokeV1)> = vec![
            ("canister_id", RevokeV1 { canister_id: owner(), ..revoke_fixture() }),
            ("principal", RevokeV1 { principal: canister(), ..revoke_fixture() }),
            (
                "issuer_device_id",
                RevokeV1 { issuer_device_id: "device-issueR".to_string(), ..revoke_fixture() },
            ),
            (
                "target_device_id",
                RevokeV1 { target_device_id: "device-targeT".to_string(), ..revoke_fixture() },
            ),
            ("nonce", RevokeV1 { nonce: n(0x56), ..revoke_fixture() }),
            ("expiry_ns", RevokeV1 { expiry_ns: 1_700_000_000_000_000_001, ..revoke_fixture() }),
        ];
        for (field, mutated) in cases {
            assert_ne!(mutated.encode(), base, "mutating {field} must move the signed bytes");
        }
    }

    // ── COLLISION / AMBIGUITY VECTORS (brief V2 §C: "two collision/ambiguity
    //    encoding vectors") ────────────────────────────────────────────────────

    /// Vector 1 — ADJACENT variable-length fields. `("ab","c")` and `("a","bc")`
    /// concatenate to the same `"abc"`. Under a prefix-free encoder they must
    /// NOT collide; this is the exact ambiguity the u32-LE prefixes exist for.
    #[test]
    fn collision_adjacent_device_ids_do_not_alias() {
        let left = ApprovalV1 {
            issuer_device_id: "ab".to_string(),
            new_device_id: "c".to_string(),
            ..approval_fixture()
        };
        let right = ApprovalV1 {
            issuer_device_id: "a".to_string(),
            new_device_id: "bc".to_string(),
            ..approval_fixture()
        };
        assert_eq!(
            left.issuer_device_id.clone() + &left.new_device_id,
            right.issuer_device_id.clone() + &right.new_device_id,
            "the two assignments must genuinely concatenate identically — otherwise this \
             vector proves nothing"
        );
        assert_ne!(
            left.encode(),
            right.encode(),
            "length-prefixing must keep adjacent variable fields unambiguous"
        );
    }

    /// Vector 2 — CROSS-ACTION. An `ApprovalV1` and a `RevokeV1` carrying the
    /// same header and the same device id in the same positional slot must not
    /// produce the same bytes: the action tag lives INSIDE the signed stream,
    /// so a transcript signed for one action can never be replayed as the other.
    #[test]
    fn collision_cross_action_transcripts_do_not_alias() {
        let shared_device = "device-x".to_string();
        let approval = ApprovalV1 {
            issuer_device_id: "device-issuer".to_string(),
            new_device_id: shared_device.clone(),
            ..approval_fixture()
        };
        let revoke = RevokeV1 {
            canister_id: canister(),
            principal: owner(),
            issuer_device_id: "device-issuer".to_string(),
            target_device_id: shared_device,
            nonce: approval.nonce,
            expiry_ns: approval.expiry_ns,
        };
        assert_ne!(approval.encode(), revoke.encode());
        // Stronger: neither is a PREFIX of the other, so no truncation or
        // trailing-bytes trick can turn one into the other either.
        let (a, r) = (approval.encode(), revoke.encode());
        assert!(!a.starts_with(&r) && !r.starts_with(&a), "neither transcript may prefix the other");
    }

    /// The version field is a real u16-LE at a fixed offset directly after the
    /// protocol field, and reads back as 1. Pins BOTH the width and the
    /// endianness — a u16-BE or a u32 would move this.
    #[test]
    fn version_is_u16_le_at_its_pinned_offset() {
        let bytes = approval_fixture().encode();
        let off = 4 + TRANSCRIPT_PROTOCOL.len();
        assert_eq!(u16::from_le_bytes([bytes[off], bytes[off + 1]]), 1);
        assert_eq!(TRANSCRIPT_VERSION, 1);
    }

    /// Digest freeze. Verification hashes the transcript; pinning the digest
    /// alongside the bytes makes an encoder change visible even in a diff that
    /// only reads the hash.
    #[test]
    fn frozen_vector_digests() {
        assert_eq!(hex(&Sha256::digest(approval_fixture().encode())), "d10602adea0309e977e6078583fdc0eeae7c0dd2e3c373f3d88d5b03b353d35b");
        assert_eq!(hex(&Sha256::digest(revoke_fixture().encode())), "0e2b55922bca208447533ba1149239889781c77dfcd70948051f59d82e107a21");
    }

    // ── LAUNCH-HARDEN-04 O-8 — SetDeviceApprovalPolicyV1 ────────────────────

    fn set_policy_fixture() -> SetDeviceApprovalPolicyV1 {
        SetDeviceApprovalPolicyV1 {
            canister_id: canister(),
            principal: owner(),
            issuer_device_id: "device-issuer".to_string(),
            require_device_approval: true,
            nonce: n(0x99),
            expiry_ns: 1_700_000_000_000_000_000,
        }
    }

    /// Literal expected bytes, computed outside the encoder (independently, from
    /// the §C encoding rule written out by hand).
    const SET_DEVICE_APPROVAL_POLICY_V1_VECTOR_HEX: &str = "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a000000010203040506070801011a0000007365745f6465766963655f617070726f76616c5f706f6c6963790a000000aabbccddeeff001102010d0000006465766963652d697373756572019999999999999999999999999999999900002a36fe9c9717";

    #[test]
    fn set_device_approval_policy_v1_frozen_vector() {
        assert_eq!(hex(&set_policy_fixture().encode()), SET_DEVICE_APPROVAL_POLICY_V1_VECTOR_HEX);
        assert_eq!(
            hex(&Sha256::digest(set_policy_fixture().encode())),
            "df2c890eb526e1c1c50e8f3d960e73e9e8d2941a752851aace59ad07da2b99b2"
        );
    }

    /// The flag byte is bound: set and clear are different signed bytes.
    #[test]
    fn set_device_approval_policy_v1_every_field_is_bound() {
        let base = set_policy_fixture().encode();
        let cases: Vec<(&str, SetDeviceApprovalPolicyV1)> = vec![
            ("canister_id", SetDeviceApprovalPolicyV1 { canister_id: owner(), ..set_policy_fixture() }),
            ("principal", SetDeviceApprovalPolicyV1 { principal: canister(), ..set_policy_fixture() }),
            (
                "issuer_device_id",
                SetDeviceApprovalPolicyV1 {
                    issuer_device_id: "device-issueR".to_string(),
                    ..set_policy_fixture()
                },
            ),
            (
                "require_device_approval",
                SetDeviceApprovalPolicyV1 { require_device_approval: false, ..set_policy_fixture() },
            ),
            ("nonce", SetDeviceApprovalPolicyV1 { nonce: n(0x9a), ..set_policy_fixture() }),
            (
                "expiry_ns",
                SetDeviceApprovalPolicyV1 {
                    expiry_ns: 1_700_000_000_000_000_001,
                    ..set_policy_fixture()
                },
            ),
        ];
        for (field, mutated) in cases {
            assert_ne!(mutated.encode(), base, "mutating {field} must move the signed bytes");
        }
    }

    /// ACTION SEPARATION: a `ReBootstrapV1` carrying the same header fields,
    /// issuer, nonce and expiry must NOT verify as this transcript — distinct
    /// bytes, and neither prefixes the other.
    #[test]
    fn set_device_approval_policy_v1_does_not_alias_re_bootstrap() {
        let p = set_policy_fixture();
        let rb = ReBootstrapV1 {
            canister_id: p.canister_id,
            principal: p.principal,
            issuer_device_id: p.issuer_device_id.clone(),
            nonce: p.nonce,
            expiry_ns: p.expiry_ns,
        };
        let (a, b) = (p.encode(), rb.encode());
        assert_ne!(a, b);
        assert!(!a.starts_with(&b) && !b.starts_with(&a), "neither may prefix the other");
        for other in [approval_fixture().encode(), revoke_fixture().encode(), replace_fixture().encode()] {
            assert_ne!(a, other);
        }
    }
}
