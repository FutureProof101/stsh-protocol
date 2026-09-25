// =============================================================================
// W-VETKEYS two-layer — STABLE LAYOUTS + MemoryId ALLOCATIONS
// =============================================================================
//
// COMMIT-1 FREEZE. This module declares the stable-memory SHAPE of the lane:
// the key/value byte layouts, their `Storable` bounds, and the MemoryId
// allocations (registered in docs/MEMORY_ID_REGISTRY.md in this same commit,
// per the append-only rule). It contains NO endpoint, NO admission logic and NO
// verification — those land in later commits against these frozen layouts.
//
// WHY EXPLICIT BYTE LAYOUTS RATHER THAN CANDID. Two reasons, both structural:
//
//  1. `StableBTreeMap` iterates in ENCODED-BYTE order, so a key's encoding IS
//     its ordering. The per-principal ranges this lane needs (all devices of
//     one owner, all nonces of one issuer) are only well-defined if the
//     principal sits at a FIXED-WIDTH prefix — which a self-describing format
//     does not guarantee. Same reasoning as the pool's `TerminalSpendKey`.
//  2. A candid layout can shift under a candid release; a stable region cannot.
//     Every record therefore carries an explicit `layout` version byte, and an
//     unknown layout version traps rather than decoding into a different type's
//     bytes — the silent-reinterpretation failure the MemoryId rule exists for.
//
// FAIL-CLOSED DECODE. `from_bytes` traps on anything it cannot decode exactly.
// A stable region that decodes to a *plausible default* is how a lost region
// becomes a plausible "unused quota" or "unused ticket" — i.e. free derives and a live
// bootstrap capability out of nowhere. Refusing is the only safe direction
// here, so these decoders have no lenient arm.

use std::borrow::Cow;
use std::cell::RefCell;

use candid::Principal;
use ic_stable_structures::memory_manager::MemoryId;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{StableBTreeMap, StableCell, Storable};

use crate::mem;
use crate::pins::MAX_DEVICE_ID_BYTES;
use crate::Memory;

/// Layout version byte carried by every variable-width record here. Bumping it
/// is a schema boundary, not a chore.
const LAYOUT_V1: u8 = 1;

/// Maximum principal length in bytes (IC principals are ≤ 29 bytes).
const PRINCIPAL_MAX_BYTES: usize = 29;

/// Encoded width of a `PrincipalKey`: one length byte + the padded principal.
const PRINCIPAL_KEY_BYTES: usize = 1 + PRINCIPAL_MAX_BYTES;

/// Encoded width of a `DeviceIdKey`: one length byte + the padded id.
const DEVICE_ID_KEY_BYTES: usize = 1 + MAX_DEVICE_ID_BYTES;

/// Bound on the number of timestamps a per-principal window record may hold.
/// Far above anything the pins can produce (`DERIVE_QUOTA` reservations can
/// each stale-charge into `committed`, so 2 × 5 is the true ceiling); the
/// headroom exists so the bound is a storage guard, not a behavioural one.
// pub(crate): the admission machine's overshoot arm asserts against this
// directly — a test that hardcoded 32 would drift from the storage bound.
pub(crate) const MAX_WINDOW_ENTRIES: usize = 32;

// ═════════════════════════════════════════════════════════════════════════════
// KEYS — fixed width, length-prefixed, order-preserving
// ═════════════════════════════════════════════════════════════════════════════

/// A principal as a FIXED-WIDTH, order-preserving map key.
///
/// Layout: `len: u8 || principal bytes || zero padding` to `PRINCIPAL_KEY_BYTES`.
/// The length byte leads so that two principals where one is a prefix of the
/// other still order and compare distinctly; the padding is what makes the
/// width fixed, which is what makes a per-principal `range` well-defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalKey([u8; PRINCIPAL_KEY_BYTES]);

impl PrincipalKey {
    pub fn new(p: Principal) -> Self {
        let bytes = p.as_slice();
        assert!(
            bytes.len() <= PRINCIPAL_MAX_BYTES,
            "a principal is at most {PRINCIPAL_MAX_BYTES} bytes"
        );
        let mut out = [0u8; PRINCIPAL_KEY_BYTES];
        out[0] = bytes.len() as u8;
        out[1..1 + bytes.len()].copy_from_slice(bytes);
        PrincipalKey(out)
    }
}

impl Storable for PrincipalKey {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: PRINCIPAL_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), PRINCIPAL_KEY_BYTES, "PrincipalKey: wrong stable width");
        let mut a = [0u8; PRINCIPAL_KEY_BYTES];
        a.copy_from_slice(&b);
        assert!(a[0] as usize <= PRINCIPAL_MAX_BYTES, "PrincipalKey: impossible length byte");
        PrincipalKey(a)
    }
}

/// A device id as a FIXED-WIDTH key component. Same layout discipline as
/// `PrincipalKey`; ids are UTF-8, bounded by `pins::MAX_DEVICE_ID_BYTES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceIdKey([u8; DEVICE_ID_KEY_BYTES]);

impl DeviceIdKey {
    /// `None` if the id is empty or exceeds the pinned bound — the caller-facing
    /// validation that keeps this a storage guard rather than a panic surface.
    pub fn new(device_id: &str) -> Option<Self> {
        let bytes = device_id.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_DEVICE_ID_BYTES {
            return None;
        }
        let mut out = [0u8; DEVICE_ID_KEY_BYTES];
        out[0] = bytes.len() as u8;
        out[1..1 + bytes.len()].copy_from_slice(bytes);
        Some(DeviceIdKey(out))
    }

    pub fn as_str(&self) -> String {
        let len = self.0[0] as usize;
        String::from_utf8(self.0[1..1 + len].to_vec()).expect("device ids are stored as UTF-8")
    }
}

impl Storable for DeviceIdKey {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: DEVICE_ID_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), DEVICE_ID_KEY_BYTES, "DeviceIdKey: wrong stable width");
        let mut a = [0u8; DEVICE_ID_KEY_BYTES];
        a.copy_from_slice(&b);
        assert!(
            a[0] as usize <= MAX_DEVICE_ID_BYTES && a[0] != 0,
            "DeviceIdKey: impossible length byte"
        );
        DeviceIdKey(a)
    }
}

/// L04-07 — the per-principal RE-BOOTSTRAP POLICY row.
///
/// WHAT IT DECIDES. Revocation RETAINS the `DeviceRecord` and only flips its
/// status, so a principal that has revoked its way to ZERO active devices is
/// indistinguishable, by a device-count alone, from one that has revoked its
/// way there deliberately and one that never enrolled at all. Only the first
/// two are the same principal; the third is a fresh user. A bootstrap ticket
/// is the capability to enrol a device with NO existing device's signature, so
/// handing one to a revoked-to-zero principal unconditionally would make
/// revocation reversible by whoever holds the II — including whoever stole it,
/// which is the reason the devices were revoked.
///
/// So: never-enrolled bootstraps freely; revoked-to-zero needs a row here with
/// `allow_re_bootstrap = true`, minted by `authorize_re_bootstrap` against a
/// signature from a device that was ACTIVE before the revocation.
///
/// ABSENT ROW = NOT AUTHORIZED. Every pre-this-lane enrolment has no row, and
/// that is the correct, fail-closed default — the same posture as every other
/// decoder in this module.
///
/// NO `CandidType`. `DeviceIdKey` derives none and does not need one: the
/// query surface returns a separate, Candid-safe DTO built field-by-field
/// (`RebootstrapPolicyView` in `lib.rs`), so the stored type never crosses
/// into Candid.
#[derive(Clone, Debug, PartialEq)]
pub struct RebootstrapPolicyV1 {
    pub allow_re_bootstrap: bool,
    /// The ACTIVE-at-signing-time device whose signature authorized this row.
    /// Retained as forensic evidence of who re-opened the bootstrap path.
    pub authorized_by_device: Option<DeviceIdKey>,
    pub authorized_at_ns: u64,
}

/// 1 (`LAYOUT_V1`) + 1 (`allow_re_bootstrap`) + 1 (the `Option`
/// DISCRIMINANT, its own term) + `DEVICE_ID_KEY_BYTES` (the device-id payload,
/// always emitted, zero-filled when `None`) + 8 (`authorized_at_ns`).
const REBOOTSTRAP_POLICY_BYTES: usize = 1 + 1 + 1 + DEVICE_ID_KEY_BYTES + 8;

impl Storable for RebootstrapPolicyV1 {
    /// `is_fixed_size: false`: the width is constant in practice, but the
    /// record is a versioned layout with an optional limb, and claiming fixed
    /// size for it would freeze that shape at the storage bound rather than at
    /// the layout byte where the freeze belongs.
    const BOUND: Bound = Bound::Bounded {
        max_size: REBOOTSTRAP_POLICY_BYTES as u32,
        is_fixed_size: false,
    };
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(REBOOTSTRAP_POLICY_BYTES);
        out.push(LAYOUT_V1);
        out.push(self.allow_re_bootstrap as u8);
        match &self.authorized_by_device {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; DEVICE_ID_KEY_BYTES]);
            }
            Some(dev) => {
                out.push(1);
                out.extend_from_slice(&dev.to_bytes());
            }
        }
        out.extend_from_slice(&self.authorized_at_ns.to_le_bytes());
        debug_assert_eq!(out.len(), REBOOTSTRAP_POLICY_BYTES);
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(
            b.len(),
            REBOOTSTRAP_POLICY_BYTES,
            "RebootstrapPolicyV1: wrong stable width"
        );
        assert_eq!(
            b[0], LAYOUT_V1,
            "RebootstrapPolicyV1: unknown layout version — TRAP, no repair path"
        );
        let allow_re_bootstrap = b[1] != 0;
        let authorized_by_device = if b[2] == 0 {
            None
        } else {
            Some(DeviceIdKey::from_bytes(Cow::Borrowed(
                &b[3..3 + DEVICE_ID_KEY_BYTES],
            )))
        };
        let tail = 3 + DEVICE_ID_KEY_BYTES;
        let authorized_at_ns = u64::from_le_bytes(b[tail..tail + 8].try_into().unwrap());
        RebootstrapPolicyV1 {
            allow_re_bootstrap,
            authorized_by_device,
            authorized_at_ns,
        }
    }
}

/// LAUNCH-HARDEN-04 O-8 (RW-02) — the per-principal "require device approval"
/// flag row, MemoryId 19.
///
/// WHAT IT DECIDES. While `require_device_approval` is set (and no II-only
/// clear has matured), a principal with ≥1 ACTIVE device cannot enrol a new
/// device via the BOOTSTRAP path: only an existing device's signed
/// `DeviceApproval::Device` can. It blocks new-device enrolment without an
/// existing device's approval, and nothing else — a live, hijacked II session
/// can still derive the vetKey.
///
/// ABSENT ROW = FLAG OFF — today's behaviour for every pre-lane principal. A
/// device-signed clear DELETES the row; the II-only clear sets
/// `pending_clear_at_ns` and the flag lapses at that instant (inclusive).
///
/// NO `CandidType` (the `RebootstrapPolicyV1` precedent): the query returns a
/// separate Candid-safe view, and `set_by_device` is never exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceApprovalPolicyV1 {
    pub require_device_approval: bool,
    /// The ACTIVE device whose signature set the flag. Forensic evidence.
    pub set_by_device: DeviceIdKey,
    pub set_at_ns: u64,
    /// `Some(t)` once an II-only clear was requested: the flag lapses at `t`.
    pub pending_clear_at_ns: Option<u64>,
}

/// 1 (`LAYOUT_V1`) + 1 (`require`) + `DEVICE_ID_KEY_BYTES` (`set_by_device`) +
/// 8 (`set_at_ns`) + 1 (pending discriminant) + 8 (`pending_clear_at_ns`,
/// zero-filled when `None`).
const DEVICE_APPROVAL_POLICY_BYTES: usize = 1 + 1 + DEVICE_ID_KEY_BYTES + 8 + 1 + 8;

impl Storable for DeviceApprovalPolicyV1 {
    /// `is_fixed_size: false`, the `RebootstrapPolicyV1` reasoning: the width is
    /// constant in practice, but the freeze belongs at the layout byte.
    const BOUND: Bound = Bound::Bounded {
        max_size: DEVICE_APPROVAL_POLICY_BYTES as u32,
        is_fixed_size: false,
    };
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(DEVICE_APPROVAL_POLICY_BYTES);
        out.push(LAYOUT_V1);
        out.push(self.require_device_approval as u8);
        out.extend_from_slice(&self.set_by_device.to_bytes());
        out.extend_from_slice(&self.set_at_ns.to_le_bytes());
        match self.pending_clear_at_ns {
            None => {
                out.push(0);
                out.extend_from_slice(&0u64.to_le_bytes());
            }
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.to_le_bytes());
            }
        }
        debug_assert_eq!(out.len(), DEVICE_APPROVAL_POLICY_BYTES);
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(
            b.len(),
            DEVICE_APPROVAL_POLICY_BYTES,
            "DeviceApprovalPolicyV1: wrong stable width"
        );
        assert_eq!(
            b[0], LAYOUT_V1,
            "DeviceApprovalPolicyV1: unknown layout version — TRAP, no repair path"
        );
        let require_device_approval = match b[1] {
            0 => false,
            1 => true,
            _ => panic!("DeviceApprovalPolicyV1: impossible require byte"),
        };
        let set_by_device = DeviceIdKey::from_bytes(Cow::Borrowed(&b[2..2 + DEVICE_ID_KEY_BYTES]));
        let mut c = 2 + DEVICE_ID_KEY_BYTES;
        let set_at_ns = u64::from_le_bytes(b[c..c + 8].try_into().unwrap());
        c += 8;
        let disc = b[c];
        c += 1;
        let t = u64::from_le_bytes(b[c..c + 8].try_into().unwrap());
        let pending_clear_at_ns = match disc {
            0 => None,
            1 => Some(t),
            _ => panic!("DeviceApprovalPolicyV1: impossible pending discriminant"),
        };
        DeviceApprovalPolicyV1 { require_device_approval, set_by_device, set_at_ns, pending_clear_at_ns }
    }
}

/// `(owner, device_id)` — the device registry key. Owner FIRST so one
/// principal's devices form a contiguous range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceKey {
    pub owner: PrincipalKey,
    pub device_id: DeviceIdKey,
}

const DEVICE_KEY_BYTES: usize = PRINCIPAL_KEY_BYTES + DEVICE_ID_KEY_BYTES;

impl DeviceKey {
    /// The inclusive encoded-byte bounds of ONE owner's block, for a
    /// per-principal `range`. Correct only because the owner sits at a
    /// fixed-width prefix (see this module's header): the low bound pins the
    /// smallest possible device-id component and the high bound the largest, so
    /// the range is exactly that owner's devices and nothing else.
    pub fn owner_range(owner: PrincipalKey) -> (DeviceKey, DeviceKey) {
        (
            DeviceKey { owner, device_id: DeviceIdKey([0x00; DEVICE_ID_KEY_BYTES]) },
            DeviceKey { owner, device_id: DeviceIdKey([0xFF; DEVICE_ID_KEY_BYTES]) },
        )
    }
}

impl Storable for DeviceKey {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: DEVICE_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(DEVICE_KEY_BYTES);
        out.extend_from_slice(&self.owner.0);
        out.extend_from_slice(&self.device_id.0);
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), DEVICE_KEY_BYTES, "DeviceKey: wrong stable width");
        DeviceKey {
            owner: PrincipalKey::from_bytes(Cow::Borrowed(&b[..PRINCIPAL_KEY_BYTES])),
            device_id: DeviceIdKey::from_bytes(Cow::Borrowed(&b[PRINCIPAL_KEY_BYTES..])),
        }
    }
}

/// `(owner, issuer_device_id, nonce)` — the consumed-nonce set key.
///
/// The nonce scope is `(principal, issuer_device_id)` exactly as brief V2 §C
/// pins it, so the key carries both: a nonce burned by one issuing device does
/// not burn it for another, and no device can burn another owner's nonces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonceKey {
    pub owner: PrincipalKey,
    pub issuer_device_id: DeviceIdKey,
    pub nonce: [u8; 16],
}

const NONCE_KEY_BYTES: usize = PRINCIPAL_KEY_BYTES + DEVICE_ID_KEY_BYTES + 16;

impl Storable for NonceKey {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: NONCE_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(NONCE_KEY_BYTES);
        out.extend_from_slice(&self.owner.0);
        out.extend_from_slice(&self.issuer_device_id.0);
        out.extend_from_slice(&self.nonce);
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), NONCE_KEY_BYTES, "NonceKey: wrong stable width");
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&b[PRINCIPAL_KEY_BYTES + DEVICE_ID_KEY_BYTES..]);
        NonceKey {
            owner: PrincipalKey::from_bytes(Cow::Borrowed(&b[..PRINCIPAL_KEY_BYTES])),
            issuer_device_id: DeviceIdKey::from_bytes(Cow::Borrowed(
                &b[PRINCIPAL_KEY_BYTES..PRINCIPAL_KEY_BYTES + DEVICE_ID_KEY_BYTES],
            )),
            nonce,
        }
    }
}

/// `(expiry_ns, nonce_key)` — the expiry-ordered index over `CONSUMED_NONCES`
/// (Opus-round RED-1).
///
/// The primary map orders by `NonceKey`, so expired rows are NOT a bounded
/// prefix there — a prune over it would be a full-map scan on a
/// caller-writable path. THIS key puts `expiry_ns` first, BIG-ENDIAN (a
/// `StableBTreeMap` iterates in encoded-byte order, and only the BE encoding
/// of a u64 sorts numerically), so the expired candidates are exactly the low
/// prefix. The second component is the existing canonical, injective
/// `NonceKey` bytes, so two consumes sharing an expiry cannot collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonceExpiryKey {
    pub expiry_ns: u64,
    pub nonce_key: NonceKey,
}

const NONCE_EXPIRY_KEY_BYTES: usize = 8 + NONCE_KEY_BYTES;

impl Storable for NonceExpiryKey {
    /// `to_bytes` is the single source of the layout; `into_bytes` delegates.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: NONCE_EXPIRY_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(NONCE_EXPIRY_KEY_BYTES);
        out.extend_from_slice(&self.expiry_ns.to_be_bytes());
        out.extend_from_slice(&self.nonce_key.to_bytes());
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), NONCE_EXPIRY_KEY_BYTES, "NonceExpiryKey: wrong stable width");
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&b[..8]);
        NonceExpiryKey {
            expiry_ns: u64::from_be_bytes(expiry),
            nonce_key: NonceKey::from_bytes(Cow::Borrowed(&b[8..])),
        }
    }
}

/// `(expiry_ns, who)` — the expiry-ordered index over `ELIGIBILITY_SIGHTINGS`
/// (A1 fix brief V5 §6.5, RED-1).
///
/// THE REASON THIS TYPE EXISTS, STATED PLAINLY. The primary sighting map is
/// keyed by `PrincipalKey`, so expired rows sit NOWHERE IN PARTICULAR in it —
/// finding K expired rows there is `O(N)` over the whole table, on a
/// caller-reachable admission path. A principal-keyed map cannot produce an
/// expiry prefix, so it cannot deliver the bound; only an ordering structure
/// can. This mirrors `NonceExpiryKey` (MemoryId 13) exactly, for exactly the
/// same reason, because the precedent is what proves the structure is the load-
/// bearing part rather than the constant.
///
/// BIG-ENDIAN IS LOAD-BEARING. `StableBTreeMap` iterates in ENCODED-BYTE order,
/// and only the big-endian encoding of a `u64` sorts numerically. With
/// `expiry_ns` first and big-endian, the expired rows are exactly the LOW
/// PREFIX, so a prune walks at most `pins::SIGHTING_PRUNE_MAX` of them at
/// `O(K log N)`. Under little-endian the same walk would visit rows in an order
/// unrelated to expiry, and the bound would be a claim rather than a property.
///
/// The second component is the canonical, injective `PrincipalKey` bytes, so
/// two principals sharing an expiry cannot collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SightingExpiryKey {
    pub expiry_ns: u64,
    pub who: PrincipalKey,
}

const SIGHTING_EXPIRY_KEY_BYTES: usize = 8 + PRINCIPAL_KEY_BYTES;

impl Storable for SightingExpiryKey {
    /// `to_bytes` is the single source of the layout; `into_bytes` delegates so
    /// the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: SIGHTING_EXPIRY_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(SIGHTING_EXPIRY_KEY_BYTES);
        out.extend_from_slice(&self.expiry_ns.to_be_bytes());
        out.extend_from_slice(&self.who.to_bytes());
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(
            b.len(),
            SIGHTING_EXPIRY_KEY_BYTES,
            "SightingExpiryKey: wrong stable width"
        );
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&b[..8]);
        SightingExpiryKey {
            expiry_ns: u64::from_be_bytes(expiry),
            who: PrincipalKey::from_bytes(Cow::Borrowed(&b[8..])),
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// VALUES
// ═════════════════════════════════════════════════════════════════════════════

/// Device lifecycle status (brief V1 §2).
///
/// A `Revoked` device's RECORD is retained — revocation deletes the wrapped
/// blob (a separate map), not the evidence that the device existed. Retention
/// is what makes "this device was revoked at T" answerable after the fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

/// How a device came to be registered (brief V1 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovedBy {
    /// Consumed a §B bootstrap ticket — i.e. rode a full Layer-2 ceremony.
    Bootstrap,
    /// Approved by an existing Active device's `ApprovalV1` signature.
    Device(DeviceIdKey),
}

/// A registered device. The PUBLIC halves only — the private keys are
/// non-extractable and never leave the browser (brief V1 §1/§6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// SPKI of the RSA-OAEP-3072 device ENCRYPTION public key.
    pub enc_pubkey_spki: Vec<u8>,
    /// SPKI of the P-256 device SIGNING public key.
    pub sign_pubkey_spki: Vec<u8>,
    pub status: DeviceStatus,
    pub added_at_ns: u64,
    pub revoked_at_ns: Option<u64>,
    pub approved_by: ApprovedBy,
}

/// Storage bound for a device record. An RSA-3072 SPKI is ~422 B and a P-256
/// SPKI is 91 B; 1 KiB leaves room for both plus the fixed tail, and matches
/// the "≤ device cap × ~1 KB per principal" figure in brief V1 §8.
const DEVICE_RECORD_MAX_BYTES: u32 = 1024;

fn push_var(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_le_bytes());
    out.extend_from_slice(field);
}

fn take_var<'a>(b: &'a [u8], cursor: &mut usize) -> &'a [u8] {
    let start = *cursor;
    assert!(start + 4 <= b.len(), "stable decode: truncated length prefix");
    let len = u32::from_le_bytes(b[start..start + 4].try_into().unwrap()) as usize;
    let from = start + 4;
    assert!(from + len <= b.len(), "stable decode: length prefix overruns the record");
    *cursor = from + len;
    &b[from..from + len]
}

fn take_u64(b: &[u8], cursor: &mut usize) -> u64 {
    let start = *cursor;
    assert!(start + 8 <= b.len(), "stable decode: truncated u64");
    *cursor = start + 8;
    u64::from_le_bytes(b[start..start + 8].try_into().unwrap())
}

fn take_u8(b: &[u8], cursor: &mut usize) -> u8 {
    assert!(*cursor < b.len(), "stable decode: truncated byte");
    let v = b[*cursor];
    *cursor += 1;
    v
}

impl Storable for DeviceRecord {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: DEVICE_RECORD_MAX_BYTES,
        is_fixed_size: false,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(640);
        out.push(LAYOUT_V1);
        push_var(&mut out, &self.enc_pubkey_spki);
        push_var(&mut out, &self.sign_pubkey_spki);
        out.push(match self.status {
            DeviceStatus::Active => 0,
            DeviceStatus::Revoked => 1,
        });
        out.extend_from_slice(&self.added_at_ns.to_le_bytes());
        match self.revoked_at_ns {
            None => out.push(0),
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.to_le_bytes());
            }
        }
        match &self.approved_by {
            ApprovedBy::Bootstrap => out.push(0),
            ApprovedBy::Device(id) => {
                out.push(1);
                out.extend_from_slice(&id.0);
            }
        }
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut c = 0usize;
        assert_eq!(take_u8(&b, &mut c), LAYOUT_V1, "DeviceRecord: unknown layout version");
        let enc_pubkey_spki = take_var(&b, &mut c).to_vec();
        let sign_pubkey_spki = take_var(&b, &mut c).to_vec();
        let status = match take_u8(&b, &mut c) {
            0 => DeviceStatus::Active,
            1 => DeviceStatus::Revoked,
            other => panic!("DeviceRecord: unknown status discriminant {other}"),
        };
        let added_at_ns = take_u64(&b, &mut c);
        let revoked_at_ns = match take_u8(&b, &mut c) {
            0 => None,
            1 => Some(take_u64(&b, &mut c)),
            other => panic!("DeviceRecord: unknown option tag {other}"),
        };
        let approved_by = match take_u8(&b, &mut c) {
            0 => ApprovedBy::Bootstrap,
            1 => {
                let start = c;
                assert!(start + DEVICE_ID_KEY_BYTES <= b.len(), "DeviceRecord: truncated issuer");
                c += DEVICE_ID_KEY_BYTES;
                ApprovedBy::Device(DeviceIdKey::from_bytes(Cow::Borrowed(
                    &b[start..start + DEVICE_ID_KEY_BYTES],
                )))
            }
            other => panic!("DeviceRecord: unknown approved_by discriminant {other}"),
        };
        assert_eq!(c, b.len(), "DeviceRecord: trailing bytes");
        DeviceRecord {
            enc_pubkey_spki,
            sign_pubkey_spki,
            status,
            added_at_ns,
            revoked_at_ns,
            approved_by,
        }
    }
}

/// The RSA-OAEP-3072 wrapping of the 32-byte master note secret to one device's
/// encryption public key. Stored OPAQUE: the canister never sees the plaintext
/// (split knowledge, brief V1 §2). Held in its OWN map, keyed identically to
/// the device registry, so revocation can delete the blob while retaining the
/// device record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedSecret(pub Vec<u8>);

/// The stored value is the wallet's whole device ENVELOPE (header + body), not
/// the bare 384-byte RSA-OAEP-3072 ciphertext: 627 B worst case for this
/// protocol version (passcode mode, 64-byte device id, 29-byte owner — see
/// `tests/crossdevice_acceptance.rs` `ENVELOPE_CEILING_BYTES` and
/// `wallet/src/crypto/envelope.ts`). 1024 = 2× the prior 512 cap, headroom for
/// the passcode mode plus one future header field, without admitting a
/// storage-exhaustion payload. Raised IN PLACE on MemoryId 4 (VETKEYS-AGE-2MIN,
/// ruling RULING_VETKEYS_ENVELOPE_CAP_MECHANISM 2026-09-23, Option A): the V2
/// map layout keeps its page size on reload and stores larger values through
/// overflow pages, so no new MemoryId and no migration are needed.
const WRAPPED_SECRET_MAX_BYTES: u32 = 1024;

impl Storable for WrappedSecret {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: WRAPPED_SECRET_MAX_BYTES,
        is_fixed_size: false,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        WrappedSecret(b.into_owned())
    }
}

/// A bounded cache of the canister-scoped vetKD verification key (BLS12-381 G2
/// public key bytes), MemoryId 18. Absent (`VerificationKeyCacheV1(Vec::new())`)
/// reads as "no cache" — the caller re-fetches.
///
/// THIS IS A CACHE, NOT A SOURCE OF TRUTH. A corrupted or oversized row is
/// treated as absent on the READ path rather than trapping — deliberately the
/// opposite direction from the `TokenCanisterRef` / `GlobalDeriveWindow`
/// fail-closed-trap idiom the other two cells in this module use. Those two
/// guard security/accounting invariants where a silently-wrong default is a
/// regression; this one guards a value with a perfectly good fallback
/// (re-fetch from the management canister), so failing OPEN to "no cache" on a
/// decode anomaly is the correct direction on READ.
///
/// STATED SO THE WHOLE TYPE IS NOT READ AS FAIL-OPEN: `StableCell::set` in
/// `ic-stable-structures 0.7.2` does NOT bounds-check its own writes. `set`
/// delegates to `flush_value`, whose only length guard is `len > u32::MAX`;
/// `check_bounds` / `to_bytes_checked` / `into_bytes_checked` exist on the
/// `Storable` trait but this crate's `Cell` never calls them. (The containers
/// that DO call them are `StableBTreeMap`, from `btreemap.rs` and
/// `btreemap/node/v2.rs`, and `StableVec`, from `base_vec.rs`.) `BOUND` here
/// therefore documents intent and the contract a bounded container WOULD
/// enforce; it is not an enforced write-path invariant for this cell type.
/// The actual write-side guarantee is application-level:
/// `set_verification_key_cache` below asserts the length itself and traps by
/// name before calling `set`. A BLS12-381 G2 point is 96 bytes, so the assert
/// is not expected to fire given this cell's only two writers, but it is what
/// actually stands between an oversized value and an unchecked write.
#[derive(Clone, Default)]
pub struct VerificationKeyCacheV1(pub Vec<u8>);

/// A BLS12-381 G2 point is 96 bytes; the bound leaves headroom for a
/// length-prefixed encoding without admitting a storage-exhaustion payload.
const VERIFICATION_KEY_CACHE_MAX_BYTES: u32 = 100;

impl Storable for VerificationKeyCacheV1 {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required by
    /// ic-stable-structures 0.7, no default body) delegates so the two can
    /// never diverge — the same idiom `WrappedSecret` above uses.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: VERIFICATION_KEY_CACHE_MAX_BYTES,
        is_fixed_size: false,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        if bytes.len() > VERIFICATION_KEY_CACHE_MAX_BYTES as usize {
            // Fail OPEN on READ, not closed: an oversized/corrupt row has a
            // correct, cheap fallback (re-fetch), unlike this module's other
            // stable cells, which guard invariants with no such fallback.
            return VerificationKeyCacheV1(Vec::new());
        }
        VerificationKeyCacheV1(bytes.into_owned())
    }
}

/// A canister-minted, single-use bootstrap capability (brief V2 §B). One live
/// ticket per principal; a re-derive overwrites it.
///
/// `used` is RETAINED rather than deleted on consumption: the row is the replay
/// evidence, and a deleted row would read as "never minted", which is exactly
/// the state a replay wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapTicket {
    pub minted_at_ns: u64,
    pub expires_at_ns: u64,
    pub used: bool,
}

const BOOTSTRAP_TICKET_BYTES: usize = 1 + 8 + 8 + 1;

impl Storable for BootstrapTicket {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: BOOTSTRAP_TICKET_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(BOOTSTRAP_TICKET_BYTES);
        out.push(LAYOUT_V1);
        out.extend_from_slice(&self.minted_at_ns.to_le_bytes());
        out.extend_from_slice(&self.expires_at_ns.to_le_bytes());
        out.push(u8::from(self.used));
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), BOOTSTRAP_TICKET_BYTES, "BootstrapTicket: wrong stable width");
        let mut c = 0usize;
        assert_eq!(take_u8(&b, &mut c), LAYOUT_V1, "BootstrapTicket: unknown layout version");
        let minted_at_ns = take_u64(&b, &mut c);
        let expires_at_ns = take_u64(&b, &mut c);
        let used = match take_u8(&b, &mut c) {
            0 => false,
            1 => true,
            other => panic!("BootstrapTicket: non-boolean used flag {other}"),
        };
        BootstrapTicket { minted_at_ns, expires_at_ns, used }
    }
}

/// V4 §H′.1 — the load-bearing phase tag on a reservation.
///
/// `PreDispatch` may be TTL-pruned; `Dispatched` may NEVER be pruned to free
/// capacity, because no platform deadline makes a management callback
/// impossible. That asymmetry is the whole of RED-6, so it is a TYPE here, not
/// a boolean or an inferred age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationPhase {
    PreDispatch,
    Dispatched,
}

/// One in-flight derive (V4 §H′.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// Per-principal monotonic id. Finalization is BY ID: an id absent from the
    /// list is a no-op, which is what makes a late callback side-effect-free.
    pub id: u64,
    pub created_at_ns: u64,
    pub phase: ReservationPhase,
}

/// Per-principal admission state (V4 §H′.1).
///
/// `committed` may transiently exceed `DERIVE_QUOTA` via the §H′.3(c) stale
/// charge; capacity math uses the true sum, so over-counting only ever TIGHTENS
/// admission. That is the safe direction, and it is a stated decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdmissionState {
    /// Finalized/charged derive timestamps, pruned to the 24 h window.
    pub committed: Vec<u64>,
    pub reservations: Vec<Reservation>,
    /// Source of `Reservation::id`. Monotonic and NEVER reset — a reused id
    /// would let a late callback finalize a different call's reservation.
    pub next_reservation_id: u64,
}

const ADMISSION_STATE_MAX_BYTES: u32 = 2048;

impl Storable for AdmissionState {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: ADMISSION_STATE_MAX_BYTES,
        is_fixed_size: false,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        assert!(
            self.committed.len() <= MAX_WINDOW_ENTRIES
                && self.reservations.len() <= MAX_WINDOW_ENTRIES,
            "AdmissionState: window lists exceed the storage bound — the pins cannot produce \
             this, so it is a logic error, not a caller-reachable state"
        );
        let mut out = Vec::with_capacity(256);
        out.push(LAYOUT_V1);
        out.extend_from_slice(&self.next_reservation_id.to_le_bytes());
        out.push(self.committed.len() as u8);
        for t in &self.committed {
            out.extend_from_slice(&t.to_le_bytes());
        }
        out.push(self.reservations.len() as u8);
        for r in &self.reservations {
            out.extend_from_slice(&r.id.to_le_bytes());
            out.extend_from_slice(&r.created_at_ns.to_le_bytes());
            out.push(match r.phase {
                ReservationPhase::PreDispatch => 0,
                ReservationPhase::Dispatched => 1,
            });
        }
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut c = 0usize;
        assert_eq!(take_u8(&b, &mut c), LAYOUT_V1, "AdmissionState: unknown layout version");
        let next_reservation_id = take_u64(&b, &mut c);
        let n = take_u8(&b, &mut c) as usize;
        assert!(n <= MAX_WINDOW_ENTRIES, "AdmissionState: committed count out of bound");
        let committed = (0..n).map(|_| take_u64(&b, &mut c)).collect();
        let m = take_u8(&b, &mut c) as usize;
        assert!(m <= MAX_WINDOW_ENTRIES, "AdmissionState: reservation count out of bound");
        let reservations = (0..m)
            .map(|_| {
                let id = take_u64(&b, &mut c);
                let created_at_ns = take_u64(&b, &mut c);
                let phase = match take_u8(&b, &mut c) {
                    0 => ReservationPhase::PreDispatch,
                    1 => ReservationPhase::Dispatched,
                    other => panic!("AdmissionState: unknown reservation phase {other}"),
                };
                Reservation { id, created_at_ns, phase }
            })
            .collect();
        assert_eq!(c, b.len(), "AdmissionState: trailing bytes");
        AdmissionState { committed, reservations, next_reservation_id }
    }
}

/// Per-principal `register_device` call timestamps for the §E rate limit
/// (5 per rolling 24 h, successful or not).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistrationWindow {
    pub attempts: Vec<u64>,
}

const REGISTRATION_WINDOW_MAX_BYTES: u32 = 2 + (MAX_WINDOW_ENTRIES as u32) * 8;

impl Storable for RegistrationWindow {
    /// `to_bytes` is the single source of the layout; `into_bytes` (required
    /// by ic-stable-structures 0.7) delegates so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: REGISTRATION_WINDOW_MAX_BYTES,
        is_fixed_size: false,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        assert!(
            self.attempts.len() <= MAX_WINDOW_ENTRIES,
            "RegistrationWindow: attempt list exceeds the storage bound"
        );
        let mut out = Vec::with_capacity(2 + self.attempts.len() * 8);
        out.push(LAYOUT_V1);
        out.push(self.attempts.len() as u8);
        for t in &self.attempts {
            out.extend_from_slice(&t.to_le_bytes());
        }
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut c = 0usize;
        assert_eq!(take_u8(&b, &mut c), LAYOUT_V1, "RegistrationWindow: unknown layout version");
        let n = take_u8(&b, &mut c) as usize;
        assert!(n <= MAX_WINDOW_ENTRIES, "RegistrationWindow: attempt count out of bound");
        let attempts = (0..n).map(|_| take_u64(&b, &mut c)).collect();
        assert_eq!(c, b.len(), "RegistrationWindow: trailing bytes");
        RegistrationWindow { attempts }
    }
}

/// ONE recorded dispatch. **V2 (A1 fix brief V5 §3) — TAGGED.**
///
/// V1 stored a bare `u64`. The observability surface needs to answer "how many
/// DISTINCT principals" and "how many were FIRST derives", and neither question
/// can be answered from a list of timestamps: attribution has to be written at
/// the moment of the dispatch or it does not exist.
///
/// `who: None` is a V1 CARRY, and its absence is a VALUE, not a defect: an
/// untagged entry is counted in `consumed` (it genuinely consumed fleet
/// capacity) and is NEVER attributed to any principal. Inventing an attribution
/// for it would make `distinct_principals` a number the canister cannot
/// support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchRecord {
    /// When the dispatch was charged, ns.
    pub at_ns: u64,
    /// The principal charged, or `None` for an untagged V1 carry.
    pub who: Option<PrincipalKey>,
    /// Whether this dispatch was that principal's FIRST-ever derive.
    /// Meaningless — and always `false` — when `who` is `None`.
    pub first_derive: bool,
}

impl DispatchRecord {
    /// A V1 carry: capacity consumed, attribution unknown and never invented.
    pub fn untagged(at_ns: u64) -> Self {
        DispatchRecord { at_ns, who: None, first_derive: false }
    }
}

/// C-26 remedy R2 (brief V3 §4.1/§7.1) — the fleet-wide rolling derive window:
/// a bounded, ordered list of the timestamps at which derives were actually
/// DISPATCHED (the fence's commit phase is the only writer; §2.4 charges
/// nothing earlier). True rolling, not a reset bucket: an entry expires iff
/// `now.saturating_sub(ts) >= GLOBAL_DERIVE_WINDOW_NS` (§4.2), pruned at each
/// fence decision, and the budget admits iff the retained count is
/// `< GLOBAL_DERIVE_BUDGET`.
///
/// STORAGE IS SIZED BY `GLOBAL_DERIVE_WINDOW_MAX_ENTRIES`, NOT BY THE BUDGET.
/// A live cell may legitimately hold more entries than the CURRENT budget
/// admits — it was written under a wider one — so the layout is pinned to the
/// widest shipped value (100 entries; the V2 record width sets the byte figure) and the budget is free to
/// move by ratification. See `pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES` for what
/// went wrong when these were the same number.
///
/// STABLE, NOT HEAP (registry row 14, same reason as rows 7/9/11/12): an
/// upgrade-cleared window is a free fleet-wide allowance, and the party who
/// can trigger an upgrade is not the party the budget defends against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GlobalDeriveWindow {
    /// Dispatch records, in insertion order (monotonic in practice; the prune
    /// predicate does not require ordering to be correct).
    pub dispatched: Vec<DispatchRecord>,
}

/// Encoded width of one V2 `DispatchRecord`: `at_ns` (8, LE) + a presence byte
/// + the padded `PrincipalKey` + the `first_derive` byte.
///
/// FIXED WIDTH, INCLUDING FOR AN ABSENT PRINCIPAL — the key bytes are written
/// zeroed rather than omitted. A variable-width record would make the count
/// byte insufficient to bound the value, which is the property the storage
/// bound rests on.
const DISPATCH_RECORD_V2_BYTES: usize = 8 + 1 + PRINCIPAL_KEY_BYTES + 1;

/// V2 layout version for the MemoryId-14 cell. A SEPARATE constant from
/// `LAYOUT_V1`: this cell dual-reads, and every other record in this file is
/// still V1-only.
const GLOBAL_WINDOW_LAYOUT_V2: u8 = 2;

/// Bound: layout byte + count byte + `GLOBAL_DERIVE_WINDOW_MAX_ENTRIES` × the
/// V2 record width.
///
/// Derived from the STORAGE constant, never from the budget. `Bound::Bounded`
/// is a promise about every value that may ever be READ from this region, and a
/// cell written under a wider budget is exactly such a value; sizing the bound
/// by the current budget is what made lowering it a `post_upgrade` trap.
///
/// IT ONLY EVER GROWS, and V2 grows it: a V1 cell is `2 + N × 8` bytes, which
/// is strictly inside this bound, so every legacy cell stays readable. Shrinking
/// it back — or sizing it by the V1 width — would re-create the same trap in the
/// other direction, on the upgrade that introduces tagging.
const GLOBAL_DERIVE_WINDOW_MAX_BYTES: u32 =
    2 + (crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES as u32 * DISPATCH_RECORD_V2_BYTES as u32);

impl Storable for GlobalDeriveWindow {
    /// `to_bytes` is the single source of the layout; `into_bytes` delegates
    /// so the two can never diverge.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: GLOBAL_DERIVE_WINDOW_MAX_BYTES,
        is_fixed_size: false,
    };
    /// **WRITE V2 ONLY** (brief V5 §3). The dual read below exists to carry a
    /// predecessor's cell across one upgrade; writing V1 again would make the
    /// carry permanent and the attribution optional forever.
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        assert!(
            self.dispatched.len() <= crate::pins::GLOBAL_DERIVE_BUDGET as usize,
            "GlobalDeriveWindow: more retained dispatches than the budget admits — the fence \
             cannot produce this, so it is a logic error, not a caller-reachable state"
        );
        let mut out = Vec::with_capacity(2 + self.dispatched.len() * DISPATCH_RECORD_V2_BYTES);
        out.push(GLOBAL_WINDOW_LAYOUT_V2);
        out.push(self.dispatched.len() as u8);
        for r in &self.dispatched {
            out.extend_from_slice(&r.at_ns.to_le_bytes());
            match r.who {
                Some(who) => {
                    out.push(1);
                    out.extend_from_slice(&who.to_bytes());
                }
                // Absence is written as a PRESENT, ZEROED key rather than an
                // omitted field: fixed width is what lets the count byte bound
                // the value.
                None => {
                    out.push(0);
                    out.extend_from_slice(&[0u8; PRINCIPAL_KEY_BYTES]);
                }
            }
            out.push(u8::from(r.first_derive));
        }
        Cow::Owned(out)
    }
    /// **DUAL READ, V1 AND V2, AND NOTHING ELSE.** An unknown layout byte
    /// TRAPS: a cell this code never wrote is not something to guess at, and
    /// "accept V2 only" would trap `post_upgrade` on every live predecessor
    /// cell — the exact failure mode the storage/admission split exists to
    /// close, re-created one version later.
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut c = 0usize;
        let layout = take_u8(&b, &mut c);
        let n = take_u8(&b, &mut c) as usize;
        // Accept anything the STORAGE bound allows. A cell written under a
        // wider budget is legitimate history, not corruption — trapping on it
        // would abort `post_upgrade` on precisely the upgrade that lowers the
        // budget, with no way back. Beyond the storage bound is still a trap:
        // that cannot be a cell this code ever wrote.
        assert!(
            n <= crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES,
            "GlobalDeriveWindow: dispatch count out of bound"
        );
        let mut dispatched: Vec<DispatchRecord> = match layout {
            // V1 — bare little-endian timestamps. Counted in `consumed`,
            // NEVER attributed: the predecessor did not record who, and the
            // successor may not invent it.
            LAYOUT_V1 => (0..n).map(|_| DispatchRecord::untagged(take_u64(&b, &mut c))).collect(),
            GLOBAL_WINDOW_LAYOUT_V2 => (0..n)
                .map(|_| {
                    let at_ns = take_u64(&b, &mut c);
                    let present = take_u8(&b, &mut c);
                    let key_bytes = &b[c..c + PRINCIPAL_KEY_BYTES];
                    let who = match present {
                        0 => None,
                        1 => Some(PrincipalKey::from_bytes(Cow::Borrowed(key_bytes))),
                        // `panic!`, not `ic_cdk::trap`: the same abort inside
                        // a canister under `panic = "abort"`, and the same
                        // decode-failure convention every other Storable in
                        // this file uses — which is what makes it drivable in
                        // a native arm instead of only in PocketIC.
                        _ => panic!("GlobalDeriveWindow: unknown principal-presence discriminant"),
                    };
                    c += PRINCIPAL_KEY_BYTES;
                    let first_derive = match take_u8(&b, &mut c) {
                        0 => false,
                        1 => true,
                        _ => panic!("GlobalDeriveWindow: unknown first_derive discriminant"),
                    };
                    DispatchRecord { at_ns, who, first_derive }
                })
                .collect(),
            other => panic!(
                "GlobalDeriveWindow: unknown layout version {other} — refusing to guess at a \
                 cell this code never wrote"
            ),
        };
        assert_eq!(c, b.len(), "GlobalDeriveWindow: trailing bytes");

        // MIGRATION, FAIL-CLOSED. If the stored cell holds more than the
        // current budget admits, retain the NEWEST `GLOBAL_DERIVE_BUDGET`.
        //
        // NEWEST, DELIBERATELY, AND THE DIRECTION IS THE WHOLE POINT: a
        // retained entry holds capacity until it expires, so keeping the newest
        // keeps capacity consumed for LONGER. Keeping the oldest would expire
        // them sooner and hand the fleet a free burst on the very upgrade that
        // tightens the ceiling — a lower budget must never buy an attacker
        // capacity.
        //
        // Sorted by TIMESTAMP rather than trusting insertion order: the field's
        // own contract says the prune predicate does not require ordering, so
        // "the last N in the vec" would be an assumption this type does not
        // make. The retained set is re-sorted ascending so the decoded value
        // has the same shape as one the fence would have written.
        let budget = crate::pins::GLOBAL_DERIVE_BUDGET as usize;
        if dispatched.len() > budget {
            dispatched.sort_unstable_by_key(|r| r.at_ns);
            dispatched = dispatched.split_off(dispatched.len() - budget);
        }
        GlobalDeriveWindow { dispatched }
    }
}

/// §D — the configured token canister, or ABSENT.
///
/// Fixed width, with byte 0 as the length and 0 meaning ABSENT. Absence is a
/// first-class value here, not a decode failure: an unconfigured canister must
/// fail CLOSED and retryable (`EligibilityCheckUnavailable`), never be read as
/// "eligible" and never be confused with `PrincipalNotEligible`, which is
/// reserved for an authoritative answer below the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TokenCanisterRef([u8; PRINCIPAL_KEY_BYTES]);

impl TokenCanisterRef {
    pub fn set(p: Principal) -> Self {
        let bytes = p.as_slice();
        assert!(bytes.len() <= PRINCIPAL_MAX_BYTES && !bytes.is_empty());
        let mut out = [0u8; PRINCIPAL_KEY_BYTES];
        out[0] = bytes.len() as u8;
        out[1..1 + bytes.len()].copy_from_slice(bytes);
        TokenCanisterRef(out)
    }

    pub fn get(&self) -> Option<Principal> {
        let len = self.0[0] as usize;
        if len == 0 {
            return None;
        }
        Some(Principal::from_slice(&self.0[1..1 + len]))
    }
}

impl Storable for TokenCanisterRef {
    const BOUND: Bound = Bound::Bounded {
        max_size: PRINCIPAL_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), PRINCIPAL_KEY_BYTES, "TokenCanisterRef: wrong stable width");
        let mut a = [0u8; PRINCIPAL_KEY_BYTES];
        a.copy_from_slice(&b);
        assert!(a[0] as usize <= PRINCIPAL_MAX_BYTES, "TokenCanisterRef: impossible length byte");
        TokenCanisterRef(a)
    }
}

/// LAUNCH-HARDEN-04 O-1(b) — the ONE principal allowed to ask
/// `has_active_device` (the shielded pool), or ABSENT. MemoryId 20.
///
/// Same fixed layout as `TokenCanisterRef`: byte 0 = length, 0 = ABSENT.
/// Absence is a VALUE, not a decode failure — it means "unconfigured", which
/// `has_active_device` REFUSES (`DeviceCheckRefusal::CallerNotConfigured`,
/// fail closed), never answers. A SEPARATE type from `TokenCanisterRef` so
/// row 10's bytes and code stay untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DeviceCheckCallerRef([u8; PRINCIPAL_KEY_BYTES]);

impl DeviceCheckCallerRef {
    pub fn set(p: Principal) -> Self {
        let bytes = p.as_slice();
        assert!(bytes.len() <= PRINCIPAL_MAX_BYTES && !bytes.is_empty());
        let mut out = [0u8; PRINCIPAL_KEY_BYTES];
        out[0] = bytes.len() as u8;
        out[1..1 + bytes.len()].copy_from_slice(bytes);
        DeviceCheckCallerRef(out)
    }

    pub fn get(&self) -> Option<Principal> {
        let len = self.0[0] as usize;
        if len == 0 {
            return None;
        }
        Some(Principal::from_slice(&self.0[1..1 + len]))
    }
}

impl Storable for DeviceCheckCallerRef {
    const BOUND: Bound = Bound::Bounded {
        max_size: PRINCIPAL_KEY_BYTES as u32,
        is_fixed_size: true,
    };
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        assert_eq!(b.len(), PRINCIPAL_KEY_BYTES, "DeviceCheckCallerRef: wrong stable width");
        let mut a = [0u8; PRINCIPAL_KEY_BYTES];
        a.copy_from_slice(&b);
        assert!(
            a[0] as usize <= PRINCIPAL_MAX_BYTES,
            "DeviceCheckCallerRef: impossible length byte"
        );
        DeviceCheckCallerRef(a)
    }
}

/// Does a wrapped envelope of this length fit its stable bound? Exposed so the
/// endpoint can REFUSE an over-long envelope with a typed error while it is
/// still a caller mistake, instead of trapping inside `insert`.
pub fn wrapped_secret_fits(len: usize) -> bool {
    len <= WRAPPED_SECRET_MAX_BYTES as usize
}

/// Same, for a device record's two SPKI fields. The fixed tail is accounted for
/// by encoding a maximal record rather than by a hand-added constant, so the
/// check cannot drift from the layout it is checking.
pub fn device_record_fits(enc_len: usize, sign_len: usize) -> bool {
    let probe = DeviceRecord {
        enc_pubkey_spki: vec![0u8; enc_len],
        sign_pubkey_spki: vec![0u8; sign_len],
        status: DeviceStatus::Active,
        added_at_ns: u64::MAX,
        revoked_at_ns: Some(u64::MAX),
        approved_by: ApprovedBy::Device(DeviceIdKey([0u8; DEVICE_ID_KEY_BYTES])),
    };
    probe.to_bytes().len() <= DEVICE_RECORD_MAX_BYTES as usize
}

// ═════════════════════════════════════════════════════════════════════════════
// MemoryId ALLOCATIONS — literal at the call site (lib.rs `mem` doc comment)
// ═════════════════════════════════════════════════════════════════════════════
//
// 0–2 belong to `KeyManager` and are NOT touched. 3–9 are appended here and
// declared in docs/MEMORY_ID_REGISTRY.md in this same commit.
//
// Each `MemoryId::new(..)` below is a LITERAL at its call site, deliberately:
// hiding one behind a helper is what made the original three allocations
// invisible to the registry lint.
//
// WHY A ONE-LINE `fn` PER MAP RATHER THAN THE LITERAL INSIDE `thread_local!`.
// The lint parses source with `syn` and walks EXPRESSIONS; a `thread_local!`
// body is an unexpanded macro token stream, so a `MemoryId::new(3)` written
// inside it is INVISIBLE to the scanner — the allocation would exist and the
// registry row would be reported as undeclared-in-code (verified: the lint
// reports all seven as "no allocation exists in code" when written that way).
// That is the same vacuum the `mem(id: u8)` helper created before the P1
// hardening, arrived at from the other direction. Each allocation therefore
// sits in a plain `fn` body where the scanner sees the literal, and the `fn`
// returns `Memory` (never `MemoryId`, which the lint rejects outright).

fn devices_memory() -> Memory {
    mem(MemoryId::new(3))
}
fn wrapped_secrets_memory() -> Memory {
    mem(MemoryId::new(4))
}
fn bootstrap_tickets_memory() -> Memory {
    mem(MemoryId::new(5))
}
fn consumed_nonces_memory() -> Memory {
    mem(MemoryId::new(6))
}
fn admission_memory() -> Memory {
    mem(MemoryId::new(7))
}
fn established_memory() -> Memory {
    mem(MemoryId::new(8))
}
fn registrations_memory() -> Memory {
    mem(MemoryId::new(9))
}
fn token_canister_memory() -> Memory {
    mem(MemoryId::new(10))
}
fn replacements_memory() -> Memory {
    mem(MemoryId::new(11))
}
fn revocation_rate_memory() -> Memory {
    mem(MemoryId::new(12))
}
fn nonce_expiry_index_memory() -> Memory {
    mem(MemoryId::new(13))
}
fn global_derive_window_memory() -> Memory {
    mem(MemoryId::new(14))
}
fn eligibility_sightings_memory() -> Memory {
    mem(MemoryId::new(15))
}
fn re_bootstrap_policy_memory() -> Memory {
    mem(MemoryId::new(17))
}
fn sighting_expiry_index_memory() -> Memory {
    mem(MemoryId::new(16))
}
fn vetkey_verification_key_cache_memory() -> Memory {
    mem(MemoryId::new(18))
}
fn device_approval_policy_memory() -> Memory {
    mem(MemoryId::new(19))
}
fn device_check_caller_memory() -> Memory {
    mem(MemoryId::new(20))
}

thread_local! {
    /// MemoryId 3 — the device registry, keyed `(owner, device_id)`.
    pub static DEVICES: RefCell<StableBTreeMap<DeviceKey, DeviceRecord, Memory>> =
        RefCell::new(StableBTreeMap::init(devices_memory()));

    /// MemoryId 4 — wrapped master-secret envelopes, keyed identically to the
    /// registry. SEPARATE from 3 so revocation deletes the blob and keeps the
    /// device record.
    pub static WRAPPED_SECRETS: RefCell<StableBTreeMap<DeviceKey, WrappedSecret, Memory>> =
        RefCell::new(StableBTreeMap::init(wrapped_secrets_memory()));

    /// MemoryId 5 — one live bootstrap ticket per principal (brief V2 §B).
    pub static BOOTSTRAP_TICKETS: RefCell<StableBTreeMap<PrincipalKey, BootstrapTicket, Memory>> =
        RefCell::new(StableBTreeMap::init(bootstrap_tickets_memory()));

    /// MemoryId 6 — consumed approval nonces, keyed
    /// `(owner, issuer_device_id, nonce)`; the value is the transcript expiry,
    /// which is what makes the set PRUNABLE past expiry rather than unbounded.
    pub static CONSUMED_NONCES: RefCell<StableBTreeMap<NonceKey, u64, Memory>> =
        RefCell::new(StableBTreeMap::init(consumed_nonces_memory()));

    /// MemoryId 7 — the V4 §H′ admission machine, per principal.
    pub static ADMISSION: RefCell<StableBTreeMap<PrincipalKey, AdmissionState, Memory>> =
        RefCell::new(StableBTreeMap::init(admission_memory()));

    /// MemoryId 8 — the `established_principal` bit (brief V2 §D); the value is
    /// the ns timestamp of the ceremony that set it. Its OWN map, not a field
    /// on `AdmissionState`: "never writable by any other path" is a structural
    /// claim, and a separate map is what makes it one.
    pub static ESTABLISHED: RefCell<StableBTreeMap<PrincipalKey, u64, Memory>> =
        RefCell::new(StableBTreeMap::init(established_memory()));

    /// MemoryId 9 — the §E `register_device` rate-limit window, per principal.
    pub static REGISTRATIONS: RefCell<StableBTreeMap<PrincipalKey, RegistrationWindow, Memory>> =
        RefCell::new(StableBTreeMap::init(registrations_memory()));

    /// MemoryId 11 — the D-1b v3 §2 `replace_envelope` rate-limit window.
    /// SEPARATE from 9: a passcode toggle must not consume the allowance a user
    /// needs to register a device, and vice versa.
    pub static REPLACEMENTS: RefCell<StableBTreeMap<PrincipalKey, RegistrationWindow, Memory>> =
        RefCell::new(StableBTreeMap::init(replacements_memory()));

    /// MemoryId 13 — the Opus-round RED-1 expiry-ordered index over
    /// `CONSUMED_NONCES` (6). Row present here ⇔ row present there, maintained
    /// both-or-neither inside single non-awaiting messages; a discovered
    /// mismatch TRAPS rather than continuing on a broken invariant. What it
    /// buys: expired rows form the low prefix, so admission-time reclamation
    /// removes AT MOST `pins::NONCE_PRUNE_MAX` rows per call instead of
    /// scanning the whole primary map.
    pub static NONCE_EXPIRY_INDEX: RefCell<StableBTreeMap<NonceExpiryKey, (), Memory>> =
        RefCell::new(StableBTreeMap::init(nonce_expiry_index_memory()));

    /// MemoryId 12 — the Opus-round RED-2 `revoke_device` rate-limit window.
    /// SEPARATE from 9 and 11 (isolation is the point): exhausting revocation
    /// must not reduce the registration or replacement allowance, or vice
    /// versa. Stable for the same reason as both: an upgrade-cleared window is
    /// a free allowance.
    pub static REVOCATION_RATE: RefCell<StableBTreeMap<PrincipalKey, RegistrationWindow, Memory>> =
        RefCell::new(StableBTreeMap::init(revocation_rate_memory()));

    /// MemoryId 17 — L04-07, the per-principal re-bootstrap policy. An ABSENT
    /// row is "not authorized" and is the state every existing enrolment is
    /// in; the row is written only by `authorize_re_bootstrap`, against a
    /// signature from a device that was ACTIVE before the revocation. Stable
    /// for the same reason rows 9/11/12 are: an upgrade-cleared authorization
    /// would either be a free bootstrap or a lost one, and neither is a state
    /// this map is allowed to invent.
    pub static RE_BOOTSTRAP_POLICY:
        RefCell<StableBTreeMap<PrincipalKey, RebootstrapPolicyV1, Memory>> =
        RefCell::new(StableBTreeMap::init(re_bootstrap_policy_memory()));

    /// MemoryId 10 — the §D token canister, set at install or upgrade.
    /// A CELL, not a map: there is exactly one, and an absent one is a value
    /// (`TokenCanisterRef::default()`), not a missing row.
    pub static TOKEN_CANISTER: RefCell<StableCell<TokenCanisterRef, Memory>> =
        RefCell::new(StableCell::init(token_canister_memory(), TokenCanisterRef::default()));

    /// MemoryId 14 — `GLOBAL_DERIVE_BUDGET_WINDOW`, the C-26 remedy R2 fleet-
    /// wide rolling dispatch window (brief V3 §7.1). A CELL, not a map: there
    /// is exactly one, fleet-wide by definition. Written ONLY from the fence's
    /// commit phase; a pre-dispatch failure of any kind never touches it.
    /// Stable so an upgrade cannot grant a free fleet allowance (the reason
    /// registry rows 7/9/11/12 give). The R6-1 A-2 meter stays heap/ephemeral.
    pub static GLOBAL_DERIVE_BUDGET_WINDOW: RefCell<StableCell<GlobalDeriveWindow, Memory>> =
        RefCell::new(StableCell::init(
            global_derive_window_memory(),
            GlobalDeriveWindow::default(),
        ));

    /// MemoryId 15 — `ELIGIBILITY_SIGHTINGS`, the PRIMARY held-balance-age
    /// evidence map (A1 fix brief V5 §6.5). Key: the principal. Value:
    /// `first_seen_at_ns`, the FIRST instant at which this canister OBSERVED
    /// that principal at or above `pins::ELIGIBILITY_MIN_BALANCE_E8S`.
    ///
    /// OBSERVED, NOT READ — the whole reason this map exists. The ledger has no
    /// history query, so `icrc1_balance_of` answers only "now". Age is
    /// therefore not a fact that can be fetched; it is one this canister
    /// accumulates over time, and the row IS the accumulation.
    ///
    /// TRANSIENT BY CONSTRUCTION: a successful, finalized derive DELETES the
    /// row (from both structures) and sets `ESTABLISHED`, so a row exists only
    /// for a principal that has proven a balance and not yet derived. Bounded
    /// by `pins::MAX_SIGHTINGS`; the cap applies ONLY to a NEW insertion, so a
    /// caller that already holds a row is admitted at a full table.
    ///
    /// STABLE, NOT HEAP (rows 7/9/11/12's reason, inverted): an upgrade that
    /// forgot these rows would RESTART every waiting user's clock — the cost
    /// falls on honest users, not on an attacker, which is the direction that
    /// makes losing it unacceptable rather than merely untidy.
    pub static ELIGIBILITY_SIGHTINGS: RefCell<StableBTreeMap<PrincipalKey, u64, Memory>> =
        RefCell::new(StableBTreeMap::init(eligibility_sightings_memory()));

    /// MemoryId 16 — `SIGHTING_EXPIRY_INDEX`, the expiry-ordered secondary over
    /// 15, keyed `(expiry_ns BIG-ENDIAN, PrincipalKey)`.
    ///
    /// Row present here ⇔ row present in 15, maintained both-or-neither inside
    /// single non-awaiting messages; a discovered mismatch TRAPS rather than
    /// continuing on a broken invariant. Exactly the MemoryId-13 contract, for
    /// exactly the MemoryId-13 reason: the principal-keyed primary CANNOT
    /// provide an expiry prefix, so a prune over it alone would be a full-map
    /// scan on a caller-reachable admission path. With this index the expired
    /// rows are the low prefix, and at most `pins::SIGHTING_PRUNE_MAX` are
    /// EXAMINED per admission — `O(K log N)`, with a backlog larger than K
    /// draining across calls, never in one.
    pub static SIGHTING_EXPIRY_INDEX: RefCell<StableBTreeMap<SightingExpiryKey, (), Memory>> =
        RefCell::new(StableBTreeMap::init(sighting_expiry_index_memory()));

    /// MemoryId 18 — `VETKEY_VERIFICATION_KEY_CACHE` (R-5, L04-02). A CELL, not
    /// a map: there is exactly ONE canister-scoped verification key, so the
    /// cache is process-wide and is deliberately NOT keyed by principal.
    /// Written only through `set_verification_key_cache` below. No
    /// post-upgrade invalidation: the key is derived from this canister's own
    /// id and the configured key id, `post_upgrade` traps rather than accept a
    /// changed config, and the one path that does change it — a reinstall —
    /// wipes this cell along with everything else.
    pub static VETKEY_VERIFICATION_KEY_CACHE:
        RefCell<StableCell<VerificationKeyCacheV1, Memory>> =
        RefCell::new(StableCell::init(
            vetkey_verification_key_cache_memory(),
            VerificationKeyCacheV1::default(),
        ));

    /// MemoryId 19 — LAUNCH-HARDEN-04 O-8. The per-principal "require device
    /// approval" flag. ABSENT row = flag off (today's behaviour). Stable for
    /// the rows 9/11/12/17 reason: an upgrade-cleared flag would silently
    /// re-open the bootstrap path the user closed.
    pub static DEVICE_APPROVAL_POLICY:
        RefCell<StableBTreeMap<PrincipalKey, DeviceApprovalPolicyV1, Memory>> =
        RefCell::new(StableBTreeMap::init(device_approval_policy_memory()));

    /// MemoryId 20 — LAUNCH-HARDEN-04 O-1(b): the ONE principal allowed to ask
    /// `has_active_device` (the shielded pool). Written ONLY from
    /// `#[init]`/`#[post_upgrade]`; deliberately NO callable setter.
    pub static DEVICE_CHECK_CALLER: RefCell<StableCell<DeviceCheckCallerRef, Memory>> =
        RefCell::new(StableCell::init(device_check_caller_memory(), DeviceCheckCallerRef::default()));
}

/// Read the configured `has_active_device` caller (MemoryId 20), if any.
pub fn device_check_caller() -> Option<Principal> {
    DEVICE_CHECK_CALLER.with_borrow(|c| c.get().get())
}

/// Write MemoryId 20. Called ONLY from `#[init]` / `#[post_upgrade]` with an
/// explicit `Some(..)`; there is deliberately no callable setter.
pub fn set_device_check_caller(p: Principal) {
    DEVICE_CHECK_CALLER.with_borrow_mut(|c| {
        c.set(DeviceCheckCallerRef::set(p));
    });
}

/// Read the configured token canister, if any.
pub fn token_canister() -> Option<Principal> {
    TOKEN_CANISTER.with_borrow(|cell| cell.get().get())
}

/// Write the token canister. Called ONLY from `#[init]` / `#[post_upgrade]`
/// with an explicit `Some(..)`; there is deliberately no callable setter.
pub fn set_token_canister(p: Principal) {
    TOKEN_CANISTER.with_borrow_mut(|cell| {
        cell.set(TokenCanisterRef::set(p));
    });
}

/// The ONE write path for MemoryId 18 (R-5, L04-02). Both
/// `get_vetkey_verification_key`'s cache-fill and
/// `refresh_vetkey_verification_key_cache` go through here rather than calling
/// `set` directly, so the length `StableCell::set` does NOT check is enforced
/// in exactly one place. A key that somehow exceeded the bound traps here,
/// loudly and by name, rather than being written unchecked.
pub(crate) fn set_verification_key_cache(key: Vec<u8>) {
    assert!(
        key.len() <= VERIFICATION_KEY_CACHE_MAX_BYTES as usize,
        "vetkey verification key ({} bytes) exceeds VERIFICATION_KEY_CACHE_MAX_BYTES ({})",
        key.len(),
        VERIFICATION_KEY_CACHE_MAX_BYTES
    );
    VETKEY_VERIFICATION_KEY_CACHE.with_borrow_mut(|c| {
        c.set(VerificationKeyCacheV1(key));
    });
}

#[cfg(test)]
mod tests {

    // ── §3 / §9.2 — the storage/admission split and its migration ────────────
    //
    // These arms are the load-bearing deliverables of the re-pin lane. The
    // defect they close: byte bound and decode assertion were both derived from
    // `GLOBAL_DERIVE_BUDGET`, so lowering the budget made an existing cell
    // undecodable and trapped `post_upgrade`.

    /// Encode a window cell BY HAND, the way a predecessor release would have
    /// written it — layout byte, count byte, then little-endian timestamps.
    ///
    /// Hand-built on purpose: calling `to_bytes` would go through the CURRENT
    /// encode assertion, which refuses more than the budget, so it cannot
    /// produce the legacy cell this migration exists to read.
    fn legacy_window_bytes(timestamps: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + timestamps.len() * 8);
        out.push(LAYOUT_V1);
        out.push(timestamps.len() as u8);
        for t in timestamps {
            out.extend_from_slice(&t.to_le_bytes());
        }
        out
    }

    /// §9.2(5) THE MIGRATION ARM — a 100-entry legacy cell decodes without
    /// trapping and retains exactly the newest 20.
    ///
    /// MUTATION-RED: restore master's decode assertion
    /// (`n <= GLOBAL_DERIVE_BUDGET`) and this panics instead of returning —
    /// which is exactly the `post_upgrade` trap on the real upgrade path.
    #[test]
    fn a_hundred_entry_legacy_cell_decodes_and_retains_the_newest_budget() {
        // Timestamps 1..=100, so "newest" is unambiguous and independent of the
        // constants under test.
        let legacy: Vec<u64> = (1..=100u64).collect();
        assert_eq!(legacy.len(), crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES);

        let decoded = GlobalDeriveWindow::from_bytes(Cow::Owned(legacy_window_bytes(&legacy)));

        let budget = crate::pins::GLOBAL_DERIVE_BUDGET as usize;
        assert_eq!(decoded.dispatched.len(), budget, "exactly the budget is retained");
        // The expected set is CONSTRUCTED here from the fixture, not read back
        // from the decoder: the newest 20 of 1..=100 are 81..=100.
        let mut expected: Vec<u64> = (1..=100u64).rev().take(budget).collect();
        expected.reverse();
        assert_eq!(
            decoded.dispatched.iter().map(|r| r.at_ns).collect::<Vec<_>>(),
            expected,
            "the NEWEST entries are the ones kept"
        );
        // V5 §3: a V1 carry is counted but NEVER attributed. The decoder may
        // not invent a principal for a cell that never recorded one.
        assert!(
            decoded.dispatched.iter().all(|r| r.who.is_none() && !r.first_derive),
            "an untagged legacy entry must decode as unattributed"
        );

        // And the migrated value re-encodes inside the bound, so the very next
        // write cannot trap either.
        let re_encoded = decoded.to_bytes().into_owned();
        assert!(re_encoded.len() <= GLOBAL_DERIVE_WINDOW_MAX_BYTES as usize);
        assert_eq!(GlobalDeriveWindow::from_bytes(Cow::Owned(re_encoded)), decoded);
    }

    /// §9.2(6) TRUNCATION DIRECTION — keeping the newest is the FAIL-CLOSED
    /// choice, and this arm proves the direction rather than restating it.
    ///
    /// A retained entry holds capacity until it expires. The retained set's
    /// oldest member is therefore what decides when capacity next frees: with
    /// the newest kept, that instant is NO EARLIER than it would be under any
    /// other choice of which entries to keep. Keeping the oldest would free
    /// capacity sooner — a free burst handed out by the upgrade that tightens
    /// the ceiling.
    #[test]
    fn truncation_keeps_capacity_consumed_for_longer_not_shorter() {
        let legacy: Vec<u64> = (1..=100u64).collect();
        let decoded = GlobalDeriveWindow::from_bytes(Cow::Owned(legacy_window_bytes(&legacy)));
        let budget = crate::pins::GLOBAL_DERIVE_BUDGET as usize;

        let kept_oldest_in_retained =
            decoded.dispatched.iter().map(|r| r.at_ns).min().expect("non-empty");
        // The alternative the brief rejects: keep the OLDEST `budget` entries.
        let oldest_alternative: Vec<u64> = legacy.iter().copied().take(budget).collect();
        let alternative_oldest = *oldest_alternative.iter().min().expect("non-empty");

        assert!(
            kept_oldest_in_retained >= alternative_oldest,
            "the shipped truncation must free capacity NO EARLIER than the alternative \
             (shipped oldest-retained {kept_oldest_in_retained}, alternative {alternative_oldest})"
        );
        // Non-vacuity: while the budget is BELOW the storage bound the two
        // really are different, so the comparison above is not trivially
        // satisfied. LAUNCH-HARDEN-04 O-3 (RATIFICATION_HARDEN04_DERIVE_NUMBERS_
        // 2026-09-24) raised the budget to 100 = GLOBAL_DERIVE_WINDOW_MAX_ENTRIES,
        // at which point a legacy cell (≤ 100 entries) can no longer be
        // truncated at all; that is asserted EXPLICITLY instead, so the arm
        // re-arms automatically if the budget is ever lowered again.
        if budget < crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES {
            assert!(kept_oldest_in_retained > alternative_oldest);
        } else {
            assert_eq!(
                decoded.dispatched.iter().map(|r| r.at_ns).collect::<Vec<_>>(),
                legacy,
                "budget == storage bound: a legacy cell is never truncated"
            );
        }
    }

    /// §9.2(9) — a full budget-sized window round-trips unchanged (no
    /// truncation fires when none is needed).
    #[test]
    fn a_full_budget_window_round_trips_untouched() {
        // Built from TAGGED records: the write path is V2-only, so this arm
        // now also proves the V2 round trip preserves attribution exactly.
        let full: Vec<DispatchRecord> = (1..=crate::pins::GLOBAL_DERIVE_BUDGET as u64)
            .map(|i| DispatchRecord {
                at_ns: i,
                who: Some(PrincipalKey::new(p(i as u8))),
                // Alternating, so a decoder that dropped the flag or hardcoded
                // either value would fail rather than pass on a uniform fixture.
                first_derive: i % 2 == 0,
            })
            .collect();
        let window = GlobalDeriveWindow { dispatched: full.clone() };
        let decoded = GlobalDeriveWindow::from_bytes(Cow::Owned(window.to_bytes().into_owned()));
        assert_eq!(decoded.dispatched, full);
    }

    /// §9.2(9) — ENCODE still refuses more than the budget. The write path is
    /// unchanged by this lane: only reads accept legacy width.
    #[test]
    #[should_panic(expected = "more retained dispatches than the budget admits")]
    fn encoding_more_than_the_budget_still_asserts() {
        let over: Vec<DispatchRecord> = (1..=(crate::pins::GLOBAL_DERIVE_BUDGET as u64 + 1))
            .map(DispatchRecord::untagged)
            .collect();
        let _ = GlobalDeriveWindow { dispatched: over }.to_bytes();
    }

    /// §9.2(9) — DECODE still traps beyond the STORAGE bound. Accepting legacy
    /// width is not accepting anything: 101 entries cannot be a cell this code
    /// ever wrote, so it is corruption and must fail closed.
    #[test]
    #[should_panic(expected = "dispatch count out of bound")]
    fn decoding_beyond_the_storage_bound_still_traps() {
        let too_many: Vec<u64> =
            (1..=(crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES as u64 + 1)).collect();
        let _ = GlobalDeriveWindow::from_bytes(Cow::Owned(legacy_window_bytes(&too_many)));
    }

    /// The byte bound must admit a MAXIMAL stored cell — the storage constant's
    /// worth, not the budget's. If this ever fails, `Bound::Bounded` is smaller
    /// than something the region may legitimately hold, which is the original
    /// defect wearing a different hat.
    #[test]
    fn the_byte_bound_admits_a_maximal_legacy_cell() {
        let maximal = legacy_window_bytes(
            &(1..=crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES as u64).collect::<Vec<_>>(),
        );
        assert!(
            maximal.len() <= GLOBAL_DERIVE_WINDOW_MAX_BYTES as usize,
            "a {}-entry cell is {} bytes, over the {} byte bound",
            crate::pins::GLOBAL_DERIVE_WINDOW_MAX_ENTRIES,
            maximal.len(),
            GLOBAL_DERIVE_WINDOW_MAX_BYTES
        );
        // Regenerated here rather than read from the code: 2 header bytes plus
        // 100 V2 records of 8 (at_ns) + 1 (presence) + 30 (PrincipalKey) + 1
        // (first_derive) = 40 bytes each.
        assert_eq!(GLOBAL_DERIVE_WINDOW_MAX_BYTES, 2 + 100 * (8 + 1 + 30 + 1));
        // AND it only ever GREW: the V1 figure this lane replaces must still
        // fit, or every legacy cell would be outside the bound.
        assert!(GLOBAL_DERIVE_WINDOW_MAX_BYTES >= 2 + 100 * 8);
    }

    // ── Arm 29 (V5 §8.1) — `SightingExpiryKey`'s canonical BE encoding ───────
    //
    // The index's ENTIRE value is that expired rows form the low prefix. That
    // property is not a fact about the map; it is a fact about this encoding.
    // These arms are what make it checkable rather than asserted.

    /// Arm 29a — round trip, and the exact stable width.
    #[test]
    fn sighting_expiry_key_round_trips_at_its_pinned_width() {
        let k = SightingExpiryKey { expiry_ns: 0x0102_0304_0506_0708, who: PrincipalKey::new(p(7)) };
        let bytes = k.to_bytes().into_owned();
        // 38 = 8 (expiry) + 30 (PrincipalKey), regenerated here rather than
        // read back from the constant under test.
        assert_eq!(bytes.len(), 8 + 30);
        assert_eq!(SightingExpiryKey::from_bytes(Cow::Owned(bytes)), k);
    }

    /// Arm 29b — the expiry prefix is BIG-ENDIAN, and the leading bytes really
    /// are the most significant ones.
    ///
    /// This is the arm that FAILS under little-endian: `0x0102…` encoded LE
    /// would start with `08`, and the ordering property below would collapse.
    #[test]
    fn the_expiry_prefix_is_big_endian() {
        let k = SightingExpiryKey { expiry_ns: 0x0102_0304_0506_0708, who: PrincipalKey::new(p(1)) };
        let bytes = k.to_bytes().into_owned();
        assert_eq!(
            &bytes[..8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "the expiry prefix must be big-endian, most-significant byte first"
        );
    }

    /// **Arm 29c — the ordering arm, ACROSS A BYTE BOUNDARY.**
    ///
    /// `StableBTreeMap` iterates in ENCODED-BYTE order, so "expired rows are
    /// the low prefix" is a claim about `to_bytes()` ordering, not about the
    /// struct's `Ord`. The boundary pair is chosen deliberately: `0x00FF` and
    /// `0x0100` differ in a way little-endian gets BACKWARDS (LE would put
    /// `FF 00 …` before `00 01 …` — the later expiry first), so this arm is
    /// exactly the one that catches an endianness regression.
    ///
    /// The principal component is chosen to work AGAINST the expected result:
    /// the earlier expiry carries the LARGER principal, so a comparison that
    /// accidentally ordered on the principal first would fail here.
    #[test]
    fn an_earlier_expiry_sorts_first_in_encoded_byte_order_across_a_byte_boundary() {
        let earlier = SightingExpiryKey { expiry_ns: 0x00FF, who: PrincipalKey::new(p(250)) };
        let later = SightingExpiryKey { expiry_ns: 0x0100, who: PrincipalKey::new(p(1)) };
        assert!(earlier.expiry_ns < later.expiry_ns, "fixture: earlier really is earlier");
        assert!(
            earlier.to_bytes().into_owned() < later.to_bytes().into_owned(),
            "an earlier expiry must sort strictly first in ENCODED-BYTE order — this is the \
             arm that fails under little-endian"
        );
    }

    /// Arm 29d — a wrong stable width asserts rather than decoding garbage.
    #[test]
    #[should_panic(expected = "SightingExpiryKey: wrong stable width")]
    fn a_short_sighting_expiry_key_asserts() {
        let _ = SightingExpiryKey::from_bytes(Cow::Owned(vec![0u8; 8 + 29]));
    }

    // ── Unit 8 (V5 §8.1) — the MemoryId-14 V1/V2 DUAL READ ──────────────────

    /// V2 round-trips, INCLUDING an untagged record.
    ///
    /// The untagged case matters on the write path too: a V1 cell decoded into
    /// memory and written back out must still say "unattributed", not acquire
    /// an invented principal on the way through.
    #[test]
    fn v2_round_trips_tagged_and_untagged_records_together() {
        let mixed = vec![
            DispatchRecord::untagged(11),
            DispatchRecord { at_ns: 12, who: Some(PrincipalKey::new(p(3))), first_derive: true },
            DispatchRecord { at_ns: 13, who: Some(PrincipalKey::new(p(4))), first_derive: false },
        ];
        let window = GlobalDeriveWindow { dispatched: mixed.clone() };
        let decoded = GlobalDeriveWindow::from_bytes(Cow::Owned(window.to_bytes().into_owned()));
        assert_eq!(decoded.dispatched, mixed);
    }

    /// The write path is **V2 ONLY** — the layout byte proves it, so a silent
    /// reversion to writing V1 cannot pass.
    #[test]
    fn the_write_path_emits_the_v2_layout_byte() {
        let window =
            GlobalDeriveWindow { dispatched: vec![DispatchRecord::untagged(1)] };
        let bytes = window.to_bytes().into_owned();
        // 2, written out here rather than read from the constant under test.
        assert_eq!(bytes[0], 2, "V5 §3: write V2 only");
        assert_eq!(bytes.len(), 2 + (8 + 1 + 30 + 1), "one fixed-width V2 record");
    }

    /// **ACCEPT-V2-ONLY MUST BE RED.** A decoder that refused V1 would trap
    /// `post_upgrade` on every live predecessor cell — the storage/admission
    /// trap this canister already fixed once, re-created one version later.
    /// This arm drives a genuine V1 cell through the shipped decoder.
    #[test]
    fn a_legacy_v1_cell_still_decodes_and_is_never_attributed() {
        let legacy = legacy_window_bytes(&[5, 6, 7]);
        assert_eq!(legacy[0], 1, "fixture: this really is a V1 cell");
        let decoded = GlobalDeriveWindow::from_bytes(Cow::Owned(legacy));
        assert_eq!(
            decoded.dispatched,
            vec![
                DispatchRecord::untagged(5),
                DispatchRecord::untagged(6),
                DispatchRecord::untagged(7)
            ]
        );
    }

    /// An UNKNOWN layout byte traps. Not "falls back to V1", not "assumes V2":
    /// a cell this code never wrote is corruption, and guessing at it is how a
    /// decoder turns corruption into plausible-looking state.
    #[test]
    #[should_panic(expected = "unknown layout version")]
    fn an_unknown_layout_byte_traps() {
        let mut bytes = legacy_window_bytes(&[5]);
        bytes[0] = 3;
        let _ = GlobalDeriveWindow::from_bytes(Cow::Owned(bytes));
    }

    /// An unknown PRESENCE discriminant inside a V2 record traps too — the
    /// same rule one level down, where a two-valued byte is equally forgeable.
    #[test]
    #[should_panic(expected = "unknown principal-presence discriminant")]
    fn an_unknown_presence_discriminant_traps() {
        let mut bytes =
            GlobalDeriveWindow { dispatched: vec![DispatchRecord::untagged(1)] }
                .to_bytes()
                .into_owned();
        bytes[2 + 8] = 2; // the presence byte of the first record
        let _ = GlobalDeriveWindow::from_bytes(Cow::Owned(bytes));
    }

    /// And an unknown `first_derive` discriminant.
    #[test]
    #[should_panic(expected = "unknown first_derive discriminant")]
    fn an_unknown_first_derive_discriminant_traps() {
        let mut bytes =
            GlobalDeriveWindow { dispatched: vec![DispatchRecord::untagged(1)] }
                .to_bytes()
                .into_owned();
        let last = bytes.len() - 1;
        bytes[last] = 7;
        let _ = GlobalDeriveWindow::from_bytes(Cow::Owned(bytes));
    }
    use super::*;

    fn p(n: u8) -> Principal {
        let mut b = [0u8; 29];
        b[0] = n;
        Principal::from_slice(&b)
    }

    fn round_trip<T: Storable + PartialEq + std::fmt::Debug>(v: T) {
        let bytes = v.to_bytes().into_owned();
        assert_eq!(T::from_bytes(Cow::Owned(bytes)), v, "stable layout must round-trip");
    }

    #[test]
    fn principal_key_round_trips_and_is_fixed_width() {
        let k = PrincipalKey::new(p(7));
        assert_eq!(k.to_bytes().len(), PRINCIPAL_KEY_BYTES);
        round_trip(k);
    }

    /// The load-bearing ordering property: encoded keys sort by owner FIRST, so
    /// a per-principal `range` over the device registry is contiguous. A key
    /// layout that put the device id first would silently interleave owners.
    #[test]
    fn device_keys_group_by_owner_in_encoded_order() {
        let a_z = DeviceKey {
            owner: PrincipalKey::new(p(1)),
            device_id: DeviceIdKey::new("zzzz").unwrap(),
        };
        let b_a = DeviceKey {
            owner: PrincipalKey::new(p(2)),
            device_id: DeviceIdKey::new("aaaa").unwrap(),
        };
        assert!(
            a_z.to_bytes().into_owned() < b_a.to_bytes().into_owned(),
            "owner 1's LAST device must still sort before owner 2's FIRST device"
        );
    }

    /// Length-byte-first keying: one id being a prefix of another must not make
    /// their keys compare as equal-with-padding.
    #[test]
    fn device_id_prefixes_do_not_alias() {
        let short = DeviceIdKey::new("dev").unwrap();
        let long = DeviceIdKey::new("device").unwrap();
        assert_ne!(short.to_bytes(), long.to_bytes());
        assert_eq!(short.as_str(), "dev");
        assert_eq!(long.as_str(), "device");
    }

    #[test]
    fn device_id_bound_is_enforced_at_construction() {
        assert!(DeviceIdKey::new("").is_none(), "an empty device id is not a key");
        assert!(DeviceIdKey::new(&"x".repeat(MAX_DEVICE_ID_BYTES)).is_some());
        assert!(
            DeviceIdKey::new(&"x".repeat(MAX_DEVICE_ID_BYTES + 1)).is_none(),
            "over-long ids are refused, not truncated — truncation would ALIAS two ids"
        );
    }

    #[test]
    fn nonce_key_round_trips_with_its_full_scope() {
        let k = NonceKey {
            owner: PrincipalKey::new(p(3)),
            issuer_device_id: DeviceIdKey::new("issuer").unwrap(),
            nonce: [0xab; 16],
        };
        round_trip(k);
        // Same nonce, different issuing device → a DIFFERENT key. The nonce
        // scope is (principal, issuer_device_id), per brief V2 §C.
        let other = NonceKey {
            issuer_device_id: DeviceIdKey::new("issuer2").unwrap(),
            ..k
        };
        assert_ne!(k.to_bytes(), other.to_bytes());
    }

    /// RED-1 — the index key round-trips, and its two components are
    /// INDEPENDENTLY round-tripped: the expiry prefix and the fixed-width
    /// canonical `NonceKey` bytes each survive encode/decode exactly.
    #[test]
    fn nonce_expiry_key_round_trips_and_orders_by_expiry_first() {
        let nk = |n: u8| NonceKey {
            owner: PrincipalKey::new(p(4)),
            issuer_device_id: DeviceIdKey::new("issuer").unwrap(),
            nonce: [n; 16],
        };
        let k = NonceExpiryKey { expiry_ns: 0x0102_0304_0506_0708, nonce_key: nk(0xCD) };
        round_trip(k);
        // Component independence: decode recovers BOTH halves exactly.
        let decoded = NonceExpiryKey::from_bytes(Cow::Owned(k.to_bytes().into_owned()));
        assert_eq!(decoded.expiry_ns, 0x0102_0304_0506_0708);
        assert_eq!(decoded.nonce_key.to_bytes(), nk(0xCD).to_bytes());

        // ENCODED-BYTE order is expiry-first NUMERIC order (the BE encoding is
        // what makes a StableBTreeMap range walk the expired prefix): a
        // numerically smaller expiry with a LARGER nonce byte still sorts
        // first, including across a byte-boundary carry (255 → 256).
        let earlier = NonceExpiryKey { expiry_ns: 255, nonce_key: nk(0xFF) };
        let later = NonceExpiryKey { expiry_ns: 256, nonce_key: nk(0x00) };
        assert!(
            earlier.to_bytes().into_owned() < later.to_bytes().into_owned(),
            "expiry 255 must encode below expiry 256 whatever the nonce bytes"
        );
        // Same expiry: the injective NonceKey bytes break the tie, so two
        // consumes sharing an expiry are distinct rows.
        let a = NonceExpiryKey { expiry_ns: 7, nonce_key: nk(0x01) };
        let b = NonceExpiryKey { expiry_ns: 7, nonce_key: nk(0x02) };
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn device_record_round_trips_both_approval_shapes() {
        round_trip(DeviceRecord {
            enc_pubkey_spki: vec![0x30, 0x82, 0x01, 0x22],
            sign_pubkey_spki: vec![0x30, 0x59],
            status: DeviceStatus::Active,
            added_at_ns: 1_700_000_000_000_000_000,
            revoked_at_ns: None,
            approved_by: ApprovedBy::Bootstrap,
        });
        round_trip(DeviceRecord {
            enc_pubkey_spki: vec![1, 2, 3],
            sign_pubkey_spki: vec![4, 5, 6],
            status: DeviceStatus::Revoked,
            added_at_ns: 10,
            revoked_at_ns: Some(20),
            approved_by: ApprovedBy::Device(DeviceIdKey::new("issuer").unwrap()),
        });
    }

    /// A record at the shipped device-cap size must fit its declared bound —
    /// otherwise `StableBTreeMap::insert` traps in production on a legitimate
    /// registration. Sized at a real RSA-3072 + P-256 SPKI pair.
    #[test]
    fn device_record_bound_admits_a_real_key_pair() {
        let rec = DeviceRecord {
            enc_pubkey_spki: vec![0u8; 422],
            sign_pubkey_spki: vec![0u8; 91],
            status: DeviceStatus::Active,
            added_at_ns: 1,
            revoked_at_ns: Some(2),
            approved_by: ApprovedBy::Device(DeviceIdKey::new(&"x".repeat(64)).unwrap()),
        };
        assert!(
            rec.to_bytes().len() <= DEVICE_RECORD_MAX_BYTES as usize,
            "a maximal legitimate device record must fit the declared Storable bound"
        );
        round_trip(rec);
    }

    #[test]
    fn wrapped_secret_bound_admits_an_rsa_3072_ciphertext() {
        let w = WrappedSecret(vec![0u8; 384]);
        assert!(w.to_bytes().len() <= WRAPPED_SECRET_MAX_BYTES as usize);
        round_trip(w);
    }

    #[test]
    fn bootstrap_ticket_round_trips_both_used_states() {
        round_trip(BootstrapTicket { minted_at_ns: 1, expires_at_ns: 2, used: false });
        round_trip(BootstrapTicket { minted_at_ns: 3, expires_at_ns: 4, used: true });
    }

    /// The phase tag must SURVIVE the stable round trip distinctly. V4 §H′.3(d)
    /// turns on reading each phase back correctly after an upgrade; a layout
    /// that collapsed the two would silently free a `Dispatched` slot.
    #[test]
    fn admission_state_round_trips_both_phases_distinctly() {
        let st = AdmissionState {
            committed: vec![10, 20, 30],
            reservations: vec![
                Reservation { id: 1, created_at_ns: 100, phase: ReservationPhase::PreDispatch },
                Reservation { id: 2, created_at_ns: 200, phase: ReservationPhase::Dispatched },
            ],
            next_reservation_id: 3,
        };
        round_trip(st.clone());
        let decoded = AdmissionState::from_bytes(Cow::Owned(st.to_bytes().into_owned()));
        assert_eq!(decoded.reservations[0].phase, ReservationPhase::PreDispatch);
        assert_eq!(decoded.reservations[1].phase, ReservationPhase::Dispatched);
        assert_ne!(
            decoded.reservations[0].phase, decoded.reservations[1].phase,
            "the two phases must not collapse across the stable boundary"
        );
    }

    #[test]
    fn admission_state_default_is_empty_not_absent_capacity() {
        let d = AdmissionState::default();
        assert!(d.committed.is_empty() && d.reservations.is_empty());
        assert_eq!(d.next_reservation_id, 0);
        round_trip(d);
    }

    /// The maximal state the pins can produce must fit its declared bound:
    /// quota-many committed entries PLUS quota-many reservations (the §H′.1
    /// transient overshoot), with headroom to `MAX_WINDOW_ENTRIES`.
    #[test]
    fn admission_state_bound_admits_the_maximal_shipped_state() {
        let st = AdmissionState {
            committed: (0..MAX_WINDOW_ENTRIES as u64).collect(),
            reservations: (0..MAX_WINDOW_ENTRIES as u64)
                .map(|i| Reservation {
                    id: i,
                    created_at_ns: i,
                    phase: ReservationPhase::Dispatched,
                })
                .collect(),
            next_reservation_id: u64::MAX,
        };
        assert!(
            st.to_bytes().len() <= ADMISSION_STATE_MAX_BYTES as usize,
            "the maximal representable admission state must fit its Storable bound"
        );
        round_trip(st);
    }

    /// §D — absence is a VALUE, and it round-trips as one.
    #[test]
    fn token_canister_ref_round_trips_absent_and_set() {
        let absent = TokenCanisterRef::default();
        assert_eq!(absent.get(), None, "the default is ABSENT, never a principal");
        round_trip(absent);

        let set = TokenCanisterRef::set(p(0x5A));
        assert_eq!(set.get(), Some(p(0x5A)));
        round_trip(set);
        assert_ne!(set.to_bytes(), absent.to_bytes());
    }

    /// LAUNCH-HARDEN-04 O-1(b) — MemoryId 20: absence is a VALUE and
    /// round-trips as one (mirror of `token_canister_ref_round_trips_absent_and_set`).
    #[test]
    fn device_check_caller_ref_round_trips_absent_and_set() {
        let absent = DeviceCheckCallerRef::default();
        assert_eq!(absent.get(), None, "the default is ABSENT, never a principal");
        round_trip(absent);

        let set = DeviceCheckCallerRef::set(p(0x5A));
        assert_eq!(set.get(), Some(p(0x5A)));
        round_trip(set);
        assert_ne!(set.to_bytes(), absent.to_bytes());
        assert_eq!(set.to_bytes().len(), PRINCIPAL_KEY_BYTES, "fixed width");
    }

    /// LAUNCH-HARDEN-04 O-8 — MemoryId 19 layout round-trips, both pending arms.
    #[test]
    fn device_approval_policy_round_trips() {
        let dev = DeviceIdKey::new("device-1").unwrap();
        let a = DeviceApprovalPolicyV1 {
            require_device_approval: true,
            set_by_device: dev,
            set_at_ns: 123,
            pending_clear_at_ns: None,
        };
        assert_eq!(a.to_bytes().len(), DEVICE_APPROVAL_POLICY_BYTES);
        round_trip(a);
        round_trip(DeviceApprovalPolicyV1 { pending_clear_at_ns: Some(u64::MAX), ..a });
        round_trip(DeviceApprovalPolicyV1 { pending_clear_at_ns: Some(0), ..a });
        assert_ne!(
            DeviceApprovalPolicyV1 { pending_clear_at_ns: Some(0), ..a }.to_bytes(),
            a.to_bytes(),
            "Some(0) and None must not collapse"
        );
    }

    #[test]
    #[should_panic(expected = "unknown layout version")]
    fn device_approval_policy_refuses_a_foreign_layout_version() {
        let dev = DeviceIdKey::new("device-1").unwrap();
        let mut bytes = DeviceApprovalPolicyV1 {
            require_device_approval: true,
            set_by_device: dev,
            set_at_ns: 1,
            pending_clear_at_ns: None,
        }
        .to_bytes()
        .into_owned();
        bytes[0] = 2;
        let _ = DeviceApprovalPolicyV1::from_bytes(Cow::Owned(bytes));
    }

    #[test]
    fn registration_window_round_trips() {
        round_trip(RegistrationWindow::default());
        round_trip(RegistrationWindow { attempts: vec![1, 2, 3, 4, 5] });
        let full = RegistrationWindow { attempts: (0..MAX_WINDOW_ENTRIES as u64).collect() };
        assert!(full.to_bytes().len() <= REGISTRATION_WINDOW_MAX_BYTES as usize);
        round_trip(full);
    }

    /// FAIL-CLOSED DECODE. A truncated or foreign region must REFUSE, never
    /// decode to a plausible default: "quota never used" and "ticket unused"
    /// are exactly the states a lost region must not be able to invent.
    #[test]
    #[should_panic(expected = "unknown layout version")]
    fn admission_state_refuses_a_foreign_layout_version() {
        let _ = AdmissionState::from_bytes(Cow::Owned(vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    #[should_panic]
    fn admission_state_refuses_trailing_bytes() {
        let mut bytes = AdmissionState::default().to_bytes().into_owned();
        bytes.push(0x00);
        let _ = AdmissionState::from_bytes(Cow::Owned(bytes));
    }

    #[test]
    #[should_panic(expected = "unknown layout version")]
    fn bootstrap_ticket_refuses_a_foreign_layout_version() {
        let _ = BootstrapTicket::from_bytes(Cow::Owned(vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    #[should_panic(expected = "unknown status discriminant")]
    fn device_record_refuses_an_unknown_status() {
        let mut bytes = DeviceRecord {
            enc_pubkey_spki: vec![],
            sign_pubkey_spki: vec![],
            status: DeviceStatus::Active,
            added_at_ns: 0,
            revoked_at_ns: None,
            approved_by: ApprovedBy::Bootstrap,
        }
        .to_bytes()
        .into_owned();
        // The status byte sits after the layout byte and two empty var fields.
        bytes[1 + 4 + 4] = 0x09;
        let _ = DeviceRecord::from_bytes(Cow::Owned(bytes));
    }
}
