// =============================================================================
// STSH — eager stable-cell primitives (upgrade-persistence hardening)
// =============================================================================
//
// Shared building block for canisters converted away from a `pre_upgrade` →
// `STABLE_STATE_CELL` checkpoint (BRIEF_UPGRADE_PERSISTENCE_HARDENING_V2).
//
// ── Why raw bytes, not Candid ────────────────────────────────────────────────
//
// CTO rule, from the Phase 0 measurements (report § 1.4): eager cells use an
// explicit fixed raw-byte layout, never a Candid-derived `Storable`. Measured
// on a real replica: a raw fixed-size cell write costs ~2 170 instructions; a
// Candid-encoded record cell costs ~44 390 — a 20x penalty paid on EVERY
// write. Checkpoint cells paid Candid once per upgrade; eager cells pay it per
// mutation, which is what makes the encoding choice load-bearing here.
//
// ── The sentinel contract (V2) ───────────────────────────────────────────────
//
// `Cell::init(mem, default)` writes `default` when its memory region is FRESH
// and decodes the stored value when the region is RETAINED. Seeding the
// default with a value that no initialised state can ever equal therefore
// turns "did this region survive the upgrade?" into a decidable question:
//
//   sentinel survived  → the region was ABSENT → `post_upgrade` must trap
//   real value present → legitimate retained state → proceed
//
// This is the vetkeys pattern (`canisters/vetkeys/src/lib.rs`, the
// `\0__stsh_post_upgrade_sentinel__never_a_deployable_key__` key name),
// generalised. Note the asymmetry the brief calls out: a trapping
// `pre_upgrade` aborts an upgrade safely (old Wasm keeps running), but a
// trapping `post_upgrade` DOES block forward progress — so the sentinel must
// distinguish "fresh install" from "corrupt state" cleanly, never by guesswork.
//
// ── Layout ───────────────────────────────────────────────────────────────────
//
//   [0]                  layout_version (currently 1)
//   [1 + 30*i]           length of principal i, 0..=29
//   [2 + 30*i .. +29]    principal i bytes, zero-padded to 29
//
// Total width is fixed at `1 + 30*N` bytes. The sentinel is all-0xFF, which is
// unrepresentable as valid state on two independent grounds: 0xFF is not a
// defined layout version, and 0xFF exceeds the 29-byte maximum length of an IC
// principal. Both would have to be reinterpreted for a collision to exist.

use candid::Principal;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use std::borrow::Cow;

/// Maximum byte length of an IC principal (self-authenticating ids are 29).
pub const PRINCIPAL_MAX_LEN: usize = 29;

/// Current raw layout version. Bump ONLY with an explicit migration — a
/// changed layout on a live region decodes as the sentinel and fails closed,
/// which is safe but blocks the upgrade until the migration is written.
pub const LAYOUT_VERSION: u8 = 1;

/// Bytes per principal slot: one length byte + the padded principal.
const SLOT: usize = 1 + PRINCIPAL_MAX_LEN;

/// Fixed on-disk width of a `PrincipalRefs<N>`.
pub const fn encoded_len(n: usize) -> usize {
    1 + SLOT * n
}

/// An eager cell holding exactly `N` canister references.
///
/// `refs == None` IS the sentinel — "no initialised state has ever been
/// written to this region". Group references into a single `PrincipalRefs<N>`
/// when they are set together (all of them, in `init`), so they can never be
/// observed half-applied: one `Cell::set` is one atomic durable write.
///
/// Grouping is a correctness decision, not a cost one. Phase 0 measured a
/// grouped two-field raw cell at 2 370 instructions against 4 119 for the same
/// two fields in separate cells — grouping co-mutated fields is *cheaper* as
/// well as atomic. Do NOT group fields that mutate independently: `Cell::set`
/// rewrites the whole cell, so an unrelated field would be rewritten too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrincipalRefs<const N: usize> {
    refs: Option<[Principal; N]>,
}

impl<const N: usize> PrincipalRefs<N> {
    /// The impossible default handed to `Cell::init`.
    pub const fn sentinel() -> Self {
        PrincipalRefs { refs: None }
    }

    /// A populated cell.
    pub const fn new(refs: [Principal; N]) -> Self {
        PrincipalRefs { refs: Some(refs) }
    }

    /// `Some` only for legitimate initialised state; `None` means the sentinel
    /// survived and the caller MUST fail closed.
    pub const fn get(&self) -> Option<&[Principal; N]> {
        self.refs.as_ref()
    }

    /// True when this value is the sentinel — i.e. the region was absent.
    pub const fn is_sentinel(&self) -> bool {
        self.refs.is_none()
    }
}

impl<const N: usize> Storable for PrincipalRefs<N> {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![0u8; encoded_len(N)];
        match &self.refs {
            // Sentinel: every byte 0xFF.
            None => buf.iter_mut().for_each(|b| *b = 0xFF),
            Some(refs) => {
                buf[0] = LAYOUT_VERSION;
                for (i, p) in refs.iter().enumerate() {
                    let bytes = p.as_slice();
                    // Unreachable for a real principal. Assert rather than
                    // truncate: a silently truncated principal would be a
                    // corrupted authority record, far worse than a trap.
                    assert!(
                        bytes.len() <= PRINCIPAL_MAX_LEN,
                        "PrincipalRefs: principal longer than {PRINCIPAL_MAX_LEN} bytes"
                    );
                    let off = 1 + SLOT * i;
                    buf[off] = bytes.len() as u8;
                    buf[off + 1..off + 1 + bytes.len()].copy_from_slice(bytes);
                }
            }
        }
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        // Anything that is not exactly this layout decodes to the sentinel, so
        // a corrupt, foreign, or short region fails CLOSED rather than
        // fabricating principals out of partial bytes.
        if bytes.len() != encoded_len(N) {
            return Self::sentinel();
        }
        if bytes.iter().all(|b| *b == 0xFF) {
            return Self::sentinel();
        }
        if bytes[0] != LAYOUT_VERSION {
            return Self::sentinel();
        }
        let mut out = [Principal::anonymous(); N];
        for (i, slot) in out.iter_mut().enumerate() {
            let off = 1 + SLOT * i;
            let len = bytes[off] as usize;
            if len > PRINCIPAL_MAX_LEN {
                return Self::sentinel();
            }
            *slot = Principal::from_slice(&bytes[off + 1..off + 1 + len]);
        }
        PrincipalRefs { refs: Some(out) }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: encoded_len(N) as u32,
        is_fixed_size: true,
    };
}

// =============================================================================
// Scalars<N> — the fixed raw-byte SCALAR cell (Phase 2)
// =============================================================================
//
// Phase 1 only had to persist canister references. Phase 2 (treasury +
// staking) persists counters and numeric records that are mutated on LIVE
// paths, so the Encoding rule bites hardest here: every one of these cells is
// written per-operation, not once per upgrade.
//
//   raw fixed-size cell write ...  ~2 170 instructions
//   Candid-encoded record cell ... ~44 390 instructions   (20x, per write)
//
// so every Phase-2 cell below is raw. `Scalars<N>` is the single
// implementation: N big-endian u128 words behind the same versioned,
// all-0xFF-sentinel envelope as `PrincipalRefs<N>`. u128 is the widest scalar
// any converted field uses; narrower fields (u64, u32) are widened on write
// and narrowed on read by the owning canister, which keeps ONE layout and ONE
// sentinel proof instead of a family of per-width types.
//
// ── Layout ───────────────────────────────────────────────────────────────────
//
//   [0]                       layout_version (currently 1)
//   [1 + 16*i .. +15]         word i, big-endian u128
//
// Total width is fixed at `1 + 16*N`. The sentinel is all-0xFF and cannot
// collide with initialised state: byte 0 is pinned to LAYOUT_VERSION, so even
// an all-`u128::MAX` value encodes with a leading 0x01.
//
// ── Grouping ─────────────────────────────────────────────────────────────────
//
// Same rule as `PrincipalRefs`: group fields that are CO-mutated (one
// `Cell::set` = one atomic durable write, and Phase 0 measured a grouped
// two-field write at 2 370 against 4 119 for two separate cells), and keep
// independently-mutated fields in separate cells, because `Cell::set` rewrites
// the whole cell and grouping would drag an unrelated field into every write.

/// Bytes per scalar word.
const WORD: usize = 16;

/// Fixed on-disk width of a `Scalars<N>`.
pub const fn scalars_encoded_len(n: usize) -> usize {
    1 + WORD * n
}

/// An eager cell holding exactly `N` unsigned scalar words.
///
/// `words == None` IS the sentinel — "no initialised state has ever been
/// written to this region".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalars<const N: usize> {
    words: Option<[u128; N]>,
}

impl<const N: usize> Scalars<N> {
    /// The impossible default handed to `Cell::init`.
    pub const fn sentinel() -> Self {
        Scalars { words: None }
    }

    /// A populated cell.
    pub const fn new(words: [u128; N]) -> Self {
        Scalars { words: Some(words) }
    }

    /// `Some` only for legitimate initialised state; `None` means the sentinel
    /// survived and the caller MUST fail closed.
    pub const fn get(&self) -> Option<&[u128; N]> {
        self.words.as_ref()
    }

    /// True when this value is the sentinel — i.e. the region was absent.
    pub const fn is_sentinel(&self) -> bool {
        self.words.is_none()
    }
}

impl<const N: usize> Storable for Scalars<N> {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![0u8; scalars_encoded_len(N)];
        match &self.words {
            None => buf.iter_mut().for_each(|b| *b = 0xFF),
            Some(words) => {
                buf[0] = LAYOUT_VERSION;
                for (i, w) in words.iter().enumerate() {
                    let off = 1 + WORD * i;
                    buf[off..off + WORD].copy_from_slice(&w.to_be_bytes());
                }
            }
        }
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        // Fail CLOSED on anything that is not exactly this layout: a short,
        // foreign, or corrupt region must never decode as a plausible counter.
        if bytes.len() != scalars_encoded_len(N) {
            return Self::sentinel();
        }
        if bytes.iter().all(|b| *b == 0xFF) {
            return Self::sentinel();
        }
        if bytes[0] != LAYOUT_VERSION {
            return Self::sentinel();
        }
        let mut out = [0u128; N];
        for (i, slot) in out.iter_mut().enumerate() {
            let off = 1 + WORD * i;
            let mut w = [0u8; WORD];
            w.copy_from_slice(&bytes[off..off + WORD]);
            *slot = u128::from_be_bytes(w);
        }
        Scalars { words: Some(out) }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: scalars_encoded_len(N) as u32,
        is_fixed_size: true,
    };
}

// =============================================================================
// Sentinel construction contract — the encoding half
// =============================================================================
//
// The cross-Wasm halves (absent region traps; retained state passes unchanged)
// cannot be established here and live in integration-tests against real Wasm.

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        let mut b = [0u8; 29];
        b[0] = n;
        Principal::from_slice(&b)
    }

    /// The sentinel must survive its own encoding. If it did not, `Cell::init`
    /// would store a default `post_upgrade` cannot recognise and the
    /// fail-closed gate would silently become fail-open.
    #[test]
    fn sentinel_round_trips() {
        for_each_arity(|| {
            let s1 = PrincipalRefs::<1>::sentinel();
            assert!(s1.to_bytes().iter().all(|b| *b == 0xFF));
            assert_eq!(PrincipalRefs::<1>::from_bytes(s1.to_bytes()), s1);
            assert!(PrincipalRefs::<1>::from_bytes(s1.to_bytes()).is_sentinel());

            let s2 = PrincipalRefs::<2>::sentinel();
            assert_eq!(PrincipalRefs::<2>::from_bytes(s2.to_bytes()), s2);
            assert!(s2.is_sentinel());

            let s3 = PrincipalRefs::<3>::sentinel();
            assert_eq!(PrincipalRefs::<3>::from_bytes(s3.to_bytes()), s3);
            assert!(s3.is_sentinel());
        });
    }

    fn for_each_arity(f: impl Fn()) {
        f();
    }

    /// Legitimate state round-trips byte-exactly at every principal length the
    /// IC produces: anonymous (1), management (0), canister ids (~10), and
    /// self-authenticating (29).
    #[test]
    fn real_principals_round_trip_exactly() {
        let cases = [
            Principal::anonymous(),
            Principal::management_canister(),
            p(1),
            p(255),
            Principal::from_slice(&[0xAB; 29]),
        ];
        for a in cases {
            let one = PrincipalRefs::<1>::new([a]);
            assert_eq!(PrincipalRefs::<1>::from_bytes(one.to_bytes()), one);
            assert!(!PrincipalRefs::<1>::from_bytes(one.to_bytes()).is_sentinel());

            for b in cases {
                let two = PrincipalRefs::<2>::new([a, b]);
                let back = PrincipalRefs::<2>::from_bytes(two.to_bytes());
                assert_eq!(back, two, "exact round-trip for [{a}, {b}]");
                assert_eq!(back.get().unwrap()[0], a);
                assert_eq!(back.get().unwrap()[1], b);
            }
        }
    }

    /// The collision proof: NO initialised value can encode to the sentinel.
    /// The strongest adversarial case is an all-0xFF principal at every legal
    /// length — the length byte still cannot reach 0xFF, and byte 0 is pinned
    /// to the layout version.
    #[test]
    fn no_valid_state_can_collide_with_the_sentinel() {
        let sentinel = PrincipalRefs::<2>::sentinel().to_bytes().into_owned();
        for len in 0..=PRINCIPAL_MAX_LEN {
            let hostile = Principal::from_slice(&vec![0xFFu8; len]);
            let encoded = PrincipalRefs::<2>::new([hostile, hostile])
                .to_bytes()
                .into_owned();
            assert_ne!(encoded, sentinel, "{len}-byte all-0xFF principal must not collide");
            assert_eq!(encoded[0], LAYOUT_VERSION, "layout version byte is pinned");
            assert!(encoded[1] as usize <= PRINCIPAL_MAX_LEN, "length byte can never be 0xFF");
        }
    }

    /// Malformed regions fail CLOSED — short, long, wrong version, impossible
    /// length, and the all-zero shape a naively-zeroed page would take.
    #[test]
    fn malformed_regions_decode_as_sentinel() {
        let width = encoded_len(2);

        assert!(PrincipalRefs::<2>::from_bytes(Cow::Owned(vec![0u8; width - 1])).is_sentinel());
        assert!(PrincipalRefs::<2>::from_bytes(Cow::Owned(vec![0u8; width + 1])).is_sentinel());
        // All-zero: version byte 0 is not LAYOUT_VERSION.
        assert!(PrincipalRefs::<2>::from_bytes(Cow::Owned(vec![0u8; width])).is_sentinel());

        let mut wrong_version = vec![0u8; width];
        wrong_version[0] = LAYOUT_VERSION + 1;
        assert!(PrincipalRefs::<2>::from_bytes(Cow::Owned(wrong_version)).is_sentinel());

        // Right width and version, impossible length in the SECOND slot —
        // proves every slot is validated, not just the first.
        let mut bad_len = PrincipalRefs::<2>::new([p(1), p(2)]).to_bytes().into_owned();
        bad_len[1 + SLOT] = (PRINCIPAL_MAX_LEN + 1) as u8;
        assert!(PrincipalRefs::<2>::from_bytes(Cow::Owned(bad_len)).is_sentinel());
    }

    /// The declared bound must match what the encoder actually produces —
    /// a mismatch would corrupt the cell region at runtime.
    #[test]
    fn declared_bound_matches_encoded_width() {
        assert_eq!(PrincipalRefs::<1>::new([p(1)]).to_bytes().len(), encoded_len(1));
        assert_eq!(PrincipalRefs::<2>::new([p(1), p(2)]).to_bytes().len(), encoded_len(2));
        assert_eq!(PrincipalRefs::<1>::sentinel().to_bytes().len(), encoded_len(1));
        match PrincipalRefs::<2>::BOUND {
            Bound::Bounded { max_size, is_fixed_size } => {
                assert_eq!(max_size as usize, encoded_len(2));
                assert!(is_fixed_size, "the cell must be fixed-size for a cheap in-place write");
            }
            Bound::Unbounded => panic!("eager cells must be bounded"),
        }
    }

    // ── Scalars<N> — the same four obligations, for the Phase-2 scalar cell ──

    /// The sentinel must survive its own encoding, or `Cell::init` would store
    /// a default `post_upgrade` cannot recognise and the fail-closed gate would
    /// silently become fail-open.
    #[test]
    fn scalar_sentinel_round_trips() {
        let s1 = Scalars::<1>::sentinel();
        assert!(s1.to_bytes().iter().all(|b| *b == 0xFF));
        assert_eq!(Scalars::<1>::from_bytes(s1.to_bytes()), s1);
        assert!(Scalars::<1>::from_bytes(s1.to_bytes()).is_sentinel());

        let s5 = Scalars::<5>::sentinel();
        assert_eq!(Scalars::<5>::from_bytes(s5.to_bytes()), s5);
        assert!(s5.is_sentinel());

        let s9 = Scalars::<9>::sentinel();
        assert_eq!(Scalars::<9>::from_bytes(s9.to_bytes()), s9);
        assert!(s9.is_sentinel());
    }

    /// Legitimate values round-trip byte-exactly at the boundaries every
    /// converted field can reach — 0, 1, u32::MAX, u64::MAX, u128::MAX.
    #[test]
    fn scalar_values_round_trip_exactly() {
        let cases = [0u128, 1, u32::MAX as u128, u64::MAX as u128, u128::MAX];
        for a in cases {
            let one = Scalars::<1>::new([a]);
            let back = Scalars::<1>::from_bytes(one.to_bytes());
            assert_eq!(back, one);
            assert!(!back.is_sentinel(), "{a} must not read back as the sentinel");
            assert_eq!(back.get().unwrap()[0], a);

            for b in cases {
                let two = Scalars::<2>::new([a, b]);
                let back = Scalars::<2>::from_bytes(two.to_bytes());
                assert_eq!(back.get().unwrap(), &[a, b], "exact round-trip for [{a}, {b}]");
            }
        }
    }

    /// The collision proof: NO initialised value can encode to the sentinel.
    /// The strongest adversarial case is every word at `u128::MAX` — which is
    /// all-0xFF in the payload, and still cannot collide because byte 0 is
    /// pinned to the layout version.
    #[test]
    fn no_valid_scalar_can_collide_with_the_sentinel() {
        let sentinel = Scalars::<3>::sentinel().to_bytes().into_owned();
        let hostile = Scalars::<3>::new([u128::MAX; 3]).to_bytes().into_owned();
        assert_ne!(hostile, sentinel, "all-u128::MAX must not collide with the sentinel");
        assert_eq!(hostile[0], LAYOUT_VERSION, "layout version byte is pinned");
        assert!(hostile[1..].iter().all(|b| *b == 0xFF), "payload really is all-0xFF");
        assert!(
            !Scalars::<3>::from_bytes(Cow::Owned(hostile)).is_sentinel(),
            "the maximal legitimate value must decode as real state, not as the sentinel"
        );
    }

    /// Malformed regions fail CLOSED — short, long, wrong version, and the
    /// all-zero shape a naively-zeroed page would take.
    #[test]
    fn malformed_scalar_regions_decode_as_sentinel() {
        let width = scalars_encoded_len(2);

        assert!(Scalars::<2>::from_bytes(Cow::Owned(vec![0u8; width - 1])).is_sentinel());
        assert!(Scalars::<2>::from_bytes(Cow::Owned(vec![0u8; width + 1])).is_sentinel());
        // All-zero: version byte 0 is not LAYOUT_VERSION. This is the important
        // one — a zeroed region must NOT decode as the perfectly plausible
        // counter value 0.
        assert!(Scalars::<2>::from_bytes(Cow::Owned(vec![0u8; width])).is_sentinel());

        let mut wrong_version = Scalars::<2>::new([7, 9]).to_bytes().into_owned();
        wrong_version[0] = LAYOUT_VERSION + 1;
        assert!(Scalars::<2>::from_bytes(Cow::Owned(wrong_version)).is_sentinel());

        // A PrincipalRefs region must not decode as a plausible Scalars region
        // either: the widths differ (1+30N vs 1+16N) for every N in use here.
        let foreign = PrincipalRefs::<2>::new([p(1), p(2)]).to_bytes().into_owned();
        assert!(Scalars::<2>::from_bytes(Cow::Owned(foreign)).is_sentinel());
    }

    /// The declared bound must match what the encoder actually produces — a
    /// mismatch would corrupt the cell region at runtime.
    #[test]
    fn declared_scalar_bound_matches_encoded_width() {
        assert_eq!(Scalars::<1>::new([1]).to_bytes().len(), scalars_encoded_len(1));
        assert_eq!(Scalars::<5>::sentinel().to_bytes().len(), scalars_encoded_len(5));
        match Scalars::<9>::BOUND {
            Bound::Bounded { max_size, is_fixed_size } => {
                assert_eq!(max_size as usize, scalars_encoded_len(9));
                assert!(is_fixed_size, "the cell must be fixed-size for a cheap in-place write");
            }
            Bound::Unbounded => panic!("eager cells must be bounded"),
        }
    }
}
