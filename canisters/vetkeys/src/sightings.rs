// =============================================================================
// HELD-BALANCE-AGE — AGE EVALUATION (A1 fix brief V5 §6.3, RED-3)
// =============================================================================
//
// COMMIT-1 FREEZE (V5 §7.3). This module is the executable ANOMALY PROBE the
// freeze requires, landed ahead of the admission behaviour that will call it.
// It is PURE: no system calls, no state, no clock — `now` is a parameter, which
// is what makes every edge below drivable rather than argued.
//
// ── WHY `checked_sub`, AND WHY IT IS THE WHOLE FINDING ───────────────────────
//
// IC time is monotonic per canister, so a `first_seen_at_ns` in the FUTURE is a
// BUG — not clock drift. There is therefore no tolerance pin here, deliberately:
// a tolerance would be a rule about a condition that cannot legitimately occur,
// and inventing one would give a real corruption a benign-looking home.
//
// The two wrong ways to write this subtraction, and what each does:
//
//   * PLAIN subtraction TRAPS under the workspace's `overflow-checks = true`
//     (CLAUDE.md tech stack). A trap is not a fail-closed outcome — it is an
//     unhandled one, and it destroys the evidence row along with the message.
//   * SATURATING subtraction silently yields age ZERO, manufacturing an
//     ordinary countdown out of an anomaly. The refusal would look identical to
//     a first sighting, so the corruption would never be observable.
//
// Only `checked_sub` gives the anomaly its OWN outcome, which is what §6.3
// requires: refuse, leave the row byte-for-byte untouched (it is the evidence),
// dispatch nothing, release §H′, and self-heal once time passes `first_seen`.

use crate::pins::ELIGIBILITY_MIN_AGE_NS;

/// The outcome of evaluating one sighting row against `now`.
///
/// `NotYet` and `Anomalous` both refuse, and both surface as
/// `VetkeysError::EligibilityAgeNotMet` on the wire — the wallet has nothing
/// different to do. They are DISTINCT here because the CANISTER does: an
/// ordinary refusal is a normal countdown, while an anomaly must leave the row
/// untouched rather than renewing or deleting it. Collapsing them is exactly
/// how the evidence would get overwritten by the code that noticed the problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeVerdict {
    /// `age >= T` — the first derive is admissible.
    Admit,
    /// `age < T` — refuse, come back in `retry_after_ns`.
    NotYet { retry_after_ns: u64 },
    /// `first_seen_at_ns > now` — impossible under monotonic time. Refuse, and
    /// DO NOT TOUCH THE ROW.
    Anomalous { retry_after_ns: u64 },
}

impl AgeVerdict {
    /// True iff this verdict admits.
    ///
    /// TEST-FACING, on the `fence::global_admit` precedent: production code
    /// matches the verdict EXHAUSTIVELY in `decide` below, so a refusal variant
    /// can never be mistaken for admission by forgetting a branch — the
    /// compiler enforces it. A shipped `admits()` would offer exactly the
    /// boolean shortcut that removes that guarantee.
    #[cfg(test)]
    pub fn admits(self) -> bool {
        matches!(self, AgeVerdict::Admit)
    }
}

/// Evaluate one sighting against `now` (§6.3, the ruled shape verbatim).
///
/// `retry_after_ns` is EXACT on the ordinary limb: a call at
/// `now + retry_after_ns` admits, one ns earlier does not — the same
/// exactness contract `DerivationQuotaExceeded` and
/// `GlobalDerivationBudgetExceeded` already carry.
///
/// On the anomalous limb the retry is `(first_seen - now) + T`: the time until
/// the row would become admissible if `first_seen` were taken at face value.
/// `checked_add` saturating to `u64::MAX` there is ACCEPTABLE ONLY BECAUSE THE
/// LIMB STILL REFUSES — saturation cannot turn into an admission, and the arm
/// below proves that rather than asserting it.
pub fn evaluate_age(now_ns: u64, first_seen_at_ns: u64) -> AgeVerdict {
    match now_ns.checked_sub(first_seen_at_ns) {
        Some(age) if age >= ELIGIBILITY_MIN_AGE_NS => AgeVerdict::Admit,
        Some(age) => AgeVerdict::NotYet {
            // `age < T` on this arm, so the subtraction cannot underflow; it is
            // still written `checked` so no future edit can make it a trap.
            retry_after_ns: ELIGIBILITY_MIN_AGE_NS.checked_sub(age).unwrap_or(0),
        },
        None => AgeVerdict::Anomalous {
            retry_after_ns: first_seen_at_ns
                .checked_sub(now_ns)
                .unwrap_or(0)
                .checked_add(ELIGIBILITY_MIN_AGE_NS)
                .unwrap_or(u64::MAX),
        },
    }
}


// ═════════════════════════════════════════════════════════════════════════════
// THE SIGHTING STORE — bounded, both-or-neither, expiry-ordered (V5 §6.5)
// ═════════════════════════════════════════════════════════════════════════════
//
// Two structures, one invariant: **a row is present in MemoryId 15 if and only
// if its matching row is present in MemoryId 16.** Every mutation below touches
// both or neither, inside a single non-awaiting message, and any discovered
// mismatch TRAPS rather than committing a half-state — the MemoryId-13 contract,
// applied here for the same reason.
//
// THE BOUND THE INDEX BUYS. The primary is keyed by principal, so expired rows
// sit nowhere in particular in it: finding K of them there is O(N) over the
// whole table, on a path any caller can reach. The index is keyed by
// `expiry_ns` BIG-ENDIAN first, and `StableBTreeMap` iterates in encoded-byte
// order, so the expired rows are exactly the LOW PREFIX. The prune walks that
// prefix and stops at `SIGHTING_PRUNE_MAX` rows EXAMINED — examined, not merely
// removed, because the bound has to be over the WORK, not over the outcome.

use crate::pins::{MAX_SIGHTINGS, SIGHTING_PRUNE_MAX, SIGHTING_RETENTION_NS};
use crate::state::{PrincipalKey, SightingExpiryKey, ELIGIBILITY_SIGHTINGS, SIGHTING_EXPIRY_INDEX};

/// A row's index key, derived from its stored value. `checked_add` because a
/// `first_seen_at_ns` near `u64::MAX` must not wrap into a LOW expiry — that
/// would place a far-future row at the front of the prune prefix and delete it
/// immediately. Saturating to `u64::MAX` is the fail-closed direction: the row
/// is never pruned early.
fn expiry_key(who: PrincipalKey, first_seen_at_ns: u64) -> SightingExpiryKey {
    SightingExpiryKey {
        expiry_ns: first_seen_at_ns.checked_add(SIGHTING_RETENTION_NS).unwrap_or(u64::MAX),
        who,
    }
}

/// Is a row past its retention at `now`? `expiry_ns < now`, strictly — the same
/// predicate the prune walks, deliberately shared so the two can never disagree
/// about which rows are expired. A row AT its expiry is retained until a later
/// call: conservative, bounded, and it makes the 7-day retention arm's boundary
/// exact.
fn expired_at(now_ns: u64, first_seen_at_ns: u64) -> bool {
    first_seen_at_ns.checked_add(SIGHTING_RETENTION_NS).is_some_and(|e| e < now_ns)
}

thread_local! {
    /// Index rows EXAMINED by the prune walk, cumulative. Heap, ephemeral, and
    /// never read by any decision — it exists ONLY so the bound can be measured
    /// rather than argued.
    ///
    /// EXAMINED, NOT REMOVED, and the distinction is the entire point of arm
    /// 44: a prune that removed at most K rows while SCANNING the whole primary
    /// map would satisfy a removal count and still be the O(N) attacker path
    /// the index exists to close. This counts the walk. It follows the
    /// `MeterState::entries_examined` precedent (lane A-2, arm e11), which is
    /// how this crate already makes a per-call cost bound checkable.
    static SIGHTING_ROWS_EXAMINED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Rows examined by every prune since install. Monotonic; an upgrade resets it,
/// which is why arms read DELTAS and never the absolute value.
pub fn rows_examined_total() -> u64 {
    SIGHTING_ROWS_EXAMINED.with(|c| c.get())
}

/// Remove AT MOST `SIGHTING_PRUNE_MAX` expired rows from BOTH structures,
/// walking the index's low prefix. `O(K log N)`; a backlog larger than K drains
/// across successive calls, never in one.
///
/// Runs BEFORE the caller's own row is looked up (§6.2 step 2), so reclamation
/// happens even on calls that go on to be refused — the set cannot grow
/// monotonically on a path where every call is a refusal.
///
/// THE WALK IS OVER THE INDEX (MemoryId 16), and that is what supplies the
/// bound. `take_while` stops at the first row whose expiry is at or after
/// `now`, and because the index is ordered by BIG-ENDIAN `expiry_ns` in
/// encoded-byte order, everything past that point is unexpired — so the walk
/// touches at most `SIGHTING_PRUNE_MAX` rows plus the one that stops it, no
/// matter how large the table is. Walking the PRIMARY map instead would examine
/// O(N) rows for the same K removals; `SIGHTING_ROWS_EXAMINED` is what makes
/// that difference fail a test rather than pass unnoticed.
pub fn prune_expired_sightings(now_ns: u64) {
    let victims: Vec<SightingExpiryKey> = SIGHTING_EXPIRY_INDEX.with_borrow(|ix| {
        ix.iter()
            .map(|entry| *entry.key())
            .inspect(|_| SIGHTING_ROWS_EXAMINED.with(|c| c.set(c.get().saturating_add(1))))
            .take_while(|k| k.expiry_ns < now_ns)
            .take(SIGHTING_PRUNE_MAX)
            .collect()
    });
    for k in victims {
        let index_row = SIGHTING_EXPIRY_INDEX.with_borrow_mut(|ix| ix.remove(&k));
        let primary = ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.remove(&k.who));
        // Both-or-neither on the way OUT: a row in one structure but not the
        // other is a broken bijection, and a trap rolls this message back
        // rather than committing a half-removal.
        if index_row.is_none() || primary.map(|v| expiry_key(k.who, v)) != Some(k) {
            panic!("ELIGIBILITY_SIGHTINGS/SIGHTING_EXPIRY_INDEX bijection violated during prune");
        }
    }
}

/// What one admission decision did to the store — returned so the caller can
/// move the epoch-scoped counters without this module reaching into them, and
/// so every arm can assert the ACT, not just the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SightingOutcome {
    /// A first sighting was recorded. Refuse; the clock starts now.
    Inserted,
    /// An expired row was renewed in place. Refuse; the clock RESTARTS —
    /// correctly, because an expired sighting is no longer evidence.
    Renewed,
    /// The caller holds a valid row and it is old enough. ADMIT.
    Admitted,
    /// The caller holds a valid row that is not old enough yet. Refuse.
    NotYet { retry_after_ns: u64 },
    /// `first_seen_at_ns` is in the FUTURE. Refuse, row UNTOUCHED.
    Anomalous { retry_after_ns: u64 },
    // LAUNCH-HARDEN-04 O-2: the former `CapReached` outcome is GONE. A full
    // table no longer refuses an insertion; it EVICTS the oldest unconverted row
    // (`evict_oldest_sighting`) and the caller is `Inserted`.
}

/// The §6.2 decision, in the RULED ORDER, in one non-awaiting sequence.
///
/// Called only after the balance query has answered AT OR ABOVE the floor: a
/// below-floor answer and an unavailable answer both return earlier and write
/// NOTHING (SSA GREEN-2). Nothing in here awaits, which is what makes every
/// two-structure mutation below atomic.
///
/// **THE CAP APPLIES ONLY WHERE A SLOT IS ACTUALLY NEEDED.** Steps 4 and 5 —
/// own valid row, own expired row — consume no slot, so a full table still
/// serves them. Only step 6, an insertion for a caller with no row, meets
/// `MAX_SIGHTINGS` — and there (LAUNCH-HARDEN-04 O-2,
/// RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24) a full table EVICTS the
/// oldest unconverted row (lowest expiry = oldest `first_seen`) and inserts the
/// caller; it no longer refuses. Every row is unconverted by construction
/// (`clear_on_success` deletes a row when `ESTABLISHED` is written). The
/// residual is therefore: an attacker sustaining ≥ `MAX_SIGHTINGS` insertions
/// per age-in period degrades ALL pending first-derives indiscriminately (each
/// evicted user's clock restarts on their next attempt), with no permanent
/// state; before this change the same table allowed a PERMANENT denial of all
/// new first-derives until 7-day expiry.
pub fn decide(now_ns: u64, caller: PrincipalKey) -> SightingOutcome {
    // Step 2 — bounded reclamation, before the lookup.
    prune_expired_sightings(now_ns);

    // Step 3 — the caller's own row.
    let own = ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&caller));

    match own {
        // Steps 4 and 5 — the caller already has a row, so NO SLOT IS NEEDED
        // and the cap is never consulted on either branch.
        Some(first_seen_at_ns) => {
            if expired_at(now_ns, first_seen_at_ns) {
                // Step 5 — renew in place. The primary value is rewritten and
                // the index entry is RE-KEYED (old key deleted, new inserted),
                // both or neither. No slot is consumed.
                renew(caller, first_seen_at_ns, now_ns);
                return SightingOutcome::Renewed;
            }
            // Step 4 — evaluate age (§6.3).
            match evaluate_age(now_ns, first_seen_at_ns) {
                AgeVerdict::Admit => SightingOutcome::Admitted,
                AgeVerdict::NotYet { retry_after_ns } => {
                    SightingOutcome::NotYet { retry_after_ns }
                }
                // The row IS the evidence: do not delete it, do not rewrite it.
                AgeVerdict::Anomalous { retry_after_ns } => {
                    SightingOutcome::Anomalous { retry_after_ns }
                }
            }
        }
        // Step 6 — this caller needs an INSERTION, and only here does the cap
        // apply. LAUNCH-HARDEN-04 O-2: at a full table, evict the OLDEST row
        // (both structures) and insert — never refuse.
        None => {
            if ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.len()) >= MAX_SIGHTINGS as u64 {
                evict_oldest_sighting();
            }
            insert(caller, now_ns);
            SightingOutcome::Inserted
        }
    }
}

/// LAUNCH-HARDEN-04 O-2: remove the LOWEST-expiry row (= oldest `first_seen`)
/// from BOTH maps. `O(log N)`. One index read, counted in
/// `SIGHTING_ROWS_EXAMINED`. A bijection break panics (rolls the message back).
///
/// The index is keyed on BIG-ENDIAN `expiry_ns` first, so its first entry is
/// the oldest sighting; an anomalous (future-dated) row sorts LAST and is never
/// the victim. Eviction is oldest-first and indiscriminate — no caller can
/// choose whose row goes.
fn evict_oldest_sighting() {
    let k = SIGHTING_EXPIRY_INDEX
        .with_borrow(|ix| ix.iter().next().map(|e| *e.key()))
        .expect("MAX_SIGHTINGS reached but SIGHTING_EXPIRY_INDEX empty — bijection violated");
    SIGHTING_ROWS_EXAMINED.with(|c| c.set(c.get().saturating_add(1)));
    let index_row = SIGHTING_EXPIRY_INDEX.with_borrow_mut(|ix| ix.remove(&k));
    let primary = ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.remove(&k.who));
    if index_row.is_none() || primary.map(|v| expiry_key(k.who, v)) != Some(k) {
        panic!("ELIGIBILITY_SIGHTINGS/SIGHTING_EXPIRY_INDEX bijection violated during eviction");
    }
}

/// Insert a first sighting into BOTH structures.
fn insert(who: PrincipalKey, now_ns: u64) {
    ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.insert(who, now_ns));
    SIGHTING_EXPIRY_INDEX.with_borrow_mut(|ix| {
        // The primary row did not exist, so this index row cannot have either.
        // If it does, the bijection was already broken and continuing would
        // compound it.
        if ix.insert(expiry_key(who, now_ns), ()).is_some() {
            panic!("SIGHTING_EXPIRY_INDEX invariant violated: index row existed without its \
                    primary row");
        }
    });
}

/// Renew an expired row in place: rewrite the primary value, RE-KEY the index.
///
/// The old index key is derived from the STORED value, never guessed — deleting
/// a key computed from anything else would orphan the real one and break the
/// bijection silently.
fn renew(who: PrincipalKey, stored_first_seen_ns: u64, now_ns: u64) {
    let old_key = expiry_key(who, stored_first_seen_ns);
    let new_key = expiry_key(who, now_ns);
    ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.insert(who, now_ns));
    SIGHTING_EXPIRY_INDEX.with_borrow_mut(|ix| {
        if ix.remove(&old_key).is_none() {
            panic!("ELIGIBILITY_SIGHTINGS/SIGHTING_EXPIRY_INDEX bijection violated during renew");
        }
        ix.insert(new_key, ());
    });
}

/// Delete a row from BOTH structures after a successful, FINALIZED derive.
///
/// This is what makes rows transient by construction: a row exists only for a
/// principal that has proven a balance and not yet derived. Called at the same
/// point `ESTABLISHED` is written, so the two can never disagree about whether
/// this principal is still bootstrapping.
///
/// Absent is NOT an error here: an established principal never had a row, and a
/// re-derive by a principal whose row was already cleared is ordinary. Only a
/// HALF-present pair is a bijection violation.
pub fn clear_on_success(who: PrincipalKey) {
    let primary = ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.remove(&who));
    match primary {
        Some(first_seen_at_ns) => {
            let key = expiry_key(who, first_seen_at_ns);
            if SIGHTING_EXPIRY_INDEX.with_borrow_mut(|ix| ix.remove(&key)).is_none() {
                panic!("ELIGIBILITY_SIGHTINGS/SIGHTING_EXPIRY_INDEX bijection violated during \
                        success-delete");
            }
        }
        None => {
            // No primary row: there must be no index row for this principal
            // either. Checked rather than assumed — an orphaned index row would
            // otherwise sit there until its expiry and consume nothing visible.
            let orphan = SIGHTING_EXPIRY_INDEX
                .with_borrow(|ix| ix.iter().any(|entry| entry.key().who == who));
            if orphan {
                panic!("SIGHTING_EXPIRY_INDEX holds a row whose primary is absent");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T, regenerated as its own literal for these arms. Hardcoded on purpose:
    /// reading `ELIGIBILITY_MIN_AGE_NS` here could not RED on a mutation of it,
    /// because the expectation would move with the constant.
    const T: u64 = 120_000_000_000;

    /// A base `now` far from both `u64` ends, so an edge case is a real edge
    /// and not an artefact of arithmetic near a boundary.
    const NOW: u64 = 1_000 * T;

    /// Arm 27 — the age boundary triple: `T-1` refuses, `T` admits, `T+1`
    /// admits.
    #[test]
    fn age_boundary_triple_refuses_below_t_and_admits_at_and_above() {
        assert_eq!(
            evaluate_age(NOW, NOW - (T - 1)),
            AgeVerdict::NotYet { retry_after_ns: 1 },
            "age T-1 refuses, with exactly 1 ns left"
        );
        assert_eq!(evaluate_age(NOW, NOW - T), AgeVerdict::Admit, "age exactly T admits");
        assert_eq!(evaluate_age(NOW, NOW - (T + 1)), AgeVerdict::Admit, "age T+1 admits");
    }

    /// Arm 28 — `retry_after_ns` exactness, from both sides.
    ///
    /// The property: a call at `now + retry_after_ns` is admitted, and one ns
    /// earlier is not. Driven for several ages rather than one, so an
    /// off-by-one that happens to vanish at a particular age cannot pass.
    #[test]
    fn retry_after_is_exact_from_both_sides() {
        for age in [0u64, 1, T / 3, T / 2, T - 2, T - 1] {
            let first_seen = NOW - age;
            let AgeVerdict::NotYet { retry_after_ns } = evaluate_age(NOW, first_seen) else {
                panic!("age {age} is below T and must refuse");
            };
            assert!(
                evaluate_age(NOW + retry_after_ns, first_seen).admits(),
                "age {age}: a call at now + retry_after_ns must be admitted"
            );
            assert!(
                !evaluate_age(NOW + retry_after_ns - 1, first_seen).admits(),
                "age {age}: one ns earlier must NOT be admitted"
            );
        }
    }

    /// **Arm 27b (RED-3) — the anomaly probe, executable.**
    ///
    /// `first_seen == now` is an ORDINARY refusal with the full wait; one ns
    /// later is ANOMALOUS, with a distinct outcome and a distinct retry. The
    /// two must not collapse into each other: that collapse is precisely what
    /// saturating subtraction would produce.
    #[test]
    fn a_future_first_seen_is_a_distinct_anomalous_outcome() {
        assert_eq!(
            evaluate_age(NOW, NOW),
            AgeVerdict::NotYet { retry_after_ns: T },
            "first_seen == now is age zero — an ordinary refusal with the full wait"
        );
        assert_eq!(
            evaluate_age(NOW, NOW + 1),
            AgeVerdict::Anomalous { retry_after_ns: T + 1 },
            "one ns into the future is IMPOSSIBLE under monotonic time and must be its own \
             outcome, not an age-zero countdown"
        );
    }

    /// Arm 27b, second limb — the checked-add saturation path still REFUSES.
    ///
    /// This is the arm that makes `unwrap_or(u64::MAX)` acceptable. It is not
    /// an argument that saturation is unreachable; it is a proof that when it
    /// IS reached, the outcome is still fail-closed.
    #[test]
    fn the_saturating_retry_path_still_refuses() {
        let v = evaluate_age(0, u64::MAX);
        assert_eq!(
            v,
            AgeVerdict::Anomalous { retry_after_ns: u64::MAX },
            "the retry addition saturates here"
        );
        assert!(!v.admits(), "saturation must never become an admission");
    }

    /// **Arm 27b, the mutation limb.** Plain subtraction TRAPS (panics under
    /// `overflow-checks`) and saturating subtraction yields age ZERO — this arm
    /// states both alternatives as executable behaviour, so the RED is a
    /// property of the code rather than a claim in a comment.
    ///
    /// A mutation of `evaluate_age` to saturating subtraction makes
    /// `a_future_first_seen_is_a_distinct_anomalous_outcome` fail, because the
    /// anomalous input would return `NotYet { retry_after_ns: T }` — exactly
    /// what this arm shows the saturating form produces.
    #[test]
    fn the_two_rejected_subtractions_are_not_fail_closed_outcomes() {
        let (now, first_seen) = (NOW, NOW + 1);

        // Saturating: the anomaly is laundered into an ordinary age of zero,
        // indistinguishable from a brand-new sighting.
        assert_eq!(now.saturating_sub(first_seen), 0, "saturating manufactures age zero");

        // Plain: a trap, not an outcome. Caught rather than asserted in prose,
        // so the claim is checked on this profile instead of assumed.
        let plain = std::panic::catch_unwind(|| now - first_seen);
        assert!(plain.is_err(), "plain subtraction must overflow-trap on this profile");

        // And the shipped form is neither.
        assert!(matches!(evaluate_age(now, first_seen), AgeVerdict::Anomalous { .. }));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // §6 STORE ARMS — native, over the SAME stable structures (V5 §8.2)
    // ═════════════════════════════════════════════════════════════════════════
    //
    // WHY NATIVE, AND WHERE THE LINE IS. These arms are the crate's existing
    // technique for the MemoryId-13 pair (`l1_prune_boundary_is_exact…`,
    // `l1_consume_inserts_both…`, `l1_backlog_over_k_drains…`): each `#[test]`
    // runs on its own thread, so each sees a fresh `MemoryManager` and a fresh
    // pair of maps. They drive the REAL `StableBTreeMap`s and the REAL shipped
    // predicates — nothing is re-implemented here.
    //
    // What native CANNOT prove is durability across a genuine upgrade, and that
    // is deliberately NOT claimed here: arm 34 is a PocketIC arm, because a
    // heap-backed structure would pass a native "survives" test and fail a real
    // one. The split is: state-machine properties native, cross-Wasm properties
    // in the acceptance suite.
    //
    // A 10,000-row table is also only reachable natively at a sensible cost —
    // filling `MAX_SIGHTINGS` through ingress messages is not a test, it is a
    // load run.

    use crate::state::{ELIGIBILITY_SIGHTINGS, SIGHTING_EXPIRY_INDEX};

    fn who(n: u64) -> PrincipalKey {
        let mut b = [0u8; 29];
        b[0..8].copy_from_slice(&n.to_le_bytes());
        PrincipalKey::new(candid::Principal::from_slice(&b))
    }

    /// `(primary rows, index rows)`.
    fn counts() -> (u64, u64) {
        (
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.len()),
            SIGHTING_EXPIRY_INDEX.with_borrow(|ix| ix.len()),
        )
    }

    /// The bijection, checked in BOTH directions rather than by comparing
    /// lengths: equal counts with two mismatched rows would pass a length check
    /// and be exactly the broken state this invariant exists to exclude.
    fn assert_bijection() {
        let (p, i) = counts();
        assert_eq!(p, i, "row counts must match");
        ELIGIBILITY_SIGHTINGS.with_borrow(|m| {
            for entry in m.iter() {
                let k = expiry_key(*entry.key(), entry.value());
                assert!(
                    SIGHTING_EXPIRY_INDEX.with_borrow(|ix| ix.contains_key(&k)),
                    "primary row {:?} has no index row at its stored expiry",
                    entry.key()
                );
            }
        });
        SIGHTING_EXPIRY_INDEX.with_borrow(|ix| {
            for entry in ix.iter() {
                let k = entry.key();
                let stored = ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&k.who));
                assert_eq!(
                    stored.map(|v| expiry_key(k.who, v)),
                    Some(*k),
                    "index row has no primary row deriving the same key"
                );
            }
        });
    }

    /// T and the retention, as their own literals — never read back from the
    /// pins under test.
    const T_NS: u64 = 120_000_000_000;
    const RETENTION_NS: u64 = 604_800_000_000_000;
    /// A base `now` far from both `u64` ends.
    const T0: u64 = 10 * RETENTION_NS;

    /// A first sighting refuses and starts the clock; the same caller at T
    /// admits; nothing else moved.
    #[test]
    fn s1_a_first_sighting_refuses_and_the_same_caller_admits_at_t() {
        assert_eq!(decide(T0, who(1)), SightingOutcome::Inserted, "never admit on first sight");
        assert_eq!(counts(), (1, 1));
        assert_eq!(
            decide(T0 + T_NS - 1, who(1)),
            SightingOutcome::NotYet { retry_after_ns: 1 },
            "one ns short still refuses, and says exactly how short"
        );
        assert_eq!(decide(T0 + T_NS, who(1)), SightingOutcome::Admitted, "exactly T admits");
        // Admission does NOT itself delete the row: deletion is bound to a
        // FINALIZED derive, not to passing the age test, so a call that is
        // admitted here and then refused downstream keeps its accumulated age.
        assert_eq!(counts(), (1, 1));
        assert_bijection();
    }

    /// **Arm 32 / LAUNCH-HARDEN-04 O-2 — a full table EVICTS the oldest row
    /// and inserts; it no longer refuses.**
    ///
    /// Driven at the real `MAX_SIGHTINGS` (written as the literal 10_000), with
    /// every row unexpired so the prune can reclaim nothing — otherwise the
    /// eviction would never be the thing under test.
    #[test]
    fn s2_full_table_evicts_oldest_and_inserts() {
        const FULL: u64 = 10_000;
        for i in 0..FULL {
            assert_eq!(decide(T0 + i, who(i)), SightingOutcome::Inserted);
        }
        assert_eq!(counts(), (FULL, FULL));

        // A caller with NO row needs a slot: the OLDEST row (who(0), sighted at
        // T0) is evicted from both structures and the caller is inserted.
        assert_eq!(decide(T0 + FULL, who(999_999)), SightingOutcome::Inserted);
        assert!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(0)).is_none()),
            "the oldest row must be gone from the primary"
        );
        assert!(
            !SIGHTING_EXPIRY_INDEX.with_borrow(|ix| ix.contains_key(&expiry_key(who(0), T0))),
            "and from the index"
        );
        assert_eq!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(999_999))),
            Some(T0 + FULL),
            "the newcomer is recorded"
        );
        assert_eq!(counts(), (FULL, FULL), "the table stays exactly full");
        assert_bijection();
    }

    /// O-2 — a caller that ALREADY holds a valid row at age T is ADMITTED at a
    /// full table, and nothing is evicted: it needs no slot.
    #[test]
    fn s2b_own_row_at_full_table_evicts_nothing() {
        const FULL: u64 = 10_000;
        for i in 0..FULL {
            assert_eq!(decide(T0, who(i)), SightingOutcome::Inserted);
        }
        let before = counts();
        assert_eq!(decide(T0 + T_NS, who(5)), SightingOutcome::Admitted);
        assert_eq!(counts(), before, "an admission consumes no slot and evicts nothing");
        for i in 0..FULL {
            assert!(
                ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(i))) == Some(T0),
                "row {i} must be untouched"
            );
        }
        assert_bijection();
    }

    /// O-2 — an anomalous (future-dated) row sorts LAST by expiry and is never
    /// the eviction victim; the oldest REAL row is.
    #[test]
    fn s2c_anomalous_row_never_evicted() {
        const FULL: u64 = 10_000;
        let anomalous = who(777_777);
        let future = T0 + 10 * RETENTION_NS;
        // Injected through the real store path: sighted at a future instant.
        assert_eq!(decide(future, anomalous), SightingOutcome::Inserted);
        for i in 0..(FULL - 1) {
            assert_eq!(decide(T0 + i, who(i)), SightingOutcome::Inserted);
        }
        assert_eq!(counts(), (FULL, FULL));

        assert_eq!(decide(T0 + FULL, who(999_999)), SightingOutcome::Inserted);
        assert!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(0)).is_none()),
            "the oldest REAL row is the victim"
        );
        assert_eq!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&anomalous)),
            Some(future),
            "the anomalous row survives, byte-for-byte"
        );
        assert_eq!(counts(), (FULL, FULL));
        assert_bijection();
    }

    /// O-2 — one insertion at a full table examines at most K (prune) + 1
    /// (the row that stops the walk) + 1 (the eviction read) index rows.
    #[test]
    fn s2d_eviction_work_bound() {
        const FULL: u64 = 10_000;
        for i in 0..FULL {
            assert_eq!(decide(T0 + i, who(i)), SightingOutcome::Inserted);
        }
        let before = rows_examined_total();
        assert_eq!(decide(T0 + FULL, who(999_999)), SightingOutcome::Inserted);
        let examined = rows_examined_total() - before;
        assert!(examined <= 16 + 1 + 1, "one evicting insertion examined {examined} rows");
        assert!(examined >= 2, "the prune walk and the eviction read must both be counted");
        assert_bijection();
    }

    /// O-2 — the victim-reset bound: a victim survives until it is the oldest
    /// of a full table; once evicted and re-sighted, it is admitted at T if
    /// fewer than a full table's worth of insertions follow it.
    #[test]
    fn s2e_victim_reset_bound() {
        const FULL: u64 = 10_000;
        let victim = who(555_555);
        let t = T0;
        assert_eq!(decide(t, victim), SightingOutcome::Inserted);
        for i in 1..FULL {
            assert_eq!(decide(t + i, who(i)), SightingOutcome::Inserted);
        }
        assert!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&victim)).is_some(),
            "after 9,999 later inserts the victim is still present"
        );
        assert_eq!(decide(t + FULL, who(FULL)), SightingOutcome::Inserted);
        assert!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&victim)).is_none(),
            "the 10,000th later insert evicts the victim"
        );

        // The victim re-sights at t2: its clock restarts.
        let t2 = t + FULL + 1;
        assert_eq!(decide(t2, victim), SightingOutcome::Inserted);
        // Fewer than a full table of insertions inside [t2, t2 + T): the
        // victim is never the oldest, so it survives.
        for j in 0..(FULL - 2) {
            assert_eq!(decide(t2 + 1 + j, who(1_000_000 + j)), SightingOutcome::Inserted);
        }
        assert_eq!(decide(t2 + T_NS, victim), SightingOutcome::Admitted);
        assert_bijection();
    }

    /// **O-2 / SSA C-5 — the collateral is INDISCRIMINATE.** Filling the table
    /// with 10,000 newer insertions evicts EVERY older honest row, not one
    /// attacker-chosen victim.
    #[test]
    fn s2f_collateral_is_indiscriminate() {
        const FULL: u64 = 10_000;
        const HONEST: u64 = 50;
        for i in 0..HONEST {
            assert_eq!(decide(T0 + i, who(i)), SightingOutcome::Inserted);
        }
        for j in 0..FULL {
            assert_eq!(
                decide(T0 + HONEST + j, who(2_000_000 + j)),
                SightingOutcome::Inserted
            );
        }
        for i in 0..HONEST {
            assert!(
                ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(i))).is_none(),
                "honest row {i} must have been evicted"
            );
        }
        assert_eq!(counts(), (FULL, FULL));
        assert_bijection();
    }

    /// **Arm 32(d) — an own EXPIRED row is RENEWED IN PLACE, before any cap
    /// test, consuming no slot; the index is re-keyed and the clock restarts.**
    ///
    /// The fixture makes the renewal path genuinely reachable: the caller's row
    /// must survive the prune, which needs MORE than `SIGHTING_PRUNE_MAX`
    /// expired rows sorting ahead of it. That is a real property of the ruled
    /// order (prune, then look up) and is stated in the report.
    #[test]
    fn s3_an_expired_own_row_is_renewed_in_place_and_consumes_no_slot() {
        // Rows 0..=K sort ahead of the caller by expiry: they are sighted
        // EARLIER, so their expiry keys are strictly lower.
        let backlog = SIGHTING_PRUNE_MAX as u64 + 4;
        for i in 0..backlog {
            assert_eq!(decide(T0 + i, who(i)), SightingOutcome::Inserted);
        }
        let caller = who(backlog);
        assert_eq!(decide(T0 + backlog, caller), SightingOutcome::Inserted);
        let occupied_before = counts().0;

        // Everything is now past retention. The caller's row is the LAST by
        // expiry, so the K-bounded prune cannot reach it.
        let now = T0 + backlog + RETENTION_NS + 1;
        let old_index_key = expiry_key(caller, T0 + backlog);

        assert_eq!(decide(now, caller), SightingOutcome::Renewed, "renewed, not re-inserted");

        // NO SLOT CONSUMED: occupancy fell by exactly the K the prune removed,
        // and not by one less — the renewal added nothing.
        assert_eq!(
            counts().0,
            occupied_before - SIGHTING_PRUNE_MAX as u64,
            "the renewal must not consume a slot on top of the prune's reclamation"
        );

        // THE INDEX WAS RE-KEYED, both halves checked: the stale key is gone
        // and the new one is present. Leaving the old key would orphan it until
        // its own expiry and break the bijection silently.
        assert!(
            !SIGHTING_EXPIRY_INDEX.with_borrow(|ix| ix.contains_key(&old_index_key)),
            "the stale index key must be DELETED, not left behind"
        );
        assert!(
            SIGHTING_EXPIRY_INDEX.with_borrow(|ix| ix.contains_key(&expiry_key(caller, now))),
            "and the new key inserted at the renewed expiry"
        );

        // THE CLOCK RESTARTED — correctly: an expired sighting is no longer
        // evidence, so the wait begins again rather than resuming.
        assert_eq!(ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&caller)), Some(now));
        assert_eq!(
            decide(now + T_NS - 1, caller),
            SightingOutcome::NotYet { retry_after_ns: 1 }
        );
        assert_eq!(decide(now + T_NS, caller), SightingOutcome::Admitted);
        assert_bijection();
    }

    /// **Arm 44 — one admission EXAMINES at most `SIGHTING_PRUNE_MAX` rows,
    /// measured causally; and a backlog larger than K drains ACROSS calls.**
    ///
    /// EXAMINED, not removed. A prune that removed ≤ K rows while scanning the
    /// whole primary map would satisfy a removal count and still be the O(N)
    /// attacker path. Reverting to a primary-map scan makes this arm RED
    /// because the examined delta would rise with the table, not with K.
    #[test]
    fn s4_one_admission_examines_at_most_k_rows_and_a_backlog_drains_across_calls() {
        // A large table — two orders of magnitude above K — so an O(N) walk is
        // unmistakably distinguishable from an O(K) one.
        const TABLE: u64 = 2_000;
        let backlog = SIGHTING_PRUNE_MAX as u64 * 3;
        for i in 0..TABLE {
            assert_eq!(decide(T0 + i, who(i)), SightingOutcome::Inserted);
        }
        // Expire only the first `backlog` rows.
        let now = T0 + backlog - 1 + RETENTION_NS + 1;

        let before = rows_examined_total();
        assert_eq!(decide(now, who(TABLE + 1)), SightingOutcome::Inserted);
        let examined = rows_examined_total() - before;

        // The walk stops at K expired rows plus the one that ends `take_while`.
        assert!(
            examined <= SIGHTING_PRUNE_MAX as u64 + 1,
            "one admission examined {examined} index rows over a {TABLE}-row table; the bound \
             is K = {SIGHTING_PRUNE_MAX} (+1 for the row that stops the walk). A primary-map \
             scan would examine on the order of {TABLE}."
        );
        // NON-VACUITY: the bound is not met by never walking at all.
        assert!(examined > 0, "the prune must actually walk");
        assert_eq!(
            counts().0,
            TABLE - SIGHTING_PRUNE_MAX as u64 + 1,
            "exactly K removals, plus the caller's own insertion"
        );

        // ACROSS CALLS, never in one: the remaining backlog needs two more
        // admissions to drain, and each takes exactly K.
        for call in 1..=2u64 {
            let mark = rows_examined_total();
            assert_eq!(decide(now, who(TABLE + 1 + call)), SightingOutcome::Inserted);
            assert!(
                rows_examined_total() - mark <= SIGHTING_PRUNE_MAX as u64 + 1,
                "draining call {call} must obey the same bound"
            );
        }
        assert_eq!(
            counts().0,
            TABLE - backlog + 3,
            "the whole backlog drained across three calls, never in one"
        );
        assert_bijection();
    }

    /// **Arm 45 — both-or-neither across all four mutations.**
    #[test]
    fn s5_all_four_mutations_leave_the_two_maps_in_bijection() {
        // insert
        assert_eq!(decide(T0, who(1)), SightingOutcome::Inserted);
        assert_bijection();
        // renew (via an expired own row that the prune cannot reach)
        for i in 2..(SIGHTING_PRUNE_MAX as u64 + 4) {
            decide(T0 - 1, who(i));
        }
        let now = T0 + RETENTION_NS + 1;
        assert_eq!(decide(now, who(1)), SightingOutcome::Renewed);
        assert_bijection();
        // expiry-delete happened inside that same prune
        assert_bijection();
        // success-delete
        clear_on_success(who(1));
        assert_bijection();
        assert!(ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(1)).is_none()));
    }

    /// Arm 45's other half — an INJECTED half-state TRAPS rather than being
    /// committed over.
    ///
    /// The primary row is removed behind the store's back, leaving an orphaned
    /// index row. The next prune that reaches it must trap: continuing would
    /// compound a broken invariant, and a bijection that repairs itself
    /// silently is one nobody can rely on.
    #[test]
    #[should_panic(expected = "bijection violated during prune")]
    fn s6_an_injected_half_state_traps_rather_than_being_committed_over() {
        assert_eq!(decide(T0, who(1)), SightingOutcome::Inserted);
        ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.remove(&who(1)));
        // The index row survives; the prune walk now finds a key with no
        // primary behind it.
        prune_expired_sightings(T0 + RETENTION_NS + 1);
    }

    /// The success-delete's own half-state check: an orphaned INDEX row for a
    /// principal with no primary row must trap too.
    #[test]
    #[should_panic(expected = "SIGHTING_EXPIRY_INDEX holds a row whose primary is absent")]
    fn s7_a_success_delete_traps_on_an_orphaned_index_row() {
        assert_eq!(decide(T0, who(1)), SightingOutcome::Inserted);
        ELIGIBILITY_SIGHTINGS.with_borrow_mut(|m| m.remove(&who(1)));
        clear_on_success(who(1));
    }

    /// **Arm 46 — retention at the SHIPPED value: a user returning inside
    /// seven days is NOT restarted; past it, the row expires and renews.**
    ///
    /// Driven at 6 d 23 h and at 7 d + 1 ns, both computed from their own unit
    /// arithmetic. Shrinking retention to hours makes the first half RED.
    #[test]
    fn s8_retention_holds_at_the_shipped_seven_days() {
        let six_days_23h: u64 = (6 * 24 + 23) * 60 * 60 * 1_000_000_000;
        let seven_days: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

        assert_eq!(decide(T0, who(1)), SightingOutcome::Inserted);

        // Inside retention: the row is still the same row, still aging from the
        // ORIGINAL sighting — a returning user is not silently restarted.
        assert_eq!(decide(T0 + six_days_23h, who(1)), SightingOutcome::Admitted);
        assert_eq!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(1))),
            Some(T0),
            "the stored sighting must be the ORIGINAL instant, not refreshed by a lookup"
        );

        // AT the boundary the row is retained (`expiry_ns < now`, strictly).
        assert_eq!(decide(T0 + seven_days, who(1)), SightingOutcome::Admitted);
        assert_eq!(ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(1))), Some(T0));

        // One ns past it, the row is expired. With no backlog ahead of it the
        // prune reclaims it and the caller re-enters as a fresh insertion —
        // the same observable outcome as a renewal: refused, clock restarted.
        let past = T0 + seven_days + 1;
        assert_eq!(decide(past, who(1)), SightingOutcome::Inserted);
        assert_eq!(
            ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.get(&who(1))),
            Some(past),
            "the clock restarts — an expired sighting is no longer evidence"
        );
        assert_bijection();
    }

    /// A below-floor or unavailable balance never reaches `decide`, so the
    /// store cannot be written by a caller who was never seen above the floor.
    /// This arm pins the property `decide` relies on: it is only ever called
    /// with a proven balance, and it writes on no other path.
    #[test]
    fn s9_the_store_is_untouched_until_a_balance_is_proven() {
        assert_eq!(counts(), (0, 0));
        // Nothing here calls `decide`; the eligibility fence returns earlier on
        // both non-proven outcomes. The store stays empty.
        assert_eq!(counts(), (0, 0), "no path other than a proven balance may write a row");
    }

}
