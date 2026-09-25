// =============================================================================
// W-VETKEYS — THE §H′ ADMISSION MACHINE (brief V4)
// =============================================================================
//
// Phase-tagged, stable, pre-await. The principle the brief adopts, restated
// because every function here is an application of it:
//
//   TIME ALONE IS NEVER EVIDENCE A CALL CANNOT RESUME. Only state that a live
//   path revalidates, or a charge that can only OVER-count, may free or fill
//   capacity.
//
// So: a `PreDispatch` reservation may be TTL-pruned — safely, because a call
// that resumes past the prune must find its own id still in that phase before
// it may dispatch, and dies if it cannot (`revalidate_for_dispatch`). A
// `Dispatched` reservation may NEVER be pruned to free capacity, because no
// citable platform deadline makes a management callback impossible; at the
// window edge it is CHARGED instead (`stale_charge`), which is capacity-neutral
// at the moment of conversion.
//
// PURITY. Every decision here is a pure function over `(now_ns, &mut
// AdmissionState)` — the `validate_retained_config` / `meter_admit` idiom this
// crate already uses. The endpoint is the impure shell that reads the stable
// map, applies one of these, and writes it back inside the SAME synchronous
// message step. That is what makes the ordering claims testable without
// PocketIC, and what keeps the PocketIC arms free to prove the CAUSAL half
// (management-dispatch counts) rather than re-deriving the arithmetic.
//
// ORDERING (CTO_ADJUDICATION_W_VETKEYS_COMMIT1_HALT_2026-08-27, item A):
// the A-2 meter pre-filter runs FIRST in the endpoint, then `admit`. A meter
// refusal therefore never reaches this module and never writes a reservation.
// `remaining` and `retry_after` are reported from HERE only.

use crate::pins::{
    DERIVE_QUOTA, DERIVE_WINDOW_NS, STALE_DISPATCHED_CHARGE_NS, STALE_PREDISPATCH_TTL_NS,
};
use crate::state::{AdmissionState, Reservation, ReservationPhase};

/// Why admission refused. One variant: the quota. Everything else that can
/// refuse a derive (anonymous, meter, eligibility, transport key) refuses
/// OUTSIDE this module and never touches admission state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRejection {
    /// `retry_after_ns` is the EXACT time until a slot frees, computed
    /// conservatively across both lists. Exactness is tested from both sides:
    /// admitted at `now + retry_after_ns`, refused at one ns less.
    QuotaExceeded { retry_after_ns: u64 },
}

/// A granted admission. The id is what every later step is keyed on — an id
/// absent from the reservation list makes every finalization path a no-op,
/// which is what makes a late callback side-effect-free by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub reservation_id: u64,
    /// Derives left in this principal's rolling window AFTER this admission.
    /// Reported to the wallet, which warns at `<= QUOTA_WARN_REMAINING`.
    pub remaining: u8,
}

/// Why a call may not proceed to the management canister after its await.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLapsed;

/// Prune `committed` timestamps that have aged out of the rolling window.
///
/// Boundary convention, matching the existing A-2 meter: an entry frees at
/// EXACTLY `t + DERIVE_WINDOW_NS` (`>=`, not `>`).
fn prune_committed(now_ns: u64, state: &mut AdmissionState) {
    state
        .committed
        .retain(|t| now_ns.saturating_sub(*t) < DERIVE_WINDOW_NS);
}

/// Prune `PreDispatch` reservations older than the TTL — and ONLY those.
///
/// Safe per §H′.3(a): a call still alive past this prune fails
/// `revalidate_for_dispatch` and aborts BEFORE any management dispatch, so the
/// freed slot can only ever be reused by a path that can no longer spend cycles.
fn prune_stale_predispatch(now_ns: u64, state: &mut AdmissionState) {
    state.reservations.retain(|r| {
        r.phase != ReservationPhase::PreDispatch
            || now_ns.saturating_sub(r.created_at_ns) < STALE_PREDISPATCH_TTL_NS
    });
}

/// Convert `Dispatched` reservations at or past the charge age into COMMITTED
/// timestamps AT THEIR OWN `created_at` (§H′.3(c)).
///
/// Not a prune: the slot is not freed, it is CHARGED. It ages out of the window
/// honestly from the moment the call was actually dispatched, and because the
/// committed prune has already run for this pass, the conversion is exactly
/// capacity-neutral at the instant it happens. Its id being absent afterwards
/// is what routes a truly-late callback to the discard path — idempotent by
/// construction, no tombstone required.
fn stale_charge_dispatched(now_ns: u64, state: &mut AdmissionState) {
    let mut charged: Vec<u64> = Vec::new();
    state.reservations.retain(|r| {
        let stale = r.phase == ReservationPhase::Dispatched
            && now_ns.saturating_sub(r.created_at_ns) >= STALE_DISPATCHED_CHARGE_NS;
        if stale {
            charged.push(r.created_at_ns);
        }
        !stale
    });
    state.committed.extend(charged);
}

/// The absolute time at which capacity NEXT frees, over both lists.
///
/// Each source's free time is written from that source's own rule, not
/// inferred:
///
/// * a committed `t` frees at `t + DERIVE_WINDOW_NS` (prune boundary);
/// * a `PreDispatch` frees at `created_at + STALE_PREDISPATCH_TTL_NS`;
/// * a `Dispatched` frees at `created_at + STALE_DISPATCHED_CHARGE_NS + 1`.
///   The `+ 1` is not a fudge: at exactly the charge age the reservation
///   becomes a committed entry and the sum is UNCHANGED (that is the point of
///   capacity-neutrality), so the slot genuinely does not free until the next
///   admission pass, one ns later, when the committed prune reaches it.
fn next_free_ns(state: &AdmissionState) -> Option<u64> {
    let committed = state.committed.iter().map(|t| t.saturating_add(DERIVE_WINDOW_NS));
    let reservations = state.reservations.iter().map(|r| match r.phase {
        ReservationPhase::PreDispatch => r.created_at_ns.saturating_add(STALE_PREDISPATCH_TTL_NS),
        ReservationPhase::Dispatched => r
            .created_at_ns
            .saturating_add(STALE_DISPATCHED_CHARGE_NS)
            .saturating_add(1),
    });
    committed.chain(reservations).min()
}

/// §H′.2(1) — ADMISSION. The first thing the endpoint does after the anonymous
/// check and the A-2 meter pre-filter, BEFORE any await, in one atomic step.
///
/// The reservation IS the check's side effect, so the check-then-await gap
/// does not exist: overlapping same-principal calls each run this step in
/// message order and the sum bound makes over-admission unrepresentable.
pub fn admit(now_ns: u64, state: &mut AdmissionState) -> Result<Admitted, AdmissionRejection> {
    prune_committed(now_ns, state);
    prune_stale_predispatch(now_ns, state);
    stale_charge_dispatched(now_ns, state);

    // Conservative over BOTH lists: a `Dispatched` reservation is treated as a
    // FULL charge even though its callback has not landed.
    let used = state.committed.len().saturating_add(state.reservations.len());
    if used >= DERIVE_QUOTA as usize {
        let retry_after_ns = next_free_ns(state)
            .map(|free| free.saturating_sub(now_ns))
            .unwrap_or(0);
        return Err(AdmissionRejection::QuotaExceeded { retry_after_ns });
    }

    let reservation_id = state.next_reservation_id;
    // Monotonic and NEVER reset: a reused id would let a late callback finalize
    // a different call's reservation.
    state.next_reservation_id = state.next_reservation_id.saturating_add(1);
    state.reservations.push(Reservation {
        id: reservation_id,
        created_at_ns: now_ns,
        phase: ReservationPhase::PreDispatch,
    });

    let used_after = state.committed.len().saturating_add(state.reservations.len());
    let remaining = (DERIVE_QUOTA as usize).saturating_sub(used_after) as u8;
    Ok(Admitted { reservation_id, remaining })
}

/// §H′.2(2) — RESUMPTION from the eligibility await, and the ONLY path to a
/// management dispatch.
///
/// Requires this call's exact id to still exist in phase `PreDispatch`, and
/// flips it to `Dispatched` in the SAME synchronous step that precedes the
/// management call. Absent (TTL-pruned while the call was parked) → `Err`, and
/// the caller must abort with a typed lapse WITHOUT dispatching: nothing was
/// spent, nothing is charged.
///
/// Non-first derives skip eligibility and therefore have no await between
/// admission and dispatch — they still call this, in the same message, so
/// there is exactly ONE way for a reservation to become `Dispatched`.
pub fn revalidate_for_dispatch(
    state: &mut AdmissionState,
    reservation_id: u64,
) -> Result<(), AdmissionLapsed> {
    match state
        .reservations
        .iter_mut()
        .find(|r| r.id == reservation_id && r.phase == ReservationPhase::PreDispatch)
    {
        Some(r) => {
            r.phase = ReservationPhase::Dispatched;
            Ok(())
        }
        // Either pruned as stale, or already `Dispatched` — a second dispatch
        // on one reservation is refused just as hard as a lapsed one.
        None => Err(AdmissionLapsed),
    }
}

/// Whether the id is still live. The production callback path asks this
/// question through `finalize`'s return value (one lookup, one decision), so
/// this is the TEST-facing spelling of the same predicate — kept because the
/// stale-charge arms need to observe the absence WITHOUT consuming it.
#[cfg(test)]
pub fn is_live(state: &AdmissionState, reservation_id: u64) -> bool {
    state.reservations.iter().any(|r| r.id == reservation_id)
}

/// §H′.2(3)/(4) — FINALIZE. Removes the reservation and records a committed
/// timestamp.
///
/// One function for BOTH callback outcomes, deliberately: success and
/// post-dispatch failure are accounted identically because cycles were spent
/// either way, and a failure that restored capacity would be a free retry.
/// The commit is stamped at `now_ns` (when the call resolved), not at the
/// reservation's `created_at` — that is the stale-charge path's rule, and
/// conflating the two would let a normal derive age out early.
///
/// Returns `false` if the id is ABSENT (already stale-charged). The caller MUST
/// then discard the result: no key returned, no ticket minted, no established
/// bit written. A late callback can never produce an uncounted key.
#[must_use]
pub fn finalize(now_ns: u64, state: &mut AdmissionState, reservation_id: u64) -> bool {
    let before = state.reservations.len();
    state.reservations.retain(|r| r.id != reservation_id);
    if state.reservations.len() == before {
        return false;
    }
    state.committed.push(now_ns);
    true
}

/// §H′.3 / V3 §H.3 — RELEASE, the pre-dispatch failure path.
///
/// Eligibility rejection, eligibility-query unavailability, or an invalid
/// transport key: no management cycles were spent, so the slot is returned.
/// Refuses to release anything already `Dispatched` — that is what stops this
/// from becoming the refund API the A-2 lane structurally forbids.
#[must_use]
pub fn release(state: &mut AdmissionState, reservation_id: u64) -> bool {
    let before = state.reservations.len();
    state
        .reservations
        .retain(|r| !(r.id == reservation_id && r.phase == ReservationPhase::PreDispatch));
    state.reservations.len() != before
}


// ═════════════════════════════════════════════════════════════════════════════
// PREFLIGHT — the whole pre-await admission sequence, as ONE pure decision
// ═════════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS AS A FUNCTION. The CTO adjudication (7cd63a14…, item A)
// requires that a METER refusal occur BEFORE any §H′ reservation is written,
// and the SSA checkpoint requires proof that such a refusal leaves §H′ state
// unmoved. That property is NOT observable through the canister's public
// surface: a stray `PreDispatch` reservation is visible for at most
// `STALE_PREDISPATCH_TTL_NS` (5 min), which lies strictly INSIDE the meter's
// one-hour refusal window for the same principal — by the time the caller can
// call again, a stray would have pruned itself. An endpoint-level arm can
// therefore only show the typed variant, never the absence of the write.
//
// So the ordering is expressed as a pure function over BOTH states, and the
// absence of the write is asserted directly on the state's own bytes
// (`meter_refusal_leaves_admission_state_byte_identical`). The endpoint is the
// impure shell that applies it. Swapping the two limbs REDs that arm, which is
// the mutation proof the ordering is load-bearing.

/// Why the pre-await sequence refused. The two rate limits stay DISTINCT all
/// the way out to the caller (adjudication item A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightRejection {
    /// The A-2 per-hour meter refused — FIRST, and before any §H′ write.
    Meter(crate::MeterRejection),
    /// The ruled §H′ rolling-24 h quota refused.
    Quota { retry_after_ns: u64 },
}

/// Meter pre-filter, THEN §H′ admission. Both synchronous, both pre-await.
///
/// The `?` on the meter limb is the ordering: on a meter refusal this returns
/// before `admit` is reachable, so no reservation is written, no id is
/// consumed, and no §H′ capacity is taken or leaked.
pub fn preflight(
    now_ns: u64,
    caller: candid::Principal,
    meter: &mut crate::MeterState,
    state: &mut AdmissionState,
) -> Result<Admitted, PreflightRejection> {
    crate::meter_admit(now_ns, caller, meter).map_err(PreflightRejection::Meter)?;
    admit(now_ns, state).map_err(|e| match e {
        AdmissionRejection::QuotaExceeded { retry_after_ns } => {
            PreflightRejection::Quota { retry_after_ns }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600_000_000_000;

    fn admit_ok(now: u64, st: &mut AdmissionState) -> u64 {
        admit(now, st).expect("expected admission").reservation_id
    }

    /// Drive a reservation all the way to `Dispatched`, the way the endpoint
    /// does — never by writing the phase directly, so the tests exercise the
    /// same single transition the production path uses.
    fn dispatch(now: u64, st: &mut AdmissionState) -> u64 {
        let id = admit_ok(now, st);
        revalidate_for_dispatch(st, id).expect("fresh reservation must revalidate");
        id
    }

    #[test]
    fn admits_exactly_the_quota_then_refuses() {
        let mut st = AdmissionState::default();
        for i in 0..DERIVE_QUOTA {
            let a = admit(1_000, &mut st).unwrap_or_else(|e| panic!("call {i} refused: {e:?}"));
            // `remaining` counts down to zero across the quota. Regenerated
            // here from the loop index, not read back from the machine.
            assert_eq!(a.remaining as u32, DERIVE_QUOTA - i - 1);
        }
        assert!(matches!(
            admit(1_000, &mut st),
            Err(AdmissionRejection::QuotaExceeded { .. })
        ));
        assert_eq!(st.reservations.len(), DERIVE_QUOTA as usize);
    }

    /// The sum bound is over BOTH lists: a mix of committed and reservations
    /// refuses at the same total. Proves `Dispatched` counts as a full charge.
    #[test]
    fn the_bound_is_the_sum_of_committed_and_reservations() {
        let mut st = AdmissionState::default();
        // Three finalized derives…
        for _ in 0..3 {
            let id = dispatch(1_000, &mut st);
            assert!(finalize(1_000, &mut st, id));
        }
        // …plus two still in flight, one in each phase.
        let _pre = admit_ok(1_000, &mut st);
        let _disp = dispatch(1_000, &mut st);
        assert_eq!(st.committed.len() + st.reservations.len(), DERIVE_QUOTA as usize);
        assert!(matches!(
            admit(1_000, &mut st),
            Err(AdmissionRejection::QuotaExceeded { .. })
        ));
    }

    /// `retry_after_ns` is EXACT, from both sides — the V3 §H.5 boundary arm.
    /// Committed source: refused one ns early, admitted at the returned instant.
    #[test]
    fn retry_after_is_exact_for_a_committed_slot() {
        let mut st = AdmissionState::default();
        let t0 = 5_000_000_000u64;
        for _ in 0..DERIVE_QUOTA {
            let id = dispatch(t0, &mut st);
            assert!(finalize(t0, &mut st, id));
        }
        let now = t0 + HOUR;
        let retry = match admit(now, &mut st) {
            Err(AdmissionRejection::QuotaExceeded { retry_after_ns }) => retry_after_ns,
            other => panic!("expected refusal, got {other:?}"),
        };
        // Regenerated independently: the oldest commit frees one full window
        // after it was made.
        assert_eq!(retry, (t0 + DERIVE_WINDOW_NS) - now);
        assert!(
            admit(now + retry - 1, &mut st).is_err(),
            "one ns early must still refuse — otherwise retry_after is not the boundary"
        );
        assert!(admit(now + retry, &mut st).is_ok(), "admitted exactly at retry_after");
    }

    /// Same exactness for a `PreDispatch` slot: it frees at its TTL.
    #[test]
    fn retry_after_is_exact_for_a_predispatch_slot() {
        let mut st = AdmissionState::default();
        let t0 = 9_000_000_000u64;
        for _ in 0..DERIVE_QUOTA {
            let _ = admit_ok(t0, &mut st);
        }
        let retry = match admit(t0, &mut st) {
            Err(AdmissionRejection::QuotaExceeded { retry_after_ns }) => retry_after_ns,
            other => panic!("expected refusal, got {other:?}"),
        };
        assert_eq!(retry, STALE_PREDISPATCH_TTL_NS);
        assert!(admit(t0 + retry - 1, &mut st).is_err());
        assert!(admit(t0 + retry, &mut st).is_ok());
    }

    /// And for a `Dispatched` slot — including the `+ 1`, which exists because
    /// the charge conversion is capacity-NEUTRAL at the instant it happens.
    #[test]
    fn retry_after_is_exact_for_a_dispatched_slot_including_the_neutral_conversion() {
        let mut st = AdmissionState::default();
        let t0 = 11_000_000_000u64;
        for _ in 0..DERIVE_QUOTA {
            let _ = dispatch(t0, &mut st);
        }
        let retry = match admit(t0, &mut st) {
            Err(AdmissionRejection::QuotaExceeded { retry_after_ns }) => retry_after_ns,
            other => panic!("expected refusal, got {other:?}"),
        };
        assert_eq!(retry, STALE_DISPATCHED_CHARGE_NS + 1);

        // AT the charge age: converted, but the sum is unchanged, so still
        // refused. This is the capacity-neutrality claim, tested directly.
        let at_charge = t0 + STALE_DISPATCHED_CHARGE_NS;
        let mut probe = st.clone();
        assert!(admit(at_charge, &mut probe).is_err(), "conversion must not free capacity");
        assert!(probe.reservations.is_empty(), "the reservations were charged…");
        assert_eq!(probe.committed.len(), DERIVE_QUOTA as usize, "…into committed, one for one");
        assert!(
            probe.committed.iter().all(|t| *t == t0),
            "a charge is stamped at the reservation's OWN created_at, so it ages honestly"
        );

        assert!(admit(at_charge, &mut st).is_err());
        assert!(admit(t0 + retry, &mut st).is_ok(), "freed one pass later, exactly as reported");
    }

    /// §H′.3(a) — a TTL-pruned `PreDispatch` frees a slot, and the call that
    /// owned it can no longer dispatch. Both halves in one arm: the freeing is
    /// only safe BECAUSE of the revalidation, so testing them apart would prove
    /// half a property.
    #[test]
    fn a_pruned_predispatch_frees_capacity_but_kills_its_own_call() {
        let mut st = AdmissionState::default();
        let t0 = 2_000_000_000u64;
        let parked = admit_ok(t0, &mut st);
        for _ in 1..DERIVE_QUOTA {
            let _ = admit_ok(t0, &mut st);
        }
        assert!(admit(t0, &mut st).is_err(), "quota is full");

        let after_ttl = t0 + STALE_PREDISPATCH_TTL_NS;
        assert!(admit(after_ttl, &mut st).is_ok(), "the stale pre-dispatch slot frees");
        assert_eq!(
            revalidate_for_dispatch(&mut st, parked),
            Err(AdmissionLapsed),
            "the parked call must die at revalidation rather than dispatch"
        );
    }

    /// §H′.3(b) — a `Dispatched` reservation is NEVER TTL-pruned. Time alone
    /// does not free it: at a thousand TTLs it still holds its slot.
    #[test]
    fn a_dispatched_reservation_is_never_ttl_pruned() {
        let mut st = AdmissionState::default();
        let t0 = 3_000_000_000u64;
        for _ in 0..DERIVE_QUOTA {
            let _ = dispatch(t0, &mut st);
        }
        // 200 TTLs ≈ 16.7 h — far past the pre-dispatch TTL, still strictly
        // inside the 24 h charge age, which the next assertion pins.
        let long_after_ttl = t0 + STALE_PREDISPATCH_TTL_NS * 200;
        assert!(
            long_after_ttl < t0 + STALE_DISPATCHED_CHARGE_NS,
            "this arm must stay strictly inside the charge age, or it proves nothing"
        );
        assert!(
            admit(long_after_ttl, &mut st).is_err(),
            "a Dispatched slot must still be occupied far past the PreDispatch TTL"
        );
        assert_eq!(st.reservations.len(), DERIVE_QUOTA as usize);
    }

    /// §H′.2(2) — exactly one transition to `Dispatched`. A second attempt on
    /// the same id is refused, so one admission can never yield two dispatches.
    #[test]
    fn a_reservation_can_be_dispatched_only_once() {
        let mut st = AdmissionState::default();
        let id = admit_ok(1_000, &mut st);
        assert_eq!(revalidate_for_dispatch(&mut st, id), Ok(()));
        assert_eq!(revalidate_for_dispatch(&mut st, id), Err(AdmissionLapsed));
    }

    #[test]
    fn an_unknown_reservation_id_can_never_dispatch() {
        let mut st = AdmissionState::default();
        let _ = admit_ok(1_000, &mut st);
        assert_eq!(revalidate_for_dispatch(&mut st, 4_242), Err(AdmissionLapsed));
    }

    /// §H′.2(3) — the late-callback discard path. A stale-charged id must make
    /// `finalize` a no-op, and must not add a SECOND committed entry: the
    /// charge already counted this derive.
    #[test]
    fn finalizing_a_stale_charged_id_is_a_side_effect_free_no_op() {
        let mut st = AdmissionState::default();
        let t0 = 4_000_000_000u64;
        let id = dispatch(t0, &mut st);
        let at_charge = t0 + STALE_DISPATCHED_CHARGE_NS;
        let _ = admit(at_charge, &mut st); // an admission pass performs the charge
        assert!(!is_live(&st, id), "the id must be gone after the stale charge");

        let committed_before = st.committed.clone();
        let reservations_before = st.reservations.clone();
        assert!(
            !finalize(at_charge + 1, &mut st, id),
            "a late callback must be told its reservation is absent"
        );
        assert_eq!(st.committed, committed_before, "no second charge for one derive");
        assert_eq!(st.reservations, reservations_before, "no other state moved either");
    }

    /// Post-dispatch failure does NOT restore capacity — `finalize` is the one
    /// accounting rule for both callback outcomes.
    #[test]
    fn a_post_dispatch_failure_commits_just_like_a_success() {
        let mut st = AdmissionState::default();
        for _ in 0..DERIVE_QUOTA {
            let id = dispatch(1_000, &mut st);
            // The endpoint calls the SAME function on the rejection arm.
            assert!(finalize(1_000, &mut st, id));
        }
        assert_eq!(st.committed.len(), DERIVE_QUOTA as usize);
        assert!(st.reservations.is_empty());
        assert!(
            matches!(admit(1_000, &mut st), Err(AdmissionRejection::QuotaExceeded { .. })),
            "five dispatched-then-failed derives must exhaust the window, not refund it"
        );
    }

    /// A pre-dispatch failure (ineligible / query unavailable / bad transport
    /// key) DOES restore capacity: no cycles were spent.
    #[test]
    fn release_restores_capacity_before_dispatch() {
        let mut st = AdmissionState::default();
        for _ in 1..DERIVE_QUOTA {
            let _ = admit_ok(1_000, &mut st);
        }
        let last = admit_ok(1_000, &mut st);
        assert!(admit(1_000, &mut st).is_err(), "full");
        assert!(release(&mut st, last));
        let follow_up = admit(1_000, &mut st);
        assert!(follow_up.is_ok(), "a released slot must be immediately reusable");
        assert_eq!(follow_up.unwrap().remaining, 0);
    }

    /// `release` is NOT a refund API: it refuses a dispatched reservation.
    /// This is the structural half of "post-dispatch failure never restores
    /// capacity" — the release path cannot express it even if called.
    #[test]
    fn release_refuses_a_dispatched_reservation() {
        let mut st = AdmissionState::default();
        let id = dispatch(1_000, &mut st);
        assert!(!release(&mut st, id), "a dispatched slot must not be releasable");
        assert!(is_live(&st, id));
        assert!(!release(&mut st, 999), "an unknown id releases nothing");
    }

    /// The window SLIDES: five derives at t, then one at t+window is admitted,
    /// and the machine holds at the bound rather than accumulating.
    #[test]
    fn the_window_slides() {
        let mut st = AdmissionState::default();
        let t0 = 6_000_000_000u64;
        for _ in 0..DERIVE_QUOTA {
            let id = dispatch(t0, &mut st);
            assert!(finalize(t0, &mut st, id));
        }
        assert!(admit(t0 + DERIVE_WINDOW_NS - 1, &mut st).is_err(), "one ns early");
        let a = admit(t0 + DERIVE_WINDOW_NS, &mut st).expect("the window has slid");
        // All five were committed at the SAME instant, so they age out
        // together: the full allowance is back, minus the one just admitted.
        assert_eq!(a.remaining as u32, DERIVE_QUOTA - 1);
        assert!(st.committed.is_empty(), "all five aged out together");
    }

    /// §H′.1 — the transient overshoot is real and is SAFE: `committed` may
    /// exceed the quota after a stale charge, and capacity math uses the true
    /// sum, so over-counting only ever TIGHTENS admission.
    #[test]
    fn a_transient_committed_overshoot_only_tightens_admission() {
        let mut st = AdmissionState::default();
        let t0 = 8_000_000_000u64;
        // Five dispatched calls that never call back…
        for _ in 0..DERIVE_QUOTA {
            let _ = dispatch(t0, &mut st);
        }
        // …then, just under the charge age, five MORE cannot be admitted.
        assert!(admit(t0 + STALE_DISPATCHED_CHARGE_NS - 1, &mut st).is_err());

        // At the charge age the five convert; the sum is unchanged.
        let at_charge = t0 + STALE_DISPATCHED_CHARGE_NS;
        assert!(admit(at_charge, &mut st).is_err());
        assert_eq!(st.committed.len(), DERIVE_QUOTA as usize);
        assert!(
            st.committed.len() <= crate::state::MAX_WINDOW_ENTRIES,
            "the overshoot must stay inside the stable storage bound"
        );
    }

    /// Ids are monotonic across the whole life of the state, including after a
    /// full drain. A reused id would let a late callback finalize a LIVE
    /// reservation belonging to a different call.
    #[test]
    fn reservation_ids_are_never_reused() {
        let mut st = AdmissionState::default();
        let mut seen = Vec::new();
        for round in 0..3 {
            let t = 1_000 + round * DERIVE_WINDOW_NS;
            for _ in 0..DERIVE_QUOTA {
                let id = dispatch(t, &mut st);
                assert!(finalize(t, &mut st, id));
                assert!(!seen.contains(&id), "id {id} was reused");
                seen.push(id);
            }
        }
        assert_eq!(seen.len(), (DERIVE_QUOTA * 3) as usize);
    }


    // ── PREFLIGHT ORDERING (CTO adjudication item A) ─────────────────────────

    fn principal(n: u8) -> candid::Principal {
        let mut b = [0u8; 29];
        b[0] = n;
        candid::Principal::from_slice(&b)
    }

    /// THE ORDERING ARM. Exhaust the METER while leaving §H′ capacity free
    /// (the §D first-derive-eligibility failure — `PrincipalNotEligible`, at
    /// `get_encrypted_vetkey`'s STEP 3b — charges the meter and then releases
    /// §H′, so it is the production-reachable way to get here; the
    /// invalid-transport-key branch is NOT, since R-5/L04-01 moved that check
    /// ahead of `METER`/`with_admission` entirely), then prove the refusal is
    /// the METER's AND that `AdmissionState` is byte-identical across it.
    ///
    /// Byte-identical, not "equal": the state is what gets written back to
    /// stable memory, so its ENCODING is the thing that must not move — a
    /// bumped `next_reservation_id` would be invisible to a field-by-field
    /// eyeball and visible here.
    #[test]
    fn meter_refusal_leaves_admission_state_byte_identical() {
        use ic_stable_structures::Storable;
        let mut meter = crate::MeterState::default();
        let mut st = AdmissionState::default();
        let caller = principal(0xC1);
        let now = 1_000_000_000u64;

        // Spend the meter's whole hourly budget WITHOUT committing §H′ derives:
        // each call is admitted then released, exactly as the endpoint's §D
        // first-derive-eligibility failure branch does (R-5/L04-01: the
        // invalid-transport-key branch no longer reaches this state at all).
        for _ in 0..crate::MAX_DERIVATIONS_PER_WINDOW {
            let a = preflight(now, caller, &mut meter, &mut st).expect("meter budget available");
            assert!(release(&mut st, a.reservation_id));
        }
        assert!(st.reservations.is_empty(), "no §H′ capacity is held at this point");
        assert!(st.committed.is_empty(), "and none was committed either");

        let before = st.to_bytes().into_owned();
        let rejection = preflight(now, caller, &mut meter, &mut st)
            .expect_err("the meter must refuse the sixth call within the hour");
        assert!(
            matches!(rejection, PreflightRejection::Meter(_)),
            "the METER must be the mechanism that refuses here, not §H′ — §H′ still has its \
             full allowance. Got {rejection:?}"
        );
        assert_eq!(
            st.to_bytes().into_owned(),
            before,
            "a meter refusal must not write, bump or leak ANY §H′ state"
        );
    }

    /// The converse, so the arm above is not vacuous: with the meter neutralized
    /// (time advanced past its hour), the same principal IS admitted by §H′ —
    /// and once §H′ is full, the refusal comes from §H′ with its own variant.
    #[test]
    fn past_the_meter_hour_the_quota_is_the_mechanism_that_refuses() {
        let mut meter = crate::MeterState::default();
        let mut st = AdmissionState::default();
        let caller = principal(0xC2);
        let mut now = 1_000_000_000u64;

        // Five real derives, each in its own meter hour so the meter never
        // refuses — this is the "advance PocketIC time past the meter hour"
        // discipline the adjudication requires, in its unit-level form.
        for _ in 0..DERIVE_QUOTA {
            let a = preflight(now, caller, &mut meter, &mut st).expect("meter is never the limit");
            revalidate_for_dispatch(&mut st, a.reservation_id).expect("fresh reservation");
            assert!(finalize(now, &mut st, a.reservation_id));
            now += HOUR + 1;
        }
        // Still inside the §H′ 24 h window (5 hours of steps).
        assert!(now < 1_000_000_000 + DERIVE_WINDOW_NS);
        match preflight(now, caller, &mut meter, &mut st) {
            Err(PreflightRejection::Quota { retry_after_ns }) => {
                assert!(retry_after_ns > 0, "§H′ must say when a slot frees");
            }
            other => panic!("expected the §H′ quota to refuse, got {other:?}"),
        }
    }

    /// The whole machine is per-principal: these are separate `AdmissionState`
    /// values, so one principal's exhaustion cannot touch another's. Asserted
    /// rather than assumed, because the map keying is what carries it.
    #[test]
    fn states_are_independent_per_principal() {
        let mut a = AdmissionState::default();
        let mut b = AdmissionState::default();
        for _ in 0..DERIVE_QUOTA {
            let _ = admit_ok(1_000, &mut a);
        }
        assert!(admit(1_000, &mut a).is_err());
        assert!(admit(1_000, &mut b).is_ok(), "B is unaffected by A's exhaustion");
    }
}
