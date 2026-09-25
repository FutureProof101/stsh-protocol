// =============================================================================
// C-26 remedy — THE DISPATCH FENCE (A1 fix brief V3 §2, §4)
// =============================================================================
//
// One fence, all-or-nothing (§2.1): there is an await between admission and
// dispatch (the §D eligibility query), so any balance read before it is stale
// by dispatch time; building the management future does not dispatch, awaiting
// it does; and `release` only removes a `PreDispatch` reservation, so a fence
// that flipped the phase and then refused would have consumed §H′ capacity for
// a derive that never dispatched. Therefore: CHECK all three limbs, then
// COMMIT all three, in one synchronous block with no await inside it.
//
// THE SPLIT (§2.2, RED-5): `fence_decide` below is PURE — no system calls,
// fully deterministic, natively testable, MUTATES NOTHING. The impure wrapper
// (`dispatch_fence` in lib.rs) reads the liquid balance and the live price AT
// ITS OWN CALL SITE and takes neither as a parameter, so a stale value is not
// expressible at the call site; reintroducing one requires editing the wrapper
// body, which is visible in diff review. That is a structural guarantee, not a
// behavioural proof — the same claim, in the same terms, the crate already
// makes for `MeterState`'s missing refund API. The behavioural proof is the
// §6.2 causal harness in the tests below (arms 15/15a/15b).

use crate::pins::{
    DERIVE_CYCLE_FLOOR_CYCLES, GLOBAL_DERIVE_BUDGET, GLOBAL_DERIVE_WINDOW_NS,
    PER_PRINCIPAL_HOURLY_DERIVE_CAP,
};
use crate::state::{AdmissionState, DispatchRecord, GlobalDeriveWindow, PrincipalKey, ReservationPhase};
use crate::VetkeysError;

/// The pure fence verdict. `Commit` authorizes the caller to flip the phase
/// AND record one dispatch timestamp — both, in the same synchronous step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceDecision {
    Commit,
    Refuse(VetkeysError),
}

// ─────────────────────────────────────────────────────────────────────────────
// R1 — the cycle floor (brief V3 §3)
// ─────────────────────────────────────────────────────────────────────────────

/// The floor predicate: the liquid balance (already net of the freezing
/// reserve) must cover the LIVE derive price plus the pinned floor.
/// `saturating_add` is pinned (§6.1 arm 3): an absurd price must refuse, never
/// overflow into an admit.
pub fn cycle_floor_admits(liquid: u128, live_cost: u128) -> bool {
    liquid >= live_cost.saturating_add(DERIVE_CYCLE_FLOOR_CYCLES)
}

/// The WEAKER predicate: does the liquid balance meet the PINNED FLOOR ALONE?
///
/// This is deliberately NOT the admission verdict, and the difference is the
/// whole reason it is a separate function. `cycle_floor_admits` answers "may a
/// derive proceed", which needs the live price. THIS answers "is the canister
/// above its reserve floor at all", which does not — so it stays answerable on
/// the one path where the price query fails.
///
/// Inclusive at the floor (`>=`): equality MEETS the floor, matching
/// `cycle_floor_admits`'s own boundary so the two cannot disagree at the edge.
///
/// A SHARED PREDICATE, not a comparison copied into the query: a second copy
/// could drift from this one, and the observability surface reporting a
/// different floor position from the one the fence would compute is exactly the
/// failure a monitor cannot detect.
pub fn meets_pinned_floor(liquid: u128) -> bool {
    liquid >= DERIVE_CYCLE_FLOOR_CYCLES
}

/// Fail-closed price resolution (§1: a cost-query `Err` REFUSES — never skips,
/// unwraps, or defaults to zero). When the price is unknown the refusal's
/// `required_cycles` carries the floor alone — an honest LOWER bound on what
/// would be required, stated so the wallet still gets a number, not a guess at
/// a price nobody has.
pub fn resolve_live_cost(
    liquid: u128,
    cost: Result<u128, String>,
) -> Result<u128, VetkeysError> {
    cost.map_err(|_| VetkeysError::CycleFloorReached {
        liquid_cycles: liquid,
        required_cycles: DERIVE_CYCLE_FLOOR_CYCLES,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// R2 — the global rolling window (brief V3 §4)
// ─────────────────────────────────────────────────────────────────────────────

/// §4.2, pinned exactly: a recorded timestamp `ts` is EXPIRED at `now` iff
/// `now.saturating_sub(ts) >= GLOBAL_DERIVE_WINDOW_NS` — `>=`, matching
/// `meter_admit`'s boundary, and saturating so `now < window` underflows to
/// "nothing has expired" rather than to a panic.
fn expired(now_ns: u64, ts: u64) -> bool {
    now_ns.saturating_sub(ts) >= GLOBAL_DERIVE_WINDOW_NS
}

/// Prune expired entries — the `prune_committed` pattern. True rolling, not a
/// reset bucket: a reset window would admit 2 × budget across its boundary
/// (§4.1), which defeats the remedy.
pub fn prune_window(now_ns: u64, win: &mut GlobalDeriveWindow) {
    win.dispatched.retain(|r| !expired(now_ns, r.at_ns));
}

/// Retained (unexpired) count WITHOUT mutating — the read `fence_decide` uses.
fn retained_count(now_ns: u64, win: &GlobalDeriveWindow) -> usize {
    win.dispatched.iter().filter(|r| !expired(now_ns, r.at_ns)).count()
}

/// §4.2: `retry_after_ns = (oldest_retained_ts + WINDOW).saturating_sub(now)`,
/// and `0` when the budget admits. Exact from both sides (§6.1 arm 7).
pub fn global_retry_after_ns(now_ns: u64, win: &GlobalDeriveWindow) -> u64 {
    if retained_count(now_ns, win) < GLOBAL_DERIVE_BUDGET as usize {
        return 0;
    }
    let oldest_retained = win
        .dispatched
        .iter()
        .filter(|r| !expired(now_ns, r.at_ns))
        .map(|r| r.at_ns)
        .min()
        .unwrap_or(now_ns);
    oldest_retained
        .saturating_add(GLOBAL_DERIVE_WINDOW_NS)
        .saturating_sub(now_ns)
}

/// The §4.2 budget predicate as one pure step: prune, then admit iff the
/// retained count is under the budget. `Err` carries the exact retry hint.
/// Recording the dispatch is the CALLER's commit-phase act (`record_dispatch`)
/// — this function only decides. TEST-facing spelling of the same predicate
/// `fence_decide` limb (c) applies read-only (the `admission::is_live`
/// precedent): the boundary arms need to drive prune + check + record
/// step-by-step, which the production path performs inside one commit block.
#[cfg(test)]
pub fn global_admit(now_ns: u64, win: &mut GlobalDeriveWindow) -> Result<(), u64> {
    prune_window(now_ns, win);
    if win.dispatched.len() < GLOBAL_DERIVE_BUDGET as usize {
        Ok(())
    } else {
        Err(global_retry_after_ns(now_ns, win))
    }
}

/// Record one actual dispatch — the ONLY writer of fleet capacity, called
/// exclusively from the fence's commit phase.
pub fn record_dispatch(
    now_ns: u64,
    who: PrincipalKey,
    first_derive: bool,
    win: &mut GlobalDeriveWindow,
) {
    // TAGGED AT THE MOMENT OF THE CHARGE (brief V5 §3). Attribution cannot be
    // reconstructed later from a list of timestamps, so it is written here or
    // it does not exist. `who` is always `Some` on this path: only a
    // predecessor's V1 cell can carry an untagged entry.
    win.dispatched.push(DispatchRecord { at_ns: now_ns, who: Some(who), first_derive });
}

// ─────────────────────────────────────────────────────────────────────────────
// The pure decision (§2.2) — check all three, mutate NOTHING
// ─────────────────────────────────────────────────────────────────────────────

/// Limbs, in fixed order:
///   (a) the reservation exists and is still `PreDispatch` (§H′ revalidation);
///   (b) `liquid >= live_cost + DERIVE_CYCLE_FLOOR_CYCLES` (the floor);
///   (d) LAUNCH-HARDEN-04 O-3: `who`'s own TAGGED, unexpired dispatches in the
///       window are under `PER_PRINCIPAL_HOURLY_DERIVE_CAP` (all derives count;
///       untagged legacy entries never count). Checked BEFORE (c) so a
///       principal at its own cap is told so, not told the fleet is full;
///   (c) the window, pruned at `now_ns`, has room (the fleet budget).
/// Any failure refuses with its typed error and mutates nothing — no ordering
/// of failures can ever commit one limb alone (§6.1 arm 14), because this
/// function cannot commit anything: it holds only shared references.
pub fn fence_decide(
    now_ns: u64,
    reservation_id: u64,
    liquid: u128,
    live_cost: u128,
    st: &AdmissionState,
    win: &GlobalDeriveWindow,
    who: PrincipalKey,
) -> FenceDecision {
    // (a) §H′ — the exact id, still PreDispatch. Absent (TTL-pruned while the
    // call was parked) or already Dispatched → lapse, exactly as
    // `revalidate_for_dispatch` would rule.
    let still_predispatch = st
        .reservations
        .iter()
        .any(|r| r.id == reservation_id && r.phase == ReservationPhase::PreDispatch);
    if !still_predispatch {
        return FenceDecision::Refuse(VetkeysError::AdmissionLapsed);
    }
    // (b) the live floor.
    if !cycle_floor_admits(liquid, live_cost) {
        return FenceDecision::Refuse(VetkeysError::CycleFloorReached {
            liquid_cycles: liquid,
            required_cycles: live_cost.saturating_add(DERIVE_CYCLE_FLOOR_CYCLES),
        });
    }
    // (d) LAUNCH-HARDEN-04 O-3 — the per-principal hourly cap, over this
    // principal's own tagged, unexpired entries. `retry_after_ns` is EXACT:
    // the oldest own entry frees exactly one window after it was recorded.
    let own_min = win
        .dispatched
        .iter()
        .filter(|r| !expired(now_ns, r.at_ns) && r.who == Some(who))
        .map(|r| r.at_ns)
        .fold((0usize, u64::MAX), |(n, m), t| (n + 1, m.min(t)));
    if own_min.0 >= PER_PRINCIPAL_HOURLY_DERIVE_CAP as usize {
        return FenceDecision::Refuse(VetkeysError::PrincipalHourlyDerivationCapExceeded {
            retry_after_ns: own_min
                .1
                .saturating_add(GLOBAL_DERIVE_WINDOW_NS)
                .saturating_sub(now_ns),
        });
    }
    // (c) the fleet budget, over the retained (unexpired) entries only.
    if retained_count(now_ns, win) >= GLOBAL_DERIVE_BUDGET as usize {
        return FenceDecision::Refuse(VetkeysError::GlobalDerivationBudgetExceeded {
            retry_after_ns: global_retry_after_ns(now_ns, win),
        });
    }
    FenceDecision::Commit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission;

    /// The floor as its own literal — arms 1–3 never read the constant under
    /// test (its value is pinned separately in `pins::tests`).
    const FLOOR: u128 = 500_000_000_000;
    const COST: u128 = 26_000_000_000;

    // ── §6.1 arms 1–4: the floor predicate ───────────────────────────────────

    /// Arm 1+2 — the boundary pair, inclusive at exactly `cost + floor`.
    #[test]
    fn floor_boundary_is_inclusive_at_cost_plus_floor() {
        assert!(cycle_floor_admits(COST + FLOOR, COST), "liquid == cost + floor admits");
        assert!(!cycle_floor_admits(COST + FLOOR - 1, COST), "one cycle less refuses");
    }

    /// SSA RED-1 — the PINNED-FLOOR-ALONE predicate, inclusive at the floor.
    ///
    /// Driven from its own literals, and checked to be genuinely WEAKER than
    /// the admission predicate: a balance can meet the floor and still not
    /// admit a derive, which is precisely the state `FloorOnly` must be able to
    /// report. Non-vacuity is asserted, so the two predicates cannot silently
    /// collapse into one.
    #[test]
    fn the_pinned_floor_predicate_is_inclusive_and_strictly_weaker_than_admission() {
        assert!(meets_pinned_floor(FLOOR), "equality MEETS the floor");
        assert!(!meets_pinned_floor(FLOOR - 1), "one cycle below does not");
        assert!(meets_pinned_floor(FLOOR + 1));
        assert!(!meets_pinned_floor(0));

        // Strictly weaker, demonstrated on a real value rather than argued:
        // exactly at the floor the canister is above its reserve, but a derive
        // still cannot be paid for.
        assert!(meets_pinned_floor(FLOOR));
        assert!(!cycle_floor_admits(FLOOR, COST));
        // And admission always implies the floor is met — the direction that
        // would break if either boundary moved alone.
        for liquid in [FLOOR + COST, FLOOR + COST + 1, FLOOR + COST * 4] {
            assert!(cycle_floor_admits(liquid, COST));
            assert!(meets_pinned_floor(liquid), "admission must imply the floor is met");
        }
    }

    /// Arm 3 — `cost > liquid` refuses, and an absurd cost cannot overflow
    /// into an admit (`saturating_add` pinned).
    #[test]
    fn floor_refuses_unpayable_cost_without_overflow() {
        assert!(!cycle_floor_admits(COST - 1, COST));
        assert!(!cycle_floor_admits(u128::MAX - 1, u128::MAX), "saturation must refuse");
    }

    /// Arm 4 — a cost-query `Err` refuses, fail-closed, as the typed floor
    /// refusal with the floor as the honest lower bound.
    #[test]
    fn cost_query_error_refuses_fail_closed() {
        let e = resolve_live_cost(7, Err("InvalidCurveOrAlgorithm".to_string()))
            .expect_err("an unknown price must refuse, never default to zero");
        match e {
            VetkeysError::CycleFloorReached { liquid_cycles, required_cycles } => {
                assert_eq!(liquid_cycles, 7);
                assert_eq!(required_cycles, FLOOR);
            }
            other => panic!("expected CycleFloorReached, got {other:?}"),
        }
        assert_eq!(resolve_live_cost(7, Ok(42)), Ok(42), "a known price passes through");
    }

    // ── §6.1 arms 5–9: the global rolling predicate ──────────────────────────

    fn filled(n: usize, ts: u64) -> GlobalDeriveWindow {
        GlobalDeriveWindow {
            dispatched: (0..n).map(|i| tagged(ts, i as u8)).collect(),
        }
    }

    /// A DISTINCT test principal per index — the arms below are about capacity,
    /// but the V2 record carries attribution, and reusing one principal would
    /// let a future attribution bug pass a capacity arm unnoticed.
    fn who(i: u8) -> PrincipalKey {
        PrincipalKey::new(candid::Principal::from_slice(&[i, 1, 2, 3, 4]))
    }

    fn tagged(ts: u64, i: u8) -> DispatchRecord {
        DispatchRecord { at_ns: ts, who: Some(who(i)), first_derive: false }
    }

    /// The budget, regenerated as its own literal for these arms (pinned
    /// separately in `pins::tests`); the window likewise.
    ///
    /// LAUNCH ON-RAMP RE-PIN 2026-09-01: 100 → 20 (ratification addd59af…).
    /// LAUNCH-HARDEN-04 O-3 RE-PIN 2026-09-24: 20 → 100
    /// (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24, sha256 249f551b…ec417).
    /// Hardcoded on purpose — reading it from the code under test could not RED
    /// when it moves — so a re-pin changes it here deliberately and visibly.
    /// The ARMS' FORM is unchanged: same predicate, same boundaries, same
    /// assertions; only this mirror of the shipped value moves.
    const BUDGET: usize = 100;
    /// The per-principal hourly cap, as its own literal (O-3).
    const OWN_CAP: usize = 2;
    /// A principal that owns NONE of the fixture entries, used by the arms that
    /// test the OTHER limbs so limb (d) is never the thing under test there.
    fn bystander() -> PrincipalKey {
        PrincipalKey::new(candid::Principal::from_slice(&[0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE]))
    }
    const WINDOW: u64 = 3_600_000_000_000;

    /// Arm 5 — exactly the budget admits; the next refuses.
    #[test]
    fn exactly_the_budget_admits_then_refuses() {
        let mut win = GlobalDeriveWindow::default();
        let t0 = 10 * WINDOW;
        for i in 0..BUDGET {
            assert!(global_admit(t0, &mut win).is_ok(), "dispatch {} of {BUDGET}", i + 1);
            record_dispatch(t0, who(i as u8), false, &mut win);
        }
        let retry = global_admit(t0, &mut win).expect_err("the budget-plus-one must refuse");
        assert_eq!(retry, WINDOW, "all slots free exactly one window after t0");
    }

    /// Arm 6 — the boundary triple. A reset-window implementation passes arm 5
    /// and fails this one.
    #[test]
    fn boundary_triple_window_minus_one_counted_window_freed() {
        let t0 = 20 * WINDOW;
        let t_young = t0 + 1;
        // `BUDGET - 1` young entries + 1 old entry.
        let mut win = filled(BUDGET - 1, t_young);
        win.dispatched.push(tagged(t0, 99));

        // Aged `window − 1`: the old entry is still counted → full → refused.
        assert!(global_admit(t0 + WINDOW - 1, &mut win.clone()).is_err());
        // Aged exactly `window`: the old entry frees — EXACTLY ONE admits.
        let mut probe = win.clone();
        assert!(global_admit(t0 + WINDOW, &mut probe).is_ok(), "aged == window is freed");
        record_dispatch(t0 + WINDOW, who(200), false, &mut probe);
        assert!(global_admit(t0 + WINDOW, &mut probe).is_err(), "and only one");
        // Aged `window + 1`: freed as well.
        assert!(global_admit(t0 + WINDOW + 1, &mut win.clone()).is_ok());
    }

    /// Arm 7 — `retry_after_ns` exactness from both sides, and 0 on admit.
    #[test]
    fn retry_after_is_exact_from_both_sides() {
        let t0 = 30 * WINDOW;
        let mut win = filled(BUDGET, t0);
        let now = t0 + 1_234_567;
        let retry = global_admit(now, &mut win).expect_err("full window refuses");
        // Regenerated independently: the oldest entry frees one window after t0.
        assert_eq!(retry, (t0 + WINDOW) - now);
        assert!(global_admit(now + retry - 1, &mut win.clone()).is_err(), "one ns early");
        let mut at = win.clone();
        assert!(global_admit(now + retry, &mut at).is_ok(), "admitted exactly at retry");
        assert_eq!(global_retry_after_ns(now + retry, &at), 0, "0 when admitting");
    }

    /// Arm 8 — `now < window` saturates: nothing expires, no underflow.
    #[test]
    fn early_clock_saturates_without_underflow() {
        let mut win = filled(3, 0);
        let now = WINDOW - 1; // every entry is younger than the window
        assert!(global_admit(now, &mut win).is_ok());
        assert_eq!(win.dispatched.len(), 3, "nothing may expire before the window elapses");
    }

    /// Arm 9 — the retained list never exceeds the budget in length.
    #[test]
    fn retained_list_never_exceeds_the_budget() {
        let mut win = GlobalDeriveWindow::default();
        let mut now = 40 * WINDOW;
        for i in 0..(BUDGET * 3) {
            if global_admit(now, &mut win).is_ok() {
                record_dispatch(now, who(i as u8), false, &mut win);
            }
            assert!(win.dispatched.len() <= BUDGET, "len {} at step {i}", win.dispatched.len());
            now += WINDOW / 50; // slides so entries expire over the run
        }
    }

    // ── §6.1 arms 10–14: fence_decide atomicity ──────────────────────────────

    /// Mirror of the wrapper's commit phase, for the harness: flip the phase
    /// through the SAME single transition production uses, then record.
    fn apply_commit(now_ns: u64, id: u64, st: &mut AdmissionState, win: &mut GlobalDeriveWindow) {
        admission::revalidate_for_dispatch(st, id).expect("Commit implies still PreDispatch");
        prune_window(now_ns, win);
        record_dispatch(now_ns, who(0), false, win);
    }

    fn park_one(now: u64, st: &mut AdmissionState) -> u64 {
        admission::admit(now, st).expect("§H′ capacity available").reservation_id
    }

    /// Arm 10 — all three hold → Commit; the commit flips the phase AND
    /// appends exactly one timestamp.
    #[test]
    fn commit_flips_phase_and_appends_exactly_one_timestamp() {
        let mut st = AdmissionState::default();
        let mut win = GlobalDeriveWindow::default();
        let t0 = 50 * WINDOW;
        let id = park_one(t0, &mut st);
        let d = fence_decide(t0, id, COST + FLOOR, COST, &st, &win, bystander());
        assert_eq!(d, FenceDecision::Commit);
        apply_commit(t0, id, &mut st, &mut win);
        assert_eq!(
            win.dispatched,
            vec![DispatchRecord { at_ns: t0, who: Some(who(0)), first_derive: false }],
            "exactly one record, tagged with the principal the commit charged"
        );
        assert!(
            st.reservations.iter().any(|r| r.id == id
                && r.phase == crate::state::ReservationPhase::Dispatched),
            "the phase must be flipped by the commit"
        );
    }

    /// Arm 11 — §H′ lapsed → window unchanged, phase unchanged.
    #[test]
    fn a_lapsed_reservation_refuses_and_moves_nothing() {
        let mut st = AdmissionState::default();
        let win = GlobalDeriveWindow::default();
        let t0 = 60 * WINDOW;
        let _live = park_one(t0, &mut st);
        let before = st.clone();
        let d = fence_decide(t0, 4_242, COST + FLOOR, COST, &st, &win, bystander());
        assert_eq!(d, FenceDecision::Refuse(VetkeysError::AdmissionLapsed));
        assert_eq!(st, before, "a lapse decision mutates no §H′ state");
        assert!(win.dispatched.is_empty(), "and no fleet capacity");
    }

    /// Arm 12 — floor fails → window unchanged, reservation still
    /// `PreDispatch`, so `release` still works.
    #[test]
    fn a_floor_refusal_leaves_the_reservation_releasable() {
        let mut st = AdmissionState::default();
        let win = GlobalDeriveWindow::default();
        let t0 = 70 * WINDOW;
        let id = park_one(t0, &mut st);
        let d = fence_decide(t0, id, COST + FLOOR - 1, COST, &st, &win, bystander());
        match d {
            FenceDecision::Refuse(VetkeysError::CycleFloorReached {
                liquid_cycles,
                required_cycles,
            }) => {
                assert_eq!(liquid_cycles, COST + FLOOR - 1);
                assert_eq!(required_cycles, COST + FLOOR);
            }
            other => panic!("expected CycleFloorReached, got {other:?}"),
        }
        assert!(win.dispatched.is_empty());
        assert!(
            admission::release(&mut st, id),
            "the refused reservation must still be PreDispatch and releasable"
        );
    }

    /// Arm 13 — budget full → phase NOT flipped, typed error carries the §4.2
    /// retry hint exactly.
    #[test]
    fn a_full_budget_refuses_with_the_exact_retry_hint() {
        let mut st = AdmissionState::default();
        let t0 = 80 * WINDOW;
        let win = filled(BUDGET, t0);
        let id = park_one(t0, &mut st);
        let now = t0 + 999;
        let d = fence_decide(now, id, COST + FLOOR, COST, &st, &win, bystander());
        assert_eq!(
            d,
            FenceDecision::Refuse(VetkeysError::GlobalDerivationBudgetExceeded {
                retry_after_ns: (t0 + WINDOW) - now, // regenerated independently
            })
        );
        assert!(
            st.reservations.iter().all(|r| r.phase
                == crate::state::ReservationPhase::PreDispatch),
            "no phase may flip on a refusal"
        );
    }

    /// Arm 14 — no combination of failures ever commits one limb alone: every
    /// failing configuration returns Refuse, and the decision holds only
    /// shared references so it CANNOT mutate (typestate half); the harness
    /// applies nothing on Refuse (behavioural half).
    #[test]
    fn no_ordering_of_failures_commits_one_limb_alone() {
        let t0 = 90 * WINDOW;
        for lapsed in [false, true] {
            for floor_fails in [false, true] {
                for budget_full in [false, true] {
                    if !lapsed && !floor_fails && !budget_full {
                        continue;
                    }
                    let mut st = AdmissionState::default();
                    let real = park_one(t0, &mut st);
                    let id = if lapsed { real + 999 } else { real };
                    let liquid = if floor_fails { COST + FLOOR - 1 } else { COST + FLOOR };
                    let win = if budget_full {
                        filled(BUDGET, t0)
                    } else {
                        GlobalDeriveWindow::default()
                    };
                    let before_st = st.clone();
                    let before_win = win.clone();
                    let d = fence_decide(t0, id, liquid, COST, &st, &win, bystander());
                    assert!(
                        matches!(d, FenceDecision::Refuse(_)),
                        "({lapsed},{floor_fails},{budget_full}) must refuse"
                    );
                    assert_eq!(st, before_st);
                    assert_eq!(win, before_win);
                }
            }
        }
    }

    // ── §6.2 — the RED-5 causal harness (arms 15 / 15a / 15b) ────────────────

    /// Drive N parked resumers through `fence_decide` with a liquid sequence
    /// chosen by `stale_balance`: the true decreasing sequence (each step
    /// reduced by the independently-computed live cost — never by a value the
    /// fence returned), or the initial pre-await observation at every step
    /// (the stale-balance mutation, 15a). `count_commits: false` disables the
    /// independent commit counter (15b). Returns Err when the proof's
    /// assertions do not hold — so the mutations are shown to make it FAIL,
    /// not merely differ.
    fn causal_proof(stale_balance: bool, count_commits: bool) -> Result<(), String> {
        let t0 = 200 * WINDOW;
        let n = 5usize; // = the §H′ quota: the most parkable against one state
        let initial_liquid = FLOOR + COST * 3 + COST / 2;
        // Independently-computed expected prefix: how many whole costs fit
        // above the floor. Regenerated from the same literals the sequence is
        // built from — never from the fence.
        let liquid_at = |i: usize| initial_liquid - COST * i as u128;
        let expected_prefix = (0..n).filter(|i| liquid_at(*i) >= COST + FLOOR).count();
        assert_eq!(expected_prefix, 3, "harness self-check: the fixture must be non-trivial");

        // Park N reservations against ONE pre-await observation.
        let mut st = AdmissionState::default();
        let ids: Vec<u64> = (0..n).map(|_| park_one(t0, &mut st)).collect();
        let mut win = GlobalDeriveWindow::default();

        let mut commits = 0usize;
        let mut decisions = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let liquid = if stale_balance { initial_liquid } else { liquid_at(i) };
            match fence_decide(t0, *id, liquid, COST, &st, &win, bystander()) {
                FenceDecision::Commit => {
                    if count_commits {
                        commits += 1;
                    }
                    apply_commit(t0, *id, &mut st, &mut win);
                    decisions.push(true);
                }
                FenceDecision::Refuse(VetkeysError::CycleFloorReached { .. }) => {
                    decisions.push(false);
                }
                FenceDecision::Refuse(other) => {
                    return Err(format!("resumer {i}: unexpected refusal {other:?}"));
                }
            }
        }
        // Exactly the expected PREFIX commits, and every later resumer refuses.
        let observed_prefix: Vec<bool> =
            (0..n).map(|i| i < expected_prefix).collect();
        if decisions != observed_prefix {
            return Err(format!(
                "decision shape {decisions:?} != expected prefix {observed_prefix:?}"
            ));
        }
        // The COUNT of Commit decisions equals the expected prefix length.
        if commits != expected_prefix {
            return Err(format!("commit count {commits} != expected prefix {expected_prefix}"));
        }
        Ok(())
    }

    /// Arm 15 — the causal proof holds on the true decreasing sequence.
    #[test]
    fn causal_arm_exactly_the_affordable_prefix_commits() {
        causal_proof(false, true).expect("the shipped fence must pass the causal arm");
    }

    /// Arm 15a — harness self-mutation: feed the INITIAL liquid at every step
    /// (the stale-balance mutation). Arm 15 must go RED.
    #[test]
    fn causal_arm_bites_on_a_stale_balance() {
        let err = causal_proof(true, true)
            .expect_err("a fence fed the pre-await balance MUST fail the causal arm");
        assert!(err.contains("decision shape") || err.contains("commit count"), "{err}");
    }

    /// Arm 15b — harness self-mutation: disable the independent commit
    /// counter. The proof must FAIL, not pass vacuously.
    #[test]
    fn causal_arm_cannot_pass_with_the_counter_disabled() {
        let err = causal_proof(false, false)
            .expect_err("a disabled commit counter must fail the proof, not vacuously pass");
        assert!(err.contains("commit count"), "{err}");
    }

    // ── LAUNCH-HARDEN-04 O-3 — limb (d), the per-principal hourly cap ───────

    fn own_tagged(ts: u64, p: PrincipalKey) -> DispatchRecord {
        DispatchRecord { at_ns: ts, who: Some(p), first_derive: false }
    }

    /// Boundary triple: OWN_CAP own entries at t0 → at `t0 + W − 1` refused
    /// with exact retry 1; at `t0 + W` admitted.
    #[test]
    fn own_cap_boundary_triple() {
        let t0 = 300 * WINDOW;
        let me = who(7);
        let mut st = AdmissionState::default();
        let id = park_one(t0, &mut st);
        let win = GlobalDeriveWindow {
            dispatched: (0..OWN_CAP).map(|_| own_tagged(t0, me)).collect(),
        };
        assert_eq!(
            fence_decide(t0 + WINDOW - 1, id, COST + FLOOR, COST, &st, &win, me),
            FenceDecision::Refuse(VetkeysError::PrincipalHourlyDerivationCapExceeded {
                retry_after_ns: 1
            })
        );
        assert_eq!(
            fence_decide(t0 + WINDOW, id, COST + FLOOR, COST, &st, &win, me),
            FenceDecision::Commit,
            "aged exactly one window, the own entries free"
        );
        // One own entry fewer than the cap admits at t0 itself.
        let one = GlobalDeriveWindow { dispatched: vec![own_tagged(t0, me)] };
        assert_eq!(fence_decide(t0, id, COST + FLOOR, COST, &st, &one, me), FenceDecision::Commit);
    }

    /// Another principal's entries never count against `who`.
    #[test]
    fn other_principal_unaffected() {
        let t0 = 310 * WINDOW;
        let (a, b) = (who(1), who(2));
        let mut st = AdmissionState::default();
        let id = park_one(t0, &mut st);
        let win = GlobalDeriveWindow {
            dispatched: (0..OWN_CAP).map(|_| own_tagged(t0, a)).collect(),
        };
        assert!(matches!(
            fence_decide(t0, id, COST + FLOOR, COST, &st, &win, a),
            FenceDecision::Refuse(VetkeysError::PrincipalHourlyDerivationCapExceeded { .. })
        ));
        assert_eq!(fence_decide(t0, id, COST + FLOOR, COST, &st, &win, b), FenceDecision::Commit);
    }

    /// Untagged legacy (V1-carry) entries have no principal and never count.
    #[test]
    fn legacy_untagged_entries_ignored() {
        let t0 = 320 * WINDOW;
        let me = who(3);
        let mut st = AdmissionState::default();
        let id = park_one(t0, &mut st);
        let win = GlobalDeriveWindow {
            dispatched: (0..(OWN_CAP * 5))
                .map(|_| DispatchRecord { at_ns: t0, who: None, first_derive: false })
                .collect(),
        };
        assert_eq!(fence_decide(t0, id, COST + FLOOR, COST, &st, &win, me), FenceDecision::Commit);
    }

    /// A cap refusal mutates nothing: the reservation stays PreDispatch
    /// (releasable) and the window is unchanged.
    #[test]
    fn cap_refusal_mutates_nothing() {
        let t0 = 330 * WINDOW;
        let me = who(4);
        let mut st = AdmissionState::default();
        let id = park_one(t0, &mut st);
        let win = GlobalDeriveWindow {
            dispatched: (0..OWN_CAP).map(|_| own_tagged(t0, me)).collect(),
        };
        let (before_st, before_win) = (st.clone(), win.clone());
        assert!(matches!(
            fence_decide(t0, id, COST + FLOOR, COST, &st, &win, me),
            FenceDecision::Refuse(VetkeysError::PrincipalHourlyDerivationCapExceeded { .. })
        ));
        assert_eq!(st, before_st);
        assert_eq!(win, before_win);
        assert!(admission::release(&mut st, id), "still PreDispatch, still releasable");
    }

    /// With BOTH the own cap and the fleet budget exhausted, the own-cap limb
    /// answers first (it precedes limb (c)).
    #[test]
    fn cap_limb_precedes_budget_limb() {
        let t0 = 340 * WINDOW;
        let me = who(5);
        let mut st = AdmissionState::default();
        let id = park_one(t0, &mut st);
        let mut win = filled(BUDGET - OWN_CAP, t0);
        for _ in 0..OWN_CAP {
            win.dispatched.push(own_tagged(t0, me));
        }
        assert_eq!(win.dispatched.len(), BUDGET, "fleet budget full");
        assert!(matches!(
            fence_decide(t0, id, COST + FLOOR, COST, &st, &win, me),
            FenceDecision::Refuse(VetkeysError::PrincipalHourlyDerivationCapExceeded { .. })
        ));
        // And a bystander at the same full window gets the FLEET refusal.
        assert!(matches!(
            fence_decide(t0, id, COST + FLOOR, COST, &st, &win, bystander()),
            FenceDecision::Refuse(VetkeysError::GlobalDerivationBudgetExceeded { .. })
        ));
    }
}
