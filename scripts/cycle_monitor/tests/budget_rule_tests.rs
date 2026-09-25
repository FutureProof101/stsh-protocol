//! C-26 derive-budget rules — §8.3 arms 16–19, 21–25 (extended), 36, 37.
//!
//! Every limb is driven through the INJECTED budget source and an explicitly
//! constructed prior state: no network, no canister, no timing assertion. The
//! counters and clocks are integers, so every boundary here is exact.
//!
//! The rule under test throughout: **absence must not read as health.** A
//! partial history is `Incomplete`, never extrapolated; an epoch change drops
//! its history rather than differencing across a reset; and an unwired or
//! failed query is `Incomplete`, never `Ok`.

use cycle_monitor::*;

const HOUR_NS: u64 = 3_600_000_000_000;
const NOW: u64 = 1_800_000_000_000_000_000;
const EPOCH: u64 = 42;

fn stats() -> DeriveBudgetStats {
    DeriveBudgetStats {
        window_ns: HOUR_NS,
        budget: 20,
        consumed: 0,
        retry_after_ns: 0,
        tagged_consumed: 0,
        distinct_principals: 0,
        max_by_one_principal: 0,
        first_derive_dispatches: 0,
        refusals_budget_total: 0,
        stats_epoch_ns: EPOCH,
        floor: CycleFloorView::Live { admits: true },
        sightings_recorded_total: 0,
        age_refusals_total: 0,
        sightings_pending: 0,
    }
}


/// A prior report whose histories span a FULL hour at `base`, so the two
/// rolling-hour rules are evaluated rather than Incomplete.
fn prior_with(refusals: u64, sightings: u64) -> DeriveBudgetReport {
    DeriveBudgetReport {
        saturation: RuleOutcome::Quiet,
        concentration: RuleOutcome::Quiet,
        refusal_spike: RuleOutcome::Quiet,
        funding_wave: RuleOutcome::Quiet,
        floor: RuleOutcome::Quiet,
        first_saturated_at_ns: None,
        refusal_history: vec![CounterSample {
            at_ns: NOW - HOUR_NS,
            value: refusals,
            epoch_ns: EPOCH,
        }],
        sighting_history: vec![CounterSample {
            at_ns: NOW - HOUR_NS,
            value: sightings,
            epoch_ns: EPOCH,
        }],
        reasons: Vec::new(),
    }
}

fn eval(s: DeriveBudgetStats, prior: Option<&DeriveBudgetReport>) -> DeriveBudgetReport {
    evaluate_budget_rules(&BudgetObservation::Stats(s), prior, NOW)
}

// ── Rule 4 — the FUNDING WAVE (arm 36) ───────────────────────────────────────

/// **Arm 36 — the boundary is INCLUSIVE: 19 does not alert, 20 does.**
///
/// SSA GREEN-5 corrected V4's "more … than" wording to match the shipped
/// equality. Both sides are driven, and the threshold is written here as its
/// own literal so a re-pin cannot move this expectation with it.
#[test]
fn the_funding_wave_boundary_is_inclusive_at_one_hundred() {
    // Re-derived for the ratified B = 100 (LAUNCH-HARDEN-04 O-3; was 20).
    let threshold: u64 = 100;
    let base = prior_with(0, 1_000);

    let mut nineteen = stats();
    nineteen.sightings_recorded_total = 1_000 + (threshold - 1);
    assert_eq!(
        eval(nineteen, Some(&base)).funding_wave,
        RuleOutcome::Quiet,
        "99 new age-in periods in the hour must NOT alert"
    );

    let mut twenty = stats();
    twenty.sightings_recorded_total = 1_000 + threshold;
    assert_eq!(
        eval(twenty, Some(&base)).funding_wave,
        RuleOutcome::Alert,
        "100 — at least as many as the fleet can admit in an hour — MUST alert"
    );
}

/// A partial history is `Incomplete` and is NEVER extrapolated to an hour.
#[test]
fn a_partial_history_is_incomplete_not_a_scaled_up_rate() {
    let mut half = prior_with(0, 0);
    // Only half an hour of history.
    half.sighting_history = vec![CounterSample {
        at_ns: NOW - HOUR_NS / 2,
        value: 0,
        epoch_ns: EPOCH,
    }];
    let mut s = stats();
    // A rate that WOULD alert if doubled to a full hour.
    s.sightings_recorded_total = 15;
    assert_eq!(
        eval(s, Some(&half)).funding_wave,
        RuleOutcome::Incomplete,
        "half an hour at 15 would extrapolate to 30/h — the monitor must refuse to invent it"
    );
}

/// An epoch change DROPS the history, re-baselines, and does not alert.
///
/// The counters are ephemeral heap and reset on upgrade. Differencing across a
/// reset would read a restart as a rate — here, a huge one.
#[test]
fn an_epoch_change_drops_history_and_cannot_alert() {
    let base = prior_with(0, 10_000);
    let mut s = stats();
    s.stats_epoch_ns = EPOCH + 1; // upgraded
    s.sightings_recorded_total = 0; // and the counter restarted

    let out = eval(s, Some(&base));
    assert_eq!(
        out.funding_wave,
        RuleOutcome::Incomplete,
        "a new epoch has no comparable history — Incomplete, never a rate"
    );
    assert_eq!(out.sighting_history.len(), 1, "the pre-epoch samples are dropped, not kept");
    assert_eq!(out.sighting_history[0].epoch_ns, EPOCH + 1, "and the new sample is the baseline");
}

// ── Rule 3 — the REFUSAL SPIKE ───────────────────────────────────────────────

/// 4 in the hour does not alert; 5 does. The threshold is this file's own
/// literal, not a read-back.
#[test]
fn the_refusal_spike_fires_at_five_and_not_at_four() {
    let threshold: u64 = 5;
    let base = prior_with(100, 0);

    let mut four = stats();
    four.refusals_budget_total = 100 + (threshold - 1);
    assert_eq!(eval(four, Some(&base)).refusal_spike, RuleOutcome::Quiet);

    let mut five = stats();
    five.refusals_budget_total = 100 + threshold;
    assert_eq!(eval(five, Some(&base)).refusal_spike, RuleOutcome::Alert);
}

/// A single refusal inside one five-minute cadence is not an hourly rate.
///
/// This is the arm that fails if the rule ever annualizes a short sample: one
/// refusal 300 s ago is 12/h if extrapolated, well over the threshold, and it
/// must still not alert.
#[test]
fn one_refusal_in_a_five_minute_sample_is_not_an_hourly_rate() {
    let mut recent = prior_with(0, 0);
    recent.refusal_history = vec![CounterSample {
        at_ns: NOW - 300_000_000_000,
        value: 0,
        epoch_ns: EPOCH,
    }];
    let mut s = stats();
    s.refusals_budget_total = 1;
    assert_eq!(
        eval(s, Some(&recent)).refusal_spike,
        RuleOutcome::Incomplete,
        "a 300 s sample cannot answer an hourly question, and 12/h is a number nobody measured"
    );
}

// ── Rule 2 — CONCENTRATION ───────────────────────────────────────────────────

/// 9 tagged observations are NOT EVALUATED; 10 are.
#[test]
fn concentration_is_not_evaluated_below_the_sample_floor() {
    let mut nine = stats();
    nine.tagged_consumed = 9;
    nine.distinct_principals = 1;
    assert_eq!(eval(nine, None).concentration, RuleOutcome::NotEvaluated);

    let mut ten = stats();
    ten.tagged_consumed = 10;
    ten.distinct_principals = 1;
    assert_eq!(
        eval(ten, None).concentration,
        RuleOutcome::Alert,
        "ten dispatches by one principal is a mean of 10 — far above 2×"
    );
}

/// The organic shape — ten principals, one derive each — is quiet.
#[test]
fn organic_traffic_does_not_trip_the_concentration_rule() {
    let mut s = stats();
    s.tagged_consumed = 10;
    s.distinct_principals = 10;
    assert_eq!(eval(s, None).concentration, RuleOutcome::Quiet, "a mean of 1.0 is organic");

    // The boundary: a mean of exactly 2.0 alerts.
    let mut at_two = stats();
    at_two.tagged_consumed = 10;
    at_two.distinct_principals = 5;
    assert_eq!(eval(at_two, None).concentration, RuleOutcome::Alert);

    // Just under it does not.
    let mut under = stats();
    under.tagged_consumed = 11;
    under.distinct_principals = 6;
    assert_eq!(eval(under, None).concentration, RuleOutcome::Quiet);
}

/// 99 untagged and 1 tagged raises NO concentration alert: the rule is computed
/// over the tagged subset only, and one observation is below the floor.
#[test]
fn a_mostly_untagged_window_raises_no_concentration_alert() {
    let mut s = stats();
    s.consumed = 100;
    s.tagged_consumed = 1;
    s.distinct_principals = 1;
    assert_eq!(eval(s, None).concentration, RuleOutcome::NotEvaluated);
}

/// `distinct_principals == 0` short-circuits rather than dividing.
#[test]
fn zero_distinct_principals_short_circuits() {
    let mut s = stats();
    s.tagged_consumed = 50;
    s.distinct_principals = 0;
    assert_eq!(eval(s, None).concentration, RuleOutcome::NotEvaluated);
}

// ── Rule 1 — SATURATION, on elapsed time ─────────────────────────────────────

/// Saturation alerts only once it has PERSISTED for the pinned window; the mark
/// is set on the first saturated observation and cleared the moment it lifts.
#[test]
fn saturation_alerts_only_after_the_pinned_elapsed_window() {
    let mut full = stats();
    full.consumed = 20;

    // First observation: saturated, but no elapsed time yet.
    let first = eval(full.clone(), None);
    assert_eq!(first.saturation, RuleOutcome::Quiet);
    assert_eq!(first.first_saturated_at_ns, Some(NOW));

    // One ns short of the window.
    let mut nearly = first.clone();
    nearly.first_saturated_at_ns = Some(NOW - (SATURATION_MIN_ELAPSED_NS - 1));
    assert_eq!(
        evaluate_budget_rules(&BudgetObservation::Stats(full.clone()), Some(&nearly), NOW)
            .saturation,
        RuleOutcome::Quiet
    );

    // Exactly the window: alert.
    let mut at = first.clone();
    at.first_saturated_at_ns = Some(NOW - SATURATION_MIN_ELAPSED_NS);
    assert_eq!(
        evaluate_budget_rules(&BudgetObservation::Stats(full.clone()), Some(&at), NOW).saturation,
        RuleOutcome::Alert
    );

    // And it CLEARS the moment the fleet is no longer saturated — a stale mark
    // would alert across a gap the fleet had already recovered from.
    let mut relieved = stats();
    relieved.consumed = 19;
    let out = evaluate_budget_rules(&BudgetObservation::Stats(relieved), Some(&at), NOW);
    assert_eq!(out.saturation, RuleOutcome::Quiet);
    assert_eq!(out.first_saturated_at_ns, None);
}

// ── The floor limb ───────────────────────────────────────────────────────────

/// Every floor reading maps to exactly one outcome, and the two `FloorOnly`
/// verdicts do NOT collapse — that distinction is SSA RED-1.
#[test]
fn every_floor_reading_has_its_own_mapping() {
    let mut ok = stats();
    ok.floor = CycleFloorView::Live { admits: true };
    assert_eq!(eval(ok, None).floor, RuleOutcome::Quiet);

    let mut refusing = stats();
    refusing.floor = CycleFloorView::Live { admits: false };
    assert_eq!(eval(refusing, None).floor, RuleOutcome::Alert);

    // Below the pinned floor with the price unavailable: a DEFINITE hard-floor
    // event. Reporting this as "price unavailable" would lose the alert.
    let mut below = stats();
    below.floor =
        CycleFloorView::FloorOnly { meets_pinned_floor: false, reason: "no price".into() };
    assert_eq!(eval(below, None).floor, RuleOutcome::Alert);

    // Floor met, cost unknown: coverage, NOT an admission verdict — so
    // Incomplete, never Quiet.
    let mut met = stats();
    met.floor = CycleFloorView::FloorOnly { meets_pinned_floor: true, reason: "no price".into() };
    assert_eq!(eval(met, None).floor, RuleOutcome::Incomplete);

    let mut unavailable = stats();
    unavailable.floor = CycleFloorView::Unavailable("no key manager".into());
    assert_eq!(eval(unavailable, None).floor, RuleOutcome::Incomplete);
}

// ── Absence must not read as health ──────────────────────────────────────────

/// An UNWIRED budget query makes the whole section Incomplete — never Ok.
#[test]
fn an_unwired_budget_query_is_incomplete_never_ok() {
    let out = evaluate_budget_rules(&BudgetObservation::NotWired, None, NOW);
    assert_eq!(out.aggregate(), Aggregate::Incomplete);
    assert!(!out.reasons.is_empty(), "and it must say why");
}

/// A FAILED budget query is Incomplete too, carrying its reason.
#[test]
fn a_failed_budget_query_is_incomplete_and_says_why() {
    let out =
        evaluate_budget_rules(&BudgetObservation::Failed("canister unreachable".into()), None, NOW);
    assert_eq!(out.aggregate(), Aggregate::Incomplete);
    assert!(out.reasons.iter().any(|r| r.contains("canister unreachable")));
}

/// `NotEvaluated` is NOT Incomplete: a rule waiting for its sample floor is
/// working correctly, and reporting the run indeterminate every quiet hour
/// would train an operator to ignore the monitor.
#[test]
fn a_rule_below_its_sample_floor_does_not_make_the_run_indeterminate() {
    let mut s = stats();
    s.tagged_consumed = 1;
    s.distinct_principals = 1;
    let out = eval(s, Some(&prior_with(0, 0)));
    assert_eq!(out.concentration, RuleOutcome::NotEvaluated);
    assert_eq!(out.aggregate(), Aggregate::Ok);
}

/// **Arm 37 — the reachability relation.**
#[test]
fn the_wave_threshold_is_reachable_within_one_window() {
    let mut s = stats();
    s.sightings_recorded_total = FUNDING_WAVE_PER_HOUR as u64;
    let out = eval(s, Some(&prior_with(0, 0)));
    assert_eq!(
        out.funding_wave,
        RuleOutcome::Alert,
        "the threshold must be reachable by real traffic, or the rule can never fire"
    );
}

/// History is capped and trimmed to the pinned span — the state file cannot
/// grow without bound however often the monitor runs.
#[test]
fn history_is_trimmed_to_the_pinned_span_and_cap() {
    let mut report = prior_with(0, 0);
    for i in 0..(REFUSAL_HISTORY_MAX_SAMPLES * 3) {
        let at = NOW + i as u64 * 60_000_000_000; // a sample a minute
        let mut s = stats();
        s.refusals_budget_total = i as u64;
        report = evaluate_budget_rules(&BudgetObservation::Stats(s), Some(&report), at);
    }
    assert!(
        report.refusal_history.len() <= REFUSAL_HISTORY_MAX_SAMPLES,
        "history must respect its cap; got {}",
        report.refusal_history.len()
    );
    let newest = report.refusal_history.last().unwrap().at_ns;
    assert!(
        report.refusal_history.iter().all(|s| newest - s.at_ns <= REFUSAL_HISTORY_SPAN_NS),
        "and its span"
    );
}
