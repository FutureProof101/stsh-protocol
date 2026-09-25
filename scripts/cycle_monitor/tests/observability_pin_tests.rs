//! C-26 observability pins — Rule-2 mutation arms and relation arms.
//!
//! A1 fix brief V5 §1, §6.7, §7.2. **COMMIT-1 FREEZE (§7.3):** these arms pin
//! the numbers ahead of the four rules that consume them, so the pins are under
//! review before any behaviour depends on them.
//!
//! Rule 2 throughout: no assertion reads the constant under test to build its
//! own expectation. Each is regenerated from unit arithmetic, from an
//! independently written literal, or — for the cross-crate relations — from the
//! vetkeys SOURCE at compile time.

use cycle_monitor::*;

/// The vetkeys pins source, read AT COMPILE TIME.
///
/// `canisters/vetkeys` is a workspace-EXCLUDED crate (ic-cdk 0.20 against the
/// workspace's 0.16), so this crate cannot depend on it — and a hand-copied
/// number here would be exactly the drift the relations exist to catch. This is
/// the `include_str!` drift-lock pattern the vetkeys crate already uses to bind
/// its own eligibility floor to the ruled fee-policy floor: no dependency, no
/// runtime I/O, and a REAL failure when the two sides diverge.
const VETKEYS_PINS_SRC: &str = include_str!("../../../canisters/vetkeys/src/pins.rs");

/// Parse `pub const <name>: <ty> = <integer literal>;` out of that source.
///
/// FAIL LOUDLY, NOT SILENTLY. If the declaration is missing or is no longer a
/// plain literal, this panics with a repair instruction rather than returning a
/// default — a drift lock that quietly stops checking is worse than none, and
/// that is the specific way this class of lock dies.
fn vetkeys_pin(name: &str) -> u128 {
    let needle = format!("pub const {name}:");
    let line = VETKEYS_PINS_SRC
        .lines()
        .find(|l| l.trim_start().starts_with(&needle))
        .unwrap_or_else(|| {
            panic!(
                "canisters/vetkeys/src/pins.rs no longer declares {name} — this drift lock \
                 cannot verify the C-26 monitor relations and must be REPAIRED, not deleted"
            )
        });
    line.rsplit('=')
        .next()
        .and_then(|v| v.trim().trim_end_matches(';').replace('_', "").parse().ok())
        .unwrap_or_else(|| panic!("{name} is no longer a plain integer literal: {line:?}"))
}

// ── §1 — the re-derived thresholds ───────────────────────────────────────────

/// Mutation-RED — the saturation rule's elapsed-time floor, as unit arithmetic.
#[test]
fn saturation_min_elapsed_is_pinned_at_fifteen_minutes() {
    let fifteen_minutes_ns: u64 = 15 * 60 * 1_000_000_000;
    assert_eq!(SATURATION_MIN_ELAPSED_NS, fifteen_minutes_ns);
}

/// Relation arm — the saturation window equals the staleness bound.
///
/// LOAD-BEARING: beyond `MAX_STALENESS_NS` the previous run is `Stale`, so a
/// saturation window SHORTER than it could fire on history the monitor has
/// already declared untrustworthy. They are separate pins and either may move,
/// but they may not drift apart silently.
#[test]
fn the_saturation_window_matches_the_staleness_bound() {
    assert_eq!(
        SATURATION_MIN_ELAPSED_NS, MAX_STALENESS_NS,
        "a saturation window shorter than the staleness bound would fire on history the \
         monitor has already called stale"
    );
}

/// Mutation-RED — the concentration multiple.
#[test]
fn concentration_multiple_is_pinned_at_two() {
    assert_eq!(CONCENTRATION_MULTIPLE, 2);
}

/// Mutation-RED — the concentration sample floor, ABSOLUTE.
#[test]
fn concentration_min_sample_is_pinned_at_ten() {
    assert_eq!(
        CONCENTRATION_MIN_SAMPLE, 10,
        "absolute, not derived: deriving it from BUDGET / QUOTA collapsed it to 4"
    );
}

/// **The relation the collapsed derivation would have failed.**
///
/// A GUARD, NOT A DERIVATION (§1): the sample floor must be reachable within
/// one window's fleet capacity, or the concentration rule could never be
/// evaluated at all. Checked against the vetkeys SOURCE, so a budget re-pin
/// that made the rule unreachable fails here instead of going quiet.
#[test]
fn the_concentration_sample_floor_is_reachable_within_one_window() {
    let budget = vetkeys_pin("GLOBAL_DERIVE_BUDGET");
    assert!(
        CONCENTRATION_MIN_SAMPLE as u128 <= budget,
        "the concentration rule needs {CONCENTRATION_MIN_SAMPLE} tagged observations, but the \
         fleet budget admits only {budget} per window — the rule would never be evaluated"
    );
}

/// Mutation-RED — the refusal-spike threshold, read off the ratified B = 20
/// Erlang-B table. The table figures are written out here as their own
/// literals (in milli-refusals/hour, to stay integer), so the derivation is
/// checkable rather than a claim in a comment.
#[test]
fn refusal_spike_is_pinned_at_five_per_hour() {
    assert_eq!(REFUSAL_SPIKE_PER_HOUR, 5);

    // Ratified B = 20 table, ×1000: λ = 10 → 19, λ = 15 → 684, λ = 20 → 3178,
    // λ = 25 → 6997 refusals/hour.
    let (at_offered_equal_to_budget, at_offered_above_budget) = (3_178u32, 6_997u32);
    let threshold_milli = REFUSAL_SPIKE_PER_HOUR * 1_000;
    assert!(
        threshold_milli > at_offered_equal_to_budget,
        "the threshold must sit ABOVE the rate produced when offered load merely EQUALS the \
         budget, or normal saturation would alert"
    );
    assert!(
        threshold_milli < at_offered_above_budget,
        "and BELOW the rate at λ = 25, or sustained over-ceiling load would not alert"
    );
}

// ── §6.7 — the funding-wave rule ─────────────────────────────────────────────

/// Mutation-RED — the funding-wave threshold, pinned ABSOLUTELY at 100 with its
/// meaning stated: at least as many principals began aging in this hour as the
/// fleet can admit in an hour. Re-derived on that meaning for the ratified
/// B = 100 (LAUNCH-HARDEN-04 O-3; was 20 at B = 20).
#[test]
fn funding_wave_is_pinned_at_one_hundred_per_hour() {
    assert_eq!(FUNDING_WAVE_PER_HOUR, 100);
}

/// **§7.2 relation arm — REACHABILITY, not derivation (SSA GREEN-5).**
///
/// A threshold BELOW fleet capacity would alert on traffic the fleet can
/// absorb; the relation states the floor, and the pin above states the value.
/// If the budget is re-pinned, this value is re-derived on its MEANING — never
/// rescaled by arithmetic, which is the mistake that collapsed
/// `CONCENTRATION_MIN_SAMPLE`.
#[test]
fn the_funding_wave_threshold_is_at_least_fleet_capacity() {
    let budget = vetkeys_pin("GLOBAL_DERIVE_BUDGET");
    assert!(
        FUNDING_WAVE_PER_HOUR as u128 >= budget,
        "a wave threshold ({FUNDING_WAVE_PER_HOUR}) below fleet capacity ({budget}) would alert \
         on load the fleet can absorb"
    );
}

// ── Persisted history pins ───────────────────────────────────────────────────

/// Mutation-RED — the rolling history span, as unit arithmetic.
#[test]
fn refusal_history_span_is_pinned_at_one_hour() {
    let one_hour_ns: u64 = 60 * 60 * 1_000_000_000;
    assert_eq!(REFUSAL_HISTORY_SPAN_NS, one_hour_ns);
}

/// Mutation-RED — the sample cap, plus the relation that makes it a cap rather
/// than a constraint: it must hold at least one full span at the shipped
/// cadence, or the rolling rules could never see a complete hour.
#[test]
fn the_history_cap_holds_at_least_a_full_span_at_the_shipped_cadence() {
    assert_eq!(REFUSAL_HISTORY_MAX_SAMPLES, 24);
    let samples_per_span = (REFUSAL_HISTORY_SPAN_NS / EXPECTED_INTERVAL_NS) as usize;
    assert_eq!(samples_per_span, 12, "one hour at the 5-minute cadence is twelve samples");
    assert!(
        REFUSAL_HISTORY_MAX_SAMPLES >= samples_per_span,
        "the cap must hold a full span, or a complete hour is never observable"
    );
}

// ── The pins are INDEPENDENT ────────────────────────────────────────────────

/// The canister's age pin and the monitor's 15-minute windows shared a number
/// BY COINCIDENCE (until VETKEYS-AGE-2MIN moved T) and must remain separate
/// declarations.
///
/// This arm is the anti-collapse guard: it proves the monitor's own window is
/// declared in the monitor, and the canister's age pin is declared in the
/// canister, so a future edit cannot quietly make one an alias of the other and
/// tie three unrelated policies to a single edit.
#[test]
fn the_age_pin_and_the_monitor_windows_are_separate_declarations() {
    let eligibility_min_age = vetkeys_pin("ELIGIBILITY_MIN_AGE_NS") as u64;
    assert_eq!(
        eligibility_min_age, 120_000_000_000,
        "T is 2 minutes (559b411e…, superseding the 15-minute value of 6b60d432…), \
         regenerated here as its own literal"
    );
    // They coincided until VETKEYS-AGE-2MIN (2026-09-22). The two pins have now
    // DIVERGED — T moved to 2 minutes, the monitor window stayed at 15 — which is
    // exactly the move this arm exists to make visible: they were never bound.
    assert_ne!(eligibility_min_age, SATURATION_MIN_ELAPSED_NS);
    assert!(
        VETKEYS_PINS_SRC.contains("pub const ELIGIBILITY_MIN_AGE_NS"),
        "the canister pin must remain its OWN declaration, never an alias of a monitor constant"
    );
}
