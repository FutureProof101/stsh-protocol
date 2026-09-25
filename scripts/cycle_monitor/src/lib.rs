//! A-6 / GAP-U9-1 — off-chain fleet cycle monitor.
//!
//! Watches the cycle balance of the spend-path canisters and alerts before any
//! of them can drift toward its freezing threshold.
//!
//! ── THE RULE THIS IS BUILT ON ────────────────────────────────────────────────
//!
//! **Absence must not read as health. An unverifiable input must not assert its
//! own freshness. Where the monitor cannot distinguish fine from broken, the
//! answer is the alerting one.**
//!
//! A monitor is the component whose failure is silent by construction: when it
//! breaks, nothing complains, because complaining was its job. Every input is
//! therefore treated as hostile by default —
//!
//!  1. missing input ⇒ alerting, unless a human has explicitly declared the
//!     absence expected;
//!  2. every externally supplied timestamp is validated before it is used in an
//!     age comparison — against the future, and against being absent;
//!  3. an age computation never yields "fresh" from an out-of-range input
//!     (checked/saturating arithmetic only);
//!  4. the tool never trusts its own history to prove its own liveness unless
//!     the operator has declared that the history is where it should be.
//!
//! All logic lives here, in the library, so every limb is gate-testable; the CLI
//! is a thin wrapper. That is what made `verify_genesis_manifest` fully
//! testable, and it is the pattern this crate follows.
//!
//! INTEGER ONLY. Cycles are integers and this campaign has no rounding to hide.

use serde::{Deserialize, Serialize};

// ── Shipped magnitudes (Rule 2 pins each) ────────────────────────────────────

/// `alert_threshold = freeze_reserve_cycles * ALERT_MULTIPLE`.
///
/// The reserve is what keeps a canister alive for its freezing window. Alerting
/// at 3× leaves roughly two further reserve-periods to notice, decide and top
/// up — enough for a human loop, tight enough not to alert constantly. It is a
/// judgement, so it is a named constant and a test pins it.
pub const ALERT_MULTIPLE: u128 = 3;

/// LAUNCH-HARDEN-04 O-4 (CTO addendum 2026-09-23): absolute alert floors, in
/// cycles, for the two canisters whose drain matters most and whose
/// freeze-reserve-derived threshold alone can sit too low. The effective
/// threshold is `max(freeze_reserve_cycles × ALERT_MULTIPLE, floor)`; the
/// boundary stays INCLUSIVE (`balance <= threshold` alerts), so a balance of
/// exactly the floor alerts. COMPILED IN, so operator config can never lower
/// them. The vetkeys 1 T floor is also the compensating control for the new
/// pool → vetkeys spend-path coupling (a stopped/drained vetkeys fails every
/// `private_spend` closed with DEVICE_CHECK_UNAVAILABLE).
pub const ABSOLUTE_ALERT_FLOORS: [(&str, u128); 2] =
    [("verifier", 500_000_000_000), ("vetkeys", 1_000_000_000_000)];

/// The compiled-in absolute floor for `name`, or `0` if it has none.
pub fn absolute_alert_floor(name: &str) -> u128 {
    ABSOLUTE_ALERT_FLOORS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
        .unwrap_or(0)
}

/// 30 days in nanoseconds. Beyond this a configured reserve is `RESERVE_STALE`.
///
/// The reserve is a function of `threshold_s` and idle burn, both deploy-time
/// settings that change only through a deliberate `update_settings`. Thirty days
/// bounds drift without generating churn. A silently stale reserve is a monitor
/// alerting on the wrong line, which is why this is a status and not a warning.
pub const MAX_RESERVE_AGE_NS: u64 = 2_592_000_000_000_000;

/// 5 minutes — the scheduled cadence, matching `smoke-alarm-monitor`'s
/// OPERATIONS.md. Reusing 5/15 is deliberate: an operator running two monitors
/// on two cadences will eventually run one of them wrong.
pub const EXPECTED_INTERVAL_NS: u64 = 300_000_000_000;

/// 15 minutes — beyond this the previous run is `STALE` (runs are being missed).
pub const MAX_STALENESS_NS: u64 = 900_000_000_000;

/// 1 minute of permitted forward clock skew.
pub const CLOCK_SKEW_TOLERANCE_NS: u64 = 60_000_000_000;

// ── C-26 observability pins (A1 fix brief V5 §1, §6.7, §7.2) ─────────────────
//
// FOUR RULES over the vetkeys `derive_budget_stats` surface — saturation,
// concentration, refusal spike, funding wave — evaluated in the EXISTING report
// section over the EXISTING query. One lane, no fork: a second query, state
// file or alert channel would be a second thing to forget to install.
//
// EVERY NUMBER HERE IS RE-DERIVED ON ITS MEANING, NEVER RESCALED. The lesson is
// specific and recent: deriving `CONCENTRATION_MIN_SAMPLE` from
// `GLOBAL_DERIVE_BUDGET / DERIVE_QUOTA` collapsed it to a meaningless 4 the
// moment the budget was re-pinned. An arithmetic tie between two pins that have
// no semantic relationship is an accident waiting for a re-pin.

/// Minimum elapsed time before the SATURATION rule may fire.
///
/// An ELAPSED-TIME rule, not a sample count, and that is the point: a
/// cadence-based rule silently changes meaning when the schedule changes, and
/// the schedule is an operator setting. Pinned to the same magnitude as
/// `MAX_STALENESS_NS` — beyond that the previous run is stale anyway, so a
/// window shorter than it could fire on a history the monitor has already
/// declared untrustworthy. Boundary: `899_999_999_999` does not fire,
/// `900_000_000_000` does.
pub const SATURATION_MIN_ELAPSED_NS: u64 = 900_000_000_000;

/// CONCENTRATION alert multiple: dispatches-per-distinct-principal at or above
/// this multiple of the organic mean. Integer arithmetic — this campaign has no
/// rounding to hide.
pub const CONCENTRATION_MULTIPLE: u32 = 2;

/// Minimum TAGGED observations before the concentration rule is evaluated at
/// all. **ABSOLUTE, and deliberately not derived from any other pin.**
///
/// Organic traffic is one derive per principal (`wallet/src/crypto/vetkeys.ts`;
/// recovery ≈0.83 %/month), so the organic mean is ≈1.00. A mean of 2.0 across
/// TEN observations needs five principals deriving twice, or two exhausting a
/// five-derive quota — a real signal. Across four it needs almost nothing,
/// which is what the discarded `BUDGET / QUOTA` derivation produced.
pub const CONCENTRATION_MIN_SAMPLE: u32 = 10;

/// REFUSAL SPIKE threshold: budget refusals in the rolling monitor hour at or
/// above which the rule alerts.
///
/// Read off the ratified B = 20 Erlang-B table: 0.019/h at λ = 10, 0.684/h at
/// λ = 15, 3.178/h at λ = 20 (offered load exactly equal to the budget), and
/// 6.997/h at λ = 25. Five therefore implies a trigger at λ ≈ 22/h — sustained
/// refusals at a rate only reachable when offered load EXCEEDS the ratified
/// ceiling. Evaluated over a genuine rolling 60-minute counter history, never a
/// five-minute sample annualized.
pub const REFUSAL_SPIKE_PER_HOUR: u32 = 5;

/// FUNDING WAVE threshold (V5 §6.7): alert when the rolling monitor hour
/// records AT LEAST this many new sightings. **The boundary is INCLUSIVE** —
/// 99 does not alert, 100 does.
///
/// MEANING, ON PURPOSE: at least as many principals began aging in this hour as
/// the fleet can admit in an hour. RE-DERIVED ON THAT MEANING (not rescaled) for
/// the Owner-ratified `GLOBAL_DERIVE_BUDGET = 100`
/// (LAUNCH-HARDEN-04 O-3, RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24): the
/// fleet admits 100 derives an hour, so the wave threshold is 100 (was 20 at
/// B = 20). Pinned ABSOLUTELY at 100 with that meaning stated; the `>= GLOBAL_DERIVE_BUDGET` relation is a REACHABILITY check, not
/// a derivation. This is a SEMANTIC tie, deliberately unlike the accidental
/// `BUDGET / QUOTA` tie that collapsed `CONCENTRATION_MIN_SAMPLE` — if the
/// budget is re-pinned this value is re-derived on its meaning, never rescaled.
///
/// A WARNING, NEVER A WALL, and quiet data is not exculpatory: the wave arrives
/// T ahead of the derive wave it predicts, which is the whole leading-indicator
/// value, but its absence proves nothing.
pub const FUNDING_WAVE_PER_HOUR: u32 = 100;

/// The span of persisted counter history the rolling-hour rules evaluate over
/// (1 h). A SEPARATE constant from `MAX_STALENESS_NS` and from the vetkeys
/// canister's own window: same family of magnitudes, different pins, any may
/// move alone.
pub const REFUSAL_HISTORY_SPAN_NS: u64 = 3_600_000_000_000;

/// Cap on persisted history samples. At the 5-minute cadence one hour is twelve
/// samples; 24 leaves a full hour of headroom for a faster schedule without
/// letting the state file grow without bound. A cap, not a target: fewer
/// samples than an hour's worth is `Incomplete`, never extrapolated.
pub const REFUSAL_HISTORY_MAX_SAMPLES: usize = 24;

// ── Statuses ─────────────────────────────────────────────────────────────────

/// Per-canister outcome. These deliberately do NOT collapse into one another:
/// each names a distinct operational condition with a distinct remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanisterStatus {
    /// Observed, STRICTLY above the alert threshold.
    CoveredHealthy,
    /// Observed, at or below the threshold — **this is the alert**.
    CoveredBelowThreshold,
    /// A source exists and was tried, and it failed.
    SourceFailed,
    /// No source exists yet for this canister. Distinct from `SourceFailed`:
    /// nothing broke, the coverage simply is not built — which must read as
    /// INCOMPLETE, never as health.
    ///
    /// C-18: the earlier wording said "and vetkeys until A-2 merges". A-2 has
    /// merged and `vetkeys::cycle_balance` ships, so that clause described a
    /// state the tree left behind. Comment-only — if any test moved with this
    /// edit, the edit was not comment-only.
    NotYetCovered,
    /// Reserve absent, zero, or overflowing when multiplied.
    ReserveMisconfigured,
    /// `reserve_observed_at_ns` older than `MAX_RESERVE_AGE_NS`.
    ReserveStale,
    /// `reserve_observed_at_ns` absent, or in the future beyond tolerance.
    ReserveTimestampInvalid,
}

/// RUN-LEVEL outcome — a property of the MONITOR, not of any canister.
///
/// Missed runs are deliberately not folded into a per-canister status: doing so
/// would misattribute a scheduler failure to the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    /// Prior snapshot within `MAX_STALENESS_NS`.
    Fresh,
    /// No state file AND `--allow-missing-state` given — a declared first run.
    NoPriorState,
    /// No state file and NO flag — history lost or scheduler re-pointed ⇒ ALERT.
    ///
    /// This is the case that used to be benign by default, which meant deleting
    /// the state file — or re-pointing the scheduler at a fresh path — erased
    /// the missed-run evidence and returned OK. The monitor's history was its
    /// only liveness input, and it was unauthenticated and destructible, so the
    /// cheapest way to silence this monitor was to remove a file.
    StateMissing,
    /// Prior snapshot older than `MAX_STALENESS_NS` — runs are being missed.
    Stale,
    /// State file present but unparseable — the previous outcome is unknown.
    StateUnreadable,
    /// Persisted `run_at_ns` in the future beyond tolerance. Fail closed: a
    /// backwards clock would otherwise suppress staleness forever.
    ClockSkew,
}

/// Aggregate verdict. Maps 1:1 onto the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Aggregate {
    Ok,
    Alert,
    Incomplete,
}

impl Aggregate {
    /// `watcher.ts` sets the precedent (exit 1 on any invariant failure).
    ///
    /// INCOMPLETE must NOT exit 0: a monitor that returns success while
    /// watching nothing is worse than no monitor — it manufactures the
    /// assurance it fails to provide. A distinct code lets an operator alert on
    /// 1 and track 2 without conflating them.
    pub fn exit_code(self) -> i32 {
        match self {
            Aggregate::Ok => 0,
            Aggregate::Alert => 1,
            Aggregate::Incomplete => 2,
        }
    }
}

// ── Config / observation ─────────────────────────────────────────────────────

/// One monitored canister, as configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanisterConfig {
    pub name: String,
    pub principal: Option<String>,
    /// The reserve, expressed in cycles. It is not a duration.
    ///
    /// The IC `freezing_threshold` setting is a duration in seconds and
    /// `balance` is cycles; their product is not a quantity. Deriving the
    /// reserve on the fly needs `idle_cycles_burned_per_day` from
    /// `canister_status`, which requires controller rights — the exact wall that
    /// moved this monitor off-chain. So config supplies it, with provenance.
    pub freeze_reserve_cycles: Option<u128>,
    /// How the number was obtained. Required, non-empty.
    pub reserve_provenance: Option<String>,
    /// When it was obtained. Drives the refresh contract.
    pub reserve_observed_at_ns: Option<u64>,
}

/// WHY a live balance read failed.
///
/// A-6c. Before this lane `Observation::Failed` carried no detail and
/// `classify_canister` wrote one fixed sentence for every cause, so an operator
/// reading the report could not tell a config typo from a dead replica from a
/// canister that had changed shape. Each kind below has a DIFFERENT remedy, so
/// each is a distinct machine-readable `reason`.
///
/// `Copy`, so `Observation` stays `Copy` and the deterministic suite's
/// `Fixed(Observation)` source keeps compiling unchanged.
///
/// Every kind maps to `CanisterStatus::SourceFailed`, hence to
/// `Aggregate::Alert`. The DISTINCTION is carried in `reason`, never in the
/// aggregate — so no new status, no `Snapshot` schema movement, and a state
/// file written by the previous build still parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Config supplies no principal (or an empty one) for a registered
    /// canister. An OPERATOR error; the fix is the config file.
    ///
    /// This must NEVER read as `NotYetCovered`: after A-6c a source EXISTS, so
    /// an unconfigured canister is a failure to watch it, not an absence of
    /// coverage — Alert (exit 1), never Incomplete (exit 2), never healthy.
    PrincipalMissing,
    /// The principal string is present but is not a valid principal.
    PrincipalUnparseable,
    /// The query did not complete — network, replica down, HTTP error.
    /// An ENVIRONMENT problem, possibly transient.
    Transport,
    /// A reply came back but did not decode as candid `nat`.
    /// An INTERFACE problem — the canister changed shape.
    ReplyUndecodable,
    /// The reply decoded as a valid `nat` that does not fit `u128`.
    ///
    /// Kept separate from `ReplyUndecodable` because the remedy differs and
    /// because this is the limb that must never silently truncate: a truncated
    /// value landing under the threshold alerts spuriously, and one landing
    /// above it MANUFACTURES health. Neither is acceptable, so the conversion is
    /// checked and its failure is observable.
    BalanceExceedsU128,
}

impl FailureKind {
    /// The machine-readable `reason` for this kind. One value per kind — this
    /// is what makes the four operator-distinguishable failures distinguishable.
    pub fn reason(self) -> &'static str {
        match self {
            FailureKind::PrincipalMissing => {
                "balance source failed: no principal configured for this canister"
            }
            FailureKind::PrincipalUnparseable => {
                "balance source failed: configured principal is not a valid principal"
            }
            FailureKind::Transport => {
                "balance source failed: cycle_balance query did not complete (transport)"
            }
            FailureKind::ReplyUndecodable => {
                "balance source failed: cycle_balance reply did not decode as candid nat"
            }
            FailureKind::BalanceExceedsU128 => {
                "balance source failed: cycle_balance nat exceeds u128 (refusing to truncate)"
            }
        }
    }
}

/// What a balance source returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The source produced a balance.
    Balance(u128),
    /// A source exists and was tried, and it failed — carrying WHY (A-6c).
    Failed(FailureKind),
    /// No source is wired for this canister yet.
    NotWired,
}

/// The balance source is INJECTED (Rule 7) rather than hardcoded, so every limb
/// is deterministically drivable in tests.
///
/// C-18: the earlier wording said no live caller was wired because
/// `cycle_balance` did not exist at the pinned base and vetkeys' lived only in
/// A-2's unmerged worktree. A-2 has merged and `vetkeys::cycle_balance` ships,
/// so the Rule-7 blocker it described is gone; injection remains because it is
/// what makes every limb drivable, not because of an unmerged artifact.
/// Comment-only.
pub trait BalanceSource {
    fn balance_of(&self, canister: &CanisterConfig) -> Observation;
}

// ── Report ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanisterReport {
    pub canister: String,
    pub principal: Option<String>,
    pub balance: Option<u128>,
    pub freeze_reserve_cycles: Option<u128>,
    pub reserve_provenance: Option<String>,
    pub reserve_observed_at_ns: Option<u64>,
    pub alert_threshold: Option<u128>,
    pub status: CanisterStatus,
    /// The branch-specific observable — one machine-readable value per status.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub run_at_ns: u64,
    pub run_status: RunStatus,
    pub aggregate: Aggregate,
    pub canisters: Vec<CanisterReport>,
    /// The C-26 derive-budget section (§4, §6.7).
    ///
    /// `#[serde(default)]` on EVERY new persisted field, without exception: a
    /// state file written by the previous release must still parse, or the
    /// upgrade that adds a rule is also the upgrade that blinds the monitor to
    /// its own history — which is the one input it has for its own liveness.
    #[serde(default)]
    pub budget: Option<DeriveBudgetReport>,
}

/// The prior run's persisted snapshot, as read from `--state`.
///
/// `Present` now carries the prior BUDGET SECTION as well as `run_at_ns`: three
/// of the four C-26 rules are about change over time (elapsed saturation, and
/// two rolling-hour counters), and a single run cannot observe duration. The
/// history is the evidence, and it lives in the state file.
///
/// `Option<DeriveBudgetReport>`, because `None` is a real state and not an
/// error: a file written before this section existed parses with `None` and the
/// rules start accumulating afresh, reporting `Incomplete` until they have a
/// full span. That is the truthful reading, and it is why the field is
/// `#[serde(default)]`.
#[derive(Debug, Clone)]
pub enum PriorState {
    /// Parsed, carrying its `run_at_ns` and its budget section.
    Present { run_at_ns: u64, budget: Option<DeriveBudgetReport> },
    /// No file at the path.
    Absent,
    /// File present but unparseable.
    Unreadable,
}

// ── Logic ────────────────────────────────────────────────────────────────────

/// Classify one canister.
///
/// ORDER MATTERS and is deliberate: reserve validity is checked BEFORE the
/// balance comparison, because a threshold computed from an absent, zero, stale
/// or unvalidated reserve is a threshold on the wrong line — and reporting
/// `CoveredHealthy` against a wrong line is exactly "absence reading as health".
pub fn classify_canister(
    cfg: &CanisterConfig,
    obs: Observation,
    now_ns: u64,
) -> CanisterReport {
    let mut report = CanisterReport {
        canister: cfg.name.clone(),
        principal: cfg.principal.clone(),
        balance: None,
        freeze_reserve_cycles: cfg.freeze_reserve_cycles,
        reserve_provenance: cfg.reserve_provenance.clone(),
        reserve_observed_at_ns: cfg.reserve_observed_at_ns,
        alert_threshold: None,
        status: CanisterStatus::NotYetCovered,
        reason: String::new(),
    };

    // (0) COVERAGE STATE SHORT-CIRCUITS.
    //
    // If no source is wired, or the source failed, there is no balance to
    // compare against any line — so validating the reserve first would report
    // RESERVE_MISCONFIGURED for a canister whose actual problem is that nothing
    // queries it. That misattributes the cause and sends an operator to fix the
    // wrong thing. Coverage is reported first; reserve validity is only
    // meaningful once there IS an observation to judge.
    //
    // The "a wrong line must never read as healthy" property is unaffected:
    // CoveredHealthy is reachable only past every reserve check below.
    match obs {
        Observation::NotWired => {
            report.status = CanisterStatus::NotYetCovered;
            report.reason = "no balance source wired for this canister yet".to_string();
            return report;
        }
        Observation::Failed(kind) => {
            report.status = CanisterStatus::SourceFailed;
            // A-6c: the branch-specific observable, per kind. Every kind still
            // routes to SourceFailed => Alert; only the reason discriminates.
            report.reason = kind.reason().to_string();
            return report;
        }
        Observation::Balance(_) => {}
    }

    // (1) Reserve present, non-zero, and with provenance.
    let Some(reserve) = cfg.freeze_reserve_cycles.filter(|r| *r > 0) else {
        report.status = CanisterStatus::ReserveMisconfigured;
        report.reason = "freeze_reserve_cycles absent or zero".to_string();
        return report;
    };
    if cfg.reserve_provenance.as_ref().map_or(true, |p| p.trim().is_empty()) {
        report.status = CanisterStatus::ReserveMisconfigured;
        report.reason = "reserve_provenance absent or empty".to_string();
        return report;
    }

    // (2) The reserve timestamp is VALIDATED before any age comparison.
    let Some(observed_at) = cfg.reserve_observed_at_ns else {
        report.status = CanisterStatus::ReserveTimestampInvalid;
        report.reason = "reserve_observed_at_ns absent".to_string();
        return report;
    };
    if observed_at > now_ns.saturating_add(CLOCK_SKEW_TOLERANCE_NS) {
        report.status = CanisterStatus::ReserveTimestampInvalid;
        report.reason = format!("reserve_observed_at_ns {observed_at} is in the future (now {now_ns})");
        return report;
    }
    // saturating_sub: an out-of-range input can never present as a small age.
    if now_ns.saturating_sub(observed_at) > MAX_RESERVE_AGE_NS {
        report.status = CanisterStatus::ReserveStale;
        report.reason = format!(
            "reserve observed {} ns ago, older than MAX_RESERVE_AGE_NS {}",
            now_ns.saturating_sub(observed_at),
            MAX_RESERVE_AGE_NS
        );
        return report;
    }

    // (3) The threshold. Overflow fails CLOSED — a reserve that overflows u128
    //     when tripled is not a real figure.
    let Some(threshold) = reserve.checked_mul(ALERT_MULTIPLE) else {
        report.status = CanisterStatus::ReserveMisconfigured;
        report.reason = format!("freeze_reserve_cycles {reserve} * {ALERT_MULTIPLE} overflows u128");
        return report;
    };
    // LAUNCH-HARDEN-04 O-4: never below the compiled-in absolute floor.
    let threshold = threshold.max(absolute_alert_floor(&cfg.name));
    report.alert_threshold = Some(threshold);

    // (4) The comparison. Only a real observation reaches here.
    match obs {
        // Unreachable: both short-circuited at (0). Kept explicit rather than a
        // wildcard so a new Observation variant fails to compile here.
        Observation::NotWired | Observation::Failed(_) => unreachable!(
            "coverage states short-circuit at step (0)"
        ),
        Observation::Balance(balance) => {
            report.balance = Some(balance);
            // BOUNDARY IS INCLUSIVE: balance <= threshold alerts. Stated here as
            // well as in the brief — a boundary left to inference is a boundary
            // that drifts.
            if balance <= threshold {
                report.status = CanisterStatus::CoveredBelowThreshold;
                report.reason = format!("balance {balance} <= alert_threshold {threshold}");
            } else {
                report.status = CanisterStatus::CoveredHealthy;
                report.reason = format!("balance {balance} > alert_threshold {threshold}");
            }
        }
    }
    report
}

/// Classify the RUN from the prior state.
pub fn classify_run(prior: PriorState, allow_missing_state: bool, now_ns: u64) -> RunStatus {
    match prior {
        PriorState::Unreadable => RunStatus::StateUnreadable,
        PriorState::Absent => {
            if allow_missing_state {
                RunStatus::NoPriorState
            } else {
                RunStatus::StateMissing
            }
        }
        PriorState::Present { run_at_ns: run_at, .. } => {
            if run_at > now_ns.saturating_add(CLOCK_SKEW_TOLERANCE_NS) {
                RunStatus::ClockSkew
            } else if now_ns.saturating_sub(run_at) > MAX_STALENESS_NS {
                RunStatus::Stale
            } else {
                RunStatus::Fresh
            }
        }
    }
}

/// The aggregate mapping — EXHAUSTIVE over both status enums.
///
/// Amended by `CTO_ADDENDUM_A-6_aggregate_mapping.md` to include
/// `ReserveTimestampInvalid` and `StateMissing`, which V5 defined as alerting
/// conditions in their status tables but omitted from this enumeration.
///
/// Every status appears in exactly one arm. The `match` is deliberately
/// wildcard-free: a status added later fails to compile here rather than
/// silently falling through to OK.
pub fn aggregate(reports: &[CanisterReport], run_status: RunStatus) -> Aggregate {
    let run_alerts = match run_status {
        RunStatus::Stale
        | RunStatus::StateUnreadable
        | RunStatus::ClockSkew
        | RunStatus::StateMissing => true,
        RunStatus::Fresh | RunStatus::NoPriorState => false,
    };
    if run_alerts {
        return Aggregate::Alert;
    }

    let mut any_incomplete = false;
    for r in reports {
        match r.status {
            CanisterStatus::CoveredBelowThreshold
            | CanisterStatus::SourceFailed
            | CanisterStatus::ReserveMisconfigured
            | CanisterStatus::ReserveStale
            | CanisterStatus::ReserveTimestampInvalid => return Aggregate::Alert,
            CanisterStatus::NotYetCovered => any_incomplete = true,
            CanisterStatus::CoveredHealthy => {}
        }
    }
    if any_incomplete {
        return Aggregate::Incomplete;
    }
    Aggregate::Ok
}


// ═════════════════════════════════════════════════════════════════════════════
// C-26 — THE DERIVE-BUDGET RULES (A1 fix brief V5 §4, §6.7)
// ═════════════════════════════════════════════════════════════════════════════
//
// ONE LANE, NO FORK (§6.7): the funding-wave rule is evaluated in the SAME
// report section, over the SAME query, as the other three. A second query, a
// second state file or a second alert channel would be a second thing an
// operator can forget to install — and a monitor nobody installed is the
// failure mode this whole crate is built against.
//
// THE RULE THIS SECTION INHERITS. Absence must not read as health. Every limb
// below that cannot be evaluated returns `Incomplete`, never `Ok`: a partial
// history is not extrapolated, an epoch change is not a rate, and an
// unreachable canister is not a quiet one.
//
// AND THE OPERATIONAL POINT, because the numbers alone do not carry it: these
// rules distinguish ORGANIC growth from an ATTACK, and the correct response
// differs. Organic → the graduation artifact. Adversarial → sitting out is
// SAFE; do NOT reflexively top up, because raising the budget during an attack
// funds the attacker.

/// One sample of a monotonic counter, with the epoch it was read under.
///
/// THE EPOCH IS NOT DECORATION. The canister's counters are ephemeral heap and
/// reset on upgrade. Differencing across a reset would read the restart as a
/// rate falling to zero — or, worse, a wrap as an enormous spike. A sample from
/// a different epoch is DROPPED, never differenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSample {
    pub at_ns: u64,
    pub value: u64,
    pub epoch_ns: u64,
}

/// What the derive-budget query returned this run.
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetObservation {
    /// The query answered.
    Stats(DeriveBudgetStats),
    /// A source exists and was tried, and it failed.
    Failed(String),
    /// No source is wired for the budget query yet.
    NotWired,
}

/// The monitor's view of the canister's `derive_budget_stats` reply.
///
/// Mirrors the DID INDEPENDENTLY of the canister crate — `canisters/vetkeys` is
/// workspace-excluded and this crate cannot depend on it, and a shared type
/// would in any case let a canister-side field rename pass unnoticed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, candid::CandidType)]
pub struct DeriveBudgetStats {
    pub window_ns: u64,
    pub budget: u32,
    pub consumed: u32,
    pub retry_after_ns: u64,
    pub tagged_consumed: u32,
    pub distinct_principals: u32,
    pub max_by_one_principal: u32,
    pub first_derive_dispatches: u32,
    pub refusals_budget_total: u64,
    pub stats_epoch_ns: u64,
    pub floor: CycleFloorView,
    pub sightings_recorded_total: u64,
    pub age_refusals_total: u64,
    pub sightings_pending: u32,
}

/// The cycle-floor reading, mirrored from the DID.
///
/// `FloorOnly` carries a verdict, not a magnitude: `meets_pinned_floor == false`
/// is a DEFINITE below-floor condition and alerts; `true` means the reserve
/// floor is met with the cost component unavailable, which is coverage, not
/// admission. `Unavailable` is neither — it is Incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, candid::CandidType)]
pub enum CycleFloorView {
    Live { admits: bool },
    FloorOnly { meets_pinned_floor: bool, reason: String },
    Unavailable(String),
}

/// The budget query source is INJECTED, exactly as `BalanceSource` is, so every
/// limb below is deterministically drivable without a canister.
pub trait DeriveBudgetSource {
    fn budget_stats(&self) -> BudgetObservation;
}

/// One rule's outcome. `Incomplete` is a first-class result, not an error:
/// "this rule could not be evaluated" is different from "this rule found
/// nothing", and collapsing them is how a monitor reports health it never
/// established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOutcome {
    Quiet,
    Alert,
    Incomplete,
    /// The rule's precondition is not met yet — a sample floor, a history span.
    /// Distinct from `Incomplete`: nothing is broken, there is simply not
    /// enough evidence YET, and that is the truthful thing to report.
    NotEvaluated,
}

/// The four rules, plus the floor limb, as one report section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveBudgetReport {
    pub saturation: RuleOutcome,
    pub concentration: RuleOutcome,
    pub refusal_spike: RuleOutcome,
    pub funding_wave: RuleOutcome,
    pub floor: RuleOutcome,
    /// Set while the fleet has been continuously saturated; cleared the moment
    /// it is not. Persisted, because the rule is about ELAPSED TIME and a
    /// single run cannot observe duration.
    #[serde(default)]
    pub first_saturated_at_ns: Option<u64>,
    #[serde(default)]
    pub refusal_history: Vec<CounterSample>,
    #[serde(default)]
    pub sighting_history: Vec<CounterSample>,
    /// The branch-specific observable, one machine-readable line per rule.
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// Append a sample and trim to the pinned span and cap.
///
/// EPOCH REGRESSION DROPS HISTORY. On a new epoch every earlier sample belongs
/// to a counter that no longer exists; keeping them would produce a difference
/// that is not a rate. The new sample becomes the baseline and the rule reports
/// `Incomplete` until a full span has accumulated again.
fn push_sample(history: &mut Vec<CounterSample>, sample: CounterSample) {
    if history.last().is_some_and(|prev| prev.epoch_ns != sample.epoch_ns) {
        history.clear();
    }
    history.push(sample);
    let horizon = sample.at_ns.saturating_sub(REFUSAL_HISTORY_SPAN_NS);
    history.retain(|s| s.at_ns >= horizon);
    while history.len() > REFUSAL_HISTORY_MAX_SAMPLES {
        history.remove(0);
    }
}

/// The rise of a counter across a FULL span, or `None` if the history does not
/// yet cover one.
///
/// `None` is `Incomplete`, never zero and never extrapolated: a partial window
/// scaled up to an hour is a number the monitor invented.
fn rise_over_full_span(history: &[CounterSample]) -> Option<u64> {
    let newest = history.last()?;
    let oldest = history.first()?;
    if newest.epoch_ns != oldest.epoch_ns {
        return None;
    }
    if newest.at_ns.saturating_sub(oldest.at_ns) < REFUSAL_HISTORY_SPAN_NS {
        return None;
    }
    // Saturating: a counter that went BACKWARDS inside one epoch cannot happen,
    // and reporting a huge rise for it would be worse than reporting none.
    Some(newest.value.saturating_sub(oldest.value))
}

/// Evaluate all four rules plus the floor limb (§4, §6.7).
pub fn evaluate_budget_rules(
    obs: &BudgetObservation,
    prior: Option<&DeriveBudgetReport>,
    now_ns: u64,
) -> DeriveBudgetReport {
    let mut reasons = Vec::new();
    let stats = match obs {
        BudgetObservation::NotWired => {
            reasons.push("no derive-budget source wired yet".to_string());
            return incomplete_report(reasons);
        }
        BudgetObservation::Failed(why) => {
            reasons.push(format!("derive-budget query failed: {why}"));
            return incomplete_report(reasons);
        }
        BudgetObservation::Stats(s) => s,
    };

    // ── The floor limb (§3): every platform outcome has a mapping ────────────
    let floor = match &stats.floor {
        CycleFloorView::Live { admits: true } => RuleOutcome::Quiet,
        CycleFloorView::Live { admits: false } => {
            reasons.push("cycle floor: the live verdict REFUSES — derives are paused".to_string());
            RuleOutcome::Alert
        }
        // A definite below-floor condition, even though the cost component is
        // unavailable. This is the reading SSA RED-1 exists to preserve.
        CycleFloorView::FloorOnly { meets_pinned_floor: false, reason } => {
            reasons.push(format!(
                "cycle floor: liquid balance is BELOW the pinned floor (price unavailable: \
                 {reason})"
            ));
            RuleOutcome::Alert
        }
        // Floor met, cost unknown. NOT proof that a derive admits — reported as
        // Incomplete rather than Quiet, because the admission question was not
        // answered.
        CycleFloorView::FloorOnly { meets_pinned_floor: true, reason } => {
            reasons.push(format!(
                "cycle floor: reserve floor met, but the live derive price is unavailable \
                 ({reason}) — coverage, not an admission verdict"
            ));
            RuleOutcome::Incomplete
        }
        CycleFloorView::Unavailable(reason) => {
            reasons.push(format!("cycle floor: position could not be established ({reason})"));
            RuleOutcome::Incomplete
        }
    };

    // ── Rule 1 — SATURATION, on ELAPSED TIME ────────────────────────────────
    //
    // An elapsed-time rule, not a sample count: a cadence-based rule silently
    // changes meaning when the schedule changes, and the schedule is an
    // operator setting.
    let saturated_now = stats.consumed >= stats.budget;
    let first_saturated_at_ns = match (saturated_now, prior.and_then(|p| p.first_saturated_at_ns)) {
        (true, Some(since)) => Some(since),
        (true, None) => Some(now_ns),
        // Cleared the moment the fleet is not saturated — the rule is about a
        // CONTINUOUS condition, and a stale mark would alert on a gap.
        (false, _) => None,
    };
    let saturation = match first_saturated_at_ns {
        None => RuleOutcome::Quiet,
        Some(since) => {
            let elapsed = now_ns.saturating_sub(since);
            if elapsed >= SATURATION_MIN_ELAPSED_NS {
                reasons.push(format!(
                    "saturation: the fleet has been at or over its budget ({}/{}) for {elapsed} \
                     ns",
                    stats.consumed, stats.budget
                ));
                RuleOutcome::Alert
            } else {
                RuleOutcome::Quiet
            }
        }
    };

    // ── Rule 2 — CONCENTRATION, over the TAGGED subset only ─────────────────
    //
    // Untagged V1 carry has no principal, so including it would compute a mean
    // over a denominator it does not belong to.
    let concentration = if stats.tagged_consumed < CONCENTRATION_MIN_SAMPLE {
        RuleOutcome::NotEvaluated
    } else if stats.distinct_principals == 0 {
        // Short-circuit: tagged dispatches with no distinct principals is not a
        // division to attempt, and it is not evidence either.
        RuleOutcome::NotEvaluated
    } else if stats.tagged_consumed >= CONCENTRATION_MULTIPLE * stats.distinct_principals {
        reasons.push(format!(
            "concentration: {} tagged dispatches across {} principals is at or above {}× the \
             organic mean of one derive per principal",
            stats.tagged_consumed, stats.distinct_principals, CONCENTRATION_MULTIPLE
        ));
        RuleOutcome::Alert
    } else {
        RuleOutcome::Quiet
    };

    // ── Rules 3 and 4 — the rolling-hour counters ───────────────────────────
    let mut refusal_history = prior.map(|p| p.refusal_history.clone()).unwrap_or_default();
    push_sample(
        &mut refusal_history,
        CounterSample {
            at_ns: now_ns,
            value: stats.refusals_budget_total,
            epoch_ns: stats.stats_epoch_ns,
        },
    );
    let refusal_spike = match rise_over_full_span(&refusal_history) {
        None => RuleOutcome::Incomplete,
        Some(rise) if rise >= REFUSAL_SPIKE_PER_HOUR as u64 => {
            reasons.push(format!(
                "refusal spike: {rise} budget refusals in the rolling hour, at or above the \
                 threshold of {REFUSAL_SPIKE_PER_HOUR} — offered load is over the ratified \
                 ceiling"
            ));
            RuleOutcome::Alert
        }
        Some(_) => RuleOutcome::Quiet,
    };

    let mut sighting_history = prior.map(|p| p.sighting_history.clone()).unwrap_or_default();
    push_sample(
        &mut sighting_history,
        CounterSample {
            at_ns: now_ns,
            value: stats.sightings_recorded_total,
            epoch_ns: stats.stats_epoch_ns,
        },
    );
    // INCLUSIVE at the threshold (SSA GREEN-5): 99 does not alert, 100 does.
    // "At least as many principals began aging in this hour as the fleet can
    // admit in an hour" — a semantic tie, re-derived on its meaning if the
    // budget is re-pinned, never rescaled by arithmetic.
    let funding_wave = match rise_over_full_span(&sighting_history) {
        None => RuleOutcome::Incomplete,
        Some(rise) if rise >= FUNDING_WAVE_PER_HOUR as u64 => {
            reasons.push(format!(
                "funding wave: {rise} new age-in periods began in the rolling hour, at or above \
                 fleet capacity ({FUNDING_WAVE_PER_HOUR}/h). This is a LEADING indicator — the \
                 derive wave it predicts arrives one age-window later. Triage: a known growth \
                 event routes to the graduation artifact; no known growth event routes to \
                 ledger corroboration. It is a WARNING, never a wall, and quiet data is not \
                 exculpatory."
            ));
            RuleOutcome::Alert
        }
        Some(_) => RuleOutcome::Quiet,
    };

    DeriveBudgetReport {
        saturation,
        concentration,
        refusal_spike,
        funding_wave,
        floor,
        first_saturated_at_ns,
        refusal_history,
        sighting_history,
        reasons,
    }
}

fn incomplete_report(reasons: Vec<String>) -> DeriveBudgetReport {
    DeriveBudgetReport {
        saturation: RuleOutcome::Incomplete,
        concentration: RuleOutcome::Incomplete,
        refusal_spike: RuleOutcome::Incomplete,
        funding_wave: RuleOutcome::Incomplete,
        floor: RuleOutcome::Incomplete,
        first_saturated_at_ns: None,
        refusal_history: Vec::new(),
        sighting_history: Vec::new(),
        reasons,
    }
}

impl DeriveBudgetReport {
    /// This section's contribution to the run verdict.
    ///
    /// `CanisterStatus` is deliberately NOT overloaded (§4): these are
    /// properties of the FLEET's admission behaviour, not of any one canister's
    /// cycle balance, and folding them into a per-canister status would
    /// misattribute a fleet condition to whichever canister happened to be
    /// listed first.
    pub fn aggregate(&self) -> Aggregate {
        let outcomes = [
            &self.saturation,
            &self.concentration,
            &self.refusal_spike,
            &self.funding_wave,
            &self.floor,
        ];
        if outcomes.iter().any(|o| **o == RuleOutcome::Alert) {
            return Aggregate::Alert;
        }
        if outcomes.iter().any(|o| **o == RuleOutcome::Incomplete) {
            return Aggregate::Incomplete;
        }
        // `NotEvaluated` is NOT Incomplete: a rule waiting for its sample floor
        // is working correctly, and reporting the whole run as indeterminate
        // every hour with light traffic would train an operator to ignore it.
        Aggregate::Ok
    }
}

/// Run the monitor over a configured fleet.
pub fn run<S: BalanceSource>(
    configs: &[CanisterConfig],
    source: &S,
    prior: PriorState,
    allow_missing_state: bool,
    now_ns: u64,
) -> Snapshot {
    run_with_budget(configs, source, &NoBudgetSource, prior, allow_missing_state, now_ns)
}

/// A deployment with no budget query wired yet. `NotWired` ⇒ Incomplete, never
/// Ok — the register's own rule, applied to this section.
pub struct NoBudgetSource;
impl DeriveBudgetSource for NoBudgetSource {
    fn budget_stats(&self) -> BudgetObservation {
        BudgetObservation::NotWired
    }
}

/// Run the monitor over a configured fleet AND the C-26 budget rules.
pub fn run_with_budget<S: BalanceSource, B: DeriveBudgetSource>(
    configs: &[CanisterConfig],
    source: &S,
    budget_source: &B,
    prior: PriorState,
    allow_missing_state: bool,
    now_ns: u64,
) -> Snapshot {
    let canisters: Vec<CanisterReport> = configs
        .iter()
        .map(|c| classify_canister(c, source.balance_of(c), now_ns))
        .collect();
    let prior_budget = match &prior {
        PriorState::Present { budget, .. } => budget.clone(),
        _ => None,
    };
    let budget =
        evaluate_budget_rules(&budget_source.budget_stats(), prior_budget.as_ref(), now_ns);
    let run_status = classify_run(prior, allow_missing_state, now_ns);
    // The fleet verdict is the WORST of the two sections. A budget alert must
    // not be masked by healthy cycle balances, and vice versa: they describe
    // different failures with different remedies.
    let aggregate = worst(aggregate(&canisters, run_status), budget.aggregate());
    Snapshot { run_at_ns: now_ns, run_status, aggregate, canisters, budget: Some(budget) }
}

/// Alert beats Incomplete beats Ok. Ordered so that adding a section can only
/// ever make the verdict MORE alarming, never less.
fn worst(a: Aggregate, b: Aggregate) -> Aggregate {
    let rank = |x: Aggregate| match x {
        Aggregate::Ok => 0,
        Aggregate::Incomplete => 1,
        Aggregate::Alert => 2,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// The shipped monitoring register — the five spend-path canisters plus vetkeys.
///
/// IN THE LIBRARY, not a config file, deliberately: the lane's fence is six
/// paths and a shipped register file would be a seventh. Keeping it here also
/// means the honest end state of this lane is a compiled-in fact rather than a
/// deployment artifact someone can forget to install.
///
/// An entry with no wired source reports `NOT_YET_COVERED`, so a run over an
/// unwired register exits 2 (INCOMPLETE) — the truthful answer, and exactly why
/// INCOMPLETE must not exit 0.
///
/// C-18: the earlier wording asserted that `cycle_balance` did not exist at the
/// pinned base for any of the six and that vetkeys' lived only in an unmerged
/// worktree. Both ceased to be true when A-2 merged. Comment-only — the
/// register's contents and every test over it are unchanged.
pub fn shipped_register() -> Vec<CanisterConfig> {
    ["shielded_pool", "verifier", "nullifier_registry", "merkle_tree", "token", "vetkeys"]
        .into_iter()
        .map(|name| CanisterConfig {
            name: name.to_string(),
            principal: None,
            freeze_reserve_cycles: None,
            reserve_provenance: None,
            reserve_observed_at_ns: None,
        })
        .collect()
}

/// DERIVE the monitored fleet from the compiled-in register (SSA-A6-D5,
/// `CTO_RULING_A-6_register_derives.md`).
///
/// **Membership is a fact of the binary, not an input.** The executable iterates
/// `shipped_register()`; config supplies per-canister PARAMETERS keyed by that
/// identity. Validation — checking that a supplied list is right — can be
/// defeated by supplying a different list; derivation cannot, because the caller
/// never gets to say who is watched.
///
/// This is §4.0's rule applied to **the register itself** — the input that
/// decides whether any other input is ever evaluated. V1 applied "absence must
/// not read as health" to the state file, the reserve timestamp and source
/// failures, but not to the root of the tree, so an empty config produced an
/// empty report and `OK` vacuously.
///
/// - unknown key in config ⇒ **Err**, fail-closed (a typo must not silently
///   shrink or misdirect the watched set);
/// - missing key for a known canister ⇒ that canister is still monitored, with
///   no parameters, so it reports `RESERVE_MISCONFIGURED` — never healthy.
pub fn derive_fleet(params: &[CanisterConfig]) -> Result<Vec<CanisterConfig>, String> {
    let register = shipped_register();

    for p in params {
        if !register.iter().any(|r| r.name == p.name) {
            return Err(format!(
                "config supplies parameters for unknown canister {} — the monitored fleet is \
                 compiled in and config cannot add to it. Known: {}",
                p.name,
                register.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for p in params {
        if seen.contains(&p.name.as_str()) {
            return Err(format!("config supplies parameters for {} more than once", p.name));
        }
        seen.push(&p.name);
    }

    // Iterate the REGISTER, not the config. This is the whole ruling.
    Ok(register
        .into_iter()
        .map(|r| match params.iter().find(|p| p.name == r.name) {
            Some(p) => CanisterConfig { name: r.name, ..p.clone() },
            None => r,
        })
        .collect())
}

/// §4.5a coherence: the staleness window must not be shorter than the cadence,
/// or every run would report its predecessor stale. Mirrors the rule the pinned
/// smoke-alarm monitor enforces on its own pair.
pub fn config_is_coherent() -> bool {
    MAX_STALENESS_NS >= EXPECTED_INTERVAL_NS
}

// ═════════════════════════════════════════════════════════════════════════════
// A-6c — THE LIVE BALANCE SOURCE
// ═════════════════════════════════════════════════════════════════════════════
//
// A-6 defined the shape and wired `UnwiredSource`; A-6b merged
// `cycle_balance : () -> (nat) query` onto all six registered canisters. A-6c
// is the consumer: it actually reads them.
//
// TWO SEAMS, deliberately.
//
//   BalanceSource   (unchanged, SYNCHRONOUS) — what the monitor logic consumes.
//   QueryTransport  (new)                    — one `cycle_balance` call,
//                                              returning the RAW candid reply.
//
// The transport returns BYTES, not a decoded `u128`. That is the load-bearing
// choice: a mock that hands back a pre-decoded `Observation::Balance(u128)`
// cannot prove anything about candid decoding or about the `nat`-exceeds-`u128`
// refusal, because it never runs that code. Handing back raw candid puts the
// SHIPPED decoder and the SHIPPED checked conversion under the deterministic
// tests, so L3 and L4 measure the real thing.
//
// The trait stays synchronous. Making it `async` would rewrite every existing
// deterministic test for no property gained; instead the ONE implementation
// that needs an async runtime owns one, built once, and blocks on it.

use candid::{Nat, Principal};

/// One `cycle_balance : () -> (nat) query` against one canister.
///
/// Returns the RAW candid-encoded reply payload. Decoding is the SOURCE's job,
/// not the transport's, so the decode and range limbs are exercised by every
/// implementation — including the mock.
pub trait QueryTransport {
    fn query_cycle_balance(&self, principal: Principal) -> Result<Vec<u8>, String>;
    /// The C-26 observability query. A SEPARATE method rather than a
    /// method-name parameter: `cycle_balance` is on all six canisters and
    /// `derive_budget_stats` is on exactly one, so making them the same call
    /// shape would invite querying it on a canister that does not serve it.
    fn query_derive_budget_stats(&self, principal: Principal) -> Result<Vec<u8>, String>;
}

/// The method name queried on every registered canister.
///
/// It is the same on all six. `canisters/vetkeys/src/lib.rs` calls ic-cdk
/// 0.20's `canister_cycle_balance()` INTERNALLY, but its exported endpoint is
/// `cycle_balance`, identical to the other five — verified against all six
/// `.did` service definitions, each `cycle_balance : () -> (nat) query`.
pub const CYCLE_BALANCE_METHOD: &str = "cycle_balance";

/// The C-26 observability query, served by `vetkeys` ALONE.
pub const DERIVE_BUDGET_METHOD: &str = "derive_budget_stats";

/// The canister that serves it. Derived from the compiled-in register, never
/// from config — the same rule the fleet membership follows: a caller who could
/// name the canister could point the rules at one that does not serve them and
/// get a permanent, quiet `Incomplete`.
pub const DERIVE_BUDGET_CANISTER: &str = "vetkeys";

/// The live source: config in, one query per canister, `Observation` out.
pub struct LiveBalanceSource<T: QueryTransport> {
    transport: T,
}

impl<T: QueryTransport> LiveBalanceSource<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: QueryTransport> BalanceSource for LiveBalanceSource<T> {
    fn balance_of(&self, canister: &CanisterConfig) -> Observation {
        // (1) Principal present. Checked HERE, above the transport, so an
        //     unconfigured canister costs no socket and is deterministic
        //     offline. Absence is a FAILURE, never NotYetCovered.
        let Some(text) = canister.principal.as_deref().map(str::trim).filter(|p| !p.is_empty())
        else {
            return Observation::Failed(FailureKind::PrincipalMissing);
        };

        // (2) Principal parses.
        let Ok(principal) = Principal::from_text(text) else {
            return Observation::Failed(FailureKind::PrincipalUnparseable);
        };

        // (3) The query.
        let Ok(reply) = self.transport.query_cycle_balance(principal) else {
            return Observation::Failed(FailureKind::Transport);
        };

        // (4) The reply decodes as candid `nat`.
        let Ok(nat) = candid::decode_one::<Nat>(&reply) else {
            return Observation::Failed(FailureKind::ReplyUndecodable);
        };

        // (5) CHECKED conversion. `nat` is unbounded; `Observation::Balance` is
        //     u128. Truncation here would manufacture a healthy-looking figure,
        //     so an out-of-range value is a failure, never a balance.
        match u128::try_from(nat.0) {
            Ok(balance) => Observation::Balance(balance),
            Err(_) => Observation::Failed(FailureKind::BalanceExceedsU128),
        }
    }
}

// ── The real transport ───────────────────────────────────────────────────────

/// `ic-agent` over HTTP, against a CONFIGURED endpoint.
///
/// Owns ONE current-thread tokio runtime, built at construction and reused for
/// every query. A per-call runtime is a resource leak dressed as simplicity.
///
/// Construction performs NO network I/O unless `fetch_root_key` is asked for:
/// `Agent::build` only assembles a client. That is what lets the CLI tests run
/// the real binary, with a real agent, fully offline.
pub struct AgentTransport {
    runtime: tokio::runtime::Runtime,
    agent: ic_agent::Agent,
}

impl AgentTransport {
    /// `url` is SUPPLIED — there is no default and no literal anywhere in this
    /// crate. Mainnet identifiers are A6.5's business, not this lane's.
    ///
    /// `fetch_root_key` is an explicit OPT-IN, required against a local replica
    /// and never correct against a trusted endpoint. It is not the default
    /// because a monitor that fetches a root key from whatever answers has
    /// delegated its trust decision to the network.
    pub fn new(url: &str, fetch_root_key: bool) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot build tokio runtime: {e}"))?;

        let agent = ic_agent::Agent::builder()
            .with_url(url)
            .build()
            .map_err(|e| format!("cannot build ic-agent for {url}: {e}"))?;

        if fetch_root_key {
            runtime
                .block_on(agent.fetch_root_key())
                .map_err(|e| format!("cannot fetch root key from {url}: {e}"))?;
        }

        Ok(Self { runtime, agent })
    }
}

impl QueryTransport for AgentTransport {
    fn query_cycle_balance(&self, principal: Principal) -> Result<Vec<u8>, String> {
        let arg = candid::encode_args(()).map_err(|e| format!("cannot encode empty arg: {e}"))?;
        self.runtime
            .block_on(
                self.agent
                    .query(&principal, CYCLE_BALANCE_METHOD)
                    .with_arg(arg)
                    .call(),
            )
            .map_err(|e| format!("{CYCLE_BALANCE_METHOD} query to {principal} failed: {e}"))
    }

    fn query_derive_budget_stats(&self, principal: Principal) -> Result<Vec<u8>, String> {
        let arg = candid::encode_args(()).map_err(|e| format!("cannot encode empty arg: {e}"))?;
        self.runtime
            .block_on(
                self.agent.query(&principal, DERIVE_BUDGET_METHOD).with_arg(arg).call(),
            )
            .map_err(|e| format!("{DERIVE_BUDGET_METHOD} query to {principal} failed: {e}"))
    }
}

/// A BORROWED transport is a transport. One agent, one runtime, two sources —
/// the balance source and the C-26 source share the connection rather than each
/// building its own, which is the resource-leak-dressed-as-simplicity that
/// `AgentTransport`'s own doc warns about.
impl<T: QueryTransport + ?Sized> QueryTransport for &T {
    fn query_cycle_balance(&self, principal: Principal) -> Result<Vec<u8>, String> {
        (**self).query_cycle_balance(principal)
    }
    fn query_derive_budget_stats(&self, principal: Principal) -> Result<Vec<u8>, String> {
        (**self).query_derive_budget_stats(principal)
    }
}

/// The live C-26 budget source: one query to the ONE canister that serves it.
///
/// FAIL-CLOSED AT EVERY STEP, the `LiveBalanceSource` discipline: a missing or
/// unparseable principal, a transport failure and an undecodable reply are each
/// `Failed` with their own reason — never `NotWired`, which would read as "this
/// deployment does not have it yet" rather than "it is broken".
pub struct LiveDeriveBudgetSource<'a, T: QueryTransport> {
    transport: T,
    /// The `vetkeys` entry from the derived fleet.
    config: Option<&'a CanisterConfig>,
}

impl<'a, T: QueryTransport> LiveDeriveBudgetSource<'a, T> {
    pub fn new(transport: T, fleet: &'a [CanisterConfig]) -> Self {
        Self { transport, config: fleet.iter().find(|c| c.name == DERIVE_BUDGET_CANISTER) }
    }
}

impl<T: QueryTransport> DeriveBudgetSource for LiveDeriveBudgetSource<'_, T> {
    fn budget_stats(&self) -> BudgetObservation {
        let Some(cfg) = self.config else {
            return BudgetObservation::Failed(format!(
                "{DERIVE_BUDGET_CANISTER} is not in the derived fleet, so the C-26 rules have                  no source"
            ));
        };
        let Some(text) = cfg.principal.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
            return BudgetObservation::NotWired;
        };
        let Ok(principal) = Principal::from_text(text) else {
            return BudgetObservation::Failed(format!(
                "{DERIVE_BUDGET_CANISTER} principal {text:?} does not parse"
            ));
        };
        let reply = match self.transport.query_derive_budget_stats(principal) {
            Ok(r) => r,
            Err(e) => return BudgetObservation::Failed(e),
        };
        match candid::decode_one::<DeriveBudgetStats>(&reply) {
            Ok(stats) => BudgetObservation::Stats(stats),
            // An undecodable reply is a DRIFT signal, not an outage: the
            // canister answered and the monitor could not read it, which means
            // the two sides disagree about the surface.
            Err(e) => BudgetObservation::Failed(format!(
                "{DERIVE_BUDGET_METHOD} reply did not decode as DeriveBudgetStats ({e}) — the                  monitor's mirror and the canister's DID have drifted"
            )),
        }
    }
}
