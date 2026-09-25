//! A-6 evidence suite (E1–E11).
//!
//! Every limb is driven deterministically through the INJECTED balance source —
//! no network, no canister, no timing assertion anywhere. Cycles and clocks are
//! integers, so every boundary below is exact.

use cycle_monitor::*;
use std::cell::RefCell;

// ── Injected sources ─────────────────────────────────────────────────────────

struct Fixed(Observation);
impl BalanceSource for Fixed {
    fn balance_of(&self, _c: &CanisterConfig) -> Observation {
        self.0
    }
}

/// Per-canister scripted outcomes, plus a call counter for E8.
struct Scripted {
    by_name: Vec<(String, Observation)>,
    calls: RefCell<usize>,
}
impl BalanceSource for Scripted {
    fn balance_of(&self, c: &CanisterConfig) -> Observation {
        *self.calls.borrow_mut() += 1;
        self.by_name
            .iter()
            .find(|(n, _)| *n == c.name)
            .map(|(_, o)| *o)
            .unwrap_or(Observation::NotWired)
    }
}

const NOW: u64 = 1_700_000_000_000_000_000;
const RESERVE: u128 = 1_000_000_000_000; // 1T cycles

fn cfg(name: &str) -> CanisterConfig {
    CanisterConfig {
        name: name.to_string(),
        principal: Some("aaaaa-aa".to_string()),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("controller canister_status at deploy".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    }
}

fn classify(c: &CanisterConfig, obs: Observation) -> CanisterReport {
    classify_canister(c, obs, NOW)
}

// ── E1 / E2 / E3 — the threshold and its exact inclusive boundary ────────────

#[test]
fn e1_balance_below_threshold_alerts_and_exits_1() {
    let r = classify(&cfg("pool"), Observation::Balance(RESERVE)); // 1T <= 3T
    assert_eq!(r.status, CanisterStatus::CoveredBelowThreshold);
    let agg = aggregate(&[r], RunStatus::Fresh);
    assert_eq!(agg, Aggregate::Alert);
    assert_eq!(agg.exit_code(), 1, "ALERT must route to exit 1");
}

#[test]
fn e2_balance_above_threshold_is_healthy_anti_vacuity() {
    let r = classify(&cfg("pool"), Observation::Balance(RESERVE * 10));
    assert_eq!(r.status, CanisterStatus::CoveredHealthy);
    assert_eq!(aggregate(&[r], RunStatus::Fresh), Aggregate::Ok);
}

/// E3 — the boundary is INCLUSIVE, asserted on all three sides at once so a
/// one-off can't hide: a `<` where `<=` was meant moves only the exact-equal
/// case, which is the single input most tests skip.
#[test]
fn e3_boundary_is_inclusive_on_all_three_sides() {
    let threshold = RESERVE * ALERT_MULTIPLE;

    let at = classify(&cfg("pool"), Observation::Balance(threshold));
    assert_eq!(
        at.status,
        CanisterStatus::CoveredBelowThreshold,
        "balance EXACTLY at the threshold must alert — the boundary is inclusive"
    );

    let below = classify(&cfg("pool"), Observation::Balance(threshold - 1));
    assert_eq!(below.status, CanisterStatus::CoveredBelowThreshold);

    let above = classify(&cfg("pool"), Observation::Balance(threshold + 1));
    assert_eq!(above.status, CanisterStatus::CoveredHealthy);
}

#[test]
fn e3b_threshold_is_reserve_times_three_and_overflow_fails_closed() {
    assert_eq!(ALERT_MULTIPLE, 3, "shipped ALERT_MULTIPLE is pinned");
    let r = classify(&cfg("pool"), Observation::Balance(u128::MAX));
    assert_eq!(r.alert_threshold, Some(RESERVE * 3), "integer-only, reserve * 3");

    // A reserve that overflows u128 when tripled is not a real figure.
    let mut c = cfg("pool");
    c.freeze_reserve_cycles = Some(u128::MAX);
    let r = classify(&c, Observation::Balance(1));
    assert_eq!(r.status, CanisterStatus::ReserveMisconfigured);
    assert!(r.reason.contains("overflow"), "reason names the overflow: {}", r.reason);
    assert_eq!(r.alert_threshold, None, "no threshold may be reported on overflow");
}

#[test]
fn e3c_absent_and_zero_reserve_are_misconfigured_never_healthy() {
    for reserve in [None, Some(0u128)] {
        let mut c = cfg("pool");
        c.freeze_reserve_cycles = reserve;
        // A comfortable balance must NOT rescue a broken reserve: with reserve
        // zero the line is zero and every balance would read "healthy".
        let r = classify(&c, Observation::Balance(u128::MAX));
        assert_eq!(
            r.status,
            CanisterStatus::ReserveMisconfigured,
            "reserve {reserve:?} must be misconfigured, not healthy"
        );
    }
    // Provenance is equally required — a number with no story is not a reserve.
    let mut c = cfg("pool");
    c.reserve_provenance = Some("   ".to_string());
    assert_eq!(
        classify(&c, Observation::Balance(u128::MAX)).status,
        CanisterStatus::ReserveMisconfigured
    );
}

#[test]
fn e3d_stale_reserve_alerts_even_with_a_comfortable_balance() {
    let mut c = cfg("pool");
    c.reserve_observed_at_ns = Some(NOW - MAX_RESERVE_AGE_NS - 1);
    let r = classify(&c, Observation::Balance(u128::MAX));
    assert_eq!(r.status, CanisterStatus::ReserveStale);

    // At exactly MAX_RESERVE_AGE the reserve is still acceptable — the stale
    // test is strictly greater-than, stated here so the boundary is pinned.
    let mut c2 = cfg("pool");
    c2.reserve_observed_at_ns = Some(NOW - MAX_RESERVE_AGE_NS);
    assert_eq!(
        classify(&c2, Observation::Balance(u128::MAX)).status,
        CanisterStatus::CoveredHealthy
    );
}

#[test]
fn e3e_future_dated_reserve_timestamp_is_invalid_never_healthy() {
    let mut c = cfg("pool");
    c.reserve_observed_at_ns = Some(NOW + CLOCK_SKEW_TOLERANCE_NS + 1);
    let r = classify(&c, Observation::Balance(u128::MAX));
    assert_eq!(r.status, CanisterStatus::ReserveTimestampInvalid);
    assert_eq!(
        aggregate(&[r], RunStatus::Fresh),
        Aggregate::Alert,
        "an unverifiable timestamp must alert, not read as freshly observed"
    );

    // Absent is equally invalid — it must not assert its own freshness.
    let mut c2 = cfg("pool");
    c2.reserve_observed_at_ns = None;
    assert_eq!(
        classify(&c2, Observation::Balance(u128::MAX)).status,
        CanisterStatus::ReserveTimestampInvalid
    );

    // Within tolerance is fine — anti-vacuity for the skew allowance.
    let mut c3 = cfg("pool");
    c3.reserve_observed_at_ns = Some(NOW + CLOCK_SKEW_TOLERANCE_NS - 1);
    assert_eq!(
        classify(&c3, Observation::Balance(u128::MAX)).status,
        CanisterStatus::CoveredHealthy
    );
}

// ── E4 / E5 — coverage gaps and source failures are DIFFERENT ────────────────

#[test]
fn e4_not_yet_covered_is_incomplete_exit_2_and_never_ok() {
    let r = classify(&cfg("pool"), Observation::NotWired);
    assert_eq!(r.status, CanisterStatus::NotYetCovered);
    let agg = aggregate(&[r], RunStatus::Fresh);
    assert_eq!(agg, Aggregate::Incomplete);
    assert_eq!(agg.exit_code(), 2, "INCOMPLETE must NOT exit 0");
    assert_ne!(agg, Aggregate::Ok, "watching nothing is not health");
}

/// E5 — asserted in the SAME test, because the whole point is that they are not
/// interchangeable: "nothing is wired" and "the wire broke" have different
/// remedies, and collapsing them loses the distinction exactly when it matters.
#[test]
fn e5_source_failure_is_distinct_from_not_yet_covered() {
    // A-6c: `Failed` now carries WHY. The kind is immaterial to E5's property
    // (any kind is a SourceFailed); Transport is used as a representative.
    let failed = classify(&cfg("pool"), Observation::Failed(FailureKind::Transport));
    let unwired = classify(&cfg("pool"), Observation::NotWired);

    assert_eq!(failed.status, CanisterStatus::SourceFailed);
    assert_eq!(unwired.status, CanisterStatus::NotYetCovered);
    assert_ne!(failed.status, unwired.status);
    assert_ne!(failed.reason, unwired.reason, "each carries its own observable");

    assert_eq!(aggregate(&[failed], RunStatus::Fresh), Aggregate::Alert);
    assert_eq!(aggregate(&[unwired], RunStatus::Fresh), Aggregate::Incomplete);
}

// ── E6 / E7 — cadence, staleness, and the state-file contract ────────────────

#[test]
fn e6_config_coherence_at_the_shipped_values() {
    assert_eq!(EXPECTED_INTERVAL_NS, 300_000_000_000, "5 min, shipped");
    assert_eq!(MAX_STALENESS_NS, 900_000_000_000, "15 min, shipped");
    assert_eq!(CLOCK_SKEW_TOLERANCE_NS, 60_000_000_000, "1 min, shipped");
    assert!(
        config_is_coherent(),
        "max_staleness must be >= expected_interval or every run reports its \
         predecessor stale"
    );
}

#[test]
fn e7_stale_prior_run_alerts_and_exits_1() {
    let status = classify_run(PriorState::Present { run_at_ns: NOW - MAX_STALENESS_NS - 1, budget: None }, false, NOW);
    assert_eq!(status, RunStatus::Stale);
    let agg = aggregate(&[], status);
    assert_eq!(agg, Aggregate::Alert);
    assert_eq!(agg.exit_code(), 1, "the ROUTE matters, not just the status");

    // Anti-vacuity: just inside the window is FRESH.
    assert_eq!(
        classify_run(PriorState::Present { run_at_ns: NOW - MAX_STALENESS_NS, budget: None }, false, NOW),
        RunStatus::Fresh
    );
}

/// E7b — absence is only benign when a human DECLARED it.
#[test]
fn e7b_absent_state_alerts_unless_explicitly_declared() {
    let undeclared = classify_run(PriorState::Absent, false, NOW);
    assert_eq!(undeclared, RunStatus::StateMissing);
    assert_eq!(aggregate(&[], undeclared).exit_code(), 1);

    let declared = classify_run(PriorState::Absent, true, NOW);
    assert_eq!(declared, RunStatus::NoPriorState);
    assert_eq!(aggregate(&[], declared), Aggregate::Ok);

    // THE FLAG IS FIRST-RUN-ONLY AND MUST BE IGNORED WHEN STATE EXISTS.
    //
    // If it also suppressed staleness on a PRESENT state file, then a scheduler
    // passing it permanently — the documented misuse — would silently disable
    // the missed-run check altogether, which is the single thing this monitor
    // exists to notice about itself.
    let stale_with_flag =
        classify_run(PriorState::Present { run_at_ns: NOW - MAX_STALENESS_NS - 1, budget: None }, true, NOW);
    assert_eq!(
        stale_with_flag,
        RunStatus::Stale,
        "--allow-missing-state must NOT rescue a stale present state file"
    );
    assert_eq!(aggregate(&[], stale_with_flag), Aggregate::Alert);

    // ...and it must not turn a fresh present state into a declared first run.
    assert_eq!(
        classify_run(PriorState::Present { run_at_ns: NOW, budget: None }, true, NOW),
        RunStatus::Fresh,
        "a present state file is never NO_PRIOR_STATE, flag or no flag"
    );
}

/// E7e — THE DELETION ATTACK. The monitor's history is its only liveness input,
/// and it is unauthenticated and destructible, so the cheapest way to silence
/// this monitor is to remove a file. Deleting evidence must not produce OK.
#[test]
fn e7e_deleting_the_state_file_does_not_produce_ok() {
    // Run 1 produces state.
    let after_run_1 = PriorState::Present { run_at_ns: NOW, budget: None };
    assert_eq!(classify_run(after_run_1, false, NOW + 1), RunStatus::Fresh);

    // The file is deleted; the next scheduled run carries no flag.
    let after_deletion = classify_run(PriorState::Absent, false, NOW + 1);
    assert_eq!(after_deletion, RunStatus::StateMissing);
    assert_eq!(
        aggregate(&[], after_deletion),
        Aggregate::Alert,
        "deleting the state file must ALERT — otherwise removing evidence is a way \
         to pass the check"
    );
}

#[test]
fn e7c_malformed_state_and_future_clock_both_alert() {
    let unreadable = classify_run(PriorState::Unreadable, false, NOW);
    assert_eq!(unreadable, RunStatus::StateUnreadable);
    assert_eq!(aggregate(&[], unreadable), Aggregate::Alert);
    // Even the declared-first-run flag must not excuse corruption.
    assert_eq!(classify_run(PriorState::Unreadable, true, NOW), RunStatus::StateUnreadable);

    let skewed = classify_run(
        PriorState::Present { run_at_ns: NOW + CLOCK_SKEW_TOLERANCE_NS + 1, budget: None },
        false,
        NOW,
    );
    assert_eq!(skewed, RunStatus::ClockSkew);
    assert_eq!(aggregate(&[], skewed), Aggregate::Alert);
}

/// E7d — a crash-equivalent: evaluate but never persist. The prior state is
/// untouched, so the NEXT run sees the older timestamp and reports STALE rather
/// than silently resetting the liveness clock.
#[test]
fn e7d_crash_before_write_leaves_prior_state_and_next_run_is_stale() {
    let original = NOW - MAX_STALENESS_NS - 1;
    let _evaluated = classify_run(PriorState::Present { run_at_ns: original, budget: None }, false, NOW);
    // No write happened; the next run still reads the ORIGINAL timestamp.
    assert_eq!(classify_run(PriorState::Present { run_at_ns: original, budget: None }, false, NOW), RunStatus::Stale);
}

// ── E8 — query budget, counted, never timed ─────────────────────────────────

#[test]
fn e8_at_most_one_query_per_monitored_canister() {
    let configs = shipped_register();
    let source = Scripted { by_name: vec![], calls: RefCell::new(0) };
    let _ = run(&configs, &source, PriorState::Absent, true, NOW);
    let calls = *source.calls.borrow();
    assert!(
        calls <= configs.len(),
        "queries per run ({calls}) must be at most one per monitored canister ({})",
        configs.len()
    );
    assert_eq!(calls, configs.len(), "and each canister is actually consulted");
}

// ── E10 — the honest end state of this lane ─────────────────────────────────

#[test]
fn e10_shipped_register_is_all_not_yet_covered_and_exits_2() {
    let configs = shipped_register();
    assert_eq!(configs.len(), 6, "five spend-path canisters plus vetkeys");

    let snap = run(&configs, &Fixed(Observation::NotWired), PriorState::Absent, true, NOW);
    assert!(
        snap.canisters.iter().all(|c| c.status == CanisterStatus::NotYetCovered),
        "no source is wired at the pinned base — Rule 7 forbids compiling against \
         A-2's unmerged cycle_balance"
    );
    assert_eq!(snap.aggregate, Aggregate::Incomplete);
    assert_eq!(
        snap.aggregate.exit_code(),
        2,
        "the truthful end state of this lane is INCOMPLETE, and it must not be 0"
    );
}

// ── E11 — the crate touches none of the protected surface ───────────────────

/// E11 — asserted, not assumed. The off-chain home is what makes the 29-file
/// smoke-alarm/snapshot surface out of scope rather than merely protected; this
/// proves the crate never entered any of the registries that would drag it back
/// in.
#[test]
fn e11_crate_is_absent_from_every_protected_registry() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for rel in [
        "dfx.json",
        "scripts/did_export_census.toml",
        "docs/MEMORY_ID_REGISTRY.md",
        "deployment/mainnet/custody_manifest.toml",
    ] {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("E11 cannot read {}: {e}", path.display()));
        for needle in ["cycle_monitor", "cycle-monitor"] {
            assert!(
                !text.contains(needle),
                "E11: {rel} mentions {needle} — this crate is a HOST TOOL and must not \
                 appear in a canister/DID/MemoryId/custody registry. Its absence is what \
                 keeps the certified-snapshot surface out of scope."
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// E12 / E13 — the EXECUTABLE, not the library (SSA-A6-D1, SSA-A6-D2)
// ═════════════════════════════════════════════════════════════════════════════
//
// V1's suite proved things about `lib.rs` and asserted nothing about the binary
// that ships. SSA ran the actual CLI and found two paths where it manufactured
// health: an empty fleet exited 0, and every state-read error was treated as
// benign absence. E10 could not see either — it called `shipped_register()`
// itself and handed the result to the library, so it verified that a value
// EXISTS, never that the executable USES it.
//
// These tests drive `CARGO_BIN_EXE_cycle_monitor`. Both fail on the V1 binary.

/// A-6c: the endpoint every CLI test runs against, and **no test in this file
/// ever contacts it**.
///
/// `--url` became required, so the binary needs a syntactically valid one. It is
/// never reached: every fixture here either leaves `principal` null or supplies
/// an unparseable one, and the live source decides both ABOVE the transport.
/// `AgentTransport::new` itself performs no I/O without `--fetch-root-key`.
/// **Zero sockets are opened by this suite** — asserted causally, not assumed,
/// by `l7b_unconfigured_canisters_cost_no_query_at_all`.
///
/// SSA_DIFF_A-6c_RED_V2 D1 removed the one case that did open a socket. A
/// standing gate must be reproducible offline (brief §5.2); an OS socket
/// outcome is an environment dependency even on loopback, and "port 1 is never
/// bound" is an assumption about the host rather than a guarantee.
const OFFLINE_URL: &str = "http://127.0.0.1:1";

/// A-6c: `--url` is now required, and no test here is about the endpoint, so it
/// is injected once here rather than repeated at every call site. A test that
/// IS about the endpoint passes its own `--url` (or deliberately omits it).
fn run_cli(args: &[&str]) -> (Option<i32>, String, String) {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 2);
    if !args.contains(&"--url") {
        full.extend_from_slice(&["--url", OFFLINE_URL]);
    }
    full.extend_from_slice(args);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cycle_monitor"))
        .args(&full)
        .output()
        .expect("cycle_monitor binary must run");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("cycle_monitor_test_{}_{}", std::process::id(), name));
    p
}

/// E12 — an empty fleet must NOT emit OK or exit 0, through the real binary.
#[test]
fn e12_cli_rejects_an_empty_fleet_fail_closed() {
    let cfg = temp_path("empty.json");
    std::fs::write(&cfg, "[]").unwrap();

    // A-6c: --url is REQUIRED now, but it is never contacted here. Every
    // canister in this fixture has `principal: null`, so the live source
    // short-circuits at PrincipalMissing before any socket is opened. This test
    // stays fully offline and fully deterministic.
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        cfg.to_str().unwrap(),
        "--allow-missing-state",
    ]);
    let _ = std::fs::remove_file(&cfg);

    assert_ne!(
        code,
        Some(0),
        "an empty fleet must NEVER exit 0 — watching nothing is not health. \
         stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        !stdout.contains("\"Ok\""),
        "an empty fleet must not report aggregate Ok; got: {stdout}"
    );
    // A-6c MOVED THIS EXPECTATION, deliberately, and it is the ONLY behavioural
    // expectation this lane changes.
    //
    // Before A-6c no source existed, so six unconfigured canisters were
    // NOT_YET_COVERED => INCOMPLETE => exit 2. After A-6c a source DOES exist,
    // so an unconfigured canister is a failure to watch it, not an absence of
    // coverage: SOURCE_FAILED => ALERT => exit 1. Reading it as INCOMPLETE would
    // now be the lie — it would say "coverage is not built" about a monitor that
    // is built and is being starved of config.
    //
    // The property E12 exists to defend — an empty params list must never exit 0
    // and never report Ok — is asserted above and is UNCHANGED. Exit 2 at the
    // six-name register is still pinned, by E10, through the library.
    assert_eq!(
        code,
        Some(1),
        "empty params ⇒ six SOURCE_FAILED (no principal) ⇒ ALERT, stdout: {stdout}"
    );
    assert_eq!(
        stdout.matches("SourceFailed").count(),
        6,
        "all six registered canisters must be reported as SourceFailed, not five, \
         not one: {stdout}"
    );
}

/// E12b — a PARTIAL fleet is equally refused: dropping five canisters from the
/// config must not shrink what the monitor claims to watch.
#[test]
fn e12b_cli_rejects_a_partial_fleet() {
    let cfg = temp_path("partial.json");
    std::fs::write(
        &cfg,
        r#"[{"name":"shielded_pool","principal":null,"freeze_reserve_cycles":null,
             "reserve_provenance":null,"reserve_observed_at_ns":null}]"#,
    )
    .unwrap();

    let (code, _stdout, stderr) =
        run_cli(&["--config", cfg.to_str().unwrap(), "--allow-missing-state"]);
    let _ = std::fs::remove_file(&cfg);

    // A partial params list cannot shrink the watched set: the register is
    // iterated, so the other five are still monitored and still reported.
    assert_ne!(code, Some(0), "a partial params list must not exit 0");
    let _ = stderr;
}

/// E13 — a state path that exists but cannot be READ is not absence.
///
/// A directory stands in for the whole class (permission denied, transient I/O,
/// a path that is not a file). With `--allow-missing-state` these previously
/// became `NoPriorState` and exited 0, so the flag excused corruption — exactly
/// what E7c promises it cannot.
#[test]
fn e13_cli_unreadable_state_is_not_benign_absence() {
    let dir = temp_path("state_dir");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = temp_path("full.json");
    let full: Vec<String> = ["shielded_pool", "verifier", "nullifier_registry", "merkle_tree", "token", "vetkeys"]
        .iter()
        .map(|n| format!(
            r#"{{"name":"{n}","principal":null,"freeze_reserve_cycles":null,
                 "reserve_provenance":null,"reserve_observed_at_ns":null}}"#
        ))
        .collect();
    std::fs::write(&cfg, format!("[{}]", full.join(","))).unwrap();

    let (code, stdout, _stderr) = run_cli(&[
        "--config",
        cfg.to_str().unwrap(),
        "--state",
        dir.to_str().unwrap(),
        "--allow-missing-state",
    ]);
    let _ = std::fs::remove_file(&cfg);
    let _ = std::fs::remove_dir_all(&dir);

    assert_ne!(code, Some(0), "an unreadable state path must not exit 0");
    assert!(
        !stdout.contains("NoPriorState"),
        "an unreadable state path must NOT be reported as a declared first run — \
         the flag declares absence, never corruption. got: {stdout}"
    );
}

/// E13b — the library-level counterpart, so the discrimination is pinned on both
/// sides of the adapter that SSA found untested.
#[test]
fn e13b_unreadable_state_is_never_excused_by_the_flag() {
    assert_eq!(
        classify_run(PriorState::Unreadable, true, NOW),
        RunStatus::StateUnreadable,
        "--allow-missing-state must not convert corruption into a declared first run"
    );
    assert_eq!(aggregate(&[], RunStatus::StateUnreadable), Aggregate::Alert);
}


// ── D5 — the fleet is DERIVED, not supplied ─────────────────────────────────

/// E14 — a caller cannot shrink, extend or misdirect the monitored set.
///
/// This is the test SSA asked for: proof that the executable iterates the
/// compiled-in register rather than the caller's list. `validate_fleet` could be
/// satisfied by supplying the right list; derivation cannot be defeated by
/// supplying a different one, because the caller never names the fleet.
#[test]
fn e14_fleet_is_derived_from_the_register_not_from_config() {
    // Empty params ⇒ all six still monitored.
    let derived = derive_fleet(&[]).expect("empty params is legal — membership is compiled in");
    assert_eq!(derived.len(), 6, "the register decides membership, not the caller");

    // One param entry ⇒ still six; the other five carry no parameters.
    let one = vec![CanisterConfig {
        name: "shielded_pool".to_string(),
        principal: Some("aaaaa-aa".to_string()),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("deploy-time canister_status".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    }];
    let derived = derive_fleet(&one).expect("known key");
    assert_eq!(derived.len(), 6, "supplying one entry must not shrink the fleet to one");
    assert_eq!(
        derived.iter().filter(|c| c.freeze_reserve_cycles.is_some()).count(),
        1,
        "only the supplied canister gets parameters"
    );

    // An unknown key is refused — a typo must not silently misdirect.
    let unknown = vec![CanisterConfig {
        name: "not_a_canister".to_string(),
        principal: None,
        freeze_reserve_cycles: None,
        reserve_provenance: None,
        reserve_observed_at_ns: None,
    }];
    let err = derive_fleet(&unknown).expect_err("unknown canister must fail closed");
    assert!(err.contains("unknown canister"), "got: {err}");

    // A canister with NO parameters is monitored and reports misconfigured —
    // never healthy. Absence at the root of the tree does not read as health.
    let reports: Vec<CanisterReport> = derive_fleet(&[])
        .unwrap()
        .iter()
        .map(|c| classify_canister(c, Observation::Balance(u128::MAX), NOW))
        .collect();
    assert!(
        reports.iter().all(|r| r.status == CanisterStatus::ReserveMisconfigured),
        "an unparameterised canister must not be healthy"
    );
    assert_eq!(aggregate(&reports, RunStatus::Fresh), Aggregate::Alert);
}

// ── D3 — persistence is ATOMIC ──────────────────────────────────────────────

/// E15 — the prior snapshot survives a failed persist.
///
/// `fs::write` truncates before writing, so a crash mid-persist destroys exactly
/// the evidence E7d claims survives. This drives the real binary: point --state
/// at a path whose PARENT does not exist, so the temp-file create fails, and
/// assert the run alerts rather than silently continuing.
#[test]
fn e15_failed_persist_alerts_and_leaves_prior_state_intact() {
    let good = temp_path("e15_state.json");
    let cfg = temp_path("e15_cfg.json");
    std::fs::write(&cfg, "[]").unwrap();

    // Run 1: writes a real snapshot.
    let (_c1, _o1, _e1) = run_cli(&[
        "--config", cfg.to_str().unwrap(),
        "--state", good.to_str().unwrap(),
        "--allow-missing-state",
    ]);
    let first = std::fs::read_to_string(&good).expect("run 1 must persist a snapshot");
    assert!(first.contains("run_at_ns"), "run 1 wrote a real snapshot");

    // Run 2: a --state path inside a NON-EXISTENT directory. The temp create
    // fails, so persistence fails.
    let bad = temp_path("e15_nodir").join("nested").join("state.json");
    let (code2, _o2, err2) = run_cli(&[
        "--config", cfg.to_str().unwrap(),
        "--state", bad.to_str().unwrap(),
        "--allow-missing-state",
    ]);
    assert_ne!(code2, Some(0), "a failed persist must not exit 0; stderr: {err2}");
    assert!(err2.contains("cannot persist state"), "got: {err2}");

    // The ORIGINAL snapshot is untouched — that is the property.
    let after = std::fs::read_to_string(&good).expect("prior snapshot must still exist");
    assert_eq!(after, first, "a failed persist elsewhere must not disturb prior state");

    // No temp debris for THIS target. Scoped to our own filename prefix: the
    // temp dir is shared with every other test in this binary, so a broad
    // `.tmp.` scan would see their in-flight files and fail under parallelism —
    // which would make this a flaky test rather than evidence.
    let dir = good.parent().unwrap();
    let our_prefix = format!(
        ".{}.tmp.",
        good.file_name().and_then(|s| s.to_str()).unwrap()
    );
    let debris: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&our_prefix))
        .collect();
    assert!(debris.is_empty(), "temp files for this target must be cleaned up: {debris:?}");

    let _ = std::fs::remove_file(&good);
    let _ = std::fs::remove_file(&cfg);
}

/// E15b — a successful persist REPLACES rather than truncating-in-place: the
/// file is always complete and parseable, run over run.
#[test]
fn e15b_successive_persists_leave_a_complete_parseable_snapshot() {
    let state = temp_path("e15b_state.json");
    let cfg = temp_path("e15b_cfg.json");
    std::fs::write(&cfg, "[]").unwrap();

    for _ in 0..3 {
        let (_c, _o, _e) = run_cli(&[
            "--config", cfg.to_str().unwrap(),
            "--state", state.to_str().unwrap(),
            "--allow-missing-state",
        ]);
        let text = std::fs::read_to_string(&state).expect("state present after each run");
        let parsed: Result<Snapshot, _> = serde_json::from_str(&text);
        assert!(parsed.is_ok(), "every persisted snapshot must be complete and parseable");
    }
    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&cfg);
}

/// E15c — THE test that actually distinguishes atomic replacement from an
/// in-place overwrite.
///
/// E15 alone does not: it drives a *failure to open* (a non-existent parent),
/// and `fs::write` and temp+rename both fail there identically. Verified — with
/// `fs::write` restored, E15 still passes. A test that cannot tell the two
/// implementations apart is not evidence for choosing between them, which is the
/// exact defect class this lane has already been REDed for twice.
///
/// The distinguisher is a permission fact, not a timing one:
///
/// * `fs::write` opens the TARGET for writing → needs write permission on the
///   FILE → fails on a read-only file.
/// * temp + `rename` opens a NEW file in the directory and renames over the
///   target → needs write permission on the DIRECTORY → succeeds.
///
/// So a read-only state file with a writable parent separates them cleanly, and
/// it is the same property that makes the write crash-safe: the live file is
/// never opened for writing, so it is never truncated.
#[test]
fn e15c_atomic_replace_succeeds_where_in_place_overwrite_cannot() {
    use std::os::unix::fs::PermissionsExt;

    let state = temp_path("e15c_state.json");
    let cfg = temp_path("e15c_cfg.json");
    std::fs::write(&cfg, "[]").unwrap();

    // Run 1 creates a real snapshot.
    let _ = run_cli(&[
        "--config", cfg.to_str().unwrap(),
        "--state", state.to_str().unwrap(),
        "--allow-missing-state",
    ]);
    let first = std::fs::read_to_string(&state).expect("run 1 persisted");

    // Make the TARGET read-only; its directory stays writable.
    let mut perms = std::fs::metadata(&state).unwrap().permissions();
    perms.set_mode(0o444);
    std::fs::set_permissions(&state, perms).unwrap();

    // Skip rather than assert falsely if the test user can write anyway (root).
    if std::fs::OpenOptions::new().write(true).open(&state).is_ok() {
        let mut p = std::fs::metadata(&state).unwrap().permissions();
        p.set_mode(0o644);
        let _ = std::fs::set_permissions(&state, p);
        let _ = std::fs::remove_file(&state);
        let _ = std::fs::remove_file(&cfg);
        eprintln!("E15c skipped: this user can write a 0444 file (running as root?)");
        return;
    }

    let (code, _out, err) = run_cli(&[
        "--config", cfg.to_str().unwrap(),
        "--state", state.to_str().unwrap(),
        "--allow-missing-state",
    ]);

    let mut p = std::fs::metadata(&state).unwrap().permissions();
    p.set_mode(0o644);
    let _ = std::fs::set_permissions(&state, p);
    let after = std::fs::read_to_string(&state).unwrap_or_default();
    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&cfg);

    assert!(
        !err.contains("cannot persist state"),
        "atomic replacement must SUCCEED over a read-only target (rename needs \
         directory permission, not file permission) — an in-place overwrite fails \
         here. stderr: {err}"
    );
    // A-6c: the exit code no longer discriminates here. Every run over this
    // fixture now ALERTS on its own merits — six canisters with no principal are
    // six SOURCE_FAILEDs — so `code != 1` stopped being a statement about
    // PERSISTENCE and became a statement about the fleet, which is not what
    // E15c is for. The persistence property is asserted directly instead, on
    // the two observables that actually carry it: no persist error on stderr
    // (above), and the file genuinely replaced (below).
    let _ = code;
    assert_ne!(after, first, "the snapshot must actually have been replaced");
    assert!(after.contains("run_at_ns"), "and the replacement is a real snapshot");
}

/// E16 — CAMPAIGN RULE 12: the real artifact, the real exit codes.
///
/// *"For any deliverable with an executable entry point the review runs the
/// executable against the failure cases, not only the library its tests call."*
///
/// One table, four real invocations, asserted on the process exit code — the
/// thing an operator's scheduler actually branches on.
#[test]
fn e16_rule12_real_invocation_matrix() {
    let dir = temp_path("e16");
    std::fs::create_dir_all(&dir).unwrap();

    // (1) EMPTY params — legal under derivation; all six still monitored, none
    //     given a principal ⇒ six SOURCE_FAILED ⇒ ALERT ⇒ exit 1. Never 0.
    //
    //     A-6c moved this from exit 2. Before the lane no source existed, so an
    //     unconfigured canister was NOT_YET_COVERED. Now a source DOES exist and
    //     is being starved of config, which is a failure to watch, not a gap in
    //     coverage. Exit 2 at the six-name register is still pinned — by E10,
    //     through the library, and by L2b through the live source.
    let empty = dir.join("empty.json");
    std::fs::write(&empty, "[]").unwrap();
    let (code, out, _) = run_cli(&["--config", empty.to_str().unwrap(), "--allow-missing-state"]);
    assert_eq!(code, Some(1), "empty params ⇒ exit 1 (ALERT), never 0. out: {out}");
    assert_eq!(out.matches("SourceFailed").count(), 6, "all six still monitored");
    assert_eq!(out.matches("NotYetCovered").count(), 0, "and none reads as a coverage gap");

    // (2) UNKNOWN canister in config ⇒ fail closed, exit 1.
    let unknown = dir.join("unknown.json");
    std::fs::write(&unknown, r#"[{"name":"nope","principal":null,"freeze_reserve_cycles":null,
        "reserve_provenance":null,"reserve_observed_at_ns":null}]"#).unwrap();
    let (code, _, err) = run_cli(&["--config", unknown.to_str().unwrap(), "--allow-missing-state"]);
    assert_eq!(code, Some(1), "unknown canister ⇒ exit 1");
    assert!(err.contains("unknown canister"), "and says which: {err}");

    // (3) MISSING config file ⇒ fail closed, exit 1. An unreadable config is not
    //     an empty fleet.
    let (code, _, err) = run_cli(&[
        "--config", dir.join("does_not_exist.json").to_str().unwrap(),
        "--allow-missing-state",
    ]);
    assert_eq!(code, Some(1), "missing config ⇒ exit 1");
    assert!(err.contains("cannot read config"), "{err}");

    // (4) GOOD config, UNPARSEABLE principals — six failures ⇒ ALERT ⇒ exit 1,
    //     through the real binary, with ZERO sockets opened.
    //
    //     SSA_DIFF_A-6c_RED_V2 D1: this case previously used real principals
    //     against an unreachable endpoint, which made the STANDING GATE depend
    //     on an OS socket outcome. Brief §5.2 forbids that — the gate must be
    //     reproducible offline — and "port 1 is never bound" is an assumption
    //     about the environment, not a guarantee. So the case now exercises a
    //     limb that short-circuits ABOVE the transport, which keeps the
    //     real-binary coverage and drops the network dependency entirely.
    //
    //     The transport-failure limb has not lost coverage: it is driven
    //     deterministically over the mock transport by L2 (six slots), L5c and
    //     L8, and observed for real in the recorded live leg.
    let good = dir.join("good.json");
    let entries: Vec<String> = ["shielded_pool","verifier","nullifier_registry","merkle_tree","token","vetkeys"]
        .iter()
        .map(|n| format!(r#"{{"name":"{n}","principal":"not-a-principal","freeze_reserve_cycles":1000000000000,
             "reserve_provenance":"deploy-time canister_status","reserve_observed_at_ns":{}}}"#, NOW - 1))
        .collect();
    std::fs::write(&good, format!("[{}]", entries.join(","))).unwrap();
    let (code, out, _) = run_cli(&["--config", good.to_str().unwrap(), "--allow-missing-state"]);
    assert_eq!(code, Some(1), "an unusable principal is ALERT, never OK and never 0: {out}");
    assert!(!out.contains("\"Ok\""), "and never OK: {out}");
    assert_eq!(
        out.matches("not a valid principal").count(),
        6,
        "each of the six must say WHY it failed, and say its own distinguishable \
         thing — not one collapsed sentence: {out}"
    );

    // (5) A-6c: NO ENDPOINT AT ALL ⇒ fail closed, exit 1.
    //     A monitor with no configured endpoint is a misconfiguration, not an
    //     empty fleet, and must not be allowed to report anything at all.
    let (code, out, err) = std::process::Command::new(env!("CARGO_BIN_EXE_cycle_monitor"))
        .args(["--config", empty.to_str().unwrap(), "--allow-missing-state"])
        .env_remove("CYCLE_MONITOR_IC_URL")
        .output()
        .map(|o| {
            (
                o.status.code(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        })
        .expect("binary runs");
    assert_eq!(code, Some(1), "no endpoint ⇒ exit 1; stderr: {err}");
    assert!(out.is_empty(), "and reports NOTHING — no snapshot at all: {out}");
    assert!(err.contains("no IC endpoint configured"), "and says why: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ── LAUNCH-HARDEN-04 O-4 — compiled-in absolute alert floors ─────────────────

/// A reserve whose 3× (300 B) sits BELOW both floors, so the floor governs.
const SMALL_RESERVE: u128 = 100_000_000_000;

fn small(name: &str) -> CanisterConfig {
    let mut c = cfg(name);
    c.freeze_reserve_cycles = Some(SMALL_RESERVE);
    c
}

#[test]
fn o4_floors_are_pinned() {
    assert_eq!(absolute_alert_floor("verifier"), 500_000_000_000);
    assert_eq!(absolute_alert_floor("vetkeys"), 1_000_000_000_000);
    assert_eq!(absolute_alert_floor("pool"), 0, "no floor for an unlisted canister");
    assert_eq!(ABSOLUTE_ALERT_FLOORS.len(), 2);
}

#[test]
fn o4_verifier_floor_is_inclusive() {
    let at = classify(&small("verifier"), Observation::Balance(500_000_000_000));
    assert_eq!(at.status, CanisterStatus::CoveredBelowThreshold, "exactly 500 B alerts");
    assert_eq!(at.alert_threshold, Some(500_000_000_000));
    let above = classify(&small("verifier"), Observation::Balance(500_000_000_001));
    assert_eq!(above.status, CanisterStatus::CoveredHealthy);
}

#[test]
fn o4_vetkeys_floor_is_inclusive() {
    let at = classify(&small("vetkeys"), Observation::Balance(1_000_000_000_000));
    assert_eq!(at.status, CanisterStatus::CoveredBelowThreshold, "exactly 1 T alerts");
    assert_eq!(at.alert_threshold, Some(1_000_000_000_000));
    let above = classify(&small("vetkeys"), Observation::Balance(1_000_000_000_001));
    assert_eq!(above.status, CanisterStatus::CoveredHealthy);
}

#[test]
fn o4_a_larger_three_times_reserve_still_governs() {
    // RESERVE = 1 T → 3 T > both floors.
    let r = classify(&cfg("verifier"), Observation::Balance(3_000_000_000_000));
    assert_eq!(r.alert_threshold, Some(3_000_000_000_000));
    assert_eq!(r.status, CanisterStatus::CoveredBelowThreshold);
    let r = classify(&cfg("vetkeys"), Observation::Balance(3_000_000_000_001));
    assert_eq!(r.alert_threshold, Some(3_000_000_000_000));
    assert_eq!(r.status, CanisterStatus::CoveredHealthy);
    // An unlisted canister keeps the plain 3× threshold even when small.
    let r = classify(&small("pool"), Observation::Balance(300_000_000_001));
    assert_eq!(r.alert_threshold, Some(300_000_000_000));
    assert_eq!(r.status, CanisterStatus::CoveredHealthy);
}
