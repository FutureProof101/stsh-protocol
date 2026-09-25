//! A-6 / GAP-U9-1 — CLI wrapper for the off-chain fleet cycle monitor.
//!
//! DELIBERATELY THIN. Every decision lives in the library so it is gate-testable
//! (the `verify_genesis_manifest` pattern). This file reads config, calls the
//! library, prints the snapshot as JSON and sets the exit code — nothing else.
//!
//! Usage:
//!   cycle_monitor --url <IC endpoint> --config <path>
//!                 [--state <path>] [--allow-missing-state] [--fetch-root-key]
//!
//! The endpoint may also come from $CYCLE_MONITOR_IC_URL. There is no default:
//! a monitor with no configured endpoint refuses to run.
//!
//! `--fetch-root-key` is LOCAL-REPLICA ONLY. It is opt-in because a binary that
//! fetches a root key from an arbitrary endpoint by default trusts whatever
//! answers it.
//!
//! Exit codes:
//!   0  OK          every canister healthy, run fresh (or a declared first run)
//!   1  ALERT       something is below threshold, misconfigured, or runs missed
//!   2  INCOMPLETE  coverage gaps only — NEVER 0, see the library's note
//!
//! `--allow-missing-state` is a FIRST-RUN-ONLY declaration and must not be wired
//! into the scheduled invocation: a scheduler passing it permanently has
//! disabled the missed-run check. B-2 records that operational requirement.

use std::process::ExitCode;

use cycle_monitor::*;

/// A-6c: the source is LIVE. `UnwiredSource` is gone.
///
/// A-6 defined the shape while `cycle_balance` did not exist; A-6b merged the
/// endpoint onto all six registered canisters; this binary now queries them
/// through `LiveBalanceSource<AgentTransport>`.
///
/// The endpoint is SUPPLIED, never compiled in — see `endpoint_url`.
const URL_ENV: &str = "CYCLE_MONITOR_IC_URL";

/// Persist the snapshot ATOMICALLY (SSA-A6-D3).
///
/// `std::fs::write` TRUNCATES the live file before writing the replacement, so a
/// crash or partial write mid-persistence destroys the prior snapshot — the very
/// evidence E7d claims survives a crash. Evaluating before writing does not make
/// an in-place overwrite crash-safe; it only narrows the window.
///
/// Write to a temporary file in the SAME DIRECTORY (so the rename is within one
/// filesystem and therefore atomic), flush it to the OS, then `rename` over the
/// target. `rename` is atomic on POSIX: an observer sees either the old snapshot
/// or the new one, never a truncated file. On any failure the temp file is
/// removed and the prior snapshot is untouched.
fn persist_atomically(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;

    let target = std::path::Path::new(path);
    let dir = target.parent().filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        target.file_name().and_then(|s| s.to_str()).unwrap_or("cycle_monitor_state"),
        std::process::id()
    ));

    let write_then_rename = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        // flush the process buffer AND ask the OS to commit, so the rename cannot
        // publish a file whose contents are still in flight.
        f.flush()?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, target)
    };

    match write_then_rename() {
        Ok(()) => Ok(()),
        Err(e) => {
            // Leave no debris, and leave the prior snapshot exactly as it was.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

/// The IC endpoint, from `--url` or from `$CYCLE_MONITOR_IC_URL`.
///
/// THERE IS NO DEFAULT AND NO LITERAL. A monitor that falls back to a built-in
/// URL is a monitor that can silently watch the wrong network, and mainnet
/// identifiers belong to A6.5's reconcile, not to this lane. An absent endpoint
/// is a hard, fail-closed error: it is a misconfiguration, not an empty fleet.
fn endpoint_url(args: &[String]) -> Option<String> {
    arg_value(args, "--url")
        .or_else(|| std::env::var(URL_ENV).ok())
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Some(config_path) = arg_value(&args, "--config") else {
        eprintln!(
            "usage: cycle_monitor --url <IC endpoint> --config <path> \
             [--state <path>] [--allow-missing-state] [--fetch-root-key]"
        );
        return ExitCode::from(2);
    };
    let allow_missing_state = args.iter().any(|a| a == "--allow-missing-state");

    let configs: Vec<CanisterConfig> = match std::fs::read_to_string(&config_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            // Fail CLOSED: an unreadable config is not an empty fleet.
            eprintln!("cycle_monitor: cannot read config {config_path}: {e}");
            return ExitCode::from(1);
        }
    };

    // The prior run's snapshot. Absent vs unreadable are DIFFERENT states and
    // the library treats them differently — absence may be declared, corruption
    // never can be.
    // SSA-A6-D5 / CTO_RULING_A-6_register_derives: the fleet is DERIVED from the
    // compiled-in register, never taken from the caller. `configs` here is a bag
    // of PARAMETERS keyed by canister identity; the monitored set is whatever
    // `shipped_register()` says it is. A caller cannot shrink, extend or
    // misdirect what is watched.
    let configs = match derive_fleet(&configs) {
        Ok(fleet) => fleet,
        Err(why) => {
            eprintln!("cycle_monitor: {why}");
            return ExitCode::from(1);
        }
    };

    let state_path = arg_value(&args, "--state");
    let prior = match &state_path {
        None => PriorState::Absent,
        Some(p) => match std::fs::read_to_string(p) {
            // SSA-A6-D2: ONLY a genuinely missing path is `Absent`. A directory,
            // a permission error or a transient I/O failure is NOT absence — and
            // collapsing them meant `--allow-missing-state` excused corruption,
            // which is precisely what E7c promises it cannot.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PriorState::Absent,
            Err(_) => PriorState::Unreadable,
            Ok(text) => match serde_json::from_str::<Snapshot>(&text) {
                Ok(prev) => PriorState::Present {
                    run_at_ns: prev.run_at_ns,
                    // Carry the prior budget section forward: three of the four
                    // C-26 rules are about change over time, and this file is
                    // the only place that evidence lives.
                    budget: prev.budget.clone(),
                },
                Err(_) => PriorState::Unreadable,
            },
        },
    };

    // The live source. Built BEFORE the clock read so a misconfigured endpoint
    // fails immediately rather than after a partial run.
    //
    // `AgentTransport::new` performs no network I/O unless --fetch-root-key is
    // given, so constructing it is not itself an observation of anything.
    let Some(url) = endpoint_url(&args) else {
        eprintln!(
            "cycle_monitor: no IC endpoint configured. Pass --url <URL> or set ${URL_ENV}. \
             Refusing to run: an unconfigured endpoint is a misconfiguration, not an empty fleet."
        );
        return ExitCode::from(1);
    };
    let fetch_root_key = args.iter().any(|a| a == "--fetch-root-key");
    let transport = match AgentTransport::new(&url, fetch_root_key) {
        Ok(t) => t,
        Err(why) => {
            eprintln!("cycle_monitor: {why}");
            return ExitCode::from(1);
        }
    };
    // ONE transport, TWO sources. The balance source queries `cycle_balance` on
    // every registered canister; the C-26 source queries `derive_budget_stats`
    // on the ONE that serves it, named from the compiled-in register rather
    // than from config.
    let budget_source = LiveDeriveBudgetSource::new(&transport, &configs);
    let source = LiveBalanceSource::new(&transport);

    let now_ns = match std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    {
        Ok(n) => n,
        Err(_) => {
            eprintln!("cycle_monitor: system clock is before the unix epoch — refusing to run");
            return ExitCode::from(1);
        }
    };

    let snapshot =
        run_with_budget(&configs, &source, &budget_source, prior, allow_missing_state, now_ns);

    match serde_json::to_string_pretty(&snapshot) {
        Ok(json) => {
            println!("{json}");
            if let Some(p) = &state_path {
                if let Err(e) = persist_atomically(p, &json) {
                    // Failure to persist is ALERT, not a silent carry-on: the
                    // next run would read a stale timestamp and under-report
                    // staleness. The PRIOR snapshot is intact either way.
                    eprintln!("cycle_monitor: cannot persist state {p}: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        Err(e) => {
            eprintln!("cycle_monitor: cannot serialise snapshot: {e}");
            return ExitCode::from(1);
        }
    }

    ExitCode::from(snapshot.aggregate.exit_code() as u8)
}
