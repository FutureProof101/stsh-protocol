// =============================================================================
// R-10 item 2 — the OPERATIONS.md run command must resolve an IC endpoint
// =============================================================================
//
// The documented command carried no `--url` and set no `$CYCLE_MONITOR_IC_URL`,
// so an operator following the runbook verbatim got exit 1 and no monitoring.
// `endpoint_url` (src/main.rs) has no default by design, so the runbook is the
// only place the endpoint can come from — which makes the runbook text a
// load-bearing artifact, and load-bearing artifacts get a test.

use std::process::Command;

/// Extracts every logical `cargo run ... cycle_monitor ...` command from
/// OPERATIONS.md, joining `\`-continued physical lines into one logical line
/// FIRST so a flag sitting on a continuation line is still visible to the
/// filter below. Only lines that actually START with `cargo run` are
/// candidates — a running-prose mention of the binary elsewhere in the doc is
/// not swept in.
fn documented_cycle_monitor_commands() -> Vec<String> {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("OPERATIONS.md"),
    )
    .unwrap();

    let mut buf = String::new();
    let mut logical: Vec<String> = Vec::new();
    for line in doc.lines() {
        let trimmed = line.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            buf.push_str(head.trim_end());
            buf.push(' ');
        } else {
            buf.push_str(trimmed);
            let candidate = buf.trim().to_string();
            if candidate.starts_with("cargo run") && candidate.contains("cycle_monitor") {
                logical.push(candidate);
            }
            buf.clear();
        }
    }
    logical
}

#[test]
fn test_documented_run_command_resolves_an_endpoint() {
    let cmds = documented_cycle_monitor_commands();
    assert!(!cmds.is_empty(), "OPERATIONS.md must document at least one runnable command");
    for cmd in cmds {
        assert!(
            cmd.contains("--url") || cmd.contains("$CYCLE_MONITOR_IC_URL"),
            "documented command resolves no endpoint and would exit 1 at \
             `endpoint_url` (scripts/cycle_monitor/src/main.rs): `{cmd}`"
        );
    }
}

/// Positive/negative pair: proves the check above discriminates rather than
/// passing on an earlier, unrelated exit. `--state` points at a not-yet-created
/// path so `--allow-missing-state` is load bearing (a NotFound state path is
/// `Absent`, which the flag then permits).
///
/// Accepted residual: no explicit timeout wrapper around the subprocess. A
/// connection refusal to 127.0.0.1:1 is a local, immediate OS-level refusal (no
/// DNS, no TLS handshake), so no hang is expected in practice; a full timeout
/// harness is out of proportion to this fix and is recorded here as a
/// deliberate, reasoned residual rather than silently dropped.
#[test]
fn test_binary_resolves_endpoint_only_when_url_is_passed() {
    let pid = std::process::id();
    let tmp_cfg = std::env::temp_dir().join(format!("cm_cfg_{pid}.json"));
    let tmp_state = std::env::temp_dir().join(format!("cm_state_{pid}.json")); // not created
    std::fs::write(&tmp_cfg, "[]").unwrap();

    let with_url = Command::new(env!("CARGO_BIN_EXE_cycle_monitor"))
        .args([
            "--url",
            "http://127.0.0.1:1",
            "--config",
            tmp_cfg.to_str().unwrap(),
            "--state",
            tmp_state.to_str().unwrap(),
            "--allow-missing-state",
        ])
        .output()
        .expect("binary must run");
    let stderr_with = String::from_utf8_lossy(&with_url.stderr);
    assert!(
        !stderr_with.contains("no IC endpoint configured"),
        "binary rejected the URL as absent even though --url was passed: {stderr_with}"
    );

    let without_url = Command::new(env!("CARGO_BIN_EXE_cycle_monitor"))
        .env_remove("CYCLE_MONITOR_IC_URL")
        .args([
            "--config",
            tmp_cfg.to_str().unwrap(),
            "--state",
            tmp_state.to_str().unwrap(),
            "--allow-missing-state",
        ])
        .output()
        .expect("binary must run");
    let stderr_without = String::from_utf8_lossy(&without_url.stderr);
    assert!(
        stderr_without.contains("no IC endpoint configured"),
        "binary did NOT report the expected endpoint-resolution failure with no --url and \
         no env var — the with-url case above proves nothing if this half cannot fail: \
         {stderr_without}"
    );

    let _ = std::fs::remove_file(&tmp_cfg);
}
