//! CLI for Gate-D + Gate-V (P-ARITH G-1/G-2). Exit 0 only when EVERY check
//! passes — fail closed on any mismatch.
//!
//! Usage:
//!   verify_genesis_manifest [DEPLOYMENT_DIR]
//!       Gate-D + Gate-V phase 1 (pre-install) over
//!       DEPLOYMENT_DIR/{genesis_manifest.toml, stsh_token_init.did,
//!       vesting_init.did} (default: deployment/mainnet). Prints each
//!       artifact's SHA-256 — record these in MAINNET_DEPLOYMENT.md at RR-2.
//!
//!       R4-1: Gate-D REFUSES, fail-closed, to certify an artifact set that
//!       still carries a P0-3 placeholder principal — every rejected site is a
//!       failing `DP3-*` check and the CLI exits nonzero until RR-1 (the real
//!       principal replacement) has been performed.
//!
//!   verify_genesis_manifest [DEPLOYMENT_DIR] --posture
//!       R-3 §6.1: run the full gate and assert the DECLARED posture in
//!       deployment/mainnet/genesis_principals.toml. This is the form
//!       `run_gate.sh` invokes — see the block comment at the call site below.
//!
//!   verify_genesis_manifest [DEPLOYMENT_DIR] --post-install \
//!       --vesting-balance <base_units> --schedule-sum <base_units>
//!       Gate-V phase 2: feed the LIVE post-install queries (token
//!       icrc1_balance_of(vesting canister) and Σ over list_schedules) and
//!       verify both equal the manifest founders allocation.

use std::path::PathBuf;
use std::process::ExitCode;
use verify_genesis_manifest::*;

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn print_checks(checks: &[CheckResult]) -> bool {
    for c in checks {
        println!("[{}] {} — {}", if c.pass { "PASS" } else { "FAIL" }, c.name, c.detail);
    }
    all_pass(checks)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = PathBuf::from(
        args.first()
            .filter(|a| !a.starts_with("--"))
            .cloned()
            .unwrap_or_else(|| "deployment/mainnet".to_string()),
    );

    if args.iter().any(|a| a == "--post-install") {
        let manifest = match std::fs::read_to_string(dir.join("genesis_manifest.toml")) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read manifest: {}", e);
                return ExitCode::FAILURE;
            }
        };
        let expected = match vesting_custody_total(&manifest) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                return ExitCode::FAILURE;
            }
        };
        let parse = |flag: &str| -> Option<u128> {
            arg_value(&args, flag).and_then(|v| v.replace('_', "").parse().ok())
        };
        let (Some(balance), Some(sum)) = (parse("--vesting-balance"), parse("--schedule-sum"))
        else {
            eprintln!("--post-install requires --vesting-balance <n> and --schedule-sum <n>");
            return ExitCode::FAILURE;
        };
        println!(
            "Gate-V phase 2 (post-install), expected vesting custody total (founders + counsel) = {}",
            expected
        );
        let ok = print_checks(&gate_v_post_install(balance, sum, expected));
        println!("{}", if ok { "GATE-V POST-INSTALL: PASS" } else { "GATE-V POST-INSTALL: FAIL" });
        return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }

    // ── R-3 §6.1 — the POSTURE stage (run_gate.sh) ───────────────────────────
    //
    // `verify_genesis_manifest <dir>` is fail-closed and stays RED until RR-1,
    // which is why the gate could not simply invoke it. `--posture` asserts the
    // DECLARED posture in deployment/mainnet/genesis_principals.toml instead:
    //
    //   rr1_performed = false ⇒ pass iff the observed failing set is a SUBSET of
    //     the CLOSED three-member allowed list (DP3 sites ∪ GP1-pending-<ROLE>
    //     for roles with no in-repo value ∪ GP2-value-STAKING_CANISTER, that
    //     last one only while its own DP3 sites still fail). EXACT-MATCH
    //     membership, never a prefix test — `GP1-pending-` and
    //     `GP1-pending-input-populated-` share a prefix on purpose.
    //   rr1_performed = true  ⇒ pass IF AND ONLY IF the observed failing set is
    //     EXACTLY EMPTY. Any single failure of any kind at any site exits
    //     nonzero. There is no "no failures are expected" branch.
    //
    // The POSTURE_MARKER line is printed on EVERY invocation, pass or fail: it
    // is the only evidence that distinguishes "the stage ran and passed" from
    // "the stage was never invoked", and AC-12's behavioural self-test asserts
    // on it.
    if args.iter().any(|a| a == "--posture") {
        let (verdict, checks) = match run_posture_on_dir(&dir) {
            Ok(v) => v,
            Err(e) => {
                println!("{POSTURE_MARKER} die — genesis inputs unreadable/unparseable: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "genesis posture: rr1_performed={} — {} check(s), {} failing",
            verdict.rr1_performed,
            checks.len(),
            verdict.failing.len()
        );
        if verdict.passes() {
            if verdict.rr1_performed {
                println!(
                    "{POSTURE_MARKER} pass — rr1_performed=true and the observed failing set is \
                     EXACTLY EMPTY"
                );
            } else {
                println!(
                    "{POSTURE_MARKER} pass — rr1_performed=false and all {} failing check(s) are \
                     within the closed pre-RR-1 allowed set ({} names)",
                    verdict.failing.len(),
                    verdict.allowed.len()
                );
            }
            return ExitCode::SUCCESS;
        }
        for name in verdict.disallowed.iter() {
            let detail = checks
                .iter()
                .find(|c| &c.name == name)
                .map(|c| c.detail.as_str())
                .unwrap_or("");
            println!("  DISALLOWED  {name} — {detail}");
        }
        if verdict.rr1_performed {
            println!(
                "{POSTURE_MARKER} die — rr1_performed=true requires the observed failing set to \
                 be EXACTLY EMPTY; {} check(s) are failing (listed above)",
                verdict.disallowed.len()
            );
        } else {
            println!(
                "{POSTURE_MARKER} die — {} failing check(s) are NOT in the closed pre-RR-1 \
                 allowed set (listed above)",
                verdict.disallowed.len()
            );
        }
        return ExitCode::FAILURE;
    }

    match run_gates_on_dir(&dir) {
        Ok(report) => {
            println!("Artifact SHA-256 (record at RR-2):");
            for (name, sha) in &report.artifact_hashes {
                println!("  {}  {}", sha, name);
            }
            let ok = print_checks(&report.checks);
            // R4-1: a raw `DP3-… FAIL` must not read as a manifest authoring
            // bug. Name the cause and the remedy explicitly.
            if report.checks.iter().any(|c| !c.pass && c.name.starts_with("DP3-")) {
                println!();
                println!(
                    "DEPLOY BLOCKED — RR-1 HAS NOT BEEN PERFORMED. The genesis artifacts in \
                     this directory still carry P0-3 PLACEHOLDER principals (each failing \
                     DP3-* check above names the exact site). These are deterministic \
                     stand-ins, not owned principals: installing genesis against them would \
                     assign real supply to accounts nobody controls. Remedy: perform RR-1 — \
                     replace every placeholder principal in genesis_manifest.toml, \
                     stsh_token_init.did and vesting_init.did with the approved production \
                     principals — then re-run this gate."
                );
            }
            println!(
                "{}",
                if ok { "GATE-D + GATE-V(pre-install): PASS" } else { "GATE-D + GATE-V(pre-install): FAIL" }
            );
            if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Err(e) => {
            eprintln!("FAIL (parse/read): {}", e);
            ExitCode::FAILURE
        }
    }
}
