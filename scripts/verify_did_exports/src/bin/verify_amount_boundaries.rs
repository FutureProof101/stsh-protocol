// D2 — C4 rule-3 amount-boundary census. See src/lib.rs for the contract.
//
// Usage: verify_amount_boundaries <repo-root> [census.toml] [allowlist.toml]
// Exit:  0 = every raw u128/i128 reachable from a public endpoint (direct,
//        wrapper, or init argument) is on the reviewed allowlist; 1 = otherwise.
//
// A hit that is NOT on the allowlist is a STOP: a new raw-amount boundary needs
// a reviewed entry (C4 §4 rule 2), which only CTO/SSA adjudication grants. This
// tool never invites the operator to add one.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (root, census_path, allow_path): (PathBuf, PathBuf, PathBuf) = match args.as_slice() {
        [root] => (
            root.into(),
            Path::new(root).join("scripts/did_export_census.toml"),
            Path::new(root).join("scripts/amount_boundary_allowlist.toml"),
        ),
        [root, census, allow] => (root.into(), census.into(), allow.into()),
        _ => {
            eprintln!("usage: verify_amount_boundaries <repo-root> [census.toml] [allowlist.toml]");
            return ExitCode::FAILURE;
        }
    };

    let census = match verify_did_exports::load_census(&census_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("amount-boundary census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let allowlist = match verify_did_exports::load_allowlist(&allow_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("amount-boundary census: {e}");
            return ExitCode::FAILURE;
        }
    };

    match verify_did_exports::check_amount_boundaries(&root, &census, &allowlist) {
        Err(e) => {
            eprintln!("amount-boundary census could not complete: {e}");
            ExitCode::FAILURE
        }
        Ok(findings) if findings.is_empty() => {
            println!(
                "amount boundaries: OK — {} reviewed boundary allowance(s), all still present",
                allowlist.amount.len()
            );
            ExitCode::SUCCESS
        }
        Ok(findings) => {
            eprintln!("amount-boundary census FAILED — {} finding(s):", findings.len());
            for f in &findings {
                eprintln!("  {f}");
            }
            ExitCode::FAILURE
        }
    }
}
