// D1 — did-vs-exports equivalence gate. See src/lib.rs for the contract.
//
// Usage: verify_did_exports <repo-root> [census.toml]
// Exit:  0 = every in-scope canister's .did and exports agree; 1 = anything else.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (root, census_path): (PathBuf, PathBuf) = match args.as_slice() {
        [root] => (root.into(), Path::new(root).join("scripts/did_export_census.toml")),
        [root, census] => (root.into(), census.into()),
        _ => {
            eprintln!("usage: verify_did_exports <repo-root> [census.toml]");
            return ExitCode::FAILURE;
        }
    };

    let census = match verify_did_exports::load_census(&census_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("did-vs-exports gate: {e}");
            return ExitCode::FAILURE;
        }
    };

    match verify_did_exports::check_did_exports(&root, &census) {
        Err(e) => {
            // Unresolvable input is a failure, never a skip.
            eprintln!("did-vs-exports gate could not complete: {e}");
            ExitCode::FAILURE
        }
        Ok(findings) if findings.is_empty() => {
            let scoped = census.canister.iter().filter(|c| c.in_scope).count();
            let excluded = census.canister.len() - scoped;
            println!(
                "did-vs-exports: OK — {scoped} canister(s) in scope, {excluded} excluded by name, \
                 {} named exception(s)",
                census.exception.len()
            );
            ExitCode::SUCCESS
        }
        Ok(findings) => {
            eprintln!("did-vs-exports gate FAILED — {} finding(s):", findings.len());
            for f in &findings {
                eprintln!("  {f}");
            }
            ExitCode::FAILURE
        }
    }
}
