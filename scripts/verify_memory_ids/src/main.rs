// MemoryId registry lint — blocking gate check (HARDENING V2 acceptance #4).
//
//   verify_memory_ids [<repo-root>]
//
// Exit 0 = clean. Exit 1 = violations (prints every one). Exit 2 = usage/IO.

use std::path::PathBuf;
use std::process::ExitCode;
use verify_memory_ids::{check, scan_tree, Config};

fn main() -> ExitCode {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let config_path = root.join("docs/MEMORY_ID_REGISTRY.md");
    let raw = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("verify_memory_ids: cannot read {}: {e}", config_path.display());
            return ExitCode::from(2);
        }
    };
    let config: Config = match verify_memory_ids::parse_registry(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verify_memory_ids: {} is malformed: {e}", config_path.display());
            return ExitCode::from(2);
        }
    };

    // Errors propagate: a discovery failure, malformed manifest, or degenerate
    // scan set is a HARD failure, never an empty pass.
    let code = match scan_tree(&root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verify_memory_ids: scan-set discovery FAILED — {e}");
            eprintln!(
                "The scan set must be complete: an unreadable or ambiguous tree cannot be \
                 certified, and an empty set would be a vacuous pass."
            );
            return ExitCode::from(2);
        }
    };

    let total: usize = code.values().map(|v| v.result.allocations.len()).sum();
    let errors = check(&config, &code);

    let canisters = code.values().filter(|c| c.info.is_canister).count();
    let shared = code.len() - canisters;

    if errors.is_empty() {
        println!(
            "verify_memory_ids: scan set = {} first-party crates ({canisters} canister, \
             {shared} shared), discovered exhaustively under the repo root.",
            code.len()
        );
        println!(
            "verify_memory_ids: OK — {total} allocations across {} canisters, \
             no duplicates, no retired-ID reuse, code and docs/MEMORY_ID_REGISTRY.md agree.",
            code.values().filter(|v| !v.result.allocations.is_empty()).count()
        );
        return ExitCode::SUCCESS;
    }

    eprintln!("verify_memory_ids: {} VIOLATION(S)\n", errors.len());
    for e in &errors {
        eprintln!("  • {e}\n");
    }
    eprintln!(
        "MemoryId allocation is append-only per canister. Retired IDs are frozen forever \
         — recycling one silently reinterprets the old region's bytes as a new type.\n\
         Reconcile canisters/*/src against docs/MEMORY_ID_REGISTRY.md (and the office registry) \
         before this can build."
    );
    ExitCode::from(1)
}
