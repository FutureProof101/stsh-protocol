// R-1 S4(b2) + S4(b3-belt) — the caller-boundary occurrence lint, the three
// categorical bans, and the identifier-synthesizing-macro name belt, all over
// rustc's OWN dep-info census of `stsh_token`.
//
// Usage: verify_ledger_boundary <repo-root> [--disable-include-ban]
//                                           [--disable-path-ban]
//                                           [--disable-belt]
//                                           [--ast-layer-only]
// Exit:  0 = clean; 1 = a finding; 3 = stsh_token's dep-info `.d` is MISSING.
//
// Exit 3 is deliberately distinct from a finding: a missing compiler record is
// not "0 findings", and this lint never falls back to a directory walk.
//
// The four flags exist ONLY for the brief's required what-if mutation runs
// (M7m, M7p, M-compile-fail, and AC-7i's Layer-1-alone demonstration); the gate
// never passes them.

use std::path::PathBuf;
use std::process::ExitCode;

use verify_did_exports::r1_ledger_boundary as boundary;

fn main() -> ExitCode {
    let mut root: Option<PathBuf> = None;
    let mut opts = boundary::Options::default();
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--disable-include-ban" => opts.disable_include_ban = true,
            "--disable-path-ban" => opts.disable_path_ban = true,
            "--disable-belt" => opts.disable_belt = true,
            "--ast-layer-only" => opts.ast_layer_only = true,
            other if other.starts_with("--") => {
                eprintln!("unknown flag: {other}");
                return ExitCode::from(1);
            }
            other => root = Some(other.into()),
        }
    }
    let Some(root) = root else {
        eprintln!("usage: verify_ledger_boundary <repo-root> [flags]");
        return ExitCode::from(1);
    };
    match boundary::run(&root, &opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if let Some(rest) = e.strip_prefix(boundary::NO_DEPINFO_SENTINEL) {
                eprintln!("{rest}");
                ExitCode::from(boundary::EXIT_NO_DEPINFO)
            } else {
                eprintln!("{e}");
                ExitCode::from(1)
            }
        }
    }
}
