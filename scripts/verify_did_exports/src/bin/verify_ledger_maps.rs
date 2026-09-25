// R-1 S4(b) — the `mod ledger_maps` visibility/cfg allowlist lint.
//
// Usage: verify_ledger_maps <repo-root>
// Exit:  0 = both views match the reviewed allowlist; 1 = a finding or a hard
//        failure (unparseable source, malformed/duplicate-key TOML, an
//        unevaluatable cfg). There is no silent-pass path.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root: PathBuf = match args.as_slice() {
        [root] => root.into(),
        _ => {
            eprintln!("usage: verify_ledger_maps <repo-root>");
            return ExitCode::from(1);
        }
    };
    match verify_did_exports::r1_ledger_maps::run(&root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
