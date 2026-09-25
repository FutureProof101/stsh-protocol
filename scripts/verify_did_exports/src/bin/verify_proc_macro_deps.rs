// R-1 S4(b3-direct) + S4(b3-transitive) — the proc-macro dependency-identity
// allowlists, split by EDGE (the crate's own manifest edges vs the rest of the
// resolved closure).
//
// Usage: verify_proc_macro_deps <repo-root>
// Exit:  0 = both allowlists match the resolved graph exactly, both directions;
//        1 = a finding or a hard failure.
//
// Reads `cargo metadata --format-version 1 --offline --locked`'s structured JSON
// resolve graph directly. It never shells out to `cargo tree`: that command's
// `{p}` format and tree-drawing characters are a human-readability convenience,
// not a stable machine interface.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root: PathBuf = match args.as_slice() {
        [root] => root.into(),
        _ => {
            eprintln!("usage: verify_proc_macro_deps <repo-root>");
            return ExitCode::from(1);
        }
    };
    match verify_did_exports::r1_proc_macro_deps::run(&root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
