// R-1 AC-15 — the ICRC deviation register lint. See src/r1_deviation_register.rs.
//
// Usage: verify_icrc_deviation_register <repo-root>
// Exit:  0 = every cited devNNN has an entry and every entry's binding test
//        exists; 1 = otherwise.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root: PathBuf = match args.as_slice() {
        [root] => root.into(),
        _ => {
            eprintln!("usage: verify_icrc_deviation_register <repo-root>");
            return ExitCode::from(1);
        }
    };
    match verify_did_exports::r1_deviation_register::run(&root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
