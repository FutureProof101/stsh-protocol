// =============================================================================
// check_candid_did — parse a .did with the real Candid parser, or fail
// =============================================================================
// scripts/embed_candid_metadata.sh must not hand ic-wasm a .did it has not
// parsed: ic-wasm embeds whatever bytes it is given and performs no Candid
// parse, so a malformed interface is published on a CLEAN EXIT. The structural
// (delimiter-balance) check this replaces could not decide syntax — it accepted
// `service : { method : (nat) -> (nat) nonsense };`, which is balanced,
// service-shaped, and syntactically invalid.
//
// This binary is the parser the script lacked. It does nothing but parse: the
// crate already depends on candid_parser, is host-only, and adding a bin here
// moves neither the root Cargo.toml nor Cargo.lock.
//
// Usage:   check_candid_did <path.did>
// Exit:    0 = parses and declares a service; 1 = anything else, reason on stderr.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [did] = args.as_slice() else {
        eprintln!("usage: check_candid_did <path.did>");
        return ExitCode::FAILURE;
    };
    let path = Path::new(did);
    if !path.is_file() {
        eprintln!("candid file not found: {did}");
        return ExitCode::FAILURE;
    }
    // pretty_check_file parses AND type-checks, resolving `import` relative to
    // the file, which is what an embedded candid:service has to satisfy.
    match candid_parser::pretty_check_file(path) {
        Err(e) => {
            eprintln!("{did} is not valid candid: {e}");
            ExitCode::FAILURE
        }
        // The Option<Type> is the actor the parse produced. Absent means the
        // file declares no service, so there is no interface to embed.
        Ok((_, None)) => {
            eprintln!("{did} declares no service");
            ExitCode::FAILURE
        }
        Ok((_, Some(_))) => ExitCode::SUCCESS,
    }
}
