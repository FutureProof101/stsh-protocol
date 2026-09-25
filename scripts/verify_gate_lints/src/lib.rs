//! `verify_gate_lints` — remediation lane R-L, campaign §5 G-a..G-d.
//!
//! Four blocking `run_gate.sh` stages plus one packet-only tool. Host tool
//! only; never compiled into a canister Wasm.
//!
//! WHAT THE GATE TRUSTS (CTO ruling `cto-ruling-lint-tcb-boundary-2026-09-04`):
//!   1. This crate's own source — including the cfg evaluator, the default-
//!      closure resolver, and the `--target wasm32-unknown-unknown` literal.
//!      A compromised `syn` or Rust parser is residual #1.
//!   2. The committed data under `scripts/gate_lints/` and
//!      `tests/BINDING_REGISTRY.toml`. Editing one to remove a real finding is
//!      residual #2; the control is the reviewed diff, not a second lint.
//!   3. `run_gate.sh` and the shell/toolchain it runs under, INCLUDING the
//!      `BASH_ENV`/`ENV` startup files bash sources before the script's first
//!      line — residual #3. R-3b's environment sanitisation is the named
//!      control for the shell-injection sub-case.
//!   4. Each canister crate's own `Cargo.toml` as the source of truth for its
//!      `default` closure — residual #4 (a `build.rs` that rewrites the
//!      manifest between scan and build).
//!   5. The reviewed dependency set (`Cargo.lock`) — residual #5.
//!
//! The production TARGET ATOMS are captured live from the pinned toolchain
//! (`rustc --print cfg --target wasm32-unknown-unknown`), per the CTO ruling
//! addendum 2026-09-05: rustc's key set is authoritative, a hand-written table
//! is not. The `--target` triple itself is the literal constant; only the atom
//! VALUES for that triple come from rustc, so the host's own triple never
//! substitutes for the production one.

pub mod bindings;
pub mod ceilings;
pub mod census;
pub mod cfg_eval;
pub mod claims;
pub mod data;
pub mod did;
pub mod features;
pub mod no_skips;
pub mod pool_accounting_census;
pub mod scope;
pub mod shell_lex;
pub mod target_cfg;

/// Exit codes. 0 = clean, 1 = findings, 2 = the lint refuses to evaluate
/// (unknown cfg atom, `testing` in `default`, unreadable input).
pub const EXIT_OK: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_REFUSE: i32 = 2;

/// Locate the workspace root from an explicit argument or the CWD.
pub fn workspace_root(arg: Option<&str>) -> std::path::PathBuf {
    match arg {
        Some(a) => std::path::PathBuf::from(a),
        None => std::env::current_dir().expect("cwd"),
    }
}

/// Does this attribute list make the function a HARNESS-EXECUTED test?
///
/// ENUMERATION (2026-09-05, over the whole tree — `#[...test...]` attribute
/// census): the STSH tree uses exactly ONE form, `#[test]`, 2,205 times. There
/// is no `#[tokio::test]`, `#[async_std::test]`, `#[pocket_ic::test]` or
/// `#[test_case]` anywhere in it today. The rule is nevertheless written as
/// "the attribute path's LAST segment is `test`", so the three qualified async
/// forms above are accepted the day one is introduced, rather than the lint
/// silently going blind to a whole suite. A `test_case`-style parameterised
/// macro is NOT accepted: it does not name a single harness test, and the
/// binding registry names one.
///
/// Used by `bindings` (a bound test that is not a test is not evidence) and by
/// `no_skips` (the scanned corpus is `#[test]` fns plus fixture loaders), so
/// the two lints cannot disagree about what a test is.
pub fn is_test_attr(attr: &syn::Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|s| s.ident == "test")
}

/// Every accepted rendering of the test attribute on this function, for use in
/// a violation message.
pub fn test_attrs(f: &syn::ItemFn) -> Vec<String> {
    f.attrs
        .iter()
        .filter(|a| is_test_attr(a))
        .map(|a| {
            let p = a.path();
            quote::quote!(#p).to_string().replace(' ', "")
        })
        .collect()
}
