// =============================================================================
// R-1 — negative fixtures for the three new gate lints.
// =============================================================================
//
// A lint that has never been shown to FAIL is not evidence. Each case below
// constructs a minimal tree in a temp directory, runs the lint against it, and
// asserts the specific finding — so the gate's green result means "these
// mutations were tried and refused", not "nothing was checked".
//
// The boundary fixtures BUILD A REAL CRATE with a real `cargo build
// --target wasm32-unknown-unknown`, so the dep-info `.d` they are checked
// against is one rustc actually wrote. A hand-written `.d`-shaped string would
// be self-inherited verification: the lint would be checked against the very
// belief under test (brief §8).

use std::path::{Path, PathBuf};
use std::process::Command;

use verify_did_exports::{r1_deviation_register, r1_ledger_boundary as boundary, r1_ledger_maps};

// ── temp-tree plumbing ───────────────────────────────────────────────────────

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "r1fix-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, rel: &str, body: &str) {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// =============================================================================
// S4(b) — the mod ledger_maps visibility/cfg allowlist lint
// =============================================================================

/// The shape the real crate has: the module, its statics, and the visible items.
fn maps_source(extra_items: &str, balances_vis: &str) -> String {
    format!(
        r#"
mod ledger_maps {{
    use super::*;

    thread_local! {{
        {balances_vis} static BALANCES: RefCell<u128> = RefCell::new(0);
        static STAKING_LOCKS: RefCell<u128> = RefCell::new(0);
        static SUM_BALANCES: RefCell<u128> = RefCell::new(0);
        static SUM_STAKING_LOCKS: RefCell<u128> = RefCell::new(0);
    }}

    pub fn get_balance() -> u128 {{ 0 }}
    pub fn write_balance() {{}}

    struct UpgradeWitness(());
    fn witness_for_post_upgrade() -> UpgradeWitness {{ UpgradeWitness(()) }}
    pub(crate) fn restore_from_checkpoint() {{}}

    #[cfg(feature = "testing")]
    pub(crate) fn set_sums_for_test() {{}}
{extra_items}
}}
"#
    )
}

const MAPS_ALLOWLIST: &str = r#"
[[item]]
name = "get_balance"
cfg = "always"

[[item]]
name = "write_balance"
cfg = "always"

[[item]]
name = "restore_from_checkpoint"
cfg = "always"

[[item]]
name = "set_sums_for_test"
cfg = "testing"
"#;

fn maps_tree(tag: &str, source: &str, allowlist: &str) -> Tmp {
    let t = Tmp::new(tag);
    t.write("canisters/token/src/lib.rs", source);
    t.write("canisters/token/ledger_maps_allowlist.toml", allowlist);
    t
}

/// F-A (positive control): the module and the TOML as specified PASS both views.
/// Without this, every negative below could be passing for the wrong reason.
#[test]
fn r1f_maps_a_specified_module_and_toml_pass_both_views() {
    let t = maps_tree("maps-a", &maps_source("", ""), MAPS_ALLOWLIST);
    r1_ledger_maps::run(t.root()).expect("the specified shape must pass");
}

/// F-B / M5-(x2b): a new non-private item with no TOML row fails the production
/// view — at `pub`, `pub(crate)`, and `pub(super)` alike, because all three are
/// reachable from every other function in `lib.rs`.
#[test]
fn r1f_maps_b_a_new_visible_item_without_a_row_fails() {
    for vis in ["pub", "pub(crate)", "pub(super)"] {
        let t = maps_tree(
            "maps-b",
            &maps_source(&format!("    {vis} fn write_balance_no_sum() {{}}\n"), ""),
            MAPS_ALLOWLIST,
        );
        let e = r1_ledger_maps::run(t.root())
            .unwrap_err_or_panic(&format!("`{vis}` item with no row must be refused"));
        assert!(
            e.contains("write_balance_no_sum") && e.contains("PRODUCTION VIEW"),
            "[{vis}] {e}"
        );
    }
}

/// F-C / M5-(x2a): widening BALANCES itself — inside the `thread_local!` macro,
/// which is where a scan that only walked resolvable items would miss it.
#[test]
fn r1f_maps_c_widening_the_maps_themselves_fails() {
    for vis in ["pub", "pub(crate)"] {
        let t = maps_tree("maps-c", &maps_source("", vis), MAPS_ALLOWLIST);
        let e = r1_ledger_maps::run(t.root())
            .unwrap_err_or_panic("a widened BALANCES must be refused");
        assert!(e.contains("BALANCES"), "[{vis}] {e}");
    }
}

/// F-D: an unparseable `.rs`, and a missing / malformed TOML, are HARD failures
/// — never a pass.
#[test]
fn r1f_maps_d_unparseable_or_malformed_inputs_are_hard_failures() {
    let t = maps_tree("maps-d1", "mod ledger_maps { this is not rust", MAPS_ALLOWLIST);
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("unparseable source");
    assert!(e.contains("cannot parse as Rust"), "{e}");

    let t = Tmp::new("maps-d2");
    t.write("canisters/token/src/lib.rs", &maps_source("", ""));
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("missing TOML");
    assert!(e.contains("cannot read"), "{e}");

    let t = maps_tree("maps-d3", &maps_source("", ""), "[[item]\nname = \"x\"");
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("malformed TOML");
    assert!(e.contains("malformed allowlist TOML"), "{e}");

    // The module itself missing is a hard failure, not a vacuous pass.
    let t = maps_tree("maps-d4", "fn nothing() {}", MAPS_ALLOWLIST);
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("no module");
    assert!(e.contains("not found"), "{e}");
}

/// F-E / M5-(x2c): the exact V5 RED-1 gap — a `testing`-cfg'd item present in
/// the code with NO TOML row fails the testing view.
#[test]
fn r1f_maps_e_a_testing_item_without_a_row_fails_the_testing_view() {
    let t = maps_tree(
        "maps-e",
        &maps_source(
            "    #[cfg(feature = \"testing\")]\n    pub fn extra_hook_for_test() {}\n",
            "",
        ),
        MAPS_ALLOWLIST,
    );
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("extra testing item");
    assert!(
        e.contains("TESTING VIEW") && e.contains("extra_hook_for_test"),
        "{e}"
    );
}

/// F-E2 / M5-(x2e): the mismatched-cfg direction — the TOML claims an item is
/// `"always"` while the source gates it behind `testing`. This is the gap that
/// lets a test hook ship with no cfg guard at all if it is not checked.
#[test]
fn r1f_maps_e2_a_cfg_mismatch_fails_the_production_view() {
    let bad = MAPS_ALLOWLIST.replace(
        "name = \"set_sums_for_test\"\ncfg = \"testing\"",
        "name = \"set_sums_for_test\"\ncfg = \"always\"",
    );
    let t = maps_tree("maps-e2", &maps_source("", ""), &bad);
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("cfg mismatch");
    assert!(
        e.contains("PRODUCTION VIEW") && e.contains("set_sums_for_test"),
        "{e}"
    );
}

/// F-F / M5-(x2d): a TOML row naming an item that does not exist.
#[test]
fn r1f_maps_f_a_stale_row_fails() {
    let t = maps_tree(
        "maps-f",
        &maps_source("", ""),
        &format!("{MAPS_ALLOWLIST}\n[[item]]\nname = \"ghost\"\ncfg = \"always\"\n"),
    );
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("stale row");
    assert!(e.contains("ghost"), "{e}");
}

/// F-G / M5-(x2f), the RED-1 (V6) mutation: a DUPLICATE key inside one
/// `[[item]]` table must fail AT LOAD, before either view runs. A loader that
/// silently keeps the first or the last value is itself the defect this catches.
#[test]
fn r1f_maps_g_a_duplicate_key_in_one_table_fails_at_load() {
    let dup = format!("{MAPS_ALLOWLIST}\n[[item]]\nname = \"a\"\nname = \"b\"\ncfg = \"always\"\n");
    let t = maps_tree("maps-g", &maps_source("", ""), &dup);
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("duplicate key");
    assert!(
        e.contains("malformed allowlist TOML"),
        "the DUPLICATE KEY must be refused by the loader, not silently resolved: {e}"
    );
}

/// F-H: an unrecognised `cfg` form is a hard failure. This lint has no cfg
/// evaluator and must not pretend to one.
#[test]
fn r1f_maps_h_an_unevaluatable_cfg_is_a_hard_failure() {
    let t = maps_tree(
        "maps-h",
        &maps_source("    #[cfg(target_arch = \"wasm32\")]\n    pub fn odd() {}\n", ""),
        MAPS_ALLOWLIST,
    );
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("unknown cfg");
    assert!(e.contains("cannot evaluate"), "{e}");
}

// ── V1 RED-1: associated items in `impl` blocks are items too ────────────────
//
// SSA landed-diff review `SSA_LANDED_DIFF_R-1_V1_2026-09-05.md` RED-1 / CTO
// triage `cto-triage-ssa-landed-diff-round1-2026-09-05` §2: a public associated
// function on a module newtype was a raw-write seam that both boundary lints
// reported clean, because `collect_into` had a `syn::Item::Impl(_) => continue`
// arm. These fixtures pin the closed hole.

/// F-I / the SSA's EXACT bypass: an inherent `impl UpgradeWitness` inside the
/// module with a `pub` associated function writing `BALANCES` directly.
#[test]
fn r1f_maps_i_a_public_associated_fn_inside_the_module_fails() {
    for vis in ["pub", "pub(crate)", "pub(super)"] {
        let t = maps_tree(
            "maps-i",
            &maps_source(
                &format!(
                    "    impl UpgradeWitness {{\n        \
                     {vis} fn ssa_write_without_sum(key: Vec<u8>, value: u128) {{\n            \
                     BALANCES.with(|b| {{ b.borrow_mut().insert(key, value); }});\n        \
                     }}\n    }}\n"
                ),
                "",
            ),
            MAPS_ALLOWLIST,
        );
        let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic(
            "a public associated fn on a module type must be refused",
        );
        assert!(
            e.contains("UpgradeWitness::ssa_write_without_sum")
                && e.contains("PRODUCTION VIEW"),
            "[{vis}] {e}"
        );
    }
}

/// F-J (negative control): a default-private associated fn in an INHERENT impl
/// is unreachable outside the module and must NOT be demanded of the allowlist —
/// otherwise F-I would be passing merely because impls are now banned outright.
#[test]
fn r1f_maps_j_a_private_associated_fn_is_not_a_seam() {
    let t = maps_tree(
        "maps-j",
        &maps_source(
            "    impl UpgradeWitness {\n        fn helper(&self) -> u128 { 0 }\n    }\n",
            "",
        ),
        MAPS_ALLOWLIST,
    );
    r1_ledger_maps::run(t.root()).expect("a private associated fn is not a visible seam");
}

/// F-K: a TRAIT impl's items carry no written visibility yet are callable
/// wherever the trait is in scope, so every one of them must be enumerated.
#[test]
fn r1f_maps_k_trait_impl_items_are_enumerated_without_pub() {
    let t = maps_tree(
        "maps-k",
        &maps_source(
            "    impl Default for UpgradeWitness {\n        \
             fn default() -> Self { UpgradeWitness(()) }\n    }\n",
            "",
        ),
        MAPS_ALLOWLIST,
    );
    let e = r1_ledger_maps::run(t.root())
        .unwrap_err_or_panic("a trait impl item must be enumerated");
    assert!(
        e.contains("<UpgradeWitness as Default>::default"),
        "{e}"
    );
}

/// F-L: the same seam moved OUT of the module — an `impl` block elsewhere in
/// `lib.rs` on a module type. Since RED-1 round 2 this shape requires a
/// non-private type in the module in the first place, so BOTH signals must
/// fire: the MODULE TYPE rule (the type must not leave the module at all) AND
/// the out-of-module impl enumeration (the seam it carries is still named).
#[test]
fn r1f_maps_l_impl_outside_the_module_on_a_module_type_fails() {
    let src = format!(
        "{}\nimpl ledger_maps::Escapee {{\n    \
         pub fn escape_hatch() {{}}\n}}\n",
        maps_source("    pub(crate) struct Escapee(());\n", "")
    );
    let t = maps_tree("maps-l", &src, MAPS_ALLOWLIST);
    let e = r1_ledger_maps::run(t.root())
        .unwrap_err_or_panic("an out-of-module impl on a module type must be refused");
    assert!(e.contains("Escapee::escape_hatch"), "{e}");
    assert!(
        e.contains("MODULE TYPE: `Escapee`"),
        "the type itself must be refused, not only the seam it carries: {e}"
    );
}

/// F-O / RED-1 round 2 (SSA_LANDED_DIFF_R-1_V2_2026-09-05.md): the residual
/// drift-lock. A type declared in `mod ledger_maps` at ANY visibility broader
/// than default-private is refused — and an allowlist row for it CANNOT rescue
/// it, because a nameable type carries inherent `impl`s written anywhere in the
/// crate, including inside a function body where no item walk looks (which is
/// exactly how the V2 lint was bypassed).
#[test]
fn r1f_maps_o_a_non_private_type_in_the_module_is_refused_even_with_a_row() {
    for (decl, name) in [
        ("pub struct Seam(());", "Seam"),
        ("pub(crate) struct Seam(());", "Seam"),
        ("pub(super) enum Seam { A }", "Seam"),
        ("pub(crate) type Seam = u128;", "Seam"),
    ] {
        // WITH a row: the row must not buy a pass.
        let allowlist =
            format!("{MAPS_ALLOWLIST}\n[[item]]\nname = \"{name}\"\ncfg = \"always\"\n");
        let t = maps_tree("maps-o", &maps_source(&format!("    {decl}\n"), ""), &allowlist);
        let e = r1_ledger_maps::run(t.root())
            .unwrap_err_or_panic("a non-private type in the module must be refused");
        assert!(
            e.contains(&format!("MODULE TYPE: `{name}`")),
            "[{decl}] {e}"
        );
    }
}

/// F-P (negative control for F-O): a default-private type in the module is NOT
/// a finding — otherwise F-O would be passing merely because types are banned
/// outright, and the real module's own `UpgradeWitness`/`GenesisWitness` would
/// be permanently RED.
#[test]
fn r1f_maps_p_a_private_type_in_the_module_is_not_a_finding() {
    let t = maps_tree(
        "maps-p",
        &maps_source("    struct Sealed(());\n    enum Other { A }\n", ""),
        MAPS_ALLOWLIST,
    );
    r1_ledger_maps::run(t.root()).expect("a private type is not a visible seam");
}

/// F-M (positive control for the new row shape): an allowlisted `Type::name`
/// row is accepted, and under the testing cfg it lands in the TESTING view only —
/// so a `Type::name` row is a real, usable review record, not a permanent RED.
#[test]
fn r1f_maps_m_an_allowlisted_associated_fn_row_passes_under_its_cfg() {
    let allowlist = format!(
        "{MAPS_ALLOWLIST}\n[[item]]\nname = \"UpgradeWitness::seed_for_test\"\ncfg = \"testing\"\n"
    );
    let t = maps_tree(
        "maps-m",
        &maps_source(
            "    #[cfg(feature = \"testing\")]\n    impl UpgradeWitness {\n        \
             pub fn seed_for_test() {}\n    }\n",
            "",
        ),
        &allowlist,
    );
    r1_ledger_maps::run(t.root()).expect("an allowlisted associated fn must pass");

    // …and the same item WITHOUT the cfg is a production-view violation, so the
    // cfg column is actually load-bearing for associated items too.
    let t2 = maps_tree(
        "maps-m2",
        &maps_source(
            "    impl UpgradeWitness {\n        pub fn seed_for_test() {}\n    }\n",
            "",
        ),
        &allowlist,
    );
    let e = r1_ledger_maps::run(t2.root()).unwrap_err_or_panic("cfg mismatch on an impl item");
    assert!(e.contains("UpgradeWitness::seed_for_test"), "{e}");
}

/// F-N: an associated item kind the lint cannot classify (a macro invocation in
/// an impl body, which can expand to a `pub fn`) is a HARD failure, never a pass.
#[test]
fn r1f_maps_n_an_unclassifiable_associated_item_is_a_hard_failure() {
    let t = maps_tree(
        "maps-n",
        &maps_source(
            "    impl UpgradeWitness {\n        declare_methods!();\n    }\n",
            "",
        ),
        MAPS_ALLOWLIST,
    );
    let e = r1_ledger_maps::run(t.root()).unwrap_err_or_panic("macro in an impl body");
    assert!(e.contains("Fail closed"), "{e}");
}

// =============================================================================
// S4(b2) + S4(b3-belt) — the boundary lint, over a REAL dep-info census
// =============================================================================

/// A minimal, dependency-free crate literally named `stsh_token`, built for
/// wasm32 so cargo writes a real `.d`. Returns the fixture root.
///
/// `extra_root` is appended to `lib.rs`; `extra_files` are written verbatim.
fn boundary_tree(tag: &str, extra_root: &str, extra_files: &[(&str, &str)]) -> Tmp {
    boundary_tree_with(tag, extra_root, "", extra_files)
}

/// As `boundary_tree`, plus `extra_module`, appended INSIDE `mod ledger_maps`.
/// RED-1 round 2 made the witness constructors module-private, so a
/// second-occurrence fixture for one of them cannot be written at crate root
/// any more — it would not compile, and a fixture that cannot compile proves
/// nothing about a lint that runs on compiled crates.
fn boundary_tree_with(
    tag: &str,
    extra_root: &str,
    extra_module: &str,
    extra_files: &[(&str, &str)],
) -> Tmp {
    let t = Tmp::new(tag);
    t.write(
        "canisters/token/Cargo.toml",
        r#"[package]
name = "stsh_token"
version = "0.1.0"
edition = "2021"

[workspace]

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
"#,
    );
    t.write(
        "canisters/token/src/lib.rs",
        &format!(
            r#"
pub struct TokenStableState {{ pub x: u32 }}

mod ledger_maps {{
    struct UpgradeWitness(());
    struct GenesisWitness(());
    fn witness_for_post_upgrade() -> UpgradeWitness {{ UpgradeWitness(()) }}
    fn witness_for_init() -> GenesisWitness {{ GenesisWitness(()) }}
    pub(crate) fn restore_from_checkpoint(_s: &super::TokenStableState) {{
        let _w: UpgradeWitness = witness_for_post_upgrade();
    }}
    pub(crate) fn seed_at_genesis(_t: u128) {{
        let _w: GenesisWitness = witness_for_init();
    }}
{extra_module}
}}

pub fn post_upgrade() {{
    let state = TokenStableState {{ x: 0 }};
    ledger_maps::restore_from_checkpoint(&state);
}}

pub fn init() {{
    ledger_maps::seed_at_genesis(0);
}}
{extra_root}
"#
        ),
    );
    t.write(
        "canisters/token/identifier_synthesizing_macro_denylist.toml",
        "[[name]]\nvalue = \"paste\"\n\n[[name]]\nvalue = \"concat_idents\"\n\n[[name]]\nvalue = \"seq-macro\"\n",
    );
    for (rel, body) in extra_files {
        t.write(rel, body);
    }
    build_census(t.root());
    t
}

/// Build the fixture crate for wasm32 and copy its real dep-info into the place
/// the lint looks — the fixture crate is its own workspace, so its `target/`
/// lives beside its manifest.
fn build_census(root: &Path) {
    let manifest = root.join("canisters/token/Cargo.toml");
    let out = Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            manifest.to_str().unwrap(),
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .output()
        .expect("cargo build for the fixture crate");
    assert!(
        out.status.success(),
        "fixture crate must COMPILE (the census is rustc's own record, so there is \
         nothing to read if it does not):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let from = root.join("canisters/token/target/wasm32-unknown-unknown/release/deps");
    let to = root.join("target/wasm32-unknown-unknown/release/deps");
    std::fs::create_dir_all(&to).unwrap();
    let mut copied = 0;
    for e in std::fs::read_dir(&from).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("stsh_token") && name.ends_with(".d") {
            // The fixture crate is its own workspace ROOT (that is what keeps it
            // out of the estate's Cargo.lock), so cargo writes its relative
            // source paths against `canisters/token/`, while the lint resolves a
            // relative dep-info path against the REPO root — which is what cargo
            // does in the real tree, where the workspace root IS the repo root.
            // Re-anchor the fixture's paths so the fixture models the real
            // layout instead of the lint modelling the fixture's.
            let raw = std::fs::read_to_string(e.path()).unwrap();
            let fixed: String = raw
                .lines()
                .map(|line| {
                    line.split(' ')
                        .map(|tok| {
                            if !tok.is_empty()
                                && !tok.starts_with('/')
                                && !tok.starts_with('#')
                                && (tok.ends_with(".rs") || tok.ends_with(".rs:")
                                    || tok.ends_with(".txt") || tok.ends_with(".txt:"))
                            {
                                format!("canisters/token/{tok}")
                            } else {
                                tok.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(to.join(&name), fixed).unwrap();
            copied += 1;
        }
    }
    assert!(copied > 0, "cargo must have written a stsh_token dep-info file");
}

fn opts() -> boundary::Options {
    boundary::Options::default()
}

/// M7n (negative control): the specified shape is CLEAN, and in particular
/// `include_str!` is NOT flagged by the `include!` ban (exact name match, never
/// a substring).
#[test]
fn r1f_bound_a_the_specified_shape_is_clean() {
    let t = boundary_tree(
        "bound-a",
        "pub const LOGO: &str = include_str!(\"logo.txt\");\n",
        &[("canisters/token/src/logo.txt", "svg")],
    );
    boundary::run(t.root(), &opts()).expect("the specified shape must be clean");
}

/// M7f: the alias bypass a CALL-SITE count cannot see — both shapes the ruling
/// names, `use … as` and a bare function-item binding.
#[test]
fn r1f_bound_b_alias_bindings_raise_the_occurrence_count() {
    for (tag, extra) in [
        (
            "use-as",
            "use crate::ledger_maps::restore_from_checkpoint as restore;\n\
             pub fn elsewhere() { let _ = restore; }\n",
        ),
        (
            "fn-item",
            "pub fn elsewhere() { let f = ledger_maps::restore_from_checkpoint; let _ = f; }\n",
        ),
    ] {
        let t = boundary_tree("bound-b", extra, &[]);
        let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic(tag);
        assert!(
            e.contains("restore_from_checkpoint") && e.contains("found 3"),
            "[{tag}] {e}"
        );
    }
}

/// M7h: a second occurrence of a WITNESS CONSTRUCTOR alone is caught, even
/// though the outer restore call is untouched — the four identifiers are
/// tracked independently, not only in combination.
#[test]
fn r1f_bound_c_a_second_witness_constructor_occurrence_is_caught() {
    let t = boundary_tree_with(
        "bound-c",
        "",
        "    pub(crate) fn elsewhere() { let _w = witness_for_post_upgrade(); }\n",
        &[],
    );
    let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic("second witness call");
    assert!(e.contains("witness_for_post_upgrade") && e.contains("found 3"), "{e}");
    assert!(
        !e.contains("OCCURRENCE(`restore_from_checkpoint`)"),
        "restore_from_checkpoint's own count is unaffected: {e}"
    );
}

/// M7i / M7j / M7k: the TOKEN layer. Each of these carries the identifier as an
/// opaque token that `visit_path` never resolves — and the same tree with only
/// Layer 1 enabled reports exactly the count that LOOKS correct (2) and stays
/// GREEN, which is the whole demonstration that Layer 2 is not optional.
#[test]
fn r1f_bound_d_the_token_layer_catches_macro_hidden_identifiers() {
    let cases = [
        (
            "M7i macro invocation",
            "macro_rules! invoke_restore { ($r:path, $w:path, $s:expr) => { { let _n = stringify!($w); $r($s) } }; }\n\
             pub fn elsewhere() {\n    let state = TokenStableState { x: 0 };\n\
             \x20   invoke_restore!(ledger_maps::restore_from_checkpoint, ledger_maps::witness_for_post_upgrade, &state);\n}\n",
        ),
        (
            "M7j format! argument",
            "pub fn elsewhere() -> String { format!(\"{}\", stringify!(restore_from_checkpoint)) }\n",
        ),
        (
            "M7k macro_rules! body",
            "macro_rules! m { () => { restore_from_checkpoint() } }\n",
        ),
    ];
    for (tag, extra) in cases {
        let t = boundary_tree("bound-d", extra, &[]);

        // Layer 1 alone: exactly 2, GREEN — the count that looks correct.
        let mut ast_only = opts();
        ast_only.ast_layer_only = true;
        boundary::run(t.root(), &ast_only).unwrap_or_else(|e| {
            panic!("[{tag}] Layer 1 ALONE must stay green — that is the point: {e}")
        });

        // Both layers: RED, naming the macro node.
        let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic(tag);
        assert!(
            e.contains("restore_from_checkpoint") && e.contains("TOKEN/"),
            "[{tag}] {e}"
        );
    }
}

/// M7l / M7m: the `include!` ban, and — with the ban DISABLED — the census
/// catching the identical mutation on its own. Two independent nets over one
/// mutation, shown rather than asserted.
#[test]
fn r1f_bound_e_include_is_banned_and_the_census_catches_it_anyway() {
    let extra_file = (
        "canisters/token/src/extra_restore.rs",
        "pub(crate) fn call_restore_again(state: &TokenStableState) {\n\
         \x20   ledger_maps::restore_from_checkpoint(state);\n}\n",
    );
    let t = boundary_tree("bound-e", "include!(\"extra_restore.rs\");\n", &[extra_file]);

    let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic("include! ban");
    assert!(e.contains("BAN(include!)"), "{e}");

    let mut no_ban = opts();
    no_ban.disable_include_ban = true;
    let e = boundary::run(t.root(), &no_ban)
        .unwrap_err_or_panic("the census alone, with the ban disabled");
    assert!(
        e.contains("restore_from_checkpoint") && e.contains("found 3"),
        "the dep-info census contains the included file whether the ban runs or not: {e}"
    );
}

/// M7o / M7p / M7q: the `#[path]` ban for an OUT-of-crate target, the census
/// catching the identical mutation with that ban disabled, and the in-crate
/// negative control (a `#[path]` that stays inside the crate is NOT flagged).
#[test]
fn r1f_bound_f_out_of_crate_path_is_banned_and_the_census_catches_it_anyway() {
    let t = boundary_tree(
        "bound-f",
        "#[path = \"../../../review-fixtures/extra_restore.rs\"]\nmod extra_restore;\n",
        &[(
            "review-fixtures/extra_restore.rs",
            "pub(crate) fn call_restore_again(state: &crate::TokenStableState) {\n\
             \x20   crate::ledger_maps::restore_from_checkpoint(state);\n}\n",
        )],
    );

    let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic("#[path] ban");
    assert!(e.contains("BAN(#[path] outside the crate)"), "{e}");

    let mut no_ban = opts();
    no_ban.disable_path_ban = true;
    let e = boundary::run(t.root(), &no_ban)
        .unwrap_err_or_panic("the census alone, with the ban disabled");
    assert!(
        e.contains("extra_restore.rs") && e.contains("found 3"),
        "rustc read the out-of-crate file, so it is in the `.d` regardless: {e}"
    );

    // M7q: an IN-crate #[path] target is permitted and clean.
    let t = boundary_tree(
        "bound-f2",
        "#[path = \"sub/inner.rs\"]\nmod inner;\n",
        &[("canisters/token/src/sub/inner.rs", "pub fn ok() {}\n")],
    );
    boundary::run(t.root(), &opts())
        .expect("an in-crate #[path] target is not the violation — the ban is scoped");
}

/// M7r / AC-7l: a missing `.d` is a HARD FAILURE with a distinct exit code, and
/// its message names the glob and the exact build command. It must NOT report
/// "0 findings" and must NOT fall back to any weaker census.
#[test]
fn r1f_bound_g_a_missing_dep_info_is_a_hard_failure() {
    let t = Tmp::new("bound-g");
    t.write("canisters/token/src/lib.rs", "pub fn init() {}\npub fn post_upgrade() {}\n");
    let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic("missing .d");
    assert!(
        e.starts_with(boundary::NO_DEPINFO_SENTINEL),
        "the missing-.d failure must be distinguishable from a finding: {e}"
    );
    assert!(e.contains("cargo build --target wasm32-unknown-unknown"), "{e}");
    assert_eq!(boundary::EXIT_NO_DEPINFO, 3, "the exit code is part of the contract");
}

/// (b3-belt) M-invoke-rename / M-extern-rename / M-extern-plain / M-invoke, plus
/// AC-7o-bis: every binding form and the `macro_rules!` body.
///
/// These run WITHOUT `paste` being a dependency of the fixture crate, which is
/// why the fixture uses a `macro_rules!` body and path-only forms that still
/// compile — the belt's job is to fire on the NAME, whether or not the crate
/// resolves. The compile-failure floor is demonstrated separately, on the real
/// tree, in the packet.
#[test]
fn r1f_belt_every_binding_form_is_refused() {
    let cases = [
        ("M-invoke-rename (use … as)", "#[allow(unused_imports)] use paste as p;\n", "use"),
        ("M-use-plain", "#[allow(unused_imports)] use paste::paste;\n", "use"),
        ("M-use-glob", "#[allow(unused_imports)] use paste::*;\n", "use"),
        ("M-extern-rename", "extern crate paste as p;\n", "extern crate"),
        ("M-extern-plain", "extern crate paste;\n", "extern crate"),
        (
            "AC-7o-bis (macro_rules! body)",
            "macro_rules! gen { () => { ::paste::paste! { fn x() {} } } }\n",
            "macro_rules! body",
        ),
    ];
    for (tag, extra, kind) in cases {
        // The belt is a SOURCE scan: it does not need the tree to compile, and
        // must not, so the census is built from a clean tree and the mutated
        // source written afterwards.
        let t = boundary_tree("belt", "", &[]);
        let mut src = std::fs::read_to_string(t.root().join("canisters/token/src/lib.rs")).unwrap();
        src.push_str(extra);
        std::fs::write(t.root().join("canisters/token/src/lib.rs"), src).unwrap();

        let e = boundary::run(t.root(), &opts()).unwrap_err_or_panic(tag);
        assert!(
            e.contains("BELT(") && e.contains("paste") && e.contains(kind),
            "[{tag}] expected a BELT({kind}) finding naming `paste`, got: {e}"
        );

        // …and with the belt disabled, this specific finding is gone — proving
        // the belt, not some other layer, is what refused it.
        let mut no_belt = opts();
        no_belt.disable_belt = true;
        let r = boundary::run(t.root(), &no_belt);
        assert!(
            r.as_ref().err().map(|e| !e.contains("BELT(")).unwrap_or(true),
            "[{tag}] disabling the belt must remove the belt finding: {r:?}"
        );
    }
}

/// The belt's negative control: ordinary macros and ordinary `use` statements
/// are untouched. A ban that fires on everything proves nothing.
#[test]
fn r1f_belt_ordinary_macros_and_uses_are_not_flagged() {
    let t = boundary_tree(
        "belt-neg",
        "#[allow(unused_imports)] use std::collections::BTreeMap;\n\
         macro_rules! ordinary { () => { 1 + 1 } }\n\
         pub fn f() -> usize { let _ = ordinary!(); format!(\"{}\", 1).len() }\n",
        &[],
    );
    boundary::run(t.root(), &opts()).expect("ordinary macros and uses must be clean");
}

// =============================================================================
// AC-15 — the deviation register lint
// =============================================================================

const REGISTER_OK: &str = r#"# register

## dev001 — a thing

**Bound by:**
- `test_a_dev001` —
  `integration-tests/tests/x.rs`
"#;

fn register_tree(tag: &str, register: &str, test_src: &str) -> Tmp {
    let t = Tmp::new(tag);
    t.write("canisters/token/NOTE_A-3_icrc_deviation.md", register);
    t.write("integration-tests/tests/x.rs", test_src);
    t
}

#[test]
fn r1f_register_a_matching_register_passes() {
    let t = register_tree("reg-a", REGISTER_OK, "#[test]\nfn test_a_dev001() {}\n");
    r1_deviation_register::run(t.root()).expect("a matching register must pass");
}

/// M15d: renaming a bound test without updating the register.
#[test]
fn r1f_register_b_a_renamed_test_is_caught() {
    let t = register_tree("reg-b", REGISTER_OK, "#[test]\nfn test_a_renamed_dev001() {}\n");
    let e = r1_deviation_register::run(t.root()).unwrap_err_or_panic("renamed test");
    assert!(e.contains("test_a_dev001") && e.contains("does not exist"), "{e}");
}

/// M15e: deleting an entry whose tag is still cited in source.
#[test]
fn r1f_register_c_a_deleted_entry_is_caught() {
    let t = register_tree("reg-c", "# register\n", "#[test]\nfn test_a_dev001() {}\n");
    let e = r1_deviation_register::run(t.root()).unwrap_err_or_panic("deleted entry");
    assert!(e.contains("no `## dev"), "{e}");
}

/// An entry with NO binding test is a claim, not a register row.
#[test]
fn r1f_register_d_an_unbound_entry_is_caught() {
    let t = register_tree("reg-d", "# register\n\n## dev001 — a thing\n\nNo bindings.\n", "");
    let e = r1_deviation_register::run(t.root()).unwrap_err_or_panic("unbound entry");
    assert!(e.contains("names NO binding test"), "{e}");
}

// ── a tiny ergonomic helper, so every negative reads the same way ────────────

trait ExpectErr<T> {
    fn unwrap_err_or_panic(self, what: &str) -> String;
}

impl<T: std::fmt::Debug> ExpectErr<T> for Result<T, String> {
    fn unwrap_err_or_panic(self, what: &str) -> String {
        match self {
            Err(e) => e,
            Ok(v) => panic!("MUTATION LEFT THE LINT GREEN ({what}): {v:?}"),
        }
    }
}
