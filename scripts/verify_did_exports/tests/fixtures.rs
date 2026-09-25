// =============================================================================
// Fixture proofs — every failure mode this gate claims to catch, demonstrated
// =============================================================================
// A gate is only worth what its negative fixtures prove. Each case below is a
// minimal repo root under tests/fixtures/: canisters/<crate>/{Cargo.toml,src},
// a tracked .did where relevant, a census, and (for D2) an allowlist.
//
// Packet §4.1 enumerates the required cases; each `#[test]` names the one it
// discharges.

use std::path::{Path, PathBuf};

use verify_did_exports::*;

fn root(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(case)
}

fn d1(case: &str) -> Vec<Finding> {
    let r = root(case);
    let census = load_census(&r.join("census.toml")).expect("census parses");
    check_did_exports(&r, &census).expect("scan completes")
}

/// D1 where the scan itself must refuse to complete.
fn d1_err(case: &str) -> String {
    let r = root(case);
    let census = load_census(&r.join("census.toml")).expect("census parses");
    check_did_exports(&r, &census).expect_err("scan must refuse to complete")
}

fn d2(case: &str) -> Vec<Finding> {
    let r = root(case);
    let census = load_census(&r.join("census.toml")).expect("census parses");
    let allow = load_allowlist(&r.join("allowlist.toml")).expect("allowlist parses");
    check_amount_boundaries(&r, &census, &allow).expect("scan completes")
}

/// Some fixtures need an on-disk shape that must NOT live in the repo. A
/// dangling symlink is the case: it is legal Rust-tree topology, but it is
/// hostile to every tool that walks the estate — `verify_memory_ids` aborts its
/// whole scan set on the ENOENT, which took the gate down at the first lint.
/// The in-tree fixture therefore ships without it and the test stages a copy,
/// rather than another gate being blunted to accommodate this one's test data.
fn staged(case: &str, prepare: impl Fn(&Path)) -> PathBuf {
    let dst = std::env::temp_dir().join(format!("verify_did_exports_{case}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    copy_tree(&root(case), &dst);
    prepare(&dst);
    dst
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("staging dir");
    for entry in std::fs::read_dir(src).expect("fixture readable") {
        let entry = entry.expect("fixture entry");
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy fixture file");
        }
    }
}

fn d1_at(rootdir: &Path) -> Vec<Finding> {
    let census = load_census(&rootdir.join("census.toml")).expect("census parses");
    check_did_exports(rootdir, &census).expect("scan completes")
}

fn d1_err_at(rootdir: &Path) -> String {
    let census = load_census(&rootdir.join("census.toml")).expect("census parses");
    check_did_exports(rootdir, &census).expect_err("scan must refuse to complete")
}

fn codes(findings: &[Finding]) -> Vec<&'static str> {
    findings.iter().map(|f| f.code).collect()
}

// ── D1 negative fixtures ─────────────────────────────────────────────────────

#[test]
fn missing_did_fails() {
    assert_eq!(codes(&d1("did_missing")), ["DID-INVALID"]);
    assert!(d1("did_missing")[0].detail.contains("missing"));
}

#[test]
fn empty_did_fails() {
    assert_eq!(codes(&d1("did_empty")), ["DID-INVALID"]);
    assert!(d1("did_empty")[0].detail.contains("empty"));
}

/// The case the delimiter-balance check could not decide: balanced, service-
/// shaped, and syntactically invalid. Only a real parse rejects it.
#[test]
fn balanced_but_invalid_did_fails() {
    assert_eq!(codes(&d1("did_invalid")), ["DID-INVALID"]);
    assert!(d1("did_invalid")[0].detail.contains("not valid candid"));
}

/// F4: the pre-existing no-service-actor rejection, preserved in the new gate.
#[test]
fn did_without_service_actor_fails() {
    assert_eq!(codes(&d1("did_no_actor")), ["DID-INVALID"]);
    assert!(d1("did_no_actor")[0].detail.contains("declares no service"));
}

#[test]
fn did_method_absent_from_exports_fails() {
    let f = d1("did_method_not_exported");
    assert_eq!(codes(&f), ["DID-METHOD-NOT-EXPORTED"]);
    assert!(f[0].detail.contains("ghost"));
}

#[test]
fn exported_endpoint_absent_from_did_fails() {
    let f = d1("export_not_in_did");
    assert_eq!(codes(&f), ["EXPORT-NOT-IN-DID"]);
    assert!(f[0].detail.contains("undeclared_mutator"));
}

/// §2.4: the census is the universe. A crate that is simply not listed must not
/// be silently skipped just because nobody wrote it down.
#[test]
fn crate_absent_from_census_fails() {
    let f = d1("census_missing");
    assert_eq!(codes(&f), ["CENSUS-MISSING"]);
    assert!(f[0].subject.contains("stowaway"));
    assert!(f[0].detail.contains("endpoint"));
}

/// Unresolvable is a hard failure, never an omission — for attribute forms…
#[test]
fn unrecognised_attribute_form_refuses_to_complete() {
    let e = d1_err("unknown_attr");
    assert!(e.contains("unrecognised endpoint attribute path"), "{e}");
}

/// …and for cfg predicates.
#[test]
fn unresolvable_cfg_refuses_to_complete() {
    let e = d1_err("unknown_cfg");
    assert!(e.contains("unrecognised cfg predicate"), "{e}");
}

// ── D1 positive fixtures ─────────────────────────────────────────────────────

/// Every recognised attribute form — bare, both qualified spellings,
/// parameterised (guard/composite_query), the `name = "..."` rename resolving
/// to the EXPORTED name, a nested module, and cfg-gated test-only endpoints
/// that the production interface must not be asked to declare.
#[test]
fn every_attribute_form_is_recognised() {
    assert_eq!(d1("attribute_forms"), Vec::new());
}

/// F1: lifecycle entry points are not service methods and are never demanded
/// of a .did.
#[test]
fn lifecycle_entry_points_are_not_service_methods() {
    assert_eq!(d1("lifecycle_only"), Vec::new());
}

// ── D2 fixtures ──────────────────────────────────────────────────────────────

#[test]
fn unallowlisted_direct_amount_fails() {
    let f = d2("amount_direct");
    assert_eq!(codes(&f), ["AMOUNT-BOUNDARY"]);
    assert!(f[0].detail.contains("`amount: u128`"));
}

/// F3, the case that makes rule 3 non-obvious: the u128 appears in no endpoint
/// signature at all — only through an alias, a vec, a variant, and a struct.
#[test]
fn unallowlisted_wrapper_amount_fails() {
    let f = d2("amount_wrapper");
    assert_eq!(codes(&f), ["AMOUNT-BOUNDARY"]);
    assert!(f[0].detail.contains("Wrapper.Spend.0::Inner.value: u128"), "{}", f[0].detail);
}

/// F6: init is outside D1's method universe and inside D2's boundary universe.
#[test]
fn unallowlisted_init_wrapper_amount_fails() {
    let f = d2("amount_init");
    assert_eq!(codes(&f), ["AMOUNT-BOUNDARY"]);
    assert!(f[0].subject.contains("::init"));
    assert!(f[0].detail.contains("InitArgs.allocations"), "{}", f[0].detail);
}

/// A type the traversal cannot follow is reported, not skipped.
#[test]
fn unfollowable_undeclared_type_fails() {
    let f = d2("amount_opaque");
    assert_eq!(codes(&f), ["BOUNDARY-UNRESOLVED"]);
    assert!(f[0].detail.contains("ForeignThing"));
}

/// SSA-1's required scope proof, half 1: a foreign type declared opaque FOR THE
/// CRATE THAT USES IT stops the traversal there and yields no finding.
#[test]
fn crate_scoped_opaque_declaration_passes() {
    assert_eq!(d2("opaque_crate_scoped"), Vec::new());
}

/// Half 2, the half that makes it a lock rather than an observation: the SAME bare
/// name in a crate the row does not name is still unfollowable and still a finding.
/// Under the previous global bare-name set this case was silently suppressed.
#[test]
fn opaque_declaration_does_not_leak_to_another_crate() {
    let f = d2("opaque_wrong_crate");
    assert_eq!(codes(&f), ["BOUNDARY-UNRESOLVED"]);
    assert!(f[0].subject.contains("canisters/b"), "the surviving finding must be crate b's: {}", f[0].subject);
    assert!(f[0].detail.contains("ForeignBytes"), "{}", f[0].detail);
}

/// R2-1: the census reads `sig.output`. Before this lane a `-> u128` on a public
/// query reached `check_amount_boundaries` through no path at all, while the
/// identical type as a PARAMETER failed the gate — proven in both directions by
/// R2's causal probe and locked here.
#[test]
fn unallowlisted_return_amount_fails() {
    let f = d2("amount_return");
    assert_eq!(codes(&f), ["AMOUNT-BOUNDARY"]);
    assert!(f[0].detail.contains("`->: u128`"), "the finding must name the RETURN surface: {}", f[0].detail);
}

/// R2-1 (a), ruled by CTO_ADJUDICATION_MINI_QUEUE_2026-08-23 §2(a): a value in the
/// ERROR half of a return `Result` is out of universe — it is the disclosure of a
/// public governance parameter the caller failed against. This fixture is the
/// STATED RULE's proof; deleting the rule re-surfaces this case (and 396 in-tree
/// ones) and REDs the gate.
#[test]
fn return_side_error_variant_amount_is_out_of_universe() {
    assert_eq!(d2("amount_return_error_excluded"), Vec::new());
}

/// R2-1 (c): a deliberately-published reporting struct is enrolled by ONE class-row
/// naming it, its rationale and its reviewed field count — not by one row per field.
#[test]
fn class_rowed_report_struct_passes() {
    assert_eq!(d2("amount_struct_classrow"), Vec::new());
}

/// THE DRIFT LOCK, and the reason a class-row is not a blanket licence: the same row
/// against a struct that has grown a third amount field must RED.
#[test]
fn class_row_field_count_drift_fails() {
    let f = d2("amount_struct_drift");
    assert_eq!(codes(&f), ["AMOUNT-STRUCT-DRIFT"]);
    assert!(f[0].detail.contains("ADDED without review"), "{}", f[0].detail);
}

/// A class-row covering nothing is the same standing licence a stale amount row is.
#[test]
fn stale_class_row_fails() {
    let f = d2("amount_struct_classrow_stale");
    assert_eq!(codes(&f), ["AMOUNT-STRUCT-STALE"]);
}

#[test]
fn allowlisted_amount_passes() {
    assert_eq!(d2("amount_allowlisted"), Vec::new());
}

/// A row that covers nothing is a standing licence for a boundary that moved.
#[test]
fn stale_allowlist_row_fails() {
    let f = d2("amount_stale");
    assert_eq!(codes(&f), ["ALLOWLIST-STALE"]);
}

// ── SSA landed-diff regressions (F1, F2) ─────────────────────────────────────
//
// Both defects returned exit 0 while hiding exactly the thing the gate exists
// to census. `unknown_attr` and `amount_wrapper` could not catch them: the
// former tests an unknown path whose LAST segment is still `update`, and the
// latter uses unique type names. These three cases close that gap and must
// never be deleted without a replacement that fails on the same inputs.

/// F1: an endpoint macro imported under another name is still an export. A
/// last-segment test on the WRITTEN attribute never reaches the hard-fail arm,
/// so the export vanished from a census claiming completeness.
#[test]
fn aliased_endpoint_attribute_is_not_missed() {
    let f = d1("alias_endpoint");
    assert_eq!(codes(&f), ["EXPORT-NOT-IN-DID"]);
    assert!(f[0].detail.contains("hidden_export"), "{}", f[0].detail);
}

/// F1c: two sibling modules legally bind the same local name to different
/// things. Flattening the file's imports into one map let the second binding
/// overwrite the first and restored the original F1 exit-0 — with no illegal
/// code anywhere. Resolution is per module scope, so siblings cannot erase each
/// other's endpoint aliases.
#[test]
fn sibling_module_import_cannot_erase_an_endpoint_alias() {
    let f = d1("alias_sibling_scope");
    assert_eq!(codes(&f), ["EXPORT-NOT-IN-DID"]);
    assert!(f[0].detail.contains("hidden_export"), "{}", f[0].detail);
}

/// F1d: `mod foo;` is not a second crate root. The declaring scope's bindings
/// are inherited, so an endpoint alias declared in `lib.rs` still classifies an
/// attribute in `foo.rs`.
#[test]
fn external_module_inherits_the_declaring_scope() {
    let f = d1("external_mod_alias");
    assert_eq!(codes(&f), ["EXPORT-NOT-IN-DID"]);
    assert!(f[0].detail.contains("hidden_export"), "{}", f[0].detail);
}

/// F1d, the other half: the `#[cfg]` sits on the module DECLARATION, so a
/// test-only external module is outside the production interface and its
/// endpoints are never demanded of the `.did`.
#[test]
fn cfg_disabled_external_module_is_not_production() {
    assert_eq!(d1("external_mod_cfg"), Vec::new());
}

/// Walking the module graph must not become a way to miss files: one that no
/// `mod` declaration claims, and that no disabled module explains, hard-fails.
#[test]
fn unreachable_module_file_refuses_to_complete() {
    let e = d1_err("orphan_module_file");
    assert!(e.contains("not reachable from the crate root"), "{e}");
    assert!(e.contains("stray.rs"), "{e}");
}

/// F1e: a disabled module's skipped subtree must follow its DECLARED `#[path]`,
/// not the conventional filename it never uses.
#[test]
fn disabled_module_with_explicit_path_is_accepted() {
    assert_eq!(d1("disabled_path_module"), Vec::new());
}

/// F1f: a file-level `#![cfg(...)]` disables the file AND the modules it
/// declares; its children are not unreachable files.
#[test]
fn file_level_cfg_disables_the_whole_subtree() {
    assert_eq!(d1("file_cfg_subtree"), Vec::new());
}

/// F1g: `src/bin/*` is a Cargo target, not an orphan module of the library.
#[test]
fn cargo_bin_target_is_not_an_orphan_file() {
    assert_eq!(d1("bin_target_layout"), Vec::new());
}

/// F1h: one target claiming the same file twice is an invalid topology. Rust
/// rejects it; so must a gate that says it fails closed.
#[test]
fn duplicate_module_declaration_refuses_to_complete() {
    let e = d1_err("duplicate_mod_decl");
    assert!(e.contains("claimed more than once"), "{e}");
}

/// F1i: claims are compared by PHYSICAL identity. A symlink alias is the same
/// file, so declaring it a second time is the same invalid topology F1h rejects.
#[test]
fn symlink_alias_is_the_same_claim() {
    let e = d1_err("symlink_alias_claim");
    assert!(e.contains("claimed more than once"), "{e}");
}

/// F1j: a manifest-declared target must resolve. Dropping it silently removes a
/// whole module graph from a census that reports success.
#[test]
fn missing_declared_bin_target_refuses_to_complete() {
    let e = d1_err("missing_declared_bin");
    assert!(e.contains("[[bin]] `missing`"), "{e}");
    assert!(e.contains("must resolve"), "{e}");
}

#[test]
fn missing_declared_lib_target_refuses_to_complete() {
    let e = d1_err("missing_declared_lib");
    assert!(e.contains("[lib]"), "{e}");
    assert!(e.contains("must resolve"), "{e}");
}

/// F1k: a cfg-disabled `#[path]` may point at nothing — that is what disabled
/// means. The walk matches it lexically, exactly as its skip candidate was
/// recorded, instead of demanding an identity it cannot have.
#[test]
fn disabled_dangling_path_is_accepted() {
    let r = staged("disabled_dangling_path", |dst| {
        std::os::unix::fs::symlink("missing-target.rs", dst.join("canisters/c/src/dangling.rs"))
            .expect("stage dangling symlink");
    });
    assert_eq!(d1_at(&r), Vec::new());
    // …and the same dangling entry with nothing to explain it is still a place
    // an endpoint could hide.
    let r2 = staged("disabled_dangling_path", |dst| {
        std::os::unix::fs::symlink("missing-target.rs", dst.join("canisters/c/src/dangling.rs"))
            .expect("stage dangling symlink");
        std::fs::write(dst.join("canisters/c/src/lib.rs"), "#[update]\nfn real_export() {}\n")
            .expect("drop the disabled declaration");
    });
    assert!(d1_err_at(&r2).contains("not reachable"), "{}", d1_err_at(&r2));
}

/// F2: qualification IS type identity. `external::Shared` must not resolve to a
/// same-named local type — the raw `u128` is reachable and must be reported.
#[test]
fn qualified_type_is_not_shadowed_by_a_local_basename() {
    let f = d2("amount_qualified_shadow");
    assert_eq!(codes(&f), ["AMOUNT-BOUNDARY"]);
    assert!(f[0].detail.contains("Shared.amount: u128"), "{}", f[0].detail);
}

/// The inverse: a name defined in two OTHER crates and unqualified at the
/// boundary is ambiguous. Ambiguity hard-fails; it is never resolved by a
/// guess, in either direction.
#[test]
fn ambiguous_global_type_refuses_to_resolve() {
    let f = d2("amount_ambiguous_global");
    assert_eq!(codes(&f), ["BOUNDARY-UNRESOLVED"]);
    assert!(f[0].detail.contains("defined in 2 crates"), "{}", f[0].detail);
}
