//! Fixture tests for `verify_gate_lints` (brief §3 S0: "fixture tests for each
//! subcommand live in the crate; the real-tree run is the gate stage").
//!
//! The gate stages prove the lints run over the REAL tree. These prove the
//! MECHANISMS behave as specified on inputs the real tree does not contain —
//! most importantly the host-triple negative control (M2c-19), which cannot be
//! written as a tree mutation at all, because it is a claim about where the
//! target map COMES FROM, not about what any source file says.

use std::collections::BTreeSet;
use verify_gate_lints::cfg_eval::{parse_cfg_attr, Env, Pred};
use verify_gate_lints::features::{default_closure, FeatureTable};
use verify_gate_lints::target_cfg::TargetAtoms;

const WASM32_CFG: &str = r#"debug_assertions
panic="abort"
target_abi=""
target_arch="wasm32"
target_endian="little"
target_env=""
target_family="wasm"
target_feature="bulk-memory"
target_feature="multivalue"
target_has_atomic="32"
target_has_atomic="ptr"
target_os="unknown"
target_pointer_width="32"
target_vendor="unknown"
"#;

/// A typical Linux build host — the triple a lint that asked its OWN process
/// (or ran `rustc --print cfg` with no `--target`) would get.
const HOST_CFG: &str = r#"debug_assertions
panic="unwind"
target_arch="x86_64"
target_endian="little"
target_env="gnu"
target_family="unix"
target_os="linux"
target_pointer_width="64"
target_vendor="unknown"
unix
"#;

fn parse(src: &str, target: &TargetAtoms) -> Pred {
    let f: syn::File = syn::parse_str(src).expect("parse fixture");
    let item = f.items.first().expect("one item");
    let attrs = match item {
        syn::Item::Fn(f) => &f.attrs,
        _ => panic!("fixture must be a fn"),
    };
    for a in attrs {
        if let Some(p) = parse_cfg_attr(a, "fixture.rs", target).expect("no hard error") {
            return p;
        }
    }
    panic!("no cfg attribute in fixture")
}

fn envs(target: &TargetAtoms) -> (Env, Env) {
    let feats: BTreeSet<String> = BTreeSet::new();
    (
        Env::production(feats.clone(), target.clone()),
        Env::testing(feats, target.clone()),
    )
}

// ── target atoms ────────────────────────────────────────────────────────────

#[test]
fn rustc_cfg_parses_multi_valued_keys_as_sets() {
    let t = TargetAtoms::from_rustc_stdout(WASM32_CFG);
    assert!(t.matches("target_arch", "wasm32"));
    assert!(t.matches("target_env", ""), "empty string is a REAL matchable value, not 'unset'");
    // The two multi-valued keys the brief's hand-written "exactly seven" table
    // omitted, and would therefore have hard-errored on.
    assert!(t.matches("target_feature", "bulk-memory"));
    assert!(t.matches("target_feature", "multivalue"));
    assert!(!t.matches("target_feature", "simd128"), "a value rustc does not print is FALSE");
    assert!(t.matches("target_has_atomic", "ptr"));
    assert!(t.knows("target_abi"), "target_abi is printed and is not in the brief's seven");
    // Non-target atoms rustc also prints are NOT in this evaluator's vocabulary.
    assert!(!t.knows("debug_assertions"));
    assert!(!t.knows("panic"));
}

/// M2c-15 / M2c-16 / M2c-17 at the evaluator level.
#[test]
fn target_leaves_evaluate_against_the_wasm32_map() {
    let t = TargetAtoms::from_rustc_stdout(WASM32_CFG);
    let (prod, test) = envs(&t);
    let yes = parse(r#"#[cfg(target_arch = "wasm32")] fn f() {}"#, &t);
    assert!(yes.eval(&prod) && yes.eval(&test), "M2c-15: present in BOTH views");
    let neg = parse(r#"#[cfg(not(target_arch = "wasm32"))] fn f() {}"#, &t);
    assert!(!neg.eval(&prod), "M2c-16: negation IS applied to a target_* leaf");
    let wrong = parse(r#"#[cfg(target_os = "linux")] fn f() {}"#, &t);
    assert!(
        !wrong.eval(&prod),
        "M2c-17: target_os is \"unknown\" here — a target_* leaf is not vacuously true"
    );
}

/// **M2c-19 — the host-triple negative control.**
///
/// This is the mutation the real tree CANNOT express: it is not about what any
/// source file says, it is about where the target map comes from. Evaluated
/// against the HOST's atoms, `#[cfg(target_arch = "wasm32")]` is false and a
/// real production endpoint silently vanishes from the census — and every other
/// mutation in this lane still passes. The shipped code obtains its map by
/// running `rustc --print cfg --target wasm32-unknown-unknown`, with the triple
/// a literal constant; it never reads `std::env::consts`, never evaluates
/// `cfg!(target_arch = …)` in its own process, and never invokes rustc without
/// `--target`.
#[test]
fn host_triple_would_hide_a_production_endpoint() {
    let wasm = TargetAtoms::from_rustc_stdout(WASM32_CFG);
    let host = TargetAtoms::from_rustc_stdout(HOST_CFG);
    let pred = parse(r#"#[cfg(target_arch = "wasm32")] fn wasm_only_endpoint() {}"#, &wasm);
    let (wasm_prod, _) = envs(&wasm);
    let (host_prod, _) = envs(&host);
    assert!(pred.eval(&wasm_prod), "under the production map the endpoint is present");
    assert!(
        !pred.eval(&host_prod),
        "under the HOST map the same endpoint disappears — this is the failure the \
         production triple being a literal constant exists to make impossible"
    );
    // And the shipped constant is the production triple, not the host's.
    assert_eq!(verify_gate_lints::target_cfg::PRODUCTION_TARGET, "wasm32-unknown-unknown");
}

/// An empty target map is not a silent `false` either — the evaluator is only
/// ever handed a map that came from a successful rustc invocation, and
/// `TargetAtoms::capture` refuses one with no `target_arch`.
#[test]
fn empty_target_map_is_refused_at_capture() {
    let empty = TargetAtoms::from_rustc_stdout("");
    assert!(!empty.knows("target_arch"));
    assert!(
        empty.map.is_empty(),
        "an empty rustc output yields an empty map, which capture() rejects rather than \
         evaluating every target_* leaf as vacuously false"
    );
}

// ── unknown atoms are hard errors, never silent defaults ────────────────────

#[test]
fn unknown_atoms_are_hard_errors() {
    let t = TargetAtoms::from_rustc_stdout(WASM32_CFG);
    for src in [
        r#"#[cfg(not(some_unrecognised_marker))] fn f() {}"#,   // M2c-8
        r#"#[cfg(target_frobnicate = "x")] fn f() {}"#,          // M2c-18
        r#"#[cfg(target_has_atomic_load_store = "8")] fn f() {}"#,
        r#"#[cfg(debug_assertions)] fn f() {}"#,
        r#"#[cfg(unix)] fn f() {}"#,
    ] {
        let f: syn::File = syn::parse_str(src).unwrap();
        let syn::Item::Fn(func) = f.items.first().unwrap() else { panic!() };
        let err = parse_cfg_attr(&func.attrs[0], "fixture.rs", &t)
            .expect_err("an atom outside the vocabulary must be a HARD ERROR");
        assert!(!err.fragment.is_empty(), "the error names the offending fragment verbatim");
        assert_eq!(err.file, "fixture.rs");
    }
}

// ── Boolean composition ─────────────────────────────────────────────────────

#[test]
fn boolean_composition_is_evaluated_not_atom_matched() {
    let t = TargetAtoms::from_rustc_stdout(WASM32_CFG);
    let (prod, test) = envs(&t);
    // M2c-5: an atom-presence search sees `feature = "testing"` and excludes.
    let p = parse(r#"#[cfg(not(feature = "testing"))] fn f() {}"#, &t);
    assert!(p.eval(&prod) && !p.eval(&test));
    // M2c-6 / M2c-7.
    let all = parse(r#"#[cfg(all(feature = "testing", not(test)))] fn f() {}"#, &t);
    assert!(!all.eval(&prod) && all.eval(&test));
    let any = parse(r#"#[cfg(any(feature = "testing", feature = "unused"))] fn f() {}"#, &t);
    assert!(!any.eval(&prod) && any.eval(&test));
    // `test` is false in BOTH views: neither view names a `cargo test` build.
    let t_only = parse(r#"#[cfg(test)] fn f() {}"#, &t);
    assert!(!t_only.eval(&prod) && !t_only.eval(&test));
}

// ── default-feature closure ─────────────────────────────────────────────────

fn table(rows: &[(&str, &[&str])]) -> FeatureTable {
    let mut t = FeatureTable::default();
    for (k, v) in rows {
        if *k == "default" {
            t.has_default_key = true;
        }
        t.declared.insert(k.to_string(), v.iter().map(|s| s.to_string()).collect());
    }
    t
}

#[test]
fn default_closure_is_transitive_cycle_safe_and_dep_aware() {
    // M2c-12: two hops. `b` is reachable ONLY by opening `a`'s own array.
    let c = default_closure(&table(&[("default", &["a"]), ("a", &["b"]), ("b", &[]), ("c", &[])]));
    assert!(c.contains("a") && c.contains("b"), "M2c-12: genuine second hop");
    assert!(!c.contains("c"), "M2c-12: declared-but-unreachable stays OFF");

    // M2c-14: a genuine mutual cycle terminates and keeps BOTH.
    let c = default_closure(&table(&[("default", &["a"]), ("a", &["b"]), ("b", &["a"])]));
    assert_eq!(c.len(), 2, "M2c-14: a cycle is ordinary Cargo shape, not a defect");

    // M2c-13: `dep:` is SILENTLY excluded — never an error, never a feature name.
    let c = default_closure(&table(&[("default", &["dep:foo", "real"]), ("real", &[])]));
    assert!(!c.contains("dep:foo") && c.contains("real"));
    let c = default_closure(&table(&[("default", &["foo?/bar", "real"]), ("real", &[])]));
    assert!(!c.iter().any(|f| f.contains('/')) && c.contains("real"));

    // No `default` key ⇒ empty. DERIVED, not a constant standing in for it.
    assert!(default_closure(&table(&[("testing", &[])])).is_empty());
}

// ── the .did service-block parser ───────────────────────────────────────────

#[test]
fn did_parser_skips_the_constructor_and_splits_on_top_level_semicolons() {
    let did = r#"
type Args = record { a : nat64 };
service : (record {
    controller : principal;
    initial    : blob;
}) -> {
    // a method spanning several lines, with a nested record in its argument
    shield_deposit : (record {
        amount : nat;
        memo   : opt blob;
    }) -> (variant { Ok : nat; Err : text });
    get_status     : ()      -> (nat64) query;
    composite      : ()      -> (nat64) composite_query;
    withdraw       : (nat64) -> (variant { Ok; Err : text });
}
"#;
    let all = verify_gate_lints::did::service_methods(did);
    let names: Vec<&str> = all.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["shield_deposit", "get_status", "composite", "withdraw"],
               "the CONSTRUCTOR's record fields (controller, initial) are NOT methods");
    let ups_owned = verify_gate_lints::did::update_methods(did);
    let ups: Vec<&str> = ups_owned.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(ups, ["shield_deposit", "withdraw"],
               "query and composite_query are excluded by mode suffix");
}

// ── the binding registry's banned-field schema check ────────────────────────

#[test]
fn binding_schema_refuses_office_and_evidence_file_fields() {
    for line in [
        "proof_evidence_file = \"tests/binding_evidence/B-1.md\"",
        "proof_sha256 = \"deadbeef\"",
        "office_path = \"reviews/PACKET.md\"",
        "note = \"/mnt/c/Users/example/Documents/office\"",
    ] {
        let v = verify_gate_lints::bindings::schema_check(line);
        assert!(!v.is_empty(), "must be REFUSED, not ignored: {line}");
    }
    // A comment quoting a banned name is not a field.
    assert!(verify_gate_lints::bindings::schema_check("# proof_sha256 is banned").is_empty());
}

// ── S3 bindings: a bound test must actually BE a harness-executed test ───────
// SSA landed-diff round 1, RED-1: `bindings` located the named function by name
// alone, so deleting `#[test]` from a bound test left the registry row
// certified GREEN while the gate no longer ran it.

#[test]
fn binding_eligibility_requires_a_test_attribute() {
    let src = r#"
        #[test]        fn plain() {}
        #[tokio::test] fn qualified() {}
        #[test]
        #[ignore = "why"]
        fn ignored_but_still_a_test() {}
        fn bare_helper() {}
        #[allow(dead_code)] fn attributed_helper() {}
        #[test_case(1)] fn parameterised() {}
        mod inner { #[test] fn nested() {} fn nested_helper() {} }
    "#;
    let file = syn::parse_file(src).expect("parses");
    let mut seen: Vec<(String, bool)> = Vec::new();
    fn walk(items: &[syn::Item], seen: &mut Vec<(String, bool)>) {
        for it in items {
            match it {
                syn::Item::Fn(f) => seen.push((
                    f.sig.ident.to_string(),
                    !verify_gate_lints::test_attrs(f).is_empty(),
                )),
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        walk(inner, seen);
                    }
                }
                _ => {}
            }
        }
    }
    walk(&file.items, &mut seen);
    let got: std::collections::BTreeMap<String, bool> = seen.into_iter().collect();

    // Accepted forms — the tree uses `#[test]` exclusively today; the qualified
    // async form is accepted so the lint does not go blind the day one appears.
    assert_eq!(got["plain"], true);
    assert_eq!(got["qualified"], true);
    // `#[ignore]` is a SEPARATE, already-enforced violation — it must not be
    // conflated with "is not a test", or the two messages would swap.
    assert_eq!(got["ignored_but_still_a_test"], true);

    // Refused — the RED-1 shape, plus near-misses that must NOT be accepted.
    assert_eq!(got["bare_helper"], false);
    assert_eq!(got["attributed_helper"], false);
    assert_eq!(
        got["parameterised"], false,
        "a parameterised-case macro does not name one harness test; the registry names one"
    );
    assert_eq!(got["nested"], true);
    assert_eq!(got["nested_helper"], false);
}

// ── S4 no-skips: shape detection is STRUCTURAL, not a helper-name list ───────
// SSA landed-diff round 1, RED-3: the shape-3 rule tested the rendered
// condition against a fixed list of helper NAMES, so an ordinary statically
// dispatched presence helper called anything else bypassed the whole net.

fn no_skips_pats() -> verify_gate_lints::data::NoSkipsPatterns {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("gate_lints")
        .join("no_skips_patterns.toml");
    verify_gate_lints::data::load(&root).expect("committed no-skips patterns load")
}

/// Scan one synthetic file whose helpers are indexed from the SAME text, so
/// the fixture exercises the real resolver rather than a stub of it.
fn scan_synthetic(src: &str) -> Vec<verify_gate_lints::no_skips::Finding> {
    let pats = no_skips_pats();
    let rel = "integration-tests/tests/synthetic_fixture.rs";
    let index = verify_gate_lints::no_skips::FnIndex::from_source(rel, src);
    verify_gate_lints::no_skips::scan_file(rel, src, &pats, &index).expect("parses")
}

#[test]
fn presence_helper_is_resolved_by_body_not_by_name() {
    // The exact RED-3 bypass: a helper whose name matches NONE of the
    // presence-predicate vocabulary, whose body does the path-existence call.
    let caught = scan_synthetic(
        r#"
        fn check_ssa() -> bool { std::path::Path::new("absent").exists() }
        #[test]
        fn ssa_helper_skip() { if !check_ssa() { return; } assert!(false); }
        "#,
    );
    assert_eq!(caught.len(), 1, "renamed presence helper must still be found: {caught:?}");
    assert_eq!(caught[0].shape, 3);
    assert_eq!(caught[0].owner_fn, "ssa_helper_skip");

    // A helper that does NOT test presence must not be dragged in — the rule
    // has to distinguish, or it is a rule that fires on every `if`.
    let clean = scan_synthetic(
        r#"
        fn some_number() -> bool { 2 + 2 == 4 }
        #[test]
        fn ordinary_guard() { if !some_number() { return; } assert!(false); }
        "#,
    );
    assert!(clean.is_empty(), "non-presence helper must not be a finding: {clean:?}");
}

#[test]
fn helper_resolution_walks_the_call_graph_to_depth_three() {
    let src = |entry: &str| {
        format!(
            r#"
            fn lvl3() -> bool {{ std::path::Path::new("absent").exists() }}
            fn lvl2() -> bool {{ lvl3() }}
            fn lvl1() -> bool {{ lvl2() }}
            fn lvl0() -> bool {{ lvl1() }}
            #[test]
            fn t() {{ if !{entry}() {{ return; }} assert!(false); }}
            "#
        )
    };
    // Depth 1, 2 and 3 are inside the declared bound.
    for entry in ["lvl3", "lvl2", "lvl1"] {
        let f = scan_synthetic(&src(entry));
        assert_eq!(f.len(), 1, "`{entry}` is within depth 3 and must be caught: {f:?}");
        assert_eq!(f[0].shape, 3);
    }
    // Depth 4 is OUTSIDE it. This is a DISCLOSED bound, asserted here so the
    // limit is a decision on record rather than an accident nobody measured.
    let f = scan_synthetic(&src("lvl0"));
    assert!(f.is_empty(), "depth 4 is beyond MAX_HELPER_DEPTH; bound must be honest: {f:?}");
    assert_eq!(verify_gate_lints::no_skips::MAX_HELPER_DEPTH, 3);
}

/// RED-8. A name reached FIRST by a longer path must not suppress its own
/// exploration when it is reached again by a SHORTER one.
///
/// SSA's construction verbatim: the condition's own operand `ssa_b` reaches the
/// presence call in exactly 3 levels, but the resolver sorted `ssa_a` first,
/// walked b/c from there near the depth limit, marked them visited, and then
/// found b already-seen at the top level. Adding a candidate path removed
/// exploration from another — the opposite of a conservative union.
#[test]
fn a_longer_path_must_not_suppress_a_shorter_one() {
    let helpers = r#"
        fn ssa_a() -> bool { ssa_b() }
        fn ssa_b() -> bool { ssa_c() }
        fn ssa_c() -> bool { ssa_d() }
        fn ssa_d() -> bool { std::path::Path::new("absent").exists() }
    "#;
    let with = |cond: &str| {
        scan_synthetic(&format!(
            "{helpers}\n#[test]\nfn t() {{ if {cond} {{ return; }} assert!(false); }}\n"
        ))
    };
    // The shorter path ALONE is a finding — SSA's negative control.
    let f = with("!ssa_b()");
    assert_eq!(f.len(), 1, "the 3-level path alone must be caught: {f:?}");
    assert_eq!(f[0].shape, 3);

    // The exact mutation. `ssa_a` sorts first and is walked first; `ssa_b`
    // must still be explored with its own, larger, remaining budget.
    let f = with("!ssa_b() || !ssa_a()");
    assert_eq!(f.len(), 1, "adding a longer candidate path must not silence it: {f:?}");

    // Order-independent, and the same in a `&&` chain and under `!`.
    assert_eq!(with("!ssa_a() || !ssa_b()").len(), 1);
    assert_eq!(with("!ssa_a() && !ssa_b()").len(), 1);
    assert_eq!(with("!(ssa_b())").len(), 1);

    // And it still discriminates: no candidate reaches a presence call within
    // the bound, so nothing fires.
    let f = scan_synthetic(&format!(
        "{}\n#[test]\nfn t() {{ if !x_a() || !x_b() {{ return; }} assert!(false); }}\n",
        r#"
        fn x_a() -> bool { x_b() }
        fn x_b() -> bool { 2 + 2 == 4 }
        "#
    ));
    assert!(f.is_empty(), "no candidate is a presence helper: {f:?}");
}

/// RED-8, second half of the ruling: the traversal follows every ordinary CALL
/// FORM within the bound, and a guarded `continue` is a skip exit like
/// `return`. One assertion per form, so a regression names the form it broke.
#[test]
fn every_call_form_and_exit_form_within_the_bound_is_followed() {
    let helpers = r#"
        struct H;
        impl H { fn m(&self) -> bool { lvl1() } }
        fn lvl2() -> bool { std::path::Path::new("absent").exists() }
        fn lvl1() -> bool { lvl2() }
        fn opt() -> Option<bool> { Some(lvl1()) }
    "#;
    let body = |body: &str| {
        scan_synthetic(&format!("{helpers}\n#[test]\nfn t() {{ {body} }}\n"))
    };
    let cases: &[(&str, &str)] = &[
        ("path call", "if !lvl1() { return; } assert!(false);"),
        ("method call", "let h = H; if !h.m() { return; } assert!(false);"),
        ("negation", "if !(!lvl1()) { return; } assert!(false);"),
        ("&& chain", "if !lvl1() && true { return; } assert!(false);"),
        ("|| chain", "if !lvl1() || false { return; } assert!(false);"),
        (".then()", "if (!lvl1()).then(|| 1).is_some() { return; } assert!(false);"),
        ("inline closure", "if (|| !lvl1())() { return; } assert!(false);"),
        ("if let scrutinee", "if let Some(false) = opt() { return; } assert!(false);"),
        // Shape 4's absence patterns (`None` / `Err(..)`), over a scrutinee
        // whose presence call is 2 helper levels down.
        ("match scrutinee", "match opt() { None => return, _ => {} } assert!(false);"),
        (
            "guarded continue",
            "for _i in 0..2 { if !lvl1() { continue; } assert!(false); }",
        ),
    ];
    for (name, src) in cases {
        let f = body(src);
        assert!(!f.is_empty(), "call/exit form `{name}` was not followed: {src}");
    }

    // The `?` exit form is DISCLOSED-OPEN, not silently claimed: a bare
    // `expr?;` is how any fallible helper is called, and treating it as a skip
    // exit fires on ordinary error propagation. Recognising it needs an
    // Option/Result distinction this AST-only lint does not have.
    let f = body("lvl1(); assert!(false);");
    assert!(f.is_empty(), "a plain call with no guarded exit is not a skip: {f:?}");
}

#[test]
fn mutually_recursive_helpers_terminate() {
    // A cycle in the call graph must not hang the resolver, and must not
    // manufacture a presence verdict out of nothing.
    let f = scan_synthetic(
        r#"
        fn a() -> bool { b() }
        fn b() -> bool { a() }
        #[test]
        fn t() { if !a() { return; } assert!(false); }
        "#,
    );
    assert!(f.is_empty(), "cyclic non-presence helpers are not findings: {f:?}");
}

// ── S4 no-skips: an exemption covers a COUNTED SET of sites, not a function ──
// SSA landed-diff round 1, RED-2: the baseline key was (file, owner_fn, shape)
// with no multiplicity, so a brand-new skip inserted into an already-exempted
// function inherited that function's exemption and the lint stayed green.

fn baseline_row(
    file: &str,
    owner_fn: &str,
    shape: u8,
    count: usize,
) -> verify_gate_lints::data::NoSkipsBaselineSite {
    toml::from_str(&format!(
        "file = \"{file}\"\nowner_fn = \"{owner_fn}\"\nshape = {shape}\ncount = {count}\n\
         reason = \"pre-existing, owned elsewhere\"\nowner = \"some lane\"\n"
    ))
    .expect("row parses")
}

fn baseline(
    rows: Vec<verify_gate_lints::data::NoSkipsBaselineSite>,
) -> verify_gate_lints::data::NoSkipsBaseline {
    verify_gate_lints::data::NoSkipsBaseline { site: rows }
}

#[test]
fn a_new_skip_in_an_exempted_function_is_a_violation() {
    let key = ("f.rs".to_string(), "already_exempted".to_string(), 5u8);
    let bl = baseline(vec![baseline_row("f.rs", "already_exempted", 5, 1)]);

    // Exactly the recorded site: suppressed, no finding. (Regression guard —
    // the fix must not turn the existing baseline into 34 fresh violations.)
    let mut found = std::collections::BTreeMap::new();
    found.insert(key.clone(), vec!["f.rs:100: shape 5 — original".to_string()]);
    let (v, sup) = verify_gate_lints::no_skips::apply_baseline(&found, &bl);
    assert!(v.is_empty(), "the recorded site must stay suppressed: {v:?}");
    assert_eq!(sup, 1);

    // One MORE site of the same shape in the same function — the RED-2 shape.
    let mut found = std::collections::BTreeMap::new();
    found.insert(
        key.clone(),
        vec![
            "f.rs:100: shape 5 — original".to_string(),
            "f.rs:98: shape 5 — SSA newly introduced unconditional bypass".to_string(),
        ],
    );
    let (v, sup) = verify_gate_lints::no_skips::apply_baseline(&found, &bl);
    assert_eq!(v.len(), 1, "a new site in an exempted function must be a violation: {v:?}");
    assert!(v[0].contains("now has 2 matching site(s)"));
    assert!(v[0].contains("exempts only 1"));
    // Both sites are printed — the baseline cannot know which one is new.
    assert!(v[0].contains("f.rs:98"));
    assert!(v[0].contains("f.rs:100"));
    assert_eq!(sup, 1, "the exemption still covers only the counted site");
}

#[test]
fn an_exemption_never_keys_on_the_file_alone() {
    // A same-shape finding in a DIFFERENT function of an exempted FILE, and a
    // different shape in the exempted function, are both violations. If either
    // were suppressed, the key would have collapsed toward the file.
    let bl = baseline(vec![baseline_row("f.rs", "exempted_fn", 5, 1)]);
    let mut found = std::collections::BTreeMap::new();
    found.insert(
        ("f.rs".into(), "exempted_fn".into(), 5u8),
        vec!["f.rs:100: shape 5 — original".to_string()],
    );
    found.insert(
        ("f.rs".into(), "some_other_fn".into(), 5u8),
        vec!["f.rs:200: shape 5 — different fn".to_string()],
    );
    found.insert(
        ("f.rs".into(), "exempted_fn".into(), 3u8),
        vec!["f.rs:101: shape 3 — different shape".to_string()],
    );
    let (v, sup) = verify_gate_lints::no_skips::apply_baseline(&found, &bl);
    assert_eq!(v.len(), 2, "only the exact (file, fn, shape, count) row is exempt: {v:?}");
    assert!(v.iter().any(|x| x.contains("f.rs:200")));
    assert!(v.iter().any(|x| x.contains("f.rs:101")));
    assert_eq!(sup, 1);
}

#[test]
fn an_over_counting_or_stale_row_is_itself_a_finding() {
    // Over-count: standing amnesty for a site that no longer exists.
    let bl = baseline(vec![baseline_row("f.rs", "fn_a", 5, 2)]);
    let mut found = std::collections::BTreeMap::new();
    found.insert(("f.rs".into(), "fn_a".into(), 5u8), vec!["f.rs:1: shape 5 — x".to_string()]);
    let (v, _) = verify_gate_lints::no_skips::apply_baseline(&found, &bl);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("RE-COUNT"));

    // Fully stale row.
    let (v, sup) =
        verify_gate_lints::no_skips::apply_baseline(&Default::default(), &bl);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("DELETE the stale baseline row"));
    assert_eq!(sup, 0);

    // A row that exempts nothing.
    let bl0 = baseline(vec![baseline_row("f.rs", "fn_a", 5, 0)]);
    let mut found = std::collections::BTreeMap::new();
    found.insert(("f.rs".into(), "fn_a".into(), 5u8), vec!["f.rs:1: shape 5 — x".to_string()]);
    let (v, _) = verify_gate_lints::no_skips::apply_baseline(&found, &bl0);
    assert!(v.iter().any(|x| x.contains("`count = 0`")), "{v:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA landed-diff ROUND 2 — RED-4 / RED-5 / RED-6.
//
// Each of these three exercises the REAL stage entry point against real source
// text, because round 2's finding was precisely that the round-1 fixtures
// stopped short of the entry point: the eligibility fixture called `test_attrs`
// instead of `bindings::run`, and the multiplicity fixture built the grouped
// map by hand instead of letting the scanner produce it.
// ─────────────────────────────────────────────────────────────────────────────

/// A throwaway workspace root under the system temp dir, unique per test.
struct TmpRoot(std::path::PathBuf);

impl TmpRoot {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("vgl-fixture-{tag}-{n}-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("mkdir");
        TmpRoot(p)
    }
    fn write(&self, rel: &str, body: &str) {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).expect("mkdir -p");
        std::fs::write(&p, body).expect("write");
    }
}

impl Drop for TmpRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn wasm32_atoms() -> TargetAtoms {
    TargetAtoms::from_rustc_stdout(
        "target_arch=\"wasm32\"\ntarget_os=\"unknown\"\ntarget_pointer_width=\"32\"\n\
         target_endian=\"little\"\ntarget_family=\"wasm\"\n",
    )
}

/// The atoms `cargo test` really compiles against — captured LIVE from the
/// pinned toolchain with NO `--target`, exactly as `main`'s bindings stage
/// does (RED-7). Not a hand-written table, and not this process's `cfg!`.
fn host_atoms() -> TargetAtoms {
    TargetAtoms::capture_host(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("rustc --print cfg (host)")
}

/// Run the REAL `bindings::run` over a synthetic root whose one bound test
/// carries `cfgs` above it and sits inside `mod_cfg`-gated module(s), with the
/// TEST-view atom set the stage uses.
fn bindings_over(cfgs: &str, mod_cfg: &str) -> Vec<String> {
    bindings_over_with(&host_atoms(), cfgs, mod_cfg)
}

fn bindings_over_with(atoms: &TargetAtoms, cfgs: &str, mod_cfg: &str) -> Vec<String> {
    let t = TmpRoot::new("bind");
    t.write("run_gate.sh", "#!/usr/bin/env bash\ncargo test --workspace --locked --no-fail-fast\n");
    t.write(
        "scripts/gate_lints/BOUND_TEST_SUITES.toml",
        "[[suite]]\ncrate_name = \"demo\"\n\
         gate_invocation = \"cargo test --workspace --locked --no-fail-fast\"\n",
    );
    let reg = "schema_version = 1\nposture = \"prelaunch\"\nrequired_bindings = [\"B-1\"]\n\
        [[binding]]\nid = \"B-1\"\nproperty = \"approve_inner\"\nstatus = \"closed\"\n\
        bound = \"bound_demo\"\ntest_crate = \"demo\"\ntest_file = \"demo/src/lib.rs\"\n";
    t.write("tests/BINDING_REGISTRY.toml", reg);
    t.write("demo/Cargo.toml", "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\
        [features]\ndefault = []\ntesting = []\n");
    t.write(
        "demo/src/lib.rs",
        &format!(
            "fn approve_inner(x: u8) -> Result<(), ()> {{ if x == 0 {{ Ok(()) }} else {{ Err(()) }} }}\n\
             {mod_cfg}mod tests {{\n    use super::*;\n    // BINDING: B-1\n    #[test]\n    {cfgs}fn bound_demo() {{\n\
             \x20       assert!(approve_inner(0).is_ok());\n        assert!(approve_inner(1).is_err());\n    }}\n}}\n"
        ),
    );
    let raw = std::fs::read_to_string(t.0.join("tests/BINDING_REGISTRY.toml")).unwrap();
    let reg: verify_gate_lints::data::BindingRegistry = toml::from_str(&raw).expect("registry");
    let suites: verify_gate_lints::data::BoundTestSuites =
        verify_gate_lints::data::load(&t.0.join("scripts/gate_lints/BOUND_TEST_SUITES.toml"))
            .expect("suites");
    let gate = std::fs::read_to_string(t.0.join("run_gate.sh")).unwrap();
    let out = verify_gate_lints::bindings::run(&t.0, &reg, &raw, &suites, &gate, atoms);
    assert!(out.refusals.is_empty(), "unexpected refusal: {:?}", out.refusals);
    out.violations
}

/// RED-4. A bound test the gate's own invocation does not COMPILE is not
/// evidence, whether the exclusion sits on the function or on an enclosing
/// module. Exercises `bindings::run`, not a helper of it.
#[test]
fn a_cfg_excluded_bound_test_is_not_evidence() {
    // Baseline: an ordinary `#[cfg(test)] mod tests` bound test certifies.
    assert!(
        bindings_over("", "#[cfg(test)]\n").is_empty(),
        "an ordinarily gated bound test must still certify"
    );

    // The exact SSA round-2 mutation: keep `#[test]`, add a feature gate the
    // gate invocation does not turn on.
    let v = bindings_over("#[cfg(feature = \"testing\")]\n", "#[cfg(test)]\n");
    assert!(
        v.iter().any(|x| x.contains("CFG-EXCLUDED")),
        "a `testing`-gated bound test must be a violation: {v:?}"
    );

    // The same exclusion one level up, on the ENCLOSING module — the reason
    // the evaluation is over the whole scope chain and not the item alone.
    let v = bindings_over("", "#[cfg(all(test, feature = \"testing\"))]\n");
    assert!(
        v.iter().any(|x| x.contains("CFG-EXCLUDED")),
        "an enclosing module's exclusion must be a violation: {v:?}"
    );

    // `not(test)` is excluded in the TEST view for the same reason.
    let v = bindings_over("#[cfg(not(test))]\n", "#[cfg(test)]\n");
    assert!(
        v.iter().any(|x| x.contains("CFG-EXCLUDED")),
        "`not(test)` must be excluded from the test view: {v:?}"
    );
}

/// RED-7. The test view's TARGET is the one `cargo test` builds for — the
/// HOST — not the production wasm32 triple. A bound test gated
/// `#[cfg(target_arch = "wasm32")]` compiles to ZERO host tests, so it is not
/// evidence; evaluating it against the wasm32 atom map certified it.
#[test]
fn a_wasm32_gated_bound_test_is_not_evidence_in_the_host_test_view() {
    let host = host_atoms();
    let host_arch = host
        .map
        .get("target_arch")
        .and_then(|v| v.iter().next().cloned())
        .expect("host target_arch");
    assert_ne!(host_arch, "wasm32", "the gate's `cargo test` leg is not a wasm target");

    // The SSA round-3 mutation, verbatim in shape: `#[test]` retained,
    // `#[cfg(target_arch = "wasm32")]` added.
    let v = bindings_over("#[cfg(target_arch = \"wasm32\")]\n", "#[cfg(test)]\n");
    assert!(
        v.iter().any(|x| x.contains("CFG-EXCLUDED")),
        "a wasm32-gated bound test must be a violation in the host test view: {v:?}"
    );

    // The same exclusion one level up, on the enclosing module.
    let v = bindings_over("", "#[cfg(all(test, target_arch = \"wasm32\"))]\n");
    assert!(
        v.iter().any(|x| x.contains("CFG-EXCLUDED")),
        "an enclosing wasm32-gated module must be a violation: {v:?}"
    );

    // The DEFECT, pinned: under the production wasm32 atom map the very same
    // source certifies. This is why the two views must not share an atom set.
    let v = bindings_over_with(&wasm32_atoms(), "#[cfg(target_arch = \"wasm32\")]\n", "#[cfg(test)]\n");
    assert!(
        v.is_empty(),
        "pins the round-3 defect: the wasm32 atom map certifies a host-excluded test"
    );

    // Positive control: gated on the HOST arch, the test really does compile,
    // so the row stands. The check discriminates; it is not "wasm32 is bad".
    let v = bindings_over(&format!("#[cfg(target_arch = \"{host_arch}\")]\n"), "#[cfg(test)]\n");
    assert!(v.is_empty(), "a host-arch-gated bound test does compile: {v:?}");

    // And the production census keeps its production target: the literal is
    // still the wasm triple, and the host capture is a separate entry point.
    assert_eq!(verify_gate_lints::target_cfg::PRODUCTION_TARGET, "wasm32-unknown-unknown");
    assert!(wasm32_atoms().matches("target_arch", "wasm32"));
}

/// The test view's feature set is READ FROM the suite's committed
/// `gate_invocation`, not assumed. A gate that really did pass
/// `--features testing` would compile the test, and the row would stand.
#[test]
fn the_test_view_features_come_from_the_gate_invocation() {
    let declared: BTreeSet<String> =
        ["testing".to_string(), "extra".to_string()].into_iter().collect();
    let f = |inv: &str| verify_gate_lints::bindings::gate_enabled_features(inv, &declared);
    assert!(f("cargo test --workspace --locked --no-fail-fast").is_empty());
    assert!(f("cargo test -p vault --features testing").contains("testing"));
    assert!(f("cargo test -p vault --features=testing,extra").contains("extra"));
    assert_eq!(f("cargo test --all-features").len(), 2);
    // The crate directory decomposition the manifest lookup depends on.
    assert_eq!(
        verify_gate_lints::bindings::crate_dir_of("canisters/vault/src/lib.rs").as_deref(),
        Some("canisters/vault")
    );
    assert_eq!(
        verify_gate_lints::bindings::crate_dir_of("scripts/verify_custody_manifest/tests/export.rs")
            .as_deref(),
        Some("scripts/verify_custody_manifest")
    );
}

/// RED-5. Two distinct skips rendered on ONE source line are two sites.
/// This drives the real SCANNER (`scan_file`) and groups its output the way
/// `main` does, so nothing about the multiplicity comparison is hand-built.
#[test]
fn same_line_formatting_does_not_collapse_two_skips() {
    let pats = no_skips_pats();
    let rel = "integration-tests/tests/synthetic_fixture.rs";
    let multi = "#[test] fn t() { eprintln!(\"SKIP: one\"); return; }";
    let single = "#[test]\nfn t() {\n    eprintln!(\"SKIP: one\");\n    return;\n}\n";
    let two_one_line =
        "#[test] fn t() { eprintln!(\"SKIP: added\"); return; eprintln!(\"SKIP: one\"); }";

    let scan = |src: &str| {
        let index = verify_gate_lints::no_skips::FnIndex::from_source(rel, src);
        verify_gate_lints::no_skips::scan_file(rel, src, &pats, &index).expect("parses")
    };
    assert_eq!(scan(single).len(), 1);
    assert_eq!(scan(multi).len(), 1, "reformatting alone must not change the count");
    let f = scan(two_one_line);
    assert_eq!(
        f.len(),
        2,
        "two distinct skip sites on one line are TWO sites, not one: {f:?}"
    );
    assert!(f.iter().all(|x| x.shape == 5 && x.owner_fn == "t"));

    // And the grouped count `apply_baseline` compares is 2, so a `count = 1`
    // baseline row RED-s — the end-to-end path RED-5 walked.
    let mut found: std::collections::BTreeMap<(String, String, u8), Vec<String>> =
        Default::default();
    for x in f {
        found
            .entry((x.file.clone(), x.owner_fn.clone(), x.shape))
            .or_default()
            .push(x.to_string());
    }
    let bl: verify_gate_lints::data::NoSkipsBaseline = toml::from_str(&format!(
        "[[site]]\nfile = \"{rel}\"\nowner_fn = \"t\"\nshape = 5\ncount = 1\n\
         reason = \"pre-existing\"\nowner = \"R-L\"\n"
    ))
    .expect("baseline");
    let (v, _) = verify_gate_lints::no_skips::apply_baseline(&found, &bl);
    assert!(
        v.iter().any(|x| x.contains("now has 2 matching site(s)")),
        "the one-line variant must still exceed its counted exemption: {v:?}"
    );
}

/// RED-6. An unrelated function sharing a presence helper's bare name must not
/// be able to answer for it. Ambiguity resolves to the conservative UNION.
#[test]
fn a_same_named_decoy_cannot_shadow_a_presence_helper() {
    // Decoy FIRST — the order a first-wins bare-name index lost to.
    let decoy_first = scan_synthetic(
        r#"
        mod ssa_decoy { fn check_ssa() -> bool { true } }
        fn check_ssa() -> bool { std::path::Path::new("absent").exists() }
        #[test]
        fn ssa_helper_skip() { if !check_ssa() { return; } assert!(false); }
        "#,
    );
    assert_eq!(decoy_first.len(), 1, "the decoy must not shadow the real helper: {decoy_first:?}");
    assert_eq!(decoy_first[0].shape, 3);

    // Decoy LAST — the same verdict, so the rule is not order-dependent.
    let decoy_last = scan_synthetic(
        r#"
        fn check_ssa() -> bool { std::path::Path::new("absent").exists() }
        mod ssa_decoy { fn check_ssa() -> bool { true } }
        #[test]
        fn ssa_helper_skip() { if !check_ssa() { return; } assert!(false); }
        "#,
    );
    assert_eq!(decoy_last.len(), 1, "order must not matter: {decoy_last:?}");

    // Both definition sites are indexed, keyed by module path — not collapsed.
    let index = verify_gate_lints::no_skips::FnIndex::from_source(
        "integration-tests/tests/synthetic_fixture.rs",
        r#"
        mod ssa_decoy { fn check_ssa() -> bool { true } }
        fn check_ssa() -> bool { std::path::Path::new("absent").exists() }
        "#,
    );
    let cands = index.candidates("integration-tests/tests/synthetic_fixture.rs", "check_ssa");
    assert_eq!(cands.len(), 2, "both definition sites must be indexed: {cands:?}");
    let mut paths: Vec<&str> = cands.iter().map(|c| c.module_path.as_str()).collect();
    paths.sort();
    assert_eq!(paths, vec!["", "ssa_decoy"]);

    // The conservative union must NOT fire when NO candidate is a presence
    // helper — otherwise the rule would fire on every `if` and prove nothing.
    let clean = scan_synthetic(
        r#"
        mod ssa_decoy { fn check_ssa() -> bool { true } }
        fn check_ssa() -> bool { 2 + 2 == 4 }
        #[test]
        fn ordinary_guard() { if !check_ssa() { return; } assert!(false); }
        "#,
    );
    assert!(clean.is_empty(), "no candidate is a presence helper: {clean:?}");
}

// ── AC-4 — per-target-key fixtures, GENERATED from the live map ─────────────
//
// The brief this crate replaced shipped a hand-written table of "exactly seven"
// `target_*` keys. It was false, and a hand-maintained table cannot be both
// exhaustive and correct. These tests therefore enumerate whatever
// `rustc --print cfg --target wasm32-unknown-unknown` prints for the PINNED
// toolchain and generate a positive and a negative case per key — so a rustc
// that starts printing an eleventh key is covered the day it does, without an
// edit here.

fn live_wasm_atoms() -> TargetAtoms {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    TargetAtoms::capture(root).expect("the pinned toolchain prints a wasm32 cfg map")
}

/// AC-4a — for EVERY key the live map carries, a value it prints matches and a
/// value it does not print (`__absent__`) does not.
///
/// Real-site mutation: `target_cfg.rs`'s `matches` is
/// `self.map.get(key).map(|vs| vs.contains(value))`. Replace `vs.contains(value)`
/// with `!vs.is_empty()` — both sides `bool`, the crate still compiles — and
/// every `__absent__` negative below flips to true.
#[test]
fn every_live_target_key_evaluates_true_positive_false_negative() {
    let t = live_wasm_atoms();
    let keys: Vec<String> = t.keys().cloned().collect();
    assert!(
        keys.len() >= 10,
        "the live map must be the real one, not an empty stand-in: {keys:?}"
    );
    for key in &keys {
        let values: Vec<String> = t.map.get(key).expect("key came from keys()").iter().cloned().collect();
        assert!(!values.is_empty(), "{key} printed no value");
        for v in &values {
            assert!(
                t.matches(key, v),
                "{key} = {v:?} is a value rustc printed and must match"
            );
        }
        assert!(
            !t.matches(key, "__absent__"),
            "{key} must NOT match a value rustc never printed — a `matches` that \
             answered 'the key exists' instead of 'this value is in its set' would \
             pass every positive above and fail only here"
        );
        assert!(t.knows(key));
    }
    assert!(!t.knows("target_frobnicate"), "an unknown KEY is not known");
}

/// AC-4b — the multi-valued keys are SET MEMBERSHIP, not any-match. This is the
/// assertion the `!vs.is_empty()` mutation flips a second time, independently:
/// `target_feature` genuinely carries several values, and `simd128` is not one
/// of them on this target.
// BINDING: B-RL2-TARGET-KEY-FIXTURES
#[test]
fn target_feature_and_target_has_atomic_are_set_membership_not_any_match() {
    let t = live_wasm_atoms();
    let features = t.map.get("target_feature").expect("wasm32 prints target_feature");
    assert!(
        features.len() > 1,
        "target_feature must be MULTI-VALUED for this test to discriminate: {features:?}"
    );
    let present = features.iter().next().expect("at least one feature").clone();
    // Two invocations of the bound entrypoint, differing in their second
    // argument, with an inequality between the outcomes. A `matches` that
    // answered on the KEY rather than the VALUE could not tell these apart.
    assert_ne!(
        t.matches("target_feature", &present),
        t.matches("target_feature", "simd128"),
        "a value rustc printed and one it did not must not evaluate the same"
    );
    assert!(t.matches("target_feature", &present));
    assert!(
        !t.matches("target_feature", "simd128"),
        "simd128 is not enabled by default on wasm32-unknown-unknown"
    );
    // Both hold simultaneously — set membership, not a single-value key.
    for f in features {
        assert!(t.matches("target_feature", f));
    }
    let atomics = t.map.get("target_has_atomic");
    if let Some(atomics) = atomics {
        for a in atomics {
            assert!(t.matches("target_has_atomic", a));
        }
        assert!(!t.matches("target_has_atomic", "__absent__"));
    }
}

/// AC-4c — a key OUTSIDE the live map is a hard error at parse time, not a
/// silent false. The generated loop above would otherwise quietly certify a
/// misspelled key as "absent everywhere".
#[test]
fn unknown_target_key_in_generated_loop_is_hard_error() {
    let t = live_wasm_atoms();
    let f: syn::File =
        syn::parse_str(r#"#[cfg(target_frobnicate = "x")] fn f() {}"#).unwrap();
    let syn::Item::Fn(func) = f.items.first().unwrap() else { panic!() };
    let err = parse_cfg_attr(&func.attrs[0], "fixture.rs", &t)
        .expect_err("a target_* key rustc does not print is a REFUSAL, not a false");
    assert!(err.fragment.contains("target_frobnicate"), "{}", err.fragment);
    // Positive control: a real key from the same live map parses cleanly.
    let key = t.keys().next().expect("a live key").clone();
    let value = t.map.get(&key).unwrap().iter().next().unwrap().clone();
    let src = format!("#[cfg({key} = \"{value}\")] fn f() {{}}");
    let g: syn::File = syn::parse_str(&src).unwrap();
    let syn::Item::Fn(gf) = g.items.first().unwrap() else { panic!() };
    parse_cfg_attr(&gf.attrs[0], "fixture.rs", &t)
        .expect("a key rustc DID print must parse without a refusal");
}
