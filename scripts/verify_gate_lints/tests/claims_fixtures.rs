//! AC-2 / AC-3 / AC-5 — the `claims` lint's `property` rule and its behaviour on
//! a synthetic tree.
//!
//! `referent_exists` cannot distinguish "a fn of this name exists" from "this fn
//! measures this sentence" — by construction, at any depth of checking. Lane
//! R-11 found one live row where it did not (the vault history-depth clause,
//! pointed at an unrelated upgrade test) and this lane found a second (the
//! vetkeys fail-closed-decode clause, pointed at the round-trip test above it).
//! `property` does not close that gap. It makes the link RE-CHECKABLE: a
//! re-pointed row now costs a read of the referent, because the token has to be
//! in the referent's own code.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use verify_gate_lints::claims;
use verify_gate_lints::data::{BaselineClaim, ClaimsBaseline, ClaimsPatterns, Corpus};

// ── a throwaway tree ────────────────────────────────────────────────────────

struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp_tree(tag: &str) -> Tmp {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "vgl_claims_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).expect("temp tree");
    Tmp(p)
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn patterns() -> ClaimsPatterns {
    ClaimsPatterns {
        normative: vec!["cannot".into()],
        cost_rate: vec!["cycles".into()],
        measured_marker: "MEASURED:".into(),
        unbacked_marker: "UNBACKED:".into(),
        ignore_lines_containing: vec![],
    }
}

fn corpus() -> Corpus {
    Corpus {
        dirs: vec!["canisters".into()],
        files: vec![],
        extensions: vec!["rs".into()],
        exclude: vec![],
    }
}

/// One claim-bearing source file plus the referent that is supposed to back it.
/// `EXPECTED_CHUNK` is the honest token: the referent asserts on it. `only_in_a_
/// doc_comment` appears ONLY in prose above the fn, which is the whole point of
/// AC-2d.
const REFERENT_SRC: &str = r#"
// This claim cannot exceed the per-message cycles budget.
/// Backs the claim above. Mentions only_in_a_doc_comment, which is PROSE.
#[test]
fn synthetic_referent_measures_the_chunk() {
    assert_eq!(observed_chunk(), EXPECTED_CHUNK);
}
"#;

const CLAIM_TEXT: &str = "// This claim cannot exceed the per-message cycles budget.";

fn tree_with_referent(tag: &str) -> Tmp {
    let t = tmp_tree(tag);
    write(&t.0, "canisters/synthetic/src/lib.rs", REFERENT_SRC);
    t
}

fn measured_row(property: Option<&str>, referent: &str) -> BaselineClaim {
    BaselineClaim {
        file: "canisters/synthetic/src/lib.rs".into(),
        text: CLAIM_TEXT.into(),
        marker: "MEASURED".into(),
        referent: referent.into(),
        reason: String::new(),
        property: property.map(str::to_string),
    }
}

fn run(root: &Path, rows: Vec<BaselineClaim>) -> Vec<String> {
    let baseline = ClaimsBaseline { claim: rows };
    claims::run(root, &corpus(), &patterns(), &baseline).violations
}

// ── AC-2 — the `property` rule ──────────────────────────────────────────────

/// AC-2a — a `MEASURED` row with no `property` is a finding. Positive control:
/// the same row WITH the honest token is clean.
#[test]
fn measured_row_missing_property_is_red() {
    let t = tree_with_referent("ac2a");
    let v = run(&t.0, vec![measured_row(None, "synthetic_referent_measures_the_chunk")]);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("carries no `property`"), "{}", v[0]);

    let ok = run(
        &t.0,
        vec![measured_row(Some("EXPECTED_CHUNK"), "synthetic_referent_measures_the_chunk")],
    );
    assert!(ok.is_empty(), "positive control must be clean: {ok:?}");
}

/// AC-2b — a `property` absent from the referent's own code is a finding. This
/// is the case that makes the token a LINK rather than a decoration.
// BINDING: B-RL2-MEASURED-PROPERTY
#[test]
fn measured_row_property_absent_from_referent_body_is_red() {
    let t = tree_with_referent("ac2b");
    let absent = run(
        &t.0,
        vec![measured_row(Some("A_TOKEN_THE_REFERENT_NEVER_USES"), "synthetic_referent_measures_the_chunk")],
    );
    let present = run(
        &t.0,
        vec![measured_row(Some("EXPECTED_CHUNK"), "synthetic_referent_measures_the_chunk")],
    );
    // Two invocations of the bound entrypoint with DIFFERING inputs, and the
    // outcomes differ.
    assert_ne!(
        absent.len(),
        present.len(),
        "the property's presence in the referent has to change the verdict"
    );
    assert_eq!(absent.len(), 1, "{absent:?}");
    assert!(absent[0].contains("is ABSENT from referent"), "{}", absent[0]);
    assert!(present.is_empty(), "{present:?}");
}

/// AC-2c — `property` equal to the referent's own name is the existence check
/// restated. It would pass a naive token scan (the fn's own name IS in its
/// rendered tokens) and prove nothing, so it is rejected by name.
#[test]
fn property_token_reused_as_referent_name_is_rejected() {
    let t = tree_with_referent("ac2c");
    let v = run(
        &t.0,
        vec![measured_row(
            Some("synthetic_referent_measures_the_chunk"),
            "synthetic_referent_measures_the_chunk",
        )],
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("is the referent's own name"), "{}", v[0]);
}

/// AC-2d — a token that appears only in a doc comment is PROSE, and prose is
/// what a marker is meant to be backed against, not matched to. `#[doc]`
/// attributes are stripped before the referent's tokens are scanned.
#[test]
fn property_in_doc_comment_only_does_not_count() {
    let t = tree_with_referent("ac2d");
    let src = std::fs::read_to_string(t.0.join("canisters/synthetic/src/lib.rs")).unwrap();
    assert!(
        src.contains("only_in_a_doc_comment"),
        "the token IS in the file — the check must still reject it"
    );
    let v = run(
        &t.0,
        vec![measured_row(Some("only_in_a_doc_comment"), "synthetic_referent_measures_the_chunk")],
    );
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("is ABSENT from referent"), "{}", v[0]);
}

// ── AC-3 — `claims::run` on a synthetic tree ────────────────────────────────

/// AC-3a — a hit with no marker and no baseline row is a finding; the same line
/// carrying an in-source `UNBACKED:` reason is not.
#[test]
fn run_on_synthetic_tree_flags_unbaselined_claim() {
    let t = tmp_tree("ac3a");
    write(&t.0, "canisters/synthetic/src/lib.rs", "// cannot burn cycles here\n");
    let v = run(&t.0, vec![]);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("with no `MEASURED:` or `UNBACKED:` marker"), "{}", v[0]);

    let t2 = tmp_tree("ac3a_ok");
    write(
        &t2.0,
        "canisters/synthetic/src/lib.rs",
        "// cannot burn cycles here\n// UNBACKED: no measurement exists yet; lane R-L2 owns it\n",
    );
    let ok = run(&t2.0, vec![]);
    assert!(ok.is_empty(), "positive control: {ok:?}");
}

/// AC-3b — a baseline `MEASURED` referent naming neither a file nor a fn is a
/// finding. Positive control: a real fn name in the same tree.
#[test]
fn run_on_synthetic_tree_flags_dangling_measured_referent() {
    let t = tree_with_referent("ac3b");
    let v = run(
        &t.0,
        vec![measured_row(Some("EXPECTED_CHUNK"), "no_such_fn_exists_anywhere")],
    );
    assert!(
        v.iter().any(|x| x.contains("names no file and no fn in the tree")),
        "{v:?}"
    );
    let ok = run(
        &t.0,
        vec![measured_row(Some("EXPECTED_CHUNK"), "synthetic_referent_measures_the_chunk")],
    );
    assert!(ok.is_empty(), "{ok:?}");
}

/// AC-3c — `scope`'s undeclared-file diagnostic, asserted VERBATIM.
///
/// `scope::run(root, base, files)` is the packet-only tool. Its cross-check is
/// the half that catches a claim-bearing file edited but left out of the
/// declared scope list — the exact shape a "docs-only" commit uses to carry an
/// unrelated change (ARCHITECTURE.md law 9). The diagnostic string is asserted
/// character for character, because a diagnostic nobody reads the text of is a
/// diagnostic that can silently stop naming the file.
#[test]
fn scope_exclusion_diagnostic_is_exact() {
    let t = tmp_tree("ac3c");
    let root = &t.0;
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@example.invalid"]);
    git(&["config", "user.name", "t"]);
    write(root, "declared.rs", "pub fn declared() {}\n");
    write(root, "undeclared.rs", "pub fn undeclared() {}\n");
    git(&["add", "-A"]);
    git(&["commit", "-qm", "base"]);
    let base = {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    // Both files change; only one is declared.
    write(root, "declared.rs", "pub fn declared() {}\n// a comment, behaviourally inert\n");
    write(root, "undeclared.rs", "pub fn undeclared() { let _ = 1; }\n");
    git(&["add", "-A"]);
    git(&["commit", "-qm", "head"]);

    let report = verify_gate_lints::scope::run(root, &base, &["declared.rs".to_string()]);
    assert!(
        report.lines.contains(&"  cross-check: 1 touched file(s) NOT declared: undeclared.rs".to_string()),
        "the diagnostic must name the file, verbatim: {:?}",
        report.lines
    );
    // Positive control: declare both and the cross-check is clean.
    let ok = verify_gate_lints::scope::run(
        root,
        &base,
        &["declared.rs".to_string(), "undeclared.rs".to_string()],
    );
    assert!(
        ok.lines.contains(&"  cross-check: every touched file is declared".to_string()),
        "{:?}",
        ok.lines
    );
}

// ── AC-5 — the additive pattern set over the REAL corpus ────────────────────

/// AC-5 — after the additive set lands, EVERY hit over the governed corpus is
/// still discharged, and every baseline row still matches a live hit.
///
/// The count is NOT pinned here. `claims_baseline.toml`'s own header says why:
/// a hand-maintained tally above a list is a second source of truth. The
/// property is `unmarked == 0` and `stale == 0`, which is what "the additions
/// produce only baselined hits" means; the number is regenerated by the gate
/// stage at the point of use.
#[test]
fn low_and_measured_risk_additions_produce_only_baselined_hits() {
    let root = workspace_root();
    let d = root.join("scripts").join("gate_lints");
    let corpus: Corpus = verify_gate_lints::data::load(&d.join("CORPUS.toml")).unwrap();
    let pats: ClaimsPatterns =
        verify_gate_lints::data::load(&d.join("claims_patterns.toml")).unwrap();
    let baseline: ClaimsBaseline =
        verify_gate_lints::data::load(&d.join("claims_baseline.toml")).unwrap();

    // The additive set adjudicated for this lane is actually IN the committed
    // pattern data — a test that passed with the patterns absent would be
    // vacuous.
    for w in ["no drain", "negligible", "only ever", "by construction", "there is no",
              "fail-closed", "fail closed", "at most"] {
        assert!(pats.normative.iter().any(|x| x == w), "normative pattern `{w}` is not committed");
    }
    for w in ["unbounded", "per-call", "per call", "refund"] {
        assert!(pats.cost_rate.iter().any(|x| x == w), "cost_rate pattern `{w}` is not committed");
    }
    // A zero-hit pattern is barred: it can never fail, so it is not a lint.
    assert!(
        !pats.normative.iter().any(|x| x == "unreachable"),
        "`unreachable` produced 0 hits over the governed corpus and must not be carried"
    );

    let outcome = claims::run(&root, &corpus, &pats, &baseline);
    let marked = outcome.hits.iter().filter(|h| h.marker.is_some()).count();
    let unmarked = outcome.hits.len() - marked - outcome.baseline_discharged;
    assert_eq!(unmarked, 0, "every hit is discharged; violations: {:?}", outcome.violations);
    assert!(outcome.violations.is_empty(), "{:?}", outcome.violations);
    assert_eq!(
        outcome.baseline_discharged,
        baseline.claim.len(),
        "every baseline row matches exactly one live hit — a row that matches nothing is a \
         stale annotation nobody is watching"
    );
}

/// The `property` field is populated on EVERY committed `MEASURED` row, and no
/// row's token is its own referent's name. This is the real-tree counterpart of
/// AC-2a/AC-2c: the fixtures prove the rule bites, this proves it is satisfied
/// by the shipped data rather than by an empty row set.
#[test]
fn every_committed_measured_row_carries_a_distinct_property_token() {
    let root = workspace_root();
    let baseline: ClaimsBaseline = verify_gate_lints::data::load(
        &root.join("scripts/gate_lints/claims_baseline.toml"),
    )
    .unwrap();
    let mut by_token: BTreeMap<&str, usize> = BTreeMap::new();
    let mut measured = 0usize;
    for c in &baseline.claim {
        match c.marker.as_str() {
            "MEASURED" => {
                measured += 1;
                let p = c.property.as_deref().unwrap_or("");
                assert!(!p.is_empty(), "MEASURED row for `{}` has no property", c.referent);
                assert_ne!(p, c.referent, "property restates the referent's name");
                *by_token.entry(p).or_default() += 1;
            }
            "UNBACKED" => assert!(
                !c.reason.trim().is_empty(),
                "an UNBACKED row's reason says what is missing; it is never blank"
            ),
            other => panic!("unexpected marker `{other}`"),
        }
    }
    assert!(measured > 0, "the check must not be satisfied by an empty MEASURED set");
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above scripts/verify_gate_lints")
        .to_path_buf()
}
