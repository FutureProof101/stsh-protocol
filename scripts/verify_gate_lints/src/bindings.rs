//! `bindings` (G-c) — the binding TEST is the permanent in-repo evidence.
//!
//! For every registry row, the named test must:
//!   (a) EXIST, in the named file, in the named crate, AND actually be a
//!       HARNESS-EXECUTED TEST — it must carry a test attribute (`#[test]` and
//!       the qualified `#[<path>::test]` async forms; see
//!       `crate::is_test_attr` for the enumeration). Finding a FUNCTION of the
//!       right name is not finding a TEST: deleting `#[test]` from a bound
//!       test turns it into an uncalled helper that the gate never executes,
//!       while `bindings` went on certifying the row (SSA landed-diff round 1,
//!       RED-1);
//!   (a3) be EFFECTIVELY COMPILED IN under the view the gate's own test
//!       invocation builds — the conjunction of the function's own `#[cfg(...)]`
//!       predicates AND every enclosing module's, evaluated by
//!       `crate::cfg_eval` in the TEST VIEW: `test = true`, and the crate's
//!       resolved `default` feature closure plus exactly the features the
//!       suite's `gate_invocation` turns on (none of the four committed
//!       invocations passes `--features`, so `testing` is NOT on). A `#[test]`
//!       the harness never compiles lists ZERO tests and executes nothing;
//!       keeping `#[test]` while adding `#[cfg(feature = "testing")]` was a
//!       source-only edit that left the row certified GREEN (SSA landed-diff
//!       round 2, RED-4). This is the same evaluator the ceiling census uses —
//!       an unrecognised cfg atom is a REFUSAL (exit 2), never a silent pass;
//!   (b) carry a `BINDING: <id>` marker comment;
//!   (c) invoke the bound entrypoint AT LEAST TWICE with DIFFERING inputs, and
//!       assert an inequality or a rejection — a structural shape check, not a
//!       claim about what the binding actually proves;
//!   (d) NOT be `#[ignore]`d;
//!   (e) live in a crate whose suite `run_gate.sh` actually invokes, checked by
//!       a CENSUS OF THE SCRIPT'S CONTENT (`crate::shell_lex::census_invoked`):
//!       the invocation's word sequence must appear at COMMAND POSITION in a
//!       simple command the script actually runs. A literal-substring check —
//!       what this rule used to be — is satisfied by a commented-out line, a
//!       quoted `echo`, or a here-document, none of which run anything.
//!
//! NO evidence file, NO office path, NO sha256 pinning, ever (AC-7g). The
//! registry schema REFUSES such a field rather than merely omitting it.
//!
//! Launch-posture closure: with `posture = "launch"`, every row must be
//! `status = "closed"`. R-3b's `[deploy_gate]` partition is the deployment-side
//! counterpart; this keying is noted in the packet and reconciled at merge.

use std::collections::BTreeSet;
use std::path::Path;

use syn::ItemFn;

use crate::cfg_eval::{effective, parse_cfg_attr, Env, Pred};
use crate::data::{BindingRegistry, BoundSuite, BoundTestSuites};
use crate::features::{default_closure, read_feature_table};
use crate::shell_lex::census_invoked;
use crate::target_cfg::TargetAtoms;
use crate::{is_test_attr, test_attrs};

pub struct BindingOutcome {
    pub violations: Vec<String>,
    pub checked: usize,
    /// Conditions the lint REFUSES to evaluate past (exit 2), not findings:
    /// an unreadable manifest or an unrecognised cfg atom on the path to a
    /// bound test. Reporting "0 findings" while unable to evaluate a row's
    /// effective cfg would be the silent-false the evaluator exists to forbid.
    pub refusals: Vec<String>,
}

/// Reject any registry key that would reintroduce an office/evidence-file
/// dependency. Read as raw TOML so an added field is caught even though the
/// typed struct would silently ignore it.
pub fn schema_check(raw: &str) -> Vec<String> {
    const BANNED: &[&str] = &[
        "proof_evidence_file",
        "proof_sha256",
        "evidence_file",
        "evidence_sha256",
        "office_path",
        "packet_sha256",
    ];
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        for b in BANNED {
            if t.starts_with(b) || t.starts_with(&format!("\"{b}\"")) {
                out.push(format!(
                    "tests/BINDING_REGISTRY.toml:{}: banned field `{b}` — the binding TEST is the \
                     evidence; no repo-committed review/packet file and no office-path or hash \
                     dependency may be reintroduced",
                    i + 1
                ));
            }
        }
        if t.contains("/mnt/") {
            out.push(format!(
                "tests/BINDING_REGISTRY.toml:{}: office mount path in a gate input",
                i + 1
            ));
        }
    }
    out
}

/// Every argument list `target(...)` receives anywhere in a token stream —
/// direct calls, method calls, and calls nested inside an assertion macro
/// alike. Macro bodies are not parsed by `syn`, so an AST-only visit sees
/// `assert_eq!(approve_inner(a, b), Err(..))` as ONE opaque macro and counts
/// zero invocations; scanning the rendered token stream is what makes the
/// two-differing-invocations rule actually reach the shape it is written for.
fn invocation_args(tokens: &str, target: &str) -> Vec<String> {
    let bytes: Vec<char> = tokens.chars().collect();
    let t: Vec<char> = target.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + t.len() < bytes.len() {
        if bytes[i..i + t.len()] != t[..] {
            i += 1;
            continue;
        }
        // Must be a whole identifier, not a suffix of a longer one.
        let before_ok = i == 0 || !(bytes[i - 1].is_alphanumeric() || bytes[i - 1] == '_');
        let mut j = i + t.len();
        while j < bytes.len() && bytes[j] == ' ' {
            j += 1;
        }
        if !before_ok || j >= bytes.len() || bytes[j] != '(' {
            i += 1;
            continue;
        }
        let mut depth = 0i32;
        let mut arg = String::new();
        let mut k = j;
        while k < bytes.len() {
            match bytes[k] {
                '(' => {
                    depth += 1;
                    if depth > 1 {
                        arg.push('(');
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    arg.push(')');
                }
                c => arg.push(c),
            }
            k += 1;
        }
        out.push(arg.split_whitespace().collect::<Vec<_>>().join(" "));
        i = k.max(i + 1);
    }
    out
}

/// Does this token stream assert an inequality or a rejection?
fn asserts_inequality(tokens: &str) -> bool {
    const REJECTION: &[&str] = &[
        "assert_ne !",
        "assert_ne!",
        "!=",
        "is_err",
        "expect_err",
        "unwrap_err",
        "Err (",
        "should_panic",
    ];
    REJECTION.iter().any(|m| tokens.contains(m))
}

/// The crate directory a registered `test_file` belongs to: everything before
/// its `src/` or `tests/` component. `canisters/vault/src/lib.rs` ->
/// `canisters/vault`; `scripts/verify_custody_manifest/tests/export.rs` ->
/// `scripts/verify_custody_manifest`. Same decomposition `no_skips::crate_key`
/// uses, so the two lints agree about crate boundaries.
pub fn crate_dir_of(test_file: &str) -> Option<String> {
    let rel = test_file.replace('\\', "/");
    for marker in ["/src/", "/tests/", "/benches/", "/examples/"] {
        if let Some(i) = rel.find(marker) {
            return Some(rel[..i].to_string());
        }
    }
    None
}

/// The features the GATE's own invocation of this suite turns on, over and
/// above the crate's resolved `default` closure.
///
/// This is the "as the gate builds it" half of the test view. It is read from
/// the committed `gate_invocation` string — the same literal the (e) check
/// already proves is present in `run_gate.sh` — so the lint cannot assume a
/// feature the gate does not actually pass. None of the committed invocations
/// passes `--features`, which is exactly why `#[cfg(feature = "testing")]` on
/// a bound test makes it non-evidence.
pub fn gate_enabled_features(invocation: &str, declared: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let toks: Vec<&str> = invocation.split_whitespace().collect();
    let mut i = 0usize;
    while i < toks.len() {
        let t = toks[i];
        if t == "--all-features" {
            out.extend(declared.iter().cloned());
        } else if t == "--features" || t == "-F" {
            if let Some(v) = toks.get(i + 1) {
                for f in v.split([',', ' ']) {
                    if !f.is_empty() {
                        out.insert(f.to_string());
                    }
                }
                i += 1;
            }
        } else if let Some(v) = t.strip_prefix("--features=") {
            for f in v.split(',') {
                if !f.is_empty() {
                    out.insert(f.to_string());
                }
            }
        }
        i += 1;
    }
    out
}

/// The cfg predicates on an item, parsed. A `CfgError` is a refusal, not a
/// finding.
fn item_cfgs(
    attrs: &[syn::Attribute],
    file: &str,
    target: &TargetAtoms,
    refusals: &mut Vec<String>,
) -> Vec<Pred> {
    let mut out = Vec::new();
    for a in attrs {
        match parse_cfg_attr(a, file, target) {
            Ok(Some(p)) => out.push(p),
            Ok(None) => {}
            Err(e) => refusals.push(e.to_string()),
        }
    }
    out
}

/// The located bound function plus the cfg predicates in scope at its
/// definition site: its own, and every enclosing `mod`'s.
struct Located<'a> {
    f: &'a ItemFn,
    /// Enclosing-module predicates, outermost first.
    module_cfgs: Vec<Pred>,
}

fn find_test_scoped<'a>(
    items: &'a [syn::Item],
    name: &str,
    file: &str,
    target: &TargetAtoms,
    refusals: &mut Vec<String>,
    inherited: &[Pred],
) -> Option<Located<'a>> {
    // Prefer a same-named function that IS a test, so a non-test helper
    // shadowing the name earlier in the file cannot mask the real bound test
    // (nor a real test mask a helper — the eligibility checks below report on
    // whatever is returned).
    let mut fallback: Option<Located<'a>> = None;
    for item in items {
        match item {
            syn::Item::Fn(f) if f.sig.ident == name => {
                let loc = Located { f, module_cfgs: inherited.to_vec() };
                if f.attrs.iter().any(is_test_attr) {
                    return Some(loc);
                }
                fallback = fallback.or(Some(loc));
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    let mut scope = inherited.to_vec();
                    scope.extend(item_cfgs(&m.attrs, file, target, refusals));
                    if let Some(loc) =
                        find_test_scoped(inner, name, file, target, refusals, &scope)
                    {
                        if loc.f.attrs.iter().any(is_test_attr) {
                            return Some(loc);
                        }
                        fallback = fallback.or(Some(loc));
                    }
                }
            }
            _ => {}
        }
    }
    fallback
}

pub fn run(
    root: &Path,
    reg: &BindingRegistry,
    raw: &str,
    suites: &BoundTestSuites,
    gate_script: &str,
    target: &TargetAtoms,
) -> BindingOutcome {
    let mut violations = schema_check(raw);
    let mut refusals: Vec<String> = Vec::new();

    // Required rows — same reasoning as the ceiling registry's: a registry you
    // can satisfy by DELETING a row is not a registry (M7a).
    let have: std::collections::BTreeSet<&str> =
        reg.binding.iter().map(|b| b.id.as_str()).collect();
    for id in &reg.required_bindings {
        if !have.contains(id.as_str()) {
            violations.push(format!(
                "required binding `{id}` is missing from tests/BINDING_REGISTRY.toml — \
                 deleting a row deletes the evidence, not the obligation"
            ));
        }
    }

    // EVERY suite listed in BOUND_TEST_SUITES.toml must be gate-invoked,
    // whether or not a binding row currently points at it. Checking only the
    // referenced ones means commenting the vetkeys leg out of run_gate.sh goes
    // unnoticed until the day someone binds a property to it (M7f-3) — and
    // vetkeys is workspace-EXCLUDED, so its separate invocation is the only
    // thing that ever runs it. `census_invoked` decides "invoked" by tokenizing
    // the script, so `# cargo test …` no longer counts as running it.
    for suite in &suites.suite {
        if !census_invoked(gate_script, &suite.gate_invocation) {
            violations.push(format!(
                "BOUND_TEST_SUITES.toml lists crate `{}`, but run_gate.sh INVOKES no \
                 command matching `{}` — a suite the gate does not run can hold no \
                 binding evidence (a commented, quoted or here-doc'd copy of the line is \
                 not an invocation)",
                suite.crate_name, suite.gate_invocation
            ));
        }
    }

    for row in &reg.binding {
        // (e) the suite must be one the gate actually invokes.
        let mut suite_for_row: Option<&BoundSuite> = None;
        match suites.suite.iter().find(|s| s.crate_name == row.test_crate) {
            None => violations.push(format!(
                "binding {}: test_crate `{}` is not listed in scripts/gate_lints/BOUND_TEST_SUITES.toml — \
                 a bound test in a suite the gate does not invoke is not evidence",
                row.id, row.test_crate
            )),
            Some(suite) => {
                suite_for_row = Some(suite);
                if !census_invoked(gate_script, &suite.gate_invocation) {
                    violations.push(format!(
                        "binding {}: run_gate.sh INVOKES no command matching `{}` for crate `{}` — \
                         the bound test's suite is not gate-invoked",
                        row.id, suite.gate_invocation, row.test_crate
                    ));
                }
            }
        }

        let path = root.join(&row.test_file);
        let Ok(text) = std::fs::read_to_string(&path) else {
            violations.push(format!(
                "binding {}: test_file `{}` does not exist",
                row.id, row.test_file
            ));
            continue;
        };
        let Ok(ast) = syn::parse_file(&text) else {
            violations.push(format!("binding {}: could not parse `{}`", row.id, row.test_file));
            continue;
        };
        let Some(located) =
            find_test_scoped(&ast.items, &row.bound, &row.test_file, target, &mut refusals, &[])
        else {
            violations.push(format!(
                "binding {}: `bound` names test `{}`, which does not exist in {}",
                row.id, row.bound, row.test_file
            ));
            continue;
        };
        let f = located.f;
        // (a3) EFFECTIVE cfg in the gate's test view. The function's own
        // predicates AND every enclosing module's must ALL hold, or the
        // harness never compiles the test and the row certifies a test that
        // does not run (SSA landed-diff round 2, RED-4).
        match crate_dir_of(&row.test_file) {
            None => refusals.push(format!(
                "binding {}: cannot locate the crate directory for test_file `{}` (no `src/` or \
                 `tests/` component) — the bound test's effective cfg cannot be evaluated",
                row.id, row.test_file
            )),
            Some(cdir) => {
                let manifest = root.join(&cdir).join("Cargo.toml");
                match read_feature_table(&manifest) {
                    Err(e) => refusals.push(format!(
                        "binding {}: {e} — the bound test's effective cfg cannot be evaluated",
                        row.id
                    )),
                    Ok(table) => {
                        let mut feats = default_closure(&table);
                        if let Some(suite) = suite_for_row {
                            let declared: BTreeSet<String> =
                                table.declared.keys().cloned().collect();
                            feats.extend(gate_enabled_features(
                                &suite.gate_invocation,
                                &declared,
                            ));
                        }
                        // The TEST view: `cargo test` compiles both unit-test
                        // and integration-test targets with `--cfg test`.
                        let env = Env {
                            test: true,
                            features: feats.clone(),
                            target: target.clone(),
                        };
                        let mut preds = located.module_cfgs.clone();
                        preds.extend(item_cfgs(&f.attrs, &row.test_file, target, &mut refusals));
                        if !effective(&preds, &env) {
                            let rendered: Vec<String> =
                                preds.iter().map(|p| format!("{p:?}")).collect();
                            violations.push(format!(
                                "binding {}: bound test `{}` in {} is CFG-EXCLUDED from the view \
                                 the gate builds — its own and/or an enclosing module's \
                                 `#[cfg(...)]` evaluates FALSE under `test = true`, the HOST \
                                 target `cargo test` builds for, with features \
                                 {{{}}} (crate `{}`'s resolved `default` closure plus whatever \
                                 `{}` turns on). The harness compiles zero such tests, so the row \
                                 certifies a test that never runs. Predicates in scope: [{}]",
                                row.id,
                                row.bound,
                                row.test_file,
                                feats.iter().cloned().collect::<Vec<_>>().join(", "),
                                cdir,
                                suite_for_row
                                    .map(|s| s.gate_invocation.as_str())
                                    .unwrap_or("<no gate invocation>"),
                                rendered.join(", ")
                            ));
                        }
                    }
                }
            }
        }
        // (a2) it must actually BE a test. A function of the right name that
        // the harness never runs is not evidence — removing `#[test]` from a
        // bound test is a source-only edit that used to leave the row
        // certified GREEN (SSA landed-diff round 1, RED-1).
        let attrs = test_attrs(f);
        if attrs.is_empty() {
            violations.push(format!(
                "binding {}: `bound` names `{}` in {}, but that function carries NO test \
                 attribute — it is an uncalled helper, not a gate-executed test, so it is not \
                 evidence. Accepted: `#[test]`, or a qualified `#[<path>::test]` (e.g. \
                 `#[tokio::test]`).",
                row.id, row.bound, row.test_file
            ));
        }
        // (d) not ignored — with OR without a reason. An ignored bound test is
        // no evidence regardless of how well the ignore is explained.
        if f.attrs.iter().any(|a| a.path().is_ident("ignore")) {
            violations.push(format!(
                "binding {}: bound test `{}` is `#[ignore]`d — it never runs, so it is not evidence",
                row.id, row.bound
            ));
        }
        // (b) BINDING: marker.
        let want = format!("BINDING: {}", row.id);
        let fn_line = f.sig.fn_token.span.start().line;
        let lines: Vec<&str> = text.lines().collect();
        let lo = fn_line.saturating_sub(30);
        let has_marker = lines[lo..fn_line.min(lines.len())]
            .iter()
            .any(|l| l.contains(&want));
        if !has_marker {
            violations.push(format!(
                "binding {}: bound test `{}` carries no `{}` marker comment",
                row.id, row.bound, want
            ));
        }
        // (c) shape: ≥2 invocations of the bound entrypoint with DIFFERING
        // arguments, plus an inequality/rejection assertion. Both are read from
        // the function's rendered token stream, so a call nested inside an
        // assertion macro counts — an AST-only walk would see the macro as one
        // opaque token tree and miss it.
        let body_tokens = {
            let b = &f.block;
            quote::quote!(#b).to_string()
        };
        let args = invocation_args(&body_tokens, &row.property);
        let distinct: std::collections::BTreeSet<&String> = args.iter().collect();
        if args.len() < 2 {
            violations.push(format!(
                "binding {}: bound test `{}` invokes `{}` {} time(s) — a binding test must invoke \
                 the bound entrypoint at least twice",
                row.id, row.bound, row.property, args.len()
            ));
        } else if distinct.len() < 2 {
            violations.push(format!(
                "binding {}: bound test `{}` invokes `{}` {} times but with IDENTICAL arguments — \
                 a binding test must vary the bound input",
                row.id, row.bound, row.property, args.len()
            ));
        }
        if !asserts_inequality(&body_tokens) {
            violations.push(format!(
                "binding {}: bound test `{}` asserts no inequality or rejection — a binding test \
                 must show the differing input produces a differing/refused outcome",
                row.id, row.bound
            ));
        }
    }

    // Launch-posture closure.
    if reg.posture == "launch" {
        let open: Vec<&str> = reg
            .binding
            .iter()
            .filter(|b| b.status != "closed")
            .map(|b| b.id.as_str())
            .collect();
        if !open.is_empty() {
            violations.push(format!(
                "posture = \"launch\" but {} binding row(s) are not closed: {}",
                open.len(),
                open.join(", ")
            ));
        }
    }

    BindingOutcome { violations, checked: reg.binding.len(), refusals }
}
