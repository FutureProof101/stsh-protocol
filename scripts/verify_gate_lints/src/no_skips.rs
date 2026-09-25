//! `no-skips` (G-d) — a STRUCTURAL net over seven syntax shapes.
//!
//! Defect class: a test or fixture loader that, on a branch testing whether a
//! required precondition/fixture is present, returns without the outcome being
//! distinguishable from a genuine pass.
//!
//! Corpus: `#[test]` functions and fixture-loader functions (`fn load_*` and the
//! loader-name patterns in `no_skips_patterns.toml`) under the scanned roots.
//! This is a NET over seven shapes, not a completeness proof: a skip dispatched
//! through a `dyn Trait` custom check is a KNOWN GAP, disclosed (M9j), not
//! claimed closed.
//!
//! Separate, narrow rule inside the SAME scanned corpus: a bare `#[ignore]`
//! (no reason string) is a violation. The whole-tree `#[ignore` textual
//! population (SI-X-01) is NOT in scope and is neither converted nor counted.

use std::path::{Path, PathBuf};

use syn::visit::Visit;
use syn::{Block, Expr, ItemFn, Stmt};

use std::collections::{BTreeMap, BTreeSet};

use crate::data::NoSkipsPatterns;

/// Maximum call-graph depth the presence resolver follows (triage: <= 3).
///
pub const MAX_HELPER_DEPTH: usize = 3;

/// A definition-site index of every free function in the tree, per CRATE:
/// crate -> bare fn name -> EVERY definition of that name, each carrying its
/// module path and rendered body tokens.
///
/// Why this exists (SSA landed-diff round 1, RED-3): shape-3 detection used to
/// be a SUBSTRING TEST over the condition text against a fixed list of helper
/// NAMES (`_present`, `have_fixture`, `has_fixture`, `fixture_available`). A
/// presence helper called anything else — `fn check_ssa() -> bool {
/// std::path::Path::new("absent").exists() }` — bypassed the whole net while
/// being an entirely ordinary statically dispatched call. Names are not a
/// shape. This index lets the condition's CALLEES be resolved to their bodies
/// so the path-existence call is found where it actually is.
///
/// AMBIGUITY IS RESOLVED CONSERVATIVELY (SSA landed-diff round 2, RED-6).
/// Functions are indexed BY DEFINITION SITE — module path plus name — so a
/// second definition never overwrites, and is never overwritten by, the first.
/// When a call names an identifier that several definition sites declare, the
/// resolver takes the UNION: every candidate is treated as a possible callee,
/// and if ANY of them performs a presence test the condition is a presence
/// condition. A first-wins bare-name map did the opposite — appending
/// `mod ssa_decoy { fn check_ssa() -> bool { true } }` ABOVE the real root
/// `check_ssa` made the lint read the decoy's body and miss the skip, while
/// Rust resolved the call to the real one. Under-approximating the callee set
/// turns an ambiguity into a bypass; over-approximating it can only produce a
/// finding a reviewer must then read.
///
/// SCOPE, stated plainly: free functions only, within the callee's own crate.
/// Inherent/trait METHODS are not indexed, and the disclosed `dyn Trait`
/// dispatch gap is unchanged — this closes the static free-function case the
/// REDs demonstrated, not the dynamic one.
#[derive(Debug, Clone)]
pub struct HelperDef {
    /// `::`-joined enclosing module path, `""` at file root. Part of the key,
    /// so two same-named functions are two entries, never one.
    pub module_path: String,
    /// Rendered body tokens.
    pub body: String,
}

#[derive(Debug, Default)]
pub struct FnIndex {
    /// crate directory (relative to the workspace root) -> fn name -> every
    /// definition site declaring that name.
    by_crate: BTreeMap<String, BTreeMap<String, Vec<HelperDef>>>,
}

impl FnIndex {
    pub fn build(root: &Path) -> Self {
        let mut me = Self::default();
        for r in scan_roots(root) {
            for f in crate::census::rust_files(&r) {
                let Ok(text) = std::fs::read_to_string(&f) else { continue };
                let Ok(ast) = syn::parse_file(&text) else { continue };
                let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
                let ckey = crate_key(&rel);
                let mut fns: Vec<(String, String, String)> = Vec::new();
                collect_fns_scoped(&ast.items, "", &mut fns);
                let bucket = me.by_crate.entry(ckey).or_default();
                for (module_path, name, body) in fns {
                    bucket.entry(name).or_default().push(HelperDef { module_path, body });
                }
            }
        }
        me
    }

    /// Index a single in-memory source file. Used by the retained fixtures so
    /// they exercise the REAL resolver against synthetic sources rather than a
    /// reimplementation of it.
    pub fn from_source(rel: &str, text: &str) -> Self {
        let mut me = Self::default();
        let Ok(ast) = syn::parse_file(text) else { return me };
        let mut fns: Vec<(String, String, String)> = Vec::new();
        collect_fns_scoped(&ast.items, "", &mut fns);
        let bucket = me.by_crate.entry(crate_key(rel)).or_default();
        for (module_path, name, body) in fns {
            bucket.entry(name).or_default().push(HelperDef { module_path, body });
        }
        me
    }

    /// EVERY definition site in this crate declaring `name` — the conservative
    /// union. An empty slice means the name is not an indexed definition.
    pub fn candidates(&self, rel: &str, name: &str) -> &[HelperDef] {
        match self.by_crate.get(&crate_key(rel)).and_then(|m| m.get(name)) {
            Some(v) => v.as_slice(),
            None => &[],
        }
    }
}

/// The crate a scanned file belongs to, as the leading path components before
/// its `src/` or `tests/` directory. `integration-tests/tests/x.rs` ->
/// `integration-tests`; `canisters/vault/src/lib.rs` -> `canisters/vault`.
fn crate_key(rel: &str) -> String {
    let rel = rel.replace('\\', "/");
    for marker in ["/src/", "/tests/"] {
        if let Some(i) = rel.find(marker) {
            return rel[..i].to_string();
        }
    }
    rel
}

/// Every identifier that is CALLED in this rendered token stream: an
/// identifier immediately followed by `(`. Qualified calls contribute their
/// last segment, which is what the bare-name index is keyed on.
fn called_idents(tokens: &str) -> BTreeSet<String> {
    let ch: Vec<char> = tokens.chars().collect();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i < ch.len() {
        if !(ch[i].is_alphabetic() || ch[i] == '_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < ch.len() && (ch[i].is_alphanumeric() || ch[i] == '_') {
            i += 1;
        }
        let name: String = ch[start..i].iter().collect();
        let mut j = i;
        while j < ch.len() && ch[j] == ' ' {
            j += 1;
        }
        // `foo !(` is a macro invocation, not a call to `foo`.
        if j < ch.len() && ch[j] == '(' {
            out.insert(name);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub shape: u8,
    /// The enclosing `#[test]`/loader fn. The BASELINE is keyed on
    /// (file, fn, shape), never on a line number — a line number moves the
    /// moment anything above it is edited, which would silently re-baseline a
    /// new defect onto an old row's exemption.
    pub owner_fn: String,
    pub what: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.shape == 0 {
            write!(f, "{}:{}: {}", self.file, self.line, self.what)
        } else {
            write!(f, "{}:{}: shape {} — {}", self.file, self.line, self.shape, self.what)
        }
    }
}

struct FnScan<'a> {
    file: &'a str,
    owner_fn: &'a str,
    pats: &'a NoSkipsPatterns,
    index: &'a FnIndex,
    out: Vec<Finding>,
}

fn expr_text(e: &Expr) -> String {
    quote::quote!(#e).to_string()
}

/// Does this condition express a "is the fixture/precondition present?" test?
///
/// TWO independent routes, and the second is the one that makes this a SHAPE
/// rule rather than a vocabulary rule:
///
///   1. The condition ITSELF performs the presence test — it contains one of
///      the `presence_predicates` (`.exists()`, `is_err`, `read_to_string`, …).
///   2. The condition CALLS a function that, within `MAX_HELPER_DEPTH` levels
///      of the intra-crate call graph, performs a path-existence call
///      (`presence_body_calls`). The helper's NAME is irrelevant: it is found
///      by resolving the call and reading the body. SSA landed-diff round 1
///      RED-3 bypassed route 1 with a helper named `check_ssa`; route 2 catches
///      it because `Path::new("absent").exists()` is in its body.
fn is_presence_condition(
    text: &str,
    pats: &NoSkipsPatterns,
    rel: &str,
    index: &FnIndex,
) -> bool {
    if pats.presence_predicates.iter().any(|p| text.contains(p.as_str())) {
        return true;
    }
    // The memo is keyed on (name -> the LARGEST remaining depth budget that
    // name has already been explored with). A plain visited SET is unsound
    // here: a name first reached at depth 2 and cut off by the bound would
    // suppress the SAME name later reached at depth 0, where its subtree is
    // still in scope (SSA landed-diff round 3, RED-8).
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    resolves_to_presence(text, pats, rel, index, 0, &mut seen)
}

/// Follow the callees of `tokens` down the intra-crate call graph, at most
/// `MAX_HELPER_DEPTH` levels, looking for a path-existence call in a body.
/// `seen` breaks recursive/mutually-recursive helpers.
fn resolves_to_presence(
    tokens: &str,
    pats: &NoSkipsPatterns,
    rel: &str,
    index: &FnIndex,
    depth: usize,
    seen: &mut BTreeMap<String, usize>,
) -> bool {
    if depth >= MAX_HELPER_DEPTH {
        return false;
    }
    let remaining = MAX_HELPER_DEPTH - depth;
    for name in called_idents(tokens) {
        // Skip ONLY if this name was already explored with at least as much
        // budget as we have now. Re-explore when we arrive by a SHORTER path:
        // adding a candidate path must never remove exploration from another
        // (RED-8). Termination still holds — `remaining` strictly decreases,
        // so each name is re-entered at most MAX_HELPER_DEPTH times.
        match seen.get(&name) {
            Some(&best) if best >= remaining => continue,
            _ => {
                seen.insert(name.clone(), remaining);
            }
        }
        // CONSERVATIVE UNION over every definition site declaring this name:
        // an ambiguous callee is treated as a presence helper if ANY candidate
        // is one (RED-6). Picking one candidate — whichever the index happened
        // to store first — is what a same-named decoy exploited.
        for cand in index.candidates(rel, &name) {
            if pats
                .presence_body_calls
                .iter()
                .any(|p| cand.body.contains(p.as_str()))
            {
                return true;
            }
        }
        for cand in index.candidates(rel, &name) {
            if resolves_to_presence(&cand.body, pats, rel, index, depth + 1, seen) {
                return true;
            }
        }
    }
    false
}

/// Does this block contain a bare early return (`return;` / `return None;`)?
/// M9f/M9g: a preceding `assert!(true)` / `assert_eq!(1,1)` grants NO exemption —
/// the rule is about the return, not about what precedes it.
/// `continue_counts`: does a `continue` count as a silent exit here?
///
/// It does for a GUARDED skip — `if !fixture_present() { continue; }` inside a
/// loop over cases abandons exactly what the guard protected, which is the
/// same defect as `return` in a non-loop test (SSA landed-diff round 3, RED-8
/// ruling). It does NOT for a `let ... else { continue }` diverge branch,
/// which is the ordinary way a loop FILTERS its input: over the existing
/// corpus every such site is line/entry filtering, not a skipped assertion.
/// The exit form alone is not the property; where it sits is.
fn block_has_bare_exit(b: &Block, continue_counts: bool) -> Option<usize> {
    for stmt in &b.stmts {
        if let Some(l) = stmt_bare_exit(stmt, continue_counts) {
            return Some(l);
        }
    }
    None
}

fn stmt_bare_exit(stmt: &Stmt, continue_counts: bool) -> Option<usize> {
    let e = match stmt {
        Stmt::Expr(e, _) => e,
        _ => return None,
    };
    expr_bare_exit(e, continue_counts)
}

fn expr_bare_return(e: &Expr) -> Option<usize> {
    expr_bare_exit(e, false)
}

fn expr_bare_exit(e: &Expr, continue_counts: bool) -> Option<usize> {
    match e {
        Expr::Return(r) => {
            let line = r.return_token.span.start().line;
            match &r.expr {
                None => Some(line),
                Some(inner) => {
                    let t = expr_text(inner);
                    let t = t.replace(' ', "");
                    // `return None` / `return Ok(())` / `return Default::default()`
                    // are all indistinguishable-from-pass outcomes.
                    if t == "None" || t == "Ok(())" || t == "()" {
                        Some(line)
                    } else {
                        None
                    }
                }
            }
        }
        Expr::Block(b) => block_has_bare_exit(&b.block, continue_counts),
        // A guarded `continue` leaves the loop iteration exactly as a `return`
        // leaves the test: whatever the guard was protecting never runs
        // (SSA landed-diff round 3, RED-8 ruling — the exit FORM is not the
        // property; the unexecuted body is).
        //
        // `?` is NOT added here. A bare `expr?;` is the ordinary way ANY
        // fallible helper is called, guarded or not; treating it as a skip
        // exit produced 6 findings over the existing corpus, all of them
        // ordinary error propagation in `let ... else` diverge branches, and
        // none of them a guarded presence skip. Recognising it needs the
        // Option/Result distinction this AST-only lint does not have, so it
        // stays DISCLOSED-OPEN rather than silently over-firing.
        Expr::Continue(c) if continue_counts => Some(c.continue_token.span.start().line),
        _ => None,
    }
}

impl<'a> FnScan<'a> {
    fn check_skip_macro(&mut self, mac: &syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if !self.pats.skip_macros.contains(&name) {
            return;
        }
        let text = mac.tokens.to_string();
        if self.pats.skip_markers.iter().any(|m| text.contains(m.as_str())) {
            self.out.push(Finding {
                file: self.file.into(),
                line: mac.path.segments[0].ident.span().start().line,
                shape: 5,
                owner_fn: self.owner_fn.into(),
                what: format!("`{name}!` announces a SKIP inside a test/loader body"),
            });
        }
    }
}

impl<'ast, 'a> Visit<'ast> for FnScan<'a> {
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            // Shapes 1, 2, 3, 7 — a presence/precondition `if` guard whose body
            // returns without a distinguishable outcome.
            Expr::If(ifx) => {
                let cond = expr_text(&ifx.cond);
                if is_presence_condition(&cond, self.pats, self.file, self.index) {
                    if let Some(line) = block_has_bare_exit(&ifx.then_branch, true) {
                        let shape = if cond.contains("metadata") {
                            7
                        } else if cond.contains("is_err") || cond.contains("is_none") || cond.contains("is_ok") {
                            2
                        } else if cond.contains("exists") {
                            1
                        } else {
                            3
                        };
                        self.out.push(Finding {
                            file: self.file.into(),
                            line,
                            shape,
                            owner_fn: self.owner_fn.into(),
                            what: format!(
                                "precondition guard returns without a distinguishable outcome: `if {}`",
                                cond.trim()
                            ),
                        });
                    }
                }
            }
            // Shape 4 — `match … { None => return, … }` / `Err(_) => return`.
            Expr::Match(m) => {
                for arm in &m.arms {
                    let pat_txt = {
                        let p = &arm.pat;
                        quote::quote!(#p).to_string()
                    };
                    if pat_txt.contains("None") || pat_txt.starts_with("Err") {
                        if let Some(line) = expr_bare_exit(&arm.body, true) {
                            self.out.push(Finding {
                                file: self.file.into(),
                                line,
                                shape: 4,
                                owner_fn: self.owner_fn.into(),
                                what: format!(
                                    "match arm `{}` returns without a distinguishable outcome",
                                    pat_txt.trim()
                                ),
                            });
                        }
                    }
                }
            }
            // Shape 5 — a SKIP announcement inside a test/loader body.
            Expr::Macro(mac) => self.check_skip_macro(&mac.mac),
            _ => {}
        }
        syn::visit::visit_expr(self, e);
    }

    /// `eprintln!("SKIP …");` in STATEMENT position is a `Stmt::Macro`, not a
    /// `Stmt::Expr(Expr::Macro)` — `visit_expr` never sees it. Missing this is
    /// how the canonical shape-5 site (a SKIP print followed by a bare return)
    /// slipped past the first cut of this lint entirely, which is exactly what
    /// mutation M9a was written to catch.
    fn visit_stmt_macro(&mut self, sm: &'ast syn::StmtMacro) {
        self.check_skip_macro(&sm.mac);
        syn::visit::visit_stmt_macro(self, sm);
    }

    // Shape 6 — `let Ok(x) = … else { return; };`
    fn visit_local(&mut self, l: &'ast syn::Local) {
        if let Some(init) = &l.init {
            if let Some((_, div)) = &init.diverge {
                if let Some(line) = expr_bare_return(div) {
                    self.out.push(Finding {
                        file: self.file.into(),
                        line,
                        shape: 6,
                        owner_fn: self.owner_fn.into(),
                        what: "let-else diverge branch returns without a distinguishable outcome"
                            .into(),
                    });
                }
            }
        }
        syn::visit::visit_local(self, l);
    }
}

fn is_in_corpus(f: &ItemFn, pats: &NoSkipsPatterns) -> bool {
    let name = f.sig.ident.to_string();
    // Same test-attribute predicate `bindings` uses, so the two lints cannot
    // disagree about what a test is (RED-1).
    let is_test = f.attrs.iter().any(crate::is_test_attr);
    is_test || pats.loader_prefixes.iter().any(|p| name.starts_with(p.as_str()))
}

/// Scan one file. Returns the seven-shape findings plus bare-`#[ignore]` findings.
pub fn scan_file(
    rel: &str,
    text: &str,
    pats: &NoSkipsPatterns,
    index: &FnIndex,
) -> Result<Vec<Finding>, String> {
    let ast = syn::parse_file(text).map_err(|e| format!("{rel}: {e}"))?;
    let mut out = Vec::new();
    let mut fns: Vec<&ItemFn> = Vec::new();
    collect_fns(&ast.items, &mut fns);
    for f in &fns {
        // Bare `#[ignore]` — the narrow, separate rule. Applies to every fn in
        // the scanned corpus, not only to the seven shapes.
        for attr in &f.attrs {
            if attr.path().is_ident("ignore") && matches!(attr.meta, syn::Meta::Path(_)) {
                out.push(Finding {
                    file: rel.into(),
                    line: attr.pound_token.spans[0].start().line,
                    shape: 0,
                    owner_fn: f.sig.ident.to_string(),
                    what: format!("`#[ignore]` with no reason on `{}`", f.sig.ident),
                });
            }
        }
        if !is_in_corpus(f, pats) {
            continue;
        }
        let owner = f.sig.ident.to_string();
        let mut scan = FnScan { file: rel, owner_fn: &owner, pats, index, out: Vec::new() };
        scan.visit_block(&f.block);
        out.extend(scan.out);
    }
    // NO line-based deduplication (SSA landed-diff round 2, RED-5). Each
    // finding comes from a DISTINCT AST node; collapsing two of them because
    // they render on the same source line made an added unconditional skip
    // disappear the moment its enclosing function was reformatted onto one
    // line — the upstream site count then matched the baseline's `count` and
    // the stage passed. Source formatting is not a structural property. The
    // ordering below is likewise AST-derived (owner, shape, message), with the
    // reported line last and only for determinism of the printed list.
    out.sort_by(|a, b| {
        (&a.owner_fn, a.shape, &a.what, a.line).cmp(&(&b.owner_fn, b.shape, &b.what, b.line))
    });
    Ok(out)
}

/// Like `collect_fns`, but carrying each function's enclosing module path, so
/// the index is keyed by DEFINITION SITE rather than by bare name alone.
/// Every callable definition site, as `(module_path, name, body_tokens)`.
///
/// INHERENT and TRAIT-IMPL METHODS are indexed alongside free functions
/// (SSA landed-diff round 3, RED-8 ruling: the traversal must follow method
/// calls). They are keyed on the bare method NAME, under the enclosing
/// module path plus the impl's self type — a method call `h.m()` is resolved
/// to EVERY definition named `m`, the same conservative union RED-6 installed
/// for free functions. This over-approximates the receiver's type, which is
/// the safe direction: it can only add a candidate, never remove one.
/// `dyn Trait` dispatch through a trait OBJECT remains the disclosed gap.
fn collect_fns_scoped(items: &[syn::Item], prefix: &str, out: &mut Vec<(String, String, String)>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let b = &f.block;
                out.push((
                    prefix.to_string(),
                    f.sig.ident.to_string(),
                    quote::quote!(#b).to_string(),
                ));
            }
            syn::Item::Impl(i) => {
                let ty = &i.self_ty;
                let tyname = quote::quote!(#ty).to_string().replace(' ', "");
                let next = if prefix.is_empty() {
                    format!("impl {tyname}")
                } else {
                    format!("{prefix}::impl {tyname}")
                };
                for ii in &i.items {
                    if let syn::ImplItem::Fn(f) = ii {
                        let b = &f.block;
                        out.push((
                            next.clone(),
                            f.sig.ident.to_string(),
                            quote::quote!(#b).to_string(),
                        ));
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    let name = m.ident.to_string();
                    let next = if prefix.is_empty() {
                        name
                    } else {
                        format!("{prefix}::{name}")
                    };
                    collect_fns_scoped(inner, &next, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_fns<'a>(items: &'a [syn::Item], out: &mut Vec<&'a ItemFn>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => out.push(f),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_fns(inner, out);
                }
            }
            _ => {}
        }
    }
}

/// The scanned roots (brief §3 S4), derived from the tree.
pub fn scan_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![root.join("integration-tests").join("tests")];
    for (_, dir) in crate::census::canister_crates(root) {
        roots.push(dir.join("src"));
        roots.push(dir.join("tests"));
    }
    roots.retain(|p| p.is_dir());
    roots
}

/// Match the scanned findings against the committed baseline.
///
/// Split out of `main` so it has a retained fixture: this is the code SSA
/// landed-diff round 1 RED-2 walked through, and a rule with no test is a rule
/// that can regress silently.
///
/// `found` maps (file, owner_fn, shape) to that key's matching sites. Returns
/// (violations, suppressed-count).
pub fn apply_baseline(
    found: &BTreeMap<(String, String, u8), Vec<String>>,
    baseline: &crate::data::NoSkipsBaseline,
) -> (Vec<String>, usize) {
    let mut violations = Vec::new();
    let mut annotated: BTreeMap<(String, String, u8), usize> = Default::default();
    for s in &baseline.site {
        let key = (s.file.clone(), s.owner_fn.clone(), s.shape);
        if annotated.insert(key.clone(), s.count).is_some() {
            violations.push(format!(
                "{}: DUPLICATE baseline row for `{}` (shape {}) — one row per \
                 (file, owner_fn, shape), with `count` carrying the multiplicity",
                key.0, key.1, key.2
            ));
        }
    }
    let mut suppressed = 0usize;
    for (key, sites) in found {
        let Some(&allowed) = annotated.get(key) else {
            violations.extend(sites.iter().cloned());
            continue;
        };
        if sites.len() > allowed {
            // The baseline cannot say WHICH matching site is the new one — that
            // is the point. An exemption is granted to a COUNTED SET of sites,
            // never to a function name. Every matching site is printed so the
            // reviewer can see what changed.
            violations.push(format!(
                "{}: `{}` (shape {}) now has {} matching site(s) but \
                 scripts/gate_lints/no_skips_baseline.toml exempts only {} — {} NEW silent \
                 skip(s) in an already-annotated function. An exemption covers a COUNTED set \
                 of pre-existing sites, never the function. Fix the new site; do not raise \
                 `count`. All matching sites:\n    {}",
                key.0,
                key.1,
                key.2,
                sites.len(),
                allowed,
                sites.len() - allowed,
                sites.join("\n    ")
            ));
            suppressed += allowed;
        } else {
            if sites.len() < allowed {
                violations.push(format!(
                    "{}: baseline row for `{}` (shape {}) records `count = {}` but only {} \
                     site(s) match — some were fixed or renamed; RE-COUNT the row. A row that \
                     over-counts is standing amnesty for a site that no longer exists.",
                    key.0, key.1, key.2, allowed, sites.len()
                ));
            }
            suppressed += sites.len();
        }
    }
    // A baseline row whose site no longer exists is itself a finding: a stale
    // exemption is an exemption nobody is watching. This is what stops the
    // baseline becoming a permanent amnesty (invariant 4).
    for site in &baseline.site {
        let key = (site.file.clone(), site.owner_fn.clone(), site.shape);
        if !found.contains_key(&key) {
            violations.push(format!(
                "{}: baseline row for `{}` (shape {}) no longer matches any site — the site was \
                 fixed or renamed; DELETE the stale baseline row",
                site.file, site.owner_fn, site.shape
            ));
        }
        if site.reason.trim().is_empty() || site.owner.trim().is_empty() {
            violations.push(format!(
                "{}: baseline row for `{}` has an empty reason or owner",
                site.file, site.owner_fn
            ));
        }
        if site.count == 0 {
            violations.push(format!(
                "{}: baseline row for `{}` has `count = 0` — a row that exempts nothing is a \
                 row that should be deleted",
                site.file, site.owner_fn
            ));
        }
    }
    violations.sort();
    (violations, suppressed)
}
