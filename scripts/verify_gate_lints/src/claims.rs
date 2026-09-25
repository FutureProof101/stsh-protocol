//! `claims` (G-a) — every normative cost/rate claim in the governed corpus
//! carries a `MEASURED: <path-or-test-name>` or `UNBACKED: <reason>` marker.
//!
//! AMBER-1 (brief §2), stated honestly and not papered over: the AUTOMATED
//! guarantee is marker presence plus REFERENT EXISTENCE. It is not, and does
//! not claim to be, a proof that the referent's measurement is true or that it
//! measures the specific attached claim. That is AC-3's M3b human sample.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::data::{ClaimsBaseline, ClaimsPatterns, Corpus};

#[derive(Debug, Clone)]
pub struct Hit {
    pub file: String,
    pub line: usize,
    pub text: String,
    pub marker: Option<Marker>,
}

#[derive(Debug, Clone)]
pub enum Marker {
    Measured(String),
    Unbacked(String),
}

pub fn corpus_files(root: &Path, corpus: &Corpus) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for f in &corpus.files {
        let p = root.join(f);
        if p.is_file() {
            out.push(p);
        }
    }
    for d in &corpus.dirs {
        let dir = root.join(d);
        let mut stack = vec![dir];
        while let Some(cur) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&cur) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Some(ext) = p.extension().and_then(|x| x.to_str()) {
                    if corpus.extensions.iter().any(|w| w == ext) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out.retain(|p| {
        let s = p.to_string_lossy().to_string();
        !corpus.exclude.iter().any(|x| s.contains(x.as_str()))
    });
    out.sort();
    out.dedup();
    out
}

/// A hit is a line carrying BOTH a normative word and a cost/rate word.
pub fn scan_text(rel: &str, text: &str, pats: &ClaimsPatterns) -> Vec<Hit> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if pats
            .ignore_lines_containing
            .iter()
            .any(|x| line.contains(x.as_str()))
        {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let normative = pats.normative.iter().any(|w| word_contains(&lower, w));
        if !normative {
            continue;
        }
        let costly = pats.cost_rate.iter().any(|w| word_contains(&lower, w));
        if !costly {
            continue;
        }
        // The marker may sit on the claim line itself or within the two lines
        // above or below it (a wrapped comment block).
        let lo = i.saturating_sub(2);
        let hi = (i + 3).min(lines.len());
        let window = lines[lo..hi].join("\n");
        let marker = extract_marker(&window, pats);
        out.push(Hit {
            file: rel.to_string(),
            line: i + 1,
            text: line.to_string(),
            marker,
        });
    }
    out
}

fn extract_marker(window: &str, pats: &ClaimsPatterns) -> Option<Marker> {
    if let Some(idx) = window.find(&pats.measured_marker) {
        let rest = window[idx + pats.measured_marker.len()..]
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        return Some(Marker::Measured(rest));
    }
    if let Some(idx) = window.find(&pats.unbacked_marker) {
        let rest = window[idx + pats.unbacked_marker.len()..]
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        return Some(Marker::Unbacked(rest));
    }
    None
}

/// Referent existence: a `MEASURED:` referent must name a real file in the tree
/// or a real `#[test]`/`fn` name somewhere in the tree.
pub fn referent_exists(root: &Path, referent: &str, test_names: &BTreeSet<String>) -> bool {
    let r = referent.trim().trim_end_matches(&['.', ','][..]);
    if r.is_empty() {
        return false;
    }
    // Take the first whitespace-delimited token — the referent proper.
    let token = r.split_whitespace().next().unwrap_or(r);
    let token = token.trim_matches(|c: char| c == '`' || c == '(' || c == ')');
    if token.contains('/') || token.contains('.') {
        let base = token.split(':').next().unwrap_or(token);
        if root.join(base).exists() {
            return true;
        }
    }
    test_names.contains(token)
}

/// Every `fn` name in the tree (tests included) — the referent name universe.
pub fn all_fn_names(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut roots = vec![root.join("integration-tests"), root.join("canisters"), root.join("scripts")];
    roots.retain(|p| p.is_dir());
    for r in roots {
        for f in crate::census::rust_files(&r) {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            for line in text.lines() {
                let t = line.trim();
                let t = t.strip_prefix("pub ").unwrap_or(t);
                let t = t.strip_prefix("async ").unwrap_or(t);
                if let Some(rest) = t.strip_prefix("fn ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        out.insert(name);
                    }
                }
            }
        }
    }
    out
}

/// Every `fn` in the tree, name -> its own RENDERED TOKEN STREAM with `#[doc]`
/// attributes stripped.
///
/// This is the universe the `property` check reads. It is deliberately NOT the
/// raw file text: a token that appears only in a doc comment above the function
/// is prose, not code, and prose is exactly what a claim marker is supposed to
/// be backed against rather than matched to. `syn` drops `//` comments outright
/// and `scope::strip_doc_attrs_*` removes the `///`/`#[doc]` ones.
///
/// Names collide (a `fn run` exists many times over). A colliding name's token
/// streams are concatenated, which makes the check PERMISSIVE in the same
/// direction everything else in this lint is: a `property` present in any
/// same-named function passes. That is honest — `referent` names a function by
/// NAME and nothing else, so the check can be no sharper than the key it is
/// given.
pub fn fn_code_tokens(root: &Path) -> std::collections::BTreeMap<String, String> {
    let mut out: std::collections::BTreeMap<String, String> = Default::default();
    let mut roots = vec![
        root.join("integration-tests"),
        root.join("canisters"),
        root.join("scripts"),
    ];
    roots.retain(|p| p.is_dir());
    for r in roots {
        for f in crate::census::rust_files(&r) {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            let Ok(ast) = syn::parse_file(&text) else { continue };
            collect_fn_tokens(&ast.items, &mut out);
        }
    }
    out
}

fn push_tokens(out: &mut std::collections::BTreeMap<String, String>, name: String, toks: String) {
    out.entry(name).or_default().push_str(&toks);
}

fn collect_fn_tokens(
    items: &[syn::Item],
    out: &mut std::collections::BTreeMap<String, String>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let mut f = f.clone();
                crate::scope::strip_doc_attrs_fn(&mut f);
                let name = f.sig.ident.to_string();
                push_tokens(out, name, quote::quote!(#f).to_string());
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_fn_tokens(inner, out);
                }
            }
            syn::Item::Impl(im) => {
                for ii in &im.items {
                    if let syn::ImplItem::Fn(m) = ii {
                        let mut m = m.clone();
                        crate::scope::strip_doc_attrs_impl_fn(&mut m);
                        let name = m.sig.ident.to_string();
                        push_tokens(out, name, quote::quote!(#m).to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Case-SENSITIVE whole-identifier presence. `word_contains` lower-cases both
/// sides, which is right for prose and wrong for a code token: it would let
/// `max_upgrade_scan` stand in for `MAX_UPGRADE_SCAN`.
pub fn ident_present(haystack: &str, needle: &str) -> bool {
    let n = needle.trim();
    if n.is_empty() {
        return false;
    }
    let hb = haystack.as_bytes();
    let nb = n.as_bytes();
    let boundary = |c: u8| !(c.is_ascii_alphanumeric() || c == b'_');
    let mut i = 0usize;
    while i + nb.len() <= hb.len() {
        if &hb[i..i + nb.len()] == nb {
            let left_ok = i == 0 || boundary(hb[i - 1]);
            let j = i + nb.len();
            let right_ok = j == hb.len() || boundary(hb[j]);
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Is `property` present in `referent`'s own code tokens?
///
/// `None` means the referent could not be resolved to code at all — the
/// referent-existence check owns that finding, and reporting it twice would
/// make one defect look like two.
pub fn property_in_referent(
    root: &Path,
    referent: &str,
    property: &str,
    fn_tokens: &std::collections::BTreeMap<String, String>,
) -> Option<bool> {
    let r = referent.trim().trim_end_matches(&['.', ','][..]);
    let token = r.split_whitespace().next().unwrap_or(r);
    let token = token.trim_matches(|c: char| c == '`' || c == '(' || c == ')');
    if let Some(toks) = fn_tokens.get(token) {
        return Some(ident_present(toks, property));
    }
    if token.contains('/') || token.contains('.') {
        let base = token.split(':').next().unwrap_or(token);
        if let Ok(text) = std::fs::read_to_string(root.join(base)) {
            return Some(ident_present(&text, property));
        }
    }
    None
}

pub struct ClaimsOutcome {
    pub hits: Vec<Hit>,
    pub violations: Vec<String>,
    pub baseline_discharged: usize,
}

/// Substring match at WORD BOUNDARIES. A raw `contains` matched "cycle" inside
/// "recycle" and "lifecycle", which turned every `// NEVER RECYCLE` MemoryId
/// banner in the tree into a "normative cost claim" — 30-odd false positives
/// from one missing boundary check.
pub fn word_contains(haystack: &str, needle: &str) -> bool {
    let n = needle.to_ascii_lowercase();
    let n = n.trim();
    if n.is_empty() {
        return false;
    }
    let hb = haystack.as_bytes();
    let nb = n.as_bytes();
    let boundary = |c: u8| !(c.is_ascii_alphanumeric() || c == b'_');
    let mut i = 0usize;
    while i + nb.len() <= hb.len() {
        if &hb[i..i + nb.len()] == nb {
            let left_ok = i == 0 || boundary(hb[i - 1]);
            let j = i + nb.len();
            let right_ok = j == hb.len() || boundary(hb[j]);
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Whitespace-normalised claim text — the baseline's stable key.
pub fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn run(
    root: &Path,
    corpus: &Corpus,
    pats: &ClaimsPatterns,
    baseline: &ClaimsBaseline,
) -> ClaimsOutcome {
    let mut hits = Vec::new();
    for f in corpus_files(root, corpus) {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
        hits.extend(scan_text(&rel, &text, pats));
    }
    let names = all_fn_names(root);
    // The referent's own code tokens, for the `property` check. Built once.
    let fn_tokens = fn_code_tokens(root);
    // The baseline annotates the FIXED tree's hits, keyed on (file, normalised
    // text). It discharges an EXISTING claim's marker obligation and nothing
    // else: a new or edited claim matches no row and must carry an in-source
    // marker. It never grants cover to a hit that is not already on it.
    let mut annotated: std::collections::BTreeMap<(String, String), &crate::data::BaselineClaim> =
        Default::default();
    for c in &baseline.claim {
        annotated.insert((c.file.clone(), norm(&c.text)), c);
    }
    let mut matched: std::collections::BTreeSet<(String, String)> = Default::default();
    let mut violations = Vec::new();
    let mut baseline_discharged = 0usize;
    for h in &hits {
        let key = (h.file.clone(), norm(&h.text));
        if h.marker.is_none() {
            if let Some(row) = annotated.get(&key) {
                matched.insert(key.clone());
                baseline_discharged += 1;
                match row.marker.as_str() {
                    "MEASURED" => {
                        if !referent_exists(root, &row.referent, &names) {
                            violations.push(format!(
                                "{}:{}: baseline MEASURED referent `{}` names no file and no fn \
                                 in the tree",
                                h.file, h.line, row.referent
                            ));
                        }
                        // A `property` is REQUIRED on every MEASURED row, and
                        // must be a code token of the referent itself. Existence
                        // of a fn by that name is not evidence it measures this
                        // sentence; the token is the re-checkable link between
                        // the two. It closes nothing about semantic relevance —
                        // that gap cannot be closed by construction — but it
                        // makes a re-pointed row cost a read of the referent.
                        let prop = row.property.as_deref().unwrap_or("").trim().to_string();
                        if prop.is_empty() {
                            violations.push(format!(
                                "{}:{}: baseline MEASURED row for referent `{}` carries no \
                                 `property` — every MEASURED row must name a code token of its \
                                 referent that binds it to THIS claim; referent existence alone \
                                 cannot tell \"this test exists\" from \"this test measures this \
                                 sentence\"",
                                h.file, h.line, row.referent
                            ));
                        } else if prop == row.referent.trim() {
                            violations.push(format!(
                                "{}:{}: baseline MEASURED row's `property` is the referent's own \
                                 name `{}` — that is the existence check restated, not a link to \
                                 what the referent measures. Name a token INSIDE the referent.",
                                h.file, h.line, prop
                            ));
                        } else {
                            match property_in_referent(root, &row.referent, &prop, &fn_tokens) {
                                Some(true) => {}
                                Some(false) => violations.push(format!(
                                    "{}:{}: baseline MEASURED row names `property` = `{}`, which \
                                     is ABSENT from referent `{}`'s own code tokens (doc comments \
                                     stripped) — the property must be an identifier the referent \
                                     genuinely uses, read out of it, never written into it",
                                    h.file, h.line, prop, row.referent
                                )),
                                // Unresolvable referent: already reported above.
                                None => {}
                            }
                        }
                    }
                    "UNBACKED" => {
                        if row.reason.trim().is_empty() {
                            violations.push(format!(
                                "{}:{}: baseline UNBACKED row has no reason",
                                h.file, h.line
                            ));
                        }
                    }
                    other => violations.push(format!(
                        "{}:{}: baseline row has marker `{other}` (expected MEASURED or UNBACKED)",
                        h.file, h.line
                    )),
                }
                continue;
            }
        }
        match &h.marker {
            None => violations.push(format!(
                "{}:{}: normative cost/rate claim with no `{}` or `{}` marker — {}",
                h.file, h.line, pats.measured_marker, pats.unbacked_marker, h.text
            )),
            Some(Marker::Measured(referent)) => {
                if !referent_exists(root, referent, &names) {
                    violations.push(format!(
                        "{}:{}: dangling `{}` referent `{}` — names no file and no fn in the tree",
                        h.file, h.line, pats.measured_marker, referent
                    ));
                }
            }
            Some(Marker::Unbacked(reason)) => {
                if reason.trim().is_empty() {
                    violations.push(format!(
                        "{}:{}: `{}` with no reason",
                        h.file, h.line, pats.unbacked_marker
                    ));
                }
            }
        }
    }
    // A baseline row that matches nothing is a STALE annotation — the claim was
    // rewritten or deleted, and an annotation nobody is watching is exactly the
    // amnesty this lint exists to prevent. It is a finding, not a shrug.
    for c in &baseline.claim {
        let key = (c.file.clone(), norm(&c.text));
        if !matched.contains(&key) {
            violations.push(format!(
                "{}: stale baseline row — no current hit matches this claim text; DELETE the row \
                 (or re-annotate the rewritten claim): {}",
                c.file,
                c.text.chars().take(90).collect::<String>()
            ));
        }
    }
    ClaimsOutcome { hits, violations, baseline_discharged }
}
