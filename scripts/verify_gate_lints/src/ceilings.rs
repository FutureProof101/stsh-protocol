//! `refused-ceilings` (G-b) — every guarded production `#[update]` carries a
//! refused-call cycle ceiling registry row.
//!
//! THREE legs, all over the PRODUCTION view (never the testing view — a
//! cfg-excluded item ships in no production Wasm and cannot meaningfully carry
//! a ceiling):
//!   1. Marker path      — `// RATE-LIMITED` / `// FLOOR-GUARDED` on the fn.
//!   2. Structural path  — intra-crate call-graph walk, depth ≤ 3, over the
//!                         committed guard-shape patterns. A NET, not a
//!                         completeness proof.
//!   3. `.did` cross-check — every `.did` update-method NAME must appear in the
//!                         production-view found-fn name set, closing the
//!                         macro-alias gap the syntax walk cannot see.
//!
//! DISCLOSED GAP (DID-MODE-01): a method whose `.did` mode is `query` but whose
//! source attribute is `#[update]` (or vice versa) evades BOTH leg 3 and
//! `verify_did_exports` — `did_methods()` returns names only, discarding the
//! candid `Func` mode. That gap is its own campaign item; R-L discloses and
//! demonstrates it (AC-4f) and does not close it.

use std::collections::BTreeSet;
use std::path::Path;

use crate::census::{canister_crates, census_crate, Census, UpdateSite};
use crate::data::CeilingRegistry;
use crate::target_cfg::TargetAtoms;

pub struct CeilingOutcome {
    pub violations: Vec<String>,
    pub per_crate: Vec<(String, usize, usize)>, // crate, testing view, production view
    pub obligated: Vec<UpdateSite>,
}

/// Depth-≤3 intra-crate call-graph walk: does this endpoint reach a guard shape,
/// directly or through up to three levels of local helper?
fn reaches_guard(site: &UpdateSite, census: &Census, patterns: &[String]) -> bool {
    fn hits(text: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|p| text.contains(p.as_str()))
    }
    if hits(&site.body_tokens, patterns) {
        return true;
    }
    let mut frontier: Vec<String> = called_names(&site.body_tokens, census);
    let mut seen: BTreeSet<String> = frontier.iter().cloned().collect();
    for _depth in 0..3 {
        let mut next = Vec::new();
        for name in frontier.drain(..) {
            let Some(body) = census.helpers.get(&name) else { continue };
            if hits(body, patterns) {
                return true;
            }
            for c in called_names(body, census) {
                if seen.insert(c.clone()) {
                    next.push(c);
                }
            }
        }
        if next.is_empty() {
            return false;
        }
        frontier = next;
    }
    false
}

/// Names of local helpers this token stream calls. Token-level, over the set of
/// names the same `syn` walk already collected — never a free-text regex.
fn called_names(tokens: &str, census: &Census) -> Vec<String> {
    let mut out = Vec::new();
    for name in census.helpers.keys() {
        if tokens.contains(&format!("{name} (")) || tokens.contains(&format!("{name}(")) {
            out.push(name.clone());
        }
    }
    out
}

pub fn run(root: &Path, reg: &CeilingRegistry, target: &TargetAtoms) -> Result<CeilingOutcome, String> {
    let mut violations = Vec::new();
    let mut per_crate = Vec::new();
    let mut obligated = Vec::new();

    let rows_by_endpoint: BTreeSet<(String, String)> = reg
        .row
        .iter()
        .map(|r| (r.crate_name.clone(), r.endpoint.clone()))
        .collect();
    let unguarded: BTreeSet<(String, String)> = reg
        .unguarded
        .iter()
        .map(|r| (r.crate_name.clone(), r.endpoint.clone()))
        .collect();
    let did_excluded: BTreeSet<String> =
        reg.did_excluded.iter().map(|d| d.crate_name.clone()).collect();

    for (name, dir) in canister_crates(root) {
        let census = census_crate(&name, &dir, root, target).map_err(|e| e.to_string())?;
        per_crate.push((name.clone(), census.testing.len(), census.production.len()));

        // Legs 1 and 2 — the marker obligation over the PRODUCTION view.
        for site in &census.production {
            let marked = !site.markers.is_empty();
            let structural = reaches_guard(site, &census, &reg.structural_patterns);
            if !(marked || structural) {
                continue;
            }
            obligated.push(site.clone());
            let key = (name.clone(), site.fn_name.clone());
            if rows_by_endpoint.contains(&key) || unguarded.contains(&key) {
                continue;
            }
            violations.push(format!(
                "{}:{}: `{}` is a {} production `#[update]` with NO refused-call ceiling row \
                 (add a `[[row]]` with a measured ceiling, or an explicit `[[unguarded]]` row \
                 with a reason)",
                site.file.strip_prefix(root).unwrap_or(&site.file).display(),
                site.line,
                site.fn_name,
                if marked { "marked" } else { "structurally guarded" }
            ));
        }

        // Leg 3 — `.did` name-set cross-check.
        if did_excluded.contains(&name) {
            continue;
        }
        let prod_names = census.production_names();
        for did in did_paths(root, &name) {
            let Ok(text) = std::fs::read_to_string(&did) else { continue };
            for m in crate::did::update_methods(&text) {
                if !prod_names.contains(&m.name) {
                    violations.push(format!(
                        "unrecognised update attribute form: {} ({}:{})",
                        m.name,
                        did.strip_prefix(root).unwrap_or(&did).display(),
                        m.line
                    ));
                }
            }
        }
    }

    // Required rows. A registry you can satisfy by DELETING a row is not a
    // registry — the obligation would vanish with the evidence (M4).
    let have: BTreeSet<&str> = reg.row.iter().map(|r| r.id.as_str()).collect();
    for id in &reg.required_rows {
        if !have.contains(id.as_str()) {
            violations.push(format!(
                "required ceiling row `{id}` is missing from \
                 scripts/gate_lints/refused_call_ceilings.toml — deleting a row deletes the \
                 evidence, not the obligation"
            ));
        }
    }

    // Every row must name a REAL test. A ceiling nothing asserts is a number
    // in a file (the self-inherited-verification class, one step removed).
    let test_names = crate::claims::all_fn_names(root);
    for r in &reg.row {
        if r.test.trim().is_empty() {
            violations.push(format!("ceiling row `{}`: no `test` named", r.id));
        } else if !test_names.contains(&r.test) {
            violations.push(format!(
                "ceiling row `{}`: `test = \"{}\"` names no fn in the tree — the ceiling is \
                 asserted by nothing",
                r.id, r.test
            ));
        }
        if r.samples.len() < 3 {
            violations.push(format!(
                "ceiling row `{}`: {} sample(s) recorded — cycle deltas are noisy, so a pin \
                 needs at least three",
                r.id,
                r.samples.len()
            ));
        }
    }

    // Registry self-consistency: a ceiling must exceed its own measurement.
    for r in &reg.row {
        if r.ceiling_cycles <= r.measured_cycles {
            violations.push(format!(
                "ceiling row `{}`: ceiling_cycles ({}) must exceed measured_cycles ({}) — \
                 a ceiling at or below the measurement cannot bite",
                r.id, r.ceiling_cycles, r.measured_cycles
            ));
        }
    }

    per_crate.sort();
    Ok(CeilingOutcome { violations, per_crate, obligated })
}

/// The tracked `.did` files for a crate. Derived from the tree.
fn did_paths(root: &Path, crate_name: &str) -> Vec<std::path::PathBuf> {
    let snake = crate_name.replace('-', "_");
    let candidates = [
        root.join("canisters").join(crate_name).join(format!("{snake}.did")),
        root.join("canisters").join(crate_name).join(format!("{crate_name}.did")),
    ];
    let mut out: Vec<std::path::PathBuf> = candidates.into_iter().filter(|p| p.is_file()).collect();
    // Also any `.did` shipped anywhere inside the crate directory.
    let dir = root.join("canisters").join(crate_name);
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "did").unwrap_or(false) && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}
