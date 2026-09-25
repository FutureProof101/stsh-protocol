//! Committed lint data — patterns, corpus roots and registries are DATA,
//! reviewed as data (invariant 3), never inlined into the lint's logic.
//!
//! TCB residual #2 (brief §9): editing one of these files to remove a real
//! finding is a bypass whose control is the reviewed diff, not a second lint.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

pub fn load<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

// ── S1 claims ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Corpus {
    /// Directories scanned recursively.
    #[serde(default)]
    pub dirs: Vec<String>,
    /// Individual files.
    #[serde(default)]
    pub files: Vec<String>,
    /// Extensions scanned inside `dirs`.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Path fragments excluded from the scan.
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimsPatterns {
    /// A line matches if it contains a normative word AND a cost/rate word.
    pub normative: Vec<String>,
    pub cost_rate: Vec<String>,
    /// Substrings that discharge the marker obligation.
    pub measured_marker: String,
    pub unbacked_marker: String,
    /// Lines containing any of these are never claims (the lint's own data,
    /// pattern definitions, and prose that quotes the markers).
    #[serde(default)]
    pub ignore_lines_containing: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ClaimsBaseline {
    #[serde(default)]
    pub claim: Vec<BaselineClaim>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BaselineClaim {
    pub file: String,
    /// The claim's own text, whitespace-normalised. The baseline is keyed on
    /// (file, text) and NEVER on a line number: a line number moves the moment
    /// anything above it is edited, which would silently transfer an old row's
    /// annotation onto a newly-introduced claim.
    pub text: String,
    pub marker: String,
    /// For `MEASURED:` — the test name or path that backs it.
    #[serde(default)]
    pub referent: String,
    /// For `MEASURED:` — a CODE TOKEN of the referent that binds it to THIS
    /// claim. REQUIRED on every `MEASURED` row.
    ///
    /// `referent` alone proves only that a function of that name exists. It
    /// cannot distinguish "this test exists" from "this test measures this
    /// sentence", and lane R-11 found a live row where it did not (the vault
    /// history-depth clause pointed at an unrelated upgrade test, which the
    /// existence check passed).
    ///
    /// The token is an identifier ALREADY PRESENT in the referent's own code —
    /// a called fn, a const, a local, a field, or an endpoint name inside a
    /// string literal the referent's control flow uses. It is chosen by READING
    /// the referent, never written into it: this lane edits no canister source.
    /// `#[doc]` attributes are stripped before the referent's tokens are
    /// scanned, so a token that appears only in prose does not count.
    ///
    /// This is a RE-CHECKABLE LINK, not a proof of relevance. Semantic
    /// relevance cannot be decided by any depth of token presence; that gap is
    /// disclosed, not closed.
    #[serde(default)]
    pub property: Option<String>,
    /// For `UNBACKED:` — why. Never blank.
    #[serde(default)]
    pub reason: String,
}

// ── S2 refused-call ceilings ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CeilingRegistry {
    pub schema_version: u32,
    /// Row ids that MUST be present. Without this, deleting a row simply
    /// deletes the obligation — the lint would report zero findings for a
    /// registry that had lost half its ceilings. Mutation M4 exists to prove
    /// the deletion bites.
    #[serde(default)]
    pub required_rows: Vec<String>,
    #[serde(default)]
    pub row: Vec<CeilingRow>,
    /// Production-view `#[update]`s that carry NO guard and need none.
    #[serde(default)]
    pub unguarded: Vec<UnguardedRow>,
    /// `.did`-tracked crates. Derived from the tree; listed here only to record
    /// the ONE deliberate exclusion.
    #[serde(default)]
    pub did_excluded: Vec<DidExclusion>,
    #[serde(default)]
    pub structural_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CeilingRow {
    pub id: String,
    pub crate_name: String,
    pub endpoint: String,
    pub kind: String,
    pub measured_cycles: u64,
    pub ceiling_cycles: u64,
    #[serde(default)]
    pub samples: Vec<u64>,
    #[serde(default)]
    pub test: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UnguardedRow {
    pub crate_name: String,
    pub endpoint: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DidExclusion {
    pub crate_name: String,
    pub reason: String,
}

// ── S3 bindings ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BindingRegistry {
    pub schema_version: u32,
    pub posture: String,
    /// Binding ids that MUST be present. Same reasoning as the ceiling
    /// registry's `required_rows`: without it, `bindings` reports zero findings
    /// for a registry someone deleted a row from (mutation M7a).
    #[serde(default)]
    pub required_bindings: Vec<String>,
    #[serde(default)]
    pub binding: Vec<BindingRow>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BindingRow {
    pub id: String,
    pub property: String,
    pub status: String,
    /// The bound TEST — the permanent in-repo evidence. There is NO
    /// evidence-file field and no office hash, ever (AC-7g).
    pub bound: String,
    pub test_crate: String,
    pub test_file: String,
}

#[derive(Debug, Deserialize)]
pub struct BoundTestSuites {
    #[serde(default)]
    pub suite: Vec<BoundSuite>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BoundSuite {
    /// The crate name as it appears in the gate's invocation.
    pub crate_name: String,
    /// The invocation's word sequence, which must appear at COMMAND POSITION in
    /// a simple command of `run_gate.sh` (`shell_lex::census_invoked`), not
    /// merely as a literal substring of its bytes.
    pub gate_invocation: String,
}

// ── S4 no-skips ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct NoSkipsBaseline {
    #[serde(default)]
    pub site: Vec<NoSkipsBaselineSite>,
}

fn one() -> usize {
    1
}

#[derive(Debug, Deserialize, Clone)]
pub struct NoSkipsBaselineSite {
    pub file: String,
    pub owner_fn: String,
    pub shape: u8,
    /// HOW MANY sites of this shape the row exempts inside that function.
    ///
    /// (file, owner_fn, shape) alone is NOT a site identity: one test function
    /// can hold several findings of the same shape, and a row keyed without
    /// multiplicity silently extends its exemption to every future one. That
    /// is exactly the bypass SSA landed-diff round 1 RED-2 demonstrated —
    /// inserting a BRAND NEW unconditional `eprintln!("SKIP …"); return;` at the
    /// top of an already-exempted shape-5 function, and watching `no-skips`
    /// stay green while its suppressed tally quietly went 34 -> 35.
    ///
    /// The count is therefore EXACT in both directions: more matching sites
    /// than the row records is a new defect, fewer is a row that must be
    /// re-counted rather than left as standing amnesty for a site that no
    /// longer exists.
    #[serde(default = "one")]
    pub count: usize,
    /// Why this pre-existing site is annotated rather than converted, and WHO
    /// owns converting it. Never blank — an unexplained exemption is the thing
    /// this lint exists to stop.
    pub reason: String,
    pub owner: String,
}

#[derive(Debug, Deserialize)]
pub struct NoSkipsPatterns {
    pub presence_predicates: Vec<String>,
    /// Calls that, found anywhere in a resolved helper's BODY, make that helper
    /// a presence test — however it is named. See `no_skips::is_presence_condition`.
    pub presence_body_calls: Vec<String>,
    pub skip_macros: BTreeSet<String>,
    pub skip_markers: Vec<String>,
    pub loader_prefixes: Vec<String>,
}
