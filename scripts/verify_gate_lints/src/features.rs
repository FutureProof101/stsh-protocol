//! Default-feature closure resolution (brief §0's resolution rule, invariants
//! 11 and 12).
//!
//! The production feature set for crate C is C's resolved `default` closure,
//! READ FROM C's OWN `Cargo.toml` AT SCAN TIME. It is never a hardcoded
//! literal, and specifically never a hardcoded EMPTY literal — every canister
//! crate's closure happens to be empty at base, which is exactly the condition
//! under which a hardcoded `{}` and a real resolver are indistinguishable
//! (V9 RED-1). M2c-9/10/11/12/13/14 force the divergence.
//!
//! Resolution:
//!   1. Read `[features] default = [...]` (absent key ⇒ empty array).
//!   2. For each name: if it names another feature declared in the same
//!      `[features]` table, RECURSE into that feature's own array — transitive
//!      closure, cycle-safe (a visited feature is not re-expanded). A
//!      `dep:<crate>` or `<crate>?/<feature>` entry turns on no NAMED feature
//!      of C and is silently excluded from the closure — it is ordinary Cargo
//!      syntax, NOT a manifest defect, so it must not raise an error.
//!   3. The flattened set is C's default closure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug)]
pub enum FeatureError {
    Read(String),
    Parse(String),
    /// The `default`-on-`testing` guard: a crate that ships `testing` on by
    /// default is a manifest defect the lint refuses to evaluate past. Exit 2.
    /// Distinct from the unknown-atom exit — that is an unparseable predicate,
    /// this is a manifest shape.
    TestingIsDefault { crate_name: String },
}

impl std::fmt::Display for FeatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureError::Read(m) | FeatureError::Parse(m) => write!(f, "{m}"),
            FeatureError::TestingIsDefault { crate_name } => write!(
                f,
                "crate `{crate_name}`: \"testing\" is in default — a crate that ships the \
                 testing feature on by default has no distinguishable production view; \
                 refusing to evaluate either view for this crate"
            ),
        }
    }
}

/// The `[features]` table of one crate, as declared.
#[derive(Debug, Default, Clone)]
pub struct FeatureTable {
    pub declared: BTreeMap<String, Vec<String>>,
    pub has_default_key: bool,
}

pub fn read_feature_table(manifest: &Path) -> Result<FeatureTable, FeatureError> {
    let text = std::fs::read_to_string(manifest)
        .map_err(|e| FeatureError::Read(format!("{}: {e}", manifest.display())))?;
    let doc: toml::Value = toml::from_str(&text)
        .map_err(|e| FeatureError::Parse(format!("{}: {e}", manifest.display())))?;
    let mut table = FeatureTable::default();
    let Some(features) = doc.get("features").and_then(|v| v.as_table()) else {
        return Ok(table);
    };
    for (name, value) in features {
        let entries = value
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if name == "default" {
            table.has_default_key = true;
        }
        table.declared.insert(name.clone(), entries);
    }
    Ok(table)
}

/// Resolve the transitive `default` closure. Cycle-safe by visited-set: a
/// feature already in the closure is not re-expanded, so `default = ["a"]`,
/// `a = ["b"]`, `b = ["a"]` terminates with BOTH `a` and `b` true — a cycle is
/// valid, ordinary Cargo manifest shape, not a defect to refuse.
pub fn default_closure(table: &FeatureTable) -> BTreeSet<String> {
    let mut closure: BTreeSet<String> = BTreeSet::new();
    let Some(seeds) = table.declared.get("default") else {
        // Absent `default` key ⇒ empty closure. "Empty" is DERIVED here, from
        // the manifest, for this crate — it is not a constant standing in for
        // the computation.
        return closure;
    };
    let mut stack: Vec<String> = seeds.clone();
    while let Some(entry) = stack.pop() {
        // Cargo optional-dependency syntax. `dep:foo` and `foo?/bar` turn on no
        // named feature of this crate, so they carry no `cfg(feature = "…")`
        // atom this evaluator can match. Silently excluded — NOT an error.
        if entry.starts_with("dep:") || entry.contains("?/") {
            continue;
        }
        // `foo/bar` (non-optional dependency feature) likewise names a feature
        // of `foo`, not of this crate.
        if entry.contains('/') {
            continue;
        }
        if !closure.insert(entry.clone()) {
            continue; // already visited — cycle-safe termination
        }
        if let Some(children) = table.declared.get(&entry) {
            stack.extend(children.iter().cloned());
        }
    }
    closure
}

/// Full resolution with the `default`-on-`testing` guard applied.
pub fn production_features(
    crate_name: &str,
    manifest: &Path,
) -> Result<BTreeSet<String>, FeatureError> {
    let table = read_feature_table(manifest)?;
    let closure = default_closure(&table);
    if closure.contains("testing") {
        return Err(FeatureError::TestingIsDefault {
            crate_name: crate_name.to_string(),
        });
    }
    Ok(closure)
}
