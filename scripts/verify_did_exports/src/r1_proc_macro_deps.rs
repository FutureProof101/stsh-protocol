// =============================================================================
// R-1 S4(b3-direct) + S4(b3-transitive) — the proc-macro dependency-identity
// allowlists, split by EDGE.
// =============================================================================
//
// The supply-chain boundary a source-occurrence lint definitionally cannot reach:
// an identifier a proc-macro crate assembles inside its OWN already-compiled code
// never exists as text in any file rustc reads for `stsh_token`, so no census,
// however complete, contains it. The control is therefore WHICH proc-macro crates,
// at which exact pinned bytes, the token crate depends on at all — and, separately,
// which of them it reaches DIRECTLY rather than only transitively, because
// promoting an already-allowlisted transitive package to a direct edge changes
// nothing a single set comparison can see, yet changes everything about what the
// crate's own source may legally name.
//
// Both files are PURE ALLOWLISTS: set comparisons against reviewed data, both
// directions. Neither carries a name-based policy step (V13 fix, CTO ruling item
// 1) — the refusal to INVOKE a denylisted crate lives entirely in the belt
// (r1_ledger_boundary), which consults neither of these files.
//
// A resolved package with a `path`/`git` source and therefore NO `Cargo.lock`
// checksum is an UNCONDITIONAL finding regardless of allowlist membership: that
// is the `evil_macro` shape.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AllowFile {
    #[serde(default, rename = "crate")]
    krate: Vec<AllowRow>,
}

#[derive(Debug, Deserialize)]
struct AllowRow {
    name: String,
    version: String,
    checksum: String,
}

type Triple = (String, String, String);

pub fn run(root: &Path) -> Result<(), String> {
    let meta = metadata(root)?;
    let lock = lock_checksums(root)?;

    let (direct_ids, all_ids, pkgs) = resolve(&meta)?;

    let mut findings: Vec<String> = Vec::new();

    let direct = triples(&direct_ids, &pkgs, &lock, &mut findings);
    let transitive_ids: BTreeSet<String> = all_ids.difference(&direct_ids).cloned().collect();
    let transitive = triples(&transitive_ids, &pkgs, &lock, &mut findings);

    compare(
        "DIRECT",
        &direct,
        &load(root, "canisters/token/proc_macro_allowlist_direct.toml")?,
        "canisters/token/proc_macro_allowlist_direct.toml",
        &mut findings,
    );
    compare(
        "TRANSITIVE",
        &transitive,
        &load(root, "canisters/token/proc_macro_allowlist_transitive.toml")?,
        "canisters/token/proc_macro_allowlist_transitive.toml",
        &mut findings,
    );

    // The two files must PARTITION the resolved set: no overlap, no gap.
    let d_names: BTreeSet<&String> = direct.iter().map(|(n, _, _)| n).collect();
    let t_names: BTreeSet<&String> = transitive.iter().map(|(n, _, _)| n).collect();
    for n in d_names.intersection(&t_names) {
        findings.push(format!(
            "PARTITION: `{n}` appears in BOTH the direct and transitive sets. The two \
             allowlists must partition the resolved set exactly once each."
        ));
    }

    if findings.is_empty() {
        println!(
            "  proc-macro allowlists: OK — {} direct + {} transitive = {} resolved \
             proc-macro packages, pinned by name + version + Cargo.lock checksum.",
            direct.len(),
            transitive.len(),
            direct.len() + transitive.len()
        );
        Ok(())
    } else {
        Err(findings.join("\n"))
    }
}

fn compare(
    view: &str,
    actual: &BTreeSet<Triple>,
    allowed: &BTreeSet<Triple>,
    file: &str,
    findings: &mut Vec<String>,
) {
    for t in actual.difference(allowed) {
        let same_name: Vec<&Triple> = allowed.iter().filter(|(n, _, _)| *n == t.0).collect();
        if let Some(a) = same_name.first() {
            if a.1 != t.1 {
                findings.push(format!(
                    "{view}: `{}` resolves at version {} but {file} pins {}.",
                    t.0, t.1, a.1
                ));
            } else {
                findings.push(format!(
                    "{view}: `{} {}` resolves with Cargo.lock checksum {} but {file} \
                     pins {}. The bytes are not the reviewed bytes.",
                    t.0, t.1, t.2, a.2
                ));
            }
        } else {
            findings.push(format!(
                "{view}: `{} {}` is a resolved proc-macro dependency with NO row in \
                 {file}. An unreviewed proc-macro crate can synthesize any identifier \
                 it likes into this crate.",
                t.0, t.1
            ));
        }
    }
    for t in allowed.difference(actual) {
        if actual.iter().any(|(n, _, _)| *n == t.0) {
            continue; // already reported as a version/checksum mismatch above
        }
        findings.push(format!(
            "{view}: {file} carries a row for `{} {}` that matches no resolved \
             {view} proc-macro dependency. A stale allowlist row hides what is \
             actually in the build.",
            t.0, t.1
        ));
    }
}

fn triples(
    ids: &BTreeSet<String>,
    pkgs: &BTreeMap<String, (String, String, bool, bool)>,
    lock: &BTreeMap<(String, String), String>,
    findings: &mut Vec<String>,
) -> BTreeSet<Triple> {
    let mut out = BTreeSet::new();
    for id in ids {
        let (name, version, is_pm, registry) = pkgs.get(id).cloned().unwrap();
        if !is_pm {
            continue;
        }
        if !registry {
            findings.push(format!(
                "UNCONDITIONAL: proc-macro crate `{name} {version}` has a path/git \
                 source and therefore NO Cargo.lock checksum. There is nothing to pin \
                 it against; this is refused regardless of allowlist membership."
            ));
            continue;
        }
        match lock.get(&(name.clone(), version.clone())) {
            Some(c) => {
                out.insert((name, version, c.clone()));
            }
            None => findings.push(format!(
                "UNCONDITIONAL: proc-macro crate `{name} {version}` has no `checksum` \
                 entry in Cargo.lock."
            )),
        }
    }
    out
}

fn load(root: &Path, rel: &str) -> Result<BTreeSet<Triple>, String> {
    let p = root.join(rel);
    let raw = std::fs::read_to_string(&p)
        .map_err(|e| format!("{}: cannot read allowlist: {e}", p.display()))?;
    let parsed: AllowFile = toml::from_str(&raw)
        .map_err(|e| format!("{}: malformed allowlist TOML: {e}", p.display()))?;
    let mut out = BTreeSet::new();
    for r in parsed.krate {
        if r.name.is_empty() || r.version.is_empty() || r.checksum.is_empty() {
            return Err(format!(
                "{}: row `{}` is missing a required field (name, version, checksum are \
                 all required).",
                p.display(),
                r.name
            ));
        }
        out.insert((r.name, r.version, r.checksum));
    }
    Ok(out)
}

fn metadata(root: &Path) -> Result<serde_json::Value, String> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--offline", "--locked"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata failed to start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata --format-version 1 --offline --locked FAILED:\n{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata is not JSON: {e}"))
}

type Pkgs = BTreeMap<String, (String, String, bool, bool)>;

/// Returns `(direct proc-macro-or-not ids, full reachable ids, package table)`.
/// The package table value is `(name, version, is_proc_macro, has_registry_source)`.
fn resolve(meta: &serde_json::Value) -> Result<(BTreeSet<String>, BTreeSet<String>, Pkgs), String> {
    let mut pkgs: Pkgs = BTreeMap::new();
    for p in meta["packages"].as_array().ok_or("metadata: no packages")? {
        let id = p["id"].as_str().unwrap_or_default().to_string();
        let name = p["name"].as_str().unwrap_or_default().to_string();
        let version = p["version"].as_str().unwrap_or_default().to_string();
        let is_pm = p["targets"]
            .as_array()
            .map(|ts| {
                ts.iter().any(|t| {
                    t["kind"]
                        .as_array()
                        .map(|k| k.len() == 1 && k[0] == "proc-macro")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        let registry = p["source"].as_str().unwrap_or("").starts_with("registry+");
        pkgs.insert(id, (name, version, is_pm, registry));
    }

    let nodes: BTreeMap<String, &serde_json::Value> = meta["resolve"]["nodes"]
        .as_array()
        .ok_or("metadata: no resolve.nodes")?
        .iter()
        .map(|n| (n["id"].as_str().unwrap_or_default().to_string(), n))
        .collect();

    let token = pkgs
        .iter()
        .find(|(_, (n, ..))| n == "stsh_token")
        .map(|(id, _)| id.clone())
        .ok_or("metadata: stsh_token is not in the resolve graph")?;

    let edge_ok = |d: &serde_json::Value| -> bool {
        d["dep_kinds"]
            .as_array()
            .map(|ks| {
                ks.iter().any(|k| {
                    let kind = k["kind"].as_str();
                    kind.is_none() || kind == Some("build")
                })
            })
            .unwrap_or(false)
    };

    let mut direct = BTreeSet::new();
    for d in nodes[&token]["deps"].as_array().unwrap_or(&vec![]) {
        if edge_ok(d) {
            direct.insert(d["pkg"].as_str().unwrap_or_default().to_string());
        }
    }

    let mut all = BTreeSet::new();
    let mut stack = vec![token.clone()];
    while let Some(c) = stack.pop() {
        let Some(node) = nodes.get(&c) else { continue };
        for d in node["deps"].as_array().unwrap_or(&vec![]) {
            if !edge_ok(d) {
                continue;
            }
            let id = d["pkg"].as_str().unwrap_or_default().to_string();
            if all.insert(id.clone()) {
                stack.push(id);
            }
        }
    }

    Ok((direct, all, pkgs))
}

fn lock_checksums(root: &Path) -> Result<BTreeMap<(String, String), String>, String> {
    let p = root.join("Cargo.lock");
    let raw = std::fs::read_to_string(&p)
        .map_err(|e| format!("{}: cannot read: {e}", p.display()))?;
    let v: toml::Value = toml::from_str(&raw)
        .map_err(|e| format!("{}: malformed Cargo.lock: {e}", p.display()))?;
    let mut out = BTreeMap::new();
    if let Some(list) = v.get("package").and_then(|p| p.as_array()) {
        for p in list {
            let (Some(n), Some(ver)) = (
                p.get("name").and_then(|x| x.as_str()),
                p.get("version").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            if let Some(c) = p.get("checksum").and_then(|x| x.as_str()) {
                out.insert((n.to_string(), ver.to_string()), c.to_string());
            }
        }
    }
    Ok(out)
}
