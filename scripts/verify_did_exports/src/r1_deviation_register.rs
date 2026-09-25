// =============================================================================
// R-1 AC-15 — the ICRC deviation register lint.
// =============================================================================
//
// `canisters/token/NOTE_A-3_icrc_deviation.md` is a REGISTER, not a document.
// What makes it one is that both directions are enforced:
//
//   1. every `devNNN` tag cited anywhere under `canisters/` or
//      `integration-tests/` has an entry in the register, and
//   2. every entry's named binding test function actually exists in the file the
//      entry names.
//
// Renaming a bound test without updating the register is a RED (M15d). Deleting
// an entry whose tag is still cited in source is a RED (M15e). Without this
// lint, the register is a claim about the code rather than a check on it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn run(root: &Path) -> Result<(), String> {
    let register_path = root.join("canisters/token/NOTE_A-3_icrc_deviation.md");
    let text = std::fs::read_to_string(&register_path)
        .map_err(|e| format!("{}: cannot read the deviation register: {e}", register_path.display()))?;

    // Entries are `## devNNN — …` headings; bindings are the `- \`fn_name\` —
    // \`path\`` bullets that follow, up to the next heading.
    let mut entries: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut current: Option<String> = None;
    // A markdown bullet may wrap across lines, so bullets are accumulated and
    // flushed at the next bullet, heading, or blank line.
    let mut bullet = String::new();
    let flush = |bullet: &mut String,
                     current: &Option<String>,
                     entries: &mut BTreeMap<String, Vec<(String, String)>>| {
        if let (Some(tag), Some((f, p))) = (current.as_ref(), parse_binding(bullet)) {
            if let Some(v) = entries.get_mut(tag) {
                v.push((f, p));
            }
        }
        bullet.clear();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if line.starts_with("## ") || trimmed.starts_with("- ") || trimmed.is_empty() {
            flush(&mut bullet, &current, &mut entries);
        }
        if let Some(rest) = line.strip_prefix("## ") {
            let tag = rest.split_whitespace().next().unwrap_or("").to_string();
            if is_dev_tag(&tag) {
                entries.insert(tag.clone(), Vec::new());
                current = Some(tag);
            } else {
                current = None;
            }
            continue;
        }
        if trimmed.starts_with("- ") || (!bullet.is_empty() && line.starts_with("  ")) {
            if !bullet.is_empty() {
                bullet.push(' ');
            }
            bullet.push_str(trimmed);
        }
    }
    flush(&mut bullet, &current, &mut entries);
    if entries.is_empty() {
        return Err(format!(
            "{}: no `## devNNN` entries found. An empty register would vacuously \
             satisfy every citation.",
            register_path.display()
        ));
    }

    let mut findings: Vec<String> = Vec::new();

    // ── direction 1: every cited tag has an entry ────────────────────────────
    let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for dir in ["canisters", "integration-tests"] {
        collect_citations(&root.join(dir), root, &mut cited)?;
    }
    for (tag, where_) in &cited {
        if !entries.contains_key(tag) {
            findings.push(format!(
                "REGISTER: `{tag}` is cited in source ({}) but has no `## {tag}` entry \
                 in {}. A deviation the code names and the register does not is \
                 exactly the drift this file exists to prevent.",
                where_.iter().cloned().collect::<Vec<_>>().join(", "),
                register_path.display()
            ));
        }
    }

    // ── direction 2: every entry's named test exists ─────────────────────────
    for (tag, bindings) in &entries {
        if bindings.is_empty() {
            findings.push(format!(
                "REGISTER: entry `{tag}` names NO binding test. A row with no binding \
                 test is a claim, not a register entry."
            ));
            continue;
        }
        for (func, file) in bindings {
            let p = root.join(file);
            let Ok(src) = std::fs::read_to_string(&p) else {
                findings.push(format!(
                    "REGISTER: entry `{tag}` names {file}, which cannot be read."
                ));
                continue;
            };
            if !src.contains(&format!("fn {func}(")) {
                findings.push(format!(
                    "REGISTER: entry `{tag}` names binding test `{func}`, which does \
                     not exist in {file}. A renamed test with a stale register row is \
                     an unbound deviation."
                ));
            }
        }
    }

    if findings.is_empty() {
        println!(
            "  ICRC deviation register: OK — {} entries, {} binding tests, {} cited \
             tags, both directions.",
            entries.len(),
            entries.values().map(|v| v.len()).sum::<usize>(),
            cited.len()
        );
        Ok(())
    } else {
        Err(findings.join("\n"))
    }
}

fn is_dev_tag(s: &str) -> bool {
    s.len() == 6 && s.starts_with("dev") && s[3..].chars().all(|c| c.is_ascii_digit())
}

/// `- \`test_name\` — \`relative/path.rs\`` (the register's own bullet shape).
fn parse_binding(bullet: &str) -> Option<(String, String)> {
    let l = bullet.trim().strip_prefix("- ")?;
    // The two backtick-quoted spans of the bullet: the test function, then the
    // file that must contain it.
    let quoted: Vec<&str> = l.split('`').skip(1).step_by(2).collect();
    let func = quoted.first()?.trim().to_string();
    let file = quoted.get(1)?.trim().to_string();
    if !func.starts_with("test_") || !file.ends_with(".rs") {
        return None;
    }
    Some((func, file))
}

fn collect_citations(
    dir: &Path,
    root: &Path,
    out: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name == "target" || name == "node_modules" || name == ".git" {
                continue;
            }
            collect_citations(&p, root, out)?;
            continue;
        }
        match p.extension().and_then(|s| s.to_str()) {
            Some("rs") | Some("did") => {}
            _ => continue,
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .to_string();
        for tag in scan_tags(&text) {
            out.entry(tag).or_default().insert(rel.clone());
        }
    }
    Ok(())
}

/// Every `devNNN` occurrence, case-sensitive, three digits, not part of a longer
/// identifier tail (so `dev0060` is not read as `dev006`).
fn scan_tags(text: &str) -> BTreeSet<String> {
    let b = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i + 6 <= b.len() {
        if &b[i..i + 3] == b"dev"
            && b[i + 3].is_ascii_digit()
            && b[i + 4].is_ascii_digit()
            && b[i + 5].is_ascii_digit()
        {
            let after_ok = i + 6 >= b.len() || !(b[i + 6] as char).is_ascii_alphanumeric();
            let before_ok = i == 0 || !(b[i - 1] as char).is_ascii_alphanumeric();
            if after_ok && before_ok {
                out.insert(String::from_utf8_lossy(&b[i..i + 6]).to_string());
            }
        }
        i += 1;
    }
    out
}

/// Exposed for the fixture suite.
pub fn register_path(root: &Path) -> PathBuf {
    root.join("canisters/token/NOTE_A-3_icrc_deviation.md")
}
