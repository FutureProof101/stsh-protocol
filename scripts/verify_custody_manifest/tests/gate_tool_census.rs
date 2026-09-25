// ─────────────────────────────────────────────────────────────────────────────
// R-3b — GATE TOOL CENSUS FIXTURE  (campaign §5 G-e)
//
// Proves, against the LIVE `run_gate.sh` and the LIVE tree, that every tracked
// entry directly under `scripts/` is either invoked by the gate in a form whose
// failure actually aborts it, or is declared, with a reason and an owner, as
// deliberately not.
//
// Everything here is located BY CONTENT. Nothing is keyed to a line number and
// nothing is pasted: each check re-reads `run_gate.sh` and re-derives what it
// asserts, so the fixture stays true as the gate's own text changes and goes
// RED — loudly, naming which predicate fired — when it stops being true.
//
// Five predicates gate `invoked_by_gate = true`, deliberately disjoint so a
// failure message can say which layer broke:
//
//   (e) invocation grammar       — the line identifies the tool
//   (f) call-site blocking form  — its failure reaches a terminator
//   (g) terminator body          — that terminator actually exits nonzero
//   (h) command resolution       — it does so unshadowably (`builtin exit N`)
//   (i) process environment      — nothing imported from a parent shell is in
//                                  scope when any of the above runs
//
// Each was added because the layer above it was proven insufficient on its own:
// naming a tool is not invoking it; invoking it is not blocking on it; a call
// site that names `die` is not a call site that exits, if `die`'s body changed;
// a body that reads `exit 1` is not an exit, if a shell function named `exit`
// shadows the builtin; and no grammar over this file's text can see a function
// the PARENT process exported before bash read line 1.
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── locating the tree ────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    // scripts/verify_custody_manifest → scripts → root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives at <root>/scripts/verify_custody_manifest")
        .to_path_buf()
}

fn gate_text() -> String {
    let p = repo_root().join("run_gate.sh");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("run_gate.sh must be readable at {}: {e}", p.display()))
}

fn census_text() -> String {
    let p = repo_root().join("scripts/GATE_TOOL_CENSUS.toml");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("GATE_TOOL_CENSUS.toml must be readable at {}: {e}", p.display()))
}

// ── the census, as data ──────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct Census {
    #[allow(dead_code)]
    schema_version: u32,
    #[serde(rename = "entry")]
    entries: Vec<Entry>,
}

#[derive(Debug, serde::Deserialize)]
struct Entry {
    path: String,
    shape: String,
    kind: String,
    #[allow(dead_code)]
    rule: String,
    invoked_by_gate: bool,
    owner: String,
    reason: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    via: Vec<Via>,
}

#[derive(Debug, serde::Deserialize)]
struct Via {
    /// Every one of these substrings must appear on ONE physical line of
    /// `run_gate.sh`. This LOCATES a candidate; it does not credit it — the
    /// located line must then independently satisfy grammars (e) and (f).
    anchor: Vec<String>,
    /// The token by which grammar (e) step 3 resolves the tool's identity.
    tool_token: String,
    /// "a" (guarded `if !`) or "b" (inline `||`).
    form: String,
    /// "die" or "verdict_fail".
    terminator: String,
}

fn census() -> Census {
    toml::from_str(&census_text()).expect("GATE_TOOL_CENSUS.toml must parse")
}

// ── small shell-text helpers ─────────────────────────────────────────────────

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Whitespace/`;`-separated words, with the shell's own punctuation split off
/// so `die"x"` and `;die` both tokenise to a bare `die`.
fn words(line: &str) -> Vec<String> {
    line.split(|c: char| c.is_whitespace() || c == ';' || c == '{' || c == '}' || c == '&')
        .map(|w| w.trim().to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

/// The part of a line before any `#` that starts a comment (crude but adequate:
/// `run_gate.sh` has no `#` inside a command word on any invocation line, and
/// the census's own anchors would stop matching if that ever changed).
fn code_part(line: &str) -> &str {
    match line.find(" #") {
        Some(i) if !line[..i].contains('"') => &line[..i],
        _ => line,
    }
}

/// True if `line` (a bare `if`/`fi`-bearing line) opens an `if` block.
fn opens_if(line: &str) -> bool {
    let w = words(code_part(line));
    !w.is_empty() && w[0] == "if"
}

fn closes_if(line: &str) -> bool {
    let w = words(code_part(line));
    w.iter().any(|t| t == "fi")
}

// ── grammar (e): invocation ──────────────────────────────────────────────────

/// Apply the five-step invocation grammar to one physical line.
///
/// A line survives only if, after stripping an optional leading `if !`/`if`/`!`
/// and an optional `$(`, its command word is one of the recognised forms AND the
/// tool's identity is resolvable from a token on that SAME line. A comment, a
/// variable ASSIGNMENT, a mention inside a `die` message, or an `npm run` line
/// whose script body reaches the tool only through a hook is not an invocation.
fn satisfies_invocation_grammar(line: &str, tool_token: &str) -> Result<(), String> {
    if is_comment(line) {
        return Err("the matched line is a COMMENT — a mention is not an invocation".into());
    }
    let mut t = line.trim_start().to_string();

    // step 1: strip an optional leading `if !` / `if` / `!`
    for lead in ["if ! ", "if !", "if ", "! "] {
        if t.starts_with(lead) {
            t = t[lead.len()..].trim_start().to_string();
            break;
        }
    }
    // step 2: strip an optional `$(`
    if let Some(rest) = t.strip_prefix("$(") {
        t = rest.trim_start().to_string();
    }

    // A variable ASSIGNMENT is never an invocation (`CANDID_TOOL="…/Cargo.toml"`).
    let first = words(&t).first().cloned().unwrap_or_default();
    if first.contains('=') && !first.starts_with('-') {
        return Err(format!(
            "the matched line is a variable ASSIGNMENT (`{first}`), not an invocation"
        ));
    }

    // step 3a: recognised command word.
    let ok_cmd = t.starts_with("cargo run")
        || t.starts_with("cargo test")
        || first == "bash"
        || first == "sh"
        || first == "node"
        || first == "npx"
        || first.starts_with("./")
        || (first.starts_with("\"$") && first.ends_with('"'));
    if !ok_cmd {
        return Err(format!(
            "command word `{first}` is not one of cargo/bash/sh/node/npx/./…/\"$VAR\" — \
             the line does not invoke anything (prose, or a mention inside a message string)"
        ));
    }

    // An `npm run` line never resolves to a tool reached through a hook.
    if t.starts_with("npm run") {
        return Err(
            "an `npm run` line is NEVER gate-invocation evidence for a tool reached through a \
             pre/post hook — `ignore-scripts` suppresses hooks invisibly"
                .into(),
        );
    }

    // step 3b: the tool's identity must be resolvable from a token on this line.
    if !t.contains(tool_token) {
        return Err(format!(
            "the line does not carry the identifying token `{tool_token}` \
             (-p <crate>, --bin <name>, --manifest-path …/<dir>/Cargo.toml, or the tool's own path)"
        ));
    }
    Ok(())
}

// ── grammar (f): blocking form + disqualifiers ───────────────────────────────

/// Constant-false / dead-code wrappers, scanning OUTWARD from `idx` to the
/// nearest enclosing construct. A match withholds credit no matter how correct
/// the inner line's own text is.
fn disqualified(lines: &[&str], idx: usize) -> Option<String> {
    // heredoc-comment: `: <<'EOF' … EOF` containing the line
    let mut i = idx;
    loop {
        let l = lines[i].trim_start();
        if l.starts_with(": <<") {
            let tag = l
                .trim_start_matches(": <<")
                .trim_matches(|c| c == '\'' || c == '"' || c == '-')
                .trim()
                .to_string();
            if !tag.is_empty() && lines[i..idx].iter().all(|x| x.trim() != tag) {
                return Some(format!(
                    "the invocation sits inside a `: <<{tag}` heredoc-comment — it is text, not code"
                ));
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    // nearest enclosing `if`, walking backwards by if/fi depth
    let mut depth = 0i32;
    let mut j = idx;
    while j > 0 {
        j -= 1;
        let l = lines[j];
        if is_comment(l) {
            continue;
        }
        if closes_if(l) {
            depth += 1;
        }
        if opens_if(l) {
            if depth == 0 {
                let cond = code_part(l).trim();
                for bad in ["if false", "if 0", "if [ 0 ]", "if [[ 0 ]]"] {
                    if cond.starts_with(bad) {
                        return Some(format!(
                            "the invocation is nested inside a constant-false wrapper (`{bad}`) — \
                             it is present in the file and never executed"
                        ));
                    }
                }
                return None;
            }
            depth -= 1;
        }
    }
    None
}

/// Form (b): the terminator is the immediate right-hand operand of `||` on the
/// SAME physical line. `<inv> || { echo …; die …; }` counts (the terminator is
/// still what failure reaches); `|| true`, `|| echo`, `; true` do not.
fn blocking_form_b(line: &str, terminator: &str) -> Result<(), String> {
    let code = code_part(line);
    let Some(pos) = code.find("||") else {
        return Err("form (b) requires `||` on the invocation's own physical line; none found".into());
    };
    let rhs = &code[pos + 2..];
    let rhs_words = words(rhs);
    let Some(first) = rhs_words.first() else {
        return Err("nothing follows `||` on this line".into());
    };
    // Allow only a `{ …; die …; }` group between `||` and the terminator.
    let reaches = first == terminator
        || (code[pos..].contains('{') && rhs_words.iter().any(|w| w == terminator));
    if !reaches {
        return Err(format!(
            "the right-hand operand of `||` is `{first}`, not `{terminator}` — the stage swallows \
             its own failure (this is the `|| true` defeat: the invocation text is intact and the \
             gate no longer fails on it)"
        ));
    }
    Ok(())
}

/// Form (a): `if ! <invocation>` (with `; then` here or `then` next), and a
/// `die`/`verdict_fail` reachable as a BARE COMMAND on the invocation's own
/// failure path — inside the `if !`'s then-block, at its own nesting level, not
/// under a second nested condition, not in a comment, not inside a string.
///
/// The matching `fi` is found by if/fi DEPTH, never by searching forward for the
/// next `die` textually: a terminator belonging to a different, later block must
/// never be credited to this invocation.
fn blocking_form_a(lines: &[&str], idx: usize, terminator: &str) -> Result<(), String> {
    let head = lines[idx].trim_start();
    if !(head.starts_with("if !") || head.starts_with("if !")) {
        return Err(format!(
            "form (a) requires the invocation line to begin `if !`; it begins `{}`",
            head.chars().take(24).collect::<String>()
        ));
    }
    let has_then = code_part(lines[idx]).contains("; then")
        || lines
            .get(idx + 1)
            .map(|l| words(l).first().map(|w| w == "then").unwrap_or(false))
            .unwrap_or(false);
    if !has_then {
        return Err("form (a) requires `; then` on the `if !` line or `then` on the next".into());
    }

    let mut depth = 1i32; // we are inside this `if`
    let mut nested = 0i32; // nesting BELOW the then-block
    for l in &lines[idx + 1..] {
        if is_comment(l) {
            continue;
        }
        let c = code_part(l);
        if closes_if(c) {
            depth -= 1;
            if depth == 0 {
                break;
            }
            nested -= 1;
            continue;
        }
        if opens_if(c) {
            depth += 1;
            nested += 1;
            continue;
        }
        if nested == 0 {
            // a bare command word, not a token inside a string literal
            let before_quote = c.split('"').next().unwrap_or("");
            if words(before_quote).iter().any(|w| w == terminator) {
                return Ok(());
            }
        }
    }
    Err(format!(
        "no `{terminator}` is reachable as a bare command on this invocation's OWN failure path \
         inside the matching `fi` (this is the deleted-terminator defeat: the `if !`/`fi` shell and \
         the invocation line are intact and nothing aborts)"
    ))
}

// ── terminator bodies: extraction, (g) structural, (g)/(h) behavioural ───────

/// Extract a function body by BRACE DEPTH from the first `^name() {` — never a
/// fixed line range, so a future multi-line rewrite does not break extraction.
fn extract_body(gate: &str, name: &str) -> String {
    let head = format!("{name}() {{");
    let start = gate
        .find(&head)
        .unwrap_or_else(|| panic!("run_gate.sh must define `{name}()` (searched for `{head}`)"));
    let open = start + head.len() - 1;
    let bytes: Vec<char> = gate[open..].chars().collect();
    let mut depth = 0i32;
    let mut out = String::new();
    for ch in bytes {
        out.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return out;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces extracting `{name}` from run_gate.sh")
}

const CONTROL_KEYWORDS: [&str; 6] = ["if", "case", "while", "for", "until", "elif"];

/// Grammar (g) structural + (h) Grammar-h1, over the extracted body TEXT.
fn terminator_structure(body: &str, name: &str) -> Result<(), String> {
    let w = words(body);
    if w.iter().any(|t| t == "return") {
        return Err(format!(
            "`{name}`'s body contains `return`. A `return` stops the FUNCTION, not the script — \
             `{name}` is called as a bare command, so the failing stage would silently resume"
        ));
    }
    // Grammar-h1: the terminating statement is literally `builtin exit <nonzero>`.
    let mut found = false;
    for i in 0..w.len() {
        if w[i] == "exit" {
            let n: i64 = w
                .get(i + 1)
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| format!("`{name}`: `exit` without a literal integer status"))?;
            if n == 0 {
                return Err(format!("`{name}`'s body exits ZERO — it does not terminate anything"));
            }
            if i == 0 || w[i - 1] != "builtin" {
                return Err(format!(
                    "`{name}`'s terminating statement is bare `exit {n}`, not `builtin exit {n}` \
                     (Grammar-h1). Bash resolves a shell FUNCTION ahead of a builtin of the same \
                     name, so a function named `exit` in scope would make this return with $? == 0 \
                     and turn every `|| {name}` in the gate fail-open — while this very body still \
                     read `exit {n}` verbatim"
                ));
            }
            found = true;
        }
    }
    if !found {
        return Err(format!("`{name}`'s body contains no `builtin exit <nonzero>` at all"));
    }
    // "reachable on every path", conservatively: an unconditional body. A
    // terminator with ANY branching construct cannot be shown to exit on every
    // path by inspection, and neither base terminator has one — so a body that
    // grows one (e.g. the dead-branch `if false; then exit 1; fi` defeat) is
    // refused rather than adjudicated.
    if let Some(k) = w.iter().find(|t| CONTROL_KEYWORDS.contains(&t.as_str())) {
        return Err(format!(
            "`{name}`'s body contains the control keyword `{k}`, so its `exit` is CONDITIONAL. A \
             conditional exit is not a guarantee — this is the dead-branch defeat, where the \
             `exit` token stays present in the text and executes on no path"
        ));
    }
    Ok(())
}

/// Grammar (g) behavioural + (h) Behavioral-h: run the LIVE extracted body,
/// twice — Pass A with no shadow, Pass B with `exit(){ :; }` deliberately
/// defined in the SAME shell BEFORE the body — and assert nonzero both times.
///
/// The MARKER after the call is what distinguishes a hard `exit` from a
/// `return`: with a real exit the marker never prints; with a `return` it does,
/// proving the calling stage would have resumed as if nothing failed.
fn terminator_behaviour(body: &str, name: &str, shadow: bool) -> Result<(), String> {
    let pass = if shadow { "B (shadow PRESENT)" } else { "A (shadow absent)" };
    let shadow_src = if shadow {
        // defined BEFORE the body, in the same shell — a sibling subshell would
        // not do: bash function definitions do not cross subshell boundaries.
        "exit() { :; }\nbuiltin export -f exit 2>/dev/null || true\n"
    } else {
        ""
    };
    let script = format!(
        "set +o posix\nunset -f exit builtin 2>/dev/null || true\n\
         RED=''; BOLD=''; RESET=''; GREEN=''; YELLOW=''\n\
         {shadow_src}{name}() {body}\n\
         ( {name} \"probe\" >/dev/null 2>&1; echo MARKER_REACHED )\n"
    );
    let out = Command::new("/bin/bash")
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("bash must be runnable");
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.contains("MARKER_REACHED") {
        return Err(format!(
            "`{name}` Pass {pass}: the marker after the call PRINTED — the body did not terminate \
             its shell. A caller would have resumed past the failure as if nothing happened."
        ));
    }
    Ok(())
}

// ── Grammar-h2: whole-file ban list ──────────────────────────────────────────

fn ban_list(gate: &str) -> Result<(), String> {
    let mut def_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for line in gate.lines() {
        if is_comment(line) {
            continue;
        }
        let c = code_part(line);
        let t = c.trim_start();
        for name in ["exit", "builtin", "die", "verdict_fail"] {
            if t.starts_with(&format!("{name}()")) || t.starts_with(&format!("{name} ()")) {
                *def_counts.entry(name).or_insert(0) += 1;
            }
            if t.starts_with(&format!("alias {name}=")) {
                return Err(format!(
                    "run_gate.sh defines an ALIAS named `{name}` — it can intercept the token the \
                     terminators depend on"
                ));
            }
        }
        for banned in ["enable -n exit", "enable -n builtin"] {
            if c.contains(banned) {
                return Err(format!(
                    "run_gate.sh contains `{banned}` — disabling the builtin makes even a correct \
                     `builtin exit 1` resolve to something else"
                ));
            }
        }
        // A trap that VISIBLY reassigns the final status.
        if t.starts_with("trap ") {
            let body: String = c.chars().collect();
            if (body.contains("exit ") && !body.contains("exit \"$?\"")) || body.contains("return ")
            {
                return Err(format!(
                    "run_gate.sh has a trap that calls exit/return with an argument, overwriting \
                     whatever status fired it: {}",
                    t.trim()
                ));
            }
        }
    }
    for name in ["exit", "builtin"] {
        if def_counts.get(name).copied().unwrap_or(0) > 0 {
            return Err(format!(
                "run_gate.sh defines a shell FUNCTION named `{name}`. Bash resolves a function \
                 ahead of a builtin of the same name, so this reopens the exact command-resolution \
                 hole `builtin exit` closes — one level up in the case of `builtin`"
            ));
        }
    }
    for name in ["die", "verdict_fail"] {
        let n = def_counts.get(name).copied().unwrap_or(0);
        if n != 1 {
            return Err(format!(
                "run_gate.sh has {n} definitions of `{name}`; exactly ONE canonical definition is \
                 allowed. A second definition later in the file silently shadows the first at every \
                 subsequent call site, while extraction — which keys on the FIRST match — would \
                 never see it"
            ));
        }
    }
    Ok(())
}

// ── Grammar-i1 / i2: the self-sanitising preamble ────────────────────────────

/// The eight names, exhaustive, in BOTH directions (§2.8 Ruling-2).
const ALLOWLIST: [&str; 7] = [
    "CARGO_HOME", "HOME", "PATH", "PWD", "RUSTUP_HOME", "SHLVL", "_",
];

/// The preamble's statements: everything from the first non-comment,
/// non-shebang line up to and including the `builtin unset` that closes it.
fn preamble_statements(gate: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = gate.lines();
    // shebang
    let _ = it.next();
    for line in it {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            if out.is_empty() {
                continue;
            }
        }
        if !t.is_empty() && !t.starts_with('#') {
            out.push(line.to_string());
        }
        if t.starts_with("builtin unset __stsh_gate") {
            break;
        }
        if !out.is_empty() && out.len() > 40 {
            break;
        }
    }
    out
}

// ═════════════════════════ THE TESTS ═════════════════════════════════════════

// ── (a)–(d) completeness ─────────────────────────────────────────────────────

const TOOL_EXTENSIONS: [&str; 5] = ["sh", "mjs", "js", "ts", "py"];

fn tracked(pathspec: &str) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .arg("ls-files")
        .arg(pathspec)
        .output()
        .expect("git ls-files must run");
    assert!(out.status.success(), "git ls-files {pathspec} failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect()
}

fn has_shebang(rel: &str) -> bool {
    std::fs::read_to_string(repo_root().join(rel))
        .map(|s| s.starts_with("#!"))
        .unwrap_or(false)
}

#[test]
fn census_is_complete_over_every_tracked_scripts_entry() {
    let c = census();
    let rows: BTreeMap<&str, &Entry> = c.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    assert_eq!(rows.len(), c.entries.len(), "duplicate census row path");

    // Direct entries only: the first path segment under scripts/.
    let mut direct: BTreeSet<String> = BTreeSet::new();
    for f in tracked("scripts/") {
        let rest = f.strip_prefix("scripts/").expect("under scripts/");
        direct.insert(rest.split('/').next().unwrap().to_string());
    }
    assert!(!direct.is_empty(), "git ls-files scripts/ returned nothing");

    // Every in-scope entry has a row — NO exclusion by shape.
    for e in &direct {
        assert!(
            rows.contains_key(e.as_str()),
            "scripts/{e} is a tracked direct entry with NO census row. Every file and every \
             directory under scripts/ needs one — including data, which must be named as some \
             tool's consumed data. Add a row to scripts/GATE_TOOL_CENSUS.toml."
        );
    }
    // Every row points at something that still exists.
    for (p, _) in &rows {
        assert!(
            direct.contains(*p),
            "census row `{p}` names a path that is no longer a tracked direct entry under \
             scripts/ — a stale row is a claim about a tool that is not there"
        );
    }

    for e in &c.entries {
        let full = repo_root().join("scripts").join(&e.path);
        let is_dir = full.is_dir();
        // (a)/(c) directory rows
        if is_dir {
            let nested = tracked(&format!("scripts/{}/", e.path));
            let crate_dir = nested.iter().any(|f| f.ends_with("/Cargo.toml"));
            if crate_dir {
                assert_eq!(e.shape, "crate", "scripts/{} contains a Cargo.toml → rule (a) crate", e.path);
            } else {
                assert_eq!(e.shape, "dir", "scripts/{} has no Cargo.toml → rule (c) uncrated dir", e.path);
                let has_tool = nested.iter().any(|f| {
                    TOOL_EXTENSIONS.iter().any(|x| f.ends_with(&format!(".{x}"))) || has_shebang(f)
                });
                // R-L post-merge rebase: an uncrated directory under scripts/ is
                // not necessarily a TOOL directory. scripts/gate_lints/ is pure
                // committed DATA — the four lint stages' pattern files, baselines
                // and registries — with no Cargo.toml, no tool extension and no
                // shebang anywhere under it. The original rule had no such case
                // and asserted every dir row was a tool row, so the honest fix is
                // to admit the data shape rather than to weaken the tool bar.
                //
                // The rule keeps its force in BOTH directions and cannot be used
                // to hide a check the gate does not run:
                //   * a directory that DOES contain a tool file must still be
                //     kind = "tool", and must still name it;
                //   * a directory claiming kind = "data" must contain NO tool
                //     file at all, and its `reason` must name a tool that itself
                //     has a census row — so the data cannot be orphaned either.
                if has_tool {
                    assert_eq!(
                        e.kind, "tool",
                        "scripts/{} contains a nested tool file, so its row cannot claim kind = \
                         \"data\" — that is exactly the evasion this census exists to stop",
                        e.path
                    );
                } else {
                    assert_eq!(
                        e.kind, "data",
                        "census row for the directory scripts/{} points at NO nested tool file, so \
                         it cannot be a tool row — a directory-shaped tool row must name a real \
                         tool, not an empty claim. If it is committed data, say so with \
                         kind = \"data\" and name its consuming tool in `reason`.",
                        e.path
                    );
                    assert!(
                        !e.invoked_by_gate,
                        "scripts/{} is a data directory and cannot be `invoked_by_gate`",
                        e.path
                    );
                    let named = c.entries.iter().any(|other| {
                        other.path != e.path
                            && other.kind == "tool"
                            && e.reason.contains(&other.path)
                    });
                    assert!(
                        named,
                        "the data directory scripts/{}'s `reason` names no tool that has a census \
                         row of its own — data must be named as some tool's consumed data",
                        e.path
                    );
                }
                continue;
            }
            assert_eq!(e.kind, "tool", "a crate directory row is always a tool row");
            continue;
        }
        // (b)/(d) file rows
        let rel = format!("scripts/{}", e.path);
        let ext = e.path.rsplit('.').next().unwrap_or("");
        let referenced = {
            let mut hay = gate_text();
            hay.push_str(&std::fs::read_to_string(repo_root().join("justfile")).unwrap_or_default());
            for pj in tracked("*package.json") {
                hay.push_str(&std::fs::read_to_string(repo_root().join(&pj)).unwrap_or_default());
            }
            ["node ", "npx ", "bash ", "sh ", "python3 ", "tsx "]
                .iter()
                .any(|cmd| {
                    hay.lines().any(|l| {
                        l.contains(cmd) && l.contains(&e.path) && !is_comment(l)
                    })
                })
        };
        let is_tool = has_shebang(&rel) || TOOL_EXTENSIONS.contains(&ext) || referenced;
        let expected = if is_tool { "tool" } else { "data" };
        assert_eq!(
            e.kind, expected,
            "scripts/{} classifies as `{expected}` under the rule-(b) DISJUNCTION (shebang OR \
             extension in {TOOL_EXTENSIONS:?} OR referenced as a node/npx/bash/sh/python3/tsx \
             argument), but the census calls it `{}`. The executable bit is deliberately NOT a \
             criterion — a mode-100644 file with a matching extension is still a tool.",
            e.path, e.kind
        );
        // rule (d): a data file is only excluded from needing its own tool
        // treatment if some tool row names it.
        if e.kind == "data" {
            let named = c.entries.iter().any(|o| {
                o.kind == "tool" && (o.note.contains(&e.path) || o.reason.contains(&e.path))
            });
            assert!(
                named,
                "scripts/{} is data that NO tool row names as its consumed data — an orphan data \
                 file is a file nothing accounts for",
                e.path
            );
        }
    }
}

#[test]
fn every_uninvoked_row_carries_a_reason_and_an_owner() {
    for e in census().entries {
        if e.invoked_by_gate {
            assert!(!e.via.is_empty(), "row `{}` claims invocation with no `via`", e.path);
            continue;
        }
        assert!(
            !e.reason.trim().is_empty() && !e.owner.trim().is_empty(),
            "row `{}` is NOT invoked by the gate and must state a reason AND an owning lane — \
             \"nobody runs it and nobody owns it\" is the exact state this census exists to make \
             impossible to reach silently",
            e.path
        );
    }
}

// ── (e) invocation grammar ───────────────────────────────────────────────────

fn locate<'a>(lines: &[&'a str], via: &Via, path: &str) -> usize {
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| via.anchor.iter().all(|a| l.contains(a.as_str())) && !is_comment(l))
        .map(|(i, _)| i)
        .collect();
    assert!(
        !hits.is_empty(),
        "PREDICATE (e) FAILED for census row `{path}`: NO line of the live run_gate.sh carries \
         all of {:?}. The census claims this tool is invoked by the gate and the gate does not \
         invoke it — either the stage was deleted, or the invocation was reworded and the census \
         was not.",
        via.anchor
    );
    hits[0]
}

#[test]
fn invoked_rows_satisfy_the_invocation_grammar() {
    let gate = gate_text();
    let lines: Vec<&str> = gate.lines().collect();
    for e in census().entries.iter().filter(|e| e.invoked_by_gate) {
        for via in &e.via {
            let i = locate(&lines, via, &e.path);
            satisfies_invocation_grammar(lines[i], &via.tool_token).unwrap_or_else(|why| {
                panic!(
                    "PREDICATE (e) FAILED for census row `{}`, line:\n    {}\n  {why}",
                    e.path,
                    lines[i].trim()
                )
            });
        }
    }
}

#[test]
fn the_grammar_rejects_the_known_non_invocations() {
    // NEGATIVE controls: shapes that exist in the live file and must NOT be
    // credited. A grammar that only ever says yes proves nothing.
    let gate = gate_text();
    let assignment = gate
        .lines()
        .find(|l| l.trim_start().starts_with("CANDID_TOOL="))
        .expect("run_gate.sh still assigns CANDID_TOOL");
    assert!(
        satisfies_invocation_grammar(assignment, "verify_did_exports").is_err(),
        "the assignment `{}` must NOT count as an invocation",
        assignment.trim()
    );

    let comment = gate
        .lines()
        .find(|l| is_comment(l) && l.contains("embed_candid_metadata.sh"))
        .expect("run_gate.sh still names embed_candid_metadata.sh in a comment");
    assert!(
        satisfies_invocation_grammar(comment, "embed_candid_metadata.sh").is_err(),
        "a prose COMMENT naming a tool must NOT count as an invocation"
    );

    let npm_build = gate
        .lines()
        .find(|l| l.trim_start().starts_with("npm run --prefix wallet build "))
        .expect("run_gate.sh still runs the wallet build");
    assert!(
        satisfies_invocation_grammar(npm_build, "verify_spend_artifacts.mjs").is_err(),
        "`npm run --prefix wallet build` must NEVER resolve to verify_spend_artifacts.mjs — the \
         prebuild HOOK is not gate-invocation evidence, resolved or not"
    );

    let die_msg = gate
        .lines()
        .find(|l| l.contains("die \"verify_spend_artifacts.mjs failed"))
        .map(|l| l[l.find("|| die").unwrap() + 3..].to_string())
        .expect("the new stage's die message names the tool");
    assert!(
        satisfies_invocation_grammar(&die_msg, "verify_spend_artifacts.mjs").is_err(),
        "a tool named inside a die MESSAGE STRING must NOT count as an invocation"
    );
}

// ── (f) blocking form ────────────────────────────────────────────────────────

#[test]
fn invoked_rows_satisfy_the_blocking_form_grammar() {
    let gate = gate_text();
    let lines: Vec<&str> = gate.lines().collect();
    for e in census().entries.iter().filter(|e| e.invoked_by_gate) {
        for via in &e.via {
            let i = locate(&lines, via, &e.path);
            if let Some(why) = disqualified(&lines, i) {
                panic!(
                    "PREDICATE (f) FAILED (DISQUALIFIER) for census row `{}`, line:\n    {}\n  {why}",
                    e.path,
                    lines[i].trim()
                );
            }
            let r = match via.form.as_str() {
                "a" => blocking_form_a(&lines, i, &via.terminator),
                "b" => blocking_form_b(lines[i], &via.terminator),
                other => panic!("census row `{}`: unknown blocking form `{other}`", e.path),
            };
            r.unwrap_or_else(|why| {
                panic!(
                    "PREDICATE (f) FAILED for census row `{}`, form ({}), line:\n    {}\n  {why}",
                    e.path,
                    via.form,
                    lines[i].trim()
                )
            });
        }
    }
}

// ── (g) terminator body ──────────────────────────────────────────────────────

fn cited_terminators() -> BTreeSet<String> {
    census()
        .entries
        .iter()
        .filter(|e| e.invoked_by_gate)
        .flat_map(|e| e.via.iter().map(|v| v.terminator.clone()))
        .collect()
}

fn rows_citing(t: &str) -> Vec<String> {
    census()
        .entries
        .iter()
        .filter(|e| e.invoked_by_gate && e.via.iter().any(|v| v.terminator == t))
        .map(|e| e.path.clone())
        .collect()
}

#[test]
fn terminator_bodies_are_structurally_sound() {
    let gate = gate_text();
    for t in cited_terminators() {
        let body = extract_body(&gate, &t);
        terminator_structure(&body, &t).unwrap_or_else(|why| {
            panic!(
                "PREDICATE (g)/(h)-h1 FAILED for terminator `{t}`.\n  {why}\n  Rows that lose \
                 `invoked_by_gate = true` as a result: {:?}",
                rows_citing(&t)
            )
        });
    }
}

#[test]
fn terminator_bodies_actually_exit_nonzero_pass_a_shadow_absent() {
    let gate = gate_text();
    for t in cited_terminators() {
        let body = extract_body(&gate, &t);
        terminator_behaviour(&body, &t, false).unwrap_or_else(|why| {
            panic!(
                "PREDICATE (g) BEHAVIOURAL Pass A FAILED for `{t}`.\n  {why}\n  Rows affected: {:?}",
                rows_citing(&t)
            )
        });
    }
}

#[test]
fn terminator_bodies_survive_a_live_exit_shadow_pass_b() {
    // Pass B is not scaffolding. It is the acceptance evidence that
    // `builtin exit` closes the command-resolution gap: the shadow that defeats
    // a bare `exit 1` is deliberately re-created, in the SAME shell, BEFORE the
    // body, and the terminator must still terminate.
    let gate = gate_text();
    for t in cited_terminators() {
        let body = extract_body(&gate, &t);
        terminator_behaviour(&body, &t, true).unwrap_or_else(|why| {
            panic!(
                "PREDICATE (h) BEHAVIOURAL Pass B FAILED for `{t}`.\n  {why}\n  A shell function \
                 named `exit` intercepted the terminator — the fix has regressed to bare `exit`. \
                 Rows affected: {:?}",
                rows_citing(&t)
            )
        });
    }
}

#[test]
fn pass_b_can_actually_distinguish_a_bare_exit_harness_self_check() {
    // If Pass B degenerated to Pass A — the shadow defined in a sibling shell,
    // or after the body — it would pass a bare `exit 1` and prove nothing. So
    // run Pass B against a DELIBERATELY UNFIXED body and require it to FAIL.
    let unfixed = "{ echo; exit 1; }";
    assert!(
        terminator_behaviour(unfixed, "probe", true).is_err(),
        "Pass B passed a body that terminates with BARE `exit 1` under a live `exit` shadow. The \
         harness is not exercising the shadow — it has degenerated into a second Pass A and can \
         no longer distinguish `builtin exit` from `exit`."
    );
    assert!(
        terminator_behaviour(unfixed, "probe", false).is_ok(),
        "Pass A must still accept a bare `exit 1` — that is precisely why Pass A alone is \
         insufficient and both passes are required."
    );
    assert!(
        terminator_behaviour("{ echo; builtin exit 1; }", "probe", true).is_ok(),
        "Pass B must accept `builtin exit 1` — otherwise it is not testing what it claims"
    );
    assert!(
        terminator_behaviour("{ echo; return 1; }", "probe", false).is_err(),
        "the marker technique must catch a `return`, which resumes the caller"
    );
}

// ── (h) Grammar-h2 whole-file ban list ───────────────────────────────────────

#[test]
fn run_gate_contains_no_command_resolution_shadow() {
    ban_list(&gate_text()).unwrap_or_else(|why| {
        panic!(
            "PREDICATE (h) Grammar-h2 FAILED (whole-file ban list).\n  {why}\n  Because this is a \
             WHOLE-FILE ban, a single violation invalidates EVERY row citing EITHER terminator: \
             the grammar cannot know which call site the shadow was aimed at."
        )
    });
}

// ── (i) the self-sanitising preamble ─────────────────────────────────────────

#[test]
fn grammar_i1_re_exec_is_unconditional_first_and_argv_keyed() {
    // AC-13/AC-15, V2 (after SSA_LANDED_DIFF_R-3b_V1_2026-09-05 RED-1).
    //
    // V1 asserted that the FIRST statement was `__stsh_gate_allow=`, i.e. the
    // first of four STATE PROBES whose combined verdict decided whether to
    // re-exec. That shape was defeated by an exported function named `builtin`:
    // the probes themselves were shadowable command words, so the decision
    // never ran and the gate continued inside the hostile environment. The
    // shape asserted here is UNCONDITIONAL re-exec keyed on an ARGV MARKER —
    // there is no state to inspect and therefore nothing to shadow into a
    // "skip".
    let gate = gate_text();
    let stmts = preamble_statements(&gate);
    assert!(!stmts.is_empty(), "run_gate.sh has no executable statement at all");

    let first = stmts[0].trim().to_string();
    assert!(
        first.starts_with(r#"[ "${1:-}" = "--stsh-sanitised" ] ||"#),
        "PREDICATE (i) Grammar-i1 FAILED: the FIRST non-comment statement in run_gate.sh is\n    \
         {first}\nand not the unconditional argv-keyed re-exec\n    \
         [ \"${{1:-}}\" = \"--stsh-sanitised\" ] || exec /usr/bin/env -i ...\nAnything above it — \
         `set -uo pipefail`, `GATE_ROOT=`, or a STATE PROBE — runs in the UNSANITISED environment, \
         with whatever the parent process exported still in scope."
    );
    assert!(
        first.contains("|| exec /usr/bin/env -i "),
        "PREDICATE (i) Grammar-i1 FAILED: the first statement does not `exec` into `/usr/bin/env \
         -i`. The marker test must be the ONLY thing standing between line 1 and a fresh, empty \
         environment.\n    {first}"
    );
    // AFFIRMATIVE ban on the V1 conditional shape: the decision must not be
    // reachable from any inspected state.
    for banned in ["__stsh_gate_clean", "builtin exec /usr/bin/env"] {
        assert!(
            !gate.contains(banned),
            "PREDICATE (i) Grammar-i1 FAILED: run_gate.sh still contains `{banned}`, the V1 \
             CONDITIONAL re-exec shape. RED-1 of SSA_LANDED_DIFF_R-3b_V1_2026-09-05: an exported \
             function named `builtin` shadows the very probes that shape depends on, so the \
             re-exec silently does not happen. The re-exec must be unconditional."
        );
    }
    // The marker is forwarded to the child, ahead of the caller's own argv,
    // and the child drops it.
    assert!(
        first.contains(r#"/bin/bash --noprofile --norc "$0" --stsh-sanitised "$@""#),
        "PREDICATE (i) Grammar-i1 FAILED: the re-exec does not re-run `\"$0\"` under \
         `/bin/bash --noprofile --norc` with `--stsh-sanitised` FIRST and the caller's `\"$@\"` \
         after it. Without the marker the child re-execs forever; without `\"$@\"` the child \
         silently loses `--partial`/`--help`.\n    {first}"
    );
    assert_eq!(
        stmts.get(1).map(|s| s.trim()),
        Some("builtin shift"),
        "PREDICATE (i) Grammar-i1 FAILED: the statement after the re-exec is not `builtin shift`. \
         The marker must be consumed before the option parser sees `$1`, and it must be consumed \
         through `builtin` so a (hypothetical, pre-sanitisation-only) `shift` function cannot \
         intervene."
    );
    for tok in ["--noprofile", "--norc"] {
        assert!(
            first.contains(tok),
            "PREDICATE (i) Grammar-i1 FAILED: `{tok}` is absent from the re-exec line. It is \
             retained as defence-in-depth ALONGSIDE `env -i` (it suppresses rc files; `env -i` \
             empties the environment), not instead of it."
        );
    }
    // Absolute paths: a word containing a slash is never subject to function lookup.
    for tok in ["/usr/bin/env", "/bin/bash"] {
        assert!(
            first.contains(tok),
            "PREDICATE (i) Grammar-i1 FAILED: the re-exec line does not invoke `{tok}` by \
             ABSOLUTE PATH. An unqualified command word is resolved as a shell FUNCTION first — \
             which is exactly how RED-1's exported `builtin` defeated V1."
        );
    }
    let joined = stmts.join("\n");
    for tok in ["/usr/bin/cut", "/usr/bin/sort", "/usr/bin/tr", "/bin/grep"] {
        assert!(
            joined.contains(tok),
            "PREDICATE (i) Grammar-i1 FAILED: the post-re-exec assertion does not invoke `{tok}` \
             by ABSOLUTE PATH."
        );
    }
}

#[test]
fn grammar_i2_marker_is_argv_and_the_env_list_is_closed() {
    // AC-14. The env `-i` list is the complete set of values that cross the
    // sanitisation boundary; the allowlist is what the post-re-exec assertion
    // demands on the other side. They must agree.
    let gate = gate_text();
    let stmts = preamble_statements(&gate);
    let joined = stmts.join("\n");

    let decl = joined
        .lines()
        .find(|l| l.trim_start().starts_with("__stsh_gate_allow="))
        .expect("preamble declares the assertion allowlist")
        .split('"')
        .nth(1)
        .expect("allowlist is a quoted string")
        .to_string();
    let declared: BTreeSet<&str> = decl.split_whitespace().collect();
    let expected: BTreeSet<&str> = ALLOWLIST.into_iter().collect();
    assert_eq!(
        declared, expected,
        "PREDICATE (i) Grammar-i2 FAILED: the post-re-exec assertion compares against \
         {declared:?}, but a sanitised child has EXACTLY {expected:?}. An eighth name means an \
         arbitrary inherited variable now passes the assertion unremarked."
    );

    let exec_line = stmts[0].clone();
    let passed: BTreeSet<String> = exec_line
        .split_whitespace()
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        .collect();
    // PWD, SHLVL and `_` are set by bash itself in the fresh child and are
    // never passed explicitly; the other four are. OLDPWD is deliberately NOT
    // passed: bash discards an empty/non-directory OLDPWD, and under an argv
    // marker there is no fixpoint requirement that would need it.
    let must_pass: BTreeSet<String> = ALLOWLIST
        .iter()
        .filter(|n| !matches!(**n, "PWD" | "SHLVL" | "_"))
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        passed, must_pass,
        "PREDICATE (i) Grammar-i2 FAILED: the `env -i` re-exec line passes {passed:?}, but must \
         pass exactly {must_pass:?} (the allowlist minus PWD/SHLVL/`_`, which bash sets itself). \
         A name added here survives sanitisation; a name dropped here makes the post-re-exec \
         assertion fail on every run."
    );

    // The marker is ARGV, not ENVIRONMENT — affirmatively, not by omission.
    // This is the distinction RED-1's fix turns on: a parent can `export`
    // anything, but it cannot put a word in this script's argv without
    // invoking the script with that word.
    for banned in ["STSH_GATE_SANITISED", "GATE_SANITISED", "_SANITISED", "ALREADY_CLEAN"] {
        assert!(
            !joined.contains(banned),
            "PREDICATE (i) Grammar-i2 FAILED: the preamble mentions the ENVIRONMENT-marker-shaped \
             name `{banned}`. The re-exec decision reads `$1` and nothing else. An environment \
             marker is settable by any parent and would reintroduce exactly the skip that RED-1 \
             achieved by shadowing `builtin`."
        );
    }
    assert!(
        !stmts[0].contains("$STSH") && !stmts[0].contains("${STSH"),
        "PREDICATE (i) Grammar-i2 FAILED: the re-exec decision reads an environment variable. It \
         must read `$1`."
    );
}

#[test]
fn grammar_i3_state_checks_are_a_post_re_exec_assertion_not_the_trigger() {
    // AC-16. The four V1 probes are retained — demoted from TRIGGER to
    // ASSERTION. They now run only inside a process this script itself created
    // with `env -i`, and a violation DIES rather than deciding anything.
    let gate = gate_text();
    let stmts = preamble_statements(&gate);
    let joined = stmts.join("\n");
    let exec_at = joined
        .find("|| exec /usr/bin/env -i ")
        .expect("PREDICATE (i) Grammar-i3 FAILED: no unconditional re-exec found");

    let probes: [(&str, &str); 4] = [
        ("compgen -A function", "(a) live function-table inspection"),
        ("/usr/bin/env | /usr/bin/cut -d= -f1", "(b) environment NAME-SET equality"),
        ("${BASH_ENV+x}", "(c) BASH_ENV presence"),
        ("'^BASH_FUNC_'", "(d) BASH_FUNC_* export grep"),
    ];
    for (needle, what) in probes {
        let at = joined.find(needle).unwrap_or_else(|| {
            panic!(
                "PREDICATE (i) Grammar-i3 FAILED: probe {what} is ABSENT (searched for \
                 `{needle}`). The four checks survive the V2 redesign as a post-re-exec \
                 assertion; deleting one removes the only detection of a sanitised child that is \
                 nonetheless dirty."
            )
        });
        assert!(
            at > exec_at,
            "PREDICATE (i) Grammar-i3 FAILED: probe {what} appears BEFORE the re-exec. That is \
             the V1 shape RED-1 defeated: a check that must run in the hostile environment in \
             order to decide whether to leave it can be shadowed into never running."
        );
    }
    let marks = joined.matches("__stsh_gate_dirty=\"$__stsh_gate_dirty").count();
    assert!(
        marks >= 4,
        "PREDICATE (i) Grammar-i3 FAILED: only {marks} of the four probes record their own \
         failure into `__stsh_gate_dirty`; a probe that observes a dirty environment and does not \
         record it is decoration"
    );
    let if_at = joined.find(r#"if [ -n "$__stsh_gate_dirty" ]"#).expect(
        "PREDICATE (i) Grammar-i3 FAILED: no `if [ -n \"$__stsh_gate_dirty\" ]` assertion block — \
         the probes are recorded and then ignored",
    );
    let tail = &joined[if_at..];
    assert!(
        tail.contains("builtin exit 1"),
        "PREDICATE (i) Grammar-i3 FAILED: the assertion block does not terminate with `builtin \
         exit 1`. A post-re-exec assertion that warns and continues is not an assertion."
    );
    for (needle, what) in probes {
        assert!(
            joined.find(needle).unwrap() < if_at,
            "PREDICATE (i) Grammar-i3 FAILED: probe {what} runs AFTER the assertion that consumes \
             its result"
        );
    }
}

#[test]
fn the_preamble_actually_sanitises_an_imported_shadow_behavioral_i() {
    // AC-17, Pass C. Each sub-case is a FRESH PROCESS whose PARENT has
    // deliberately arranged hostile state, and each probe ends with a FAILING
    // STAGE guarded by the gate's own `die` — so the test binds both halves of
    // the guarantee: nothing hostile survives, AND a failure after the preamble
    // still terminates with nonzero status.
    //
    // Sub-case (iv) is SSA_LANDED_DIFF_R-3b_V1_2026-09-05 RED-1 VERBATIM. It
    // passed against V1's conditional preamble — the gate continued, `exit`
    // resolved to a function, `|| die` was fail-open, and the script returned
    // 0 after an aborted stage.
    let gate = gate_text();
    let preamble = preamble_statements(&gate).join("\n");
    let dir = std::env::temp_dir().join(format!("stsh_r3b_passc_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("probe.sh");
    std::fs::write(
        &probe,
        format!(
            "#!/bin/bash\n{preamble}\n\
             echo \"FUNCS=[$(compgen -A function | tr '\\n' ' ')]\"\n\
             echo \"ENV=[$(env | cut -d= -f1 | LC_ALL=C sort | tr '\\n' ' ')]\"\n\
             echo \"TYPE_EXIT=$(type -t exit) TYPE_DIE=$(type -t die)\"\n\
             die() {{ echo \"GATE ABORTED: $*\" >&2; builtin exit 1; }}\n\
             false || die controlled_failure\n\
             echo REACHED_AFTER_FAILED_STAGE\n"
        ),
    )
    .unwrap();

    let cases: [(&str, &str); 4] = [
        ("(i) imported exit()/die()", "exit(){ :; }; export -f exit; die(){ :; }; export -f die"),
        (
            "(ii) imported exit()/die() PLUS a pre-set STSH_GATE_SANITISED=1",
            "export STSH_GATE_SANITISED=1; exit(){ :; }; export -f exit; die(){ :; }; export -f die",
        ),
        ("(iii) an arbitrary extra variable, NO function", "export EVIL=1"),
        (
            "(iv) SSA RED-1 VERBATIM: an exported function named `builtin`",
            "builtin() { case \"$1\" in exec|exit) return 0;; esac; command builtin \"$@\"; }; \
             export -f builtin; exit(){ :; }; export -f exit; die(){ :; }; export -f die; \
             export EVIL=1; unset BASH_ENV ENV",
        ),
    ];
    for (label, setup) in cases {
        let out = Command::new("timeout")
            .arg("20")
            .arg("/bin/bash")
            .arg("--noprofile")
            .arg("-c")
            .arg(format!("{setup}; bash {}", probe.display()))
            .output()
            .expect("probe must run");
        let s = String::from_utf8_lossy(&out.stdout).to_string();
        let e = String::from_utf8_lossy(&out.stderr).to_string();
        assert_ne!(
            out.status.code(),
            Some(124),
            "Behavioral-i Pass C {label}: the probe did NOT TERMINATE within 20s — an infinite \
             re-exec loop. The child must see `--stsh-sanitised` as `$1` and stop re-execing; \
             check that the re-exec passes the marker BEFORE `\"$@\"`."
        );
        assert!(
            s.contains("FUNCS=[]"),
            "Behavioral-i Pass C {label}: a shell function survived into the sanitised child.\n{s}"
        );
        assert!(
            s.contains("TYPE_EXIT=builtin"),
            "Behavioral-i Pass C {label}: `exit` does NOT resolve to the builtin inside the gate. \
             Every `|| die` in the gate is fail-open in this state.\n{s}"
        );
        assert!(
            !s.contains("TYPE_DIE=function"),
            "Behavioral-i Pass C {label}: an imported `die` survived.\n{s}"
        );
        let env_line = s.lines().find(|l| l.starts_with("ENV=[")).expect("ENV line");
        let got: BTreeSet<&str> = env_line
            .trim_start_matches("ENV=[")
            .trim_end_matches(']')
            .split_whitespace()
            .collect();
        let want: BTreeSet<&str> = ALLOWLIST.into_iter().collect();
        assert_eq!(
            got, want,
            "Behavioral-i Pass C {label}: the sanitised child's environment is not the \
             seven-name allowlist. `EVIL`/`STSH_GATE_SANITISED` and friends must not survive."
        );
        // The second half of the guarantee: a failing stage after the preamble
        // must abort with NONZERO status that the hostile parent observes.
        assert!(
            e.contains("GATE ABORTED: controlled_failure"),
            "Behavioral-i Pass C {label}: `|| die` did not fire on a failed stage.\nstdout:{s}\nstderr:{e}"
        );
        assert!(
            !s.contains("REACHED_AFTER_FAILED_STAGE"),
            "Behavioral-i Pass C {label}: execution CONTINUED past a failed stage — `die` did not \
             terminate. This is RED-1's fail-open outcome.\n{s}"
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "Behavioral-i Pass C {label}: the hostile PARENT observed exit status {:?}, not 1. \
             RED-1's signature was a gate that aborted a stage and still returned 0.\nstdout:{s}\nstderr:{e}",
            out.status.code()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── positive control: the census is GREEN on the REAL tree ───────────────────

#[test]
fn the_census_credits_the_real_tree_with_no_mutation_applied() {
    // A fixture that only ever fires on mutated trees, and never proves GREEN
    // on the real one, is not evidence.
    let c = census();
    let invoked: BTreeSet<&str> = c
        .entries
        .iter()
        .filter(|e| e.invoked_by_gate)
        .map(|e| e.path.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "verify_memory_ids",
        "verify_custody_manifest",
        "verify_did_exports",
        "verify_spend_artifacts.mjs",
        // R-3 post-merge rebase: the genesis posture stage (run_gate.sh Phase-1,
        // `-p verify-genesis-manifest … --posture`) flipped this row to true.
        "verify_genesis_manifest",
        // R-L post-merge rebase: the four permanent gate lints (G-a claims,
        // G-b refused-ceilings, G-c bindings, G-d no-skips) — one crate, four
        // blocking form-(a) stages with `die`, all in Phase 0 after the
        // MemoryId lint. Lane R-L moved this set.
        "verify_gate_lints",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        invoked, expected,
        "the set of gate-invoked tools changed. That is not automatically wrong — but it is never \
         silent: reconcile scripts/GATE_TOOL_CENSUS.toml and say in the packet which lane moved it."
    );
    // and both terminators are live-verified against the real file
    let gate = gate_text();
    for t in ["die", "verdict_fail"] {
        let body = extract_body(&gate, t);
        terminator_structure(&body, t).expect("real tree: structure");
        terminator_behaviour(&body, t, false).expect("real tree: Pass A");
        terminator_behaviour(&body, t, true).expect("real tree: Pass B");
    }
    ban_list(&gate).expect("real tree: ban list");
}
