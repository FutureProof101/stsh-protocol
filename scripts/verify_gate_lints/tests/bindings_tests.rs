//! AC-1 — the `bindings` (e) census is a census of what `run_gate.sh` RUNS.
//!
//! Rule (e) used to be `gate_script.contains(&suite.gate_invocation)`. Every
//! mutation below keeps that substring in the file and runs nothing, so every
//! one of them was GREEN under the old check. The positive control in each test
//! is the REAL committed `run_gate.sh`, read from disk, not a paraphrase of it:
//! a census that agrees with a fixture of the script but not with the script is
//! not a census.

use verify_gate_lints::shell_lex::{census_invoked, command_runs};

/// The vetkeys leg — the one `cargo test --workspace` can never run, so the
/// only thing that runs it is this exact line.
const VETKEYS: &str = "cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked --no-fail-fast";
/// The workspace leg. Deliberately a strict PREFIX of `run_gate.sh:1338`, whose
/// next word is `--` — nothing after a matched run is examined.
const WORKSPACE: &str = "cargo test --workspace --locked --no-fail-fast";

fn gate_script() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above scripts/verify_gate_lints")
        .to_path_buf();
    std::fs::read_to_string(root.join("run_gate.sh")).expect("the committed run_gate.sh")
}

/// The one line in the script the vetkeys leg lives on, located by content so a
/// mutation can be applied to it without a line number that drifts.
fn vetkeys_line(script: &str) -> &str {
    script
        .lines()
        .find(|l| l.trim_start().starts_with("cargo test --manifest-path canisters/vetkeys"))
        .expect("run_gate.sh still carries the vetkeys leg")
}

/// Both real legs are found in the unmodified script. This is the positive
/// control every mutation below is measured against.
#[test]
fn census_finds_both_real_legs_in_the_committed_script() {
    let s = gate_script();
    assert!(census_invoked(&s, VETKEYS), "the vetkeys leg is invoked by run_gate.sh");
    assert!(census_invoked(&s, WORKSPACE), "the workspace leg is invoked by run_gate.sh");
}

/// AC-1a — a commented-out leg is not an invoked leg.
#[test]
fn census_rejects_commented_vetkeys_line() {
    let s = gate_script();
    let line = vetkeys_line(&s).to_string();
    let mutated = s.replace(&line, &format!("# {line}"));
    assert_ne!(s, mutated, "the mutation must actually change the script text");
    assert!(
        mutated.contains(VETKEYS),
        "the mutated script STILL CONTAINS the substring — this is exactly why a \
         `contains` check certified it"
    );
    assert!(!census_invoked(&mutated, VETKEYS), "rule 4: a comment contributes zero words");
    assert!(
        census_invoked(&mutated, WORKSPACE),
        "the workspace leg is untouched — the census is not failing for an unrelated reason"
    );
}

/// AC-1b — a quoted `echo` of the line prints it; it does not run it.
#[test]
fn census_rejects_invocation_inside_quoted_echo_string() {
    let s = gate_script();
    let line = vetkeys_line(&s).to_string();
    let mutated = s.replace(&line, &format!("echo \"{}\"", line.trim()));
    assert!(mutated.contains(VETKEYS), "substring preserved");
    assert!(
        !census_invoked(&mutated, VETKEYS),
        "rule 2: the whole invocation is ONE quoted word, not a ten-word run"
    );
}

/// AC-1b′ — an UNQUOTED `echo` prefix. The words are all there, in order, as
/// separate words; only the anchor at command position rejects it. This is the
/// case that discriminates an anchored design from an unanchored one, and it is
/// the binding demonstration for B-RL2-CENSUS-BY-CONTENT: the SAME word
/// sequence, at command position and behind `echo`, must not evaluate the same.
// BINDING: B-RL2-CENSUS-BY-CONTENT
#[test]
fn census_rejects_invocation_inside_unquoted_echo() {
    let s = gate_script();
    let line = vetkeys_line(&s).to_string();
    let mutated = s.replace(&line, &format!("echo {}", line.trim()));
    let runs = command_runs(&mutated);
    assert!(
        runs.iter().any(|r| r.first().map(String::as_str) == Some("echo")),
        "the mutated script really does carry an `echo` command"
    );
    // Two invocations of the bound entrypoint with DIFFERING inputs, and the
    // outcomes differ. Position is the whole criterion.
    assert_ne!(
        census_invoked(&s, VETKEYS),
        census_invoked(&mutated, VETKEYS),
        "the same word sequence at command position is an invocation; behind `echo` it is not"
    );
    assert!(census_invoked(&s, VETKEYS));
    assert!(
        !census_invoked(&mutated, VETKEYS),
        "rule 9: `cargo` is the command's SECOND word, so no run STARTS with the invocation"
    );
    // The workspace row is a strict PREFIX of run_gate.sh:1338, whose next word
    // is `--`. Anchoring the match and examining nothing after the run is what
    // lets the six committed rows match the UNMODIFIED script at all.
    assert!(
        s.contains("cargo test --workspace --locked --no-fail-fast -- --test-threads=1"),
        "the committed line really does carry `--` after the row's words"
    );
    assert!(census_invoked(&s, WORKSPACE));
}

/// AC-1c — a here-document body is data, not commands.
#[test]
fn census_rejects_invocation_inside_heredoc() {
    let s = gate_script();
    let line = vetkeys_line(&s).to_string();
    let mutated = s.replace(&line, &format!(": <<'EOF'\n{}\nEOF", line.trim()));
    assert!(mutated.contains(VETKEYS), "substring preserved");
    assert!(
        !census_invoked(&mutated, VETKEYS),
        "rule 7: the delimiter's quotes are stripped and every line to `EOF` is data"
    );
    assert!(
        census_invoked(&mutated, WORKSPACE),
        "the body skip STOPS at the delimiter — it must not swallow the rest of the file"
    );
}

/// AC-1d — DISCLOSED RESIDUAL (NOTE-1), asserted as a pass, not fixed.
///
/// `if false; then … fi` is lexically a command and the census says so. The
/// census decides what IS a command, never whether it RUNS: deciding that means
/// evaluating the script. The direction is permissive — it finds an invocation
/// that does not execute, never misses one that does — which is the safe
/// direction for a check whose failure mode is orphaning a binding.
#[test]
fn census_disclosed_residual_if_false_still_matches() {
    let s = gate_script();
    let line = vetkeys_line(&s).to_string();
    let mutated = s.replace(&line, &format!("if false; then\n{}\nfi", line.trim()));
    assert!(
        census_invoked(&mutated, VETKEYS),
        "documented residual: reachability is not evaluated. If this ever flips, the \
         residual has been closed and NOTE-1 must be re-written, not this assertion"
    );
}

/// AC-1e — a `\`-continuation split is joined (rule 5), so the run is still one
/// simple command. Permissive-direction case, asserted GREEN.
#[test]
fn census_permissive_over_continuation_split() {
    let s = gate_script();
    let line = vetkeys_line(&s).to_string();
    let split = line.trim().replace(
        "canisters/vetkeys/Cargo.toml --locked",
        "canisters/vetkeys/Cargo.toml \\\n  --locked",
    );
    let mutated = s.replace(&line, &split);
    assert!(!mutated.contains(VETKEYS), "the raw substring is BROKEN by the split");
    assert!(
        census_invoked(&mutated, VETKEYS),
        "rule 5: a backslash-newline is deleted, not a terminator — this is a case a \
         `contains` check gets WRONG in the other direction"
    );
}

/// **AC-1f — the here-string rule.**
///
/// `run_gate.sh` carries three `<<<` here-strings and no here-document at all.
/// Two of them (`:296`, `:297`) sit inside a `$( … )` span, which rule 3
/// consumes opaquely — rules 6/7 are never reached there, so they discriminate
/// nothing. The third, quoted verbatim below, is at bare command-argument
/// position after `if ! grep -q "$m"`, and it is the one line in the file rule 6
/// actually has to adjudicate.
///
/// The fixture is DOUBLY discriminating and both halves are load-bearing:
/// under "delete rule 6", the real `:305` line alone swallows the fixture to its
/// end (its `<<` is read as a here-doc opener whose delimiter, `<$COMMENT_BLOCK`
/// after quote-stripping, matches no line), and so does the synthetic
/// `cat <<< "x"` pair independently. Do not simplify the fixture or reorder it.
#[test]
fn census_here_string_does_not_swallow_the_file() {
    // Line 1: the REAL run_gate.sh here-string, verbatim.
    let real_305 = r#"  if ! grep -q "$m" <<<"$COMMENT_BLOCK"; then"#;
    let fixture = format!("{real_305}\ncat <<< \"x\"\n{VETKEYS}\n");

    // Positive control: rule 6 skips each operand as ONE word and scanning
    // resumes on the very next line, where the invocation is found.
    assert!(
        census_invoked(&fixture, VETKEYS),
        "rule 6: a here-string's operand is one word, not a here-document body"
    );

    // The real script is unaffected by the same shape.
    assert!(census_invoked(&gate_script(), VETKEYS));

    // And the operand really is skipped rather than contributed as a word: the
    // `if` line's run must not carry `\"$COMMENT_BLOCK\"`.
    let runs = command_runs(&fixture);
    let grep_run = runs
        .iter()
        .find(|r| r.first().map(String::as_str) == Some("grep"))
        .expect("the `if` sets command position and `grep` starts the next run");
    assert!(
        !grep_run.iter().any(|w| w.contains("COMMENT_BLOCK")),
        "rule 6: the operand is skipped, not contributed: {grep_run:?}"
    );

    // The invocation is reached at all — i.e. the scanner did not stop at line 1.
    assert!(
        runs.iter().any(|r| r.first().map(String::as_str) == Some("cargo")),
        "the invocation line is REACHED, not consumed as here-document data: {runs:?}"
    );
}
