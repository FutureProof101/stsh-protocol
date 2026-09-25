//! Census by CONTENT: does `run_gate.sh` actually INVOKE this suite?
//!
//! The `bindings` (e) check used to be a raw `str::contains` of the committed
//! `gate_invocation` against the script text. That is not a census of what the
//! gate runs; it is a census of what the gate's bytes SPELL. Every one of these
//! keeps the substring and runs nothing:
//!
//! ```text
//! # cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked --no-fail-fast
//! echo "cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked --no-fail-fast"
//! echo cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked --no-fail-fast
//! : <<'EOF'
//! cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked --no-fail-fast
//! EOF
//! ```
//!
//! [`census_invoked`] tokenizes the script into simple commands and requires the
//! invocation's own word sequence to appear as an exact, contiguous run STARTING
//! AT COMMAND POSITION. A commented, quoted, echoed or here-doc'd copy is not a
//! command; an `echo`-prefixed copy does not start at command position.
//!
//! ## The nine rules (precedence at each scan position)
//!
//! 1. `'…'` — consume to the closing `'`; no escapes; contributes to the
//!    current word.
//! 2. `"…"` — consume to the closing `"`, honoring `\"`. A `$( … )`/backtick
//!    span inside is consumed by rule 3, and its own inner `"` does not close
//!    the outer span.
//! 3. `$(` / backtick — `$(` consumes by paren depth to the matching `)`;
//!    a backtick consumes to the next backtick. Either way this is ONE OPAQUE
//!    WORD, never split into the words it contains (disclosed residual below).
//! 4. `#` at word start — comment to end of line; contributes zero words.
//! 5. `\` immediately followed by a newline, outside quotes — deleted. NOT a
//!    terminator: the next line's words continue the current command.
//! 6. `<<<` — here-STRING. The following word is the operand: skip it as ONE
//!    WORD, not as here-document data. Not a terminator.
//! 7. `<<WORD` / `<<-WORD` (not `<<<`) — here-DOCUMENT. `WORD` with its quotes
//!    stripped is the delimiter; from the end of the current line, every
//!    following line is data up to and including a line that is exactly the
//!    delimiter (or end of input). Zero words contributed.
//! 8. Redirections (`>`, `>>`, `<`, `N>`, `2>&1`, `&>`) and their target word —
//!    ORDINARY WORDS. Not terminators, not skipped. Nothing after a matched run
//!    is examined, so this is behaviourally equivalent to skipping them, and it
//!    is what lets the six committed `gate_invocation` rows — which are strict
//!    PREFIXES of `run_gate.sh:1338`, whose next word is `--` — match the
//!    unmodified script at all.
//! 9. Terminators — newline, `;`, `&`, `&&`, `||`, `|`, and `(`, `)`, `{`, `}`
//!    AS THEIR OWN STANDALONE WORD. Each ends the current word-run. Command
//!    position is the start of input, immediately after any terminator, or
//!    immediately after one of `if elif while until then do else ! time`.
//!
//! Anything else is a WORD: a maximal run of non-blank bytes in bare state,
//! with rule 1/2 quote spans and rule 3 substitution spans folded in by
//! concatenation. Whitespace outside quotes and here-doc bodies separates words.
//!
//! `${…}` gets NO rule of its own. `$` and `{` are ordinary bytes in bare state;
//! `{`/`}` are rule-9 terminators only as a standalone word (a brace group
//! `{ …; }`), which `${VAR}` never produces — the `{` is glued to the preceding
//! `$` and the word runs on through the closing `}`. So `${canister//-/_}` is
//! one word and manufactures no extra command position. A `${…}` containing
//! literal whitespace or a `;` would split, and the direction of that split is
//! strictly permissive: an extra command position creates extra match
//! OPPORTUNITIES, never a false negative on a real invocation.
//!
//! ## Disclosed residual (NOTE-1) — reachability, not evaluation
//!
//! This decides what IS a command, never whether it RUNS. `if false; then … fi`
//! branches, uninvoked function bodies, dead `&&`/`||` arms, the contents of a
//! rule-3 span, and a word-splitting `${…}` all leave the judgment permissive or
//! unevaluated. Every one of them errs toward finding an invocation that does
//! not execute — never toward missing one that does. Same TCB-residual register
//! as `no_skips`'s disclosed depth and `dyn Trait` limits.

/// Words that put the NEXT word back at command position.
const COMMAND_POSITION_KEYWORDS: &[&str] =
    &["if", "elif", "while", "until", "then", "do", "else", "!", "time"];

fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Tokenize `script` into word-runs, each starting at a command position.
///
/// A run is closed by a rule-9 terminator, and also immediately after a
/// command-position keyword, so the keyword itself never occupies index 0 of the
/// run that follows it.
pub fn command_runs(script: &str) -> Vec<Vec<String>> {
    let s: Vec<char> = script.chars().collect();
    let n = s.len();
    let mut runs: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    // Pending here-doc delimiters, in the order their operators appeared. They
    // take effect at the END of the current line, which is what makes rule 7
    // swallow the file rather than only the rest of one line.
    let mut pending_heredocs: Vec<String> = Vec::new();
    let mut i = 0usize;

    macro_rules! close_run {
        () => {
            if !cur.is_empty() {
                runs.push(std::mem::take(&mut cur));
            }
        };
    }

    while i < n {
        let c = s[i];

        // Rule 5 — a backslash-newline outside quotes is deleted outright. It is
        // NOT a terminator, so the next line continues this command.
        if c == '\\' && i + 1 < n && s[i + 1] == '\n' {
            i += 2;
            continue;
        }

        if is_blank(c) {
            i += 1;
            continue;
        }

        // Rule 9 — newline. Any here-doc opened on this line consumes from here.
        if c == '\n' {
            i += 1;
            if !pending_heredocs.is_empty() {
                for delim in std::mem::take(&mut pending_heredocs) {
                    i = skip_heredoc_body(&s, i, &delim);
                }
            }
            close_run!();
            continue;
        }

        // Rule 4 — `#` at word start is a comment to end of line.
        if c == '#' {
            while i < n && s[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Rule 9 — the operator terminators.
        if c == ';' {
            close_run!();
            i += 1;
            continue;
        }
        if c == '&' {
            // `&>` is a REDIRECTION (rule 8), an ordinary word — not a terminator.
            if i + 1 < n && s[i + 1] == '>' {
                let (w, j) = read_word(&s, i);
                i = j;
                if !w.is_empty() {
                    cur.push(w);
                }
                continue;
            }
            close_run!();
            i += if i + 1 < n && s[i + 1] == '&' { 2 } else { 1 };
            continue;
        }
        if c == '|' {
            close_run!();
            i += if i + 1 < n && s[i + 1] == '|' { 2 } else { 1 };
            continue;
        }

        // Rule 6 / rule 7 — here-string vs here-document, decided at operator
        // position. `<<<` FIRST: a `<<`-only lexer reads `<<<"$X"` as a here-doc
        // whose delimiter no line ever matches and swallows the rest of the file.
        if c == '<' && i + 1 < n && s[i + 1] == '<' {
            if i + 2 < n && s[i + 2] == '<' {
                // Rule 6 — skip the operand as ONE WORD.
                i += 3;
                while i < n && is_blank(s[i]) {
                    i += 1;
                }
                if i < n && s[i] != '\n' {
                    let (_operand, j) = read_word(&s, i);
                    i = j;
                }
                continue;
            }
            // Rule 7 — `<<WORD` or `<<-WORD`.
            i += 2;
            if i < n && s[i] == '-' {
                i += 1;
            }
            while i < n && is_blank(s[i]) {
                i += 1;
            }
            let (raw, j) = read_word(&s, i);
            i = j;
            let delim: String = raw
                .chars()
                .filter(|ch| *ch != '\'' && *ch != '"')
                .collect();
            if !delim.is_empty() {
                pending_heredocs.push(delim);
            }
            continue;
        }

        // Rule 9 — `(`, `)`, `{`, `}` as a STANDALONE word.
        if matches!(c, '(' | ')' | '{' | '}') {
            let next_is_boundary =
                i + 1 >= n || is_blank(s[i + 1]) || s[i + 1] == '\n' || s[i + 1] == ';';
            if next_is_boundary {
                close_run!();
                i += 1;
                continue;
            }
        }

        // Everything else is a word (rules 1, 2, 3, 8 and Word all fold in here).
        let (w, j) = read_word(&s, i);
        i = j;
        if w.is_empty() {
            i += 1;
            continue;
        }
        let keyword = COMMAND_POSITION_KEYWORDS.contains(&w.as_str());
        cur.push(w);
        if keyword {
            close_run!();
        }
    }
    close_run!();
    runs
}

/// Consume one word starting at `i`, folding rule-1/2 quote spans and rule-3
/// substitution spans in by concatenation. Returns the word's VERBATIM source
/// text (quotes included) and the index just past it. Keeping the bytes verbatim
/// is what makes the script side and the invocation side comparable: both are
/// tokenized by this same function.
fn read_word(s: &[char], mut i: usize) -> (String, usize) {
    let n = s.len();
    let mut w = String::new();
    while i < n {
        let c = s[i];
        if is_blank(c) || c == '\n' || c == ';' || c == '|' {
            break;
        }
        if c == '&' && !(i + 1 < n && s[i + 1] == '>') {
            break;
        }
        // Rule 5 inside a bare word: a continuation ends the word's line but not
        // the word's command; treat it as a word boundary and let the caller's
        // loop delete it.
        if c == '\\' && i + 1 < n && s[i + 1] == '\n' {
            break;
        }
        // A here-string / here-doc operator at a word boundary belongs to the
        // caller, not to this word.
        if c == '<' && i + 1 < n && s[i + 1] == '<' && w.is_empty() {
            break;
        }
        match c {
            // Rule 1 — single quotes: no escapes at all.
            '\'' => {
                w.push(c);
                i += 1;
                while i < n && s[i] != '\'' {
                    w.push(s[i]);
                    i += 1;
                }
                if i < n {
                    w.push('\'');
                    i += 1;
                }
            }
            // Rule 2 — double quotes, honoring `\"`, with rule 3 spans inside.
            '"' => {
                w.push(c);
                i += 1;
                while i < n && s[i] != '"' {
                    if s[i] == '\\' && i + 1 < n {
                        w.push(s[i]);
                        w.push(s[i + 1]);
                        i += 2;
                        continue;
                    }
                    if s[i] == '$' && i + 1 < n && s[i + 1] == '(' {
                        let (span, j) = read_paren_span(s, i);
                        w.push_str(&span);
                        i = j;
                        continue;
                    }
                    if s[i] == '`' {
                        let (span, j) = read_backtick_span(s, i);
                        w.push_str(&span);
                        i = j;
                        continue;
                    }
                    w.push(s[i]);
                    i += 1;
                }
                if i < n {
                    w.push('"');
                    i += 1;
                }
            }
            // Rule 3 — one opaque word, never split into what it contains.
            '$' if i + 1 < n && s[i + 1] == '(' => {
                let (span, j) = read_paren_span(s, i);
                w.push_str(&span);
                i = j;
            }
            '`' => {
                let (span, j) = read_backtick_span(s, i);
                w.push_str(&span);
                i = j;
            }
            '\\' if i + 1 < n => {
                w.push(c);
                w.push(s[i + 1]);
                i += 2;
            }
            _ => {
                w.push(c);
                i += 1;
            }
        }
    }
    (w, i)
}

/// Rule 3 — `$( … )` consumed by paren depth. Nested substitutions and any
/// quoting inside are part of the same opaque span.
fn read_paren_span(s: &[char], mut i: usize) -> (String, usize) {
    let n = s.len();
    let mut out = String::from("$(");
    i += 2;
    let mut depth = 1i32;
    while i < n && depth > 0 {
        match s[i] {
            '(' => {
                depth += 1;
                out.push('(');
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    out.push(')');
                    i += 1;
                    break;
                }
                out.push(')');
            }
            c => out.push(c),
        }
        i += 1;
    }
    (out, i)
}

fn read_backtick_span(s: &[char], mut i: usize) -> (String, usize) {
    let n = s.len();
    let mut out = String::from("`");
    i += 1;
    while i < n && s[i] != '`' {
        out.push(s[i]);
        i += 1;
    }
    if i < n {
        out.push('`');
        i += 1;
    }
    (out, i)
}

/// Rule 7's body skip: from `i` (the first byte of the line after the operator's
/// line), consume whole lines until one is exactly `delim`, or until end of
/// input. Returns the index just past the terminating line.
fn skip_heredoc_body(s: &[char], mut i: usize, delim: &str) -> usize {
    let n = s.len();
    while i < n {
        let start = i;
        while i < n && s[i] != '\n' {
            i += 1;
        }
        let line: String = s[start..i].iter().collect();
        if i < n {
            i += 1;
        }
        if line.trim() == delim {
            return i;
        }
    }
    n
}

/// Does `script_text` INVOKE `invocation`?
///
/// True iff `invocation`'s own word sequence — tokenized by exactly the rules
/// above — appears as a contiguous run at the START of some simple command's
/// word run. Nothing after the matched run is examined: the committed
/// `gate_invocation` strings are deliberate PREFIXES of the real command lines,
/// which carry `--`, `--test-threads=1` and a redirection after them.
pub fn census_invoked(script_text: &str, invocation: &str) -> bool {
    let want: Vec<String> = command_runs(invocation).into_iter().flatten().collect();
    if want.is_empty() {
        return false;
    }
    command_runs(script_text)
        .iter()
        .any(|run| run.len() >= want.len() && run[..want.len()] == want[..])
}
