//! UMC-12 (lane R-11) — `scripts/amount_boundary_allowlist.toml`'s header
//! counts must equal the rows the file actually carries.
//!
//! WHAT WENT WRONG. The header claimed "the 33 adjudicated boundaries" and
//! "Class C (6 rows)". Recounted at this base the classes hold 6 / 10 / 4 / 11
//! = 31, and Class C holds 4. Both figures were transcribed once and never
//! re-derived, so the file's own summary disagreed with its own rows.
//!
//! THE LOCK. The header is now the single place a count is stated, and this
//! test re-derives every one of them from the rows. Adding a row to any class
//! without updating its header count REDs, and so does reinstating a total.
//!
//! WHY IT LIVES IN `verify_gate_lints` AND NOT IN `verify_did_exports`
//! (deviation from the R-11 brief §3.13(a), disclosed). `verify_did_exports` is
//! a STANDALONE crate with its own workspace root, and `run_gate.sh` invokes
//! only its BINARY (`cargo run --manifest-path … --bin verify_did_exports`) —
//! it never runs `cargo test` there. A test placed in that crate would compile
//! for nobody and run in no gate, which is the "unlisted reproducibility claim"
//! shape this campaign exists to remove. `verify_gate_lints` is a real
//! workspace member, so `cargo test --workspace` runs this.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above scripts/verify_gate_lints")
        .to_path_buf()
}

/// The count stated in a header line of the form
/// `#   Class C — <description> (4 rows)`.
fn stated_count(text: &str, class: char) -> u32 {
    let needle = format!("Class {class} —");
    let start = text
        .find(&needle)
        .unwrap_or_else(|| panic!("the header no longer declares `Class {class}`"));
    // The count may sit on a continuation line, so scan forward to the first
    // `(N rows)` that appears before the NEXT class header (or the first row).
    let rest = &text[start..];
    let stop = ["Class A —", "Class B —", "Class C —", "Class D —", "[[amount]]"]
        .iter()
        .filter_map(|m| rest[needle.len()..].find(m).map(|i| i + needle.len()))
        .min()
        .unwrap_or(rest.len());
    let window = &rest[..stop];
    let open = window
        .rfind('(')
        .unwrap_or_else(|| panic!("`Class {class}` header states no `(N rows)` count"));
    let close = window[open..]
        .find(')')
        .map(|i| i + open)
        .unwrap_or_else(|| panic!("`Class {class}` header has an unclosed count"));
    window[open + 1..close]
        .trim()
        .trim_end_matches("rows")
        .trim_end_matches("row")
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("`Class {class}` header count does not parse: {e}"))
}

#[test]
fn umc12_allowlist_header_class_counts_match_actual_rows() {
    let path = repo_root().join("scripts/amount_boundary_allowlist.toml");
    let text = std::fs::read_to_string(&path).expect("read amount_boundary_allowlist.toml");

    let mut total_stated = 0u32;
    let mut total_actual = 0u32;
    for class in ['A', 'B', 'C', 'D'] {
        let stated = stated_count(&text, class);
        // Rows carry their class in the `reason` field, lower-case, as
        // `class C — …`. Counted by whole line, so a class letter appearing in
        // prose elsewhere cannot inflate the tally.
        let actual = text
            .lines()
            .filter(|l| l.contains(&format!("class {class} —")))
            .count() as u32;
        assert_eq!(
            stated, actual,
            "Class {class}: the allowlist header says {stated} rows, the file carries {actual}. \
             The header is the only place a count is stated — update it, or the summary is a \
             second source of truth with nothing behind it."
        );
        total_stated += stated;
        total_actual += actual;
    }

    assert_eq!(total_stated, total_actual, "per-class sums must agree");
    assert!(
        total_actual > 0,
        "fixture guard: zero adjudicated rows found — the class marker format changed and this \
         test is now counting nothing"
    );

    // No file-level total may be restated: the classes sum to it, and the stale
    // "33 adjudicated boundaries" line is exactly what a restated total decays
    // into.
    for stale in ["33 adjudicated", "31 adjudicated"] {
        assert!(
            !text.contains(stale),
            "the allowlist restates a file-level total (`{stale}`). The per-class counts sum to \
             {total_actual}; a second, hand-maintained total is what drifted before."
        );
    }
}
