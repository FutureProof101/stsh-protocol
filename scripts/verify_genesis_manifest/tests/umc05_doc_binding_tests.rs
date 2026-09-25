//! UMC-05 (lane R-11) — the Gate-V paragraph in `MAINNET_DEPLOYMENT.md` must
//! state the custody total BY REFERENCE, not as a transcribed literal.
//!
//! WHAT WENT WRONG. The runbook quoted the founders-only allocation (then
//! `18,000,000,000,000,000`, now `12,000,000,000,000,000` per a14beef1) as
//! "the founders allocation" that Σ(schedules) is checked against. Since D-4 V2
//! the check compares against founders **+ counsel**, so the quoted figure was
//! the wrong number for the check it described — a reader reconciling a real
//! deployment against that paragraph would have failed a correct deployment.
//!
//! THE LOCK. This test fails if the literal comes back, and fails if the
//! paragraph stops naming the real check. It is a genuine drift-LOCK, not
//! drift-avoidance: reverting the doc to the stale literal REDs it directly.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above scripts/verify_genesis_manifest")
        .to_path_buf()
}

fn gate_v_paragraph(doc: &str) -> String {
    let start = doc
        .find("**Gate-V phase 1")
        .expect("MAINNET_DEPLOYMENT.md must still carry a Gate-V phase 1 bullet");
    let rest = &doc[start..];
    let end = rest.find("\n- ").unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn umc05_gate_v_doc_states_the_custody_formula_by_reference() {
    let doc = std::fs::read_to_string(repo_root().join("MAINNET_DEPLOYMENT.md"))
        .expect("read MAINNET_DEPLOYMENT.md");
    let para = gate_v_paragraph(&doc);

    // (a) No transcribed amount. Any run of digits with the thousands grouping
    // the stale literal used is a transcribed total — the tool derives it.
    // Re-pointed by the genesis reallocation (a14beef1): the founders-only
    // allocation is now 12e15, so THAT is the literal whose return must RED.
    // The PRE-reallocation 18e15 spellings are RETAINED, not replaced (SSA note,
    // RR-1a): re-pointing the list alone would have let the superseded figure
    // walk back into the paragraph unchallenged, which is the same stale-literal
    // defect one revision earlier.
    for stale in [
        "12,000,000,000,000,000",
        "12_000_000_000_000_000",
        "18,000,000,000,000,000",
        "18_000_000_000_000_000",
    ] {
        assert!(
            !para.contains(stale),
            "MAINNET_DEPLOYMENT.md's Gate-V paragraph transcribes `{stale}` again. That figure \
             is the FOUNDERS-only allocation; the check compares Σ(schedules) against \
             founders + counsel. State it by reference to \
             `V6-schedule-sum-eq-custody-allocation` instead.\n\nparagraph:\n{para}"
        );
    }

    // (b) It names the real check, so the reference actually resolves.
    let src = std::fs::read_to_string(
        repo_root().join("scripts/verify_genesis_manifest/src/lib.rs"),
    )
    .expect("read verify_genesis_manifest");
    let check_id = "V6-schedule-sum-eq-custody-allocation";
    assert!(
        src.contains(check_id),
        "the check id `{check_id}` no longer exists in verify_genesis_manifest — the runbook's \
         by-reference statement points at nothing"
    );
    assert!(
        para.contains(check_id),
        "MAINNET_DEPLOYMENT.md's Gate-V paragraph must name the check that actually performs \
         it (`{check_id}`), or the by-reference statement is unverifiable prose.\n\n{para}"
    );

    // (c) It states the FORMULA the check evaluates — founders + counsel — and
    //     the tool really does sum both categories.
    assert!(
        para.contains("founders + counsel") || para.contains("**founders + counsel**"),
        "the paragraph must state the custody formula as founders + counsel.\n\n{para}"
    );
    assert!(
        src.contains("let counsel_amount = allocation_amount(manifest, COUNSEL_CATEGORY_ID);")
            && src.contains("(Some(f), Some(c)) => f.checked_add(c),"),
        "verify_genesis_manifest no longer sums founders + counsel for the expected custody \
         total; the runbook's stated formula and the code have diverged"
    );
}
