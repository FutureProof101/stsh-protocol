// R-3a / REPIN-FIX — `--repin`'s refusals plus the three SETTLEMENT-escalation
// failure modes (CTO_ESCALATION_HARDEN03_SETTLEMENT_GATE_BLOCK_AND_REPIN_BUG_2026-09-18):
//
//   1. anchor match on a substring, so `[wasm.vault]` written as PROSE inside a
//      comment paragraph was treated as the real table header;
//   2. that false anchor's "next `\n[`" end-of-table search also stopped on a
//      `[` inside a comment, deleting hundreds of protected lines (the 723-line
//      delete);
//   3. the printed report could label a hash under the wrong table, and the
//      tool exited 0 even though it had corrupted the record.
//
// Each test drives the REAL binary against a scratch git repository, so every
// refusal/behaviour is observed at the process boundary the runbook uses.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_verify_custody_manifest");

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vcm_repin_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn git(root: &Path, args: &[&str]) {
    let o = Command::new("git")
        .args(["-C", &root.to_string_lossy()])
        .args(args)
        .output()
        .expect("git must be available");
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn write(p: &Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

fn record_path(root: &Path) -> PathBuf {
    root.join("deployment/mainnet/release_hashes.toml")
}

/// A full, realistic `[wasm.*]` table for every INLINE_PAYLOAD_ARTIFACTS
/// package, in the same field order/layout the real release record uses,
/// interleaved with a comment paragraph that mentions a REAL table header
/// name in PROSE (the exact SETTLEMENT anchor-collision shape) and a block of
/// historical/superseded commentary between tables (the 723-line-delete
/// shape). Every `[wasm.*]` package gets a placeholder hash/bytes/path from
/// pkg-named bytes so a repin always changes something observable.
fn realistic_record(root: &Path) -> String {
    let mut s = String::new();
    s.push_str("[build]\nsource_sha = \"0000\"\nasserts_identity_at = \"0000\"\n\n");
    s.push_str(
        "# HISTORICAL NOTE, superseded 2026-09-11. The prior builder's leg\n\
         # reproduced [wasm.vault] and [wasm.upgrader] EXACTLY as recorded here.\n\
         # ONLY THE COMMENT CHANGED that round — no hash below moved. This\n\
         # paragraph exists purely as protected history and must never be\n\
         # touched by a repin; several more comment blocks like it follow\n\
         # between tables further down, mirroring the real release record.\n\
         #\n\
         # A second historical paragraph, also mentioning bracketed prose:\n\
         # see [build] above and [wasm.vault] again here — neither is a real\n\
         # header on this line, both are inside a comment.\n\n",
    );
    for (pkg, file) in verify_custody_manifest::INLINE_PAYLOAD_ARTIFACTS {
        let key = if pkg.contains('-') { format!("\"{pkg}\"") } else { (*pkg).to_string() };
        s.push_str(&format!(
            "# superseded comment block before [wasm.{key}] — historical prose only,\n\
             # not a table, and must survive byte-identical.\n\
             [wasm.{key}]\n\
             sha256 = \"stale0000000000000000000000000000000000000000000000000000000000\" # old leg\n\
             bytes  = 1\n\
             path   = \"target/wasm32-unknown-unknown/release/{file}\"\n\n",
        ));
    }
    s.push_str("# trailing historical footer paragraph — must survive untouched.\n");
    let _ = root;
    s
}

/// A committed scratch root whose ten artifacts are all present, whose tree
/// is CLEAN, and whose release record is the realistic multi-comment fixture
/// above.
fn clean_root(tag: &str) -> PathBuf {
    let root = scratch(tag);
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.email", "fixture@example.invalid"]);
    git(&root, &["config", "user.name", "fixture"]);
    write(&root.join(".gitignore"), "target/\n");
    write(&record_path(&root), &realistic_record(&root));
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "fixture"]);
    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    std::fs::create_dir_all(&wasm_dir).unwrap();
    for (pkg, file) in verify_custody_manifest::INLINE_PAYLOAD_ARTIFACTS {
        std::fs::write(wasm_dir.join(file), format!("{pkg}-bytes-v2")).unwrap();
    }
    root
}

fn repin(root: &Path, extra: &[&str]) -> (i32, String) {
    let o = Command::new(BIN)
        .arg("--repin")
        .args(extra)
        .arg(root)
        .output()
        .expect("binary must run");
    (
        o.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

fn read_record(root: &Path) -> String {
    std::fs::read_to_string(record_path(root)).unwrap()
}

// ── Baseline refusals (dirty tree / missing artifact) ──────────────────────

#[test]
fn repin_refuses_dirty_tree() {
    let root = clean_root("dirty");
    write(&root.join("deployment/mainnet/scratch.txt"), "uncommitted\n");
    let (code, out) = repin(&root, &["--write"]);
    assert_ne!(code, 0, "a dirty tree must be REFUSED, got exit 0:\n{out}");
    assert!(
        out.contains("REFUSED") && out.contains("DIRTY"),
        "the refusal must NAME the dirty tree, got:\n{out}"
    );
}

#[test]
fn repin_refuses_missing_artifact() {
    let root = clean_root("missing");
    let gone = root.join("target/wasm32-unknown-unknown/release/treasury.wasm");
    std::fs::remove_file(&gone).unwrap();
    let (code, out) = repin(&root, &["--write"]);
    assert_ne!(code, 0, "a missing artifact must be REFUSED, got exit 0:\n{out}");
    assert!(
        out.contains("REFUSED") && out.contains("MISSING ARTIFACT") && out.contains("treasury.wasm"),
        "the refusal must NAME the missing artifact, got:\n{out}"
    );
}

// ── AC-3: default dry-run, --write required to modify ──────────────────────

#[test]
fn repin_default_is_dry_run_and_writes_nothing() {
    let root = clean_root("dryrun");
    let before = read_record(&root);
    let (code, out) = repin(&root, &[]);
    assert_eq!(code, 0, "dry-run over a clean, complete fixture must succeed:\n{out}");
    let after = read_record(&root);
    assert_eq!(before, after, "dry-run must never modify the file on disk");
    assert!(
        out.contains("--- a/") && out.contains("+++ b/") && out.contains("@@"),
        "dry-run must print a unified-style diff to stdout, got:\n{out}"
    );
    assert!(
        out.contains("DRY RUN"),
        "dry-run must say so explicitly, got:\n{out}"
    );
}

#[test]
fn repin_write_flag_actually_modifies_the_file() {
    let root = clean_root("write");
    let before = read_record(&root);
    let (code, out) = repin(&root, &["--write"]);
    assert_eq!(code, 0, "--write over a clean, complete fixture must succeed:\n{out}");
    let after = read_record(&root);
    assert_ne!(before, after, "--write must actually rewrite the stale pins");
    assert!(out.contains("WROTE"), "got:\n{out}");
    for (_, file) in verify_custody_manifest::INLINE_PAYLOAD_ARTIFACTS {
        let bytes = std::fs::read(root.join("target/wasm32-unknown-unknown/release").join(file)).unwrap();
        let sha = verify_custody_manifest::sha256_hex(&bytes);
        assert!(after.contains(&sha), "expected new hash for {file} in rewritten record:\n{after}");
    }
    assert!(
        after.contains("asserts_identity_at = \"0000\""),
        "--repin must not touch asserts_identity_at, got:\n{after}"
    );
}

#[test]
fn repin_write_without_repin_flag_is_rejected() {
    let root = clean_root("write_alone");
    let o = Command::new(BIN).arg("--write").arg(&root).output().unwrap();
    assert!(!o.status.success(), "--write with no --repin must be rejected");
}

// ── AC-1: header anchored by real TOML table position, never text search ───

#[test]
fn repin_ignores_a_table_name_written_as_prose_inside_a_comment() {
    // The fixture already embeds `[wasm.vault]` twice inside comment prose
    // (see realistic_record). Confirm those bytes are untouched and only the
    // REAL `[wasm.vault]` table's sha256/bytes/path rows changed.
    let root = clean_root("prose_anchor");
    let before = read_record(&root);
    let (code, out) = repin(&root, &["--write"]);
    assert_eq!(code, 0, "got:\n{out}");
    let after = read_record(&root);
    assert!(
        after.contains("reproduced [wasm.vault] and [wasm.upgrader] EXACTLY as recorded here."),
        "the comment prose mentioning [wasm.vault] must survive byte-identical, got:\n{after}"
    );
    assert!(
        after.contains("see [build] above and [wasm.vault] again here"),
        "the second prose mention must also survive byte-identical, got:\n{after}"
    );
    // Exactly one real `[wasm.vault]` header must still exist, and only its
    // sha256/bytes/path values differ from before.
    assert_eq!(
        after.matches("[wasm.vault]").count(),
        before.matches("[wasm.vault]").count(),
        "repin must not create or delete table headers"
    );
}

// ── AC-2: never deletes a line outside the target rows (723-line-delete) ───

#[test]
fn repin_round_trips_comment_blocks_byte_identical_except_target_rows() {
    let root = clean_root("comment_blocks");
    let before = read_record(&root);
    let (code, out) = repin(&root, &["--write"]);
    assert_eq!(code, 0, "got:\n{out}");
    let after = read_record(&root);

    // Every historical/superseded comment line from the fixture must appear
    // verbatim in the output — this is the direct regression test for the
    // 723-line delete (many comment blocks between tables).
    for line in before.lines().filter(|l| l.trim_start().starts_with('#')) {
        assert!(
            after.contains(line),
            "comment line dropped by repin (723-line-delete regression):\n{line}\n\nfull after:\n{after}"
        );
    }
    assert!(after.contains("# trailing historical footer paragraph — must survive untouched."));

    // Line counts must match: nothing was deleted, nothing extra appended.
    assert_eq!(
        before.lines().count(),
        after.lines().count(),
        "repin must not change the file's line count when every table already exists"
    );

    // Only sha256/bytes/path lines may differ.
    for (b, a) in before.lines().zip(after.lines()) {
        if b == a {
            continue;
        }
        let key = a.trim().split('=').next().unwrap_or("").trim();
        assert!(
            key == "sha256" || key == "bytes" || key == "path",
            "an unexpected line changed — before: {b:?} after: {a:?}"
        );
    }
}

// ── AC-3: structural mismatches refuse, write nothing ───────────────────────

fn corrupt_and_expect_refusal(root: &Path, mutate: impl FnOnce(&str) -> String) {
    let before = std::fs::read_to_string(record_path(root)).unwrap();
    let corrupted = mutate(&before);
    write(&record_path(root), &corrupted);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "corrupt"]);
    let (code, out) = repin(root, &["--write"]);
    assert_ne!(code, 0, "structural mismatch must be REFUSED, got exit 0:\n{out}");
    let after = std::fs::read_to_string(record_path(root)).unwrap();
    assert_eq!(after, corrupted, "a refused repin must write NOTHING");
}

#[test]
fn repin_refuses_missing_table() {
    let root = clean_root("missing_table");
    corrupt_and_expect_refusal(&root, |t| t.replace("[wasm.vault]", "[wasm.not_vault]"));
}

#[test]
fn repin_refuses_duplicate_table() {
    let root = clean_root("dup_table");
    corrupt_and_expect_refusal(&root, |t| {
        let extra = "\n[wasm.vault]\nsha256 = \"dup0000000000000000000000000000000000000000000000000000000000\"\nbytes  = 1\npath   = \"target/wasm32-unknown-unknown/release/vault.wasm\"\n";
        format!("{t}{extra}")
    });
}

#[test]
fn repin_refuses_missing_sha256_key() {
    let root = clean_root("missing_sha");
    corrupt_and_expect_refusal(&root, |t| {
        t.lines()
            .filter(|l| !(l.trim().starts_with("sha256") && t.contains("[wasm.vault]")))
            .collect::<Vec<_>>()
            .join("\n")
    });
}

#[test]
fn repin_refuses_unparseable_toml() {
    let root = clean_root("bad_toml");
    corrupt_and_expect_refusal(&root, |t| format!("{t}\n[unterminated table\nkey = \n"));
}

// ── AC-4: report labels each hash under the correct table ───────────────────

#[test]
fn repin_report_labels_each_row_under_its_own_table() {
    let root = clean_root("labels");
    let (code, out) = repin(&root, &["--write"]);
    assert_eq!(code, 0, "got:\n{out}");
    for (pkg, _) in verify_custody_manifest::INLINE_PAYLOAD_ARTIFACTS {
        let key = if pkg.contains('-') { format!("\"{pkg}\"") } else { (*pkg).to_string() };
        let label = format!("[wasm.{key}]");
        assert!(
            out.contains(&format!("[{label}]")),
            "expected the report to cite the real table label `{label}` for pkg `{pkg}`, got:\n{out}"
        );
    }
}

// ── Vacuity: repin actually changes something on the unbroken fixture ──────

#[test]
fn repin_succeeds_and_changes_every_stale_row() {
    let root = clean_root("ok");
    let (code, out) = repin(&root, &["--write"]);
    assert_eq!(code, 0, "the unbroken fixture must be accepted:\n{out}");
    let rec = read_record(&root);
    assert_eq!(
        rec.matches("sha256 = \"").count(),
        verify_custody_manifest::INLINE_PAYLOAD_ARTIFACTS.len(),
        "one pinned row per shipped artifact, got:\n{rec}"
    );
    assert!(
        !rec.contains("stale0000000000000000000000000000000000000000000000000000000000"),
        "every stale placeholder hash must have been replaced, got:\n{rec}"
    );
    assert!(
        out.contains("run this only as a step of `./run_gate.sh`"),
        "the obligation line must print on EVERY invocation, got:\n{out}"
    );
}
