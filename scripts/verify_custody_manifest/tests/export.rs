// §P.2 acceptance tests — the authenticated D5 exporter.
//
// Every rule in the packet is a hard requirement with a negative test here:
// authenticated access (an unauthorized `None` is a STOP, never
// end-of-pagination), pinned cursor/limit, strict cursor progress, termination
// only at `next_cursor = None`, duplicate/cycle detection, canonicalization
// BEFORE hashing, the exactly-nine-Bound-receipt contract, deterministic
// rendering, newly-created scratch destinations, and a clean immutable source
// clone whose SHA is an ARGUMENT rather than a hardcoded commit.
//
// The whole rule set runs offline against a synthetic page source, so the
// tests exercise the same code path the live `dfx` transport does.

use std::path::{Path, PathBuf};
use verify_custody_manifest as vcm;
use vcm::export::{
    self, AcquiredPage, CreationReceipt, CreationReceiptPage, CreationReceiptStatus, ExportError,
    PageSource, PINNED_PAGE_LIMIT,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("export").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// The pool principal RECORDED in `deployment/mainnet/custody_manifest.toml`
/// (born_under_vault entry), bound there by lane A-3 FINALIZE (2026-09-12).
const BOUND_SHIELDED_POOL: &str = "cxrfg-qaaaa-aaaar-qchfa-cai";

fn principal_for(role: &str) -> candid::Principal {
    // A-3 FINALIZE forced `ids_name`/`principal` onto the pool's
    // born_under_vault entry (the D2 binding check requires the principal once
    // the name is bound). `render_manifest` refuses a receipt that contradicts
    // an ALREADY-RECORDED binding, so a synthetic principal for this role would
    // make `healthy_pages()` a contradiction fixture rather than a healthy one:
    // the test would be asserting that a receipt may disagree with the custody
    // record. The fixture therefore carries the real bound value for this one
    // role, and stays synthetic for the eight roles that carry no principal yet.
    if role == "shielded_pool" {
        return candid::Principal::from_text(BOUND_SHIELDED_POOL).expect("bound pool principal");
    }
    candid::Principal::self_authenticating(role.as_bytes())
}

fn receipt(i: usize, role: &str, status: CreationReceiptStatus) -> CreationReceipt {
    CreationReceipt {
        proposal_id: i as u64 + 1,
        principal: principal_for(role),
        purpose: role.to_string(),
        disposition: stsh_custody_types::ManifestDisposition::BornUnderVault,
        created_at_ns: 1_700_000_000_000_000_000 + i as u64,
        status,
    }
}

/// Render a page as the textual Candid a `dfx canister call` would print.
fn page_text(page: Option<CreationReceiptPage>) -> String {
    let bytes = candid::encode_one(&page).expect("encode");
    let args = candid::IDLArgs::from_bytes(&bytes).expect("decode to IDLArgs");
    args.to_string()
}

/// Nine `Bound` receipts split across two pages plus a terminal page.
fn healthy_pages() -> Vec<String> {
    let all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES
        .iter()
        .enumerate()
        .map(|(i, r)| receipt(i, r, CreationReceiptStatus::Bound))
        .collect();
    vec![
        page_text(Some(CreationReceiptPage {
            items: all[..5].to_vec(),
            next_cursor: Some(10),
        })),
        page_text(Some(CreationReceiptPage {
            items: all[5..].to_vec(),
            next_cursor: Some(20),
        })),
        page_text(Some(CreationReceiptPage {
            items: vec![],
            next_cursor: None,
        })),
    ]
}

struct Scripted {
    pages: Vec<String>,
    at: usize,
    seen_cursors: Vec<Option<u64>>,
    seen_limits: Vec<u32>,
}

impl Scripted {
    fn new(pages: Vec<String>) -> Self {
        Self { pages, at: 0, seen_cursors: vec![], seen_limits: vec![] }
    }
}

impl PageSource for Scripted {
    fn fetch(&mut self, cursor: Option<u64>, limit: u32) -> Result<String, ExportError> {
        self.seen_cursors.push(cursor);
        self.seen_limits.push(limit);
        let p = self
            .pages
            .get(self.at)
            .cloned()
            .ok_or(ExportError::TruncatedWalk { last_next_cursor: cursor.unwrap_or_default() })?;
        self.at += 1;
        Ok(p)
    }
}

fn walk_ok(pages: Vec<String>) -> Vec<AcquiredPage> {
    let mut s = Scripted::new(pages);
    export::walk(&mut s, PINNED_PAGE_LIMIT).expect("walk")
}

// ── Positive control: the whole pipeline, end to end ─────────────────────────

/// The healthy walk validates, renders, and the RENDERED MANIFEST satisfies
/// the §P.1 partition contract. This is the join between P.1 and P.2: the
/// exporter's output is checked by the gate that will police it.
#[test]
fn healthy_export_renders_a_manifest_the_gate_accepts() {
    let pages = walk_ok(healthy_pages());
    export::verify_sequence(&pages).expect("sequence");
    let receipts = export::validate_receipts(&pages).expect("nine bound receipts");
    assert_eq!(receipts.len(), 9);
    // Allowlist order, deterministically.
    assert_eq!(
        receipts.iter().map(|r| r.role.as_str()).collect::<Vec<_>>(),
        vcm::BORN_UNDER_VAULT_ROLES.to_vec()
    );

    let root = repo_root();
    let template =
        std::fs::read_to_string(root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let rendered = export::render_manifest(&template, &receipts).expect("render");

    let dir = scratch("rendered");
    let path = dir.join("custody_manifest.toml");
    std::fs::write(&path, &rendered).unwrap();
    let m = vcm::load_manifest(&path).expect("rendered manifest parses");
    let v = vcm::check_partition(&root, &m);
    assert!(v.is_empty(), "rendered manifest must satisfy §P.1, got: {v:?}");
}

/// The pinned initial cursor and page limit are what actually go on the wire.
#[test]
fn pinned_cursor_and_limit_are_used() {
    let mut s = Scripted::new(healthy_pages());
    export::walk(&mut s, PINNED_PAGE_LIMIT).expect("walk");
    assert_eq!(s.seen_cursors[0], export::PINNED_INITIAL_CURSOR);
    assert_eq!(s.seen_cursors, vec![None, Some(10), Some(20)]);
    assert!(s.seen_limits.iter().all(|l| *l == PINNED_PAGE_LIMIT));
    assert!(PINNED_PAGE_LIMIT >= 1 && PINNED_PAGE_LIMIT <= export::MAX_READ_PAGE_LIMIT);
}

/// Rendering is deterministic: same input, byte-identical output.
#[test]
fn rendering_is_deterministic_and_leaves_unrelated_bytes_alone() {
    let pages = walk_ok(healthy_pages());
    let receipts = export::validate_receipts(&pages).unwrap();
    let root = repo_root();
    let template =
        std::fs::read_to_string(root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let a = export::render_manifest(&template, &receipts).unwrap();
    let b = export::render_manifest(&template, &receipts).unwrap();
    assert_eq!(a, b, "rendering must be deterministic");

    // Untouched regions survive verbatim: the axis-2 rows, the D4 facts, and
    // the ring section are all carried through byte for byte.
    for probe in [
        "[bootstrap_ring]",
        "gate_epoch = \"custody-l0-2026-08-03\"",
        "[sources.d4]",
        "collection_run = \"artifact2-2026-08-02\"",
        "field = \"STAKING_CANISTER\"",
    ] {
        assert!(a.contains(probe), "rendering dropped `{probe}`");
    }
    // Only the D5 status flipped and principals/receipts were added.
    assert!(a.contains("status = \"populated\""));
    assert_eq!(a.matches("[[sources.d5.receipts]]").count(), 9);
}

/// The hash is taken over the CANONICAL form, so transport whitespace does not
/// change it while the decoded value still does.
#[test]
fn hash_is_over_the_canonical_form_not_transport_bytes() {
    let base = healthy_pages();
    let spaced: Vec<String> = base.iter().map(|p| format!("  {p}  \n")).collect();
    let a = walk_ok(base);
    let b = walk_ok(spaced);
    assert_eq!(
        a.iter().map(|p| p.sha256.clone()).collect::<Vec<_>>(),
        b.iter().map(|p| p.sha256.clone()).collect::<Vec<_>>(),
        "whitespace must not change the page hash"
    );
    assert_ne!(a[0].raw, b[0].raw, "the raw bytes DID differ");
}

// ── Authentication ───────────────────────────────────────────────────────────

/// `None` is an UNAUTHORIZED read and a STOP. Treating it as
/// end-of-pagination would export zero receipts and call the walk complete.
#[test]
fn unauthorized_none_is_a_stop_not_end_of_pagination() {
    let mut s = Scripted::new(vec![page_text(None)]);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must STOP");
    assert!(
        matches!(e, ExportError::Unauthorized { .. }),
        "must be Unauthorized, got: {e:?}"
    );
}

/// An unauthorized page MID-walk is equally terminal — a partial export is not
/// a smaller success.
#[test]
fn unauthorized_mid_walk_is_a_stop() {
    let mut pages = healthy_pages();
    pages[1] = page_text(None);
    let mut s = Scripted::new(pages);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must STOP");
    assert!(matches!(e, ExportError::Unauthorized { cursor: Some(10) }), "got: {e:?}");
}

/// The limit is validated BEFORE any call, so a `None` can never be blamed on
/// a bad limit — which is what makes the unauthorized reading unambiguous.
#[test]
fn out_of_range_limits_are_refused_before_any_call() {
    for limit in [0u32, export::MAX_READ_PAGE_LIMIT + 1] {
        let mut s = Scripted::new(healthy_pages());
        let e = export::walk(&mut s, limit).expect_err("must refuse");
        assert!(matches!(e, ExportError::InvalidPageLimit { .. }), "got: {e:?}");
        assert!(s.seen_cursors.is_empty(), "no call may be made with a bad limit");
    }
}

// ── Pagination ───────────────────────────────────────────────────────────────

#[test]
fn non_advancing_cursor_fails() {
    let pages = vec![page_text(Some(CreationReceiptPage {
        items: vec![],
        next_cursor: Some(0),
    }))];
    // First page is fetched at cursor None, so 0 is progress; the SECOND hand
    // back of 0 is not.
    let pages = [pages, vec![page_text(Some(CreationReceiptPage {
        items: vec![],
        next_cursor: Some(0),
    }))]]
    .concat();
    let mut s = Scripted::new(pages);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must fail");
    assert!(
        matches!(e, ExportError::CursorNonProgress { .. }),
        "got: {e:?}"
    );
}

/// A repeated cursor is refused. Under STRICT monotonic progress a repeat is
/// necessarily also a non-advance, so this is the error the walk reports
/// first; the explicit cycle guard behind it is defence in depth, not the
/// primary control. The property under test is that the walk cannot revisit a
/// cursor, not which of the two guards names it.
#[test]
fn repeated_cursor_is_detected_as_a_cycle() {
    let p = |next: u64| {
        page_text(Some(CreationReceiptPage {
            items: vec![],
            next_cursor: Some(next),
        }))
    };
    // 5 → 9 → 5: strictly advancing each step, but 5 recurs.
    let mut s = Scripted::new(vec![p(5), p(9), p(5), p(9)]);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must fail");
    assert!(
        matches!(
            e,
            ExportError::CursorCycle { .. } | ExportError::CursorNonProgress { .. }
        ),
        "a revisited cursor must be refused, got: {e:?}"
    );
}

/// A recorded set that stops while `next_cursor` is still `Some` is TRUNCATED.
/// Under-reporting is precisely how a governed target goes missing unnoticed.
#[test]
fn truncated_sequence_fails() {
    let mut pages = walk_ok(healthy_pages());
    pages.pop();
    let e = export::verify_sequence(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::TruncatedWalk { .. }), "got: {e:?}");
}

/// A truncated RECORDING is caught at fetch time too.
#[test]
fn truncated_recording_fails_the_walk() {
    let mut pages = healthy_pages();
    pages.pop();
    let mut s = Scripted::new(pages);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must fail");
    assert!(matches!(e, ExportError::TruncatedWalk { .. }), "got: {e:?}");
}

#[test]
fn reordered_pages_fail() {
    let mut pages = walk_ok(healthy_pages());
    pages.swap(0, 1);
    let e = export::verify_sequence(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::ReorderedPages { .. }), "got: {e:?}");
}

/// A terminal page followed by more pages is a reordering, not a longer walk.
#[test]
fn pages_after_the_terminal_page_fail() {
    let mut pages = walk_ok(healthy_pages());
    let terminal = pages.pop().unwrap();
    pages.insert(0, terminal);
    let e = export::verify_sequence(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::ReorderedPages { .. }), "got: {e:?}");
}

#[test]
fn duplicated_page_fails() {
    let mut pages = walk_ok(healthy_pages());
    let dup = pages[0].clone();
    pages.insert(1, dup);
    let e = export::verify_sequence(&pages).expect_err("must fail");
    assert!(
        matches!(e, ExportError::ReorderedPages { .. } | ExportError::CursorCycle { .. }),
        "got: {e:?}"
    );
}

// ── Input integrity ──────────────────────────────────────────────────────────

/// A hand-typed / transcribed "page" is not evidence: it does not decode.
#[test]
fn manually_transcribed_page_fails() {
    let mut s = Scripted::new(vec![
        "receipts: shielded_pool = aaaaa-aa (bound, proposal 1)".to_string()
    ]);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must fail");
    assert!(matches!(e, ExportError::DecodeFailed { .. }), "got: {e:?}");
}

/// Valid Candid of the WRONG SHAPE is also refused — a page must decode as the
/// Vault's typed page, not merely as some Candid value.
#[test]
fn wrong_shaped_candid_page_fails() {
    let mut s = Scripted::new(vec!["(42 : nat64)".to_string()]);
    let e = export::walk(&mut s, PINNED_PAGE_LIMIT).expect_err("must fail");
    assert!(matches!(e, ExportError::DecodeFailed { .. }), "got: {e:?}");
}

/// A recorded page whose hash does not reproduce is rejected.
#[test]
fn hash_mismatched_page_fails() {
    let mut pages = walk_ok(healthy_pages());
    pages[0].sha256 = "0".repeat(64);
    let e = export::verify_sequence(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::HashMismatch { .. }), "got: {e:?}");
}

/// Editing the canonical body invalidates the hash — the tamper cannot pass by
/// keeping the recorded hash.
#[test]
fn edited_canonical_body_fails() {
    let mut pages = walk_ok(healthy_pages());
    pages[0].canonical.push(' ');
    let e = export::verify_sequence(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::HashMismatch { .. }), "got: {e:?}");
}

// ── The nine-receipt contract ────────────────────────────────────────────────

#[test]
fn eight_receipts_fail_cardinality() {
    let all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES[..8]
        .iter()
        .enumerate()
        .map(|(i, r)| receipt(i, r, CreationReceiptStatus::Bound))
        .collect();
    let pages = walk_ok(vec![page_text(Some(CreationReceiptPage {
        items: all,
        next_cursor: None,
    }))]);
    let e = export::validate_receipts(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::ReceiptCardinality { .. }), "got: {e:?}");
}

#[test]
fn an_orphaned_receipt_stops_the_export() {
    let mut all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES
        .iter()
        .enumerate()
        .map(|(i, r)| receipt(i, r, CreationReceiptStatus::Bound))
        .collect();
    all[3].status = CreationReceiptStatus::OrphanedPurposeConflict;
    let pages = walk_ok(vec![page_text(Some(CreationReceiptPage {
        items: all,
        next_cursor: None,
    }))]);
    let e = export::validate_receipts(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::ReceiptNotBound { .. }), "got: {e:?}");
}

#[test]
fn a_purpose_outside_the_allowlist_stops_the_export() {
    let mut all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES
        .iter()
        .enumerate()
        .map(|(i, r)| receipt(i, r, CreationReceiptStatus::Bound))
        .collect();
    all.push(receipt(99, "disposable_proof_target", CreationReceiptStatus::Bound));
    let pages = walk_ok(vec![page_text(Some(CreationReceiptPage {
        items: all,
        next_cursor: None,
    }))]);
    let e = export::validate_receipts(&pages).expect_err("must fail");
    assert!(
        matches!(&e, ExportError::PurposeNotAllowed { purpose } if purpose == "disposable_proof_target"),
        "got: {e:?}"
    );
}

#[test]
fn a_repeated_principal_stops_the_export() {
    let mut all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES
        .iter()
        .enumerate()
        .map(|(i, r)| receipt(i, r, CreationReceiptStatus::Bound))
        .collect();
    let dup = all[0].clone();
    all.push(dup);
    let pages = walk_ok(vec![page_text(Some(CreationReceiptPage {
        items: all,
        next_cursor: None,
    }))]);
    let e = export::validate_receipts(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::DuplicateReceipt { .. }), "got: {e:?}");
}

/// Two DIFFERENT principals claiming the same one-shot role.
#[test]
fn a_repeated_role_stops_the_export() {
    let mut all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES
        .iter()
        .enumerate()
        .map(|(i, r)| receipt(i, r, CreationReceiptStatus::Bound))
        .collect();
    let mut clash = all[0].clone();
    clash.principal = principal_for("impostor");
    all.push(clash);
    let pages = walk_ok(vec![page_text(Some(CreationReceiptPage {
        items: all,
        next_cursor: None,
    }))]);
    let e = export::validate_receipts(&pages).expect_err("must fail");
    assert!(matches!(e, ExportError::DuplicateReceipt { .. }), "got: {e:?}");
}

/// Nothing is rendered when validation fails — the render entry point refuses
/// a short receipt set outright.
#[test]
fn nothing_renders_without_nine_receipts() {
    let e = export::render_manifest("", &[]).expect_err("must fail");
    assert!(matches!(e, ExportError::RenderFailed { .. }), "got: {e:?}");
}

/// Rendering over an already-populated D5 is refused rather than layered.
#[test]
fn rendering_over_a_populated_d5_is_refused() {
    let pages = walk_ok(healthy_pages());
    let receipts = export::validate_receipts(&pages).unwrap();
    let root = repo_root();
    let template =
        std::fs::read_to_string(root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let once = export::render_manifest(&template, &receipts).unwrap();
    let e = export::render_manifest(&once, &receipts).expect_err("must refuse");
    assert!(matches!(e, ExportError::RenderFailed { .. }), "got: {e:?}");
}

// ── The ceremony verification root ───────────────────────────────────────────

#[test]
fn ceremony_root_records_every_hash_and_refuses_to_overwrite() {
    let pages = walk_ok(healthy_pages());
    let receipts = export::validate_receipts(&pages).unwrap();
    let root_dir = repo_root();
    let template =
        std::fs::read_to_string(root_dir.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let rendered = export::render_manifest(&template, &receipts).unwrap();

    let dest = scratch("root").join("ceremony");
    let sha = "0".repeat(40);
    let out = export::write_ceremony_root(&dest, "test", &sha, &pages, &rendered).expect("write");

    // Every page contributes a raw and a canonical artifact; plus the manifest.
    assert_eq!(out.inventory.len(), pages.len() * 2 + 1);
    assert_eq!(out.manifest_sha256, vcm::sha256_hex(rendered.as_bytes()));
    assert_eq!(out.inventory_sha256.len(), 64);
    let listing = std::fs::read_to_string(dest.join("INVENTORY")).unwrap();
    assert_eq!(vcm::sha256_hex(listing.as_bytes()), out.inventory_sha256);
    assert!(listing.starts_with("mode test\n"), "the mode is bound into the root hash");

    // Refuses to overwrite: an evidence root is written once.
    let e = export::write_ceremony_root(&dest, "test", &sha, &pages, &rendered)
        .expect_err("must refuse");
    assert!(matches!(e, ExportError::DestinationExists { .. }), "got: {e:?}");
}

/// The replay mode is stamped into the inventory, so a replay root hashes
/// differently from an authenticated export of the same bytes.
// BINDING: B-4 — the ceremony root binds its EXPORT MODE. Registered in
// tests/BINDING_REGISTRY.toml; `verify_gate_lints bindings` checks this test
// still calls write_ceremony_root twice with differing modes and still asserts
// the two inventory hashes differ.
#[test]
fn replay_and_export_roots_hash_differently() {
    let pages = walk_ok(healthy_pages());
    let receipts = export::validate_receipts(&pages).unwrap();
    let root_dir = repo_root();
    let template =
        std::fs::read_to_string(root_dir.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let rendered = export::render_manifest(&template, &receipts).unwrap();
    let sha = "0".repeat(40);
    let base = scratch("modes");
    let a = export::write_ceremony_root(&base.join("a"), "authenticated-export", &sha, &pages, &rendered)
        .unwrap();
    let b = export::write_ceremony_root(&base.join("b"), "replay", &sha, &pages, &rendered).unwrap();
    assert_ne!(a.inventory_sha256, b.inventory_sha256);
}

// ── The source clone ─────────────────────────────────────────────────────────

fn init_repo(dir: &Path) -> String {
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@example.invalid"]);
    git(&["config", "user.name", "t"]);
    std::fs::write(dir.join("a.txt"), "a\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "c"]);
    git(&["rev-parse", "HEAD"])
}

#[test]
fn clean_clone_at_the_declared_sha_verifies() {
    let dir = scratch("clone_ok");
    let head = init_repo(&dir);
    export::verify_source_clone(&dir, &head).expect("clean clone at HEAD verifies");
}

#[test]
fn wrong_sha_fails() {
    let dir = scratch("clone_wrong_sha");
    init_repo(&dir);
    let e = export::verify_source_clone(&dir, &"1".repeat(40)).expect_err("must fail");
    assert!(matches!(e, ExportError::SourceShaMismatch { .. }), "got: {e:?}");
}

#[test]
fn dirty_clone_fails() {
    let dir = scratch("clone_dirty");
    let head = init_repo(&dir);
    std::fs::write(dir.join("a.txt"), "tampered\n").unwrap();
    let e = export::verify_source_clone(&dir, &head).expect_err("must fail");
    assert!(matches!(e, ExportError::DirtySourceClone { .. }), "got: {e:?}");
}

#[test]
fn a_short_or_malformed_sha_is_refused() {
    let dir = scratch("clone_shortsha");
    init_repo(&dir);
    for given in ["e72203e", "", "zz"] {
        let e = export::verify_source_clone(&dir, given).expect_err("must fail");
        assert!(matches!(e, ExportError::MalformedSourceSha { .. }), "got: {e:?}");
    }
}

/// Adjudication §1: the ceremony-source pin is an ARGUMENT. The exporter must
/// not hardcode any commit — least of all the base it was built on, which by
/// construction cannot contain the exporter.
#[test]
fn the_exporter_hardcodes_no_commit() {
    for f in ["src/export.rs", "src/bin/export_creation_receipts.rs"] {
        let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).unwrap();
        for line in src.lines() {
            // Ignore prose that merely names the base commit in a comment.
            if line.trim_start().starts_with("//") || line.trim_start().starts_with("///") {
                continue;
            }
            assert!(
                !line.contains("e72203e") && !line.contains("caa2b29"),
                "{f} hardcodes a commit: {line}"
            );
        }
    }
}


// ── Synthetic fixture generator (evidence reproducibility) ───────────────────

/// Writes the synthetic raw pages used in the §P evidence transcript, so the
/// transcript is reproducible rather than a pasted artifact of one session:
///
///   STSH_FIXTURE_DIR=<dir> cargo test -p verify-custody-manifest \
///       --test export emit_synthetic_fixture -- --ignored --exact
///
/// Ignored by default: it writes outside the test's own scratch tree, and a
/// fixture generator is not a check.
#[test]
#[ignore = "SI-X-01: fixture GENERATOR, not a check — it writes outside the \
            test's own scratch tree into STSH_FIXTURE_DIR. Run explicitly when \
            regenerating the §P evidence transcript."]
fn emit_synthetic_fixture() {
    let dir = PathBuf::from(
        std::env::var("STSH_FIXTURE_DIR").expect("STSH_FIXTURE_DIR must name a new directory"),
    );
    assert!(!dir.exists(), "{} already exists", dir.display());
    std::fs::create_dir_all(&dir).unwrap();
    for (i, body) in healthy_pages().iter().enumerate() {
        std::fs::write(dir.join(format!("page-{i:03}.raw.candid")), body).unwrap();
    }
    println!("wrote {} synthetic pages to {}", healthy_pages().len(), dir.display());
}
