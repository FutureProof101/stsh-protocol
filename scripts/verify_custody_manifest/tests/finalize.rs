// §Q acceptance tests — the exporter's finalize+assemble phase.
//
// The centrepiece is `end_to_end_from_clean_clone_to_deploy_time_exit_zero`
// (SSA §4C correction 4): a clean pinned clone → the exact command sequence →
// `verify_custody_manifest --deploy-time <tree>` exit 0 → then a manifest
// mutation AND a ring-artifact mutation, each flipping it to a typed failure.
// Everything else here is a fail-closed negative for one named input.
//
// Both binaries are driven as PROCESSES, not as library calls, so what the
// tests exercise is the command sequence a runbook can actually contain.

use std::path::{Path, PathBuf};
use std::process::Command;
use verify_custody_manifest as vcm;
use vcm::export::{
    CreationReceipt, CreationReceiptPage, CreationReceiptStatus, ExportError,
};
use vcm::finalize::{self, ExportAttestation, FinalizeInputs};

const EXPORT_BIN: &str = env!("CARGO_BIN_EXE_export_creation_receipts");
const CHECK_BIN: &str = env!("CARGO_BIN_EXE_verify_custody_manifest");

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("finalize").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().expect("git");
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A clean immutable clone of the repository, at a SCRATCH-TREE PRE-CEREMONY
/// FREEZE COMMIT that this fixture creates itself.
///
/// WHY THE FREEZE COMMIT EXISTS — TEST HERMETICITY (SSA/CTO, §Q V2 correction
/// 2). `verify_custody_manifest --deploy-time` only compares the pinned Wasm
/// hashes at an ASSERTING head: `build.asserts_identity_at` must be a real
/// ancestor of HEAD, and no commit in `asserts_identity_at..HEAD` may touch a
/// production build input (`BUILD_INPUT_PATHS`). Cloning the repository at
/// whatever master happens to be makes that condition a property of the DAY:
/// the moment an unrelated production commit lands, the release record goes
/// non-asserting and the positive control of every end-to-end test here fails
/// before the mutation under test is ever reached. That is precisely what
/// happened when W2 2-1 landed, and a test whose outcome flips because an
/// unrelated item landed on master is not a regression test.
///
/// The cure is NOT to relax the deploy-time assertion — the checker's
/// deploy-time proof is the whole subject of §Q — and it is NOT to touch
/// `ReleaseIdentityNotAsserted`, which is designed truth at master and is
/// resolved ONCE at the real pre-ceremony source freeze by the rebind chain.
/// The cure is for the fixture to establish its own asserted-identity condition
/// INSIDE the scratch tree, which is what a real ceremony does anyway:
///
///   freeze → rebind the release record → export → finalize+assemble → deploy
///
/// So the clone commits exactly ONE change, to
/// `deployment/mainnet/release_hashes.toml`, setting `asserts_identity_at` to
/// the clone's PRE-REBIND HEAD. That commit touches no `BUILD_INPUT_PATHS`
/// entry, so the range is quiescent and the record asserts — by construction,
/// from the clone's own history, with no dependence on master's head. The
/// pinned Wasm hashes themselves are NOT rewritten: the built artifacts really
/// must equal the pinned bytes, and that comparison is the property under test.
///
/// The commit lands on a BRANCH, not a detached HEAD, because the finalize
/// phase re-clones this clone and `git clone` only transfers commits reachable
/// from a ref.
///
/// The SHA is READ back from the clone, never written down here.
fn pinned_clone(base: &Path) -> (PathBuf, String) {
    let root = repo_root();
    let head = git(&root, &["rev-parse", "HEAD"]);
    let clone = base.join("clone");
    let out = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(&root)
        .arg(&clone)
        .output()
        .expect("git clone");
    assert!(out.status.success(), "clone: {}", String::from_utf8_lossy(&out.stderr));
    git(&clone, &["checkout", "--quiet", "-B", "ceremony-freeze", &head]);
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), head);
    assert!(git(&clone, &["status", "--porcelain"]).is_empty(), "clone must be clean");

    // ── The scratch tree's own pre-ceremony freeze ───────────────────────────
    let record = clone.join(vcm::RELEASE_RECORD_ARTIFACT);
    let body = std::fs::read_to_string(&record).expect("release record");
    let old = body
        .lines()
        .find_map(|l| l.trim().strip_prefix("asserts_identity_at = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("the release record must pin asserts_identity_at");
    let rebound = body.replace(
        &format!("asserts_identity_at = \"{old}\""),
        &format!("asserts_identity_at = \"{head}\""),
    );
    assert_ne!(rebound, body, "the freeze must actually rebind the record");
    std::fs::write(&record, &rebound).expect("write release record");
    let out = Command::new("git")
        .arg("-C")
        .arg(&clone)
        .args([
            "-c",
            "user.name=SQ Fixture",
            "-c",
            "user.email=sq-fixture@invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "test(fixture): scratch-tree pre-ceremony freeze — rebind release identity",
            "--",
            vcm::RELEASE_RECORD_ARTIFACT,
        ])
        .output()
        .expect("git commit");
    assert!(
        out.status.success(),
        "freeze commit: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let frozen = git(&clone, &["rev-parse", "HEAD"]);
    assert_ne!(frozen, head, "the freeze must advance the clone's HEAD");
    assert!(git(&clone, &["status", "--porcelain"]).is_empty(), "clone must be clean");
    // The freeze itself touches no production build input, so the record now
    // asserts at this head. Asserted BY CONSTRUCTION, checked here.
    assert!(
        git(
            &clone,
            &[
                "log",
                "--oneline",
                "--no-decorate",
                &format!("{head}..{frozen}"),
                "--",
                "canisters/",
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
            ],
        )
        .is_empty(),
        "the freeze commit must not touch a production build input"
    );
    (clone, frozen)
}

// ── Synthetic D5 pages (the same shape the §P export tests use) ──────────────

/// The pool principal RECORDED in `deployment/mainnet/custody_manifest.toml`
/// (born_under_vault entry), bound there by lane A-3 FINALIZE (2026-09-12).
const BOUND_SHIELDED_POOL: &str = "cxrfg-qaaaa-aaaar-qchfa-cai";

fn principal_for(role: &str) -> candid::Principal {
    // See tests/export.rs for the full reasoning: A-3 FINALIZE bound the pool's
    // principal in the committed manifest, and `render_manifest` refuses a
    // receipt that contradicts an already-recorded binding. A synthetic
    // principal for this one role would make the healthy fixture a
    // contradiction fixture.
    if role == "shielded_pool" {
        return candid::Principal::from_text(BOUND_SHIELDED_POOL).expect("bound pool principal");
    }
    candid::Principal::self_authenticating(role.as_bytes())
}

fn page_text(page: Option<CreationReceiptPage>) -> String {
    let bytes = candid::encode_one(&page).expect("encode");
    candid::IDLArgs::from_bytes(&bytes).expect("decode").to_string()
}

/// Nine `Bound` receipts over two pages plus a terminal page.
fn write_synthetic_pages(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let all: Vec<CreationReceipt> = vcm::BORN_UNDER_VAULT_ROLES
        .iter()
        .enumerate()
        .map(|(i, role)| CreationReceipt {
            proposal_id: i as u64 + 1,
            principal: principal_for(role),
            purpose: role.to_string(),
            disposition: stsh_custody_types::ManifestDisposition::BornUnderVault,
            created_at_ns: 1_700_000_000_000_000_000 + i as u64,
            status: CreationReceiptStatus::Bound,
        })
        .collect();
    let pages = [
        page_text(Some(CreationReceiptPage { items: all[..5].to_vec(), next_cursor: Some(10) })),
        page_text(Some(CreationReceiptPage { items: all[5..].to_vec(), next_cursor: Some(20) })),
        page_text(Some(CreationReceiptPage { items: vec![], next_cursor: None })),
    ];
    for (i, body) in pages.iter().enumerate() {
        std::fs::write(dir.join(format!("page-{i:03}.raw.candid")), body).unwrap();
    }
}

/// A synthetic bootstrap-ring ceremony artifact. Its CONTENT is ceremony-time
/// and out of scope; what matters here is that it exists and hashes.
const RING_ARTIFACT: &str = "\
# SYNTHETIC bootstrap-ring ceremony evidence (test fixture).
[ring.vault]
principal = \"synthetic-vault-principal\"
[ring.upgrader]
principal = \"synthetic-upgrader-principal\"
";

/// Run the §P export phase in replay mode; returns the export root.
///
/// The §P transcript's `mode` and `ceremony root sha256` are what the operator
/// attests to the finalize phase, so they are READ FROM THE EXPORT PHASE'S OWN
/// STDOUT here — exactly the two values a runbook copies forward — and never
/// re-read out of the root the finalize phase is about to re-prove.
fn run_export(base: &Path, clone: &Path, sha: &str) -> (PathBuf, ExportAttestation) {
    let pages = base.join("pages");
    write_synthetic_pages(&pages);
    let export_root = base.join("export-root");
    let out = Command::new(EXPORT_BIN)
        .args(["--ceremony-source-sha", sha])
        .arg("--clone")
        .arg(clone)
        .arg("--replay")
        .arg(&pages)
        .arg("--out")
        .arg(&export_root)
        .output()
        .expect("export phase");
    assert!(
        out.status.success(),
        "export phase must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let transcript = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |k: &str| -> String {
        transcript
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| panic!("the export transcript must print `{k}`:\n{transcript}"))
    };
    let attestation = ExportAttestation {
        mode: field("mode "),
        root_sha256: field("ceremony root sha256 "),
    };
    assert_eq!(attestation.mode, "replay");
    assert_eq!(attestation.root_sha256.len(), 64);
    (export_root, attestation)
}

fn ring_file(base: &Path) -> PathBuf {
    let p = base.join("ring_evidence.toml");
    std::fs::write(&p, RING_ARTIFACT).unwrap();
    p
}

fn wasm_dir() -> PathBuf {
    let d = repo_root().join(finalize::TREE_WASM_DIR);
    // R-3a: the presence assertion covers ALL TEN shipped artifacts, not
    // vault.wasm alone. The tree-assembly loop (src/finalize.rs:636-642) has
    // always read all ten; asserting only one of them meant nine could be
    // absent and the failure would surface later, as an opaque read error,
    // instead of here with the missing name.
    let missing: Vec<&str> = vcm::INLINE_PAYLOAD_ARTIFACTS
        .iter()
        .filter(|(_, f)| !d.join(f).exists())
        .map(|(_, f)| *f)
        .collect();
    assert!(
        missing.is_empty(),
        "the production Wasms must be built before this suite runs (gate phase 2/4): {:?} \
         missing under {}. This test is NOT skipped when they are absent — a skipped ceremony \
         regression is indistinguishable from a passing one.",
        missing,
        d.display()
    );
    d
}

fn inputs(
    base: &Path,
    clone: &Path,
    sha: &str,
    export_root: &Path,
    att: &ExportAttestation,
    out: &str,
) -> FinalizeInputs {
    FinalizeInputs {
        ceremony_source_sha: sha.to_string(),
        clone: clone.to_path_buf(),
        export_root: export_root.to_path_buf(),
        export_attestation: att.clone(),
        ring_artifact: ring_file(base),
        wasm_dir: wasm_dir(),
        out: base.join(out),
    }
}

/// ROT-LEDGER: put the scratch tree through its own identity rotation.
///
/// `--deploy-time` reports every deploy-time violation and exits non-zero on
/// ANY of them — it does not consult `[deploy_gate].expected_pending`, which is
/// the `--deploy-posture` stage's job. The assembled tree is a POST-ceremony
/// tree: that is why its manifest carries real D5 receipts instead of the
/// pending declaration master carries. The rotation ledger is the same class of
/// fact, so the fixture performs the rotation inside its own scratch tree, in
/// exactly the spirit of `pinned_clone` committing its own pre-ceremony freeze.
///
/// Relaxing the `exit 0` assertion instead was rejected: it is the positive
/// control this whole test exists to be.
fn rotate_scratch_tree(tree: &Path) {
    // PRE-rotation set: the ordered chain root the committed
    // `[rotation.bootstrap]` snapshot holds. POST set: canister-rooted.
    const P1: &str = "5jmfd-2u6rs-j5c3d-jhmmq-3ri63-iha4r-l5vwb-smaqn-bjodx-y4alu-qae";
    const P2: &str = "lwiax-bc6fp-osh2p-jhbyc-tpxjl-ir24x-o5pde-gtzl2-4ht56-ikt6h-oqe";
    const P3: &str = "4f6wg-dzscu-4ixsl-t57n5-tiilb-4tqcj-i6vzi-3qvqt-5y5fu-d6b6y-cae";
    const Q1: &str = "cpdab-saaaa-aaaar-qca2q-cai";
    const Q2: &str = "cgal5-eiaaa-aaaar-qca3a-cai";
    const Q3: &str = "cxrfg-qaaaa-aaaar-qchfa-cai";

    let rec_path = tree.join(vcm::VAULT_AUTHORITY_RECORD);
    let body = std::fs::read_to_string(&rec_path).expect("the authority record");

    // ROT-LEDGER-FILL (2026-09-21): the rotation has now HAPPENED, so the tree
    // this fixture clones already carries the real rotated ledger and its real
    // committed evidence. Synthesising a second pair of sequence-1 rows on top
    // of it would be a corrupt ledger, not a rotated one. The helper therefore
    // keeps its contract — "this scratch tree is rotated, and its ledger is
    // clean" — and ASSERTS it rather than manufacturing it. The synthesis below
    // is retained for a tree that is still pending, which is what a clone of any
    // pre-FILL commit is; deleting it would silently stop covering that case.
    if body.contains("state = \"rotated\"") {
        let v = vcm::check_rotation_ledger(tree);
        assert!(
            v.is_empty(),
            "the scratch tree inherits an ALREADY-rotated ledger, which must be clean before \
             --deploy-time is asked to exit 0 on it: {v:#?}"
        );
        return;
    }

    let rotated = body
        .replace("state = \"not-yet-performed\"", "state = \"rotated\"")
        .replace("upgrader = []\nvault = []\n", "");
    assert_ne!(rotated, body, "the fixture must actually flip the ledger state");

    let evidence_dir = tree.join("deployment/mainnet/evidence");
    std::fs::create_dir_all(&evidence_dir).expect("evidence dir");
    let mut rows = String::new();
    for (plane, canister, secs, utc, proposal, extra) in [
        (
            "upgrader",
            Q2,
            1_789_700_000u64,
            "2026-09-18T02:53:20Z",
            16u64,
            String::new(),
        ),
        (
            "vault",
            Q1,
            1_789_700_060,
            "2026-09-18T02:54:20Z",
            17,
            "old_epoch = 0\nnew_epoch = 1\nafter_upgrader_sequence = 1\n".to_string(),
        ),
    ] {
        let rel = format!("deployment/mainnet/evidence/{plane}_readback.txt");
        let contents = format!("{plane} read-back, complete and unedited (fixture)\n");
        std::fs::write(tree.join(&rel), &contents).expect("evidence file");
        let sha = vcm::sha256_hex(contents.as_bytes());
        rows += &format!(
            "[[rotation.{plane}]]\nsequence = 1\nstatus = \"EXECUTED\"\n\
             old_members = [\"{P1}\", \"{P2}\", \"{P3}\"]\n\
             new_members = [\"{Q1}\", \"{Q2}\", \"{Q3}\"]\n\
             old_threshold = 2\nnew_threshold = 2\n{extra}proposal_id = {proposal}\n\
             approvers = [\"{P1}\", \"{P2}\"]\n\
             observed_at_ns = {}\nobserved_at_utc = \"{utc}\"\nnetwork = \"ic\"\n\
             canister = \"{canister}\"\nread_by = \"{P1}\"\n\
             readback_command = \"dfx canister --network ic call {canister} \
             get_recovery_summary '()'\"\n\
             readback_evidence_path = \"{rel}\"\nreadback_output_sha256 = \"{sha}\"\n\
             predecessor_row_sha256 = \"\"\n\n",
            secs * 1_000_000_000,
        );
    }
    std::fs::write(&rec_path, format!("{rotated}{rows}")).expect("write the rotated record");
    assert!(
        vcm::check_rotation_ledger(tree).is_empty(),
        "the fixture's own rotated ledger must be clean: {:#?}",
        vcm::check_rotation_ledger(tree)
    );
}

fn deploy_time(tree: &Path) -> (bool, String) {
    let out = Command::new(CHECK_BIN)
        .args(["--deploy-time"])
        .arg(tree)
        .output()
        .expect("checker");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), combined)
}

// ── The end-to-end regression (SSA §4C correction 4) ─────────────────────────

#[test]
fn end_to_end_from_clean_clone_to_deploy_time_exit_zero() {
    let base = scratch("e2e");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);

    // The finalize+assemble phase, driven exactly as a runbook would.
    let out = Command::new(EXPORT_BIN)
        .arg("--finalize-assemble")
        .args(["--ceremony-source-sha", &sha])
        .arg("--clone")
        .arg(&clone)
        .arg("--export-root")
        .arg(&export_root)
        .args(["--export-mode", &att.mode])
        .args(["--export-root-sha256", &att.root_sha256])
        .arg("--ring-artifact")
        .arg(ring_file(&base))
        .arg("--wasm-dir")
        .arg(wasm_dir())
        .arg("--out")
        .arg(base.join("final"))
        .output()
        .expect("finalize phase");
    assert!(
        out.status.success(),
        "finalize+assemble must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = base.join("final/tree");
    rotate_scratch_tree(&tree);

    // POSITIVE CONTROL. Release identity asserts inside the scratch tree
    // because `pinned_clone` committed the freeze rebind there — never because
    // master happened to be quiescent today.
    let (ok, log) = deploy_time(&tree);
    assert!(
        ok,
        "--deploy-time on the assembled tree must exit 0, got:\n{log}"
    );
    assert!(
        !log.contains("RELEASE IDENTITY NOT ASSERTED"),
        "the positive control must reach an ASSERTING head inside the scratch tree, got:\n{log}"
    );

    // The finalized manifest really is final: D5 populated AND ring pointer
    // populated with the artifact's real hash.
    let manifest =
        std::fs::read_to_string(tree.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    assert_eq!(manifest.matches("[[sources.d5.receipts]]").count(), 9);
    assert!(manifest.contains("status = \"populated\""));
    assert!(
        manifest.contains(&format!(
            "evidence_sha256 = \"{}\"",
            vcm::sha256_hex(RING_ARTIFACT.as_bytes())
        )),
        "the ring pointer must carry the artifact's real hash"
    );

    // ── Mutation flip 1: the finalized manifest ──────────────────────────────
    let mutated = manifest.replacen(
        "manifest_purpose = \"treasury\"",
        "manifest_purpose = \"verifier\"",
        1,
    );
    assert_ne!(mutated, manifest, "the mutation must actually change the file");
    std::fs::write(tree.join("deployment/mainnet/custody_manifest.toml"), &mutated).unwrap();
    let (ok, log) = deploy_time(&tree);
    assert!(!ok, "a mutated manifest must FAIL --deploy-time");
    assert!(
        log.contains("RECEIPT PURPOSE MISMATCH") || log.contains("GOVERNED TARGET UNBOUND"),
        "the failure must be TYPED, got:\n{log}"
    );
    std::fs::write(tree.join("deployment/mainnet/custody_manifest.toml"), &manifest).unwrap();
    let (ok, _) = deploy_time(&tree);
    assert!(ok, "restoring the manifest must restore exit 0");

    // ── Mutation flip 2: the ring artifact ──────────────────────────────────
    let ring_in_tree = tree.join(finalize::template_ring_path(&manifest).unwrap());
    assert!(ring_in_tree.exists(), "the ring artifact must be inside the tree");
    std::fs::write(&ring_in_tree, format!("{RING_ARTIFACT}# tampered\n")).unwrap();
    let (ok, log) = deploy_time(&tree);
    assert!(!ok, "a mutated ring artifact must FAIL --deploy-time");
    assert!(
        log.contains("RING EVIDENCE UNAVAILABLE"),
        "the failure must be TYPED, got:\n{log}"
    );
    std::fs::write(&ring_in_tree, RING_ARTIFACT).unwrap();
    let (ok, _) = deploy_time(&tree);
    assert!(ok, "restoring the ring artifact must restore exit 0");

    // ── Mutation flip 3 (R-3a): one of the EIGHT NEW pins ────────────────────
    //
    // BINDING: B-R3A-RELEASE-HASH-10 (companion end-to-end arm)
    //
    // Before this lane the record pinned only vault and upgrader, so the other
    // eight shipped Wasms in this very tree could be replaced wholesale and
    // --deploy-time would still exit 0. Falsifying `treasury`'s pin — a package
    // the pre-R-3a two-element loop never visited — must now be caught, and the
    // typed failure must name the Wasm FILE (lib.rs's `{file}` interpolation),
    // not the package key.
    //
    // The tamper is applied to the SCRATCH TREE's copy of the record. The
    // committed record is never written by this test.
    let record_path = tree.join(vcm::RELEASE_RECORD_ARTIFACT);
    let record = std::fs::read_to_string(&record_path).expect("the tree carries the record");
    let treasury_pin = {
        let head = record
            .find("[wasm.treasury]")
            .expect("R-3a: the record must pin treasury among the ten shipped Wasms");
        let rest = &record[head..];
        let at = rest.find("sha256 = \"").expect("treasury row must carry sha256");
        let start = head + at + "sha256 = \"".len();
        let end = start + record[start..].find('"').unwrap();
        record[start..end].to_string()
    };
    assert_eq!(treasury_pin.len(), 64, "the treasury pin must be a full sha256");
    let tampered_record = record.replacen(&treasury_pin, &"0".repeat(64), 1);
    assert_ne!(tampered_record, record, "the mutation must actually change the file");
    std::fs::write(&record_path, &tampered_record).unwrap();
    let (ok, log) = deploy_time(&tree);
    assert!(
        !ok,
        "R-3a: a falsified treasury pin must FAIL --deploy-time; if it does not, the eight \
         non-vault/upgrader shipped Wasms are unpinned in practice. Log:\n{log}"
    );
    assert!(
        log.contains("treasury.wasm sha256"),
        "the failure must name the tampered artifact's FILE, got:\n{log}"
    );
    std::fs::write(&record_path, &record).unwrap();
    let (ok, _) = deploy_time(&tree);
    assert!(ok, "restoring the record must restore exit 0");
}

/// The recorded root still describes the tree: every inventoried file is
/// re-read from disk and the root hash re-derived. This is what makes "no
/// post-hash mutation path exists" checkable rather than asserted.
#[test]
fn the_recorded_root_hash_is_reproducible_from_the_tree() {
    let base = scratch("root_reproducible");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let o = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect("finalize");

    let mut rederived: Vec<(String, String)> = Vec::new();
    for (rel, _) in &o.tree_inventory {
        let bytes = std::fs::read(o.tree.join(rel)).expect("inventoried file present");
        rederived.push((rel.clone(), vcm::sha256_hex(&bytes)));
    }
    rederived.sort();
    assert_eq!(rederived, o.tree_inventory, "the tree inventory must describe the tree");

    let listing = finalize::root_listing(
        &o.export_mode,
        &o.ceremony_source_sha,
        &o.page_hashes,
        &o.ring_sha256,
        &o.ring_path,
        &o.manifest_sha256,
        &o.tree_inventory,
    );
    assert_eq!(vcm::sha256_hex(listing.as_bytes()), o.root_sha256);
    let written = std::fs::read_to_string(base.join("final/INVENTORY")).unwrap();
    assert_eq!(written, listing, "the written INVENTORY must be the hashed listing");

    // The root binds every named input.
    assert!(listing.contains(&format!("ceremony_source_sha {sha}")));
    assert!(listing.contains(&o.ring_sha256));
    assert!(listing.contains(&format!("final_manifest {}", o.manifest_sha256)));
    for h in &o.page_hashes {
        assert!(listing.contains(h), "page hash {h} must be bound");
    }
}

/// The committed repository is untouched: the tool writes only inside its new
/// scratch root.
#[test]
fn the_committed_repository_is_untouched() {
    let base = scratch("untouched");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let before = git(&clone, &["status", "--porcelain"]);
    finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect("finalize");
    assert_eq!(git(&clone, &["status", "--porcelain"]), before, "the clone must be untouched");
    assert!(before.is_empty());
}

/// A replay-derived root and an authenticated-export-derived root of the same
/// bytes must not share a hash.
#[test]
fn export_mode_is_carried_into_the_root_hash() {
    let base = scratch("modes");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let o = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect("finalize");
    assert_eq!(o.export_mode, "replay");
    let as_authenticated = finalize::root_listing(
        "authenticated-export",
        &o.ceremony_source_sha,
        &o.page_hashes,
        &o.ring_sha256,
        &o.ring_path,
        &o.manifest_sha256,
        &o.tree_inventory,
    );
    assert_ne!(vcm::sha256_hex(as_authenticated.as_bytes()), o.root_sha256);
}

// ── Negative controls — every named input, fail-closed and typed ─────────────

#[test]
fn a_missing_ring_artifact_fails_closed() {
    let base = scratch("ring_missing");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let mut i = inputs(&base, &clone, &sha, &export_root, &att, "final");
    i.ring_artifact = base.join("nope.toml");
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::RingArtifactUnavailable { .. }), "got: {e:?}");
}

#[test]
fn an_empty_ring_artifact_fails_closed() {
    let base = scratch("ring_empty");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let mut i = inputs(&base, &clone, &sha, &export_root, &att, "final");
    i.ring_artifact = base.join("empty.toml");
    std::fs::write(&i.ring_artifact, "").unwrap();
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::RingArtifactUnavailable { .. }), "got: {e:?}");
}

/// A ring artifact swapped AFTER finalization does not match the hash the
/// manifest pinned — the checker catches it, which is the whole point of the
/// pointer being fail-closed.
#[test]
fn a_hash_mismatched_ring_artifact_fails_the_checker() {
    let base = scratch("ring_mismatch");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let o = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect("finalize");
    rotate_scratch_tree(&o.tree);
    let (ok, log) = deploy_time(&o.tree);
    assert!(ok, "{log}");
    std::fs::write(o.tree.join(&o.ring_path), "different bytes\n").unwrap();
    let (ok, log) = deploy_time(&o.tree);
    assert!(!ok, "a swapped ring artifact must FAIL");
    assert!(log.contains("RING EVIDENCE UNAVAILABLE"), "got:\n{log}");
}

/// A ring artifact DELETED after finalization is equally fatal — absence is
/// never read as "no finding".
#[test]
fn a_deleted_ring_artifact_fails_the_checker() {
    let base = scratch("ring_deleted");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let o = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect("finalize");
    std::fs::remove_file(o.tree.join(&o.ring_path)).unwrap();
    let (ok, log) = deploy_time(&o.tree);
    assert!(!ok, "a deleted ring artifact must FAIL");
    assert!(log.contains("RING EVIDENCE UNAVAILABLE"), "got:\n{log}");
}

/// A template whose ring pointer is already populated is refused, not layered.
#[test]
fn a_pre_populated_ring_pointer_is_refused() {
    let base = scratch("prepopulated");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let o = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect("finalize");
    let finalized =
        std::fs::read_to_string(o.tree.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let e = finalize::render_ring_pointer(&finalized, &"0".repeat(64)).expect_err("must refuse");
    assert!(matches!(e, ExportError::RenderFailed { .. }), "got: {e:?}");
}

/// A pre-populated D5 template is refused by the §P renderer the phase reuses.
#[test]
fn a_pre_populated_d5_template_is_refused() {
    let base = scratch("prepopulated_d5");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    // Populate the clone's template, then point the phase at it. The clone is
    // now dirty, so this ALSO proves the clean-clone check fires first.
    let template = clone.join("deployment/mainnet/custody_manifest.toml");
    let body = std::fs::read_to_string(&template).unwrap();
    std::fs::write(&template, body.replace("receipts = []", "receipts = [] # touched")).unwrap();
    let e = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect_err("must fail");
    assert!(matches!(e, ExportError::DirtySourceClone { .. }), "got: {e:?}");
}

#[test]
fn an_existing_destination_is_refused() {
    let base = scratch("dest_exists");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let i = inputs(&base, &clone, &sha, &export_root, &att, "final");
    std::fs::create_dir_all(&i.out).unwrap();
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::DestinationExists { .. }), "got: {e:?}");
}

#[test]
fn a_dirty_clone_is_refused() {
    let base = scratch("dirty");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    std::fs::write(clone.join("DIRTY"), "x").unwrap();
    let e = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect_err("must fail");
    assert!(matches!(e, ExportError::DirtySourceClone { .. }), "got: {e:?}");
}

#[test]
fn a_wrong_ceremony_source_sha_is_refused() {
    let base = scratch("wrong_sha");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let mut i = inputs(&base, &clone, &sha, &export_root, &att, "final");
    i.ceremony_source_sha = "1".repeat(40);
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::SourceShaMismatch { .. }), "got: {e:?}");
}

#[test]
fn a_short_ceremony_source_sha_is_refused() {
    let base = scratch("short_sha");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let mut i = inputs(&base, &clone, &sha, &export_root, &att, "final");
    i.ceremony_source_sha = sha[..7].to_string();
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::MalformedSourceSha { .. }), "got: {e:?}");
}

// ── The consumed export root is re-proved, not trusted ───────────────────────

#[test]
fn an_absent_export_root_is_refused() {
    let base = scratch("no_export_root");
    let (clone, sha) = pinned_clone(&base);
    let att = ExportAttestation {
        mode: "replay".into(),
        root_sha256: "0".repeat(64),
    };
    let mut i = inputs(&base, &clone, &sha, &base.join("nothing"), &att, "final");
    i.export_root = base.join("nothing");
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::ExportRootUnusable { .. }), "got: {e:?}");
}

/// Clause: hash-check every CANONICAL page — and prove it is the HASH CHECK
/// that fires, not some earlier guard.
///
/// WHY THE MUTATION IS WELL-FORMED (SSA return on `2028ffb`). The previous
/// version of this test appended whitespace to a canonical page and accepted
/// either `ExportRootUnusable` or `HashMismatch`. A whitespace edit breaks
/// canonical FORM, so `read_export_root`'s re-canonicalization rejected it
/// before the recorded hash was ever consulted: the test proved the form check
/// and merely assumed the hash check, and the `|` meant it could not report
/// which guard had fired.
///
/// So the mutation here is a DIFFERENT, WELL-FORMED canonical page. It is
/// produced through `canonicalize_and_decode` itself, so it re-canonicalizes to
/// itself and passes canonical-form validation; it keeps `next_cursor =
/// Some(10)`, so the derived cursor chain still verifies through
/// `verify_sequence`; and the export `INVENTORY` is left completely untouched,
/// so the recorded hash still describes the ORIGINAL bytes. Every other guard
/// upstream of the hash check therefore passes, and the recorded canonical-page
/// hash is the only thing left that can catch it.
#[test]
fn an_edited_canonical_page_is_refused() {
    let base = scratch("edited_page");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);

    let p = export_root.join("page-000.canonical.candid");
    let original = std::fs::read_to_string(&p).unwrap();
    // Page 000 is fetched for the pinned initial cursor.
    let (_, decoded) = vcm::export::canonicalize_and_decode(&original, None).unwrap();
    let mut page = decoded.expect("page 000 decodes");
    assert_eq!(
        page.next_cursor,
        Some(10),
        "the fixture's page 000 hands over cursor 10"
    );
    // One field of one receipt, still a valid Bound receipt for its role: the
    // page stays well-formed and the walk stays cursor-valid.
    page.items[0].created_at_ns += 1;
    let mutated = vcm::export::canonicalize_and_decode(&page_text(Some(page)), None)
        .unwrap()
        .0;
    assert_ne!(mutated, original, "the mutation must actually change the bytes");
    // It really is canonical: re-canonicalizing is a no-op, so the form check
    // upstream of the hash check cannot be what rejects it.
    assert_eq!(
        vcm::export::canonicalize_and_decode(&mutated, None).unwrap().0,
        mutated,
        "the mutated page must itself be in canonical form"
    );
    std::fs::write(&p, &mutated).unwrap();

    // The INVENTORY is NOT updated — the recorded hash still describes the
    // original bytes, and that is the check under test.
    let e = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect_err("must fail");
    assert!(
        matches!(&e, ExportError::HashMismatch { what, expected, actual }
            if what == "page-000.canonical.candid"
                && expected == &vcm::sha256_hex(original.as_bytes())
                && actual == &vcm::sha256_hex(mutated.as_bytes())),
        "the RECORDED canonical-page hash must be what rejects a well-formed substitution, \
         got: {e:?}"
    );
}

/// Removing the terminal page truncates the walk.
#[test]
fn a_truncated_export_root_is_refused() {
    let base = scratch("truncated_export");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    for suffix in ["raw", "canonical"] {
        std::fs::remove_file(export_root.join(format!("page-002.{suffix}.candid"))).unwrap();
    }
    let e = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect_err("must fail");
    assert!(matches!(e, ExportError::TruncatedWalk { .. }), "got: {e:?}");
}

/// A raw page removed while its canonical twin stays breaks the pairing.
#[test]
fn a_half_present_page_pair_is_refused() {
    let base = scratch("half_pair");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    std::fs::remove_file(export_root.join("page-001.raw.candid")).unwrap();
    let e = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect_err("must fail");
    assert!(matches!(e, ExportError::ExportRootUnusable { .. }), "got: {e:?}");
}

/// The export root's own INVENTORY must be present and must agree.
#[test]
fn a_missing_export_inventory_is_refused() {
    let base = scratch("no_inventory");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    std::fs::remove_file(export_root.join("INVENTORY")).unwrap();
    let e = finalize::finalize_and_assemble(&inputs(&base, &clone, &sha, &export_root, &att, "final"))
        .expect_err("must fail");
    assert!(matches!(e, ExportError::ExportRootUnusable { .. }), "got: {e:?}");
}

#[test]
fn a_missing_built_wasm_is_refused() {
    let base = scratch("no_wasm");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let mut i = inputs(&base, &clone, &sha, &export_root, &att, "final");
    i.wasm_dir = base.join("empty-wasm-dir");
    std::fs::create_dir_all(&i.wasm_dir).unwrap();
    let e = finalize::finalize_and_assemble(&i).expect_err("must fail");
    assert!(matches!(e, ExportError::TreeAssemblyFailed { .. }), "got: {e:?}");
}

// ── The export phase is unchanged ────────────────────────────────────────────

/// §Q must not alter the §P export phase. Its usage without the new flag is
/// byte-identical in behaviour, which the whole §P export suite already
/// asserts; this pins the CLI contract itself.
#[test]
fn the_export_phase_cli_is_unchanged() {
    let base = scratch("cli_unchanged");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let listing = std::fs::read_to_string(export_root.join("INVENTORY")).unwrap();
    assert!(listing.starts_with("mode replay\n"));
    assert!(export_root.join("custody_manifest.toml").exists());
    // And the new flag refuses to be mixed with the old phase's flags.
    let out = Command::new(EXPORT_BIN)
        .arg("--finalize-assemble")
        .args(["--ceremony-source-sha", &sha])
        .arg("--clone")
        .arg(&clone)
        .arg("--replay")
        .arg(base.join("pages"))
        .arg("--out")
        .arg(base.join("mixed"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "mixing phases must be a usage error");
    let _ = att;

    // …and the §Q attestation flags are refused by the export phase, so an
    // operator can never believe an attestation was checked by a run that
    // never read one.
    let out = Command::new(EXPORT_BIN)
        .args(["--ceremony-source-sha", &sha])
        .arg("--clone")
        .arg(&clone)
        .arg("--replay")
        .arg(base.join("pages"))
        .args(["--export-mode", "authenticated-export"])
        .arg("--out")
        .arg(base.join("mixed2"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "§Q flags must require --finalize-assemble");
}

// ── Task 1: the export INVENTORY must prove the COMPLETE §P root ─────────────
//
// One negative per clause of the binding correction. Each runs the real §P
// export phase, tampers with exactly one thing, and points at the rejection.

/// Helper: the export root, its pristine attestation, and a finalize call over
/// whatever state the caller has left the root in.
fn finalize_over(
    base: &Path,
    clone: &Path,
    sha: &str,
    export_root: &Path,
    att: &ExportAttestation,
) -> ExportError {
    finalize::finalize_and_assemble(&inputs(base, clone, sha, export_root, att, "final"))
        .expect_err("must fail")
}

/// Clause: the recorded ceremony-source SHA must equal the finalize argument.
#[test]
fn an_export_root_recorded_for_a_different_ceremony_source_is_refused() {
    let base = scratch("inv_source_sha");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    let swapped = body.replace(
        &format!("ceremony_source_sha {sha}"),
        &format!("ceremony_source_sha {}", "a".repeat(40)),
    );
    assert_ne!(swapped, body);
    std::fs::write(&inv, swapped).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(matches!(e, ExportError::SourceShaMismatch { .. }), "got: {e:?}");
}

/// Clause: hash-check every RAW page — not canonical pages alone.
#[test]
fn an_edited_raw_page_is_refused() {
    let base = scratch("inv_raw_page");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let p = export_root.join("page-001.raw.candid");
    let body = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, format!("{body}\n")).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::HashMismatch { what, .. } if what == "page-001.raw.candid"),
        "the RAW page must be hash-checked, got: {e:?}"
    );
}

/// Clause: hash-check the RENDERED MANIFEST recorded in the export root.
#[test]
fn an_edited_export_manifest_is_refused() {
    let base = scratch("inv_manifest");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let p = export_root.join(finalize::EXPORT_MANIFEST_NAME);
    let body = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, format!("{body}# tampered\n")).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::HashMismatch { what, .. } if what == finalize::EXPORT_MANIFEST_NAME),
        "the rendered manifest must be hash-checked, got: {e:?}"
    );
}

/// Clause: reject MALFORMED inventory entries.
#[test]
fn a_malformed_inventory_line_is_refused() {
    let base = scratch("inv_malformed");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    std::fs::write(&inv, format!("{body}not-a-sha  page-999.canonical.candid\n")).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(matches!(e, ExportError::ExportRootUnusable { .. }), "got: {e:?}");
}

/// Clause: reject DUPLICATE inventory entries.
#[test]
fn a_duplicate_inventory_entry_is_refused() {
    let base = scratch("inv_duplicate");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    let dup = body
        .lines()
        .find(|l| l.ends_with("page-000.canonical.candid"))
        .expect("a canonical entry")
        .to_string();
    std::fs::write(&inv, format!("{body}{dup}\n")).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::ExportRootUnusable { detail } if detail.contains("more than once")),
        "got: {e:?}"
    );
}

/// Clause: reject MISSING inventory entries.
#[test]
fn a_missing_inventory_entry_is_refused() {
    let base = scratch("inv_missing");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    let kept: Vec<&str> = body
        .lines()
        .filter(|l| !l.ends_with("page-001.raw.candid"))
        .collect();
    std::fs::write(&inv, format!("{}\n", kept.join("\n"))).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::ExportRootUnusable { detail }
            if detail.contains("missing [\"page-001.raw.candid\"]")),
        "got: {e:?}"
    );
}

/// Clause: reject EXTRA inventory entries.
#[test]
fn an_extra_inventory_entry_is_refused() {
    let base = scratch("inv_extra");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    std::fs::write(export_root.join("SMUGGLED.toml"), "extra\n").unwrap();
    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    std::fs::write(
        &inv,
        format!("{body}{}  SMUGGLED.toml\n", vcm::sha256_hex(b"extra\n")),
    )
    .unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::ExportRootUnusable { detail }
            if detail.contains("extra [\"SMUGGLED.toml\"]")),
        "got: {e:?}"
    );
}

/// Clause: prove each RAW page canonicalizes to its PAIRED canonical page.
///
/// The raw page is rewritten to a DIFFERENT but still well-formed page, and the
/// INVENTORY is updated to its new hash — so every hash agrees and only the
/// raw↔canonical pairing is broken. Nothing but clause 6 can catch this.
#[test]
fn a_raw_page_that_does_not_canonicalize_to_its_pair_is_refused() {
    let base = scratch("inv_pairing");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let p = export_root.join("page-002.raw.candid");
    let original = std::fs::read_to_string(&p).unwrap();
    // A well-formed terminal page carrying a receipt the canonical twin does
    // not carry.
    let divergent = page_text(Some(CreationReceiptPage {
        items: vec![CreationReceipt {
            proposal_id: 99,
            principal: principal_for("smuggled"),
            purpose: "treasury".into(),
            disposition: stsh_custody_types::ManifestDisposition::BornUnderVault,
            created_at_ns: 1,
            status: CreationReceiptStatus::Bound,
        }],
        next_cursor: None,
    }));
    assert_ne!(divergent, original);
    std::fs::write(&p, &divergent).unwrap();
    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    let patched: Vec<String> = body
        .lines()
        .map(|l| {
            if l.ends_with("page-002.raw.candid") {
                format!("{}  page-002.raw.candid", vcm::sha256_hex(divergent.as_bytes()))
            } else {
                l.to_string()
            }
        })
        .collect();
    std::fs::write(&inv, format!("{}\n", patched.join("\n"))).unwrap();
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::ExportRootUnusable { detail } if detail.contains("canonicalize")),
        "got: {e:?}"
    );
}

/// Clause: reject PAGES AFTER TERMINAL PAGINATION.
///
/// The walk ends at `next_cursor = None` on page 002. A well-formed page 003
/// dropped into the root — inventoried or not — is post-terminal and must be
/// refused rather than silently ignored.
#[test]
fn a_page_after_terminal_pagination_is_refused() {
    let base = scratch("inv_post_terminal");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    let body = page_text(Some(CreationReceiptPage {
        items: vec![],
        next_cursor: None,
    }));
    for suffix in ["raw", "canonical"] {
        std::fs::write(export_root.join(format!("page-003.{suffix}.candid")), &body).unwrap();
    }
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(
        matches!(&e, ExportError::ExportRootUnusable { detail } if detail.contains("not exactly the pages")),
        "a post-terminal page must be refused, got: {e:?}"
    );
}

/// THE SHARP ONE. An edited `mode` line must NOT relabel replay evidence as an
/// authenticated export.
///
/// The attacker's best attempt: rewrite `mode replay` to `mode
/// authenticated-export` inside the export root, leaving every artifact and
/// every recorded hash untouched and self-consistent, then declare the export
/// authenticated. It fails because the mode sits inside the listing that the
/// §P root sha256 covers, and that hash was recorded OUTSIDE the root.
#[test]
fn an_edited_mode_line_cannot_relabel_replay_as_authenticated_export() {
    let base = scratch("inv_mode_relabel");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, att) = run_export(&base, &clone, &sha);
    assert_eq!(att.mode, "replay", "the fixture's export really is a replay");

    let inv = export_root.join("INVENTORY");
    let body = std::fs::read_to_string(&inv).unwrap();
    let relabelled = body.replace("mode replay\n", "mode authenticated-export\n");
    assert_ne!(relabelled, body, "the relabelling must actually change the file");
    std::fs::write(&inv, &relabelled).unwrap();
    // The root is now internally self-consistent AND claims to be an
    // authenticated export: every artifact entry still hash-checks.
    for line in relabelled.lines().filter_map(|l| l.split_once("  ")) {
        let (hash, name) = line;
        assert_eq!(
            vcm::sha256_hex(&std::fs::read(export_root.join(name)).unwrap()),
            hash,
            "the relabelled root must remain internally consistent — otherwise this test proves \
             nothing about the mode line specifically"
        );
    }

    // (a) Declaring the relabelled root authenticated — the actual attack.
    let lying = ExportAttestation {
        mode: "authenticated-export".into(),
        root_sha256: att.root_sha256.clone(),
    };
    let e = finalize_over(&base, &clone, &sha, &export_root, &lying);
    assert!(
        matches!(e, ExportError::ExportRootUnattested { .. }),
        "an edited mode line must fail against the §P-recorded root hash, got: {e:?}"
    );

    // (b) …and it also cannot be laundered by recomputing the hash of the
    //     edited listing, because the mode no longer matches what the §P
    //     transcript says the run was.
    let laundered = ExportAttestation {
        mode: "replay".into(),
        root_sha256: vcm::sha256_hex(relabelled.as_bytes()),
    };
    let e = finalize::finalize_and_assemble(&inputs(
        &base,
        &clone,
        &sha,
        &export_root,
        &laundered,
        "final2",
    ))
    .expect_err("must fail");
    assert!(
        matches!(e, ExportError::ExportModeUnattested { .. }),
        "a recomputed hash must not launder the relabelling, got: {e:?}"
    );
}

/// The attestation is not decorative: a wrong declared root hash over an
/// UNTOUCHED root is refused too.
#[test]
fn a_wrong_declared_export_root_sha256_is_refused() {
    let base = scratch("inv_wrong_root_sha");
    let (clone, sha) = pinned_clone(&base);
    let (export_root, mut att) = run_export(&base, &clone, &sha);
    att.root_sha256 = "0".repeat(64);
    let e = finalize_over(&base, &clone, &sha, &export_root, &att);
    assert!(matches!(e, ExportError::ExportRootUnattested { .. }), "got: {e:?}");
}
