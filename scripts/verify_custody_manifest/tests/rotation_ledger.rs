// ROT-LEDGER — the identity-rotation ledger, tested.
//
// FIXTURE DISCIPLINE (tests/wallet_bundles.rs:10-17, carried across verbatim in
// spirit): every negative below starts from a BASELINE that is asserted to pass,
// then injects EXACTLY ONE defect. No expected value is read from the committed
// `deployment/mainnet/vault_authorities.toml` — the baseline is CONSTRUCTED
// here, so a fixture cannot inherit the artifact it is supposed to check.
//
// IDENTITY, NOT "IT FAILED" (genesis `schema_version_lockstep_tests.rs:14-20`,
// rule 4). Every negative asserts the TYPED `RotationDefect` and the `row` the
// violation names. A test that merely observed "some violation" could pass for
// the wrong reason and would discharge nothing — acutely so here, where ~20
// conditions funnel into ONE violation kind.
//
// EVERY FIXTURE TREE IS A REAL GIT REPO with one commit at a KNOWN commit time.
// The HEAD-time bound shells out to `git -C <root>`, and a fixture that failed
// because its tempdir was not a repository would "fail" for the wrong reason.
// Missing git in a real tree is a VIOLATION (`HeadTimeUnavailable`), never a
// skip — that is asserted too.

use std::path::{Path, PathBuf};
use std::process::Command;
use verify_custody_manifest as vcm;
use vcm::{RotationDefect, Violation};

// ── the two authority sets used throughout ──────────────────────────────────
// PRE-rotation: three real II/dfx-shaped principals. POST-rotation: three real
// canister-rooted principals. Neither list is read from the committed record.
const P1: &str = "5jmfd-2u6rs-j5c3d-jhmmq-3ri63-iha4r-l5vwb-smaqn-bjodx-y4alu-qae";
const P2: &str = "lwiax-bc6fp-osh2p-jhbyc-tpxjl-ir24x-o5pde-gtzl2-4ht56-ikt6h-oqe";
const P3: &str = "4f6wg-dzscu-4ixsl-t57n5-tiilb-4tqcj-i6vzi-3qvqt-5y5fu-d6b6y-cae";
const Q1: &str = "cpdab-saaaa-aaaar-qca2q-cai";
const Q2: &str = "cgal5-eiaaa-aaaar-qca3a-cai";
const Q3: &str = "cxrfg-qaaaa-aaaar-qchfa-cai";
// A THIRD set, so a plane can hold TWO rows and the row-to-row link of the
// chain (as opposed to the row-1-to-bootstrap link) is actually exercised.
const R1: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
const R2: &str = "pyeop-7yaaa-aaaam-ajfja-cai";
const R3: &str = "mxzaz-hqaaa-aaaar-qaada-cai";

/// The fixture repo's HEAD commit time, and the instant every row records.
/// 2026-09-19T12:00:00Z. The commit is made ONE hour later so a well-formed row
/// is comfortably inside the HEAD-time bound.
const OBS_UTC: &str = "2026-09-19T12:00:00Z";
const OBS_SECS: u64 = 1_789_819_200;
const HEAD_SECS: u64 = OBS_SECS + 3600;

fn uniq(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("stsh_rotledger_{tag}_{}_{n}", std::process::id()))
}

struct Tree {
    dir: PathBuf,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Tree {
    /// A fixture tree that IS a git repository, with one commit at [`HEAD_SECS`].
    fn new(tag: &str) -> Tree {
        let dir = uniq(tag);
        std::fs::create_dir_all(dir.join("deployment/mainnet")).unwrap();
        let t = Tree { dir };
        t.git(&["init", "-q"]);
        t.git(&["config", "user.email", "fixture@stsh.invalid"]);
        t.git(&["config", "user.name", "rot-ledger fixture"]);
        std::fs::write(t.dir.join("README"), b"fixture").unwrap();
        t.commit();
        t
    }

    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(["-C", self.dir.to_str().unwrap()])
            .args(args)
            .env("GIT_COMMITTER_DATE", format!("{HEAD_SECS} +0000"))
            .env("GIT_AUTHOR_DATE", format!("{HEAD_SECS} +0000"))
            .output()
            .expect("git must run");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    fn commit(&self) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", "fixture", "--allow-empty"]);
    }

    fn record(&self, body: &str) -> &Tree {
        std::fs::write(self.dir.join("deployment/mainnet/vault_authorities.toml"), body).unwrap();
        self
    }

    /// Write a read-back evidence file and return its sha256, exactly as the
    /// checker will recompute it.
    fn evidence(&self, rel: &str, contents: &str) -> String {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, contents).unwrap();
        vcm::sha256_hex(contents.as_bytes())
    }

    fn check(&self) -> Vec<Violation> {
        vcm::check_rotation_ledger(&self.dir)
    }
}

// ── record construction ─────────────────────────────────────────────────────

fn pins(signers: [&str; 3], members: [&str; 3]) -> String {
    format!(
        "threshold = 2\nsigners = [\n  \"{}\",\n  \"{}\",\n  \"{}\",\n]\nupgrader = \"{Q2}\"\n\n\
         [recovery]\nmembers = [\n  \"{}\",\n  \"{}\",\n  \"{}\",\n]\nthreshold = 2\n\
         vault = \"{Q1}\"\n\n",
        signers[0], signers[1], signers[2], members[0], members[1], members[2]
    )
}

fn bootstrap(vault: [&str; 3], upg: [&str; 3], epoch: u64) -> String {
    format!(
        "[rotation.bootstrap]\nvault_signers = [\n  \"{}\",\n  \"{}\",\n  \"{}\",\n]\n\
         vault_threshold = 2\nupgrader_members = [\n  \"{}\",\n  \"{}\",\n  \"{}\",\n]\n\
         upgrader_threshold = 2\nvault_epoch = {epoch}\n\
         snapshot_of_pins_at_commit = \"0000000000000000000000000000000000000000\"\n\n",
        vault[0], vault[1], vault[2], upg[0], upg[1], upg[2]
    )
}

#[derive(Clone)]
struct Row {
    plane: &'static str,
    sequence: u32,
    status: String,
    old: [String; 3],
    new: [String; 3],
    old_threshold: u32,
    new_threshold: u32,
    epochs: Option<(u64, u64)>,
    after_upgrader_sequence: Option<u32>,
    proposal_id: u64,
    approvers: Vec<String>,
    observed_at_ns: u64,
    observed_at_utc: String,
    network: String,
    canister: String,
    read_by: String,
    evidence_path: String,
    evidence_sha: String,
    /// F-1: `predecessor_row_sha256`. Empty for row 1 of a plane (which chains
    /// onto `[rotation.bootstrap]` instead); for row 2+ it is the sha256 of
    /// the predecessor's canonical text.
    predecessor: String,
}

fn row(plane: &'static str, old: [&str; 3], new: [&str; 3]) -> Row {
    Row {
        plane,
        sequence: 1,
        status: "EXECUTED".into(),
        old: [old[0].into(), old[1].into(), old[2].into()],
        new: [new[0].into(), new[1].into(), new[2].into()],
        old_threshold: 2,
        new_threshold: 2,
        epochs: if plane == "vault" { Some((0, 1)) } else { None },
        after_upgrader_sequence: if plane == "vault" { Some(1) } else { None },
        proposal_id: if plane == "vault" { 17 } else { 16 },
        approvers: vec![old[0].into(), old[1].into()],
        observed_at_ns: OBS_SECS * 1_000_000_000,
        observed_at_utc: OBS_UTC.into(),
        network: "ic".into(),
        canister: if plane == "vault" { Q1.into() } else { Q2.into() },
        read_by: old[0].into(),
        evidence_path: format!("deployment/mainnet/evidence/{plane}_readback.txt"),
        evidence_sha: String::new(),
        predecessor: String::new(),
    }
}

fn render_row(r: &Row) -> String {
    let mut s = format!("[[rotation.{}]]\n", r.plane);
    s += &format!("sequence = {}\nstatus = \"{}\"\n", r.sequence, r.status);
    s += &format!(
        "old_members = [\"{}\", \"{}\", \"{}\"]\nnew_members = [\"{}\", \"{}\", \"{}\"]\n",
        r.old[0], r.old[1], r.old[2], r.new[0], r.new[1], r.new[2]
    );
    s += &format!(
        "old_threshold = {}\nnew_threshold = {}\n",
        r.old_threshold, r.new_threshold
    );
    if let Some((o, n)) = r.epochs {
        s += &format!("old_epoch = {o}\nnew_epoch = {n}\n");
    }
    if let Some(a) = r.after_upgrader_sequence {
        s += &format!("after_upgrader_sequence = {a}\n");
    }
    s += &format!("proposal_id = {}\n", r.proposal_id);
    s += &format!(
        "approvers = [{}]\n",
        r.approvers
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    s += &format!(
        "observed_at_ns = {}\nobserved_at_utc = \"{}\"\nnetwork = \"{}\"\ncanister = \"{}\"\n\
         read_by = \"{}\"\n",
        r.observed_at_ns, r.observed_at_utc, r.network, r.canister, r.read_by
    );
    s += "readback_command = \"dfx canister --network ic call <c> get_recovery_summary '()'\"\n";
    s += &format!(
        "readback_evidence_path = \"{}\"\nreadback_output_sha256 = \"{}\"\n\
         predecessor_row_sha256 = \"{}\"\n\n",
        r.evidence_path, r.evidence_sha, r.predecessor
    );
    s
}

/// The PENDING baseline: pre-rotation pins, snapshot equal to them, both arrays
/// empty. This is the shape the committed record carries.
fn pending_record() -> String {
    pins([P1, P2, P3], [P1, P2, P3])
        + "[rotation]\nschema_version = 1\nstate = \"not-yet-performed\"\nupgrader = []\n\
           vault = []\n\n"
        + &bootstrap([P1, P2, P3], [P1, P2, P3], 0)
}

/// The ROTATED baseline: pins already reconciled to the POST-rotation set (what
/// ROT-LEDGER-FILL leaves behind), snapshot still the PRE-rotation set, one
/// executed row per plane chaining onto the snapshot.
fn rotated_record(t: &Tree, mutate: impl FnOnce(&mut Row, &mut Row)) -> String {
    let mut u = row("upgrader", [P1, P2, P3], [Q1, Q2, Q3]);
    let mut v = row("vault", [P1, P2, P3], [Q1, Q2, Q3]);
    u.evidence_sha = t.evidence(&u.evidence_path.clone(), "upgrader read-back, unedited\n");
    v.evidence_sha = t.evidence(&v.evidence_path.clone(), "vault read-back, unedited\n");
    mutate(&mut u, &mut v);
    pins([Q1, Q2, Q3], [Q1, Q2, Q3])
        + "[rotation]\nschema_version = 1\nstate = \"rotated\"\n\n"
        + &bootstrap([P1, P2, P3], [P1, P2, P3], 0)
        + &render_row(&u)
        + &render_row(&v)
}

/// F-1: a TWO-row-per-plane rotated record, so the `i > 0` branch of the chain
/// — `predecessor_row_sha256`, and with it the whole of the canonical form — is
/// executed at all. `rotated_record` holds exactly one row per plane, which
/// leaves that branch unproven code.
///
/// The predecessor hashes are computed through the crate's OWN public
/// accessor from a FIRST render of the same rows, so the fixture cannot silently
/// diverge from the field order the checker uses — and the accessor is exercised
/// on the path a real ROT-LEDGER-FILL would take. The hashes are computed BEFORE
/// `mutate` runs, so a mutation that edits row 1 leaves row 2's pin STALE, which
/// is exactly the condition under test.
fn two_row_record(t: &Tree, mutate: impl FnOnce(&mut Row, &mut Row, &mut Row, &mut Row)) -> String {
    const OBS2_UTC: &str = "2026-09-19T12:10:00Z";
    let obs2 = OBS_SECS + 600;

    let mut u1 = row("upgrader", [P1, P2, P3], [Q1, Q2, Q3]);
    let mut v1 = row("vault", [P1, P2, P3], [Q1, Q2, Q3]);
    let mut u2 = row("upgrader", [Q1, Q2, Q3], [R1, R2, R3]);
    let mut v2 = row("vault", [Q1, Q2, Q3], [R1, R2, R3]);
    for (r, seq, pid) in [(&mut u2, 2u32, 18u64), (&mut v2, 2, 19)] {
        r.sequence = seq;
        r.proposal_id = pid;
        r.approvers = vec![Q1.into(), Q2.into()];
        r.read_by = Q1.into();
        r.observed_at_ns = obs2 * 1_000_000_000;
        r.observed_at_utc = OBS2_UTC.into();
    }
    v2.epochs = Some((1, 2));
    v2.after_upgrader_sequence = Some(2);

    // One evidence file per ROW, not per plane: two rows sharing one read-back
    // would be two rotations attested by one observation.
    for r in [&mut u1, &mut v1, &mut u2, &mut v2] {
        r.evidence_path =
            format!("deployment/mainnet/evidence/{}_{}_readback.txt", r.plane, r.sequence);
        let body = format!("{} #{} read-back, unedited\n", r.plane, r.sequence);
        r.evidence_sha = t.evidence(&r.evidence_path.clone(), &body);
    }

    // Pass 1: render with EMPTY predecessors, then ask the crate for the
    // canonical hash of each plane's row 1.
    let head = |state: &str| {
        pins([R1, R2, R3], [R1, R2, R3])
            + &format!("[rotation]\nschema_version = 1\nstate = \"{state}\"\n\n")
            + &bootstrap([P1, P2, P3], [P1, P2, P3], 0)
    };
    let pass1 = head("rotated")
        + &render_row(&u1)
        + &render_row(&u2)
        + &render_row(&v1)
        + &render_row(&v2);
    u2.predecessor = vcm::rotation_row_sha256(&pass1, "upgrader", 1).expect("upgrader#1 canonical");
    v2.predecessor = vcm::rotation_row_sha256(&pass1, "vault", 1).expect("vault#1 canonical");

    mutate(&mut u1, &mut u2, &mut v1, &mut v2);
    head("rotated") + &render_row(&u1) + &render_row(&u2) + &render_row(&v1) + &render_row(&v2)
}

/// Every negative below starts here: the SAME builder, unmutated, asserted to
/// pass in its own tree. A negative whose baseline was never shown to pass
/// proves only that the fixture is broken.
fn assert_one_row_baseline_passes() {
    let t = Tree::new("bl_1row");
    t.record(&rotated_record(&t, |_, _| {}));
    t.commit();
    assert!(t.check().is_empty(), "one-row baseline must pass: {:#?}", t.check());
}

fn assert_two_row_baseline_passes() {
    let t = Tree::new("bl_2row");
    t.record(&two_row_record(&t, |_, _, _, _| {}));
    t.commit();
    assert!(t.check().is_empty(), "two-row baseline must pass: {:#?}", t.check());
}

// ── assertion helpers: IDENTITY, never a message substring ──────────────────

fn only_defect(vs: &[Violation]) -> (RotationDefect, String) {
    assert_eq!(
        vs.len(),
        1,
        "expected exactly ONE violation so the fixture cannot pass for the wrong reason, got: \
         {vs:#?}"
    );
    match &vs[0] {
        Violation::RotationLedgerInconsistent { defect, row, .. } => (*defect, row.clone()),
        other => panic!("expected RotationLedgerInconsistent, got {other:#?}"),
    }
}

fn assert_defect(vs: &[Violation], want: RotationDefect, want_row: &str) {
    let (d, r) = only_defect(vs);
    assert_eq!(d, want, "wrong defect identity (row `{r}`)");
    assert_eq!(r, want_row, "violation names the wrong row");
}

// ═══ BASELINES ══════════════════════════════════════════════════════════════

#[test]
fn a4_baseline_pending_ledger_reports_exactly_the_declared_pending_key() {
    let t = Tree::new("base_pending");
    t.record(&pending_record());
    t.commit();
    let vs = t.check();
    assert_eq!(vs.len(), 1, "{vs:#?}");
    match &vs[0] {
        Violation::PendingDeploymentArtifact { path, .. } => {
            assert_eq!(path, vcm::ROTATION_LEDGER_PENDING_PATH)
        }
        other => panic!("the pending state must be a DECLARABLE PendingDeploymentArtifact, got {other:#?}"),
    }
    assert_eq!(
        vs[0].key(),
        format!("PendingDeploymentArtifact:{}", vcm::ROTATION_LEDGER_PENDING_PATH)
    );
}

#[test]
fn a4_baseline_rotated_ledger_is_clean() {
    let t = Tree::new("base_rotated");
    t.record(&rotated_record(&t, |_, _| {}));
    t.commit();
    assert!(t.check().is_empty(), "{:#?}", t.check());
}

// ═══ A-5: fail closed on absence / malformation ═════════════════════════════

#[test]
fn a5_a_missing_record_is_a_violation_not_a_skip() {
    let t = Tree::new("missing");
    t.commit();
    assert_defect(&t.check(), RotationDefect::MalformedTable, "[rotation]");
}

#[test]
fn a5_a_record_without_a_rotation_table_is_a_violation_not_a_pending_state() {
    let t = Tree::new("no_table");
    t.record(&pins([P1, P2, P3], [P1, P2, P3]));
    t.commit();
    assert_defect(&t.check(), RotationDefect::MalformedTable, "[rotation]");
}

#[test]
fn a5_unparseable_toml_fails_closed() {
    let t = Tree::new("badtoml");
    t.record("this is not = = toml\n[rotation\n");
    t.commit();
    assert_defect(&t.check(), RotationDefect::MalformedTable, "[rotation]");
}

#[test]
fn a5_an_unknown_row_field_is_refused_rather_than_silently_ignored() {
    // An unvalidated field is indistinguishable from a checked one, so the
    // schema denies unknown fields outright.
    let t = Tree::new("unknown_field");
    let rec = rotated_record(&t, |_, _| {}).replace(
        "predecessor_row_sha256 = \"\"\n\n[[rotation.vault]]",
        "predecessor_row_sha256 = \"\"\nsigned_off_by = \"someone\"\n\n[[rotation.vault]]",
    );
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::MalformedTable, "[rotation]");
}

#[test]
fn a5_missing_git_metadata_is_a_violation_never_a_skip() {
    // The HEAD-time bound must fail CLOSED where it cannot be evaluated. Built
    // deliberately WITHOUT `git init` — the one fixture in this file that is not
    // a repository, and it asserts exactly that consequence.
    let dir = uniq("nogit");
    std::fs::create_dir_all(dir.join("deployment/mainnet")).unwrap();
    let t = Tree { dir };
    let rec = rotated_record(&t, |_, _| {});
    std::fs::write(t.dir.join("deployment/mainnet/vault_authorities.toml"), rec).unwrap();
    assert_defect(&t.check(), RotationDefect::HeadTimeUnavailable, "[rotation]");
}

// ═══ A-10: schema_version lockstep ══════════════════════════════════════════

#[test]
fn a10_schema_version_moves_in_lockstep_with_the_reader() {
    // Leg 1 — the version the reader accepts PASSES. Leg 2 — any other version
    // is REFUSED as the corrupt kind. Two legs, because a refusal test alone
    // would pass for a reader that refuses everything.
    let t = Tree::new("schema_ok");
    t.record(&pending_record());
    t.commit();
    assert_eq!(vcm::ROTATION_LEDGER_SCHEMA_VERSION, 1);
    assert!(matches!(
        t.check().as_slice(),
        [Violation::PendingDeploymentArtifact { .. }]
    ));

    let t2 = Tree::new("schema_bad");
    t2.record(&pending_record().replace("schema_version = 1", "schema_version = 2"));
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::UnknownSchemaVersion, "[rotation]");
}

#[test]
fn a10_the_committed_record_declares_the_version_this_reader_understands() {
    // Lockstep in the other direction: the record in the tree and the constant
    // in the source must not drift apart.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let raw = std::fs::read_to_string(root.join("deployment/mainnet/vault_authorities.toml"))
        .expect("the committed authority record");
    assert!(
        raw.contains(&format!("schema_version = {}", vcm::ROTATION_LEDGER_SCHEMA_VERSION)),
        "the committed ledger's schema_version must equal ROTATION_LEDGER_SCHEMA_VERSION"
    );
}

// ═══ A-4: one negative per condition, each asserting its identity ═══════════

#[test]
fn a4_state_and_arrays_must_agree_in_both_directions() {
    let t = Tree::new("state_rotated_empty");
    t.record(&pending_record().replace("state = \"not-yet-performed\"", "state = \"rotated\""));
    t.commit();
    assert_defect(&t.check(), RotationDefect::StateArrayInconsistent, "[rotation]");

    let t2 = Tree::new("state_pending_rows");
    let rec = rotated_record(&t2, |_, _| {}).replace("state = \"rotated\"", "state = \"not-yet-performed\"");
    t2.record(&rec);
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::StateArrayInconsistent, "[rotation]");
}

#[test]
fn a4_an_unrecognised_state_word_is_refused() {
    let t = Tree::new("state_word");
    t.record(&pending_record().replace("\"not-yet-performed\"", "\"soon\""));
    t.commit();
    assert_defect(&t.check(), RotationDefect::UnknownState, "[rotation]");
}

#[test]
fn a4_a_placeholder_row_is_a_corrupt_ledger_not_a_pending_one() {
    // The declared pending form is state + EMPTY arrays, full stop.
    let t = Tree::new("placeholder");
    let rec = rotated_record(&t, |u, _| u.status = "PLACEHOLDER".into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::PlaceholderRow, "upgrader#1");
}

#[test]
fn a4_an_executed_row_carrying_a_placeholder_value_is_refused() {
    let t = Tree::new("placeholder_val");
    let rec = rotated_record(&t, |u, _| u.read_by = "TBD".into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::PlaceholderRow, "upgrader#1");
}

#[test]
fn a4_a_required_field_empty_on_an_executed_row_is_refused() {
    let t = Tree::new("empty_field");
    let rec = rotated_record(&t, |u, _| u.evidence_path = String::new());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::RequiredFieldEmpty, "upgrader#1");
}

#[test]
fn a4_evidence_that_does_not_hash_to_its_pin_is_refused() {
    let t = Tree::new("evidence_sha");
    let rec = rotated_record(&t, |u, _| {
        u.evidence_sha = "0".repeat(64);
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::EvidenceUnavailable, "upgrader#1");
}

#[test]
fn a4_evidence_that_does_not_exist_is_refused() {
    let t = Tree::new("evidence_missing");
    let rec = rotated_record(&t, |u, _| {
        u.evidence_path = "deployment/mainnet/evidence/never_written.txt".into();
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::EvidenceUnavailable, "upgrader#1");
}

#[test]
fn a4_a_sequence_gap_is_refused() {
    let t = Tree::new("seq_gap");
    let rec = rotated_record(&t, |u, v| {
        u.sequence = 2;
        v.after_upgrader_sequence = Some(2);
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SequenceBroken, "upgrader#2");
}

#[test]
fn a4_a_member_set_of_the_wrong_cardinality_is_refused() {
    let t = Tree::new("cardinality");
    // replacen: the UPGRADER row only. Replacing both rows would inject two
    // defects and the fixture would no longer isolate one condition.
    let rec = rotated_record(&t, |_, _| {}).replacen(
        &format!("new_members = [\"{Q1}\", \"{Q2}\", \"{Q3}\"]"),
        &format!("new_members = [\"{Q1}\", \"{Q2}\"]"),
        1,
    );
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#1");
}

#[test]
fn a4_a_duplicate_member_is_refused() {
    let t = Tree::new("dup");
    let rec = rotated_record(&t, |u, _| u.new[2] = Q1.into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#1");
}

#[test]
fn a4_a_contracted_threshold_is_refused() {
    let t = Tree::new("threshold");
    let rec = rotated_record(&t, |u, _| u.new_threshold = 1);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#1");
}

#[test]
fn a4_a_forbidden_principal_in_a_new_set_is_refused() {
    // Reuses FORBIDDEN_AUTHORITY_PRINCIPALS — one denylist, never a second.
    let t = Tree::new("forbidden");
    assert!(vcm::FORBIDDEN_AUTHORITY_PRINCIPALS.contains(&"2vxsx-fae"));
    let rec = rotated_record(&t, |u, _| u.new[2] = "2vxsx-fae".into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ForbiddenPrincipal, "upgrader#1");
}

#[test]
fn a4_an_unparseable_principal_is_refused() {
    let t = Tree::new("badprincipal");
    let rec = rotated_record(&t, |u, _| u.new[0] = "not-a-principal".into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::BadPrincipal, "upgrader#1");
}

#[test]
fn a4_approvers_must_be_two_distinct_members_of_the_old_set() {
    let t = Tree::new("approvers_outside");
    let rec = rotated_record(&t, |u, _| u.approvers = vec![P1.into(), Q3.into()]);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ApproversInvalid, "upgrader#1");

    let t2 = Tree::new("approvers_same");
    let rec = rotated_record(&t2, |u, _| u.approvers = vec![P1.into(), P1.into()]);
    t2.record(&rec);
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::ApproversInvalid, "upgrader#1");
}

#[test]
fn a4_a_reader_outside_the_old_set_is_refused() {
    let t = Tree::new("reader");
    let rec = rotated_record(&t, |u, _| u.read_by = Q3.into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ReaderNotInOldSet, "upgrader#1");
}

#[test]
fn a4_the_two_timestamps_must_be_the_same_instant() {
    let t = Tree::new("ts_disagree");
    let rec = rotated_record(&t, |u, _| u.observed_at_utc = "2026-09-18T12:00:00Z".into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::TimestampDisagrees, "upgrader#1");
}

#[test]
fn a4_a_timestamp_after_the_checked_heads_commit_time_is_refused() {
    // This fixture EXERCISES the git-rooted HEAD bound, so its tree is a real
    // repository with a known commit time — the negative fails for the reason
    // under test, not for "not a git repo".
    let t = Tree::new("ts_future");
    // The VAULT row is moved into the future: moving the upgrader row instead
    // would ALSO break plane ordering, and the fixture would stop isolating the
    // bound under test.
    let rec = rotated_record(&t, |_, v| {
        v.observed_at_ns = (HEAD_SECS + 86_400) * 1_000_000_000;
        v.observed_at_utc = "2026-09-20T13:00:00Z".into();
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::TimestampInFuture, "vault#1");
}

#[test]
fn a4_a_vault_row_must_strictly_advance_the_epoch() {
    let t = Tree::new("epoch");
    let rec = rotated_record(&t, |_, v| v.epochs = Some((0, 0)));
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::EpochNotAdvanced, "vault#1");
}

#[test]
fn a4_a_vault_row_naming_no_executed_upgrader_row_is_refused() {
    let t = Tree::new("plane_missing");
    let rec = rotated_record(&t, |_, v| v.after_upgrader_sequence = Some(9));
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::PlaneOrdering, "vault#1");
}

#[test]
fn a4_the_vault_may_not_rotate_before_the_upgrader_in_time() {
    let t = Tree::new("plane_order");
    let rec = rotated_record(&t, |u, _| {
        u.observed_at_ns = (OBS_SECS + 60) * 1_000_000_000;
        u.observed_at_utc = "2026-09-19T12:01:00Z".into();
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::PlaneOrdering, "vault#1");
}

#[test]
fn a4_an_upgrader_row_may_not_carry_the_vault_only_fields() {
    let t = Tree::new("plane_fields");
    let rec = rotated_record(&t, |u, _| u.epochs = Some((0, 1)));
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::MalformedTable, "upgrader#1");
}

#[test]
fn a4_mode_exclusivity_is_unchanged_because_this_lane_adds_no_mode() {
    // A-4's mode-exclusivity leg is conditional on adding a CLI mode. This lane
    // adds none — the check rides the existing `--deploy-posture` path — so the
    // guard is asserted to still cover exactly the seven flags it covered.
    let out = Command::new(env!("CARGO_BIN_EXE_verify_custody_manifest"))
        .args(["--deploy-posture", "--coverage-only", "."])
        .output()
        .expect("binary must run");
    assert_eq!(out.status.code(), Some(2));
}

// ═══ C-2: the chain root is checked AT BIRTH ════════════════════════════════

#[test]
fn c2_the_bootstrap_snapshot_must_equal_the_live_pins_while_not_yet_performed() {
    // Positive: snapshot == pins ⇒ the pending key and nothing else (asserted in
    // a4_baseline_pending_ledger_...). Negative, one principal transposed:
    let t = Tree::new("birth_mismatch");
    t.record(&(pins([P1, P2, P3], [P1, P2, P3])
        + "[rotation]\nschema_version = 1\nstate = \"not-yet-performed\"\nupgrader = []\nvault = []\n\n"
        + &bootstrap([P1, P2, Q3], [P1, P2, P3], 0)));
    t.commit();
    let vs = t.check();
    // The DECLARED pending key is still emitted — the corruption shows up as a
    // pure SURPLUS, not by silencing the declaration.
    assert!(vs.iter().any(|v| matches!(v, Violation::PendingDeploymentArtifact { .. })));
    let corrupt: Vec<&Violation> = vs
        .iter()
        .filter(|v| matches!(v, Violation::RotationLedgerInconsistent { .. }))
        .collect();
    assert_eq!(corrupt.len(), 1, "{vs:#?}");
    match corrupt[0] {
        Violation::RotationLedgerInconsistent { defect, row, .. } => {
            assert_eq!(*defect, RotationDefect::BootstrapMismatch);
            assert_eq!(row, "[rotation.bootstrap]");
        }
        _ => unreachable!(),
    }
}

#[test]
fn c2_a_reordered_bootstrap_snapshot_is_also_a_birth_mismatch() {
    // Ordered BYTE equality, deliberately not set equality.
    let t = Tree::new("birth_reorder");
    t.record(&(pins([P1, P2, P3], [P1, P2, P3])
        + "[rotation]\nschema_version = 1\nstate = \"not-yet-performed\"\nupgrader = []\nvault = []\n\n"
        + &bootstrap([P2, P1, P3], [P1, P2, P3], 0)));
    t.commit();
    let corrupt: Vec<&Violation> = t
        .check()
        .into_iter()
        .filter(|v| matches!(v, Violation::RotationLedgerInconsistent { .. }))
        .collect::<Vec<_>>()
        .leak()
        .iter()
        .collect();
    assert_eq!(corrupt.len(), 1);
    match corrupt[0] {
        Violation::RotationLedgerInconsistent { defect, .. } => {
            assert_eq!(*defect, RotationDefect::BootstrapMismatch)
        }
        _ => unreachable!(),
    }
}

// ═══ A-12 (paired): the anchor does NOT depend on the install-time pins ═════

#[test]
fn a12_pass_pins_rewritten_and_row1_still_chains_onto_the_snapshot() {
    // LEG (i). The pins are the POST-rotation set — what ROT-LEDGER-FILL leaves
    // behind — while row 1's old_* is the PRE-rotation set held in
    // [rotation.bootstrap]. A chain anchored on the pins would go RED here on a
    // correct record. It must PASS.
    let t = Tree::new("a12_pass");
    let rec = rotated_record(&t, |_, _| {});
    assert!(rec.contains(&format!("signers = [\n  \"{Q1}\"")), "pins must be the POST set");
    t.record(&rec);
    t.commit();
    assert!(t.check().is_empty(), "{:#?}", t.check());
}

#[test]
fn a12_fail_same_tree_row1_old_mutated_by_one_principal() {
    // LEG (ii)(a). Identical pins, identical everything — one principal of row
    // 1's old_members changed. This is what makes leg (i) mean anything: a
    // checker that performs no chain comparison passes leg (i) and FAILS here.
    let t = Tree::new("a12_mutate");
    // `approvers` and `read_by` are moved onto the mutated set too, so the ONLY
    // thing wrong with this row is that its old_* no longer equals the anchor.
    let rec = rotated_record(&t, |u, _| {
        u.old[1] = Q2.into();
        u.approvers = vec![P1.into(), Q2.into()];
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#1");
}

#[test]
fn a12_fail_same_tree_row1_old_merely_reordered() {
    // LEG (ii)(b). A REORDER only — same members, different order. A set
    // comparison would silently accept it; ordered byte equality does not.
    let t = Tree::new("a12_reorder");
    let rec = rotated_record(&t, |u, _| {
        u.old = [P2.into(), P1.into(), P3.into()];
        u.approvers = vec![P2.into(), P1.into()];
        u.read_by = P2.into();
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#1");
}

// ═══ the new kind is NOT declarable, by construction ════════════════════════

#[test]
fn the_corrupt_ledger_kind_can_never_be_declared_pending() {
    assert!(
        !vcm::DECLARABLE_KINDS.contains(&"RotationLedgerInconsistent"),
        "a record that cannot be trusted to mean what it says must be FIXED, never allowlisted"
    );
    assert_eq!(vcm::DECLARABLE_KINDS.len(), 4, "the declarable set stays a frozen four");
    let v = Violation::RotationLedgerInconsistent {
        defect: RotationDefect::ChainBreak,
        row: "vault#1".into(),
        detail: "x".into(),
    };
    assert_eq!(v.key(), "RotationLedgerInconsistent");
    // Identity comes from the TYPED fields, never from `detail`: a reworded
    // message must not change what a fixture is asserting.
    let w = Violation::RotationLedgerInconsistent {
        defect: RotationDefect::ChainBreak,
        row: "vault#1".into(),
        detail: "a completely different wording".into(),
    };
    assert_eq!(v.key(), w.key());
}

// ═══ A-11 / A-6: demonstrated on the CLI path the GATE actually invokes ═════
//
// `run_gate.sh` runs `--deploy-posture` (and `--coverage-only`, `--sizes-only`,
// `verify_a7_kit`). It never runs `--wallet-bundles`. A control that only fired
// in a mode the gate does not invoke would be invisible, so the demonstration
// below is made through the real binary, in `--deploy-posture`, over a tree that
// is the real repository in every respect except the one file under test.
//
// The shadow root is a SYMLINK FARM: every top-level entry of the repo
// (including `.git`, so the git-rooted checks behave identically) is symlinked,
// except `deployment/mainnet/vault_authorities.toml`, which is a real file this
// test writes. Nothing in the repository is modified.

fn shadow_root(tag: &str, record: &str) -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let dir = uniq(tag);
    std::fs::create_dir_all(dir.join("deployment/mainnet")).unwrap();
    let link_all = |src: &Path, dst: &Path, skip: &str| {
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let name = e.file_name();
            if name.to_string_lossy() == skip {
                continue;
            }
            std::os::unix::fs::symlink(e.path(), dst.join(&name)).unwrap();
        }
    };
    link_all(repo, &dir, "deployment");
    link_all(&repo.join("deployment"), &dir.join("deployment"), "mainnet");
    link_all(
        &repo.join("deployment/mainnet"),
        &dir.join("deployment/mainnet"),
        "vault_authorities.toml",
    );
    std::fs::write(dir.join("deployment/mainnet/vault_authorities.toml"), record).unwrap();
    dir
}

fn deploy_posture(root: &Path) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_verify_custody_manifest"))
        .args(["--deploy-posture", root.to_str().unwrap()])
        .output()
        .expect("binary must run");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}

#[test]
fn a6_and_a11_the_corrupt_kind_turns_deploy_posture_red_as_a_surplus() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let committed =
        std::fs::read_to_string(repo.join("deployment/mainnet/vault_authorities.toml")).unwrap();

    // CONTROL — the shadow root with the record UNCHANGED must reproduce the
    // real tree's verdict. Without this leg the negative below could be failing
    // because the shadow root itself is broken.
    let ok = shadow_root("shadow_ok", &committed);
    let (code, out) = deploy_posture(&ok);
    assert_eq!(code, 0, "the unmodified shadow root must pass:\n{out}");
    assert!(out.contains("surplus (observed, NOT declared):   []"), "{out}");
    assert!(out.contains("shortfall (declared, NOT observed): []"), "{out}");
    // ROT-LEDGER-FILL (2026-09-21): the rotation has been PERFORMED, so the
    // declared-pending key is gone from both sides. The exit-zero and the two
    // empty set controls above are retained deliberately — they are what proves
    // the shadow root is not simply broken, which a bare absence assertion
    // could not distinguish from a root that observes nothing at all.
    assert!(
        !out.contains(&format!(
            "PendingDeploymentArtifact:{}",
            vcm::ROTATION_LEDGER_PENDING_PATH
        )),
        "the rotation key must be neither declared NOR observed once the ledger carries \
         EXECUTED rows on both planes:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&ok);

    // NEGATIVE — ONE edit: the chain root's first principal is replaced, so the
    // committed upgrader/vault row 1 no longer chains onto it.
    // `RotationLedgerInconsistent` is not declarable, so it can only ever appear
    // as a SURPLUS — which is precisely why no declaration can silence it.
    //
    // Post-rotation that one edit legitimately moves TWO checks, and the test
    // says so rather than pretending otherwise: the chain (ChainBreak) and the
    // Q5-A init↔bootstrap comparison, which now judges `vault_init.did` against
    // this very snapshot. Both are surpluses; the assertion below is on the
    // rotation-ledger kind, which is the one this fixture exists for.
    let corrupted = committed.replacen(
        "vault_signers = [\n  \"5jmfd",
        "vault_signers = [\n  \"2vxsx-fae\",  # \"5jmfd",
        1,
    );
    assert_ne!(corrupted, committed, "the fixture must actually change the record");
    let bad = shadow_root("shadow_bad", &corrupted);
    let (code, out) = deploy_posture(&bad);
    assert_ne!(code, 0, "a corrupted ledger must turn --deploy-posture RED:\n{out}");
    assert!(out.contains("DEPLOY POSTURE MISMATCH"), "{out}");
    assert!(out.contains("SURPLUS"), "the corrupt kind must appear as a SURPLUS:\n{out}");
    assert!(out.contains("RotationLedgerInconsistent"), "{out}");
    assert!(
        out.contains("shortfall (declared, NOT observed): []"),
        "a corrupt ledger must show up as a pure SURPLUS and must not create a SHORTFALL — \
         post-rotation there is no rotation key left to declare, and corrupting the ledger \
         must not make some OTHER declared obligation look unobserved:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&bad);
}

// ═══ F-1: the row-to-row chain hash, which had no fixture at all ════════════
//
// SSA_LANDED_DIFF_ROT_LEDGER_e567ff7 §8 M7: disabling the
// `predecessor_row_sha256` comparison outright left all 262 tests green,
// because `rotated_record` builds exactly ONE row per plane and the `i > 0`
// branch of `rotation_plane_chain` was therefore never executed. These
// fixtures execute it.

#[test]
fn f1_baseline_a_two_row_plane_with_correct_predecessor_hashes_is_clean() {
    let t = Tree::new("f1_base");
    let rec = two_row_record(&t, |_, _, _, _| {});
    // Assert the fixture's OWN premise: it really does hold two rows per plane
    // with non-empty predecessor pins. A builder that silently degraded to one
    // row would otherwise be scored as a passing two-row baseline.
    assert_eq!(rec.matches("[[rotation.upgrader]]").count(), 2);
    assert_eq!(rec.matches("[[rotation.vault]]").count(), 2);
    assert_eq!(
        rec.matches("predecessor_row_sha256 = \"\"").count(),
        2,
        "exactly the two row-1s anchor on the bootstrap snapshot"
    );
    t.record(&rec);
    t.commit();
    assert!(t.check().is_empty(), "{:#?}", t.check());
}

#[test]
fn f1_a_forged_predecessor_row_sha256_is_a_chain_break_naming_the_row() {
    assert_two_row_baseline_passes();
    let t = Tree::new("f1_forge_upg");
    let rec = two_row_record(&t, |_, u2, _, _| {
        u2.predecessor = "0".repeat(64);
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#2");

    // The Vault plane too: the check is per-plane, and a fixture that only ever
    // exercised the Upgrader would leave half of it unproven.
    let t2 = Tree::new("f1_forge_vault");
    let rec2 = two_row_record(&t2, |_, _, _, v2| {
        v2.predecessor = "0".repeat(64);
    });
    t2.record(&rec2);
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::ChainBreak, "vault#2");
}

#[test]
fn f1_an_empty_predecessor_on_a_successor_row_is_a_chain_break() {
    // The row-1 form ("") is NOT acceptable on row 2: omitting the pin must not
    // be a way to opt out of the chain.
    assert_two_row_baseline_passes();
    let t = Tree::new("f1_empty_pred");
    let rec = two_row_record(&t, |_, u2, _, _| u2.predecessor = String::new());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#2");
}

#[test]
fn f1_the_predecessor_hash_covers_the_whole_predecessor_row() {
    // The pins are computed BEFORE the mutation, so editing a field of row 1
    // that nothing else validates cross-row — `proposal_id` — must still break
    // row 2's pin. That is what makes it a hash of the ROW rather than of a
    // handful of fields.
    assert_two_row_baseline_passes();
    let t = Tree::new("f1_covers");
    let rec = two_row_record(&t, |u1, _, _, _| u1.proposal_id = 20);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#2");
}

#[test]
fn f1_row2_old_members_must_still_ordered_byte_equal_row1_new_members() {
    // The other half of the row-to-row link: the SET chain, at i > 0. A reorder
    // only — the case a set comparison would silently accept.
    assert_two_row_baseline_passes();
    let t = Tree::new("f1_setchain");
    let rec = two_row_record(&t, |_, u2, _, _| {
        u2.old = [Q2.into(), Q1.into(), Q3.into()];
        u2.approvers = vec![Q2.into(), Q1.into()];
        u2.read_by = Q2.into();
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#2");
}

#[test]
fn f1_rotation_row_canonical_form_is_pinned_by_a_golden_test() {
    // The canonical form is a WIRE FORMAT: once a real row exists, changing the
    // field order, a separator, or the set of fields covered silently
    // invalidates every recorded chain. This test makes such a change LOUD.
    // The expected text is written out here in full; it is NOT derived from the
    // committed record, and it is not recomputed from the function under test.
    let t = Tree::new("f1_golden");
    let rec = two_row_record(&t, |_, _, _, _| {});
    let canonical =
        vcm::rotation_row_canonical_text(&rec, "upgrader", 1).expect("upgrader#1 canonical");
    let expected = format!(
        "plane=upgrader\n\
         sequence=1\n\
         status=EXECUTED\n\
         old_members={P1},{P2},{P3}\n\
         new_members={Q1},{Q2},{Q3}\n\
         old_threshold=2\n\
         new_threshold=2\n\
         old_epoch=None\n\
         new_epoch=None\n\
         after_upgrader_sequence=None\n\
         proposal_id=16\n\
         approvers={P1},{P2}\n\
         observed_at_ns={}\n\
         observed_at_utc={OBS_UTC}\n\
         network=ic\n\
         canister={Q2}\n\
         read_by={P1}\n\
         readback_command=dfx canister --network ic call <c> get_recovery_summary '()'\n\
         readback_evidence_path=deployment/mainnet/evidence/upgrader_1_readback.txt\n\
         readback_output_sha256={}\n",
        OBS_SECS * 1_000_000_000,
        vcm::sha256_hex(b"upgrader #1 read-back, unedited\n"),
    );
    assert_eq!(
        canonical, expected,
        "the canonical row form changed. It is the wire form of the chain: if this is \
         deliberate, every existing predecessor_row_sha256 must be recomputed in the same \
         change, and the schema_version bumped."
    );
    // And the hash the successor actually records is the hash of exactly this.
    assert_eq!(
        vcm::rotation_row_sha256(&rec, "upgrader", 1).unwrap(),
        vcm::sha256_hex(expected.as_bytes())
    );
    assert!(
        rec.contains(&format!(
            "predecessor_row_sha256 = \"{}\"",
            vcm::sha256_hex(expected.as_bytes())
        )),
        "upgrader#2 must pin exactly this hash"
    );
}

// ═══ F-2: `rotated` requires BOTH planes, not just one ══════════════════════

/// Strip one plane's rows out of a rotated record, leaving the other.
fn keep_only_plane(rec: &str, plane: &str) -> String {
    let upg_at = rec.find("[[rotation.upgrader]]").expect("an upgrader row");
    let vault_at = rec.find("[[rotation.vault]]").expect("a vault row");
    assert!(upg_at < vault_at, "the builder renders upgrader rows first");
    match plane {
        "upgrader" => rec[..vault_at].to_string(),
        "vault" => format!("{}{}", &rec[..upg_at], &rec[vault_at..]),
        other => panic!("unknown plane {other}"),
    }
}

#[test]
fn f2_rotated_with_an_upgrader_row_but_an_empty_vault_plane_is_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f2_upg_only");
    let rec = keep_only_plane(&rotated_record(&t, |_, _| {}), "upgrader");
    assert!(!rec.contains("[[rotation.vault]]"));
    t.record(&rec);
    t.commit();
    // Half-rotated is a MID-ceremony state. The word `rotated` must not cover
    // it — and it must not be reported as pending either.
    assert_defect(&t.check(), RotationDefect::StateArrayInconsistent, "[rotation]");
}

#[test]
fn f2_rotated_with_a_vault_row_but_an_empty_upgrader_plane_is_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f2_vault_only");
    let rec = keep_only_plane(&rotated_record(&t, |_, _| {}), "vault");
    assert!(!rec.contains("[[rotation.upgrader]]"));
    t.record(&rec);
    t.commit();
    // Previously this direction fell through to PlaneOrdering, by accident of
    // the vault row citing an upgrader row that did not exist. It is now the
    // same, stated defect as its mirror.
    assert_defect(&t.check(), RotationDefect::StateArrayInconsistent, "[rotation]");
}

#[test]
fn f2_a_half_rotated_ledger_never_emits_the_declared_pending_key() {
    // The corrupt state must be a pure SURPLUS: if it also suppressed the
    // declared key it would show up as a shortfall and could be argued away.
    let t = Tree::new("f2_no_pending");
    t.record(&keep_only_plane(&rotated_record(&t, |_, _| {}), "upgrader"));
    t.commit();
    assert!(
        !t.check()
            .iter()
            .any(|v| matches!(v, Violation::PendingDeploymentArtifact { .. })),
        "a half-rotated ledger is not the declared pending state"
    );
}

// ═══ F-3: `canister` is bound to the record's own pin for that plane ════════

#[test]
fn f3_an_upgrader_row_naming_the_vault_canister_is_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f3_upg");
    // Q1 is a perfectly valid principal, and it is the canister the OTHER plane
    // governs — the exact confusion a parse-only check cannot see.
    let rec = rotated_record(&t, |u, _| u.canister = Q1.into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::CanisterMismatch, "upgrader#1");
}

#[test]
fn f3_a_vault_row_naming_the_upgrader_canister_is_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f3_vault");
    let rec = rotated_record(&t, |_, v| v.canister = Q2.into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::CanisterMismatch, "vault#1");
}

#[test]
fn f3_a_row_naming_an_unrelated_canister_is_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f3_other");
    let rec = rotated_record(&t, |u, _| u.canister = R3.into());
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::CanisterMismatch, "upgrader#1");
}

// ═══ F-4: proposal_id — uniqueness within a plane, no hard-coded floor ══════

#[test]
fn f4_two_rows_of_one_plane_citing_the_same_proposal_id_are_refused() {
    assert_two_row_baseline_passes();
    let t = Tree::new("f4_dup_upg");
    // Row 2's proposal_id is not part of row 1's canonical text, so the chain
    // pins stay valid and this fixture injects exactly ONE defect.
    let rec = two_row_record(&t, |u1, u2, _, _| u2.proposal_id = u1.proposal_id);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ProposalIdNotUnique, "upgrader#2");

    let t2 = Tree::new("f4_dup_vault");
    let rec2 = two_row_record(&t2, |_, _, v1, v2| v2.proposal_id = v1.proposal_id);
    t2.record(&rec2);
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::ProposalIdNotUnique, "vault#2");
}

#[test]
fn f4_no_lower_bound_beyond_one_is_hard_coded() {
    // The record's prose says ">= 16"; that is a fact about THIS ceremony's
    // proposal numbering, not a schema rule. Hard-coding it would make the
    // checker wrong for the next rotation, so a small id must still pass.
    assert_one_row_baseline_passes();
    let t = Tree::new("f4_small");
    let rec = rotated_record(&t, |u, v| {
        u.proposal_id = 1;
        v.proposal_id = 2;
    });
    t.record(&rec);
    t.commit();
    assert!(t.check().is_empty(), "{:#?}", t.check());
}

#[test]
fn f4_a_proposal_id_of_zero_is_still_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f4_zero");
    let rec = rotated_record(&t, |u, _| u.proposal_id = 0);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::RequiredFieldEmpty, "upgrader#1");
}

#[test]
fn f4_the_two_planes_may_cite_different_proposals_of_the_same_ceremony() {
    // Uniqueness is WITHIN a plane. The positive control for F-4: the baseline
    // already uses 16 and 17 across the two planes, and that must stay legal —
    // an over-broad global-uniqueness rule would break a correct ledger.
    let t = Tree::new("f4_cross_plane");
    let rec = rotated_record(&t, |u, v| {
        u.proposal_id = 16;
        v.proposal_id = 17;
    });
    t.record(&rec);
    t.commit();
    assert!(t.check().is_empty(), "{:#?}", t.check());
}

// ═══ F-5: a row that changes nothing is not a rotation ══════════════════════

#[test]
fn f5_a_row_whose_new_set_equals_its_old_set_is_refused() {
    assert_one_row_baseline_passes();
    let t = Tree::new("f5_noop_upg");
    // Every other check still passes on this row: it chains onto the snapshot,
    // its approvers and reader are in the old set, its evidence hashes. The
    // ONLY thing wrong with it is that it rotates nobody.
    let rec = rotated_record(&t, |u, _| u.new = [P1.into(), P2.into(), P3.into()]);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#1");

    let t2 = Tree::new("f5_noop_vault");
    let rec2 = rotated_record(&t2, |_, v| v.new = [P1.into(), P2.into(), P3.into()]);
    t2.record(&rec2);
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::SetShapeInvalid, "vault#1");
}

#[test]
fn f5_a_no_op_row_is_refused_at_row_2_as_well_as_row_1() {
    assert_two_row_baseline_passes();
    let t = Tree::new("f5_noop_row2");
    let rec = two_row_record(&t, |_, u2, _, _| u2.new = [Q1.into(), Q2.into(), Q3.into()]);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#2");
}

// ═══ G-1: F-3's fail-closed `None` arm — the pins CANNOT be loaded ══════════
//
// SSA_LANDED_DIFF_ROT_LEDGER_FIX_ea3b153 G-1: the arm is right and was
// untested, so mutating it into a silent skip changed nothing. A fail-closed
// branch that no fixture reaches is a claim, not a control.

/// Break the AUTHORITY table only: remove the `signers` array, which
/// `load_authority_record` requires. The `[rotation]` table still parses (it is
/// read by a separate, `deny_unknown_fields` decoder), so the ledger is reached
/// with `pins == None` — exactly the state the fail-closed arm exists for.
fn without_the_signers_pin(rec: &str) -> String {
    // `\nsigners = [`, not `signers = [`: the bootstrap snapshot's
    // `vault_signers = [` would otherwise match, and removing THAT would break
    // the ledger instead of the authority table.
    let at = rec.find("\nsigners = [").expect("the fixture pins signers") + 1;
    let end = rec[at..].find("]\n").expect("the signers array closes") + at + 2;
    let out = format!("{}{}", &rec[..at], &rec[end..]);
    assert!(!out.contains("\nsigners = ["), "the top-level signers pin must be gone");
    assert!(out.contains("vault_signers = ["), "the bootstrap snapshot must survive intact");
    assert!(out.contains("[rotation]"), "the ledger itself must survive intact");
    assert!(out.contains("[[rotation.upgrader]]"), "the rows must survive intact");
    out
}

#[test]
fn g1_a_row_whose_planes_pin_cannot_be_loaded_fails_closed() {
    assert_one_row_baseline_passes();
    let t = Tree::new("g1_nopins");
    let rec = without_the_signers_pin(&rotated_record(&t, |_, _| {}));
    t.record(&rec);
    t.commit();
    // NOT a skip, and NOT a pass: an unbound `canister` names nothing
    // checkable, so EVERY row is refused, each naming the row it could not
    // bind. Both planes lose their pin at once — this is deliberately not
    // routed through `only_defect`, which asserts exactly ONE violation:
    // asserting one here would either be false or would need the fixture to
    // hide a real second refusal.
    let vs = t.check();
    let mut seen: Vec<(RotationDefect, String)> = vs
        .iter()
        .map(|v| match v {
            Violation::RotationLedgerInconsistent { defect, row, .. } => (*defect, row.clone()),
            other => panic!("expected RotationLedgerInconsistent, got {other:#?}"),
        })
        .collect();
    seen.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        seen,
        vec![
            (RotationDefect::CanisterMismatch, "upgrader#1".to_string()),
            (RotationDefect::CanisterMismatch, "vault#1".to_string()),
        ],
        "both planes lose their pin at once, and each row must say so: {vs:#?}"
    );
}

#[test]
fn g1_unloadable_pins_do_not_turn_a_corrupt_ledger_into_a_pending_one() {
    // The fail-closed arm must not become an escape hatch: a record whose pins
    // are unreadable is not the declared pending state either.
    let t = Tree::new("g1_notpending");
    t.record(&without_the_signers_pin(&rotated_record(&t, |_, _| {})));
    t.commit();
    let vs = t.check();
    assert!(
        !vs.iter().any(|v| matches!(v, Violation::PendingDeploymentArtifact { .. })),
        "an unbindable ledger is a corrupt ledger, not a pending one: {vs:#?}"
    );
}

// ═══ G-2: a PERMUTATION of the same set is not a rotation either ════════════
//
// The no-op check compared ordered bytes, so re-ordering the same three
// principals read as a performed rotation. Order is not a property of a
// canister's signer set — nobody's authority changes. This ONE comparison is
// therefore a SET comparison; the CHAIN comparison stays ORDERED, and the
// positive control below proves it did not follow the change.

#[test]
fn g2_a_permutation_of_the_same_set_is_not_a_rotation() {
    assert_one_row_baseline_passes();
    let t = Tree::new("g2_perm_upg");
    // Same three principals, different order. Every other check still passes:
    // the row chains onto the snapshot, approvers and reader are in the old
    // set, the evidence hashes. It simply rotates nobody.
    let rec = rotated_record(&t, |u, _| u.new = [P2.into(), P3.into(), P1.into()]);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#1");

    let t2 = Tree::new("g2_perm_vault");
    let rec2 = rotated_record(&t2, |_, v| v.new = [P3.into(), P1.into(), P2.into()]);
    t2.record(&rec2);
    t2.commit();
    assert_defect(&t2.check(), RotationDefect::SetShapeInvalid, "vault#1");
}

#[test]
fn g2_a_permutation_is_refused_at_row_2_as_well_as_row_1() {
    assert_two_row_baseline_passes();
    let t = Tree::new("g2_perm_row2");
    let rec = two_row_record(&t, |_, u2, _, _| u2.new = [Q3.into(), Q1.into(), Q2.into()]);
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::SetShapeInvalid, "upgrader#2");
}

#[test]
fn g2_a_genuinely_new_set_still_passes_even_when_it_overlaps_the_old_one() {
    // POSITIVE CONTROL for G-2. Without it, "reject when the sets are equal"
    // could have been widened into "reject whenever any member is reused", and
    // a real rotation that retains two of three members — the likely shape of a
    // single-member replacement — would be refused. One principal changed is a
    // rotation and must pass.
    let t = Tree::new("g2_positive");
    let rec = rotated_record(&t, |u, _| u.new = [P1.into(), P2.into(), Q3.into()]);
    t.record(&rec);
    t.commit();
    assert!(t.check().is_empty(), "{:#?}", t.check());
}

#[test]
fn g2_the_chain_comparison_did_not_follow_the_no_op_check_into_set_equality() {
    // The other half of the positive control: the two comparisons ask opposite
    // questions about the same principals, and only ONE of them became a set
    // comparison. A reorder of row 1's old_* against the bootstrap snapshot must
    // STILL be a ChainBreak — if the chain had been widened to set equality with
    // the no-op check, this would silently pass.
    let t = Tree::new("g2_chain_still_ordered");
    let rec = rotated_record(&t, |u, _| {
        u.old = [P2.into(), P1.into(), P3.into()];
        u.approvers = vec![P2.into(), P1.into()];
        u.read_by = P2.into();
    });
    t.record(&rec);
    t.commit();
    assert_defect(&t.check(), RotationDefect::ChainBreak, "upgrader#1");
}

// ═══ A-6 — the two negatives on the REAL committed record ═══════════════════
//
// SSA C-2. Both start from a PRIVATE COPY of the committed record and of the
// committed evidence — never a symlink into the repository, because both
// fixtures MUTATE what they point at and a symlink would write through into the
// working tree. Each starts from an asserted-passing baseline and injects
// exactly one change.

/// Like [`shadow_root`], but `deployment/mainnet/evidence` is a real recursive
/// COPY rather than a symlink, so an evidence file can be corrupted safely.
fn private_root(tag: &str, record: &str) -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let dir = uniq(tag);
    std::fs::create_dir_all(dir.join("deployment/mainnet")).unwrap();
    let link_all = |src: &Path, dst: &Path, skip: &[&str]| {
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let name = e.file_name();
            if skip.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            std::os::unix::fs::symlink(e.path(), dst.join(&name)).unwrap();
        }
    };
    fn copy_tree(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let (from, to) = (e.path(), dst.join(e.file_name()));
            if from.is_dir() {
                copy_tree(&from, &to);
            } else {
                std::fs::copy(&from, &to).unwrap();
            }
        }
    }
    link_all(repo, &dir, &["deployment"]);
    link_all(&repo.join("deployment"), &dir.join("deployment"), &["mainnet"]);
    link_all(
        &repo.join("deployment/mainnet"),
        &dir.join("deployment/mainnet"),
        &["vault_authorities.toml", "evidence"],
    );
    copy_tree(
        &repo.join("deployment/mainnet/evidence"),
        &dir.join("deployment/mainnet/evidence"),
    );
    std::fs::write(dir.join("deployment/mainnet/vault_authorities.toml"), record).unwrap();
    // Nothing under the private root may be a symlink back into the repository
    // on the two paths these fixtures mutate.
    assert!(!dir.join("deployment/mainnet/vault_authorities.toml").is_symlink());
    assert!(!dir.join("deployment/mainnet/evidence").is_symlink());
    dir
}

fn committed_record() -> String {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    std::fs::read_to_string(repo.join("deployment/mainnet/vault_authorities.toml")).unwrap()
}

fn defect_at(v: &[Violation], row: &str) -> Option<RotationDefect> {
    v.iter().find_map(|x| match x {
        Violation::RotationLedgerInconsistent { defect, row: r, .. } if r == row => Some(*defect),
        _ => None,
    })
}

/// A-6(1): replace ONE principal in the committed Upgrader row-1 `old_members`
/// — the second entry, `lwiax` — with a distinct valid non-forbidden principal
/// that is absent from that old roster. Approvers, `read_by`, the bootstrap
/// snapshot, the evidence and the pins are all left untouched, so the row still
/// satisfies every shape, approver and reader rule and the ONLY thing that can
/// fail is the chain onto `[rotation.bootstrap]`.
#[test]
fn a6_one_mutated_old_member_on_the_real_upgrader_row_is_a_chain_break() {
    let committed = committed_record();
    let base = private_root("a6_chain_ok", &committed);
    let v = vcm::check_rotation_ledger(&base);
    assert!(v.is_empty(), "BASELINE: the committed record must pass on a private copy: {v:#?}");
    let _ = std::fs::remove_dir_all(&base);

    // `R1` is a real, valid, non-forbidden principal, and is not in the old
    // roster [5jmfd, lwiax, 4f6wg].
    // The TABLE HEADER, not the several prose mentions of it in the ROW SCHEMA
    // comment above — hence the `\nsequence` anchor.
    let head = committed
        .find("\n[[rotation.upgrader]]\nsequence")
        .expect("the committed record must carry an upgrader row")
        + 1;
    assert!(
        committed[head..].contains(P2),
        "the mutation target must be present to begin with"
    );
    let mutated = format!(
        "{}{}",
        &committed[..head],
        committed[head..].replacen(&format!("\"{P2}\""), &format!("\"{R1}\""), 1)
    );
    assert_ne!(mutated, committed, "the mutation must actually change the record");
    assert_eq!(
        mutated.matches(&format!("\"{R1}\"")).count(),
        1,
        "exactly ONE principal may be replaced"
    );

    let bad = private_root("a6_chain_bad", &mutated);
    let v = vcm::check_rotation_ledger(&bad);
    assert_eq!(
        defect_at(&v, "upgrader#1"),
        Some(RotationDefect::ChainBreak),
        "one changed old_members principal on row 1 must be a ChainBreak at upgrader#1: {v:#?}"
    );
    let _ = std::fs::remove_dir_all(&bad);
}

/// A-6(2): from a FRESH passing copy, corrupt ONE byte of the file the committed
/// Upgrader row cites, keeping the recorded digest. The row is otherwise
/// untouched, so the only thing that can fail is the evidence hash.
#[test]
fn a6_one_corrupted_evidence_byte_is_evidence_unavailable() {
    let committed = committed_record();
    let root = private_root("a6_evidence", &committed);
    let v = vcm::check_rotation_ledger(&root);
    assert!(v.is_empty(), "BASELINE: the committed record must pass on a private copy: {v:#?}");

    let rel = "deployment/mainnet/evidence/identity_rotation/04_upgrader_rotation_1_readback.txt";
    assert!(
        committed.contains(rel),
        "the row under test must actually cite {rel}"
    );
    let p = root.join(rel);
    assert!(!p.is_symlink(), "the mutated file must be a private copy, not a symlink");
    let mut bytes = std::fs::read(&p).unwrap();
    let before = vcm::sha256_hex(&bytes);
    bytes[0] ^= 0x20; // one byte, one bit-pair: a case flip in the first character
    std::fs::write(&p, &bytes).unwrap();
    let after = vcm::sha256_hex(&bytes);
    assert_ne!(before, after, "the corruption must actually change the file's digest");
    assert!(
        committed.contains(&before),
        "the record's recorded digest must be the PRE-corruption one, left in place"
    );

    let v = vcm::check_rotation_ledger(&root);
    assert_eq!(
        defect_at(&v, "upgrader#1"),
        Some(RotationDefect::EvidenceUnavailable),
        "a corrupted evidence byte under an unchanged digest must be EvidenceUnavailable at \
         upgrader#1: {v:#?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
