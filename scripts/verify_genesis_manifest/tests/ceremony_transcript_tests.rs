//! R-6 (G4) — the ceremony trust root: DPOOL-8a (posture-gated record-vs-artifact)
//! and DPOOL-8b (always-on record transcript anchor).
//!
//! INDEPENDENT-EXPECTED-SIDE (HARNESS_DELTA §1): the pinned record transcript
//! and the computed VK hash are TRANSCRIBED BY HAND below. Nothing in this file
//! reads `VK_PIN.toml` and compares it against itself, and nothing reads
//! `CEREMONY_RECORD_v3.md`'s hash and then uses that value as the expectation
//! for the same record. The one place the record's real bytes are read is when
//! COPYING it into a fixture tree — the expected hash it is checked against is
//! the hand-transcribed literal.
//!
//! Every invocation below resolves `VK_PIN.toml` at
//! `<repo_root>/scripts/verify_genesis_manifest/VK_PIN.toml` — the SAME
//! `repo_root` argument the check reads the record from. A temp root therefore
//! ships its OWN fixture pin, or the check fails closed on
//! `record_transcript_unreadable` rather than on the byte mismatch under test.

use std::path::{Path, PathBuf};
use verify_genesis_manifest::*;

/// sha256 of `docs/ceremony/CEREMONY_RECORD_v3.md`'s committed, unedited bytes,
/// transcribed by hand from `sha256sum` — NOT read back from `VK_PIN.toml`.
const RECORD_TRANSCRIPT_LITERAL: &str =
    "d619ccd6d75a7054b14247d56fcb9d32b88c90f044b5ded35fbaf27107db4e54";
/// A DELIBERATELY WRONG "computed artifact hash", transcribed by hand: the M5 DEV key.
/// Since A-4 armed the manifest with the launch VK, this value is NOT what
/// `sha256(circuits/verification_key.json)` returns — and that is exactly why it is used
/// here. Feeding DPOOL-8a a computed hash the record does NOT name is what proves the
/// armed branch really compares; a literal that happened to match would make the negative
/// case vacuous.
const COMPUTED_VK_HEX_LITERAL: &str =
    "fc73ca4dcdcfd5a2eb0dd6165c5cf2b1e039c3acdad2d360258c5d42ba530dc8";
/// The LIVE `[pool_init].vk_hash`, ARMED at A-4 with the mainnet-v2 launch VK.
/// Transcribed BY HAND from `sha256sum circuits/verification_key.json` — never read back
/// from the manifest, or these fixtures would agree with whatever the manifest says.
const LIVE_VK_HEX_LITERAL: &str =
    "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914";
/// The 64-zero P0-3 placeholder, transcribed by hand.
const PLACEHOLDER_LITERAL: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// A well-formed hash that is neither the placeholder nor the dev key.
const ARMED_VK_HEX_LITERAL: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
/// The record's repo-relative path, as `[pool_init].ceremony_record` names it.
const RECORD_REL: &str = "docs/ceremony/CEREMONY_RECORD_v3.md";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn manifest_text() -> String {
    std::fs::read_to_string(repo_root().join("deployment/mainnet/genesis_manifest.toml"))
        .expect("committed manifest must be readable")
}
fn parse(text: &str) -> Manifest {
    toml::from_str(text).expect("manifest parses")
}
// A-4 LANDING INVERTED THESE TWO HELPERS, and the reason matters more than the diff.
//
// Before A-4 the committed manifest was PENDING (all-zeros placeholder), so the suite
// took the live text as the pending case and SYNTHESISED the armed one. A-4 armed
// `[pool_init].vk_hash` with the launch VK, so the live text is now the ARMED case and
// the PENDING one has to be synthesised instead. Left alone, two tests failed on a stale
// premise rather than on a real defect — the law 7(e-i) fixture class: a test literal
// that inherits the record's own posture is not independent evidence about that record.
//
// Both helpers therefore assert their own setup, so a future posture change fails LOUDLY
// here ("SETUP BUG") instead of quietly making a negative case vacuous.

/// The manifest as ARMED, but with a SYNTHETIC key, not the real launch VK: these tests
/// are about posture, and must not start passing or failing because the launch key moved.
fn armed_manifest() -> Manifest {
    let armed = manifest_text().replace(
        &format!("vk_hash         = \"{LIVE_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{ARMED_VK_HEX_LITERAL}\""),
    );
    assert!(
        armed.contains(ARMED_VK_HEX_LITERAL),
        "SETUP BUG: the armed fixture did not substitute — the live manifest no longer \
         carries LIVE_VK_HEX_LITERAL, so this suite is testing a stale premise"
    );
    assert!(
        !armed.contains(PLACEHOLDER_LITERAL),
        "SETUP BUG: the armed fixture still carries the placeholder"
    );
    parse(&armed)
}

/// The manifest forced BACK to the pre-ceremony placeholder posture.
fn pending_manifest() -> Manifest {
    let pending = manifest_text().replace(
        &format!("vk_hash         = \"{LIVE_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{PLACEHOLDER_LITERAL}\""),
    );
    assert!(
        pending.contains(PLACEHOLDER_LITERAL),
        "SETUP BUG: the pending fixture did not substitute — the live manifest no longer \
         carries LIVE_VK_HEX_LITERAL, so the pending posture is not being exercised"
    );
    parse(&pending)
}
fn named(checks: &[CheckResult], name: &str) -> CheckResult {
    checks
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("check {name} must be present — a renamed or removed check is itself the defect"))
        .clone()
}

/// A throwaway `repo_root` carrying its OWN fixture `VK_PIN.toml` (pinning the
/// hand-transcribed record transcript) plus a copy of the record at the
/// manifest-relative path. Neither invocation can then fail on a missing file.
struct FixtureRoot(PathBuf);
impl FixtureRoot {
    fn new(tag: &str, record_bytes: &[u8]) -> FixtureRoot {
        let root = std::env::temp_dir().join(format!(
            "stsh-r6-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("scripts/verify_genesis_manifest")).unwrap();
        std::fs::write(
            root.join("scripts/verify_genesis_manifest/VK_PIN.toml"),
            format!(
                "label             = \"DEV\"\n\
                 source            = \"fixture\"\n\
                 sha256            = \"{COMPUTED_VK_HEX_LITERAL}\"\n\
                 record_transcript = \"{RECORD_TRANSCRIPT_LITERAL}\"\n"
            ),
        )
        .unwrap();
        std::fs::create_dir_all(root.join(RECORD_REL).parent().unwrap()).unwrap();
        std::fs::write(root.join(RECORD_REL), record_bytes).unwrap();
        FixtureRoot(root)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn committed_record_bytes() -> Vec<u8> {
    std::fs::read(repo_root().join(RECORD_REL)).expect("committed ceremony record must be readable")
}

// BINDING: B-4-CEREMONY-ANCHOR — DPOOL-8b binds the ceremony record's own
// content hash independently of the manifest; two invocations with differing
// record bytes must disagree on pass/fail. Both invocations use a temp
// repo_root that carries its OWN fixture VK_PIN.toml, so neither can fail on a
// missing pin — resolution is <repo_root>/scripts/verify_genesis_manifest/VK_PIN.toml
// for both. The assertion below is `assert_ne!` on the two `pass` booleans:
// it is both the actual binding property and the token bindings.rs's rule (d)
// `asserts_inequality` scan recognises. `r.name == "..."` plus `.unwrap()` plus
// `assert!(!result.pass)` satisfies NONE of the eight recognised markers.
/// **AC-3** — the record's transcript is ANCHORED, not merely echoing the
/// manifest's own string. A junk record containing the right hash substring —
/// the mutation the old DPOOL-8 passed 47/47 — fails here.
#[test]
fn test_ceremony_record_transcript_anchor_rejects_mismatch() {
    let manifest = parse(&manifest_text());
    let computed = COMPUTED_VK_HEX_LITERAL;

    // Invocation 1 — fixture pin + the real record's bytes, copied verbatim.
    let root_a = FixtureRoot::new("anchor-base", &committed_record_bytes());
    let base = check_ceremony_record_anchor(root_a.path(), &manifest, computed);
    let base_result = named(&base, "DPOOL-8b-record-transcript-anchor");
    assert!(
        base_result.pass,
        "SETUP BUG: the base invocation must pass — the fixture pin names the real \
         record's transcript; detail: {}",
        base_result.detail
    );

    // Invocation 2 — SAME fixture pin (record_transcript unmoved), but the
    // record copy is the campaign's junk record: one line holding nothing but
    // the manifest's own bound hash. DPOOL-8 passes this. DPOOL-8b must not.
    let junk = format!("{PLACEHOLDER_LITERAL}\n");
    let root_b = FixtureRoot::new("anchor-junk", junk.as_bytes());
    let tampered = check_ceremony_record_anchor(root_b.path(), &manifest, computed);
    let tampered_result = named(&tampered, "DPOOL-8b-record-transcript-anchor");

    assert_ne!(
        base_result.pass, tampered_result.pass,
        "differing record bytes must produce differing DPOOL-8b verdicts — base: {}, tampered: {}",
        base_result.detail, tampered_result.detail
    );
    assert!(
        tampered_result.detail.contains("record_transcript_mismatch"),
        "the failure must name a hash MISMATCH via the exact `record_transcript_mismatch` \
         literal, never a missing-file detail (`record_transcript_unreadable`) — the two \
         prefixes are disjoint by construction; detail: {}",
        tampered_result.detail
    );
}

/// **AC-3 (M3b shape)** — a ONE-BYTE change to the record, with its bound-hash
/// substring untouched, still REDs DPOOL-8b. The substring DPOOL-8 checks is
/// unaffected; only the whole-file transcript moves.
#[test]
fn test_ceremony_record_transcript_anchor_rejects_one_byte_change() {
    let manifest = parse(&manifest_text());
    let mut bytes = committed_record_bytes();
    bytes.push(b'\n');
    let root = FixtureRoot::new("anchor-onebyte", &bytes);
    let checks = check_ceremony_record_anchor(root.path(), &manifest, COMPUTED_VK_HEX_LITERAL);
    let r = named(&checks, "DPOOL-8b-record-transcript-anchor");
    assert!(!r.pass, "one appended byte must move the transcript; detail: {}", r.detail);
    assert!(
        r.detail.contains("record_transcript_mismatch"),
        "detail: {}",
        r.detail
    );
    // The DPOOL-8 substring binding is deliberately NOT what moved: the record
    // copy still contains the manifest's bound hash. DPOOL-8b is independent of it.
    // A-4: the manifest's bound hash is now the LAUNCH VK, not the placeholder.
    assert!(
        String::from_utf8_lossy(&bytes).contains(LIVE_VK_HEX_LITERAL),
        "SETUP BUG: the one-byte-changed record must still carry the manifest's bound \
         hash, or this test proves nothing DPOOL-8 does not already prove"
    );
}

/// **AC-3 (vacuity guard)** — an ABSENT pin produces the OTHER, disjoint prefix.
/// If a temp root ever forgot its fixture pin, the RED would say
/// `record_transcript_unreadable`, which the AC-3 guard can never mistake for a
/// mismatch. This test is what makes that claim falsifiable.
#[test]
fn test_missing_pin_reports_unreadable_not_mismatch() {
    let manifest = parse(&manifest_text());
    let root = std::env::temp_dir().join(format!("stsh-r6-nopin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(RECORD_REL).parent().unwrap()).unwrap();
    std::fs::write(root.join(RECORD_REL), committed_record_bytes()).unwrap();
    let checks = check_ceremony_record_anchor(&root, &manifest, COMPUTED_VK_HEX_LITERAL);
    let r = named(&checks, "DPOOL-8b-record-transcript-anchor");
    assert!(!r.pass, "a missing pin must fail CLOSED; detail: {}", r.detail);
    assert!(
        r.detail.contains("record_transcript_unreadable"),
        "detail: {}",
        r.detail
    );
    assert!(
        !r.detail.contains("record_transcript_mismatch"),
        "the two prefixes must stay disjoint — an absent pin must never be reported \
         as a byte mismatch; detail: {}",
        r.detail
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **AC-2** — `DPOOL-8a-record-vs-artifact` is posture-gated on DPOOL-1b: while
/// the manifest holds the placeholder it performs NO comparison and cannot be
/// influenced by the record's bytes at all. Once armed, it requires the record
/// to name the computed artifact hash.
#[test]
fn test_record_vs_artifact_posture_gated() {
    let pending = pending_manifest();

    // (i) real root, pending posture -> PASS, no comparison performed.
    // NOTE (A-4): the live manifest is ARMED, so the pending posture is synthesised.
    // The record now names the LAUNCH VK and COMPUTED_VK_HEX_LITERAL is deliberately a
    // DIFFERENT hash — so if DPOOL-8a compared under pending posture, this would RED.
    // That disagreement is what makes the "no comparison performed" claim falsifiable.
    let base = check_ceremony_record_anchor(&repo_root(), &pending, COMPUTED_VK_HEX_LITERAL);
    let base_8a = named(&base, "DPOOL-8a-record-vs-artifact");
    assert!(
        base_8a.pass,
        "under pending posture DPOOL-8a must not compare at all — the record does NOT \
         name COMPUTED_VK_HEX_LITERAL, and an always-on equality here would be \
         unsatisfiable; detail: {}",
        base_8a.detail
    );
    assert!(
        base_8a.detail.starts_with("pending (pre-ceremony)"),
        "detail: {}",
        base_8a.detail
    );

    // (ii) pending posture, JUNK record: still PASS. This is what proves the
    // pending branch reads no record bytes at all, rather than passing by luck.
    let junk = FixtureRoot::new("8a-pending-junk", b"not a ceremony record\n");
    let junk_checks = check_ceremony_record_anchor(junk.path(), &pending, COMPUTED_VK_HEX_LITERAL);
    let junk_8a = named(&junk_checks, "DPOOL-8a-record-vs-artifact");
    assert!(
        junk_8a.pass,
        "the pending branch must be independent of the record's bytes; detail: {}",
        junk_8a.detail
    );

    // (iii) ARMED posture, real record: FAIL. The record still names the
    // placeholder, not the computed artifact hash.
    let armed = check_ceremony_record_anchor(&repo_root(), &armed_manifest(), COMPUTED_VK_HEX_LITERAL);
    let armed_8a = named(&armed, "DPOOL-8a-record-vs-artifact");
    assert!(
        !armed_8a.pass,
        "once armed, a record that does not name the computed artifact hash MUST fail — \
         that is the whole binding; detail: {}",
        armed_8a.detail
    );
    assert!(
        armed_8a.detail.contains("record_names_computed_artifact_hash=false"),
        "the RED must name what it looked for; detail: {}",
        armed_8a.detail
    );
    assert_ne!(
        base_8a.pass, armed_8a.pass,
        "the posture is the ONLY thing that differs between these two invocations — if \
         the verdicts agree, DPOOL-8a is not posture-gated at all"
    );
}
