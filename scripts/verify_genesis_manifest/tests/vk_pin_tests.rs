//! R-6 (G4) — the VK pin registry: DPOOL-1b posture, DPOOL-9 artifact pin,
//! DPOOL-9b label posture.
//!
//! INDEPENDENT-EXPECTED-SIDE (HARNESS_DELTA §1): every expected value below is
//! written into this file by hand — the placeholder literal, the DEV VK hash,
//! the two label strings, the two posture detail strings. Nothing is read back
//! from `VK_PIN.toml`, from `DEV_VK_HASH_HEX`, or from
//! `circuits/verification_key.json` and then compared against itself.

use std::path::{Path, PathBuf};
use verify_genesis_manifest::*;

/// The 64-zero P0-3 placeholder, transcribed independently.
const PLACEHOLDER_LITERAL: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// A well-formed hash that is NOT the placeholder and NOT the dev key.
const ARMED_VK_HEX_LITERAL: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
/// The CURRENT VK hash — sha256 of the committed
/// `circuits/verification_key.json` — transcribed independently.
///
/// **NAME CAVEAT (O-9, lane DOCS-T1).** The symbol is called `DEV_VK_HEX_LITERAL`
/// for historical reasons, but the value it holds is **no longer a dev VK**: at
/// `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914` it is the
/// **LAUNCH** verifying key produced by the mainnet-v2 ceremony (lane A-4,
/// 2026-09-12 — public Hermez power-15 ptau for phase 1, one operator contribution
/// finalized by drand mainnet round 6460200 for phase 2). Authorities:
/// `MAINNET_DEPLOYMENT.md` *Deployment-wide fields* and
/// `docs/ceremony/CEREMONY_RECORD_v3.md`. Renaming the symbol is a test change and
/// is deliberately NOT done here — it needs its own brief line and SSA GREEN
/// (standing law 7). Read the name as "the VK this repo currently ships", which is
/// what the assertions below actually check.
///
/// MOVED at lane A-3 FINALIZE (2026-09-12), then again by the A-4 ceremony. This
/// literal is the *computed artifact* side of DPOOL-9, so it tracks whatever VK the
/// repo ships. It is NOT the Gate-D DENY literal: `verify_genesis_manifest::DEV_VK_HASH_HEX` and
/// `vkgate_pool_init_tests::DEV_VK_HEX_LITERAL` still name the OLD
/// `fc73ca4d…` key by design (the deny-list entry is deferred to the W0-2/A-4
/// VK lane), and those two are deliberately left where they are.
const DEV_VK_HEX_LITERAL: &str =
    "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914";

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
// A-4 LANDING INVERTED THE POSTURE HELPERS. The committed manifest USED to hold the
// all-zeros placeholder, so the live text was the pending case and the armed one was
// synthesised. A-4 armed `[pool_init].vk_hash`, so the live text is now ARMED and the
// PENDING case must be synthesised instead. Two tests here failed on that stale premise
// rather than on any defect (law 7(e-i): a fixture literal that inherits the record's own
// posture is not independent evidence about that record). Both helpers assert their own
// substitution so a future posture change fails LOUDLY rather than silently vacuously.

/// The committed manifest with `[pool_init].vk_hash` replaced by a SYNTHETIC armed value
/// — the ARMED posture, held independent of whatever the real launch VK is.
fn armed_manifest() -> Manifest {
    let armed = manifest_text().replace(
        &format!("vk_hash         = \"{DEV_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{ARMED_VK_HEX_LITERAL}\""),
    );
    assert!(
        armed.contains(ARMED_VK_HEX_LITERAL),
        "SETUP BUG: the armed fixture did not substitute — the committed manifest no \
         longer carries DEV_VK_HEX_LITERAL, so this suite is testing a stale premise"
    );
    assert!(
        !armed.contains(PLACEHOLDER_LITERAL),
        "SETUP BUG: the armed fixture still carries the placeholder — the \
         replacement did not match the committed spelling"
    );
    parse(&armed)
}

/// The committed manifest forced BACK to the pre-ceremony placeholder posture.
fn pending_manifest() -> Manifest {
    let pending = manifest_text().replace(
        &format!("vk_hash         = \"{DEV_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{PLACEHOLDER_LITERAL}\""),
    );
    assert!(
        pending.contains(PLACEHOLDER_LITERAL),
        "SETUP BUG: the pending fixture did not substitute — the committed manifest no \
         longer carries DEV_VK_HEX_LITERAL, so the pending posture is not exercised"
    );
    parse(&pending)
}

/// A throwaway repo_root carrying ONLY a fixture `VK_PIN.toml`, so a check that
/// reads the pin resolves it to a present file and can only fail on the
/// comparison the test is about — never on "file not found" (the RED-γ guard).
struct TempRoot(PathBuf);
impl TempRoot {
    fn new(tag: &str, label: &str, sha256: &str, record_transcript: &str) -> TempRoot {
        let root = std::env::temp_dir().join(format!(
            "stsh-r6-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("scripts/verify_genesis_manifest"))
            .expect("temp root");
        std::fs::write(
            root.join("scripts/verify_genesis_manifest/VK_PIN.toml"),
            format!(
                "label             = \"{label}\"\n\
                 source            = \"fixture\"\n\
                 sha256            = \"{sha256}\"\n\
                 record_transcript = \"{record_transcript}\"\n"
            ),
        )
        .expect("fixture VK_PIN.toml");
        TempRoot(root)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// **AC-0** — `DPOOL-1b-manifest-posture` names both states and NEVER fails.
///
/// The `pass == true` assertion in the armed branch is the load-bearing one: a
/// posture primitive that could fail would turn a correct pre/post-ceremony
/// state into a gate failure, which is exactly the trap DPOOL-1b exists to
/// stop DPOOL-9b and DPOOL-8a from each re-deriving inline.
#[test]
fn test_manifest_posture_reports_both_states() {
    // A-4: the committed manifest is ARMED, so the pending posture is synthesised.
    let pending = check_manifest_posture(&pending_manifest());
    assert_eq!(pending.name, "DPOOL-1b-manifest-posture");
    assert_eq!(
        pending.detail, "pending (pre-ceremony)",
        "a manifest holding the placeholder must report the pending posture"
    );
    // And the COMMITTED manifest must now report the armed posture — the A-4 arming
    // itself, asserted rather than assumed.
    let committed = check_manifest_posture(&parse(&manifest_text()));
    assert_eq!(
        committed.detail, "armed (post-ceremony)",
        "since A-4 the committed manifest carries the launch VK, so DPOOL-1b must say armed"
    );
    assert!(committed.pass, "DPOOL-1b must never itself fail: {}", committed.detail);
    assert!(pending.pass, "DPOOL-1b must never itself fail: {}", pending.detail);

    let armed = check_manifest_posture(&armed_manifest());
    assert_eq!(
        armed.detail, "armed (post-ceremony)",
        "a non-placeholder vk_hash is the armed posture"
    );
    assert!(
        armed.pass,
        "DPOOL-1b must never itself fail, in EITHER posture — only DPOOL-9b and \
         DPOOL-8a may gate on what it reports: {}",
        armed.detail
    );
    assert_ne!(
        pending.detail, armed.detail,
        "a posture check that reports the same detail in both states names nothing"
    );
}

/// **AC-1** — DPOOL-9 passes at base, and disagreement on EITHER side is caught
/// and named.
#[test]
fn test_vk_pin_passes_at_base() {
    let base = check_vk_artifact_pin(&repo_root());
    assert_eq!(base.name, "DPOOL-9-vk-artifact-pin");
    assert!(
        base.pass,
        "the committed VK_PIN.toml must hash-match the committed artifact; detail: {}",
        base.detail
    );
    assert!(
        base.detail.contains(DEV_VK_HEX_LITERAL),
        "the passing detail must name the computed hash so a reader can see WHICH \
         artifact was pinned; detail: {}",
        base.detail
    );

    // Registry side moved (M1b's shape, exercised in-test): a temp root whose
    // fixture pin names a different, well-formed hash. The artifact is the real
    // one, unmodified — only the pin side differs.
    let t = TempRoot::new(
        "vkpin-registry-side",
        "DEV",
        ARMED_VK_HEX_LITERAL,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    std::fs::create_dir_all(t.path().join("circuits")).unwrap();
    std::fs::copy(
        repo_root().join("circuits/verification_key.json"),
        t.path().join("circuits/verification_key.json"),
    )
    .unwrap();
    let moved = check_vk_artifact_pin(t.path());
    assert!(!moved.pass, "a pin naming a different hash MUST fail; detail: {}", moved.detail);
    assert!(
        moved.detail.contains("vk_artifact_pin_mismatch"),
        "the RED must name a hash mismatch, not an unreadable file; detail: {}",
        moved.detail
    );
    assert!(
        moved.detail.contains(DEV_VK_HEX_LITERAL) && moved.detail.contains(ARMED_VK_HEX_LITERAL),
        "the RED must name BOTH sides so a reader can see which one moved; detail: {}",
        moved.detail
    );
}

/// **AC-4** — `DPOOL-9b-vk-pin-label-posture` has both states tested, and every
/// temp-root invocation ships its own fixture pin so nothing can pass or fail on
/// a missing-file path instead of the label comparison.
#[test]
fn test_vk_pin_label_posture_both_states() {
    // (i) pending state. A-4 armed the manifest AND flipped the committed pin to
    // PRODUCTION, so BOTH sides of this leg are now synthesised: a pending manifest
    // paired with a DEV-labelled fixture pin. That pairing is the correct
    // pre-ceremony state and must still pass.
    let dev_pin = TempRoot::new("vkpin-label-pending", "DEV", DEV_VK_HEX_LITERAL, "00");
    let pending = check_vk_pin_label_posture(dev_pin.path(), &pending_manifest());
    assert_eq!(pending.name, "DPOOL-9b-vk-pin-label-posture");
    assert!(
        pending.pass,
        "a pending manifest paired with a DEV-labelled pin MUST pass, or the gate \
         rejects the correct pre-ceremony state; detail: {}",
        pending.detail
    );
    assert!(
        pending.detail.contains("label=DEV") && pending.detail.contains("expected=DEV"),
        "detail: {}",
        pending.detail
    );

    // (i-b) the COMMITTED state after A-4: armed manifest + PRODUCTION pin. This is the
    // flip §4.3 required, asserted against the real repo root rather than a fixture.
    let committed = check_vk_pin_label_posture(&repo_root(), &parse(&manifest_text()));
    assert!(
        committed.pass,
        "the committed A-4 state is an armed manifest with a PRODUCTION pin and MUST \
         pass; detail: {}",
        committed.detail
    );
    assert!(
        committed.detail.contains("label=PRODUCTION") && committed.detail.contains("expected=PRODUCTION"),
        "detail: {}",
        committed.detail
    );

    // (ii) armed manifest, pin still labelled DEV — half of the one-commit
    // re-ceremony flip was forgotten. Must FAIL.
    let stale = TempRoot::new("vkpin-label-stale", "DEV", DEV_VK_HEX_LITERAL, "00");
    let armed_stale = check_vk_pin_label_posture(stale.path(), &armed_manifest());
    assert!(
        !armed_stale.pass,
        "an armed manifest paired with a DEV-labelled pin MUST fail — that is the \
         forgotten-flip case this check exists for; detail: {}",
        armed_stale.detail
    );
    assert!(
        armed_stale.detail.contains("expected=PRODUCTION"),
        "the RED must name the expected label, not merely report a boolean; detail: {}",
        armed_stale.detail
    );

    // (iii) armed manifest, pin correctly flipped to PRODUCTION. Must PASS.
    let flipped = TempRoot::new("vkpin-label-flipped", "PRODUCTION", DEV_VK_HEX_LITERAL, "00");
    let armed_ok = check_vk_pin_label_posture(flipped.path(), &armed_manifest());
    assert!(
        armed_ok.pass,
        "a correctly flipped pin must pass in the armed posture, or the flip is \
         impossible to complete; detail: {}",
        armed_ok.detail
    );
    assert_ne!(
        armed_stale.pass, armed_ok.pass,
        "the label is what distinguishes these two invocations — if both verdicts \
         agree, DPOOL-9b is not reading the label at all"
    );
}
