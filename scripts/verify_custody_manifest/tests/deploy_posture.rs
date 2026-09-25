// R-3b S1/S2 — the deploy-posture declaration and the key set it is compared to.
//
// The point of `Violation::key()` is that an obligation's IDENTITY comes from
// TYPED data carried on the violation, never from re-parsing its message. So the
// tests below construct violations through the ordinary public path and assert
// on keys only — none of them reads, matches, or asserts against `detail`.

use std::path::{Path, PathBuf};
use std::process::Command;
use verify_custody_manifest as vcm;
use vcm::{LaunchObligation, Violation};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

// ── keys are derived from TYPED fields, and they DISTINGUISH ─────────────────

#[test]
fn two_instances_differing_only_in_the_typed_key_field_get_different_keys() {
    // Each pair differs ONLY in the new typed field(s). If `key()` ever falls
    // back to the kind name — or to `detail` — for a declarable kind, the two
    // collapse into one and a same-kind SWAP becomes invisible to the set
    // comparison: the exact regression the declaration exists to detect.
    let same_detail = "identical message text on purpose".to_string();

    let a = Violation::ReleaseIdentityNotAsserted {
        package: "vault".into(),
        detail: same_detail.clone(),
    };
    let b = Violation::ReleaseIdentityNotAsserted {
        package: "upgrader".into(),
        detail: same_detail.clone(),
    };
    assert_ne!(a.key(), b.key(), "ReleaseIdentityNotAsserted must key on `package`");
    assert_eq!(a.key(), "ReleaseIdentityNotAsserted:vault");

    let a = Violation::LaunchEvidenceIncomplete {
        obligation: LaunchObligation::D5Receipts,
        detail: same_detail.clone(),
    };
    let b = Violation::LaunchEvidenceIncomplete {
        obligation: LaunchObligation::NoTargets,
        detail: same_detail.clone(),
    };
    let c = Violation::LaunchEvidenceIncomplete {
        obligation: LaunchObligation::Unreceipted("aaaaa-aa".into()),
        detail: same_detail.clone(),
    };
    assert_ne!(a.key(), b.key(), "LaunchEvidenceIncomplete must key on `obligation`");
    assert_ne!(a.key(), c.key());
    assert_ne!(b.key(), c.key());
    assert_eq!(a.key(), "LaunchEvidenceIncomplete:d5-receipts");

    let a = Violation::PendingDeploymentArtifact {
        path: "deployment/mainnet/vault_init.did".into(),
        detail: same_detail.clone(),
    };
    let b = Violation::PendingDeploymentArtifact {
        path: "deployment/mainnet/other.did".into(),
        detail: same_detail.clone(),
    };
    assert_ne!(a.key(), b.key(), "PendingDeploymentArtifact must key on `path`");

    let a = Violation::AuthorityFieldIncomplete {
        canister: "vault".into(),
        field: "signers".into(),
        detail: same_detail.clone(),
    };
    let b = Violation::AuthorityFieldIncomplete {
        canister: "upgrader".into(),
        field: "signers".into(),
        detail: same_detail.clone(),
    };
    let c = Violation::AuthorityFieldIncomplete {
        canister: "vault".into(),
        field: "threshold".into(),
        detail: same_detail,
    };
    assert_ne!(a.key(), b.key(), "AuthorityFieldIncomplete must key on `canister`");
    assert_ne!(a.key(), c.key(), "AuthorityFieldIncomplete must key on `field`");
    assert_eq!(a.key(), "AuthorityFieldIncomplete:vault.signers");
}

#[test]
fn a_reworded_message_never_changes_an_obligations_identity() {
    let a = Violation::ReleaseIdentityNotAsserted {
        package: "vault".into(),
        detail: "one wording".into(),
    };
    let b = Violation::ReleaseIdentityNotAsserted {
        package: "vault".into(),
        detail: "a completely different wording, rewritten later".into(),
    };
    assert_eq!(
        a.key(),
        b.key(),
        "`key()` must read TYPED fields only. If it re-parsed `detail`, every message edit would \
         silently become a set difference and the declaration would rot on wording changes."
    );
}

#[test]
fn every_non_declarable_kind_keys_to_its_bare_name() {
    let v = Violation::AuthorityBindingViolation { detail: "x".into() };
    assert_eq!(v.key(), "AuthorityBindingViolation");
    let v = Violation::MissingDisposition { candidate: "x".into() };
    assert_eq!(v.key(), "MissingDisposition");
    // Safe only because the loader independently refuses a non-declarable
    // kind-prefix in `expected_pending` — see below.
}

// ── the declaration is refused at LOAD when it cannot mean what it says ──────

fn manifest_with(deploy_gate: &str) -> Result<vcm::Manifest, String> {
    let src = std::fs::read_to_string(repo_root().join("deployment/mainnet/custody_manifest.toml"))
        .expect("real manifest");
    let start = src.find("\n[deploy_gate]").expect("real manifest has [deploy_gate]");
    let end = src[start + 1..].find("\n[bootstrap_ring]").expect("…followed by bootstrap_ring") + start + 1;
    let patched = format!("{}\n{deploy_gate}\n{}", &src[..start], &src[end..]);
    // Unique per CALL: these tests run in parallel and would otherwise delete
    // one another's scratch directory.
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("stsh_r3b_dg_{}_{uniq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("custody_manifest.toml");
    std::fs::write(&p, patched).unwrap();
    let r = vcm::load_manifest(&p);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[test]
fn a_non_declarable_kind_is_refused_at_load() {
    let e = manifest_with(
        "[deploy_gate]\nposture = \"pre-ceremony\"\nexpected_pending = [\"AuthorityBindingViolation:x\"]",
    )
    .expect_err("a non-declarable kind must be refused");
    assert!(e.contains("not \ndeclarable") || e.contains("not declarable"), "{e}");
    assert!(
        e.contains("AuthorityBindingViolation"),
        "the refusal must name the offending key: {e}"
    );
}

#[test]
fn a_duplicate_declared_key_is_refused_at_load() {
    let e = manifest_with(
        "[deploy_gate]\nposture = \"pre-ceremony\"\nexpected_pending = [\
         \"ReleaseIdentityNotAsserted:vault\", \"ReleaseIdentityNotAsserted:vault\"]",
    )
    .expect_err("a duplicate must be refused");
    assert!(e.contains("more than once"), "{e}");
}

#[test]
fn launch_posture_refuses_a_non_empty_allowlist_at_load() {
    let e = manifest_with(
        "[deploy_gate]\nposture = \"launch\"\nexpected_pending = [\"ReleaseIdentityNotAsserted:vault\"]",
    )
    .expect_err("launch posture must refuse an allowlist");
    assert!(e.contains("launch"), "{e}");
    assert!(
        e.contains("ZERO") || e.contains("[]"),
        "the refusal must say launch means zero: {e}"
    );
}

#[test]
fn an_unknown_posture_word_is_refused_at_load() {
    let e = manifest_with("[deploy_gate]\nposture = \"soon\"\nexpected_pending = []")
        .expect_err("an unknown posture must be refused");
    assert!(e.contains("soon"), "{e}");
}

#[test]
fn the_real_manifest_declares_a_well_formed_pre_ceremony_posture() {
    // Positive control: the tree as committed.
    let m = vcm::load_manifest(&repo_root().join("deployment/mainnet/custody_manifest.toml"))
        .expect("the real manifest must load");
    assert_eq!(m.deploy_gate.posture, "pre-ceremony");
    let declared = vcm::declared_pending(&m.deploy_gate);
    assert!(!declared.is_empty(), "pre-ceremony with an EMPTY declaration would mean the deploy \
         checks are all passing — flip the posture to `launch` instead of declaring nothing");
    for k in &declared {
        let kind = k.split(':').next().unwrap();
        assert!(vcm::DECLARABLE_KINDS.contains(&kind), "{k}");
    }
}

// ── the four modes stay pairwise exclusive ──────────────────────────────────

fn run_cli(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_verify_custody_manifest"))
        .args(args)
        .output()
        .expect("binary must run");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}

#[test]
fn deploy_posture_is_mutually_exclusive_with_every_other_mode() {
    // Each flag selects a different SUBSET of the gate, so any combination
    // narrows what exit 0 means. `--deploy-posture` asserts a declaration
    // against the FULL deploy-time set; combined with a narrowing flag it would
    // compare the declaration to a subset, and a declared obligation whose check
    // was skipped would read as satisfied.
    for other in ["--sizes-only", "--coverage-only", "--deploy-time"] {
        let (code, out) = run_cli(&["--deploy-posture", other, "."]);
        assert_eq!(code, 2, "`--deploy-posture {other}` must exit 2, got {code}:\n{out}");
        assert!(out.contains("--deploy-posture") && out.contains(other),
            "the refusal must NAME BOTH flags, got:\n{out}");
    }
}

#[test]
fn deploy_posture_passes_on_the_real_tree_and_is_loud_about_it() {
    let root = repo_root();
    let (code, out) = run_cli(&["--deploy-posture", root.to_str().unwrap()]);
    assert_eq!(code, 0, "the real tree must satisfy its declared posture:\n{out}");
    // AC-10: loud on pass. Silence would make "declared and observed agree"
    // indistinguishable in a log from "this stage never ran".
    assert!(out.contains("posture:"), "the verdict must name the posture:\n{out}");
    assert!(out.contains("declared:"), "the verdict must print the declared key set:\n{out}");
    assert!(out.contains("observed:"), "the verdict must print the observed key set:\n{out}");
    // W0 (f49bcd31) re-armed release identity, so no `ReleaseIdentityNotAsserted:*`
    // key is pending any more; the earlier literal here was a fixture that
    // inherited the record's own pending set (the gate-fixtures-are-unlisted-
    // claims class). Assert the SHAPE of a loud pass instead of one key that
    // moves with every binding act: the verdict must state exact set equality.
    assert!(out.contains("observed set equals the declared set exactly"), "{out}");
}
