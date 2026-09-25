// §P.1 acceptance tests — the 2+9 custody partition.
//
// One committed test per typed violation named in the §P prerequisite packet:
// missing ring member, duplicate ring member, ring receipt presented as
// Vault-created, governed target lacking a `bound` receipt, orphan receipt,
// purpose/principal mismatch, extra receipt, and 2+9 cardinality drift — plus
// the ring-evidence fail-closed contract and the allowlist drift lock.
//
// Every fixture is an inline manifest string written to a per-test scratch
// directory under the crate's target dir. No scratch files anywhere else.

use std::path::{Path, PathBuf};
use verify_custody_manifest as vcm;
use vcm::Violation;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// The nine governed entries, in allowlist order, with placeholder principals
/// when `with_principals`.
fn governed_entries(with_principals: bool) -> String {
    let mut s = String::new();
    for role in vcm::BORN_UNDER_VAULT_ROLES {
        s.push_str("[[canister]]\n");
        s.push_str(&format!("dfx_name = \"{role}\"\n"));
        s.push_str("disposition = \"born_under_vault\"\n");
        if with_principals {
            s.push_str(&format!("principal = \"principal-{role}\"\n"));
        }
        s.push('\n');
    }
    s
}

/// A structurally valid §P.1 manifest. `extra` is appended verbatim, and the
/// named blocks are substituted, so each test mutates exactly one thing.
struct Fixture {
    ring_status: &'static str,
    ring_evidence_sha256: String,
    ring_entries: String,
    governed: String,
    d5_status: &'static str,
    receipts: String,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            ring_status: "pending",
            ring_evidence_sha256: String::new(),
            ring_entries: RING_ENTRIES_OK.into(),
            governed: governed_entries(false),
            d5_status: "pending",
            receipts: String::new(),
        }
    }
}

const RING_ENTRIES_OK: &str = "\
[[canister]]
dfx_name = \"vault\"
disposition = \"bootstrap_ring\"
ring_role = \"vault\"

[[canister]]
dfx_name = \"upgrader\"
disposition = \"bootstrap_ring\"
ring_role = \"upgrader\"

";

impl Fixture {
    fn render(&self) -> String {
        format!(
            "schema_version = {}\n\
             gate_epoch = \"partition-fixture-epoch\"\n\
             \n\
             [deploy_gate]\n\
             posture = \"pre-ceremony\"\n\
             expected_pending = []\n\
             \n\
             [bootstrap_ring]\n\
             status = \"{}\"\n\
             evidence_path = \"deployment/mainnet/bootstrap_ring_evidence.toml\"\n\
             evidence_sha256 = \"{}\"\n\
             members = [\"vault\", \"upgrader\"]\n\
             \n\
             [sources.d1]\n\
             kind = \"dfx_json_launch_entries\"\n\
             declared_complete_for = []\n\
             \n\
             [sources.d2]\n\
             kind = \"canister_ids_json\"\n\
             declared_complete_for = []\n\
             \n\
             [sources.d3]\n\
             kind = \"dns_zone_snapshot\"\n\
             status = \"pending\"\n\
             declared_complete_for = []\n\
             candidates = []\n\
             \n\
             [sources.d4]\n\
             kind = \"artifact2_evidenced_set\"\n\
             status = \"pending\"\n\
             declared_complete_for = []\n\
             candidates = []\n\
             \n\
             [sources.d5]\n\
             kind = \"vault_create_canister_receipts\"\n\
             status = \"{}\"\n\
             declared_complete_for = [\"vault_created_production\"]\n\
             {}\n\
             {}{}",
            vcm::MANIFEST_SCHEMA_VERSION,
            self.ring_status,
            self.ring_evidence_sha256,
            self.d5_status,
            if self.receipts.is_empty() {
                "receipts = []".to_string()
            } else {
                self.receipts.clone()
            },
            self.ring_entries,
            self.governed,
        )
    }

    /// Write the manifest into a fresh scratch dir and run `check_partition`
    /// against the REAL repo root (the allowlist drift lock reads the live
    /// vault source; a fixture that stubbed it would lock nothing).
    fn check(&self, name: &str) -> Vec<Violation> {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("custody_manifest.toml");
        std::fs::write(&path, self.render()).expect("write fixture");
        let m = vcm::load_manifest(&path)
            .unwrap_or_else(|e| panic!("fixture {name} must parse: {e}"));
        vcm::check_partition(&repo_root(), &m)
    }
}

/// One `bound` receipt per governed role — the complete D5 bijection.
fn full_bound_receipts() -> String {
    let mut s = String::new();
    for (i, role) in vcm::BORN_UNDER_VAULT_ROLES.iter().enumerate() {
        s.push_str("[[sources.d5.receipts]]\n");
        s.push_str(&format!("principal = \"principal-{role}\"\n"));
        s.push_str(&format!("manifest_purpose = \"{role}\"\n"));
        s.push_str("status = \"bound\"\n");
        s.push_str(&format!("proposal_id = {}\n", i + 1));
        s.push_str(&format!("created_at_ns = {}\n", 1_700_000_000_000_000_000u64 + i as u64));
        s.push('\n');
    }
    s
}

// ── Positive controls ────────────────────────────────────────────────────────

/// The pre-ceremony state: ring pending, D5 pending, 2+9 declared. Passes.
#[test]
fn pre_ceremony_partition_passes() {
    let v = Fixture::default().check("pre_ceremony");
    assert!(v.is_empty(), "pre-ceremony partition must PASS, got: {v:?}");
}

/// The post-ceremony state: nine governed principals, nine `bound` receipts.
#[test]
fn complete_bijection_passes() {
    let v = Fixture {
        governed: governed_entries(true),
        d5_status: "populated",
        receipts: full_bound_receipts(),
        ..Default::default()
    }
    .check("complete_bijection");
    assert!(v.is_empty(), "complete D5 bijection must PASS, got: {v:?}");
}

/// The real committed manifest must satisfy the partition contract.
#[test]
fn committed_manifest_satisfies_the_partition() {
    let root = repo_root();
    let m = vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml"))
        .expect("committed manifest parses");
    let v = vcm::check_partition(&root, &m);
    assert!(v.is_empty(), "committed manifest must satisfy §P.1, got: {v:?}");
}

// ── Negative controls — one per named violation ──────────────────────────────

#[test]
fn missing_ring_member_fails() {
    let ring = RING_ENTRIES_OK
        .split("[[canister]]\ndfx_name = \"upgrader\"")
        .next()
        .unwrap()
        .to_string();
    let v = Fixture { ring_entries: ring, ..Default::default() }.check("missing_ring_member");
    assert!(
        v.iter()
            .any(|x| matches!(x, Violation::RingMemberMissing { role } if role == "upgrader")),
        "must FAIL with RingMemberMissing(upgrader), got: {v:?}"
    );
}

#[test]
fn duplicate_ring_member_fails() {
    let ring = format!(
        "{RING_ENTRIES_OK}[[canister]]\ndfx_name = \"vault_again\"\n\
         disposition = \"bootstrap_ring\"\nring_role = \"vault\"\n\n"
    );
    let v = Fixture { ring_entries: ring, ..Default::default() }.check("duplicate_ring_member");
    assert!(
        v.iter()
            .any(|x| matches!(x, Violation::RingMemberDuplicate { role } if role == "vault")),
        "must FAIL with RingMemberDuplicate(vault), got: {v:?}"
    );
}

/// A D5 receipt claiming the Vault or Upgrader as Vault-created. The Vault
/// cannot create the ring, so this is forged or misfiled provenance — and it
/// must never be accepted as a governed binding.
#[test]
fn ring_receipt_presented_as_vault_created_fails() {
    let receipts = "\
[[sources.d5.receipts]]
principal = \"principal-upgrader\"
manifest_purpose = \"upgrader\"
status = \"bound\"
proposal_id = 1
created_at_ns = 1700000000000000000
"
    .to_string();
    let v = Fixture {
        d5_status: "populated",
        receipts,
        governed: governed_entries(true),
        ..Default::default()
    }
    .check("ring_receipt");
    assert!(
        v.iter()
            .any(|x| matches!(x, Violation::RingReceiptPresentedAsVaultCreated { .. })),
        "must FAIL with RingReceiptPresentedAsVaultCreated, got: {v:?}"
    );
}

/// An `orphaned_purpose_conflict` receipt is custody visibility, NOT a
/// binding: the governed role it names is still unbound.
#[test]
fn governed_target_without_bound_receipt_fails() {
    let receipts = full_bound_receipts().replace(
        "principal = \"principal-treasury\"\nmanifest_purpose = \"treasury\"\nstatus = \"bound\"",
        "principal = \"principal-treasury\"\nmanifest_purpose = \"treasury\"\n\
         status = \"orphaned_purpose_conflict\"",
    );
    let v = Fixture {
        d5_status: "populated",
        receipts,
        governed: governed_entries(true),
        ..Default::default()
    }
    .check("unbound_governed");
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::GovernedTargetUnbound { detail } if detail.contains("treasury")
        )),
        "an orphaned receipt must NOT satisfy the binding, got: {v:?}"
    );
}

#[test]
fn orphan_receipt_fails() {
    let receipts = format!(
        "{}[[sources.d5.receipts]]\nprincipal = \"principal-nobody\"\n\
         manifest_purpose = \"verifier\"\nstatus = \"bound\"\nproposal_id = 99\n\
         created_at_ns = 1700000000000000099\n",
        full_bound_receipts()
    );
    let v = Fixture {
        d5_status: "populated",
        receipts,
        governed: governed_entries(true),
        ..Default::default()
    }
    .check("orphan_receipt");
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::OrphanReceipt { detail } if detail.contains("principal-nobody")
        )),
        "must FAIL with OrphanReceipt, got: {v:?}"
    );
}

/// The receipt's purpose and the principal it binds disagree: the `verifier`
/// purpose is presented against the treasury's principal.
#[test]
fn purpose_principal_mismatch_fails() {
    let receipts = full_bound_receipts().replace(
        "principal = \"principal-treasury\"\nmanifest_purpose = \"treasury\"",
        "principal = \"principal-treasury\"\nmanifest_purpose = \"verifier\"",
    );
    let v = Fixture {
        d5_status: "populated",
        receipts,
        governed: governed_entries(true),
        ..Default::default()
    }
    .check("purpose_mismatch");
    assert!(
        v.iter().any(|x| matches!(x, Violation::ReceiptPurposeMismatch { .. })),
        "must FAIL with ReceiptPurposeMismatch, got: {v:?}"
    );
}

/// A second `bound` receipt for an already-bound role. The allowlist roles are
/// one-shot; two bindings mean one of them is not what it claims to be.
#[test]
fn extra_receipt_fails() {
    let receipts = format!(
        "{}[[sources.d5.receipts]]\nprincipal = \"principal-treasury\"\n\
         manifest_purpose = \"treasury\"\nstatus = \"bound\"\nproposal_id = 98\n\
         created_at_ns = 1700000000000000098\n",
        full_bound_receipts()
    );
    let v = Fixture {
        d5_status: "populated",
        receipts,
        governed: governed_entries(true),
        ..Default::default()
    }
    .check("extra_receipt");
    assert!(
        v.iter().any(|x| matches!(x, Violation::ExtraReceipt { .. })),
        "must FAIL with ExtraReceipt, got: {v:?}"
    );
}

/// Cardinality drift from 2+9 — a governed role silently dropped.
#[test]
fn cardinality_drift_fails() {
    let governed = governed_entries(false)
        .replace("[[canister]]\ndfx_name = \"vetkeys\"\ndisposition = \"born_under_vault\"\n\n", "");
    let v = Fixture { governed, ..Default::default() }.check("cardinality_drift");
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::PartitionCardinalityDrift { detail } if detail.contains("vetkeys")
        )),
        "must FAIL with PartitionCardinalityDrift, got: {v:?}"
    );
}

/// A tenth governed role — the case the runbook's disposable proof target
/// would have needed. It is not representable, and the checker says so.
#[test]
fn tenth_governed_role_fails() {
    let governed = format!(
        "{}[[canister]]\ndfx_name = \"disposable_proof_target\"\n\
         disposition = \"born_under_vault\"\n\n",
        governed_entries(false)
    );
    let v = Fixture { governed, ..Default::default() }.check("tenth_role");
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::PartitionCardinalityDrift { detail }
                if detail.contains("disposable_proof_target")
        )),
        "a tenth governed role must FAIL, got: {v:?}"
    );
}

// ── Ring evidence: fail-closed, never an empty pass ──────────────────────────

/// Populated ring evidence whose artifact does not exist fails closed.
#[test]
fn populated_ring_evidence_missing_artifact_fails() {
    let v = Fixture {
        ring_status: "populated",
        ring_evidence_sha256: "0".repeat(64),
        ..Default::default()
    }
    .check("ring_evidence_missing");
    assert!(
        v.iter().any(|x| matches!(x, Violation::RingEvidenceUnavailable { .. })),
        "missing ring evidence must FAIL CLOSED, got: {v:?}"
    );
}

/// Populated ring evidence with no pinned hash fails closed — unpinned
/// evidence is unverifiable evidence.
#[test]
fn populated_ring_evidence_unpinned_fails() {
    let v = Fixture { ring_status: "populated", ..Default::default() }
        .check("ring_evidence_unpinned");
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::RingEvidenceUnavailable { detail } if detail.contains("evidence_sha256")
        )),
        "unpinned ring evidence must FAIL CLOSED, got: {v:?}"
    );
}

/// A ring principal asserted while the ceremony input is still pending is an
/// authored fact — exactly what this manifest forbids.
#[test]
fn ring_principal_without_evidence_fails() {
    let ring = RING_ENTRIES_OK.replace(
        "dfx_name = \"vault\"\ndisposition = \"bootstrap_ring\"",
        "dfx_name = \"vault\"\nprincipal = \"principal-vault\"\ndisposition = \"bootstrap_ring\"",
    );
    let v = Fixture { ring_entries: ring, ..Default::default() }.check("ring_principal_pending");
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::RingEvidenceUnavailable { detail } if detail.contains("pending")
        )),
        "an unevidenced ring principal must FAIL, got: {v:?}"
    );
}

// ── The mirror is locked to the Vault source ─────────────────────────────────

/// The checker mirrors `BORN_UNDER_VAULT_ROLES` rather than depending on the
/// vault crate (which would move `Cargo.lock`, a production build input, and
/// disarm the release tripwire). The mirror must equal the live source.
#[test]
fn allowlist_mirror_equals_vault_source() {
    let source = vcm::vault_born_under_vault_roles(&repo_root()).expect("vault allowlist scan");
    assert_eq!(
        source,
        vcm::BORN_UNDER_VAULT_ROLES.to_vec(),
        "the mirrored allowlist has drifted from canisters/vault/src/lib.rs"
    );
}

/// A drifted mirror is reported, not tolerated: pointing the checker at a root
/// whose vault source declares a different allowlist fails typed.
#[test]
fn allowlist_drift_is_reported() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("allowlist_drift");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("canisters/vault/src")).expect("scratch dir");
    std::fs::write(
        dir.join("canisters/vault/src/lib.rs"),
        "pub const BORN_UNDER_VAULT_ROLES: [&str; 2] = [\n    \"treasury\",\n    \"vesting\",\n];\n",
    )
    .expect("write stub vault source");
    let path = dir.join("custody_manifest.toml");
    std::fs::write(&path, Fixture::default().render()).expect("write fixture");
    let m = vcm::load_manifest(&path).expect("fixture parses");
    let v = vcm::check_partition(&dir, &m);
    assert!(
        v.iter().any(|x| matches!(x, Violation::RoleAllowlistDrift { .. })),
        "allowlist drift must be REPORTED, got: {v:?}"
    );
}

/// An unreadable vault source fails closed as drift, never as a silent pass.
#[test]
fn unreadable_vault_source_fails_closed() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no_vault_source");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("custody_manifest.toml");
    std::fs::write(&path, Fixture::default().render()).expect("write fixture");
    let m = vcm::load_manifest(&path).expect("fixture parses");
    let v = vcm::check_partition(&dir, &m);
    assert!(
        v.iter().any(|x| matches!(x, Violation::RoleAllowlistDrift { .. })),
        "an unreadable allowlist must FAIL CLOSED, got: {v:?}"
    );
}

// ── Schema-version discipline ────────────────────────────────────────────────

/// A schema_version 1 manifest — one with no partition at all — is refused
/// outright rather than read as an unpartitioned pass.
#[test]
fn schema_version_1_is_refused() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("schema_v1");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("custody_manifest.toml");
    std::fs::write(&path, Fixture::default().render().replace("schema_version = 2", "schema_version = 1"))
        .expect("write fixture");
    let err = vcm::load_manifest(&path).expect_err("schema 1 must be refused");
    assert!(err.contains("unsupported schema_version 1"), "got: {err}");
}
