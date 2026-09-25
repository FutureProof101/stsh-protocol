// Acceptance fixtures for the custody coverage gate (freeze §13.2a) and the
// §8 size invariant. Every fixture is a self-contained directory under
// tests/fixtures — no scratch files anywhere else.

use std::path::{Path, PathBuf};
use verify_custody_manifest as vcm;
use vcm::Violation;

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run_fixture(name: &str) -> Vec<Violation> {
    let dir = fixture_dir(name);
    let manifest = vcm::load_manifest(&dir.join("custody_manifest.toml"))
        .unwrap_or_else(|e| panic!("fixture {name}: manifest must parse: {e}"));
    let d1 = vcm::load_d1(&dir.join("dfx.json")).expect("fixture dfx.json");
    let d2 = vcm::load_d2(&dir.join("canister_ids.json")).expect("fixture canister_ids.json");
    vcm::check_coverage(&manifest, &d1, &d2)
}

// ── Positive controls ────────────────────────────────────────────────────────

/// The REAL s3tyu case (corrected round 3, RR3-2): s3tyu is ABSENT from D2
/// and found through D3/D4; D2 is not declared complete for out-of-manifest
/// canisters, so the candidate still receives exactly one disposition.
#[test]
fn s3tyu_only_positive_control_passes() {
    let v = run_fixture("s3tyu_positive");
    assert!(v.is_empty(), "s3tyu positive control must PASS, got: {v:?}");
}

/// zmvwg-only discovery: present only in D3, absent from D1 and D2 — passes
/// for the same reason (no declared-complete source claims its universe).
#[test]
fn zmvwg_only_positive_control_passes() {
    let v = run_fixture("zmvwg_positive");
    assert!(v.is_empty(), "zmvwg positive control must PASS, got: {v:?}");
}

/// Generic synthetic single-source candidate (deliberately NOT labeled s3tyu).
#[test]
fn generic_single_source_candidate_passes() {
    let v = run_fixture("generic_single_source");
    assert!(v.is_empty(), "generic single-source fixture must PASS, got: {v:?}");
}

// ── Negative control ─────────────────────────────────────────────────────────

/// A union element with no manifest disposition at all must FAIL.
#[test]
fn missing_disposition_negative_control_fails() {
    let v = run_fixture("negative_missing_disposition");
    assert!(
        v.iter().any(|x| matches!(x, Violation::MissingDisposition { candidate } if candidate.contains("aaaaa-aa"))),
        "must FAIL with MissingDisposition, got: {v:?}"
    );
}

// ── Temporal-semantics controls (RR3-3 / R4-H1) ─────────────────────────────

/// A legitimate controller change between two differently-timestamped,
/// same-epoch snapshots FAILS as typed StaleEvidence — never a pass, never a
/// FactConflict.
#[test]
fn legitimate_transition_between_snapshots_fails_as_stale_evidence() {
    let v = run_fixture("stale_evidence");
    assert!(!v.is_empty(), "stale evidence must NEVER be a pass");
    assert!(
        v.iter().any(|x| matches!(x, Violation::StaleEvidence { .. })),
        "must be typed StaleEvidence, got: {v:?}"
    );
    assert!(
        !v.iter().any(|x| matches!(x, Violation::FactConflict { .. })),
        "must NOT be misclassified as FactConflict, got: {v:?}"
    );
}

/// Two sources disagreeing on module hash for the same principal at the same
/// observation time, run and epoch is an unexplained FactConflict.
#[test]
fn same_instant_disagreement_fails_as_fact_conflict() {
    let v = run_fixture("fact_conflict");
    assert!(
        v.iter().any(|x| matches!(x, Violation::FactConflict { .. })),
        "must FAIL with FactConflict, got: {v:?}"
    );
    assert!(
        !v.iter().any(|x| matches!(x, Violation::StaleEvidence { .. })),
        "must NOT be misclassified as StaleEvidence, got: {v:?}"
    );
}

/// Facts from DIFFERENT epochs are never compared — because an epoch that is
/// not the manifest gate_epoch is REJECTED outright (SSA L0 defect 6
/// mutation: editing a fact's epoch to dodge a conflict FAILS).
#[test]
fn epoch_dodge_fails_as_epoch_mismatch() {
    let toml = r##"
schema_version = 2
gate_epoch = "epoch-2"

[bootstrap_ring]
status = "pending"
evidence_path = "deployment/mainnet/bootstrap_ring_evidence.toml"
evidence_sha256 = ""
members = ["vault", "upgrader"]

[sources.d1]
kind = "dfx_json_launch_entries"
declared_complete_for = []

[sources.d2]
kind = "canister_ids_json"
declared_complete_for = []

[sources.d3]
kind = "dns_zone_snapshot"
status = "pending"
declared_complete_for = []
candidates = []

[sources.d4]
kind = "artifact2_evidenced_set"
status = "populated"
declared_complete_for = []
collection_run = "run-2"
candidates = ["pyeop-7yaaa-aaaam-ajfja-cai"]

[sources.d5]
kind = "vault_create_canister_receipts"
status = "pending"
declared_complete_for = []
receipts = []

[[facts]]
principal = "pyeop-7yaaa-aaaam-ajfja-cai"
field = "controllers"
semantic = "observed_current"
value = ["4f6wg-dzscu-4ixsl-t57n5-tiilb-4tqcj-i6vzi-3qvqt-5y5fu-d6b6y-cae"]
source = "D4"
network = "ic"
observed_at = "2026-08-02T16:20:17Z"
collection_run = "run-1"
epoch = "epoch-1"

[[canister]]
principal = "pyeop-7yaaa-aaaam-ajfja-cai"
disposition = "set_controller_at_cutover"

[deploy_gate]
posture = "pre-ceremony"
expected_pending = []
"##;
    let manifest: vcm::Manifest = toml::from_str(toml).expect("inline manifest");
    let d1 = std::collections::BTreeSet::new();
    let d2 = std::collections::BTreeMap::new();
    let v = vcm::check_coverage(&manifest, &d1, &d2);
    assert!(
        v.iter().any(|x| matches!(x, Violation::EpochMismatch { .. })),
        "a fact whose epoch dodges the gate epoch must FAIL as EpochMismatch, got: {v:?}"
    );
}

/// Different semantic fields (observed_current vs expected) are never
/// compared either — a cutover expectation disagreeing with a pre-cutover
/// observation is the design, not a conflict.
#[test]
fn different_semantic_fields_are_never_compared() {
    let toml = r##"
schema_version = 2
gate_epoch = "epoch-1"

[bootstrap_ring]
status = "pending"
evidence_path = "deployment/mainnet/bootstrap_ring_evidence.toml"
evidence_sha256 = ""
members = ["vault", "upgrader"]

[sources.d1]
kind = "dfx_json_launch_entries"
declared_complete_for = []

[sources.d2]
kind = "canister_ids_json"
declared_complete_for = []

[sources.d3]
kind = "dns_zone_snapshot"
status = "pending"
declared_complete_for = []
candidates = []

[sources.d4]
kind = "artifact2_evidenced_set"
status = "populated"
declared_complete_for = []
collection_run = "run-1"
candidates = ["pyeop-7yaaa-aaaam-ajfja-cai"]

[sources.d5]
kind = "vault_create_canister_receipts"
status = "pending"
declared_complete_for = []
receipts = []

[[facts]]
principal = "pyeop-7yaaa-aaaam-ajfja-cai"
field = "controllers"
semantic = "observed_current"
value = ["4f6wg-dzscu-4ixsl-t57n5-tiilb-4tqcj-i6vzi-3qvqt-5y5fu-d6b6y-cae"]
source = "D4"
network = "ic"
observed_at = "2026-08-02T16:20:17Z"
collection_run = "run-1"
epoch = "epoch-1"

[[facts]]
principal = "pyeop-7yaaa-aaaam-ajfja-cai"
field = "controllers"
semantic = "expected"
value = ["rrkah-fqaaa-aaaaa-aaaaq-cai"]
source = "D4"
network = "ic"
observed_at = "2026-08-02T16:20:17Z"
collection_run = "run-1"
epoch = "epoch-1"

[[canister]]
principal = "pyeop-7yaaa-aaaam-ajfja-cai"
disposition = "set_controller_at_cutover"

[deploy_gate]
posture = "pre-ceremony"
expected_pending = []
"##;
    let manifest: vcm::Manifest = toml::from_str(toml).expect("inline manifest");
    let v = vcm::check_coverage(&manifest, &std::collections::BTreeSet::new(), &std::collections::BTreeMap::new());
    assert!(
        !v.iter().any(|x| matches!(x, Violation::FactConflict { .. } | Violation::StaleEvidence { .. })),
        "different semantic fields must not be compared, got: {v:?}"
    );
}

// ── §8 size invariant — the deliberately oversized fixture MUST fire ────────

#[test]
fn size_invariant_fires_on_deliberately_oversized_fixture() {
    // A complete encoded install payload one byte over the gate bound, with a
    // proven maximum-length target principal.
    let oversized_wasm = vec![0u8; (vcm::GATE_SIZE_BOUND_BYTES + 1) as usize];
    let n = vcm::encode_install_payload(vcm::max_length_principal(0xA5), &oversized_wasm, &[])
        .expect("encodes");
    assert!(n > vcm::GATE_SIZE_BOUND_BYTES);
    let err = vcm::assert_size("oversized fixture", n).expect_err("must FIRE");
    assert!(
        matches!(err, Violation::SizeViolation { encoded_bytes, bound_bytes, .. }
            if encoded_bytes == n && bound_bytes == vcm::GATE_SIZE_BOUND_BYTES),
        "typed SizeViolation expected, got: {err:?}"
    );
    // And the platform limit itself is documented above the gate bound.
    assert!(vcm::GATE_SIZE_BOUND_BYTES < vcm::PLATFORM_MESSAGE_LIMIT_BYTES);
}

#[test]
fn size_invariant_passes_a_realistic_payload() {
    let wasm = vec![0u8; 800_000]; // stsh_token.wasm magnitude
    let args = vec![0u8; 6_000]; // genesis init args magnitude
    let n = vcm::encode_install_payload(vcm::max_length_principal(0xA5), &wasm, &args)
        .expect("encodes");
    assert!(vcm::assert_size("realistic install", n).is_ok());
    let n = vcm::encode_upgrader_upgrade_payload(&wasm, &args);
    assert!(vcm::assert_size("UpgraderUpgrade", n).is_ok());
    let n = vcm::encode_trigger_vault_upgrade_payload(&wasm, &args);
    assert!(vcm::assert_size("trigger_vault_upgrade", n).is_ok());
    let n = vcm::encode_vault_upgrade_via_upgrader_payload(&wasm, &args);
    assert!(vcm::assert_size("VaultUpgradeViaUpgrader", n).is_ok());
}

/// SSA L0 defect 4: a missing required artifact FAILS — never a zero-arg
/// measurement, never PENDING.
#[test]
fn missing_payload_artifact_fails() {
    let empty = std::env::temp_dir().join(format!("vcm-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let (measured, violations) = vcm::measure_payloads(&empty);
    assert!(measured.is_empty());
    assert!(
        violations
            .iter()
            .all(|v| matches!(v, Violation::MissingPayloadArtifact { .. })),
        "every payload class must fail as MissingPayloadArtifact, got: {violations:?}"
    );
    assert_eq!(violations.len(), vcm::INLINE_PAYLOAD_ARTIFACTS.len());
    std::fs::remove_dir_all(&empty).ok();
}

/// SSA L0 defect 4: the real token genesis init artifact encodes EXACTLY —
/// not a text-length proxy.
#[test]
fn token_genesis_args_are_the_real_encoded_value() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bytes = vcm::encode_init_artifact(&root.join("deployment/mainnet/stsh_token_init.did"))
        .expect("canonical token init artifact must parse");
    assert!(!bytes.is_empty(), "zero-arg measurements are forbidden");
    // Binary Candid starts with the magic header.
    assert_eq!(&bytes[..4], b"DIDL");
}

/// SSA L0 round-2 defect 4: the pool maximal fixture must cover EVERY field
/// of the real InitArgs (shielded-pool/src/lib.rs:2834) — an omitted Option
/// field silently shrinks the measured payload. Driven by the real SOURCE:
/// field names are scanned from `pub struct InitArgs` and compared against
/// the fixture encoding's type table.
#[test]
fn pool_init_fixture_covers_every_real_init_field() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    // Source side: field names from the real InitArgs struct.
    let src = std::fs::read_to_string(root.join("canisters/shielded-pool/src/lib.rs")).unwrap();
    let start = src.find("pub struct InitArgs {").expect("InitArgs not found");
    let end = src[start..].find("\n}").map(|i| start + i).expect("InitArgs end");
    let source_fields: std::collections::BTreeSet<String> = src[start..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("pub ")
                .and_then(|r| r.split(':').next())
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_'))
        })
        .collect();
    assert!(
        source_fields.contains("verifier_canister"),
        "source scan must find verifier_canister: {source_fields:?}"
    );

    // Fixture side: compile-time reflection over the fixture's Candid type.
    let fixture_fields = vcm::pool_init_fixture_field_names();

    assert_eq!(
        source_fields, fixture_fields,
        "pool init fixture field coverage must EQUAL the real InitArgs fields"
    );

    // And every populated value is maximal: the Option principal is Some.
    let bytes = vcm::init_args_for(&root, "shielded_pool").expect("pool fixture encodes");
    let decoded = vcm::decode_pool_init_fixture(&bytes).expect("fixture decodes");
    assert!(
        decoded.iter().any(|s| s == "verifier_canister_some=true"),
        "verifier_canister must be populated (Some) in the maximal fixture: {decoded:?}"
    );
}

/// SSA L0 round-2 defect 4 audit: the OTHER maximal fixtures were checked
/// for the same omitted-Option-field bug against their .did init shapes —
/// treasury (3 principals), nullifier/merkle/verifier (1 principal), monitor
/// (7 non-optional fields) carry no Option fields, so field-maximal fixtures
/// are provably complete. Pin that audit: every fixture must encode
/// non-empty args.
#[test]
fn all_maximal_fixtures_encode_non_empty_args() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for pkg in [
        "treasury",
        "nullifier_registry",
        "merkle_tree",
        "stsh-verifier",
        "smoke_alarm_monitor",
        "vault",
        "upgrader",
        "stsh_token",
        "vesting",
    ] {
        let bytes = vcm::init_args_for(&root, pkg)
            .unwrap_or_else(|e| panic!("{pkg}: fixture must encode: {e}"));
        assert!(!bytes.is_empty(), "{pkg}: empty args fixture");
    }
}

#[test]
fn monitor_maximal_fixture_matches_production_init_shape_and_values() {
    use candid::CandidType;
    use serde::Serialize;
    use std::collections::BTreeMap;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src = std::fs::read_to_string(root.join("canisters/smoke-alarm-monitor/src/lib.rs"))
        .expect("production monitor source");
    let start = src.find("pub struct MonitorInit {").expect("MonitorInit not found");
    let end = start + src[start..].find("\n}").expect("MonitorInit end");
    let source_types: BTreeMap<String, String> = src[start..end].lines().filter_map(|line| {
        let declaration = line.trim().strip_prefix("pub ")?;
        let (name, rust_type) = declaration.split_once(':')?;
        let candid_type = match rust_type.trim().trim_end_matches(',') {
            "Principal" => "principal",
            "u64" => "nat64",
            "u32" => "nat32",
            other => panic!("unrecognized MonitorInit type for {name}: {other}"),
        };
        Some((name.trim().to_string(), candid_type.to_string()))
    }).collect();

    assert_eq!(source_types.len(), 7, "production MonitorInit field scan drifted");
    assert!(source_types.contains_key("treasury_principal"));
    assert!(source_types.contains_key("pool_attestation_source"));
    assert_eq!(source_types, vcm::monitor_init_fixture_field_types());

    let current = vcm::init_args_for(&root, "smoke_alarm_monitor").unwrap();
    assert_eq!(
        vcm::decode_monitor_init_principal_lengths(&current).unwrap(),
        [29, 29, 29, 29],
        "every monitor principal must use the platform maximum length"
    );

    #[derive(CandidType, Serialize)]
    struct LegacyFiveFieldMonitorInit {
        token_canister: candid::Principal,
        pool_principal: candid::Principal,
        refresh_interval_ns: u64,
        max_staleness_ns: u64,
        history_capacity: u32,
    }
    let p = |fill| vcm::max_length_principal(fill);
    let omitted = candid::encode_one(LegacyFiveFieldMonitorInit {
        token_canister: p(1),
        pool_principal: p(2),
        refresh_interval_ns: u64::MAX,
        max_staleness_ns: u64::MAX,
        history_capacity: u32::MAX,
    }).unwrap();
    let old_enclosing = vcm::encode_install_payload(p(0xA5), &[], &omitted).unwrap();
    let new_enclosing = vcm::encode_install_payload(p(0xA5), &[], &current).unwrap();
    assert!(current.len() > omitted.len(), "old omission under-measures init");
    assert!(new_enclosing > old_enclosing, "old omission under-measures enclosing payload");
    eprintln!(
        "monitor measurement: init {} -> {} (+{}); enclosing empty-wasm {} -> {} (+{})",
        omitted.len(), current.len(), current.len() - omitted.len(),
        old_enclosing, new_enclosing, new_enclosing - old_enclosing
    );
}

// ── SSA L0 defect 5: axis-2 set mutations must FAIL ─────────────────────────

fn real_manifest() -> vcm::Manifest {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml"))
        .expect("the real custody manifest must parse")
}

fn real_sources() -> (std::collections::BTreeSet<String>, std::collections::BTreeMap<String, String>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    (
        vcm::load_d1(&root.join("dfx.json")).expect("dfx.json"),
        vcm::load_d2(&root.join("canister_ids.json")).expect("canister_ids.json"),
    )
}

#[test]
fn real_manifest_is_clean() {
    let m = real_manifest();
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(v.is_empty(), "the real manifest must pass cleanly, got: {v:?}");
}

#[test]
fn deleting_any_axis2_row_fails() {
    let (d1, d2) = real_sources();
    for i in 0..real_manifest().authority_fields.len() {
        let mut m = real_manifest();
        let removed = m.authority_fields.remove(i);
        let v = vcm::check_coverage(&m, &d1, &d2);
        assert!(
            v.iter().any(|x| matches!(x, Violation::AuthoritySetMismatch { .. })),
            "deleting {}.{} must FAIL, got: {v:?}",
            removed.canister,
            removed.field
        );
    }
}

#[test]
fn duplicate_axis2_row_fails() {
    let mut m = real_manifest();
    let dup = m.authority_fields[0].clone();
    m.authority_fields.push(dup);
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(v.iter().any(|x| matches!(x, Violation::AuthoritySetMismatch { .. })));
}

#[test]
fn unknown_axis2_row_fails() {
    let mut m = real_manifest();
    m.authority_fields.push(vcm::AuthorityField {
        canister: "staking".into(),
        field: "REWARD_POOL".into(),
        storage: "somewhere".into(),
        writers: vec!["init".into()],
        launch_value: "x".into(),
        read_back: "y".into(),
    });
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(v.iter().any(|x| matches!(x, Violation::AuthoritySetMismatch { .. })));
}

// ── SSA L0 defect 6: fact-metadata mutations must FAIL ──────────────────────

#[test]
fn semantic_dodge_fails_as_invalid_evidence() {
    let mut m = real_manifest();
    m.facts[0].semantic = "observed_currentish".into();
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(
        v.iter().any(|x| matches!(x, Violation::InvalidEvidence { .. })),
        "editing semantic to a non-enum value must FAIL, got: {v:?}"
    );
}

#[test]
fn fact_epoch_mutation_fails_as_epoch_mismatch() {
    let mut m = real_manifest();
    m.facts[0].epoch = "some-other-epoch".into();
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(
        v.iter().any(|x| matches!(x, Violation::EpochMismatch { .. })),
        "editing a fact's epoch must FAIL as EpochMismatch, got: {v:?}"
    );
}

#[test]
fn empty_evidence_metadata_fails() {
    let mut m = real_manifest();
    m.facts[0].collection_run = String::new();
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(v.iter().any(|x| matches!(x, Violation::InvalidEvidence { .. })));
}

#[test]
fn unknown_source_status_fails() {
    let mut m = real_manifest();
    m.sources.d4.status = "mostly-populated".into();
    let (d1, d2) = real_sources();
    let v = vcm::check_coverage(&m, &d1, &d2);
    assert!(
        v.iter().any(|x| matches!(x, Violation::InvalidEvidence { .. })),
        "a free-string source status must FAIL, got: {v:?}"
    );
}

// ── SSA integration item 6: cutover binding assertion ────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn cutover_binding_holds_on_the_real_tree() {
    let root = repo_root();
    let m = vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let v = vcm::check_cutover_binding(&root, &m);
    assert!(v.is_empty(), "cutover binding must hold, got: {v:?}");
}

#[test]
fn cutover_pairs_present_in_encoded_vault_init_payload() {
    let root = repo_root();
    let bytes = vcm::encode_vault_init_fixture(&root).expect("fixture encodes");
    let pairs = vcm::cutover_pairs_in_vault_init_payload(&bytes).expect("pairs extractable");
    let set: std::collections::BTreeSet<_> = pairs.into_iter().collect();
    assert_eq!(
        set,
        [
            ("solvency_status".to_string(), "pyeop-7yaaa-aaaam-ajfja-cai".to_string()),
            ("wallet_frontend".to_string(), "s3tyu-aaaaa-aaaab-qhdjq-cai".to_string()),
        ]
        .into_iter()
        .collect(),
        "the encoded vault init payload must carry exactly the ruled cutover pairs"
    );
}

/// Mutation: change one manifest cutover row's principal → FAIL.
#[test]
fn cutover_binding_mutation_manifest_row_fails() {
    let root = repo_root();
    let mut m = vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let row = m
        .canisters
        .iter_mut()
        .find(|e| e.disposition == vcm::Disposition::SetControllerAtCutover)
        .expect("a cutover row exists");
    row.principal = Some("aaaaa-aa".into());
    let v = vcm::check_cutover_binding(&root, &m);
    assert!(
        v.iter().any(|x| matches!(x, Violation::CutoverBindingMismatch { .. })),
        "mutating a manifest cutover row must FAIL, got: {v:?}"
    );
}

/// Mutation: change one REQUIRED_CUTOVER pair → FAIL (pure check path).
#[test]
fn cutover_binding_mutation_constant_fails() {
    let root = repo_root();
    let required = vcm::vault_required_cutover(&root).unwrap();
    assert_eq!(required.len(), 2, "exactly the two ruled pairs");
    let m = vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let manifest_rows = vcm::manifest_cutover_rows(&m);
    let bytes = vcm::encode_vault_init_fixture(&root).unwrap();
    let payload = vcm::cutover_pairs_in_vault_init_payload(&bytes).unwrap();
    // Positive control: all three agree.
    assert!(vcm::check_cutover_sets(&required, &manifest_rows, &payload).is_empty());
    // Mutated constant set: FAIL.
    let mut mutated = required.clone();
    mutated[0].1 = "rrkah-fqaaa-aaaaa-aaaaq-cai".into();
    let v = vcm::check_cutover_sets(&mutated, &manifest_rows, &payload);
    assert!(
        v.iter().any(|x| matches!(x, Violation::CutoverBindingMismatch { .. })),
        "mutating a REQUIRED_CUTOVER pair must FAIL, got: {v:?}"
    );
    // Mutated payload (a pair missing): FAIL.
    let v = vcm::check_cutover_sets(&required, &manifest_rows, &payload[..1]);
    assert!(
        v.iter().any(|x| matches!(x, Violation::CutoverBindingMismatch { .. })),
        "a payload missing a cutover pair must FAIL, got: {v:?}"
    );
}

// ── SSA integration INT-02: deploy-time artifact gate ────────────────────────

/// L4-01 real-root state assertion. SEMANTIC CHANGE (SSA-authorized 2026-08-05,
/// L4 authority-pin lane): this previously asserted the real repo root FAILED,
/// because the Upgrader was a knowingly-placeholder principal and no authority
/// record was pinned. Both are now pinned — the real 2-of-3 signer roster
/// (2026-08-04) and the real born-at-bootstrap Upgrader (2026-08-05) — so the
/// real root must now PASS. The assertion direction is inverted deliberately;
/// it tracks the repo's pinned state, which is exactly why the placeholder
/// FAIL-CLOSED property no longer belongs here. That property is preserved,
/// undiluted, in `deploy_time_gate_fails_closed_on_placeholder_authorities`
/// below, which builds a synthetic root and is independent of repo state.
#[test]
fn deploy_time_gate_passes_on_real_root_with_pinned_authorities() {
    let root = repo_root();
    assert!(
        root.join(vcm::VAULT_INIT_ARTIFACT).is_file(),
        "L4 must have produced {} — the deploy-time artifact is missing",
        vcm::VAULT_INIT_ARTIFACT
    );
    let m = vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    // Binding classes only — see `binding_violations`. The launch-evidence and
    // release-identity classes are deliberately open until S10 and are asserted
    // separately by the `r5_3_*` tests.
    let v = binding_violations(vcm::check_deploy_time(&root, &m));
    assert!(
        v.is_empty(),
        "real root with pinned authorities + pinned record must PASS every deploy-gate \
         BINDING (cutover, authority, recovery roster), got: {v:?}"
    );
}

/// L4-01 (SSA HOLD) FAIL-CLOSED property, preserved on a SYNTHETIC root so it is
/// independent of whether the real repo has since pinned its authorities — the
/// same reasoning as `deploy_time_gate_fails_closed_on_artifactless_root`.
///
/// The counterexample is deliberately STRONG: the denylisted placeholder Upgrader
/// appears in BOTH the artifact and the pinned authority record, so the record
/// matches the artifact exactly and set-equality alone would PASS. The signers are
/// valid and distinct, and the cutover pairs are the ruled ones. The ONLY defect is
/// that the upgrader is a forbidden principal — so an AuthorityBindingViolation here
/// can only have been produced by the forbidden-principal rule, not by set drift,
/// a missing record, or a cutover mismatch. Causation is then isolated positively:
/// swapping ONLY the upgrader for a valid principal, leaving everything else byte
/// for byte, must make the very same root PASS.
#[test]
fn deploy_time_gate_fails_closed_on_placeholder_authorities() {
    let tmp = std::env::temp_dir().join(format!("vcm_authz_placeholder_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    // Vault source stub (REQUIRED_CUTOVER) copied from the committed fixture.
    let src =
        std::fs::read_to_string(fixture_dir("deploy_time").join("canisters/vault/src/lib.rs"))
            .unwrap();
    write_file(&tmp.join("canisters/vault/src/lib.rs"), &src);

    let s1 = vcm::max_length_principal(11).to_text();
    let s2 = vcm::max_length_principal(12).to_text();
    let s3 = vcm::max_length_principal(13).to_text();
    // The denylisted placeholder — the exact principal the real artifact carried
    // before the 2026-08-05 pin.
    let placeholder = "rrkah-fqaaa-aaaaa-aaaaq-cai";
    assert!(
        vcm::FORBIDDEN_AUTHORITY_PRINCIPALS.contains(&placeholder),
        "the counterexample must use a genuinely denylisted principal"
    );

    let write_root = |upgrader: &str| {
        let did = format!(
            "(record {{ quorum = record {{ signers = vec {{ \
               principal \"{s1}\"; principal \"{s2}\"; principal \"{s3}\"; \
             }}; threshold = 2 : nat32; upgrader = principal \"{upgrader}\"; }}; \
             cutover_targets = vec {{ \
               record {{ \"principal\" = principal \"pyeop-7yaaa-aaaam-ajfja-cai\"; \
                         disposition = variant {{ SetControllerAtCutover }}; purpose = \"solvency_status\"; }}; \
               record {{ \"principal\" = principal \"s3tyu-aaaaa-aaaab-qhdjq-cai\"; \
                         disposition = variant {{ SetControllerAtCutover }}; purpose = \"wallet_frontend\"; }}; \
             }}; }})"
        );
        write_file(&tmp.join("deployment/mainnet/vault_init.did"), &did);
        // The record carries the SAME upgrader — equality alone would pass.
        // The [recovery] pin and matching upgrader_init.did are VALID here, so
        // the roster binding is genuinely satisfied and the only defect left is
        // the forbidden upgrader.
        let rec = format!(
            "threshold = 2\nsigners = [\n  \"{s1}\",\n  \"{s2}\",\n  \"{s3}\",\n]\nupgrader = \"{upgrader}\"\n{}",
            recovery_section(&s1, &s2, &s3)
        );
        write_file(&tmp.join("deployment/mainnet/vault_authorities.toml"), &rec);
        write_upgrader_init(&tmp, &s1, &s2, &s3);
    };

    let m = vcm::load_manifest(&repo_root().join("deployment/mainnet/custody_manifest.toml"))
        .unwrap();

    // Placeholder upgrader, mirrored in the record → must FAIL CLOSED.
    write_root(placeholder);
    let v = vcm::check_deploy_time(&tmp, &m);
    assert!(
        v.iter().any(|x| matches!(x, Violation::AuthorityBindingViolation { .. })),
        "a denylisted placeholder upgrader must FAIL the deploy gate even when the \
         pinned record matches it exactly, got: {v:?}"
    );
    // The cutover binding must remain correct — only authorities fail.
    assert!(
        !v.iter().any(|x| matches!(x, Violation::CutoverBindingMismatch { .. })),
        "cutover binding must stay correct, got: {v:?}"
    );

    // Causation isolated: change ONLY the upgrader to a valid principal → PASS.
    write_root(&vcm::max_length_principal(19).to_text());
    let v = binding_violations(vcm::check_deploy_time(&tmp, &m));
    assert!(
        v.is_empty(),
        "the identical root with only the forbidden upgrader replaced must PASS every \
         BINDING — proving the failure above was caused by the forbidden-principal rule, \
         got: {v:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Fail-closed coverage (preserved from the pre-L4 test): a root WITHOUT the
/// artifact still fails with the typed PendingDeploymentArtifact. Uses a
/// synthetic artifact-less root so it is independent of whether the real repo
/// has since produced the artifact — the early `is_file()` guard in
/// `check_deploy_time` returns before the manifest is consulted.
#[test]
fn deploy_time_gate_fails_closed_on_artifactless_root() {
    let root = std::env::temp_dir()
        .join(format!("vcm_no_artifact_{}", std::process::id()));
    assert!(
        !root.join(vcm::VAULT_INIT_ARTIFACT).is_file(),
        "the synthetic root must not contain the artifact"
    );
    let m = vcm::load_manifest(
        &repo_root().join("deployment/mainnet/custody_manifest.toml"),
    )
    .unwrap();
    let v = vcm::check_deploy_time(&root, &m);
    assert!(
        v.iter().any(|x| matches!(x, Violation::PendingDeploymentArtifact { .. })),
        "absent artifact must FAIL as PendingDeploymentArtifact, got: {v:?}"
    );
}

fn write_file(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

// ── Truthful release-record fixtures (SSA S10-R2) ────────────────────────────
//
// The old fixture asserted `source_sha = "deadbeef"` and a `1.80.0` toolchain
// and PASSED — which is precisely the defect SSA found: the gate accepted
// fabricated provenance. Fixtures below are TRUTHFUL: a real commit in a real
// git repository, and the toolchain actually running the test. A fixture that
// lies is a fixture that cannot detect the check being removed.

/// Initialise `root` as a real git repository with one real commit, and return
/// that commit's SHA. `source_sha` = HEAD here, which recorded-ancestor
/// semantics accept (ancestor **or equal**).
fn init_git_root(root: &Path) -> String {
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .expect("git must be available for provenance tests");
        assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    };
    std::fs::create_dir_all(root).unwrap();
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "fixture"]);
    write_file(&root.join("seed.txt"), "release-provenance fixture\n");
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "fixture commit"]);
    git(&["rev-parse", "HEAD"]).trim().to_string()
}

/// The ACTIVE toolchain version strings, in the form the record stores them
/// (the tool's own `-V` output with the program-name prefix removed).
fn active_versions() -> (String, String) {
    let v = |bin: &str| {
        let out = std::process::Command::new(bin).arg("-V").output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .strip_prefix(bin)
            .unwrap()
            .trim()
            .to_string()
    };
    (v("rustc"), v("cargo"))
}

/// A complete, TRUTHFUL release record over the given field values.
fn release_record(sha: &str, rustv: &str, cargov: &str, pins: &[(&str, String)]) -> String {
    release_record_at(sha, sha, rustv, cargov, pins)
}

/// R-3a — return a copy of `pins` with exactly ONE named package's hash
/// replaced by a well-formed but wrong value. Tampering by NAME (not by tuple
/// position) is what keeps the ten-artifact negatives attributable.
fn tamper_pin(pins: &[(&'static str, String)], pkg: &str) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = pins.to_vec();
    let hit = out.iter_mut().find(|(p, _)| *p == pkg);
    let hit = hit.unwrap_or_else(|| panic!("no pinned package named {pkg} among {pins:?}"));
    hit.1 = "0".repeat(64);
    out
}

/// R-3a — the pins slice in the shape `release_record*` wants, borrowed from an
/// owned `Vec<(&'static str, String)>`.
fn pin_slice<'a>(pins: &'a [(&'static str, String)]) -> Vec<(&'a str, String)> {
    pins.iter().map(|(p, h)| (*p, h.clone())).collect()
}

/// S11-5 — the full form, with `asserts_identity_at` SEPARATE from
/// `source_sha`.
///
/// The two fields answer different questions — "which tree were these bytes
/// built from" versus "at which head is the byte-equality claim made" — and the
/// negative controls below alter exactly ONE field per case. Collapsing them
/// onto one argument would make every source_sha negative silently falsify the
/// assertion scope too, and a case that changes two fields cannot attribute the
/// failure to either.
fn release_record_at(
    asserts_at: &str,
    sha: &str,
    rustv: &str,
    cargov: &str,
    pins: &[(&str, String)],
) -> String {
    let packages: String = pins.iter().map(|(p, _)| format!(" -p {p}")).collect();
    let tables: String = pins
        .iter()
        .map(|(p, h)| format!("[wasm.\"{p}\"]\nsha256 = \"{h}\"\n"))
        .collect();
    format!(
        "[toolchain]\nrust_version = \"{rustv}\"\ncargo_version = \"{cargov}\"\n\
         [build]\ncommand = \"cargo build --target wasm32-unknown-unknown --release{packages}\"\n\
         features = \"none\"\nsource_sha = \"{sha}\"\n\
         asserts_identity_at = \"{asserts_at}\"\n\
         {tables}"
    )
}

/// Build a synthetic root that PASSES every release-identity check: real git
/// repo, real commit, active toolchain, and Wasms whose hashes are computed
/// from the bytes actually written — all TEN of them (R-3a). Returns
/// (root, sha, rustv, cargov, pins).
fn truthful_release_root(tag: &str) -> (PathBuf, String, String, String, Vec<(&'static str, String)>) {
    let root = std::env::temp_dir().join(format!("vcm_prov_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let sha = init_git_root(&root);
    let (rustv, cargov) = active_versions();
    let pins = write_synthetic_wasms(&root);
    write_file(
        &root.join("deployment/mainnet/release_hashes.toml"),
        &release_record(&sha, &rustv, &cargov, &pin_slice(&pins)),
    );
    (root, sha, rustv, cargov, pins)
}

/// R-3a — write one synthetic Wasm file per `INLINE_PAYLOAD_ARTIFACTS` entry
/// (TEN, not two) under `<root>/target/wasm32-unknown-unknown/release`, each
/// with distinct bytes, and return the (pkg, sha256-of-those-bytes) pairs in
/// registry order. Every release fixture in this file is built from this one
/// helper, so the fixtures track the registry rather than a hand-kept literal.
fn write_synthetic_wasms(root: &std::path::Path) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    std::fs::create_dir_all(&wasm_dir).unwrap();
    vcm::INLINE_PAYLOAD_ARTIFACTS
        .iter()
        .map(|(pkg, file)| {
            let bytes = format!("{pkg}-bytes").into_bytes();
            std::fs::write(wasm_dir.join(file), &bytes).unwrap();
            (*pkg, format!("{:x}", Sha256::digest(&bytes)))
        })
        .collect()
}

/// S11-6 — a CLEAN, FULLY COMMITTED release root, which is the shape the
/// release ceremony actually produces.
///
/// WHY THIS FIXTURE EXISTS. `truthful_release_root` leaves the record
/// UNCOMMITTED, so `git status` is dirty and HEAD is the seed commit. Under the
/// S11-5 arming condition (`HEAD == asserts_identity_at`) that dirtiness was
/// load-bearing: it was the only way the arm could fire at all, because a
/// commit cannot contain its own SHA. SSA caught exactly that. A positive test
/// whose premise is an uncommittable state proves nothing about the ceremony.
///
/// This builds the real thing:
///   B — binding commit (seed + .gitignore for target/)
///   C — record-bearing CHILD of B touching ONLY the record
/// and asserts the working tree is CLEAN afterwards. `asserts_identity_at`
/// points at B, HEAD is C, and B..C is quiescent over BUILD_INPUT_PATHS — so
/// the arm fires on a state that can actually be committed.
///
/// Returns (root, binding_sha_B, head_sha_C, rustv, cargov, pins) where `pins`
/// carries all TEN `INLINE_PAYLOAD_ARTIFACTS` (pkg, sha256) pairs (R-3a).
fn committed_release_root(
    tag: &str,
) -> (PathBuf, String, String, String, String, Vec<(&'static str, String)>) {
    let root = std::env::temp_dir().join(format!("vcm_committed_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .expect("git must be available");
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    };

    // ── B: the binding commit. Carries a .gitignore for target/ so the built
    // artifacts below do not make the tree dirty — mirroring the real
    // repository, where build output is never tracked.
    std::fs::create_dir_all(&root).unwrap();
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "fixture"]);
    write_file(&root.join("seed.txt"), "release-provenance fixture\n");
    write_file(&root.join(".gitignore"), "target/\n");
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "binding commit B"]);
    let b = git(&["rev-parse", "HEAD"]).trim().to_string();

    // Artifacts, hashed from the bytes actually written — all TEN of them.
    let (rustv, cargov) = active_versions();
    let pins = write_synthetic_wasms(&root);

    // ── C: record-bearing child of B, touching ONLY the record. This is the
    // release-binding ceremony's shape, per the adjudication §2 requirement 4.
    write_file(
        &root.join("deployment/mainnet/release_hashes.toml"),
        &release_record_at(&b, &b, &rustv, &cargov, &pin_slice(&pins)),
    );
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "record-bearing child C (record only)"]);
    let c = git(&["rev-parse", "HEAD"]).trim().to_string();

    assert_ne!(b, c, "the record must live in a CHILD of the binding commit");
    assert!(
        git(&["status", "--porcelain"]).trim().is_empty(),
        "the fixture must be CLEAN — a positive that depends on a dirty tree is \
         exactly the defect S11-6 corrects"
    );
    (root, b, c, rustv, cargov, pins)
}

/// R5.3 (landed S1) — `check_deploy_time` now ALSO carries the launch-evidence
/// and release-identity classes, and both are DELIBERATELY unsatisfiable until
/// S10: creation receipts cannot exist before the Vault has created the
/// canisters, and release hashes must derive from the final integrated commit.
/// A complete deploy-gate GREEN is therefore intentionally impossible before
/// S10 — that is the control working, not a regression.
///
/// The three binding tests below predate that and used "the deploy gate is
/// empty" as a PROXY for "the bindings hold". S1 makes that proxy false. Each
/// test's property is unchanged; only the proxy is replaced by naming the
/// binding classes directly.
///
/// This is deliberately NOT a blanket refresh. The two filtered classes have
/// their own dedicated fail-closed tests (`r5_3_*`), and the synthetic roots
/// below carry a real `[recovery]` pin, so the roster binding is genuinely
/// satisfied rather than filtered away.
fn binding_violations(v: Vec<Violation>) -> Vec<Violation> {
    v.into_iter()
        .filter(|x| {
            !matches!(
                x,
                Violation::LaunchEvidenceIncomplete { .. }
                    | Violation::ReleaseIdentityUnbound { .. }
                    // S11-5: the same deploy-time class. On the real repo root
                    // at any head other than `asserts_identity_at` the checker
                    // reports the typed non-assertion, which is CORRECT and is
                    // legitimately pending until the release commit — exactly
                    // like the two above. Filtered here for the same reason and
                    // covered by its own dedicated tests
                    // (`s11_5_*`, `r5_3_release_identity_bound_at_s10`), never
                    // by this proxy.
                    | Violation::ReleaseIdentityNotAsserted { .. }
            )
        })
        .collect()
}

/// The `[recovery]` section a synthetic deployment root needs so the R2.3
/// roster binding is exercised for real: roster == signers, in order, ruled
/// threshold, separate vault.
fn recovery_section(s1: &str, s2: &str, s3: &str) -> String {
    let vault = vcm::max_length_principal(90).to_text();
    format!(
        "\n[recovery]\nmembers = [\n  \"{s1}\",\n  \"{s2}\",\n  \"{s3}\",\n]\n\
         threshold = 2\nvault = \"{vault}\"\n"
    )
}

/// The matching `upgrader_init.did` for a synthetic root.
fn write_upgrader_init(root: &Path, s1: &str, s2: &str, s3: &str) {
    let vault = vcm::max_length_principal(90).to_text();
    write_file(
        &root.join("deployment/mainnet/upgrader_init.did"),
        &format!(
            "(record {{ recovery_members = vec {{ \
               principal \"{s1}\"; principal \"{s2}\"; principal \"{s3}\"; \
             }}; threshold = 2 : nat32; vault = principal \"{vault}\"; }})"
        ),
    );
}

/// Positive control (L4-01): a FULLY valid deployment root — the ruled cutover
/// pairs AND valid, distinct, non-forbidden authorities that EQUAL a matching
/// pinned authority record — passes both bindings. Built programmatically so no
/// real principals are hardcoded.
#[test]
fn deploy_time_gate_passes_with_valid_authorities_and_matching_record() {
    let tmp = std::env::temp_dir().join(format!("vcm_authz_ok_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    // Vault source stub (REQUIRED_CUTOVER) copied from the committed fixture.
    let src =
        std::fs::read_to_string(fixture_dir("deploy_time").join("canisters/vault/src/lib.rs"))
            .unwrap();
    write_file(&tmp.join("canisters/vault/src/lib.rs"), &src);

    let s1 = vcm::max_length_principal(11).to_text();
    let s2 = vcm::max_length_principal(12).to_text();
    let s3 = vcm::max_length_principal(13).to_text();
    let up = vcm::max_length_principal(19).to_text();

    let did = format!(
        "(record {{ quorum = record {{ signers = vec {{ \
           principal \"{s1}\"; principal \"{s2}\"; principal \"{s3}\"; \
         }}; threshold = 2 : nat32; upgrader = principal \"{up}\"; }}; \
         cutover_targets = vec {{ \
           record {{ \"principal\" = principal \"pyeop-7yaaa-aaaam-ajfja-cai\"; \
                     disposition = variant {{ SetControllerAtCutover }}; purpose = \"solvency_status\"; }}; \
           record {{ \"principal\" = principal \"s3tyu-aaaaa-aaaab-qhdjq-cai\"; \
                     disposition = variant {{ SetControllerAtCutover }}; purpose = \"wallet_frontend\"; }}; \
         }}; }})"
    );
    write_file(&tmp.join("deployment/mainnet/vault_init.did"), &did);
    let rec = format!(
        "threshold = 2\nsigners = [\n  \"{s1}\",\n  \"{s2}\",\n  \"{s3}\",\n]\nupgrader = \"{up}\"\n{}",
        recovery_section(&s1, &s2, &s3)
    );
    write_file(&tmp.join("deployment/mainnet/vault_authorities.toml"), &rec);
    write_upgrader_init(&tmp, &s1, &s2, &s3);

    let m = vcm::load_manifest(&repo_root().join("deployment/mainnet/custody_manifest.toml"))
        .unwrap();
    let v = binding_violations(vcm::check_deploy_time(&tmp, &m));
    assert!(
        v.is_empty(),
        "valid authorities + matching record + matching recovery roster must PASS every \
         BINDING, got: {v:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// L4-01 mutation matrix — every authority defect fails closed. Exercises the
/// pure `authority_violations` in-memory (SSA's required mutation list).
#[test]
fn authority_mutations_all_fail_closed() {
    let p = |b: u8| vcm::max_length_principal(b);
    let ok = vec![p(11), p(12), p(13)];
    let up = p(19);
    let rec = vcm::AuthorityRecord {
        signers: ok.clone(),
        threshold: 2,
        upgrader: up,
    };
    let fails = |s: &[candid::Principal], t: u32, u: &candid::Principal, r: Option<&vcm::AuthorityRecord>| {
        !vcm::authority_violations(s, t, u, r).is_empty()
    };

    // Positive baseline.
    assert!(
        vcm::authority_violations(&ok, 2, &up, Some(&rec)).is_empty(),
        "valid authorities + matching record must pass"
    );
    // Absent authority record.
    assert!(fails(&ok, 2, &up, None), "absent record must fail closed");
    // Each changed signer (record mismatch).
    assert!(fails(&[p(99), p(12), p(13)], 2, &up, Some(&rec)), "changed signer 1");
    assert!(fails(&[p(11), p(99), p(13)], 2, &up, Some(&rec)), "changed signer 2");
    assert!(fails(&[p(11), p(12), p(99)], 2, &up, Some(&rec)), "changed signer 3");
    // Duplicate / missing / anonymous signer.
    assert!(fails(&[p(11), p(11), p(12)], 2, &up, Some(&rec)), "duplicate signer");
    assert!(fails(&[p(11), p(12)], 2, &up, Some(&rec)), "missing signer");
    assert!(fails(&[candid::Principal::anonymous(), p(12), p(13)], 2, &up, Some(&rec)), "anonymous signer");
    // Wrong threshold / wrong upgrader.
    assert!(fails(&ok, 3, &up, Some(&rec)), "wrong threshold");
    assert!(fails(&ok, 2, &p(88), Some(&rec)), "wrong upgrader");
    // Forbidden (placeholder) upgrader and signer.
    let ph_up = candid::Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
    assert!(fails(&ok, 2, &ph_up, Some(&rec)), "placeholder upgrader");
    let ph_signers = [
        candid::Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap(),
        p(12),
        p(13),
    ];
    assert!(fails(&ph_signers, 2, &up, Some(&rec)), "placeholder signer");
    // Syntactically valid but incorrectly bound: upgrader equals a signer.
    assert!(fails(&ok, 2, &ok[0], Some(&rec)), "upgrader == signer");
}

/// Mutation: an artifact whose cutover pair is wrong FAILS the three-way
/// check as CutoverBindingMismatch (not PendingDeploymentArtifact).
#[test]
fn deploy_time_gate_rejects_a_wrong_artifact() {
    let root = repo_root();
    let m = vcm::load_manifest(&root.join("deployment/mainnet/custody_manifest.toml")).unwrap();
    let required = vcm::vault_required_cutover(&fixture_dir("deploy_time")).unwrap();
    let manifest_rows = vcm::manifest_cutover_rows(&m);
    let mut wrong = manifest_rows.clone();
    wrong[0].1 = "aaaaa-aa".into();
    let v = vcm::check_cutover_sets(&required, &manifest_rows, &wrong);
    assert!(
        v.iter().any(|x| matches!(x, Violation::CutoverBindingMismatch { .. })),
        "a wrong deployment payload pair must FAIL, got: {v:?}"
    );
}

// ── SSA L0 round-4 defect 2: DID fixture drift lock ─────────────────────────

#[test]
fn did_fixtures_match_committed_dids_at_head() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let v = vcm::check_did_fixtures(&root);
    assert!(v.is_empty(), "pinned fixtures must equal committed DIDs, got: {v:?}");
}

/// Mutation proof: a changed target DID FAILS the drift check (the repin is
/// an enforced, reviewable event — never silent).
#[test]
fn drift_check_fires_on_modified_did() {
    let fixture = "// PINNED FIXTURE — provenance line 1\n// line 2\n// line 3\n// line 4\nservice : {};\n";
    // Committed DID equals the fixture body: passes.
    assert_eq!(
        vcm::fixture_matches_committed(fixture, "service : {};\n").unwrap(),
        true
    );
    // Any target-DID change: FAILS.
    assert_eq!(
        vcm::fixture_matches_committed(fixture, "service : { ping : () -> () };\n").unwrap(),
        false
    );
    // A missing/malformed provenance header is an error, never a pass.
    assert!(vcm::fixture_matches_committed("service : {};\n", "service : {};\n").is_err());
}

// ── R2 (CUST-SSA-002, Critical): Upgrader recovery roster ────────────────────
//
// Every negative below is checked against the PURE `recovery_roster_violations`
// so the assertion is about the rule, not about transient repo state. The real
// tree is asserted separately, once, as a positive control.

fn ps(n: usize) -> Vec<candid::Principal> {
    (0..n).map(|i| vcm::max_length_principal(20 + i as u8)).collect()
}

fn rec_of(members: &[candid::Principal], threshold: u32, vault: candid::Principal) -> vcm::RecoveryRecord {
    vcm::RecoveryRecord { members: members.to_vec(), threshold, vault }
}

fn is_roster(v: &[Violation]) -> bool {
    v.iter().any(|x| matches!(x, Violation::RecoveryRosterViolation { .. }))
}

/// Positive control: pinned roster == Vault signers == install payload, same
/// order, valid threshold, separate vault. Must pass cleanly.
#[test]
fn r2_roster_positive_control_passes() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let rec = rec_of(&m, 2, vault);
    let v = vcm::recovery_roster_violations(Some(&rec), &m, Some((&m, 2, &vault)));
    assert!(v.is_empty(), "byte-identical roster across all surfaces must pass, got: {v:?}");
}

/// The real repository tree: surfaces 1-3 must byte-match today.
#[test]
fn r2_roster_binds_on_the_real_tree() {
    let root = repo_root();
    assert!(
        root.join(vcm::UPGRADER_INIT_ARTIFACT).is_file(),
        "R2.1 must have produced {} — without it the gate verifies a synthesised fiction",
        vcm::UPGRADER_INIT_ARTIFACT
    );
    let encoded = vcm::encode_init_artifact(&root.join(vcm::VAULT_INIT_ARTIFACT)).unwrap();
    let v = vcm::check_recovery_roster(&root, &encoded);
    assert!(v.is_empty(), "real tree roster binding must pass, got: {v:?}");
}

/// A roster differing by ONE principal fails.
#[test]
fn r2_one_differing_principal_fails() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let mut tampered = m.clone();
    tampered[1] = vcm::max_length_principal(77);
    let rec = rec_of(&m, 2, vault);
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&rec), &tampered, Some((&m, 2, &vault)))),
        "a Vault signer set differing by one principal must fail"
    );
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&rec), &m, Some((&tampered, 2, &vault)))),
        "an install payload differing by one principal must fail"
    );
}

/// THE SAME MEMBERS IN A DIFFERENT ORDER fail. This is the fixture that proves
/// the comparison is ordered — a set-equality implementation passes this and is
/// therefore wrong.
#[test]
fn r2_reordered_roster_fails() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let reordered = vec![m[2], m[1], m[0]];
    assert_ne!(
        m.iter().collect::<std::collections::BTreeSet<_>>().len(),
        0,
        "sanity"
    );
    // Same SET, different ORDER — set-equality would accept this.
    let rec = rec_of(&m, 2, vault);
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&rec), &reordered, Some((&m, 2, &vault)))),
        "a reordered Vault signer vector must fail — ordered byte-equality is the requirement"
    );
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&rec), &m, Some((&reordered, 2, &vault)))),
        "a reordered install payload must fail"
    );
}

/// A duplicated principal fails — at every surface, even though the duplicate
/// keeps the vectors equal to each other.
#[test]
fn r2_duplicate_principal_fails() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let dup = vec![m[0], m[0], m[2]];
    let rec = rec_of(&dup, 2, vault);
    // Pinned record, Vault signers and install payload are all byte-identical,
    // so ONLY the duplicate rule can fire here.
    let v = vcm::recovery_roster_violations(Some(&rec), &dup, Some((&dup, 2, &vault)));
    assert!(is_roster(&v), "a duplicated principal must fail even when every surface agrees");
    assert!(
        v.iter().any(|x| format!("{x}").contains("duplicate")),
        "the failure must be attributed to the duplicate rule, got: {v:?}"
    );
}

/// A missing/unparseable `upgrader_init.did` fails CLOSED — never skipped.
#[test]
fn r2_missing_artifact_fails_closed() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let rec = rec_of(&m, 2, vault);
    let v = vcm::recovery_roster_violations(Some(&rec), &m, None);
    assert!(is_roster(&v), "an absent install payload must fail closed, not pass");
}

/// An unpinned roster fails CLOSED — this is the pre-fix state that reported
/// GREEN for an attacker-chosen roster.
#[test]
fn r2_unpinned_roster_fails_closed() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let v = vcm::recovery_roster_violations(None, &m, Some((&m, 2, &vault)));
    assert!(is_roster(&v), "an unpinned recovery roster must fail closed");
}

/// Threshold 1 and threshold 3 both fail: never 1 (V7 §4 D4), never contracted
/// or expanded from the ruled fixed 2 (freeze §6).
#[test]
fn r2_threshold_one_or_three_fails() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    for bad in [1u32, 3u32] {
        let rec = rec_of(&m, bad, vault);
        assert!(
            is_roster(&vcm::recovery_roster_violations(Some(&rec), &m, Some((&m, bad, &vault)))),
            "recovery threshold {bad} must fail — the ruled quorum is exactly 2"
        );
    }
    // A threshold mismatch BETWEEN surfaces fails too.
    let rec = rec_of(&m, 2, vault);
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&rec), &m, Some((&m, 1, &vault)))),
        "an install payload threshold disagreeing with the pin must fail"
    );
}

/// The Vault principal must match the pin, must not be anonymous, and must not
/// be a member of the roster that recovers it.
#[test]
fn r2_vault_target_must_be_pinned_and_separate() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let rec = rec_of(&m, 2, vault);
    let other = vcm::max_length_principal(91);
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&rec), &m, Some((&m, 2, &other)))),
        "an install payload targeting a different Vault must fail"
    );
    let anon = candid::Principal::anonymous();
    let anon_rec = rec_of(&m, 2, anon);
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&anon_rec), &m, Some((&m, 2, &anon)))),
        "an anonymous Vault target must fail"
    );
    // Vault is also a recovery member.
    let member_vault = m[0];
    let mv_rec = rec_of(&m, 2, member_vault);
    assert!(
        is_roster(&vcm::recovery_roster_violations(Some(&mv_rec), &m, Some((&m, 2, &member_vault)))),
        "a Vault that is also a recovery member must fail — the counterpart must be separate"
    );
}

/// A forbidden (placeholder/management/anonymous) principal anywhere in the
/// roster fails, even when every surface agrees byte for byte.
#[test]
fn r2_forbidden_principal_in_roster_fails() {
    let placeholder =
        candid::Principal::from_text(vcm::FORBIDDEN_AUTHORITY_PRINCIPALS[0]).unwrap();
    let m = vec![ps(3)[0], placeholder, ps(3)[2]];
    let vault = vcm::max_length_principal(90);
    let rec = rec_of(&m, 2, vault);
    let v = vcm::recovery_roster_violations(Some(&rec), &m, Some((&m, 2, &vault)));
    assert!(is_roster(&v), "a denylisted principal in the roster must fail");
    assert!(
        v.iter().any(|x| format!("{x}").contains("forbidden")),
        "the failure must be attributed to the forbidden-principal rule, got: {v:?}"
    );
}

/// R2.4 — SCOPE LIMITATION, STATED HONESTLY.
///
/// This proves the FIRST half of R2.4: the verifier no longer verifies a
/// fiction. `init_args_for("upgrader")` reads the committed artifact and has no
/// synthesis fallback, so a gate PASS is now about the real payload.
///
/// It does NOT prove the second half — that the ACTUAL install command consumes
/// this exact file. It cannot: there is no install or deployment path anywhere
/// in this repository, for the ring or for any other canister (`stsh_token_init.did`
/// and `vesting_init.did` are equally unconsumed). The canonical install command
/// lives in the runbook, whose destination is BLOCKED on §10 item 3.
///
/// R2.4's install half is therefore formally RECLASSIFIED AS BLOCKED, not
/// silently claimed. When the runbook destination is ruled, the install command
/// must be pinned and tested to consume `deployment/mainnet/upgrader_init.did`
/// byte for byte — verifying an artifact that deployment then reconstructs
/// independently is exactly the hole R2.4 exists to close.
#[test]
fn r2_install_consumes_pinned_artifact() {
    let root = repo_root();
    let from_artifact = vcm::init_args_for(&root, "upgrader").expect("upgrader init args");
    let direct =
        vcm::encode_init_artifact(&root.join(vcm::UPGRADER_INIT_ARTIFACT)).expect("encode");
    assert_eq!(
        from_artifact, direct,
        "init_args_for(\"upgrader\") must BE the encoding of the committed artifact"
    );
    // The decoded roster must equal WHAT WAS INSTALLED, byte for byte and in
    // order. Before the 2026-09-21 rotation that was the pin; after it
    // (ROT-LEDGER-FILL, Q5-A) the pin is the LIVE roster and the install-time
    // roster is `[rotation.bootstrap].upgrader_members`. The artifact cannot
    // change — it records an install that already happened — so it is compared
    // to the snapshot of it, not to a pin that has since moved.
    let (members, threshold, vault) = vcm::upgrader_init_roster(&from_artifact).unwrap();
    let pinned = vcm::load_recovery_record(&root).unwrap().expect("[recovery] must be pinned");
    let lock = vcm::load_rotation_lockstep(&root).expect("the rotation lockstep must load");
    assert_eq!(vault, pinned.vault);
    let bytes = |ps: &[candid::Principal]| {
        ps.iter().map(|p| p.as_slice().to_vec()).collect::<Vec<_>>()
    };
    let (expected_members, expected_threshold) = if lock.rotated {
        (lock.bootstrap_upgrader_members.clone(), lock.bootstrap_upgrader_threshold)
    } else {
        (pinned.members.clone(), pinned.threshold)
    };
    assert_eq!(threshold, expected_threshold);
    assert_eq!(
        bytes(&members),
        bytes(&expected_members),
        "install payload roster must equal the install-time roster as an ordered byte-vector"
    );
    // And the pin must be the LIVE roster: the last EXECUTED upgrader row.
    if lock.rotated {
        assert_eq!(
            bytes(&pinned.members),
            bytes(&lock.last_upgrader_new_members),
            "the pin must equal the last EXECUTED [[rotation.upgrader]] row's new_members"
        );
    }
}

// ── R5.3: the gate must not report GREEN on incomplete launch evidence ───────

/// S10 (R2.5): release identity is now BOUND. This test previously asserted the
/// PRE-S10 state — that `deployment/mainnet/release_hashes.toml` was absent and
/// the control fired. Its own docstring named S10 as the point the artifact
/// arrives, so landing the record is precisely what flips it; leaving the old
/// assertion in place would have made a green gate mean "the release is still
/// unpinned". The fail-closed control itself is NOT weakened here: it is proved
/// by `r2_release_hash_mismatch_fails` (mutated hash) and
/// `r5_3_release_record_without_build_invocation_fails` (missing invocation),
/// both of which still exercise the absent/mutated paths on synthetic roots.
///
/// BUILD-ORDER DEPENDENCY, STATED: `check_release_identity` fails closed when
/// the production Wasm is not built — a pinned hash never compared to an
/// artifact is unbound. At the ASSERTING head this test therefore asserts the
/// bound verdict only when the artifacts exist, and the fail-closed verdict
/// when they do not. Both branches are real assertions; neither is a skip.
///
/// IDENTITY SCOPE (CTO ruling S11 R5.3, shape (b); arming condition superseded
/// by the S11-6 adjudication §2). Byte-equality binds only while the range
/// `asserts_identity_at..HEAD` is QUIESCENT over `BUILD_INPUT_PATHS`. This test
/// derives that arm exactly as the checker does, and BOTH arms assert:
///
///   - armed → the record must match the built Wasms exactly (the original
///     property, undiminished);
///   - disarmed → a TYPED `ReleaseIdentityNotAsserted` outcome, and explicitly
///     NOT an empty verdict. A disarmed head must never be able to report
///     release-identity success, which is the outcome that would actually be
///     dangerous.
///
/// WHY THE SCOPE CHANGED: the unconditional form bound release identity to
/// every future head of the branch, so any legitimate vault/upgrader source
/// change — which S11-1 and S11-2 are, by SSA direction — turned the gate red.
/// The alternatives were re-pinning per corrective (laundering unreviewed bytes
/// into a "release" record) or a standing-red gate (which trains readers past
/// the VERDICT line); the ruling rejected both.
#[test]
fn r5_3_release_identity_bound_at_s10() {
    let root = repo_root();
    let record = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    assert!(
        record.is_file(),
        "{} must exist at S10 — R2.5 release identity is landed, not pending",
        vcm::RELEASE_RECORD_ARTIFACT
    );

    // Read the binding commit out of the record and derive the ARM the same way
    // the checker does — S11-6 quiescence over BUILD_INPUT_PATHS, NOT HEAD
    // equality. Deriving it any other way would let this test and the checker
    // disagree about which arm applies; the previous HEAD-equality form agreed
    // with the checker only by coincidence, and would have taken the wrong arm
    // on a docs-only child of the binding commit.
    let raw = std::fs::read_to_string(&record).expect("record is readable");
    let doc: toml::Value = raw.parse().expect("record is well-formed TOML");
    let asserts_at = doc
        .get("build")
        .and_then(|b| b.get("asserts_identity_at"))
        .and_then(|x| x.as_str())
        .expect("the record must declare build.asserts_identity_at")
        .trim()
        .to_string();
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .expect("git must be available");
        assert!(o.status.success(), "git {args:?} must succeed");
        String::from_utf8(o.stdout).unwrap()
    };
    let head = git(&["rev-parse", "HEAD"]).trim().to_string();
    let touching = {
        let mut args: Vec<String> = vec![
            "log".into(),
            "--oneline".into(),
            "--no-decorate".into(),
            format!("{asserts_at}..HEAD"),
            "--".into(),
        ];
        args.extend(vcm::BUILD_INPUT_PATHS.iter().map(|p| (*p).to_string()));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        git(&refs).lines().filter(|l| !l.trim().is_empty()).count()
    };
    let armed = touching == 0;

    let v = vcm::check_release_identity(&root);

    if !armed {
        // DISARMED. Typed outcome, never a pass.
        assert!(
            v.iter().any(|x| matches!(x, Violation::ReleaseIdentityNotAsserted { .. })),
            "with {touching} production-touching commit(s) since {asserts_at} (head {head}) \
             the checker must report the TYPED non-assertion, got: {v:?}"
        );
        assert!(
            !v.is_empty(),
            "a disarmed head must never report release-identity success"
        );
        // And it must NOT have silently compared: a byte-equality failure here
        // would mean the arming was not applied at all.
        assert!(
            !v.iter().any(|x| format!("{x}").contains("does not derive from the reviewed tree")),
            "byte-equality must not be evaluated at a disarmed head, got: {v:?}"
        );
        return;
    }

    // ARMED — the original property, at full force.
    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    let built = vcm::INLINE_PAYLOAD_ARTIFACTS
        .iter()
        .all(|(_, f)| wasm_dir.join(f).is_file());
    if built {
        assert!(
            v.is_empty(),
            "at an ARMED head the landed release record must match the built \
             production Wasms exactly, got: {v:?}"
        );
    } else {
        assert!(
            v.iter().any(|x| matches!(x, Violation::ReleaseIdentityUnbound { .. })),
            "a pinned hash with no built artifact to compare against must fail closed, got: {v:?}"
        );
    }
}

/// S11-6 required test — CLEAN COMMITTED-ROOT POSITIVE: the arm fires, and
/// byte-equality PASSES, on a state that can actually be committed.
///
/// THIS IS THE TEST SSA'S RETURN REQUIRED. Its predecessor armed only because
/// `truthful_release_root` left the record UNCOMMITTED, making HEAD equal to
/// `asserts_identity_at` on a DIRTY tree. Under the S11-5 condition that was
/// the only way to arm at all — a commit cannot contain its own SHA — so the
/// positive rested on an uncommittable premise and proved nothing about the
/// release ceremony.
///
/// Here the record lives in a COMMITTED child of the binding commit, the
/// working tree is clean, and the arm fires because the range B..C touches no
/// production build input. The clean-tree assertion is made explicitly, so a
/// regression back to the dirty-tree premise fails here rather than passing
/// quietly.
#[test]
fn s11_6_clean_committed_root_arms_and_byte_equality_passes() {
    let (root, b, c, _rustv, _cargov, _pins) = committed_release_root("pos");
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    };

    // The premise, asserted rather than assumed: HEAD is NOT the binding
    // commit, and the tree is clean. Both were false in the predecessor.
    assert_ne!(b, c);
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), c);
    assert!(git(&["status", "--porcelain"]).trim().is_empty(), "clean tree");

    let v = vcm::check_release_identity(&root);
    assert!(
        v.is_empty(),
        "S11-6: a clean committed root whose child touches only the record must ARM \
         and PASS byte-equality — this is the release ceremony's shape, got: {v:?}"
    );
}

/// S11-6 required test — ARMED MISMATCH ON A CLEAN COMMITTED ROOT IS RED.
///
/// The positive above only shows the arm can fire. This shows that when it
/// fires it BITES: same clean committed shape, wrong pinned bytes, and the
/// verdict must be a byte-equality failure — not a non-assertion, and not a
/// pass. Without this, an implementation that armed and then skipped the
/// comparison would satisfy the positive.
#[test]
fn s11_6_armed_mismatch_on_clean_committed_root_is_red() {
    let (root, b, _c, rustv, cargov, pins) = committed_release_root("mismatch");
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    };
    // Amend the record in a further record-only commit, so the tree stays clean
    // and the range stays quiescent — only the pinned bytes are wrong.
    write_file(
        &root.join("deployment/mainnet/release_hashes.toml"),
        &release_record_at(&b, &b, &rustv, &cargov, &pin_slice(&tamper_pin(&pins, "vault"))),
    );
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "record-only: wrong vault pin"]);
    assert!(git(&["status", "--porcelain"]).trim().is_empty(), "clean tree");

    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("vault.wasm sha256")),
        "an ARMED head with a mutated pin must fail on the hash, got: {v:?}"
    );
    assert!(
        !v.iter().any(|x| matches!(x, Violation::ReleaseIdentityNotAsserted { .. })),
        "a quiescent range is ARMED — it must not report a non-assertion, got: {v:?}"
    );
}

/// S11-6 required test — A PRODUCTION-TOUCHING CHILD DISARMS, EVEN WITH
/// MATCHING BYTES.
///
/// The sharp one. The artifacts on disk still match the pins exactly, so a
/// checker that ignored quiescence would report SUCCESS here, and one that
/// compared anyway would still find equality. Only a correctly-armed checker
/// reports the typed non-assertion — and it must not be an empty verdict, and
/// must not be a byte-equality failure either.
///
/// Each `BUILD_INPUT_PATHS` entry is exercised independently, on its own clean
/// committed root. Testing only one would leave the others unproven, and an
/// implementation that listed a single path would pass a combined case.
#[test]
fn s11_6_production_touching_child_disarms_for_each_build_input() {
    for (tag, rel) in [
        ("canisters", "canisters/vault/src/lib.rs"),
        ("cargotoml", "Cargo.toml"),
        ("cargolock", "Cargo.lock"),
        ("toolchain", "rust-toolchain.toml"),
    ] {
        let (root, _b, _c, _rustv, _cargov, _pins) = committed_release_root(tag);
        let git = |args: &[&str]| {
            let o = std::process::Command::new("git")
                .args(["-C", &root.to_string_lossy()])
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8(o.stdout).unwrap()
        };

        // Baseline: armed and passing BEFORE the production change. Without it
        // this case could pass because the fixture was broken all along.
        assert!(
            vcm::check_release_identity(&root).is_empty(),
            "[{tag}] baseline: the clean committed root must arm and pass"
        );

        write_file(&root.join(rel), "a production change lands on top\n");
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "production change"]);
        assert!(git(&["status", "--porcelain"]).trim().is_empty(), "[{tag}] clean tree");

        let v = vcm::check_release_identity(&root);
        assert!(
            v.iter().any(|x| matches!(x, Violation::ReleaseIdentityNotAsserted { .. })),
            "[{tag}] touching `{rel}` after the binding commit must DISARM into the typed \
             non-assertion, got: {v:?}"
        );
        assert!(
            !v.is_empty(),
            "[{tag}] a disarmed head must NEVER report release-identity success"
        );
        assert!(
            !v.iter().any(|x| format!("{x}").contains("does not derive from the reviewed tree")),
            "[{tag}] byte-equality must not be evaluated at a disarmed head, got: {v:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// S11-6 — a NON-production child leaves the claim ARMED.
///
/// The complement of the case above, and the property that makes the release
/// ceremony workable at all: docs, review artifacts and the record itself may
/// land on top of a binding commit without withdrawing the claim. Without this
/// test, an implementation that disarmed on ANY child would pass every other
/// case here while making the ceremony as uncommittable as the S11-5 form was.
#[test]
fn s11_6_non_production_child_leaves_the_claim_armed() {
    let (root, _b, _c, _rustv, _cargov, _pins) = committed_release_root("docs");
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    };
    write_file(&root.join("docs/NOTES.md"), "documentation only\n");
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "docs only"]);
    assert!(git(&["status", "--porcelain"]).trim().is_empty(), "clean tree");

    let v = vcm::check_release_identity(&root);
    assert!(
        v.is_empty(),
        "a docs-only child must leave the claim ARMED and passing — otherwise the \
         release ceremony cannot be committed, got: {v:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// S11-5 — `asserts_identity_at` is REQUIRED and AUTHENTICATED.
///
/// Two fail-open shapes the scope could have introduced, both closed here:
/// omitting the field must not mean "assert everywhere" (the old behaviour) or
/// "assert nowhere" (a permanent free pass); and naming an invented commit must
/// not buy permanent non-assertion, which would be a fail-open wearing a typed
/// outcome's clothes.
#[test]
fn s11_5_asserts_identity_at_is_required_and_authenticated() {
    let (root, sha, rustv, cargov, pins) = truthful_release_root("scopefield");
    let rec = root.join("deployment/mainnet/release_hashes.toml");

    // (a) ABSENT — a record that does not say where its claim holds is unbound.
    let without = release_record_at(&sha, &sha, &rustv, &cargov, &pin_slice(&pins))
        .lines()
        .filter(|l| !l.starts_with("asserts_identity_at"))
        .collect::<Vec<_>>()
        .join("\n");
    write_file(&rec, &format!("{without}\n"));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("build.asserts_identity_at")),
        "a record omitting asserts_identity_at must fail as unbound, got: {v:?}"
    );

    // (b) NAMES NO COMMIT — a well-formed but invented SHA must fail, not
    // quietly render the record permanently non-asserting.
    let ghost = "0123456789abcdef0123456789abcdef01234567";
    write_file(&rec, &release_record_at(ghost, &sha, &rustv, &cargov, &pin_slice(&pins)));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("not a commit object")),
        "an asserts_identity_at naming no commit must fail, got: {v:?}"
    );
    assert!(
        v.iter().any(|x| format!("{x}").contains("build.asserts_identity_at")),
        "and the failure must be attributed to THAT field, not to source_sha, got: {v:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A release record with a mutated Wasm hash fails.
/// V4.1 traceability ID (SSA-4). The positive fixture is now TRUTHFUL — real
/// commit, active toolchain — so a pass means every field authenticated, not
/// merely that the hashes lined up around fabricated provenance.
#[test]
fn r2_release_hash_mismatch_fails() {
    let (root, sha, rustv, cargov, pins) = truthful_release_root("hash");
    let rec = root.join("deployment/mainnet/release_hashes.toml");

    // Correct, truthful record: passes.
    let v = vcm::check_release_identity(&root);
    assert!(v.is_empty(), "a correct truthful release record must pass, got: {v:?}");

    // Mutated vault hash: fails, and ONLY the hash changed.
    write_file(&rec, &release_record(&sha, &rustv, &cargov, &pin_slice(&tamper_pin(&pins, "vault"))));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("vault.wasm sha256")),
        "a mutated vault release hash must fail on the hash, got: {v:?}"
    );

    // Mutated upgrader hash: same, independently.
    write_file(&rec, &release_record(&sha, &rustv, &cargov, &pin_slice(&tamper_pin(&pins, "upgrader"))));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("upgrader.wasm sha256")),
        "a mutated upgrader release hash must fail on the hash, got: {v:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// SSA S10-R2 — PROVENANCE NEGATIVE CONTROLS, one field altered per case.
///
/// Each case starts from the truthful record that passes, changes EXACTLY ONE
/// field, and requires a failure attributed to that field. This is what the
/// `deadbeef` fixture could not do: with presence-only checks, every one of
/// these cases passed.
#[test]
fn r2_release_provenance_rejects_each_falsified_field() {
    let (root, sha, rustv, cargov, pins) = truthful_release_root("neg");
    let rec = root.join("deployment/mainnet/release_hashes.toml");

    // Baseline: truthful record passes. Without this, a check that rejects
    // everything would satisfy the negatives vacuously.
    assert!(
        vcm::check_release_identity(&root).is_empty(),
        "baseline truthful record must pass"
    );

    // (a) wrong source_sha — well-formed, but no such commit object.
    let ghost = "0123456789abcdef0123456789abcdef01234567";
    write_file(&rec, &release_record_at(&sha, ghost, &rustv, &cargov, &pin_slice(&pins)));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("not a commit object")),
        "a source_sha naming no commit must fail, got: {v:?}"
    );

    // (a2) real commit, but NOT an ancestor of HEAD — the recorded-ancestor
    // rule, not merely "is this a commit anywhere".
    let orphan = {
        let g = |args: &[&str]| {
            let o = std::process::Command::new("git")
                .args(["-C", &root.to_string_lossy()])
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8(o.stdout).unwrap()
        };
        g(&["checkout", "-q", "--orphan", "sidebranch"]);
        write_file(&root.join("other.txt"), "unrelated history\n");
        g(&["add", "-A"]);
        g(&["commit", "-q", "-m", "orphan commit"]);
        let s = g(&["rev-parse", "HEAD"]).trim().to_string();
        // Return to the recorded commit by SHA. `checkout -` has no
        // previous-branch record in a freshly-initialised repo, and checking
        // out `sha` directly also makes HEAD == source_sha, exercising the
        // "ancestor OR EQUAL" half of the rule.
        g(&["checkout", "-q", &sha]);
        s
    };
    write_file(&rec, &release_record_at(&sha, &orphan, &rustv, &cargov, &pin_slice(&pins)));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("NOT an ancestor of HEAD")),
        "a real but unrelated commit must fail the ancestry rule, got: {v:?}"
    );

    // (b) empty source_sha — still caught by the presence rule.
    write_file(&rec, &release_record_at(&sha, "", &rustv, &cargov, &pin_slice(&pins)));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("build.source_sha")),
        "an empty source_sha must fail, got: {v:?}"
    );

    // (c) wrong rust_version — plausible, but not the active compiler.
    write_file(&rec, &release_record(&sha, "1.70.0 (000000000 2020-01-01)", &cargov, &pin_slice(&pins)));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("recorded rustc version")),
        "a recorded rustc version that is not the active one must fail, got: {v:?}"
    );

    // (d) wrong cargo_version — independently.
    write_file(&rec, &release_record(&sha, &rustv, "1.70.0 (000000000 2020-01-01)", &pin_slice(&pins)));
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("recorded cargo version")),
        "a recorded cargo version that is not the active one must fail, got: {v:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The exact defect SSA reported, pinned so it cannot silently return: the
/// historical fixture values (`deadbeef` source, a `1.80.0` toolchain) must now
/// FAIL even when both artifact hashes are correct.
#[test]
fn r2_release_deadbeef_provenance_no_longer_passes() {
    let (root, _sha, _rustv, _cargov, pins) = truthful_release_root("deadbeef");
    write_file(
        &root.join("deployment/mainnet/release_hashes.toml"),
        &release_record("deadbeef", "1.80.0", "1.80.0", &pin_slice(&pins)),
    );
    let v = vcm::check_release_identity(&root);
    assert!(
        v.iter().any(|x| format!("{x}").contains("not a commit object")),
        "the deadbeef source_sha must be rejected, got: {v:?}"
    );
    assert!(
        v.iter().any(|x| format!("{x}").contains("recorded rustc version")),
        "the fabricated rustc version must be rejected, got: {v:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A release record missing the canonical build invocation fails: hashes were
/// reproducible per package-set but differed ACROSS package selections, so the
/// invocation is part of release identity.
#[test]
fn r5_3_release_record_without_build_invocation_fails() {
    let tmp = std::env::temp_dir().join(format!("vcm_release_noinv_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    write_file(
        &tmp.join("deployment/mainnet/release_hashes.toml"),
        "[toolchain]\nrust_version = \"1.80.0\"\ncargo_version = \"1.80.0\"\n\
         [wasm.vault]\nsha256 = \"aa\"\n[wasm.upgrader]\nsha256 = \"bb\"\n",
    );
    let v = vcm::check_release_identity(&tmp);
    assert!(
        v.iter().any(|x| format!("{x}").contains("build.command")),
        "a record without the canonical build invocation must fail, got: {v:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Creation receipts: born-under-Vault targets declared with zero receipts is a
/// deploy-time blocker. This is the current, correct state of the real manifest.
#[test]
fn r5_3_missing_creation_receipts_fails() {
    let m = real_manifest();
    let v = vcm::check_launch_evidence(&m);
    assert!(
        v.iter().any(|x| matches!(x, Violation::LaunchEvidenceIncomplete { .. })),
        "born-under-Vault targets with no D5 receipts must fail the deploy gate, got: {v:?}"
    );
}

/// The build-time gate is NOT affected by the R5.3 deploy-time class — a green
/// ./run_gate.sh must remain achievable while these artifacts are legitimately
/// pending, or the two gates stop meaning different things.
#[test]
fn r5_3_is_deploy_time_only_and_build_gate_stays_green() {
    let root = repo_root();
    let m = real_manifest();
    let d1 = vcm::load_d1(&root.join("dfx.json")).unwrap();
    let d2 = vcm::load_d2(&root.join("canister_ids.json")).unwrap();
    let build_time = [
        vcm::check_coverage(&m, &d1, &d2),
        vcm::check_did_fixtures(&root),
        vcm::check_cutover_binding(&root, &m),
    ]
    .concat();
    assert!(
        build_time.is_empty(),
        "the build-time gate must stay green while release identity and receipts are pending, \
         got: {build_time:?}"
    );
}

/// R2.4 second half, as far as it CAN be tested in-repo: no synthesis path
/// survives. Removing the artifact must make `init_args_for` FAIL rather than
/// fall back to placeholders — while synthesis survives anywhere, the gate is
/// checking a file the install never reads.
#[test]
fn r2_upgrader_init_has_no_synthesis_fallback() {
    let tmp = std::env::temp_dir().join(format!("vcm_nosynth_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("deployment/mainnet")).unwrap();
    let r = vcm::init_args_for(&tmp, "upgrader");
    assert!(
        r.is_err(),
        "with no committed artifact, init_args_for(\"upgrader\") must FAIL — a placeholder \
         fallback is how the pre-fix gate reported GREEN for an attacker-chosen roster"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// V4.1 REQUIRED TRACEABILITY ID (SSA-3): the four compared surfaces agree on
/// an exact ordered principal-byte vector.
///
/// Surfaces 1-3 are machine-verified from the real tree. Surface 4 is
/// operator-attested and is validated here against a constructed attestation
/// set — the validator checks RECORDED BYTES against the pin and cannot, by
/// construction, prove those bytes came from the live signer-gated query.
#[test]
fn r2_gate_d_four_surface_byte_equality() {
    let root = repo_root();
    let pinned = vcm::load_recovery_record(&root).unwrap().expect("[recovery] must be pinned");

    // Surface 2 — vault_init.did signers.
    let vault_encoded = vcm::encode_init_artifact(&root.join(vcm::VAULT_INIT_ARTIFACT)).unwrap();
    let (vault_signers, _, upgrader) = vcm::vault_init_quorum(&vault_encoded).unwrap();

    // Surface 3 — upgrader_init.did as actually encoded for install.
    let up_encoded =
        vcm::encode_init_artifact(&root.join(vcm::UPGRADER_INIT_ARTIFACT)).unwrap();
    let (up_members, up_threshold, up_vault) = vcm::upgrader_init_roster(&up_encoded).unwrap();

    // 1 ↔ 2 ↔ 3, byte-exact and ORDERED — through the rotation ledger once the
    // rotation has happened (Q5-A / binding Addendum 1). Pre-rotation the pin IS
    // the install-time roster and the three surfaces are compared directly.
    // Post-rotation the two install surfaces are compared to
    // `[rotation.bootstrap]`, the pin to the last EXECUTED row of each plane,
    // and the planes to each other. The INTENT — "the recovery roster is the
    // same three principals, in the same order, as the Vault signers" — is
    // asserted in both states; only what each surface is compared to changes.
    let lock = vcm::load_rotation_lockstep(&root).expect("the rotation lockstep must load");
    let bytes = |ps: &[candid::Principal]| {
        ps.iter().map(|p| p.as_slice().to_vec()).collect::<Vec<_>>()
    };
    if lock.rotated {
        assert_eq!(
            bytes(&vault_signers),
            bytes(&lock.bootstrap_vault_signers),
            "surface 2 != [rotation.bootstrap].vault_signers"
        );
        assert_eq!(
            bytes(&up_members),
            bytes(&lock.bootstrap_upgrader_members),
            "surface 3 != [rotation.bootstrap].upgrader_members"
        );
        assert_eq!(
            bytes(&lock.bootstrap_upgrader_members),
            bytes(&lock.bootstrap_vault_signers),
            "install cross-plane: the snapshot halves must be the same ordered vector"
        );
        assert_eq!(
            bytes(&lock.last_upgrader_new_members),
            bytes(&lock.last_vault_new_members),
            "live cross-plane: the two planes' last EXECUTED rows must agree"
        );
        assert_eq!(
            bytes(&pinned.members),
            bytes(&lock.last_upgrader_new_members),
            "surface 1 != the last EXECUTED [[rotation.upgrader]] row"
        );
        assert_eq!(up_threshold, lock.bootstrap_upgrader_threshold, "surface 3 threshold");
    } else {
        assert_eq!(bytes(&pinned.members), bytes(&vault_signers), "surface 1 != surface 2");
        assert_eq!(bytes(&up_members), bytes(&pinned.members), "surface 3 != surface 1");
        assert_eq!(up_threshold, pinned.threshold, "surface 3 threshold != pin");
    }
    assert_eq!(up_vault, pinned.vault, "surface 3 vault != pin");
    assert!(
        vcm::recovery_roster_violations_with_rotation(
            Some(&pinned),
            &vault_signers,
            Some((&up_members, up_threshold, &up_vault)),
            Some(&lock),
        )
        .is_empty(),
        "surfaces 1-3 must bind cleanly"
    );

    // Surface 4 — one attestation per ruled recovery principal, all agreeing.
    let attest = |who: candid::Principal| vcm::MembershipAttestation {
        read_by: who,
        signer_label: format!("device:{}", who.to_text()),
        network: "ic".into(),
        observed_at: "2026-08-06T00:00:00Z".into(),
        upgrader,
        members: Some(pinned.members.clone()),
        threshold: Some(pinned.threshold),
    };
    let all: Vec<_> = pinned.members.iter().copied().map(attest).collect();
    let v = vcm::attestation_violations(Some(&pinned), &upgrader, &all);
    assert!(v.is_empty(), "four-surface agreement must pass, got: {v:?}");
}

/// Surface 4 negative: an attestation whose recorded membership does NOT match
/// the pin fails. This is the mismatching-attestation case R2.3 requires.
#[test]
fn r2_surface4_attestation_mismatch_fails() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let upgrader = vcm::max_length_principal(91);
    let rec = rec_of(&m, 2, vault);
    let good = |who: candid::Principal, members: Vec<candid::Principal>| vcm::MembershipAttestation {
        read_by: who,
        signer_label: "device".into(),
        network: "ic".into(),
        observed_at: "2026-08-06T00:00:00Z".into(),
        upgrader,
        members: Some(members),
        threshold: Some(2),
    };

    // Baseline: all three agree → passes.
    let ok: Vec<_> = m.iter().map(|w| good(*w, m.clone())).collect();
    assert!(
        vcm::attestation_violations(Some(&rec), &upgrader, &ok).is_empty(),
        "agreeing attestations must pass"
    );

    // ONE attestation reports a different roster → fails.
    let mut tampered = ok.clone();
    tampered[1] = good(m[1], vec![m[0], vcm::max_length_principal(77), m[2]]);
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &tampered)),
        "an attestation disagreeing with the pin must fail"
    );

    // A REORDERED attested roster fails — ordered equality here too.
    let mut reordered = ok.clone();
    reordered[0] = good(m[0], vec![m[2], m[1], m[0]]);
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &reordered)),
        "a reordered attested roster must fail"
    );
}

/// Surface 4 fails closed on absence, on a `None` readback, on a missing
/// principal's read, and on an attestation read against the wrong Upgrader.
#[test]
fn r2_surface4_fails_closed_on_absent_none_and_partial() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let upgrader = vcm::max_length_principal(91);
    let rec = rec_of(&m, 2, vault);
    let mk = |who: candid::Principal| vcm::MembershipAttestation {
        read_by: who,
        signer_label: "device".into(),
        network: "ic".into(),
        observed_at: "2026-08-06T00:00:00Z".into(),
        upgrader,
        members: Some(m.clone()),
        threshold: Some(2),
    };

    // No attestations at all.
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &[])),
        "absent attestations must fail closed"
    );
    // Only two of the three ruled principals read.
    let partial: Vec<_> = m.iter().take(2).map(|w| mk(*w)).collect();
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &partial)),
        "a read missing from a ruled recovery principal must fail"
    );
    // A `None` readback HALTS.
    let mut noned: Vec<_> = m.iter().map(|w| mk(*w)).collect();
    noned[2].members = None;
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &noned)),
        "a None readback must fail — it means the roster lacks that principal"
    );
    // Read against the wrong Upgrader.
    let mut wrong: Vec<_> = m.iter().map(|w| mk(*w)).collect();
    wrong[0].upgrader = vcm::max_length_principal(92);
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &wrong)),
        "an attestation read against a different Upgrader must fail"
    );
    // Undated evidence cannot be shown fresh.
    let mut undated: Vec<_> = m.iter().map(|w| mk(*w)).collect();
    undated[0].observed_at = "   ".into();
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &undated)),
        "undated attestation evidence must fail"
    );
}

/// An attestation from a principal that is NOT a ruled recovery member is not
/// evidence, even if the bytes it reports are correct.
#[test]
fn r2_surface4_unruled_reader_is_not_evidence() {
    let m = ps(3);
    let vault = vcm::max_length_principal(90);
    let upgrader = vcm::max_length_principal(91);
    let rec = rec_of(&m, 2, vault);
    let intruder = vcm::max_length_principal(70);
    let mk = |who: candid::Principal| vcm::MembershipAttestation {
        read_by: who,
        signer_label: "device".into(),
        network: "ic".into(),
        observed_at: "2026-08-06T00:00:00Z".into(),
        upgrader,
        members: Some(m.clone()),
        threshold: Some(2),
    };
    let mut set: Vec<_> = m.iter().map(|w| mk(*w)).collect();
    set.push(mk(intruder));
    assert!(
        is_roster(&vcm::attestation_violations(Some(&rec), &upgrader, &set)),
        "an attestation from an unruled reader must fail"
    );
}

/// R5.3 / point 3: a MISSING production Wasm fails inside the release check
/// itself. Deferring to the separate size gate was fail-open, because
/// `--deploy-time --coverage-only` skips that gate.
///
/// S11-5 required test (iii) — this is now asserted AT THE ASSERTING HEAD,
/// which is the only place the fail-closed-on-absent-artifact rule is
/// meaningful: elsewhere the checker does not compare at all, so "the artifact
/// is missing" is not the question being asked.
///
/// THE FIXTURE IS NOW TRUTHFUL EXCEPT FOR THE ONE THING UNDER TEST. It was a
/// bare temp directory with `deadbeef` provenance, a `1.80.0` toolchain and
/// `aa`/`bb` hashes — every field wrong at once, so the test could pass on any
/// of five unrelated violations while the absent-artifact rule was broken. It
/// is now a real git root at the asserting head with the active toolchain and
/// WELL-FORMED pinned hashes; the ONLY defect is that the Wasms were never
/// built. That is what makes the assertion attributable.
#[test]
fn r5_3_missing_production_wasm_fails_release_check() {
    let root = std::env::temp_dir().join(format!("vcm_nowasm_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let sha = init_git_root(&root);
    let (rustv, cargov) = active_versions();
    // Well-formed, and deliberately NOT matching anything — there is nothing to
    // match, which is the point.
    let pins: Vec<(&'static str, String)> = vcm::INLINE_PAYLOAD_ARTIFACTS
        .iter()
        .enumerate()
        .map(|(i, (pkg, _))| (*pkg, char::from_digit((i % 10) as u32, 10).unwrap().to_string().repeat(64)))
        .collect();
    write_file(
        &root.join("deployment/mainnet/release_hashes.toml"),
        &release_record_at(&sha, &sha, &rustv, &cargov, &pin_slice(&pins)),
    );
    // NOTE: no target/wasm32-unknown-unknown/release — that is the defect.
    let v = vcm::check_release_identity(&root);
    for (_, who) in vcm::INLINE_PAYLOAD_ARTIFACTS {
        assert!(
            v.iter().any(|x| format!("{x}").contains(who)
                && format!("{x}").contains("is not built")),
            "at the asserting head an absent {who} must fail CLOSED inside the release \
             check itself, got: {v:?}"
        );
    }
    // And it must be the unbound class, not the non-assertion class: this head
    // DOES assert identity, so the failure is "never compared", not "not claimed".
    assert!(
        v.iter().any(|x| matches!(x, Violation::ReleaseIdentityUnbound { .. })),
        "an absent artifact at the asserting head is UNBOUND, got: {v:?}"
    );
    assert!(
        !v.iter().any(|x| matches!(x, Violation::ReleaseIdentityNotAsserted { .. })),
        "the asserting head must not report a non-assertion, got: {v:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ── CLI mode-flag exclusivity (S1.2) ─────────────────────────────────────────
//
// The three mode flags each select a DIFFERENT SUBSET of the gate, so any
// combination narrows what exit 0 means. Rejecting a single pair was the
// original defect — the hazard is the class. `--deploy-time --sizes-only` was
// the sharpest case: `if !sizes_only` skips the whole coverage/deploy-time
// block, so the process could exit 0 having run NO roster, authority, receipt
// or release-identity check while carrying a deploy-time flag.
//
// Driven through the real binary, because this is control flow in `main`, not
// a library property — a library-level assertion would not have caught it.

fn run_cli(args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_verify_custody_manifest"))
        .args(args)
        .arg(repo_root())
        .output()
        .expect("verifier binary must run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// EVERY combination of more than one mode flag is rejected with exit 2 —
/// all three pairs and the triple.
#[test]
fn cli_rejects_every_mixed_gate_mode() {
    let combos: &[&[&str]] = &[
        &["--deploy-time", "--coverage-only"],
        &["--deploy-time", "--sizes-only"],
        &["--coverage-only", "--sizes-only"],
        &["--deploy-time", "--coverage-only", "--sizes-only"],
    ];
    for combo in combos {
        let (code, stderr) = run_cli(combo);
        assert_eq!(
            code, 2,
            "{combo:?} must be REJECTED with exit 2, got {code}. A narrowed gate must never be \
             reportable as a pass; stderr: {stderr}"
        );
        assert!(
            stderr.contains("mutually exclusive"),
            "{combo:?} must be rejected as a mode-exclusivity error, got: {stderr}"
        );
    }
}

/// The specific bypass that motivated this: `--deploy-time --sizes-only` must
/// NOT be able to exit 0. Asserted independently of the message so a future
/// refactor of the wording cannot quietly reopen it.
#[test]
fn cli_deploy_time_with_sizes_only_cannot_report_success() {
    let (code, _) = run_cli(&["--deploy-time", "--sizes-only"]);
    assert_ne!(
        code, 0,
        "--deploy-time --sizes-only skips the entire deploy-time block; exiting 0 would be a \
         deploy-time verdict from a run that performed no deploy-time check"
    );
}

/// Each mode alone still works — the exclusivity check must not have broken the
/// invocations run_gate.sh actually uses.
#[test]
fn cli_accepts_each_single_mode() {
    for m in ["--coverage-only", "--sizes-only"] {
        let (code, stderr) = run_cli(&[m]);
        assert_ne!(code, 2, "{m} alone must be accepted, got usage error: {stderr}");
    }
    // --deploy-time alone is accepted as an invocation; it is EXPECTED to fail
    // on the open R5.3 items until S10, which is exit 1, never exit 2.
    let (code, stderr) = run_cli(&["--deploy-time"]);
    assert_ne!(code, 2, "--deploy-time alone must be a valid invocation: {stderr}");
}

// ─────────────────────────────────────────────────────────────────────────────
// R-3a — release-hash coverage 2 → TEN.
//
// Before this lane `check_release_identity` iterated a two-element literal
// [("vault","vault.wasm"),("upgrader","upgrader.wasm")], so eight of the ten
// artifacts the ceremony actually SHIPS (INLINE_PAYLOAD_ARTIFACTS) were pinned
// nowhere and could be swapped for bytes from an unreviewed tree without any
// gate noticing. The loop now iterates INLINE_PAYLOAD_ARTIFACTS itself.
//
// BINDING: B-R3A-RELEASE-HASH-10
//
// The property is a DISCRIMINATION, not a pass: the truthful ten-pin root and a
// root with ONE of the eight NEW pins falsified must not produce the same
// verdict. Tampering `treasury` — a package the old two-element loop never
// visited — is what makes the mutation (reverting the loop to the literal)
// collapse the two results onto each other.
#[test]
fn r3a_check_release_identity_distinguishes_truthful_from_tampered_root() {
    let (truthful_root, sha, rustv, cargov, pins) = truthful_release_root("r3a_truthful");
    let (tampered_root, t_sha, t_rustv, t_cargov, t_pins) =
        truthful_release_root("r3a_tampered");

    // The truthful root, untouched.
    let truthful = vcm::check_release_identity(&truthful_root);

    // The tampered root: exactly ONE pin falsified, and it is one of the EIGHT
    // the pre-R-3a loop did not visit.
    assert!(
        !["vault", "upgrader"].contains(&"treasury"),
        "the tampered package must be one of the eight NEW pins, not a pre-existing one"
    );
    write_file(
        &tampered_root.join("deployment/mainnet/release_hashes.toml"),
        &release_record(
            &t_sha,
            &t_rustv,
            &t_cargov,
            &pin_slice(&tamper_pin(&t_pins, "treasury")),
        ),
    );
    let tampered = vcm::check_release_identity(&tampered_root);

    // VACUITY, both sides, asserted independently of the discrimination.
    assert!(
        truthful.is_empty(),
        "vacuity: the truthful ten-pin root must produce NO violations, got: {truthful:?}"
    );
    assert!(
        !tampered.is_empty(),
        "vacuity: the one-pin-tampered root must produce at least one violation, \
         got none — the fixture is not exercising the check"
    );
    assert!(
        tampered.iter().any(|x| format!("{x}").contains("treasury.wasm sha256")),
        "the violation must name the tampered artifact's FILE (lib.rs's {{file}} \
         interpolation), got: {tampered:?}"
    );

    // THE PROPERTY.
    assert_ne!(
        format!("{truthful:?}"),
        format!("{tampered:?}"),
        "check_release_identity must DISTINGUISH a truthful ten-pin root from one \
         whose treasury pin is falsified; if it cannot, the eight non-vault/upgrader \
         shipped Wasms are unpinned in practice"
    );

    // Unused-binding hygiene: the truthful root's own fields are the control
    // the tampered root was built to differ from.
    let _ = (sha, rustv, cargov, pins);
}

/// R-3a AC-2 — the shipped-Wasm registry's CARDINALITY is bound to the gate's
/// own production package list, so a future package added to `run_gate.sh`
/// without a pin (or a pin silently dropped) is a test failure rather than a
/// silent coverage hole.
#[test]
fn r3a_inline_payload_artifacts_matches_run_gate_prod_packages_minus_exclusions() {
    let root = repo_root();

    // ── The registry side.
    assert_eq!(
        vcm::INLINE_PAYLOAD_ARTIFACTS.len(),
        10,
        "INLINE_PAYLOAD_ARTIFACTS must carry exactly the TEN shipped Wasms"
    );

    // ── The gate side: PROD_PACKAGES, read as text out of run_gate.sh.
    let gate = std::fs::read_to_string(root.join("run_gate.sh")).expect("run_gate.sh");
    let open = gate.find("PROD_PACKAGES=(").expect("PROD_PACKAGES=( must exist in run_gate.sh");
    let body = &gate[open + "PROD_PACKAGES=(".len()..];
    let close = body.find(')').expect("PROD_PACKAGES must be closed");
    let mut prod: Vec<&str> = body[..close].split_whitespace().collect();
    prod.sort_unstable();

    // VACUITY for the text extraction: all 13 raw names must still be there. If
    // the block moves or the parse silently yields nothing, this fires first.
    let expected_13 = {
        let mut v = vec![
            "stsh_token", "staking", "shielded_pool", "nullifier_registry", "merkle_tree",
            "treasury", "vesting", "stsh-verifier", "stsh-stub-verifier", "stub_bad_fee_token",
            "smoke_alarm_monitor", "vault", "upgrader",
        ];
        v.sort_unstable();
        v
    };
    assert_eq!(
        prod, expected_13,
        "run_gate.sh's PROD_PACKAGES must still be the 13 raw names this test subtracts from"
    );

    // ── The subtraction: 13 − 3 = 10.
    const EXCLUDED: [&str; 3] = ["stsh-stub-verifier", "stub_bad_fee_token", "staking"];
    let mut expected: Vec<&str> =
        prod.iter().copied().filter(|p| !EXCLUDED.contains(p)).collect();
    expected.sort_unstable();
    let mut actual: Vec<&str> =
        vcm::INLINE_PAYLOAD_ARTIFACTS.iter().map(|(p, _)| *p).collect();
    actual.sort_unstable();
    assert_eq!(
        actual, expected,
        "INLINE_PAYLOAD_ARTIFACTS must equal run_gate.sh's PROD_PACKAGES minus the two \
         test stubs and staking (D1, 2026-08-14 — not installed at launch)"
    );

    // ── D1's premise, asserted rather than assumed: `staking` really is absent
    // from dfx.json's canister table. WITH a positive control in the same
    // parsed table (C-1) — without it, a failed read or an empty parse would
    // satisfy the absence assertion silently.
    let dfx: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("dfx.json")).expect("dfx.json"))
            .expect("dfx.json must parse");
    let canisters = dfx
        .get("canisters")
        .and_then(|c| c.as_object())
        .expect("dfx.json must carry a canisters table");
    assert!(
        canisters.contains_key("shielded_pool"),
        "positive control: shielded_pool MUST be present in the same parsed dfx.json \
         canister table the staking-absence assertion reads — if it is not, the table \
         did not parse and the absence proves nothing. Keys seen: {:?}",
        canisters.keys().collect::<Vec<_>>()
    );
    assert!(
        !canisters.contains_key("staking"),
        "D1 (2026-08-14): staking is NOT installed at launch and must stay absent from \
         dfx.json; if it is re-added, this lane's ten-artifact subtraction is stale"
    );
}
