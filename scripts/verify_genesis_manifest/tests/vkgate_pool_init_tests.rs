//! W-VKGATE (AR1-05 / C-27) — deliverables (b) and (c): Gate-D verifies the
//! pool's trust roots field-by-field, refuses the dev verifying key in
//! `[pool_init].vk_hash`, fails CLOSED when the section is absent, and requires
//! a committed ceremony record bound to the same hash.
//!
//! INDEPENDENT-EXPECTED-SIDE (HARNESS_DELTA §1): every expected value below is
//! written into this file by hand — a hardcoded dev-VK literal, a hardcoded
//! "other" hash, hand-written principals. Nothing is read back from the
//! manifest under test, from `DEV_VK_HASH_HEX`, or from
//! `circuits/verification_key.json`. The named anti-pattern is
//! `wallet/tests/artifacts_l3c.test.ts`, which builds its expected tuple out of
//! the artefact it is checking.

use std::path::PathBuf;
use verify_genesis_manifest::*;
const A7_REBASE_DEPLOYMENT_REL: &str = "../../deployment/mainnet";

// ── A-7 REBASE (RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13) ──────────────────
// DPOOL-5 and DPOOL-7 now read the records that actually own the pool's
// treasury and controller roots. Both are supplied to every call below, so a
// site that is not ABOUT those two checks keeps exercising what it was written
// to exercise instead of REDing fail-closed on an unsupplied record.
fn a7_kit_src() -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(A7_REBASE_DEPLOYMENT_REL)
            .join("a7_install_kit.toml"),
    )
    .expect("committed a7_install_kit.toml")
}
fn vault_src() -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(A7_REBASE_DEPLOYMENT_REL)
            .join("vault_authorities.toml"),
    )
    .expect("committed vault_authorities.toml")
}


/// The M5 single-participant DEV VK hash, transcribed independently (see docs).
const DEV_VK_HEX_LITERAL: &str =
    "fc73ca4dcdcfd5a2eb0dd6165c5cf2b1e039c3acdad2d360258c5d42ba530dc8";
/// A well-formed hash that is NOT the denied one, by construction.
const OTHER_VK_HEX_LITERAL: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
/// The LIVE `[pool_init].vk_hash`, ARMED at A-4 with the mainnet-v2 launch VK, transcribed
/// BY HAND (never read back from the manifest under test — see the header note).
///
/// A-4 LANDING: these tests used to substitute the all-zeros P0-3 placeholder, because that
/// is what the committed manifest held. Arming it made every such substitution a silent
/// no-op — `assert_ne!(tampered, manifest, "the substitution must bite")` is what caught it,
/// and is why that guard is in the file at all.
const LIVE_VK_HEX_LITERAL: &str =
    "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914";

fn deployment_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deployment/mainnet")
}
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn artifacts() -> (String, String, String) {
    let d = deployment_dir();
    (
        std::fs::read_to_string(d.join("genesis_manifest.toml")).unwrap(),
        std::fs::read_to_string(d.join("stsh_token_init.did")).unwrap(),
        std::fs::read_to_string(d.join("vesting_init.did")).unwrap(),
    )
}
fn named(checks: &[CheckResult], name: &str) -> CheckResult {
    checks
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("check {name} must exist — a renamed or removed check is itself the defect"))
        .clone()
}

/// **N-3** — a manifest whose `[pool_init].vk_hash` carries the dev VK hash
/// fails the NAMED pool check, and its rendered detail names both values.
#[test]
fn n3_pool_init_carrying_dev_vk_hash_fails_named_check() {
    let (manifest, token, vesting) = artifacts();
    let tampered = manifest.replace(
        &format!("vk_hash         = \"{LIVE_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{DEV_VK_HEX_LITERAL}\""),
    );
    assert_ne!(tampered, manifest, "the substitution must bite");

    let checks = run_gates_from_strs_with_record(&tampered, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).expect("gates must run");
    let c = named(&checks, "DPOOL-2-vk-hash-not-dev");
    assert!(!c.pass, "the dev VK hash MUST be refused in the manifest; detail: {}", c.detail);
    assert!(
        c.detail.contains(DEV_VK_HEX_LITERAL),
        "the rendered detail must name the refused value: {}",
        c.detail
    );
    // Not vacuous by shape: a well-formed non-denied hash passes the same check.
    let ok = manifest.replace(
        &format!("vk_hash         = \"{LIVE_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{OTHER_VK_HEX_LITERAL}\""),
    );
    let checks = run_gates_from_strs_with_record(&ok, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).expect("gates must run");
    assert!(named(&checks, "DPOOL-2-vk-hash-not-dev").pass, "control: a non-denied hash passes");
}

/// **N-4** — a manifest with `[pool_init]` ABSENT fails closed at PARSE.
/// Asserting the parse error, not a default-shaped value: `#[serde(default)]`
/// on the section would turn a missing pool trust root into a silent empty one.
#[test]
fn n4_manifest_without_pool_init_fails_closed_at_parse() {
    let (manifest, token, vesting) = artifacts();
    let start = manifest.find("[pool_init]").expect("the section must be present to remove");
    let end = manifest.find("# ── Allocation table").expect("section boundary");
    let stripped = format!("{}{}", &manifest[..start], &manifest[end..]);
    assert!(!stripped.contains("[pool_init]"), "the section must actually be gone");

    let err = run_gates_from_strs_with_record(&stripped, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
        .expect_err("a manifest with no [pool_init] MUST fail closed at parse");
    assert!(
        err.contains("pool_init"),
        "the parse error must name the missing section, not fail obscurely: {err}"
    );
}

/// **N-6** — the ceremony-record check fails when the record is missing, and
/// when it exists but binds a DIFFERENT hash than `[pool_init]`.
#[test]
fn n6_ceremony_record_must_exist_and_bind_the_same_hash() {
    let (manifest, _, _) = artifacts();
    let parsed: Manifest = toml::from_str(&manifest).expect("manifest parses");

    // Positive control on the real tree: record present and bound.
    let c = check_ceremony_record(&repo_root(), &parsed);
    assert!(c.pass, "the committed record must exist and bind the pin; detail: {}", c.detail);
    assert!(c.detail.contains("binds_vk_hash=true"), "detail: {}", c.detail);

    // (a) record absent — point the manifest at a path that does not exist.
    let missing = manifest.replace(
        "ceremony_record = \"docs/ceremony/CEREMONY_RECORD_v3.md\"",
        "ceremony_record = \"docs/ceremony/NO_SUCH_RECORD.md\"",
    );
    let parsed_missing: Manifest = toml::from_str(&missing).unwrap();
    let c = check_ceremony_record(&repo_root(), &parsed_missing);
    assert!(!c.pass, "a missing ceremony record MUST fail closed; detail: {}", c.detail);

    // (b) record present but bound to a different hash than [pool_init].
    let drifted = manifest.replace(
        &format!("vk_hash         = \"{LIVE_VK_HEX_LITERAL}\""),
        &format!("vk_hash         = \"{OTHER_VK_HEX_LITERAL}\""),
    );
    let parsed_drift: Manifest = toml::from_str(&drifted).unwrap();
    let c = check_ceremony_record(&repo_root(), &parsed_drift);
    assert!(
        !c.pass,
        "a record bound to a different hash MUST fail — that is the whole point of the binding; detail: {}",
        c.detail
    );
    assert!(c.detail.contains("binds_vk_hash=false"), "detail: {}", c.detail);
}

/// Rewrite ONE `[pool_init]` field's value, anchored on the SECTION and the
/// FIELD KEY — never on the value that happens to be committed today.
///
/// RR-1a (2026-09-12): the four trust roots below used to be substituted by a
/// bare `str::replace` keyed on the P0-3 placeholder principal each field then
/// held. RR-1 rebound them to real production principals and every one of those
/// substitutions became a silent no-op — the same A-4 failure mode the
/// `LIVE_VK_HEX_LITERAL` note above records, caught again by the same
/// `assert_ne!` guard. Anchoring structurally is the fix: this helper cannot go
/// stale when a principal is re-ruled, and it PANICS rather than no-ops if the
/// section or the key is ever renamed.
///
/// The INDEPENDENT-EXPECTED-SIDE rule (header) is untouched: the value written
/// in is still a hand-written literal supplied by the caller. Only the ADDRESS
/// of the field is derived structurally, and an address is not an expectation.
fn set_pool_init_field(manifest: &str, field: &str, value: &str) -> String {
    let sec = manifest
        .find("\n[pool_init]\n")
        .map(|i| i + 1)
        .expect("manifest must carry a [pool_init] section");
    // The section runs to the next top-level header, or to EOF.
    let end = manifest[sec + 1..]
        .find("\n[")
        .map(|o| sec + 1 + o)
        .unwrap_or(manifest.len());
    let body = &manifest[sec..end];
    let mut hits = body
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .chain(std::iter::once(0))
        .filter(|&i| {
            let line = body[i..].lines().next().unwrap_or("");
            line.split('=').next().map(str::trim) == Some(field)
        })
        .collect::<Vec<_>>();
    hits.sort_unstable();
    assert_eq!(
        hits.len(),
        1,
        "`{field}` must appear exactly once in [pool_init] (found {})",
        hits.len()
    );
    let ls = sec + hits[0];
    let le = ls + manifest[ls..].lines().next().unwrap().len();
    format!("{}{} = \"{}\"{}", &manifest[..ls], field, value, &manifest[le..])
}

/// Field-by-field coverage: each `DPOOL-*` trust-root check bites when its own
/// field drifts. Without this, "verified field-by-field" is a claim about code
/// shape rather than about behaviour.
#[test]
fn pool_init_trust_roots_are_checked_field_by_field() {
    let (manifest, token, vesting) = artifacts();
    let cases: [(&str, &str); 4] = [
        ("DPOOL-4-token-canister", "token_canister"),
        ("DPOOL-5-treasury", "treasury_canister"),
        ("DPOOL-6-staking-canister", "staking_canister"),
        ("DPOOL-7-controller", "controller"),
    ];
    for (check_name, field) in cases {
        let tampered = set_pool_init_field(&manifest, field, "aaaaa-aa");
        assert_ne!(tampered, manifest, "{check_name}: substitution must bite ({field})");
        let checks = run_gates_from_strs_with_record(&tampered, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).expect("gates must run");
        let c = named(&checks, check_name);
        assert!(!c.pass, "{check_name} must fail when its own field drifts; detail: {}", c.detail);
    }
}

// ── A-7 REBASE — the AMENDED DPOOL-5/7 and the new DPOOL-5b ──────────────────
//
// RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13 §3. Every expected value below is
// a HAND-WRITTEN literal, per the file header's independent-expected-side rule:
// the treasury CANISTER's D5 principal and the Vault's, transcribed by hand and
// never read back from the manifest, the kit, or vault_authorities.toml.

/// The treasury CANISTER born under the Vault at J-18 (prop 2), by hand.
const TREASURY_CANISTER_LITERAL: &str = "cqqds-5yaaa-aaaar-qchfq-cai";
/// The custody Vault, by hand.
const VAULT_LITERAL: &str = "cpdab-saaaa-aaaar-qca2q-cai";
/// The TREASURY_MULTISIG allocation holder — `token_init.treasury`, and the
/// value the PRE-amendment DPOOL-5 required. By hand.
const TREASURY_MULTISIG_LITERAL: &str =
    "7aacs-7ky4d-2f7wg-rq4yh-c6us4-gmzow-inzyz-mdglq-ov72c-hx4zc-gae";
/// The VESTING_CONTROLLER multisig — `vesting_init.controller`, and the value
/// the PRE-amendment DPOOL-7 required. By hand.
const VESTING_CONTROLLER_LITERAL: &str =
    "fshhc-2gwwz-ppjrt-3kzea-xt3l6-oemkp-6vkjz-soogu-e5y55-qolw4-wae";
/// A P0-3 placeholder principal, by its published suffix.
const A_P0_3_PLACEHOLDER: &str = "smrmg-tbxqb-3mtei-j5yfc-2b2ny-msuen-ygyyl-dmvug-63dem-vza";

/// The committed manifest carries the RULED trust roots, and both amended
/// checks PASS on it. The positive half — without it the refusals below could
/// be satisfied by a check that never passes at all.
#[test]
fn a7_committed_pool_roots_are_the_ruled_values_and_pass() {
    let (manifest, token, vesting) = artifacts();
    assert!(
        manifest.contains(&format!("treasury_canister = \"{TREASURY_CANISTER_LITERAL}\"")),
        "the committed [pool_init] must name the treasury CANISTER"
    );
    assert!(
        manifest.contains(&format!("controller        = \"{VAULT_LITERAL}\"")),
        "the committed [pool_init] must name the Vault as controller"
    );
    let checks =
        run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
            .expect("gates must run");
    for n in ["DPOOL-5-treasury", "DPOOL-5b-no-placeholder-trust-root", "DPOOL-7-controller"] {
        let c = named(&checks, n);
        assert!(c.pass, "{n} must PASS on the committed tree; detail: {}", c.detail);
    }
}

/// The OLD equalities are now REFUSED, and the refusal NAMES the ruling — so a
/// future reader who re-introduces them is told why, not merely that.
#[test]
fn a7_old_dpool5_and_dpool7_equalities_are_refused_by_name() {
    let (manifest, token, vesting) = artifacts();

    // DPOOL-5: the pre-amendment source was token_init.treasury.
    let old5 = set_pool_init_field(&manifest, "treasury_canister", TREASURY_MULTISIG_LITERAL);
    assert_ne!(old5, manifest, "the substitution must bite");
    let checks =
        run_gates_from_strs_with_record(&old5, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
            .expect("gates must run");
    let c = named(&checks, "DPOOL-5-treasury");
    assert!(!c.pass, "token_init.treasury in pool_init.treasury_canister MUST be refused");
    assert!(
        c.detail.contains("RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13"),
        "the refusal must name the ruling: {}",
        c.detail
    );
    assert!(
        c.detail.contains(TREASURY_MULTISIG_LITERAL),
        "the refusal must name the refused value: {}",
        c.detail
    );

    // DPOOL-7: the pre-amendment source was vesting_init.controller.
    let old7 = set_pool_init_field(&manifest, "controller", VESTING_CONTROLLER_LITERAL);
    assert_ne!(old7, manifest, "the substitution must bite");
    let checks =
        run_gates_from_strs_with_record(&old7, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
            .expect("gates must run");
    let c = named(&checks, "DPOOL-7-controller");
    assert!(!c.pass, "vesting_init.controller in pool_init.controller MUST be refused");
    assert!(
        c.detail.contains("RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13"),
        "the refusal must name the ruling: {}",
        c.detail
    );
}

/// Both amended checks fail CLOSED when their source record is not supplied —
/// never silently skipped.
#[test]
fn a7_amended_checks_fail_closed_without_their_source_record() {
    let (manifest, token, vesting) = artifacts();

    let no_kit =
        run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", None)
            .expect("gates must run");
    let c = named(&no_kit, "DPOOL-5-treasury");
    assert!(!c.pass, "DPOOL-5 with no kit must fail closed; detail: {}", c.detail);
    assert!(c.detail.contains("a7_install_kit.toml"), "detail: {}", c.detail);

    let no_vault =
        run_gates_from_strs_with_record(&manifest, &token, &vesting, None, None, "", Some(&a7_kit_src()))
            .expect("gates must run");
    let c = named(&no_vault, "DPOOL-7-controller");
    assert!(!c.pass, "DPOOL-7 with no vault record must fail closed; detail: {}", c.detail);
    assert!(c.detail.contains("vault_authorities.toml"), "detail: {}", c.detail);

    // A malformed kit is a RED on the named check, not an Err that skips it.
    let bad_kit = a7_kit_src().replace("canister        = \"treasury\"", "canister        = \"nope\"");
    let checks =
        run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&bad_kit))
            .expect("gates must run");
    assert!(!named(&checks, "DPOOL-5-treasury").pass, "a kit with no treasury row must RED DPOOL-5");
}

/// DPOOL-5b: a P0-3 placeholder in ANY of the four pool trust roots is refused
/// on its own limb — the coverage DPOOL-4..7's pure equalities cannot give.
#[test]
fn a7_dpool5b_refuses_a_placeholder_in_every_pool_trust_root() {
    let (manifest, token, vesting) = artifacts();
    for field in ["token_canister", "treasury_canister", "staking_canister", "controller"] {
        let tampered = set_pool_init_field(&manifest, field, A_P0_3_PLACEHOLDER);
        assert_ne!(tampered, manifest, "{field}: substitution must bite");
        let checks = run_gates_from_strs_with_record(
            &tampered,
            &token,
            &vesting,
            None,
            Some(&vault_src()),
            "",
            Some(&a7_kit_src()),
        )
        .expect("gates must run");
        let c = named(&checks, "DPOOL-5b-no-placeholder-trust-root");
        assert!(!c.pass, "a placeholder in {field} MUST be refused; detail: {}", c.detail);
        assert!(c.detail.contains(field), "the refusal must name the field: {}", c.detail);
    }
    // Not vacuous: the committed values carry no placeholder.
    let checks =
        run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
            .expect("gates must run");
    assert!(named(&checks, "DPOOL-5b-no-placeholder-trust-root").pass);
}
