//! C-22 (ruling 9cd1f67c §6), carried forward by W-VKGATE (AR1-05 / C-27):
//! the genesis `schema_version` integer and the `D0-schema` check move together,
//! in the same commit, every time the manifest's SHAPE changes.
//!
//! History of this arm, so the counter's movement is auditable rather than
//! mysterious: C-22 moved it 1 → 2 (A6.5). W-VKGATE moves it **2 → 3**, because
//! `[pool_init]` is a new required section — a shape change. The arm always
//! tests the SHIPPED value against the one below it; it is retargeted with the
//! counter, never relaxed.
//!
//! The manifest DOCUMENT label stays "V4" (R1 reading); this is a separate
//! counter, and conflating the two is what produced O-1.
//!
//! Rule 4 — the lockstep is proven by an EXECUTED negative arm, never by
//! argument: the committed stage-1-shape manifest (basis-point percentages,
//! 11 allocation rows, generalised schedule section) must FAIL `D0-schema` at
//! `schema_version = 2` and PASS it at `3`. Both legs assert the named
//! `D0-schema` `CheckResult` specifically — a test that merely observed
//! "gate_d returned some failure" could pass for the wrong reason and would
//! discharge nothing.

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


fn artifacts() -> (String, String, String) {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deployment/mainnet");
    (
        std::fs::read_to_string(dir.join("genesis_manifest.toml")).unwrap(),
        std::fs::read_to_string(dir.join("stsh_token_init.did")).unwrap(),
        std::fs::read_to_string(dir.join("vesting_init.did")).unwrap(),
    )
}

fn d0_schema(manifest: &str, token: &str, vesting: &str) -> CheckResult {
    run_gates_from_strs_with_record(manifest, token, vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
        .expect("gates must run")
        .into_iter()
        .find(|c| c.name == "D0-schema")
        .expect("the D0-schema check must exist — a renamed or removed check is itself the defect")
}

/// The committed manifest is the stage-1 shape PLUS `[pool_init]`, at `schema_version = 3`.
#[test]
fn committed_manifest_is_stage_one_shape_at_schema_three() {
    let (manifest, _, _) = artifacts();
    assert!(manifest.contains("schema_version = 3"), "manifest must carry the bumped counter");
    assert!(manifest.contains("percent_bps"), "stage-1 shape: basis-point percentages");
    assert!(manifest.contains("[pool_init]"), "W-VKGATE shape: the pool trust-root section");
    assert_eq!(
        manifest.matches("[[allocation]]").count(),
        11,
        "stage-1 shape: 11 allocation rows"
    );
}

/// GREEN leg — the same shape at `schema_version = 3` passes `D0-schema`.
#[test]
fn d0_schema_passes_at_schema_version_3() {
    let (manifest, token, vesting) = artifacts();
    let c = d0_schema(&manifest, &token, &vesting);
    assert!(c.pass, "D0-schema must pass at schema_version = 3; detail: {}", c.detail);
    assert!(c.detail.contains("schema_version=3"), "detail must render the value: {}", c.detail);
}

/// RED leg — the SAME manifest at the PREVIOUS counter (`schema_version = 2`) fails
/// `D0-schema`. This is the executed failing check C-22 requires: if site 3
/// (`src/lib.rs` `D0-schema`) is left behind at `== 1` while site 1 moves, this
/// assertion fails and the lockstep is broken loudly.
#[test]
fn d0_schema_fails_closed_at_schema_version_2() {
    let (manifest, token, vesting) = artifacts();
    let stage_one_at_schema_2 = manifest.replace("schema_version = 3", "schema_version = 2");
    assert!(
        stage_one_at_schema_2.contains("schema_version = 2")
            && !stage_one_at_schema_2.contains("schema_version = 3"),
        "the substitution must actually bite (and the diagnostic must stay readable — \
         never dump both manifests into the transcript)"
    );

    let c = d0_schema(&stage_one_at_schema_2, &token, &vesting);
    assert!(
        !c.pass,
        "D0-schema MUST fail at schema_version = 2 — the moved pin does not bite; detail: {}",
        c.detail
    );
    assert!(c.detail.contains("schema_version=2"), "detail must name the rejected value: {}", c.detail);

    // Not vacuous by the ticker/decimals arms: only the counter differs, and the
    // rest of the manifest is byte-identical to the passing GREEN-leg input.
    let green = d0_schema(&manifest, &token, &vesting);
    assert!(green.pass, "control: the unmodified manifest passes");
}
