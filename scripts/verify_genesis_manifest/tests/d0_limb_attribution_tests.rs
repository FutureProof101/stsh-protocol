//! W-VKGATE §2.4 (ruled row) — `D0-schema` failures are attributable to a
//! single limb WITHOUT byte-identical differential scaffolding, and the
//! decomposition changes NO behaviour.
//!
//! N-7 = three per-limb mutations (schema / ticker / decimals), each asserted
//! to name its own limb.
//! N-8 = a behaviour-equivalence matrix: for all-pass and each single-limb
//! break, the COMPOSITE verdict equals what the pre-refactor check produced.
//!
//! INDEPENDENT-EXPECTED-SIDE (HARNESS_DELTA §1): every limb name, every limb
//! verdict and every composite verdict below is a HARDCODED literal written
//! from the pre-refactor behaviour of the three-condition AND
//! (`schema_version == 3 && ticker == "STSH" && decimals == 8`). Nothing is
//! captured from the refactored code's own output, and nothing is read back
//! from the manifest under test — the anti-pattern is
//! `wallet/tests/artifacts_l3c.test.ts`, which builds its expected tuple from
//! the artefact it checks.

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


fn artifacts() -> (String, String, String) {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deployment/mainnet");
    (
        std::fs::read_to_string(d.join("genesis_manifest.toml")).unwrap(),
        std::fs::read_to_string(d.join("stsh_token_init.did")).unwrap(),
        std::fs::read_to_string(d.join("vesting_init.did")).unwrap(),
    )
}

fn d0(manifest: &str, token: &str, vesting: &str) -> CheckResult {
    run_gates_from_strs_with_record(manifest, token, vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
        .expect("gates must run")
        .into_iter()
        .find(|c| c.name == "D0-schema")
        .expect("D0-schema must exist — a renamed or removed check is itself the defect")
}

/// Single-limb breaks, each expressed as one substitution against the shipped
/// manifest. Tuple: (label, from, to).
const BREAK_SCHEMA: (&str, &str) = ("schema_version = 3", "schema_version = 2");
const BREAK_TICKER: (&str, &str) = ("ticker = \"STSH\"", "ticker = \"NOPE\"");
const BREAK_DECIMALS: (&str, &str) = ("decimals = 8", "decimals = 6");

fn mutate(manifest: &str, (from, to): (&str, &str)) -> String {
    let out = manifest.replacen(from, to, 1);
    assert_ne!(out, manifest, "the substitution `{from}` -> `{to}` must actually bite");
    out
}

/// **N-7a** — breaking `schema_version` alone is attributable to the SCHEMA limb.
#[test]
fn n7a_schema_limb_failure_is_attributable() {
    let (m, t, v) = artifacts();
    let c = d0(&mutate(&m, BREAK_SCHEMA), &t, &v);
    assert!(!c.pass, "composite must fail; detail: {}", c.detail);
    assert!(c.detail.contains("schema=FAIL"), "the SCHEMA limb must name itself: {}", c.detail);
    assert!(c.detail.contains("ticker=PASS"), "the ticker limb must not be implicated: {}", c.detail);
    assert!(c.detail.contains("decimals=PASS"), "the decimals limb must not be implicated: {}", c.detail);
}

/// **N-7b** — breaking `ticker` alone is attributable to the TICKER limb.
#[test]
fn n7b_ticker_limb_failure_is_attributable() {
    let (m, t, v) = artifacts();
    let c = d0(&mutate(&m, BREAK_TICKER), &t, &v);
    assert!(!c.pass, "composite must fail; detail: {}", c.detail);
    assert!(c.detail.contains("ticker=FAIL"), "the TICKER limb must name itself: {}", c.detail);
    assert!(c.detail.contains("schema=PASS"), "the schema limb must not be implicated: {}", c.detail);
    assert!(c.detail.contains("decimals=PASS"), "the decimals limb must not be implicated: {}", c.detail);
}

/// **N-7c** — breaking `decimals` alone is attributable to the DECIMALS limb.
#[test]
fn n7c_decimals_limb_failure_is_attributable() {
    let (m, t, v) = artifacts();
    let c = d0(&mutate(&m, BREAK_DECIMALS), &t, &v);
    assert!(!c.pass, "composite must fail; detail: {}", c.detail);
    assert!(c.detail.contains("decimals=FAIL"), "the DECIMALS limb must name itself: {}", c.detail);
    assert!(c.detail.contains("schema=PASS"), "the schema limb must not be implicated: {}", c.detail);
    assert!(c.detail.contains("ticker=PASS"), "the ticker limb must not be implicated: {}", c.detail);
}

/// **N-8** — behaviour equivalence.
///
/// The expected column is a hardcoded table written from the PRE-refactor
/// behaviour: `D0-schema` passed iff `schema_version == 3 && ticker == "STSH"
/// && decimals == 8`, so all-pass is `true` and each single-limb break is
/// `false`. If the decomposition had moved any composite verdict, one of these
/// rows would disagree.
#[test]
fn n8_composite_behaviour_is_unchanged_by_the_decomposition() {
    let (m, t, v) = artifacts();

    let cases: [(&str, Option<(&str, &str)>, bool); 4] = [
        ("all limbs satisfied",   None,                 true),
        ("schema limb broken",    Some(BREAK_SCHEMA),   false),
        ("ticker limb broken",    Some(BREAK_TICKER),   false),
        ("decimals limb broken",  Some(BREAK_DECIMALS), false),
    ];

    for (label, mutation, expected_composite) in cases {
        let manifest = match mutation {
            None => m.clone(),
            Some(sub) => mutate(&m, sub),
        };
        let c = d0(&manifest, &t, &v);
        assert_eq!(
            c.pass, expected_composite,
            "{label}: composite verdict moved — the refactor changed behaviour, which §2.4 forbids. detail: {}",
            c.detail
        );
    }

    // The detail's original rendering is preserved byte-for-byte ahead of the
    // limb suffix, which is why the A6.5 C-22 arms keep passing untouched.
    let c = d0(&m, &t, &v);
    assert!(
        c.detail.starts_with("schema_version=3 ticker=STSH decimals=8"),
        "the pre-refactor rendering must survive as the prefix: {}",
        c.detail
    );
}
