//! AR-5/AR-6 fixture proofs: Gate-D + Gate-V validate the committed
//! placeholder artifacts (positive), and FAIL CLOSED on every adversarial
//! mutation the brief names (negative) — including the "reconstructed args
//! differing from the deployed artifact" vector.

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


fn deployment_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deployment/mainnet")
}

fn fixtures() -> (String, String, String) {
    let dir = deployment_dir();
    (
        std::fs::read_to_string(dir.join("genesis_manifest.toml")).unwrap(),
        std::fs::read_to_string(dir.join("stsh_token_init.did")).unwrap(),
        std::fs::read_to_string(dir.join("vesting_init.did")).unwrap(),
    )
}

fn failing_names(checks: &[CheckResult]) -> Vec<String> {
    checks.iter().filter(|c| !c.pass).map(|c| c.name.clone()).collect()
}

// ── Structural addressing rule (RR-1a, 2026-09-12) ──────────────────────────
// Until RR-1 the principals in the committed inputs were P0-3 placeholders, and
// the negative controls below named them as literals. RR-1 rebound every one of
// them to a real production principal and each of those literals became a silent
// no-op — the mutation stopped applying and the test went on asserting a RED it
// was no longer causing. (A-4 hit the same class on `[pool_init].vk_hash`; see
// `vkgate_pool_init_tests.rs`.)
//
// Every control now addresses its target STRUCTURALLY — by allocation
// `category_id`, by init field, by schedule index — and reads the CURRENT value
// only in order to move it. That is not self-inherited verification: the
// expectation is still the hand-written name of the check that must RED, and the
// `assert_ne!` bite guard still proves the mutation applied.

fn parsed(m: &str, t: &str, v: &str) -> (Manifest, ParsedTokenInit, ParsedVestingInit) {
    (
        toml::from_str(m).expect("manifest parses"),
        extract_token_init(&parse_artifact(t).expect("token .did parses")).expect("token init"),
        extract_vesting_init(&parse_artifact(v).expect("vesting .did parses")).expect("vesting init"),
    )
}

/// The `principal` of the manifest allocation row with this `category_id`.
fn manifest_row_principal(manifest: &str, id: &str) -> String {
    let m: Manifest = toml::from_str(manifest).expect("manifest parses");
    m.allocation
        .iter()
        .find(|a| a.category_id == id)
        .unwrap_or_else(|| panic!("manifest row `{id}` not found"))
        .principal
        .clone()
}

/// The `recipient` of the token-artifact allocation record with this `category_id`.
fn token_row_recipient(token: &str, id: &str) -> String {
    let t = extract_token_init(&parse_artifact(token).expect("token .did parses")).expect("token init");
    t.allocations
        .iter()
        .find(|a| a.category_id == id)
        .unwrap_or_else(|| panic!("token record `{id}` not found"))
        .recipient
        .clone()
}

/// A deterministic, VALID, non-placeholder principal distinct from everything any
/// input carries — derived via `to_text()`, so its checksum cannot be wrong.
fn outsider_principal(i: u8) -> String {
    candid::Principal::from_slice(&[0xC0, 0xFF, 0xEE, 0, 0, 0, 0, i, 0x01]).to_text()
}

// R4-1 RETARGET (lane A-4): the COMMITTED artifacts still carry P0-3
// placeholder principals, so Gate-D now REFUSES them by design — that refusal
// is the bite proof, asserted in `placeholder_gate_tests.rs`. The all-pass
// direction therefore moves onto the RR-1-replaced set, which is what a real
// genesis will actually present. The artifact-SHA assertions are unchanged:
// they do not depend on pass/fail.
#[test]
fn rr1_replaced_artifacts_pass_gate_d_and_gate_v_pre_install() {
    let report = run_gates_on_dir(&deployment_dir()).expect("gates must run");
    assert_eq!(report.artifact_hashes.len(), 3, "all three artifact SHAs recorded");
    for (name, sha) in &report.artifact_hashes {
        assert_eq!(sha.len(), 64, "{}: full SHA-256 recorded", name);
    }

    let (manifest, token, vesting) = fixtures();
    let (manifest, token, vesting) = rr1_replaced_fixture(&manifest, &token, &vesting);
    let checks = run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    // R-3a: `run_gates_from_strs` (the record-BLIND surface this test used to
    // call) is gone as a public API, so the call is made on the record-bearing
    // surface with `None` for the record — which is exactly the "no record was
    // supplied" state, and `GP0-record` correctly reports it. The GP* family is
    // therefore NOT part of this test's claim, which is the one its NAME makes:
    // gate_d and gate_v_pre_install. The record-bearing re-proof of the GP*
    // family over this same RR-1-replaced set is the block immediately below,
    // added by R-3 for precisely this reason.
    let failing: Vec<String> =
        failing.into_iter().filter(|n| !n.starts_with("GP")).collect();
    assert!(
        failing.is_empty(),
        "RR-1-replaced artifacts must pass every gate_d/gate_v_pre_install check; failing: {:?}",
        failing
    );
    // Vacuity for the filter: the GP* family really did run on this surface, so
    // the filter above is narrowing a real set rather than papering over an
    // empty one.
    assert!(
        checks.iter().any(|c| c.name.starts_with("GP")),
        "the principal-gate family must have RUN here — if it did not, the filter above is \
         hiding nothing and this test's surface silently shrank"
    );
    // Not vacuous: the full check surface ran (D-checks + V-checks + 11 rows +
    // the 39 DP3-* sites + DP3-scan-coverage). 11 rows since D-4 (drift item).
    assert!(checks.len() >= 62, "expected the full check surface, got {}", checks.len());

    // RETARGETED BY R-3 (brief §4 item 4). `run_gates_from_strs` is RECORD-BLIND,
    // so the claim above — "the RR-1-replaced artifacts pass every check" — no
    // longer describes what the real gate does: since R-3 the genesis principals
    // are also bound to an INDEPENDENT record, and a replaced set whose record
    // does not match is refused at `GP2-value-<ROLE>`. Re-proven on the surface
    // that carries GP0..GP6, with the cross-bound role pinned to the REAL Vault
    // principal (freeze §14) — which is what a real RR-1 writes there.
    let root = deployment_dir().parent().unwrap().parent().unwrap().to_path_buf();
    let vault = load_vault_bound_principal(&root)
        .expect("vault_authorities.toml parses")
        .expect("vault_authorities.toml present");
    let (bm, bt, bv) = fixtures();
    let (vm, vt, vv) = rr1_replaced_fixture_with_vault(&bm, &bt, &bv, &vault.to_text());
    let record = record_matching(&vm, &vt, &vv, true).expect("matching record");
    let vault_toml = std::fs::read_to_string(root.join(GENESIS_VAULT_AUTHORITY_RECORD)).unwrap();
    let bound = run_gates_from_strs_with_record(
        &vm,
        &vt,
        &vv,
        Some(&record),
        Some(&vault_toml),
        &sha256_hex(record.as_bytes()), Some(&a7_kit_src()))
    .unwrap();
    let bound_failing = failing_names(&bound);
    assert!(
        bound_failing.is_empty(),
        "a legitimate RR-1 (replaced inputs + matching record) must pass GP0..GP6 too: {:?}",
        bound_failing
    );
    // Lane A-2 (D-9): the census count is REGENERATED by parsing the committed
    // record at point of use, never inherited from a prior revision's prose.
    let census_entries = std::fs::read_to_string(
        deployment_dir().join("genesis_principals.toml"),
    )
    .unwrap()
    .lines()
    .filter(|l| l.starts_with("[role."))
    .count();
    assert_eq!(
        bound.iter().filter(|c| c.name.starts_with("GP2-value-")).count(),
        census_entries,
        "anti-vacuity: all {} census roles must be GP2-evaluated once resolved",
        census_entries
    );
}

#[test]
fn wrapping_or_wrong_sum_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // Artifact amount tampered (+1 on liquidity): D11 row + D12 checked sum fail.
    // Reallocation (a14beef1): liquidity is 14e15 and that literal is unique in
    // the artifact — 12e15 is `insurance` AND `founders`, 5e15 is three rows.
    let tampered = token.replace("14_000_000_000_000_000", "14_000_000_000_000_001");
    let checks = run_gates_from_strs_with_record(&manifest, &tampered, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(failing.iter().any(|n| n.starts_with("D11-row-9")), "row check must fail: {:?}", failing);
    assert!(failing.contains(&"D12-artifact-sum-checked".to_string()));
}

#[test]
fn reconstructed_args_differing_from_manifest_fail_closed() {
    let (manifest, token, vesting) = fixtures();
    // The adversarial Gate-D vector: an operator "reconstructs" the init args
    // and swaps a recipient principal (airdrop's recipient -> liquidity's).
    let from = token_row_recipient(&token, "airdrop");
    let to = token_row_recipient(&token, "liquidity");
    let reconstructed = replace_in_token_record(&token, "airdrop", &from, &to);
    assert_ne!(reconstructed, token, "the recipient swap must bite");
    let checks = run_gates_from_strs_with_record(&manifest, &reconstructed, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    assert!(
        failing_names(&checks).iter().any(|n| n.starts_with("D11-row-7-airdrop")),
        "recipient swap must fail the airdrop row"
    );
}

#[test]
fn non_canonical_subaccount_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // §0.3: subaccount MUST be the canonical `null`, never an all-zero vec.
    let non_canonical = token.replacen(
        "subaccount = null;",
        "subaccount = opt blob \"\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\";",
        1,
    );
    let checks = run_gates_from_strs_with_record(&manifest, &non_canonical, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    assert!(
        failing_names(&checks).iter().any(|n| n.starts_with("D11-row-0")),
        "non-null subaccount must fail the row's canonical-form check"
    );
}

#[test]
fn fee_collector_equal_to_treasury_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    let (m, t, _) = parsed(&manifest, &token, &vesting);
    let fc = m.token_init.fee_collector.clone();
    let treasury = m.token_init.treasury.clone();
    assert_eq!(t.fee_collector.as_deref(), Some(fc.as_str()), "artifact carries the same fee_collector");
    let bad_manifest = manifest.replace(
        &format!("fee_collector    = \"{fc}\""),
        &format!("fee_collector    = \"{treasury}\""),
    );
    let bad_token = token.replace(
        &format!("fee_collector = opt principal \"{fc}\""),
        &format!("fee_collector = opt principal \"{treasury}\""),
    );
    assert_ne!(bad_manifest, manifest, "the manifest mutation must bite");
    assert_ne!(bad_token, token, "the artifact mutation must bite");
    let checks = run_gates_from_strs_with_record(&bad_manifest, &bad_token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(
        failing.contains(&"D9-fee-collector-distinct-nonnull".to_string())
            && failing.contains(&"D15-init-fee-collector".to_string()),
        "fee_collector == treasury must fail closed: {:?}",
        failing
    );
}

#[test]
fn founders_recipient_not_vesting_canister_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // Swap the founders recipient to the ceremony holding account — the
    // custody-binding core of Gate-V phase 1.
    let bad = replace_in_token_record(
        &token,
        "founders",
        &token_row_recipient(&token, "founders"),
        &token_row_recipient(&token, "ceremony_rewards"),
    );
    assert_ne!(bad, token, "the founders-recipient swap must bite");
    let checks = run_gates_from_strs_with_record(&manifest, &bad, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(
        failing.contains(&"V2-founders-recipient-is-vesting-canister".to_string()),
        "custody binding must fail closed: {:?}",
        failing
    );
}

#[test]
fn schedule_sum_off_by_one_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // DRIFT-1: ONE founder schedule carrying the whole founders allocation, now
    // 12e15 (a14beef1). Unique in vesting_init.did — counsel carries 0.5e15.
    let bad = vesting.replace("12_000_000_000_000_000", "11_999_999_999_999_999");
    let checks = run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(failing.contains(&"V6-schedule-sum-eq-custody-allocation".to_string()));
    assert!(failing.contains(&"V5-schedules-match-manifest".to_string()));
}

#[test]
fn wrong_founder_shape_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // §0.4 LOCKED: every founder schedule is cliff 6 / linear 30.
    let bad = vesting.replacen("cliff_months = 6 : nat32", "cliff_months = 7 : nat32", 1);
    let checks = run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    assert!(failing_names(&checks).contains(&"V3-founder-schedule-shape".to_string()));
}

#[test]
fn duplicate_beneficiary_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // DRIFT-1 retired FOUNDER_2/3; the two remaining beneficiaries are the
    // founder and counsel, so the collision is built from those.
    let (_, _, v) = parsed(&manifest, &token, &vesting);
    let counsel = v.schedules[1].beneficiary.clone();
    let founder = v.schedules[0].beneficiary.clone();
    let bad = vesting.replace(&counsel, &founder);
    assert_ne!(bad, vesting, "the beneficiary collision must bite");
    let checks = run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(failing.contains(&"V4-unique-beneficiaries".to_string()), "{:?}", failing);
}

// ── SSA P1 negatives: the APPROVED §0.3 schema is pinned IN THE TOOL — a
//    coherent manifest(+artifact) drift must fail, with only the P0-3
//    principal VALUES replaceable. ─────────────────────────────────────────

#[test]
fn role_mutation_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // The exact SSA repro: TREASURY_MULTISIG -> ATTACKER_ROLE (manifest-only,
    // internally coherent — previously a full PASS).
    let bad = manifest.replace(
        "principal_role = \"TREASURY_MULTISIG\"",
        "principal_role = \"ATTACKER_ROLE\"",
    );
    let checks = run_gates_from_strs_with_record(&bad, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(
        failing.contains(&"DP1-row-0-treasury".to_string()),
        "role mutation must fail the pinned-schema check: {:?}",
        failing
    );
}

#[test]
fn percentage_redistribution_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // The exact SSA repro, RE-POINTED onto the reallocated shares (a14beef1):
    // treasury 3000/insurance 1200 -> 3001/1199 — still sums to 10,000, so the
    // aggregate check still passes. The pinned per-row shares must fail it.
    // `percent_bps = 1200` is now `founders`' share too, so the insurance leg is
    // row-anchored; treasury's 3000 is unique but is scoped the same way.
    let bad = replace_in_manifest_row(&manifest, "treasury", "percent_bps = 3000", "percent_bps = 3001");
    let bad = replace_in_manifest_row(&bad, "insurance", "percent_bps = 1200", "percent_bps = 1199");
    let checks = run_gates_from_strs_with_record(&bad, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(
        failing.contains(&"DP1-row-0-treasury".to_string())
            && failing.contains(&"DP1-row-1-insurance".to_string()),
        "percent redistribution must fail both pinned rows: {:?}",
        failing
    );
    // The aggregate check alone would NOT have caught it:
    assert!(!failing.contains(&"D3-percent-sum".to_string()));
}

#[test]
fn coherent_manifest_plus_artifact_amount_drift_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // Treasury -1e15 / airdrop +1e15 applied COHERENTLY to BOTH files: checked
    // sums still equal 10^17 and artifact == manifest, so every pre-P1 check
    // passed. The pinned amounts must fail it.
    // Reallocation (a14beef1): treasury's pinned amount is 30e15 and
    // `external_lp_incentives` is 5e15 — a literal now shared with `airdrop` and
    // `capital_reserve`, so BOTH legs are row-anchored and each moves exactly one
    // row. The pair is still Sigma-preserving (-1e15 / +1e15).
    let bad_manifest = replace_in_manifest_row(&manifest, "treasury", "amount_base_units = 30000000000000000", "amount_base_units = 29000000000000000");
    let bad_manifest = replace_in_manifest_row(&bad_manifest, "external_lp_incentives", "amount_base_units = 5000000000000000", "amount_base_units = 6000000000000000");
    let bad_token = replace_in_token_record(&token, "treasury", "amount = 30_000_000_000_000_000 : nat", "amount = 29_000_000_000_000_000 : nat");
    let bad_token = replace_in_token_record(&bad_token, "external_lp_incentives", "amount = 5_000_000_000_000_000 : nat", "amount = 6_000_000_000_000_000 : nat");
    let checks = run_gates_from_strs_with_record(&bad_manifest, &bad_token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    assert!(
        failing.contains(&"DP1-row-0-treasury".to_string())
            && failing.contains(&"DP1-row-10-external_lp_incentives".to_string()),
        "coherent amount drift must fail the pinned rows: {:?}",
        failing
    );
    // Confirm the drift really was coherent (the old checks would have passed):
    assert!(!failing.contains(&"D2-manifest-sum-checked".to_string()));
    assert!(!failing.contains(&"D12-artifact-sum-checked".to_string()));
    assert!(!failing.iter().any(|n| n.starts_with("D11-row-")));
}

#[test]
fn coherent_name_drift_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    let bad_manifest =
        manifest.replace("category_name = \"Protocol Treasury\"", "category_name = \"War Chest\"");
    let bad_token =
        token.replace("category_name = \"Protocol Treasury\";", "category_name = \"War Chest\";");
    let checks = run_gates_from_strs_with_record(&bad_manifest, &bad_token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    assert!(
        failing_names(&checks).contains(&"DP1-row-0-treasury".to_string()),
        "coherent name drift must fail the pinned schema"
    );
}

#[test]
fn founder_shape_manifest_drift_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    let bad = manifest.replace("founder_cliff_months  = 6", "founder_cliff_months  = 7");
    let checks = run_gates_from_strs_with_record(&bad, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    assert!(
        failing_names(&checks).contains(&"DP2-founder-shape-pin".to_string()),
        "the LOCKED 6/30 founder shape is pinned in the tool"
    );
}

#[test]
fn gate_v_post_install_exact_or_fail() {
    let expected = 12_000_000_000_000_000u128;
    assert!(all_pass(&gate_v_post_install(expected, expected, expected)));
    // Any drift fails closed — balance short, sum long, both off.
    assert!(!all_pass(&gate_v_post_install(expected - 1, expected, expected)));
    assert!(!all_pass(&gate_v_post_install(expected, expected + 1, expected)));
    assert!(!all_pass(&gate_v_post_install(0, 0, expected)));
}

// ── D-4 (drift item) bps drift lock: D3-percent-sum must BITE at the new target ──
//
// SSA-2's GREEN (89a7f130a7784899) gate 3: a passing true case alone is
// insufficient — the mutated sum must be exhibited FAILING at the 10,000 target
// and the true sum PASSING, on this surface. Both directions are asserted here.
//
// This is the check the move to basis points could have silently loosened: if the
// target had been left at 100, or the sum computed from the artifact under test,
// every real manifest would fail or every mutation would pass. Neither happens.
#[test]
fn bps_sum_drift_fails_closed_and_true_sum_passes() {
    let (manifest, token, vesting) = fixtures();

    // FAILING direction: shrink ONE row's share without compensating. Σbps = 9,999.
    // `percent_bps = 1200` is `insurance` AND `founders` since a14beef1, so the
    // leg is row-anchored — a bare replace would move two rows (Σbps = 9,998) and
    // the stated reason would no longer be the reason the test REDs.
    let bad = replace_in_manifest_row(&manifest, "insurance", "percent_bps = 1200", "percent_bps = 1199");
    assert_ne!(bad, manifest, "mutation must actually apply");
    let failing = failing_names(&run_gates_from_strs_with_record(&bad, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"D3-percent-sum".to_string()),
        "Σbps=9999 must fail D3-percent-sum at the 10,000 target: {:?}",
        failing
    );

    // Over the target too — a one-sided inflation, Σbps = 10,001.
    let bad_up = replace_in_manifest_row(&manifest, "insurance", "percent_bps = 1200", "percent_bps = 1201");
    let failing_up = failing_names(&run_gates_from_strs_with_record(&bad_up, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing_up.contains(&"D3-percent-sum".to_string()),
        "Σbps=10001 must fail D3-percent-sum: {:?}",
        failing_up
    );

    // PASSING direction: the committed manifest's true sum is exactly 10,000.
    let true_failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        !true_failing.contains(&"D3-percent-sum".to_string()),
        "the true Σbps must PASS D3-percent-sum: {:?}",
        true_failing
    );

    // And the old integer-percent target must be genuinely gone: a manifest whose
    // shares sum to 100 (the pre-D-4 target) must now FAIL. Proves the constant
    // moved rather than the field being reinterpreted.
    // Re-pointed onto the reallocated shares (a14beef1).
    // 30+12+12+4.5+0.5+2+10+5+5+14+5 = 100, so integer-percent truncation of the
    // two half-percent rows to 4 and 0 yields Sigma = 99 — either way it is not
    // 10,000 and D3 must RED. This mutation is DELIBERATELY table-wide (every row
    // is demoted to integer percent), so the shared 1200/500 literals are not a
    // collision here: replace-all is the intended semantics. Longest-first so
    // `percent_bps = 500` cannot shadow `= 50`.
    let legacy = manifest
        .replace("percent_bps = 3000", "percent_bps = 30")
        .replace("percent_bps = 1400", "percent_bps = 14")
        .replace("percent_bps = 1200", "percent_bps = 12")
        .replace("percent_bps = 1000", "percent_bps = 10")
        .replace("percent_bps = 500", "percent_bps = 5")
        .replace("percent_bps = 450", "percent_bps = 4")
        .replace("percent_bps = 200", "percent_bps = 2")
        .replace("percent_bps = 50", "percent_bps = 0");
    let legacy_failing = failing_names(&run_gates_from_strs_with_record(&legacy, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        legacy_failing.contains(&"D3-percent-sum".to_string()),
        "a legacy Σ%=100 manifest must FAIL the bps target: {:?}",
        legacy_failing
    );
}

// ── D-4 (drift item) MISMINT CLOSURE: the pre-D-4 allocation shape is refused ──
//
// The scope's countersign gate: Gate-D was blind to the pre-V4 manifest and would
// MISMINT — treasury minting 30% with the legal-counsel grant existing nowhere.
// Closed here by a NAMED failing-then-passing check, on this surface, both
// directions in one test.
//
// Limb 1 (check level): a manifest carrying the pre-D-4 TEN-row allocation shape
// is parseable but must FAIL by name. Limb 2 (parse level): the literal base
// manifest cannot even be read, because `percent` -> `percent_bps` is a schema
// move, so a pre-D-4 file can never be silently accepted.
#[test]
fn pre_d4_ten_row_shape_fails_by_name_and_rebuilt_shape_passes() {
    let (manifest, token, vesting) = fixtures();

    // RE-POINT (a14beef1). The excised row is still the LAST one of the D-7 order,
    // `external_lp_incentives`, now 5%, with its 5% folded back into `liquidity`
    // (14% -> 19%) so the ten-row shape is internally coherent — Sigma still 10,000
    // bps and 10^17 base units — and it is the ROW PIN that catches it, not an
    // arithmetic accident. 1400/1900 and 14e15/19e15 are unique literals, so the
    // fold needs no row anchor; the EXCISION itself is already byte-range scoped.
    let start = manifest
        .find("[[allocation]]\n# NEW ROW. D-0 bucket 10")
        .expect("external_lp_incentives row present");
    let end = manifest
        .find("# ── Counsel schedule")
        .expect("the allocation table ends at the counsel schedule section");
    let ten_row = format!("{}{}", &manifest[..start], &manifest[end..])
        .replace("amount_base_units = 14000000000000000", "amount_base_units = 19000000000000000")
        .replace("percent_bps = 1400", "percent_bps = 1900");
    let ten_row_token = {
        let cut = token
            .find("      // NEW. V4 D-0 bucket 10, AMENDED 3% -> 5%")
            .expect("external_lp_incentives record in the artifact");
        let close = cut + token[cut..].find("      };\n").expect("record closes") + "      };\n".len();
        format!("{}{}", &token[..cut], &token[close..])
            .replace("amount = 14_000_000_000_000_000 : nat", "amount = 19_000_000_000_000_000 : nat")
    };
    let (pre_d4, pre_d4_token) = (ten_row, ten_row_token);

    let failing = failing_names(&run_gates_from_strs_with_record(&pre_d4, &pre_d4_token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    for name in [
        "DP0-approved-row-count",
        "DP1-row-9-liquidity",
        "DP1-row-10-external_lp_incentives",
        "DP3-scan-coverage",
    ] {
        assert!(
            failing.contains(&name.to_string()),
            "pre-D-4 shape must FAIL {} by name: {:?}",
            name,
            failing
        );
    }

    // PASSING direction: the rebuilt artifacts pass every one of those same names.
    let rebuilt = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    for name in [
        "DP0-approved-row-count",
        "DP1-row-9-liquidity",
        "DP1-row-10-external_lp_incentives",
        "DP3-scan-coverage",
        "D2-manifest-sum-checked",
        "D12-artifact-sum-checked",
        "D3-percent-sum",
    ] {
        assert!(
            !rebuilt.contains(&name.to_string()),
            "rebuilt shape must PASS {}: {:?}",
            name,
            rebuilt
        );
    }

    // Limb 2: the literal pre-D-4 field name is not merely wrong, it is unreadable.
    let legacy_field = manifest.replace("percent_bps = ", "percent = ");
    assert!(
        run_gates_from_strs_with_record(&legacy_field, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).is_err(),
        "a pre-D-4 `percent` manifest must fail CLOSED at parse, never be accepted"
    );
}

// ── Sub-item 1 (bucket identity): D16, and the ENUMERATED D-4 V2 exemption ──
//
// The hole D16 closed, measured before it existed: pointing one allocation row's
// principal at another's produced ZERO non-placeholder failures — the 0.5% counsel
// grant would have minted into the treasury account with Gate-D silent. DP1 pins
// roles, not principals (those are RR-1-replaceable); D4 covers ids; D5 only parses.
//
// D-4 V2 then required ONE collision to be legal: `founders` and `legal_counsel`
// both name the vesting canister, because it is the schedule authority for both.
// These tests prove the exemption is exactly that pair on exactly that principal —
// a wildcard would have silently reopened the hole.
#[test]
fn duplicate_allocation_principal_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    let vc = manifest_row_principal(&manifest, "founders"); // genesis vesting canister
    let treasury_p = manifest_row_principal(&manifest, "treasury");

    // (a) A THIRD row joining the exempt pair must FAIL. Treasury is re-pointed at
    // the vesting canister — the exemption names two categories, not a principal
    // that anyone may share.
    let collide_third = |s: &str| s.replace(treasury_p.as_str(), vc.as_str());
    assert_ne!(collide_third(&manifest), manifest, "the third-row collision must bite");
    let failing = failing_names(
        &run_gates_from_strs_with_record(&collide_third(&manifest), &collide_third(&token), &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap(),
    );
    assert!(
        failing.contains(&"D16-unique-allocation-principals".to_string()),
        "a third row joining the exempt pair must fail closed: {:?}",
        failing
    );

    // (b) An ordinary two-row collision, nowhere near the exemption, must FAIL.
    let insurance_p = manifest_row_principal(&manifest, "insurance");
    let liquidity_p = manifest_row_principal(&manifest, "liquidity");
    let collide_plain = |s: &str| s.replace(insurance_p.as_str(), liquidity_p.as_str());
    assert_ne!(collide_plain(&manifest), manifest, "the plain collision must bite");
    let failing_plain = failing_names(
        &run_gates_from_strs_with_record(&collide_plain(&manifest), &collide_plain(&token), &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap(),
    );
    assert!(
        failing_plain.contains(&"D16-unique-allocation-principals".to_string()),
        "an ordinary allocation-principal collision must still fail closed: {:?}",
        failing_plain
    );

    // (c) The exempt pair itself PASSES on the committed artifacts, and D16 is not
    // among the true set's failures.
    let true_failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        !true_failing.contains(&"D16-unique-allocation-principals".to_string()),
        "the ruled founders/counsel pair must pass D16: {:?}",
        true_failing
    );

    // (d) Survives RR-1: the pair still resolves to ONE production principal (a
    // single token-map entry), and D16 still passes on the replaced set.
    let (rr1_m, rr1_t, rr1_v) = rr1_replaced_fixture(&manifest, &token, &vesting);
    let rr1_failing = failing_names(&run_gates_from_strs_with_record(&rr1_m, &rr1_t, &rr1_v, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        !rr1_failing.contains(&"D16-unique-allocation-principals".to_string()),
        "RR-1-replaced set must keep the exemption intact: {:?}",
        rr1_failing
    );
}

// The exemption is pinned to the VESTING CANISTER, not merely to the two category
// names: founders + counsel sharing some other principal is still a collision.
#[test]
fn exempt_pair_sharing_a_non_vesting_principal_fails_closed() {
    let (manifest, token, vesting) = fixtures();
    // Move BOTH rows of the pair onto the treasury principal instead.
    let vc = manifest_row_principal(&manifest, "founders");
    let treasury = manifest_row_principal(&manifest, "treasury");
    let bad_manifest = manifest.replace(vc.as_str(), treasury.as_str());
    let bad_token = token.replace(vc.as_str(), treasury.as_str());
    assert_ne!(bad_manifest, manifest, "the pair move must bite");
    assert_ne!(bad_token, token, "the pair move must bite in the artifact too");
    let failing = failing_names(&run_gates_from_strs_with_record(&bad_manifest, &bad_token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"D16-unique-allocation-principals".to_string()),
        "the exempt pair on a non-vesting-canister principal must fail closed: {:?}",
        failing
    );
}

// ══ D-4 V2 Rule-4 obligations: every widened check proves it still bites ══════
//
// SURFACE for all seven: the COMMITTED artifacts in `deployment/mainnet/` mutated
// in memory (V8's S-1 surface), run through `run_gates_from_strs`. None of them
// touch S-2 (the RR-1-replaced set) — that surface is exercised by
// `rr1_replaced_artifacts_pass_gate_d_and_gate_v_pre_install` and by
// `t3_rr1_replaced_set_passes_everything`.
//
// Every assertion is at SHIPPED values: no mutation weakens a pin to make itself
// pass, and each names the check it must RED.

// M1 — counsel schedule shape → anything but 0/12 ⇒ V3 REDs.
#[test]
fn m1_counsel_shape_drift_reds_v3() {
    let (manifest, token, vesting) = fixtures();
    // Give counsel the FOUNDERS shape. This is the dangerous direction: it looks
    // legitimate everywhere else, and before V3 became per-schedule it would pass.
    let bad = vesting.replace(
        "        cliff_months = 0 : nat32;\n        linear_months = 12 : nat32;",
        "        cliff_months = 6 : nat32;\n        linear_months = 30 : nat32;",
    );
    assert_ne!(bad, vesting, "mutation must apply");
    let failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"V3-founder-schedule-shape".to_string()),
        "counsel wearing the founders shape must RED V3: {:?}",
        failing
    );
}

// M2 — a schedule matching NEITHER pin ⇒ V3 REDs (exhaustiveness).
#[test]
fn m2_schedule_matching_neither_pin_reds_v3() {
    let (manifest, token, vesting) = fixtures();
    let bad = vesting.replace(
        "        cliff_months = 0 : nat32;\n        linear_months = 12 : nat32;",
        "        cliff_months = 3 : nat32;\n        linear_months = 9 : nat32;",
    );
    assert_ne!(bad, vesting, "mutation must apply");
    let failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"V3-founder-schedule-shape".to_string()),
        "a shape matching neither pin must RED V3: {:?}",
        failing
    );
}

// M3 — schedule list permuted (counsel before founders) ⇒ V5 REDs (order pin).
#[test]
fn m3_permuted_schedule_order_reds_v5() {
    let (manifest, token, vesting) = fixtures();
    // Move the counsel record to the FRONT of the schedules vec, unchanged in
    // content. Σ is identical and every beneficiary still unique, so only the
    // positional binding can catch it.
    let counsel_start = vesting.find("      // D-4 V2 — legal-counsel grant").expect("counsel record");
    let counsel_end = vesting[counsel_start..].find("      };").expect("record end") + counsel_start + "      };\n".len();
    let counsel_block = &vesting[counsel_start..counsel_end];
    let without = format!("{}{}", &vesting[..counsel_start], &vesting[counsel_end..]);
    let first_rec = without.find("      record {").expect("first schedule record");
    let bad = format!("{}{}{}", &without[..first_rec], counsel_block, &without[first_rec..]);

    let failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"V5-schedules-match-manifest".to_string()),
        "permuting the schedule order must RED V5: {:?}",
        failing
    );
}

// M4 — Σ(schedules) off by any amount ⇒ V6 REDs, and VP1 on the balance leg.
#[test]
fn m4_schedule_sum_drift_reds_v6_and_vp1() {
    let (manifest, token, vesting) = fixtures();
    let bad = vesting.replace(
        "        total_amount = 500_000_000_000_000 : nat;",
        "        total_amount = 500_000_000_000_001 : nat;",
    );
    assert_ne!(bad, vesting, "mutation must apply");
    let failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &bad, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"V6-schedule-sum-eq-custody-allocation".to_string()),
        "Σ drift must RED V6: {:?}",
        failing
    );

    // Balance leg (Gate-V phase 2, pure): the expectation is founders + counsel.
    let expected = vesting_custody_total(&manifest).expect("custody total");
    assert_eq!(expected, 12_500_000_000_000_000, "founders 12e15 + counsel 0.5e15");
    let post = gate_v_post_install(expected - 1, expected, expected);
    assert!(
        post.iter().any(|c| !c.pass && c.name == "VP1-vesting-canister-balance"),
        "a short balance must RED VP1"
    );
    let post2 = gate_v_post_install(expected, expected - 1, expected);
    assert!(
        post2.iter().any(|c| !c.pass && c.name == "VP2-installed-schedule-sum"),
        "a short installed sum must RED VP2"
    );
    // Not vacuous: at the true values both pass.
    assert!(gate_v_post_install(expected, expected, expected).iter().all(|c| c.pass));
}

// M5 — a third-party principal collision ⇒ D16 still REDs despite the exemption.
//      (Covered in full by `duplicate_allocation_principal_fails_closed` (a)/(b)
//      and `exempt_pair_sharing_a_non_vesting_principal_fails_closed`; asserted
//      here too so the Rule-4 set is complete and legible on its own.)
#[test]
fn m5_third_party_collision_still_reds_d16() {
    let (manifest, token, vesting) = fixtures();
    let bounty_p = manifest_row_principal(&manifest, "audit_bounty");
    let ceremony_p = manifest_row_principal(&manifest, "ceremony_rewards"); // lane A-2: `dev` retired
    let collide = |s: &str| s.replace(bounty_p.as_str(), ceremony_p.as_str());
    assert_ne!(collide(&manifest), manifest, "the third-party collision must bite");
    let failing =
        failing_names(&run_gates_from_strs_with_record(&collide(&manifest), &collide(&token), &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"D16-unique-allocation-principals".to_string()),
        "a collision unrelated to the exemption must still RED D16: {:?}",
        failing
    );
}

// M6 — counsel beneficiary == a founder's ⇒ V4-unique-beneficiaries REDs.
#[test]
fn m6_counsel_beneficiary_equal_to_founder_reds_v4() {
    let (manifest, token, vesting) = fixtures();
    let mp: Manifest = toml::from_str(&manifest).unwrap();
    let founder_1 = mp.founder_schedule[0].beneficiary.clone();
    let counsel_b = mp.counsel_schedule[0].beneficiary.clone();
    let bad_manifest = manifest.replace(counsel_b.as_str(), founder_1.as_str());
    let bad_vesting = vesting.replace(counsel_b.as_str(), founder_1.as_str());
    assert_ne!(bad_manifest, manifest, "the manifest collision must bite");
    assert_ne!(bad_vesting, vesting, "the artifact collision must bite");
    let failing =
        failing_names(&run_gates_from_strs_with_record(&bad_manifest, &token, &bad_vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"V4-unique-beneficiaries".to_string()),
        "a counsel beneficiary equal to a founder must RED V4: {:?}",
        failing
    );
}

// M7 — any row's `vesting_policy` non-null ⇒ D6 still REDs. D6 was NOT amended by
//      D-4 V2 (the schedule went back on-canister, so nothing needed it); this
//      proves the rule the manifest header states is still enforced, on the very
//      row that once would have carried a policy string under withdrawn option (C).
#[test]
fn m7_non_null_vesting_policy_still_reds_d6() {
    let (manifest, token, vesting) = fixtures();
    // The counsel row is the only one carrying this role, so `replacen(.., 1)`
    // targets it unambiguously.
    let bad = manifest.replacen(
        "vesting_policy = \"null\"\nprincipal_role = \"LEGAL_COUNSEL_VESTING\"",
        "vesting_policy = \"cliff 0 + linear 12; administratively enforced\"\nprincipal_role = \"LEGAL_COUNSEL_VESTING\"",
        1,
    );
    assert_ne!(bad, manifest, "mutation must apply");
    let failing = failing_names(&run_gates_from_strs_with_record(&bad, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"D6-vesting-policy-null-all-rows".to_string()),
        "a non-null vesting_policy must still RED D6: {:?}",
        failing
    );
}

// ══ Bite proofs for the three checks Builder-3 ADDED beyond the brief's six ══
//
// SSA-2 accepted V7/V8/V9 in scope (SSA_LANDED_TASK60_SUBITEM3_RED_V1,
// 24f4be239891f7e9) but REDed the package because they shipped with pass-evidence
// only. The campaign rule that a drift lock must be PROVEN TO BITE applies to
// builder-added locks too — acceptance is not a bite proof. Both mutations below
// run on the S-1 surface (committed artifacts mutated in memory).

// M8 — the amount-trade hole that total-only V6 cannot see.
//
// Move 0.5e15 from a founder schedule into the counsel schedule, coherently in the
// manifest AND the vesting artifact, holding the COMBINED total at 12.5e15. V6
// compares only that total, so it still PASSES — which is precisely why the
// per-section checks exist. V7 and V8 must both RED by name.
#[test]
fn m8_section_amount_trade_reds_v7_and_v8_while_v6_passes() {
    let (manifest, token, vesting) = fixtures();

    // DRIFT-1: ONE founder schedule at 12e15 (a14beef1). founder: 12e15 -> 11.5e15 ;
    // counsel: 0.5e15 -> 1e15. The combined 12.5e15 is unchanged. The `total_`
    // prefix keeps both keys unique: `amount_base_units = 12000000000000000` is
    // shared by the insurance and founders ALLOCATION rows, but
    // `total_amount_base_units = 12000000000000000` is the founder schedule alone.
    let bad_manifest = manifest
        .replace("total_amount_base_units = 12000000000000000", "total_amount_base_units = 11500000000000000")
        .replace("total_amount_base_units = 500000000000000", "total_amount_base_units = 1000000000000000");
    let bad_vesting = vesting
        .replace("total_amount = 12_000_000_000_000_000 : nat;", "total_amount = 11_500_000_000_000_000 : nat;")
        .replace("total_amount = 500_000_000_000_000 : nat;", "total_amount = 1_000_000_000_000_000 : nat;");
    assert_ne!(bad_manifest, manifest, "manifest mutation must apply");
    assert_ne!(bad_vesting, vesting, "artifact mutation must apply");

    let checks = run_gates_from_strs_with_record(&bad_manifest, &token, &bad_vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);

    // The hole: the combined total still matches, so V6 is blind to the trade.
    assert!(
        !failing.contains(&"V6-schedule-sum-eq-custody-allocation".to_string()),
        "V6 must still PASS — if it fails, this mutation is not isolating the hole: {:?}",
        failing
    );
    // And the schedules still zip 1:1 with the manifest, so V5 is blind too.
    assert!(
        !failing.contains(&"V5-schedules-match-manifest".to_string()),
        "V5 must still PASS — both files moved together: {:?}",
        failing
    );

    // The two locks that DO see it:
    assert!(
        failing.contains(&"V7-founder-section-sum".to_string()),
        "V7 must RED: Σ(founder_schedule) is now 17.5e15 against an 18e15 allocation: {:?}",
        failing
    );
    assert!(
        failing.contains(&"V8-counsel-section-sum".to_string()),
        "V8 must RED: Σ(counsel_schedule) is now 1e15 against a 0.5e15 allocation: {:?}",
        failing
    );

    // Not vacuous: both pass at shipped values.
    let true_failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(!true_failing.contains(&"V7-founder-section-sum".to_string()));
    assert!(!true_failing.contains(&"V8-counsel-section-sum".to_string()));
}

// M9 — the counsel custodian binding.
//
// Re-point ONLY the token artifact's counsel recipient away from the vesting
// canister. `D11-row-4-legal_counsel` also REDs (artifact recipient no longer
// equals the manifest principal) — that is expected defence in depth and is
// asserted here rather than left to be discovered; V9 is the check that names the
// custodian relationship specifically.
#[test]
fn m9_counsel_recipient_off_the_vesting_canister_reds_v9() {
    let (manifest, token, vesting) = fixtures();
    let vc = token_row_recipient(&token, "legal_counsel");
    let elsewhere = outsider_principal(9); // valid, distinct, not the custodian

    // Only the counsel allocation record in the token artifact moves. The founders
    // record must keep the vesting canister, so V2 stays green and V9 is isolated.
    let counsel_rec = token
        .find("        category_id = \"legal_counsel\";")
        .expect("counsel allocation record in the artifact");
    let bad_token = format!(
        "{}{}",
        &token[..counsel_rec],
        token[counsel_rec..].replacen(vc.as_str(), elsewhere.as_str(), 1)
    );
    assert_ne!(bad_token, token, "mutation must apply");

    let failing = failing_names(&run_gates_from_strs_with_record(&manifest, &bad_token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(
        failing.contains(&"V9-counsel-recipient-is-vesting-canister".to_string()),
        "V9 must RED when the counsel row leaves the vesting canister: {:?}",
        failing
    );
    assert!(
        failing.contains(&"D11-row-4-legal_counsel".to_string()),
        "D11 is expected to RED too (artifact/manifest principal divergence): {:?}",
        failing
    );
    // The founders binding is untouched, proving the mutation was surgical.
    assert!(
        !failing.contains(&"V2-founders-recipient-is-vesting-canister".to_string()),
        "V2 must still PASS — only the counsel row moved: {:?}",
        failing
    );

    // Not vacuous: V9 passes at the shipped value.
    let true_failing = failing_names(&run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap());
    assert!(!true_failing.contains(&"V9-counsel-recipient-is-vesting-canister".to_string()));
}

// ── Literal-collision rule (genesis reallocation, a14beef1) ──────────────────
// After the Owner reallocation, `1200`/`12000000000000000` is shared by
// `founders` and `insurance`, and `500`/`5000000000000000` by
// `external_lp_incentives`, `airdrop` and `capital_reserve`. A bare
// `str::replace` on such a literal would silently move TWO or THREE rows and
// quietly change what the test proves. Every mutation below that touches a
// non-unique literal is re-anchored on the row's own `category_id` through
// these helpers, which assert the single-occurrence property they rely on.

/// Replace `old` with `new` ONLY inside the `[[allocation]]` row whose
/// `category_id` is `id`. Panics unless `old` occurs exactly once in that row.
fn replace_in_manifest_row(manifest: &str, id: &str, old: &str, new: &str) -> String {
    let anchor = format!("category_id = \"{id}\"\n");
    let start = manifest
        .find(&anchor)
        .unwrap_or_else(|| panic!("manifest row `{id}` not found"));
    let end = manifest[start..]
        .find("\n\n")
        .map(|o| start + o)
        .unwrap_or(manifest.len());
    let row = &manifest[start..end];
    assert_eq!(
        row.matches(old).count(),
        1,
        "`{old}` must occur exactly once inside manifest row `{id}` (row scope: {row})"
    );
    format!("{}{}{}", &manifest[..start], row.replace(old, new), &manifest[end..])
}

/// Replace `old` with `new` ONLY inside the token-init allocation record whose
/// `category_id` is `id`. Panics unless `old` occurs exactly once in it.
fn replace_in_token_record(token: &str, id: &str, old: &str, new: &str) -> String {
    let anchor = format!("category_id = \"{id}\";");
    let start = token
        .find(&anchor)
        .unwrap_or_else(|| panic!("token record `{id}` not found"));
    let end = start
        + token[start..]
            .find("      };")
            .unwrap_or_else(|| panic!("token record `{id}` does not close"));
    let rec = &token[start..end];
    assert_eq!(
        rec.matches(old).count(),
        1,
        "`{old}` must occur exactly once inside token record `{id}` (record scope: {rec})"
    );
    format!("{}{}{}", &token[..start], rec.replace(old, new), &token[end..])
}
