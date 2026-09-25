//! LANE A-2 (2026-09-09) — the E-6 closure evidence.
//!
//! Until this lane `APPROVED_ALLOCATIONS` was FIELD-IDENTICAL to
//! `deployment/mainnet/genesis_manifest.toml`, the artifact it exists to
//! certify. That is self-inherited verification: a check whose expected values
//! come from the thing it checks cannot fail, and Gate-D certified the V2-era
//! distribution GREEN for months (SSoT V8 A-2 / census E-6, HOLD-LAUNCH).
//!
//! Nothing in this file reads `APPROVED_ALLOCATIONS` for its expectations. The
//! expectations are a SECOND, INDEPENDENT transcription of the ruling documents
//! (`RULED_TABLE` below), typed from the office mount:
//!
//!   [D-0] CANONICAL/STSH_TOKENOMICS_V4_RULINGS_2026-07-28.md §D-0, lines 22-31
//!   [D-4] CANONICAL/STSH_TOKENOMICS_V4_ADDENDUM_D4_2026-07-29.md §D-4.1, :13/:18/:19
//!   [D-5] CANONICAL/STSH_TOKENOMICS_V4_ADDENDUM_D5_2026-07-31.md :15/:21/:22/:37
//!   [C/D/E] reviews/RULING_RECORD_LAUNCH_WEEK_2026-09-09.md Addenda C, D, E
//!   [D4V2]  reviews/OWNER_RULING_D4_LEGAL_COUNSEL_V2_2026-08-23.md §1
//!
//! Two independent transcriptions of the same ruling can only agree if both are
//! right; a constant re-copied from a drifted manifest disagrees with this file.

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

fn pre_a2_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pre_a2")
}

fn read(dir: &std::path::Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("{}: {}", dir.join(name).display(), e))
}

fn current() -> (String, String, String) {
    let d = deployment_dir();
    (
        read(&d, "genesis_manifest.toml"),
        read(&d, "stsh_token_init.did"),
        read(&d, "vesting_init.did"),
    )
}

/// The committed genesis inputs AS THEY STOOD at master 58d18e7, the last commit
/// before lane A-2 — the V2-era distribution the drifted constant certified.
/// Kept as committed bytes so the "old manifest must RED" claim is about the
/// real artifact, not a reconstruction of it.
fn pre_a2() -> (String, String, String) {
    let d = pre_a2_dir();
    (
        read(&d, "genesis_manifest.toml"),
        read(&d, "stsh_token_init.did"),
        read(&d, "vesting_init.did"),
    )
}

fn failing(checks: &[CheckResult]) -> Vec<String> {
    checks.iter().filter(|c| !c.pass).map(|c| c.name.clone()).collect()
}

fn run(m: &str, t: &str, v: &str) -> Vec<CheckResult> {
    run_gates_from_strs_with_record(m, t, v, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap()
}

// ═════════════════════════════════════════════════════════════════════════════
// The SECOND transcription. Order is the D-7 canonical order (Addendum C Q6).
// ═════════════════════════════════════════════════════════════════════════════

struct RuledRow {
    id: &'static str,
    name: &'static str,
    bps: u32,
    lock: &'static str,
    role: &'static str,
    /// The ruling section this row's share is read from.
    cite: &'static str,
}

const RULED_TABLE: [RuledRow; 11] = [
    RuledRow { id: "treasury", name: "Protocol Treasury", bps: 3000, lock: "GovernanceLocked", role: "TREASURY_MULTISIG", cite: "GR a14beef1 (27% -> 30%, +300 bps); identity from D-0 :22 + D-4 :13 + Addendum D (Owner)" },
    RuledRow { id: "insurance", name: "Security & Recovery Reserve", bps: 1200, lock: "GovernanceLocked", role: "INSURANCE_MULTISIG", cite: "D-0 :23 (12%)" },
    RuledRow { id: "founders", name: "founder", bps: 1200, lock: "Vested", role: "FOUNDERS_VESTING_CANISTER", cite: "GR a14beef1 (18% -> 12%, -600 bps); identity from D-0 :24" },
    RuledRow { id: "strategic_contributors_locked", name: "Strategic Contributors — unallocated", bps: 450, lock: "GovernanceLocked", role: "STRATEGIC_GRANTS_MULTISIG", cite: "D-0 :25 (5%) less D-4 :19 counsel 0.5% = 4.5%; split per Addendum C Q1" },
    RuledRow { id: "legal_counsel", name: "Strategic Contributors — legal counsel", bps: 50, lock: "Vested", role: "LEGAL_COUNSEL_VESTING", cite: "D-4 :18 (0.5%, bucket 4); Addendum C Q3 -> Addendum D" },
    RuledRow { id: "ceremony_rewards", name: "Ceremony Participants", bps: 200, lock: "GovernanceLocked", role: "CEREMONY_HOLDING", cite: "D-0 :26 (2%)" },
    RuledRow { id: "audit_bounty", name: "Security, Audit & Bounties", bps: 1000, lock: "GovernanceLocked", role: "BOUNTY_MULTISIG", cite: "D-0 :27 (10%)" },
    RuledRow { id: "airdrop", name: "Shield Adoption Incentives", bps: 500, lock: "GovernanceLocked", role: "AIRDROP_PROGRAM", cite: "D-0 :28 (5%); Addendum C Q2 (one row); E Q5 (id kept)" },
    RuledRow { id: "capital_reserve", name: "Capital & Contributor Reserve", bps: 500, lock: "GovernanceLocked", role: "CAPITAL_RESERVE_MULTISIG", cite: "D-0 :29 (5%)" },
    RuledRow { id: "liquidity", name: "Protocol-Owned Liquidity", bps: 1400, lock: "ImmediatelyLiquid", role: "LIQUIDITY_MULTISIG", cite: "GR a14beef1 (13% -> 14%, +100 bps); identity from D-0 :30, D-5 :21/:37" },
    RuledRow { id: "external_lp_incentives", name: "External LP Incentives", bps: 500, lock: "GovernanceLocked", role: "EXTERNAL_LP_INCENTIVES", cite: "GR a14beef1 (3% -> 5%, +200 bps); identity from D-0 :31" },
];

// ═════════════════════════════════════════════════════════════════════════════
// I-2 — the arithmetic that makes a typo detectable (SSA A-3(1))
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn i2_every_row_amount_equals_bps_times_unit_and_the_sums_close() {
    let mut bps_sum: u32 = 0;
    let mut amount_sum: u128 = 0;
    for row in APPROVED_ALLOCATIONS.iter() {
        assert_eq!(
            row.amount_base_units,
            row.percent_bps as u128 * BPS_UNIT,
            "I-2: {} amount {} != {} bps x 10^13",
            row.category_id, row.amount_base_units, row.percent_bps
        );
        bps_sum += row.percent_bps;
        amount_sum = amount_sum
            .checked_add(row.amount_base_units)
            .expect("I-1: the approved amounts must not overflow");
    }
    assert_eq!(bps_sum, 10_000, "I-2: Sigma bps");
    assert_eq!(amount_sum, TOTAL_SUPPLY_BASE_UNITS, "I-1: Sigma amounts == TOTAL_SUPPLY");
    // BPS_UNIT is itself derived, not asserted against a copy of itself.
    assert_eq!(BPS_UNIT * 10_000, TOTAL_SUPPLY_BASE_UNITS);
}

// ═════════════════════════════════════════════════════════════════════════════
// The SELF-INHERITANCE DETECTOR (brief §5 DRIFT-2(3) / §7.10)
// ═════════════════════════════════════════════════════════════════════════════

/// The detector. It takes a candidate approved table — the shipped constant, or
/// a counterfeit built by copying a manifest — and reports every way in which it
/// diverges from `RULED_TABLE` and from the I-2 arithmetic.
///
/// This is deliberately NOT "constant != manifest": that predicate is satisfied
/// by any typo, and is FALSE for a correct constant (a correct constant and a
/// correct manifest agree, and must). What makes the constant independent is
/// that its values are anchored to a source the manifest cannot reach — so a
/// constant produced by copying ANY manifest other than the ruled one is caught
/// here, which is exactly the pre-A-2 state.
fn detect(candidate: &[(String, String, u128, u32, String, String)]) -> Vec<String> {
    let mut defects = Vec::new();
    if candidate.len() != RULED_TABLE.len() {
        defects.push(format!(
            "row count {} != ruled {}",
            candidate.len(),
            RULED_TABLE.len()
        ));
        return defects;
    }
    for (i, ruled) in RULED_TABLE.iter().enumerate() {
        let (id, name, amount, bps, lock, role) = &candidate[i];
        if id != ruled.id {
            defects.push(format!("row {i}: category_id {id:?} != ruled {:?} [{}]", ruled.id, ruled.cite));
        }
        if name != ruled.name {
            defects.push(format!("row {i} {id}: category_name {name:?} != ruled {:?}", ruled.name));
        }
        if *bps != ruled.bps {
            defects.push(format!("row {i} {id}: percent_bps {bps} != ruled {} [{}]", ruled.bps, ruled.cite));
        }
        if *amount != ruled.bps as u128 * BPS_UNIT {
            defects.push(format!(
                "row {i} {id}: amount {amount} != ruled {} bps x 10^13 = {} [{}]",
                ruled.bps, ruled.bps as u128 * BPS_UNIT, ruled.cite
            ));
        }
        if lock != ruled.lock {
            defects.push(format!("row {i} {id}: lock_policy {lock:?} != ruled {:?}", ruled.lock));
        }
        if role != ruled.role {
            defects.push(format!("row {i} {id}: principal_role {role:?} != ruled {:?}", ruled.role));
        }
    }
    defects
}

fn approved_as_candidate() -> Vec<(String, String, u128, u32, String, String)> {
    APPROVED_ALLOCATIONS
        .iter()
        .map(|r| {
            (
                r.category_id.to_string(),
                r.category_name.to_string(),
                r.amount_base_units,
                r.percent_bps,
                r.lock_policy.to_string(),
                r.principal_role.to_string(),
            )
        })
        .collect()
}

/// A counterfeit constant built the way the pre-A-2 one was: by copying a
/// manifest's own allocation table into the approved schema.
fn constant_copied_from(manifest_toml: &str) -> Vec<(String, String, u128, u32, String, String)> {
    #[derive(serde::Deserialize)]
    struct Row {
        category_id: String,
        category_name: String,
        // u64 because the `toml` crate does not deserialize u128; 10^17 fits.
        amount_base_units: u64,
        percent_bps: u32,
        lock_policy: String,
        principal_role: String,
    }
    #[derive(serde::Deserialize)]
    struct Doc {
        allocation: Vec<Row>,
    }
    let doc: Doc = toml::from_str(manifest_toml).expect("manifest parses");
    doc.allocation
        .into_iter()
        .map(|r| {
            (
                r.category_id,
                r.category_name,
                r.amount_base_units as u128,
                r.percent_bps,
                r.lock_policy,
                r.principal_role,
            )
        })
        .collect()
}

/// BOTH DIRECTIONS, in one test (brief §7.10).
#[test]
fn self_inheritance_detector_passes_the_rulings_constant_and_reds_a_copied_one() {
    // GREEN: the shipped constant, re-typed from the rulings this lane.
    let defects = detect(&approved_as_candidate());
    assert!(
        defects.is_empty(),
        "APPROVED_ALLOCATIONS must equal the independently transcribed ruled table. \
         If this is RED, do NOT edit RULED_TABLE to match — re-read the cited ruling \
         section and fix whichever side is wrong. Defects: {:#?}",
        defects
    );

    // RED: a constant copied from the PRE-A-2 committed manifest — the exact
    // artefact of the E-6 defect. Every drifted bucket must be named.
    let (old_m, _, _) = pre_a2();
    let copied_old = detect(&constant_copied_from(&old_m));
    assert!(
        !copied_old.is_empty(),
        "a constant copied from the pre-A-2 manifest MUST be rejected by the detector"
    );
    for expect in [
        "treasury", "insurance", "audit_bounty", "liquidity",
        "strategic_contributors_locked", "capital_reserve", "external_lp_incentives",
    ] {
        assert!(
            copied_old.iter().any(|d| d.contains(expect)),
            "the detector must NAME the {expect} divergence: {:#?}",
            copied_old
        );
    }

    // RED: a constant copied from a mutated CURRENT manifest. This is the limb
    // that proves independence rather than mere disagreement — the shipped
    // constant does not follow the manifest wherever it goes.
    let (m, _, _) = current();
    // Literal-collision rule (a14beef1): `amount_base_units = 12000000000000000`
    // and `percent_bps = 1200` are now carried by BOTH `insurance` and `founders`
    // (and `amount_base_units = 12000000000000000` is also a suffix of the founder
    // schedule's `total_amount_base_units` line), so the insurance leg is anchored
    // on its own row. The drift stays Sigma-preserving: treasury -50 bps,
    // insurance +50 bps.
    let drifted = replace_in_manifest_row(&m, "treasury", "amount_base_units = 30000000000000000", "amount_base_units = 29500000000000000");
    let drifted = replace_in_manifest_row(&drifted, "treasury", "percent_bps = 3000", "percent_bps = 2950");
    let drifted = replace_in_manifest_row(&drifted, "insurance", "amount_base_units = 12000000000000000", "amount_base_units = 12500000000000000");
    let drifted = replace_in_manifest_row(&drifted, "insurance", "percent_bps = 1200", "percent_bps = 1250");
    assert_ne!(drifted, m, "the drift mutation must apply");
    let copied_drift = detect(&constant_copied_from(&drifted));
    assert!(
        copied_drift.iter().any(|d| d.contains("treasury"))
            && copied_drift.iter().any(|d| d.contains("insurance")),
        "a coherent (Sigma-preserving) manifest drift copied into the constant must be \
         caught on both moved rows: {:#?}",
        copied_drift
    );
    // ...and the drift really was coherent, so no sum check could have seen it.
    let (_, t, v) = current();
    let drift_failing = failing(&run(&drifted, &t, &v));
    assert!(!drift_failing.contains(&"D2-manifest-sum-checked".to_string()));
    assert!(!drift_failing.contains(&"D3-percent-sum".to_string()));
}

// ═════════════════════════════════════════════════════════════════════════════
// MUTATION EVIDENCE — brief §7.9: the re-typed constant REDs the OLD manifest
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn the_pre_a2_committed_manifest_reds_the_retyped_constant_and_the_new_one_passes() {
    let (old_m, old_t, old_v) = pre_a2();
    let old_failing = failing(&run(&old_m, &old_t, &old_v));

    // The V2-era table is INTERNALLY COHERENT — it sums to 10,000 bps and 10^17
    // base units, which is precisely why nothing caught it for months.
    assert!(
        !old_failing.contains(&"D2-manifest-sum-checked".to_string())
            && !old_failing.contains(&"D3-percent-sum".to_string())
            && !old_failing.contains(&"D12-artifact-sum-checked".to_string()),
        "the old table must still be internally coherent — otherwise this test is \
         proving an arithmetic accident, not the pin: {:?}",
        old_failing
    );

    // The re-typed pin is what sees it. Every row that moved must RED by name.
    for name in [
        "DP1-row-0-treasury",
        "DP1-row-1-insurance",
        "DP1-row-3-strategic_contributors_locked",
        "DP1-row-4-legal_counsel",
        "DP1-row-6-audit_bounty",
        "DP1-row-8-capital_reserve",
        "DP1-row-9-liquidity",
        "DP1-row-10-external_lp_incentives",
    ] {
        assert!(
            old_failing.contains(&name.to_string()),
            "the pre-A-2 manifest must RED {name} against the re-typed constant: {:?}",
            old_failing
        );
    }

    // PASSING direction: none of those names fails on the rebuilt artifacts.
    let (m, t, v) = current();
    let new_failing = failing(&run(&m, &t, &v));
    assert!(
        !new_failing.iter().any(|n| n.starts_with("DP1-row-")),
        "no DP1 row may fail on the rebuilt artifacts: {:?}",
        new_failing
    );
    assert!(!new_failing.contains(&"DP0-approved-row-count".to_string()));
}

// ═════════════════════════════════════════════════════════════════════════════
// MUTATION EVIDENCE — brief §7.8: the POSITIONAL re-base is load-bearing
// ═════════════════════════════════════════════════════════════════════════════

/// Swap two ADJACENT allocation rows, values untouched, in BOTH the manifest and
/// the token artifact. Every aggregate is unchanged and the two files still
/// agree with each other, so only the positional pin can see it. D-7 re-based
/// that order once; without this mutation the re-base is unproven.
#[test]
fn d7_transposed_adjacent_rows_red_dp1() {
    let (m, t, v) = current();

    // Rows 8 (capital_reserve) and 9 (liquidity): different ids, names, bps and
    // lock policies, so a transposition is visible on several fields at once.
    let swap_toml = |s: &str| -> String {
        let a = s.find("[[allocation]]\n# NEW ROW. D-0 bucket 8").expect("capital_reserve row");
        let b = s.find("[[allocation]]\n# D-0 bucket 9").expect("liquidity row");
        let c = s.find("[[allocation]]\n# NEW ROW. D-0 bucket 10").expect("external_lp row");
        assert!(a < b && b < c, "rows must be in canonical order");
        format!("{}{}{}{}", &s[..a], &s[b..c], &s[a..b], &s[c..])
    };
    let swap_did = |s: &str| -> String {
        let a = s.find("      // NEW. V4 D-0 bucket 8").expect("capital_reserve record");
        let b = s.find("      // V4 D-0 bucket 9").expect("liquidity record");
        let c = s.find("      // NEW. V4 D-0 bucket 10").expect("external_lp record");
        assert!(a < b && b < c);
        format!("{}{}{}{}", &s[..a], &s[b..c], &s[a..b], &s[c..])
    };
    let bad_m = swap_toml(&m);
    let bad_t = swap_did(&t);
    assert_ne!(bad_m, m, "manifest transposition must apply");
    assert_ne!(bad_t, t, "artifact transposition must apply");

    let f = failing(&run(&bad_m, &bad_t, &v));

    // Blind: every aggregate, and the manifest<->artifact agreement.
    for blind in [
        "D2-manifest-sum-checked",
        "D12-artifact-sum-checked",
        "D3-percent-sum",
        "DP0-approved-row-count",
        "D10-artifact-row-count",
    ] {
        assert!(
            !f.contains(&blind.to_string()),
            "{blind} must still PASS — if it fails, the mutation is not isolating position: {:?}",
            f
        );
    }
    assert!(
        !f.iter().any(|n| n.starts_with("D11-row-")),
        "D11 (artifact vs manifest) must still PASS — both files moved together: {:?}",
        f
    );

    // Seeing: the positional pin, on both transposed indices.
    assert!(
        f.contains(&"DP1-row-8-capital_reserve".to_string())
            && f.contains(&"DP1-row-9-liquidity".to_string()),
        "DP1 must RED on both transposed positions: {:?}",
        f
    );

    // Not vacuous: green again when reverted.
    let reverted = failing(&run(&m, &t, &v));
    assert!(!reverted.iter().any(|n| n.starts_with("DP1-row-")));
}

/// The schedule list is ALSO positional (V5 is a 1:1 zip over
/// `founder_schedule ++ counsel_schedule`). Transposing the vesting artifact's
/// two schedule records leaves both sums and both shapes present in the file and
/// is seen only by the positional bind.
#[test]
fn d7_transposed_schedule_records_red_v5() {
    let (m, t, v) = current();
    let a = v.find("      // Founder (single, Owner)").expect("founder record");
    let b = v.find("      // D-4 V2 — legal-counsel grant").expect("counsel record");
    let end = v.find("    };\n  },").expect("schedule vec closes");
    assert!(a < b && b < end);
    let bad_v = format!("{}{}{}{}", &v[..a], &v[b..end], &v[a..b], &v[end..]);
    assert_ne!(bad_v, v, "schedule transposition must apply");

    let f = failing(&run(&m, &t, &bad_v));
    assert!(
        f.contains(&"V5-schedules-match-manifest".to_string()),
        "V5 must RED on a transposed schedule list: {:?}",
        f
    );
    // Blind: the combined custody total is unchanged, so V6 cannot see it.
    assert!(
        !f.contains(&"V6-schedule-sum-eq-custody-allocation".to_string()),
        "V6 must still PASS — the combined total did not move: {:?}",
        f
    );

    // Not vacuous.
    let reverted = failing(&run(&m, &t, &v));
    assert!(!reverted.contains(&"V5-schedules-match-manifest".to_string()));
}

// ═════════════════════════════════════════════════════════════════════════════
// DRIFT-1 / counsel shape / I-10 — the ruled schedule facts, asserted directly
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn drift1_exactly_one_founder_schedule_and_two_vesting_records() {
    let (m, _, v) = current();
    let manifest: Manifest = toml::from_str(&m).unwrap();
    assert_eq!(
        manifest.founder_schedule.len(),
        1,
        "D-0 :24 is \"Founder (single, Owner)\" — exactly one founder schedule"
    );
    assert_eq!(manifest.counsel_schedule.len(), 1, "D-4 :18 is a single counsel grant");
    assert_eq!(
        v.matches("beneficiary = principal").count(),
        2,
        "vesting_init.did must carry exactly two schedule records: founder + counsel"
    );
    // I-5 / I-4: each section sums to its own allocation row.
    let founders: u128 = manifest.founder_schedule.iter().map(|r| r.total_amount_base_units as u128).sum();
    let counsel: u128 = manifest.counsel_schedule.iter().map(|r| r.total_amount_base_units as u128).sum();
    assert_eq!(founders, 1200 * BPS_UNIT, "Sigma(founder) == the 12% founders row (a14beef1)");
    assert_eq!(counsel, 50 * BPS_UNIT, "Sigma(counsel) == the 0.5% legal_counsel row");
}

#[test]
fn counsel_shape_is_cliff_0_linear_12_and_founder_is_6_30() {
    // D-4 V2 §1 (OPERATIVE); Addendum E Q1 STRIKES Addendum C's 50/25/25.
    assert_eq!(APPROVED_COUNSEL_CLIFF_MONTHS, 0);
    assert_eq!(APPROVED_COUNSEL_LINEAR_MONTHS, 12);
    // D-0 :24 "6mo cliff + 30mo linear, m36" (§0.4 Option A, LOCKED).
    assert_eq!(APPROVED_FOUNDER_CLIFF_MONTHS, 6);
    assert_eq!(APPROVED_FOUNDER_LINEAR_MONTHS, 30);
}

#[test]
fn i10_exactly_one_immediately_liquid_row_and_it_is_bucket_9() {
    let liquid: Vec<&str> = APPROVED_ALLOCATIONS
        .iter()
        .filter(|r| r.lock_policy == "ImmediatelyLiquid")
        .map(|r| r.category_id)
        .collect();
    assert_eq!(
        liquid,
        vec!["liquidity"],
        "I-10: bucket 9 is the ONLY ImmediatelyLiquid row. The K-5 \"3%\" is D-5's \
         day-one deploy OUT of this bucket (Addendum D), never a second liquid row."
    );
    // D-5 :15: the day-one deploy is 30,000,000 STSH = 3% of Sigma, and it must fit
    // inside bucket 9 rather than beside it.
    let bucket9 = APPROVED_ALLOCATIONS.iter().find(|r| r.category_id == "liquidity").unwrap();
    assert!(300 * BPS_UNIT < bucket9.amount_base_units);
}

/// I-9 / D-6 naming law: surviving ids and roles are immutable, and the ONLY
/// permitted principal collision is the enumerated founders/counsel pair.
#[test]
fn surviving_ids_and_roles_are_immutable_and_roles_are_distinct() {
    for id in [
        "treasury", "insurance", "founders", "legal_counsel", "ceremony_rewards",
        "audit_bounty", "airdrop", "liquidity",
    ] {
        assert!(
            APPROVED_ALLOCATIONS.iter().any(|r| r.category_id == id),
            "surviving category_id {id:?} must not be renamed (Addendum E Q5). \
             `founders` in particular: FOUNDERS_CATEGORY_ID resolves Gate-V through it, \
             so renaming it is a silent Gate-V miss, not a loud RED."
        );
    }
    assert_eq!(FOUNDERS_CATEGORY_ID, "founders");
    assert_eq!(COUNSEL_CATEGORY_ID, "legal_counsel");

    let mut roles: Vec<&str> = APPROVED_ALLOCATIONS.iter().map(|r| r.principal_role).collect();
    let n = roles.len();
    roles.sort_unstable();
    roles.dedup();
    assert_eq!(roles.len(), n, "I-9: every principal_role must be distinct");

    // Retired by this lane — none may reappear.
    for retired in ["dev", "zk_advisors", "shielded_incentives"] {
        assert!(
            !APPROVED_ALLOCATIONS.iter().any(|r| r.category_id == retired),
            "{retired:?} has no counterpart in the V4 D-0 table (SSoT V8 K-23 / Addendum C Q2)"
        );
    }
}

/// The `expected_fixed_sites` derivation, SHOWN rather than tuned until green
/// (brief §7.11). The literal in `src/lib.rs` is
/// `APPROVED_ALLOCATIONS.len() * 2 + 3 + 3 + 3 + 2`; the trailing literals are
/// init-field site counts and are untouched by DRIFT-1, because schedule sites
/// are input-variable and excluded from the fixed cardinality.
#[test]
fn expected_fixed_sites_derivation_is_33_and_the_gate_agrees() {
    let manifest_alloc = APPROVED_ALLOCATIONS.len();     // 11
    let artifact_alloc = APPROVED_ALLOCATIONS.len();     // 11
    let manifest_token_init = 3;    // treasury, staking_canister, fee_collector
    let manifest_vesting_init = 3;  // token_canister, controller, founders_vesting_canister
    let artifact_token = 3;         // treasury, staking_canister, fee_collector
    let artifact_vesting = 2;       // token_canister, controller
    let derived = manifest_alloc + artifact_alloc + manifest_token_init
        + manifest_vesting_init + artifact_token + artifact_vesting;
    assert_eq!(derived, 33);

    let (m, t, v) = current();
    let coverage = run(&m, &t, &v)
        .into_iter()
        .find(|c| c.name == "DP3-scan-coverage")
        .expect("DP3-scan-coverage must run");
    assert!(coverage.pass, "coverage must pass at the rebuilt shape: {}", coverage.detail);
    assert!(
        coverage.detail.contains(&format!("cardinality={}", derived)),
        "the gate's own cardinality must equal the derivation: {}",
        coverage.detail
    );
}

/// Replace `old` with `new` ONLY inside the `[[allocation]]` row whose
/// `category_id` is `id` (literal-collision rule, genesis reallocation
/// a14beef1: `1200`/`12000000000000000` is shared by `founders` and
/// `insurance`, `500`/`5000000000000000` by three rows). Panics unless `old`
/// occurs exactly once in that row, so a mutation can never silently move two.
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
