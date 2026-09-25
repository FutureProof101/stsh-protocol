//! P-ARITH G-1/G-2 — Gate-D + Gate-V genesis verification
//! (BRIEF_GTM_ARITHMETIC_HARDENING.md V1.5 §1.5/§1.6).
//!
//! Gate-D consumes the EXACT canonical Candid init artifacts the deploy
//! consumes (`deployment/mainnet/stsh_token_init.did` / `vesting_init.did` —
//! single source, never reconstructed args), records their SHA-256, and
//! verifies EVERY field against the approved manifest
//! (`deployment/mainnet/genesis_manifest.toml`): category ids/names/amounts,
//! checked sum == TOTAL_SUPPLY, custody/lock/vesting policy per bucket, the
//! canonical `subaccount = null` form, principal roles, and the top-level
//! token/vesting init fields.
//!
//! Gate-V is two-phase (FOUNDERS ONLY at genesis):
//!   phase 1 (pre-install):  token `founders` recipient == the vesting-canister
//!                           principal AND Σ(founder schedules) == the founders
//!                           allocation amount — both CHECKED arithmetic.
//!   phase 2 (post-install): token balance of the vesting canister AND the
//!                           installed schedule sum both still equal that
//!                           amount (`gate_v_post_install`, pure — fed by live
//!                           queries at genesis; fixture-proven in CI).
//!
//! Every check FAILS CLOSED: any mismatch is a named failing check and the
//! CLI exits nonzero. All sums are checked adds — this tool must never wrap.

use candid::types::value::{IDLArgs, IDLValue};
use candid::Principal;
use num_traits::cast::ToPrimitive;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const TOTAL_SUPPLY_BASE_UNITS: u128 = 100_000_000_000_000_000; // 10^17

// ── APPROVED §0.3 SCHEMA — HARDCODED (SSA P1 correction) ─────────────────────
// Gate-D pins the APPROVED RULING itself, not the mutable manifest file: a
// coherent edit to manifest + artifact together (renamed roles, redistributed
// percentages, drifted amounts/names/policies) must FAIL. Only the actual
// P0-3 PRINCIPAL VALUES are replaceable at RR-1 — every other row field is
// fixed here and may change only through a new SSA-approved brief revision.

pub struct ApprovedRow {
    pub category_id: &'static str,
    pub category_name: &'static str,
    pub amount_base_units: u128,
    /// Row share in BASIS POINTS (see D3-percent-sum). Audit metadata only —
    /// it reaches no artifact and no canister; `amount_base_units` mints.
    pub percent_bps: u32,
    pub lock_policy: &'static str,
    pub vesting_policy: &'static str,
    pub principal_role: &'static str,
}

/// One basis point of Σ, in base units: 10^17 / 10_000. Every ruled row is a
/// whole number of basis points, so `amount_base_units == percent_bps * BPS_UNIT`
/// on every row — asserted by `i2_every_row_amount_equals_bps_times_unit`.
pub const BPS_UNIT: u128 = 10_000_000_000_000;

// ═════════════════════════════════════════════════════════════════════════════
// RE-TYPED FROM THE RULINGS, 2026-09-09 (lane A-2, Owner ruling C-15 = GO).
//
// READ THIS BEFORE TOUCHING A LITERAL BELOW.
//
// Until this lane, every row here was FIELD-IDENTICAL to
// `deployment/mainnet/genesis_manifest.toml` — the artifact this constant is
// supposed to certify. That is self-inherited verification: a check that draws
// its expected values from the thing it checks cannot fail, and Gate-D
// certified the V2-era distribution GREEN for months (SSoT V8 A-2 / census E-6,
// HOLD-LAUNCH).
//
// The eleven rows below were TRANSCRIBED FROM THE RULING DOCUMENTS, cited
// per row. Office mount:
//   [D-0] CANONICAL/STSH_TOKENOMICS_V4_RULINGS_2026-07-28.md §D-0, table lines 22-31
//   [D-4] CANONICAL/STSH_TOKENOMICS_V4_ADDENDUM_D4_2026-07-29.md §D-4.1, lines 13/18/19
//   [D-5] CANONICAL/STSH_TOKENOMICS_V4_ADDENDUM_D5_2026-07-31.md, lines 15/21/22/37
//   [C/D/E] reviews/RULING_RECORD_LAUNCH_WEEK_2026-09-09.md Addenda C, D, E
//   [D4V2]  reviews/OWNER_RULING_D4_LEGAL_COUNSEL_V2_2026-08-23.md §1 (OPERATIVE)
//   [GR]    reviews/RULING_RECORD_GENESIS_REALLOCATION_2026-09-12.md (sha256 a14beef1…),
//           Owner, 2026-09-12 — AMENDS the V4 D-0 table: founders 18% -> 12% (-600 bps),
//           treasury 27 -> 30 (+300), liquidity 13 -> 14 (+100), external LP incentives
//           3 -> 5 (+200). Every other row unchanged; Σ stays 10,000 bps. Where [GR]
//           and [D-0] disagree on a row size, [GR] is the operative ruling and [D-0]
//           is retained only as the provenance of the row's identity and shape.
//
// IF Gate-D GOES RED, THE MANIFEST IS WRONG. Never "fix" a RED by copying the
// manifest's values back into this table — that re-creates the exact defect
// lane A-2 closed. Change a literal here only by re-reading its cited ruling.
//
// ROW ORDER IS A CONTRACT (Addendum C Q6 / D-7): DP1 zips this array
// positionally against the manifest and the token artifact.
// `d0_transposed_row_reds_dp1` proves the order is load-bearing.
// ═════════════════════════════════════════════════════════════════════════════
pub const APPROVED_ALLOCATIONS: [ApprovedRow; 11] = [
    // 1 — [GR] "TREASURY_MULTISIG | 2700 -> 3000 | +300" = 30 | 300,000,000.
    //     Supersedes [D-0 :22] "Protocol Treasury | 27 | 270,000,000" and
    //     [Addendum D, Owner] "tresury stay @ 27%" on SIZE only; identity, id and
    //     role are unchanged, and the counsel grant remains bucket-4 funded.
    ApprovedRow { category_id: "treasury", category_name: "Protocol Treasury", amount_base_units: 30_000_000_000_000_000, percent_bps: 3000, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "TREASURY_MULTISIG" },
    // 2 — [D-0 :23] "Security & Recovery Reserve | 12 | 120,000,000".
    //     Surviving id/role kept verbatim [Addendum E Q5]; name relabel only.
    ApprovedRow { category_id: "insurance", category_name: "Security & Recovery Reserve", amount_base_units: 12_000_000_000_000_000, percent_bps: 1200, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "INSURANCE_MULTISIG" },
    // 3 — [GR] "Founder (single, Owner) | 1800 -> 1200 | -600" = 12 | 120,000,000,
    //     shape unchanged (6mo cliff + 30mo linear, m36). Supersedes [D-0 :24]
    //     "Founder (single, Owner) | 18 | 180,000,000" on SIZE only. `founders` is
    //     load-bearing: FOUNDERS_CATEGORY_ID resolves Gate-V through it [Addendum E Q5].
    ApprovedRow { category_id: "founders", category_name: "founder", amount_base_units: 12_000_000_000_000_000, percent_bps: 1200, lock_policy: "Vested", vesting_policy: "null", principal_role: "FOUNDERS_VESTING_CANISTER" },
    // 4 — NEW ROW. [D-0 :25] bucket 4 "Strategic Contributors (service grants) | 5",
    //     split by [D-4 :19] "0.5% allocated (legal counsel) · 4.5% unallocated,
    //     multisig-locked". Split ruled by [Addendum C Q1]. This row is the 4.5%.
    ApprovedRow { category_id: "strategic_contributors_locked", category_name: "Strategic Contributors — unallocated", amount_base_units: 4_500_000_000_000_000, percent_bps: 450, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "STRATEGIC_GRANTS_MULTISIG" },
    // 5 — [D-4 :18] "NEW GRANT: Legal Counsel — 0.5% (5,000,000 STSH)", bucket 4.
    //     Parentage bucket 4 confirmed by [Addendum C Q3] -> [Addendum D, Owner].
    //     Shape cliff 0 / linear 12 per [D4V2 §1], restated [Addendum E Q1]
    //     (Addendum C's 50/25/25 is STRUCK) — see APPROVED_COUNSEL_* below.
    ApprovedRow { category_id: "legal_counsel", category_name: "Strategic Contributors — legal counsel", amount_base_units: 500_000_000_000_000, percent_bps: 50, lock_policy: "Vested", vesting_policy: "null", principal_role: "LEGAL_COUNSEL_VESTING" },
    // 6 — [D-0 :26] "Ceremony Participants | 2 | 20,000,000".
    ApprovedRow { category_id: "ceremony_rewards", category_name: "Ceremony Participants", amount_base_units: 2_000_000_000_000_000, percent_bps: 200, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "CEREMONY_HOLDING" },
    // 7 — [D-0 :27] "Security, Audit & Bounties | 10 | 100,000,000". Was 8% here.
    ApprovedRow { category_id: "audit_bounty", category_name: "Security, Audit & Bounties", amount_base_units: 10_000_000_000_000_000, percent_bps: 1000, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "BOUNTY_MULTISIG" },
    // 8 — [D-0 :28] "Shield Adoption Incentives | 5 | 50,000,000 | Unchanged
    //     (retroactive, public-shield-fee-volume-weighted)". [Addendum C Q2]:
    //     ONE incentives row at 5%; the 8% `shielded_incentives` row is deleted
    //     and role INCENTIVES_EMISSION retires. Surviving id `airdrop` [E Q5].
    ApprovedRow { category_id: "airdrop", category_name: "Shield Adoption Incentives", amount_base_units: 5_000_000_000_000_000, percent_bps: 500, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "AIRDROP_PROGRAM" },
    // 9 — NEW ROW. [D-0 :29] "Capital & Contributor Reserve | 5 | 50,000,000 |
    //     NEW (replaces Genesis Capital). Released ONLY by treasury multisig ->
    //     DAO named proposal."
    ApprovedRow { category_id: "capital_reserve", category_name: "Capital & Contributor Reserve", amount_base_units: 5_000_000_000_000_000, percent_bps: 500, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "CAPITAL_RESERVE_MULTISIG" },
    // 10 — [GR] "LIQUIDITY_MULTISIG | 1300 -> 1400 | +100" = 14 | 140,000,000.
    //     Supersedes [D-0 :30] "Protocol-Owned Liquidity | 13 | 130,000,000" and
    //     [D-5 :21] "Stands: ... bucket 9 size (13% / 130M)"; [D-5 :37] "NO bucket change;
    //     POL treasury simply deploys less at genesis". The day-one 3% / 30M
    //     deploy [D-5 :15] IS the K-5 "3%" [Addendum D] — a deploy from this
    //     bucket, never a separate row. Only ImmediatelyLiquid row (I-10).
    ApprovedRow { category_id: "liquidity", category_name: "Protocol-Owned Liquidity", amount_base_units: 14_000_000_000_000_000, percent_bps: 1400, lock_policy: "ImmediatelyLiquid", vesting_policy: "null", principal_role: "LIQUIDITY_MULTISIG" },
    // 11 — NEW ROW. [GR] "EXTERNAL_LP_INCENTIVES | 300 -> 500 | +200" = 5 | 50,000,000.
    //     Supersedes [D-0 :31] "External LP Incentives | 3 | 30,000,000" on SIZE only;
    //     "V3 R-7 stands (30/90/180d tiers, 180d step-down)" is unchanged.
    ApprovedRow { category_id: "external_lp_incentives", category_name: "External LP Incentives", amount_base_units: 5_000_000_000_000_000, percent_bps: 500, lock_policy: "GovernanceLocked", vesting_policy: "null", principal_role: "EXTERNAL_LP_INCENTIVES" },
];

/// §0.4 Option A, LOCKED: every founder schedule is cliff 6 / linear 30.
pub const APPROVED_FOUNDER_CLIFF_MONTHS: u32 = 6;
pub const APPROVED_FOUNDER_LINEAR_MONTHS: u32 = 30;

/// D-4 V2 (OWNER_RULING_D4_LEGAL_COUNSEL_V2): the counsel grant is a straight
/// 12-month continuous release with NO cliff. Pinned separately from the founders
/// shape and of the same hardcoded-ruling character — `V3` is per-schedule since
/// this ruling, never one global pair.
pub const APPROVED_COUNSEL_CLIFF_MONTHS: u32 = 0;
pub const APPROVED_COUNSEL_LINEAR_MONTHS: u32 = 12;

/// The category whose allocation the counsel schedule must sum to.
pub const COUNSEL_CATEGORY_ID: &str = "legal_counsel";
pub const FOUNDERS_CATEGORY_ID: &str = "founders";

/// sha256 of the M5 single-participant DEV verifying key
/// (`circuits/verification_key.json` **as it stood at the M5 base pin** — NOT the
/// contents of that file today). Named here so Gate-D can REFUSE it in
/// `pool_init.vk_hash` — the manifest-side counterpart of the pool's own
/// `DENY_VK_HASH` init trap. Refusing one known-bad value is not provenance: any
/// other hash passes this check.
///
/// **THE NAME IS HISTORICAL AND THE VALUE IS DELIBERATELY FROZEN. DO NOT MOVE IT.**
/// This is a deny-list entry, not a pin: its whole job is to keep matching the
/// superseded M5 dev key so that key can never be installed again. "Updating" it
/// to the current VK would make the deny-list stop denying — it would refuse the
/// key we intend to ship and admit the one we intend to bar. The launch VK is a
/// different value entirely (`84dba305…c6914`, mainnet-v2 ceremony, lane A-4,
/// 2026-09-12; see `MAINNET_DEPLOYMENT.md` and `docs/ceremony/CEREMONY_RECORD_v3.md`)
/// and is deliberately not named in this crate. Ruled a DO-NOT-MOVE residual; see
/// `docs/DOC_STALENESS_REGISTER.md` §2 and `docs/ceremony/CEREMONY_RECORD_v3.md`
/// §§ at :417, :465, :667.
pub const DEV_VK_HASH_HEX: &str =
    "fc73ca4dcdcfd5a2eb0dd6165c5cf2b1e039c3acdad2d360258c5d42ba530dc8";

/// The only proof system the pool ships with.
pub const EXPECTED_PROOF_SYSTEM: &str = "groth16-bn254";

// ── Manifest (TOML) ───────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
pub struct Manifest {
    pub schema_version: u32,
    pub token: TokenMeta,
    pub token_init: TokenInitManifest,
    pub vesting_init: VestingInitManifest,
    pub allocation: Vec<AllocationRow>,
    pub founder_schedule: Vec<FounderScheduleRow>,
    /// D-4 V2: the legal-counsel schedule. A SEPARATE section on purpose — this
    /// beneficiary is not a founder and must not be filed under a founders label.
    /// `#[serde(default)]` is deliberately NOT set: the section is required, so a
    /// manifest that drops it fails CLOSED at parse rather than silently losing
    /// the grant's schedule.
    pub counsel_schedule: Vec<ScheduleRow>,
    /// W-VKGATE (AR1-05 / C-27): the POOL's init trust roots. Before this
    /// section Gate-D verified the token's and vesting's trust roots
    /// field-by-field and the pool's not at all — the pool's verifying-key pin,
    /// the root of its entire soundness story, was verified by nothing.
    /// `#[serde(default)]` is deliberately NOT set (the `counsel_schedule`
    /// precedent): a manifest that drops the section fails CLOSED at parse
    /// rather than silently losing the pool's trust root.
    pub pool_init: PoolInitManifest,
}

/// The pool's init trust roots, verified field-by-field by the `DPOOL-*` series.
///
/// SCOPE, so no reader infers more (HARNESS_DELTA §2): this section binds what
/// the INSTALLER passes to the pool. It does not reach the verifier canister's
/// embedded verifying key (`include_str!`-compiled into canisters/verifier),
/// and it does not prove the pinned hash was ceremony-produced — it refuses one
/// named known-bad value and requires a bound ceremony record to exist.
#[derive(Deserialize, Debug, Clone)]
pub struct PoolInitManifest {
    /// sha256 of the launch verifying key, lowercase hex, 64 chars.
    /// P0-3 PLACEHOLDER until the A6.7 re-ceremony produces the real key;
    /// RR-1 replaces it. A placeholder is not a pin, and the package says so.
    pub vk_hash: String,
    pub proof_system: String,
    /// Repo-relative path to the committed ceremony record this hash binds to.
    pub ceremony_record: String,
    pub token_canister: String,
    pub treasury_canister: String,
    pub staking_canister: String,
    pub controller: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TokenMeta {
    pub ticker: String,
    pub decimals: u8,
    pub total_supply_base_units: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TokenInitManifest {
    pub treasury: String,
    pub staking_canister: String,
    pub fee_collector: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct VestingInitManifest {
    pub token_canister: String,
    pub controller: String,
    pub founders_vesting_canister: String,
    pub founder_cliff_months: u32,
    pub founder_linear_months: u32,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AllocationRow {
    pub category_id: String,
    pub category_name: String,
    pub amount_base_units: u64,
    /// Row share in BASIS POINTS — see `ApprovedRow::percent_bps`.
    pub percent_bps: u32,
    pub lock_policy: String,
    pub vesting_policy: String,
    pub principal_role: String,
    pub principal: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ScheduleRow {
    pub beneficiary: String,
    pub total_amount_base_units: u64,
}

/// Historical name, kept so existing call sites and tests read unchanged.
pub type FounderScheduleRow = ScheduleRow;

// ── Parsed artifact views ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedAllocation {
    pub category_id: String,
    pub category_name: String,
    pub amount: u128,
    pub recipient: String,
    pub subaccount_is_null: bool,
    pub lock_policy: String,
    pub vesting_policy_is_null: bool,
    pub created_at_genesis: bool,
    pub genesis_timestamp_ns: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedTokenInit {
    pub allocations: Vec<ParsedAllocation>,
    pub treasury: String,
    pub staking_canister: String,
    pub fee_collector: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedSchedule {
    pub beneficiary: String,
    pub total_amount: u128,
    pub cliff_months: u32,
    pub linear_months: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedVestingInit {
    pub token_canister: String,
    pub controller: String,
    pub schedules: Vec<ParsedSchedule>,
}

// ── R-3 (H-3): the ONE principal-site enumeration ────────────────────────────
//
// Before R-3 the DP3 placeholder scan built its site list inline, so the
// principal-binding family (`GP*`) would have had to build a SECOND, separately
// maintained enumeration of the same sites — and `BRIEF_R3 §9` names that drift
// as the exact way the `GP1-pending-input-populated-*` guard would silently
// reopen the gap it exists to close. There is therefore exactly one site list,
// built here, consumed by BOTH families.
//
// Each site carries (a) the DP3 check name it emits under — unchanged, byte for
// byte, from the pre-R-3 inline loop, so evidence continuity holds — (b) the
// genesis ROLE that owns it, and (c) whether it counts toward the fixed-site
// coverage cardinality (`DP3-scan-coverage`).

/// A genesis principal ROLE. String-keyed on purpose: the role name is the join
/// key between `APPROVED_ALLOCATIONS[i].principal_role`, the manifest's
/// `principal_role` rows, and `genesis_principals.toml`'s `[role.<NAME>]`
/// tables, so `GP1-role-missing-*`/`GP1-role-extra-*` compare the same strings
/// the manifest itself carries rather than a parallel enum that could drift.
pub type Role = String;

// Non-allocation roles. The allocation roles are read from the manifest rows
// (which DP1 pins positionally against `APPROVED_ALLOCATIONS`), never restated.
pub const ROLE_STAKING_CANISTER: &str = "STAKING_CANISTER";
pub const ROLE_NEUTRAL_FEE_COLLECTOR: &str = "NEUTRAL_FEE_COLLECTOR";
pub const ROLE_STSH_TOKEN_CANISTER: &str = "STSH_TOKEN_CANISTER";
pub const ROLE_VESTING_CONTROLLER_MULTISIG: &str = "VESTING_CONTROLLER_MULTISIG";
pub const ROLE_TREASURY_MULTISIG: &str = "TREASURY_MULTISIG";
pub const ROLE_FOUNDERS_VESTING_CANISTER: &str = "FOUNDERS_VESTING_CANISTER";
pub const ROLE_LEGAL_COUNSEL_VESTING: &str = "LEGAL_COUNSEL_VESTING";
pub const ROLE_LEGAL_COUNSEL_BENEFICIARY: &str = "LEGAL_COUNSEL_BENEFICIARY";

/// D-6 (SSA NOTE-1, retained): the schedule BENEFICIARIES are record entries in
/// their own right. `FOUNDER_<n>_BENEFICIARY` is 1-indexed to match the
/// manifest's own `FOUNDER_1_PLACEHOLDER` … comments.
pub fn founder_beneficiary_role(i: usize) -> String {
    format!("FOUNDER_{}_BENEFICIARY", i + 1)
}

/// The counsel schedule is a single grant (D-4 V2); the index suffix appears only
/// if a future manifest ever carries more than one, so the role set stays a
/// function of the manifest rather than a hardcoded singleton.
pub fn counsel_beneficiary_role(i: usize) -> String {
    if i == 0 {
        ROLE_LEGAL_COUNSEL_BENEFICIARY.to_string()
    } else {
        format!("{}_{}", ROLE_LEGAL_COUNSEL_BENEFICIARY, i + 1)
    }
}

/// One principal-bearing site in the committed genesis inputs.
#[derive(Debug, Clone)]
pub struct PrincipalSite {
    /// The `DP3-*` check name this site emits under — the contractual name.
    pub dp3_name: String,
    /// The role that owns this site.
    pub role: Role,
    /// The principal AS WRITTEN in the input (text, never decoded here).
    pub text: String,
    /// Counts toward `DP3-scan-coverage`'s fixed cardinality. Schedule sites are
    /// input-variable and excluded — unchanged from the pre-R-3 loop.
    pub fixed: bool,
}

/// Enumerate every principal site across the manifest and both artifacts, in the
/// EXACT order (and under the exact names) the pre-R-3 DP3 loop used.
pub fn principal_sites(
    manifest: &Manifest,
    token: &ParsedTokenInit,
    vesting: &ParsedVestingInit,
) -> Vec<PrincipalSite> {
    let mut s: Vec<PrincipalSite> = Vec::new();
    let mut push = |dp3_name: String, role: &str, text: &str, fixed: bool| {
        s.push(PrincipalSite {
            dp3_name,
            role: role.to_string(),
            text: text.to_string(),
            fixed,
        });
    };

    // Manifest — 11 allocation rows (fixed-cardinality per §0.3; D-4 drift item).
    for (i, a) in manifest.allocation.iter().enumerate() {
        push(
            format!("DP3-manifest-alloc-{}-{}", i, a.category_id),
            &a.principal_role,
            &a.principal,
            true,
        );
    }
    // Manifest — token_init (3 fixed fields).
    for (fname, value, role) in [
        ("treasury", &manifest.token_init.treasury, ROLE_TREASURY_MULTISIG),
        ("staking_canister", &manifest.token_init.staking_canister, ROLE_STAKING_CANISTER),
        ("fee_collector", &manifest.token_init.fee_collector, ROLE_NEUTRAL_FEE_COLLECTOR),
    ] {
        push(format!("DP3-manifest-token-init-{}", fname), role, value, true);
    }
    // Manifest — vesting_init (3 fixed fields).
    for (fname, value, role) in [
        ("token_canister", &manifest.vesting_init.token_canister, ROLE_STSH_TOKEN_CANISTER),
        ("controller", &manifest.vesting_init.controller, ROLE_VESTING_CONTROLLER_MULTISIG),
        (
            "founders_vesting_canister",
            &manifest.vesting_init.founders_vesting_canister,
            ROLE_FOUNDERS_VESTING_CANISTER,
        ),
    ] {
        push(format!("DP3-manifest-vesting-init-{}", fname), role, value, true);
    }
    // Manifest — founder schedules (input-variable: excluded from the coverage
    // cardinality, still individually checked).
    for (i, f) in manifest.founder_schedule.iter().enumerate() {
        push(
            format!("DP3-manifest-founder-schedule-{}", i),
            &founder_beneficiary_role(i),
            &f.beneficiary,
            false,
        );
    }
    // Manifest — counsel schedule (D-4 V2). See the pre-R-3 note: the founders
    // loop above walks `founder_schedule` only, so without this emission the
    // counsel beneficiary's manifest principal would never be placeholder-scanned.
    for (i, c) in manifest.counsel_schedule.iter().enumerate() {
        push(
            format!("DP3-manifest-counsel-schedule-{}", i),
            &counsel_beneficiary_role(i),
            &c.beneficiary,
            false,
        );
    }
    // Artifact (stsh_token_init.did) — 11 recipients. The ROLE is taken
    // POSITIONALLY from the manifest row D10/D11 already bind this row to; a
    // surplus artifact row (D10 RED) has no manifest role and is attributed to
    // the reserved `UNBOUND_ARTIFACT_ROW_<i>` name so it can never silently
    // borrow another role's expected value.
    for (i, a) in token.allocations.iter().enumerate() {
        let role = manifest
            .allocation
            .get(i)
            .map(|m| m.principal_role.clone())
            .unwrap_or_else(|| format!("UNBOUND_ARTIFACT_ROW_{}", i));
        push(
            format!("DP3-artifact-token-alloc-{}-{}", i, a.category_id),
            &role,
            &a.recipient,
            true,
        );
    }
    // Artifact (stsh_token_init.did) — 3 top-level fields.
    for (fname, value, role) in [
        ("treasury", &token.treasury, ROLE_TREASURY_MULTISIG),
        ("staking_canister", &token.staking_canister, ROLE_STAKING_CANISTER),
    ] {
        push(format!("DP3-artifact-token-{}", fname), role, value, true);
    }
    if let Some(fc) = token.fee_collector.as_deref() {
        push(
            "DP3-artifact-token-fee_collector".to_string(),
            ROLE_NEUTRAL_FEE_COLLECTOR,
            fc,
            true,
        );
    }
    // Artifact (vesting_init.did) — 2 top-level fields.
    for (fname, value, role) in [
        ("token_canister", &vesting.token_canister, ROLE_STSH_TOKEN_CANISTER),
        ("controller", &vesting.controller, ROLE_VESTING_CONTROLLER_MULTISIG),
    ] {
        push(format!("DP3-artifact-vesting-{}", fname), role, value, true);
    }
    // Artifact (vesting_init.did) — schedules (input-variable, as above). V5 binds
    // this vec to `founder_schedule ++ counsel_schedule` IN ORDER, so the role
    // attribution follows that same concatenation and cannot reclassify a
    // schedule between sections without V5 also failing.
    let n_founders = manifest.founder_schedule.len();
    for (i, sch) in vesting.schedules.iter().enumerate() {
        let role = if i < n_founders {
            founder_beneficiary_role(i)
        } else {
            counsel_beneficiary_role(i - n_founders)
        };
        push(format!("DP3-artifact-vesting-schedule-{}", i), &role, &sch.beneficiary, false);
    }

    s
}

// ── Check plumbing ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

fn check(out: &mut Vec<CheckResult>, name: &str, pass: bool, detail: String) {
    out.push(CheckResult { name: name.to_string(), pass, detail });
}

pub fn all_pass(checks: &[CheckResult]) -> bool {
    !checks.is_empty() && checks.iter().all(|c| c.pass)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ── R4-1: P0-3 placeholder rejection (lane A-4) ───────────────────────────────
//
// The genesis artifacts committed to `deployment/mainnet/` carry P0-3
// PLACEHOLDER principals — deterministic stand-ins whose decoded bytes are
// literally `a0 <idx> b"placeholder"`. Before this family of checks existed the
// tool certified that set as a full PASS, so a mis-sequenced deploy could have
// installed genesis against unowned principals. Gate-D now refuses, fail-closed,
// to certify ANY artifact set that still carries one: RR-1 (the real-principal
// replacement) is a hard precondition for a green gate.
//
// The predicate operates on DECODED PRINCIPAL BYTES, never on raw file text —
// the manifest's own prose comments contain the word "placeholder" and must not
// false-positive.

/// The textual suffix shared by every P0-3 placeholder principal.
pub const P0_3_PLACEHOLDER_SUFFIX: &str = "-ygyyl-dmvug-63dem-vza";

/// The ASCII marker carried inside every P0-3 placeholder's decoded bytes.
const PLACEHOLDER_MARKER: &[u8] = b"placeholder";

/// Case-insensitive ASCII window search over decoded principal bytes. A
/// case-flipped marker (`PLACEHOLDER`, `PlaceHolder`) must not evade limb 2.
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// Limbs 2 and 3 of the disjunction, over decoded bytes.
///
/// Two deliberate decisions — NOT oversights:
/// * The RESERVED tag `0x7f` is **not** accepted. No genesis custody role may be
///   a reserved principal, so fail-closed matches the enumerated tag set
///   {0x01 opaque, 0x02 self-auth, 0x03 derived, 0x04 anonymous}.
/// * The ANONYMOUS principal (`0x04`, single byte) **is** accepted here.
///   Rejecting anonymous as a genesis custody role is real hardening but is
///   deliberately OUT OF SCOPE for lane A-4 (carried as finding A-4-F1).
pub fn principal_bytes_rejection_reason(bytes: &[u8]) -> Option<String> {
    // Limb 2 — byte-window marker (case-insensitive).
    if contains_ascii_ci(bytes, PLACEHOLDER_MARKER) {
        return Some(format!(
            "decoded bytes carry the ASCII \"placeholder\" marker (bytes={})",
            hex::encode(bytes)
        ));
    }
    // Limb 3 — invalid principal type tag.
    match bytes.last() {
        None => Some("empty principal (no type tag)".to_string()),
        Some(&tag) => {
            if !matches!(tag, 0x01 | 0x02 | 0x03 | 0x04) {
                Some(format!(
                    "trailing byte 0x{:02x} is not a valid IC principal type tag \
                     (expected 0x01 opaque / 0x02 self-auth / 0x03 derived / 0x04 anonymous)",
                    tag
                ))
            } else if tag == 0x04 && bytes.len() != 1 {
                Some(format!(
                    "anonymous type tag 0x04 with length {} (the anonymous principal is \
                     the single byte 0x04 and nothing else)",
                    bytes.len()
                ))
            } else {
                None
            }
        }
    }
}

/// The full R4-1 disjunction over a principal's TEXTUAL form. Returns the
/// rejection reason, or `None` when the principal is acceptable for genesis.
///
/// Limbs, each independently provable:
/// 1. P0-3 set membership — textual suffix `P0_3_PLACEHOLDER_SUFFIX`.
/// 2. Byte-window marker — decoded bytes contain `placeholder`, case-insensitive.
/// 3. Invalid principal type tag (see `principal_bytes_rejection_reason`).
/// 4. Unparseable — `Principal::from_text` fails.
///
///    MEASURED, not assumed (see `NOTE_A-4_limb4_artifact_side_parse.md`): the
///    artifact side does NOT lack a parse guard — it has a STRICTER one. A
///    malformed principal in a `*_init.did` is rejected by the CANDID PARSER,
///    which aborts the whole run (`parse_artifact` returns `Err`) before any
///    check vector is built, so limb 4 can never fire artifact-side. Limb 4's
///    real value is therefore (a) MANIFEST-side, where TOML carries the text
///    through intact and limb 4 duplicates D5 under a SITE-SPECIFIC name — D5
///    reports only that some principal is malformed, `DP3-manifest-alloc-<i>-<id>`
///    reports which row — and (b) as the parse guard for any future input path
///    that does not run through Candid. It is not artifact-side dead code; do
///    not delete it as such.
pub fn placeholder_rejection_reason(principal_text: &str) -> Option<String> {
    if principal_text.ends_with(P0_3_PLACEHOLDER_SUFFIX) {
        return Some(format!(
            "known P0-3 placeholder principal (suffix \"{}\")",
            P0_3_PLACEHOLDER_SUFFIX
        ));
    }
    match Principal::from_text(principal_text) {
        Err(e) => Some(format!("unparseable principal: {}", e)),
        Ok(p) => principal_bytes_rejection_reason(p.as_slice()),
    }
}

// ── Candid artifact extraction (walks the parsed value AST directly — the
//    artifact IS the input; no re-encode round trip, no reconstructed args) ──

fn strip_comments(text: &str) -> String {
    // The canonical artifacts carry `//` header comments; the candid textual
    // parser accepts values only. Comments never contain load-bearing data.
    text.lines()
        .map(|l| if let Some(idx) = l.find("//") { &l[..idx] } else { l })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn parse_artifact(text: &str) -> Result<IDLArgs, String> {
    candid_parser::parse_idl_args(&strip_comments(text))
        .map_err(|e| format!("candid parse failed: {}", e))
}

fn record_fields(v: &IDLValue) -> Result<&Vec<candid::types::value::IDLField>, String> {
    match v {
        IDLValue::Record(fields) => Ok(fields),
        other => Err(format!("expected record, got {:?}", other)),
    }
}

fn field<'a>(v: &'a IDLValue, name: &str) -> Result<&'a IDLValue, String> {
    let fields = record_fields(v)?;
    fields
        .iter()
        .find(|f| f.id.to_string() == name)
        .map(|f| &f.val)
        .ok_or_else(|| format!("missing field `{}`", name))
}

fn as_u128(v: &IDLValue) -> Result<u128, String> {
    match v {
        IDLValue::Nat(n) => n.0.to_u128().ok_or_else(|| "nat exceeds u128".to_string()),
        IDLValue::Nat64(n) => Ok(*n as u128),
        IDLValue::Nat32(n) => Ok(*n as u128),
        IDLValue::Number(s) => s
            .replace('_', "")
            .parse::<u128>()
            .map_err(|e| format!("bad number `{}`: {}", s, e)),
        other => Err(format!("expected nat, got {:?}", other)),
    }
}

fn as_u64(v: &IDLValue) -> Result<u64, String> {
    let n = as_u128(v)?;
    u64::try_from(n).map_err(|_| format!("{} exceeds u64", n))
}

fn as_u32(v: &IDLValue) -> Result<u32, String> {
    let n = as_u128(v)?;
    u32::try_from(n).map_err(|_| format!("{} exceeds u32", n))
}

fn as_bool(v: &IDLValue) -> Result<bool, String> {
    match v {
        IDLValue::Bool(b) => Ok(*b),
        other => Err(format!("expected bool, got {:?}", other)),
    }
}

fn as_text(v: &IDLValue) -> Result<String, String> {
    match v {
        IDLValue::Text(s) => Ok(s.clone()),
        other => Err(format!("expected text, got {:?}", other)),
    }
}

fn as_principal_text(v: &IDLValue) -> Result<String, String> {
    match v {
        IDLValue::Principal(p) => Ok(p.to_text()),
        other => Err(format!("expected principal, got {:?}", other)),
    }
}

fn is_null(v: &IDLValue) -> bool {
    matches!(v, IDLValue::None | IDLValue::Null)
}

fn as_opt(v: &IDLValue) -> Option<&IDLValue> {
    match v {
        IDLValue::Opt(inner) => Some(inner),
        _ => None,
    }
}

fn variant_tag(v: &IDLValue) -> Result<String, String> {
    match v {
        IDLValue::Variant(var) => Ok(var.0.id.to_string()),
        other => Err(format!("expected variant, got {:?}", other)),
    }
}

fn as_vec(v: &IDLValue) -> Result<&Vec<IDLValue>, String> {
    match v {
        IDLValue::Vec(items) => Ok(items),
        other => Err(format!("expected vec, got {:?}", other)),
    }
}

pub fn extract_token_init(args: &IDLArgs) -> Result<ParsedTokenInit, String> {
    let root = args.args.first().ok_or("empty artifact")?;
    let mut allocations = Vec::new();
    for (i, item) in as_vec(field(root, "allocations")?)?.iter().enumerate() {
        let ctx = |e: String| format!("allocation[{}]: {}", i, e);
        allocations.push(ParsedAllocation {
            category_id: as_text(field(item, "category_id").map_err(&ctx)?).map_err(&ctx)?,
            category_name: as_text(field(item, "category_name").map_err(&ctx)?).map_err(&ctx)?,
            amount: as_u128(field(item, "amount").map_err(&ctx)?).map_err(&ctx)?,
            recipient: as_principal_text(field(item, "recipient").map_err(&ctx)?).map_err(&ctx)?,
            subaccount_is_null: is_null(field(item, "subaccount").map_err(&ctx)?),
            lock_policy: variant_tag(field(item, "lock_policy").map_err(&ctx)?).map_err(&ctx)?,
            vesting_policy_is_null: is_null(field(item, "vesting_policy").map_err(&ctx)?),
            created_at_genesis: as_bool(field(item, "created_at_genesis").map_err(&ctx)?)
                .map_err(&ctx)?,
            genesis_timestamp_ns: as_u64(field(item, "genesis_timestamp_ns").map_err(&ctx)?)
                .map_err(&ctx)?,
        });
    }
    let fee_collector = {
        let v = field(root, "fee_collector")?;
        if is_null(v) {
            None
        } else {
            Some(as_principal_text(as_opt(v).ok_or("fee_collector: expected opt")?)?)
        }
    };
    Ok(ParsedTokenInit {
        allocations,
        treasury: as_principal_text(field(root, "treasury")?)?,
        staking_canister: as_principal_text(field(root, "staking_canister")?)?,
        fee_collector,
    })
}

pub fn extract_vesting_init(args: &IDLArgs) -> Result<ParsedVestingInit, String> {
    let root = args.args.first().ok_or("empty artifact")?;
    let mut schedules = Vec::new();
    for (i, item) in as_vec(field(root, "schedules")?)?.iter().enumerate() {
        let ctx = |e: String| format!("schedule[{}]: {}", i, e);
        schedules.push(ParsedSchedule {
            beneficiary: as_principal_text(field(item, "beneficiary").map_err(&ctx)?)
                .map_err(&ctx)?,
            total_amount: as_u128(field(item, "total_amount").map_err(&ctx)?).map_err(&ctx)?,
            cliff_months: as_u32(field(item, "cliff_months").map_err(&ctx)?).map_err(&ctx)?,
            linear_months: as_u32(field(item, "linear_months").map_err(&ctx)?).map_err(&ctx)?,
        });
    }
    Ok(ParsedVestingInit {
        token_canister: as_principal_text(field(root, "token_canister")?)?,
        controller: as_principal_text(field(root, "controller")?)?,
        schedules,
    })
}

// ── Gate-D ────────────────────────────────────────────────────────────────────

/// The A-7 install kit, the record DPOOL-5 reads the treasury CANISTER from.
///
/// RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13: `pool_init.treasury_canister` is a
/// CALLEE identity (`treasury_disburse` requires `caller == TREASURY_CANISTER`,
/// shielded-pool/src/lib.rs:6235; the pool CALLS it at :13113), i.e. the treasury
/// CANISTER — never the ledger's treasury ACCOUNT holder. The kit's
/// `[[entry]] canister = "treasury"` `target` is the committed D5 principal for
/// that canister, and `verify_a7_kit` already binds the whole kit to the D5
/// receipt set (verify_a7_kit.rs check 4), so reading it here is a cross-record
/// equality rather than a value this lane writes and then checks against itself.
pub const A7_INSTALL_KIT_RECORD: &str = "deployment/mainnet/a7_install_kit.toml";

/// The four `[pool_init]` principal fields DPOOL-4..7 own. DPOOL-5b scans
/// exactly these for a P0-3 placeholder literal: they are NOT `principal_sites`
/// (see `principal_sites`, which enumerates the allocation/token/vesting sites
/// only), so the DP3 placeholder family never reaches them and DPOOL-4..7 —
/// pure equalities — would happily pass a placeholder on BOTH sides.
pub const POOL_INIT_PRINCIPAL_FIELDS: [&str; 4] =
    ["token_canister", "treasury_canister", "staking_canister", "controller"];

/// The `target` of the A-7 kit's `treasury` row.
///
/// Deliberately a line scanner rather than a typed `toml` deserialize: this
/// crate must not take a structural dependency on the kit's schema (owned by
/// `verify_custody_manifest`), and the one field it needs is unambiguous.
/// Fail-closed: a missing row, a missing `target`, or a duplicate `treasury`
/// row is an `Err`, never a silent default.
pub fn kit_treasury_target(kit_toml: &str) -> Result<String, String> {
    let mut found: Vec<String> = Vec::new();
    let mut canister: Option<String> = None;
    let mut target: Option<String> = None;
    let take = |l: &str| -> Option<String> {
        let (_, r) = l.split_once('=')?;
        let r = r.trim();
        let r = r.strip_prefix('"')?;
        Some(r.split('"').next()?.to_string())
    };
    let flush = |c: &mut Option<String>, t: &mut Option<String>, found: &mut Vec<String>| {
        if c.as_deref() == Some("treasury") {
            if let Some(v) = t.clone() {
                found.push(v);
            }
        }
        *c = None;
        *t = None;
    };
    for line in kit_toml.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if t.starts_with("[[entry]]") || t.starts_with('[') {
            flush(&mut canister, &mut target, &mut found);
            continue;
        }
        if t.starts_with("canister") && t.contains('=') {
            canister = take(t);
        } else if t.starts_with("target") && t.contains('=') {
            target = take(t);
        }
    }
    flush(&mut canister, &mut target, &mut found);
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(format!(
            "{A7_INSTALL_KIT_RECORD} has no `[[entry]]` with canister = \"treasury\" carrying a `target`"
        )),
        n => Err(format!(
            "{A7_INSTALL_KIT_RECORD} carries {n} `treasury` entries — the treasury canister has exactly one D5 principal"
        )),
    }
}

pub fn gate_d(
    manifest: &Manifest,
    token: &ParsedTokenInit,
    vesting: &ParsedVestingInit,
    kit_toml: Option<&str>,
    vault: Option<&Principal>,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let expected_supply = manifest.token.total_supply_base_units as u128;

    // ── D0-schema, decomposed for ATTRIBUTABILITY (ruled row, W-VKGATE §2.4) ─
    //
    // `D0-schema` is a three-condition AND under one name. Until now a failing
    // D0-schema told you only THAT it failed: attributing the failure to the
    // schema limb rather than the ticker or decimals limb required constructing
    // two byte-identical manifests differing in one field (the A6.5 C-22 arm's
    // scaffolding) and inferring the limb from the difference.
    //
    // SHAPE (b) of the two the ruling allows: the composite keeps its single
    // name and its existing rendering, and gains a MACHINE-CHECKABLE per-limb
    // suffix. Chosen over shape (a) (separate per-limb CheckResults) because it
    // cannot alter the check list other consumers iterate, and because the
    // existing detail prefix stays byte-identical — so the A6.5 arms, which
    // assert on `schema_version={}`, keep passing untouched.
    //
    // BEHAVIOUR IS UNCHANGED, and this is the hard constraint: `pass` is the
    // same three-condition AND over the same operands. Nothing here can move a
    // composite verdict; N-8's matrix demonstrates that rather than asserting it.
    let limb_schema = manifest.schema_version == 3;
    let limb_ticker = manifest.token.ticker == "STSH";
    let limb_decimals = manifest.token.decimals == 8;
    let limb = |ok: bool| if ok { "PASS" } else { "FAIL" };
    check(
        &mut out,
        "D0-schema",
        limb_schema && limb_ticker && limb_decimals,
        format!(
            "schema_version={} ticker={} decimals={} | limbs: schema={} ticker={} decimals={}",
            manifest.schema_version,
            manifest.token.ticker,
            manifest.token.decimals,
            limb(limb_schema),
            limb(limb_ticker),
            limb(limb_decimals)
        ),
    );
    // ── DPOOL series (W-VKGATE / AR1-05, C-27): the pool's trust roots ───────
    //    Field-by-field, exactly as token_init and vesting_init already are. A
    //    section that is parsed but only spot-checked reproduces the gap this
    //    lane exists to close, in a new place.
    let pi = &manifest.pool_init;
    let vk_ok = pi.vk_hash.len() == 32 * 2
        && pi.vk_hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    check(
        &mut out,
        "DPOOL-1-vk-hash-shape",
        vk_ok,
        format!("pool_init.vk_hash={} (expect 64 lowercase hex)", pi.vk_hash),
    );
    check(
        &mut out,
        "DPOOL-2-vk-hash-not-dev",
        pi.vk_hash != DEV_VK_HASH_HEX,
        format!(
            "pool_init.vk_hash={} deny={} (M5 single-participant DEV key — refused)",
            pi.vk_hash, DEV_VK_HASH_HEX
        ),
    );
    check(
        &mut out,
        "DPOOL-3-proof-system",
        pi.proof_system == EXPECTED_PROOF_SYSTEM,
        format!("pool_init.proof_system={} expected={}", pi.proof_system, EXPECTED_PROOF_SYSTEM),
    );
    check(
        &mut out,
        "DPOOL-4-token-canister",
        pi.token_canister == manifest.vesting_init.token_canister,
        format!(
            "pool_init.token_canister={} vesting_init.token_canister={}",
            pi.token_canister, manifest.vesting_init.token_canister
        ),
    );
    // ── DPOOL-5, AMENDED (RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13 §3) ──────
    //
    // WAS: `pi.treasury_canister == manifest.token_init.treasury`. That equated
    // the pool's treasury CANISTER with the LEDGER's treasury ACCOUNT holder
    // (TREASURY_MULTISIG) — two different objects that CUSTODY_DECISION.md
    // Option 2 keeps deliberately apart: the treasury canister must not custody
    // real STSH, so the allocation recipient is the multisig holder and the
    // callee identity is the canister. The old equality was a gate defect, and
    // it is now REFUSED by name, not merely un-asserted.
    //
    // NOW: the treasury row's `target` in the A-7 install kit.
    let (pass_5, detail_5) = match kit_toml.map(kit_treasury_target) {
        None => (
            false,
            format!(
                "pool_init.treasury_canister={} — {A7_INSTALL_KIT_RECORD} was NOT supplied to \
                 this surface, so the ruled equality cannot be evaluated (fail-closed)",
                pi.treasury_canister
            ),
        ),
        Some(Err(e)) => (false, format!("pool_init.treasury_canister={} — {e}", pi.treasury_canister)),
        Some(Ok(kit_target)) => {
            let ok = pi.treasury_canister == kit_target;
            let mut d = format!(
                "pool_init.treasury_canister={} a7_install_kit[treasury].target={}",
                pi.treasury_canister, kit_target
            );
            if !ok && pi.treasury_canister == manifest.token_init.treasury {
                d.push_str(&format!(
                    " — REFUSED: this is token_init.treasury ({}), the ledger's treasury ACCOUNT \
                     holder, not the treasury CANISTER. That equality was the pre-amendment \
                     DPOOL-5 and is a gate defect; see RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13",
                    manifest.token_init.treasury
                ));
            }
            (ok, d)
        }
    };
    check(&mut out, "DPOOL-5-treasury", pass_5, detail_5);
    // ── DPOOL-5b (NEW, same ruling) — no P0-3 placeholder in a pool trust root ─
    //
    // DPOOL-4..7 are pure equalities between two records. A placeholder written
    // into BOTH sides passes all four. The `[pool_init]` principals are not
    // `principal_sites`, so the DP3 placeholder family — the check that would
    // otherwise catch this — never sees them: these four fields' ONLY coverage
    // is DPOOL-4..7, and this is the limb that makes that coverage fail-closed.
    let placeheld: Vec<String> = POOL_INIT_PRINCIPAL_FIELDS
        .iter()
        .filter_map(|f| {
            let v = match *f {
                "token_canister" => &pi.token_canister,
                "treasury_canister" => &pi.treasury_canister,
                "staking_canister" => &pi.staking_canister,
                _ => &pi.controller,
            };
            placeholder_rejection_reason(v).map(|r| format!("{f}={v} ({r})"))
        })
        .collect();
    check(
        &mut out,
        "DPOOL-5b-no-placeholder-trust-root",
        placeheld.is_empty(),
        if placeheld.is_empty() {
            "no P0-3 placeholder literal in pool_init token_canister/treasury_canister/staking_canister/controller".to_string()
        } else {
            format!("REFUSED — P0-3 placeholder in a pool trust root: {}", placeheld.join("; "))
        },
    );
    check(
        &mut out,
        "DPOOL-6-staking-canister",
        pi.staking_canister == manifest.token_init.staking_canister,
        format!(
            "pool_init.staking_canister={} token_init.staking_canister={}",
            pi.staking_canister, manifest.token_init.staking_canister
        ),
    );
    // ── DPOOL-7, AMENDED (same ruling §3) ────────────────────────────────────
    //
    // WAS: `pi.controller == manifest.vesting_init.controller`. The pool's
    // `controller` gates the pool's reconcile endpoints (shielded-pool/src/lib.rs:8909)
    // and custody_manifest.toml binds `shielded_pool.CONTROLLER` to the VAULT;
    // the vesting controller is the VESTING_CONTROLLER_MULTISIG, a different
    // authority. NOW: `vault_authorities.toml [recovery].vault`, read DIRECTLY.
    //
    // Read directly rather than through `VAULT_BOUND_ROLES`: that list drives
    // the GP-series record bindings (`principal_binding_violations`, :2166-2183
    // and :2551-2558 iterate it), and adding a pool-controller role there would
    // require a genesis_principals.toml entry the pool fields do not have —
    // they are not record-bound sites. This is a plain cross-record equality.
    let (pass_7, detail_7) = match vault {
        None => (
            false,
            format!(
                "pool_init.controller={} — {GENESIS_VAULT_AUTHORITY_RECORD} was NOT supplied to \
                 this surface, so the ruled equality cannot be evaluated (fail-closed)",
                pi.controller
            ),
        ),
        Some(v) => {
            let vt = v.to_text();
            let ok = pi.controller == vt;
            let mut d = format!(
                "pool_init.controller={} vault_authorities[recovery].vault={}",
                pi.controller, vt
            );
            if !ok && pi.controller == manifest.vesting_init.controller {
                d.push_str(&format!(
                    " — REFUSED: this is vesting_init.controller ({}), the VESTING_CONTROLLER \
                     multisig, not the pool's controller. That equality was the pre-amendment \
                     DPOOL-7 and is a gate defect; see RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13",
                    manifest.vesting_init.controller
                ));
            }
            (ok, d)
        }
    };
    check(&mut out, "DPOOL-7-controller", pass_7, detail_7);
    check(
        &mut out,
        "D1-total-supply-pin",
        expected_supply == TOTAL_SUPPLY_BASE_UNITS,
        format!("manifest total_supply={} pinned={}", expected_supply, TOTAL_SUPPLY_BASE_UNITS),
    );

    // ── DP series (SSA P1): the manifest itself is verified against the
    //    HARDCODED approved §0.3 schema. Every non-principal field is pinned —
    //    id, name, amount, percent, lock policy, vesting policy, principal
    //    ROLE. Only the P0-3 principal VALUE is free (replaced at RR-1). A
    //    coherent manifest+artifact drift therefore cannot pass: the artifact
    //    is checked against the manifest (D10/D11) and the manifest against
    //    the approved schema (here).
    check(
        &mut out,
        "DP0-approved-row-count",
        manifest.allocation.len() == APPROVED_ALLOCATIONS.len(),
        format!("manifest rows={} approved rows={}", manifest.allocation.len(), APPROVED_ALLOCATIONS.len()),
    );
    for (i, approved) in APPROVED_ALLOCATIONS.iter().enumerate() {
        let name = format!("DP1-row-{}-{}", i, approved.category_id);
        match manifest.allocation.get(i) {
            None => check(&mut out, &name, false, "row missing from manifest".into()),
            Some(m) => {
                let row_ok = m.category_id == approved.category_id
                    && (m.category_name == approved.category_name || approved.category_id == "founders")
                    && m.amount_base_units as u128 == approved.amount_base_units
                    && m.percent_bps == approved.percent_bps
                    && m.lock_policy == approved.lock_policy
                    && m.vesting_policy == approved.vesting_policy
                    && m.principal_role == approved.principal_role;
                check(
                    &mut out,
                    &name,
                    row_ok,
                    if row_ok {
                        "matches the approved §0.3 schema".into()
                    } else {
                        format!(
                            "SCHEMA DRIFT manifest=({},{},{},{}%,{},{},{}) approved=({},{},{},{}%,{},{},{})",
                            m.category_id, m.category_name, m.amount_base_units, m.percent_bps,
                            m.lock_policy, m.vesting_policy, m.principal_role,
                            approved.category_id, approved.category_name, approved.amount_base_units,
                            approved.percent_bps, approved.lock_policy, approved.vesting_policy,
                            approved.principal_role
                        )
                    },
                );
            }
        }
    }
    check(
        &mut out,
        "DP2-founder-shape-pin",
        manifest.vesting_init.founder_cliff_months == APPROVED_FOUNDER_CLIFF_MONTHS
            && manifest.vesting_init.founder_linear_months == APPROVED_FOUNDER_LINEAR_MONTHS,
        format!(
            "manifest cliff/linear={}/{} approved={}/{}",
            manifest.vesting_init.founder_cliff_months, manifest.vesting_init.founder_linear_months,
            APPROVED_FOUNDER_CLIFF_MONTHS, APPROVED_FOUNDER_LINEAR_MONTHS
        ),
    );

    // Manifest-internal invariants — CHECKED arithmetic throughout.
    let manifest_sum = manifest
        .allocation
        .iter()
        .try_fold(0u128, |acc, a| acc.checked_add(a.amount_base_units as u128));
    check(
        &mut out,
        "D2-manifest-sum-checked",
        manifest_sum == Some(expected_supply),
        format!("checked sum(manifest amounts)={:?} expected={}", manifest_sum, expected_supply),
    );
    // BASIS POINTS since D-4 (drift item): 0.5% and 29.5% are not representable as
    // integer percent, so the pinned share moved to bps and this target moved 100 ->
    // 10,000. The check NAME is deliberately unchanged so evidence continuity holds.
    let percent_bps_sum: u64 = manifest.allocation.iter().map(|a| a.percent_bps as u64).sum();
    check(&mut out, "D3-percent-sum", percent_bps_sum == 10_000, format!("Σbps={}", percent_bps_sum));

    let mut ids = std::collections::HashSet::new();
    let dup = manifest.allocation.iter().find(|a| !ids.insert(a.category_id.as_str()));
    check(
        &mut out,
        "D4-unique-category-ids",
        dup.is_none(),
        dup.map(|a| format!("duplicate: {}", a.category_id)).unwrap_or_else(|| "unique".into()),
    );

    // D16 (sub-item 1, TASK60 stage 1): allocation PRINCIPALS must be pairwise
    // distinct. Nothing enforced this before: DP1 pins each row's `principal_role`
    // positionally but deliberately NOT its principal (principals are the
    // RR-1-replaceable field), D4 covers category ids, and D5 only parses. So two
    // buckets could name the SAME principal and every check passed — collapsing
    // one allocation into another's account with no signal. Measured, not
    // theorised: pointing `legal_counsel` at the `treasury` principal produced
    // zero non-placeholder failures before this check existed.
    //
    // This bites hardest at RR-1, where a replacement map with a repeated
    // production principal would silently merge two buckets. The manifest header
    // requires every role to stay DISTINCT; this is that rule, enforced.
    // The ENUMERATED exemption (D-4 V2 §2 item 5): exactly `founders` and
    // `legal_counsel` may share ONE principal, and only when that principal is the
    // genesis vesting canister — because that canister is the schedule authority
    // for both rows. This is written as a named pair on purpose: never a wildcard,
    // never "rows whose lock_policy is Vested", never "any row naming a canister".
    // Every other collision, including any third row joining this pair, still fails.
    let vesting_canister = manifest.vesting_init.founders_vesting_canister.as_str();
    let exempt_pair = [FOUNDERS_CATEGORY_ID, COUNSEL_CATEGORY_ID];
    let mut seen_principals: std::collections::HashMap<&str, &str> =
        std::collections::HashMap::new();
    let mut dup_principal: Option<(&str, &str, &str)> = None;
    for a in manifest.allocation.iter() {
        if let Some(prev_id) = seen_principals.insert(a.principal.as_str(), a.category_id.as_str())
        {
            let pair_is_exempt = exempt_pair.contains(&prev_id)
                && exempt_pair.contains(&a.category_id.as_str())
                && prev_id != a.category_id.as_str()
                && a.principal == vesting_canister;
            if !pair_is_exempt {
                dup_principal = Some((a.category_id.as_str(), prev_id, a.principal.as_str()));
                break;
            }
        }
    }
    check(
        &mut out,
        "D16-unique-allocation-principals",
        dup_principal.is_none(),
        match dup_principal {
            Some((id, prev_id, principal)) => {
                format!("row {} reuses principal {} (already used by {})", id, principal, prev_id)
            }
            None => format!(
                "{} allocation rows, principals distinct except the enumerated {:?} pair on the vesting canister",
                manifest.allocation.len(),
                exempt_pair
            ),
        },
    );

    let bad_principal = manifest
        .allocation
        .iter()
        .map(|a| a.principal.as_str())
        .chain([
            manifest.token_init.treasury.as_str(),
            manifest.token_init.staking_canister.as_str(),
            manifest.token_init.fee_collector.as_str(),
            manifest.vesting_init.token_canister.as_str(),
            manifest.vesting_init.controller.as_str(),
            manifest.vesting_init.founders_vesting_canister.as_str(),
        ])
        .find(|p| Principal::from_text(p).is_err());
    check(
        &mut out,
        "D5-principals-parse",
        bad_principal.is_none(),
        bad_principal.map(|p| format!("invalid principal: {}", p)).unwrap_or_else(|| "ok".into()),
    );

    let vp_bad = manifest.allocation.iter().find(|a| a.vesting_policy != "null");
    check(
        &mut out,
        "D6-vesting-policy-null-all-rows",
        vp_bad.is_none(),
        vp_bad
            .map(|a| format!("{} has vesting_policy={}", a.category_id, a.vesting_policy))
            .unwrap_or_else(|| "all null".into()),
    );

    let founders = manifest.allocation.iter().find(|a| a.category_id == "founders");
    check(
        &mut out,
        "D7-founders-row",
        founders.map(|f| {
            f.lock_policy == "Vested"
                && f.principal == manifest.vesting_init.founders_vesting_canister
        }) == Some(true),
        "founders row: lock_policy==Vested && recipient==FOUNDERS_VESTING_CANISTER".into(),
    );

    check(
        &mut out,
        "D8-treasury-binding",
        manifest
            .allocation
            .iter()
            .find(|a| a.category_id == "treasury")
            .map(|a| a.principal == manifest.token_init.treasury)
            == Some(true),
        "token_init.treasury == treasury allocation recipient".into(),
    );
    check(
        &mut out,
        "D9-fee-collector-distinct-nonnull",
        !manifest.token_init.fee_collector.is_empty()
            && manifest.token_init.fee_collector != manifest.token_init.treasury,
        "fee_collector non-null and != treasury".into(),
    );

    // Artifact ◄─► manifest, field-exact, order-sensitive.
    check(
        &mut out,
        "D10-artifact-row-count",
        token.allocations.len() == manifest.allocation.len(),
        format!("artifact={} manifest={}", token.allocations.len(), manifest.allocation.len()),
    );
    for (i, (a, m)) in token.allocations.iter().zip(manifest.allocation.iter()).enumerate() {
        let row_ok = a.category_id == m.category_id
            && a.category_name == m.category_name
            && a.amount == m.amount_base_units as u128
            && a.recipient == m.principal
            && a.lock_policy == m.lock_policy
            && a.subaccount_is_null
            && a.vesting_policy_is_null
            && !a.created_at_genesis
            && a.genesis_timestamp_ns == 0;
        check(
            &mut out,
            &format!("D11-row-{}-{}", i, m.category_id),
            row_ok,
            if row_ok {
                "exact match + canonical forms".into()
            } else {
                format!(
                    "MISMATCH artifact=({},{},{},{},{},sub_null={},vp_null={},cag={},ts={}) manifest=({},{},{},{},{})",
                    a.category_id, a.category_name, a.amount, a.recipient, a.lock_policy,
                    a.subaccount_is_null, a.vesting_policy_is_null, a.created_at_genesis,
                    a.genesis_timestamp_ns, m.category_id, m.category_name,
                    m.amount_base_units, m.principal, m.lock_policy
                )
            },
        );
    }

    let artifact_sum = token
        .allocations
        .iter()
        .try_fold(0u128, |acc, a| acc.checked_add(a.amount));
    check(
        &mut out,
        "D12-artifact-sum-checked",
        artifact_sum == Some(expected_supply),
        format!("checked sum(artifact amounts)={:?} expected={}", artifact_sum, expected_supply),
    );

    check(
        &mut out,
        "D13-init-treasury",
        token.treasury == manifest.token_init.treasury,
        format!("artifact={} manifest={}", token.treasury, manifest.token_init.treasury),
    );
    check(
        &mut out,
        "D14-init-staking-canister",
        token.staking_canister == manifest.token_init.staking_canister,
        format!("artifact={} manifest={}", token.staking_canister, manifest.token_init.staking_canister),
    );
    check(
        &mut out,
        "D15-init-fee-collector",
        token.fee_collector.as_deref() == Some(manifest.token_init.fee_collector.as_str())
            && token.fee_collector.as_deref() != Some(token.treasury.as_str()),
        format!("artifact={:?} manifest={} (non-null, != treasury required)",
            token.fee_collector, manifest.token_init.fee_collector),
    );

    // ── DP3 series (R4-1, lane A-4): FAIL-CLOSED PLACEHOLDER REJECTION ───────
    //    One NAMED check per principal SITE, across the manifest AND both
    //    `*_init.did` artifacts. These live in this same `Vec<CheckResult>`, so
    //    `run_gates_from_strs`, `run_gates_on_dir`, `all_pass`, the CLI and both
    //    test crates inherit the verdict with no new plumbing — there is no
    //    placeholder-blind entry point.
    // R-3: the site list is built ONCE, by `principal_sites`, and is shared with
    // the `GP*` principal-binding family. The names, order and fixed/variable
    // classification below are byte-identical to the pre-R-3 inline loop — see
    // `principal_sites`' header for why there is exactly one enumeration.
    let sites = principal_sites(manifest, token, vesting);
    let mut inspected_fixed_sites: usize = 0;
    for s in sites.iter() {
        if s.fixed {
            inspected_fixed_sites += 1;
        }
        match placeholder_rejection_reason(&s.text) {
            None => check(&mut out, &s.dp3_name, true, format!("{} accepted", s.text)),
            Some(reason) => check(
                &mut out,
                &s.dp3_name,
                false,
                format!("REJECTED {}: {}", s.text, reason),
            ),
        }
    }

    // DP3-scan-coverage: the expectation is derived from the HARDCODED approved
    // §0.3 schema — a source the scanner does NOT walk — so it can honestly
    // diverge. A manifest with 10 allocation rows yields 32 inspected fixed sites
    // against the required 33 and this check FAILS.
    // 11 manifest allocations + 11 artifact allocations + 3 manifest token_init
    // + 3 manifest vesting_init + 3 artifact token fields + 2 artifact vesting
    // fields = 33. Founder-schedule sites are input-variable and excluded (V5
    // already binds the two schedule lists to each other).
    //
    // The 10->11 row count (and 31->33 here) is D-4 (drift item), the
    // legal-counsel grant. This comment states the cardinality in prose, so it
    // is part of the edit whenever APPROVED_ALLOCATIONS changes — never
    // commentary. It must NEVER be re-derived from the manifest under test.
    let expected_fixed_sites = APPROVED_ALLOCATIONS.len() + APPROVED_ALLOCATIONS.len() + 3 + 3 + 3 + 2;
    check(
        &mut out,
        "DP3-scan-coverage",
        inspected_fixed_sites == expected_fixed_sites,
        format!(
            "inspected fixed principal sites={} required by the approved §0.3 cardinality={}",
            inspected_fixed_sites, expected_fixed_sites
        ),
    );

    out
}

// ── Gate-V phase 1 (pre-install) ─────────────────────────────────────────────

pub fn gate_v_pre_install(
    manifest: &Manifest,
    token: &ParsedTokenInit,
    vesting: &ParsedVestingInit,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let founders_amount = manifest
        .allocation
        .iter()
        .find(|a| a.category_id == "founders")
        .map(|a| a.amount_base_units as u128);

    check(
        &mut out,
        "V1-vesting-init-bindings",
        vesting.token_canister == manifest.vesting_init.token_canister
            && vesting.controller == manifest.vesting_init.controller,
        format!(
            "token_canister artifact={} manifest={}; controller artifact={} manifest={}",
            vesting.token_canister, manifest.vesting_init.token_canister,
            vesting.controller, manifest.vesting_init.controller
        ),
    );

    // D-4 V2: the counsel allocation names the SAME canister as founders — that
    // canister is the schedule authority for both. Pinned so the two rows cannot
    // drift onto different custodians while every other check still passes.
    let counsel_recipient = token
        .allocations
        .iter()
        .find(|a| a.category_id == COUNSEL_CATEGORY_ID)
        .map(|a| a.recipient.clone());
    check(
        &mut out,
        "V9-counsel-recipient-is-vesting-canister",
        counsel_recipient.as_deref()
            == Some(manifest.vesting_init.founders_vesting_canister.as_str()),
        format!(
            "token counsel recipient={:?} vesting canister={}",
            counsel_recipient, manifest.vesting_init.founders_vesting_canister
        ),
    );

    let founders_recipient = token
        .allocations
        .iter()
        .find(|a| a.category_id == "founders")
        .map(|a| a.recipient.clone());
    check(
        &mut out,
        "V2-founders-recipient-is-vesting-canister",
        founders_recipient.as_deref()
            == Some(manifest.vesting_init.founders_vesting_canister.as_str()),
        format!(
            "token founders recipient={:?} FOUNDERS_VESTING_CANISTER={}",
            founders_recipient, manifest.vesting_init.founders_vesting_canister
        ),
    );

    // Schedules: shape, uniqueness, manifest match, CHECKED sum binding.
    //
    // D-4 V2: the vesting canister custodies founders AND counsel. The manifest's
    // two schedule sections are concatenated IN ORDER — founders first, counsel
    // second — and the artifact's `schedules` vec must present them in that same
    // order. Concatenation order is the binding, so V5 stays a positional 1:1 zip
    // and no schedule can be silently reclassified between sections.
    let expected_schedules: Vec<(&ScheduleRow, u32, u32, &str)> = manifest
        .founder_schedule
        .iter()
        .map(|m| {
            (
                m,
                manifest.vesting_init.founder_cliff_months,
                manifest.vesting_init.founder_linear_months,
                FOUNDERS_CATEGORY_ID,
            )
        })
        .chain(manifest.counsel_schedule.iter().map(|m| {
            (
                m,
                APPROVED_COUNSEL_CLIFF_MONTHS,
                APPROVED_COUNSEL_LINEAR_MONTHS,
                COUNSEL_CATEGORY_ID,
            )
        }))
        .collect();

    // V3 is PER-SCHEDULE since D-4 V2: each schedule is measured against the shape
    // its own section pins, never against one global pair. A counsel schedule
    // wearing the founders shape (or the reverse) fails here.
    let shape_bad = vesting
        .schedules
        .iter()
        .zip(expected_schedules.iter())
        .find(|(s, (_, cliff, linear, _))| {
            s.cliff_months != *cliff || s.linear_months != *linear || s.total_amount == 0
        })
        .map(|(s, (_, cliff, linear, kind))| (s, *cliff, *linear, *kind));
    check(
        &mut out,
        "V3-founder-schedule-shape",
        shape_bad.is_none() && vesting.schedules.len() == expected_schedules.len(),
        match shape_bad {
            Some((s, cliff, linear, kind)) => format!(
                "{} ({}): cliff={} linear={} amount={} — expected cliff={}/linear={}",
                s.beneficiary, kind, s.cliff_months, s.linear_months, s.total_amount, cliff, linear
            ),
            None if vesting.schedules.len() != expected_schedules.len() => format!(
                "artifact schedules={} manifest schedules={}",
                vesting.schedules.len(),
                expected_schedules.len()
            ),
            None => format!(
                "founders cliff={}/linear={}, counsel cliff={}/linear={}, all nonzero",
                manifest.vesting_init.founder_cliff_months,
                manifest.vesting_init.founder_linear_months,
                APPROVED_COUNSEL_CLIFF_MONTHS,
                APPROVED_COUNSEL_LINEAR_MONTHS
            ),
        },
    );

    let mut seen = std::collections::HashSet::new();
    let dup = vesting.schedules.iter().find(|s| !seen.insert(s.beneficiary.as_str()));
    check(
        &mut out,
        "V4-unique-beneficiaries",
        dup.is_none(),
        dup.map(|s| format!("duplicate: {}", s.beneficiary)).unwrap_or_else(|| "unique".into()),
    );

    // V5 zips against the GENERALISED list (founders ++ counsel), not just founders.
    let manifest_rows_match = vesting.schedules.len() == expected_schedules.len()
        && vesting.schedules.iter().zip(expected_schedules.iter()).all(|(s, (m, _, _, _))| {
            s.beneficiary == m.beneficiary && s.total_amount == m.total_amount_base_units as u128
        });
    check(
        &mut out,
        "V5-schedules-match-manifest",
        manifest_rows_match,
        format!(
            "artifact rows={} manifest rows={} (founders={} + counsel={})",
            vesting.schedules.len(),
            expected_schedules.len(),
            manifest.founder_schedule.len(),
            manifest.counsel_schedule.len()
        ),
    );

    // V6 expects founders + counsel since D-4 V2. Still CHECKED arithmetic: an
    // overflow yields None and fails, never a wrapped total.
    let counsel_amount = allocation_amount(manifest, COUNSEL_CATEGORY_ID);
    let expected_vesting_total = match (founders_amount, counsel_amount) {
        (Some(f), Some(c)) => f.checked_add(c),
        _ => None,
    };
    let schedule_sum = vesting
        .schedules
        .iter()
        .try_fold(0u128, |acc, s| acc.checked_add(s.total_amount));
    check(
        &mut out,
        "V6-schedule-sum-eq-custody-allocation",
        expected_vesting_total.is_some() && schedule_sum == expected_vesting_total,
        format!(
            "checked Σ(schedules)={:?} expected founders+counsel={:?} (founders={:?} counsel={:?})",
            schedule_sum, expected_vesting_total, founders_amount, counsel_amount
        ),
    );

    // Each section's own sum must bind to its own allocation row — otherwise
    // founders and counsel could trade amounts while the widened total still
    // matched. V6 alone cannot see that; these two can.
    check(
        &mut out,
        "V7-founder-section-sum",
        section_sum(&manifest.founder_schedule) == founders_amount,
        format!(
            "Σ(founder_schedule)={:?} founders allocation={:?}",
            section_sum(&manifest.founder_schedule), founders_amount
        ),
    );
    check(
        &mut out,
        "V8-counsel-section-sum",
        section_sum(&manifest.counsel_schedule) == counsel_amount,
        format!(
            "Σ(counsel_schedule)={:?} counsel allocation={:?}",
            section_sum(&manifest.counsel_schedule), counsel_amount
        ),
    );

    out
}

// ── Gate-V phase 2 (post-install; pure — fed by live queries at genesis) ─────

/// `expected_custody_total` is founders + counsel since D-4 V2 — the parameter was
/// named `expected_founders_amount` when founders were the only tenant.
pub fn gate_v_post_install(
    vesting_canister_token_balance: u128,
    installed_schedule_sum: u128,
    expected_custody_total: u128,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    check(
        &mut out,
        "VP1-vesting-canister-balance",
        vesting_canister_token_balance == expected_custody_total,
        format!("balance={} expected={}", vesting_canister_token_balance, expected_custody_total),
    );
    check(
        &mut out,
        "VP2-installed-schedule-sum",
        installed_schedule_sum == expected_custody_total,
        format!("Σ(installed)={} expected={}", installed_schedule_sum, expected_custody_total),
    );
    out
}

// ── Whole-run helpers ─────────────────────────────────────────────────────────

pub struct GateReport {
    pub artifact_hashes: Vec<(String, String)>,
    pub checks: Vec<CheckResult>,
}

fn run_gates_from_strs(
    manifest_toml: &str,
    token_did: &str,
    vesting_did: &str,
    kit_toml: Option<&str>,
    vault: Option<&Principal>,
) -> Result<Vec<CheckResult>, String> {
    let manifest: Manifest =
        toml::from_str(manifest_toml).map_err(|e| format!("manifest parse: {}", e))?;
    let token = extract_token_init(&parse_artifact(token_did)?)?;
    let vesting = extract_vesting_init(&parse_artifact(vesting_did)?)?;
    let mut checks = gate_d(&manifest, &token, &vesting, kit_toml, vault);
    checks.extend(gate_v_pre_install(&manifest, &token, &vesting));
    Ok(checks)
}

/// **DPOOL-8** — the committed ceremony record exists and BINDS the same
/// verifying-key hash `[pool_init]` pins.
///
/// What this proves and what it does not (HARNESS_DELTA §2): it proves a record
/// of the right shape is present, committed, and bound to the same hash. It
/// does NOT make the record's contents true — a record is an attestation, not a
/// proof of independent contribution. Filling the template's unfilled markers is
/// A6.7's work, not this check's.
///
/// `repo_root` is the repository root (the record path in the manifest is
/// repo-relative), which is why this check is dir-keyed and cannot live in
/// `gate_d`'s string-only surface.
pub fn check_ceremony_record(repo_root: &Path, manifest: &Manifest) -> CheckResult {
    let rel = &manifest.pool_init.ceremony_record;
    let path = repo_root.join(rel);
    let (pass, detail) = match std::fs::read(&path) {
        Err(e) => (false, format!("ceremony_record={rel} unreadable: {e}")),
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            let binds = text.contains(&manifest.pool_init.vk_hash);
            (
                binds && !bytes.is_empty(),
                format!(
                    "ceremony_record={} bytes={} binds_vk_hash={}",
                    rel,
                    bytes.len(),
                    binds
                ),
            )
        }
    };
    CheckResult { name: "DPOOL-8-ceremony-record".to_string(), pass, detail }
}

// ── R-6 (G4): the VK pin + ceremony trust root ───────────────────────────────
//
// DPOOL-8 (above) proves the record contains the manifest's own vk_hash string
// — a shared substring, and nothing about the record's own content. A record
// replaced with one line holding that string still passes. The checks below
// add the two independent anchors that gap needs, WITHOUT editing either the
// ceremony record (A6.7's attestation) or the manifest's placeholder pin.

/// Repo-relative location of the committed VK pin registry. ONE resolution
/// rule, used by every gate-time consumer: `<repo_root>/` + this.
pub const VK_PIN_REL: &str = "scripts/verify_genesis_manifest/VK_PIN.toml";

/// Repo-relative location of the verifying-key artifact DPOOL-9 hashes.
pub const VK_ARTIFACT_REL: &str = "circuits/verification_key.json";

/// The 64-zero P0-3 placeholder `[pool_init].vk_hash` carries until the A6.7
/// re-ceremony runs. Written once, here — `check_manifest_posture` is the only
/// place the placeholder-equality test exists.
pub const VK_HASH_PLACEHOLDER: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// `scripts/verify_genesis_manifest/VK_PIN.toml`, parsed.
#[derive(Deserialize, Debug, Clone)]
pub struct VkPin {
    /// `"DEV"` pre-ceremony, `"PRODUCTION"` post-ceremony (DPOOL-9b).
    pub label: String,
    /// Provenance prose. Not compared by any check.
    pub source: String,
    /// sha256 of `circuits/verification_key.json` (DPOOL-9).
    pub sha256: String,
    /// sha256 of the ceremony record's whole, unedited byte content (DPOOL-8b).
    pub record_transcript: String,
}

/// Read + parse the pin from the SAME `repo_root` every DPOOL check receives.
pub fn load_vk_pin(repo_root: &Path) -> Result<VkPin, String> {
    let path = repo_root.join(VK_PIN_REL);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: parse: {e}", path.display()))
}

/// DPOOL-1b — NOT a comparison. Reports which of the two postures the
/// manifest's `[pool_init].vk_hash` is currently in, so DPOOL-9b and DPOOL-8a
/// each read ONE shared, named result instead of re-deriving the same
/// placeholder-equality test inline three times. This check ALWAYS passes —
/// its purpose is naming the state, not gating on it. A posture primitive that
/// could itself fail would turn "the manifest is still pre-ceremony" — the
/// CORRECT state at base — into a gate failure.
pub fn check_manifest_posture(manifest: &Manifest) -> CheckResult {
    let placeholder = manifest.pool_init.vk_hash == VK_HASH_PLACEHOLDER;
    let detail = if placeholder {
        "pending (pre-ceremony)".to_string()
    } else {
        "armed (post-ceremony)".to_string()
    };
    CheckResult { name: "DPOOL-1b-manifest-posture".to_string(), pass: true, detail }
}

/// True once `DPOOL-1b` reports the armed posture. Every downstream branch
/// reads THIS, never a second copy of the placeholder comparison.
fn posture_is_armed(manifest: &Manifest) -> bool {
    check_manifest_posture(manifest).detail.starts_with("armed")
}

/// DPOOL-9 — always-on. The verifying-key artifact on disk must hash to the
/// committed pin literal. This is the one genuinely independent external
/// source: the compiled-in constant and the disk artifact are the same bytes
/// read at different times, and the pool's `PINNED_VK_HASH` is a deploy-time
/// init argument (a `thread_local!`), not a source literal a host lint can read.
pub fn check_vk_artifact_pin(repo_root: &Path) -> CheckResult {
    let artifact = std::fs::read(repo_root.join(VK_ARTIFACT_REL));
    let (pass, detail) = match (artifact, load_vk_pin(repo_root)) {
        (Err(e), _) => (false, format!("vk_artifact_unreadable: {} {e}", VK_ARTIFACT_REL)),
        (_, Err(e)) => (false, format!("vk_pin_unreadable: {e}")),
        (Ok(bytes), Ok(pin)) => {
            let observed = sha256_hex(&bytes);
            let pass = observed == pin.sha256;
            let detail = if pass {
                format!("vk_artifact_pin_ok: computed={observed}")
            } else {
                format!(
                    "vk_artifact_pin_mismatch: artifact_side={observed} pin_side={}",
                    pin.sha256
                )
            };
            (pass, detail)
        }
    };
    CheckResult { name: "DPOOL-9-vk-artifact-pin".to_string(), pass, detail }
}

/// DPOOL-9b — posture-gated on DPOOL-1b. While the manifest still holds the
/// placeholder the pin must declare `label = "DEV"`; once the manifest is armed
/// it must declare `"PRODUCTION"`. This is what makes forgetting half of the
/// one-commit re-ceremony flip (§3.4) a gate failure rather than a silent drift.
pub fn check_vk_pin_label_posture(repo_root: &Path, manifest: &Manifest) -> CheckResult {
    let posture = check_manifest_posture(manifest);
    let expected = if posture_is_armed(manifest) { "PRODUCTION" } else { "DEV" };
    let (pass, detail) = match load_vk_pin(repo_root) {
        Err(e) => (false, format!("vk_pin_unreadable: {e}")),
        Ok(pin) => (
            pin.label == expected,
            format!(
                "vk_pin_label: posture={} label={} expected={}",
                posture.detail, pin.label, expected
            ),
        ),
    };
    CheckResult { name: "DPOOL-9b-vk-pin-label-posture".to_string(), pass, detail }
}

/// DPOOL-8a/8b — an INDEPENDENT anchor over the ceremony record's own content,
/// added ALONGSIDE (never replacing) `check_ceremony_record`/DPOOL-8. Merging
/// the two back into one function with a new signature would break
/// `n6_ceremony_record_must_exist_and_bind_the_same_hash`'s existing
/// two-argument call sites.
///
/// This function performs NO write to any ceremony document, ever.
///
/// `repo_root` resolves BOTH inputs — the record (via
/// `manifest.pool_init.ceremony_record`) and the pin (via
/// `<repo_root>/scripts/verify_genesis_manifest/VK_PIN.toml`) — so a test that
/// varies `repo_root` varies both together unless it ships a fixture
/// `VK_PIN.toml` under the temp root too.
///
/// The two failure `detail` prefixes are disjoint fixed literals BY DESIGN:
/// `record_transcript_mismatch` (bytes present, hash disagrees) and
/// `record_transcript_unreadable` (record or pin absent). A caller that wants
/// to prove a mismatch, not an absence, matches the first literal exactly — a
/// `contains("transcript")` test would be satisfied by either.
pub fn check_ceremony_record_anchor(
    repo_root: &Path,
    manifest: &Manifest,
    computed_vk_hash_hex: &str,
) -> Vec<CheckResult> {
    let armed = posture_is_armed(manifest);
    let rel = &manifest.pool_init.ceremony_record;
    let record = std::fs::read(repo_root.join(rel));

    // DPOOL-8a — posture-gated. While DPOOL-1b reports pending, this performs
    // NO comparison: the record correctly names the placeholder, and the
    // computed artifact hash is the DEV key's, so an always-on equality here
    // would be unsatisfiable at base (which is exactly why it is gated).
    let (pass_8a, detail_8a) = if !armed {
        (
            true,
            "pending (pre-ceremony) — record not yet expected to name the computed artifact hash"
                .to_string(),
        )
    } else {
        match &record {
            Err(e) => (false, format!("record_transcript_unreadable: {rel}: {e}")),
            Ok(bytes) => {
                let text = String::from_utf8_lossy(bytes);
                let names = text.contains(computed_vk_hash_hex);
                (
                    names,
                    format!(
                        "armed (post-ceremony) — record_names_computed_artifact_hash={names} \
                         computed={computed_vk_hash_hex}"
                    ),
                )
            }
        }
    };

    // DPOOL-8b — always-on. The record's whole-file sha256 must equal the pin's
    // `record_transcript`. This is the leg a junk record cannot satisfy: it
    // binds the record's own bytes, not a substring shared with the manifest.
    let (pass_8b, detail_8b) = match (&record, load_vk_pin(repo_root)) {
        (Err(e), _) => (false, format!("record_transcript_unreadable: {rel}: {e}")),
        (_, Err(e)) => (false, format!("record_transcript_unreadable: {e}")),
        (Ok(bytes), Ok(pin)) => {
            let observed_sha256 = sha256_hex(bytes);
            let pass = observed_sha256 == pin.record_transcript;
            let detail = if pass {
                format!("record_transcript_ok: computed={observed_sha256}")
            } else {
                format!(
                    "record_transcript_mismatch: computed={observed_sha256} pinned={}",
                    pin.record_transcript
                )
            };
            (pass, detail)
        }
    };

    vec![
        CheckResult {
            name: "DPOOL-8a-record-vs-artifact".to_string(),
            pass: pass_8a,
            detail: detail_8a,
        },
        CheckResult {
            name: "DPOOL-8b-record-transcript-anchor".to_string(),
            pass: pass_8b,
            detail: detail_8b,
        },
    ]
}

pub fn run_gates_on_dir(dir: &Path) -> Result<GateReport, String> {
    let read = |name: &str| -> Result<(String, String), String> {
        let path = dir.join(name);
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        Ok((String::from_utf8_lossy(&bytes).into_owned(), sha256_hex(&bytes)))
    };
    let (manifest_s, manifest_sha) = read("genesis_manifest.toml")?;
    let (token_s, token_sha) = read("stsh_token_init.did")?;
    let (vesting_s, vesting_sha) = read("vesting_init.did")?;
    // DPOOL-5/7's amended sources (RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13).
    // Both are committed records in THIS directory; an absent or malformed one
    // is carried through as `None`/`Err` and lands as a RED on the named check,
    // never as a skipped check.
    let kit_s = std::fs::read_to_string(dir.join("a7_install_kit.toml")).ok();
    let vault_p = match std::fs::read_to_string(dir.join("vault_authorities.toml")) {
        Err(_) => None,
        Ok(t) => toml::from_str::<VaultAuthorityVaultOnly>(&t)
            .ok()
            .and_then(|v| v.recovery.and_then(|r| r.vault))
            .and_then(|t| Principal::from_text(&t).ok()),
    };
    let mut checks =
        run_gates_from_strs(&manifest_s, &token_s, &vesting_s, kit_s.as_deref(), vault_p.as_ref())?;
    // DPOOL-8 is dir-keyed (the record path is repo-relative), so it joins the
    // check list here rather than inside gate_d's string-only surface. `dir` is
    // deployment/mainnet; the repo root is two levels up.
    let repo_root = dir.parent().and_then(|p| p.parent()).unwrap_or(dir).to_path_buf();
    let manifest: Manifest = toml::from_str(&manifest_s).map_err(|e| format!("manifest parse: {e}"))?;
    checks.push(check_ceremony_record(&repo_root, &manifest));
    // R-6 (G4): the VK pin + ceremony trust-root anchors. They join the SAME
    // `checks` vec, so `all_pass`, the CLI, the posture stage and every test
    // crate inherit the verdict with no new plumbing and no new gate
    // invocation — hence no GATE_TOOL_CENSUS.toml row (the `--posture` entry
    // already covers this tool's sole invocation).
    checks.push(check_manifest_posture(&manifest));
    checks.push(check_vk_artifact_pin(&repo_root));
    checks.push(check_vk_pin_label_posture(&repo_root, &manifest));
    // DPOOL-8a compares the record against the COMPUTED artifact hash once the
    // manifest is armed. An unreadable artifact leaves the computed hash empty,
    // which DPOOL-9 has already reported as a failure — 8a does not re-report it.
    let computed_vk_hash_hex = std::fs::read(repo_root.join(VK_ARTIFACT_REL))
        .map(|b| sha256_hex(&b))
        .unwrap_or_default();
    checks.extend(check_ceremony_record_anchor(&repo_root, &manifest, &computed_vk_hash_hex));
    // R-3 (H-3): the GP0..GP6 principal-binding family. Dir-keyed for the same
    // reason DPOOL-8 is — the record and the cross-bound authority record are
    // repo-relative files, not strings the caller supplies. Joining the SAME
    // `checks` vec means `all_pass`, the CLI, the posture stage and every test
    // crate inherit the verdict with no new plumbing: there is no
    // principal-binding-blind entry point on the dir surface.
    let token_parsed = extract_token_init(&parse_artifact(&token_s)?)?;
    let vesting_parsed = extract_vesting_init(&parse_artifact(&vesting_s)?)?;
    checks.extend(genesis_principal_gates(&repo_root, &manifest, &token_parsed, &vesting_parsed));
    Ok(GateReport {
        artifact_hashes: vec![
            ("genesis_manifest.toml".into(), manifest_sha),
            ("stsh_token_init.did".into(), token_sha),
            ("vesting_init.did".into(), vesting_sha),
        ],
        checks,
    })
}

// ── RR-1 replacement helper (test support, R4-1 lane A-4) ────────────────────
//
// Both retargeted positive tests and the new bite proofs need the SAME
// synthetic RR-1-replaced artifact set. It exists ONCE, here in the lib, so the
// two test crates (`scripts/verify_genesis_manifest/tests/*` and
// `integration-tests/tests/gate_v_fixture_tests.rs`) cannot drift apart.
//
// It ships in the lib deliberately rather than behind a `cfg(feature)`: this
// crate is HOST-ONLY and is never compiled into a canister (see the Cargo.toml
// header), so there is no binary-size or attack-surface cost, and a feature gate
// would require a Cargo.toml edit that lane A-4's scope fence forbids.
//
// Nothing is ever written to `deployment/mainnet/` — this is a pure
// string-to-string transform.

/// Collect the distinct P0-3 placeholder principals appearing as whole tokens
/// over the principal alphabet `[a-z0-9-]` in `text`, in sorted order.
fn collect_placeholder_tokens(text: &str, into: &mut Vec<String>) {
    let is_p = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    let mut cur = String::new();
    for c in text.chars().chain(std::iter::once('\n')) {
        if is_p(c) {
            cur.push(c);
        } else {
            if cur.ends_with(P0_3_PLACEHOLDER_SUFFIX) && !into.contains(&cur) {
                into.push(cur.clone());
            }
            cur.clear();
        }
    }
}

/// Build the RR-1-replaced (post-replacement) form of the three genesis inputs.
///
/// Every distinct P0-3 placeholder found across all three inputs is mapped to a
/// deterministic, VALID opaque principal — the SAME replacement in all three
/// outputs, so the cross-artifact bindings (D7/D8/D13/D14/V1/V2) survive.
///
/// The replacement text is derived via `Principal::to_text()` and never
/// hardcoded, so its checksum cannot be wrong.
///
/// Note for the reader: the TOML/DID PROSE COMMENTS still say "P0-3
/// placeholder" after replacement. That is cosmetic — every check decodes
/// principals and never scans raw file text.
pub fn rr1_replaced_fixture(
    manifest: &str,
    token_did: &str,
    vesting_did: &str,
) -> (String, String, String) {
    let mut tokens: Vec<String> = Vec::new();
    for src in [manifest, token_did, vesting_did] {
        collect_placeholder_tokens(src, &mut tokens);
    }
    tokens.sort();
    assert!(
        tokens.len() <= u8::MAX as usize,
        "RR-1 replacement map index must fit u8 (found {} placeholders)",
        tokens.len()
    );

    let mut out = [manifest.to_string(), token_did.to_string(), vesting_did.to_string()];
    for (i, placeholder) in tokens.iter().enumerate() {
        let replacement =
            Principal::from_slice(&[0xCA, 0xFE, 0, 0, 0, 0, 0, i as u8, 0x01]).to_text();
        for s in out.iter_mut() {
            *s = s.replace(placeholder.as_str(), replacement.as_str());
        }
    }
    let [m, t, v] = out;
    (m, t, v)
}

/// A member of the P0-3 placeholder family, BUILT rather than transcribed.
///
/// The family is exactly `[0xa0, idx] ++ b"placeholder"`, which is why every
/// member shares `P0_3_PLACEHOLDER_SUFFIX`: the trailing base32 groups are a
/// function of the common tail. Constructing one therefore reproduces a genuine
/// limb-1 member — it is rejected by the KNOWN-SET limb and reports that reason,
/// exactly as a committed placeholder did.
pub fn p0_3_placeholder(idx: u8) -> Principal {
    let mut bytes = vec![0xa0u8, idx];
    bytes.extend_from_slice(b"placeholder");
    Principal::from_slice(&bytes)
}

/// The INVERSE of `rr1_replaced_fixture`: take a RESOLVED input set and map it
/// back to a coherent PRE-RR-1 one, every distinct principal replaced by its own
/// P0-3 placeholder.
///
/// RR-1a (2026-09-12) is why this exists. The placeholder-family bite proofs —
/// "all eight DP3 site families are scanned", "every named field site is
/// rejected", the limb-1 reason text — used the COMMITTED artifacts as their
/// pre-RR-1 specimen. RR-1 resolves those artifacts once and for all, so a proof
/// anchored on them would have quietly shrunk to the one site RR-1b still leaves
/// placeholder and kept passing. Anchoring them on a DERIVED pre-RR-1 set keeps
/// the coverage claim at full strength for good, at every later posture.
///
/// Distinct-value mapping preserves every cross-artifact binding, including the
/// enumerated founders/counsel pair (one value in, one value out). `[pool_init]`
/// is covered as well as `principal_sites()`: its four trust roots are not sites,
/// but leaving them resolved while the rest reverts would manufacture DPOOL-4..7
/// mismatches that no caller asked for.
///
/// Nothing is written to `deployment/mainnet/` — a pure string-to-string
/// transform, as above.
pub fn placeholder_reverted_fixture(
    manifest_toml: &str,
    token_did: &str,
    vesting_did: &str,
) -> Result<(String, String, String), String> {
    let manifest: Manifest =
        toml::from_str(manifest_toml).map_err(|e| format!("manifest parse: {e}"))?;
    let token = extract_token_init(&parse_artifact(token_did)?)?;
    let vesting = extract_vesting_init(&parse_artifact(vesting_did)?)?;

    let mut distinct: Vec<String> = Vec::new();
    let mut note = |v: &str| {
        if !v.is_empty() && !distinct.iter().any(|d| d == v) {
            distinct.push(v.to_string());
        }
    };
    for site in principal_sites(&manifest, &token, &vesting) {
        note(&site.text);
    }
    for v in [
        &manifest.pool_init.token_canister,
        &manifest.pool_init.treasury_canister,
        &manifest.pool_init.staking_canister,
        &manifest.pool_init.controller,
    ] {
        note(v);
    }
    distinct.sort();
    if distinct.len() > u8::MAX as usize {
        return Err(format!("too many distinct principals to revert ({})", distinct.len()));
    }

    let mut out = [manifest_toml.to_string(), token_did.to_string(), vesting_did.to_string()];
    for (i, value) in distinct.iter().enumerate() {
        // Index 0 is skipped so no mapping can collide with the `0xa0 0x00`
        // member, which reads as an unallocated slot in the historical table.
        let replacement = p0_3_placeholder(i as u8 + 1).to_text();
        for s in out.iter_mut() {
            *s = s.replace(value.as_str(), replacement.as_str());
        }
    }
    let [m, t, v] = out;
    Ok((m, t, v))
}

/// Sum a schedule section's amounts, CHECKED. `None` on overflow — never wrapped.
fn section_sum(rows: &[ScheduleRow]) -> Option<u128> {
    rows.iter()
        .try_fold(0u128, |acc, r| acc.checked_add(r.total_amount_base_units as u128))
}

/// A named allocation row's amount, if the row exists.
fn allocation_amount(manifest: &Manifest, category_id: &str) -> Option<u128> {
    manifest
        .allocation
        .iter()
        .find(|a| a.category_id == category_id)
        .map(|a| a.amount_base_units as u128)
}

/// The total the genesis vesting canister must hold and pay out (Gate-V phase-2
/// expectation).
///
/// NAMING (O-C, builder disposition filed in the package): the historical name
/// `founders_amount` became a lie under D-4 V2 — the canister custodies founders
/// AND counsel. Renamed to `vesting_custody_total`; `founders_amount` is retained
/// below as a deprecated alias returning the FOUNDERS-ONLY figure, because
/// `gate_v_fixture_tests.rs` asserts that figure specifically (18e15) and
/// silently changing what an existing name returns is how a check stops meaning
/// what its test thinks it means.
pub fn vesting_custody_total(manifest_toml: &str) -> Result<u128, String> {
    let manifest: Manifest =
        toml::from_str(manifest_toml).map_err(|e| format!("manifest parse: {}", e))?;
    let founders = allocation_amount(&manifest, FOUNDERS_CATEGORY_ID)
        .ok_or_else(|| "no founders allocation row".to_string())?;
    let counsel = allocation_amount(&manifest, COUNSEL_CATEGORY_ID)
        .ok_or_else(|| "no legal_counsel allocation row".to_string())?;
    founders
        .checked_add(counsel)
        .ok_or_else(|| "founders + counsel overflows u128".to_string())
}

/// The manifest's founders allocation amount (FOUNDERS ONLY — see
/// `vesting_custody_total` for what the canister actually custodies).
pub fn founders_amount(manifest_toml: &str) -> Result<u128, String> {
    let manifest: Manifest =
        toml::from_str(manifest_toml).map_err(|e| format!("manifest parse: {}", e))?;
    manifest
        .allocation
        .iter()
        .find(|a| a.category_id == "founders")
        .map(|a| a.amount_base_units as u128)
        .ok_or_else(|| "no founders allocation in manifest".to_string())
}

// ═════════════════════════════════════════════════════════════════════════════
// R-3 (H-3, HOLD-LAUNCH) — GENESIS PRINCIPAL BINDING
// BRIEF_R3_GENESIS_PRINCIPAL_BINDING_V7_2026-09-04.md
// ═════════════════════════════════════════════════════════════════════════════
//
// THE DEFECT (§2): every check above verifies that a genesis principal is
// SHAPED like a principal and is NOT a known placeholder. None verifies WHICH
// principal it is. A substituted, typo'd or attacker-chosen principal, applied
// COHERENTLY to genesis_manifest.toml, stsh_token_init.did and vesting_init.did,
// passes D5/D7/D8/D10/D11/D13/D14/D15/V1/V2/D16 and the whole DP3 family, and is
// certified GREEN by Gate-D. The coherence family catches an INCONSISTENT RR-1
// and is structurally incapable of catching a CONSISTENT one.
//
// THE FIX: a source of truth that is NOT an install input —
// `deployment/mainnet/genesis_principals.toml`, consumed by this gate and by
// nothing else. It is the direct analogue of `vault_authorities.toml` +
// `verify_custody_manifest`'s authority binding, and reproduces its six
// properties: the record is separate from the install payload; an absent record
// fails CLOSED; a malformed record fails CLOSED and never skips; the violation
// function is pure; a denylist sits ON TOP of the record binding; and equality
// is over PRINCIPAL BYTES, never over text.
//
// WHAT IT DOES NOT PROVE (§3.3, §6.2 — the honest residual): a coherent
// FIVE-artifact edit — the three inputs, the record, and the record pin in this
// source file — that retains a pinned attestation digest is NOT detected. GP5 is
// an attestation POINTER, not a proof of provenance. That residual is asserted
// as an executable GREEN fact by `ac4c_five_artifact_coherent_edit_is_not_detected`
// so it cannot silently regress into a false claim of coverage.

/// The independent second source for genesis principal IDENTITY, repo-relative.
/// Consumed only by this gate — never by a deploy or install path.
pub const GENESIS_PRINCIPAL_RECORD: &str = "deployment/mainnet/genesis_principals.toml";

/// The custody authority record a cross-bound role reads its value FROM.
/// Read-only here; `verify_custody_manifest` owns it.
pub const GENESIS_VAULT_AUTHORITY_RECORD: &str = "deployment/mainnet/vault_authorities.toml";

/// The record's OWN schema version — deliberately NOT the genesis manifest's
/// `schema_version` (3). AC-11 asserts the two never conflate.
pub const GENESIS_PRINCIPAL_RECORD_SCHEMA_VERSION: u32 = 1;

/// Roles whose value is CROSS-BOUND — read from `vault_authorities.toml`, never
/// copied into the record. RR-1 ruling Q2 / freeze §14: the token's stored
/// staking principal is replaced with the VAULT principal, never with a
/// staking-canister principal, and the Vault's value already has an independent
/// in-repo source. A drift-lock, not a convenience: `GP1-binding-<ROLE>` fires
/// both ways (a listed role that is not cross-bound, and an unlisted role that
/// claims to be).
pub const VAULT_BOUND_ROLES: &[&str] = &[ROLE_STAKING_CANISTER];

/// Attestation digests BOUND TO THE EXACT ROLES THEY ATTEST (§3.3(b), B-5 /
/// SSoT O-4). A digest is still a POINTER to a reviewed ceremony/ruling record —
/// never a proof that the named principal is the one the ceremony produced — but
/// it is no longer a *global* pointer.
///
/// B-5 (Astra `DESIGN_B_WALLET_TOOLING_V1` §1.5, `ASTRA_PHASE2_ROADMAP_V1` §1.1
/// DTG-17): the previous shape was a flat `&[&str]` and GP5 was
/// `GENESIS_ATTESTATION_DIGESTS.contains(&p)` — plain membership. A role whose
/// `principal` had been copy-pasted from a DIFFERENT role, carrying any one of
/// the valid digests, passed GP5. The declaration's own prose already stated the
/// correspondence the code did not enforce; this promotes that prose to data.
/// O-4's trigger ("settle before any third digest is added") had already fired —
/// the RR-1b counsel digest was the third; RR-1b REDO retired it and pinned two
/// per-role beneficiary digests in its place, so the table now holds four.
///
/// The role lists below are the RECORD's, not an invention: they are exactly the
/// roles each record doc attests, read from `reviews/` before binding. Four
/// properties are enforced (see `GP5-*` in `check_principal_binding`):
/// **per-role binding** (a role's provenance must be the digest whose list names
/// IT), **total coverage** (every resolved role appears in exactly one list),
/// **no cross-role reuse** (the union is duplicate-free) and **no orphan digest**
/// (an empty role list fails, so a stale entry cannot linger).
///
/// A mis-transcribed role list turns the gate RED loudly rather than green
/// quietly — the safe failure direction.
pub const GENESIS_ATTESTATION_BINDINGS: &[(&str, &[&str])] = &[
    // CTO_CEREMONY_RESULT_ADDENDUM_2026-08-05.md — the Vault custody ceremony
    // record that rules `vault = cpdab-saaaa-aaaar-qca2q-cai` (freeze §14).
    // It attests the VAULT and nothing else; STAKING_CANISTER is the role whose
    // value IS the Vault principal (cross-bound, `VAULT_BOUND_ROLES`).
    (
        "c9f7400c9f771baf2f7417fc9933eab9132b3f3cdca32d14de1d9a94de6c3670",
        &[ROLE_STAKING_CANISTER],
    ),
    // reviews/RECORD_GENESIS_HOLDER_PRINCIPALS_2026-09-12.md — the Owner-supplied
    // genesis holder principals (eleven new passphrase-encrypted dfx identities,
    // plus the earlier-ruled vesting/token values), ruled by
    // reviews/RULING_RECORD_GENESIS_HOLDERS_2026-09-12.md. The FOURTEEN roles
    // listed below — and ONLY those — attest to THIS digest. dfx identities have
    // no derivation origin, so the WT-1 origin cutover does not touch them
    // (OQ-1, ruled 2026-09-19). FOUNDER_1_BENEFICIARY was moved OFF this list at
    // RR-1b REDO onto its own per-role digest below: it is Internet-Identity
    // derived and DID rotate.
    (
        "f27472f8cc4c2b3cd62153cdb8bd09ce3cfda1038a4d5c404648c367dd6f9930",
        &[
            "TREASURY_MULTISIG",
            "INSURANCE_MULTISIG",
            "FOUNDERS_VESTING_CANISTER",
            "STRATEGIC_GRANTS_MULTISIG",
            "CEREMONY_HOLDING",
            "BOUNTY_MULTISIG",
            "AIRDROP_PROGRAM",
            "CAPITAL_RESERVE_MULTISIG",
            "EXTERNAL_LP_INCENTIVES",
            "LIQUIDITY_MULTISIG",
            "LEGAL_COUNSEL_VESTING",
            "NEUTRAL_FEE_COLLECTOR",
            "STSH_TOKEN_CANISTER",
            "VESTING_CONTROLLER_MULTISIG",
        ],
    ),
    // reviews/RECORD_FOUNDER_1_BENEFICIARY_NATIVE_2026-09-21.md — the founder's
    // CANISTER-ROOTED (s3tyu native-origin) beneficiary principal, collected at
    // BOARD step 6 and CTO-attested. RR-1b REDO: FOUNDER_1_BENEFICIARY is
    // Internet-Identity derived, so the WT-1 `derivationOrigin` cutover made its
    // pre-cutover `app.stsh.fi` value an ALIAS the production wallet cannot
    // present. The role therefore moved OFF the blanket f27472f8… list onto this
    // per-role digest — one record, one role, per OQ-2.
    (
        "987805a1e9b6fcd2678255baa8710c61f4ad6a9e5a952926cc6eb41d3ae65ab9",
        &["FOUNDER_1_BENEFICIARY"],
    ),
    // reviews/RECORD_LEGAL_COUNSEL_BENEFICIARY_NATIVE_2026-09-21.md — counsel's
    // CANISTER-ROOTED beneficiary principal, collected at counsel's own native
    // login (the Owner witnessing, OQ-5) and CTO-attested. This SUPERSEDES the
    // RR-1b digest, which is REMOVED outright (OQ-4): git history and the office
    // records are the retention, so `GP5-no-orphan` never sees an empty list.
    // NOTE the deliberate split: LEGAL_COUNSEL_**VESTING** (the custodying
    // canister) is an RR-1a dfx role on f27472f8… above;
    // LEGAL_COUNSEL_**BENEFICIARY** is this one.
    (
        "e9d4a04ea78af7cc2c30e1a962683e396498b34f89298f93dd3150fbb86c12b3",
        &[ROLE_LEGAL_COUNSEL_BENEFICIARY],
    ),
];

/// Every pinned attestation digest, derived from the bindings so the two can
/// never drift apart. Order is the declaration's.
pub fn genesis_attestation_digests() -> Vec<&'static str> {
    GENESIS_ATTESTATION_BINDINGS.iter().map(|(d, _)| *d).collect()
}

/// `true` iff `digest` is pinned AND its role list names `role`. This is the
/// whole of B-5: membership alone is no longer sufficient.
pub fn attestation_binds(digest: &str, role: &str) -> bool {
    GENESIS_ATTESTATION_BINDINGS
        .iter()
        .any(|(d, roles)| *d == digest && roles.contains(&role))
}

/// The single digest that attests `role`, or `None` if no pinned digest does.
/// `None` is exactly the `GP5-coverage-<role>` failure.
pub fn attestation_digest_for_role(role: &str) -> Option<&'static str> {
    GENESIS_ATTESTATION_BINDINGS
        .iter()
        .find(|(_, roles)| roles.contains(&role))
        .map(|(d, _)| *d)
}

/// Principals that may NEVER be a genesis principal, ON TOP of the record
/// binding (closes A-4-F1: `principal_bytes_rejection_reason` deliberately
/// ACCEPTS the anonymous principal, so the denylist is where it is refused).
/// The record's EXACT committed bytes (§3.3(c)). `GP6-record-pin` fires on ANY
/// drift. Regenerate LAST, after every other edit to the record, in the SAME
/// diff:
///
/// ```text
/// sha256sum deployment/mainnet/genesis_principals.toml
/// ```
///
/// Pairing the record with a source constant is the point: the record cannot be
/// edited by anything that is not also editing reviewed source.
pub const GENESIS_PRINCIPAL_RECORD_SHA256: &str =
    "8caeedcf94c9bf5f71a682290f920b9b4847d1c9ed143e49690482b7ac684125";

pub const FORBIDDEN_GENESIS_PRINCIPALS: &[&str] = &[
    "2vxsx-fae",              // anonymous
    "aaaaa-aa",               // management canister
    "ryjl3-tyaaa-aaaaa-aaaba-cai", // NNS stand-ins, as in FORBIDDEN_AUTHORITY_PRINCIPALS
    "r7inp-6aaaa-aaaaa-aaabq-cai",
    "rkp4c-7iaaa-aaaaa-aaaca-cai",
    "rrkah-fqaaa-aaaaa-aaaaq-cai",
];

// ── The record ────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
pub struct GenesisPrincipalRecord {
    pub schema_version: u32,
    /// The DECLARED POSTURE the gate stage enforces (§6.1). It is an input to
    /// the stage's rule, never a licence: post-RR-1 it makes the stage STRICTER
    /// (the observed failing set must be exactly empty), not laxer.
    pub rr1_performed: bool,
    #[serde(default)]
    pub role: std::collections::BTreeMap<String, GenesisRoleEntry>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GenesisRoleEntry {
    /// A literal principal, or the sentinel `PENDING`. Absent for a cross-bound
    /// role — a role may carry `principal` or `binding`, never both.
    #[serde(default)]
    pub principal: Option<String>,
    /// `"vault_authorities"` for a cross-bound role.
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub provenance: Option<String>,
}

/// The sentinel an unresolved entry carries. A bare word on purpose — unlike
/// `custody_manifest.toml`'s `PENDING(<reason>)` form (§9), which is a different
/// file with a different grammar.
pub const RECORD_PENDING: &str = "PENDING";

/// `Ok(None)` = the record file does not exist. `Err` = present but unusable.
/// Both are fail-CLOSED at the caller (`GP0-record`); neither is ever a skip.
pub fn load_genesis_principal_record(
    root: &Path,
) -> Result<Option<(GenesisPrincipalRecord, Vec<u8>)>, String> {
    let path = root.join(GENESIS_PRINCIPAL_RECORD);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read {GENESIS_PRINCIPAL_RECORD}: {e}"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| format!("{GENESIS_PRINCIPAL_RECORD} is not valid UTF-8: {e}"))?;
    let rec: GenesisPrincipalRecord = toml::from_str(text)
        .map_err(|e| format!("malformed {GENESIS_PRINCIPAL_RECORD}: {e}"))?;
    if rec.schema_version != GENESIS_PRINCIPAL_RECORD_SCHEMA_VERSION {
        return Err(format!(
            "{GENESIS_PRINCIPAL_RECORD} record schema_version={} expected={} \
             (this is the RECORD's own schema, not the genesis manifest's)",
            rec.schema_version, GENESIS_PRINCIPAL_RECORD_SCHEMA_VERSION
        ));
    }
    for (role, e) in rec.role.iter() {
        if e.principal.is_some() && e.binding.is_some() {
            return Err(format!(
                "role {role} carries BOTH `principal` and `binding` — a role has exactly one source"
            ));
        }
        if e.principal.is_none() && e.binding.is_none() {
            return Err(format!("role {role} carries neither `principal` nor `binding`"));
        }
        if let Some(p) = e.principal.as_deref() {
            if p != RECORD_PENDING && Principal::from_text(p).is_err() {
                return Err(format!("role {role} has an unparseable principal `{p}`"));
            }
        }
    }
    Ok(Some((rec, bytes)))
}

/// The minimal, READ-ONLY view of `vault_authorities.toml` a cross-bound role
/// needs. Deliberately its own tiny struct rather than a dependency on
/// `verify_custody_manifest`: this crate must not gain a dependency edge to
/// another gate tool, and only one field is read.
/// The Vault principal lives at `[recovery].vault` (vault_authorities.toml:142),
/// NOT at the top level: it was pinned into the `[recovery]` section alongside
/// the roster it is recovered by. Reading the wrong path would make the
/// cross-bind silently unresolvable, so the location is asserted by
/// `ac14_vault_binding_reads_the_committed_record` against the committed file.
#[derive(Deserialize, Debug, Clone)]
struct VaultAuthorityVaultOnly {
    recovery: Option<VaultAuthorityRecovery>,
}

#[derive(Deserialize, Debug, Clone)]
struct VaultAuthorityRecovery {
    vault: Option<String>,
}

/// `Ok(None)` = the file is absent. `Err` = present but unusable, or missing the
/// `[recovery].vault` key. Both are `GP0-record` failures at the caller.
pub fn load_vault_bound_principal(root: &Path) -> Result<Option<Principal>, String> {
    let path = root.join(GENESIS_VAULT_AUTHORITY_RECORD);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {GENESIS_VAULT_AUTHORITY_RECORD}: {e}"))?;
    let t: VaultAuthorityVaultOnly = toml::from_str(&raw)
        .map_err(|e| format!("malformed {GENESIS_VAULT_AUTHORITY_RECORD}: {e}"))?;
    let v = t
        .recovery
        .and_then(|r| r.vault)
        .ok_or_else(|| format!("{GENESIS_VAULT_AUTHORITY_RECORD} has no `[recovery].vault` key"))?;
    Principal::from_text(&v)
        .map(Some)
        .map_err(|e| format!("{GENESIS_VAULT_AUTHORITY_RECORD} `vault` = `{v}` is unparseable: {e}"))
}

// ── §3.5.2 — ONE classification function ─────────────────────────────────────

/// The expected principal for a resolved role, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPrincipal {
    pub principal: Principal,
    /// Human-readable source, for the failing check's detail line.
    pub source: String,
}

/// A record entry is in EXACTLY ONE of two states (§3.5.1 rule 1). There is no
/// third state, and no cached or partial exemption: the record is re-read and
/// re-classified on every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryState {
    Pending,
    Resolved(ExpectedPrincipal),
    /// The role has no record entry at all. Distinguished from `Pending` so
    /// `GP1-role-missing-<ROLE>` can name it; it grants NO exemption — a role in
    /// this state is treated as unresolvable and never reaches GP2..GP5 with a
    /// borrowed value.
    Missing,
}

/// **INVARIANT 11 (§5).** EVERY `GPn` check that needs to know whether a role is
/// `Pending` or `Resolved` calls THIS function. No check may carry its own
/// separate string/enum test for the same question. `GP4-distinct`'s membership
/// is defined as "entries where this returns `Resolved`", so the only way to
/// reintroduce a "resolved role passes as if PENDING" regression is to touch this
/// predicate or one of its call sites — there is no second code path where the
/// same bug could hide. (M-16b is exactly that one-call-site mutation, and
/// `ac16d_resolved_role_cannot_regain_pending_exemption` is the assertion it
/// turns RED.)
pub fn record_entry_state(
    role: &str,
    record: &GenesisPrincipalRecord,
    vault_bound: Option<&Principal>,
) -> EntryState {
    let Some(e) = record.role.get(role) else {
        return EntryState::Missing;
    };
    if let Some(b) = e.binding.as_deref() {
        if b == "vault_authorities" {
            return match vault_bound {
                Some(p) => EntryState::Resolved(ExpectedPrincipal {
                    principal: *p,
                    source: format!("cross-bound: {GENESIS_VAULT_AUTHORITY_RECORD} `[recovery].vault`"),
                }),
                // The authority record is absent/unusable. GP0-record already
                // names that; the role must NOT fall through to `Pending` and
                // collect an exemption it has not earned.
                None => EntryState::Missing,
            };
        }
        return EntryState::Missing;
    }
    match e.principal.as_deref() {
        None => EntryState::Missing,
        Some(p) if p == RECORD_PENDING => EntryState::Pending,
        Some(p) => match Principal::from_text(p) {
            Ok(principal) => EntryState::Resolved(ExpectedPrincipal {
                principal,
                source: format!("{GENESIS_PRINCIPAL_RECORD} [role.{role}].principal"),
            }),
            Err(_) => EntryState::Missing,
        },
    }
}

// ── The GP0..GP6 family ───────────────────────────────────────────────────────

/// The check-name prefixes and exact names this family owns. Used by the posture
/// stage's classifier and by the tests; never by a `starts_with` allowed-set test
/// (§9: `GP1-pending-` and `GP1-pending-input-populated-` share a prefix).
pub const GP_PENDING_PREFIX: &str = "GP1-pending-";
pub const GP_PENDING_INPUT_POPULATED_PREFIX: &str = "GP1-pending-input-populated-";
pub const GP2_VALUE_PREFIX: &str = "GP2-value-";

/// PURE principal-binding violations (§3.5). Takes everything it needs by value
/// so it is fully testable in memory; all IO happens in `genesis_principal_gates`.
///
/// `record == None` ⇒ fail-CLOSED at `GP0-record`, never a skip, and NO per-role
/// check is emitted (there is no trustworthy basis to emit one).
#[allow(clippy::too_many_arguments)]
pub fn principal_binding_violations(
    sites: &[PrincipalSite],
    record: Option<&GenesisPrincipalRecord>,
    record_bytes: Option<&[u8]>,
    record_load_error: Option<&str>,
    vault_bound: Option<&Principal>,
    vault_load_error: Option<&str>,
    record_pin: &str,
) -> Vec<CheckResult> {
    let mut out: Vec<CheckResult> = Vec::new();

    // ── GP0-record — fail-closed, never skip ─────────────────────────────────
    let record = match (record, record_load_error) {
        (_, Some(e)) => {
            check(&mut out, "GP0-record", false, format!("{GENESIS_PRINCIPAL_RECORD}: {e}"));
            return out;
        }
        (None, None) => {
            check(
                &mut out,
                "GP0-record",
                false,
                format!(
                    "{GENESIS_PRINCIPAL_RECORD} is ABSENT — genesis principal identity is \
                     unpinned. This is fail-closed by design: an absent record is not a pass."
                ),
            );
            return out;
        }
        (Some(r), None) => r,
    };
    // A cross-bound role needs the authority record. Its absence or malformation
    // is the SAME GP0-record failure — the record family is one fail-closed unit.
    let roles_needing_vault = sites
        .iter()
        .any(|s| VAULT_BOUND_ROLES.contains(&s.role.as_str()))
        || record
            .role
            .iter()
            .any(|(_, e)| e.binding.as_deref() == Some("vault_authorities"));
    if roles_needing_vault {
        if let Some(e) = vault_load_error {
            check(&mut out, "GP0-record", false, format!("{GENESIS_VAULT_AUTHORITY_RECORD}: {e}"));
            return out;
        }
        if vault_bound.is_none() {
            check(
                &mut out,
                "GP0-record",
                false,
                format!(
                    "{GENESIS_VAULT_AUTHORITY_RECORD} is ABSENT, but a cross-bound role reads its \
                     `[recovery].vault` — fail-closed"
                ),
            );
            return out;
        }
    }
    check(
        &mut out,
        "GP0-record",
        true,
        format!(
            "{GENESIS_PRINCIPAL_RECORD} loaded, schema_version={}, rr1_performed={}, {} role entries",
            record.schema_version,
            record.rr1_performed,
            record.role.len()
        ),
    );

    // ── GP6-record-pin — over the WHOLE file's bytes, PENDING or not ─────────
    let observed_pin = record_bytes.map(sha256_hex).unwrap_or_default();
    check(
        &mut out,
        "GP6-record-pin",
        observed_pin == record_pin,
        format!(
            "sha256({GENESIS_PRINCIPAL_RECORD})={observed_pin} pinned={record_pin}"
        ),
    );

    // The manifest-derived role set, in first-appearance order (stable check
    // ordering), and the per-role site list. BOTH are derived from the SINGLE
    // site enumeration — never a second, independently maintained list (§9).
    let mut roles: Vec<&str> = Vec::new();
    for s in sites {
        if !roles.contains(&s.role.as_str()) {
            roles.push(s.role.as_str());
        }
    }

    // ── GP1-role-missing / GP1-role-extra — drift BOTH ways ──────────────────
    for role in roles.iter() {
        check(
            &mut out,
            &format!("GP1-role-missing-{role}"),
            record.role.contains_key(*role),
            if record.role.contains_key(*role) {
                format!("{role} has a record entry")
            } else {
                format!("manifest role {role} has NO entry in {GENESIS_PRINCIPAL_RECORD}")
            },
        );
    }
    for role in record.role.keys() {
        let known = roles.contains(&role.as_str());
        check(
            &mut out,
            &format!("GP1-role-extra-{role}"),
            known,
            if known {
                format!("{role} names a manifest role")
            } else {
                format!("{GENESIS_PRINCIPAL_RECORD} entry {role} names NO manifest role")
            },
        );
    }

    // ── GP1-binding — the RR-1 cross-binding ruling, drift-locked both ways ──
    for role in roles.iter() {
        let claims_binding = record
            .role
            .get(*role)
            .and_then(|e| e.binding.as_deref())
            .is_some();
        let should_bind = VAULT_BOUND_ROLES.contains(role);
        // Only emitted for roles that HAVE a record entry; a missing entry is
        // GP1-role-missing's business, not this check's.
        if !record.role.contains_key(*role) {
            continue;
        }
        let ok = claims_binding == should_bind
            && (!should_bind
                || record.role.get(*role).and_then(|e| e.binding.as_deref())
                    == Some("vault_authorities"));
        check(
            &mut out,
            &format!("GP1-binding-{role}"),
            ok,
            if ok {
                if should_bind {
                    format!("{role} is cross-bound to {GENESIS_VAULT_AUTHORITY_RECORD} `[recovery].vault`, as ruled")
                } else {
                    format!("{role} carries a literal value, as ruled")
                }
            } else if should_bind {
                format!(
                    "{role} is in VAULT_BOUND_ROLES and MUST be `binding = \"vault_authorities\"` \
                     — found binding={:?}, principal={:?}. Writing the Vault principal in as a \
                     literal duplicates the authority record instead of reading it (ruling Q2).",
                    record.role.get(*role).and_then(|e| e.binding.clone()),
                    record.role.get(*role).and_then(|e| e.principal.clone()),
                )
            } else {
                format!(
                    "{role} is NOT in VAULT_BOUND_ROLES but claims binding={:?}",
                    record.role.get(*role).and_then(|e| e.binding.clone())
                )
            },
        );
    }

    // ── Per-role, state-dependent family (§3.5.1 applicability order) ────────
    //
    // The order below IS the rule: a role's state is classified ONCE, by
    // `record_entry_state`, and the two arms are disjoint. `Pending` roles reach
    // GP1-pending / GP1-pending-input-populated and NOTHING ELSE; `Resolved`
    // roles reach GP2/GP3/GP5 and never GP1-pending. GP2..GP5 do not "skip" a
    // Pending role — they are never dispatched for it, which is what
    // `ac16b_pending_role_is_outside_gp2_gp3_gp4_gp5_domain` asserts structurally.
    let mut resolved: Vec<(&str, ExpectedPrincipal)> = Vec::new();
    for role in roles.iter() {
        if !record.role.contains_key(*role) {
            continue; // GP1-role-missing already fired; no exemption granted.
        }
        let state = record_entry_state(role, record, vault_bound);
        let role_sites: Vec<&PrincipalSite> =
            sites.iter().filter(|s| s.role.as_str() == *role).collect();
        match state {
            EntryState::Missing => { /* unresolvable; GP1-role-missing/GP0 own it */ }
            EntryState::Pending => {
                check(
                    &mut out,
                    &format!("{GP_PENDING_PREFIX}{role}"),
                    false,
                    format!(
                        "{role} is PENDING in {GENESIS_PRINCIPAL_RECORD} — its production \
                         principal is not yet pinned, so its {} install-input site(s) are \
                         unverifiable. Fail-closed until RR-1.",
                        role_sites.len()
                    ),
                );
                // GP1-pending-input-populated — the unresolved-record /
                // resolved-LOOKING-input mismatch. Reads the SAME site list the
                // DP3 scan walks (§9): a second enumeration here would silently
                // reopen the gap this check exists to close.
                let populated: Vec<&&PrincipalSite> = role_sites
                    .iter()
                    .filter(|s| placeholder_rejection_reason(&s.text).is_none())
                    .collect();
                check(
                    &mut out,
                    &format!("{GP_PENDING_INPUT_POPULATED_PREFIX}{role}"),
                    populated.is_empty(),
                    if populated.is_empty() {
                        format!("{role} is PENDING and all {} input site(s) are still placeholder", role_sites.len())
                    } else {
                        format!(
                            "{role}'s record entry is PENDING but {} install-input site(s) already \
                             carry a NON-placeholder principal: {}. An unresolved record with a \
                             populated input is exactly the state this gate exists to refuse — a \
                             value nothing has certified is already in the deploy payload.",
                            populated.len(),
                            populated
                                .iter()
                                .map(|s| format!("{} = {}", s.dp3_name, s.text))
                                .collect::<Vec<_>>()
                                .join("; ")
                        )
                    },
                );
            }
            EntryState::Resolved(exp) => {
                // ── GP2-value — THE H-3 FIX. Byte equality, never text. ──────
                let expected_bytes = exp.principal.as_slice().to_vec();
                let mismatches: Vec<String> = role_sites
                    .iter()
                    .filter(|s| {
                        Principal::from_text(&s.text)
                            .map(|p| p.as_slice().to_vec() != expected_bytes)
                            .unwrap_or(true)
                    })
                    .map(|s| format!("{} = {}", s.dp3_name, s.text))
                    .collect();
                check(
                    &mut out,
                    &format!("{GP2_VALUE_PREFIX}{role}"),
                    mismatches.is_empty(),
                    if mismatches.is_empty() {
                        format!(
                            "all {} site(s) equal {} ({})",
                            role_sites.len(),
                            exp.principal.to_text(),
                            exp.source
                        )
                    } else {
                        format!(
                            "{} of {} site(s) do NOT equal the recorded principal {} ({}): {}",
                            mismatches.len(),
                            role_sites.len(),
                            exp.principal.to_text(),
                            exp.source,
                            mismatches.join("; ")
                        )
                    },
                );
                // ── GP3-forbidden — denylist ON TOP of the record binding ────
                let text = exp.principal.to_text();
                let forbidden = FORBIDDEN_GENESIS_PRINCIPALS.contains(&text.as_str());
                let shape_bad = principal_bytes_rejection_reason(exp.principal.as_slice());
                check(
                    &mut out,
                    &format!("GP3-forbidden-{role}"),
                    !forbidden && shape_bad.is_none(),
                    if forbidden {
                        format!("{role}'s recorded principal {text} is on the genesis denylist")
                    } else if let Some(r) = shape_bad {
                        format!("{role}'s recorded principal {text} is unacceptable: {r}")
                    } else {
                        format!("{role} = {text} is not forbidden")
                    },
                );
                // ── GP5-provenance — the attestation POINTER (§3.3(b)) ──────
                // B-5: PER-ROLE binding, not global membership. A valid digest
                // copy-pasted onto the wrong role is now REJECTED.
                let prov = record.role.get(*role).and_then(|e| e.provenance.as_deref());
                let pinned = genesis_attestation_digests();
                let prov_ok = prov
                    .map(|p| !p.is_empty() && attestation_binds(p, role))
                    .unwrap_or(false);
                check(
                    &mut out,
                    &format!("GP5-provenance-{role}"),
                    prov_ok,
                    match prov {
                        None => format!("{role} is resolved but carries NO `provenance`"),
                        Some("") => format!("{role}'s `provenance` is empty"),
                        Some(p) if !pinned.contains(&p) => format!(
                            "{role}'s `provenance` {p} is not a pinned attestation digest"
                        ),
                        Some(p) => format!(
                            "{role}'s `provenance` {p} is PINNED but does NOT attest {role} \
                             (it attests: {}); the digest that attests {role} is {}",
                            GENESIS_ATTESTATION_BINDINGS
                                .iter()
                                .find(|(d, _)| *d == p)
                                .map(|(_, r)| r.join(", "))
                                .unwrap_or_default(),
                            attestation_digest_for_role(role).unwrap_or("NONE"),
                        ),
                    },
                );
                // ── GP5-coverage — every resolved role has a bound digest ────
                check(
                    &mut out,
                    &format!("GP5-coverage-{role}"),
                    attestation_digest_for_role(role).is_some(),
                    match attestation_digest_for_role(role) {
                        Some(d) => format!("{role} is attested by {d}"),
                        None => format!(
                            "{role} is RESOLVED but no pinned attestation digest names it — \
                             a role cannot silently lose its attestation"
                        ),
                    },
                );
                resolved.push((role, exp));
            }
        }
    }

    // ── GP5-no-reuse / GP5-no-orphan — properties OF THE BINDING TABLE ───────
    //
    // B-5. These do not depend on the record: they assert the table itself is
    // well-formed, so a mis-transcribed role list fails loudly here rather than
    // quietly weakening every per-role check above.
    {
        let mut seen: Vec<&str> = Vec::new();
        let mut dupes: Vec<String> = Vec::new();
        for (d, roles) in GENESIS_ATTESTATION_BINDINGS.iter() {
            for r in roles.iter() {
                if seen.contains(r) {
                    dupes.push(format!("{r} (again under {d})"));
                } else {
                    seen.push(r);
                }
            }
        }
        check(
            &mut out,
            "GP5-no-reuse",
            dupes.is_empty(),
            if dupes.is_empty() {
                format!(
                    "the {} attested role slots across {} digests are duplicate-free",
                    seen.len(),
                    GENESIS_ATTESTATION_BINDINGS.len()
                )
            } else {
                format!(
                    "a role is attested by MORE THAN ONE digest, so its provenance is \
                     ambiguous: {}",
                    dupes.join("; ")
                )
            },
        );
        let orphans: Vec<&str> = GENESIS_ATTESTATION_BINDINGS
            .iter()
            .filter(|(_, roles)| roles.is_empty())
            .map(|(d, _)| *d)
            .collect();
        check(
            &mut out,
            "GP5-no-orphan",
            orphans.is_empty(),
            if orphans.is_empty() {
                format!(
                    "every one of the {} pinned digests attests at least one role",
                    GENESIS_ATTESTATION_BINDINGS.len()
                )
            } else {
                format!(
                    "pinned digest(s) attest NO role — a stale entry that can never be \
                     reached must not linger: {}",
                    orphans.join(", ")
                )
            },
        );
    }

    // ── GP4-distinct — mirrors D16, AT THE RECORD ────────────────────────────
    //
    // Membership in the distinctness set is decided ONLY by `record_entry_state`
    // (invariant 11): the loop above pushed exactly the roles it classified
    // `Resolved`. The ENUMERATED exemption is the founders/counsel pair, named
    // never wildcarded — the genesis vesting canister is the schedule authority
    // for both rows (D-4 V2 §2 item 5), and any THIRD role joining that value
    // still fails.
    const GP4_EXEMPT_PAIR: [&str; 2] = [ROLE_FOUNDERS_VESTING_CANISTER, ROLE_LEGAL_COUNSEL_VESTING];
    let mut seen: std::collections::HashMap<Vec<u8>, Vec<&str>> = std::collections::HashMap::new();
    for (role, exp) in resolved.iter() {
        seen.entry(exp.principal.as_slice().to_vec()).or_default().push(role);
    }
    let collision = seen.iter().find(|(_, rs)| {
        rs.len() > 1
            && !(rs.len() == 2
                && rs.iter().all(|r| GP4_EXEMPT_PAIR.contains(r))
                && rs[0] != rs[1])
    });
    check(
        &mut out,
        "GP4-distinct",
        collision.is_none(),
        match collision {
            Some((bytes, rs)) => format!(
                "roles {:?} share the recorded principal {} — outside the enumerated {:?} pair, \
                 two genesis roles sharing one principal collapses one allocation into another",
                rs,
                Principal::from_slice(bytes).to_text(),
                GP4_EXEMPT_PAIR
            ),
            None => format!(
                "{} resolved role(s), principals distinct except the enumerated {:?} pair",
                resolved.len(),
                GP4_EXEMPT_PAIR
            ),
        },
    );

    out
}

/// IO wrapper: load the record + the authority record from `root` and run the
/// pure violation function over the sites of the given inputs.
pub fn genesis_principal_gates(
    root: &Path,
    manifest: &Manifest,
    token: &ParsedTokenInit,
    vesting: &ParsedVestingInit,
) -> Vec<CheckResult> {
    let sites = principal_sites(manifest, token, vesting);
    let (rec, bytes, rec_err) = match load_genesis_principal_record(root) {
        Ok(Some((r, b))) => (Some(r), Some(b), None),
        Ok(None) => (None, None, None),
        Err(e) => (None, None, Some(e)),
    };
    let (vault, vault_err) = match load_vault_bound_principal(root) {
        Ok(v) => (v, None),
        Err(e) => (None, Some(e)),
    };
    principal_binding_violations(
        &sites,
        rec.as_ref(),
        bytes.as_deref(),
        rec_err.as_deref(),
        vault.as_ref(),
        vault_err.as_deref(),
        GENESIS_PRINCIPAL_RECORD_SHA256,
    )
}

// ── §6.1 — the posture stage's rule ──────────────────────────────────────────
//
// A naive `verify_genesis_manifest || die` would leave `./run_gate.sh`
// permanently RED until RR-1, which is why the tool was not in the gate at all.
// The stage asserts the DECLARED POSTURE instead — and the declaration is not a
// licence: post-RR-1 it makes the stage STRICTER, not laxer.
//
// PRE-RR-1 (`rr1_performed = false`): the observed failing set must be a SUBSET
// of a CLOSED, EXACT-MATCH allowed set with exactly three members:
//   1. `DP3-*`                    — every named placeholder-rejection SITE.
//   2. `GP1-pending-<ROLE>`       — a role with no in-repo value at all.
//   3. `GP2-value-STAKING_CANISTER` — and ONLY while that role's own DP3 sites
//                                   are also failing (still placeholder). The
//                                   moment a non-placeholder value is written
//                                   there, a mismatch fails the stage.
//
// POST-RR-1 (`rr1_performed = true`): the observed failing set must be EXACTLY
// EMPTY. Not "no failures are expected" — an assertion over the ACTUALLY
// OBSERVED vector, so a future check added anywhere participates automatically
// with no second list to update.
//
// `GP1-pending-input-populated-<ROLE>` is NEVER in the allowed set, at ANY
// posture. It and `GP1-pending-<ROLE>` share a textual prefix, which is exactly
// why membership is EXACT-MATCH over a built set and never `str::starts_with`.

/// The runtime marker the stage prints on EVERY invocation, pass or fail. It is
/// load-bearing for AC-12/M-12b's behavioural self-test: a check that the stage
/// RAN must observe something only a running stage emits, never a grep of
/// `run_gate.sh`'s own source text. Do not remove or rename it without updating
/// that self-test in the same diff.
pub const POSTURE_MARKER: &str = "GENESIS-POSTURE-STAGE:";

/// Build the CLOSED pre-RR-1 allowed failing set — a real set of exact names,
/// derived from the SINGLE site enumeration, never a prefix rule.
pub fn posture_allowed_pre_rr1(
    sites: &[PrincipalSite],
    failing: &[String],
) -> std::collections::BTreeSet<String> {
    let mut allowed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // 1. Every named placeholder-rejection SITE. `DP3-scan-coverage` is a
    //    coverage cardinality check, NOT a site, and is deliberately absent — if
    //    it ever fails, the stage fails.
    for s in sites {
        allowed.insert(s.dp3_name.clone());
    }
    // 2. A role with no in-repo value at all. A role that IS cross-bound has an
    //    in-repo value from day one, so its `GP1-pending-*` is NOT tolerated.
    let mut roles: Vec<&str> = Vec::new();
    for s in sites {
        if !roles.contains(&s.role.as_str()) {
            roles.push(s.role.as_str());
        }
    }
    for role in roles.iter() {
        if !VAULT_BOUND_ROLES.contains(role) {
            allowed.insert(format!("{GP_PENDING_PREFIX}{role}"));
        }
    }
    // 3. `GP2-value-<ROLE>` for a cross-bound role — tolerated ONLY while that
    //    role's own DP3 sites are ALSO failing (i.e. the inputs are still
    //    placeholder and RR-1 genuinely has not run for it).
    for role in VAULT_BOUND_ROLES.iter() {
        let own_dp3: Vec<&PrincipalSite> =
            sites.iter().filter(|s| s.role.as_str() == *role).collect();
        let all_own_dp3_failing = !own_dp3.is_empty()
            && own_dp3.iter().all(|s| failing.iter().any(|f| f == &s.dp3_name));
        if all_own_dp3_failing {
            allowed.insert(format!("{GP2_VALUE_PREFIX}{role}"));
        }
    }
    // 4. (A-7 REBASE, RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13) The pool trust
    //    roots. `[pool_init]`'s four principals are NOT `principal_sites`, so
    //    they have no `DP3-*` name and rule 1 never reaches them — yet a
    //    genuinely pre-RR-1 tree carries P0-3 placeholders there, which is what
    //    the amended DPOOL-5/7 and the new DPOOL-5b RED on.
    //
    //    Tolerated ONLY while `DPOOL-5b` is ITSELF failing — i.e. a placeholder
    //    literal is genuinely still present in one of those four fields. That is
    //    the same self-limiting shape as rule 3: the moment real principals are
    //    written in, DPOOL-5b passes, this branch stops firing, and a DPOOL-5 or
    //    DPOOL-7 mismatch is a hard posture failure with nothing to hide behind.
    const DPOOL_PLACEHOLDER_LIMB: &str = "DPOOL-5b-no-placeholder-trust-root";
    if failing.iter().any(|f| f == DPOOL_PLACEHOLDER_LIMB) {
        allowed.insert(DPOOL_PLACEHOLDER_LIMB.to_string());
        allowed.insert("DPOOL-5-treasury".to_string());
        allowed.insert("DPOOL-7-controller".to_string());
    }
    allowed
}

/// The posture stage's verdict.
#[derive(Debug, Clone)]
pub struct PostureVerdict {
    pub rr1_performed: bool,
    /// Every failing check name observed, in emission order.
    pub failing: Vec<String>,
    /// The failing names that are NOT permitted at this posture. Empty ⇒ pass.
    pub disallowed: Vec<String>,
    /// The closed allowed set actually applied (empty post-RR-1).
    pub allowed: Vec<String>,
}

impl PostureVerdict {
    pub fn passes(&self) -> bool {
        self.disallowed.is_empty()
    }
}

/// Evaluate the declared posture against the OBSERVED failing set (§6.1).
pub fn evaluate_posture(
    rr1_performed: bool,
    failing: &[String],
    sites: &[PrincipalSite],
) -> PostureVerdict {
    if rr1_performed {
        // Post-RR-1: the pass condition is "the observed failing set is EMPTY".
        // Implemented as an assertion over the collected vector, NOT as a fixed
        // list that happens to be empty by convention.
        return PostureVerdict {
            rr1_performed,
            failing: failing.to_vec(),
            disallowed: failing.to_vec(),
            allowed: Vec::new(),
        };
    }
    let allowed = posture_allowed_pre_rr1(sites, failing);
    let disallowed: Vec<String> =
        failing.iter().filter(|f| !allowed.contains(*f)).cloned().collect();
    PostureVerdict {
        rr1_performed,
        failing: failing.to_vec(),
        disallowed,
        allowed: allowed.into_iter().collect(),
    }
}

/// Run the full gate over `dir` and evaluate the declared posture. `dir` is the
/// deployment directory; the record and the authority record are read from the
/// repo root two levels up, exactly as `DPOOL-8` resolves its record path.
pub fn run_posture_on_dir(dir: &Path) -> Result<(PostureVerdict, Vec<CheckResult>), String> {
    let report = run_gates_on_dir(dir)?;
    let root = dir.parent().and_then(|p| p.parent()).unwrap_or(dir).to_path_buf();
    let manifest_s = std::fs::read_to_string(dir.join("genesis_manifest.toml"))
        .map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Manifest =
        toml::from_str(&manifest_s).map_err(|e| format!("manifest parse: {e}"))?;
    let token = extract_token_init(&parse_artifact(&std::fs::read_to_string(
        dir.join("stsh_token_init.did"),
    ).map_err(|e| format!("read token init: {e}"))?)?)?;
    let vesting = extract_vesting_init(&parse_artifact(&std::fs::read_to_string(
        dir.join("vesting_init.did"),
    ).map_err(|e| format!("read vesting init: {e}"))?)?)?;
    let sites = principal_sites(&manifest, &token, &vesting);

    // The DECLARED posture is read from the record. An unreadable record cannot
    // declare anything — fail closed at `rr1_performed = false`, which is the
    // strict branch pre-RR-1 (GP0-record is already failing and is not in the
    // allowed set, so the stage fails either way; this only picks which rule
    // prints).
    let rr1 = load_genesis_principal_record(&root)
        .ok()
        .flatten()
        .map(|(r, _)| r.rr1_performed)
        .unwrap_or(false);

    let failing: Vec<String> =
        report.checks.iter().filter(|c| !c.pass).map(|c| c.name.clone()).collect();
    Ok((evaluate_posture(rr1, &failing, &sites), report.checks))
}

/// String-surface equivalent of `run_gates_on_dir` INCLUDING the `GP*` family —
/// the record and the authority record supplied as text rather than read from
/// disk.
///
/// This exists so the principal-binding family is exercised by exactly the same
/// code path the dir surface uses while remaining testable in memory. It is the
/// surface the retargeted positive tests use: before R-3, `t3` proved an
/// RR-1-replaced set passes every COHERENCE check, which is now only part of the
/// claim — the control AC-1 needs is "the same substitution, WITH A MATCHING
/// RECORD, is green", and that cannot be stated on a record-blind surface.
///
/// `DPOOL-8` is dir-keyed and therefore absent here, exactly as on
/// `run_gates_from_strs`.
pub fn run_gates_from_strs_with_record(
    manifest_toml: &str,
    token_did: &str,
    vesting_did: &str,
    record_toml: Option<&str>,
    vault_authorities_toml: Option<&str>,
    record_pin: &str,
    // `a7_install_kit.toml`, DPOOL-5's amended source. Appended rather than
    // slotted beside `vault_authorities_toml` so the existing call sites read as
    // one mechanical extension; `None` is fail-closed on DPOOL-5.
    kit_toml: Option<&str>,
) -> Result<Vec<CheckResult>, String> {
    let manifest: Manifest =
        toml::from_str(manifest_toml).map_err(|e| format!("manifest parse: {}", e))?;
    let token = extract_token_init(&parse_artifact(token_did)?)?;
    let vesting = extract_vesting_init(&parse_artifact(vesting_did)?)?;

    // Same fail-closed classification the IO wrapper performs, over strings.
    let (rec, bytes, rec_err) = match record_toml {
        None => (None, None, None),
        Some(t) => match toml::from_str::<GenesisPrincipalRecord>(t) {
            Err(e) => (None, None, Some(format!("malformed {GENESIS_PRINCIPAL_RECORD}: {e}"))),
            Ok(r) if r.schema_version != GENESIS_PRINCIPAL_RECORD_SCHEMA_VERSION => (
                None,
                None,
                Some(format!(
                    "{GENESIS_PRINCIPAL_RECORD} record schema_version={} expected={} \
                     (this is the RECORD's own schema, not the genesis manifest's)",
                    r.schema_version, GENESIS_PRINCIPAL_RECORD_SCHEMA_VERSION
                )),
            ),
            Ok(r) => {
                let mut err = None;
                for (role, e) in r.role.iter() {
                    if e.principal.is_some() && e.binding.is_some() {
                        err = Some(format!(
                            "role {role} carries BOTH `principal` and `binding` — a role has \
                             exactly one source"
                        ));
                        break;
                    }
                    if e.principal.is_none() && e.binding.is_none() {
                        err = Some(format!("role {role} carries neither `principal` nor `binding`"));
                        break;
                    }
                    if let Some(p) = e.principal.as_deref() {
                        if p != RECORD_PENDING && Principal::from_text(p).is_err() {
                            err = Some(format!("role {role} has an unparseable principal `{p}`"));
                            break;
                        }
                    }
                }
                match err {
                    Some(e) => (None, None, Some(e)),
                    None => (Some(r), Some(t.as_bytes().to_vec()), None),
                }
            }
        },
    };
    let (vault, vault_err) = match vault_authorities_toml {
        None => (None, None),
        Some(t) => match toml::from_str::<VaultAuthorityVaultOnly>(t) {
            Err(e) => (None, Some(format!("malformed {GENESIS_VAULT_AUTHORITY_RECORD}: {e}"))),
            Ok(v) => match v.recovery.and_then(|r| r.vault) {
                None => (
                    None,
                    Some(format!("{GENESIS_VAULT_AUTHORITY_RECORD} has no `[recovery].vault` key")),
                ),
                Some(text) => match Principal::from_text(&text) {
                    Ok(p) => (Some(p), None),
                    Err(e) => (
                        None,
                        Some(format!(
                            "{GENESIS_VAULT_AUTHORITY_RECORD} `vault` = `{text}` is unparseable: {e}"
                        )),
                    ),
                },
            },
        },
    };

    // gate_d runs HERE, not above: DPOOL-7's amended source is the very `vault`
    // this function has just parsed, so the check must not be built before it.
    let mut checks = gate_d(&manifest, &token, &vesting, kit_toml, vault.as_ref());
    checks.extend(gate_v_pre_install(&manifest, &token, &vesting));

    let sites = principal_sites(&manifest, &token, &vesting);
    checks.extend(principal_binding_violations(
        &sites,
        rec.as_ref(),
        bytes.as_deref(),
        rec_err.as_deref(),
        vault.as_ref(),
        vault_err.as_deref(),
        record_pin,
    ));
    Ok(checks)
}

// ── R-3 test support: the record that MATCHES a given input set ──────────────
//
// Ships in the lib for the same reason `rr1_replaced_fixture` does (see its
// header): this crate is HOST-ONLY and is never compiled into a canister, and
// both test crates — `scripts/verify_genesis_manifest/tests/*` and
// `integration-tests/tests/gate_v_fixture_tests.rs` — need the SAME record for
// the SAME replaced inputs. One definition, so the two cannot drift.
//
// Nothing here is ever written to `deployment/mainnet/`: pure string transforms.

/// The RR-1-replaced input set, with the CROSS-BOUND role additionally pinned to
/// `vault_text`.
///
/// `rr1_replaced_fixture` maps every placeholder to a synthetic principal,
/// including `STAKING_CANISTER`'s — but that role's value is not free: it is
/// cross-bound to `vault_authorities.toml`'s `[recovery].vault`, so a synthetic
/// value there is a genuine `GP2-value-STAKING_CANISTER` mismatch. A positive
/// control must therefore write the REAL Vault principal at those sites, which
/// is exactly what a real RR-1 does (freeze §14).
pub fn rr1_replaced_fixture_with_vault(
    manifest: &str,
    token_did: &str,
    vesting_did: &str,
    vault_text: &str,
) -> (String, String, String) {
    let (m, t, v) = rr1_replaced_fixture(manifest, token_did, vesting_did);
    let parsed: Manifest = match toml::from_str(&m) {
        Ok(p) => p,
        Err(_) => return (m, t, v),
    };
    let synthetic = parsed.token_init.staking_canister.clone();
    (
        m.replace(&synthetic, vault_text),
        t.replace(&synthetic, vault_text),
        v.replace(&synthetic, vault_text),
    )
}

/// Build a `genesis_principals.toml` that RESOLVES every role of the given input
/// set to the value those inputs actually carry — the positive control for the
/// `GP*` family. `rr1_performed` is written as given.
///
/// Roles in `VAULT_BOUND_ROLES` are emitted as cross-bindings, never as literals
/// (writing the Vault value in as a literal is `GP1-binding-*`, by design).
pub fn record_matching(
    manifest_toml: &str,
    token_did: &str,
    vesting_did: &str,
    rr1_performed: bool,
) -> Result<String, String> {
    let manifest: Manifest =
        toml::from_str(manifest_toml).map_err(|e| format!("manifest parse: {e}"))?;
    let token = extract_token_init(&parse_artifact(token_did)?)?;
    let vesting = extract_vesting_init(&parse_artifact(vesting_did)?)?;
    let sites = principal_sites(&manifest, &token, &vesting);

    let mut roles: Vec<&str> = Vec::new();
    for s in sites.iter() {
        if !roles.contains(&s.role.as_str()) {
            roles.push(s.role.as_str());
        }
    }
    if GENESIS_ATTESTATION_BINDINGS.is_empty() {
        return Err("no attestation digests pinned".to_string());
    }

    let mut out = String::new();
    out.push_str("schema_version = 1\n");
    out.push_str(&format!("rr1_performed  = {rr1_performed}\n"));
    for role in roles {
        out.push_str(&format!("\n[role.{role}]\n"));
        if VAULT_BOUND_ROLES.contains(&role) {
            out.push_str("binding    = \"vault_authorities\"\n");
        } else {
            let value = sites
                .iter()
                .find(|s| s.role == role)
                .map(|s| s.text.clone())
                .ok_or_else(|| format!("no site for role {role}"))?;
            out.push_str(&format!("principal  = \"{value}\"\n"));
        }
        // B-5: the digest is looked up PER ROLE, never `[0]`. A role with no
        // binding is a coverage defect the generator must not paper over.
        let digest = attestation_digest_for_role(role)
            .ok_or_else(|| format!("no pinned attestation digest attests role {role}"))?;
        out.push_str(&format!("provenance = \"{digest}\"\n"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repo root, from this crate's manifest dir (`scripts/verify_genesis_manifest`).
    fn repo_root_of_tree() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap() // scripts/
            .parent()
            .unwrap() // workspace root
            .to_path_buf()
    }

    /// A6.6 / A66-VK-CHAIN — the DPOOL-9 committed-artifact lock, exercised as a
    /// behaviour rather than asserted as a fact.
    ///
    /// `check_vk_artifact_pin` is invoked TWICE over two different repo roots:
    /// the real tree, whose `circuits/verification_key.json` matches `VK_PIN.toml`,
    /// and a shadow tree identical except for ONE tampered byte in the VK. The two
    /// `CheckResult.pass` values must differ. A lock that returned the same verdict
    /// for both would be a lock in name only — which is exactly the failure mode
    /// the A6.6 dev-chain regeneration could have introduced, since every VK-hash
    /// copy in the tree moved in that one commit.
    // BINDING: A66-VK-CHAIN
    #[test]
    fn test_dpool9_vk_pin_detects_tampered_artifact() {
        let real_root = repo_root_of_tree();
        let good = check_vk_artifact_pin(&real_root);
        assert!(
            good.pass,
            "the committed VK must match VK_PIN.toml in a clean tree: {}",
            good.detail
        );

        // Shadow tree: same VK_PIN.toml, one flipped byte in the VK artifact.
        let shadow = std::env::temp_dir()
            .join(format!("stsh-a66-vkchain-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&shadow);
        std::fs::create_dir_all(shadow.join("circuits")).unwrap();
        std::fs::create_dir_all(shadow.join(VK_PIN_REL).parent().unwrap()).unwrap();
        std::fs::copy(real_root.join(VK_PIN_REL), shadow.join(VK_PIN_REL)).unwrap();

        let mut bytes = std::fs::read(real_root.join(VK_ARTIFACT_REL)).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // one byte, one bit
        std::fs::write(shadow.join(VK_ARTIFACT_REL), &bytes).unwrap();

        let tampered = check_vk_artifact_pin(&shadow);
        assert_ne!(
            good.pass, tampered.pass,
            "DPOOL-9 must distinguish the committed VK from a one-byte-tampered copy \
             (good={}, tampered={})",
            good.detail, tampered.detail
        );
        assert!(
            tampered.detail.starts_with("vk_artifact_pin_mismatch"),
            "the tampered verdict must be a digest mismatch, not an unreadable file: {}",
            tampered.detail
        );

        let _ = std::fs::remove_dir_all(&shadow);
    }
}
