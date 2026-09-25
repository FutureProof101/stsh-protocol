// =============================================================================
// STSH — P-ARITH G-2: Gate-V two-phase FIXTURE PROOF (AR-6)
// =============================================================================
//
// Phase 1 (pre-install) runs the real verifier over the canonical artifacts
// (deployment/mainnet/*). Phase 2 (post-install) drives a LIVE PocketIC install
// whose VALUES come from those artifacts, then proves the token balance of the
// vesting canister AND the installed schedule sum both equal the founders
// allocation — through the SAME gate_v_post_install checker the release CLI
// uses.
//
// R4-1 (lane A-4): the COMMITTED artifacts still carry P0-3 placeholder
// principals, and Gate-D now REFUSES them fail-closed. Phase 1 therefore
// asserts the real genesis shape — the RR-1-replaced set passes the full gates
// — and additionally asserts that the committed set is rejected, so this file
// carries the R4-1 verdict too. (Before this change phase 1 asserted the
// committed set PASSED; that claim is now false by design.)
//
// FIXTURE SUBSTITUTION (inherent, documented): placeholder principals are not
// installable canister ids, so the live install rewrites exactly two wires —
// founders recipient -> the LIVE vesting canister id, and vesting
// token_canister -> the LIVE token id. Every amount, category, policy and
// schedule value flows from the artifacts unchanged. At genesis (RR-3) the
// real artifacts carry the real canister ids and NOTHING is rewritten.
//
// PREREQUISITES: Law #7 phase 2 build (stsh_token + vesting release Wasms),
// POCKET_IC_BIN exported.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use verify_genesis_manifest as vgm;
const A7_REBASE_DEPLOYMENT_REL: &str = "../deployment/mainnet";

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


fn token_wasm() -> Vec<u8> {
    std::fs::read(env!("TOKEN_WASM")).expect("build stsh_token release Wasm first (Law #7)")
}
fn vesting_wasm() -> Vec<u8> {
    std::fs::read(env!("VESTING_WASM")).expect("build vesting release Wasm first (Law #7)")
}

fn deployment_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deployment/mainnet")
}

// ── Wire mirrors (match canisters/token + canisters/vesting) ─────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy {
    cliff_end_ns: u64,
    vesting_end_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String,
    category_name: String,
    amount: u128,
    recipient: Principal,
    subaccount: Option<[u8; 32]>,
    lock_policy: LockPolicy,
    vesting_policy: Option<VestingPolicy>,
    created_at_genesis: bool,
    genesis_timestamp_ns: u64,
}

#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
    fee_collector: Option<Principal>,
}

#[derive(CandidType, Deserialize)]
struct VestingInitArgs {
    token_canister: Principal,
    controller: Principal,
    schedules: Vec<NewSchedule>,
}

#[derive(CandidType, Deserialize)]
struct NewSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_months: u32,
    linear_months: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_end_ns: u64,
    vesting_end_ns: u64,
    claimed: u128,
    start_ns: u64,
}

fn lock_policy_from(tag: &str) -> LockPolicy {
    match tag {
        "ImmediatelyLiquid" => LockPolicy::ImmediatelyLiquid,
        "Vested" => LockPolicy::Vested,
        "GovernanceLocked" => LockPolicy::GovernanceLocked,
        other => panic!("unexpected lock_policy in artifact: {}", other),
    }
}

/// Restore the two EXTERNALLY-pinned `[pool_init]` trust roots into a derived
/// manifest.
///
/// RR-1b: `placeholder_reverted_fixture` reverts all four `[pool_init]`
/// principals and a wholesale RR-1 replacement then rewrites them. Two of the
/// four are checked against the manifest itself and so follow the replacement
/// (DPOOL-4, DPOOL-6); the other two are checked against records OUTSIDE the
/// manifest — DPOOL-5 against the A-7 kit's treasury target, DPOOL-7 against
/// `vault_authorities[recovery].vault` — which the replacement cannot move, so
/// they must carry their committed values. Anchored on the section header and
/// the field KEYS, never on a line number or a principal literal.
fn with_committed_pool_trust_roots(manifest: &str) -> String {
    fn span(src: &str) -> (usize, usize) {
        let lines: Vec<&str> = src.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.trim_start().starts_with("[pool_init]"))
            .expect("the manifest must carry a [pool_init] section");
        let end = lines[start + 1..]
            .iter()
            .position(|l| l.starts_with('['))
            .map(|i| start + 1 + i)
            .unwrap_or(lines.len());
        (start, end)
    }
    let committed =
        std::fs::read_to_string(deployment_dir().join("genesis_manifest.toml")).unwrap();
    let clines: Vec<&str> = committed.lines().collect();
    let cspan = span(&committed);
    let mut mlines: Vec<String> = manifest.lines().map(|l| l.to_string()).collect();
    let mspan = span(manifest);
    let mut changed = false;
    for key in ["treasury_canister", "controller"] {
        let src = clines[cspan.0..cspan.1]
            .iter()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("committed [pool_init] must carry `{key}`"))
            .to_string();
        let idx = mlines[mspan.0..mspan.1]
            .iter()
            .position(|l| l.trim_start().starts_with(key))
            .map(|i| mspan.0 + i)
            .unwrap_or_else(|| panic!("derived [pool_init] must carry `{key}`"));
        if mlines[idx] != src {
            changed = true;
        }
        mlines[idx] = src;
    }
    assert!(changed, "the pool trust-root restore must actually change the derived manifest");
    mlines.join("\n") + "\n"
}

/// The DERIVED pre-RR-1 specimen: the committed artifacts with every principal
/// reverted to its P0-3 placeholder.
///
/// RR-1b RETARGET. This file used to feed `rr1_replaced_fixture` the COMMITTED
/// artifacts. That worked only while those artifacts still carried placeholders;
/// RR-1b resolved the last one, so the substitution became a silent NO-OP and
/// every claim built on it decayed into "the committed tree passes". Deriving
/// the specimen keeps the claims about a REAL RR-1 substitution.
fn pre_rr1_fixtures() -> (String, String, String) {
    let read = |name: &str| std::fs::read_to_string(deployment_dir().join(name)).unwrap();
    vgm::placeholder_reverted_fixture(
        &read("genesis_manifest.toml"),
        &read("stsh_token_init.did"),
        &read("vesting_init.did"),
    )
    .expect("committed inputs must parse")
}

#[test]
fn gate_v_two_phase_fixture_proof() {
    // ── Phase 1 (pre-install) ───────────────────────────────────────────────
    // R4-1 direction (a): a placeholder-carrying set must be REFUSED. RR-1b
    // RETARGET — this ran against the COMMITTED artifacts while they still
    // carried placeholders; they no longer do, so the claim moves onto the
    // DERIVED pre-RR-1 specimen where it keeps full strength, and the committed
    // tree carries the dual claim instead: nothing placeholder remains, so no
    // DP3-* may fail.
    let (pre_m, pre_t, pre_v) = pre_rr1_fixtures();
    let pre = vgm::run_gates_from_strs_with_record(
        &pre_m, &pre_t, &pre_v, None, Some(&vault_src()), "", Some(&a7_kit_src()),
    )
    .expect("gates run on the derived pre-RR-1 specimen");
    assert!(
        pre.iter().any(|c| !c.pass && c.name.starts_with("DP3-")),
        "a placeholder-carrying set must fail at least one DP3-* check"
    );
    let report = vgm::run_gates_on_dir(&deployment_dir()).expect("gates run");
    assert!(
        !report.checks.iter().any(|c| !c.pass && c.name.starts_with("DP3-")),
        "post-RR-1b no committed site is a placeholder, so no DP3-* may fail: {:?}",
        report
            .checks
            .iter()
            .filter(|c| !c.pass && c.name.starts_with("DP3-"))
            .map(|c| &c.name)
            .collect::<Vec<_>>()
    );

    // R4-1 direction (b): the RR-1-replaced set — the real genesis shape —
    // passes the full gates. Replaced FROM the derived specimen (RR-1b), so the
    // substitution is real rather than a no-op.
    let (rr1_manifest, rr1_token, rr1_vesting) =
        vgm::rr1_replaced_fixture(&pre_m, &pre_t, &pre_v);
    let rr1_manifest = with_committed_pool_trust_roots(&rr1_manifest);
    let rr1_checks = vgm::run_gates_from_strs_with_record(&rr1_manifest, &rr1_token, &rr1_vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
        .expect("gates run on the RR-1-replaced set");
    // R-3a: `run_gates_from_strs` (the record-BLIND surface this call used to
    // make) is gone as a public API, so the call is made on the record-bearing
    // surface with `None` for the record — which is exactly the "no record was
    // supplied" state, and `GP0-record` correctly reports it. The GP* family is
    // therefore NOT part of THIS claim, which is the phase-1 gate_d /
    // gate_v_pre_install claim. The record-bearing re-proof of the GP* family
    // over this same RR-1-replaced set is the block immediately below, added by
    // R-3 for precisely this reason.
    let rr1_failing: Vec<String> = rr1_checks
        .iter()
        .filter(|c| !c.pass && !c.name.starts_with("GP"))
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    assert!(
        rr1_failing.is_empty(),
        "phase 1 must pass every gate_d/gate_v_pre_install check on the RR-1-replaced \
         artifacts: {:?}",
        rr1_failing
    );
    // Vacuity for the filter: the GP* family really did run on this surface, so
    // the filter above narrows a real set rather than papering over an empty one.
    assert!(
        rr1_checks.iter().any(|c| c.name.starts_with("GP")),
        "the principal-gate family must have RUN here — if it did not, the filter above is \
         hiding nothing and this test's surface silently shrank"
    );

    // RETARGETED BY R-3 (brief §4 item 4). The claim above is stated on a
    // RECORD-BLIND surface. After R-3 the genesis principals are bound to an
    // INDEPENDENT record (deployment/mainnet/genesis_principals.toml), so
    // "a legitimate RR-1 passes" must be re-proven on the surface that carries
    // GP0..GP6 — otherwise this test would keep certifying an RR-1 shape the
    // real gate now refuses. The cross-bound role is pinned to the REAL Vault
    // principal, read from the committed authority record, because that is what
    // a real RR-1 writes there (freeze §14).
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let vault = vgm::load_vault_bound_principal(&repo_root)
        .expect("vault_authorities.toml parses")
        .expect("vault_authorities.toml present");
    // RR-1b: same retarget — the DERIVED specimen is the input, so the
    // substitution below is a real one.
    let (bm, bt, bv) = pre_rr1_fixtures();
    let (vm, vt, vv) = vgm::rr1_replaced_fixture_with_vault(&bm, &bt, &bv, &vault.to_text());
    let vm = with_committed_pool_trust_roots(&vm);
    let record = vgm::record_matching(&vm, &vt, &vv, true).expect("matching record");
    let vault_toml =
        std::fs::read_to_string(repo_root.join(vgm::GENESIS_VAULT_AUTHORITY_RECORD)).unwrap();
    let bound = vgm::run_gates_from_strs_with_record(
        &vm,
        &vt,
        &vv,
        Some(&record),
        Some(&vault_toml),
        &vgm::sha256_hex(record.as_bytes()), Some(&a7_kit_src()))
    .expect("gates run on the RR-1-replaced set with its record");
    assert!(
        vgm::all_pass(&bound),
        "a legitimate RR-1 (replaced inputs + matching record) must pass GP0..GP6 too: {:?}",
        bound.iter().filter(|c| !c.pass).collect::<Vec<_>>()
    );
    // Lane A-2 (D-9): the census figure is REGENERATED by parsing the committed
    // record at point of use. It was the literal `19`, which silently encoded a
    // role set that A-2 changed (three allocation roles retired, three added, two
    // founder beneficiaries retired). An inherited count is exactly the class of
    // defect this lane closed on the allocation table; it does not belong in the
    // anti-vacuity guard either.
    let census_entries = std::fs::read_to_string(
        deployment_dir().join("genesis_principals.toml"),
    )
    .unwrap()
    .lines()
    .filter(|l| l.starts_with("[role."))
    .count();
    assert!(census_entries > 0, "the census must not be empty — that would make this guard vacuous");
    assert_eq!(
        bound.iter().filter(|c| c.name.starts_with("GP2-value-")).count(),
        census_entries,
        "anti-vacuity: all {} census roles must be GP2-evaluated once resolved",
        census_entries
    );

    let manifest_str =
        std::fs::read_to_string(deployment_dir().join("genesis_manifest.toml")).unwrap();
    // The founders allocation is unchanged by D-4 V2 ...
    let founders = vgm::founders_amount(&manifest_str).expect("founders amount");
    assert_eq!(founders, 12_000_000_000_000_000, "§0.3 founders allocation (a14beef1: 18% -> 12%)");
    // ... but the vesting canister now custodies founders AND the counsel grant,
    // so the Gate-V phase-2 expectation is the CUSTODY TOTAL, not the founders row.
    // Passing `founders` here would under-expect by the counsel amount and VP1
    // would RED against a correctly funded canister at genesis.
    let expected = vgm::vesting_custody_total(&manifest_str).expect("vesting custody total");
    assert_eq!(expected, 12_500_000_000_000_000, "founders 12e15 + counsel 0.5e15");

    let token_init_parsed = vgm::extract_token_init(
        &vgm::parse_artifact(
            &std::fs::read_to_string(deployment_dir().join("stsh_token_init.did")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let vesting_init_parsed = vgm::extract_vesting_init(
        &vgm::parse_artifact(
            &std::fs::read_to_string(deployment_dir().join("vesting_init.did")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    // ── Live install (values from the artifacts; two wires substituted). ─────
    let pic = PocketIc::new();
    let vesting_cid = pic.create_canister();
    pic.add_cycles(vesting_cid, 10_000_000_000_000);

    let allocations: Vec<AllocationCategory> = token_init_parsed
        .allocations
        .iter()
        .map(|a| AllocationCategory {
            category_id: a.category_id.clone(),
            category_name: a.category_name.clone(),
            amount: a.amount,
            // Fixture substitution: the live vesting canister id stands in for the
            // placeholder. Since D-4 V2 BOTH the founders and legal_counsel rows
            // name that canister (it is the schedule authority for both), so both
            // must be substituted — substituting only founders would mint the
            // counsel grant to a placeholder and leave the canister under-funded.
            // VP1 catches exactly that, which is how this was found.
            recipient: if a.category_id == "founders" || a.category_id == "legal_counsel" {
                vesting_cid
            } else {
                Principal::from_text(&a.recipient).unwrap()
            },
            subaccount: None,
            lock_policy: lock_policy_from(&a.lock_policy),
            vesting_policy: None,
            created_at_genesis: a.created_at_genesis,
            genesis_timestamp_ns: a.genesis_timestamp_ns,
        })
        .collect();

    let token_cid = pic.create_canister();
    pic.add_cycles(token_cid, 10_000_000_000_000);
    pic.install_canister(
        token_cid,
        token_wasm(),
        candid::encode_one(&TokenInitArgs {
            allocations,
            treasury: Principal::from_text(&token_init_parsed.treasury).unwrap(),
            staking_canister: Principal::from_text(&token_init_parsed.staking_canister).unwrap(),
            fee_collector: token_init_parsed
                .fee_collector
                .as_deref()
                .map(|p| Principal::from_text(p).unwrap()),
        })
        .unwrap(),
        None,
    );

    // Lane A-2: the expected installed-schedule count is DERIVED from the
    // artifact actually being installed, not a literal. It was `4` (three
    // founders + one counsel); DRIFT-1 made it two (one founder + one counsel),
    // and a hardcoded count turns a ruled table change into a false regression.
    let expected_schedule_count = vesting_init_parsed.schedules.len();
    let schedules: Vec<NewSchedule> = vesting_init_parsed
        .schedules
        .iter()
        .map(|s| NewSchedule {
            beneficiary: Principal::from_text(&s.beneficiary).unwrap(),
            total_amount: s.total_amount,
            cliff_months: s.cliff_months,
            linear_months: s.linear_months,
        })
        .collect();
    pic.install_canister(
        vesting_cid,
        vesting_wasm(),
        candid::encode_one(&VestingInitArgs {
            token_canister: token_cid, // fixture substitution: live token id
            controller: Principal::from_text(&vesting_init_parsed.controller).unwrap(),
            schedules,
        })
        .unwrap(),
        None,
    );

    // ── Phase 2 (post-install): live queries through the release checker. ────
    let balance_bytes = pic
        .query_call(
            token_cid,
            Principal::anonymous(),
            "icrc1_balance_of",
            candid::encode_one(Account { owner: vesting_cid, subaccount: None }).unwrap(),
        )
        .expect("icrc1_balance_of");
    let balance: Nat = candid::decode_one(&balance_bytes).unwrap();
    let balance_u128: u128 = balance.0.to_string().parse().unwrap();

    let schedules_bytes = pic
        .query_call(
            vesting_cid,
            Principal::anonymous(),
            "list_schedules",
            candid::encode_args(()).unwrap(),
        )
        .expect("list_schedules");
    let installed: Vec<VestingSchedule> = candid::decode_one(&schedules_bytes).unwrap();
    // The count is asserted (not just the sum) so a schedule silently dropped by
    // the canister cannot be masked by another being oversized. Since lane A-2
    // the expectation is the artifact's own schedule count — 1 founder (DRIFT-1)
    // + 1 counsel today — so this guard tracks the ruled table instead of a
    // literal that has to be chased every time the table moves. It still bites:
    // the canister must install exactly what it was handed.
    assert!(
        expected_schedule_count >= 2,
        "the fixture must install at least the founder and counsel schedules, got {}",
        expected_schedule_count
    );
    assert_eq!(
        installed.len(),
        expected_schedule_count,
        "every schedule in vesting_init.did must be installed on-canister"
    );
    // The counsel schedule is really on-canister with the ruled shape — this is the
    // proof that the grant is CODE-enforced, not policy-enforced: the canister
    // itself holds a zero-cliff 12-month schedule for it.
    let counsel = installed
        .iter()
        .find(|s| s.total_amount == 500_000_000_000_000)
        .expect("counsel schedule installed on-canister");
    assert_eq!(
        counsel.cliff_end_ns, counsel.start_ns,
        "counsel cliff is ZERO: cliff_end == start"
    );
    assert_eq!(
        counsel.vesting_end_ns - counsel.cliff_end_ns,
        12 * 30 * 24 * 60 * 60 * 1_000_000_000u64,
        "counsel releases over 12 fixed 30-day months"
    );
    let schedule_sum = installed
        .iter()
        .try_fold(0u128, |acc, s| acc.checked_add(s.total_amount))
        .expect("checked schedule sum");

    let post = vgm::gate_v_post_install(balance_u128, schedule_sum, expected);
    assert!(
        vgm::all_pass(&post),
        "Gate-V phase 2 must pass on the live install: {:?}",
        post.iter().filter(|c| !c.pass).collect::<Vec<_>>()
    );

    // Drift is caught: the checker fails closed if either side moved.
    assert!(!vgm::all_pass(&vgm::gate_v_post_install(balance_u128 - 1, schedule_sum, expected)));
}
