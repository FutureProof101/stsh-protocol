//! R4-1 (lane A-4) bite proofs: Gate-D refuses, fail-closed, to certify any
//! genesis artifact set that still carries a P0-3 placeholder principal.
//!
//! Evidence, not argument — both directions are asserted:
//!   (a) the artifacts COMMITTED at the pinned base, which passed the full gate
//!       before this change, now FAIL (T1, T2);
//!   (b) an RR-1-replaced set still PASSES everything (T3) — so the check does
//!       not simply reject everything, and RR-1 genuinely unblocks the gate.
//! T4 and T5 prove the byte-marker and invalid-tag limbs bite INDEPENDENTLY of
//! the P0-3 suffix list, and T6 proves the coverage invariant can diverge.

use candid::Principal;
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

/// Restore the two EXTERNALLY-pinned `[pool_init]` trust roots into a derived
/// manifest.
///
/// RR-1b: `placeholder_reverted_fixture` reverts all four `[pool_init]`
/// principals, and a wholesale RR-1 replacement then rewrites them along with
/// everything else. Two of the four are checked against the manifest itself and
/// so follow the replacement correctly (DPOOL-4 vs `vesting_init.token_canister`,
/// DPOOL-6 vs `token_init.staking_canister`). The other two are checked against
/// records OUTSIDE the manifest — DPOOL-5 against the A-7 kit's treasury row
/// target, DPOOL-7 against `vault_authorities[recovery].vault` — which the
/// replacement cannot move, so they must carry their committed values or those
/// two checks go RED for a reason that has nothing to do with the placeholder
/// family these tests are about. Anchored on the `[pool_init]` header and the
/// field KEYS, never on a line number or a principal literal.
fn with_committed_pool_trust_roots(manifest: &str) -> String {
    fn pool_init_span(src: &str) -> (usize, usize) {
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
    fn field_line<'a>(lines: &[&'a str], span: (usize, usize), key: &str) -> &'a str {
        lines[span.0..span.1]
            .iter()
            .copied()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("[pool_init] must carry a `{key}` field"))
    }
    let (cm, _, _) = fixtures();
    let clines: Vec<&str> = cm.lines().collect();
    let cspan = pool_init_span(&cm);
    let mut mlines: Vec<String> = manifest.lines().map(|l| l.to_string()).collect();
    let mspan = pool_init_span(manifest);
    let mut changed = false;
    for key in ["treasury_canister", "controller"] {
        let committed = field_line(&clines, cspan, key).to_string();
        let idx = mlines[mspan.0..mspan.1]
            .iter()
            .position(|l| l.trim_start().starts_with(key))
            .map(|i| mspan.0 + i)
            .unwrap_or_else(|| panic!("[pool_init] must carry a `{key}` field"));
        if mlines[idx] != committed {
            changed = true;
        }
        mlines[idx] = committed;
    }
    assert!(
        changed,
        "the pool trust-root restore must actually change the derived manifest — if it does \
         not, the specimen was never a derived one"
    );
    mlines.join("\n") + "\n"
}

/// RR-1b RETARGET. `rr1_replaced_fixture` substitutes every P0-3 placeholder
/// TOKEN it finds; post-RR-1b the committed tree holds none, so feeding it the
/// committed artifacts made it a silent NO-OP and every claim built on it
/// decayed to "the committed tree passes". It is therefore fed the DERIVED
/// pre-RR-1 specimen, which is what it was always modelling: a full
/// placeholder set, replaced wholesale, the way a real RR-1 does it.
fn replaced_fixtures() -> (String, String, String) {
    let (m, t, v) = pre_rr1_fixtures();
    let (rm, rt, rv) = rr1_replaced_fixture(&m, &t, &v);
    assert_ne!(rm, m, "the RR-1 replacement must not be a no-op");
    (with_committed_pool_trust_roots(&rm), rt, rv)
}

/// The PRE-RR-1 specimen this file's coverage proofs run against.
///
/// RR-1a (2026-09-12) resolved the committed artifacts, so they carry exactly ONE
/// placeholder left (the counsel beneficiary, held for RR-1b) and after RR-1b
/// they will carry none. Anchoring "all eight site families are scanned and
/// rejected" on the committed files would therefore have shrunk that claim to a
/// single site — silently, and while still passing. The claim is anchored on a
/// DERIVED pre-RR-1 set instead, built by `placeholder_reverted_fixture` from
/// the committed shape, so it stays at full strength at every future posture.
/// The committed set keeps its own, separate assertions below (fail-closed, and
/// the failing sites are exactly the ones the record still leaves PENDING).
fn pre_rr1_fixtures() -> (String, String, String) {
    let (m, t, v) = fixtures();
    placeholder_reverted_fixture(&m, &t, &v).expect("committed inputs must parse")
}

fn failing_names(checks: &[CheckResult]) -> Vec<String> {
    checks.iter().filter(|c| !c.pass).map(|c| c.name.clone()).collect()
}

/// The genesis principal record's role count, REGENERATED by parsing the
/// committed record at point of use (lane A-2 / D-9). Never a literal: an
/// inherited census figure is exactly the class of defect this lane closed.
fn census_entries() -> usize {
    std::fs::read_to_string(deployment_dir().join("genesis_principals.toml"))
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("[role."))
        .count()
}

fn is_dp3_site(name: &str) -> bool {
    name.starts_with("DP3-") && name != "DP3-scan-coverage"
}

/// The eight site families of brief §4.2 — T1 proves every one is scanned.
/// The token/vesting FIELD families need a matcher rather than a bare prefix,
/// because `DP3-artifact-token-alloc-*` shares their prefix.
const DP3_FAMILIES: [(&str, fn(&str) -> bool); 8] = [
    ("manifest allocation rows", |n| n.starts_with("DP3-manifest-alloc-")),
    ("manifest token_init fields", |n| n.starts_with("DP3-manifest-token-init-")),
    ("manifest vesting_init fields", |n| n.starts_with("DP3-manifest-vesting-init-")),
    ("manifest founder schedules", |n| n.starts_with("DP3-manifest-founder-schedule-")),
    ("artifact token allocations", |n| n.starts_with("DP3-artifact-token-alloc-")),
    ("artifact token fields", |n| {
        matches!(
            n,
            "DP3-artifact-token-treasury"
                | "DP3-artifact-token-staking_canister"
                | "DP3-artifact-token-fee_collector"
        )
    }),
    ("artifact vesting fields", |n| {
        matches!(n, "DP3-artifact-vesting-token_canister" | "DP3-artifact-vesting-controller")
    }),
    ("artifact vesting schedules", |n| n.starts_with("DP3-artifact-vesting-schedule-")),
];

// ── T1 — direction (a): a placeholder-carrying set FAILS, coherence survives ──

#[test]
fn t1_committed_placeholder_artifacts_fail_closed_and_coherence_survives() {
    let report = run_gates_on_dir(&deployment_dir()).expect("gates must run");

    // RR-1b RETARGET. Direction (a) — "a placeholder-carrying set does NOT
    // certify" — was asserted against the COMMITTED tree while that tree still
    // carried P0-3 placeholders. RR-1b resolved the last of them, so the claim
    // moves onto the DERIVED pre-RR-1 specimen (`pre_rr1_fixtures`, asserted
    // below), where it keeps full strength. Against the committed tree the
    // claim is now its dual and is asserted as such: nothing placeholder is
    // left, so it MUST certify. Leaving the old form would have silently
    // decayed into an assertion that could no longer be caused to fire by the
    // thing it was written to catch.
    assert!(
        all_pass(&report.checks),
        "post-RR-1b the committed artifacts carry no placeholder and MUST certify; \
         failing: {:?}",
        failing_names(&report.checks)
    );

    // Every COHERENCE check still passes: the failure is caused by DP3-* (and the
    // record's own PENDING family) alone, not by unrelated drift.
    //
    // RETARGETED BY R-3 (brief §4 item 4), and again by RR-1a (2026-09-12).
    // `run_gates_on_dir` carries the GP0..GP6 principal-binding family, whose
    // failures under a record that still holds a role PENDING are expected and
    // enumerated: `GP1-pending-<ROLE>` for each such role, plus
    // `GP2-value-STAKING_CANISTER` while that cross-bound role's own DP3 sites
    // also fail (pre-RR-1 only — after RR-1a pinned it to the Vault, they do
    // not, and the name is simply absent rather than tolerated). This test keeps
    // its original claim — NO COHERENCE CHECK REGRESSED — by excluding exactly
    // those named families and nothing else. A GP3/GP4/GP5/GP6/GP0 failure, or
    // any `GP1-pending-input-populated-*`, still lands in `unexpected` and still
    // REDs this test.
    let unexpected: Vec<&String> = report
        .checks
        .iter()
        .filter(|c| !c.pass)
        .map(|c| &c.name)
        .filter(|n| !n.starts_with("DP3-"))
        .filter(|n| {
            !(n.starts_with(GP_PENDING_PREFIX)
                && !n.starts_with(GP_PENDING_INPUT_POPULATED_PREFIX))
        })
        .filter(|n| n.as_str() != "GP2-value-STAKING_CANISTER")
        .collect();
    assert!(
        unexpected.is_empty(),
        "coherence must survive; unexpected failures: {:?}",
        unexpected
    );

    // On the COMMITTED set the failing sites are exactly the sites whose role the
    // record still leaves PENDING — DERIVED from the record at point of use, never
    // a literal count, so this assertion holds unchanged across RR-1b (when the
    // last role resolves and the expected set becomes empty).
    let (m, t, v) = fixtures();
    let sites = principal_sites(
        &toml::from_str(&m).unwrap(),
        &extract_token_init(&parse_artifact(&t).unwrap()).unwrap(),
        &extract_vesting_init(&parse_artifact(&v).unwrap()).unwrap(),
    );
    let pending_roles: Vec<String> = report
        .checks
        .iter()
        .filter(|c| {
            !c.pass
                && c.name.starts_with(GP_PENDING_PREFIX)
                && !c.name.starts_with(GP_PENDING_INPUT_POPULATED_PREFIX)
        })
        .map(|c| c.name[GP_PENDING_PREFIX.len()..].to_string())
        .collect();
    let mut expected_failing: Vec<String> = sites
        .iter()
        .filter(|s| pending_roles.contains(&s.role))
        .map(|s| s.dp3_name.clone())
        .collect();
    expected_failing.sort();
    let mut committed_failing: Vec<String> = report
        .checks
        .iter()
        .filter(|c| !c.pass && is_dp3_site(&c.name))
        .map(|c| c.name.clone())
        .collect();
    committed_failing.sort();
    assert_eq!(
        committed_failing, expected_failing,
        "a committed site is placeholder if and only if its role is still PENDING \
         in the record — a site rejected under a RESOLVED role is a partial RR-1, \
         and a resolved site under a PENDING role is `GP1-pending-input-populated-*`"
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "DP3-scan-coverage" && c.pass),
        "DP3-scan-coverage must PASS on the committed (full-shape) set"
    );

    // ── Coverage, on the DERIVED pre-RR-1 specimen ───────────────────────────
    //
    // Exactly 37 principal SITES rejected when every principal is a placeholder.
    // Lane A-2 derivation (regenerated, never inherited): 33 FIXED sites —
    // 11 manifest allocations + 11 artifact allocations + 3 manifest token_init
    // + 3 manifest vesting_init + 3 artifact token fields + 2 artifact vesting
    // fields — plus 4 input-variable SCHEDULE sites: 1 manifest
    // [[founder_schedule]] (DRIFT-1: one founder, was three) + 1 manifest
    // [[counsel_schedule]] + 2 artifact vesting-schedule records. 33 + 4 = 37.
    // The FIXED-site expectation is unchanged at 33: the row count stayed 11 and
    // schedule sites never counted toward it.
    let (pm, pt, pv) = pre_rr1_fixtures();
    let pre_checks =
        run_gates_from_strs_with_record(&pm, &pt, &pv, None, Some(&vault_src()), "", Some(&a7_kit_src())).expect("gates must run");
    // Direction (a), on the surface that still carries placeholders: a
    // placeholder-bearing set must NOT certify. This is the claim the committed
    // tree used to carry (see the RR-1b retarget note above).
    assert!(
        !all_pass(&pre_checks),
        "a placeholder-carrying set must NOT certify"
    );
    let failing_sites: Vec<&String> = pre_checks
        .iter()
        .filter(|c| !c.pass && is_dp3_site(&c.name))
        .map(|c| &c.name)
        .collect();
    assert_eq!(
        failing_sites.len(),
        37,
        "every principal site must be rejected; got: {:?}",
        failing_sites
    );
    assert!(
        pre_checks.iter().any(|c| c.name == "DP3-scan-coverage" && c.pass),
        "DP3-scan-coverage must PASS on the derived (full-shape) set"
    );

    // ── Limb 1 bite proof (SSA-A4-D1) ───────────────────────────────────
    // No input inside this fence can isolate limb 1: every P0-3 placeholder
    // ALSO carries the `placeholder` byte window (limb 2) and the invalid
    // trailing tag 0x72 (limb 3), so the pass/fail VERDICT cannot distinguish
    // it. The branch-specific observable is therefore the emitted REASON. Limb 1
    // is evaluated first, so every site must report the KNOWN-SET reason —
    // replace the suffix branch with `false` and each detail flips to another
    // limb's reason, failing this assertion.
    //
    // The specimen is DERIVED (RR-1a), and `p0_3_placeholder` builds genuine
    // members of the family — `[0xa0, idx] ++ b"placeholder"` — so they carry the
    // pinned suffix and reach limb 1 exactly as the committed ones did.
    //
    // Stated honestly, per CTO_RULING/NOTE bounds: this pins limb 1's
    // EVALUATION ORDER and its OPERATOR-FACING REASON TEXT — the property that
    // sends an RR-2 operator to RR-1 rather than hunting an authoring bug. It
    // does NOT claim limb 1 is independently load-bearing for rejection; on
    // this fixture it is not, and nothing here implies otherwise.
    const KNOWN_SET_REASON: &str = "known P0-3 placeholder principal";
    let wrong_reason: Vec<&String> = pre_checks
        .iter()
        .filter(|c| !c.pass && is_dp3_site(&c.name))
        .filter(|c| !c.detail.contains(KNOWN_SET_REASON))
        .map(|c| &c.name)
        .collect();
    assert!(
        wrong_reason.is_empty(),
        "every P0-3 site must be rejected by the KNOWN-SET limb and say so \
         (limb 1 unreached or its reason changed); offending sites: {:?}",
        wrong_reason
    );
    // Non-vacuity: the reason text really is limb 1's, naming the pinned suffix.
    assert!(
        pre_checks.iter().any(|c| {
            !c.pass
                && is_dp3_site(&c.name)
                && c.detail.contains(KNOWN_SET_REASON)
                && c.detail.contains(P0_3_PLACEHOLDER_SUFFIX)
        }),
        "the known-set rejection reason must name the pinned P0-3 suffix"
    );

    // The manifest AND both *_init.did artifacts are scanned — one failing name
    // from each of the eight families.
    for (label, matches_family) in DP3_FAMILIES {
        assert!(
            failing_sites.iter().any(|n| matches_family(n)),
            "family \"{}\" unscanned; failing: {:?}",
            label,
            failing_sites
        );
    }
    // Every named field site is present, not just one per family.
    for name in [
        "DP3-manifest-token-init-treasury",
        "DP3-manifest-token-init-staking_canister",
        "DP3-manifest-token-init-fee_collector",
        "DP3-manifest-vesting-init-token_canister",
        "DP3-manifest-vesting-init-controller",
        "DP3-manifest-vesting-init-founders_vesting_canister",
        "DP3-artifact-token-treasury",
        "DP3-artifact-token-staking_canister",
        "DP3-artifact-token-fee_collector",
        "DP3-artifact-vesting-token_canister",
        "DP3-artifact-vesting-controller",
    ] {
        assert!(
            failing_sites.iter().any(|n| n.as_str() == name),
            "{} must be scanned and rejected",
            name
        );
    }
}

// ── T2 — the CLI actually gates ──────────────────────────────────────────────

#[test]
fn t2_cli_exits_nonzero_with_the_rr1_remedy_line() {
    // RR-1b RETARGET. This ran against `deployment_dir()` back when the
    // committed tree still carried P0-3 placeholders; post-RR-1b that tree
    // certifies, so the CLI-gates claim would have decayed into a test that
    // could never fire. It now runs over a SCRATCH root whose three genesis
    // inputs are the DERIVED pre-RR-1 specimen — the same surface T1's
    // coverage proofs use — so the claim keeps full strength.
    let root = posture_scratch_root("t2_pre_rr1");
    let dir = root.join("deployment/mainnet");
    let (pm, pt, pv) = pre_rr1_fixtures();
    for (name, body) in [
        ("genesis_manifest.toml", &pm),
        ("stsh_token_init.did", &pt),
        ("vesting_init.did", &pv),
    ] {
        let before = std::fs::read_to_string(dir.join(name)).unwrap();
        assert_ne!(
            &before, body,
            "{name}: the pre-RR-1 specimen must DIFFER from the committed artifact — if it \
             does not, this test is gating the committed tree again"
        );
        std::fs::write(dir.join(name), body).unwrap();
    }
    // Non-vacuity: the specimen really carries placeholders, which is the only
    // reason the CLI below is expected to refuse.
    assert!(pm.contains(P0_3_PLACEHOLDER_SUFFIX), "the specimen must carry P0-3 placeholders");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_verify_genesis_manifest"))
        .arg(&dir)
        .output()
        .expect("CLI must run");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(!out.status.success(), "CLI must exit NONZERO; stdout:\n{}", stdout);
    assert!(
        stdout.lines().any(|l| l.starts_with("[FAIL] DP3-")),
        "CLI must print DP3- FAIL lines; stdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("DEPLOY BLOCKED") && stdout.contains("RR-1"),
        "CLI must print the operator-legible RR-1 remedy; stdout:\n{}",
        stdout
    );
    assert!(stdout.contains("GATE-D + GATE-V(pre-install): FAIL"));
}

// ── T3 — direction (b): the RR-1-replaced set PASSES everything ──────────────

#[test]
fn t3_rr1_replaced_set_passes_everything() {
    // Read the COMMITTED manifest before any transform, so the "nothing was
    // written to deployment/mainnet" proof at the end is differential rather
    // than keyed on a literal (see the RR-1b note there).
    let (committed_at_entry, _, _) = fixtures();
    let (manifest, token, vesting) = replaced_fixtures();

    // Anti-vacuity: no placeholder text survives anywhere in the replaced set.
    for (label, s) in
        [("manifest", &manifest), ("token_init", &token), ("vesting_init", &vesting)]
    {
        assert!(
            !s.contains(P0_3_PLACEHOLDER_SUFFIX),
            "{}: RR-1 replacement left a placeholder principal behind",
            label
        );
    }

    let checks = run_gates_from_strs_with_record(&manifest, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let failing = failing_names(&checks);
    // R-3a: this call was made on the record-BLIND `run_gates_from_strs`, which
    // is no longer a public surface. With `None` for the record the GP* family
    // correctly reports "no record supplied", so it is outside this test's
    // claim — which is the placeholder/DP-family one. The record-bearing
    // re-proof over this same RR-1-replaced set is the block below (R-3).
    let failing: Vec<String> =
        failing.into_iter().filter(|n| !n.starts_with("GP")).collect();
    assert!(failing.is_empty(), "RR-1-replaced set must pass every check: {:?}", failing);
    assert!(
        checks.iter().any(|c| c.name.starts_with("GP")),
        "vacuity: the GP* family must have RUN on this surface"
    );

    // RETARGETED BY R-3 (brief §4 item 4). The claim above — "an RR-1-replaced
    // set still passes everything" — was stated on a RECORD-BLIND surface, and
    // after R-3 that is only part of it: the control AC-1 needs is "the same
    // substitution, WITH A MATCHING RECORD, is green", which is what makes the
    // headline RED meaningful rather than a gate that rejects everything.
    //
    // The cross-bound role is additionally pinned to the REAL Vault principal,
    // because a synthetic value there is a genuine GP2 mismatch — writing the
    // Vault at those sites is exactly what a real RR-1 does (freeze §14).
    let root = deployment_dir().parent().unwrap().parent().unwrap().to_path_buf();
    let vault = load_vault_bound_principal(&root)
        .expect("vault_authorities.toml parses")
        .expect("vault_authorities.toml present");
    // Same RR-1b retarget as `replaced_fixtures`: the input is the DERIVED
    // pre-RR-1 specimen, so the substitution is real rather than a no-op.
    let (m0, t0, v0) = pre_rr1_fixtures();
    let (rm, rt, rv) = rr1_replaced_fixture_with_vault(&m0, &t0, &v0, &vault.to_text());
    let rm = with_committed_pool_trust_roots(&rm);
    let record = record_matching(&rm, &rt, &rv, true).expect("record for the replaced set");
    let vault_toml =
        std::fs::read_to_string(root.join(GENESIS_VAULT_AUTHORITY_RECORD)).unwrap();
    let with_record = run_gates_from_strs_with_record(
        &rm,
        &rt,
        &rv,
        Some(&record),
        Some(&vault_toml),
        &sha256_hex(record.as_bytes()), Some(&a7_kit_src()))
    .unwrap();
    let failing_with_record = failing_names(&with_record);
    assert!(
        failing_with_record.is_empty(),
        "the RR-1-replaced set WITH A MATCHING RECORD must pass every check, GP0..GP6 \
         included: {:?}",
        failing_with_record
    );
    // Anti-vacuity: the GP family actually RAN on that surface.
    assert!(
        with_record.iter().filter(|c| c.name.starts_with("GP2-value-")).count() == census_entries(),
        "all {} census roles must be GP2-evaluated once resolved",
        census_entries()
    );
    assert!(
        checks.iter().filter(|c| is_dp3_site(&c.name)).count() == 37,
        "the full 41-site DP3 surface must still run on the replaced set"
    );
    assert!(checks.len() >= 62, "full check surface expected, got {}", checks.len());

    // Nothing was written to deployment/mainnet — this is a pure string
    // transform. RR-1b RETARGET: the old proof was `on_disk.contains(P0-3
    // suffix)`, a control keyed on a placeholder LITERAL that RR-1b removed
    // from the committed manifest; it would have gone RED for the right file
    // but the wrong reason, and once "fixed" by deletion nothing would have
    // guarded the write at all. The proof is now differential and derived: the
    // manifest on disk must still equal the bytes this test read at entry, and
    // the transform must actually have produced something different from them.
    let (on_disk, _, _) = fixtures();
    assert_eq!(
        on_disk, committed_at_entry,
        "deployment/mainnet must be untouched — the committed manifest must be byte-identical \
         to what this test read before any transform ran"
    );
    assert_ne!(rm, m0, "vacuity: the RR-1 replacement must actually change the manifest");
    assert!(
        m0.contains(P0_3_PLACEHOLDER_SUFFIX) && !rm.contains(P0_3_PLACEHOLDER_SUFFIX),
        "vacuity: the specimen carried placeholders and the replacement removed them"
    );
}

// ── T4 / T5 — the byte-marker and invalid-tag limbs bite independently ───────

/// Swap the airdrop recipient (row 7) in BOTH the manifest and the token
/// artifact, so the D11 row stays coherent and only the DP3 sites move.
fn swap_airdrop_recipient(bad: &Principal) -> Vec<CheckResult> {
    let (manifest, token, vesting) = replaced_fixtures();
    let parsed = extract_token_init(&parse_artifact(&token).unwrap()).unwrap();
    let old = parsed.allocations[7].recipient.clone();
    assert_eq!(parsed.allocations[7].category_id, "airdrop", "row 7 is the airdrop row");
    let bad_text = bad.to_text();
    assert!(
        !bad_text.ends_with(P0_3_PLACEHOLDER_SUFFIX),
        "the adversarial principal must NOT be in the P0-3 suffix set"
    );
    run_gates_from_strs_with_record(
        &manifest.replace(&old, &bad_text),
        &token.replace(&old, &bad_text),
        &vesting,
        None,
        Some(&vault_src()),
        "", Some(&a7_kit_src()))
    .unwrap()
}

fn assert_only_these_dp3_sites_fail(checks: &[CheckResult], expected: &[&str]) {
    let failing = failing_names(checks);
    // R-3a: GP* is excluded for the same reason as above — these helpers drive
    // the record-bearing surface with `None`, so "no record supplied" is the
    // expected GP0 verdict and is not what this helper asserts about.
    let non_dp3: Vec<&String> = failing
        .iter()
        .filter(|n| !n.starts_with("DP3-") && !n.starts_with("GP"))
        .collect();
    assert!(non_dp3.is_empty(), "every pre-existing check must still pass: {:?}", non_dp3);
    let mut sites: Vec<&String> = failing.iter().filter(|n| is_dp3_site(n)).collect();
    sites.sort();
    let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(
        sites.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        want.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "exactly the swapped sites must fail"
    );
}

#[test]
fn t4_uppercase_placeholder_window_bites_without_the_suffix_list() {
    // Bytes carry an UPPERCASE "PLACEHOLDER" window and a VALID trailing tag
    // 0x01 — invisible to limbs 1, 3 and 4. Without limb 2 the implementation
    // could be a suffix-list stub and still pass T1–T3.
    let bad = Principal::from_slice(b"\xA5PLACEHOLDER\x01");
    let checks = swap_airdrop_recipient(&bad);
    assert_only_these_dp3_sites_fail(
        &checks,
        &["DP3-manifest-alloc-7-airdrop", "DP3-artifact-token-alloc-7-airdrop"],
    );
}

#[test]
fn t5_invalid_type_tag_bites_and_is_invisible_to_every_prior_check() {
    // No "placeholder" window, not in the P0-3 set, well-formed textual
    // principal — but the trailing byte 0x7e is not a valid IC type tag. This
    // vector is invisible to EVERY pre-existing check (including D5, which only
    // asks that the text parses); only limb 3 catches it.
    let bad = Principal::from_slice(&[0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x7E]);
    assert!(
        Principal::from_text(bad.to_text()).is_ok(),
        "the vector must parse — D5 alone cannot see it"
    );
    let checks = swap_airdrop_recipient(&bad);
    assert_only_these_dp3_sites_fail(
        &checks,
        &["DP3-manifest-alloc-7-airdrop", "DP3-artifact-token-alloc-7-airdrop"],
    );
}

// ── T6 — DP3-scan-coverage genuinely diverges ────────────────────────────────

#[test]
fn t6_scan_coverage_fails_when_a_fixed_site_is_missing() {
    let (manifest, token, vesting) = replaced_fixtures();
    // Drop one allocation row (liquidity): 10 manifest + 11 artifact + 3 + 3 + 3
    // + 2 = 32 inspected fixed sites, against the 33 the hardcoded approved
    // §0.3 cardinality requires. The expectation comes from a source the
    // scanner does not walk, so this divergence is real, not tautological.
    //
    // The terminator is the blank line between rows. It was `"\n\n#"` before D-4
    // (drift item), which assumed the NEXT block always opens with a comment —
    // the appended `legal_counsel` row opens with `[[allocation]]`, so that
    // pattern silently skipped past it and deleted TWO rows, understating the
    // count. Blank-line termination is row-shape independent.
    // Lane A-2: allocation rows now open with their per-row ruling citation, so
    // the anchor is the row's own comment head rather than a bare `[[allocation]]`.
    let start = manifest
        .find("[[allocation]]\n# D-0 bucket 9")
        .expect("liquidity allocation row");
    let end = start
        + manifest[start..].find("\n\n").expect("row is followed by a blank line")
        + 2;
    let short = format!("{}{}", &manifest[..start], &manifest[end..]);

    let checks = run_gates_from_strs_with_record(&short, &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src())).unwrap();
    let coverage = checks
        .iter()
        .find(|c| c.name == "DP3-scan-coverage")
        .expect("DP3-scan-coverage must exist");
    assert!(
        !coverage.pass,
        "coverage invariant must diverge when a fixed site is not scanned: {}",
        coverage.detail
    );
    assert!(
        coverage.detail.contains("=32") && coverage.detail.contains("=33"),
        "coverage detail must name both cardinalities: {}",
        coverage.detail
    );
    // Sanity: the removal really did shrink the scanned surface.
    assert_eq!(
        checks.iter().filter(|c| is_dp3_site(&c.name)).count(),
        36,
        "one manifest allocation site fewer (lane A-2 baseline 37 - 1)"
    );
}

// ── T7 — limb 4 (unparseable principal) bites ────────────────────────────────
//
// CTO_DIRECTION_A-4_limb_coverage.md §1 directs limb 4 be pinned in this round
// and directs that, if it proves unreachable, that be shown with evidence rather
// than asserted. Both happen here.
//
// ARTIFACT SIDE — DEMONSTRATED UNREACHABLE. `t7b` below proves it: an
// unparseable principal in a `.did` is rejected by the CANDID PARSER, so
// `run_gates_from_strs` returns `Err` and no check surface is ever built. The
// predicate is never called and limb 4 cannot fire there. That is a real finding
// about the predicate's shape (raised as NOTE_A-4_limb4_artifact_side_parse.md),
// not an assertion of unreachability.
//
// MANIFEST SIDE — REACHABLE, and pinned by `t7a`. The manifest is TOML, so a
// malformed principal is just a string and reaches the predicate intact.
//
// HONESTY (CTO §1): collateral failures ARE expected here and are asserted as
// present, not narrowed away. Unlike T4/T5 this test does NOT claim "only DP3-*
// fails" — that claim is true there and false here. An unparseable manifest
// principal necessarily also fails D5 (parse) and D11 (artifact↔manifest row
// binding, since the artifact still carries the valid replacement).

/// A well-formed-looking but UNPARSEABLE principal: correct shape, bad CRC32.
/// It is not in the P0-3 suffix set, so limb 1 cannot claim it.
const UNPARSEABLE_PRINCIPAL: &str = "zzzzz-zzzzz-zzzzz-zzzzz-cai";

#[test]
fn t7a_unparseable_manifest_principal_bites_via_limb4() {
    assert!(
        Principal::from_text(UNPARSEABLE_PRINCIPAL).is_err(),
        "the vector must genuinely be unparseable"
    );
    assert!(
        !UNPARSEABLE_PRINCIPAL.ends_with(P0_3_PLACEHOLDER_SUFFIX),
        "limb 1 must not be able to claim this vector"
    );

    let (manifest, token, vesting) = replaced_fixtures();
    let parsed = extract_token_init(&parse_artifact(&token).unwrap()).unwrap();
    let old = parsed.allocations[7].recipient.clone();
    assert_eq!(parsed.allocations[7].category_id, "airdrop");

    // Manifest side ONLY — the artifact keeps the valid replacement (see t7b).
    let checks =
        run_gates_from_strs_with_record(&manifest.replace(&old, UNPARSEABLE_PRINCIPAL), &token, &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
            .expect("the manifest side still parses; the gates run");

    // The site fails, and it fails with LIMB 4's reason — not a byte-marker
    // reason and not a type-tag reason.
    let site = checks
        .iter()
        .find(|c| c.name == "DP3-manifest-alloc-7-airdrop")
        .expect("the airdrop manifest site must be scanned");
    assert!(!site.pass, "an unparseable principal must be rejected: {}", site.detail);
    assert!(
        site.detail.contains("unparseable principal"),
        "must be rejected by limb 4 specifically, got: {}",
        site.detail
    );
    for other_limb in ["placeholder", "type tag", "known P0-3"] {
        assert!(
            !site.detail.contains(other_limb),
            "limb 4's reason must not be another limb's: {}",
            site.detail
        );
    }

    // COLLATERAL, asserted as present rather than narrowed away (CTO §1).
    let failing = failing_names(&checks);
    assert!(
        failing.contains(&"D5-principals-parse".to_string()),
        "D5 collateral is expected and must be stated: {:?}",
        failing
    );
    assert!(
        failing.iter().any(|n| n.starts_with("D11-row-7")),
        "D11 row-binding collateral is expected (the artifact keeps the valid \
         principal while the manifest does not): {:?}",
        failing
    );
}

#[test]
fn t7b_artifact_side_limb4_is_unreachable_the_candid_parser_rejects_first() {
    let (manifest, token, vesting) = replaced_fixtures();
    let parsed = extract_token_init(&parse_artifact(&token).unwrap()).unwrap();
    let old = parsed.allocations[7].recipient.clone();

    // The SAME vector, placed artifact-side instead.
    let err = run_gates_from_strs_with_record(&manifest, &token.replace(&old, UNPARSEABLE_PRINCIPAL), &vesting, None, Some(&vault_src()), "", Some(&a7_kit_src()))
        .expect_err("an unparseable principal in a .did must abort before any check runs");
    assert!(
        err.contains("candid parse failed"),
        "the CANDID PARSER is what rejects it — no check surface is built, so the \
         predicate is never reached and limb 4 cannot fire artifact-side: {}",
        err
    );
    // Evidence that this is upstream of the predicate, not a silent pass: there
    // is no `Vec<CheckResult>` at all to inspect.
}

// ── R-3a AC-6 — `--posture` is asserted at the CLI BOUNDARY ──────────────────
//
// THE GAP. `run_posture_on_dir` and `PostureVerdict` were covered in-process,
// but `run_gate.sh` does not call them — it spawns the BINARY and reads its
// exit code and its `GENESIS-POSTURE-STAGE:` line. Everything between the
// verdict and the process boundary (the `verdict.passes()` branch, the two
// `pass` prints, the `DISALLOWED  {name}` lines, the exit code) was unbound.
//
// BINDING: B-R3A-CLI-POSTURE

/// The CLI, spawned exactly as `run_gate.sh` spawns it.
fn run_posture_cli(dir: &std::path::Path) -> (std::process::ExitStatus, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_verify_genesis_manifest"))
        // Argument ORDER matches run_gate.sh:627 exactly — main.rs takes the
        // dir from args[0] and only when it does not start with `--`, so
        // `--posture <dir>` would silently gate `deployment/mainnet` relative
        // to the CWD instead of the dir under test.
        .arg(dir)
        .arg("--posture")
        .output()
        .expect("CLI must run");
    (
        out.status,
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A scratch REPO ROOT that the checker's `repo_root` resolution reaches
/// exactly as it reaches the committed one.
///
/// Both `run_gates_on_dir` and `run_posture_on_dir` recompute the repo root as
/// `dir.parent().and_then(|p| p.parent())` — two levels up from
/// `deployment/mainnet` — and then read real files through it (the ceremony
/// record, the VK artifact and its pin label, the ceremony anchor, and the
/// genesis principal gates). So the scratch root SYMLINKS every top-level entry
/// of the real repo except `deployment`, and gets a real, tamperable,
/// RECURSIVE AND COMPLETE copy of `deployment/mainnet` — complete because
/// `genesis_principals.toml` and `vault_authorities.toml` live inside it and
/// `GP6-record-pin` hashes the former's whole bytes; a copy of only the three
/// gate inputs would add `GP0-record`/`GP6-record-pin` to `disallowed` in BOTH
/// scratch runs, breaking the untampered control and falsifying the negative's
/// expected set.
fn posture_scratch_root(tag: &str) -> std::path::PathBuf {
    let repo = deployment_dir().parent().unwrap().parent().unwrap().to_path_buf();
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("posture_scratch_{tag}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let mut linked = 0usize;
    for e in std::fs::read_dir(&repo).unwrap() {
        let e = e.unwrap();
        if e.file_name() == "deployment" {
            continue;
        }
        std::os::unix::fs::symlink(e.path(), root.join(e.file_name())).unwrap();
        linked += 1;
    }
    assert!(
        linked > 20,
        "the scratch root must mirror the real repo's top level; only {linked} entries \
         were linked, which means the checks that read through it are being answered by \
         absence rather than by the real files"
    );

    // The recursive, complete copy.
    let dst = root.join("deployment/mainnet");
    std::fs::create_dir_all(&dst).unwrap();
    let o = std::process::Command::new("cp")
        .arg("-a")
        .arg(deployment_dir().join("."))
        .arg(&dst)
        .output()
        .expect("cp must run");
    assert!(o.status.success(), "cp -a: {}", String::from_utf8_lossy(&o.stderr));
    for must in ["genesis_manifest.toml", "genesis_principals.toml", "vault_authorities.toml"] {
        assert!(
            dst.join(must).is_file(),
            "the deployment/mainnet copy must be COMPLETE — {must} is missing"
        );
    }
    root
}

/// Delete the LAST `[[allocation]]` table from a scratch manifest.
///
/// LANE A-2 RETARGET. Before the D-7 re-base the last row was `legal_counsel`;
/// under the V4 D-0 order it is `external_lp_incentives`, and the last row is
/// what this tamper wants — deleting an INTERIOR row shifts every DP1 index
/// after it and turns a small, legible disallowed set into a cascade.
/// The schedule sections are untouched, so `V5`/`V6`/`V8` stay green and the
/// disallowed set stays a short, exactly-asserted list.
///
/// This is the smallest single-row edit that moves `DP3-scan-coverage`:
/// `expected_fixed_sites` is derived from the fixed `APPROVED_ALLOCATIONS`
/// array, which no manifest edit can reach, while `inspected_fixed_sites`
/// counts one site per ACTUAL manifest allocation row.
fn delete_last_allocation_row(root: &std::path::Path) {
    let p = root.join("deployment/mainnet/genesis_manifest.toml");
    let text = std::fs::read_to_string(&p).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    let start = lines
        .iter()
        .rposition(|l| l.trim() == "[[allocation]]")
        .expect("the manifest must carry [[allocation]] tables");
    let end = lines[start..]
        .iter()
        .position(|l| l.starts_with("principal = "))
        .map(|i| start + i)
        .expect("the legal_counsel row must end with its principal line");
    assert!(
        lines[start..=end]
            .iter()
            .any(|l| l.contains("category_id = \"external_lp_incentives\"")),
        "the LAST [[allocation]] table must be the external_lp_incentives row — the D-7 \
         canonical order ends there (V4 D-0 bucket 10) and DP1 row checks are POSITIONAL, \
         so only the tail is index-stable. If it moved, the expected name set below is no \
         longer exact."
    );

    let mut out: Vec<&str> = Vec::new();
    out.extend_from_slice(&lines[..start]);
    out.extend_from_slice(&lines[end + 1..]);
    let new = out.join("\n") + "\n";
    assert_ne!(new, text, "the tamper must actually change the file");
    assert!(
        new.contains("[[counsel_schedule]]"),
        "[[counsel_schedule]] is LEFT IN PLACE — stripping it would additionally fail V5 \
         and change the expected disallowed set"
    );
    assert!(
        !new.contains("category_id = \"external_lp_incentives\""),
        "the allocation row must be gone"
    );
    std::fs::write(&p, new).unwrap();
}

// BINDING: B-R3A-CLI-POSTURE
#[test]
fn r3a_posture_cli_distinguishes_pass_from_dp3_scan_coverage_disallowed() {
    // ── 1. POSITIVE CONTROL: the committed deployment dir.
    let (pass_status, pass_out) = run_posture_cli(&deployment_dir());
    assert!(
        pass_status.success(),
        "the committed tree's declared posture must PASS at the CLI boundary:\n{pass_out}"
    );
    // RR-1b RETARGET: the committed record now declares `rr1_performed = true`
    // (genesis_principals.toml), so it is main.rs's FIRST pass branch — the
    // STRICT one, satisfied only by an EXACTLY EMPTY failing set — that must
    // have printed. The marker line remains the only evidence distinguishing
    // 'the stage ran and passed' from 'the stage never ran'.
    assert!(
        pass_out.contains(&format!(
            "{POSTURE_MARKER} pass — rr1_performed=true and the observed failing set is \
             EXACTLY EMPTY"
        )),
        "the CLI must print the rr1_performed=true pass marker — it is the ONLY evidence \
         distinguishing 'the stage ran and passed' from 'the stage never ran':\n{pass_out}"
    );
    let committed_failing = run_posture_on_dir(&deployment_dir()).expect("posture").0.failing;

    // ── 2. UNTAMPERED-SCRATCH CONTROL. The scratch root must be
    // INDISTINGUISHABLE from the committed one before the tamper — otherwise
    // the negative below would be attributable to the scaffolding, not the
    // tamper.
    let clean = posture_scratch_root("clean");
    let clean_dir = clean.join("deployment/mainnet");
    let (clean_status, clean_out) = run_posture_cli(&clean_dir);
    assert!(
        clean_status.success(),
        "the UNTAMPERED scratch root must pass exactly as the committed tree does; if it \
         does not, the symlink/copy construction is itself failing checks:\n{clean_out}"
    );
    // The set-equality is asserted IN-PROCESS: the CLI's pass path prints only
    // a count line, never per-name detail, so there is nothing in stdout to
    // reconstruct a passing run's failing set from.
    let clean_failing = run_posture_on_dir(&clean_dir).expect("posture").0.failing;
    assert_eq!(
        clean_failing, committed_failing,
        "the untampered scratch root's failing set must be EXACTLY the committed tree's. \
         This is the vacuity guard for the negative below: if a tamper were applied here by \
         accident, or the scaffolding perturbed a check, this fires."
    );

    // ── 3. NEGATIVE: the same construction, with the LAST allocation row
    // (external_lp_incentives, V4 D-0 bucket 10) deleted.
    let bad = posture_scratch_root("dp3");
    let bad_dir = bad.join("deployment/mainnet");
    delete_last_allocation_row(&bad);
    let (bad_status, bad_out) = run_posture_cli(&bad_dir);
    assert!(
        !bad_status.success(),
        "a DP3-scan-coverage failure is outside the closed pre-RR-1 allowed set by \
         construction and must exit NONZERO:\n{bad_out}"
    );

    // Rule (c): >=2 invocations of run_posture_cli with differing arguments,
    // and an inequality asserted on their results.
    assert_ne!(
        pass_status.code(),
        bad_status.code(),
        "the CLI must DISTINGUISH the committed tree from the tampered scratch at the \
         process boundary; if the two exit codes agree, the posture stage's verdict never \
         reaches run_gate.sh"
    );

    // AC-6: the exact DISALLOWED set, read from the negative's own stdout —
    // main.rs prints per-name detail ONLY on the failing path.
    let mut names: Vec<String> = bad_out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("DISALLOWED  "))
        .map(|r| r.split(" — ").next().unwrap().trim().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "D10-artifact-row-count",
            "D2-manifest-sum-checked",
            "D3-percent-sum",
            "DP0-approved-row-count",
            "DP1-row-10-external_lp_incentives",
            "DP3-scan-coverage",
            "GP1-role-extra-EXTERNAL_LP_INCENTIVES",
            "GP1-role-missing-UNBOUND_ARTIFACT_ROW_10",
        ],
        "the disallowed set must be EXACTLY these EIGHT names — asserted as a set, not by \
         `contains`, so a check that silently stops running is a failure here rather than \
         a quiet loss of coverage. Lane A-2: the tamper moved from the (interior) \
         legal_counsel row to the tail external_lp_incentives row, so the two counsel \
         schedule-sum names (V6/V8) are correctly no longer in the set — the schedules are \
         untouched by this tamper. Full output:\n{bad_out}"
    );
}
