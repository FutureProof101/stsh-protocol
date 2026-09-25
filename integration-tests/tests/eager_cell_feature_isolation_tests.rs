// =============================================================================
// Upgrade-persistence hardening Phase 1 + 2 — testing-feature build isolation
// =============================================================================
//
// Architect condition (2026-07-28) on approving the TEST_CANISTERS 4→7
// expansion:
//
//   "The `testing` feature must be build-gated off by default and provably
//    absent from every production/deploy Wasm — the prod build compiles
//    without it. A test-only feature on nullifier-registry that could weaken
//    the sentinel path in a shipped binary is the one way this bites. Prove it
//    in the report."
//
// This suite is that proof, and it is enforced by the gate on every run rather
// than asserted once in prose. It scans the SHIPPED binaries for the test-only
// export name. `cargo` feature unification is the specific hazard: a `testing`
// feature enabled anywhere in a shared dependency graph can silently leak into
// a sibling build. A byte-level scan of the artifact that would actually be
// deployed is the only check that cannot be fooled by that.
//
// Scope note: the probe is a READ-ONLY query returning the eager cell's raw
// bytes. Even if it did leak it could not write, clear, or weaken the sentinel
// path. The isolation requirement is defence in depth, not the primary guard —
// the primary guard is that the sentinel is validated in `post_upgrade` before
// it can ever become observable.

/// The test-only export added to every converted canister under
/// `--features testing` (the Phase-1 trio and the Phase-2 pair alike).
const PROBE_EXPORT: &[u8] = b"eager_cell_probe_for_test";

/// EVERY test-only export on `shielded_pool` (RB-SWARM-A1, on SSA HOLD 3801394).
///
/// The pool was outside this suite's scan set until now — it is not one of the
/// Phase-1/Phase-2 eager-cell conversions the suite was originally written for.
/// A-1 changed that: it added three test-only endpoints to the pool on top of
/// the probe, and its own source comments claimed they were "proved (not
/// asserted)" absent from production. That claim was FALSE for the pool
/// specifically — nothing scanned `shielded_pool.wasm`. SSA's byte scan found
/// the shipping artifact clean, but a one-time manual observation is not a gate.
///
/// These four are listed EXPLICITLY rather than derived, because the failure
/// this guards against is someone adding a fifth and not thinking about it.
/// Two of them can WRITE (unlike the read-only probe): the unguarded fee setter
/// bypasses the entire RULED guardrail policy, and the corruption hooks plant a
/// hostile checkpoint and clear a stable region. A leak of those into a shipped
/// binary is not defence-in-depth — it is the vulnerability itself.
///
/// R-2 (C-30) added four more, listed here for the same reason: the blanket
/// `_for_test` sweep below already covers the PRODUCTION-negative side, but the
/// TEST-POSITIVE side needs each name written down, or a rename would silently
/// void the negative assertion for that symbol. Three of the four can WRITE —
/// the window-bytes plant corrupts a stable region, the timer driver invokes the
/// production flush callback, and the withdrawal driver runs the production
/// unshield finalizer.
const POOL_TEST_EXPORTS: [&[u8]; 22] = [
    b"set_governance_fee_params_unchecked_for_test",
    b"plant_corrupt_checkpoint_for_test",
    b"drop_fee_governance_region_for_test",
    PROBE_EXPORT,
    // R-2 (C-30)
    b"plant_fee_flush_window_bytes_for_test",
    b"fire_fee_flush_timer_for_test",
    b"finalize_confirmed_withdrawal_payout_for_test",
    b"get_treasury_notifications_in_flight_hwm_for_test",
    // R-8 (SI-11): the pool's read-back of what its own mid-flight observer
    // saw in treasury. Read-only, but listed for the same reason as the rest —
    // a rename would silently void the production-negative assertion for it.
    b"observed_reservation_status_for_test",
    // R-9 (B-3-INTENT-*): the pool's read-back of a PendingSpend's stored payout
    // intent. Read-only, but listed for the same reason as the rest — a rename
    // would silently void the production-negative assertion for it.
    b"pending_spend_intent_for_test",
    // R-15: every new fault/read hook must exist only in testing builds.
    b"r15_fault_for_test",
    b"r15_live_for_test",
    b"r15_fixture_split_for_test",
    b"r15_accrual_for_test",
    b"r15_record_reads_for_test",
    b"r15_corrupt_frozen_for_test",
    b"r15_control_fault_for_test",
    b"r15_release_all_for_test",
    b"r15_provision_fault_for_test",
    b"r15_control_public_for_test",
    b"r15_seed_history_for_test",
    b"r15_no_payout_for_test",
];

fn read(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "{label}: cannot read {path}: {e}\n\
             Run ./run_gate.sh — the two-phase build produces both variants."
        )
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every PRODUCTION Wasm of a converted canister must be free of the test-only
/// export. A failure here means a test-only surface reached a deployable
/// artifact.
#[test]
fn production_wasms_do_not_export_the_test_probe() {
    let prod = [
        (env!("NULLIFIER_WASM"), "nullifier_registry"),
        (env!("MERKLE_WASM"), "merkle_tree"),
        (env!("VESTING_WASM"), "vesting"),
        // Phase 2
        (env!("TREASURY_WASM"), "treasury"),
        (env!("STAKING_WASM"), "staking"),
    ];
    for (path, label) in prod {
        let wasm = read(path, label);
        assert!(
            !contains(&wasm, PROBE_EXPORT),
            "{label}: PRODUCTION Wasm contains the test-only export \
             `eager_cell_probe_for_test`. The `testing` feature has leaked into a \
             deployable artifact — do NOT ship this build."
        );
    }
}

/// The converse, so the check above cannot pass vacuously: if the scan could
/// never find the export at all (wrong name, stripped symbols, changed
/// codegen), the production assertion would be meaningless.
#[test]
fn testing_wasms_do_export_the_test_probe() {
    let test_builds = [
        (env!("NULLIFIER_TEST_WASM"), "nullifier_registry_test"),
        (env!("MERKLE_TEST_WASM"), "merkle_tree_test"),
        (env!("VESTING_TEST_WASM"), "vesting_test"),
        // Phase 2
        (env!("TREASURY_TEST_WASM"), "treasury_test"),
        (env!("STAKING_TEST_WASM"), "staking_test"),
    ];
    for (path, label) in test_builds {
        let wasm = read(path, label);
        assert!(
            contains(&wasm, PROBE_EXPORT),
            "{label}: testing Wasm is MISSING `eager_cell_probe_for_test`. Either the \
             --features testing build did not happen, or the export name changed — \
             which would silently void the production isolation assertion."
        );
    }
}

/// Production and testing builds must be genuinely DIFFERENT modules. If they
/// were byte-identical, the "cross-Wasm" positive sentinel test would in fact
/// be a same-Wasm test, which the brief explicitly rules insufficient.
#[test]
fn production_and_testing_wasms_are_distinct_modules() {
    let pairs = [
        (env!("NULLIFIER_WASM"), env!("NULLIFIER_TEST_WASM"), "nullifier_registry"),
        (env!("MERKLE_WASM"), env!("MERKLE_TEST_WASM"), "merkle_tree"),
        (env!("VESTING_WASM"), env!("VESTING_TEST_WASM"), "vesting"),
        // Phase 2
        (env!("TREASURY_WASM"), env!("TREASURY_TEST_WASM"), "treasury"),
        (env!("STAKING_WASM"), env!("STAKING_TEST_WASM"), "staking"),
    ];
    for (prod_path, test_path, label) in pairs {
        let prod = read(prod_path, label);
        let test = read(test_path, label);
        assert_ne!(
            prod, test,
            "{label}: production and testing Wasms are byte-identical, so the positive \
             sentinel test would not be cross-Wasm. Check that the two-phase build ran in \
             the right order (phase 2 must not overwrite the *_test.wasm copies)."
        );
    }
}

/// The pre-conversion base Wasms must ALSO be distinct from the converted ones,
/// for the same reason on the negative case.
#[test]
fn base_wasms_are_distinct_from_converted_wasms() {
    let pairs = [
        (env!("NULLIFIER_BASE_F2D9EE7_WASM"), env!("NULLIFIER_WASM"), "nullifier_registry"),
        (env!("MERKLE_BASE_F2D9EE7_WASM"), env!("MERKLE_WASM"), "merkle_tree"),
        (env!("VESTING_BASE_F2D9EE7_WASM"), env!("VESTING_WASM"), "vesting"),
        // Phase 2 — pre-conversion base at 944d8c1
        (env!("TREASURY_BASE_944D8C1_WASM"), env!("TREASURY_WASM"), "treasury"),
        (env!("STAKING_BASE_944D8C1_WASM"), env!("STAKING_WASM"), "staking"),
    ];
    for (base_path, prod_path, label) in pairs {
        let base = read(base_path, label);
        let prod = read(prod_path, label);
        assert_ne!(
            base, prod,
            "{label}: the pre-conversion base Wasm is byte-identical to the converted \
             Wasm — the absent-cell trap test would not be cross-Wasm. Rebuild the base \
             from a detached worktree at the pre-conversion commit (f2d9ee7 for the \
             Phase-1 trio, 944d8c1 for the Phase-2 pair)."
        );
    }
}

// =============================================================================
// shielded-pool (RB-SWARM-A1) — same prod-negative / test-positive pairing
// =============================================================================

/// PRODUCTION-NEGATIVE. The shipping pool build must contain NONE of the
/// test-only exports. Every symbol is checked and every failure is collected,
/// so one leak does not mask the others in the report.
#[test]
fn production_pool_wasm_exports_no_test_only_surface() {
    let wasm = read(env!("POOL_WASM"), "shielded_pool");
    let leaked: Vec<String> = POOL_TEST_EXPORTS
        .iter()
        .filter(|sym| contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        leaked.is_empty(),
        "shielded_pool: PRODUCTION Wasm contains test-only export(s) {leaked:?}. The          `testing` feature has leaked into a deployable artifact — do NOT ship this          build. Two of these can WRITE: `set_governance_fee_params_unchecked_for_test`          bypasses the entire RULED fee-guardrail policy, and the corruption hooks plant          a hostile checkpoint / clear the fee-governance region."
    );
}

/// TEST-POSITIVE, so the assertion above cannot pass vacuously. If a rename,
/// symbol stripping, or a codegen change meant the scan could never find these
/// strings at all, the production check would be meaningless while still green
/// — which is the specific way a negative-only gate rots.
#[test]
fn testing_pool_wasm_exports_every_test_only_surface() {
    let wasm = read(env!("POOL_TEST_WASM"), "shielded_pool_test");
    let missing: Vec<String> = POOL_TEST_EXPORTS
        .iter()
        .filter(|sym| !contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        missing.is_empty(),
        "shielded_pool_test: testing Wasm is MISSING {missing:?}. Either the          --features testing build did not happen, or the export name(s) changed —          either way the production isolation assertion above is silently void."
    );
}

/// BLANKET SWEEP — beyond the four named exports.
///
/// Going in, the assumption was that A-1's four hooks were the pool's test-only
/// surface. They are not: the pool's `_test` build carries **46** distinct
/// `_for_test` symbols (the P-REC injectors, the P-ROOT lease hooks, the
/// transport-unknown forcers, the status setters, and A-1's four). Enumerating
/// four of forty-six would have produced a gate that looks thorough and covers
/// under a tenth of the surface — and the next hook added would sit outside it
/// silently, which is the exact failure mode this suite exists to prevent.
///
/// So the naming convention itself is the invariant: NOTHING whose name carries
/// the `_for_test` marker may appear in the shipping build. The production Wasm
/// currently contains zero, so this is enforcing an existing property rather
/// than demanding a new one.
///
/// This is deliberately BROADER than the dispatch asked for, and it is additive
/// — the explicit four above still stand on their own, so a rename that dodged
/// the convention would still be caught for the hooks that matter most.
#[test]
fn production_pool_wasm_contains_no_test_only_naming_convention_at_all() {
    const MARKER: &[u8] = b"_for_test";
    let wasm = read(env!("POOL_WASM"), "shielded_pool");
    assert!(
        !contains(&wasm, MARKER),
        "shielded_pool: PRODUCTION Wasm contains the `_for_test` naming marker — some          test-only surface has leaked into a deployable artifact. Find it with:\n           python3 -c \"import re;print(sorted(set(re.findall(rb'[a-z0-9_]+_for_test',          open('target/wasm32-unknown-unknown/release/shielded_pool.wasm','rb').read()))))\""
    );
}

/// Non-vacuity for the sweep: the marker must be findable where it SHOULD be.
#[test]
fn testing_pool_wasm_does_carry_the_test_only_naming_convention() {
    const MARKER: &[u8] = b"_for_test";
    let wasm = read(env!("POOL_TEST_WASM"), "shielded_pool_test");
    assert!(
        contains(&wasm, MARKER),
        "shielded_pool_test: the `_for_test` marker is absent from the TESTING build, so          the production sweep above cannot detect anything and is silently void."
    );
}

/// The pool's two builds must be genuinely DIFFERENT modules, for the same
/// reason the five converted canisters' are: a byte-identical pair would make
/// the pairing above self-satisfying.
#[test]
fn production_and_testing_pool_wasms_are_distinct_modules() {
    let prod = read(env!("POOL_WASM"), "shielded_pool");
    let test = read(env!("POOL_TEST_WASM"), "shielded_pool_test");
    assert_ne!(
        prod, test,
        "shielded_pool: production and testing Wasms are byte-identical. Check that the          two-phase build ran in the right order (phase 2 must not overwrite the          *_test.wasm copies)."
    );
}

// =============================================================================
// Custody ring (S2.4) — Vault + Upgrader prod-negative / test-positive pairing
// =============================================================================
//
// The ring was OUTSIDE this suite's scan set until now, exactly as the pool
// was. S2.3 added test-only hooks to both canisters and the report claimed the
// suite's 9/9 result confirmed `testing` was absent from every production Wasm.
// That claim was FALSE for the ring: the tables above list neither canister, so
// adding packages to TEST_CANISTERS extended the BUILD, not these ASSERTIONS.
// A one-time byte scan by a reviewer is not a gate. This is the gate.
//
// Both ring hooks can WRITE, which is why this matters more than the read-only
// probe: `inject_nonterminal_creation_for_test` plants a nonterminal proposal
// that HOLDS the purpose-scoped single-flight lock, and `corrupt_indexes_for_test`
// empties the derived indexes on either canister. A leak of either into a
// deployable custody artifact is not defence-in-depth — it is the vulnerability.

/// EVERY test-only export on `vault`. Listed EXPLICITLY rather than derived,
/// because the failure this guards against is someone adding a third and not
/// thinking about it.
const VAULT_TEST_EXPORTS: [&[u8]; 18] = [
    // §S7 P1-4 (corrective r1) — the production-faithful start seam. It runs the
    // REAL quorum path and merely DROPS the planned management call, which is
    // the only way to hold a start at the await boundary in a test: management
    // `start_canister` always replies within the message, so E2's precondition
    // is otherwise unreachable and would have to be fabricated by hand. It
    // plants nothing — every durable write it leaves is produced by production
    // code — but it IS a write path, so it is listed here like any other.
    b"approve_start_without_issuing_call_for_test",
    // S5A corrective-2: the C8 logical-byte total computed by the SAME function
    // S6 enforcement will use, so the constant and the check share a domain.
    b"c8_logical_total_for_test",
    // S5A corrective Blocker 3: total stable pages, so C6/C8 can be measured
    // against ACTUAL allocation (StableBTreeMap nodes, per-entry slack,
    // MemoryManager buckets) rather than a logical payload sum.
    b"stable_pages_for_test",
    // S5A M1 gate C (spec §C): inline commitment-validation cost, the occupancy
    // it was taken at, and the complete admission path's total. The occupancy
    // readback is listed because "at C12 occupancy" is the load-bearing half of
    // the requirement — a validation measured at an empty registry would pass
    // its budget while saying nothing about the state that budget bounds.
    b"measure_companion_validation_for_test",
    b"companion_occupancy_for_test",
    b"last_propose_instructions_for_test",
    // S5A M1 gate A: reports instructions consumed by one sweep call plus the
    // records it reaped, so c_fixed_worst and c_record_worst can be separated
    // by intercept and slope rather than guessed from a single total.
    b"measure_sweep_instructions_for_test",
    // S5A I_msg probe (CTO ruling T0010Z leg (i)): burns instructions to find
    // the per-message ceiling empirically, because every ruled budget is a
    // fraction of a limit pinned nowhere in this repo. Unbounded compute by
    // construction — it must never reach a deployable artifact.
    b"burn_instructions_for_test",
    // S5A M1 gate A: injects candidate proposal-lifetime bounds / sweep work
    // limit into a DEPLOYED canister. Without it the expiry index is empty by
    // construction and the sweep's per-record cost cannot be measured at all.
    // Production constants stay None; this symbol must be ABSENT from the
    // release Wasm, which the leak test below asserts.
    b"set_lifetime_params_for_test",
    b"inject_nonterminal_creation_for_test",
    b"corrupt_indexes_for_test",
    // S5B W5(a): arms one of the two governance trap boundaries so the
    // rollback evidence can run through a real PocketIC message boundary.
    // The §4 amendment rules an in-process Rust panic inadmissible as
    // evidence, so the trap must fire inside a deployed Wasm — which is why
    // this hook exists at all rather than the test calling an internal helper.
    b"arm_governance_trap_for_test",
    // SSA RF-1 (W2 acceptance 11): arms the COMPANION-WRITE boundary so the
    // index-writes-and-accounting rollback can be proved through a real
    // PocketIC message boundary. Detection had evidence; rollback did not.
    b"arm_companion_trap_for_test",
    // SSA RF-6: injects candidate C9 values into a DEPLOYED canister, which the
    // native thread_local hook cannot reach. Brief §3 holds — the production
    // constant stays None and this symbol must be ABSENT from the release Wasm,
    // which the leak test below asserts.
    b"set_entry_rate_params_for_test",
    // SSA RF-3: reports instruction_counter delta for one ID allocation, so
    // cost-at-depth can be measured deterministically under PocketIC rather
    // than guessed from wall-clock.
    b"measure_allocation_instructions_for_test",
    // SSA RF-7: produces the ABSENT-companion state in a deployed canister so
    // B3's rejection can be proved through a real post_upgrade boundary.
    b"clear_companion_state_for_test",
    // S6: injects candidate C5/C7 caps into a DEPLOYED canister. V15 §4
    // obligation 6 measures at occupancy 320, which the real propose path
    // CANNOT reach under the ruled constants — C5 bounds a signer to 32 and the
    // ruled roster maximum is 9, so 9 x 32 = 288 < 320. The top of C7 is ruled
    // margin (the same 9-capacity-plus-1-margin shape V15 states for C8), so
    // the harness must raise the cap to measure at the ceiling.
    b"set_nonterminal_caps_for_test",
    // S6 corrective: injects candidate C6/C8 byte quotas. The allocation sweep
    // measures AT the C8 ceiling, which legal admission cannot reach (C6 x
    // 9-signer roster = 18,874,368 < C8 = 20,971,520; the top C6 is ruled
    // margin, as C7's top 32 slots are).
    b"set_byte_quotas_for_test",
];

/// EVERY test-only export on `upgrader`.
const UPGRADER_TEST_EXPORTS: [&[u8]; 17] = [
    // §S7 P1-4 (corrective r1) — the production-faithful start seam. It runs the
    // REAL quorum path and merely DROPS the planned management call, which is
    // the only way to hold a start at the await boundary in a test: management
    // `start_canister` always replies within the message, so E2's precondition
    // is otherwise unreachable and would have to be fabricated by hand. It
    // plants nothing — every durable write it leaves is produced by production
    // code — but it IS a write path, so it is listed here like any other.
    b"approve_start_without_issuing_call_for_test",
    // S5A M1 gate A — the recovery plane's half of §A's "both canisters".
    b"measure_sweep_instructions_for_test",
    // S5A M1 gate C — the RECOVERY-ORIGIN half of §C, whose budgets apply to
    // both origin paths INDEPENDENTLY. Measuring the Vault and assuming the
    // recovery plane is similar would be the substitute-reading-stronger-than-
    // it-is failure this campaign keeps catching.
    b"measure_companion_validation_for_test",
    b"last_propose_instructions_for_test",
    // S5A M1 gate B: reads back the instruction count recorded by the last
    // approve_recovery, so the one-message rotation envelope can be measured on
    // the real quorum-reaching message rather than approximated.
    b"last_approve_instructions_for_test",
    // S5A M1 gate A — the recovery plane's half of the same injection.
    b"set_lifetime_params_for_test",
    b"corrupt_indexes_for_test",
    // S5B W3 acceptance 13: arms the rotation trap boundary so rollback can be
    // proved through a real PocketIC message boundary. An in-process panic is
    // inadmissible evidence per the §4 amendment, which is why this hook must
    // exist rather than the test calling an internal helper.
    b"arm_rotation_trap_for_test",
    // SSA RF-1 (W2 acceptance 11): the recovery plane's companion-write
    // boundary. Both planes need it — closing only one would leave the other's
    // rollback claim resting on the Vault's evidence, which says nothing about
    // it.
    b"arm_companion_trap_for_test",
    // SSA RF-7: the recovery plane's half of the same evidence.
    b"clear_companion_state_for_test",
    // W3 acceptance 13: injects candidate C12 so the "at C12 occupancy"
    // requirement can be exercised with real occupancy in a deployed canister.
    b"set_nonterminal_caps_for_test",
    // S6: the recovery plane's half of the C9 suspension. The core injector
    // existed since S5B W4; only the ingress hook was missing, which was
    // invisible while C9 was `None`. Both planes must suspend identically or
    // the two sets of §A/§C figures are taken under different regimes.
    b"set_entry_rate_params_for_test",
    // S8A / R6.0 acceptance 4: records a controller-invariant observation in a
    // DEPLOYED canister. The production seam needs two successful management
    // `canister_status` calls, one of them against the Vault as its controller,
    // so reaching it under PocketIC would make a DURABILITY test depend on the
    // full ring wiring — and a wiring failure would then be reported as a
    // durability failure. It calls the SAME core function the production seam
    // calls, so the surviving record is production-shaped.
    b"record_controller_invariant_for_test",
    // S8A / R6.0 acceptance 2: appends filler audit events so MemoryId 4 can be
    // driven past the 10,000-event cap of the removed backwards scan. A WRITE
    // into permanent history — it must never reach a deployable artifact.
    b"seed_audit_events_for_test",
    // S8A / R6.0 acceptance 2: reads back `AUDIT_EVENTS.len()` so the harness
    // proves the tail actually exceeded the cap instead of assuming its seeding
    // worked. A run that seeded short would pass the regression BELOW the cap,
    // which is the substitute-reading-stronger-than-it-is failure again.
    b"audit_len_for_test",
    // S8B: injects candidate R6 refresh constants into a DEPLOYED canister.
    // Without it every S8B acceptance is VACUOUS there — the production
    // constants are `None` on Route 2, so the endpoint refuses `NotRuled`
    // before touching state and a durability test would be asserting that an
    // inert endpoint stayed inert. Production constants are untouched.
    b"set_invariant_refresh_params_for_test",
    // S8B criterion 3: reads the durable MemoryId 12 limiter state, so the
    // real-upgrade test asserts the WINDOW survived rather than inferring it
    // from a refusal that might have had another cause.
    b"refresh_ledger_for_test",
];

/// PRODUCTION-NEGATIVE — the shipping Vault build carries no test-only surface.
#[test]
fn production_vault_wasm_exports_no_test_only_surface() {
    let wasm = read(env!("VAULT_WASM"), "vault");
    let leaked: Vec<String> = VAULT_TEST_EXPORTS
        .iter()
        .filter(|sym| contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        leaked.is_empty(),
        "vault: PRODUCTION Wasm contains test-only export(s) {leaked:?}. The `testing` \
         feature has leaked into a DEPLOYABLE CUSTODY artifact — do NOT ship this build. \
         Both hooks can WRITE: `inject_nonterminal_creation_for_test` plants a proposal \
         holding the purpose-scoped single-flight lock, and `corrupt_indexes_for_test` \
         empties the derived indexes."
    );
}

/// PRODUCTION-NEGATIVE — the shipping Upgrader build likewise.
#[test]
fn production_upgrader_wasm_exports_no_test_only_surface() {
    let wasm = read(env!("UPGRADER_WASM"), "upgrader");
    let leaked: Vec<String> = UPGRADER_TEST_EXPORTS
        .iter()
        .filter(|sym| contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        leaked.is_empty(),
        "upgrader: PRODUCTION Wasm contains test-only export(s) {leaked:?}. \
         `corrupt_indexes_for_test` empties the nonterminal-intent index — leaking it \
         into a deployable recovery-plane artifact would let a member drop the \
         single-flight lock. Do NOT ship this build."
    );
}

/// TEST-POSITIVE, so the negatives above cannot pass vacuously. A rename,
/// symbol stripping or a codegen change that made these strings unfindable
/// would leave the production assertions green and meaningless — which is
/// exactly how a negative-only gate rots.
#[test]
fn testing_vault_wasm_exports_every_test_only_surface() {
    let wasm = read(env!("VAULT_TEST_WASM"), "vault_test");
    let missing: Vec<String> = VAULT_TEST_EXPORTS
        .iter()
        .filter(|sym| !contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        missing.is_empty(),
        "vault_test: testing Wasm is MISSING {missing:?}. Either the --features testing \
         build did not happen, or the export name(s) changed — either way the production \
         isolation assertion above is silently void."
    );
}

#[test]
fn testing_upgrader_wasm_exports_every_test_only_surface() {
    let wasm = read(env!("UPGRADER_TEST_WASM"), "upgrader_test");
    let missing: Vec<String> = UPGRADER_TEST_EXPORTS
        .iter()
        .filter(|sym| !contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        missing.is_empty(),
        "upgrader_test: testing Wasm is MISSING {missing:?} — the production isolation \
         assertion above is silently void."
    );
}

/// The ring's production and testing builds must be genuinely DIFFERENT
/// modules. If they were byte-identical the migration tests would be upgrading
/// a testing build to itself, which is precisely the defect S2.4 fixes.
#[test]
fn ring_production_and_testing_wasms_are_distinct_modules() {
    let pairs = [
        (env!("VAULT_WASM"), env!("VAULT_TEST_WASM"), "vault"),
        (env!("UPGRADER_WASM"), env!("UPGRADER_TEST_WASM"), "upgrader"),
    ];
    for (prod_path, test_path, label) in pairs {
        let prod = read(prod_path, label);
        let test = read(test_path, label);
        assert_ne!(
            prod, test,
            "{label}: production and testing Wasms are byte-identical, so the index-repair \
             migration tests would never exercise the PRODUCTION post_upgrade. Check the \
             two-phase build order (phase 2 must not overwrite the *_test.wasm copies)."
        );
    }
}

/// BLANKET SWEEP (S2.5) — the explicit arrays above are NOT self-enforcing.
///
/// They check only the names written in them. A fourth hook added to either
/// ring canister and omitted from its array is invisible to BOTH the
/// production-negative and the testing-positive check: the negative never looks
/// for it, and the positive only requires the listed names to be present. The
/// S2.4 report claimed "adding a third hook breaks the build" — that was wrong,
/// and this is what makes it true.
///
/// The naming convention itself is the invariant, exactly as for shielded_pool:
/// NOTHING whose name carries the `_for_test` marker may appear in a shipping
/// custody build. Both production artifacts currently contain zero, so this
/// enforces an existing property rather than demanding a new one.
///
/// Additive, not a replacement: the explicit arrays still stand on their own,
/// so a hook renamed to dodge the convention is still caught for the two hooks
/// that matter most.
#[test]
fn production_ring_wasms_contain_no_test_only_naming_convention_at_all() {
    const MARKER: &[u8] = b"_for_test";
    for (var, label, file) in [
        (env!("VAULT_WASM"), "vault", "vault.wasm"),
        (env!("UPGRADER_WASM"), "upgrader", "upgrader.wasm"),
    ] {
        let wasm = read(var, label);
        assert!(
            !contains(&wasm, MARKER),
            "{label}: PRODUCTION Wasm contains the `_for_test` naming marker — some \
             test-only surface has leaked into a DEPLOYABLE CUSTODY artifact. Find it \
             with:\n  python3 -c \"import re;print(sorted(set(re.findall(rb'[a-z0-9_]+_for_test', \
             open('target/wasm32-unknown-unknown/release/{file}','rb').read()))))\""
        );
    }
}

/// Non-vacuity for the sweep: the marker must be findable where it SHOULD be,
/// or the production sweep above can detect nothing and is silently void.
#[test]
fn testing_ring_wasms_do_carry_the_test_only_naming_convention() {
    const MARKER: &[u8] = b"_for_test";
    for (var, label) in [
        (env!("VAULT_TEST_WASM"), "vault_test"),
        (env!("UPGRADER_TEST_WASM"), "upgrader_test"),
    ] {
        let wasm = read(var, label);
        assert!(
            contains(&wasm, MARKER),
            "{label}: the `_for_test` marker is absent from the TESTING build, so the \
             production sweep above cannot detect anything and is silently void."
        );
    }
}

/// EXHAUSTIVENESS of the explicit allowlists (S2.5).
///
/// Extracts every `*_for_test` name actually present in each TESTING build and
/// requires it to appear in that canister's array. This is the check that makes
/// "adding a hook without listing it breaks the build" a true statement: a new
/// hook lands in the testing Wasm, is not in the array, and this fails —
/// pointing at the omission before the blanket sweep has to catch it as a
/// production leak.
#[test]
fn ring_test_export_allowlists_are_exhaustive() {
    fn markers(wasm: &[u8]) -> std::collections::BTreeSet<String> {
        // Scan for the marker, then walk backwards over the identifier chars
        // that precede it to recover the whole symbol name.
        const MARKER: &[u8] = b"_for_test";
        let mut out = std::collections::BTreeSet::new();
        for i in 0..wasm.len().saturating_sub(MARKER.len()) {
            if &wasm[i..i + MARKER.len()] != MARKER {
                continue;
            }
            let mut start = i;
            while start > 0 {
                let c = wasm[start - 1];
                if c.is_ascii_alphanumeric() || c == b'_' {
                    start -= 1;
                } else {
                    break;
                }
            }
            if start < i {
                if let Ok(name) = std::str::from_utf8(&wasm[start..i + MARKER.len()]) {
                    out.insert(name.to_string());
                }
            }
        }
        out
    }

    for (var, label, allow) in [
        (
            env!("VAULT_TEST_WASM"),
            "vault",
            VAULT_TEST_EXPORTS.to_vec(),
        ),
        (
            env!("UPGRADER_TEST_WASM"),
            "upgrader",
            UPGRADER_TEST_EXPORTS.to_vec(),
        ),
    ] {
        let wasm = read(var, label);
        let allowed: std::collections::BTreeSet<String> = allow
            .iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        let found = markers(&wasm);
        // DEAD-ENTRY DETECTION (SSA-authorized 2026-08-08). An allowlist entry
        // matching NO real export is a defect, not harmless slack.
        //
        // The class this kills: a hook named `x_for_test_endpoint` is recorded
        // by the backward-walking scanner above as `x_for_test`, so the
        // "obvious" fix for the resulting failure is to allowlist the truncated
        // name. That goes green immediately while leaving the allowlist naming
        // a symbol that does not exist — and a DIFFERENT future hook named
        // exactly `x_for_test` would then pass unnoticed, with neither the
        // production-negative nor the testing-positive check ever seeing it.
        // This assertion makes that wrong fix fail instead of pass.
        let dead: Vec<&String> = allowed.difference(&found).collect();
        assert!(
            dead.is_empty(),
            "{label}: allowlist names {dead:?}, which match NO export in the testing \
             Wasm. A dead entry is not harmless slack — it silently pre-authorizes a \
             future hook of that name. Either the hook was renamed or removed (drop \
             the entry), or it was misspelled (fix it). Real exports found: {found:?}"
        );

        let unlisted: Vec<&String> = found.difference(&allowed).collect();
        assert!(
            unlisted.is_empty(),
            "{label}: testing Wasm carries `_for_test` export(s) {unlisted:?} that are NOT \
             in the explicit allowlist. Add them to the array in this file — an unlisted \
             hook is invisible to the production-negative and testing-positive checks, \
             which is precisely the gap this test closes. Found: {found:?}"
        );
    }
}

// =============================================================================
// stsh_token (R-8 V1a) — the SI-11 second observer's surfaces
// =============================================================================
//
// The token was OUTSIDE this suite's scan set until now, exactly as the pool
// and the custody ring were. R-8 V1a gives it test-only surfaces of its own —
// the SI-11 observer that fires inside the testing build's `icrc1_fee` — so it
// needs the same prod-negative / test-positive pairing the others have.
//
// One of these can WRITE: `set_si11_observer_for_test` arms an outbound
// inter-canister call from inside the fee handler. A leak of that into a
// shipped ledger would let anyone point the estate's ICRC ledger at an
// arbitrary canister on every fee query — which is not defence-in-depth, it is
// the vulnerability. `debug_credit_balance_for_test` and
// `seed_balance_rows_for_test` write ledger BALANCES directly, bypassing the
// arithmetic funnel; `set_supply_totals_for_test` rewrites the maintained
// totals the solvency attestation is computed from.
//
// The blanket `_for_test` sweep below is what actually covers all seventeen;
// the named list is the TEST-POSITIVE side, where each name has to be written
// down or a rename silently voids the negative assertion for that symbol.
const TOKEN_TEST_EXPORTS: [&[u8]; 6] = [
    // R-8 V1a (SI-11): arms and reads the token-side mid-flight observer.
    b"set_si11_observer_for_test",
    b"si11_observed_reservation_status_for_test",
    // Pre-existing write hooks, listed because they are the highest-severity
    // surfaces on this canister.
    b"debug_credit_balance_for_test",
    b"set_supply_totals_for_test",
    // R-15: every new fault/read hook must exist only in testing builds.
    b"r15_set_transfer_fee_for_test",
    b"r15_balance_oversize_for_test",
];

/// PRODUCTION-NEGATIVE.
#[test]
fn production_token_wasm_exports_no_test_only_surface() {
    let wasm = read(env!("TOKEN_WASM"), "stsh_token");
    let leaked: Vec<String> = TOKEN_TEST_EXPORTS
        .iter()
        .filter(|sym| contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        leaked.is_empty(),
        "stsh_token: PRODUCTION Wasm contains test-only export(s) {leaked:?}. The `testing` \
         feature has leaked into a deployable ledger — do NOT ship this build. \
         `set_si11_observer_for_test` arms an outbound call from inside `icrc1_fee`; \
         `debug_credit_balance_for_test` and `set_supply_totals_for_test` write balances and \
         supply totals directly."
    );
}

/// TEST-POSITIVE, so the assertion above cannot pass vacuously.
#[test]
fn testing_token_wasm_exports_every_test_only_surface() {
    let wasm = read(env!("TOKEN_TEST_WASM"), "stsh_token_test");
    let missing: Vec<String> = TOKEN_TEST_EXPORTS
        .iter()
        .filter(|sym| !contains(&wasm, sym))
        .map(|sym| String::from_utf8_lossy(sym).into_owned())
        .collect();
    assert!(
        missing.is_empty(),
        "stsh_token_test: testing Wasm is MISSING {missing:?}. Either the --features testing \
         build did not happen, or the export name(s) changed — either way the production \
         isolation assertion above is silently void."
    );
}

/// BLANKET SWEEP — the naming convention itself is the invariant, so the next
/// hook added to this canister is covered without anyone remembering to list it.
#[test]
fn production_token_wasm_contains_no_test_only_naming_convention_at_all() {
    const MARKER: &[u8] = b"_for_test";
    let wasm = read(env!("TOKEN_WASM"), "stsh_token");
    assert!(
        !contains(&wasm, MARKER),
        "stsh_token: PRODUCTION Wasm contains the `_for_test` naming marker — some test-only \
         surface has leaked into a deployable ledger. Find it with:\n  python3 -c \"import \
         re;print(sorted(set(re.findall(rb'[a-z0-9_]+_for_test',open('target/wasm32-unknown-unknown/release/stsh_token.wasm','rb').read()))))\""
    );
}

/// Non-vacuity for the sweep.
#[test]
fn testing_token_wasm_does_carry_the_test_only_naming_convention() {
    const MARKER: &[u8] = b"_for_test";
    let wasm = read(env!("TOKEN_TEST_WASM"), "stsh_token_test");
    assert!(
        contains(&wasm, MARKER),
        "stsh_token_test: the `_for_test` marker is absent from the TESTING build, so the \
         production sweep above cannot detect anything and is silently void."
    );
}

/// The two builds must be genuinely DIFFERENT modules, or the pairing above is
/// self-satisfying.
#[test]
fn production_and_testing_token_wasms_are_distinct_modules() {
    let prod = read(env!("TOKEN_WASM"), "stsh_token");
    let test = read(env!("TOKEN_TEST_WASM"), "stsh_token_test");
    assert_ne!(
        prod, test,
        "stsh_token: production and testing Wasms are byte-identical. Check that the two-phase \
         build ran in the right order (phase 2 must not overwrite the *_test.wasm copies)."
    );
}
