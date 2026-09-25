// build.rs — resolves canister Wasm paths at compile time.
//
// ── IMPORTANT: Wasm files are NOT built here ─────────────────────────────────
//
// This script does NOT build canister Wasms. It only records their on-disk paths
// as compile-time env vars. Tests load Wasms at runtime via std::fs::read.
//
// CONSEQUENCE: if you edit canister source but skip the Wasm build step, tests
// will run the old pre-edit Wasm and produce silent incorrect results.
// `cargo test -p integration-tests` alone is NOT sufficient after canister changes.
//
// CORRECT WORKFLOW after any canister source change:
//
//   ./run_gate.sh          # or: just gate
//
// That is the canonical gate (workspace root). It performs every step below in
// order, refuses to start if a prerequisite is missing, and — critically — also
// runs the workspace-EXCLUDED canisters/vetkeys suite, which `cargo test
// --workspace` cannot see. Prefer it over hand-assembling the sequence.
//
// The steps it encapsulates, for when you need to run one by hand:
//
//   # 1. Test Wasms — FOUR of them, and this must come first.
//   #    Each exposes test-only endpoints the suites depend on:
//   #      shielded_pool  inject_private_liability_for_test
//   #      treasury       inject_inflight_proposal_for_test
//   #      stsh_token     debug_credit_balance_for_test        (B1)
//   #      merkle_tree    stable-map corruption hook           (P-MRK)
//   for c in shielded_pool treasury stsh_token merkle_tree; do
//       cargo build --target wasm32-unknown-unknown --release -p "$c" --features testing
//       cp target/wasm32-unknown-unknown/release/"$c".wasm \
//          target/wasm32-unknown-unknown/release/"$c"_test.wasm
//   done
//
//   # 2. Rebuild all canister Wasms (production; overwrites the plain names).
//   #    This list must cover every *_WASM env var exported below.
//   cargo build --target wasm32-unknown-unknown --release \
//       -p stsh_token -p staking -p shielded_pool -p nullifier_registry \
//       -p merkle_tree -p treasury -p vesting -p stsh-verifier \
//       -p stsh-stub-verifier -p stub_bad_fee_token -p smoke_alarm_monitor
//
//   # 3. Run the tests. --no-fail-fast is REQUIRED: without it cargo stops at
//   #    the first failing suite, so one missing artifact hides the true state
//   #    of every suite after it.
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test --workspace --locked --no-fail-fast -- --test-threads=1
//
//   # 4. The workspace run is NOT the whole gate. canisters/vetkeys is
//   #    workspace-EXCLUDED (ic-cdk 0.16 vs 0.20 `links` conflict) and is
//   #    therefore invisible to step 3 — it does not run, does not fail, and
//   #    does not appear in the tally.
//   cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked
//
// If a Wasm file is missing entirely, the env var points to a non-existent path
// and tests will fail at runtime with a clear "file not found" message — which
// looks like a regression but is not one. run_gate.sh preflights every artifact
// precisely so that failure mode cannot reach the test run.
//
// ── Suites with ADDITIONAL prerequisites beyond the Wasm build ────────────────
//
// The sequence above covers canister Wasms only. Some suites also consume
// deliberately-uncommitted inputs (Node toolchains, circuit build outputs,
// trusted-setup keys, historical base Wasms). Those are declared in full in each
// suite's own file header, and asserted at the point of use:
//
//   pmrk_public_sync_tests.rs      npm ci --prefix circuits (circomlibjs +
//                                  snarkjs), circuits/build/spend_js/spend.wasm,
//                                  circuits/build/spend_1.zkey (M5 ceremony key,
//                                  NOT regenerable), and the ef635ce base
//                                  merkle_tree Wasm for the real upgrade test.
//   prec_recovery_index_tests.rs   the 20a6fb3 (P-REC v1-era, pre-P-ROOT) base
//                                  shielded_pool TEST Wasm for the real v1→v2
//                                  schema-migration regression (worktree build;
//                                  exact command in that suite's require guard).
//   token_icrc_conformance_tests.rs  $ICRC_REF_LEDGER_WASM (pinned release).
//
// A missing prerequisite fails loudly with the exact command that produces it —
// no suite silently degrades to a weaker check when one is absent.
// ─────────────────────────────────────────────────────────────────────────────

use std::path::PathBuf;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // integration-tests/ is one level below the workspace root
    let workspace = PathBuf::from(&manifest)
        .parent()
        .expect("integration-tests must be inside the workspace")
        .to_owned();

    let target = workspace
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release");

    // Export each Wasm path as a compile-time env var
    let canisters = [
        ("TOKEN_WASM",     "stsh_token.wasm"),
        // B1: token built with --features testing (debug_credit_balance_for_test)
        ("TOKEN_TEST_WASM", "stsh_token_test.wasm"),
        ("STAKING_WASM",   "staking.wasm"),
        ("POOL_WASM",      "shielded_pool.wasm"),
        ("NULLIFIER_WASM", "nullifier_registry.wasm"),
        ("MERKLE_WASM",    "merkle_tree.wasm"),
        ("TREASURY_WASM",  "treasury.wasm"),
        ("VESTING_WASM",   "vesting.wasm"),
        // A2-0: dedicated verifier canister (standalone, no pool linkage)
        ("VERIFIER_WASM",      "stsh_verifier.wasm"),
        // #87: test-only stub verifier (always Ok(())) for fee-routing tests
        ("STUB_VERIFIER_WASM", "stsh_stub_verifier.wasm"),
        // #89: test-only pool Wasm with inject_private_liability_for_test endpoint
        ("POOL_TEST_WASM",     "shielded_pool_test.wasm"),
        // R-15: exact 9f7c81e predecessor, before payout retry metadata/control.
        // Reproduce with scripts/build_pool_pre_r15_wasm.sh; gate pins its hash.
        ("POOL_PRE_R15_TEST_WASM", "shielded_pool_pre_r15_test.wasm"),
        // F2-REDACT: the PRE-change pool Wasm (018331a, testing feature). Its
        // PendingDeposit still carries a bare `depositor : principal`, which is
        // what makes U1 a genuine decode-compatibility test (old record written
        // by the old Wasm, read back under the new one) rather than a same-Wasm
        // round trip that could not fail.
        ("POOL_PRE_F2REDACT_TEST_WASM", "shielded_pool_pre_f2redact_test.wasm"),
        // #120: stub token that always returns BadFee from icrc1_transfer
        ("STUB_BAD_FEE_TOKEN_WASM", "stub_bad_fee_token.wasm"),
        // #120: treasury built with --features testing (inject_inflight_proposal_for_test)
        ("TREASURY_TEST_WASM", "treasury_test.wasm"),
        // Smoke-alarm solvency monitor (standalone, reads public token data only)
        ("MONITOR_WASM", "smoke_alarm_monitor.wasm"),
        // R-4 RED-1 (SSA landed-diff round 1): the PRE-schema-3 monitor Wasm,
        // built from 115526d — the last commit BEFORE the schema-2→3 bump. Its
        // stable `SolvencySnapshot` has NO `supply_invariant_unavailable`
        // field, which is exactly what makes test_sam_10 a genuine cross-Wasm
        // state-migration test (state written by the old module, decoded by the
        // new one) rather than the same-Wasm round trip test_sam_05 performs
        // and which therefore could not catch the trap.
        ("MONITOR_PRE_V3_TEST_WASM", "smoke_alarm_monitor_pre_v3_test.wasm"),
        // ── Upgrade-persistence hardening Phase 1 ────────────────────────────
        // testing-feature builds of the converted trio. Each is a DISTINCT
        // module from its production counterpart (it carries the read-only
        // eager_cell_probe_for_test export), which is what makes the positive
        // sentinel test a genuine CROSS-Wasm upgrade rather than a same-Wasm one.
        ("NULLIFIER_TEST_WASM", "nullifier_registry_test.wasm"),
        ("MERKLE_TEST_WASM",    "merkle_tree_test.wasm"),
        ("VESTING_TEST_WASM",   "vesting_test.wasm"),
        // Pre-conversion (f2d9ee7) base Wasms — still carry the pre_upgrade
        // checkpoint and never allocate the eager cell's MemoryId. Upgrading
        // one of these to a converted Wasm MUST trap on the surviving sentinel.
        ("NULLIFIER_BASE_F2D9EE7_WASM", "nullifier_registry_base_f2d9ee7.wasm"),
        ("MERKLE_BASE_F2D9EE7_WASM",    "merkle_tree_base_f2d9ee7.wasm"),
        ("VESTING_BASE_F2D9EE7_WASM",   "vesting_base_f2d9ee7.wasm"),
        // P-STK: the pre-P1-fix staking Wasm (0b88405). Carries the zero-weight
        // snapshot defect and the pre-dedup_key PendingLockOp layout, so the
        // cross-Wasm regressions can create genuinely-old stored state and prove
        // the fixed code still handles it.
        ("STAKING_BASE_0B88405_WASM", "staking_base_0b88405.wasm"),
        // ── Upgrade-persistence hardening Phase 2 ────────────────────────────
        // testing-feature builds of the converted pair. Each is a DISTINCT
        // module from its production counterpart (it carries the read-only
        // eager_cell_probe_for_test export), which is what makes the positive
        // sentinel test a genuine CROSS-Wasm upgrade rather than a same-Wasm one.
        // treasury_test.wasm is already exported above (TREASURY_TEST_WASM).
        ("STAKING_TEST_WASM", "staking_test.wasm"),
        // Pre-conversion (944d8c1) base Wasms — still carry the pre_upgrade
        // checkpoint and never allocate the Phase-2 eager cells' MemoryIds.
        // Upgrading one of these to a converted Wasm MUST trap on the surviving
        // sentinel.
        ("TREASURY_BASE_944D8C1_WASM", "treasury_base_944d8c1.wasm"),
        ("STAKING_BASE_944D8C1_WASM",  "staking_base_944d8c1.wasm"),

        // ── Custody ring (S2.4) ─────────────────────────────────────────────
        // Added so eager_cell_feature_isolation_tests can scan the ring's
        // shipping artifacts. Both canisters gained WRITE-CAPABLE test-only
        // hooks in S2.3, and until now NOTHING scanned vault.wasm or
        // upgrader.wasm — the same gap that was found for shielded_pool.
        ("VAULT_WASM",         "vault.wasm"),
        ("VAULT_TEST_WASM",    "vault_test.wasm"),
        ("UPGRADER_WASM",      "upgrader.wasm"),
        ("UPGRADER_TEST_WASM", "upgrader_test.wasm"),

        // ── R-1 (token supply integrity) ────────────────────────────────────
        // The BASE production token Wasm, built from master 115526d BEFORE the
        // R-1 fix. It is what makes AC-7a/AC-7b genuine CROSS-Wasm upgrade
        // tests: it writes a real STATE_VERSION 2 checkpoint in which the two
        // new `sum_*` fields are literally ABSENT, which is the only way to
        // prove the Option-as-discriminator decode. A same-Wasm "v2" fixture
        // would round-trip a v3 checkpoint and could not fail.
        //   expected sha256: 154362a64a4ab35acb40517feff6f25b2e96761cd147ced0e7b610600b023777
        //   rebuild:
        //     git worktree add --detach /tmp/stsh-token-base 115526d3a2755b6b5c9ed1f5a0014e746cff8b57 \
        //       && (cd /tmp/stsh-token-base && cargo build --target wasm32-unknown-unknown \
        //            --release -p stsh_token --locked) \
        //       && cp /tmp/stsh-token-base/target/wasm32-unknown-unknown/release/stsh_token.wasm \
        //            target/wasm32-unknown-unknown/release/stsh_token_base_115526d.wasm
        ("TOKEN_BASE_115526D_WASM", "stsh_token_base_115526d.wasm"),

        // The AC-10 "before" side (RED-2 round 2, SSA
        // SSA_LANDED_DIFF_R-1_V2_2026-09-05.md / CTO triage
        // `cto-triage-ssa-landed-diff-round2-2026-09-05`): the SAME base source
        // at 115526d, built with `--features testing` and with the two
        // `performance_counter(0)` measurement wrappers appended VERBATIM from
        // the fixed tree. AC-10 now measures INSTRUCTIONS DIRECTLY on both
        // sides; nothing is derived from cycles. The base Wasm has no hook of
        // its own, and a comparison that can only be run on one side is not a
        // comparison — so the hook is added to the base, identically, and its
        // own cost cancels in the delta.
        //   rebuild (the whole recipe, including the appended wrappers, lives
        //   in the script — a fixture with no committed recipe is an unlisted
        //   reproducibility claim):
        //     scripts/build_token_base_measure_wasm.sh
        //   expected sha256: 45ef18347a985553885b10567f109c2f0230db195aac4dbc1694f4780390c834
        ("TOKEN_BASE_MEASURE_TEST_WASM", "stsh_token_base_115526d_measure_test.wasm"),
    ];

    for (var, file) in &canisters {
        let path = target.join(file);
        println!("cargo:rustc-env={}={}", var, path.display());
        // Re-run this build script when any Wasm changes
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Also rerun if canister sources change (catches fresh builds)
    println!("cargo:rerun-if-changed=../canisters/token/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/staking/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/shielded-pool/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/nullifier-registry/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/merkle-tree/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/treasury/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/vesting/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/verifier/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/stub-verifier/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/stub-bad-fee-token/src/lib.rs");
    println!("cargo:rerun-if-changed=../canisters/smoke-alarm-monitor/src/lib.rs");
    // treasury_test.wasm rerun-if-changed is covered by the treasury/src/lib.rs entry above.
}
