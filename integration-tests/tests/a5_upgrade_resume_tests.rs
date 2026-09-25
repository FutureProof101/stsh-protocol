// =============================================================================
// STSH — lane A-5 evidence (FU1-1, FU1-2, FU1-3, U10)
// =============================================================================
//
// Cross-Wasm upgrade evidence for the resumable scan and the accounting-cell
// migration, plus the FU1-3 relation lock.
//
// LAW 7: the cross-Wasm items require BOTH a base-built Wasm and the new one —
// a same-Wasm install→upgrade cannot see a seeding failure, because everything
// is then consistently zero and consistently consistent.
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::Deserialize;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

// ── FU1-3 — pool ↔ merkle byte-cap relation lock ─────────────────────────────
//
// MECHANISM (CTO_RULING_A-5_fu13_mechanism.md): a SOURCE-PARSING lock, not the
// compile-time assert originally preferred. The pool cannot name the merkle
// constant at compile time — `canisters/shielded-pool/Cargo.toml` has no merkle
// dependency, and adding one is both out of fence and independently dangerous:
// the pool's own Cargo.toml records that linking a sibling canister crate blew
// the IC Wasm function-complexity limit (2,051,003 > 1,000,000), and merkle
// pulls the same ark-* tree.
//
// This reads the SHIPPED SOURCE of both canisters, so it cannot drift from what
// is actually built — the property a copied constant would lose. The codebase
// already solves this class the same way: verify_memory_ids and the
// did-vs-exports lint are both source-parsing locks in the standing gate.
//
// RULE 4: the lock asserts its own anchors. A source-parsing lock that silently
// failed to find its literal would PASS while proving nothing, which is exactly
// the anchor-uniqueness trap lane A-3 hit. `read_usize_const` therefore requires
// EXACTLY ONE declaration and panics loudly on zero or many.

/// Extract `const NAME: usize = <literal>;` from a source file.
///
/// Requires exactly one declaration: zero means the constant was renamed or
/// moved and the lock is vacuous; more than one means the lock cannot know which
/// value ships. Both are failures, not skips.
fn read_usize_const(file: &Path, name: &str) -> usize {
    let src = std::fs::read_to_string(file)
        .unwrap_or_else(|e| panic!("FU1-3 lock cannot read {}: {e}", file.display()));

    let hits: Vec<usize> = src
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // `const NAME: usize = N;` with an optional `pub`.
            let rest = line.strip_prefix("pub ").unwrap_or(line);
            let rest = rest.strip_prefix("const ")?;
            let rest = rest.strip_prefix(name)?;
            let rest = rest.trim_start().strip_prefix(':')?;
            let rest = rest.trim_start().strip_prefix("usize")?;
            let rest = rest.trim_start().strip_prefix('=')?;
            let value = rest.trim().trim_end_matches(';').trim().replace('_', "");
            value.parse::<usize>().ok()
        })
        .collect();

    assert_eq!(
        hits.len(),
        1,
        "FU1-3 lock: expected EXACTLY ONE `const {name}: usize = …` in {} — found {}. \
         Zero means the lock is vacuous (constant renamed or moved); more than one means \
         it cannot know which value ships. Fix the lock, do not relax it.",
        file.display(),
        hits.len()
    );
    hits[0]
}

#[test]
fn fu1_3_merkle_payload_cap_is_at_least_the_pool_output_cap() {
    let pool_src = repo_root().join("canisters/shielded-pool/src/lib.rs");
    let merkle_src = repo_root().join("canisters/merkle-tree/src/lib.rs");

    let pool_output = read_usize_const(&pool_src, "MAX_ENCRYPTED_OUTPUT_BYTES");
    let pool_payload = read_usize_const(&pool_src, "MAX_ENCRYPTED_PAYLOAD_BYTES");
    let merkle_payload = read_usize_const(&merkle_src, "MAX_ENCRYPTED_PAYLOAD_BYTES");

    // THE RELATION. The pool's outputs eventually become merkle payloads, so
    // merkle must accept everything the pool admits. If merkle < pool, the pool
    // accepts what merkle will later reject — a record the pool considers valid
    // that can never be appended.
    assert!(
        merkle_payload >= pool_output,
        "FU1-3 DRIFT: merkle MAX_ENCRYPTED_PAYLOAD_BYTES ({merkle_payload}) < pool \
         MAX_ENCRYPTED_OUTPUT_BYTES ({pool_output}). The pool would accept outputs the \
         merkle canister will reject on append."
    );
    assert!(
        merkle_payload >= pool_payload,
        "FU1-3 DRIFT: merkle MAX_ENCRYPTED_PAYLOAD_BYTES ({merkle_payload}) < pool \
         MAX_ENCRYPTED_PAYLOAD_BYTES ({pool_payload})."
    );

    // Non-vacuity: this lane locks a RELATION, it does not change a cap. Both
    // sides are 1024 at the pinned base and stay there. If a future lane
    // legitimately moves a cap, this line is the one that makes the change
    // deliberate rather than silent.
    assert_eq!(pool_output, 1024, "pool MAX_ENCRYPTED_OUTPUT_BYTES pinned at 1024");
    assert_eq!(pool_payload, 1024, "pool MAX_ENCRYPTED_PAYLOAD_BYTES pinned at 1024");
    assert_eq!(merkle_payload, 1024, "merkle MAX_ENCRYPTED_PAYLOAD_BYTES pinned at 1024");
}

// ── FU1-2 — RETIRED at R-13 ──────────────────────────────────────────────────
//
// `fu1_2_no_direct_accounting_mutation_outside_the_funnel` was deleted here by
// CTO ruling `cto-ruling-r13-packet-2026-09-07`. It was a LINE-LOCAL text scan
// over the pool source: it missed any write `rustfmt` had split across two
// lines — the exact shape of the real `GOVERNANCE_REWARDS_RESERVE` bypass R-13
// closed — and it RED-ed on a comment that merely quoted a cell name next to
// `borrow_mut`. Two AST locks strictly dominate it and both run today:
//
//   * `r13_accounting_cell_writer_set_is_the_funnel_only`
//     (`r13_pool_accounting_writethrough_tests.rs`) — a depth-aware `syn` walk
//     resolving every write to one of the six cells to its owning fn, asserting
//     the writer set is exactly `{commit_pool_accounting}`.
//   * `fu1_2_known_bypass_census` (`scripts/verify_gate_lints`) — the
//     reference-count census, which asserts the same writer set and baselines
//     the two former bypass fns at zero references.
//
// Deletion, not `#[ignore]`, per the ruling and the no-skips lint.

// ── U10 — the `overflow-checks` detector, MEASURED ───────────────────────────
//
// The property is a RELEASE-PROFILE property, so no unit test can see it: the
// test profile carries its own overflow setting. This drives the release-built
// `shielded_pool_test.wasm` (law 7 phase 1 builds it `--release --features
// testing`) over PocketIC.
//
// E10 has TWO halves and only the pair is evidence:
//   (a) with `overflow-checks = true`  → the call TRAPS      (asserted here)
//   (b) with the flag REMOVED          → the call WRAPS to 0 (the mutation)
//
// Half (b) cannot be asserted from inside a single test run — it requires
// rebuilding the workspace without the flag — so it is the mutation-table row,
// performed and quoted in the package. Half (a) is what pins the shipped state,
// and it is what fails if the flag is ever dropped.

#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
}

fn principal(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn install_pool(pic: &PocketIc) -> Principal {
    let wasm = std::fs::read(env!("POOL_TEST_WASM")).unwrap_or_else(|e| {
        panic!("read shielded_pool_test Wasm {}: {e}", env!("POOL_TEST_WASM"))
    });
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    pic.install_canister(
        cid,
        wasm,
        candid::encode_one(PoolInitArgs {
            token_canister: principal(0x10),
            nullifier_canister: principal(0x11),
            merkle_canister: principal(0x12),
            treasury_canister: principal(0x01),
            staking_canister: principal(0x02),
            controller: principal(0x0C),
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .expect("encode init"),
        None,
    );
    cid
}

#[test]
fn u10_overflow_checks_are_live_in_the_release_profile() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic);

    let res = pic.query_call(
        pool,
        principal(0x0C),
        "overflow_checks_detector_for_test",
        candid::encode_args(()).unwrap(),
    );

    match res {
        Err(reject) => {
            // The shipped state: u128::MAX + 1 traps instead of wrapping.
            let text = format!("{reject:?}");
            assert!(
                text.contains("overflow") || text.contains("trap") || text.contains("Trap"),
                "U10: the detector must trap ON OVERFLOW specifically; got: {text}"
            );
        }
        Ok(bytes) => {
            let wrapped: u128 = candid::decode_one(&bytes).unwrap_or(u128::MAX);
            panic!(
                "U10 DRIFT: `overflow-checks` is NOT active in the release profile — \
                 u128::MAX + 1 returned {wrapped} instead of trapping. A silent wrap in a \
                 release binary is a trap, not a wrong number (P-ARITH R-1). Restore \
                 `overflow-checks = true` in the workspace [profile.release] and in \
                 canisters/vetkeys/Cargo.toml."
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FU1-1 / E1 — over the old cap the upgrade must SUCCEED and resume
// ─────────────────────────────────────────────────────────────────────────────

fn inject_terminal_deposit(pic: &PocketIc, pool: Principal, ctrl: Principal, i: u32) {
    let mut commitment = [0u8; 32];
    commitment[0..4].copy_from_slice(&i.to_be_bytes());
    commitment[31] = 0xAA;
    pic.update_call(
        pool,
        ctrl,
        "inject_terminal_deposit_for_test",
        candid::encode_args((commitment, i as u64, 1_000u64)).expect("encode"),
    )
    .expect("inject_terminal_deposit_for_test");
}

/// E1: 1001 terminal deposits — over `MAX_UPGRADE_SCAN` — must no longer block
/// the upgrade. The failure message is asserted verbatim so that WHICH guard
/// blocks it is visible, rather than just "it trapped".
#[test]
fn e1_over_the_old_cap_the_upgrade_succeeds() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic);
    let ctrl = principal(0x0C);
    for i in 0..1001u32 {
        inject_terminal_deposit(&pic, pool, ctrl, i);
    }
    let wasm = std::fs::read(env!("POOL_TEST_WASM")).expect("read pool test wasm");
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    let res = pic.upgrade_canister(pool, wasm, candid::encode_one(()).unwrap(), None);
    assert!(
        res.is_ok(),
        "FU1-1: an over-cap pool must upgrade and resume, not trap. Got: {res:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// FU1-1 evidence battery — E2, E4, E14, E15
//
// The remaining-work count is read out of the `RecoveryInProgress` payload. The
// reply is a Candid `Result<(), PoolError>` whose Err arm carries the message as
// UTF-8, so the count is recovered by scanning the reply bytes for the literal
// the canister emits. Crude, and deliberately so: it reads what an OPERATOR would
// actually see, rather than a number this test could privately agree with the
// canister about.
// ─────────────────────────────────────────────────────────────────────────────

/// Extract `~N records remaining` from a raw Candid reply, if present.
fn remaining_from_reply(bytes: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(bytes);
    let at = text.find("records remaining")?;
    let head = &text[..at];
    let tilde = head.rfind('~')?;
    head[tilde + 1..].trim().parse::<u64>().ok()
}

/// One gated update. Returns the remaining-work count it reported, or None when
/// the gate let the call through (recovery complete).
fn gated_call(pic: &PocketIc, pool: Principal, caller: Principal) -> Option<u64> {
    match pic.update_call(
        pool,
        caller,
        "reconcile_deposit_commitment",
        candid::encode_one([0u8; 32]).unwrap(),
    ) {
        Ok(bytes) => remaining_from_reply(&bytes),
        Err(_) => None,
    }
}

fn over_cap_pool(pic: &PocketIc, n: u32) -> (Principal, Principal) {
    let pool = install_pool(pic);
    let ctrl = principal(0x0C);
    for i in 0..n {
        inject_terminal_deposit(pic, pool, ctrl, i);
    }
    let wasm = std::fs::read(env!("POOL_TEST_WASM")).expect("read");
    // PocketIC rate-limits consecutive install_code messages; advance time first,
    // exactly as the P-REC suite's `upgrade` helper does.
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    pic.upgrade_canister(pool, wasm, candid::encode_one(()).unwrap(), None)
        .expect("over-cap upgrade must succeed");
    (pool, ctrl)
}

/// E4 (Rule 5): records examined per message never exceed the named const.
/// COUNTED from the falling remaining-work figure — no timing anywhere.
#[test]
fn e4_per_message_work_never_exceeds_the_named_chunk() {
    let pic = PocketIc::new();
    let (pool, ctrl) = over_cap_pool(&pic, 1001);
    let chunk = read_usize_const(
        &repo_root().join("canisters/shielded-pool/src/lib.rs"),
        "UPGRADE_SCAN_CHUNK",
    ) as u64;

    let mut prev = gated_call(&pic, pool, ctrl).expect("recovery must be pending after the upgrade");
    let mut steps = 0;
    while let Some(now) = gated_call(&pic, pool, ctrl) {
        let done = prev.saturating_sub(now);
        assert!(
            done <= chunk,
            "a single message examined {done} records, exceeding UPGRADE_SCAN_CHUNK={chunk}"
        );
        assert!(done > 0, "E15: every gated update must make NONZERO progress");
        prev = now;
        steps += 1;
        assert!(steps < 50, "cursor is not converging");
    }
}

/// E15: the degraded period is bounded and cannot deadlock — the count falls
/// monotonically to zero and the pool opens. Queries advance NOTHING.
#[test]
fn e15_bounded_monotonic_and_queries_advance_nothing() {
    let pic = PocketIc::new();
    let (pool, ctrl) = over_cap_pool(&pic, 1001);

    // A query must not count as progress.
    let before = gated_call(&pic, pool, ctrl).expect("pending");
    for _ in 0..5 {
        let _ = pic.query_call(pool, ctrl, "is_deposits_paused", candid::encode_args(()).unwrap());
    }
    let after_queries = gated_call(&pic, pool, ctrl).expect("still pending");
    // Exactly one chunk of progress happened between the two gated calls: the one
    // the second gated call itself performed. The queries added none.
    assert!(after_queries < before, "the gated call must advance");

    // Monotonic to completion.
    let mut prev = after_queries;
    let mut calls = 0;
    loop {
        match gated_call(&pic, pool, ctrl) {
            Some(now) => {
                assert!(now < prev, "remaining must fall monotonically: {prev} -> {now}");
                prev = now;
            }
            None => break, // gate opened
        }
        calls += 1;
        assert!(calls < 50, "did not converge");
    }
}

/// E14: the pause queries report OPERATOR state only. A recovery closure must not
/// make `is_deposits_paused` lie.
#[test]
fn e14_pause_queries_report_operator_state_only() {
    let pic = PocketIc::new();
    let (pool, ctrl) = over_cap_pool(&pic, 1001);

    // Recovery IS pending here...
    assert!(gated_call(&pic, pool, ctrl).is_some(), "recovery must be pending");
    // ...and the operator has paused nothing, so both queries must say false.
    for q in ["is_deposits_paused", "is_spends_paused"] {
        assert!(!query_bool(&pic, pool, ctrl, q),
            "{q} must report OPERATOR state only, not the recovery closure");
    }

    // The other direction, so the assertion above is not vacuous: an ACTUAL
    // operator pause must flip it to true while recovery is still pending.
    pic.update_call(pool, ctrl, "emergency_pause_deposits", candid::encode_args(()).unwrap())
        .expect("emergency_pause_deposits");
    assert!(query_bool(&pic, pool, ctrl, "is_deposits_paused"),
        "an operator pause MUST be visible — otherwise the false above proves nothing");
    assert!(!query_bool(&pic, pool, ctrl, "is_spends_paused"),
        "pausing deposits must not report spends as paused");

    pic.update_call(pool, ctrl, "unpause_deposits", candid::encode_args(()).unwrap())
        .expect("unpause_deposits");
    assert!(!query_bool(&pic, pool, ctrl, "is_deposits_paused"), "unpause restores false");
}

fn query_bool(pic: &PocketIc, pool: Principal, caller: Principal, method: &str) -> bool {
    let bytes = pic
        .query_call(pool, caller, method, candid::encode_args(()).unwrap())
        .unwrap_or_else(|e| panic!("{method} rejected: {e:?}"));
    candid::decode_one(&bytes).expect("decode bool")
}

/// E13 (SSA-A5-BR1) — the migration safety gate.
///
/// While the nullifier reservations are only PARTIALLY reconstructed, an
/// attacker-reachable spend path must be REFUSED rather than allowed to pass the
/// absent heap protection. `private_spend` is the attacker-reachable entry point;
/// the gate refuses it before any nullifier logic runs, which is the point — the
/// pool never acts on not-yet-reconstructed protection.
#[test]
fn e13_attacker_reachable_spend_is_refused_while_protection_is_unreconstructed() {
    let pic = PocketIc::new();
    // Sized so several chunks remain AFTER the attacker's own call: the refused
    // call itself advances the scan, so a 1001-record pool completes too early for
    // the count-still-falling assertion to mean anything.
    let (pool, ctrl) = over_cap_pool(&pic, 1500);
    let attacker = principal(0xA9);

    // Recovery is pending, so the heap nullifier set is incomplete.
    let first = gated_call(&pic, pool, ctrl).expect("recovery must be pending");

    // The attacker-reachable path is refused, and the refusal is the RECOVERY one.
    // A well-formed PrivateSpendArgs. The VALUES are irrelevant — the gate refuses
    // before any validation — but the SHAPE must decode, or the call would trap in
    // argument decoding before reaching the gate and prove nothing. (It did exactly
    // that on the first attempt.)
    #[derive(CandidType)]
    struct ProofEnvelopeMirror {
        circuit_version: u32,
        proof_system_id: String,
        verifying_key_hash: [u8; 32],
        root_reference: [u8; 32],
        pool_version: u32,
        proof_bytes: Vec<u8>,
    }
    #[derive(CandidType)]
    struct PrivateSpendArgsMirror {
        spend_id: u64,
        envelope: ProofEnvelopeMirror,
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
        encrypted_outputs: Vec<Vec<u8>>,
        fee: u128,
        public_payout: Option<()>,
        expected_deployment_config_hash: Option<[u8; 32]>,
    }
    let args = PrivateSpendArgsMirror {
        spend_id: 7,
        envelope: ProofEnvelopeMirror {
            circuit_version: 1,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0u8; 32],
            root_reference: [0u8; 32],
            pool_version: 1,
            proof_bytes: vec![0u8; 8],
        },
        // The conflicting nullifier: exactly the class of value whose heap
        // reservation is not yet reconstructed while the cursor is pending.
        nullifiers: vec![[0x5Au8; 32]],
        output_commitments: vec![[0u8; 32]],
        encrypted_outputs: vec![vec![0u8; 4]],
        fee: 0,
        public_payout: None,
        expected_deployment_config_hash: None,
    };
    let reply = pic
        .update_call(pool, attacker, "private_spend", candid::encode_one(args).unwrap());
    let text = match &reply {
        Ok(b) => String::from_utf8_lossy(b).to_string(),
        Err(e) => format!("{e:?}"),
    };
    assert!(
        text.contains("recovery scan in progress") || text.contains("RecoveryInProgress"),
        "a spend must be refused with the RECOVERY error while protection is          unreconstructed, got: {text}"
    );

    // And the count is FALLING, so the closure is temporary and self-clearing —
    // including across the ATTACKER's own refused call, which advances the scan
    // exactly like any other gated caller. Being refused is not being idle.
    let second = gated_call(&pic, pool, ctrl).expect("still pending");
    assert!(second < first, "remaining-work count must decrease across gated calls");
}

/// E2: no truncation — every injected record is still present after resumption.
#[test]
fn e2_resumption_loses_no_records() {
    let pic = PocketIc::new();
    let n = 1001u32;
    let (pool, ctrl) = over_cap_pool(&pic, n);
    // Drive to completion.
    let mut calls = 0;
    while gated_call(&pic, pool, ctrl).is_some() {
        calls += 1;
        assert!(calls < 50, "did not converge");
    }
    // count in == count out, read from the authoritative map.
    let bytes = pic
        .query_call(pool, ctrl, "recovery_index_counts_for_test", candid::encode_args(()).unwrap())
        .expect("counts query");
    let (_d, _s, version): (u64, u64, u32) = candid::decode_args(&bytes).expect("decode counts");
    assert_eq!(version, 2, "the stamp appears only on genuine completion");
}

// ─────────────────────────────────────────────────────────────────────────────
// FU1-2 — the eager accounting cell (MemoryId 20)
// ─────────────────────────────────────────────────────────────────────────────

/// The six scalars, read back through the public accounting query.
fn accounting_words(pic: &PocketIc, pool: Principal, caller: Principal) -> Vec<u128> {
    let bytes = pic
        .query_call(pool, caller, "get_accounting_state", candid::encode_args(()).unwrap())
        .expect("get_accounting_state");
    #[derive(candid::Deserialize, CandidType)]
    struct AccountingStateMirror {
        private_liability: u128,
        escrow_backing: u128,
        operations_reserve: u128,
        insurance_reserve: u128,
        governance_rewards_reserve: u128,
        pending_fee_reimbursements: u128,
    }
    let a: AccountingStateMirror = candid::decode_one(&bytes).expect("decode accounting state");
    vec![
        a.private_liability,
        a.escrow_backing,
        a.operations_reserve,
        a.insurance_reserve,
        a.governance_rewards_reserve,
        a.pending_fee_reimbursements,
    ]
}

/// E5: all six scalars NON-ZERO and pairwise DISTINCT survive a real cross-Wasm
/// upgrade with their exact values. Distinctness matters: six equal values (or six
/// zeroes) would pass a survival check even if the restore mixed the words up.
#[test]
fn e5_six_distinct_scalars_survive_the_upgrade_exactly() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic);
    let ctrl = principal(0x0C);
    let want: Vec<u128> = vec![11, 22, 33, 44, 55, 66];
    pic.update_call(
        pool,
        ctrl,
        "set_accounting_words_for_test",
        candid::encode_one(want.clone()).unwrap(),
    )
    .expect("set_accounting_words_for_test");
    assert_eq!(accounting_words(&pic, pool, ctrl), want, "precondition: set took effect");

    let wasm = std::fs::read(env!("POOL_TEST_WASM")).expect("read");
    // PocketIC rate-limits consecutive install_code messages; advance time first,
    // exactly as the P-REC suite's `upgrade` helper does.
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    pic.upgrade_canister(pool, wasm, candid::encode_one(()).unwrap(), None)
        .expect("upgrade must succeed");

    let got = accounting_words(&pic, pool, ctrl);
    assert_eq!(got, want, "each scalar must survive with its EXACT value, in its own slot");
    // Non-zero and pairwise distinct, asserted rather than assumed of the fixture.
    assert!(got.iter().all(|v| *v != 0), "all six must be non-zero");
    let mut sorted = got.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 6, "all six must be pairwise distinct");
}

/// E6: FU1-2 fails CLOSED. A pool whose accounting region is absent — neither
/// cleanly-legacy nor cleanly-migrated — must TRAP on upgrade rather than
/// resurrect itself with zero liability and zero backing.
#[test]
fn e6_absent_accounting_region_traps_the_upgrade() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic);
    let ctrl = principal(0x0C);
    pic.update_call(pool, ctrl, "drop_accounting_region_for_test", candid::encode_args(()).unwrap())
        .expect("drop_accounting_region_for_test");

    let wasm = std::fs::read(env!("POOL_TEST_WASM")).expect("read");
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    let res = pic.upgrade_canister(pool, wasm, candid::encode_one(()).unwrap(), None);
    let text = format!("{res:?}");
    // Guard against proving nothing: a rate-limited install is NOT the fail-closed
    // behaviour under test, and asserting only `is_err()` would have accepted it.
    assert!(
        !text.contains("rate limited"),
        "install_code was rate limited, so the sentinel path never ran: {text}"
    );
    assert!(res.is_err(), "an absent accounting region MUST fail closed, got Ok");
    assert!(
        text.contains("POOL_ACCOUNTING sentinel survived"),
        "the trap must name the sentinel, not fail for some incidental reason: {text}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// E9 — U10's two CHECKED accounting sites, locked at the source
//
// The mutation-table row "revert either `checked_add` to `+=`" has to have
// something to fail. The release-profile detector (E10) proves `overflow-checks`
// is live; it says NOTHING about whether these two sites are checked, because a
// wrapping `+=` under `overflow-checks = true` traps with a generic message
// rather than the fail-closed accounting one. This lock is a source-parsing lock
// for the same reason FU1-3's is: it reads what actually ships.
//
// RULE 4 — the lock asserts its own anchors. Each literal must occur EXACTLY
// once: zero means the site was renamed and the lock is vacuous, more than one
// means it cannot know which site it is pinning.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e9_the_two_accounting_sites_are_checked_arithmetic() {
    let pool_src = repo_root().join("canisters/shielded-pool/src/lib.rs");
    let src = std::fs::read_to_string(&pool_src)
        .unwrap_or_else(|e| panic!("E9 lock cannot read {}: {e}", pool_src.display()));

    for (site, literal) in [
        ("acct_add", "w[word] = w[word].checked_add(amount)"),
        ("acct_sub", "w[word] = w[word].checked_sub(amount)"),
    ] {
        assert_eq!(
            src.matches(literal).count(),
            1,
            "E9 lock: expected EXACTLY ONE `{literal}` (the {site} site) in {}. Zero means \
             the site was renamed or reverted to raw arithmetic and this lock is vacuous; \
             more than one means it cannot know which site ships. Fix the lock, do not \
             relax it.",
            pool_src.display()
        );
    }

    // The fail-closed behaviour is part of the contract, not just the operator.
    // A `checked_add` whose None arm returned a value instead of trapping would
    // satisfy the literals above and still carry a wrong number forward.
    let add_at = src.find("fn acct_add(").expect("E9 lock: `acct_add` not found");
    let sub_at = src.find("fn acct_sub(").expect("E9 lock: `acct_sub` not found");
    let end = src[sub_at..]
        .find("\n}\n")
        .map(|o| sub_at + o)
        .expect("E9 lock: cannot delimit `acct_sub`");
    let body = &src[add_at..end];
    assert_eq!(
        body.matches("ic_cdk::trap(").count(),
        2,
        "E9 lock: `acct_add` + `acct_sub` must trap on overflow/underflow — exactly two \
         trap sites, one each. A returned Err would COMMIT whatever the message already \
         wrote, which is the failure mode U10 exists to remove."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 5 — the per-message bound, MEASURED
//
// §4.1.3: name the per-message work bound as a `const`, justify it against the
// IC INSTRUCTION LIMIT, and MEASURE it — an estimate is not enough here.
//
// `measure_recovery_chunk_instructions_for_test` runs exactly the work the
// ingress gate runs on a refused call (`advance_recovery_cursor()`) inside
// `instruction_counter()` reads. The counter is per-message and resets on each
// message, so what comes back is one continuation message's real cost under the
// profile the gate builds (`--release --features testing`, same
// `[profile.release]`, `overflow-checks = true` included — the profile
// `h1_upgrade_safety_tests.rs:246` records as the more expensive one).
//
// COUNTABLE OBSERVABLE ONLY. Instructions and records visited. No timing.
// ─────────────────────────────────────────────────────────────────────────────

/// The IC's per-message instruction limit for an update call (5B). The bound
/// being justified is `UPGRADE_SCAN_CHUNK` against THIS number — not against
/// memory and not against record count.
const IC_UPDATE_INSTRUCTION_LIMIT: u64 = 5_000_000_000;

/// The budget this lane ships against: 20% of the limit, i.e. a 5x margin.
/// Chosen so the row "raise the per-message bound above the named const" has
/// something to fail against, and so a future chunk-size increase that eats the
/// margin surfaces here rather than on mainnet.
const CHUNK_INSTRUCTION_BUDGET: u64 = IC_UPDATE_INSTRUCTION_LIMIT / 5;

fn measure_chunk(pic: &PocketIc, pool: Principal, ctrl: Principal) -> (u64, u64, u64) {
    let bytes = pic
        .update_call(
            pool,
            ctrl,
            "measure_recovery_chunk_instructions_for_test",
            candid::encode_args(()).unwrap(),
        )
        .expect("measure_recovery_chunk_instructions_for_test");
    candid::decode_args::<(u64, u64, u64)>(&bytes).expect("decode measurement")
}

#[test]
fn rule5_per_message_instruction_cost_is_measured_and_under_budget() {
    let pic = PocketIc::new();
    let (pool, ctrl) = over_cap_pool(&pic, 3003);
    let chunk = read_usize_const(
        &repo_root().join("canisters/shielded-pool/src/lib.rs"),
        "UPGRADE_SCAN_CHUNK",
    ) as u64;

    // The cap is an anti-hang guard, not a bound on the property: it must be
    // loose enough that a SMALLER chunk size (the Rule 2 second measurement)
    // still reaches completion inside the window, or a shrunk chunk would fail
    // here for the harness's reason rather than the code's.
    let mut rows: Vec<(u64, u64, u64)> = Vec::new();
    for _ in 0..2_000 {
        let row = measure_chunk(&pic, pool, ctrl);
        rows.push(row);
        if row.2 == 0 {
            break;
        }
    }
    assert!(
        rows.last().map(|r| r.2) == Some(0),
        "the cursor must complete inside the measured window; rows: {rows:?}"
    );

    // Report every measurement — the package quotes these, so they must be in
    // the test output rather than summarised into a single number.
    for (i, (instr, visited, remaining)) in rows.iter().enumerate() {
        println!(
            "RULE5 message {:>2}: instructions={instr:>12} records_visited={visited:>5} \
             remaining={remaining:>6}",
            i + 1
        );
    }

    let full: Vec<&(u64, u64, u64)> = rows.iter().filter(|r| r.1 == chunk).collect();
    assert!(
        !full.is_empty(),
        "no FULL chunk was measured — a cost taken on a partial chunk does not bound the \
         worst message. rows: {rows:?}"
    );
    let worst = full.iter().map(|r| r.0).max().unwrap();
    println!(
        "RULE5 worst FULL-chunk message: {worst} instructions at UPGRADE_SCAN_CHUNK={chunk}; \
         budget {CHUNK_INSTRUCTION_BUDGET}, IC limit {IC_UPDATE_INSTRUCTION_LIMIT}, margin \
         {:.1}x to the limit",
        IC_UPDATE_INSTRUCTION_LIMIT as f64 / worst as f64
    );
    assert!(
        worst <= CHUNK_INSTRUCTION_BUDGET,
        "a full chunk of {chunk} records cost {worst} instructions, over the shipped budget \
         of {CHUNK_INSTRUCTION_BUDGET} (IC per-message limit {IC_UPDATE_INSTRUCTION_LIMIT}). \
         The chunk size is no longer justified against the instruction limit — lower \
         UPGRADE_SCAN_CHUNK or re-argue the budget, do not raise it silently."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// E13 (payload half) — the remaining-work count is taken AFTER this call's chunk
//
// `CTO_RULING_A-5_recovery_error_V2` requires the count to be computed after the
// advance, so a caller retrying sees the number fall *because of its own call*.
// Monotonic decrease alone does NOT prove that: a count read BEFORE the advance
// also falls across calls, one chunk in arrears. The per-limb mutation table
// found exactly that — the "compute the count before the advance" row did not
// bite against the monotonicity assertions — so this pins the property directly
// by comparing the payload against a non-advancing read of the same cursor.
// ─────────────────────────────────────────────────────────────────────────────

fn probe_remaining(pic: &PocketIc, pool: Principal, caller: Principal) -> u64 {
    let bytes = pic
        .query_call(pool, caller, "recovery_remaining_for_test", candid::encode_args(()).unwrap())
        .expect("recovery_remaining_for_test");
    candid::decode_one::<u64>(&bytes).expect("decode remaining")
}

#[test]
fn e13_the_reported_count_is_taken_after_this_calls_chunk() {
    let pic = PocketIc::new();
    let (pool, ctrl) = over_cap_pool(&pic, 1001);

    let before = probe_remaining(&pic, pool, ctrl);
    assert!(before > 0, "precondition: recovery must still be pending");
    let reported = gated_call(&pic, pool, ctrl).expect("the gate must still be closed");
    let after = probe_remaining(&pic, pool, ctrl);

    assert!(
        reported < before,
        "the payload count must reflect work THIS call performed: probed {before} before, \
         payload said {reported}"
    );
    assert_eq!(
        reported, after,
        "the payload must be the POST-advance count. Got payload {reported} against a \
         non-advancing read of {after} (pre-call read was {before}) — a count taken before \
         the advance is one chunk in arrears and tells the operator that their retry did \
         less than it did."
    );
}

// =============================================================================
// SSA-A5-D1 / SSA-A5-D2 — the two defects the independent landed-diff review
// found, and the evidence that closes them
// =============================================================================
//
// D1: `remaining()` fixed the work at three visits per record, but phase 2's H-1
// normalization REMOVES pre-mutation spends (`Requested` / `VerificationPending`)
// from `PENDING_SPENDS`, and phase 5 then reads the smaller map. The scan
// therefore completed after `3S - R` spend visits while the count still expected
// `3S` — so the COMPLETING call refused once more, reporting `~R records
// remaining` on a scan that was already finished and stamped.
//
// Why the existing evidence could not see it: every continuation fixture used
// TERMINAL DEPOSITS only, which are never removed, so `R` was always 0. And
// E13's post-advance probe compares the payload against a non-advancing read of
// the SAME cursor — both sides shared the incorrect arithmetic, so they agreed.
//
// The assertion below is therefore against GROUND TRUTH rather than against the
// cursor's own arithmetic: **a call that refuses must not be a call after which
// the recovery index is stamped.** The stamp is written only by
// `finish_recovery_build`, i.e. only on genuine completion.

fn inject_verification_pending_spend(pic: &PocketIc, pool: Principal, ctrl: Principal, id: u64) {
    let mut nullifier = [0u8; 32];
    nullifier[0..8].copy_from_slice(&id.to_be_bytes());
    nullifier[31] = 0x02; // keep it a canonical BN254 Fr element
    #[derive(CandidType)]
    enum SpendStatusMirror {
        VerificationPending,
    }
    pic.update_call(
        pool,
        ctrl,
        "inject_spend_with_nullifiers_for_test",
        candid::encode_args((id, vec![nullifier], SpendStatusMirror::VerificationPending))
            .expect("encode"),
    )
    .expect("inject_spend_with_nullifiers_for_test");
}

fn index_version(pic: &PocketIc, pool: Principal, ctrl: Principal) -> u32 {
    let bytes = pic
        .query_call(pool, ctrl, "recovery_index_counts_for_test", candid::encode_args(()).unwrap())
        .expect("recovery_index_counts_for_test");
    candid::decode_args::<(u64, u64, u32)>(&bytes).expect("decode counts").2
}

fn spend_exists(pic: &PocketIc, pool: Principal, ctrl: Principal, id: u64) -> bool {
    let bytes = pic
        .query_call(pool, ctrl, "spend_record_exists_for_test", candid::encode_one(id).unwrap())
        .expect("spend_record_exists_for_test");
    candid::decode_one::<bool>(&bytes).expect("decode exists")
}

#[test]
fn d1_the_count_reaches_zero_on_the_completing_call_with_removable_spends() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic);
    let ctrl = principal(0x0C);

    // Over the old cap, so the scan genuinely spans continuations...
    for i in 0..1001u32 {
        inject_terminal_deposit(&pic, pool, ctrl, i);
    }
    // ...and REMOVABLE spends, which is the shape every prior fixture lacked.
    const REMOVABLE: u64 = 7;
    for id in 1..=REMOVABLE {
        inject_verification_pending_spend(&pic, pool, ctrl, id);
    }
    for id in 1..=REMOVABLE {
        assert!(spend_exists(&pic, pool, ctrl, id), "precondition: spend {id} was injected");
    }

    let wasm = std::fs::read(env!("POOL_TEST_WASM")).expect("read");
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    pic.upgrade_canister(pool, wasm, candid::encode_one(()).unwrap(), None)
        .expect("over-cap upgrade must succeed");

    // Drive to completion, checking the ground truth on EVERY refusal.
    let mut refusals = 0;
    let mut last_reported = u64::MAX;
    for call in 1..=60 {
        match gated_call(&pic, pool, ctrl) {
            Some(reported) => {
                refusals += 1;
                assert!(reported > 0, "a refusal must report outstanding work, got 0");
                assert!(
                    reported < last_reported,
                    "the count must fall on every refusal: {last_reported} -> {reported}"
                );
                last_reported = reported;
                assert_eq!(
                    index_version(&pic, pool, ctrl),
                    0,
                    "SSA-A5-D1: call {call} REFUSED with ~{reported} records remaining, but the \
                     recovery index is already STAMPED — the scan had finished and the message \
                     reported work that does not exist. A count that does not reach zero when \
                     the work is done cannot be told from a stalled scan by an operator."
                );
            }
            None => break,
        }
        assert!(call < 60, "cursor did not converge");
    }
    assert!(refusals > 1, "the fixture must span more than one continuation; got {refusals}");

    // The scan finished: stamped, count exactly zero, and the pool is open.
    assert_eq!(index_version(&pic, pool, ctrl), 2, "the index must be stamped on completion");
    assert_eq!(
        probe_remaining(&pic, pool, ctrl),
        0,
        "the remaining-work count must be EXACTLY zero once the scan is complete"
    );
    // Non-vacuity: the removals this defect is about actually happened.
    for id in 1..=REMOVABLE {
        assert!(
            !spend_exists(&pic, pool, ctrl, id),
            "fixture is vacuous unless spend {id} was actually REMOVED by H-1 normalization"
        );
    }
}

// ── SSA-A5-D2 — the cursor's fail-closed sentinel, both halves ───────────────

#[test]
fn d2_a_corrupt_cursor_is_never_trusted_across_an_upgrade() {
    // WHERE THE DECODER ACTUALLY RUNS, and why this test is shaped as it is:
    // `Cell` caches its value in the heap, so `set`/`get` never round-trip
    // through `Storable`. `from_bytes` runs when the cell is (re-)initialised
    // from stable memory — i.e. across an upgrade. And the branch that then
    // TRUSTS the stored cursor is the STAMPED one, which does not re-arm the
    // cursor. So the reachable shape of "a corrupt cursor must not open the
    // pool" is: complete a migration, corrupt the durable cursor, upgrade again.
    let pic = PocketIc::new();
    let pool = install_pool(&pic);
    let ctrl = principal(0x0C);
    for i in 0..1001u32 {
        inject_terminal_deposit(&pic, pool, ctrl, i);
    }
    let wasm = std::fs::read(env!("POOL_TEST_WASM")).expect("read");

    // 1. First upgrade: the scan runs, and we drive it to genuine completion.
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    pic.upgrade_canister(pool, wasm.clone(), candid::encode_one(()).unwrap(), None)
        .expect("first upgrade must succeed");
    let mut guard = 0;
    while gated_call(&pic, pool, ctrl).is_some() {
        guard += 1;
        assert!(guard < 60, "the first scan must converge");
    }
    assert_eq!(index_version(&pic, pool, ctrl), 2, "control: the pool is now STAMPED and OPEN");

    // 2. Corrupt the durable cursor. It still PARSES; it just is not consistent.
    pic.update_call(
        pool,
        ctrl,
        "set_recovery_cursor_phase_for_test",
        candid::encode_one(200u8).unwrap(),
    )
    .expect("set_recovery_cursor_phase_for_test");

    // 3. Second upgrade — the STAMPED branch, which does not re-arm the cursor,
    //    so the pool's openness rests entirely on what the cell decodes to.
    pic.advance_time(std::time::Duration::from_secs(86_400));
    pic.tick();
    pic.upgrade_canister(pool, wasm, candid::encode_one(()).unwrap(), None)
        .expect("second upgrade must succeed");

    // WHAT THIS ESTABLISHES, stated exactly. On the STAMPED path `post_upgrade`
    // runs every phase eagerly and then writes a complete cursor, so the pool
    // opens on a FACT — the work was just done in this very message — and not on
    // trust in the stored bytes. The corrupt cursor is therefore REPAIRED rather
    // than believed, and no state carries over from it.
    //
    // This also names the limitation honestly: because both `post_upgrade`
    // branches rewrite the cursor, the fail-closed DECODER cannot be reached from
    // the public surface. It is exercised directly instead, in the pool crate's
    // own unit tests (`d2_absent_region_bytes_decode_to_pending_never_complete`,
    // `d2_a_syntactically_valid_cursor_still_has_to_satisfy_its_invariants`), and
    // the initializer that supplies the absent-region value is pinned by
    // `d2_the_absent_region_initializer_is_pending_not_complete`.
    assert!(
        gated_call(&pic, pool, ctrl).is_none(),
        "on the stamped path every phase ran eagerly inside post_upgrade, so the pool must be \
         open on the work actually performed"
    );
    assert_eq!(
        index_version(&pic, pool, ctrl),
        2,
        "the stamp must survive: the corrupt cursor must not have cost the index its stamp"
    );
    assert_eq!(
        probe_remaining(&pic, pool, ctrl),
        0,
        "and the repaired cursor must report zero outstanding work, not the corrupt state"
    );
}

/// The absent-region half of D2 cannot be driven from a test: the region can only
/// be absent before the cell is first written, and `Cell::init`'s default — not
/// `Storable::from_bytes` — is what supplies the value there. That is exactly why
/// the defect survived a fail-closed `from_bytes` and a comment asserting the
/// property. It is locked at the source instead, the same mechanism FU1-3 and E9
/// use, with Rule 4 anchor uniqueness.
///
/// This test FAILS if the initializer is changed back to `complete()`.
#[test]
fn d2_the_absent_region_initializer_is_pending_not_complete() {
    let pool_src = repo_root().join("canisters/shielded-pool/src/lib.rs");
    let src = std::fs::read_to_string(&pool_src)
        .unwrap_or_else(|e| panic!("D2 lock cannot read {}: {e}", pool_src.display()));

    let at = src
        .find("Cell::init(\n            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_RECOVERY_CURSOR)),")
        .expect(
            "D2 lock: the MemoryId 21 `Cell::init` call was not found — it was moved or \
             reshaped and this lock is vacuous. Fix the lock, do not relax it.",
        );
    assert_eq!(
        src.matches("MEMORY_MANAGER.with(|m| m.borrow().get(MEM_RECOVERY_CURSOR))").count(),
        1,
        "D2 lock: MEM_RECOVERY_CURSOR is acquired more than once — the lock cannot know which \
         initializer ships."
    );
    let init_call = &src[at..at + 300];
    assert!(
        init_call.contains("RecoveryCursor::pending_maximal()"),
        "SSA-A5-D2: MemoryId 21's initializer must be FAIL-CLOSED. `Cell::init` uses this value \
         when the region is ABSENT — it does not decode zero bytes through `from_bytes` — so an \
         initializer of `complete()` makes a lost region read as scan-complete and opens the \
         pool with its protections unreconstructed. Got:\n{init_call}"
    );
    assert!(
        !init_call.contains("RecoveryCursor::complete()"),
        "SSA-A5-D2: the MemoryId 21 initializer must not supply a complete cursor:\n{init_call}"
    );

    // D1's companion drift-lock: the removal accounting covers spends because
    // ONLY spend normalization removes records. If deposit normalization ever
    // gains a removal arm, phase 4's visit count silently drops the same way and
    // this is the line that says so.
    let dep_at = src
        .find("fn normalize_deposit_record_for_upgrade(")
        .expect("D1 lock: `normalize_deposit_record_for_upgrade` not found");
    let dep_end = src[dep_at..]
        .find("\n}\n")
        .map(|o| dep_at + o)
        .expect("D1 lock: cannot delimit `normalize_deposit_record_for_upgrade`");
    assert!(
        !src[dep_at..dep_end].contains(".remove("),
        "SSA-A5-D1: deposit normalization now REMOVES records. Phase 4 will read the smaller \
         map and the work snapshot will over-count by one visit per removed deposit, exactly as \
         it did for spends. Count the cancelled visits in phase 3 as phase 2 does, then update \
         this lock."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BR-05 (lane R-11) — the drain loop's PER-CALL RECORD CAP, measured
//
// `canisters/shielded-pool/UPGRADE_BOOTSTRAP_RUNBOOK.md` says the bootstrap
// drain "is bounded per call and resumable — drain the backlog with repeated
// calls".
// MEASURED: r11_drain_loop_per_call_record_cap_is_enforced `e4_per_message_work_never_exceeds_the_named_chunk` above proves the
// UPPER half of that (no call exceeds the cap) — but a drain loop that visited
// ONE record per call would satisfy it just as well, and would not be resumable
// in any useful sense. Nothing asserted the cap is actually SPENT.
//
// This asserts the other half: with a backlog seeded strictly inside a single
// phase, one call visits EXACTLY `UPGRADE_SCAN_CHUNK` records.
// ─────────────────────────────────────────────────────────────────────────────

/// The runbook's documented per-call drain size, as an INDEPENDENT literal.
///
/// Deliberately NOT read back from `UPGRADE_SCAN_CHUNK`: a check that takes its
/// expected value from the artifact it checks cannot detect that artifact
/// changing. Changing `UPGRADE_SCAN_CHUNK` without updating this literal (and
/// the runbook it documents) fails the equality below.
const EXPECTED_DRAIN_CHUNK: u64 = 1_000;

fn recovery_phase(pic: &PocketIc, pool: Principal, ctrl: Principal) -> u8 {
    let bytes = pic
        .query_call(
            pool,
            ctrl,
            "recovery_cursor_phase_for_test",
            candid::encode_args(()).unwrap(),
        )
        .expect("recovery_cursor_phase_for_test");
    candid::decode_one::<u8>(&bytes).expect("decode phase")
}

#[test]
fn r11_drain_loop_per_call_record_cap_is_enforced() {
    let pic = PocketIc::new();
    let chunk = read_usize_const(
        &repo_root().join("canisters/shielded-pool/src/lib.rs"),
        "UPGRADE_SCAN_CHUNK",
    ) as u64;
    assert_eq!(
        chunk, EXPECTED_DRAIN_CHUNK,
        "UPGRADE_SCAN_CHUNK moved to {chunk}. That is a documented operational number: update \
         EXPECTED_DRAIN_CHUNK here AND the per-call figure in \
         canisters/shielded-pool/UPGRADE_BOOTSTRAP_RUNBOOK.md together."
    );

    // Seed 3x the cap, ALL deposits, so the backlog left after `post_upgrade`
    // spends its own first chunk is still ~2x the cap and lives entirely in the
    // deposit phase. A seed spanning a phase boundary would let the boundary,
    // not the cap, decide how many records a call visits.
    let (pool, ctrl) = over_cap_pool(&pic, (3 * EXPECTED_DRAIN_CHUNK) as u32);

    let phase_before = recovery_phase(&pic, pool, ctrl);
    let (_instr, visited, remaining) = measure_chunk(&pic, pool, ctrl);
    let phase_after = recovery_phase(&pic, pool, ctrl);

    assert!(
        remaining > 0,
        "fixture guard: the seed must leave work AFTER this call, or the call could have \
         stopped on completion rather than on the cap (visited={visited})"
    );
    assert_eq!(
        phase_after, phase_before,
        "fixture guard: the measured call crossed a phase boundary ({phase_before} -> \
         {phase_after}), so a short visit count would not mean the cap was respected"
    );
    assert_eq!(
        visited, EXPECTED_DRAIN_CHUNK,
        "one drain call visited {visited} records inside a single phase; the runbook's \
         documented per-call cap is {EXPECTED_DRAIN_CHUNK}. Fewer means the backlog does not \
         drain at the documented rate; more means the per-call bound is not enforced."
    );
}
