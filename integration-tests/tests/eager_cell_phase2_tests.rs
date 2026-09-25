// =============================================================================
// Upgrade-persistence hardening Phase 2 — treasury + staking
// =============================================================================
//
// DISPATCH_HARDENING_PHASE2. Two obligations, and they are different in kind:
//
//  A. The Phase-1 SENTINEL contract, repeated for the Phase-2 cells. Its two
//     operational halves cannot be established natively — both need a real
//     replica and two DIFFERENT Wasm modules:
//       (a) target cell ABSENT        → `post_upgrade` MUST trap, on the
//                                       SPECIFIC message, not merely `is_err`
//       (b) legitimate retained state → passes through UNCHANGED, asserted on
//                                       the DURABLE bytes via the probe
//     A same-Wasm install→upgrade→assert test does NOT satisfy this, so (a)
//     installs the pre-conversion 944d8c1 build and (b) upgrades production →
//     testing (a genuinely distinct binary carrying the read-only probe).
//
//  B. The ATOMICITY template, made REAL. Phase 1's converted trio was set-once,
//     so "a rejected operation persists no partial scalar" was vacuous there
//     and was discharged by a recorded proof obligation. Treasury's
//     `fee_log_index` / `next_proposal_id` and staking's `next_position_id`
//     have LIVE mutation paths, so these are running-code tests.
//
// ── RED discipline (dispatch §RED-requirement) ───────────────────────────────
//
// The requirement is NOT blanket, and this header records which is which so no
// reader has to guess:
//
//   REGRESSION (RED on 944d8c1 → GREEN after conversion) — every test that
//   reads a Phase-2 eager cell. On the base Wasm the trap tests do not trap at
//   all (base → base is a clean upgrade through the `pre_upgrade` checkpoint),
//   and the retention/atomicity probes cannot even run: `eager_cell_probe_for_test`
//   does not exist on 944d8c1, so the query is rejected outright. These are
//   marked  [REGRESSION]  below with the exact base-Wasm failure.
//
//   CONTROL (may pass on BOTH) — the atomicity properties that already held at
//   944d8c1 because same-message mutations roll back atomically. Converting to
//   eager cells must not BREAK them, which is precisely what a control proves.
//   Claiming these as RED would be a fabricated RED. They are marked
//   [CONTROL]  below.
//
// PREREQUISITES (preflighted by run_gate.sh — do not run this suite by hand
// without them):
//   treasury_base_944d8c1.wasm / staking_base_944d8c1.wasm — detached worktree
//   treasury_test.wasm / staking_test.wasm                 — --features testing

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Wasm loaders ─────────────────────────────────────────────────────────────

fn load_wasm(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "{label}: cannot read {path}: {e}\n\
             Build artifacts are missing — run ./run_gate.sh (law #7 two-phase build)."
        )
    })
}

fn treasury_prod() -> Vec<u8> { load_wasm(env!("TREASURY_WASM"), "treasury") }
fn treasury_test() -> Vec<u8> { load_wasm(env!("TREASURY_TEST_WASM"), "treasury_test") }
fn treasury_base() -> Vec<u8> { load_wasm(env!("TREASURY_BASE_944D8C1_WASM"), "treasury_base") }
fn staking_prod() -> Vec<u8> { load_wasm(env!("STAKING_WASM"), "staking") }
fn staking_test() -> Vec<u8> { load_wasm(env!("STAKING_TEST_WASM"), "staking_test") }
fn staking_base() -> Vec<u8> { load_wasm(env!("STAKING_BASE_944D8C1_WASM"), "staking_base") }

// ── Mirrored types ───────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum FeeSource { ShieldFee, PrivateTransferFee, UnshieldFee, DexRevenue }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceParams {
    min_proposal_deposit: u128,
    voting_delay_ns: u64,
    voting_period_ns: u64,
    execution_timelock_ns: u64,
    vk_upgrade_timelock_ns: u64,
    quorum_bps: u32,
    treasury_quorum_bps: u32,
    vk_quorum_bps: u32,
    approval_threshold_bps: u32,
}

#[derive(CandidType, Deserialize)]
struct StakingInitArgs {
    token_canister: Principal,
    pool_canister: Principal,
    treasury_canister: Principal,
    initial_rewards_pool: u128,
    initial_emission_rate_per_day: u128,
    governance_params: Option<GovernanceParams>,
}

const STSH: u128 = 100_000_000;
const SEVEN_DAYS_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;
const FOURTEEN_DAYS_NS: u64 = 14 * 24 * 60 * 60 * 1_000_000_000;
const MIN_LOCK_DAYS: u32 = 30;

fn gov_params() -> GovernanceParams {
    GovernanceParams {
        min_proposal_deposit: 1_000 * STSH,
        voting_delay_ns: 0,
        voting_period_ns: 2_000_000_000,
        execution_timelock_ns: SEVEN_DAYS_NS,
        vk_upgrade_timelock_ns: FOURTEEN_DAYS_NS,
        quorum_bps: 1000,
        treasury_quorum_bps: 2000,
        vk_quorum_bps: 3000,
        approval_threshold_bps: 5001,
    }
}

// ── Layout mirrors ───────────────────────────────────────────────────────────
//
// Deliberately RE-STATED rather than imported from stsh-eager-cell: these tests
// assert on the DURABLE on-disk layout, and a test that derived the expected
// bytes from the same code that wrote them could not detect a layout change.

/// `PrincipalRefs<N>` — 1 version byte + N × (1 length byte + 29 padded bytes).
fn principal_sentinel_bytes(n: usize) -> Vec<u8> { vec![0xFFu8; 1 + 30 * n] }
fn principal_slot(bytes: &[u8], i: usize) -> &[u8] {
    let off = 1 + 30 * i;
    let len = bytes[off] as usize;
    &bytes[off + 1..off + 1 + len]
}

/// `Scalars<N>` — 1 version byte + N × 16-byte big-endian words.
fn scalar_sentinel_bytes(n: usize) -> Vec<u8> { vec![0xFFu8; 1 + 16 * n] }
fn scalar_word(bytes: &[u8], i: usize) -> u128 {
    let off = 1 + 16 * i;
    let mut w = [0u8; 16];
    w.copy_from_slice(&bytes[off..off + 16]);
    u128::from_be_bytes(w)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn new_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    cid
}

/// Clear the replica's install_code rate limiter between an install and the
/// upgrade that follows it.
///
/// This is NOT cosmetic. An expensive `init` makes the very next `install_code`
/// message come back `CanisterInstallCodeRateLimited` — a SysTransient reject
/// that never executes `post_upgrade` at all. A trap test that only asserted
/// "the upgrade failed" would PASS on that error while proving nothing. Every
/// negative test below therefore asserts on the trap MESSAGE, and this removes
/// the transient error that would otherwise mask it.
fn settle_install_rate_limit(pic: &PocketIc) {
    pic.advance_time(Duration::from_secs(600));
    for _ in 0..2 {
        pic.tick();
    }
}

/// Read the RAW durable bytes of a named eager cell. Only the testing Wasm
/// exports this — that is the point: it forces the positive case to be a
/// genuinely cross-Wasm upgrade.
fn probe(pic: &PocketIc, cid: Principal, which: &str) -> Vec<u8> {
    let raw = pic
        .query_call(
            cid,
            Principal::anonymous(),
            "eager_cell_probe_for_test",
            candid::encode_one(which.to_string()).unwrap(),
        )
        .unwrap_or_else(|e| panic!("eager_cell_probe_for_test({which}): query rejected: {e:?}"));
    candid::decode_one(&raw).expect("eager_cell_probe_for_test: decode failed")
}

// ── Treasury deployment ──────────────────────────────────────────────────────

const TREASURY_TOKEN: fn() -> Principal = || p(0x11);
const TREASURY_POOL: fn() -> Principal = || p(0x12);
const TREASURY_CONTROLLER: fn() -> Principal = || p(0x13);

fn install_treasury(pic: &PocketIc, cid: Principal, wasm: Vec<u8>) {
    pic.install_canister(
        cid,
        wasm,
        candid::encode_args((TREASURY_TOKEN(), TREASURY_POOL(), TREASURY_CONTROLLER())).unwrap(),
        None,
    );
}

fn fee_split(pic: &PocketIc, cid: Principal, ops: u128) -> Result<(), String> {
    let raw = pic
        .update_call(
            cid,
            TREASURY_POOL(),
            "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, ops, 0u128, 0u128, 0u64)).unwrap(),
        )
        .expect("receive_fee_split: call rejected");
    candid::decode_one(&raw).expect("receive_fee_split: decode failed")
}

fn propose_withdrawal(
    pic: &PocketIc,
    cid: Principal,
    amount: u128,
) -> Result<u64, String> {
    pic.update_call(
        cid,
        TREASURY_CONTROLLER(),
        "propose_withdrawal",
        candid::encode_args((
            "operations".to_string(),
            p(0x77),
            amount,
            "phase2".to_string(),
        ))
        .unwrap(),
    )
    .map(|raw| candid::decode_one(&raw).expect("propose_withdrawal: decode failed"))
    .map_err(|e| format!("{e:?}"))
}

// ── Staking deployment ───────────────────────────────────────────────────────

const STAKING_TREASURY: fn() -> Principal = || p(0x23);

fn staking_init(rewards_pool: u128) -> StakingInitArgs {
    StakingInitArgs {
        token_canister: p(0x21),
        pool_canister: p(0x22),
        treasury_canister: STAKING_TREASURY(),
        initial_rewards_pool: rewards_pool,
        initial_emission_rate_per_day: 7,
        governance_params: Some(gov_params()),
    }
}

fn install_staking(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, rewards_pool: u128) {
    pic.install_canister(
        cid,
        wasm,
        candid::encode_one(staking_init(rewards_pool)).unwrap(),
        None,
    );
}

/// `stake` needs a real token canister to lock against, which these tests
/// deliberately do NOT deploy — the token principal is a dead end, so the
/// inter-canister lock call fails. That is exactly the shape wanted here: it
/// exercises the allocation point and the failure path without needing the
/// whole token stack. The return value is ignored; the cells are the subject.
fn try_stake(pic: &PocketIc, cid: Principal, user: Principal, amount: u128, lock_days: u32, key: &[u8]) -> Result<Result<u64, String>, String> {
    pic.update_call(
        cid,
        user,
        "stake",
        candid::encode_args((amount, lock_days, key.to_vec())).unwrap(),
    )
    .map(|raw| candid::decode_one(&raw).expect("stake: decode failed"))
    .map_err(|e| format!("{e:?}"))
}

// =============================================================================
// A(a) — ABSENT CELL → post_upgrade MUST trap   [cross-Wasm: 944d8c1 → converted]
// =============================================================================
//
// [REGRESSION] RED on 944d8c1. Running this test with the BASE Wasm as the
// upgrade target (944d8c1 → 944d8c1) does not trap at all: the pre-conversion
// build writes its `pre_upgrade` checkpoint into MemoryId 3/4 and `post_upgrade`
// decodes it happily, so `expect_err` fails with "upgrade must trap". Only the
// converted Wasm has a cell to find missing.
//
// The trap is INTENDED, not a defect. Nothing is on mainnet, so there is no
// legacy state to migrate, and silently resurrecting the treasury on default
// refs and reset counters would be far worse than a blocked upgrade.
// Operationally: a rehearsal canister must be WIPED and reinstalled, never
// upgraded across the conversion boundary.

#[test]
fn treasury_absent_eager_cell_traps_on_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);

    // Pre-conversion module: checkpoint at MemoryId 3, no MemoryId 4/5/6.
    install_treasury(&pic, cid, treasury_base());

    settle_install_rate_limit(&pic);

    let err = pic
        .upgrade_canister(cid, treasury_prod(), candid::encode_args(()).unwrap(), None)
        .expect_err(
            "treasury: upgrading from the pre-conversion 944d8c1 Wasm MUST trap — the eager \
             cell regions are absent, so the sentinel survives. A success here means the \
             fail-closed gate has become fail-open.",
        );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("CANISTER_REFS sentinel survived"),
        "must trap on the SENTINEL specifically, not incidentally. Got: {msg}"
    );
}

#[test]
fn staking_absent_eager_cell_traps_on_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);

    install_staking(&pic, cid, staking_base(), 1_000 * STSH);

    settle_install_rate_limit(&pic);

    let err = pic
        .upgrade_canister(cid, staking_prod(), candid::encode_args(()).unwrap(), None)
        .expect_err(
            "staking: upgrading from the pre-conversion 944d8c1 Wasm MUST trap on the \
             surviving sentinel.",
        );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("CANISTER_REFS sentinel survived"),
        "must trap on the SENTINEL specifically, not incidentally. Got: {msg}"
    );
}

// =============================================================================
// A(b) — LEGITIMATE RETAINED STATE PASSES UNCHANGED [cross-Wasm: prod → testing]
// =============================================================================
//
// [REGRESSION] RED on 944d8c1: `eager_cell_probe_for_test` does not exist on the
// base Wasm, so every `probe(...)` below is rejected with
// `CanisterMethodNotFound` and the test panics before it can assert. The
// assertions are on the DURABLE bytes, not on a downstream getter, so the test
// cannot pass by accident if the heap mirror were repopulated from elsewhere.

#[test]
fn treasury_retained_state_survives_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_treasury(&pic, cid, treasury_prod());

    // Mutate BOTH live counters, so retention is proved on moved values rather
    // than on their install-time defaults.
    fee_split(&pic, cid, 5_000).expect("fee split must be accepted from the pool");
    fee_split(&pic, cid, 7_000).expect("fee split must be accepted from the pool");
    let first = propose_withdrawal(&pic, cid, 1_000).expect("proposal must be created");

    settle_install_rate_limit(&pic);

    // Cross-Wasm: production module → testing module (distinct binaries).
    pic.upgrade_canister(cid, treasury_test(), candid::encode_args(()).unwrap(), None)
        .expect("legitimate retained state must upgrade cleanly, not trap");

    let refs = probe(&pic, cid, "refs");
    assert_ne!(refs, principal_sentinel_bytes(3), "refs must not read back as the sentinel");
    assert_eq!(refs[0], 1, "layout version byte must be 1");
    assert_eq!(principal_slot(&refs, 0), TREASURY_TOKEN().as_slice(), "token ref unchanged");
    assert_eq!(principal_slot(&refs, 1), TREASURY_POOL().as_slice(), "pool ref unchanged");
    assert_eq!(
        principal_slot(&refs, 2),
        TREASURY_CONTROLLER().as_slice(),
        "controller ref unchanged"
    );

    let fee_idx = probe(&pic, cid, "fee_log_index");
    assert_ne!(fee_idx, scalar_sentinel_bytes(1), "counter must not read back as the sentinel");
    assert_eq!(fee_idx[0], 1, "layout version byte must be 1");
    assert_eq!(
        scalar_word(&fee_idx, 0),
        2,
        "two fee receipts must leave the durable fee-log index at 2"
    );

    let prop_id = probe(&pic, cid, "next_proposal_id");
    assert_eq!(
        scalar_word(&prop_id, 0),
        (first + 1) as u128,
        "the durable proposal counter must be one past the id actually handed out"
    );

    // And the restored value is in force: the next proposal continues the
    // sequence rather than colliding with the stored one.
    let second = propose_withdrawal(&pic, cid, 1_000).expect("second proposal must be created");
    assert_eq!(second, first + 1, "proposal ids must continue across the upgrade");
}

#[test]
fn staking_retained_state_survives_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_staking(&pic, cid, staking_prod(), 4_242 * STSH);

    // Move the reward record off its install-time value through the real
    // treasury-authenticated path.
    pic.update_call(
        cid,
        STAKING_TREASURY(),
        "receive_fee_revenue",
        candid::encode_one(900u128).unwrap(),
    )
    .expect("receive_fee_revenue must be accepted from the treasury");

    settle_install_rate_limit(&pic);

    pic.upgrade_canister(cid, staking_test(), candid::encode_args(()).unwrap(), None)
        .expect("legitimate retained state must upgrade cleanly, not trap");

    let refs = probe(&pic, cid, "refs");
    assert_ne!(refs, principal_sentinel_bytes(3), "refs must not read back as the sentinel");
    assert_eq!(refs[0], 1, "layout version byte must be 1");
    assert_eq!(principal_slot(&refs, 0), p(0x21).as_slice(), "token ref unchanged");
    assert_eq!(principal_slot(&refs, 1), p(0x22).as_slice(), "pool ref unchanged");
    assert_eq!(principal_slot(&refs, 2), STAKING_TREASURY().as_slice(), "treasury ref unchanged");

    // Every governance scalar, in declaration order — a reordered layout would
    // decode to plausible-but-wrong parameters, which is the failure this
    // catches and a round-trip through the getter would not.
    let gp = probe(&pic, cid, "gov_params");
    assert_ne!(gp, scalar_sentinel_bytes(9), "gov params must not read back as the sentinel");
    let expected = gov_params();
    assert_eq!(scalar_word(&gp, 0), expected.min_proposal_deposit);
    assert_eq!(scalar_word(&gp, 1), expected.voting_delay_ns as u128);
    assert_eq!(scalar_word(&gp, 2), expected.voting_period_ns as u128);
    assert_eq!(scalar_word(&gp, 3), expected.execution_timelock_ns as u128);
    assert_eq!(scalar_word(&gp, 4), expected.vk_upgrade_timelock_ns as u128);
    assert_eq!(scalar_word(&gp, 5), expected.quorum_bps as u128);
    assert_eq!(scalar_word(&gp, 6), expected.treasury_quorum_bps as u128);
    assert_eq!(scalar_word(&gp, 7), expected.vk_quorum_bps as u128);
    assert_eq!(scalar_word(&gp, 8), expected.approval_threshold_bps as u128);

    let rs = probe(&pic, cid, "reward_state");
    assert_ne!(rs, scalar_sentinel_bytes(5), "reward state must not read back as the sentinel");
    assert_eq!(scalar_word(&rs, 0), 4_242 * STSH, "rewards_pool_balance unchanged");
    assert_eq!(scalar_word(&rs, 1), 900, "fee_revenue_balance carries the credited fee");
    assert_eq!(scalar_word(&rs, 2), 7, "emission_rate_per_day unchanged");
    assert!(scalar_word(&rs, 3) > 0, "rewards_start_ns must be a real install timestamp");
    assert_eq!(scalar_word(&rs, 4), 0, "total_distributed unchanged");

    // Both id counters seeded at 1 and untouched by the above.
    assert_eq!(scalar_word(&probe(&pic, cid, "next_position_id"), 0), 1);
    assert_eq!(scalar_word(&probe(&pic, cid, "next_proposal_id"), 0), 1);
}

// =============================================================================
// B — THE ATOMICITY TEMPLATE, MADE REAL
// =============================================================================

/// [CONTROL] A DEFINITE local rejection persists no partial scalar.
///
/// `propose_withdrawal` traps on an over-balance request. The trap happens
/// BEFORE `alloc_proposal_id`, and the whole message segment rolls back
/// regardless — so this property already held at 944d8c1 (heap counter, rolled
/// back with the message) and holds now (eager cell, rolled back with the same
/// message). Labelling it RED would be a fabrication; its job is to prove the
/// conversion did not BREAK it.
///
/// The assertion is on the DURABLE bytes and then across a real upgrade, which
/// is the part that is genuinely new: at 944d8c1 a rolled-back heap counter was
/// only durable because `pre_upgrade` ran later.
#[test]
fn treasury_rejected_proposal_persists_no_partial_counter() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_treasury(&pic, cid, treasury_test());

    fee_split(&pic, cid, 1_000).expect("seed the operations bucket");
    let before = scalar_word(&probe(&pic, cid, "next_proposal_id"), 0);

    // Over-balance: the canister asserts and traps.
    let rejected = propose_withdrawal(&pic, cid, 999_999_999);
    assert!(rejected.is_err(), "an over-balance proposal must be rejected");

    let after = scalar_word(&probe(&pic, cid, "next_proposal_id"), 0);
    assert_eq!(
        after, before,
        "a REJECTED proposal must persist no partial counter — the durable next_proposal_id \
         moved from {before} to {after}"
    );

    // Non-caller-facing corollary: the rejection also left no fee-log drift.
    assert_eq!(
        scalar_word(&probe(&pic, cid, "fee_log_index"), 0),
        1,
        "the rejected proposal must not touch the unrelated fee-log counter"
    );

    // And the id that WOULD have been allocated is still available afterwards.
    let id = propose_withdrawal(&pic, cid, 100).expect("a valid proposal must succeed");
    assert_eq!(id as u128, before, "the rejected call must not have consumed an id");
}

/// [CONTROL] Co-mutated scalars stay atomic; INDEPENDENTLY-mutated scalars stay
/// independent.
///
/// This is the grouping decision under test, not just a counter check. The two
/// treasury counters are in SEPARATE cells because they are written by
/// different operations, and `Cell::set` rewrites the whole cell — so a fee
/// receipt must move the fee index and leave the proposal counter's durable
/// bytes byte-identical, and vice versa. If someone later groups them "for
/// cheapness", this test fails.
#[test]
fn treasury_counter_cells_are_mutually_independent() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_treasury(&pic, cid, treasury_test());

    let prop_before = probe(&pic, cid, "next_proposal_id");

    fee_split(&pic, cid, 3_000).expect("fee split must be accepted");
    assert_eq!(scalar_word(&probe(&pic, cid, "fee_log_index"), 0), 1);
    assert_eq!(
        probe(&pic, cid, "next_proposal_id"),
        prop_before,
        "a fee receipt must leave the proposal counter's durable bytes untouched"
    );

    let fee_before = probe(&pic, cid, "fee_log_index");
    propose_withdrawal(&pic, cid, 100).expect("proposal must be created");
    assert_eq!(scalar_word(&probe(&pic, cid, "next_proposal_id"), 0), 2);
    assert_eq!(
        probe(&pic, cid, "fee_log_index"),
        fee_before,
        "creating a proposal must leave the fee-log counter's durable bytes untouched"
    );
}

/// [CONTROL] A rejected `stake` persists no partial position id.
///
/// C-A2 rejects an out-of-bounds lock at the ENTRY POINT, before any token call
/// and before `alloc_position_id`. As with the treasury case this already held
/// at 944d8c1; the new content is that the invariant is now asserted against
/// DURABLE bytes rather than a heap counter awaiting a checkpoint.
#[test]
fn staking_rejected_stake_persists_no_partial_position_id() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_staking(&pic, cid, staking_test(), 1_000 * STSH);

    let before = probe(&pic, cid, "next_position_id");

    for (amount, lock_days, why) in [
        (0u128, MIN_LOCK_DAYS, "zero amount"),
        (10 * STSH, MIN_LOCK_DAYS - 1, "below the 30-day floor"),
        (10 * STSH, 1096, "above the 1095-day ceiling"),
    ] {
        let outcome = try_stake(&pic, cid, p(0x31), amount, lock_days, b"k1");
        let rejected = match outcome {
            Ok(Ok(id)) => panic!("{why}: stake must be rejected, got position {id}"),
            Ok(Err(e)) => e,
            Err(e) => e,
        };
        assert!(!rejected.is_empty(), "{why}: rejection must carry a reason");
        assert_eq!(
            probe(&pic, cid, "next_position_id"),
            before,
            "{why}: a rejected stake must persist no partial position id"
        );
    }
}

/// [REGRESSION — SSA P1, 2026-07-31] The near-`u64::MAX` lock_end_ns rejection
/// persists no partial position id.
///
/// This is the one `stake` rejection that does NOT trap: C-A2's
/// `now.checked_add(duration_ns)` overflow returns an ordinary `Err`, so the
/// message segment COMMITS. As first written, Phase 2 allocated `position_id`
/// (and `op_id`) before that check, so the eager cell write committed with it
/// and a rejected stake durably consumed an id. The fix moves the check ahead
/// of both allocations.
///
/// RED on `49c936c` (the pre-fix Phase-2 commit): the durable `next_position_id`
/// advances by 1 across the rejected call. Also RED on `944d8c1` in the weaker
/// sense that the probe does not exist there.
///
/// Reaching the overflow needs replica time within one lock-duration of
/// `u64::MAX` nanoseconds — around the year 2551 — which `set_time` can express
/// exactly and no amount of `advance_time` realistically can.
#[test]
fn staking_lock_end_overflow_rejection_persists_no_partial_position_id() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_staking(&pic, cid, staking_test(), 1_000 * STSH);

    let before = probe(&pic, cid, "next_position_id");

    // Jumping the clock ~530 years forward bills the canister for that whole
    // idle period, so top it up first — otherwise the stake call comes back
    // CanisterOutOfCycles and the assertion below would hold for the wrong
    // reason (no allocation because the message never ran).
    pic.add_cycles(cid, 100_000_000_000_000_000_000u128);

    // One day short of u64::MAX: any lock of 30 days or more overflows the sum.
    const DAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
    pic.set_time(pocket_ic::Time::from_nanos_since_unix_epoch(u64::MAX - DAY_NS));
    pic.tick();

    let outcome = try_stake(&pic, cid, p(0x33), 10 * STSH, MIN_LOCK_DAYS, b"overflow");
    let err = match outcome {
        Ok(Ok(id)) => panic!("a lock_start this close to u64::MAX must be rejected, got {id}"),
        Ok(Err(e)) => e,
        Err(e) => e,
    };
    assert!(
        err.contains("lock_end_ns overflow"),
        "must be rejected by the C-A2 overflow guard specifically, not incidentally: {err}"
    );

    assert_eq!(
        probe(&pic, cid, "next_position_id"),
        before,
        "a lock_end_ns overflow returns Err WITHOUT trapping, so the message segment \
         commits — the position counter must therefore never have been allocated. \
         Durable next_position_id moved, which means a rejected stake consumed an id."
    );
    assert_eq!(
        scalar_word(&probe(&pic, cid, "next_position_id"), 0),
        1,
        "and it must still be the SEEDED value, not merely stable"
    );

    // Not vacuous: with the clock rolled back, the same request allocates.
    let pic2 = PocketIc::new();
    let cid2 = new_canister(&pic2);
    install_staking(&pic2, cid2, staking_test(), 1_000 * STSH);
    let baseline = scalar_word(&probe(&pic2, cid2, "next_position_id"), 0);
    let _ = try_stake(&pic2, cid2, p(0x33), 10 * STSH, MIN_LOCK_DAYS, b"overflow");
    assert!(
        scalar_word(&probe(&pic2, cid2, "next_position_id"), 0) > baseline,
        "a request that passes the overflow guard MUST allocate — otherwise the assertion \
         above would hold for the wrong reason"
    );
}

/// [CONTROL] A retry cannot double-apply the position counter.
///
/// The scope clause is deliberate: this exercises the EXISTING C-A5 idempotent
/// path only. Transport-unknown idempotency of a previously non-idempotent
/// interface is explicitly OUT of scope for Phase 2 and is not improvised here.
///
/// The token canister is a dead principal, so the `lock_for_staking` call
/// cannot succeed; the retry with the SAME dedup key must therefore resolve
/// through STAKE_DEDUP to the original outcome and must NOT allocate a second
/// position id. A distinct key is then shown to allocate normally, so the test
/// cannot pass merely because nothing ever advances.
#[test]
fn staking_dedup_retry_does_not_double_advance_position_id() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_staking(&pic, cid, staking_test(), 1_000 * STSH);

    let user = p(0x32);
    let _ = try_stake(&pic, cid, user, 10 * STSH, MIN_LOCK_DAYS, b"dedup-key");
    let after_first = scalar_word(&probe(&pic, cid, "next_position_id"), 0);

    let _ = try_stake(&pic, cid, user, 10 * STSH, MIN_LOCK_DAYS, b"dedup-key");
    assert_eq!(
        scalar_word(&probe(&pic, cid, "next_position_id"), 0),
        after_first,
        "an identical retry must resolve through the dedup record, not allocate a second id"
    );

    let _ = try_stake(&pic, cid, user, 10 * STSH, MIN_LOCK_DAYS, b"different-key");
    assert!(
        scalar_word(&probe(&pic, cid, "next_position_id"), 0) > after_first,
        "a genuinely new request must still allocate — otherwise the assertion above is vacuous"
    );
}

/// [REGRESSION] The grouped canister-ref cell is never half-applied.
///
/// RED on 944d8c1: the probe does not exist there. Either ALL THREE slots hold
/// their principal or the cell is the sentinel; a half-applied state — one slot
/// written, the others still 0xFF — is exactly what one `Cell::set` makes
/// unrepresentable, and is the reason the three refs are grouped.
#[test]
fn grouped_canister_refs_are_never_half_applied() {
    let pic = PocketIc::new();

    for (label, cid, sentinel) in [
        ("treasury", {
            let cid = new_canister(&pic);
            install_treasury(&pic, cid, treasury_test());
            cid
        }, principal_sentinel_bytes(3)),
        ("staking", {
            let cid = new_canister(&pic);
            install_staking(&pic, cid, staking_test(), 1_000 * STSH);
            cid
        }, principal_sentinel_bytes(3)),
    ] {
        let durable = probe(&pic, cid, "refs");
        assert_ne!(durable, sentinel, "{label}: initialised cell must not be the sentinel");
        for slot in 0..3 {
            let raw = &durable[1 + 30 * slot..1 + 30 * (slot + 1)];
            assert!(
                raw.iter().any(|b| *b != 0xFF),
                "{label}: slot {slot} is unwritten — the grouped refs were half-applied"
            );
            assert!(
                !principal_slot(&durable, slot).is_empty(),
                "{label}: slot {slot} decoded to an empty principal"
            );
        }
    }
}

/// [REGRESSION] The reward record is ONE atomic cell write.
///
/// RED on 944d8c1: the probe does not exist there. `receive_fee_revenue`
/// mutates a single field of `RewardState`, and the whole five-word record must
/// come back internally consistent — the mutated field moved, every other field
/// byte-identical. This is the property that justifies grouping the record
/// instead of splitting it into five cells, where a partial write could leave a
/// debit without its counterpart.
#[test]
fn staking_reward_state_is_one_atomic_record_write() {
    let pic = PocketIc::new();
    let cid = new_canister(&pic);
    install_staking(&pic, cid, staking_test(), 5_000 * STSH);

    let before = probe(&pic, cid, "reward_state");
    assert_ne!(before, scalar_sentinel_bytes(5), "init must seed the record, not leave a sentinel");

    pic.update_call(
        cid,
        STAKING_TREASURY(),
        "receive_fee_revenue",
        candid::encode_one(1_234u128).unwrap(),
    )
    .expect("receive_fee_revenue must be accepted from the treasury");

    let after = probe(&pic, cid, "reward_state");
    assert_eq!(
        scalar_word(&after, 1),
        scalar_word(&before, 1) + 1_234,
        "fee_revenue_balance must carry the credit"
    );
    for (i, field) in [
        (0usize, "rewards_pool_balance"),
        (2, "emission_rate_per_day"),
        (3, "rewards_start_ns"),
        (4, "total_distributed"),
    ] {
        assert_eq!(
            scalar_word(&after, i),
            scalar_word(&before, i),
            "{field} must be byte-identical — the record is written as ONE unit"
        );
    }

    // A rejected call (wrong caller — receive_fee_revenue is treasury-only)
    // must leave the whole record untouched, not partially applied.
    let snapshot = probe(&pic, cid, "reward_state");
    let rejected = pic.update_call(
        cid,
        p(0x99),
        "receive_fee_revenue",
        candid::encode_one(1u128).unwrap(),
    );
    assert!(rejected.is_err(), "a non-treasury caller must be rejected");
    assert_eq!(
        probe(&pic, cid, "reward_state"),
        snapshot,
        "a rejected fee credit must persist no partial record"
    );
}
