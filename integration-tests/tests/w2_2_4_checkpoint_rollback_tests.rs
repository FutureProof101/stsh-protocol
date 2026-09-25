// =============================================================================
// STSH — W2 2-4 (L1-03): stale-checkpoint / rollback guard, cross-Wasm suite
// A1 brief V3 §1 (shape (a)); SSA Checkpoint 1 GREEN 2026-08-18.
// =============================================================================
//
// WHY THIS FILE EXISTS AND WHY NATIVE TESTS CANNOT REPLACE IT: thread-locals
// survive an in-process `post_upgrade()` call, so a native "upgrade" passes
// whether or not state is genuinely durable. The defect here is defined by what
// a REAL upgrade does to a REAL stable region, so it is only provable across a
// Wasm boundary with a real `install_code`.
//
// The untested case the existing skip-pre test does NOT cover
// (h3_followup_skip_pre_tests.rs traps because the cell is EMPTY — no
// pre_upgrade has ever run): after a NORMAL upgrade the cell is non-empty, so
// the empty-checkpoint trap can no longer fire, and a subsequent skip-pre
// upgrade silently restores a STALE checkpoint. That is what this suite drives.
//
// PREREQUISITES: the two-phase build (Law #7) — see run_gate.sh.
// =============================================================================

// =============================================================================
// STSH — H-3 follow-up: `skip_pre_upgrade` is UNSUPPORTED for stsh_token
// BRIEF_TOKEN_DEDUP_FOLLOWUP.md — R2 (behavioural regression test, production Wasm)
// =============================================================================
//
// stsh_token checkpoints ALL heap-only state (BLOCK_HEIGHT, fee reserve, mint flag,
// canister principals, migration state_version) to STABLE_STATE_CELL *only* in
// pre_upgrade. An upgrade with `skip_pre_upgrade = true` therefore skips the only
// write of that cell. On a fresh install the cell is empty, so post_upgrade hits the
// existing empty-checkpoint trap and ABORTS the upgrade — which is exactly the
// protection we lock here. (No production code changes in this lane; this proves the
// existing trap behaviourally and guards against a future regression — e.g. an `init`
// that pre-populates the cell — that would let a skip-pre upgrade silently restore a
// stale snapshot and reset BLOCK_HEIGHT to produce duplicate block indices.)
//
// PocketIC 9.0.2's `upgrade_canister` hardcodes `skip_pre_upgrade: Some(false)`, so
// this issues a raw management-canister `install_code` via
// `update_call_with_effective_principal` with `skip_pre_upgrade: Some(true)`.
//
// PREREQUISITES:
//   cargo build --target wasm32-unknown-unknown --release -p stsh_token
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test h3_followup_skip_pre_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use ic_management_canister_types::{
    CanisterInstallMode, InstallCodeArgs, UpgradeFlags, WasmMemoryPersistence,
};
use pocket_ic::common::rest::RawEffectivePrincipal;
use pocket_ic::PocketIc;
use std::time::Duration;
use serde::{Deserialize, Serialize};

// ── Wasm loader (PRODUCTION only — no test-feature build needed) ─────────────

fn token_test_wasm() -> Vec<u8> {
    let path = env!("TOKEN_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token TEST Wasm at {}: {}.\nBuild first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing\n  \
             cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
             target/wasm32-unknown-unknown/release/stsh_token_test.wasm",
            path, e
        )
    })
}

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token Wasm at {}: {}.\nBuild first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token",
            path, e
        )
    })
}

// ── Constants — must match canisters/token/src/lib.rs ────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH, 8 decimals
const STSH: u128 = 100_000_000; // 1 STSH in base units
/// Must match canisters/token/src/lib.rs:48.
const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

// ── Wire-type mirrors ────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferArgs {
    from_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TransferError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
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

// ── Principals + plumbing ────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}
fn acct(owner: Principal) -> Account {
    Account { owner, subaccount: None }
}

fn create_canister(pic: &PocketIc) -> Principal {
    // create_canister() makes the anonymous principal the sole controller (settings:
    // None → controller defaults to the caller, which PocketIC sends as anonymous).
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    cid
}

/// Fresh-install the production token with the full supply to `owner`.
fn deploy(pic: &PocketIc, owner: Principal) -> Principal {
    let cid = create_canister(pic);
    let init = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: owner,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
        fee_collector: Some(p(0xF1)),
    };
    pic.install_canister(cid, token_wasm(), candid::encode_one(&init).unwrap(), None);
    cid
}

/// Same install, but the `--features testing` Wasm, so the suite can OBSERVE the
/// dedup map state it claims to have created (`dedup_index_stats_for_test`) and
/// drive a prune directly. Without this the no-false-positive cases would assert
/// "the upgrade proceeded" over a map whose emptiness was never checked — a
/// vacuous pass.
fn deploy_test(pic: &PocketIc, owner: Principal) -> Principal {
    let cid = create_canister(pic);
    let init = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: owner,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
        fee_collector: Some(p(0xF1)),
    };
    pic.install_canister(cid, token_test_wasm(), candid::encode_one(&init).unwrap(), None);
    cid
}

/// (primary_len, index_len, bijective, stored_state_version) — existing H-3 hook.
fn dedup_stats(pic: &PocketIc, cid: Principal) -> (u64, u64, bool, u32) {
    let bytes = pic
        .query_call(cid, anon(), "dedup_index_stats_for_test", candid::encode_args(()).unwrap())
        .expect("dedup_index_stats_for_test");
    candid::decode_args(&bytes).unwrap()
}

/// Existing H-3 hook: runs `prune_expired_dedup(time())` with no insert, so the
/// map can be driven to genuinely EMPTY (a dedup-bearing transfer would always
/// leave its own fresh row behind).
fn force_prune(pic: &PocketIc, cid: Principal, caller: Principal) {
    pic.update_call(cid, caller, "measure_prune_instructions_for_test", candid::encode_args(()).unwrap())
        .expect("measure_prune_instructions_for_test");
}

fn balance_of(pic: &PocketIc, cid: Principal, owner: Principal) -> u128 {
    let bytes = pic
        .query_call(cid, anon(), "icrc1_balance_of", candid::encode_one(acct(owner)).unwrap())
        .expect("icrc1_balance_of");
    let n: Nat = candid::decode_one(&bytes).unwrap();
    n.0.to_string().parse().unwrap()
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() as u64
}

/// A transfer carrying `created_at_time` — the ONLY path that records a dedup
/// row (and therefore the only path that leaves a durable block-index witness).
fn transfer_at(
    pic: &PocketIc,
    cid: Principal,
    caller: Principal,
    to: Principal,
    amount: u128,
    created_at_time: Option<u64>,
    nonce: u64,
) -> Result<Nat, TransferError> {
    // `nonce` rides in the memo, which is part of the dedup key. PocketIC advances
    // the clock by a fixed step per round, so deriving distinct created_at_time
    // values from `now_ns()` inside a loop can cancel out and collide; the memo
    // makes each call distinct by construction.
    let args = TransferArgs {
        from_subaccount: None,
        to: acct(to),
        amount: Nat::from(amount),
        fee: None,
        memo: Some(nonce.to_le_bytes().to_vec()),
        created_at_time,
    };
    let bytes = pic
        .update_call(cid, caller, "icrc1_transfer", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc1_transfer rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

/// A plain (non-idempotent, created_at_time = None) transfer; returns the block index.
fn transfer(pic: &PocketIc, cid: Principal, caller: Principal, to: Principal, amount: u128) -> Result<Nat, TransferError> {
    let args = TransferArgs {
        from_subaccount: None,
        to: acct(to),
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let bytes = pic
        .update_call(cid, caller, "icrc1_transfer", candid::encode_one(&args).unwrap())
        .unwrap_or_else(|e| panic!("icrc1_transfer rejected: {:?}", e));
    candid::decode_one(&bytes).unwrap()
}

/// Raw management-canister `install_code` with `skip_pre_upgrade = Some(true)`
/// (PocketIC's `upgrade_canister` can only send `Some(false)`). Sent as the
/// controller (anonymous) with the target canister as the effective principal.
/// Returns Err (stringified reject) when the upgrade traps.
fn skip_pre_upgrade_install(pic: &PocketIc, token: Principal, wasm: Vec<u8>) -> Result<Vec<u8>, String> {
    let args = InstallCodeArgs {
        mode: CanisterInstallMode::Upgrade(Some(UpgradeFlags {
            skip_pre_upgrade: Some(true),
            wasm_memory_persistence: Some(WasmMemoryPersistence::Replace),
        })),
        canister_id: token,
        wasm_module: wasm,
        arg: candid::encode_args(()).unwrap(),
        sender_canister_version: None,
    };
    pic.update_call_with_effective_principal(
        Principal::management_canister(),
        RawEffectivePrincipal::CanisterId(token.as_slice().to_vec()),
        anon(), // controller
        "install_code",
        candid::encode_one(&args).unwrap(),
    )
    .map_err(|e| format!("{:?}", e))
}


// =============================================================================
// 1 — the untested case: stale (not empty) checkpoint MUST be refused
// =============================================================================
#[test]
fn w2_24_stale_checkpoint_after_a_normal_upgrade_is_refused() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let recip = p(0xB2);
    let amt = 1_000 * STSH;

    // 1. Fresh install, one transfer.
    let token = deploy(&pic, owner);
    let _ = transfer(&pic, token, owner, recip, amt).expect("first transfer");

    // 2. NORMAL upgrade — pre_upgrade runs and writes a checkpoint. From here the
    //    empty-checkpoint guard can never fire again; only freshness can catch a
    //    rollback. This step must SUCCEED (the guard must not false-fire on a
    //    checkpoint that is exactly current).
    pic.upgrade_canister(token, token_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("normal upgrade with a current checkpoint must succeed");

    // 3. Advance BLOCK_HEIGHT past that checkpoint with created_at_time transfers,
    //    so the dedup map durably witnesses the newer block indices.
    let mut last = Nat::from(0u32);
    for i in 0..5u64 {
        last = transfer_at(&pic, token, owner, recip, amt, Some(now_ns(&pic) - 1_000), i)
            .expect("post-checkpoint transfer");
    }
    let owner_bal = balance_of(&pic, token, owner);
    let recip_bal = balance_of(&pic, token, recip);

    // 4. skip-pre upgrade → the checkpoint is version-correct but STALE.
    let err = skip_pre_upgrade_install(&pic, token, token_wasm())
        .expect_err("a stale checkpoint MUST be refused, not silently restored");
    assert!(
        err.contains("STALE CHECKPOINT REFUSED"),
        "the trap must be the W2 2-4 freshness guard, not some other failure; got: {}",
        err
    );

    // 5. Fail-closed means the OLD canister is untouched.
    assert_eq!(balance_of(&pic, token, owner), owner_bal, "owner balance unchanged");
    assert_eq!(balance_of(&pic, token, recip), recip_bal, "recipient balance unchanged");

    // 6. BLOCK_HEIGHT was never rewound: the next index is exactly previous + 1.
    let next = transfer(&pic, token, owner, recip, amt).expect("post-refusal transfer");
    assert_eq!(
        next,
        last + Nat::from(1u32),
        "BLOCK_HEIGHT must be preserved, never rewound to the stale checkpoint"
    );
}

// =============================================================================
// 2 — NO FALSE POSITIVES: both blind-spot states must still upgrade
//     (a) dedup map EMPTY — transfers without created_at_time leave no row
//     (b) dedup map FULLY PRUNED — every row aged out past TX_DEDUP_WINDOW_NS
// =============================================================================
#[test]
fn w2_24_guard_never_false_traps_on_an_empty_or_fully_pruned_dedup_map() {
    let pic = PocketIc::new();
    let owner = p(0xC3);
    let recip = p(0xD4);
    let amt = 10 * STSH;

    // ── (a) EMPTY: every transfer omits created_at_time, so record_dedup is never
    //        reached and the map stays empty while BLOCK_HEIGHT advances. This is
    //        the guard's blind spot, and it must not be mistaken for a rollback.
    let empty = deploy_test(&pic, owner);
    for _ in 0..3 {
        transfer(&pic, empty, owner, recip, amt).expect("transfer without created_at_time");
    }
    let (primary, index, bijective, _) = dedup_stats(&pic, empty);
    assert_eq!((primary, index), (0, 0), "case (a) must really have an EMPTY dedup map");
    assert!(bijective);

    pic.upgrade_canister(empty, token_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade with an EMPTY dedup map must proceed — silence is not a rollback");
    let after_empty = transfer(&pic, empty, owner, recip, amt).expect("transfer after upgrade");
    assert!(after_empty > Nat::from(0u32), "the canister is live after the upgrade");

    // ── (b) FULLY PRUNED: dedup-bearing transfers first, then age past the 24h
    //        window and prune directly. A dedup-bearing transfer would always leave
    //        its OWN fresh row, so the existing prune-only hook is what makes a
    //        genuinely witness-free map reachable.
    let pruned = deploy_test(&pic, owner);
    for i in 0..3u64 {
        transfer_at(&pic, pruned, owner, recip, amt, Some(now_ns(&pic) - 1_000), i)
            .expect("dedup-bearing transfer");
    }
    let (primary, _, _, _) = dedup_stats(&pic, pruned);
    assert_eq!(primary, 3, "the dedup rows must exist before they can be pruned");

    pic.advance_time(Duration::from_nanos(TX_DEDUP_WINDOW_NS + 60 * 1_000_000_000));
    pic.tick();
    force_prune(&pic, pruned, owner);

    let (primary, index, bijective, _) = dedup_stats(&pic, pruned);
    assert_eq!((primary, index), (0, 0), "case (b) must really be FULLY PRUNED");
    assert!(bijective);

    // BLOCK_HEIGHT is now strictly above every (now absent) witness — precisely
    // the state a naive "no witness means rollback" guard would false-trap on.
    pic.upgrade_canister(pruned, token_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade with a FULLY PRUNED dedup map must proceed — a pruned witness is not a rollback");
    let after_pruned = transfer(&pic, pruned, owner, recip, amt).expect("transfer after upgrade");
    assert!(after_pruned > Nat::from(0u32), "the canister is live after the upgrade");
}
