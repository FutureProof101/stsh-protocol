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
use serde::{Deserialize, Serialize};

// ── Wasm loader (PRODUCTION only — no test-feature build needed) ─────────────

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

fn balance_of(pic: &PocketIc, cid: Principal, owner: Principal) -> u128 {
    let bytes = pic
        .query_call(cid, anon(), "icrc1_balance_of", candid::encode_one(acct(owner)).unwrap())
        .expect("icrc1_balance_of");
    let n: Nat = candid::decode_one(&bytes).unwrap();
    n.0.to_string().parse().unwrap()
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
// R2 — skip_pre_upgrade traps (empty checkpoint) + BLOCK_HEIGHT preserved
// =============================================================================
#[test]
fn test_h3_followup_skip_pre_upgrade_traps_and_preserves_block_height() {
    let pic = PocketIc::new();
    let owner = p(0xA1);
    let recip = p(0xB2);
    let amt = 1_000 * STSH;

    // 1. Fresh-install production v2; first transfer → record block index + balances.
    let token = deploy(&pic, owner);
    let b0 = transfer(&pic, token, owner, recip, amt).expect("first transfer");
    let owner_bal = balance_of(&pic, token, owner);
    let recip_bal = balance_of(&pic, token, recip);

    // 2. Attempt a skip-pre upgrade to production v2 → MUST trap. pre_upgrade is
    //    skipped, so STABLE_STATE_CELL stays empty and post_upgrade's empty-checkpoint
    //    guard aborts the upgrade.
    let err = skip_pre_upgrade_install(&pic, token, token_wasm())
        .expect_err("skip_pre_upgrade upgrade MUST trap on the empty checkpoint, not succeed");
    assert!(
        err.contains("checkpoint") || err.contains("BLOCK_HEIGHT"),
        "the trap must be the empty-checkpoint guard (silent state loss prevention); got: {}",
        err
    );

    // 3. The old canister survived unchanged — balances identical to pre-attempt.
    assert_eq!(balance_of(&pic, token, owner), owner_bal, "owner balance unchanged after the aborted skip-pre");
    assert_eq!(balance_of(&pic, token, recip), recip_bal, "recipient balance unchanged after the aborted skip-pre");

    // 4. A distinct transfer's block index is exactly previous + 1 → BLOCK_HEIGHT was
    //    preserved, not reset (a reset would restart the counter, not yield b0 + 1).
    let b1 = transfer(&pic, token, owner, recip, amt).expect("post-attempt transfer");
    assert_eq!(
        b1,
        b0 + Nat::from(1u32),
        "BLOCK_HEIGHT preserved: the next block index must be previous + 1, never a reset"
    );
}
