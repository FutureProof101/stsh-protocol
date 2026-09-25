// =============================================================================
// STSH — SI-11: treasury's withdrawal reservation is durable BEFORE its first
//               await (PocketIC, cross-Wasm)
// =============================================================================
//
// THE PROPERTY. `execute_withdrawal` writes its durable per-proposal
// reservation into stable memory in the await-free segment that precedes its
// FIRST AWAIT. That ordering is the whole no-double-debit guard: two concurrent
// executions of the same proposal must not both get past the gate.
//
// TWO OBSERVERS, AND WHY (SSA landed-diff R-8 V1, AMBER-1; CTO ruling
// cto-ruling-r8-landed-diff-fix-wave-2026-09-06 item 2). Treasury's first await
// is NOT the pool call: it is `call(token, "icrc1_fee", ())`, which sits
// between `reserve_withdrawal` and the pool call. The POOL-side observer alone
// therefore binds only "before the POOL call" — the SSA proved the gap by
// moving the reservation below the `icrc1_fee` await and watching the
// pool-side arm stay GREEN. The TOKEN-side observer, inside the testing build's
// `icrc1_fee` handler, closes it: it fires at the earlier boundary, so the two
// observers together bind the property as stated. Both must see `Reserved`.
//
// WHY IT NEEDED A NEW SURFACE. Every existing observation of the reservation
// is taken AFTER `execute_withdrawal` has returned, by which time the record
// exists either way — pre-await or post-await writes are indistinguishable
// from outside. The only vantage point that can tell them apart is INSIDE the
// call treasury is parked on. So the REAL pool's testing build asks treasury,
// from inside its own `treasury_disburse` handler, what treasury has durably
// recorded for this proposal id, and parks the answer in a cell this test
// reads back afterwards.
//
// A replicated inter-canister call to a `#[query]` executes against the
// callee's COMMITTED state, so treasury cannot answer out of the suspended
// continuation — `Some(Reserved)` here means the reservation was written and
// committed before treasury awaited.
//
// NO STUB CANISTER. The observer is an inline `#[cfg(feature = "testing")]`
// block in the real pool, so it exists only in `shielded_pool_test.wasm` and
// is compiled out of the production binary —
// `eager_cell_feature_isolation_tests` proves the absence against the shipped
// Wasm, not by assertion.
//
// HARNESS. `deploy`/`propose`/`execute`/`Stack` are the
// `w2_2_6_treasury_debit_exactness_tests.rs` surface, replicated here verbatim
// (integration test files are separate crates and cannot import one another).
// `propose` advances past the timelock internally.
//
// PREREQUISITES: ./run_gate.sh builds the testing-feature Wasms and copies them
// to the _test names before running the suites.
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first with ./run_gate.sh (it builds the testing-feature Wasms \
             and copies them to the _test names before running the suites).",
            pkg, path, e
        )
    })
}

fn token_test_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_TEST_WASM"), "stsh_token_test") }
fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
fn treasury_test_wasm() -> Vec<u8> { load_wasm(env!("TREASURY_TEST_WASM"), "treasury_test") }

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }

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
}

fn all_to(recipient: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
    }
}

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum FeeSource { ShieldFee, PrivateTransferFee, UnshieldFee, DexRevenue }

/// Mirror of the pool's testing-only `ReservationStatusForTest`, which is
/// itself a decode-shape mirror of treasury's real `ReservationStatus`. Same
/// variants, SAME ORDER — Candid decodes variants by name hash, and this is
/// the type the pool's read-back query returns.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
enum ReservationStatusForTest {
    Reserved,
    Executed,
    Failed,
    OutcomeUnknown,
    RetryingUnknown,
    RetiredNotExecuted,
}

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 20_000_000_000_000u128);
    cid
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

struct Stack {
    token: Principal,
    pool: Principal,
    treasury: Principal,
    controller: Principal,
}

/// Token + pool(test) + treasury(test), wired together, with the treasury's
/// `operations` bucket and the pool's OPERATIONS_RESERVE both funded and the
/// pool holding real ledger balance so a transfer can genuinely be attempted.
fn deploy(pic: &PocketIc, controller: Principal, funded: u128) -> Stack {
    let token = create_canister(pic);
    let pool = create_canister(pic);
    let treasury = create_canister(pic);

    // The TESTING token, for the SECOND observer (R-8 V1a): treasury's FIRST
    // await is its `icrc1_fee` call, not the pool call, so the token's own
    // handler is the only vantage point on the earlier boundary. UNARMED the
    // handler is identical to production's.
    pic.install_canister(token, token_test_wasm(), candid::encode_one(all_to(pool)).unwrap(), None);
    pic.install_canister(
        pool,
        pool_test_wasm(),
        candid::encode_one(PoolInitArgs {
            token_canister: token,
            nullifier_canister: p(0x07),
            merkle_canister: p(0x08),
            treasury_canister: treasury,
            staking_canister: p(0x09),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .unwrap(),
        None,
    );
    pic.install_canister(
        treasury,
        treasury_test_wasm(),
        candid::encode_args((token, pool, controller)).unwrap(),
        None,
    );

    let s = Stack { token, pool, treasury, controller };
    seed_ops_reserve(pic, &s, funded);
    credit_bucket(pic, &s, funded);
    s
}

fn seed_ops_reserve(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: () = decode(
        "inject_operations_reserve_for_test",
        pic.update_call(
            s.pool, s.controller, "inject_operations_reserve_for_test",
            candid::encode_one(amount).unwrap(),
        ),
    );
}

fn credit_bucket(pic: &PocketIc, s: &Stack, amount: u128) {
    let r: Result<(), String> = decode(
        "receive_fee_split",
        pic.update_call(
            s.treasury, s.pool, "receive_fee_split",
            candid::encode_args((FeeSource::ShieldFee, amount, 0u128, 0u128, 0u64)).unwrap(),
        ),
    );
    assert!(r.is_ok(), "receive_fee_split setup must succeed; got {:?}", r);
}

fn propose(pic: &PocketIc, s: &Stack, recipient: Principal, amount: u128, desc: &str) -> u64 {
    let pid: u64 = decode(
        "propose_withdrawal",
        pic.update_call(
            s.treasury, s.controller, "propose_withdrawal",
            candid::encode_args((
                "operations".to_string(), recipient, amount, desc.to_string(),
            )).unwrap(),
        ),
    );
    pic.advance_time(Duration::from_secs(TIMELOCK_SECS + 1));
    pid
}

fn execute(pic: &PocketIc, s: &Stack, pid: u64) -> Result<(), String> {
    decode(
        "execute_withdrawal",
        pic.update_call(
            s.treasury, s.controller, "execute_withdrawal",
            candid::encode_one(pid).unwrap(),
        ),
    )
}

/// Arm the token-side observer for one proposal id, and clear any previous
/// observation. The token's `icrc1_fee` is inert until this is called.
fn arm_token_observer(pic: &PocketIc, s: &Stack, pid: u64) {
    let _: () = decode(
        "set_si11_observer_for_test",
        pic.update_call(
            s.token, s.controller, "set_si11_observer_for_test",
            candid::encode_args((s.treasury, pid)).unwrap(),
        ),
    );
}

/// Read back what the TOKEN-side observer recorded — the observation taken at
/// treasury's FIRST await.
fn query_token_observed_status(pic: &PocketIc, token: Principal) -> Option<ReservationStatusForTest> {
    decode(
        "si11_observed_reservation_status_for_test",
        pic.query_call(
            token,
            Principal::anonymous(),
            "si11_observed_reservation_status_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// The one genuinely new helper this suite needs: read back what the pool's
/// own mid-flight observer recorded. It is NOT a `w2_2_6` borrowing — that
/// file never had reason to read the pool's testing-only observation query.
fn query_observed_status(pic: &PocketIc, pool: Principal) -> Option<ReservationStatusForTest> {
    decode(
        "observed_reservation_status_for_test",
        pic.query_call(
            pool,
            Principal::anonymous(),
            "observed_reservation_status_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// The binding
// ─────────────────────────────────────────────────────────────────────────────

// BINDING: SI-11 — treasury's reservation-before-first-await guarantee,
// exercised through the REAL `execute_withdrawal` entrypoint against the REAL
// pool's testing build, which observes treasury's own durable reservation
// state mid-flight (inline in its own `treasury_disburse` handler) and records
// it for a separate follow-up read. No stub-pool crate.
#[test]
fn si11_reservation_exists_before_pool_call_resolves() {
    let pic = PocketIc::new();
    let stack: Stack = deploy(&pic, p(0xC0), 10_000_000_000_000);
    let proposal_id = propose(&pic, &stack, p(0xB1), 1_000, "SI-11 durability");
    arm_token_observer(&pic, &stack, proposal_id);

    execute(&pic, &stack, proposal_id)
        .expect("execute_withdrawal completes against the real pool");

    // ── OBSERVER 1 — the TOKEN, at treasury's FIRST await ───────────────────
    //
    // This is the strict one. `icrc1_fee` is the first thing `execute_withdrawal`
    // awaits, so a reservation written anywhere below it is invisible here.
    let at_first_await = query_token_observed_status(&pic, stack.token);
    assert_eq!(
        at_first_await,
        Some(ReservationStatusForTest::Reserved),
        "the reservation must already be durable (status == Reserved) at treasury's FIRST \
         await — the token's own `icrc1_fee` handler, which is the earliest point any \
         other canister can observe treasury's committed state — observed: {at_first_await:?}"
    );

    // ── OBSERVER 2 — the POOL, at the pool call ────────────────────────────
    //
    // Kept, and still load-bearing: it is the only observer that sees the state
    // treasury is in when the disbursement itself is claimed, which is the
    // boundary the no-double-debit guard is written against.
    let at_pool_call = query_observed_status(&pic, stack.pool);
    assert_eq!(
        at_pool_call,
        Some(ReservationStatusForTest::Reserved),
        "the reservation must still be durable (status == Reserved) at the moment the \
         pool's own inline observer queried treasury, mid-flight, before treasury's own \
         pool-call await had resolved — observed: {at_pool_call:?}"
    );
}
