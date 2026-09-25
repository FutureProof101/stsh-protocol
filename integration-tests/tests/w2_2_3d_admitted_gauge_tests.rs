// =============================================================================
// STSH — W2 2-3-D: admitted-operations gauge (MW-006) — PocketIC
// =============================================================================
//
// SPEC: CTO_RESCOPE_W2_2-3D_ADMITTED_OPS_GAUGE_V1_2026-08-17 (4f6796e3…),
// A1 lane doc V6 (5ed571e0…), SSA countersign V6 (ace5f2d2…), as amended by
// CTO_AMENDMENT_W2_2-3D_SECOND_SHAPE_A3_V1_2026-08-17 (1f1ebfcd…) and its SSA
// countersign (9d394eb2…).
//
// THE GAP. An operation admitted before a maintenance pause and suspended at an
// await BEFORE its first durable write has no state anywhere: it is invisible to
// `in_flight` and to every query. `shield_deposit` awaits `icrc1_fee` long
// before the `PENDING_DEPOSITS` insert; `private_spend` awaits inside its
// read-only precheck long before the `PENDING_SPENDS` insert. The gauge makes
// that window observable, and `post_upgrade` converts a lost one into a
// permanent receipt.
//
// WHY POCKETIC AND NOT NATIVE. Native tests keep the pool's thread-locals alive
// in-process, so a native "upgrade" never re-runs `post_upgrade` across a Wasm
// boundary — a heap gauge with a broken fold passes natively and fails on-chain.
// That is a KNOWN blind spot in this codebase, not a hypothetical. Only a real
// cross-Wasm upgrade proves the gauge rides the existing `PoolStableState`
// serialization and that the fold + unconditional reset actually run.
//
// HOW A SUSPENDED OPERATION IS STAGED, AND WHY NO HOOK WAS ADDED. The thing
// under test is a REAL in-flight update call, not a spawned future — so unlike
// W2 2-3-C it needs no injection hook and none was added. `submit_call`
// enqueues the ingress message without awaiting it; ONE `tick()` executes the
// entry segment up to the first inter-canister await and sends that call. The
// response cannot arrive in the same round, so the operation is deterministically
// parked at its first await, with no durable record — which each fold test
// asserts directly via `get_deposit_status` / `get_spend_status` rather than
// inferring it.
//
// SECOND LIVE SHAPE = A3 `private_spend`, PER THE CTO AMENDMENT. V6 originally
// named a withdrawal-side member (A4 `withdraw` / A6
// `reconcile_withdrawal_registry_insert`). The whole withdrawal family fails
// closed at entry — `reject_unbound_withdrawal_proof` (committed base
// `canisters/shielded-pool/src/lib.rs:6407-6409`) returns `InvalidProof`
// unconditionally — so no withdrawal-side operation can reach an await at all.
// The withdrawal-side live fold is DEFERRED DEBT owed by the lane that removes
// that guard. Its fail-closed return is still used here, as one distinct
// active-guard `Drop` error shape (SSA amendment countersign §4, item 4).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing
//   cp .../shielded_pool.wasm .../shielded_pool_test.wasm
//   cargo build --target wasm32-unknown-unknown --release \
//       -p stsh_token -p shielded_pool -p nullifier_registry -p merkle_tree -p stsh-verifier
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test -p integration-tests --test w2_2_3d_admitted_gauge_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::common::rest::SubnetId;
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
fn token_wasm() -> Vec<u8> {
    load_wasm(env!("TOKEN_WASM"), "stsh_token")
}
/// The PRODUCTION pool Wasm — the upgrade TARGET of the old-shape checkpoint
/// test, so that decode is proved on the binary that actually ships.
fn pool_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_WASM"), "shielded_pool")
}
fn pool_test_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test")
}
fn nullifier_wasm() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry")
}
fn merkle_wasm() -> Vec<u8> {
    load_wasm(env!("MERKLE_WASM"), "merkle_tree")
}
fn treasury_wasm() -> Vec<u8> {
    load_wasm(env!("TREASURY_WASM"), "treasury")
}
fn verifier_wasm() -> Vec<u8> {
    load_wasm(env!("VERIFIER_WASM"), "stsh_verifier")
}

// ── Constants (same fixture as accounting_invariant_tests) ──────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DEFAULT_FEE: u128 = 0; // F-000: token transfers free at launch
const DEPOSIT_AMOUNT: u128 = 1_000 * 100_000_000; // 1,000 STSH — a valid denomination
const CONTROLLER: u8 = 0x06;
const USER: u8 = 0xB0;

/// in_commitment for the spend circuit test vectors, MAINNET domain_sep.
/// A-3 FINALIZE regen (2026-09-12): the DOMAIN_POOL_CANISTER_ID re-encode to
/// cxrfg-qaaaa-aaaar-qchfa-cai moved domain_sep and therefore this commitment.
/// Regenerate via `node circuits/tests/gen_test_input.js`.
const IN_COMMITMENT: [u8; 32] = [
    0xd2, 0x6f, 0x9b, 0xb7, 0x36, 0x0a, 0xed, 0x7f, 0x09, 0x18, 0xe7, 0x27, 0x12, 0x3c, 0x86, 0x90,
    0xe2, 0x71, 0xb0, 0x5b, 0x6c, 0xb4, 0x52, 0xfc, 0x6f, 0x05, 0x3a, 0xd4, 0xa1, 0x18, 0xdc, 0x0b,
];

// ── Token mirrors ───────────────────────────────────────────────────────────

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveError {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

// ── Pool mirrors ────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment: [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version: u32,
    proof_system_id: String,
    verifying_key_hash: [u8; 32],
    root_reference: [u8; 32],
    pool_version: u32,
    proof_bytes: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct WithdrawArgs {
    withdrawal_id: u64,
    envelope: ProofEnvelope,
    nullifier: [u8; 32],
    gross_withdraw_amount: u128,
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
}

/// Wire mirror of the pool's `AdmittedOperationStats` — THE new query.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct AdmittedOperationStats {
    admitted: u64,
    upgrade_dropped: u64,
}

/// Wire mirror of the W2 2-3-C `TreasuryNotificationStats`, read here only to
/// prove the two gauges move independently and are never summed.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TreasuryNotificationStats {
    in_flight: u64,
    returned_failures: u64,
    upgrade_dropped: u64,
}

/// Only the variants these tests actually decode.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination,
    InvalidProof,
    AnchorNotFound,
    Paused,
    TransferFailed(String),
    NotInitialised,
    VerifierUnavailable(String),
    VerifierKeyHashMismatch,
    InvalidVerifierKeyHashLength { len: u64 },
    ProofRejected(String),
    AnonymousCaller,
    WithdrawalNotFound,
    DuplicateSpendId,
    MalformedSpendArgs,
    InvalidCommitment,
    DepositNotFound,
}

// ── Harness ─────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

struct Stack {
    pool: Principal,
    token: Principal,
    verifier: Principal,
}

/// A full 5-canister instance on the TEST pool Wasm (the corruption hooks are
/// build-gated off in production and one test needs to plant a checkpoint).
///
/// TOPOLOGY MATTERS, AND IT IS NOT A TRICK. The pool sits on one application
/// subnet and every canister it calls on another. On a single subnet PocketIC
/// can execute a canister's outbound call, the callee, the reply and the
/// caller's continuation inside ONE round, which makes some await windows
/// unobservable from outside — not absent, merely too short to sample. Across
/// subnets a call costs a round, which is what the real IC does for every
/// inter-canister call in any case. Nothing about the pool changes; only the
/// observability of a window that exists either way.
fn new_instance() -> (PocketIc, Stack) {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let subnets = pic.topology().get_app_subnets();
    assert_eq!(subnets.len(), 2, "this suite requires two application subnets");
    let stack = setup_instance_on(&pic, subnets[0], subnets[1]);
    (pic, stack)
}

fn setup_instance_on(pic: &PocketIc, pool_subnet: SubnetId, peer_subnet: SubnetId) -> Stack {
    let user = p(USER);
    let create_on = |subnet| {
        let cid = pic.create_canister_on_subnet(None, None, subnet);
        pic.add_cycles(cid, 2_000_000_000_000u128);
        cid
    };

    let pool = create_on(pool_subnet);
    let token = create_on(peer_subnet);
    let null = create_on(peer_subnet);
    let merkle = create_on(peer_subnet);
    let verifier = create_on(peer_subnet);
    // R-2 (C-30): a REAL treasury, not the dummy principal p(0x04) this suite
    // used to pass. The pool now flushes one PrivateTransferFee notification at
    // every wall-clock window boundary, UNCONDITIONALLY — including empty
    // windows. Against an uninstallable principal each of those flushes returns
    // Err and climbs `returned_failures`, which this suite asserts is zero to
    // prove a dropped ADMITTED operation is not a dropped treasury
    // notification. That claim is unchanged; a treasury that ACCEPTS is what
    // keeps the counter measuring only what the claim is about — and removes a
    // real source of flakiness, since whether a boundary fell inside a given
    // test run was previously a matter of timing.
    let treasury = create_on(peer_subnet);

    pic.install_canister(null, nullifier_wasm(), candid::encode_one(pool).unwrap(), None);
    pic.install_canister(
        treasury,
        treasury_wasm(),
        candid::encode_args((token, pool, p(CONTROLLER))).unwrap(),
        None,
    );
    pic.install_canister(merkle, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    // DEF-083: the verifier is pool-caller-gated — bind it to this pool.
    pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool).unwrap(), None);

    install(
        pic,
        token,
        token_wasm(),
        &TokenInitArgs {
            allocations: vec![AllocationCategory {
                category_id: "all".to_string(),
                category_name: "All tokens".to_string(),
                amount: TOTAL_SUPPLY,
                recipient: user,
                subaccount: None,
                lock_policy: LockPolicy::ImmediatelyLiquid,
                vesting_policy: None,
                created_at_genesis: false,
                genesis_timestamp_ns: 0,
            }],
            treasury: p(0x01),
            staking_canister: p(0x02),
        },
    );

    install(
        pic,
        pool,
        pool_test_wasm(),
        &PoolInitArgs {
            token_canister: token,
            nullifier_canister: null,
            merkle_canister: merkle,
            treasury_canister: treasury,
            staking_canister: p(0x02),
            controller: p(CONTROLLER),
            initial_vk_hash: stsh_verifier::compiled_vk_sha256(),
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );

    pic.update_call(
        pool,
        p(CONTROLLER),
        "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    )
    .expect("set_verifier_canister must succeed in setup");

    Stack { pool, token, verifier }
}

// ── Queries ─────────────────────────────────────────────────────────────────

fn admitted_stats(pic: &PocketIc, pool: Principal) -> AdmittedOperationStats {
    decode(
        "get_admitted_operation_stats",
        pic.query_call(
            pool,
            anon(),
            "get_admitted_operation_stats",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn notification_stats(pic: &PocketIc, pool: Principal) -> TreasuryNotificationStats {
    decode(
        "get_treasury_notification_stats",
        pic.query_call(
            pool,
            anon(),
            "get_treasury_notification_stats",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// THE MAINTENANCE-WINDOW GATE, as ruled: `admitted == 0 AND in_flight == 0`.
/// Two DISTINCT readings — never a sum.
fn gate_is_clear(pic: &PocketIc, pool: Principal) -> bool {
    admitted_stats(pic, pool).admitted == 0 && notification_stats(pic, pool).in_flight == 0
}

/// Does a durable deposit record exist? `reserved` is Candid's top type, so
/// this decodes any `PendingDeposit` without mirroring its shape.
fn deposit_exists(pic: &PocketIc, pool: Principal, commitment: [u8; 32]) -> bool {
    let r: Option<candid::Reserved> = decode(
        "get_deposit_status",
        pic.query_call(
            pool,
            p(USER),
            "get_deposit_status",
            candid::encode_one(commitment).unwrap(),
        ),
    );
    r.is_some()
}

fn spend_exists(pic: &PocketIc, pool: Principal, spend_id: u64) -> bool {
    let r: Option<candid::Reserved> = decode(
        "get_spend_status",
        pic.query_call(
            pool,
            p(USER),
            "get_spend_status",
            candid::encode_one(spend_id).unwrap(),
        ),
    );
    r.is_some()
}

// ── Staging helpers ─────────────────────────────────────────────────────────

fn do_approve(pic: &PocketIc, s: &Stack, amount: u128) {
    let result: Result<Nat, ApproveError> = decode(
        "icrc2_approve",
        pic.update_call(
            s.token,
            p(USER),
            "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount: None,
                spender: Account { owner: s.pool, subaccount: None },
                amount: Nat::from(amount),
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at: Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee: None,
                memo: None,
                created_at_time: None,
            })
            .unwrap(),
        ),
    );
    result.expect("icrc2_approve must succeed in setup");
}

fn deposit_args(commitment: [u8; 32]) -> ShieldDepositArgs {
    ShieldDepositArgs {
        note_commitment: commitment,
        encrypted_payload: vec![],
        public_amount: DEPOSIT_AMOUNT,
    }
}

/// Seed IN_COMMITMENT into the Merkle tree via a COMPLETED shield_deposit, so a
/// later `private_spend` has a real anchor to prove against.
fn seed_deposit(pic: &PocketIc, s: &Stack) {
    do_approve(pic, s, DEPOSIT_AMOUNT + DEFAULT_FEE);
    let result: Result<Nat, PoolError> = decode(
        "seed shield_deposit",
        pic.update_call(
            s.pool,
            p(USER),
            "shield_deposit",
            candid::encode_one(deposit_args(IN_COMMITMENT)).unwrap(),
        ),
    );
    result.expect("seed shield_deposit must succeed");
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .join("circuits")
}

/// The REAL Groth16 artifacts. These are TRACKED in the repo, so a missing file
/// is a provisioning failure, not a reason to skip: a silently skipped fold
/// test is exactly the false green this lane exists to prevent.
fn spend_fixture() -> PrivateSpendArgs {
    let public_json = std::fs::read_to_string(circuits_dir().join("public.json"))
        .expect("circuits/public.json is tracked and required by this suite");
    let proof_json = std::fs::read_to_string(circuits_dir().join("proof.json"))
        .expect("circuits/proof.json is tracked and required by this suite");
    let signals = stsh_verifier::public_json_to_signals(&public_json).expect("public.json signals");
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json).expect("proof.json bytes");
    PrivateSpendArgs {
        spend_id: 0,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference: signals[0],
            pool_version: 1,
            proof_bytes,
        },
                nullifiers: vec![signals[1]],
        output_commitments: vec![signals[2], signals[3]],
        encrypted_outputs: vec![vec![0xAA], vec![0xBB]],
        fee: 0,
    }
}

/// Submit an update call WITHOUT awaiting it, then execute exactly ONE round.
///
/// After that round the method has run its entry segment and issued its first
/// inter-canister call; the reply cannot arrive in the same round, so the
/// operation is parked at its first await with no durable record. This is the
/// whole staging mechanism — no injection hook, no counter forgery.
fn submit_and_suspend(
    pic: &PocketIc,
    canister: Principal,
    sender: Principal,
    method: &str,
    payload: Vec<u8>,
) -> pocket_ic::common::rest::RawMessageId {
    let msg = pic
        .submit_call(canister, sender, method, payload)
        .expect("submit_call must be accepted");
    pic.tick();
    msg
}

/// Pay PocketIC's `install_code` rate limit UP FRONT.
///
/// This MUST be called before an operation is parked, not after: the throttle
/// is settled by executing rounds, and a round executed while an operation is
/// suspended would let it finish — silently converting a fold test into a
/// no-op that passes. The throttle is a replica-side quota, not a canister
/// property, and nothing on the path under test has time-window semantics.
fn settle_install_budget(pic: &PocketIc) {
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
}

/// A REAL cross-Wasm upgrade, with NO preparatory rounds — see above.
fn upgrade_pool_to(pic: &PocketIc, pool: Principal, wasm: Vec<u8>) -> Result<(), String> {
    pic.upgrade_canister(pool, wasm, candid::encode_args(()).unwrap(), None)
        .map_err(|e| format!("{:?}", e))
}

fn upgrade_pool(pic: &PocketIc, pool: Principal) {
    upgrade_pool_to(pic, pool, pool_test_wasm()).expect("pool upgrade must succeed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — §6 item 1, shape A1: a live suspended `shield_deposit` folds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_w2_23d_a1_shield_deposit_suspended_before_first_write_folds_into_dropped() {
    let (pic, s) = new_instance();
    do_approve(&pic, &s, DEPOSIT_AMOUNT + DEFAULT_FEE);

    assert_eq!(
        admitted_stats(&pic, s.pool),
        AdmittedOperationStats { admitted: 0, upgrade_dropped: 0 },
        "a freshly installed pool must report both admitted quantities zero"
    );

    // Pay the install-code throttle BEFORE anything is parked.
    settle_install_budget(&pic);

    let commitment = IN_COMMITMENT;
    let _msg = submit_and_suspend(
        &pic,
        s.pool,
        p(USER),
        "shield_deposit",
        candid::encode_one(deposit_args(commitment)).unwrap(),
    );

    // THE WINDOW, observed: admitted, past an await, and durably invisible.
    let before = admitted_stats(&pic, s.pool);
    assert_eq!(
        before.admitted, 1,
        "a shield_deposit parked at its icrc1_fee await must be counted as admitted; got {:?}",
        before
    );
    assert_eq!(before.upgrade_dropped, 0, "nothing dropped before any upgrade");
    assert!(
        !deposit_exists(&pic, s.pool, commitment),
        "the operation must have NO durable record yet — that invisibility is the gap \
         the gauge exists to close, and this assertion is what makes the fold meaningful"
    );

    // The upgrade discards the continuation. Cross-Wasm, not in-process.
    upgrade_pool(&pic, s.pool);

    let after = admitted_stats(&pic, s.pool);
    assert_eq!(
        after.upgrade_dropped, 1,
        "the suspended admitted operation must fold into upgrade_dropped; got {:?}",
        after
    );
    assert_eq!(
        after.admitted, 0,
        "the gauge must reset to zero after the fold — carrying it forward would wedge \
         the maintenance gate permanently; got {:?}",
        after
    );
    assert!(
        !deposit_exists(&pic, s.pool, commitment),
        "the dropped operation left no record — the counter is its ONLY receipt"
    );
    // The 2-3-C counters are a DISTINCT quantity and must not have moved.
    assert_eq!(
        notification_stats(&pic, s.pool),
        TreasuryNotificationStats { in_flight: 0, returned_failures: 0, upgrade_dropped: 0 },
        "a dropped ADMITTED operation is not a dropped treasury notification — the two \
         must never be conflated or summed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — §6 item 1, shape A3: a live suspended `private_spend` folds
// ─────────────────────────────────────────────────────────────────────────────
//
// The ruled second shape (CTO amendment 1f1ebfcd…). Its first durable write is
// the `PENDING_SPENDS` insert — an independently shaped path from A1's
// `PENDING_DEPOSITS`, reached through a read-only precheck that awaits first.

#[test]
fn test_w2_23d_a3_private_spend_suspended_before_first_write_folds_into_dropped() {
    let (pic, s) = new_instance();
    seed_deposit(&pic, &s);

    // The seeding deposit completed, so the gauge is back to zero: a completed
    // operation leaves nothing behind in it.
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "a COMPLETED shield_deposit must leave the admitted gauge at zero"
    );

    settle_install_budget(&pic);

    let spend_id = 23_400_1;
    let args = PrivateSpendArgs { spend_id, ..spend_fixture() };
    let _msg = submit_and_suspend(
        &pic,
        s.pool,
        p(USER),
        "private_spend",
        candid::encode_one(args).unwrap(),
    );

    let before = admitted_stats(&pic, s.pool);
    assert_eq!(
        before.admitted, 1,
        "a private_spend parked at its precheck await must be counted as admitted; got {:?}",
        before
    );
    assert!(
        !spend_exists(&pic, s.pool, spend_id),
        "the spend must have NO durable record yet — the precheck is read-only, which is \
         precisely why this window is invisible"
    );

    upgrade_pool(&pic, s.pool);

    let after = admitted_stats(&pic, s.pool);
    assert_eq!(
        after.upgrade_dropped, 1,
        "the suspended private_spend must fold into upgrade_dropped; got {:?}",
        after
    );
    assert_eq!(after.admitted, 0, "the gauge must reset to zero; got {:?}", after);
    assert!(
        !spend_exists(&pic, s.pool, spend_id),
        "the dropped spend left no record — the counter is its ONLY receipt"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — `upgrade_dropped` is a cumulative receipt, not a gauge
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_w2_23d_dropped_is_cumulative_across_upgrades() {
    let (pic, s) = new_instance();
    do_approve(&pic, &s, (DEPOSIT_AMOUNT + DEFAULT_FEE) * 4);
    settle_install_budget(&pic);

    let _ = submit_and_suspend(
        &pic,
        s.pool,
        p(USER),
        "shield_deposit",
        candid::encode_one(deposit_args([0x11; 32])).unwrap(),
    );
    upgrade_pool(&pic, s.pool);
    assert_eq!(admitted_stats(&pic, s.pool).upgrade_dropped, 1);

    // An upgrade that drops nothing must neither reset nor inflate the receipt.
    settle_install_budget(&pic);
    upgrade_pool(&pic, s.pool);
    let quiet = admitted_stats(&pic, s.pool);
    assert_eq!(
        quiet.upgrade_dropped, 1,
        "the receipt must persist across an upgrade that dropped nothing; got {:?}",
        quiet
    );
    assert_eq!(quiet.admitted, 0);

    // A later drop ADDS to the running total.
    settle_install_budget(&pic);
    let _ = submit_and_suspend(
        &pic,
        s.pool,
        p(USER),
        "shield_deposit",
        candid::encode_one(deposit_args([0x22; 32])).unwrap(),
    );
    upgrade_pool(&pic, s.pool);
    let total = admitted_stats(&pic, s.pool);
    assert_eq!(
        total.upgrade_dropped, 2,
        "drops must accumulate across upgrades; got {:?}",
        total
    );
    assert_eq!(total.admitted, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — §6 item 3: the gate reads BUSY while suspended, CLEAR once durable
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_w2_23d_gate_reads_busy_while_suspended_and_clear_after_commit() {
    let (pic, s) = new_instance();
    seed_deposit(&pic, &s);

    assert!(
        gate_is_clear(&pic, s.pool),
        "an idle pool must read clear on BOTH quantities"
    );

    let spend_id = 23_400_2;
    let msg = submit_and_suspend(
        &pic,
        s.pool,
        p(USER),
        "private_spend",
        candid::encode_one(PrivateSpendArgs { spend_id, ..spend_fixture() }).unwrap(),
    );

    // THE POINT OF THE LANE: at the read baseline this pool looked quiescent
    // here — no record, no in_flight, nothing to see. It now reads BUSY.
    assert!(
        !gate_is_clear(&pic, s.pool),
        "the gate must read BUSY while an admitted operation is suspended before its \
         first durable write — this is the MW-006 gap, closed"
    );
    assert_eq!(admitted_stats(&pic, s.pool).admitted, 1);
    assert_eq!(
        notification_stats(&pic, s.pool).in_flight,
        0,
        "busy for the ADMITTED reason, not the notification one — the operator must be \
         able to tell which"
    );

    // Let it run to completion.
    let bytes = pic.await_call(msg).expect("the suspended private_spend must complete");
    let result: Result<(), PoolError> = candid::decode_one(&bytes).expect("decode private_spend");
    assert!(result.is_ok(), "private_spend must succeed: {:?}", result);

    assert!(
        spend_exists(&pic, s.pool, spend_id),
        "a completed spend must have a durable record"
    );
    assert!(
        gate_is_clear(&pic, s.pool),
        "once the operation is durable and finished, the gate must read CLEAR again — a \
         gauge that never clears is a gauge no operator can act on"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — §6 item 6: `admitted` and `in_flight` are independent, never summed
// ─────────────────────────────────────────────────────────────────────────────
//
// The narrow-gauge property. `admitted` covers admission → first durable write;
// `in_flight` covers a spawned treasury notification, which can only exist long
// AFTER that write. The windows are disjoint, the readings independent, and the
// two folds must not touch each other.

#[test]
fn test_w2_23d_admitted_and_inflight_are_disjoint_and_fold_independently() {
    let (pic, s) = new_instance();
    seed_deposit(&pic, &s);

    // Stage notifications FIRST, then park the spend. Order matters: any update
    // call executes rounds, and a round executed while an operation is parked
    // would let it finish. This lane adds no hook of its own — the injector is
    // W2 2-3-C's, used here only to move the OTHER gauge.
    let _: () = decode(
        "inject_inflight_notifications_for_test",
        pic.update_call(
            s.pool,
            p(CONTROLLER),
            "inject_inflight_notifications_for_test",
            candid::encode_one(2u64).unwrap(),
        ),
    );
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "spawning notifications must not move the admitted gauge"
    );
    assert_eq!(notification_stats(&pic, s.pool).in_flight, 2);

    settle_install_budget(&pic);
    let _msg = submit_and_suspend(
        &pic,
        s.pool,
        p(USER),
        "private_spend",
        candid::encode_one(PrivateSpendArgs { spend_id: 23_400_3, ..spend_fixture() }).unwrap(),
    );
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        1,
        "an admitted-but-not-durable operation must be counted by its OWN gauge"
    );
    assert_eq!(
        notification_stats(&pic, s.pool).in_flight,
        2,
        "and it must not be counted as a treasury notification — the windows are \
         disjoint and the two readings independent"
    );

    // One upgrade, two INDEPENDENT folds into two DISTINCT receipts.
    upgrade_pool(&pic, s.pool);

    assert_eq!(
        admitted_stats(&pic, s.pool),
        AdmittedOperationStats { admitted: 0, upgrade_dropped: 1 },
        "exactly the ONE dropped admitted operation — not three, and not the sum"
    );
    let n = notification_stats(&pic, s.pool);
    assert_eq!(
        (n.in_flight, n.upgrade_dropped),
        (0, 2),
        "exactly the TWO dropped notifications — the folds must not borrow from each \
         other; got {:?}",
        n
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 — §6 item 4: every pre-write return leaves the gauge at zero
// ─────────────────────────────────────────────────────────────────────────────
//
// Under the mandated RAII the `Drop` path is what resolves these, so one
// representative test per distinct return SHAPE is what has evidentiary value:
//
//   - a pre-await synchronous rejection (A1, invalid denomination);
//   - a pre-await pause rejection (A1);
//   - a POST-await rejection, where the guard has already survived an await
//     and a suspension window (A3, unknown anchor);
//   - the fail-closed withdrawal family (A4), which returns before ANY await —
//     the CTO amendment keeps this as one distinct error shape; and
//   - A7's two shapes, in test 7.

#[test]
fn test_w2_23d_error_paths_leave_admitted_at_zero() {
    let (pic, s) = new_instance();
    seed_deposit(&pic, &s);
    assert_eq!(admitted_stats(&pic, s.pool).admitted, 0);

    // (a) A1, pre-await synchronous rejection.
    let r: Result<Nat, PoolError> = decode(
        "shield_deposit(bad denomination)",
        pic.update_call(
            s.pool,
            p(USER),
            "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment: [0x33; 32],
                encrypted_payload: vec![],
                public_amount: 12_345, // not a denomination
            })
            .unwrap(),
        ),
    );
    assert_eq!(r, Err(PoolError::InvalidDenomination));
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "a pre-await `?` return must resolve the guard by Drop"
    );

    // (b) A1, pre-await pause rejection.
    let _: () = decode(
        "emergency_pause_deposits",
        pic.update_call(
            s.pool,
            p(CONTROLLER),
            "emergency_pause_deposits",
            candid::encode_args(()).unwrap(),
        ),
    );
    let r: Result<Nat, PoolError> = decode(
        "shield_deposit(paused)",
        pic.update_call(
            s.pool,
            p(USER),
            "shield_deposit",
            candid::encode_one(deposit_args([0x44; 32])).unwrap(),
        ),
    );
    assert_eq!(r, Err(PoolError::Paused));
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "a paused rejection must not leak an increment — a leaked one would make the \
         maintenance gate unclearable by exactly the operation the pause refused"
    );
    let _: () = decode(
        "unpause_deposits",
        pic.update_call(
            s.pool,
            p(CONTROLLER),
            "unpause_deposits",
            candid::encode_args(()).unwrap(),
        ),
    );

    // (c) A3, POST-await rejection: the guard survived a real await and a real
    //     suspension window, then resolved by Drop on an unknown anchor.
    let mut bogus = spend_fixture();
    bogus.spend_id = 23_400_4;
    // Canonical (top bytes zero) but not in ACCEPTED_SPEND_ROOTS — the #116
    // canonical-encoding guard rejects a 0x55-filled anchor before the precheck
    // ever sees it, which would prove nothing about the guard's Drop path.
    let mut unknown_anchor = [0u8; 32];
    unknown_anchor[0] = 0x9A;
    bogus.envelope.root_reference = unknown_anchor;
    let r: Result<(), PoolError> = decode(
        "private_spend(unknown anchor)",
        pic.update_call(s.pool, p(USER), "private_spend", candid::encode_one(bogus).unwrap()),
    );
    assert!(
        matches!(r, Err(PoolError::AnchorNotFound)),
        "expected an unknown-anchor rejection from the precheck; got {:?}",
        r
    );
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "a rejection AFTER the first await must still resolve the guard exactly once"
    );

    // (d) A4 `withdraw` — the fail-closed withdrawal family. Its guard is
    //     constructed and immediately resolved by Drop on the `?`. This is the
    //     CTO-amendment-retained withdrawal error shape; the withdrawal-side
    //     LIVE FOLD is deferred debt owed by the lane that removes
    //     `reject_unbound_withdrawal_proof` (committed base :6407-6409).
    let r: Result<Nat, PoolError> = decode(
        "withdraw(fail-closed)",
        pic.update_call(
            s.pool,
            p(USER),
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: 23_400_5,
                envelope: spend_fixture().envelope,
                nullifier: [0x66; 32],
                gross_withdraw_amount: DEPOSIT_AMOUNT,
                destination: p(USER),
                destination_subaccount: None,
            })
            .unwrap(),
        ),
    );
    assert_eq!(
        r,
        Err(PoolError::InvalidProof),
        "the withdrawal family must still fail closed — this test also PINS that fact, \
         which is what makes the deferred withdrawal-side evidence debt detectable"
    );
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "the fail-closed return must resolve its guard by Drop"
    );

    // Nothing above may have manufactured a phantom drop.
    assert_eq!(admitted_stats(&pic, s.pool).upgrade_dropped, 0);
    assert!(gate_is_clear(&pic, s.pool), "after five rejections the gate must read clear");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7 — §6 item 7: A7 `set_verifier_canister`, the sharpest RAII site
// ─────────────────────────────────────────────────────────────────────────────
//
// Its first durable write sits INSIDE the post-await synchronous closure, which
// has three `Err` returns before it. It carries no funds — but it bumps the
// security epoch, and a dropped one leaves the operator believing an attestation
// landed. `upgrade_dropped` is the only signal that it did not.

#[test]
fn test_w2_23d_a7_set_verifier_gate_reading_and_error_paths() {
    let (pic, s) = new_instance();
    let vk = stsh_verifier::compiled_vk_sha256().to_vec();

    // (a) Pre-await rejection: the expected hash does not match the pin.
    let r: Result<(), PoolError> = decode(
        "set_verifier_canister(wrong expected hash)",
        pic.update_call(
            s.pool,
            p(CONTROLLER),
            "set_verifier_canister",
            candid::encode_args((s.verifier, vec![0xEEu8; 32])).unwrap(),
        ),
    );
    assert_eq!(r, Err(PoolError::VerifierKeyHashMismatch));
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "A7's pre-await rejection must resolve by Drop"
    );

    // (b) POST-await rejection inside the closure: the attested canister cannot
    //     answer vk_hash. This is the highest-risk RAII site in the diff — the
    //     guard is resolved by Drop from INSIDE a closure that also clears the
    //     re-entrancy flag.
    let stranger = create_canister(&pic);
    let r: Result<(), PoolError> = decode(
        "set_verifier_canister(unreachable verifier)",
        pic.update_call(
            s.pool,
            p(CONTROLLER),
            "set_verifier_canister",
            candid::encode_args((stranger, vk.clone())).unwrap(),
        ),
    );
    assert!(
        matches!(r, Err(PoolError::VerifierUnavailable(_))),
        "expected a post-await VerifierUnavailable; got {:?}",
        r
    );
    assert_eq!(
        admitted_stats(&pic, s.pool).admitted,
        0,
        "an Err return from inside A7's closure, after the await, must resolve the guard \
         exactly once — the three pre-write Err paths fall through to Drop"
    );

    // (c) Gate reading: a real attestation suspended at its vk_hash await reads
    //     BUSY, and resolves at the durable write.
    let msg = submit_and_suspend(
        &pic,
        s.pool,
        p(CONTROLLER),
        "set_verifier_canister",
        candid::encode_args((s.verifier, vk)).unwrap(),
    );
    assert!(
        !gate_is_clear(&pic, s.pool),
        "a security-epoch-bumping attestation in flight must read BUSY — an operator who \
         upgrades here loses it with no other trace"
    );
    assert_eq!(admitted_stats(&pic, s.pool).admitted, 1);

    let bytes = pic.await_call(msg).expect("the attestation must complete");
    let r: Result<(), PoolError> = candid::decode_one(&bytes).expect("decode set_verifier");
    assert!(r.is_ok(), "set_verifier_canister must succeed: {:?}", r);
    assert!(
        gate_is_clear(&pic, s.pool),
        "resolve() runs at the durable write (VERIFIER_CANISTER + the security-epoch \
         bump), so the gate clears once the attestation lands"
    );
    assert_eq!(admitted_stats(&pic, s.pool).upgrade_dropped, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8 — §6 item 2: a pre-change checkpoint decodes on the PRODUCTION Wasm
// ─────────────────────────────────────────────────────────────────────────────
//
// Cross-Wasm proof of the Candid wire contract, with ZERO fixture or preflight
// expansion: plant an exact, structurally valid pre-change `PoolStableState`
// that OMITS the two new optional fields, then upgrade from the testing Wasm to
// the distinct PRODUCTION Wasm — the binary that actually ships, which also
// proves the new query is present there and not only under `--features testing`.
//
// `Option` is what makes this work. A new REQUIRED field would fail this decode
// wherever it sat in the declaration: Candid records are label-matched, not
// position-matched, so appending is a reviewability choice, not the mechanism.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode {
    FixedStsh,
    BpsOfAmount,
    Disabled,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceFeeParams {
    protocol_shielding_fee_stsh: u128,
    protocol_unshielding_fee_stsh: u128,
    protocol_private_spend_fee_stsh: u128,
    minimum_withdrawal_gross: u128,
    minimum_recipient_amount: u128,
    minimum_private_credit: u128,
    fee_reference_price_stsh_per_icp_e8s: u128,
    fee_safety_margin_bps: u32,
    max_fee_change_bps_per_update: u32,
    fee_update_cooldown_ns: u64,
    operations_split_bps: u32,
    insurance_split_bps: u32,
    staking_rewards_split_bps: u32,
    staking_rewards_enabled: bool,
    minimum_treasury_runway_months: u32,
    target_treasury_runway_months: u32,
    shield_fee_bps: Option<u16>,
    unshield_fee_bps: Option<u16>,
    shield_flat_minimum_fee_e8s: Option<u128>,
    unshield_flat_minimum_fee_e8s: Option<u128>,
    spend_fee_mode: Option<SpendFeeMode>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
}

/// `PoolStableState` EXACTLY as it was immediately before this lane — the W2
/// 2-3-C pair present, the two W2 2-3-D fields absent.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PreW223dPoolStableState {
    state_version: u32,
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
    pinned_circuit_version: u32,
    pinned_pool_version: u32,
    pinned_vk_hash: [u8; 32],
    pinned_proof_system: String,
    pending_vk_hash: Option<[u8; 32]>,
    pending_vk_version: Option<u32>,
    pending_vk_active_at: Option<u64>,
    old_vk_cutoff_at: Option<u64>,
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    deposits_paused: bool,
    spends_paused: bool,
    next_withdrawal_id: u64,
    verifier_canister: Option<Principal>,
    governance_fee_params: GovernanceFeeParams,
    treasury_notification_failures: Option<u64>,
    treasury_notifications_in_flight: Option<u64>,
    treasury_notifications_dropped: Option<u64>,
}

fn launch_default_params() -> GovernanceFeeParams {
    GovernanceFeeParams {
        protocol_shielding_fee_stsh: 0,
        protocol_unshielding_fee_stsh: 0,
        protocol_private_spend_fee_stsh: 0,
        minimum_withdrawal_gross: 0,
        minimum_recipient_amount: 0,
        minimum_private_credit: 0,
        fee_reference_price_stsh_per_icp_e8s: 0,
        fee_safety_margin_bps: 12_500,
        max_fee_change_bps_per_update: 1_000,
        fee_update_cooldown_ns: 86_400_000_000_000,
        operations_split_bps: 8_500,
        insurance_split_bps: 1_500,
        staking_rewards_split_bps: 0,
        staking_rewards_enabled: false,
        minimum_treasury_runway_months: 6,
        target_treasury_runway_months: 12,
        shield_fee_bps: None,
        unshield_fee_bps: None,
        shield_flat_minimum_fee_e8s: None,
        unshield_flat_minimum_fee_e8s: None,
        spend_fee_mode: None,
        fee_model_version: None,
        params_epoch: None,
    }
}

#[test]
fn test_w2_23d_pre_change_checkpoint_traps_on_production_wasm() {
    let (pic, s) = new_instance();

    let old_shape = PreW223dPoolStableState {
        state_version: 2,
        private_liability: 0,
        escrow_backing: 0,
        operations_reserve: 0,
        insurance_reserve: 0,
        governance_rewards_reserve: 0,
        pending_fee_reimbursements: 0,
        pinned_circuit_version: 0,
        pinned_pool_version: 1,
        pinned_vk_hash: stsh_verifier::compiled_vk_sha256(),
        pinned_proof_system: "groth16-bn254".to_string(),
        pending_vk_hash: None,
        pending_vk_version: None,
        pending_vk_active_at: None,
        old_vk_cutoff_at: None,
        token_canister: s.token,
        nullifier_canister: p(0x11),
        merkle_canister: p(0x12),
        treasury_canister: p(0x04),
        staking_canister: p(0x02),
        controller: p(CONTROLLER),
        deposits_paused: false,
        spends_paused: false,
        next_withdrawal_id: 1,
        verifier_canister: Some(s.verifier),
        governance_fee_params: launch_default_params(),
        treasury_notification_failures: Some(4),
        // Present and NON-ZERO, so this also proves the new fold does not
        // cannibalise the 2-3-C one on the same upgrade.
        treasury_notifications_in_flight: Some(3),
        treasury_notifications_dropped: Some(5),
    };

    let _: () = decode(
        "plant_corrupt_checkpoint_for_test",
        pic.update_call(
            s.pool,
            p(CONTROLLER),
            "plant_corrupt_checkpoint_for_test",
            candid::encode_one(candid::encode_one(&old_shape).unwrap()).unwrap(),
        ),
    );

    // testing Wasm → PRODUCTION Wasm, across a real canister boundary.
    //
    // RETARGETED (lane A-5, FU1-2, CTO_RULING_A-5_gate_red.md §F2). This test
    // previously asserted that a pre-change checkpoint DECODES on the production
    // Wasm ("an absent optional field is `null` → None, with no migration
    // handler"). FU1-2 was ruled to make exactly that false: the six accounting
    // scalars move to their own eager cell at MemoryId 20, `STATE_VERSION` is
    // bumped to 3, and `post_upgrade` TRAPS unconditionally on any pre-existing
    // blob — no migration arm, no seeding, no legacy decode
    // (`CTO_RULING_A-5_fu12_boundary.md`). The pre-FU1-2 boundary is therefore a
    // REINSTALL boundary, and the invariant survives in its new form: the
    // boundary is explicit, self-describing, and refuses rather than silently
    // reinterpreting a stale shape. Every other assertion in this file is
    // unchanged. R-15 now supports the explicit v3 -> v4 migration; the v2
    // boundary remains refused, and the diagnostic must name current version4.
    settle_install_budget(&pic);
    let err = upgrade_pool_to(&pic, s.pool, pool_wasm()).expect_err(
        "a pre-change (STATE_VERSION 2) checkpoint must be REFUSED by the production \
         Wasm — FU1-2 made the pre-change boundary a reinstall boundary, so a silent \
         decode here would mean the trap is not on the shipping binary",
    );
    assert!(
        err.contains("STATE_VERSION mismatch — stored 2, expected 4"),
        "the refusal must name the stored and expected versions so an operator can \
         act on it — a bare trap is not the contract; got: {err}"
    );
    assert!(
        err.contains("Write an explicit migration before upgrading to this version."),
        "the refusal must name the remedy (an explicit migration), not just the \
         mismatch; got: {err}"
    );
}
