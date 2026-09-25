// =============================================================================
// STSH — A2-2 Criterion #16: Full-Path private_spend Benchmark (PocketIC)
// =============================================================================
//
// Gate:
//   cargo test -p integration-tests --test full_path_private_spend_benchmark \
//       -- --nocapture --test-threads=1
//
// SKIP behaviour:
//   Requires circuits/proof.json + circuits/public.json (real Groth16 artifacts).
//   If either file is absent the test prints SKIP and returns — not a failure.
//
// What is measured (full path through the shielded-pool state machine):
//   1. shield_deposit       — seeds in_commitment into the Merkle tree (anchor setup)
//   2. private_spend call   — static validation + precheck queries
//                             (is_known_root, contains_nullifier)
//   3. async verifier call  — real Groth16 proof verification
//   4. post-verify recheck  — anchor + nullifier recheck after await
//   5. insert_batch         — nullifier registry mutation
//   6. append_commitment×2  — two output commitments appended to Merkle tree
//   7. SpendStatus::Finalized confirmed
//
// Metrics captured:
//   N=10 wall-clock runs (each fresh PocketIC instance; see LIMITATIONS).
//   Single canonical run: cycle-balance breakdown across all four involved
//     canisters (pool, verifier, merkle, nullifier).
//   Verifier-only instruction count via verify_spend_canister_benchmark
//     (sub-metric; allows comparison with A2-1 baseline in verifier_tests).
//   Canister Wasm sizes.
//
// LIMITATIONS:
//   1. Wall-clock is a local PocketIC proxy, NOT real-subnet latency.
//      PocketIC 9.0.2 executes the full inter-canister call chain synchronously
//      within a single tick(); on ICP each cross-canister hop crosses subnet
//      rounds (~2 s/round minimum). On-chain end-to-end latency will be higher.
//   2. cycle_balance() delta is a PocketIC simulation proxy. On-chain cycle
//      accounting includes per-message routing fees not replicated by PocketIC.
//   3. Per-step instruction breakdown is only available for the verifier (via the
//      existing verify_spend_canister_benchmark endpoint). No equivalent endpoint
//      exists for pool, merkle, or nullifier canisters.
//   4. N=10 uses independent fresh PocketIC instances per iteration. The fixed
//      proof fixture has a single nullifier; reusing the same instance would
//      reject the second spend with NullifierAlreadySpent.
//   5. No failure paths benchmarked — happy path (SpendStatus::Finalized) only.
// =============================================================================
//
// #114 BENCHMARK RESULTS (2026-06-15, HEAD eccab9e, PocketIC 9.0.2)
// ─────────────────────────────────────────────────────────────────
// Wall-clock latency (PocketIC proxy, milliseconds):
//   avg :       63 ms   p50 :  64 ms   p95 :  67 ms   max :  67 ms
//   raw : [59, 61, 62, 63, 64, 64, 65, 66, 67, 67]
//
// Cycle breakdown — private_spend only (single canonical run):
//   shielded_pool      :    53,616,408 cycles
//   stsh_verifier      :   254,101,496 cycles
//   merkle_tree        :   278,194,755 cycles
//   nullifier_registry :    15,490,774 cycles
//   total              :   601,403,433 cycles  (601.4 M cycles)
//   verifier share     :          42.3%
//
// Verifier-only instruction count (A2-1 method):
//   instructions :       149,132,896  (well within 20B A2-1 ceiling)
//
// Canister Wasm sizes:
//   shielded_pool 861.6 KiB  |  stsh_verifier 537.4 KiB
//   merkle_tree   588.9 KiB  |  nullifier_registry 423.8 KiB
//
// Final state: SpendStatus::Finalized, outputs_committed=2, 3 Merkle leaves
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading (same env! vars as security_tests / verifier_tests)
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release \\\n    \
             -p stsh_token -p shielded_pool -p nullifier_registry \\\n    \
             -p merkle_tree -p stsh_verifier",
            pkg, path, e
        )
    })
}

fn token_wasm()     -> Vec<u8> { load_wasm(env!("TOKEN_WASM"),     "stsh_token") }
fn pool_wasm()      -> Vec<u8> { load_wasm(env!("POOL_WASM"),      "shielded_pool") }
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm()    -> Vec<u8> { load_wasm(env!("MERKLE_WASM"),    "merkle_tree") }
fn verifier_wasm()  -> Vec<u8> { load_wasm(env!("VERIFIER_WASM"),  "stsh_verifier") }

// ─────────────────────────────────────────────────────────────────────────────
// Candid type mirrors
//
// Canister crates use crate-type = ["cdylib"] which prevents linking them as
// normal Rust deps.  Only the types needed for this benchmark are mirrored here.
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DEFAULT_FEE:  u128 = 0; // F-000: token transfers free at launch
// DENOMINATIONS[0] = 1,000 STSH (must be in the pool's fixed denomination set; A6.6)
const DEPOSIT_AMOUNT: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0] (A6.6)

/// in_commitment for the spend circuit test vectors
/// (spend_key=42, in_value=100_000_000_000, in_rho=99, in_rseed=77).
/// DEF-035: domain-separated — Poseidon(domain_sep, in_value, derived_pk, in_rho,
/// in_rseed, COMMITMENT_DOMAIN). Regenerated by circuits/tests/gen_test_input.js.
// DEF-111 finalization regen: in_commitment over the finalized circuit's domain_sep [2,0,2,1].
// Post-A1 regen (2026-07-07): in_commitment over the MAINNET domain_sep
// [ohspu-zqaaa-aaaad-qmasq-cai→Fr, 0, 2, 1].
// A6.6 regen (2026-09-08): DOMAIN_CIRCUIT_VERSION 2 -> 3 AND in_value 1 STSH ->
// 1,000 STSH (the new ladder floor — the fixture note must be depositable), so
// the commitment moved on both counts. Regenerate via
// `node circuits/tests/gen_test_input.js`, then re-prove with snarkjs.
// A-3 FINALIZE regen (2026-09-12): DOMAIN_POOL_CANISTER_ID re-encoded to the
// Vault-born pool cxrfg-qaaaa-aaaar-qchfa-cai, so domain_sep — and therefore this
// known-answer commitment — moved. Regenerated via
// `node circuits/tests/gen_test_input.js`, then re-proved with snarkjs
// (circuits/proof.json + public.json, and the payout-A pair).
// A-3 FINALIZE value = 5364317693480985596849535143007715299620008859654397609343785557192353738706
// (was 10736000484984796872851673331456014893505793551453256205310079874034616912601 at A6.6).
const IN_COMMITMENT: [u8; 32] = [
    0xd2, 0x6f, 0x9b, 0xb7, 0x36, 0x0a, 0xed, 0x7f,
    0x09, 0x18, 0xe7, 0x27, 0x12, 0x3c, 0x86, 0x90,
    0xe2, 0x71, 0xb0, 0x5b, 0x6c, 0xb4, 0x52, 0xfc,
    0x6f, 0x05, 0x3a, 0xd4, 0xa1, 0x18, 0xdc, 0x0b,
];

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id:          String,
    category_name:        String,
    amount:               u128,
    recipient:            Principal,
    subaccount:           Option<[u8; 32]>,
    lock_policy:          LockPolicy,
    vesting_policy:       Option<VestingPolicy>,
    created_at_genesis:   bool,
    genesis_timestamp_ns: u64,
}

#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations:      Vec<AllocationCategory>,
    treasury:         Principal,
    staking_canister: Principal,
}

#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister:       Principal,
    nullifier_canister:   Principal,
    merkle_canister:      Principal,
    treasury_canister:    Principal,
    staking_canister:     Principal,
    controller:           Principal,
    initial_vk_hash:      [u8; 32],
    initial_proof_system: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version:    u32,
    proof_system_id:    String,
    verifying_key_hash: [u8; 32],
    root_reference:     [u8; 32],
    pool_version:       u32,
    proof_bytes:        Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs {
    note_commitment:   [u8; 32],
    encrypted_payload: Vec<u8>,
    public_amount:     u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id:           u64,
    envelope:           ProofEnvelope,
    nullifiers:         Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs:  Vec<Vec<u8>>,
    fee:                u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SpendStatus {
    Requested,
    OutputsStaged,
    Finalized,
    FailedBeforeStateChange     { reason: String },
    FailedAfterOutputsStaged    { reason: String },
    VerificationPending,
    NullifierReserved,
    // A2 (QA-DEF-034/036) + Pass 4 — superset so any returned status decodes.
    PayoutPending { reason: String },
    PayoutSubmitting,
    PayoutUnknown { reason: String },
    NullifierInsertUnknown { reason: String },
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingSpend {
    spend_id:           u64,
    nullifiers:         Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    outputs_committed:  u32,
    status:             SpendStatus,
    created_at_ns:      u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    EscrowUnderfunded          { required: u128, available: u128 },
    CircuitVersionMismatch     { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee       { amount: u128, fee: u128 },
    BelowMinimumDeposit        { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch                { inputs: u128, outputs: u128 },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateSpendId,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    InsufficientPrivateLiability { required: u128, available: u128 },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner:      Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount:    Option<[u8; 32]>,
    spender:            Account,
    amount:             Nat,
    expected_allowance: Option<Nat>,
    expires_at:         Option<u64>,
    fee:                Option<Nat>,
    memo:               Option<Vec<u8>>,
    created_at_time:    Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ApproveError {
    BadFee            { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged  { current_allowance: Nat },
    Expired           { ledger_time: u64 },
    TooOld,
    CreatedInFuture   { ledger_time: u64 },
    Duplicate         { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError      { error_code: Nat, message: String },
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
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    let args = candid::encode_one(init).expect("encode init args");
    pic.install_canister(cid, wasm, args, None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result
        .unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes)
        .unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn do_approve(pic: &PocketIc, token_id: Principal, caller: Principal,
              spender: Principal, amount: u128) {
    let result: Result<Nat, ApproveError> = decode(
        "icrc2_approve",
        pic.update_call(
            token_id, caller, "icrc2_approve",
            candid::encode_one(ApproveArgs {
                from_subaccount:    None,
                spender:            Account { owner: spender, subaccount: None },
                amount:             Nat::from(amount),
                expected_allowance: None,
                // H-01/dev007 (HARDEN-02): `expires_at` is MANDATORY on an approve that writes an
                // allowance row. 1 h — well inside MAX_APPROVAL_TTL_NS (24 h). This suite does not
                // exercise expiry, so the value only has to be present and in range.
                expires_at:         Some(pic.get_time().as_nanos_since_unix_epoch() as u64 + 3_600_000_000_000),
                fee:                None,
                memo:               None,
                created_at_time:    None,
            }).unwrap(),
        ),
    );
    result.expect("icrc2_approve must succeed in benchmark setup");
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .join("circuits")
}

/// Load the real proof/public artifacts and build a PrivateSpendArgs template.
/// Returns None if circuits/proof.json or circuits/public.json are absent.
fn load_fixture_args() -> Option<PrivateSpendArgs> {
    let public_json = std::fs::read_to_string(circuits_dir().join("public.json")).ok()?;
    let proof_json  = std::fs::read_to_string(circuits_dir().join("proof.json")).ok()?;
    let signals     = stsh_verifier::public_json_to_signals(&public_json).ok()?;
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json).ok()?;
    Some(PrivateSpendArgs {
        spend_id:    0, // overridden per-iteration
        envelope: ProofEnvelope {
            circuit_version:    0,
            proof_system_id:    "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference:     signals[0],
            pool_version:       1,
            proof_bytes,
        },
                nullifiers:         vec![signals[1]],
        output_commitments: vec![signals[2], signals[3]],
        encrypted_outputs:  vec![vec![0xAA], vec![0xBB]],
        fee:                0,
    })
}

/// Create and fully configure a fresh 5-canister full-path instance.
/// Returns (token_id, null_id, pool_id, merkle_id, verifier).
fn setup_instance(pic: &PocketIc) -> (Principal, Principal, Principal, Principal, Principal) {
    let user      = p(0xB0);
    let token_id  = create_canister(pic);
    let null_id   = create_canister(pic);
    let pool_id   = create_canister(pic);
    let merkle_id = create_canister(pic);
    let verifier  = create_canister(pic);

    pic.install_canister(null_id,   nullifier_wasm(), candid::encode_one(pool_id).unwrap(),   None);
    pic.install_canister(merkle_id, merkle_wasm(),    candid::encode_one(pool_id).unwrap(),   None);
    // DEF-083: the verifier is pool-caller-gated — bind it to this instance's pool.
    pic.install_canister(verifier,  verifier_wasm(),  candid::encode_one(pool_id).unwrap(), None);

    install(pic, token_id, token_wasm(), &TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id:          "all".to_string(),
            category_name:        "All tokens".to_string(),
            amount:               TOTAL_SUPPLY,
            recipient:            user,
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }],
        treasury:         p(0x01),
        staking_canister: p(0x02),
    });

    install(pic, pool_id, pool_wasm(), &PoolInitArgs {
        token_canister:       token_id,
        nullifier_canister:   null_id,
        merkle_canister:      merkle_id,
        treasury_canister:    p(0x04),
        staking_canister:     p(0x02),
        controller:           p(0x06),
        initial_vk_hash:      stsh_verifier::compiled_vk_sha256(),
        initial_proof_system: "groth16-bn254".to_string(),
    });

    // Wire the real verifier to the pool (controller-only call).
    pic.update_call(
        pool_id, p(0x06), "set_verifier_canister",
        candid::encode_args((verifier, stsh_verifier::compiled_vk_sha256().to_vec())).unwrap(),
    ).expect("set_verifier_canister must succeed");

    (token_id, null_id, pool_id, merkle_id, verifier)
}

/// Seed IN_COMMITMENT into the Merkle tree via shield_deposit.
/// This is setup — not part of the timed / measured window.
fn seed_deposit(pic: &PocketIc, token_id: Principal, pool_id: Principal) {
    let user = p(0xB0);
    do_approve(pic, token_id, user, pool_id, DEPOSIT_AMOUNT + DEFAULT_FEE);
    let result: Result<Nat, PoolError> = decode(
        "seed shield_deposit",
        pic.update_call(
            pool_id, user, "shield_deposit",
            candid::encode_one(ShieldDepositArgs {
                note_commitment:   IN_COMMITMENT,
                encrypted_payload: vec![],
                public_amount:     DEPOSIT_AMOUNT,
            }).unwrap(),
        ),
    );
    result.expect("seed shield_deposit must succeed");
}

fn percentile<T: Copy>(sorted: &[T], pct: usize) -> T {
    let idx = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

// ─────────────────────────────────────────────────────────────────────────────
// A2-2 Criterion #16 — Full-path private_spend benchmark
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_b01_full_path_private_spend_benchmark() {
    let Some(fixture) = load_fixture_args() else {
        // R4-2 (sweep fold): a silent skip is indistinguishable from a pass.
        panic!("circuits/proof.json and circuits/public.json are TRACKED files, so their absence means they were DELETED, not that this environment lacks an optional artifact. A silent SKIP reported as ok, which left the gate line unable to distinguish a verified real-proof path from a missing fixture (R4-2). Restore them: git checkout -- circuits/proof.json circuits/public.json");
    };

    // ── Phase 1: N=10 wall-clock measurement ─────────────────────────────────
    //
    // Timed window: private_spend call only.
    // Setup (canister install + shield_deposit) is EXCLUDED from timing.
    // Each iteration uses a fresh PocketIC instance (see LIMITATIONS #4).

    const N: usize = 10;
    let mut wall_ms: Vec<u128> = Vec::with_capacity(N);

    for i in 0..N {
        let pic   = PocketIc::new();
        let (token_id, _null_id, pool_id, _merkle_id, _verifier) = setup_instance(&pic);
        seed_deposit(&pic, token_id, pool_id);

        let args = PrivateSpendArgs {
            spend_id: 9000 + i as u64,
            ..fixture.clone()
        };

        let start  = Instant::now();
        let result: Result<(), PoolError> = decode(
            "private_spend (wall-clock)",
            pic.update_call(
                pool_id, p(0xB0), "private_spend",
                candid::encode_one(args).unwrap(),
            ),
        );
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "wall-clock iteration {} failed: {:?}", i, result
        );
        wall_ms.push(elapsed.as_millis());
    }

    wall_ms.sort_unstable();
    let avg_ms  = wall_ms.iter().sum::<u128>() / N as u128;
    let p50_ms  = percentile(&wall_ms, 50);
    let p95_ms  = percentile(&wall_ms, 95);
    let max_ms  = *wall_ms.last().unwrap();

    // ── Phase 2: Cycle-balance breakdown (single canonical run) ───────────────
    //
    // Snapshot cycle balances immediately before and after the private_spend call.
    // Deltas capture compute cost + inter-canister routing charged to each canister.

    let pic_c = PocketIc::new();
    let (token_id_c, null_id_c, pool_id_c, merkle_id_c, verifier_c) = setup_instance(&pic_c);
    seed_deposit(&pic_c, token_id_c, pool_id_c);

    let args_canonical = PrivateSpendArgs { spend_id: 9100, ..fixture.clone() };

    // Snapshot before private_spend (after deposit — deposit cycles not counted)
    let pool_before     = pic_c.cycle_balance(pool_id_c);
    let verifier_before = pic_c.cycle_balance(verifier_c);
    let merkle_before   = pic_c.cycle_balance(merkle_id_c);
    let null_before     = pic_c.cycle_balance(null_id_c);

    let result_c: Result<(), PoolError> = decode(
        "private_spend (cycle measurement)",
        pic_c.update_call(
            pool_id_c, p(0xB0), "private_spend",
            candid::encode_one(args_canonical).unwrap(),
        ),
    );
    assert!(result_c.is_ok(), "canonical cycle-measurement run failed: {:?}", result_c);

    let pool_delta     = pool_before     as i128 - pic_c.cycle_balance(pool_id_c)  as i128;
    let verifier_delta = verifier_before as i128 - pic_c.cycle_balance(verifier_c) as i128;
    let merkle_delta   = merkle_before   as i128 - pic_c.cycle_balance(merkle_id_c) as i128;
    let null_delta     = null_before     as i128 - pic_c.cycle_balance(null_id_c)  as i128;
    let total_delta    = pool_delta + verifier_delta + merkle_delta + null_delta;

    // Sanity-check: SpendStatus must be Finalized
    let record: Option<PendingSpend> = decode(
        "get_spend_status (canonical)",
        pic_c.query_call(
            // DEF-069: get_spend_status is owner-or-controller gated — poll as the
            // pool controller p(0x06) (controller may read any record).
            pool_id_c, p(0x06), "get_spend_status",
            candid::encode_one(9100_u64).unwrap(),
        ),
    );
    let rec = record.expect("spend record must exist after canonical run");
    assert!(
        matches!(rec.status, SpendStatus::Finalized),
        "canonical run must reach Finalized; got {:?}", rec.status
    );
    assert_eq!(rec.outputs_committed, 2, "both output commitments must be appended");

    // ── Phase 3: Verifier instruction sub-metric ──────────────────────────────
    //
    // Call verify_spend_canister_benchmark directly on the verifier canister
    // from the canonical instance.  This endpoint returns (Result<(),String>, u64)
    // where the u64 is ic_cdk::api::instruction_counter() after verification.
    // Provides a direct comparison point with the A2-1 baseline (test_v08).
    // DEF-083: the endpoint is pool-gated — send as pool_id_c, the principal the
    // verifier was installed with (PocketIC allows canister principals as sender).

    let proof_bytes: Vec<u8> = fixture.envelope.proof_bytes.clone();
    let signals: Vec<Vec<u8>> = {
        // Reload signals directly from public.json — the canonical source of truth.
        // signals layout (M4 circuit): [root, nullifier, oc0, oc1, in_value, out_value_sum]
        let public_json = std::fs::read_to_string(circuits_dir().join("public.json"))
            .expect("public.json must be present if fixture loaded");
        stsh_verifier::public_json_to_signals(&public_json)
            .expect("public_json_to_signals must succeed")
            .iter()
            .map(|s| s.to_vec())
            .collect()
    };

    let vb_encoded = candid::encode_args((&proof_bytes, &signals))
        .expect("encode verify_spend_canister_benchmark args");
    let vb_bytes = pic_c.update_call(
        verifier_c, pool_id_c, "verify_spend_canister_benchmark", vb_encoded,
    ).expect("verify_spend_canister_benchmark must succeed");
    let (vb_result, verify_instructions): (Result<(), String>, u64) =
        candid::decode_args(&vb_bytes)
            .expect("decode verify_spend_canister_benchmark result");
    assert!(vb_result.is_ok(), "standalone verifier benchmark rejected the proof: {:?}", vb_result);

    // ── Phase 4: Wasm sizes ───────────────────────────────────────────────────

    let pool_wasm_size     = std::fs::metadata(env!("POOL_WASM"))    .map(|m| m.len()).unwrap_or(0);
    let verifier_wasm_size = std::fs::metadata(env!("VERIFIER_WASM")).map(|m| m.len()).unwrap_or(0);
    let merkle_wasm_size   = std::fs::metadata(env!("MERKLE_WASM"))  .map(|m| m.len()).unwrap_or(0);
    let null_wasm_size     = std::fs::metadata(env!("NULLIFIER_WASM")).map(|m| m.len()).unwrap_or(0);

    // ── Report ────────────────────────────────────────────────────────────────

    let verifier_pct = if total_delta > 0 {
        verifier_delta as f64 / total_delta as f64 * 100.0
    } else {
        0.0
    };

    println!();
    println!("=============================================================");
    println!("A2-2 CRITERION #16: FULL-PATH private_spend BENCHMARK (N={})", N);
    println!("  PocketIC 9.0.2 / production instruction limits");
    println!("  Timed window: private_spend only (setup + deposit excluded)");
    println!("-------------------------------------------------------------");
    println!("Wall-clock latency (PocketIC proxy, milliseconds):");
    println!("  avg : {:>8} ms", avg_ms);
    println!("  p50 : {:>8} ms", p50_ms);
    println!("  p95 : {:>8} ms", p95_ms);
    println!("  max : {:>8} ms", max_ms);
    println!("  raw : {:?}", wall_ms);
    println!("-------------------------------------------------------------");
    println!("Cycle breakdown — private_spend only (single canonical run):");
    println!("  shielded_pool      : {:>15} cycles", pool_delta);
    println!("  stsh_verifier      : {:>15} cycles", verifier_delta);
    println!("  merkle_tree        : {:>15} cycles", merkle_delta);
    println!("  nullifier_registry : {:>15} cycles", null_delta);
    println!("  ─────────────────────────────────────────────");
    println!("  total              : {:>15} cycles  ({:.1} M cycles)",
             total_delta, total_delta as f64 / 1_000_000.0);
    println!("  verifier share     : {:.1}%", verifier_pct);
    println!("-------------------------------------------------------------");
    println!("Verifier-only instruction count (A2-1 method, single direct call):");
    println!("  instructions : {:>15}  (compare: A2-1 baseline in test_v08)", verify_instructions);
    println!("-------------------------------------------------------------");
    println!("Canister Wasm sizes:");
    println!("  shielded_pool      : {:>8} bytes  ({:.1} KiB)",
             pool_wasm_size,     pool_wasm_size     as f64 / 1024.0);
    println!("  stsh_verifier      : {:>8} bytes  ({:.1} KiB)",
             verifier_wasm_size, verifier_wasm_size as f64 / 1024.0);
    println!("  merkle_tree        : {:>8} bytes  ({:.1} KiB)",
             merkle_wasm_size,   merkle_wasm_size   as f64 / 1024.0);
    println!("  nullifier_registry : {:>8} bytes  ({:.1} KiB)",
             null_wasm_size,     null_wasm_size     as f64 / 1024.0);
    println!("-------------------------------------------------------------");
    println!("Final state (canonical run):");
    println!("  SpendStatus        : Finalized");
    println!("  outputs_committed  : {}", rec.outputs_committed);
    println!("  nullifiers         : 1 (in permanent registry)");
    println!("  Merkle leaves      : 3 (1 deposit + 2 spend outputs)");
    println!("=============================================================");
    println!();
}
