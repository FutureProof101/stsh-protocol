// =============================================================================
// EXT REGRESSION PROOF — PoC-2 (H-3, EXT-2): token dedup algorithmic-complexity DoS
// =============================================================================
//
// GTM Step 1 regression proof. Test-only; zero production/DID/circuit/VK diff.
// Proves the H-3 (EXT-2) O(N) prune DoS reproduces RED at the pre-fix parent
// `76de5c6` and is closed GREEN at current master.
//
// The defect: `prune_expired_dedup` walked the ENTIRE TRANSFER_DEDUP map on every
// `created_at_time` op (the early `break` sat inside `if expired`, so a fresh
// flood where nothing is expired scanned all N). A zero-fee attacker forces an
// O(N) scan per call. The fix adds a time-keyed index → bounded range scan.
//
// Construction — deterministic, PURE PUBLIC INGRESS (the fix's
// inject_live_dedup_entries_for_test / measure_prune_instructions_for_test are
// #[cfg(feature="testing")] and do NOT exist at the parent, so they are barred).
// Production token Wasm at BOTH anchors; N resident FRESH dedup entries are built
// with real `icrc1_transfer`s (distinct memo, created_at_time = now ⇒ unexpired).
//
// Metric — cycle-balance delta for ONE `created_at_time` op (the SSA-recognised
// PocketIC proxy). Measured at N_small then N_large:
//   parent 76de5c6 : per-op delta SCALES with N (O(N) full prune walk).
//   fixed  master   : per-op delta is BOUNDED / independent of N.
// INTENTIONAL STOP CONDITION (not an unmeasured claim): if PocketIC cycle
// deltas do not witness the slope, the test STOPs and reports (panics with a
// STOP message) — never a wall-clock or weaker substitute.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read stsh_token Wasm at {}: {}", path, e))
}

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;

// ── Token candid mirrors ──────────────────────────────────────────────────────
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String, category_name: String, amount: u128, recipient: Principal,
    subaccount: Option<[u8; 32]>, lock_policy: LockPolicy, vesting_policy: Option<VestingPolicy>,
    created_at_genesis: bool, genesis_timestamp_ns: u64,
}
#[derive(CandidType, Deserialize)]
struct TokenInitArgs { allocations: Vec<AllocationCategory>, treasury: Principal, staking_canister: Principal }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferArgs {
    from_subaccount: Option<[u8; 32]>, to: Account, amount: Nat, fee: Option<Nat>,
    memo: Option<Vec<u8>>, created_at_time: Option<u64>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TransferError {
    BadFee { expected_fee: Nat }, BadBurn { min_burn_amount: Nat }, InsufficientFunds { balance: Nat },
    TooOld, CreatedInFuture { ledger_time: u64 }, Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable, GenericError { error_code: Nat, message: String },
}

// ── Helpers ───────────────────────────────────────────────────────────────────
fn p(n: u8) -> Principal { let mut b = [0u8; 29]; b[0] = n; Principal::from_slice(&b) }
fn decode<T, E>(label: &str, r: Result<Vec<u8>, E>) -> T
where T: CandidType + for<'de> serde::Deserialize<'de>, E: std::fmt::Debug {
    let bytes = r.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}
fn all_to(recipient: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".into(), category_name: "All".into(), amount: TOTAL_SUPPLY,
            recipient, subaccount: None, lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None, created_at_genesis: false, genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01), staking_canister: p(0x02),
    }
}
fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

/// One `created_at_time` transfer (amount 1, DISTINCT memo `seq`, fresh timestamp).
/// A distinct memo ⇒ a distinct dedup key ⇒ a NEW resident entry; the fresh
/// timestamp ⇒ unexpired. Returns the dedup-recording op it performed.
fn created_at_transfer(pic: &PocketIc, token: Principal, from: Principal, to: Principal, seq: u64) {
    let args = TransferArgs {
        from_subaccount: None, to: Account { owner: to, subaccount: None },
        amount: Nat::from(1u8), fee: None, memo: Some(seq.to_le_bytes().to_vec()),
        created_at_time: Some(now_ns(pic)),
    };
    let r: Result<Nat, TransferError> =
        decode("icrc1_transfer", pic.update_call(token, from, "icrc1_transfer", candid::encode_one(args).unwrap()));
    assert!(r.is_ok(), "population transfer seq={} must succeed (distinct memo ⇒ not a Duplicate); got {:?}", seq, r);
}

/// Cycle-balance delta the token canister spent executing ONE created_at_time op.
fn measure_one_op(pic: &PocketIc, token: Principal, from: Principal, to: Principal, seq: u64) -> u128 {
    let before = pic.cycle_balance(token);
    created_at_transfer(pic, token, from, to, seq);
    let after = pic.cycle_balance(token);
    before.saturating_sub(after)
}

fn median(mut v: Vec<u128>) -> u128 { v.sort_unstable(); v[v.len() / 2] }

// Resident-entry counts. N_LARGE / N_SMALL = 10× ⇒ an O(N) prune shows a ~10×
// per-op slope at the parent, while the bounded green prune stays flat.
const N_SMALL: u64 = 100;
const N_LARGE: u64 = 1000;
const SAMPLES: u64 = 5;

#[test]
fn poc2_h3_dedup_prune_complexity() {
    let pic = PocketIc::new();
    let user = p(0xAA);
    let sink = p(0xBB);
    let token = pic.create_canister();
    pic.add_cycles(token, 1_000_000_000_000_000u128); // ample headroom for N_LARGE ops
    pic.install_canister(token, token_wasm(), candid::encode_one(all_to(user)).unwrap(), None);

    let mut seq: u64 = 0;

    // ── Populate to N_SMALL fresh resident entries ────────────────────────────
    while seq < N_SMALL { created_at_transfer(&pic, token, user, sink, seq); seq += 1; }
    let small_samples: Vec<u128> = (0..SAMPLES).map(|_| { let d = measure_one_op(&pic, token, user, sink, seq); seq += 1; d }).collect();
    let small = median(small_samples.clone());
    println!("[PoC-2] resident≈{} per-op cycle deltas = {:?}  median={}", N_SMALL, small_samples, small);

    // ── Populate up to N_LARGE fresh resident entries ─────────────────────────
    while seq < N_LARGE { created_at_transfer(&pic, token, user, sink, seq); seq += 1; }
    let large_samples: Vec<u128> = (0..SAMPLES).map(|_| { let d = measure_one_op(&pic, token, user, sink, seq); seq += 1; d }).collect();
    let large = median(large_samples.clone());
    println!("[PoC-2] resident≈{} per-op cycle deltas = {:?}  median={}", N_LARGE, large_samples, large);

    let ratio = large as f64 / small.max(1) as f64;
    let per_entry = (large as i128 - small as i128) as f64 / (N_LARGE - N_SMALL) as f64;
    println!("[PoC-2] SUMMARY: small(N={})={}  large(N={})={}  ratio={:.2}x  slope≈{:.1} cycles/entry",
        N_SMALL, small, N_LARGE, large, ratio, per_entry);

    // STOP condition: if the metric is degenerate (no measurable cost), do not
    // dress up a null result as proof.
    assert!(small > 0 && large > 0,
        "STOP: PocketIC cycle deltas are degenerate (small={}, large={}); the metric cannot witness the slope — report, do not substitute.",
        small, large);

    // ── FINAL COMPLEXITY ASSERTION (the FIXED behavior) ───────────────────────
    // The discriminator is the SLOPE — per-op cycles added per resident entry —
    // NOT the ratio (the ~7.2M fixed transfer cost dilutes the ratio: measured
    // parent ratio at N=1000 is only ~1.5×, which would not separate cleanly).
    // GREEN keeps the per-op prune independent of the resident-set size, so the
    // slope collapses to log-N + memory + sampling noise (measured ≈56/entry).
    // The parent's O(N) full-scan walk costs ≈4.5k cycles per resident entry.
    // Threshold 1000 sits an order of magnitude above the green noise floor and
    // ~4.5× below the parent's linear cost.
    const GREEN_MAX_SLOPE_CYCLES_PER_ENTRY: f64 = 1000.0;
    assert!(per_entry < GREEN_MAX_SLOPE_CYCLES_PER_ENTRY,
        "GREEN: per-op prune cost must be INDEPENDENT of the resident-set size \
         (slope < {:.0} cycles/entry); got {:.1} cycles/entry over a {}× resident-set increase \
         (small={}, large={}). At the parent the O(N) full-scan prune scales linearly with N (RED).",
        GREEN_MAX_SLOPE_CYCLES_PER_ENTRY, per_entry, N_LARGE / N_SMALL, small, large);
}
