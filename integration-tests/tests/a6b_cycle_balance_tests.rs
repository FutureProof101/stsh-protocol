// =============================================================================
// STSH — A-6b: the `cycle_balance` interface contract, five times (PocketIC)
// Automated remediation campaign wave 2, lane A-6b.
// =============================================================================
//
// Lane A-6 shipped the off-chain fleet cycle monitor; its register names six
// canisters and vetkeys already carries `cycle_balance` (merged with A-2). This
// lane adds the canister-side query contract to the remaining five, and these
// tests are the evidence that the contract is real on each of them:
//
//   E1 ×5  anonymous `cycle_balance` decodes as Candid `nat`  (shape + the
//          deliberate no-caller-gate decision)
//   E2 ×5  0 < balance < funded    (a LIVE value: not zero, not a constant,
//          and not the funded figure echoed back — installation burns cycles)
//   E3     two canisters funded DIFFERENTLY in one instance report DISTINCT
//          values, each inside its own funding (RULE 6 — causal: a hardcoded
//          constant, a neighbour's value, or a `0` stub all fail here where a
//          single post-state equality check would not distinguish them)
//   E4     a real cycle-burning message makes the reported value DECREASE
//          (the query reads live state, not an install-time snapshot)
//   E5m    RULE 5 — the endpoint's own cost, MEASURED in replicated execution
//
// GAP-U9-1 is NOT closed by this lane: the monitor's live source is still
// `UnwiredSource` and it still reports six × NOT_YET_COVERED / exit 2. These
// tests prove the five interfaces exist, not that the fleet is monitored.
//
// PRODUCTION Wasms only (RULE 12a — the artifact under review is the shipped
// canister, never a `--features testing` build).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   ./run_gate.sh   (canonical; it does both phases and both suites)
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ── Wasm loading ─────────────────────────────────────────────────────────────

fn load(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {} Wasm {}: {}", label, path, e))
}
fn pool_wasm() -> Vec<u8> { load(env!("POOL_WASM"), "shielded_pool") }
fn verifier_wasm() -> Vec<u8> { load(env!("VERIFIER_WASM"), "stsh_verifier") }
fn nullifier_wasm() -> Vec<u8> { load(env!("NULLIFIER_WASM"), "nullifier_registry") }
fn merkle_wasm() -> Vec<u8> { load(env!("MERKLE_WASM"), "merkle_tree") }
fn token_wasm() -> Vec<u8> { load(env!("TOKEN_WASM"), "stsh_token") }

// ── Principals ───────────────────────────────────────────────────────────────

fn p(b: u8) -> Principal { Principal::from_slice(&[b; 29]) }
fn controller() -> Principal { p(0xC0) }
/// The principal the merkle/nullifier registries are initialised to trust.
fn pool_principal() -> Principal { p(0xAA) }

// ── Type mirrors ─────────────────────────────────────────────────────────────

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
    verifier_canister: Option<Principal>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

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

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;

fn token_init() -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id:          "all".to_string(),
            category_name:        "All tokens".to_string(),
            amount:               TOTAL_SUPPLY,
            recipient:            p(0x11),
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }],
        treasury:         p(0x01),
        staking_canister: p(0x02),
    }
}

fn pool_init() -> PoolInitArgs {
    PoolInitArgs {
        token_canister:       p(0x21),
        nullifier_canister:   p(0x22),
        merkle_canister:      p(0x23),
        treasury_canister:    p(0x24),
        staking_canister:     p(0x25),
        controller:           controller(),
        initial_vk_hash:      [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister:    None,
    }
}

// ── PocketIC helpers ─────────────────────────────────────────────────────────

/// Creates a canister, funds it with EXACTLY `funded` cycles beyond whatever
/// `create_canister` seeds, installs `wasm`, and returns the canister id
/// together with the host-observed balance IMMEDIATELY BEFORE installation.
/// That pre-install figure is the honest "funded" reference for E2: the query's
/// answer must be strictly below it, because installing burns cycles.
fn install_funded<T: CandidType>(
    pic: &PocketIc,
    wasm: Vec<u8>,
    init: &T,
    funded: u128,
) -> (Principal, u128) {
    let cid = pic.create_canister();
    pic.add_cycles(cid, funded);
    let before_install = pic.cycle_balance(cid);
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
    (cid, before_install)
}

/// ANONYMOUS query — the endpoint carries no caller gate by design, and every
/// E1 goes through this path so the absence of a gate is asserted, not assumed.
fn cycle_balance_anon(pic: &PocketIc, cid: Principal) -> Nat {
    let bytes = pic
        .query_call(cid, Principal::anonymous(), "cycle_balance", candid::encode_args(()).unwrap())
        .unwrap_or_else(|e| panic!("cycle_balance query rejected for {}: {:?}", cid, e));
    candid::decode_one::<Nat>(&bytes).unwrap_or_else(|e| panic!("cycle_balance did not decode as nat: {}", e))
}

fn nat_to_u128(n: &Nat) -> u128 {
    // Via Display rather than a `num-traits` cast: this lane's fence holds
    // `Cargo.toml` / `Cargo.lock` at zero diff, so no dependency is added.
    n.0.to_string().parse::<u128>().expect("cycle balance is not a u128-sized nat")
}

const FUND: u128 = 3_000_000_000_000; // 3T — comfortably above the install cost

/// Installs one of the five, funded with `funded`, and returns (id, pre-install balance).
fn install_target(pic: &PocketIc, which: &str, funded: u128) -> (Principal, u128) {
    match which {
        "shielded_pool"      => install_funded(pic, pool_wasm(),      &pool_init(),        funded),
        "verifier"           => install_funded(pic, verifier_wasm(),  &pool_principal(),   funded),
        "nullifier_registry" => install_funded(pic, nullifier_wasm(), &pool_principal(),   funded),
        "merkle_tree"        => install_funded(pic, merkle_wasm(),    &pool_principal(),   funded),
        "token"              => install_funded(pic, token_wasm(),     &token_init(),       funded),
        other                => panic!("unknown target {}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// E1 ×5 — anonymous call, Candid `nat` shape
// ─────────────────────────────────────────────────────────────────────────────

fn e1_shape(which: &str) {
    let pic = PocketIc::new();
    let (cid, _) = install_target(&pic, which, FUND);
    let n = cycle_balance_anon(&pic, cid);
    // Decoding as Nat above IS the shape assertion; converting proves it is a
    // plain unsigned integer and not, say, a wrapped variant.
    let v = nat_to_u128(&n);
    println!("E1 {}: anonymous cycle_balance = {} (decoded as nat)", which, v);
}

#[test] fn e1_shape_shielded_pool()      { e1_shape("shielded_pool"); }
#[test] fn e1_shape_verifier()           { e1_shape("verifier"); }
#[test] fn e1_shape_nullifier_registry() { e1_shape("nullifier_registry"); }
#[test] fn e1_shape_merkle_tree()        { e1_shape("merkle_tree"); }
#[test] fn e1_shape_token()              { e1_shape("token"); }

// ─────────────────────────────────────────────────────────────────────────────
// E2 ×5 — a LIVE value: 0 < balance < funded
// ─────────────────────────────────────────────────────────────────────────────

fn e2_live_value(which: &str) {
    let pic = PocketIc::new();
    let (cid, funded) = install_target(&pic, which, FUND);
    let v = nat_to_u128(&cycle_balance_anon(&pic, cid));
    assert!(v > 0, "{}: cycle_balance reported 0 — a stub, not a live balance", which);
    assert!(
        v < funded,
        "{}: cycle_balance reported {} which is not BELOW the pre-install funding {} — \
         the endpoint is echoing the funded figure rather than reading the live balance",
        which, v, funded
    );
    println!("E2 {}: {} < funded {} (delta {} burned by installation)", which, v, funded, funded - v);
}

#[test] fn e2_live_value_shielded_pool()      { e2_live_value("shielded_pool"); }
#[test] fn e2_live_value_verifier()           { e2_live_value("verifier"); }
#[test] fn e2_live_value_nullifier_registry() { e2_live_value("nullifier_registry"); }
#[test] fn e2_live_value_merkle_tree()        { e2_live_value("merkle_tree"); }
#[test] fn e2_live_value_token()              { e2_live_value("token"); }

// ─────────────────────────────────────────────────────────────────────────────
// E3 — RULE 6, causal: two canisters, two fundings, two distinct answers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e3_two_fundings_report_distinct_values_each_within_its_own() {
    let pic = PocketIc::new();
    let low_fund = 2_000_000_000_000u128;
    let high_fund = 9_000_000_000_000u128;

    let (low, low_funded) = install_funded(&pic, merkle_wasm(), &pool_principal(), low_fund);
    let (high, high_funded) = install_funded(&pic, merkle_wasm(), &pool_principal(), high_fund);

    let lo = nat_to_u128(&cycle_balance_anon(&pic, low));
    let hi = nat_to_u128(&cycle_balance_anon(&pic, high));

    // Distinct: rules out a hardcoded constant and rules out one canister
    // reporting the other's (or the subnet's) figure.
    assert_ne!(lo, hi, "both canisters reported {} — the value cannot be canister-specific", lo);
    // Each inside ITS OWN funding, and ordered as funded: rules out the values
    // being swapped or unrelated to this canister's actual endowment.
    assert!(lo > 0 && lo < low_funded, "low canister: {} not in (0, {})", lo, low_funded);
    assert!(hi > 0 && hi < high_funded, "high canister: {} not in (0, {})", hi, high_funded);
    assert!(hi > lo, "the canister funded with {} reported {}, not more than the one funded with {} ({})",
            high_fund, hi, low_fund, lo);
    println!("E3: low {} (funded {}) < high {} (funded {})", lo, low_funded, hi, high_funded);
}

// ─────────────────────────────────────────────────────────────────────────────
// E4 — the value tracks real cycle burn (live read, not an install snapshot)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e4_reported_balance_decreases_after_a_real_burning_message() {
    let pic = PocketIc::new();
    // merkle_tree is initialised to trust `pool_principal()`, so we can send it
    // a genuine authorized update message that does real work.
    let (merkle, _) = install_funded(&pic, merkle_wasm(), &pool_principal(), FUND);

    let before = nat_to_u128(&cycle_balance_anon(&pic, merkle));

    // A canonical BN254 field element (value 1, little-endian) — a real append,
    // not a rejected call, so the canister genuinely executes and pays.
    let mut commitment = [0u8; 32];
    commitment[0] = 1;
    let res: Result<u64, String> = candid::decode_one(
        &pic.update_call(
            merkle,
            pool_principal(),
            "append_commitment",
            candid::encode_args((commitment.to_vec(), Vec::<u8>::new())).unwrap(),
        )
        .expect("append_commitment rejected"),
    )
    .expect("decode append_commitment");
    assert!(res.is_ok(), "append_commitment failed: {:?} — E4 needs a message that really executes", res);

    let after = nat_to_u128(&cycle_balance_anon(&pic, merkle));
    assert!(
        after < before,
        "cycle_balance did not fall across a real burning message ({} -> {}): the query is \
         reporting an install-time snapshot, not live state",
        before, after
    );
    println!("E4: {} -> {} ({} cycles burned by one append_commitment)", before, after, before - after);
}

// ─────────────────────────────────────────────────────────────────────────────
// E5m — RULE 5: bound the defence's own cost, MEASURED
// ─────────────────────────────────────────────────────────────────────────────

/// The endpoint is a query with one system call and no state read, so on the IC
/// it costs the caller's replica nothing the canister pays for. To put a real
/// number on it anyway, this measures the method executed in REPLICATED mode
/// (a query method may be invoked as an update call), which is the strictly
/// more expensive path and therefore an honest UPPER bound: it includes the
/// full ingress-message overhead the query path does not pay at all.
///
/// The 1e9-cycle assertion is a TEST bound, not a shipped parameter — this lane
/// ships no magnitude (see the package's RULE 2 section).
#[test]
fn e5m_replicated_execution_cost_is_bounded() {
    let pic = PocketIc::new();
    let (merkle, _) = install_funded(&pic, merkle_wasm(), &pool_principal(), FUND);

    let before = pic.cycle_balance(merkle);
    pic.update_call(merkle, Principal::anonymous(), "cycle_balance", candid::encode_args(()).unwrap())
        .expect("cycle_balance as replicated call");
    let cost = before - pic.cycle_balance(merkle);

    const BOUND: u128 = 1_000_000_000; // 1e9 cycles
    assert!(
        cost < BOUND,
        "cycle_balance cost {} cycles in replicated execution, above the {} bound",
        cost, BOUND
    );
    println!("E5m: replicated execution of cycle_balance cost {} cycles (bound {})", cost, BOUND);
}
