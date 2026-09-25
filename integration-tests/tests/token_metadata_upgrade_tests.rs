// =============================================================================
// TOKEN-METADATA — live-module upgrade fixture (brief AC-2 / I-2)
//
// Installs the GENUINE live clv7x stsh_token module (ac9336f2…, the
// pre-TOKEN-METADATA `[wasm.stsh_token]` pin, byte-identical to the staged
// A-7 artifact ~/a7-kit/stsh_token.wasm), builds ledger state, upgrades to the
// freshly built stsh_token.wasm with an EMPTY upgrade arg (exactly the bytes
// the operator page sends with no arg file → expected_arg_hash e3b0c442…),
// and proves:
//   * icrc1_metadata differs in EXACTLY icrc1:name (the pre-launch name → "STSH")
//     and icrc1:logo (SVG data URL → the committed PNG data URL); same keys,
//     same order, every other value byte-identical;
//   * balances (≥3 accounts, incl. a subaccount), an allowance,
//     icrc1_total_supply, icrc1_minting_account, fee/symbol/decimals,
//     supported standards, genesis allocations and the supply invariant are
//     byte-identical pre/post;
//   * the ledger is live post-upgrade: the dedup row survives (replay →
//     Duplicate), a fresh transfer succeeds, the allowance is spendable.
//
// Fixture mechanism = the LAUNCH-HARDEN-04 pattern
// (harden04_common/mod.rs `live_pool_wasm()`): a hash-checked loader beside
// TOKEN_WASM, with the placement recipe in the panic. Not wired into
// run_gate.sh / build.rs.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;

/// The LIVE clv7x token module before this lane — the pre-TOKEN-METADATA
/// `[wasm.stsh_token]` pin (ac9336f2…, 893,997 B, byte-identical to the staged
/// A-7 artifact ~/a7-kit/stsh_token.wasm).
const LIVE_TOKEN_SHA256: &str =
    "ac9336f2111b76e25f8afd0957dd5c0c619166c96192e7de5bc8fcf944c354b6";

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token Wasm at {path}: {e}.\nBuild first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token"
        )
    })
}

fn live_token_wasm() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let path = std::path::Path::new(env!("TOKEN_WASM"))
        .with_file_name("stsh_token_live_clv7x_ac9336f2.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} not found ({e}) — the upgrade arm needs the GENUINE live clv7x token \
             module (ac9336f2 — the pre-TOKEN-METADATA [wasm.stsh_token] pin, \
             byte-identical to the staged A-7 artifact). Place it with:\n  \
             cp ~/a7-kit/stsh_token.wasm {}\n  expected sha256: {LIVE_TOKEN_SHA256}\n  \
             (alternative: a clean env -i gate build of any head in dc622d5..9a96175)",
            path.display(),
            path.display()
        )
    });
    let got: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, LIVE_TOKEN_SHA256, "live token fixture has the WRONG hash");
    bytes
}

/// RFC 4648 standard base64 (padded) — integration-tests has no base64 dep.
fn b64_standard(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

// ── Wire types ───────────────────────────────────────────────────────────────

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>,
    from: Account,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum TransferFromError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllowanceArgs {
    account: Account,
    spender: Account,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Allowance {
    allowance: Nat,
    expires_at: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum MetadataValue {
    Nat(Nat),
    Int(candid::Int),
    Text(String),
    Blob(Vec<u8>),
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct SupplyInvariantReport {
    fixed_max_supply: u128,
    sum_all_balances: u128,
    staking_locked_total: u128,
    fee_reserve_total: u128,
    invariant_holds: bool,
    checked_at_ns: u64,
    violation_detail: Option<String>,
    arithmetic_error: Option<ArithmeticErrorReport>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ArithmeticErrorReport {
    balances_overflow: bool,
    staking_locks_overflow: bool,
    balances_plus_fee_overflow: bool,
}

// ── Principals / accounts ────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn alice() -> Principal { p(0xA1) }
fn bob() -> Principal { p(0xB2) }
fn carol() -> Principal { p(0xC3) }
fn dave() -> Principal { p(0xD5) }
fn dexp() -> Principal { p(0xD4) } // spender
fn feecol() -> Principal { p(0xF1) }

fn acct(owner: Principal) -> Account { Account { owner, subaccount: None } }
fn acct_sub(owner: Principal, tag: u8) -> Account {
    let mut s = [0u8; 32];
    s[31] = tag;
    Account { owner, subaccount: Some(s) }
}

// ── Call plumbing ────────────────────────────────────────────────────────────

fn q_raw(pic: &PocketIc, cid: Principal, method: &str, args: Vec<u8>) -> Vec<u8> {
    pic.query_call(cid, Principal::anonymous(), method, args)
        .unwrap_or_else(|e| panic!("{method}: query rejected: {e:?}"))
}

fn q<T: CandidType + for<'de> Deserialize<'de>>(
    pic: &PocketIc, cid: Principal, method: &str, args: Vec<u8>,
) -> T {
    candid::decode_one(&q_raw(pic, cid, method, args))
        .unwrap_or_else(|e| panic!("{method}: decode failed: {e}"))
}

fn u<T: CandidType + for<'de> Deserialize<'de>>(
    pic: &PocketIc, cid: Principal, caller: Principal, method: &str, args: Vec<u8>,
) -> T {
    let bytes = pic
        .update_call(cid, caller, method, args)
        .unwrap_or_else(|e| panic!("{method}: update rejected: {e:?}"));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{method}: decode failed: {e}"))
}

fn noargs() -> Vec<u8> { candid::encode_args(()).unwrap() }

fn to_u128(n: &Nat) -> u128 { n.0.to_string().parse::<u128>().expect("Nat exceeds u128") }

fn now_ns(pic: &PocketIc) -> u64 { pic.get_time().as_nanos_since_unix_epoch() as u64 }

fn xfer(to: Account, amount: u128) -> TransferArgs {
    TransferArgs { from_subaccount: None, to, amount: Nat::from(amount), fee: None, memo: None, created_at_time: None }
}

fn transfer(pic: &PocketIc, cid: Principal, caller: Principal, a: &TransferArgs) -> Result<Nat, TransferError> {
    u(pic, cid, caller, "icrc1_transfer", candid::encode_one(a).unwrap())
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

/// Raw Candid reply bytes of every state-bearing query (byte-identical
/// comparison), plus the decoded metadata and supply report.
#[derive(Debug)]
struct Snapshot {
    raw: Vec<(String, Vec<u8>)>,
    metadata: Vec<(String, MetadataValue)>,
    supply: SupplyInvariantReport,
}

fn tracked_accounts() -> Vec<Account> {
    vec![
        acct(alice()),
        acct(bob()),
        acct_sub(carol(), 7),
        acct(dave()),
        acct(dexp()),
        acct(feecol()),
    ]
}

fn allowance_args() -> AllowanceArgs {
    AllowanceArgs { account: acct(alice()), spender: acct(dexp()) }
}

fn snapshot(pic: &PocketIc, cid: Principal) -> Snapshot {
    let mut raw = Vec::new();
    for (i, a) in tracked_accounts().iter().enumerate() {
        raw.push((
            format!("icrc1_balance_of[{i}]"),
            q_raw(pic, cid, "icrc1_balance_of", candid::encode_one(a).unwrap()),
        ));
    }
    raw.push(("icrc2_allowance".into(), q_raw(pic, cid, "icrc2_allowance", candid::encode_one(allowance_args()).unwrap())));
    for m in [
        "icrc1_total_supply",
        "icrc1_minting_account",
        "icrc1_fee",
        "icrc1_symbol",
        "icrc1_decimals",
        "icrc1_supported_standards",
        "icrc10_supported_standards",
        "get_genesis_allocations",
    ] {
        raw.push((m.to_string(), q_raw(pic, cid, m, noargs())));
    }
    Snapshot {
        raw,
        metadata: q(pic, cid, "icrc1_metadata", noargs()),
        supply: q(pic, cid, "verify_supply_invariant", noargs()),
    }
}

fn install_live(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    let init = TokenInitArgs {
        allocations: vec![
            AllocationCategory {
                category_id: "a".into(), category_name: "Alice".into(),
                amount: TOTAL_SUPPLY - 3_000_000 * STSH, recipient: alice(), subaccount: None,
                lock_policy: LockPolicy::ImmediatelyLiquid, vesting_policy: None,
                created_at_genesis: false, genesis_timestamp_ns: 0,
            },
            AllocationCategory {
                category_id: "b".into(), category_name: "Bob".into(),
                amount: 2_000_000 * STSH, recipient: bob(), subaccount: None,
                lock_policy: LockPolicy::ImmediatelyLiquid, vesting_policy: None,
                created_at_genesis: false, genesis_timestamp_ns: 0,
            },
            AllocationCategory {
                category_id: "c".into(), category_name: "Carol sub".into(),
                amount: 1_000_000 * STSH, recipient: carol(), subaccount: acct_sub(carol(), 7).subaccount,
                lock_policy: LockPolicy::ImmediatelyLiquid, vesting_policy: None,
                created_at_genesis: false, genesis_timestamp_ns: 0,
            },
        ],
        treasury: p(0x01),
        staking_canister: p(0x02),
        fee_collector: Some(feecol()),
    };
    pic.install_canister(cid, live_token_wasm(), candid::encode_one(&init).unwrap(), None);
    cid
}

fn expected_png_logo() -> String {
    format!(
        "data:image/png;base64,{}",
        b64_standard(include_bytes!("../../canisters/token/assets/stsh-logo.png"))
    )
}

#[test]
fn test_b64_standard_rfc4648_vectors() {
    for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"),
                   ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
        assert_eq!(b64_standard(i.as_bytes()), o);
    }
}

/// AC-2 / I-2 — upgrade FROM the live clv7x module (ac9336f2) with an EMPTY
/// arg preserves every ledger value; only icrc1:name and icrc1:logo change.
#[test]
fn test_token_metadata_upgrade_from_live_module_preserves_state() {
    let pic = PocketIc::new();
    let cid = install_live(&pic);

    // Behavioural guard: the fixture is genuinely the pre-change module.
    let pre_name: String = q(&pic, cid, "icrc1_name", noargs());
    assert_eq!(pre_name, "Stealth Cash", "fixture must be the pre-change live module");

    // Build state: transfers (incl. to a subaccount), an allowance with expiry,
    // and a dedup row (created_at_time set).
    assert!(transfer(&pic, cid, alice(), &xfer(acct(dave()), 12_345 * STSH)).is_ok());
    assert!(transfer(&pic, cid, bob(), &xfer(acct_sub(carol(), 7), 777 * STSH)).is_ok());
    let dedup = TransferArgs { created_at_time: Some(now_ns(&pic)), memo: Some(b"tm-dedup".to_vec()), ..xfer(acct(bob()), 42 * STSH) };
    let dedup_idx = transfer(&pic, cid, alice(), &dedup).expect("dedup-row transfer");
    let expires_at = now_ns(&pic) + 24 * 3600 * 1_000_000_000; // within MAX_APPROVAL_TTL_NS
    let appr: Result<Nat, ApproveError> = u(&pic, cid, alice(), "icrc2_approve", candid::encode_one(ApproveArgs {
        from_subaccount: None, spender: acct(dexp()), amount: Nat::from(5_000 * STSH),
        expected_allowance: None, expires_at: Some(expires_at), fee: None, memo: None, created_at_time: None,
    }).unwrap());
    appr.expect("approve");

    let pre = snapshot(&pic, cid);
    assert!(pre.supply.invariant_holds, "pre: supply invariant holds");
    match pre.metadata.iter().find(|(k, _)| k == "icrc1:logo") {
        Some((_, MetadataValue::Text(t))) => assert!(t.starts_with("data:image/svg+xml;base64,"), "fixture logo is the old SVG URL"),
        other => panic!("pre: icrc1:logo missing: {other:?}"),
    }

    // Upgrade with EMPTY arg bytes (= expected_arg_hash e3b0c442…).
    pic.upgrade_canister(cid, token_wasm(), vec![], None)
        .expect("upgrade from the live module with an empty arg");

    let post = snapshot(&pic, cid);

    // Every raw state reply byte-identical.
    assert_eq!(pre.raw.len(), post.raw.len());
    for ((kp, vp), (kq, vq)) in pre.raw.iter().zip(post.raw.iter()) {
        assert_eq!(kp, kq);
        assert_eq!(vp, vq, "{kp}: reply bytes changed across the upgrade");
    }
    // Supply report identical except the query timestamp.
    let mut s_pre = pre.supply.clone();
    s_pre.checked_at_ns = post.supply.checked_at_ns;
    assert_eq!(s_pre, post.supply, "supply invariant report changed");
    assert!(post.supply.invariant_holds);
    assert_eq!(post.supply.fixed_max_supply, TOTAL_SUPPLY);

    // Metadata: same keys, same order; exactly name + logo differ.
    let keys = |m: &Vec<(String, MetadataValue)>| m.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
    assert_eq!(keys(&pre.metadata), keys(&post.metadata), "metadata key set/order unchanged");
    let mut changed = Vec::new();
    for ((k, a), (_, b)) in pre.metadata.iter().zip(post.metadata.iter()) {
        if a != b { changed.push(k.clone()); }
    }
    assert_eq!(changed, vec!["icrc1:name".to_string(), "icrc1:logo".to_string()], "exactly two metadata keys differ");
    let get = |k: &str| post.metadata.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
    assert_eq!(get("icrc1:name"), Some(MetadataValue::Text("STSH".into())));
    assert_eq!(get("icrc1:logo"), Some(MetadataValue::Text(expected_png_logo())));
    let post_name: String = q(&pic, cid, "icrc1_name", noargs());
    assert_eq!(post_name, "STSH");

    // Read-backs for the packet (visible with --nocapture).
    let supply: Nat = q(&pic, cid, "icrc1_total_supply", noargs());
    let bob_bal: Nat = q(&pic, cid, "icrc1_balance_of", candid::encode_one(acct(bob())).unwrap());
    let logo = match get("icrc1:logo") { Some(MetadataValue::Text(t)) => t, _ => unreachable!() };
    println!("READBACK icrc1_name(post) = {post_name:?}");
    println!("READBACK icrc1:logo(post) prefix = {:?} (len {})", &logo[..40], logo.len());
    println!("READBACK icrc1_total_supply pre==post = {}", to_u128(&supply));
    println!("READBACK icrc1_balance_of(bob) pre==post = {}", to_u128(&bob_bal));

    // Liveness: dedup row survives, fresh transfer and allowance spend work.
    assert_eq!(
        transfer(&pic, cid, alice(), &dedup),
        Err(TransferError::Duplicate { duplicate_of: dedup_idx }),
        "dedup row survives the upgrade"
    );
    assert!(transfer(&pic, cid, alice(), &xfer(acct(dave()), STSH)).is_ok(), "fresh transfer post-upgrade");
    let tf: Result<Nat, TransferFromError> = u(&pic, cid, dexp(), "icrc2_transfer_from", candid::encode_one(TransferFromArgs {
        spender_subaccount: None, from: acct(alice()), to: acct(bob()), amount: Nat::from(1_000 * STSH),
        fee: None, memo: None, created_at_time: None,
    }).unwrap());
    tf.expect("allowance spendable post-upgrade");
    let allw: Allowance = q(&pic, cid, "icrc2_allowance", candid::encode_one(allowance_args()).unwrap());
    assert_eq!(to_u128(&allw.allowance), 4_000 * STSH);
    assert_eq!(allw.expires_at, Some(expires_at));
    let after: SupplyInvariantReport = q(&pic, cid, "verify_supply_invariant", noargs());
    assert!(after.invariant_holds);
}
