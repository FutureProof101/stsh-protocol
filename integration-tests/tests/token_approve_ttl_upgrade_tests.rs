// =============================================================================
// TOKEN-APPROVE-TTL — live-module fixture suite (brief AC-2 / AC-3 / AC-5)
//
// Installs the GENUINE live clv7x stsh_token module (994a77ff…, the
// TOKEN-METADATA `[wasm.stsh_token]` pin, byte-identical to the staged A-7
// artifact ~/a7-kit/stsh_token_metadata.wasm) and proves:
//
//   AC-3 (contrast). The ICPSwap-shaped client sequence — `icrc2_approve` with
//   NO `expires_at` and `fee = Some(0)`, then `icrc2_transfer_from` by the
//   spender with an 8-byte memo and no `created_at_time` (ICPSwap SwapPool
//   `depositFrom`; reviews/ICPSWAP_POOL_PREFLIGHT_2026-09-24.md §4) — FAILS on
//   the live module with the retired dev007 code 7 (the 2026-09-25 ICPSwap
//   failure, reproduced), and SUCCEEDS on the freshly built module.
//
//   AC-2. An in-place upgrade from the live module with an EMPTY arg (exactly
//   the bytes the operator page sends with no arg file → expected_arg_hash
//   e3b0c442…) preserves balances, an EXISTING real-expiry allowance (the only
//   shape the live module admits), supply, the dedup row, name and logo.
//
//   AC-5. READBACK lines (visible with --nocapture): `icrc2_allowance` after an
//   expiry-less approve reads `Some(now + 24 h)`; `icrc1_name` == "STSH";
//   supply pre == post. Plus the ICRC-21 consent text for an expiry-less
//   approve no longer says "never" (SSA R-1).
//
// Fixture mechanism = the TOKEN-METADATA / LAUNCH-HARDEN-04 pattern: a
// hash-checked loader beside TOKEN_WASM, with the placement recipe in the
// panic. Not wired into run_gate.sh / build.rs — the file must be placed before
// the gate (SSA R-4).
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const STSH: u128 = 100_000_000;
/// `MAX_APPROVAL_TTL_NS` — duplicated because PocketIC cannot link the constant.
const MAX_APPROVAL_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
/// The retired dev007 absent-expiry refusal code, as the live module raises it.
const RETIRED_ERR_CODE_APPROVAL_EXPIRY_REQUIRED: u32 = 7;

/// The LIVE clv7x token module before this lane — the TOKEN-METADATA
/// `[wasm.stsh_token]` pin (994a77ff…, 895,317 B, byte-identical to the staged
/// A-7 artifact ~/a7-kit/stsh_token_metadata.wasm).
const LIVE_TOKEN_SHA256: &str =
    "994a77ff3c34c8b941b18ce6e63c74e42c4963aa0ffcc31404501de31639800b";

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
        .with_file_name("stsh_token_live_clv7x_994a77ff.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} not found ({e}) — the TOKEN-APPROVE-TTL arms need the GENUINE live \
             clv7x token module (994a77ff — the TOKEN-METADATA [wasm.stsh_token] pin, \
             byte-identical to the staged A-7 artifact). Place it with:\n  \
             cp ~/a7-kit/stsh_token_metadata.wasm {}\n  expected sha256: {LIVE_TOKEN_SHA256}\n  \
             (alternative: a clean env -i gate build of TOKEN-METADATA head 5e8d54a)",
            path.display(),
            path.display()
        )
    });
    let got: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, LIVE_TOKEN_SHA256, "live token fixture has the WRONG hash");
    bytes
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

/// Carries `pool_canister` (SSA sanity-check (c)): the D-8 settlement pool is
/// set to `p(0x03)`, so the ICPSwap spender below (≠ `p(0x03)`) is deliberately
/// on the ORDINARY, non-D-8 `transfer_from` path — not vacuously so because no
/// pool was configured.
#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
    fee_collector: Option<Principal>,
    pool_canister: Option<Principal>,
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

// ICRC-21 (mirrors of the canister's own declarations).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21ConsentMessageMetadata {
    language: String,
    utc_offset_minutes: Option<i16>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21DeviceSpec {
    GenericDisplay,
    FieldsDisplay,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21ConsentMessageSpec {
    metadata: Icrc21ConsentMessageMetadata,
    device_spec: Option<Icrc21DeviceSpec>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21ConsentMessageRequest {
    method: String,
    arg: Vec<u8>,
    user_preferences: Icrc21ConsentMessageSpec,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21Value {
    TokenAmount { decimals: u8, amount: u64, symbol: String },
    TimestampSeconds { amount: u64 },
    DurationSeconds { amount: u64 },
    Text { content: String },
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21FieldsDisplay {
    intent: String,
    fields: Vec<(String, Icrc21Value)>,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21ConsentMessage {
    GenericDisplayMessage(String),
    FieldsDisplayMessage(Icrc21FieldsDisplay),
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21ConsentInfo {
    consent_message: Icrc21ConsentMessage,
    metadata: Icrc21ConsentMessageMetadata,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21ErrorInfo {
    description: String,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21Error {
    UnsupportedCanisterCall(Icrc21ErrorInfo),
    ConsentMessageUnavailable(Icrc21ErrorInfo),
    InsufficientPayment(Icrc21ErrorInfo),
    GenericError { error_code: Nat, description: String },
}

// ── Principals / accounts ────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
/// The liquidity provider / seller (the approving owner).
fn lp() -> Principal { p(0xA1) }
fn bob() -> Principal { p(0xB2) }
fn carol() -> Principal { p(0xC3) }
fn dave() -> Principal { p(0xD5) }
/// A pre-existing spender whose allowance the live module admitted (real expiry).
fn dexp() -> Principal { p(0xD4) }
/// The ICPSwap SwapPool stand-in — the ICRC-2 spender. NOT the D-8 pool.
fn icpswap_pool() -> Principal { p(0xE7) }
fn d8_pool() -> Principal { p(0x03) }
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

fn balance(pic: &PocketIc, cid: Principal, a: Account) -> u128 {
    let n: Nat = q(pic, cid, "icrc1_balance_of", candid::encode_one(a).unwrap());
    to_u128(&n)
}

fn allowance(pic: &PocketIc, cid: Principal, account: Account, spender: Account) -> Allowance {
    q(pic, cid, "icrc2_allowance", candid::encode_one(AllowanceArgs { account, spender }).unwrap())
}

// ── The ICPSwap-shaped client sequence ───────────────────────────────────────

/// ICPSwap's front end: `icrc2_approve` with NO `expires_at`, `fee = Some(0)`,
/// no `expected_allowance`, no memo, no `created_at_time`; the UI approves
/// amount x 1000 by default.
fn icpswap_approve_args(amount: u128) -> ApproveArgs {
    ApproveArgs {
        from_subaccount: None,
        spender: acct(icpswap_pool()),
        amount: Nat::from(amount),
        expected_allowance: None,
        expires_at: None,
        fee: Some(Nat::from(0u32)),
        memo: None,
        created_at_time: None,
    }
}

fn icpswap_approve(pic: &PocketIc, cid: Principal, amount: u128) -> Result<Nat, ApproveError> {
    u(pic, cid, lp(), "icrc2_approve", candid::encode_one(icpswap_approve_args(amount)).unwrap())
}

/// ICPSwap SwapPool `depositFrom`: the pool, as spender, pulls from the owner
/// into its own account — `fee = Some(0)`, an 8-byte memo, no `created_at_time`.
fn icpswap_deposit_from(pic: &PocketIc, cid: Principal, amount: u128) -> Result<Nat, TransferFromError> {
    u(pic, cid, icpswap_pool(), "icrc2_transfer_from", candid::encode_one(TransferFromArgs {
        spender_subaccount: None,
        from: acct(lp()),
        to: acct(icpswap_pool()),
        amount: Nat::from(amount),
        fee: Some(Nat::from(0u32)),
        memo: Some(vec![0x49, 0x43, 0x50, 0x53, 0x77, 0x61, 0x70, 0x01]),
        created_at_time: None,
    }).unwrap())
}

fn consent_text(pic: &PocketIc, cid: Principal, caller: Principal, args: &ApproveArgs) -> String {
    let req = Icrc21ConsentMessageRequest {
        method: "icrc2_approve".into(),
        arg: candid::encode_one(args).unwrap(),
        user_preferences: Icrc21ConsentMessageSpec {
            metadata: Icrc21ConsentMessageMetadata { language: "en".into(), utc_offset_minutes: None },
            device_spec: Some(Icrc21DeviceSpec::GenericDisplay),
        },
    };
    let r: Result<Icrc21ConsentInfo, Icrc21Error> =
        u(pic, cid, caller, "icrc21_canister_call_consent_message", candid::encode_one(req).unwrap());
    match r.expect("consent message").consent_message {
        Icrc21ConsentMessage::GenericDisplayMessage(m) => m,
        other => panic!("expected a GenericDisplayMessage, got {other:?}"),
    }
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Snapshot {
    raw: Vec<(String, Vec<u8>)>,
    metadata_raw: Vec<u8>,
    supply: SupplyInvariantReport,
}

fn tracked_accounts() -> Vec<Account> {
    vec![
        acct(lp()),
        acct(bob()),
        acct_sub(carol(), 7),
        acct(dave()),
        acct(dexp()),
        acct(icpswap_pool()),
        acct(feecol()),
    ]
}

fn snapshot(pic: &PocketIc, cid: Principal) -> Snapshot {
    let mut raw = Vec::new();
    for (i, a) in tracked_accounts().iter().enumerate() {
        raw.push((
            format!("icrc1_balance_of[{i}]"),
            q_raw(pic, cid, "icrc1_balance_of", candid::encode_one(a).unwrap()),
        ));
    }
    for (name, spender) in [("dexp", dexp()), ("icpswap_pool", icpswap_pool())] {
        raw.push((
            format!("icrc2_allowance[{name}]"),
            q_raw(pic, cid, "icrc2_allowance", candid::encode_one(AllowanceArgs {
                account: acct(lp()), spender: acct(spender),
            }).unwrap()),
        ));
    }
    for m in [
        "icrc1_name",
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
        metadata_raw: q_raw(pic, cid, "icrc1_metadata", noargs()),
        supply: q(pic, cid, "verify_supply_invariant", noargs()),
    }
}

fn install_live(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    let init = TokenInitArgs {
        allocations: vec![
            AllocationCategory {
                category_id: "a".into(), category_name: "LP".into(),
                amount: TOTAL_SUPPLY - 3_000_000 * STSH, recipient: lp(), subaccount: None,
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
        pool_canister: Some(d8_pool()),
    };
    pic.install_canister(cid, live_token_wasm(), candid::encode_one(&init).unwrap(), None);
    cid
}

/// AC-3 contrast + AC-2 upgrade + AC-3 success + AC-5 read-backs, on ONE canister:
/// live 994a77ff refuses the ICPSwap sequence; an empty-arg in-place upgrade to
/// the new module preserves all state; the new module accepts the same sequence.
#[test]
fn test_token_approve_ttl_icpswap_sequence_live_fails_new_succeeds_across_upgrade() {
    let pic = PocketIc::new();
    let cid = install_live(&pic);

    // Behavioural guard: the fixture is the post-TOKEN-METADATA live module.
    let pre_name: String = q(&pic, cid, "icrc1_name", noargs());
    assert_eq!(pre_name, "STSH", "fixture must be the live 994a77ff module (post-METADATA)");

    let deposit = 1_000 * STSH;

    // ── AC-3, live side: the ICPSwap sequence FAILS ──────────────────────────
    let lp_before = balance(&pic, cid, acct(lp()));
    match icpswap_approve(&pic, cid, deposit * 1_000) {
        Err(ApproveError::GenericError { error_code, message }) => {
            assert_eq!(
                error_code,
                Nat::from(RETIRED_ERR_CODE_APPROVAL_EXPIRY_REQUIRED),
                "live module refuses an expiry-less approve with dev007 code 7"
            );
            assert!(message.contains("expires_at is required"), "got {message}");
            println!("READBACK live 994a77ff icrc2_approve(expires_at=None) = GenericError {{ error_code: 7, message: {message:?} }}");
        }
        other => panic!("live module must refuse the ICPSwap approve with code 7, got {other:?}"),
    }
    assert_eq!(
        icpswap_deposit_from(&pic, cid, deposit),
        Err(TransferFromError::InsufficientAllowance { allowance: Nat::from(0u32) }),
        "live: with the approve refused, depositFrom has no allowance to spend"
    );
    assert_eq!(balance(&pic, cid, acct(lp())), lp_before, "live: nothing moved");
    assert_eq!(balance(&pic, cid, acct(icpswap_pool())), 0);
    // The live consent text for this call says "never" — the text SSA R-1 retires.
    let live_consent = consent_text(&pic, cid, lp(), &icpswap_approve_args(deposit * 1_000));
    assert!(live_consent.contains("never"), "live consent text (contrast): {live_consent}");

    // ── AC-2: build state on the live module ─────────────────────────────────
    assert!(transfer(&pic, cid, lp(), &xfer(acct(dave()), 12_345 * STSH)).is_ok());
    assert!(transfer(&pic, cid, bob(), &xfer(acct_sub(carol(), 7), 777 * STSH)).is_ok());
    let dedup = TransferArgs {
        created_at_time: Some(now_ns(&pic)),
        memo: Some(b"ttl-dedup".to_vec()),
        ..xfer(acct(bob()), 42 * STSH)
    };
    let dedup_idx = transfer(&pic, cid, lp(), &dedup).expect("dedup-row transfer");
    // An EXISTING capped allowance — the only shape the live module admits.
    let existing_exp = now_ns(&pic) + MAX_APPROVAL_TTL_NS - 3_600 * 1_000_000_000;
    let appr: Result<Nat, ApproveError> = u(&pic, cid, lp(), "icrc2_approve", candid::encode_one(ApproveArgs {
        from_subaccount: None, spender: acct(dexp()), amount: Nat::from(5_000 * STSH),
        expected_allowance: None, expires_at: Some(existing_exp), fee: None, memo: None, created_at_time: None,
    }).unwrap());
    appr.expect("live: approve with a real in-cap expiry");

    let pre = snapshot(&pic, cid);
    assert!(pre.supply.invariant_holds, "pre: supply invariant holds");

    // Upgrade in place with EMPTY arg bytes (= expected_arg_hash e3b0c442…).
    pic.upgrade_canister(cid, token_wasm(), vec![], None)
        .expect("upgrade from the live 994a77ff module with an empty arg");

    let post = snapshot(&pic, cid);
    assert_eq!(pre.raw.len(), post.raw.len());
    for ((kp, vp), (kq, vq)) in pre.raw.iter().zip(post.raw.iter()) {
        assert_eq!(kp, kq);
        assert_eq!(vp, vq, "{kp}: reply bytes changed across the upgrade");
    }
    assert_eq!(pre.metadata_raw, post.metadata_raw, "icrc1_metadata (name, logo, …) byte-identical");
    let mut s_pre = pre.supply.clone();
    s_pre.checked_at_ns = post.supply.checked_at_ns;
    assert_eq!(s_pre, post.supply, "supply invariant report changed");
    assert!(post.supply.invariant_holds);
    assert_eq!(post.supply.fixed_max_supply, TOTAL_SUPPLY);
    assert_eq!(
        allowance(&pic, cid, acct(lp()), acct(dexp())),
        Allowance { allowance: Nat::from(5_000 * STSH), expires_at: Some(existing_exp) },
        "the pre-existing real-expiry allowance survives with its expiry unchanged"
    );
    assert_eq!(
        transfer(&pic, cid, lp(), &dedup),
        Err(TransferError::Duplicate { duplicate_of: dedup_idx }),
        "dedup row survives the upgrade"
    );
    let tf: Result<Nat, TransferFromError> = u(&pic, cid, dexp(), "icrc2_transfer_from", candid::encode_one(TransferFromArgs {
        spender_subaccount: None, from: acct(lp()), to: acct(bob()), amount: Nat::from(1_000 * STSH),
        fee: None, memo: None, created_at_time: None,
    }).unwrap());
    tf.expect("the pre-existing allowance is spendable post-upgrade");
    assert_eq!(
        allowance(&pic, cid, acct(lp()), acct(dexp())),
        Allowance { allowance: Nat::from(4_000 * STSH), expires_at: Some(existing_exp) }
    );

    // ── AC-3, new module: the SAME ICPSwap sequence SUCCEEDS ─────────────────
    let consent = consent_text(&pic, cid, lp(), &icpswap_approve_args(deposit * 1_000));
    assert!(!consent.contains("never"), "SSA R-1: consent must not say 'never': {consent}");
    assert!(
        consent.contains("**Expires:** 24 hours after the approval executes (ledger maximum)"),
        "SSA R-1: consent states the 24 h ledger maximum: {consent}"
    );

    let lp_before = balance(&pic, cid, acct(lp()));
    let t_before = now_ns(&pic);
    icpswap_approve(&pic, cid, deposit * 1_000)
        .expect("new module: the ICPSwap expiry-less approve is accepted");
    let t_after = now_ns(&pic);
    let a = allowance(&pic, cid, acct(lp()), acct(icpswap_pool()));
    assert_eq!(to_u128(&a.allowance), deposit * 1_000);
    let e = a.expires_at.expect("new module: the expiry-less approve is stored with an expiry");
    assert!(
        t_before + MAX_APPROVAL_TTL_NS <= e && e <= t_after + MAX_APPROVAL_TTL_NS,
        "icrc2_allowance reports now + 24 h: {e} not in [{}, {}]",
        t_before + MAX_APPROVAL_TTL_NS,
        t_after + MAX_APPROVAL_TTL_NS
    );

    icpswap_deposit_from(&pic, cid, deposit)
        .expect("new module: ICPSwap depositFrom (transfer_from) succeeds");
    assert_eq!(balance(&pic, cid, acct(lp())), lp_before - deposit, "fee 0: LP debited exactly the amount");
    assert_eq!(balance(&pic, cid, acct(icpswap_pool())), deposit, "pool credited");
    assert_eq!(
        allowance(&pic, cid, acct(lp()), acct(icpswap_pool())),
        Allowance { allowance: Nat::from(deposit * 999), expires_at: Some(e) },
        "allowance reduced by the amount, expiry unchanged by transfer_from"
    );
    let after: SupplyInvariantReport = q(&pic, cid, "verify_supply_invariant", noargs());
    assert!(after.invariant_holds);

    // ── AC-5 read-backs ──────────────────────────────────────────────────────
    let name: String = q(&pic, cid, "icrc1_name", noargs());
    assert_eq!(name, "STSH");
    let supply: Nat = q(&pic, cid, "icrc1_total_supply", noargs());
    assert_eq!(to_u128(&supply), TOTAL_SUPPLY);
    let logo = match candid::decode_one::<Vec<(String, MetadataValue)>>(&post.metadata_raw)
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == "icrc1:logo")
    {
        Some((_, MetadataValue::Text(t))) => t,
        other => panic!("icrc1:logo missing: {other:?}"),
    };
    assert!(logo.starts_with("data:image/png;base64,"));
    println!(
        "READBACK new icrc2_allowance(after expiry-less approve) = {{ allowance: {}, expires_at: Some({e}) }} \
         — approve executed in [{t_before}, {t_after}], so expires_at - now = 24 h (+{} ns round advance)",
        deposit * 1_000,
        e - (t_before + MAX_APPROVAL_TTL_NS)
    );
    println!("READBACK icrc1_name(post) = {name:?}");
    println!("READBACK icrc1:logo(post) prefix = {:?}", &logo[..40]);
    println!("READBACK icrc1_total_supply pre==post = {}", to_u128(&supply));
    println!("READBACK consent(expires_at=None) expiry line = {:?}",
        consent.lines().find(|l| l.contains("**Expires:**")).unwrap_or(""));
}

/// The clamp and the revoke consent line, on the new module (post-upgrade from
/// live): an over-cap expiry is clamped and consent says so; a zero approve's
/// consent says no expiry applies (it removes the approval).
#[test]
fn test_token_approve_ttl_clamp_and_consent_on_upgraded_module() {
    let pic = PocketIc::new();
    let cid = install_live(&pic);
    // Let the install_code rate limiter drain (install and upgrade back to back
    // trip CanisterInstallCodeRateLimited on PocketIC).
    pic.advance_time(std::time::Duration::from_secs(600));
    pic.tick();
    pic.upgrade_canister(cid, token_wasm(), vec![], None).expect("upgrade");

    let far = now_ns(&pic) + 7 * MAX_APPROVAL_TTL_NS;
    let args = ApproveArgs { expires_at: Some(far), ..icpswap_approve_args(STSH) };
    let consent = consent_text(&pic, cid, lp(), &args);
    assert!(
        consent.contains("or 24 hours after the approval executes if that is sooner (ledger maximum)"),
        "over-cap consent states the clamp: {consent}"
    );
    let t_before = now_ns(&pic);
    let r: Result<Nat, ApproveError> = u(&pic, cid, lp(), "icrc2_approve", candid::encode_one(&args).unwrap());
    r.expect("over-cap approve is accepted and clamped");
    let t_after = now_ns(&pic);
    let e = allowance(&pic, cid, acct(lp()), acct(icpswap_pool())).expires_at.expect("clamped");
    assert!(t_before + MAX_APPROVAL_TTL_NS <= e && e <= t_after + MAX_APPROVAL_TTL_NS && e < far);

    // In-cap consent is unchanged in shape: the requested instant, no cap clause.
    let near = now_ns(&pic) + 15 * 60 * 1_000_000_000;
    let c = consent_text(&pic, cid, lp(), &ApproveArgs { expires_at: Some(near), ..icpswap_approve_args(STSH) });
    assert!(c.contains(&format!("**Expires:** {} (seconds since Unix epoch)", near / 1_000_000_000)), "{c}");
    assert!(!c.contains("ledger maximum"), "{c}");

    // A revoke's consent: no expiry applies.
    let c = consent_text(&pic, cid, lp(), &icpswap_approve_args(0));
    assert!(c.contains("**Expires:** not applicable"), "{c}");
    assert!(!c.contains("never"), "{c}");
}
