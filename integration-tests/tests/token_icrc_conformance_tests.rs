// =============================================================================
// STSH — ICRC-1/2 compatibility audit conformance suite (PocketIC)
// BRIEF_ICRC_COMPATIBILITY_AUDIT.md — Lane 10 harness, executing the Lane 1/2/3/9
// behavioural matrices (§4.3, §5.3, §6.3, §12) against the STSH token canister
// and, for the differential sections, the DFINITY reference ICRC-1 ledger.
// =============================================================================
//
// TEST PHILOSOPHY: every test asserts the ACTUAL current behaviour of the STSH
// canister, so the suite is green and acts as a regression harness. Where the
// actual behaviour deviates from the ICRC-1/2 spec or from the reference
// ledger, the test name carries a `finding`/`dev` tag and the assertion is
// accompanied by a FINDING/DEV comment. The audit lane reports (maintained in
// the internal workspace, outside the repo) classify each tagged test as Pass /
// Deviation with severity. If a deviation is later FIXED, the tagged test will
// fail — that is the signal to flip the assertion to the spec shape and close
// the finding.
//
// REFERENCE LEDGER (Lane 3 differential):
//   Release:  ledger-suite-icrc-2026-03-09 (dfinity/ic release artifact)
//   Artifact: ic-icrc1-ledger.wasm.gz
//   sha256:   354dd6ecfdc72b5409805b31dea22c9db11df6e14095a5a68924eb63535e6d8a
//   The wasm is NOT committed to the repo. Tests read it from
//   $ICRC_REF_LEDGER_WASM (default target/icrc-ref/ic-icrc1-ledger.wasm.gz).
//   PocketIC accepts the gzipped bytes directly (IC install supports gzip).
//
// PREREQUISITES:
//   1. cargo build --target wasm32-unknown-unknown --release -p stsh_token
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. export ICRC_REF_LEDGER_WASM=target/icrc-ref/ic-icrc1-ledger.wasm.gz
//   4. cargo test -p integration-tests --test token_icrc_conformance_tests \
//        -- --test-threads=1
//
// FEE NOTE (F-000, PM decision LOCKED 2026-07-09): token transfers are FREE at
// launch — DEFAULT_FEE = 0 (protocol revenue is pool shield/unshield fees,
// Phase 2). Every test keys off LIVE_FEE, asserted against icrc1_fee() at
// setup, so a future fee change is surfaced loudly. The reference ledger is
// deployed with the same fee for differential parity.
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

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

/// Reference ICRC-1 ledger (gzipped release artifact — see file header).
fn ref_ledger_wasm() -> Vec<u8> {
    let path = std::env::var("ICRC_REF_LEDGER_WASM")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../target/icrc-ref/ic-icrc1-ledger.wasm.gz").to_string());
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Cannot read reference ledger Wasm at {}: {}.\nDownload the pinned release:\n  \
             curl -sL -o ic-icrc1-ledger.wasm.gz https://github.com/dfinity/ic/releases/download/ledger-suite-icrc-2026-03-09/ic-icrc1-ledger.wasm.gz\n\
             expected sha256 354dd6ecfdc72b5409805b31dea22c9db11df6e14095a5a68924eb63535e6d8a",
            path, e
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants — must match canisters/token/src/lib.rs exactly
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH, 8 decimals
const STSH: u128 = 100_000_000; // 1 STSH in base units
const LIVE_FEE: u128 = 0; // DEFAULT_FEE in lib.rs (F-000: free transfers) — asserted at setup
const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000; // 24h
const PERMITTED_DRIFT_NS: u64 = 5 * 60 * 1_000_000_000; // 5 min (STSH; ref uses 2 min)

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — field/variant names must match the wire types exactly
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

/// Variant of Account whose subaccount length is NOT fixed at 32 — used to
/// prove that wrong-length subaccounts are rejected at Candid decode (A-04/05).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AccountRaw {
    owner: Principal,
    subaccount: Option<Vec<u8>>,
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

/// The ICRC-2 SPEC TransferFromError shape (what a standard client's idlFactory
/// declares). Both the reference ledger and — since the F-002 fix — STSH
/// return exactly this shape.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SpecTransferFromError {
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Allowance {
    allowance: Nat,
    expires_at: Option<u64>,
}

/// ICRC-1 spec shape for icrc1_supported_standards entries:
///   vec record { name : text; url : text }
/// STSH returns vec record { text; text } (tuple record) — FINDING-001.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct StandardRecord {
    name: String,
    url: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum MetadataValue {
    Nat(Nat),
    Int(candid::Int),
    Text(String),
    Blob(Vec<u8>),
}

// ── STSH init ────────────────────────────────────────────────────────────────

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
    /// DEF-080 neutral fee collector — fees credited to this account's BALANCES
    /// entry, keeping sum(balances) == TOTAL_SUPPLY throughout the suite.
    fee_collector: Option<Principal>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SupplyInvariantReport {
    fixed_max_supply: u128,
    sum_all_balances: u128,
    staking_locked_total: u128,
    fee_reserve_total: u128,
    invariant_holds: bool,
    checked_at_ns: u64,
    violation_detail: Option<String>,
    // K3-002b (P-ARITH): additive per-site overflow attribution.
    arithmetic_error: Option<ArithmeticErrorReport>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ArithmeticErrorReport {
    balances_overflow: bool,
    staking_locks_overflow: bool,
    balances_plus_fee_overflow: bool,
}

// ── Reference ledger init (ledger.did from the pinned release) ───────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct RefFeatureFlags {
    icrc2: bool,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct RefArchiveOptions {
    num_blocks_to_archive: u64,
    max_transactions_per_response: Option<u64>,
    trigger_threshold: u64,
    max_message_size_bytes: Option<u64>,
    cycles_for_archive_creation: Option<u64>,
    node_max_memory_size_bytes: Option<u64>,
    controller_id: Principal,
    more_controller_ids: Option<Vec<Principal>>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct RefInitArgs {
    minting_account: Account,
    fee_collector_account: Option<Account>,
    transfer_fee: Nat,
    decimals: Option<u8>,
    max_memo_length: Option<u16>,
    token_symbol: String,
    token_name: String,
    metadata: Vec<(String, MetadataValue)>,
    initial_balances: Vec<(Account, Nat)>,
    feature_flags: Option<RefFeatureFlags>,
    archive_options: RefArchiveOptions,
    index_principal: Option<Principal>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum RefLedgerArg {
    Init(RefInitArgs),
    Upgrade(Option<u8>), // payload unused — we never upgrade the reference
}

// ─────────────────────────────────────────────────────────────────────────────
// Principals + helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal {
    Principal::anonymous()
}

fn alice() -> Principal { p(0xA1) }
fn bob() -> Principal { p(0xB2) }
fn carol() -> Principal { p(0xC3) }
fn dexp() -> Principal { p(0xD4) } // acts as the DEX/spender principal
fn feecol() -> Principal { p(0xF1) } // DEF-080 neutral fee collector
fn minter() -> Principal { p(0x7F) } // reference-ledger minting account owner

fn acct(owner: Principal) -> Account {
    Account { owner, subaccount: None }
}

fn acct_sub(owner: Principal, tag: u8) -> Account {
    let mut s = [0u8; 32];
    s[31] = tag;
    Account { owner, subaccount: Some(s) }
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 4_000_000_000_000u128);
    cid
}

/// Deploy STSH token: full supply to alice, fee collector = feecol().
fn deploy_stsh(pic: &PocketIc) -> Principal {
    let cid = create_canister(pic);
    let init = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: alice(),
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(0x02),
        fee_collector: Some(feecol()),
    };
    pic.install_canister(cid, token_wasm(), candid::encode_one(&init).unwrap(), None);
    // Guard: the whole suite computes against the live fee. If the fee model
    // ever changes, fail loudly here rather than silently skewing every test.
    assert_eq!(live_fee(pic, cid), LIVE_FEE, "live fee != LIVE_FEE (F-000: 0) — update suite");
    cid
}

/// Deploy the reference ledger with STATE PARITY to deploy_stsh():
/// same supply to alice, same fee, same decimals, fee collector account (so
/// fees are transferred, not burned — matching STSH's fee-to-collector model).
fn deploy_ref(pic: &PocketIc) -> Principal {
    let cid = create_canister(pic);
    let init = RefLedgerArg::Init(RefInitArgs {
        minting_account: acct(minter()),
        fee_collector_account: Some(acct(feecol())),
        transfer_fee: Nat::from(LIVE_FEE),
        decimals: Some(8),
        max_memo_length: None, // ledger default (32) — memo-length differential documents this
        token_symbol: "STSH".to_string(),
        token_name: "STSH".to_string(),
        metadata: vec![],
        initial_balances: vec![(acct(alice()), Nat::from(TOTAL_SUPPLY))],
        feature_flags: Some(RefFeatureFlags { icrc2: true }),
        archive_options: RefArchiveOptions {
            num_blocks_to_archive: 2_000,
            max_transactions_per_response: None,
            trigger_threshold: 1_000_000, // never triggers in-suite
            max_message_size_bytes: None,
            cycles_for_archive_creation: None,
            node_max_memory_size_bytes: None,
            controller_id: minter(),
            more_controller_ids: None,
        },
        index_principal: None,
    });
    pic.install_canister(cid, ref_ledger_wasm(), candid::encode_one(&init).unwrap(), None);
    cid
}

fn setup() -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let stsh = deploy_stsh(&pic);
    (pic, stsh)
}

fn setup_diff() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let stsh = deploy_stsh(&pic);
    let refl = deploy_ref(&pic);
    (pic, stsh, refl)
}

// ── Call plumbing ────────────────────────────────────────────────────────────

/// Raw update call — Err carries the formatted reject (trap/decode-failure text).
fn raw_update(
    pic: &PocketIc, cid: Principal, caller: Principal, method: &str, args: Vec<u8>,
) -> Result<Vec<u8>, String> {
    pic.update_call(cid, caller, method, args).map_err(|e| format!("{:?}", e))
}

fn raw_query(
    pic: &PocketIc, cid: Principal, caller: Principal, method: &str, args: Vec<u8>,
) -> Result<Vec<u8>, String> {
    pic.query_call(cid, caller, method, args).map_err(|e| format!("{:?}", e))
}

fn decode<T>(label: &str, bytes: Vec<u8>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
{
    candid::decode_one(&bytes)
        .unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn q<T>(pic: &PocketIc, cid: Principal, method: &str, args: Vec<u8>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
{
    decode(method, raw_query(pic, cid, anon(), method, args).unwrap_or_else(|e| {
        panic!("{}: query rejected: {}", method, e)
    }))
}

fn to_u128(n: &Nat) -> u128 {
    n.0.to_string().parse::<u128>().expect("Nat exceeds u128")
}

fn live_fee(pic: &PocketIc, cid: Principal) -> u128 {
    to_u128(&q::<Nat>(pic, cid, "icrc1_fee", candid::encode_args(()).unwrap()))
}

fn balance_of(pic: &PocketIc, cid: Principal, account: &Account) -> u128 {
    to_u128(&q::<Nat>(pic, cid, "icrc1_balance_of", candid::encode_one(account).unwrap()))
}

fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() as u64
}

fn xfer_args(to: Account, amount: u128) -> TransferArgs {
    TransferArgs {
        from_subaccount: None,
        to,
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    }
}

fn transfer(
    pic: &PocketIc, cid: Principal, caller: Principal, args: &TransferArgs,
) -> Result<Nat, TransferError> {
    decode(
        "icrc1_transfer",
        raw_update(pic, cid, caller, "icrc1_transfer", candid::encode_one(args).unwrap())
            .unwrap_or_else(|e| panic!("icrc1_transfer rejected: {}", e)),
    )
}

/// Transfer where the CALL itself may be rejected (trap) — returns the reject
/// text in the outer Err. Used for differential cases where the reference
/// ledger traps (e.g. oversized memo).
fn transfer_outcome(
    pic: &PocketIc, cid: Principal, caller: Principal, args: &TransferArgs,
) -> Result<Result<Nat, TransferError>, String> {
    raw_update(pic, cid, caller, "icrc1_transfer", candid::encode_one(args).unwrap())
        .map(|bytes| decode("icrc1_transfer", bytes))
}

fn approve(
    pic: &PocketIc, cid: Principal, caller: Principal, args: &ApproveArgs,
) -> Result<Nat, ApproveError> {
    decode(
        "icrc2_approve",
        raw_update(pic, cid, caller, "icrc2_approve", candid::encode_one(args).unwrap())
            .unwrap_or_else(|e| panic!("icrc2_approve rejected: {}", e)),
    )
}

fn approve_outcome(
    pic: &PocketIc, cid: Principal, caller: Principal, args: &ApproveArgs,
) -> Result<Result<Nat, ApproveError>, String> {
    raw_update(pic, cid, caller, "icrc2_approve", candid::encode_one(args).unwrap())
        .map(|bytes| decode("icrc2_approve", bytes))
}

/// H-01 / dev007: `expires_at` is MANDATORY on `icrc2_approve` for any approve
/// that WRITES a row, so this factory supplies a bounded default and every case
/// below keeps testing what it was written to test rather than all failing on the
/// admission rule. Cases that care about the expiry overwrite the field
/// explicitly, as they already did.
///
/// A ZERO-amount approve deliberately keeps `expires_at: None`. A zero approve is
/// revocation — it writes no row — so (f1) exempts it (I-A1), and the dev006 cases
/// depend on that: with an expiry supplied, a zero approve against nothing live
/// would still be refused, but a `None` here is what keeps the exemption itself
/// under test.
///
/// The same default is applied to the REFERENCE ledger's approves, where the field
/// is spec-optional and accepted, so the differential comparisons stay symmetric:
/// both ledgers see the same argument.
const CONFORMANCE_APPROVAL_TTL_NS: u64 = 60 * 60 * 1_000_000_000; // 1 h, well inside the 24 h cap

fn approve_args(pic: &PocketIc, spender: Account, amount: u128) -> ApproveArgs {
    ApproveArgs {
        from_subaccount: None,
        spender,
        amount: Nat::from(amount),
        expected_allowance: None,
        expires_at: if amount == 0 {
            None
        } else {
            Some(now_ns(pic) + CONFORMANCE_APPROVAL_TTL_NS)
        },
        fee: None,
        memo: None,
        created_at_time: None,
    }
}

/// icrc2_transfer_from decode. Since the F-002 fix STSH natively returns the
/// ICRC-2 spec TransferFromError shape, so the STSH helper and the spec helper
/// are the same decode — kept as an alias so pre-fix test names still read.
fn transfer_from_stsh(
    pic: &PocketIc, cid: Principal, caller: Principal, args: &TransferFromArgs,
) -> Result<Nat, SpecTransferFromError> {
    transfer_from_spec(pic, cid, caller, args)
}

/// Spec-shape decode (what a standard ICRC-2 client sees) — used for both
/// ledgers.
fn transfer_from_spec(
    pic: &PocketIc, cid: Principal, caller: Principal, args: &TransferFromArgs,
) -> Result<Nat, SpecTransferFromError> {
    decode(
        "icrc2_transfer_from",
        raw_update(pic, cid, caller, "icrc2_transfer_from", candid::encode_one(args).unwrap())
            .unwrap_or_else(|e| panic!("icrc2_transfer_from rejected: {}", e)),
    )
}

fn tf_args(from: Account, to: Account, amount: u128) -> TransferFromArgs {
    TransferFromArgs {
        spender_subaccount: None,
        from,
        to,
        amount: Nat::from(amount),
        fee: None,
        memo: None,
        created_at_time: None,
    }
}

fn allowance_of(pic: &PocketIc, cid: Principal, account: Account, spender: Account) -> Allowance {
    q(pic, cid, "icrc2_allowance", candid::encode_one(AllowanceArgs { account, spender }).unwrap())
}

fn supply_report(pic: &PocketIc, cid: Principal) -> SupplyInvariantReport {
    q(pic, cid, "verify_supply_invariant", candid::encode_args(()).unwrap())
}

fn assert_invariant(pic: &PocketIc, cid: Principal, ctx: &str) {
    let r = supply_report(pic, cid);
    assert!(
        r.invariant_holds,
        "{}: supply invariant broken: {:?}", ctx, r.violation_detail
    );
    assert!(
        r.arithmetic_error.is_none(),
        "{}: arithmetic_error must be null on a healthy ledger: {:?}",
        ctx, r.arithmetic_error
    );
    assert_eq!(
        r.sum_all_balances + r.fee_reserve_total, TOTAL_SUPPLY,
        "{}: sum(balances)+fee_reserve != TOTAL_SUPPLY", ctx
    );
}

// =============================================================================
// §4.3.1 — Metadata queries (M-01 .. M-10)
// =============================================================================

#[test]
fn test_icrc1_m01_07_metadata_matches_direct_queries() {
    let (pic, stsh) = setup();

    let name: String = q(&pic, stsh, "icrc1_name", candid::encode_args(()).unwrap());
    let symbol: String = q(&pic, stsh, "icrc1_symbol", candid::encode_args(()).unwrap());
    let decimals: u8 = q(&pic, stsh, "icrc1_decimals", candid::encode_args(()).unwrap());
    let fee = live_fee(&pic, stsh);
    let supply: Nat = q(&pic, stsh, "icrc1_total_supply", candid::encode_args(()).unwrap());

    assert!(!name.is_empty(), "M-01: name non-empty");
    assert_eq!(name, "STSH", "M-01: ledger name (TOKEN-METADATA, renamed)");
    assert!(!symbol.is_empty(), "M-02: symbol non-empty");
    assert_eq!(symbol, "STSH");
    assert_eq!(decimals, 8, "M-03");
    assert_eq!(to_u128(&supply), TOTAL_SUPPLY, "M-05: total supply");

    let metadata: Vec<(String, MetadataValue)> =
        q(&pic, stsh, "icrc1_metadata", candid::encode_args(()).unwrap());

    // M-08: all keys follow <namespace>:<key>
    for (k, _) in &metadata {
        assert!(k.contains(':'), "M-08: malformed metadata key {}", k);
    }

    let get = |key: &str| -> Option<&MetadataValue> {
        metadata.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    };

    // M-07: required keys present, correct Value variants, values match queries
    match get("icrc1:name") {
        Some(MetadataValue::Text(t)) => assert_eq!(t, &name, "metadata name matches"),
        other => panic!("icrc1:name missing or wrong variant: {:?}", other),
    }
    match get("icrc1:symbol") {
        Some(MetadataValue::Text(t)) => assert_eq!(t, &symbol),
        other => panic!("icrc1:symbol missing or wrong variant: {:?}", other),
    }
    // CRITICAL check from §7.4: decimals must be the Nat variant, not Int
    match get("icrc1:decimals") {
        Some(MetadataValue::Nat(n)) => assert_eq!(to_u128(n), decimals as u128),
        other => panic!("icrc1:decimals missing or NOT the Nat variant: {:?}", other),
    }
    match get("icrc1:fee") {
        Some(MetadataValue::Nat(n)) => assert_eq!(to_u128(n), fee),
        other => panic!("icrc1:fee missing or wrong variant: {:?}", other),
    }
}

/// Minimal RFC 4648 standard base64 (with padding). integration-tests has no
/// `base64` dependency and its Cargo.toml is out of the TOKEN-METADATA scope.
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

#[test]
fn test_b64_standard_rfc4648_vectors() {
    for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"),
                   ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
        assert_eq!(b64_standard(i.as_bytes()), o);
    }
}

#[test]
fn test_icrc1_m09_logo_absent_dev003() {
    let (pic, stsh) = setup();
    let metadata: Vec<(String, MetadataValue)> =
        q(&pic, stsh, "icrc1_metadata", candid::encode_args(()).unwrap());
    // DEV-003 FIXED (regression guard): icrc1:logo present as a Text data URL
    // (base64 of the committed PNG asset, canisters/token/assets/stsh-logo.png —
    // TOKEN-METADATA lane; was an SVG data URL). Exact equality, not a prefix.
    let expected = format!(
        "data:image/png;base64,{}",
        b64_standard(include_bytes!("../../canisters/token/assets/stsh-logo.png"))
    );
    match metadata.iter().find(|(k, _)| k == "icrc1:logo") {
        Some((_, MetadataValue::Text(url))) => {
            assert!(
                url.starts_with("data:image/png;base64,"),
                "logo is a png data URL: {}...", &url[..40.min(url.len())]
            );
            assert!(url.len() > 100, "logo payload non-trivial");
            assert_eq!(url, &expected, "logo is exactly the committed PNG asset");
        }
        other => panic!("DEV-003 regressed? icrc1:logo missing/wrong variant: {:?}", other),
    }
    // DEV-004 (Low, accepted): icrc1:max_memo_length still not advertised.
    assert!(!metadata.iter().any(|(k, _)| k == "icrc1:max_memo_length"));
}

#[test]
fn test_icrc1_m06_minting_account_null() {
    let (pic, stsh) = setup();
    let minting: Option<Account> =
        q(&pic, stsh, "icrc1_minting_account", candid::encode_args(()).unwrap());
    // DEV-001 (by design): fixed supply, no minting account.
    assert!(minting.is_none(), "M-06: minting account must be null");
}

#[test]
fn test_icrc1_m10_supported_standards_content_and_shape_finding001() {
    let (pic, stsh) = setup();
    let bytes = raw_query(
        &pic, stsh, anon(), "icrc1_supported_standards", candid::encode_args(()).unwrap(),
    ).expect("supported_standards query");

    // F-001 FIXED (regression guard): the spec-shaped NAMED record decodes.
    let records: Vec<StandardRecord> =
        candid::decode_one(&bytes).expect("FINDING-001 regressed? named-record decode failed");
    let names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"ICRC-1"), "must advertise ICRC-1");
    assert!(names.contains(&"ICRC-2"), "must advertise ICRC-2");
    assert!(names.contains(&"ICRC-10"), "advertises ICRC-10 (discovery method exposed)");
    assert!(names.contains(&"ICRC-21"), "advertises ICRC-21");
    // Non-Negotiable #7: ICRC-3 must NOT be advertised (not implemented).
    assert!(!names.contains(&"ICRC-3"), "ICRC-3 must not be advertised");

    // EXT-DBR-001: exact canonical URLs, verified against the spec texts.
    // ICRC-1 → the repository ROOT its own icrc1_supported_standards example
    // advertises (normative realignment, adversarial-lane EXT-DBR-001); ICRC-2 →
    // the accurate subpath (its URL is not spec-mandated); ICRC-10 → the spec's
    // MUST-clause self-reference; ICRC-21 → the entry its own .did mandates.
    let url_of = |n: &str| {
        records.iter().find(|r| r.name == n)
            .unwrap_or_else(|| panic!("{} entry missing", n)).url.as_str()
    };
    assert_eq!(url_of("ICRC-1"), "https://github.com/dfinity/ICRC-1");
    assert_eq!(url_of("ICRC-2"), "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2");
    assert_eq!(
        url_of("ICRC-10"),
        "https://github.com/dfinity/ICRCs/ICRC-10",
        "ICRC-10 MUST-clause self-reference URL (spec-literal string)"
    );
    assert_eq!(
        url_of("ICRC-21"),
        "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md",
        "URL mandated by the ICRC-21 spec's own .did"
    );

    // ICRC-10: the standalone discovery method returns the same list.
    let ten: Vec<StandardRecord> =
        q(&pic, stsh, "icrc10_supported_standards", candid::encode_args(()).unwrap());
    let ten_names: Vec<&str> = ten.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ten_names, "icrc10 list identical to icrc1 list");
}

// =============================================================================
// §4.3.2 — Account and balance handling (A-01 .. A-06)
// =============================================================================

#[test]
fn test_icrc1_a01_a02_default_and_zero_subaccount_same_account() {
    let (pic, stsh) = setup();
    let via_none = balance_of(&pic, stsh, &acct(alice()));
    let via_zero = balance_of(&pic, stsh, &Account {
        owner: alice(),
        subaccount: Some([0u8; 32]),
    });
    assert_eq!(via_none, TOTAL_SUPPLY, "A-01");
    assert_eq!(via_zero, via_none, "A-02: all-zero subaccount == default account");

    // Credit sent to the explicit-zero form lands on the default account.
    transfer(&pic, stsh, alice(), &xfer_args(
        Account { owner: bob(), subaccount: Some([0u8; 32]) }, 5 * STSH,
    )).expect("transfer to zero-subaccount");
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 5 * STSH);
}

#[test]
fn test_icrc1_a03_nonzero_subaccount_isolated() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct_sub(bob(), 1), 3 * STSH)).unwrap();
    assert_eq!(balance_of(&pic, stsh, &acct_sub(bob(), 1)), 3 * STSH);
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 0, "default account not credited");
    assert_eq!(balance_of(&pic, stsh, &acct_sub(bob(), 2)), 0, "other subaccount zero");
}

#[test]
fn test_icrc1_a04_oversize_subaccount_rejected_at_decode() {
    let (pic, stsh) = setup();
    // 33-byte subaccount: canister-side Candid decode into [u8;32] fails and the
    // call is rejected — NOT silently truncated. Matches reference-ledger
    // behaviour (its Subaccount is also a fixed [u8;32] at decode).
    let bad = AccountRaw { owner: alice(), subaccount: Some(vec![7u8; 33]) };
    let r = raw_query(&pic, stsh, anon(), "icrc1_balance_of", candid::encode_one(&bad).unwrap());
    assert!(r.is_err(), "A-04: oversize subaccount must be rejected, got {:?}", r);
}

#[test]
fn test_icrc1_a05_short_subaccount_rejected_at_decode() {
    let (pic, stsh) = setup();
    // 31-byte subaccount: rejected at decode — NOT zero-padded.
    let bad = AccountRaw { owner: alice(), subaccount: Some(vec![7u8; 31]) };
    let r = raw_query(&pic, stsh, anon(), "icrc1_balance_of", candid::encode_one(&bad).unwrap());
    assert!(r.is_err(), "A-05: short subaccount must be rejected, got {:?}", r);
}

#[test]
fn test_icrc1_a06_anonymous_principal_balance_no_trap() {
    let (pic, stsh) = setup();
    assert_eq!(balance_of(&pic, stsh, &acct(anon())), 0, "A-06");
}

// =============================================================================
// §4.3.3 — Transfer happy path (T-01 .. T-09)
// =============================================================================

#[test]
fn test_icrc1_t01_t02_basic_transfer_fee_none_and_explicit() {
    let (pic, stsh) = setup();
    let fee = LIVE_FEE;

    // T-01: fee not specified → live fee applied silently
    let r1 = transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 10 * STSH)).unwrap();
    assert!(to_u128(&r1) > 0, "block index returned");
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 10 * STSH);
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        TOTAL_SUPPLY - 10 * STSH - fee,
        "sender debited amount + fee"
    );
    // DEF-080: fee credited to the neutral fee collector account
    assert_eq!(balance_of(&pic, stsh, &acct(feecol())), fee);

    // T-02: fee explicitly Some(live_fee)
    let mut a2 = xfer_args(acct(bob()), STSH);
    a2.fee = Some(Nat::from(fee));
    transfer(&pic, stsh, alice(), &a2).unwrap();
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 11 * STSH);
    assert_eq!(balance_of(&pic, stsh, &acct(feecol())), 2 * fee);
    assert_invariant(&pic, stsh, "t01_t02");
}

#[test]
fn test_icrc1_t03_t04_subaccount_transfers() {
    let (pic, stsh) = setup();
    // T-04: credit a subaccount
    transfer(&pic, stsh, alice(), &xfer_args(acct_sub(bob(), 9), 5 * STSH)).unwrap();
    assert_eq!(balance_of(&pic, stsh, &acct_sub(bob(), 9)), 5 * STSH);

    // T-03: debit from that subaccount via from_subaccount
    let mut args = xfer_args(acct(carol()), STSH);
    let mut s = [0u8; 32];
    s[31] = 9;
    args.from_subaccount = Some(s);
    transfer(&pic, stsh, bob(), &args).unwrap();
    assert_eq!(balance_of(&pic, stsh, &acct_sub(bob(), 9)), 4 * STSH - LIVE_FEE);
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), STSH);
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 0, "default account untouched");
}

#[test]
fn test_icrc1_t05_t06_memo_32_and_64_bytes() {
    let (pic, stsh) = setup();
    let mut a = xfer_args(acct(bob()), STSH);
    a.memo = Some(vec![0xAB; 32]);
    transfer(&pic, stsh, alice(), &a).expect("T-05: 32-byte memo");
    a.memo = Some(vec![0xCD; 64]);
    transfer(&pic, stsh, alice(), &a).expect("T-06: 64-byte memo (SHOULD allow ≥32)");
}

#[test]
fn test_icrc1_t07_created_at_now_ok() {
    let (pic, stsh) = setup();
    let mut a = xfer_args(acct(bob()), STSH);
    a.created_at_time = Some(now_ns(&pic));
    transfer(&pic, stsh, alice(), &a).expect("T-07");
}

#[test]
fn test_icrc1_t08_self_transfer_different_subaccount() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct_sub(alice(), 1), 7 * STSH)).expect("T-08");
    assert_eq!(balance_of(&pic, stsh, &acct_sub(alice(), 1)), 7 * STSH);
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        TOTAL_SUPPLY - 7 * STSH - LIVE_FEE
    );
    assert_invariant(&pic, stsh, "t08");
}

#[test]
fn test_icrc1_t09_self_transfer_same_account_loses_only_fee() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(alice()), 42 * STSH)).expect("T-09");
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        TOTAL_SUPPLY - LIVE_FEE,
        "T-09: self-transfer nets to −fee only, no state corruption"
    );
    assert_invariant(&pic, stsh, "t09");
}

// =============================================================================
// §4.3.4 — Transfer error cases (E-01 .. E-11)
// =============================================================================

#[test]
fn test_icrc1_e01_e02_bad_fee_exact_variant() {
    let (pic, stsh) = setup();
    // F-000 (live fee 0): any nonzero explicit fee is wrong — E-02's "fee = 1
    // when fee = 0" case is now the exact brief scenario.
    for wrong in [1u128, 10_000u128] {
        let mut a = xfer_args(acct(bob()), STSH);
        a.fee = Some(Nat::from(wrong));
        match transfer(&pic, stsh, alice(), &a) {
            Err(TransferError::BadFee { expected_fee }) => {
                assert_eq!(to_u128(&expected_fee), LIVE_FEE, "payload carries live fee (0)")
            }
            other => panic!("E-01/02: expected BadFee, got {:?}", other),
        }
    }
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 0, "no state change on BadFee");
}

#[test]
fn test_icrc1_e03_insufficient_funds_exact_variant() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), STSH)).unwrap();
    match transfer(&pic, stsh, bob(), &xfer_args(acct(carol()), 2 * STSH)) {
        Err(TransferError::InsufficientFunds { balance }) => {
            assert_eq!(to_u128(&balance), STSH, "payload carries current balance")
        }
        other => panic!("E-03: expected InsufficientFunds, got {:?}", other),
    }
}

#[test]
fn test_icrc1_e04_amount_equals_balance_fee_on_top() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), STSH)).unwrap();
    // F-000 (fee = 0): with no fee on top, a full-balance transfer SUCCEEDS and
    // empties the account exactly. E-04's fee>0 branch (InsufficientFunds when
    // amount == balance) is unreachable at a zero fee; the boundary is instead
    // amount == balance + 1.
    transfer(&pic, stsh, bob(), &xfer_args(acct(carol()), STSH))
        .expect("E-04 (fee=0): full-balance transfer succeeds");
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 0, "account emptied exactly");
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), STSH);
    match transfer(&pic, stsh, bob(), &xfer_args(acct(carol()), 1)) {
        Err(TransferError::InsufficientFunds { balance }) => {
            assert_eq!(to_u128(&balance), 0, "one unit past the balance fails")
        }
        other => panic!("E-04b: expected InsufficientFunds, got {:?}", other),
    }
}

#[test]
fn test_icrc1_e05_too_old_exact_variant() {
    let (pic, stsh) = setup();
    let mut a = xfer_args(acct(bob()), STSH);
    a.created_at_time = Some(now_ns(&pic) - TX_DEDUP_WINDOW_NS - 1_000_000_000);
    match transfer(&pic, stsh, alice(), &a) {
        Err(TransferError::TooOld) => {} // exact variant, no payload
        other => panic!("E-05: expected TooOld, got {:?}", other),
    }
}

#[test]
fn test_icrc1_e06_created_in_future_exact_variant() {
    let (pic, stsh) = setup();
    let mut a = xfer_args(acct(bob()), STSH);
    a.created_at_time = Some(now_ns(&pic) + PERMITTED_DRIFT_NS + 60_000_000_000);
    match transfer(&pic, stsh, alice(), &a) {
        Err(TransferError::CreatedInFuture { ledger_time }) => {
            let now = now_ns(&pic);
            assert!(ledger_time <= now + 1_000_000_000, "ledger_time plausible");
        }
        other => panic!("E-06: expected CreatedInFuture, got {:?}", other),
    }
}

// R10-1 RETARGET (lane A-3) — renamed with the suite's `dev` tag, not erased.
//
// WAS: `test_icrc1_e07_zero_amount_transfer_ok_fee_charged`, asserting that a
//      zero-amount transfer returns Ok and still debits LIVE_FEE. It carried NO
//      tag, which is this suite's way of classifying zero-amount acceptance as
//      CONFORMANT — and it passed at the pinned base c48ef2a.
// NOW: the ledger REFUSES zero-amount transfers (R10-1), which is a KNOWING
//      ICRC-1 DEVIATION rather than a conformance fix — ICRC-1 permits them.
//      Hence the `dev004` tag (next free: dev001-003 and finding001-004/006-007
//      were in use). Registered in NOTE_A-3_icrc_deviation.md.
// CAUSE: R10-1. At DEFAULT_FEE = 0 a zero-amount transfer was a completely free
//      no-op that still wrote a dedup entry — an unpriced state-growth vector.
#[test]
fn test_icrc1_e07_zero_amount_transfer_rejected_dev004() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), STSH)).unwrap();
    let before_bob = balance_of(&pic, stsh, &acct(bob()));
    let before_carol = balance_of(&pic, stsh, &acct(carol()));

    match transfer(&pic, stsh, bob(), &xfer_args(acct(carol()), 0)) {
        Err(TransferError::GenericError { error_code, .. }) => {
            assert_eq!(error_code, Nat::from(5u32), "E-07 dev004: pinned R10-1 error code");
        }
        other => panic!("E-07 dev004: expected the R10-1 zero-amount refusal, got {:?}", other),
    }
    // Balances must not move — not even the fee (contrast with the old
    // behaviour, which debited LIVE_FEE on the accepted no-op).
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), before_bob, "sender balance unchanged");
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), before_carol, "recipient balance unchanged");
    assert_invariant(&pic, stsh, "e07_dev004");
}

#[test]
fn test_icrc1_e08_anonymous_can_receive_and_spend() {
    let (pic, stsh) = setup();
    // E-08: send TO the anonymous principal succeeds
    transfer(&pic, stsh, alice(), &xfer_args(acct(anon()), 2 * STSH)).expect("E-08");
    assert_eq!(balance_of(&pic, stsh, &acct(anon())), 2 * STSH);
    // AUTH-04: anonymous caller can spend its own account — no fee/balance bypass
    transfer(&pic, stsh, anon(), &xfer_args(acct(bob()), STSH)).expect("AUTH-04");
    assert_eq!(balance_of(&pic, stsh, &acct(anon())), STSH - LIVE_FEE);
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), STSH);
}

#[test]
fn test_icrc1_e09_huge_amounts_no_trap() {
    let (pic, stsh) = setup();

    // amount > supply but amount + fee fits u128 → InsufficientFunds
    match transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), TOTAL_SUPPLY + 1)) {
        Err(TransferError::InsufficientFunds { .. }) => {}
        other => panic!("E-09a: expected InsufficientFunds, got {:?}", other),
    }

    // amount = u128::MAX: with the F-000 zero fee, amount + fee no longer
    // overflows u128 — the transfer falls through to the balance check and
    // returns InsufficientFunds (reference parity; the GenericError(3)
    // overflow guard remains for any future nonzero fee and is unit-tested
    // in test_u128_overflow_safe).
    match transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), u128::MAX)) {
        Err(TransferError::InsufficientFunds { .. }) => {}
        other => panic!("E-09b: expected InsufficientFunds, got {:?}", other),
    }

    // amount = 2^128 (exceeds u128 entirely) → GenericError(1), decoded fine as Nat
    let mut big = Nat::from(u128::MAX);
    big.0 = big.0.clone() + 1u32;
    let args = TransferArgs {
        from_subaccount: None,
        to: acct(bob()),
        amount: big,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    match transfer(&pic, stsh, alice(), &args) {
        Err(TransferError::GenericError { error_code, .. }) => {
            assert_eq!(to_u128(&error_code), 1, "amount > u128 guard (SER-04)")
        }
        other => panic!("E-09c: expected GenericError(1), got {:?}", other),
    }
    assert_invariant(&pic, stsh, "e09");
}

#[test]
fn test_icrc1_e10_e11_memo_empty_and_10kb() {
    let (pic, stsh) = setup();
    let mut a = xfer_args(acct(bob()), STSH);
    a.memo = Some(vec![]);
    transfer(&pic, stsh, alice(), &a).expect("E-10: empty memo");
    // DEV-004 (Low): memo unbounded — 10 KB accepted. Dedup stores only the
    // sha256 of the transfer identity, not the raw memo (no storage blowup).
    a.memo = Some(vec![0x55; 10_000]);
    transfer(&pic, stsh, alice(), &a).expect("E-11: 10KB memo accepted");
}

// =============================================================================
// §4.3.5 — Transaction deduplication (D-01 .. D-08)
// =============================================================================

fn dedup_args(pic: &PocketIc) -> TransferArgs {
    let mut a = xfer_args(acct(bob()), STSH);
    a.memo = Some(vec![1, 2, 3]);
    a.created_at_time = Some(now_ns(pic));
    a
}

#[test]
fn test_icrc1_d01_duplicate_within_window() {
    let (pic, stsh) = setup();
    let a = dedup_args(&pic);
    let block = transfer(&pic, stsh, alice(), &a).unwrap();
    match transfer(&pic, stsh, alice(), &a) {
        Err(TransferError::Duplicate { duplicate_of }) => {
            assert_eq!(duplicate_of, block, "D-01: payload carries original index")
        }
        other => panic!("D-01: expected Duplicate, got {:?}", other),
    }
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), STSH, "exactly one credit");
}

#[test]
fn test_icrc1_d02_d05_field_changes_break_dedup() {
    let (pic, stsh) = setup();
    let a = dedup_args(&pic);
    transfer(&pic, stsh, alice(), &a).unwrap();
    // Fund carol so she can act as the different caller in D-05.
    transfer(&pic, stsh, alice(), &xfer_args(acct(carol()), 5 * STSH)).unwrap();

    // D-02: different memo → new transaction
    let mut m = a.clone();
    m.memo = Some(vec![9, 9, 9]);
    transfer(&pic, stsh, alice(), &m).expect("D-02");

    // D-03: different amount
    let mut m = a.clone();
    m.amount = Nat::from(2 * STSH);
    transfer(&pic, stsh, alice(), &m).expect("D-03");

    // D-04: different `to`
    let mut m = a.clone();
    m.to = acct_sub(bob(), 1);
    transfer(&pic, stsh, alice(), &m).expect("D-04");

    // D-05: different caller (same args)
    transfer(&pic, stsh, carol(), &a).expect("D-05");
}

#[test]
fn test_icrc1_d06_no_created_at_time_no_dedup() {
    let (pic, stsh) = setup();
    let a = xfer_args(acct(bob()), STSH);
    transfer(&pic, stsh, alice(), &a).expect("first");
    transfer(&pic, stsh, alice(), &a).expect("D-06: no created_at_time → no dedup");
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 2 * STSH);
}

#[test]
fn test_icrc1_d07_replay_after_window_too_old() {
    let (pic, stsh) = setup();
    let a = dedup_args(&pic);
    transfer(&pic, stsh, alice(), &a).unwrap();
    pic.advance_time(Duration::from_nanos(TX_DEDUP_WINDOW_NS + 1_000_000_000));
    pic.tick();
    match transfer(&pic, stsh, alice(), &a) {
        Err(TransferError::TooOld) => {} // D-07: window expired → TooOld, not re-execution
        other => panic!("D-07: expected TooOld, got {:?}", other),
    }
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), STSH, "no second credit");
}

#[test]
fn test_icrc1_d08_exactly_one_credit_on_immediate_resubmit() {
    let (pic, stsh) = setup();
    let a = dedup_args(&pic);
    let r1 = transfer(&pic, stsh, alice(), &a);
    let r2 = transfer(&pic, stsh, alice(), &a);
    assert!(r1.is_ok(), "first commits");
    assert!(matches!(r2, Err(TransferError::Duplicate { .. })), "second is Duplicate");
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), STSH, "D-08: exactly one credit");
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        TOTAL_SUPPLY - STSH - LIVE_FEE,
        "exactly one debit"
    );
}

// =============================================================================
// §5.3.1 — Approve + transfer_from (AP-01 .. AP-10)
// =============================================================================

#[test]
fn test_icrc2_ap01_ap02_partial_and_full_allowance_consumption() {
    let (pic, stsh) = setup();
    let allow = 100 * STSH;
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), allow)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        allow
    );

    // AP-01: spend 50 — allowance decremented by amount + fee
    let spend = 50 * STSH;
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), spend)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        allow - spend - LIVE_FEE,
        "AP-01/FEE-05: allowance -= amount + fee"
    );
    assert_eq!(balance_of(&pic, stsh, &acct(dexp())), spend);

    // AP-02: spend the exact remainder (amount + fee == remaining allowance)
    let remaining = allow - spend - LIVE_FEE;
    let spend2 = remaining - LIVE_FEE;
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), spend2)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        0,
        "AP-02: full allowance consumed"
    );
    assert_invariant(&pic, stsh, "ap01_ap02");
}

#[test]
fn test_icrc2_ap03_insufficient_allowance_shape_finding002() {
    let (pic, stsh) = setup();
    let allow = 100 * STSH;
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), allow)).unwrap();

    // F-002 FIXED (regression guard): ICRC-2 spec shape —
    //   Err(InsufficientAllowance { allowance : nat })
    // with the CURRENT allowance in the payload. A regression to the pre-fix
    // behaviour (InsufficientFunds carrying the allowance) fails here.
    match transfer_from_spec(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), allow + 1)) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), allow, "payload carries the current allowance");
        }
        Err(SpecTransferFromError::InsufficientFunds { .. }) => {
            panic!("FINDING-002 REGRESSED: allowance shortfall reported as InsufficientFunds")
        }
        other => panic!("AP-03: unexpected {:?}", other),
    }
}

#[test]
fn test_icrc2_ap04_insufficient_funds_with_ample_allowance() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 100 * STSH)).unwrap();
    approve(&pic, stsh, bob(), &approve_args(&pic, acct(dexp()), 200 * STSH)).unwrap();
    let bob_liquid = balance_of(&pic, stsh, &acct(bob()));
    match transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(dexp()), 150 * STSH)) {
        Err(SpecTransferFromError::InsufficientFunds { balance }) => {
            assert_eq!(to_u128(&balance), bob_liquid, "AP-04: balance payload = liquid funds")
        }
        other => panic!("AP-04: expected InsufficientFunds, got {:?}", other),
    }
    // allowance untouched by the failed transfer (QA-DEF-019 ordering)
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(bob()), acct(dexp())).allowance),
        200 * STSH
    );
}

#[test]
fn test_icrc2_ap05_revoke_to_zero() {
    let (pic, stsh) = setup();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 10 * STSH)).unwrap();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 0)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        0,
        "AP-05: revoked"
    );
    match transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), 1)) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), 0, "no spend after revoke (spec variant)")
        }
        other => panic!("AP-05: expected InsufficientAllowance, got {:?}", other),
    }
}

#[test]
fn test_icrc2_ap06_ap07_expiry_honored_then_generic_error_finding003() {
    let (pic, stsh) = setup();
    let mut args = approve_args(&pic, acct(dexp()), 10 * STSH);
    args.expires_at = Some(now_ns(&pic) + 60_000_000_000); // now + 60s
    approve(&pic, stsh, alice(), &args).unwrap();

    // AP-06: within the window — works
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), STSH))
        .expect("AP-06: spend within expiry window");

    // AP-07: after expiry.
    pic.advance_time(Duration::from_secs(61));
    pic.tick();
    // F-003 FIXED (regression guard): spec shape for an expired approval —
    //   Err(InsufficientAllowance { allowance : 0 })
    match transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), STSH)) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), 0, "AP-07: expired approval reads as zero allowance");
        }
        other => panic!("AP-07 (FINDING-003 regressed?): got {:?}", other),
    }

    // F-005 FIXED (regression guard): icrc2_allowance zeroes an expired
    // allowance — { allowance = 0; expires_at = null }, reference parity.
    let a = allowance_of(&pic, stsh, acct(alice()), acct(dexp()));
    assert_eq!(to_u128(&a.allowance), 0, "AC-03: expired allowance reads 0");
    assert!(a.expires_at.is_none(), "AC-03: expires_at cleared in the read");
}

#[test]
fn test_icrc2_ap08_expires_at_in_past_accepted_finding006() {
    let (pic, stsh) = setup();
    let mut args = approve_args(&pic, acct(dexp()), 10 * STSH);
    args.expires_at = Some(now_ns(&pic).saturating_sub(3_600_000_000_000)); // 1h ago
    // F-006 FIXED (regression guard): an already-expired expires_at is rejected
    // with Expired { ledger_time } — no dead record is stored.
    match approve(&pic, stsh, alice(), &args) {
        Err(ApproveError::Expired { ledger_time }) => {
            assert!(ledger_time > 0, "ledger_time populated");
        }
        other => panic!("AP-08 (FINDING-006 regressed?): {:?}", other),
    }
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        0,
        "no allowance record created"
    );
}

#[test]
fn test_icrc2_ap09_reapprove_resets_not_adds() {
    let (pic, stsh) = setup();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 100 * STSH)).unwrap();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 30 * STSH)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        30 * STSH,
        "AP-09/AC-02/OVER-02: re-approval RESETS, never adds"
    );
}

#[test]
fn test_icrc2_ap10_approve_from_subaccount() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct_sub(alice(), 3), 10 * STSH)).unwrap();
    let mut args = approve_args(&pic, acct(dexp()), 5 * STSH);
    let mut s = [0u8; 32];
    s[31] = 3;
    args.from_subaccount = Some(s);
    approve(&pic, stsh, alice(), &args).unwrap();

    // Allowance is keyed to the SUBACCOUNT, not the default account
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct_sub(alice(), 3), acct(dexp())).allowance),
        5 * STSH
    );
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        0
    );
    // Approval fee was debited from the subaccount
    assert_eq!(balance_of(&pic, stsh, &acct_sub(alice(), 3)), 10 * STSH - LIVE_FEE);

    // Spend from the subaccount
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct_sub(alice(), 3), acct(dexp()), STSH))
        .expect("AP-10: spend from approved subaccount");
}

// =============================================================================
// §5.3.2 — expected_allowance CAS (CAS-01 .. CAS-04)
// =============================================================================

#[test]
fn test_icrc2_cas01_04_expected_allowance_semantics() {
    let (pic, stsh) = setup();

    // CAS-01: expected 0 on first approval
    let mut args = approve_args(&pic, acct(dexp()), 50 * STSH);
    args.expected_allowance = Some(Nat::from(0u8));
    approve(&pic, stsh, alice(), &args).expect("CAS-01");

    // CAS-02: expected == current
    let mut args = approve_args(&pic, acct(dexp()), 80 * STSH);
    args.expected_allowance = Some(Nat::from(50 * STSH));
    approve(&pic, stsh, alice(), &args).expect("CAS-02");

    // CAS-03: expected != current → AllowanceChanged with the real value
    let mut args = approve_args(&pic, acct(dexp()), 99 * STSH);
    args.expected_allowance = Some(Nat::from(1u8));
    match approve(&pic, stsh, alice(), &args) {
        Err(ApproveError::AllowanceChanged { current_allowance }) => {
            assert_eq!(to_u128(&current_allowance), 80 * STSH, "CAS-03 payload")
        }
        other => panic!("CAS-03: expected AllowanceChanged, got {:?}", other),
    }

    // CAS-04: spender consumed some allowance between read and write
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), 10 * STSH))
        .unwrap();
    let consumed = 10 * STSH + LIVE_FEE;
    let mut args = approve_args(&pic, acct(dexp()), 42 * STSH);
    args.expected_allowance = Some(Nat::from(80 * STSH)); // stale read
    match approve(&pic, stsh, alice(), &args) {
        Err(ApproveError::AllowanceChanged { current_allowance }) => {
            assert_eq!(to_u128(&current_allowance), 80 * STSH - consumed, "CAS-04 payload")
        }
        other => panic!("CAS-04: expected AllowanceChanged, got {:?}", other),
    }
}

// =============================================================================
// §5.3.3 — Fee handling in approval flows (FEE-01 .. FEE-05)
// =============================================================================

#[test]
fn test_icrc2_fee01_02_approve_fee_semantics() {
    let (pic, stsh) = setup();

    // FEE-01: approval fee deducted from the approver
    let before = balance_of(&pic, stsh, &acct(alice()));
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), STSH)).unwrap();
    assert_eq!(balance_of(&pic, stsh, &acct(alice())), before - LIVE_FEE, "FEE-01");

    // FEE-02: wrong explicit fee → BadFee
    let mut args = approve_args(&pic, acct(dexp()), STSH);
    args.fee = Some(Nat::from(LIVE_FEE + 5));
    match approve(&pic, stsh, alice(), &args) {
        Err(ApproveError::BadFee { expected_fee }) => {
            assert_eq!(to_u128(&expected_fee), LIVE_FEE, "FEE-02")
        }
        other => panic!("FEE-02: expected BadFee, got {:?}", other),
    }
}

#[test]
fn test_icrc2_fee03_exact_fee_balance_approve() {
    let (pic, stsh) = setup();
    // FEE-03 under F-000 (fee = 0): "balance == fee" means a ZERO-balance
    // account — approvals are free, so even an empty account can approve
    // (brief: "Ok(tx_index) if fee=0 (free approval)"). Nothing is debited.
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), 0, "carol starts empty");
    approve(&pic, stsh, carol(), &approve_args(&pic, acct(dexp()), 999 * STSH))
        .expect("FEE-03 (fee=0): free approval from an empty account");
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), 0, "still empty — no debit");
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(carol()), acct(dexp())).allowance),
        999 * STSH,
        "allowance recorded"
    );
}

#[test]
fn test_icrc2_fee04_fee05_transfer_from_fee_paid_by_from_account() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 100 * STSH)).unwrap();
    approve(&pic, stsh, bob(), &approve_args(&pic, acct(dexp()), 10 * STSH + LIVE_FEE)).unwrap();
    let bob_before = balance_of(&pic, stsh, &acct(bob()));
    let dex_before = balance_of(&pic, stsh, &acct(dexp()));

    // FEE-05 negative: allowance == amount + fee − 1 → rejected
    match transfer_from_stsh(
        &pic, stsh, dexp(), &tf_args(acct(bob()), acct(carol()), 10 * STSH + 1),
    ) {
        Err(_) => {} // allowance (10 STSH + fee) < amount (10 STSH + 1) + fee
        Ok(_) => panic!("FEE-05: allowance must cover amount + fee"),
    }

    // FEE-04: fee is paid by the FROM account (bob), never by the spender
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(carol()), 10 * STSH))
        .unwrap();
    assert_eq!(
        balance_of(&pic, stsh, &acct(bob())),
        bob_before - 10 * STSH - LIVE_FEE,
        "FEE-04: from-account pays amount + fee"
    );
    assert_eq!(balance_of(&pic, stsh, &acct(dexp())), dex_before, "spender balance unchanged");
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), 10 * STSH);
    assert_invariant(&pic, stsh, "fee04");
}

// =============================================================================
// §5.3.4 — Spender subaccount edge cases (SA-01 .. SA-04)
// =============================================================================

#[test]
fn test_icrc2_sa01_sa02_spender_subaccount_distinct_allowances() {
    let (pic, stsh) = setup();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct_sub(dexp(), 1), 7 * STSH)).unwrap();

    // SA-01: allowance tracked against the spender's SUBACCOUNT identity
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct_sub(dexp(), 1)).allowance),
        7 * STSH
    );
    // SA-02: same owner, different subaccount → different spender → 0
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        0
    );
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct_sub(dexp(), 2)).allowance),
        0
    );

    // SA-04: the spender selects that identity via spender_subaccount
    let mut args = tf_args(acct(alice()), acct(bob()), STSH);
    let mut s = [0u8; 32];
    s[31] = 1;
    args.spender_subaccount = Some(s);
    transfer_from_stsh(&pic, stsh, dexp(), &args).expect("SA-04: subaccount spender identity");
    // and WITHOUT spender_subaccount the default spender identity has no allowance
    match transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(bob()), STSH)) {
        Err(_) => {}
        Ok(_) => panic!("SA-02: default spender identity must have no allowance"),
    }
}

#[test]
fn test_icrc2_sa03_self_approval_allowed_documented() {
    let (pic, stsh) = setup();
    // DOCUMENTED: STSH allows spender.owner == caller (self-approval). The spec
    // says a ledger SHOULD reject; the reference ledger's behaviour is captured
    // in the differential section. Harmless (self-spend of own funds) but
    // documented as a deviation candidate.
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(alice()), STSH))
        .expect("SA-03: self-approval currently allowed");
}

// =============================================================================
// §5.3.5 — Dedup for approve and transfer_from (DD-01 .. DD-03)
// =============================================================================

#[test]
fn test_icrc2_dd02_transfer_from_duplicate() {
    let (pic, stsh) = setup();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 100 * STSH)).unwrap();
    let mut args = tf_args(acct(alice()), acct(dexp()), STSH);
    args.created_at_time = Some(now_ns(&pic));
    let block = transfer_from_stsh(&pic, stsh, dexp(), &args).unwrap();
    match transfer_from_stsh(&pic, stsh, dexp(), &args) {
        Err(SpecTransferFromError::Duplicate { duplicate_of }) => {
            assert_eq!(duplicate_of, block, "DD-02")
        }
        other => panic!("DD-02: expected Duplicate, got {:?}", other),
    }
    // allowance decremented exactly once
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        100 * STSH - STSH - LIVE_FEE
    );
}

#[test]
fn test_icrc2_dd01_approve_ignores_created_at_time_finding004() {
    let (pic, stsh) = setup();
    let mut args = approve_args(&pic, acct(dexp()), 10 * STSH);
    args.created_at_time = Some(now_ns(&pic));
    args.memo = Some(vec![7; 8]);

    let before = balance_of(&pic, stsh, &acct(alice()));
    let block = approve(&pic, stsh, alice(), &args).expect("first approve");

    // F-004 FIXED (regression guard): a byte-identical approve retry within the
    // dedup window returns Duplicate carrying the original block index — it is
    // NOT re-executed, and the approval fee is debited exactly once.
    match approve(&pic, stsh, alice(), &args) {
        Err(ApproveError::Duplicate { duplicate_of }) => {
            assert_eq!(duplicate_of, block, "DD-01: payload carries original index")
        }
        other => panic!("DD-01 (FINDING-004 regressed?): {:?}", other),
    }
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        before - LIVE_FEE,
        "exactly ONE fee debit across the original + deduped retry"
    );

    // Window validation now enforced, making the previously unreachable
    // TooOld / CreatedInFuture ApproveError variants live:
    let mut old = approve_args(&pic, acct(dexp()), 11 * STSH);
    old.created_at_time = Some(now_ns(&pic) - TX_DEDUP_WINDOW_NS - 1_000_000_000);
    match approve(&pic, stsh, alice(), &old) {
        Err(ApproveError::TooOld) => {}
        other => panic!("stale approve must be TooOld: {:?}", other),
    }
    let mut fut = approve_args(&pic, acct(dexp()), 12 * STSH);
    fut.created_at_time = Some(now_ns(&pic) + PERMITTED_DRIFT_NS + 60_000_000_000);
    match approve(&pic, stsh, alice(), &fut) {
        Err(ApproveError::CreatedInFuture { .. }) => {}
        other => panic!("future approve must be CreatedInFuture: {:?}", other),
    }
    // A changed field (memo) is a NEW approval, not a duplicate.
    let mut changed = args.clone();
    changed.memo = Some(vec![9; 8]);
    approve(&pic, stsh, alice(), &changed).expect("changed memo → new approval");
}

#[test]
fn test_icrc2_dd03_approve_without_created_at_both_succeed() {
    let (pic, stsh) = setup();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 5 * STSH)).unwrap();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 5 * STSH)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        5 * STSH,
        "DD-03: second approve resets to same value"
    );
}

// =============================================================================
// §5.3.6 — DEX-style flows (DEX-01 .. DEX-04)
// =============================================================================

#[test]
fn test_icrc2_dex01_04_dex_deposit_flows() {
    let (pic, stsh) = setup();
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 1_000 * STSH)).unwrap();

    // DEX-01: user approves DEX; DEX pulls deposit to its own account
    approve(&pic, stsh, bob(), &approve_args(&pic, acct(dexp()), 100 * STSH)).unwrap();
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(dexp()), 50 * STSH))
        .expect("DEX-01: deposit lands");
    assert_eq!(balance_of(&pic, stsh, &acct(dexp())), 50 * STSH);

    // DEX-02: partial-fill attempt beyond remaining allowance → spec variant
    // with the remaining allowance (F-002 fixed shape)
    match transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(dexp()), 60 * STSH)) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), 100 * STSH - 50 * STSH - LIVE_FEE);
        }
        other => panic!("DEX-02: expected InsufficientAllowance, got {:?}", other),
    }

    // DEX-03: revoke-then-spend — revoke wins, spend cleanly rejected, no
    // double-debit (canister execution is single-threaded per message; the
    // "race" resolves to strict ordering on the IC)
    approve(&pic, stsh, bob(), &approve_args(&pic, acct(dexp()), 0)).unwrap();
    let bob_bal = balance_of(&pic, stsh, &acct(bob()));
    assert!(
        transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(dexp()), STSH)).is_err(),
        "DEX-03: spend after revoke rejected"
    );
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), bob_bal, "no debit on failure");

    // DEX-04: two sequential spends within one approval — both succeed and the
    // allowance is decremented exactly (amount + fee) twice
    approve(&pic, stsh, bob(), &approve_args(&pic, acct(dexp()), 10 * STSH + 2 * LIVE_FEE)).unwrap();
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(dexp()), 5 * STSH)).unwrap();
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(bob()), acct(dexp()), 5 * STSH)).unwrap();
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(bob()), acct(dexp())).allowance),
        0,
        "DEX-04: exact double decrement"
    );
    assert_invariant(&pic, stsh, "dex01_04");
}

// =============================================================================
// §12 — Lane 9: supply invariant, auth, overflow, upgrade persistence
// =============================================================================

#[test]
fn test_si01_03_supply_invariant_through_operations() {
    let (pic, stsh) = setup();
    assert_invariant(&pic, stsh, "genesis");
    let supply0: Nat = q(&pic, stsh, "icrc1_total_supply", candid::encode_args(()).unwrap());

    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 100 * STSH)).unwrap();
    transfer(&pic, stsh, alice(), &xfer_args(acct_sub(carol(), 5), 20 * STSH)).unwrap();
    approve(&pic, stsh, alice(), &approve_args(&pic, acct(dexp()), 50 * STSH)).unwrap();
    transfer_from_stsh(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), 10 * STSH))
        .unwrap();
    transfer(&pic, stsh, bob(), &xfer_args(acct(alice()), 1)).unwrap();

    // SI-01/02/03: invariant holds; total supply constant; fees accumulated at
    // the collector ACCOUNT (inside BALANCES), not burned
    assert_invariant(&pic, stsh, "si01 after ops");
    let supply1: Nat = q(&pic, stsh, "icrc1_total_supply", candid::encode_args(()).unwrap());
    assert_eq!(supply0, supply1, "SI-02/03: total supply never changes");
    assert_eq!(
        balance_of(&pic, stsh, &acct(feecol())),
        5 * LIVE_FEE,
        "SI-03: 5 fee-bearing ops → 5 fees at the collector"
    );

    // SI-04/05: exact debit/credit arithmetic across one more transfer
    let a0 = balance_of(&pic, stsh, &acct(alice()));
    let b0 = balance_of(&pic, stsh, &acct(bob()));
    transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 7 * STSH)).unwrap();
    assert_eq!(balance_of(&pic, stsh, &acct(alice())), a0 - 7 * STSH - LIVE_FEE, "SI-04");
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), b0 + 7 * STSH, "SI-05");
}

#[test]
fn test_si_property_random_ops_invariant_held() {
    let (pic, stsh) = setup();
    // Seed working balances
    for (who, amt) in [(bob(), 1_000 * STSH), (carol(), 1_000 * STSH), (dexp(), 1_000 * STSH)] {
        transfer(&pic, stsh, alice(), &xfer_args(acct(who), amt)).unwrap();
    }
    let actors = [alice(), bob(), carol(), dexp()];
    let mut rng: u64 = 0x5DEECE66D;
    let mut next = move || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng
    };

    // 60 pseudo-random ops (transfer / approve / transfer_from, random
    // subaccounts and amounts, errors allowed) — invariant after every op.
    for i in 0..60u32 {
        let a = actors[(next() % 4) as usize];
        let b = actors[(next() % 4) as usize];
        let amount = (next() % (3 * STSH as u64)) as u128;
        let sub_tag = (next() % 3) as u8; // 0 → default account
        let to = if sub_tag == 0 { acct(b) } else { acct_sub(b, sub_tag) };
        match next() % 3 {
            0 => {
                let _ = transfer(&pic, stsh, a, &xfer_args(to, amount));
            }
            1 => {
                let _ = approve(&pic, stsh, a, &approve_args(&pic, to, amount));
            }
            _ => {
                let _ = transfer_from_stsh(&pic, stsh, a, &tf_args(acct(b), acct(a), amount));
            }
        }
        assert_invariant(&pic, stsh, &format!("property op {}", i));
    }
}

#[test]
fn test_auth02_03_no_unapproved_transfer_from() {
    let (pic, stsh) = setup();
    // AUTH-02/03: a spender (user principal or canister — same caller semantics)
    // with no approval cannot move funds. Zero allowance → spec variant.
    match transfer_from_spec(&pic, stsh, dexp(), &tf_args(acct(alice()), acct(dexp()), STSH)) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), 0, "zero allowance")
        }
        other => panic!("AUTH-02: expected InsufficientAllowance, got {:?}", other),
    }
    assert_eq!(balance_of(&pic, stsh, &acct(alice())), TOTAL_SUPPLY, "no debit");
}

#[test]
fn test_trap02_03_upgrade_persistence_and_replay() {
    let (pic, stsh) = setup();

    // Pre-upgrade state: transfer with dedup entry + allowance with expiry
    let mut targs = xfer_args(acct(bob()), 10 * STSH);
    targs.created_at_time = Some(now_ns(&pic));
    targs.memo = Some(vec![0xEE; 4]);
    let block_pre = transfer(&pic, stsh, alice(), &targs).unwrap();

    let mut aargs = approve_args(&pic, acct(dexp()), 33 * STSH);
    aargs.expires_at = Some(now_ns(&pic) + 3_600_000_000_000);
    approve(&pic, stsh, alice(), &aargs).unwrap();

    // TRAP-02/03: upgrade with the same Wasm (pre_upgrade → post_upgrade)
    pic.upgrade_canister(stsh, token_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade must succeed");

    // Balances persist
    assert_eq!(balance_of(&pic, stsh, &acct(bob())), 10 * STSH);
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        TOTAL_SUPPLY - 10 * STSH - 2 * LIVE_FEE
    );
    // Allowance (incl. expiry) persists
    let a = allowance_of(&pic, stsh, acct(alice()), acct(dexp()));
    assert_eq!(to_u128(&a.allowance), 33 * STSH);
    assert!(a.expires_at.is_some());
    // Dedup window persists: pre-upgrade transfer still deduplicates
    match transfer(&pic, stsh, alice(), &targs) {
        Err(TransferError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, block_pre),
        other => panic!("REPLAY after upgrade: expected Duplicate, got {:?}", other),
    }
    // Block height did not reset: next block index is strictly greater
    let block_post = transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), 1)).unwrap();
    assert!(
        to_u128(&block_post) > to_u128(&block_pre),
        "block height monotonic across upgrade"
    );
    assert_invariant(&pic, stsh, "post-upgrade");
}

// =============================================================================
// §6 — Lane 3: reference ledger differential
// =============================================================================

#[test]
fn test_differential_r01_r04_basic_queries_match() {
    let (pic, stsh, refl) = setup_diff();
    for m in ["icrc1_name", "icrc1_symbol"] {
        let s: String = q(&pic, stsh, m, candid::encode_args(()).unwrap());
        let r: String = q(&pic, refl, m, candid::encode_args(()).unwrap());
        assert_eq!(s, r, "{} differs", m);
    }
    let sd: u8 = q(&pic, stsh, "icrc1_decimals", candid::encode_args(()).unwrap());
    let rd: u8 = q(&pic, refl, "icrc1_decimals", candid::encode_args(()).unwrap());
    assert_eq!(sd, rd, "R-03 decimals");
    assert_eq!(live_fee(&pic, stsh), live_fee(&pic, refl), "R-04 fee");
    let ss: Nat = q(&pic, stsh, "icrc1_total_supply", candid::encode_args(()).unwrap());
    let rs: Nat = q(&pic, refl, "icrc1_total_supply", candid::encode_args(()).unwrap());
    assert_eq!(ss, rs, "total supply parity");
}

#[test]
fn test_differential_r05_metadata_key_sets() {
    let (pic, stsh, refl) = setup_diff();
    let sm: Vec<(String, MetadataValue)> =
        q(&pic, stsh, "icrc1_metadata", candid::encode_args(()).unwrap());
    let rm: Vec<(String, MetadataValue)> =
        q(&pic, refl, "icrc1_metadata", candid::encode_args(()).unwrap());
    let skeys: Vec<&String> = sm.iter().map(|(k, _)| k).collect();
    let rkeys: Vec<&String> = rm.iter().map(|(k, _)| k).collect();
    println!("STSH metadata keys:      {:?}", skeys);
    println!("Reference metadata keys: {:?}", rkeys);
    for req in ["icrc1:name", "icrc1:symbol", "icrc1:decimals", "icrc1:fee"] {
        assert!(skeys.iter().any(|k| *k == req), "STSH missing {}", req);
        assert!(rkeys.iter().any(|k| *k == req), "reference missing {}", req);
    }
    // Keys the reference advertises that STSH does not — the metadata delta for
    // the deviation register (DEV-003 logo is tracked separately; the reference
    // default set includes icrc1:max_memo_length — DEV-004).
    let missing: Vec<&&String> = rkeys.iter().filter(|k| !skeys.contains(*k)).collect();
    println!("Reference-only metadata keys (STSH gaps): {:?}", missing);
}

#[test]
fn test_differential_r06_minting_account_dev001() {
    let (pic, stsh, refl) = setup_diff();
    let s: Option<Account> =
        q(&pic, stsh, "icrc1_minting_account", candid::encode_args(()).unwrap());
    let r: Option<Account> =
        q(&pic, refl, "icrc1_minting_account", candid::encode_args(()).unwrap());
    assert!(s.is_none(), "DEV-001: STSH fixed supply → null");
    assert_eq!(r, Some(acct(minter())), "reference has a minting account");
}

#[test]
fn test_differential_r07_r08_balance_parity_and_first_transfer_index() {
    let (pic, stsh, refl) = setup_diff();
    assert_eq!(
        balance_of(&pic, stsh, &acct(alice())),
        balance_of(&pic, refl, &acct(alice())),
        "R-07: identical state → identical balance"
    );
    let sb = transfer(&pic, stsh, alice(), &xfer_args(acct(bob()), STSH)).unwrap();
    let rb = transfer(&pic, refl, alice(), &xfer_args(acct(bob()), STSH)).unwrap();
    // Block-index basis: STSH starts at 1; the reference counts its genesis
    // mint block(s) first (1 initial balance → mint block 0 → first transfer 1).
    // Indices are opaque per the standard — recorded, not asserted equal.
    println!("first transfer index — STSH: {}, reference: {}", sb, rb);
    assert_eq!(
        balance_of(&pic, stsh, &acct(bob())),
        balance_of(&pic, refl, &acct(bob())),
        "post-transfer balance parity"
    );
}

#[test]
fn test_differential_r09_supported_standards_finding001() {
    let (pic, stsh, refl) = setup_diff();

    // Reference: spec shape — named record decodes
    let r_bytes = raw_query(
        &pic, refl, anon(), "icrc1_supported_standards", candid::encode_args(()).unwrap(),
    ).unwrap();
    let r_named: Vec<StandardRecord> =
        candid::decode_one(&r_bytes).expect("reference: named-record decode");
    let r_names: Vec<&str> = r_named.iter().map(|s| s.name.as_str()).collect();
    println!("Reference standards: {:?}", r_names);
    assert!(r_names.contains(&"ICRC-1") && r_names.contains(&"ICRC-2"));

    // F-001 FIXED — STSH decodes with the same spec-shaped named record as the
    // reference.
    let s_bytes = raw_query(
        &pic, stsh, anon(), "icrc1_supported_standards", candid::encode_args(()).unwrap(),
    ).unwrap();
    let s_named: Vec<StandardRecord> = candid::decode_one(&s_bytes)
        .expect("FINDING-001 regressed? STSH named-record decode failed");
    let s_names: Vec<&str> = s_named.iter().map(|s| s.name.as_str()).collect();
    println!("STSH standards: {:?}", s_names);
    assert!(s_names.contains(&"ICRC-1") && s_names.contains(&"ICRC-2"));
    // Both ledgers now expose ICRC-10 discovery too.
    for n in ["ICRC-10", "ICRC-21"] {
        assert!(s_names.contains(&n), "STSH advertises {}", n);
        assert!(r_names.contains(&n), "reference advertises {}", n);
    }
}

#[test]
fn test_differential_error_variant_parity() {
    let (pic, stsh, refl) = setup_diff();
    let now = now_ns(&pic);

    for ledger in [stsh, refl] {
        // BadFee — same variant, same payload value
        let mut a = xfer_args(acct(bob()), STSH);
        a.fee = Some(Nat::from(LIVE_FEE + 1));
        match transfer(&pic, ledger, alice(), &a) {
            Err(TransferError::BadFee { expected_fee }) => {
                assert_eq!(to_u128(&expected_fee), LIVE_FEE)
            }
            other => panic!("BadFee parity ({}): {:?}", ledger, other),
        }
        // InsufficientFunds — bob has 0 on both
        match transfer(&pic, ledger, bob(), &xfer_args(acct(carol()), STSH)) {
            Err(TransferError::InsufficientFunds { balance }) => {
                assert_eq!(to_u128(&balance), 0)
            }
            other => panic!("InsufficientFunds parity ({}): {:?}", ledger, other),
        }
        // TooOld — 25h in the past is outside both windows
        let mut a = xfer_args(acct(bob()), STSH);
        a.created_at_time = Some(now - TX_DEDUP_WINDOW_NS - 3_600_000_000_000);
        match transfer(&pic, ledger, alice(), &a) {
            Err(TransferError::TooOld) => {}
            other => panic!("TooOld parity ({}): {:?}", ledger, other),
        }
        // CreatedInFuture — 1h ahead is outside both drift windows
        let mut a = xfer_args(acct(bob()), STSH);
        a.created_at_time = Some(now + 3_600_000_000_000);
        match transfer(&pic, ledger, alice(), &a) {
            Err(TransferError::CreatedInFuture { .. }) => {}
            other => panic!("CreatedInFuture parity ({}): {:?}", ledger, other),
        }
        // Duplicate — identical resubmit with created_at_time
        let mut a = xfer_args(acct(bob()), STSH);
        a.created_at_time = Some(now);
        a.memo = Some(vec![0x42; 8]);
        let b1 = transfer(&pic, ledger, alice(), &a).unwrap();
        match transfer(&pic, ledger, alice(), &a) {
            Err(TransferError::Duplicate { duplicate_of }) => assert_eq!(duplicate_of, b1),
            other => panic!("Duplicate parity ({}): {:?}", ledger, other),
        }
    }
}

#[test]
fn test_differential_drift_boundaries_dev002() {
    let (pic, stsh, refl) = setup_diff();
    let now = now_ns(&pic);

    // DEV-002 (documented, PM-closed): future-dated tx at now + 3 min.
    // STSH drift = 5 min → accepted. Reference drift = 2 min → CreatedInFuture.
    let mut fut = xfer_args(acct(bob()), STSH);
    fut.created_at_time = Some(now + 3 * 60 * 1_000_000_000);
    transfer(&pic, stsh, alice(), &fut).expect("STSH accepts +3min (5min drift)");
    match transfer(&pic, refl, alice(), &fut) {
        Err(TransferError::CreatedInFuture { .. }) => {}
        other => panic!("reference should reject +3min (2min drift): {:?}", other),
    }

    // Old-side boundary: tx aged window + 30s. EMPIRICAL PARITY — both ledgers
    // reject at window + 1ns with TooOld (the reference does NOT extend the
    // old side by its drift; first suite run disproved that hypothesis).
    // DEV-002 is therefore a FUTURE-side-only deviation.
    let mut old = xfer_args(acct(bob()), STSH);
    old.created_at_time = Some(now - TX_DEDUP_WINDOW_NS - 30_000_000_000);
    match transfer(&pic, stsh, alice(), &old) {
        Err(TransferError::TooOld) => {}
        other => panic!("STSH should TooOld at window+30s: {:?}", other),
    }
    match transfer(&pic, refl, alice(), &old) {
        Err(TransferError::TooOld) => {}
        other => panic!("reference should also TooOld at window+30s: {:?}", other),
    }
}

#[test]
fn test_differential_insufficient_allowance_finding002() {
    let (pic, stsh, refl) = setup_diff();
    for ledger in [stsh, refl] {
        approve(&pic, ledger, alice(), &approve_args(&pic, acct(dexp()), 10 * STSH)).unwrap();
    }
    let args = tf_args(acct(alice()), acct(dexp()), 20 * STSH);

    // F-002 FIXED — full parity: both ledgers return the spec variant with the
    // current allowance in the payload.
    for ledger in [stsh, refl] {
        match transfer_from_spec(&pic, ledger, dexp(), &args) {
            Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
                assert_eq!(to_u128(&allowance), 10 * STSH, "parity ({})", ledger)
            }
            other => panic!("{}: expected InsufficientAllowance, got {:?}", ledger, other),
        }
    }
}

#[test]
fn test_differential_expired_allowance_finding003() {
    let (pic, stsh, refl) = setup_diff();
    let exp = now_ns(&pic) + 60_000_000_000;
    for ledger in [stsh, refl] {
        let mut args = approve_args(&pic, acct(dexp()), 10 * STSH);
        args.expires_at = Some(exp);
        approve(&pic, ledger, alice(), &args).unwrap();
    }
    pic.advance_time(Duration::from_secs(120));
    pic.tick();

    let args = tf_args(acct(alice()), acct(dexp()), STSH);
    // Reference: expired approval == no approval → InsufficientAllowance{0},
    // and icrc2_allowance reads 0
    match transfer_from_spec(&pic, refl, dexp(), &args) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), 0)
        }
        other => panic!("reference expired-allowance: {:?}", other),
    }
    assert_eq!(to_u128(&allowance_of(&pic, refl, acct(alice()), acct(dexp())).allowance), 0);

    // F-003 FIXED — STSH matches the reference: expired approval spends as
    // InsufficientAllowance { allowance: 0 }.
    match transfer_from_spec(&pic, stsh, dexp(), &args) {
        Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
            assert_eq!(to_u128(&allowance), 0)
        }
        other => panic!("STSH expired-allowance (FINDING-003 regressed?): {:?}", other),
    }
    // F-005 FIXED — allowance-query parity with the reference: both read 0.
    assert_eq!(
        to_u128(&allowance_of(&pic, stsh, acct(alice()), acct(dexp())).allowance),
        0,
        "expired allowance reads 0 (parity)"
    );
}

#[test]
fn test_differential_allowance_expiry_boundary_fdbr1() {
    let (pic, stsh, refl) = setup_diff();

    // F-DBR-1: the expiry boundary is INCLUSIVE — an allowance whose
    // expires_at equals the current ledger time is already unusable, on all
    // three methods, on BOTH ledgers. The instance clock is landed exactly on
    // expires_at via an exact-delta advance; execution rounds may add a few ns
    // on top, so the assertions read "unusable AT/after the boundary":
    // deterministically green under the inclusive `>=` checks, red or flaky
    // under an exclusive `>`.
    let expiry = now_ns(&pic) + 3_600_000_000_000; // now + 1h, absolute
    for ledger in [stsh, refl] {
        let mut args = approve_args(&pic, acct(dexp()), 10 * STSH);
        args.expires_at = Some(expiry);
        approve(&pic, ledger, alice(), &args).unwrap();
        assert_eq!(
            to_u128(&allowance_of(&pic, ledger, acct(alice()), acct(dexp())).allowance),
            10 * STSH,
            "pre-boundary: allowance live ({})", ledger
        );
    }

    let delta = expiry - now_ns(&pic);
    pic.advance_time(Duration::from_nanos(delta));
    // advance_time alone does not execute a round — tick once so queries see
    // certified state time == expiry exactly (the >= vs > discriminator).
    pic.tick();

    for ledger in [stsh, refl] {
        // (a) icrc2_allowance reads 0 at the boundary
        let a = allowance_of(&pic, ledger, acct(alice()), acct(dexp()));
        assert_eq!(to_u128(&a.allowance), 0, "boundary allowance read ({})", ledger);
        // (b) icrc2_transfer_from at the boundary → InsufficientAllowance { 0 }
        match transfer_from_spec(&pic, ledger, dexp(), &tf_args(acct(alice()), acct(dexp()), STSH)) {
            Err(SpecTransferFromError::InsufficientAllowance { allowance }) => {
                assert_eq!(to_u128(&allowance), 0, "boundary spend ({})", ledger)
            }
            other => panic!("boundary spend ({}): {:?}", ledger, other),
        }
        // (c) F-006 boundary: a NEW approve whose expires_at == now is Expired
        let mut args = approve_args(&pic, acct(carol()), STSH);
        args.expires_at = Some(now_ns(&pic));
        match approve(&pic, ledger, alice(), &args) {
            Err(ApproveError::Expired { .. }) => {}
            other => panic!("approve expires_at == now ({}): {:?}", ledger, other),
        }
    }
}

#[test]
fn test_differential_approve_dedup_finding004() {
    let (pic, stsh, refl) = setup_diff();
    let now = now_ns(&pic);
    let mk = || {
        let mut a = approve_args(&pic, acct(dexp()), 10 * STSH);
        a.created_at_time = Some(now);
        // H-01 / dev007: the factory's default expiry is read from the clock, which
        // ADVANCES between the original and the retry. `approve_dedup_key` hashes
        // the whole argument, so the two calls would hash differently and the retry
        // would be a new approve rather than a Duplicate. Pinned to `now` here — the
        // same derivation the shipped wallet uses, and for the same reason.
        a.expires_at = Some(now + CONFORMANCE_APPROVAL_TTL_NS);
        a.memo = Some(vec![3; 4]);
        a
    };
    // F-004 FIXED — parity: identical approve retry → Duplicate on both ledgers.
    for ledger in [refl, stsh] {
        approve(&pic, ledger, alice(), &mk()).unwrap();
        match approve(&pic, ledger, alice(), &mk()) {
            Err(ApproveError::Duplicate { .. }) => {}
            other => panic!("approve dedup parity ({}): {:?}", ledger, other),
        }
    }
}

#[test]
fn test_differential_approve_expires_at_past_finding006() {
    let (pic, stsh, refl) = setup_diff();
    let past = now_ns(&pic).saturating_sub(3_600_000_000_000);
    let mk = || {
        let mut a = approve_args(&pic, acct(dexp()), 10 * STSH);
        a.expires_at = Some(past);
        a
    };
    // F-006 FIXED — parity: both ledgers reject with Expired { ledger_time }.
    for ledger in [refl, stsh] {
        match approve_outcome(&pic, ledger, alice(), &mk()) {
            Ok(Err(ApproveError::Expired { .. })) => {}
            other => panic!("expires_at-in-past parity ({}): {:?}", ledger, other),
        }
    }
}

// R10-1 RETARGET (lane A-3) — the ZERO-AMOUNT half only; the self-approve half
// below is byte-for-byte unchanged.
//
// WAS: the zero-amount half asserted `matches!(z_stsh, Ok(Ok(_)))` — "STSH
//      accepts zero-amount", i.e. parity with the reference ledger.
// NOW: STSH refuses, the reference ledger still accepts. That is a DIFFERENTIAL
//      DEVIATION, and registering those is this file's whole purpose — so both
//      outcomes are recorded and the divergence is asserted, hence `dev005`.
// CAUSE: R10-1.
#[test]
fn test_differential_self_approve_and_zero_amount_outcomes_dev005() {
    let (pic, stsh, refl) = setup_diff();

    // Self-approval (SA-03): record both outcomes for the deviation register
    let self_stsh = approve_outcome(&pic, stsh, alice(), &approve_args(&pic, acct(alice()), STSH));
    let self_ref = approve_outcome(&pic, refl, alice(), &approve_args(&pic, acct(alice()), STSH));
    println!("self-approve — STSH: {:?}", self_stsh);
    println!("self-approve — reference: {:?}", self_ref);
    assert!(matches!(self_stsh, Ok(Ok(_))), "STSH allows self-approval (documented)");

    // Zero-amount transfer (E-07 differential)
    let z_stsh = transfer_outcome(&pic, stsh, alice(), &xfer_args(acct(bob()), 0));
    let z_ref = transfer_outcome(&pic, refl, alice(), &xfer_args(acct(bob()), 0));
    println!("zero-amount transfer — STSH: {:?}", z_stsh);
    println!("zero-amount transfer — reference: {:?}", z_ref);
    // STSH now REFUSES (R10-1) with the pinned GenericError code...
    match &z_stsh {
        Ok(Err(TransferError::GenericError { error_code, .. })) => {
            assert_eq!(*error_code, Nat::from(5u32), "dev005: pinned R10-1 error code");
        }
        other => panic!("dev005: expected the R10-1 zero-amount refusal from STSH, got {:?}", other),
    }
    // ...while the REFERENCE ledger still accepts. Recording both sides is the
    // deviation register's job; do not "fix" this into parity.
    assert!(
        matches!(z_ref, Ok(Ok(_))),
        "dev005: the reference ledger still accepts zero-amount — this divergence IS the finding"
    );
}

#[test]
fn test_differential_memo_length_policy() {
    let (pic, stsh, refl) = setup_diff();
    let mut a = xfer_args(acct(bob()), STSH);
    a.memo = Some(vec![0xAA; 64]);
    // STSH: unbounded memo → Ok. Reference (default max_memo_length = 32):
    // rejects. Recorded for the deviation register (DEV-004 companion).
    transfer(&pic, stsh, alice(), &a).expect("STSH accepts 64-byte memo");
    let r = transfer_outcome(&pic, refl, alice(), &a);
    println!("64-byte memo — reference outcome: {:?}", r);
    assert!(
        !matches!(r, Ok(Ok(_))),
        "reference default config should reject a 64-byte memo"
    );
}

#[test]
fn test_differential_ser03_04_large_nat_amounts() {
    let (pic, stsh, refl) = setup_diff();

    // SER-03: 2^64 − 1 — inside u64. Both reject as InsufficientFunds (> supply).
    let a1 = xfer_args(acct(bob()), (u64::MAX) as u128);
    match transfer(&pic, stsh, alice(), &a1) {
        Err(TransferError::InsufficientFunds { .. }) => {}
        other => panic!("STSH 2^64-1: {:?}", other),
    }
    match transfer_outcome(&pic, refl, alice(), &a1) {
        Ok(Err(TransferError::InsufficientFunds { .. })) => {}
        other => println!("reference 2^64-1 outcome (recorded): {:?}", other),
    }

    // SER-04: exactly 2^64 — exceeds the reference's internal u64 token type;
    // STSH (u128 internal) handles it as a clean InsufficientFunds.
    let a2 = xfer_args(acct(bob()), (u64::MAX as u128) + 1);
    match transfer(&pic, stsh, alice(), &a2) {
        Err(TransferError::InsufficientFunds { .. }) => {}
        other => panic!("STSH 2^64: {:?}", other),
    }
    let r = transfer_outcome(&pic, refl, alice(), &a2);
    println!("reference 2^64 outcome (recorded): {:?}", r);
}

#[test]
fn test_differential_ser05_subaccount_default_equivalence() {
    let (pic, stsh, refl) = setup_diff();
    for ledger in [stsh, refl] {
        let via_none = balance_of(&pic, ledger, &acct(alice()));
        let via_zero = balance_of(&pic, ledger, &Account {
            owner: alice(),
            subaccount: Some([0u8; 32]),
        });
        assert_eq!(via_none, via_zero, "SER-05 ({}): zero-sub == default", ledger);
    }
}

// =============================================================================
// §4.2.1 / Lane 4 item 7 — ICRC-21 consent messages (advertised standard)
// =============================================================================
//
// ICRC-21 SPEC shapes (mirrored from the reference ledger.did, which carries
// the standard types verbatim):
//   request:  record { method : text; arg : blob;
//                      user_preferences : record {
//                          metadata : record { language : text;
//                                              utc_offset_minutes : opt int16 };
//                          device_spec : opt variant { GenericDisplay;
//                                                      FieldsDisplay } } }
//   response: variant { Ok : record { consent_message : variant {
//                              GenericDisplayMessage : text;
//                              FieldsDisplayMessage : ... };
//                          metadata : record { ... } };
//               Err : variant { UnsupportedCanisterCall : record {...}; ... } }
//
// STSH's shapes (lib.rs :956–995):
//   request:  record { method; arg; user_preferences : record { language : opt text } }
//   response: variant { Ok : record { consent_message : text }; Err : text }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21Metadata {
    language: String,
    utc_offset_minutes: Option<i16>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21DeviceSpec {
    GenericDisplay,
    FieldsDisplay,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21MessageSpec {
    metadata: Icrc21Metadata,
    device_spec: Option<Icrc21DeviceSpec>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21SpecRequest {
    method: String,
    arg: Vec<u8>,
    user_preferences: Icrc21MessageSpec,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21FieldsDisplay {
    intent: String,
    fields: Vec<(String, Icrc21Value)>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21Value {
    TokenAmount { decimals: u8, amount: u64, symbol: String },
    TimestampSeconds { amount: u64 },
    DurationSeconds { amount: u64 },
    Text { content: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum Icrc21SpecMessage {
    GenericDisplayMessage(String),
    FieldsDisplayMessage(Icrc21FieldsDisplay),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Icrc21SpecConsentInfo {
    consent_message: Icrc21SpecMessage,
    metadata: Icrc21Metadata,
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

fn icrc21_spec_request(method: &str, arg: Vec<u8>) -> Vec<u8> {
    candid::encode_one(Icrc21SpecRequest {
        method: method.to_string(),
        arg,
        user_preferences: Icrc21MessageSpec {
            metadata: Icrc21Metadata { language: "en".to_string(), utc_offset_minutes: None },
            device_spec: Some(Icrc21DeviceSpec::GenericDisplay),
        },
    })
    .unwrap()
}

#[test]
fn test_differential_icrc21_response_shape_finding007() {
    let (pic, stsh, refl) = setup_diff();
    let transfer_arg = candid::encode_one(&xfer_args(acct(bob()), STSH)).unwrap();
    let req = icrc21_spec_request("icrc1_transfer", transfer_arg);

    // F-007 FIXED — full parity: BOTH ledgers answer the spec-shaped request
    // with a spec-shaped response (variant { Ok : consent_info; Err :
    // icrc21_error }), decoded by the same client types, as UPDATE calls.
    for (label, ledger) in [("reference", refl), ("STSH", stsh)] {
        let bytes = raw_update(
            &pic, ledger, alice(), "icrc21_canister_call_consent_message", req.clone(),
        ).unwrap_or_else(|e| panic!("{} icrc21 call rejected: {}", label, e));
        let r: Result<Icrc21SpecConsentInfo, Icrc21Error> = candid::decode_one(&bytes)
            .unwrap_or_else(|e| panic!("{} (F-007 regressed?): spec decode failed: {}", label, e));
        match r {
            Ok(info) => {
                assert_eq!(info.metadata.language, "en", "{}: metadata echoed", label);
                match info.consent_message {
                    Icrc21SpecMessage::GenericDisplayMessage(m) => {
                        println!("{} consent message:\n{}\n", label, m);
                        assert!(m.contains("STSH"), "{}: names the token", label);
                        assert!(
                            m.to_lowercase().contains("fee"),
                            "{} (F-008): the fee must be stated", label
                        );
                    }
                    other => panic!("{}: expected GenericDisplayMessage, got {:?}", label, other),
                }
            }
            Err(e) => panic!("{} icrc21 unexpectedly errored: {:?}", label, e),
        }
    }
}

/// Decode helper for STSH's (now spec-shaped) ICRC-21 response and extract the
/// GenericDisplayMessage text.
fn icrc21_message(pic: &PocketIc, cid: Principal, caller: Principal, req: Vec<u8>) -> String {
    let bytes = raw_update(pic, cid, caller, "icrc21_canister_call_consent_message", req)
        .expect("icrc21 call");
    let r: Result<Icrc21SpecConsentInfo, Icrc21Error> =
        candid::decode_one(&bytes).expect("spec-shape decode");
    match r.expect("Ok consent info").consent_message {
        Icrc21SpecMessage::GenericDisplayMessage(m) => m,
        other => panic!("expected GenericDisplayMessage, got {:?}", other),
    }
}

#[test]
fn test_icrc21_message_content_and_unsupported_method() {
    let (pic, stsh) = setup();

    // F-008 FIXED — transfer message states amount, recipient INCLUDING the
    // subaccount, the fee, and the memo.
    let mut t = xfer_args(acct_sub(bob(), 7), 5 * STSH);
    t.memo = Some(vec![0xAB, 0xCD]);
    let transfer_arg = candid::encode_one(&t).unwrap();
    let msg = icrc21_message(
        &pic, stsh, alice(), icrc21_spec_request("icrc1_transfer", transfer_arg),
    );
    println!("transfer consent:\n{}\n", msg);
    assert!(msg.contains("5.00000000 STSH"), "amount rendered exactly: {}", msg);
    assert!(msg.contains(&bob().to_text()), "recipient rendered: {}", msg);
    assert!(msg.contains("subaccount 0x"), "recipient SUBACCOUNT rendered: {}", msg);
    assert!(msg.contains("**Fee:**"), "fee stated (F-008): {}", msg);
    assert!(msg.contains("0.00000000 STSH"), "zero fee rendered exactly: {}", msg);
    assert!(msg.contains("**Memo:** 0xabcd"), "memo rendered: {}", msg);

    // approve message: spender + allowance + fee + expiry wording
    let approve_arg = candid::encode_one(&approve_args(&pic, acct(dexp()), 7 * STSH)).unwrap();
    let msg = icrc21_message(
        &pic, stsh, alice(), icrc21_spec_request("icrc2_approve", approve_arg),
    );
    println!("approve consent:\n{}\n", msg);
    assert!(msg.contains("7.00000000 STSH") && msg.contains(&dexp().to_text()), "{}", msg);
    assert!(msg.contains("**Approval fee:**"), "approve fee stated: {}", msg);
    assert!(msg.contains("**Expires:**"), "expiry stated: {}", msg);

    // transfer_from message
    let tf_arg = candid::encode_one(&tf_args(acct(alice()), acct(carol()), 3 * STSH)).unwrap();
    let msg = icrc21_message(
        &pic, stsh, dexp(), icrc21_spec_request("icrc2_transfer_from", tf_arg),
    );
    assert!(msg.contains("3.00000000 STSH") && msg.contains(&carol().to_text()), "{}", msg);
    assert!(msg.contains("**Fee:**"), "transfer_from fee stated: {}", msg);

    // Unsupported method → typed UnsupportedCanisterCall (no trap, no generic string)
    let bytes = raw_update(
        &pic, stsh, alice(), "icrc21_canister_call_consent_message",
        icrc21_spec_request("icrc1_balance_of", vec![]),
    ).expect("must not trap on unsupported method");
    let r: Result<Icrc21SpecConsentInfo, Icrc21Error> = candid::decode_one(&bytes).unwrap();
    match r {
        Err(Icrc21Error::UnsupportedCanisterCall(info)) => {
            assert!(info.description.contains("icrc1_balance_of"), "{}", info.description)
        }
        other => panic!("expected UnsupportedCanisterCall, got {:?}", other),
    }

    // Undecodable argument → typed ConsentMessageUnavailable
    let bytes = raw_update(
        &pic, stsh, alice(), "icrc21_canister_call_consent_message",
        icrc21_spec_request("icrc1_transfer", vec![0xDE, 0xAD]),
    ).expect("must not trap on garbage arg");
    let r: Result<Icrc21SpecConsentInfo, Icrc21Error> = candid::decode_one(&bytes).unwrap();
    assert!(
        matches!(r, Err(Icrc21Error::ConsentMessageUnavailable(_))),
        "expected ConsentMessageUnavailable, got {:?}", r
    );

    // T-ICRC-L1 FIXED (was: anonymous served a consent message rendering
    // "From: <anonymous>"): the consent path now fails closed on the anonymous
    // principal with a typed GenericError (code 6).
    let anon_arg = candid::encode_one(&xfer_args(acct(bob()), STSH)).unwrap();
    let bytes = raw_update(
        &pic, stsh, anon(), "icrc21_canister_call_consent_message",
        icrc21_spec_request("icrc1_transfer", anon_arg),
    ).expect("must not trap on anonymous caller");
    let r: Result<Icrc21SpecConsentInfo, Icrc21Error> = candid::decode_one(&bytes).unwrap();
    match r {
        Err(Icrc21Error::GenericError { error_code, description }) => {
            assert_eq!(to_u128(&error_code), 6, "T-ICRC-L1 pinned error code");
            assert!(description.contains("anonymous"), "{}", description);
        }
        other => panic!("T-ICRC-L1: expected typed anonymous refusal, got {:?}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// T-ICRC-1 — allowance compound-key injectivity (HOLD-LAUNCH fix arms)
// ─────────────────────────────────────────────────────────────────────────────

/// Reviewer PoC pair (A1_TOKEN_ICRC_CAMPAIGN_2026-08-27 §1): under the pre-fix
/// plain-concat key these two DISTINCT (from, spender) pairs shared one stored
/// row. All principals 29 bytes (real self-authenticating length).
fn poc_pairs() -> ((Account, Account), (Account, Account)) {
    let p_o = p(0x50);
    let q_o = p(0x51);
    let r_o = p(0x52);
    let mut s = [0u8; 32]; // spender sub S = [0xAA,0xBB] || [29] || R
    s[0] = 0xAA; s[1] = 0xBB; s[2] = 29;
    s[3..32].copy_from_slice(r_o.as_slice());
    let mut a = [0u8; 32]; // victim sub A = [29] || Q || [0xAA,0xBB]
    a[0] = 29;
    a[1..30].copy_from_slice(q_o.as_slice());
    a[30] = 0xAA; a[31] = 0xBB;
    (
        (Account { owner: p_o, subaccount: None },  Account { owner: q_o, subaccount: Some(s) }),
        (Account { owner: p_o, subaccount: Some(a) }, Account { owner: r_o, subaccount: None }),
    )
}

/// GREEN-after arm of the reviewer PoC: approving pair 1 leaves pair 2's
/// allowance at zero (pre-fix, pair 2 read pair 1's row — the RED half lives
/// as a unit test against the replicated old scheme in the canister crate).
#[test]
fn test_ticrc1_poc_pair_allowances_isolated() {
    let (pic, stsh) = setup();
    let ((from1, spender1), (from2, spender2)) = poc_pairs();
    // Fund the victim's colliding accounts so approve fees (if any) clear.
    transfer(&pic, stsh, alice(), &xfer_args(from1.clone(), 10 * STSH)).unwrap();
    let mut args = approve_args(&pic, spender1.clone(), 7 * STSH);
    args.from_subaccount = from1.subaccount;
    approve(&pic, stsh, from1.owner, &args).expect("pair-1 approve");

    let a1 = allowance_of(&pic, stsh, from1.clone(), spender1.clone());
    assert_eq!(to_u128(&a1.allowance), 7 * STSH, "pair 1 allowance stored");
    let a2 = allowance_of(&pic, stsh, from2.clone(), spender2.clone());
    assert_eq!(to_u128(&a2.allowance), 0, "PoC pair 2 must NOT alias pair 1's row");

    // And R (pair 2's spender) cannot spend the victim's pair-2 account.
    let mut tf = tf_args(from2, acct(carol()), STSH);
    tf.spender_subaccount = spender2.subaccount;
    let res = transfer_from_spec(&pic, stsh, spender2.owner, &tf);
    assert!(
        matches!(res, Err(SpecTransferFromError::InsufficientAllowance { .. })),
        "colliding-pair spend must refuse on allowance, got {:?}", res
    );
}

/// Dual-nonzero-subaccount round-trip: allowance approved with a non-zero
/// subaccount on BOTH the from-account and the spender survives store, read
/// and spend — the axis prior arms never exercised.
#[test]
fn test_ticrc1_dual_nonzero_subaccount_allowance_roundtrip() {
    let (pic, stsh) = setup();
    let from = acct_sub(alice(), 0x11);
    let spender = acct_sub(dexp(), 0x22);
    transfer(&pic, stsh, alice(), &xfer_args(from.clone(), 10 * STSH)).unwrap();

    let mut args = approve_args(&pic, spender.clone(), 5 * STSH);
    args.from_subaccount = from.subaccount;
    approve(&pic, stsh, alice(), &args).expect("dual-sub approve");

    // Round-trip read: exact pair reads back; neighbouring pairs read zero.
    assert_eq!(to_u128(&allowance_of(&pic, stsh, from.clone(), spender.clone()).allowance), 5 * STSH);
    assert_eq!(to_u128(&allowance_of(&pic, stsh, acct(alice()), spender.clone()).allowance), 0);
    assert_eq!(to_u128(&allowance_of(&pic, stsh, from.clone(), acct(dexp())).allowance), 0);

    // Spend through the dual-sub allowance.
    let mut tf = tf_args(from.clone(), acct(carol()), 2 * STSH);
    tf.spender_subaccount = spender.subaccount;
    transfer_from_spec(&pic, stsh, dexp(), &tf).expect("dual-sub transfer_from");
    assert_eq!(to_u128(&allowance_of(&pic, stsh, from, spender).allowance), 3 * STSH - LIVE_FEE);
    assert_eq!(balance_of(&pic, stsh, &acct(carol())), 2 * STSH);
}

// =============================================================================
// dev006 (R-1 S1) — zero-amount icrc2_approve is refused UNLESS it revokes
// =============================================================================
//
// Three SEPARATELY NAMED tests, because one test asserting all three claims
// could be made vacuous by a single edit, and because the register
// (canisters/token/NOTE_A-3_icrc_deviation.md) binds each of them by name:
//
//   (1) the STSH refusal — deleting the guard drives THIS test RED and leaves
//       (2) and (3) untouched;
//   (2) the reference side — proves the divergence is real rather than assumed,
//       and is not satisfied by any STSH-side assertion;
//   (3) revocation — the reason the guard is narrow rather than blanket, and the
//       one a sibling-shaped `amount == 0` refusal would break.

/// dev006 (1): with NO live allowance there is nothing to revoke, so a zero
/// approve is the free, unauthenticated state-growth write the guard refuses.
#[test]
fn test_icrc2_dev006_stsh_refuses_zero_approve_without_live_allowance() {
    let (pic, stsh) = setup();
    match approve_outcome(&pic, stsh, alice(), &approve_args(&pic, acct(bob()), 0)) {
        Ok(Err(ApproveError::GenericError { error_code, .. })) => {
            assert_eq!(error_code, Nat::from(5u32), "dev006: pinned R10-1 error code");
        }
        other => panic!("dev006: expected the zero-amount refusal from STSH, got {:?}", other),
    }
}

/// dev006 (2): the REFERENCE ledger still accepts the same call. Recording both
/// sides is what makes this a deviation rather than a conformance fix — do not
/// "fix" it into parity.
#[test]
fn test_icrc2_dev006_reference_accepts_zero_approve() {
    let (pic, _stsh, refl) = setup_diff();
    let r = approve_outcome(&pic, refl, alice(), &approve_args(&pic, acct(bob()), 0));
    println!("dev006 zero approve — reference: {:?}", r);
    assert!(
        matches!(r, Ok(Ok(_))),
        "dev006: the reference ledger accepts a zero approve — this divergence IS the \
         registered deviation, got {:?}",
        r
    );
}

/// dev006 (3): a zero approve against a LIVE allowance is REVOCATION and
/// succeeds, clearing it. This is the wallet's own revocation shape
/// (wallet/src/ui/shieldFlow.ts, revokeShieldAllowance).
#[test]
fn test_icrc2_dev006_stsh_revokes_live_allowance_with_zero_approve() {
    let (pic, stsh) = setup();

    approve_outcome(&pic, stsh, alice(), &approve_args(&pic, acct(bob()), STSH))
        .expect("approve call")
        .expect("dev006: a nonzero approve must succeed");

    let mut revoke = approve_args(&pic, acct(bob()), 0);
    revoke.expected_allowance = Some(Nat::from(STSH));
    approve_outcome(&pic, stsh, alice(), &revoke)
        .expect("revoke call")
        .expect("dev006: approve(0) against a LIVE allowance is revocation and must succeed");

    let a = allowance_of(&pic, stsh, acct(alice()), acct(bob()));
    assert_eq!(a.allowance, Nat::from(0u32), "dev006: the allowance must read 0 after revocation");
}
