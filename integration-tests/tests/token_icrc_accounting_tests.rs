// =============================================================================
// STSH — ICRC-1/ICRC-2 token accounting tests (PocketIC)
// Pass 3 remediation: QA-DEF-018, QA-DEF-019, QA-DEF-021
// =============================================================================
//
// These cover three token-canister defects that require real caller identity and
// therefore cannot run as host unit tests:
//
//   QA-DEF-018 — icrc2_transfer_from must validate args.fee against the live fee
//                (BadFee), exactly like icrc1_transfer / icrc2_approve.
//     test_icrc_t1 — fee = Some(live_fee + 1)  → BadFee, no state change.
//     test_icrc_t2 — fee = Some(live_fee)      → succeeds.
//     test_icrc_t3 — fee = None                → succeeds using the live fee.
//
//   QA-DEF-019 — icrc2_transfer_from must check the allowance AND the liquid
//                balance BEFORE any mutation. On the IC a returned Err commits
//                already-applied writes, so the old "reduce allowance, then maybe
//                fail the balance debit" ordering left a phantom allowance
//                decrement on a failed transfer.
//     test_icrc_t4 — partially locked owner, transfer exceeds liquid → the
//                    allowance is UNCHANGED after the failed transfer_from.
//     test_icrc_t5 — fully locked owner (liquid == 0) → same: allowance unchanged.
//
//   QA-DEF-021 — None and Some([0u8;32]) are the same ICRC-1 account; they must
//                key to the same balance / allowance entry.
//     test_icrc_t6 — balance_of({owner, Some([0;32])}) == balance_of({owner,None})
//                    and an icrc1_transfer from the explicit-zero subaccount debits
//                    the same (default) account.
//
// Only the token Wasm is needed: lock_for_staking is driven directly from a bare
// principal acting as the authorized staking caller (same pattern as
// lane_b_safety::test_lb03 / test_lb04).
//
// PREREQUISITES:
//   1. cargo build --target wasm32-unknown-unknown --release -p stsh_token
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests --test token_icrc_accounting_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn token_wasm() -> Vec<u8> {
    let path = env!("TOKEN_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read stsh_token Wasm at {}: {}.\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token",
            path, e
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH
const STSH: u128 = 100_000_000; // 1 STSH in base units

// DEF-050B-1: must match the token canister constants exactly.
const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000; // 24h
const PERMITTED_DRIFT_NS: u64 = 5 * 60 * 1_000_000_000;       // 5 min

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — field names/order must match the canister Candid types exactly.
// ─────────────────────────────────────────────────────────────────────────────

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

/// Token init: all supply to `recipient` (subaccount: None); `staking` is the
/// authorized lock_for_staking caller.
fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id:          "all".to_string(),
            category_name:        "All tokens".to_string(),
            amount:               TOTAL_SUPPLY,
            recipient,
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }],
        treasury:         p(0x01),
        staking_canister: staking,
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferArgs {
    from_subaccount: Option<[u8; 32]>,
    to:              Account,
    amount:          u128,
    fee:             Option<u128>,
    memo:            Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount:    Option<[u8; 32]>,
    spender:            Account,
    amount:             u128,
    expected_allowance: Option<u128>,
    expires_at:         Option<u64>,
    fee:                Option<u128>,
    memo:               Option<Vec<u8>>,
    created_at_time:    Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferFromArgs {
    spender_subaccount: Option<[u8; 32]>,
    from:               Account,
    to:                 Account,
    amount:             u128,
    fee:                Option<u128>,
    memo:               Option<Vec<u8>>,
    created_at_time:    Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllowanceArgs { account: Account, spender: Account }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Allowance { allowance: Nat, expires_at: Option<u64> }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TransferError {
    BadFee             { expected_fee: Nat },
    BadBurn            { min_burn_amount: Nat },
    InsufficientFunds  { balance: Nat },
    TooOld,
    CreatedInFuture    { ledger_time: u64 },
    Duplicate          { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError       { error_code: Nat, message: String },
}

/// ICRC remediation F-002: icrc2_transfer_from now returns the ICRC-2 spec
/// TransferFromError (TransferError + InsufficientAllowance). The
/// transfer_from helper decodes with this mirror.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TransferFromError {
    BadFee             { expected_fee: Nat },
    BadBurn            { min_burn_amount: Nat },
    InsufficientFunds  { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture    { ledger_time: u64 },
    Duplicate          { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError       { error_code: Nat, message: String },
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

fn anon() -> Principal { Principal::anonymous() }

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &TokenInitArgs) {
    let args = candid::encode_one(init).expect("encode init args");
    pic.install_canister(cid, wasm, args, None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

fn to_u128(n: Nat) -> u128 { n.0.to_string().parse::<u128>().unwrap_or(0) }

fn deploy_token(pic: &PocketIc, owner: Principal, staking: Principal) -> Principal {
    let token = create_canister(pic);
    install(pic, token, token_wasm(), &all_to(owner, staking));
    token
}

fn live_fee(pic: &PocketIc, token: Principal) -> u128 {
    to_u128(decode(
        "icrc1_fee",
        pic.query_call(token, anon(), "icrc1_fee", candid::encode_args(()).unwrap()),
    ))
}

fn balance_of(pic: &PocketIc, token: Principal, account: Account) -> u128 {
    to_u128(decode(
        "icrc1_balance_of",
        pic.query_call(token, anon(), "icrc1_balance_of", candid::encode_one(account).unwrap()),
    ))
}

fn balance(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    balance_of(pic, token, Account { owner, subaccount: None })
}

fn staking_locked(pic: &PocketIc, token: Principal, owner: Principal) -> u128 {
    to_u128(decode(
        "staking_locked_balance",
        pic.query_call(token, anon(), "staking_locked_balance", candid::encode_one(owner).unwrap()),
    ))
}

fn allowance_of(pic: &PocketIc, token: Principal, owner: Principal, spender: Principal) -> u128 {
    let a: Allowance = decode(
        "icrc2_allowance",
        pic.query_call(token, anon(), "icrc2_allowance", candid::encode_one(AllowanceArgs {
            account: Account { owner, subaccount: None },
            spender: Account { owner: spender, subaccount: None },
        }).unwrap()),
    );
    to_u128(a.allowance)
}

/// 1 h, well inside MAX_APPROVAL_TTL_NS (24 h).
const ACCOUNTING_APPROVAL_TTL_NS: u64 = 60 * 60 * 1_000_000_000;

fn approve(pic: &PocketIc, token: Principal, owner: Principal, spender: Principal, amount: u128)
    -> Result<Nat, ApproveError>
{
    decode(
        "icrc2_approve",
        pic.update_call(token, owner, "icrc2_approve", candid::encode_one(ApproveArgs {
            from_subaccount: None,
            spender: Account { owner: spender, subaccount: None },
            amount,
            expected_allowance: None,
            // H-01 / dev007: `expires_at` is MANDATORY on icrc2_approve for any
            // approve that writes a row. A bounded default keeps every case in this
            // suite testing accounting rather than the admission rule; a zero
            // approve is revocation, writes no row, and is exempt (I-A1).
            expires_at: if amount == 0 {
                None
            } else {
                Some(now_ns(pic) + ACCOUNTING_APPROVAL_TTL_NS)
            },
            fee: None,
            memo: None,
            created_at_time: None,
        }).unwrap()),
    )
}

fn transfer_from(
    pic: &PocketIc, token: Principal, spender: Principal,
    from: Account, to: Account, amount: u128, fee: Option<u128>,
) -> Result<Nat, TransferFromError> {
    decode(
        "icrc2_transfer_from",
        pic.update_call(token, spender, "icrc2_transfer_from", candid::encode_one(TransferFromArgs {
            spender_subaccount: None,
            from,
            to,
            amount,
            fee,
            memo: None,
            created_at_time: None,
        }).unwrap()),
    )
}

fn lock_for_staking(pic: &PocketIc, token: Principal, staking: Principal, holder: Principal, amount: u128)
    -> Result<(), String>
{
    decode(
        "lock_for_staking",
        pic.update_call(token, staking, "lock_for_staking",
                        candid::encode_args((holder, amount)).unwrap()),
    )
}

// ── DEF-050B-1 helpers ─────────────────────────────────────────────────────────

/// Current PocketIC time in nanoseconds since the Unix epoch — the same clock the
/// canister reads via ic_cdk::api::time().
fn now_ns(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch()
}

/// transfer_from with explicit memo and created_at_time (the dedup-relevant fields
/// the bare `transfer_from` helper pins to None).
#[allow(clippy::too_many_arguments)]
fn transfer_from_ext(
    pic: &PocketIc, token: Principal, spender: Principal,
    from: Account, to: Account, amount: u128, fee: Option<u128>,
    memo: Option<Vec<u8>>, created_at_time: Option<u64>,
) -> Result<Nat, TransferFromError> {
    decode(
        "icrc2_transfer_from",
        pic.update_call(token, spender, "icrc2_transfer_from", candid::encode_one(TransferFromArgs {
            spender_subaccount: None,
            from,
            to,
            amount,
            fee,
            memo,
            created_at_time,
        }).unwrap()),
    )
}

/// In-place upgrade of the token canister (runs pre_upgrade/post_upgrade). The
/// token's post_upgrade takes no args.
fn upgrade_token(pic: &PocketIc, token: Principal) {
    pic.upgrade_canister(token, token_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("token upgrade: pre/post_upgrade hooks trapped or controller check failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-018 — transfer_from fee validation
// ─────────────────────────────────────────────────────────────────────────────

// test_icrc_t1 — fee = Some(live_fee + 1) → BadFee; allowance and balances all
// unchanged (the fee is validated before any mutation).
#[test]
fn test_icrc_t1_transfer_from_bad_fee_rejected() {
    let pic = PocketIc::new();
    let owner     = p(0xA0);
    let spender   = p(0xA1);
    let recipient = p(0xA2);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("t1: approve must succeed; got {:?}", e));

    let allow_before = allowance_of(&pic, token, owner, spender);
    let owner_before = balance(&pic, token, owner);
    assert_eq!(allow_before, allow_amount, "t1: precondition — allowance set");

    let xfer = transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        1_000 * STSH,
        Some(fee + 1), // wrong fee
    );

    match &xfer {
        Err(TransferFromError::BadFee { expected_fee }) => {
            assert_eq!(to_u128(expected_fee.clone()), fee,
                "t1: BadFee must report the live fee as expected_fee");
        }
        other => panic!("t1: expected BadFee, got {:?}", other),
    }

    // No mutation whatsoever.
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_before,
        "t1: allowance must be unchanged after a BadFee rejection");
    assert_eq!(balance(&pic, token, owner), owner_before,
        "t1: owner balance must be unchanged after a BadFee rejection");
    assert_eq!(balance(&pic, token, recipient), 0,
        "t1: recipient must receive nothing");
}

// test_icrc_t2 — fee = Some(live_fee) (correct) → succeeds; amount moves,
// owner debited amount + fee, allowance reduced by amount + fee.
#[test]
fn test_icrc_t2_transfer_from_correct_fee_succeeds() {
    let pic = PocketIc::new();
    let owner     = p(0xB0);
    let spender   = p(0xB1);
    let recipient = p(0xB2);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("t2: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);

    let amount = 1_000 * STSH;
    let xfer = transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount,
        Some(fee), // correct fee
    );
    assert!(xfer.is_ok(), "t2: transfer_from with the correct fee must succeed; got {:?}", xfer);

    assert_eq!(balance(&pic, token, recipient), amount,
        "t2: recipient must receive exactly the amount");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee,
        "t2: owner must be debited amount + fee");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - amount - fee,
        "t2: allowance must be reduced by amount + fee");
}

// test_icrc_t3 — fee = None → succeeds using the live fee silently (ICRC-2
// compliant: no fee validation when None).
#[test]
fn test_icrc_t3_transfer_from_none_fee_succeeds() {
    let pic = PocketIc::new();
    let owner     = p(0xC0);
    let spender   = p(0xC1);
    let recipient = p(0xC2);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("t3: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);

    let amount = 1_000 * STSH;
    let xfer = transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount,
        None, // no fee supplied → live fee applied silently
    );
    assert!(xfer.is_ok(), "t3: transfer_from with fee=None must succeed; got {:?}", xfer);

    assert_eq!(balance(&pic, token, recipient), amount,
        "t3: recipient must receive exactly the amount");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee,
        "t3: owner must be debited amount + live fee");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - amount - fee,
        "t3: allowance must be reduced by amount + live fee");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-019 — allowance mutation ordering (no phantom decrement on failure)
// ─────────────────────────────────────────────────────────────────────────────

// test_icrc_t4 — owner partially locked so transfer exceeds liquid (but is within
// allowance). transfer_from must fail AND leave the allowance untouched.
#[test]
fn test_icrc_t4_insufficient_liquid_allowance_unchanged() {
    let pic = PocketIc::new();
    let owner     = p(0xD0);
    let spender   = p(0xD1);
    let recipient = p(0xD2);
    let staking   = p(0x02); // authorized lock caller

    let token = deploy_token(&pic, owner, staking);

    // Lock almost everything, leaving a small liquid buffer (enough for the approve
    // fee, far less than the transfer amount).
    let lock_amount = TOTAL_SUPPLY - 100_000;
    lock_for_staking(&pic, token, staking, owner, lock_amount)
        .unwrap_or_else(|e| panic!("t4: lock must succeed; got {:?}", e));

    // Approve a large allowance — valid even though it exceeds liquid.
    let big_allowance = 10_000_000u128;
    approve(&pic, token, owner, spender, big_allowance)
        .unwrap_or_else(|e| panic!("t4: approve must succeed; got {:?}", e));

    let allow_before = allowance_of(&pic, token, owner, spender);
    let owner_before = balance(&pic, token, owner);
    assert_eq!(allow_before, big_allowance, "t4: precondition — full allowance set");

    // transfer_from for more than liquid (but within allowance) → must fail.
    let amount = 1_000_000u128; // total_debit ~1_010_000 >> liquid ~90_000
    let xfer = transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount,
        None,
    );
    assert!(
        matches!(xfer, Err(TransferFromError::InsufficientFunds { .. })),
        "t4: transfer exceeding liquid must return InsufficientFunds; got {:?}", xfer
    );

    // QA-DEF-019: the allowance must NOT have been decremented by the failed call.
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_before,
        "t4: allowance must be UNCHANGED after a failed transfer_from (no phantom decrement)");
    assert_eq!(balance(&pic, token, owner), owner_before,
        "t4: owner balance must be unchanged after the failed transfer_from");
    assert_eq!(balance(&pic, token, recipient), 0,
        "t4: recipient must receive nothing");
    assert_eq!(staking_locked(&pic, token, owner), lock_amount,
        "t4: locked stake must be unchanged");
}

// test_icrc_t5 — owner entirely locked (liquid == 0). A transfer within the
// allowance must fail and leave the allowance untouched.
#[test]
fn test_icrc_t5_fully_locked_allowance_unchanged() {
    let pic = PocketIc::new();
    let owner     = p(0xE0);
    let spender   = p(0xE1);
    let recipient = p(0xE2);
    let staking   = p(0x02);

    let token = deploy_token(&pic, owner, staking);

    // Approve FIRST (while liquid is available so the approve fee succeeds), then
    // lock the entire remaining balance so liquid == 0.
    let big_allowance = 10_000_000u128;
    approve(&pic, token, owner, spender, big_allowance)
        .unwrap_or_else(|e| panic!("t5: approve must succeed; got {:?}", e));

    let owner_before = balance(&pic, token, owner); // TOTAL_SUPPLY - approve fee
    lock_for_staking(&pic, token, staking, owner, owner_before)
        .unwrap_or_else(|e| panic!("t5: full lock must succeed; got {:?}", e));
    assert_eq!(staking_locked(&pic, token, owner), owner_before, "t5: fully locked");

    let allow_before = allowance_of(&pic, token, owner, spender);
    assert_eq!(allow_before, big_allowance, "t5: precondition — full allowance set");

    // Any positive transfer now exceeds liquid (0) → must fail. The amount is
    // genuinely WITHIN the allowance (1_000_000 <= 10_000_000) so the failure
    // is the LIQUID check (InsufficientFunds), not the allowance check.
    // (Pre-F-002 this used 1 STSH = 100_000_000 — actually ABOVE the allowance —
    // and passed only because allowance shortfalls were then also reported as
    // InsufficientFunds; the spec InsufficientAllowance variant exposed it.)
    let xfer = transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        1_000_000, // within allowance, exceeds liquid (0)
        None,
    );
    assert!(
        matches!(xfer, Err(TransferFromError::InsufficientFunds { .. })),
        "t5: transfer against zero liquid must return InsufficientFunds; got {:?}", xfer
    );

    assert_eq!(allowance_of(&pic, token, owner, spender), allow_before,
        "t5: allowance must be UNCHANGED after a failed transfer_from (no phantom decrement)");
    assert_eq!(balance(&pic, token, owner), owner_before,
        "t5: owner balance must be unchanged");
    assert_eq!(staking_locked(&pic, token, owner), owner_before,
        "t5: locked stake must be unchanged");
    assert_eq!(balance(&pic, token, recipient), 0,
        "t5: recipient must receive nothing");
}

// ─────────────────────────────────────────────────────────────────────────────
// QA-DEF-021 — default-subaccount canonicalization (None == Some([0;32]))
// ─────────────────────────────────────────────────────────────────────────────

// test_icrc_t6 — the explicit all-zero subaccount is the same account as None.
#[test]
fn test_icrc_t6_subaccount_zero_canonicalizes_to_default() {
    let pic = PocketIc::new();
    let owner     = p(0xF0);
    let recipient = p(0xF2);

    let token = deploy_token(&pic, owner, p(0x02)); // genesis credits {owner, None}
    let fee = live_fee(&pic, token);
    let zero_sub: Option<[u8; 32]> = Some([0u8; 32]);

    // (a) balance under the explicit-zero subaccount == balance under None.
    let bal_none = balance_of(&pic, token, Account { owner, subaccount: None });
    let bal_zero = balance_of(&pic, token, Account { owner, subaccount: zero_sub });
    assert_eq!(bal_none, TOTAL_SUPPLY, "t6: default account holds the full genesis supply");
    assert!(bal_none > 0, "t6: balance must be non-zero");
    assert_eq!(bal_zero, bal_none,
        "t6: balance_of({{owner, Some([0;32])}}) must equal balance_of({{owner, None}})");

    // (b) icrc1_transfer FROM the explicit-zero subaccount debits the default
    // account and succeeds.
    let amount = 1_000 * STSH;
    let xfer: Result<Nat, TransferError> = decode(
        "t6: icrc1_transfer",
        pic.update_call(token, owner, "icrc1_transfer", candid::encode_one(TransferArgs {
            from_subaccount: zero_sub,
            to: Account { owner: recipient, subaccount: None },
            amount,
            fee: None,
            memo: None,
            created_at_time: None,
        }).unwrap()),
    );
    assert!(xfer.is_ok(), "t6: transfer from the explicit-zero subaccount must succeed; got {:?}", xfer);

    let expected_owner = TOTAL_SUPPLY - amount - fee;
    assert_eq!(balance(&pic, token, recipient), amount,
        "t6: recipient must receive exactly the amount");
    assert_eq!(balance_of(&pic, token, Account { owner, subaccount: None }), expected_owner,
        "t6: the default (None) account must be debited amount + fee");
    assert_eq!(balance_of(&pic, token, Account { owner, subaccount: zero_sub }), expected_owner,
        "t6: the explicit-zero subaccount must reflect the same debit (same account)");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-050B-1 — icrc2_transfer_from idempotency (QA-DEF-050B; transfer_from half
// of QA-DEF-023). A created_at_time-bearing transfer is deduplicated by the
// canonical transfer identity, so a byte-identical retry of a transport-unknown
// transfer returns Duplicate { duplicate_of } instead of debiting twice.
// ─────────────────────────────────────────────────────────────────────────────

// DEF050B1-A — identical retry returns Duplicate; allowance and balances move once.
#[test]
fn test_def050b1_a_identical_retry_returns_duplicate() {
    let pic = PocketIc::new();
    let owner     = p(0x30);
    let spender   = p(0x31);
    let recipient = p(0x32);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("A: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);

    let amount = 1_000 * STSH;
    let t = now_ns(&pic);
    let memo = Some(b"deposit-A".to_vec());

    let first = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, memo.clone(), Some(t),
    );
    let block1 = match first {
        Ok(b) => b,
        other => panic!("A: first transfer must succeed; got {:?}", other),
    };

    // State after the first (successful) transfer.
    assert_eq!(balance(&pic, token, recipient), amount, "A: recipient credited once");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee, "A: owner debited once");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - amount - fee,
        "A: allowance reduced once");

    // Byte-identical retry → Duplicate { duplicate_of: block1 }, no further debit.
    let second = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, memo.clone(), Some(t),
    );
    match &second {
        Err(TransferFromError::Duplicate { duplicate_of }) => {
            assert_eq!(to_u128(duplicate_of.clone()), to_u128(block1.clone()),
                "A: Duplicate must point at the original block index");
        }
        other => panic!("A: retry must return Duplicate; got {:?}", other),
    }

    // No double-debit: every figure is exactly as it was after the first call.
    assert_eq!(balance(&pic, token, recipient), amount, "A: recipient NOT credited twice");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee, "A: owner NOT debited twice");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - amount - fee,
        "A: allowance NOT reduced twice");
}

// DEF050B1-B — created_at_time: None bypasses dedup (backward compatible).
#[test]
fn test_def050b1_b_none_created_at_bypasses_dedup() {
    let pic = PocketIc::new();
    let owner     = p(0x40);
    let spender   = p(0x41);
    let recipient = p(0x42);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("B: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);

    let amount = 1_000 * STSH;

    let first = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, Some(b"same".to_vec()), None,
    );
    let block1 = first.unwrap_or_else(|e| panic!("B: first must succeed; got {:?}", e));

    let second = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, Some(b"same".to_vec()), None,
    );
    let block2 = second.unwrap_or_else(|e| panic!("B: second must also succeed (no dedup); got {:?}", e));

    assert_ne!(to_u128(block1), to_u128(block2), "B: two distinct blocks (None bypasses dedup)");
    assert_eq!(balance(&pic, token, recipient), 2 * amount, "B: recipient credited twice");
    assert_eq!(balance(&pic, token, owner), owner_before - 2 * (amount + fee), "B: owner debited twice");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - 2 * (amount + fee),
        "B: allowance reduced twice");
}

// DEF050B1-C — different memo → different dedup key → not a duplicate.
#[test]
fn test_def050b1_c_different_memo_not_duplicate() {
    let pic = PocketIc::new();
    let owner     = p(0x50);
    let spender   = p(0x51);
    let recipient = p(0x52);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("C: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);

    let amount = 1_000 * STSH;
    let t = now_ns(&pic);

    let first = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, Some(b"deposit-1".to_vec()), Some(t),
    );
    assert!(first.is_ok(), "C: first must succeed; got {:?}", first);

    // Same t / amount / from / spender / to, DIFFERENT memo → fresh execution.
    let second = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, Some(b"deposit-2".to_vec()), Some(t),
    );
    assert!(second.is_ok(), "C: a different memo must NOT be a duplicate; got {:?}", second);

    assert_eq!(balance(&pic, token, recipient), 2 * amount, "C: recipient credited twice");
    assert_eq!(balance(&pic, token, owner), owner_before - 2 * (amount + fee), "C: owner debited twice");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - 2 * (amount + fee),
        "C: allowance reduced twice");
}

// DEF050B1-D — created_at_time older than the dedup window → TooOld, no mutation.
#[test]
fn test_def050b1_d_too_old_rejected() {
    let pic = PocketIc::new();
    let owner     = p(0x60);
    let spender   = p(0x61);
    let recipient = p(0x62);

    let token = deploy_token(&pic, owner, p(0x02));

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("D: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);
    let allow_before = allowance_of(&pic, token, owner, spender);

    // One hour beyond the dedup window in the past → TooOld.
    let now = now_ns(&pic);
    let t = now.saturating_sub(TX_DEDUP_WINDOW_NS + 3_600_000_000_000);

    let xfer = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        1_000 * STSH, None, Some(b"stale".to_vec()), Some(t),
    );
    assert!(matches!(xfer, Err(TransferFromError::TooOld)),
        "D: created_at_time older than the window must return TooOld; got {:?}", xfer);

    assert_eq!(allowance_of(&pic, token, owner, spender), allow_before, "D: allowance unchanged");
    assert_eq!(balance(&pic, token, owner), owner_before, "D: owner balance unchanged");
    assert_eq!(balance(&pic, token, recipient), 0, "D: recipient unchanged");
}

// DEF050B1-E — created_at_time beyond the permitted drift → CreatedInFuture.
#[test]
fn test_def050b1_e_created_in_future_rejected() {
    let pic = PocketIc::new();
    let owner     = p(0x70);
    let spender   = p(0x71);
    let recipient = p(0x72);

    let token = deploy_token(&pic, owner, p(0x02));

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("E: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);
    let allow_before = allowance_of(&pic, token, owner, spender);

    // One hour beyond the permitted drift in the future → CreatedInFuture.
    let now = now_ns(&pic);
    let t = now + PERMITTED_DRIFT_NS + 3_600_000_000_000;

    let xfer = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        1_000 * STSH, None, Some(b"future".to_vec()), Some(t),
    );
    match &xfer {
        Err(TransferFromError::CreatedInFuture { .. }) => {}
        other => panic!("E: created_at_time beyond drift must return CreatedInFuture; got {:?}", other),
    }

    assert_eq!(allowance_of(&pic, token, owner, spender), allow_before, "E: allowance unchanged");
    assert_eq!(balance(&pic, token, owner), owner_before, "E: owner balance unchanged");
    assert_eq!(balance(&pic, token, recipient), 0, "E: recipient unchanged");
}

// DEF050B1-F — the dedup store survives a canister upgrade.
#[test]
fn test_def050b1_f_dedup_survives_upgrade() {
    let pic = PocketIc::new();
    let owner     = p(0x80);
    let spender   = p(0x81);
    let recipient = p(0x82);

    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow_amount = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow_amount)
        .unwrap_or_else(|e| panic!("F: approve must succeed; got {:?}", e));
    let owner_before = balance(&pic, token, owner);

    let amount = 1_000 * STSH;
    let t = now_ns(&pic);
    let memo = Some(b"deposit-F".to_vec());

    let first = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, memo.clone(), Some(t),
    );
    let block1 = first.unwrap_or_else(|e| panic!("F: first must succeed; got {:?}", e));

    // Upgrade the token canister in place (pre_upgrade/post_upgrade run).
    upgrade_token(&pic, token);

    // Same identity after upgrade → Duplicate from the persisted dedup store.
    let second = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount, None, memo.clone(), Some(t),
    );
    match &second {
        Err(TransferFromError::Duplicate { duplicate_of }) => {
            assert_eq!(to_u128(duplicate_of.clone()), to_u128(block1.clone()),
                "F: Duplicate must point at the pre-upgrade block index");
        }
        other => panic!("F: post-upgrade retry must return Duplicate; got {:?}", other),
    }

    // No double-debit across the upgrade boundary.
    assert_eq!(balance(&pic, token, recipient), amount, "F: recipient credited once");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee, "F: owner debited once");
    assert_eq!(allowance_of(&pic, token, owner, spender), allow_amount - amount - fee,
        "F: allowance reduced once");
}

// ═════════════════════════════════════════════════════════════════════════════
// B1 — icrc1_transfer idempotent dedup + check-before-mutate write-ordering
// (withdraw-side of QA-DEF-023; brings icrc1_transfer to icrc2_transfer_from parity)
// ═════════════════════════════════════════════════════════════════════════════

const TREASURY: fn() -> Principal = || p(0x01); // matches all_to()'s treasury

/// icrc1_transfer with explicit memo + created_at_time (the dedup-relevant fields
/// the plain path pins to None). Caller == `from.owner` (ICRC-1 semantics).
#[allow(clippy::too_many_arguments)]
fn transfer_ext(
    pic: &PocketIc, token: Principal, caller: Principal,
    from_subaccount: Option<[u8; 32]>, to: Account, amount: u128, fee: Option<u128>,
    memo: Option<Vec<u8>>, created_at_time: Option<u64>,
) -> Result<Nat, TransferError> {
    decode(
        "icrc1_transfer",
        pic.update_call(token, caller, "icrc1_transfer", candid::encode_one(TransferArgs {
            from_subaccount,
            to,
            amount,
            fee,
            memo,
            created_at_time,
        }).unwrap()),
    )
}

// ── B1-A: identical retry returns Duplicate; balances move exactly once. ─────────
#[test]
fn test_b1_a_icrc1_identical_retry_returns_duplicate() {
    let pic = PocketIc::new();
    let owner     = p(0x30);
    let recipient = p(0x32);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let owner_before = balance(&pic, token, owner);
    let amount = 1_000 * STSH;
    let t = now_ns(&pic);
    let memo = Some(b"b1-a".to_vec());

    let first = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, memo.clone(), Some(t));
    let block1 = first.unwrap_or_else(|e| panic!("A: first must succeed; got {:?}", e));

    assert_eq!(balance(&pic, token, recipient), amount, "A: recipient credited once");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee, "A: owner debited once");

    let second = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, memo.clone(), Some(t));
    match &second {
        Err(TransferError::Duplicate { duplicate_of }) => {
            assert_eq!(to_u128(duplicate_of.clone()), to_u128(block1.clone()),
                "A: Duplicate must point at the original block index");
        }
        other => panic!("A: retry must return Duplicate; got {:?}", other),
    }
    assert_eq!(balance(&pic, token, recipient), amount, "A: recipient NOT credited twice");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee, "A: owner NOT debited twice");
}

// ── B1-B: created_at_time == None bypasses dedup (backward compatible). ──────────
#[test]
fn test_b1_b_icrc1_none_created_at_bypasses_dedup() {
    let pic = PocketIc::new();
    let owner     = p(0x40);
    let recipient = p(0x42);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let owner_before = balance(&pic, token, owner);
    let amount = 1_000 * STSH;

    let b1 = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, Some(b"same".to_vec()), None)
        .unwrap_or_else(|e| panic!("B: first must succeed; got {:?}", e));
    let b2 = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, Some(b"same".to_vec()), None)
        .unwrap_or_else(|e| panic!("B: second must also succeed (no dedup); got {:?}", e));

    assert_ne!(to_u128(b1), to_u128(b2), "B: two distinct blocks (None bypasses dedup)");
    assert_eq!(balance(&pic, token, recipient), 2 * amount, "B: recipient credited twice");
    assert_eq!(balance(&pic, token, owner), owner_before - 2 * (amount + fee), "B: owner debited twice");
}

// ── B1-C: differing amount / to / memo / created_at_time each executes (not dedup). ─
#[test]
fn test_b1_c_icrc1_variant_fields_not_duplicate() {
    let pic = PocketIc::new();
    let owner     = p(0x50);
    let recipient = p(0x52);
    let other_rcpt = p(0x53);
    let token = deploy_token(&pic, owner, p(0x02));
    let t = now_ns(&pic);
    let base = |memo: &[u8], amt: u128, to: Principal, ts: u64| {
        transfer_ext(&pic, token, owner, None,
            Account { owner: to, subaccount: None }, amt, None, Some(memo.to_vec()), Some(ts))
    };
    // Establish a baseline entry.
    assert!(base(b"m", 1_000 * STSH, recipient, t).is_ok(), "C: baseline must succeed");
    // Differ by memo → not a duplicate.
    assert!(base(b"m2", 1_000 * STSH, recipient, t).is_ok(), "C: different memo executes");
    // Differ by amount → not a duplicate.
    assert!(base(b"m", 2_000 * STSH, recipient, t).is_ok(), "C: different amount executes");
    // Differ by recipient → not a duplicate.
    assert!(base(b"m", 1_000 * STSH, other_rcpt, t).is_ok(), "C: different to executes");
    // Differ by created_at_time → not a duplicate.
    assert!(base(b"m", 1_000 * STSH, recipient, t + 1).is_ok(), "C: different created_at executes");
    // The exact baseline tuple, however, IS a duplicate.
    match base(b"m", 1_000 * STSH, recipient, t) {
        Err(TransferError::Duplicate { .. }) => {}
        other => panic!("C: exact-tuple retry must be Duplicate; got {:?}", other),
    }
}

// ── B1-D / B1-E: window validation (TooOld / CreatedInFuture), no mutation. ──────
#[test]
fn test_b1_d_icrc1_too_old_rejected() {
    let pic = PocketIc::new();
    let owner     = p(0x60);
    let recipient = p(0x62);
    let token = deploy_token(&pic, owner, p(0x02));
    let owner_before = balance(&pic, token, owner);
    let t = now_ns(&pic).saturating_sub(TX_DEDUP_WINDOW_NS + 3_600_000_000_000);
    let xfer = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, 1_000 * STSH, None, Some(b"stale".to_vec()), Some(t));
    assert!(matches!(xfer, Err(TransferError::TooOld)), "D: must be TooOld; got {:?}", xfer);
    assert_eq!(balance(&pic, token, owner), owner_before, "D: owner unchanged");
    assert_eq!(balance(&pic, token, recipient), 0, "D: recipient unchanged");
}

#[test]
fn test_b1_e_icrc1_created_in_future_rejected() {
    let pic = PocketIc::new();
    let owner     = p(0x70);
    let recipient = p(0x72);
    let token = deploy_token(&pic, owner, p(0x02));
    let owner_before = balance(&pic, token, owner);
    let t = now_ns(&pic) + PERMITTED_DRIFT_NS + 3_600_000_000_000;
    let xfer = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, 1_000 * STSH, None, Some(b"future".to_vec()), Some(t));
    match &xfer {
        Err(TransferError::CreatedInFuture { .. }) => {}
        other => panic!("E: must be CreatedInFuture; got {:?}", other),
    }
    assert_eq!(balance(&pic, token, owner), owner_before, "E: owner unchanged");
    assert_eq!(balance(&pic, token, recipient), 0, "E: recipient unchanged");
}

// ── B1-F: dedup store survives a canister upgrade. ───────────────────────────────
#[test]
fn test_b1_f_icrc1_dedup_survives_upgrade() {
    let pic = PocketIc::new();
    let owner     = p(0x80);
    let recipient = p(0x82);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);
    let owner_before = balance(&pic, token, owner);
    let amount = 1_000 * STSH;
    let t = now_ns(&pic);
    let memo = Some(b"b1-f".to_vec());

    let block1 = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, memo.clone(), Some(t))
        .unwrap_or_else(|e| panic!("F: first must succeed; got {:?}", e));

    upgrade_token(&pic, token);

    let second = transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, memo.clone(), Some(t));
    match &second {
        Err(TransferError::Duplicate { duplicate_of }) => {
            assert_eq!(to_u128(duplicate_of.clone()), to_u128(block1.clone()),
                "F: Duplicate must point at the pre-upgrade block index");
        }
        other => panic!("F: post-upgrade retry must be Duplicate; got {:?}", other),
    }
    assert_eq!(balance(&pic, token, recipient), amount, "F: recipient credited once across upgrade");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee, "F: owner debited once across upgrade");
}

// ── B1-G: an ICRC-1 transfer and an ICRC-2 transfer_from with IDENTICAL
// (from, to, amount, fee, memo, created_at_time) must NOT collide — distinct domain
// tags keep them in separate dedup namespaces. ──────────────────────────────────
#[test]
fn test_b1_g_icrc1_icrc2_dedup_no_collision() {
    let pic = PocketIc::new();
    let owner     = p(0x90);
    let spender   = p(0x91);
    let recipient = p(0x92);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);

    let allow = 5_000 * STSH;
    approve(&pic, token, owner, spender, allow).unwrap_or_else(|e| panic!("G: approve; {:?}", e));

    let owner_before = balance(&pic, token, owner);
    let amount = 1_000 * STSH;
    let t = now_ns(&pic);
    let memo = Some(b"shared-identity".to_vec());
    let from = Account { owner, subaccount: None };
    let to = Account { owner: recipient, subaccount: None };

    // ICRC-1 leg (writes the icrc1-tagged dedup entry).
    let icrc1_block = transfer_ext(&pic, token, owner, None, to.clone(), amount, None, memo.clone(), Some(t))
        .unwrap_or_else(|e| panic!("G: icrc1 leg must succeed; got {:?}", e));

    // ICRC-2 leg with the SAME (from,to,amount,fee,memo,t). If the keys collided it
    // would return Duplicate { duplicate_of: icrc1_block }. It must instead execute.
    let icrc2 = transfer_from_ext(&pic, token, spender, from, to, amount, None, memo.clone(), Some(t));
    let icrc2_block = icrc2.unwrap_or_else(|e|
        panic!("G: icrc2 leg must NOT be deduped by the icrc1 entry (distinct tag); got {:?}", e));
    assert_ne!(to_u128(icrc2_block), to_u128(icrc1_block),
        "G: the two standards must produce distinct blocks (no cross-standard dedup)");

    // Both legs moved funds: recipient credited twice, owner debited twice.
    assert_eq!(balance(&pic, token, recipient), 2 * amount, "G: recipient credited by both legs");
    assert_eq!(balance(&pic, token, owner), owner_before - 2 * (amount + fee), "G: owner debited by both legs");
}

// ── B1-H: self-transfer (to == from) loses only the fee — write-ordering rewrite
// preserves the prior read-after-write semantics. ──────────────────────────────
#[test]
fn test_b1_h_icrc1_self_transfer_loses_only_fee() {
    let pic = PocketIc::new();
    let owner = p(0xA0);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);
    let before = balance(&pic, token, owner);

    let xfer = transfer_ext(&pic, token, owner, None,
        Account { owner, subaccount: None }, 1_000 * STSH, None, None, None);
    assert!(xfer.is_ok(), "H: self-transfer must succeed; got {:?}", xfer);
    assert_eq!(balance(&pic, token, owner), before - fee,
        "H: a self-transfer must net exactly the fee (amount returns to the same account)");
}

// ── B1-I: supply conservation — owner debit == recipient credit + fee-to-treasury. ─
#[test]
fn test_b1_i_icrc1_supply_conserved() {
    let pic = PocketIc::new();
    let owner     = p(0xB0);
    let recipient = p(0xB2);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);
    let treasury = TREASURY();

    let owner_before     = balance(&pic, token, owner);
    let recipient_before = balance(&pic, token, recipient);
    let treasury_before  = balance(&pic, token, treasury);

    let amount = 1_234 * STSH;
    transfer_ext(&pic, token, owner, None,
        Account { owner: recipient, subaccount: None }, amount, None, None, Some(now_ns(&pic)))
        .unwrap_or_else(|e| panic!("I: transfer must succeed; got {:?}", e));

    let owner_debit    = owner_before - balance(&pic, token, owner);
    let recipient_gain = balance(&pic, token, recipient) - recipient_before;
    let treasury_gain  = balance(&pic, token, treasury) - treasury_before;
    assert_eq!(owner_debit, amount + fee, "I: owner debited amount + fee");
    assert_eq!(recipient_gain, amount, "I: recipient credited amount");
    assert_eq!(treasury_gain, fee, "I: fee routed to treasury");
    // Conservation: what left the sender arrived at recipient + treasury exactly.
    assert_eq!(owner_debit, recipient_gain + treasury_gain, "I: supply conserved (no tokens created/destroyed)");
}

// ── B1-J: forced credit-failure → NO partial debit (the write-ordering
// discriminator). Uses the --features testing token to seed the recipient near
// u128::MAX so checked_credit(to_base, amount) overflows (otherwise unreachable, as
// sum(balances) == TOTAL_SUPPLY << u128::MAX). On the PRE-fix code the debit would
// commit and the credit be dropped; on the fix nothing moves. ──────────────────
fn token_test_wasm() -> Vec<u8> {
    let path = env!("TOKEN_TEST_WASM");
    std::fs::read(path).unwrap_or_else(|e| panic!(
        "Cannot read stsh_token TEST Wasm at {}: {}.\nBuild first:\n  \
         cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing\n  \
         cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
         target/wasm32-unknown-unknown/release/stsh_token_test.wasm",
        path, e))
}

fn debug_credit(pic: &PocketIc, token: Principal, account: Account, amount: u128) {
    let _: () = decode(
        "debug_credit_balance_for_test",
        pic.update_call(token, anon(), "debug_credit_balance_for_test",
            candid::encode_args((account, amount)).unwrap()),
    );
}

#[test]
fn test_b1_j_icrc1_forced_credit_failure_no_partial_debit() {
    let pic = PocketIc::new();
    let owner     = p(0xC0);
    let recipient = p(0xC2);
    let treasury  = TREASURY();

    // Deploy the --features testing token (adds debug_credit_balance_for_test).
    let token = create_canister(&pic);
    install(&pic, token, token_test_wasm(), &all_to(owner, p(0x02)));
    // R-8 V1a: on the `--features testing` build `icrc1_fee` is an UPDATE, not
    // a query — it has to be, so the SI-11 observer inside it can make an
    // inter-canister call at all (the outbound-call System API is unavailable
    // under replicated query execution). Same value, same computation; only the
    // call kind differs, and only on this build. `live_fee`'s `query_call` is
    // therefore not usable here, and nowhere else in the estate query-calls
    // `icrc1_fee` on the TESTING token.
    let fee = to_u128(decode::<Nat, _>(
        "icrc1_fee (testing build: update)",
        pic.update_call(token, anon(), "icrc1_fee", candid::encode_args(()).unwrap()),
    ));

    // R-1 S4(d), the pre-declared rewrite class. This test used to seed the
    // recipient to u128::MAX through `debug_credit_balance_for_test` and then
    // assert that the OVERFLOWING TRANSFER errored leaving no partial state.
    // R-1 moved the arithmetic refusal from the transfer to WRITE TIME: every
    // write now goes through `ledger_maps::write_balance`, which `checked_add`s
    // the maintained running total and TRAPS rather than wrapping. Seeding one
    // account to u128::MAX therefore drives SUM_BALANCES past u128::MAX and is
    // refused at the seam, so the old scenario is no longer reachable — there is
    // no ledger state in which a credit can overflow while the total has not.
    //
    // The property is preserved with the observable moved to where the refusal
    // now lives: the write is REFUSED and leaves NO partial state. A wrapped
    // total could never produce this.
    let recipient_account = Account { owner: recipient, subaccount: None };
    let owner_before     = balance(&pic, token, owner);
    let recipient_before = balance(&pic, token, recipient);
    let treasury_before  = balance(&pic, token, treasury);

    let seed = pic.update_call(
        token,
        anon(),
        "debug_credit_balance_for_test",
        candid::encode_args((recipient_account.clone(), u128::MAX)).unwrap(),
    );
    assert!(
        seed.is_err(),
        "J: crediting u128::MAX must be REFUSED at the write funnel, never wrapped"
    );

    // NO partial state: sender, recipient and treasury are all exactly unchanged.
    assert_eq!(balance(&pic, token, owner), owner_before,
        "J: NO partial debit — the sender balance is unchanged after the refused write");
    assert_eq!(balance(&pic, token, recipient), recipient_before,
        "J: the refused write leaves the recipient balance untouched");
    assert_eq!(balance(&pic, token, treasury), treasury_before,
        "J: no fee routed by a refused write");

    // The refusal rejects ONE write; it does not wedge the ledger. An ordinary
    // transfer still settles exactly afterwards.
    let amount = 1_000 * STSH;
    let t = now_ns(&pic);
    transfer_ext(&pic, token, owner, None, recipient_account, amount, None,
        Some(b"after-refusal".to_vec()), Some(t))
        .expect("J: an ordinary transfer must still succeed after the refused write");
    assert_eq!(balance(&pic, token, recipient), recipient_before + amount,
        "J: the recipient is credited normally afterwards");
    assert_eq!(balance(&pic, token, owner), owner_before - amount - fee,
        "J: the sender is debited exactly amount + fee");
}

// ═════════════════════════════════════════════════════════════════════════════
// R10-1 (lane A-3) — `amount == 0` is refused on the two transfer write paths
// ═════════════════════════════════════════════════════════════════════════════
//
// A KNOWING ICRC-1 DEVIATION, not a conformance fix: ICRC-1 permits zero-amount
// transfers and this ledger accepted them until now. It ships because at
// DEFAULT_FEE = 0 a zero-amount transfer is a completely free no-op that still
// writes a dedup entry — an unpriced state-growth vector spammable at ingress
// cost alone. Registered in NOTE_A-3_icrc_deviation.md.
//
// `icrc2_approve` is deliberately NOT covered: a zero approve is how an
// allowance is REVOKED. E4 pins that.

/// The pinned R10-1 `GenericError.error_code` — mirrors
/// `stsh_token::ERR_CODE_ZERO_AMOUNT`. Duplicated because this suite drives the
/// canister over PocketIC and cannot link its constants; E6 (unit, in the token
/// crate) pins the production value, so a drift between the two REDs here.
const ERR_CODE_ZERO_AMOUNT: u32 = 5;

fn assert_zero_amount_transfer_error(err: &TransferError, ctx: &str) {
    match err {
        TransferError::GenericError { error_code, message } => {
            assert_eq!(
                to_u128(error_code.clone()),
                ERR_CODE_ZERO_AMOUNT as u128,
                "{ctx}: pinned R10-1 error code"
            );
            assert!(
                message.contains("greater than zero"),
                "{ctx}: message names the rule, got {message:?}"
            );
        }
        other => panic!("{ctx}: expected the R10-1 GenericError, got {other:?}"),
    }
}

/// E1 — `icrc1_transfer` with `amount == 0` is refused with the pinned code.
#[test]
fn test_r10_1_e1_icrc1_transfer_zero_amount_rejected() {
    let pic = PocketIc::new();
    let owner = p(0x40);
    let token = deploy_token(&pic, owner, p(0x02));
    let err = transfer_ext(&pic, token, owner, None, Account { owner: p(0x41), subaccount: None }, 0, None, None, None)
        .expect_err("E1: a zero-amount transfer must be refused");
    assert_zero_amount_transfer_error(&err, "E1");
}

/// E2 — `icrc2_transfer_from` with `amount == 0` is refused with the pinned code.
#[test]
fn test_r10_1_e2_icrc2_transfer_from_zero_amount_rejected() {
    let pic = PocketIc::new();
    let owner = p(0x42);
    let spender = p(0x43);
    let token = deploy_token(&pic, owner, p(0x02));
    approve(&pic, token, owner, spender, 1_000 * STSH).expect("approve");

    let err = transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: p(0x44), subaccount: None },
        0, None,
    )
    .expect_err("E2: a zero-amount transfer_from must be refused");
    match err {
        TransferFromError::GenericError { ref error_code, ref message } => {
            assert_eq!(to_u128(error_code.clone()), ERR_CODE_ZERO_AMOUNT as u128, "E2: pinned code");
            assert!(message.contains("greater than zero"), "E2: message names the rule");
        }
        other => panic!("E2: expected the R10-1 GenericError, got {other:?}"),
    }
}

/// E3 — NO PARTIAL STATE ON REJECTION.
///
/// On the IC a returned `Err` COMMITS whatever the message already wrote — only
/// a trap rolls back. So "no partial state on rejection" is the correctness
/// requirement, and it is the observable one.
///
/// WHAT THIS CANNOT PROVE (SSA-A3-BR2): reads leave no trace, so state equality
/// cannot distinguish a check placed before the reads from one placed after the
/// reads and before the writes. This pins the WRITE-order invariant only, and
/// nothing here should be read as proving no state was read.
#[test]
fn test_r10_1_e3_no_partial_state_on_zero_amount_rejection() {
    let pic = PocketIc::new();
    let owner = p(0x45);
    let spender = p(0x46);
    let recipient = p(0x47);
    let token = deploy_token(&pic, owner, p(0x02));
    approve(&pic, token, owner, spender, 1_000 * STSH).expect("approve");

    let owner_before = balance(&pic, token, owner);
    let recipient_before = balance(&pic, token, recipient);
    let spender_before = balance(&pic, token, spender);
    let allowance_before = allowance_of(&pic, token, owner, spender);
    let supply_before: Nat = decode(
        "icrc1_total_supply",
        pic.query_call(token, anon(), "icrc1_total_supply", candid::encode_args(()).unwrap()),
    );

    // Both paths, each with created_at_time set so the dedup map would be
    // written if the refusal came too late.
    let now = now_ns(&pic);
    let e1 = transfer_ext(
        &pic, token, owner, None, Account { owner: recipient, subaccount: None },
        0, None, Some(vec![0xA1; 8]), Some(now),
    );
    assert!(e1.is_err(), "E3: the icrc1 zero-amount call must be refused");
    let e2 = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        0, None, Some(vec![0xA2; 8]), Some(now),
    );
    assert!(e2.is_err(), "E3: the transfer_from zero-amount call must be refused");

    assert_eq!(balance(&pic, token, owner), owner_before, "E3: sender balance unchanged");
    assert_eq!(balance(&pic, token, recipient), recipient_before, "E3: recipient balance unchanged");
    assert_eq!(balance(&pic, token, spender), spender_before, "E3: spender balance unchanged");
    assert_eq!(
        allowance_of(&pic, token, owner, spender), allowance_before,
        "E3: allowance unchanged"
    );
    let supply_after: Nat = decode(
        "icrc1_total_supply",
        pic.query_call(token, anon(), "icrc1_total_supply", candid::encode_args(()).unwrap()),
    );
    assert_eq!(supply_after, supply_before, "E3: total supply unchanged");

    // NO BLOCK WAS CONSUMED. There is no block-height query, but `icrc1_transfer`
    // RETURNS its block index, so a block consumed by a rejected call shows up as
    // a GAP between two successful transfers that bracket it.
    //
    // This is the only observable that can distinguish a refusal placed before
    // `next_block()` from one placed after it. It cannot distinguish a refusal
    // placed before the phase-2 balance writes from one placed after them — see
    // NOTE_A-3_e3_dedup_observable.md + CTO_RULING_A-3_before_write_limb_V2.md:
    // at DEFAULT_FEE = 0 those
    // writes are numerically IDENTITY operations for a zero-amount transfer, so
    // no assertion over balances can see them.
    let blk_before = transfer_ext(
        &pic, token, owner, None, Account { owner: recipient, subaccount: None },
        1, None, None, None,
    )
    .expect("E3: bracketing transfer before");
    let rejected = transfer_ext(
        &pic, token, owner, None, Account { owner: recipient, subaccount: None },
        0, None, None, None,
    );
    assert!(rejected.is_err(), "E3: the bracketed zero-amount call must be refused");
    let blk_after = transfer_ext(
        &pic, token, owner, None, Account { owner: recipient, subaccount: None },
        1, None, None, None,
    )
    .expect("E3: bracketing transfer after");
    assert_eq!(
        to_u128(blk_after.clone()),
        to_u128(blk_before.clone()) + 1,
        "E3: the refused call must not consume a block index (before={blk_before}, after={blk_after})"
    );

    // No dedup entry was written: a byte-identical retry must re-error with the
    // SAME refusal, not return Duplicate.
    let retry = transfer_ext(
        &pic, token, owner, None, Account { owner: recipient, subaccount: None },
        0, None, Some(vec![0xA1; 8]), Some(now),
    );
    match retry {
        Err(ref err) => assert_zero_amount_transfer_error(err, "E3 retry"),
        Ok(_) => panic!("E3: the retry must still be refused"),
    }
}

/// The staleness margin used by E3b-a and E3b-b, chosen deliberately per
/// CAMPAIGN RULE 2 (NOTE_A-3_e3b_magnitude.md).
///
/// A `created_at_time` a hair past `TX_DEDUP_WINDOW_NS` is the `MAX + 3` defect
/// shape: the test could pass because no ordering was exercised at all rather
/// than because the ordering is right. This margin is a **full hour clear** of
/// the 24-hour window, and both tests assert the subtraction did not saturate,
/// so a stale timestamp can never be manufactured by clamping to 0.
///
/// MEASURED (mutation table rows M4/M5, run at both values):
/// ```text
///   window + 60s   → M4 REDs E3b-a, M5 REDs E3b-b   (bites, but only 60s clear)
///   window + 1h    → M4 REDs E3b-a, M5 REDs E3b-b   (SHIPPED)
/// ```
/// Both bite; the shipped value is the one with margin. Recording both means the
/// value cannot later be quietly reduced below the point where it stops biting.
const E3B_STALENESS_MARGIN_NS: u64 = 3_600_000_000_000; // 1 hour clear of the window

/// Build a deliberately-stale `created_at_time`, asserting no saturation.
fn stale_created_at(pic: &PocketIc) -> u64 {
    let now = now_ns(pic);
    let back = TX_DEDUP_WINDOW_NS + E3B_STALENESS_MARGIN_NS;
    assert!(
        now > back,
        "the PocketIC clock ({now}) must be past the staleness offset ({back}) — otherwise \
         saturating_sub would manufacture a stale timestamp by clamping to 0 and the test \
         would pass without exercising the window at all"
    );
    now - back
}

/// E3c — THE BEFORE-WRITE LIMB, proven causally on both endpoints.
///
/// CAMPAIGN RULE 6: *an assertion that state is unchanged cannot distinguish
/// "never written" from "written identically."* E3's equality checks over
/// balances and the dedup map have exactly that blind spot — at
/// `DEFAULT_FEE = 0` the debit and credit are identity operations, and an
/// unchanged-map assertion cannot see a write that reproduced the same bytes.
///
/// THE OBSERVABLE (A1, `NOTE_A-3_e3_dedup_observable.md`): `record_dedup` at the
/// end of the commit block is **not** an identity operation, and the code's own
/// comment states its purpose — "a byte-identical retry within
/// `TX_DEDUP_WINDOW_NS` returns Duplicate." So the limb has a deterministic,
/// fee-free, in-fence probe: reject a zero-amount call carrying an explicit
/// `created_at_time`, then repeat it byte-identically.
///
///   correct ordering → no dedup entry written → the retry REJECTS identically
///   refusal after the commit block → an entry was written → the retry returns
///   `Duplicate`, which is the countable RED
///
/// Run on BOTH endpoints rather than letting one stand in for the other: each
/// carries its own dedup key under a distinct domain tag, so each limb bites on
/// its own evidence.
#[test]
fn test_r10_1_e3c_rejection_writes_no_dedup_entry_on_either_path() {
    let pic = PocketIc::new();
    let owner = p(0x53);
    let spender = p(0x54);
    let recipient = p(0x55);
    let token = deploy_token(&pic, owner, p(0x02));
    approve(&pic, token, owner, spender, 1_000 * STSH).expect("approve");
    let now = now_ns(&pic);

    // ── icrc1_transfer ──────────────────────────────────────────────────────
    let memo = Some(vec![0xC1; 8]);
    let call_icrc1 = || {
        transfer_ext(
            &pic, token, owner, None, Account { owner: recipient, subaccount: None },
            0, None, memo.clone(), Some(now),
        )
    };
    assert_zero_amount_transfer_error(
        &call_icrc1().expect_err("E3c: first zero-amount call must be refused"),
        "E3c icrc1 first",
    );
    match call_icrc1() {
        Err(TransferError::Duplicate { duplicate_of }) => panic!(
            "E3c icrc1: the retry returned Duplicate{{{duplicate_of}}} — the refused call              WROTE A DEDUP ENTRY, so the refusal is ordered after the commit block instead              of before it. This is the before-write limb failing."
        ),
        Err(ref e) => assert_zero_amount_transfer_error(e, "E3c icrc1 retry"),
        Ok(_) => panic!("E3c icrc1: the retry must still be refused"),
    }

    // ── icrc2_transfer_from (its own dedup key, distinct domain tag) ─────────
    let memo2 = Some(vec![0xC2; 8]);
    let call_tf = || {
        transfer_from_ext(
            &pic, token, spender,
            Account { owner, subaccount: None },
            Account { owner: recipient, subaccount: None },
            0, None, memo2.clone(), Some(now),
        )
    };
    let first = call_tf().expect_err("E3c: first zero-amount transfer_from must be refused");
    match first {
        TransferFromError::GenericError { ref error_code, .. } => {
            assert_eq!(to_u128(error_code.clone()), ERR_CODE_ZERO_AMOUNT as u128);
        }
        other => panic!("E3c transfer_from first: expected the R10-1 refusal, got {other:?}"),
    }
    match call_tf() {
        Err(TransferFromError::Duplicate { duplicate_of }) => panic!(
            "E3c transfer_from: the retry returned Duplicate{{{duplicate_of}}} — the refused              call WROTE A DEDUP ENTRY, so the refusal is ordered after the commit block."
        ),
        Err(TransferFromError::GenericError { ref error_code, .. }) => {
            assert_eq!(
                to_u128(error_code.clone()), ERR_CODE_ZERO_AMOUNT as u128,
                "E3c transfer_from retry: must reject identically, not Duplicate"
            );
        }
        other => panic!("E3c transfer_from retry: expected the R10-1 refusal, got {other:?}"),
    }
}

/// E3b-a — `icrc1_transfer` ORDERING. This endpoint validates `created_at_time`
/// ABOVE the amount decode, so a STALE zero-amount call returns `TooOld`, NOT
/// the zero refusal.
///
/// The opposite expectation to E3b-b, deliberately. See
/// CTO_RULING_A-3_error_precedence and NOTE_A-3_error_precedence_asymmetry.md.
/// Do NOT harmonise these two tests into one shared expectation.
#[test]
fn test_r10_1_e3b_a_icrc1_stale_zero_returns_too_old() {
    let pic = PocketIc::new();
    let owner = p(0x48);
    let token = deploy_token(&pic, owner, p(0x02));
    let stale = stale_created_at(&pic);

    let err = transfer_ext(
        &pic, token, owner, None, Account { owner: p(0x49), subaccount: None },
        0, None, None, Some(stale),
    )
    .expect_err("E3b-a: a stale zero-amount call must be refused");
    assert!(
        matches!(err, TransferError::TooOld),
        "E3b-a: icrc1_transfer validates the window FIRST, so a stale zero call is TooOld, \
         not the zero refusal; got {err:?}"
    );
}

/// E3b-b — `icrc2_transfer_from` ORDERING. This endpoint decodes the amount
/// BEFORE its dedup/time block, so the same stale zero-amount call returns the
/// ZERO REFUSAL, not `TooOld`. Opposite to E3b-a, and correct.
#[test]
fn test_r10_1_e3b_b_transfer_from_stale_zero_returns_zero_error() {
    let pic = PocketIc::new();
    let owner = p(0x4A);
    let spender = p(0x4B);
    let token = deploy_token(&pic, owner, p(0x02));
    approve(&pic, token, owner, spender, 1_000 * STSH).expect("approve");
    let stale = stale_created_at(&pic);

    let err = transfer_from_ext(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: p(0x4C), subaccount: None },
        0, None, None, Some(stale),
    )
    .expect_err("E3b-b: a stale zero-amount transfer_from must be refused");
    match err {
        TransferFromError::GenericError { ref error_code, .. } => {
            assert_eq!(
                to_u128(error_code.clone()), ERR_CODE_ZERO_AMOUNT as u128,
                "E3b-b: transfer_from decodes amount BEFORE its time block, so the zero \
                 refusal precedes TooOld here"
            );
        }
        TransferFromError::TooOld => panic!(
            "E3b-b: got TooOld — the zero check has moved below the dedup/time block, \
             which is the ordering change this lane declined to make"
        ),
        other => panic!("E3b-b: expected the R10-1 GenericError, got {other:?}"),
    }
}

/// E4 — NON-REGRESSION: `icrc2_approve` with `amount == 0` must still SUCCEED.
/// A zero approve is how an allowance is revoked; breaking it would remove a
/// user's ability to withdraw an approval. R10-1 names the two transfer write
/// paths only.
#[test]
fn test_r10_1_e4_approve_zero_still_revokes() {
    let pic = PocketIc::new();
    let owner = p(0x4D);
    let spender = p(0x4E);
    let token = deploy_token(&pic, owner, p(0x02));

    approve(&pic, token, owner, spender, 500 * STSH).expect("E4: initial approve");
    assert_eq!(allowance_of(&pic, token, owner, spender), 500 * STSH, "E4: allowance set");

    approve(&pic, token, owner, spender, 0).expect("E4: a zero approve must still succeed (revoke)");
    assert_eq!(allowance_of(&pic, token, owner, spender), 0, "E4: allowance revoked");
}

/// E5 — ANTI-VACUITY: a normal nonzero transfer still succeeds on both paths.
/// A check that accidentally rejected `amount == 1` would pass E1–E4 and break
/// the ledger.
#[test]
fn test_r10_1_e5_nonzero_transfers_still_succeed() {
    let pic = PocketIc::new();
    let owner = p(0x50);
    let spender = p(0x51);
    let recipient = p(0x52);
    let token = deploy_token(&pic, owner, p(0x02));
    let fee = live_fee(&pic, token);
    approve(&pic, token, owner, spender, 1_000 * STSH).expect("approve");

    // The smallest possible nonzero amount — the boundary next to the check.
    let before = balance(&pic, token, recipient);
    transfer_ext(&pic, token, owner, None, Account { owner: recipient, subaccount: None }, 1, None, None, None)
        .expect("E5: icrc1_transfer of 1 base unit must succeed");
    assert_eq!(balance(&pic, token, recipient), before + 1, "E5: recipient credited 1");

    transfer_from(
        &pic, token, spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        1, Some(fee),
    )
    .expect("E5: icrc2_transfer_from of 1 base unit must succeed");
    assert_eq!(balance(&pic, token, recipient), before + 2, "E5: recipient credited again");
}

// ═════════════════════════════════════════════════════════════════════════════
// HARDEN-03-SETTLEMENT — the receipt surface, from the ledger's side
//
// AC-16: an ORDINARY transfer is byte-identical in behaviour and writes no
// receipt. This is the half that protects the ledger's highest-volume endpoint:
// the whole receipt mechanism costs a non-pool transfer ONE `Principal`
// comparison and nothing else — no stable-map read, no derivation, no hash.
//
// AC-11: the receipt map is reachable by the configured pool and by NOTHING
// else, and a wrong caller cannot learn whether a receipt exists by asking.
// ═════════════════════════════════════════════════════════════════════════════

/// The post-lane token init shape, used only by the two tests below. Every other
/// fixture in this file keeps the three-field `TokenInitArgs` and decodes
/// `pool_canister` as `None` — which is exactly D-3's decode-compatibility
/// claim, demonstrated by this file continuing to compile and pass around it.
#[derive(CandidType, Deserialize)]
struct SettlementTokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
    fee_collector: Option<Principal>,
    pool_canister: Option<Principal>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SettlementReceipt {
    Applied {
        block_index: u64,
        amount: Nat,
        fee_charged: Nat,
        request_hash: [u8; 32],
        applied_at_ns: u64,
    },
    Cancelled {
        request_hash: [u8; 32],
        closed_at_ns: u64,
    },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SettlementAttemptArgs {
    from: Account,
    spender_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SettlementLookup {
    Found(SettlementReceipt),
    Unrecorded,
    RetiredOrUnavailable,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SettlementClose {
    Applied(SettlementReceipt),
    Cancelled(SettlementReceipt),
    RetiredOrUnavailable,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum SettlementReceiptError {
    Unauthorized,
    RequestMismatch,
    UnsupportedProtocol,
}

fn deploy_settlement_token(pic: &PocketIc, owner: Principal, pool: Option<Principal>) -> Principal {
    let token = create_canister(pic);
    let init = SettlementTokenInitArgs {
        allocations: all_to(owner, p(0x02)).allocations,
        treasury: TREASURY(),
        staking_canister: p(0x02),
        fee_collector: None,
        pool_canister: pool,
    };
    pic.install_canister(
        token,
        token_test_wasm(),
        candid::encode_one(&init).expect("encode settlement init"),
        None,
    );
    token
}

fn settlement_receipt_count(pic: &PocketIc, token: Principal) -> u64 {
    decode(
        "deposit_receipt_count_for_test",
        pic.query_call(
            token,
            anon(),
            "deposit_receipt_count_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}

/// AC-16: an ordinary, non-pool `icrc2_transfer_from` writes NO receipt, and its
/// balance / allowance / fee / block effects are exactly what they were before
/// this lane.
///
/// The control at the end is what makes this an assertion about the SPENDER
/// rather than about the arguments: the identical call, made by the configured
/// pool with a memo and timestamp, DOES write a receipt. So the receipt path is
/// selected by who the spender is and nothing else.
#[test]
fn test_harden03_ac16_an_ordinary_transfer_from_writes_no_receipt() {
    let pic = PocketIc::new();
    let owner = p(0x70);
    let spender = p(0x71);
    let recipient = p(0x72);
    let pool = p(0x7F);
    let token = deploy_settlement_token(&pic, owner, Some(pool));

    let fee = to_u128(decode::<Nat, _>(
        "icrc1_fee (testing build: update)",
        pic.update_call(token, anon(), "icrc1_fee", candid::encode_args(()).unwrap()),
    ));
    approve(&pic, token, owner, spender, 1_000 * STSH).expect("approve");

    let owner_before = balance(&pic, token, owner);
    let recipient_before = balance(&pic, token, recipient);
    let treasury_before = balance(&pic, token, TREASURY());
    let allowance_before = allowance_of(&pic, token, owner, spender);
    assert_eq!(settlement_receipt_count(&pic, token), 0, "no receipts yet");

    let amount = 25 * STSH;
    let block = transfer_from(
        &pic,
        token,
        spender,
        Account { owner, subaccount: None },
        Account { owner: recipient, subaccount: None },
        amount,
        Some(fee),
    )
    .expect("AC-16: an ordinary transfer_from must succeed exactly as before");

    // Accounting is untouched by this lane.
    assert_eq!(
        balance(&pic, token, owner),
        owner_before - amount - fee,
        "AC-16: sender debited amount + fee, unchanged"
    );
    assert_eq!(
        balance(&pic, token, recipient),
        recipient_before + amount,
        "AC-16: recipient credited the amount, unchanged"
    );
    assert_eq!(
        balance(&pic, token, TREASURY()),
        treasury_before + fee,
        "AC-16: the fee is routed exactly as before"
    );
    assert_eq!(
        allowance_of(&pic, token, owner, spender),
        allowance_before - amount - fee,
        "AC-16: the allowance decrement is unchanged"
    );
    let _ = block;

    // The property the whole test is about.
    assert_eq!(
        settlement_receipt_count(&pic, token),
        0,
        "AC-16: a NON-POOL transfer must write no receipt. If this is 1, the \
         pool-path gate is selecting on something other than the spender, and every \
         ordinary transfer on this ledger is paying for a stable-map write."
    );

    // Control — the pool spending DOES write one, so the assertion above is
    // about the spender and not about some unrelated precondition.
    approve(&pic, token, owner, pool, 1_000 * STSH).expect("approve pool");
    transfer_from_ext(
        &pic,
        token,
        pool,
        Account { owner, subaccount: None },
        Account { owner: pool, subaccount: None },
        amount,
        Some(fee),
        Some(b"stsh/pool/F-2/deposit-memo/v1:control".to_vec()),
        Some(now_ns(&pic)),
    )
    .expect("control: the pool's own transfer must succeed");
    assert_eq!(
        settlement_receipt_count(&pic, token),
        1,
        "control: the configured pool's transfer DOES write a receipt"
    );
}

/// AC-11: the receipt endpoints reject every non-pool caller — including the
/// anonymous principal — with an IDENTICAL response whether or not a receipt
/// exists for the derived operation id. And NO token query returns receipt data.
///
/// The "identical" half is the one that matters and is easy to get wrong. If the
/// authority check sat after the map read, a wrong caller could distinguish
/// "there is a receipt here" from "there is not" by the error it got back — a
/// linkability oracle over deposit operations, built out of an access-control
/// ordering mistake. The check is first, before any existence-sensitive read,
/// and this asserts the observable consequence rather than the ordering.
#[test]
fn test_harden03_ac11_receipt_endpoints_reject_non_pool_callers_indistinguishably() {
    let pic = PocketIc::new();
    let owner = p(0x80);
    let pool = p(0x8F);
    let token = deploy_settlement_token(&pic, owner, Some(pool));

    // One operation id that HAS a receipt, and one that does not.
    let present_memo = b"stsh/settlement/ac11/present".to_vec();
    let absent_memo = b"stsh/settlement/ac11/absent".to_vec();
    let present_op: [u8; 32] = decode(
        "deposit_operation_id_for_test",
        pic.query_call(
            token,
            anon(),
            "deposit_operation_id_for_test",
            candid::encode_one(present_memo.clone()).unwrap(),
        ),
    );
    let _: () = decode(
        "inject_deposit_receipt_for_test",
        pic.update_call(
            token,
            anon(),
            "inject_deposit_receipt_for_test",
            candid::encode_args((
                present_op,
                SettlementReceipt::Cancelled {
                    request_hash: [0x11u8; 32],
                    closed_at_ns: 99,
                },
            ))
            .unwrap(),
        ),
    );
    assert_eq!(
        settlement_receipt_count(&pic, token),
        1,
        "fixture: exactly one receipt exists"
    );

    let args_for = |memo: Vec<u8>| SettlementAttemptArgs {
        from: Account { owner, subaccount: None },
        spender_subaccount: None,
        to: Account { owner: pool, subaccount: None },
        amount: Nat::from(10u128 * STSH),
        fee: Some(Nat::from(0u128)),
        memo: Some(memo),
        created_at_time: Some(now_ns(&pic)),
    };

    for caller in [anon(), owner, p(0xDE)] {
        for (label, memo) in [
            ("receipt PRESENT", present_memo.clone()),
            ("receipt ABSENT", absent_memo.clone()),
        ] {
            let read: Result<SettlementLookup, SettlementReceiptError> = decode(
                "get_deposit_receipt",
                pic.update_call(
                    token,
                    caller,
                    "get_deposit_receipt",
                    candid::encode_one(args_for(memo.clone())).unwrap(),
                ),
            );
            assert_eq!(
                read.err(),
                Some(SettlementReceiptError::Unauthorized),
                "AC-11: caller {caller} reading with a {label} must get Unauthorized — \
                 the SAME answer in both cases, so the reply reveals nothing about \
                 whether the receipt exists"
            );

            let close: Result<SettlementClose, SettlementReceiptError> = decode(
                "close_deposit_attempt",
                pic.update_call(
                    token,
                    caller,
                    "close_deposit_attempt",
                    candid::encode_one(args_for(memo)).unwrap(),
                ),
            );
            assert_eq!(
                close.err(),
                Some(SettlementReceiptError::Unauthorized),
                "AC-11: caller {caller} closing with a {label} must get Unauthorized"
            );
        }
    }

    // A refused call writes nothing — in particular, a refused CLOSE must not
    // have planted a fence.
    assert_eq!(
        settlement_receipt_count(&pic, token),
        1,
        "AC-11: twelve refused calls wrote nothing"
    );

    // NO TOKEN QUERY RETURNS RECEIPT DATA. Both endpoints are updates, so a
    // query call to either is rejected outright — which is the strongest form
    // of P-1 available: not "the query returns nothing useful", but "there is
    // no query".
    assert!(
        pic.query_call(
            token,
            pool,
            "get_deposit_receipt",
            candid::encode_one(args_for(present_memo.clone())).unwrap(),
        )
        .is_err(),
        "AC-11: get_deposit_receipt must not be callable as a QUERY — the receipt map \
         is exposed by no query at all (P-1)"
    );
    assert!(
        pic.query_call(
            token,
            pool,
            "close_deposit_attempt",
            candid::encode_one(args_for(present_memo)).unwrap(),
        )
        .is_err(),
        "AC-11: close_deposit_attempt must not be callable as a QUERY"
    );
}
