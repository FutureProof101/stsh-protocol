// Stub token for BadFee integration tests (#120).
//
// icrc1_fee()        → 10_000 (an arbitrary NONZERO fee — deliberately NOT the
//                      real stsh_token DEFAULT_FEE, which is 0 since F-000; a
//                      nonzero value here keeps the BadFee scenario realistic)
// icrc1_transfer(_)  → Err(BadFee { expected_fee: 20_000 }) always
//
// Used by test_76 to verify that treasury.execute_withdrawal:
//   - treats BadFee as a terminal error (no silent retry with expected_fee)
//   - re-credits total_debit on BadFee
//   - leaves the proposal Pending for manual controller retry

use candid::{CandidType, Nat, Principal};
use ic_cdk_macros::{query, update};
use serde::{Deserialize, Serialize};

// Mirror of IcrcAccount in treasury — must be Candid-compatible with what
// treasury sends.  Vec<u8> for subaccount is Candid-equivalent to [u8; 32].
#[derive(CandidType, Deserialize)]
struct IcrcAccount {
    owner:      Principal,
    subaccount: Option<Vec<u8>>,
}

// Mirror of IcrcTransferArgs in treasury.  All fields are present to ensure
// Candid decoding succeeds; none are used since this stub always returns BadFee.
#[derive(CandidType, Deserialize)]
struct TransferArgs {
    from_subaccount: Option<Vec<u8>>,
    to:              IcrcAccount,
    amount:          Nat,
    fee:             Option<Nat>,
    memo:            Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize)]
enum TransferError {
    BadFee { expected_fee: Nat },
}

#[query]
fn icrc1_fee() -> Nat {
    Nat::from(10_000u64)
}

#[update]
fn icrc1_transfer(_args: TransferArgs) -> Result<Nat, TransferError> {
    Err(TransferError::BadFee { expected_fee: Nat::from(20_000u64) })
}
