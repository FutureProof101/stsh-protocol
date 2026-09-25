import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface Account {
  'owner' : Principal,
  'subaccount' : [] | [Uint8Array | number[]],
}
export interface AllocationCategory {
  'created_at_genesis' : boolean,
  'vesting_policy' : [] | [VestingPolicy],
  'subaccount' : [] | [Uint8Array | number[]],
  'recipient' : Principal,
  'lock_policy' : LockPolicy,
  'category_name' : string,
  'genesis_timestamp_ns' : bigint,
  'amount' : bigint,
  'category_id' : string,
}
export interface Allowance {
  'allowance' : bigint,
  'expires_at' : [] | [bigint],
}
export interface AllowanceArgs { 'account' : Account, 'spender' : Account }
export interface ApproveArgs {
  'fee' : [] | [bigint],
  'memo' : [] | [Uint8Array | number[]],
  'from_subaccount' : [] | [Uint8Array | number[]],
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
  'expected_allowance' : [] | [bigint],
  'expires_at' : [] | [bigint],
  'spender' : Account,
}
export type ApproveError = {
    'GenericError' : { 'message' : string, 'error_code' : bigint }
  } |
  { 'TemporarilyUnavailable' : null } |
  { 'Duplicate' : { 'duplicate_of' : bigint } } |
  { 'BadFee' : { 'expected_fee' : bigint } } |
  { 'AllowanceChanged' : { 'current_allowance' : bigint } } |
  { 'CreatedInFuture' : { 'ledger_time' : bigint } } |
  { 'TooOld' : null } |
  { 'Expired' : { 'ledger_time' : bigint } } |
  { 'InsufficientFunds' : { 'balance' : bigint } };
export interface AuthorityRefs {
  'fee_collector' : [] | [Principal],
  'staking_canister' : Principal,
  'treasury' : Principal,
}
export interface BuildInfo {
  'governance_canister' : [] | [Principal],
  'mint_done' : boolean,
  'version' : string,
  'staking_canister' : [] | [Principal],
  'canister_name' : string,
  'treasury' : [] | [Principal],
}
export type CloseOutcome = { 'RetiredOrUnavailable' : null } |
  { 'Applied' : DepositReceiptView } |
  { 'Cancelled' : DepositReceiptView };
export interface DepositAttemptArgs {
  'to' : Account,
  'fee' : [] | [bigint],
  'spender_subaccount' : [] | [Uint8Array | number[]],
  'from' : Account,
  'memo' : [] | [Uint8Array | number[]],
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
}
export type DepositReceiptView = {
    'Applied' : {
      'request_hash' : Uint8Array | number[],
      'block_index' : bigint,
      'applied_at_ns' : bigint,
      'fee_charged' : bigint,
      'amount' : bigint,
    }
  } |
  {
    'Cancelled' : {
      'request_hash' : Uint8Array | number[],
      'closed_at_ns' : bigint,
    }
  };
export type LockPolicy = { 'GovernanceLocked' : null } |
  { 'ImmediatelyLiquid' : null } |
  { 'LockedUntil' : bigint } |
  { 'Vested' : null };
export type ReceiptError = { 'RequestMismatch' : null } |
  { 'Unauthorized' : null } |
  { 'UnsupportedProtocol' : null };
export type ReceiptLookup = { 'RetiredOrUnavailable' : null } |
  { 'Unrecorded' : null } |
  { 'Found' : DepositReceiptView };
export interface SupplyInvariantReport {
  'checked_at_ns' : bigint,
  'arithmetic_error' : [] | [
    {
      'balances_overflow' : boolean,
      'balances_plus_fee_overflow' : boolean,
      'staking_locks_overflow' : boolean,
    }
  ],
  'fee_reserve_total' : bigint,
  'fixed_max_supply' : bigint,
  'invariant_holds' : boolean,
  'violation_detail' : [] | [string],
  'staking_locked_total' : bigint,
  'sum_all_balances' : bigint,
}
export interface SupplyReconciliation {
  'rows_examined' : bigint,
  'maintained_sum_staking_locks' : bigint,
  'fee_reserve' : bigint,
  'folded_sum_balances' : bigint,
  'totals_consistent' : boolean,
  'detail' : [] | [string],
  'maintained_sum_balances' : bigint,
  'folded_sum_staking_locks' : bigint,
  'folded_first_law_holds' : boolean,
}
export interface TransferArgs {
  'to' : Account,
  'fee' : [] | [bigint],
  'memo' : [] | [Uint8Array | number[]],
  'from_subaccount' : [] | [Uint8Array | number[]],
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
}
export type TransferError = {
    'GenericError' : { 'message' : string, 'error_code' : bigint }
  } |
  { 'TemporarilyUnavailable' : null } |
  { 'BadBurn' : { 'min_burn_amount' : bigint } } |
  { 'Duplicate' : { 'duplicate_of' : bigint } } |
  { 'BadFee' : { 'expected_fee' : bigint } } |
  { 'CreatedInFuture' : { 'ledger_time' : bigint } } |
  { 'TooOld' : null } |
  { 'InsufficientFunds' : { 'balance' : bigint } };
export interface TransferFromArgs {
  'to' : Account,
  'fee' : [] | [bigint],
  'spender_subaccount' : [] | [Uint8Array | number[]],
  'from' : Account,
  'memo' : [] | [Uint8Array | number[]],
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
}
export type TransferFromError = {
    'GenericError' : { 'message' : string, 'error_code' : bigint }
  } |
  { 'TemporarilyUnavailable' : null } |
  { 'InsufficientAllowance' : { 'allowance' : bigint } } |
  { 'BadBurn' : { 'min_burn_amount' : bigint } } |
  { 'Duplicate' : { 'duplicate_of' : bigint } } |
  { 'BadFee' : { 'expected_fee' : bigint } } |
  { 'CreatedInFuture' : { 'ledger_time' : bigint } } |
  { 'TooOld' : null } |
  { 'InsufficientFunds' : { 'balance' : bigint } };
export interface VestingPolicy {
  'vesting_end_ns' : bigint,
  'cliff_end_ns' : bigint,
}
export interface icrc21_consent_info {
  'metadata' : icrc21_consent_message_metadata,
  'consent_message' : icrc21_consent_message,
}
export type icrc21_consent_message = {
    'FieldsDisplayMessage' : icrc21_fields_display
  } |
  { 'GenericDisplayMessage' : string };
export interface icrc21_consent_message_metadata {
  'utc_offset_minutes' : [] | [number],
  'language' : string,
}
export interface icrc21_consent_message_request {
  'arg' : Uint8Array | number[],
  'method' : string,
  'user_preferences' : icrc21_consent_message_spec,
}
export type icrc21_consent_message_response = { 'Ok' : icrc21_consent_info } |
  { 'Err' : icrc21_error };
export interface icrc21_consent_message_spec {
  'metadata' : icrc21_consent_message_metadata,
  'device_spec' : [] | [
    { 'GenericDisplay' : null } |
      { 'FieldsDisplay' : null }
  ],
}
export type icrc21_error = {
    'GenericError' : { 'description' : string, 'error_code' : bigint }
  } |
  { 'InsufficientPayment' : icrc21_error_info } |
  { 'UnsupportedCanisterCall' : icrc21_error_info } |
  { 'ConsentMessageUnavailable' : icrc21_error_info };
export interface icrc21_error_info { 'description' : string }
export interface icrc21_fields_display {
  'fields' : Array<[string, icrc21_value]>,
  'intent' : string,
}
export type icrc21_value = { 'Text' : { 'content' : string } } |
  {
    'TokenAmount' : {
      'decimals' : number,
      'amount' : bigint,
      'symbol' : string,
    }
  } |
  { 'TimestampSeconds' : { 'amount' : bigint } } |
  { 'DurationSeconds' : { 'amount' : bigint } };
export interface _SERVICE {
  'close_deposit_attempt' : ActorMethod<
    [DepositAttemptArgs],
    { 'Ok' : CloseOutcome } |
      { 'Err' : ReceiptError }
  >,
  'cycle_balance' : ActorMethod<[], bigint>,
  'get_allocation_by_category' : ActorMethod<
    [string],
    [] | [AllocationCategory]
  >,
  'get_authority_refs' : ActorMethod<[], AuthorityRefs>,
  'get_build_info' : ActorMethod<[], BuildInfo>,
  'get_deposit_receipt' : ActorMethod<
    [DepositAttemptArgs],
    { 'Ok' : ReceiptLookup } |
      { 'Err' : ReceiptError }
  >,
  'get_deposit_settlement_authority' : ActorMethod<[], [] | [Principal]>,
  'get_genesis_allocations' : ActorMethod<[], Array<AllocationCategory>>,
  'icrc10_supported_standards' : ActorMethod<
    [],
    Array<{ 'url' : string, 'name' : string }>
  >,
  'icrc1_balance_of' : ActorMethod<[Account], bigint>,
  'icrc1_decimals' : ActorMethod<[], number>,
  'icrc1_fee' : ActorMethod<[], bigint>,
  'icrc1_metadata' : ActorMethod<
    [],
    Array<
      [
        string,
        { 'Int' : bigint } |
          { 'Nat' : bigint } |
          { 'Blob' : Uint8Array | number[] } |
          { 'Text' : string },
      ]
    >
  >,
  'icrc1_minting_account' : ActorMethod<[], [] | [Account]>,
  'icrc1_name' : ActorMethod<[], string>,
  'icrc1_supported_standards' : ActorMethod<
    [],
    Array<{ 'url' : string, 'name' : string }>
  >,
  'icrc1_symbol' : ActorMethod<[], string>,
  'icrc1_total_supply' : ActorMethod<[], bigint>,
  'icrc1_transfer' : ActorMethod<
    [TransferArgs],
    { 'Ok' : bigint } |
      { 'Err' : TransferError }
  >,
  'icrc21_canister_call_consent_message' : ActorMethod<
    [icrc21_consent_message_request],
    icrc21_consent_message_response
  >,
  'icrc2_allowance' : ActorMethod<[AllowanceArgs], Allowance>,
  'icrc2_approve' : ActorMethod<
    [ApproveArgs],
    { 'Ok' : bigint } |
      { 'Err' : ApproveError }
  >,
  'icrc2_transfer_from' : ActorMethod<
    [TransferFromArgs],
    { 'Ok' : bigint } |
      { 'Err' : TransferFromError }
  >,
  'liquid_balance' : ActorMethod<[Principal], bigint>,
  'lock_for_staking' : ActorMethod<
    [Principal, bigint],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'reconcile_supply_invariant' : ActorMethod<[], SupplyReconciliation>,
  'staking_locked_balance' : ActorMethod<[Principal], bigint>,
  'unlock_from_staking' : ActorMethod<
    [Principal, bigint],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'verify_supply_invariant' : ActorMethod<[], SupplyInvariantReport>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
