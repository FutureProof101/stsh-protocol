export const idlFactory = ({ IDL }) => {
  const VestingPolicy = IDL.Record({
    'vesting_end_ns' : IDL.Nat64,
    'cliff_end_ns' : IDL.Nat64,
  });
  const LockPolicy = IDL.Variant({
    'GovernanceLocked' : IDL.Null,
    'ImmediatelyLiquid' : IDL.Null,
    'LockedUntil' : IDL.Nat64,
    'Vested' : IDL.Null,
  });
  const AllocationCategory = IDL.Record({
    'created_at_genesis' : IDL.Bool,
    'vesting_policy' : IDL.Opt(VestingPolicy),
    'subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'recipient' : IDL.Principal,
    'lock_policy' : LockPolicy,
    'category_name' : IDL.Text,
    'genesis_timestamp_ns' : IDL.Nat64,
    'amount' : IDL.Nat,
    'category_id' : IDL.Text,
  });
  const Account = IDL.Record({
    'owner' : IDL.Principal,
    'subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
  });
  const DepositAttemptArgs = IDL.Record({
    'to' : Account,
    'fee' : IDL.Opt(IDL.Nat),
    'spender_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'from' : Account,
    'memo' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'created_at_time' : IDL.Opt(IDL.Nat64),
    'amount' : IDL.Nat,
  });
  const DepositReceiptView = IDL.Variant({
    'Applied' : IDL.Record({
      'request_hash' : IDL.Vec(IDL.Nat8),
      'block_index' : IDL.Nat64,
      'applied_at_ns' : IDL.Nat64,
      'fee_charged' : IDL.Nat,
      'amount' : IDL.Nat,
    }),
    'Cancelled' : IDL.Record({
      'request_hash' : IDL.Vec(IDL.Nat8),
      'closed_at_ns' : IDL.Nat64,
    }),
  });
  const CloseOutcome = IDL.Variant({
    'RetiredOrUnavailable' : IDL.Null,
    'Applied' : DepositReceiptView,
    'Cancelled' : DepositReceiptView,
  });
  const ReceiptError = IDL.Variant({
    'RequestMismatch' : IDL.Null,
    'Unauthorized' : IDL.Null,
    'UnsupportedProtocol' : IDL.Null,
  });
  const AuthorityRefs = IDL.Record({
    'fee_collector' : IDL.Opt(IDL.Principal),
    'staking_canister' : IDL.Principal,
    'treasury' : IDL.Principal,
  });
  const BuildInfo = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'mint_done' : IDL.Bool,
    'version' : IDL.Text,
    'staking_canister' : IDL.Opt(IDL.Principal),
    'canister_name' : IDL.Text,
    'treasury' : IDL.Opt(IDL.Principal),
  });
  const ReceiptLookup = IDL.Variant({
    'RetiredOrUnavailable' : IDL.Null,
    'Unrecorded' : IDL.Null,
    'Found' : DepositReceiptView,
  });
  const TransferArgs = IDL.Record({
    'to' : Account,
    'fee' : IDL.Opt(IDL.Nat),
    'memo' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'from_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'created_at_time' : IDL.Opt(IDL.Nat64),
    'amount' : IDL.Nat,
  });
  const TransferError = IDL.Variant({
    'GenericError' : IDL.Record({
      'message' : IDL.Text,
      'error_code' : IDL.Nat,
    }),
    'TemporarilyUnavailable' : IDL.Null,
    'BadBurn' : IDL.Record({ 'min_burn_amount' : IDL.Nat }),
    'Duplicate' : IDL.Record({ 'duplicate_of' : IDL.Nat }),
    'BadFee' : IDL.Record({ 'expected_fee' : IDL.Nat }),
    'CreatedInFuture' : IDL.Record({ 'ledger_time' : IDL.Nat64 }),
    'TooOld' : IDL.Null,
    'InsufficientFunds' : IDL.Record({ 'balance' : IDL.Nat }),
  });
  const icrc21_consent_message_metadata = IDL.Record({
    'utc_offset_minutes' : IDL.Opt(IDL.Int16),
    'language' : IDL.Text,
  });
  const icrc21_consent_message_spec = IDL.Record({
    'metadata' : icrc21_consent_message_metadata,
    'device_spec' : IDL.Opt(
      IDL.Variant({ 'GenericDisplay' : IDL.Null, 'FieldsDisplay' : IDL.Null })
    ),
  });
  const icrc21_consent_message_request = IDL.Record({
    'arg' : IDL.Vec(IDL.Nat8),
    'method' : IDL.Text,
    'user_preferences' : icrc21_consent_message_spec,
  });
  const icrc21_value = IDL.Variant({
    'Text' : IDL.Record({ 'content' : IDL.Text }),
    'TokenAmount' : IDL.Record({
      'decimals' : IDL.Nat8,
      'amount' : IDL.Nat64,
      'symbol' : IDL.Text,
    }),
    'TimestampSeconds' : IDL.Record({ 'amount' : IDL.Nat64 }),
    'DurationSeconds' : IDL.Record({ 'amount' : IDL.Nat64 }),
  });
  const icrc21_fields_display = IDL.Record({
    'fields' : IDL.Vec(IDL.Tuple(IDL.Text, icrc21_value)),
    'intent' : IDL.Text,
  });
  const icrc21_consent_message = IDL.Variant({
    'FieldsDisplayMessage' : icrc21_fields_display,
    'GenericDisplayMessage' : IDL.Text,
  });
  const icrc21_consent_info = IDL.Record({
    'metadata' : icrc21_consent_message_metadata,
    'consent_message' : icrc21_consent_message,
  });
  const icrc21_error_info = IDL.Record({ 'description' : IDL.Text });
  const icrc21_error = IDL.Variant({
    'GenericError' : IDL.Record({
      'description' : IDL.Text,
      'error_code' : IDL.Nat,
    }),
    'InsufficientPayment' : icrc21_error_info,
    'UnsupportedCanisterCall' : icrc21_error_info,
    'ConsentMessageUnavailable' : icrc21_error_info,
  });
  const icrc21_consent_message_response = IDL.Variant({
    'Ok' : icrc21_consent_info,
    'Err' : icrc21_error,
  });
  const AllowanceArgs = IDL.Record({
    'account' : Account,
    'spender' : Account,
  });
  const Allowance = IDL.Record({
    'allowance' : IDL.Nat,
    'expires_at' : IDL.Opt(IDL.Nat64),
  });
  const ApproveArgs = IDL.Record({
    'fee' : IDL.Opt(IDL.Nat),
    'memo' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'from_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'created_at_time' : IDL.Opt(IDL.Nat64),
    'amount' : IDL.Nat,
    'expected_allowance' : IDL.Opt(IDL.Nat),
    'expires_at' : IDL.Opt(IDL.Nat64),
    'spender' : Account,
  });
  const ApproveError = IDL.Variant({
    'GenericError' : IDL.Record({
      'message' : IDL.Text,
      'error_code' : IDL.Nat,
    }),
    'TemporarilyUnavailable' : IDL.Null,
    'Duplicate' : IDL.Record({ 'duplicate_of' : IDL.Nat }),
    'BadFee' : IDL.Record({ 'expected_fee' : IDL.Nat }),
    'AllowanceChanged' : IDL.Record({ 'current_allowance' : IDL.Nat }),
    'CreatedInFuture' : IDL.Record({ 'ledger_time' : IDL.Nat64 }),
    'TooOld' : IDL.Null,
    'Expired' : IDL.Record({ 'ledger_time' : IDL.Nat64 }),
    'InsufficientFunds' : IDL.Record({ 'balance' : IDL.Nat }),
  });
  const TransferFromArgs = IDL.Record({
    'to' : Account,
    'fee' : IDL.Opt(IDL.Nat),
    'spender_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'from' : Account,
    'memo' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'created_at_time' : IDL.Opt(IDL.Nat64),
    'amount' : IDL.Nat,
  });
  const TransferFromError = IDL.Variant({
    'GenericError' : IDL.Record({
      'message' : IDL.Text,
      'error_code' : IDL.Nat,
    }),
    'TemporarilyUnavailable' : IDL.Null,
    'InsufficientAllowance' : IDL.Record({ 'allowance' : IDL.Nat }),
    'BadBurn' : IDL.Record({ 'min_burn_amount' : IDL.Nat }),
    'Duplicate' : IDL.Record({ 'duplicate_of' : IDL.Nat }),
    'BadFee' : IDL.Record({ 'expected_fee' : IDL.Nat }),
    'CreatedInFuture' : IDL.Record({ 'ledger_time' : IDL.Nat64 }),
    'TooOld' : IDL.Null,
    'InsufficientFunds' : IDL.Record({ 'balance' : IDL.Nat }),
  });
  const SupplyReconciliation = IDL.Record({
    'rows_examined' : IDL.Nat64,
    'maintained_sum_staking_locks' : IDL.Nat,
    'fee_reserve' : IDL.Nat,
    'folded_sum_balances' : IDL.Nat,
    'totals_consistent' : IDL.Bool,
    'detail' : IDL.Opt(IDL.Text),
    'maintained_sum_balances' : IDL.Nat,
    'folded_sum_staking_locks' : IDL.Nat,
    'folded_first_law_holds' : IDL.Bool,
  });
  const SupplyInvariantReport = IDL.Record({
    'checked_at_ns' : IDL.Nat64,
    'arithmetic_error' : IDL.Opt(
      IDL.Record({
        'balances_overflow' : IDL.Bool,
        'balances_plus_fee_overflow' : IDL.Bool,
        'staking_locks_overflow' : IDL.Bool,
      })
    ),
    'fee_reserve_total' : IDL.Nat,
    'fixed_max_supply' : IDL.Nat,
    'invariant_holds' : IDL.Bool,
    'violation_detail' : IDL.Opt(IDL.Text),
    'staking_locked_total' : IDL.Nat,
    'sum_all_balances' : IDL.Nat,
  });
  return IDL.Service({
    'close_deposit_attempt' : IDL.Func(
        [DepositAttemptArgs],
        [IDL.Variant({ 'Ok' : CloseOutcome, 'Err' : ReceiptError })],
        [],
      ),
    'cycle_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'get_allocation_by_category' : IDL.Func(
        [IDL.Text],
        [IDL.Opt(AllocationCategory)],
        ['query'],
      ),
    'get_authority_refs' : IDL.Func([], [AuthorityRefs], ['query']),
    'get_build_info' : IDL.Func([], [BuildInfo], ['query']),
    'get_deposit_receipt' : IDL.Func(
        [DepositAttemptArgs],
        [IDL.Variant({ 'Ok' : ReceiptLookup, 'Err' : ReceiptError })],
        [],
      ),
    'get_deposit_settlement_authority' : IDL.Func(
        [],
        [IDL.Opt(IDL.Principal)],
        ['query'],
      ),
    'get_genesis_allocations' : IDL.Func(
        [],
        [IDL.Vec(AllocationCategory)],
        ['query'],
      ),
    'icrc10_supported_standards' : IDL.Func(
        [],
        [IDL.Vec(IDL.Record({ 'url' : IDL.Text, 'name' : IDL.Text }))],
        ['query'],
      ),
    'icrc1_balance_of' : IDL.Func([Account], [IDL.Nat], ['query']),
    'icrc1_decimals' : IDL.Func([], [IDL.Nat8], ['query']),
    'icrc1_fee' : IDL.Func([], [IDL.Nat], ['query']),
    'icrc1_metadata' : IDL.Func(
        [],
        [
          IDL.Vec(
            IDL.Tuple(
              IDL.Text,
              IDL.Variant({
                'Int' : IDL.Int,
                'Nat' : IDL.Nat,
                'Blob' : IDL.Vec(IDL.Nat8),
                'Text' : IDL.Text,
              }),
            )
          ),
        ],
        ['query'],
      ),
    'icrc1_minting_account' : IDL.Func([], [IDL.Opt(Account)], ['query']),
    'icrc1_name' : IDL.Func([], [IDL.Text], ['query']),
    'icrc1_supported_standards' : IDL.Func(
        [],
        [IDL.Vec(IDL.Record({ 'url' : IDL.Text, 'name' : IDL.Text }))],
        ['query'],
      ),
    'icrc1_symbol' : IDL.Func([], [IDL.Text], ['query']),
    'icrc1_total_supply' : IDL.Func([], [IDL.Nat], ['query']),
    'icrc1_transfer' : IDL.Func(
        [TransferArgs],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : TransferError })],
        [],
      ),
    'icrc21_canister_call_consent_message' : IDL.Func(
        [icrc21_consent_message_request],
        [icrc21_consent_message_response],
        [],
      ),
    'icrc2_allowance' : IDL.Func([AllowanceArgs], [Allowance], ['query']),
    'icrc2_approve' : IDL.Func(
        [ApproveArgs],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : ApproveError })],
        [],
      ),
    'icrc2_transfer_from' : IDL.Func(
        [TransferFromArgs],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : TransferFromError })],
        [],
      ),
    'liquid_balance' : IDL.Func([IDL.Principal], [IDL.Nat], ['query']),
    'lock_for_staking' : IDL.Func(
        [IDL.Principal, IDL.Nat],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'reconcile_supply_invariant' : IDL.Func([], [SupplyReconciliation], []),
    'staking_locked_balance' : IDL.Func([IDL.Principal], [IDL.Nat], ['query']),
    'unlock_from_staking' : IDL.Func(
        [IDL.Principal, IDL.Nat],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'verify_supply_invariant' : IDL.Func(
        [],
        [SupplyInvariantReport],
        ['query'],
      ),
  });
};
export const init = ({ IDL }) => {
  const VestingPolicy = IDL.Record({
    'vesting_end_ns' : IDL.Nat64,
    'cliff_end_ns' : IDL.Nat64,
  });
  const LockPolicy = IDL.Variant({
    'GovernanceLocked' : IDL.Null,
    'ImmediatelyLiquid' : IDL.Null,
    'LockedUntil' : IDL.Nat64,
    'Vested' : IDL.Null,
  });
  const AllocationCategory = IDL.Record({
    'created_at_genesis' : IDL.Bool,
    'vesting_policy' : IDL.Opt(VestingPolicy),
    'subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'recipient' : IDL.Principal,
    'lock_policy' : LockPolicy,
    'category_name' : IDL.Text,
    'genesis_timestamp_ns' : IDL.Nat64,
    'amount' : IDL.Nat,
    'category_id' : IDL.Text,
  });
  return [
    IDL.Record({
      'fee_collector' : IDL.Opt(IDL.Principal),
      'staking_canister' : IDL.Principal,
      'allocations' : IDL.Vec(AllocationCategory),
      'pool_canister' : IDL.Opt(IDL.Principal),
      'treasury' : IDL.Principal,
    }),
  ];
};
