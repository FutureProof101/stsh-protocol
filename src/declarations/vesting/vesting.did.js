export const idlFactory = ({ IDL }) => {
  const CanisterRefsReadback = IDL.Record({
    'controller' : IDL.Principal,
    'token_canister' : IDL.Principal,
  });
  const VestingSchedule = IDL.Record({
    'vesting_end_ns' : IDL.Nat64,
    'total_amount' : IDL.Nat,
    'beneficiary' : IDL.Principal,
    'start_ns' : IDL.Nat64,
    'claimed' : IDL.Nat,
    'cliff_end_ns' : IDL.Nat64,
  });
  const ClaimMarkerState = IDL.Variant({
    'Stuck' : IDL.Null,
    'InFlight' : IDL.Null,
  });
  const OutstandingClaimMarker = IDL.Record({
    'pending_amount' : IDL.Opt(IDL.Nat),
    'created_at_time_ns' : IDL.Opt(IDL.Nat64),
    'beneficiary' : IDL.Principal,
    'claim_seq' : IDL.Opt(IDL.Nat64),
    'state' : ClaimMarkerState,
  });
  const OutstandingClaimMarkerError = IDL.Variant({
    'NotController' : IDL.Null,
    'ControllerNotConfigured' : IDL.Null,
  });
  const ClaimDecision = IDL.Variant({
    'Executed' : IDL.Null,
    'NotExecuted' : IDL.Null,
  });
  return IDL.Service({
    'claim' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : IDL.Text })],
        [],
      ),
    'claimable_amount' : IDL.Func([IDL.Principal], [IDL.Nat], ['query']),
    'get_canister_refs_readback' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : CanisterRefsReadback, 'Err' : IDL.Text })],
        ['query'],
      ),
    'get_schedule' : IDL.Func(
        [IDL.Principal],
        [IDL.Opt(VestingSchedule)],
        ['query'],
      ),
    'list_outstanding_claim_markers' : IDL.Func(
        [],
        [
          IDL.Variant({
            'Ok' : IDL.Vec(OutstandingClaimMarker),
            'Err' : OutstandingClaimMarkerError,
          }),
        ],
        ['query'],
      ),
    'list_schedules' : IDL.Func([], [IDL.Vec(VestingSchedule)], ['query']),
    'reconcile_claim' : IDL.Func(
        [IDL.Principal, ClaimDecision],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  return [
    IDL.Record({
      'controller' : IDL.Principal,
      'schedules' : IDL.Vec(
        IDL.Record({
          'total_amount' : IDL.Nat,
          'beneficiary' : IDL.Principal,
          'linear_months' : IDL.Nat32,
          'cliff_months' : IDL.Nat32,
        })
      ),
      'token_canister' : IDL.Principal,
    }),
  ];
};
