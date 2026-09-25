export const idlFactory = ({ IDL }) => {
  const SignedApproval = IDL.Record({
    'issuer_device_id' : IDL.Text,
    'signature' : IDL.Vec(IDL.Nat8),
    'expiry_ns' : IDL.Nat64,
    'nonce' : IDL.Vec(IDL.Nat8),
  });
  const VetkeysError = IDL.Variant({
    'EligibilityCheckUnavailable' : IDL.Text,
    'CycleFloorReached' : IDL.Record({
      'liquid_cycles' : IDL.Nat,
      'required_cycles' : IDL.Nat,
    }),
    'BootstrapNotAuthorized' : IDL.Record({ 'reason' : IDL.Text }),
    'ApprovalRejected' : IDL.Text,
    'PrincipalNotEligible' : IDL.Text,
    'UnknownDevice' : IDL.Null,
    'NotAuthorized' : IDL.Text,
    'RevocationRateExceeded' : IDL.Record({ 'retry_after_ns' : IDL.Nat64 }),
    'PrincipalHourlyDerivationCapExceeded' : IDL.Record({
      'retry_after_ns' : IDL.Nat64,
    }),
    'AdmissionLapsed' : IDL.Null,
    'EligibilityAgeNotMet' : IDL.Record({ 'retry_after_ns' : IDL.Nat64 }),
    'RegistrationRateExceeded' : IDL.Record({ 'retry_after_ns' : IDL.Nat64 }),
    'RateLimited' : IDL.Text,
    'DerivationQuotaExceeded' : IDL.Record({ 'retry_after_ns' : IDL.Nat64 }),
    'InvalidRequest' : IDL.Text,
    'DeviceLimitReached' : IDL.Record({ 'active' : IDL.Nat32 }),
    'InvalidTransportKey' : IDL.Text,
    'DeviceRevoked' : IDL.Null,
    'GlobalDerivationBudgetExceeded' : IDL.Record({
      'retry_after_ns' : IDL.Nat64,
    }),
    'AnonymousCaller' : IDL.Null,
  });
  const CycleFloorView = IDL.Variant({
    'FloorOnly' : IDL.Record({
      'meets_pinned_floor' : IDL.Bool,
      'reason' : IDL.Text,
    }),
    'Live' : IDL.Record({ 'admits' : IDL.Bool }),
    'Unavailable' : IDL.Text,
  });
  const DeriveBudgetStats = IDL.Record({
    'floor' : CycleFloorView,
    'age_refusals_total' : IDL.Nat64,
    'sightings_pending' : IDL.Nat32,
    'max_by_one_principal' : IDL.Nat32,
    'stats_epoch_ns' : IDL.Nat64,
    'first_derive_dispatches' : IDL.Nat32,
    'window_ns' : IDL.Nat64,
    'retry_after_ns' : IDL.Nat64,
    'consumed' : IDL.Nat32,
    'distinct_principals' : IDL.Nat32,
    'tagged_consumed' : IDL.Nat32,
    'budget' : IDL.Nat32,
    'verification_key_management_calls_total' : IDL.Nat64,
    'sightings_recorded_total' : IDL.Nat64,
    'refusals_budget_total' : IDL.Nat64,
  });
  const DeviceApprovalPolicyView = IDL.Record({
    'require_device_approval' : IDL.Bool,
    'set_at_ns' : IDL.Nat64,
    'pending_clear_effective_at_ns' : IDL.Opt(IDL.Nat64),
  });
  const EncryptedVetKeyReply = IDL.Record({
    'encrypted_key' : IDL.Vec(IDL.Nat8),
    'remaining' : IDL.Nat8,
  });
  const DeviceCheckRefusal = IDL.Variant({
    'CallerNotAuthorized' : IDL.Null,
    'CallerNotConfigured' : IDL.Null,
  });
  const DeviceView = IDL.Record({
    'active' : IDL.Bool,
    'added_at_ns' : IDL.Nat64,
    'device_id' : IDL.Text,
    'enc_pubkey_spki' : IDL.Vec(IDL.Nat8),
    'approved_by_device' : IDL.Opt(IDL.Text),
    'revoked_at_ns' : IDL.Opt(IDL.Nat64),
    'sign_pubkey_spki' : IDL.Vec(IDL.Nat8),
  });
  const RebootstrapPolicyView = IDL.Record({
    'allow_re_bootstrap' : IDL.Bool,
    'authorized_at_ns' : IDL.Nat64,
  });
  const DeviceApproval = IDL.Variant({
    'Bootstrap' : IDL.Null,
    'Device' : SignedApproval,
  });
  return IDL.Service({
    'authorize_re_bootstrap' : IDL.Func(
        [IDL.Principal, SignedApproval],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : VetkeysError })],
        [],
      ),
    'cycle_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'derive_budget_stats' : IDL.Func([], [DeriveBudgetStats], ['query']),
    'device_approval_policy' : IDL.Func(
        [],
        [IDL.Opt(DeviceApprovalPolicyView)],
        ['query'],
      ),
    'get_config' : IDL.Func([], [IDL.Text, IDL.Text], ['query']),
    'get_device_check_caller' : IDL.Func(
        [],
        [IDL.Opt(IDL.Principal)],
        ['query'],
      ),
    'get_encrypted_vetkey' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : EncryptedVetKeyReply, 'Err' : VetkeysError })],
        [],
      ),
    'get_token_canister' : IDL.Func([], [IDL.Opt(IDL.Principal)], ['query']),
    'get_vetkey_verification_key' : IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    'get_wrapped_secret' : IDL.Func(
        [IDL.Text],
        [IDL.Variant({ 'Ok' : IDL.Vec(IDL.Nat8), 'Err' : VetkeysError })],
        ['query'],
      ),
    'has_active_device' : IDL.Func(
        [IDL.Principal],
        [IDL.Variant({ 'Ok' : IDL.Bool, 'Err' : DeviceCheckRefusal })],
        ['query'],
      ),
    'list_devices' : IDL.Func([], [IDL.Vec(DeviceView)], ['query']),
    're_bootstrap_policy' : IDL.Func(
        [],
        [IDL.Opt(RebootstrapPolicyView)],
        ['query'],
      ),
    'refresh_vetkey_verification_key_cache' : IDL.Func(
        [],
        [IDL.Vec(IDL.Nat8)],
        [],
      ),
    'register_device' : IDL.Func(
        [
          IDL.Text,
          IDL.Vec(IDL.Nat8),
          IDL.Vec(IDL.Nat8),
          IDL.Vec(IDL.Nat8),
          DeviceApproval,
        ],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : VetkeysError })],
        [],
      ),
    'replace_envelope' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8), SignedApproval],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : VetkeysError })],
        [],
      ),
    'request_device_approval_policy_clear' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : VetkeysError })],
        [],
      ),
    'revoke_device' : IDL.Func(
        [IDL.Text, SignedApproval],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : VetkeysError })],
        [],
      ),
    'set_device_approval_policy' : IDL.Func(
        [IDL.Bool, SignedApproval],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : VetkeysError })],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  return [IDL.Text, IDL.Opt(IDL.Principal), IDL.Opt(IDL.Principal)];
};
