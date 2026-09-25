import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type CycleFloorView = {
    'FloorOnly' : { 'meets_pinned_floor' : boolean, 'reason' : string }
  } |
  { 'Live' : { 'admits' : boolean } } |
  { 'Unavailable' : string };
export interface DeriveBudgetStats {
  'floor' : CycleFloorView,
  'age_refusals_total' : bigint,
  'sightings_pending' : number,
  'max_by_one_principal' : number,
  'stats_epoch_ns' : bigint,
  'first_derive_dispatches' : number,
  'window_ns' : bigint,
  'retry_after_ns' : bigint,
  'consumed' : number,
  'distinct_principals' : number,
  'tagged_consumed' : number,
  'budget' : number,
  'verification_key_management_calls_total' : bigint,
  'sightings_recorded_total' : bigint,
  'refusals_budget_total' : bigint,
}
export type DeviceApproval = { 'Bootstrap' : null } |
  { 'Device' : SignedApproval };
export interface DeviceApprovalPolicyView {
  'require_device_approval' : boolean,
  'set_at_ns' : bigint,
  'pending_clear_effective_at_ns' : [] | [bigint],
}
export type DeviceCheckRefusal = { 'CallerNotAuthorized' : null } |
  { 'CallerNotConfigured' : null };
export interface DeviceView {
  'active' : boolean,
  'added_at_ns' : bigint,
  'device_id' : string,
  'enc_pubkey_spki' : Uint8Array | number[],
  'approved_by_device' : [] | [string],
  'revoked_at_ns' : [] | [bigint],
  'sign_pubkey_spki' : Uint8Array | number[],
}
export interface EncryptedVetKeyReply {
  'encrypted_key' : Uint8Array | number[],
  'remaining' : number,
}
export interface RebootstrapPolicyView {
  'allow_re_bootstrap' : boolean,
  'authorized_at_ns' : bigint,
}
export interface SignedApproval {
  'issuer_device_id' : string,
  'signature' : Uint8Array | number[],
  'expiry_ns' : bigint,
  'nonce' : Uint8Array | number[],
}
export type VetkeysError = { 'EligibilityCheckUnavailable' : string } |
  {
    'CycleFloorReached' : {
      'liquid_cycles' : bigint,
      'required_cycles' : bigint,
    }
  } |
  { 'BootstrapNotAuthorized' : { 'reason' : string } } |
  { 'ApprovalRejected' : string } |
  { 'PrincipalNotEligible' : string } |
  { 'UnknownDevice' : null } |
  { 'NotAuthorized' : string } |
  { 'RevocationRateExceeded' : { 'retry_after_ns' : bigint } } |
  { 'PrincipalHourlyDerivationCapExceeded' : { 'retry_after_ns' : bigint } } |
  { 'AdmissionLapsed' : null } |
  { 'EligibilityAgeNotMet' : { 'retry_after_ns' : bigint } } |
  { 'RegistrationRateExceeded' : { 'retry_after_ns' : bigint } } |
  { 'RateLimited' : string } |
  { 'DerivationQuotaExceeded' : { 'retry_after_ns' : bigint } } |
  { 'InvalidRequest' : string } |
  { 'DeviceLimitReached' : { 'active' : number } } |
  { 'InvalidTransportKey' : string } |
  { 'DeviceRevoked' : null } |
  { 'GlobalDerivationBudgetExceeded' : { 'retry_after_ns' : bigint } } |
  { 'AnonymousCaller' : null };
export interface _SERVICE {
  'authorize_re_bootstrap' : ActorMethod<
    [Principal, SignedApproval],
    { 'Ok' : null } |
      { 'Err' : VetkeysError }
  >,
  'cycle_balance' : ActorMethod<[], bigint>,
  'derive_budget_stats' : ActorMethod<[], DeriveBudgetStats>,
  'device_approval_policy' : ActorMethod<[], [] | [DeviceApprovalPolicyView]>,
  'get_config' : ActorMethod<[], [string, string]>,
  'get_device_check_caller' : ActorMethod<[], [] | [Principal]>,
  'get_encrypted_vetkey' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : EncryptedVetKeyReply } |
      { 'Err' : VetkeysError }
  >,
  'get_token_canister' : ActorMethod<[], [] | [Principal]>,
  'get_vetkey_verification_key' : ActorMethod<[], Uint8Array | number[]>,
  'get_wrapped_secret' : ActorMethod<
    [string],
    { 'Ok' : Uint8Array | number[] } |
      { 'Err' : VetkeysError }
  >,
  'has_active_device' : ActorMethod<
    [Principal],
    { 'Ok' : boolean } |
      { 'Err' : DeviceCheckRefusal }
  >,
  'list_devices' : ActorMethod<[], Array<DeviceView>>,
  're_bootstrap_policy' : ActorMethod<[], [] | [RebootstrapPolicyView]>,
  'refresh_vetkey_verification_key_cache' : ActorMethod<
    [],
    Uint8Array | number[]
  >,
  'register_device' : ActorMethod<
    [
      string,
      Uint8Array | number[],
      Uint8Array | number[],
      Uint8Array | number[],
      DeviceApproval,
    ],
    { 'Ok' : null } |
      { 'Err' : VetkeysError }
  >,
  'replace_envelope' : ActorMethod<
    [string, Uint8Array | number[], SignedApproval],
    { 'Ok' : null } |
      { 'Err' : VetkeysError }
  >,
  'request_device_approval_policy_clear' : ActorMethod<
    [],
    { 'Ok' : bigint } |
      { 'Err' : VetkeysError }
  >,
  'revoke_device' : ActorMethod<
    [string, SignedApproval],
    { 'Ok' : null } |
      { 'Err' : VetkeysError }
  >,
  'set_device_approval_policy' : ActorMethod<
    [boolean, SignedApproval],
    { 'Ok' : null } |
      { 'Err' : VetkeysError }
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
