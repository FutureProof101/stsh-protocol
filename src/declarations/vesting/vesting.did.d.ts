import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface CanisterRefsReadback {
  'controller' : Principal,
  'token_canister' : Principal,
}
export type ClaimDecision = { 'Executed' : null } |
  { 'NotExecuted' : null };
export type ClaimMarkerState = { 'Stuck' : null } |
  { 'InFlight' : null };
export interface OutstandingClaimMarker {
  'pending_amount' : [] | [bigint],
  'created_at_time_ns' : [] | [bigint],
  'beneficiary' : Principal,
  'claim_seq' : [] | [bigint],
  'state' : ClaimMarkerState,
}
export type OutstandingClaimMarkerError = { 'NotController' : null } |
  { 'ControllerNotConfigured' : null };
export interface VestingSchedule {
  'vesting_end_ns' : bigint,
  'total_amount' : bigint,
  'beneficiary' : Principal,
  'start_ns' : bigint,
  'claimed' : bigint,
  'cliff_end_ns' : bigint,
}
export interface _SERVICE {
  'claim' : ActorMethod<[], { 'Ok' : bigint } | { 'Err' : string }>,
  'claimable_amount' : ActorMethod<[Principal], bigint>,
  'get_canister_refs_readback' : ActorMethod<
    [],
    { 'Ok' : CanisterRefsReadback } |
      { 'Err' : string }
  >,
  'get_schedule' : ActorMethod<[Principal], [] | [VestingSchedule]>,
  'list_outstanding_claim_markers' : ActorMethod<
    [],
    { 'Ok' : Array<OutstandingClaimMarker> } |
      { 'Err' : OutstandingClaimMarkerError }
  >,
  'list_schedules' : ActorMethod<[], Array<VestingSchedule>>,
  'reconcile_claim' : ActorMethod<
    [Principal, ClaimDecision],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
