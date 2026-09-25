import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type EmergencyPauseTarget = { 'Both' : null } |
  { 'PoolDeposits' : null } |
  { 'PoolSpends' : null };
export interface GovernanceParams {
  'approval_threshold_bps' : number,
  'voting_period_ns' : bigint,
  'vk_upgrade_timelock_ns' : bigint,
  'quorum_bps' : number,
  'min_proposal_deposit' : bigint,
  'execution_timelock_ns' : bigint,
  'voting_delay_ns' : bigint,
  'vk_quorum_bps' : number,
  'treasury_quorum_bps' : number,
}
export interface InitArgs {
  'treasury_canister' : Principal,
  'token_canister' : Principal,
  'initial_rewards_pool' : bigint,
  'initial_emission_rate_per_day' : bigint,
  'governance_params' : [] | [GovernanceParams],
  'pool_canister' : Principal,
}
export type LockDecision = { 'Executed' : null } |
  { 'NotExecuted' : null };
export type LockOpType = { 'Lock' : null } |
  { 'Unlock' : null };
export interface PendingLockOp {
  'snapshot' : StakePosition,
  'op_id' : bigint,
  'initiated_at_ns' : bigint,
  'holder' : Principal,
  'op_type' : LockOpType,
  'amount' : bigint,
  'position_id' : bigint,
}
export interface Proposal {
  'id' : bigint,
  'execution_result' : [] | [string],
  'status' : ProposalStatus,
  'description' : string,
  'created_at_ns' : bigint,
  'voting_opens_ns' : bigint,
  'executed_at_ns' : [] | [bigint],
  'proposer' : Principal,
  'votes_for' : bigint,
  'execute_after_ns' : bigint,
  'voting_closes_ns' : bigint,
  'proposal_type' : ProposalType,
  'votes_against' : bigint,
}
export type ProposalStatus = { 'Passed' : null } |
  { 'VotingClosed' : null } |
  { 'Executing' : null } |
  { 'Rejected' : null } |
  { 'VotingOpen' : null } |
  { 'Executed' : null } |
  { 'Cancelled' : null } |
  { 'VotingPending' : null } |
  { 'Expired' : null };
export type ProposalType = {
    'RewardScheduleUpdate' : { 'new_emission_rate_per_day' : bigint }
  } |
  {
    'FeeUpdate' : {
      'transfer_bps' : number,
      'unshield_bps' : number,
      'shield_bps' : number,
    }
  } |
  { 'ParameterUpdate' : { 'key' : string, 'value' : string } } |
  {
    'EmergencyPause' : { 'target' : EmergencyPauseTarget, 'reason' : string }
  } |
  {
    'CanisterUpgrade' : {
      'canister_id' : Principal,
      'description' : string,
      'wasm_hash' : Uint8Array | number[],
    }
  } |
  {
    'TreasurySpend' : {
      'subaccount' : string,
      'recipient' : Principal,
      'amount' : bigint,
      'reason' : string,
    }
  } |
  { 'GovernanceParamUpdate' : GovernanceParams } |
  { 'VerifierKeyUpgrade' : VerifierKeyUpgradePayload };
export interface RewardSourceBreakdown {
  'fee_revenue_pct' : number,
  'disclosure' : string,
  'incentive_allocation_pct' : number,
}
export interface StakePosition {
  'voting_weight' : bigint,
  'closed' : boolean,
  'op_id' : [] | [bigint],
  'rewards_claimed' : bigint,
  'created_at_ns' : bigint,
  'lock_days' : number,
  'lock_end_ns' : bigint,
  'holder' : Principal,
  'last_claim_ns' : bigint,
  'amount' : bigint,
  'position_id' : bigint,
}
export interface VerifierKeyUpgradePayload {
  'circuit_version' : number,
  'audit_artifact_hash' : Uint8Array | number[],
  'activation_timestamp_ns' : bigint,
  'emergency_disable_supported' : boolean,
  'new_verifying_key_hash' : Uint8Array | number[],
  'old_verifying_key_hash' : Uint8Array | number[],
  'circuit_source_commit' : string,
  'proof_system_id' : string,
  'verifier_wasm_hash' : Uint8Array | number[],
  'audit_artifact_url' : string,
}
export interface _SERVICE {
  'claim_rewards' : ActorMethod<
    [bigint],
    { 'Ok' : bigint } |
      { 'Err' : string }
  >,
  'create_proposal' : ActorMethod<
    [ProposalType, string],
    { 'Ok' : bigint } |
      { 'Err' : string }
  >,
  'execute_proposal' : ActorMethod<
    [bigint],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'get_build_info' : ActorMethod<[], string>,
  'get_governance_params' : ActorMethod<[], GovernanceParams>,
  'get_pending_rewards' : ActorMethod<[Principal], bigint>,
  'get_reward_source_breakdown' : ActorMethod<[], RewardSourceBreakdown>,
  'get_rewards_pool_balance' : ActorMethod<[], bigint>,
  'get_stake_positions' : ActorMethod<[Principal], Array<StakePosition>>,
  'get_total_voting_weight' : ActorMethod<[], bigint>,
  'list_pending_lock_ops' : ActorMethod<[], Array<PendingLockOp>>,
  'list_proposals_by_status' : ActorMethod<
    [[] | [ProposalStatus]],
    Array<Proposal>
  >,
  'receive_fee_revenue' : ActorMethod<[bigint], undefined>,
  'reconcile_lock' : ActorMethod<
    [bigint, LockDecision],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'reconcile_unlock' : ActorMethod<
    [bigint, LockDecision],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'stake' : ActorMethod<
    [bigint, number],
    { 'Ok' : bigint } |
      { 'Err' : string }
  >,
  'unstake' : ActorMethod<[bigint], { 'Ok' : null } | { 'Err' : string }>,
  'vote' : ActorMethod<[bigint, boolean], { 'Ok' : null } | { 'Err' : string }>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
