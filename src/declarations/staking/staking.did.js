export const idlFactory = ({ IDL }) => {
  const GovernanceParams = IDL.Record({
    'approval_threshold_bps' : IDL.Nat32,
    'voting_period_ns' : IDL.Nat64,
    'vk_upgrade_timelock_ns' : IDL.Nat64,
    'quorum_bps' : IDL.Nat32,
    'min_proposal_deposit' : IDL.Nat,
    'execution_timelock_ns' : IDL.Nat64,
    'voting_delay_ns' : IDL.Nat64,
    'vk_quorum_bps' : IDL.Nat32,
    'treasury_quorum_bps' : IDL.Nat32,
  });
  const InitArgs = IDL.Record({
    'treasury_canister' : IDL.Principal,
    'token_canister' : IDL.Principal,
    'initial_rewards_pool' : IDL.Nat,
    'initial_emission_rate_per_day' : IDL.Nat,
    'governance_params' : IDL.Opt(GovernanceParams),
    'pool_canister' : IDL.Principal,
  });
  const EmergencyPauseTarget = IDL.Variant({
    'Both' : IDL.Null,
    'PoolDeposits' : IDL.Null,
    'PoolSpends' : IDL.Null,
  });
  const VerifierKeyUpgradePayload = IDL.Record({
    'circuit_version' : IDL.Nat32,
    'audit_artifact_hash' : IDL.Vec(IDL.Nat8),
    'activation_timestamp_ns' : IDL.Nat64,
    'emergency_disable_supported' : IDL.Bool,
    'new_verifying_key_hash' : IDL.Vec(IDL.Nat8),
    'old_verifying_key_hash' : IDL.Vec(IDL.Nat8),
    'circuit_source_commit' : IDL.Text,
    'proof_system_id' : IDL.Text,
    'verifier_wasm_hash' : IDL.Vec(IDL.Nat8),
    'audit_artifact_url' : IDL.Text,
  });
  const ProposalType = IDL.Variant({
    'RewardScheduleUpdate' : IDL.Record({
      'new_emission_rate_per_day' : IDL.Nat,
    }),
    'FeeUpdate' : IDL.Record({
      'transfer_bps' : IDL.Nat32,
      'unshield_bps' : IDL.Nat32,
      'shield_bps' : IDL.Nat32,
    }),
    'ParameterUpdate' : IDL.Record({ 'key' : IDL.Text, 'value' : IDL.Text }),
    'EmergencyPause' : IDL.Record({
      'target' : EmergencyPauseTarget,
      'reason' : IDL.Text,
    }),
    'CanisterUpgrade' : IDL.Record({
      'canister_id' : IDL.Principal,
      'description' : IDL.Text,
      'wasm_hash' : IDL.Vec(IDL.Nat8),
    }),
    'TreasurySpend' : IDL.Record({
      'subaccount' : IDL.Text,
      'recipient' : IDL.Principal,
      'amount' : IDL.Nat,
      'reason' : IDL.Text,
    }),
    'GovernanceParamUpdate' : GovernanceParams,
    'VerifierKeyUpgrade' : VerifierKeyUpgradePayload,
  });
  const RewardSourceBreakdown = IDL.Record({
    'fee_revenue_pct' : IDL.Nat32,
    'disclosure' : IDL.Text,
    'incentive_allocation_pct' : IDL.Nat32,
  });
  const StakePosition = IDL.Record({
    'voting_weight' : IDL.Nat,
    'closed' : IDL.Bool,
    'op_id' : IDL.Opt(IDL.Nat64),
    'rewards_claimed' : IDL.Nat,
    'created_at_ns' : IDL.Nat64,
    'lock_days' : IDL.Nat32,
    'lock_end_ns' : IDL.Nat64,
    'holder' : IDL.Principal,
    'last_claim_ns' : IDL.Nat64,
    'amount' : IDL.Nat,
    'position_id' : IDL.Nat64,
  });
  const LockOpType = IDL.Variant({ 'Lock' : IDL.Null, 'Unlock' : IDL.Null });
  const PendingLockOp = IDL.Record({
    'snapshot' : StakePosition,
    'op_id' : IDL.Nat64,
    'initiated_at_ns' : IDL.Nat64,
    'holder' : IDL.Principal,
    'op_type' : LockOpType,
    'amount' : IDL.Nat,
    'position_id' : IDL.Nat64,
  });
  const ProposalStatus = IDL.Variant({
    'Passed' : IDL.Null,
    'VotingClosed' : IDL.Null,
    'Executing' : IDL.Null,
    'Rejected' : IDL.Null,
    'VotingOpen' : IDL.Null,
    'Executed' : IDL.Null,
    'Cancelled' : IDL.Null,
    'VotingPending' : IDL.Null,
    'Expired' : IDL.Null,
  });
  const Proposal = IDL.Record({
    'id' : IDL.Nat64,
    'execution_result' : IDL.Opt(IDL.Text),
    'status' : ProposalStatus,
    'description' : IDL.Text,
    'created_at_ns' : IDL.Nat64,
    'voting_opens_ns' : IDL.Nat64,
    'executed_at_ns' : IDL.Opt(IDL.Nat64),
    'proposer' : IDL.Principal,
    'votes_for' : IDL.Nat,
    'execute_after_ns' : IDL.Nat64,
    'voting_closes_ns' : IDL.Nat64,
    'proposal_type' : ProposalType,
    'votes_against' : IDL.Nat,
  });
  const LockDecision = IDL.Variant({
    'Executed' : IDL.Null,
    'NotExecuted' : IDL.Null,
  });
  return IDL.Service({
    'claim_rewards' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : IDL.Text })],
        [],
      ),
    'create_proposal' : IDL.Func(
        [ProposalType, IDL.Text],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : IDL.Text })],
        [],
      ),
    'execute_proposal' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'get_build_info' : IDL.Func([], [IDL.Text], ['query']),
    'get_governance_params' : IDL.Func([], [GovernanceParams], ['query']),
    'get_pending_rewards' : IDL.Func([IDL.Principal], [IDL.Nat], ['query']),
    'get_reward_source_breakdown' : IDL.Func(
        [],
        [RewardSourceBreakdown],
        ['query'],
      ),
    'get_rewards_pool_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'get_stake_positions' : IDL.Func(
        [IDL.Principal],
        [IDL.Vec(StakePosition)],
        ['query'],
      ),
    'get_total_voting_weight' : IDL.Func([], [IDL.Nat], ['query']),
    'list_pending_lock_ops' : IDL.Func([], [IDL.Vec(PendingLockOp)], ['query']),
    'list_proposals_by_status' : IDL.Func(
        [IDL.Opt(ProposalStatus)],
        [IDL.Vec(Proposal)],
        ['query'],
      ),
    'receive_fee_revenue' : IDL.Func([IDL.Nat], [], []),
    'reconcile_lock' : IDL.Func(
        [IDL.Nat64, LockDecision],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'reconcile_unlock' : IDL.Func(
        [IDL.Nat64, LockDecision],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'stake' : IDL.Func(
        [IDL.Nat, IDL.Nat32],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : IDL.Text })],
        [],
      ),
    'unstake' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'vote' : IDL.Func(
        [IDL.Nat64, IDL.Bool],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  const GovernanceParams = IDL.Record({
    'approval_threshold_bps' : IDL.Nat32,
    'voting_period_ns' : IDL.Nat64,
    'vk_upgrade_timelock_ns' : IDL.Nat64,
    'quorum_bps' : IDL.Nat32,
    'min_proposal_deposit' : IDL.Nat,
    'execution_timelock_ns' : IDL.Nat64,
    'voting_delay_ns' : IDL.Nat64,
    'vk_quorum_bps' : IDL.Nat32,
    'treasury_quorum_bps' : IDL.Nat32,
  });
  const InitArgs = IDL.Record({
    'treasury_canister' : IDL.Principal,
    'token_canister' : IDL.Principal,
    'initial_rewards_pool' : IDL.Nat,
    'initial_emission_rate_per_day' : IDL.Nat,
    'governance_params' : IDL.Opt(GovernanceParams),
    'pool_canister' : IDL.Principal,
  });
  return [InitArgs];
};
