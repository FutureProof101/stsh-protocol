export const idlFactory = ({ IDL }) => {
  const ManifestDisposition = IDL.Variant({
    'OutOfScope' : IDL.Null,
    'SetControllerAtCutover' : IDL.Null,
    'BornUnderVault' : IDL.Null,
  });
  const GovernedTarget = IDL.Record({
    'principal' : IDL.Principal,
    'disposition' : ManifestDisposition,
    'purpose' : IDL.Text,
  });
  const VaultInitArgs = IDL.Record({
    'threshold' : IDL.Nat32,
    'signers' : IDL.Vec(IDL.Principal),
    'upgrader' : IDL.Principal,
  });
  const VaultInit = IDL.Record({
    'cutover_targets' : IDL.Vec(GovernedTarget),
    'quorum' : VaultInitArgs,
  });
  const ActionOutcome = IDL.Variant({
    'OutcomeUnknown' : IDL.Null,
    'Failed' : IDL.Null,
    'Executing' : IDL.Null,
    'Executed' : IDL.Null,
    'Cancelled' : IDL.Null,
    'Expired' : IDL.Null,
    'Pending' : IDL.Null,
  });
  const ApprovalOutcome = IDL.Variant({
    'Executing' : IDL.Null,
    'Approved' : IDL.Record({
      'threshold' : IDL.Nat32,
      'approvals' : IDL.Nat32,
    }),
    'PriorResult' : IDL.Record({
      'result' : IDL.Opt(IDL.Text),
      'outcome' : ActionOutcome,
    }),
  });
  const ReconcileTerminalOutcome = IDL.Variant({
    'Failed' : IDL.Null,
    'Executed' : IDL.Null,
  });
  const CommitmentMismatch = IDL.Variant({
    'StoredVsRecomputed' : IDL.Null,
    'CallerMismatch' : IDL.Null,
  });
  const GuardTarget = IDL.Variant({
    'Upgrader' : IDL.Null,
    'Vault' : IDL.Null,
  });
  const GuardViolation = IDL.Variant({
    'StopForbidden' : IDL.Record({ 'target' : GuardTarget }),
    'ControllerInvariantBroken' : IDL.Record({ 'target' : GuardTarget }),
  });
  const LifetimeViolation = IDL.Variant({
    'BoundsNotRuled' : IDL.Record({ 'requested_ns' : IDL.Nat64 }),
    'TooLong' : IDL.Record({
      'requested_ns' : IDL.Nat64,
      'max_ns' : IDL.Nat64,
    }),
    'TooShort' : IDL.Record({
      'min_ns' : IDL.Nat64,
      'requested_ns' : IDL.Nat64,
    }),
  });
  const VaultError = IDL.Variant({
    'AlreadyApproved' : IDL.Null,
    'ThresholdViolation' : IDL.Null,
    'AlreadySettled' : IDL.Record({ 'outcome' : ReconcileTerminalOutcome }),
    'ReadBoundExceeded' : IDL.Record({
      'max' : IDL.Nat64,
      'what' : IDL.Text,
      'bytes' : IDL.Nat64,
    }),
    'IllegalSourceState' : IDL.Null,
    'AlreadyTerminal' : IDL.Null,
    'NotAuthorized' : IDL.Null,
    'ProposalExpired' : IDL.Record({
      'now_ns' : IDL.Nat64,
      'expires_at_ns' : IDL.Nat64,
    }),
    'StaleEpoch' : IDL.Record({ 'found' : IDL.Nat64, 'expected' : IDL.Nat64 }),
    'CommitmentMismatch' : CommitmentMismatch,
    'HashMismatch' : IDL.Null,
    'GuardRejected' : GuardViolation,
    'NotProposer' : IDL.Null,
    'LifetimeOutOfBounds' : LifetimeViolation,
    'SizeLimitExceeded' : IDL.Record({
      'limit_bytes' : IDL.Nat64,
      'encoded_bytes' : IDL.Nat64,
    }),
    'ReadLimitExceeded' : IDL.Record({
      'max' : IDL.Nat32,
      'limit' : IDL.Nat32,
    }),
    'UnknownProposal' : IDL.Record({ 'proposal_id' : IDL.Nat64 }),
  });
  const AuditKind = IDL.Variant({
    'OutcomeUnknown' : IDL.Null,
    'SettlementEvidenceConflict' : IDL.Null,
    'LateCallbackFenced' : IDL.Null,
    'Failed' : IDL.Null,
    'ReconcileConflict' : IDL.Null,
    'QuorumReached' : IDL.Null,
    'Reconciled' : IDL.Null,
    'CanisterCreated' : IDL.Null,
    'SnapshotStored' : IDL.Null,
    'ProposalCreated' : IDL.Null,
    'ProposalExpired' : IDL.Null,
    'Executed' : IDL.Null,
    'GovernanceTransition' : IDL.Null,
    'ProposalCancelled' : IDL.Null,
    'ApprovalAdded' : IDL.Null,
  });
  const SettlementEvidenceConflict = IDL.Record({
    'replay_semantic_key' : IDL.Vec(IDL.Nat8),
    'stored_outcome' : ReconcileTerminalOutcome,
    'replay_mapped_outcome' : ReconcileTerminalOutcome,
    'stored_semantic_key' : IDL.Vec(IDL.Nat8),
    'proposal_id' : IDL.Nat64,
    'stored_evidence_commitment' : IDL.Vec(IDL.Nat8),
    'replay_observed_at_ns' : IDL.Nat64,
    'replay_evidence_commitment' : IDL.Vec(IDL.Nat8),
  });
  const CreationReceiptStatus = IDL.Variant({
    'Bound' : IDL.Null,
    'OrphanedPurposeConflict' : IDL.Null,
  });
  const CreationReceipt = IDL.Record({
    'status' : CreationReceiptStatus,
    'principal' : IDL.Principal,
    'created_at_ns' : IDL.Nat64,
    'proposal_id' : IDL.Nat64,
    'disposition' : ManifestDisposition,
    'purpose' : IDL.Text,
  });
  const AuditEvent = IDL.Record({
    'id' : IDL.Nat64,
    'approving_signers' : IDL.Opt(IDL.Vec(IDL.Principal)),
    'actor' : IDL.Principal,
    'at_ns' : IDL.Nat64,
    'kind' : AuditKind,
    'settlement_conflict' : IDL.Opt(SettlementEvidenceConflict),
    'detail' : IDL.Text,
    'epoch' : IDL.Nat64,
    'proposal_id' : IDL.Opt(IDL.Nat64),
    'creation_receipt' : IDL.Opt(CreationReceipt),
  });
  const ReadModelAction = IDL.Variant({
    'PoolReadAccountingState' : IDL.Null,
    'TokenReadSupplyReconciliation' : IDL.Null,
    'NullifierReadSpentAt' : IDL.Null,
    'PoolReadPendingOutputPromotions' : IDL.Null,
    'PoolReadTreasuryReconciliationTombstone' : IDL.Null,
    'PoolReadPayoutMemoKeyReady' : IDL.Null,
    'PoolReadAppendLeaseOwner' : IDL.Null,
  });
  const SnapshotSource = IDL.Variant({ 'ReadModel' : ReadModelAction });
  const BoundedCursor = IDL.Vec(IDL.Nat8);
  const PageRequest = IDL.Record({
    'cursor' : IDL.Opt(BoundedCursor),
    'limit' : IDL.Nat32,
  });
  const ReadModelRequest = IDL.Variant({
    'PoolReadAccountingState' : PageRequest,
    'TokenReadSupplyReconciliation' : IDL.Record({
      'receipt_audit_id' : IDL.Nat64,
    }),
    'NullifierReadSpentAt' : IDL.Record({
      'nullifier' : IDL.Vec(IDL.Nat8),
      'page' : PageRequest,
    }),
    'PoolReadPendingOutputPromotions' : PageRequest,
    'PoolReadTreasuryReconciliationTombstone' : PageRequest,
    'PoolReadPayoutMemoKeyReady' : IDL.Null,
    'PoolReadAppendLeaseOwner' : PageRequest,
  });
  const BoundedItem = IDL.Vec(IDL.Nat8);
  const PageResponse = IDL.Record({
    'next_cursor' : IDL.Opt(BoundedCursor),
    'items' : IDL.Vec(BoundedItem),
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
  const NullifierSpentAtItem = IDL.Record({
    'nullifier' : IDL.Vec(IDL.Nat8),
    'spent_at' : IDL.Opt(IDL.Nat64),
  });
  const ReadModelResponse = IDL.Variant({
    'PoolReadAccountingState' : PageResponse,
    'TokenReadSupplyReconciliation' : SupplyReconciliation,
    'NullifierReadSpentAt' : IDL.Record({
      'next_cursor' : IDL.Opt(BoundedCursor),
      'items' : IDL.Vec(NullifierSpentAtItem),
    }),
    'PoolReadPendingOutputPromotions' : PageResponse,
    'PoolReadTreasuryReconciliationTombstone' : PageResponse,
    'PoolReadPayoutMemoKeyReady' : IDL.Opt(IDL.Bool),
    'PoolReadAppendLeaseOwner' : PageResponse,
  });
  const ControllerReadSnapshot = IDL.Record({
    'request_hash' : IDL.Vec(IDL.Nat8),
    'source_canister' : IDL.Principal,
    'governance_epoch' : IDL.Nat64,
    'source' : SnapshotSource,
    'completed_at_ns' : IDL.Nat64,
    'request' : ReadModelRequest,
    'originating_proposal_id' : IDL.Nat64,
    'observed_at_ns' : IDL.Nat64,
    'response' : ReadModelResponse,
    'terminal_outcome' : ReconcileTerminalOutcome,
    'snapshot_id' : IDL.Nat64,
  });
  const CreationReceiptPage = IDL.Record({
    'next_cursor' : IDL.Opt(IDL.Nat64),
    'items' : IDL.Vec(CreationReceipt),
  });
  const GovernanceSummary = IDL.Record({
    'governance_epoch' : IDL.Nat64,
    'threshold' : IDL.Nat32,
    'signer_count' : IDL.Nat32,
  });
  const VaultTargets = IDL.Record({
    'vesting' : IDL.Opt(IDL.Principal),
    'shielded_pool' : IDL.Opt(IDL.Principal),
    'nullifier_registry' : IDL.Opt(IDL.Principal),
    'treasury' : IDL.Opt(IDL.Principal),
  });
  const ObservedCanisterStatus = IDL.Variant({
    'Stopped' : IDL.Null,
    'Stopping' : IDL.Null,
    'Running' : IDL.Null,
  });
  const UpgradeObjectiveEvidence = IDL.Record({
    'observed_controllers' : IDL.Vec(IDL.Principal),
    'observed_at_ns' : IDL.Nat64,
    'observed_upgrader_principal' : IDL.Principal,
    'observed_module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'observed_canister_status' : ObservedCanisterStatus,
  });
  const ManagementActionView = IDL.Variant({
    'DepositCycles' : IDL.Record({
      'cycles' : IDL.Nat,
      'target' : IDL.Principal,
    }),
    'Start' : IDL.Record({ 'target' : IDL.Principal }),
    'Upgrade' : IDL.Record({
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'wasm_bytes_len' : IDL.Nat64,
      'bytes_retained' : IDL.Bool,
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
      'arg_bytes_len' : IDL.Nat64,
      'target' : IDL.Principal,
    }),
    'Stop' : IDL.Record({ 'target' : IDL.Principal }),
    'InstallCode' : IDL.Record({
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'wasm_bytes_len' : IDL.Nat64,
      'bytes_retained' : IDL.Bool,
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
      'arg_bytes_len' : IDL.Nat64,
      'target' : IDL.Principal,
    }),
    'UpdateSettings' : IDL.Record({
      'controllers' : IDL.Vec(IDL.Principal),
      'target' : IDL.Principal,
    }),
    'CreateCanister' : IDL.Record({
      'manifest_purpose' : IDL.Text,
      'disposition' : ManifestDisposition,
    }),
  });
  const StartObjectiveEvidence = IDL.Record({
    'observed_controllers' : IDL.Vec(IDL.Principal),
    'observed_at_ns' : IDL.Nat64,
    'observed_target_principal' : IDL.Principal,
    'observed_canister_status' : ObservedCanisterStatus,
  });
  const ActionView = IDL.Variant({
    'Application' : IDL.Text,
    'UpdateSignerSet' : IDL.Record({
      'threshold' : IDL.Nat32,
      'signers' : IDL.Vec(IDL.Principal),
    }),
    'ReconcileVaultUpgradeViaUpgrader' : IDL.Record({
      'target_proposal_id' : IDL.Nat64,
      'objective_evidence' : UpgradeObjectiveEvidence,
    }),
    'VaultUpgradeViaUpgrader' : IDL.Record({
      'request_id' : IDL.Nat64,
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'bytes_retained' : IDL.Bool,
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
    }),
    'ReadModel' : IDL.Text,
    'Management' : ManagementActionView,
    'UpgraderUpgrade' : IDL.Record({
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'bytes_retained' : IDL.Bool,
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
    }),
    'ReconcileUpgraderUpgrade' : IDL.Record({
      'target_proposal_id' : IDL.Nat64,
      'objective_evidence' : UpgradeObjectiveEvidence,
    }),
    'ReconcileUpgraderStart' : IDL.Record({
      'target_proposal_id' : IDL.Nat64,
      'objective_evidence' : StartObjectiveEvidence,
    }),
  });
  const ProposalView = IDL.Record({
    'result' : IDL.Opt(IDL.Text),
    'action' : ActionView,
    'commitment_hash' : IDL.Vec(IDL.Nat8),
    'epoch' : IDL.Nat64,
    'created_at_ns' : IDL.Nat64,
    'proposal_id' : IDL.Nat64,
    'proposer' : IDL.Principal,
    'outcome' : ActionOutcome,
    'snapshot_id' : IDL.Opt(IDL.Nat64),
    'approvals' : IDL.Vec(IDL.Principal),
  });
  const PayoutOutcome = IDL.Variant({
    'Executed' : IDL.Record({ 'block_index' : IDL.Nat64 }),
    'NotExecuted' : IDL.Null,
  });
  const SpendFeeModeMirror = IDL.Variant({
    'XdrPegged' : IDL.Null,
    'FixedStsh' : IDL.Null,
  });
  const GovernanceFeeParamsMirror = IDL.Record({
    'minimum_withdrawal_gross' : IDL.Nat,
    'shield_flat_minimum_fee_e8s' : IDL.Opt(IDL.Nat),
    'operations_split_bps' : IDL.Nat32,
    'staking_rewards_enabled' : IDL.Bool,
    'spend_fee_mode' : IDL.Opt(SpendFeeModeMirror),
    'max_fee_change_bps_per_update' : IDL.Nat32,
    'fee_reference_price_stsh_per_icp_e8s' : IDL.Nat,
    'fee_update_cooldown_ns' : IDL.Nat64,
    'protocol_shielding_fee_stsh' : IDL.Nat,
    'unshield_flat_minimum_fee_e8s' : IDL.Opt(IDL.Nat),
    'fee_safety_margin_bps' : IDL.Nat32,
    'target_treasury_runway_months' : IDL.Nat32,
    'params_epoch' : IDL.Opt(IDL.Nat64),
    'minimum_recipient_amount' : IDL.Nat,
    'protocol_private_spend_fee_stsh' : IDL.Nat,
    'shield_fee_bps' : IDL.Opt(IDL.Nat16),
    'staking_rewards_split_bps' : IDL.Nat32,
    'unshield_fee_bps' : IDL.Opt(IDL.Nat16),
    'protocol_unshielding_fee_stsh' : IDL.Nat,
    'minimum_private_credit' : IDL.Nat,
    'minimum_treasury_runway_months' : IDL.Nat32,
    'insurance_split_bps' : IDL.Nat32,
    'fee_model_version' : IDL.Opt(IDL.Nat32),
  });
  const ClaimDecision = IDL.Variant({
    'Executed' : IDL.Null,
    'NotExecuted' : IDL.Null,
  });
  const DisburseOutcome = IDL.Variant({
    'Executed' : IDL.Record({ 'block_index' : IDL.Nat64 }),
    'NotExecuted' : IDL.Null,
  });
  const PruneRequest = IDL.Record({
    'max_records' : IDL.Nat64,
    'legacy_deposit_cursor' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'prune_spends' : IDL.Bool,
    'scan_legacy_deposits' : IDL.Bool,
    'scan_legacy_spends' : IDL.Bool,
    'legacy_spend_cursor' : IDL.Opt(IDL.Nat64),
    'prune_deposits' : IDL.Bool,
    'max_scan_records' : IDL.Nat64,
    'older_than_ns' : IDL.Nat64,
  });
  const ActionRequest = IDL.Variant({
    'PoolUnpauseDeposits' : IDL.Null,
    'PoolReconcilePrivateSpendPayout' : IDL.Tuple(IDL.Nat64, PayoutOutcome),
    'PoolUnpauseSpends' : IDL.Null,
    'PoolEmergencyPauseDeposits' : IDL.Null,
    'PoolReconcilePendingSpend' : IDL.Nat64,
    'PoolReconcileDepositAppendUnknown' : IDL.Vec(IDL.Nat8),
    'PoolSetGovernanceFeeParams' : GovernanceFeeParamsMirror,
    'PoolScheduleVkActivation' : IDL.Tuple(
      IDL.Nat32,
      IDL.Vec(IDL.Nat8),
      IDL.Nat64,
      IDL.Nat64,
    ),
    'PoolEmergencyPauseSpends' : IDL.Null,
    'TreasuryRejectProposal' : IDL.Nat64,
    'VestingReconcileClaim' : IDL.Tuple(IDL.Principal, ClaimDecision),
    'PoolReconcileTreasuryDisburse' : IDL.Tuple(IDL.Nat64, DisburseOutcome),
    'PoolReconcileDepositTransferNotExecuted' : IDL.Vec(IDL.Nat8),
    'PoolReconcileNullifierInsert' : IDL.Nat64,
    'PoolClearVerifierConfigGuard' : IDL.Null,
    'PoolEmergencyDisableCircuitVersion' : IDL.Nat32,
    'TreasuryProposeWithdrawal' : IDL.Tuple(
      IDL.Text,
      IDL.Principal,
      IDL.Nat,
      IDL.Text,
    ),
    'PoolPruneTerminalRecords' : PruneRequest,
    'PoolReconcileDepositCommitment' : IDL.Vec(IDL.Nat8),
    'PoolSetVerifierCanister' : IDL.Tuple(IDL.Principal, IDL.Vec(IDL.Nat8)),
    'TreasuryExecuteWithdrawal' : IDL.Nat64,
    'PoolInitializePayoutMemoKey' : IDL.Null,
  });
  const ReconcileVaultUpgradeViaUpgrader = IDL.Record({
    'request_id' : IDL.Nat64,
    'objective_evidence' : UpgradeObjectiveEvidence,
  });
  const VaultUpgradeViaUpgrader = IDL.Record({
    'request_id' : IDL.Nat64,
    'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
    'expected_arg_hash' : IDL.Vec(IDL.Nat8),
    'wasm_bytes' : IDL.Vec(IDL.Nat8),
    'arg_bytes' : IDL.Vec(IDL.Nat8),
  });
  const ManagementAction = IDL.Variant({
    'DepositCycles' : IDL.Record({
      'cycles' : IDL.Nat,
      'target' : IDL.Principal,
    }),
    'Start' : IDL.Record({ 'target' : IDL.Principal }),
    'Upgrade' : IDL.Record({
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
      'wasm_bytes' : IDL.Vec(IDL.Nat8),
      'target' : IDL.Principal,
      'arg_bytes' : IDL.Vec(IDL.Nat8),
    }),
    'Stop' : IDL.Record({ 'target' : IDL.Principal }),
    'InstallCode' : IDL.Record({
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
      'wasm_bytes' : IDL.Vec(IDL.Nat8),
      'target' : IDL.Principal,
      'arg_bytes' : IDL.Vec(IDL.Nat8),
    }),
    'UpdateSettings' : IDL.Record({
      'controllers' : IDL.Vec(IDL.Principal),
      'target' : IDL.Principal,
    }),
    'CreateCanister' : IDL.Record({
      'manifest_purpose' : IDL.Text,
      'disposition' : ManifestDisposition,
    }),
  });
  const UpgraderUpgrade = IDL.Record({
    'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
    'expected_arg_hash' : IDL.Vec(IDL.Nat8),
    'wasm_bytes' : IDL.Vec(IDL.Nat8),
    'arg_bytes' : IDL.Vec(IDL.Nat8),
  });
  const ReconcileUpgraderUpgrade = IDL.Record({
    'objective_evidence' : UpgradeObjectiveEvidence,
    'proposal_id' : IDL.Nat64,
  });
  const ReconcileUpgraderStart = IDL.Record({
    'objective_evidence' : StartObjectiveEvidence,
    'proposal_id' : IDL.Nat64,
  });
  const VaultActionKind = IDL.Variant({
    'Application' : ActionRequest,
    'UpdateSignerSet' : IDL.Record({
      'threshold' : IDL.Nat32,
      'signers' : IDL.Vec(IDL.Principal),
    }),
    'ReconcileVaultUpgradeViaUpgrader' : ReconcileVaultUpgradeViaUpgrader,
    'VaultUpgradeViaUpgrader' : VaultUpgradeViaUpgrader,
    'ReadModel' : ReadModelRequest,
    'Management' : ManagementAction,
    'UpgraderUpgrade' : UpgraderUpgrade,
    'ReconcileUpgraderUpgrade' : ReconcileUpgraderUpgrade,
    'ReconcileUpgraderStart' : ReconcileUpgraderStart,
  });
  return IDL.Service({
    'approve' : IDL.Func(
        [IDL.Nat64, IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : ApprovalOutcome, 'Err' : VaultError })],
        [],
      ),
    'cancel_proposal' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : VaultError })],
        [],
      ),
    'get_action_catalogue' : IDL.Func([], [IDL.Vec(IDL.Text)], ['query']),
    'get_audit_events' : IDL.Func(
        [IDL.Opt(IDL.Nat64), IDL.Nat32],
        [IDL.Opt(IDL.Vec(AuditEvent))],
        ['query'],
      ),
    'get_build_info' : IDL.Func([], [IDL.Text], ['query']),
    'get_controller_read_snapshot' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(ControllerReadSnapshot)],
        ['query'],
      ),
    'get_creation_receipts' : IDL.Func(
        [IDL.Opt(IDL.Nat64), IDL.Nat32],
        [IDL.Opt(CreationReceiptPage)],
        ['query'],
      ),
    'get_governance_summary' : IDL.Func([], [GovernanceSummary], ['query']),
    'get_governed_targets' : IDL.Func(
        [],
        [IDL.Opt(IDL.Tuple(VaultTargets, IDL.Vec(GovernedTarget)))],
        ['query'],
      ),
    'get_proposal' : IDL.Func([IDL.Nat64], [IDL.Opt(ProposalView)], ['query']),
    'get_signers' : IDL.Func([], [IDL.Opt(IDL.Vec(IDL.Principal))], ['query']),
    'list_proposals' : IDL.Func(
        [IDL.Opt(IDL.Nat64), IDL.Nat32],
        [IDL.Opt(IDL.Vec(ProposalView))],
        ['query'],
      ),
    'propose' : IDL.Func(
        [VaultActionKind, IDL.Opt(IDL.Nat64)],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : VaultError })],
        [],
      ),
    'sweep_expired_proposals' : IDL.Func(
        [IDL.Nat32],
        [IDL.Variant({ 'Ok' : IDL.Vec(IDL.Nat64), 'Err' : VaultError })],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  const ManifestDisposition = IDL.Variant({
    'OutOfScope' : IDL.Null,
    'SetControllerAtCutover' : IDL.Null,
    'BornUnderVault' : IDL.Null,
  });
  const GovernedTarget = IDL.Record({
    'principal' : IDL.Principal,
    'disposition' : ManifestDisposition,
    'purpose' : IDL.Text,
  });
  const VaultInitArgs = IDL.Record({
    'threshold' : IDL.Nat32,
    'signers' : IDL.Vec(IDL.Principal),
    'upgrader' : IDL.Principal,
  });
  const VaultInit = IDL.Record({
    'cutover_targets' : IDL.Vec(GovernedTarget),
    'quorum' : VaultInitArgs,
  });
  return [VaultInit];
};
