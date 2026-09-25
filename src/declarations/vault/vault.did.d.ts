import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type ActionOutcome = { 'OutcomeUnknown' : null } |
  { 'Failed' : null } |
  { 'Executing' : null } |
  { 'Executed' : null } |
  { 'Cancelled' : null } |
  { 'Expired' : null } |
  { 'Pending' : null };
export type ActionRequest = { 'PoolUnpauseDeposits' : null } |
  { 'PoolReconcilePrivateSpendPayout' : [bigint, PayoutOutcome] } |
  { 'PoolUnpauseSpends' : null } |
  { 'PoolEmergencyPauseDeposits' : null } |
  { 'PoolReconcilePendingSpend' : bigint } |
  { 'PoolReconcileDepositAppendUnknown' : Uint8Array | number[] } |
  { 'PoolSetGovernanceFeeParams' : GovernanceFeeParamsMirror } |
  {
    'PoolScheduleVkActivation' : [number, Uint8Array | number[], bigint, bigint]
  } |
  { 'PoolEmergencyPauseSpends' : null } |
  { 'TreasuryRejectProposal' : bigint } |
  { 'VestingReconcileClaim' : [Principal, ClaimDecision] } |
  { 'PoolReconcileTreasuryDisburse' : [bigint, DisburseOutcome] } |
  { 'PoolReconcileDepositTransferNotExecuted' : Uint8Array | number[] } |
  { 'PoolReconcileNullifierInsert' : bigint } |
  { 'PoolClearVerifierConfigGuard' : null } |
  { 'PoolEmergencyDisableCircuitVersion' : number } |
  { 'TreasuryProposeWithdrawal' : [string, Principal, bigint, string] } |
  { 'PoolPruneTerminalRecords' : PruneRequest } |
  { 'PoolReconcileDepositCommitment' : Uint8Array | number[] } |
  { 'PoolSetVerifierCanister' : [Principal, Uint8Array | number[]] } |
  { 'TreasuryExecuteWithdrawal' : bigint } |
  { 'PoolInitializePayoutMemoKey' : null };
export type ActionView = { 'Application' : string } |
  {
    'UpdateSignerSet' : { 'threshold' : number, 'signers' : Array<Principal> }
  } |
  {
    'ReconcileVaultUpgradeViaUpgrader' : {
      'target_proposal_id' : bigint,
      'objective_evidence' : UpgradeObjectiveEvidence,
    }
  } |
  {
    'VaultUpgradeViaUpgrader' : {
      'request_id' : bigint,
      'expected_wasm_hash' : Uint8Array | number[],
      'bytes_retained' : boolean,
      'expected_arg_hash' : Uint8Array | number[],
    }
  } |
  { 'ReadModel' : string } |
  { 'Management' : ManagementActionView } |
  {
    'UpgraderUpgrade' : {
      'expected_wasm_hash' : Uint8Array | number[],
      'bytes_retained' : boolean,
      'expected_arg_hash' : Uint8Array | number[],
    }
  } |
  {
    'ReconcileUpgraderUpgrade' : {
      'target_proposal_id' : bigint,
      'objective_evidence' : UpgradeObjectiveEvidence,
    }
  } |
  {
    'ReconcileUpgraderStart' : {
      'target_proposal_id' : bigint,
      'objective_evidence' : StartObjectiveEvidence,
    }
  };
export type ApprovalOutcome = { 'Executing' : null } |
  { 'Approved' : { 'threshold' : number, 'approvals' : number } } |
  { 'PriorResult' : { 'result' : [] | [string], 'outcome' : ActionOutcome } };
export interface AuditEvent {
  'id' : bigint,
  'approving_signers' : [] | [Array<Principal>],
  'actor' : Principal,
  'at_ns' : bigint,
  'kind' : AuditKind,
  'settlement_conflict' : [] | [SettlementEvidenceConflict],
  'detail' : string,
  'epoch' : bigint,
  'proposal_id' : [] | [bigint],
  'creation_receipt' : [] | [CreationReceipt],
}
export type AuditKind = { 'OutcomeUnknown' : null } |
  { 'SettlementEvidenceConflict' : null } |
  { 'LateCallbackFenced' : null } |
  { 'Failed' : null } |
  { 'ReconcileConflict' : null } |
  { 'QuorumReached' : null } |
  { 'Reconciled' : null } |
  { 'CanisterCreated' : null } |
  { 'SnapshotStored' : null } |
  { 'ProposalCreated' : null } |
  { 'ProposalExpired' : null } |
  { 'Executed' : null } |
  { 'GovernanceTransition' : null } |
  { 'ProposalCancelled' : null } |
  { 'ApprovalAdded' : null };
export type BoundedCursor = Uint8Array | number[];
export type BoundedItem = Uint8Array | number[];
export type ClaimDecision = { 'Executed' : null } |
  { 'NotExecuted' : null };
export type CommitmentMismatch = { 'StoredVsRecomputed' : null } |
  { 'CallerMismatch' : null };
export interface ControllerReadSnapshot {
  'request_hash' : Uint8Array | number[],
  'source_canister' : Principal,
  'governance_epoch' : bigint,
  'source' : SnapshotSource,
  'completed_at_ns' : bigint,
  'request' : ReadModelRequest,
  'originating_proposal_id' : bigint,
  'observed_at_ns' : bigint,
  'response' : ReadModelResponse,
  'terminal_outcome' : ReconcileTerminalOutcome,
  'snapshot_id' : bigint,
}
export interface CreationReceipt {
  'status' : CreationReceiptStatus,
  'principal' : Principal,
  'created_at_ns' : bigint,
  'proposal_id' : bigint,
  'disposition' : ManifestDisposition,
  'purpose' : string,
}
export interface CreationReceiptPage {
  'next_cursor' : [] | [bigint],
  'items' : Array<CreationReceipt>,
}
export type CreationReceiptStatus = { 'Bound' : null } |
  { 'OrphanedPurposeConflict' : null };
export type DisburseOutcome = { 'Executed' : { 'block_index' : bigint } } |
  { 'NotExecuted' : null };
export interface GovernanceFeeParamsMirror {
  'minimum_withdrawal_gross' : bigint,
  'shield_flat_minimum_fee_e8s' : [] | [bigint],
  'operations_split_bps' : number,
  'staking_rewards_enabled' : boolean,
  'spend_fee_mode' : [] | [SpendFeeModeMirror],
  'max_fee_change_bps_per_update' : number,
  'fee_reference_price_stsh_per_icp_e8s' : bigint,
  'fee_update_cooldown_ns' : bigint,
  'protocol_shielding_fee_stsh' : bigint,
  'unshield_flat_minimum_fee_e8s' : [] | [bigint],
  'fee_safety_margin_bps' : number,
  'target_treasury_runway_months' : number,
  'params_epoch' : [] | [bigint],
  'minimum_recipient_amount' : bigint,
  'protocol_private_spend_fee_stsh' : bigint,
  'shield_fee_bps' : [] | [number],
  'staking_rewards_split_bps' : number,
  'unshield_fee_bps' : [] | [number],
  'protocol_unshielding_fee_stsh' : bigint,
  'minimum_private_credit' : bigint,
  'minimum_treasury_runway_months' : number,
  'insurance_split_bps' : number,
  'fee_model_version' : [] | [number],
}
export interface GovernanceSummary {
  'governance_epoch' : bigint,
  'threshold' : number,
  'signer_count' : number,
}
export interface GovernedTarget {
  'principal' : Principal,
  'disposition' : ManifestDisposition,
  'purpose' : string,
}
export type GuardTarget = { 'Upgrader' : null } |
  { 'Vault' : null };
export type GuardViolation = { 'StopForbidden' : { 'target' : GuardTarget } } |
  { 'ControllerInvariantBroken' : { 'target' : GuardTarget } };
export type LifetimeViolation = {
    'BoundsNotRuled' : { 'requested_ns' : bigint }
  } |
  { 'TooLong' : { 'requested_ns' : bigint, 'max_ns' : bigint } } |
  { 'TooShort' : { 'min_ns' : bigint, 'requested_ns' : bigint } };
export type ManagementAction = {
    'DepositCycles' : { 'cycles' : bigint, 'target' : Principal }
  } |
  { 'Start' : { 'target' : Principal } } |
  {
    'Upgrade' : {
      'expected_wasm_hash' : Uint8Array | number[],
      'expected_arg_hash' : Uint8Array | number[],
      'wasm_bytes' : Uint8Array | number[],
      'target' : Principal,
      'arg_bytes' : Uint8Array | number[],
    }
  } |
  { 'Stop' : { 'target' : Principal } } |
  {
    'InstallCode' : {
      'expected_wasm_hash' : Uint8Array | number[],
      'expected_arg_hash' : Uint8Array | number[],
      'wasm_bytes' : Uint8Array | number[],
      'target' : Principal,
      'arg_bytes' : Uint8Array | number[],
    }
  } |
  {
    'UpdateSettings' : {
      'controllers' : Array<Principal>,
      'target' : Principal,
    }
  } |
  {
    'CreateCanister' : {
      'manifest_purpose' : string,
      'disposition' : ManifestDisposition,
    }
  };
export type ManagementActionView = {
    'DepositCycles' : { 'cycles' : bigint, 'target' : Principal }
  } |
  { 'Start' : { 'target' : Principal } } |
  {
    'Upgrade' : {
      'expected_wasm_hash' : Uint8Array | number[],
      'wasm_bytes_len' : bigint,
      'bytes_retained' : boolean,
      'expected_arg_hash' : Uint8Array | number[],
      'arg_bytes_len' : bigint,
      'target' : Principal,
    }
  } |
  { 'Stop' : { 'target' : Principal } } |
  {
    'InstallCode' : {
      'expected_wasm_hash' : Uint8Array | number[],
      'wasm_bytes_len' : bigint,
      'bytes_retained' : boolean,
      'expected_arg_hash' : Uint8Array | number[],
      'arg_bytes_len' : bigint,
      'target' : Principal,
    }
  } |
  {
    'UpdateSettings' : {
      'controllers' : Array<Principal>,
      'target' : Principal,
    }
  } |
  {
    'CreateCanister' : {
      'manifest_purpose' : string,
      'disposition' : ManifestDisposition,
    }
  };
export type ManifestDisposition = { 'OutOfScope' : null } |
  { 'SetControllerAtCutover' : null } |
  { 'BornUnderVault' : null };
export interface NullifierSpentAtItem {
  'nullifier' : Uint8Array | number[],
  'spent_at' : [] | [bigint],
}
export type ObservedCanisterStatus = { 'Stopped' : null } |
  { 'Stopping' : null } |
  { 'Running' : null };
export interface PageRequest {
  'cursor' : [] | [BoundedCursor],
  'limit' : number,
}
export interface PageResponse {
  'next_cursor' : [] | [BoundedCursor],
  'items' : Array<BoundedItem>,
}
export type PayoutOutcome = { 'Executed' : { 'block_index' : bigint } } |
  { 'NotExecuted' : null };
export interface ProposalView {
  'result' : [] | [string],
  'action' : ActionView,
  'commitment_hash' : Uint8Array | number[],
  'epoch' : bigint,
  'created_at_ns' : bigint,
  'proposal_id' : bigint,
  'proposer' : Principal,
  'outcome' : ActionOutcome,
  'snapshot_id' : [] | [bigint],
  'approvals' : Array<Principal>,
}
export interface PruneRequest {
  'max_records' : bigint,
  'legacy_deposit_cursor' : [] | [Uint8Array | number[]],
  'prune_spends' : boolean,
  'scan_legacy_deposits' : boolean,
  'scan_legacy_spends' : boolean,
  'legacy_spend_cursor' : [] | [bigint],
  'prune_deposits' : boolean,
  'max_scan_records' : bigint,
  'older_than_ns' : bigint,
}
export type ReadModelAction = { 'PoolReadAccountingState' : null } |
  { 'TokenReadSupplyReconciliation' : null } |
  { 'NullifierReadSpentAt' : null } |
  { 'PoolReadPendingOutputPromotions' : null } |
  { 'PoolReadTreasuryReconciliationTombstone' : null } |
  { 'PoolReadPayoutMemoKeyReady' : null } |
  { 'PoolReadAppendLeaseOwner' : null };
export type ReadModelRequest = { 'PoolReadAccountingState' : PageRequest } |
  { 'TokenReadSupplyReconciliation' : { 'receipt_audit_id' : bigint } } |
  {
    'NullifierReadSpentAt' : {
      'nullifier' : Uint8Array | number[],
      'page' : PageRequest,
    }
  } |
  { 'PoolReadPendingOutputPromotions' : PageRequest } |
  { 'PoolReadTreasuryReconciliationTombstone' : PageRequest } |
  { 'PoolReadPayoutMemoKeyReady' : null } |
  { 'PoolReadAppendLeaseOwner' : PageRequest };
export type ReadModelResponse = { 'PoolReadAccountingState' : PageResponse } |
  { 'TokenReadSupplyReconciliation' : SupplyReconciliation } |
  {
    'NullifierReadSpentAt' : {
      'next_cursor' : [] | [BoundedCursor],
      'items' : Array<NullifierSpentAtItem>,
    }
  } |
  { 'PoolReadPendingOutputPromotions' : PageResponse } |
  { 'PoolReadTreasuryReconciliationTombstone' : PageResponse } |
  { 'PoolReadPayoutMemoKeyReady' : [] | [boolean] } |
  { 'PoolReadAppendLeaseOwner' : PageResponse };
export type ReconcileTerminalOutcome = { 'Failed' : null } |
  { 'Executed' : null };
export interface ReconcileUpgraderStart {
  'objective_evidence' : StartObjectiveEvidence,
  'proposal_id' : bigint,
}
export interface ReconcileUpgraderUpgrade {
  'objective_evidence' : UpgradeObjectiveEvidence,
  'proposal_id' : bigint,
}
export interface ReconcileVaultUpgradeViaUpgrader {
  'request_id' : bigint,
  'objective_evidence' : UpgradeObjectiveEvidence,
}
export interface SettlementEvidenceConflict {
  'replay_semantic_key' : Uint8Array | number[],
  'stored_outcome' : ReconcileTerminalOutcome,
  'replay_mapped_outcome' : ReconcileTerminalOutcome,
  'stored_semantic_key' : Uint8Array | number[],
  'proposal_id' : bigint,
  'stored_evidence_commitment' : Uint8Array | number[],
  'replay_observed_at_ns' : bigint,
  'replay_evidence_commitment' : Uint8Array | number[],
}
export type SnapshotSource = { 'ReadModel' : ReadModelAction };
export type SpendFeeModeMirror = { 'XdrPegged' : null } |
  { 'FixedStsh' : null };
export interface StartObjectiveEvidence {
  'observed_controllers' : Array<Principal>,
  'observed_at_ns' : bigint,
  'observed_target_principal' : Principal,
  'observed_canister_status' : ObservedCanisterStatus,
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
export interface UpgradeObjectiveEvidence {
  'observed_controllers' : Array<Principal>,
  'observed_at_ns' : bigint,
  'observed_upgrader_principal' : Principal,
  'observed_module_hash' : [] | [Uint8Array | number[]],
  'observed_canister_status' : ObservedCanisterStatus,
}
export interface UpgraderUpgrade {
  'expected_wasm_hash' : Uint8Array | number[],
  'expected_arg_hash' : Uint8Array | number[],
  'wasm_bytes' : Uint8Array | number[],
  'arg_bytes' : Uint8Array | number[],
}
export type VaultActionKind = { 'Application' : ActionRequest } |
  {
    'UpdateSignerSet' : { 'threshold' : number, 'signers' : Array<Principal> }
  } |
  { 'ReconcileVaultUpgradeViaUpgrader' : ReconcileVaultUpgradeViaUpgrader } |
  { 'VaultUpgradeViaUpgrader' : VaultUpgradeViaUpgrader } |
  { 'ReadModel' : ReadModelRequest } |
  { 'Management' : ManagementAction } |
  { 'UpgraderUpgrade' : UpgraderUpgrade } |
  { 'ReconcileUpgraderUpgrade' : ReconcileUpgraderUpgrade } |
  { 'ReconcileUpgraderStart' : ReconcileUpgraderStart };
export type VaultError = { 'AlreadyApproved' : null } |
  { 'ThresholdViolation' : null } |
  { 'AlreadySettled' : { 'outcome' : ReconcileTerminalOutcome } } |
  {
    'ReadBoundExceeded' : { 'max' : bigint, 'what' : string, 'bytes' : bigint }
  } |
  { 'IllegalSourceState' : null } |
  { 'AlreadyTerminal' : null } |
  { 'NotAuthorized' : null } |
  { 'ProposalExpired' : { 'now_ns' : bigint, 'expires_at_ns' : bigint } } |
  { 'StaleEpoch' : { 'found' : bigint, 'expected' : bigint } } |
  { 'CommitmentMismatch' : CommitmentMismatch } |
  { 'HashMismatch' : null } |
  { 'GuardRejected' : GuardViolation } |
  { 'NotProposer' : null } |
  { 'LifetimeOutOfBounds' : LifetimeViolation } |
  {
    'SizeLimitExceeded' : { 'limit_bytes' : bigint, 'encoded_bytes' : bigint }
  } |
  { 'ReadLimitExceeded' : { 'max' : number, 'limit' : number } } |
  { 'UnknownProposal' : { 'proposal_id' : bigint } };
export interface VaultInit {
  'cutover_targets' : Array<GovernedTarget>,
  'quorum' : VaultInitArgs,
}
export interface VaultInitArgs {
  'threshold' : number,
  'signers' : Array<Principal>,
  'upgrader' : Principal,
}
export interface VaultTargets {
  'vesting' : [] | [Principal],
  'shielded_pool' : [] | [Principal],
  'nullifier_registry' : [] | [Principal],
  'treasury' : [] | [Principal],
}
export interface VaultUpgradeViaUpgrader {
  'request_id' : bigint,
  'expected_wasm_hash' : Uint8Array | number[],
  'expected_arg_hash' : Uint8Array | number[],
  'wasm_bytes' : Uint8Array | number[],
  'arg_bytes' : Uint8Array | number[],
}
export interface _SERVICE {
  'approve' : ActorMethod<
    [bigint, Uint8Array | number[]],
    { 'Ok' : ApprovalOutcome } |
      { 'Err' : VaultError }
  >,
  'cancel_proposal' : ActorMethod<
    [bigint],
    { 'Ok' : null } |
      { 'Err' : VaultError }
  >,
  'get_action_catalogue' : ActorMethod<[], Array<string>>,
  'get_audit_events' : ActorMethod<
    [[] | [bigint], number],
    [] | [Array<AuditEvent>]
  >,
  'get_build_info' : ActorMethod<[], string>,
  'get_controller_read_snapshot' : ActorMethod<
    [bigint],
    [] | [ControllerReadSnapshot]
  >,
  'get_creation_receipts' : ActorMethod<
    [[] | [bigint], number],
    [] | [CreationReceiptPage]
  >,
  'get_governance_summary' : ActorMethod<[], GovernanceSummary>,
  'get_governed_targets' : ActorMethod<
    [],
    [] | [[VaultTargets, Array<GovernedTarget>]]
  >,
  'get_proposal' : ActorMethod<[bigint], [] | [ProposalView]>,
  'get_signers' : ActorMethod<[], [] | [Array<Principal>]>,
  'list_proposals' : ActorMethod<
    [[] | [bigint], number],
    [] | [Array<ProposalView>]
  >,
  'propose' : ActorMethod<
    [VaultActionKind, [] | [bigint]],
    { 'Ok' : bigint } |
      { 'Err' : VaultError }
  >,
  'sweep_expired_proposals' : ActorMethod<
    [number],
    { 'Ok' : BigUint64Array | bigint[] } |
      { 'Err' : VaultError }
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
