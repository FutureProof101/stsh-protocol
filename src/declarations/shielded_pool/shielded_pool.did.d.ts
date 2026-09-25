import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface AcceptedRootHead {
  'root' : Uint8Array | number[],
  'leaf_count' : bigint,
}
export interface AccountingState {
  'private_liability' : bigint,
  'pending_fee_reimbursements' : bigint,
  'operations_reserve' : bigint,
  'escrow_backing' : bigint,
  'governance_rewards_reserve' : bigint,
  'insurance_reserve' : bigint,
}
export interface ActiveDepositsPage {
  'next_cursor' : [] | [Uint8Array | number[]],
  'deposits' : Array<PendingDeposit>,
}
export interface ActiveSpendsPage {
  'next_cursor' : [] | [bigint],
  'spends' : Array<PendingSpend>,
}
export interface AdmittedOperationStats {
  'upgrade_dropped' : bigint,
  'admitted' : bigint,
}
export type AppendLeaseOwner = { 'Spend' : { 'spend_id' : bigint } } |
  { 'Deposit' : { 'commitment' : Uint8Array | number[] } };
export interface AppendLeaseOwnerView {
  'owner' : AppendLeaseOwner,
  'generation' : bigint,
  'acquired_at_ns' : bigint,
  'phase' : LeasePhase,
  'phase_started_at_ns' : bigint,
}
export interface AppendLeaseStatus {
  'held' : boolean,
  'age_bucket' : [] | [LeaseAgeBucket],
  'phase' : [] | [LeasePhase],
}
export interface CertifiedSolvencyAttestation {
  'certificate' : [] | [Uint8Array | number[]],
  'attestation' : SolvencyAttestation,
  'witness' : Uint8Array | number[],
  'canonical_bytes' : Uint8Array | number[],
}
export interface ControllerReadPage {
  'next_cursor' : [] | [Uint8Array | number[]],
  'items' : Array<Uint8Array | number[]>,
}
export interface ControllerReadPageRequest {
  'cursor' : [] | [Uint8Array | number[]],
  'limit' : number,
}
export interface DeploymentAttestation {
  'circuit_version' : number,
  'merkle' : Principal,
  'verifier' : [] | [Principal],
  'token' : Principal,
  'proof_system' : string,
  'nullifier' : Principal,
  'pool' : Principal,
  'config_version' : number,
  'pool_version' : number,
  'config_hash' : Uint8Array | number[],
  'vk_hash' : Uint8Array | number[],
}
export type DepositAppendReconcileResult = { 'Finalized' : null } |
  { 'RevertedRetryable' : null };
export type DepositSettlementOutcome = { 'CreditedFromReceipt' : bigint } |
  { 'FencedNotExecuted' : null } |
  { 'CreditedFromDuplicate' : bigint } |
  { 'CreditedFromExecution' : bigint };
export type DepositStatus = { 'CommitmentReconcileInFlight' : null } |
  { 'CommitmentAppended' : { 'leaf_index' : bigint } } |
  { 'CommitmentAppendUnknown' : null } |
  {
    'CommitmentRootAccepted' : {
      'root' : Uint8Array | number[],
      'leaf_index' : bigint,
    }
  } |
  { 'TransferPending' : null } |
  { 'CommitmentPending' : null } |
  { 'TransferConfirmedCommitmentPending' : null } |
  { 'CommitmentAppendInFlight' : null };
export type DisburseOutcome = { 'Executed' : { 'block_index' : bigint } } |
  { 'NotExecuted' : null };
export interface FeeGovernanceState {
  'last_fee_update_ns' : bigint,
  'fee_update_cooldown_ns' : bigint,
  'launch_fee_activated' : boolean,
  'params_epoch' : bigint,
}
export interface FrozenPayout {
  'fee' : [] | [bigint],
  'destination' : Principal,
  'memo' : [] | [Uint8Array | number[]],
  'from_subaccount' : [] | [Uint8Array | number[]],
  'ledger' : Principal,
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
  'destination_subaccount' : [] | [Uint8Array | number[]],
}
export interface GovernanceFeeParams {
  'minimum_withdrawal_gross' : bigint,
  'shield_flat_minimum_fee_e8s' : [] | [bigint],
  'operations_split_bps' : number,
  'staking_rewards_enabled' : boolean,
  'spend_fee_mode' : [] | [SpendFeeMode],
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
export type LeaseAgeBucket = { 'OverHour' : null } |
  { 'UnderHour' : null } |
  { 'UnderMinute' : null } |
  { 'UnderTenMinutes' : null };
export type LeasePhase = { 'AppendConfirmedRootPending' : null } |
  { 'AppendInFlight' : null } |
  { 'AppendUnknown' : null } |
  { 'ReconcileInFlight' : null } |
  { 'Snapshotting' : null };
export type PayoutOutcome = { 'Executed' : { 'block_index' : bigint } } |
  { 'NotExecuted' : null };
export type PayoutPhase = { 'PreDispatch' : null } |
  { 'MayHaveDispatched' : null };
export interface PayoutRetryState {
  'memo_sequence' : bigint,
  'boot' : bigint,
  'generation' : bigint,
  'dispatched' : boolean,
  'prior_ambiguity' : boolean,
  'frozen' : [] | [FrozenPayout],
  'phase' : PayoutPhase,
}
export interface PendingDeposit {
  'status' : DepositStatus,
  'depositor' : [] | [Principal],
  'encrypted_payload' : Uint8Array | number[],
  'insurance_amount' : bigint,
  'private_balance' : bigint,
  'created_at_ns' : bigint,
  'staking_amount' : [] | [bigint],
  'ops_amount' : bigint,
  'expected_leaf_index' : [] | [bigint],
  'note_commitment' : Uint8Array | number[],
  'finalized_at_ns' : [] | [bigint],
}
export interface PendingPromotionRecord {
  'status' : SpendStatus,
  'expected_first_leaf_index' : [] | [bigint],
  'created_at_ns' : bigint,
  'recommended_action' : RecommendedAction,
  'output_commitment_count' : number,
  'resulting_root' : [] | [Uint8Array | number[]],
  'spend_id' : bigint,
}
export interface PendingPublicPayout {
  'destination' : Principal,
  'block_index' : [] | [bigint],
  'ledger_created_at_time_ns' : [] | [bigint],
  'protocol_fee' : bigint,
  'destination_subaccount' : [] | [Uint8Array | number[]],
  'retry' : [] | [PayoutRetryState],
  'public_amount' : bigint,
}
export interface PendingSpend {
  'fee' : [] | [bigint],
  'status' : SpendStatus,
  'public_payout' : [] | [PendingPublicPayout],
  'output_commitments' : Array<Uint8Array | number[]>,
  'fee_split_staking' : [] | [bigint],
  'submitter' : [] | [Principal],
  'spend_fee_mode' : [] | [SpendFeeMode],
  'fee_split_ops' : [] | [bigint],
  'created_at_ns' : bigint,
  'fee_split_insurance' : [] | [bigint],
  'params_epoch' : [] | [bigint],
  'nullifiers' : Array<Uint8Array | number[]>,
  'finalized_at_ns' : [] | [bigint],
  'outputs_committed' : number,
  'spend_id' : bigint,
  'fee_model_version' : [] | [number],
}
export interface PendingWithdrawal {
  'status' : WithdrawalStatus,
  'destination' : Principal,
  'recipient_net_amount' : bigint,
  'submitter' : [] | [Principal],
  'nullifier' : Uint8Array | number[],
  'withdrawal_id' : bigint,
  'protocol_unshielding_fee' : bigint,
  'created_at_ns' : bigint,
  'ledger_created_at_time_ns' : [] | [bigint],
  'ledger_memo' : [] | [Uint8Array | number[]],
  'ledger_fee' : bigint,
  'finalized_at_ns' : [] | [bigint],
  'destination_subaccount' : [] | [Uint8Array | number[]],
  'gross_withdraw_amount' : bigint,
}
export interface PoolAuthorityRefs {
  'controller' : Principal,
  'treasury_canister' : Principal,
  'verifier_canister' : Principal,
  'token_canister' : Principal,
  'staking_canister' : Principal,
  'nullifier_canister' : Principal,
  'merkle_canister' : Principal,
}
export type PoolControllerReadRequest = {
    'PoolReadAccountingState' : ControllerReadPageRequest
  } |
  { 'PoolReadPendingOutputPromotions' : ControllerReadPageRequest } |
  { 'PoolReadTreasuryReconciliationTombstone' : ControllerReadPageRequest } |
  { 'PoolReadAppendLeaseOwner' : ControllerReadPageRequest };
export type PoolControllerReadResponse = {
    'PoolReadAccountingState' : ControllerReadPage
  } |
  { 'PoolReadPendingOutputPromotions' : ControllerReadPage } |
  { 'PoolReadTreasuryReconciliationTombstone' : ControllerReadPage } |
  { 'PoolReadAppendLeaseOwner' : ControllerReadPage };
export type PoolError = { 'InvalidCommitment' : null } |
  {
    'InsufficientOperationsReserve' : {
      'needed' : bigint,
      'available' : bigint,
    }
  } |
  {
    'GrossAmountBelowFees' : {
      'total_fee' : bigint,
      'withdraw_gross_amount' : bigint,
    }
  } |
  { 'SecurityEpochChanged' : null } |
  { 'WrongWithdrawalStatus' : null } |
  {
    'EncryptedOutputTooLarge' : {
      'len' : bigint,
      'max' : bigint,
      'index' : number,
    }
  } |
  { 'WrongSpendStatus' : null } |
  { 'InvalidOutputCommitment' : null } |
  { 'InvalidDenomination' : null } |
  { 'DisbursementNotReconcilable' : null } |
  { 'DuplicateSpendId' : null } |
  { 'VerifierKeyHashMismatch' : null } |
  { 'OutputAppendUnknown' : null } |
  { 'Paused' : null } |
  { 'NullifierAlreadySpent' : null } |
  { 'DepositAppendInProgress' : null } |
  { 'DepositNotReconcilable' : null } |
  { 'OutputAppendRejected' : string } |
  { 'DepositNotFound' : null } |
  { 'DepositAppendUnknown' : null } |
  { 'WithdrawalPayoutObligation' : null } |
  { 'InvalidProof' : null } |
  { 'StagedOutputsMissing' : null } |
  { 'EscrowUnderfunded' : { 'available' : bigint, 'required' : bigint } } |
  { 'ProofSystemMismatch' : null } |
  { 'CommitmentAppendFailed' : string } |
  { 'PayoutMemoKeyNotReady' : null } |
  {
    'InsufficientPrivateLiability' : {
      'available' : bigint,
      'required' : bigint,
    }
  } |
  { 'IdempotencyKeyConflict' : null } |
  { 'DuplicateWithdrawalId' : null } |
  { 'InvalidVerifierKeyHashLength' : { 'len' : bigint } } |
  { 'DeploymentConfigMismatch' : null } |
  { 'PayoutNotPending' : null } |
  { 'DisbursementProposalIdRetired' : null } |
  { 'PayoutExecutorBusy' : null } |
  { 'AmbiguousMerkleState' : null } |
  { 'PayoutStateInvalid' : null } |
  { 'NotInitialised' : null } |
  { 'RecoveryInProgress' : string } |
  { 'DisbursementNotFound' : null } |
  { 'VerifierConfigInProgress' : null } |
  { 'MalformedSpendArgs' : null } |
  {
    'WithdrawalBelowMinimum' : {
      'minimum_withdrawal_gross' : bigint,
      'withdraw_gross_amount' : bigint,
    }
  } |
  { 'BelowMinimumDeposit' : { 'minimum' : bigint, 'public_amount' : bigint } } |
  { 'DuplicateOutputCommitment' : null } |
  { 'NullifierReserved' : null } |
  { 'SpendFeeNotSupported' : null } |
  { 'Unauthorized' : null } |
  { 'SumOverflow' : null } |
  { 'PayoutOutcomePrivate' : null } |
  {
    'PartialNullifierInsert' : {
      'total' : number,
      'present' : number,
      'absent' : number,
    }
  } |
  { 'SpendNotFound' : null } |
  { 'SumMismatch' : { 'inputs' : bigint, 'outputs' : bigint } } |
  { 'CircuitVersionMismatch' : { 'got' : number, 'expected' : number } } |
  { 'InvalidProofLength' : { 'len' : bigint, 'expected' : bigint } } |
  { 'PrivateSpendFeeMismatch' : { 'got' : bigint, 'expected' : bigint } } |
  { 'DepositTransferNotConfirmed' : null } |
  { 'DepositCommitmentPending' : null } |
  { 'EncryptedPayloadTooLarge' : { 'len' : bigint, 'max' : bigint } } |
  { 'SolvencyCheckFailed' : null } |
  { 'AmountBelowLedgerFee' : { 'fee' : bigint, 'amount' : bigint } } |
  { 'TransferFailed' : string } |
  { 'VerifierUnavailable' : string } |
  {
    'InsufficientEscrowCoverage' : {
      'requested' : bigint,
      'available' : bigint,
    }
  } |
  {
    'RecipientBelowMinimum' : {
      'recipient_net_amount' : bigint,
      'minimum_recipient_amount' : bigint,
    }
  } |
  { 'ProofRejected' : string } |
  { 'PayoutLegacyHold' : null } |
  { 'VerifyingKeyMismatch' : null } |
  { 'AnchorNotFound' : null } |
  { 'PoolVersionMismatch' : null } |
  { 'WithdrawalNotFound' : null } |
  { 'PayoutOutcomeUnknown' : null } |
  { 'VerifierKeyHashChangedDuringAttestation' : null } |
  { 'AnonymousCaller' : null } |
  { 'InvariantViolationDuplicateNullifier' : null } |
  { 'DepositAlreadyCompleted' : null };
export interface PoolVersionStats {
  'retired_at_ns' : [] | [bigint],
  'total_deposited' : bigint,
  'active_at_ns' : bigint,
  'version' : number,
  'max_liability' : bigint,
  'total_withdrawn' : bigint,
}
export interface PrivateSpendArgs {
  'fee' : bigint,
  'public_payout' : [] | [PrivateSpendPublicPayout],
  'envelope' : ProofEnvelope,
  'encrypted_outputs' : Array<Uint8Array | number[]>,
  'output_commitments' : Array<Uint8Array | number[]>,
  'expected_deployment_config_hash' : [] | [Uint8Array | number[]],
  'nullifiers' : Array<Uint8Array | number[]>,
  'spend_id' : bigint,
}
export interface PrivateSpendPublicPayout {
  'destination' : Principal,
  'destination_subaccount' : [] | [Uint8Array | number[]],
  'public_amount' : bigint,
}
export interface ProofEnvelope {
  'circuit_version' : number,
  'verifying_key_hash' : Uint8Array | number[],
  'root_reference' : Uint8Array | number[],
  'proof_bytes' : Uint8Array | number[],
  'proof_system_id' : string,
  'pool_version' : number,
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
export interface PruneResult {
  'deposits_pruned' : bigint,
  'legacy_deposit_scan_complete' : boolean,
  'stopped_due_to_record_limit' : boolean,
  'next_legacy_spend_cursor' : [] | [bigint],
  'legacy_deposits_pruned' : bigint,
  'legacy_spend_scan_complete' : boolean,
  'legacy_spends_pruned' : bigint,
  'spends_pruned' : bigint,
  'next_legacy_deposit_cursor' : [] | [Uint8Array | number[]],
}
export type RecommendedAction = { 'ReconcilePendingSpend' : null } |
  { 'RetryPrivateSpendPayout' : null } |
  { 'ReconcileNullifierInsert' : null } |
  { 'ReconcilePrivateSpendPayout' : null };
export type ReconcileDisburseResult = {
    'AlreadyExecuted' : { 'block_index' : bigint }
  } |
  { 'Reverted' : null } |
  { 'Recorded' : { 'block_index' : bigint } };
export type ReconcileNullifierResult = { 'NotCommittedFailed' : null } |
  { 'CommittedFinalized' : null } |
  { 'CommittedPayoutPending' : null };
export type ReconcilePayoutResult = {
    'AlreadyExecuted' : { 'block_index' : bigint }
  } |
  { 'Finalized' : { 'block_index' : bigint } } |
  { 'RevertedToPending' : null };
export type ReconcilePendingSpendResult = { 'PromotedPayoutPending' : null } |
  { 'AppendRetryScheduled' : null } |
  { 'PromotedFinalized' : null };
export type ReconciliationDecision = { 'Executed' : null } |
  { 'NotExecuted' : null };
export type SettlementError = { 'NotSettleable' : null } |
  { 'EvidenceAmbiguous' : null } |
  { 'TooEarly' : null } |
  { 'Pool' : PoolError } |
  { 'IdentityMismatch' : null } |
  { 'InProgress' : null } |
  { 'Unavailable' : null };
export interface ShieldDepositArgs {
  'encrypted_payload' : Uint8Array | number[],
  'expected_deployment_config_hash' : [] | [Uint8Array | number[]],
  'note_commitment' : Uint8Array | number[],
  'public_amount' : bigint,
}
export interface SolvencyAttestation {
  'public_delta_e8s' : bigint,
  'healthy' : boolean,
  'schema_version' : number,
  'attested_at_ns' : bigint,
}
export type SpendFeeMode = { 'XdrPegged' : null } |
  { 'FixedStsh' : null };
export type SpendStatus = { 'PayoutUnknown' : { 'reason' : string } } |
  { 'NullifierReconcileInFlight' : null } |
  { 'NullifierInsertUnknown' : { 'reason' : string } } |
  { 'NullifierFinalizedOutputsPending' : null } |
  { 'Finalized' : null } |
  { 'ActiveAppendUnknown' : { 'reason' : string } } |
  { 'PayoutPending' : { 'reason' : string } } |
  { 'OutputsStaged' : null } |
  { 'VerificationPending' : null } |
  { 'RootAccepted' : null } |
  { 'NullifierReserved' : null } |
  { 'ActiveAppendRejected' : { 'reason' : string } } |
  { 'Requested' : null } |
  { 'ActiveRootPending' : null } |
  { 'ActiveAppendInFlight' : null } |
  { 'PayoutSubmitting' : null } |
  { 'FailedBeforeStateChange' : { 'reason' : string } } |
  { 'FailedAfterOutputsStaged' : { 'reason' : string } };
export interface TreasuryDisburseArgs {
  'expected_ledger_fee' : bigint,
  'recipient' : Principal,
  'recipient_subaccount' : [] | [Uint8Array | number[]],
  'proposal_id' : bigint,
  'bucket' : TreasuryReserveBucket,
  'amount' : bigint,
}
export type TreasuryDisburseResult = {
    'AlreadyExecuted' : { 'block_index' : bigint }
  } |
  { 'Executed' : { 'block_index' : bigint } };
export type TreasuryDisbursementStatus = { 'PendingTransfer' : null } |
  { 'PendingValidation' : null } |
  { 'TransportUnknown' : null } |
  { 'Executed' : { 'block_index' : bigint } } |
  { 'Pending' : null };
export interface TreasuryNotificationStats {
  'upgrade_dropped' : bigint,
  'in_flight' : bigint,
  'returned_failures' : bigint,
}
export interface TreasuryReconciliationTombstone {
  'expected_ledger_fee' : bigint,
  'decision' : ReconciliationDecision,
  'reconciler' : Principal,
  'memo' : Uint8Array | number[],
  'recipient' : Principal,
  'recipient_subaccount' : [] | [Uint8Array | number[]],
  'ledger_created_at_time_ns' : [] | [bigint],
  'proposal_id' : bigint,
  'asserted_block_index' : [] | [bigint],
  'bucket' : TreasuryReserveBucket,
  'amount' : bigint,
  'pre_reconcile_status' : TreasuryDisbursementStatus,
  'reconciled_at_ns' : bigint,
}
export type TreasuryReserveBucket = { 'Insurance' : null } |
  { 'StakingRewards' : null } |
  { 'Operations' : null };
export interface WithdrawArgs {
  'envelope' : ProofEnvelope,
  'destination' : Principal,
  'nullifier' : Uint8Array | number[],
  'withdrawal_id' : bigint,
  'destination_subaccount' : [] | [Uint8Array | number[]],
  'gross_withdraw_amount' : bigint,
}
export type WithdrawalStatus = { 'LedgerTransferUnknown' : null } |
  { 'FailedTerminalUserError' : { 'reason' : string } } |
  { 'RegistryInsertPending' : null } |
  { 'PayoutObligationPending' : null } |
  { 'Finalized' : null } |
  { 'FeeReimbursementPending' : { 'ledger_fee' : bigint } } |
  { 'FailedRetryable' : null } |
  { 'ProofVerified' : null } |
  { 'LedgerTransferPending' : null } |
  { 'RegistryInserted' : null } |
  { 'AccountingApplied' : null } |
  { 'NullifierReserved' : null } |
  { 'SolvencyBlocked' : { 'available' : bigint, 'required' : bigint } } |
  { 'Requested' : null } |
  { 'RegistryInsertUnknown' : null } |
  { 'EscrowCoverageChecked' : null } |
  { 'LedgerTransferConfirmed' : null };
export interface _SERVICE {
  'accepted_spend_root_count' : ActorMethod<[], bigint>,
  'clear_verifier_config_guard' : ActorMethod<[], boolean>,
  'cycle_balance' : ActorMethod<[], bigint>,
  'emergency_disable_circuit_version' : ActorMethod<
    [number],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'emergency_pause_deposits' : ActorMethod<[], undefined>,
  'emergency_pause_spends' : ActorMethod<
    [],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'fee_params_match_mainnet_launch_config' : ActorMethod<[], boolean>,
  'get_accepted_root_head' : ActorMethod<[], [] | [AcceptedRootHead]>,
  'get_accounting_state' : ActorMethod<[], AccountingState>,
  'get_accounting_state_for_controller_update' : ActorMethod<
    [PoolControllerReadRequest],
    PoolControllerReadResponse
  >,
  'get_admitted_operation_stats' : ActorMethod<[], AdmittedOperationStats>,
  'get_append_lease_owner' : ActorMethod<[], [] | [AppendLeaseOwnerView]>,
  'get_append_lease_owner_for_controller_update' : ActorMethod<
    [PoolControllerReadRequest],
    PoolControllerReadResponse
  >,
  'get_append_lease_status' : ActorMethod<[], AppendLeaseStatus>,
  'get_authority_refs' : ActorMethod<[], [] | [PoolAuthorityRefs]>,
  'get_build_info' : ActorMethod<[], string>,
  'get_circuit_version' : ActorMethod<[], number>,
  'get_denominations' : ActorMethod<[], Array<bigint>>,
  'get_deployment_attestation' : ActorMethod<
    [],
    { 'Ok' : DeploymentAttestation } |
      { 'Err' : PoolError }
  >,
  'get_deposit_status' : ActorMethod<
    [Uint8Array | number[]],
    [] | [PendingDeposit]
  >,
  'get_fee_flush_window_ns' : ActorMethod<[], bigint>,
  'get_fee_governance_state' : ActorMethod<[], FeeGovernanceState>,
  'get_governance_fee_params' : ActorMethod<[], GovernanceFeeParams>,
  'get_pinned_vk_hash' : ActorMethod<[], Uint8Array | number[]>,
  'get_pool_version' : ActorMethod<[], number>,
  'get_pool_version_stats' : ActorMethod<[], Array<PoolVersionStats>>,
  'get_security_epoch' : ActorMethod<[], bigint>,
  'get_solvency_attestation' : ActorMethod<[], CertifiedSolvencyAttestation>,
  'get_spend_status' : ActorMethod<[bigint], [] | [PendingSpend]>,
  'get_treasury_notification_failures' : ActorMethod<[], bigint>,
  'get_treasury_notification_stats' : ActorMethod<
    [],
    TreasuryNotificationStats
  >,
  'get_treasury_reconciliation_tombstone' : ActorMethod<
    [bigint],
    [] | [TreasuryReconciliationTombstone]
  >,
  'get_treasury_reconciliation_tombstone_for_controller_update' : ActorMethod<
    [PoolControllerReadRequest],
    PoolControllerReadResponse
  >,
  'get_verifier_canister' : ActorMethod<[], [] | [Principal]>,
  'get_vetkeys_canister' : ActorMethod<[], [] | [Principal]>,
  'get_withdrawal_status' : ActorMethod<[bigint], [] | [PendingWithdrawal]>,
  'icrc21_canister_call_consent_message' : ActorMethod<
    [string],
    { 'Ok' : string } |
      { 'Err' : string }
  >,
  'initialize_payout_memo_key' : ActorMethod<
    [],
    { 'Ok' : boolean } |
      { 'Err' : PoolError }
  >,
  'is_accepted_spend_root' : ActorMethod<[Uint8Array | number[]], boolean>,
  'is_deposits_paused' : ActorMethod<[], boolean>,
  'is_spends_paused' : ActorMethod<[], boolean>,
  'list_my_active_deposits' : ActorMethod<
    [[] | [Uint8Array | number[]], bigint],
    ActiveDepositsPage
  >,
  'list_my_active_spends' : ActorMethod<
    [[] | [bigint], bigint],
    ActiveSpendsPage
  >,
  'list_pending_output_promotions' : ActorMethod<
    [],
    Array<PendingPromotionRecord>
  >,
  'list_pending_output_promotions_for_controller_update' : ActorMethod<
    [PoolControllerReadRequest],
    PoolControllerReadResponse
  >,
  'payout_memo_key_ready' : ActorMethod<[], [] | [boolean]>,
  'payout_memo_key_ready_for_controller_update' : ActorMethod<
    [],
    [] | [boolean]
  >,
  'private_spend' : ActorMethod<
    [PrivateSpendArgs],
    { 'Ok' : null } |
      { 'Err' : PoolError }
  >,
  'prune_terminal_records' : ActorMethod<[PruneRequest], PruneResult>,
  'reconcile_deposit_append_unknown' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : DepositAppendReconcileResult } |
      { 'Err' : PoolError }
  >,
  'reconcile_deposit_commitment' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : null } |
      { 'Err' : PoolError }
  >,
  'reconcile_deposit_transfer_not_executed' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : null } |
      { 'Err' : PoolError }
  >,
  'reconcile_nullifier_insert' : ActorMethod<
    [bigint],
    { 'Ok' : ReconcileNullifierResult } |
      { 'Err' : PoolError }
  >,
  'reconcile_pending_spend' : ActorMethod<
    [bigint],
    { 'Ok' : ReconcilePendingSpendResult } |
      { 'Err' : PoolError }
  >,
  'reconcile_private_spend_payout' : ActorMethod<
    [bigint, PayoutOutcome],
    { 'Ok' : ReconcilePayoutResult } |
      { 'Err' : PoolError }
  >,
  'reconcile_treasury_disburse' : ActorMethod<
    [bigint, DisburseOutcome],
    { 'Ok' : ReconcileDisburseResult } |
      { 'Err' : PoolError }
  >,
  'reconcile_withdrawal_ledger_transfer' : ActorMethod<
    [bigint],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
  'reconcile_withdrawal_registry_insert' : ActorMethod<
    [bigint],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
  'resume_blocked_withdrawal' : ActorMethod<
    [bigint],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
  'retry_deposit_commitment' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
  'retry_private_spend_payout' : ActorMethod<
    [bigint],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
  'schedule_vk_activation' : ActorMethod<
    [number, Uint8Array | number[], bigint, bigint],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'set_fee_flush_window_ns' : ActorMethod<
    [bigint],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'set_governance_fee_params' : ActorMethod<
    [GovernanceFeeParams],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'set_verifier_canister' : ActorMethod<
    [Principal, Uint8Array | number[]],
    { 'Ok' : null } |
      { 'Err' : PoolError }
  >,
  'settle_deposit_transfer' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : DepositSettlementOutcome } |
      { 'Err' : SettlementError }
  >,
  'shield_deposit' : ActorMethod<
    [ShieldDepositArgs],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
  'treasury_disburse' : ActorMethod<
    [TreasuryDisburseArgs],
    { 'Ok' : TreasuryDisburseResult } |
      { 'Err' : PoolError }
  >,
  'unpause_deposits' : ActorMethod<[], undefined>,
  'unpause_spends' : ActorMethod<[], undefined>,
  'withdraw' : ActorMethod<
    [WithdrawArgs],
    { 'Ok' : bigint } |
      { 'Err' : PoolError }
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
