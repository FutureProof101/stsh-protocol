export const idlFactory = ({ IDL }) => {
  const AcceptedRootHead = IDL.Record({
    'root' : IDL.Vec(IDL.Nat8),
    'leaf_count' : IDL.Nat64,
  });
  const AccountingState = IDL.Record({
    'private_liability' : IDL.Nat,
    'pending_fee_reimbursements' : IDL.Nat,
    'operations_reserve' : IDL.Nat,
    'escrow_backing' : IDL.Nat,
    'governance_rewards_reserve' : IDL.Nat,
    'insurance_reserve' : IDL.Nat,
  });
  const ControllerReadPageRequest = IDL.Record({
    'cursor' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'limit' : IDL.Nat32,
  });
  const PoolControllerReadRequest = IDL.Variant({
    'PoolReadAccountingState' : ControllerReadPageRequest,
    'PoolReadPendingOutputPromotions' : ControllerReadPageRequest,
    'PoolReadTreasuryReconciliationTombstone' : ControllerReadPageRequest,
    'PoolReadAppendLeaseOwner' : ControllerReadPageRequest,
  });
  const ControllerReadPage = IDL.Record({
    'next_cursor' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'items' : IDL.Vec(IDL.Vec(IDL.Nat8)),
  });
  const PoolControllerReadResponse = IDL.Variant({
    'PoolReadAccountingState' : ControllerReadPage,
    'PoolReadPendingOutputPromotions' : ControllerReadPage,
    'PoolReadTreasuryReconciliationTombstone' : ControllerReadPage,
    'PoolReadAppendLeaseOwner' : ControllerReadPage,
  });
  const AdmittedOperationStats = IDL.Record({
    'upgrade_dropped' : IDL.Nat64,
    'admitted' : IDL.Nat64,
  });
  const AppendLeaseOwner = IDL.Variant({
    'Spend' : IDL.Record({ 'spend_id' : IDL.Nat64 }),
    'Deposit' : IDL.Record({ 'commitment' : IDL.Vec(IDL.Nat8) }),
  });
  const LeasePhase = IDL.Variant({
    'AppendConfirmedRootPending' : IDL.Null,
    'AppendInFlight' : IDL.Null,
    'AppendUnknown' : IDL.Null,
    'ReconcileInFlight' : IDL.Null,
    'Snapshotting' : IDL.Null,
  });
  const AppendLeaseOwnerView = IDL.Record({
    'owner' : AppendLeaseOwner,
    'generation' : IDL.Nat64,
    'acquired_at_ns' : IDL.Nat64,
    'phase' : LeasePhase,
    'phase_started_at_ns' : IDL.Nat64,
  });
  const LeaseAgeBucket = IDL.Variant({
    'OverHour' : IDL.Null,
    'UnderHour' : IDL.Null,
    'UnderMinute' : IDL.Null,
    'UnderTenMinutes' : IDL.Null,
  });
  const AppendLeaseStatus = IDL.Record({
    'held' : IDL.Bool,
    'age_bucket' : IDL.Opt(LeaseAgeBucket),
    'phase' : IDL.Opt(LeasePhase),
  });
  const PoolAuthorityRefs = IDL.Record({
    'controller' : IDL.Principal,
    'treasury_canister' : IDL.Principal,
    'verifier_canister' : IDL.Principal,
    'token_canister' : IDL.Principal,
    'staking_canister' : IDL.Principal,
    'nullifier_canister' : IDL.Principal,
    'merkle_canister' : IDL.Principal,
  });
  const DeploymentAttestation = IDL.Record({
    'circuit_version' : IDL.Nat32,
    'merkle' : IDL.Principal,
    'verifier' : IDL.Opt(IDL.Principal),
    'token' : IDL.Principal,
    'proof_system' : IDL.Text,
    'nullifier' : IDL.Principal,
    'pool' : IDL.Principal,
    'config_version' : IDL.Nat32,
    'pool_version' : IDL.Nat32,
    'config_hash' : IDL.Vec(IDL.Nat8),
    'vk_hash' : IDL.Vec(IDL.Nat8),
  });
  const PoolError = IDL.Variant({
    'InvalidCommitment' : IDL.Null,
    'InsufficientOperationsReserve' : IDL.Record({
      'needed' : IDL.Nat,
      'available' : IDL.Nat,
    }),
    'GrossAmountBelowFees' : IDL.Record({
      'total_fee' : IDL.Nat,
      'withdraw_gross_amount' : IDL.Nat,
    }),
    'SecurityEpochChanged' : IDL.Null,
    'WrongWithdrawalStatus' : IDL.Null,
    'EncryptedOutputTooLarge' : IDL.Record({
      'len' : IDL.Nat64,
      'max' : IDL.Nat64,
      'index' : IDL.Nat32,
    }),
    'WrongSpendStatus' : IDL.Null,
    'InvalidOutputCommitment' : IDL.Null,
    'InvalidDenomination' : IDL.Null,
    'DisbursementNotReconcilable' : IDL.Null,
    'DuplicateSpendId' : IDL.Null,
    'VerifierKeyHashMismatch' : IDL.Null,
    'OutputAppendUnknown' : IDL.Null,
    'Paused' : IDL.Null,
    'NullifierAlreadySpent' : IDL.Null,
    'DepositAppendInProgress' : IDL.Null,
    'DepositNotReconcilable' : IDL.Null,
    'OutputAppendRejected' : IDL.Text,
    'DepositNotFound' : IDL.Null,
    'DepositAppendUnknown' : IDL.Null,
    'WithdrawalPayoutObligation' : IDL.Null,
    'InvalidProof' : IDL.Null,
    'StagedOutputsMissing' : IDL.Null,
    'EscrowUnderfunded' : IDL.Record({
      'available' : IDL.Nat,
      'required' : IDL.Nat,
    }),
    'ProofSystemMismatch' : IDL.Null,
    'CommitmentAppendFailed' : IDL.Text,
    'PayoutMemoKeyNotReady' : IDL.Null,
    'InsufficientPrivateLiability' : IDL.Record({
      'available' : IDL.Nat,
      'required' : IDL.Nat,
    }),
    'IdempotencyKeyConflict' : IDL.Null,
    'DuplicateWithdrawalId' : IDL.Null,
    'InvalidVerifierKeyHashLength' : IDL.Record({ 'len' : IDL.Nat64 }),
    'DeploymentConfigMismatch' : IDL.Null,
    'PayoutNotPending' : IDL.Null,
    'DisbursementProposalIdRetired' : IDL.Null,
    'PayoutExecutorBusy' : IDL.Null,
    'AmbiguousMerkleState' : IDL.Null,
    'PayoutStateInvalid' : IDL.Null,
    'NotInitialised' : IDL.Null,
    'RecoveryInProgress' : IDL.Text,
    'DisbursementNotFound' : IDL.Null,
    'VerifierConfigInProgress' : IDL.Null,
    'MalformedSpendArgs' : IDL.Null,
    'WithdrawalBelowMinimum' : IDL.Record({
      'minimum_withdrawal_gross' : IDL.Nat,
      'withdraw_gross_amount' : IDL.Nat,
    }),
    'BelowMinimumDeposit' : IDL.Record({
      'minimum' : IDL.Nat,
      'public_amount' : IDL.Nat,
    }),
    'DuplicateOutputCommitment' : IDL.Null,
    'NullifierReserved' : IDL.Null,
    'SpendFeeNotSupported' : IDL.Null,
    'Unauthorized' : IDL.Null,
    'SumOverflow' : IDL.Null,
    'PayoutOutcomePrivate' : IDL.Null,
    'PartialNullifierInsert' : IDL.Record({
      'total' : IDL.Nat32,
      'present' : IDL.Nat32,
      'absent' : IDL.Nat32,
    }),
    'SpendNotFound' : IDL.Null,
    'SumMismatch' : IDL.Record({ 'inputs' : IDL.Nat, 'outputs' : IDL.Nat }),
    'CircuitVersionMismatch' : IDL.Record({
      'got' : IDL.Nat32,
      'expected' : IDL.Nat32,
    }),
    'InvalidProofLength' : IDL.Record({
      'len' : IDL.Nat64,
      'expected' : IDL.Nat64,
    }),
    'PrivateSpendFeeMismatch' : IDL.Record({
      'got' : IDL.Nat,
      'expected' : IDL.Nat,
    }),
    'DepositTransferNotConfirmed' : IDL.Null,
    'DepositCommitmentPending' : IDL.Null,
    'EncryptedPayloadTooLarge' : IDL.Record({
      'len' : IDL.Nat64,
      'max' : IDL.Nat64,
    }),
    'SolvencyCheckFailed' : IDL.Null,
    'AmountBelowLedgerFee' : IDL.Record({
      'fee' : IDL.Nat,
      'amount' : IDL.Nat,
    }),
    'TransferFailed' : IDL.Text,
    'VerifierUnavailable' : IDL.Text,
    'InsufficientEscrowCoverage' : IDL.Record({
      'requested' : IDL.Nat,
      'available' : IDL.Nat,
    }),
    'RecipientBelowMinimum' : IDL.Record({
      'recipient_net_amount' : IDL.Nat,
      'minimum_recipient_amount' : IDL.Nat,
    }),
    'ProofRejected' : IDL.Text,
    'PayoutLegacyHold' : IDL.Null,
    'VerifyingKeyMismatch' : IDL.Null,
    'AnchorNotFound' : IDL.Null,
    'PoolVersionMismatch' : IDL.Null,
    'WithdrawalNotFound' : IDL.Null,
    'PayoutOutcomeUnknown' : IDL.Null,
    'VerifierKeyHashChangedDuringAttestation' : IDL.Null,
    'AnonymousCaller' : IDL.Null,
    'InvariantViolationDuplicateNullifier' : IDL.Null,
    'DepositAlreadyCompleted' : IDL.Null,
  });
  const DepositStatus = IDL.Variant({
    'CommitmentReconcileInFlight' : IDL.Null,
    'CommitmentAppended' : IDL.Record({ 'leaf_index' : IDL.Nat64 }),
    'CommitmentAppendUnknown' : IDL.Null,
    'CommitmentRootAccepted' : IDL.Record({
      'root' : IDL.Vec(IDL.Nat8),
      'leaf_index' : IDL.Nat64,
    }),
    'TransferPending' : IDL.Null,
    'CommitmentPending' : IDL.Null,
    'TransferConfirmedCommitmentPending' : IDL.Null,
    'CommitmentAppendInFlight' : IDL.Null,
  });
  const PendingDeposit = IDL.Record({
    'status' : DepositStatus,
    'depositor' : IDL.Opt(IDL.Principal),
    'encrypted_payload' : IDL.Vec(IDL.Nat8),
    'insurance_amount' : IDL.Nat,
    'private_balance' : IDL.Nat,
    'created_at_ns' : IDL.Nat64,
    'staking_amount' : IDL.Opt(IDL.Nat),
    'ops_amount' : IDL.Nat,
    'expected_leaf_index' : IDL.Opt(IDL.Nat64),
    'note_commitment' : IDL.Vec(IDL.Nat8),
    'finalized_at_ns' : IDL.Opt(IDL.Nat64),
  });
  const FeeGovernanceState = IDL.Record({
    'last_fee_update_ns' : IDL.Nat64,
    'fee_update_cooldown_ns' : IDL.Nat64,
    'launch_fee_activated' : IDL.Bool,
    'params_epoch' : IDL.Nat64,
  });
  const SpendFeeMode = IDL.Variant({
    'XdrPegged' : IDL.Null,
    'FixedStsh' : IDL.Null,
  });
  const GovernanceFeeParams = IDL.Record({
    'minimum_withdrawal_gross' : IDL.Nat,
    'shield_flat_minimum_fee_e8s' : IDL.Opt(IDL.Nat),
    'operations_split_bps' : IDL.Nat32,
    'staking_rewards_enabled' : IDL.Bool,
    'spend_fee_mode' : IDL.Opt(SpendFeeMode),
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
  const PoolVersionStats = IDL.Record({
    'retired_at_ns' : IDL.Opt(IDL.Nat64),
    'total_deposited' : IDL.Nat,
    'active_at_ns' : IDL.Nat64,
    'version' : IDL.Nat32,
    'max_liability' : IDL.Nat,
    'total_withdrawn' : IDL.Nat,
  });
  const SolvencyAttestation = IDL.Record({
    'public_delta_e8s' : IDL.Int,
    'healthy' : IDL.Bool,
    'schema_version' : IDL.Nat32,
    'attested_at_ns' : IDL.Nat64,
  });
  const CertifiedSolvencyAttestation = IDL.Record({
    'certificate' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'attestation' : SolvencyAttestation,
    'witness' : IDL.Vec(IDL.Nat8),
    'canonical_bytes' : IDL.Vec(IDL.Nat8),
  });
  const SpendStatus = IDL.Variant({
    'PayoutUnknown' : IDL.Record({ 'reason' : IDL.Text }),
    'NullifierReconcileInFlight' : IDL.Null,
    'NullifierInsertUnknown' : IDL.Record({ 'reason' : IDL.Text }),
    'NullifierFinalizedOutputsPending' : IDL.Null,
    'Finalized' : IDL.Null,
    'ActiveAppendUnknown' : IDL.Record({ 'reason' : IDL.Text }),
    'PayoutPending' : IDL.Record({ 'reason' : IDL.Text }),
    'OutputsStaged' : IDL.Null,
    'VerificationPending' : IDL.Null,
    'RootAccepted' : IDL.Null,
    'NullifierReserved' : IDL.Null,
    'ActiveAppendRejected' : IDL.Record({ 'reason' : IDL.Text }),
    'Requested' : IDL.Null,
    'ActiveRootPending' : IDL.Null,
    'ActiveAppendInFlight' : IDL.Null,
    'PayoutSubmitting' : IDL.Null,
    'FailedBeforeStateChange' : IDL.Record({ 'reason' : IDL.Text }),
    'FailedAfterOutputsStaged' : IDL.Record({ 'reason' : IDL.Text }),
  });
  const FrozenPayout = IDL.Record({
    'fee' : IDL.Opt(IDL.Nat),
    'destination' : IDL.Principal,
    'memo' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'from_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'ledger' : IDL.Principal,
    'created_at_time' : IDL.Opt(IDL.Nat64),
    'amount' : IDL.Nat,
    'destination_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
  });
  const PayoutPhase = IDL.Variant({
    'PreDispatch' : IDL.Null,
    'MayHaveDispatched' : IDL.Null,
  });
  const PayoutRetryState = IDL.Record({
    'memo_sequence' : IDL.Nat,
    'boot' : IDL.Nat64,
    'generation' : IDL.Nat64,
    'dispatched' : IDL.Bool,
    'prior_ambiguity' : IDL.Bool,
    'frozen' : IDL.Opt(FrozenPayout),
    'phase' : PayoutPhase,
  });
  const PendingPublicPayout = IDL.Record({
    'destination' : IDL.Principal,
    'block_index' : IDL.Opt(IDL.Nat),
    'ledger_created_at_time_ns' : IDL.Opt(IDL.Nat64),
    'protocol_fee' : IDL.Nat,
    'destination_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'retry' : IDL.Opt(PayoutRetryState),
    'public_amount' : IDL.Nat,
  });
  const PendingSpend = IDL.Record({
    'fee' : IDL.Opt(IDL.Nat),
    'status' : SpendStatus,
    'public_payout' : IDL.Opt(PendingPublicPayout),
    'output_commitments' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'fee_split_staking' : IDL.Opt(IDL.Nat),
    'submitter' : IDL.Opt(IDL.Principal),
    'spend_fee_mode' : IDL.Opt(SpendFeeMode),
    'fee_split_ops' : IDL.Opt(IDL.Nat),
    'created_at_ns' : IDL.Nat64,
    'fee_split_insurance' : IDL.Opt(IDL.Nat),
    'params_epoch' : IDL.Opt(IDL.Nat64),
    'nullifiers' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'finalized_at_ns' : IDL.Opt(IDL.Nat64),
    'outputs_committed' : IDL.Nat32,
    'spend_id' : IDL.Nat64,
    'fee_model_version' : IDL.Opt(IDL.Nat32),
  });
  const TreasuryNotificationStats = IDL.Record({
    'upgrade_dropped' : IDL.Nat64,
    'in_flight' : IDL.Nat64,
    'returned_failures' : IDL.Nat64,
  });
  const ReconciliationDecision = IDL.Variant({
    'Executed' : IDL.Null,
    'NotExecuted' : IDL.Null,
  });
  const TreasuryReserveBucket = IDL.Variant({
    'Insurance' : IDL.Null,
    'StakingRewards' : IDL.Null,
    'Operations' : IDL.Null,
  });
  const TreasuryDisbursementStatus = IDL.Variant({
    'PendingTransfer' : IDL.Null,
    'PendingValidation' : IDL.Null,
    'TransportUnknown' : IDL.Null,
    'Executed' : IDL.Record({ 'block_index' : IDL.Nat }),
    'Pending' : IDL.Null,
  });
  const TreasuryReconciliationTombstone = IDL.Record({
    'expected_ledger_fee' : IDL.Nat,
    'decision' : ReconciliationDecision,
    'reconciler' : IDL.Principal,
    'memo' : IDL.Vec(IDL.Nat8),
    'recipient' : IDL.Principal,
    'recipient_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'ledger_created_at_time_ns' : IDL.Opt(IDL.Nat64),
    'proposal_id' : IDL.Nat64,
    'asserted_block_index' : IDL.Opt(IDL.Nat64),
    'bucket' : TreasuryReserveBucket,
    'amount' : IDL.Nat,
    'pre_reconcile_status' : TreasuryDisbursementStatus,
    'reconciled_at_ns' : IDL.Nat64,
  });
  const WithdrawalStatus = IDL.Variant({
    'LedgerTransferUnknown' : IDL.Null,
    'FailedTerminalUserError' : IDL.Record({ 'reason' : IDL.Text }),
    'RegistryInsertPending' : IDL.Null,
    'PayoutObligationPending' : IDL.Null,
    'Finalized' : IDL.Null,
    'FeeReimbursementPending' : IDL.Record({ 'ledger_fee' : IDL.Nat }),
    'FailedRetryable' : IDL.Null,
    'ProofVerified' : IDL.Null,
    'LedgerTransferPending' : IDL.Null,
    'RegistryInserted' : IDL.Null,
    'AccountingApplied' : IDL.Null,
    'NullifierReserved' : IDL.Null,
    'SolvencyBlocked' : IDL.Record({
      'available' : IDL.Nat,
      'required' : IDL.Nat,
    }),
    'Requested' : IDL.Null,
    'RegistryInsertUnknown' : IDL.Null,
    'EscrowCoverageChecked' : IDL.Null,
    'LedgerTransferConfirmed' : IDL.Null,
  });
  const PendingWithdrawal = IDL.Record({
    'status' : WithdrawalStatus,
    'destination' : IDL.Principal,
    'recipient_net_amount' : IDL.Nat,
    'submitter' : IDL.Opt(IDL.Principal),
    'nullifier' : IDL.Vec(IDL.Nat8),
    'withdrawal_id' : IDL.Nat64,
    'protocol_unshielding_fee' : IDL.Nat,
    'created_at_ns' : IDL.Nat64,
    'ledger_created_at_time_ns' : IDL.Opt(IDL.Nat64),
    'ledger_memo' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'ledger_fee' : IDL.Nat,
    'finalized_at_ns' : IDL.Opt(IDL.Nat64),
    'destination_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'gross_withdraw_amount' : IDL.Nat,
  });
  const ActiveDepositsPage = IDL.Record({
    'next_cursor' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'deposits' : IDL.Vec(PendingDeposit),
  });
  const ActiveSpendsPage = IDL.Record({
    'next_cursor' : IDL.Opt(IDL.Nat64),
    'spends' : IDL.Vec(PendingSpend),
  });
  const RecommendedAction = IDL.Variant({
    'ReconcilePendingSpend' : IDL.Null,
    'RetryPrivateSpendPayout' : IDL.Null,
    'ReconcileNullifierInsert' : IDL.Null,
    'ReconcilePrivateSpendPayout' : IDL.Null,
  });
  const PendingPromotionRecord = IDL.Record({
    'status' : SpendStatus,
    'expected_first_leaf_index' : IDL.Opt(IDL.Nat64),
    'created_at_ns' : IDL.Nat64,
    'recommended_action' : RecommendedAction,
    'output_commitment_count' : IDL.Nat32,
    'resulting_root' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'spend_id' : IDL.Nat64,
  });
  const PrivateSpendPublicPayout = IDL.Record({
    'destination' : IDL.Principal,
    'destination_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'public_amount' : IDL.Nat,
  });
  const ProofEnvelope = IDL.Record({
    'circuit_version' : IDL.Nat32,
    'verifying_key_hash' : IDL.Vec(IDL.Nat8),
    'root_reference' : IDL.Vec(IDL.Nat8),
    'proof_bytes' : IDL.Vec(IDL.Nat8),
    'proof_system_id' : IDL.Text,
    'pool_version' : IDL.Nat32,
  });
  const PrivateSpendArgs = IDL.Record({
    'fee' : IDL.Nat,
    'public_payout' : IDL.Opt(PrivateSpendPublicPayout),
    'envelope' : ProofEnvelope,
    'encrypted_outputs' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'output_commitments' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'expected_deployment_config_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'nullifiers' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'spend_id' : IDL.Nat64,
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
  const PruneResult = IDL.Record({
    'deposits_pruned' : IDL.Nat64,
    'legacy_deposit_scan_complete' : IDL.Bool,
    'stopped_due_to_record_limit' : IDL.Bool,
    'next_legacy_spend_cursor' : IDL.Opt(IDL.Nat64),
    'legacy_deposits_pruned' : IDL.Nat64,
    'legacy_spend_scan_complete' : IDL.Bool,
    'legacy_spends_pruned' : IDL.Nat64,
    'spends_pruned' : IDL.Nat64,
    'next_legacy_deposit_cursor' : IDL.Opt(IDL.Vec(IDL.Nat8)),
  });
  const DepositAppendReconcileResult = IDL.Variant({
    'Finalized' : IDL.Null,
    'RevertedRetryable' : IDL.Null,
  });
  const ReconcileNullifierResult = IDL.Variant({
    'NotCommittedFailed' : IDL.Null,
    'CommittedFinalized' : IDL.Null,
    'CommittedPayoutPending' : IDL.Null,
  });
  const ReconcilePendingSpendResult = IDL.Variant({
    'PromotedPayoutPending' : IDL.Null,
    'AppendRetryScheduled' : IDL.Null,
    'PromotedFinalized' : IDL.Null,
  });
  const PayoutOutcome = IDL.Variant({
    'Executed' : IDL.Record({ 'block_index' : IDL.Nat64 }),
    'NotExecuted' : IDL.Null,
  });
  const ReconcilePayoutResult = IDL.Variant({
    'AlreadyExecuted' : IDL.Record({ 'block_index' : IDL.Nat }),
    'Finalized' : IDL.Record({ 'block_index' : IDL.Nat }),
    'RevertedToPending' : IDL.Null,
  });
  const DisburseOutcome = IDL.Variant({
    'Executed' : IDL.Record({ 'block_index' : IDL.Nat64 }),
    'NotExecuted' : IDL.Null,
  });
  const ReconcileDisburseResult = IDL.Variant({
    'AlreadyExecuted' : IDL.Record({ 'block_index' : IDL.Nat }),
    'Reverted' : IDL.Null,
    'Recorded' : IDL.Record({ 'block_index' : IDL.Nat }),
  });
  const DepositSettlementOutcome = IDL.Variant({
    'CreditedFromReceipt' : IDL.Nat,
    'FencedNotExecuted' : IDL.Null,
    'CreditedFromDuplicate' : IDL.Nat,
    'CreditedFromExecution' : IDL.Nat,
  });
  const SettlementError = IDL.Variant({
    'NotSettleable' : IDL.Null,
    'EvidenceAmbiguous' : IDL.Null,
    'TooEarly' : IDL.Null,
    'Pool' : PoolError,
    'IdentityMismatch' : IDL.Null,
    'InProgress' : IDL.Null,
    'Unavailable' : IDL.Null,
  });
  const ShieldDepositArgs = IDL.Record({
    'encrypted_payload' : IDL.Vec(IDL.Nat8),
    'expected_deployment_config_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'note_commitment' : IDL.Vec(IDL.Nat8),
    'public_amount' : IDL.Nat,
  });
  const TreasuryDisburseArgs = IDL.Record({
    'expected_ledger_fee' : IDL.Nat,
    'recipient' : IDL.Principal,
    'recipient_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'proposal_id' : IDL.Nat64,
    'bucket' : TreasuryReserveBucket,
    'amount' : IDL.Nat,
  });
  const TreasuryDisburseResult = IDL.Variant({
    'AlreadyExecuted' : IDL.Record({ 'block_index' : IDL.Nat }),
    'Executed' : IDL.Record({ 'block_index' : IDL.Nat }),
  });
  const WithdrawArgs = IDL.Record({
    'envelope' : ProofEnvelope,
    'destination' : IDL.Principal,
    'nullifier' : IDL.Vec(IDL.Nat8),
    'withdrawal_id' : IDL.Nat64,
    'destination_subaccount' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'gross_withdraw_amount' : IDL.Nat,
  });
  return IDL.Service({
    'accepted_spend_root_count' : IDL.Func([], [IDL.Nat64], ['query']),
    'clear_verifier_config_guard' : IDL.Func([], [IDL.Bool], []),
    'cycle_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'emergency_disable_circuit_version' : IDL.Func(
        [IDL.Nat32],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'emergency_pause_deposits' : IDL.Func([], [], []),
    'emergency_pause_spends' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'fee_params_match_mainnet_launch_config' : IDL.Func(
        [],
        [IDL.Bool],
        ['query'],
      ),
    'get_accepted_root_head' : IDL.Func(
        [],
        [IDL.Opt(AcceptedRootHead)],
        ['query'],
      ),
    'get_accounting_state' : IDL.Func([], [AccountingState], ['query']),
    'get_accounting_state_for_controller_update' : IDL.Func(
        [PoolControllerReadRequest],
        [PoolControllerReadResponse],
        [],
      ),
    'get_admitted_operation_stats' : IDL.Func(
        [],
        [AdmittedOperationStats],
        ['query'],
      ),
    'get_append_lease_owner' : IDL.Func(
        [],
        [IDL.Opt(AppendLeaseOwnerView)],
        ['query'],
      ),
    'get_append_lease_owner_for_controller_update' : IDL.Func(
        [PoolControllerReadRequest],
        [PoolControllerReadResponse],
        [],
      ),
    'get_append_lease_status' : IDL.Func([], [AppendLeaseStatus], ['query']),
    'get_authority_refs' : IDL.Func(
        [],
        [IDL.Opt(PoolAuthorityRefs)],
        ['query'],
      ),
    'get_build_info' : IDL.Func([], [IDL.Text], ['query']),
    'get_circuit_version' : IDL.Func([], [IDL.Nat32], ['query']),
    'get_denominations' : IDL.Func([], [IDL.Vec(IDL.Nat)], ['query']),
    'get_deployment_attestation' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : DeploymentAttestation, 'Err' : PoolError })],
        ['query'],
      ),
    'get_deposit_status' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Opt(PendingDeposit)],
        ['query'],
      ),
    'get_fee_flush_window_ns' : IDL.Func([], [IDL.Nat64], ['query']),
    'get_fee_governance_state' : IDL.Func([], [FeeGovernanceState], ['query']),
    'get_governance_fee_params' : IDL.Func(
        [],
        [GovernanceFeeParams],
        ['query'],
      ),
    'get_pinned_vk_hash' : IDL.Func([], [IDL.Vec(IDL.Nat8)], ['query']),
    'get_pool_version' : IDL.Func([], [IDL.Nat32], ['query']),
    'get_pool_version_stats' : IDL.Func(
        [],
        [IDL.Vec(PoolVersionStats)],
        ['query'],
      ),
    'get_security_epoch' : IDL.Func([], [IDL.Nat64], ['query']),
    'get_solvency_attestation' : IDL.Func(
        [],
        [CertifiedSolvencyAttestation],
        ['query'],
      ),
    'get_spend_status' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(PendingSpend)],
        ['query'],
      ),
    'get_treasury_notification_failures' : IDL.Func([], [IDL.Nat64], ['query']),
    'get_treasury_notification_stats' : IDL.Func(
        [],
        [TreasuryNotificationStats],
        ['query'],
      ),
    'get_treasury_reconciliation_tombstone' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(TreasuryReconciliationTombstone)],
        ['query'],
      ),
    'get_treasury_reconciliation_tombstone_for_controller_update' : IDL.Func(
        [PoolControllerReadRequest],
        [PoolControllerReadResponse],
        [],
      ),
    'get_verifier_canister' : IDL.Func([], [IDL.Opt(IDL.Principal)], ['query']),
    'get_vetkeys_canister' : IDL.Func([], [IDL.Opt(IDL.Principal)], ['query']),
    'get_withdrawal_status' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(PendingWithdrawal)],
        ['query'],
      ),
    'icrc21_canister_call_consent_message' : IDL.Func(
        [IDL.Text],
        [IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text })],
        ['query'],
      ),
    'initialize_payout_memo_key' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : IDL.Bool, 'Err' : PoolError })],
        [],
      ),
    'is_accepted_spend_root' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Bool],
        ['query'],
      ),
    'is_deposits_paused' : IDL.Func([], [IDL.Bool], ['query']),
    'is_spends_paused' : IDL.Func([], [IDL.Bool], ['query']),
    'list_my_active_deposits' : IDL.Func(
        [IDL.Opt(IDL.Vec(IDL.Nat8)), IDL.Nat64],
        [ActiveDepositsPage],
        ['query'],
      ),
    'list_my_active_spends' : IDL.Func(
        [IDL.Opt(IDL.Nat64), IDL.Nat64],
        [ActiveSpendsPage],
        ['query'],
      ),
    'list_pending_output_promotions' : IDL.Func(
        [],
        [IDL.Vec(PendingPromotionRecord)],
        ['query'],
      ),
    'list_pending_output_promotions_for_controller_update' : IDL.Func(
        [PoolControllerReadRequest],
        [PoolControllerReadResponse],
        [],
      ),
    'payout_memo_key_ready' : IDL.Func([], [IDL.Opt(IDL.Bool)], ['query']),
    'payout_memo_key_ready_for_controller_update' : IDL.Func(
        [],
        [IDL.Opt(IDL.Bool)],
        [],
      ),
    'private_spend' : IDL.Func(
        [PrivateSpendArgs],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : PoolError })],
        [],
      ),
    'prune_terminal_records' : IDL.Func([PruneRequest], [PruneResult], []),
    'reconcile_deposit_append_unknown' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [
          IDL.Variant({
            'Ok' : DepositAppendReconcileResult,
            'Err' : PoolError,
          }),
        ],
        [],
      ),
    'reconcile_deposit_commitment' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : PoolError })],
        [],
      ),
    'reconcile_deposit_transfer_not_executed' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : PoolError })],
        [],
      ),
    'reconcile_nullifier_insert' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : ReconcileNullifierResult, 'Err' : PoolError })],
        [],
      ),
    'reconcile_pending_spend' : IDL.Func(
        [IDL.Nat64],
        [
          IDL.Variant({
            'Ok' : ReconcilePendingSpendResult,
            'Err' : PoolError,
          }),
        ],
        [],
      ),
    'reconcile_private_spend_payout' : IDL.Func(
        [IDL.Nat64, PayoutOutcome],
        [IDL.Variant({ 'Ok' : ReconcilePayoutResult, 'Err' : PoolError })],
        [],
      ),
    'reconcile_treasury_disburse' : IDL.Func(
        [IDL.Nat64, DisburseOutcome],
        [IDL.Variant({ 'Ok' : ReconcileDisburseResult, 'Err' : PoolError })],
        [],
      ),
    'reconcile_withdrawal_ledger_transfer' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
    'reconcile_withdrawal_registry_insert' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
    'resume_blocked_withdrawal' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
    'retry_deposit_commitment' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
    'retry_private_spend_payout' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
    'schedule_vk_activation' : IDL.Func(
        [IDL.Nat32, IDL.Vec(IDL.Nat8), IDL.Nat64, IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'set_fee_flush_window_ns' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'set_governance_fee_params' : IDL.Func(
        [GovernanceFeeParams],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'set_verifier_canister' : IDL.Func(
        [IDL.Principal, IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : PoolError })],
        [],
      ),
    'settle_deposit_transfer' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [
          IDL.Variant({
            'Ok' : DepositSettlementOutcome,
            'Err' : SettlementError,
          }),
        ],
        [],
      ),
    'shield_deposit' : IDL.Func(
        [ShieldDepositArgs],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
    'treasury_disburse' : IDL.Func(
        [TreasuryDisburseArgs],
        [IDL.Variant({ 'Ok' : TreasuryDisburseResult, 'Err' : PoolError })],
        [],
      ),
    'unpause_deposits' : IDL.Func([], [], []),
    'unpause_spends' : IDL.Func([], [], []),
    'withdraw' : IDL.Func(
        [WithdrawArgs],
        [IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : PoolError })],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  return [
    IDL.Record({
      'initial_vk_hash' : IDL.Vec(IDL.Nat8),
      'controller' : IDL.Principal,
      'treasury_canister' : IDL.Principal,
      'verifier_canister' : IDL.Opt(IDL.Principal),
      'token_canister' : IDL.Principal,
      'initial_proof_system' : IDL.Text,
      'staking_canister' : IDL.Principal,
      'nullifier_canister' : IDL.Principal,
      'merkle_canister' : IDL.Principal,
    }),
  ];
};
