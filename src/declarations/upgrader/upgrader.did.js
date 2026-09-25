export const idlFactory = ({ IDL }) => {
  const UpgraderInitArgs = IDL.Record({
    'vault' : IDL.Principal,
    'threshold' : IDL.Nat32,
    'recovery_members' : IDL.Vec(IDL.Principal),
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
  const EvidenceRejection = IDL.Variant({
    'FutureEvidence' : IDL.Null,
    'StatusNotRunning' : IDL.Null,
    'WrongPrincipal' : IDL.Null,
    'AmbiguousIntentId' : IDL.Null,
    'PredatesIntent' : IDL.Null,
    'EvidenceTooOld' : IDL.Null,
    'WrongControllers' : IDL.Null,
  });
  const RecoveryError = IDL.Variant({
    'AlreadyApproved' : IDL.Null,
    'ThresholdViolation' : IDL.Null,
    'AlreadySettled' : IDL.Record({ 'outcome' : ReconcileTerminalOutcome }),
    'IllegalSourceState' : IDL.Null,
    'AlreadyTerminal' : IDL.Null,
    'NotAuthorized' : IDL.Null,
    'ProposalExpired' : IDL.Record({
      'now_ns' : IDL.Nat64,
      'expires_at_ns' : IDL.Nat64,
    }),
    'StaleEpoch' : IDL.Record({
      'proposal' : IDL.Nat64,
      'current' : IDL.Nat64,
    }),
    'CommitmentMismatch' : CommitmentMismatch,
    'HashMismatch' : IDL.Null,
    'GuardRejected' : GuardViolation,
    'NotProposer' : IDL.Null,
    'LifetimeOutOfBounds' : LifetimeViolation,
    'SizeLimitExceeded' : IDL.Record({
      'limit_bytes' : IDL.Nat64,
      'encoded_bytes' : IDL.Nat64,
    }),
    'EvidenceRejected' : EvidenceRejection,
    'UnknownProposal' : IDL.Record({ 'proposal_id' : IDL.Nat64 }),
  });
  const ControllerInvariant = IDL.Record({
    'upgrader_controllers_ok' : IDL.Bool,
    'observed_at_ns' : IDL.Nat64,
    'vault_controllers_ok' : IDL.Bool,
  });
  const InvariantFreshness = IDL.Variant({
    'Stale' : IDL.Null,
    'NeverObserved' : IDL.Null,
    'Fresh' : IDL.Null,
  });
  const ControllerInvariantProof = IDL.Record({
    'upgrader_controllers_ok' : IDL.Bool,
    'freshness' : InvariantFreshness,
    'observed_at_ns' : IDL.Nat64,
    'age_ns' : IDL.Opt(IDL.Nat64),
    'max_age_ns' : IDL.Nat64,
    'vault_controllers_ok' : IDL.Bool,
    'current_proof_ok' : IDL.Bool,
  });
  const ObservedCanisterStatus = IDL.Variant({
    'Stopped' : IDL.Null,
    'Stopping' : IDL.Null,
    'Running' : IDL.Null,
  });
  const StartObjectiveEvidence = IDL.Record({
    'observed_controllers' : IDL.Vec(IDL.Principal),
    'observed_at_ns' : IDL.Nat64,
    'observed_target_principal' : IDL.Principal,
    'observed_canister_status' : ObservedCanisterStatus,
  });
  const UpgradeObjectiveEvidence = IDL.Record({
    'observed_controllers' : IDL.Vec(IDL.Principal),
    'observed_at_ns' : IDL.Nat64,
    'observed_upgrader_principal' : IDL.Principal,
    'observed_module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'observed_canister_status' : ObservedCanisterStatus,
  });
  const RecoveryAction = IDL.Variant({
    'ReconcileVaultStart' : IDL.Record({
      'objective_evidence' : StartObjectiveEvidence,
      'proposal_id' : IDL.Nat64,
    }),
    'ReconcileVaultUpgrade' : IDL.Record({
      'objective_evidence' : UpgradeObjectiveEvidence,
      'proposal_id' : IDL.Nat64,
    }),
    'StartVault' : IDL.Null,
    'TriggerVaultUpgrade' : IDL.Record({
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
      'wasm_bytes' : IDL.Vec(IDL.Nat8),
      'arg_bytes' : IDL.Vec(IDL.Nat8),
    }),
  });
  const StartIntent = IDL.Record({
    'intent_at_ns' : IDL.Nat64,
    'epoch' : IDL.Nat64,
    'target' : IDL.Principal,
    'proposal_id' : IDL.Nat64,
  });
  const SettlementRecord = IDL.Record({
    'evidence_commitment' : IDL.Vec(IDL.Nat8),
    'observed_at_ns' : IDL.Nat64,
    'semantic_key' : IDL.Vec(IDL.Nat8),
    'outcome' : ReconcileTerminalOutcome,
    'conflict_recorded' : IDL.Bool,
  });
  const StartSettlementState = IDL.Record({
    'intent' : StartIntent,
    'settlement' : IDL.Opt(SettlementRecord),
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
  const RecoveryProposal = IDL.Record({
    'action' : RecoveryAction,
    'threshold' : IDL.Nat32,
    'commitment_hash' : IDL.Vec(IDL.Nat8),
    'created_at_ns' : IDL.Nat64,
    'start' : IDL.Opt(StartSettlementState),
    'proposal_id' : IDL.Nat64,
    'proposer' : IDL.Principal,
    'outcome' : ActionOutcome,
    'expires_at_ns' : IDL.Opt(IDL.Nat64),
    'approvals' : IDL.Vec(IDL.Principal),
  });
  const RecoverySummary = IDL.Record({
    'threshold' : IDL.Nat32,
    'member_count' : IDL.Nat32,
  });
  const RotationProposalView = IDL.Record({
    'threshold' : IDL.Nat32,
    'commitment_hash' : IDL.Vec(IDL.Nat8),
    'epoch' : IDL.Nat64,
    'created_at_ns' : IDL.Nat64,
    'new_members' : IDL.Vec(IDL.Principal),
    'proposal_id' : IDL.Nat64,
    'proposer' : IDL.Principal,
    'outcome' : ActionOutcome,
    'expires_at_ns' : IDL.Opt(IDL.Nat64),
    'approvals' : IDL.Vec(IDL.Principal),
  });
  const IntentOriginView = IDL.Variant({
    'Recovery' : IDL.Null,
    'Vault' : IDL.Null,
  });
  const UpgradeStatusView = IDL.Record({
    'id' : IDL.Nat64,
    'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
    'origin' : IntentOriginView,
    'expected_arg_hash' : IDL.Vec(IDL.Nat8),
    'artifact_bytes_held' : IDL.Bool,
    'created_at_ns' : IDL.Nat64,
    'terminal_at_ns' : IDL.Opt(IDL.Nat64),
    'outcome' : ActionOutcome,
  });
  const RecoveryActionTag = IDL.Variant({
    'ReconcileVaultStart' : IDL.Null,
    'ReconcileVaultUpgrade' : IDL.Null,
    'StartVault' : IDL.Null,
    'TriggerVaultUpgrade' : IDL.Null,
  });
  const ReconcileAuthorityView = IDL.Variant({
    'Recovery' : IDL.Record({ 'approvers' : IDL.Vec(IDL.Principal) }),
    'Vault' : IDL.Null,
  });
  const InitValidationError = IDL.Variant({
    'DuplicatePrincipal' : IDL.Null,
    'CounterpartAnonymous' : IDL.Null,
    'TooFewMembers' : IDL.Record({
      'threshold' : IDL.Nat32,
      'distinct' : IDL.Nat64,
    }),
    'ThresholdNotExactlyInitial' : IDL.Record({ 'found' : IDL.Nat32 }),
    'CounterpartIsSigner' : IDL.Null,
    'TooManyMembers' : IDL.Record({
      'distinct' : IDL.Nat64,
      'maximum' : IDL.Nat32,
    }),
    'AnonymousSigner' : IDL.Null,
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
  const UpgraderAuditEventKind = IDL.Variant({
    'MembershipRotated' : IDL.Record({
      'proposal_id' : IDL.Nat64,
      'member_count' : IDL.Nat32,
      'approvers' : IDL.Vec(IDL.Principal),
      'new_epoch' : IDL.Nat64,
    }),
    'ControllerInvariantObserved' : IDL.Record({
      'upgrader_controllers_ok' : IDL.Bool,
      'vault_controllers_ok' : IDL.Bool,
    }),
    'LateCallbackFenced' : IDL.Record({
      'proposal_id' : IDL.Nat64,
      'observed_state' : ActionOutcome,
    }),
    'VaultUpgradeIntentRecorded' : IDL.Record({
      'id' : IDL.Nat64,
      'expected_wasm_hash' : IDL.Vec(IDL.Nat8),
      'origin' : IntentOriginView,
      'expected_arg_hash' : IDL.Vec(IDL.Nat8),
    }),
    'RecoveryProposalCreated' : IDL.Record({
      'action' : RecoveryActionTag,
      'proposal_id' : IDL.Nat64,
      'proposer' : IDL.Principal,
    }),
    'RecoveryApprovalRecorded' : IDL.Record({
      'approver' : IDL.Principal,
      'proposal_id' : IDL.Nat64,
    }),
    'VaultUpgradeOutcomeUnknown' : IDL.Record({
      'id' : IDL.Nat64,
      'origin' : IntentOriginView,
      'reject_detail' : IDL.Text,
    }),
    'StaleProposalTerminalized' : IDL.Record({
      'epoch' : IDL.Nat64,
      'proposal_id' : IDL.Nat64,
    }),
    'VaultUpgradeReconcileRejected' : IDL.Record({
      'id' : IDL.Nat64,
      'authority' : ReconcileAuthorityView,
      'reason' : EvidenceRejection,
    }),
    'VaultUpgradeReconciled' : IDL.Record({
      'id' : IDL.Nat64,
      'origin' : IntentOriginView,
      'authority' : ReconcileAuthorityView,
      'outcome' : ReconcileTerminalOutcome,
    }),
    'VaultStartSweptToUnknown' : IDL.Record({ 'proposal_id' : IDL.Nat64 }),
    'RecoveryProposalTerminal' : IDL.Record({
      'proposal_id' : IDL.Nat64,
      'outcome' : ActionOutcome,
    }),
    'RecoveryExecutionStarted' : IDL.Record({ 'proposal_id' : IDL.Nat64 }),
    'VaultStartIntentRecorded' : IDL.Record({
      'epoch' : IDL.Nat64,
      'target' : IDL.Principal,
      'proposal_id' : IDL.Nat64,
    }),
    'VaultStartSettled' : IDL.Record({
      'proposal_id' : IDL.Nat64,
      'authority' : ReconcileAuthorityView,
      'outcome' : ReconcileTerminalOutcome,
    }),
    'MembershipRotationRejected' : IDL.Record({
      'proposer' : IDL.Principal,
      'reason' : InitValidationError,
    }),
    'MembershipRotationProposed' : IDL.Record({
      'proposal_id' : IDL.Nat64,
      'proposer' : IDL.Principal,
      'member_count' : IDL.Nat32,
    }),
    'StaleIntentTerminalized' : IDL.Record({
      'epoch' : IDL.Nat64,
      'proposal_id' : IDL.Nat64,
      'intent_id' : IDL.Nat64,
    }),
    'SettlementEvidenceConflictRecorded' : IDL.Record({
      'conflict' : SettlementEvidenceConflict,
    }),
    'VaultStartOutcomeUnknown' : IDL.Record({
      'reject_detail' : IDL.Text,
      'proposal_id' : IDL.Nat64,
    }),
    'VaultStartExecuted' : IDL.Record({ 'proposal_id' : IDL.Nat64 }),
    'VaultUpgradeExecuted' : IDL.Record({
      'id' : IDL.Nat64,
      'origin' : IntentOriginView,
    }),
    'RecoveryBootstrapped' : IDL.Record({
      'vault' : IDL.Principal,
      'threshold' : IDL.Nat32,
      'member_count' : IDL.Nat32,
    }),
  });
  const UpgraderAuditEvent = IDL.Record({
    'seq' : IDL.Nat64,
    'at_ns' : IDL.Nat64,
    'kind' : UpgraderAuditEventKind,
  });
  const AuditEventsPage = IDL.Record({
    'events' : IDL.Vec(UpgraderAuditEvent),
    'next_cursor' : IDL.Opt(IDL.Nat64),
  });
  const InvariantRefreshRefusal = IDL.Variant({
    'TooSoon' : IDL.Record({ 'retry_after_ns' : IDL.Nat64 }),
    'AlreadyInFlight' : IDL.Null,
    'NotRuled' : IDL.Null,
    'NotStale' : IDL.Record({ 'age_ns' : IDL.Nat64 }),
  });
  const TriggerUpgradeResult = IDL.Record({ 'outcome' : ActionOutcome });
  return IDL.Service({
    'approve_recovery' : IDL.Func(
        [IDL.Nat64, IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : RecoveryError })],
        [],
      ),
    'cancel_recovery_proposal' : IDL.Func(
        [IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : RecoveryError })],
        [],
      ),
    'get_build_info' : IDL.Func([], [IDL.Text], ['query']),
    'get_controller_invariant' : IDL.Func([], [ControllerInvariant], ['query']),
    'get_controller_invariant_proof' : IDL.Func(
        [],
        [ControllerInvariantProof],
        ['query'],
      ),
    'get_recovery_membership' : IDL.Func(
        [],
        [IDL.Opt(IDL.Vec(IDL.Principal))],
        ['query'],
      ),
    'get_recovery_proposal' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(RecoveryProposal)],
        ['query'],
      ),
    'get_recovery_summary' : IDL.Func([], [RecoverySummary], ['query']),
    'get_rotation_proposal' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(RotationProposalView)],
        ['query'],
      ),
    'get_upgrade_status' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(UpgradeStatusView)],
        ['query'],
      ),
    'get_upgrader_audit_events' : IDL.Func(
        [IDL.Opt(IDL.Nat64), IDL.Nat32],
        [IDL.Opt(AuditEventsPage)],
        ['query'],
      ),
    'propose_membership_rotation' : IDL.Func(
        [IDL.Vec(IDL.Principal), IDL.Opt(IDL.Nat64)],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : RecoveryError })],
        [],
      ),
    'propose_recovery' : IDL.Func(
        [RecoveryAction, IDL.Opt(IDL.Nat64)],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : RecoveryError })],
        [],
      ),
    'reconcile_vault_upgrade' : IDL.Func(
        [IDL.Nat64, UpgradeObjectiveEvidence],
        [
          IDL.Variant({
            'Ok' : ReconcileTerminalOutcome,
            'Err' : RecoveryError,
          }),
        ],
        [],
      ),
    'refresh_controller_invariant_now' : IDL.Func(
        [],
        [
          IDL.Variant({
            'Ok' : ControllerInvariant,
            'Err' : InvariantRefreshRefusal,
          }),
        ],
        [],
      ),
    'sweep_expired_recovery_proposals' : IDL.Func(
        [IDL.Nat32],
        [IDL.Variant({ 'Ok' : IDL.Vec(IDL.Nat64), 'Err' : RecoveryError })],
        [],
      ),
    'trigger_vault_upgrade' : IDL.Func(
        [
          IDL.Nat64,
          IDL.Vec(IDL.Nat8),
          IDL.Vec(IDL.Nat8),
          IDL.Vec(IDL.Nat8),
          IDL.Vec(IDL.Nat8),
        ],
        [IDL.Variant({ 'Ok' : TriggerUpgradeResult, 'Err' : RecoveryError })],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  const UpgraderInitArgs = IDL.Record({
    'vault' : IDL.Principal,
    'threshold' : IDL.Nat32,
    'recovery_members' : IDL.Vec(IDL.Principal),
  });
  return [UpgraderInitArgs];
};
