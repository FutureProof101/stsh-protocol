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
export interface AuditEventsPage {
  'events' : Array<UpgraderAuditEvent>,
  'next_cursor' : [] | [bigint],
}
export type CommitmentMismatch = { 'StoredVsRecomputed' : null } |
  { 'CallerMismatch' : null };
export interface ControllerInvariant {
  'upgrader_controllers_ok' : boolean,
  'observed_at_ns' : bigint,
  'vault_controllers_ok' : boolean,
}
export interface ControllerInvariantProof {
  'upgrader_controllers_ok' : boolean,
  'freshness' : InvariantFreshness,
  'observed_at_ns' : bigint,
  'age_ns' : [] | [bigint],
  'max_age_ns' : bigint,
  'vault_controllers_ok' : boolean,
  'current_proof_ok' : boolean,
}
export type EvidenceRejection = { 'FutureEvidence' : null } |
  { 'StatusNotRunning' : null } |
  { 'WrongPrincipal' : null } |
  { 'AmbiguousIntentId' : null } |
  { 'PredatesIntent' : null } |
  { 'EvidenceTooOld' : null } |
  { 'WrongControllers' : null };
export type GuardTarget = { 'Upgrader' : null } |
  { 'Vault' : null };
export type GuardViolation = { 'StopForbidden' : { 'target' : GuardTarget } } |
  { 'ControllerInvariantBroken' : { 'target' : GuardTarget } };
export type InitValidationError = { 'DuplicatePrincipal' : null } |
  { 'CounterpartAnonymous' : null } |
  { 'TooFewMembers' : { 'threshold' : number, 'distinct' : bigint } } |
  { 'ThresholdNotExactlyInitial' : { 'found' : number } } |
  { 'CounterpartIsSigner' : null } |
  { 'TooManyMembers' : { 'distinct' : bigint, 'maximum' : number } } |
  { 'AnonymousSigner' : null };
export type IntentOriginView = { 'Recovery' : null } |
  { 'Vault' : null };
export type InvariantFreshness = { 'Stale' : null } |
  { 'NeverObserved' : null } |
  { 'Fresh' : null };
export type InvariantRefreshRefusal = {
    'TooSoon' : { 'retry_after_ns' : bigint }
  } |
  { 'AlreadyInFlight' : null } |
  { 'NotRuled' : null } |
  { 'NotStale' : { 'age_ns' : bigint } };
export type LifetimeViolation = {
    'BoundsNotRuled' : { 'requested_ns' : bigint }
  } |
  { 'TooLong' : { 'requested_ns' : bigint, 'max_ns' : bigint } } |
  { 'TooShort' : { 'min_ns' : bigint, 'requested_ns' : bigint } };
export type ObservedCanisterStatus = { 'Stopped' : null } |
  { 'Stopping' : null } |
  { 'Running' : null };
export type ReconcileAuthorityView = {
    'Recovery' : { 'approvers' : Array<Principal> }
  } |
  { 'Vault' : null };
export type ReconcileTerminalOutcome = { 'Failed' : null } |
  { 'Executed' : null };
export type RecoveryAction = {
    'ReconcileVaultStart' : {
      'objective_evidence' : StartObjectiveEvidence,
      'proposal_id' : bigint,
    }
  } |
  {
    'ReconcileVaultUpgrade' : {
      'objective_evidence' : UpgradeObjectiveEvidence,
      'proposal_id' : bigint,
    }
  } |
  { 'StartVault' : null } |
  {
    'TriggerVaultUpgrade' : {
      'expected_wasm_hash' : Uint8Array | number[],
      'expected_arg_hash' : Uint8Array | number[],
      'wasm_bytes' : Uint8Array | number[],
      'arg_bytes' : Uint8Array | number[],
    }
  };
export type RecoveryActionTag = { 'ReconcileVaultStart' : null } |
  { 'ReconcileVaultUpgrade' : null } |
  { 'StartVault' : null } |
  { 'TriggerVaultUpgrade' : null };
export type RecoveryError = { 'AlreadyApproved' : null } |
  { 'ThresholdViolation' : null } |
  { 'AlreadySettled' : { 'outcome' : ReconcileTerminalOutcome } } |
  { 'IllegalSourceState' : null } |
  { 'AlreadyTerminal' : null } |
  { 'NotAuthorized' : null } |
  { 'ProposalExpired' : { 'now_ns' : bigint, 'expires_at_ns' : bigint } } |
  { 'StaleEpoch' : { 'proposal' : bigint, 'current' : bigint } } |
  { 'CommitmentMismatch' : CommitmentMismatch } |
  { 'HashMismatch' : null } |
  { 'GuardRejected' : GuardViolation } |
  { 'NotProposer' : null } |
  { 'LifetimeOutOfBounds' : LifetimeViolation } |
  {
    'SizeLimitExceeded' : { 'limit_bytes' : bigint, 'encoded_bytes' : bigint }
  } |
  { 'EvidenceRejected' : EvidenceRejection } |
  { 'UnknownProposal' : { 'proposal_id' : bigint } };
export interface RecoveryProposal {
  'action' : RecoveryAction,
  'threshold' : number,
  'commitment_hash' : Uint8Array | number[],
  'created_at_ns' : bigint,
  'start' : [] | [StartSettlementState],
  'proposal_id' : bigint,
  'proposer' : Principal,
  'outcome' : ActionOutcome,
  'expires_at_ns' : [] | [bigint],
  'approvals' : Array<Principal>,
}
export interface RecoverySummary {
  'threshold' : number,
  'member_count' : number,
}
export interface RotationProposalView {
  'threshold' : number,
  'commitment_hash' : Uint8Array | number[],
  'epoch' : bigint,
  'created_at_ns' : bigint,
  'new_members' : Array<Principal>,
  'proposal_id' : bigint,
  'proposer' : Principal,
  'outcome' : ActionOutcome,
  'expires_at_ns' : [] | [bigint],
  'approvals' : Array<Principal>,
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
export interface SettlementRecord {
  'evidence_commitment' : Uint8Array | number[],
  'observed_at_ns' : bigint,
  'semantic_key' : Uint8Array | number[],
  'outcome' : ReconcileTerminalOutcome,
  'conflict_recorded' : boolean,
}
export interface StartIntent {
  'intent_at_ns' : bigint,
  'epoch' : bigint,
  'target' : Principal,
  'proposal_id' : bigint,
}
export interface StartObjectiveEvidence {
  'observed_controllers' : Array<Principal>,
  'observed_at_ns' : bigint,
  'observed_target_principal' : Principal,
  'observed_canister_status' : ObservedCanisterStatus,
}
export interface StartSettlementState {
  'intent' : StartIntent,
  'settlement' : [] | [SettlementRecord],
}
export interface TriggerUpgradeResult { 'outcome' : ActionOutcome }
export interface UpgradeObjectiveEvidence {
  'observed_controllers' : Array<Principal>,
  'observed_at_ns' : bigint,
  'observed_upgrader_principal' : Principal,
  'observed_module_hash' : [] | [Uint8Array | number[]],
  'observed_canister_status' : ObservedCanisterStatus,
}
export interface UpgradeStatusView {
  'id' : bigint,
  'expected_wasm_hash' : Uint8Array | number[],
  'origin' : IntentOriginView,
  'expected_arg_hash' : Uint8Array | number[],
  'artifact_bytes_held' : boolean,
  'created_at_ns' : bigint,
  'terminal_at_ns' : [] | [bigint],
  'outcome' : ActionOutcome,
}
export interface UpgraderAuditEvent {
  'seq' : bigint,
  'at_ns' : bigint,
  'kind' : UpgraderAuditEventKind,
}
export type UpgraderAuditEventKind = {
    'MembershipRotated' : {
      'proposal_id' : bigint,
      'member_count' : number,
      'approvers' : Array<Principal>,
      'new_epoch' : bigint,
    }
  } |
  {
    'ControllerInvariantObserved' : {
      'upgrader_controllers_ok' : boolean,
      'vault_controllers_ok' : boolean,
    }
  } |
  {
    'LateCallbackFenced' : {
      'proposal_id' : bigint,
      'observed_state' : ActionOutcome,
    }
  } |
  {
    'VaultUpgradeIntentRecorded' : {
      'id' : bigint,
      'expected_wasm_hash' : Uint8Array | number[],
      'origin' : IntentOriginView,
      'expected_arg_hash' : Uint8Array | number[],
    }
  } |
  {
    'RecoveryProposalCreated' : {
      'action' : RecoveryActionTag,
      'proposal_id' : bigint,
      'proposer' : Principal,
    }
  } |
  {
    'RecoveryApprovalRecorded' : {
      'approver' : Principal,
      'proposal_id' : bigint,
    }
  } |
  {
    'VaultUpgradeOutcomeUnknown' : {
      'id' : bigint,
      'origin' : IntentOriginView,
      'reject_detail' : string,
    }
  } |
  {
    'StaleProposalTerminalized' : { 'epoch' : bigint, 'proposal_id' : bigint }
  } |
  {
    'VaultUpgradeReconcileRejected' : {
      'id' : bigint,
      'authority' : ReconcileAuthorityView,
      'reason' : EvidenceRejection,
    }
  } |
  {
    'VaultUpgradeReconciled' : {
      'id' : bigint,
      'origin' : IntentOriginView,
      'authority' : ReconcileAuthorityView,
      'outcome' : ReconcileTerminalOutcome,
    }
  } |
  { 'VaultStartSweptToUnknown' : { 'proposal_id' : bigint } } |
  {
    'RecoveryProposalTerminal' : {
      'proposal_id' : bigint,
      'outcome' : ActionOutcome,
    }
  } |
  { 'RecoveryExecutionStarted' : { 'proposal_id' : bigint } } |
  {
    'VaultStartIntentRecorded' : {
      'epoch' : bigint,
      'target' : Principal,
      'proposal_id' : bigint,
    }
  } |
  {
    'VaultStartSettled' : {
      'proposal_id' : bigint,
      'authority' : ReconcileAuthorityView,
      'outcome' : ReconcileTerminalOutcome,
    }
  } |
  {
    'MembershipRotationRejected' : {
      'proposer' : Principal,
      'reason' : InitValidationError,
    }
  } |
  {
    'MembershipRotationProposed' : {
      'proposal_id' : bigint,
      'proposer' : Principal,
      'member_count' : number,
    }
  } |
  {
    'StaleIntentTerminalized' : {
      'epoch' : bigint,
      'proposal_id' : bigint,
      'intent_id' : bigint,
    }
  } |
  {
    'SettlementEvidenceConflictRecorded' : {
      'conflict' : SettlementEvidenceConflict,
    }
  } |
  {
    'VaultStartOutcomeUnknown' : {
      'reject_detail' : string,
      'proposal_id' : bigint,
    }
  } |
  { 'VaultStartExecuted' : { 'proposal_id' : bigint } } |
  { 'VaultUpgradeExecuted' : { 'id' : bigint, 'origin' : IntentOriginView } } |
  {
    'RecoveryBootstrapped' : {
      'vault' : Principal,
      'threshold' : number,
      'member_count' : number,
    }
  };
export interface UpgraderInitArgs {
  'vault' : Principal,
  'threshold' : number,
  'recovery_members' : Array<Principal>,
}
export interface _SERVICE {
  'approve_recovery' : ActorMethod<
    [bigint, Uint8Array | number[]],
    { 'Ok' : null } |
      { 'Err' : RecoveryError }
  >,
  'cancel_recovery_proposal' : ActorMethod<
    [bigint],
    { 'Ok' : null } |
      { 'Err' : RecoveryError }
  >,
  'get_build_info' : ActorMethod<[], string>,
  'get_controller_invariant' : ActorMethod<[], ControllerInvariant>,
  'get_controller_invariant_proof' : ActorMethod<[], ControllerInvariantProof>,
  'get_recovery_membership' : ActorMethod<[], [] | [Array<Principal>]>,
  'get_recovery_proposal' : ActorMethod<[bigint], [] | [RecoveryProposal]>,
  'get_recovery_summary' : ActorMethod<[], RecoverySummary>,
  'get_rotation_proposal' : ActorMethod<[bigint], [] | [RotationProposalView]>,
  'get_upgrade_status' : ActorMethod<[bigint], [] | [UpgradeStatusView]>,
  'get_upgrader_audit_events' : ActorMethod<
    [[] | [bigint], number],
    [] | [AuditEventsPage]
  >,
  'propose_membership_rotation' : ActorMethod<
    [Array<Principal>, [] | [bigint]],
    { 'Ok' : bigint } |
      { 'Err' : RecoveryError }
  >,
  'propose_recovery' : ActorMethod<
    [RecoveryAction, [] | [bigint]],
    { 'Ok' : bigint } |
      { 'Err' : RecoveryError }
  >,
  'reconcile_vault_upgrade' : ActorMethod<
    [bigint, UpgradeObjectiveEvidence],
    { 'Ok' : ReconcileTerminalOutcome } |
      { 'Err' : RecoveryError }
  >,
  'refresh_controller_invariant_now' : ActorMethod<
    [],
    { 'Ok' : ControllerInvariant } |
      { 'Err' : InvariantRefreshRefusal }
  >,
  'sweep_expired_recovery_proposals' : ActorMethod<
    [number],
    { 'Ok' : BigUint64Array | bigint[] } |
      { 'Err' : RecoveryError }
  >,
  'trigger_vault_upgrade' : ActorMethod<
    [
      bigint,
      Uint8Array | number[],
      Uint8Array | number[],
      Uint8Array | number[],
      Uint8Array | number[],
    ],
    { 'Ok' : TriggerUpgradeResult } |
      { 'Err' : RecoveryError }
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
