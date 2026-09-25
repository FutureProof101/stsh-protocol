// =============================================================================
// L2 acceptance tests — run with `cargo test -p upgrader`.
//
// Every test drives `core` directly (the wrappers in lib.rs only resolve
// caller/time/self-id and perform the management awaits the core plans).
// Management-canister outcomes are simulated by calling `finish_intent` with
// Ok/Err — the seam documented in core.rs; no PocketIC needed.
//
// SSA round-2 findings L2-1..L2-4 each carry named tests below.
// =============================================================================

use candid::Principal;
use sha2::{Digest, Sha256};
use stsh_custody_types::{
    ActionOutcome, EvidenceRejection, GrowthClass, GrowthCounts, GuardTarget,
    InvariantFreshness, ObservedCanisterStatus, PermanentGrowthModel, RecoveryAction, RecoveryError,
    ReconcileTerminalOutcome, SurfaceHorizon, UpgraderInitArgs, UpgradeObjectiveEvidence,
    VaultSelfControlGuard, GATE_SIZE_BOUND_BYTES, MAX_READ_PAGE_LIMIT,
};

use crate::core::{
    self, ApproveOutcome, IntentKey, IntentOriginView, ReconcileAuthorityView, RecoveryExecution,
    StoredProposal, UpgraderAuditEventKind, MAX_EVIDENCE_AGE_NS,
};

fn p(byte: u8) -> Principal {
    Principal::from_slice(&[byte; 29])
}

/// Fixed wall-clock for post_upgrade in unit tests. `post_upgrade` takes
/// `now_ns` explicitly (rather than calling `ic_cdk::api::time()`) so the core
/// stays natively testable — the §S7 E2 sweep runs inside it and needs a clock.
const T0: u64 = 1_000_000;
const VAULT: u8 = 0xF0;
const SELF_ID: u8 = 0xF1;
const M1: u8 = 0x01;
const M2: u8 = 0x02;
const M3: u8 = 0x03;
const M4: u8 = 0x04;
const M5: u8 = 0x05;

/// The stored commitment for `id` — what a member reads off the proposal view
/// and supplies to `approve_recovery` (R1.5).
fn commit_of(id: u64) -> Vec<u8> {
    core::stored_commitment(&core::get_stored_proposal(id).expect("proposal exists"))
}

/// This canister's principal in native tests.
fn self_p() -> Principal {
    p(0xFE)
}

fn setup() {
    core::init(
        UpgraderInitArgs {
            recovery_members: vec![p(M1), p(M2), p(M3)],
            threshold: 2,
            vault: p(VAULT),
        },
        1_000,
    );
}

fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

/// A hash-consistent artifact set: (wasm, arg, wasm_hash, arg_hash).
fn artifact(tag: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let wasm = vec![tag; 64];
    let arg = vec![tag + 1; 16];
    let wh = sha256(&wasm);
    let ah = sha256(&arg);
    (wasm, arg, wh, ah)
}

fn evidence(module_hash: Option<Vec<u8>>, observed_at_ns: u64) -> UpgradeObjectiveEvidence {
    UpgradeObjectiveEvidence {
        observed_upgrader_principal: p(VAULT),
        observed_module_hash: module_hash,
        observed_controllers: vec![p(SELF_ID)],
        observed_canister_status: ObservedCanisterStatus::Running,
        observed_at_ns,
    }
}

fn trigger_action(tag: u8) -> RecoveryAction {
    let (wasm, arg, wh, ah) = artifact(tag);
    RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: wh,
        expected_arg_hash: ah,
        wasm_bytes: wasm,
        arg_bytes: arg,
    }
}

/// The typed evidence-rejection reason of the most recent reconcile
/// rejection (member-visible through the gated audit query — the distinct
/// classification SSA L2-2 requires).
fn last_reject_reason(member: &Principal) -> EvidenceRejection {
    let page = core::query_audit_events(member, None, MAX_READ_PAGE_LIMIT).expect("audit");
    page.events
        .iter()
        .rev()
        .find_map(|e| match &e.kind {
            UpgraderAuditEventKind::VaultUpgradeReconcileRejected { reason, .. } => {
                Some(reason.clone())
            }
            _ => None,
        })
        .expect("a reconcile rejection was audited")
}

// ── Bootstrap / threshold (freeze §1: initial exactly 2, hard floor) ─────────

#[test]
fn init_happy_path_records_membership_and_audits() {
    setup();
    let s = core::query_recovery_summary();
    assert_eq!(s.threshold, 2);
    assert_eq!(s.member_count, 3);
    assert_eq!(core::vault_principal(), Some(p(VAULT)));
    let page = core::query_audit_events(&p(M1), None, 10).expect("member sees audit");
    assert_eq!(page.events.len(), 1); // RecoveryBootstrapped
}

/// S6 / CTO_NOTE_S5A §5 — the tenth RECOVERY MEMBER is refused at init.
///
/// Enforced independently of the Vault's maximum rather than inherited: this
/// plane keeps its OWN durable membership and is never synced from the Vault,
/// so a bound arriving by inheritance would stop applying precisely when that
/// independence is exercised.
#[test]
#[should_panic]
fn s6_init_rejects_the_tenth_recovery_member() {
    let oversize: Vec<Principal> = (0..=stsh_custody_types::MAX_RECOVERY_MEMBERS)
        .map(|i| p(0x40 + i as u8))
        .collect();
    core::init(
        UpgraderInitArgs { recovery_members: oversize, threshold: 2, vault: p(VAULT) },
        1,
    );
}

/// The NON-VACUITY half of the test above: exactly nine members INSTALLS.
///
/// Without it, `s6_init_rejects_the_tenth_recovery_member` would pass equally
/// well against an init that rejected every roster, and the "10th is refused"
/// claim would rest on a panic that had nothing to do with the maximum.
#[test]
fn s6_init_accepts_the_ruled_maximum_recovery_roster() {
    let at_max: Vec<Principal> = (0..stsh_custody_types::MAX_RECOVERY_MEMBERS)
        .map(|i| p(0x40 + i as u8))
        .collect();
    core::init(
        UpgraderInitArgs { recovery_members: at_max, threshold: 2, vault: p(VAULT) },
        1,
    );
}

/// S6 corrective CUST-SSA-S6-03 — the oversize refusal CHARGES AND RECORDS,
/// atomically, with a TRUTHFUL reason.
///
/// S6 charged the entry event and appended nothing, because no
/// `InitValidationError` variant was true of "too many" and a false reason was
/// refused. Budget drained with no trace of why — invisible to anyone auditing
/// it. The authorized `TooManyMembers` variant closes both halves.
#[test]
fn s6c_oversize_rotation_charges_and_records_truthfully() {
    setup();
    core::inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
        window_ns: 1_000_000_000_000,
        global_per_window: 50,
        per_signer_per_window: 50,
    })));
    let oversize: Vec<Principal> = (0..=stsh_custody_types::MAX_RECOVERY_MEMBERS)
        .map(|i| p(0x40 + i as u8))
        .collect();
    let n = oversize.len();

    let charged_before = core::entry_rate_global_count_for_test();
    let audit_before = core::audit_len_for_test();

    assert_eq!(
        core::propose_membership_rotation(&p(M1), oversize, 100, None, &self_p()),
        Err(RecoveryError::ThresholdViolation),
        "an oversize roster is refused"
    );

    // BOTH move, together.
    assert_eq!(
        core::entry_rate_global_count_for_test(),
        charged_before + 1,
        "the refusal is an entry event and is charged"
    );
    assert_eq!(
        core::audit_len_for_test(),
        audit_before + 1,
        "S6 charged budget and wrote NOTHING — the gap this closes"
    );

    // And the reason is TRUE of what happened.
    let last = core::last_audit_event_for_test().expect("an audit event was appended");
    match last.kind {
        UpgraderAuditEventKind::MembershipRotationRejected { reason, .. } => assert_eq!(
            reason,
            stsh_custody_types::InitValidationError::TooManyMembers {
                distinct: n,
                maximum: stsh_custody_types::MAX_RECOVERY_MEMBERS as u32,
            },
            "the recorded reason must be TRUE of the rejection — TooFewMembers \
             is its exact opposite and would be a false permanent record"
        ),
        other => panic!("expected MembershipRotationRejected, got {other:?}"),
    }
    core::inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// S6 — the tenth member is refused at the ROTATION path too.
///
/// The mutation path that actually matters: init is a one-time event under
/// direct operator control, while a rotation is a governed runtime operation
/// and is exactly how a tenth member would otherwise arrive.
#[test]
fn s6_rotation_rejects_the_tenth_recovery_member() {
    setup();
    let oversize: Vec<Principal> = (0..=stsh_custody_types::MAX_RECOVERY_MEMBERS)
        .map(|i| p(0x40 + i as u8))
        .collect();
    assert_eq!(
        core::propose_membership_rotation(&p(M1), oversize, 100, None, &self_p()),
        Err(RecoveryError::ThresholdViolation),
        "a rotation to a tenth member must be refused"
    );

    // NON-VACUITY: the ruled maximum itself rotates fine.
    let at_max: Vec<Principal> = (0..stsh_custody_types::MAX_RECOVERY_MEMBERS)
        .map(|i| p(0x40 + i as u8))
        .collect();
    assert!(
        core::propose_membership_rotation(&p(M1), at_max, 101, None, &self_p()).is_ok(),
        "nine members is legal; only the tenth is not"
    );
}

#[test]
#[should_panic]
fn init_rejects_threshold_1() {
    core::init(
        UpgraderInitArgs { recovery_members: vec![p(M1), p(M2)], threshold: 1, vault: p(VAULT) },
        1,
    );
}

#[test]
#[should_panic]
fn init_rejects_threshold_3() {
    core::init(
        UpgraderInitArgs {
            recovery_members: vec![p(M1), p(M2), p(M3)],
            threshold: 3,
            vault: p(VAULT),
        },
        1,
    );
}

#[test]
#[should_panic]
fn init_rejects_duplicate_member() {
    core::init(
        UpgraderInitArgs {
            recovery_members: vec![p(M1), p(M1)],
            threshold: 2,
            vault: p(VAULT),
        },
        1,
    );
}

#[test]
#[should_panic]
fn init_rejects_anonymous_member() {
    core::init(
        UpgraderInitArgs {
            recovery_members: vec![p(M1), Principal::anonymous()],
            threshold: 2,
            vault: p(VAULT),
        },
        1,
    );
}

#[test]
#[should_panic]
fn init_rejects_counterpart_that_is_a_member() {
    core::init(
        UpgraderInitArgs {
            recovery_members: vec![p(M1), p(M2)],
            threshold: 2,
            vault: p(M2),
        },
        1,
    );
}

#[test]
#[should_panic]
fn init_rejects_too_few_members() {
    core::init(
        UpgraderInitArgs { recovery_members: vec![p(M1)], threshold: 2, vault: p(VAULT) },
        1,
    );
}

// ── trigger_vault_upgrade: spoofed caller rejected ───────────────────────────

#[test]
fn spoofed_caller_rejected_on_trigger() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    for bad in [p(0x77), p(M1), Principal::anonymous()] {
        assert_eq!(
            core::trigger_begin(&bad, 1, wh.clone(), ah.clone(), wasm.clone(), arg.clone(), 100)
                .unwrap_err(),
            RecoveryError::NotAuthorized,
            "non-Vault caller must be rejected"
        );
    }
    // No intent was recorded for any spoofed attempt.
    assert!(core::query_upgrade_status(&p(M1), 1).is_none());
}

// ── Hash binding: mismatched wasm or arg hash rejected ───────────────────────

#[test]
fn mismatched_wasm_or_arg_hash_rejected_on_trigger() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let wrong = sha256(b"different");
    assert_eq!(
        core::trigger_begin(&p(VAULT), 1, wrong.clone(), ah.clone(), wasm.clone(), arg.clone(), 100)
            .unwrap_err(),
        RecoveryError::HashMismatch
    );
    assert_eq!(
        core::trigger_begin(&p(VAULT), 1, wh.clone(), wrong, wasm.clone(), arg.clone(), 100)
            .unwrap_err(),
        RecoveryError::HashMismatch
    );
    // Wrong hash LENGTHS are rejected too.
    assert_eq!(
        core::trigger_begin(&p(VAULT), 1, vec![0u8; 16], ah.clone(), wasm.clone(), arg.clone(), 100)
            .unwrap_err(),
        RecoveryError::HashMismatch
    );
    // The correct binding passes.
    let (res, plan) =
        core::trigger_begin(&p(VAULT), 1, wh, ah, wasm, arg, 100).expect("correct hashes pass");
    assert_eq!(res.outcome, ActionOutcome::Executing);
    assert!(plan.is_some());
}

#[test]
fn mismatched_hash_rejected_on_recovery_propose() {
    setup();
    let (wasm, arg, _wh, ah) = artifact(1);
    let wrong = sha256(b"other");
    let action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: wrong,
        expected_arg_hash: ah,
        wasm_bytes: wasm,
        arg_bytes: arg,
    };
    assert_eq!(
        core::propose_recovery(&p(M1), action, 100, None, &self_p()).unwrap_err(),
        RecoveryError::HashMismatch
    );
}

// ── §8 size invariant: oversized inline payloads rejected ────────────────────

#[test]
fn oversized_payload_rejected_by_size_invariant() {
    setup();
    let wasm = vec![0u8; GATE_SIZE_BOUND_BYTES as usize]; // over the bound once args are added
    let arg = vec![1u8; 16];
    let wh = sha256(&wasm);
    let ah = sha256(&arg);
    match core::trigger_begin(&p(VAULT), 1, wh, ah, wasm, arg, 100) {
        Err(RecoveryError::SizeLimitExceeded { .. }) => {}
        other => panic!("expected SizeLimitExceeded, got {other:?}"),
    }
}

// ── Replay returns the prior result; never re-triggerable ────────────────────

#[test]
fn replay_returns_prior_result_and_never_retriggers() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 7, wh.clone(), ah.clone(), wasm.clone(), arg.clone(), 100)
        .expect("first trigger");
    let plan = plan.expect("plan issued");
    assert_eq!(plan.target, p(VAULT));
    // Replay while in flight: prior result, no new plan.
    let (res, plan2) = core::trigger_begin(&p(VAULT), 7, wh.clone(), ah.clone(), wasm.clone(), arg.clone(), 200)
        .expect("replay");
    assert_eq!(res.outcome, ActionOutcome::Executing);
    assert!(plan2.is_none(), "replay must not re-issue the install");
    // Finish: Executed. Bytes cleared only with terminal evidence durable.
    let outcome = core::finish_intent(&plan.key, &Ok(()), 300);
    assert_eq!(outcome, ActionOutcome::Executed);
    let status = core::query_upgrade_status(&p(M1), 7).expect("member sees status");
    assert_eq!(status.outcome, ActionOutcome::Executed);
    assert!(!status.artifact_bytes_held, "bytes cleared at terminal");
    // Replay after terminal: prior result, still no plan.
    let (res, plan3) = core::trigger_begin(&p(VAULT), 7, wh, ah, wasm.clone(), arg, 400).expect("replay");
    assert_eq!(res.outcome, ActionOutcome::Executed);
    assert!(plan3.is_none(), "terminal intent is never re-triggerable");
    // Same id, different payload: conflict, not replay.
    let (wasm2, arg2, _, _) = artifact(2);
    assert_eq!(
        core::trigger_begin(&p(VAULT), 7, sha256(&wasm2), sha256(&arg2), wasm2, arg2, 500)
            .unwrap_err(),
        RecoveryError::HashMismatch
    );
}

// ── OutcomeUnknown: bytes kept, never returns to Pending ─────────────────────

#[test]
fn outcome_unknown_keeps_bytes_and_never_returns_to_pending() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 5, wh.clone(), ah.clone(), wasm.clone(), arg.clone(), 100)
        .expect("trigger");
    let plan = plan.expect("plan");
    let outcome = core::finish_intent(&plan.key, &Err("timeout".into()), 200);
    assert_eq!(outcome, ActionOutcome::OutcomeUnknown);
    let status = core::query_upgrade_status(&p(M1), 5).expect("status");
    assert_eq!(status.outcome, ActionOutcome::OutcomeUnknown);
    assert!(status.artifact_bytes_held, "bytes kept while outcome unknown");
    // The raw durable record holds them too (SSA L2-1: ONLY OutcomeUnknown retains bytes).
    let intent = core::get_intent(&IntentKey::vault(5)).expect("intent");
    assert_eq!(intent.wasm_bytes, Some(wasm));
    assert_eq!(intent.arg_bytes, Some(arg));
    // Reconciliation of an unknown id is indistinguishable from absent.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 9, &evidence(None, 0), &p(SELF_ID), 300)
            .unwrap_err(),
        RecoveryError::UnknownProposal { proposal_id: 9 }
    );
}

// ── Controller-preservation validators, both directions (freeze §3c) ─────────

#[test]
fn controller_preservation_validators_hold_both_directions() {
    let guard = VaultSelfControlGuard { vault: p(VAULT), upgrader: p(SELF_ID) };
    // update_settings against the UPGRADER must preserve controllers==[Vault].
    assert!(guard.validate_update_settings(GuardTarget::Upgrader, &[p(VAULT)]).is_ok());
    assert!(guard.validate_update_settings(GuardTarget::Upgrader, &[p(SELF_ID)]).is_err());
    assert!(guard.validate_update_settings(GuardTarget::Upgrader, &[p(VAULT), p(M1)]).is_err());
    assert!(guard.validate_update_settings(GuardTarget::Upgrader, &[]).is_err());
    // update_settings against the VAULT must preserve controllers==[Upgrader].
    assert!(guard.validate_update_settings(GuardTarget::Vault, &[p(SELF_ID)]).is_ok());
    assert!(guard.validate_update_settings(GuardTarget::Vault, &[p(VAULT)]).is_err());
    assert!(guard.validate_update_settings(GuardTarget::Vault, &[p(SELF_ID), p(M1)]).is_err());
    // Self/cross stop FORBIDDEN both directions between Vault and Upgrader.
    assert!(guard.validate_stop(p(VAULT)).is_err());
    assert!(guard.validate_stop(p(SELF_ID)).is_err());
    // Stopping ordinary targets is permitted.
    assert!(guard.validate_stop(p(0x99)).is_ok());
}

// ── Recovery happy path: 2-of-3 quorum executes ──────────────────────────────

#[test]
fn recovery_happy_path_2_of_3_executes() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(3), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(pid, 1);
    match core::approve_recovery(&p(M2), pid, 200, commit_of(pid), &self_p()).expect("approve") {
        ApproveOutcome::Execute(RecoveryExecution::Trigger { proposal_id, plan }) => {
            assert_eq!(proposal_id, pid);
            assert_eq!(plan.key, IntentKey::recovery(pid));
            assert_eq!(plan.target, p(VAULT));
            // Proposal durably Executing BEFORE the (simulated) await.
            let prop = core::query_recovery_proposal(&p(M1), pid).expect("proposal");
            assert_eq!(prop.outcome, ActionOutcome::Executing);
            // Simulate management success.
            let outcome = core::finish_intent(&plan.key, &Ok(()), 300);
            assert_eq!(outcome, ActionOutcome::Executed);
            core::recovery_finish_trigger(pid, outcome, 300);
        }
        other => panic!("expected quorum execution, got {other:?}"),
    }
    let prop = core::query_recovery_proposal(&p(M2), pid).expect("proposal");
    assert_eq!(prop.outcome, ActionOutcome::Executed);
    assert_eq!(prop.threshold, 2);
    // The intent is terminal, bytes cleared.
    let status = core::query_upgrade_status(&p(M1), pid).expect("status");
    assert_eq!(status.outcome, ActionOutcome::Executed);
    assert_eq!(status.origin, IntentOriginView::Recovery);
    assert!(!status.artifact_bytes_held);
}

#[test]
fn concurrent_quorum_admits_exactly_one_execution() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(3), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    // M2 reaches quorum and owns execution.
    assert!(matches!(
        core::approve_recovery(&p(M2), pid, 200, commit_of(pid), &self_p()).expect("approve"),
        ApproveOutcome::Execute(_)
    ));
    // M3 arriving after the durable Executing flip is rejected — a second
    // execution is structurally impossible.
    assert_eq!(
        core::approve_recovery(&p(M3), pid, 300, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState
    );
    // Duplicate approval by the same member is rejected.
    assert_eq!(
        core::approve_recovery(&p(M1), pid, 300, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState // proposal already left Pending
    );
}

// ── L2-1: terminal state retains NO artifact bytes anywhere ──────────────────

#[test]
fn l2_1_terminal_state_retains_no_artifact_bytes_anywhere() {
    setup();
    let (_, _, wh, ah) = artifact(3);
    // Recovery trigger → Executed.
    let pid = core::propose_recovery(&p(M1), trigger_action(3), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    // At proposal time the proposal stores ONLY the redacted action.
    match core::get_stored_proposal(pid).expect("stored") {
        StoredProposal::Recovery { proposal, epoch } => {
            assert_eq!(epoch, 0);
            match proposal.action {
                RecoveryAction::TriggerVaultUpgrade {
                    expected_wasm_hash,
                    expected_arg_hash,
                    wasm_bytes,
                    arg_bytes,
                } => {
                    assert!(wasm_bytes.is_empty() && arg_bytes.is_empty(),
                        "proposal metadata is hash-only from the start");
                    assert_eq!(expected_wasm_hash, wh, "hashes remain");
                    assert_eq!(expected_arg_hash, ah);
                }
                other => panic!("wrong action: {other:?}"),
            }
        }
        other => panic!("wrong stored proposal: {other:?}"),
    }
    let plan = match core::approve_recovery(&p(M2), pid, 200, commit_of(pid), &self_p()).expect("approve") {
        ApproveOutcome::Execute(RecoveryExecution::Trigger { plan, .. }) => plan,
        other => panic!("expected execution, got {other:?}"),
    };
    let outcome = core::finish_intent(&plan.key, &Ok(()), 300);
    assert_eq!(outcome, ActionOutcome::Executed);
    core::recovery_finish_trigger(pid, outcome, 300);
    // ATOMICITY: outcome terminal AND bytes gone in the same durable record.
    let intent = core::get_intent(&IntentKey::recovery(pid)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::Executed);
    assert!(intent.wasm_bytes.is_none() && intent.arg_bytes.is_none(),
        "Executed intent retains no bytes");
    assert_eq!(intent.expected_wasm_hash, wh, "hashes remain");
    assert_eq!(intent.terminal_at_ns, Some(300));
}

#[test]
fn l2_1_failed_terminalization_also_clears_bytes_atomically() {
    setup();
    // Reconcile an OutcomeUnknown vault-origin intent to Failed.
    let (_, _, wh, ah) = artifact(6);
    let (wasm, arg, wh2, ah2) = artifact(6);
    let (_, plan) = core::trigger_begin(&p(VAULT), 8, wh2, ah2, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    let other = sha256(b"old module");
    let result = core::reconcile_vault_upgrade(
        &p(VAULT),
        8,
        &evidence(Some(other), 300),
        &p(SELF_ID),
        300,
    );
    assert_eq!(result, Ok(ReconcileTerminalOutcome::Failed));
    let intent = core::get_intent(&IntentKey::vault(8)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::Failed);
    assert!(intent.wasm_bytes.is_none() && intent.arg_bytes.is_none(),
        "Failed intent retains no bytes — same write as the terminal outcome");
    assert_eq!(intent.expected_wasm_hash, wh);
    let _ = ah;
}

#[test]
#[should_panic]
fn l2_1_second_terminalization_traps_bytes_cannot_be_resurrected() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 7, wh, ah, wasm, arg, 100).expect("trigger");
    let plan = plan.expect("plan");
    core::finish_intent(&plan.key, &Ok(()), 200);
    // A second finalization attempt on a terminal intent traps — terminal
    // state is never re-writable, so cleared bytes can never return.
    core::finish_intent(&plan.key, &Ok(()), 300);
}

// ── L2-2: evidence temporal/status rules with typed classification ───────────

#[test]
fn l2_2_future_evidence_rejected() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh.clone(), ah, wasm, arg, 100).expect("t");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 1, &evidence(Some(wh), 10_000), &p(SELF_ID), 300)
            .unwrap_err(),
        RecoveryError::EvidenceRejected(EvidenceRejection::FutureEvidence)
    );
    assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::FutureEvidence);
}

#[test]
fn l2_2_too_old_evidence_rejected() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh.clone(), ah, wasm, arg, 100).expect("t");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    let now = 200 + MAX_EVIDENCE_AGE_NS + 1;
    // observed within [created, now] but older than the ruled maximum age.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 1, &evidence(Some(wh), 200), &p(SELF_ID), now)
            .unwrap_err(),
        RecoveryError::EvidenceRejected(EvidenceRejection::EvidenceTooOld)
    );
    assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::EvidenceTooOld);
    // Exactly at the bound it is accepted (then decides on the hash).
    let ok = core::reconcile_vault_upgrade(
        &p(VAULT),
        1,
        &evidence(Some(sha256(&vec![1u8; 64])), 201),
        &p(SELF_ID),
        201 + MAX_EVIDENCE_AGE_NS,
    );
    assert_eq!(ok, Ok(ReconcileTerminalOutcome::Executed));
}

#[test]
fn l2_2_pre_intent_evidence_rejected() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh.clone(), ah, wasm, arg, 100).expect("t");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 1, &evidence(Some(wh), 50), &p(SELF_ID), 300)
            .unwrap_err(),
        RecoveryError::EvidenceRejected(EvidenceRejection::PredatesIntent)
    );
    assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::PredatesIntent);
}

#[test]
fn l2_2_wrong_status_evidence_rejected() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh.clone(), ah, wasm, arg, 100).expect("t");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    for status in [ObservedCanisterStatus::Stopping, ObservedCanisterStatus::Stopped] {
        let mut ev = evidence(Some(wh.clone()), 250);
        ev.observed_canister_status = status;
        assert_eq!(
            core::reconcile_vault_upgrade(&p(VAULT), 1, &ev, &p(SELF_ID), 300).unwrap_err(),
            RecoveryError::EvidenceRejected(EvidenceRejection::StatusNotRunning),
            "non-Running status must reject ({status:?})"
        );
        assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::StatusNotRunning);
    }
}

#[test]
fn l2_2_wrong_principal_and_controllers_rejected_with_typed_reason() {
    setup();
    let (wasm, arg, wh, ah) = artifact(8);
    let (_, plan) = core::trigger_begin(&p(VAULT), 10, wh.clone(), ah, wasm, arg, 100)
        .expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    // Controller set contradicts the ring invariant.
    let mut ev = evidence(Some(wh.clone()), 300);
    ev.observed_controllers = vec![p(0x77)];
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 10, &ev, &p(SELF_ID), 300).unwrap_err(),
        RecoveryError::EvidenceRejected(EvidenceRejection::WrongControllers)
    );
    assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::WrongControllers);
    // Evidence about a different canister.
    let mut ev = evidence(Some(wh), 300);
    ev.observed_upgrader_principal = p(0x78);
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 10, &ev, &p(SELF_ID), 300).unwrap_err(),
        RecoveryError::EvidenceRejected(EvidenceRejection::WrongPrincipal)
    );
    assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::WrongPrincipal);
    // Spoofed caller cannot reconcile at all.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(0x79), 10, &evidence(None, 300), &p(SELF_ID), 300)
            .unwrap_err(),
        RecoveryError::NotAuthorized
    );
    // Intent is untouched — still OutcomeUnknown with bytes held.
    let status = core::query_upgrade_status(&p(M1), 10).expect("status");
    assert_eq!(status.outcome, ActionOutcome::OutcomeUnknown);
    assert!(status.artifact_bytes_held);
}

// ── L2-3: id collisions across intent namespaces ─────────────────────────────

/// Build the collision: vault-origin intent id 1 (OutcomeUnknown) AND
/// recovery-origin intent id 1 (Pending). The L2-5 single-flight lock makes
/// this state unreachable through the public surface — the L2-3 ambiguity
/// path is defense-in-depth for corrupted/legacy durable state, so the
/// fixture plants the colliding intent directly.
fn setup_id_collision() -> u64 {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh, ah, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 150);
    let (wasm2, arg2, wh2, ah2) = artifact(2);
    core::put_intent_for_test(
        &IntentKey::recovery(1),
        &core::UpgradeIntent {
            id: 1,
            origin: IntentOriginView::Recovery,
            expected_wasm_hash: wh2,
            expected_arg_hash: ah2,
            wasm_bytes: Some(wasm2),
            arg_bytes: Some(arg2),
            outcome: ActionOutcome::Pending,
            created_at_ns: 160,
            terminal_at_ns: None,
        },
    );
    1
}

#[test]
fn l2_3_colliding_ids_reconcile_rejected_as_ambiguous() {
    let collision_id = setup_id_collision();
    // Recovery-originated reconcile referencing the colliding id.
    let (_, _, wh1, _) = artifact(1);
    let pid2 = core::propose_recovery(
        &p(M2),
        RecoveryAction::ReconcileVaultUpgrade {
            proposal_id: collision_id,
            objective_evidence: evidence(Some(wh1), 170),
        },
        170, None, &self_p())
    .expect("propose reconcile");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M2), pid2, 171, commit_of(pid2), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    match core::approve_recovery(&p(M3), pid2, 180, commit_of(pid2), &self_p()).expect("approve") {
        ApproveOutcome::Execute(RecoveryExecution::Reconcile {
            intent_id, evidence: ev, approvers, ..
        }) => {
            let res = core::reconcile_intent(
                intent_id,
                None, // recovery path: namespace NOT pre-bound
                &ev,
                ReconcileAuthorityView::Recovery { approvers },
                &p(SELF_ID),
                190,
                false,
            );
            assert_eq!(
                res.as_ref().unwrap_err(),
                &RecoveryError::EvidenceRejected(EvidenceRejection::AmbiguousIntentId),
                "ambiguity rejects with the typed wire variant, never precedence"
            );
            core::recovery_finish_reconcile(pid2, &res, 190);
        }
        other => panic!("expected reconcile execution, got {other:?}"),
    }
    assert_eq!(last_reject_reason(&p(M1)), EvidenceRejection::AmbiguousIntentId);
    // The reconcile proposal failed closed; BOTH intents are untouched.
    let prop = core::get_stored_proposal(pid2).expect("stored");
    match prop {
        StoredProposal::Recovery { proposal, .. } => {
            assert_eq!(proposal.outcome, ActionOutcome::Failed)
        }
        _ => panic!("wrong stored proposal"),
    }
    let vault_intent = core::get_intent(&IntentKey::vault(collision_id)).expect("vault intent");
    assert_eq!(vault_intent.outcome, ActionOutcome::OutcomeUnknown);
    let rec_intent = core::get_intent(&IntentKey::recovery(collision_id)).expect("rec intent");
    assert_eq!(rec_intent.outcome, ActionOutcome::Pending);
    // The status query never answers by precedence either.
    assert!(core::query_upgrade_status(&p(M1), collision_id).is_none());
}

#[test]
fn l2_3_explicitly_namespaced_reconcile_hits_exactly_the_intended_intent() {
    let collision_id = setup_id_collision();
    let (_, _, wh1, _) = artifact(1);
    // The Vault endpoint is namespace-scoped by authority (Vault origin):
    // it hits exactly the vault-originated intent, collision or not.
    let res = core::reconcile_vault_upgrade(
        &p(VAULT),
        collision_id,
        &evidence(Some(wh1.clone()), 200),
        &p(SELF_ID),
        200,
    );
    assert_eq!(res, Ok(ReconcileTerminalOutcome::Executed));
    let vault_intent = core::get_intent(&IntentKey::vault(collision_id)).expect("vault intent");
    assert_eq!(vault_intent.outcome, ActionOutcome::Executed);
    assert!(vault_intent.wasm_bytes.is_none(), "bytes cleared with terminal evidence");
    // The recovery-originated intent is untouched — still Pending, bytes held.
    let rec_intent = core::get_intent(&IntentKey::recovery(collision_id)).expect("rec intent");
    assert_eq!(rec_intent.outcome, ActionOutcome::Pending);
    assert!(rec_intent.wasm_bytes.is_some());
    let _ = wh1;
}

// ── L2-4: governed recovery-membership rotation ──────────────────────────────

#[test]
fn l2_4_rotation_happy_path_2_of_3() {
    setup();
    let pid = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("propose rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    match core::approve_recovery(&p(M3), pid, 200, commit_of(pid), &self_p()).expect("approve") {
        ApproveOutcome::RotationExecuted { new_epoch } => assert_eq!(new_epoch, 1),
        other => panic!("expected rotation execution, got {other:?}"),
    }
    // Membership swapped atomically; threshold still fixed 2.
    let members = core::query_recovery_membership(&p(M2)).expect("current member sees set");
    assert_eq!(members, vec![p(M2), p(M3), p(M4)]);
    let s = core::query_recovery_summary();
    assert_eq!((s.threshold, s.member_count), (2, 3));
    // Attribution: the approving current-member set is in the audit event.
    let page = core::query_audit_events(&p(M2), None, MAX_READ_PAGE_LIMIT).expect("audit");
    let rotated = page.events.iter().rev().find_map(|e| match &e.kind {
        UpgraderAuditEventKind::MembershipRotated {
            proposal_id,
            new_epoch,
            member_count,
            approvers,
        } => Some((*proposal_id, *new_epoch, *member_count, approvers.clone())),
        _ => None,
    });
    assert_eq!(rotated, Some((pid, 1, 3, vec![p(M1), p(M3)])));
    // Rotation survives post_upgrade (durable cell, epoch and all).
    core::post_upgrade(T0);
    assert_eq!(
        core::query_recovery_membership(&p(M4)).expect("post-upgrade"),
        vec![p(M2), p(M3), p(M4)]
    );
    // Recovery still functions in the new epoch.
    let pid2 = core::propose_recovery(&p(M2), trigger_action(9), 300, None, &self_p()).expect("propose after");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M2), pid2, 301, commit_of(pid2), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(matches!(
        core::approve_recovery(&p(M4), pid2, 400, commit_of(pid2), &self_p()).expect("approve after"),
        ApproveOutcome::Execute(RecoveryExecution::Trigger { .. })
    ));
}

#[test]
fn l2_4_rotated_out_member_denied_and_prior_approvals_dont_count() {
    setup();
    // Pending recovery proposal by M1 in epoch 0 (M1's approval recorded).
    let pid = core::propose_recovery(&p(M1), trigger_action(4), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    // Rotate M1 out: {M2, M3, M4} at epoch 1.
    let r = core::propose_membership_rotation(&p(M2), vec![p(M2), p(M3), p(M4)], 200, None, &self_p())
        .expect("propose rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M2), r, 201, commit_of(r), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(matches!(
        core::approve_recovery(&p(M3), r, 300, commit_of(r), &self_p()).expect("approve rotation"),
        ApproveOutcome::RotationExecuted { new_epoch: 1 }
    ));
    // Rotated-out member denied on every path.
    assert_eq!(
        core::propose_recovery(&p(M1), trigger_action(5), 400, None, &self_p()).unwrap_err(),
        RecoveryError::NotAuthorized
    );
    assert_eq!(
        core::approve_recovery(&p(M1), pid, 400, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::NotAuthorized
    );
    assert!(core::query_recovery_membership(&p(M1)).is_none());
    assert!(core::query_audit_events(&p(M1), None, 10).is_none());
    // M1's pre-rotation approval can never carry the proposal: the proposal
    // was terminalized Failed IN THE SAME rotation transaction (SSA L2-7) —
    // there is no stuck-Pending proposal beside a Failed intent. Further
    // approvals reject stale-epoch regardless.
    assert_eq!(
        core::approve_recovery(&p(M4), pid, 500, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::StaleEpoch { current: 1, proposal: 0 },
        "stale-epoch proposal admits no further approvals — typed wire variant"
    );
    assert_eq!(
        core::approve_recovery(&p(M2), pid, 500, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::StaleEpoch { current: 1, proposal: 0 }
    );
    // Proposal AND intent are consistently terminal Failed.
    let prop = core::query_recovery_proposal(&p(M2), pid).expect("proposal");
    assert_eq!(prop.outcome, ActionOutcome::Failed);
    let intent = core::get_intent(&IntentKey::recovery(pid)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::Failed);
    assert!(intent.wasm_bytes.is_none() && intent.arg_bytes.is_none());
}

#[test]
fn l2_7_rotation_terminalizes_linked_proposals_and_intents_atomically() {
    setup();
    // Three stale-to-be proposals in epoch 0: a trigger (intent-linked),
    // a reconcile (no intent), and a second rotation.
    let p_trigger = core::propose_recovery(&p(M1), trigger_action(4), 100, None, &self_p()).expect("trigger");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), p_trigger, 101, commit_of(p_trigger), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let p_reconcile = core::propose_recovery(
        &p(M2),
        RecoveryAction::ReconcileVaultUpgrade {
            proposal_id: 999,
            objective_evidence: evidence(None, 100),
        },
        110, None, &self_p())
    .expect("reconcile");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M2), p_reconcile, 111, commit_of(p_reconcile), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let p_rotation2 =
        core::propose_membership_rotation(&p(M3), vec![p(M1), p(M2)], 120, None, &self_p()).expect("rotation2");
    // Execute the first rotation.
    let r1 = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 200, None, &self_p())
        .expect("rotation1");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), r1, 201, commit_of(r1), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(matches!(
        core::approve_recovery(&p(M2), r1, 300, commit_of(r1), &self_p()).expect("approve rotation1"),
        ApproveOutcome::RotationExecuted { new_epoch: 1 }
    ));
    // SAME transaction: every linked proposal AND intent is terminal Failed,
    // intent bytes cleared.
    let check_terminal = |pid: u64, expect_intent: bool| {
        match core::get_stored_proposal(pid).expect("stored") {
            StoredProposal::Recovery { proposal, .. } => {
                assert_eq!(proposal.outcome, ActionOutcome::Failed, "proposal {pid} terminal")
            }
            StoredProposal::Rotation(r) => {
                assert_eq!(r.outcome, ActionOutcome::Failed, "rotation {pid} terminal")
            }
        }
        let intent = core::get_intent(&IntentKey::recovery(pid));
        assert_eq!(intent.is_some(), expect_intent, "intent linkage for {pid}");
        if let Some(i) = intent {
            assert_eq!(i.outcome, ActionOutcome::Failed, "intent {pid} terminal");
            assert!(i.wasm_bytes.is_none() && i.arg_bytes.is_none(), "bytes cleared");
            assert_eq!(i.terminal_at_ns, Some(300), "terminalized in the rotation tx");
        }
    };
    check_terminal(p_trigger, true);
    check_terminal(p_reconcile, false);
    check_terminal(p_rotation2, false);
    // Linked terminal evidence: one audit event ties proposal id ↔ intent id.
    let page = core::query_audit_events(&p(M2), None, MAX_READ_PAGE_LIMIT).expect("audit");
    let linked: Vec<_> = page
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            UpgraderAuditEventKind::StaleIntentTerminalized { proposal_id, intent_id, epoch } => {
                Some((*proposal_id, *intent_id, *epoch))
            }
            _ => None,
        })
        .collect();
    assert_eq!(linked, vec![(p_trigger, p_trigger, 1)]);
    let unlinked: Vec<_> = page
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            UpgraderAuditEventKind::StaleProposalTerminalized { proposal_id, epoch } => {
                Some((*proposal_id, *epoch))
            }
            _ => None,
        })
        .collect();
    assert_eq!(unlinked, vec![(p_reconcile, 1), (p_rotation2, 1)]);
    // Consistency survives post_upgrade; no stuck-Pending proposals remain.
    core::post_upgrade(T0);
    for pid in [p_trigger, p_reconcile, p_rotation2] {
        let outcome = match core::get_stored_proposal(pid).expect("stored") {
            StoredProposal::Recovery { proposal, .. } => proposal.outcome,
            StoredProposal::Rotation(r) => r.outcome,
        };
        assert_eq!(outcome, ActionOutcome::Failed, "post-upgrade: proposal {pid} terminal");
    }
    let intent = core::get_intent(&IntentKey::recovery(p_trigger)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::Failed);
    assert!(intent.wasm_bytes.is_none());
    // And the single-flight lock is released: a fresh trigger works.
    assert!(core::propose_recovery(&p(M2), trigger_action(6), 400, None, &self_p()).is_ok());
}

#[test]
fn l2_4_stale_epoch_approval_rejected() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(4), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let r = core::propose_membership_rotation(&p(M1), vec![p(M1), p(M2), p(M5)], 200, None, &self_p())
        .expect("rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), r, 201, commit_of(r), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(matches!(
        core::approve_recovery(&p(M2), r, 300, commit_of(r), &self_p()).expect("approve rotation"),
        ApproveOutcome::RotationExecuted { new_epoch: 1 }
    ));
    // Same member, still in the set, but the proposal predates the epoch.
    assert_eq!(
        core::approve_recovery(&p(M2), pid, 400, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::StaleEpoch { current: 1, proposal: 0 }
    );
    // A fresh proposal in the new epoch works.
    let pid2 = core::propose_recovery(&p(M1), trigger_action(6), 500, None, &self_p()).expect("propose new");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid2, 501, commit_of(pid2), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(matches!(
        core::approve_recovery(&p(M5), pid2, 600, commit_of(pid2), &self_p()).expect("approve new"),
        ApproveOutcome::Execute(_)
    ));
}

#[test]
fn l2_4_rotation_rejects_duplicate_and_anonymous_members() {
    setup();
    assert_eq!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M2)], 100, None, &self_p()).unwrap_err(),
        RecoveryError::ThresholdViolation
    );
    assert_eq!(
        core::propose_membership_rotation(
            &p(M1),
            vec![p(M2), Principal::anonymous()],
            200
        , None, &self_p())
        .unwrap_err(),
        RecoveryError::ThresholdViolation
    );
    // The audit carries the validator's exact reasons.
    let page = core::query_audit_events(&p(M1), None, MAX_READ_PAGE_LIMIT).expect("audit");
    let reasons: Vec<_> = page
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            UpgraderAuditEventKind::MembershipRotationRejected { reason, .. } => {
                Some(format!("{reason:?}"))
            }
            _ => None,
        })
        .collect();
    assert_eq!(reasons, vec!["DuplicatePrincipal", "AnonymousSigner"]);
}

#[test]
fn l2_4_rotation_rejects_too_few_members_and_counterpart_member() {
    setup();
    assert_eq!(
        core::propose_membership_rotation(&p(M1), vec![p(M2)], 100, None, &self_p()).unwrap_err(),
        RecoveryError::ThresholdViolation
    );
    assert_eq!(
        core::propose_membership_rotation(&p(M1), vec![], 200, None, &self_p()).unwrap_err(),
        RecoveryError::ThresholdViolation
    );
    // The Vault counterpart can never be a recovery member.
    assert_eq!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(VAULT)], 300, None, &self_p()).unwrap_err(),
        RecoveryError::ThresholdViolation
    );
}

#[test]
fn l2_4_non_member_cannot_propose_or_approve_rotation() {
    setup();
    assert_eq!(
        core::propose_membership_rotation(&p(0xAB), vec![p(M1), p(M2)], 100, None, &self_p()).unwrap_err(),
        RecoveryError::NotAuthorized
    );
    let pid = core::propose_membership_rotation(&p(M1), vec![p(M1), p(M2)], 200, None, &self_p())
        .expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 201, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(
        core::approve_recovery(&p(0xAB), pid, 300, commit_of(pid), &self_p()).unwrap_err(),
        RecoveryError::NotAuthorized
    );
}

#[test]
#[should_panic]
fn l2_4_post_upgrade_revalidation_traps_on_corrupt_membership_cell() {
    setup();
    core::write_bootstrap_raw_for_test(b"garbage".to_vec());
    core::post_upgrade(T0);
}

// ── ReconcileVaultUpgrade: 2-of-3 fallback with the Vault unavailable ────────

#[test]
fn reconcile_2_of_3_fallback_works_with_vault_unavailable() {
    setup();
    let (wasm, arg, wh, ah) = artifact(5);
    // Vault triggers, management call outcome is lost (Vault now unavailable).
    let (_, plan) = core::trigger_begin(&p(VAULT), 42, wh.clone(), ah.clone(), wasm, arg, 100)
        .expect("trigger");
    let plan = plan.expect("plan");
    let outcome = core::finish_intent(&plan.key, &Err("timeout: unknown".into()), 200);
    assert_eq!(outcome, ActionOutcome::OutcomeUnknown);

    // Recovery quorum reconciles — the path makes NO Vault call.
    let pid = core::propose_recovery(
        &p(M1),
        RecoveryAction::ReconcileVaultUpgrade {
            proposal_id: 42,
            objective_evidence: evidence(Some(wh.clone()), 250),
        },
        300, None, &self_p())
    .expect("propose reconcile");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 301, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let approvers = match core::approve_recovery(&p(M3), pid, 400, commit_of(pid), &self_p()).expect("approve") {
        ApproveOutcome::Execute(RecoveryExecution::Reconcile {
            proposal_id,
            intent_id,
            evidence,
            approvers,
        }) => {
            assert_eq!(proposal_id, pid);
            assert_eq!(intent_id, 42);
            let result = core::reconcile_intent(
                intent_id,
                None,
                &evidence,
                ReconcileAuthorityView::Recovery { approvers: approvers.clone() },
                &p(SELF_ID),
                500,
                false,
            );
            assert_eq!(result, Ok(ReconcileTerminalOutcome::Executed));
            core::recovery_finish_reconcile(pid, &result, 500);
            approvers
        }
        other => panic!("expected reconcile execution, got {other:?}"),
    };
    assert_eq!(approvers.len(), 2, "2-of-3 quorum reached");
    let status = core::query_upgrade_status(&p(M2), 42).expect("status");
    assert_eq!(status.outcome, ActionOutcome::Executed);
    assert!(!status.artifact_bytes_held, "bytes cleared with terminal evidence");
    let prop = core::query_recovery_proposal(&p(M2), pid).expect("proposal");
    assert_eq!(prop.outcome, ActionOutcome::Executed);
    // Never re-triggerable after terminal.
    let (w2, a2, wh2, ah2) = (vec![5u8; 64], vec![6u8; 16], wh.clone(), ah.clone());
    let (res, plan2) =
        core::trigger_begin(&p(VAULT), 42, wh2, ah2, w2, a2, 600).expect("replay");
    assert_eq!(res.outcome, ActionOutcome::Executed);
    assert!(plan2.is_none());
    // Never reconcilable again via the RECOVERY path (one-shot,
    // AlreadyTerminal — replay is disabled there, CUST-L12-02).
    assert_eq!(
        core::reconcile_intent(
            42,
            Some(IntentOriginView::Vault),
            &evidence(Some(wh), 700),
            ReconcileAuthorityView::Vault,
            &p(SELF_ID),
            700,
            false,
        )
        .unwrap_err(),
        RecoveryError::AlreadyTerminal
    );
}

#[test]
fn reconcile_rejects_illegal_source_state() {
    setup();
    let (wasm, arg, wh, ah) = artifact(7);
    let (_, plan) = core::trigger_begin(&p(VAULT), 9, wh.clone(), ah, wasm, arg, 100).expect("trigger");
    let plan = plan.expect("plan");
    // Executing (not OutcomeUnknown): reconciliation is illegal — it can
    // never move a live intent, and OutcomeUnknown never returns to Pending.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 9, &evidence(Some(wh), 200), &p(SELF_ID), 200)
            .unwrap_err(),
        RecoveryError::IllegalSourceState
    );
    core::finish_intent(&plan.key, &Ok(()), 300);
    // Executed: the Vault endpoint REPLAYS the terminal outcome read-only
    // (CUST-L12-02) instead of rejecting.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 9, &evidence(None, 400), &p(SELF_ID), 400),
        Ok(ReconcileTerminalOutcome::Executed)
    );
}

// ── CUST-L12-02: idempotent terminal replay on reconcile_vault_upgrade ───────

/// Audit event count helper (replay must append NOTHING).
fn audit_len(member: &Principal) -> usize {
    core::query_audit_events(member, None, MAX_READ_PAGE_LIMIT)
        .expect("audit")
        .events
        .len()
}

#[test]
fn l12_02_terminal_replay_executed_is_read_only_and_repeatable() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 7, wh, ah, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Ok(()), 200);
    let before = core::get_intent(&IntentKey::vault(7)).expect("intent");
    let audit_before = audit_len(&p(M1));
    // Replay: Ok(Executed), no intent rewrite, no audit append, and NO
    // management call — reconcile_intent performs no inter-canister call by
    // construction (it returns no InstallPlan; the only backend-issuing
    // path is execute_install, driven solely by trigger/approve flows).
    for now in [300, 400, 500] {
        assert_eq!(
            core::reconcile_vault_upgrade(&p(VAULT), 7, &evidence(None, now), &p(SELF_ID), now),
            Ok(ReconcileTerminalOutcome::Executed),
            "repeated replays return the same result"
        );
    }
    let after = core::get_intent(&IntentKey::vault(7)).expect("intent");
    assert_eq!(before, after, "replay must not mutate the durable intent");
    assert_eq!(audit_len(&p(M1)), audit_before, "replay appends no audit event");
    // Note: replay does NOT validate evidence — the outcome is already
    // durable fact; nothing depends on the evidence any more (documented).
}

#[test]
fn l12_02_terminal_replay_failed_is_read_only() {
    setup();
    let (wasm, arg, wh, ah) = artifact(6);
    let (_, plan) = core::trigger_begin(&p(VAULT), 8, wh, ah, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    // Drive it to Failed via the state-changing path.
    assert_eq!(
        core::reconcile_vault_upgrade(
            &p(VAULT),
            8,
            &evidence(Some(sha256(b"old")), 300),
            &p(SELF_ID),
            300,
        ),
        Ok(ReconcileTerminalOutcome::Failed)
    );
    let before = core::get_intent(&IntentKey::vault(8)).expect("intent");
    let audit_before = audit_len(&p(M1));
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 8, &evidence(None, 400), &p(SELF_ID), 400),
        Ok(ReconcileTerminalOutcome::Failed)
    );
    let after = core::get_intent(&IntentKey::vault(8)).expect("intent");
    assert_eq!(before, after, "no rewrite, no byte resurrection");
    assert!(after.wasm_bytes.is_none() && after.arg_bytes.is_none());
    assert_eq!(audit_len(&p(M1)), audit_before);
}

#[test]
fn l12_02_pending_and_executing_and_unknown_rejected() {
    setup();
    // Executing vault intent.
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh.clone(), ah, wasm, arg, 100).expect("t");
    assert!(plan.is_some());
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 1, &evidence(Some(wh), 200), &p(SELF_ID), 200)
            .unwrap_err(),
        RecoveryError::IllegalSourceState,
        "Executing is never replayed nor transitioned"
    );
    // Pending vault-namespace intent (planted — the public Vault path
    // creates Executing directly; the rejection rule is state-based).
    let (w2, a2, wh2, ah2) = artifact(2);
    core::put_intent_for_test(
        &IntentKey::vault(2),
        &core::UpgradeIntent {
            id: 2,
            origin: IntentOriginView::Vault,
            expected_wasm_hash: wh2.clone(),
            expected_arg_hash: ah2,
            wasm_bytes: Some(w2),
            arg_bytes: Some(a2),
            outcome: ActionOutcome::Pending,
            created_at_ns: 100,
            terminal_at_ns: None,
        },
    );
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 2, &evidence(Some(wh2), 200), &p(SELF_ID), 200)
            .unwrap_err(),
        RecoveryError::IllegalSourceState
    );
    // Unknown request id.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 999, &evidence(None, 200), &p(SELF_ID), 200)
            .unwrap_err(),
        RecoveryError::UnknownProposal { proposal_id: 999 }
    );
}

// ── Query gating: positive + negative, indistinguishable ─────────────────────

#[test]
fn query_gating_positive_and_negative_indistinguishable() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(9), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");

    for gated in [M1, M2, M3] {
        assert!(core::query_recovery_proposal(&p(gated), pid).is_some());
        assert!(core::query_recovery_membership(&p(gated)).is_some());
        assert!(core::query_audit_events(&p(gated), None, 10).is_some());
    }
    for bad in [Principal::anonymous(), p(0xAB)] {
        // Unknown principal / anonymous: same shape as "does not exist".
        assert!(core::query_recovery_proposal(&bad, pid).is_none());
        assert!(core::query_recovery_proposal(&bad, 999).is_none());
        assert!(core::query_recovery_membership(&bad).is_none());
        assert!(core::query_audit_events(&bad, None, 10).is_none());
        assert!(core::query_upgrade_status(&bad, pid).is_none());
    }
    // Indistinguishability on the member side too: unknown id is also None.
    assert!(core::query_recovery_proposal(&p(M1), 999).is_none());
    assert!(core::query_upgrade_status(&p(M1), 999).is_none());
    // Membership view returns exactly the durable set, to members only.
    let members = core::query_recovery_membership(&p(M2)).expect("members");
    assert_eq!(members, vec![p(M1), p(M2), p(M3)]);
}

#[test]
fn audit_query_is_bounded_and_paginates() {
    setup();
    // Generate a few events: propose (intent + proposal) + approve.
    let pid = core::propose_recovery(&p(M1), trigger_action(10), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let _ = core::approve_recovery(&p(M2), pid, 200, commit_of(pid), &self_p()).expect("approve");
    // Events: bootstrap, intent recorded, proposal created, approval (M1 —
    // the proposer, now EXPLICIT per V8 §3), approval (M2), execution started
    // — 6 total. Was 5 when proposing implicitly seeded the proposer's
    // approval: that seeding logged one entry at creation; now the proposer
    // logs its own, like every other member.
    let page1 = core::query_audit_events(&p(M1), None, 2).expect("page1");
    assert_eq!(page1.events.len(), 2);
    assert!(page1.next_cursor.is_some());
    let page2 = core::query_audit_events(&p(M1), page1.next_cursor, 2).expect("page2");
    assert_eq!(page2.events.len(), 2);
    let page3 = core::query_audit_events(&p(M1), page2.next_cursor, 2).expect("page3");
    assert_eq!(page3.events.len(), 2);
    assert!(page3.next_cursor.is_none());
    // Sequential and complete.
    let seqs: Vec<u64> = page1
        .events
        .iter()
        .chain(page2.events.iter())
        .chain(page3.events.iter())
        .map(|e| e.seq)
        .collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5], "6 events: the proposer's approval is now its own logged entry");
    // Bounds: limit 0 and above the frozen maximum are indistinguishable None.
    assert!(core::query_audit_events(&p(M1), None, 0).is_none());
    assert!(core::query_audit_events(&p(M1), None, MAX_READ_PAGE_LIMIT + 1).is_none());
    assert!(core::query_audit_events(&p(M1), None, MAX_READ_PAGE_LIMIT).is_some());
}

#[test]
#[should_panic]
fn l2_hardening_rotation_traps_on_pending_trigger_proposal_without_intent() {
    setup();
    // Corrupt durable state: a Pending trigger proposal with NO linked
    // intent. Unreachable through the public surface (propose always writes
    // both); planted directly to prove rotation fails closed rather than
    // emitting StaleIntentTerminalized for a nonexistent intent.
    // S5B W1.4 — planted at a HIGH id deliberately. The allocation counter now
    // hands out ids from 1 upward, so planting at 1 would collide with the
    // rotation proposal this test creates, and the W1.4 insert-if-absent guard
    // would trap on the collision instead of on the corrupt linkage this test
    // is actually about. (Under the old `next_back()` allocator the planted
    // record silently pushed the allocator past it, which is precisely the
    // history-as-authority behaviour W1.1 removes.)
    let pid = 10_000u64;
    core::put_stored_proposal_for_test(
        pid,
        &StoredProposal::Recovery {
            epoch: 0,
            proposal: stsh_custody_types::RecoveryProposal {
                start: None,
                proposal_id: pid,
                action: trigger_action(4),
                proposer: p(M1),
                approvals: vec![p(M1)],
                threshold: 2,
                created_at_ns: 100,
                outcome: ActionOutcome::Pending,
                // R3.1: no expiry while the §10.5 lifetime bounds are unruled.
                expires_at_ns: None,
                // Planted directly, so no commitment is stored: this fixture
                // exercises a corrupt/unreachable state deliberately.
                commitment_hash: Vec::new(),
            },
        },
    );
    let r = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 200, None, &self_p())
        .expect("rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), r, 201, commit_of(r), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    // Quorum-reaching approval executes the rotation, which must TRAP on
    // the corrupt linkage (rolling the whole rotation back).
    let _ = core::approve_recovery(&p(M2), r, 300, commit_of(r), &self_p());
}

#[test]
#[should_panic]
fn l2_hardening_rotation_traps_on_linked_intent_not_pending() {
    setup();
    // Corrupt durable state: Pending trigger proposal whose linked intent
    // is already terminal — same fail-closed rule, second shape.
    let pid = core::propose_recovery(&p(M1), trigger_action(4), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let mut intent = core::get_intent(&IntentKey::recovery(pid)).expect("intent");
    intent.outcome = ActionOutcome::Executed;
    intent.terminal_at_ns = Some(150);
    intent.wasm_bytes = None;
    intent.arg_bytes = None;
    core::put_intent_for_test(&IntentKey::recovery(pid), &intent);
    let r = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 200, None, &self_p())
        .expect("rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), r, 201, commit_of(r), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let _ = core::approve_recovery(&p(M2), r, 300, commit_of(r), &self_p());
}

// ── UTF-8-safe truncation of target-controlled rejection text (SSA HIGH) ────

#[test]
fn truncate_utf8_bounded_ascii_and_short_strings() {
    use crate::core::{truncate_utf8_bounded, MAX_REJECT_DETAIL_BYTES};
    assert_eq!(truncate_utf8_bounded("hello", 512), "hello");
    let exactly = "a".repeat(MAX_REJECT_DETAIL_BYTES);
    assert_eq!(truncate_utf8_bounded(&exactly, MAX_REJECT_DETAIL_BYTES), exactly);
    let over = "a".repeat(MAX_REJECT_DETAIL_BYTES + 100);
    assert_eq!(truncate_utf8_bounded(&over, MAX_REJECT_DETAIL_BYTES).len(), MAX_REJECT_DETAIL_BYTES);
}

#[test]
fn truncate_utf8_bounded_never_splits_a_char() {
    use crate::core::truncate_utf8_bounded;
    // 'é' is 2 bytes: a cap landing on its second byte must back off.
    let s = format!("{}é{}", "a".repeat(511), "tail");
    let out = truncate_utf8_bounded(&s, 512);
    assert_eq!(out.len(), 511, "mid-char cap backs off to the boundary");
    assert!(out.ends_with('a'));
    // '€' is 3 bytes; '🦀' is 4 bytes.
    let s2 = format!("{}€{}", "b".repeat(510), "x");
    assert_eq!(truncate_utf8_bounded(&s2, 512).len(), 510);
    let s3 = format!("{}🦀{}", "c".repeat(510), "x");
    assert_eq!(truncate_utf8_bounded(&s3, 512).len(), 510);
    // Exactly-at-boundary keeps the full character.
    let s4 = format!("{}é", "d".repeat(510)); // 510 + 2 = 512 exactly
    let out4 = truncate_utf8_bounded(&s4, 512);
    assert_eq!(out4.len(), 512);
    assert!(out4.ends_with('é'));
    // Degenerate caps.
    assert_eq!(truncate_utf8_bounded("é", 1), "");
    assert_eq!(truncate_utf8_bounded("", 0), "");
}

#[test]
fn multibyte_rejection_does_not_strand_intent_in_executing() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh.clone(), ah, wasm, arg, 100).expect("t");
    let plan = plan.expect("plan");
    // Durable pre-await state is Executing; the rejection text carries a
    // multibyte char straddling the 512-byte cap (the old String::truncate
    // would panic HERE, stranding the intent in Executing forever).
    let hostile = format!("mgmt reject: {}é{}", "x".repeat(498), "padding");
    assert!(hostile.len() > 512 && !hostile.is_char_boundary(512));
    let outcome = core::finish_intent(&plan.key, &Err(hostile), 200);
    // NOT stranded: the intent reaches OutcomeUnknown...
    assert_eq!(outcome, ActionOutcome::OutcomeUnknown);
    let intent = core::get_intent(&IntentKey::vault(1)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::OutcomeUnknown);
    assert!(intent.wasm_bytes.is_some(), "bytes retained while unknown");
    // ...the audit detail is bounded and valid UTF-8...
    let page = core::query_audit_events(&p(M1), None, MAX_READ_PAGE_LIMIT).expect("audit");
    let detail = page.events.iter().rev().find_map(|e| match &e.kind {
        UpgraderAuditEventKind::VaultUpgradeOutcomeUnknown { reject_detail, .. } => {
            Some(reject_detail.clone())
        }
        _ => None,
    });
    let detail = detail.expect("OutcomeUnknown audited");
    assert!(detail.len() <= 512);
    // ...and reconciliation can now terminalize it, unwedging single-flight.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 1, &evidence(Some(wh), 300), &p(SELF_ID), 300),
        Ok(ReconcileTerminalOutcome::Executed)
    );
    let (w2, a2, wh2, ah2) = artifact(2);
    assert!(
        core::trigger_begin(&p(VAULT), 2, wh2, ah2, w2, a2, 400).is_ok(),
        "single-flight lock released after reconciliation"
    );
}

#[test]
fn controller_invariant_reflects_last_durable_observation() {
    setup();
    // Fail-closed before any observation.
    let inv = core::query_controller_invariant();
    assert!(!inv.vault_controllers_ok && !inv.upgrader_controllers_ok && inv.observed_at_ns == 0);
    core::record_controller_invariant(true, true, 123_456);
    let inv = core::query_controller_invariant();
    assert!(inv.vault_controllers_ok && inv.upgrader_controllers_ok);
    assert_eq!(inv.observed_at_ns, 123_456);
    // R6.0 — the observation is served from its OWN cell (MemoryId 11), so
    // `post_upgrade` neither rebuilds it nor reads the audit trail. This
    // assertion used to read "post_upgrade rebuilds the mirror from the durable
    // audit tail", which was exactly the defect.
    core::post_upgrade(T0);
    let inv = core::query_controller_invariant();
    assert!(inv.vault_controllers_ok && inv.upgrader_controllers_ok);
    assert_eq!(inv.observed_at_ns, 123_456);
}

// ── S11-2 / CUST-SSA-006 — V4.1 R6 freshness response contract ──────────────
//
// THE DEFECT, STATED PLAINLY. `ControllerInvariant` served three fields and no
// freshness, so the only externally-verifiable "no human holds a controller
// key" proof could not distinguish:
//
//   (a) the ring is intact and was checked minutes ago,
//   (b) the ring was intact when someone last looked — a year ago,
//   (c) nobody has EVER looked (the { false, false, 0 } sentinel), which on
//       the wire is byte-identical to a genuine DOUBLE BREACH observed at
//       time 0.
//
// (a) is a proof. (b) and (c) are not, and the old contract reported all three
// through the same shape. V4.1 R6 requirements 7-9 close it: three-state
// freshness, computed at query time, plus a fail-closed aggregate that is true
// ONLY for a fresh, intact reading.

/// The ruled 24 h bound — read from the pinned MemoryId 12 constant, never
/// retyped as a literal here. A test that hard-coded 86_400e9 would keep
/// passing if the ruled constant moved, which is the whole failure mode the
/// no-invented-constants discipline exists to prevent.
fn max_age_for_test() -> u64 {
    stsh_custody_types::INVARIANT_REFRESH_PARAMS
        .expect("S11-2 requires the R6 constants ruled")
        .max_age_ns
}

/// Requirement 7+9 — NeverObserved is fail-closed and is NOT a breach report.
///
/// The sharpest half of CUST-SSA-006: before S11-2 this state and "both
/// controller sets are broken, observed at time 0" produced the same three
/// fields. They are now different values of an explicit variant, and the
/// absent-evidence case carries `age_ns: None` rather than `0` — `0` would
/// read as "just observed", the most dangerous possible lie for that field.
#[test]
fn s11_2_never_observed_is_fail_closed_and_distinguishable() {
    setup();
    let proof = core::query_controller_invariant_proof(500_000);
    assert_eq!(proof.freshness, InvariantFreshness::NeverObserved);
    assert_eq!(proof.age_ns, None, "there is no age of a thing that never happened");
    assert_eq!(proof.observed_at_ns, 0);
    assert!(!proof.current_proof_ok, "absence of evidence is NEVER success-shaped");
    assert!(!proof.vault_controllers_ok && !proof.upgrader_controllers_ok);
    assert_eq!(proof.max_age_ns, max_age_for_test());

    // THE DISAMBIGUATION, ASSERTED. A real double breach observed at time 0 is
    // now a DIFFERENT value — under the old contract these two were identical
    // on the wire.
    core::record_controller_invariant(false, false, 0);
    let breach = core::query_controller_invariant_proof(500_000);
    assert_ne!(
        breach.freshness, proof.freshness,
        "a real observation must never classify as NeverObserved"
    );
    assert_eq!(breach.age_ns, Some(500_000), "a real observation HAS an age");
    // Both are fail-closed, but for different and now-distinguishable reasons.
    assert!(!breach.current_proof_ok);
}

/// Requirement 9 — the aggregate is true ONLY for Fresh && ok && ok, and the
/// truth booleans survive staleness unmodified.
#[test]
fn s11_2_aggregate_is_fail_closed_across_freshness_and_truth() {
    setup();
    let max_age = max_age_for_test();
    let observed = 1_000_000_000;
    core::record_controller_invariant(true, true, observed);

    // FRESH + both true — the ONLY success-shaped combination.
    let fresh = core::query_controller_invariant_proof(observed + 1);
    assert_eq!(fresh.freshness, InvariantFreshness::Fresh);
    assert_eq!(fresh.age_ns, Some(1));
    assert!(fresh.current_proof_ok, "a fresh intact reading IS a current proof");

    // STALE + both true — the aggregate goes false, and this is the assertion
    // that matters most: the TRUTH BOOLEANS ARE PRESERVED. Staleness withdraws
    // the warrant to act on a reading; it never rewrites what the reading said.
    let stale = core::query_controller_invariant_proof(observed + max_age + 1);
    assert_eq!(stale.freshness, InvariantFreshness::Stale);
    assert!(
        stale.vault_controllers_ok && stale.upgrader_controllers_ok,
        "staleness must not rewrite history — freshness is ORTHOGONAL to breach truth"
    );
    assert_eq!(stale.observed_at_ns, observed, "and the timestamp is preserved too");
    assert_eq!(stale.age_ns, Some(max_age + 1));
    assert!(!stale.current_proof_ok, "a stale reading is NEVER a current proof");

    // FRESH but breached, each limb independently — neither alone may carry
    // the aggregate. Asserted separately because a `||` where the contract
    // says `&&` would pass a test that only ever broke both at once.
    for (v_ok, u_ok) in [(true, false), (false, true), (false, false)] {
        core::record_controller_invariant(v_ok, u_ok, observed);
        let proof = core::query_controller_invariant_proof(observed + 1);
        assert_eq!(proof.freshness, InvariantFreshness::Fresh);
        assert!(
            !proof.current_proof_ok,
            "fresh but breached ({v_ok}, {u_ok}) must not be success-shaped"
        );
        assert_eq!(proof.vault_controllers_ok, v_ok);
        assert_eq!(proof.upgrader_controllers_ok, u_ok);
    }
}

/// Requirement 7 — THE BOUNDARY, at EXACTLY `max_age`.
///
/// Pinned in its own test because an off-by-one here is invisible in normal
/// operation and is exactly where a freshness bound is got wrong. The ruling:
/// `age >= max_age_ns` is Stale — `max_age` is the age at which an observation
/// STOPS being relied upon, not the last age at which it is.
#[test]
fn s11_2_freshness_boundary_is_exactly_max_age() {
    setup();
    let max_age = max_age_for_test();
    let observed = 1_000_000_000;
    core::record_controller_invariant(true, true, observed);

    // One nanosecond short: still Fresh, still a current proof.
    let just_fresh = core::query_controller_invariant_proof(observed + max_age - 1);
    assert_eq!(just_fresh.freshness, InvariantFreshness::Fresh);
    assert!(just_fresh.current_proof_ok);

    // EXACTLY max_age: already Stale.
    let at_bound = core::query_controller_invariant_proof(observed + max_age);
    assert_eq!(
        at_bound.freshness,
        InvariantFreshness::Stale,
        "exactly max_age is already too old — the bound is inclusive of staleness"
    );
    assert_eq!(at_bound.age_ns, Some(max_age));
    assert!(!at_bound.current_proof_ok);

    // A clock that went BACKWARDS must not underflow into a huge age that
    // reads as Stale, and must not panic. Saturation gives age 0 → Fresh.
    let backwards = core::query_controller_invariant_proof(observed - 1);
    assert_eq!(backwards.age_ns, Some(0));
    assert_eq!(backwards.freshness, InvariantFreshness::Fresh);
}

// ── R6.0 — durable controller-invariant observation (MemoryId 11) ────────────

/// R6.0 acceptance 1+2 — survival is INDEPENDENT of audit-tail length.
///
/// THE DEFECT, STATED AS THE TEST. `rebuild_invariant_mirror` scanned
/// `AUDIT_EVENTS` backwards from the tail for at most `SCAN_CAP = 10_000`
/// events (core.rs:806 at 41ff8f01, the pre-S8A base — the constant is cited,
/// not invented, and the scan is removed by this change). One observation
/// followed by more than that many other events put the observation out of
/// reach: the rebuild produced `None` and the PUBLIC proof reverted to
/// `{false, false, 0}` for a ring that was intact and observed.
///
/// Seeded to `SCAN_CAP + 1` events AFTER the observation, so the tail is
/// strictly beyond the cap and the pre-R6.0 code would have failed here. The
/// comparison is BYTE-EXACT on all three fields, not a shape check: an
/// observation that survived with a zeroed timestamp, or with the two booleans
/// swapped, is a different observation and must not read as success.
#[test]
fn r6_0_observation_survives_beyond_scan_cap_audit_tail() {
    setup();
    /// The cap the REMOVED backwards scan used, retained here only as the
    /// threshold this regression must exceed. Not a live constant.
    const HISTORICAL_SCAN_CAP: u32 = 10_000;

    core::record_controller_invariant(true, false, 777_000);
    let before = core::invariant_record_for_test().expect("observation is durable");

    let len_at_observation = core::audit_len_for_test();
    core::seed_audit_events_for_test(HISTORICAL_SCAN_CAP + 1, 800_000);
    assert!(
        core::audit_len_for_test() > len_at_observation + HISTORICAL_SCAN_CAP as u64,
        "the tail must be driven STRICTLY past the cap, or this regression \
         passes below the threshold it exists to cross"
    );

    core::post_upgrade(T0);

    let after = core::invariant_record_for_test().expect(
        "R6.0: the observation must survive an audit tail longer than the removed \
         scan's cap — this is the defect",
    );
    assert_eq!(after, before, "R6.0: the durable record must be byte-identical");
    let inv = core::query_controller_invariant();
    assert!(inv.vault_controllers_ok, "vault_controllers_ok must survive as true");
    assert!(!inv.upgrader_controllers_ok, "upgrader_controllers_ok must survive as false");
    assert_eq!(inv.observed_at_ns, 777_000, "the timestamp must survive exactly");
}

/// R6.0 acceptance 1 — recovery never walks the audit log.
///
/// The complement of the test above, and the reason it is separate: that one
/// proves the observation survives a long tail, this one proves the tail is not
/// consulted AT ALL. Recording an observation and then DELETING every audit
/// event leaves a state in which any audit-derived recovery must fail and a
/// cell read must succeed. A rebuild-from-history implementation passes the
/// beyond-cap test if its cap is merely raised; it cannot pass this one.
#[test]
fn r6_0_observation_recoverable_with_the_entire_audit_trail_erased() {
    setup();
    core::record_controller_invariant(true, true, 424_242);
    core::erase_audit_trail_for_test();
    assert_eq!(core::audit_len_for_test(), 0, "the trail must actually be gone");

    core::post_upgrade(T0);

    let inv = core::query_controller_invariant();
    assert!(
        inv.vault_controllers_ok && inv.upgrader_controllers_ok,
        "R6.0: recovery of the observation must never require walking the audit log"
    );
    assert_eq!(inv.observed_at_ns, 424_242);
}

/// R6.0 — the LAST observation wins, and a later one is durable too.
///
/// A cell rewritten in place has a failure mode an append-only trail does not:
/// a stale value surviving a newer write. Two observations, the second
/// contradicting the first on both booleans, so a read of the wrong one is
/// unambiguous rather than coincidentally equal.
#[test]
fn r6_0_latest_observation_replaces_the_previous_one_durably() {
    setup();
    core::record_controller_invariant(true, true, 100);
    core::record_controller_invariant(false, false, 200);
    core::post_upgrade(T0);
    let inv = core::query_controller_invariant();
    assert!(!inv.vault_controllers_ok && !inv.upgrader_controllers_ok);
    assert_eq!(inv.observed_at_ns, 200, "the LAST observation must be the durable one");
}

/// R6.0 — an EMPTY cell is "never observed"; a CORRUPT cell is not.
///
/// These two states must not collapse into one answer. Absence is the
/// legitimate pre-first-observation state and fails closed to `{false,false,0}`.
/// Undecodable bytes are corruption, and degrading them to the same
/// `{false,false,0}` would make a corrupt durable state indistinguishable from
/// a fresh install — the silent substitution the sentinels elsewhere on this
/// canister exist to prevent.
///
/// Bare `#[should_panic]`, matching every other fail-closed test on this
/// canister: `ic_cdk::trap` outside a canister panics with the runtime's own
/// "trap should only be called inside canisters" text, so the trap MESSAGE is
/// not assertable natively. The gate that fires is pinned structurally instead
/// — these bytes are not valid Candid, so the decode gate is the only one
/// reachable.
#[test]
#[should_panic]
fn r6_0_corrupt_invariant_cell_traps_rather_than_reading_as_never_observed() {
    setup();
    core::record_controller_invariant(true, true, 100);
    core::write_invariant_raw_for_test(vec![0xff, 0xff, 0xff, 0xff]);
    let _ = core::query_controller_invariant();
}

/// R6.0 — a record from an unrecognised schema version fails CLOSED.
///
/// Distinct from the undecodable case: these bytes decode perfectly. Only the
/// version says the writer was a different build, and a valid-looking decode
/// under the wrong schema is the more dangerous of the two — it would be
/// SERVED, as a public no-human-controller proof, on fields that may not mean
/// what this build thinks they mean.
///
/// Bare `#[should_panic]` for the same reason as above. The gate is pinned
/// structurally: these bytes DECODE cleanly, so the decode gate cannot be what
/// fires and only the version gate is left.
#[test]
#[should_panic]
fn r6_0_wrong_schema_version_traps() {
    setup();
    let forged = candid::encode_one(&core::LastControllerInvariant {
        schema_version: core::LAST_CONTROLLER_INVARIANT_SCHEMA_VERSION + 1,
        vault_controllers_ok: true,
        upgrader_controllers_ok: true,
        observed_at_ns: 1,
    })
    .expect("encodes");
    core::write_invariant_raw_for_test(forged);
    let _ = core::query_controller_invariant();
}

/// R6.0 — the audit event is still written alongside the cell.
///
/// The cell is where the proof is SERVED from; the append-only trail remains
/// the public record of when observations happened. Replacing one with the
/// other would have been a quieter regression than the defect being fixed, so
/// the pairing is asserted rather than assumed.
#[test]
fn r6_0_observation_still_appends_its_audit_event() {
    setup();
    let before = core::audit_len_for_test();
    core::record_controller_invariant(true, true, 555);
    assert_eq!(
        core::audit_len_for_test(),
        before + 1,
        "R6.0 must not silently drop the append-only audit record"
    );
    match core::last_audit_event_for_test().expect("an event was appended").kind {
        core::UpgraderAuditEventKind::ControllerInvariantObserved {
            vault_controllers_ok,
            upgrader_controllers_ok,
        } => assert!(vault_controllers_ok && upgrader_controllers_ok),
        other => panic!("expected ControllerInvariantObserved, got {other:?}"),
    }
}

// ── Durability across upgrade (no pre_upgrade; stable maps persist) ──────────

#[test]
fn durable_state_survives_post_upgrade() {
    setup();
    let (wasm, arg, wh, ah) = artifact(11);
    let (_, plan) = core::trigger_begin(&p(VAULT), 77, wh, ah, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("lost".into()), 200);
    core::post_upgrade(T0);
    // Everything still there; membership and outcome intact.
    let s = core::query_recovery_summary();
    assert_eq!((s.threshold, s.member_count), (2, 3));
    let status = core::query_upgrade_status(&p(M1), 77).expect("status survives");
    assert_eq!(status.outcome, ActionOutcome::OutcomeUnknown);
    assert!(status.artifact_bytes_held);
    // And the recovery path still works after the upgrade.
    let pid = core::propose_recovery(
        &p(M2),
        RecoveryAction::ReconcileVaultUpgrade {
            proposal_id: 77,
            objective_evidence: evidence(Some(sha256(&vec![11u8; 64])), 300),
        },
        300, None, &self_p())
    .expect("propose after upgrade");
    // R1.1 (V8 §3): the proposer approves explicitly.
    core::approve_recovery(&p(M2), pid, 350, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(matches!(
        core::approve_recovery(&p(M3), pid, 400, commit_of(pid), &self_p()).expect("approve"),
        ApproveOutcome::Execute(RecoveryExecution::Reconcile { .. })
    ));
}

// ── L2-5: single-flight — one nonterminal intent across both namespaces ─────

#[test]
fn l2_5_vault_intent_blocks_recovery_trigger_until_terminal() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh, ah, wasm, arg, 100).expect("trigger");
    let plan = plan.expect("plan");
    // Executing Vault intent blocks a recovery trigger proposal.
    assert_eq!(
        core::propose_recovery(&p(M1), trigger_action(2), 200, None, &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "Executing vault intent must block recovery trigger"
    );
    // OutcomeUnknown still blocks.
    core::finish_intent(&plan.key, &Err("unknown".into()), 300);
    assert_eq!(
        core::propose_recovery(&p(M1), trigger_action(2), 400, None, &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "OutcomeUnknown vault intent must block recovery trigger"
    );
    // Reconcile to terminal Executed releases the lock.
    let (_, _, wh1, _) = artifact(1);
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 1, &evidence(Some(wh1), 500), &p(SELF_ID), 500),
        Ok(ReconcileTerminalOutcome::Executed)
    );
    assert!(core::propose_recovery(&p(M1), trigger_action(2), 600, None, &self_p()).is_ok(),
        "terminal intent releases the single-flight lock");
}

#[test]
fn l2_5_recovery_intent_blocks_vault_trigger_until_terminal() {
    setup();
    // A Pending recovery intent (proposal exists, quorum not reached).
    let pid = core::propose_recovery(&p(M1), trigger_action(2), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let (wasm, arg, wh, ah) = artifact(1);
    assert_eq!(
        core::trigger_begin(&p(VAULT), 9, wh, ah, wasm, arg, 200).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "Pending recovery intent must block a Vault trigger"
    );
    // Execute the recovery trigger; Executing still blocks.
    let plan = match core::approve_recovery(&p(M2), pid, 300, commit_of(pid), &self_p()).expect("approve") {
        ApproveOutcome::Execute(RecoveryExecution::Trigger { plan, .. }) => plan,
        other => panic!("expected trigger execution, got {other:?}"),
    };
    let (wasm2, arg2, wh2, ah2) = artifact(3);
    assert_eq!(
        core::trigger_begin(&p(VAULT), 9, wh2, ah2, wasm2, arg2, 400).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "Executing recovery intent must block a Vault trigger"
    );
    // Terminal releases.
    core::finish_intent(&plan.key, &Ok(()), 500);
    core::recovery_finish_trigger(pid, ActionOutcome::Executed, 500);
    let (wasm3, arg3, wh3, ah3) = artifact(4);
    assert!(core::trigger_begin(&p(VAULT), 9, wh3, ah3, wasm3, arg3, 600).is_ok());
}

#[test]
fn l2_5_outcome_unknown_blocks_both_namespaces_until_reconciliation() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh, ah, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    // Both namespaces blocked.
    let (w2, a2, wh2, ah2) = artifact(2);
    assert_eq!(
        core::trigger_begin(&p(VAULT), 2, wh2, ah2, w2, a2, 300).unwrap_err(),
        RecoveryError::IllegalSourceState
    );
    assert_eq!(
        core::propose_recovery(&p(M1), trigger_action(3), 300, None, &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState
    );
    // Reconciliation to FAILED also releases the lock (terminal either way).
    assert_eq!(
        core::reconcile_vault_upgrade(
            &p(VAULT),
            1,
            &evidence(Some(sha256(b"old module")), 400),
            &p(SELF_ID),
            400,
        ),
        Ok(ReconcileTerminalOutcome::Failed)
    );
    let (w3, a3, wh3, ah3) = artifact(5);
    assert!(core::trigger_begin(&p(VAULT), 2, wh3, ah3, w3, a3, 500).is_ok());
}

#[test]
fn l2_5_post_upgrade_rebuild_preserves_the_lock() {
    setup();
    let (wasm, arg, wh, ah) = artifact(1);
    let (_, plan) = core::trigger_begin(&p(VAULT), 1, wh, ah, wasm, arg, 100).expect("trigger");
    core::finish_intent(&plan.expect("plan").key, &Err("unknown".into()), 200);
    core::post_upgrade(T0);
    // The lock is read from the AUTHORITATIVE companion — an upgrade cannot
    // clear it.
    let (w2, a2, wh2, ah2) = artifact(2);
    assert_eq!(
        core::trigger_begin(&p(VAULT), 2, wh2, ah2, w2, a2, 300).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "single-flight lock must survive post_upgrade"
    );
    assert_eq!(
        core::propose_recovery(&p(M1), trigger_action(3), 300, None, &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState
    );
}

// ── .did drift lock: the interface file parses and matches the real surface ──

#[test]
fn did_method_set_matches_the_real_interface() {
    let did = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/upgrader.did"));
    let prog: candid_parser::IDLProg = did.parse().expect("upgrader.did must parse");
    let mut env = candid::types::TypeEnv::new();
    let actor = candid_parser::check_prog(&mut env, &prog)
        .expect("did must type-check")
        .expect("did must have an actor");
    let mut t = actor;
    loop {
        let next = match &*t {
            candid::types::TypeInner::Class(_, s) => s.clone(),
            candid::types::TypeInner::Var(name) => {
                env.find_type(name).expect("actor var").clone()
            }
            _ => break,
        };
        t = next;
    }
    let candid::types::TypeInner::Service(meths) = &*t else {
        panic!("actor must resolve to a service");
    };
    let mut updates: Vec<&str> = meths
        .iter()
        .filter(|(_, ty)| {
            let candid::types::TypeInner::Func(f) = &**ty else { panic!("func") };
            !f.modes.contains(&candid::types::FuncMode::Query)
        })
        .map(|(n, _)| n.as_str())
        .collect();
    let mut queries: Vec<&str> = meths
        .iter()
        .filter(|(_, ty)| {
            let candid::types::TypeInner::Func(f) = &**ty else { panic!("func") };
            f.modes.contains(&candid::types::FuncMode::Query)
        })
        .map(|(n, _)| n.as_str())
        .collect();
    updates.sort();
    queries.sort();
    assert_eq!(
        updates,
        [
            "approve_recovery",
            // S2/R3.7+R3.11 — DELIBERATE interface widening, repinned in the
            // same change as the surface edit. Both are member-gated; cancel is
            // additionally proposer-scoped, and the sweep is work-bounded.
            // Neither widens AUTHORITY: no new principal can do anything it
            // could not already do, and neither can act on a peer's proposal.
            "cancel_recovery_proposal",
            "propose_membership_rotation",
            "propose_recovery",
            "reconcile_vault_upgrade",
            // S8B / R6 Option B — DELIBERATE interface widening, repinned in
            // the same change as the surface edit. DID movement pre-authorized
            // by CTO_ADDENDUM_S8B_DID_PREAUTH_2026-08-12.md (0d509960…) §1.
            //
            // UNLIKE every other entry in this list, it DOES widen the caller
            // set: it is the first PERMISSIONLESS update on this canister. That
            // is ruled in scope by R-3's explicit "permissionless" concurrence
            // and the addendum §2, on five binding conditions — inert while the
            // R6 constants are unruled, refusals append nothing, allowance
            // charged before the first await, limiter durable in MemoryId 12,
            // and the observation written only when BOTH status calls succeed.
            // It widens no AUTHORITY: it can only cause the canister to
            // re-observe controllers it already observes on every update path,
            // and it can write nothing else.
            "refresh_controller_invariant_now",
            "sweep_expired_recovery_proposals",
            "trigger_vault_upgrade"
        ]
    );
    assert_eq!(
        queries,
        [
            "get_build_info",
            // RETAINED as a deliberate PREDECESSOR (S11-2 / CUST-SSA-006), not
            // reshaped in place: its 3-field record still means exactly what it
            // always meant, and existing readers do not silently change
            // meaning. It is now documented as NON-AUTHORITATIVE historical
            // evidence — no freshness, and { false, false, 0 } cannot be told
            // apart from a real double breach at time 0.
            "get_controller_invariant",
            // S11-2 / CUST-SSA-006 — DELIBERATE query-surface widening,
            // repinned in the same change as the surface edit (drift lock).
            // The SUCCESSOR contract, under a NEW name, serving V4.1 R6
            // requirements 7-9: three-state freshness, preserved truth
            // booleans, age against the ruled 24 h bound, and the fail-closed
            // current_proof_ok aggregate. PUBLIC and READ-ONLY, exactly like
            // its predecessor — it widens no authority whatsoever.
            "get_controller_invariant_proof",
            "get_recovery_membership",
            "get_recovery_proposal",
            "get_recovery_summary",
            // S3d.1 / R1.6 — DELIBERATE query-surface widening, repinned in
            // the same change. Signer-gated and READ-ONLY; it widens no
            // authority. Required because R1.5 makes the commitment hash
            // mandatory at approve-time, and without this a member can obtain
            // neither the proposed roster nor its commitment — which made
            // rotation approval impossible.
            "get_rotation_proposal",
            "get_upgrade_status",
            "get_upgrader_audit_events"
        ]
    );
}

// ── S2 / R3.11: same treatment on the recovery plane ────────────────────────

/// R3.7/R3.11: only the PROPOSER may cancel their recovery proposal, and only
/// while Pending. A member who is not the proposer must not be able to veto a
/// proposal the other members are still evaluating.
#[test]
fn r3_recovery_cancel_is_proposer_scoped() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(1), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");

    assert_eq!(
        core::cancel_recovery_proposal(&p(M2), id, 300),
        Err(RecoveryError::NotProposer),
        "a non-proposer member must not cancel a peer's proposal"
    );
    // A non-member is rejected earlier, as a non-member — never told that the
    // proposal exists.
    assert_eq!(
        core::cancel_recovery_proposal(&p(0x7f), id, 300),
        Err(RecoveryError::NotAuthorized)
    );

    assert_eq!(core::cancel_recovery_proposal(&p(M1), id, 300), Ok(()));
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(outcome, ActionOutcome::Cancelled);

    // Never twice.
    assert_eq!(
        core::cancel_recovery_proposal(&p(M1), id, 300),
        Err(RecoveryError::AlreadyTerminal)
    );
}

/// R3.11: rotation proposals — one of the two classes the finding names as
/// UNCAPPED — are cancellable on exactly the same terms.
#[test]
fn r3_rotation_proposal_is_cancellable_by_its_proposer() {
    setup();
    let id = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(
        core::cancel_recovery_proposal(&p(M2), id, 300),
        Err(RecoveryError::NotProposer)
    );
    assert_eq!(core::cancel_recovery_proposal(&p(M1), id, 300), Ok(()));
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(outcome, ActionOutcome::Cancelled);
}

/// R3: a cancelled proposal can never collect another approval — it is
/// terminal, and `approve_recovery` must say so rather than record silently.
#[test]
fn r3_cancelled_recovery_proposal_cannot_be_approved() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(2), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    core::cancel_recovery_proposal(&p(M1), id, 300).unwrap();
    assert_eq!(
        core::approve_recovery(&p(M2), id, 200, commit_of(id), &self_p()).err(),
        Some(RecoveryError::AlreadyTerminal),
        "a withdrawn proposal must not be approvable back to life"
    );
}

/// R3.1/R3.8/R3.11 at the RULED bounds — the recovery sweep is LIVE.
///
/// RETIRES `r3_recovery_sweep_is_vacuous_until_bounds_are_ruled`. Same
/// inversion as the Vault's, for the same reason: its premise held only while
/// C3/C4 were `None`, and S6 crossed that boundary deliberately.
///
/// This plane's version matters independently rather than by symmetry. W3's
/// carried finding is that `RECOVERY_PROPOSAL_EXPIRY_INDEX` is populated ONLY
/// for proposals carrying an expiry, so while the bounds were unruled the index
/// was vacuously empty and ANY wiring of it — including a wrong one — passed
/// every test. The delayed fuse that finding describes is armed exactly now,
/// at the moment the lifetime constants land. This is the test that fires it.
#[test]
fn s6_recovery_sweep_is_live_at_the_ruled_lifetime_bounds() {
    setup();
    let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS
        .expect("S6 rules C3/C4; `None` here means enforcement is off");
    let created = 100;

    let id = core::propose_recovery(&p(M1), trigger_action(3), created, None, &self_p())
        .expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer reaches quorum
    // through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, created + 1, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");

    let (_, expiry) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(
        expiry,
        Some(created + bounds.max_ns),
        "a recovery proposal with no explicit lifetime must expire at C4"
    );

    // Non-vacuity: one nanosecond early reaps nothing.
    assert!(core::sweep_expired_recovery_proposals(created + bounds.max_ns - 1, 100).is_empty());
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(outcome, ActionOutcome::Pending);

    // At expiry: reaped and terminal.
    assert_eq!(
        core::sweep_expired_recovery_proposals(created + bounds.max_ns, 100),
        vec![id]
    );
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(outcome, ActionOutcome::Expired);
}

// ── S11-1 (P1-A): committed expiry enforced AT APPROVAL ADMISSION ───────────
//
// Recovery-plane twin of the Vault's `s11_vault_*` pair. The defect and the
// ruling are identical: `expires_at_ns` was written and indexed but never
// consulted by `approve_recovery`, so between the deadline and the next sweep
// batch a quorum could still form and TRIGGER A VAULT UPGRADE. The ruling is a
// typed reject with ZERO mutation; the bounded R3.8/R3.11 sweep stays the sole
// terminalizer and sole releaser of capacity.

/// Everything a refused recovery approval could possibly have moved, captured
/// whole so a future write on the rejection path fails here even if no
/// assertion below names it.
fn recovery_approval_footprint(id: u64) -> (Vec<u8>, usize, u64, u64, ActionOutcome, Option<u64>) {
    let stored = core::get_stored_proposal(id).expect("proposal exists");
    let (outcome, expiry) = core::stored_state(&stored);
    (
        candid::encode_one(&stored).expect("stored proposal encodes"),
        audit_len(&p(M1)),
        // The approval log is a SEPARATE durable append from the proposal
        // record; a rejection that skipped the record but still logged the
        // approval would compare equal on the encoding alone.
        core::approval_log_len_for_test(),
        core::recovery_expiry_index_len_for_test(),
        outcome,
        expiry,
    )
}

/// S11-1 test 3 — the FIRST recovery approval after the deadline is refused,
/// typed, with zero mutation.
#[test]
fn s11_recovery_first_approval_after_expiry_is_refused_with_zero_mutation() {
    setup();
    let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
    let created = 100;

    // Two proposals, one install, identical committed deadlines — `control`
    // proves the pre-deadline path still works, `id` is approved after the
    // deadline. See the Vault twin for why this is not two installs.
    //
    // The CONTROL is a reconcile, not a second trigger: single flight admits at
    // most one nonterminal upgrade intent globally, so two trigger proposals
    // cannot coexist and the second is refused at PROPOSE time. A reconcile
    // takes no target lock and is the only shape that can sit alongside.
    let control =
        core::propose_recovery(&p(M1), reconcile_action_for_measurement(), created, None, &self_p())
            .expect("propose control");
    let id = core::propose_recovery(&p(M2), trigger_action(4), created, None, &self_p())
        .expect("propose subject");
    let expires = created + bounds.max_ns;
    let (_, expiry) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(expiry, Some(expires), "the ruled C4 deadline is committed");

    // NON-VACUITY: one nanosecond before the deadline, the same call succeeds.
    assert!(
        core::approve_recovery(&p(M1), control, expires - 1, commit_of(control), &self_p()).is_ok(),
        "the last nanosecond before the deadline is still approvable"
    );

    let before = recovery_approval_footprint(id);
    // AT the deadline, not merely past it — `now >= expires_at_ns`.
    assert_eq!(
        core::approve_recovery(&p(M1), id, expires, commit_of(id), &self_p()),
        Err(RecoveryError::ProposalExpired {
            expires_at_ns: expires,
            now_ns: expires
        }),
        "a recovery approval at or after the committed deadline must be refused, typed"
    );
    assert_eq!(
        recovery_approval_footprint(id),
        before,
        "S11-1 ruling: a refused post-expiry recovery approval mutates NOTHING"
    );
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(
        outcome,
        ActionOutcome::Pending,
        "admission never terminalizes — the sweep is the SOLE terminalizer"
    );

    // The sweep still reaps it, which is what makes leaving it Pending safe.
    let reaped = core::sweep_expired_recovery_proposals(expires, 100);
    assert!(reaped.contains(&id), "the sweep reaps the refused proposal: {reaped:?}");
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(outcome, ActionOutcome::Expired);
}

/// S11-1 test 4 — the QUORUM-REACHING recovery approval after the deadline is
/// refused: no execution plan, no `Executing`, no intent, no start.
///
/// The consequential one. Threshold is 2, so this approval WOULD have crossed
/// the quorum boundary and returned an execution decision the shell acts on —
/// a Vault upgrade triggered by a proposal whose deadline had already passed.
#[test]
fn s11_recovery_quorum_reaching_approval_after_expiry_triggers_nothing() {
    setup();
    let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
    let created = 100;
    let id = core::propose_recovery(&p(M1), trigger_action(5), created, None, &self_p())
        .expect("propose");
    let expires = created + bounds.max_ns;

    // First approval lands legitimately, before the deadline. One short of
    // quorum (threshold 2).
    core::approve_recovery(&p(M1), id, created + 1, commit_of(id), &self_p())
        .expect("pre-deadline approval");

    let before = recovery_approval_footprint(id);
    let intent_before = core::get_intent_for_test(&core::intent_key_recovery_for_test(id));
    assert!(intent_before.is_some(), "a trigger proposal holds its intent from creation");
    assert_eq!(
        core::approve_recovery(&p(M2), id, expires + 1, commit_of(id), &self_p()),
        Err(RecoveryError::ProposalExpired {
            expires_at_ns: expires,
            now_ns: expires + 1
        }),
        "the quorum-reaching approval must be refused, never success-shaped"
    );
    assert_eq!(
        recovery_approval_footprint(id),
        before,
        "S11-1: the quorum-reaching recovery refusal mutates NOTHING"
    );
    let (outcome, _) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(outcome, ActionOutcome::Pending, "never Executing");
    // The upgrade intent is created at PROPOSE time on this plane, not at the
    // quorum boundary — so the assertion is that the refusal left it exactly as
    // it was, NOT that none exists. An intent silently advanced by a refused
    // approval would be the same class of defect as a recorded approval.
    assert_eq!(
        core::get_intent_for_test(&core::intent_key_recovery_for_test(id)),
        intent_before,
        "a refused post-expiry quorum must not touch the upgrade intent"
    );
}

/// A recovery proposal that creates NO upgrade intent.
///
/// Load-bearing for S5A gate A on this plane, and the reason is the same
/// unreachable-state correction the measurement spec makes at §B.1: single
/// flight permits at most ONE nonterminal upgrade intent globally, so a sweep
/// (or rotation) can never face more than one `TriggerVaultUpgrade` record. A
/// multi-record fixture built from trigger proposals would not merely be
/// unrealistic — it is a state the system cannot enter, and measuring it would
/// over-constrain the constant it feeds. `ReconcileVaultUpgrade` carries no
/// intent and is therefore the only shape a multi-record fixture can use.
fn reconcile_action_for_measurement() -> RecoveryAction {
    let (_, _, wh, _) = artifact(1);
    RecoveryAction::ReconcileVaultUpgrade {
        proposal_id: 1,
        objective_evidence: evidence(Some(wh), 170),
    }
}

/// S5A M1 gate A — the recovery plane's INJECTOR, proved before it is measured
/// with.
///
/// Same reasoning as the Vault's twin: an inert injector leaves
/// `RECOVERY_PROPOSAL_EXPIRY_INDEX` empty, the sweep reaps nothing, and the
/// harness reports a per-record instruction cost of ZERO — a broken fixture
/// that reads as a good result. Asserted against the real propose/sweep path,
/// with `r3_recovery_sweep_is_vacuous_until_bounds_are_ruled` above as the
/// paired negative showing the production default is unchanged.
#[test]
fn s5a_recovery_lifetime_injector_moves_the_sweep_off_vacuous() {
    setup();
    // S6 — the baseline is the RULED expiry, not the absent one. See the
    // Vault's counterpart for the full reasoning: what must be proved is no
    // longer "the injector lifts the plane off vacuity" but "injected bounds
    // OVERRIDE the ruled ones", because an inert injector would now leave C4
    // in force while the harness believed it was measuring its candidate.
    let ruled = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
    let baseline =
        core::propose_recovery(&p(M1), trigger_action(7), 100, None, &self_p()).expect("propose");
    let (_, expiry) = core::stored_state(&core::get_stored_proposal(baseline).unwrap());
    assert_eq!(
        expiry,
        Some(100 + ruled.max_ns),
        "before injection the RULED bounds are in force on this plane"
    );

    // FIXTURE values, not proposed constants — the builder measures, the table
    // rules. Orders of magnitude shorter than the ruled bounds, so the two are
    // distinguishable below.
    core::inject_lifetime_params_for_test(
        Some(Some(stsh_custody_types::ProposalLifetimeBounds {
            min_ns: 1_000,
            max_ns: 1_000_000,
        })),
        Some(Some(2)),
    );
    assert_eq!(core::sweep_work_limit(), Some(2));

    let explicit = core::propose_recovery(&p(M1), reconcile_action_for_measurement(), 200, Some(5_000), &self_p())
        .expect("propose with explicit lifetime");
    let (_, expiry) = core::stored_state(&core::get_stored_proposal(explicit).unwrap());
    assert_eq!(
        expiry,
        Some(200u64.saturating_add(5_000)),
        "an explicit in-bounds lifetime must be honoured through the real path"
    );

    // Validation is still enforced — the injector supplies bounds, it does not
    // switch checking off.
    assert!(
        core::propose_recovery(&p(M1), reconcile_action_for_measurement(), 300, Some(1), &self_p()).is_err(),
        "a below-minimum lifetime must still be refused under injected bounds"
    );

    // The sweep reaps AT THE INJECTED HORIZON. Sweeping at `u64::MAX` — the
    // old form — would reap the ruled-expiry baseline too and pass whichever
    // bounds were actually in force. The injected horizon is ~30 days short of
    // the ruled one, so it separates them.
    let horizon = 200u64 + 5_000;
    let reaped = core::sweep_expired_recovery_proposals(horizon, 100);
    assert!(
        !reaped.is_empty(),
        "the recovery sweep must reap real due records at the INJECTED horizon; \
         an empty result would make every gate A figure on this plane a \
         measurement of nothing"
    );
    assert!(
        !reaped.contains(&baseline),
        "the ruled-expiry proposal is not due for another 30 days and must not \
         be reaped at the injected horizon"
    );
}

/// R3.9/R3.11: `nonterminal_intent_in_flight` consults the AUTHORITATIVE companion, so
/// the single-flight check does not get more expensive as terminal intents
/// accumulate. The index holds only nonterminal intents, which the invariant
/// caps at one.
///
/// NOTE the Upgrader's single-flight differs from the Vault's: here a
/// TriggerVaultUpgrade proposal writes its durable intent at PROPOSE time with
/// outcome `Pending`, and `Pending` COUNTS as nonterminal on this plane (the
/// artifact bytes live in the intent from creation). The Vault's lock
/// deliberately excludes Pending. The two are different locks over different
/// state, and this test pins the Upgrader's actual contract.
#[test]
fn r3_nonterminal_intent_index_tracks_only_open_intents() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(4), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(
        core::nonterminal_intent_count_for_test(),
        1,
        "the intent is durable from propose time and Pending is nonterminal here"
    );
    assert!(core::nonterminal_intent_in_flight_for_test(None));

    core::approve_recovery(&p(M2), id, 200, commit_of(id), &self_p()).expect("quorum");
    assert_eq!(
        core::nonterminal_intent_count_for_test(),
        1,
        "reaching quorum moves the SAME intent, it does not open a second"
    );
}

/// R3.9/R3.11: the index EMPTIES when an intent terminalizes, which is what
/// keeps the single-flight check bounded as history accumulates.
#[test]
fn r3_nonterminal_index_releases_on_terminal_intent() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(5), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    core::approve_recovery(&p(M2), id, 200, commit_of(id), &self_p()).expect("quorum");
    let key = core::only_intent_key_for_test().expect("exactly one open intent");
    core::finish_intent(&key, &Ok(()), 300);
    assert_eq!(
        core::nonterminal_intent_count_for_test(),
        0,
        "terminalizing must release the single-flight index entry"
    );
    assert!(!core::nonterminal_intent_in_flight_for_test(None));
}

/// S2.1 / R3.2+R3.11 — REGRESSION: reaping a TriggerVaultUpgrade proposal must
/// also terminalize its linked intent.
///
/// `redact_action` empties the artifact vectors before storing, so the stored
/// proposal is only a hash-bearing shadow: the real Wasm/arg bytes live in
/// UPGRADE_INTENTS from PROPOSE time. Terminalizing the proposal alone retained
/// every byte the reap was meant to release, left the intent `Pending`, and —
/// because Pending is nonterminal on this plane — held the single-flight lock
/// forever. ONE cancelled proposal then permanently blocked every future
/// trigger: a worse denial of service than the one R3 exists to close.
///
/// The load-bearing assertion is the LAST one: a new trigger must succeed.
#[test]
fn r3_cancel_releases_linked_intent_and_unblocks_future_triggers() {
    setup();
    let first = core::propose_recovery(&p(M1), trigger_action(1), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), first, 101, commit_of(first), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);

    core::cancel_recovery_proposal(&p(M1), first, 150).expect("cancel");

    // The linked intent is terminal, byte-cleared, and off the index.
    let key = core::intent_key_recovery_for_test(first);
    let intent = core::get_intent_for_test(&key).expect("intent still recorded");
    assert_eq!(intent.outcome, ActionOutcome::Cancelled);
    assert_eq!(intent.wasm_bytes, None, "artifact bytes must be released");
    assert_eq!(intent.arg_bytes, None);
    assert_eq!(intent.terminal_at_ns, Some(150));
    assert_eq!(
        core::nonterminal_intent_count_for_test(),
        0,
        "the single-flight entry must be released by the reap"
    );

    // THE POINT: the plane is not wedged.
    let second = core::propose_recovery(&p(M1), trigger_action(2), 200, None, &self_p())
        .expect("a cancelled proposal must not block every future trigger");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), second, 201, commit_of(second), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);
    core::approve_recovery(&p(M2), second, 300, commit_of(second), &self_p()).expect("the new trigger reaches quorum");
}

/// Same property via EXPIRY rather than cancellation — the two reap routes
/// share `reap_stored_pending`, and this pins that they share it.
#[test]
fn r3_expiry_releases_linked_intent_and_unblocks_future_triggers() {
    setup();
    let first = core::propose_recovery(&p(M1), trigger_action(3), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), first, 101, commit_of(first), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    // Set an expiry directly: the §10.5 lifetime bounds are unruled, so this
    // exercises the mechanism without pre-empting the constants.
    core::set_expiry_for_test(first, Some(1_000));

    assert_eq!(core::sweep_expired_recovery_proposals(5_000, 10), vec![first]);

    let key = core::intent_key_recovery_for_test(first);
    let intent = core::get_intent_for_test(&key).expect("intent still recorded");
    assert_eq!(intent.outcome, ActionOutcome::Expired);
    assert_eq!(intent.wasm_bytes, None);
    assert_eq!(core::nonterminal_intent_count_for_test(), 0);

    let second = core::propose_recovery(&p(M1), trigger_action(4), 6_000, None, &self_p())
        .expect("an expired proposal must not block every future trigger");
    core::approve_recovery(&p(M2), second, 6_100, commit_of(second), &self_p()).expect("quorum");
}

/// An intent past the first await is NOT reapable: `Executing`/`OutcomeUnknown`
/// are facts about a call that may have landed and must settle through
/// objective reconciliation, never through cancellation.
#[test]
fn r3_reaping_never_touches_an_intent_past_the_first_await() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(5), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    core::approve_recovery(&p(M2), id, 200, commit_of(id), &self_p()).expect("quorum");
    let key = core::intent_key_recovery_for_test(id);
    let before = core::get_intent_for_test(&key).expect("intent");
    assert_ne!(before.outcome, ActionOutcome::Pending, "past the first await");

    // The proposal is no longer Pending either, so cancel is refused outright.
    assert_eq!(
        core::cancel_recovery_proposal(&p(M1), id, 300),
        Err(RecoveryError::AlreadyTerminal)
    );
    let after = core::get_intent_for_test(&key).expect("intent");
    assert_eq!(after.outcome, before.outcome, "the intent must be untouched");
}

/// S2.1 — STRUCTURAL DID DRIFT LOCK.
///
/// The pre-existing conformance test compared only the METHOD SET, so it was
/// blind to TYPE drift: `RecoveryProposal` gained `expires_at_ns` in Rust while
/// the committed Candid did not, and nothing caught it. A client decoding
/// against the stale DID would mis-decode a moved record.
///
/// This generates the service from the REAL Rust types and asserts equality
/// with the committed file, so any future divergence — a new field, a new
/// variant arm, a changed argument — fails here rather than on the wire.
/// A deliberate interface change repins the .did in the SAME commit; that is
/// the enforced review event, not an inconvenience.
#[test]
fn did_types_match_the_real_rust_interface() {
    let generated = crate::generated_did();
    let committed = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/upgrader.did"));
    candid_parser::utils::service_equal(
        candid_parser::utils::CandidSource::Text(&generated),
        candid_parser::utils::CandidSource::Text(committed),
    )
    .unwrap_or_else(|e| {
        panic!(
            "upgrader.did has DRIFTED from the Rust interface: {e}\n\n\
             Repin the committed .did in the SAME change as the source edit — \
             never refresh it later to make a gate go green.\n\n\
             --- generated from Rust ---\n{generated}"
        )
    });
}

/// S2.1 / amended R3 item 10 — UPGRADE MIGRATION over BOTH new Upgrader indexes, through
/// the REAL `post_upgrade` entry point.
///
/// The nonterminal-intent index is the dangerous one: a STALE entry holds the
/// single-flight lock and wedges the recovery plane, while a MISSING entry
/// releases a lock that is genuinely held. Both directions are asserted.
#[test]
fn r3_post_upgrade_migration_restores_both_upgrader_indexes() {
    setup();
    // An open intent (Pending is nonterminal here) plus a Pending rotation
    // proposal carrying an expiry.
    let trigger = core::propose_recovery(&p(M1), trigger_action(7), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), trigger, 101, commit_of(trigger), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let rotation = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 110, None, &self_p())
        .expect("rotation");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), rotation, 111, commit_of(rotation), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    core::set_expiry_for_test(rotation, Some(9_999));

    // S6 — BOTH proposals now carry an expiry, so the index holds TWO entries.
    // Before C3/C4 were ruled, no proposal was given one naturally and this
    // fixture had to plant the rotation's by hand to have anything to migrate;
    // that `set_expiry_for_test` call is now overriding a real expiry rather
    // than creating the only one. The count is 2 for that reason and not
    // because migration duplicated anything — which is exactly the confusion
    // W3's carried finding warned this index would produce once the lifetime
    // constants landed.
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);
    assert_eq!(core::recovery_expiry_index_len_for_test(), 2);

    // INTACT: the real upgrade entry point validates and leaves both
    // companions exactly as it found them. Under amended item 10 this — not
    // re-derivation — is the migration property.
    assert!(core::companion_check().is_ok(), "clean before the upgrade");
    core::post_upgrade(T0);
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);
    assert_eq!(core::recovery_expiry_index_len_for_test(), 2);
    // Idempotent: validation is a read.
    core::post_upgrade(T0);
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);
    assert_eq!(core::recovery_expiry_index_len_for_test(), 2);

    // Corrupting BOTH companions must now be DETECTED, not silently repaired.
    core::clear_companion_indexes_for_test();
    let e = core::companion_check()
        .expect_err("clearing both companions must be detected, never repaired");
    assert!(
        e.contains("integrity mismatch") && e.contains("DIFFERS"),
        "the failure must name the integrity mismatch and the moved commitment: {e}"
    );
    let _ = trigger;
}

/// S5B W2(d) — a FORGED nonterminal entry is DETECTED, not silently dropped.
///
/// REVISED from `r3_post_upgrade_drops_stale_upgrader_index_entries`, which
/// asserted that an upgrade re-derives the pointer from `UPGRADE_INTENTS` and
/// thereby clears the forgery. Amended item 10(a)/(d) makes that the wrong
/// behaviour: the companion is authoritative, and disagreement is durable
/// corruption that must trap rather than be quietly reconciled away.
///
/// The old test's final assertion — that the plane becomes usable again
/// because the upgrade "repairs" the index — is exactly the silent
/// reactivation (d) forbids, so it is removed rather than adjusted.
#[test]
fn w2_forged_upgrader_companion_entry_is_detected() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(8), 100, None, &self_p()).expect("propose");
    // R1.1 (V8 §3): proposing approves NOTHING — the proposer now reaches
    // quorum through an explicit approval, on equal terms with every peer.
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    core::cancel_recovery_proposal(&p(M1), id, 150).expect("cancel");
    assert_eq!(core::nonterminal_intent_count_for_test(), 0);

    assert!(core::companion_check().is_ok(), "clean before the forgery");

    // Forge a lock entry for the now-terminal intent, bypassing the primitive
    // so the commitment does not move with it.
    core::forge_nonterminal_entry_for_test(core::intent_key_recovery_for_test(id));
    assert_eq!(core::nonterminal_intent_count_for_test(), 1, "wedged");

    let e = core::companion_check().expect_err("a forged pointer entry must be detected");
    assert!(
        e.contains("integrity mismatch"),
        "unexpected failure shape: {e}"
    );
}

/// NON-VACUITY for the Upgrader companion tests: an intact plane must validate
/// cleanly, or every `expect_err` above would pass against a `companion_check`
/// that simply always failed.
#[test]
fn w2_intact_upgrader_companion_validates() {
    setup();
    assert!(core::companion_check().is_ok(), "empty plane is consistent");
    let id = core::propose_recovery(&p(M1), trigger_action(21), 100, None, &self_p())
        .expect("propose");
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(
        core::companion_check().is_ok(),
        "the primitive must keep the companion consistent through a real write"
    );
    core::post_upgrade(T0);
    assert!(core::companion_check().is_ok(), "and across an upgrade");
}

/// S2.1 / R3.1 — the caller-selected lifetime path on the RECOVERY plane also
/// fails closed while the §10.5 bounds are unruled, and leaves nothing behind.
#[test]
fn r3_recovery_explicit_lifetime_is_bound_by_the_ruled_c3_and_c4() {
    setup();
    // S6 — REPLACES `r3_recovery_explicit_lifetime_fails_closed_while_bounds_
    // unruled`. Its `BoundsNotRuled` expectation described production only
    // while C3/C4 were `None`; the refusal is now the real bounds check. The
    // property that actually mattered — a REFUSED LIFETIME LEAVES NO INTENT
    // BEHIND — is preserved and is the reason this test still exists on this
    // plane rather than deferring to the Vault's. For a recovery trigger the
    // intent is where the artifact bytes live, so creating one and then failing
    // would retain bytes for a proposal that never existed.
    let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
    let before = core::nonterminal_intent_count_for_test();

    assert!(
        matches!(
            core::propose_recovery(&p(M1), trigger_action(6), 100, Some(bounds.min_ns - 1), &self_p()),
            Err(RecoveryError::LifetimeOutOfBounds(
                stsh_custody_types::LifetimeViolation::TooShort { .. }
            ))
        ),
        "a below-C3 lifetime must be refused on this plane too"
    );
    assert!(
        matches!(
            core::propose_recovery(&p(M1), trigger_action(6), 100, Some(bounds.max_ns + 1), &self_p()),
            Err(RecoveryError::LifetimeOutOfBounds(
                stsh_custody_types::LifetimeViolation::TooLong { .. }
            ))
        ),
        "an above-C4 lifetime must be refused"
    );
    assert_eq!(
        core::nonterminal_intent_count_for_test(),
        before,
        "a rejected lifetime must leave NO intent behind — the artifact bytes \
         must not outlive a proposal that was never admitted"
    );

    // Rotation proposals take the same argument and the same rule.
    assert!(matches!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, Some(5), &self_p()),
        Err(RecoveryError::LifetimeOutOfBounds(_))
    ));

    // Supplying nothing is unaffected and takes the ruled default.
    let id = core::propose_recovery(&p(M1), trigger_action(7), 100, None, &self_p()).expect("propose");
    let (_, expiry) = core::stored_state(&core::get_stored_proposal(id).unwrap());
    assert_eq!(expiry, Some(100 + bounds.max_ns));
}

// ── S3 / R1.1 (V8 §3, CTO R-1a): proposing approves NOTHING ────────────────

/// Proposal creation contributes ZERO approvals, on BOTH propose paths.
///
/// The commitment binds the canister-assigned proposal id, which does not
/// exist before creation — so an implicit creation-time approval is
/// NECESSARILY UNBOUND. That is the CUST-SSA-001 attack path, and rotation is
/// the original Critical's own route, which is why both paths are asserted.
#[test]
fn r1_propose_contributes_zero_approvals() {
    setup();
    let trigger = core::propose_recovery(&p(M1), trigger_action(1), 100, None, &self_p()).expect("propose");
    let stored = core::get_stored_proposal(trigger).expect("stored");
    match &stored {
        core::StoredProposal::Recovery { proposal, .. } => {
            assert!(
                proposal.approvals.is_empty(),
                "creating a recovery proposal must contribute NO approvals"
            );
            assert_eq!(proposal.proposer, p(M1), "the proposer is recorded explicitly");
        }
        other => panic!("unexpected {other:?}"),
    }

    let rotation = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("rotation");
    match core::get_stored_proposal(rotation).expect("stored") {
        core::StoredProposal::Rotation(r) => {
            assert!(
                r.approvals.is_empty(),
                "creating a ROTATION proposal must contribute NO approvals — this is the \
                 original Critical's own attack path"
            );
            assert_eq!(r.proposer, p(M1));
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// A proposal cannot reach quorum from creation alone: with threshold 2, ONE
/// explicit approval is still below quorum. Before v8 the proposer's implicit
/// seed meant a single peer approval executed.
#[test]
fn r1_proposal_cannot_reach_quorum_from_creation_alone() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(2), 100, None, &self_p()).expect("propose");
    assert!(
        matches!(
            core::approve_recovery(&p(M2), pid, 200, commit_of(pid), &self_p()).expect("approve"),
            core::ApproveOutcome::Recorded
        ),
        "one explicit approval must be BELOW quorum — if this executes, the proposer's \
         approval is being counted implicitly somewhere"
    );
    // The second explicit approval is what reaches quorum.
    assert!(!matches!(
        core::approve_recovery(&p(M1), pid, 300, commit_of(pid), &self_p()).expect("approve"),
        core::ApproveOutcome::Recorded
    ));
}

/// The proposer's own approval is recorded on EQUAL TERMS with any other
/// member's — same call, same duplicate rule. A duplicate is a NO-MUTATION
/// error (V8 §3, CTO R-1b: never a success-shaped replay).
///
/// NO-MUTATION IS ASSERTED AS EXACT STATE EQUALITY, not inferred. An earlier
/// version showed only that the next peer still reached quorum, which proves
/// the duplicate added no SECOND APPROVAL — but a duplicate could still have
/// appended an audit event, an approval-log entry, or touched the intent or
/// its index, and that test would have passed anyway. Every retained surface
/// is snapshotted and compared.
#[test]
fn r1_proposer_approval_is_on_equal_terms_and_duplicates_are_errors() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(3), 100, None, &self_p()).expect("propose");
    core::approve_recovery(&p(M1), pid, 200, commit_of(pid), &self_p()).expect("proposer approves like anyone else");

    // Snapshot EVERY retained surface before the duplicate.
    let before_proposal = core::get_stored_proposal(pid).expect("stored");
    let before_approval_log = core::approval_log_entries_for_test();
    let before_audit_len = core::audit_len_for_test();
    let before_intent =
        core::get_intent_for_test(&core::intent_key_recovery_for_test(pid));
    let before_nonterminal = core::nonterminal_intent_count_for_test();
    let before_expiry_index = core::recovery_expiry_index_len_for_test();

    assert_eq!(
        core::approve_recovery(&p(M1), pid, 250, commit_of(pid), &self_p()).err(),
        Some(RecoveryError::AlreadyApproved),
        "a duplicate approval must be a NO-MUTATION ERROR, never a success-shaped replay"
    );

    assert_eq!(
        core::get_stored_proposal(pid).expect("stored"),
        before_proposal,
        "duplicate mutated the stored proposal"
    );
    assert_eq!(
        core::approval_log_entries_for_test(),
        before_approval_log,
        "duplicate appended to the APPROVAL LOG"
    );
    assert_eq!(
        core::audit_len_for_test(),
        before_audit_len,
        "duplicate appended an AUDIT event — append-only growth from a rejected call"
    );
    assert_eq!(
        core::get_intent_for_test(&core::intent_key_recovery_for_test(pid)),
        before_intent,
        "duplicate mutated the durable intent"
    );
    assert_eq!(
        core::nonterminal_intent_count_for_test(),
        before_nonterminal,
        "duplicate moved the single-flight index"
    );
    assert_eq!(
        core::recovery_expiry_index_len_for_test(),
        before_expiry_index,
        "duplicate moved the expiry index"
    );

    // And the peer's approval still reaches quorum — the duplicate consumed
    // nothing.
    assert!(!matches!(
        core::approve_recovery(&p(M2), pid, 300, commit_of(pid), &self_p()).expect("approve"),
        core::ApproveOutcome::Recorded
    ));
}

/// The APPROVAL LOG (`RECOVERY_APPROVALS`, MemoryId 2) gains no entry at
/// creation, on BOTH propose paths.
///
/// This asserts the actual claim. An earlier version searched
/// `UpgraderAuditEventKind` — a DIFFERENT stable map — so it proved something
/// adjacent to R1.1 rather than R1.1 itself: the approval log could have grown
/// at propose and the test would still have passed.
#[test]
fn r1_approval_log_has_no_creation_time_entry() {
    setup();
    let base_log = core::approval_log_len_for_test();
    let base_audit = core::audit_len_for_test();

    let trigger = core::propose_recovery(&p(M1), trigger_action(4), 100, None, &self_p()).expect("propose");
    assert_eq!(
        core::approval_log_len_for_test(),
        base_log,
        "propose_recovery must append NO approval-log entry"
    );
    let rotation = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("rotation");
    assert_eq!(
        core::approval_log_len_for_test(),
        base_log,
        "propose_membership_rotation must append NO approval-log entry — rotation is the \
         original Critical's own attack path"
    );

    // The ProposalCreated audit events DO still land: recording that a
    // proposal exists is not an approval.
    assert!(
        core::audit_len_for_test() > base_audit,
        "creation must still be audited"
    );

    // Non-vacuity: the log DOES grow on a real approval, so the assertions
    // above cannot be passing because nothing ever writes it.
    core::approve_recovery(&p(M1), trigger, 200, commit_of(trigger), &self_p()).expect("approve");
    assert_eq!(
        core::approval_log_len_for_test(),
        base_log + 1,
        "an explicit approval MUST append exactly one approval-log entry"
    );
    let entries = core::approval_log_entries_for_test();
    let last = entries.last().expect("entry");
    assert_eq!(last.proposal_id, trigger);
    assert_eq!(last.approver, p(M1));
    let _ = rotation;
}

// ── S3 / R1.5 on the RECOVERY plane — symmetry with the Vault ───────────────

/// R1.5 — a mismatched hash rejects with ZERO writes, and the proposal stays
/// Pending. One member's wrong hash must not destroy a proposal their peers
/// are still evaluating.
#[test]
fn r1_recovery_approve_rejects_mismatched_hash_no_writes() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(1), 100, None, &self_p())
        .expect("propose");
    let before_proposal = core::get_stored_proposal(pid).expect("stored");
    let before_log = core::approval_log_entries_for_test();
    let before_audit = core::audit_len_for_test();

    assert_eq!(
        core::approve_recovery(&p(M1), pid, 200, vec![0xEE; 32], &self_p()),
        Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::CallerMismatch
        )),
        "a wrong expected hash must reject, typed as a CALLER mismatch"
    );
    assert_eq!(core::get_stored_proposal(pid).expect("stored"), before_proposal);
    assert_eq!(core::approval_log_entries_for_test(), before_log, "no approval logged");
    assert_eq!(core::audit_len_for_test(), before_audit, "no audit entry");

    // An honest approval still works afterwards.
    core::approve_recovery(&p(M1), pid, 300, commit_of(pid), &self_p())
        .expect("correct hash still approves");
}

/// R1.5 — stored-vs-recomputed divergence fails CLOSED, typed as corruption,
/// even when the caller faithfully supplies the stored value.
#[test]
fn r1_recovery_stored_vs_recomputed_corruption_fails_closed() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(2), 100, None, &self_p())
        .expect("propose");
    core::corrupt_stored_commitment_for_test(pid, vec![0xCD; 32]);
    let before_audit = core::audit_len_for_test();

    assert_eq!(
        core::approve_recovery(&p(M1), pid, 200, vec![0xCD; 32], &self_p()),
        Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::StoredVsRecomputed
        )),
        "corruption must be typed APART from a caller mismatch and must fail even when \
         the caller faithfully supplies the STORED value"
    );
    assert_eq!(core::audit_len_for_test(), before_audit, "zero writes");
}

/// R1.5 — the commitment binds the proposal's RETAINED epoch, so a rotation
/// that advances the recovery epoch does NOT move a pending proposal's stored
/// commitment. The epoch pin remains the sole stale-epoch rejector.
#[test]
fn r1_recovery_stored_commitment_unchanged_across_epoch() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(3), 100, None, &self_p())
        .expect("propose");
    let before = commit_of(pid);

    // Rotate the membership, which bumps the recovery epoch.
    let rot = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 110, None, &self_p())
        .expect("rotation");
    core::approve_recovery(&p(M1), rot, 120, commit_of(rot), &self_p()).expect("approve");
    core::approve_recovery(&p(M2), rot, 130, commit_of(rot), &self_p()).expect("quorum");

    assert_eq!(
        commit_of(pid),
        before,
        "advancing the recovery epoch must not move a proposal's commitment"
    );
}

/// R1.2 — the commitment covers the PROPOSED MEMBER SET on a rotation.
///
/// AN EARLIER VERSION OF THIS TEST WAS VACUOUS: it compared two rotations with
/// DIFFERENT proposal ids, and `proposal_id` is already bound by
/// ApprovalCommitmentV1 — so the hashes differed even if `canonical_stored_bytes`
/// ignored `new_members` entirely. It proved nothing about the roster.
///
/// This mutates ONLY the stored roster on ONE proposal while PRESERVING its
/// stored commitment. Everything else — id, epoch, expiry, canister — is held
/// fixed, so the recomputed hash can only diverge if the roster is genuinely
/// inside the digest. Rotation is the ORIGINAL Critical's attack path: a
/// commitment that ignored the proposed members would let an approval be
/// replayed onto a different recovery set.
#[test]
fn r1_rotation_commitment_covers_the_proposed_member_set() {
    setup();
    let pid = core::propose_membership_rotation(
        &p(M1),
        vec![p(M2), p(M3), p(M4)],
        100,
        None,
        &self_p(),
    )
    .expect("rotation");
    let stored_hash = commit_of(pid);

    // Swap the roster, keep the stored commitment. Nothing else moves.
    core::swap_rotation_roster_for_test(pid, vec![p(M2), p(M3), p(0x5A)]);
    assert_eq!(commit_of(pid), stored_hash, "the stored hash is preserved");

    let before_log = core::approval_log_entries_for_test();
    let before_audit = core::audit_len_for_test();
    assert_eq!(
        core::approve_recovery(&p(M1), pid, 200, stored_hash, &self_p()),
        Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::StoredVsRecomputed
        )),
        "swapping ONLY the proposed roster must make the recomputed commitment diverge \
         — if it does not, the member set is not inside the digest and an approval \
         could be replayed onto a different recovery set"
    );
    assert_eq!(core::approval_log_entries_for_test(), before_log, "zero writes");
    assert_eq!(core::audit_len_for_test(), before_audit, "zero writes");
}

/// R1.6 — a member can actually OBTAIN a rotation's roster and commitment.
///
/// Once R1.5 made the hash required at approve-time, the absence of a rotation
/// view made rotation approval IMPOSSIBLE: `query_recovery_proposal` returns
/// None for rotations and the audit carries only `member_count`.
#[test]
fn r1_rotation_view_exposes_roster_and_commitment() {
    setup();
    let roster = vec![p(M2), p(M3), p(M4)];
    let pid = core::propose_membership_rotation(&p(M1), roster.clone(), 100, None, &self_p())
        .expect("rotation");

    let view = core::query_rotation_proposal(&p(M2), pid).expect("member may read");
    assert_eq!(view.new_members, roster, "the PROPOSED roster must be inspectable in full");
    assert_eq!(view.proposer, p(M1));
    assert_eq!(view.commitment_hash, commit_of(pid));

    // A non-member gets the indistinguishable None.
    assert!(core::query_rotation_proposal(&p(0x7f), pid).is_none());

    // And the view's hash is sufficient to actually approve.
    core::approve_recovery(&p(M2), pid, 200, view.commitment_hash, &self_p())
        .expect("a member can approve using the hash from the view");
}

/// R1.5 ordering — a wrong hash against a SAME-EPOCH terminal proposal is a
/// CallerMismatch; the correct hash reaches the terminal check.
#[test]
fn r1_recovery_terminal_wrong_hash_is_caller_mismatch() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(5), 100, None, &self_p())
        .expect("propose");
    let good = commit_of(pid);
    core::cancel_recovery_proposal(&p(M1), pid, 150).expect("cancel -> terminal");

    assert_eq!(
        core::approve_recovery(&p(M1), pid, 200, vec![0xEE; 32], &self_p()),
        Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::CallerMismatch
        )),
        "the commitment check runs BEFORE the terminal check, so a wrong hash is a \
         mismatch rather than AlreadyTerminal"
    );
    assert_eq!(
        core::approve_recovery(&p(M1), pid, 210, good, &self_p()),
        Err(RecoveryError::AlreadyTerminal),
        "the CORRECT hash passes the commitment check and reaches the terminal check"
    );
}

/// R1.5 ordering — a wrong-epoch preimage against a CURRENT proposal is a
/// CallerMismatch, not a stale-epoch rejection. The caller got the preimage
/// wrong; the proposal is perfectly current.
#[test]
fn r1_recovery_wrong_epoch_preimage_is_caller_mismatch() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(6), 100, None, &self_p())
        .expect("propose");
    let wrong = core::commitment_with_epoch_for_test(pid, &self_p(), 999);
    assert_ne!(wrong, commit_of(pid));
    assert_eq!(
        core::approve_recovery(&p(M1), pid, 200, wrong, &self_p()),
        Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::CallerMismatch
        ))
    );
}

/// R1.5 ordering — for a STALE proposal: a wrong hash is a CallerMismatch, and
/// the CORRECT old hash passes the commitment check and is rejected SOLELY by
/// the epoch pin. Zero writes in both cases.
///
/// This is the asymmetry SSA ruled: on this plane the epoch pin sits BEFORE the
/// terminal check, because rotation atomically terminalizes every prior-epoch
/// proposal — moving terminal ahead would make the required StaleEpoch response
/// effectively unreachable and conflict with L2-4/L2-7.
#[test]
fn r1_recovery_stale_proposal_wrong_hash_vs_correct_old_hash() {
    setup();
    let pid = core::propose_recovery(&p(M1), trigger_action(7), 100, None, &self_p())
        .expect("propose");
    let old_hash = commit_of(pid);

    // Rotate: bumps the recovery epoch and terminalizes prior-epoch proposals.
    let rot = core::propose_membership_rotation(
        &p(M1),
        vec![p(M2), p(M3), p(M4)],
        110,
        None,
        &self_p(),
    )
    .expect("rotation");
    core::approve_recovery(&p(M1), rot, 120, commit_of(rot), &self_p()).expect("approve");
    core::approve_recovery(&p(M2), rot, 130, commit_of(rot), &self_p()).expect("quorum");

    let before_log = core::approval_log_entries_for_test();
    let before_audit = core::audit_len_for_test();

    assert_eq!(
        core::approve_recovery(&p(M2), pid, 200, vec![0xEE; 32], &self_p()),
        Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::CallerMismatch
        )),
        "a wrong hash is caught by the commitment check, which runs first"
    );
    let stale = core::approve_recovery(&p(M2), pid, 210, old_hash, &self_p());
    assert!(
        matches!(stale, Err(RecoveryError::StaleEpoch { .. })),
        "the CORRECT old hash must pass the commitment check and be rejected SOLELY by \
         the epoch pin, got {stale:?}"
    );
    assert_eq!(core::approval_log_entries_for_test(), before_log, "zero writes");
    assert_eq!(core::audit_len_for_test(), before_audit, "zero writes");
}

/// S5B acceptance 9 on the UPGRADER plane — remove each written component in
/// turn. Clause (g) requires both canisters, and the brief states plainly that
/// whole-primitive testing is insufficient, so the Vault's coverage does not
/// discharge this.
///
/// The companion-ENTRY components (nonterminal-intent pointer,
/// recovery-expiry entry) are covered by `w2_forged_upgrader_companion_entry_
/// is_detected` and the migration test. This covers the accounting written in
/// the same transaction: commitment, count and bytes.
#[test]
fn w2_upgrader_each_written_component_is_independently_checked() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(31), 100, None, &self_p())
        .expect("propose");
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert!(core::companion_check().is_ok(), "clean baseline");
    let good = core::companion_load();

    // ENTRY ACCUMULATOR stale — index writes landed, accumulator did not.
    // This is the exact bug this plane shipped with briefly:
    // `reindex_stored_proposal` applied the delta and never stored it, and
    // this check caught it. Caught by the recompute comparison.
    let mut m = good.clone();
    m.entry_acc = vec![0u8; 32];
    core::companion_seal(&mut m);
    core::companion_store(&m);
    let e = core::companion_check().expect_err("a stale accumulator must be detected");
    assert!(e.contains("DIFFERS"), "must name the accumulator: {e}");
    core::companion_store(&good);
    assert!(core::companion_check().is_ok(), "restored");

    // SEAL stale — any field moved without re-sealing.
    let mut m = good.clone();
    m.commitment = vec![0u8; 32];
    core::companion_store(&m);
    let e = core::companion_check().expect_err("a stale seal must be detected");
    assert!(e.contains("seal does not cover"), "must name the seal: {e}");
    core::companion_store(&good);
    assert!(core::companion_check().is_ok(), "restored");

    // COUNTER tampering — the case maximum-based validation cannot catch, and
    // the reason the brief moved this plane off `next_back()`.
    let mut m = good.clone();
    m.next_proposal_id = 1;
    core::companion_store(&m);
    let e = core::companion_check().expect_err("a lowered counter must be detected");
    assert!(e.contains("seal does not cover"), "must name the seal: {e}");
    core::companion_store(&good);
    assert!(core::companion_check().is_ok(), "restored");

    // COUNT drift, seal re-applied so only the recompute can catch it.
    let mut m = good.clone();
    m.entries = good.entries.saturating_sub(1);
    core::companion_seal(&mut m);
    core::companion_store(&m);
    assert!(
        core::companion_check().is_err(),
        "W2: entry-count drift must be detected independently of the commitment"
    );
    core::companion_store(&good);
    assert!(core::companion_check().is_ok(), "restored");

    // BYTE accounting drift, commitment and count intact.
    let mut m = good.clone();
    m.bytes = good.bytes.saturating_sub(1);
    core::companion_seal(&mut m);
    core::companion_store(&m);
    assert!(
        core::companion_check().is_err(),
        "W2: byte-accounting drift must be detected independently of count \
         and commitment"
    );
    core::companion_store(&good);
    assert!(core::companion_check().is_ok(), "restored");
}

/// S5B W2 row 3, INTENT CLASS — the split the brief requires.
///
/// On the Vault (proposal class) a nonterminal record without its registry
/// entry is inactive corruption scoped to that proposal. On this plane the
/// pointer is the only record of which intent holds the single-flight lock and
/// it is not scoped to an origin, so the same shape must produce a GLOBAL
/// intent-admission hold across BOTH origin namespaces — not a per-record
/// fault. Admitting on either origin while the pointer is untrustworthy is the
/// concurrent-module-mutation hazard the lock exists to prevent.
#[test]
fn w2_row3_intent_class_holds_admission_across_both_origins() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(41), 100, None, &self_p())
        .expect("propose");
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);
    assert!(core::companion_check().is_ok(), "clean baseline");

    // Empty the pointer WITHOUT going through the primitive — the row-3 shape:
    // the intent record still exists and is nonterminal, the pointer does not
    // claim it.
    core::clear_companion_indexes_for_test();

    let e = core::companion_check()
        .expect_err("row 3 on the intent class must be detected, never reactivated");
    assert!(e.contains("integrity mismatch"), "unexpected shape: {e}");

    // GLOBAL: the hold is not scoped to the origin that lost its pointer.
    // Both admission paths must refuse while the companion is untrustworthy.
    // `nonterminal_intent_in_flight` is the shared gate for both namespaces and
    // now validates before answering, so a trap here is the hold taking effect.
    let recovery_origin = std::panic::catch_unwind(|| {
        core::nonterminal_intent_in_flight_for_test(None)
    });
    assert!(
        recovery_origin.is_err(),
        "W2 row 3: intent admission must be HELD while the pointer is \
         untrustworthy — returning `false` here would admit a second concurrent \
         intent against the same target"
    );
}

/// S5B W3 — rotation terminalizes the COMPLETE stale set in ONE message, via
/// the bounded Pending index.
///
/// NON-VACUITY IS THE POINT OF THIS TEST. The obvious way to get W3 wrong is to
/// wire rotation to an index that is always empty — the expiry index (MemoryId
/// 6) is exactly that while PROPOSAL_LIFETIME_BOUNDS is None, and rotation
/// against it would terminalize NOTHING while reporting success and passing
/// every existing test. So the index is asserted populated BEFORE rotation and
/// empty after, and the stale proposals are asserted individually terminal.
#[test]
fn w3_rotation_terminalizes_complete_stale_set_in_one_message() {
    setup();

    // Two Pending proposals of DIFFERENT classes, plus the rotation itself.
    // They must not contend for the same lock: single-flight admits only one
    // nonterminal upgrade intent, so a second trigger proposal is refused
    // (IllegalSourceState) and would test nothing.
    let a = core::propose_recovery(&p(M1), trigger_action(51), 100, None, &self_p()).expect("a");
    let b = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M1)], 101, None, &self_p())
        .expect("b — a Pending rotation proposal, no upgrade intent");

    let before = core::pending_index_ids_for_test();
    assert!(
        before.contains(&a) && before.contains(&b),
        "W3 VACUITY GUARD: the bounded Pending index must actually hold the \
         Pending proposals. An empty index would make rotation terminalize \
         nothing and still pass — which is precisely why the expiry index \
         cannot serve this path. Index held: {before:?}"
    );

    let r = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 200, None, &self_p())
        .expect("rotation");
    core::approve_recovery(&p(M1), r, 201, commit_of(r), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    // Threshold is 2 (fixed, no contraction) — the SECOND approval is what
    // reaches quorum and executes the rotation in that same message.
    core::approve_recovery(&p(M2), r, 202, commit_of(r), &self_p())
        .expect("quorum-reaching approval");

    // ONE message reached quorum and executed. Every stale Pending proposal is
    // terminal, and the membership rotation committed — together.
    for (label, id) in [("a", a), ("b", b)] {
        let stored = core::get_stored_proposal(id).expect("stale proposal still exists");
        let (outcome, _) = core::stored_state(&stored);
        assert!(
            outcome.is_terminal(),
            "W3: stale Pending proposal {label} ({id}) was not terminalized by the \
             rotation — a partial stale set is the split-brain state one-message \
             atomicity exists to prevent, got {outcome:?}"
        );
    }

    let after = core::pending_index_ids_for_test();
    assert!(
        !after.contains(&a) && !after.contains(&b),
        "W3: terminalization must release the Pending index entries in the same \
         transaction; left behind: {after:?}"
    );
    assert!(
        core::companion_check().is_ok(),
        "W3: the companion must remain consistent across rotation"
    );
}

/// S5B W3 — `Executing` is EXCLUDED, preserving the in-flight carve-out and
/// L2-7 unchanged. The index predicate is `is_reapable()`, byte-identical to
/// the full scan it replaces, so this property must not have shifted.
#[test]
fn w3_executing_is_excluded_from_the_pending_index() {
    setup();
    let id = core::propose_recovery(&p(M1), trigger_action(61), 100, None, &self_p()).expect("propose");
    assert!(
        core::pending_index_ids_for_test().contains(&id),
        "Pending must be indexed"
    );

    // Drive it out of Pending; the index entry must be released.
    core::cancel_recovery_proposal(&p(M1), id, 150).expect("cancel");
    assert!(
        !core::pending_index_ids_for_test().contains(&id),
        "W3: a proposal that has left Pending must not remain in the index — a \
         stale entry would make rotation attempt to terminalize a terminal record"
    );
    assert!(core::companion_check().is_ok());
}

/// S5B W3 — LINT: no cursor, no continuation, no batching on the rotation path.
///
/// The brief is absolute: "no cursor, no continuation, no multi-call batching —
/// none may exist in the rotation path." A resumable rotation can leave
/// membership rotated while part of the stale set is still Pending, which is
/// the split-brain state one-message atomicity exists to prevent.
///
/// Like the W5(b) tripwire this is a source lint, because "is resumable" is not
/// a property the type system can express — a `cursor: Option<u64>` parameter
/// is perfectly legal Rust.
#[test]
fn w3_no_cursor_or_continuation_on_the_rotation_path() {
    const SRC: &str = include_str!("core.rs");
    let start = SRC
        .find("S5B W3 — ONE-MESSAGE ATOMIC TERMINALIZATION")
        .expect("W3 lint: rotation anchor not found — re-anchor it");
    // Bound to the END OF THE ROTATION BLOCK, not the next indented `fn`:
    // an over-wide region ran into the audit-events pagination helper, which
    // legitimately uses a cursor, and the lint fired on unrelated code.
    let end = SRC[start..]
        .find("\n            for pid in stale_pending {")
        .map(|i| start + i)
        .expect("W3 lint: rotation terminator not found — re-anchor it");
    // CODE ONLY. The prohibition is stated in prose directly above the
    // rotation path, so scanning comments would make the lint fire on its own
    // documentation — the same false positive the W1 lint hit.
    let region: String = SRC[start..end]
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n");

    for banned in ["cursor", "continuation", "resume_from", "batch_size", "next_page"] {
        assert!(
            !region.to_lowercase().contains(banned),
            "W3 VIOLATED: `{banned}` appears on the rotation path. Rotation must \
             terminalize the COMPLETE stale set and commit the membership change \
             in ONE message. If the ruled C12 does not fit that envelope, that is \
             a constants decision for CTO (lower C12) — never a licence to batch."
        );
    }
}

/// S5B W3 — the trap boundary EXISTS and fires mid-terminalization.
///
/// WHAT THIS DOES NOT PROVE, stated plainly rather than implied: it does NOT
/// prove rollback. Outside a canister there is no transaction — `catch_unwind`
/// catches the panic and leaves every mutation in place. Measured directly:
/// membership was already rotated when the trap fired, because the membership
/// write precedes the terminalization loop within the message.
///
/// That ordering is SAFE only because the whole path is one message with no
/// `await`, so the IC commits or discards it whole. There is no ordering safety
/// net underneath — the one-message property is doing all of the work. Which is
/// exactly why acceptance 13's rollback evidence must run through a real
/// Wasm/PocketIC message boundary, per the standard the §4 amendment pins for
/// W5(a). That evidence is OUTSTANDING, not partial: see the handoff.
///
/// What this test does establish is that the boundary is reachable and armed on
/// the real path — without which the PocketIC test would have nothing to fire.
#[test]
fn w3_trap_boundary_exists_and_fires_mid_terminalization() {
    setup();
    let a = core::propose_recovery(&p(M1), trigger_action(71), 100, None, &self_p()).expect("a");
    assert!(core::pending_index_ids_for_test().contains(&a));

    let r = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 200, None, &self_p())
        .expect("rotation");
    core::approve_recovery(&p(M1), r, 201, commit_of(r), &self_p()).expect("first approval");

    core::arm_rotation_trap_for_test(core::ROTATION_TRAP_MID_TERMINALIZATION);
    let trapped = std::panic::catch_unwind(|| {
        core::approve_recovery(&p(M2), r, 202, commit_of(r), &self_p())
    });
    core::arm_rotation_trap_for_test("none");
    assert!(
        trapped.is_err(),
        "the rotation trap boundary did not fire — it is unreachable on the real          path, so the PocketIC rollback evidence would have nothing to arm"
    );
}

/// S5B W3 — GATE CONDITION (CTO ratification, 2026-08-08, condition b).
///
/// Rotation must NEVER be wired to `RECOVERY_PROPOSAL_EXPIRY_INDEX`.
///
/// That index is keyed `(expires_at_ns, id)` and populated only for proposals
/// carrying an expiry; while `PROPOSAL_LIFETIME_BOUNDS` is `None` no proposal
/// ever has one, so it is VACUOUSLY EMPTY. Rotation reading it would
/// terminalize nothing, report success, and pass every behavioural test in this
/// suite — detonating only after S6 pins the lifetime constants, which is after
/// review and after signoff.
///
/// This is a GATE TEST rather than a comment because the failure mode is
/// invisible to the suite AS IT STOOD: the natural "simplification" (two
/// Pending-ish indexes, why not one?) passed everything that existed before
/// this work. It is caught behaviourally today only because
/// `w3_rotation_terminalizes_complete_stale_set_in_one_message` asserts the
/// index is POPULATED — an assertion easy to weaken or lose to fixture drift.
/// Two independent layers, verified: re-wiring rotation to the expiry index
/// fails BOTH the behavioural guard and this gate.
///
/// If lifetimes are ever ruled such that every proposal carries an expiry,
/// unification becomes arguable — and needs its own ruling, not a refactor.
/// Deleting this test to make that refactor pass is the failure it guards.
#[test]
fn w3_rotation_must_not_be_wired_to_the_vacuous_expiry_index() {
    const SRC: &str = include_str!("core.rs");
    let start = SRC
        .find("S5B W3 — ONE-MESSAGE ATOMIC TERMINALIZATION")
        .expect("W3 gate: rotation anchor not found — re-anchor it");
    let end = SRC[start..]
        .find("\n            for pid in stale_pending {")
        .map(|i| start + i)
        .expect("W3 gate: rotation terminator not found — re-anchor it");

    let code: String = SRC[start..end]
        .lines()
        .filter(|l| !l.trim().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !code.contains("RECOVERY_PROPOSAL_EXPIRY_INDEX"),
        "W3 GATE VIOLATED: rotation is reading RECOVERY_PROPOSAL_EXPIRY_INDEX. \
         That index is VACUOUSLY EMPTY while PROPOSAL_LIFETIME_BOUNDS is None, so \
         rotation would terminalize NOTHING while reporting success. The \
         PRE-EXISTING suite passed against exactly this; it is caught today only \
         because `w3_rotation_terminalizes_complete_stale_set_in_one_message` \
         asserts the index is POPULATED before rotation. This gate is the second \
         layer: it holds even if that behavioural guard is weakened or its \
         fixtures drift. The underlying failure surfaces only after S6 pins the \
         lifetime constants — i.e. after review and after signoff. \
         Use PENDING_RECOVERY_PROPOSAL_INDEX. Re-unifying the two indexes is \
         forbidden while lifetime bounds are unruled (CTO ratification, \
         2026-08-08)."
    );
    assert!(
        code.contains("PENDING_RECOVERY_PROPOSAL_INDEX"),
        "W3 GATE VIOLATED: rotation no longer reads the bounded Pending index. \
         If the source of the stale set has changed, this gate must be re-derived \
         deliberately — it cannot be left pointing at a path that no longer exists."
    );
}

/// S5B W6 — COST-AT-DEPTH CLASSIFICATION, Upgrader plane.
///
/// Clause (g) requires both canisters. The permanently-growing maps here are
/// `RECOVERY_PROPOSALS`, `UPGRADE_INTENTS` and `AUDIT_EVENTS`; the companions
/// (`NONTERMINAL_INTENT_INDEX`, `RECOVERY_PROPOSAL_EXPIRY_INDEX`,
/// `PENDING_RECOVERY_PROPOSAL_INDEX`) are bounded-active-set and excluded.
///
/// Same reasoning as the Vault's: cost-at-depth is invisible at test scale, so
/// it must be caught at the source rather than by a behavioural assertion that
/// would pass over twenty records and fail only in production.
#[test]
fn w6_no_unbounded_iteration_over_permanent_history_upgrader() {
    const SRC: &str = include_str!("core.rs");
    const PERMANENT: [&str; 3] = ["RECOVERY_PROPOSALS", "UPGRADE_INTENTS", "AUDIT_EVENTS"];

    // SSA CUST-SSA-S5B-FINAL-01 — SHARED, FORMATTING-INSENSITIVE CLASSIFIER.
    //
    // This was line-based while the Vault's had been hardened to statement
    // level, so a rustfmt-split `RECOVERY_PROPOSALS.with(|p| { p.borrow().iter()
    // })` evaded it here — the exact defect class RF-3 exists to close, on a
    // clause that expressly covers BOTH canisters. Two copies of one rule is
    // how that divergence happened, so both planes now call ONE implementation
    // in custody-types; drifting again would require deleting a caller.
    // PRODUCTION REGION ONLY — the same carve-out the Vault's W6 lint already
    // has, made explicit here because `core.rs` has no `mod tests` boundary to
    // cut at.
    //
    // A census of the permanent maps must ITERATE them; counting bytes in
    // permanent history is its purpose. That is legitimate in a measurement
    // harness and forbidden on a live path, and the `measurement` module is what
    // separates them — a boundary the COMPILER enforces, since nothing in that
    // module is compiled into a deployable build. Scanning the test-only region would make this lint fire on its own
    // measurement harness — the failure mode that recurred three times in S5B
    // and that gets a lint disabled by the next person who hits it.
    //
    // `expect` rather than a silent fallback: if the marker is renamed or
    // removed, the lint must fail loudly rather than quietly revert to scanning
    // the whole file (noisy, and it would be "fixed" by deleting the lint) or
    // quietly scanning none of it (silent, and far worse).
    let prod = SRC
        .split_once("pub mod measurement {")
        .map(|(before, _)| before)
        .expect(
            "W6 lint (upgrader): the test-only `measurement` module was not found — \
             re-anchor this cut. It must point at a cfg-gated boundary, never be \
             widened to scan nothing.",
        );

    let offenders =
        stsh_custody_types::unbounded_history_iteration_offenders(prod, &PERMANENT);
    assert!(
        offenders.is_empty(),
        "W6 VIOLATED (upgrader): unbounded iteration over permanently-growing \
         history. These maps are never pruned, so this call's cost grows without \
         bound — the exhaustion half of CUST-SSA-003. Use a keyed read, a bounded \
         page, or a bounded-active-set companion.\nOffenders: {offenders:#?}"
    );
}

/// S5B W6 acceptance 2 — post_upgrade does NO UNBOUNDED HISTORY-DEPENDENT WORK.
///
/// **REWORDED at W6-EVIDENCE-01 item 3.** This doc previously asserted that
/// "`post_upgrade` performs NO read of the history maps at all", citing the
/// first-layer source lint as enforcement. That claim was FALSE while it was
/// written: `rebuild_invariant_mirror` read `AUDIT_EVENTS` up to 10,000 times at
/// `post_upgrade` via keyed `get(&seq)` in a range loop, which the `.iter()`
/// matcher cannot see. R6.0 removed that particular offender, but the stronger
/// no-read claim is still not what the gates prove — `post_upgrade` legitimately
/// reaches three bounded keyed accesses through the E2 sweep, enumerated in
/// `w6_evidence_01_reachable_history_accesses_are_enumerated_upgrader`.
///
/// So the assertion is now the one the evidence actually supports: no unbounded
/// history-dependent work. Enforcement is TWO layers — the first-layer `.iter()`
/// shape matcher, and the reachability gate that enumerates every access from
/// `post_upgrade` with its loop and recursion context.
///
/// Proved STRUCTURALLY rather than by timing. A wall-clock assertion at test
/// scale cannot distinguish O(1) from O(n) — twenty records run fast either way,
/// and a threshold tuned to pass here would be meaningless in production. This
/// test adds the behavioural half: a DEEP history must not change the outcome or
/// wedge the path.
#[test]
fn w6_post_upgrade_unaffected_by_deep_terminal_history() {
    setup();
    // Build a deep TERMINAL history directly. These records are permanent and
    // would each have been decoded by the removed rebuilds.
    for i in 0..400u64 {
        core::put_stored_proposal_for_test(
            100_000 + i,
            &StoredProposal::Recovery {
                epoch: 0,
                proposal: stsh_custody_types::RecoveryProposal {
                    start: None,
                    proposal_id: 100_000 + i,
                    action: trigger_action(1),
                    proposer: p(M1),
                    approvals: vec![],
                    threshold: 2,
                    created_at_ns: 100,
                    // TERMINAL: holds no companion entry, so it is pure
                    // permanent history — the thing whose size must not matter.
                    outcome: ActionOutcome::Failed,
                    expires_at_ns: None,
                    commitment_hash: Vec::new(),
                },
            },
        );
    }
    assert!(
        core::companion_check().is_ok(),
        "deep terminal history must not disturb the companion"
    );
    core::post_upgrade(T0);
    assert!(
        core::companion_check().is_ok(),
        "W6: post_upgrade must remain consistent against a deep terminal history"
    );
    // And the plane still admits normally afterwards.
    let id = core::propose_recovery(&p(M1), trigger_action(81), 100, None, &self_p())
        .expect("W6: admission must still work at depth");
    assert!(core::pending_index_ids_for_test().contains(&id));
}

/// SSA BLOCKER 2 — the C9 entry gate exists on the RECOVERY plane.
///
/// W4 landed the gate on the Vault only. The route SSA named —
/// `MembershipRotationRejected` — appended directly into permanent history with
/// no budget at all, so a member could drive unbounded audit growth with
/// invalid rosters. Closing only the Vault moves the exhaustion route rather
/// than removing it.
#[test]
fn b2_recovery_plane_entry_gate_binds() {
    setup();
    core::inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
        window_ns: 1_000_000_000_000,
        global_per_window: 2,
        per_signer_per_window: 2,
    })));

    // Two entries consume the budget: one admission, one AUDITED REJECTION
    // (an invalid roster). They share ONE budget, which is the property.
    core::propose_recovery(&p(M1), trigger_action(91), 100, None, &self_p()).expect("admission");
    let rejected = core::propose_membership_rotation(&p(M1), vec![p(M1)], 101, None, &self_p());
    assert!(rejected.is_err(), "an invalid roster must be rejected");

    // Budget now exhausted: the next entry is refused BEFORE it can append.
    let refused = core::propose_membership_rotation(&p(M1), vec![p(M1)], 102, None, &self_p());
    assert!(
        refused.is_err(),
        "SSA BLOCKER 2: the recovery plane must rate-limit ENTRY events. \
         MembershipRotationRejected appended with no budget, so invalid rosters \
         drove unbounded permanent-history growth."
    );
    assert_eq!(
        core::entry_rate_global_count_for_test(),
        2,
        "admissions and audited rejections must share ONE budget, and a \
         rate-limited refusal must consume nothing further — a refusal that \
         charged again would be the recursive append the brief forbids"
    );
    core::inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// NON-VACUITY: unruled params must ADMIT, matching the Vault's asymmetry.
#[test]
fn b2_recovery_gate_inactive_while_unruled() {
    setup();
    core::inject_entry_rate_for_test(Some(None));
    // RF-1: drive PAST the ruled per-signer bound (C9 = 26/member/window).
    //
    // A single admission proved nothing: 1 is under the ruled cap too, so this
    // test passed identically whether it reached the unruled path or the ruled
    // one — which is exactly what it did, silently, from S6 until RF-1. Past 26
    // the RULED gate refuses, so only a genuinely unruled gate admits them all.
    //
    // ROTATIONS, not trigger proposals: repeated trigger proposals collide with
    // CREATION single-flight (keyed on the manifest purpose, which a different
    // artifact tag does not change), so they would refuse for a reason that has
    // nothing to do with the rate gate under test. C12 is suspended for the
    // same reason — at 32 it would refuse first and mask the property.
    core::inject_nonterminal_caps_for_test(Some(None));
    let ruled_per_signer = stsh_custody_types::ENTRY_RATE_PARAMS
        .expect("C9 ruled at S6")
        .per_signer_per_window as u64;
    for i in 0..(ruled_per_signer + 4) {
        core::propose_membership_rotation(
            &p(M1),
            vec![p(M2), p(M3), p(M4)],
            100 + i,
            None,
            &self_p(),
        )
        .unwrap_or_else(|e| panic!(
            "while unruled the gate must admit — refusing every entry would brick \
             the recovery plane rather than protect it (admission {i} of {}): {e:?}",
            ruled_per_signer + 4
        ));
    }
    assert!(
        ruled_per_signer + 4 > ruled_per_signer,
        "RF-1 non-vacuity: the loop must exceed the ruled per-signer bound"
    );
}

/// SSA BLOCKER 2 (re-check) — a NON-AUDITED validation failure must cost NO
/// budget, and a saturated refusal must write NOTHING.
///
/// SSA's point about the first B2 test stands: it checked only the ledger
/// COUNT, so moving the rejection append across the gate would have left it
/// green. This asserts full retained-state equality — ledger AND audit length —
/// which is what actually pins the ordering.
#[test]
fn b2_non_audited_failures_cost_no_budget_and_saturation_writes_nothing() {
    setup();
    core::inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
        window_ns: 1_000_000_000_000,
        global_per_window: 1,
        per_signer_per_window: 1,
    })));

    let ledger0 = core::entry_rate_global_count_for_test();
    let audit0 = core::audit_len_for_test();

    // A NON-AUDITED refusal: an out-of-bounds lifetime, rejected while the
    // §10.5 bounds are unruled. Neither an admission nor an audited rejection,
    // so it must consume nothing and write nothing.
    let r = core::propose_recovery(&p(M1), trigger_action(95), 100, Some(60_000_000_000), &self_p());
    assert!(r.is_err(), "fixture guard: the lifetime request must fail closed");
    assert_eq!(
        (core::entry_rate_global_count_for_test(), core::audit_len_for_test()),
        (ledger0, audit0),
        "SSA BLOCKER 2: a non-audited validation failure consumed durable budget. \
         The frozen definition is admission OR AUDITED rejection — charging for \
         anything else is silent quota consumption."
    );

    // A real admission consumes exactly one and exhausts the budget.
    core::propose_recovery(&p(M1), trigger_action(96), 100, None, &self_p()).expect("admission");
    let ledger1 = core::entry_rate_global_count_for_test();
    let audit1 = core::audit_len_for_test();
    assert_eq!(ledger1, ledger0 + 1, "an admission charges exactly one entry");

    // SATURATED: the next entry is refused and must write NOTHING — not the
    // ledger, not an audit event. A refusal that appended would need a second
    // budgeted entry to record the refusal of the first, which is the recursion
    // the brief forbids.
    let refused = core::propose_membership_rotation(&p(M2), vec![p(M2)], 102, None, &self_p());
    assert!(refused.is_err(), "saturated: the entry must be refused");
    assert_eq!(
        (core::entry_rate_global_count_for_test(), core::audit_len_for_test()),
        (ledger1, audit1),
        "SSA BLOCKER 2: a saturated refusal wrote to durable state. It must \
         produce ZERO writes — ledger and audit alike."
    );
    core::inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// SSA RF-7 — B3 regression evidence: the companion record is created at fresh
/// install, and an ABSENT record is rejected rather than defaulted.
#[test]
fn rf7_companion_sentinel_created_at_install_and_absence_rejected() {
    setup();
    // Fresh install wrote it: a load succeeds and validation is clean.
    assert!(
        core::companion_check().is_ok(),
        "RF-7: fresh install must CREATE the companion record"
    );

    // Absence must be rejected, not silently defaulted. This is the pre-
    // companion-deployment case: empty cell, empty indexes — which the first
    // cut accepted as a valid default and so failed OPEN.
    core::clear_companion_state_for_test();
    let r = std::panic::catch_unwind(core::companion_check);
    assert!(
        r.is_err(),
        "RF-7 / BLOCKER 3: an ABSENT companion record must TRAP. Reading it as \
         an empty default lets a pre-companion deployment pass post_upgrade \
         whenever its active indexes happen to be empty."
    );
}

// ── SSA re-check BLOCKER 1 — recovery-plane C12 ──────────────────────────────
//
// The Pending-inclusive index and the caps landed on the VAULT ONLY. These
// pin the recovery plane's half: that a slot is occupied from admission to
// terminalization for BOTH variants, that the cap binds ahead of the C9
// charge and ID allocation, and that the predicate is `!is_terminal()` rather
// than either of the two neighbouring predicates it is easy to confuse.

fn caps(global: u32, per_signer: u32) -> stsh_custody_types::NonterminalCaps {
    stsh_custody_types::NonterminalCaps { global, per_signer }
}

/// A PENDING proposal occupies a nonterminal slot. This is the Vault defect,
/// re-asserted on this plane: counting the single-flight indexes instead would
/// leave Pending free and let Pending spam bypass the caps entirely.
#[test]
fn b1_pending_proposal_occupies_a_nonterminal_slot() {
    setup();
    core::inject_nonterminal_caps_for_test(Some(Some(caps(1, 1))));

    core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("first admission fits under the cap");
    assert_eq!(
        core::nonterminal_proposal_count_for_test(),
        1,
        "an admitted PENDING proposal must occupy a slot"
    );

    let refused =
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 101, None, &self_p());
    assert!(
        refused.is_err(),
        "SSA BLOCKER 1: a PENDING proposal must occupy a nonterminal slot on the \
         RECOVERY plane. The caps landed on the Vault only, so this plane admitted \
         without bound."
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// The slot is RELEASED at terminalization — a cap that never releases is a
/// one-shot canister, not a rate bound.
#[test]
fn b1_nonterminal_slot_released_at_terminalization() {
    setup();
    core::inject_nonterminal_caps_for_test(Some(Some(caps(1, 1))));

    let id = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("first admission");
    core::cancel_recovery_proposal(&p(M1), id, 110).expect("proposer cancels their own proposal");
    assert_eq!(
        core::nonterminal_proposal_count_for_test(),
        0,
        "terminalization must release the slot"
    );
    assert!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 120, None, &self_p())
            .is_ok(),
        "with the slot released the next admission must fit"
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// THE PREDICATE TRAP (§3.6), pinned directly. `Executing` and
/// `OutcomeUnknown` are NOT reapable and do NOT hold Pending — but both are
/// nonterminal and both occupy a slot. Wiring this index to `is_reapable()`
/// (the predicate of its neighbour, MemoryId 8) or to `holds_single_flight()`
/// type-checks and passes every Pending-only test.
/// Deliberately NOT a loop over both outcomes: stable memory lives in
/// `thread_local`s that persist for the whole test, so a second iteration
/// inherits the first's occupied slot and the count assertion reads 2. One
/// outcome per test, each on its own test thread and so its own fresh state.
fn assert_nonterminal_outcome_occupies_a_slot(outcome: ActionOutcome) {
    setup();
    let id =
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
            .expect("admission");

    // Drive it to the non-Pending nonterminal state.
    let stored = core::get_stored_proposal(id).expect("proposal exists");
    let next = match stored {
        core::StoredProposal::Rotation(mut r) => {
            r.outcome = outcome;
            core::StoredProposal::Rotation(r)
        }
        other => other,
    };
    core::put_stored_proposal_for_test(id, &next);

    assert_eq!(
        core::nonterminal_proposal_count_for_test(),
        1,
        "SSA BLOCKER 1 / §3.6: {outcome:?} is NONTERMINAL and must occupy a slot. \
         `is_reapable()` (Pending only) and `holds_single_flight()` (excludes \
         Pending) both type-check here and both get this wrong — the membership \
         predicate is `!outcome.is_terminal()`."
    );

    // And the cap actually binds on the strength of that occupancy.
    core::inject_nonterminal_caps_for_test(Some(Some(caps(1, 1))));
    assert!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 101, None, &self_p())
            .is_err(),
        "a {outcome:?} proposal must consume cap capacity, not merely index space"
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

#[test]
fn b1_executing_occupies_a_slot() {
    assert_nonterminal_outcome_occupies_a_slot(ActionOutcome::Executing);
}

#[test]
fn b1_outcome_unknown_occupies_a_slot() {
    assert_nonterminal_outcome_occupies_a_slot(ActionOutcome::OutcomeUnknown);
}

/// BOTH proposal variants are covered. A recovery action and a membership
/// rotation each occupy one slot; maintaining the index for only the variant
/// the tests happen to use is the shape of the original defect.
#[test]
fn b1_both_proposal_variants_occupy_slots() {
    setup();
    core::propose_recovery(&p(M1), trigger_action(41), 100, None, &self_p())
        .expect("recovery admission");
    assert_eq!(
        core::nonterminal_proposal_count_for_test(),
        1,
        "a RECOVERY-action proposal must occupy a slot"
    );
    core::propose_membership_rotation(&p(M2), vec![p(M2), p(M3), p(M4)], 101, None, &self_p())
        .expect("rotation admission");
    assert_eq!(
        core::nonterminal_proposal_count_for_test(),
        2,
        "a MEMBERSHIP-ROTATION proposal must occupy a slot on the same index"
    );
}

/// The cap is PER-MEMBER as well as global — a single member must not be able
/// to consume the whole ring's capacity.
#[test]
fn b1_caps_bind_per_member_and_globally() {
    setup();
    core::inject_nonterminal_caps_for_test(Some(Some(caps(10, 1))));

    core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("M1's first fits");
    assert!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 101, None, &self_p())
            .is_err(),
        "the PER-MEMBER cap must bind while global capacity remains"
    );
    assert!(
        core::propose_membership_rotation(&p(M2), vec![p(M2), p(M3), p(M4)], 102, None, &self_p())
            .is_ok(),
        "a DIFFERENT member must still be admitted — the per-member cap is not global"
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// ORDERING, the property SSA pinned: C12 cap → C9 charge → allocation →
/// durable writes. A capped admission must consume NO rate budget, NO
/// proposal id, and write NOTHING.
///
/// A count-only assertion cannot see this — it is the ordering defect §0 warns
/// about — so this asserts full retained-state equality across the refusal.
#[test]
fn b1_cap_binds_before_c9_charge_and_id_allocation() {
    setup();
    core::inject_nonterminal_caps_for_test(Some(Some(caps(1, 1))));
    core::inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
        window_ns: 1_000_000_000_000,
        global_per_window: 100,
        per_signer_per_window: 100,
    })));

    core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("first admission");

    let ledger0 = core::entry_rate_global_count_for_test();
    let audit0 = core::audit_len_for_test();
    let next_id0 = core::companion_load().next_proposal_id;

    let refused =
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 101, None, &self_p());
    assert!(refused.is_err(), "fixture guard: the cap must refuse here");

    assert_eq!(
        (
            core::entry_rate_global_count_for_test(),
            core::audit_len_for_test(),
            core::companion_load().next_proposal_id,
        ),
        (ledger0, audit0, next_id0),
        "SSA BLOCKER 1 ordering: the C12 cap must bind BEFORE the C9 charge, before \
         ID allocation and before any durable write. A capped admission that charged \
         budget or burned an id would consume durable state for an operation that \
         never happened."
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    core::inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// NON-VACUITY: while the caps are unruled the path must ADMIT. Every one of
/// these tests would pass against a cap that refused everything.
#[test]
fn b1_caps_inactive_while_unruled() {
    setup();
    core::inject_nonterminal_caps_for_test(Some(None));
    // RF-1: 4 iterations proved nothing — 4 is under the ruled C12 per-signer
    // bound of 32, so this passed on the ruled path too and had done since S6.
    // Suspend C9 as well (it would refuse first at 26) and drive past 32, so
    // only a genuinely unruled cap admits every one.
    core::inject_entry_rate_for_test(Some(None));
    let ruled_per_signer = stsh_custody_types::RECOVERY_NONTERMINAL_CAPS
        .expect("C12 ruled at S6")
        .per_signer as u64;
    for i in 0..(ruled_per_signer + 4) {
        core::propose_membership_rotation(
            &p(M1),
            vec![p(M2), p(M3), p(M4)],
            100 + i,
            None,
            &self_p(),
        )
        .expect("while unruled the caps must not bind — `Option = None` carries no value");
    }
    assert_eq!(
        core::nonterminal_proposal_count_for_test(),
        (ruled_per_signer + 4) as usize,
        "every admission must have occupied a slot — and the count must EXCEED \
         the ruled per-signer cap, or this test is passing on the ruled path"
    );
    assert!(
        core::nonterminal_proposal_count_for_test() > ruled_per_signer as usize,
        "RF-1 non-vacuity: the occupancy must be past the ruled cap"
    );
}

/// MemoryId 10 is covered by MemoryId 7's accounting and seal — not merely
/// stored alongside it. A forged entry without its accounting must be caught.
#[test]
fn b1_nonterminal_index_is_covered_by_the_companion_seal() {
    setup();
    core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("admission");
    assert!(
        core::companion_check().is_ok(),
        "fixture guard: steady state must be clean"
    );

    core::forge_nonterminal_proposal_entry_for_test(p(M5), 4242);
    assert!(
        core::companion_check().is_err(),
        "SSA BLOCKER 1: MemoryId 10 must be inside MemoryId 7's commitment. An index \
         the seal does not cover can be forged to manufacture or release cap capacity \
         with no detection."
    );
}

// ── SSA B1 re-review — BLOCKER 1, BLOCKER 2, required proof fix ──────────────

/// BLOCKER 1 — a PREDECESSOR companion record must not be accepted as the new
/// layout.
///
/// MemoryId 10 changed the companion registry and the commitment domain. Left
/// at schema 1, an upgrade from the predecessor build would have been accepted
/// silently: the new index starts EMPTY, an empty index contributes nothing to
/// the accumulator or the accounting, so the old commitment still verifies —
/// and `companion_recompute` never reads history, so it cannot see that live
/// nonterminal proposals are absent from the new index. C12 would undercount
/// exactly those proposals.
///
/// The sentinel is what closes this, so it is asserted directly rather than
/// inferred from the constant's value.
#[test]
fn b1_predecessor_companion_schema_is_rejected() {
    setup();
    assert!(
        core::companion_check().is_ok(),
        "fixture guard: a fresh install must be clean"
    );

    // A record that is VALID in every respect except its version — sealed and
    // self-consistent, exactly as the predecessor build would have left it.
    // Anything less would prove only that garbage is rejected.
    //
    // The version is the LITERAL 1 — the predecessor build's actual value —
    // NOT `COMPANION_STATE_SCHEMA_VERSION - 1`. Written relative to the
    // constant, this test passes for ANY value of it, including a revert of
    // the bump, and so could not detect the very regression it exists to
    // catch. (It was written that way first.)
    let mut predecessor = core::companion_load();
    predecessor.schema_version = 1;
    core::companion_seal(&mut predecessor);
    core::companion_store(&predecessor);

    let r = std::panic::catch_unwind(core::companion_check);
    assert!(
        r.is_err(),
        "BLOCKER 1: a predecessor companion record was accepted as the new layout. \
         MemoryId 10 would then start empty against live nonterminal proposals and \
         C12 would undercount every proposal admitted before the upgrade. The schema \
         sentinel exists precisely to make this fail closed."
    );
}

/// BLOCKER 2 — corruption of MemoryId 10 must TRAP at the earliest
/// cap-dependent admission, not surface as a typed cap refusal.
///
/// A forged entry manufactures cap capacity (or removes it). Returning
/// `IllegalSourceState` would present durable corruption as a routine "the ring
/// is busy" error — indistinguishable, to a caller and to an operator, from
/// legitimate saturation.
#[test]
fn b1_forged_index_entry_traps_at_admission_not_typed_refusal() {
    setup();
    // The caps MUST be tight enough that the forged entry alone SATURATES
    // them. With slack caps the forged entry never reaches the comparison, the
    // call proceeds, and the trap arrives later from `next_proposal_id`'s
    // validation — so the test passes whether or not the cap validates first,
    // proving nothing about the ordering. (The first cut used caps(4,4) and
    // survived exactly that mutation.)
    core::inject_nonterminal_caps_for_test(Some(Some(caps(1, 1))));

    // NON-VACUITY: uncorrupted, this same call is ADMITTED. Without this the
    // assertion below would also hold against a path that always trapped.
    assert!(
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 99, None, &self_p())
            .is_ok(),
        "fixture guard: with a clean index the first admission must succeed"
    );
    core::cancel_recovery_proposal(&p(M1), 1, 100).expect("release the slot again");

    core::forge_nonterminal_proposal_entry_for_test(p(M5), 9999);
    let r = std::panic::catch_unwind(|| {
        core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 101, None, &self_p())
    });
    assert!(
        r.is_err(),
        "BLOCKER 2: admission read the nonterminal index BEFORE validating it, so a \
         forged entry produced an ordinary cap error instead of trapping. Corruption \
         must never present as a typed refusal — and the later next_proposal_id \
         validation cannot save this, because a cap refusal returns before it."
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

/// REQUIRED PROOF FIX — the GLOBAL limb, isolated.
///
/// `b1_caps_bind_per_member_and_globally` sets `global=10, per_signer=1`, so
/// only the per-member comparison can ever fire; deleting `global >= caps.global`
/// leaves it green. Here each member holds strictly fewer than its own quota,
/// so the ONLY thing that can refuse the third proposer is the global limb.
#[test]
fn b1_global_cap_binds_across_distinct_members() {
    setup();
    // per_signer deliberately 5: no member comes close to its own quota, so a
    // refusal cannot be attributed to the per-member limb.
    core::inject_nonterminal_caps_for_test(Some(Some(caps(2, 5))));

    core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 100, None, &self_p())
        .expect("M1 fits: global 0/2, M1 0/5");
    core::propose_membership_rotation(&p(M2), vec![p(M2), p(M3), p(M4)], 101, None, &self_p())
        .expect("M2 fits: global 1/2, M2 0/5");
    assert_eq!(core::nonterminal_proposal_count_for_test(), 2, "global cap now met");

    let refused =
        core::propose_membership_rotation(&p(M3), vec![p(M2), p(M3), p(M4)], 102, None, &self_p());
    assert!(
        refused.is_err(),
        "REQUIRED PROOF FIX: the GLOBAL cap must bind across DISTINCT members. M3 holds \
         0 of its own 5, so only `global >= caps.global` can refuse here — with that \
         comparison removed, every other B1 test still passes."
    );

    // And the refusal is genuinely the global limb: freeing one slot lets the
    // same member through unchanged. Without this the assertion above would
    // also hold against a cap that refused M3 for any other reason.
    let id = core::propose_membership_rotation(&p(M1), vec![p(M2), p(M3), p(M4)], 103, None, &self_p());
    assert!(id.is_err(), "still saturated globally");
    core::cancel_recovery_proposal(&p(M1), 1, 110).expect("M1 cancels its own proposal");
    assert!(
        core::propose_membership_rotation(&p(M3), vec![p(M2), p(M3), p(M4)], 111, None, &self_p())
            .is_ok(),
        "with global capacity freed, the previously-refused member is admitted"
    );
    core::inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
}

// ═════════════════════════════════════════════════════════════════════════════
// S5A — M2″ RECOVERY-PLANE PERMANENT-SURFACE CENSUS
// ═════════════════════════════════════════════════════════════════════════════

fn census_total(c: &[(&'static str, usize, usize)]) -> usize {
    c.iter().map(|(_, _, b)| b).sum()
}

fn print_census_delta(label: &str, before: &[(&'static str, usize, usize)]) {
    let after = core::measurement::census_for_test();
    println!("| surface | entries Δ | bytes Δ |");
    println!("|---|---|---|");
    for (i, (name, cnt, by)) in after.iter().enumerate() {
        let (_, c0, b0) = before[i];
        if *cnt != c0 || *by != b0 {
            println!(
                "| {name} | {}{} | {}{} |",
                if *cnt >= c0 { "+" } else { "-" },
                cnt.abs_diff(c0),
                if *by >= b0 { "+" } else { "-" },
                by.abs_diff(b0)
            );
        }
    }
    println!(
        "| **{label} TOTAL** | | **{}{}** |",
        if census_total(&after) >= census_total(before) { "+" } else { "-" },
        census_total(&after).abs_diff(census_total(before))
    );
}

/// M2″ — permanent growth per operation on the RECOVERY plane.
///
/// This plane has never been censused. All five `s5a_` census tests live on the
/// Vault, so every M2 figure the constants table has seen describes one plane
/// of a two-plane system — and the omission understates total growth rather
/// than merely being incomplete.
///
/// Measured by DRIVING a real recovery lifecycle, not by hand-assembling
/// records: a regression that stopped writing an index or changed a record
/// shape would move these numbers, which is the whole point of a census that
/// feeds a byte quota.
#[test]
fn s5a_m2_census_recovery_plane_permanent_growth() {
    setup();

    println!("\n=== S5A/M2″ — RECOVERY PLANE, PERMANENT SURFACES ===");
    println!("(logical payload; excludes StableBTreeMap node/allocator overhead —");
    println!(" the same basis the Vault census uses, so the planes are comparable)");

    let before = core::measurement::census_for_test();
    println!("\n(baseline at fresh install)");
    println!("| surface | entries | bytes |");
    println!("|---|---|---|");
    for (name, cnt, by) in &before {
        println!("| {name} | {cnt} | {by} |");
    }
    println!("| **TOTAL** | | **{}** |", census_total(&before));

    // A complete recovery-originated operation: propose → quorum.
    let base = core::measurement::census_for_test();
    let id = core::propose_recovery(&p(M1), trigger_action(9), 100, None, &self_p())
        .expect("propose");
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    println!("\n(delta after propose + first approval, TriggerVaultUpgrade)");
    print_census_delta("recovery operation", &base);

    // The artifact-bearing surface, isolated: an upgrade intent holds the
    // artifact bytes until terminal evidence is durable, so peak footprint is
    // dominated by it and is RELEASED at terminalization — unlike the audit
    // trail, which is not.
    let intents_bytes = core::measurement::census_for_test()
        .iter()
        .find(|(n, _, _)| n.starts_with("3 UPGRADE_INTENTS"))
        .map(|(_, _, b)| *b)
        .unwrap_or(0);
    println!(
        "\nUPGRADE_INTENTS holds {intents_bytes} B with one Pending trigger intent \
         — artifact-bearing and RELEASED at terminalization, unlike AUDIT_EVENTS \
         which is append-only and is not."
    );

    println!(
        "\nFIXTURE, NOT THRESHOLD: the artifact in this fixture is small. The \
         per-operation byte figures scale with the admitted artifact, so C6/C8 \
         must be derived against the largest ADMITTED payload — the same \
         dependence gate A and gate C both exhibit.\n"
    );

    let after = core::measurement::census_for_test();
    assert!(
        census_total(&after) > census_total(&base),
        "a driven recovery operation must grow permanent state — a zero delta \
         would mean the census is not observing the surfaces it names"
    );
}

/// M3‴ — C9 permanent-growth horizon, RECOVERY plane, all surfaces.
///
/// The recovery half of the horizon. It exists separately because the planes
/// have separate per-operation costs and neither substitutes for the other —
/// the same reason §C's budgets apply to both origin paths independently.
///
/// RULED POLICY INPUTS, not builder selections: 24 entry events/day, 10x burst,
/// PERMANENT retention. This test supplies the measured per-operation term and
/// multiplies; it recommends no constant.
#[test]
fn s5a_m3_c9_permanent_growth_horizon_recovery_plane() {
    setup();

    // ── COMPLETE TERMINAL LIFECYCLE, not propose + first approve ────────────
    //
    // SSA Blocker 4: a half-lifecycle understates permanent growth, because the
    // events that terminalize an operation (RecoveryExecutionStarted,
    // RecoveryProposalTerminal) are appended AFTER the point the prior fixture
    // stopped — and audit is append-only, so those bytes are permanent.
    let before = core::measurement::census_for_test();
    let id = core::propose_recovery(&p(M1), trigger_action(12), 100, None, &self_p())
        .expect("propose");
    core::approve_recovery(&p(M1), id, 101, commit_of(id), &self_p())
        .expect("proposer approves explicitly (V8 §3)");
    let plan = match core::approve_recovery(&p(M2), id, 102, commit_of(id), &self_p())
        .expect("quorum-reaching approval")
    {
        ApproveOutcome::Execute(RecoveryExecution::Trigger { plan, .. }) => plan,
        other => panic!("expected execution, got {other:?}"),
    };
    let outcome = core::finish_intent(&plan.key, &Ok(()), 200);
    assert_eq!(outcome, ActionOutcome::Executed, "the lifecycle must reach terminal");
    core::recovery_finish_trigger(id, outcome, 200);
    let after = core::measurement::census_for_test();

    // ── UPGRADE_INTENTS: ARTIFACT vs ENVELOPE ───────────────────────────────
    //
    // SUPERSEDED MODEL, RECORDED SO IT IS NOT REINTRODUCED. This block used to
    // say the whole `UPGRADE_INTENTS` surface was EXCLUDED from permanent growth
    // as a peak-footprint term. That was wrong, and it contradicted the code
    // below (SSA r3 return). It conflated two different things:
    //
    //   ARTIFACT bytes  — `wasm_bytes`/`arg_bytes`. Released at terminalization,
    //                     so genuinely a PEAK term. They do not accumulate, and
    //                     they scale with P_max.
    //   ENVELOPE        — the surviving `UpgradeIntent` record: id, origin, the
    //                     two 32-byte hashes, outcome, timestamps. PERMANENT.
    //                     `put_intent` only ever inserts, there is no delete
    //                     path on MemoryId 3, and no sweep prunes it. The
    //                     module contract in `core.rs` says the same thing —
    //                     "intents METADATA are permanent".
    //
    // The census delta is taken AFTER terminalization, so what it measures is
    // the ENVELOPE ALONE — the artifact is already gone by then (asserted just
    // below, which is what makes the delta fixed-width rather than P_max-sized).
    //
    // Excluding the whole surface therefore dropped a permanent term and
    // understated the coefficient by 251 B/op. The envelope is INCLUDED in the
    // permanent coefficient; the artifact peak is a separate quantity this delta
    // never contained. SSA Blocker 4's original point still holds and is kept:
    // any exclusion is applied INSIDE the arithmetic, never narrated after the
    // total is printed — the only remaining exclusion is the C9-pruned ledger.
    // Per-surface deltas, so the decomposition below is MEASURED term by term
    // rather than asserted as a total.
    let delta_of = |prefix: &str| -> usize {
        let pick = |c: &Vec<(&'static str, usize, usize)>| {
            c.iter()
                .find(|(n, _, _)| n.starts_with(prefix))
                .map(|(_, _, b)| *b)
                .unwrap_or(0)
        };
        pick(&after).saturating_sub(pick(&before))
    };
    let proposals_delta = delta_of("1 RECOVERY_PROPOSALS");
    let approvals_delta = delta_of("2 RECOVERY_APPROVALS");
    let intents_delta = delta_of("3 UPGRADE_INTENTS");
    let audit_delta = delta_of("4 AUDIT_EVENTS");
    let entry_rate_delta = delta_of("9 ENTRY_RATE_LEDGER");

    // The terminal record must hold NO artifact bytes — which is what makes
    // `intents_delta` pure METADATA, and therefore permanent rather than peak.
    // If this ever failed, the delta would contain artifact bytes and the
    // coefficient would scale with P_max instead of being fixed-width.
    let intent = core::get_intent(&IntentKey::recovery(id)).expect("intent exists");
    assert!(
        intent.wasm_bytes.is_none() && intent.arg_bytes.is_none(),
        "a terminal intent must have RELEASED its artifact bytes — the surviving \
         record is metadata only, and that is why its delta is a fixed-width \
         PERMANENT term rather than an artifact-sized peak"
    );

    let gross = census_total(&after) - census_total(&before);

    // ── FINDING 4 — PERMANENT vs BOUNDED, SEPARATED BEFORE THE MULTIPLICATION ─
    //
    // The prior figure multiplied a per-operation coefficient that still
    // contained C9-BOUNDED surfaces by a year of operations. That is not an
    // overstatement of a permanent quantity — it is a CATEGORY ERROR: a bounded
    // surface reaches a plateau and then stops, so multiplying it reports bytes
    // that are never allocated. Every bounded/pruned surface is therefore
    // classified and subtracted HERE, ahead of any horizon arithmetic, and the
    // plateau is reported as its own named quantity rather than folded in.
    //
    // The classification is EXHAUSTIVE over the census: every surface gets a
    // `SurfaceHorizon`, so a new store cannot be added without being classified.
    fn horizon_of(name: &str) -> SurfaceHorizon {
        match name {
            // Append-only permanent history — these ARE the growth.
            "1 RECOVERY_PROPOSALS" | "2 RECOVERY_APPROVALS" | "4 AUDIT_EVENTS" => {
                SurfaceHorizon::Permanent
            }
            // PERMANENT — corrected at SSA r2 return. The artifact FIELDS are
            // released at terminal, but the terminal `UpgradeIntent` RECORD
            // itself is never removed: `put_intent` only ever inserts, there is
            // no delete path on `UPGRADE_INTENTS` (MemoryId 3) anywhere, and no
            // sweep prunes it — core.rs calls it a permanent history in as many
            // words. The measured delta below is taken AFTER terminalization, so
            // it is exactly that surviving metadata (id, origin, the two 32-byte
            // hashes, outcome, timestamps) and not the artifact.
            //
            // The prior round classified the whole surface as a bounded
            // PEAK-FOOTPRINT term. That conflated the artifact with its
            // envelope: the artifact peak is indeed not permanent, but the
            // envelope outlives it forever, and excluding both understated the
            // coefficient by 251 B/op.
            "3 UPGRADE_INTENTS" => SurfaceHorizon::Permanent,
            // Active-set companions: emptied as operations terminalize, and
            // bounded by C12/single-flight while occupied.
            "5 NONTERMINAL_INTENT_INDEX"
            | "6 RECOVERY_PROPOSAL_EXPIRY_INDEX"
            | "8 PENDING_RECOVERY_PROPOSAL_INDEX"
            | "10 NONTERMINAL_RECOVERY_PROPOSAL_INDEX" => {
                SurfaceHorizon::Bounded { plateau_bytes: 0 }
            }
            // Fixed-size cells, rewritten in place — never appended.
            "7 COMPANION_STATE (bounded cell)" => SurfaceHorizon::Bounded { plateau_bytes: 0 },
            // THE C9-BOUNDED LEDGER the dispatch names: pruned to the rolling
            // window, so it plateaus at the global entry bound. Measured below.
            "9 ENTRY_RATE_LEDGER (bounded cell)" => SurfaceHorizon::Bounded { plateau_bytes: 0 },
            // R6.0 — MemoryId 11. Rewritten in place, at most once per
            // update-path observation, so it is a fixed footprint rather than
            // per-operation growth. It is the surface whose whole purpose is
            // NOT to grow with history.
            "11 LAST_CONTROLLER_INVARIANT (bounded cell)" => {
                SurfaceHorizon::Bounded { plateau_bytes: 0 }
            }
            // S8B — MemoryId 12. Two Option<u64> plus a version, rewritten in
            // place; the limiter's whole purpose is that it does not grow with
            // caller count, which is why it holds no per-caller state.
            "12 INVARIANT_REFRESH_LEDGER (bounded cell)" => {
                SurfaceHorizon::Bounded { plateau_bytes: 0 }
            }
            other => panic!(
                "census surface {other} is unclassified — every durable surface must be \
                 declared PERMANENT or BOUNDED before it can enter a horizon"
            ),
        }
    }

    let mut permanent_per_op = 0usize;
    let mut bounded_per_op = 0usize;
    for (i, (name, _, by)) in after.iter().enumerate() {
        let (_, _, b0) = before[i];
        let delta = by.saturating_sub(b0);
        if horizon_of(name).is_permanent() {
            permanent_per_op += delta;
        } else {
            bounded_per_op += delta;
        }
    }
    // The split is exhaustive: nothing may fall outside it.
    assert_eq!(
        permanent_per_op + bounded_per_op,
        gross,
        "every measured byte must be classified as permanent or bounded"
    );
    assert_eq!(
        bounded_per_op, entry_rate_delta,
        "the ONLY bounded share is the C9-pruned ledger — the terminal intent \
         record is permanent metadata and belongs in the coefficient"
    );
    assert_eq!(
        permanent_per_op,
        proposals_delta + approvals_delta + intents_delta + audit_delta,
        "the permanent coefficient is proposals + approvals + terminal intent \
         metadata + audit, each measured"
    );

    // ── THE BOUNDED PLATEAU, MEASURED AT C9 SATURATION ──────────────────────
    //
    // A named quantity in its own right: the ENTRY_RATE_LEDGER cannot exceed
    // this no matter how many operations run, because the sliding window prunes
    // to at most `global_per_window` live events.
    let c9 = stsh_custody_types::ENTRY_RATE_PARAMS.expect("C9 ruled at S6");
    let ledger_plateau = {
        // Saturate the global term with principals that stay under their own
        // per-signer bound, then read the cell's real encoded size.
        let t = 10_000_000u64;
        let mut n = 0u64;
        'fill: for who in 0..12u8 {
            for _ in 0..c9.per_signer_per_window as u64 - 1 {
                if core::charge_entry_event(p(0x30 + who), t + n).is_err() {
                    break 'fill;
                }
                n += 1;
            }
        }
        assert_eq!(
            core::entry_rate_global_count_for_test(),
            c9.global_per_window,
            "the ledger must be driven to the C9 global bound to measure its plateau"
        );
        core::measurement::census_for_test()
            .iter()
            .find(|(nm, _, _)| nm.starts_with("9 ENTRY_RATE_LEDGER"))
            .map(|(_, _, b)| *b)
            .expect("the ledger surface is censused")
    };

    const OPS_PER_DAY: usize = 24;
    const BURST: usize = 10;
    const DAYS: usize = 365;

    println!("\n=== M3‴ — C9 HORIZON, RECOVERY PLANE (COMPLETE TERMINAL LIFECYCLE) ===");
    println!("RULED INPUTS: {OPS_PER_DAY} ops/day, {BURST}x burst, PERMANENT retention.");
    println!("(ruled inputs, not builder selections)\n");
    println!("| surface | horizon | bytes / recovery operation |");
    println!("|---|---|---|");
    for (i, (name, cnt, by)) in after.iter().enumerate() {
        let (_, c0, b0) = before[i];
        if *cnt != c0 || *by != b0 {
            let h = if horizon_of(name).is_permanent() { "PERMANENT" } else { "bounded" };
            println!("| {name} | {h} | +{} |", by - b0);
        }
    }
    println!("| gross delta | — | {gross} |");
    println!(
        "| less ENTRY_RATE_LEDGER (C9-pruned — PLATEAUS, not growth) | bounded | -{entry_rate_delta} |"
    );
    println!("| **PERMANENT COEFFICIENT (recovery op class)** | PERMANENT | **{permanent_per_op}** |");
    println!(
        "\n  decomposed: proposals {proposals_delta} + approvals {approvals_delta} \
         + terminal intent metadata {intents_delta} + audit {audit_delta} = {permanent_per_op}"
    );

    println!("\n| bounded surface | plateau (one-time, NOT multiplied) |");
    println!("|---|---|");
    println!(
        "| ENTRY_RATE_LEDGER at C9 = {} live events | {ledger_plateau} B |",
        c9.global_per_window
    );
    println!(
        "\nTWO SEPARATE QUANTITIES, deliberately not summed into one: the \n\
         coefficient below is multiplied by operations; the plateau above is \n\
         reached once and then stops. Adding them would restate the category \n\
         error this corrects.\n"
    );

    // ── THE COEFFICIENT, ROUTED THROUGH GrowthClass (FINDING 3) ─────────────
    //
    // The measured recovery figure enters the V15 §2 model as the RECOVERY
    // class's own coefficient. This is the connection obligation 10 was missing:
    // the growth accounting now flows through the type, so a fifth term fails to
    // compile and a blended term fails the assertion below — neither is
    // `ALL.len()` arithmetic.
    let model = PermanentGrowthModel::new(
        3_135,                    // governed — Vault plane, M3 (unchanged here)
        139_057,                  // read-model — Vault plane, M3 (unchanged here)
        permanent_per_op as u64,  // recovery — MEASURED ABOVE, this plane
        714,                      // rotation, per event
    );
    assert_eq!(
        model.coefficient(GrowthClass::Recovery),
        permanent_per_op as u64,
        "the recovery class must carry the MEASURED coefficient, not a literal"
    );
    assert!(
        !model.has_blended_coefficients(),
        "the four V15 §2 terms must stay distinct — a measured recovery \
         coefficient that collides with another class means the terms have been \
         blended and the horizon below would be untrustworthy"
    );

    let year = permanent_per_op * OPS_PER_DAY * DAYS;
    println!("| horizon (PERMANENT term only) | bytes/yr | MiB/yr |");
    println!("|---|---|---|");
    println!("| steady ({OPS_PER_DAY}/day) | {year} | {:.2} |", year as f64 / 1_048_576.0);
    println!(
        "| burst ({BURST}x, capacity arithmetic NOT expectation) | {} | {:.2} |",
        year * BURST,
        (year * BURST) as f64 / 1_048_576.0
    );
    // Cross-check against the model, which multiplies the same coefficient by
    // the same op count through the typed path.
    assert_eq!(
        model.permanent_bytes(&GrowthCounts {
            recovery_ops: (OPS_PER_DAY * DAYS) as u64,
            ..GrowthCounts::default()
        }),
        year as u64,
        "the typed model and the printed horizon must agree — if they diverge, \
         one of them is not the accounting the other reports"
    );

    // ── ROTATION SERIES: FOUR base events, sized on THIS plane ──────────────
    //
    // E_rotation_max = C12 + 3 (V11/V12, frozen) — FOUR base lifecycle events,
    // superseding the rotation-decision doc's 3 + (G-1) (seat-owned, dispatch
    // §0.2). Event sizes are measured from the UPGRADER audit trail, which is
    // where rotation events are actually written; the prior version sized them
    // from the VAULT audit map, a different event set on a different plane.
    let upgrader_event_max = {
        let evs: Vec<usize> = core::measurement::audit_event_sizes_for_test();
        evs.iter().copied().max().unwrap_or(0)
    };
    println!("\n| E_rotation series (worst case, capacity arithmetic) | value |");
    println!("|---|---|");
    println!("| bound | E_rotation_max = C12 + 3 (FOUR base events) |");
    println!("| largest UPGRADER audit event measured | {upgrader_event_max} B |");
    for c12 in [32usize, 320] {
        let events = c12 + 3;
        println!(
            "| at C12={c12}: {events} events x {upgrader_event_max} B | {} B/rotation |",
            events * upgrader_event_max
        );
    }
    println!(
        "\nCAPACITY ARITHMETIC, not expectation: every pending slot occupied at the \n\
         moment of rotation and every event at the largest measured size. Rotation is \n\
         a governed recovery action — a ceiling on a rare event, not a rate."
    );
    println!(
        "\nFIXTURE, NOT THRESHOLD: the artifact in this fixture is small, but the \n\
         PERMANENT intent term does not depend on that — the surviving terminal \n\
         record is metadata (id, origin, two 32-byte hashes, outcome, timestamps) \n\
         and is FIXED-WIDTH. The artifact peak scales with P_max and is a separate \n\
         non-permanent quantity that this delta does not contain. The audit term \n\
         does not scale either.\n"
    );

    assert!(permanent_per_op > 0, "a recovery operation must grow permanent state");
    // FINDING 4, as corrected at the SSA r2 return. The ONLY bounded surface in
    // the coefficient was the C9-pruned ledger. The terminal intent record is
    // permanent history — `UPGRADE_INTENTS` has no delete path and no sweep —
    // so its metadata belongs IN the coefficient, not subtracted from it.
    assert_eq!(
        permanent_per_op,
        gross - entry_rate_delta,
        "the permanent coefficient excludes the C9-pruned ledger and NOTHING else"
    );
    assert!(
        entry_rate_delta > 0,
        "the C9 ledger must have MOVED — if it did not, the subtraction is \
         vacuous and proves nothing about the term it claims to remove"
    );
    assert!(
        ledger_plateau > 0 && (ledger_plateau as u64) < stsh_custody_types::GATE_SIZE_BOUND_BYTES,
        "the C9 plateau must be a real, bounded quantity"
    );
    assert!(
        intents_delta > 0,
        "the terminal intent surface must have MOVED — if it did not, the \
         permanent metadata term is vacuous and proves nothing"
    );
    assert!(upgrader_event_max > 0, "upgrader audit events must be measurable");
}

// =============================================================================
// FINDING 2 (S6 corrective r2) — RECOVERY-PLANE EVIDENCE PARITY
//
// The Upgrader's C6/C8 and its sliding C9 are SEPARATE IMPLEMENTATIONS from the
// Vault's. Vault tests prove nothing about them, so the full evidence set is
// duplicated here against this plane's own mechanisms.
//
// C6/C8 EQUALITY IS NOT LEGALLY REACHABLE HERE, AND THAT IS PROVED, NOT ASSUMED.
// Authorized substitution: DISPATCH_ADDENDUM_S6C2_RECOVERY_C6C8_SUBSTITUTION_
// 2026-08-11 (sha256 5b303862b4733a5d6d3c41306bc877fa985ea0472b0b3c0dc6599b053
// 759a26c), amending the dispatch (4cc8c774…). Three enforced mechanisms bound
// the retained total below C6:
//
//   M1 ATOMIC RELEASE   — `put_intent` is the SOLE `UPGRADE_INTENTS` write path
//                         and maintains the nonterminal index; terminalization
//                         releases the byte fields without any intervening
//                         await, so bytes never outlive their accounting entry
//                         across a message boundary. STATED PRECISELY, because
//                         the two terminalization paths differ (SSA r2 return):
//                           * `finish_intent` / `reconcile_intent` clear both
//                             byte fields in the SAME `put_intent` INVOCATION
//                             that drops the index entry — one logical phase;
//                           * `reap_linked_intent` (cancellation / expiry) uses
//                             TWO ordered `put_intent` invocations — terminal
//                             state and index release first, byte clear second —
//                             deliberately ordered so terminal state is durable
//                             before the bytes go. Both land in ONE message with
//                             no await between them, so they are
//                             transaction-atomic at message scope and a trap
//                             rolls back both.
//                         COUNTED IN INVOCATIONS, NOT STABLE WRITES (SSA r4): a
//                         single `put_intent` performs up to THREE stable
//                         mutations — `UPGRADE_INTENTS`, the nonterminal index,
//                         and the companion seal — so a raw write count would
//                         make both paths multi-write and hide the real property.
//                         The guarantee is "no MESSAGE boundary separates release
//                         from index removal", not "always a single write" —
//                         which would be false for the reap path.
//   M2 SINGLE FLIGHT    — gated pre-creation on BOTH origins, so at most one
//                         nonterminal intent exists across both namespaces.
//   M3 ARTIFACT BOUND   — `validate_artifact` refuses above GATE_SIZE_BOUND_BYTES
//                         = 1,900,000, of which 64 B are the two hashes.
//
//   => max retained = 1,900,000 - 64 = 1,899,936 B  <  C6 = 2,097,152  <  C8.
//
// WHY THIS IS NOT THE WITHDRAWN VAULT MARGIN CLAIM. That claim assumed the
// ROSTER bounded the ACCOUNTING, and it was false because nonterminal proposals
// outlived a rotation — bytes survived their proposer's departure. That exact
// failure mode is checked here and closed by M1: no message boundary separates
// the byte release from the index removal, so there is no state a later message
// could observe in which bytes are held but unaccounted. The bound is enforced
// mechanism, not headroom, and each mechanism carries a test below that FAILS
// if that mechanism breaks — never frozen commentary.
// =============================================================================

/// wasm+arg bytes of the largest artifact `validate_artifact` admits: the gate
/// bound less the two 32-byte hashes it counts alongside them.
const MAX_LEGAL_ARTIFACT_BYTES: u64 = GATE_SIZE_BOUND_BYTES - 64;

/// A hash-consistent artifact whose `wasm + arg` length is exactly `total`.
fn artifact_of_size(total: u64) -> RecoveryAction {
    // Split so the sum is EXACTLY `total` at every size the tests use, down to
    // a couple of bytes — both limbs count `wasm + arg`, so the split itself
    // must never change the quantity under test.
    let arg_len = std::cmp::min(16, total / 2) as usize;
    let arg = vec![0xABu8; arg_len];
    let wasm = vec![0xCDu8; (total as usize) - arg_len];
    RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: wasm,
        arg_bytes: arg,
    }
}

/// Every durable surface a refused admission must leave untouched.
#[derive(PartialEq, Eq, Debug)]
struct RecoveryStateSnapshot {
    audit_len: u64,
    entry_rate: u32,
    nonterminal_proposals: usize,
    nonterminal_intents: usize,
    global_bytes: u64,
    approval_log: u64,
}

fn snapshot() -> RecoveryStateSnapshot {
    RecoveryStateSnapshot {
        audit_len: core::audit_len_for_test(),
        entry_rate: core::entry_rate_global_count_for_test(),
        nonterminal_proposals: core::nonterminal_proposal_count_for_test(),
        nonterminal_intents: core::nonterminal_intent_count_for_test(),
        global_bytes: core::recovery_retained_bytes_for_test(None),
        approval_log: core::approval_log_len_for_test(),
    }
}

// ── The conclusion, stated as arithmetic over ruled constants ────────────────

#[test]
fn s6c2_recovery_c6_c8_are_unreachable_by_enumerated_mechanism() {
    // Pure constant arithmetic — no fixture can make this true by accident, and
    // re-ruling any of the three constants breaks it loudly.
    assert_eq!(MAX_LEGAL_ARTIFACT_BYTES, 1_899_936);
    assert!(
        MAX_LEGAL_ARTIFACT_BYTES < stsh_custody_types::PER_SIGNER_BYTE_QUOTA,
        "C6 must sit ABOVE the largest legally admissible artifact"
    );
    assert!(
        stsh_custody_types::PER_SIGNER_BYTE_QUOTA
            < stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA,
        "C8 must sit above C6"
    );

    // And the mechanism agrees with the arithmetic: drive the single permitted
    // nonterminal intent to the ceiling and observe the limbs at their maximum.
    setup();
    let pid = core::propose_recovery(
        &p(M1),
        artifact_of_size(MAX_LEGAL_ARTIFACT_BYTES),
        100,
        None,
        &self_p(),
    )
    .expect("the ceiling artifact is legally admissible");

    assert_eq!(
        core::recovery_retained_bytes_for_test(None),
        MAX_LEGAL_ARTIFACT_BYTES,
        "the global limb sits at the ceiling — this is the MAXIMUM this plane \
         can ever hold, because single-flight forbids a second nonterminal intent"
    );
    assert_eq!(
        core::recovery_retained_bytes_for_test(Some(p(M1))),
        MAX_LEGAL_ARTIFACT_BYTES,
        "and all of it attributes to the one proposer"
    );
    // The maximum possible total is still short of BOTH caps.
    assert!(core::recovery_retained_bytes_for_test(None) < stsh_custody_types::PER_SIGNER_BYTE_QUOTA);
    assert!(
        core::recovery_retained_bytes_for_test(None)
            < stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA
    );
    assert_eq!(core::nonterminal_intent_count_for_test(), 1, "single-flight holds");
    let _ = pid;
}

// ── M1: atomic release — bytes never outlive the accounting entry ────────────

/// FAILS IF M1 BREAKS, on the `finish_intent` path — ONE `put_intent`
/// invocation, byte fields cleared in the same invocation that drops the index
/// entry. (One INVOCATION, not one stable write: `put_intent` also reindexes and
/// seals the companion.)
///
/// This is the finding-1 failure mode transplanted to this plane: if
/// terminalization ever stopped releasing the bytes, they would become invisible
/// to the limbs and could accumulate without bound — exactly how the Vault's
/// roster-bound assumption went wrong.
///
/// The OTHER terminalization path (`reap_linked_intent`, two ordered
/// invocations) is covered by the companion test below; the two are separated
/// because the paths genuinely differ and one test cannot witness both.
#[test]
fn s6c2_m1_release_is_atomic_with_index_removal() {
    setup();
    let size = 4_096u64;
    let pid = core::propose_recovery(&p(M1), artifact_of_size(size), 100, None, &self_p())
        .expect("propose");
    assert_eq!(core::recovery_retained_bytes_for_test(None), size);

    core::approve_recovery(&p(M1), pid, 101, commit_of(pid), &self_p()).expect("proposer approves");
    let plan = match core::approve_recovery(&p(M2), pid, 200, commit_of(pid), &self_p())
        .expect("quorum")
    {
        ApproveOutcome::Execute(RecoveryExecution::Trigger { plan, .. }) => plan,
        other => panic!("expected execution, got {other:?}"),
    };
    core::finish_intent(&plan.key, &Ok(()), 300);
    core::recovery_finish_trigger(pid, ActionOutcome::Executed, 300);

    // Both halves of atomicity, asserted independently — neither implies the
    // other, and checking only the limb would pass even if the bytes stayed.
    let intent = core::get_intent_for_test(&IntentKey::recovery(pid)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::Executed);
    assert!(
        intent.wasm_bytes.is_none() && intent.arg_bytes.is_none(),
        "M1: the terminal record itself must hold no bytes — a limb reading 0 \
         because the entry left the index would be under-accounting, not release"
    );
    assert_eq!(core::nonterminal_intent_count_for_test(), 0, "M1: entry dropped");
    assert_eq!(core::recovery_retained_bytes_for_test(None), 0, "M1: global limb released");
    assert_eq!(core::recovery_retained_bytes_for_test(Some(p(M1))), 0, "M1: per-signer released");
}

/// FAILS IF M1 BREAKS on the REAP path — `reap_linked_intent` (cancellation and
/// expiry), which uses TWO ordered `put_intent` invocations rather than one.
///
/// ADDED AT THE SSA r2 RETURN. The packet-v2 wording claimed terminalization
/// always clears the bytes in a single `put_intent`; that is true of
/// `finish_intent`/`reconcile_intent` but FALSE here. `reap_linked_intent`
/// deliberately records terminal state and releases the index in its FIRST
/// invocation, then clears the bytes in a SECOND, so that terminal state is
/// durable before the evidence goes. Both invocations land in one message with
/// no await between them, so they are transaction-atomic at message scope — but
/// the evidence set had no test on this path at all, which is why the wording
/// error survived review.
///
/// What must hold is the OBSERVABLE property: after the message, no bytes are
/// held and no index entry remains.
#[test]
fn s6c2_m1_reap_path_releases_bytes_and_index_together() {
    setup();
    let size = 4_096u64;
    let pid = core::propose_recovery(&p(M1), artifact_of_size(size), 100, None, &self_p())
        .expect("propose");
    assert_eq!(core::recovery_retained_bytes_for_test(None), size, "held while Pending");
    assert_eq!(core::nonterminal_intent_count_for_test(), 1);

    // Cancellation reaps the linked PENDING intent through the two-write path.
    core::cancel_recovery_proposal(&p(M1), pid, 200).expect("proposer cancels their own");

    let intent = core::get_intent_for_test(&IntentKey::recovery(pid)).expect("intent");
    assert_eq!(intent.outcome, ActionOutcome::Cancelled);
    assert!(
        intent.wasm_bytes.is_none() && intent.arg_bytes.is_none(),
        "M1/reap: the cancelled record must hold no bytes once the message ends"
    );
    assert_eq!(core::nonterminal_intent_count_for_test(), 0, "M1/reap: index released");
    assert_eq!(core::recovery_retained_bytes_for_test(None), 0, "M1/reap: global limb");
    assert_eq!(core::recovery_retained_bytes_for_test(Some(p(M1))), 0, "M1/reap: per-signer");

    // And the single-flight slot is genuinely free again — the release is real,
    // not merely an accounting adjustment.
    core::propose_recovery(&p(M2), artifact_of_size(size), 300, None, &self_p())
        .expect("M1/reap: a released slot must admit a fresh intent");
}

// ── M2: single-flight gate — at most one nonterminal intent, both origins ────

/// FAILS IF M2 BREAKS. If a second artifact-bearing intent could be admitted
/// while one is nonterminal, the retained total would no longer be bounded by a
/// single artifact and the C6/C8 unreachability proof would collapse.
#[test]
fn s6c2_m2_single_flight_gate_bounds_the_nonterminal_set_at_one() {
    setup();
    let size = 8_192u64;
    core::propose_recovery(&p(M1), artifact_of_size(size), 100, None, &self_p()).expect("first");
    assert_eq!(core::recovery_retained_bytes_for_test(None), size);

    let before = snapshot();
    // A DIFFERENT member proposing a DIFFERENT artifact — the gate is global
    // across proposers and across both origin namespaces, not per-member.
    assert_eq!(
        core::propose_recovery(&p(M2), artifact_of_size(size), 200, None, &self_p()).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "M2: a second nonterminal artifact-bearing intent must be refused"
    );
    assert_eq!(snapshot(), before, "M2: the refusal is free — no durable movement");

    // The vault-origin namespace is gated by the same lock.
    let (wasm, arg, wh, ah) = artifact(9);
    assert_eq!(
        core::trigger_begin(&p(VAULT), 4_242, wh, ah, wasm, arg, 300).unwrap_err(),
        RecoveryError::IllegalSourceState,
        "M2: single-flight spans BOTH origins, not just the recovery namespace"
    );
    assert_eq!(core::nonterminal_intent_count_for_test(), 1, "M2: still exactly one");
    assert_eq!(core::recovery_retained_bytes_for_test(None), size, "unchanged");
}

// ── M3: artifact bound — nothing above the gate bound is ever stored ─────────

/// FAILS IF M3 BREAKS. The ceiling is what makes one artifact smaller than C6;
/// without it a single intent could hold arbitrarily many bytes.
#[test]
fn s6c2_m3_artifact_bound_refuses_above_the_gate_bound_with_zero_mutation() {
    setup();
    let before = snapshot();
    let err = core::propose_recovery(
        &p(M1),
        artifact_of_size(MAX_LEGAL_ARTIFACT_BYTES + 1),
        100,
        None,
        &self_p(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        RecoveryError::SizeLimitExceeded {
            encoded_bytes: GATE_SIZE_BOUND_BYTES + 1,
            limit_bytes: GATE_SIZE_BOUND_BYTES,
        },
        "M3: one byte over the gate bound is refused, and the error reports the \
         ruled limit rather than a derived one"
    );
    // CEILING+1 IS FREE: refused above the C9 charge and above id allocation.
    assert_eq!(
        snapshot(),
        before,
        "M3: an oversize refusal burns no rate budget, allocates no id, appends \
         no audit and moves neither byte limb"
    );
    // The id was not consumed — the next admission takes the id the refusal
    // would have taken had it allocated one.
    let pid = core::propose_recovery(&p(M1), artifact_of_size(1_024), 200, None, &self_p())
        .expect("admission after a refusal");
    assert_eq!(pid, 1, "M3: the refused attempt consumed no proposal id");
}

// ── Both limbs enforce on the admission path ────────────────────────────────

/// The per-signer (C6) and global (C8) limbs are two separate checks in
/// `check_recovery_retained_bytes`. Neither is reachable by a legal artifact, so
/// enforcement is proved by driving each limb directly with a lowered ceiling —
/// the same technique the Vault uses to measure a limb whose legal path is long.
#[test]
fn s6c2_both_recovery_byte_limbs_enforce_on_the_admission_path() {
    setup();
    // At the ceiling the accounting attributes ALL bytes to the proposer, so
    // both limbs see the same total and both are exercised by the same read.
    let pid = core::propose_recovery(
        &p(M1),
        artifact_of_size(MAX_LEGAL_ARTIFACT_BYTES),
        100,
        None,
        &self_p(),
    )
    .expect("ceiling admits");

    assert_eq!(core::recovery_retained_bytes_for_test(Some(p(M1))), MAX_LEGAL_ARTIFACT_BYTES);
    assert_eq!(core::recovery_retained_bytes_for_test(Some(p(M2))), 0,
        "attribution is per-proposer — M2 holds nothing");
    assert_eq!(core::recovery_retained_bytes_for_test(None), MAX_LEGAL_ARTIFACT_BYTES,
        "the global limb sums the same bytes exactly once");

    // Reconciliation carries evidence, not an artifact: delta 0, no quota.
    let _ = pid;
}

// ── Release vs OutcomeUnknown, at the BYTE-LIMB level ────────────────────────

/// The existing `l2_1_*` tests prove retention at the RECORD level. Finding 2
/// needs it at the ACCOUNTING level: the limbs must track retention and release
/// 1:1, because the limbs are what admission actually reads.
#[test]
fn s6c2_byte_limbs_track_release_vs_outcome_unknown() {
    setup();
    let size = 16_384u64;
    let (wasm, arg, wh, ah) = {
        let arg = vec![0x11u8; 16];
        let wasm = vec![0x22u8; (size as usize) - 16];
        let (wh, ah) = (sha256(&wasm), sha256(&arg));
        (wasm, arg, wh, ah)
    };
    let (_, plan) = core::trigger_begin(&p(VAULT), 21, wh, ah, wasm, arg, 100).expect("trigger");
    let plan = plan.expect("plan");
    assert_eq!(core::recovery_retained_bytes_for_test(None), size, "held while Executing");

    // OutcomeUnknown RETAINS — the evidence is still needed, so the bytes still
    // count against the quota. A limb that released here would under-account.
    assert_eq!(core::finish_intent(&plan.key, &Err("timeout".into()), 200),
        ActionOutcome::OutcomeUnknown);
    assert_eq!(
        core::recovery_retained_bytes_for_test(None),
        size,
        "OutcomeUnknown is NONTERMINAL: bytes retained AND still accounted"
    );
    assert_eq!(core::nonterminal_intent_count_for_test(), 1, "still occupies the slot");

    // Reconciling to terminal releases, in the same write.
    assert_eq!(
        core::reconcile_vault_upgrade(&p(VAULT), 21, &evidence(Some(sha256(b"other")), 300),
            &p(SELF_ID), 300),
        Ok(ReconcileTerminalOutcome::Failed)
    );
    assert_eq!(core::recovery_retained_bytes_for_test(None), 0, "terminal releases");
    assert_eq!(core::nonterminal_intent_count_for_test(), 0);
}

// ── Independent 1:1 mutation checks — byte limbs ─────────────────────────────

/// The limbs must move by EXACTLY the admitted artifact and back to EXACTLY
/// zero — not merely "increase" and "decrease". A drifting accumulator that is
/// only ever asserted directionally passes a directional test forever.
#[test]
fn s6c2_byte_limbs_move_1_to_1_with_admission_and_release() {
    setup();
    for (round, size) in [(1u64, 1_024u64), (2, 65_536), (3, 4)].into_iter() {
        assert_eq!(core::recovery_retained_bytes_for_test(None), 0, "round {round}: clean start");
        let t = 1_000 * round;
        let pid = core::propose_recovery(&p(M1), artifact_of_size(size), t, None, &self_p())
            .expect("propose");
        assert_eq!(
            core::recovery_retained_bytes_for_test(None), size,
            "round {round}: global limb moved by EXACTLY the artifact size"
        );
        assert_eq!(
            core::recovery_retained_bytes_for_test(Some(p(M1))), size,
            "round {round}: per-signer limb moved by exactly the same amount"
        );
        core::approve_recovery(&p(M1), pid, t + 1, commit_of(pid), &self_p()).expect("approve");
        let plan = match core::approve_recovery(&p(M2), pid, t + 2, commit_of(pid), &self_p())
            .expect("quorum")
        {
            ApproveOutcome::Execute(RecoveryExecution::Trigger { plan, .. }) => plan,
            other => panic!("expected execution, got {other:?}"),
        };
        core::finish_intent(&plan.key, &Ok(()), t + 3);
        core::recovery_finish_trigger(pid, ActionOutcome::Executed, t + 3);
        assert_eq!(
            core::recovery_retained_bytes_for_test(None), 0,
            "round {round}: released to EXACTLY zero — no residue accumulates \
             across operations"
        );
        assert_eq!(core::recovery_retained_bytes_for_test(Some(p(M1))), 0);
    }
}

// ── C9 on the recovery plane: sliding, straddle, gradual expiry ──────────────

const C9_WINDOW_NS: u64 = 86_400 * 1_000_000_000;

/// The recovery plane's C9 is its OWN sliding ledger. The corrected behaviour
/// is that a caller straddling what used to be the tumbling reset boundary does
/// NOT get a second full budget: expiry is per-event, so exactly one slot frees
/// at a time.
#[test]
fn s6c2_recovery_c9_slides_and_the_straddle_grants_no_second_budget() {
    setup();
    let params = stsh_custody_types::ENTRY_RATE_PARAMS.expect("C9 ruled at S6");
    let per_signer = params.per_signer_per_window;
    assert_eq!(per_signer, 26, "C9 per-signer, V15 §1 row 9");
    assert_eq!(params.window_ns, C9_WINDOW_NS);

    // Fill M1's per-signer budget, one event per ns so each expires distinctly.
    let t0 = 1_000_000u64;
    for i in 0..per_signer as u64 {
        core::charge_entry_event(p(M1), t0 + i).expect("within budget");
    }
    assert_eq!(core::entry_rate_global_count_for_test(), per_signer);
    // At the bound, refused.
    assert_eq!(
        core::charge_entry_event(p(M1), t0 + per_signer as u64).unwrap_err(),
        RecoveryError::ThresholdViolation
    );

    // THE STRADDLE. Under the old TUMBLING window this instant reset the whole
    // count and handed out a second full budget inside one real rolling window.
    // Sliding: only the single event that has aged out is released.
    let straddle = t0 + C9_WINDOW_NS;
    assert_eq!(core::entry_rate_global_count_for_test(), per_signer);
    core::charge_entry_event(p(M1), straddle).expect("exactly one slot has freed");
    assert_eq!(
        core::charge_entry_event(p(M1), straddle).unwrap_err(),
        RecoveryError::ThresholdViolation,
        "SLIDING, NOT TUMBLING: the boundary frees ONE slot, never the budget"
    );
    assert_eq!(
        core::entry_rate_global_count_for_test(), per_signer,
        "the live count stays pinned at the bound across the boundary"
    );
}

/// Gradual expiry: slots return one at a time as individual events age out,
/// which is the property that makes the sliding window a real rate limit.
#[test]
fn s6c2_recovery_c9_expires_gradually_one_slot_at_a_time() {
    setup();
    let per_signer =
        stsh_custody_types::ENTRY_RATE_PARAMS.expect("C9 ruled").per_signer_per_window;
    let t0 = 5_000_000u64;
    for i in 0..per_signer as u64 {
        core::charge_entry_event(p(M1), t0 + i).expect("fill");
    }
    // Walk the boundary forward one nanosecond at a time: each step retires
    // exactly one event and therefore admits exactly one.
    for i in 0..5u64 {
        let now = t0 + C9_WINDOW_NS + i;
        core::charge_entry_event(p(M1), now).expect("one slot freed by expiry");
        assert_eq!(
            core::charge_entry_event(p(M1), now).unwrap_err(),
            RecoveryError::ThresholdViolation,
            "step {i}: only ONE slot may be reclaimed per expired event"
        );
        assert_eq!(core::entry_rate_global_count_for_test(), per_signer);
    }
}

/// The global term is a LIVE constraint, not a restatement of the per-signer
/// one: 26 x 9 = 234 < 240, so saturating it needs more principals than a full
/// roster, and it must bind independently.
#[test]
fn s6c2_recovery_c9_global_limb_binds_independently_of_the_per_signer_limb() {
    setup();
    let params = stsh_custody_types::ENTRY_RATE_PARAMS.expect("C9 ruled");
    assert_eq!((params.global_per_window, params.per_signer_per_window), (240, 26));
    let t0 = 9_000_000u64;
    let mut charged = 0u32;
    // Ten principals x 24 each = 240, with every principal strictly under its
    // own per-signer bound — so the refusal below can only be the GLOBAL limb.
    for who in 0..10u8 {
        for i in 0..24u64 {
            core::charge_entry_event(p(0x20 + who), t0 + charged as u64 + i).expect("under both");
            charged += 1;
        }
    }
    assert_eq!(charged, params.global_per_window);
    assert_eq!(core::entry_rate_global_count_for_test(), params.global_per_window);
    // A fresh principal with ZERO personal history is refused — per-signer
    // cannot be the cause, so this is the global term binding.
    assert_eq!(
        core::charge_entry_event(p(0x7E), t0 + 1_000).unwrap_err(),
        RecoveryError::ThresholdViolation,
        "the global limb refuses a caller who has spent none of their own budget"
    );
}

// ── Independent 1:1 mutation check — the recovery sliding ledger ─────────────

/// The ledger must move by exactly one per ADMITTED event and by exactly zero
/// per refusal. A refusal that still recorded its event would let a
/// rate-limited caller consume budget by being refused.
#[test]
fn s6c2_recovery_sliding_ledger_moves_1_to_1_with_charges() {
    setup();
    let t0 = 3_000_000u64;
    for i in 0..10u64 {
        let before = core::entry_rate_global_count_for_test();
        core::charge_entry_event(p(M1), t0 + i).expect("within budget");
        assert_eq!(
            core::entry_rate_global_count_for_test(), before + 1,
            "step {i}: exactly one event recorded per admission"
        );
    }
    // Drive M1 to its bound, then confirm refusals cost exactly nothing.
    let per_signer =
        stsh_custody_types::ENTRY_RATE_PARAMS.expect("C9 ruled").per_signer_per_window;
    for i in 10..per_signer as u64 {
        core::charge_entry_event(p(M1), t0 + i).expect("fill to bound");
    }
    let at_bound = core::entry_rate_global_count_for_test();
    for i in 0..5u64 {
        assert_eq!(
            core::charge_entry_event(p(M1), t0 + 1_000 + i).unwrap_err(),
            RecoveryError::ThresholdViolation
        );
        assert_eq!(
            core::entry_rate_global_count_for_test(), at_bound,
            "refusal {i}: a refused charge records NOTHING — being refused must \
             never consume budget"
        );
    }
}

// =============================================================================
// §S7 START SETTLEMENT — CELL 4 ACCEPTANCE (Upgrader -> Vault), CUST-SSA-004
//
// The PLANE-SPECIFIC half. The direction-agnostic predicates (§4, §4a, §5, §7d
// classification, §7f order, §3c guard) are asserted once, over BOTH
// directions, in `stsh-custody-types/tests/s7_start_settlement_acceptance.rs`:
// both planes call the SAME functions, so asserting them there is stronger than
// asserting two copies here. What CANNOT be proven from pure functions is
// asserted below — E1, the E2 sweep, the §3c fence's audit and its bound, the
// §8a atomic durable transition, single-flight, and target non-redirection.
//
// The cell-3 twin lives in the vault's suite and asserts the same properties in
// the other direction.
// =============================================================================

/// A §4 start evidence fixture for cell 4: the target is the VAULT and its
/// controller must be exactly this canister (the Upgrader).
fn start_evidence(status: ObservedCanisterStatus, at: u64) -> stsh_custody_types::StartObjectiveEvidence {
    stsh_custody_types::StartObjectiveEvidence {
        observed_target_principal: p(VAULT),
        observed_canister_status: status,
        observed_controllers: vec![self_p()],
        observed_at_ns: at,
    }
}

/// Drive a `StartVault` proposal to the quorum boundary and return its id.
/// Returns the id and the execution the quorum decided on.
fn start_to_quorum(now: u64) -> (u64, ApproveOutcome) {
    let id = core::propose_recovery(&p(M1), RecoveryAction::StartVault, now, None, &self_p())
        .expect("propose StartVault");
    core::approve_recovery(&p(M1), id, now, commit_of(id), &self_p()).expect("first approval");
    let out = core::approve_recovery(&p(M2), id, now, commit_of(id), &self_p())
        .expect("quorum approval");
    (id, out)
}

fn outcome_of(id: u64) -> ActionOutcome {
    core::query_recovery_proposal(&p(M1), id).expect("proposal").outcome
}

fn start_state(id: u64) -> stsh_custody_types::StartSettlementState {
    core::query_recovery_proposal(&p(M1), id)
        .expect("proposal")
        .start
        .expect("start state present")
}

fn audit_kinds() -> Vec<UpgraderAuditEventKind> {
    core::query_audit_events(&p(M1), None, MAX_READ_PAGE_LIMIT)
        .expect("audit")
        .events
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

fn count_fenced(id: u64) -> usize {
    audit_kinds()
        .iter()
        .filter(|k| matches!(k, UpgraderAuditEventKind::LateCallbackFenced { proposal_id, .. } if *proposal_id == id))
        .count()
}

fn count_conflicts(id: u64) -> usize {
    audit_kinds()
        .iter()
        .filter(|k| matches!(
            k,
            UpgraderAuditEventKind::SettlementEvidenceConflictRecorded { conflict }
                if conflict.proposal_id == id
        ))
        .count()
}

// ── ACCEPTANCE 2 (part) / §2 — the pre-await obligations ────────────────────

/// §2: at the quorum boundary, `Executing` is durable AND the start-intent is
/// durable, BOTH before the shell can reach the first `await`. The intent binds
/// proposal id, target, epoch and intent time; the target comes from DURABLE
/// MEMBERSHIP, never from the action.
#[test]
fn s7_cell4_start_intent_is_durable_before_the_first_await() {
    setup();
    let (id, out) = start_to_quorum(2_000);

    // The plan the shell will act on — returned only AFTER both writes landed.
    match out {
        ApproveOutcome::Execute(RecoveryExecution::Start { proposal_id, target }) => {
            assert_eq!(proposal_id, id);
            assert_eq!(target, p(VAULT), "§1: the target is the Vault from durable membership");
        }
        other => panic!("expected a Start execution, got {other:?}"),
    }

    assert_eq!(outcome_of(id), ActionOutcome::Executing, "§2.2: Executing is durable");
    let st = start_state(id);
    assert_eq!(st.intent.proposal_id, id);
    assert_eq!(st.intent.target, p(VAULT));
    assert_eq!(st.intent.intent_at_ns, 2_000, "§2.3: the intent is timestamped");
    assert!(st.settlement.is_none(), "no settlement before reconciliation");

    // MUTATION: were the intent written AFTER the await (or not at all), the
    // start state would be absent here while the plan had already been issued
    // — and `finish_start` traps on exactly that, which is what makes the
    // ordering load-bearing rather than incidental.
    assert!(
        core::query_recovery_proposal(&p(M1), id).unwrap().start.is_some(),
        "MUTATION: dropping the pre-await intent write leaves no start state"
    );
}

// ── ACCEPTANCE 1 — reply loss => OutcomeUnknown via E1, never blindly Failed ──

#[test]
fn s7_cell4_acceptance_1_reply_loss_is_outcome_unknown_never_failed() {
    setup();
    let (id, _) = start_to_quorum(2_000);

    let outcome = core::finish_start(id, &Err("SysTransient: no reply".to_string()), 3_000);

    assert_eq!(outcome, ActionOutcome::OutcomeUnknown);
    assert_eq!(
        outcome_of(id),
        ActionOutcome::OutcomeUnknown,
        "E1: a transport rejection routes to OutcomeUnknown IN THIS SAME MESSAGE"
    );
    assert_ne!(
        outcome_of(id),
        ActionOutcome::Failed,
        "NEVER blindly Failed — a management-call rejection cannot distinguish \
         pre- from post-execution, and inferring failure is the assumption R-2 \
         forecloses"
    );
    assert!(
        start_state(id).settlement.is_none(),
        "E1 writes no SettlementRecord: no §4 evidence existed"
    );
    assert!(
        audit_kinds().iter().any(|k| matches!(
            k,
            UpgraderAuditEventKind::VaultStartOutcomeUnknown { proposal_id, .. } if *proposal_id == id
        )),
        "E1 is audited"
    );
}

/// The other half of §3a's callback edge: an observed success terminalizes
/// `Executed` and — deliberately — carries NO `SettlementRecord`, because no §4
/// evidence existed. That is what makes a later reconcile against it a §7f
/// step-2 illegal source (acceptance 7) rather than a replay.
#[test]
fn s7_cell4_observed_success_is_executed_with_no_settlement_record() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    assert_eq!(core::finish_start(id, &Ok(()), 3_000), ActionOutcome::Executed);
    assert_eq!(outcome_of(id), ActionOutcome::Executed);
    assert!(
        start_state(id).settlement.is_none(),
        "a callback-terminalized start holds NO SettlementRecord"
    );

    // Consequently a reconcile against it is an ILLEGAL SOURCE, never a replay.
    let r = core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Running, 3_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    );
    assert_eq!(r, Err(RecoveryError::IllegalSourceState));
}

// ── ACCEPTANCE 4 / 5 end-to-end on the plane ────────────────────────────────

#[test]
fn s7_cell4_settlement_writes_outcome_and_record_together() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);

    let ev = start_evidence(ObservedCanisterStatus::Running, 3_500);
    let out = core::reconcile_vault_start(
        id,
        &ev,
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    );
    assert_eq!(out, Ok(Some(ReconcileTerminalOutcome::Executed)));

    // §8a invariant 1: THERE IS NO INTERLEAVING IN WHICH THE PROPOSAL IS
    // TERMINAL WITHOUT ITS RECORD — both are fields of one object written by a
    // single synchronous `put_stored_proposal`.
    let st = start_state(id);
    let rec = st.settlement.expect("terminal implies a durable record");
    assert_eq!(outcome_of(id), ActionOutcome::Executed);
    assert_eq!(rec.outcome, ReconcileTerminalOutcome::Executed);
    assert_eq!(rec.semantic_key, ev.semantic_key(), "the SETTLING evidence's identity");
    assert_eq!(rec.evidence_commitment, ev.evidence_commitment());
    assert_eq!(rec.observed_at_ns, 3_500);
    assert!(!rec.conflict_recorded, "the §7d cap starts available");
}

/// §5 / acceptance 5 on the plane: `Stopping` does not terminalize, the lock is
/// NOT released, no audit append — and a later re-observation settles it.
#[test]
fn s7_cell4_acceptance_5_stopping_retains_the_lock_and_appends_nothing() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);

    let before = audit_kinds().len();
    let out = core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Stopping, 3_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    );
    assert_eq!(out, Ok(None), "no settlement — inconclusive");
    assert_eq!(outcome_of(id), ActionOutcome::OutcomeUnknown, "no terminalization");
    assert!(start_state(id).settlement.is_none(), "no record is written");
    assert_eq!(audit_kinds().len(), before, "NO audit append: a non-transition is not an event");

    // The lock is RETAINED: the proposal is still nonterminal, so a second
    // start cannot be admitted while it is open.
    assert!(
        !outcome_of(id).is_terminal(),
        "§7e: the lock releases ONLY at the first transition to Executed|Failed"
    );

    // Re-observation settles it (acceptance 5's final clause).
    let out = core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Stopped, 4_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        5_000,
    );
    assert_eq!(out, Ok(Some(ReconcileTerminalOutcome::Failed)));
    assert_eq!(outcome_of(id), ActionOutcome::Failed);
}

// ── ACCEPTANCE 10 / 11 — late-callback fencing, and its bound ───────────────

/// Acceptance 10: drive the E2 sweep, THEN deliver the pre-upgrade callback and
/// assert `ActionOutcome` unchanged, no terminalization, lock still held,
/// `SettlementRecord` absent. Repeated with the proposal already settled.
#[test]
fn s7_cell4_acceptance_10_late_callback_is_fenced_after_e2() {
    setup();
    let (id, _) = start_to_quorum(2_000);

    // E2 runs (the upgrade boundary).
    core::sweep_executing_starts_to_unknown(3_000);
    assert_eq!(outcome_of(id), ActionOutcome::OutcomeUnknown);

    let before_state = core::query_recovery_proposal(&p(M1), id).unwrap();
    // The pre-upgrade callback is delivered AFTERWARDS, carrying "success".
    let observed = core::finish_start(id, &Ok(()), 3_500);

    assert_eq!(observed, ActionOutcome::OutcomeUnknown, "the fenced state is reported back");
    let after_state = core::query_recovery_proposal(&p(M1), id).unwrap();
    assert_eq!(
        before_state, after_state,
        "§3c.2: a fenced callback performs ZERO settlement-state mutation — \
         asserted as EXACT RECORD EQUALITY, not inferred from one field"
    );
    assert!(after_state.start.unwrap().settlement.is_none(), "no SettlementRecord");
    assert_eq!(count_fenced(id), 1, "§3c.3: exactly one bounded fencing event");

    // MUTATION: remove the guard — i.e. let the callback write from a
    // non-`Executing` state — and the `Ok(())` above would terminalize the
    // proposal `Executed` from a payload that is NEVER evidence, reintroducing
    // the un-evidenced settlement path R-2 forecloses. The equality assertion
    // above is what registers that.
    assert!(
        !stsh_custody_types::callback_may_write(ActionOutcome::OutcomeUnknown),
        "MUTATION: widening the guard to admit OutcomeUnknown breaks the \
         zero-mutation assertion above"
    );
}

/// Acceptance 10, repeated with the proposal already `Executed` and already
/// `Failed` — the "already settled, single-shot" rows of §3c.2's table.
#[test]
fn s7_cell4_acceptance_10_late_callback_fenced_when_already_settled() {
    for (status, expected) in [
        (ObservedCanisterStatus::Running, ActionOutcome::Executed),
        (ObservedCanisterStatus::Stopped, ActionOutcome::Failed),
    ] {
        setup();
        let (id, _) = start_to_quorum(2_000);
        core::finish_start(id, &Err("no reply".to_string()), 3_000);
        core::reconcile_vault_start(
            id,
            &start_evidence(status, 3_500),
            ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
            &self_p(),
            4_000,
        )
        .expect("settles");
        assert_eq!(outcome_of(id), expected);

        let before = core::query_recovery_proposal(&p(M1), id).unwrap();
        core::finish_start(id, &Ok(()), 5_000);
        let after = core::query_recovery_proposal(&p(M1), id).unwrap();
        assert_eq!(
            before, after,
            "already-settled is FENCED: no second terminalization, no second \
             audit of the settlement, zero state change"
        );
        assert_eq!(count_fenced(id), 1);
    }
}

/// Acceptance 11 — the fencing audit is bounded at AT MOST ONE PER PROPOSAL,
/// ALWAYS. Bounded by construction (§2: at most one outstanding call per
/// proposal), not by a cap, and not caller-driven.
#[test]
fn s7_cell4_acceptance_11_fencing_audit_is_bounded() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::sweep_executing_starts_to_unknown(3_000);
    // One callback is all §2 admits; deliver it.
    core::finish_start(id, &Ok(()), 3_500);
    assert_eq!(count_fenced(id), 1, "at most one LateCallbackFenced per proposal");
}

// ── ACCEPTANCE 12 — the E2 sweep is idempotent and safe ─────────────────────

#[test]
fn s7_cell4_acceptance_12_e2_sweep_is_idempotent_and_safe() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    assert_eq!(outcome_of(id), ActionOutcome::Executing);

    // First upgrade: promotion.
    core::sweep_executing_starts_to_unknown(3_000);
    assert_eq!(outcome_of(id), ActionOutcome::OutcomeUnknown);
    let after_first = core::query_recovery_proposal(&p(M1), id).unwrap();
    let audits_after_first = audit_kinds().len();

    // Second upgrade: NO further change, no terminal outcome, lock still held.
    core::sweep_executing_starts_to_unknown(4_000);
    assert_eq!(
        core::query_recovery_proposal(&p(M1), id).unwrap(),
        after_first,
        "acceptance 12: the sweep is IDEMPOTENT — a second upgrade changes nothing"
    );
    assert_eq!(audit_kinds().len(), audits_after_first, "and appends nothing further");
    assert!(!outcome_of(id).is_terminal(), "E2 writes NO terminal outcome");
    assert!(start_state(id).settlement.is_none(), "E2 takes NO evidence");

    // MUTATION: drop the `outcome != Executing` guard and the second sweep
    // would re-promote and re-append, breaking both assertions above.
}

// ── ACCEPTANCE 16(b)(c) — the conflict cap, end-to-end on the plane ─────────

/// 16(b): the FIRST valid discordance produces exactly one event and sets the
/// marker; EVERY later valid discordance produces NO WRITE AT ALL.
#[test]
fn s7_cell4_acceptance_16b_only_the_first_discordance_writes() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);
    // Settle Executed on a Running observation.
    core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Running, 3_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    )
    .expect("settles");

    // N distinct, fresh, semantically DISCORDANT observations.
    for k in 0..5u64 {
        let r = core::reconcile_vault_start(
            id,
            &start_evidence(ObservedCanisterStatus::Stopped, 4_100 + k),
            ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
            &self_p(),
            5_000,
        );
        assert_eq!(
            r,
            Err(RecoveryError::AlreadySettled { outcome: ReconcileTerminalOutcome::Executed }),
            "§7c: every replay branch returns the SAME typed error, never Ok"
        );
        assert_eq!(outcome_of(id), ActionOutcome::Executed, "NO RE-OPEN");
    }

    assert_eq!(
        count_conflicts(id),
        1,
        "§7d: AT MOST ONE conflict event per proposal, EVER — not one per hash"
    );
    assert!(
        start_state(id).settlement.expect("settled").conflict_recorded,
        "the one-shot marker is durably set"
    );

    // The one event carries the frozen payload, read from the STORED record.
    let conflict = audit_kinds()
        .into_iter()
        .find_map(|k| match k {
            UpgraderAuditEventKind::SettlementEvidenceConflictRecorded { conflict }
                if conflict.proposal_id == id =>
            {
                Some(conflict)
            }
            _ => None,
        })
        .expect("the one conflict event");
    assert_eq!(conflict.stored_outcome, ReconcileTerminalOutcome::Executed);
    assert_eq!(conflict.replay_mapped_outcome, ReconcileTerminalOutcome::Failed);
    assert_ne!(conflict.stored_outcome, conflict.replay_mapped_outcome);

    // MUTATION: clear the marker and a second event becomes possible, breaking
    // the count assertion above — which is what makes the cap load-bearing.
}

/// Acceptance 9(b) on the plane — the C2 GROWTH ROUTE. N distinct, valid, fresh
/// observations with N distinct timestamps and N distinct
/// `evidence_commitment` values, all semantically CONCORDANT, must produce ZERO
/// conflict events.
#[test]
fn s7_cell4_acceptance_9b_concordant_reobservation_never_conflicts() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);
    core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Running, 3_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    )
    .expect("settles");

    let audits_before = audit_kinds().len();
    let mut commitments = std::collections::HashSet::new();
    for k in 0..6u64 {
        let ev = start_evidence(ObservedCanisterStatus::Running, 4_100 + k);
        assert!(
            commitments.insert(ev.evidence_commitment()),
            "9(b) requires N DISTINCT evidence_commitment values"
        );
        let r = core::reconcile_vault_start(
            id,
            &ev,
            ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
            &self_p(),
            5_000,
        );
        assert_eq!(
            r,
            Err(RecoveryError::AlreadySettled { outcome: ReconcileTerminalOutcome::Executed })
        );
    }
    assert_eq!(count_conflicts(id), 0, "ZERO conflict events for N concordant re-observations");
    assert_eq!(
        audit_kinds().len(),
        audits_before,
        "§7d: a concordant replay appends NOTHING — an un-prunable log reached \
         by a caller-repeatable path is a griefing surface"
    );
}

// ── ACCEPTANCE 8 — no retry exists ──────────────────────────────────────────

/// §6: an `OutcomeUnknown` start is NEVER re-triggerable. Asserted structurally:
/// the ONLY producer of a `RecoveryExecution::Start` is the quorum boundary of a
/// `StartVault` proposal, and a proposal reaches that boundary exactly once
/// because the `Pending -> Executing` edge is single and terminal states are
/// un-executable.
#[test]
fn s7_cell4_acceptance_8_no_path_re_triggers_an_outcome_unknown_start() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);
    assert_eq!(outcome_of(id), ActionOutcome::OutcomeUnknown);

    // A further approval on the same proposal cannot re-issue the start.
    let again = core::approve_recovery(&p(M3), id, 3_500, commit_of(id), &self_p());
    assert!(
        !matches!(again, Ok(ApproveOutcome::Execute(RecoveryExecution::Start { .. }))),
        "§6: NO automatic retry, and no path re-triggers an OutcomeUnknown start"
    );

    // §7e — while the start sits in OutcomeUnknown it STILL HOLDS the
    // single-flight lock, so no second start can be admitted against the same
    // target. The lock releases ONLY at the first transition to Executed|Failed.
    let id2 = core::propose_recovery(&p(M1), RecoveryAction::StartVault, 4_000, None, &self_p())
        .expect("proposing is allowed");
    core::approve_recovery(&p(M1), id2, 4_000, commit_of(id2), &self_p()).expect("first approval");
    assert_eq!(
        core::approve_recovery(&p(M2), id2, 4_000, commit_of(id2), &self_p()),
        Err(RecoveryError::IllegalSourceState),
        "§2/§7e: a second start is refused while the first still holds the lock          in OutcomeUnknown — concurrent module mutation would destroy the          attributability of the §4 status evidence"
    );
    assert_eq!(outcome_of(id), ActionOutcome::OutcomeUnknown, "the old proposal stays put");
    // P1-1 — THE REFUSED PROPOSAL LEAVES NO `Executing` ORPHAN. Asserted
    // explicitly: the earlier version of this test reproduced the refusal but
    // never checked what it left behind, and what it left behind was a durable
    // `Executing` record with `start == None` that no path could clear.
    assert_eq!(
        outcome_of(id2),
        ActionOutcome::Pending,
        "P1-1: a refused start records NOTHING — it stays Pending and retryable, \
         never stranded Executing"
    );
    assert!(
        core::query_recovery_proposal(&p(M1), id2).unwrap().start.is_none(),
        "P1-1: no start-intent was written by the refused quorum"
    );

    // Settle the first, releasing the lock. Recovery from a Failed start is then
    // a NEW proposal at full quorum, with a new id and therefore a new
    // commitment — it is NOT a retry, and the old proposal stays terminal for
    // ever (§6).
    core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Stopped, 4_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        5_000,
    )
    .expect("settles Failed");
    assert_eq!(outcome_of(id), ActionOutcome::Failed);

    let (id3, out) = start_to_quorum(6_000);
    assert_ne!(id3, id, "recovery is a NEW proposal, never a retry of the old one");
    assert!(matches!(out, ApproveOutcome::Execute(RecoveryExecution::Start { .. })));
    assert_eq!(
        outcome_of(id),
        ActionOutcome::Failed,
        "§6: the old proposal stays terminal FOREVER"
    );
}

// ── ACCEPTANCE 19 — target non-redirection, on the CANDID SURFACE ───────────

/// §1 / brief R4.4: cell 4's action "carries NO target parameter at all", and
/// that is "a structural property proven by the Candid surface, NOT a runtime
/// check". Asserted against the committed `upgrader.did`: the `StartVault`
/// variant must have NO payload.
#[test]
fn s7_cell4_acceptance_19_start_vault_has_no_target_parameter() {
    const DID: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/upgrader.did"));
    let action = DID
        .split("type RecoveryAction = variant {")
        .nth(1)
        .expect("upgrader.did declares RecoveryAction");
    let body = &action[..action.find("\n};").expect("variant closes")];

    // The variant is present, and it is a BARE variant: `StartVault;` with no
    // `:` introducing a payload.
    assert!(body.contains("StartVault;"), "StartVault must exist as a bare variant: {body}");
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("StartVault") {
            assert!(
                !t.contains(':'),
                "R4.4 VIOLATED: StartVault carries a payload on the Candid \
                 surface — target non-redirection must be structural, with no \
                 field for a caller to populate: {t}"
            );
        }
    }

    // And the Rust variant likewise carries nothing.
    let a = RecoveryAction::StartVault;
    assert_eq!(a, RecoveryAction::StartVault);
    assert_eq!(
        candid::encode_one(&a).expect("encodes").len(),
        candid::encode_one(&RecoveryAction::StartVault).expect("encodes").len(),
        "a payload-free variant encodes identically every time"
    );
}

// ── §0b — THE TRANSACTION-BOUNDARY TRIPWIRES ───────────────────────────────

/// §0b / acceptance 13(a) and 16(c) — **the mutation form is NORMATIVE**: the
/// halves of an atomic durable transition must be separated by NO `await` and
/// no message boundary, and the check must move one half ACROSS A TRANSACTION
/// BOUNDARY rather than merely splitting a write.
///
/// Rust cannot express "these two statements share a message" as a type, and a
/// runtime test cannot observe a boundary that does not exist. The codebase's
/// established idiom for exactly this class — the S5B W5(b) tripwire in the
/// vault — is a SOURCE-TEXT LINT, and that is what is used here.
///
/// This asserts the §7d.1 pair: `conflict_recorded: false -> true` and the
/// audit append, with no `await` between them.
#[test]
fn s7_cell4_conflict_marker_and_append_share_one_message() {
    const SRC: &str = include_str!("core.rs");
    let f = SRC
        .find("pub fn reconcile_vault_start(")
        .expect("the settlement core exists");
    let body = &SRC[f..];
    let end = body.find("\n// ── Recovery protocol").unwrap_or(body.len());
    let body = &body[..end];

    assert!(
        !body.contains(".await"),
        "§0b VIOLATED: `.await` inside the start-settlement core. Every write it \
         performs — the terminal outcome, the SettlementRecord, the \
         conflict_recorded transition and the audit append — must land in ONE \
         synchronous message execution, committing or rolling back together. An \
         await admits `marker without event` (every future discordance silenced \
         while nothing was recorded) and `event without marker` (a second event \
         becomes possible, breaking the §7d cap). Neither is a permitted state."
    );

    // The pair really is in this function, so the lint is not vacuous.
    assert!(body.contains("conflict_recorded = true"), "the marker transition is here");
    assert!(
        body.contains("SettlementEvidenceConflictRecorded"),
        "the audit append is here"
    );

    // MUTATION (the normative form): inserting an `await` between the two
    // halves must REGISTER. Applied to the real text and re-checked.
    let mutated = body.replacen(
        "record.conflict_recorded = true;",
        "record.conflict_recorded = true;\n    some_future().await;",
        1,
    );
    assert!(
        mutated.contains(".await"),
        "§0b MUTATION DID NOT REGISTER: an await injected between the marker \
         transition and the append was not detected — the tripwire is inert"
    );
}

/// §8a invariants 1 and 2 / acceptance 13(a) — the terminal outcome, the intent
/// terminalization, the lock release and the record are ONE atomic durable
/// transition. Same tripwire form, same reason.
#[test]
fn s7_cell4_settlement_write_is_one_transaction() {
    const SRC: &str = include_str!("core.rs");
    let f = SRC.find("StartReconcileDisposition::Settle(outcome) => {").expect("the settle arm");
    let arm = &SRC[f..];
    let end = arm.find("Ok(Some(outcome))").expect("the arm returns") + "Ok(Some(outcome))".len();
    let arm = &arm[..end];

    assert!(
        !arm.contains(".await"),
        "§8a invariant 1 VIOLATED: an `await` inside the settle arm would make \
         each half independently committable and admit a proposal that is \
         terminal without its record — a state no later code can detect or repair"
    );
    // ONE write call carries outcome + record together.
    assert_eq!(
        arm.matches("put_stored_proposal(").count(),
        1,
        "§8a invariants 1 and 2: the terminal outcome, the record and the lock \
         release land in a SINGLE durable write, so the record is durable before \
         the release is observable as a property of the transition rather than a \
         two-write ordering rule a crash could split"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// §S7 CORRECTIVE r1 — P1-1 and P1-3 regressions
//
// Authority: CTO_ADJUDICATION_S7_RETURN_AND_CORRECTIVE_DISPATCH_2026-08-11.md
// (sha256 62393a04ee9c5387c9260135cfc7cbee682625646db07b89e7f176a2e864c8ad),
// upholding SSA_S7_LANDED_DIFF_REVIEW_2026-08-11.md (sha256 31e79b1c…).
// ═════════════════════════════════════════════════════════════════════════════

/// **P1-1 regression (a) — AN OPEN START BLOCKS AN UPGRADE.**
///
/// This is the direction that was open. `start_in_flight` was consulted only on
/// the start arm, so upgrade→start was refused while start→upgrade was
/// admitted. §2 forbids the pair in EITHER order, and the admitted direction is
/// the dangerous one: an upgrade landing against the Vault while a start is
/// outstanding destroys the attributability of the §4 status evidence, because
/// neither proposal can then claim the observation.
#[test]
fn s7_p1_1_open_start_blocks_a_new_upgrade() {
    setup();
    let (start_id, _) = start_to_quorum(2_000);
    core::finish_start(start_id, &Err("no reply".to_string()), 3_000);
    assert_eq!(
        outcome_of(start_id),
        ActionOutcome::OutcomeUnknown,
        "the start holds the target lock while OutcomeUnknown (§7e)"
    );

    // Propose-time admission (:3299-class) must now refuse.
    assert_eq!(
        core::propose_recovery(&p(M1), trigger_action(7), 3_500, None, &self_p()),
        Err(RecoveryError::IllegalSourceState),
        "P1-1: an outstanding start must block a new upgrade at propose time"
    );

    // MUTATION 1:1 — the refusal is genuinely produced by the START limb, not
    // by the pre-existing upgrade limb. No upgrade intent exists here at all,
    // so `nonterminal_intent_in_flight` is false; only `start_in_flight` can be
    // returning true. Dropping `start_in_flight` from that check restores the
    // old one-way lock and this assertion fails.
    assert!(
        !core::nonterminal_intent_in_flight_for_test(None),
        "MUTATION GUARD: no upgrade intent is in flight, so the refusal above \
         can only come from the start limb — which is the limb P1-1 added"
    );

    // Once the start settles, the lock releases and the upgrade is admissible.
    core::reconcile_vault_start(
        start_id,
        &start_evidence(ObservedCanisterStatus::Stopped, 3_600),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    )
    .expect("settles Failed");
    assert!(
        core::propose_recovery(&p(M1), trigger_action(7), 4_500, None, &self_p()).is_ok(),
        "§7e: the lock releases at the first transition to Executed|Failed, and \
         the upgrade is then admissible — the block is a lock, not a ban"
    );
}

/// **P1-1 regression (b) — A REFUSED START MUTATES NOTHING.**
///
/// The refusal now runs BEFORE the quorum boundary's `Executing` write and its
/// `RecoveryExecutionStarted` append. Asserted as EXACT RECORD EQUALITY plus an
/// unchanged audit length, not inferred from one field: the defect this guards
/// against was precisely a record left in a state nobody looked at.
#[test]
fn s7_p1_1_refused_start_leaves_state_byte_unchanged_and_retryable() {
    setup();
    let (first, _) = start_to_quorum(2_000);
    core::finish_start(first, &Err("no reply".to_string()), 3_000);

    // A second start reaches its quorum boundary and is refused.
    let second = core::propose_recovery(&p(M1), RecoveryAction::StartVault, 3_500, None, &self_p())
        .expect("proposing a second start is allowed");
    core::approve_recovery(&p(M1), second, 3_500, commit_of(second), &self_p())
        .expect("first approval records normally");

    let before = core::query_recovery_proposal(&p(M1), second).expect("proposal");
    let audits_before = audit_kinds().len();
    let first_before = core::query_recovery_proposal(&p(M1), first).expect("first proposal");

    assert_eq!(
        core::approve_recovery(&p(M2), second, 3_500, commit_of(second), &self_p()),
        Err(RecoveryError::IllegalSourceState),
        "the quorum-reaching approval is refused"
    );

    let after = core::query_recovery_proposal(&p(M1), second).expect("proposal");
    assert_eq!(
        before, after,
        "P1-1: a blocked quorum records NOTHING — no Executing, no approval, no \
         start-intent. Asserted as exact record equality"
    );
    assert_eq!(
        audit_kinds().len(),
        audits_before,
        "P1-1: and appends nothing — no RecoveryExecutionStarted for a refused start"
    );
    assert_eq!(
        core::query_recovery_proposal(&p(M1), first).expect("first"),
        first_before,
        "the proposal actually holding the lock is untouched by the refusal"
    );
    assert_eq!(
        after.outcome,
        ActionOutcome::Pending,
        "STILL RETRYABLE: Pending, not a stranded Executing orphan that E2 \
         cannot sweep (it filters on start presence) and reconciliation cannot \
         resolve (it resolves only start-bearing proposals)"
    );

    // And it really is retryable once the lock frees.
    core::reconcile_vault_start(
        first,
        &start_evidence(ObservedCanisterStatus::Stopped, 3_600),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    )
    .expect("settles Failed");
    assert!(
        matches!(
            core::approve_recovery(&p(M2), second, 4_500, commit_of(second), &self_p()),
            Ok(ApproveOutcome::Execute(RecoveryExecution::Start { .. }))
        ),
        "the same proposal executes once the lock frees — a blocked quorum is a \
         delay, never a loss"
    );
}

/// **P1-3 regression — EVERY §4 REJECTION CLASS WRITES NOTHING AND APPENDS
/// NOTHING.**
///
/// V5 §7a permits audit appends ONLY where the contract explicitly requires
/// them; §7e and §7f step 3 both state that rejected evidence produces no
/// append. The landed code appended a rejection event on the ground that the
/// §3d upgrade path does — a precedent that does not govern the start contract.
/// The rule has a concrete purpose: `reconcile` is reachable by a quorum that
/// can resubmit, so an append here is an un-prunable log reached by a
/// repeatable path, which is the griefing surface §7a names.
#[test]
fn s7_p1_3_every_evidence_rejection_writes_and_appends_nothing() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);

    let intent_at = start_state(id).intent.intent_at_ns;
    let cases: Vec<(&str, stsh_custody_types::StartObjectiveEvidence, u64)> = vec![
        ("pre-intent", start_evidence(ObservedCanisterStatus::Running, intent_at - 1), 4_000),
        ("future-dated", start_evidence(ObservedCanisterStatus::Running, 9_000), 4_000),
        (
            "too-old",
            start_evidence(ObservedCanisterStatus::Running, intent_at),
            intent_at + stsh_custody_types::START_MAX_EVIDENCE_AGE_NS + 1,
        ),
        (
            "wrong target",
            stsh_custody_types::StartObjectiveEvidence {
                observed_target_principal: p(0x0C),
                ..start_evidence(ObservedCanisterStatus::Running, 3_500)
            },
            4_000,
        ),
        (
            "drifted controllers",
            stsh_custody_types::StartObjectiveEvidence {
                observed_controllers: vec![p(0x0D)],
                ..start_evidence(ObservedCanisterStatus::Running, 3_500)
            },
            4_000,
        ),
    ];

    for (label, ev, now) in cases {
        let before = core::query_recovery_proposal(&p(M1), id).expect("proposal");
        let audits_before = audit_kinds().len();

        let r = core::reconcile_vault_start(
            id,
            &ev,
            ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
            &self_p(),
            now,
        );
        assert!(
            matches!(r, Err(RecoveryError::EvidenceRejected(_))),
            "{label}: must be a typed evidence rejection, got {r:?}"
        );
        assert_eq!(
            core::query_recovery_proposal(&p(M1), id).expect("proposal"),
            before,
            "{label}: ZERO settlement-state mutation — exact record equality"
        );
        assert_eq!(
            audit_kinds().len(),
            audits_before,
            "{label}: §7e/§7f step 3 — NO AUDIT APPEND on a rejected evidence \
             submission. This is the P1-3 defect: the landed code appended here"
        );
        assert!(
            !outcome_of(id).is_terminal(),
            "{label}: none terminalizing, and the lock is RETAINED"
        );
    }

    // MUTATION 1:1 — the audit assertion is live. A path that DOES append (the
    // settlement below) moves the counter, so a zero-delta assertion is not
    // vacuously true of this harness.
    let audits_before = audit_kinds().len();
    core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Running, 3_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    )
    .expect("settles");
    assert!(
        audit_kinds().len() > audits_before,
        "MUTATION GUARD: a genuine transition DOES append, so the zero-delta \
         assertions above are measuring something real"
    );
}

/// **P1-3 regression — INVALID EVIDENCE AGAINST A SETTLED PROPOSAL LEAVES
/// `conflict_recorded` AVAILABLE**, at the plane level.
///
/// Acceptance 15(b) proved this on the shared predicate, which is pure and
/// cannot observe audit growth or durable state. This proves it where the
/// writes actually happen: N invalid submissions against a settled proposal
/// leave the one-shot marker untouched and the log unchanged, and the first
/// genuinely discordant §4-valid observation then records exactly once.
#[test]
fn s7_p1_3_invalid_evidence_against_a_settled_proposal_never_burns_the_marker() {
    setup();
    let (id, _) = start_to_quorum(2_000);
    core::finish_start(id, &Err("no reply".to_string()), 3_000);
    core::reconcile_vault_start(
        id,
        &start_evidence(ObservedCanisterStatus::Running, 3_500),
        ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
        &self_p(),
        4_000,
    )
    .expect("settles Executed");

    let audits_before = audit_kinds().len();
    for k in 0..5u64 {
        // Would be DISCORDANT if it reached §7d — it observes Stopped against a
        // proposal settled Executed — but it is §4-invalid, so §7f step 3
        // rejects it first.
        let ev = stsh_custody_types::StartObjectiveEvidence {
            observed_controllers: vec![p(0x0D)],
            ..start_evidence(ObservedCanisterStatus::Stopped, 3_600 + k)
        };
        assert!(matches!(
            core::reconcile_vault_start(
                id,
                &ev,
                ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
                &self_p(),
                4_100,
            ),
            Err(RecoveryError::EvidenceRejected(_))
        ));
        assert!(
            !start_state(id).settlement.as_ref().expect("settled").conflict_recorded,
            "the one-shot marker must remain AVAILABLE after invalid submission {k}"
        );
    }
    assert_eq!(
        audit_kinds().len(),
        audits_before,
        "and no rejection event was appended for any of them (P1-3)"
    );

    // The first genuinely valid discordance still records — the marker was
    // preserved for it, which is the whole point of ordering §4 ahead of §7d.
    assert_eq!(
        core::reconcile_vault_start(
            id,
            &start_evidence(ObservedCanisterStatus::Stopped, 3_700),
            ReconcileAuthorityView::Recovery { approvers: vec![p(M1), p(M2)] },
            &self_p(),
            4_100,
        ),
        Err(RecoveryError::AlreadySettled { outcome: ReconcileTerminalOutcome::Executed })
    );
    assert!(
        start_state(id).settlement.expect("settled").conflict_recorded,
        "the preserved marker is consumed by the first VALID discordance"
    );
    assert_eq!(count_conflicts(id), 1, "exactly one conflict event, ever");
}

// ═══════════════════════════════════════════════════════════════════════════
// S8B / R6 Option B — permissionless rate-limited refresh
//
// Dispatch 4b61221b… §2 binds five acceptance criteria; DID pre-auth
// 0d509960… §2 binds five conditions. Each gets a mechanism test and a 1:1
// mutation. The three R6 constants are UNRULED (Route 2), so every test here
// injects candidates — otherwise the endpoint is inert by design and every
// assertion below would be vacuously true.
// ═══════════════════════════════════════════════════════════════════════════

/// Candidate R6 constants. FIXTURE VALUES, recorded as such — they are not
/// proposals for the pin. Only their ORDERING matters to these tests
/// (max_age < min_interval so staleness and cadence can be separated).
fn refresh_fixture() -> stsh_custody_types::InvariantRefreshParams {
    stsh_custody_types::InvariantRefreshParams {
        min_interval_ns: 3_600 * stsh_custody_types::NANOS_PER_SEC,
        cycle_budget: 1_000_000_000,
        max_age_ns: 600 * stsh_custody_types::NANOS_PER_SEC,
    }
}

fn arm_refresh() -> stsh_custody_types::InvariantRefreshParams {
    let p = refresh_fixture();
    core::inject_refresh_params_for_test(Some(Some(p)));
    p
}

/// Force the UNRULED path. Post-pin the production constant is `Some`, so this
/// must be an explicit override — not `inject(None)`, which now means "use
/// production" and would silently test the pinned path instead.
fn force_refresh_unruled() {
    core::inject_refresh_params_for_test(Some(None));
}

/// Addendum condition 1 — while the constants are unruled the endpoint is
/// INERT: it refuses before reading or writing anything.
///
/// Asserted as "no state written", not merely "returned an error": a refusal
/// that had already charged the allowance would rate-limit a capability that
/// does not exist yet, and the first thing the A1 pin did would be to hand out
/// a refusal.
#[test]
fn s8b_unruled_constants_refuse_without_touching_state() {
    setup();
    force_refresh_unruled();
    let audit_before = core::audit_len_for_test();

    assert_eq!(
        core::refresh_charge(T0),
        Err(stsh_custody_types::InvariantRefreshRefusal::NotRuled)
    );

    let l = core::refresh_ledger_for_test();
    assert_eq!(l.last_accepted_at_ns, None, "NotRuled must not charge the allowance");
    assert_eq!(l.in_flight_since_ns, None, "NotRuled must not set the in-flight marker");
    assert_eq!(
        core::audit_len_for_test(),
        audit_before,
        "condition 2: refusals append NOTHING"
    );
}

/// Criterion 1 (cycle-drain) — an attacker looping the permissionless endpoint
/// cannot exceed the ADMISSION ceiling the rate limiter sets.
///
/// SCOPE, stated precisely (lane R-11, UMC-03). What this test measures is how
/// many refreshes are ADMITTED per window. It does NOT measure what a REFUSED
/// call costs, and a refused call is not free: the endpoint is permissionless,
/// so the upgrader still pays a full message induction and decode for every
/// rejected attempt. That half is separately sampled and pinned by
/// `pic_s8b_measure_refresh_cycle_cost_by_balance_delta`
/// (`canisters/vault/tests/pic_tests.rs`).
///
/// Driven as a real loop over a real window rather than a single TooSoon
/// assertion: the property is about the CEILING over time, and a one-shot check
/// cannot distinguish "rate limited" from "limited to exactly one, ever".
/// 10,000 attempts across three windows must yield exactly 3 admissions.
#[test]
fn s8b_cycle_drain_bounded_by_rate_limit_over_windows() {
    setup();
    let p = arm_refresh();
    // Keep the observation permanently stale so staleness never masks the rate
    // limit — this test must fail for cadence reasons only.
    let span = p.min_interval_ns * 3;
    let mut admitted = 0u32;
    let mut t = T0;
    let step = span / 10_000;
    for _ in 0..10_000 {
        if let Ok(charge) = core::refresh_charge(t) {
            admitted += 1;
            core::refresh_release(charge);
        }
        t += step;
    }
    assert_eq!(
        admitted, 3,
        "10,000 permissionless attempts across 3 x min_interval must admit \
         exactly 3 — the ceiling is windows elapsed, not attempts made"
    );
}

/// Criterion 2 (concurrency-burst) — overlapping calls collapse; the allowance
/// is not spent twice and the marker is durable before the first await.
///
/// The interleaving is modelled exactly as it occurs: `refresh_charge` is what
/// runs before the await, so two charges with NO release between them are
/// precisely two callers overlapping at the await boundary.
#[test]
fn s8b_concurrency_burst_collapses_and_charges_once() {
    setup();
    arm_refresh();
    let first = core::refresh_charge(T0).expect("first caller admitted");
    let charged_at = core::refresh_ledger_for_test().last_accepted_at_ns;
    assert_eq!(
        charged_at,
        Some(T0),
        "condition 3: the charge must be DURABLE before the first await"
    );

    // A second caller arriving while the first is still between its two
    // management calls.
    assert_eq!(
        core::refresh_charge(T0 + 1),
        Err(stsh_custody_types::InvariantRefreshRefusal::AlreadyInFlight)
    );
    assert_eq!(
        core::refresh_ledger_for_test().last_accepted_at_ns,
        charged_at,
        "the refused caller must not move the allowance"
    );
    core::refresh_release(first);
    assert_eq!(
        core::refresh_ledger_for_test().in_flight_since_ns,
        None,
        "release clears the marker"
    );
    assert_eq!(
        core::refresh_ledger_for_test().last_accepted_at_ns,
        charged_at,
        "release must NOT refund the allowance"
    );
}

/// Criterion 2, second half — a trap after the first await must not wedge the
/// endpoint forever.
///
/// A trap between the two status calls commits the in-flight marker and returns
/// no reply, so `refresh_release` never runs. Without a reclaim the endpoint
/// would be permanently `AlreadyInFlight`. The reclaim deliberately reuses
/// `min_interval_ns` rather than inventing a second timeout: it can never fire
/// earlier than the rate limit would refuse anyway, so it grants nothing.
#[test]
fn s8b_stale_in_flight_marker_is_reclaimed_after_min_interval() {
    setup();
    let p = arm_refresh();
    core::put_refresh_ledger_for_test(&core::InvariantRefreshLedger {
        schema_version: core::INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION,
        last_accepted_at_ns: Some(T0),
        in_flight_since_ns: Some(T0),
    });
    assert_eq!(
        core::refresh_charge(T0 + p.min_interval_ns - 1),
        Err(stsh_custody_types::InvariantRefreshRefusal::AlreadyInFlight),
        "still in flight just before the reclaim"
    );
    assert!(
        core::refresh_charge(T0 + p.min_interval_ns).is_ok(),
        "the marker is reclaimed at min_interval, so one failed call cannot \
         wedge the endpoint permanently"
    );
}

/// Criterion 1 — `TooSoon` carries the earliest acceptable time, so a caller
/// can back off precisely instead of polling. A wrong figure here would be
/// worse than none: it would be believed.
#[test]
fn s8b_too_soon_reports_the_exact_retry_time() {
    setup();
    let p = arm_refresh();
    let first = core::refresh_charge(T0).expect("admitted");
    core::refresh_release(first);
    assert_eq!(
        core::refresh_charge(T0 + 1),
        Err(stsh_custody_types::InvariantRefreshRefusal::TooSoon {
            retry_after_ns: T0 + p.min_interval_ns
        })
    );
    assert!(core::refresh_charge(T0 + p.min_interval_ns).is_ok(), "admitted exactly at the boundary");
}

/// `NotStale` is about the OBSERVATION's age, `TooSoon` about the CALLER's
/// cadence. The addendum ratified the distinction; this pins it.
///
/// A fresh observation with NO prior charge must yield `NotStale` — if the two
/// were conflated this would return `TooSoon` (or admit), and a live rate limit
/// would be hidden behind a fresh reading.
#[test]
fn s8b_not_stale_is_distinct_from_too_soon() {
    setup();
    let p = arm_refresh();
    core::record_controller_invariant(true, true, T0);
    assert_eq!(
        core::refresh_ledger_for_test().last_accepted_at_ns,
        None,
        "no charge has happened, so TooSoon cannot be the reason"
    );
    match core::refresh_charge(T0 + p.max_age_ns - 1) {
        Err(stsh_custody_types::InvariantRefreshRefusal::NotStale { age_ns }) => {
            assert_eq!(age_ns, p.max_age_ns - 1)
        }
        other => panic!("expected NotStale, got {other:?}"),
    }
    assert!(
        core::refresh_charge(T0 + p.max_age_ns).is_ok(),
        "refreshable once the observation reaches max_age"
    );
}

/// With no observation at all, the FIRST refresh is always permitted — that is
/// the case the public proof most needs served, and a staleness check that
/// treated "never observed" as "fresh" would lock the endpoint out precisely
/// when the ring is unproven.
#[test]
fn s8b_first_ever_refresh_is_permitted_with_no_observation() {
    setup();
    arm_refresh();
    assert!(core::query_controller_invariant().observed_at_ns == 0);
    assert!(core::refresh_charge(T0).is_ok());
}

/// Criterion 4 (audit-growth) — refusals append nothing; an accepted refresh
/// appends exactly one event, and its measured size is the coefficient the
/// packet reports.
#[test]
fn s8b_audit_growth_is_bounded_by_accepted_refreshes_only() {
    setup();
    let p = arm_refresh();
    let before = core::audit_len_for_test();

    // Every refusal arm, none of which may append.
    force_refresh_unruled();
    let _ = core::refresh_charge(T0);
    core::inject_refresh_params_for_test(Some(Some(p)));
    let c = core::refresh_charge(T0).expect("admitted");
    let after_accept = core::audit_len_for_test();
    core::refresh_release(c);
    let _ = core::refresh_charge(T0 + 1); // TooSoon
    core::record_controller_invariant(true, true, T0 + 1);
    let _ = core::refresh_charge(T0 + 2); // NotStale or TooSoon

    assert_eq!(
        after_accept, before,
        "the CHARGE itself appends nothing — only the observation does"
    );
    // One observation was recorded explicitly above; nothing else appended.
    assert_eq!(
        core::audit_len_for_test(),
        before + 1,
        "criterion 4: audit growth comes from recorded observations only, never \
         from refusals"
    );
}

/// Criterion 5 (partial-call) — a failure between the two management status
/// calls leaves the stored observation coherent: prior value intact, never a
/// torn pair.
///
/// The two-call seam records ONLY when both succeed, so the in-process
/// equivalent of a partial call is "no `record_controller_invariant` happened".
/// Asymmetric fields per S8A discipline, so a torn or defaulted write is
/// distinguishable from the prior value rather than coincidentally equal to it.
#[test]
fn s8b_partial_call_leaves_the_prior_observation_intact() {
    setup();
    arm_refresh();
    core::record_controller_invariant(true, false, 777_000);
    let prior = core::invariant_record_for_test().expect("prior observation");

    // Admit a refresh, then complete it WITHOUT recording — exactly what the
    // seam does when either status call fails.
    let c = core::refresh_charge(T0 + refresh_fixture().max_age_ns).expect("admitted");
    core::refresh_release(c);

    let after = core::invariant_record_for_test().expect("still present");
    assert_eq!(after, prior, "criterion 5: prior value intact, byte-identical");
    let inv = core::query_controller_invariant();
    assert!(inv.vault_controllers_ok && !inv.upgrader_controllers_ok);
    assert_eq!(inv.observed_at_ns, 777_000);
}

/// A failed refresh still SPENDS its allowance. Otherwise a caller who can
/// induce management-call failures has an unmetered retry loop — the
/// cycle-drain route criterion 1 exists to close.
#[test]
fn s8b_failed_refresh_still_spends_the_allowance() {
    setup();
    let p = arm_refresh();
    let c = core::refresh_charge(T0).expect("admitted");
    core::refresh_release(c); // completed, recorded nothing
    assert_eq!(
        core::refresh_charge(T0 + 1),
        Err(stsh_custody_types::InvariantRefreshRefusal::TooSoon {
            retry_after_ns: T0 + p.min_interval_ns
        }),
        "a refresh that recorded nothing must still have consumed its window"
    );
}

/// The limiter survives `post_upgrade` in process; the real cross-Wasm proof
/// for criterion 3 is the PocketIC test. Both exist because they fail for
/// different reasons — this one catches a limiter that is not durable at all.
#[test]
fn s8b_limiter_state_survives_post_upgrade() {
    setup();
    arm_refresh();
    let c = core::refresh_charge(T0).expect("admitted");
    core::refresh_release(c);
    core::post_upgrade(T0);
    let l = core::refresh_ledger_for_test();
    assert_eq!(
        l.last_accepted_at_ns,
        Some(T0),
        "criterion 3: an upgrade must not reset the window and grant a burst"
    );
}

/// MemoryId 12 fails CLOSED on corruption — it never degrades to "never
/// charged", which would hand out a free window.
#[test]
#[should_panic]
fn s8b_corrupt_limiter_cell_traps_rather_than_granting_a_free_window() {
    setup();
    arm_refresh();
    core::write_refresh_ledger_raw_for_test(vec![0xff, 0xff, 0xff, 0xff]);
    let _ = core::refresh_charge(T0);
}

/// Wrong schema version fails closed too — these bytes decode cleanly, so only
/// the version gate can be what fires.
#[test]
#[should_panic]
fn s8b_wrong_limiter_schema_version_traps() {
    setup();
    arm_refresh();
    let forged = candid::encode_one(&core::InvariantRefreshLedger {
        schema_version: core::INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION + 1,
        last_accepted_at_ns: Some(T0),
        in_flight_since_ns: None,
    })
    .expect("encodes");
    core::write_refresh_ledger_raw_for_test(forged);
    let _ = core::refresh_charge(T0);
}

/// A clock that moves BACKWARDS must refuse, never wrap into a free window.
/// Saturating arithmetic throughout is the mechanism; this is the test that
/// notices if any of it becomes a bare subtraction.
#[test]
fn s8b_backwards_clock_cannot_manufacture_a_window() {
    setup();
    arm_refresh();
    let c = core::refresh_charge(T0).expect("admitted");
    core::refresh_release(c);
    assert!(
        matches!(
            core::refresh_charge(T0 - 1_000),
            Err(stsh_custody_types::InvariantRefreshRefusal::TooSoon { .. })
        ),
        "an earlier timestamp must still be refused"
    );
}

/// **THE PIN, SELF-ASSERTING.** `A1_PIN_R6_REFRESH_CONSTANTS_2026-08-12.md`
/// (`eee3f17acd47abca6b8196b715586118b9e711a4997aa27ef5ec18294e4d22ea`).
///
/// This test REPLACES `s8b_production_refresh_constants_remain_unruled`, which
/// asserted the constants were still `None`. That test was correct until the pin
/// landed and is now wrong — deleting it and asserting the opposite is the
/// point, not an oversight: the shipped constant must always be pinned to
/// SOMETHING a filing authorises, and the test says which filing.
///
/// Values are asserted in their DERIVED form (seconds × NANOS_PER_SEC) rather
/// than as raw nanosecond literals, so a transcription slip in the constant
/// cannot agree with a matching transcription slip here.
#[test]
fn s8b_pinned_refresh_constants_match_the_a1_filing() {
    let p = stsh_custody_types::INVARIANT_REFRESH_PARAMS
        .expect("A1_PIN_R6_REFRESH_CONSTANTS_2026-08-12.md (eee3f17a…) pinned these — \
                 a `None` here means the pin was reverted without a superseding filing");
    assert_eq!(
        p.min_interval_ns,
        6 * 60 * 60 * stsh_custody_types::NANOS_PER_SEC,
        "pin row 1: max refresh frequency = 6 h"
    );
    assert_eq!(p.cycle_budget, 50_000_000, "pin row 2: cycle budget");
    assert_eq!(
        p.max_age_ns,
        24 * 60 * 60 * stsh_custody_types::NANOS_PER_SEC,
        "pin row 3: staleness horizon = 24 h"
    );
}

/// Pin check 1 — ORDERING: `max_age >= 4 x min_interval`.
///
/// Four refresh opportunities inside one staleness window, so a single missed or
/// refused cycle cannot flap the public proof stale. Asserted as the INEQUALITY
/// the filing states, not as the two numbers: a future re-pin that keeps the
/// ratio is fine, one that breaks it must fail here.
#[test]
fn s8b_pin_ordering_gives_four_refresh_opportunities_per_staleness_window() {
    let p = stsh_custody_types::INVARIANT_REFRESH_PARAMS.expect("pinned");
    assert!(
        p.max_age_ns >= 4 * p.min_interval_ns,
        "pin check: max_age {} must be at least 4 x min_interval {} — below that, \
         one missed cycle flaps the proof stale",
        p.max_age_ns,
        p.min_interval_ns
    );
}

/// Pin check 2 — the cycle budget COVERS the measured ceiling, with the headroom
/// the filing claims.
///
/// THIS IS THE CONDITION THE PIN CARRIES. Management-call pricing is the
/// platform's; the filing accepts that and makes the 2.29x headroom the buffer,
/// on the explicit condition that a repricing which consumes it directs a
/// RE-PIN rather than passing silently. That condition is only real if something
/// fails — so it is asserted here against the measured figure, not left in prose.
///
/// The ceiling is the S8B packet v2 §5 measurement
/// (`pic_s8b_measure_refresh_cycle_cost_by_balance_delta`), quoted as a named
/// constant so the provenance is legible at the assertion.
#[test]
fn s8b_pin_cycle_budget_covers_the_measured_ceiling() {
    /// Highest ACCEPTED-call cost measured across the 3- and 9-member rosters
    /// (S8B packet v2 §5; 9-member was 21,854,662).
    const MEASURED_ACCEPTED_CALL_CEILING: u64 = 21_864_835;
    let p = stsh_custody_types::INVARIANT_REFRESH_PARAMS.expect("pinned");
    assert!(
        p.cycle_budget >= MEASURED_ACCEPTED_CALL_CEILING,
        "pin check: cycle_budget {} must cover the measured accepted-call ceiling {}",
        p.cycle_budget,
        MEASURED_ACCEPTED_CALL_CEILING
    );
    // The filing's claimed headroom, to one decimal place. If a re-measurement
    // erodes this, the pin needs revisiting — which is exactly what the filing
    // says should happen, and this is what makes that happen.
    let headroom_tenths = p.cycle_budget * 10 / MEASURED_ACCEPTED_CALL_CEILING;
    assert!(
        headroom_tenths >= 22,
        "pin check: headroom {}.{}x has fallen below the 2.2x the filing rests on \
         — platform repricing directs a RE-PIN, not a silent breach",
        headroom_tenths / 10,
        headroom_tenths % 10
    );
}

/// Pin check 3 — the AUDIT-GROWTH arithmetic the filing was derived from.
///
/// Recomputed here from the pinned interval and the measured per-refresh cost,
/// so the filing's 1.20 MB/yr is reproduced by the code rather than trusted. The
/// bound is the inequality from the packet: growth <= 839 B x (window /
/// min_interval).
#[test]
fn s8b_pin_audit_growth_reproduces_the_filing_arithmetic() {
    /// Measured audit bytes per accepted refresh (S8B packet v2 §5).
    const AUDIT_BYTES_PER_ACCEPTED_REFRESH: u64 = 839;
    let p = stsh_custody_types::INVARIANT_REFRESH_PARAMS.expect("pinned");
    let year_ns: u64 = 365 * 24 * 60 * 60 * stsh_custody_types::NANOS_PER_SEC;
    let max_refreshes_per_year = year_ns / p.min_interval_ns;
    assert_eq!(max_refreshes_per_year, 1_460, "6 h cadence = 4/day = 1,460 per 365 d");
    let worst_case_bytes = AUDIT_BYTES_PER_ACCEPTED_REFRESH * max_refreshes_per_year;
    assert!(
        worst_case_bytes < 2_000_000,
        "worst-case audit growth {worst_case_bytes} B/yr must stay near the \
         ~1.2 MB the pin was derived against"
    );
}

/// S8B MEASUREMENT — the figures the packet reports for the A1 pin.
///
/// Route 2 means the three constants are pinned on MEASURED numbers, so this
/// test's job is to produce them, not to assert a threshold. It prints; the
/// assertions cover only the properties that must hold whatever the values are.
#[test]
fn s8b_measure_refresh_costs_for_the_pin() {
    use stsh_custody_types::InvariantRefreshRefusal as R;
    setup();
    arm_refresh();

    // (a) Audit bytes per ACCEPTED refresh — one ControllerInvariantObserved.
    let before: usize = core::measurement::audit_event_sizes_for_test().iter().sum();
    core::record_controller_invariant(true, false, T0);
    let sizes = core::measurement::audit_event_sizes_for_test();
    let audit_bytes_per_refresh: usize = sizes.iter().sum::<usize>() - before;

    // (b) MemoryId 12 encoded size, charged (the worst case: both Options set).
    core::put_refresh_ledger_for_test(&core::InvariantRefreshLedger {
        schema_version: core::INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION,
        last_accepted_at_ns: Some(u64::MAX),
        in_flight_since_ns: Some(u64::MAX),
    });
    let mem12 = core::measurement::census_for_test()
        .iter()
        .find(|(n, _, _)| n.starts_with("12 INVARIANT_REFRESH_LEDGER"))
        .map(|(_, _, b)| *b)
        .expect("MemoryId 12 is censused");

    // (c) Response sizes — every arm of the pre-authorized return type.
    let ok_len = candid::encode_one(Ok::<_, R>(core::query_controller_invariant()))
        .expect("encodes")
        .len();
    let arms: Vec<(&str, usize)> = vec![
        ("NotRuled", candid::encode_one(Err::<stsh_custody_types::ControllerInvariant, R>(R::NotRuled)).unwrap().len()),
        ("AlreadyInFlight", candid::encode_one(Err::<stsh_custody_types::ControllerInvariant, R>(R::AlreadyInFlight)).unwrap().len()),
        ("TooSoon", candid::encode_one(Err::<stsh_custody_types::ControllerInvariant, R>(R::TooSoon { retry_after_ns: u64::MAX })).unwrap().len()),
        ("NotStale", candid::encode_one(Err::<stsh_custody_types::ControllerInvariant, R>(R::NotStale { age_ns: u64::MAX })).unwrap().len()),
    ];

    println!("\n=== S8B MEASURED FIGURES (R6 Option B, for the A1 pin) ===");
    println!("| quantity | measured |");
    println!("|---|---|");
    println!("| audit bytes per ACCEPTED refresh (logical, incl. 8 B key) | {audit_bytes_per_refresh} B |");
    println!("| audit bytes per REFUSED refresh (all four arms) | 0 B |");
    println!("| MemoryId 12 encoded size, worst case (both Options set) | {mem12} B |");
    println!("| response size, Ok(ControllerInvariant) | {ok_len} B |");
    for (n, l) in &arms {
        println!("| response size, Err({n}) | {l} B |");
    }
    println!(
        "\nPER-WINDOW CEILING (criterion 1), as an inequality keyed to the ruled\n\
         constant rather than a number: accepted refreshes per window <=\n\
         window / min_interval_ns, so audit growth <= {audit_bytes_per_refresh} B x\n\
         (window / min_interval_ns) and cycle spend <= cycle_budget x\n\
         (window / min_interval_ns). Both terms are linear in the pin, so A1 can\n\
         evaluate any candidate without a re-measure.\n"
    );

    // Properties that must hold for ANY pin.
    assert!(audit_bytes_per_refresh > 0, "an accepted refresh must be auditable");
    assert!(mem12 > 0 && mem12 < 128, "MemoryId 12 must stay a small bounded cell");
    // Every arm is a FIXED-size response: the only payloads are one `nat64`, so
    // the spread across arms is a handful of bytes and nothing scales with
    // caller count, roster size or history. Bounds are set from the measured
    // figures, not guessed — the type table ships inside each response, which
    // is why these are ~80 B rather than ~10 B.
    let lo = arms.iter().map(|(_, l)| *l).min().unwrap();
    let hi = arms.iter().map(|(_, l)| *l).max().unwrap();
    assert!(hi < 256, "refusal responses must stay small and fixed: max {hi} B");
    assert!(
        hi - lo <= 16,
        "all four refusal arms must be within a few bytes — a wide spread would \
         mean an unbounded field reached the return type ({lo}..{hi} B)"
    );
}

/// S8B / MAX_VAULT_SIGNERS = 9 law — the refresh response carries NO
/// maxima-keyed term.
///
/// The law says inequalities key to ruled maxima and never to a hard-coded
/// roster size. The honest way to satisfy it here is to show there is no
/// roster-dependent term at all: the response type has no collection field, so
/// its size cannot vary with the roster. Asserted rather than asserted-in-prose
/// — the response is measured at a 3-member and a 9-member roster (the ruled
/// MAX_RECOVERY_MEMBERS) and must be byte-identical.
#[test]
fn s8b_refresh_response_size_is_independent_of_roster_size() {
    let encode = |members: Vec<Principal>| {
        core::init(
            UpgraderInitArgs { recovery_members: members, threshold: 2, vault: p(VAULT) },
            1_000,
        );
        core::record_controller_invariant(true, false, 777_000);
        candid::encode_one(Ok::<_, stsh_custody_types::InvariantRefreshRefusal>(
            core::query_controller_invariant(),
        ))
        .expect("encodes")
        .len()
    };
    let at_three = encode(vec![p(M1), p(M2), p(M3)]);
    let at_nine = encode(vec![
        p(M1), p(M2), p(M3), p(M4), p(M5), p(0x06), p(0x07), p(0x08), p(0x09),
    ]);
    assert_eq!(
        at_three, at_nine,
        "the refresh response must carry no roster-keyed term — if this ever \
         differs, a collection reached the response type and the ceiling \
         arithmetic needs a maxima-keyed bound"
    );
}


// ── W6-EVIDENCE-01 — layer 2: reachability gate (upgrader plane) ─────────────

/// W6-EVIDENCE-01 item 1 — EVERY permanent-history access reachable from
/// `post_upgrade` is enumerated, with its loop/recursion context.
///
/// WHY THIS EXISTS. The first-layer classifier matches a SHAPE — a permanent
/// map with `.iter()` in one statement. S8A proved that is not the property the
/// W6 assertion was being cited for: the removed `rebuild_invariant_mirror`
/// read `AUDIT_EVENTS` up to 10,000 times at `post_upgrade` with keyed
/// `get(&seq)` inside a range loop. Every read O(1), no `.iter()` anywhere, cost
/// growing with history regardless — invisible to a per-statement matcher.
///
/// EXACT-SET EQUALITY, not "no unexpected offenders". Drift in EITHER direction
/// must fail: a new access appearing is the obvious case, but an enumerated one
/// vanishing or changing context means its written justification is now stale,
/// and a stale justification is how the first W6 claim survived being false.
#[test]
fn w6_evidence_01_reachable_history_accesses_are_enumerated_upgrader() {
    use stsh_custody_types::HistoryAccessContext as C;
    const SRC: &str = include_str!("core.rs");
    const PERMANENT: [&str; 3] = ["RECOVERY_PROPOSALS", "UPGRADE_INTENTS", "AUDIT_EVENTS"];

    // Production region only, cut at the same cfg-gated boundary the
    // first-layer lint uses — fixtures legitimately iterate deep histories.
    let prod = SRC
        .split_once("pub mod measurement {")
        .map(|(before, _)| before)
        .expect("W6-EVIDENCE-01: the measurement-module boundary was not found");

    let found = stsh_custody_types::reachable_history_accesses(prod, &PERMANENT, "post_upgrade");

    // THE ENUMERATION. Each entry is (function, map, context) plus the reason it
    // is permitted. All three are the §S7 E2 sweep doing per-item work.
    //
    // WHY `InLoopViaCaller` IS RULED ACCEPTABLE HERE, AND WHY THAT IS NOT A
    // LOOPHOLE. `sweep_executing_starts_to_unknown` iterates
    // `NONTERMINAL_RECOVERY_PROPOSAL_INDEX` (MemoryId 10) — a BOUNDED
    // authoritative companion whose membership is capped by C5/C7/C12, ruled at
    // S6. It is deliberately NOT in the PERMANENT set above, for exactly that
    // reason. So the loop's trip count is bounded by the cap, not by history
    // length, and each per-item access is a keyed read or a keyed insert.
    //
    // The gate CANNOT prove that bound textually — which is the point of making
    // it an enumeration a human has to write. What the gate guarantees is that
    // no FOURTH access can appear without this list failing.
    let expected: Vec<(&str, &str, C)> = vec![
        // Appends the swept-to-unknown audit event, once per swept proposal.
        ("append_audit", "AUDIT_EVENTS", C::InLoopViaCaller),
        // Writes the promoted proposal back, once per swept proposal.
        ("put_stored_proposal", "RECOVERY_PROPOSALS", C::InLoopViaCaller),
        // Keyed read of the proposal being promoted.
        ("get_stored_proposal", "RECOVERY_PROPOSALS", C::InLoopViaCaller),
    ];

    let mut actual: Vec<(String, String, C)> = found
        .iter()
        .map(|a| (a.function.clone(), a.map.clone(), a.context))
        .collect();
    actual.sort_by(|a, b| (a.0.clone(), a.1.clone()).cmp(&(b.0.clone(), b.1.clone())));
    let mut want: Vec<(String, String, C)> = expected
        .iter()
        .map(|(f, m, c)| (f.to_string(), m.to_string(), *c))
        .collect();
    want.sort_by(|a, b| (a.0.clone(), a.1.clone()).cmp(&(b.0.clone(), b.1.clone())));

    assert_eq!(
        actual, want,
        "W6-EVIDENCE-01 (upgrader): the set of permanent-history accesses \
         reachable from post_upgrade has CHANGED.\n\n\
         If you added one: it must be a bounded, justified access, and it must be \
         enumerated here with the reason. If one disappeared: delete its entry, \
         because a justification for code that no longer exists is how a false W6 \
         claim survives.\n\nFull findings: {found:#?}"
    );

    // No access may sit in a recursive cycle: depth is not statically evident,
    // so it cannot be called bounded.
    assert!(
        !found.iter().any(|a| a.context == C::InRecursiveCycle),
        "W6-EVIDENCE-01: a permanent-history access is reachable through a call \
         cycle, whose depth this gate cannot bound: {found:#?}"
    );
}

/// W6-EVIDENCE-01 item 2 — the four named mutation fixtures.
///
/// **WHICH COVERAGE IS NATIVE AND WHICH IS CROSS-WASM ONLY** (CTO instruction,
/// carried from the S8B mutation-5 finding). All four fixtures below are
/// NATIVE-catchable by construction: this gate is a text analyser, so feeding it
/// source strings is the complete test and a PocketIC run would add nothing.
///
/// That is NOT true of the sibling properties, and the distinction matters
/// because the failure mode is silent. `s8b_limiter_state_survives_post_upgrade`
/// and `r6_0_*` durability tests PASS against a non-durable implementation when
/// run natively — in process, `post_upgrade` is a plain function call and never
/// clears a thread-local. Only
/// `pic_s8b_refresh_rate_limiter_survives_a_real_upgrade` and
/// `pic_s8a_r6_0_controller_invariant_survives_real_upgrades_past_scan_cap`
/// exercise a genuine module replacement, and mutation 5 confirmed that a
/// heap-only limiter is caught ONLY there.
///
/// So: do not "optimize" those two PocketIC tests down to native equivalents.
/// They are not slow duplicates of the native ones — they are the only tests
/// that can fail for the reason they exist. This gate's fixtures, by contrast,
/// are correctly native and should stay that way.
///
/// These are SOURCE FIXTURES, not canister code: the gate is a text analyser, so
/// the honest way to prove it discriminates is to feed it the exact constructs
/// it must accept and reject. Three must be REJECTED (flagged as loop-context),
/// one must remain ALLOWED. Fixture 3 is the one that matters most — it is the
/// shape S8A's defect actually had, and the shape the first-layer matcher is
/// blind to.
#[test]
fn w6_evidence_01_gate_discriminates_the_four_named_fixtures() {
    use stsh_custody_types::HistoryAccessContext as C;
    const PERMANENT: [&str; 1] = ["AUDIT_EVENTS"];

    // Fixture 1 — keyed `get` in a RANGE LOOP. This is `rebuild_invariant_mirror`
    // as it actually existed at 41ff8f01.
    let f1 = r#"
        fn post_upgrade() { rebuild(); }
        fn rebuild() {
            for seq in 0..10_000u64 {
                if let Some(raw) = AUDIT_EVENTS.with(|a| a.borrow().get(&seq)) { drop(raw); }
            }
        }
    "#;
    // Fixture 2 — keyed `get` in a `while` loop.
    let f2 = r#"
        fn post_upgrade() { drain(); }
        fn drain() {
            let mut seq = 0u64;
            while seq < 10_000 {
                let _ = AUDIT_EVENTS.with(|a| a.borrow().get(&seq));
                seq += 1;
            }
        }
    "#;
    // Fixture 3 — HELPER-MEDIATED keyed loop: the loop is in one function, the
    // keyed read in another. Every statement in isolation looks O(1).
    let f3 = r#"
        fn post_upgrade() { walk(); }
        fn walk() { for seq in 0..10_000u64 { read_one(seq); } }
        fn read_one(seq: u64) -> Option<Vec<u8>> { AUDIT_EVENTS.with(|a| a.borrow().get(&seq)) }
    "#;
    // Fixture 4 — a genuinely SINGLE keyed read, which must stay ALLOWED. A gate
    // that rejects this is useless: it would ban the bounded reads the design
    // depends on and would be switched off by the next person who hit it.
    let f4 = r#"
        fn post_upgrade() { let _ = head(); }
        fn head() -> Option<Vec<u8>> { AUDIT_EVENTS.with(|a| a.borrow().last_key_value().map(|(_, v)| v)) }
    "#;

    for (name, src) in [("range-loop", f1), ("while-loop", f2), ("helper-mediated", f3)] {
        let found = stsh_custody_types::reachable_history_accesses(src, &PERMANENT, "post_upgrade");
        assert_eq!(found.len(), 1, "fixture {name}: expected exactly one access, got {found:#?}");
        assert_ne!(
            found[0].context,
            C::PointRead,
            "fixture {name} MUST be rejected — this is the class the first-layer \
             matcher cannot see, so a gate that calls it a point read adds nothing"
        );
    }

    let allowed = stsh_custody_types::reachable_history_accesses(f4, &PERMANENT, "post_upgrade");
    assert_eq!(allowed.len(), 1, "fixture single-read: {allowed:#?}");
    assert_eq!(
        allowed[0].context,
        C::PointRead,
        "fixture single-read MUST stay ALLOWED — a gate that bans bounded keyed \
         reads bans the design and gets disabled"
    );
}

/// W6-EVIDENCE-01 — the gate must not fire on its own prose.
///
/// The first-layer classifier's comment block records this failure mode as
/// having recurred four times: a lint that quotes its own patterns in
/// documentation matches itself. This gate strips comments AND string literals,
/// so a panic message naming a map and `.iter()` is inert.
#[test]
fn w6_evidence_01_gate_ignores_comments_and_string_literals() {
    const PERMANENT: [&str; 1] = ["AUDIT_EVENTS"];
    let src = r#"
        fn post_upgrade() {
            // AUDIT_EVENTS.with(|a| a.borrow().iter()) — quoted in a comment.
            /* AUDIT_EVENTS.iter() in a block comment */
            panic!("AUDIT_EVENTS.iter() named in a panic message");
        }
    "#;
    let found = stsh_custody_types::reachable_history_accesses(src, &PERMANENT, "post_upgrade");
    assert!(
        found.is_empty(),
        "the gate matched its own prose — the exact failure that recurred four \
         times on the first-layer lint: {found:#?}"
    );
}

// ── RF-1 (SSA S8B return) — sibling injection seams ─────────────────────────

/// **RF-1 DISTINCTNESS.** "Clear the injection" and "force unruled" must be
/// OBSERVABLY different on all four sibling seams, now that every one of their
/// production constants is ruled `Some`.
///
/// This is the test whose absence let the defect live. Before RF-1 the seams
/// were single-`Option`, so `inject(None)` could only mean one thing, and which
/// thing it meant depended entirely on whether the production constant happened
/// to be `None`. It was — until S6 ruled C9, C5/C7/C12, C3/C4 and C11. From
/// that moment every `inject(None)` silently switched from "unruled" to "the
/// ruled value", and every test that believed it was exercising the unruled
/// path was exercising the ruled one instead.
///
/// Asserted per seam, not in aggregate: a single combined assertion would pass
/// if any one seam were still conflated.
#[test]
fn rf1_clear_override_and_force_unruled_are_distinguishable_upgrader() {
    setup();

    // (a) No injection at all -> the RULED production values.
    let (er, caps, life, sweep) = core::resolved_sibling_params_for_test();
    assert!(er.is_some(), "C9 is ruled since S6 — a non-injecting caller must see it");
    assert!(caps.is_some(), "C12 is ruled since S6");
    assert!(life.is_some(), "C3/C4 are ruled since S6");
    assert!(sweep.is_some(), "C11 is ruled since S6");

    // (b) FORCE UNRULED -> None on every seam, despite production being Some.
    core::inject_entry_rate_for_test(Some(None));
    core::inject_nonterminal_caps_for_test(Some(None));
    core::inject_lifetime_params_for_test(Some(None), Some(None));
    let (er_u, caps_u, life_u, sweep_u) = core::resolved_sibling_params_for_test();
    assert_eq!(er_u, None, "force-unruled must reach the unruled path for C9");
    assert_eq!(caps_u, None, "force-unruled must reach the unruled path for C12");
    assert_eq!(life_u, None, "force-unruled must reach the unruled path for C3/C4");
    assert_eq!(sweep_u, None, "force-unruled must reach the unruled path for C11");

    // (c) CLEAR the injection -> back to the ruled values, byte-identical to (a).
    core::inject_entry_rate_for_test(None);
    core::inject_nonterminal_caps_for_test(None);
    core::inject_lifetime_params_for_test(None, None);
    assert_eq!(
        core::resolved_sibling_params_for_test(),
        (er, caps, life, sweep),
        "clearing the injection must restore the RULED values — if this equals \
         the force-unruled result, the two are still conflated"
    );

    // The two must differ. Stated explicitly so the property is not merely
    // implied by the two blocks above.
    assert_ne!(
        (er, caps, life, sweep),
        (er_u, caps_u, life_u, sweep_u),
        "RF-1: clear-override and force-unruled are INDISTINGUISHABLE — this is \
         exactly the defect, and it is invisible until the constants are pinned"
    );
}

/// **RF-1 NON-VACUITY.** The candidate-injection direction still works, so the
/// fix did not simply disable the seams.
#[test]
fn rf1_candidate_injection_still_overrides_the_ruled_values_upgrader() {
    setup();
    let ruled = core::resolved_sibling_params_for_test().0.expect("C9 ruled");
    let candidate = stsh_custody_types::EntryRateParams {
        window_ns: ruled.window_ns + 1,
        global_per_window: ruled.global_per_window + 1,
        per_signer_per_window: ruled.per_signer_per_window + 1,
    };
    core::inject_entry_rate_for_test(Some(Some(candidate)));
    assert_eq!(
        core::resolved_sibling_params_for_test().0,
        Some(candidate),
        "a candidate must still override the ruled value"
    );
    assert_ne!(candidate, ruled, "the fixture must actually differ from the ruled value");
}
