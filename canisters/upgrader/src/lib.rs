// =============================================================================
// STSH Custody Upgrader Canister — L2 body
// =============================================================================
//
// The other half of the closed ring: `Upgrader.controllers == [Vault]`
// (brief invariant 1, freeze §3c). Carries the recovery plane with its OWN
// durable membership at fixed threshold 2 — NOT synced from the Vault
// (brief L2), validated by the shared `validate_bootstrap_quorum`.
//
// This file is the thin ic-cdk shell. All state and every authorization /
// transition decision lives in `core.rs`, parameterized on caller/time/self
// so the state machine is natively testable. The shell:
//   * resolves ic_cdk::caller() / api::time() / id();
//   * calls the core's `*_begin` functions (all durable writes land BEFORE
//     the first inter-canister call — brief invariant 4);
//   * issues the planned management `install_code` — the ONLY management
//     call this canister can make, always `mode = upgrade`, inline-only,
//     hash-bound (freeze §3c/§3d; NO stop/update_settings/delete/reinstall
//     path exists here, so self/cross stop between Vault and Upgrader is
//     structurally impossible from this side);
//   * feeds the outcome back through `finish_*`;
//   * opportunistically refreshes the durable controller-invariant
//     observation from management `canister_status` (self + Vault) — queries
//     cannot observe controllers, and no timers exist (freeze §11), so the
//     PUBLIC `get_controller_invariant` proof is exactly as fresh as the
//     last update-path observation and fails closed before the first one.
//
// Query surface: freeze §5 rulings exactly — PUBLIC: get_controller_invariant,
// get_recovery_summary, get_build_info; RECOVERY-SIGNER-GATED (the only gate
// the platform allows an Upgrader query — canister-to-canister queries do
// not exist; NO Vault-signer mirror is invented): get_upgrader_audit_events,
// get_upgrade_status, get_recovery_proposal, get_recovery_membership.
// Unauthorized responses are indistinguishable `None` on every gated query.
//
// MemoryIds 0–4 (freeze §7) live in core.rs — the complete namespace.
// =============================================================================

#![cfg_attr(not(test), forbid(unsafe_code))]

mod core;

#[cfg(test)]
mod tests;

use candid::Principal;
use ic_cdk::api::management_canister::main::{
    canister_status, install_code, start_canister, CanisterIdRecord, CanisterInstallMode,
    InstallCodeArgument,
};
use ic_cdk_macros::{init, post_upgrade, query, update};
use stsh_custody_types::{
    ActionOutcome, ControllerInvariant, ControllerInvariantProof, InvariantRefreshRefusal,
    RecoveryAction, RecoveryError, RecoveryProposal,
    RecoverySummary, ReconcileTerminalOutcome, UpgraderInitArgs, UpgradeObjectiveEvidence,
};

use crate::core::{
    ApproveOutcome, AuditEventsPage, ReconcileAuthorityView, RecoveryExecution,
    TriggerUpgradeResult, UpgradeStatusView,
};

#[init]
fn init(args: UpgraderInitArgs) {
    core::init(args, ic_cdk::api::time());
}

#[post_upgrade]
fn post_upgrade() {
    core::post_upgrade(ic_cdk::api::time());
}

// ── Management-call execution (the seam) ─────────────────────────────────────

/// Issue the ONLY management call this canister can plan — upgrade-mode
/// `install_code` against the Vault — and apply the outcome to the durable
/// intent. Returns the resulting intent outcome.
async fn execute_install(plan: core::InstallPlan) -> ActionOutcome {
    let now = ic_cdk::api::time();
    let result = install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Upgrade(None),
        canister_id: plan.target,
        wasm_module: plan.wasm_module,
        arg: plan.arg,
    })
    .await
    .map_err(|(code, msg)| format!("{code:?}: {msg}"));
    let outcome = core::finish_intent(&plan.key, &result, now);
    // Best-effort controller-invariant refresh (both status calls must
    // succeed for an observation to be recorded).
    refresh_controller_invariant().await;
    outcome
}

/// Refresh the durable controller-invariant observation. Self-status is a
/// legal management call (a canister may read its own status); the Vault's
/// status is readable because the Upgrader is its controller. Records
/// nothing unless BOTH observations succeed — a partial observation is not
/// evidence.
async fn refresh_controller_invariant() {
    let self_id = ic_cdk::id();
    let Some(vault) = core::vault_principal() else { return };
    let self_res = canister_status(CanisterIdRecord { canister_id: self_id }).await;
    let vault_res = canister_status(CanisterIdRecord { canister_id: vault }).await;
    // Only a fully-observed pair is evidence: a failed call must not record
    // a false "breach" nor overwrite a prior good observation.
    if let (Ok((s,)), Ok((v,))) = (self_res, vault_res) {
        let upgrader_ok = s.settings.controllers == vec![vault];
        let vault_ok = v.settings.controllers == vec![self_id];
        core::record_controller_invariant(vault_ok, upgrader_ok, ic_cdk::api::time());
    }
}

/// R6 Option B — PERMISSIONLESS, rate-limited refresh of the
/// controller-invariant observation. DID movement pre-authorized by
/// `CTO_ADDENDUM_S8B_DID_PREAUTH_2026-08-12.md` (0d509960…), §1.
///
/// The ONLY permissionless update on this canister, and the only one that is
/// not gated to the Vault or a recovery member. What makes that safe is the
/// order below, not the caller's identity:
///
///   1. `refresh_charge` admits or refuses. The three R6 constants are PINNED
///      by `A1_PIN_R6_REFRESH_CONSTANTS_2026-08-12.md` (eee3f17a…) — 6 h
///      cadence, 50,000,000 cycle budget, 24 h staleness — so the endpoint is
///      now live. Were they ever `None` again it would refuse `NotRuled` having
///      read and written NOTHING (addendum condition 1), which is why that arm
///      remains and is still tested.
///   2. On admission the allowance is ALREADY durable — charged before this
///      function's first `await` — so a concurrent burst cannot each see an
///      unspent allowance (conditions 2 and 3).
///   3. Only then are the two management status calls issued, through the SAME
///      seam the update paths use, which records an observation only when BOTH
///      succeed (condition 5).
///
/// `Ok` means the endpoint RAN, not that the observation necessarily moved: a
/// management call that fails leaves the prior observation intact and returns
/// it unchanged. That is deliberate and is why no fifth refusal variant was
/// added — the caller compares `observed_at_ns` to see whether it advanced, and
/// the DID ledger stays exactly the shape the addendum pre-authorized. A failed
/// refresh still spends its allowance, or arranging for failures would be an
/// unmetered retry loop.
#[update]
async fn refresh_controller_invariant_now(
) -> Result<ControllerInvariant, InvariantRefreshRefusal> {
    let charge = core::refresh_charge(ic_cdk::api::time())?;
    refresh_controller_invariant().await;
    core::refresh_release(charge);
    Ok(core::query_controller_invariant())
}

// ── Update surface (deny by default; exactly two authorities) ────────────────

/// The Vault instructs the Upgrader to upgrade the VAULT via management
/// `install_code`, upgrade-mode ONLY, hash-bound (expected wasm + arg hashes
/// recomputed, rejected on mismatch), inline-only. The durable intent —
/// binding the delivered bytes — is written BEFORE the install call; the
/// artifact bytes are cleared only with terminal evidence durable. Caller
/// must be the Vault principal recorded durably at init; anything else is
/// rejected. Replay with the same request id returns the prior result and
/// issues no new call.
#[update]
async fn trigger_vault_upgrade(
    request_id: u64,
    expected_wasm_hash: Vec<u8>,
    expected_arg_hash: Vec<u8>,
    wasm_bytes: Vec<u8>,
    arg_bytes: Vec<u8>,
) -> Result<TriggerUpgradeResult, RecoveryError> {
    let caller = ic_cdk::caller();
    let (result, plan) = core::trigger_begin(
        &caller,
        request_id,
        expected_wasm_hash,
        expected_arg_hash,
        wasm_bytes,
        arg_bytes,
        ic_cdk::api::time(),
    )?;
    if let Some(plan) = plan {
        let outcome = execute_install(plan).await;
        return Ok(TriggerUpgradeResult { outcome });
    }
    Ok(result)
}

/// Vault-originated reconciliation of an OutcomeUnknown Vault upgrade to
/// terminal `Executed | Failed` (freeze §3d contract applied to Vault
/// upgrades). Legal source state OutcomeUnknown ONLY; never back to Pending;
/// never re-triggerable; never retries or reinstalls (no inter-canister
/// call is made). Caller must be the Vault.
#[update]
async fn reconcile_vault_upgrade(
    request_id: u64,
    objective_evidence: UpgradeObjectiveEvidence,
) -> Result<ReconcileTerminalOutcome, RecoveryError> {
    let caller = ic_cdk::caller();
    let self_id = ic_cdk::id();
    let outcome = core::reconcile_vault_upgrade(
        &caller,
        request_id,
        &objective_evidence,
        &self_id,
        ic_cdk::api::time(),
    )?;
    refresh_controller_invariant().await;
    Ok(outcome)
}

/// Propose a recovery action (recovery-member-gated; own durable membership,
/// fixed threshold 2). PROPOSING APPROVES NOTHING (V8 §3, CTO R-1a): zero
/// approvals, no approval-log entry; the proposer must call approve_recovery
/// separately, carrying the commitment hash, on equal terms with every other
/// member. For TriggerVaultUpgrade the durable intent — the sole artifact
/// store — is created in `Pending` at proposal time.
#[update]
fn propose_recovery(
    action: RecoveryAction,
    requested_lifetime_ns: Option<u64>,
) -> Result<u64, RecoveryError> {
    let r = core::propose_recovery(
        &ic_cdk::caller(),
        action,
        ic_cdk::api::time(),
        requested_lifetime_ns,
        &ic_cdk::id(),
    );
    // S5A M1 gate C — RECOVERY-ORIGIN `admission_path_total`. §C applies to
    // both origin paths INDEPENDENTLY, so the recovery plane needs its own
    // figure rather than inheriting the Vault's. Absolute counter, so candid
    // decode of the payload is included — material at maximum admitted payload,
    // and a delta around the core call alone would understate the path.
    #[cfg(feature = "testing")]
    LAST_PROPOSE_INSTRUCTIONS.with(|c| c.set(ic_cdk::api::instruction_counter()));
    r
}

/// Propose a governed recovery-membership rotation (SSA L2-4):
/// recovery-member-gated, fixed threshold 2, no anonymous/duplicate members,
/// >= 2 distinct members — validated by the shared validate_bootstrap_quorum
/// at proposal time AND again at execution, fully before the atomic durable
/// transition (epoch bump; approvals from a prior epoch are then rejected).
#[update]
fn propose_membership_rotation(
    new_members: Vec<Principal>,
    requested_lifetime_ns: Option<u64>,
) -> Result<u64, RecoveryError> {
    core::propose_membership_rotation(&ic_cdk::caller(), new_members, ic_cdk::api::time(), requested_lifetime_ns, &ic_cdk::id())
}

/// R3.7/R3.11 (V7 §3) — withdraw your OWN pending recovery proposal.
/// Recovery-member-gated, then proposer-scoped: a member who is not the
/// proposer receives `NotProposer`, so no member can veto a proposal the other
/// members are still evaluating.
#[update]
fn cancel_recovery_proposal(proposal_id: u64) -> Result<(), RecoveryError> {
    core::cancel_recovery_proposal(&ic_cdk::caller(), proposal_id, ic_cdk::api::time())
}

/// R3.8/R3.11 — drive the bounded expiry sweep over recovery proposals.
/// Member-gated; work per call is bounded so the sweep cannot itself become
/// the denial of service it exists to prevent. Returns the ids reaped, so a
/// caller repeats until it returns empty.
#[update]
fn sweep_expired_recovery_proposals(limit: u32) -> Result<Vec<u64>, RecoveryError> {
    let caller = ic_cdk::caller();
    core::require_member_public(&caller)?;
    // Clamp to the ruled per-call work bound once S5A sets it. Until then the
    // caller's limit governs, which is safe because no proposal carries an
    // expiry yet, so the index is empty and the sweep is vacuous.
    let limit = match core::sweep_work_limit() {
        Some(cap) => (limit as usize).min(cap),
        None => limit as usize,
    };
    Ok(core::sweep_expired_recovery_proposals(ic_cdk::api::time(), limit))
}

/// Approve a proposal (recovery action or membership rotation;
/// recovery-member-gated). The quorum-reaching approval durably flips the
/// proposal to `Executing` BEFORE the first inter-canister call and is the
/// only admitted execution — concurrent quorum admits exactly one.
/// `ReconcileVaultUpgrade` and rotation executions are synchronous (no
/// inter-canister call): the 2-of-3 fallback reconciles an OutcomeUnknown
/// Vault upgrade to terminal with the Vault unavailable.
#[update]
async fn approve_recovery(
    proposal_id: u64,
    expected_action_hash: Vec<u8>,
) -> Result<(), RecoveryError> {
    let caller = ic_cdk::caller();
    let now = ic_cdk::api::time();
    let approve_result =
        core::approve_recovery(&caller, proposal_id, now, expected_action_hash, &ic_cdk::id());
    // S5A M1 gate B — record what THIS MESSAGE has consumed at the point the
    // synchronous approval work completes.
    //
    // The absolute counter is recorded rather than a delta, because
    // `instruction_counter` measures from the START of the message: the figure
    // therefore includes argument decode and dispatch, and is the closest
    // available proxy for the cost of the whole quorum-reaching message. Only
    // reply encoding falls outside it.
    //
    // THE MEASUREMENT BOUNDARY IS STRUCTURAL, NOT A MATTER OF PROBE PLACEMENT.
    // Spec §B.3 insists `rotation_fixed` covers the quorum-reaching message
    // ONLY, never the lifecycle audit events emitted by the earlier propose and
    // first-approve messages. Those are separate ingress messages with their
    // own counters, so they cannot leak into this figure however the probe is
    // positioned — the per-message/per-lifecycle distinction §B.3 draws is
    // enforced by the platform rather than by care taken here.
    //
    // On the rotation path `core::approve_recovery` is synchronous and returns
    // `RotationExecuted` before any `await`, so this single reading covers
    // rotation_fixed AND the complete stale-set terminalization — which is
    // exactly the quantity §B gates.
    #[cfg(feature = "testing")]
    LAST_APPROVE_INSTRUCTIONS.with(|c| c.set(ic_cdk::api::instruction_counter()));
    match approve_result? {
        ApproveOutcome::Recorded | ApproveOutcome::RotationExecuted { .. } => Ok(()),
        ApproveOutcome::Execute(RecoveryExecution::Trigger { proposal_id, plan }) => {
            let outcome = execute_install(plan).await;
            core::recovery_finish_trigger(proposal_id, outcome, ic_cdk::api::time());
            Ok(())
        }
        // §S7 cell 4 — the ONLY `start_canister` this canister issues.
        //
        // §9: nothing here widens the Upgrader beyond `install_code`
        // (upgrade-mode) plus read-only `canister_status` plus this
        // `start_canister`. NO stop, NO `update_settings`, NO delete, NO
        // reinstall, NO create. The Upgrader remains structurally incapable of
        // stopping either ring member, and §3c is NOT to be resolved by adding
        // stop or uninstall — the ring pays for that foreclosure with the
        // in-canister fence instead.
        ApproveOutcome::Execute(RecoveryExecution::Start { proposal_id, target }) => {
            let result = start_canister(CanisterIdRecord { canister_id: target })
                .await
                .map_err(|(code, msg)| format!("{code:?}: {msg}"));
            // E1 is IN THIS SAME MESSAGE: `finish_start` re-reads the durable
            // state (§3c.2) and, on any reply that does not objectively
            // establish success, writes `OutcomeUnknown` atomically — never
            // `Failed`, which would infer the call's fate rather than observe
            // it.
            core::finish_start(proposal_id, &result, ic_cdk::api::time());
            refresh_controller_invariant().await;
            Ok(())
        }
        ApproveOutcome::Execute(RecoveryExecution::ReconcileStart {
            proposal_id,
            target_proposal_id,
            evidence,
            approvers,
        }) => {
            let self_id = ic_cdk::id();
            // Synchronous — no inter-canister call, which is why the 2-of-3
            // fallback settles a stopped-recovery start with the Vault
            // unavailable.
            let result = core::reconcile_vault_start(
                target_proposal_id,
                &evidence,
                ReconcileAuthorityView::Recovery { approvers },
                &self_id,
                ic_cdk::api::time(),
            );
            core::recovery_finish_reconcile_start(proposal_id, &result, ic_cdk::api::time());
            refresh_controller_invariant().await;
            result.map(|_| ())
        }
        ApproveOutcome::Execute(RecoveryExecution::Reconcile {
            proposal_id,
            intent_id,
            evidence,
            approvers,
        }) => {
            let self_id = ic_cdk::id();
            // Recovery-originated reconciliation: the namespace is NOT
            // pre-bound — ambiguity (id in both namespaces) REJECTS, never
            // selects by precedence (SSA L2-3). Terminal replay is disabled
            // here (CUST-L12-02): recovery reconcile proposals stay strictly
            // one-shot — AlreadyTerminal on an already-terminal intent.
            let result = core::reconcile_intent(
                intent_id,
                None,
                &evidence,
                ReconcileAuthorityView::Recovery { approvers },
                &self_id,
                ic_cdk::api::time(),
                false,
            );
            core::recovery_finish_reconcile(proposal_id, &result, ic_cdk::api::time());
            refresh_controller_invariant().await;
            result.map(|_| ())
        }
    }
}

// ── Query surface (freeze §5 — exact rulings) ────────────────────────────────

/// PUBLIC, conscious (freeze §5). **NON-AUTHORITATIVE HISTORICAL EVIDENCE**
/// since S11-2 — reports the last durably-recorded observation with no
/// freshness, and cannot distinguish "never observed" from a double breach at
/// time 0. Retained for compatibility; use `get_controller_invariant_proof`
/// for any decision.
#[query]
fn get_controller_invariant() -> ControllerInvariant {
    core::query_controller_invariant()
}

/// PUBLIC, conscious (freeze §5). S11-2 / CUST-SSA-006 — the AUTHORITATIVE
/// current-proof contract (BRIEF V4.1 R6 requirements 7–9): three-state
/// freshness, the recorded truth booleans, age against the ruled 24 h bound,
/// and the fail-closed `current_proof_ok` aggregate. Freshness is computed
/// against the CURRENT IC time on every call.
#[query]
fn get_controller_invariant_proof() -> ControllerInvariantProof {
    core::query_controller_invariant_proof(ic_cdk::api::time())
}

/// RECOVERY-SIGNER-GATED, bounded (freeze §5). Unauthorized / invalid
/// bounds / out of range are the same `None`.
#[query]
fn get_upgrader_audit_events(cursor: Option<u64>, limit: u32) -> Option<AuditEventsPage> {
    core::query_audit_events(&ic_cdk::caller(), cursor, limit)
}

/// RECOVERY-SIGNER-GATED (freeze §5: gated because recovery membership is
/// the only gate available to an Upgrader query). Unknown id and
/// unauthorized are the same `None`.
#[query]
fn get_upgrade_status(proposal_id: u64) -> Option<UpgradeStatusView> {
    core::query_upgrade_status(&ic_cdk::caller(), proposal_id)
}

/// RECOVERY-SIGNER-GATED (freeze §5).
#[query]
fn get_recovery_proposal(id: u64) -> Option<RecoveryProposal> {
    core::query_recovery_proposal(&ic_cdk::caller(), id)
}

/// RECOVERY-SIGNER-GATED (freeze §5).
/// R1.6 — SIGNER-GATED typed rotation view. Without it a member cannot obtain
/// the proposed roster or its commitment, and therefore cannot approve a
/// rotation at all once R1.5 makes the hash required.
#[query]
fn get_rotation_proposal(proposal_id: u64) -> Option<core::RotationProposalView> {
    core::query_rotation_proposal(&ic_cdk::caller(), proposal_id)
}

#[query]
fn get_recovery_membership() -> Option<Vec<Principal>> {
    core::query_recovery_membership(&ic_cdk::caller())
}

/// PUBLIC, conscious (freeze §5): mirrors the Vault summary. No principals.
#[query]
fn get_recovery_summary() -> RecoverySummary {
    core::query_recovery_summary()
}

/// PUBLIC — house convention (freeze §5).
#[query]
fn get_build_info() -> String {
    format!("upgrader v{}", env!("CARGO_PKG_VERSION"))
}

/// TEST-ONLY (feature `testing`): corrupt the companion indexes.
///
/// Same reason as the Vault's hook. `NONTERMINAL_INTENT_INDEX` and
/// `RECOVERY_PROPOSAL_EXPIRY_INDEX` are `StableBTreeMap`s, so they survive a
/// Wasm replacement inherently: a real-upgrade test that does not corrupt them
/// first asserts only that stable memory persisted, which nothing in this
/// change put at risk. Corrupting first makes the post-upgrade assertions
/// depend on DETECTION — `companion_check` trapping on a companion that
/// disagrees with its accounting. Nothing is repaired; there is no repair
/// surface to exercise.
/// §S7 P1-4 — PRODUCTION-FAITHFUL SEAM: reach the start's quorum boundary and
/// DROP the planned management call, modelling a `start_canister` whose reply
/// has not arrived.
///
/// This plants NOTHING. It runs the REAL `core::approve_recovery`, so the
/// durable state it leaves — proposal `Executing`, the §2 start-intent, the
/// audit trail — is produced byte-for-byte by the production pre-await path.
/// The only difference from production is that the returned `RecoveryExecution`
/// is discarded instead of being awaited, which is precisely the condition E2
/// exists for: a call outstanding across an upgrade boundary.
///
/// Without this seam the state is unreachable in a test, because a management
/// `start_canister` always replies within the message on PocketIC — so the
/// alternative is to fabricate `Executing` by hand, which proves nothing about
/// the wiring E2 actually runs against.
#[cfg(feature = "testing")]
#[update]
fn approve_start_without_issuing_call_for_test(
    proposal_id: u64,
    expected_action_hash: Vec<u8>,
) -> Result<(), RecoveryError> {
    let outcome = core::approve_recovery(
        &ic_cdk::caller(),
        proposal_id,
        ic_cdk::api::time(),
        expected_action_hash,
        &ic_cdk::id(),
    )?;
    match outcome {
        // The plan is deliberately dropped — the call is never issued.
        ApproveOutcome::Execute(RecoveryExecution::Start { .. }) | ApproveOutcome::Recorded => {
            Ok(())
        }
        // NOTE: the message deliberately does NOT embed this function's own
        // name. The ring test-export allowlist scanner recovers symbols by
        // walking backwards over identifier bytes, so a copy of the name
        // sitting in the data section beside an unrelated string is picked up
        // as a spurious symbol with a leading character glued on. Allowlisting
        // that phantom is precisely the wrong fix the scanner's own
        // dead-entry note warns about, so the literal is simply not created.
        other => ic_cdk::trap(&format!("start seam: not a start quorum: {other:?}")),
    }
}

/// TEST-ONLY (feature `testing`): record a controller-invariant observation in
/// a DEPLOYED canister (R6.0 acceptance 4).
///
/// The production path reaches `core::record_controller_invariant` only from
/// `refresh_controller_invariant`, which requires TWO successful management
/// `canister_status` calls — one against the Vault, which the Upgrader can read
/// only as its controller. Standing up the full closed ring under PocketIC just
/// to produce one observation would make the durability test depend on the ring
/// wiring rather than on durability, and a failure there would be reported as a
/// durability failure. This hook calls the SAME core function the production
/// seam calls, with the same arguments, so what survives the upgrade is a
/// genuinely production-shaped record.
#[cfg(feature = "testing")]
#[update]
fn record_controller_invariant_for_test(vault_ok: bool, upgrader_ok: bool, at_ns: u64) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    core::record_controller_invariant(vault_ok, upgrader_ok, at_ns);
}

/// TEST-ONLY (feature `testing`): append filler audit events to a DEPLOYED
/// canister, so the R6.0 regression can grow MemoryId 4 past the 10,000-event
/// cap of the removed backwards scan (R6.0 acceptance 2).
///
/// Batched by the caller: 10,000+ appends do not fit in one message's
/// instruction budget, and a single call that silently wrote fewer events than
/// asked would deflate the regression into passing below the cap — the exact
/// class of substitute-reading-stronger-than-it-is this campaign keeps
/// catching. The harness therefore drives it in bounded batches and asserts the
/// resulting `audit_len` against the cap it must exceed.
#[cfg(feature = "testing")]
#[update]
fn seed_audit_events_for_test(count: u32) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    core::seed_audit_events_for_test(count, ic_cdk::api::time());
}

/// TEST-ONLY (feature `testing`): total audit-event count in a DEPLOYED
/// canister, so the harness can prove the tail actually exceeded the cap rather
/// than assume its seeding worked.
#[cfg(feature = "testing")]
#[query]
fn audit_len_for_test() -> u64 {
    if core::require_member_public(&ic_cdk::caller()).is_err() {
        return 0;
    }
    core::audit_len_for_test()
}

/// TEST-ONLY (feature `testing`): inject candidate R6 refresh constants into a
/// DEPLOYED canister (S8B).
///
/// Not merely convenient — without it every S8B acceptance is VACUOUS in a
/// deployed canister. `INVARIANT_REFRESH_PARAMS` is `None` on Route 2, so the
/// endpoint refuses `NotRuled` before touching state, and a rate-limit
/// durability test across a real upgrade would be asserting that an inert
/// endpoint stayed inert. Production constants are untouched; the
/// feature-isolation suite asserts this symbol is absent from every release
/// Wasm.
///
/// Member-gated like every other hook here. That is a TEST-harness gate, not a
/// claim about the endpoint under test — `refresh_controller_invariant_now`
/// itself is permissionless, and the harness calls it as an arbitrary caller.
#[cfg(feature = "testing")]
#[update]
fn set_invariant_refresh_params_for_test(
    params: Option<stsh_custody_types::InvariantRefreshParams>,
) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    // Always an override: on a deployed canister `None` means "force the
    // UNRULED path" (condition 1 coverage post-pin), never "clear the
    // injection" — there is no reason for a harness to ask for the production
    // value it could simply not inject.
    core::inject_refresh_params_for_test(Some(params));
}

/// TEST-ONLY (feature `testing`): read the durable MemoryId 12 limiter state,
/// so the S7 P1-4-standard upgrade test can assert the WINDOW survived rather
/// than infer it from a refusal that might have had another cause.
#[cfg(feature = "testing")]
#[query]
fn refresh_ledger_for_test() -> Option<(Option<u64>, Option<u64>)> {
    if core::require_member_public(&ic_cdk::caller()).is_err() {
        return None;
    }
    let l = core::refresh_ledger_for_test();
    Some((l.last_accepted_at_ns, l.in_flight_since_ns))
}

#[cfg(feature = "testing")]
#[update]
fn corrupt_indexes_for_test() {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    core::clear_companion_indexes_for_test();
}

/// TEST-ONLY (feature `testing`): inject candidate C5/C7/C12 caps into a
/// DEPLOYED canister (W3 acceptance 13).
///
/// Acceptance 13 is specified "at C12 occupancy (parameter-injected)", and the
/// occupancy has to be real: the native `thread_local` hook cannot reach a Wasm
/// under PocketIC, so without this the acceptance can only be approximated in
/// process — which is what the §4 amendment rules inadmissible for the rollback
/// half and is no better here.
///
/// Brief §3 unchanged: the production constant stays `None` and the
/// feature-isolation suite asserts this symbol is absent from the release Wasm.
#[cfg(feature = "testing")]
#[update]
fn set_nonterminal_caps_for_test(caps: Option<stsh_custody_types::NonterminalCaps>) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    // RF-1: a DEPLOYED harness always OVERRIDES — `None` here means "force the
    // unruled path", never "clear the injection". A harness that wanted the
    // production value would simply not call this.
    core::inject_nonterminal_caps_for_test(Some(caps));
}

/// TEST-ONLY (feature `testing`): inject candidate C9 entry-rate parameters
/// into a DEPLOYED canister. The recovery plane's counterpart to the Vault's
/// `set_entry_rate_params_for_test`, added at S6.
///
/// The core injector has existed since S5B W4; only the INGRESS hook was
/// missing, which did not matter while C9 was `None` — the gate admitted
/// everything, so no harness ever needed to move it. S6 ruled C9 at 26 entry
/// events per member per rolling 24 h, and this plane's gate-A and gate-C
/// harnesses seed well past that from a single member, so without this hook
/// they are refused partway through and report truncated tables.
///
/// The Vault's half of §A/§C could suspend C9 and this one could not, which
/// would have left the recovery figures measured under a different regime than
/// the Vault's — the "substitute reading stronger than it is" failure this
/// campaign keeps catching. Both planes now suspend identically.
///
/// Production constants are untouched; the feature-isolation suite asserts this
/// symbol is absent from every release Wasm.
#[cfg(feature = "testing")]
#[update]
fn set_entry_rate_params_for_test(params: Option<stsh_custody_types::EntryRateParams>) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    // RF-1: a DEPLOYED harness always OVERRIDES — `None` here means "force the
    // unruled path", never "clear the injection". A harness that wanted the
    // production value would simply not call this.
    core::inject_entry_rate_for_test(Some(params));
}

#[cfg(feature = "testing")]
thread_local! {
    /// Instructions consumed by the most recent `approve_recovery` message, at
    /// the point its synchronous work completed (S5A M1 gate B).
    static LAST_APPROVE_INSTRUCTIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The same for the most recent `propose_recovery` (S5A M1 gate C,
    /// recovery-origin admission path).
    static LAST_PROPOSE_INSTRUCTIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// TEST-ONLY (feature `testing`): instructions consumed by ONE inline
/// commitment validation on the RECOVERY plane (S5A M1 gate C).
///
/// §C's budgets apply to both origin paths INDEPENDENTLY. Measuring the Vault
/// and asserting the recovery plane is similar would be exactly the substitute-
/// reading-stronger-than-it-is failure this campaign keeps catching.
#[cfg(feature = "testing")]
#[update]
fn measure_companion_validation_for_test() -> u64 {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    let before = ic_cdk::api::instruction_counter();
    core::companion_validate();
    ic_cdk::api::instruction_counter().saturating_sub(before)
}

/// TEST-ONLY (feature `testing`): read back the instruction count recorded by
/// the most recent `propose_recovery` (S5A M1 gate C). A query, for the same
/// reason as the approve readback: a fresh update call starts its own counter
/// at zero and cannot observe the previous message's total.
#[cfg(feature = "testing")]
#[query]
fn last_propose_instructions_for_test() -> u64 {
    if core::require_member_public(&ic_cdk::caller()).is_err() {
        return 0;
    }
    LAST_PROPOSE_INSTRUCTIONS.with(|c| c.get())
}

/// TEST-ONLY (feature `testing`): read back the instruction count recorded by
/// the most recent `approve_recovery` (S5A M1 gate B).
///
/// A QUERY, deliberately. Reading over a fresh update call would consume
/// instructions of its own and — worse — would be a second message whose own
/// counter starts at zero, so it could not observe the previous message's
/// total at all. The value lives in canister heap, which persists between
/// messages within a Wasm instance.
///
/// Member-gated like every other surface on this canister; unauthorized reads
/// get 0, indistinguishable from "nothing measured yet", which is the same
/// fail-closed shape the gated queries already use.
#[cfg(feature = "testing")]
#[query]
fn last_approve_instructions_for_test() -> u64 {
    if core::require_member_public(&ic_cdk::caller()).is_err() {
        return 0;
    }
    LAST_APPROVE_INSTRUCTIONS.with(|c| c.get())
}

/// TEST-ONLY (feature `testing`): instructions consumed by ONE recovery sweep
/// call, and how many records it reaped (S5A M1 gate A, spec §A — the RECOVERY
/// plane's half of "both canisters").
///
/// Returns both figures for the same reason the Vault's twin does: §A asks for
/// two separate symbols, `c_fixed_worst` and `c_record_worst`, and one total
/// cannot separate them. Measuring across occupancies and reading intercept and
/// slope does, and it exposes non-linearity if the marginal cost is not flat.
/// The reaped count is returned so a run cannot silently measure fewer records
/// than the fixture intended — the failure that would deflate every per-record
/// figure while looking healthy.
///
/// `now_ns_override` forces the due prefix rather than advancing the canister's
/// clock; a FIXTURE choice, recorded as one. The per-record reap work is
/// identical either way, since `now` only selects which prefix of the expiry
/// index is due.
#[cfg(feature = "testing")]
#[update]
fn measure_sweep_instructions_for_test(now_ns_override: u64, limit: u32) -> (u64, u32) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    let before = ic_cdk::api::instruction_counter();
    let reaped = core::sweep_expired_recovery_proposals(now_ns_override, limit as usize);
    let delta = ic_cdk::api::instruction_counter().saturating_sub(before);
    (delta, reaped.len() as u32)
}

/// TEST-ONLY (feature `testing`): inject candidate proposal-lifetime bounds and
/// a candidate sweep work limit (S5A M1 gate A) — the recovery plane's half.
///
/// Gate A is not merely inconvenient to measure without this, it is
/// unmeasurable: while `PROPOSAL_LIFETIME_BOUNDS` is `None` no recovery
/// proposal is ever assigned an expiry, so `RECOVERY_PROPOSAL_EXPIRY_INDEX` is
/// empty by construction and the sweep is provably vacuous
/// (`r3_recovery_sweep_is_vacuous_until_bounds_are_ruled`). `c_record_worst`
/// has no due record to be measured against, and a run at zero occupancy would
/// report a per-record cost of zero while appearing perfectly healthy.
///
/// Brief §3 unchanged: production constants stay `None`, candidate values reach
/// the code ONLY here, and the feature-isolation suite asserts this symbol is
/// absent from the release Wasm.
#[cfg(feature = "testing")]
#[update]
fn set_lifetime_params_for_test(
    bounds: Option<stsh_custody_types::ProposalLifetimeBounds>,
    sweep_limit: Option<u32>,
) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    // RF-1: a DEPLOYED harness always OVERRIDES — `None` here means "force the
    // unruled path", never "clear the injection". A harness that wanted the
    // production value would simply not call this.
    core::inject_lifetime_params_for_test(Some(bounds), Some(sweep_limit.map(|l| l as usize)));
}

/// TEST-ONLY (feature `testing`): clear the companion sentinel record (RF-7).
///
/// B3's property is that an ABSENT companion record is REJECTED rather than
/// silently defaulted — the pre-companion-deployment case, which the first cut
/// accepted whenever the active indexes happened to be empty. Proving it
/// through a real `post_upgrade` message boundary needs a way to produce the
/// absent state in a DEPLOYED canister; there is no production path to one, by
/// design.
#[cfg(feature = "testing")]
#[update]
fn clear_companion_state_for_test() {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    core::clear_companion_state_for_test();
}

/// TEST-ONLY (feature `testing`): arm or ("none") disarm the S5B W3 rotation
/// trap boundary.
///
/// This endpoint exists for the same reason `arm_governance_trap_for_test` does
/// on the Vault: `AMENDMENT_V8_S4_GOVERNANCE_ATOMICITY_V2` §2 rules that an
/// in-process Rust panic does not prove canister-state rollback and is not
/// acceptable evidence. Rollback on the rotation path must therefore be shown
/// inside a deployed Wasm under PocketIC, which needs an arming call.
///
/// Measured directly, and why an in-process test cannot substitute: outside a
/// canister there is no transaction, `catch_unwind` leaves every mutation in
/// place, and the membership write precedes the terminalization loop — so an
/// in-process "rollback" assertion observes an already-rotated membership.
#[cfg(feature = "testing")]
#[update]
fn arm_rotation_trap_for_test(point: String) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    core::arm_rotation_trap_for_test(&point);
}

/// TEST-ONLY (feature `testing`): arm the companion-WRITE trap boundary (RF-1).
///
/// Separate from the rotation trap because it guards a different property: not
/// "a multi-record loop rolls back", but "the index writes and their accounting
/// commit or roll back TOGETHER". W2 acceptance 11 had detection evidence and
/// no rollback evidence on either plane; this is the hook that lets the
/// rollback half run inside a deployed Wasm.
#[cfg(feature = "testing")]
#[update]
fn arm_companion_trap_for_test(point: String) {
    core::require_member_public(&ic_cdk::caller()).expect("member-only");
    core::arm_companion_trap_for_test(&point);
}

// ── DID drift lock (S2.1) ───────────────────────────────────────────────────
//
// `export_service!` must sit at crate scope, AFTER every endpoint, so it can
// see them all. The generated service is compared against the committed
// upgrader.did by `tests::did_types_match_the_real_rust_interface`. The
// pre-existing conformance test compared only the METHOD SET and was therefore
// blind to TYPE drift — which is exactly how `RecoveryProposal::expires_at_ns`
// reached the Rust interface without reaching the committed Candid.
candid::export_service!();

#[cfg(test)]
pub(crate) fn generated_did() -> String {
    __export_service()
}
