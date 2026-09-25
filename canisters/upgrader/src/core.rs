// =============================================================================
// STSH Custody Upgrader — recovery-plane core (L2)
// =============================================================================
//
// All durable state and every authorization/transition decision lives here,
// parameterized on caller / time / self-id so the whole state machine is
// exercisable from native unit tests. `lib.rs` is a thin ic-cdk shell: it
// resolves `ic_cdk::caller()` / `ic_cdk::api::time()` / `ic_cdk::id()`, calls
// these functions, performs the management-canister awaits the core plans,
// and feeds the results back through the `finish_*` entry points.
//
// Management-call seam (documented choice, no PocketIC needed): every
// inter-canister effect is split into a `*_begin`/plan step (all durable
// writes BEFORE the first await — brief invariant 4) and a `finish_*` step
// applied with the call's outcome. Tests drive both halves directly and
// simulate management-canister success/rejection; nothing else in the
// canister can issue a management call.
//
// MemoryIds (freeze §7; docs/MEMORY_ID_REGISTRY.md rows `upgrader` 0–4 — the
// COMPLETE namespace; a new MemoryId need is a freeze defect):
//   0 RECOVERY_MEMBERSHIP_CELL — durable MembershipState { epoch,
//      BootstrapRecord } (own recovery membership, fixed threshold 2, NOT
//      synced from the Vault — brief L2; governed rotation bumps the epoch)
//   1 RECOVERY_PROPOSALS     — proposal_id -> StoredProposal (recovery action
//      proposals AND membership-rotation proposals, epoch-stamped)
//   2 RECOVERY_APPROVALS     — seq -> ApprovalLogEntry (append-only)
//   3 UPGRADE_INTENTS        — IntentKey -> UpgradeIntent (the ONLY artifact
//      working store — see the byte-clearing rule below)
//   4 AUDIT_EVENTS           — seq -> UpgraderAuditEvent (append-only)
//
// ── Artifact byte-clearing rule (SSA L2-1; reconciles the freeze tension) ───
//
// The freeze's "nothing deletable/replaceable/prunable including via upgrade"
// and §3d's "artifact bytes cleared only after terminal evidence is durable"
// are reconciled per SSA's L2 ruling as: **reservations/intents METADATA are
// permanent; artifact working bytes are clearable exactly once, at
// terminalization, atomically**.
//
// WHAT "ATOMICALLY" MEANS HERE, stated precisely because the blanket phrasing
// ("bytes and terminal outcome always change in the same durable write") was
// FALSE for one of the two paths and is corrected at the SSA r3 return. The
// guarantee is NO INTERVENING MESSAGE BOUNDARY, which the two paths reach
// differently:
//
//   * `finish_intent` / the reconciliation core — ONE `put_intent` invocation.
//     The byte fields are cleared in the SAME invocation that records the
//     terminal outcome and drops the nonterminal index entry.
//   * `reap_linked_intent` (cancellation / expiry) — TWO ordered `put_intent`
//     invocations, sequenced AFTER the terminal proposal state is stored:
//     first the terminal outcome plus index release, then the byte clear. The
//     order is deliberate — terminal state must be durable BEFORE the evidence
//     goes.
//
// COUNTED IN LOGICAL PHASES, NOT STABLE WRITES — the distinction matters and an
// earlier revision got it wrong (SSA r4 return). A single `put_intent` is NOT
// one stable-map write: it inserts into `UPGRADE_INTENTS`, then `reindex_intent`
// inserts into or removes from `NONTERMINAL_INTENT_INDEX` and seals and stores
// `COMPANION_STATE` — up to THREE stable mutations per invocation. Counting raw
// writes would make both paths multi-write and obscure the property that
// actually holds, which is about ORDERING and MESSAGE SCOPE, not write counts.
//
// Both paths run to completion inside ONE message with no `await` anywhere
// between the invocations, so every mutation they make is transaction-atomic at
// message scope and a trap rolls back the whole set. No later message can
// observe an intent holding bytes that its accounting no longer counts, which is
// the property the byte limbs rely on.
//
// Concretely:
//   * artifact bytes live in EXACTLY ONE stable location: the UpgradeIntent
//     (MemoryId 3). Recovery proposals store hash-only action metadata — the
//     stored RecoveryAction::TriggerVaultUpgrade carries the two expected
//     hashes with EMPTY wasm_bytes/arg_bytes (the redacted representation);
//   * an OutcomeUnknown intent RETAINS its bytes (the evidence needed to
//     prove what was delivered);
//   * terminal intents NEVER retain bytes — released with no message boundary
//     between the release and the index removal, per the two paths above
//     (`finish_intent` and the reconciliation core in ONE `put_intent`
//     invocation; `reap_linked_intent` in TWO ordered invocations). No replay
//     or second terminalization can resurrect them (terminal intents are never
//     re-writable).
//
// Nothing else is deletable: proposals, approvals, audit events and intent
// metadata are append-only/permanent; there is no removal API on any map.
// OutcomeUnknown never returns to Pending; replay returns the prior result.
// =============================================================================

use candid::{CandidType, Principal};
use ic_stable_structures::{
    cell::Cell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::{Bound, Storable},
    DefaultMemoryImpl, StableBTreeMap,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cell::RefCell;
use stsh_custody_types::{
    callback_may_write, classify_start_reconcile, validate_bootstrap_quorum, ActionOutcome,
    BootstrapRecord, EvidenceRejection, InitValidationError, RecoveryAction, RecoveryError,
    RecoveryProposal, RecoverySummary, ReconcileTerminalOutcome, SettlementEvidenceConflict,
    SettlementRecord, StartIntent, StartObjectiveEvidence, StartReconcileDisposition,
    StartReconcileRejection, StartSettlementState, StartSourceState, UpgradeObjectiveEvidence,
    BOOTSTRAP_RECORD_SCHEMA_VERSION, GATE_SIZE_BOUND_BYTES, INITIAL_THRESHOLD,
    MAX_READ_PAGE_LIMIT, START_MAX_EVIDENCE_AGE_NS,
};

// ── Evidence freshness bound (SSA L2-2) ──────────────────────────────────────
//
// Ruled here, FLAGGED FOR SSA: reconciliation evidence must be fresh —
// `observed_at_ns` must lie within [intent.created_at_ns, now_ns] AND be no
// older than MAX_EVIDENCE_AGE_NS relative to the reconciliation time. The
// value is 24 hours: long enough for a 2-of-3 recovery quorum to convene
// with the Vault unavailable (the primary use case), short enough that the
// observation cannot silently span an unrelated intermediate canister state.
// A different operational tempo changes this constant, not the rule.
pub const MAX_EVIDENCE_AGE_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

// §S7 §4 directs that the start path REUSE this discipline "rather than
// re-derive" it. `START_MAX_EVIDENCE_AGE_NS` is the shared pin both directions
// read; this assertion makes the reuse STRUCTURAL rather than a claim in a
// comment. If either value is ever edited alone, the build fails here instead
// of the two disciplines silently splitting — which is the failure mode a
// duplicated constant always eventually reaches.
const _: () = assert!(MAX_EVIDENCE_AGE_NS == START_MAX_EVIDENCE_AGE_NS);

// ── MemoryIds (freeze §7 allocation — do not add to this list) ───────────────
const MEM_RECOVERY_MEMBERSHIP_CELL: MemoryId = MemoryId::new(0);
const MEM_RECOVERY_PROPOSALS: MemoryId = MemoryId::new(1);
const MEM_RECOVERY_APPROVALS: MemoryId = MemoryId::new(2);
const MEM_UPGRADE_INTENTS: MemoryId = MemoryId::new(3);
const MEM_AUDIT_EVENTS: MemoryId = MemoryId::new(4);
// S5B W2 (amended R3 item 10, 878d685e…): reclassified DERIVED → AUTHORITATIVE
// COMPANION. No longer reconstructed from UPGRADE_INTENTS (MemoryId 3) and no
// longer rebuilt at post_upgrade; maintained transactionally and validated
// against MemoryId 7.
const MEM_NONTERMINAL_INTENT_INDEX: MemoryId = MemoryId::new(5);
// S5B W2: likewise reclassified. Was a DERIVED expiry index over
// RECOVERY_PROPOSALS (MemoryId 1) rebuilt at post_upgrade; now authoritative.
const MEM_RECOVERY_PROPOSAL_EXPIRY_INDEX: MemoryId = MemoryId::new(6);
// S5B W2 — companion integrity state for MemoryIds 5 and 6. Registered in
// docs/MEMORY_ID_REGISTRY.md in this same change (W7).
const MEM_COMPANION_STATE: MemoryId = MemoryId::new(7);
// S5B W3 — bounded PENDING index over RECOVERY_PROPOSALS, keyed by proposal id.
//
// ── WHY THIS IS NOT MemoryId 6, AND WHY RE-UNIFYING IS FORBIDDEN ─────────────
//
// RATIFIED DEVIATION from the brief's letter (CTO, 2026-08-08). The brief says
// to replace the rotation scan with "the bounded index", meaning the existing
// expiry index. THAT WOULD BE A SILENT CORRECTNESS FAILURE WITH A DELAYED FUSE.
//
// `RECOVERY_PROPOSAL_EXPIRY_INDEX` (MemoryId 6) is keyed `(expires_at_ns, id)`
// and populated ONLY for proposals carrying an expiry. While
// `PROPOSAL_LIFETIME_BOUNDS` is `None` — which is its state until S6 rules the
// §10.5 constants — NO PROPOSAL EVER CARRIES ONE. The index is therefore
// vacuously empty, and rotation wired to it would:
//   * terminalize NOTHING,
//   * report SUCCESS,
//   * and pass every existing test,
// detonating only once S6 pins the lifetime constants — i.e. AFTER this work is
// reviewed, after SSA signs it, and after the deviation would have been
// forgotten.
//
// **Re-unifying these two indexes is FORBIDDEN while the lifetime bounds are
// unruled.** Not discouraged — forbidden. If a future change makes every
// proposal carry an expiry, unification becomes arguable, and at that point it
// needs its own ruling rather than a refactor. Until then the prohibition is
// enforced mechanically by
// `w3_rotation_must_not_be_wired_to_the_vacuous_expiry_index`, so the
// "simplification" breaks the build rather than merely contradicting a comment.
//
// Predicate is exactly `is_reapable()`, identical to the full scan it replaces,
// so `Executing` stays excluded and the in-flight carve-out and L2-7 are
// preserved unchanged.
const MEM_PENDING_RECOVERY_PROPOSAL_INDEX: MemoryId = MemoryId::new(8);
/// SSA BLOCKER 2 — C9 entry-rate ledger for the RECOVERY plane.
///
/// W4 landed the entry gate on the Vault only, leaving this plane's admission
/// and audited-rejection paths ungated — `MembershipRotationRejected` appended
/// directly, which is an unbounded caller-driven append into permanent history.
/// Closing only the Vault moves the exhaustion route rather than removing it,
/// the same reasoning that put the recovery plane in R3.8/R3.11.
const MEM_ENTRY_RATE_LEDGER: MemoryId = MemoryId::new(9);
/// SSA BLOCKER 1 (re-check) — NONTERMINAL recovery-proposal index.
///
/// The Pending-inclusive index and the C5/C7/C12 caps landed on the VAULT
/// ONLY. This plane had no caps lookup, no cap check, and no call before
/// either admission path — both ran from the C9 gate straight to allocation
/// and durable writes. Closing only the Vault moves the exhaustion route
/// rather than removing it, the same reasoning as R3.8/R3.11 and MemoryId 9.
///
/// WHY NOT MemoryId 8: `PENDING_RECOVERY_PROPOSAL_INDEX` is keyed by
/// `proposal_id` alone under the `is_reapable()` predicate — Pending ONLY. It
/// can answer neither "how many are open" (it excludes `Executing` and
/// `OutcomeUnknown`, both of which occupy a slot) nor "how many are open for
/// THIS member" (its key carries no proposer). Widening MemoryId 8 instead
/// would have broken W3: rotation's predicate must stay byte-identical to the
/// scan it replaced, or `Executing` proposals become reapable and the L2-7
/// in-flight carve-out silently dies. Two predicates, two indexes.
const MEM_NONTERMINAL_RECOVERY_PROPOSAL_INDEX: MemoryId = MemoryId::new(10);
/// R6.0 (spec gate, SSA_SPEC_GATE_GREEN_2026-08-06) — own stable cell for the
/// last controller-invariant observation.
///
/// WHY A CELL AND NOT THE AUDIT TRAIL. The observation was durable ONLY as an
/// `UpgraderAuditEventKind::ControllerInvariantObserved` entry in MemoryId 4,
/// and the live value was a HEAP mirror rebuilt at `post_upgrade` by scanning
/// that trail backwards under a 10,000-event cap. Both halves of that are
/// defects:
///
///   * SURVIVAL WAS A FUNCTION OF AUDIT-TAIL LENGTH. With more than the cap's
///     worth of events appended since the last observation, the backwards scan
///     ran off the end, the mirror rebuilt as `None`, and the PUBLIC
///     `get_controller_invariant` proof silently reverted to the fail-closed
///     `{false, false, 0}` — reporting "no evidence the ring is intact" for a
///     ring that was intact and observed. The audit record still existed; it
///     was simply out of reach. Nothing about the observation's validity
///     changed, only how much unrelated history had accumulated behind it.
///   * THE RECOVERY WAS A HISTORY WALK AT `post_upgrade`, which amended R3
///     item 10 clause (c) forbids outright, for the reason MemoryIds 7 and 9
///     exist: permanent history is not an allocation or recovery authority.
///     It evaded `w6_no_unbounded_iteration_over_permanent_history_upgrader`
///     only because it used keyed `get(&seq)` calls in a loop rather than
///     `.iter()`, which the textual classifier cannot see — so that lint's own
///     stated property ("`post_upgrade` performs NO read of the history maps
///     at all") was not actually true of this canister until R6.0 made it so.
///
/// The cell is written in the SAME synchronous call that appends the audit
/// event, so the durable record and the durable observation cannot diverge.
/// Recovery is a single bounded cell read that never touches MemoryId 4.
const MEM_LAST_CONTROLLER_INVARIANT_CELL: MemoryId = MemoryId::new(11);
/// S8B / R6 Option B — durable rate-limiter state for the PERMISSIONLESS
/// controller-invariant refresh.
///
/// DURABILITY IS A PINNED REQUIREMENT (R-3 acceptance criterion 3, and the CTO
/// addendum's condition 4 refuses a heap counter explicitly), for the same
/// reason MemoryIds 9 and 10 give: a heap counter clears on every upgrade, and
/// the party able to trigger an upgrade is the governed path itself — so a
/// resettable limiter is no limiter. An upgrade must not hand out a free burst.
///
/// Bounded by construction: two `Option<u64>` timestamps and a schema version,
/// rewritten in place, never appended. It holds no per-caller state at all —
/// the endpoint is permissionless, so a per-principal ledger would be an
/// unbounded map keyed by an attacker-chosen principal, which is the exhaustion
/// route rather than a defence against it. The single global interval is what
/// makes the bound hold against an unbounded caller set.
const MEM_INVARIANT_REFRESH_LEDGER: MemoryId = MemoryId::new(12);

type Mem = VirtualMemory<DefaultMemoryImpl>;
type MembershipCellStore = Cell<Vec<u8>, Mem>;

// ── Durable record shapes (L2-owned; the frozen shared types live in
//    stsh-custody-types and are NOT extended here) ────────────────────────────

/// Which id-namespace an upgrade intent lives in. Vault-originated intents
/// are keyed by the Vault's own proposal/request id (idempotency key);
/// recovery-originated intents by the recovery proposal id.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentOriginView {
    Vault,
    Recovery,
}

const TAG_VAULT: u8 = 0;
const TAG_RECOVERY: u8 = 1;

/// Stable-map key for UPGRADE_INTENTS: origin tag ++ big-endian id (9 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IntentKey {
    pub tag: u8,
    pub id: u64,
}

impl IntentKey {
    pub fn vault(id: u64) -> Self {
        IntentKey { tag: TAG_VAULT, id }
    }
    pub fn recovery(id: u64) -> Self {
        IntentKey { tag: TAG_RECOVERY, id }
    }
    pub fn origin(&self) -> IntentOriginView {
        match self.tag {
            TAG_VAULT => IntentOriginView::Vault,
            _ => IntentOriginView::Recovery,
        }
    }
}

impl Storable for IntentKey {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut b = [0u8; 9];
        b[0] = self.tag;
        b[1..].copy_from_slice(&self.id.to_be_bytes());
        Cow::Owned(b.to_vec())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        assert_eq!(bytes.len(), 9, "IntentKey: corrupt key length");
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes[1..]);
        IntentKey { tag: bytes[0], id: u64::from_be_bytes(id) }
    }
    const BOUND: Bound = Bound::Bounded { max_size: 9, is_fixed_size: true };
}

/// The MemoryId-0 cell content: the frozen BootstrapRecord plus the recovery
/// EPOCH (SSA L2-4). The epoch bumps on every governed membership rotation;
/// proposals are stamped with the epoch they were created in and approvals
/// from a prior epoch are rejected (stale-epoch fail-closed).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MembershipState {
    pub epoch: u64,
    pub record: BootstrapRecord,
}

/// A durable upgrade intent (freeze §3d) — the ONLY stable location that ever
/// holds artifact bytes (see the byte-clearing rule in the module header).
/// Recovery-originated intents are created in `Pending` at PROPOSAL time
/// (binding the delivered bytes durably before any approval/await exists);
/// Vault-originated intents are created directly in `Executing`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeIntent {
    pub id: u64,
    pub origin: IntentOriginView,
    pub expected_wasm_hash: Vec<u8>,
    pub expected_arg_hash: Vec<u8>,
    pub wasm_bytes: Option<Vec<u8>>,
    pub arg_bytes: Option<Vec<u8>>,
    pub outcome: ActionOutcome,
    pub created_at_ns: u64,
    pub terminal_at_ns: Option<u64>,
}

/// Append-only approval log entry (RECOVERY_APPROVALS).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApprovalLogEntry {
    pub proposal_id: u64,
    pub approver: Principal,
    pub at_ns: u64,
}

/// A governed membership-rotation proposal (SSA L2-4). Rotation is approved
/// by a quorum of the CURRENT membership; execution swaps the durable
/// membership atomically (validation fully precedes the single write
/// boundary) and bumps the recovery epoch.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RotationProposal {
    pub proposal_id: u64,
    pub epoch: u64,
    pub new_members: Vec<Principal>,
    /// R1.1 (V8 §3) — explicit proposer; see `RecoveryProposal::proposer`.
    pub proposer: Principal,
    /// Explicit, hash-bound approvals ONLY. Empty at creation (V8 §3).
    pub approvals: Vec<Principal>,
    pub threshold: u32,
    pub created_at_ns: u64,
    pub outcome: ActionOutcome,
    /// R3.1/R3.11 — absolute expiry; `None` while the §10.5 bounds are
    /// unruled. Rotation proposals were one of the two UNCAPPED classes the
    /// finding names explicitly.
    pub expires_at_ns: Option<u64>,
    /// R1.2 — ApprovalCommitmentV1 hash, written ONCE at creation.
    pub commitment_hash: Vec<u8>,
}

/// What lives in RECOVERY_PROPOSALS. Recovery-action proposals store the
/// frozen RecoveryProposal shape with the action in its REDACTED form
/// (hashes only, empty artifact vectors — SSA L2-1); rotation proposals are
/// L2-owned. Both carry the epoch they were created in.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum StoredProposal {
    Recovery { epoch: u64, proposal: RecoveryProposal },
    Rotation(RotationProposal),
}

/// Who authorized a reconciliation — recorded in the audit event (F-4-style
/// attribution: the recovery path records the approving member set).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReconcileAuthorityView {
    Vault,
    Recovery { approvers: Vec<Principal> },
}

/// Compact action tag for audit events (the full metadata lives on the
/// proposal; the audit event must stay bounded).
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryActionTag {
    TriggerVaultUpgrade,
    ReconcileVaultUpgrade,
    /// §S7 cell 4 — Upgrader → Vault stopped-recovery start.
    StartVault,
    /// §S7 cell 4 — settlement of an outcome-unknown Vault start.
    ReconcileVaultStart,
}

/// Typed reconciliation-evidence rejection classification (SSA L2-2/L2-3):
/// `stsh_custody_types::EvidenceRejection` (frozen there at 25ccbe7 — the
/// local enum that used to live here was deleted in favor of the shared
/// type, so callers receive the distinct classification ON THE WIRE via
/// `RecoveryError::EvidenceRejected`; the audit event remains the
/// attribution secondary surface).

/// Append-only audit event kinds (AUDIT_EVENTS). Reject detail is truncated
/// at construction so every event stays bounded.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum UpgraderAuditEventKind {
    RecoveryBootstrapped { member_count: u32, threshold: u32, vault: Principal },
    VaultUpgradeIntentRecorded {
        id: u64,
        origin: IntentOriginView,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
    },
    VaultUpgradeExecuted { id: u64, origin: IntentOriginView },
    VaultUpgradeOutcomeUnknown { id: u64, origin: IntentOriginView, reject_detail: String },
    VaultUpgradeReconciled {
        id: u64,
        origin: IntentOriginView,
        outcome: ReconcileTerminalOutcome,
        authority: ReconcileAuthorityView,
    },
    /// A reconciliation was REJECTED — the typed evidence classification
    /// (SSA L2-2) that the frozen RecoveryError cannot carry on the wire.
    VaultUpgradeReconcileRejected {
        id: u64,
        reason: EvidenceRejection,
        authority: ReconcileAuthorityView,
    },
    RecoveryProposalCreated {
        proposal_id: u64,
        proposer: Principal,
        action: RecoveryActionTag,
    },
    RecoveryApprovalRecorded { proposal_id: u64, approver: Principal },
    RecoveryExecutionStarted { proposal_id: u64 },
    RecoveryProposalTerminal { proposal_id: u64, outcome: ActionOutcome },
    MembershipRotationProposed { proposal_id: u64, proposer: Principal, member_count: u32 },
    /// A rotation proposal rejected at proposal time — the shared validator's
    /// exact reason (duplicate / anonymous / too few / counterpart).
    MembershipRotationRejected { proposer: Principal, reason: InitValidationError },
    MembershipRotated {
        proposal_id: u64,
        new_epoch: u64,
        member_count: u32,
        approvers: Vec<Principal>,
    },
    /// A Pending recovery trigger proposal AND its linked intent
    /// terminalized Failed at rotation time: the proposal belongs to a
    /// pre-rotation epoch and can never execute, so both halves of the
    /// durable record move to terminal Failed in the SAME transaction —
    /// never a stuck-Pending proposal beside a Failed intent (SSA L2-7).
    /// The event ties proposal id ↔ intent id; intent bytes are cleared
    /// atomically with the transition.
    StaleIntentTerminalized { proposal_id: u64, intent_id: u64, epoch: u64 },
    /// A Pending proposal with no linked intent (reconcile / rotation)
    /// terminalized Failed at rotation time (SSA L2-7): after any rotation,
    /// no stuck-Pending proposals remain.
    StaleProposalTerminalized { proposal_id: u64, epoch: u64 },
    ControllerInvariantObserved { vault_controllers_ok: bool, upgrader_controllers_ok: bool },

    // ── §S7 start settlement (cell 4) ────────────────────────────────────────
    /// §2 — the durable start-intent was recorded, BEFORE the first `await`.
    VaultStartIntentRecorded { proposal_id: u64, target: Principal, epoch: u64 },
    /// §3a — observed success in the reply callback: `Executing → Executed`.
    /// Terminal, and carries NO `SettlementRecord`: no §4 evidence existed.
    VaultStartExecuted { proposal_id: u64 },
    /// §3a E1 — transport rejection or any reply that does not objectively
    /// establish success: `Executing → OutcomeUnknown`, IN THE SAME MESSAGE.
    /// Never blindly `Failed` (acceptance 1).
    VaultStartOutcomeUnknown { proposal_id: u64, reject_detail: String },
    /// §3a E2 — the post-upgrade sweep promoted a durably-`Executing` start to
    /// `OutcomeUnknown`. Takes NO evidence, writes NO terminal outcome,
    /// releases NO lock, and is idempotent (acceptance 12).
    VaultStartSweptToUnknown { proposal_id: u64 },
    /// §5 — a terminal settlement from objective evidence.
    VaultStartSettled {
        proposal_id: u64,
        outcome: ReconcileTerminalOutcome,
        authority: ReconcileAuthorityView,
    },
    /// §3c.3 — a late callback was FENCED.
    ///
    /// DECLARED DEVIATION, carried from V3 §3c.3 and independently concurred by
    /// the project SSA: SSA's C1 remediation asked acceptance to prove "zero
    /// state/audit/lock change" after a delayed callback. Zero STATE and zero
    /// LOCK change are delivered unconditionally; this departs on AUDIT only,
    /// appending exactly one bounded event, because a silently fenced callback
    /// makes the fence unobservable in production — an operator would have no
    /// way to know the hazard fired, and a fence that leaves no trace cannot be
    /// distinguished from a fence that never engaged.
    ///
    /// BOUNDED BY CONSTRUCTION, not by a cap: §2 pins AT MOST ONE outstanding
    /// `start_canister` call per proposal, so at most one fencing event per
    /// proposal can ever be appended. It is NOT caller-driven — no external
    /// party can provoke a second — so it does not reproduce the C2 growth
    /// route. Acceptance 11 asserts the bound.
    LateCallbackFenced { proposal_id: u64, observed_state: ActionOutcome },
    /// §7d.1 — the FIRST §4-valid semantic discordance against a settled
    /// proposal. AT MOST ONE PER PROPOSAL, EVER; every subsequent discordance
    /// appends nothing and writes nothing.
    ///
    /// The append and the `conflict_recorded: false → true` transition occur in
    /// ONE ATOMIC DURABLE TRANSITION (§0b) — same synchronous message
    /// execution, no `await` and no message boundary between them.
    SettlementEvidenceConflictRecorded { conflict: SettlementEvidenceConflict },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgraderAuditEvent {
    pub seq: u64,
    pub at_ns: u64,
    pub kind: UpgraderAuditEventKind,
}

/// Bounded audit page for `get_upgrader_audit_events` (freeze §5: gated,
/// bounded, `{cursor, limit}`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditEventsPage {
    pub events: Vec<UpgraderAuditEvent>,
    pub next_cursor: Option<u64>,
}

/// Status view for `get_upgrade_status` (freeze §5: gated). Never carries
/// artifact bytes.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeStatusView {
    pub id: u64,
    pub origin: IntentOriginView,
    pub expected_wasm_hash: Vec<u8>,
    pub expected_arg_hash: Vec<u8>,
    pub outcome: ActionOutcome,
    pub created_at_ns: u64,
    pub terminal_at_ns: Option<u64>,
    /// True while the intent still holds the delivered artifact bytes (i.e.
    /// no terminal evidence is durable yet).
    pub artifact_bytes_held: bool,
}

/// Result of `trigger_vault_upgrade` — replay of an already-recorded request
/// id returns the PRIOR outcome and issues no new call (brief invariant 4).
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct TriggerUpgradeResult {
    pub outcome: ActionOutcome,
}

// ── Planned effects handed to the ic-cdk shell ───────────────────────────────

/// A management `install_code` the shell must issue (upgrade mode ONLY,
/// inline-only — freeze §3c/§3d). The durable intent already exists (in
/// `Executing`) when this is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPlan {
    pub key: IntentKey,
    pub target: Principal,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
}

/// What an `approve_recovery` quorum decided the shell must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryExecution {
    /// Issue the install, then `finish_intent` + `recovery_finish_trigger`.
    Trigger { proposal_id: u64, plan: InstallPlan },
    /// Apply the reconciliation core (synchronous — no inter-canister call;
    /// this is why the 2-of-3 fallback works with the Vault unavailable),
    /// then `recovery_finish_reconcile`.
    Reconcile {
        proposal_id: u64,
        intent_id: u64,
        evidence: Box<UpgradeObjectiveEvidence>,
        approvers: Vec<Principal>,
    },
    /// §S7 cell 4 — issue `start_canister` against the Vault, then
    /// `finish_start`. The §2 start-intent and durable `Executing` ALREADY
    /// EXIST when this is returned: both were written before this value was
    /// constructed, and this value is the only way to reach the `await`.
    ///
    /// `target` is carried here having been read from DURABLE MEMBERSHIP, not
    /// from the action — `RecoveryAction::StartVault` has no target field to
    /// read (§1, R4.4).
    Start { proposal_id: u64, target: Principal },
    /// §S7 cell 4 — apply the start-settlement core. SYNCHRONOUS: no
    /// inter-canister call, which is exactly why the 2-of-3 fallback works with
    /// the Vault unavailable.
    ReconcileStart {
        proposal_id: u64,
        target_proposal_id: u64,
        evidence: Box<StartObjectiveEvidence>,
        approvers: Vec<Principal>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApproveOutcome {
    /// Approval recorded; quorum not yet reached.
    Recorded,
    /// This call reached quorum and owns the execution.
    Execute(RecoveryExecution),
    /// This call reached quorum on a membership rotation; the rotation was
    /// executed atomically in-message (no inter-canister call exists).
    RotationExecuted { new_epoch: u64 },
}

// ── Storage ──────────────────────────────────────────────────────────────────

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// MemoryId 0 — durable membership state: epoch + recovery bootstrap
    /// record (members, threshold, counterpart Vault). Written at init and
    /// ONLY by a quorum-approved rotation; re-validated at post_upgrade.
    static RECOVERY_MEMBERSHIP_CELL: RefCell<MembershipCellStore> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_RECOVERY_MEMBERSHIP_CELL)),
            Vec::new(),
        ).expect("RECOVERY_MEMBERSHIP_CELL: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 1 — recovery + rotation proposals (append-only; outcomes
    /// mutate in place along the legal lifecycle only).
    static RECOVERY_PROPOSALS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_RECOVERY_PROPOSALS)))
    );

    /// MemoryId 2 — append-only approval log.
    static RECOVERY_APPROVALS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_RECOVERY_APPROVALS)))
    );

    /// MemoryId 3 — durable upgrade intents (freeze §3d; sole artifact store).
    static UPGRADE_INTENTS: RefCell<StableBTreeMap<IntentKey, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_UPGRADE_INTENTS)))
    );

    /// MemoryId 5 — R3.9 nonterminal-intent index: `IntentKey -> ()`.
    ///
    /// `nonterminal_intent_in_flight` scanned the ENTIRE intent map, decoding
    /// every intent on every call, on the single-flight authorization path.
    /// Terminal intents are never removed, so that scan grew without bound —
    /// the instruction-exhaustion half of CUST-SSA-003. This index holds ONLY
    /// nonterminal intents, and the single-flight invariant caps it at one, so
    /// the check is bounded by the invariant rather than by history.
    static NONTERMINAL_INTENT_INDEX: RefCell<StableBTreeMap<IntentKey, (), Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NONTERMINAL_INTENT_INDEX))
        ));

    /// MemoryId 8 — S5B W3 bounded Pending index: `proposal_id -> ()`.
    /// An authoritative companion like the others: maintained transactionally
    /// and covered by MemoryId 7's accounting.
    static PENDING_RECOVERY_PROPOSAL_INDEX: RefCell<StableBTreeMap<u64, (), Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PENDING_RECOVERY_PROPOSAL_INDEX))
        ));

    /// MemoryId 9 — SSA BLOCKER 2: durable C9 entry-rate ledger, recovery plane.
    /// Durable for the same pinned reason as the Vault's: a heap counter clears
    /// on upgrade, and the party who can trigger an upgrade is the governed
    /// path itself, so a resettable bound is no bound.
    static ENTRY_RATE_LEDGER: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ENTRY_RATE_LEDGER)),
            Vec::new(),
        ).expect("ENTRY_RATE_LEDGER: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 7 — S5B W2 companion integrity state for MemoryIds 5 and 6.
    /// Written in the same synchronous transaction as every companion
    /// mutation; never reconstructed from the histories it guards.
    static COMPANION_STATE: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_COMPANION_STATE)),
            Vec::new(),
        ).expect("COMPANION_STATE: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 6 — R3.8/R3.11 expiry index: `(expires_at_ns, proposal_id) -> ()`.
    ///
    /// Ordered by expiry first so the sweep reads a bounded PREFIX of due
    /// proposals rather than scanning. The recovery plane gets the same
    /// treatment as the Vault because the finding names rotation and reconcile
    /// proposals as UNCAPPED — closing only the Vault would move the
    /// exhaustion route rather than remove it.
    static RECOVERY_PROPOSAL_EXPIRY_INDEX: RefCell<StableBTreeMap<(u64, u64), (), Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_RECOVERY_PROPOSAL_EXPIRY_INDEX))
        ));

    /// MemoryId 10 — SSA BLOCKER 1: nonterminal recovery-proposal index,
    /// `(proposer, proposal_id) -> ()`.
    ///
    /// Authoritative companion, covered by MemoryId 7's accounting and seal.
    /// Keyed proposer-first so the global count is `len()` (O(1)) and the
    /// per-member count is a contiguous range — both bounded-active-set reads,
    /// never a history scan.
    ///
    /// PREDICATE, stated because choosing wrong type-checks (§3.6): membership
    /// is `!outcome.is_terminal()` — Pending, Executing AND OutcomeUnknown.
    /// NOT `holds_single_flight()` (excludes Pending) and NOT `is_reapable()`
    /// (Pending only). The caps bound how many proposals are OPEN, and a
    /// Pending proposal is open; counting the single-flight indexes is exactly
    /// how the Vault defect shipped.
    static NONTERMINAL_RECOVERY_PROPOSAL_INDEX:
        RefCell<StableBTreeMap<(Principal, u64), (), Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NONTERMINAL_RECOVERY_PROPOSAL_INDEX))
        ));

    /// MemoryId 4 — append-only audit events.
    static AUDIT_EVENTS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_AUDIT_EVENTS)))
    );

    /// MemoryId 11 — R6.0: the last controller-invariant observation, in its
    /// own bounded cell. Rewritten in place, never appended; there is NO heap
    /// mirror of it, deliberately (see `query_controller_invariant`).
    static LAST_CONTROLLER_INVARIANT_CELL: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_LAST_CONTROLLER_INVARIANT_CELL)),
            Vec::new(),
        ).expect("LAST_CONTROLLER_INVARIANT_CELL: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 12 — S8B rate-limiter state for the permissionless refresh.
    /// Bounded cell, rewritten in place. No per-caller state (see the MemoryId
    /// declaration for why that is load-bearing, not an omission).
    static INVARIANT_REFRESH_LEDGER: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_INVARIANT_REFRESH_LEDGER)),
            Vec::new(),
        ).expect("INVARIANT_REFRESH_LEDGER: Cell::init failed — stable memory corrupt")
    );

    // Heap mirrors of durable state (rebuilt at init/post_upgrade/rotation).
    static RECOVERY_MEMBERS: RefCell<Vec<Principal>> = const { RefCell::new(Vec::new()) };
    static RECOVERY_THRESHOLD: RefCell<u32> = const { RefCell::new(0) };
    static RECOVERY_EPOCH: RefCell<u64> = const { RefCell::new(0) };
    static VAULT: RefCell<Option<Principal>> = const { RefCell::new(None) };
}

// ── Membership state (bootstrap cell) ────────────────────────────────────────

fn store_membership(state: &MembershipState) {
    let bytes = candid::encode_one(state).expect("MembershipState encodes");
    RECOVERY_MEMBERSHIP_CELL.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("RECOVERY_MEMBERSHIP_CELL: stable write failed")
    });
    RECOVERY_MEMBERS.with(|m| *m.borrow_mut() = state.record.members.clone());
    RECOVERY_THRESHOLD.with(|t| *t.borrow_mut() = state.record.threshold);
    RECOVERY_EPOCH.with(|e| *e.borrow_mut() = state.epoch);
    VAULT.with(|v| *v.borrow_mut() = Some(state.record.counterpart));
}

/// Decode + re-validate the durable membership state. Fail-closed: any
/// corruption, schema drift, or validation failure is a trap, never a
/// default. Post-upgrade revalidation of the membership cell is the stale
/// recovery set's last line of defense (SSA L2-4).
fn load_membership() -> MembershipState {
    let bytes = RECOVERY_MEMBERSHIP_CELL.with(|c| c.borrow().get().clone());
    let state: MembershipState = candid::decode_one(&bytes).unwrap_or_else(|_| {
        ic_cdk::trap(
            "RECOVERY_MEMBERSHIP_CELL: undecodable membership state — refusing to resume \
             with unverifiable recovery membership",
        )
    });
    if state.record.schema_version != BOOTSTRAP_RECORD_SCHEMA_VERSION {
        ic_cdk::trap("RECOVERY_MEMBERSHIP_CELL: bootstrap record schema version mismatch");
    }
    validate_bootstrap_quorum(
        &state.record.members,
        state.record.threshold,
        &state.record.counterpart,
    )
    .unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "RECOVERY_MEMBERSHIP_CELL: durable record failed revalidation: {e}"
        ))
    });
    // S6 — the ruled maximum is revalidated on the DURABLE record too, not only
    // at the paths that write it. A record that predates the maximum, or that
    // reached memory some other way, must not be quietly honoured.
    stsh_custody_types::check_recovery_roster_size(state.record.members.len()).unwrap_or_else(
        |e| {
            ic_cdk::trap(&format!(
                "RECOVERY_MEMBERSHIP_CELL: durable record holds {} members, above \
                 the ruled MAX_RECOVERY_MEMBERS of {}",
                e.requested, e.maximum
            ))
        },
    );
    state
}

/// Init (called from `#[init]`). Validates via the SHARED
/// `validate_bootstrap_quorum` (threshold exactly 2, distinct non-anonymous
/// members, counterpart non-anonymous and not a member), durably records the
/// recovery membership at epoch 0 — the Upgrader's OWN membership, never
/// synced from the Vault — and appends the bootstrap audit event.
pub fn init(args: stsh_custody_types::UpgraderInitArgs, now_ns: u64) {
    validate_bootstrap_quorum(&args.recovery_members, args.threshold, &args.vault)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("init: {e}")));
    // S6 / CTO_NOTE_S5A §5 — MAX_RECOVERY_MEMBERS = 9, production-enforced at
    // the install path. Enforced independently of the Vault's maximum rather
    // than inherited from it, because recovery keeps its OWN durable membership
    // and is never synced from the Vault; a bound that arrived by inheritance
    // would silently stop applying the moment that independence was exercised.
    stsh_custody_types::check_recovery_roster_size(args.recovery_members.len()).unwrap_or_else(
        |e| {
            ic_cdk::trap(&format!(
                "init: {} recovery members exceeds the ruled MAX_RECOVERY_MEMBERS \
                 of {} — every V15 quota is derived at a nine-member roster",
                e.requested, e.maximum
            ))
        },
    );
    // SSA BLOCKER 3 — companion record written at fresh install; absence
    // thereafter traps rather than defaulting.
    companion_init();
    let member_count = args.recovery_members.len() as u32;
    let threshold = args.threshold;
    let vault = args.vault;
    store_membership(&MembershipState {
        epoch: 0,
        record: BootstrapRecord {
            schema_version: BOOTSTRAP_RECORD_SCHEMA_VERSION,
            members: args.recovery_members,
            threshold,
            counterpart: vault,
        },
    });
    append_audit(
        now_ns,
        UpgraderAuditEventKind::RecoveryBootstrapped { member_count, threshold, vault },
    );
}

/// Post-upgrade (called from `#[post_upgrade]`). NO pre_upgrade anywhere:
/// every durable write is current at all times, so there is nothing to
/// checkpoint. Fail-closed sentinel gate: an undecodable/invalid membership
/// cell traps; the canister never resumes on unverifiable membership.
pub fn post_upgrade(now_ns: u64) {
    let state = load_membership();
    RECOVERY_MEMBERS.with(|m| *m.borrow_mut() = state.record.members);
    RECOVERY_THRESHOLD.with(|t| *t.borrow_mut() = state.record.threshold);
    RECOVERY_EPOCH.with(|e| *e.borrow_mut() = state.epoch);
    VAULT.with(|v| *v.borrow_mut() = Some(state.record.counterpart));
    // VALIDATE the single-flight invariant against the AUTHORITATIVE
    // companion (SSA L2-5). The nonterminal-intent index is not re-derived
    // from `UPGRADE_INTENTS` here or anywhere: under amended R3 item 10 the
    // companion AUTHORIZES active membership, history establishes existence
    // and immutable terminal outcomes, and neither rebuilds the other.
    // `revalidate_single_flight` validates and traps; it does not repair.
    revalidate_single_flight();
    // §S7 §3a E2 — the post-upgrade sweep, in BOTH canisters' `post_upgrade`
    // (release condition 1). It runs AFTER the fail-closed validation above:
    // promoting proposals on state this canister has not yet proved
    // trustworthy would be a write ahead of the sentinel gate. It takes no
    // evidence, writes no terminal outcome and releases no lock, so it cannot
    // settle anything — it only moves callback-writable proposals to the state
    // that demands objective evidence.
    sweep_executing_starts_to_unknown(now_ns);
    // R6.0 — NOTE WHAT IS ABSENT. There is no controller-invariant rebuild step
    // here any more. The observation lives in its own cell (MemoryId 11) and is
    // read on demand by `query_controller_invariant`, so `post_upgrade` neither
    // reconstructs it nor touches MemoryId 4. Re-adding a rebuild would restore
    // both defects at once: survival coupled to audit-tail length, and a
    // history walk at `post_upgrade`.
}

// ── R6.0 — durable controller-invariant observation (MemoryId 11) ────────────

/// The durable form of a controller-invariant observation.
///
/// Carries its own `schema_version` for the same reason the bootstrap and
/// companion records do: an undecodable or unrecognised record must fail
/// CLOSED rather than be reinterpreted. This type is internal to the recovery
/// plane's storage — it is NOT part of any endpoint signature, so it adds no
/// Candid surface. The PUBLIC shape stays the frozen
/// `stsh_custody_types::ControllerInvariant`, unchanged.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastControllerInvariant {
    pub schema_version: u32,
    pub vault_controllers_ok: bool,
    pub upgrader_controllers_ok: bool,
    pub observed_at_ns: u64,
}

/// Schema version of the MemoryId 11 record. Deliberately its own constant,
/// distinct from `BOOTSTRAP_RECORD_SCHEMA_VERSION` and
/// `COMPANION_STATE_SCHEMA_VERSION`: these three records version
/// independently, and sharing one number is how a bump for one silently
/// invalidates the others.
pub const LAST_CONTROLLER_INVARIANT_SCHEMA_VERSION: u32 = 1;

/// Read the durable observation. `None` means "never observed" — the
/// legitimate pre-first-observation state, which the caller renders as the
/// fail-closed `{false, false, 0}`.
///
/// An empty cell is that absence. An undecodable or wrong-version cell is NOT:
/// it is corruption or schema drift, and it TRAPS rather than degrading to
/// `None`. Degrading would turn a corrupt durable state into the same answer
/// as a fresh install, which is precisely the silent-substitution failure the
/// fail-closed sentinels elsewhere on this canister exist to prevent.
fn invariant_load() -> Option<LastControllerInvariant> {
    let raw = LAST_CONTROLLER_INVARIANT_CELL.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        return None;
    }
    let rec: LastControllerInvariant = candid::decode_one(&raw).unwrap_or_else(|_| {
        ic_cdk::trap("LAST_CONTROLLER_INVARIANT_CELL: undecodable — fail closed")
    });
    if rec.schema_version != LAST_CONTROLLER_INVARIANT_SCHEMA_VERSION {
        ic_cdk::trap(&format!(
            "LAST_CONTROLLER_INVARIANT_CELL: schema version {} is not the expected {} \
             — fail closed",
            rec.schema_version, LAST_CONTROLLER_INVARIANT_SCHEMA_VERSION
        ));
    }
    Some(rec)
}

// ── S8B / R6 Option B — permissionless refresh rate limiter (MemoryId 12) ────

/// Durable limiter state. Two timestamps, no per-caller map (see
/// `MEM_INVARIANT_REFRESH_LEDGER`).
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct InvariantRefreshLedger {
    pub schema_version: u32,
    /// When the last refresh was ACCEPTED — set at charge time, not at
    /// completion. Charging on admission is what makes the allowance
    /// single-spend: a burst that all passed the check before any of them
    /// finished would otherwise each see an unspent allowance.
    pub last_accepted_at_ns: Option<u64>,
    /// Set before the first `await`, cleared on return. Non-`None` means a
    /// refresh is between its two management status calls.
    pub in_flight_since_ns: Option<u64>,
}

/// Schema version of the MemoryId 12 record. Its own constant, distinct from
/// the bootstrap, companion and MemoryId 11 versions — four independently
/// versioned records; one shared number is how a bump for one silently
/// invalidates the others.
pub const INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION: u32 = 1;

/// What `refresh_charge` returns on success: the admission is already durable.
/// Deliberately carries no capability — it is a receipt, not a token, so it
/// cannot be replayed to skip a second charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshCharge {
    pub accepted_at_ns: u64,
}

fn refresh_ledger_load() -> InvariantRefreshLedger {
    let raw = INVARIANT_REFRESH_LEDGER.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        // Never charged. Distinct from corrupt, exactly as MemoryId 11 treats
        // its empty cell: absence is the legitimate fresh-install state.
        return InvariantRefreshLedger {
            schema_version: INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION,
            last_accepted_at_ns: None,
            in_flight_since_ns: None,
        };
    }
    let rec: InvariantRefreshLedger = candid::decode_one(&raw)
        .unwrap_or_else(|_| ic_cdk::trap("INVARIANT_REFRESH_LEDGER: undecodable — fail closed"));
    if rec.schema_version != INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION {
        ic_cdk::trap(&format!(
            "INVARIANT_REFRESH_LEDGER: schema version {} is not the expected {} — fail closed",
            rec.schema_version, INVARIANT_REFRESH_LEDGER_SCHEMA_VERSION
        ));
    }
    rec
}

fn refresh_ledger_store(l: &InvariantRefreshLedger) {
    let bytes = candid::encode_one(l).expect("InvariantRefreshLedger encodes");
    INVARIANT_REFRESH_LEDGER.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("INVARIANT_REFRESH_LEDGER: stable write failed")
    });
}

/// The three R6 constants, with the same test-injection seam every other
/// Route-2 parameter uses. Production value is `None` until the A1 pin lands.
pub fn refresh_params() -> Option<stsh_custody_types::InvariantRefreshParams> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_REFRESH_PARAMS.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::INVARIANT_REFRESH_PARAMS
}

/// Admit or refuse one permissionless refresh, and — on admission — make the
/// charge DURABLE before the caller issues any management call.
///
/// ORDER IS THE MECHANISM (addendum condition 3). Every refusal path returns
/// having written nothing and appended nothing; the admission path writes the
/// ledger before returning, so the charge is committed at the caller's first
/// `await` and a concurrent second caller cannot see an unspent allowance. A
/// trap anywhere in the message rolls the write back with it, which is the
/// correct outcome: no refresh happened, so no allowance was spent.
///
/// While the constants are unruled this returns `NotRuled` **before touching
/// any state** (addendum condition 1) — the endpoint is inert, not merely
/// permissive, and the update-path seam keeps the public proof exactly as fresh
/// as it is today.
pub fn refresh_charge(
    now_ns: u64,
) -> Result<RefreshCharge, stsh_custody_types::InvariantRefreshRefusal> {
    use stsh_custody_types::InvariantRefreshRefusal as R;

    // Condition 1 — hard gate, first, before any read or write.
    let Some(params) = refresh_params() else { return Err(R::NotRuled) };

    let mut ledger = refresh_ledger_load();

    // In-flight collapse (criterion 2). The marker is RECLAIMED after
    // `min_interval_ns`, because a trap AFTER the first await commits the
    // marker and returns no reply — without a reclaim the endpoint would wedge
    // permanently on a single failed call. The reclaim reuses a RULED constant
    // rather than inventing a second timeout: it can never fire earlier than
    // the rate limit would refuse anyway, so it grants nothing.
    if let Some(since) = ledger.in_flight_since_ns {
        if now_ns.saturating_sub(since) < params.min_interval_ns {
            return Err(R::AlreadyInFlight);
        }
    }

    // Rate limit (criterion 1). Saturating throughout: a clock that moved
    // backwards must refuse, never wrap into a free window.
    if let Some(last) = ledger.last_accepted_at_ns {
        let earliest = last.saturating_add(params.min_interval_ns);
        if now_ns < earliest {
            return Err(R::TooSoon { retry_after_ns: earliest });
        }
    }

    // Staleness. No observation yet = maximally stale, so the first refresh is
    // always permitted; that is the case the public proof most needs served.
    if let Some(obs) = invariant_load() {
        let age_ns = now_ns.saturating_sub(obs.observed_at_ns);
        if age_ns < params.max_age_ns {
            return Err(R::NotStale { age_ns });
        }
    }

    ledger.last_accepted_at_ns = Some(now_ns);
    ledger.in_flight_since_ns = Some(now_ns);
    refresh_ledger_store(&ledger);
    Ok(RefreshCharge { accepted_at_ns: now_ns })
}

/// Clear the in-flight marker after the management calls have returned.
///
/// Deliberately does NOT touch `last_accepted_at_ns`: the allowance was spent
/// at admission and must stay spent whether the observation succeeded or not.
/// Rolling it back on failure would let a caller retry for free by arranging
/// for the status calls to fail — turning a failed refresh into an unlimited
/// one, which is the cycle-drain route criterion 1 closes.
pub fn refresh_release(_charge: RefreshCharge) {
    let mut ledger = refresh_ledger_load();
    ledger.in_flight_since_ns = None;
    refresh_ledger_store(&ledger);
}

fn invariant_store(rec: &LastControllerInvariant) {
    let bytes = candid::encode_one(rec).expect("LastControllerInvariant encodes");
    LAST_CONTROLLER_INVARIANT_CELL.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("LAST_CONTROLLER_INVARIANT_CELL: stable write failed")
    });
}

/// TEST-ONLY (`test` or feature `testing`): append `count` filler audit events,
/// so the R6.0 beyond-SCAN_CAP regression can drive MemoryId 4 past the 10,000
/// events the removed backwards scan was capped at.
///
/// WHY A HOOK AND NOT REAL TRAFFIC. Producing 10,000+ events through the
/// governed paths would take 10,000+ quorum-approved operations, each C9-gated;
/// the property under test is about audit-tail LENGTH alone, and nothing about
/// how the bytes got there changes it. The filler is a real `append_audit` call
/// writing real encoded events at real sequence numbers — the same map, the
/// same encoding, the same growth — not a fabricated `len()`.
///
/// It deliberately appends a kind that is NOT `ControllerInvariantObserved`, so
/// the seeded tail can only ever BURY an observation, never supply one.
#[cfg(any(test, feature = "testing"))]
pub fn seed_audit_events_for_test(count: u32, now_ns: u64) {
    for _ in 0..count {
        append_audit(
            now_ns,
            UpgraderAuditEventKind::MembershipRotationRejected {
                proposer: Principal::anonymous(),
                reason: stsh_custody_types::InitValidationError::AnonymousSigner,
            },
        );
    }
}

/// Test-only: remove every audit event, producing a state in which any
/// audit-derived recovery of the controller-invariant observation MUST fail.
/// That is the point: a rebuild-from-history implementation survives a
/// raised cap, but it cannot survive an empty trail.
///
/// No `.iter()` — drains via `first_key_value` + `remove`. The W6 lint is
/// textual and scans this whole region regardless of `cfg`, and a test helper
/// is not a reason to teach the lint an exception.
#[cfg(test)]
pub fn erase_audit_trail_for_test() {
    AUDIT_EVENTS.with(|a| {
        let mut map = a.borrow_mut();
        while let Some((seq, _)) = map.first_key_value() {
            map.remove(&seq);
        }
    });
}

/// Test-only: write raw bytes into the MemoryId 11 cell, so the fail-closed
/// decode and schema-version gates can be exercised natively. There is no
/// production path to a corrupt cell, by design.
#[cfg(test)]
pub fn write_invariant_raw_for_test(bytes: Vec<u8>) {
    LAST_CONTROLLER_INVARIANT_CELL.with(|c| c.borrow_mut().set(bytes).expect("test write"));
}

/// Test-only: the durable MemoryId 11 record exactly as stored, so a test can
/// compare the DURABLE state field-by-field rather than only the projection
/// `query_controller_invariant` serves.
#[cfg(test)]
pub fn invariant_record_for_test() -> Option<LastControllerInvariant> {
    invariant_load()
}

/// Test-only: write raw bytes into the membership cell so the fail-closed
/// revalidation path can be exercised natively.
#[cfg(test)]
pub fn write_bootstrap_raw_for_test(bytes: Vec<u8>) {
    RECOVERY_MEMBERSHIP_CELL.with(|c| c.borrow_mut().set(bytes).expect("test write"));
}

/// Test-only: plant an intent directly into the durable map. The L2-5
/// single-flight lock makes cross-namespace id collisions unreachable
/// through the public surface; the L2-3 ambiguity path guards exactly such
/// corrupted/legacy durable states, so tests must construct them directly.
#[cfg(test)]
pub fn put_intent_for_test(key: &IntentKey, intent: &UpgradeIntent) {
    put_intent(key, intent);
}

/// Test-only: plant a proposal directly into the durable map, so corrupt
/// states unreachable through the public surface (e.g. a Pending trigger
/// proposal with no linked intent) can exercise the fail-closed rotation
/// linkage assertion.
#[cfg(test)]
pub fn put_stored_proposal_for_test(proposal_id: u64, stored: &StoredProposal) {
    put_stored_proposal(proposal_id, stored);
}

// ── Audit (append-only) ──────────────────────────────────────────────────────

/// Byte cap for target-controlled rejection text recorded in audit events.
pub const MAX_REJECT_DETAIL_BYTES: usize = 512;

/// Byte-bounded, UTF-8-safe truncation: keeps the longest prefix ending on a
/// char boundary within `max_bytes`. NEVER `String::truncate` at an
/// unchecked byte index — it panics mid-character, and the call site records
/// target-controlled rejection content AFTER an inter-canister await, where
/// a panic strands the durable intent in `Executing`: irreconcilable
/// (reconciliation accepts only `OutcomeUnknown`) and permanently holding
/// the single-flight lock (SSA HIGH).
pub fn truncate_utf8_bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn append_audit(now_ns: u64, kind: UpgraderAuditEventKind) {
    AUDIT_EVENTS.with(|a| {
        let mut map = a.borrow_mut();
        let seq = map.len();
        let bytes = candid::encode_one(&UpgraderAuditEvent { seq, at_ns: now_ns, kind })
            .expect("UpgraderAuditEvent encodes");
        map.insert(seq, bytes);
    });
}

/// Record a fresh controller-invariant observation (update paths only, after
/// both management `canister_status` calls succeeded).
pub fn record_controller_invariant(vault_ok: bool, upgrader_ok: bool, now_ns: u64) {
    append_audit(
        now_ns,
        UpgraderAuditEventKind::ControllerInvariantObserved {
            vault_controllers_ok: vault_ok,
            upgrader_controllers_ok: upgrader_ok,
        },
    );
    // R6.0 — the DURABLE observation, written in the same synchronous call as
    // the audit append so the two cannot diverge. The audit event remains the
    // append-only public record of WHEN observations happened; this cell is
    // what the proof is actually served from, and its survival is independent
    // of how long that trail has grown.
    invariant_store(&LastControllerInvariant {
        schema_version: LAST_CONTROLLER_INVARIANT_SCHEMA_VERSION,
        vault_controllers_ok: vault_ok,
        upgrader_controllers_ok: upgrader_ok,
        observed_at_ns: now_ns,
    });
}

// ── Authorization (deny by default; ONE deterministic path) ──────────────────
//
// There are exactly two update-path authorities, never ORed with anything
// else (brief invariant 3):
//   * the durably-recorded Vault counterpart — for trigger/reconcile of a
//     Vault upgrade (the Vault speaks for its own quorum);
//   * membership in the durable recovery set — for the recovery protocol
//     (including membership rotation).
// Gated QUERIES gate on recovery membership only (freeze §5 platform
// constraint: canister-to-canister queries do not exist, so no Vault-signer
// gate is possible — and no mirror is invented).

pub fn vault_principal() -> Option<Principal> {
    VAULT.with(|v| *v.borrow())
}

fn current_epoch() -> u64 {
    RECOVERY_EPOCH.with(|e| *e.borrow())
}

fn require_vault_caller(caller: &Principal) -> Result<Principal, RecoveryError> {
    let vault = vault_principal().ok_or(RecoveryError::NotAuthorized)?;
    if *caller == vault {
        Ok(vault)
    } else {
        Err(RecoveryError::NotAuthorized)
    }
}

pub fn is_recovery_member(caller: &Principal) -> bool {
    *caller != Principal::anonymous()
        && RECOVERY_MEMBERS.with(|m| m.borrow().contains(caller))
}

/// Test-only: how many nonterminal intents the AUTHORITATIVE companion holds. Reads the
/// index, not the intent map, so a test can distinguish "the index is right"
/// from "the scan happened to agree".
#[cfg(test)]
pub fn nonterminal_intent_count_for_test() -> usize {
    NONTERMINAL_INTENT_INDEX.with(|x| x.borrow().iter().count())
}

#[cfg(test)]
pub fn nonterminal_intent_in_flight_for_test(except: Option<&IntentKey>) -> bool {
    nonterminal_intent_in_flight(except)
}

/// Test-only: the single open intent key, if exactly one is open.
#[cfg(test)]
pub fn only_intent_key_for_test() -> Option<IntentKey> {
    NONTERMINAL_INTENT_INDEX.with(|x| {
        let x = x.borrow();
        let mut it = x.iter().map(|(k, _)| k);
        match (it.next(), it.next()) {
            (Some(k), None) => Some(k),
            _ => None,
        }
    })
}

#[cfg(test)]
pub fn intent_key_recovery_for_test(id: u64) -> IntentKey {
    IntentKey::recovery(id)
}

#[cfg(test)]
pub fn get_intent_for_test(key: &IntentKey) -> Option<UpgradeIntent> {
    get_intent(key)
}

/// Test-only: set a stored proposal's expiry, so the sweep mechanism can be
/// exercised while the §10.5 lifetime bounds are still unruled.
#[cfg(test)]
pub fn set_expiry_for_test(proposal_id: u64, expiry: Option<u64>) {
    let stored = get_stored_proposal(proposal_id).expect("proposal exists");
    let next = match stored {
        StoredProposal::Recovery { epoch, mut proposal } => {
            proposal.expires_at_ns = expiry;
            StoredProposal::Recovery { epoch, proposal }
        }
        StoredProposal::Rotation(mut r) => {
            r.expires_at_ns = expiry;
            StoredProposal::Rotation(r)
        }
    };
    put_stored_proposal(proposal_id, &next);
}

/// S5B W3 — visibility for the non-vacuity assertions. Without this a test
/// cannot distinguish "rotation terminalized the complete stale set" from
/// "the index was empty and rotation terminalized nothing", which is the exact
/// failure mode that makes the expiry index unusable for this purpose.
/// S5B W3 — durable membership, for asserting that a trapped rotation left it
/// untouched.
#[cfg(any(test, feature = "testing"))]
pub fn recovery_members_for_test() -> Vec<Principal> {
    RECOVERY_MEMBERS.with(|m| m.borrow().clone())
}

#[cfg(any(test, feature = "testing"))]
pub fn pending_index_ids_for_test() -> Vec<u64> {
    PENDING_RECOVERY_PROPOSAL_INDEX.with(|x| x.borrow().iter().map(|(id, _)| id).collect())
}

#[cfg(test)]
pub fn recovery_expiry_index_len_for_test() -> u64 {
    RECOVERY_PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len())
}

/// Test-only: empty BOTH companion indexes, producing durable corruption that
/// the validation path must DETECT.
///
/// They are not caches and nothing re-derives them; an emptied companion is a
/// fault, and `companion_check` traps on it (amended R3 item 10, clause d).
#[cfg(any(test, feature = "testing"))]
pub fn clear_companion_indexes_for_test() {
    NONTERMINAL_INTENT_INDEX.with(|x| {
        let mut x = x.borrow_mut();
        let keys: Vec<IntentKey> = x.iter().map(|(k, _)| k).collect();
        for k in keys {
            x.remove(&k);
        }
    });
    RECOVERY_PROPOSAL_EXPIRY_INDEX.with(|x| {
        let mut x = x.borrow_mut();
        let keys: Vec<(u64, u64)> = x.iter().map(|(k, _)| k).collect();
        for k in keys {
            x.remove(&k);
        }
    });
}

/// Test-only: plant a lock entry for an intent that is NOT nonterminal — the
/// stale-cache direction that wedges the plane.
#[cfg(test)]
pub fn forge_nonterminal_entry_for_test(key: IntentKey) {
    NONTERMINAL_INTENT_INDEX.with(|x| {
        x.borrow_mut().insert(key, ());
    });
}

/// Test-only: the number of entries in the APPROVAL LOG (`RECOVERY_APPROVALS`,
/// MemoryId 2) — a SEPARATE stable map from the audit events. R1.1's "no
/// creation-time approval-log entry" is a claim about THIS map, so a test that
/// only searches audit events proves something adjacent, not the claim.
#[cfg(test)]
pub fn approval_log_len_for_test() -> u64 {
    RECOVERY_APPROVALS.with(|a| a.borrow().len())
}

/// Test-only: every approval-log entry, decoded.
#[cfg(test)]
pub fn approval_log_entries_for_test() -> Vec<ApprovalLogEntry> {
    RECOVERY_APPROVALS.with(|a| {
        a.borrow()
            .iter()
            .map(|(_, raw)| candid::decode_one(&raw).expect("ApprovalLogEntry decodes"))
            .collect()
    })
}

/// Test-only: total audit-event count, for no-mutation snapshots. Also the
/// R6.0 harness's proof that its beyond-cap seeding actually landed, which is
/// why the gate is `test` OR `testing` rather than `test` alone — a DEPLOYED
/// canister has to be able to answer it. `len()` is O(1) and reads no records,
/// so this is not a history walk.
#[cfg(any(test, feature = "testing"))]
pub fn audit_len_for_test() -> u64 {
    AUDIT_EVENTS.with(|a| a.borrow().len())
}

/// Test-only: the most recently appended audit event, so a rejection's RECORDED
/// REASON can be asserted rather than merely its existence (CUST-SSA-S6-03: the
/// defect was a missing record, and a wrong record would be worse).
#[cfg(test)]
pub fn last_audit_event_for_test() -> Option<UpgraderAuditEvent> {
    // KEYED read, not `.iter().next_back()`. W6 forbids iteration over
    // permanently-growing history, and although `next_back()` on a BTreeMap is
    // a bounded descent rather than a scan, the W6 lint is textual and — more
    // to the point — the distinction is exactly the kind a future reader should
    // not have to re-derive. `last_key_value` says what it does.
    AUDIT_EVENTS.with(|a| {
        a.borrow()
            .last_key_value()
            .map(|(_, raw)| candid::decode_one(&raw).expect("UpgraderAuditEvent decodes"))
    })
}

/// Test-only: corrupt a stored commitment, leaving the payload intact, so the
/// stored-vs-recomputed path can be exercised. No production path produces
/// this state.
#[cfg(test)]
pub fn corrupt_stored_commitment_for_test(proposal_id: u64, hash: Vec<u8>) {
    let stored = get_stored_proposal(proposal_id).expect("proposal exists");
    put_stored_proposal(proposal_id, &with_commitment(stored, hash));
}

/// Test-only: swap a rotation's stored roster while PRESERVING its stored
/// commitment, so "is the roster inside the digest?" can be asked directly.
#[cfg(test)]
pub fn swap_rotation_roster_for_test(proposal_id: u64, new_members: Vec<Principal>) {
    let stored = get_stored_proposal(proposal_id).expect("proposal exists");
    match stored {
        StoredProposal::Rotation(mut r) => {
            r.new_members = new_members; // commitment_hash deliberately untouched
            put_stored_proposal(proposal_id, &StoredProposal::Rotation(r));
        }
        other => panic!("not a rotation: {other:?}"),
    }
}

/// Test-only: the commitment a caller would build with the WRONG epoch.
#[cfg(test)]
pub fn commitment_with_epoch_for_test(proposal_id: u64, self_id: &Principal, epoch: u64) -> Vec<u8> {
    let stored = get_stored_proposal(proposal_id).expect("proposal exists");
    let expires = stored_state(&stored).1;
    stsh_custody_types::ApprovalCommitmentV1::new(
        *self_id,
        proposal_id,
        epoch,
        expires,
        canonical_stored_bytes(&stored),
    )
    .hash()
}

/// Public wrapper so the endpoint layer can gate without duplicating the rule.
pub fn require_member_public(caller: &Principal) -> Result<(), RecoveryError> {
    require_member(caller)
}

fn require_member(caller: &Principal) -> Result<(), RecoveryError> {
    if vault_principal().is_some() && is_recovery_member(caller) {
        Ok(())
    } else {
        Err(RecoveryError::NotAuthorized)
    }
}

// ── Hash binding (freeze §3d/§3f: recomputed, rejected on mismatch) ─────────

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn validate_artifact(
    expected_wasm_hash: &[u8],
    expected_arg_hash: &[u8],
    wasm_bytes: &[u8],
    arg_bytes: &[u8],
) -> Result<(), RecoveryError> {
    // freeze §8: the complete encoded message must stay under the gate bound.
    // Inline-only — exceeding is a failure, never a route to chunking.
    let encoded = (wasm_bytes.len() + arg_bytes.len()
        + expected_wasm_hash.len()
        + expected_arg_hash.len()) as u64;
    if encoded > GATE_SIZE_BOUND_BYTES {
        return Err(RecoveryError::SizeLimitExceeded {
            encoded_bytes: encoded,
            limit_bytes: GATE_SIZE_BOUND_BYTES,
        });
    }
    if expected_wasm_hash.len() != 32 || expected_arg_hash.len() != 32 {
        return Err(RecoveryError::HashMismatch);
    }
    if sha256(wasm_bytes) != expected_wasm_hash || sha256(arg_bytes) != expected_arg_hash {
        return Err(RecoveryError::HashMismatch);
    }
    Ok(())
}

// ── Intent storage helpers ───────────────────────────────────────────────────

pub(crate) fn get_intent(key: &IntentKey) -> Option<UpgradeIntent> {
    UPGRADE_INTENTS.with(|m| {
        m.borrow()
            .get(key)
            .map(|raw| candid::decode_one(&raw).expect("UpgradeIntent decodes"))
    })
}

/// The SINGLE write path for `UPGRADE_INTENTS`, and therefore the only place
/// the authoritative nonterminal companion is maintained. Callers cannot write an intent
/// without updating its index entry — the same discipline as the Vault's
/// `proposal_put` (amended R3 item 10, `878d685e…`).
fn put_intent(key: &IntentKey, intent: &UpgradeIntent) {
    UPGRADE_INTENTS.with(|m| {
        m.borrow_mut()
            .insert(*key, candid::encode_one(intent).expect("UpgradeIntent encodes"));
    });
    reindex_intent(key, intent);
}

// ── S5B W2 — bounded authoritative companions (Upgrader plane) ───────────────
//
// The Upgrader half of amended R3 item 10 (878d685e…), clause (g): the
// recovery-proposal expiry index (MemoryId 6) and the nonterminal-intent
// pointer (MemoryId 5) become AUTHORITATIVE companions rather than derived
// caches, accounted for by MemoryId 7.
//
// Same construction as the Vault's — see `vault/src/lib.rs` for the full
// rationale on the XOR accumulator and its deliberately-stated limits. Item 10
// clause (g) requires BOTH canisters; closing only the Vault would move the
// exhaustion route rather than remove it, which is the same reasoning that put
// the recovery plane in R3.8/R3.11 to begin with.
// S5B W3 — trap injection for rotation rollback evidence. Same shape and same
// reasoning as W5(a) on the Vault: the brief requires trap/rollback evidence
// through a real message boundary, and an in-process panic does not exercise IC
// transactional semantics. Release builds compile `rotation_trap` to nothing
// and carry no arming endpoint.
pub const ROTATION_TRAP_MID_TERMINALIZATION: &str = "mid_terminalization";

/// SSA RF-2 — the GENUINELY mid-work boundary.
///
/// `ROTATION_TRAP_MID_TERMINALIZATION` is the FIRST statement in the loop, so
/// it fires before any stale record has changed. That proves "trap BEFORE
/// work", which is a strictly weaker property than the one acceptance 13
/// claims: with a single stale proposal it cannot distinguish "rolled back"
/// from "never started". SSA is right that this is a real gap.
///
/// This point fires at the END of a loop iteration, so at least one stale
/// proposal — and, for a trigger proposal, its linked intent and its audit
/// event — is already durably mutated within the message when it trips. With
/// two or more stale records the untouched remainder proves the loop was
/// genuinely mid-flight, and the terminalized first record proves the rollback
/// discarded completed work rather than merely unstarted work.
pub const ROTATION_TRAP_AFTER_FIRST_TERMINALIZATION: &str = "after_first_terminalization";

/// SSA RF-5 — the RECOVERY plane's W1 message boundary.
///
/// RF-5 records that the Vault's committed-ID evidence had no recovery-plane
/// equivalent at all. This boundary sits between the proposal insertion and
/// `commit_proposal_id`, so a trap here proves the pair is atomic on THIS
/// plane too: the record does not survive without its counter, and the
/// uncommitted id comes back to the next attempt unchanged (W1.2/W1.3).
pub const PROPOSE_TRAP_AFTER_INSERT_BEFORE_COUNTER: &str = "after_insert_before_counter";

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static ARMED_ROTATION_TRAP: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[cfg(any(test, feature = "testing"))]
fn rotation_trap(point: &'static str) {
    let armed = ARMED_ROTATION_TRAP.with(|t| t.borrow().clone());
    if armed.as_deref() == Some(point) {
        ic_cdk::trap(&format!("S5B W3 injected trap at {point}"));
    }
}

#[cfg(not(any(test, feature = "testing")))]
#[inline(always)]
fn rotation_trap(_point: &'static str) {}

// ── SSA RF-1 — companion-write trap boundary ────────────────────────────────
//
// Same construction as the rotation trap: rollback evidence must run through a
// real Wasm/PocketIC message boundary. Release builds compile this to nothing
// and carry no arming endpoint.
pub const COMPANION_TRAP_AFTER_INDEX_BEFORE_ACCOUNTING: &str = "after_index_before_accounting";

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static ARMED_COMPANION_TRAP: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[cfg(any(test, feature = "testing"))]
fn companion_trap(point: &'static str) {
    let armed = ARMED_COMPANION_TRAP.with(|t| t.borrow().clone());
    if armed.as_deref() == Some(point) {
        ic_cdk::trap(&format!("S5B RF-1 injected trap at {point}"));
    }
}

#[cfg(not(any(test, feature = "testing")))]
#[inline(always)]
fn companion_trap(_point: &'static str) {}

/// TEST-ONLY: arm or ("none") disarm the companion-write trap.
#[cfg(any(test, feature = "testing"))]
pub fn arm_companion_trap_for_test(point: &str) {
    ARMED_COMPANION_TRAP.with(|t| {
        *t.borrow_mut() = if point == "none" { None } else { Some(point.to_string()) };
    });
}

/// RF-2 — trap carrying the number of stale records ALREADY terminalized in
/// this message.
///
/// The count is in the reject message so the evidence that work preceded the
/// trap comes from the canister's own execution, observed over ingress. Without
/// it the test could not distinguish this boundary from the loop-head one:
/// rollback erases the completed work, so after the fact both look identical,
/// and moving the call back to the head of the loop would leave every
/// assertion passing while proving only "trap before work" again.
#[cfg(any(test, feature = "testing"))]
fn rotation_trap_after_n(point: &'static str, n: u32) {
    let armed = ARMED_ROTATION_TRAP.with(|t| t.borrow().clone());
    if armed.as_deref() == Some(point) {
        ic_cdk::trap(&format!("S5B W3 injected trap at {point} after {n} terminalized"));
    }
}

#[cfg(not(any(test, feature = "testing")))]
#[inline(always)]
fn rotation_trap_after_n(_point: &'static str, _n: u32) {}

/// TEST-ONLY: arm or ("none") disarm the rotation trap.
#[cfg(any(test, feature = "testing"))]
pub fn arm_rotation_trap_for_test(point: &str) {
    ARMED_ROTATION_TRAP.with(|t| {
        *t.borrow_mut() = if point == "none" { None } else { Some(point.to_string()) };
    });
}

/// SSA B1 re-review BLOCKER 1 — bumped 1 → 2 by the MemoryId 10 addition.
///
/// MemoryId 10 changed the authoritative companion REGISTRY and the commitment
/// DOMAIN, and the version sentinel is what stops a predecessor record being
/// read as the new layout. Left at 1, an upgrade from the predecessor build
/// would have been silently accepted: MemoryId 10 starts empty, an empty index
/// contributes nothing to the XOR accumulator or the byte/entry accounting, so
/// the OLD commitment still verifies — and `companion_recompute` walks only the
/// companion indexes, never history, so it cannot notice that the existing
/// nonterminal proposals are missing from the new index. C12 would then
/// undercount every proposal admitted before the upgrade.
///
/// Fresh-install cutover means no migration has to be invented: a predecessor
/// V1 record now FAILS CLOSED in `companion_load` (schema mismatch traps). A
/// bounded transition, if ever wanted, is a separately reviewed change.
pub const COMPANION_STATE_SCHEMA_VERSION: u32 = 2;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CompanionState {
    pub schema_version: u32,
    pub entries: u64,
    pub bytes: u64,
    /// XOR accumulator over per-entry digests — recomputable from the bounded
    /// companions.
    pub entry_acc: Vec<u8>,
    /// S5B W1 — the recovery-proposal id counter. The brief tolerates
    /// `next_back()` on this plane "only until" the companion work lands in
    /// W2; it has landed, so the counter becomes the sole allocation authority
    /// here too. `next_back()` was a bounded read rather than a full scan, but
    /// it is still HISTORY as allocation authority, which W1.1 forbids
    /// outright.
    pub next_proposal_id: u64,
    /// Seals the accounting AND the counter (W1.6). The counter is not
    /// recomputable, so this is what makes it checkable.
    pub commitment: Vec<u8>,
}

impl Default for CompanionState {
    fn default() -> Self {
        let mut s = Self {
            schema_version: COMPANION_STATE_SCHEMA_VERSION,
            entries: 0,
            bytes: 0,
            entry_acc: vec![0u8; 32],
            next_proposal_id: 1,
            commitment: Vec::new(),
        };
        companion_seal(&mut s);
        s
    }
}

pub fn companion_seal(s: &mut CompanionState) {
    let mut b = Vec::new();
    b.extend_from_slice(b"companion-seal-v1-upgrader");
    b.extend_from_slice(&s.schema_version.to_be_bytes());
    b.extend_from_slice(&s.entries.to_be_bytes());
    b.extend_from_slice(&s.bytes.to_be_bytes());
    b.extend_from_slice(&s.entry_acc);
    b.extend_from_slice(&s.next_proposal_id.to_be_bytes());
    s.commitment = companion_sha256(&b);
}

fn companion_sha256(b: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().to_vec()
}

fn companion_digest_expiry(exp: u64, id: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"rexpiry\0");
    b.extend_from_slice(&exp.to_be_bytes());
    b.extend_from_slice(&id.to_be_bytes());
    companion_sha256(&b)
}

fn companion_digest_pending(id: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"rpending");
    b.extend_from_slice(&id.to_be_bytes());
    companion_sha256(&b)
}

fn companion_bytes_pending() -> u64 {
    8
}

/// Domain-separated like every other companion digest, so a nonterminal entry
/// and a Pending entry for the same proposal cannot cancel each other in the
/// XOR accumulator.
fn companion_digest_nonterminal(proposer: Principal, id: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"nonterm\0");
    b.extend_from_slice(proposer.as_slice());
    b.extend_from_slice(&id.to_be_bytes());
    companion_sha256(&b)
}

/// Key + value bytes, matching what the digest covers. Principals are
/// variable-length, so this is computed per entry rather than pinned.
fn companion_bytes_nonterminal(proposer: Principal) -> u64 {
    (proposer.as_slice().len() + 8) as u64
}

fn companion_digest_intent(key: &IntentKey) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"nintent\0");
    b.push(key.tag);
    b.extend_from_slice(&key.id.to_be_bytes());
    companion_sha256(&b)
}

fn companion_bytes_expiry() -> u64 {
    16
}
fn companion_bytes_intent() -> u64 {
    9
}

/// SSA landed-diff BLOCKER 3 — absence must TRAP, not default. Same reasoning
/// as the Vault's: treating an empty cell as a valid default fails OPEN for a
/// pre-companion deployment whose active indexes happen to be empty.
pub fn companion_load() -> CompanionState {
    let raw = COMPANION_STATE.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        ic_cdk::trap(
            "COMPANION_STATE: ABSENT. Written at fresh install; absence means a \
             pre-companion deployment was upgraded into this build, or the cell was \
             cleared. Durable corruption — fail closed, never rebuild.",
        );
    }
    let s: CompanionState = candid::decode_one(&raw)
        .unwrap_or_else(|_| ic_cdk::trap("COMPANION_STATE: undecodable — fail closed (W2 d)"));
    if s.schema_version != COMPANION_STATE_SCHEMA_VERSION {
        ic_cdk::trap("COMPANION_STATE: schema version mismatch — fail closed (W2 c/d)");
    }
    s
}

/// Idempotent; see the Vault's `companion_init` for why it does not police
/// double-writes. What BLOCKER 3 requires is that the record EXISTS after
/// install, enforced by `companion_load` trapping on absence.
// ── SSA BLOCKER 2 — C9 entry gate, recovery plane ───────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct EntryRateLedger {
    // S6 corrective (CUST-SSA-S6-02) — SLIDING, was TUMBLING. The recovery
    // plane carried the identical defect and the identical consequence: a
    // caller straddling the reset boundary got 2 x C9 inside one real rolling
    // window. See the Vault's ledger for the full reasoning; both planes are
    // corrected the same way deliberately, because leaving one tumbling would
    // just move the exhaustion route rather than remove it — the same argument
    // that put this plane in R3.8/R3.11 to begin with.
    /// Retained entry events as `(who, at_ns)`, pruned to the live window.
    /// Bounded by C9's global term: admission is refused AT it.
    pub events: Vec<(Principal, u64)>,
}

impl EntryRateLedger {
    /// Live in-window count as of the last charge (which prunes first).
    pub fn retained(&self) -> u32 {
        self.events.len() as u32
    }
    /// The same, for one member.
    pub fn retained_for(&self, who: Principal) -> u32 {
        self.events.iter().filter(|(p, _)| *p == who).count() as u32
    }
}

fn entry_rate_load() -> EntryRateLedger {
    let raw = ENTRY_RATE_LEDGER.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        return EntryRateLedger::default();
    }
    candid::decode_one(&raw)
        .unwrap_or_else(|_| ic_cdk::trap("ENTRY_RATE_LEDGER: undecodable — fail closed"))
}

fn entry_rate_store(l: &EntryRateLedger) {
    let bytes = candid::encode_one(l).expect("EntryRateLedger encodes");
    ENTRY_RATE_LEDGER.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("ENTRY_RATE_LEDGER: stable write failed")
    });
}

fn entry_rate_params() -> Option<stsh_custody_types::EntryRateParams> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_ENTRY_RATE.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::ENTRY_RATE_PARAMS
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    // RF-1 (SSA S8B return) — ALL of these are `Option<Option<…>>`, for the
    // reason spelled out on INJECTED_REFRESH_PARAMS below: the outer layer is
    // "is anything injected", the inner is the value. A single `Option`
    // conflates them, and the conflation is INVISIBLE for exactly as long as
    // the production constant is `None`.
    //
    // Every one of these four is production-`Some` TODAY — C9 entry rate,
    // C5/C7/C12 caps, C3/C4 lifetime bounds and C11 sweep limits were all
    // ruled at S6. So before this change, every test calling `inject(None)`
    // believing it forced the unruled path was in fact exercising the RULED
    // production value, silently, and had been since S6. The S8B pin surfaced
    // the class on a fifth seam; this is the sweep.
    static INJECTED_ENTRY_RATE:
        RefCell<Option<Option<stsh_custody_types::EntryRateParams>>> =
        const { RefCell::new(None) };
    static INJECTED_NONTERMINAL_CAPS:
        RefCell<Option<Option<stsh_custody_types::NonterminalCaps>>> =
        const { RefCell::new(None) };
    static INJECTED_LIFETIME_BOUNDS:
        RefCell<Option<Option<stsh_custody_types::ProposalLifetimeBounds>>> =
        const { RefCell::new(None) };
    static INJECTED_SWEEP_WORK_LIMIT: RefCell<Option<Option<usize>>> =
        const { RefCell::new(None) };
    /// S8B — the three R6 constants.
    ///
    /// DOUBLE `Option`, and the reason is load-bearing. The inner layer is the
    /// value; the OUTER layer is "is anything injected at all". A single
    /// `Option` conflated the two, so `inject(None)` meant "clear the
    /// injection" — which was indistinguishable from "force unruled" only for
    /// as long as the production constant happened to BE `None`. The A1 pin
    /// (`eee3f17a…`) made production `Some`, and at that moment two tests that
    /// believed they were exercising the unruled path silently began exercising
    /// the pinned one instead. They failed loudly here, but the same shape in a
    /// test that asserted less would have passed while proving nothing.
    ///
    ///   `None`             — no injection; use the production constant.
    ///   `Some(None)`       — force UNRULED, whatever production says.
    ///   `Some(Some(p))`    — force `p`.
    static INJECTED_REFRESH_PARAMS:
        RefCell<Option<Option<stsh_custody_types::InvariantRefreshParams>>> =
        const { RefCell::new(None) };
}

/// S8B — inject candidate R6 refresh constants (test/testing only).
///
/// `None` clears the injection; `Some(None)` forces the UNRULED path even
/// though the A1 pin made the production constant `Some`. See the thread_local
/// for why those must be distinguishable.
#[cfg(any(test, feature = "testing"))]
pub fn inject_refresh_params_for_test(
    params: Option<Option<stsh_custody_types::InvariantRefreshParams>>,
) {
    INJECTED_REFRESH_PARAMS.with(|c| *c.borrow_mut() = params);
}

/// S8B — read the durable limiter state (test/testing only), so a test can
/// assert the CHARGE is durable rather than infer it from behaviour.
#[cfg(any(test, feature = "testing"))]
pub fn refresh_ledger_for_test() -> InvariantRefreshLedger {
    refresh_ledger_load()
}

/// S8B — plant a limiter state directly, so the stale-in-flight reclaim and
/// the corrupt-cell gates can be reached; no production path produces either.
#[cfg(test)]
pub fn put_refresh_ledger_for_test(l: &InvariantRefreshLedger) {
    refresh_ledger_store(l);
}

/// S8B — write raw bytes into the MemoryId 12 cell (test only).
#[cfg(test)]
pub fn write_refresh_ledger_raw_for_test(bytes: Vec<u8>) {
    INVARIANT_REFRESH_LEDGER.with(|c| c.borrow_mut().set(bytes).expect("test write"));
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_entry_rate_for_test(p: Option<Option<stsh_custody_types::EntryRateParams>>) {
    INJECTED_ENTRY_RATE.with(|c| *c.borrow_mut() = p);
}

/// The ruled C5/C7/C12 caps, or a test-injected candidate.
///
/// RF-1 correction: this doc previously read "the production constant stays
/// `None`". That has been FALSE since S6 ruled C5/C7/C12 — the constant is
/// `Some`, and a reader trusting the comment would conclude an `inject(None)`
/// test still exercised the unruled path. Candidate values still reach the code
/// only through the test-only seam, and release Wasms still carry neither the
/// candidate nor the hook; what changed is that the RULED value is what a
/// non-injecting caller now gets.
fn nonterminal_caps() -> Option<stsh_custody_types::NonterminalCaps> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_NONTERMINAL_CAPS.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::RECOVERY_NONTERMINAL_CAPS
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_nonterminal_caps_for_test(
    c: Option<Option<stsh_custody_types::NonterminalCaps>>,
) {
    INJECTED_NONTERMINAL_CAPS.with(|x| *x.borrow_mut() = c);
}

/// The ruled proposal-lifetime bounds, or an S5A-injected candidate.
///
/// The recovery plane's half of the M1 gate A prerequisite. See the Vault's
/// accessor for why the injection is load-bearing rather than convenient: while
/// the bounds are `None` this plane's `RECOVERY_PROPOSAL_EXPIRY_INDEX` is
/// vacuously empty, so the sweep has no due record whose marginal cost could be
/// measured.
fn proposal_lifetime_bounds() -> Option<stsh_custody_types::ProposalLifetimeBounds> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_LIFETIME_BOUNDS.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS
}

/// The ruled per-call sweep work bound, or an S5A-injected candidate.
pub fn sweep_work_limit() -> Option<usize> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_SWEEP_WORK_LIMIT.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::RECOVERY_SWEEP_WORK_LIMIT_PER_CALL
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_lifetime_params_for_test(
    bounds: Option<Option<stsh_custody_types::ProposalLifetimeBounds>>,
    sweep_limit: Option<Option<usize>>,
) {
    INJECTED_LIFETIME_BOUNDS.with(|x| *x.borrow_mut() = bounds);
    INJECTED_SWEEP_WORK_LIMIT.with(|x| *x.borrow_mut() = sweep_limit);
}

/// RF-1 — the four sibling seams' RESOLVED values, so a test can observe that
/// "clear the injection" and "force unruled" are different. The resolvers are
/// private to `core`; this is the seam the distinctness test reads them through.
#[cfg(any(test, feature = "testing"))]
#[allow(clippy::type_complexity)]
pub fn resolved_sibling_params_for_test() -> (
    Option<stsh_custody_types::EntryRateParams>,
    Option<stsh_custody_types::NonterminalCaps>,
    Option<stsh_custody_types::ProposalLifetimeBounds>,
    Option<usize>,
) {
    (entry_rate_params(), nonterminal_caps(), proposal_lifetime_bounds(), sweep_work_limit())
}

/// Test-only: how many nonterminal recovery proposals the index holds.
#[cfg(any(test, feature = "testing"))]
pub fn nonterminal_proposal_count_for_test() -> usize {
    NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|x| x.borrow().iter().count())
}

/// Test-only: plant an index entry WITHOUT its companion accounting — the
/// "companion moved, commitment did not" corruption `companion_check` exists
/// to catch. Proves MemoryId 10 is actually covered by the seal rather than
/// merely adjacent to it.
#[cfg(test)]
pub fn forge_nonterminal_proposal_entry_for_test(proposer: Principal, id: u64) {
    NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|x| {
        x.borrow_mut().insert((proposer, id), ());
    });
}

/// C5/C7/C12 — refuse admission when the nonterminal caps are already met.
///
/// ORDERING, per SSA: this binds BEFORE the C9 charge, before proposal-ID
/// allocation, before intent creation, and before any other durable write. A
/// refused admission therefore consumes no id, burns no rate budget, and
/// leaves no record — which is also what keeps W1.3's "a record-less rejection
/// burns nothing" true on this plane.
///
/// NOT applied to the audited-rejection branch of `propose_membership_rotation`:
/// that path creates no proposal and occupies no slot, so a cap has nothing to
/// bound there. Capping it would refuse to RECORD a rejection once the ring is
/// merely busy — destroying the audit trail the rejection exists to write,
/// which is the same reasoning that makes downstream appends unrefusable under
/// W4. That branch is bounded by C9, which is the gate that fits it.
fn check_nonterminal_caps(who: Principal) -> Result<(), RecoveryError> {
    // SSA B1 re-review BLOCKER 2 — VALIDATE BEFORE READING.
    //
    // MemoryId 10 is authoritative companion state, so it must be validated
    // before any admission decision is taken FROM it. The first cut read the
    // index directly: a forged extra entry then produced an ordinary typed cap
    // refusal instead of a trap, i.e. corruption presenting as a routine
    // "ring is busy" error — the exact failure mode the seal exists to catch.
    //
    // The `next_proposal_id` validation further down the path cannot repair
    // this: a cap refusal RETURNS before ever reaching it. Validation must
    // therefore also precede C9 charging, which it does — this function is the
    // first thing both admission paths call.
    //
    // Unconditional, ahead of the caps lookup: while the caps are unruled the
    // read below does not happen, but validating anyway keeps a corrupt
    // companion failing closed at the same point on both sides of the S6
    // ruling, rather than changing where corruption surfaces when a value
    // lands.
    companion_validate();
    let Some(caps) = nonterminal_caps() else {
        // Unruled: the mechanism is built, enforcement is S6's. `Option = None`
        // fail-closed convention — no placeholder value appears here.
        return Ok(());
    };
    // Both reads are bounded-active-set: `len()` is O(1) and the per-member
    // count is a contiguous range over a key that leads with the proposer.
    // Neither touches RECOVERY_PROPOSALS.
    let global = NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|x| x.borrow().len()) as u32;
    let mine = NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|x| {
        x.borrow()
            .range((who, u64::MIN)..=(who, u64::MAX))
            .count()
    }) as u32;
    if global >= caps.global || mine >= caps.per_signer {
        return Err(RecoveryError::IllegalSourceState);
    }
    Ok(())
}

/// RF-7 — clear the companion cell to reproduce the PRE-COMPANION deployment
/// state (empty cell). There is deliberately no production path to this.
#[cfg(any(test, feature = "testing"))]
pub fn clear_companion_state_for_test() {
    COMPANION_STATE.with(|c| c.borrow_mut().set(Vec::new()).expect("clear"));
}

#[cfg(any(test, feature = "testing"))]
pub fn entry_rate_global_count_for_test() -> u32 {
    entry_rate_load().retained()
}

/// Charge ONE entry event — an admission OR an audited rejection, sharing one
/// budget, exactly as on the Vault.
///
/// NON-RECURSIVE BY CONSTRUCTION: when this refuses, the caller returns a typed
/// error and appends NOTHING. A rate-limited rejection that itself demanded an
/// audited append would need a second budgeted entry to record the refusal of
/// the first, which is the recursion the brief forbids.
pub fn charge_entry_event(who: Principal, now: u64) -> Result<(), RecoveryError> {
    let Some(params) = entry_rate_params() else {
        return Ok(());
    };
    let mut l = entry_rate_load();
    // Slide: half-open `(now - window, now]`, so an event exactly one full
    // window old has expired rather than lingering one more charge.
    let cutoff = now.saturating_sub(params.window_ns);
    l.events.retain(|(_, at)| *at > cutoff);

    let global = l.events.len() as u32;
    let mine = l.events.iter().filter(|(p, _)| *p == who).count() as u32;
    if global >= params.global_per_window || mine >= params.per_signer_per_window {
        return Err(RecoveryError::ThresholdViolation);
    }
    l.events.push((who, now));
    entry_rate_store(&l);
    Ok(())
}

pub fn companion_init() {
    let raw = COMPANION_STATE.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        companion_store(&CompanionState::default());
    }
}

pub fn companion_store(s: &CompanionState) {
    let bytes = candid::encode_one(s).expect("CompanionState encodes");
    COMPANION_STATE.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("COMPANION_STATE: stable write failed")
    });
}

fn companion_apply(s: &mut CompanionState, digest: Vec<u8>, bytes: u64, insert: bool) {
    for (acc, d) in s.entry_acc.iter_mut().zip(digest.iter()) {
        *acc ^= d;
    }
    if insert {
        s.entries = s.entries.saturating_add(1);
        s.bytes = s.bytes.saturating_add(bytes);
    } else {
        s.entries = s.entries.saturating_sub(1);
        s.bytes = s.bytes.saturating_sub(bytes);
    }
}

/// (c)-COMPLIANT: walks the BOUNDED companions only. Never touches
/// `RECOVERY_PROPOSALS` or `UPGRADE_INTENTS` — the permanent histories.
fn companion_recompute() -> CompanionState {
    // The counter is not derivable — carried from stored and checked by the
    // seal (W1.6), never re-derived from history.
    let stored = companion_load();
    let mut s = CompanionState {
        next_proposal_id: stored.next_proposal_id,
        ..CompanionState::default()
    };
    RECOVERY_PROPOSAL_EXPIRY_INDEX.with(|x| {
        for ((exp, id), _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_expiry(exp, id),
                companion_bytes_expiry(),
                true,
            );
        }
    });
    NONTERMINAL_INTENT_INDEX.with(|x| {
        for (k, _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_intent(&k),
                companion_bytes_intent(),
                true,
            );
        }
    });
    PENDING_RECOVERY_PROPOSAL_INDEX.with(|x| {
        for (id, _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_pending(id),
                companion_bytes_pending(),
                true,
            );
        }
    });
    NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|x| {
        for ((proposer, id), _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_nonterminal(proposer, id),
                companion_bytes_nonterminal(proposer),
                true,
            );
        }
    });
    companion_seal(&mut s);
    s
}

/// Detection, split from trapping for the same reason as the Vault's: an
/// in-process `trap` panics generically, so tests could not otherwise assert
/// WHICH check fired.
pub fn companion_check() -> Result<(), String> {
    let stored = companion_load();
    // W1.6 — seal first: the counter cannot be recomputed, so the comparison
    // below carries it forward and could never catch tampering on its own.
    let mut resealed = stored.clone();
    companion_seal(&mut resealed);
    if resealed.commitment != stored.commitment {
        return Err(format!(
            "COMPANION_STATE: integrity mismatch — the seal does not cover the stored \
             state (counter proposal={}, entries={} bytes={}). Some field moved outside \
             the per-map primitive. Fail closed (W1.6/W2 d); NOT repaired at runtime.",
            stored.next_proposal_id, stored.entries, stored.bytes,
        ));
    }
    let computed = companion_recompute();
    if stored == computed {
        return Ok(());
    }
    Err(format!(
        "COMPANION_STATE: integrity mismatch — companion state disagrees with the \
         companions it accounts for (stored entries={} bytes={}, computed entries={} \
         bytes={}, commitment {}). Fail closed (W2 d). NOT repaired at runtime; \
         recovery is a governed, hash-bound Wasm upgrade.",
        stored.entries,
        stored.bytes,
        computed.entries,
        computed.bytes,
        if stored.commitment == computed.commitment {
            "matches"
        } else {
            "DIFFERS"
        },
    ))
}

pub fn companion_validate() {
    if let Err(e) = companion_check() {
        ic_cdk::trap(&e);
    }
}

/// Companion-maintaining intent pointer write. (b) — the pointer and its
/// accounting move in the same synchronous transaction as the intent record.
fn reindex_intent(key: &IntentKey, intent: &UpgradeIntent) {
    let nonterminal = !intent.outcome.is_terminal();
    let mut cs = companion_load();
    NONTERMINAL_INTENT_INDEX.with(|x| {
        let mut x = x.borrow_mut();
        if nonterminal {
            if x.insert(*key, ()).is_none() {
                companion_apply(
                    &mut cs,
                    companion_digest_intent(key),
                    companion_bytes_intent(),
                    true,
                );
            }
        } else if x.remove(key).is_some() {
            companion_apply(
                &mut cs,
                companion_digest_intent(key),
                companion_bytes_intent(),
                false,
            );
        }
    });
    companion_seal(&mut cs);
    companion_store(&cs);
}

/// (outcome, expiry) of a stored proposal, whichever variant it is.
pub(crate) fn stored_state(stored: &StoredProposal) -> (ActionOutcome, Option<u64>) {
    match stored {
        StoredProposal::Recovery { proposal, .. } => {
            (proposal.outcome, proposal.expires_at_ns)
        }
        StoredProposal::Rotation(r) => (r.outcome, r.expires_at_ns),
    }
}

/// The EXPLICIT proposer of either variant. Both carry one; there is no
/// inference from the approval set (V8 §3 struck the propose-time seeding that
/// made such inference possible).
pub(crate) fn stored_proposer(stored: &StoredProposal) -> Principal {
    match stored {
        StoredProposal::Recovery { proposal, .. } => proposal.proposer,
        StoredProposal::Rotation(r) => r.proposer,
    }
}

/// Computed purely from (prior, next), and idempotent.
///
/// SSA CUST-SSA-S5B-COMP-01: this previously said "the steady-state write path
/// and the post_upgrade rebuild are the same code". There IS no post_upgrade
/// rebuild — amended R3 item 10 removed it, and clause (c) forbids the
/// history pass outright. Idempotence matters because the same primitive runs
/// on every record write, not because an upgrade replays it.
fn reindex_stored_proposal(
    proposal_id: u64,
    prior: Option<&StoredProposal>,
    next: &StoredProposal,
) {
    let mut cs = companion_load();
    if let Some(p) = prior {
        if let (_, Some(exp)) = stored_state(p) {
            let existed = RECOVERY_PROPOSAL_EXPIRY_INDEX
                .with(|x| x.borrow_mut().remove(&(exp, proposal_id)).is_some());
            if existed {
                companion_apply(
                    &mut cs,
                    companion_digest_expiry(exp, proposal_id),
                    companion_bytes_expiry(),
                    false,
                );
            }
        }
    }
    let (outcome, expiry) = stored_state(next);
    if outcome.is_reapable() {
        if let Some(exp) = expiry {
            let prior_entry = RECOVERY_PROPOSAL_EXPIRY_INDEX
                .with(|x| x.borrow_mut().insert((exp, proposal_id), ()));
            if prior_entry.is_none() {
                companion_apply(
                    &mut cs,
                    companion_digest_expiry(exp, proposal_id),
                    companion_bytes_expiry(),
                    true,
                );
            }
        }
    }
    // S5B W3 — the bounded Pending index, maintained in the SAME transaction.
    // Predicate is `is_reapable()`, byte-identical to the full scan this
    // replaces, so `Executing` is excluded here exactly as it was there.
    let (prior_reapable, _) = prior.map(stored_state).unwrap_or((ActionOutcome::Executed, None));
    if prior_reapable.is_reapable() {
        let existed =
            PENDING_RECOVERY_PROPOSAL_INDEX.with(|x| x.borrow_mut().remove(&proposal_id).is_some());
        if existed {
            companion_apply(
                &mut cs,
                companion_digest_pending(proposal_id),
                companion_bytes_pending(),
                false,
            );
        }
    }
    if outcome.is_reapable() {
        let prior_entry =
            PENDING_RECOVERY_PROPOSAL_INDEX.with(|x| x.borrow_mut().insert(proposal_id, ()));
        if prior_entry.is_none() {
            companion_apply(
                &mut cs,
                companion_digest_pending(proposal_id),
                companion_bytes_pending(),
                true,
            );
        }
    }

    // ── SSA BLOCKER 1 — NONTERMINAL membership, in the SAME transaction ─────
    //
    // Nonterminal = Pending | Executing | OutcomeUnknown, i.e.
    // `!outcome.is_terminal()`. Deliberately NOT `is_reapable()` (the Pending
    // predicate used by the W3 index directly above) and NOT
    // `holds_single_flight()` (which excludes Pending): C5/C7/C12 bound how
    // many proposals are OPEN, and a Pending proposal is open. Reusing either
    // neighbouring predicate type-checks and is how the Vault defect shipped.
    //
    // Maintained for BOTH variants — a Rotation proposal occupies a slot
    // exactly as a Recovery one does; `stored_proposer` covers both.
    let was_nonterminal = prior
        .map(|p| !stored_state(p).0.is_terminal())
        .unwrap_or(false);
    let is_nonterminal = !outcome.is_terminal();
    if was_nonterminal {
        // Remove under the PRIOR proposer: the key that was written. Reading
        // `next`'s proposer here would leak an entry whenever the two differ.
        let prior_proposer = prior.map(stored_proposer).unwrap_or_else(|| stored_proposer(next));
        let existed = NONTERMINAL_RECOVERY_PROPOSAL_INDEX
            .with(|x| x.borrow_mut().remove(&(prior_proposer, proposal_id)).is_some());
        if existed {
            companion_apply(
                &mut cs,
                companion_digest_nonterminal(prior_proposer, proposal_id),
                companion_bytes_nonterminal(prior_proposer),
                false,
            );
        }
    }
    if is_nonterminal {
        let proposer = stored_proposer(next);
        let prior_entry = NONTERMINAL_RECOVERY_PROPOSAL_INDEX
            .with(|x| x.borrow_mut().insert((proposer, proposal_id), ()));
        if prior_entry.is_none() {
            companion_apply(
                &mut cs,
                companion_digest_nonterminal(proposer, proposal_id),
                companion_bytes_nonterminal(proposer),
                true,
            );
        }
    }

    // (b) — the accounting lands in the SAME transaction as the index writes
    // above. Omitting this store is precisely the "companion moved, commitment
    // did not" corruption `companion_check` exists to catch, and it did.
    //
    // SSA RF-1 — W2 acceptance 11: the COMPANION-WRITE boundary, mirroring the
    // Vault's. At this instant the indexes have moved and the accounting has
    // not been stored. Detection had evidence; ROLLBACK did not, on either
    // plane. A trap here must discard the index writes with everything else,
    // leaving a canister whose companion still validates — because if the
    // indexes survived without the accounting, the next `companion_validate`
    // would trap and the canister would be bricked with no repair surface.
    companion_trap(COMPANION_TRAP_AFTER_INDEX_BEFORE_ACCOUNTING);
    companion_seal(&mut cs);
    companion_store(&cs);
}

// S5B W2(c): `rebuild_recovery_expiry_index` REMOVED. It decoded every
// StoredProposal ever written — a full pass over permanent history at
// post_upgrade, which (c) forbids outright. The expiry index is now an
// authoritative companion (a), validated by `companion_check`, never
// re-derived from RECOVERY_PROPOSALS.

/// Set a stored proposal's outcome to a terminal reaped state, AND terminalize
/// the linked upgrade intent if one exists.
///
/// THE INTENT IS NOT OPTIONAL HOUSEKEEPING — it is where the bytes are.
/// `redact_action` empties the artifact vectors before storing, so for a
/// `TriggerVaultUpgrade` the stored proposal is only a hash-bearing shadow and
/// the real Wasm/arg bytes live in `UPGRADE_INTENTS` from PROPOSE time.
/// Terminalizing the proposal alone would therefore: retain every artifact
/// byte the reap was supposed to release, leave the intent `Pending`, and —
/// because `Pending` counts as nonterminal on this plane — leave the
/// single-flight lock held forever. One cancelled proposal would permanently
/// block every future trigger. That is a worse denial of service than the one
/// R3 exists to close, introduced by the fix for it.
///
/// SAME ORDERING RULE as the Vault (R3.2), applied to BOTH records: terminal
/// state durable FIRST, bytes released in a SECOND write.
fn reap_stored_pending(
    proposal_id: u64,
    stored: &StoredProposal,
    terminal: ActionOutcome,
    now_ns: u64,
) {
    let next = match stored.clone() {
        StoredProposal::Recovery { epoch, mut proposal } => {
            proposal.outcome = terminal;
            StoredProposal::Recovery { epoch, proposal }
        }
        StoredProposal::Rotation(mut r) => {
            r.outcome = terminal;
            StoredProposal::Rotation(r)
        }
    };
    put_stored_proposal(proposal_id, &next);
    reap_linked_intent(proposal_id, terminal, now_ns);
}

/// Terminalize the recovery-origin intent linked to `proposal_id`, if any.
///
/// Only `Pending` intents are reaped: an intent past the first await is a fact
/// about a call that may have landed, and `Executing`/`OutcomeUnknown` must
/// settle through the objective-reconciliation path, never by cancellation.
/// Rotation proposals have no intent, so this is a no-op for them.
fn reap_linked_intent(proposal_id: u64, terminal: ActionOutcome, now_ns: u64) {
    let key = IntentKey::recovery(proposal_id);
    let Some(mut intent) = get_intent(&key) else { return };
    if !intent.outcome.is_reapable() {
        return;
    }
    // 1. Terminal state durable first. `put_intent` reindexes, which RELEASES
    //    the nonterminal single-flight entry as part of this same write.
    intent.outcome = terminal;
    intent.terminal_at_ns = Some(now_ns);
    put_intent(&key, &intent);
    // 2. Only now, with the terminal state durable, release the bytes.
    intent.wasm_bytes = None;
    intent.arg_bytes = None;
    put_intent(&key, &intent);
}

/// R3.7/R3.11 — the proposer withdraws their OWN pending recovery proposal.
/// Proposer-scoped: a recovery member who is not the proposer gets the typed
/// `NotProposer`, never a silent success and never a veto over a peer.
pub fn cancel_recovery_proposal(
    caller: &Principal,
    proposal_id: u64,
    now_ns: u64,
) -> Result<(), RecoveryError> {
    require_member(caller)?;
    let stored =
        get_stored_proposal(proposal_id).ok_or(RecoveryError::UnknownProposal { proposal_id })?;
    // R1.1 (V8 §3): read the EXPLICIT proposer. Inferring it from
    // `approvals.first()` was only ever possible because propose seeded the
    // approval set; V8 strikes that seeding, so the inference now has nothing
    // to read and would make every cancel fail closed as NotProposer.
    let proposer = match &stored {
        StoredProposal::Recovery { proposal, .. } => Some(proposal.proposer),
        StoredProposal::Rotation(r) => Some(r.proposer),
    };
    if proposer != Some(*caller) {
        return Err(RecoveryError::NotProposer);
    }
    let (outcome, _) = stored_state(&stored);
    if !outcome.is_reapable() {
        return Err(RecoveryError::AlreadyTerminal);
    }
    reap_stored_pending(proposal_id, &stored, ActionOutcome::Cancelled, now_ns);
    Ok(())
}

/// R3.8/R3.11 — the bounded expiry sweep for recovery proposals. Work is
/// bounded by `limit` and by the ordered due-prefix, so the sweep can never
/// itself become the denial of service it exists to prevent.
pub fn sweep_expired_recovery_proposals(now_ns: u64, limit: usize) -> Vec<u64> {
    let due: Vec<u64> = RECOVERY_PROPOSAL_EXPIRY_INDEX.with(|x| {
        x.borrow()
            .iter()
            .take_while(|((exp, _), _)| *exp <= now_ns)
            .take(limit)
            .map(|((_, id), _)| id)
            .collect()
    });
    let mut reaped = Vec::new();
    for id in due {
        let Some(stored) = get_stored_proposal(id) else { continue };
        let (outcome, _) = stored_state(&stored);
        // PRECEDENCE (amended R3 item 10): history establishes EXISTENCE and
        // immutable TERMINAL OUTCOMES; the companion AUTHORIZES ACTIVE
        // membership. Neither is rebuilt from the other. Re-reading the record
        // here resolves the record's own class, not the companion's authority.
        if !outcome.is_reapable() {
            continue;
        }
        reap_stored_pending(id, &stored, ActionOutcome::Expired, now_ns);
        reaped.push(id);
    }
    reaped
}

// S5B W2(c): `rebuild_nonterminal_intent_index` was REMOVED, for the same
// reason the expiry rebuild above was — it decoded every UpgradeIntent ever
// written. The pointer is an authoritative companion; nothing rebuilds it.

// ── Single-flight lock (SSA L2-5, CRITICAL) ──────────────────────────────────
//
// Exactly ONE nonterminal upgrade intent may exist at a time, across BOTH
// origin namespaces: a second in-flight intent breaks objective
// reconciliation (if intent A is OutcomeUnknown and intent B changed the
// module, mismatched-hash evidence can no longer prove A failed). The lock
// is READ FROM THE AUTHORITATIVE COMPANION on every check — there is no
// heap-only guard to lose at upgrade — and `post_upgrade` revalidates the
// invariant against durable state (traps on violation).
//
// Nonterminal = Pending | Executing | OutcomeUnknown. Release happens ONLY
// at Executed | Failed (direct finalization or reconciliation).
/// R3.9 — reads the authoritative companion instead of scanning every intent ever made.
/// Bounded by the single-flight invariant (at most one nonterminal intent),
/// not by how many terminal intents have accumulated.
// ── S6 corrective (CUST-SSA-S6-01) — C6/C8 on the RECOVERY plane ─────────────
//
// The recovery plane had no byte enforcement at all. Its retained artifact is
// the `UpgradeIntent`'s `wasm_bytes`/`arg_bytes` — the SOLE artifact working
// store on this plane, because the `RecoveryProposal` stores `redact_action`
// and therefore holds no second copy. That is the "every retained artifact
// copy" clause discharged by enumeration, not by assumption: `put_intent` is
// the single write path for `UPGRADE_INTENTS`, so there is one store to cover.
//
// SUMMED, NOT ACCOUNTED — and deliberately unlike the Vault.
//
// The Vault needed durable incremental counters because summing there means
// decoding up to C7 = 320 artifact-bearing PERMANENT HISTORY records, which
// amended item 10 clause (c) forbids. Here the live set is
// `NONTERMINAL_INTENT_INDEX`, a BOUNDED ACTIVE-SET COMPANION — precisely what
// clause (c) permits — and single-flight admits at most ONE nonterminal intent
// across both origin namespaces. So the sum is over a set of size <= 1 in
// practice and bounded by the index in principle.
//
// Summing is the better choice where it is available: it cannot drift. The
// Vault's counters can, which is why they are sealed and reconciled; this has
// no such failure mode because there is nothing to keep in step.

/// Retained artifact bytes on the recovery plane, optionally for one member.
///
/// Attribution reads the proposal for each nonterminal intent by id — a bounded
/// number of POINT READS over the active set, never a scan.
fn recovery_retained_bytes(who: Option<Principal>) -> u64 {
    let keys: Vec<IntentKey> =
        NONTERMINAL_INTENT_INDEX.with(|x| x.borrow().iter().map(|(k, _)| k).collect());
    let mut total = 0u64;
    for k in keys {
        let Some(intent) = get_intent(&k) else { continue };
        let bytes = intent_artifact_bytes(&intent);
        if bytes == 0 {
            continue;
        }
        match who {
            None => total = total.saturating_add(bytes),
            Some(w) => {
                let owner = get_stored_proposal(intent.id).map(|s| stored_proposer(&s));
                if owner == Some(w) {
                    total = total.saturating_add(bytes);
                }
            }
        }
    }
    total
}

/// The retained-artifact domain for one intent — the recovery plane's
/// counterpart to the Vault's `c8_logical_bytes`, and the same scope: the bytes
/// that `wasm_bytes = None` releases, not the record envelope.
fn intent_artifact_bytes(intent: &UpgradeIntent) -> u64 {
    let w = intent.wasm_bytes.as_ref().map(|b| b.len()).unwrap_or(0);
    let a = intent.arg_bytes.as_ref().map(|b| b.len()).unwrap_or(0);
    (w + a) as u64
}

/// C6/C8 admission check for the recovery plane. Runs BEFORE the C9 charge and
/// before id allocation, matching the Vault's ordering, so a byte-refused
/// request burns no rate budget and consumes no id.
fn check_recovery_retained_bytes(
    who: Principal,
    action: &RecoveryAction,
) -> Result<(), RecoveryError> {
    let delta = match action {
        RecoveryAction::TriggerVaultUpgrade { wasm_bytes, arg_bytes, .. } => {
            (wasm_bytes.len() + arg_bytes.len()) as u64
        }
        // Reconciliation carries objective evidence, not an artifact; the
        // proposal is stored redacted and no intent artifact is created.
        // Classified explicitly rather than by a catch-all, for the same reason
        // `c8_logical_bytes` is exhaustive on the Vault: a future
        // artifact-bearing variant is classified here explicitly, not by default.
        RecoveryAction::ReconcileVaultUpgrade { .. } => 0,
        // §S7 cell 4. A start carries NO artifact: `StartVault` is a unit
        // variant with no payload at all, and `ReconcileVaultStart` carries
        // fixed-shape objective evidence, not bytes. Both are classified
        // EXPLICITLY as zero rather than swept into a catch-all, for the same
        // reason the two variants above are: a future artifact-bearing variant
        // must fail to compile here rather than default to zero quota.
        RecoveryAction::StartVault | RecoveryAction::ReconcileVaultStart { .. } => 0,
    };
    if delta == 0 {
        return Ok(());
    }
    let mine = recovery_retained_bytes(Some(who)).saturating_add(delta);
    if mine > stsh_custody_types::PER_SIGNER_BYTE_QUOTA {
        return Err(RecoveryError::SizeLimitExceeded {
            encoded_bytes: mine,
            limit_bytes: stsh_custody_types::PER_SIGNER_BYTE_QUOTA,
        });
    }
    let total = recovery_retained_bytes(None).saturating_add(delta);
    if total > stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA {
        return Err(RecoveryError::SizeLimitExceeded {
            encoded_bytes: total,
            limit_bytes: stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA,
        });
    }
    Ok(())
}

/// Read-only view of the recovery plane's retained-byte limbs, for the
/// finding-2 evidence set: `None` = the C8 global limb, `Some(who)` = that
/// member's C6 limb.
///
/// Deliberately an OBSERVER, not an injection hook — it reads the same function
/// admission reads and can move nothing. The dispatch's "no test-only injection
/// hooks" constraint is about manufacturing states the mechanism would not
/// produce; asserting on the real accounting is the opposite of that.
#[cfg(any(test, feature = "testing"))]
pub fn recovery_retained_bytes_for_test(who: Option<Principal>) -> u64 {
    recovery_retained_bytes(who)
}

fn nonterminal_intent_in_flight(except: Option<&IntentKey>) -> bool {
    // S5B W2(e) — this is an ABSENCE-DEPENDENT read: returning `false` admits a
    // new intent. A silently-emptied pointer would therefore admit a second
    // concurrent upgrade against the same target, so the companion is proved
    // intact before its silence is believed.
    //
    // W2 row 3, INTENT CLASS — the split the brief calls for. On the proposal
    // class a nonterminal record without its registry entry is inactive
    // corruption scoped to that proposal. Here it is worse: the pointer is the
    // ONLY record of which intent holds the single-flight lock, and it is not
    // scoped to one origin. So the failure is a GLOBAL INTENT-ADMISSION HOLD
    // ACROSS BOTH ORIGIN NAMESPACES — Vault-originated and recovery-originated
    // alike — rather than a per-record fault. `companion_validate` traps, which
    // refuses every admission path at once. That is the intended blast radius:
    // admitting on either origin while the pointer is untrustworthy is exactly
    // the concurrent-module-mutation hazard the lock exists to prevent.
    companion_validate();
    NONTERMINAL_INTENT_INDEX
        .with(|x| x.borrow().iter().map(|(k, _)| k).find(|k| except != Some(k)))
        .is_some()
}

/// Revalidation pass for post_upgrade: the durable intent map must satisfy
/// the single-flight invariant. Fail-closed — a violation is durable
/// corruption, never a resumable state.
fn revalidate_single_flight() {
    // S5B W2(c)/(d): validate the companions, never rebuild them. The former
    // code re-derived both indexes from permanent history FIRST and then
    // validated the result — which is exactly the authority inversion amended
    // item 10 removes, and (c) forbids the history pass regardless. A
    // companion that disagrees with its accounting is durable corruption and
    // traps here.
    companion_validate();
    let nonterminal = NONTERMINAL_INTENT_INDEX.with(|x| x.borrow().iter().count());
    if nonterminal > 1 {
        ic_cdk::trap(
            "UPGRADE_INTENTS: single-flight invariant violated — more than one nonterminal \
             intent in durable state, refusing to resume",
        );
    }
}

// ── Proposal storage helpers ─────────────────────────────────────────────────

pub(crate) fn get_stored_proposal(proposal_id: u64) -> Option<StoredProposal> {
    RECOVERY_PROPOSALS.with(|m| {
        m.borrow()
            .get(&proposal_id)
            .map(|raw| candid::decode_one(&raw).expect("StoredProposal decodes"))
    })
}

/// The SINGLE write path for `RECOVERY_PROPOSALS`, and therefore the only
/// place the authoritative expiry companion is maintained (amended R3 item 10) — callers cannot write
/// a proposal without reconciling its index entry.
fn put_stored_proposal(proposal_id: u64, stored: &StoredProposal) {
    let prior = get_stored_proposal(proposal_id);
    reindex_stored_proposal(proposal_id, prior.as_ref(), stored);
    RECOVERY_PROPOSALS.with(|m| {
        m.borrow_mut()
            .insert(proposal_id, candid::encode_one(stored).expect("StoredProposal encodes"));
    });
}

// S5B W1 — the counter is the sole allocation authority on this plane too.
//
// The old form read `.next_back()` off `RECOVERY_PROPOSALS`. That was a
// BOUNDED read rather than a full scan, which is why the brief tolerated it
// "only until" the companion work landed — but it is still HISTORY acting as
// allocation authority, which W1.1 forbids outright, and a terminal-record
// retention policy that ever pruned the tail would silently hand back a
// previously-committed id.
fn next_proposal_id() -> u64 {
    // W1.6 — inline validation before every allocation.
    companion_validate();
    let id = companion_load().next_proposal_id;
    assert_proposal_id_absent(id);
    id
}

/// W1.4 — the allocated id must be ABSENT before anything is written to it.
/// An occupied key is corruption, not a retry, and must trap BEFORE the
/// overwrite. Defence in depth: the seal is the primary integrity mechanism
/// (W1.6), because a counter lowered into an unused historical gap would sail
/// past this check.
fn assert_proposal_id_absent(proposal_id: u64) {
    if RECOVERY_PROPOSALS.with(|m| m.borrow().contains_key(&proposal_id)) {
        ic_cdk::trap(
            "RECOVERY_PROPOSALS: allocated id already occupied — durable corruption, \
             refusing to overwrite (W1.4)",
        );
    }
}

/// Advance the recovery-proposal counter, checked (W1.7).
fn commit_proposal_id(allocated: u64) {
    let mut s = companion_load();
    if s.next_proposal_id != allocated {
        ic_cdk::trap(
            "ID ALLOCATION: committing an id other than the one allocated — the \
             per-map primitive was bypassed. Fail closed (W1.4).",
        );
    }
    s.next_proposal_id = s
        .next_proposal_id
        .checked_add(1)
        .unwrap_or_else(|| ic_cdk::trap("ID ALLOCATION: id space exhausted — never wrap (W1.7)"));
    companion_seal(&mut s);
    companion_store(&s);
}

fn append_approval_log(proposal_id: u64, approver: &Principal, now_ns: u64) {
    RECOVERY_APPROVALS.with(|a| {
        let mut map = a.borrow_mut();
        let seq = map.len();
        map.insert(
            seq,
            candid::encode_one(&ApprovalLogEntry {
                proposal_id,
                approver: *approver,
                at_ns: now_ns,
            })
            .expect("ApprovalLogEntry encodes"),
        );
    });
}

/// Quorum check over DISTINCT CURRENT members — approvals from principals no
/// longer in the durable set never count (stale recovery set fails closed).
/// Returns the sorted current-member approver set for attribution.
fn quorum_approvers(approvals: &[Principal]) -> Vec<Principal> {
    let members = RECOVERY_MEMBERS.with(|m| m.borrow().clone());
    let distinct: std::collections::BTreeSet<Principal> = approvals
        .iter()
        .filter(|p| members.contains(p))
        .copied()
        .collect();
    distinct.into_iter().collect()
}

fn quorum_reached(approvals: &[Principal]) -> bool {
    let threshold = RECOVERY_THRESHOLD.with(|t| *t.borrow());
    (quorum_approvers(approvals).len() as u32) >= threshold
}

// ── trigger_vault_upgrade (Vault-originated) ─────────────────────────────────

/// Begin a Vault-originated Vault upgrade. Caller MUST be the durably-recorded
/// Vault counterpart — a spoofed caller is rejected. The durable intent is
/// written (in `Executing`, binding the delivered bytes) BEFORE this returns
/// the plan, i.e. before the first inter-canister call. Replay with the same
/// request id returns the prior outcome and issues no plan. Single-flight
/// (SSA L2-5): rejected while ANY nonterminal intent exists in either
/// namespace — replay of the SAME intent is checked first and is not a new
/// flight.
pub fn trigger_begin(
    caller: &Principal,
    request_id: u64,
    expected_wasm_hash: Vec<u8>,
    expected_arg_hash: Vec<u8>,
    wasm_bytes: Vec<u8>,
    arg_bytes: Vec<u8>,
    now_ns: u64,
) -> Result<(TriggerUpgradeResult, Option<InstallPlan>), RecoveryError> {
    let vault = require_vault_caller(caller)?;
    let key = IntentKey::vault(request_id);

    if let Some(prior) = get_intent(&key) {
        // Replay returns the prior result — never re-triggerable. An id
        // reused with a DIFFERENT payload is a conflict, not a replay.
        if prior.expected_wasm_hash == expected_wasm_hash
            && prior.expected_arg_hash == expected_arg_hash
            && sha256(&wasm_bytes) == prior.expected_wasm_hash
            && sha256(&arg_bytes) == prior.expected_arg_hash
        {
            return Ok((TriggerUpgradeResult { outcome: prior.outcome }, None));
        }
        return Err(RecoveryError::HashMismatch);
    }

    validate_artifact(&expected_wasm_hash, &expected_arg_hash, &wasm_bytes, &arg_bytes)?;

    // Single-flight (SSA L2-5): one nonterminal intent across both
    // namespaces. Wire classification is IllegalSourceState (the upgrade
    // plane is in a state that cannot accept a new intent).
    if nonterminal_intent_in_flight(None) {
        return Err(RecoveryError::IllegalSourceState);
    }

    let intent = UpgradeIntent {
        id: request_id,
        origin: IntentOriginView::Vault,
        expected_wasm_hash: expected_wasm_hash.clone(),
        expected_arg_hash: expected_arg_hash.clone(),
        wasm_bytes: Some(wasm_bytes.clone()),
        arg_bytes: Some(arg_bytes.clone()),
        outcome: ActionOutcome::Executing,
        created_at_ns: now_ns,
        terminal_at_ns: None,
    };
    put_intent(&key, &intent);
    append_audit(
        now_ns,
        UpgraderAuditEventKind::VaultUpgradeIntentRecorded {
            id: request_id,
            origin: IntentOriginView::Vault,
            expected_wasm_hash,
            expected_arg_hash,
        },
    );
    Ok((
        TriggerUpgradeResult { outcome: ActionOutcome::Executing },
        Some(InstallPlan { key, target: vault, wasm_module: wasm_bytes, arg: arg_bytes }),
    ))
}

/// Apply a finished management call to an intent. `Ok` → terminal `Executed`,
/// bytes cleared in the SAME `put_intent` invocation (SSA L2-1). `Err` →
/// `OutcomeUnknown`, bytes KEPT — management-call rejections cannot
/// distinguish pre- from post-execution, and the variant never retries
/// (NoRetry): the only way out is reconciliation to a terminal state.
/// Traps on an already-terminal intent: terminal state is never re-writable,
/// so no replay or second finalization can resurrect cleared bytes.
pub fn finish_intent(key: &IntentKey, result: &Result<(), String>, now_ns: u64) -> ActionOutcome {
    let mut intent = get_intent(key).unwrap_or_else(|| {
        ic_cdk::trap("finish_intent: no durable intent — plan issued without intent")
    });
    match intent.outcome {
        ActionOutcome::Executed | ActionOutcome::Failed => {
            ic_cdk::trap("finish_intent: intent already terminal — never re-writable")
        }
        ActionOutcome::Pending => {
            ic_cdk::trap("finish_intent: intent never entered Executing")
        }
        // R3: UNREACHABLE BY CONSTRUCTION. Cancelled/Expired are reachable
        // only from `Pending`, and an UpgradeIntent is created at the quorum
        // boundary — past Pending — so an intent can never carry them. Trap
        // rather than tolerate: reaching here means the durable state machine
        // has been violated, and continuing would finalize an intent whose
        // proposal was withdrawn.
        ActionOutcome::Cancelled | ActionOutcome::Expired => ic_cdk::trap(
            "finish_intent: intent is Cancelled/Expired — unreachable; intents exist only \
             past the quorum boundary and those states are Pending-only",
        ),
        ActionOutcome::Executing | ActionOutcome::OutcomeUnknown => {}
    }
    match result {
        Ok(()) => {
            intent.outcome = ActionOutcome::Executed;
            intent.terminal_at_ns = Some(now_ns);
            // Terminal evidence is durable in this same write — the artifact
            // bytes are cleared atomically with it (SSA L2-1).
            intent.wasm_bytes = None;
            intent.arg_bytes = None;
            put_intent(key, &intent);
            append_audit(
                now_ns,
                UpgraderAuditEventKind::VaultUpgradeExecuted {
                    id: intent.id,
                    origin: intent.origin,
                },
            );
        }
        Err(detail) => {
            intent.outcome = ActionOutcome::OutcomeUnknown;
            put_intent(key, &intent);
            // Rejection content is target-controlled and arrives AFTER an
            // inter-canister await: String::truncate would PANIC on a
            // mid-char boundary here, stranding the intent in Executing —
            // irreconcilable (reconcile accepts only OutcomeUnknown) and
            // permanently holding the single-flight lock (SSA HIGH). The
            // truncation is therefore byte-bounded AND UTF-8-safe.
            let d = truncate_utf8_bounded(detail, MAX_REJECT_DETAIL_BYTES);
            append_audit(
                now_ns,
                UpgraderAuditEventKind::VaultUpgradeOutcomeUnknown {
                    id: intent.id,
                    origin: intent.origin,
                    reject_detail: d,
                },
            );
        }
    }
    intent.outcome
}

// ── Reconciliation (freeze §3d contract, applied to Vault upgrades) ──────────
//
// Legal source state: OutcomeUnknown ONLY. Terminal transitions: Executed |
// Failed. Never back to Pending, never re-triggerable, never retries or
// reinstalls — this function performs NO inter-canister call, which is
// exactly why the recovery 2-of-3 fallback works with the Vault unavailable.

/// Resolution failure: unknown id vs ambiguous id (SSA L2-3) — distinct
/// outcomes, never collapsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntentResolution {
    NotFound,
    Ambiguous,
}

/// Resolve an intent id with its origin namespace bound (SSA L2-3).
/// `Some(origin)` restricts to exactly that namespace (the Vault-originated
/// endpoint is namespace-scoped by authority). `None` resolves across both
/// namespaces and REJECTS ambiguity — an id present in both is never
/// resolved by precedence.
fn resolve_intent(
    intent_id: u64,
    origin: Option<IntentOriginView>,
) -> Result<(IntentKey, UpgradeIntent), IntentResolution> {
    match origin {
        Some(IntentOriginView::Vault) => {
            let key = IntentKey::vault(intent_id);
            get_intent(&key).map(|i| (key, i)).ok_or(IntentResolution::NotFound)
        }
        Some(IntentOriginView::Recovery) => {
            let key = IntentKey::recovery(intent_id);
            get_intent(&key).map(|i| (key, i)).ok_or(IntentResolution::NotFound)
        }
        None => {
            let v = get_intent(&IntentKey::vault(intent_id));
            let r = get_intent(&IntentKey::recovery(intent_id));
            match (v, r) {
                (Some(i), None) => Ok((IntentKey::vault(intent_id), i)),
                (None, Some(i)) => Ok((IntentKey::recovery(intent_id), i)),
                // Ambiguous: exists in BOTH — reject, never prefer.
                (Some(_), Some(_)) => Err(IntentResolution::Ambiguous),
                (None, None) => Err(IntentResolution::NotFound),
            }
        }
    }
}

/// Validate reconciliation evidence (SSA L2-2). Rules:
///   * the evidence must name the recorded Vault counterpart;
///   * observed controllers must be exactly [Upgrader] (the ring invariant
///     the upgrade must preserve);
///   * observed_canister_status must be RUNNING for any terminal decision —
///     a terminal `Executed` requires evidence consistent with a live
///     upgraded canister, and a Stopping/Stopped observation describes an
///     unstable transition window that proves nothing in either direction
///     (ruled: status is validated, not ignored);
///   * temporal: created_at_ns <= observed_at_ns <= now_ns AND
///     now_ns - observed_at_ns <= MAX_EVIDENCE_AGE_NS (named constant,
///     flagged for SSA — see the constant's rationale).
fn validate_evidence(
    intent: &UpgradeIntent,
    evidence: &UpgradeObjectiveEvidence,
    vault: &Principal,
    self_id: &Principal,
    now_ns: u64,
) -> Result<(), EvidenceRejection> {
    if evidence.observed_upgrader_principal != *vault {
        return Err(EvidenceRejection::WrongPrincipal);
    }
    if evidence.observed_controllers != [*self_id] {
        return Err(EvidenceRejection::WrongControllers);
    }
    if evidence.observed_canister_status
        != stsh_custody_types::ObservedCanisterStatus::Running
    {
        return Err(EvidenceRejection::StatusNotRunning);
    }
    if evidence.observed_at_ns < intent.created_at_ns {
        return Err(EvidenceRejection::PredatesIntent);
    }
    if evidence.observed_at_ns > now_ns {
        return Err(EvidenceRejection::FutureEvidence);
    }
    if now_ns - evidence.observed_at_ns > MAX_EVIDENCE_AGE_NS {
        return Err(EvidenceRejection::EvidenceTooOld);
    }
    Ok(())
}

/// The reconciliation core. `origin` binds the intent namespace (SSA L2-3):
/// the Vault endpoint passes `Some(Vault)`; the recovery-originated variant
/// passes `None` and ambiguity rejects. Every evidence rejection carries the
/// typed `EvidenceRejection` ON THE WIRE (`RecoveryError::EvidenceRejected`,
/// frozen at 25ccbe7) and in the audit log (attribution secondary surface).
///
/// `terminal_replay` (CUST-L12-02): when set (the Vault-authorized
/// `reconcile_vault_upgrade` endpoint ONLY), an already-terminal intent
/// replays its terminal outcome as `Ok(Executed|Failed)` — READ-ONLY: no
/// intent rewrite, no audit append, no management call, never a reinstall,
/// never a byte resurrection. The state-changing transition remains
/// OutcomeUnknown→terminal ONLY; replay does not weaken that rule — it
/// changes nothing. The recovery-originated path passes `false`: its
/// behavior is unchanged (a recovery reconcile proposal referencing an
/// already-terminal intent fails closed AlreadyTerminal), keeping the
/// recovery quorum's proposals strictly one-shot.
pub fn reconcile_intent(
    intent_id: u64,
    origin: Option<IntentOriginView>,
    evidence: &UpgradeObjectiveEvidence,
    authority: ReconcileAuthorityView,
    self_id: &Principal,
    now_ns: u64,
    terminal_replay: bool,
) -> Result<ReconcileTerminalOutcome, RecoveryError> {
    let vault = vault_principal().ok_or(RecoveryError::NotAuthorized)?;
    let (key, intent) = match resolve_intent(intent_id, origin) {
        Ok(found) => found,
        Err(IntentResolution::NotFound) => {
            return Err(RecoveryError::UnknownProposal { proposal_id: intent_id })
        }
        Err(IntentResolution::Ambiguous) => {
            // Ambiguity REJECTS (SSA L2-3) — typed on the wire AND audited;
            // never a precedence-based guess.
            append_audit(
                now_ns,
                UpgraderAuditEventKind::VaultUpgradeReconcileRejected {
                    id: intent_id,
                    reason: EvidenceRejection::AmbiguousIntentId,
                    authority,
                },
            );
            return Err(RecoveryError::EvidenceRejected(
                EvidenceRejection::AmbiguousIntentId,
            ));
        }
    };

    match intent.outcome {
        ActionOutcome::OutcomeUnknown => {}
        ActionOutcome::Executed | ActionOutcome::Failed => {
            if terminal_replay {
                // READ-ONLY terminal replay (CUST-L12-02): return the durable
                // outcome without touching the intent, the audit log, or any
                // backend. The terminal record is never re-written.
                return Ok(match intent.outcome {
                    ActionOutcome::Executed => ReconcileTerminalOutcome::Executed,
                    _ => ReconcileTerminalOutcome::Failed,
                });
            }
            return Err(RecoveryError::AlreadyTerminal)
        }
        ActionOutcome::Pending | ActionOutcome::Executing => {
            return Err(RecoveryError::IllegalSourceState)
        }
        // R3: terminal, but NEVER an execution outcome. A cancelled or expired
        // proposal made no inter-canister call, so there is nothing to
        // reconcile and no prior result to replay. Deliberately NOT folded
        // into the Executed|Failed arm above: that arm's replay maps anything
        // non-Executed to `Failed`, which would report a withdrawn proposal as
        // a failed execution — a false statement about the world.
        ActionOutcome::Cancelled | ActionOutcome::Expired => {
            return Err(RecoveryError::IllegalSourceState)
        }
    }

    if let Err(reason) = validate_evidence(&intent, evidence, &vault, self_id, now_ns) {
        append_audit(
            now_ns,
            UpgraderAuditEventKind::VaultUpgradeReconcileRejected {
                id: intent_id,
                reason: reason.clone(),
                authority,
            },
        );
        return Err(RecoveryError::EvidenceRejected(reason));
    }

    // Hash-bound decision: the live module matching the approved hash is
    // objective proof of execution; anything else (a different live module,
    // or no module at all) means the recorded upgrade did not land.
    let outcome = if evidence.observed_module_hash.as_deref()
        == Some(intent.expected_wasm_hash.as_slice())
    {
        ReconcileTerminalOutcome::Executed
    } else {
        ReconcileTerminalOutcome::Failed
    };

    let mut updated = intent.clone();
    updated.outcome = match outcome {
        ReconcileTerminalOutcome::Executed => ActionOutcome::Executed,
        ReconcileTerminalOutcome::Failed => ActionOutcome::Failed,
    };
    updated.terminal_at_ns = Some(now_ns);
    // Terminal evidence durable in this SAME write — bytes cleared
    // atomically (SSA L2-1). OutcomeUnknown retained them; terminal never does.
    updated.wasm_bytes = None;
    updated.arg_bytes = None;
    put_intent(&key, &updated);
    append_audit(
        now_ns,
        UpgraderAuditEventKind::VaultUpgradeReconciled {
            id: intent.id,
            origin: intent.origin,
            outcome,
            authority,
        },
    );
    Ok(outcome)
}

/// Vault-originated reconciliation entrypoint (`reconcile_vault_upgrade`).
/// Caller must be the Vault; the endpoint is namespace-scoped by authority —
/// it can only ever target Vault-originated intents (SSA L2-3). Terminal
/// intents REPLAY read-only (CUST-L12-02): Ok(Executed|Failed), no mutation.
pub fn reconcile_vault_upgrade(
    caller: &Principal,
    request_id: u64,
    evidence: &UpgradeObjectiveEvidence,
    self_id: &Principal,
    now_ns: u64,
) -> Result<ReconcileTerminalOutcome, RecoveryError> {
    require_vault_caller(caller)?;
    reconcile_intent(
        request_id,
        Some(IntentOriginView::Vault),
        evidence,
        ReconcileAuthorityView::Vault,
        self_id,
        now_ns,
        true,
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// §S7 START SETTLEMENT — CELL 4 (Upgrader → Vault), CUST-SSA-004
//
// The twin of the Vault's cell 3. Every predicate below is imported from
// `stsh_custody_types` and is the SAME CODE the Vault runs; what lives here is
// only the plane-specific storage and audit. That split is deliberate: it is
// what makes "the builder must not implement the two directions differently"
// (V5 §0) a structural property rather than a review obligation.
// ═════════════════════════════════════════════════════════════════════════════

/// Read a stored recovery proposal that carries start state.
fn get_start_proposal(proposal_id: u64) -> Option<(u64, RecoveryProposal)> {
    match get_stored_proposal(proposal_id) {
        Some(StoredProposal::Recovery { epoch, proposal }) if proposal.start.is_some() => {
            Some((epoch, proposal))
        }
        _ => None,
    }
}

/// §2 — is another START already in flight?
///
/// The upgrade single-flight check (`nonterminal_intent_in_flight`) covers
/// UPGRADE intents only, so on its own it would admit a second concurrent start
/// against the same target. §2 forbids exactly that pairing, because concurrent
/// module mutation "would destroy the attributability of the status evidence in
/// §4" — and two concurrent starts are indistinguishable in the evidence for
/// the same reason. Both checks are therefore required, and both run before the
/// intent is written.
///
/// Bounded: it iterates the NONTERMINAL recovery-proposal index (MemoryId 10),
/// whose size is capped by the nonterminal caps, not the permanent proposal
/// history.
fn start_in_flight(except: Option<u64>) -> bool {
    // Absence-dependent read, same class as `nonterminal_intent_in_flight`:
    // returning `false` ADMITS a new start, so the companion is proved intact
    // before its silence is believed.
    companion_validate();
    NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|x| {
        x.borrow().iter().any(|((_, id), _)| {
            if except == Some(id) {
                return false;
            }
            matches!(
                get_start_proposal(id),
                Some((_, p)) if p.outcome.holds_single_flight()
            )
        })
    })
}

/// §3a — apply a finished `start_canister` call to a start proposal.
///
/// **THIS IS THE CALLBACK, AND IT IS ADVISORY, NEVER AUTHORITATIVE (§3c).**
/// It re-reads the DURABLE state first and writes settlement state if and only
/// if that state is exactly `Executing`. It never acts on an in-memory
/// expectation formed before an upgrade — such an expectation cannot survive
/// one, and the IC interface specification is explicit that outstanding
/// callbacks CAN execute after an upgrade under the new code (§3c.1).
///
/// Two edges, and only these two:
///   * `Ok` — observed success in the reply callback ⇒ `Executed` [terminal].
///     No `SettlementRecord`: no §4 evidence existed.
///   * `Err` — **E1**: transport rejection, or ANY reply that does not
///     objectively establish success ⇒ `OutcomeUnknown`, IN THIS SAME MESSAGE,
///     atomically. **NEVER BLINDLY `Failed`** (acceptance 1) — a management-call
///     rejection cannot distinguish pre- from post-execution, so inferring
///     failure from it is precisely the assumption R-2 forecloses.
pub fn finish_start(proposal_id: u64, result: &Result<(), String>, now_ns: u64) -> ActionOutcome {
    let (epoch, proposal) = get_start_proposal(proposal_id).unwrap_or_else(|| {
        ic_cdk::trap("finish_start: no durable start proposal — plan issued without intent")
    });

    // ── §3c.2 THE GUARD ──────────────────────────────────────────────────────
    //
    // Fenced states and their behaviour, per §3c.2's table:
    //   OutcomeUnknown  — the E2 sweep already ran;
    //   Executed/Failed — already settled, single-shot;
    //   Cancelled/Expired/Pending — unreachable with a live intent, illegal.
    // In EVERY fenced case: zero settlement-state mutation, zero lock change,
    // no terminalization, no second audit of the settlement. One bounded
    // `LateCallbackFenced` event (§3c.3), and nothing else.
    //
    // A FENCED CALLBACK'S PAYLOAD IS NEVER EVIDENCE. It cannot terminalize,
    // cannot influence a later reconcile, and is not retained — which is why
    // `result` is not read at all on this branch. Admitting it would
    // reintroduce an un-evidenced settlement path, exactly what R-2 forecloses.
    if !callback_may_write(proposal.outcome) {
        append_audit(
            now_ns,
            UpgraderAuditEventKind::LateCallbackFenced {
                proposal_id,
                observed_state: proposal.outcome,
            },
        );
        return proposal.outcome;
    }

    let mut updated = proposal;
    match result {
        Ok(()) => {
            updated.outcome = ActionOutcome::Executed;
            put_stored_proposal(
                proposal_id,
                &StoredProposal::Recovery { epoch, proposal: updated },
            );
            append_audit(now_ns, UpgraderAuditEventKind::VaultStartExecuted { proposal_id });
            ActionOutcome::Executed
        }
        Err(detail) => {
            updated.outcome = ActionOutcome::OutcomeUnknown;
            put_stored_proposal(
                proposal_id,
                &StoredProposal::Recovery { epoch, proposal: updated },
            );
            // Rejection content is target-controlled and arrives AFTER an
            // inter-canister await, so the truncation is byte-bounded AND
            // UTF-8-safe — `String::truncate` would panic on a mid-char
            // boundary and strand the proposal in `Executing`, which is
            // irreconcilable (§3 admits only `OutcomeUnknown`) and would hold
            // the single-flight lock forever.
            append_audit(
                now_ns,
                UpgraderAuditEventKind::VaultStartOutcomeUnknown {
                    proposal_id,
                    reject_detail: truncate_utf8_bounded(detail, MAX_REJECT_DETAIL_BYTES),
                },
            );
            ActionOutcome::OutcomeUnknown
        }
    }
}

/// §3a **E2 — the post-upgrade sweep.**
///
/// Every proposal durably in `Executing` holding a start-intent is promoted to
/// `OutcomeUnknown`. It takes **no evidence**, writes **no terminal outcome**,
/// releases **no lock**, and is **idempotent** (acceptance 12).
///
/// E2'S ACTUAL JUSTIFICATION (§3c.2) — NOT callback non-delivery, which was V2's
/// false claim and is withdrawn. E2 does not assert the call is over. It asserts
/// that ACROSS AN UPGRADE BOUNDARY THE CANISTER CAN NO LONGER RELY ON ITS
/// IN-MEMORY EXPECTATION OF A REPLY, so the proposal must be moved to the state
/// that demands objective evidence. The promotion is CONSERVATIVE: it only ever
/// moves a proposal from a state where a callback MAY write to a state where no
/// callback may write. Combined with §3c.2, correctness does not depend on
/// whether late delivery actually occurs — the contract is sound under BOTH
/// readings of the platform's behaviour.
///
/// There is deliberately no third promotion: no timeout, no heartbeat, no
/// operator-invoked "declare unknown". Each would infer a call's fate from
/// elapsed time — the assumption R-2 forecloses.
pub fn sweep_executing_starts_to_unknown(now_ns: u64) {
    let ids: Vec<u64> = NONTERMINAL_RECOVERY_PROPOSAL_INDEX
        .with(|x| x.borrow().iter().map(|((_, id), _)| id).collect());
    for id in ids {
        let Some((epoch, mut proposal)) = get_start_proposal(id) else {
            continue;
        };
        // Idempotent by this guard: a second upgrade finds `OutcomeUnknown`,
        // not `Executing`, and changes nothing.
        if proposal.outcome != ActionOutcome::Executing {
            continue;
        }
        proposal.outcome = ActionOutcome::OutcomeUnknown;
        put_stored_proposal(id, &StoredProposal::Recovery { epoch, proposal });
        append_audit(
            now_ns,
            UpgraderAuditEventKind::VaultStartSweptToUnknown { proposal_id: id },
        );
    }
}

/// §7f — the start-settlement reconciliation core for cell 4.
///
/// Performs NO inter-canister call, which is exactly why the 2-of-3 recovery
/// fallback works with the Vault unavailable.
///
/// The gate ORDER is not implemented here: it is `classify_start_reconcile`,
/// the single shared function both directions call. This function only applies
/// the disposition it returns. That separation is what makes acceptance 15(a) —
/// four distinct typed errors, IDENTICAL ACROSS DIRECTIONS — true by
/// construction rather than by parallel maintenance of two gate ladders.
/// **RETURN SHAPE, AND WHY `Option` RATHER THAN A NEW ERROR VARIANT.**
/// `Ok(Some(outcome))` = settled; `Ok(None)` = §5's inconclusive `Stopping`
/// observation from `OutcomeUnknown`; `Err` = the §7f gates and §7c replays.
///
/// V5 pins the inconclusive branch's BEHAVIOUR exactly — no transition, zero
/// mutation, lock retained, no audit append (§5, §7e, acceptance 5) — but it
/// never names a wire error for it, and acceptance 15(a)'s four required
/// distinct typed errors do not include this case. Rather than invent an error
/// variant with no authorizing clause, the "no settlement yet" fact is carried
/// in the RETURN TYPE, which §4 explicitly leaves to the builder ("Whether that
/// is a new type or a reuse is the builder's call"). `Ok(None)` also states
/// §5's own words — "No settlement. Not terminal — inconclusive... re-observe
/// later" — without asserting a failure that did not occur.
///
/// This is NOT the success-shaped replay §7c forbids: that prohibition is
/// scoped to REPLAYS, and every replay branch below returns
/// `AlreadySettled { outcome }`, including an inconclusive replay, exactly as
/// §7d's table requires.
pub fn reconcile_vault_start(
    target_proposal_id: u64,
    evidence: &StartObjectiveEvidence,
    authority: ReconcileAuthorityView,
    self_id: &Principal,
    now_ns: u64,
) -> Result<Option<ReconcileTerminalOutcome>, RecoveryError> {
    let found = get_start_proposal(target_proposal_id);
    // §4.3 ring invariant for THIS target: the Vault's controllers must be
    // exactly [Upgrader], and this canister IS the Upgrader.
    let required = [*self_id];

    let disposition = {
        let source = found.as_ref().map(|(_, p)| {
            let start = p.start.as_ref().expect("get_start_proposal filters on start");
            StartSourceState {
                outcome: p.outcome,
                intent: &start.intent,
                settlement: start.settlement.as_ref(),
                required_controllers: &required,
            }
        });
        classify_start_reconcile(source, evidence, now_ns)
    };

    let disposition = match disposition {
        Ok(d) => d,
        Err(StartReconcileRejection::UnknownProposal) => {
            // §7f step 1 / §7e: zero mutation, NO audit append. **Never a
            // settlement**, and never a fresh settlement of a proposal that was
            // already settled once (§8a invariant 5).
            return Err(RecoveryError::UnknownProposal { proposal_id: target_proposal_id });
        }
        Err(StartReconcileRejection::IllegalSourceState) => {
            // §7e: typed rejection, zero settlement-state mutation, NO audit
            // append — nothing was ever settled, so there is no integrity fact
            // to record. It also does NOT release the single-flight lock (§3).
            return Err(RecoveryError::IllegalSourceState);
        }
        Err(StartReconcileRejection::EvidenceRejected(reason)) => {
            // §7f step 3 / §7e: zero settlement-state mutation, zero
            // dedup-state write, lock retained, `conflict_recorded` UNTOUCHED,
            // and **NO AUDIT APPEND**.
            //
            // P1-3: this arm previously appended a rejection event, justified
            // by the §3d upgrade path's precedent. THAT JUSTIFICATION WAS
            // WRONG. §7a permits appends ONLY where this contract explicitly
            // requires them, and §7e and §7f step 3 both state in terms that
            // rejected evidence produces no append. An upgrade-plane precedent
            // does not override the start contract — and the reason the rule
            // exists is concrete: `reconcile` is reachable by a quorum that can
            // resubmit, so an append here is an un-prunable log reached by a
            // repeatable path, which is the griefing surface §7a names.
            // The typed classification still rides the wire, which is where
            // §7f step 3 puts it.
            return Err(RecoveryError::EvidenceRejected(reason));
        }
    };

    let (epoch, proposal) = found.expect("a disposition implies the proposal resolved");

    match disposition {
        // §7e — inconclusive `Stopping` observation from `OutcomeUnknown`: NO
        // transition, zero mutation, lock RETAINED, NO audit append. Not a
        // transition, so §5's append rule does not fire.
        StartReconcileDisposition::Inconclusive => Ok(None),

        // §7b/§8/§8a — THE terminal transition, at most once per proposal.
        //
        // **ONE ATOMIC DURABLE TRANSITION (§0b).** The terminal outcome, the
        // intent terminalization, the lock release and the `SettlementRecord`
        // all land in the SINGLE `put_stored_proposal` call below: one
        // synchronous message execution, NO `await` and no message boundary
        // between any of them, committing or rolling back together. There is no
        // interleaving in which this proposal is terminal without its record
        // (§8a invariant 1), and the record is durable before the lock release
        // is observable (invariant 2) because the lock release IS part of the
        // same write — a property of the single transition, not a two-write
        // ordering rule that a crash could split.
        StartReconcileDisposition::Settle(outcome) => {
            let mut updated = proposal;
            updated.outcome = match outcome {
                ReconcileTerminalOutcome::Executed => ActionOutcome::Executed,
                ReconcileTerminalOutcome::Failed => ActionOutcome::Failed,
            };
            let start = updated.start.as_mut().expect("start state present");
            debug_assert!(
                start.settlement.is_none(),
                "§7b: reconciliation terminalizes at most once per proposal"
            );
            start.settlement = Some(SettlementRecord::settle(outcome, evidence));
            put_stored_proposal(
                target_proposal_id,
                &StoredProposal::Recovery { epoch, proposal: updated },
            );
            append_audit(
                now_ns,
                UpgraderAuditEventKind::VaultStartSettled {
                    proposal_id: target_proposal_id,
                    outcome,
                    authority,
                },
            );
            Ok(Some(outcome))
        }

        // §7d concordant / inconclusive replay — zero settlement-state
        // mutation, zero dedup-state write, ZERO AUDIT APPEND.
        //
        // The audit silence is normative, not an omission: §7a permits appends
        // ONLY where the contract requires them, "because an un-prunable log
        // reached by a caller-repeatable path is a griefing surface". A
        // concordant replay is ordinary re-observation and is not an event.
        StartReconcileDisposition::ReplayConcordant { stored }
        | StartReconcileDisposition::ReplayInconclusive { stored } => {
            Err(RecoveryError::AlreadySettled { outcome: stored })
        }

        // §7d DISCORDANT replay — **NO RE-OPEN**, identical error shape.
        StartReconcileDisposition::ReplayDiscordant {
            stored,
            replay_mapped,
            cap_available,
        } => {
            if cap_available {
                // §7d.1 — ONE ATOMIC DURABLE TRANSITION (§0b): the
                // `conflict_recorded: false → true` transition and the audit
                // append occur in the SAME synchronous message execution, with
                // no `await` and no message boundary between them, committing
                // or rolling back together. Structure count is irrelevant — the
                // proposal map and the audit log are separate stable structures
                // and still satisfy this.
                //
                // Both interleavings an `await` here would admit are
                // impermissible: MARKER WITHOUT EVENT silences every future
                // discordance while nothing was recorded (the exact failure
                // CUST-SSA-V3-01 guards against), and EVENT WITHOUT MARKER makes
                // a second event possible, breaking the §7d cap.
                let conflict = {
                    let start = proposal.start.as_ref().expect("start state present");
                    let record = start.settlement.as_ref().expect("discordance implies settled");
                    // Fields 2–4 are READ FROM THE STORED RECORD, never
                    // recomputed from live state (§8a invariant 6).
                    SettlementEvidenceConflict::new(
                        target_proposal_id,
                        record,
                        evidence,
                        replay_mapped,
                    )
                };
                let mut updated = proposal;
                {
                    let start = updated.start.as_mut().expect("start state present");
                    let record = start.settlement.as_mut().expect("discordance implies settled");
                    record.conflict_recorded = true;
                }
                put_stored_proposal(
                    target_proposal_id,
                    &StoredProposal::Recovery { epoch, proposal: updated },
                );
                append_audit(
                    now_ns,
                    UpgraderAuditEventKind::SettlementEvidenceConflictRecorded { conflict },
                );
            }
            // Every subsequent discordance appends nothing and writes nothing —
            // and returns the SAME shape as a concordant replay, because §7c
            // requires one error shape for every replay branch.
            Err(RecoveryError::AlreadySettled { outcome: stored })
        }
    }
}

// ── Recovery protocol (own durable membership, fixed threshold 2) ────────────

fn action_tag(action: &RecoveryAction) -> RecoveryActionTag {
    match action {
        RecoveryAction::TriggerVaultUpgrade { .. } => RecoveryActionTag::TriggerVaultUpgrade,
        RecoveryAction::ReconcileVaultUpgrade { .. } => RecoveryActionTag::ReconcileVaultUpgrade,
        RecoveryAction::StartVault => RecoveryActionTag::StartVault,
        RecoveryAction::ReconcileVaultStart { .. } => RecoveryActionTag::ReconcileVaultStart,
    }
}

/// The redacted stored form of a recovery action (SSA L2-1): hashes and
/// metadata only — artifact bytes live solely in the intent.
/// R1.2 — the CANONICAL, byte-free form of a stored proposal.
///
/// For a recovery action this is the ALREADY-REDACTED action: `redact_action`
/// empties the artifact vectors at store time, and the canonical form is
/// defined over exactly that. Artifact bytes therefore enter the commitment
/// through their hashes (which `RecoveryAction` already carries) and never
/// their contents, so redaction cannot move the commitment — the same identity
/// the Vault gets from `cleared_action`.
fn canonical_stored_bytes(stored: &StoredProposal) -> Vec<u8> {
    match stored {
        StoredProposal::Recovery { proposal, .. } => {
            candid::encode_one(&redact_action(&proposal.action)).expect("canonical action encodes")
        }
        // Rotation carries no artifact bytes at all; the proposed member set IS
        // the security-critical payload — and it is the ORIGINAL Critical's
        // attack path, so it must be inside the digest.
        StoredProposal::Rotation(r) => {
            candid::encode_one(&r.new_members).expect("canonical members encode")
        }
    }
}

/// R1.2 — the commitment for a stored proposal's CURRENT retained state.
/// `epoch` is the proposal's RETAINED creation epoch, never current recovery
/// state (R1.5).
fn commitment_for_stored(
    proposal_id: u64,
    stored: &StoredProposal,
    self_id: &Principal,
) -> stsh_custody_types::ApprovalCommitmentV1 {
    let (epoch, expires) = match stored {
        StoredProposal::Recovery { epoch, proposal } => (*epoch, proposal.expires_at_ns),
        StoredProposal::Rotation(r) => (r.epoch, r.expires_at_ns),
    };
    stsh_custody_types::ApprovalCommitmentV1::new(
        *self_id,
        proposal_id,
        epoch,
        expires,
        canonical_stored_bytes(stored),
    )
}

/// Rewrite a stored proposal's commitment hash (creation only).
fn with_commitment(mut stored: StoredProposal, hash: Vec<u8>) -> StoredProposal {
    match &mut stored {
        StoredProposal::Recovery { proposal, .. } => proposal.commitment_hash = hash,
        StoredProposal::Rotation(r) => r.commitment_hash = hash,
    }
    stored
}

/// The stored commitment of a proposal.
pub(crate) fn stored_commitment(stored: &StoredProposal) -> Vec<u8> {
    match stored {
        StoredProposal::Recovery { proposal, .. } => proposal.commitment_hash.clone(),
        StoredProposal::Rotation(r) => r.commitment_hash.clone(),
    }
}

fn redact_action(action: &RecoveryAction) -> RecoveryAction {
    match action {
        RecoveryAction::TriggerVaultUpgrade {
            expected_wasm_hash,
            expected_arg_hash,
            ..
        } => RecoveryAction::TriggerVaultUpgrade {
            expected_wasm_hash: expected_wasm_hash.clone(),
            expected_arg_hash: expected_arg_hash.clone(),
            wasm_bytes: Vec::new(),
            arg_bytes: Vec::new(),
        },
        other => other.clone(),
    }
}

/// Propose a recovery action. Caller must be a CURRENT member of the durable
/// recovery set — the one deterministic auth path (stale/unknown principals
/// are denied). PROPOSING APPROVES NOTHING (V8 §3, CTO R-1a): the proposal is
/// created with an empty approval set and no approval-log entry, and the
/// proposer reaches quorum only through a separate explicit approve_recovery
/// call. The proposal is stamped with the current recovery epoch (approvals
/// from a
/// prior epoch are rejected — SSA L2-4). For TriggerVaultUpgrade the durable
/// intent (the sole artifact store) is created here in `Pending`, binding
/// the delivered bytes before any approval or await exists.
pub fn propose_recovery(
    caller: &Principal,
    action: RecoveryAction,
    now_ns: u64,
    requested_lifetime_ns: Option<u64>,
    self_id: &Principal,
) -> Result<u64, RecoveryError> {
    require_member(caller)?;
    // R3.1 — resolved and VALIDATED before anything durable is written, so a
    // rejected lifetime leaves no proposal and no intent behind.
    let expires_at_ns = stsh_custody_types::resolve_expiry_with(
        proposal_lifetime_bounds(),
        now_ns,
        requested_lifetime_ns,
    )
        .map_err(RecoveryError::LifetimeOutOfBounds)?;
    // ── SSA BLOCKER 2 (re-check) — CHARGE ONLY FOR REAL ENTRY EVENTS ────────
    //
    // Every NON-AUDITED validation failure must be decided BEFORE the ledger is
    // touched. The first cut charged immediately after `require_member`, so an
    // invalid lifetime, a bad artifact, or a single-flight refusal each burned
    // durable budget while producing neither an admitted operation nor an
    // audited rejection — silent quota consumption, and a violation of the
    // frozen "admission OR audited rejection" definition.
    //
    // So the artifact and single-flight checks are hoisted above allocation and
    // above the charge. They return ordinary `Err` with no audit, and must
    // therefore cost nothing.
    if let RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash,
        expected_arg_hash,
        wasm_bytes,
        arg_bytes,
    } = &action
    {
        validate_artifact(expected_wasm_hash, expected_arg_hash, wasm_bytes, arg_bytes)?;
        // Single-flight (SSA L2-5): a Pending recovery intent is itself a
        // nonterminal intent — proposing a second trigger while ANY intent
        // is Pending/Executing/OutcomeUnknown (either namespace) rejects.
        //
        // §S7 §2 — P1-1: THE TARGET LOCK IS SHARED IN BOTH DIRECTIONS.
        // `start_in_flight` was previously consulted only on the START arm, so
        // start→upgrade was admitted while upgrade→start was refused. That is
        // a one-way lock, and the direction it left open is the dangerous one:
        // an upgrade landing against the Vault while a start is outstanding is
        // exactly the concurrent module mutation §2 forbids, because it
        // destroys the attributability of the §4 status evidence — neither
        // proposal could then claim the observation.
        if nonterminal_intent_in_flight(None) || start_in_flight(None) {
            return Err(RecoveryError::IllegalSourceState);
        }
    }
    // Every non-audited refusal is now behind us: this IS an admission.
    //
    // SSA BLOCKER 1 — C12 cap → C9 charge → allocation → durable writes. The
    // cap binds FIRST: a capped admission is not an entry event, so charging
    // it would burn durable budget for an operation that never happened.
    check_nonterminal_caps(*caller)?;
    // S6 corrective (CUST-SSA-S6-01) — C6/C8 before the C9 charge and the id,
    // same ordering as the Vault.
    check_recovery_retained_bytes(*caller, &action)?;
    charge_entry_event(*caller, now_ns)?;
    let proposal_id = next_proposal_id();
    let threshold = RECOVERY_THRESHOLD.with(|t| *t.borrow());
    if let RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash,
        expected_arg_hash,
        wasm_bytes,
        arg_bytes,
    } = &action
    {
        // Sole artifact working store, Pending until quorum executes it.
        let key = IntentKey::recovery(proposal_id);
        let intent = UpgradeIntent {
            id: proposal_id,
            origin: IntentOriginView::Recovery,
            expected_wasm_hash: expected_wasm_hash.clone(),
            expected_arg_hash: expected_arg_hash.clone(),
            wasm_bytes: Some(wasm_bytes.clone()),
            arg_bytes: Some(arg_bytes.clone()),
            outcome: ActionOutcome::Pending,
            created_at_ns: now_ns,
            terminal_at_ns: None,
        };
        put_intent(&key, &intent);
        append_audit(
            now_ns,
            UpgraderAuditEventKind::VaultUpgradeIntentRecorded {
                id: proposal_id,
                origin: IntentOriginView::Recovery,
                expected_wasm_hash: expected_wasm_hash.clone(),
                expected_arg_hash: expected_arg_hash.clone(),
            },
        );
    }
    let proposal = RecoveryProposal {
        proposal_id,
        action: redact_action(&action),
        proposer: *caller,
        // R1.1 (V8 §3, CTO R-1a): proposing approves NOTHING. The commitment
        // binds the canister-assigned proposal id, which does not exist before
        // creation, so an implicit creation-time approval is NECESSARILY
        // UNBOUND — which is the CUST-SSA-001 attack path, including for
        // recovery-roster rotation. The proposer reaches quorum only through a
        // separate, hash-bound approve_recovery call, on equal terms with
        // every other member. Matches the Vault, which already writes no
        // approval at propose.
        approvals: Vec::new(),
        // §S7 §2: the start-intent is created at the QUORUM BOUNDARY, not at
        // proposal time. A `StartVault` proposal is born with no start state
        // and gains it in `approve_recovery`, durably, before the first
        // `await`. Writing an intent here would date it from proposal time,
        // and §4 freshness is evaluated AGAINST that timestamp — evidence
        // observed between proposal and quorum would then wrongly pass the
        // pre-intent check, admitting an observation that cannot describe the
        // outcome of a call not yet made.
        start: None,
        threshold,
        created_at_ns: now_ns,
        outcome: ActionOutcome::Pending,
        expires_at_ns,
        // Placeholder; replaced immediately below once the record exists to
        // compute it from — the same store-once shape as the Vault.
        commitment_hash: Vec::new(),
    };
    put_stored_proposal(
        proposal_id,
        &StoredProposal::Recovery { epoch: current_epoch(), proposal },
    );
    // R1.2 — store the commitment ONCE, at creation, immutably.
    {
        let stored = get_stored_proposal(proposal_id).expect("just-created proposal");
        let h = commitment_for_stored(proposal_id, &stored, self_id).hash();
        put_stored_proposal(proposal_id, &with_commitment(stored, h));
    }
    // RF-5 — W1 message boundary: the record is durable here, the counter is
    // not yet. A trap at this point must discard BOTH.
    rotation_trap(PROPOSE_TRAP_AFTER_INSERT_BEFORE_COUNTER);
    // S5B W1.2 — same synchronous message as the insertion above.
    commit_proposal_id(proposal_id);
    // R1.1 (V8 §3): NO approval-log entry at creation. The ProposalCreated
    // audit event below still lands — it records that a proposal exists, which
    // is not an approval.
    append_audit(
        now_ns,
        UpgraderAuditEventKind::RecoveryProposalCreated {
            proposal_id,
            proposer: *caller,
            action: action_tag(&action),
        },
    );
    Ok(proposal_id)
}

/// Propose a governed membership rotation (SSA L2-4). Fixed threshold 2,
/// validated by the SHARED validate_bootstrap_quorum: no anonymous or
/// duplicate members, >= 2 distinct members, counterpart (the Vault)
/// unchanged and never a member. Invalid memberships are rejected at
/// proposal time with the validator's exact reason in the audit log.
pub fn propose_membership_rotation(
    caller: &Principal,
    new_members: Vec<Principal>,
    now_ns: u64,
    requested_lifetime_ns: Option<u64>,
    self_id: &Principal,
) -> Result<u64, RecoveryError> {
    require_member(caller)?;
    // ── SSA BLOCKER 2 (re-check) — charge only for REAL entry events ────────
    //
    // `vault_principal()` returning None is a non-audited refusal, so it is
    // decided BEFORE the ledger is touched. The first cut charged above this
    // line and so burned budget on it.
    let vault = vault_principal().ok_or(RecoveryError::NotAuthorized)?;
    // S6 / CTO_NOTE_S5A §5 — MAX_RECOVERY_MEMBERS = 9 at the ROTATION path.
    //
    // Checked BEFORE `validate_bootstrap_quorum` so an oversize roster is
    // refused on its own terms rather than incidentally: the shared validator
    // enforces the Route-1 minimum and would admit ten distinct members
    // happily, so without this a rotation is exactly how a tenth signer would
    // arrive — the mutation path that matters most, since init is a one-time
    // event under direct operator control and this one is not.
    //
    // The entry event IS charged, so probing roster sizes costs budget exactly
    // as every other refusal on this path does.
    //
    // NO AUDIT EVENT IS APPENDED, AND THAT IS A KNOWN GAP — reported, not
    // papered over. `MembershipRotationRejected` carries an
    // `InitValidationError`, and BOTH that enum and the audit-event enum are
    // exposed in `upgrader.did` (lines 150 and 200), so adding a
    // roster-maximum variant is a DID change S6 is not authorized to make.
    // None of the existing variants is TRUE of an oversize roster:
    // `TooFewMembers` is its exact opposite, and labelling the rejection with
    // it would put a false statement into permanent audit history to make the
    // trail look complete. This campaign has twice been burned by a claim that
    // was wrong rather than a mechanism that was — an audit entry asserting the
    // wrong reason is the same failure in the place it is least recoverable.
    //
    // The wire classification is `ThresholdViolation` for the reason already
    // documented below: `RecoveryError` is frozen without a suitable variant.
    // Closing the audit gap needs a DID authorization.
    if let Err(e) = stsh_custody_types::check_recovery_roster_size(new_members.len()) {
        // S6 corrective (CUST-SSA-S6-03) — the charge and the record are now
        // ATOMIC. S6 charged the entry event and appended nothing, because no
        // existing InitValidationError variant was true of "too many"; budget
        // drained with no trace of why. The authorized `TooManyMembers` variant
        // closes it truthfully, and the append sits in the same synchronous
        // message as the charge, so the two commit or roll back together —
        // there is no ordering in which budget is consumed without a record.
        charge_entry_event(*caller, now_ns)?;
        append_audit(
            now_ns,
            UpgraderAuditEventKind::MembershipRotationRejected {
                proposer: *caller,
                reason: stsh_custody_types::InitValidationError::TooManyMembers {
                    distinct: e.requested as usize,
                    maximum: e.maximum,
                },
            },
        );
        return Err(RecoveryError::ThresholdViolation);
    }
    if let Err(reason) = validate_bootstrap_quorum(&new_members, INITIAL_THRESHOLD, &vault) {
        // An AUDITED rejection IS an entry event. Charged immediately before
        // its append, so the two commit together in this one message — and a
        // saturated refusal returns here having written NOTHING, which is what
        // makes the gate non-recursive: a rate-limited refusal does not need a
        // second audited append to record the refusal of the first.
        charge_entry_event(*caller, now_ns)?;
        append_audit(
            now_ns,
            UpgraderAuditEventKind::MembershipRotationRejected {
                proposer: *caller,
                reason: reason.clone(),
            },
        );
        // RecoveryError is frozen without a membership-validation variant;
        // ThresholdViolation is the least-wrong wire classification (the
        // precise reason is in the audit event). Reported as a freeze defect.
        return Err(RecoveryError::ThresholdViolation);
    }
    let expires_at_ns = stsh_custody_types::resolve_expiry_with(
        proposal_lifetime_bounds(),
        now_ns,
        requested_lifetime_ns,
    )
        .map_err(RecoveryError::LifetimeOutOfBounds)?;
    // Non-audited refusals are all behind us: this IS an admission.
    //
    // SSA BLOCKER 1 — C12 cap → C9 charge → allocation → durable writes, the
    // same ordering as `propose_recovery`. A Rotation proposal occupies a
    // nonterminal slot exactly as a Recovery one does.
    check_nonterminal_caps(*caller)?;
    charge_entry_event(*caller, now_ns)?;
    let proposal_id = next_proposal_id();
    let threshold = RECOVERY_THRESHOLD.with(|t| *t.borrow());
    let member_count = new_members.len() as u32;
    put_stored_proposal(
        proposal_id,
        &StoredProposal::Rotation(RotationProposal {
            proposal_id,
            epoch: current_epoch(),
            new_members,
            proposer: *caller,
            // R1.1 (V8 §3) — see propose_recovery. Rotation is the original
            // Critical's attack path, so this is the one that matters most.
            approvals: Vec::new(),
            threshold,
            created_at_ns: now_ns,
            outcome: ActionOutcome::Pending,
            expires_at_ns,
            commitment_hash: Vec::new(),
        }),
    );
    {
        let stored = get_stored_proposal(proposal_id).expect("just-created proposal");
        let h = commitment_for_stored(proposal_id, &stored, self_id).hash();
        put_stored_proposal(proposal_id, &with_commitment(stored, h));
    }
    // RF-5 — the same W1 message boundary as `propose_recovery`. BOTH
    // admission paths carry it: they have independent insert/commit sequences,
    // so evidence on one says nothing about the other.
    rotation_trap(PROPOSE_TRAP_AFTER_INSERT_BEFORE_COUNTER);
    // S5B W1.2 — counter advances in the SAME synchronous message as the
    // insertion above; a trap before this commits neither (committed-ID
    // semantics, W1.3).
    commit_proposal_id(proposal_id);
    // R1.1 (V8 §3): NO approval-log entry at creation.
    append_audit(
        now_ns,
        UpgraderAuditEventKind::MembershipRotationProposed {
            proposal_id,
            proposer: *caller,
            member_count,
        },
    );
    Ok(proposal_id)
}

/// Approve a proposal (recovery action or membership rotation). Caller must
/// be a CURRENT member. Quorum is counted over DISTINCT CURRENT members
/// only. Proposals carry the epoch they were created in — an approval
/// against a proposal from a PRIOR epoch is rejected with the typed
/// `RecoveryError::StaleEpoch` (SSA L2-4/L2-6). The quorum-reaching call
/// flips the proposal to `Executing` DURABLY before any await and is the
/// only call admitted to execution; a concurrent quorum admits exactly one
/// because the check-and-set contains no inter-canister await.
/// R1.5 — approve-time ordering on the RECOVERY plane, mirroring the Vault:
/// require_member -> load -> COMMITMENT CHECK -> (terminal / epoch / duplicate)
/// -> writes. The commitment check precedes EVERY other outcome and every
/// write, so no rejected approval can be answered in a success shape.
///
/// DELIBERATE DIFFERENCE FROM THE VAULT, FLAGGED FOR REVIEW: this plane keeps
/// its existing EPOCH-PIN-BEFORE-TERMINAL order, whereas the Vault checks
/// terminal-replay first. Swapping them here would change which error a
/// terminal proposal in a superseded epoch returns (StaleEpoch -> AlreadyTerminal),
/// which is a behavioural change R1.5 does not ask for. The load-bearing part
/// of the ordering — commitment FIRST — is identical on both planes. Note also
/// that this plane returns a typed AlreadyTerminal rather than the Vault's
/// success-shaped PriorResult, so the specific hazard that forced the Vault's
/// reorder does not arise here.
pub fn approve_recovery(
    caller: &Principal,
    proposal_id: u64,
    now_ns: u64,
    expected_action_hash: Vec<u8>,
    self_id: &Principal,
) -> Result<ApproveOutcome, RecoveryError> {
    require_member(caller)?;
    let stored = get_stored_proposal(proposal_id)
        .ok_or(RecoveryError::UnknownProposal { proposal_id })?;

    // ── COMMITMENT CHECK — before any other outcome, before any write.
    // Recomputation uses the proposal's RETAINED epoch (inside
    // commitment_for_stored), never current recovery state: the epoch pin
    // below is the SOLE rejector of stale-epoch approvals.
    let recomputed = commitment_for_stored(proposal_id, &stored, self_id).hash();
    let stored_hash = stored_commitment(&stored);
    if recomputed != stored_hash {
        // Durable corruption, not a caller error. Fail closed.
        return Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::StoredVsRecomputed,
        ));
    }
    if expected_action_hash != stored_hash {
        return Err(RecoveryError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::CallerMismatch,
        ));
    }

    let (proposal_epoch, approvals, outcome, expires_at_ns) = match &stored {
        StoredProposal::Recovery { epoch, proposal } => (
            *epoch,
            proposal.approvals.clone(),
            proposal.outcome,
            proposal.expires_at_ns,
        ),
        StoredProposal::Rotation(r) => (r.epoch, r.approvals.clone(), r.outcome, r.expires_at_ns),
    };
    // Stale-epoch fail-closed: nothing created before the latest rotation
    // can collect new approvals.
    if proposal_epoch != current_epoch() {
        return Err(RecoveryError::StaleEpoch {
            current: current_epoch(),
            proposal: proposal_epoch,
        });
    }
    match outcome {
        ActionOutcome::Pending => {}
        // R3: a withdrawn or lapsed proposal is terminal and can never collect
        // another approval. Grouped with Executed|Failed because the caller's
        // question — "may I approve this?" — has the same answer for all four:
        // no, and never again.
        ActionOutcome::Executed
        | ActionOutcome::Failed
        | ActionOutcome::Cancelled
        | ActionOutcome::Expired => return Err(RecoveryError::AlreadyTerminal),
        ActionOutcome::Executing | ActionOutcome::OutcomeUnknown => {
            return Err(RecoveryError::IllegalSourceState)
        }
    }
    // ── EXPIRY ADMISSION (S11-1, P1-A) — recovery-plane twin of the Vault's
    // step 4b. The proposal is still `Pending`; compare the CURRENT time
    // against its IMMUTABLE committed `expires_at_ns` BEFORE any approval,
    // audit or execution write.
    //
    // ORDER. The S11 packet forbids changing which error a terminal or a
    // stale-epoch proposal returns, and this plane's pre-existing precedence is
    // commitment → epoch → terminal (the Vault's is commitment → terminal →
    // epoch). Both precedences are preserved exactly; the expiry check is
    // inserted immediately after each plane's pre-existing rejectors and before
    // any mutation, which is the property that matters. It is deliberately NOT
    // reordered to make the two planes agree on compound cases — doing so would
    // change a stale-epoch or terminal answer, which the packet pins.
    //
    // CTO RULING (S11 packet V2) — TYPED REJECT, ZERO MUTATION, identical to
    // the Vault: this does NOT terminalize and does NOT release capacity. The
    // bounded R3.8/R3.11 sweep remains the SOLE terminalizer and the SOLE
    // releaser. Never success-shaped; `None` expiry is unaffected.
    if let Some(expires_at_ns) = expires_at_ns {
        if now_ns >= expires_at_ns {
            return Err(RecoveryError::ProposalExpired {
                expires_at_ns,
                now_ns,
            });
        }
    }

    if approvals.contains(caller) {
        return Err(RecoveryError::AlreadyApproved);
    }

    // Compute the would-be approval set BEFORE writing anything.
    let mut new_approvals = approvals;
    new_approvals.push(*caller);

    // Single-flight defense-in-depth (SSA L2-5): if THIS approval would
    // reach quorum on a Trigger execution, the lock is re-checked before any
    // write — a blocked quorum records nothing and is retryable once the
    // in-flight intent terminalizes. (Propose-time enforcement makes this
    // unreachable through the public surface; it guards the durable state
    // machine itself.)
    //
    // §S7 §2 — P1-1: THIS IS ALSO THE START ARM'S ONLY LOCK CHECK, AND IT MUST
    // RUN HERE, BEFORE ANY MUTATION.
    //
    // The start check previously lived inside the execution match, which runs
    // AFTER the quorum boundary has already written the proposal `Executing`
    // and appended `RecoveryExecutionStarted`. A refused start therefore left a
    // durable `Executing` proposal with `start == None` — an ORPHAN that no
    // path could clear: E2 filters on start presence, and reconciliation
    // resolves only start-bearing proposals, so it would sit in the nonterminal
    // population for ever, itself holding capacity. Refusing before any write
    // means a blocked quorum records NOTHING and stays retryable once the
    // in-flight intent or start terminalizes, which is the property this block
    // already delivered for the upgrade direction.
    if let StoredProposal::Recovery { proposal, .. } = &stored {
        if quorum_reached(&new_approvals) {
            let blocked = match proposal.action {
                // Upgrade admission consults BOTH limbs (P1-1): an outstanding
                // start blocks a new upgrade, not merely the reverse.
                RecoveryAction::TriggerVaultUpgrade { .. } => {
                    nonterminal_intent_in_flight(Some(&IntentKey::recovery(proposal_id)))
                        || start_in_flight(None)
                }
                // Start admission consults both limbs, as it always did — what
                // changed is WHEN, not what.
                RecoveryAction::StartVault => {
                    nonterminal_intent_in_flight(None) || start_in_flight(Some(proposal_id))
                }
                // Reconciliations make no inter-canister call and mutate no
                // module, so they take no target lock. Classified explicitly
                // rather than by a catch-all: a future action that DOES mutate
                // the target must fail to compile here until it is classified.
                RecoveryAction::ReconcileVaultUpgrade { .. }
                | RecoveryAction::ReconcileVaultStart { .. } => false,
            };
            if blocked {
                return Err(RecoveryError::IllegalSourceState);
            }
        }
    }

    // Record the approval (durable, both stores).
    match &stored {
        StoredProposal::Recovery { epoch, proposal } => {
            let mut p = proposal.clone();
            p.approvals = new_approvals.clone();
            put_stored_proposal(proposal_id, &StoredProposal::Recovery { epoch: *epoch, proposal: p });
        }
        StoredProposal::Rotation(r) => {
            let mut r2 = r.clone();
            r2.approvals = new_approvals.clone();
            put_stored_proposal(proposal_id, &StoredProposal::Rotation(r2));
        }
    }
    append_approval_log(proposal_id, caller, now_ns);
    append_audit(
        now_ns,
        UpgraderAuditEventKind::RecoveryApprovalRecorded { proposal_id, approver: *caller },
    );

    if !quorum_reached(&new_approvals) {
        return Ok(ApproveOutcome::Recorded);
    }

    // This call owns the execution: durable Executing BEFORE any effect.
    match stored {
        StoredProposal::Recovery { epoch, proposal } => {
            let mut executing = proposal.clone();
            executing.approvals = new_approvals.clone();
            executing.outcome = ActionOutcome::Executing;
            put_stored_proposal(
                proposal_id,
                &StoredProposal::Recovery { epoch, proposal: executing },
            );
            append_audit(
                now_ns,
                UpgraderAuditEventKind::RecoveryExecutionStarted { proposal_id },
            );
            match &proposal.action {
                RecoveryAction::TriggerVaultUpgrade { .. } => {
                    let vault = vault_principal().ok_or(RecoveryError::NotAuthorized)?;
                    let key = IntentKey::recovery(proposal_id);
                    let mut intent = get_intent(&key).unwrap_or_else(|| {
                        ic_cdk::trap("approve: trigger proposal without its durable intent")
                    });
                    let wasm = intent.wasm_bytes.clone().unwrap_or_else(|| {
                        ic_cdk::trap("approve: pending intent without artifact bytes")
                    });
                    let arg = intent.arg_bytes.clone().unwrap_or_else(|| {
                        ic_cdk::trap("approve: pending intent without artifact bytes")
                    });
                    // Re-verify the hash binding at execution (defense in
                    // depth — verified at proposal time; a mismatch here is
                    // durable corruption and fails closed: proposal AND
                    // intent terminal-Failed, bytes cleared atomically).
                    if validate_artifact(
                        &intent.expected_wasm_hash,
                        &intent.expected_arg_hash,
                        &wasm,
                        &arg,
                    )
                    .is_err()
                    {
                        intent.outcome = ActionOutcome::Failed;
                        intent.terminal_at_ns = Some(now_ns);
                        intent.wasm_bytes = None;
                        intent.arg_bytes = None;
                        put_intent(&key, &intent);
                        let mut failed = proposal.clone();
                        failed.approvals = new_approvals;
                        failed.outcome = ActionOutcome::Failed;
                        put_stored_proposal(
                            proposal_id,
                            &StoredProposal::Recovery { epoch, proposal: failed },
                        );
                        append_audit(
                            now_ns,
                            UpgraderAuditEventKind::RecoveryProposalTerminal {
                                proposal_id,
                                outcome: ActionOutcome::Failed,
                            },
                        );
                        return Ok(ApproveOutcome::Recorded);
                    }
                    // Intent Pending -> Executing, durable before the await.
                    intent.outcome = ActionOutcome::Executing;
                    put_intent(&key, &intent);
                    Ok(ApproveOutcome::Execute(RecoveryExecution::Trigger {
                        proposal_id,
                        plan: InstallPlan { key, target: vault, wasm_module: wasm, arg },
                    }))
                }
                RecoveryAction::ReconcileVaultUpgrade {
                    proposal_id: intent_id,
                    objective_evidence,
                } => Ok(ApproveOutcome::Execute(RecoveryExecution::Reconcile {
                    proposal_id,
                    intent_id: *intent_id,
                    evidence: Box::new(objective_evidence.clone()),
                    approvers: quorum_approvers(&new_approvals),
                })),
                // ── §S7 cell 4: Upgrader → Vault start ───────────────────────
                //
                // §2 PRE-AWAIT OBLIGATIONS, all four discharged HERE, before
                // this function returns and therefore before the shell can
                // reach the first `await`:
                //   1. the proposal is at the quorum boundary with a
                //      distinct-signature quorum at the current threshold
                //      (`quorum_reached` above, on explicit commitment-bound
                //      approvals);
                //   2. `Executing` is durable — written by the `put_stored_
                //      proposal` above, ahead of this match;
                //   3. the durable start-intent exists, written below, binding
                //      proposal id, target principal, epoch and intent time;
                //   4. both writes land BEFORE the first inter-canister call.
                RecoveryAction::StartVault => {
                    // §1: the target is read from DURABLE MEMBERSHIP. The
                    // action carries no target field, so there is nothing here
                    // that a caller could have influenced.
                    let vault = vault_principal().ok_or(RecoveryError::NotAuthorized)?;
                    // §2 single-flight is enforced BEFORE this point (P1-1):
                    // see the pre-mutation block in `approve_recovery`. It is
                    // deliberately NOT re-checked here — a refusal at this
                    // point would already be too late, because the proposal has
                    // been written `Executing` and the execution-started event
                    // appended, which is exactly the orphan the earlier check
                    // exists to prevent. One check, at the only point where
                    // refusing is free.
                    let intent = StartIntent {
                        proposal_id,
                        target: vault,
                        epoch,
                        intent_at_ns: now_ns,
                    };
                    let mut executing = proposal.clone();
                    executing.approvals = new_approvals;
                    executing.outcome = ActionOutcome::Executing;
                    executing.start = Some(StartSettlementState {
                        intent: intent.clone(),
                        settlement: None,
                    });
                    put_stored_proposal(
                        proposal_id,
                        &StoredProposal::Recovery { epoch, proposal: executing },
                    );
                    append_audit(
                        now_ns,
                        UpgraderAuditEventKind::VaultStartIntentRecorded {
                            proposal_id,
                            target: vault,
                            epoch,
                        },
                    );
                    Ok(ApproveOutcome::Execute(RecoveryExecution::Start {
                        proposal_id,
                        target: vault,
                    }))
                }
                RecoveryAction::ReconcileVaultStart {
                    proposal_id: target_proposal_id,
                    objective_evidence,
                } => Ok(ApproveOutcome::Execute(RecoveryExecution::ReconcileStart {
                    proposal_id,
                    target_proposal_id: *target_proposal_id,
                    evidence: Box::new(objective_evidence.clone()),
                    approvers: quorum_approvers(&new_approvals),
                })),
            }
        }
        StoredProposal::Rotation(r) => {
            let mut executing = r.clone();
            executing.approvals = new_approvals.clone();
            executing.outcome = ActionOutcome::Executing;
            put_stored_proposal(proposal_id, &StoredProposal::Rotation(executing));

            // Rotation execution — atomic, synchronous, no inter-canister
            // call. Validation FULLY PRECEDES the single write boundary.
            let vault = vault_principal().ok_or(RecoveryError::NotAuthorized)?;
            validate_bootstrap_quorum(&r.new_members, INITIAL_THRESHOLD, &vault)
                .unwrap_or_else(|e| {
                    ic_cdk::trap(&format!(
                        "rotation: durable proposal failed revalidation at execution: {e}"
                    ))
                });
            // S6 — the maximum is revalidated AT EXECUTION as well as at
            // propose. The proposal has been sitting durably since admission,
            // and the execution boundary is the last point before the roster
            // becomes the live membership.
            stsh_custody_types::check_recovery_roster_size(r.new_members.len()).unwrap_or_else(
                |e| {
                    ic_cdk::trap(&format!(
                        "rotation: durable proposal holds {} members at execution, \
                         above the ruled MAX_RECOVERY_MEMBERS of {}",
                        e.requested, e.maximum
                    ))
                },
            );
            let new_epoch = current_epoch() + 1;
            let member_count = r.new_members.len() as u32;
            let approvers = quorum_approvers(&new_approvals);
            store_membership(&MembershipState {
                epoch: new_epoch,
                record: BootstrapRecord {
                    schema_version: BOOTSTRAP_RECORD_SCHEMA_VERSION,
                    members: r.new_members.clone(),
                    threshold: INITIAL_THRESHOLD,
                    counterpart: vault,
                },
            });
            // Every still-Pending proposal (other than the rotation just
            // executed) belongs to the epoch the bump just froze — stale,
            // never executable. Terminalize them ALL Failed in this SAME
            // transaction (SSA L2-7): a Pending trigger proposal moves
            // WITH its linked intent (bytes cleared atomically, one audit
            // event tying proposal id ↔ intent id); Pending reconcile and
            // rotation proposals terminalize likewise. After any rotation
            // there is no stuck-Pending proposal beside a Failed intent.
            // Executing proposals are genuinely in flight (their approve
            // call holds a live management await) and finish normally.
            // S5B W3 — ONE-MESSAGE ATOMIC TERMINALIZATION.
            //
            // Replaces a full scan over RECOVERY_PROPOSALS that decoded every
            // proposal ever written (brief R3 item 11's "uncapped rotation").
            //
            // NOT A RESUMABLE SWEEP. The bounded Pending index is snapshotted
            // ONCE, here, and the COMPLETE stale set is terminalized and the
            // membership rotation committed in this SAME message. There is no
            // cursor, no continuation and no batching anywhere on this path,
            // and none may be added: a partially-rotated membership with a
            // partially-terminalized stale set is precisely the split-brain
            // state the atomicity exists to prevent.
            //
            // Whether the ruled C12 fits this envelope is M1's finding, not an
            // assumption made here. If it does not, that returns to CTO as a
            // constants problem (lower C12) — never as a licence to batch.
            //
            // W2(e): the index is validated before it is read, because a
            // silently-emptied Pending index would make rotation terminalize
            // NOTHING while reporting success.
            companion_validate();
            let stale_pending: Vec<u64> = PENDING_RECOVERY_PROPOSAL_INDEX.with(|x| {
                x.borrow()
                    .iter()
                    .map(|(pid, _)| pid)
                    .filter(|pid| *pid != proposal_id)
                    .collect()
            });
            // RF-2 — counts records fully terminalized in THIS message, so the
            // after-first boundary below can fire with completed work behind
            // it. Message-local: no cursor, no continuation, nothing durable —
            // W3's one-message discipline is untouched.
            let mut terminalized_in_this_message: u32 = 0;
            for pid in stale_pending {
                // S5B W3 — mid-terminalization boundary. A trap here must roll
                // back the ENTIRE rotation: every stale proposal already
                // terminalized in this message, AND the membership change.
                // Partial rotation is the split-brain state the one-message
                // discipline exists to prevent.
                rotation_trap(ROTATION_TRAP_MID_TERMINALIZATION);
                let stored = get_stored_proposal(pid).unwrap_or_else(|| {
                    ic_cdk::trap("rotation: stale proposal vanished")
                });
                match stored {
                    StoredProposal::Recovery { epoch, proposal } => {
                        let mut p = proposal.clone();
                        p.outcome = ActionOutcome::Failed;
                        put_stored_proposal(pid, &StoredProposal::Recovery { epoch, proposal: p });
                        if matches!(proposal.action, RecoveryAction::TriggerVaultUpgrade { .. })
                        {
                            // Fail-closed linkage invariant (SSA L2
                            // hardening): a Pending trigger proposal has
                            // EXACTLY ONE linked Pending intent. Normal
                            // source paths maintain this; corruption (e.g.
                            // a future migration) must TRAP — rolling the
                            // whole rotation back — rather than emit a
                            // terminalization event for a nonexistent or
                            // non-Pending intent.
                            let key = IntentKey::recovery(pid);
                            let mut i = get_intent(&key).unwrap_or_else(|| {
                                ic_cdk::trap(
                                    "rotation: Pending trigger proposal without its linked \
                                     intent — durable state corrupt, refusing to rotate",
                                )
                            });
                            if i.outcome != ActionOutcome::Pending {
                                ic_cdk::trap(
                                    "rotation: linked intent not Pending for a Pending \
                                     trigger proposal — durable state corrupt, refusing to rotate",
                                );
                            }
                            i.outcome = ActionOutcome::Failed;
                            i.terminal_at_ns = Some(now_ns);
                            i.wasm_bytes = None;
                            i.arg_bytes = None;
                            put_intent(&key, &i);
                            append_audit(
                                now_ns,
                                UpgraderAuditEventKind::StaleIntentTerminalized {
                                    proposal_id: pid,
                                    intent_id: pid,
                                    epoch: new_epoch,
                                },
                            );
                        } else {
                            append_audit(
                                now_ns,
                                UpgraderAuditEventKind::StaleProposalTerminalized {
                                    proposal_id: pid,
                                    epoch: new_epoch,
                                },
                            );
                        }
                    }
                    StoredProposal::Rotation(r) => {
                        let mut r2 = r.clone();
                        r2.outcome = ActionOutcome::Failed;
                        put_stored_proposal(pid, &StoredProposal::Rotation(r2));
                        append_audit(
                            now_ns,
                            UpgraderAuditEventKind::StaleProposalTerminalized {
                                proposal_id: pid,
                                epoch: new_epoch,
                            },
                        );
                    }
                }
                // RF-2 — fires only once this stale record is FULLY
                // terminalized (proposal, linked intent if any, and audit
                // event all written). A trap here has real completed work
                // behind it to roll back, which the loop-head boundary above
                // does not.
                terminalized_in_this_message += 1;
                rotation_trap_after_n(
                    ROTATION_TRAP_AFTER_FIRST_TERMINALIZATION,
                    terminalized_in_this_message,
                );
            }
            let mut done = r.clone();
            done.approvals = new_approvals;
            done.outcome = ActionOutcome::Executed;
            put_stored_proposal(proposal_id, &StoredProposal::Rotation(done));
            append_audit(
                now_ns,
                UpgraderAuditEventKind::MembershipRotated {
                    proposal_id,
                    new_epoch,
                    member_count,
                    approvers,
                },
            );
            Ok(ApproveOutcome::RotationExecuted { new_epoch })
        }
    }
}

/// After the shell finished the management call of a recovery-triggered
/// upgrade: apply the intent outcome and close the proposal (mirrors the
/// intent: Executed, or OutcomeUnknown — which never returns to Pending).
pub fn recovery_finish_trigger(
    proposal_id: u64,
    intent_outcome: ActionOutcome,
    now_ns: u64,
) {
    match get_stored_proposal(proposal_id) {
        Some(StoredProposal::Recovery { epoch, proposal }) => {
            let mut p = proposal;
            p.outcome = intent_outcome;
            put_stored_proposal(proposal_id, &StoredProposal::Recovery { epoch, proposal: p });
            append_audit(
                now_ns,
                UpgraderAuditEventKind::RecoveryProposalTerminal {
                    proposal_id,
                    outcome: intent_outcome,
                },
            );
        }
        _ => ic_cdk::trap("recovery_finish_trigger: no durable recovery proposal"),
    }
}

/// Close a reconciliation proposal with the core's result. A successful
/// reconciliation — Executed OR Failed on the intent — is an Executed
/// proposal; a rejected reconciliation (illegal source state, ambiguous id,
/// stale or non-binding evidence) fails the proposal closed.
pub fn recovery_finish_reconcile(
    proposal_id: u64,
    result: &Result<ReconcileTerminalOutcome, RecoveryError>,
    now_ns: u64,
) {
    match get_stored_proposal(proposal_id) {
        Some(StoredProposal::Recovery { epoch, proposal }) => {
            let mut p = proposal;
            let outcome = match result {
                Ok(_) => ActionOutcome::Executed,
                Err(_) => ActionOutcome::Failed,
            };
            p.outcome = outcome;
            put_stored_proposal(proposal_id, &StoredProposal::Recovery { epoch, proposal: p });
            append_audit(
                now_ns,
                UpgraderAuditEventKind::RecoveryProposalTerminal { proposal_id, outcome },
            );
        }
        _ => ic_cdk::trap("recovery_finish_reconcile: no durable recovery proposal"),
    }
}

/// §S7 — close a cell-4 START-reconciliation proposal with the core's result.
///
/// Separate from `recovery_finish_reconcile` because the start core returns
/// `Ok(None)` for §5's inconclusive `Stopping` observation, and that case must
/// NOT be collapsed into either arm of the upgrade version:
///   * `Ok(Some(_))` — the target settled. The reconcile proposal is `Executed`.
///   * `Err(_)` — rejected or a replay. The reconcile proposal is `Failed`.
///   * `Ok(None)` — **INCONCLUSIVE.** The target correctly remains
///     `OutcomeUnknown` with its lock retained (§7e). The reconcile PROPOSAL is
///     nonetheless terminal `Executed`: it did exactly what it was approved to
///     do — submit a valid observation — and it is never re-triggerable (§6).
///     Acceptance 5 requires "re-observation settles it", which is a NEW
///     proposal at full quorum (§6), not a retry of this one. Marking it
///     `Failed` would be a false statement about a proposal that executed
///     correctly against a target that was legitimately still transitioning.
pub fn recovery_finish_reconcile_start(
    proposal_id: u64,
    result: &Result<Option<ReconcileTerminalOutcome>, RecoveryError>,
    now_ns: u64,
) {
    match get_stored_proposal(proposal_id) {
        Some(StoredProposal::Recovery { epoch, proposal }) => {
            let mut p = proposal;
            let outcome = match result {
                Ok(_) => ActionOutcome::Executed,
                Err(_) => ActionOutcome::Failed,
            };
            p.outcome = outcome;
            put_stored_proposal(proposal_id, &StoredProposal::Recovery { epoch, proposal: p });
            append_audit(
                now_ns,
                UpgraderAuditEventKind::RecoveryProposalTerminal { proposal_id, outcome },
            );
        }
        _ => ic_cdk::trap("recovery_finish_reconcile_start: no durable recovery proposal"),
    }
}

// ── Query surface (freeze §5 — exact rulings) ────────────────────────────────

/// Gate for the RECOVERY-SIGNER-GATED queries. Bootstrap queries fail closed
/// on uninitialized/sentinel state (no durable counterpart loaded → deny).
fn query_gate(caller: &Principal) -> bool {
    vault_principal().is_some() && is_recovery_member(caller)
}

/// `get_upgrader_audit_events` — RECOVERY-SIGNER-GATED, bounded (freeze §5).
/// Unauthorized AND invalid-bounds AND out-of-range all return the same
/// `None` — never a distinct observable.
pub fn query_audit_events(
    caller: &Principal,
    cursor: Option<u64>,
    limit: u32,
) -> Option<AuditEventsPage> {
    if !query_gate(caller) {
        return None;
    }
    if limit == 0 || limit > MAX_READ_PAGE_LIMIT {
        return None;
    }
    let start = cursor.and_then(|c| c.checked_add(1)).unwrap_or(0);
    AUDIT_EVENTS.with(|a| {
        let map = a.borrow();
        let len = map.len();
        if start >= len {
            return Some(AuditEventsPage { events: vec![], next_cursor: None });
        }
        let mut events = Vec::new();
        let mut last = start;
        for seq in start..len {
            if events.len() as u32 >= limit {
                break;
            }
            if let Some(raw) = map.get(&seq) {
                if let Ok(ev) = candid::decode_one::<UpgraderAuditEvent>(&raw) {
                    events.push(ev);
                    last = seq;
                }
            }
        }
        let next_cursor = if last + 1 < len { Some(last) } else { None };
        Some(AuditEventsPage { events, next_cursor })
    })
}

fn status_view(intent: &UpgradeIntent) -> UpgradeStatusView {
    UpgradeStatusView {
        id: intent.id,
        origin: intent.origin,
        expected_wasm_hash: intent.expected_wasm_hash.clone(),
        expected_arg_hash: intent.expected_arg_hash.clone(),
        outcome: intent.outcome,
        created_at_ns: intent.created_at_ns,
        terminal_at_ns: intent.terminal_at_ns,
        artifact_bytes_held: intent.wasm_bytes.is_some(),
    }
}

/// `get_upgrade_status` — RECOVERY-SIGNER-GATED (freeze §5: gated because
/// that is the only gate available). Unknown id and unauthorized are the
/// same `None`; an id ambiguous across both intent namespaces (SSA L2-3) is
/// also `None` — never a precedence-based answer.
pub fn query_upgrade_status(caller: &Principal, id: u64) -> Option<UpgradeStatusView> {
    if !query_gate(caller) {
        return None;
    }
    let v = get_intent(&IntentKey::vault(id));
    let r = get_intent(&IntentKey::recovery(id));
    match (v, r) {
        (Some(i), None) | (None, Some(i)) => Some(status_view(&i)),
        _ => None,
    }
}

/// `get_recovery_proposal` — RECOVERY-SIGNER-GATED (freeze §5). Returns the
/// stored proposal; trigger actions are in their redacted form (hashes only
/// — SSA L2-1). Rotation proposals are not this frozen type and are visible
/// via the audit log instead.
pub fn query_recovery_proposal(caller: &Principal, id: u64) -> Option<RecoveryProposal> {
    if !query_gate(caller) {
        return None;
    }
    match get_stored_proposal(id) {
        Some(StoredProposal::Recovery { proposal, .. }) => Some(proposal),
        _ => None,
    }
}

/// R1.6 — SIGNER-GATED TYPED ROTATION VIEW.
///
/// `query_recovery_proposal` returns `None` for a rotation, and the audit event
/// carries only `member_count`. Once R1.5 made the commitment REQUIRED at
/// approve-time, that combination made rotation approval IMPOSSIBLE: a peer
/// member could obtain neither the proposed roster nor its commitment, so they
/// could not supply the hash and could not approve.
///
/// It also reinstates the disclosure R1.6 requires: the PROPOSED RECOVERY
/// MEMBERS must be independently inspectable. Approving a roster you cannot
/// see is the CUST-SSA-001 social-engineering path — and rotation is that
/// finding's own attack route.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RotationProposalView {
    pub proposal_id: u64,
    pub epoch: u64,
    /// The PROPOSED roster, in full. Not a count.
    pub new_members: Vec<Principal>,
    pub proposer: Principal,
    pub approvals: Vec<Principal>,
    pub threshold: u32,
    pub created_at_ns: u64,
    pub outcome: ActionOutcome,
    pub expires_at_ns: Option<u64>,
    /// The stored commitment a member must supply to `approve_recovery`.
    pub commitment_hash: Vec<u8>,
}

pub fn query_rotation_proposal(caller: &Principal, id: u64) -> Option<RotationProposalView> {
    if !query_gate(caller) {
        return None;
    }
    match get_stored_proposal(id) {
        Some(StoredProposal::Rotation(r)) => Some(RotationProposalView {
            proposal_id: r.proposal_id,
            epoch: r.epoch,
            new_members: r.new_members,
            proposer: r.proposer,
            approvals: r.approvals,
            threshold: r.threshold,
            created_at_ns: r.created_at_ns,
            outcome: r.outcome,
            expires_at_ns: r.expires_at_ns,
            commitment_hash: r.commitment_hash,
        }),
        _ => None,
    }
}

/// `get_recovery_membership` — RECOVERY-SIGNER-GATED (freeze §5): the count
/// is public credibility, the identities are a target list.
pub fn query_recovery_membership(caller: &Principal) -> Option<Vec<Principal>> {
    if !query_gate(caller) {
        return None;
    }
    Some(RECOVERY_MEMBERS.with(|m| m.borrow().clone()))
}

/// `get_controller_invariant` — PUBLIC, conscious (freeze §5): the external
/// no-human-controller proof. Returns the last durably-recorded observation;
/// before any observation exists it fails closed to `{false, false, 0}` —
/// never a claim the ring is intact without evidence.
///
/// R6.0 — READ STRAIGHT FROM THE DURABLE CELL, no heap mirror. The mirror was
/// removed rather than repointed: a mirror has to be reloaded somewhere, and
/// every reload site is a place the served proof can silently diverge from the
/// durable record. A bounded cell read has no such site, and this is a query —
/// there is no cost argument for caching one fixed-size decode.
/// **NON-AUTHORITATIVE — HISTORICAL EVIDENCE ONLY (S11-2 / CUST-SSA-006).**
///
/// Retained unchanged for compatibility. It serves the raw last observation and
/// cannot express how old that observation is, nor tell "never observed" apart
/// from "double breach at time 0". Callers deciding anything must use
/// [`query_controller_invariant_proof`] instead; this endpoint is a deliberate
/// PREDECESSOR, kept so existing readers do not silently change meaning, and
/// must not be reshaped in place (DID drift lock).
pub fn query_controller_invariant() -> stsh_custody_types::ControllerInvariant {
    raw_invariant_observation().unwrap_or(stsh_custody_types::ControllerInvariant {
        vault_controllers_ok: false,
        upgrader_controllers_ok: false,
        observed_at_ns: 0,
    })
}

/// The durable observation, or `None` if none was ever recorded.
///
/// Split out so the never-observed case survives as an ABSENCE all the way to
/// the proof constructor. The legacy endpoint above collapses it to the
/// `{ false, false, 0 }` sentinel — that collapse is the whole defect, so it
/// happens in exactly one place and never upstream of the new contract.
fn raw_invariant_observation() -> Option<stsh_custody_types::ControllerInvariant> {
    invariant_load().map(|rec| stsh_custody_types::ControllerInvariant {
        vault_controllers_ok: rec.vault_controllers_ok,
        upgrader_controllers_ok: rec.upgrader_controllers_ok,
        observed_at_ns: rec.observed_at_ns,
    })
}

/// `get_controller_invariant_proof` — PUBLIC, conscious (freeze §5).
///
/// S11-2 / CUST-SSA-006, BRIEF V4.1 R6 requirements 7–9: the AUTHORITATIVE
/// answer to "is the no-human-controller property currently PROVEN?".
///
/// Freshness is computed HERE, at query time, from the current IC time against
/// the ruled 24 h bound — never stored, because a stored freshness flag is
/// wrong the moment after it is written.
///
/// Fail-closed when the R6 constants are unruled (`INVARIANT_REFRESH_PARAMS ==
/// None`): `max_age_ns` is 0, so every observation classifies `Stale` and
/// `current_proof_ok` is false. An unruled freshness policy must not be able to
/// produce a success-shaped proof.
pub fn query_controller_invariant_proof(
    now_ns: u64,
) -> stsh_custody_types::ControllerInvariantProof {
    let max_age_ns = stsh_custody_types::INVARIANT_REFRESH_PARAMS
        .map(|p| p.max_age_ns)
        .unwrap_or(0);
    stsh_custody_types::ControllerInvariantProof::from_observation(
        raw_invariant_observation(),
        now_ns,
        max_age_ns,
    )
}

/// `get_recovery_summary` — PUBLIC, conscious (freeze §5). No principals.
pub fn query_recovery_summary() -> RecoverySummary {
    RecoverySummary {
        threshold: RECOVERY_THRESHOLD.with(|t| *t.borrow()),
        member_count: RECOVERY_MEMBERS.with(|m| m.borrow().len() as u32),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST-ONLY MODULE — THE W6 LINT STOPS HERE
// ═══════════════════════════════════════════════════════════════════════════

/// Measurement harness. **Compiled out of every deployable build.**
///
/// WHY THIS IS A MODULE AND NOT JUST A `cfg`-GATED FUNCTION. W6 forbids
/// unbounded iteration over permanently-growing history in production code,
/// because such a call's cost grows without bound — the exhaustion half of
/// CUST-SSA-003. A CENSUS of those maps must iterate them: counting bytes in
/// permanent history is its entire purpose. That is legitimate in a measurement
/// harness and forbidden on a live path, and the only thing separating the two
/// is which side of this boundary the code sits on.
///
/// The Vault has the identical carve-out and gets it for free — its census
/// lives inside `#[cfg(test)] mod tests` and its W6 lint cuts at that boundary.
/// `core.rs` has no test module, so the boundary is declared here.
///
/// THE BOUNDARY IS ENFORCED BY THE COMPILER, NOT BY A COMMENT. Everything in
/// this module is `cfg(any(test, feature = "testing"))`, and neither condition
/// holds in a deployable build. So a live path moved in here does not acquire a
/// silent W6 blind spot — it VANISHES from the production Wasm and fails at the
/// first production build or feature-isolation proof. That is the whole reason
/// for the module: a textual marker would have made the same carve-out with
/// nothing but prose stopping a real path from being hidden behind it.
#[cfg(any(test, feature = "testing"))]
pub mod measurement {
    use super::*;

    /// M2″ — the RECOVERY PLANE's permanent-surface census. Test-only.
    ///
    /// WHY IT DID NOT EXIST. All five `s5a_` census tests live on the Vault, so
    /// every M2 figure the constants table has seen describes ONE plane. The
    /// recovery plane has its own twelve MemoryIds (0–11 after R6.0 added the
    /// controller-invariant cell), its own audit trail and its own
    /// per-operation growth, none of which has ever been counted. Brief V3 §4's
    /// obligation is ALL permanent per-operation surfaces; a one-plane census does
    /// not meet it, and it fails in the direction that understates growth.
    ///
    /// Returned as (label, entries, logical bytes). Logical payload only —
    /// StableBTreeMap node and allocator overhead are excluded, the same basis the
    /// Vault census uses, so the two planes are comparable and can be summed.
    ///
    /// The two `Cell`s are BOUNDED and rewritten rather than appended, so they
    /// contribute a roughly fixed footprint rather than per-operation growth. They
    /// are reported anyway: a bounded surface is still a permanent one, and a
    /// reader must be able to see that the bound is what makes it safe rather than
    /// find it silently absent.
    pub fn census_for_test() -> Vec<(&'static str, usize, usize)> {
        let mut out: Vec<(&'static str, usize, usize)> = Vec::new();
        RECOVERY_PROPOSALS.with(|m| {
            let m = m.borrow();
            out.push((
                "1 RECOVERY_PROPOSALS",
                m.iter().count(),
                m.iter().map(|(_, v)| v.len() + 8).sum(),
            ))
        });
        RECOVERY_APPROVALS.with(|m| {
            let m = m.borrow();
            out.push((
                "2 RECOVERY_APPROVALS",
                m.iter().count(),
                m.iter().map(|(_, v)| v.len() + 8).sum(),
            ))
        });
        UPGRADE_INTENTS.with(|m| {
            let m = m.borrow();
            out.push((
                "3 UPGRADE_INTENTS",
                m.iter().count(),
                m.iter().map(|(_, v)| v.len() + 33).sum(),
            ))
        });
        AUDIT_EVENTS.with(|m| {
            let m = m.borrow();
            out.push((
                "4 AUDIT_EVENTS",
                m.iter().count(),
                m.iter().map(|(_, v)| v.len() + 8).sum(),
            ))
        });
        NONTERMINAL_INTENT_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            out.push(("5 NONTERMINAL_INTENT_INDEX", c, c * 33))
        });
        RECOVERY_PROPOSAL_EXPIRY_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            out.push(("6 RECOVERY_PROPOSAL_EXPIRY_INDEX", c, c * 16))
        });
        COMPANION_STATE.with(|c| {
            let n = c.borrow().get().len();
            out.push(("7 COMPANION_STATE (bounded cell)", 1, n))
        });
        PENDING_RECOVERY_PROPOSAL_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            out.push(("8 PENDING_RECOVERY_PROPOSAL_INDEX", c, c * 8))
        });
        ENTRY_RATE_LEDGER.with(|c| {
            let n = c.borrow().get().len();
            out.push(("9 ENTRY_RATE_LEDGER (bounded cell)", 1, n))
        });
        NONTERMINAL_RECOVERY_PROPOSAL_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            out.push(("10 NONTERMINAL_RECOVERY_PROPOSAL_INDEX", c, c * 37))
        });
        // R6.0 — MemoryId 11. Censused for the same reason the other two cells
        // are: bounded is not absent, and a reader must be able to see the
        // bound rather than discover the surface missing. Rewritten in place at
        // most once per update-path observation, so it contributes a fixed
        // footprint and no per-operation growth.
        LAST_CONTROLLER_INVARIANT_CELL.with(|c| {
            let n = c.borrow().get().len();
            out.push(("11 LAST_CONTROLLER_INVARIANT (bounded cell)", 1, n))
        });
        // S8B — MemoryId 12. Bounded: two Option<u64> and a version, rewritten
        // in place. Censused because a bounded surface is still a permanent
        // one, and a reader must see the bound rather than find it missing.
        INVARIANT_REFRESH_LEDGER.with(|c| {
            let n = c.borrow().get().len();
            out.push(("12 INVARIANT_REFRESH_LEDGER (bounded cell)", 1, n))
        });
        out
    }

    /// Encoded size of every audit event on THIS plane (M3‴ rotation series).
    ///
    /// Rotation events are written to the UPGRADER trail, so their sizes must be
    /// measured HERE. The prior version sized them from the Vault's audit map —
    /// a different event set on a different plane — which was SSA Blocker 4.
    pub fn audit_event_sizes_for_test() -> Vec<usize> {
        AUDIT_EVENTS.with(|a| a.borrow().iter().map(|(_, v)| v.len() + 8).collect())
    }
}
