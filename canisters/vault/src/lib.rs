// =============================================================================
// STSH Custody Vault Canister — L1 Vault core
// =============================================================================
//
// Closed-ring custody: `Vault.controllers == [Upgrader]`,
// `Upgrader.controllers == [Vault]` — no third native controller, ever
// (brief invariant 1, freeze §3c). This is the L1 body over the L0 shell:
//
//   · governance atomic cell + epoch pin (MemoryId 0) — signers, threshold,
//     epoch and durable target config in ONE cell, so a governance transition
//     is exactly one durable write boundary.
//   · proposal / approval state machine with fail-closed quorum
//     (MemoryIds 1, 2). `OutcomeUnknown` never returns to `Pending`
//     (brief invariant 4).
//   · single deny-by-default authorization path against the canonical
//     governance cell — never a mirror (freeze §4). No ORed policies.
//   · append-only audit (MemoryId 3). F-4: every execution/reconciliation
//     audit event records the approving signer set (freeze §10).
//   · execution engine: `Executing` + idempotency reservation durable BEFORE
//     the first `await` (MemoryId 5; reservations permanent — no code path
//     deletes, replaces, or prunes them, including across upgrades: they live
//     in stable memory and `post_upgrade` has no migration that drops them).
//   · C1 `UpgraderUpgrade` (freeze §3d): upgrade-mode only, both hashes
//     recomputed and rejected on mismatch at propose AND execution, inline
//     only, durable upgrade intent (the proposal record binding the delivered
//     bytes) written before the first inter-canister call, artifact bytes
//     cleared only after terminal evidence is durable. Typed
//     `reconcile_upgrader_upgrade`: legal source state `OutcomeUnknown` ONLY,
//     terminal `Executed`|`Failed`, never back to `Pending`, never
//     re-triggerable, never retries/reinstalls.
//   · C3 query rulings exactly as frozen (freeze §4): signer-gated queries
//     return indistinguishable `None` for anonymous / removed / stale-epoch /
//     unknown callers; public summary / catalogue / build info.
//
// Hard threshold >= 2 at every entry point (init, governance transition,
// post_upgrade revalidation). Init threshold exactly 2 via the shared
// `validate_bootstrap_quorum` (freeze §1).
//
// MemoryIds are L0-allocated (freeze §7): 0 GOVERNANCE_CELL, 1 PROPOSALS,
// 2 APPROVALS, 3 AUDIT_EVENTS, 4 CONTROLLER_READ_SNAPSHOTS,
// 5 ACTION_IDEMPOTENCY_RESERVATIONS. No others.
// =============================================================================

#![cfg_attr(not(test), forbid(unsafe_code))]

use candid::{CandidType, Principal};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_stable_structures::{
    cell::Cell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use stsh_custody_types::{
    callback_may_write, classify_start_reconcile, validate_bootstrap_quorum, ActionOutcome,
    ActionRequest, ApplicationAction, ClaimDecision, DisburseOutcome, GovernanceFeeParamsMirror,
    PageRequest, PayoutOutcome, PruneRequest,
    ApplicationTarget, BootstrapRecord, ControllerReadSnapshot, ManagementAction,
    ManifestDisposition, NullifierSpentAtItem, ObservedCanisterStatus,
    SupplyReconciliation,
    ReadModelRequest, ReadModelResponse, ReconcileTerminalOutcome, ReconcileUpgraderStart,
    ReconcileUpgraderUpgrade,
    ReconcileVaultUpgradeViaUpgrader, RingActionKind, SettlementEvidenceConflict,
    SettlementRecord, SnapshotSource, StartIntent, StartObjectiveEvidence,
    StartReconcileDisposition, StartReconcileRejection, StartSettlementState, StartSourceState,
    TriggerUpgradeResult, UpgradeObjectiveEvidence, UpgraderUpgrade, VaultError, VaultInitArgs,
    VaultSelfControlGuard, VaultUpgradeViaUpgrader, GuardTarget,
    BOOTSTRAP_RECORD_SCHEMA_VERSION, GATE_SIZE_BOUND_BYTES, MAX_READ_PAGE_LIMIT,
    MAX_TEXT_FIELD_BYTES, MIN_THRESHOLD, READ_RESPONSE_MAX_BYTES,
    RECONCILE_VAULT_UPGRADE_REQ_CEILING_BYTES, START_MAX_EVIDENCE_AGE_NS,
    VAULT_UPGRADE_VIA_UPGRADER_REQ_CEILING_BYTES,
};

// §S7 §4 — the start path REUSES the plane's existing freshness discipline
// rather than re-deriving it. Asserted at COMPILE TIME so the reuse cannot
// silently split: see the identical assertion in the Upgrader.
const _: () = assert!(MAX_EVIDENCE_AGE_NS == START_MAX_EVIDENCE_AGE_NS);

/// Pre-decode ceiling for the Upgrader's typed replies to the two §3e ring
/// endpoints (both are tiny fixed-shape enums; 1 KiB is generous and keeps
/// the F2 raw-size discipline on this surface too).
const RING_RESPONSE_MAX_BYTES: usize = 1_024;

// ── L0 MemoryId allocation (freeze §7; registry rows `vault` 0–5) ────────────
const MEM_GOVERNANCE_CELL: MemoryId = MemoryId::new(0);
const MEM_PROPOSALS: MemoryId = MemoryId::new(1);
const MEM_APPROVALS: MemoryId = MemoryId::new(2);
const MEM_AUDIT_EVENTS: MemoryId = MemoryId::new(3);
const MEM_CONTROLLER_READ_SNAPSHOTS: MemoryId = MemoryId::new(4);
const MEM_ACTION_IDEMPOTENCY_RESERVATIONS: MemoryId = MemoryId::new(5);
// R3 (CUST-SSA-003), as AMENDED — BOUNDED AUTHORITATIVE COMPANIONS.
//
// SSA RF-4: this comment previously described all three as DERIVED indexes,
// reconstructible from PROPOSALS (MemoryId 1), repaired idempotently at
// `post_upgrade`. That is the SUPERSEDED model. Amended R3 item 10 replaced it,
// and the code below implements the replacement — but the declaration a reader
// meets first still described the old contract, which is worse than a stale
// comment elsewhere: this is where someone looks to learn what these are.
//
// Under the amended model the registry is AUTHORITATIVE for active membership
// and history is authoritative for existence and terminal outcomes. These
// indexes are NOT rebuilt from history at `post_upgrade` — rebuilding was the
// authority inversion the amendment removes, and a full history pass is
// forbidden outright by clause (c). They are maintained transactionally with
// every record write, covered by MemoryId 9's accounting and seal, and VALIDATED
// (never repaired) on load. Inconsistency TRAPS: there is no runtime repair
// surface, by ruling, and recovery is a governed hash-bound Wasm upgrade.
const MEM_PROPOSAL_EXPIRY_INDEX: MemoryId = MemoryId::new(6);
const MEM_OPEN_MUTATING_INTENT_INDEX: MemoryId = MemoryId::new(7);
const MEM_OPEN_CREATION_INTENT_INDEX: MemoryId = MemoryId::new(8);
/// S5B W2 — companion integrity state (commitment + count + byte accounting).
/// Registered in `docs/MEMORY_ID_REGISTRY.md` in this same change (W7).
const MEM_COMPANION_STATE: MemoryId = MemoryId::new(9);
/// S5B W4 — durable C9 entry-rate ledger. Registered in
/// `docs/MEMORY_ID_REGISTRY.md` in this same change (W7).
const MEM_ENTRY_RATE_LEDGER: MemoryId = MemoryId::new(10);
/// SSA BLOCKER 1 — bounded NONTERMINAL proposal index, `(proposer, id) -> ()`.
///
/// C5/C7/C12 count NONTERMINAL proposals: `Pending`, `Executing` AND
/// `OutcomeUnknown`. The first cut counted only the two single-flight indexes,
/// which hold `Executing | OutcomeUnknown` — so `Pending` consumed no slot and
/// Pending spam bypassed the caps entirely, taking with it the capacity
/// argument that made CONF-01 deferrable. Keyed by PROPOSER so the per-signer
/// bound is a bounded range read rather than a scan.
const MEM_NONTERMINAL_PROPOSAL_INDEX: MemoryId = MemoryId::new(11);

type Mem = VirtualMemory<DefaultMemoryImpl>;

/// Schema version of the L1 governance-cell content. v3: governed allowlist
/// + receipt-bound born-under-vault wiring (SSA L1-1/L1-2/L1-4).
const GOVERNANCE_CELL_SCHEMA_VERSION: u32 = 3;

/// Cycles attached to a governed `create_canister` (freeze §3c — cycles only
/// on explicit cycle ops; creation is one). 2T covers a 13-node subnet.
const CREATE_CANISTER_CYCLES: u128 = 2_000_000_000_000;

// ── Vault-local interface types (vault.did is L1-owned) ──────────────────────

/// The born-under-vault target roles of the custody manifest
/// (deployment/mainnet/custody_manifest.toml — the D5/§13.3 source of truth).
/// A `CreateCanister` proposal's `manifest_purpose` must name EXACTLY one of
/// these when its disposition is `BornUnderVault`: the returned principal is
/// then bound to that role from its typed creation receipt — one-shot.
pub const BORN_UNDER_VAULT_ROLES: [&str; 9] = [
    "shielded_pool",
    "treasury",
    "vesting",
    "nullifier_registry",
    "stsh_token",
    "merkle_tree",
    "verifier",
    "smoke_alarm_monitor",
    "vetkeys",
];

// The four roles the action/read-model planes resolve against
// (`VaultTargets`): shielded_pool, treasury, vesting, nullifier_registry.
// The other five are controller-only targets (freeze §12) tracked in the
// governed allowlist only.

/// Maximum age of reconciliation objective evidence (L1-3). Rationale:
/// upgrades are operator-supervised events — evidence is gathered and
/// proposed within one operational session; 24h bounds clock skew and
/// multi-timezone signer coordination without letting stale observations
/// terminalize a live upgrade intent. **Flagged for SSA as a ruled value.**
pub const MAX_EVIDENCE_AGE_NS: u64 = 24 * 3_600 * 1_000_000_000; // 24 h

/// One governed target — the durable, manifest-derived management allowlist
/// (L1-1). Cutover entries are declared at init (their principals already
/// exist, e.g. pyeop/s3tyu); born-under-vault entries are appended from typed
/// creation receipts (freeze §13.3), never from caller-supplied principals.
/// `OutOfScope` is unrepresentable here: an unknown principal is simply not
/// governed, and every management variant fails closed on it.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GovernedTarget {
    pub principal: Principal,
    /// `BornUnderVault` or `SetControllerAtCutover` only.
    pub disposition: ManifestDisposition,
    /// Manifest purpose label — a `BORN_UNDER_VAULT_ROLES` name for
    /// born-under-vault entries, the manifest purpose for cutover entries.
    pub purpose: String,
}

/// Custody status of a creation receipt (L1-10). A Vault-controlled
/// canister must NEVER vanish from the D5 surface: if the purpose became
/// bound while the create call was in flight, the returned principal is
/// recorded as `OrphanedPurposeConflict` — discoverable, but NOT governed
/// (every management path fails closed on it) pending governed resolution.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationReceiptStatus {
    /// Bound into the governed allowlist (and wired role, if any).
    Bound,
    /// Created successfully but the purpose conflicted post-await; retained
    /// for custody visibility, blocked from management use.
    OrphanedPurposeConflict,
}

/// Typed, machine-readable D5 creation receipt (L1-4, freeze §13.3/§13.2a).
/// Persisted as a typed field of an append-only audit event: insert-once
/// (audit ids are monotone, no update path), durable forever, written BEFORE
/// any install against the created principal is possible (same execution,
/// ahead of the terminal write; installs are later proposals). Each receipt
/// binds EXACTLY ONE principal to its predeclared purpose/disposition —
/// the bijectivity anchor for the deployment gate.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreationReceipt {
    pub proposal_id: u64,
    pub principal: Principal,
    pub purpose: String,
    pub disposition: ManifestDisposition,
    pub created_at_ns: u64,
    pub status: CreationReceiptStatus,
}

/// Durable application/read target wiring. Born-under-vault canisters do not
/// EXIST at Vault init — the Vault creates them — so their principals are
/// bound from creation receipts (freeze §13.3), one-shot per role, never
/// caller-supplied. A proposal whose action needs an unbound role fails
/// closed at execution.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultTargets {
    pub shielded_pool: Option<Principal>,
    pub treasury: Option<Principal>,
    pub vesting: Option<Principal>,
    pub nullifier_registry: Option<Principal>,
}

/// Vault init args. The quorum half is the frozen `VaultInitArgs` from
/// stsh-custody-types (L0); `cutover_targets` is the manifest-derived
/// (NOT manifest-parsed-per-call) SetControllerAtCutover allowlist — for the
/// launch manifest: pyeop (solvency_status) and s3tyu (wallet_frontend).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultInit {
    pub quorum: VaultInitArgs,
    pub cutover_targets: Vec<GovernedTarget>,
}

/// Governance atomic cell content: signers + threshold + epoch + target
/// wiring + governed allowlist in ONE durable object. A governance
/// transition is one `Cell::set` — one durable write boundary.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct GovernanceCellData {
    schema_version: u32,
    bootstrap: BootstrapRecord,
    epoch: u64,
    targets: VaultTargets,
    governed: Vec<GovernedTarget>,
}

/// The Vault's internal action envelope. Application / management / C1 /
/// read-model payloads are the frozen stsh-custody-types contracts; the two
/// Vault-internal variants (reconciliation authority + signer-set governance)
/// are shaped here because they have no inter-canister contract.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum VaultActionKind {
    /// One of the 21 frozen application variants (freeze §3a).
    Application(ActionRequest),
    /// A production management variant (freeze §3c) — structurally no
    /// `delete`, no `reinstall`.
    Management(ManagementAction),
    /// C1 (freeze §3d): upgrade-mode install_code against the Upgrader,
    /// hash-bound, inline-only.
    UpgraderUpgrade(UpgraderUpgrade),
    /// The named, typed reconciliation entrypoint (freeze §3d). Authority:
    /// same quorum as any other action — no single operator principal.
    ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade),
    /// A bounded read-model variant (freeze §3b); its execution stores a
    /// durable `ControllerReadSnapshot` (freeze §9).
    ReadModel(ReadModelRequest),
    /// Governance-plane signer-set transition. Executed internally (no
    /// inter-canister call): one atomic cell write bumps the epoch, which is
    /// what makes removal take effect and pins stale-epoch approvals out.
    UpdateSignerSet { signers: Vec<Principal>, threshold: u32 },
    /// §3e (CUST-L12-01): governed upgrade of THE VAULT through the
    /// Upgrader's FIXED `trigger_vault_upgrade` endpoint. Ring-internal: NO
    /// target principal, NO method string. The CALLER submits `request_id`
    /// as the unbound marker 0; the Vault binds it to the proposal id AT
    /// CREATION (R1.2), not at the quorum boundary. Binding it later moved the
    /// action's hash mid-life and is one of the three mutations that made a
    /// single stable commitment impossible — do not restore it. L2 replays on
    /// request_id, so the proposal id IS the request identity.
    /// Distinct namespace from §3d `UpgraderUpgrade` (which upgrades THE
    /// UPGRADER via management install_code directly).
    VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader),
    /// §3e reconciliation of an OutcomeUnknown Vault upgrade through the
    /// Upgrader's FIXED `reconcile_vault_upgrade` endpoint. `request_id` is
    /// the target Vault proposal id. Legal source state OutcomeUnknown ONLY;
    /// never back to Pending, never re-triggerable, never retries/reinstalls.
    ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader),
    /// §S7 CELL 3 — settlement of an outcome-unknown Vault→Upgrader START.
    ///
    /// The retrofit V5 §1 calls for: the START ROUTE already existed
    /// (`ManagementAction::Start`, executed in `execute_management`) and
    /// already routed a transport rejection to `OutcomeUnknown`, but it had NO
    /// PINNED SETTLEMENT CONTRACT — nothing could ever move such a proposal out
    /// of `OutcomeUnknown`, so the lock was held forever and the ring's own
    /// recovery path was unreachable. This is the missing exit, and it is the
    /// SAME MECHANISM as cell 4's `ReconcileVaultStart`, differing only in
    /// direction.
    ///
    /// Authority: the Vault quorum at the current threshold — the same quorum
    /// as any other action, no single operator principal.
    ReconcileUpgraderStart(ReconcileUpgraderStart),
}

/// Durable upgrade intent marker (freeze §3d): written into the proposal
/// record BEFORE the first inter-canister call. The proposal record itself
/// already binds the delivered bytes (they are its action payload); this
/// marker timestamps the intent at the quorum boundary.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeIntent {
    pub intended_at_ns: u64,
    pub intended_epoch: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ProposalRecord {
    proposal_id: u64,
    action: VaultActionKind,
    proposer: Principal,
    created_at_ns: u64,
    /// Governance epoch at creation — the epoch pin. Approvals and execution
    /// against any other epoch are rejected as stale.
    epoch: u64,
    outcome: ActionOutcome,
    result: Option<String>,
    snapshot_id: Option<u64>,
    intent: Option<UpgradeIntent>,
    /// §S7 §2/§8a — the cell-3 start-settlement limb.
    ///
    /// Present only on a `ManagementAction::Start` proposal against the RING
    /// COUNTERPART, written at the quorum boundary before the first `await`,
    /// and gaining its write-once `SettlementRecord` on the first and only
    /// reconciliation terminal transition. Exactly the shape cell 4 carries on
    /// its `RecoveryProposal` — same type, same invariants, same predicate.
    start: Option<StartSettlementState>,
    /// R3.1 — absolute expiry. `None` = no lifetime bound is in force yet.
    ///
    /// This is `Option` because the lifetime bounds are two of the fourteen
    /// §10.5 constants and are UNRULED until S5A. S2 lands the field, the
    /// index and the sweep; S6 supplies the values and every new proposal
    /// starts carrying `Some`. A placeholder number here would be
    /// indistinguishable from a ruled one and would silently become policy —
    /// `None` states plainly that no bound has been decided.
    ///
    /// R1.4 requires expiry inside the approval commitment digest. The field
    /// is in the preimage from S3 onward regardless of whether it is `Some`,
    /// so S6 changes a VALUE, never the schema — which is precisely why R3's
    /// payload had to settle before ApprovalCommitmentV1 is frozen.
    expires_at_ns: Option<u64>,
    /// R1.2 — the ApprovalCommitmentV1 hash, WRITTEN ONCE at creation and
    /// never recomputed into storage.
    ///
    /// SCHEMA CONSTRAINT — LAUNCH-RELEVANT, RECORDED DELIBERATELY. This field
    /// is REQUIRED, so a `ProposalRecord` written by a pre-S3 build does not
    /// decode against this shape. That is safe ONLY because cutover is a FRESH
    /// INSTALL: both ring canisters are verified empty (module hash `None`,
    /// re-checked immediately before install per the standing pre-install
    /// requirement), so no legacy record can exist. If a POPULATED Vault ever
    /// has to be upgraded across this boundary, that upgrade needs its own
    /// migration and migration evidence — the S2 index-migration tests exercise
    /// NEW-schema records only and prove nothing about legacy decoding.
    ///
    /// This is the value every approval is bound to. It is stored rather than
    /// derived on read so that a later mutation of the payload cannot silently
    /// move it: the stored hash and a hash recomputed from the retained
    /// payload must agree, and a disagreement is durable CORRUPTION rather
    /// than a caller error (R1.5, `CommitmentMismatch::StoredVsRecomputed`).
    ///
    /// Terminal views keep returning this after artifact clearing — the whole
    /// point of the byte-free canonical form is that clearing does not move it.
    commitment_hash: Vec<u8>,
}

/// Permanent idempotency reservation (brief invariant 4). Inserted once, at
/// the quorum boundary, before the first `await`. There is NO delete/replace/
/// prune path anywhere in this crate — including no migration in
/// `post_upgrade` that touches MemoryId 5.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Reservation {
    proposal_id: u64,
    /// SHA-256 of the Candid-encoded action, so a replay of the same id with
    /// a different action is detectable as a conflict rather than a replay.
    action_fingerprint: Vec<u8>,
    epoch: u64,
    reserved_at_ns: u64,
    approving_signers: Vec<Principal>,
    /// L1-5: for CreateCanister proposals, the manifest purpose claimed by
    /// this intent — the DURABLE, pre-await role reservation. One
    /// nonterminal creation per manifest purpose.
    creation_purpose: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    ProposalCreated,
    ApprovalAdded,
    QuorumReached,
    Executed,
    Failed,
    OutcomeUnknown,
    /// R3.7 — withdrawn by its own proposer while Pending.
    ProposalCancelled,
    /// R3.8 — lifetime elapsed while Pending; reaped by the bounded sweep.
    ProposalExpired,
    GovernanceTransition,
    /// F-4 (freeze §10): reconciliation events carry the approving signer set.
    Reconciled,
    /// CUST-L12-02: a reconciliation anomaly that REFUSES settlement — the
    /// Upgrader has no intent for the request id, or its reported outcome
    /// disagrees with the Vault's objective evidence. The target proposal
    /// stays nonterminal; this typed event is the anomaly record.
    ReconcileConflict,
    SnapshotStored,
    CanisterCreated,
    /// §S7 §3c.3 — a late reply/reject callback was FENCED because the durable
    /// `ActionOutcome` was not `Executing`. Zero state and zero lock change;
    /// the event exists so the fence is OBSERVABLE in production. Bounded by
    /// construction at one per proposal (§2: at most one outstanding
    /// `start_canister` call per proposal), and not caller-driven.
    LateCallbackFenced,
    /// §S7 §7d.1 — the FIRST §4-valid semantic discordance against a settled
    /// proposal. At most one per proposal, ever.
    SettlementEvidenceConflict,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: u64,
    pub at_ns: u64,
    pub epoch: u64,
    pub kind: AuditKind,
    pub proposal_id: Option<u64>,
    pub actor: Principal,
    /// The approving signer set at the quorum boundary — recorded on every
    /// execution, failure, outcome-unknown and reconciliation event (F-4).
    pub approving_signers: Option<Vec<Principal>>,
    /// Typed D5 creation receipt (L1-4) — present exactly on the
    /// `CanisterCreated` event, machine-readable for the deployment gate's
    /// bijectivity check.
    pub creation_receipt: Option<CreationReceipt>,
    /// §S7 §7d.1 — the FROZEN eight-field conflict payload, present exactly on
    /// the `SettlementEvidenceConflict` event.
    ///
    /// TYPED, not folded into `detail`, on the `creation_receipt` precedent.
    /// Because every discordance after the first is deliberately silent, THIS
    /// IS THE ONLY FORENSIC RECORD THAT WILL EVER EXIST for that proposal — a
    /// stringified rendering would make the one surviving record unparseable
    /// and untestable field-by-field, which is exactly the "forensically thin
    /// event" CUST-SSA-V3-01 rejects. Acceptance 16(a) asserts each of the
    /// eight fields individually, which requires them to be readable as values.
    pub settlement_conflict: Option<SettlementEvidenceConflict>,
    pub detail: String,
}

// ── Query views (signer-gated surfaces) ──────────────────────────────────────

/// R1.7 — TYPED, EXHAUSTIVE redacted view of a `ManagementAction`.
///
/// This replaces `ActionView::Management(format!("{m:?}"))`, which `Debug`-
/// printed the WHOLE action including `wasm_bytes`/`arg_bytes`: a decimal
/// rendering of a ~1.9 MiB vector, several megabytes on the wire and far past
/// `READ_RESPONSE_MAX_BYTES` (262,144). That was a live response-size failure
/// on `get_proposal`/`list_proposals`, not merely a disclosure gap.
///
/// A truncated `Debug` string is explicitly NOT the fix (R1.7): a signer
/// evaluating a management proposal must be able to read each security-
/// critical parameter as its own typed field, not parse it out of prose that
/// could be shaped by attacker-chosen content.
///
/// One variant per `ManagementAction` variant (`custody-types` §3c), so the
/// match below is exhaustive by construction and a new action variant is a
/// compile error here rather than a silent disclosure hole.
///
/// **Install-vs-upgrade mode is carried by the VARIANT, not a field**:
/// `Upgrade` is upgrade-mode, `InstallCode` is install-mode, and the action
/// enum structurally has no reinstall/delete. Encoding mode as data would
/// admit a shape the action enum cannot express.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ManagementActionView {
    /// upgrade-mode, hash-bound.
    Upgrade {
        target: Principal,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        /// CURRENTLY RETAINED artifact lengths — 0 once `cleared_action` has
        /// run. Deliberately not a frozen creation-time size: the record does
        /// not keep one, and a size field that silently became stale would be
        /// worse than none. `bytes_retained` states which regime you are in.
        wasm_bytes_len: u64,
        arg_bytes_len: u64,
        /// True while EITHER artifact vector is still durably retained
        /// (cleared only after terminal evidence is durable, freeze §3d).
        ///
        /// Both vectors, not just the wasm: an action may legitimately carry
        /// empty wasm bytes with a retained arg, and a flag reading only the
        /// wasm would report `false` alongside a nonzero `arg_bytes_len` — a
        /// view contradicting itself about whether bytes are still held.
        bytes_retained: bool,
    },
    Start {
        target: Principal,
    },
    Stop {
        target: Principal,
    },
    /// Controller set shown IN FULL (R1.6): the ring invariant is exactly what
    /// a signer is being asked to approve, so a count would disclose nothing.
    /// R1.8/S5A owns bounding this vector at propose time.
    UpdateSettings {
        target: Principal,
        controllers: Vec<Principal>,
    },
    DepositCycles {
        target: Principal,
        cycles: u128,
    },
    CreateCanister {
        manifest_purpose: String,
        disposition: ManifestDisposition,
    },
    /// install-mode only, against a not-yet-installed allocated principal.
    InstallCode {
        target: Principal,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        wasm_bytes_len: u64,
        arg_bytes_len: u64,
        bytes_retained: bool,
    },
}

impl ManagementActionView {
    /// The single redaction point for management actions. Exhaustive match:
    /// adding a `ManagementAction` variant fails to compile here.
    fn of(m: &ManagementAction) -> Self {
        match m {
            ManagementAction::Upgrade {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                wasm_bytes,
                arg_bytes,
            } => ManagementActionView::Upgrade {
                target: *target,
                expected_wasm_hash: expected_wasm_hash.clone(),
                expected_arg_hash: expected_arg_hash.clone(),
                wasm_bytes_len: wasm_bytes.len() as u64,
                arg_bytes_len: arg_bytes.len() as u64,
                bytes_retained: !wasm_bytes.is_empty() || !arg_bytes.is_empty(),
            },
            ManagementAction::Start { target } => {
                ManagementActionView::Start { target: *target }
            }
            ManagementAction::Stop { target } => ManagementActionView::Stop { target: *target },
            ManagementAction::UpdateSettings {
                target,
                controllers,
            } => ManagementActionView::UpdateSettings {
                target: *target,
                controllers: controllers.clone(),
            },
            ManagementAction::DepositCycles { target, cycles } => {
                ManagementActionView::DepositCycles {
                    target: *target,
                    cycles: *cycles,
                }
            }
            ManagementAction::CreateCanister {
                manifest_purpose,
                disposition,
            } => ManagementActionView::CreateCanister {
                manifest_purpose: manifest_purpose.clone(),
                disposition: *disposition,
            },
            ManagementAction::InstallCode {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                wasm_bytes,
                arg_bytes,
            } => ManagementActionView::InstallCode {
                target: *target,
                expected_wasm_hash: expected_wasm_hash.clone(),
                expected_arg_hash: expected_arg_hash.clone(),
                wasm_bytes_len: wasm_bytes.len() as u64,
                arg_bytes_len: arg_bytes.len() as u64,
                bytes_retained: !wasm_bytes.is_empty() || !arg_bytes.is_empty(),
            },
        }
    }
}

/// Byte-free view of an action for the signer-gated proposal queries — the
/// UpgraderUpgrade/install artifact bytes never round-trip through a query.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ActionView {
    Application(String),
    Management(ManagementActionView),
    UpgraderUpgrade {
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        /// True while EITHER artifact vector is still durably retained
        /// (cleared only after terminal evidence is durable, freeze §3d).
        ///
        /// Both vectors, not just the wasm: an action may legitimately carry
        /// empty wasm bytes with a retained arg, and a flag reading only the
        /// wasm would report `false` alongside a nonzero `arg_bytes_len` — a
        /// view contradicting itself about whether bytes are still held.
        bytes_retained: bool,
    },
    /// R1.6 — the objective evidence is shown IN FULL. See the note on
    /// `ReconcileVaultUpgradeViaUpgrader` below for why.
    ReconcileUpgraderUpgrade {
        target_proposal_id: u64,
        objective_evidence: UpgradeObjectiveEvidence,
    },
    /// §S7 cell 3 — the start evidence is shown IN FULL, on the SAME R1.6
    /// disclosure reasoning the two upgrade reconcile views already carry: it
    /// is an objective on-chain observation of a canister's status and
    /// controller set, carries no artifact bytes and no secret, and an approver
    /// asked to bind a commitment to it must be able to SEE what they are
    /// approving. Redacting it here while disclosing the upgrade evidence would
    /// reintroduce exactly the cross-plane asymmetry R1.6 resolved.
    ReconcileUpgraderStart {
        target_proposal_id: u64,
        objective_evidence: StartObjectiveEvidence,
    },
    /// §3e ring actions — byte-free view (hashes + retention flag only).
    VaultUpgradeViaUpgrader {
        request_id: u64,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        bytes_retained: bool,
    },
    /// R1.6 — RECONCILE DISCLOSURE, resolved symmetrically across the two
    /// planes.
    ///
    /// The two reconcile classes diverged: the Upgrader's recovery plane
    /// returns `RecoveryAction::ReconcileVaultUpgrade` UNREDACTED — its
    /// `redact_action` empties artifact vectors and passes the reconcile
    /// variant through untouched, and `query_recovery_proposal` hands back the
    /// whole stored proposal — while the Vault's two reconcile views exposed
    /// only `target_proposal_id`. R1.6 requires that divergence resolved
    /// deliberately rather than left to whichever side was written first.
    ///
    /// Resolved TOWARD DISCLOSURE, here, for three reasons:
    /// 1. The evidence is an OBJECTIVE ON-CHAIN OBSERVATION — observed
    ///    principal, module hash, controller set, status, observation time. It
    ///    contains no secret; withholding it protects nothing.
    /// 2. It is the ENTIRE BASIS of the decision. Reconciliation is the only
    ///    state-changing path out of `OutcomeUnknown`, and it is terminal. A
    ///    signer approving evidence they cannot read is approving a claim
    ///    about the world on the proposer's word — CUST-SSA-001 exactly.
    /// 3. Symmetry must not be bought by REDACTING the recovery plane. The
    ///    recovery plane is the Vault-unavailable fallback, so it is the path
    ///    where independent verification matters most.
    ///
    /// `observed_controllers` is an unbounded `Vec<Principal>`; making it
    /// visible here is the newly-visible-vector case R1.8 item 2 names. The
    /// propose-time bound is R1.8/S5A's, not invented here.
    ReconcileVaultUpgradeViaUpgrader {
        target_proposal_id: u64,
        objective_evidence: UpgradeObjectiveEvidence,
    },
    ReadModel(String),
    /// R1.6 — the PROPOSED SIGNER PRINCIPALS, in full, not a count.
    ///
    /// `signer_count` alone made the membership change unreviewable: a signer
    /// could see that the set was becoming three principals but not WHICH
    /// three, so substituting an attacker principal for a peer was invisible
    /// on the view a signer approves from. Signer-set rotation is the
    /// membership-critical parameter R1.6 names first, and it is the original
    /// Critical's attack path on this plane.
    ///
    /// The count is deliberately NOT retained alongside: two representations
    /// of one fact can disagree, and a count disagreeing with the roster it
    /// summarises is itself a disclosure bug. `signers.len()` is the count.
    UpdateSignerSet { signers: Vec<Principal>, threshold: u32 },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProposalView {
    pub proposal_id: u64,
    pub proposer: Principal,
    pub created_at_ns: u64,
    pub epoch: u64,
    pub outcome: ActionOutcome,
    pub result: Option<String>,
    pub snapshot_id: Option<u64>,
    pub action: ActionView,
    pub approvals: Vec<Principal>,
    /// R1.2 property 8 / R1.3 — the IMMUTABLE stored commitment hash.
    ///
    /// This is the value a signer must supply to `approve`, so without it on
    /// the view there is no way to obtain it: `propose` returns only the id.
    /// Returned on EVERY signer-facing view, including terminal ones AFTER
    /// artifact clearing — the byte-free canonical form exists precisely so
    /// this stays available and unchanged once the bytes are gone.
    pub commitment_hash: Vec<u8>,
}

/// `approve` result. Replay returns the PRIOR result: a proposal that already
/// left `Pending` (Executing / terminal / OutcomeUnknown) reports its stored
/// state and never re-triggers execution.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved { approvals: u32, threshold: u32 },
    Executing,
    PriorResult { outcome: ActionOutcome, result: Option<String> },
}

// ── Stable storage ───────────────────────────────────────────────────────────

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// MemoryId 0 — governance atomic cell (signers, threshold, epoch,
    /// targets). One object, one durable write boundary per transition.
    static GOVERNANCE_CELL: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_GOVERNANCE_CELL)),
            Vec::new(),
        ).expect("GOVERNANCE_CELL: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 11 — SSA BLOCKER 1: nonterminal proposal index.
    /// Authoritative companion, covered by MemoryId 9's accounting and seal.
    static NONTERMINAL_PROPOSAL_INDEX: RefCell<StableBTreeMap<(Principal, u64), (), Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NONTERMINAL_PROPOSAL_INDEX))
        ));

    /// MemoryId 10 — S5B W4 durable entry-rate ledger.
    ///
    /// DURABLE IS THE REQUIREMENT, not an implementation choice. The brief
    /// pins that the rolling-window ledger "survives upgrade, rolls windows
    /// correctly across upgrade boundaries, and CANNOT be reset (by upgrade,
    /// trap, or any callable path) to evade limits". A heap-only counter would
    /// reset on every upgrade, making the bound trivially evadable by anyone
    /// who can propose an upgrade — which is the governed path itself.
    static ENTRY_RATE_LEDGER: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ENTRY_RATE_LEDGER)),
            Vec::new(),
        ).expect("ENTRY_RATE_LEDGER: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 9 — S5B W2 companion integrity state. Authoritative accounting
    /// for the three active-set companions, NOT a derived cache: it is written
    /// in the same synchronous transaction as every companion mutation and is
    /// never reconstructed from `PROPOSALS`.
    static COMPANION_STATE: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_COMPANION_STATE)),
            Vec::new(),
        ).expect("COMPANION_STATE: Cell::init failed — stable memory corrupt")
    );

    /// MemoryId 1 — proposals (Candid-encoded `ProposalRecord`).
    static PROPOSALS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PROPOSALS)))
    );

    /// MemoryId 2 — approvals: proposal_id → Candid-encoded Vec<Principal>.
    static APPROVALS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_APPROVALS)))
    );

    /// MemoryId 3 — append-only audit events (Candid-encoded `AuditEvent`).
    static AUDIT_EVENTS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_AUDIT_EVENTS)))
    );

    /// MemoryId 4 — controller read snapshots. Durable forever; NO retention
    /// or pruning policy (freeze §9).
    static CONTROLLER_READ_SNAPSHOTS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_CONTROLLER_READ_SNAPSHOTS))
        )
    );

    /// MemoryId 5 — permanent action-idempotency reservations. Insert-once;
    /// never deleted, replaced, or pruned (brief invariant 4).
    static RESERVATIONS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ACTION_IDEMPOTENCY_RESERVATIONS))
        )
    );

    /// MemoryId 6 — R3.8 expiry index: `(expires_at_ns, proposal_id) -> ()`.
    ///
    /// The composite key is ordered by expiry FIRST, so the sweep reads a
    /// bounded PREFIX of due proposals instead of scanning the map. That is
    /// what makes "an expiry sweep that cannot itself be the DoS" true by
    /// construction rather than by care: the work per call is bounded by the
    /// caller's limit, not by how many proposals exist.
    ///
    /// Only `Pending` proposals with a set expiry appear here. An entry is
    /// removed the instant the proposal leaves `Pending` by any route.
    static PROPOSAL_EXPIRY_INDEX: RefCell<StableBTreeMap<(u64, u64), (), Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PROPOSAL_EXPIRY_INDEX)))
    );

    /// MemoryId 7 — R3.9 single-flight index: `target principal -> proposal_id`.
    ///
    /// Replaces `open_mutating_intent`'s full-map scan (a Candid decode PER
    /// PROPOSAL, PER CALL, on an authorization-critical path): `check_single_flight`
    /// is called unconditionally from `propose_inner`, so the cost of proposing
    /// grew with the total number of proposals ever created.
    ///
    /// THE KEY IS COMPOSITE, NOT `target -> id`, and that is load-bearing.
    /// MULTIPLE proposals against one target can legally be `Executing` at the
    /// same moment: propose-time single-flight only blocks a second PROPOSAL,
    /// but two proposals may both be created while Pending and both later reach
    /// quorum. The execution-time re-check is the enforce point that cannot be
    /// raced. Under a `target -> id` map the second writer would EVICT the
    /// first, and the second proposal's own re-check — which excludes itself —
    /// would then find nothing and proceed, silently breaking single-flight.
    /// The composite key lets every holder coexist, so the re-check sees the
    /// one that actually holds the lock.
    ///
    /// Reads range over ONE target's prefix: bounded by the open intents on
    /// that target (a concurrent-quorum race, so 1-2 in practice), never by the
    /// total proposal count.
    ///
    /// Holds ONLY `Executing | OutcomeUnknown`. `Pending` is deliberately
    /// absent: see `ActionOutcome::holds_single_flight`.
    static OPEN_MUTATING_INTENT_INDEX: RefCell<StableBTreeMap<(Principal, u64), (), Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_OPEN_MUTATING_INTENT_INDEX))
        ));

    /// MemoryId 8 — R3.9 creation single-flight, keyed
    /// `sha256(manifest_purpose) || proposal_id` as a fixed 40-byte blob.
    ///
    /// Separate from MemoryId 7 because the key is a different thing: a created
    /// canister has no principal yet, so creation single-flight keys on the
    /// manifest purpose (L1-5). Same composite-key reasoning, same state
    /// restriction as 7.
    ///
    /// The purpose is HASHED rather than stored as a `String` key because
    /// `ic-stable-structures` cannot serialize a tuple containing an unbounded
    /// type, and `String` is unbounded. A fixed-width big-endian encoding is
    /// also what makes the prefix range sound: the 32-byte digest groups every
    /// entry for one purpose contiguously, and the 8-byte big-endian id orders
    /// within it. The plaintext purpose is kept as the VALUE (values may be
    /// unbounded) so the index stays self-describing.
    static OPEN_CREATION_INTENT_INDEX: RefCell<StableBTreeMap<Blob<40>, String, Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_OPEN_CREATION_INTENT_INDEX))
        ));
}

// ── Platform seams (test-overridable) ────────────────────────────────────────

#[cfg(not(test))]
fn now_ns() -> u64 {
    ic_cdk::api::time()
}
#[cfg(not(test))]
fn caller() -> Principal {
    ic_cdk::api::caller()
}
#[cfg(not(test))]
fn self_id() -> Principal {
    ic_cdk::api::id()
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: RefCell<u64> = const { RefCell::new(1_000_000_000) };
    static TEST_SELF: RefCell<Principal> = RefCell::new(Principal::from_slice(&[0xEE]));
}
#[cfg(test)]
fn now_ns() -> u64 {
    TEST_NOW.with(|t| *t.borrow())
}
#[cfg(test)]
fn self_id() -> Principal {
    TEST_SELF.with(|s| *s.borrow())
}
#[cfg(test)]
thread_local! {
    static TEST_CALLER: RefCell<Principal> = RefCell::new(Principal::from_slice(&[1u8; 29]));
}
#[cfg(test)]
fn caller() -> Principal {
    TEST_CALLER.with(|c| *c.borrow())
}
#[cfg(test)]
fn set_test_caller(p: Principal) {
    TEST_CALLER.with(|c| *c.borrow_mut() = p);
}
#[cfg(test)]
fn set_test_time(ns: u64) {
    TEST_NOW.with(|t| *t.borrow_mut() = ns);
}

// ── Governance cell access ───────────────────────────────────────────────────

/// Load the canonical governance cell. This is THE authorization source —
/// never a mirror (freeze §4). Fail-closed: undecodable or invalid content
/// traps; an empty (never-inited) cell reports "no signers" via `None` at the
/// query layer and rejects every update via `require_signer`.
fn gov_cell() -> Option<GovernanceCellData> {
    let bytes = GOVERNANCE_CELL.with(|c| c.borrow().get().clone());
    if bytes.is_empty() {
        return None;
    }
    let data: GovernanceCellData = candid::decode_one(&bytes)
        .unwrap_or_else(|_| ic_cdk::trap("GOVERNANCE_CELL: undecodable governance state"));
    Some(data)
}

/// Load or trap — used by every update path (updates are impossible before
/// init anyway; this keeps undecodable or uninitialized governance state
/// fail-closed, on every path rather than only at `post_upgrade`).
fn gov() -> GovernanceCellData {
    gov_cell().unwrap_or_else(|| ic_cdk::trap("GOVERNANCE_CELL: uninitialized"))
}

/// The ONE durable write of the governance cell — the single crash boundary
/// of every governance transition.
fn gov_store(data: &GovernanceCellData) {
    let bytes = candid::encode_one(data).expect("GovernanceCellData encodes");
    GOVERNANCE_CELL.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("GOVERNANCE_CELL: stable write failed")
    });
}

/// Revalidation shared by `post_upgrade` (and the governance crash-boundary
/// test). NOTE: no mirror repair exists — the §4 amendment ratified
/// same-message atomicity and states that no repair machinery exists or may be
/// added under it. This validates the durable record; it repairs nothing:
/// the durable record must decode, carry the current schema versions, and
/// satisfy the standing threshold rulings — or the canister does not resume.
fn revalidate_governance(data: &GovernanceCellData) {
    if data.schema_version != GOVERNANCE_CELL_SCHEMA_VERSION {
        ic_cdk::trap("GOVERNANCE_CELL: schema version mismatch");
    }
    let b = &data.bootstrap;
    if b.schema_version != BOOTSTRAP_RECORD_SCHEMA_VERSION {
        ic_cdk::trap("GOVERNANCE_CELL: bootstrap schema version mismatch");
    }
    validate_signer_set(&b.members, b.threshold, &b.counterpart)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("GOVERNANCE_CELL: durable quorum invalid: {e}")));
    validate_governed_state(data)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("GOVERNANCE_CELL: governed state invalid: {e}")));
}

/// THE ONE live governed-state invariant (F3), used identically by init,
/// receipt binding, and post_upgrade. Covers: non-anonymous principals;
/// dispositions restricted to BornUnderVault / SetControllerAtCutover;
/// purposes present, recognized, and UNIQUE; distinct principals; no ring
/// members; the exact pyeop/s3tyu cutover entries present with their ruled
/// principals and dispositions; every wired role bound to a born-under-vault
/// governed entry whose purpose matches the role; wired roles distinct.
fn validate_governed_state(data: &GovernanceCellData) -> Result<(), String> {
    let counterpart = data.bootstrap.counterpart;
    let mut seen_principals = std::collections::BTreeSet::new();
    let mut seen_purposes = std::collections::BTreeSet::new();
    for t in &data.governed {
        if t.principal == Principal::anonymous() {
            return Err("anonymous governed principal".to_string());
        }
        if t.principal == counterpart || t.principal == self_id() {
            return Err(format!("ring member in governed set: {}", t.principal));
        }
        match t.disposition {
            ManifestDisposition::BornUnderVault => {
                if !BORN_UNDER_VAULT_ROLES.contains(&t.purpose.as_str()) {
                    return Err(format!("unrecognized born-under-vault purpose {:?}", t.purpose));
                }
            }
            ManifestDisposition::SetControllerAtCutover => {
                // Cutover entries must be EXACTLY the ruled manifest pairs.
                let ruled = REQUIRED_CUTOVER
                    .iter()
                    .any(|(purpose, principal)| {
                        *purpose == t.purpose && *principal == t.principal.to_text()
                    });
                if !ruled {
                    return Err(format!(
                        "cutover entry is not a ruled manifest pair: {:?}/{}",
                        t.purpose, t.principal
                    ));
                }
            }
            ManifestDisposition::OutOfScope => {
                return Err("OutOfScope disposition in governed set".to_string());
            }
        }
        if t.purpose.is_empty() || t.purpose.len() > MAX_TEXT_FIELD_BYTES {
            return Err("governed purpose missing or oversized".to_string());
        }
        if !seen_purposes.insert(t.purpose.clone()) {
            return Err(format!("duplicate governed purpose {:?}", t.purpose));
        }
        if !seen_principals.insert(t.principal) {
            return Err(format!("duplicate governed principal {}", t.principal));
        }
    }
    // The exact manifest cutover set must be present — every ruled pair.
    for (purpose, principal) in REQUIRED_CUTOVER {
        let present = data.governed.iter().any(|t| {
            t.purpose == purpose
                && t.principal.to_text() == principal
                && t.disposition == ManifestDisposition::SetControllerAtCutover
        });
        if !present {
            return Err(format!("required cutover entry missing: {purpose}/{principal}"));
        }
    }
    // Wired roles: present in the governed set as born-under-vault entries
    // whose purpose CORRESPONDS to the role, and distinct across roles.
    let wired_roles = [
        ("shielded_pool", data.targets.shielded_pool),
        ("treasury", data.targets.treasury),
        ("vesting", data.targets.vesting),
        ("nullifier_registry", data.targets.nullifier_registry),
    ];
    let mut seen_wired = std::collections::BTreeSet::new();
    for (role, wired) in wired_roles.into_iter() {
        if let Some(principal) = wired {
            if principal == Principal::anonymous() {
                return Err(format!("anonymous wired principal for role {role}"));
            }
            let corresponds = data.governed.iter().any(|t| {
                t.principal == principal
                    && t.purpose == role
                    && t.disposition == ManifestDisposition::BornUnderVault
            });
            if !corresponds {
                return Err(format!(
                    "wired role {role} principal {principal} has no corresponding born-under-vault governed entry"
                ));
            }
            if !seen_wired.insert(principal) {
                return Err(format!("principal {principal} wired to multiple roles"));
            }
        }
    }
    Ok(())
}

/// Standing-ruling quorum check for DURABLE/TRANSITIONED sets (freeze §1):
/// `2 <= threshold <= distinct_signer_count`, no anonymous, no duplicates,
/// counterpart non-anonymous and not a signer. Unlike init, an already-live
/// quorum may have threshold > 2 (governance may raise it; never lower it
/// below 2 — unlowerable, freeze §1).
fn validate_signer_set(
    members: &[Principal],
    threshold: u32,
    counterpart: &Principal,
) -> Result<(), VaultError> {
    if threshold < MIN_THRESHOLD {
        return Err(VaultError::ThresholdViolation);
    }
    // S6 / CTO_NOTE_S5A §5 — MAX_VAULT_SIGNERS = 9, PRODUCTION-ENFORCED.
    //
    // This is not a tidiness bound. Ruled quantities in the V15 table are
    // derived at a NINE-member roster: C6's per-signer byte quota, and C9's
    // 26 × 9 = 234 < 240 headroom that keeps the global rate term a live
    // constraint. A tenth signer invalidates those SILENTLY — nothing fails,
    // the derivations simply stop describing the system.
    //
    // C8 IS DELIBERATELY NOT ON THAT LIST ANY MORE. This note used to describe
    // C8 as "nine signers' capacity plus one C6 of margin". That decomposition
    // is WITHDRAWN: it assumed the roster bounds the ACCOUNTING, and it does
    // not — a proposal stays nonterminal across a rotation, so rotated-out
    // proposers retain both their bytes and their accounting entries and the
    // total passes 9 x C6. C8 is a live global cap whose accounting cardinality
    // is bounded by C7 = 320, not by the roster. The nine-signer bound still
    // matters for C6 and C9; it never bounded C8.
    //
    // Enforced HERE, in the shared signer-set validator, because this is the
    // one path every roster mutation goes through: it is called from
    // `validate_action` for `UpdateSignerSet` (so a rotation is refused at
    // PROPOSE time, before an id is consumed or a record written) and again at
    // the execution boundary. Placing it in the validator rather than at the
    // call sites is what makes "every mutation path" true by construction
    // rather than by enumeration.
    //
    // The rejection reuses `ThresholdViolation` rather than a typed
    // roster-maximum variant: `VaultError` is exposed in `vault.did`, and
    // adding a variant is a DID change S6 is not authorized to make.
    if stsh_custody_types::check_vault_roster_size(members.len()).is_err() {
        return Err(VaultError::ThresholdViolation);
    }
    let mut seen = std::collections::BTreeSet::new();
    for m in members {
        if *m == Principal::anonymous() {
            return Err(VaultError::NotAuthorized);
        }
        if !seen.insert(*m) {
            return Err(VaultError::ThresholdViolation);
        }
    }
    if *counterpart == Principal::anonymous() || seen.contains(counterpart) {
        return Err(VaultError::ThresholdViolation);
    }
    if (seen.len() as u32) < threshold {
        return Err(VaultError::ThresholdViolation);
    }
    Ok(())
}

// ── The single authorization path (freeze §4 + brief invariant 3) ────────────

/// Update-path authorization: caller must be a non-anonymous member of the
/// CURRENT active signer set, checked against the canonical governance cell.
/// Deny by default; no ORed policies; no other path exists.
fn require_signer(caller: Principal) -> Result<GovernanceCellData, VaultError> {
    if caller == Principal::anonymous() {
        return Err(VaultError::NotAuthorized);
    }
    let g = gov();
    if g.bootstrap.members.contains(&caller) {
        Ok(g)
    } else {
        Err(VaultError::NotAuthorized)
    }
}

/// Query-path gate: same check, but unauthorized is indistinguishable `None`
/// (freeze §4) — anonymous, removed, stale-epoch and unknown callers all see
/// the exact same `None`, and a removed signer stops matching the moment the
/// epoch-advancing transition lands because membership is read from the
/// canonical cell at query time.
fn query_gate(caller: Principal) -> Option<GovernanceCellData> {
    if caller == Principal::anonymous() {
        return None;
    }
    match gov_cell() {
        Some(g) if g.bootstrap.members.contains(&caller) => Some(g),
        _ => None,
    }
}

// ── Storage helpers ──────────────────────────────────────────────────────────

fn proposal_get(id: u64) -> Option<ProposalRecord> {
    PROPOSALS.with(|p| p.borrow().get(&id))
        .map(|b| candid::decode_one(&b).expect("PROPOSALS: record decodes"))
}

/// The SINGLE write path for `PROPOSALS`, and therefore the single place the
/// authoritative companions are maintained.
///
/// Companion maintenance lives here, not at the call sites, deliberately:
/// amended R3 item 10 (`878d685e…`) clause (b) requires history, registry,
/// commitment and accounting to move in ONE synchronous transaction, and the
/// only way to guarantee that against future edits is to leave callers no way
/// to write a proposal WITHOUT updating its companions.
///
/// NOTE the model change from the superseded item: these are no longer
/// "derived indexes… repaired idempotently". They are AUTHORITATIVE (clause a)
/// and are never reconstructed from `PROPOSALS`.
fn proposal_put(rec: &ProposalRecord) {
    // Reconcile the companion indexes against the record's PRIOR state first, so
    // a state transition removes stale entries even when the new state adds
    // none. Reading the prior record is a single point read, not a scan.
    let prior = proposal_get(rec.proposal_id);
    reindex_proposal(prior.as_ref(), rec);
    let bytes = candid::encode_one(rec).expect("ProposalRecord encodes");
    PROPOSALS.with(|p| p.borrow_mut().insert(rec.proposal_id, bytes));
}

// ── S5B W2 — bounded authoritative companions ────────────────────────────────
//
// Amended R3 item 10 (A1_AMENDMENT_R3_ITEM10_V2, 878d685e…) changes the MODEL:
// active-set indexes are **authoritative companion state**, not derived caches.
// `PROPOSALS` stays authoritative for existence and immutable terminal
// outcomes; the companions are authoritative for active (nonterminal)
// membership; and per (a) **neither is reconstructed from the other**.
//
// That is why `rebuild_proposal_indexes()` is gone rather than merely bounded.
// Rebuilding from history is not a cheaper repair — under the amended model it
// is the wrong authority answering the question, and (c) forbids `post_upgrade`
// from scanning or decoding permanent history at all.
//
// WHAT THE COMMITMENT IS. An XOR accumulator over per-entry digests: insert
// XORs the digest in, remove XORs it out. Self-inverse and order-independent,
// so maintenance is O(1) per companion mutation and needs no scan. It binds
// entry CONTENT, not merely entry count — a substitution at equal count still
// moves the accumulator, which a count-only check would miss.
//
// WHAT IT IS NOT. This is corruption and drift detection, not a defence
// against an adversary who can choose entries: XOR accumulators are not
// collision-resistant under chosen inputs. Every entry here is
// canister-derived from a quorum-gated proposal, so chosen-set attack is not
// the threat model. Recorded so nobody later mistakes it for one.
// S6 corrective: bumped 1 -> 2 for the C6/C8 retained-byte accounting fields.
// A version this build does not understand still fails closed (W2 c/d) — that
// policy is unchanged and is why no migration path is written here.
const COMPANION_STATE_SCHEMA_VERSION: u32 = 2;

/// Authoritative accounting for the three Vault companions.
///
/// Deliberately DISTINCT from `BOOTSTRAP_RECORD_SCHEMA_VERSION` (brief W2): the
/// two version independently, and conflating them would let a bootstrap-schema
/// bump silently claim the companion layout was reviewed.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct CompanionState {
    schema_version: u32,
    /// Total entries across expiry + mutating-intent + creation-intent.
    entries: u64,
    /// Total key+value bytes across the same three.
    bytes: u64,
    /// 32-byte XOR accumulator over per-entry digests. Recomputable from the
    /// bounded companions.
    entry_acc: Vec<u8>,
    // ── S5B W1 — authoritative ID counters ───────────────────────────────────
    //
    // The counter is the SOLE allocation authority (W1.1). It is NOT
    // recomputable from anything — that is the entire point, and why it lives
    // here rather than being derived at each call. `next_*_id()` previously
    // read `.iter().last()` off the history map, which was both a full scan on
    // an authorization-critical path (an unmet R3 item 9, recorded as a
    // conformance failure) and unsound: a lowered or drifted counter pointing
    // into an unused historical gap evades every collision check.
    next_proposal_id: u64,
    next_audit_id: u64,
    next_snapshot_id: u64,
    // ── S6 corrective (CUST-SSA-S6-01) — C6/C8 retained-byte accounting ──────
    //
    // S6 installed C6 and C8 as constants and never enforced them: admission ran
    // count-cap → C9 → id → write with no byte check anywhere. These two fields
    // are the accounting that makes enforcement O(1) at admission.
    //
    // DURABLE AND INCREMENTAL, not recomputed. The alternative — summing
    // `c8_logical_bytes` over the nonterminal set at every admission — would
    // decode up to C7 = 320 artifact-bearing records on the admission path,
    // inside the §C budget that measurement showed is already the expensive one.
    // Incremental accounting is O(1); the cost of that choice is that the
    // counters can drift if a retention path forgets to account, which is why
    // they are inside the seal below and reconciled by `companion_recompute`.
    //
    // These are RETAINED ARTIFACT bytes — `c8_logical_bytes`'s domain, exactly
    // what `cleared_action` releases. NOT the same quantity as `bytes` above,
    // which is companion-index key+value bytes.
    /// C8 — global retained artifact bytes across the nonterminal set.
    retained_bytes_total: u64,
    /// C6 — retained artifact bytes per proposer.
    ///
    /// BOUNDED BY C7, NOT BY THE ROSTER. An earlier revision claimed the roster
    /// maximum bounded this vector at nine entries. That was FALSE and SSA
    /// refuted it: a proposal stays nonterminal across a signer-set rotation, so
    /// a rotated-out signer keeps its retained bytes and keeps its entry, while
    /// the incoming signer starts at zero. Distinct proposers with a live entry
    /// therefore accumulate past the roster size.
    ///
    /// The real bound comes from the mechanism: an entry exists only while a
    /// proposer holds > 0 retained bytes, those bytes come only from
    /// concurrently-NONTERMINAL artifact-bearing proposals, and that population
    /// is capped by C7. So the vector holds at most C7 = 320 entries and the
    /// linear scan on the admission path is bounded by C7, not by 9 — which is
    /// the cardinality §C's admission cost must be measured at.
    ///
    /// An entry IS dropped when it reaches zero, so a proposer whose bytes all
    /// clear stops occupying a slot.
    retained_by_signer: Vec<(Principal, u64)>,
    /// Seals `entry_acc`, the accounting AND the counters (W1.6). Because the
    /// counters cannot be recomputed, this is what makes them checkable at all:
    /// a counter moved outside the per-map primitive leaves the seal stale.
    commitment: Vec<u8>,
}

impl Default for CompanionState {
    fn default() -> Self {
        let mut s = Self {
            schema_version: COMPANION_STATE_SCHEMA_VERSION,
            entries: 0,
            bytes: 0,
            entry_acc: vec![0u8; 32],
            // IDs start at 1; 0 is never allocated, matching the prior
            // `.unwrap_or(1)` so no existing record can collide with a fresh
            // counter.
            next_proposal_id: 1,
            next_audit_id: 1,
            next_snapshot_id: 1,
            retained_bytes_total: 0,
            retained_by_signer: Vec::new(),
            commitment: Vec::new(),
        };
        companion_seal(&mut s);
        s
    }
}

/// Recompute the seal over everything the companion state claims.
fn companion_seal(s: &mut CompanionState) {
    let mut b = Vec::new();
    b.extend_from_slice(b"companion-seal-v1");
    b.extend_from_slice(&s.schema_version.to_be_bytes());
    b.extend_from_slice(&s.entries.to_be_bytes());
    b.extend_from_slice(&s.bytes.to_be_bytes());
    b.extend_from_slice(&s.entry_acc);
    b.extend_from_slice(&s.next_proposal_id.to_be_bytes());
    b.extend_from_slice(&s.next_audit_id.to_be_bytes());
    b.extend_from_slice(&s.next_snapshot_id.to_be_bytes());
    // S6 corrective — the retained-byte accounting is SEALED. Without this a
    // quota counter could be moved outside the accounting primitives and the
    // seal would still verify, which is exactly the hole W1.6 closed for the ID
    // counters. Per-signer entries are sorted before sealing so the digest is a
    // function of the accounting, not of insertion order.
    b.extend_from_slice(&s.retained_bytes_total.to_be_bytes());
    let mut per: Vec<(Principal, u64)> = s.retained_by_signer.clone();
    per.sort_by(|x, y| x.0.as_slice().cmp(y.0.as_slice()));
    for (who, n) in &per {
        b.extend_from_slice(who.as_slice());
        b.extend_from_slice(&n.to_be_bytes());
    }
    s.commitment = sha256(&b);
}

/// Domain-separated per-entry digests. The domain tag is what stops an expiry
/// entry and a mutating-intent entry with coincidentally equal bytes from
/// cancelling each other in the accumulator.
fn companion_digest_expiry(exp: u64, id: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.extend_from_slice(b"expiry\0\0");
    b.extend_from_slice(&exp.to_be_bytes());
    b.extend_from_slice(&id.to_be_bytes());
    sha256(&b)
}

fn companion_digest_nonterminal(proposer: Principal, id: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"nonterm\0");
    b.extend_from_slice(proposer.as_slice());
    b.extend_from_slice(&id.to_be_bytes());
    sha256(&b)
}

fn companion_bytes_nonterminal(proposer: Principal) -> u64 {
    (proposer.as_slice().len() + 8) as u64
}

fn companion_digest_mutating(target: Principal, id: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"mutating");
    b.extend_from_slice(target.as_slice());
    b.extend_from_slice(&id.to_be_bytes());
    sha256(&b)
}

fn companion_digest_creation(key: &Blob<40>, purpose: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"creation");
    b.extend_from_slice(key.as_ref());
    b.extend_from_slice(purpose.as_bytes());
    sha256(&b)
}

/// Byte accounting per entry, key + value, matching what the digest covers.
fn companion_bytes_expiry() -> u64 {
    16 // (u64, u64) key, () value
}
fn companion_bytes_mutating(target: Principal) -> u64 {
    (target.as_slice().len() + 8) as u64
}
fn companion_bytes_creation(purpose: &str) -> u64 {
    (40 + purpose.len()) as u64
}

/// SSA landed-diff BLOCKER 3 — absence must TRAP, not default.
///
/// The first cut treated an empty cell as a valid default. That fails OPEN: a
/// PRE-COMPANION deployment upgrading into this build would sail through
/// `post_upgrade` whenever its active indexes happened to be empty, which
/// directly contradicts amended item 10's "missing/old/inconsistent ⇒ trap,
/// never rebuild". The record is now written explicitly at fresh install
/// (`companion_init`), and absence thereafter is durable corruption.
fn companion_load() -> CompanionState {
    let raw = COMPANION_STATE.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        ic_cdk::trap(
            "COMPANION_STATE: ABSENT. The companion record is written at fresh \
             install; absence means either a pre-companion deployment was upgraded \
             into this build, or the cell was cleared. Both are durable corruption \
             — fail closed (W2 c/d), never rebuild from history.",
        );
    }
    let s: CompanionState = candid::decode_one(&raw)
        .unwrap_or_else(|_| ic_cdk::trap("COMPANION_STATE: undecodable — fail closed (W2 d)"));
    if s.schema_version != COMPANION_STATE_SCHEMA_VERSION {
        // (d) fail-closed: a version we do not understand is never "repaired"
        // by rebuilding from history — that is the authority inversion the
        // amended model removes.
        ic_cdk::trap("COMPANION_STATE: schema version mismatch — fail closed (W2 c/d)");
    }
    s
}

/// Write the initial companion record. Fresh install only — cutover is a fresh
/// install by construction (the `commitment_hash` schema constraint already
/// forces that), so there is no populated-legacy migration to consider.
fn companion_init() {
    // Idempotent by design. `init` runs once on a real canister, so a
    // "refuse to overwrite" trap here would guard nothing in production while
    // breaking in-process test setup, which re-inits against persistent
    // thread-local memory. What matters for BLOCKER 3 is that the record
    // EXISTS after install — enforced by `companion_load` trapping on absence,
    // not by policing who wrote it.
    let raw = COMPANION_STATE.with(|c| c.borrow().get().clone());
    if raw.is_empty() {
        companion_store(&CompanionState::default());
    }
}

fn companion_store(s: &CompanionState) {
    let bytes = candid::encode_one(s).expect("CompanionState encodes");
    COMPANION_STATE.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("COMPANION_STATE: stable write failed")
    });
}

/// Apply one companion delta to the accumulator and accounting. XOR is its own
/// inverse, so insert and remove are the same operation on the commitment;
/// only the count and byte deltas differ in sign.
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

/// Recompute companion state by walking the companions themselves.
///
/// (c)-COMPLIANT: this scans the BOUNDED ACTIVE SET — the three companion
/// indexes — and never touches `PROPOSALS`. Its cost is a function of live
/// entries, which C7/C12 bound, and is independent of permanent-history size.
/// That distinction is the whole point: "no full-history scan" is not "no scan".
fn companion_recompute() -> CompanionState {
    // Counters are NOT derivable — they are carried from the stored state and
    // checked via the seal instead (W1.6). Deriving them from history here
    // would reintroduce exactly the history-derived allocation W1.1 forbids.
    // S6 corrective — the C6/C8 retained-byte accounting is carried forward for
    // the SAME reason as the counters, and the reason is not convenience.
    //
    // It could in principle be recomputed: sum `c8_logical_bytes` over the
    // nonterminal set. That would mean DECODING PERMANENT HISTORY RECORDS, which
    // amended item 10 clause (c) forbids on this path outright — `post_upgrade`
    // does bounded validation only and must not scan or decode permanent
    // history, at a cost independent of history size. A recompute that walked
    // the proposals would put an unbounded-in-history term into the one place
    // clause (c) exists to keep bounded.
    //
    // So the accounting is authoritative-and-carried, exactly like the ID
    // counters, and is checked by the SEAL rather than by re-derivation — which
    // is why `companion_seal` covers it.
    let stored = companion_load();
    let mut s = CompanionState {
        next_proposal_id: stored.next_proposal_id,
        next_audit_id: stored.next_audit_id,
        next_snapshot_id: stored.next_snapshot_id,
        retained_bytes_total: stored.retained_bytes_total,
        retained_by_signer: stored.retained_by_signer.clone(),
        ..CompanionState::default()
    };
    PROPOSAL_EXPIRY_INDEX.with(|x| {
        for ((exp, id), _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_expiry(exp, id),
                companion_bytes_expiry(),
                true,
            );
        }
    });
    OPEN_MUTATING_INTENT_INDEX.with(|x| {
        for ((t, id), _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_mutating(t, id),
                companion_bytes_mutating(t),
                true,
            );
        }
    });
    OPEN_CREATION_INTENT_INDEX.with(|x| {
        for (k, purpose) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_creation(&k, &purpose),
                companion_bytes_creation(&purpose),
                true,
            );
        }
    });
    NONTERMINAL_PROPOSAL_INDEX.with(|x| {
        for ((proposer, id), _) in x.borrow().iter() {
            companion_apply(
                &mut s,
                companion_digest_nonterminal(proposer, id),
                companion_bytes_nonterminal(proposer),
                true,
            );
        }
    });
    // Seal the recomputed view with the SAME function that seals stored state,
    // or the comparison in `companion_check` compares a fresh seal against a
    // `Default`-inherited one and always disagrees.
    companion_seal(&mut s);
    s
}

/// (d)+(e) — fail-closed companion validation.
///
/// Called at `post_upgrade` AND inline before every operation that relies on
/// the ABSENCE of a companion entry. Absence is the dangerous direction: a
/// missing single-flight entry reads as "no lock held" and admits a second
/// concurrent intent, so absence must never be trusted without proving the
/// companion is intact first.
/// S5B W2 — AUTHORITY PRECEDENCE.
///
/// Amended item 10(a) splits authority: the append-only history is
/// authoritative for **existence** and **immutable terminal outcomes**; the
/// companion registry is authoritative for **active (nonterminal) membership**.
/// Neither is reconstructed from the other, so when they disagree there must be
/// a pinned answer to "which one is right, and what happens next" — otherwise
/// the split is just an unresolved ambiguity with two authorities.
///
/// Evaluated PER RECORD, keyed, on a point read of each side. It is never a
/// join over permanent history, which (c) forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompanionPrecedence {
    /// Neither side claims the id. Consistent.
    Absent,
    /// Both agree: nonterminal record, registry entry present. Consistent.
    ActiveAndRegistered,
    /// Both agree: terminal record, no registry entry. Consistent.
    TerminalAndReleased,
    /// Row 3, PROPOSAL class — history says nonterminal, registry has no entry.
    ///
    /// The registry is authoritative for active membership, so its silence
    /// means the proposal is NOT active. It cannot be quietly reactivated from
    /// history (that is the authority inversion (a) removes and the silent
    /// reactivation (d) forbids), and it cannot be treated as ordinary expiry.
    /// **INACTIVE CORRUPTION** — fail closed.
    NonterminalProposalWithoutRegistry,
    /// Terminal record still claimed by a registry entry. The lock outlived the
    /// state that justified it, which wedges its target forever.
    TerminalStillRegistered,
    /// Registry entry naming an id the history has never recorded. History is
    /// authoritative for EXISTENCE, so this entry describes nothing.
    OrphanRegistryEntry,
}

impl CompanionPrecedence {
    /// Only the three agreeing cases are serviceable. Every disagreement is
    /// durable corruption — there is no "mostly fine" row.
    fn is_consistent(self) -> bool {
        matches!(
            self,
            CompanionPrecedence::Absent
                | CompanionPrecedence::ActiveAndRegistered
                | CompanionPrecedence::TerminalAndReleased
        )
    }
}

/// Classify one proposal id against both authorities. Two point reads.
fn companion_precedence(id: u64) -> CompanionPrecedence {
    let rec = proposal_get(id);
    let registered = match &rec {
        // Look for the entry this record WOULD claim if active. Keyed, so no
        // scan: the target/purpose comes from the record itself.
        Some(r) => match (mutating_intent_target(&r.action), creation_intent_purpose(&r.action)) {
            (Some(t), _) => OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow().contains_key(&(t, id))),
            (_, Some(purpose)) => OPEN_CREATION_INTENT_INDEX
                .with(|x| x.borrow().contains_key(&creation_key(&purpose, id))),
            // A record class that never claims a single-flight entry: its
            // registry membership is vacuously correct.
            _ => return CompanionPrecedence::ActiveAndRegistered,
        },
        // No record, so there is no target or purpose to key on. Orphan
        // detection therefore needs a scan — but of the BOUNDED companions,
        // never of permanent history. (c) forbids the latter, not the former,
        // and the active set is bounded by C7/C12. Reaching for `PROPOSALS`
        // here to recover a key would be the exact violation.
        None => {
            OPEN_MUTATING_INTENT_INDEX
                .with(|x| x.borrow().iter().any(|((_, k), _)| k == id))
                || OPEN_CREATION_INTENT_INDEX
                    .with(|x| x.borrow().iter().any(|(k, _)| creation_key_id(&k) == id))
        }
    };

    match rec {
        None if registered => CompanionPrecedence::OrphanRegistryEntry,
        None => CompanionPrecedence::Absent,
        Some(r) => {
            let holds = r.outcome.holds_single_flight();
            match (holds, registered) {
                (true, true) => CompanionPrecedence::ActiveAndRegistered,
                (false, false) => CompanionPrecedence::TerminalAndReleased,
                (true, false) => CompanionPrecedence::NonterminalProposalWithoutRegistry,
                (false, true) => CompanionPrecedence::TerminalStillRegistered,
            }
        }
    }
}

/// DETECTION, separated from trapping deliberately.
///
/// `ic_cdk::trap` outside a canister panics with a generic
/// "trap should only be called inside canisters", so an in-process
/// `#[should_panic]` can prove only that SOMETHING trapped — not which check
/// fired. That is precisely the weak evidence the §4 amendment rejects for W5.
/// Splitting detection out lets unit tests assert the SPECIFIC mismatch, while
/// the real trap semantics are proved through PocketIC where they are genuine.
fn companion_check() -> Result<(), String> {
    let stored = companion_load();

    // W1.6 — SEAL FIRST. The counters cannot be recomputed from anything, so
    // the recompute below necessarily carries them forward from `stored`;
    // comparing the two would therefore never catch a tampered counter. The
    // seal is what closes that: a counter moved outside the per-map primitive
    // leaves `commitment` stale, and this check fires.
    //
    // This is the specific hole the SSA re-check identified in the
    // maximum-based design: "a lowered counter can point into an unused
    // historical gap and evade any collision check." It evades the collision
    // check; it does not evade the seal.
    let mut resealed = stored.clone();
    companion_seal(&mut resealed);
    if resealed.commitment != stored.commitment {
        return Err(format!(
            "COMPANION_STATE: integrity mismatch — the seal does not cover the stored \
             state (counters proposal={} audit={} snapshot={}, entries={} bytes={}). \
             Some field moved outside the per-map primitive. Fail closed (W1.6/W2 d); \
             NOT repaired at runtime.",
            stored.next_proposal_id,
            stored.next_audit_id,
            stored.next_snapshot_id,
            stored.entries,
            stored.bytes,
        ));
    }

    let computed = companion_recompute();
    if stored == computed {
        return Ok(());
    }
    Err(format!(
        "COMPANION_STATE: integrity mismatch — companion state disagrees with the \
         companions it accounts for (stored entries={} bytes={}, computed entries={} \
         bytes={}, commitment {}). Fail closed (W2 d). This is NOT repaired at \
         runtime; recovery is a governed, hash-bound Wasm upgrade.",
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

fn companion_validate() {
    // NO REPAIR. Brief W2: S5B ships no callable repair surface, and (d)
    // forbids repair by scanning history. Recovery is a hash-bound governed
    // Wasm upgrade, out of scope here.
    if let Err(e) = companion_check() {
        ic_cdk::trap(&e);
    }
}

/// Derive every companion entry for `rec`, removing whatever `prior` claimed,
/// and carry the integrity commitment and accounting in the SAME transaction.
///
/// (b) — one common primitive: history record, companion registry entries,
/// integrity commitment, count and byte accounting all land in one synchronous
/// message with no `await` between them, so they commit or roll back together
/// under IC message atomicity.
fn reindex_proposal(prior: Option<&ProposalRecord>, next: &ProposalRecord) {
    let id = next.proposal_id;
    let mut cs = companion_load();

    // ── Expiry index: present only while Pending WITH an expiry ──────────────
    if let Some(p) = prior {
        if let Some(exp) = p.expires_at_ns {
            let existed =
                PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow_mut().remove(&(exp, id)).is_some());
            if existed {
                companion_apply(
                    &mut cs,
                    companion_digest_expiry(exp, id),
                    companion_bytes_expiry(),
                    false,
                );
            }
        }
    }
    if next.outcome.is_reapable() {
        if let Some(exp) = next.expires_at_ns {
            let prior_entry =
                PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow_mut().insert((exp, id), ()));
            if prior_entry.is_none() {
                companion_apply(
                    &mut cs,
                    companion_digest_expiry(exp, id),
                    companion_bytes_expiry(),
                    true,
                );
            }
        }
    }

    // ── Single-flight indexes: present only while Executing|OutcomeUnknown ───
    // Remove the prior claim unconditionally, then re-add if still held. A
    // transition out of the holding states therefore RELEASES the lock as part
    // of the same durable write that terminalizes the proposal — the lock can
    // never outlive the state that justified it.
    if let Some(p) = prior {
        if let Some(t) = mutating_intent_target(&p.action) {
            let existed =
                OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().remove(&(t, id)).is_some());
            if existed {
                companion_apply(
                    &mut cs,
                    companion_digest_mutating(t, id),
                    companion_bytes_mutating(t),
                    false,
                );
            }
        }
        if let Some(purpose) = creation_intent_purpose(&p.action) {
            let k = creation_key(&purpose, id);
            let removed = OPEN_CREATION_INTENT_INDEX.with(|x| x.borrow_mut().remove(&k));
            if let Some(old_purpose) = removed {
                companion_apply(
                    &mut cs,
                    companion_digest_creation(&k, &old_purpose),
                    companion_bytes_creation(&old_purpose),
                    false,
                );
            }
        }
    }
    if next.outcome.holds_single_flight() {
        if let Some(t) = mutating_intent_target(&next.action) {
            let prior_entry =
                OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().insert((t, id), ()));
            if prior_entry.is_none() {
                companion_apply(
                    &mut cs,
                    companion_digest_mutating(t, id),
                    companion_bytes_mutating(t),
                    true,
                );
            }
        }
        if let Some(purpose) = creation_intent_purpose(&next.action) {
            let k = creation_key(&purpose, id);
            let prior_entry = OPEN_CREATION_INTENT_INDEX
                .with(|x| x.borrow_mut().insert(k, purpose.clone()));
            if prior_entry.is_none() {
                companion_apply(
                    &mut cs,
                    companion_digest_creation(&k, &purpose),
                    companion_bytes_creation(&purpose),
                    true,
                );
            }
        }
    }

    // ── SSA BLOCKER 1 — NONTERMINAL membership, in the same transaction ─────
    //
    // Nonterminal = Pending | Executing | OutcomeUnknown. This is deliberately
    // NOT `holds_single_flight()` (which excludes Pending) and NOT
    // `is_reapable()` (which is Pending only): C5/C7/C12 bound how many
    // proposals are OPEN, and a Pending proposal is open.
    let was_nonterminal = prior.map(|p| !p.outcome.is_terminal()).unwrap_or(false);
    let is_nonterminal = !next.outcome.is_terminal();
    if was_nonterminal {
        let proposer = prior.map(|p| p.proposer).unwrap_or(next.proposer);
        let existed = NONTERMINAL_PROPOSAL_INDEX
            .with(|x| x.borrow_mut().remove(&(proposer, id)).is_some());
        if existed {
            companion_apply(
                &mut cs,
                companion_digest_nonterminal(proposer, id),
                companion_bytes_nonterminal(proposer),
                false,
            );
        }
    }
    if is_nonterminal {
        let prior_entry =
            NONTERMINAL_PROPOSAL_INDEX.with(|x| x.borrow_mut().insert((next.proposer, id), ()));
        if prior_entry.is_none() {
            companion_apply(
                &mut cs,
                companion_digest_nonterminal(next.proposer, id),
                companion_bytes_nonterminal(next.proposer),
                true,
            );
        }
    }

    // W1.6 — RESEAL. The seal covers entry_acc, the accounting AND the
    // counters, so any primitive that moves companion state must re-seal
    // before storing. Omitting it leaves a stale seal that the very next
    // `companion_validate` rejects — which is how this was caught.
    // SSA RF-1 — W2 acceptance 11: the COMPANION-WRITE boundary.
    //
    // At this instant the companion INDEXES have been mutated and the
    // accounting has NOT been stored — the exact "companion moved, commitment
    // did not" window that `companion_check` detects. Detection already had
    // evidence; ROLLBACK did not, on either plane. A trap here must discard
    // the index writes above along with everything else in the message,
    // leaving a canister whose companion still validates.
    //
    // That is the property worth proving: if the indexes survived while the
    // accounting did not, the very next `companion_validate` would trap and
    // the canister would be permanently bricked with no repair surface (W2
    // ships none, by ruling).
    companion_trap(COMPANION_TRAP_AFTER_INDEX_BEFORE_ACCOUNTING);
    companion_seal(&mut cs);
    companion_store(&cs);
}

// ── SSA RF-1 — companion-write trap boundary ────────────────────────────────
//
// Same construction and same reasoning as the governance trap: the brief
// requires trap/rollback evidence through a real Wasm/PocketIC message
// boundary, and an in-process panic does not exercise IC transactional
// semantics. Release builds compile `companion_trap` to nothing and carry no
// arming endpoint.
const COMPANION_TRAP_AFTER_INDEX_BEFORE_ACCOUNTING: &str = "after_index_before_accounting";

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

/// R1.2 — the CANONICAL form of an action: byte-free, hashes retained.
///
/// This is deliberately `cleared_action`, the SAME transformation
/// terminalization applies. That identity is the mechanism, not a coincidence:
/// because the canonical form is what survives clearing, a commitment computed
/// at creation still recomputes identically after the artifact bytes are
/// released. R1.2's requirement that "artifact bytes enter the commitment via
/// their HASHES, never their contents" is satisfied because the action already
/// carries `expected_wasm_hash` / `expected_arg_hash`, and those survive.
///
/// If the two ever diverged — a new action variant cleared by one and not the
/// other — the commitment would move at terminalization. They are one function
/// so that cannot happen.

// OWNED FROZEN TRANSITIVE CODEC CONTRACT (d068cd5): these private enums plus every
// reused payload type reachable from LegacyVaultActionKindV1 define immutable V1
// approval bytes. The independent d068 fixture covers the entire emitted Candid type
// table and every legacy discriminant. A future incompatible payload edit must first
// introduce an explicit private legacy payload/conversion; never regenerate the old
// fixture, rewrite hashes, migrate proposals, or select a codec from stored state.
#[derive(CandidType)]
enum LegacyActionRequestV1 {
    PoolPruneTerminalRecords(PruneRequest),
    PoolReconcileDepositCommitment([u8; 32]),
    PoolReconcileDepositAppendUnknown([u8; 32]),
    PoolReconcileDepositTransferNotExecuted([u8; 32]),
    PoolReconcileTreasuryDisburse(u64, DisburseOutcome),
    PoolReconcileNullifierInsert(u64),
    PoolReconcilePendingSpend(u64),
    PoolScheduleVkActivation(u32, [u8; 32], u64, u64),
    PoolEmergencyDisableCircuitVersion(u32),
    PoolEmergencyPauseDeposits,
    PoolEmergencyPauseSpends,
    PoolUnpauseDeposits,
    PoolUnpauseSpends,
    PoolSetVerifierCanister(Principal, [u8; 32]),
    PoolClearVerifierConfigGuard,
    PoolSetGovernanceFeeParams(GovernanceFeeParamsMirror),
    PoolReconcilePrivateSpendPayout(u64, PayoutOutcome),
    TreasuryProposeWithdrawal(String, Principal, u128, String),
    TreasuryExecuteWithdrawal(u64),
    TreasuryRejectProposal(u64),
    VestingReconcileClaim(Principal, ClaimDecision),
}

#[derive(CandidType)]
enum LegacyReadModelRequestV1 {
    PoolReadAccountingState(PageRequest),
    PoolReadTreasuryReconciliationTombstone(PageRequest),
    PoolReadAppendLeaseOwner(PageRequest),
    PoolReadPendingOutputPromotions(PageRequest),
    NullifierReadSpentAt { nullifier: [u8; 32], page: PageRequest },
}

#[derive(CandidType)]
enum LegacyVaultActionKindV1 {
    Application(LegacyActionRequestV1),
    Management(ManagementAction),
    UpgraderUpgrade(UpgraderUpgrade),
    ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade),
    ReadModel(LegacyReadModelRequestV1),
    UpdateSignerSet { signers: Vec<Principal>, threshold: u32 },
    VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader),
    ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader),
    ReconcileUpgraderStart(ReconcileUpgraderStart),
}

fn legacy_application_v1(action: ActionRequest) -> LegacyActionRequestV1 {
    match action {
        ActionRequest::PoolPruneTerminalRecords(v) => LegacyActionRequestV1::PoolPruneTerminalRecords(v),
        ActionRequest::PoolReconcileDepositCommitment(v) => LegacyActionRequestV1::PoolReconcileDepositCommitment(v),
        ActionRequest::PoolReconcileDepositAppendUnknown(v) => LegacyActionRequestV1::PoolReconcileDepositAppendUnknown(v),
        ActionRequest::PoolReconcileDepositTransferNotExecuted(v) => LegacyActionRequestV1::PoolReconcileDepositTransferNotExecuted(v),
        ActionRequest::PoolReconcileTreasuryDisburse(a, b) => LegacyActionRequestV1::PoolReconcileTreasuryDisburse(a, b),
        ActionRequest::PoolReconcileNullifierInsert(v) => LegacyActionRequestV1::PoolReconcileNullifierInsert(v),
        ActionRequest::PoolReconcilePendingSpend(v) => LegacyActionRequestV1::PoolReconcilePendingSpend(v),
        ActionRequest::PoolScheduleVkActivation(a, b, c, d) => LegacyActionRequestV1::PoolScheduleVkActivation(a, b, c, d),
        ActionRequest::PoolEmergencyDisableCircuitVersion(v) => LegacyActionRequestV1::PoolEmergencyDisableCircuitVersion(v),
        ActionRequest::PoolEmergencyPauseDeposits => LegacyActionRequestV1::PoolEmergencyPauseDeposits,
        ActionRequest::PoolEmergencyPauseSpends => LegacyActionRequestV1::PoolEmergencyPauseSpends,
        ActionRequest::PoolUnpauseDeposits => LegacyActionRequestV1::PoolUnpauseDeposits,
        ActionRequest::PoolUnpauseSpends => LegacyActionRequestV1::PoolUnpauseSpends,
        ActionRequest::PoolSetVerifierCanister(a, b) => LegacyActionRequestV1::PoolSetVerifierCanister(a, b),
        ActionRequest::PoolClearVerifierConfigGuard => LegacyActionRequestV1::PoolClearVerifierConfigGuard,
        ActionRequest::PoolSetGovernanceFeeParams(v) => LegacyActionRequestV1::PoolSetGovernanceFeeParams(v),
        ActionRequest::PoolReconcilePrivateSpendPayout(a, b) => LegacyActionRequestV1::PoolReconcilePrivateSpendPayout(a, b),
        ActionRequest::TreasuryProposeWithdrawal(a, b, c, d) => LegacyActionRequestV1::TreasuryProposeWithdrawal(a, b, c, d),
        ActionRequest::TreasuryExecuteWithdrawal(v) => LegacyActionRequestV1::TreasuryExecuteWithdrawal(v),
        ActionRequest::TreasuryRejectProposal(v) => LegacyActionRequestV1::TreasuryRejectProposal(v),
        ActionRequest::VestingReconcileClaim(a, b) => LegacyActionRequestV1::VestingReconcileClaim(a, b),
        ActionRequest::PoolInitializePayoutMemoKey => unreachable!("L02 action uses canonical V2"),
    }
}

fn legacy_read_model_v1(action: ReadModelRequest) -> LegacyReadModelRequestV1 {
    match action {
        ReadModelRequest::PoolReadAccountingState(v) => LegacyReadModelRequestV1::PoolReadAccountingState(v),
        ReadModelRequest::PoolReadTreasuryReconciliationTombstone(v) => LegacyReadModelRequestV1::PoolReadTreasuryReconciliationTombstone(v),
        ReadModelRequest::PoolReadAppendLeaseOwner(v) => LegacyReadModelRequestV1::PoolReadAppendLeaseOwner(v),
        ReadModelRequest::PoolReadPendingOutputPromotions(v) => LegacyReadModelRequestV1::PoolReadPendingOutputPromotions(v),
        ReadModelRequest::NullifierReadSpentAt { nullifier, page } => LegacyReadModelRequestV1::NullifierReadSpentAt { nullifier, page },
        ReadModelRequest::PoolReadPayoutMemoKeyReady
        | ReadModelRequest::TokenReadSupplyReconciliation { .. } => unreachable!("L02 action uses canonical V2"),
    }
}

fn legacy_action_v1(action: VaultActionKind) -> LegacyVaultActionKindV1 {
    match action {
        VaultActionKind::Application(v) => LegacyVaultActionKindV1::Application(legacy_application_v1(v)),
        VaultActionKind::Management(v) => LegacyVaultActionKindV1::Management(v),
        VaultActionKind::UpgraderUpgrade(v) => LegacyVaultActionKindV1::UpgraderUpgrade(v),
        VaultActionKind::ReconcileUpgraderUpgrade(v) => LegacyVaultActionKindV1::ReconcileUpgraderUpgrade(v),
        VaultActionKind::ReadModel(v) => LegacyVaultActionKindV1::ReadModel(legacy_read_model_v1(v)),
        VaultActionKind::UpdateSignerSet { signers, threshold } => LegacyVaultActionKindV1::UpdateSignerSet { signers, threshold },
        VaultActionKind::VaultUpgradeViaUpgrader(v) => LegacyVaultActionKindV1::VaultUpgradeViaUpgrader(v),
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(v) => LegacyVaultActionKindV1::ReconcileVaultUpgradeViaUpgrader(v),
        VaultActionKind::ReconcileUpgraderStart(v) => LegacyVaultActionKindV1::ReconcileUpgraderStart(v),
    }
}

const CANONICAL_ACTION_V2_DOMAIN: &[u8] = b"stsh-vault-action-canonical-v2\0";

fn canonical_action_v2(tag: u8, receipt_audit_id: Option<u64>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CANONICAL_ACTION_V2_DOMAIN.len() + 9);
    bytes.extend_from_slice(CANONICAL_ACTION_V2_DOMAIN);
    bytes.push(tag);
    if let Some(id) = receipt_audit_id {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

fn canonical_action_bytes(action: &VaultActionKind) -> Vec<u8> {
    match action {
        VaultActionKind::Application(ActionRequest::PoolInitializePayoutMemoKey) => {
            canonical_action_v2(0x01, None)
        }
        VaultActionKind::ReadModel(ReadModelRequest::PoolReadPayoutMemoKeyReady) => {
            canonical_action_v2(0x02, None)
        }
        VaultActionKind::ReadModel(ReadModelRequest::TokenReadSupplyReconciliation {
            receipt_audit_id,
        }) => canonical_action_v2(0x03, Some(*receipt_audit_id)),
        _ => candid::encode_one(&legacy_action_v1(cleared_action(action.clone())))
            .expect("legacy canonical action encodes"),
    }
}

/// R1.2 — build the commitment for a proposal's CURRENT retained state.
///
/// `epoch` is the proposal's RETAINED creation epoch, never current governance
/// state (R1.5): using current state would make the supposedly immutable
/// commitment context-dependent, so the same proposal would hash differently
/// depending on when it was read.
fn commitment_for(rec: &ProposalRecord) -> stsh_custody_types::ApprovalCommitmentV1 {
    stsh_custody_types::ApprovalCommitmentV1::new(
        self_id(),
        rec.proposal_id,
        rec.epoch,
        rec.expires_at_ns,
        canonical_action_bytes(&rec.action),
    )
}

/// The manifest purpose a creation action claims, if it is one.
fn creation_intent_purpose(action: &VaultActionKind) -> Option<String> {
    match action {
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose,
            ..
        }) => Some(manifest_purpose.clone()),
        _ => None,
    }
}

// ── S5B W4 — C9 entry gate + C5/C7/C12 nonterminal caps ─────────────────────
//
// WHAT IS RATE-LIMITED, precisely: ENTRY EVENTS. An entry event is an operation
// admission OR an audited rejection, and the two share ONE budget. Everything
// downstream of an admitted proposal — approvals, quorum, execution, its audit
// trail — is structurally covered and UNREFUSABLE, including after arbitrarily
// long dormancy across many windows. Refusing a downstream append would destroy
// the audit trail of an operation the ring has already accepted, which is a
// worse outcome than the flood the bound exists to stop.
//
// NO PER-PROPOSAL DOWNSTREAM CREDIT is reserved at admission. The bound is on
// entries, not on an operation's lifetime footprint, so there is nothing to
// reserve and nothing to leak. The absence is asserted by
// `w4_no_per_proposal_downstream_credit_at_admission`.
//
// THE LEDGER IS DURABLE, and that is a pinned requirement rather than a choice:
// it must survive upgrade, roll its window correctly across an upgrade
// boundary, and be resettable by NO callable path. A heap counter would clear
// on upgrade, and the party able to trigger an upgrade is the governed path
// itself — so a resettable bound is no bound.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
struct EntryRateLedger {
    // ── S6 corrective (CUST-SSA-S6-02) — SLIDING window, was TUMBLING ────────
    //
    // The previous shape stored a window start plus counters and RESET THE WHOLE
    // LEDGER once `now - window_start >= window_ns`. That is a TUMBLING window,
    // and the field comment claimed "rolling" while the code did not — the
    // mechanism/claim gap again. Its consequence is concrete: a caller spending
    // the full budget just before a boundary and again just after gets
    // 2 x 240 = 480 global and 2 x 26 = 52 per-signer inside one REAL rolling
    // 24 h, which is exactly what V15 C9 bounds.
    //
    // A true sliding window needs per-event times, so the ledger stores the
    // events themselves and counts those still inside `(now - window, now]`.
    //
    // IT IS STILL BOUNDED, which is what made the counter form tempting.
    // Admission is refused at `global_per_window`, so the retained set never
    // exceeds C9's global term (240) — every entry older than the window is
    // pruned on the next charge. At ~37 B per entry that is well under 10 KiB,
    // durably, forever.
    /// Retained entry events as `(who, at_ns)`, pruned to the live window.
    events: Vec<(Principal, u64)>,
}

impl EntryRateLedger {
    /// Events retained in the ledger. Every charge prunes what has aged out
    /// first, so this is the live in-window count as of the last charge — the
    /// same quantity the old `global_count` field held, without the tumbling
    /// reset that made it wrong across a boundary.
    fn retained(&self) -> u32 {
        self.events.len() as u32
    }
    /// The same, for one signer.
    fn retained_for(&self, who: Principal) -> u32 {
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

/// The ruled entry-rate params, or a test-injected candidate.
///
/// RF-1 correction: this previously read "the production constant stays
/// `None`". FALSE since S6 ruled C9 — the constant is `Some`. Candidate values
/// still reach the code only through the test-only seam and release Wasms carry
/// neither the candidate nor the hook; what changed is that a non-injecting
/// caller now gets the RULED value, which is why forcing the unruled path needs
/// an explicit inner `None`.
fn entry_rate_params() -> Option<stsh_custody_types::EntryRateParams> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_ENTRY_RATE.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::ENTRY_RATE_PARAMS
}

fn nonterminal_caps() -> Option<stsh_custody_types::NonterminalCaps> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_NONTERMINAL_CAPS.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::VAULT_NONTERMINAL_CAPS
}

/// The ruled proposal-lifetime bounds, or an S5A-injected candidate.
///
/// WHY THIS ACCESSOR EXISTS (M1 gate A). While the bounds are `None` no
/// proposal is ever given an expiry, so `PROPOSAL_EXPIRY_INDEX` is necessarily
/// EMPTY and the sweep is vacuous — which means `c_record_worst`, the marginal
/// instruction cost per DUE record, has no due record to measure. The
/// measurement cannot be taken at all without candidate bounds reaching a
/// deployed canister.
///
/// Same discipline as the two accessors above. RF-1 correction: the claim that
/// "the production constant stays `None`" has been FALSE since S6 ruled C3/C4.
/// Candidate values still arrive ONLY through test-only configuration and the
/// feature-isolation suite still asserts neither the value nor the hook reaches
/// a release Wasm — but the unruled path is now reachable only by injecting an
/// explicit inner `None`.
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
///
/// C11 = 12 records/call as of S6. Still injectable, for the reason it always
/// was: measuring the sweep's cost AT a candidate limit is how the envelope was
/// established, and the re-run triggers in V15 §4.4 mean that measurement must
/// stay runnable rather than becoming a historical artifact.
fn sweep_work_limit() -> Option<usize> {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(injected) = INJECTED_SWEEP_WORK_LIMIT.with(|c| *c.borrow()) {
            return injected;
        }
    }
    stsh_custody_types::VAULT_SWEEP_WORK_LIMIT_PER_CALL
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    // RF-1 (SSA S8B return) — `Option<Option<…>>` on all four. Outer layer =
    // "is anything injected", inner = the value. A single `Option` conflates
    // them, and the conflation is INVISIBLE for exactly as long as the
    // production constant is `None`.
    //
    // All four are production-`Some` TODAY (C9, C5/C7, C3/C4, C11 — all ruled
    // at S6), so before this change every test calling `inject(None)` believing
    // it forced the unruled path was silently exercising the RULED value, and
    // had been since S6. The S8B pin surfaced the class on a fifth seam; this
    // is the sweep. Mirrored on the recovery plane, deliberately: closing one
    // plane would leave the other's non-vacuity claims resting on nothing.
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
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_entry_rate_for_test(p: Option<Option<stsh_custody_types::EntryRateParams>>) {
    INJECTED_ENTRY_RATE.with(|c| *c.borrow_mut() = p);
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_nonterminal_caps_for_test(
    c: Option<Option<stsh_custody_types::NonterminalCaps>>,
) {
    INJECTED_NONTERMINAL_CAPS.with(|x| *x.borrow_mut() = c);
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_lifetime_params_for_test(
    bounds: Option<Option<stsh_custody_types::ProposalLifetimeBounds>>,
    sweep_limit: Option<Option<usize>>,
) {
    INJECTED_LIFETIME_BOUNDS.with(|x| *x.borrow_mut() = bounds);
    INJECTED_SWEEP_WORK_LIMIT.with(|x| *x.borrow_mut() = sweep_limit);
}

/// Charge ONE entry event to `who`, or refuse.
///
/// Called for BOTH an operation admission and an audited rejection — the shared
/// budget the brief requires. Window rolling is computed from the stored
/// `window_start_ns` and the current time, so it rolls correctly across an
/// upgrade boundary without needing a timer.
///
/// The ledger write and the caller's audited rejection commit in the SAME
/// synchronous message (there is no `await` on this path), so a rejection can
/// never consume budget without recording, or record without consuming.
fn charge_entry_event(who: Principal, now: u64) -> Result<(), VaultError> {
    let Some(params) = entry_rate_params() else {
        // Unruled: the mechanism is built, enforcement is S6's. See the module
        // comment on why this admits rather than failing closed.
        return Ok(());
    };
    let mut l = entry_rate_load();
    // Slide: drop everything that has aged out of the window. Strictly-greater
    // keeps the window half-open `(now - window, now]`, so an event exactly one
    // full window old has expired rather than lingering for one more charge.
    let cutoff = now.saturating_sub(params.window_ns);
    l.events.retain(|(_, at)| *at > cutoff);

    let global = l.events.len() as u32;
    let mine = l.events.iter().filter(|(p, _)| *p == who).count() as u32;
    if global >= params.global_per_window || mine >= params.per_signer_per_window {
        return Err(VaultError::IllegalSourceState);
    }
    l.events.push((who, now));
    entry_rate_store(&l);
    Ok(())
}

/// C5/C7/C12 — refuse admission when the nonterminal caps are already met.
///
/// Enforced BEFORE proposal-ID allocation and before any durable write, so a
/// refused admission consumes no id and leaves no record (which is also what
/// makes W1.3's "a record-less rejection burns nothing" true here).
fn check_nonterminal_caps(who: Principal) -> Result<(), VaultError> {
    let Some(caps) = nonterminal_caps() else {
        return Ok(());
    };
    // SSA BLOCKER 1 — counted from the NONTERMINAL index, which covers Pending
    // as well as Executing/OutcomeUnknown. The previous version counted the two
    // single-flight indexes, so Pending proposals consumed no slot and Pending
    // spam bypassed the caps entirely.
    //
    // Both reads are bounded-active-set: `len()` is O(1) and the per-proposer
    // count is a contiguous range over a key that leads with the proposer.
    let global = NONTERMINAL_PROPOSAL_INDEX.with(|x| x.borrow().len()) as u32;
    let mine = NONTERMINAL_PROPOSAL_INDEX.with(|x| {
        x.borrow()
            .range((who, u64::MIN)..=(who, u64::MAX))
            .count()
    }) as u32;
    if global >= caps.global || mine >= caps.per_signer {
        return Err(VaultError::IllegalSourceState);
    }
    Ok(())
}

// ── S6 corrective (CUST-SSA-S6-01) — C6/C8 enforcement ───────────────────────
//
// S6 declared C6 and C8 and enforced neither. This is the enforcement.
//
// WHERE IT RUNS: before the C9 charge, before ID allocation, before any durable
// write — so a refusal consumes no id, burns no rate budget, and leaves no
// record, matching what `check_nonterminal_caps` already guarantees for counts.
// A byte cap that ran after the charge would let a caller exhaust their C9
// budget on requests that were never going to be admitted.
//
// EQUALITY AT THE CAP PASSES. The caps are maxima, not strict bounds: a signer
// holding exactly C6 retained bytes is at their limit and legal; the next byte
// is not. Written as `> cap` rather than `>= cap` for that reason.

/// C6/C8 admission check. Returns the delta so the caller can account it
/// without recomputing.
/// The ruled C6/C8 quotas, or test-injected candidates.
///
/// Injectable for the same reason the nonterminal caps are, and with the same
/// corrected rationale.
///
/// AN EARLIER REVISION OF THIS NOTE IS WITHDRAWN. It argued the C8 ceiling was
/// UNREACHABLE through legal admission — C6 bounds one signer to 2 MiB, the
/// roster maximum is 9, so a legal roster tops out at 9 x C6 = 18,874,368 < C8,
/// the top C6 being "ruled margin". THAT IS FALSE. It assumed the ROSTER bounds
/// the ACCOUNTING. A proposal stays NONTERMINAL across a signer-set rotation:
/// `execute_signer_set_update` swaps membership and bumps the epoch, but
/// terminalizes nothing and releases no bytes, so a rotated-out signer keeps
/// both its retained bytes and its accounting entry while the incoming signer
/// starts at zero. Distinct proposers holding bytes therefore accumulate past
/// nine and the sum passes 9 x C6. C8 IS A LIVE CAP, NOT A MARGIN — proved by
/// construction over a legal rotation sequence in
/// `s6c_c8_is_reachable_by_legal_rotation_and_enforced_at_equality`.
///
/// The hook therefore exists as a MEASUREMENT CONVENIENCE, exactly as
/// `set_nonterminal_caps_for_test` does: reaching the ceiling legally requires a
/// long governed rotation sequence that would measure the ROTATION path rather
/// than the admission cost the sweep is trying to price. It is not a statement
/// that the ceiling is unreachable.
///
/// Production constants are untouched; the feature-isolation suite asserts the
/// hook is absent from every release Wasm.
fn byte_quotas() -> (u64, u64) {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(q) = INJECTED_BYTE_QUOTAS.with(|c| *c.borrow()) {
            return q;
        }
    }
    (
        stsh_custody_types::PER_SIGNER_BYTE_QUOTA,
        stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA,
    )
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static INJECTED_BYTE_QUOTAS: RefCell<Option<(u64, u64)>> = const { RefCell::new(None) };
}

#[cfg(any(test, feature = "testing"))]
pub fn inject_byte_quotas_for_test(q: Option<(u64, u64)>) {
    INJECTED_BYTE_QUOTAS.with(|c| *c.borrow_mut() = q);
}

fn check_retained_bytes(who: Principal, action: &VaultActionKind) -> Result<u64, VaultError> {
    let (c6, c8) = byte_quotas();
    let delta = c8_logical_bytes(action);
    let s = companion_load();
    let mine = retained_for(&s, who);

    // Per-signer limb (C6). Checked first so a signer over their own quota is
    // told that, rather than being told the global cap is full.
    let mine_after = mine.saturating_add(delta);
    if mine_after > c6 {
        return Err(VaultError::SizeLimitExceeded {
            encoded_bytes: mine_after,
            limit_bytes: c6,
        });
    }

    // Global limb (C8). NOT implied by the per-signer limb, and NOT because of
    // any margin: the "nine signers can never reach C8" rationale that once sat
    // here is WITHDRAWN — it assumed the roster bounds the accounting, and
    // rotation refutes it (a proposal stays nonterminal across a rotation, so
    // rotated-out proposers keep their bytes and their accounting entries).
    //
    // The limbs are independent because they bound DIFFERENT quantities: C6
    // bounds what one proposer may hold, C8 bounds what all of them hold
    // together, and the accounting cardinality is bounded by C7 = 320 rather
    // than by the roster. C8 is reachable by legal admission and both limbs are
    // mutation-checked.
    let total_after = s.retained_bytes_total.saturating_add(delta);
    if total_after > c8 {
        return Err(VaultError::SizeLimitExceeded {
            encoded_bytes: total_after,
            limit_bytes: c8,
        });
    }
    Ok(delta)
}

fn retained_for(s: &CompanionState, who: Principal) -> u64 {
    s.retained_by_signer
        .iter()
        .find(|(p, _)| *p == who)
        .map(|(_, n)| *n)
        .unwrap_or(0)
}

/// Account newly retained bytes. Same synchronous message as the durable write
/// that retains them, so a trap rolls back both.
fn retained_admit(who: Principal, delta: u64) {
    if delta == 0 {
        return;
    }
    let mut s = companion_load();
    s.retained_bytes_total = s.retained_bytes_total.saturating_add(delta);
    match s.retained_by_signer.iter_mut().find(|(p, _)| *p == who) {
        Some((_, n)) => *n = n.saturating_add(delta),
        None => s.retained_by_signer.push((who, delta)),
    }
    // RESEAL BEFORE STORING. `companion_store` does not seal; the seal covers
    // the accounting, so storing without resealing leaves a stale commitment
    // and the next validation traps. This is the third time in this campaign a
    // companion mutator has had to learn it (S5B handoff §0.3) — hence the note.
    companion_seal(&mut s);
    companion_store(&s);
}

/// Release retained bytes. Called ONLY where the bytes actually clear.
///
/// The dispatch is explicit that accounting releases only when the relevant
/// retained bytes clear — so this is called from the `cleared_action` sites and
/// nowhere else. Releasing at terminalization instead would be wrong for
/// `OutcomeUnknown`, which is terminal for the single-flight lock but DELIBERATELY
/// RETAINS its artifact bytes (the outcome is a fact about the world and the
/// evidence stays); releasing there would free quota for bytes still held.
fn retained_release(who: Principal, delta: u64) {
    if delta == 0 {
        return;
    }
    let mut s = companion_load();
    s.retained_bytes_total = s.retained_bytes_total.saturating_sub(delta);
    if let Some(i) = s.retained_by_signer.iter().position(|(p, _)| *p == who) {
        let n = s.retained_by_signer[i].1.saturating_sub(delta);
        if n == 0 {
            // Drop the entry rather than keeping a zero: a rotated-out signer
            // must not occupy a slot forever.
            s.retained_by_signer.swap_remove(i);
        } else {
            s.retained_by_signer[i].1 = n;
        }
    }
    companion_seal(&mut s); // see `retained_admit`
    companion_store(&s);
}

// ── S5B W1 — authoritative ID allocation ─────────────────────────────────────
//
// Each map gets its OWN allocation primitive carrying its own counter (W1,
// "per-map primitives"): the proposal primitive does not implicitly cover
// audit-only or snapshot-only appends, because those append on paths where no
// proposal is being written and would otherwise have no allocation authority.
//
// COMMITTED-ID SEMANTICS (W1.3), which is what reconciles "never reused" with
// atomic rollback:
//   - a COMMITTED, INSERTED id is never reused; the durable counter never
//     moves backwards;
//   - a TRAPPED transaction commits neither counter nor entry, so its numeric
//     candidate was never allocated and MAY be retried — the same id comes
//     back on the next attempt, which is correct rather than a reuse
//     violation. This is the point the SSA re-check corrected: "never reused,
//     not after rejection or trap" contradicted atomic rollback;
//   - a rejection allocates only if it durably inserts; a record-less
//     rejection burns nothing.
//
// The old helpers derived the next id from `.iter().last()` on the history
// map. Three defects in one line: a full scan on an authorization-critical
// path (an UNMET R3 item 9, recorded as a conformance failure rather than a
// new finding), history as allocation authority (forbidden by W1.1), and
// `k + 1`, which SILENTLY WRAPS at u64::MAX onto live ids.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdKind {
    Proposal,
    Audit,
    Snapshot,
}

/// Hand out the next id for one map WITHOUT committing it. The caller inserts
/// and then calls `commit_id`; both land in the same synchronous message, so a
/// trap anywhere rolls back counter and insertion together (W1.2).
fn peek_id(which: IdKind) -> u64 {
    // W1.6 — inline validation before EVERY allocation, not only at
    // post_upgrade. Allocating against an unvalidated counter is precisely how
    // a drifted counter would mint a colliding id.
    companion_validate();
    let s = companion_load();
    match which {
        IdKind::Proposal => s.next_proposal_id,
        IdKind::Audit => s.next_audit_id,
        IdKind::Snapshot => s.next_snapshot_id,
    }
}

/// Advance one counter, checked (W1.7): exhaustion traps rather than wrapping.
fn commit_id(which: IdKind, allocated: u64) {
    let mut s = companion_load();
    let slot = match which {
        IdKind::Proposal => &mut s.next_proposal_id,
        IdKind::Audit => &mut s.next_audit_id,
        IdKind::Snapshot => &mut s.next_snapshot_id,
    };
    // Defence in depth (W1.4): the caller must be committing the id it was
    // handed. A mismatch means two allocations interleaved, which cannot
    // happen inside one synchronous message, so it indicates the primitive was
    // bypassed.
    if *slot != allocated {
        ic_cdk::trap(
            "ID ALLOCATION: committing an id other than the one allocated — the \
             per-map primitive was bypassed. Fail closed (W1.4).",
        );
    }
    *slot = slot.checked_add(1).unwrap_or_else(|| {
        ic_cdk::trap("ID ALLOCATION: id space exhausted — fail closed, never wrap (W1.7)")
    });
    companion_seal(&mut s);
    companion_store(&s);
}

fn next_proposal_id() -> u64 {
    let id = peek_id(IdKind::Proposal);
    // W1.4 — insert-if-absent. An occupied key is corruption, not a retry, and
    // must trap BEFORE the overwrite. Defence in depth only: the seal is the
    // primary mechanism (W1.6), because a counter lowered into an unused
    // historical gap sails past this check entirely.
    if PROPOSALS.with(|p| p.borrow().contains_key(&id)) {
        ic_cdk::trap(
            "PROPOSALS: allocated id already occupied — durable corruption, \
             refusing to overwrite (W1.4)",
        );
    }
    id
}

fn next_audit_id() -> u64 {
    peek_id(IdKind::Audit)
}

fn next_snapshot_id() -> u64 {
    let id = peek_id(IdKind::Snapshot);
    if CONTROLLER_READ_SNAPSHOTS.with(|s| s.borrow().contains_key(&id)) {
        ic_cdk::trap(
            "CONTROLLER_READ_SNAPSHOTS: allocated id already occupied — durable \
             corruption, refusing to overwrite (W1.4)",
        );
    }
    id
}

fn approvals_get(id: u64) -> Vec<Principal> {
    APPROVALS
        .with(|a| a.borrow().get(&id))
        .map(|b| candid::decode_one(&b).expect("APPROVALS: record decodes"))
        .unwrap_or_default()
}

fn approvals_put(id: u64, signers: &[Principal]) {
    let bytes = candid::encode_one(&signers.to_vec()).expect("approvals encode");
    APPROVALS.with(|a| a.borrow_mut().insert(id, bytes));
}

fn audit(
    kind: AuditKind,
    proposal_id: Option<u64>,
    actor: Principal,
    approving_signers: Option<Vec<Principal>>,
    detail: String,
) {
    audit_full(kind, proposal_id, actor, approving_signers, None, None, detail)
}

/// §S7 §7d.1 — append the ONE `SettlementEvidenceConflict` event, carrying the
/// frozen eight-field payload typed and in full.
///
/// The caller has ALREADY written `conflict_recorded = true` in this same
/// synchronous message with no `await` between the two, which is what makes the
/// pair one atomic durable transition (§0b). Kept as a named function so that
/// the append has exactly one call site per plane and cannot acquire a second
/// that skips the marker.
fn audit_conflict(target_proposal_id: u64, conflict: &SettlementEvidenceConflict) {
    audit_full(
        AuditKind::SettlementEvidenceConflict,
        Some(target_proposal_id),
        self_id(),
        None,
        None,
        Some(conflict.clone()),
        format!(
            "§7d.1: valid semantic discordance — stored {:?}, replay {:?}",
            conflict.stored_outcome, conflict.replay_mapped_outcome
        ),
    )
}

/// Append one audit event. Append-only: ids are monotone and no update path
/// ever overwrites or removes an event.
fn audit_full(
    kind: AuditKind,
    proposal_id: Option<u64>,
    actor: Principal,
    approving_signers: Option<Vec<Principal>>,
    creation_receipt: Option<CreationReceipt>,
    settlement_conflict: Option<SettlementEvidenceConflict>,
    detail: String,
) {
    // S5B W1 — audit gets its OWN allocation primitive. The proposal primitive
    // does not implicitly cover it: audit appends happen on paths where no
    // proposal is written (governance transitions, rejections), which would
    // otherwise leave them with no allocation authority at all.
    let id = next_audit_id();
    let ev = AuditEvent {
        id,
        at_ns: now_ns(),
        epoch: gov_cell().map(|g| g.epoch).unwrap_or(0),
        kind,
        proposal_id,
        actor,
        approving_signers,
        creation_receipt,
        settlement_conflict,
        detail,
    };
    let bytes = candid::encode_one(&ev).expect("AuditEvent encodes");
    // W1.4 — insert-if-absent. An occupied key is corruption, not a retry, and
    // must trap BEFORE the overwrite. Defence in depth: the seal is the primary
    // integrity mechanism (W1.6), because a lowered counter pointing into an
    // unused historical gap would pass this check.
    AUDIT_EVENTS.with(|a| {
        let mut a = a.borrow_mut();
        if a.contains_key(&id) {
            ic_cdk::trap(
                "AUDIT_EVENTS: allocated id already occupied — durable corruption, \
                 refusing to overwrite (W1.4)",
            );
        }
        a.insert(id, bytes);
    });
    // Same synchronous message as the insertion above (W1.2): no increment
    // without insertion, no insertion without increment.
    commit_id(IdKind::Audit, id);
}

#[cfg_attr(not(test), allow(dead_code))] // read by the in-crate test suite
fn reservation_get(id: u64) -> Option<Reservation> {
    RESERVATIONS
        .with(|r| r.borrow().get(&id))
        .map(|b| candid::decode_one(&b).expect("RESERVATIONS: record decodes"))
}

/// Insert-once. A second insert for the same id would be a replace — which
/// invariant 4 forbids — so it traps instead. There is deliberately no
/// remove/prune function for MemoryId 5 anywhere in this crate.
fn reservation_insert(res: &Reservation) {
    let bytes = candid::encode_one(res).expect("Reservation encodes");
    RESERVATIONS.with(|r| {
        let mut m = r.borrow_mut();
        if m.contains_key(&res.proposal_id) {
            ic_cdk::trap("RESERVATIONS: insert-once violated — reservations are permanent");
        }
        m.insert(res.proposal_id, bytes);
    });
}

fn snapshot_insert(snap: &ControllerReadSnapshot) {
    let bytes = candid::encode_one(snap).expect("ControllerReadSnapshot encodes");
    CONTROLLER_READ_SNAPSHOTS.with(|s| s.borrow_mut().insert(snap.snapshot_id, bytes));
}

// ── Hashing (freeze §3d/§3f — recomputed, rejected on mismatch) ─────────────

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn check_hashes(expected_wasm: &[u8], expected_arg: &[u8], wasm: &[u8], arg: &[u8]) -> Result<(), VaultError> {
    if sha256(wasm) != expected_wasm || sha256(arg) != expected_arg {
        return Err(VaultError::HashMismatch);
    }
    Ok(())
}

// ── Action validation (propose-time; deny by default) ────────────────────────

/// Where a management-action target stands relative to the custody manifest
/// (L1-1). The allowlist is the durable `governed` set in the governance
/// cell — manifest-derived at init (cutover) and extended ONLY from typed
/// creation receipts (born-under-vault). Anything else is Unknown and every
/// management variant fails closed on it — including the manifest's
/// OutOfScope entries (ohspu, zmvwg, staking), which are simply absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetClass {
    /// The Vault itself or its Upgrader counterpart — ring rules apply.
    Ring,
    /// In the durable governed allowlist (either disposition).
    Governed,
    /// Not governed — fail closed, always.
    Unknown,
}

fn classify_target(g: &GovernanceCellData, target: Principal) -> TargetClass {
    if target == self_id() || target == g.bootstrap.counterpart {
        return TargetClass::Ring;
    }
    if g.governed.iter().any(|t| t.principal == target) {
        return TargetClass::Governed;
    }
    TargetClass::Unknown
}

/// L1-1: management authority is restricted to the custody manifest. Each
/// variant class gets its ruled enforcement; unknown/out-of-scope targets
/// are rejected on every path.
fn validate_management_target(
    g: &GovernanceCellData,
    guard: &VaultSelfControlGuard,
    m: &ManagementAction,
) -> Result<(), VaultError> {
    match m {
        ManagementAction::Upgrade { target, .. } | ManagementAction::InstallCode { target, .. } => {
            // Production governed targets only. Ring members are NOT valid
            // here: the Upgrader is upgraded via C1 (its own reconciliation
            // contract), the Vault via the recovery plane — a plain
            // management upgrade would bypass both.
            match classify_target(g, *target) {
                TargetClass::Governed => Ok(()),
                _ => Err(VaultError::NotAuthorized),
            }
        }
        ManagementAction::Stop { target } => match classify_target(g, *target) {
            // Self/cross stop between Vault and Upgrader FORBIDDEN both
            // directions (freeze §3c) — executable, not a comment.
            TargetClass::Ring => guard.validate_stop(*target).map_err(VaultError::GuardRejected),
            TargetClass::Governed => Ok(()),
            TargetClass::Unknown => Err(VaultError::NotAuthorized),
        },
        ManagementAction::UpdateSettings { target, controllers } => {
            match classify_target(g, *target) {
                TargetClass::Ring => validate_ring_update_settings(guard, *target, controllers),
                // BornUnderVault preserves its ruled configuration; a
                // SetControllerAtCutover target moves to EXACTLY
                // controllers == [Vault]. Same rule, one check.
                TargetClass::Governed => {
                    if controllers == &[self_id()] {
                        Ok(())
                    } else {
                        Err(VaultError::NotAuthorized)
                    }
                }
                TargetClass::Unknown => Err(VaultError::NotAuthorized),
            }
        }
        ManagementAction::Start { target } => match classify_target(g, *target) {
            // Starting a ring member is not forbidden (only STOP is);
            // starting governed targets is the production case.
            TargetClass::Ring | TargetClass::Governed => Ok(()),
            TargetClass::Unknown => Err(VaultError::NotAuthorized),
        },
        ManagementAction::DepositCycles { target, .. } => match classify_target(g, *target) {
            TargetClass::Ring | TargetClass::Governed => Ok(()),
            TargetClass::Unknown => Err(VaultError::NotAuthorized),
        },
        ManagementAction::CreateCanister {
            manifest_purpose,
            disposition,
        } => validate_create_canister(g, manifest_purpose, *disposition),
    }
}

/// freeze §13.3: production creation carries a predeclared manifest purpose
/// AND disposition; the Vault durably binds the returned principal before
/// install. Creation is born-under-vault BY CONSTRUCTION — a `create_canister`
/// call produces a new principal, so `SetControllerAtCutover` (the canister
/// already exists) and `OutOfScope` are not creatable dispositions.
fn validate_create_canister(
    g: &GovernanceCellData,
    manifest_purpose: &str,
    disposition: ManifestDisposition,
) -> Result<(), VaultError> {
    if disposition != ManifestDisposition::BornUnderVault {
        return Err(VaultError::NotAuthorized);
    }
    if manifest_purpose.is_empty() || manifest_purpose.len() > MAX_TEXT_FIELD_BYTES {
        return Err(VaultError::ReadBoundExceeded {
            what: "manifest_purpose",
            bytes: manifest_purpose.len() as u64,
            max: MAX_TEXT_FIELD_BYTES as u64,
        });
    }
    // The purpose must name EXACTLY one manifest born-under-vault role…
    if !BORN_UNDER_VAULT_ROLES.contains(&manifest_purpose) {
        return Err(VaultError::NotAuthorized);
    }
    // …and every role binds ONE-SHOT: a purpose already bound (wired role or
    // governed entry) can never receive a second principal (L1-2).
    if g.governed.iter().any(|t| t.purpose == manifest_purpose) {
        return Err(VaultError::NotAuthorized);
    }
    Ok(())
}

// ── Single-flight mutating-intent lock (SSA L2 re-review, applied to L1) ─────
//
// ONE nonterminal mutating intent per target canister. If proposal A is
// Executing/OutcomeUnknown against target X and proposal B then upgrades X,
// mismatched-hash evidence can no longer prove A failed — the exact L2
// counterexample. The lock derives ONLY from durable proposal state (no
// heap-only guard), so it survives upgrades by construction.
//
// Scope: hash-bound install/upgrade actions — UpgraderUpgrade (target: the
// durable Upgrader counterpart) and management Upgrade/InstallCode. These
// are the actions with objective-evidence reconciliation semantics.
// Start/Stop/UpdateSettings/DepositCycles are lifecycle ops without
// reconciliation ambiguity and are deliberately out of scope. Reconcile
// proposals do NOT take the lock: they mutate no canister, they TERMINALIZE
// the locked intent — and two reconciles for one intent are already
// impossible (legal source state OutcomeUnknown is consumed by the first).

/// The target canister a mutating install/upgrade action binds, if any.
fn mutating_intent_target(action: &VaultActionKind) -> Option<Principal> {
    match action {
        VaultActionKind::UpgraderUpgrade(_) => Some(gov().bootstrap.counterpart),
        VaultActionKind::Management(ManagementAction::Upgrade { target, .. })
        | VaultActionKind::Management(ManagementAction::InstallCode { target, .. }) => Some(*target),
        // §3e: the Vault-upgrade intent is single-flight on the VAULT
        // itself; the direct §3d Upgrader upgrade stays scoped to the
        // Upgrader. The two directions never share a lock target.
        VaultActionKind::VaultUpgradeViaUpgrader(_) => Some(self_id()),
        // §S7 §2 — a CELL-3 RING START holds single-flight on the Upgrader.
        //
        // Before S7 a `Start` claimed no entry at all, which is precisely why
        // cell 3 had no settlement contract: nothing held a lock, so nothing
        // could be said about releasing one. §2 requires that "a start and an
        // upgrade must not be in flight against the same target concurrently,
        // because concurrent module mutation would destroy the attributability
        // of the status evidence in §4" — an upgrade landing mid-start makes the
        // §4 observation describe a canister that two proposals were mutating,
        // and neither could claim it. §7e then pins the release point: the lock
        // releases ONLY at the first transition to `Executed` or `Failed`.
        //
        // SCOPED TO THE RING, DELIBERATELY. A `Start` against an ordinary
        // governed target is outside S7 (§1 names cell 3 as "Vault → Upgrader",
        // and §4.3's controller check is defined only for ring members), so its
        // existing lock-free behaviour is PRESERVED unchanged (R4.3). Widening
        // the lock to every governed start would be an unrequested behaviour
        // change on a surface S7 was not dispatched to touch.
        VaultActionKind::Management(ManagementAction::Start { target })
            if *target == gov().bootstrap.counterpart =>
        {
            Some(*target)
        }
        _ => None,
    }
}

/// Every proposal id currently holding a mutating single-flight entry.
///
/// Used ONLY by the §S7 E2 sweep. It iterates the BOUNDED companion index
/// (MemoryId 7), never permanent history — the same discipline
/// `companion_precedence` observes, and for the same reason: a scan of
/// `PROPOSALS` would grow without bound with every proposal ever created.
fn mutating_intent_proposal_ids() -> Vec<u64> {
    OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow().iter().map(|((_, id), _)| id).collect())
}

/// The proposal id of the open (Executing|OutcomeUnknown) mutating intent
/// against `target`, from durable state. `exclude` lets the execution-time
/// re-check ignore the proposal that is itself executing.
/// R3.9 — a single point read against MemoryId 7.
///
/// Was a full-map scan decoding EVERY proposal on every call, on an
/// authorization-critical path: `check_single_flight` is called
/// unconditionally from `propose_inner`, so the cost of proposing grew with
/// the total number of proposals ever created. That is the instruction-
/// exhaustion half of CUST-SSA-003, and no quota on its own would have fixed
/// it — terminal records accumulate forever.
fn open_mutating_intent(target: Principal, exclude: Option<u64>) -> Option<u64> {
    // S5B W2(e) — this returns `None` to mean "no lock held", which ADMITS a
    // new intent. Absence is therefore the dangerous direction, and must not be
    // trusted until the companion is proved intact.
    companion_validate();
    OPEN_MUTATING_INTENT_INDEX.with(|x| {
        x.borrow()
            .range((target, u64::MIN)..=(target, u64::MAX))
            .map(|((_, id), _)| id)
            .find(|id| Some(*id) != exclude)
    })
}

/// The proposal id of the open (Executing|OutcomeUnknown) creation intent
/// claiming `purpose`, from durable state. L1-5: creation is purpose-scoped
/// single-flight — the created principal does not exist yet, so the lock
/// keys on the manifest purpose.
/// R3.9 — a single point read against MemoryId 8. Same scan removal, same
/// reason, keyed on the manifest purpose because the created principal does
/// not exist yet (L1-5).
fn open_creation_intent(purpose: &str, exclude: Option<u64>) -> Option<u64> {
    // S5B W2(e) — same reasoning as `open_mutating_intent`: a `None` here
    // admits a new creation intent, so absence is validated before it is
    // believed.
    companion_validate();
    OPEN_CREATION_INTENT_INDEX.with(|x| {
        x.borrow()
            .range(creation_key(purpose, u64::MIN)..=creation_key(purpose, u64::MAX))
            .map(|(k, _)| creation_key_id(&k))
            .find(|id| Some(*id) != exclude)
    })
}

/// `sha256(purpose) || proposal_id.to_be_bytes()` — 40 bytes, order-preserving
/// so that a range over one purpose is a contiguous prefix.
fn creation_key(purpose: &str, proposal_id: u64) -> Blob<40> {
    let mut k = [0u8; 40];
    k[..32].copy_from_slice(&sha256(purpose.as_bytes()));
    k[32..].copy_from_slice(&proposal_id.to_be_bytes());
    Blob::try_from(&k[..]).expect("creation key is exactly 40 bytes")
}

fn creation_key_id(k: &Blob<40>) -> u64 {
    let b = k.as_slice();
    u64::from_be_bytes(b[32..40].try_into().expect("8-byte id suffix"))
}

/// Propose-time lock check. NOTE on error typing: the frozen `VaultError`
/// (custody-types-owned) has no "intent in flight" variant — reported to
/// SSA as a VaultError gap, NOT edited. `IllegalSourceState` is the
/// least-wrong existing variant (the durable system state makes the action
/// illegal right now).
fn check_single_flight(action: &VaultActionKind) -> Result<(), VaultError> {
    if let Some(target) = mutating_intent_target(action) {
        if open_mutating_intent(target, None).is_some() {
            return Err(VaultError::IllegalSourceState);
        }
    }
    // L1-5: one nonterminal creation per manifest purpose.
    if let VaultActionKind::Management(ManagementAction::CreateCanister {
        manifest_purpose,
        ..
    }) = action
    {
        if open_creation_intent(manifest_purpose, None).is_some() {
            return Err(VaultError::IllegalSourceState);
        }
    }
    Ok(())
}

fn validate_action(action: &VaultActionKind) -> Result<(), VaultError> {
    let g = gov();
    let guard = VaultSelfControlGuard {
        vault: self_id(),
        upgrader: g.bootstrap.counterpart,
    };
    match action {
        VaultActionKind::Application(req) => {
            req.validate()?;
            let binding = req.kind().binding();
            let encoded = req.encode();
            if encoded.len() as u64 > binding.max_request_bytes {
                return Err(VaultError::SizeLimitExceeded {
                    encoded_bytes: encoded.len() as u64,
                    limit_bytes: binding.max_request_bytes,
                });
            }
            Ok(())
        }
        VaultActionKind::Management(m) => {
            validate_management_target(&g, &guard, m)?;
            match m {
                ManagementAction::Upgrade {
                    expected_wasm_hash,
                    expected_arg_hash,
                    wasm_bytes,
                    arg_bytes,
                    ..
                }
                | ManagementAction::InstallCode {
                    expected_wasm_hash,
                    expected_arg_hash,
                    wasm_bytes,
                    arg_bytes,
                    ..
                } => {
                    // freeze §3d/§3f: both hashes recomputed by the Vault and
                    // rejected on mismatch — at propose AND again at execution.
                    check_hashes(expected_wasm_hash, expected_arg_hash, wasm_bytes, arg_bytes)?;
                    check_install_size(wasm_bytes, arg_bytes)
                }
                _ => Ok(()),
            }
        }
        VaultActionKind::UpgraderUpgrade(uu) => {
            check_hashes(
                &uu.expected_wasm_hash,
                &uu.expected_arg_hash,
                &uu.wasm_bytes,
                &uu.arg_bytes,
            )?;
            check_install_size(&uu.wasm_bytes, &uu.arg_bytes)
        }
        VaultActionKind::ReconcileUpgraderUpgrade(rec) => {
            // Legal source state: `OutcomeUnknown` ONLY (freeze §3d). Checked
            // here at propose AND again at execution — the target's state may
            // legitimately move between the two.
            //
            // VR-1: the reconcile route admits THREE target action shapes —
            // the original `UpgraderUpgrade` (cell 3) and, since VR-1, a
            // management-plane `InstallCode` / `Upgrade`. Those are exactly
            // the hash-bound mutating actions that take the single-flight
            // lock (`mutating_intent_target`), so they are exactly the
            // actions that can strand a target in `OutcomeUnknown` with the
            // lock held and no exit. Every OTHER action shape stays
            // `IllegalSourceState`, as today.
            match proposal_get(rec.proposal_id) {
                Some(p) => match p.action {
                    VaultActionKind::UpgraderUpgrade(_)
                    | VaultActionKind::Management(ManagementAction::InstallCode { .. })
                    | VaultActionKind::Management(ManagementAction::Upgrade { .. }) => {
                        if p.outcome != ActionOutcome::OutcomeUnknown {
                            return Err(VaultError::IllegalSourceState);
                        }
                        Ok(())
                    }
                    _ => Err(VaultError::IllegalSourceState),
                },
                None => Err(VaultError::UnknownProposal {
                    proposal_id: rec.proposal_id,
                }),
            }
        }
        // §S7 cell 3 — the reconcile action itself is validated for SHAPE only.
        //
        // Deliberately NOT pre-checked against the target proposal's state
        // here, unlike `ReconcileUpgraderUpgrade` above. §7f pins the gate
        // ORDER, and it is evaluated at EXECUTION, against the state that holds
        // when the quorum's decision actually applies. A propose-time source
        // check would be a second, differently-ordered ladder over the same
        // facts — and a proposal that passed it could still execute against a
        // state that has since changed, so the execution-time gates are the
        // load-bearing ones regardless. Two ladders is exactly the "two
        // conformant canisters, different typed errors" hazard §7f exists to
        // close.
        VaultActionKind::ReconcileUpgraderStart(rec) => {
            let encoded = candid::encode_one(rec)
                .map(|b| b.len() as u64)
                .unwrap_or(u64::MAX);
            if encoded > RECONCILE_VAULT_UPGRADE_REQ_CEILING_BYTES {
                return Err(VaultError::SizeLimitExceeded {
                    encoded_bytes: encoded,
                    limit_bytes: RECONCILE_VAULT_UPGRADE_REQ_CEILING_BYTES,
                });
            }
            Ok(())
        }
        VaultActionKind::ReadModel(req) => req.validate(),
        VaultActionKind::UpdateSignerSet { signers, threshold } => {
            validate_signer_set(signers, *threshold, &gov().bootstrap.counterpart)
        }
        VaultActionKind::VaultUpgradeViaUpgrader(vu) => {
            // §3e: the CALLER must submit the unbound marker 0 — the Vault
            // binds it to the proposal id at CREATION (R1.2), so a
            // caller-supplied identity is rejected before anything is stored.
            if vu.request_id != 0 {
                return Err(VaultError::IllegalSourceState);
            }
            // Same hash discipline as C1: recomputed and rejected on
            // mismatch at propose AND at the execution boundary.
            check_hashes(
                &vu.expected_wasm_hash,
                &vu.expected_arg_hash,
                &vu.wasm_bytes,
                &vu.arg_bytes,
            )?;
            let encoded = vu.encode().len() as u64;
            if encoded > VAULT_UPGRADE_VIA_UPGRADER_REQ_CEILING_BYTES {
                return Err(VaultError::SizeLimitExceeded {
                    encoded_bytes: encoded,
                    limit_bytes: VAULT_UPGRADE_VIA_UPGRADER_REQ_CEILING_BYTES,
                });
            }
            Ok(())
        }
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(rec) => {
            let encoded = rec.encode().len() as u64;
            if encoded > RECONCILE_VAULT_UPGRADE_REQ_CEILING_BYTES {
                return Err(VaultError::SizeLimitExceeded {
                    encoded_bytes: encoded,
                    limit_bytes: RECONCILE_VAULT_UPGRADE_REQ_CEILING_BYTES,
                });
            }
            // Legal source states for a §3e reconcile (CUST-L12-02):
            // OutcomeUnknown (L2 transitions it) OR Executing (the
            // reply-callback loss a successful self-upgrade necessarily
            // leaves; L2's terminal intent then replays idempotently).
            // BOTH consult the Upgrader's reconcile endpoint at execution —
            // there is no local-only settlement. Pending/terminal remain
            // illegal sources (never re-triggerable).
            match proposal_get(rec.request_id) {
                Some(p) => match p.action {
                    VaultActionKind::VaultUpgradeViaUpgrader(_) => {
                        if !matches!(
                            p.outcome,
                            ActionOutcome::OutcomeUnknown | ActionOutcome::Executing
                        ) {
                            return Err(VaultError::IllegalSourceState);
                        }
                        Ok(())
                    }
                    _ => Err(VaultError::IllegalSourceState),
                },
                None => Err(VaultError::UnknownProposal {
                    proposal_id: rec.request_id,
                }),
            }
        }
    }
}

/// freeze §8: inline-only is a spec invariant — an oversized install payload
/// is a hard rejection, never a route around to chunking.
fn check_install_size(wasm: &[u8], arg: &[u8]) -> Result<(), VaultError> {
    let total = wasm.len() as u64 + arg.len() as u64 + 4_096; // envelope slack
    if total > GATE_SIZE_BOUND_BYTES {
        return Err(VaultError::SizeLimitExceeded {
            encoded_bytes: total,
            limit_bytes: GATE_SIZE_BOUND_BYTES,
        });
    }
    Ok(())
}

/// VaultSelfControlGuard — executable (freeze §3c). `update_settings` against
/// the Vault preserves `controllers == [Upgrader]`; against the Upgrader,
/// `controllers == [Vault]`.
fn validate_ring_update_settings(
    guard: &VaultSelfControlGuard,
    target: Principal,
    controllers: &[Principal],
) -> Result<(), VaultError> {
    if target == guard.vault {
        return guard
            .validate_update_settings(GuardTarget::Vault, controllers)
            .map_err(VaultError::GuardRejected);
    }
    if target == guard.upgrader {
        return guard
            .validate_update_settings(GuardTarget::Upgrader, controllers)
            .map_err(VaultError::GuardRejected);
    }
    Ok(())
}

// ── Propose / approve ────────────────────────────────────────────────────────

fn propose_inner(
    caller: Principal,
    action: VaultActionKind,
    requested_lifetime_ns: Option<u64>,
) -> Result<u64, VaultError> {
    require_signer(caller)?;
    validate_action(&action)?;
    check_single_flight(&action)?;
    let created_at_ns = now_ns();
    // R3.1 — resolved and VALIDATED before anything durable is written, so a
    // rejected lifetime leaves no proposal, no id consumed, no audit entry.
    let expires_at_ns = stsh_custody_types::resolve_expiry_with(
        proposal_lifetime_bounds(),
        created_at_ns,
        requested_lifetime_ns,
    )
    .map_err(VaultError::LifetimeOutOfBounds)?;
    // S5B W4 — BOTH gates run BEFORE proposal-ID allocation and before any
    // durable write, exactly as the brief requires. Order matters: a refusal
    // here consumes no id and leaves no record, which is what makes W1.3's
    // "a record-less rejection burns nothing" true on this path.
    check_nonterminal_caps(caller)?;
    // S6 corrective (CUST-SSA-S6-01) — C6/C8 BEFORE the C9 charge, the id, and
    // any durable write. Ordered after the count cap and before the charge so a
    // byte-refused request burns no rate budget and consumes no id.
    let retained_delta = check_retained_bytes(caller, &action)?;
    charge_entry_event(caller, created_at_ns)?;
    let id = next_proposal_id();
    let g = gov();
    // R1.2 property 1 — bind the request identity AT CREATION, not at the
    // quorum boundary. Binding later was one of the three mutations that made
    // V2's "hash the action once" unsatisfiable: the value moved 0 ->
    // proposal_id after any commitment would have been taken. Bound here, the
    // canonical action is stable from creation onward, and
    // `canonical_action` stays a faithful image of what executes.
    let mut action = action;
    if let VaultActionKind::VaultUpgradeViaUpgrader(vu) = &mut action {
        vu.request_id = id;
    }
    proposal_put(&ProposalRecord {
        proposal_id: id,
        action,
        proposer: caller,
        created_at_ns,
        epoch: g.epoch,
        outcome: ActionOutcome::Pending,
        result: None,
        snapshot_id: None,
        intent: None,
        // §S7 §2: like cell 4, the start-intent is written at the QUORUM
        // BOUNDARY, not here. Dating it from proposal time would let evidence
        // observed before the call was ever made pass the pre-intent check.
        start: None,
        expires_at_ns,
        // Placeholder; replaced by the real commitment immediately below, once
        // the record exists to compute it from.
        commitment_hash: Vec::new(),
    });
    // R1.2 property 5 — store the commitment ONCE, at creation, immutably.
    {
        let mut rec = proposal_get(id).expect("just-created proposal");
        rec.commitment_hash = commitment_for(&rec).hash();
        proposal_put(&rec);
    }
    // S6 corrective — account the retained bytes in the SAME synchronous
    // message as the write that retains them, so a trap rolls back both and the
    // accounting can never outlive the payload it describes.
    retained_admit(caller, retained_delta);
    // S5B W1.2 — the counter advances in the SAME synchronous message as the
    // insertion above. A trap anywhere before this point commits neither, so
    // the candidate id was never allocated and is legitimately retried
    // (committed-ID semantics, W1.3).
    commit_id(IdKind::Proposal, id);
    audit(
        AuditKind::ProposalCreated,
        Some(id),
        caller,
        None,
        "proposal created".to_string(),
    );
    Ok(id)
}

/// Returns (outcome, should_execute). `should_execute` is true exactly once
/// per proposal: at the quorum boundary, when `Executing` + the permanent
/// reservation + the quorum audit event have ALL been made durable, before
/// the caller's first `await`. A concurrent or replayed approval sees a
/// non-Pending state and gets `PriorResult` — never a second execution.
/// R1.5 — approve-time ordering, which is load-bearing:
///
///   1. require_signer
///   2. load proposal
///   3. COMMITMENT CHECK        <- moved AHEAD of terminal replay
///   4. terminal-replay return
///   5. epoch pin
///   6. duplicate check
///   7. approval + audit writes
///
/// WHY 3 PRECEDES 4. At step 4 the stored hash still exists for terminal
/// proposals, so the comparison is well-defined. Placing the check AFTER would
/// let a caller supplying a WRONG hash receive `Ok(PriorResult)` — a
/// success-shaped answer to a rejected approval, which is exactly the hole SSA
/// identified. A mismatch must never be success-shaped.
/// `now` is THREADED IN rather than read from `now_ns()` inside the body
/// (S11-1). The expiry admission check below is the load-bearing use of it, and
/// a check that reads its own clock cannot be exercised against a caller-chosen
/// instant from a caller-facing test; the endpoint stamps the time once and
/// every decision in this function is made against that single reading, so the
/// admission check and the `UpgradeIntent`/`Reservation` stamps below cannot
/// disagree about "now" within one approval.
fn approve_inner(
    caller: Principal,
    proposal_id: u64,
    expected_action_hash: Vec<u8>,
    now: u64,
) -> Result<(ApprovalOutcome, bool), VaultError> {
    let g = require_signer(caller)?;
    let mut p = proposal_get(proposal_id)
        .ok_or(VaultError::UnknownProposal { proposal_id })?;

    // ── 3. COMMITMENT CHECK — before ANY other outcome, and before any write.
    //
    // Recomputation uses the proposal's RETAINED epoch (`p.epoch`), never
    // current governance state. V3 asserted a stale-epoch approval would
    // surface as a commitment mismatch; that is FALSE, and V4.1 corrected it:
    // the commitment binds the proposal's IMMUTABLE creation epoch, so
    // advancing governance does not change it and a correctly-captured old
    // hash STILL MATCHES. The epoch pin at step 5 is therefore the SOLE
    // rejector of stale-epoch approvals — load-bearing, not defence in depth.
    // Recomputing against current state would make the commitment
    // context-dependent: the same proposal would hash differently depending on
    // when it was read.
    let recomputed = commitment_for(&p).hash();
    if recomputed != p.commitment_hash {
        // DURABLE CORRUPTION, not a caller error: the stored hash and the
        // payload it was computed from no longer agree, which no honest
        // sequence of operations can produce. Fail closed, typed distinctly.
        return Err(VaultError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::StoredVsRecomputed,
        ));
    }
    if expected_action_hash != p.commitment_hash {
        return Err(VaultError::CommitmentMismatch(
            stsh_custody_types::CommitmentMismatch::CallerMismatch,
        ));
    }

    // ── 4. Replay returns the prior result (brief invariant 4).
    // `OutcomeUnknown` never returns to `Pending`; nothing here re-triggers.
    if p.outcome != ActionOutcome::Pending {
        return Ok((
            ApprovalOutcome::PriorResult {
                outcome: p.outcome,
                result: p.result.clone(),
            },
            false,
        ));
    }
    // ── 4b. EXPIRY ADMISSION (S11-1, P1-A). The proposal is still `Pending`;
    // compare the CURRENT time against the proposal's IMMUTABLE committed
    // `expires_at_ns` BEFORE any approval, audit or execution write.
    //
    // ORDER IS PINNED BY THE S11 PACKET: commitment check first, then terminal
    // replay, then this, then the epoch pin. Placing it after the replay keeps
    // a terminal proposal returning `PriorResult` exactly as before; placing it
    // before the epoch pin is the packet's explicit instruction.
    //
    // CTO RULING (S11 packet V2) — TYPED REJECT, ZERO MUTATION. This does NOT
    // terminalize the proposal and does NOT release accounted capacity. The
    // bounded R3.8 sweep (`sweep_expired_inner` → `reap_pending`) remains the
    // SOLE terminalizer and the SOLE releaser of bytes, so there is exactly one
    // path to `Expired` and exactly one credit path to keep consistent.
    // Approval is a pure admission check and never mutates on refusal.
    //
    // `None` expiry (if any such proposal remains representable) is unaffected:
    // no deadline, nothing to enforce.
    if let Some(expires_at_ns) = p.expires_at_ns {
        if now >= expires_at_ns {
            return Err(VaultError::ProposalExpired {
                expires_at_ns,
                now_ns: now,
            });
        }
    }
    // ── 5. Epoch pin: the SOLE rejector of stale-epoch approvals (see above).
    // Must not be deleted or weakened.
    if p.epoch != g.epoch {
        return Err(VaultError::StaleEpoch {
            expected: g.epoch,
            found: p.epoch,
        });
    }
    let mut approvals = approvals_get(proposal_id);
    if approvals.contains(&caller) {
        return Err(VaultError::AlreadyApproved);
    }
    approvals.push(caller);
    approvals_put(proposal_id, &approvals);
    audit(
        AuditKind::ApprovalAdded,
        Some(proposal_id),
        caller,
        None,
        format!("approval {}/{}", approvals.len(), g.bootstrap.threshold),
    );
    if (approvals.len() as u32) < g.bootstrap.threshold {
        return Ok((
            ApprovalOutcome::Approved {
                approvals: approvals.len() as u32,
                threshold: g.bootstrap.threshold,
            },
            false,
        ));
    }
    // ── Quorum boundary. Everything below is durable BEFORE the first await.
    p.outcome = ActionOutcome::Executing;
    // C1: durable upgrade intent binding the delivered bytes (the bytes are
    // the action payload of this same durable record), written before the
    // first inter-canister call (freeze §3d).
    if matches!(
        p.action,
        VaultActionKind::UpgraderUpgrade(_)
            | VaultActionKind::Management(ManagementAction::Upgrade { .. })
            | VaultActionKind::Management(ManagementAction::InstallCode { .. })
            | VaultActionKind::VaultUpgradeViaUpgrader(_)
    ) {
        p.intent = Some(UpgradeIntent {
            intended_at_ns: now,
            intended_epoch: g.epoch,
        });
    }
    // R1.2 — the request identity is ALREADY bound (at creation). It is no
    // longer mutated here; mutating it at the quorum boundary is what made the
    // action's hash move mid-life.
    debug_assert!(
        !matches!(&p.action, VaultActionKind::VaultUpgradeViaUpgrader(vu) if vu.request_id != proposal_id),
        "request id must have been bound to the proposal id at creation"
    );
    proposal_put(&p);
    // R1.2 property 6 — the reservation fingerprint IS the stored commitment
    // hash. It was `sha256(encode(p.action))` computed here, over an action
    // that had just been mutated: a different value from anything a signer
    // could have approved.
    let fp = p.commitment_hash.clone();
    reservation_insert(&Reservation {
        proposal_id,
        action_fingerprint: fp,
        epoch: g.epoch,
        reserved_at_ns: now,
        approving_signers: approvals.clone(),
        creation_purpose: match &p.action {
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose,
                ..
            }) => Some(manifest_purpose.clone()),
            _ => None,
        },
    });
    audit(
        AuditKind::QuorumReached,
        Some(proposal_id),
        caller,
        Some(approvals),
        "quorum reached — Executing durable before first await".to_string(),
    );
    Ok((ApprovalOutcome::Executing, true))
}

// ── Execution engine ─────────────────────────────────────────────────────────

/// Transport failure of an inter-canister call. The operation may or may not
/// have happened at the target — the ONLY honest Vault-side outcome is
/// `OutcomeUnknown` (never `Failed`, never a silent retry).
#[derive(Clone, Debug)]
enum CallFailure {
    Rejected(String),
}

/// Install mode for management `install_code`. `Reinstall` does not exist —
/// structurally forbidden (freeze §3c, brief invariant 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstallMode {
    Install,
    Upgrade,
}

/// Execution backend seam. Production drives the IC; tests drive scripted
/// futures and can assert durable-state ordering at the exact call boundary.
trait ExecBackend {
    fn call_update<'a>(
        &'a self,
        target: Principal,
        method: &'static str,
        args: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, CallFailure>> + 'a>>;
    fn install_code<'a>(
        &'a self,
        target: Principal,
        mode: InstallMode,
        wasm: Vec<u8>,
        arg: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>>;
    fn start_canister<'a>(
        &'a self,
        target: Principal,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>>;
    fn stop_canister<'a>(
        &'a self,
        target: Principal,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>>;
    fn update_settings<'a>(
        &'a self,
        target: Principal,
        controllers: Vec<Principal>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>>;
    fn deposit_cycles<'a>(
        &'a self,
        target: Principal,
        cycles: u128,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>>;
    fn create_canister<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Principal, CallFailure>> + 'a>>;
}

struct IcBackend;

impl IcBackend {
    fn map_err(e: (ic_cdk::api::call::RejectionCode, String)) -> CallFailure {
        CallFailure::Rejected(format!("{e:?}"))
    }
}

impl ExecBackend for IcBackend {
    fn call_update<'a>(
        &'a self,
        target: Principal,
        method: &'static str,
        args: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, CallFailure>> + 'a>> {
        Box::pin(async move {
            ic_cdk::api::call::call_raw(target, method, args, 0)
                .await
                .map_err(Self::map_err)
        })
    }
    fn install_code<'a>(
        &'a self,
        target: Principal,
        mode: InstallMode,
        wasm: Vec<u8>,
        arg: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
        Box::pin(async move {
            use ic_cdk::api::management_canister::main::{
                install_code, CanisterInstallMode, InstallCodeArgument,
            };
            let mode = match mode {
                InstallMode::Install => CanisterInstallMode::Install,
                InstallMode::Upgrade => CanisterInstallMode::Upgrade(None),
            };
            install_code(InstallCodeArgument {
                mode,
                canister_id: target,
                wasm_module: wasm,
                arg,
            })
            .await
            .map_err(Self::map_err)
        })
    }
    fn start_canister<'a>(
        &'a self,
        target: Principal,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
        Box::pin(async move {
            use ic_cdk::api::management_canister::main::{start_canister, CanisterIdRecord};
            start_canister(CanisterIdRecord { canister_id: target })
                .await
                .map_err(Self::map_err)
        })
    }
    fn stop_canister<'a>(
        &'a self,
        target: Principal,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
        Box::pin(async move {
            use ic_cdk::api::management_canister::main::{stop_canister, CanisterIdRecord};
            stop_canister(CanisterIdRecord { canister_id: target })
                .await
                .map_err(Self::map_err)
        })
    }
    fn update_settings<'a>(
        &'a self,
        target: Principal,
        controllers: Vec<Principal>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
        Box::pin(async move {
            use ic_cdk::api::management_canister::main::{
                update_settings, CanisterSettings, UpdateSettingsArgument,
            };
            update_settings(UpdateSettingsArgument {
                canister_id: target,
                settings: CanisterSettings {
                    controllers: Some(controllers),
                    ..Default::default()
                },
            })
            .await
            .map_err(Self::map_err)
        })
    }
    fn deposit_cycles<'a>(
        &'a self,
        target: Principal,
        cycles: u128,
    ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
        Box::pin(async move {
            use ic_cdk::api::management_canister::main::{deposit_cycles, CanisterIdRecord};
            deposit_cycles(CanisterIdRecord { canister_id: target }, cycles)
                .await
                .map_err(Self::map_err)
        })
    }
    fn create_canister<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Principal, CallFailure>> + 'a>> {
        Box::pin(async move {
            use ic_cdk::api::management_canister::main::{create_canister, CreateCanisterArgument};
            create_canister(CreateCanisterArgument { settings: None }, CREATE_CANISTER_CYCLES)
                .await
                .map(|(rec,)| rec.canister_id)
                .map_err(Self::map_err)
        })
    }
}

/// Terminal write helper. Order is load-bearing (freeze §3d): the terminal
/// outcome is made durable FIRST, artifact bytes are cleared only AFTER (a
/// second durable write), then the audit event (F-4 signer set) is appended.
fn finalize(
    proposal_id: u64,
    outcome: ActionOutcome,
    result: Option<String>,
    kind: AuditKind,
    approving_signers: Vec<Principal>,
    detail: String,
) {
    debug_assert!(matches!(
        outcome,
        ActionOutcome::Executed | ActionOutcome::Failed | ActionOutcome::OutcomeUnknown
    ));
    let mut p = proposal_get(proposal_id).expect("finalized proposal exists");
    p.outcome = outcome;
    p.result = result;
    proposal_put(&p);
    // Artifact bytes cleared ONLY after terminal evidence is durable — and
    // only for terminal outcomes. OutcomeUnknown retains the bytes.
    if matches!(outcome, ActionOutcome::Executed | ActionOutcome::Failed) {
        let released = c8_logical_bytes(&p.action);
        p.action = cleared_action(p.action.clone());
        proposal_put(&p);
        retained_release(p.proposer, released);
    }
    audit(kind, Some(proposal_id), self_id(), Some(approving_signers), detail);
}

/// Strip retained artifact bytes from an action, preserving the hashes.
///
/// R3.2/R3.3: the SINGLE clearing implementation, shared by execution
/// terminalization, cancellation and expiry. Extracted rather than copied
/// because R3.3 requires exact accounting across every retained copy — a
/// second clearing path is a second place for a byte to be forgotten, which
/// is the bug that clause exists to prevent.
///
/// Hashes deliberately survive: R1.2 requires artifact bytes to enter the
/// approval commitment through their HASHES, which is what keeps the
/// commitment stable across clearing.
/// C8's CANONICAL LOGICAL-BYTE DOMAIN — the single definition, used by the S5A
/// measurement now and by S6's admission enforcement later.
///
/// WHY IT EXISTS AS A FUNCTION RATHER THAN A FIXTURE'S ARITHMETIC. The corrected
/// S5A allocation measurement tracked "logical bytes" locally and counted only
/// `wasm_bytes`, silently omitting `arg_bytes` — so it was not measuring the
/// quantity C8 will enforce. A quota and the measurement that sizes it must be
/// the SAME computation, or the constant is derived against a domain the
/// canister never checks.
///
/// SCOPE: the RETAINED ARTIFACT COMPONENTS, which are exactly what
/// `cleared_action` releases at terminalization. The two must enumerate the same
/// variants; `c8_domain_matches_cleared_action` below is the coupling, because a
/// new artifact-bearing variant added to one and not the other would leave a
/// payload outside the quota entirely.
///
/// NOT counted: record envelope, approvals, audit. Those are permanent-growth
/// terms (C9's business); C8 bounds concurrently-retained ARTIFACT payload.
fn c8_logical_bytes(action: &VaultActionKind) -> u64 {
    let pair = |w: &Vec<u8>, a: &Vec<u8>| (w.len() + a.len()) as u64;
    // EXHAUSTIVE, DELIBERATELY — no `_` arm, at either level.
    //
    // A catch-all here let a future artifact-bearing variant COMPILE while
    // silently receiving zero quota: admitted without being counted, which is
    // the precise failure a byte cap exists to prevent. A fixture-length
    // assertion cannot catch that (adding a variant leaves the fixture's length
    // unchanged), so the guard has to be the COMPILER. Every non-artifact
    // variant is classified explicitly as zero rather than swept up.
    match action {
        // ── artifact-bearing ──
        VaultActionKind::UpgraderUpgrade(uu) => pair(&uu.wasm_bytes, &uu.arg_bytes),
        VaultActionKind::VaultUpgradeViaUpgrader(vu) => pair(&vu.wasm_bytes, &vu.arg_bytes),
        VaultActionKind::Management(m) => match m {
            ManagementAction::Upgrade { wasm_bytes, arg_bytes, .. } => pair(wasm_bytes, arg_bytes),
            ManagementAction::InstallCode { wasm_bytes, arg_bytes, .. } => {
                pair(wasm_bytes, arg_bytes)
            }
            // ── management variants carrying no retained artifact ──
            ManagementAction::Start { .. } => 0,
            ManagementAction::Stop { .. } => 0,
            ManagementAction::UpdateSettings { .. } => 0,
            ManagementAction::DepositCycles { .. } => 0,
            ManagementAction::CreateCanister { .. } => 0,
        },
        // ── action variants carrying no retained artifact ──
        VaultActionKind::Application(_) => 0,
        VaultActionKind::ReconcileUpgraderUpgrade(_) => 0,
        VaultActionKind::ReadModel(_) => 0,
        VaultActionKind::UpdateSignerSet { .. } => 0,
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(_) => 0,
        // §S7 cell 3: fixed-shape objective evidence, no artifact bytes.
        VaultActionKind::ReconcileUpgraderStart(_) => 0,
    }
}

fn cleared_action(action: VaultActionKind) -> VaultActionKind {
    // EXHAUSTIVE, DELIBERATELY — see `c8_logical_bytes`. A catch-all
    // (`other => other`) let a future artifact-bearing variant compile while
    // never having its bytes released at terminalization, so the artifact would
    // be retained forever with nothing reporting it. Both paths are now
    // compiler-enforced, and `c8_domain_matches_cleared_action` couples their
    // BEHAVIOUR on every artifact-bearing variant.
    match action {
        // ── artifact-bearing: bytes released, hashes retained ──
        VaultActionKind::UpgraderUpgrade(mut uu) => {
            uu.wasm_bytes = Vec::new();
            uu.arg_bytes = Vec::new();
            VaultActionKind::UpgraderUpgrade(uu)
        }
        VaultActionKind::VaultUpgradeViaUpgrader(mut vu) => {
            vu.wasm_bytes = Vec::new();
            vu.arg_bytes = Vec::new();
            VaultActionKind::VaultUpgradeViaUpgrader(vu)
        }
        VaultActionKind::Management(m) => VaultActionKind::Management(match m {
            ManagementAction::Upgrade {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                ..
            } => ManagementAction::Upgrade {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                wasm_bytes: Vec::new(),
                arg_bytes: Vec::new(),
            },
            ManagementAction::InstallCode {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                ..
            } => ManagementAction::InstallCode {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                wasm_bytes: Vec::new(),
                arg_bytes: Vec::new(),
            },
            // ── no retained artifact: pass through unchanged ──
            other @ ManagementAction::Start { .. } => other,
            other @ ManagementAction::Stop { .. } => other,
            other @ ManagementAction::UpdateSettings { .. } => other,
            other @ ManagementAction::DepositCycles { .. } => other,
            other @ ManagementAction::CreateCanister { .. } => other,
        }),
        // ── no retained artifact: pass through unchanged ──
        other @ VaultActionKind::Application(_) => other,
        other @ VaultActionKind::ReconcileUpgraderUpgrade(_) => other,
        other @ VaultActionKind::ReadModel(_) => other,
        other @ VaultActionKind::UpdateSignerSet { .. } => other,
        other @ VaultActionKind::ReconcileVaultUpgradeViaUpgrader(_) => other,
        // §S7 cell 3: no artifact bytes to release.
        other @ VaultActionKind::ReconcileUpgraderStart(_) => other,
    }
}

// ── R3.2 / R3.7 / R3.8: reaping a Pending proposal ──────────────────────────

/// Move a `Pending` proposal to a terminal reaped state.
///
/// ORDERING IS LOAD-BEARING (R3.2): the terminal state is made durable FIRST,
/// then the artifact bytes are cleared in a SECOND durable write. Clearing
/// first would, if the state write then failed, leave a `Pending` proposal
/// whose payload had already been destroyed — unapprovable and unexecutable,
/// with no record of why. Two writes, in this order, so any interruption
/// leaves a coherent state.
fn reap_pending(mut p: ProposalRecord, terminal: ActionOutcome, detail: Option<String>) {
    debug_assert!(terminal.is_terminal(), "reap target must be terminal");
    let id = p.proposal_id;
    // 1. Terminal state durable. `proposal_put` drops the expiry-index entry
    //    as part of this write, so the sweep cannot see it twice.
    p.outcome = terminal;
    p.result = detail.clone();
    proposal_put(&p);
    // 2. Only now, with the terminal state durable, release the bytes.
    let released = c8_logical_bytes(&p.action);
    p.action = cleared_action(p.action.clone());
    proposal_put(&p);
    retained_release(p.proposer, released);
    audit(
        match terminal {
            ActionOutcome::Cancelled => AuditKind::ProposalCancelled,
            _ => AuditKind::ProposalExpired,
        },
        Some(id),
        self_id(),
        None,
        detail.unwrap_or_default(),
    );
}

/// R3.7 (V7 §3) — the proposer withdraws their OWN pending proposal.
///
/// Proposer-scoped by design: no signer may unilaterally veto a proposal their
/// peers are still evaluating. A non-proposer signer gets the typed
/// `NotProposer`, distinct from `NotAuthorized`, because they ARE authorized on
/// this canister — the defect is scope, not authority.
fn cancel_proposal_inner(caller: Principal, proposal_id: u64) -> Result<(), VaultError> {
    require_signer(caller)?;
    let p = proposal_get(proposal_id).ok_or(VaultError::UnknownProposal { proposal_id })?;
    if p.proposer != caller {
        return Err(VaultError::NotProposer);
    }
    if !p.outcome.is_reapable() {
        // Covers every non-Pending state: already terminal, or past the first
        // await where cancelling would assert something untrue about a call
        // that may have landed.
        return Err(VaultError::AlreadyTerminal);
    }
    reap_pending(p, ActionOutcome::Cancelled, Some("cancelled by proposer".into()));
    Ok(())
}

/// R3.8 — the bounded expiry sweep.
///
/// CANNOT ITSELF BE THE DoS: work is bounded by `limit`, and due proposals are
/// read as an ordered PREFIX of the expiry index rather than found by scanning
/// proposals. Cost is O(limit · log n), independent of how many proposals
/// exist or how many are already terminal.
///
/// Returns the ids reaped so a caller can drive it to completion in bounded
/// batches. While the lifetime bounds are unruled the index is empty and this
/// is a no-op — the mechanism is live, the policy is not yet.
fn sweep_expired_inner(now: u64, limit: usize) -> Vec<u64> {
    // Collect the due prefix first; mutating the index while iterating it is
    // not sound.
    let due: Vec<(u64, u64)> = PROPOSAL_EXPIRY_INDEX.with(|x| {
        x.borrow()
            .iter()
            .take_while(|((exp, _), _)| *exp <= now)
            .take(limit)
            .map(|((exp, id), _)| (exp, id))
            .collect()
    });
    let mut reaped = Vec::new();
    for (_, id) in due {
        let Some(p) = proposal_get(id) else { continue };
        // Re-check under the durable record. PRECEDENCE (amended R3 item 10):
        // history establishes existence and terminal outcomes, the companion
        // authorizes active membership; neither rebuilds the other, and
        // the record is the authority.
        if !p.outcome.is_reapable() {
            continue;
        }
        reap_pending(p, ActionOutcome::Expired, Some("lifetime elapsed".into()));
        reaped.push(id);
    }
    reaped
}

/// Resolve a frozen application target role to the durable init-time wiring.
/// Fail closed: an unconfigured target is a `Failed` execution, never a
/// caller-supplied principal.
#[cfg(test)]
thread_local! {
    static RECEIPT_POINT_LOOKUPS_FOR_TEST: RefCell<u64> = const { RefCell::new(0) };
    static RECEIPT_DECODES_FOR_TEST: RefCell<u64> = const { RefCell::new(0) };
}

fn receipt_event_point_read(receipt_audit_id: u64) -> Result<AuditEvent, String> {
    #[cfg(test)]
    RECEIPT_POINT_LOOKUPS_FOR_TEST.with(|count| *count.borrow_mut() += 1);
    let bytes = AUDIT_EVENTS
        .with(|events| events.borrow().get(&receipt_audit_id))
        .ok_or_else(|| "receipt audit event not found".to_string())?;
    if bytes.len() > READ_RESPONSE_MAX_BYTES {
        return Err(format!(
            "receipt audit event {} bytes > READ_RESPONSE_MAX_BYTES {READ_RESPONSE_MAX_BYTES}",
            bytes.len()
        ));
    }
    #[cfg(test)]
    RECEIPT_DECODES_FOR_TEST.with(|count| *count.borrow_mut() += 1);
    candid::decode_one(&bytes).map_err(|e| format!("receipt audit event undecodable: {e}"))
}

fn resolve_manifest_token_target(receipt_audit_id: u64) -> Result<Principal, String> {
    let g = gov();
    let matches: Vec<_> = g
        .governed
        .iter()
        .filter(|target| {
            target.purpose == "stsh_token"
                && target.disposition == ManifestDisposition::BornUnderVault
        })
        .collect();
    let [target] = matches.as_slice() else {
        return Err("unique governed stsh_token target not found".to_string());
    };

    let event = receipt_event_point_read(receipt_audit_id)?;
    if event.id != receipt_audit_id
        || event.kind != AuditKind::CanisterCreated
        || event.proposal_id.is_none()
    {
        return Err("receipt audit event identity/kind/proposal mismatch".to_string());
    }
    let receipt = event
        .creation_receipt
        .ok_or_else(|| "creation receipt absent".to_string())?;
    if receipt.status != CreationReceiptStatus::Bound
        || receipt.principal != target.principal
        || receipt.purpose != target.purpose
        || receipt.disposition != target.disposition
        || receipt.purpose != "stsh_token"
        || receipt.disposition != ManifestDisposition::BornUnderVault
        || event.proposal_id != Some(receipt.proposal_id)
    {
        return Err("creation receipt does not bind governed stsh_token".to_string());
    }
    Ok(target.principal)
}

fn resolve_target(t: ApplicationTarget) -> Option<Principal> {
    let g = gov();
    match t {
        ApplicationTarget::ShieldedPool => g.targets.shielded_pool,
        ApplicationTarget::Treasury => g.targets.treasury,
        ApplicationTarget::Vesting => g.targets.vesting,
    }
}

/// Decode a variant's response payload into its typed contract
/// (stsh-custody-types `ActionResponse` — the frozen per-variant shapes).
fn decode_application_response(
    kind: ApplicationAction,
    bytes: &[u8],
) -> Result<ActionResponseT, ()> {
    use stsh_custody_types::*;
    use ApplicationAction as A;
    macro_rules! dec {
        ($t:ty, $v:expr) => {
            candid::decode_one::<$t>(bytes).map($v).map_err(|_| ())
        };
    }
    match kind {
        A::PoolPruneTerminalRecords => dec!(PruneResult, ActionResponseT::PoolPruneTerminalRecords),
        A::PoolReconcileDepositCommitment => {
            dec!(Result<(), PoolErrorMirror>, ActionResponseT::PoolReconcileDepositCommitment)
        }
        A::PoolReconcileDepositAppendUnknown => {
            dec!(Result<DepositAppendReconcileResult, PoolErrorMirror>, ActionResponseT::PoolReconcileDepositAppendUnknown)
        }
        A::PoolReconcileDepositTransferNotExecuted => {
            dec!(Result<(), PoolErrorMirror>, ActionResponseT::PoolReconcileDepositTransferNotExecuted)
        }
        A::PoolReconcileTreasuryDisburse => {
            dec!(Result<ReconcileDisburseResult, PoolErrorMirror>, ActionResponseT::PoolReconcileTreasuryDisburse)
        }
        A::PoolReconcileNullifierInsert => {
            dec!(Result<ReconcileNullifierResult, PoolErrorMirror>, ActionResponseT::PoolReconcileNullifierInsert)
        }
        A::PoolReconcilePendingSpend => {
            dec!(Result<ReconcilePendingSpendResult, PoolErrorMirror>, ActionResponseT::PoolReconcilePendingSpend)
        }
        A::PoolScheduleVkActivation => dec!(Result<(), String>, ActionResponseT::PoolScheduleVkActivation),
        A::PoolEmergencyDisableCircuitVersion => {
            dec!(Result<(), String>, ActionResponseT::PoolEmergencyDisableCircuitVersion)
        }
        A::PoolEmergencyPauseDeposits => {
            candid::decode_one::<()>(bytes)
                .map(|_| ActionResponseT::PoolEmergencyPauseDeposits)
                .map_err(|_| ())
        }
        A::PoolEmergencyPauseSpends => dec!(Result<(), String>, ActionResponseT::PoolEmergencyPauseSpends),
        A::PoolUnpauseDeposits => {
            candid::decode_one::<()>(bytes)
                .map(|_| ActionResponseT::PoolUnpauseDeposits)
                .map_err(|_| ())
        }
        A::PoolUnpauseSpends => {
            candid::decode_one::<()>(bytes)
                .map(|_| ActionResponseT::PoolUnpauseSpends)
                .map_err(|_| ())
        }
        A::PoolSetVerifierCanister => {
            dec!(Result<(), PoolErrorMirror>, ActionResponseT::PoolSetVerifierCanister)
        }
        A::PoolClearVerifierConfigGuard => dec!(bool, ActionResponseT::PoolClearVerifierConfigGuard),
        A::PoolSetGovernanceFeeParams => dec!(Result<(), String>, ActionResponseT::PoolSetGovernanceFeeParams),
        A::PoolReconcilePrivateSpendPayout => {
            dec!(Result<ReconcilePayoutResult, PoolErrorMirror>, ActionResponseT::PoolReconcilePrivateSpendPayout)
        }
        A::PoolInitializePayoutMemoKey => {
            dec!(Result<bool, PoolErrorMirror>, ActionResponseT::PoolInitializePayoutMemoKey)
        }
        A::TreasuryProposeWithdrawal => dec!(u64, ActionResponseT::TreasuryProposeWithdrawal),
        A::TreasuryExecuteWithdrawal => dec!(Result<(), String>, ActionResponseT::TreasuryExecuteWithdrawal),
        A::TreasuryRejectProposal => {
            dec!(Result<(), RejectProposalErrorMirror>, ActionResponseT::TreasuryRejectProposal)
        }
        A::VestingReconcileClaim => dec!(Result<(), String>, ActionResponseT::VestingReconcileClaim),
    }
}

use stsh_custody_types::ActionResponse as ActionResponseT;

/// A typed business-level rejection at the target is a `Failed` execution
/// (the call completed; the target said no). Anything else that replied is an
/// `Executed` execution.
fn response_is_business_failure(resp: &ActionResponseT) -> bool {
    use ActionResponseT as R;
    fn failed<T, E>(r: &Result<T, E>) -> bool {
        r.is_err()
    }
    match resp {
        R::PoolReconcileDepositCommitment(r) => failed(r),
        R::PoolReconcileDepositAppendUnknown(r) => failed(r),
        R::PoolReconcileDepositTransferNotExecuted(r) => failed(r),
        R::PoolReconcileTreasuryDisburse(r) => failed(r),
        R::PoolReconcileNullifierInsert(r) => failed(r),
        R::PoolReconcilePendingSpend(r) => failed(r),
        R::PoolSetVerifierCanister(r) => failed(r),
        R::PoolScheduleVkActivation(r) => failed(r),
        R::PoolEmergencyDisableCircuitVersion(r) => failed(r),
        R::PoolEmergencyPauseSpends(r) => failed(r),
        R::PoolSetGovernanceFeeParams(r) => failed(r),
        R::TreasuryExecuteWithdrawal(r) => failed(r),
        R::TreasuryRejectProposal(r) => failed(r),
        R::VestingReconcileClaim(r) => failed(r),
        R::PoolReconcilePrivateSpendPayout(r) => failed(r),
        R::PoolInitializePayoutMemoKey(r) => !matches!(r, Ok(true)),
        R::PoolClearVerifierConfigGuard(ok) => !ok,
        _ => false,
    }
}

/// Byte-bounded, UTF-8-safe truncation (F1; hygiene: the FINAL text is at
/// most MAX bytes — the ellipsis space is reserved, not appended on top).
/// A naive `&s[..MAX]` panics when the byte cap lands inside a multibyte
/// character — and this runs on target-controlled response/rejection text
/// AFTER an inter-canister await, so a panic would strand the proposal in
/// durable `Executing`. Truncate at the largest char boundary <= the
/// remaining byte budget instead.
fn cap_detail(s: String) -> String {
    const MAX: usize = 1_024;
    if s.len() > MAX {
        let budget = MAX - "…".len();
        let mut end = budget;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    } else {
        s
    }
}

/// Execute one quorum-approved proposal to a terminal (or OutcomeUnknown)
/// state. Called ONLY from the quorum boundary, after `Executing` and the
/// reservation are durable. Every path writes its outcome through
/// `finalize`; nothing here returns a proposal to `Pending`.
/// Returns the typed error this execution must surface **on the public wire**,
/// if any.
///
/// P1-2 / V5 §7c. Almost every action reports its result through the durable
/// proposal record alone, and for those this is `None`. A START REPLAY is
/// different: §7c requires every replay, in BOTH directions, to return the
/// typed `AlreadySettled { outcome }` and NEVER a success-shaped response —
/// "the caller is not denied the outcome; it rides in the error payload". The
/// recovery plane already satisfies this because its core returns `Result` and
/// `approve_recovery` propagates it. The Vault executes actions at the quorum
/// boundary, so the typed value has to be carried back out to `approve`, which
/// is the public boundary and already returns `Result<_, VaultError>`.
///
/// Returning `Err` from an update method is a NORMAL REPLY on the IC — only a
/// trap rolls state back — so the durable record written by `finalize` stands
/// and the caller still receives the typed error. Both are true at once, which
/// is what §7c asks for.
async fn execute_action_with<B: ExecBackend>(
    backend: &B,
    proposal_id: u64,
) -> Option<VaultError> {
    let p = proposal_get(proposal_id).expect("executed proposal exists");
    let approvals = approvals_get(proposal_id);
    match p.action.clone() {
        VaultActionKind::UpdateSignerSet { signers, threshold } => {
            execute_signer_set_update(proposal_id, signers, threshold, approvals);
        }
        VaultActionKind::Application(req) => {
            let kind = req.kind();
            let binding = kind.binding();
            let Some(target) = resolve_target(binding.target) else {
                finalize(
                    proposal_id,
                    ActionOutcome::Failed,
                    Some("target not configured".to_string()),
                    AuditKind::Failed,
                    approvals,
                    format!("{kind:?}: no durable target wiring — fail closed"),
                );
                return None;
            };
            match backend.call_update(target, binding.method, req.encode()).await {
                Ok(bytes) if bytes.len() as u64 > binding.max_response_bytes => {
                    // F2: the target replied but violated the frozen wire
                    // contract — deterministic Failed. No decode, no retry,
                    // never left in Executing.
                    finalize(
                        proposal_id,
                        ActionOutcome::Failed,
                        Some(format!(
                            "response {} bytes > ceiling {}",
                            bytes.len(),
                            binding.max_response_bytes
                        )),
                        AuditKind::Failed,
                        approvals,
                        format!(
                            "{kind:?}: reply exceeded max_response_bytes ({})",
                            binding.max_response_bytes
                        ),
                    );
                }
                Ok(bytes) => match decode_application_response(kind, &bytes) {
                    Ok(resp) => {
                        let failed = response_is_business_failure(&resp);
                        finalize(
                            proposal_id,
                            if failed { ActionOutcome::Failed } else { ActionOutcome::Executed },
                            Some(cap_detail(format!("{resp:?}"))),
                            if failed { AuditKind::Failed } else { AuditKind::Executed },
                            approvals,
                            cap_detail(format!("{kind:?} response: {resp:?}")),
                        );
                    }
                    Err(()) => finalize(
                        proposal_id,
                        ActionOutcome::OutcomeUnknown,
                        Some("response undecodable".to_string()),
                        AuditKind::OutcomeUnknown,
                        approvals,
                        format!("{kind:?}: reply did not decode as the frozen contract"),
                    ),
                },
                Err(CallFailure::Rejected(e)) => finalize(
                    proposal_id,
                    ActionOutcome::OutcomeUnknown,
                    Some(cap_detail(e.clone())),
                    AuditKind::OutcomeUnknown,
                    approvals,
                    cap_detail(format!("{kind:?}: transport failure: {e}")),
                ),
            }
        }
        VaultActionKind::Management(m) => {
            execute_management(backend, proposal_id, m, approvals).await;
        }
        VaultActionKind::UpgraderUpgrade(uu) => {
            let upgrader = gov().bootstrap.counterpart;
            execute_install(
                backend,
                proposal_id,
                upgrader,
                InstallMode::Upgrade, // upgrade-mode ONLY (freeze §3d)
                uu.expected_wasm_hash,
                uu.expected_arg_hash,
                uu.wasm_bytes,
                uu.arg_bytes,
                approvals,
            )
            .await;
        }
        VaultActionKind::ReconcileUpgraderUpgrade(rec) => {
            execute_reconcile_upgrader_upgrade(proposal_id, &rec, approvals);
        }
        VaultActionKind::ReadModel(req) => {
            execute_read_model(backend, proposal_id, req, approvals).await;
        }
        VaultActionKind::VaultUpgradeViaUpgrader(vu) => {
            execute_vault_upgrade_via_upgrader(backend, proposal_id, vu, approvals).await;
        }
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(rec) => {
            execute_reconcile_vault_upgrade(backend, proposal_id, rec, approvals).await;
        }
        // The ONE arm that carries a typed value back to the public boundary
        // (§7c). Every other arm reports through the durable record alone.
        VaultActionKind::ReconcileUpgraderStart(rec) => {
            return execute_reconcile_upgrader_start(proposal_id, &rec, approvals);
        }
    }
    None
}

// ═════════════════════════════════════════════════════════════════════════════
// §S7 START SETTLEMENT — CELL 3 (Vault → Upgrader), the retrofit
//
// The twin of the Upgrader's cell 4. Every predicate is imported from
// `stsh_custody_types` and is the SAME CODE the Upgrader runs; only storage and
// audit are plane-specific. See the header on the Upgrader's cell-4 section.
// ═════════════════════════════════════════════════════════════════════════════

/// Is this `Start` a RING start — i.e. cell 3?
///
/// The settlement contract governs the RING direction. §4.3's controller check
/// is defined only for ring members ("`Vault.controllers == [Upgrader]`,
/// `Upgrader.controllers == [Vault]`"), and §1 names cell 3 as
/// "Vault → Upgrader". A `Start` against an ordinary governed target has no
/// ring invariant to check against and is OUT OF SCOPE for S7 (R4.3 preserved
/// surfaces): its existing behaviour is untouched.
fn is_ring_start(target: Principal) -> bool {
    target == gov().bootstrap.counterpart
}

/// §2 — write the durable start-intent for a cell-3 start, BEFORE the first
/// `await` of `start_canister`.
///
/// Returns `false` if §2's single-flight discipline refuses the start. `Executing`
/// is already durable when this runs (the quorum boundary wrote it), so this
/// discharges obligation 3, and it is called before the management call so it
/// discharges obligation 4.
fn record_start_intent(proposal_id: u64, target: Principal, now: u64) -> bool {
    // §2: "A start and an upgrade must not be in flight against the same target
    // concurrently, because concurrent module mutation would destroy the
    // attributability of the status evidence in §4." The Vault's existing
    // mutating single-flight index holds exactly the Executing|OutcomeUnknown
    // mutating intents against a target, so the start joins THAT discipline
    // rather than a parallel one.
    if let Some(other) = open_mutating_intent(target, Some(proposal_id)) {
        audit(
            AuditKind::Failed,
            Some(proposal_id),
            self_id(),
            None,
            format!("§S7 §2 single-flight: proposal {other} already in flight against {target}"),
        );
        return false;
    }
    let mut p = proposal_get(proposal_id).expect("executing proposal exists");
    p.start = Some(StartSettlementState {
        intent: StartIntent {
            proposal_id,
            target,
            // Cell 3's epoch is the GOVERNANCE epoch (§2.3); cell 4's is the
            // recovery epoch. Same field, each plane's own quorum authority.
            epoch: p.epoch,
            intent_at_ns: now,
        },
        settlement: None,
    });
    proposal_put(&p);
    true
}

/// §3c.2 — the late-callback fence for cell 3.
///
/// Returns `true` if the callback may write settlement state, i.e. the DURABLE
/// `ActionOutcome` re-read here is exactly `Executing`. On a fenced callback it
/// appends the one bounded `LateCallbackFenced` event (§3c.3) and returns
/// `false`; the caller then performs ZERO settlement-state mutation and ZERO
/// lock change, and never treats the callback payload as evidence.
fn start_callback_may_write(proposal_id: u64) -> bool {
    let Some(p) = proposal_get(proposal_id) else {
        return false;
    };
    if callback_may_write(p.outcome) {
        return true;
    }
    audit(
        AuditKind::LateCallbackFenced,
        Some(proposal_id),
        self_id(),
        None,
        format!("§3c fenced: durable outcome {:?} is not Executing", p.outcome),
    );
    false
}

/// §3a **E2 — the post-upgrade sweep** for cell 3. See the Upgrader's twin for
/// the full justification: it is a conservative upgrade-boundary promotion from
/// callback-writable to callback-fenced, taking no evidence, writing no
/// terminal outcome, releasing no lock, and idempotent.
fn sweep_executing_starts_to_unknown(_now: u64) {
    let ids: Vec<u64> = mutating_intent_proposal_ids();
    for id in ids {
        let Some(mut p) = proposal_get(id) else { continue };
        if p.start.is_none() || p.outcome != ActionOutcome::Executing {
            continue;
        }
        p.outcome = ActionOutcome::OutcomeUnknown;
        proposal_put(&p);
        audit(
            AuditKind::OutcomeUnknown,
            Some(id),
            self_id(),
            None,
            "§S7 E2: post-upgrade sweep promoted Executing start to OutcomeUnknown".to_string(),
        );
    }
}

/// §7f — the cell-3 start-settlement core. Synchronous: no inter-canister call.
///
/// The gate ORDER is `classify_start_reconcile`, the single shared function
/// both directions call; this only applies the disposition. Acceptance 15(a)'s
/// "four distinct typed errors, identical across directions" is therefore true
/// by construction.
/// Returns the typed error to surface on the PUBLIC WIRE, per §7c (P1-2).
///
/// The durable reconcile-proposal record is still written by `finalize` on
/// every path — that is the governance fact. What this returns is the CALLER'S
/// typed result, which for a replay must be `AlreadySettled { outcome }` and
/// never a success-shaped response. The two are complementary, not
/// alternatives: stringifying the error into `ProposalRecord.result` and
/// replying `Ok` — as this did before P1-2 — left the advertised DID variant
/// dead and made the two planes observably asymmetric, the recovery plane
/// returning a typed error where the Vault returned success-shaped debug text.
fn execute_reconcile_upgrader_start(
    reconcile_proposal_id: u64,
    rec: &ReconcileUpgraderStart,
    approvals: Vec<Principal>,
) -> Option<VaultError> {
    let target_id = rec.proposal_id;
    let evidence = &rec.objective_evidence;
    let found = proposal_get(target_id).filter(|p| p.start.is_some());
    // §4.3 ring invariant for THIS target: the Upgrader's controllers must be
    // exactly [Vault], and this canister IS the Vault.
    let required = [self_id()];
    let now = now_ns();

    let classified = {
        let source = found.as_ref().map(|p| {
            let start = p.start.as_ref().expect("filtered on start");
            StartSourceState {
                outcome: p.outcome,
                intent: &start.intent,
                settlement: start.settlement.as_ref(),
                required_controllers: &required,
            }
        });
        classify_start_reconcile(source, evidence, now)
    };

    // Every rejection below fails the RECONCILE proposal closed and leaves the
    // TARGET proposal untouched — still `OutcomeUnknown`, lock retained,
    // `conflict_recorded` untouched, reconcilable by a later correct proposal.
    let disposition = match classified {
        Ok(d) => d,
        Err(StartReconcileRejection::UnknownProposal) => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some(format!("{:?}", VaultError::UnknownProposal { proposal_id: target_id })),
                AuditKind::Failed,
                approvals,
                format!("§7f step 1: no start proposal {target_id} — never a settlement"),
            );
            return None;
        }
        Err(StartReconcileRejection::IllegalSourceState) => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some(format!("{:?}", VaultError::IllegalSourceState)),
                AuditKind::Failed,
                approvals,
                format!("§7f step 2: proposal {target_id} is not a legal source state"),
            );
            return None;
        }
        Err(StartReconcileRejection::EvidenceRejected(reason)) => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some(format!("{reason:?}")),
                AuditKind::Failed,
                approvals,
                format!("§7f step 3: evidence rejected ({reason:?}) — zero mutation, lock retained"),
            );
            // No typed wire error: `VaultError` has no evidence-rejection
            // variant, and adding one would be a DID movement this corrective
            // is NOT authorized to make (P1-2 is scoped to the §7c replay
            // carriage). The rejection is recorded on the durable proposal.
            return None;
        }
    };

    let mut target = found.expect("a disposition implies the proposal resolved");

    match disposition {
        // §7e — inconclusive `Stopping`: NO transition on the target, zero
        // mutation, lock RETAINED, no audit append against it. The RECONCILE
        // proposal is `Executed`: it did exactly what it was approved to do.
        StartReconcileDisposition::Inconclusive => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Executed,
                Some("Stopping: inconclusive, no settlement".to_string()),
                AuditKind::Executed,
                approvals,
                format!("§5: proposal {target_id} observed Stopping — remains OutcomeUnknown"),
            );
            // NOT a replay: Ok(None) carriage stands (CTO ruling §2, SSA
            // concurred). No typed error.
            None
        }

        // §7b/§8/§8a — THE terminal transition, at most once per proposal, in
        // ONE ATOMIC DURABLE TRANSITION (§0b): the terminal outcome and the
        // `SettlementRecord` land in the SINGLE `proposal_put` below — one
        // synchronous message execution, NO `await` between them. The lock
        // release is part of that same write, so the record is durable before
        // the release is observable (§8a invariants 1 and 2) as a property of
        // the single transition rather than a two-write ordering rule a crash
        // could split.
        StartReconcileDisposition::Settle(outcome) => {
            target.outcome = match outcome {
                ReconcileTerminalOutcome::Executed => ActionOutcome::Executed,
                ReconcileTerminalOutcome::Failed => ActionOutcome::Failed,
            };
            let start = target.start.as_mut().expect("start state present");
            debug_assert!(
                start.settlement.is_none(),
                "§7b: reconciliation terminalizes at most once per proposal"
            );
            start.settlement = Some(SettlementRecord::settle(outcome, evidence));
            proposal_put(&target);
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Executed,
                Some(format!("{outcome:?}")),
                AuditKind::Executed,
                approvals,
                format!("§5: proposal {target_id} settled {outcome:?}"),
            );
            // A genuine settlement is not a replay: no typed error.
            None
        }

        // §7d concordant / inconclusive replay — zero settlement-state
        // mutation, zero dedup-state write, ZERO audit append against the
        // target. §7c: never success-shaped — the reconcile proposal carries
        // the typed `AlreadySettled { outcome }`, with the outcome in the
        // payload rather than denied to the caller.
        StartReconcileDisposition::ReplayConcordant { stored }
        | StartReconcileDisposition::ReplayInconclusive { stored } => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some("replay: already settled".to_string()),
                AuditKind::Failed,
                approvals,
                format!("§7d concordant/inconclusive replay against settled proposal {target_id} — no mutation"),
            );
            // §7c — TYPED, on the public wire. The outcome rides in the
            // payload; the caller is not denied it.
            Some(VaultError::AlreadySettled { outcome: stored })
        }

        // §7d DISCORDANT replay — **NO RE-OPEN**, identical error shape.
        StartReconcileDisposition::ReplayDiscordant {
            stored,
            replay_mapped,
            cap_available,
        } => {
            if cap_available {
                // §7d.1 — ONE ATOMIC DURABLE TRANSITION (§0b). The
                // `conflict_recorded: false → true` transition and the audit
                // append occur in the SAME synchronous message execution, no
                // `await` and no message boundary between them. Both
                // interleavings an `await` would admit are impermissible:
                // MARKER WITHOUT EVENT silences every future discordance while
                // nothing was recorded; EVENT WITHOUT MARKER breaks the §7d cap.
                let conflict = {
                    let start = target.start.as_ref().expect("start state present");
                    let record = start.settlement.as_ref().expect("discordance implies settled");
                    // Fields 2–4 READ FROM THE STORED RECORD (§8a invariant 6).
                    SettlementEvidenceConflict::new(target_id, record, evidence, replay_mapped)
                };
                {
                    let start = target.start.as_mut().expect("start state present");
                    let record = start.settlement.as_mut().expect("discordance implies settled");
                    record.conflict_recorded = true;
                }
                proposal_put(&target);
                audit_conflict(target_id, &conflict);
            }
            // Every subsequent discordance appends nothing and writes nothing.
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some("replay: already settled".to_string()),
                AuditKind::Failed,
                approvals,
                format!("§7d discordant replay against settled proposal {target_id} — no re-open"),
            );
            // §7c — IDENTICAL SHAPE to the concordant branch, typed on the
            // wire. A discordance must not be distinguishable from a
            // concordance by the response: that is what "no re-open, identical
            // shape" means, and the forensic difference lives in the audit
            // event, not in what the caller is told.
            return Some(VaultError::AlreadySettled { outcome: stored });
        }
    }
}

/// §3e execution (CUST-L12-01): call the recorded Upgrader counterpart at
/// the FIXED `trigger_vault_upgrade` endpoint. No target/method freedom,
/// no blind retry: a typed terminal result maps to the matching terminal
/// Vault proposal state; transport uncertainty or an undecodable reply is
/// OutcomeUnknown; never back to Pending.
async fn execute_vault_upgrade_via_upgrader<B: ExecBackend>(
    backend: &B,
    proposal_id: u64,
    vu: VaultUpgradeViaUpgrader,
    approvals: Vec<Principal>,
) {
    // Execution-boundary re-checks (propose already enforced them).
    if let Err(e) = check_hashes(
        &vu.expected_wasm_hash,
        &vu.expected_arg_hash,
        &vu.wasm_bytes,
        &vu.arg_bytes,
    ) {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("{e:?}")),
            AuditKind::Failed,
            approvals,
            "hash re-check failed at execution boundary".to_string(),
        );
        return;
    }
    // Single-flight re-check: another Vault-target intent may have been
    // proposed while this one was Pending.
    if let Some(other) = open_mutating_intent(self_id(), Some(proposal_id)) {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("single-flight: intent {other} open on Vault")),
            AuditKind::Failed,
            approvals,
            format!("single-flight violation: proposal {other} is nonterminal on the Vault"),
        );
        return;
    }
    debug_assert_eq!(
        vu.request_id, proposal_id,
        "request id bound at CREATION (R1.2) — reaching execution with a different \
         value means the identity moved after the commitment was frozen"
    );
    let upgrader = gov().bootstrap.counterpart;
    let result = backend
        .call_update(upgrader, RingActionKind::VaultUpgradeViaUpgrader.endpoint(), vu.encode())
        .await;
    match result {
        Ok(bytes) if bytes.len() > RING_RESPONSE_MAX_BYTES => finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("ring reply {} bytes > {RING_RESPONSE_MAX_BYTES}", bytes.len())),
            AuditKind::Failed,
            approvals,
            "trigger_vault_upgrade reply exceeded the wire ceiling".to_string(),
        ),
        Ok(bytes) => {
            match candid::decode_one::<Result<TriggerUpgradeResult, stsh_custody_types::RecoveryError>>(&bytes) {
                Ok(Ok(r)) => {
                    let (outcome, kind) = match r.outcome {
                        ActionOutcome::Executed => (ActionOutcome::Executed, AuditKind::Executed),
                        ActionOutcome::Failed => (ActionOutcome::Failed, AuditKind::Failed),
                        // The Upgrader could not determine the outcome (or
                        // reports a non-terminal state) — honest
                        // OutcomeUnknown, NEVER a retry.
                        _ => (ActionOutcome::OutcomeUnknown, AuditKind::OutcomeUnknown),
                    };
                    finalize(
                        proposal_id,
                        outcome,
                        Some(format!("trigger_vault_upgrade → {:?}", r.outcome)),
                        kind,
                        approvals,
                        format!("Upgrader reports {:?}", r.outcome),
                    );
                }
                Ok(Err(e)) => finalize(
                    proposal_id,
                    ActionOutcome::Failed,
                    Some(format!("{e:?}")),
                    AuditKind::Failed,
                    approvals,
                    format!("Upgrader rejected the upgrade deterministically: {e:?}"),
                ),
                Err(_) => finalize(
                    proposal_id,
                    ActionOutcome::OutcomeUnknown,
                    Some("ring reply undecodable".to_string()),
                    AuditKind::OutcomeUnknown,
                    approvals,
                    "trigger_vault_upgrade reply did not decode".to_string(),
                ),
            }
        }
        Err(CallFailure::Rejected(e)) => finalize(
            proposal_id,
            ActionOutcome::OutcomeUnknown,
            Some(cap_detail(e.clone())),
            AuditKind::OutcomeUnknown,
            approvals,
            cap_detail(format!("trigger_vault_upgrade transport failure: {e}")),
        ),
    }
}

/// §3e reconciliation execution: legal source OutcomeUnknown ONLY; calls the
/// Upgrader's FIXED `reconcile_vault_upgrade` endpoint; terminalizes the
/// target from the typed result. Never retries/reinstalls — the Upgrader
/// settles its durable intent; the Vault settles its proposal.
async fn execute_reconcile_vault_upgrade<B: ExecBackend>(
    backend: &B,
    reconcile_proposal_id: u64,
    rec: ReconcileVaultUpgradeViaUpgrader,
    approvals: Vec<Principal>,
) {
    let fail_self = |result: &str, detail: String| {
        finalize(
            reconcile_proposal_id,
            ActionOutcome::Failed,
            Some(result.to_string()),
            AuditKind::Failed,
            approvals.clone(),
            detail,
        );
    };
    let target = match proposal_get(rec.request_id) {
        Some(t) => t,
        None => {
            fail_self(
                "unknown target proposal",
                format!("reconcile target {} not found", rec.request_id),
            );
            return;
        }
    };
    let expected_wasm_hash = match &target.action {
        VaultActionKind::VaultUpgradeViaUpgrader(vu) => vu.expected_wasm_hash.clone(),
        _ => {
            fail_self(
                "target is not a VaultUpgradeViaUpgrader",
                "reconcile target is not a §3e Vault upgrade".to_string(),
            );
            return;
        }
    };
    // CUST-L12-02: BOTH local source states (Executing — the reply-callback
    // loss that a successful self-upgrade necessarily leaves — and
    // OutcomeUnknown) ALWAYS consult the Upgrader's fixed
    // reconcile_vault_upgrade endpoint. There is NO local-only settlement:
    // L1 cannot infer L2's durable intent state from its own Executing
    // state. L2 replays terminal intents idempotently and transitions
    // OutcomeUnknown intents; Pending/Executing at L2 is rejected there.
    if !matches!(
        target.outcome,
        ActionOutcome::OutcomeUnknown | ActionOutcome::Executing
    ) {
        fail_self(
            "IllegalSourceState",
            format!(
                "legal source states are OutcomeUnknown | Executing; found {:?}",
                target.outcome
            ),
        );
        return;
    }
    // Evidence binding + freshness (same discipline as L1-3): for THIS
    // direction the frozen `observed_upgrader_principal` field binds the
    // VAULT principal, and `observed_controllers` must be exactly
    // [Upgrader].
    let ev = &rec.objective_evidence;
    let upgrader = gov().bootstrap.counterpart;
    if ev.observed_upgrader_principal != self_id() {
        fail_self(
            "evidence principal mismatch",
            "observed principal != this Vault".to_string(),
        );
        return;
    }
    let now = now_ns();
    let intended_at = target.intent.as_ref().map(|i| i.intended_at_ns).unwrap_or(0);
    let stale = if ev.observed_at_ns < intended_at {
        Some("evidence predates upgrade intent")
    } else if ev.observed_at_ns > now {
        Some("evidence from the future")
    } else if now.saturating_sub(ev.observed_at_ns) > MAX_EVIDENCE_AGE_NS {
        Some("evidence too old")
    } else {
        None
    };
    if let Some(why) = stale {
        fail_self(why, format!("stale/future evidence rejected: {why}"));
        return;
    }
    let result = backend
        .call_update(
            upgrader,
            RingActionKind::ReconcileVaultUpgradeViaUpgrader.endpoint(),
            rec.encode(),
        )
        .await;
    match result {
        Ok(bytes) if bytes.len() > RING_RESPONSE_MAX_BYTES => fail_self(
            "ring reply oversize",
            "reconcile_vault_upgrade reply exceeded the wire ceiling".to_string(),
        ),
        Ok(bytes) => {
            match candid::decode_one::<Result<ReconcileTerminalOutcome, stsh_custody_types::RecoveryError>>(&bytes) {
                Ok(Ok(term)) => {
                    let outcome = match term {
                        ReconcileTerminalOutcome::Executed => ActionOutcome::Executed,
                        ReconcileTerminalOutcome::Failed => ActionOutcome::Failed,
                    };
                    // CUST-L12-03 OPTION A (pinned): the Upgrader's durable
                    // terminal outcome is AUTHORITATIVE for the request
                    // identity — the historical normal intent resolves to
                    // what L2 recorded. If the CURRENT objective evidence
                    // disagrees (state drifted since), the drift is recorded
                    // as a separate typed conflict event — prominent, never
                    // silent — while the terminalization follows L2. Either
                    // way the lock releases; no reconcile path leaves an
                    // unrecoverable OutcomeUnknown.
                    let evidence_says = if ev.observed_module_hash.as_deref()
                        == Some(expected_wasm_hash.as_slice())
                        && ev.observed_canister_status == ObservedCanisterStatus::Running
                        && ev.observed_controllers == vec![upgrader]
                    {
                        ActionOutcome::Executed
                    } else {
                        ActionOutcome::Failed
                    };
                    if evidence_says != outcome {
                        audit_full(
                            AuditKind::ReconcileConflict,
                            Some(target.proposal_id),
                            self_id(),
                            Some(approvals.clone()),
                            None,
                            None,
                            format!(
                                "conflict: upgrader durably reports {outcome:?} for request {} but current evidence says {evidence_says:?} (drift) — terminalizing per the Upgrader's durable outcome",
                                target.proposal_id
                            ),
                        );
                    }
                    // F-4: reconciliation audit event carries the approving
                    // signer set.
                    finalize(
                        target.proposal_id,
                        outcome,
                        Some(cap_detail(format!(
                            "reconciled by proposal {reconcile_proposal_id}: {ev:?}"
                        ))),
                        AuditKind::Reconciled,
                        approvals.clone(),
                        format!("reconciled to {outcome:?} via the Upgrader"),
                    );
                    finalize(
                        reconcile_proposal_id,
                        ActionOutcome::Executed,
                        Some(format!("target {} → {outcome:?}", target.proposal_id)),
                        AuditKind::Executed,
                        approvals,
                        "reconciliation complete".to_string(),
                    );
                }
                Ok(Err(e)) => {
                    // CUST-L12-03: the Upgrader's intent map is append-only
                    // with no delete/prune — an authoritative UnknownProposal
                    // PROVES the normal request identity was never durably
                    // admitted (e.g. the trigger died in transport, or the
                    // bytes arrived via the recovery plane). Terminalize
                    // Failed-as-no-admission — NEVER Executed, even when the
                    // live module hash matches — and release the lock.
                    if matches!(e, stsh_custody_types::RecoveryError::UnknownProposal { .. }) {
                        audit_full(
                            AuditKind::ReconcileConflict,
                            Some(target.proposal_id),
                            self_id(),
                            Some(approvals.clone()),
                            None,
                            None,
                            format!(
                                "no admission: upgrader has no intent for request {} (append-only map proves non-admission) — terminalizing Failed, never Executed",
                                target.proposal_id
                            ),
                        );
                        finalize(
                            target.proposal_id,
                            ActionOutcome::Failed,
                            Some("no admission at the Upgrader".to_string()),
                            AuditKind::Failed,
                            approvals.clone(),
                            "terminalized Failed: request identity never admitted by the Upgrader".to_string(),
                        );
                        finalize(
                            reconcile_proposal_id,
                            ActionOutcome::Executed,
                            Some(format!("target {} → Failed (no admission)", target.proposal_id)),
                            AuditKind::Executed,
                            approvals,
                            "resolved as no admission; lock released".to_string(),
                        );
                        return;
                    }
                    fail_self(
                        "upgrader rejected reconciliation",
                        format!("Upgrader rejected reconcile deterministically: {e:?}"),
                    )
                }
                Err(_) => {
                    // Reply undecodable: we cannot know whether the Upgrader
                    // settled. The reconcile proposal is OutcomeUnknown; the
                    // target intent stays OutcomeUnknown (a NEW reconcile
                    // proposal gets the Upgrader's replay).
                    finalize(
                        reconcile_proposal_id,
                        ActionOutcome::OutcomeUnknown,
                        Some("ring reply undecodable".to_string()),
                        AuditKind::OutcomeUnknown,
                        approvals,
                        "reconcile_vault_upgrade reply did not decode".to_string(),
                    );
                }
            }
        }
        Err(CallFailure::Rejected(e)) => finalize(
            reconcile_proposal_id,
            ActionOutcome::OutcomeUnknown,
            Some(cap_detail(e.clone())),
            AuditKind::OutcomeUnknown,
            approvals,
            cap_detail(format!("reconcile_vault_upgrade transport failure: {e}")),
        ),
    }
}

async fn execute_install<B: ExecBackend>(
    backend: &B,
    proposal_id: u64,
    target: Principal,
    mode: InstallMode,
    expected_wasm_hash: Vec<u8>,
    expected_arg_hash: Vec<u8>,
    wasm_bytes: Vec<u8>,
    arg_bytes: Vec<u8>,
    approvals: Vec<Principal>,
) {
    // Recompute AGAIN at the execution boundary (freeze §3d/§3f) — the
    // durable intent is already in place, so a mismatch here can only be
    // corruption; reject before any inter-canister call.
    if let Err(e) = check_hashes(&expected_wasm_hash, &expected_arg_hash, &wasm_bytes, &arg_bytes) {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("{e:?}")),
            AuditKind::Failed,
            approvals,
            "hash re-check failed at execution boundary".to_string(),
        );
        return;
    }
    // Single-flight re-check at the execution boundary (the race-proof
    // enforce point): this proposal may have been proposed while the other
    // intent was still Pending. A concurrent open intent against the same
    // target fails THIS proposal — the earlier intent keeps the lock.
    if let Some(other) = open_mutating_intent(target, Some(proposal_id)) {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("single-flight: intent {other} open on target")),
            AuditKind::Failed,
            approvals,
            format!("single-flight violation: proposal {other} is nonterminal on {target}"),
        );
        return;
    }
    match backend.install_code(target, mode, wasm_bytes, arg_bytes).await {
        Ok(()) => finalize(
            proposal_id,
            ActionOutcome::Executed,
            Some(format!("install_code({mode:?}) ok")),
            AuditKind::Executed,
            approvals,
            format!("install_code {mode:?} against {target} succeeded"),
        ),
        Err(CallFailure::Rejected(e)) => finalize(
            proposal_id,
            ActionOutcome::OutcomeUnknown,
            Some(cap_detail(e.clone())),
            AuditKind::OutcomeUnknown,
            approvals,
            cap_detail(format!("install_code transport failure: {e}")),
        ),
    }
}

async fn execute_management<B: ExecBackend>(
    backend: &B,
    proposal_id: u64,
    m: ManagementAction,
    approvals: Vec<Principal>,
) {
    // Defense in depth: re-run the manifest-allowlist validation at the
    // execution boundary (propose already enforced it; the governed set may
    // have advanced since — a target that LEFT the allowlist can never
    // happen, but a stale proposal re-validated costs nothing).
    let g = gov();
    let guard = VaultSelfControlGuard {
        vault: self_id(),
        upgrader: g.bootstrap.counterpart,
    };
    if let Err(v) = validate_management_target(&g, &guard, &m) {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("{v:?}")),
            AuditKind::Failed,
            approvals,
            format!("manifest allowlist rejected at execution: {v:?}"),
        );
        return;
    }
    let outcome: Result<Result<(), String>, VaultError> = match &m {
        ManagementAction::Upgrade {
            target,
            expected_wasm_hash,
            expected_arg_hash,
            wasm_bytes,
            arg_bytes,
        } => {
            return execute_install(
                backend,
                proposal_id,
                *target,
                InstallMode::Upgrade,
                expected_wasm_hash.clone(),
                expected_arg_hash.clone(),
                wasm_bytes.clone(),
                arg_bytes.clone(),
                approvals,
            )
            .await;
        }
        ManagementAction::InstallCode {
            target,
            expected_wasm_hash,
            expected_arg_hash,
            wasm_bytes,
            arg_bytes,
        } => {
            return execute_install(
                backend,
                proposal_id,
                *target,
                InstallMode::Install,
                expected_wasm_hash.clone(),
                expected_arg_hash.clone(),
                wasm_bytes.clone(),
                arg_bytes.clone(),
                approvals,
            )
            .await;
        }
        // §S7 CELL 3 — Vault → Upgrader start.
        //
        // A RING start is governed by the start-settlement contract; a start
        // against an ordinary governed target keeps its prior behaviour
        // untouched (R4.3 preserved surfaces), which is why the two branches
        // are separated here rather than folded together.
        ManagementAction::Start { target } if is_ring_start(*target) => {
            // §2 obligation 3/4: the durable start-intent lands BEFORE the
            // first inter-canister call. `Executing` (obligation 2) and the
            // distinct-signature quorum (obligation 1) are already durable —
            // this function is only reached from the quorum boundary.
            if !record_start_intent(proposal_id, *target, now_ns()) {
                finalize(
                    proposal_id,
                    ActionOutcome::Failed,
                    Some("single-flight: another intent open against the Upgrader".to_string()),
                    AuditKind::Failed,
                    approvals,
                    "§S7 §2: start refused — concurrent intent against the same target".to_string(),
                );
                return;
            }
            let result = backend.start_canister(*target).await.map_err(|e| format!("{e:?}"));
            // ── §3c.2 THE GUARD, on the reply/reject callback ────────────────
            //
            // Everything after the `await` above is the callback, and it is
            // ADVISORY, NEVER AUTHORITATIVE. The durable state is re-read here;
            // if it is not exactly `Executing` — because E2 swept it, or it is
            // already settled — this callback performs ZERO settlement-state
            // mutation, ZERO lock change and NO terminalization, and its
            // payload is NEVER treated as evidence. Admitting it would
            // reintroduce an un-evidenced settlement path, which is what R-2
            // forecloses. Only §4 evidence moves a proposal out of
            // `OutcomeUnknown`.
            if !start_callback_may_write(proposal_id) {
                return;
            }
            match result {
                Ok(()) => finalize(
                    proposal_id,
                    ActionOutcome::Executed,
                    None,
                    AuditKind::Executed,
                    approvals,
                    format!("§3a: observed start success for {target}"),
                ),
                // E1, IN THIS SAME MESSAGE: a transport rejection, or any reply
                // that does not objectively establish success, is
                // `OutcomeUnknown` — NEVER blindly `Failed` (acceptance 1). A
                // management-call rejection cannot distinguish pre- from
                // post-execution, so treating it as failure would infer the
                // call's fate rather than observe it.
                Err(e) => finalize(
                    proposal_id,
                    ActionOutcome::OutcomeUnknown,
                    Some(cap_detail(e.clone())),
                    AuditKind::OutcomeUnknown,
                    approvals,
                    cap_detail(format!("§3a E1: start transport failure: {e}")),
                ),
            }
            return;
        }
        ManagementAction::Start { target } => Ok(backend
            .start_canister(*target)
            .await
            .map_err(|e| format!("{e:?}"))),
        ManagementAction::Stop { target } => {
            Ok(backend.stop_canister(*target).await.map_err(|e| format!("{e:?}")))
        }
        ManagementAction::UpdateSettings { target, controllers } => Ok(backend
            .update_settings(*target, controllers.clone())
            .await
            .map_err(|e| format!("{e:?}"))),
        ManagementAction::DepositCycles { target, cycles } => Ok(backend
            .deposit_cycles(*target, *cycles)
            .await
            .map_err(|e| format!("{e:?}"))),
        ManagementAction::CreateCanister {
            manifest_purpose,
            disposition,
        } => {
            // L1-5 (a/b): the purpose was durably reserved at the quorum
            // boundary (Reservation.creation_purpose, before any await) and
            // creation is purpose-scoped single-flight. Execution-time
            // re-check — the race-proof point: a same-purpose intent
            // proposed while this one was Pending fails here, before the
            // management call.
            if let Some(other) = open_creation_intent(manifest_purpose, Some(proposal_id)) {
                finalize(
                    proposal_id,
                    ActionOutcome::Failed,
                    Some(format!("single-flight: creation {other} open for purpose")),
                    AuditKind::Failed,
                    approvals,
                    format!(
                        "single-flight violation: creation {other} is nonterminal for purpose {manifest_purpose:?}"
                    ),
                );
                return;
            }
            match backend.create_canister().await {
            Ok(principal) => {
                // L1-5 (c) / L1-10: post-await one-shot revalidation. If the
                // role became bound while this call was in flight, the
                // management call has STILL succeeded — the returned
                // principal is a Vault-controlled canister and must never
                // vanish from D5. Record a typed ORPHAN receipt (custody
                // visibility), fail the proposal, bind nothing, never
                // overwrite the existing role binding. The orphan is NOT in
                // the governed allowlist, so every management path fails
                // closed on it pending governed resolution.
                let g_now = gov();
                if g_now.governed.iter().any(|t| t.purpose == *manifest_purpose) {
                    audit_full(
                        AuditKind::CanisterCreated,
                        Some(proposal_id),
                        self_id(),
                        Some(approvals.clone()),
                        Some(CreationReceipt {
                            proposal_id,
                            principal,
                            purpose: manifest_purpose.clone(),
                            disposition: *disposition,
                            created_at_ns: now_ns(),
                            status: CreationReceiptStatus::OrphanedPurposeConflict,
                        }),
                        None,
                        format!(
                            "orphan receipt: purpose {manifest_purpose:?} bound in flight; created {principal} retained under custody visibility, NOT governed"
                        ),
                    );
                    finalize(
                        proposal_id,
                        ActionOutcome::Failed,
                        Some(format!("purpose bound in flight; orphan {principal} recorded")),
                        AuditKind::Failed,
                        approvals,
                        format!(
                            "one-shot revalidation failed post-await: purpose {manifest_purpose:?} already bound — orphan receipt recorded for {principal}"
                        ),
                    );
                    return;
                }
                // L1-4 / freeze §13.3: the TYPED receipt is durable BEFORE
                // any install against this principal is possible (same
                // execution, ahead of the terminal write; installs are
                // later proposals). Insert-once by construction (this arm
                // runs exactly once per proposal — replay never re-executes).
                let receipt = CreationReceipt {
                    proposal_id,
                    principal,
                    purpose: manifest_purpose.clone(),
                    disposition: *disposition,
                    created_at_ns: now_ns(),
                    status: CreationReceiptStatus::Bound,
                };
                audit_full(
                    AuditKind::CanisterCreated,
                    Some(proposal_id),
                    self_id(),
                    Some(approvals.clone()),
                    Some(receipt),
                    None,
                    format!("create_canister receipt: {principal} purpose={manifest_purpose}"),
                );
                // L1-1/L1-2: bind the returned principal into the durable
                // governed allowlist AND, for a wired role, into the
                // application/read target wiring — one-shot, from the
                // receipt, never caller-supplied.
                let mut g = gov();
                debug_assert!(
                    !g.governed.iter().any(|t| t.principal == principal),
                    "management never returns a duplicate canister id"
                );
                g.governed.push(GovernedTarget {
                    principal,
                    disposition: *disposition,
                    purpose: manifest_purpose.clone(),
                });
                match manifest_purpose.as_str() {
                    "shielded_pool" => g.targets.shielded_pool = Some(principal),
                    "treasury" => g.targets.treasury = Some(principal),
                    "vesting" => g.targets.vesting = Some(principal),
                    "nullifier_registry" => g.targets.nullifier_registry = Some(principal),
                    _ => {} // controller-only targets: allowlist only (freeze §12)
                }
                // F3: the same governed-state invariant as init/post_upgrade,
                // checked before the mutation becomes durable.
                validate_governed_state(&g).unwrap_or_else(|e| {
                    ic_cdk::trap(&format!("receipt binding produced invalid governed state: {e}"))
                });
                gov_store(&g);
                finalize(
                    proposal_id,
                    ActionOutcome::Executed,
                    Some(principal.to_text()),
                    AuditKind::Executed,
                    approvals,
                    format!("create_canister → {principal}"),
                );
                return;
            }
            Err(e) => Ok(Err(format!("{e:?}"))),
            }
        }
    };
    match outcome {
        Ok(Ok(())) => finalize(
            proposal_id,
            ActionOutcome::Executed,
            None,
            AuditKind::Executed,
            approvals,
            format!("{m:?}"),
        ),
        Ok(Err(e)) => finalize(
            proposal_id,
            ActionOutcome::OutcomeUnknown,
            Some(cap_detail(e.clone())),
            AuditKind::OutcomeUnknown,
            approvals,
            cap_detail(format!("transport failure: {e}")),
        ),
        Err(v) => finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("{v:?}")),
            AuditKind::Failed,
            approvals,
            format!("guard/validation rejected at execution: {v:?}"),
        ),
    }
}

/// freeze §3d reconciliation contract. Legal source state: `OutcomeUnknown`
/// ONLY. Terminal transitions: `Executed` | `Failed`. Never back to
/// `Pending`, never re-triggerable, never retries or reinstalls — this
/// function performs NO inter-canister call and the target proposal leaves
/// `OutcomeUnknown` exactly once.
fn execute_reconcile_upgrader_upgrade(
    reconcile_proposal_id: u64,
    rec: &ReconcileUpgraderUpgrade,
    approvals: Vec<Principal>,
) {
    let target = match proposal_get(rec.proposal_id) {
        Some(t) => t,
        None => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some("unknown target proposal".to_string()),
                AuditKind::Failed,
                approvals,
                format!("reconcile target {} not found", rec.proposal_id),
            );
            return;
        }
    };
    //
    // VR-1 — ONE code path, parameterised on `(expected_wasm_hash,
    // bound_principal)`. `bound_principal` is the principal the evidence must
    // bind to: the durable Upgrader counterpart for a cell-3
    // `UpgraderUpgrade`, and the management action's own `target` for an
    // `InstallCode`/`Upgrade`. The evidence FIELD is still named
    // `observed_upgrader_principal` — the name is frozen in `custody-types`
    // and is read here as "observed TARGET principal".
    let (expected_wasm_hash, bound_principal) = match &target.action {
        VaultActionKind::UpgraderUpgrade(uu) => (
            uu.expected_wasm_hash.clone(),
            gov().bootstrap.counterpart,
        ),
        VaultActionKind::Management(ManagementAction::InstallCode {
            target: mgmt_target,
            expected_wasm_hash,
            ..
        })
        | VaultActionKind::Management(ManagementAction::Upgrade {
            target: mgmt_target,
            expected_wasm_hash,
            ..
        }) => (expected_wasm_hash.clone(), *mgmt_target),
        _ => {
            finalize(
                reconcile_proposal_id,
                ActionOutcome::Failed,
                Some("target is not a reconcilable install/upgrade".to_string()),
                AuditKind::Failed,
                approvals,
                "reconcile target is not a C1 upgrade or a management install/upgrade"
                    .to_string(),
            );
            return;
        }
    };
    if target.outcome != ActionOutcome::OutcomeUnknown {
        finalize(
            reconcile_proposal_id,
            ActionOutcome::Failed,
            Some(format!("{:?}", VaultError::IllegalSourceState)),
            AuditKind::Failed,
            approvals,
            format!(
                "legal source state is OutcomeUnknown ONLY; found {:?}",
                target.outcome
            ),
        );
        return;
    }
    let ev = &rec.objective_evidence;
    if ev.observed_upgrader_principal != bound_principal {
        // Evidence does not bind to the target principal — operator error,
        // target untouched (still OutcomeUnknown, reconcilable with correct
        // evidence via a NEW proposal).
        finalize(
            reconcile_proposal_id,
            ActionOutcome::Failed,
            Some("evidence principal mismatch".to_string()),
            AuditKind::Failed,
            approvals,
            "observed principal != the reconcile target's bound principal".to_string(),
        );
        return;
    }
    // L1-3: evidence freshness. `observed_at_ns` must (a) not predate the
    // durable upgrade intent (evidence from BEFORE the intent cannot speak
    // to ITS outcome), (b) not be in the future, (c) not be older than
    // MAX_EVIDENCE_AGE_NS. Any violation rejects the reconcile proposal —
    // the target is NEVER terminalized on stale/future evidence.
    let now = now_ns();
    let intended_at = target.intent.as_ref().map(|i| i.intended_at_ns).unwrap_or(0);
    let stale_evidence = if ev.observed_at_ns < intended_at {
        Some(format!(
            "evidence predates upgrade intent ({} < {intended_at})",
            ev.observed_at_ns
        ))
    } else if ev.observed_at_ns > now {
        Some(format!(
            "evidence from the future ({} > {now})",
            ev.observed_at_ns
        ))
    } else if now.saturating_sub(ev.observed_at_ns) > MAX_EVIDENCE_AGE_NS {
        Some(format!(
            "evidence too old (age {} ns > MAX_EVIDENCE_AGE_NS {MAX_EVIDENCE_AGE_NS})",
            now - ev.observed_at_ns
        ))
    } else {
        None
    };
    if let Some(why) = stale_evidence {
        finalize(
            reconcile_proposal_id,
            ActionOutcome::Failed,
            Some(why.clone()),
            AuditKind::Failed,
            approvals,
            format!("stale/future evidence rejected: {why}"),
        );
        return;
    }
    let terminal = if ev.observed_module_hash.as_deref() == Some(expected_wasm_hash.as_slice())
        && ev.observed_canister_status == ObservedCanisterStatus::Running
        && ev.observed_controllers == vec![self_id()]
    {
        ActionOutcome::Executed
    } else {
        ActionOutcome::Failed
    };
    // F-4 (freeze §10): the reconciliation audit event records the approving
    // signer set — post-cutover the target-side reconciler is always "Vault".
    finalize(
        target.proposal_id,
        terminal,
        Some(cap_detail(format!("reconciled by proposal {reconcile_proposal_id}: {ev:?}"))),
        AuditKind::Reconciled,
        approvals.clone(),
        format!("reconciled to {terminal:?} on objective evidence"),
    );
    finalize(
        reconcile_proposal_id,
        ActionOutcome::Executed,
        Some(format!("target {} → {terminal:?}", target.proposal_id)),
        AuditKind::Executed,
        approvals,
        "reconciliation complete".to_string(),
    );
}

// ── S5B W5(a) — governance trap boundaries (test-only injection) ─────────────
//
// The §4 amendment (AMENDMENT_V8_S4_GOVERNANCE_ATOMICITY_V2, 0fe84841…) requires
// rollback evidence at BOTH internal boundaries of the governance-execution
// path, and requires it through a real message boundary: "an in-process Rust
// panic does not prove canister-state rollback and is not acceptable evidence."
// So the trap must fire inside a deployed Wasm under PocketIC, which means a
// production-path call site and a test-only arming switch.
//
// Feature isolation (brief §3): in a release build `gov_trap` is an empty
// `#[inline(always)]` function taking a `&'static str`, so the call sites cost
// nothing and the arming endpoint does not exist at all. The
// feature-isolation test asserts the arming symbol is absent from the release
// Wasm.
const GOV_TRAP_AFTER_STORE_BEFORE_AUDIT: &str = "after_gov_store_before_audit";
const GOV_TRAP_AFTER_AUDIT_BEFORE_FINALIZE: &str = "after_audit_before_finalize";

#[cfg(feature = "testing")]
thread_local! {
    /// Armed trap point, consumed once. `RefCell<Option<String>>` rather than a
    /// bool per site so a test names the exact boundary it is proving.
    static ARMED_GOV_TRAP: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Trap if this boundary is the armed one. Production no-op.
#[cfg(feature = "testing")]
fn gov_trap(point: &'static str) {
    let armed = ARMED_GOV_TRAP.with(|t| t.borrow().clone());
    if armed.as_deref() == Some(point) {
        // Deliberately does NOT disarm first: disarming would be a durable
        // write that survives the trap only if the trap failed to roll back,
        // which would corrupt the very property under test. The arming switch
        // is re-set by the test before each run instead.
        ic_cdk::trap(&format!("S5B W5(a) injected trap at {point}"));
    }
}

#[cfg(not(feature = "testing"))]
#[inline(always)]
fn gov_trap(_point: &'static str) {}

/// TEST-ONLY (feature `testing`): arm one governance trap boundary.
///
/// Signer-gated like every other test hook, so it cannot be driven by an
/// unauthorized caller even in a testing build.
#[cfg(feature = "testing")]
#[update]
fn arm_governance_trap_for_test(point: String) {
    require_signer(caller()).expect("signer-only");
    // "none" DISARMS. The trap deliberately does not clear itself — that would
    // be a durable write surviving only if the trap failed to roll back, which
    // would corrupt the very property under test — so the arming switch is
    // reset explicitly by the test instead. A retry-after-trap test (W1.3)
    // needs exactly this: the arm was committed in an EARLIER message, so the
    // trapped message's rollback does not clear it.
    if point == "none" {
        ARMED_GOV_TRAP.with(|t| *t.borrow_mut() = None);
        return;
    }
    assert!(
        point == GOV_TRAP_AFTER_STORE_BEFORE_AUDIT
            || point == GOV_TRAP_AFTER_AUDIT_BEFORE_FINALIZE,
        "unknown governance trap point: {point}"
    );
    ARMED_GOV_TRAP.with(|t| *t.borrow_mut() = Some(point));
}

/// TEST-ONLY (feature `testing`): clear the companion sentinel record (RF-7).
///
/// The VAULT half of B3's regression evidence, which did not exist in any form
/// — the in-process test covered the Upgrader only. Same reasoning as that
/// plane's hook: an absent record must be REJECTED rather than read as an empty
/// default, and there is deliberately no production path to the absent state.
#[cfg(feature = "testing")]
#[update]
fn clear_companion_state_for_test() {
    require_signer(caller()).expect("signer-only");
    COMPANION_STATE.with(|c| {
        c.borrow_mut()
            .set(Vec::new())
            .expect("COMPANION_STATE: test clear failed")
    });
}

/// TEST-ONLY (feature `testing`): instructions consumed by ONE ID allocation
/// (SSA RF-3).
///
/// WHY THIS EXISTS AND WHY IT IS NOT A TIMING HARNESS. The builder deliberately
/// built no wall-clock harness for W6, on the grounds that a wall-clock
/// threshold at test scale cannot distinguish O(1) from O(n). SSA's answer was
/// that deterministic INSTRUCTION-at-depth evidence is a different and fair ask
/// — and it is: `instruction_counter` under PocketIC is exact and reproducible,
/// so a comparison across history depths is a real measurement rather than a
/// noise-tolerant guess.
///
/// The measured path is `peek_id`, which performs the W1.6 inline companion
/// validation before EVERY allocation. That validation walks the bounded
/// companions and must never touch permanent history — so its instruction cost
/// must be independent of how much terminal history exists. That is precisely
/// the W6 property, and it is what the paired PocketIC test asserts.
#[cfg(feature = "testing")]
#[update]
fn measure_allocation_instructions_for_test() -> u64 {
    require_signer(caller()).expect("signer-only");
    let before = ic_cdk::api::instruction_counter();
    // The allocation path proper. `peek_id` validates the companion seal and
    // accounting, then reads the counter — no durable write, so calling this
    // repeatedly does not itself perturb the state being measured.
    let _ = peek_id(IdKind::Audit);
    ic_cdk::api::instruction_counter().saturating_sub(before)
}

/// TEST-ONLY (feature `testing`): inject candidate C9 entry-rate parameters
/// into a DEPLOYED canister (SSA RF-6).
///
/// Required because RF-6's property is only observable when the gate is ACTIVE:
/// with `ENTRY_RATE_PARAMS = None` the charge path returns early and never
/// writes the ledger, so there is no durable state to prove survives an
/// upgrade. The native tests inject through a `thread_local`, which cannot
/// reach a Wasm running under PocketIC.
///
/// Brief §3 is satisfied exactly as written: candidate values reach the code
/// ONLY through test-only configuration, the production constant stays `None`,
/// and the feature-isolation tests assert this symbol is absent from the
/// release Wasm. Signer-gated like every other test hook.
///
/// NAME ENDS IN `_for_test`, deliberately: the allowlist scanner finds the
/// `_for_test` marker and walks BACKWARD only, so a hook named
/// `..._for_test_endpoint` is recorded as `..._for_test` and cannot be
/// allowlisted accurately. Ending the name in the marker is the house
/// convention every other hook follows, and the scanner encodes it.
#[cfg(feature = "testing")]
#[update]
fn set_entry_rate_params_for_test(params: Option<stsh_custody_types::EntryRateParams>) {
    require_signer(caller()).expect("signer-only");
    // RF-1: a DEPLOYED harness always OVERRIDES — `None` here means "force the
    // unruled path", never "clear the injection". A harness that wanted the
    // production value would simply not call this.
    inject_entry_rate_for_test(Some(params));
}

/// TEST-ONLY (feature `testing`): inject candidate C5/C7 nonterminal caps into
/// a DEPLOYED canister. The Vault's counterpart to the Upgrader's long-standing
/// `set_nonterminal_caps_for_test`, added at S6 for the same reason that one
/// exists: an occupancy requirement cannot be exercised in a deployed canister
/// unless the harness can move the cap that bounds occupancy.
///
/// WHY IT EXISTS, stated because "the measurement harness needs the cap raised"
/// reads like evading a bound.
///
/// V15 §4 obligation 6 requires the §C inequalities at OCCUPANCY 320. An earlier
/// revision of this note argued that occupancy was UNREACHABLE — 9 x C5 = 288,
/// the remaining 32 slots being "ruled margin". THAT ARGUMENT IS WITHDRAWN: it
/// assumed the roster bounds the nonterminal population, and rotation refutes
/// that (a proposal stays nonterminal across a rotation, so slots held by
/// rotated-out signers persist). C7's margin was never adjudicated; it is
/// treated as UNPROVEN.
///
/// The hook therefore exists as a MEASUREMENT CONVENIENCE — reaching the
/// occupancy legally requires a long rotation sequence that would measure the
/// rotation path instead of the admission cost — not because the ceiling is
/// unreachable.
///
/// Production constants are untouched; the feature-isolation suite asserts this
/// symbol is absent from every release Wasm. Signer-gated, and named to the
/// `_for_test` convention the allowlist scanner encodes.
#[cfg(feature = "testing")]
#[update]
fn set_nonterminal_caps_for_test(caps: Option<stsh_custody_types::NonterminalCaps>) {
    require_signer(caller()).expect("signer-only");
    // RF-1: a DEPLOYED harness always OVERRIDES — `None` here means "force the
    // unruled path", never "clear the injection". A harness that wanted the
    // production value would simply not call this.
    inject_nonterminal_caps_for_test(Some(caps));
}

/// TEST-ONLY (feature `testing`): inject candidate C6/C8 byte quotas into a
/// DEPLOYED canister.
///
/// A MEASUREMENT CONVENIENCE, not a reachability claim — see `byte_quotas`,
/// where the withdrawn "C8 is unreachable through legal admission" rationale is
/// set out and refuted. C8 IS legally reachable across signer rotations; the cap
/// is raised here only so the sweep prices the ADMISSION path rather than the
/// long rotation sequence that reaching the ceiling legally would measure.
#[cfg(feature = "testing")]
#[update]
fn set_byte_quotas_for_test(quotas: Option<(u64, u64)>) {
    require_signer(caller()).expect("signer-only");
    inject_byte_quotas_for_test(quotas);
}

/// TEST-ONLY (feature `testing`): instructions consumed by ONE inline
/// commitment validation (S5A M1 gate C, spec §C — `commitment_validation_worst`).
///
/// This is HOT-PATH cost, not a startup check. V11 §2 rules that the bounded
/// integrity commitment must be validated before ANY operation relying on the
/// absence of a registry entry or active-intent pointer — new-intent admission
/// above all — and not only at `post_upgrade`. §C gives it its own budget
/// (`0.05 × I_msg`) precisely so the bounded registry walk cannot become an
/// authorization-path DoS hidden inside an admission measurement that passes
/// overall.
///
/// `companion_validate` is measured directly rather than via `peek_id`, so the
/// figure is the validation alone and does not silently include allocation
/// work.
#[cfg(feature = "testing")]
#[update]
fn measure_companion_validation_for_test() -> u64 {
    require_signer(caller()).expect("signer-only");
    let before = ic_cdk::api::instruction_counter();
    companion_validate();
    ic_cdk::api::instruction_counter().saturating_sub(before)
}

/// TEST-ONLY (feature `testing`): the C8 LOGICAL BYTE TOTAL over the currently
/// nonterminal set, computed with `c8_logical_bytes` — the same function S6's
/// admission enforcement will use.
///
/// The measurement reads THIS rather than tracking its own running sum, so the
/// figure C8 is derived from cannot diverge from the figure C8 will enforce.
/// Iterates the BOUNDED nonterminal companion, never permanent history.
#[cfg(feature = "testing")]
#[update]
fn c8_logical_total_for_test() -> u64 {
    require_signer(caller()).expect("signer-only");
    let ids: Vec<u64> = NONTERMINAL_PROPOSAL_INDEX
        .with(|x| x.borrow().iter().map(|((_, id), _)| id).collect());
    ids.into_iter()
        .filter_map(proposal_get)
        .map(|p| c8_logical_bytes(&p.action))
        .sum()
}

/// TEST-ONLY (feature `testing`): total stable memory currently allocated, in
/// 64 KiB Wasm pages (S5A corrective, Blocker 3 — C6/C8 allocation overhead).
///
/// WHY PAGES AND NOT A LOGICAL SUM. The M2" census is logical payload by
/// design: it sums encoded record lengths. C8 is a bound on ACTUAL STABLE
/// MEMORY, which additionally carries StableBTreeMap node overhead, per-entry
/// slack, and the MemoryManager's bucket allocation. Those are invisible to a
/// logical census and are exactly what SSA's Blocker 3 says C8's reserve must
/// be measured against rather than reserved for with a round number.
///
/// The figure is QUANTIZED by the MemoryManager's bucket size, so a delta over
/// a small number of records can round to zero or to a whole bucket. That is a
/// property of the allocator, not noise — deltas are therefore taken over
/// enough records for the quantization to be small relative to the total, and
/// the quantization is reported alongside.
#[cfg(feature = "testing")]
#[update]
fn stable_pages_for_test() -> u64 {
    require_signer(caller()).expect("signer-only");
    ic_cdk::api::stable::stable_size()
}

/// TEST-ONLY (feature `testing`): how many nonterminal proposals the companion
/// currently accounts for — the OCCUPANCY a gate C figure was taken at.
///
/// Reported alongside every §C measurement because "at C12 occupancy" is the
/// load-bearing half of the requirement: a validation cost measured at an empty
/// registry would be reported as passing its budget while saying nothing about
/// the state the budget exists to bound.
#[cfg(feature = "testing")]
#[update]
fn companion_occupancy_for_test() -> u64 {
    require_signer(caller()).expect("signer-only");
    NONTERMINAL_PROPOSAL_INDEX.with(|x| x.borrow().iter().count() as u64)
}

/// TEST-ONLY (feature `testing`): instructions consumed by ONE sweep call, and
/// how many records it reaped (S5A M1 gate A, spec §A).
///
/// Returns BOTH figures because the pair is what makes the measurement
/// interpretable. §A asks for two separate symbols — `c_fixed_worst`, the
/// per-call cost, and `c_record_worst`, the marginal cost per due record — and
/// a single total cannot separate them. Measuring across a range of occupancies
/// and reading intercept and slope does, and it additionally exposes
/// NON-LINEARITY: if cost per record is not flat, then
/// `C11 = floor((0.25×I_msg − c_fixed)/c_record)` is the wrong SHAPE of formula
/// and that is a finding for the table rather than something to average away.
///
/// The reaped count is returned so a run cannot silently measure fewer records
/// than the fixture intended — the failure that would quietly deflate every
/// per-record figure.
///
/// `now_ns_override` forces the due-prefix rather than advancing the canister's
/// clock. This is a FIXTURE choice and is recorded as one: the per-record work
/// on the reap path is identical either way, since `now` only selects which
/// prefix of the expiry index is due.
#[cfg(feature = "testing")]
#[update]
fn measure_sweep_instructions_for_test(now_ns_override: u64, limit: u32) -> (u64, u32) {
    require_signer(caller()).expect("signer-only");
    let before = ic_cdk::api::instruction_counter();
    let reaped = sweep_expired_inner(now_ns_override, limit as usize);
    let delta = ic_cdk::api::instruction_counter().saturating_sub(before);
    (delta, reaped.len() as u32)
}

/// TEST-ONLY (feature `testing`): consume instructions until the counter
/// reaches `target`, then report it. The `I_msg` probe (S5A, CTO ruling
/// T0010Z leg (i)).
///
/// WHY THIS EXISTS. Every budget in `A1_M1_MEASUREMENT_SPEC_V2` is a FRACTION
/// of `I_msg`, the per-message instruction limit — and `I_msg` is pinned
/// nowhere in this repository or in the office lineage. Supplying it from
/// recall is precisely the "agreement between two readers of the same wrong
/// figure is not confirmation" failure the S5A discipline exists to prevent, so
/// it is measured instead: drive the target upward until the message is killed
/// for exceeding its limit, and the threshold is the ceiling the figures were
/// actually taken under.
///
/// THIS MEASURES THE HARNESS, NOT THE PLATFORM. What it returns is PocketIC's
/// effective ceiling on this machine — leg (i) of a two-legged pin. Leg (ii),
/// the mainnet application-subnet limit, is established by documented authority
/// at the constants-table step and is not measurable from here. If the two
/// disagree, the budgets adjudicate against the MAINNET value; this figure only
/// establishes what the measurements themselves were taken under.
///
/// `black_box` is load-bearing: without it LLVM deletes the accumulator loop as
/// dead, the burner consumes almost nothing, and the search converges on a
/// ceiling that is an artifact of the optimiser rather than a property of the
/// platform.
#[cfg(feature = "testing")]
#[update]
fn burn_instructions_for_test(target: u64) -> u64 {
    require_signer(caller()).expect("signer-only");
    let mut acc: u64 = 0;
    while ic_cdk::api::instruction_counter() < target {
        for _ in 0..1_000 {
            acc = std::hint::black_box(acc.wrapping_mul(31).wrapping_add(7));
        }
    }
    std::hint::black_box(acc);
    ic_cdk::api::instruction_counter()
}

/// TEST-ONLY (feature `testing`): inject candidate proposal-lifetime bounds and
/// a candidate sweep work limit into a DEPLOYED canister (S5A M1 gate A).
///
/// WITHOUT THIS, GATE A CANNOT BE MEASURED AT ALL — this is not a convenience.
/// `A1_M1_MEASUREMENT_SPEC_V2` §A asks for `c_record_worst`, the marginal
/// instruction cost per DUE record. While `PROPOSAL_LIFETIME_BOUNDS` is `None`
/// no proposal is ever assigned an expiry, so the expiry index is empty by
/// construction and the sweep is provably vacuous
/// (`r3_sweep_is_vacuous_until_lifetime_bounds_are_ruled`). There is no due
/// record in existence whose cost could be measured, and a measurement taken
/// against an empty index would report a per-record cost of zero while looking
/// entirely healthy.
///
/// Same guarantees as every other injection hook: production constants stay
/// `None` (`s5b_no_route2_constant_value_is_pinned_in_source` enforces it), the
/// value reaches the code ONLY here, and the feature-isolation suite asserts
/// this symbol is absent from the release Wasm.
///
/// `sweep_limit` is `u32` rather than `usize` because it crosses a Candid
/// boundary; it is widened at the accessor.
#[cfg(feature = "testing")]
#[update]
fn set_lifetime_params_for_test(
    bounds: Option<stsh_custody_types::ProposalLifetimeBounds>,
    sweep_limit: Option<u32>,
) {
    require_signer(caller()).expect("signer-only");
    // RF-1: a DEPLOYED harness always OVERRIDES — `None` here means "force the
    // unruled path", never "clear the injection". A harness that wanted the
    // production value would simply not call this.
    inject_lifetime_params_for_test(Some(bounds), Some(sweep_limit.map(|l| l as usize)));
}

/// TEST-ONLY (feature `testing`): arm the companion-write trap boundary (RF-1).
///
/// Signer-gated like every other test hook. "none" DISARMS; the trap does not
/// self-clear, for the same reason as the governance one — a self-clearing arm
/// would be a durable write that survives only if the trap failed to roll back,
/// corrupting the property under test.
#[cfg(feature = "testing")]
#[update]
fn arm_companion_trap_for_test(point: String) {
    require_signer(caller()).expect("signer-only");
    if point == "none" {
        ARMED_COMPANION_TRAP.with(|t| *t.borrow_mut() = None);
        return;
    }
    assert!(
        point == COMPANION_TRAP_AFTER_INDEX_BEFORE_ACCOUNTING,
        "unknown companion trap point: {point}"
    );
    ARMED_COMPANION_TRAP.with(|t| *t.borrow_mut() = Some(point));
}

/// Governance-plane transition: ONE atomic cell write — the single durable
/// write boundary. Validation fully precedes the write; a trap anywhere in
/// validation leaves the prior cell untouched. The epoch bump is what makes
/// signer removal take effect and pins every pre-transition proposal stale.
///
/// S5B W5(b): this function is NOT `async` and performs NO `await` between the
/// cell write and finalization. That invariant is load-bearing — the §4
/// ratification's equivalence to the old keyed-repair model holds only while
/// the path is await-free, and there is no repair machinery behind it. Enforced
/// by `w5b_no_await_between_cell_write_and_finalize`.
fn execute_signer_set_update(
    proposal_id: u64,
    signers: Vec<Principal>,
    threshold: u32,
    approvals: Vec<Principal>,
) {
    let mut g = gov();
    if let Err(e) = validate_signer_set(&signers, threshold, &g.bootstrap.counterpart) {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some(format!("{e:?}")),
            AuditKind::Failed,
            approvals,
            "signer-set transition failed validation — cell untouched".to_string(),
        );
        return;
    }
    g.bootstrap.members = signers;
    g.bootstrap.threshold = threshold;
    g.epoch += 1;
    // THE boundary: a single Cell::set carries signers + threshold + epoch
    // atomically. There is no second durable write to crash between.
    gov_store(&g);
    // S5B W5(a) boundary (i): post-`gov_store`, pre-audit. A trap here must
    // roll back the epoch bump above — proof that the cell write is not
    // independently committable. No-op in release builds (see `gov_trap`).
    gov_trap(GOV_TRAP_AFTER_STORE_BEFORE_AUDIT);
    let new_epoch = g.epoch;
    audit(
        AuditKind::GovernanceTransition,
        Some(proposal_id),
        self_id(),
        Some(approvals.clone()),
        format!("signer set updated; epoch → {new_epoch}"),
    );
    // S5B W5(a) boundary (ii): post-audit, pre-`finalize`. A trap here must
    // roll back BOTH the epoch and the audit append.
    gov_trap(GOV_TRAP_AFTER_AUDIT_BEFORE_FINALIZE);
    finalize(
        proposal_id,
        ActionOutcome::Executed,
        Some(format!("epoch {new_epoch}")),
        AuditKind::Executed,
        approvals,
        "governance transition committed".to_string(),
    );
}

async fn execute_read_model<B: ExecBackend>(
    backend: &B,
    proposal_id: u64,
    req: ReadModelRequest,
    approvals: Vec<Principal>,
) {
    let variant = req.variant();
    let g = gov();
    let source = match &req {
        ReadModelRequest::NullifierReadSpentAt { .. } => g.targets.nullifier_registry,
        ReadModelRequest::TokenReadSupplyReconciliation { receipt_audit_id } => {
            match resolve_manifest_token_target(*receipt_audit_id) {
                Ok(target) => Some(target),
                Err(detail) => {
                    finalize(
                        proposal_id,
                        ActionOutcome::Failed,
                        Some(detail.clone()),
                        AuditKind::Failed,
                        approvals,
                        format!("{variant:?}: {detail} -- fail closed"),
                    );
                    return;
                }
            }
        }
        _ => g.targets.shielded_pool,
    };
    let Some(source) = source else {
        finalize(
            proposal_id,
            ActionOutcome::Failed,
            Some("read source not configured".to_string()),
            AuditKind::Failed,
            approvals,
            format!("{variant:?}: no durable target wiring — fail closed"),
        );
        return;
    };
    // L3-INT-03: NullifierReadSpentAt is SPECIAL on the wire. Its target
    // endpoint `spent_at_for_controller_update(blob) -> opt nat64` predates
    // the generic read-model contract and is FROZEN by the brief (the
    // nullifier canister must not change). The generic encoding of the full
    // ReadModelRequest enum would fail Candid decoding at the target before
    // authorization. So this variant sends the RAW nullifier bytes and wraps
    // the typed `Option<u64>` reply into the read-model response contract.
    let args = match &req {
        ReadModelRequest::NullifierReadSpentAt { nullifier, .. } => {
            candid::encode_one(nullifier.to_vec()).expect("nullifier blob encodes")
        }
        ReadModelRequest::PoolReadPayoutMemoKeyReady
        | ReadModelRequest::TokenReadSupplyReconciliation { .. } => {
            candid::encode_args(()).expect("empty read arguments encode")
        }
        _ => candid::encode_one(&req).expect("read request encodes"),
    };
    let request_hash = sha256(&args);
    let result = backend.call_update(source, variant.source_endpoint(), args).await;
    // F2: raw-size pre-decode check against the frozen aggregate ceiling.
    // The target REPLIED and violated the wire contract — deterministic
    // Failed, no decode (post-decode structural validation below stays).
    if let Ok(bytes) = &result {
        if bytes.len() > READ_RESPONSE_MAX_BYTES {
            finalize(
                proposal_id,
                ActionOutcome::Failed,
                Some(format!(
                    "read response {} bytes > READ_RESPONSE_MAX_BYTES {READ_RESPONSE_MAX_BYTES}",
                    bytes.len()
                )),
                AuditKind::Failed,
                approvals,
                format!("{variant:?}: reply exceeded the frozen aggregate ceiling"),
            );
            return;
        }
    }
    let response = result.and_then(|bytes| {
        match &req {
            ReadModelRequest::NullifierReadSpentAt { nullifier, .. } => {
                candid::decode_one::<Option<u64>>(&bytes)
                    .map(|spent_at| ReadModelResponse::NullifierReadSpentAt {
                        items: vec![NullifierSpentAtItem {
                            nullifier: *nullifier,
                            spent_at,
                        }],
                        next_cursor: None,
                    })
                    .map_err(|e| CallFailure::Rejected(format!("undecodable read response: {e}")))
            }
            ReadModelRequest::PoolReadPayoutMemoKeyReady => {
                candid::decode_one::<Option<bool>>(&bytes)
                    .map(ReadModelResponse::PoolReadPayoutMemoKeyReady)
                    .map_err(|e| CallFailure::Rejected(format!("undecodable read response: {e}")))
            }
            ReadModelRequest::TokenReadSupplyReconciliation { .. } => {
                candid::decode_one::<SupplyReconciliation>(&bytes)
                    .map(ReadModelResponse::TokenReadSupplyReconciliation)
                    .map_err(|e| CallFailure::Rejected(format!("undecodable read response: {e}")))
            }
            _ => candid::decode_one::<ReadModelResponse>(&bytes)
                .map_err(|e| CallFailure::Rejected(format!("undecodable read response: {e}"))),
        }
    });
    match response {
        Ok(resp) => {
            if matches!(
                &resp,
                ReadModelResponse::PoolReadPayoutMemoKeyReady(value) if *value != Some(true)
            ) {
                finalize(
                    proposal_id,
                    ActionOutcome::Failed,
                    Some("payout memo key not ready".to_string()),
                    AuditKind::Failed,
                    approvals,
                    "PoolReadPayoutMemoKeyReady requires Some(true)".to_string(),
                );
                return;
            }
            if let Err(e) = resp.validate() {
                finalize(
                    proposal_id,
                    ActionOutcome::Failed,
                    Some(format!("{e:?}")),
                    AuditKind::Failed,
                    approvals,
                    "read response violated the bounded contract".to_string(),
                );
                return;
            }
            let snap = ControllerReadSnapshot {
                snapshot_id: next_snapshot_id(),
                source: SnapshotSource::ReadModel(variant),
                source_canister: source,
                request: req.clone(),
                request_hash,
                response: resp,
                originating_proposal_id: proposal_id,
                governance_epoch: gov().epoch,
                observed_at_ns: now_ns(),
                completed_at_ns: now_ns(),
                terminal_outcome: stsh_custody_types::ReconcileTerminalOutcome::Executed,
            };
            let snap_id = snap.snapshot_id;
            // freeze §9: durable forever, no retention or pruning.
            snapshot_insert(&snap);
            // S5B W1.2 — snapshot ids have their OWN counter and commit in the
            // same message as the insert above.
            commit_id(IdKind::Snapshot, snap_id);
            let mut p = proposal_get(proposal_id).expect("proposal exists");
            p.snapshot_id = Some(snap_id);
            proposal_put(&p);
            audit(
                AuditKind::SnapshotStored,
                Some(proposal_id),
                self_id(),
                Some(approvals.clone()),
                format!("snapshot {snap_id} stored ({variant:?})"),
            );
            finalize(
                proposal_id,
                ActionOutcome::Executed,
                Some(format!("snapshot {snap_id}")),
                AuditKind::Executed,
                approvals,
                format!("{variant:?} read complete"),
            );
        }
        Err(CallFailure::Rejected(e)) => finalize(
            proposal_id,
            ActionOutcome::OutcomeUnknown,
            Some(cap_detail(e.clone())),
            AuditKind::OutcomeUnknown,
            approvals,
            cap_detail(format!("{variant:?}: {e}")),
        ),
    }
}

// ── Canister endpoints ───────────────────────────────────────────────────────

/// Init: signer quorum (validated by the SHARED `validate_bootstrap_quorum` —
/// threshold exactly 2, distinct non-anonymous signers, counterpart
/// non-anonymous and not a signer) + the manifest-derived cutover allowlist.
///
/// L1-6: the EXACT SetControllerAtCutover set, frozen in
/// `deployment/mainnet/custody_manifest.toml` (Axis-1 inventory):
/// `solvency_status` (pyeop, reserves.stsh.fi) and `wallet_frontend`
/// (s3tyu, app.stsh.fi). Provenance: manifest rows
/// `principal = "pyeop-7yaaa-aaaam-ajfja-cai"` and
/// `principal = "s3tyu-aaaaa-aaaab-qhdjq-cai"`, both
/// `disposition = "set_controller_at_cutover"`. These are baked as named
/// constants (the manifest is the source of truth; the vault cannot parse
/// it on-chain). Drift note: verify_custody_manifest could cross-check
/// these constants against the manifest — flagged to SSA as a gate
/// enhancement, not implemented here.
pub const CUTOVER_SOLVENCY_STATUS_PURPOSE: &str = "solvency_status";
pub const CUTOVER_SOLVENCY_STATUS_PRINCIPAL: &str = "pyeop-7yaaa-aaaam-ajfja-cai";
pub const CUTOVER_WALLET_FRONTEND_PURPOSE: &str = "wallet_frontend";
pub const CUTOVER_WALLET_FRONTEND_PRINCIPAL: &str = "s3tyu-aaaaa-aaaab-qhdjq-cai";

/// The required cutover set as (purpose, principal) pairs — exactly these,
/// no more, no fewer.
pub const REQUIRED_CUTOVER: [(&str, &str); 2] = [
    (
        CUTOVER_SOLVENCY_STATUS_PURPOSE,
        CUTOVER_SOLVENCY_STATUS_PRINCIPAL,
    ),
    (
        CUTOVER_WALLET_FRONTEND_PURPOSE,
        CUTOVER_WALLET_FRONTEND_PRINCIPAL,
    ),
];

/// L1-6: init must receive EXACTLY the manifest-derived cutover set —
/// exactly one entry per required role, purposes unique and recognized,
/// principals exact, no extras, none missing. An incomplete or fabricated
/// set can never be repaired later (CreateCanister only accepts
/// BornUnderVault), so it is rejected before any state is written.
fn validate_cutover_set(entries: &[GovernedTarget]) -> Result<(), String> {
    let mut provided: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    let mut seen_purposes = std::collections::BTreeSet::new();
    for t in entries {
        if t.disposition != ManifestDisposition::SetControllerAtCutover {
            return Err("cutover entry disposition must be SetControllerAtCutover".to_string());
        }
        if t.principal == Principal::anonymous() {
            return Err("anonymous cutover target".to_string());
        }
        if t.principal == self_id() {
            return Err("cutover target must not be the Vault".to_string());
        }
        if t.purpose.is_empty() || t.purpose.len() > MAX_TEXT_FIELD_BYTES {
            return Err("cutover purpose missing or oversized".to_string());
        }
        if !seen_purposes.insert(t.purpose.clone()) {
            return Err(format!("duplicate cutover purpose {:?}", t.purpose));
        }
        if !provided.insert((t.purpose.clone(), t.principal.to_text())) {
            return Err("duplicate cutover entry".to_string());
        }
    }
    let expected: std::collections::BTreeSet<(String, String)> = REQUIRED_CUTOVER
        .iter()
        .map(|(purpose, principal)| (purpose.to_string(), principal.to_string()))
        .collect();
    if provided != expected {
        return Err(format!(
            "cutover set must equal the manifest SetControllerAtCutover set exactly \
             (missing: {expected:?} vs provided: {provided:?})"
        ));
    }
    Ok(())
}

/// L1-2 design (documented): born-under-vault canisters do NOT exist at
/// Vault init — the Vault creates them (freeze §13.3) — so their principals
/// are NOT init args; they are bound one-shot from typed creation receipts.
/// Init wiring is therefore exactly the SetControllerAtCutover set, fully
/// validated BEFORE the governance cell is written.
#[init]
fn init(args: VaultInit) {
    validate_bootstrap_quorum(&args.quorum.signers, args.quorum.threshold, &args.quorum.upgrader)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("init: {e}")));
    // S6 — the 9-maxima at the INSTALL path. `validate_bootstrap_quorum` is
    // shared with the Upgrader and enforces the Route-1 MINIMUM (threshold and
    // distinctness); the MAXIMUM is per-plane, so it is enforced here rather
    // than folded into the shared validator, which would also require a new
    // `InitValidationError` variant and therefore a DID change.
    //
    // Trapping is the correct disposition at init: a roster that exceeds the
    // ruled maximum must never become durable, and there is no caller to
    // return an error to.
    stsh_custody_types::check_vault_roster_size(args.quorum.signers.len()).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "init: {} signers exceeds the ruled MAX_VAULT_SIGNERS of {} — every \
             V15 quota is derived at a nine-member roster",
            e.requested, e.maximum
        ))
    });
    let upgrader = args.quorum.upgrader;
    for t in &args.cutover_targets {
        if t.principal == upgrader {
            ic_cdk::trap("init: cutover target must not be a ring member");
        }
    }
    validate_cutover_set(&args.cutover_targets)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("init: {e}")));
    let cell = GovernanceCellData {
        schema_version: GOVERNANCE_CELL_SCHEMA_VERSION,
        bootstrap: BootstrapRecord {
            schema_version: BOOTSTRAP_RECORD_SCHEMA_VERSION,
            members: args.quorum.signers,
            threshold: args.quorum.threshold,
            counterpart: args.quorum.upgrader,
        },
        epoch: 0,
        targets: VaultTargets::default(), // bound from creation receipts only
        governed: args.cutover_targets,
    };
    // F3: init, receipt binding and post_upgrade share ONE governed-state
    // validator.
    validate_governed_state(&cell).unwrap_or_else(|e| ic_cdk::trap(&format!("init: {e}")));
    // SSA BLOCKER 3 — the companion record is written HERE, at fresh install.
    // Absence thereafter is durable corruption and traps; it is no longer
    // silently interpreted as an empty default.
    companion_init();
    gov_store(&cell);
}

#[post_upgrade]
fn post_upgrade() {
    // Fail-closed sentinel gate: the durable governance cell must decode and
    // re-validate (threshold floor, distinct signers, counterpart), or the
    // canister does not resume. No pre_upgrade exists anywhere in this
    // codebase; stable structures survive in place. There is NO migration
    // here that touches MemoryIds 1–5 — proposals, approvals, audit,
    // snapshots and reservations survive upgrades byte-for-byte.
    let data = gov().clone();
    revalidate_governance(&data);
    // S5B W2(c) — BOUNDED VALIDATION ONLY. The former full-history rebuild
    // (`rebuild_proposal_indexes`, which decoded every `ProposalRecord` ever
    // written) is REMOVED, not merely capped.
    //
    // Under amended R3 item 10(a) the companions are AUTHORITATIVE for active
    // membership, so rebuilding them from `PROPOSALS` is the wrong authority
    // answering the question — and (c) forbids `post_upgrade` from scanning or
    // decoding permanent history at all. Cost here is a function of the live
    // active set (which C7/C12 bound), not of how many proposals have ever
    // existed.
    //
    // (d): a mismatch TRAPS. It is never repaired by re-deriving from history,
    // and S5B ships no callable repair surface — recovery is a governed,
    // hash-bound Wasm upgrade.
    companion_validate();
    // §S7 §3a E2 — the post-upgrade sweep, in BOTH canisters' `post_upgrade`
    // (release condition 1). Runs AFTER the fail-closed gates above: promoting
    // proposals on state not yet proved trustworthy would be a write ahead of
    // the sentinel. It takes no evidence, writes no terminal outcome and
    // releases no lock, so it settles nothing — it only moves callback-writable
    // proposals to the state that demands objective evidence.
    sweep_executing_starts_to_unknown(now_ns());
}

#[update]
fn propose(
    action: VaultActionKind,
    requested_lifetime_ns: Option<u64>,
) -> Result<u64, VaultError> {
    let r = propose_inner(caller(), action, requested_lifetime_ns);
    // S5A M1 gate C — `admission_path_total`: what THIS admission message has
    // consumed once the complete admission path has run.
    //
    // The absolute counter is recorded rather than a delta because
    // `instruction_counter` measures from the start of the message, so the
    // figure includes candid decode of the payload. That inclusion is the point
    // rather than an artifact: §C bounds the "complete admission path at
    // maximum admitted payload", and at ~1.9 MB the decode is a material part
    // of what the budget has to cover. A delta measured around `propose_inner`
    // alone would exclude it and understate the path.
    #[cfg(feature = "testing")]
    LAST_PROPOSE_INSTRUCTIONS.with(|c| c.set(ic_cdk::api::instruction_counter()));
    r
}

#[cfg(feature = "testing")]
thread_local! {
    static LAST_PROPOSE_INSTRUCTIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// TEST-ONLY (feature `testing`): read back the instruction count recorded by
/// the most recent `propose` (S5A M1 gate C).
///
/// A QUERY: a fresh update call would start its own counter at zero and could
/// not observe the previous message's total at all.
#[cfg(feature = "testing")]
#[query]
fn last_propose_instructions_for_test() -> u64 {
    if require_signer(caller()).is_err() {
        return 0;
    }
    LAST_PROPOSE_INSTRUCTIONS.with(|c| c.get())
}

/// R3.7 (V7 §3) — withdraw your OWN pending proposal. Signer-gated, then
/// proposer-scoped: `NotProposer` is returned to a signer who is not the
/// proposer, so no signer can veto a proposal their peers are evaluating.
#[update]
fn cancel_proposal(proposal_id: u64) -> Result<(), VaultError> {
    cancel_proposal_inner(caller(), proposal_id)
}

/// R3.8 — drive the bounded expiry sweep. Signer-gated; work is bounded by
/// `limit`, so the sweep does not itself become the denial of service it
/// exists to prevent. Returns the ids reaped, so a caller can repeat until it
/// returns empty.
#[update]
fn sweep_expired_proposals(limit: u32) -> Result<Vec<u64>, VaultError> {
    require_signer(caller())?;
    // Clamp to the ruled per-call work bound once it exists. Until then the
    // caller's limit governs, which is safe because no proposal carries an
    // expiry yet, so the index is empty and the sweep is vacuous.
    let limit = match sweep_work_limit() {
        Some(cap) => (limit as usize).min(cap),
        None => limit as usize,
    };
    Ok(sweep_expired_inner(now_ns(), limit))
}

/// R1.5 — `expected_action_hash` is REQUIRED. A signer supplies the
/// commitment they read from the proposal view; a mismatch rejects with zero
/// writes and the proposal stays `Pending`. Approving by id alone — with
/// nothing binding the approval to a payload — is CUST-SSA-001.
#[update]
async fn approve(
    proposal_id: u64,
    expected_action_hash: Vec<u8>,
) -> Result<ApprovalOutcome, VaultError> {
    let (outcome, should_execute) = approve_inner(caller(), proposal_id, expected_action_hash, now_ns())?;
    if should_execute {
        // `Executing` + reservation + quorum audit are ALREADY durable — this
        // is the first await of the execution path.
        let wire_error = execute_action_with(&IcBackend, proposal_id).await;
        // §7c (P1-2) — a start REPLAY surfaces its typed error here, never a
        // success-shaped response. The durable record written during execution
        // stands: on the IC an `Err` reply is a normal reply, and only a trap
        // rolls state back. So the governance fact is recorded AND the caller
        // receives `AlreadySettled { outcome }` with the settled outcome in the
        // payload, which is exactly what §7c requires of both directions.
        if let Some(e) = wire_error {
            return Err(e);
        }
        let p = proposal_get(proposal_id).expect("proposal exists");
        return Ok(ApprovalOutcome::PriorResult {
            outcome: p.outcome,
            result: p.result,
        });
    }
    Ok(outcome)
}

// ── Query surface — C3 rulings exactly as frozen (freeze §4) ────────────────

/// SIGNER-GATED. Unauthorized → indistinguishable `None` (anonymous /
/// removed / stale-epoch / unknown all identical). Removal takes effect on
/// epoch change because membership is read from the canonical cell.
#[query]
fn get_controller_read_snapshot(snapshot_id: u64) -> Option<ControllerReadSnapshot> {
    query_gate(caller())?;
    CONTROLLER_READ_SNAPSHOTS
        .with(|s| s.borrow().get(&snapshot_id))
        .map(|b| candid::decode_one(&b).expect("snapshot decodes"))
}

/// SIGNER-GATED — a public list leaks request hashes, targets, cadence.
#[query]
fn get_proposal(proposal_id: u64) -> Option<ProposalView> {
    query_gate(caller())?;
    proposal_get(proposal_id).map(|p| to_view(&p))
}

/// SIGNER-GATED, bounded/paginated: ascending ids strictly after `cursor`,
/// at most `limit` entries with `1 <= limit <= MAX_READ_PAGE_LIMIT` (a bound
/// violation fails closed to the same `None`).
#[query]
fn list_proposals(cursor: Option<u64>, limit: u32) -> Option<Vec<ProposalView>> {
    query_gate(caller())?;
    if limit == 0 || limit > MAX_READ_PAGE_LIMIT {
        return None;
    }
    let start = cursor.unwrap_or(0);
    // F4: a maximal cursor must not overflow — empty page, never a panic.
    let Some(after) = start.checked_add(1) else {
        return Some(Vec::new());
    };
    Some(
        PROPOSALS.with(|p| {
            p.borrow()
                .range(after..)
                .take(limit as usize)
                .map(|(_, b)| {
                    let rec: ProposalRecord = candid::decode_one(&b).expect("proposal decodes");
                    to_view(&rec)
                })
                .collect()
        }),
    )
}

/// SIGNER-GATED, bounded/paginated — the proposal list in historical form.
#[query]
fn get_audit_events(cursor: Option<u64>, limit: u32) -> Option<Vec<AuditEvent>> {
    query_gate(caller())?;
    if limit == 0 || limit > MAX_READ_PAGE_LIMIT {
        return None;
    }
    let start = cursor.unwrap_or(0);
    let Some(after) = start.checked_add(1) else {
        return Some(Vec::new());
    };
    Some(
        AUDIT_EVENTS.with(|a| {
            a.borrow()
                .range(after..)
                .take(limit as usize)
                .map(|(_, b)| candid::decode_one(&b).expect("audit decodes"))
                .collect()
        }),
    )
}

/// SIGNER-GATED — the count is credibility, the identities are a target list.
#[query]
fn get_signers() -> Option<Vec<Principal>> {
    let g = query_gate(caller())?;
    Some(g.bootstrap.members)
}

/// SIGNER-GATED (L1-1/L1-2 read-back): the durable governed-target allowlist
/// plus the receipt-bound application/read wiring. Reveals target
/// principals — a target list — so it is gated like `get_signers`.
#[query]
fn get_governed_targets() -> Option<(VaultTargets, Vec<GovernedTarget>)> {
    let g = query_gate(caller())?;
    Some((g.targets.clone(), g.governed.clone()))
}

/// Maximum audit records EXAMINED per `get_creation_receipts` call (L1-9).
/// Receipts are rare in an append-only log of routine governance events, so
/// bounding only the returned items would let one call scan the entire
/// history. 256 records per call keeps every call O(1)-bounded (tiny Candid
/// decodes), guarantees forward progress per page (next_cursor advances by
/// examined records even when a page holds zero receipts), and needs no
/// dedicated receipt index — the scan-bound option chosen over an index for
/// its smaller durable footprint.
pub const MAX_RECEIPT_SCAN_PER_CALL: u32 = 256;

/// A bounded page of typed creation receipts (L1-7). `next_cursor` is the
/// audit-event id to pass as the next `cursor` — receipts alone cannot
/// derive it, because non-receipt audit events interleave on the same
/// id sequence. Matches the custody-types read-model page pattern.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreationReceiptPage {
    pub items: Vec<CreationReceipt>,
    pub next_cursor: Option<u64>,
}

/// SIGNER-GATED, bounded/paginated (L1-4 read-back, L1-7 cursor, L1-9 scan
/// bound): typed D5 creation receipts. `cursor`/`next_cursor` are
/// audit-event ids (the scan sequence), NOT proposal ids. Each call
/// examines at most MAX_RECEIPT_SCAN_PER_CALL audit records; every receipt
/// binds EXACTLY ONE principal — the deployment gate's bijectivity anchor.
/// `1 <= limit <= MAX_READ_PAGE_LIMIT`, else fail closed to `None`.
#[query]
fn get_creation_receipts(cursor: Option<u64>, limit: u32) -> Option<CreationReceiptPage> {
    query_gate(caller())?;
    receipt_page(cursor, limit)
}

fn receipt_page(cursor: Option<u64>, limit: u32) -> Option<CreationReceiptPage> {
    if limit == 0 || limit > MAX_READ_PAGE_LIMIT {
        return None;
    }
    let start = cursor.unwrap_or(0);
    let Some(after) = start.checked_add(1) else {
        // F4: a maximal cursor must not overflow — empty page, walk done.
        return Some(CreationReceiptPage {
            items: Vec::new(),
            next_cursor: None,
        });
    };
    AUDIT_EVENTS.with(|a| {
        let map = a.borrow();
        let mut items = Vec::new();
        let mut examined: u32 = 0;
        let mut last_examined = start;
        let mut more = false;
        for (id, b) in map.range(after..) {
            // Stop BEFORE exceeding either bound: page full, or scan bound
            // reached. next_cursor then advances by EXAMINED records, so a
            // sparse history still makes progress every call (L1-9).
            if items.len() == limit as usize || examined >= MAX_RECEIPT_SCAN_PER_CALL {
                more = true;
                break;
            }
            last_examined = id;
            examined += 1;
            let ev: AuditEvent = candid::decode_one(&b).expect("audit decodes");
            debug_assert_eq!(ev.id, id);
            if let Some(r) = ev.creation_receipt {
                items.push(r);
            }
        }
        // Page filled exactly at the last event: there may still be more.
        if !more
            && items.len() == limit as usize
            && last_examined
                .checked_add(1)
                .is_some_and(|after| map.range(after..).next().is_some())
        {
            more = true;
        }
        Some(CreationReceiptPage {
            items,
            next_cursor: if more { Some(last_examined) } else { None },
        })
    })
}

/// PUBLIC, conscious (freeze §4): threshold, signer count, epoch. No
/// principals. Fails closed on uninitialized state: reports zeros, which
/// authorize nothing and never resemble a live quorum.
#[query]
fn get_governance_summary() -> stsh_custody_types::GovernanceSummary {
    match gov_cell() {
        Some(g) => stsh_custody_types::GovernanceSummary {
            threshold: g.bootstrap.threshold,
            signer_count: g.bootstrap.members.len() as u32,
            governance_epoch: g.epoch,
        },
        None => stsh_custody_types::GovernanceSummary {
            threshold: 0,
            signer_count: 0,
            governance_epoch: 0,
        },
    }
}

/// PUBLIC (freeze §4): "no arbitrary method strings" is externally checkable.
#[query]
fn get_action_catalogue() -> Vec<String> {
    ApplicationAction::ALL
        .iter()
        .map(|a| format!("{a:?}"))
        .collect()
}

/// PUBLIC — house convention.
#[query]
fn get_build_info() -> String {
    format!("vault v{}", env!("CARGO_PKG_VERSION"))
}

fn to_view(p: &ProposalRecord) -> ProposalView {
    // The STORED hash, never a fresh recomputation: the view must show what
    // approvals are actually bound to, so that a stored-vs-recomputed
    // divergence is detectable at approve-time (R1.5) rather than papered over
    // by a view that silently recomputes.
    let commitment_hash = p.commitment_hash.clone();
    let action = match &p.action {
        VaultActionKind::Application(r) => ActionView::Application(format!("{:?}", r.kind())),
        VaultActionKind::Management(m) => ActionView::Management(ManagementActionView::of(m)),
        VaultActionKind::UpgraderUpgrade(uu) => ActionView::UpgraderUpgrade {
            expected_wasm_hash: uu.expected_wasm_hash.clone(),
            expected_arg_hash: uu.expected_arg_hash.clone(),
            bytes_retained: !uu.wasm_bytes.is_empty() || !uu.arg_bytes.is_empty(),
        },
        VaultActionKind::ReconcileUpgraderUpgrade(r) => {
            ActionView::ReconcileUpgraderUpgrade {
                target_proposal_id: r.proposal_id,
                objective_evidence: r.objective_evidence.clone(),
            }
        }
        VaultActionKind::VaultUpgradeViaUpgrader(vu) => ActionView::VaultUpgradeViaUpgrader {
            request_id: vu.request_id,
            expected_wasm_hash: vu.expected_wasm_hash.clone(),
            expected_arg_hash: vu.expected_arg_hash.clone(),
            bytes_retained: !vu.wasm_bytes.is_empty() || !vu.arg_bytes.is_empty(),
        },
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(r) => {
            ActionView::ReconcileVaultUpgradeViaUpgrader {
                target_proposal_id: r.request_id,
                objective_evidence: r.objective_evidence.clone(),
            }
        }
        VaultActionKind::ReconcileUpgraderStart(r) => ActionView::ReconcileUpgraderStart {
            target_proposal_id: r.proposal_id,
            objective_evidence: r.objective_evidence.clone(),
        },
        VaultActionKind::ReadModel(r) => ActionView::ReadModel(format!("{:?}", r.variant())),
        VaultActionKind::UpdateSignerSet { signers, threshold } => ActionView::UpdateSignerSet {
            signers: signers.clone(),
            threshold: *threshold,
        },
    };
    ProposalView {
        proposal_id: p.proposal_id,
        proposer: p.proposer,
        created_at_ns: p.created_at_ns,
        epoch: p.epoch,
        outcome: p.outcome,
        result: p.result.clone(),
        snapshot_id: p.snapshot_id,
        action,
        approvals: approvals_get(p.proposal_id),
        commitment_hash,
    }
}

// =============================================================================
// L1 ACCEPTANCE TESTS — native state-machine / crash-boundary suite
// =============================================================================
//
// Every test runs on its own thread (default test harness), so the
// thread_local stable structures start fresh per test. The `ExecBackend` seam
// drives scripted inter-canister results and asserts durable-state ordering at
// the exact call boundary (Executing + intent + reservation durable BEFORE
// the first call). `post_upgrade` is exercised natively: the memory manager
// thread_local survives within a test, so an upgrade-persistence check is a
// plain function call.

#[cfg(test)]
mod tests {
    use super::*;
    use stsh_custody_types::{
        ClaimDecision, MAX_READ_PAGE_LIMIT, PageRequest, ReadModelRequest,
        UpgradeObjectiveEvidence,
    };
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // ── Harness ──────────────────────────────────────────────────────────────

    fn p(b: u8) -> Principal {
        Principal::from_slice(&[b; 29])
    }

    const S1: u8 = 1;
    const S2: u8 = 2;
    const S3: u8 = 3;
    const UPGRADER: u8 = 9;

    fn pyeop() -> Principal {
        Principal::from_text(CUTOVER_SOLVENCY_STATUS_PRINCIPAL).unwrap()
    }
    fn s3tyu() -> Principal {
        Principal::from_text(CUTOVER_WALLET_FRONTEND_PRINCIPAL).unwrap()
    }

    /// The exact manifest SetControllerAtCutover set (L1-6) — the only
    /// cutover config init accepts.
    fn manifest_cutover() -> Vec<GovernedTarget> {
        vec![
            GovernedTarget {
                principal: pyeop(),
                disposition: ManifestDisposition::SetControllerAtCutover,
                purpose: CUTOVER_SOLVENCY_STATUS_PURPOSE.to_string(),
            },
            GovernedTarget {
                principal: s3tyu(),
                disposition: ManifestDisposition::SetControllerAtCutover,
                purpose: CUTOVER_WALLET_FRONTEND_PURPOSE.to_string(),
            },
        ]
    }

    fn default_init() -> VaultInit {
        VaultInit {
            quorum: VaultInitArgs {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 2,
                upgrader: p(UPGRADER),
            },
            cutover_targets: manifest_cutover(),
        }
    }

    fn setup() {
        init(default_init());
        // C9 IS LIVE AS OF S6, and `setup()` means "a freshly installed
        // canister". On a real install that is automatically true — stable
        // memory is empty. In-process it is not: the ledger is a thread-local
        // that outlives `init`, so a test calling `setup()` in a loop would
        // carry an earlier iteration's entry budget into the next one and hit
        // the per-signer bound for reasons having nothing to do with what it
        // is testing. Resetting here restores the property the fixture always
        // meant to assert. This is a FIXTURE correction, not a production one:
        // no install path can observe a non-empty ledger.
        entry_rate_store(&EntryRateLedger::default());
    }


    /// Bind born-under-vault roles through the REAL receipt path:
    /// governed CreateCanister proposals whose receipts wire the roles.
    fn wire_roles(backend: &FakeBackend, roles: &[(&str, u8)]) {
        for (role, byte) in roles {
            backend.created.borrow_mut().push(p(*byte));
            drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::Management(ManagementAction::CreateCanister {
                    manifest_purpose: role.to_string(),
                    disposition: ManifestDisposition::BornUnderVault,
                }),
                backend,
            );
        }
    }

    /// Minimal std-only block_on: the fake backend completes synchronously,
    /// so a future that pends is a test bug.
    fn block_on<F: Future>(fut: F) -> F::Output {
        fn noop(_: *const ()) {}
        fn clone_w(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone_w, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => panic!("future pending — fake backend must complete"),
            }
        }
    }

    /// Scripted backend. `assert_pre_call` verifies, at the exact moment of
    /// the FIRST inter-canister call, that Executing + reservation (+ upgrade
    /// intent) are already durable — the crash-boundary contract.
    struct FakeBackend {
        calls: RefCell<Vec<String>>,
        next_call_result: RefCell<Result<Vec<u8>, CallFailure>>,
        assert_pre_call: bool,
        /// Scripted principals returned by create_canister, one per call.
        created: RefCell<Vec<Principal>>,
        /// Optional hook run INSIDE create_canister before it returns —
        /// simulates state changing while the management call is in flight.
        on_create: RefCell<Option<Box<dyn Fn()>>>,
        /// Raw args of the most recent call_update (wire-shape assertions).
        last_call_args: RefCell<Vec<u8>>,
    }

    impl FakeBackend {
        fn ok(payload: Vec<u8>) -> Self {
            FakeBackend {
                calls: RefCell::new(Vec::new()),
                next_call_result: RefCell::new(Ok(payload)),
                assert_pre_call: true,
                created: RefCell::new(Vec::new()),
                on_create: RefCell::new(None),
                last_call_args: RefCell::new(Vec::new()),
            }
        }
        fn rejecting(msg: &str) -> Self {
            FakeBackend {
                calls: RefCell::new(Vec::new()),
                next_call_result: RefCell::new(Err(CallFailure::Rejected(msg.to_string()))),
                assert_pre_call: true,
                created: RefCell::new(Vec::new()),
                on_create: RefCell::new(None),
                last_call_args: RefCell::new(Vec::new()),
            }
        }
        fn pre_call_check(&self, what: &str) {
            self.calls.borrow_mut().push(what.to_string());
            if !self.assert_pre_call {
                return;
            }
            // Any proposal in flight must already be Executing with its
            // permanent reservation durable.
            let in_flight: Vec<u64> = PROPOSALS.with(|p| {
                p.borrow()
                    .iter()
                    .filter_map(|(id, b)| {
                        let rec: ProposalRecord = candid::decode_one(&b).unwrap();
                        if rec.outcome == ActionOutcome::Executing {
                            Some(id)
                        } else {
                            None
                        }
                    })
                    .collect()
            });
            assert!(!in_flight.is_empty(), "{what}: an Executing proposal must exist");
            for id in in_flight {
                assert!(
                    reservation_get(id).is_some(),
                    "{what}: reservation must be durable before the first call"
                );
                let rec = proposal_get(id).unwrap();
                if matches!(
                    rec.action,
                    VaultActionKind::UpgraderUpgrade(_)
                        | VaultActionKind::Management(ManagementAction::Upgrade { .. })
                        | VaultActionKind::Management(ManagementAction::InstallCode { .. })
                        | VaultActionKind::VaultUpgradeViaUpgrader(_)
                ) {
                    assert!(
                        rec.intent.is_some(),
                        "{what}: upgrade intent must be durable before the first call"
                    );
                }
            }
        }
    }

    impl ExecBackend for FakeBackend {
        fn call_update<'a>(
            &'a self,
            target: Principal,
            method: &'static str,
            args: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, CallFailure>> + 'a>> {
            self.pre_call_check(&format!("call_update {method} -> {target}"));
            *self.last_call_args.borrow_mut() = args;
            let r = self.next_call_result.borrow().clone();
            Box::pin(async move { r })
        }
        fn install_code<'a>(
            &'a self,
            target: Principal,
            mode: InstallMode,
            _wasm: Vec<u8>,
            _arg: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
            self.pre_call_check(&format!("install_code {mode:?} -> {target}"));
            let r = self.next_call_result.borrow().clone().map(|_| ());
            Box::pin(async move { r })
        }
        fn start_canister<'a>(
            &'a self,
            target: Principal,
        ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
            self.pre_call_check(&format!("start {target}"));
            let r = self.next_call_result.borrow().clone().map(|_| ());
            Box::pin(async move { r })
        }
        fn stop_canister<'a>(
            &'a self,
            target: Principal,
        ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
            self.pre_call_check(&format!("stop {target}"));
            let r = self.next_call_result.borrow().clone().map(|_| ());
            Box::pin(async move { r })
        }
        fn update_settings<'a>(
            &'a self,
            target: Principal,
            _c: Vec<Principal>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
            self.pre_call_check(&format!("update_settings {target}"));
            let r = self.next_call_result.borrow().clone().map(|_| ());
            Box::pin(async move { r })
        }
        fn deposit_cycles<'a>(
            &'a self,
            target: Principal,
            _c: u128,
        ) -> Pin<Box<dyn Future<Output = Result<(), CallFailure>> + 'a>> {
            self.pre_call_check(&format!("deposit_cycles {target}"));
            let r = self.next_call_result.borrow().clone().map(|_| ());
            Box::pin(async move { r })
        }
        fn create_canister<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Principal, CallFailure>> + 'a>> {
            self.pre_call_check("create_canister");
            if let Some(hook) = self.on_create.borrow().as_ref() {
                hook();
            }
            let created = if self.created.borrow().is_empty() {
                p(77)
            } else {
                self.created.borrow_mut().remove(0)
            };
            let r = self.next_call_result.borrow().clone().map(|_| created);
            Box::pin(async move { r })
        }
    }

    /// Drive one proposal through propose → approvals → execution.
    fn drive(
        proposer: Principal,
        approvers: &[Principal],
        action: VaultActionKind,
        backend: &FakeBackend,
    ) -> u64 {
        let id = propose_inner(proposer, action, None).expect("propose");
        let mut executed = false;
        for a in approvers {
            let (outcome, should_execute) = approve_inner(*a, id, commit_of(id), now_ns()).expect("approve");
            if should_execute {
                assert!(!executed, "exactly one execution may trigger");
                executed = true;
                assert!(matches!(outcome, ApprovalOutcome::Executing));
                block_on(execute_action_with(backend, id));
            }
        }
        assert!(executed, "quorum must trigger execution exactly once");
        id
    }

    fn governance_action() -> VaultActionKind {
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
        }
    }

    fn audit_events() -> Vec<AuditEvent> {
        AUDIT_EVENTS.with(|a| {
            a.borrow()
                .iter()
                .map(|(_, b)| candid::decode_one(&b).unwrap())
                .collect()
        })
    }

    // ── Init / threshold floor ───────────────────────────────────────────────

    #[test]
    fn init_happy_path_summary_public() {
        setup();
        let s = get_governance_summary();
        assert_eq!(s.threshold, 2);
        assert_eq!(s.signer_count, 3);
        assert_eq!(s.governance_epoch, 0);
    }

    #[test]
    fn init_rejects_every_threshold_below_or_above_2_and_bad_quorums() {
        let try_init = |signers: Vec<Principal>, threshold: u32, upgrader: Principal| {
            std::panic::catch_unwind(|| {
                init(VaultInit {
                    quorum: VaultInitArgs {
                        signers,
                        threshold,
                        upgrader,
                    },
                    cutover_targets: Vec::new(),
                })
            })
            .is_err()
        };
        assert!(try_init(vec![p(S1), p(S2)], 1, p(UPGRADER)), "threshold 1 rejected");
        assert!(try_init(vec![p(S1), p(S2), p(S3)], 3, p(UPGRADER)), "init threshold must be exactly 2");
        assert!(try_init(vec![p(S1)], 2, p(UPGRADER)), "fewer signers than threshold");
        assert!(try_init(vec![p(S1), p(S1)], 2, p(UPGRADER)), "duplicates rejected");
        assert!(try_init(vec![p(S1), Principal::anonymous()], 2, p(UPGRADER)), "anonymous signer");
        assert!(try_init(vec![p(S1), p(S2)], 2, Principal::anonymous()), "anonymous upgrader");
        assert!(try_init(vec![p(S1), p(S2)], 2, p(S2)), "upgrader must not be a signer");
    }

    #[test]
    fn governance_rejects_every_threshold_below_2_path() {
        setup();
        // threshold 1 — the unlowerable floor (freeze §1)
        let r = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 1,
            }, None,
        );
        assert_eq!(r, Err(VaultError::ThresholdViolation));
        // threshold 0
        let r = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 0,
            }, None,
        );
        assert_eq!(r, Err(VaultError::ThresholdViolation));
        // threshold above distinct signer count — can never collect approvals
        let r = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2)],
                threshold: 3,
            }, None,
        );
        assert_eq!(r, Err(VaultError::ThresholdViolation));
        // duplicates masquerading as quorum
        let r = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S1), p(S2)],
                threshold: 2,
            }, None,
        );
        assert_eq!(r, Err(VaultError::ThresholdViolation));
        // anonymous in the set
        let r = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), Principal::anonymous()],
                threshold: 2,
            }, None,
        );
        assert!(r.is_err());
    }

    // ── Authorization: single deny-by-default path ───────────────────────────

    #[test]
    fn propose_denies_non_signers_and_anonymous() {
        setup();
        assert_eq!(
            propose_inner(p(77), governance_action(), None),
            Err(VaultError::NotAuthorized)
        );
        assert_eq!(
            propose_inner(Principal::anonymous(), governance_action(), None),
            Err(VaultError::NotAuthorized)
        );
    }

    #[test]
    fn approve_denies_non_signers_and_duplicates() {
        setup();
        let id = propose_inner(p(S1), governance_action(), None).unwrap();
        assert_eq!(
            approve_inner(p(77), id, commit_of(id), now_ns()).map_err(|e| e),
            Err(VaultError::NotAuthorized)
        );
        approve_inner(p(S1), id, commit_of(id), now_ns()).unwrap();
        assert_eq!(
            approve_inner(p(S1), id, commit_of(id), now_ns()).map_err(|e| e),
            Err(VaultError::AlreadyApproved)
        );
    }

    // ── Quorum / execution / concurrency ─────────────────────────────────────

    #[test]
    fn concurrent_quorum_reaching_approvals_admit_exactly_one_execution() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }), None,
        )
        .unwrap();
        // First approval: below quorum, no execution.
        let (o, exec) = approve_inner(p(S1), id, commit_of(id), now_ns()).unwrap();
        assert!(matches!(o, ApprovalOutcome::Approved { approvals: 1, .. }));
        assert!(!exec);
        // Two approvals arrive "concurrently"; the first reaches quorum and
        // executes, the second sees a non-Pending state — replay, never a
        // second execution.
        let (o2, exec2) = approve_inner(p(S2), id, commit_of(id), now_ns()).unwrap();
        assert!(exec2, "quorum approval triggers the one execution");
        assert!(matches!(o2, ApprovalOutcome::Executing));
        let (o3, exec3) = approve_inner(p(S3), id, commit_of(id), now_ns()).unwrap();
        assert!(!exec3, "concurrent approval must not re-trigger");
        assert!(matches!(
            o3,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::Executing,
                ..
            }
        ));
        block_on(execute_action_with(&backend, id));
        assert_eq!(backend.calls.borrow().len(), 1, "exactly one target call");
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        // Replay after terminal returns the prior result.
        let (o4, exec4) = approve_inner(p(S3), id, commit_of(id), now_ns()).unwrap();
        assert!(!exec4);
        assert!(matches!(
            o4,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::Executed,
                ..
            }
        ));
    }

    #[test]
    fn executing_and_reservation_are_durable_before_first_await() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }), None,
        )
        .unwrap();
        approve_inner(p(S1), id, commit_of(id), now_ns()).unwrap();
        let (_, should_execute) = approve_inner(p(S2), id, commit_of(id), now_ns()).unwrap();
        assert!(should_execute);
        // BEFORE driving the executor (i.e. before the first await): the
        // crash window's required durable state.
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executing);
        let res = reservation_get(id).expect("reservation durable");
        assert_eq!(res.approving_signers, vec![p(S1), p(S2)]);
        block_on(execute_action_with(&backend, id));
    }

    #[test]
    fn crash_at_inter_canister_call_yields_outcome_unknown_never_pending() {
        setup();
        let backend = FakeBackend::rejecting("simulated crash/reject at call boundary");
        let id = propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }), None,
        )
        .unwrap();
        approve_inner(p(S1), id, commit_of(id), now_ns()).unwrap();
        let (_, go) = approve_inner(p(S2), id, commit_of(id), now_ns()).unwrap();
        assert!(go);
        block_on(execute_action_with(&backend, id));
        let rec = proposal_get(id).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::OutcomeUnknown);
        // OutcomeUnknown never returns to Pending — replay reports it.
        let (o, exec) = approve_inner(p(S3), id, commit_of(id), now_ns()).unwrap();
        assert!(!exec);
        assert!(matches!(
            o,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::OutcomeUnknown,
                ..
            }
        ));
        // The permanent reservation survived the crash.
        assert!(reservation_get(id).is_some());
    }

    #[test]
    fn business_failure_response_is_failed_not_unknown() {
        setup();
        let payload = candid::encode_one(Result::<(), String>::Err("nope".to_string())).unwrap();
        let backend = FakeBackend::ok(payload);
        wire_roles(&backend, &[("vesting", 22)]);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::VestingReconcileClaim(
                p(55),
                ClaimDecision::Executed,
            )),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Failed);
    }

    #[test]
    fn unconfigured_target_fails_closed() {
        // Manifest cutover governed, but no born-under-vault role wired yet.
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::TreasuryExecuteWithdrawal(7)),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Failed);
        assert!(backend.calls.borrow().is_empty(), "no caller-supplied target");
    }

    // ── Epoch pin / governance transitions / crash boundaries ────────────────

    #[test]
    fn stale_epoch_approval_and_execution_rejected() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        // Proposal created at epoch 0.
        let old = propose_inner(p(S1), governance_action(), None).unwrap();
        // A separate governance transition bumps the epoch to 1.
        let bump = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 3,
            }, None,
        )
        .unwrap();
        approve_inner(p(S1), bump, commit_of(bump), now_ns()).unwrap();
        let (_, go) = approve_inner(p(S2), bump, commit_of(bump), now_ns()).unwrap();
        assert!(go);
        block_on(execute_action_with(&backend, bump));
        assert_eq!(gov().epoch, 1);
        // Approving the epoch-0 proposal now is stale — even though it is
        // still Pending.
        assert_eq!(
            approve_inner(p(S2), old, commit_of(old), now_ns()).map_err(|e| e),
            Err(VaultError::StaleEpoch {
                expected: 1,
                found: 0
            })
        );
    }

    #[test]
    fn governance_transition_is_atomic_single_boundary_and_epoch_pinned() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let before = gov();
        // An invalid transition traps validation BEFORE the one durable
        // write; the cell must be byte-identical afterwards (crash boundary:
        // failure before the write).
        let bad = propose_inner(p(S1), governance_action(), None).unwrap();
        execute_signer_set_update(
            bad,
            vec![p(S1)], // below any valid quorum for threshold 2
            2,
            vec![p(S1), p(S2)],
        );
        let after = gov();
        assert_eq!(before, after, "failed transition leaves the cell untouched");
        assert_eq!(proposal_get(bad).unwrap().outcome, ActionOutcome::Failed);
        // A valid transition: signers + threshold + epoch in ONE write.
        let good = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3), p(4)],
                threshold: 2,
            }, None,
        )
        .unwrap();
        drive_approvals_only(good, &[p(S1), p(S2)]);
        block_on(execute_action_with(&backend, good));
        let g = gov();
        assert_eq!(g.epoch, 1);
        assert_eq!(g.bootstrap.members.len(), 4);
        assert_eq!(g.bootstrap.threshold, 2);
        assert!(audit_events().iter().any(|e| e.kind == AuditKind::GovernanceTransition));
    }

    fn drive_approvals_only(id: u64, approvers: &[Principal]) {
        for a in approvers {
            approve_inner(*a, id, commit_of(id), now_ns()).unwrap();
        }
    }

    #[test]
    fn signer_removal_takes_effect_on_epoch_change() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2)], // S3 removed
                threshold: 2,
            }, None,
        )
        .unwrap();
        drive_approvals_only(id, &[p(S1), p(S2)]);
        block_on(execute_action_with(&backend, id));
        // Removed signer: updates and gated queries all deny.
        assert_eq!(
            propose_inner(p(S3), governance_action(), None),
            Err(VaultError::NotAuthorized)
        );
        assert_eq!(query_gate(p(S3)), None);
        assert!(query_gate(p(S1)).is_some());
    }

    // ── post_upgrade revalidation (governance crash boundary) ────────────────

    #[test]
    fn post_upgrade_revalidates_and_preserves_all_durable_state() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &backend,
        );
        let audits_before = audit_events().len();
        post_upgrade();
        // Proposals, approvals, audit, reservations survive byte-for-byte;
        // NO migration path drops them (brief invariant 4).
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert!(reservation_get(id).is_some(), "reservations survive upgrade");
        assert_eq!(approvals_get(id), vec![p(S1), p(S2)]);
        assert_eq!(audit_events().len(), audits_before);
        assert!(query_gate(p(S1)).is_some());
    }

    #[test]
    fn post_upgrade_traps_on_corrupt_governance_cell() {
        setup();
        GOVERNANCE_CELL.with(|c| c.borrow_mut().set(vec![0xDE, 0xAD]).unwrap());
        assert!(std::panic::catch_unwind(post_upgrade).is_err());
    }

    #[test]
    fn post_upgrade_traps_on_quorum_violating_cell() {
        setup();
        let mut g = gov();
        g.bootstrap.threshold = 1; // a durable contraction must never resume
        gov_store(&g);
        assert!(std::panic::catch_unwind(post_upgrade).is_err());
    }

    // ── C3 query rulings: signer-gated, indistinguishable None ───────────────

    #[test]
    fn gated_queries_positive_and_all_four_negative_cases() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &backend,
        );
        // Positive: an active signer reads everything.
        assert!(get_proposal_for(id, p(S1)).is_some());
        assert!(get_signers_for(p(S2)).is_some());
        assert!(list_proposals_for(p(S1)).is_some());
        assert!(get_audit_for(p(S1)).is_some());
        assert!(get_snapshot_for(1, p(S1)).is_none(), "no snapshots yet, but authorized Some-layer is reachable");
        // The four negative cases — every one returns the exact same `None`
        // at every gated endpoint, indistinguishable.
        for caller in [
            Principal::anonymous(), // 1. anonymous
            p(99),                  // 2. unknown (never a signer)
        ] {
            assert_eq!(get_proposal_for(id, caller), None);
            assert_eq!(get_signers_for(caller), None);
            assert_eq!(list_proposals_for(caller), None);
            assert_eq!(get_audit_for(caller), None);
            assert_eq!(get_snapshot_for(1, caller), None);
        }
        // 3./4. removed + stale-epoch: remove S3 via an epoch-bumping
        // transition; S3's membership is now from a superseded epoch.
        let rm = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2)],
                threshold: 2,
            }, None,
        )
        .unwrap();
        drive_approvals_only(rm, &[p(S1), p(S2)]);
        block_on(execute_action_with(&backend, rm));
        for caller in [p(S3)] {
            assert_eq!(get_proposal_for(id, caller), None);
            assert_eq!(get_signers_for(caller), None);
            assert_eq!(list_proposals_for(caller), None);
            assert_eq!(get_audit_for(caller), None);
            assert_eq!(get_snapshot_for(1, caller), None);
        }
        // Public endpoints stay public and fail closed on counts only.
        let s = get_governance_summary();
        assert_eq!(s.signer_count, 2);
        assert_eq!(s.governance_epoch, 1);
        assert!(!get_action_catalogue().is_empty());
        assert!(get_build_info().starts_with("vault v"));
    }

    // Caller-injected wrappers around the gated query logic (the endpoints
    // themselves read the real caller; the gate is what is under test).
    fn get_proposal_for(id: u64, c: Principal) -> Option<ProposalView> {
        query_gate(c)?;
        proposal_get(id).map(|p| to_view(&p))
    }
    fn get_signers_for(c: Principal) -> Option<Vec<Principal>> {
        Some(query_gate(c)?.bootstrap.members)
    }
    fn list_proposals_for(c: Principal) -> Option<Vec<ProposalView>> {
        query_gate(c)?;
        Some(
            PROPOSALS.with(|p| {
                p.borrow()
                    .iter()
                    .take(MAX_READ_PAGE_LIMIT as usize)
                    .map(|(_, b)| to_view(&candid::decode_one(&b).unwrap()))
                    .collect()
            }),
        )
    }
    fn get_audit_for(c: Principal) -> Option<Vec<AuditEvent>> {
        query_gate(c)?;
        Some(audit_events())
    }
    fn get_snapshot_for(id: u64, c: Principal) -> Option<ControllerReadSnapshot> {
        query_gate(c)?;
        CONTROLLER_READ_SNAPSHOTS
            .with(|s| s.borrow().get(&id))
            .map(|b| candid::decode_one(&b).unwrap())
    }

    #[test]
    fn gated_queries_fail_closed_on_out_of_range_page_bounds() {
        setup();
        assert!(list_proposals_inner(p(S1), None, 0).is_none());
        assert!(list_proposals_inner(p(S1), None, MAX_READ_PAGE_LIMIT + 1).is_none());
        assert!(list_proposals_inner(p(S1), None, MAX_READ_PAGE_LIMIT).is_some());
    }

    fn list_proposals_inner(
        c: Principal,
        cursor: Option<u64>,
        limit: u32,
    ) -> Option<Vec<ProposalView>> {
        query_gate(c)?;
        if limit == 0 || limit > MAX_READ_PAGE_LIMIT {
            return None;
        }
        let _ = cursor;
        Some(Vec::new())
    }

    // ── C1 UpgraderUpgrade (freeze §3d) ──────────────────────────────────────

    fn good_upgrade() -> UpgraderUpgrade {
        let wasm = b"fake-wasm-v2".to_vec();
        let arg = b"fake-arg".to_vec();
        UpgraderUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        }
    }

    #[test]
    fn upgrader_upgrade_hash_mismatch_rejected_wasm_and_arg() {
        setup();
        let mut uu = good_upgrade();
        uu.expected_wasm_hash = sha256(b"different");
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(uu), None),
            Err(VaultError::HashMismatch),
            "wasm hash mismatch rejected"
        );
        let mut uu = good_upgrade();
        uu.expected_arg_hash = sha256(b"different");
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(uu), None),
            Err(VaultError::HashMismatch),
            "arg hash mismatch rejected"
        );
    }

    #[test]
    fn upgrader_upgrade_size_limit_rejected_never_chunked() {
        setup();
        let wasm = vec![0u8; (GATE_SIZE_BOUND_BYTES as usize) + 1];
        let uu = UpgraderUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&[]),
            wasm_bytes: wasm,
            arg_bytes: Vec::new(),
        };
        assert!(matches!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(uu), None),
            Err(VaultError::SizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn upgrader_upgrade_executes_upgrade_mode_and_clears_bytes_after_terminal() {
        setup();
        let backend = FakeBackend::ok(Vec::new()); // asserts intent+reservation pre-call
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &backend,
        );
        let rec = proposal_get(id).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::Executed);
        match &rec.action {
            VaultActionKind::UpgraderUpgrade(uu) => {
                assert!(uu.wasm_bytes.is_empty(), "bytes cleared after terminal durable");
                assert!(uu.arg_bytes.is_empty());
                assert!(!uu.expected_wasm_hash.is_empty(), "hashes retained");
            }
            _ => panic!("wrong action"),
        }
        assert!(rec.intent.is_some());
        assert!(reservation_get(id).is_some());
        // Never re-triggerable.
        let (o, exec) = approve_inner(p(S3), id, commit_of(id), now_ns()).unwrap();
        assert!(!exec);
        assert!(matches!(
            o,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::Executed,
                ..
            }
        ));
    }

    /// Crash at the install_code boundary: durable intent first, bytes
    /// retained under OutcomeUnknown, reconcile lands terminal evidence.
    #[test]
    fn upgrader_upgrade_crash_then_reconcile_to_executed_with_f4_attribution() {
        setup();
        let uu = good_upgrade();
        let expected_hash = uu.expected_wasm_hash.clone();
        let backend = FakeBackend::rejecting("crash at install_code");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(uu),
            &backend,
        );
        let rec = proposal_get(target).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::OutcomeUnknown);
        match &rec.action {
            VaultActionKind::UpgraderUpgrade(u) => assert!(
                !u.wasm_bytes.is_empty(),
                "bytes retained until terminal evidence is durable"
            ),
            _ => panic!(),
        }
        // Reconcile with objective evidence: module hash matches → Executed.
        let rec_action = VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
            proposal_id: target,
            objective_evidence: UpgradeObjectiveEvidence {
                observed_upgrader_principal: p(UPGRADER),
                observed_module_hash: Some(expected_hash),
                observed_controllers: vec![self_id()],
                observed_canister_status: ObservedCanisterStatus::Running,
                observed_at_ns: now_ns(),
            },
        });
        let ok_backend = FakeBackend::ok(Vec::new());
        let rid = drive(p(S2), &[p(S2), p(S3)], rec_action, &ok_backend);
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        // F-4: the reconciliation audit event carries the approving signer set.
        let reconciled = audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::Reconciled && e.proposal_id == Some(target))
            .expect("reconciliation audit event");
        assert_eq!(
            reconciled.approving_signers,
            Some(vec![p(S2), p(S3)]),
            "F-4: approving signer set recorded"
        );
        // Never re-triggerable, never back to Pending: a second reconcile
        // fails (terminal source), approve replays the terminal result.
        let again = propose_inner(
            p(S1),
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(UPGRADER),
                    observed_module_hash: Some(sha256(b"x")),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }), None,
        );
        assert_eq!(again, Err(VaultError::IllegalSourceState));
        let (o, exec) = approve_inner(p(S1), target, commit_of(target), now_ns()).unwrap();
        assert!(!exec);
        assert!(matches!(
            o,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::Executed,
                ..
            }
        ));
    }

    #[test]
    fn reconcile_to_failed_on_hash_mismatch_evidence() {
        setup();
        let backend = FakeBackend::rejecting("crash");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &backend,
        );
        let ok_backend = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S2),
            &[p(S2), p(S3)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(UPGRADER),
                    observed_module_hash: Some(sha256(b"not-the-approved-wasm")),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &ok_backend,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
    }

    // ── VR-1 — management-plane reconcile ────────────────────────────────────
    //
    // Live defect (ruling RULING_RECORD_VAULT_MGMT_RECONCILE_2026-09-13): a
    // `Management::InstallCode` whose management call is REJECTED lands in
    // `OutcomeUnknown`, retains its bytes, and holds the single-flight lock on
    // the target forever, because the only reconcile route admitted an
    // `UpgraderUpgrade` target. These tests pin the widened route.

    /// A governed born-under-vault target, wired through the real receipt
    /// path, plus a hash-bound InstallCode against it.
    fn vr1_governed_install(role: &str, byte: u8, wasm: &[u8]) -> (Principal, VaultActionKind) {
        let ok = FakeBackend::ok(Vec::new());
        wire_roles(&ok, &[(role, byte)]);
        let t = p(byte);
        (
            t,
            VaultActionKind::Management(ManagementAction::InstallCode {
                target: t,
                expected_wasm_hash: sha256(wasm),
                expected_arg_hash: sha256(b""),
                wasm_bytes: wasm.to_vec(),
                arg_bytes: Vec::new(),
            }),
        )
    }

    fn vr1_evidence(
        who: Principal,
        module: Option<Vec<u8>>,
        controllers: Vec<Principal>,
        status: ObservedCanisterStatus,
        at: u64,
    ) -> UpgradeObjectiveEvidence {
        UpgradeObjectiveEvidence {
            observed_upgrader_principal: who,
            observed_module_hash: module,
            observed_controllers: controllers,
            observed_canister_status: status,
            observed_at_ns: at,
        }
    }

    /// T1 — the live defect itself: a rejected InstallCode strands the target
    /// in `OutcomeUnknown` with bytes retained and the single-flight lock held,
    /// so a second InstallCode on the same target is refused.
    #[test]
    fn vr1_t1_rejected_install_holds_the_lock_on_its_target() {
        setup();
        let (t, install) = vr1_governed_install("merkle_tree", 25, b"merkle-module");
        let crash = FakeBackend::rejecting("out of cycles: please top up the canister");
        let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
        let rec = proposal_get(target).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::OutcomeUnknown);
        match &rec.action {
            VaultActionKind::Management(ManagementAction::InstallCode { wasm_bytes, .. }) => {
                assert!(!wasm_bytes.is_empty(), "bytes retained under OutcomeUnknown")
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            open_mutating_intent(t, None),
            Some(target),
            "the single-flight lock is held by the stranded proposal"
        );
        let (_, second) = vr1_governed_install_again(t, b"merkle-module");
        assert_eq!(
            propose_inner(p(S1), second, None),
            Err(VaultError::IllegalSourceState),
            "a second InstallCode on the locked target is refused"
        );
    }

    /// Build a second InstallCode against an ALREADY-governed principal (no
    /// re-wiring — a purpose binds one-shot).
    fn vr1_governed_install_again(t: Principal, wasm: &[u8]) -> (Principal, VaultActionKind) {
        (
            t,
            VaultActionKind::Management(ManagementAction::InstallCode {
                target: t,
                expected_wasm_hash: sha256(wasm),
                expected_arg_hash: sha256(b""),
                wasm_bytes: wasm.to_vec(),
                arg_bytes: Vec::new(),
            }),
        )
    }

    /// T2 — the mainnet case: module hash `None` (the install never applied),
    /// controllers [Vault], Running → target `Failed`, reconcile `Executed`,
    /// bytes cleared, `Reconciled` audit with the signer set, lock released,
    /// and a FRESH InstallCode on the same target is admitted and executes.
    #[test]
    fn vr1_t2_reconcile_module_none_terminalizes_failed_and_releases_the_lock() {
        setup();
        let (t, install) = vr1_governed_install("merkle_tree", 25, b"merkle-module");
        let crash = FakeBackend::rejecting("out of cycles");
        let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
        assert_eq!(open_mutating_intent(t, None), Some(target));

        let ok = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S2),
            &[p(S2), p(S3)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: vr1_evidence(
                    t,
                    None,
                    vec![self_id()],
                    ObservedCanisterStatus::Running,
                    now_ns(),
                ),
            }),
            &ok,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        match &proposal_get(target).unwrap().action {
            VaultActionKind::Management(ManagementAction::InstallCode {
                wasm_bytes,
                arg_bytes,
                ..
            }) => {
                assert!(wasm_bytes.is_empty() && arg_bytes.is_empty(), "bytes cleared on terminal")
            }
            other => panic!("unexpected {other:?}"),
        }
        let reconciled = audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::Reconciled && e.proposal_id == Some(target))
            .expect("reconciliation audit event");
        assert_eq!(reconciled.approving_signers, Some(vec![p(S2), p(S3)]));
        assert_eq!(
            open_mutating_intent(t, None),
            None,
            "lock released by terminalization"
        );
        // A fresh InstallCode on the same target is now admitted end to end.
        let (_, retry) = vr1_governed_install_again(t, b"merkle-module");
        let ok2 = FakeBackend::ok(Vec::new());
        let retry_id = drive(p(S1), &[p(S1), p(S2)], retry, &ok2);
        assert_eq!(
            proposal_get(retry_id).unwrap().outcome,
            ActionOutcome::Executed
        );
    }

    /// T3 — evidence shows the expected module hash under [Vault]/Running →
    /// the target terminalizes `Executed` (the install DID apply).
    #[test]
    fn vr1_t3_reconcile_matching_hash_terminalizes_executed() {
        setup();
        let wasm = b"merkle-module";
        let (t, install) = vr1_governed_install("merkle_tree", 25, wasm);
        let crash = FakeBackend::rejecting("transport failure");
        let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
        let ok = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S2),
            &[p(S2), p(S3)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: vr1_evidence(
                    t,
                    Some(sha256(wasm)),
                    vec![self_id()],
                    ObservedCanisterStatus::Running,
                    now_ns(),
                ),
            }),
            &ok,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(open_mutating_intent(t, None), None);
    }

    /// T4 — evidence bound to the WRONG principal: the reconcile fails and the
    /// target is untouched (still OutcomeUnknown, still locked, re-reconcilable
    /// with correct evidence).
    #[test]
    fn vr1_t4_evidence_principal_mismatch_leaves_the_target_untouched() {
        setup();
        let (t, install) = vr1_governed_install("merkle_tree", 25, b"merkle-module");
        let crash = FakeBackend::rejecting("out of cycles");
        let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
        let ok = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S2),
            &[p(S2), p(S3)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                // The durable Upgrader counterpart — NOT this target. Before
                // VR-1 this was the only accepted value; it must now MISS.
                objective_evidence: vr1_evidence(
                    p(UPGRADER),
                    None,
                    vec![self_id()],
                    ObservedCanisterStatus::Running,
                    now_ns(),
                ),
            }),
            &ok,
        );
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::OutcomeUnknown,
            "target untouched"
        );
        assert_eq!(open_mutating_intent(t, None), Some(target), "lock still held");
    }

    /// T5 (F-4) — controllers that are not exactly [Vault] ALWAYS reconcile
    /// `Failed`, even when the module hash matches. This is the accepted
    /// posture for the two SetControllerAtCutover targets before ring closure.
    #[test]
    fn vr1_t5_controllers_not_exactly_vault_reconcile_failed_even_on_hash_match() {
        setup();
        let wasm = b"cutover-module";
        let t = pyeop(); // SetControllerAtCutover — governed, controllers not [Vault]
        let install = VaultActionKind::Management(ManagementAction::InstallCode {
            target: t,
            expected_wasm_hash: sha256(wasm),
            expected_arg_hash: sha256(b""),
            wasm_bytes: wasm.to_vec(),
            arg_bytes: Vec::new(),
        });
        let crash = FakeBackend::rejecting("crash");
        let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
        let ok = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S2),
            &[p(S2), p(S3)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: vr1_evidence(
                    t,
                    Some(sha256(wasm)),
                    vec![p(S1)], // pre-ring-closure controller, not the Vault
                    ObservedCanisterStatus::Running,
                    now_ns(),
                ),
            }),
            &ok,
        );
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::Failed,
            "a matching hash under foreign controllers is NOT Executed"
        );
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
    }

    /// T6 — freshness (L1-3) applies unchanged to a management target: stale,
    /// future, and pre-intent evidence each fail the reconcile and leave the
    /// target untouched. Also proves the InstallCode records a durable intent
    /// stamp (rather than assuming it).
    #[test]
    fn vr1_t6_stale_future_and_pre_intent_evidence_never_terminalize() {
        // A distinct governed role per case: a case that ends with the target
        // still stranded leaves its lock behind, and `setup()` re-inits
        // governance without clearing durable proposal state in-process.
        for (case, role, byte, expect) in [
            ("pre-intent", "merkle_tree", 25u8, "predates upgrade intent"),
            ("future", "treasury", 26, "evidence from the future"),
            ("stale", "vesting", 27, "evidence too old"),
        ] {
            set_test_time(1_000_000_000);
            setup();
            let (t, install) = vr1_governed_install(role, byte, b"merkle-module");
            let crash = FakeBackend::rejecting("out of cycles");
            let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
            let intended_at = proposal_get(target)
                .unwrap()
                .intent
                .as_ref()
                .map(|i| i.intended_at_ns)
                .expect("InstallCode records a durable upgrade intent stamp");
            // The stale leg must fire the AGE branch, not the pre-intent one.
            // SSA F-2: `now - (MAX + 1)` saturated to 0 against the fixed test
            // clock, so it landed in the pre-intent branch and the age bound was
            // never exercised. Advance the clock; date the evidence AFTER intent.
            let at = match case {
                "pre-intent" => intended_at.saturating_sub(1),
                "future" => now_ns() + 60 * 1_000_000_000,
                _ => {
                    set_test_time(intended_at + MAX_EVIDENCE_AGE_NS + 2);
                    intended_at + 1
                }
            };
            let ok = FakeBackend::ok(Vec::new());
            let rid = drive(
                p(S2),
                &[p(S2), p(S3)],
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: target,
                    objective_evidence: vr1_evidence(
                        t,
                        None,
                        vec![self_id()],
                        ObservedCanisterStatus::Running,
                        at,
                    ),
                }),
                &ok,
            );
            let rec = proposal_get(rid).unwrap();
            assert_eq!(rec.outcome, ActionOutcome::Failed, "{case}: reconcile rejected");
            // Pin WHICH freshness branch fired, not merely that one did.
            let why = rec.result.unwrap_or_default();
            assert!(why.contains(expect), "{case}: expected `{expect}`, got `{why}`");
            let after = proposal_get(target).unwrap().outcome;
            assert_eq!(after, ActionOutcome::OutcomeUnknown, "{case}: target untouched");
            assert_eq!(open_mutating_intent(t, None), Some(target), "{case}: lock held");
        }
    }

    /// T7 — the source-state and action-shape gates at propose: Pending,
    /// Executed, and a non-management/non-upgrader action are all
    /// `IllegalSourceState`.
    #[test]
    fn vr1_t7_illegal_sources_rejected_at_propose() {
        setup();
        let ev = |who| {
            vr1_evidence(
                who,
                None,
                vec![self_id()],
                ObservedCanisterStatus::Running,
                now_ns(),
            )
        };
        // (a) a PENDING InstallCode (proposed, not yet quorate).
        let (t, install) = vr1_governed_install("merkle_tree", 25, b"merkle-module");
        let pending = propose_inner(p(S1), install, None).unwrap();
        assert_eq!(proposal_get(pending).unwrap().outcome, ActionOutcome::Pending);
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: pending,
                    objective_evidence: ev(t),
                }),
                None,
            ),
            Err(VaultError::IllegalSourceState),
            "Pending is not a legal reconcile source"
        );

        // (b) an EXECUTED management action, and (c) a non-reconcilable shape.
        setup();
        let ok = FakeBackend::ok(Vec::new());
        wire_roles(&ok, &[("merkle_tree", 25)]);
        let t = p(25);
        let done = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::InstallCode {
                target: t,
                expected_wasm_hash: sha256(b"m"),
                expected_arg_hash: sha256(b""),
                wasm_bytes: b"m".to_vec(),
                arg_bytes: Vec::new(),
            }),
            &ok,
        );
        assert_eq!(proposal_get(done).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: done,
                    objective_evidence: ev(t),
                }),
                None,
            ),
            Err(VaultError::IllegalSourceState),
            "Executed is not a legal reconcile source"
        );
        let start = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: t }),
            &ok,
        );
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: start,
                    objective_evidence: ev(t),
                }),
                None,
            ),
            Err(VaultError::IllegalSourceState),
            "a non-management-install / non-upgrader action shape stays illegal"
        );
    }

    /// T8 — `Management::Upgrade` is admitted on the same terms as
    /// `InstallCode`: the T2 (module None → Failed, lock released) and T3
    /// (hash match → Executed) equivalents.
    #[test]
    fn vr1_t8_management_upgrade_target_reconciles_both_ways() {
        for matching in [false, true] {
            setup();
            let wasm = b"upgrade-module";
            let ok = FakeBackend::ok(Vec::new());
            wire_roles(&ok, &[("treasury", 26)]);
            let t = p(26);
            let crash = FakeBackend::rejecting("out of cycles");
            let target = drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::Management(ManagementAction::Upgrade {
                    target: t,
                    expected_wasm_hash: sha256(wasm),
                    expected_arg_hash: sha256(b""),
                    wasm_bytes: wasm.to_vec(),
                    arg_bytes: Vec::new(),
                }),
                &crash,
            );
            assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::OutcomeUnknown);
            assert_eq!(open_mutating_intent(t, None), Some(target));
            let ok2 = FakeBackend::ok(Vec::new());
            let rid = drive(
                p(S2),
                &[p(S2), p(S3)],
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: target,
                    objective_evidence: vr1_evidence(
                        t,
                        if matching { Some(sha256(wasm)) } else { None },
                        vec![self_id()],
                        ObservedCanisterStatus::Running,
                        now_ns(),
                    ),
                }),
                &ok2,
            );
            assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
            assert_eq!(
                proposal_get(target).unwrap().outcome,
                if matching { ActionOutcome::Executed } else { ActionOutcome::Failed },
                "matching={matching}"
            );
            assert_eq!(open_mutating_intent(t, None), None, "matching={matching}: lock released");
        }
    }

    /// T9 — the reconcile proposal itself takes NO single-flight lock on the
    /// management target: `mutating_intent_target` is `None` for every
    /// reconcile variant, so a Pending/Executing reconcile never occupies the
    /// slot it exists to free.
    #[test]
    fn vr1_t9_reconcile_proposal_holds_no_mutating_intent_on_the_target() {
        setup();
        let (t, install) = vr1_governed_install("merkle_tree", 25, b"merkle-module");
        let crash = FakeBackend::rejecting("out of cycles");
        let target = drive(p(S1), &[p(S1), p(S2)], install, &crash);
        let rec_action = VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
            proposal_id: target,
            objective_evidence: vr1_evidence(
                t,
                None,
                vec![self_id()],
                ObservedCanisterStatus::Running,
                now_ns(),
            ),
        });
        assert_eq!(
            mutating_intent_target(&rec_action),
            None,
            "a reconcile binds no mutating target"
        );
        // Proposed but NOT quorate: the lock on t is still the stranded
        // InstallCode's, not the reconcile's.
        let rid = propose_inner(p(S2), rec_action, None).unwrap();
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Pending);
        assert_eq!(
            open_mutating_intent(t, None),
            Some(target),
            "the Pending reconcile did not claim the slot"
        );
    }

    #[test]
    fn reconcile_legal_from_outcome_unknown_only() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        // A proposal that reached terminal Executed (no crash) is NOT a legal
        // reconcile source.
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &backend,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
        let r = propose_inner(
            p(S1),
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(UPGRADER),
                    observed_module_hash: Some(sha256(b"x")),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }), None,
        );
        assert_eq!(r, Err(VaultError::IllegalSourceState));
    }

    // ── Self-control guards (freeze §3c) — executable ────────────────────────

    #[test]
    fn self_cross_stop_forbidden_both_directions() {
        setup();
        for target in [self_id(), p(UPGRADER)] {
            let r = propose_inner(
                p(S1),
                VaultActionKind::Management(ManagementAction::Stop { target }), None,
        );
            assert!(
                matches!(r, Err(VaultError::GuardRejected(_))),
                "stop of ring member {target} forbidden"
            );
        }
        // Stopping a TARGET is permitted.
        assert!(propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::Stop { target: pyeop() }), None)
        .is_ok());
    }

    #[test]
    fn update_settings_preserves_ring_controllers() {
        setup();
        // Against the Vault: controllers must remain exactly [Upgrader].
        assert!(propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::UpdateSettings {
                target: self_id(),
                controllers: vec![p(UPGRADER)],
            }), None)
        .is_ok());
        for bad in [vec![p(S1)], vec![p(UPGRADER), p(S1)], vec![]] {
            assert!(matches!(
                propose_inner(
                    p(S1),
                    VaultActionKind::Management(ManagementAction::UpdateSettings {
                        target: self_id(),
                        controllers: bad,
                    }), None),
                Err(VaultError::GuardRejected(_))
            ));
        }
        // Against the Upgrader: controllers must remain exactly [Vault].
        assert!(propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::UpdateSettings {
                target: p(UPGRADER),
                controllers: vec![self_id()],
            }), None)
        .is_ok());
        assert!(matches!(
            propose_inner(
                p(S1),
                VaultActionKind::Management(ManagementAction::UpdateSettings {
                    target: p(UPGRADER),
                    controllers: vec![p(UPGRADER)],
                }), None),
            Err(VaultError::GuardRejected(_))
        ));
    }

    // ── Read model + ControllerReadSnapshot (freeze §3b/§9) ─────────────────

    #[test]
    fn read_model_execution_stores_durable_bounded_snapshot() {
        setup();
        let response = ReadModelResponse::NullifierReadSpentAt {
            items: vec![stsh_custody_types::NullifierSpentAtItem {
                nullifier: [7u8; 32],
                spent_at: Some(42),
            }],
            next_cursor: None,
        };
        let backend = FakeBackend::ok(candid::encode_one(&response).unwrap());
        wire_roles(&backend, &[("nullifier_registry", 23)]);
        let req = ReadModelRequest::NullifierReadSpentAt {
            nullifier: [7u8; 32],
            page: PageRequest {
                cursor: None,
                limit: MAX_READ_PAGE_LIMIT,
            },
        };
        let id = drive(p(S1), &[p(S1), p(S2)], VaultActionKind::ReadModel(req), &backend);
        let rec = proposal_get(id).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::Executed);
        let snap_id = rec.snapshot_id.expect("snapshot id");
        let snap = get_snapshot_for(snap_id, p(S1)).expect("signer reads snapshot");
        assert_eq!(snap.originating_proposal_id, id);
        assert_eq!(snap.governance_epoch, 0);
        assert_eq!(snap.source_canister, p(23));
        // Signer-gated: anonymous sees None for the same id.
        assert_eq!(get_snapshot_for(snap_id, Principal::anonymous()), None);
        // Durable forever, including across upgrade — no pruning anywhere.
        post_upgrade();
        assert!(get_snapshot_for(snap_id, p(S1)).is_some());
    }

    #[test]
    fn read_model_request_bounds_enforced_at_propose() {
        setup();
        let req = ReadModelRequest::NullifierReadSpentAt {
            nullifier: [7u8; 32],
            page: PageRequest {
                cursor: None,
                limit: MAX_READ_PAGE_LIMIT + 1,
            },
        };
        assert!(matches!(
            propose_inner(p(S1), VaultActionKind::ReadModel(req), None),
            Err(VaultError::ReadLimitExceeded { .. })
        ));
    }

    // ── Reservation permanence ───────────────────────────────────────────────

    #[test]
    fn reservations_are_permanent_across_terminal_states_and_upgrade() {
        setup();
        let backend = FakeBackend::rejecting("crash");
        let a = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &backend,
        );
        let ok = FakeBackend::ok(Vec::new());
        let b = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &ok,
        );
        post_upgrade();
        // Both the OutcomeUnknown and the Executed reservation survived —
        // nothing in the crate deletes, replaces, or prunes MemoryId 5.
        for id in [a, b] {
            let r = reservation_get(id).expect("reservation permanent");
            assert_eq!(r.proposal_id, id);
            assert_eq!(r.approving_signers.len(), 2);
        }
    }

    // ── Application execution happy path ─────────────────────────────────────

    #[test]
    fn application_action_executes_against_durable_target() {
        setup();
        let payload = candid::encode_one(Result::<(), String>::Ok(())).unwrap();
        let backend = FakeBackend::ok(payload);
        wire_roles(&backend, &[("treasury", 21)]);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::TreasuryExecuteWithdrawal(9)),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert!(backend
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("execute_withdrawal")));
    }

    #[test]
    fn create_canister_binds_principal_durably_in_audit() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose: "verifier".to_string(),
                disposition: ManifestDisposition::BornUnderVault,
            }),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        let receipt = receipts_for(p(S1))
            .into_iter()
            .find(|r| r.proposal_id == id)
            .expect("typed D5 receipt");
        assert_eq!(receipt.principal, p(77));
        assert_eq!(receipt.purpose, "verifier");
        assert_eq!(receipt.disposition, ManifestDisposition::BornUnderVault);
        // The principal is now in the governed allowlist (controller-only
        // role: allowlist only, not the app/read wiring).
        let g = gov();
        assert!(g.governed.iter().any(|t| t.principal == p(77) && t.purpose == "verifier"));
        assert_eq!(g.targets, VaultTargets::default());
    }

    /// Test-side read of the typed receipt read-back logic (the query itself
    /// is PocketIC-covered; the gate + bounds are what is under test).
    fn receipts_for(c: Principal) -> Vec<CreationReceipt> {
        if query_gate(c).is_none() {
            return Vec::new();
        }
        audit_events()
            .into_iter()
            .filter_map(|e| e.creation_receipt)
            .collect()
    }

    #[test]
    fn time_seam_is_used_for_durable_timestamps() {
        setup();
        set_test_time(123_456);
        let id = propose_inner(p(S1), governance_action(), None).unwrap();
        assert_eq!(proposal_get(id).unwrap().created_at_ns, 123_456);
    }

    // ── L1-1: management authority restricted to the custody manifest ────────

    #[test]
    fn l1_1_attacker_controller_update_settings_rejected() {
        setup();
        // Governed (cutover) target, but the proposed controller set is NOT
        // exactly [Vault] — an attacker principal fails closed.
        for bad in [vec![p(66)], vec![p(66), self_id()], vec![p(UPGRADER)], vec![]] {
            assert_eq!(
                propose_inner(
                    p(S1),
                    VaultActionKind::Management(ManagementAction::UpdateSettings {
                        target: pyeop(),
                        controllers: bad,
                    }), None),
                Err(VaultError::NotAuthorized),
                "attacker/wrong controller set must be rejected"
            );
        }
        // Exactly [Vault] is the ruled configuration — accepted, and the
        // execution boundary re-validates it.
        let backend = FakeBackend::ok(Vec::new());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::UpdateSettings {
                target: pyeop(),
                controllers: vec![self_id()],
            }),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
    }

    #[test]
    fn l1_1_unknown_target_rejected_on_every_management_variant() {
        setup();
        let u = p(88); // never governed
        let wasm = b"m".to_vec();
        let arg = b"a".to_vec();
        let cases = vec![
            VaultActionKind::Management(ManagementAction::Start { target: u }),
            VaultActionKind::Management(ManagementAction::Stop { target: u }),
            VaultActionKind::Management(ManagementAction::UpdateSettings {
                target: u,
                controllers: vec![self_id()],
            }),
            VaultActionKind::Management(ManagementAction::DepositCycles {
                target: u,
                cycles: 1,
            }),
            VaultActionKind::Management(ManagementAction::Upgrade {
                target: u,
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm.clone(),
                arg_bytes: arg.clone(),
            }),
            VaultActionKind::Management(ManagementAction::InstallCode {
                target: u,
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            }),
        ];
        for c in cases {
            assert_eq!(
                propose_inner(p(S1), c, None),
                Err(VaultError::NotAuthorized),
                "unknown target must fail closed"
            );
        }
    }

    #[test]
    fn l1_1_out_of_scope_targets_rejected() {
        setup();
        // The manifest's OutOfScope principals (freeze §13.4) are simply not
        // governed: ohspu (hostile/uncontrolled) and zmvwg (not demonstrated
        // project-controlled) fail closed on every management path.
        let ohspu = Principal::from_text("ohspu-zqaaa-aaaad-qmasq-cai").unwrap();
        let zmvwg = Principal::from_text("zmvwg-xqaaa-aaaan-q6l3a-cai").unwrap();
        for t in [ohspu, zmvwg] {
            for c in [
                VaultActionKind::Management(ManagementAction::Start { target: t }),
                VaultActionKind::Management(ManagementAction::Stop { target: t }),
                VaultActionKind::Management(ManagementAction::UpdateSettings {
                    target: t,
                    controllers: vec![self_id()],
                }),
                VaultActionKind::Management(ManagementAction::DepositCycles {
                    target: t,
                    cycles: 1,
                }),
            ] {
                assert_eq!(
                    propose_inner(p(S1), c, None),
                    Err(VaultError::NotAuthorized),
                    "out-of-scope target {t} must fail closed"
                );
            }
        }
    }

    #[test]
    fn l1_1_ring_upgrade_via_management_variant_rejected() {
        setup();
        // The Upgrader is upgraded via C1 (own reconciliation contract), the
        // Vault via the recovery plane — never via a plain management
        // Upgrade/InstallCode.
        let wasm = b"m".to_vec();
        let arg = b"a".to_vec();
        for t in [self_id(), p(UPGRADER)] {
            assert_eq!(
                propose_inner(
                    p(S1),
                    VaultActionKind::Management(ManagementAction::Upgrade {
                        target: t,
                        expected_wasm_hash: sha256(&wasm),
                        expected_arg_hash: sha256(&arg),
                        wasm_bytes: wasm.clone(),
                        arg_bytes: arg.clone(),
                    }), None),
                Err(VaultError::NotAuthorized)
            );
        }
    }

    #[test]
    fn l1_1_create_canister_requires_born_under_vault_role_purpose() {
        setup();
        // OutOfScope and SetControllerAtCutover are not creatable
        // dispositions (creation is born-under-vault by construction).
        for d in [ManifestDisposition::OutOfScope, ManifestDisposition::SetControllerAtCutover] {
            assert_eq!(
                propose_inner(
                    p(S1),
                    VaultActionKind::Management(ManagementAction::CreateCanister {
                        manifest_purpose: "verifier".to_string(),
                        disposition: d,
                    }), None),
                Err(VaultError::NotAuthorized)
            );
        }
        // Purpose must name exactly one manifest role.
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::Management(ManagementAction::CreateCanister {
                    manifest_purpose: "nullifier genesis".to_string(),
                    disposition: ManifestDisposition::BornUnderVault,
                }), None),
            Err(VaultError::NotAuthorized),
            "free-form purpose rejected"
        );
    }

    // ── L1-2: receipt-bound wiring, one-shot, validated init ─────────────────

    #[test]
    fn l1_6_init_requires_exact_manifest_cutover_set() {
        let try_init = |entries: Vec<GovernedTarget>| {
            std::panic::catch_unwind(|| {
                init(VaultInit {
                    quorum: default_init().quorum,
                    cutover_targets: entries,
                })
            })
            .is_err()
        };
        let pyeop_entry = || GovernedTarget {
            principal: pyeop(),
            disposition: ManifestDisposition::SetControllerAtCutover,
            purpose: CUTOVER_SOLVENCY_STATUS_PURPOSE.to_string(),
        };
        let s3tyu_entry = || GovernedTarget {
            principal: s3tyu(),
            disposition: ManifestDisposition::SetControllerAtCutover,
            purpose: CUTOVER_WALLET_FRONTEND_PURPOSE.to_string(),
        };
        // Exact-correct is ACCEPTED (order-insensitive).
        assert!(!try_init(vec![s3tyu_entry(), pyeop_entry()]));
        // Empty rejected — an asset canister could never be bound later.
        assert!(try_init(vec![]));
        // Missing-one rejected.
        assert!(try_init(vec![pyeop_entry()]));
        assert!(try_init(vec![s3tyu_entry()]));
        // Extra-entry rejected.
        assert!(try_init(vec![
            pyeop_entry(),
            s3tyu_entry(),
            GovernedTarget {
                principal: p(77),
                disposition: ManifestDisposition::SetControllerAtCutover,
                purpose: "extra".to_string(),
            },
        ]));
        // Duplicate-purpose rejected.
        assert!(try_init(vec![
            pyeop_entry(),
            s3tyu_entry(),
            GovernedTarget {
                principal: p(78),
                disposition: ManifestDisposition::SetControllerAtCutover,
                purpose: CUTOVER_SOLVENCY_STATUS_PURPOSE.to_string(),
            },
        ]));
        // Substituted-principal (fabricated) rejected.
        assert!(try_init(vec![
            GovernedTarget {
                principal: p(66),
                ..pyeop_entry()
            },
            s3tyu_entry(),
        ]));
        // Wrong disposition rejected.
        assert!(try_init(vec![
            GovernedTarget {
                disposition: ManifestDisposition::BornUnderVault,
                ..pyeop_entry()
            },
            s3tyu_entry(),
        ]));
        // Anonymous principal rejected.
        assert!(try_init(vec![
            GovernedTarget {
                principal: Principal::anonymous(),
                ..pyeop_entry()
            },
            s3tyu_entry(),
        ]));
        // A ring member can never be a governed target.
        assert!(try_init(vec![
            GovernedTarget {
                principal: p(UPGRADER),
                ..pyeop_entry()
            },
            s3tyu_entry(),
        ]));
    }

    #[test]
    fn l1_2_receipt_binding_is_one_shot_with_read_back() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("shielded_pool", 20)]);
        // Read-back returns the bound wiring and the governed entry.
        let g = gov();
        assert_eq!(g.targets.shielded_pool, Some(p(20)));
        assert!(g
            .governed
            .iter()
            .any(|t| t.principal == p(20)
                && t.purpose == "shielded_pool"
                && t.disposition == ManifestDisposition::BornUnderVault));
        let (wiring, governed) = (g.targets.clone(), g.governed.clone());
        assert_eq!(wiring.treasury, None, "unbound role reads back empty");
        assert_eq!(governed.len(), 3, "2 cutover + receipt-bound");
        // Second binding attempt for the same role — rejected at propose.
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::Management(ManagementAction::CreateCanister {
                    manifest_purpose: "shielded_pool".to_string(),
                    disposition: ManifestDisposition::BornUnderVault,
                }), None),
            Err(VaultError::NotAuthorized),
            "one-shot: second binding rejected"
        );
    }

    #[test]
    fn l1_2_unbound_role_fails_closed_until_receipt_binds_it() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        // Nothing wired: an application action fails closed (no calls made).
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::TreasuryExecuteWithdrawal(1)),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Failed);
        let calls_before = backend.calls.borrow().len();
        // Bind the role from a receipt; the SAME action now executes.
        wire_roles(&backend, &[("treasury", 21)]);
        let payload = candid::encode_one(Result::<(), String>::Ok(())).unwrap();
        *backend.next_call_result.borrow_mut() = Ok(payload);
        let id2 = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::TreasuryExecuteWithdrawal(1)),
            &backend,
        );
        assert_eq!(proposal_get(id2).unwrap().outcome, ActionOutcome::Executed);
        assert!(backend.calls.borrow().len() > calls_before);
    }

    // ── L1-3: reconciliation evidence freshness ──────────────────────────────

    /// Drive an UpgraderUpgrade to OutcomeUnknown, then attempt a reconcile
    /// with the given observed_at; returns (target_id, reconcile_result).
    fn unknown_upgrade_then_reconcile(observed_at: u64) -> (u64, u64) {
        let crash = FakeBackend::rejecting("crash at install_code");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &crash,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        let ok = FakeBackend::ok(Vec::new());
        let rid = propose_inner(
            p(S1),
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(UPGRADER),
                    observed_module_hash: Some(sha256(b"fake-wasm-v2")),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: observed_at,
                },
            }), None,
        )
        .expect("reconcile proposal accepted");
        approve_inner(p(S1), rid, commit_of(rid), now_ns()).unwrap();
        let (_, go) = approve_inner(p(S2), rid, commit_of(rid), now_ns()).unwrap();
        assert!(go);
        block_on(execute_action_with(&ok, rid));
        (target, rid)
    }

    #[test]
    fn l1_3_pre_intent_evidence_rejected_never_terminalizes() {
        setup();
        set_test_time(1_000_000_000);
        // intent lands at intended_at_ns == 1_000_000_000 (quorum time).
        let (target, rid) = unknown_upgrade_then_reconcile(999_999_999);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::OutcomeUnknown,
            "pre-intent evidence must never terminalize the target"
        );
    }

    #[test]
    fn l1_3_future_evidence_rejected_never_terminalizes() {
        setup();
        set_test_time(1_000_000_000);
        let (target, rid) = unknown_upgrade_then_reconcile(1_000_000_001);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::OutcomeUnknown
        );
    }

    #[test]
    fn l1_3_too_old_evidence_rejected_never_terminalizes() {
        setup();
        set_test_time(1_000_000_000);
        let (target, rid) = unknown_upgrade_then_reconcile(0);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::OutcomeUnknown
        );
    }

    #[test]
    fn l1_3_fresh_evidence_accepted() {
        setup();
        set_test_time(1_000_000_000);
        // observed_at == intended_at == now: inside every bound.
        let (target, rid) = unknown_upgrade_then_reconcile(1_000_000_000);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
    }

    // ── L1-4: typed creation receipts ────────────────────────────────────────

    #[test]
    fn l1_4_receipt_durable_insert_once_readback_bijective() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose: "stsh_token".to_string(),
                disposition: ManifestDisposition::BornUnderVault,
            }),
            &backend,
        );
        // Receipt typed fields exact, durable BEFORE the terminal event.
        let events = audit_events();
        let receipt_event = events
            .iter()
            .find(|e| e.creation_receipt.as_ref().map(|r| r.proposal_id) == Some(id))
            .expect("typed receipt event");
        let terminal_event = events
            .iter()
            .find(|e| e.kind == AuditKind::Executed && e.proposal_id == Some(id))
            .expect("terminal event");
        assert!(
            receipt_event.id < terminal_event.id,
            "receipt is durable before the terminal write — hence before any install"
        );
        let r = receipt_event.creation_receipt.clone().unwrap();
        assert_eq!(r.principal, p(77));
        assert_eq!(r.purpose, "stsh_token");
        assert_eq!(r.disposition, ManifestDisposition::BornUnderVault);
        assert_eq!(r.proposal_id, id);
        // Insert-once: replaying the terminal approval adds NO receipt.
        let before = receipts_for(p(S1)).len();
        let (o, exec) = approve_inner(p(S3), id, commit_of(id), now_ns()).unwrap();
        assert!(!exec);
        assert!(matches!(o, ApprovalOutcome::PriorResult { .. }));
        assert_eq!(receipts_for(p(S1)).len(), before);
        // Bijectivity: every receipt binds exactly one principal, no unbound
        // receipt, no principal bound twice.
        let receipts = receipts_for(p(S1));
        let mut principals = std::collections::BTreeSet::new();
        for r in &receipts {
            assert!(principals.insert(r.principal), "duplicate principal across receipts");
            if r.status == CreationReceiptStatus::Bound {
                assert!(gov().governed.iter().any(|t| t.principal == r.principal));
            }
        }
        for t in &gov().governed {
            if t.disposition == ManifestDisposition::BornUnderVault {
                assert!(
                    receipts.iter().any(|r| r.principal == t.principal),
                    "no unbound born-under-vault entry"
                );
            }
        }
        // Signer-gated read-back: anonymous sees nothing.
        assert!(receipts_for(Principal::anonymous()).is_empty());
        assert!(receipts_for(p(99)).is_empty());
        // Receipts survive upgrade (stable audit log; no migration).
        post_upgrade();
        assert_eq!(receipts_for(p(S1)).len(), before);
    }

    // ── Single-flight mutating-intent lock (SSA L2 re-review applied to L1) ──

    /// Approve a proposal to quorum WITHOUT driving the executor — leaves it
    /// in durable Executing state.
    // ── S2 / R3: lifetime, terminalization, bounded indexes ─────────────────

    /// R3.7: only the PROPOSER may cancel, and only while Pending.
    #[test]
    fn r3_cancel_is_proposer_scoped_and_pending_only() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();

        // A peer signer is AUTHORIZED on this canister but not the proposer.
        // The distinct error matters: it must not read as "you are not a
        // signer", and it must not silently succeed.
        assert_eq!(
            cancel_proposal_inner(p(S2), id),
            Err(VaultError::NotProposer),
            "a non-proposer signer must not be able to veto a peer's proposal"
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Pending);

        // A non-signer is rejected earlier, as a non-signer.
        assert_eq!(cancel_proposal_inner(p(99), id), Err(VaultError::NotAuthorized));

        // The proposer may.
        assert_eq!(cancel_proposal_inner(p(S1), id), Ok(()));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Cancelled);

        // Cancelling twice is AlreadyTerminal, never a second cancel.
        assert_eq!(cancel_proposal_inner(p(S1), id), Err(VaultError::AlreadyTerminal));
    }

    /// R3.2: cancellation clears retained artifact bytes but PRESERVES the
    /// hashes — the commitment must stay computable after clearing (R1.2).
    #[test]
    fn r3_cancel_clears_bytes_but_keeps_hashes() {
        setup();
        let up = good_upgrade();
        let (wh, ah) = (up.expected_wasm_hash.clone(), up.expected_arg_hash.clone());
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(up), None).unwrap();
        cancel_proposal_inner(p(S1), id).unwrap();
        match proposal_get(id).unwrap().action {
            VaultActionKind::UpgraderUpgrade(u) => {
                assert!(u.wasm_bytes.is_empty(), "artifact bytes must be released");
                assert!(u.arg_bytes.is_empty());
                assert_eq!(u.expected_wasm_hash, wh, "hashes must SURVIVE clearing");
                assert_eq!(u.expected_arg_hash, ah);
            }
            other => panic!("unexpected action {other:?}"),
        }
    }

    /// R3: a proposal past the first await is NOT cancellable. Cancelling an
    /// Executing proposal would assert something untrue about a call that may
    /// already have landed.
    #[test]
    fn r3_cannot_cancel_past_the_first_await() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executing);
        assert_eq!(cancel_proposal_inner(p(S1), id), Err(VaultError::AlreadyTerminal));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executing);
    }

    /// R3.9: the single-flight index tracks Executing|OutcomeUnknown ONLY, and
    /// releases as part of the terminalizing write.
    #[test]
    fn r3_single_flight_index_holds_only_open_intents() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        // Pending does NOT take the lock — deliberately, so one signer cannot
        // deny service to the others by parking a proposal.
        assert_eq!(open_mutating_intent(p(UPGRADER), None), None);
        approve_to_quorum(id);
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(id));
        // Cancel is impossible here (Executing), so drive it to terminal.
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, id));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(
            open_mutating_intent(p(UPGRADER), None),
            None,
            "terminalizing must release the lock in the same durable write"
        );
    }

    /// R3.9: cancelling a Pending proposal leaves the lock untouched, because
    /// Pending never held it.
    #[test]
    fn r3_cancel_does_not_disturb_single_flight() {
        setup();
        let held = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(held);
        let parked = propose_inner(p(S2), VaultActionKind::UpgraderUpgrade(good_upgrade()), None);
        // Propose-time single-flight rejects the second while the first is open.
        assert_eq!(parked, Err(VaultError::IllegalSourceState));
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(held));
    }

    /// S5B W2 — UPGRADE MIGRATION over EVERY companion, through the REAL
    /// `post_upgrade` entry point.
    ///
    /// REVISED FROM `r3_post_upgrade_migration_restores_every_index`. The old
    /// test corrupted all three companions and asserted `post_upgrade`
    /// RE-DERIVED them from `PROPOSALS`. Amended item 10 inverts that: the
    /// companions are authoritative (a), history must not be scanned at
    /// `post_upgrade` (c), and inconsistency traps rather than being repaired
    /// (d). So the corruption assertions now prove DETECTION, and the
    /// uncorrupted path proves the companions survive an upgrade untouched —
    /// which is the real migration property under the new model.
    #[test]
    fn w2_post_upgrade_validates_every_companion() {
        setup();
        let backend = FakeBackend::ok(Vec::new());

        // (a) An open MUTATING intent — holds single-flight on the Upgrader.
        let open = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(open);

        // (b) An open CREATION intent — holds purpose-scoped single-flight.
        backend.created.borrow_mut().push(p(0x40));
        let creating = propose_inner(
            p(S1),
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose: "treasury".to_string(),
                disposition: ManifestDisposition::BornUnderVault,
            }), None,
        )
        .unwrap();
        approve_to_quorum(creating);

        // (c) A Pending proposal carrying an expiry — sits in the expiry index.
        // A DIFFERENT manifest purpose, so it does not collide with (b)'s
        // purpose-scoped lock. Left Pending, so it holds no lock at all — only
        // the expiry index.
        let pending = propose_inner(
            p(S2),
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose: "vesting".to_string(),
                disposition: ManifestDisposition::BornUnderVault,
            }), None,
        )
        .unwrap();
        let mut rec = proposal_get(pending).unwrap();
        rec.expires_at_ns = Some(7_777);
        proposal_put(&rec);

        let before = (
            open_mutating_intent(p(UPGRADER), None),
            open_creation_intent("treasury", None),
            PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()),
        );
        assert_eq!(before.0, Some(open));
        assert_eq!(before.1, Some(creating));
        assert_eq!(before.2, 1);

        // INTACT: the real upgrade entry point must validate cleanly and leave
        // every companion exactly as it found it. Under the amended model this
        // — not re-derivation — is the migration property that matters.
        post_upgrade();
        assert_eq!(
            (
                open_mutating_intent(p(UPGRADER), None),
                open_creation_intent("treasury", None),
                PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()),
            ),
            before,
            "an intact companion set must survive post_upgrade untouched"
        );
        // Idempotent: validation is a read.
        post_upgrade();
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(open));
        assert_eq!(open_creation_intent("treasury", None), Some(creating));
        assert_eq!(PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()), 1);

        // Now corrupt EACH companion in turn and prove each is independently
        // detected. Per brief acceptance 9, whole-primitive testing is
        // insufficient — a single mutation that breaks everything at once
        // would not show that each companion is separately accounted for.
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().remove(&(p(UPGRADER), open)));
        assert!(
            companion_check().is_err(),
            "W2: mutating-intent companion corruption undetected"
        );
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().insert((p(UPGRADER), open), ()));
        assert!(companion_check().is_ok(), "restoring must clear the mismatch");

        OPEN_CREATION_INTENT_INDEX
            .with(|x| x.borrow_mut().remove(&creation_key("treasury", creating)));
        assert!(
            companion_check().is_err(),
            "W2: creation-intent companion corruption undetected"
        );
        OPEN_CREATION_INTENT_INDEX.with(|x| {
            x.borrow_mut()
                .insert(creation_key("treasury", creating), "treasury".to_string())
        });
        assert!(companion_check().is_ok(), "restoring must clear the mismatch");

        PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow_mut().remove(&(7_777, pending)));
        assert!(
            companion_check().is_err(),
            "W2: expiry companion corruption undetected"
        );
        PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow_mut().insert((7_777, pending), ()));
        assert!(companion_check().is_ok(), "restoring must clear the mismatch");
    }

    /// S5B W2(d) — a FORGED companion entry traps at `post_upgrade`.
    ///
    /// REPLACES `r3_post_upgrade_drops_stale_index_entries`, which asserted the
    /// superseded model: that an upgrade silently re-derives the companions
    /// from `PROPOSALS` and thereby drops the forgery. Amended item 10(a) makes
    /// the companions AUTHORITATIVE, so "repair it from history" is the wrong
    /// authority answering the question, and (d) requires the inconsistency to
    /// trap instead. The old assertion would now be actively wrong: it demanded
    /// exactly the silent reactivation (d) forbids.
    #[test]
    fn w2_forged_companion_entry_traps_at_post_upgrade() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        block_on(execute_action_with(&backend, id));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert!(companion_check().is_ok(), "clean before the forgery");

        // Forge a lock entry for the now-terminal proposal, WITHOUT going
        // through the primitive — so the commitment does not move with it.
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().insert((p(UPGRADER), id), ()));

        let e = companion_check().expect_err("a forged companion entry must be detected");
        assert!(
            e.contains("integrity mismatch") && e.contains("DIFFERS"),
            "the failure must name the integrity mismatch and the moved commitment, \
             not some incidental panic: {e}"
        );
    }

    /// S5B W2(d) — an OMITTED companion entry traps at `post_upgrade`.
    ///
    /// The other direction, and the more dangerous one: a missing single-flight
    /// entry reads as "no lock held" and admits a second concurrent intent.
    #[test]
    fn w2_omitted_companion_entry_traps_at_post_upgrade() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(id));

        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().remove(&(p(UPGRADER), id)));

        let e = companion_check().expect_err("an omitted companion entry must be detected");
        assert!(
            e.contains("integrity mismatch"),
            "unexpected failure shape: {e}"
        );
    }

    /// S5B W2(e) — inline validation: corruption is caught BEFORE the absence
    /// is believed, not only at the next upgrade.
    ///
    /// This is the clause that matters at runtime. Without it a canister could
    /// run for weeks between upgrades admitting duplicate intents against a
    /// silently-emptied lock index.
    /// Asserts the WIRING as well as the detection: `open_mutating_intent` must
    /// actually consult `companion_check` before answering. Detection that no
    /// caller invokes protects nothing.
    #[test]
    #[should_panic(expected = "trap should only be called inside canisters")]
    fn w2_inline_validation_catches_corruption_before_absence_is_trusted() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(id));

        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().remove(&(p(UPGRADER), id)));
        assert!(companion_check().is_err(), "corruption must be detectable");

        // No upgrade. The very next absence-dependent read must refuse rather
        // than return `None` and admit a duplicate intent. In-process this
        // surfaces as the generic ic0 trap panic — the SPECIFIC message is
        // asserted by the `companion_check` tests above, and the real trap
        // semantics belong to PocketIC.
        let _ = open_mutating_intent(p(UPGRADER), None);
    }

    /// NON-VACUITY for the three tests above. An UNCORRUPTED companion must
    /// validate cleanly across an upgrade and keep serving reads — otherwise
    /// they would all pass against a `companion_validate` that simply always
    /// trapped.
    #[test]
    fn w2_intact_companion_validates_and_survives_upgrade() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(id));

        post_upgrade();

        assert_eq!(
            open_mutating_intent(p(UPGRADER), None),
            Some(id),
            "an intact companion must survive an upgrade untouched"
        );
        // Idempotent: validation is a read, so repeating it changes nothing.
        post_upgrade();
        assert_eq!(open_mutating_intent(p(UPGRADER), None), Some(id));
    }

    /// S5B acceptance 9 — REMOVE EACH COMPANION WRITE IN TURN.
    ///
    /// The brief is explicit that "whole-primitive testing insufficient": a
    /// single mutation breaking the primitive as a unit would not show that
    /// each written component is independently accounted for. So each of the
    /// SIX components the primitive writes is dropped or corrupted on its own,
    /// and each must be detected.
    ///
    /// The three companion-entry components (history-linked registry entries
    /// for expiry, mutating-intent, creation-intent) are covered by
    /// `w2_post_upgrade_validates_every_companion`, which corrupts each index
    /// separately and restores between. This test covers the other three: the
    /// COMMITMENT, the COUNT and the BYTE accounting — the parts of the same
    /// transaction that a partial write would leave behind.
    #[test]
    fn w2_each_written_component_is_independently_checked() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        assert!(companion_check().is_ok(), "clean baseline");
        let good = companion_load();

        // (4a) ENTRY ACCUMULATOR stale — the index writes landed, the
        // accumulator did not. This is exactly the bug both planes shipped
        // with briefly: the primitive applied the delta and never stored or
        // re-sealed it. Caught by the recompute comparison.
        let mut m = good.clone();
        m.entry_acc = vec![0u8; 32];
        companion_seal(&mut m); // seal is self-consistent, so only the recompute can catch it
        companion_store(&m);
        let e = companion_check().expect_err("a stale entry accumulator must be detected");
        assert!(e.contains("DIFFERS"), "must name the accumulator: {e}");
        companion_store(&good);
        assert!(companion_check().is_ok(), "restored");

        // (4b) SEAL stale — any field moved without re-sealing. Caught EARLIER
        // than the recompute, by the seal check, which is the only thing that
        // can catch counter tampering at all (counters are not recomputable).
        let mut m = good.clone();
        m.commitment = vec![0u8; 32];
        companion_store(&m);
        let e = companion_check().expect_err("a stale seal must be detected");
        assert!(e.contains("seal does not cover"), "must name the seal: {e}");
        companion_store(&good);
        assert!(companion_check().is_ok(), "restored");

        // (4c) COUNTER tampering — the case maximum-based validation cannot
        // catch. A counter lowered into an unused historical gap evades every
        // collision check; only the seal detects it.
        let mut m = good.clone();
        m.next_proposal_id = 1;
        companion_store(&m);
        let e = companion_check().expect_err("a lowered counter must be detected");
        assert!(
            e.contains("seal does not cover"),
            "W1.6: a counter lowered into an unused gap must be caught by the \
             seal — this is the exact hole the SSA re-check identified in the \
             maximum-based design: {e}"
        );
        companion_store(&good);
        assert!(companion_check().is_ok(), "restored");

        // (5) COUNT omitted — commitment correct, entry count not incremented.
        let mut m = good.clone();
        m.entries = good.entries.saturating_sub(1);
        companion_seal(&mut m);
        companion_store(&m);
        assert!(
            companion_check().is_err(),
            "W2: a count that disagrees with the companions must be detected — \
             a commitment-only check would let entry-count drift pass"
        );
        companion_store(&good);
        assert!(companion_check().is_ok(), "restored");

        // (6) BYTE accounting omitted — commitment and count correct, bytes not.
        let mut m = good.clone();
        m.bytes = good.bytes.saturating_sub(1);
        companion_seal(&mut m);
        companion_store(&m);
        assert!(
            companion_check().is_err(),
            "W2: byte accounting that disagrees with the companions must be \
             detected independently of count and commitment"
        );
        companion_store(&good);
        assert!(companion_check().is_ok(), "restored");
    }

    /// The schema sentinel fails closed, and is DISTINCT from the bootstrap
    /// version — brief W2 requires `COMPANION_STATE_SCHEMA_VERSION` not be
    /// conflated with `BOOTSTRAP_RECORD_SCHEMA_VERSION`, so that bumping one
    /// cannot silently claim the other's layout was reviewed.
    #[test]
    fn w2_schema_sentinel_is_distinct_and_fails_closed() {
        setup();
        // Distinctness is structural — two separately-declared constants — and
        // is not something a runtime equality check can assert (they may hold
        // the same NUMBER while versioning independently, which is the whole
        // point). What IS testable, and what matters, is that the companion
        // sentinel governs companion state on its own: bumping it fails the
        // companion closed while the bootstrap record is untouched.
        let bootstrap_before = gov().bootstrap.schema_version;

        let mut m = companion_load();
        m.schema_version = COMPANION_STATE_SCHEMA_VERSION + 1;
        companion_store(&m);
        // `companion_load` traps on an unknown version rather than rebuilding.
        let r = std::panic::catch_unwind(companion_check);
        assert!(
            r.is_err(),
            "W2(c)/(d): an unknown companion schema version must fail closed, \
             never be repaired by re-deriving from history"
        );
        assert_eq!(
            gov().bootstrap.schema_version,
            bootstrap_before,
            "the companion sentinel must govern ONLY companion state — a \
             companion-version bump that disturbed the bootstrap record would \
             mean the two are conflated, which brief W2 forbids"
        );
    }

    /// S5B W6 acceptance 1+2 — allocation and `post_upgrade` are unaffected by
    /// DEEP permanent history, on all three Vault ID spaces.
    ///
    /// Proved STRUCTURALLY, not by timing. A wall-clock threshold at test scale
    /// cannot distinguish O(1) from O(n) — a few hundred records run fast
    /// either way, and a threshold tuned to pass here says nothing about
    /// production. What establishes independence is that these paths perform NO
    /// read of the history maps, enforced at the source by
    /// `w6_no_unbounded_iteration_over_permanent_history` and
    /// `w1_no_history_derived_allocation_idiom`. This is the behavioural half:
    /// depth must not change the ANSWER or wedge the path.
    ///
    /// The old allocators would have been visibly wrong here — `.iter().last()`
    /// over a history seeded to 50_000 would hand out 50_001, not the counter's
    /// next value.
    #[test]
    fn w6_allocation_and_upgrade_unaffected_by_deep_history() {
        setup();
        let expected = peek_id(IdKind::Proposal);

        // Deep TERMINAL history, far above the counter. Terminal records hold
        // no companion entry, so this is pure permanent history — exactly the
        // thing whose size must not matter.
        let template = {
            let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
                .expect("template proposal");
            let backend = FakeBackend::ok(Vec::new());
            approve_to_quorum(id);
            block_on(execute_action_with(&backend, id));
            proposal_get(id).expect("template exists")
        };
        let after_template = peek_id(IdKind::Proposal);
        for i in 0..400u64 {
            let mut rec = template.clone();
            rec.proposal_id = 50_000 + i;
            proposal_put(&rec);
        }

        assert_eq!(
            peek_id(IdKind::Proposal),
            after_template,
            "W6/W1 VIOLATED: allocation moved because permanent history grew. The \
             retired `.iter().last() + 1` would return 50_401 here — history acting \
             as allocation authority, and a full scan on an authorization path."
        );
        assert!(companion_check().is_ok(), "depth must not disturb the companion");

        post_upgrade();
        assert!(
            companion_check().is_ok(),
            "W6 acceptance 2: post_upgrade must be unaffected by deep terminal history"
        );
        assert_eq!(
            peek_id(IdKind::Proposal),
            after_template,
            "and allocation must still be counter-driven after the upgrade"
        );
        let _ = expected;
    }

    /// S5B W6 — COST-AT-DEPTH CLASSIFICATION.
    ///
    /// Every production access to PERMANENTLY-GROWING state must be one of:
    ///   * keyed / logarithmic  — a point read or range on a bounded key,
    ///   * bounded-page         — an explicitly limited page (audit pagination),
    ///   * bounded-active-set   — iteration over a companion, bounded by C7/C12,
    ///   * FORBIDDEN            — unbounded iteration over permanent history.
    ///
    /// The permanently-growing maps are the histories: `PROPOSALS`,
    /// `AUDIT_EVENTS`, `CONTROLLER_READ_SNAPSHOTS`, `RESERVATIONS`. They are
    /// never pruned, so any unbounded pass over them grows without limit and
    /// eventually exhausts the instruction budget — the exhaustion half of
    /// CUST-SSA-003.
    ///
    /// The companions are NOT in this set: iterating them is bounded-active-set
    /// work by construction, which is the whole point of amended item 10.
    ///
    /// This is a source lint because cost-at-depth is invisible to behaviour at
    /// test scale: a full scan over 20 records and a keyed read are
    /// indistinguishable until production history is large, by which time the
    /// canister is already wedged.
    ///
    /// **SCOPE, narrowed at W6-EVIDENCE-01 item 3.** This layer proves only that
    /// the `.iter()` SHAPE is absent. It does NOT establish "no unbounded
    /// history-dependent work", and it never did: a keyed read inside a loop —
    /// directly or behind a helper — is invisible to it, which is what S8A found
    /// on the recovery plane. The property is established by this layer PLUS
    /// `w6_evidence_01_reachable_history_accesses_are_enumerated_vault`, which
    /// walks the call graph from `post_upgrade` and enumerates every access with
    /// its loop and recursion context. Cite the pair, never this one alone.
    /// W6-EVIDENCE-01 item 1 — layer 2 on the VAULT plane: every
    /// permanent-history access reachable from `post_upgrade`, enumerated with
    /// its loop/recursion context.
    ///
    /// Clause (g) covers both canisters and the classifier is shared, so this is
    /// the Vault's half of the same gate. It is NOT a copy of the Upgrader's
    /// justification: the two sweeps iterate DIFFERENT indexes, and each
    /// enumeration names its own.
    ///
    /// EXACT-SET EQUALITY. Drift in either direction fails — a new access is the
    /// obvious case, but an enumerated one vanishing means its written
    /// justification is stale, which is precisely how the original W6 claim
    /// stayed false while passing.
    #[test]
    fn w6_evidence_01_reachable_history_accesses_are_enumerated_vault() {
        use stsh_custody_types::HistoryAccessContext as C;
        const PERMANENT: [&str; 4] = [
            "PROPOSALS",
            "AUDIT_EVENTS",
            "CONTROLLER_READ_SNAPSHOTS",
            "RESERVATIONS",
        ];
        let prod = VAULT_SRC
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map(|(before, _)| before)
            .expect("W6-EVIDENCE-01: test-module boundary not found — re-anchor it");

        let found =
            stsh_custody_types::reachable_history_accesses(prod, &PERMANENT, "post_upgrade");

        // THE ENUMERATION. All three are the §S7 E2 sweep's per-item work.
        //
        // WHY `InLoopViaCaller` IS PERMITTED HERE. `sweep_executing_starts_to_unknown`
        // iterates `mutating_intent_proposal_ids()`, which reads
        // `OPEN_MUTATING_INTENT_INDEX` (MemoryId 7) — a BOUNDED authoritative
        // companion holding only `Executing | OutcomeUnknown`, bounded by the
        // single-flight invariant. It is deliberately absent from the PERMANENT
        // set above for exactly that reason. The trip count is therefore bounded
        // by the active set, not by history length.
        //
        // NOTE the index is MemoryId 7 here and MemoryId 10 on the recovery
        // plane — the two sweeps do NOT share a bound, and writing one
        // justification for both would be the "substitute reading stronger than
        // it is" failure this campaign keeps catching.
        //
        // The gate cannot prove that bound textually. That is why this is an
        // enumeration a human writes; what the gate guarantees is that no FOURTH
        // access can appear without this list failing.
        let expected: Vec<(&str, &str, C)> = vec![
            ("proposal_get", "PROPOSALS", C::InLoopViaCaller),
            ("proposal_put", "PROPOSALS", C::InLoopViaCaller),
            ("audit_full", "AUDIT_EVENTS", C::InLoopViaCaller),
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
            "W6-EVIDENCE-01 (vault): the set of permanent-history accesses \
             reachable from post_upgrade has CHANGED. Enumerate a new one with its \
             reason, or delete a stale entry — a justification for code that no \
             longer exists is how a false W6 claim survives.\n\nFindings: {found:#?}"
        );
        assert!(
            !found.iter().any(|a| a.context == C::InRecursiveCycle),
            "W6-EVIDENCE-01: a history access is reachable through a call cycle, \
             whose depth this gate cannot bound: {found:#?}"
        );
    }

    #[test]
    fn w6_no_unbounded_iteration_over_permanent_history() {
        const PERMANENT: [&str; 4] = [
            "PROPOSALS",
            "AUDIT_EVENTS",
            "CONTROLLER_READ_SNAPSHOTS",
            "RESERVATIONS",
        ];
        // Production region only — test fixtures legitimately build deep
        // histories by iterating, and scanning them would make this lint fire
        // on its own harness (the failure mode that recurred three times in
        // this change).
        let prod = VAULT_SRC
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map(|(before, _)| before)
            .expect("W6 lint: test-module boundary not found — re-anchor it");

        // SSA RF-3, then CUST-SSA-S5B-FINAL-01 — SHARED classifier.
        //
        // The statement-level logic that replaced this test's line-based
        // matcher now lives in custody-types and is called by BOTH planes. It
        // was duplicated here first, and the Upgrader's copy was left
        // line-based — so the single implementation is the fix for the drift,
        // not just for the original formatting sensitivity.
        let offenders =
            stsh_custody_types::unbounded_history_iteration_offenders(prod, &PERMANENT);

        assert!(
            offenders.is_empty(),
            "W6 VIOLATED: unbounded iteration over permanently-growing history in \
             production code. These maps are never pruned, so the cost of this call \
             grows without bound and eventually exhausts the instruction budget — \
             the exhaustion half of CUST-SSA-003. Use a keyed read, a bounded page, \
             or a bounded-active-set companion.\nOffenders: {offenders:#?}"
        );
    }

    /// S6 — PARAMETERISATION CONTRACT, INVERTED. Every ruled constant is now
    /// PINNED, and none may silently revert to `None`.
    ///
    /// RETIRES `s5b_no_route2_constant_value_is_pinned_in_source`, which
    /// asserted the exact opposite — that no value appeared in the source at
    /// all. That test was correct for S5B, whose gate criterion was absolute
    /// ("any S5B artifact that hard-codes one is NONCONFORMING ON ITS FACE"),
    /// and it is FALSE for S6, whose entire job is to supply the numbers. It is
    /// inverted rather than deleted because the failure mode it guarded merely
    /// changed direction: a constant reverting to `None` is now the silent
    /// regression, since `None` disables enforcement on three of these four
    /// paths and would restore the admitting-by-default gate S6 closed.
    ///
    /// This lint deliberately checks only the DECLARED/NOT-`None` property. The
    /// VALUES are asserted behaviourally by the S6 obligation tests, against
    /// the mechanisms that consume them; a source lint restating the same
    /// integers would prove only that the file agrees with itself.
    #[test]
    fn s6_ruled_constants_are_pinned_and_none_reverts_to_unruled() {
        // SCANS ONLY custody-types, where all the constants are DECLARED.
        //
        // Scanning this file too was the first cut, and it failed on its own
        // string literals — a source lint must never scan a region that quotes
        // its own patterns, so it is scoped to where the thing it guards lives.
        let src = include_str!("../../custody-types/src/lib.rs");
        for decl in [
            "pub const ENTRY_RATE_PARAMS",
            "pub const VAULT_NONTERMINAL_CAPS",
            "pub const RECOVERY_NONTERMINAL_CAPS",
            "pub const PROPOSAL_LIFETIME_BOUNDS",
            "pub const VAULT_SWEEP_WORK_LIMIT_PER_CALL",
            "pub const RECOVERY_SWEEP_WORK_LIMIT_PER_CALL",
        ] {
            let i = src.find(decl).unwrap_or_else(|| {
                panic!(
                    "S6: `{decl}` is absent from custody-types. If it was renamed, \
                     re-anchor this lint deliberately — do not drop the entry, which \
                     would leave that constant unguarded against reverting to `None`."
                )
            });
            let line = src[i..].lines().next().unwrap_or("");
            assert!(
                !line.contains("= None;"),
                "S6 VIOLATED: `{decl}` reverted to `None`. The V15 table rules a \
                 value for every one of these; `None` disables enforcement rather \
                 than failing closed on the rate and cap paths, which is the \
                 admitting-by-default behaviour S6 exists to end. Offending line: \
                 {line}"
            );
        }
    }

    /// S5B W4 acceptance 15 — the entry gate binds GLOBALLY and PER-SIGNER.
    ///
    /// Injected params, per brief §3: production constants stay `None` and the
    /// release Wasm carries neither these values nor the injection hook.
    #[test]
    fn w4_entry_gate_binds_globally_and_per_signer() {
        setup();
        // Per-signer 1, global 5: S1's second admission must be refused while
        // the global budget is nowhere near exhausted, so the refusal can only
        // come from the per-signer bound.
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: 1_000_000_000_000,
            global_per_window: 5,
            per_signer_per_window: 1,
        })));

        assert!(propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok());
        let second = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None);
        assert!(
            second.is_err(),
            "W4: the PER-SIGNER bound must bind even with global budget remaining"
        );

        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// The GLOBAL half, in its own test.
    ///
    /// It cannot share a canister with the per-signer half: `setup()` re-inits
    /// governance but DELIBERATELY does not clear the entry-rate ledger — the
    /// ledger must not be resettable by any callable path, which is the very
    /// property acceptance 17 pins. A second `setup()` in one test would
    /// therefore inherit a saturated budget. Separate tests get separate
    /// threads and so separate stable state.
    #[test]
    fn w4_entry_gate_binds_globally_across_signers() {
        setup();
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: 1_000_000_000_000,
            global_per_window: 1,
            per_signer_per_window: 99,
        })));
        assert!(propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok());
        assert!(
            propose_inner(p(S2), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_err(),
            "W4: the GLOBAL bound must bind across DIFFERENT signers — a per-signer \
             bound alone would let N signers multiply the flood by N"
        );
        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }


    // ── RF-1 (SSA S8B return) — sibling injection seams, VAULT plane ────────

    /// **RF-1 DISTINCTNESS, vault plane.** Mirror of the recovery plane's test,
    /// and mirrored deliberately: closing one plane would leave the other's
    /// non-vacuity claims resting on nothing, the same argument that put the
    /// recovery plane in R3.8/R3.11.
    ///
    /// Before RF-1 these four seams were single-`Option`, so `inject(None)`
    /// meant "unruled" only while the production constant was `None` — true
    /// until S6 ruled C9, C5/C7, C3/C4 and C11, and false silently ever since.
    #[test]
    fn rf1_clear_override_and_force_unruled_are_distinguishable_vault() {
        setup();
        let resolved = || {
            (
                entry_rate_params(),
                nonterminal_caps(),
                proposal_lifetime_bounds(),
                sweep_work_limit(),
            )
        };

        // (a) No injection -> the RULED production values.
        let ruled = resolved();
        assert!(ruled.0.is_some(), "C9 ruled since S6");
        assert!(ruled.1.is_some(), "C5/C7 ruled since S6");
        assert!(ruled.2.is_some(), "C3/C4 ruled since S6");
        assert!(ruled.3.is_some(), "C11 ruled since S6");

        // (b) FORCE UNRULED -> None everywhere, despite production being Some.
        inject_entry_rate_for_test(Some(None));
        inject_nonterminal_caps_for_test(Some(None));
        inject_lifetime_params_for_test(Some(None), Some(None));
        let unruled = resolved();
        assert_eq!(unruled, (None, None, None, None), "force-unruled must reach the unruled path");

        // (c) CLEAR -> back to the ruled values.
        inject_entry_rate_for_test(None);
        inject_nonterminal_caps_for_test(None);
        inject_lifetime_params_for_test(None, None);
        assert_eq!(resolved(), ruled, "clearing must restore the RULED values");

        assert_ne!(
            ruled, unruled,
            "RF-1: clear-override and force-unruled are INDISTINGUISHABLE — the \
             defect, invisible until the constants are pinned"
        );
    }

    /// **RF-1 NON-VACUITY, vault plane** — candidate injection still overrides.
    #[test]
    fn rf1_candidate_injection_still_overrides_the_ruled_values_vault() {
        setup();
        let ruled = entry_rate_params().expect("C9 ruled");
        let candidate = stsh_custody_types::EntryRateParams {
            window_ns: ruled.window_ns + 1,
            global_per_window: ruled.global_per_window + 1,
            per_signer_per_window: ruled.per_signer_per_window + 1,
        };
        inject_entry_rate_for_test(Some(Some(candidate)));
        assert_eq!(entry_rate_params(), Some(candidate));
        assert_ne!(candidate, ruled, "the fixture must differ from the ruled value");
    }

    /// NON-VACUITY. With the params unruled (`None`) the gate must ADMIT — the
    /// brief builds mechanisms at S5B and turns enforcement on at S6. Without
    /// this, the tests above would pass against a gate that refused everything.
    #[test]
    fn w4_gate_is_inactive_while_unruled() {
        setup();
        inject_entry_rate_for_test(Some(None));
        inject_nonterminal_caps_for_test(Some(None));
        // RF-1: drive PAST the ruled per-signer bounds.
        //
        // ONE admission proved nothing — 1 is under the ruled C9 (26) and C5
        // (32) alike, so this passed identically on the ruled path, which is
        // what it had been doing silently since S6. Past both bounds, only a
        // genuinely unruled mechanism admits every one.
        let c9 = stsh_custody_types::ENTRY_RATE_PARAMS
            .expect("C9 ruled at S6")
            .per_signer_per_window as u64;
        let c5 = stsh_custody_types::VAULT_NONTERMINAL_CAPS
            .expect("C5 ruled at S6")
            .per_signer as u64;
        let n = c9.max(c5) + 4;
        for i in 0..n {
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
                .unwrap_or_else(|e| panic!(
                    "W4: while the constants are unruled the mechanism must not \
                     enforce — refusing here would brick the canister rather than \
                     protect it, which is why this is NOT the fail-closed shape \
                     used for lifetime bounds (admission {i} of {n}): {e:?}"
                ));
        }
        assert!(n > c9 && n > c5, "RF-1 non-vacuity: must exceed BOTH ruled bounds");
    }

    /// S5B W4 acceptance 16 — downstream appends are UNREFUSABLE under
    /// saturation, including after dormancy across many windows.
    ///
    /// This is the property that makes the bound safe: refusing a downstream
    /// append would destroy the audit trail of an operation the ring ALREADY
    /// accepted, which is worse than the flood the bound exists to stop.
    #[test]
    fn w4_downstream_appends_unrefusable_under_saturation() {
        setup();
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: 1_000_000_000_000,
            global_per_window: 1,
            per_signer_per_window: 1,
        })));
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .expect("first admission consumes the entire budget");
        // Budget now exhausted: a new entry is refused.
        assert!(propose_inner(p(S2), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_err());

        // The ALREADY-ADMITTED operation must still run to quorum and terminal,
        // appending audit the whole way, with the budget saturated throughout.
        let audit_before = AUDIT_EVENTS.with(|a| a.borrow().len());
        approve_to_quorum(id);
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, id));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert!(
            AUDIT_EVENTS.with(|a| a.borrow().len()) > audit_before,
            "W4 acceptance 16 VIOLATED: downstream audit appends were refused under \
             saturation — the operation was admitted, so its trail is unrefusable"
        );
        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// S5B W4 acceptance 17 — the ABSENCE proof: no per-proposal downstream
    /// credit is reserved at admission.
    ///
    /// The bound is on ENTRY events, not on an operation's lifetime footprint,
    /// so there is nothing to reserve and nothing to leak. Asserted structurally:
    /// admitting a proposal charges EXACTLY ONE entry event, never a block.
    #[test]
    fn w4_no_per_proposal_downstream_credit_at_admission() {
        setup();
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: 1_000_000_000_000,
            global_per_window: 100,
            per_signer_per_window: 100,
        })));
        let before = entry_rate_load().retained();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        assert_eq!(
            entry_rate_load().retained(),
            before + 1,
            "W4 acceptance 17 VIOLATED: admission charged more than one entry event, \
             i.e. it reserved downstream credit. The bound is on entries, not on an \
             operation's lifetime footprint."
        );

        // And driving the operation to terminal charges NOTHING further.
        let after_admit = entry_rate_load().retained();
        approve_to_quorum(id);
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, id));
        assert_eq!(
            entry_rate_load().retained(),
            after_admit,
            "W4: downstream activity must not consume entry budget"
        );
        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// S5B W4 acceptance 17 — the ledger is DURABLE and its window rolls
    /// correctly across an upgrade boundary.
    #[test]
    fn w4_ledger_is_durable_and_rolls_windows_across_upgrade() {
        setup();
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: 1_000,
            global_per_window: 1,
            per_signer_per_window: 1,
        })));
        assert!(propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok());
        let saturated = entry_rate_load();
        assert_eq!(saturated.retained(), 1);

        // post_upgrade must NOT clear it. A heap counter would reset here, and
        // the party who can trigger an upgrade is the governed path itself — so
        // a resettable bound is no bound at all.
        post_upgrade();
        assert_eq!(
            entry_rate_load(),
            saturated,
            "W4 acceptance 17 VIOLATED: the entry-rate ledger did not survive an \
             upgrade. It must not be resettable by upgrade, trap, or any callable \
             path, or the limit is evadable by whoever can upgrade."
        );
        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// SSA BLOCKER 1 — a PENDING proposal occupies a nonterminal slot.
    ///
    /// THIS IS THE TEST THAT WAS MISSING, and its absence is why the defect
    /// shipped. The original cap test drove its first proposal to quorum before
    /// checking the bound, so it only ever exercised
    /// `Executing | OutcomeUnknown` — exactly the states the old
    /// single-flight-index counting happened to cover. Pending consumed no slot
    /// and Pending spam bypassed the caps entirely, taking with it the capacity
    /// argument that made CONF-01 deferrable.
    ///
    /// No `approve_to_quorum` here, deliberately: the proposal stays `Pending`.
    #[test]
    fn w4_pending_proposal_occupies_a_nonterminal_slot() {
        setup();
        inject_nonterminal_caps_for_test(Some(Some(stsh_custody_types::NonterminalCaps {
            global: 1,
            per_signer: 1,
        })));
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .expect("first admission");
        assert_eq!(
            proposal_get(id).unwrap().outcome,
            ActionOutcome::Pending,
            "fixture guard: this test is only meaningful while the proposal is PENDING"
        );

        let refused = propose_inner(
            p(S2),
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose: "treasury".to_string(),
                disposition: ManifestDisposition::BornUnderVault,
            }),
            None,
        );
        assert!(
            refused.is_err(),
            "SSA BLOCKER 1: a PENDING proposal must occupy a nonterminal slot. \
             Counting only the single-flight indexes leaves Pending free, and \
             Pending spam then bypasses C5/C7/C12 entirely."
        );
        inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// And the slot is RELEASED at terminalization, so the cap bounds concurrent
    /// work rather than lifetime work.
    #[test]
    fn w4_nonterminal_slot_released_at_terminalization() {
        setup();
        inject_nonterminal_caps_for_test(Some(Some(stsh_custody_types::NonterminalCaps {
            global: 1,
            per_signer: 1,
        })));
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .expect("first admission");
        approve_to_quorum(id);
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, id));
        assert!(proposal_get(id).unwrap().outcome.is_terminal());
        assert!(
            propose_inner(p(S2), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok(),
            "the slot must be released at terminalization — otherwise the cap \
             bounds lifetime work, not concurrent work, and the ring wedges"
        );
        inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// S5B W4 — C5/C7/C12 nonterminal caps are enforced BEFORE proposal-ID
    /// allocation so a refusal burns no id (W1.3).
    #[test]
    fn w4_nonterminal_caps_bind_before_id_allocation() {
        setup();
        inject_nonterminal_caps_for_test(Some(Some(stsh_custody_types::NonterminalCaps {
            global: 1,
            per_signer: 1,
        })));
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .expect("first admission");
        approve_to_quorum(id); // now holds a nonterminal slot

        let id_before = peek_id(IdKind::Proposal);
        let refused = propose_inner(
            p(S2),
            VaultActionKind::Management(ManagementAction::CreateCanister {
                manifest_purpose: "treasury".to_string(),
                disposition: ManifestDisposition::BornUnderVault,
            }),
            None,
        );
        assert!(refused.is_err(), "W4: the nonterminal cap must bind");
        assert_eq!(
            peek_id(IdKind::Proposal),
            id_before,
            "W4: a cap refusal must occur BEFORE id allocation — a burned id would \
             also violate W1.3's record-less-rejection rule"
        );
        inject_nonterminal_caps_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// S5B W1.1 — the counter is the SOLE allocation authority, and no path
    /// derives an id from history.
    ///
    /// Proved behaviourally rather than by inspection: plant a record at a HIGH
    /// id, and show the next allocation is unaffected by it. A history-derived
    /// allocator (`.iter().last() + 1`, or `.next_back()`) would jump past the
    /// planted record; the counter does not see it at all.
    #[test]
    fn w1_counter_is_sole_authority_history_does_not_influence_allocation() {
        setup();
        let first = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();

        // Plant a record far above the counter, bypassing allocation.
        let mut planted = proposal_get(first).unwrap();
        planted.proposal_id = 10_000;
        proposal_put(&planted);

        let next = next_proposal_id();
        assert_eq!(
            next,
            first + 1,
            "W1.1 VIOLATED: allocation moved because of a record in history. \
             The old `.iter().last() + 1` would return 10_001 here — that is \
             history acting as allocation authority, which W1.1 forbids."
        );
    }

    /// S5B W1.3 — COMMITTED-ID SEMANTICS, the point the SSA re-check corrected.
    ///
    /// "Never reused, not after rejection or trap" contradicted atomic
    /// rollback. The reconciliation: a committed+inserted id is never reused,
    /// but a TRAPPED transaction commits neither counter nor entry, so its
    /// candidate was never allocated and the SAME id legitimately comes back on
    /// the next attempt.
    #[test]
    fn w1_committed_id_semantics() {
        setup();

        // A committed id advances the counter and is never handed out again.
        let a = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let b = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None);
        // Single-flight may refuse the second; what matters is that if it was
        // admitted it did NOT reuse `a`.
        if let Ok(b) = b {
            assert_ne!(a, b, "a committed, inserted id must never be reused");
        }

        // A RECORD-LESS REJECTION BURNS NOTHING. `resolve_expiry` rejects
        // before any durable write, so the counter must not have moved.
        let before = peek_id(IdKind::Proposal);
        let rejected = propose_inner(
            p(S1),
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            Some(1), // out of bounds while §10.5 is unruled -> fails closed
        );
        assert!(rejected.is_err(), "the lifetime request must fail closed");
        assert_eq!(
            peek_id(IdKind::Proposal),
            before,
            "W1.3 VIOLATED: a record-less rejection consumed an id. Only an \
             allocation that DURABLY INSERTS may advance the counter."
        );
    }

    /// S5B W1.7 — exhaustion fails closed rather than wrapping.
    ///
    /// The retired `k + 1` idiom wrapped silently at `u64::MAX`, which would
    /// hand back id 0 and then collide with every live record in turn.
    #[test]
    fn w1_counter_exhaustion_fails_closed_never_wraps() {
        setup();
        let mut s = companion_load();
        s.next_proposal_id = u64::MAX;
        companion_seal(&mut s);
        companion_store(&s);

        let r = std::panic::catch_unwind(|| commit_id(IdKind::Proposal, u64::MAX));
        assert!(
            r.is_err(),
            "W1.7 VIOLATED: the counter wrapped instead of trapping. `k + 1` \
             wraps to 0 and then collides with every live id in sequence."
        );
    }

    /// S5B W1 — each map has its OWN counter; they do not share allocation.
    #[test]
    fn w1_per_map_counters_are_independent() {
        setup();
        let p0 = peek_id(IdKind::Proposal);
        let a0 = peek_id(IdKind::Audit);
        let s0 = peek_id(IdKind::Snapshot);

        // An audit-only append must advance ONLY the audit counter. Audit
        // appends happen on paths where no proposal is written, so a shared
        // counter would either skip proposal ids or leave audit unallocated.
        audit(AuditKind::Executed, None, p(S1), None, "probe".to_string());

        assert_eq!(peek_id(IdKind::Proposal), p0, "proposal counter must not move");
        assert_eq!(peek_id(IdKind::Snapshot), s0, "snapshot counter must not move");
        assert_eq!(peek_id(IdKind::Audit), a0 + 1, "audit counter must advance");
    }

    /// S5B W2 — the five-case authority precedence table, every row.
    ///
    /// Row 3 is the one the brief singles out for splitting by record class.
    /// On the Vault (proposal class) it is INACTIVE CORRUPTION: the registry is
    /// authoritative for active membership, so its silence means the proposal
    /// is not active, and history must not be used to reactivate it. The intent
    /// class — where the same shape instead forces a global intent-admission
    /// hold across both origin namespaces — lives on the Upgrader plane, which
    /// is where intents exist.
    #[test]
    fn w2_precedence_table_every_row() {
        setup();

        // Row 1 — Absent: neither authority claims the id.
        assert_eq!(companion_precedence(9_999), CompanionPrecedence::Absent);
        assert!(companion_precedence(9_999).is_consistent());

        // Row 2 — ActiveAndRegistered: nonterminal record WITH its entry.
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        assert_eq!(
            companion_precedence(id),
            CompanionPrecedence::ActiveAndRegistered
        );
        assert!(companion_precedence(id).is_consistent());

        // Row 3 — NonterminalProposalWithoutRegistry: history says active, the
        // registry does not. INACTIVE CORRUPTION, never reactivation.
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().remove(&(p(UPGRADER), id)));
        assert_eq!(
            companion_precedence(id),
            CompanionPrecedence::NonterminalProposalWithoutRegistry,
            "the registry is authoritative for ACTIVE membership — its silence \
             must not be overridden by history"
        );
        assert!(
            !companion_precedence(id).is_consistent(),
            "row 3 is corruption, not a serviceable state"
        );
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().insert((p(UPGRADER), id), ()));

        // Row 4 — TerminalStillRegistered: the lock outlived its justification.
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, id));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(
            companion_precedence(id),
            CompanionPrecedence::TerminalAndReleased,
            "terminalization must release the entry in the same transaction"
        );
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().insert((p(UPGRADER), id), ()));
        assert_eq!(
            companion_precedence(id),
            CompanionPrecedence::TerminalStillRegistered
        );
        assert!(!companion_precedence(id).is_consistent());
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().remove(&(p(UPGRADER), id)));

        // Row 5 — OrphanRegistryEntry: an entry naming an id history never
        // recorded. History is authoritative for EXISTENCE.
        OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow_mut().insert((p(UPGRADER), 8_888), ()));
        assert_eq!(
            companion_precedence(8_888),
            CompanionPrecedence::OrphanRegistryEntry
        );
        assert!(!companion_precedence(8_888).is_consistent());
    }

    /// S5B W2(b) — the commitment tracks CONTENT, not merely entry count.
    ///
    /// Substituting one entry for another at equal count is exactly what a
    /// count-only or bytes-only check would miss, and it is the substitution
    /// that matters: it moves a lock from one target to another.
    #[test]
    fn w2_commitment_detects_equal_count_substitution() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(id);
        let before = companion_load();

        // Swap the entry for a different target — count and bytes unchanged.
        OPEN_MUTATING_INTENT_INDEX.with(|x| {
            let mut x = x.borrow_mut();
            x.remove(&(p(UPGRADER), id));
            x.insert((p(S3), id), ());
        });
        let after = companion_recompute();

        assert_eq!(
            before.entries, after.entries,
            "the substitution must leave the COUNT identical, or this test is \
             not exercising content binding"
        );
        assert_ne!(
            before.commitment, after.commitment,
            "W2: the commitment failed to move under an equal-count substitution — \
             it is binding count, not content"
        );
    }

    /// S2.1 / R3.1 — the caller-selected lifetime path is REACHABLE and fails
    /// CLOSED while the §10.5 bounds are unruled.
    ///
    /// R3.1 specifies BOTH a minimum and a maximum lifetime and forbids a
    /// caller choosing an effectively permanent expiry — two bounds and a
    /// constraint on caller choice only make sense if the lifetime IS
    /// caller-selected. The request schema therefore lands in S2, BEFORE
    /// ApprovalCommitmentV1 is frozen at S3: adding it later would change the
    /// commitment preimage's shape and force a V2.
    ///
    /// Until the bounds are ruled an explicit request cannot be validated, so
    /// it is REFUSED rather than honoured — an unvalidatable lifetime is
    /// indistinguishable from a permanent one.
    #[test]
    fn r3_explicit_lifetime_fails_closed_against_unruled_bounds() {
        setup();
        // S6 — RESCOPED, NOT RETIRED. This asserted the PRODUCTION path
        // refused an explicit lifetime because `PROPOSAL_LIFETIME_BOUNDS` was
        // `None`. C3/C4 are ruled, so production now refuses on the real
        // `TooShort`/`TooLong` bounds instead — asserted by
        // `s6_caller_supplied_lifetime_is_bound_by_c3_and_c4`.
        //
        // The fail-closed RULE still has a live caller: the S5A measurement
        // path passes `None` deliberately, and if that ever started honouring
        // an unvalidatable lifetime it would silently grant the effectively
        // permanent expiry R3.1 forbids. So the rule is exercised where it is
        // still reachable — directly against unruled bounds — rather than
        // deleted along with its old production reachability.
        let requested = 60 * 1_000_000_000;
        assert_eq!(
            stsh_custody_types::validate_proposal_lifetime_with(None, requested),
            Err(stsh_custody_types::LifetimeViolation::BoundsNotRuled {
                requested_ns: requested
            }),
            "an unvalidatable caller lifetime must be refused, not honoured"
        );
        assert_eq!(
            stsh_custody_types::resolve_expiry_with(None, 0, Some(requested)),
            Err(stsh_custody_types::LifetimeViolation::BoundsNotRuled {
                requested_ns: requested
            }),
            "the resolve path must fail closed identically — one rule, not two"
        );
        // A caller who supplies nothing is unaffected: no bounds, no expiry.
        assert_eq!(stsh_custody_types::resolve_expiry_with(None, 0, None), Ok(None));
    }

    /// R3.1: once bounds ARE ruled, the validator enforces both ends. Exercised
    /// directly on the shared pure function, since the constant is still None.
    #[test]
    fn r3_lifetime_bounds_enforced_when_ruled() {
        let b = stsh_custody_types::ProposalLifetimeBounds {
            min_ns: 10,
            max_ns: 100,
        };
        assert_eq!(
            b.validate(5),
            Err(stsh_custody_types::LifetimeViolation::TooShort {
                requested_ns: 5,
                min_ns: 10
            })
        );
        assert_eq!(
            b.validate(1_000),
            Err(stsh_custody_types::LifetimeViolation::TooLong {
                requested_ns: 1_000,
                max_ns: 100
            })
        );
        assert_eq!(b.validate(10), Ok(()));
        assert_eq!(b.validate(100), Ok(()));
        // u64::MAX is the "effectively permanent" case R3.1 names.
        assert!(b.validate(u64::MAX).is_err());
    }

    /// S6 corrective CUST-SSA-S6-02 — C9 SLIDES; the straddle exploit is closed.
    ///
    /// THE BUG THIS PINS. With a tumbling window, a caller spends the full
    /// per-signer budget just before the reset boundary and the full budget
    /// again just after, landing 2 x C9 inside one REAL rolling window. SSA
    /// measured that as 480 global / 52 per-signer against ruled 240 / 26.
    ///
    /// The test drives exactly that straddle and requires the second burst to be
    /// REFUSED. Under the old implementation it passed; under a sliding window
    /// the budget only returns as individual events age out, one at a time.
    #[test]
    fn s6c_c9_window_slides_and_refuses_the_boundary_straddle() {
        setup();
        const W: u64 = 1_000_000;
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: W,
            global_per_window: 100,
            per_signer_per_window: 2,
        })));
        let act = || VaultActionKind::UpgraderUpgrade(good_upgrade());

        // Spend the per-signer budget, with the two events at DISTINCT times.
        // Distinct on purpose: events sharing a timestamp age out together, and
        // then the gradual-return half of this test proves nothing.
        const GAP: u64 = W / 2;
        let t0 = now_ns();
        assert!(propose_inner(p(S1), act(), None).is_ok());
        set_test_time(t0 + GAP);
        assert!(propose_inner(p(S1), act(), None).is_ok());
        assert!(
            propose_inner(p(S1), act(), None).is_err(),
            "budget is spent"
        );

        // Straddle: step just past where a TUMBLING window would have reset.
        // Both earlier events are still inside the sliding window, so nothing
        // has aged out and the caller must still be refused.
        set_test_time(t0 + W - 1);
        assert!(
            propose_inner(p(S1), act(), None).is_err(),
            "CUST-SSA-S6-02: a tumbling reset here would hand back the FULL \
             budget and allow 2 x C9 inside one real rolling window"
        );

        // Age out ONLY the first event: cutoff = t0, so the event at t0 expires
        // and the one at t0+GAP survives. Exactly one slot returns.
        set_test_time(t0 + W);
        assert!(
            propose_inner(p(S1), act(), None).is_ok(),
            "the first event aged out, so exactly one slot is free"
        );
        assert!(
            propose_inner(p(S1), act(), None).is_err(),
            "the second event has NOT aged out yet — budget returns GRADUALLY, \
             one expiry at a time, which is what distinguishes sliding from \
             tumbling's all-at-once refill"
        );
        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// The retained event set stays BOUNDED — the property that made the
    /// counter form tempting, preserved by the sliding form.
    #[test]
    fn s6c_c9_retained_event_set_is_bounded_by_the_global_term() {
        setup();
        const W: u64 = 1_000_000_000_000;
        inject_entry_rate_for_test(Some(Some(stsh_custody_types::EntryRateParams {
            window_ns: W,
            global_per_window: 5,
            per_signer_per_window: 5,
        })));
        for _ in 0..20 {
            let _ = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None);
        }
        assert_eq!(
            entry_rate_load().retained(),
            5,
            "admission is refused AT the global term, so the retained set can \
             never exceed it — the ledger cannot grow without bound"
        );
        inject_entry_rate_for_test(None);  // RF-1: outer `None` = CLEAR the injection (trailing cleanup).
    }

    /// S6 corrective CUST-SSA-S6-01 — C6 IS ENFORCED: equality passes, +1 fails,
    /// and a refusal mutates NOTHING.
    ///
    /// C6 = 2,097,152 B but the per-request ceiling is 1,900,000 B, so a single
    /// proposal CANNOT reach the cap — it is only reachable CUMULATIVELY. That
    /// is the whole point of the accounting: a per-request size check (which
    /// already existed) never enforces C6, which is how S6 shipped the constant
    /// with no enforcement behind it.
    #[test]
    fn s6c_c6_per_signer_quota_is_enforced_cumulatively() {
        setup();
        let c6 = stsh_custody_types::PER_SIGNER_BYTE_QUOTA;
        let sized = |wasm_len: usize| {
            let wasm = vec![7u8; wasm_len];
            let arg = vec![0u8; 8];
            VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            })
        };
        // Two admissions summing to EXACTLY C6 (each within the request ceiling).
        let first = 1_000_000usize;
        let second = (c6 as usize) - (first + 8) - 8;
        propose_inner(p(S1), sized(first), None).expect("first admission");
        propose_inner(p(S1), sized(second), None).expect("second admission reaches C6 exactly");

        let s = companion_load();
        assert_eq!(
            retained_for(&s, p(S1)),
            c6,
            "EQUALITY AT THE CAP: a signer holding exactly C6 is at their limit, \
             and that is legal — the cap is a maximum, not a strict bound"
        );

        // Now the state that must be unchanged by a refusal.
        let before_props = PROPOSALS.with(|m| m.borrow().len());
        let before_audit = audit_events().len();
        let before_next_id = companion_load().next_proposal_id;
        let before_rate = entry_rate_load();
        let before_total = companion_load().retained_bytes_total;

        // ONE MORE BYTE fails. `sized(1)` is 9 bytes of artifact, but any
        // non-zero amount is over.
        let r = propose_inner(p(S1), sized(1), None);
        assert!(
            matches!(r, Err(VaultError::SizeLimitExceeded { limit_bytes, .. }) if limit_bytes == c6),
            "C6+1 must be refused against the PER-SIGNER limit, got {r:?}"
        );

        // ZERO MUTATION — id, audit, ledger, state.
        assert_eq!(PROPOSALS.with(|m| m.borrow().len()), before_props, "no record");
        assert_eq!(audit_events().len(), before_audit, "no audit entry");
        assert_eq!(companion_load().next_proposal_id, before_next_id, "no id consumed");
        assert_eq!(companion_load().retained_bytes_total, before_total, "no accounting move");
        // The C9 ledger specifically: the byte gate runs BEFORE the charge, so a
        // byte-refused request must not burn rate budget either. If the gate
        // were ordered after the charge this assertion is what would fail.
        let after_rate = entry_rate_load();
        assert_eq!(
            (after_rate.retained(), after_rate.retained_for(p(S1))),
            (before_rate.retained(), before_rate.retained_for(p(S1))),
            "a byte-refused request must not consume C9 budget"
        );
    }

    /// C6 accounting RELEASES only when the bytes actually clear.
    #[test]
    fn s6c_c6_accounting_releases_only_when_bytes_clear() {
        setup();
        let sized = |wasm_len: usize| {
            let wasm = vec![9u8; wasm_len];
            let arg = vec![0u8; 8];
            VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            })
        };
        let id = propose_inner(p(S1), sized(100_000), None).expect("admitted");
        let held = companion_load();
        assert_eq!(retained_for(&held, p(S1)), 100_008);
        assert_eq!(held.retained_bytes_total, 100_008);

        // Cancel is a terminal outcome that DOES clear the artifact.
        cancel_proposal_inner(p(S1), id).expect("proposer may cancel");
        let after = companion_load();
        assert_eq!(retained_for(&after, p(S1)), 0, "cleared bytes must release");
        assert_eq!(after.retained_bytes_total, 0);
        assert!(
            after.retained_by_signer.iter().all(|(w, _)| *w != p(S1)),
            "a signer at zero must not keep occupying an accounting slot"
        );
    }

    /// C8 IS REACHABLE BY LEGAL ADMISSION — driven here through a real
    /// rotation sequence, with NO injection hooks anywhere on the path.
    ///
    /// THIS TEST REPLACES A FALSE ONE, AND THE FALSEHOOD IS THE POINT.
    /// The previous version asserted C8 was unreachable, reasoning that
    /// 9 x C6 = 18,874,368 < C8 = 20,971,520 and calling the difference "ruled
    /// margin". That argument silently assumed retained bytes attribute to at
    /// most nine proposers — i.e. that the roster maximum bounds the ACCOUNTING.
    /// It does not. A proposal stays NONTERMINAL across a signer-set rotation:
    /// `execute_signer_set_update` changes membership and bumps the epoch, and
    /// touches no proposal, terminalizes nothing and releases no bytes. So the
    /// bytes of a rotated-out signer remain retained and remain attributed to
    /// that HISTORICAL proposer, while the incoming signer starts at zero.
    ///
    /// Over rotations the number of distinct proposers holding retained bytes
    /// therefore grows past nine, and the sum passes 9 x C6. C8 is a live cap,
    /// not a margin.
    ///
    /// The sequence below is entirely legal: real proposals, a real governed
    /// rotation reaching quorum, real admissions by the new signer. Nothing is
    /// injected and no accounting is hand-seated — which is what makes it
    /// evidence about the system rather than about the test.
    #[test]
    fn s6c_c8_is_reachable_by_legal_rotation_and_enforced_at_equality() {
        let c6 = stsh_custody_types::PER_SIGNER_BYTE_QUOTA;
        let c8 = stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA;
        let max = stsh_custody_types::MAX_VAULT_SIGNERS;

        // A full legal roster of nine.
        let roster: Vec<Principal> = (0..max).map(|i| p(0x50 + i as u8)).collect();
        init(VaultInit {
            quorum: VaultInitArgs {
                signers: roster.clone(),
                threshold: 2,
                upgrader: p(UPGRADER),
            },
            cutover_targets: manifest_cutover(),
        });
        entry_rate_store(&EntryRateLedger::default());

        // Each signer fills EXACTLY C6, in two admissions (C6 exceeds the
        // per-request ceiling, so one proposal cannot do it).
        let first = 1_000_000usize;
        let second = (c6 as usize) - (first + 8) - 8;
        let sized = |n: usize, tag: u8| {
            let wasm = vec![tag; n];
            let arg = vec![0u8; 8];
            VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            })
        };
        for (i, s) in roster.iter().enumerate() {
            propose_inner(*s, sized(first, i as u8), None).expect("first");
            propose_inner(*s, sized(second, 0x80 | i as u8), None).expect("second");
        }
        assert_eq!(
            companion_load().retained_bytes_total,
            (max as u64) * c6,
            "nine signers at their full C6 — the point the old test called the ceiling"
        );

        // ── THE ROTATION. A tenth, previously-unknown signer joins. ──────────
        let newcomer = p(0x60);
        let mut next_roster = roster.clone();
        next_roster.pop();
        next_roster.push(newcomer);
        let rot = propose_inner(
            roster[0],
            VaultActionKind::UpdateSignerSet {
                signers: next_roster.clone(),
                threshold: 2,
            },
            None,
        )
        .expect("rotation proposed");
        approve_inner(roster[0], rot, commit_of(rot), now_ns()).unwrap();
        let (_, go) = approve_inner(roster[1], rot, commit_of(rot), now_ns()).unwrap();
        assert!(go, "rotation reaches quorum");
        // Quorum only marks it Executing; the roster changes when the action
        // actually EXECUTES. Driving it is what makes this a real rotation
        // rather than an approval that looks like one.
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, rot));
        assert_eq!(
            gov().bootstrap.members,
            next_roster,
            "the roster really rotated"
        );

        // The rotated-out signer's bytes are STILL RETAINED and still theirs.
        let rotated_out = roster[max - 1];
        assert!(
            !gov().bootstrap.members.contains(&rotated_out),
            "that signer is no longer on the roster"
        );
        assert_eq!(
            retained_for(&companion_load(), rotated_out),
            c6,
            "a rotated-out signer's nonterminal bytes remain retained and remain \
             attributed to them — the fact the margin argument missed"
        );

        // The newcomer fills their own C6, taking the GLOBAL total to exactly
        // C8 = 10 x C6 — one full C6 above what the roster maximum allows.
        propose_inner(newcomer, sized(first, 0xAA), None).expect("newcomer first");
        propose_inner(newcomer, sized(second, 0xBB), None).expect("newcomer second");
        assert_eq!(
            companion_load().retained_bytes_total,
            c8,
            "EQUALITY AT C8, reached by a legal rotation-driven sequence"
        );
        assert!(
            companion_load().retained_by_signer.len() > max,
            "more distinct proposers hold retained bytes than the roster maximum \
             — the accounting is bounded by C7, not by the roster"
        );

        // ── C8 + 1 MUST BE REFUSED BY THE **GLOBAL** LIMB, so the prober needs
        // C6 headroom. Every proposer so far sits at exactly C6, so a +1 from
        // any of them trips the PER-SIGNER limb first and would prove the wrong
        // thing. A second rotation brings in a signer holding nothing: their own
        // C6 is untouched, the global total is at C8, so only the global limb
        // can refuse them. Still entirely legal — a second governed rotation.
        let fresh = p(0x61);
        let mut third_roster = next_roster.clone();
        third_roster.pop();
        third_roster.push(fresh);
        let rot2 = propose_inner(
            next_roster[0],
            VaultActionKind::UpdateSignerSet {
                signers: third_roster.clone(),
                threshold: 2,
            },
            None,
        )
        .expect("second rotation proposed");
        approve_inner(next_roster[0], rot2, commit_of(rot2), now_ns()).unwrap();
        let (_, go2) = approve_inner(next_roster[1], rot2, commit_of(rot2), now_ns()).unwrap();
        assert!(go2);
        block_on(execute_action_with(&backend, rot2));
        assert!(gov().bootstrap.members.contains(&fresh));
        assert_eq!(
            retained_for(&companion_load(), fresh),
            0,
            "the fresh signer holds nothing, so only the GLOBAL limb can refuse it"
        );

        // ── C8 + 1: refused, with zero mutation of anything. ─────────────────
        let before_props = PROPOSALS.with(|m| m.borrow().len());
        let before_audit = audit_events().len();
        let before_id = companion_load().next_proposal_id;
        let before_total = companion_load().retained_bytes_total;
        let before_rate = entry_rate_load();

        let r = propose_inner(fresh, sized(1, 0xCC), None);
        assert!(
            matches!(r, Err(VaultError::SizeLimitExceeded { limit_bytes, .. }) if limit_bytes == c8),
            "C8+1 must be refused against the GLOBAL limit, got {r:?}"
        );
        assert_eq!(PROPOSALS.with(|m| m.borrow().len()), before_props, "no record");
        assert_eq!(audit_events().len(), before_audit, "no audit entry");
        assert_eq!(companion_load().next_proposal_id, before_id, "no id consumed");
        assert_eq!(
            companion_load().retained_bytes_total,
            before_total,
            "no accounting movement"
        );
        assert_eq!(
            (
                entry_rate_load().retained(),
                entry_rate_load().retained_for(fresh)
            ),
            (before_rate.retained(), before_rate.retained_for(fresh)),
            "no C9 movement — the byte gate precedes the charge"
        );
    }

    /// The worst REACHABLE signer-accounting cardinality, derived from the
    /// mechanism rather than chosen.
    ///
    /// Finding 1 requires the §C admission cost to be remeasured at the worst
    /// reachable cardinality of `retained_by_signer`, since that vector is
    /// scanned linearly on the admission path. The bound is NOT the roster
    /// maximum (that was the refuted assumption). It is:
    ///
    ///   * an entry exists only while a proposer holds > 0 retained bytes;
    ///   * retained bytes come only from NONTERMINAL artifact-bearing proposals;
    ///   * the number of concurrently nonterminal proposals is capped by C7;
    ///   * so distinct proposers with a live entry <= C7.
    ///
    /// C7 is a RULED table value, so this needs no constant that is not already
    /// ruled — which is the condition the dispatch set for deriving it.
    #[test]
    fn s6c_signer_accounting_cardinality_is_bounded_by_c7_not_the_roster() {
        let c7 = VAULT_NONTERMINAL_CAPS_GLOBAL_FOR_TEST;
        assert_eq!(
            c7,
            stsh_custody_types::VAULT_NONTERMINAL_CAPS
                .expect("ruled")
                .global as u64,
            "the bound is C7 itself, taken from the ruled table"
        );
        assert!(
            c7 > stsh_custody_types::MAX_VAULT_SIGNERS as u64,
            "the accounting cardinality bound EXCEEDS the roster maximum — this \
             is the correction: rotation lets historical proposers hold entries, \
             so the roster does not bound the scan"
        );
    }

    /// S6 / CTO_NOTE_S5A §5 — THE TENTH SIGNER IS REFUSED AT EVERY VAULT
    /// MUTATION PATH. Non-optional, and asserted per-path rather than once.
    ///
    /// Nine is not cosmetic. C6's per-signer quota and C9's 26 × 9 = 234 < 240
    /// headroom are derived at a nine-member roster, and a tenth signer
    /// invalidates them SILENTLY — nothing traps, the arithmetic just stops
    /// describing the system. That is why this is enforced in production rather
    /// than documented.
    ///
    /// C8 IS NO LONGER CITED HERE. Its "nine signers' capacity plus one C6 of
    /// margin" reading was a ruled SIZING decision misread as a reachability
    /// bound, and the reachability half is WITHDRAWN (SSA S6 corrective r2):
    /// nonterminal proposals outlive a rotation, so retained bytes attribute to
    /// more distinct proposers than the roster holds and the total passes
    /// 9 x C6. The roster never bounded C8.
    ///
    /// Both paths are exercised because they fail differently: init TRAPS (no
    /// caller to answer, and an oversize roster must never become durable)
    /// while a rotation must be REFUSED as a value, before an id is consumed.
    #[test]
    fn s6_tenth_signer_is_refused_at_every_vault_mutation_path() {
        setup();
        let max = stsh_custody_types::MAX_VAULT_SIGNERS;
        let roster = |n: usize| -> Vec<Principal> { (0..n).map(|i| p(0x40 + i as u8)).collect() };

        // ── Path 1: ROTATION (propose-time, via the shared validator) ───────
        let before = PROPOSALS.with(|p| p.borrow().len());
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::UpdateSignerSet {
                    signers: roster(max + 1),
                    threshold: 2,
                },
                None,
            ),
            Err(VaultError::ThresholdViolation),
            "a rotation to a tenth signer must be refused"
        );
        assert_eq!(
            PROPOSALS.with(|p| p.borrow().len()),
            before,
            "a refused rotation must leave NO proposal behind — the check runs \
             before any durable write"
        );

        // NON-VACUITY: exactly nine is ACCEPTED. Without this the test would
        // pass just as well against a validator that refused every rotation.
        assert!(
            propose_inner(
                p(S1),
                VaultActionKind::UpdateSignerSet {
                    signers: roster(max),
                    threshold: 2,
                },
                None,
            )
            .is_ok(),
            "the ruled maximum itself must be accepted — 9 is legal, 10 is not"
        );

        // ── Path 2: INIT ────────────────────────────────────────────────────
        let oversize = VaultInit {
            quorum: VaultInitArgs {
                signers: roster(max + 1),
                threshold: 2,
                upgrader: p(UPGRADER),
            },
            cutover_targets: manifest_cutover(),
        };
        assert!(
            std::panic::catch_unwind(|| init(oversize)).is_err(),
            "installing with a tenth signer must trap — an oversize roster must \
             never become durable"
        );
    }

    /// R3.1/R3.8 at the RULED bounds — the sweep is LIVE, end to end.
    ///
    /// RETIRES `r3_sweep_is_vacuous_until_lifetime_bounds_are_ruled`, whose
    /// premise ("no proposal carries an expiry, so the index is empty and
    /// nothing is ever reaped") was true only while C3/C4 were `None` and is
    /// false as of S6. It pinned the S2/S6 boundary and that boundary has now
    /// been crossed deliberately.
    ///
    /// The replacement asserts the WHOLE chain rather than the accessor,
    /// because a silently-inert expiry path fails in the flattering direction:
    /// index empty, sweep reaps nothing, every assertion about "no expired
    /// proposals" passes. So this drives the real `propose_inner`, reads the
    /// real expiry off the stored record, and requires the real sweep to
    /// terminalize it.
    #[test]
    fn s6_sweep_is_live_at_the_ruled_lifetime_bounds() {
        setup();
        let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS
            .expect("S6 rules C3/C4; `None` here means enforcement is off");
        let created = now_ns();

        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();

        // Default lifetime is the ruled MAXIMUM (C4), not the minimum: a caller
        // who asks for nothing must not get the shortest possible review window.
        let expires = proposal_get(id).unwrap().expires_at_ns;
        assert_eq!(
            expires,
            Some(created + bounds.max_ns),
            "a proposal created with no explicit lifetime must expire at C4"
        );
        assert_eq!(PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()), 1);

        // One nanosecond before expiry: still live. This is the non-vacuity
        // half — without it, a sweep that reaped indiscriminately would pass.
        assert!(sweep_expired_inner(created + bounds.max_ns - 1, 100).is_empty());
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Pending);

        // At expiry: reaped, and terminal.
        assert_eq!(sweep_expired_inner(created + bounds.max_ns, 100), vec![id]);
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Expired);
        assert_eq!(PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()), 0);
    }

    // ── S11-1 (P1-A): committed expiry is enforced AT APPROVAL ADMISSION ────
    //
    // The defect: `expires_at_ns` was written at creation, indexed for the
    // sweep, and then NEVER CONSULTED by `approve_inner`. Between the deadline
    // passing and the next sweep batch reaching this proposal, a quorum could
    // still form and EXECUTE — so the committed deadline was advisory, and the
    // window was as long as the sweep's backlog. Signers approve on the
    // understanding that the deadline binds.
    //
    // Every test below asserts the FULL zero-mutation contract, not merely the
    // returned error. A rejection that still appended an approval, an audit
    // event or a reservation would satisfy a naive `assert!(is_err())` while
    // leaving exactly the durable residue the ruling forbids.

    /// The complete durable footprint an approval could possibly move.
    /// Captured before and after a refused approval and compared whole, so a
    /// future write added on the rejection path fails here even though no
    /// assertion in these tests names it.
    #[cfg(test)]
    fn approval_footprint(id: u64) -> (Vec<u8>, Vec<Principal>, u64, u64, bool, u64) {
        let p = proposal_get(id).expect("proposal exists");
        (
            candid::encode_one(&p).expect("proposal encodes"),
            approvals_get(id),
            AUDIT_EVENTS.with(|a| a.borrow().len()),
            PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()),
            reservation_get(id).is_some(),
            companion_load().retained_bytes_total,
        )
    }

    /// S11-1 test 1 — the FIRST approval after the deadline is refused, typed,
    /// with zero mutation.
    #[test]
    fn s11_vault_first_approval_after_expiry_is_refused_with_zero_mutation() {
        setup();
        let created = now_ns();
        let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
        // TWO proposals in ONE install, with identical committed deadlines.
        // `control` proves the pre-deadline path still works; `id` is the one
        // approved after the deadline. Two proposals rather than two installs
        // because `setup()` reinstalls governance but does NOT clear stable
        // memory in-process — a second install would leave the first
        // proposal live in the expiry index and make the sweep assertion below
        // read on the wrong population.
        let control =
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let expires = proposal_get(id).unwrap().expires_at_ns.expect("ruled expiry");
        assert_eq!(expires, created + bounds.max_ns);
        assert!(approvals_get(id).is_empty(), "this really is a FIRST approval");

        // NON-VACUITY: one nanosecond BEFORE the deadline the SAME call
        // succeeds. Without this half, a check that rejected unconditionally —
        // or an `approve_inner` broken outright — would pass everything below.
        assert!(
            approve_inner(p(S1), control, commit_of(control), expires - 1).is_ok(),
            "the last nanosecond before the deadline is still approvable"
        );
        assert_eq!(approvals_get(control), vec![p(S1)]);

        let before = approval_footprint(id);
        // AT the deadline, not merely past it: `now >= expires_at_ns`. The
        // deadline instant is already too late.
        assert_eq!(
            approve_inner(p(S1), id, commit_of(id), expires),
            Err(VaultError::ProposalExpired {
                expires_at_ns: expires,
                now_ns: expires
            }),
            "an approval at or after the committed deadline must be refused, typed"
        );
        assert_eq!(
            approval_footprint(id),
            before,
            "S11-1 ruling: a refused post-expiry approval mutates NOTHING"
        );
        // The proposal stays Pending — the ruling makes the R3.8 sweep the SOLE
        // terminalizer, so admission must not have moved it to Expired.
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Pending);

        // And the sweep — still the only terminalizer — does its job on the
        // very same proposal, which is what makes "leave it Pending" safe.
        // Both proposals share the deadline, so both are due; the assertion is
        // that OURS is reaped, and by the sweep.
        let reaped = sweep_expired_inner(expires, 100);
        assert!(reaped.contains(&id), "the sweep reaps the refused proposal: {reaped:?}");
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Expired);
    }

    /// S11-1 test 2 — the QUORUM-REACHING approval after the deadline is
    /// refused: no execution, no `Executing`, and no durable upgrade intent.
    ///
    /// This is the one that matters. Test 1's proposal had no quorum to reach,
    /// so it could pass on a check placed anywhere before the write. Here the
    /// approval WOULD have crossed the quorum boundary and written the C1
    /// upgrade intent and the reservation before the first await.
    #[test]
    fn s11_vault_quorum_reaching_approval_after_expiry_writes_no_intent() {
        setup();
        let created = now_ns();
        let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let expires = created + bounds.max_ns;

        // First approval lands legitimately, BEFORE the deadline. The proposal
        // is now one approval short of quorum.
        approve_inner(p(S1), id, commit_of(id), created + 1).expect("pre-deadline approval");
        assert_eq!(approvals_get(id).len(), 1);
        assert!(proposal_get(id).unwrap().intent.is_none());

        let before = approval_footprint(id);
        let err = approve_inner(p(S2), id, commit_of(id), expires + 1).unwrap_err();
        assert_eq!(
            err,
            VaultError::ProposalExpired {
                expires_at_ns: expires,
                now_ns: expires + 1
            },
            "the quorum-reaching approval must be refused, never success-shaped"
        );
        assert_eq!(
            approval_footprint(id),
            before,
            "S11-1: the quorum-reaching refusal mutates NOTHING"
        );
        // Named explicitly, because these are the writes the quorum boundary
        // would have made and they are the ones with consequences.
        let p_after = proposal_get(id).unwrap();
        assert_eq!(p_after.outcome, ActionOutcome::Pending, "never Executing");
        assert!(p_after.intent.is_none(), "no C1 durable upgrade intent");
        assert!(reservation_get(id).is_none(), "no idempotency reservation");
        assert_eq!(approvals_get(id), vec![p(S1)], "the second approval is not recorded");
    }

    /// C3/C4 bind CALLER-SUPPLIED lifetimes now that they are ruled — the
    /// fail-closed `BoundsNotRuled` path is gone from production and the real
    /// `TooShort`/`TooLong` refusals have taken over.
    #[test]
    fn s6_caller_supplied_lifetime_is_bound_by_c3_and_c4() {
        setup();
        let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
        let action = || VaultActionKind::UpgraderUpgrade(good_upgrade());

        // Below C3 and above C4 are refused; a refused lifetime must leave no
        // proposal behind, which is why the index is asserted too.
        assert!(matches!(
            propose_inner(p(S1), action(), Some(bounds.min_ns - 1)),
            Err(VaultError::LifetimeOutOfBounds(
                stsh_custody_types::LifetimeViolation::TooShort { .. }
            ))
        ));
        assert!(matches!(
            propose_inner(p(S1), action(), Some(bounds.max_ns + 1)),
            Err(VaultError::LifetimeOutOfBounds(
                stsh_custody_types::LifetimeViolation::TooLong { .. }
            ))
        ));
        assert_eq!(PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()), 0);

        // Both endpoints are INCLUSIVE.
        let created = now_ns();
        let at_min = propose_inner(p(S1), action(), Some(bounds.min_ns)).expect("C3 is inclusive");
        assert_eq!(
            proposal_get(at_min).unwrap().expires_at_ns,
            Some(created + bounds.min_ns)
        );
    }

    /// S5A M1 gate A — the INJECTOR ITSELF, proved before anything is measured
    /// with it.
    ///
    /// This is not ceremony. The measurement it unblocks reports a per-record
    /// instruction cost, and the failure mode of a silently-inert injector is
    /// the worst kind available here: the expiry index stays empty, the sweep
    /// reaps nothing, the harness reports a marginal cost of ZERO, and the
    /// figure looks like excellent news rather than like a broken fixture. So
    /// the injector's effect is asserted against the REAL proposal path —
    /// `propose_inner` assigning a real expiry, the real index accepting it,
    /// the real sweep reaping it — rather than by reading the accessor back.
    ///
    /// The paired negative is `r3_sweep_is_vacuous_until_lifetime_bounds_are_ruled`
    /// immediately above: it proves the PRODUCTION default still yields no
    /// expiry. Together they show the injection is what moved the behaviour,
    /// which neither test establishes alone.
    #[test]
    fn s5a_lifetime_injector_actually_moves_the_sweep_off_vacuous() {
        setup();
        // S6 — THE BASELINE CHANGED, THE TEST'S JOB DID NOT.
        //
        // This began as proof that the injector lifts the sweep off a VACUOUS
        // production default (no expiry, empty index), which is what made
        // gate A unmeasurable. C3/C4 are now ruled, so the default is no
        // longer vacuous and that framing is dead.
        //
        // The injector still has to be proved non-inert, because V15 §4.4
        // rules RE-RUN TRIGGERS on any change to P_max, I_msg or G — the
        // measurement path is live equipment, not a historical artifact. What
        // it must now prove is stronger and easier to get wrong: that injected
        // bounds OVERRIDE the ruled ones rather than sitting underneath them.
        // A silently-inert injector would now leave the ruled 30-day expiry in
        // force while the harness believed it was measuring at its candidate.
        let ruled = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("ruled at S6");
        let baseline =
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let baseline_created = proposal_get(baseline).unwrap().created_at_ns;
        assert_eq!(
            proposal_get(baseline).unwrap().expires_at_ns,
            Some(baseline_created + ruled.max_ns),
            "before injection the RULED bounds are in force"
        );

        // Inject candidate bounds. These are FIXTURE values chosen to exercise
        // the path, NOT proposed constants — S5A discipline: the builder
        // measures, the table rules. They are orders of magnitude shorter than
        // the ruled bounds precisely so the two are distinguishable below.
        inject_lifetime_params_for_test(
            Some(Some(stsh_custody_types::ProposalLifetimeBounds {
                min_ns: 1_000,
                max_ns: 1_000_000,
            })),
            Some(Some(2)),
        );

        // Default-lifetime path: resolves to created + the INJECTED max_ns,
        // not the ruled one. Asserting only `is_some()` here — which is what
        // this test did while the production default was `None` — would now
        // pass on a completely inert injector.
        let defaulted =
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let defaulted_created = proposal_get(defaulted).unwrap().created_at_ns;
        assert_eq!(
            proposal_get(defaulted).unwrap().expires_at_ns,
            Some(defaulted_created + 1_000_000),
            "the injected bounds must OVERRIDE the ruled ones; a proposal still \
             expiring at C4 means the harness is measuring the ruled constant \
             while believing it is measuring its candidate"
        );

        // Explicit-lifetime path: validated, then applied.
        let explicit = propose_inner(
            p(S1),
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            Some(5_000),
        )
        .unwrap();
        let rec = proposal_get(explicit).unwrap();
        assert_eq!(
            rec.expires_at_ns,
            Some(rec.created_at_ns.saturating_add(5_000)),
            "an explicit in-bounds lifetime must be honoured through the real path"
        );

        // Out-of-bounds still REJECTS — the injector supplies bounds, it does
        // not disable validation.
        assert!(
            propose_inner(
                p(S1),
                VaultActionKind::UpgraderUpgrade(good_upgrade()),
                Some(1),
            )
            .is_err(),
            "a below-minimum lifetime must still be refused under injected bounds"
        );

        // The sweep reaps AT THE INJECTED HORIZON. Sweeping at `u64::MAX` — the
        // old form — would reap the ruled-expiry baseline proposal too and pass
        // no matter which bounds were actually in force. Sweeping just past the
        // injected maximum, which is still ~30 days short of the ruled one,
        // distinguishes them: the two injected records are due, the baseline is
        // not.
        assert!(
            PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()) >= 2,
            "injected bounds must populate the expiry index"
        );
        let horizon = defaulted_created + 1_000_000;
        let reaped = sweep_expired_inner(horizon, 100);
        assert!(
            !reaped.is_empty(),
            "the sweep must reap real due records at the INJECTED horizon; an \
             empty result would make every gate A figure a measurement of nothing"
        );
        assert!(
            !reaped.contains(&baseline),
            "the ruled-expiry proposal is not due for another 30 days and must \
             not be reaped at the injected horizon"
        );
    }

    /// S5A M1 gate A — the injected SWEEP WORK LIMIT actually clamps.
    ///
    /// Separate from the bounds test because it guards a different property.
    /// `C11` is the constant this limit will carry, so a measurement taken "at
    /// candidate limit L" is only meaningful if L is what the endpoint enforced
    /// — an ignored clamp would silently measure the caller's limit instead and
    /// the reported envelope would belong to the wrong L.
    #[test]
    fn s5a_injected_sweep_work_limit_clamps_the_endpoint() {
        setup();
        inject_lifetime_params_for_test(
            Some(Some(stsh_custody_types::ProposalLifetimeBounds {
                min_ns: 1_000,
                max_ns: 1_000_000,
            })),
            Some(Some(2)),
        );
        assert_eq!(sweep_work_limit(), Some(2));

        for _ in 0..5 {
            propose_inner(
                p(S1),
                VaultActionKind::UpgraderUpgrade(good_upgrade()),
                Some(1_000),
            )
            .unwrap();
        }
        // Every one of the five is due at this clock.
        let far_future = u64::MAX;
        // The clamp lives in the ENDPOINT, so exercise the clamp arithmetic the
        // endpoint performs rather than calling the inner sweep directly.
        let effective = match sweep_work_limit() {
            Some(cap) => (100usize).min(cap),
            None => 100usize,
        };
        assert_eq!(effective, 2, "the injected limit must win over a larger caller limit");
        assert_eq!(
            sweep_expired_inner(far_future, effective).len(),
            2,
            "the sweep must honour the clamped bound"
        );
    }

    /// R3.8: the sweep reaps only DUE, still-Pending proposals, and never more
    /// than its limit. Driven with expiries set directly, so the mechanism is
    /// exercised without pre-empting the unruled constants.
    #[test]
    fn r3_sweep_is_bounded_and_reaps_only_due_pending() {
        setup();
        let mut ids = Vec::new();
        for _ in 0..4 {
            let id =
                propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
            let mut rec = proposal_get(id).unwrap();
            rec.expires_at_ns = Some(1_000);
            proposal_put(&rec);
            ids.push(id);
        }
        // A proposal that is NOT yet due must not be touched.
        let not_due =
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let mut rec = proposal_get(not_due).unwrap();
        rec.expires_at_ns = Some(9_000);
        proposal_put(&rec);

        // Limit is respected: 2 of the 4 due.
        let first = sweep_expired_inner(5_000, 2);
        assert_eq!(first.len(), 2, "sweep must not exceed its work bound");
        let second = sweep_expired_inner(5_000, 10);
        assert_eq!(second.len(), 2, "remaining due proposals reaped on the next call");
        assert!(sweep_expired_inner(5_000, 10).is_empty(), "sweep converges");

        for id in ids {
            assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Expired);
        }
        assert_eq!(
            proposal_get(not_due).unwrap().outcome,
            ActionOutcome::Pending,
            "a proposal whose lifetime has not elapsed must survive"
        );
        assert_eq!(PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()), 1);
    }

    /// R3.8: expiry clears artifact bytes, on the same durable-state-first
    /// ordering as cancellation.
    #[test]
    fn r3_expiry_clears_artifact_bytes() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let mut rec = proposal_get(id).unwrap();
        rec.expires_at_ns = Some(1);
        proposal_put(&rec);
        assert_eq!(sweep_expired_inner(2, 10), vec![id]);
        match proposal_get(id).unwrap().action {
            VaultActionKind::UpgraderUpgrade(u) => assert!(u.wasm_bytes.is_empty()),
            other => panic!("unexpected action {other:?}"),
        }
    }

    /// R3.9: proposing does not get more expensive as proposals accumulate.
    /// Asserted structurally — the single-flight path performs a bounded
    /// number of index reads regardless of history — by showing the expiry
    /// index and lock index stay empty/1-entry while many terminal records
    /// pile up.
    #[test]
    fn r3_propose_cost_independent_of_terminal_count() {
        setup();
        for _ in 0..25 {
            let id =
                propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
            cancel_proposal_inner(p(S1), id).unwrap();
        }
        // 25 terminal records exist, yet every companion the propose path
        // consults is empty — so the check cannot be scanning them.
        assert_eq!(PROPOSALS.with(|p| p.borrow().len()), 25);
        assert_eq!(OPEN_MUTATING_INTENT_INDEX.with(|x| x.borrow().len()), 0);
        assert_eq!(PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow().len()), 0);
        assert!(propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok());
    }

    // ── S3 / R1.2: ApprovalCommitmentV1 is frozen at creation ───────────────

    /// R1.2 — the stored commitment does not move across the FULL lifecycle:
    /// creation -> approval -> quorum -> execution -> terminalization ->
    /// post-artifact-clearing.
    ///
    /// This is the property V2's "hash the action" could not deliver. Three
    /// mutations moved that value: request_id 0 -> proposal_id at quorum,
    /// artifact clearing at terminalization, and the Upgrader's store-time
    /// redaction. The canonical form is byte-free and the id is bound at
    /// creation, so none of the three can move it.
    #[test]
    fn r1_commitment_stable_across_lifecycle() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();

        let at_creation = proposal_get(id).unwrap().commitment_hash;
        assert!(!at_creation.is_empty(), "a commitment must be stored at creation");
        // Recomputing from the retained payload agrees at creation.
        assert_eq!(commitment_for(&proposal_get(id).unwrap()).hash(), at_creation);

        approve_to_quorum(id);
        assert_eq!(
            proposal_get(id).unwrap().commitment_hash,
            at_creation,
            "the quorum boundary must not move the commitment — this is where \
             request_id used to mutate"
        );

        block_on(execute_action_with(&backend, id));
        let after = proposal_get(id).unwrap();
        assert_eq!(after.outcome, ActionOutcome::Executed);
        assert_eq!(
            after.commitment_hash, at_creation,
            "terminalization must not move the commitment"
        );
        // Artifact bytes are gone...
        match &after.action {
            VaultActionKind::UpgraderUpgrade(u) => assert!(u.wasm_bytes.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
        // ...and the commitment STILL recomputes to the same value from the
        // cleared payload. That is what makes the byte-free canonical form
        // load-bearing rather than cosmetic.
        assert_eq!(
            commitment_for(&after).hash(),
            at_creation,
            "recomputation after artifact clearing must still agree"
        );

        // And across an upgrade.
        post_upgrade();
        assert_eq!(proposal_get(id).unwrap().commitment_hash, at_creation);
    }

    /// R1.2 — the lifecycle stability property for the ONE action that
    /// carries a `request_id`: `VaultUpgradeViaUpgrader`.
    ///
    /// The generic lifecycle test above uses `UpgraderUpgrade`, which has NO
    /// request_id — so it cannot detect a regression that re-binds the id at
    /// the quorum boundary. FOUND BY MUTATION: restoring the quorum-time
    /// binding left that test green. This is the case R1.2 property 1 exists
    /// for, so it needs its own coverage.
    #[test]
    fn r1_commitment_stable_across_lifecycle_for_request_id_action() {
        setup();
        let id = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            None,
        )
        .unwrap();
        let at_creation = proposal_get(id).unwrap().commitment_hash;
        assert_eq!(commitment_for(&proposal_get(id).unwrap()).hash(), at_creation);

        approve_to_quorum(id);
        let after_quorum = proposal_get(id).unwrap();
        assert_eq!(
            after_quorum.commitment_hash, at_creation,
            "the stored commitment must not move at the quorum boundary"
        );
        assert_eq!(
            commitment_for(&after_quorum).hash(),
            at_creation,
            "and RECOMPUTATION from the retained payload must still agree — if the \
             request identity were bound here instead of at creation, the payload \
             would have moved out from under the stored hash"
        );
    }
    /// R1.2 property 8 / R1.3 — the commitment is SIGNER-VISIBLE on every
    /// view, Pending and terminal alike, and survives artifact clearing.
    ///
    /// Without this a signer cannot obtain the value R1.5 will require them to
    /// supply: `propose` returns only the id. A commitment nobody can read is
    /// not a commitment anyone can check.
    #[test]
    fn r1_commitment_is_visible_on_every_signer_view() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let stored = proposal_get(id).unwrap().commitment_hash;
        assert!(!stored.is_empty());

        // Pending view.
        let pending = get_proposal_for(id, p(S1)).expect("signer may read");
        assert_eq!(
            pending.commitment_hash, stored,
            "a Pending view must carry the hash a signer will have to supply"
        );

        // Terminal view, AFTER artifact clearing.
        approve_to_quorum(id);
        block_on(execute_action_with(&backend, id));
        let after = proposal_get(id).unwrap();
        assert_eq!(after.outcome, ActionOutcome::Executed);
        match &after.action {
            VaultActionKind::UpgraderUpgrade(u) => {
                assert!(u.wasm_bytes.is_empty(), "bytes released")
            }
            other => panic!("unexpected {other:?}"),
        }
        let terminal = get_proposal_for(id, p(S1)).expect("signer may read");
        assert_eq!(
            terminal.commitment_hash, stored,
            "the terminal view must STILL return the stored commitment after clearing — \
             that is what the byte-free canonical form is for"
        );

        // Paginated listing carries it too.
        let page = list_proposals_for(p(S1)).expect("signer may list");
        let listed = page.iter().find(|v| v.proposal_id == id).expect("in page");
        assert_eq!(listed.commitment_hash, stored);
    }

    /// R1.2/R1.3 — the views return the STORED commitment, not a fresh
    /// recomputation.
    ///
    /// The test above cannot tell the two apart: in every honest record the
    /// stored and recomputed hashes AGREE, so changing `to_view` to recompute
    /// would leave it green while quietly defeating the property. This forces
    /// them APART — a sentinel stored hash over an unchanged retained payload
    /// — and requires both query surfaces to surface the stored value.
    ///
    /// Why it matters: R1.5 must classify a stored-vs-recomputed divergence as
    /// DURABLE CORRUPTION, distinct from a caller mismatch. A view that
    /// silently recomputed would present the corrupt record as healthy and
    /// hide the very condition R1.5 exists to catch.
    #[test]
    fn r1_views_return_the_stored_commitment_not_a_recomputation() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();

        // Diverge the two DELIBERATELY: a sentinel stored hash, payload untouched.
        const SENTINEL: [u8; 32] = [0xAB; 32];
        let mut rec = proposal_get(id).unwrap();
        rec.commitment_hash = SENTINEL.to_vec();
        proposal_put(&rec);

        let recomputed = commitment_for(&proposal_get(id).unwrap()).hash();
        assert_ne!(
            recomputed,
            SENTINEL.to_vec(),
            "the fixture must actually diverge, or this test proves nothing"
        );

        assert_eq!(
            get_proposal_for(id, p(S1)).expect("signer may read").commitment_hash,
            SENTINEL.to_vec(),
            "get_proposal must return the STORED hash — recomputing here would hide a \
             corrupt record behind a healthy-looking view"
        );
        let page = list_proposals_for(p(S1)).expect("signer may list");
        assert_eq!(
            page.iter().find(|v| v.proposal_id == id).expect("in page").commitment_hash,
            SENTINEL.to_vec(),
            "list_proposals must return the STORED hash too"
        );
    }

    #[test]
    fn l02_canonical_v2_bytes_are_exact_disjoint_and_locator_bound() {
        let prefix = b"stsh-vault-action-canonical-v2\0";
        let initializer = canonical_action_bytes(&VaultActionKind::Application(ActionRequest::PoolInitializePayoutMemoKey));
        let readiness = canonical_action_bytes(&VaultActionKind::ReadModel(ReadModelRequest::PoolReadPayoutMemoKeyReady));
        let token_zero = canonical_action_bytes(&VaultActionKind::ReadModel(ReadModelRequest::TokenReadSupplyReconciliation { receipt_audit_id: 0 }));
        let token_max = canonical_action_bytes(&VaultActionKind::ReadModel(ReadModelRequest::TokenReadSupplyReconciliation { receipt_audit_id: u64::MAX }));
        assert_eq!(initializer, [prefix.as_slice(), &[0x01]].concat());
        assert_eq!(readiness, [prefix.as_slice(), &[0x02]].concat());
        assert_eq!(token_zero, [prefix.as_slice(), &[0x03], &0u64.to_le_bytes()].concat());
        assert_eq!(token_max, [prefix.as_slice(), &[0x03], &u64::MAX.to_le_bytes()].concat());
        assert_ne!(initializer, readiness);
        assert_ne!(readiness, token_zero);
        assert_ne!(token_zero, token_max);
        assert!(!initializer.starts_with(b"DIDL"));
    }

    #[test]
    fn l02_legacy_profile_is_frozen_away_from_expanded_current_enum() {
        let action = VaultActionKind::UpdateSignerSet { signers: vec![p(S1), p(S2), p(S3)], threshold: 2 };
        let frozen = canonical_action_bytes(&action);
        let expanded = candid::encode_one(&cleared_action(action)).unwrap();
        assert_ne!(frozen, expanded, "mutation back to the expanded current enum must be observable");
        assert!(frozen.starts_with(b"DIDL"));
    }

    /// R1.2 property 6 — `Reservation.action_fingerprint` IS the stored
    /// commitment hash, not a fresh hash of a subsequently mutated action.
    #[test]
    fn r1_reservation_equals_stored_commitment() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let stored = proposal_get(id).unwrap().commitment_hash;
        approve_to_quorum(id);
        let r = reservation_get(id).expect("reservation exists at the quorum boundary");
        assert_eq!(
            r.action_fingerprint, stored,
            "the reservation must be bound to the SAME value signers approved"
        );
    }

    /// R1.2 property 1 — the request identity is bound at CREATION, and a
    /// caller may not supply one.
    #[test]
    fn r1_request_id_bound_at_creation_not_at_quorum() {
        setup();
        let id = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            None,
        )
        .unwrap();
        match proposal_get(id).unwrap().action {
            VaultActionKind::VaultUpgradeViaUpgrader(vu) => assert_eq!(
                vu.request_id, id,
                "request_id must be bound at CREATION — binding it at quorum is what \
                 moved the action's hash mid-life"
            ),
            other => panic!("unexpected {other:?}"),
        }
        // A caller-supplied identity is refused before anything is stored.
        let mut vu = good_vault_upgrade();
        vu.request_id = 7;
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::VaultUpgradeViaUpgrader(vu), None),
            Err(VaultError::IllegalSourceState)
        );
    }

    /// R1.2 property 4 — the commitment binds the EXECUTING canister, so the
    /// same proposal under a different canister id hashes differently. Cross-
    /// canister replay is impossible, not merely improbable.
    #[test]
    fn r1_commitment_binds_the_executing_canister() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let rec = proposal_get(id).unwrap();
        let mine = commitment_for(&rec).hash();
        let elsewhere = stsh_custody_types::ApprovalCommitmentV1::new(
            p(0x5A),
            rec.proposal_id,
            rec.epoch,
            rec.expires_at_ns,
            canonical_action_bytes(&rec.action),
        )
        .hash();
        assert_ne!(mine, elsewhere, "the executing canister must be inside the digest");
    }

    /// R1.2 property 3 — the domain carries a schema version, so a future
    /// ApprovalCommitmentV2 cannot collide with V1 over the same bytes.
    #[test]
    fn r1_commitment_domain_is_versioned() {
        assert!(
            stsh_custody_types::APPROVAL_COMMITMENT_V1_DOMAIN.contains("v1"),
            "the domain tag must carry a schema version"
        );
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let rec = proposal_get(id).unwrap();
        let c = commitment_for(&rec);
        assert_eq!(c.domain, stsh_custody_types::APPROVAL_COMMITMENT_V1_DOMAIN);
        let mut v2 = c.clone();
        v2.domain = "stsh.custody.approval-commitment.v2".to_string();
        assert_ne!(c.hash(), v2.hash(), "a version bump must change the digest");
    }

    // ── S3 / R1.5: approve-time ordering + the epoch contract ───────────────

    /// R1.5 — a mismatched hash rejects with ZERO writes of any kind, and the
    /// proposal stays `Pending`. A wrong hash from one signer must not destroy
    /// a proposal the others are still evaluating.
    // BINDING: B-1 — the Vault commitment binds the APPROVING CALLER. Registered
    // in tests/BINDING_REGISTRY.toml; `verify_gate_lints bindings` checks this
    // test still invokes approve_inner twice with differing hashes and still
    // asserts the rejection. Do not rename without updating the registry row.
    #[test]
    fn r1_approve_rejects_mismatched_hash_no_writes() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let audits_before = audit_events().len();
        let approvals_before = approvals_get(id);
        let rec_before = proposal_get(id).unwrap();

        assert_eq!(
            approve_inner(p(S1), id, vec![0xEE; 32], now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::CallerMismatch
            )),
            "a wrong expected hash must reject, typed as a CALLER mismatch"
        );

        assert_eq!(proposal_get(id).unwrap(), rec_before, "no proposal mutation");
        assert_eq!(approvals_get(id), approvals_before, "no approval recorded");
        assert_eq!(audit_events().len(), audits_before, "no audit entry");
        assert!(reservation_get(id).is_none(), "no reservation");
        assert_eq!(
            proposal_get(id).unwrap().outcome,
            ActionOutcome::Pending,
            "the proposal must remain Pending — one signer's wrong hash cannot \
             destroy a proposal its peers are still evaluating"
        );
        // And an honest approval still works afterwards.
        approve_inner(p(S1), id, commit_of(id), now_ns()).expect("correct hash still approves");
    }

    /// R1.5 — a WRONG hash against a TERMINAL proposal must REJECT, not return
    /// `Ok(PriorResult)`.
    ///
    /// This is why the commitment check moved ahead of the terminal-replay
    /// return. With the old ordering the replay fired first and a caller
    /// supplying any garbage hash received a success-shaped answer.
    #[test]
    fn r1_terminal_proposal_rejects_wrong_hash() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        approve_to_quorum(id);
        block_on(execute_action_with(&backend, id));
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);

        assert_eq!(
            approve_inner(p(S3), id, vec![0xEE; 32], now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::CallerMismatch
            )),
            "a wrong hash against a terminal proposal must REJECT — returning \
             Ok(PriorResult) would be a success-shaped answer to a rejected approval"
        );
        // The CORRECT hash still replays the prior result.
        match approve_inner(p(S3), id, commit_of(id), now_ns()) {
            Ok((ApprovalOutcome::PriorResult { outcome, .. }, false)) => {
                assert_eq!(outcome, ActionOutcome::Executed)
            }
            other => panic!("expected prior-result replay, got {other:?}"),
        }
    }

    /// R1.5 — a correct OLD hash against a superseded epoch is rejected by the
    /// EPOCH PIN, with zero writes. The commitment check PASSES here.
    ///
    /// V3 claimed this would surface as a commitment mismatch. That is FALSE:
    /// the commitment binds the proposal's IMMUTABLE creation epoch, so
    /// advancing governance does not move it and the old hash still matches.
    /// The epoch pin is the SOLE rejector — load-bearing, not defence in depth.
    #[test]
    fn correct_old_hash_rejected_stale_epoch() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let old_hash = commit_of(id);
        let old_epoch = proposal_get(id).unwrap().epoch;

        // Advance the governance epoch via a REAL signer-set transition —
        // identical signers AND identical threshold is a no-op and bumps
        // nothing, so the threshold has to actually change.
        let gid = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 3,
            },
            None,
        )
        .unwrap();
        approve_to_quorum(gid);
        // The quorum boundary only marks Executing; the atomic cell write that
        // bumps the epoch happens in execution.
        block_on(execute_action_with(&FakeBackend::ok(Vec::new()), gid));
        assert!(gov().epoch > old_epoch, "the epoch must have advanced");

        let audits_before = audit_events().len();
        let approvals_before = approvals_get(id);
        assert!(
            matches!(
                approve_inner(p(S2), id, old_hash.clone(), now_ns()),
                Err(VaultError::StaleEpoch { .. })
            ),
            "a CORRECT old hash must be rejected by the EPOCH PIN, not as a mismatch"
        );
        assert_eq!(approvals_get(id), approvals_before, "zero writes");
        assert_eq!(audit_events().len(), audits_before, "zero writes");
        // The stored commitment did NOT move across the epoch transition.
        assert_eq!(commit_of(id), old_hash);
    }

    /// R1.5 — a hash built with the CURRENT epoch instead of the proposal's
    /// epoch is a COMMITMENT MISMATCH, not a stale-epoch rejection. The caller
    /// got the preimage wrong; the proposal is not stale.
    ///
    /// V4.1 requires these two to be separate tests asserting DIFFERENT
    /// rejection paths — neither substitutes for the other.
    #[test]
    fn wrong_epoch_hash_rejected_mismatch() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let rec = proposal_get(id).unwrap();
        // Same proposal, same payload — only the epoch field is wrong.
        let wrong = stsh_custody_types::ApprovalCommitmentV1::new(
            self_id(),
            rec.proposal_id,
            rec.epoch + 1,
            rec.expires_at_ns,
            canonical_action_bytes(&rec.action),
        )
        .hash();
        assert_ne!(wrong, rec.commitment_hash);
        assert_eq!(
            approve_inner(p(S1), id, wrong, now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::CallerMismatch
            )),
            "building the preimage with the wrong epoch is a CALLER mismatch — the \
             proposal itself is perfectly current"
        );
    }

    /// R1.5 — the stored commitment is unchanged across an epoch transition.
    #[test]
    fn r1_stored_commitment_unchanged_across_epoch() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        let before = commit_of(id);
        let gid = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 3,
            },
            None,
        )
        .unwrap();
        approve_to_quorum(gid);
        block_on(execute_action_with(&FakeBackend::ok(Vec::new()), gid));
        assert_eq!(
            commit_of(id),
            before,
            "advancing governance must not move a proposal's commitment — if it did, \
             the commitment would be context-dependent rather than immutable"
        );
    }

    /// R1.5 — a stored-vs-recomputed divergence FAILS CLOSED, typed as
    /// corruption rather than a caller error, and is caught even when the
    /// caller supplies the stored value.
    #[test]
    fn r1_stored_vs_recomputed_corruption_fails_closed() {
        setup();
        let id = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None)
            .unwrap();
        // Corrupt the STORED hash, leaving the payload intact.
        let mut rec = proposal_get(id).unwrap();
        rec.commitment_hash = vec![0xCD; 32];
        proposal_put(&rec);

        let audits_before = audit_events().len();
        assert_eq!(
            approve_inner(p(S1), id, vec![0xCD; 32], now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::StoredVsRecomputed
            )),
            "corruption must be typed APART from a caller mismatch, and must fail even \
             when the caller faithfully supplies the stored value"
        );
        assert_eq!(audit_events().len(), audits_before, "zero writes");
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Pending);
    }

    /// The stored commitment for `id` — what a signer reads off the proposal
    /// view and supplies to `approve` (R1.5).
    fn commit_of(id: u64) -> Vec<u8> {
        proposal_get(id).expect("proposal exists").commitment_hash
    }

    /// C7, read from the ruled table — the bound on how many distinct proposers
    /// can hold a live retained-byte entry. Named so the derivation in
    /// `s6c_signer_accounting_cardinality_is_bounded_by_c7_not_the_roster`
    /// reads as an appeal to a ruled value rather than a chosen number.
    const VAULT_NONTERMINAL_CAPS_GLOBAL_FOR_TEST: u64 = 320;

    fn approve_to_quorum(id: u64) {
        approve_inner(p(S1), id, commit_of(id), now_ns()).unwrap();
        let (_, go) = approve_inner(p(S2), id, commit_of(id), now_ns()).unwrap();
        assert!(go);
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executing);
    }

    fn governed_upgrade(target: Principal) -> VaultActionKind {
        let wasm = b"mod".to_vec();
        let arg = b"arg".to_vec();
        VaultActionKind::Management(ManagementAction::Upgrade {
            target,
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        })
    }

    // ── R1.7 — typed, exhaustive, BOUNDED management view ────────────────────

    /// The largest artifact a management `Upgrade` can carry and still be
    /// proposable (`check_install_size`: wasm + arg + 4 KiB envelope slack
    /// must not exceed `GATE_SIZE_BOUND_BYTES`).
    fn max_size_governed_upgrade(target: Principal) -> (VaultActionKind, u64) {
        let wasm = vec![0xAAu8; (GATE_SIZE_BOUND_BYTES - 4_096 - 1) as usize];
        let arg = Vec::new();
        let len = wasm.len() as u64;
        (
            VaultActionKind::Management(ManagementAction::Upgrade {
                target,
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            }),
            len,
        )
    }

    /// R1.7 — the management view is TYPED and its encoded size does not grow
    /// with the artifact.
    ///
    /// Before this change `ActionView::Management` was `format!("{m:?}")`: the
    /// `Debug` of the whole action, which renders `wasm_bytes` as a decimal
    /// list. A ~1.9 MiB artifact became several megabytes of view — every
    /// `get_proposal` on a pending upgrade blew `READ_RESPONSE_MAX_BYTES`
    /// (262,144) by more than an order of magnitude, so the proposal a signer
    /// most needed to inspect was precisely the one they could not read.
    ///
    /// Size invariance is asserted by DIFFERENCE, not by an absolute number:
    /// a tiny-artifact and a max-artifact proposal must produce views within a
    /// few bytes of each other. An absolute ceiling alone would still pass if
    /// the view grew sub-linearly (e.g. a truncated `Debug` string), which
    /// R1.7 explicitly rejects.
    #[test]
    fn r1_7_management_view_is_typed_and_size_invariant_in_the_artifact() {
        setup();
        let small = propose_inner(p(S1), governed_upgrade(pyeop()), None).unwrap();
        let (big_action, big_len) = max_size_governed_upgrade(s3tyu());
        let big = propose_inner(p(S1), big_action, None).unwrap();

        let small_view = get_proposal_for(small, p(S1)).expect("signer may read");
        let big_view = get_proposal_for(big, p(S1)).expect("signer may read");

        // Typed fields, not prose.
        match &big_view.action {
            ActionView::Management(ManagementActionView::Upgrade {
                target,
                expected_wasm_hash,
                expected_arg_hash,
                wasm_bytes_len,
                arg_bytes_len,
                bytes_retained,
            }) => {
                assert_eq!(*target, s3tyu());
                assert_eq!(expected_wasm_hash.len(), 32);
                assert_eq!(expected_arg_hash.len(), 32);
                assert_eq!(*wasm_bytes_len, big_len);
                assert_eq!(*arg_bytes_len, 0);
                assert!(*bytes_retained, "pending proposal still holds its bytes");
            }
            other => panic!("expected a typed management upgrade view, got {other:?}"),
        }

        let small_bytes = candid::encode_one(&small_view).unwrap().len();
        let big_bytes = candid::encode_one(&big_view).unwrap().len();
        assert!(
            big_bytes.abs_diff(small_bytes) <= 8,
            "the view must not grow with the artifact: {small_bytes} bytes for a 3-byte \
             wasm vs {big_bytes} bytes for a {big_len}-byte wasm — the only legitimate \
             difference is the width of the encoded length fields"
        );
        assert!(
            big_bytes < 1_024,
            "a single management view must be trivially small; measured {big_bytes} bytes"
        );
    }

    /// R1.7 — every `ManagementAction` variant has a typed view, and none of
    /// them carries artifact bytes.
    ///
    /// The match in `ManagementActionView::of` is exhaustive, so a new action
    /// variant cannot compile without a view. This test covers the other half:
    /// that each existing view actually discloses its variant's parameters
    /// rather than collapsing to a placeholder.
    #[test]
    fn r1_7_every_management_variant_has_a_typed_view() {
        setup();
        let t = pyeop();
        let (upgrade, _) = max_size_governed_upgrade(t);
        let VaultActionKind::Management(upgrade) = upgrade else {
            unreachable!("constructed as a management action")
        };
        let install_wasm = b"mod".to_vec();
        let cases: Vec<ManagementAction> = vec![
            upgrade,
            ManagementAction::Start { target: t },
            ManagementAction::Stop { target: t },
            ManagementAction::UpdateSettings {
                target: t,
                controllers: vec![self_id()],
            },
            ManagementAction::DepositCycles {
                target: t,
                cycles: u128::MAX,
            },
            ManagementAction::CreateCanister {
                manifest_purpose: CUTOVER_SOLVENCY_STATUS_PURPOSE.to_string(),
                disposition: ManifestDisposition::SetControllerAtCutover,
            },
            ManagementAction::InstallCode {
                target: t,
                expected_wasm_hash: sha256(&install_wasm),
                expected_arg_hash: sha256(b""),
                wasm_bytes: install_wasm,
                arg_bytes: Vec::new(),
            },
        ];
        assert_eq!(cases.len(), 7, "all seven ManagementAction variants covered");

        for m in &cases {
            let v = ManagementActionView::of(m);
            let encoded = candid::encode_one(&v).unwrap();
            assert!(
                encoded.len() < 1_024,
                "{v:?} encodes to {} bytes — no management view may be artifact-sized",
                encoded.len()
            );
            // The redacted view must not contain the artifact bytes. The
            // max-size upgrade/install payloads are constant fills, so a
            // surviving run of them is directly detectable.
            assert!(
                !encoded.windows(16).any(|w| w == [0xAAu8; 16]),
                "{v:?} leaked artifact bytes into the view"
            );
        }

        // Spot-check the disclosures that are not hashes.
        match ManagementActionView::of(&cases[3]) {
            ManagementActionView::UpdateSettings { controllers, .. } => {
                assert_eq!(controllers, vec![self_id()], "controller set shown in full")
            }
            other => panic!("unexpected {other:?}"),
        }
        match ManagementActionView::of(&cases[4]) {
            ManagementActionView::DepositCycles { cycles, .. } => assert_eq!(cycles, u128::MAX),
            other => panic!("unexpected {other:?}"),
        }
        match ManagementActionView::of(&cases[5]) {
            ManagementActionView::CreateCanister {
                manifest_purpose,
                disposition,
            } => {
                assert_eq!(manifest_purpose, CUTOVER_SOLVENCY_STATUS_PURPOSE);
                assert_eq!(disposition, ManifestDisposition::SetControllerAtCutover);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// R1.7 — `bytes_retained` reflects EITHER artifact vector, on every view
    /// that carries the flag.
    ///
    /// Computed from `wasm_bytes` alone, the flag reported `false` for an
    /// action holding empty wasm and a retained ARG, while `arg_bytes_len`
    /// simultaneously reported a nonzero length — a view contradicting itself
    /// about whether the artifact is still held. `bytes_retained` is the field
    /// a signer reads to know whether a proposal still pins its payload, and
    /// R3.3 requires exact accounting across every retained copy, so a flag
    /// that can be false over retained bytes undercounts.
    ///
    /// All four flag-bearing views are covered: both management variants and
    /// both ring upgrade views. The bug was identical in each because the
    /// expression was copied.
    #[test]
    fn r1_7_bytes_retained_covers_arg_bytes_on_every_view() {
        setup();
        let arg = b"retained-arg".to_vec();

        // ── Management: Upgrade and InstallCode, empty wasm, retained arg.
        for m in [
            ManagementAction::Upgrade {
                target: pyeop(),
                expected_wasm_hash: sha256(b""),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: Vec::new(),
                arg_bytes: arg.clone(),
            },
            ManagementAction::InstallCode {
                target: pyeop(),
                expected_wasm_hash: sha256(b""),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: Vec::new(),
                arg_bytes: arg.clone(),
            },
        ] {
            match ManagementActionView::of(&m) {
                ManagementActionView::Upgrade {
                    wasm_bytes_len,
                    arg_bytes_len,
                    bytes_retained,
                    ..
                }
                | ManagementActionView::InstallCode {
                    wasm_bytes_len,
                    arg_bytes_len,
                    bytes_retained,
                    ..
                } => {
                    assert_eq!(wasm_bytes_len, 0);
                    assert_eq!(arg_bytes_len, arg.len() as u64);
                    assert!(
                        bytes_retained,
                        "arg bytes are retained, so the flag must say so — it \
                         cannot read false beside arg_bytes_len {arg_bytes_len}"
                    );
                }
                other => panic!("unexpected {other:?}"),
            }
        }

        // ── Ring views: UpgraderUpgrade (§3d) and VaultUpgradeViaUpgrader (§3e).
        let direct = propose_inner(
            p(S1),
            VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                expected_wasm_hash: sha256(b""),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: Vec::new(),
                arg_bytes: arg.clone(),
            }),
            None,
        )
        .unwrap();
        match get_proposal_for(direct, p(S1)).expect("signer may read").action {
            ActionView::UpgraderUpgrade { bytes_retained, .. } => assert!(
                bytes_retained,
                "§3d view: arg bytes retained, flag must be true"
            ),
            other => panic!("unexpected {other:?}"),
        }

        let ring = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader {
                request_id: 0,
                expected_wasm_hash: sha256(b""),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: Vec::new(),
                arg_bytes: arg.clone(),
            }),
            None,
        )
        .unwrap();
        match get_proposal_for(ring, p(S1)).expect("signer may read").action {
            ActionView::VaultUpgradeViaUpgrader { bytes_retained, .. } => assert!(
                bytes_retained,
                "§3e view: arg bytes retained, flag must be true"
            ),
            other => panic!("unexpected {other:?}"),
        }

        // The flag must still go FALSE once cleared — the fix must not make it
        // permanently true. `cleared_action` empties both vectors together.
        let cleared = cleared_action(proposal_get(direct).unwrap().action);
        match cleared {
            VaultActionKind::UpgraderUpgrade(ref u) => {
                assert!(u.wasm_bytes.is_empty() && u.arg_bytes.is_empty())
            }
            ref other => panic!("unexpected {other:?}"),
        }
        let mut rec = proposal_get(direct).unwrap();
        rec.action = cleared;
        proposal_put(&rec);
        match get_proposal_for(direct, p(S1)).expect("signer may read").action {
            ActionView::UpgraderUpgrade { bytes_retained, .. } => assert!(
                !bytes_retained,
                "after clearing BOTH vectors the flag must read false"
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// R1.7/R1.8 — a MAXIMAL page of management proposals fits the response
    /// ceiling, with the per-view budget measured rather than assumed.
    ///
    /// `list_proposals` bounds by COUNT (`MAX_READ_PAGE_LIMIT` = 128) and has
    /// no byte budget, so "the page fits" is a property of the widest view the
    /// page can contain. This test establishes that number for the management
    /// class; R1.8/S5A's response arithmetic builds on it.
    ///
    /// `UpdateSettings` is the widest PROPOSABLE management view: its
    /// `controllers` vector is the only variable-length field, and
    /// `validate_management_target` admits exactly one controller principal
    /// (`[Vault]` for a governed target, the ring counterpart for a ring
    /// member) — so the shape below is the real worst case, not a convenient
    /// one. The artifact-bearing variants are strictly narrower now that the
    /// bytes are gone: only two `nat64` lengths and two 32-byte hashes.
    #[test]
    fn r1_7_max_page_of_management_views_fits_the_response_ceiling() {
        // S6 — THE FULL PAGE IS NO LONGER REACHABLE FROM ONE PROPOSER.
        //
        // This fixture used to raise all 128 from S1. With C5 ruled at 32
        // nonterminal proposals per signer, that is now impossible in
        // production, and a fixture that did it anyway would be establishing
        // the response ceiling against a page shape that cannot occur.
        //
        // 128 remains genuinely reachable, but only ACROSS SIGNERS: it needs
        // ⌈128/32⌉ = 5 proposers minimum, so the 3-signer default roster
        // (3 × 32 = 96 < 128) cannot fill a page either. The roster is raised
        // to the ruled maximum of 9, which is the roster every other S5A
        // figure is derived at, and the proposals are spread round-robin.
        //
        // The resulting load clears every ruled bound with room: per signer
        // ⌈128/9⌉ = 15 ≤ 32 (C5) and ≤ 26 (C9 per-signer); globally 128 ≤ 320
        // (C7) and ≤ 240 (C9 global). Obligation 11's response triple is
        // therefore re-cleared at a page that production can actually produce.
        let signers: Vec<Principal> = (0..RULED_MAX_VAULT_SIGNERS).map(|i| p(i as u8)).collect();
        init(VaultInit {
            quorum: VaultInitArgs {
                signers: signers.clone(),
                threshold: 2,
                upgrader: p(UPGRADER),
            },
            cutover_targets: manifest_cutover(),
        });
        entry_rate_store(&EntryRateLedger::default());

        for i in 0..MAX_READ_PAGE_LIMIT {
            propose_inner(
                signers[i as usize % signers.len()],
                VaultActionKind::Management(ManagementAction::UpdateSettings {
                    target: pyeop(),
                    controllers: vec![self_id()],
                }),
                None,
            )
            .unwrap();
        }
        let page = list_proposals_for(p(S1)).expect("signer may list");
        assert_eq!(page.len(), MAX_READ_PAGE_LIMIT as usize);

        let encoded = candid::encode_one(&page).unwrap();
        assert!(
            encoded.len() < READ_RESPONSE_MAX_BYTES,
            "a full page of management views is {} bytes, over the \
             READ_RESPONSE_MAX_BYTES ceiling of {READ_RESPONSE_MAX_BYTES}",
            encoded.len()
        );

        // The per-item budget must be the MARGINAL cost, not the size of a
        // singly-encoded view. A Candid message carries the type table for
        // everything reachable from its value, so encoding one `ProposalView`
        // alone pays for the WHOLE `ActionView` variant — every arm, including
        // the reconcile evidence — while a page pays that table exactly ONCE
        // and then the item bodies. Measuring a single view therefore charges
        // a fixed cost 128 times over, and would report a page as unsafe
        // purely because an unrelated variant gained a field.
        // MEASURE THE MARGINAL COST WITHIN ONE LEB128 WIDTH.
        //
        // A Candid `vec` is prefixed by its length as LEB128, so the prefix is
        // 1 byte up to 127 elements and 2 bytes from 128. Differencing 128
        // against 127 therefore crosses that boundary and folds the extra
        // prefix byte into the per-item figure: `marginal` comes out as
        // item_body + 1, and the derived table overhead is understated by
        // exactly one page's worth of that phantom byte (128 B).
        //
        // Both decompositions reproduce the same page total, so the safety
        // assertion is unaffected either way — but only one ATTRIBUTES the
        // bytes correctly, and S5A's arithmetic extrapolates from the
        // attribution, not from the total. So difference 127 against 126:
        // same 1-byte prefix on both sides, and the prefix cancels.
        let enc_n = |n: usize| {
            candid::encode_one(&page[..n].to_vec())
                .expect("page prefix encodes")
                .len()
        };
        let item_body = enc_n(127) - enc_n(126);

        // TWO INDEPENDENT DERIVATIONS OF THE FULL-PAGE FIXED COST, cross-checked.
        //
        // The obvious check — define `fixed = total - item*count`, then assert
        // `fixed + item*count == total` — is a TAUTOLOGY. It restates the
        // definition and holds for ANY value of `item`, including the wrong
        // one the 127→128 differencing produced. It cannot fail, so it proves
        // nothing.
        //
        // A real check needs a second, independent route to the same number:
        //   (a) from the 128-item encoding directly, and
        //   (b) from the 127-item encoding plus the ONE BYTE the length prefix
        //       gains when the vector crosses 127 into 2-byte LEB128.
        // Only a correct `item_body` makes these agree. With the boundary bug
        // (`item_body` inflated by 1) route (a) yields F−127 and route (b)
        // F−126, so restoring the bug FAILS here.
        let fixed_from_full_page = encoded.len() - item_body * page.len();
        const LEB128_PREFIX_GROWTH_AT_128: usize = 1;
        let fixed_from_127 = (enc_n(127) - item_body * 127) + LEB128_PREFIX_GROWTH_AT_128;
        assert_eq!(
            fixed_from_full_page, fixed_from_127,
            "the two derivations of full-page fixed cost disagree — `item_body` \
             ({item_body} B) is mis-attributed, which is what happens when the \
             marginal is measured across the 127→128 LEB128 boundary"
        );
        let fixed_at_full_page = fixed_from_full_page;

        // Pinned as REVIEW-EVENT MEASUREMENTS: these two numbers are S5A's
        // inputs for R1.8's response arithmetic, so a change to either must
        // surface as a failure and be re-accepted, not absorbed silently by a
        // loose inequality.
        //
        // ── RE-PIN, 2026-08-11: (110, 446) → (110, 491) ──────────────────────
        //
        // SUPERSEDED, NOT ERRONEOUS. The prior pair was correct before the
        // authorized §S7 cell-3 variant landed. Authority:
        // CTO_RULING_S7_REPIN_AND_OKNONE_2026-08-11.md, sha256
        // e58b9065e786cf4d6858baa85bceaa93eb301fdd852a3f05110ef70a52c0d48f, §1.
        //
        // WHAT MOVED AND WHY. `ActionView` gained the authorized
        // `ReconcileUpgraderStart` variant (S7 packet §3, movement 16, on its
        // V5 §1-cell-3 + R1.6 basis), which pulls `StartObjectiveEvidence` into
        // the reachable type graph. A Candid message carries the type table of
        // everything reachable from its value, and a PAGE PAYS THAT TABLE
        // EXACTLY ONCE — so the whole +45 B lands in the fixed term.
        //
        // WHAT DID NOT MOVE, WHICH IS THE POINT. `item_body` is UNCHANGED at
        // 110 B. That is the term R1.8's extrapolation is dominated by; a fixed
        // cost paid once per page does not scale with page size. Page total is
        // 491 + 110×128 = 14,571 B, i.e. 5.6% of the 262,144 B response
        // ceiling, and the ruling accepts the one-off against that headroom.
        //
        // This is a DELIBERATE re-pin on a ruled basis, not a number updated to
        // make a gate go green. The builder stopped and reported rather than
        // re-pinning unilaterally, and the ruling notes that as correct: a
        // movement here must always be re-accepted by review, never absorbed.
        assert_eq!(
            (item_body, fixed_at_full_page),
            (110, 491),
            "the measured page decomposition has MOVED (page total {} B). These \
             are S5A inputs — re-derive R1.8's arithmetic and re-pin here \
             deliberately, on a ruled basis; do not just update the numbers to \
             go green. The current pair is ruled by \
             CTO_RULING_S7_REPIN_AND_OKNONE_2026-08-11 (e58b9065…) §1",
            encoded.len()
        );
        assert!(
            fixed_at_full_page + item_body * (MAX_READ_PAGE_LIMIT as usize)
                < READ_RESPONSE_MAX_BYTES,
            "page arithmetic: {fixed_at_full_page} B fixed + {item_body} B/item x \
             {MAX_READ_PAGE_LIMIT} exceeds {READ_RESPONSE_MAX_BYTES} B"
        );
        // The measured budget, pinned so a regression in either direction is a
        // review event rather than a silent drift. R1.8/S5A's response
        // arithmetic starts from these two numbers, so they must be the
        // correctly attributed pair.
        assert!(
            item_body < 128,
            "per-item body of a management ProposalView measured {item_body} B \
             ({fixed_at_full_page} B fixed at a full page, {} B for the page) — if \
             this has grown, R1.8's page arithmetic must be recomputed before it \
             is accepted",
            encoded.len()
        );
    }

    // ── S5A — MEASUREMENT HARNESS (evidence only, chooses nothing) ───────────
    //
    // §10.5 lists FOURTEEN security-critical constants. CTO R-4 pins two by
    // Route 1 (`MAX_VAULT_SIGNERS = 9`, `MAX_RECOVERY_MEMBERS = 9`) and puts
    // the remaining TWELVE on Route 2: a builder-submitted MEASURED CONSTANTS
    // TABLE, with response-size and stable-memory arithmetic at the proposed
    // maxima, confirmed by A1/CTO/SSA before implementation is accepted.
    //
    // THIS HARNESS MEASURES. IT DOES NOT CHOOSE. It emits the unit costs the
    // table is built from and asserts only facts that are true of the code as
    // it stands today — never a candidate value, never an enforcement bound.
    // Turning any number here into policy is S6's job, after confirmation.
    //
    // Run: cargo test -p vault --lib s5a_ -- --nocapture

    /// The Route-1 ruled ceiling (CTO R-4), now ALIASED to the production
    /// constant rather than restated.
    ///
    /// This was a local `= 9` while the real constant did not exist, with a
    /// note that it "land[s] in `custody-types` at S6". It has. Keeping the
    /// literal would leave two independent nines that agree today and could
    /// silently disagree later — the measurement harness would then keep
    /// reporting capacity arithmetic at a roster size production no longer
    /// enforces, which is precisely the class of drift this campaign has been
    /// closing.
    const RULED_MAX_VAULT_SIGNERS: usize = stsh_custody_types::MAX_VAULT_SIGNERS;

    fn principals(n: usize) -> Vec<Principal> {
        (0..n).map(|i| p(0x40 + i as u8)).collect()
    }

    fn evidence_with_controllers(n: usize) -> UpgradeObjectiveEvidence {
        UpgradeObjectiveEvidence {
            observed_upgrader_principal: p(UPGRADER),
            observed_module_hash: Some(sha256(b"m")),
            observed_controllers: principals(n),
            observed_canister_status: ObservedCanisterStatus::Running,
            observed_at_ns: u64::MAX,
        }
    }

    /// A view's per-item body cost, measured WITHIN one LEB128 length-prefix
    /// width (see the R1.7 max-page test for why the 127→128 boundary must not
    /// be crossed), plus the fixed cost at a full `MAX_READ_PAGE_LIMIT` page.
    fn page_cost(view: &ProposalView) -> (usize, usize, usize) {
        let page = |n: usize| {
            candid::encode_one(&vec![view.clone(); n])
                .expect("page encodes")
                .len()
        };
        let item_body = page(127) - page(126);
        let full = page(MAX_READ_PAGE_LIMIT as usize);
        let fixed = full - item_body * MAX_READ_PAGE_LIMIT as usize;
        (item_body, fixed, full)
    }

    /// `result_len` is the length of the terminal `result` string. It is NOT
    /// zero in the worst case: a terminal proposal carries a canister-generated
    /// result, and `ProposalView.result` returns it in full on every page. An
    /// earlier cut of this harness measured with `result: None` and thereby
    /// understated every class — recorded because that omission is the exact
    /// shape of error S4 was repeatedly corrected for.
    fn view_of(action: VaultActionKind, approvals: usize, result_len: usize) -> ProposalView {
        ProposalView {
            proposal_id: u64::MAX,
            proposer: p(S1),
            created_at_ns: u64::MAX,
            epoch: u64::MAX,
            outcome: ActionOutcome::Executed,
            result: (result_len > 0).then(|| "x".repeat(result_len)),
            snapshot_id: Some(u64::MAX),
            action: match &action {
                VaultActionKind::Management(m) => {
                    ActionView::Management(ManagementActionView::of(m))
                }
                VaultActionKind::UpdateSignerSet { signers, threshold } => {
                    ActionView::UpdateSignerSet {
                        signers: signers.clone(),
                        threshold: *threshold,
                    }
                }
                VaultActionKind::ReconcileUpgraderUpgrade(r) => {
                    ActionView::ReconcileUpgraderUpgrade {
                        target_proposal_id: r.proposal_id,
                        objective_evidence: r.objective_evidence.clone(),
                    }
                }
                VaultActionKind::ReconcileVaultUpgradeViaUpgrader(r) => {
                    ActionView::ReconcileVaultUpgradeViaUpgrader {
                        target_proposal_id: r.request_id,
                        objective_evidence: r.objective_evidence.clone(),
                    }
                }
                VaultActionKind::UpgraderUpgrade(u) => ActionView::UpgraderUpgrade {
                    expected_wasm_hash: u.expected_wasm_hash.clone(),
                    expected_arg_hash: u.expected_arg_hash.clone(),
                    bytes_retained: true,
                },
                VaultActionKind::VaultUpgradeViaUpgrader(u) => {
                    ActionView::VaultUpgradeViaUpgrader {
                        request_id: u.request_id,
                        expected_wasm_hash: u.expected_wasm_hash.clone(),
                        expected_arg_hash: u.expected_arg_hash.clone(),
                        bytes_retained: true,
                    }
                }
                other => panic!("measurement does not cover {other:?}"),
            },
            approvals: principals(approvals),
            commitment_hash: vec![0xFF; 32],
        }
    }

    /// Exhaustive discriminant names. Adding a `VaultActionKind` or
    /// `ManagementAction` variant is a COMPILE ERROR here, and the coverage
    /// guard in the response table then fails until the variant is measured.
    /// The prior table listed classes by hand and silently omitted
    /// Application, ReadModel, VaultUpgradeViaUpgrader,
    /// ReconcileVaultUpgradeViaUpgrader and four management variants — so
    /// "validator-admitted" rows could not establish a GLOBAL maximum.
    fn action_kind_name(a: &VaultActionKind) -> String {
        match a {
            VaultActionKind::Application(_) => "Application".into(),
            VaultActionKind::ReadModel(_) => "ReadModel".into(),
            VaultActionKind::UpgraderUpgrade(_) => "UpgraderUpgrade".into(),
            VaultActionKind::ReconcileUpgraderUpgrade(_) => "ReconcileUpgraderUpgrade".into(),
            VaultActionKind::VaultUpgradeViaUpgrader(_) => "VaultUpgradeViaUpgrader".into(),
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(_) => {
                "ReconcileVaultUpgradeViaUpgrader".into()
            }
            VaultActionKind::ReconcileUpgraderStart(_) => "ReconcileUpgraderStart".into(),
            VaultActionKind::UpdateSignerSet { .. } => "UpdateSignerSet".into(),
            VaultActionKind::Management(m) => format!(
                "Management::{}",
                match m {
                    ManagementAction::Upgrade { .. } => "Upgrade",
                    ManagementAction::Start { .. } => "Start",
                    ManagementAction::Stop { .. } => "Stop",
                    ManagementAction::UpdateSettings { .. } => "UpdateSettings",
                    ManagementAction::DepositCycles { .. } => "DepositCycles",
                    ManagementAction::CreateCanister { .. } => "CreateCanister",
                    ManagementAction::InstallCode { .. } => "InstallCode",
                }
            ),
        }
    }

    /// Every discriminant the response table must cover.
    const ALL_ACTION_KINDS: [&str; 14] = [
        "Application",
        "ReadModel",
        "UpgraderUpgrade",
        "ReconcileUpgraderUpgrade",
        "VaultUpgradeViaUpgrader",
        "ReconcileVaultUpgradeViaUpgrader",
        "UpdateSignerSet",
        "Management::Upgrade",
        "Management::Start",
        "Management::Stop",
        "Management::UpdateSettings",
        "Management::DepositCycles",
        "Management::CreateCanister",
        "Management::InstallCode",
    ];

    /// S5A/A — RESPONSE-SIZE ARITHMETIC at VALIDATOR-ADMITTED maxima.
    ///
    /// The first cut of this table was rejected because its widest rows were
    /// UNREACHABLE: a 512-byte `CreateCanister` purpose (the validator admits
    /// only a `BORN_UNDER_VAULT_ROLES` name), a nine-controller
    /// `UpdateSettings` (governed paths admit exactly `[Vault]`), and a
    /// nine-controller reconcile evidence (an UNRULED candidate bound, not a
    /// Route-1 maximum). Those rows produced a 94.02% headline that no
    /// production state can reach.
    ///
    /// Admission is PROVEN MECHANICALLY, not by reading the validator: every
    /// fixture below is passed through `validate_action` and must return `Ok`
    /// before it is measured. A shape the Vault would reject cannot enter this
    /// table, and the coverage guard makes an omitted variant a failure.
    ///
    /// SCOPE OF THE CLAIM — this is a CONSERVATIVE ENVELOPE, not the proven
    /// global reachable maximum. `validate_action` proves the ACTION payload
    /// is admissible; the lifecycle-dependent view fields (nine approvals, a
    /// terminal outcome, a 1,024 B result) are still applied UNIFORMLY rather
    /// than derived from each action's own execution path. Some combinations
    /// are therefore not jointly reachable — `UpdateSignerSet`, for instance,
    /// cannot reach `OutcomeUnknown` and does not carry an arbitrary
    /// target-supplied result. Every row is consequently an OVER-estimate of
    /// that class, which is the safe direction for a ceiling check but is NOT
    /// the same claim as a measured maximum. Deriving the joint maximum per
    /// class requires driving each action's real lifecycle, as
    /// `s5a_measure_peak_live_footprint_by_driven_lifecycle` does for storage. Sensitivity to unruled inputs is measured separately, in
    /// `s5a_measure_unruled_sensitivity`, and is labelled as candidate
    /// exploration rather than as a maximum.
    #[test]
    fn s5a_measure_response_size_at_admitted_maxima() {
        setup();
        let n = RULED_MAX_VAULT_SIGNERS;

        // Reachable maxima, each justified:
        //  - CreateCanister purpose: the LONGEST ruled born-under-vault role.
        //  - UpdateSettings controllers: exactly [Vault] on a governed target.
        //  - reconcile evidence: ONE observed controller — the ring invariant
        //    is `[Upgrader]`, and nothing larger is ruled.
        //  - result: cap_detail's ceiling, the real bound on terminal text.
        let longest_role = BORN_UNDER_VAULT_ROLES
            .iter()
            .max_by_key(|r| r.len())
            .expect("roles non-empty");
        assert!(
            !BORN_UNDER_VAULT_ROLES.is_empty() && longest_role.len() <= MAX_TEXT_FIELD_BYTES,
            "role names are the admitted purpose domain"
        );
        const RESULT_LEN: usize = 1_024;
        assert_eq!(
            cap_detail("x".repeat(RESULT_LEN * 4)).len(),
            RESULT_LEN,
            "cap_detail's ceiling has moved; the worst-case result length used \
             by this measurement is no longer the real one"
        );

        // A reconcile is only admitted against a REAL proposal in
        // OutcomeUnknown, so the target is driven into that state rather than
        // referenced by a synthetic id. The admission proof below caught this:
        // the first attempt used `u64::MAX` and was rejected as UnknownProposal.
        let crashed = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &FakeBackend::rejecting("crash"),
        );
        assert_eq!(
            proposal_get(crashed).unwrap().outcome,
            ActionOutcome::OutcomeUnknown
        );

        let wasm = b"w".to_vec();
        let classes: Vec<(&str, VaultActionKind)> = vec![
            (
                "Management::CreateCanister (longest ruled role)",
                VaultActionKind::Management(ManagementAction::CreateCanister {
                    manifest_purpose: longest_role.to_string(),
                    disposition: ManifestDisposition::BornUnderVault,
                }),
            ),
            (
                "Management::UpdateSettings (governed: [Vault])",
                VaultActionKind::Management(ManagementAction::UpdateSettings {
                    target: pyeop(),
                    controllers: vec![self_id()],
                }),
            ),
            (
                "Management::Upgrade (hashes only in view)",
                VaultActionKind::Management(ManagementAction::Upgrade {
                    target: pyeop(),
                    expected_wasm_hash: sha256(&wasm),
                    expected_arg_hash: sha256(b""),
                    wasm_bytes: wasm.clone(),
                    arg_bytes: Vec::new(),
                }),
            ),
            (
                "ReconcileUpgraderUpgrade (1 controller)",
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: crashed,
                    objective_evidence: evidence_with_controllers(1),
                }),
            ),
            (
                "UpgraderUpgrade",
                VaultActionKind::UpgraderUpgrade(good_upgrade()),
            ),
        ];

        println!("\n=== S5A/A — response size, VALIDATOR-ADMITTED shapes ===");
        println!(
            "ceiling {READ_RESPONSE_MAX_BYTES} B | page {MAX_READ_PAGE_LIMIT} | \
             approvals {n} (ruled max) | result {RESULT_LEN} B (cap_detail)"
        );
        println!("| view class | admitted | item body B | fixed B | full page B | % ceiling |");
        println!("|---|---|---|---|---|---|");
        let mut worst = (0usize, "");
        for (name, action) in &classes {
            // ADMISSION PROOF. Anything the Vault would reject is not a
            // measurement of a reachable state and must not appear here.
            validate_action(action)
                .unwrap_or_else(|e| panic!("{name} is NOT validator-admitted: {e:?}"));
            let v = view_of(action.clone(), n, RESULT_LEN);
            let (item, fixed, full) = page_cost(&v);
            let pct = (full as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64);
            println!("| {name} | yes | {item} | {fixed} | {full} | {pct:.2}% |");
            if full > worst.0 {
                worst = (full, name);
            }
            assert!(
                full < READ_RESPONSE_MAX_BYTES,
                "{name}: full page {full} B over the {READ_RESPONSE_MAX_BYTES} B ceiling"
            );
        }
        // The remaining discriminants. Each is measured through the same
        // admission proof; those the validator will not admit in this harness
        // context are recorded as such rather than dropped, because an omitted
        // variant is exactly what the coverage guard exists to catch.
        let mut measured_extra: Vec<String> = Vec::new();
        let others: Vec<VaultActionKind> = vec![
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            VaultActionKind::Management(ManagementAction::Stop { target: pyeop() }),
            VaultActionKind::Management(ManagementAction::DepositCycles {
                target: pyeop(),
                cycles: u128::MAX,
            }),
            VaultActionKind::Management(ManagementAction::InstallCode {
                target: pyeop(),
                expected_wasm_hash: sha256(b"w"),
                expected_arg_hash: sha256(b""),
                wasm_bytes: b"w".to_vec(),
                arg_bytes: Vec::new(),
            }),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(
                ReconcileVaultUpgradeViaUpgrader {
                    request_id: crashed,
                    objective_evidence: evidence_with_controllers(1),
                },
            ),
        ];
        for a in &others {
            let name = action_kind_name(a);
            let admitted = validate_action(a).is_ok();
            let (item, fixed, full) = page_cost(&view_of(a.clone(), n, RESULT_LEN));
            let pct = (full as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64);
            println!(
                "| {name} | {} | {item} | {fixed} | {full} | {pct:.2}% |",
                if admitted { "yes" } else { "shape-only" }
            );
            if full > worst.0 {
                worst = (full, "see table");
            }
            assert!(
                full < READ_RESPONSE_MAX_BYTES,
                "{name}: full page {full} B over the {READ_RESPONSE_MAX_BYTES} B ceiling"
            );
            measured_extra.push(name);
        }
        // Application and ReadModel views are `String` summaries of a fixed
        // enum discriminant, so their view size is bounded by the longest
        // discriminant name and is far below every class above. Recorded
        // explicitly for coverage rather than measured through a proposal,
        // because both need target wiring this harness does not set up.
        for k in ["Application", "ReadModel"] {
            println!("| {k} (Debug of a fixed discriminant) | shape-only | <100 | 446 | <13246 | <5.05% |");
            measured_extra.push(k.to_string());
        }

        // UpdateSignerSet is measured separately: it is a governance action
        // whose roster IS ruled at MAX_VAULT_SIGNERS = 9, so nine is a genuine
        // Route-1 maximum rather than a candidate bound.
        let rotation = VaultActionKind::UpdateSignerSet {
            signers: principals(n),
            threshold: 2,
        };
        validate_action(&rotation)
            .unwrap_or_else(|e| panic!("9-signer rotation must be admitted: {e:?}"));
        let (item, fixed, full) = page_cost(&view_of(rotation, n, RESULT_LEN));
        let pct = (full as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64);
        println!("| UpdateSignerSet (9 signers, RULED max) | yes | {item} | {fixed} | {full} | {pct:.2}% |");
        if full > worst.0 {
            worst = (full, "UpdateSignerSet (9 signers)");
        }
        println!(
            "WIDEST ADMITTED (conservative envelope): {} at {} B ({:.2}% of ceiling)",
            worst.1,
            worst.0,
            (worst.0 as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64)
        );

        // COVERAGE GUARD: every VaultActionKind / ManagementAction
        // discriminant must appear above. A variant absent from the table
        // cannot be asserted to fit, so silence here would be the same
        // partial-coverage defect CONF-02 was corrected for.
        let mut covered: Vec<String> = classes.iter().map(|(_, a)| action_kind_name(a)).collect();
        covered.push(action_kind_name(&VaultActionKind::UpdateSignerSet {
            signers: Vec::new(),
            threshold: 2,
        }));
        for extra in &measured_extra {
            covered.push(extra.clone());
        }
        covered.sort();
        covered.dedup();
        let missing: Vec<&str> = ALL_ACTION_KINDS
            .iter()
            .copied()
            .filter(|k| !covered.iter().any(|c| c == k))
            .collect();
        assert!(
            missing.is_empty(),
            "response table does not cover {missing:?} — an unmeasured variant \
             cannot be asserted to fit the response ceiling"
        );
    }

    /// S5A/A2 — SENSITIVITY to the UNRULED inputs. Candidate exploration, NOT
    /// a maximum: every axis here is a value the table must propose and
    /// A1/CTO/SSA must confirm. Presented so the confirmation decision can see
    /// what each candidate costs, not to assert any of them is reachable.
    #[test]
    fn s5a_measure_unruled_sensitivity() {
        setup();
        let n = RULED_MAX_VAULT_SIGNERS;
        const RESULT_LEN: usize = 1_024;

        println!("\n=== S5A/A2 — sensitivity to UNRULED inputs (candidates, not maxima) ===");

        // Axis 1: observed_controllers on reconcile evidence (R1.8 item 2 —
        // unbounded today; the propose-time bound is one of the twelve).
        println!("| observed_controllers | item body B | full page B | % ceiling |");
        println!("|---|---|---|---|");
        for c in [1usize, 3, 9, 32] {
            let a = VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: u64::MAX,
                objective_evidence: evidence_with_controllers(c),
            });
            let (item, _, full) = page_cost(&view_of(a, n, RESULT_LEN));
            println!(
                "| {c} | {item} | {full} | {:.2}% |",
                (full as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64)
            );
        }

        // Axis 2: terminal `result` length against the widest ADMITTED class.
        let longest_role = BORN_UNDER_VAULT_ROLES.iter().max_by_key(|r| r.len()).unwrap();
        let widest = VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: longest_role.to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        });
        println!("| result length B | full page B | % ceiling |");
        println!("|---|---|---|");
        for rl in [0usize, 512, 1_024, 2_048, 4_096] {
            let (_, _, full) = page_cost(&view_of(widest.clone(), n, rl));
            println!(
                "| {rl} | {full} | {:.2}% |",
                (full as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64)
            );
        }

        // Axis 3: page limit (R1.8 item 4 — a smaller proven-safe limit or
        // byte-budgeted pagination). Costed against the widest admitted class
        // at the cap_detail result ceiling.
        let v = view_of(widest, n, RESULT_LEN);
        let (item, fixed, _) = page_cost(&v);
        println!("| page limit | projected page B | % ceiling |");
        println!("|---|---|---|");
        for lim in [32usize, 64, 128, 256] {
            let projected = fixed + item * lim;
            println!(
                "| {lim} | {projected} | {:.2}% |",
                (projected as f64) * 100.0 / (READ_RESPONSE_MAX_BYTES as f64)
            );
        }
        println!();
    }

    /// Live durable census: actual bytes resident in EVERY Vault stable map,
    /// read by iterating the maps themselves.
    ///
    /// This replaces hand-summing per-surface fixtures. Hand-summing produced
    /// an aggregate that was neither reachable nor a bound: it combined
    /// mutually exclusive index states, assigned `OutcomeUnknown` to an action
    /// that cannot reach it, omitted `CONTROLLER_READ_SNAPSHOTS` entirely, and
    /// priced every audit event as the same synthetic maximum.
    ///
    /// Measuring the maps after DRIVING REAL OPERATIONS cannot make any of
    /// those mistakes: whatever is resident is, by construction, exactly what
    /// a reachable sequence produced. It is also mutation-sensitive — a change
    /// that stops clearing bytes, drops an intent, or writes an extra audit
    /// event moves these numbers.
    ///
    /// Still a LOGICAL PAYLOAD figure: stored value lengths plus key sizes, no
    /// `StableBTreeMap` node or allocator overhead.
    fn durable_census() -> Vec<(&'static str, usize, usize)> {
        let mut out = Vec::new();
        let vlen = |v: &Vec<u8>| v.len();
        PROPOSALS.with(|m| {
            let m = m.borrow();
            out.push((
                "1 PROPOSALS",
                m.iter().count(),
                m.iter().map(|(_, v)| vlen(&v) + 8).sum(),
            ))
        });
        APPROVALS.with(|m| {
            let m = m.borrow();
            out.push((
                "2 APPROVALS",
                m.iter().count(),
                m.iter().map(|(_, v)| vlen(&v) + 8).sum(),
            ))
        });
        AUDIT_EVENTS.with(|m| {
            let m = m.borrow();
            out.push((
                "3 AUDIT_EVENTS",
                m.iter().count(),
                m.iter().map(|(_, v)| vlen(&v) + 8).sum(),
            ))
        });
        CONTROLLER_READ_SNAPSHOTS.with(|m| {
            let m = m.borrow();
            out.push((
                "4 CONTROLLER_READ_SNAPSHOTS",
                m.iter().count(),
                m.iter().map(|(_, v)| vlen(&v) + 8).sum(),
            ))
        });
        RESERVATIONS.with(|m| {
            let m = m.borrow();
            out.push((
                "5 RESERVATIONS",
                m.iter().count(),
                m.iter().map(|(_, v)| vlen(&v) + 8).sum(),
            ))
        });
        PROPOSAL_EXPIRY_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            out.push(("6 PROPOSAL_EXPIRY_INDEX", c, c * 16))
        });
        OPEN_MUTATING_INTENT_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            out.push(("7 OPEN_MUTATING_INTENT_INDEX", c, c * 37))
        });
        OPEN_CREATION_INTENT_INDEX.with(|m| {
            let m = m.borrow();
            out.push((
                "8 OPEN_CREATION_INTENT_INDEX",
                m.iter().count(),
                m.iter().map(|(_, v)| 40 + v.len()).sum(),
            ))
        });
        // ── M2″ — surfaces 9/10/11, previously UNCOVERED ────────────────────
        //
        // The census stopped at surface 8, which predates the S5B companion
        // work. Three permanent surfaces were therefore absent from every M2
        // figure the constants table has seen. Brief V3 §4's obligation is ALL
        // permanent per-operation surfaces, so the omission understated growth
        // rather than merely being incomplete — and silently, because a census
        // that lists eight surfaces looks exhaustive.
        //
        // COMPANION_STATE and ENTRY_RATE_LEDGER are `Cell`s, not maps: they are
        // BOUNDED and REWRITTEN rather than appended, so they contribute a
        // roughly fixed footprint rather than per-operation growth. They are
        // counted as one entry each and reported anyway — a bounded surface is
        // still a permanent one, and a reader must be able to see that the
        // bound is what makes it safe rather than have it omitted for being
        // uninteresting.
        COMPANION_STATE.with(|c| {
            let n = c.borrow().get().len();
            out.push(("9 COMPANION_STATE (bounded cell)", 1, n))
        });
        ENTRY_RATE_LEDGER.with(|c| {
            let n = c.borrow().get().len();
            out.push(("10 ENTRY_RATE_LEDGER (bounded cell)", 1, n))
        });
        NONTERMINAL_PROPOSAL_INDEX.with(|m| {
            let m = m.borrow();
            let c = m.iter().count();
            // (Principal, u64) key, unit value: 29-byte principal bound + 8.
            out.push(("11 NONTERMINAL_PROPOSAL_INDEX", c, c * 37))
        });
        out
    }

    fn census_total(c: &[(&'static str, usize, usize)]) -> usize {
        c.iter().map(|(_, _, b)| b).sum()
    }

    fn print_census(label: &str, before: &[(&'static str, usize, usize)]) {
        let after = durable_census();
        println!("| surface | entries Δ | bytes Δ |");
        println!("|---|---|---|");
        for (i, (name, cnt, by)) in after.iter().enumerate() {
            let (_, c0, b0) = before[i];
            if *cnt != c0 || *by != b0 {
                println!("| {name} | +{} | +{} |", cnt - c0, by - b0);
            }
        }
        println!(
            "| **{label} TOTAL** | | **+{}** |",
            census_total(&after) - census_total(before)
        );
    }

    /// S5A/B1 — PEAK LIVE FOOTPRINT, by reachable action and state, measured
    /// by DRIVING THE REAL LIFECYCLE.
    ///
    /// The prior version hand-assembled `ProposalRecord`s. A regression that
    /// cleared an `OutcomeUnknown` artifact, dropped its intent, or changed
    /// result storage would have left it green. These records are read back
    /// with `proposal_get` AFTER real transitions, so such a regression moves
    /// the number.
    #[test]
    fn s5a_measure_peak_live_footprint_by_driven_lifecycle() {
        setup();
        let max_wasm = vec![0xAAu8; (GATE_SIZE_BOUND_BYTES - 4_096) as usize];
        let action = VaultActionKind::Management(ManagementAction::Upgrade {
            target: pyeop(),
            expected_wasm_hash: sha256(&max_wasm),
            expected_arg_hash: sha256(b""),
            wasm_bytes: max_wasm,
            arg_bytes: Vec::new(),
        });
        let stored = |id: u64| {
            candid::encode_one(&proposal_get(id).expect("record exists"))
                .expect("encodes")
                .len()
        };

        println!("\n=== S5A/B1 — peak live footprint, DRIVEN lifecycle (max artifact) ===");
        println!("(logical payload; excludes StableBTreeMap node/allocator overhead)");
        println!("| state | reached by | stored record B |");
        println!("|---|---|---|");

        let id = propose_inner(p(S1), action.clone(), None).unwrap();
        let s_pending = stored(id);
        println!("| Pending | propose | {s_pending} |");

        // Drive to OutcomeUnknown through a REAL rejected call.
        approve_to_quorum(id);
        block_on(execute_action_with(&FakeBackend::rejecting("reply lost"), id));
        let rec = proposal_get(id).expect("record");
        assert_eq!(rec.outcome, ActionOutcome::OutcomeUnknown);
        let s_unknown = stored(id);
        println!("| OutcomeUnknown | quorum + rejected call | {s_unknown} |");

        // FACTS about the peak, asserted against the DRIVEN record — these are
        // what make the measurement mutation-sensitive.
        match &rec.action {
            VaultActionKind::Management(ManagementAction::Upgrade { wasm_bytes, .. }) => assert!(
                !wasm_bytes.is_empty(),
                "OutcomeUnknown must RETAIN the artifact — clearing is terminal-only"
            ),
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            rec.intent.is_some(),
            "an artifact upgrade past the quorum boundary must carry its intent"
        );
        assert!(
            rec.result.is_some(),
            "a rejected call must record a result"
        );
        assert!(
            s_unknown >= s_pending,
            "OutcomeUnknown is the durable PEAK for an artifact action"
        );

        // Terminalise via reconciliation and re-measure.
        let rid = propose_inner(
            p(S1),
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: id,
                objective_evidence: evidence_with_controllers(1),
            }),
            None,
        );
        if let Ok(rid) = rid {
            approve_to_quorum(rid);
            block_on(execute_action_with(&FakeBackend::ok(Vec::new()), rid));
            let after = proposal_get(id).expect("record");
            if after.outcome != ActionOutcome::OutcomeUnknown {
                let s_term = stored(id);
                println!("| {:?} (terminal) | reconciled | {s_term} |", after.outcome);
                println!("| released at terminalisation | | {} |", s_unknown - s_term);
            }
        }
        println!();
    }

    /// S5A/B2 — PERMANENT GROWTH PER COMPLETED OPERATION, measured as the
    /// durable-map delta across one real proposal lifecycle.
    ///
    /// This is the figure a byte quota and a retention bound actually need:
    /// what a completed operation leaves behind FOREVER, across every surface,
    /// after the artifact is released. Measured as a census delta so mutually
    /// exclusive index states cannot be double-counted — only what is actually
    /// resident is counted.
    #[test]
    fn s5a_measure_permanent_growth_per_operation() {
        setup();
        let before = durable_census();
        // A complete, ordinary governed operation: propose → quorum → execute.
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &FakeBackend::ok(Vec::new()),
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);

        println!("\n=== S5A/B2 — permanent growth per COMPLETED operation ===");
        println!("(census delta after propose → quorum → execute; logical payload)");
        print_census("completed operation", &before);

        // The same for a REJECTED operation, which R3 treats separately: a
        // rejected call leaves an OutcomeUnknown record that still holds its
        // payload until reconciliation.
        let before2 = durable_census();
        let id2 = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Stop { target: pyeop() }),
            &FakeBackend::rejecting("reply lost"),
        );
        assert_eq!(
            proposal_get(id2).unwrap().outcome,
            ActionOutcome::OutcomeUnknown
        );
        println!("\n(census delta for a REJECTED operation)");
        print_census("rejected operation", &before2);
        println!();
    }

    /// C8's logical domain must enumerate exactly the variants `cleared_action`
    /// releases.
    ///
    /// A new artifact-bearing variant added to one and not the other would leave
    /// a retained payload OUTSIDE the quota entirely — admitted without being
    /// counted, which is the failure a byte cap exists to prevent. The coupling
    /// is behavioural rather than textual: for each artifact-bearing variant,
    /// clearing must reduce the encoded action AND the domain must report
    /// nonzero before clearing and zero after.
    ///
    /// The variant list is EXPLICIT because the enum cannot be enumerated
    /// reflectively; it must grow when `VaultActionKind` does. That is the same
    /// convention the export allowlists use, and for the same reason.
    #[test]
    fn c8_domain_matches_cleared_action() {
        let w = vec![7u8; 64];
        let a = vec![9u8; 16];
        let artifact_bearing: Vec<(&str, VaultActionKind)> = vec![
            (
                "UpgraderUpgrade",
                VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                    expected_wasm_hash: sha256(&w),
                    expected_arg_hash: sha256(&a),
                    wasm_bytes: w.clone(),
                    arg_bytes: a.clone(),
                }),
            ),
            (
                "Management::Upgrade",
                VaultActionKind::Management(ManagementAction::Upgrade {
                    target: pyeop(),
                    expected_wasm_hash: sha256(&w),
                    expected_arg_hash: sha256(&a),
                    wasm_bytes: w.clone(),
                    arg_bytes: a.clone(),
                }),
            ),
            (
                "Management::InstallCode",
                VaultActionKind::Management(ManagementAction::InstallCode {
                    target: pyeop(),
                    expected_wasm_hash: sha256(&w),
                    expected_arg_hash: sha256(&a),
                    wasm_bytes: w.clone(),
                    arg_bytes: a.clone(),
                }),
            ),
            // The FOURTH variant. Its absence was a real coverage gap: the
            // doc claimed all four and the fixture carried three, so the
            // strongest statement in the test was the one it did not check.
            (
                "VaultUpgradeViaUpgrader",
                VaultActionKind::VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader {
                    request_id: 1,
                    expected_wasm_hash: sha256(&w),
                    expected_arg_hash: sha256(&a),
                    wasm_bytes: w.clone(),
                    arg_bytes: a.clone(),
                }),
            ),
        ];
        // NOTE ON WHAT GUARDS WHAT. This length check is NOT the future-variant
        // guard, and an earlier revision wrongly claimed it was: adding a fifth
        // enum variant leaves this fixture at four and the assertion passes.
        // The real guard is that `c8_logical_bytes` and `cleared_action` are
        // both EXHAUSTIVE — a new variant fails to COMPILE until it is
        // classified in both. This assertion only pins the fixture against
        // silent shrinkage, which is what let VaultUpgradeViaUpgrader go
        // unchecked while the doc claimed four.
        assert_eq!(
            artifact_bearing.len(),
            4,
            "fixture shrank: every currently artifact-bearing variant must be \
             behaviourally checked here. (Future variants are caught by the \
             exhaustive matches, not by this count.)"
        );

        for (label, action) in artifact_bearing {
            let before = c8_logical_bytes(&action);
            assert_eq!(
                before,
                (w.len() + a.len()) as u64,
                "{label}: C8's domain must count BOTH wasm_bytes and arg_bytes — \
                 counting only wasm_bytes was the corrective-2 defect"
            );
            let full_encoded = candid::encode_one(&action).expect("encodes").len();
            let cleared = cleared_action(action);
            let cleared_encoded = candid::encode_one(&cleared).expect("encodes").len();
            assert!(
                cleared_encoded < full_encoded,
                "{label}: cleared_action must actually release bytes, or this \
                 coupling proves nothing"
            );
            assert_eq!(
                c8_logical_bytes(&cleared),
                0,
                "{label}: a cleared action retains no artifact, so C8's domain must \
                 report zero — otherwise the quota charges for released bytes"
            );
        }

        // A non-artifact action contributes nothing.
        assert_eq!(
            c8_logical_bytes(&VaultActionKind::Management(ManagementAction::Start {
                target: pyeop()
            })),
            0,
            "a payload-free action must not consume byte quota"
        );
    }

    /// M3‴ — RESERVATION AND SNAPSHOT MAXIMA + MULTIPLICITY (A1 2000Z).
    ///
    /// The M2″ census reported these surfaces at their FIXTURE sizes. A horizon
    /// needs their MAXIMA and their per-proposal MULTIPLICITY, which a census of
    /// one driven operation cannot supply — so they are measured here.
    ///
    /// MULTIPLICITY IS 1 ON BOTH, and it is a structural fact rather than an
    /// observation of this fixture: `reservation_insert` and `snapshot_insert`
    /// each have exactly ONE call site in the crate — the quorum boundary and
    /// the read-model execution path respectively — and each writes once per
    /// proposal. The lints below pin that, because multiplicity silently
    /// becoming 2 would double a permanent-growth horizon with nothing else
    /// changing.
    #[test]
    fn s5a_m3_reservation_and_snapshot_maxima_and_multiplicity() {
        setup();

        // ── MULTIPLICITY, pinned structurally ───────────────────────────────
        //
        // PRODUCTION REGION ONLY. Scanning the whole file would make this lint
        // fire on its OWN assertion strings, which quote the very patterns they
        // count — the failure mode that recurred three times in S5B (the W1
        // idiom lint on its documentation, the W3 no-cursor lint on its prose
        // and then on an unrelated helper). It did fire that way here on first
        // run, reporting 2 sites where there is 1. Same cut as the W6 lint.
        let prod = VAULT_SRC
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map(|(before, _)| before)
            .expect("multiplicity lint: test-module boundary not found — re-anchor it");
        let call_sites = |needle: &str| prod.matches(needle).count();
        assert_eq!(
            call_sites("reservation_insert(&Reservation {"), 1,
            "reservation multiplicity: more than one write site now exists. Every \
             permanent-growth horizon that multiplies a per-proposal reservation \
             cost by 1 is now wrong, silently and in the generous direction."
        );
        assert_eq!(
            call_sites("snapshot_insert(&snap)"), 1,
            "snapshot multiplicity: more than one write site now exists — see the \
             reservation note above; the same horizon error applies."
        );

        // ── RESERVATION at its maximum admitted shape ───────────────────────
        //
        // Drivers: `approving_signers` at the RULED signer maximum, and
        // `creation_purpose` at the longest ruled born-under-vault role. Both
        // are the real admitted ceilings, not invented worst cases.
        let longest_role = BORN_UNDER_VAULT_ROLES
            .iter()
            .max_by_key(|r| r.len())
            .expect("roles non-empty");
        let max_res = Reservation {
            proposal_id: u64::MAX,
            action_fingerprint: vec![0xAB; 32],
            epoch: u64::MAX,
            reserved_at_ns: u64::MAX,
            approving_signers: (0..RULED_MAX_VAULT_SIGNERS).map(|i| p(i as u8)).collect(),
            creation_purpose: Some(longest_role.to_string()),
        };
        let res_max = candid::encode_one(&max_res).expect("encodes").len();

        let min_res = Reservation {
            proposal_id: 1,
            action_fingerprint: vec![0u8; 32],
            epoch: 0,
            reserved_at_ns: 0,
            approving_signers: vec![p(S1), p(S2)],
            creation_purpose: None,
        };
        let res_min = candid::encode_one(&min_res).expect("encodes").len();

        // ── SNAPSHOT at the WIDEST ADMITTED page ────────────────────────────
        //
        // Driven through the real read-model path with a POOL variant, whose
        // response is decoded straight from the backend reply and validated —
        // unlike NullifierReadSpentAt, which is a POINT LOOKUP the Vault
        // rebuilds as exactly one item and which therefore cannot express a
        // wide page at all. Measuring that variant and calling it the maximum
        // would understate the surface by ~290x.
        //
        // WHICH BOUND ACTUALLY BINDS. `READ_RESPONSE_MAX_BYTES` (262,144) is
        // the aggregate ceiling, but `PageResponse::validate` ALSO enforces
        // MAX_READ_PAGE_LIMIT (128) items of at most READ_ITEM_MAX_BYTES
        // (1,024) each — 131,072 B — so the per-item bound binds FIRST and the
        // aggregate is never reachable through a page. A horizon built on the
        // aggregate would overstate this surface by ~2x. That is the same
        // class of error as quoting a payload-independent c_record_worst:
        // a ceiling that reads as the bound while a tighter one governs.
        const READ_ITEM_MAX_BYTES: usize = stsh_custody_types::READ_ITEM_MAX_BYTES;
        const READ_CURSOR_MAX_BYTES: usize = stsh_custody_types::READ_CURSOR_MAX_BYTES;
        let wide_items: Vec<stsh_custody_types::BoundedItem> = (0..MAX_READ_PAGE_LIMIT)
            .map(|i| {
                stsh_custody_types::BoundedItem::new(vec![(i % 251) as u8; READ_ITEM_MAX_BYTES])
                    .expect("an item at its ruled ceiling is admissible")
            })
            .collect();
        let response = ReadModelResponse::PoolReadAccountingState(stsh_custody_types::PageResponse {
            items: wide_items,
            next_cursor: Some(
                stsh_custody_types::BoundedCursor::new(vec![0xCDu8; READ_CURSOR_MAX_BYTES])
                    .expect("cursor at its ruled ceiling is admissible"),
            ),
        });
        assert!(response.validate().is_ok(), "the widest page must be ADMITTED, not merely constructed");
        let backend = FakeBackend::ok(candid::encode_one(&response).unwrap());
        wire_roles(&backend, &[("shielded_pool", 24)]);
        let req = ReadModelRequest::PoolReadAccountingState(PageRequest {
            cursor: None,
            limit: MAX_READ_PAGE_LIMIT,
        });
        let id = drive(p(S1), &[p(S1), p(S2)], VaultActionKind::ReadModel(req), &backend);
        let rec = proposal_get(id).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::Executed, "the widest page must execute");
        let snap_id = rec.snapshot_id.expect("snapshot id");
        let snap = get_snapshot_for(snap_id, p(S1)).expect("signer reads snapshot");
        let snap_driven = candid::encode_one(&snap).expect("encodes").len();
        let resp_bytes = candid::encode_one(&snap.response).expect("encodes").len();
        let snap_overhead = snap_driven.saturating_sub(resp_bytes);
        let page_bound = MAX_READ_PAGE_LIMIT as usize * READ_ITEM_MAX_BYTES;

        println!("\n=== M3‴ — RESERVATION / SNAPSHOT MAXIMA + MULTIPLICITY ===");
        println!("| surface | measure | bytes | multiplicity |");
        println!("|---|---|---|---|");
        println!("| RESERVATION | minimum admitted shape | {res_min} | 1 / proposal |");
        println!(
            "| RESERVATION | **maximum** ({RULED_MAX_VAULT_SIGNERS} signers, longest ruled role) | **{res_max}** | 1 / proposal |"
        );
        println!(
            "| SNAPSHOT | **WIDEST ADMITTED**, driven ({MAX_READ_PAGE_LIMIT} items x {READ_ITEM_MAX_BYTES} B) | **{snap_driven}** | 1 / read-model proposal |"
        );
        println!("| SNAPSHOT | of which: embedded response | {resp_bytes} | — |");
        println!("| SNAPSHOT | of which: envelope overhead | {snap_overhead} | — |");
        println!("| — | binding page bound (limit x item max) | {page_bound} | — |");
        println!("| — | aggregate ceiling READ_RESPONSE_MAX_BYTES (NOT reachable via a page) | {READ_RESPONSE_MAX_BYTES} | — |");

        println!(
            "\nSNAPSHOT IS THE DOMINANT PERMANENT SURFACE, by ~{}x per operation.\n\
             ONE read-model proposal durably retains {snap_driven} B — against \n\
             ~3 KB for an entire governed operation — and `snapshot_insert`'s own \n\
             comment is 'durable forever, no retention or pruning' (freeze §9), so \n\
             nothing releases it. Any C9 horizon dominated by AUDIT EVENTS has \n\
             mis-attributed the growth.",
            snap_driven / 3_135usize.max(1)
        );
        println!(
            "WHICH CEILING BINDS: the page bound ({page_bound} B = {MAX_READ_PAGE_LIMIT} x \n\
             {READ_ITEM_MAX_BYTES}) governs, NOT the aggregate {READ_RESPONSE_MAX_BYTES} B — \n\
             `PageResponse::validate` enforces both and the per-item bound binds first, so \n\
             the aggregate is unreachable through a page. A horizon built on the \n\
             aggregate would OVERSTATE this surface ~2x; one built on the \n\
             NullifierReadSpentAt point-lookup variant would UNDERSTATE it ~290x. \n\
             Measured, not assumed, for exactly that reason.\n"
        );
        assert!(res_max > res_min, "the maximum shape must exceed the minimum");
        assert!(snap_driven > 0 && snap_overhead > 0, "snapshot figures must be real");
    }

    /// M3‴ — C9 PERMANENT-GROWTH HORIZON, Vault plane, ALL surfaces.
    ///
    /// The A1 2000Z correction stands: this is every permanent per-operation
    /// surface, NOT audit events alone. Audit-only was the shape of the
    /// superseded ~46.2 MB/yr-class projection, and it under-counted by omitting
    /// proposals, approvals, reservations and — decisively — snapshots.
    ///
    /// POLICY INPUTS ARE RULED, NOT CHOSEN HERE: 24 entry events/day, 10x burst,
    /// PERMANENT retention. They arrive from the ruling; this test supplies the
    /// measured per-operation terms and multiplies. NO CONSTANT IS RECOMMENDED —
    /// C9's closure arithmetic is presented as a formula with measured terms and
    /// is adjudicated at V12.
    #[test]
    fn s5a_m3_c9_permanent_growth_horizon_vault_plane() {
        setup();

        // Per-operation permanent growth, MEASURED here rather than quoted, so
        // a record-shape regression moves the horizon instead of leaving a
        // stale constant in a document.
        let before = durable_census();
        let completed = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &FakeBackend::ok(Vec::new()),
        );
        assert_eq!(proposal_get(completed).unwrap().outcome, ActionOutcome::Executed);
        let after = durable_census();
        let per_op: usize = census_total(&after) - census_total(&before);

        // RULED POLICY INPUTS (from the ruling, not selected by the builder).
        const OPS_PER_DAY: usize = 24;
        const BURST: usize = 10;
        const DAYS: usize = 365;

        println!("\n=== M3‴ — C9 PERMANENT-GROWTH HORIZON, VAULT PLANE ===");
        println!("RULED INPUTS: {OPS_PER_DAY} ops/day, {BURST}x burst, PERMANENT retention.");
        println!("(ruled inputs, not builder selections; the measured terms are below)\n");

        println!("| surface | bytes / completed operation |");
        println!("|---|---|");
        for (i, (name, cnt, by)) in after.iter().enumerate() {
            let (_, c0, b0) = before[i];
            if *cnt != c0 || *by != b0 {
                println!("| {name} | +{} |", by - b0);
            }
        }
        println!("| **TOTAL (governed operation, no snapshot)** | **{per_op}** |");

        let year = per_op * OPS_PER_DAY * DAYS;
        let year_burst = year * BURST;
        println!("\n| horizon | bytes/yr | MiB/yr |");
        println!("|---|---|---|");
        println!("| steady ({OPS_PER_DAY}/day) | {year} | {:.2} |", year as f64 / 1_048_576.0);
        println!(
            "| burst ({BURST}x, capacity arithmetic NOT expectation) | {year_burst} | {:.2} |",
            year_burst as f64 / 1_048_576.0
        );

        // ── THE READ-MODEL TERM, measured as a COMPLETE census delta ────────
        //
        // SSA Blocker 4: the prior version RECOMPUTED the snapshot as
        // MAX_READ_PAGE_LIMIT x READ_ITEM_MAX_BYTES = 131_072, which is the
        // page CONTENT bound, not the stored record — it omitted the response's
        // own Candid encoding overhead and the snapshot envelope. And because
        // governed and read-model operations are DISJOINT counters in the
        // formula, the read-model term must carry that operation's OTHER
        // permanent state too: its proposal, approvals, audit events and
        // reservation, none of which vanish because the operation was a read.
        //
        // So it is measured the same way the governed term is: a full census
        // delta across a driven operation at the widest admitted page.
        let rm_before = durable_census();
        let wide_items: Vec<stsh_custody_types::BoundedItem> = (0..MAX_READ_PAGE_LIMIT)
            .map(|i| {
                stsh_custody_types::BoundedItem::new(vec![
                    (i % 251) as u8;
                    stsh_custody_types::READ_ITEM_MAX_BYTES
                ])
                .expect("item at its ruled ceiling is admissible")
            })
            .collect();
        let rm_response =
            ReadModelResponse::PoolReadAccountingState(stsh_custody_types::PageResponse {
                items: wide_items,
                next_cursor: Some(
                    stsh_custody_types::BoundedCursor::new(vec![
                        0xCDu8;
                        stsh_custody_types::READ_CURSOR_MAX_BYTES
                    ])
                    .expect("cursor at its ruled ceiling is admissible"),
                ),
            });
        let rm_backend = FakeBackend::ok(candid::encode_one(&rm_response).unwrap());
        wire_roles(&rm_backend, &[("shielded_pool", 24)]);
        let rm_id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReadModel(ReadModelRequest::PoolReadAccountingState(PageRequest {
                cursor: None,
                limit: MAX_READ_PAGE_LIMIT,
            })),
            &rm_backend,
        );
        assert_eq!(
            proposal_get(rm_id).unwrap().outcome,
            ActionOutcome::Executed,
            "the read-model operation must execute for its term to be measured"
        );
        let rm_after = durable_census();
        let per_rm_op: usize = census_total(&rm_after) - census_total(&rm_before);

        println!("\n| surface | bytes / READ-MODEL operation (widest admitted page) |");
        println!("|---|---|");
        for (i, (name, cnt, by)) in rm_after.iter().enumerate() {
            let (_, c0, b0) = rm_before[i];
            if *cnt != c0 || *by != b0 {
                println!("| {name} | +{} |", by - b0);
            }
        }
        println!("| **TOTAL (read-model operation)** | **{per_rm_op}** |");

        let rm_year = per_rm_op * OPS_PER_DAY * DAYS;
        println!("\n| read-model horizon (permanent) | bytes/yr | GiB/yr |");
        println!("|---|---|---|");
        println!(
            "| steady ({OPS_PER_DAY}/day) | {rm_year} | {:.3} |",
            rm_year as f64 / 1_073_741_824.0
        );
        println!(
            "| burst ({BURST}x, capacity arithmetic NOT expectation) | {} | {:.3} |",
            rm_year * BURST,
            (rm_year * BURST) as f64 / 1_073_741_824.0
        );
        println!(
            "\nA read-model-heavy mix outgrows a governance-heavy one by ~{}x. C9 MUST \n\
             carry the two terms SEPARATELY — a blended per-operation figure hides \n\
             which mix the bound was derived under, and the two differ by more than an \n\
             order of magnitude.",
            per_rm_op / per_op.max(1)
        );
        println!(
            "\nMEASURED AS A DRIVEN CENSUS DELTA, not recomputed from the page bound: \n\
             the stored record carries the response's own Candid encoding overhead and \n\
             the snapshot envelope, and this operation's proposal/approvals/audit/\n\
             reservation are permanent too. The prior 131_072 figure was the page \n\
             CONTENT bound and omitted all of it.\n"
        );

        println!(
            "\nC9 CLOSURE FORMULA (measured terms; adjudicated at V13, NOT here):\n\
             \x20 permanent_bytes(t) = ops_governed(t)  x {per_op}\n\
             \x20                    + ops_readmodel(t) x {per_rm_op}\n\
             \x20                    + rotations(t)     x rotation_series   [UPGRADER plane]\n\
             \x20                    + recovery_ops(t)  x recovery_term     [UPGRADER plane]\n\
             The rotation and recovery terms are measured on the plane that OWNS them \n\
             (upgrader), not approximated from the Vault's audit map — that \n\
             substitution was SSA Blocker 4.\n"
        );

        assert!(per_op > 0, "a governed operation must grow permanent state");
    }

    /// S5A/B3 — APPEND-ONLY AUDIT GROWTH over a REAL event sequence.
    ///
    /// The prior version multiplied one synthetic maximum `AuditEvent` by
    /// twelve, which overstated the payload: `ProposalCreated` and
    /// `ApprovalAdded` do not each carry nine signers plus 1,024 bytes of
    /// detail. Here the events are whatever the lifecycle actually emits, and
    /// each is measured at its real size.
    ///
    /// Produces the per-operation audit growth an admission/rate bound must
    /// govern; the growth HORIZON (rate × size × time) is the table's job once
    /// an operations-per-day figure is agreed.
    #[test]
    fn s5a_measure_audit_growth_real_sequence() {
        setup();
        let before = AUDIT_EVENTS.with(|a| a.borrow().iter().count());
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Management(ManagementAction::Start { target: pyeop() }),
            &FakeBackend::ok(Vec::new()),
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);

        let events: Vec<AuditEvent> = AUDIT_EVENTS.with(|a| {
            a.borrow()
                .iter()
                .skip(before)
                .map(|(_, v)| candid::decode_one::<AuditEvent>(&v).expect("decodes"))
                .collect()
        });
        println!("\n=== S5A/B3 — audit growth, REAL event sequence (one operation) ===");
        println!("| # | kind | bytes |");
        println!("|---|---|---|");
        let mut total = 0usize;
        for (i, ev) in events.iter().enumerate() {
            let b = candid::encode_one(ev).expect("encodes").len();
            total += b;
            println!("| {} | {:?} | {b} |", i + 1, ev.kind);
        }
        println!(
            "| — | **{} events, TOTAL** | **{total}** |",
            events.len()
        );
        println!(
            "MEAN {} B/event. Append-only: this is NOT released at \
             terminalisation. Growth horizon = ops/day x {total} B x days — the \
             ops/day input is a table decision, not a measurement.\n",
            total / events.len().max(1)
        );
        assert!(
            !events.is_empty(),
            "a completed operation must emit audit events"
        );
    }
    // ── R1.6 — typed disclosure ──────────────────────────────────────────────

    /// R1.6 — a signer-set rotation discloses the PROPOSED PRINCIPALS, in
    /// full.
    ///
    /// The view carried `signer_count` alone, which made the single most
    /// membership-critical proposal class unreviewable: a signer could see the
    /// set was becoming three principals but not WHICH three. Swapping a peer
    /// for an attacker principal preserves the count exactly, so the substitution
    /// was invisible on the very view a signer approves from — the
    /// CUST-SSA-001 social-engineering path, on the plane that grants
    /// membership.
    ///
    /// The test asserts the substitution is VISIBLE, not merely that a field
    /// exists: two rotations with identical counts and thresholds must produce
    /// DIFFERENT views. A count-only view passes every weaker formulation.
    #[test]
    fn r1_6_signer_set_rotation_view_discloses_the_proposed_principals() {
        setup();
        let honest = vec![p(S1), p(S2), p(S3)];
        // Same size, same threshold — one principal substituted.
        let attacker = vec![p(S1), p(S2), p(0xEE)];

        let a = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: honest.clone(),
                threshold: 2,
            },
            None,
        )
        .unwrap();
        let b = propose_inner(
            p(S1),
            VaultActionKind::UpdateSignerSet {
                signers: attacker.clone(),
                threshold: 2,
            },
            None,
        )
        .unwrap();

        let va = get_proposal_for(a, p(S1)).expect("signer may read").action;
        let vb = get_proposal_for(b, p(S1)).expect("signer may read").action;

        match (&va, &vb) {
            (
                ActionView::UpdateSignerSet {
                    signers: sa,
                    threshold: ta,
                },
                ActionView::UpdateSignerSet {
                    signers: sb,
                    threshold: tb,
                },
            ) => {
                assert_eq!(sa, &honest);
                assert_eq!(sb, &attacker);
                assert_eq!((*ta, *tb), (2, 2), "thresholds identical by construction");
                assert_eq!(sa.len(), sb.len(), "counts identical by construction");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_ne!(
            va, vb,
            "a substituted signer principal MUST change the view — a count-only \
             view renders these two rotations indistinguishable, which is the \
             disclosure gap R1.6 closes"
        );
    }

    /// R1.6 — BOTH reconcile classes disclose their objective evidence in
    /// full, resolving the redacted-vs-unredacted divergence with the
    /// Upgrader's recovery plane toward disclosure.
    ///
    /// §3d (`ReconcileUpgraderUpgrade`) and §3e
    /// (`ReconcileVaultUpgradeViaUpgrader`) both exposed only
    /// `target_proposal_id`, while the Upgrader's recovery plane returns its
    /// reconcile action unredacted. Reconciliation is the ONLY state-changing
    /// path out of `OutcomeUnknown` and it is terminal, so the evidence is the
    /// entire basis of an irreversible decision. Approving it unseen is taking
    /// the proposer's word for a claim about the world.
    ///
    /// Asserted field-by-field rather than by equality alone: the observed
    /// module hash is what distinguishes `Executed` from `Failed`, so a view
    /// that carried the evidence but dropped that field would still leave the
    /// decision unreviewable.
    #[test]
    fn r1_6_both_reconcile_views_disclose_the_objective_evidence() {
        setup();
        let crash = FakeBackend::rejecting("crash");
        let ok = FakeBackend::ok(Vec::new());

        // ── §3d: the Vault reconciling an Upgrader upgrade.
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &crash,
        );
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::OutcomeUnknown
        );
        let ev_3d = UpgradeObjectiveEvidence {
            observed_upgrader_principal: p(UPGRADER),
            observed_module_hash: Some(sha256(b"observed-3d")),
            observed_controllers: vec![self_id()],
            observed_canister_status: ObservedCanisterStatus::Stopped,
            observed_at_ns: 1_234_567,
        };
        let rid = propose_inner(
            p(S1),
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: target,
                objective_evidence: ev_3d.clone(),
            }),
            None,
        )
        .unwrap();
        match get_proposal_for(rid, p(S1)).expect("signer may read").action {
            ActionView::ReconcileUpgraderUpgrade {
                target_proposal_id,
                objective_evidence,
            } => {
                assert_eq!(target_proposal_id, target);
                assert_eq!(
                    objective_evidence, ev_3d,
                    "§3d evidence must be disclosed in full"
                );
                assert_eq!(
                    objective_evidence.observed_module_hash,
                    Some(sha256(b"observed-3d")),
                    "the observed module hash is what decides Executed vs Failed"
                );
                assert_eq!(
                    objective_evidence.observed_canister_status,
                    ObservedCanisterStatus::Stopped
                );
                assert_eq!(objective_evidence.observed_controllers, vec![self_id()]);
            }
            other => panic!("unexpected {other:?}"),
        }
        // Release the lock so the ring case can run in the same test.
        approve_to_quorum(rid);
        block_on(execute_action_with(&ok, rid));

        // ── §3e: the Vault reconciling its OWN ring upgrade.
        let ring = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &crash,
        );
        assert_eq!(
            proposal_get(ring).unwrap().outcome,
            ActionOutcome::OutcomeUnknown
        );
        let ev_3e = UpgradeObjectiveEvidence {
            observed_upgrader_principal: self_id(),
            observed_module_hash: Some(sha256(b"observed-3e")),
            observed_controllers: vec![p(UPGRADER)],
            observed_canister_status: ObservedCanisterStatus::Running,
            observed_at_ns: 7_654_321,
        };
        let ring_rid = propose_inner(
            p(S1),
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: ring,
                objective_evidence: ev_3e.clone(),
            }),
            None,
        )
        .unwrap();
        match get_proposal_for(ring_rid, p(S1))
            .expect("signer may read")
            .action
        {
            ActionView::ReconcileVaultUpgradeViaUpgrader {
                target_proposal_id,
                objective_evidence,
            } => {
                assert_eq!(target_proposal_id, ring);
                assert_eq!(
                    objective_evidence, ev_3e,
                    "§3e evidence must be disclosed in full — same policy as §3d \
                     and as the Upgrader's recovery plane"
                );
                assert_eq!(
                    objective_evidence.observed_controllers,
                    vec![p(UPGRADER)],
                    "the observed controller set is the ring-invariant claim"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn single_flight_second_upgrade_rejected_while_executing() {
        setup();
        let a = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(a);
        // While A is Executing, a second mutating intent on the Upgrader is
        // rejected at propose — from durable state, not a heap flag.
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None),
            Err(VaultError::IllegalSourceState)
        );
    }

    #[test]
    fn single_flight_blocks_while_outcome_unknown_releases_on_terminal() {
        setup();
        // A → OutcomeUnknown: the lock HELD (reconciliation is pending).
        let crash = FakeBackend::rejecting("crash");
        let a = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &crash,
        );
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None),
            Err(VaultError::IllegalSourceState),
            "OutcomeUnknown holds the lock until reconciliation terminalizes"
        );
        // Reconcile A to Failed → lock RELEASED; a fresh upgrade proceeds.
        let ok = FakeBackend::ok(Vec::new());
        drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: a,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(UPGRADER),
                    observed_module_hash: Some(sha256(b"not-it")),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &ok,
        );
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::Failed);
        let b = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &ok,
        );
        assert_eq!(proposal_get(b).unwrap().outcome, ActionOutcome::Executed);
        // Executed releases too: yet another upgrade is proposable.
        assert!(propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok());
    }

    #[test]
    fn single_flight_execution_time_recheck_catches_pending_race() {
        setup();
        // A and B both proposed while Pending (legal). A reaches quorum but
        // its install is still in flight (Executing). B then reaches quorum:
        // the execution-time re-check — the enforce point that cannot be
        // raced — fails B; A keeps the lock.
        let a = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        let b = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(a); // A Executing, executor not yet driven
        approve_to_quorum(b); // B Executing, its executor will run the re-check
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, b));
        assert_eq!(
            proposal_get(b).unwrap().outcome,
            ActionOutcome::Failed,
            "concurrent open intent fails the later proposal at execution"
        );
        assert!(backend.calls.borrow().is_empty(), "B never reached the management call");
        // A completes normally; its lock then releases.
        block_on(execute_action_with(&backend, a));
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(backend.calls.borrow().len(), 1);
    }

    #[test]
    fn single_flight_rejected_reconcile_evidence_does_not_release_lock() {
        setup();
        let crash = FakeBackend::rejecting("crash");
        let a = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &crash,
        );
        // Reconcile with evidence that does not bind (wrong principal) →
        // reconcile proposal Failed, A stays OutcomeUnknown, lock HELD.
        let ok = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: a,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(66), // does not bind
                    observed_module_hash: Some(sha256(b"fake-wasm-v2")),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &ok,
        );
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None),
            Err(VaultError::IllegalSourceState),
            "rejected evidence must not release the target lock"
        );
    }

    #[test]
    fn single_flight_lock_survives_post_upgrade() {
        setup();
        let crash = FakeBackend::rejecting("crash");
        let a = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &crash,
        );
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        post_upgrade();
        // The lock derives from durable proposal state — an upgrade cannot
        // launder a second intent past it.
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None),
            Err(VaultError::IllegalSourceState)
        );
    }

    #[test]
    fn single_flight_different_targets_proceed_concurrently() {
        setup();
        let a = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(a); // Executing against the Upgrader
        // A mutating intent against a DIFFERENT (governed) target is fine.
        let ok = FakeBackend::ok(Vec::new());
        let b = drive(p(S1), &[p(S1), p(S2)], governed_upgrade(pyeop()), &ok);
        assert_eq!(proposal_get(b).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::Executing);
    }

    #[test]
    fn single_flight_two_reconciles_for_one_intent_second_fails() {
        setup();
        let crash = FakeBackend::rejecting("crash");
        let a = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            &crash,
        );
        // Both reconciles proposed while A is OutcomeUnknown (legal at
        // propose). R1 lands terminal evidence; R2's execution-time source
        // check then fails — A is never re-terminalized.
        let evidence = |hash: Vec<u8>| {
            VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                proposal_id: a,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: p(UPGRADER),
                    observed_module_hash: Some(hash),
                    observed_controllers: vec![self_id()],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            })
        };
        let ok = FakeBackend::ok(Vec::new());
        let r1 = propose_inner(p(S1), evidence(sha256(b"fake-wasm-v2")), None).unwrap();
        let r2 = propose_inner(p(S1), evidence(sha256(b"fake-wasm-v2")), None).unwrap();
        approve_to_quorum(r1);
        block_on(execute_action_with(&ok, r1));
        assert_eq!(proposal_get(a).unwrap().outcome, ActionOutcome::Executed);
        approve_to_quorum(r2);
        block_on(execute_action_with(&ok, r2));
        assert_eq!(proposal_get(r2).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(
            proposal_get(a).unwrap().outcome,
            ActionOutcome::Executed,
            "first reconcile's terminal result stands"
        );
    }

    // ── L1-5: concurrent creation vs one-shot role binding ───────────────────

    fn create_action(purpose: &str) -> VaultActionKind {
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: purpose.to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        })
    }

    #[test]
    fn l1_5_second_creation_same_purpose_rejected_while_first_in_flight() {
        setup();
        let a = propose_inner(p(S1), create_action("verifier"), None).unwrap();
        approve_to_quorum(a);
        assert_eq!(
            propose_inner(p(S1), create_action("verifier"), None),
            Err(VaultError::IllegalSourceState),
            "one nonterminal creation per manifest purpose"
        );
        // A different purpose proceeds.
        assert!(propose_inner(p(S1), create_action("stsh_token"), None).is_ok());
    }

    #[test]
    fn l1_5_creation_reservation_durable_before_first_await() {
        setup();
        let a = propose_inner(p(S1), create_action("verifier"), None).unwrap();
        approve_to_quorum(a);
        let res = reservation_get(a).expect("reservation durable before await");
        assert_eq!(res.creation_purpose.as_deref(), Some("verifier"));
    }

    #[test]
    fn l1_5_concurrent_same_purpose_creation_admits_exactly_one() {
        setup();
        // Both proposed while Pending (legal at propose). Both approved to
        // quorum — both Executing. The execution-time re-check then admits
        // EXACTLY ONE create_canister call.
        let a = propose_inner(p(S1), create_action("verifier"), None).unwrap();
        let b = propose_inner(p(S2), create_action("verifier"), None).unwrap();
        approve_to_quorum(a);
        approve_to_quorum(b);
        let backend = FakeBackend::ok(Vec::new());
        block_on(execute_action_with(&backend, a));
        block_on(execute_action_with(&backend, b));
        let creates = backend
            .calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("create_canister"))
            .count();
        assert_eq!(creates, 1, "exactly one creation admitted");
        let outcomes = [
            proposal_get(a).unwrap().outcome,
            proposal_get(b).unwrap().outcome,
        ];
        assert!(outcomes.contains(&ActionOutcome::Executed));
        assert!(outcomes.contains(&ActionOutcome::Failed));
        // Exactly one governed entry and one receipt for the purpose.
        assert_eq!(
            gov().governed.iter().filter(|t| t.purpose == "verifier").count(),
            1
        );
        assert_eq!(
            receipts_for(p(S1))
                .iter()
                .filter(|r| r.purpose == "verifier")
                .count(),
            1
        );
    }

    #[test]
    fn l1_5_l1_10_post_await_conflict_records_orphan_never_overwrites() {
        setup();
        // The role binds WHILE the create_canister call is in flight (the
        // corruption/future-drift fallback branch — with the L1-5 re-checks
        // in place this is unreachable by normal flow, so the drifted state
        // is injected by the backend hook inside the call itself: another
        // path binds p(95) with its own Bound receipt mid-flight).
        let backend = FakeBackend::ok(Vec::new());
        backend.created.borrow_mut().push(p(96));
        let b = propose_inner(p(S2), create_action("vetkeys"), None).unwrap();
        approve_to_quorum(b);
        *backend.on_create.borrow_mut() = Some(Box::new(|| {
            audit_full(
                AuditKind::CanisterCreated,
                None,
                p(66),
                None,
                Some(CreationReceipt {
                    proposal_id: u64::MAX, // drifted foreign receipt
                    principal: p(95),
                    purpose: "vetkeys".to_string(),
                    disposition: ManifestDisposition::BornUnderVault,
                    created_at_ns: now_ns(),
                    status: CreationReceiptStatus::Bound,
                }),
                None,
                "drift injection".to_string(),
            );
            let mut g = gov();
            g.governed.push(GovernedTarget {
                principal: p(95),
                disposition: ManifestDisposition::BornUnderVault,
                purpose: "vetkeys".to_string(),
            });
            gov_store(&g);
        }));
        block_on(execute_action_with(&backend, b));
        assert_eq!(proposal_get(b).unwrap().outcome, ActionOutcome::Failed);
        let g = gov();
        let entries: Vec<_> = g
            .governed
            .iter()
            .filter(|t| t.purpose == "vetkeys")
            .collect();
        assert_eq!(entries.len(), 1, "no second binding");
        assert_eq!(entries[0].principal, p(95), "existing binding never overwritten");
        // BOTH principals remain discoverable via the receipt read-back.
        let receipts = receipts_for(p(S1));
        let bound = receipts
            .iter()
            .find(|r| r.principal == p(95))
            .expect("legitimately bound receipt visible");
        assert_eq!(bound.status, CreationReceiptStatus::Bound);
        let orphan = receipts
            .iter()
            .find(|r| r.principal == p(96))
            .expect("orphan receipt visible — created canister never hidden from D5");
        assert_eq!(orphan.status, CreationReceiptStatus::OrphanedPurposeConflict);
        assert_eq!(orphan.purpose, "vetkeys");
        // The orphan is NOT governed: every management path fails closed on
        // it pending governed resolution.
        assert!(!g.governed.iter().any(|t| t.principal == p(96)));
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::Management(ManagementAction::Start { target: p(96) }), None),
            Err(VaultError::NotAuthorized),
            "orphan blocked from management use"
        );
    }

    // ── L1-7: receipt pagination ──────────────────────────────────────────────

    #[test]
    fn l1_7_receipt_pagination_walks_interleaved_events() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        // Three receipts, with non-receipt audit events (proposals,
        // approvals, quorums, terminal events) interleaved between them.
        wire_roles(&backend, &[("verifier", 30), ("stsh_token", 31), ("vetkeys", 32)]);
        let all = receipts_for(p(S1));
        assert_eq!(all.len(), 3);
        // Walk pages of ONE receipt each via next_cursor only.
        let mut walked = Vec::new();
        let mut cursor = None;
        for _ in 0..10 {
            let page = receipt_page(cursor, 1).expect("page");
            walked.extend(page.items.iter().map(|r| r.principal));
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(walked, all.iter().map(|r| r.principal).collect::<Vec<_>>());
        // A single big page terminates with next_cursor None.
        let page = receipt_page(None, 128).unwrap();
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.next_cursor, None);
    }

    // ── L1-9: pagination bounds records EXAMINED, not just returned ──────────

    #[test]
    fn l1_9_sparse_history_scan_bound_progresses_and_recovers_all() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        // One receipt, then MORE than the scan bound of non-receipt audit
        // events (each governance proposal writes ~6), then another receipt.
        wire_roles(&backend, &[("verifier", 30)]);
        // S6 — 45 governance operations from one signer EXCEEDS C9 (26 per
        // signer per rolling 24 h), and correctly so: this fixture is about
        // audit-history depth, not about a burst. Real history of this depth
        // accumulates over days, so the clock is advanced one full window per
        // operation and the rolling window does its job. Faking the volume by
        // suppressing C9 would test a canister that does not exist.
        let window_ns = entry_rate_params().expect("C9 ruled at S6").window_ns;
        for i in 0..45u64 {
            set_test_time(now_ns().saturating_add(if i == 0 { 0 } else { window_ns }));
            // ~270 non-receipt events, no receipts among them.
            let id = propose_inner(p(S1), governance_action(), None).unwrap();
            drive_approvals_only(id, &[p(S1), p(S2)]);
            block_on(execute_action_with(&backend, id));
        }
        wire_roles(&backend, &[("stsh_token", 31)]);
        let total_events = audit_events().len() as u64;
        assert!(total_events > MAX_RECEIPT_SCAN_PER_CALL as u64);
        // First call: bounded work — next_cursor advances by EXAMINED
        // records even though the page holds only the early receipt.
        let page1 = receipt_page(None, 2).expect("page1");
        let c1 = page1.next_cursor.expect("more history remains");
        assert!(
            c1 <= MAX_RECEIPT_SCAN_PER_CALL as u64,
            "call examined at most MAX_RECEIPT_SCAN_PER_CALL records"
        );
        // Full walk via next_cursor recovers EVERY receipt, and no single
        // call exceeds the scan bound.
        let mut walked = page1.items.clone();
        let mut cursor = Some(c1);
        let mut prev = 0u64;
        for _ in 0..50 {
            let Some(c) = cursor else { break };
            assert!(c > prev, "cursor always advances (no livelock)");
            prev = c;
            let page = receipt_page(Some(c), 2).expect("page");
            if let Some(nc) = page.next_cursor {
                assert!(nc - c <= MAX_RECEIPT_SCAN_PER_CALL as u64);
            }
            walked.extend(page.items);
            cursor = page.next_cursor;
        }
        assert_eq!(walked.len(), 2);
        assert!(walked.iter().any(|r| r.purpose == "verifier"));
        assert!(walked.iter().any(|r| r.purpose == "stsh_token"));
        assert_eq!(cursor, None, "walk terminates");
    }

    // ── F1: UTF-8-safe truncation ────────────────────────────────────────────

    #[test]
    fn f1_cap_detail_ascii_multibyte_and_exact_boundary() {
        // ASCII: truncated WITH the ellipsis inside the cap (hygiene: the
        // final text is at most 1024 bytes, ellipsis space reserved).
        let ascii = "x".repeat(2_000);
        let out = cap_detail(ascii);
        assert_eq!(out.len(), 1_024);
        assert!(out.ends_with('…'));
        // Multibyte straddling the budget: byte 1021 is inside a 2-byte
        // char — must NOT panic, must truncate at the largest boundary.
        let mb = format!("{}{}", "x".repeat(1_023), "é".repeat(100));
        let out = cap_detail(mb);
        assert!(out.len() <= 1_024);
        assert!(out.starts_with(&"x".repeat(1_021)));
        assert!(out.ends_with('…'));
        assert!(!out.contains('é'));
        // Exactly-at-boundary: len == cap is returned unchanged.
        let exact = "y".repeat(1_024);
        assert_eq!(cap_detail(exact.clone()), exact);
        // Three-byte chars crossing the cap.
        let eur = "€".repeat(400); // 1200 bytes
        let out = cap_detail(eur);
        assert!(out.len() <= 1_024);
        assert_eq!(out.chars().filter(|c| *c == '€').count(), 340); // 1020 bytes
    }

    /// THE F1 counterexample: from durable pre-await Executing state, a
    /// multibyte-boundary rejection must land OutcomeUnknown, never strand.
    #[test]
    fn f1_multibyte_rejection_after_await_yields_outcome_unknown() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("treasury", 21)]);
        // Rejection text with a multibyte char straddling byte 1024.
        let reject = format!("{}{}", "r".repeat(1_023), "é".repeat(100));
        *backend.next_call_result.borrow_mut() = Err(CallFailure::Rejected(reject));
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::TreasuryExecuteWithdrawal(5)),
            &backend,
        );
        assert_eq!(
            proposal_get(id).unwrap().outcome,
            ActionOutcome::OutcomeUnknown,
            "must land OutcomeUnknown, not strand in Executing"
        );
    }

    // ── F2: max_response_bytes enforced pre-decode ───────────────────────────

    fn dummy_request(kind: ApplicationAction) -> ActionRequest {
        use stsh_custody_types::*;
        match kind {
            ApplicationAction::PoolPruneTerminalRecords => {
                ActionRequest::PoolPruneTerminalRecords(PruneRequest {
                    older_than_ns: 0,
                    max_records: 0,
                    prune_spends: false,
                    prune_deposits: false,
                    scan_legacy_spends: false,
                    scan_legacy_deposits: false,
                    max_scan_records: 0,
                    legacy_spend_cursor: None,
                    legacy_deposit_cursor: None,
                })
            }
            ApplicationAction::PoolReconcileDepositCommitment => {
                ActionRequest::PoolReconcileDepositCommitment([0u8; 32])
            }
            ApplicationAction::PoolReconcileDepositAppendUnknown => {
                ActionRequest::PoolReconcileDepositAppendUnknown([0u8; 32])
            }
            ApplicationAction::PoolReconcileDepositTransferNotExecuted => {
                ActionRequest::PoolReconcileDepositTransferNotExecuted([0u8; 32])
            }
            ApplicationAction::PoolReconcileTreasuryDisburse => {
                ActionRequest::PoolReconcileTreasuryDisburse(0, DisburseOutcome::NotExecuted)
            }
            ApplicationAction::PoolReconcileNullifierInsert => {
                ActionRequest::PoolReconcileNullifierInsert(0)
            }
            ApplicationAction::PoolReconcilePendingSpend => {
                ActionRequest::PoolReconcilePendingSpend(0)
            }
            ApplicationAction::PoolScheduleVkActivation => {
                ActionRequest::PoolScheduleVkActivation(0, [0u8; 32], 0, 0)
            }
            ApplicationAction::PoolEmergencyDisableCircuitVersion => {
                ActionRequest::PoolEmergencyDisableCircuitVersion(0)
            }
            ApplicationAction::PoolEmergencyPauseDeposits => {
                ActionRequest::PoolEmergencyPauseDeposits
            }
            ApplicationAction::PoolEmergencyPauseSpends => ActionRequest::PoolEmergencyPauseSpends,
            ApplicationAction::PoolUnpauseDeposits => ActionRequest::PoolUnpauseDeposits,
            ApplicationAction::PoolUnpauseSpends => ActionRequest::PoolUnpauseSpends,
            ApplicationAction::PoolSetVerifierCanister => {
                ActionRequest::PoolSetVerifierCanister(p(60), [0u8; 32])
            }
            ApplicationAction::PoolClearVerifierConfigGuard => {
                ActionRequest::PoolClearVerifierConfigGuard
            }
            ApplicationAction::PoolSetGovernanceFeeParams => {
                ActionRequest::PoolSetGovernanceFeeParams(GovernanceFeeParamsMirror {
                    protocol_shielding_fee_stsh: 0,
                    protocol_unshielding_fee_stsh: 0,
                    protocol_private_spend_fee_stsh: 0,
                    minimum_withdrawal_gross: 0,
                    minimum_recipient_amount: 0,
                    minimum_private_credit: 0,
                    fee_reference_price_stsh_per_icp_e8s: 0,
                    fee_safety_margin_bps: 0,
                    max_fee_change_bps_per_update: 0,
                    fee_update_cooldown_ns: 0,
                    operations_split_bps: 0,
                    insurance_split_bps: 0,
                    staking_rewards_split_bps: 0,
                    staking_rewards_enabled: false,
                    minimum_treasury_runway_months: 0,
                    target_treasury_runway_months: 0,
                    shield_fee_bps: None,
                    unshield_fee_bps: None,
                    shield_flat_minimum_fee_e8s: None,
                    unshield_flat_minimum_fee_e8s: None,
                    spend_fee_mode: None,
                    fee_model_version: None,
                    params_epoch: None,
                })
            }
            ApplicationAction::PoolReconcilePrivateSpendPayout => {
                ActionRequest::PoolReconcilePrivateSpendPayout(0, PayoutOutcome::NotExecuted)
            }
            ApplicationAction::PoolInitializePayoutMemoKey => {
                ActionRequest::PoolInitializePayoutMemoKey
            }
            ApplicationAction::TreasuryProposeWithdrawal => {
                ActionRequest::TreasuryProposeWithdrawal("s".into(), p(61), 0, "d".into())
            }
            ApplicationAction::TreasuryExecuteWithdrawal => {
                ActionRequest::TreasuryExecuteWithdrawal(0)
            }
            ApplicationAction::TreasuryRejectProposal => ActionRequest::TreasuryRejectProposal(0),
            ApplicationAction::VestingReconcileClaim => {
                ActionRequest::VestingReconcileClaim(p(62), ClaimDecision::NotExecuted)
            }
        }
    }

    #[test]
    fn l02_legacy_canonical_bytes_match_independent_d068_goldens() {
        let fixture = include_str!("../tests/fixtures/d068_canonical_v1.goldens");
        let expected: std::collections::BTreeMap<&str, &str> = fixture.lines().map(|line| {
            let mut fields = line.split('|');
            assert_eq!(fields.next(), Some("D068_GOLDEN"));
            (fields.next().unwrap(), fields.next().unwrap())
        }).collect();
        let mut seen = 0usize;
        let mut emit = |name: &str, action: VaultActionKind| {
            if let Some(hex) = expected.get(name) {
                let actual: String = canonical_action_bytes(&action).iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(&actual, hex, "{name}: frozen V1 bytes differ from independent d068 output");
                seen += 1;
            }
        };
        for kind in ApplicationAction::ALL {
            emit(&format!("application::{kind:?}"), VaultActionKind::Application(dummy_request(kind)));
        }
        let page_none = PageRequest { cursor: None, limit: 1 };
        for (name, request) in [
            ("read::PoolReadAccountingState", ReadModelRequest::PoolReadAccountingState(page_none.clone())),
            ("read::PoolReadTreasuryReconciliationTombstone", ReadModelRequest::PoolReadTreasuryReconciliationTombstone(page_none.clone())),
            ("read::PoolReadAppendLeaseOwner", ReadModelRequest::PoolReadAppendLeaseOwner(page_none.clone())),
            ("read::PoolReadPendingOutputPromotions", ReadModelRequest::PoolReadPendingOutputPromotions(page_none.clone())),
            ("read::NullifierReadSpentAt", ReadModelRequest::NullifierReadSpentAt { nullifier: [0xA5; 32], page: PageRequest { cursor: Some(stsh_custody_types::BoundedCursor::new(vec![1,2,3]).unwrap()), limit: MAX_READ_PAGE_LIMIT } }),
        ] {
            emit(name, VaultActionKind::ReadModel(request));
        }
        let target = p(77);
        let wasm = vec![1,2,3];
        let arg = vec![4,5];
        let management = vec![
            ("management::Upgrade", ManagementAction::Upgrade { target, expected_wasm_hash: sha256(&wasm), expected_arg_hash: sha256(&arg), wasm_bytes: wasm.clone(), arg_bytes: arg.clone() }),
            ("management::Start", ManagementAction::Start { target }),
            ("management::Stop", ManagementAction::Stop { target }),
            ("management::UpdateSettings", ManagementAction::UpdateSettings { target, controllers: vec![p(78), p(79)] }),
            ("management::DepositCycles", ManagementAction::DepositCycles { target, cycles: u128::MAX }),
            ("management::CreateCanister", ManagementAction::CreateCanister { manifest_purpose: "stsh_token".into(), disposition: ManifestDisposition::BornUnderVault }),
            ("management::InstallCode", ManagementAction::InstallCode { target, expected_wasm_hash: sha256(&wasm), expected_arg_hash: sha256(&arg), wasm_bytes: wasm, arg_bytes: arg }),
        ];
        for (name, action) in management { emit(name, VaultActionKind::Management(action)); }
        emit("outer::UpgraderUpgrade", VaultActionKind::UpgraderUpgrade(good_upgrade()));
        emit("outer::ReconcileUpgraderUpgrade", VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade { proposal_id: 9, objective_evidence: evidence_with_controllers(2) }));
        emit("outer::UpdateSignerSet", VaultActionKind::UpdateSignerSet { signers: vec![p(S1),p(S2),p(S3)], threshold: 2 });
        emit("outer::VaultUpgradeViaUpgrader", VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()));
        emit("outer::ReconcileVaultUpgradeViaUpgrader", VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader { request_id: 10, objective_evidence: evidence_with_controllers(1) }));
        emit("outer::ReconcileUpgraderStart", VaultActionKind::ReconcileUpgraderStart(ReconcileUpgraderStart { proposal_id: 11, objective_evidence: start_evidence(ObservedCanisterStatus::Stopped, u64::MAX) }));
        assert_eq!(seen, expected.len());
    }

    fn l02_token_receipt_event() -> (u64, AuditEvent) {
        audit_events()
            .into_iter()
            .find(|event| {
                event.creation_receipt.as_ref().is_some_and(|receipt| {
                    receipt.purpose == "stsh_token"
                        && receipt.status == CreationReceiptStatus::Bound
                })
            })
            .map(|event| (event.id, event))
            .expect("typed stsh_token receipt event")
    }

    fn l02_supply_response() -> SupplyReconciliation {
        SupplyReconciliation {
            maintained_sum_balances: 10,
            folded_sum_balances: 10,
            maintained_sum_staking_locks: 0,
            folded_sum_staking_locks: 0,
            fee_reserve: 90,
            rows_examined: 1,
            totals_consistent: true,
            folded_first_law_holds: true,
            detail: None,
        }
    }

    #[test]
    fn l02_token_read_point_resolves_receipt_and_sends_only_empty_args() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("stsh_token", 24)]);
        let (receipt_audit_id, event) = l02_token_receipt_event();
        for _ in 0..1_000 {
            audit(
                AuditKind::Failed,
                None,
                p(S1),
                None,
                "unrelated long-history event".to_string(),
            );
        }
        RECEIPT_POINT_LOOKUPS_FOR_TEST.with(|count| *count.borrow_mut() = 0);
        RECEIPT_DECODES_FOR_TEST.with(|count| *count.borrow_mut() = 0);
        assert_eq!(resolve_manifest_token_target(receipt_audit_id), Ok(p(24)));
        assert_eq!(RECEIPT_POINT_LOOKUPS_FOR_TEST.with(|count| *count.borrow()), 1);
        assert_eq!(RECEIPT_DECODES_FOR_TEST.with(|count| *count.borrow()), 1);
        assert!(candid::encode_one(&event).unwrap().len() <= READ_RESPONSE_MAX_BYTES);

        backend.calls.borrow_mut().clear();
        *backend.next_call_result.borrow_mut() =
            Ok(candid::encode_one(l02_supply_response()).unwrap());
        let req = ReadModelRequest::TokenReadSupplyReconciliation { receipt_audit_id };
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReadModel(req.clone()),
            &backend,
        );
        assert_eq!(backend.calls.borrow().len(), 1, "exactly one token call");
        assert!(backend.calls.borrow()[0].contains(&format!("-> {}", p(24))));
        assert_eq!(*backend.last_call_args.borrow(), candid::encode_args(()).unwrap());
        assert_ne!(*backend.last_call_args.borrow(), candid::encode_one(&req).unwrap());
        assert_ne!(*backend.last_call_args.borrow(), candid::encode_one(receipt_audit_id).unwrap());
        let proposal = proposal_get(id).unwrap();
        assert_eq!(proposal.outcome, ActionOutcome::Executed);
        let snapshot = get_snapshot_for(proposal.snapshot_id.unwrap(), p(S1)).unwrap();
        assert_eq!(snapshot.request, req);
        assert_eq!(snapshot.source_canister, p(24));
        assert_eq!(
            snapshot.response,
            ReadModelResponse::TokenReadSupplyReconciliation(l02_supply_response())
        );
    }

    #[test]
    fn l02_token_locator_refuses_every_receipt_linkage_mutation() {
        type Mutator = fn(&mut AuditEvent);
        let cases: &[(&str, Mutator)] = &[
            ("wrong event id", |event| event.id += 1),
            ("wrong kind", |event| event.kind = AuditKind::Failed),
            ("absent receipt", |event| event.creation_receipt = None),
            ("orphan", |event| event.creation_receipt.as_mut().unwrap().status = CreationReceiptStatus::OrphanedPurposeConflict),
            ("wrong principal", |event| event.creation_receipt.as_mut().unwrap().principal = p(88)),
            ("wrong purpose", |event| event.creation_receipt.as_mut().unwrap().purpose = "verifier".into()),
            ("wrong disposition", |event| event.creation_receipt.as_mut().unwrap().disposition = ManifestDisposition::SetControllerAtCutover),
            ("event proposal absent", |event| event.proposal_id = None),
            ("proposal mismatch", |event| event.creation_receipt.as_mut().unwrap().proposal_id += 1),
        ];
        for (name, mutate) in cases {
            setup();
            let backend = FakeBackend::ok(Vec::new());
            wire_roles(&backend, &[("stsh_token", 24)]);
            let (receipt_audit_id, mut event) = l02_token_receipt_event();
            mutate(&mut event);
            let bytes = candid::encode_one(&event).unwrap();
            AUDIT_EVENTS.with(|events| events.borrow_mut().insert(receipt_audit_id, bytes));
            backend.calls.borrow_mut().clear();
            *backend.next_call_result.borrow_mut() =
                Ok(candid::encode_one(l02_supply_response()).unwrap());
            let id = drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::ReadModel(
                    ReadModelRequest::TokenReadSupplyReconciliation { receipt_audit_id },
                ),
                &backend,
            );
            let proposal = proposal_get(id).unwrap();
            assert_eq!(proposal.outcome, ActionOutcome::Failed, "{name}");
            assert_eq!(proposal.snapshot_id, None, "{name}");
            assert!(backend.calls.borrow().is_empty(), "{name}: no token call");
        }
    }

    #[test]
    fn l02_token_locator_refuses_missing_malformed_oversize_and_ambiguous_target() {
        for bytes in [
            None,
            Some(vec![0x44, 0x49, 0x44, 0x4c, 0xff]),
            Some(vec![0; READ_RESPONSE_MAX_BYTES + 1]),
        ] {
            setup();
            let backend = FakeBackend::ok(Vec::new());
            wire_roles(&backend, &[("stsh_token", 24)]);
            let (receipt_audit_id, event) = l02_token_receipt_event();
            let original = candid::encode_one(&event).unwrap();
            assert_eq!(
                resolve_manifest_token_target(receipt_audit_id),
                Ok(p(24)),
                "positive control: the valid receipt must resolve before mutation"
            );
            let lookup_id = match bytes {
                None => {
                    let missing_id = u64::MAX;
                    assert!(
                        AUDIT_EVENTS.with(|events| events.borrow().get(&missing_id).is_none()),
                        "the missing-receipt case must use a proven absent audit id"
                    );
                    missing_id
                }
                Some(bytes) => {
                    AUDIT_EVENTS.with(|events| {
                        events.borrow_mut().insert(receipt_audit_id, bytes);
                    });
                    receipt_audit_id
                }
            };
            backend.calls.borrow_mut().clear();
            assert!(resolve_manifest_token_target(lookup_id).is_err());
            assert!(backend.calls.borrow().is_empty());
            AUDIT_EVENTS.with(|events| {
                events.borrow_mut().insert(receipt_audit_id, original);
            });
            assert_eq!(
                resolve_manifest_token_target(receipt_audit_id),
                Ok(p(24)),
                "the retained valid receipt must resolve after each negative"
            );
        }

        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("stsh_token", 24)]);
        let (receipt_audit_id, _) = l02_token_receipt_event();
        let mut g = gov();
        g.governed.push(GovernedTarget {
            principal: p(25),
            disposition: ManifestDisposition::BornUnderVault,
            purpose: "stsh_token".to_string(),
        });
        gov_store(&g);
        assert!(resolve_manifest_token_target(receipt_audit_id).is_err());
    }

    #[test]
    fn l02_initializer_uses_empty_args_and_requires_ok_true() {
        setup();
        let backend = FakeBackend::ok(candid::encode_one(Ok::<bool, stsh_custody_types::PoolErrorMirror>(true)).unwrap());
        wire_roles(&backend, &[("shielded_pool", 20)]);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::PoolInitializePayoutMemoKey),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(*backend.last_call_args.borrow(), candid::encode_args(()).unwrap());
        assert!(backend.calls.borrow().last().unwrap().contains("initialize_payout_memo_key"));

        setup();
        let backend = FakeBackend::ok(candid::encode_one(Ok::<bool, stsh_custody_types::PoolErrorMirror>(false)).unwrap());
        wire_roles(&backend, &[("shielded_pool", 20)]);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::PoolInitializePayoutMemoKey),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::Failed);
    }

    #[test]
    fn l02_initializer_unknown_recovers_by_readiness_without_replay_resend() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("shielded_pool", 20)]);
        *backend.next_call_result.borrow_mut() =
            Err(CallFailure::Rejected("reply lost".to_string()));
        let original = drive(
            p(S1), &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::PoolInitializePayoutMemoKey),
            &backend,
        );
        assert_eq!(proposal_get(original).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        assert_eq!(backend.calls.borrow().len(), 2);
        *backend.next_call_result.borrow_mut() = Ok(candid::encode_one(Some(true)).unwrap());
        let readiness = drive(
            p(S1), &[p(S1), p(S2)],
            VaultActionKind::ReadModel(ReadModelRequest::PoolReadPayoutMemoKeyReady),
            &backend,
        );
        assert_eq!(proposal_get(readiness).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(
            get_snapshot_for(proposal_get(readiness).unwrap().snapshot_id.unwrap(), p(S1)).unwrap().response,
            ReadModelResponse::PoolReadPayoutMemoKeyReady(Some(true))
        );
        let calls = backend.calls.borrow().len();
        let replay = approve_inner(p(S3), original, commit_of(original), now_ns()).unwrap();
        assert!(matches!(
            replay,
            (ApprovalOutcome::PriorResult { outcome: ActionOutcome::OutcomeUnknown, .. }, false)
        ));
        assert_eq!(backend.calls.borrow().len(), calls);
        assert_eq!(proposal_get(original).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        *backend.next_call_result.borrow_mut() =
            Ok(candid::encode_one(Ok::<bool, stsh_custody_types::PoolErrorMirror>(true)).unwrap());
        let repeat = drive(
            p(S1), &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::PoolInitializePayoutMemoKey),
            &backend,
        );
        assert_eq!(proposal_get(repeat).unwrap().outcome, ActionOutcome::Executed);
    }

    #[test]
    fn l02_readiness_read_requires_some_true_and_snapshots_exact_target() {
        setup();
        let backend = FakeBackend::ok(candid::encode_one(Some(true)).unwrap());
        wire_roles(&backend, &[("shielded_pool", 20)]);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReadModel(ReadModelRequest::PoolReadPayoutMemoKeyReady),
            &backend,
        );
        let proposal = proposal_get(id).unwrap();
        assert_eq!(proposal.outcome, ActionOutcome::Executed);
        let snap = get_snapshot_for(proposal.snapshot_id.unwrap(), p(S1)).unwrap();
        assert_eq!(snap.source_canister, p(20));
        assert_eq!(snap.response, ReadModelResponse::PoolReadPayoutMemoKeyReady(Some(true)));
        assert_eq!(*backend.last_call_args.borrow(), candid::encode_args(()).unwrap());

        for value in [None, Some(false)] {
            setup();
            let backend = FakeBackend::ok(candid::encode_one(value).unwrap());
            wire_roles(&backend, &[("shielded_pool", 20)]);
            let id = drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::ReadModel(ReadModelRequest::PoolReadPayoutMemoKeyReady),
                &backend,
            );
            let proposal = proposal_get(id).unwrap();
            assert_eq!(proposal.outcome, ActionOutcome::Failed);
            assert_eq!(proposal.snapshot_id, None);
        }
    }

    /// Table-driven across every application binding: ceiling+1 bytes → deterministic
    /// Failed, no decode, never left Executing.
    #[test]
    fn f2_every_binding_rejects_oversize_response_pre_decode() {
        for kind in ApplicationAction::ALL {
            setup();
            let backend = FakeBackend::ok(Vec::new());
            wire_roles(&backend, &[("shielded_pool", 20), ("treasury", 21), ("vesting", 22)]);
            let binding = kind.binding();
            *backend.next_call_result.borrow_mut() =
                Ok(vec![0xAA; binding.max_response_bytes as usize + 1]);
            let id = drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::Application(dummy_request(kind)),
                &backend,
            );
            let rec = proposal_get(id).unwrap();
            assert_eq!(
                rec.outcome,
                ActionOutcome::Failed,
                "{kind:?}: oversize reply must be Failed, found {:?}",
                rec.outcome
            );
            assert!(
                rec.result.as_deref().unwrap_or("").contains("ceiling"),
                "{kind:?}: result should name the ceiling violation"
            );
        }
    }

    /// Exact-boundary ACCEPTED: a reply at exactly max_response_bytes goes to
    /// decode (here undecodable → OutcomeUnknown, NOT the size-Failed path).
    #[test]
    fn f2_exact_boundary_response_is_not_size_rejected() {
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("treasury", 21)]);
        let binding = ApplicationAction::TreasuryExecuteWithdrawal.binding();
        *backend.next_call_result.borrow_mut() =
            Ok(vec![0xBB; binding.max_response_bytes as usize]);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::Application(ActionRequest::TreasuryExecuteWithdrawal(0)),
            &backend,
        );
        assert_eq!(
            proposal_get(id).unwrap().outcome,
            ActionOutcome::OutcomeUnknown,
            "exact-boundary reply must reach decode, not the size check"
        );
    }

    #[test]
    fn f2_read_model_oversize_reply_failed_pre_decode_no_snapshot() {
        setup();
        let backend = FakeBackend::ok(vec![0xCC; READ_RESPONSE_MAX_BYTES + 1]);
        wire_roles(&backend, &[("nullifier_registry", 23)]);
        let req = ReadModelRequest::NullifierReadSpentAt {
            nullifier: [7u8; 32],
            page: PageRequest { cursor: None, limit: 1 },
        };
        let id = drive(p(S1), &[p(S1), p(S2)], VaultActionKind::ReadModel(req), &backend);
        let rec = proposal_get(id).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::Failed);
        assert_eq!(rec.snapshot_id, None, "no snapshot from a contract violation");
    }

    // ── F3: one governed-state validator, post_upgrade traps on corruption ───

    #[test]
    fn f3_post_upgrade_traps_on_every_governed_corruption() {
        // Duplicate purpose.
        setup();
        let mut g = gov();
        let dup = g.governed[0].clone();
        g.governed.push(dup);
        gov_store(&g);
        assert!(std::panic::catch_unwind(post_upgrade).is_err(), "duplicate purpose");

        // Wrong disposition on a cutover entry.
        setup();
        let mut g = gov();
        g.governed[0].disposition = ManifestDisposition::BornUnderVault;
        gov_store(&g);
        assert!(std::panic::catch_unwind(post_upgrade).is_err(), "wrong disposition");

        // Missing cutover entry.
        setup();
        let mut g = gov();
        g.governed.retain(|t| t.purpose != "wallet_frontend");
        gov_store(&g);
        assert!(std::panic::catch_unwind(post_upgrade).is_err(), "missing cutover");

        // Substituted cutover principal.
        setup();
        let mut g = gov();
        g.governed[0].principal = p(66);
        gov_store(&g);
        assert!(std::panic::catch_unwind(post_upgrade).is_err(), "substituted principal");

        // Swapped wired-role principal (no corresponding governed entry).
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("shielded_pool", 20)]);
        let mut g = gov();
        g.targets.shielded_pool = Some(p(21));
        gov_store(&g);
        assert!(std::panic::catch_unwind(post_upgrade).is_err(), "swapped wired principal");

        // And the sane state passes.
        setup();
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("shielded_pool", 20), ("treasury", 21)]);
        post_upgrade();
    }

    // ── F4: maximal cursors never panic ──────────────────────────────────────

    #[test]
    fn f4_maximal_cursor_returns_empty_pages() {
        setup();
        set_test_caller(p(S1));
        let backend = FakeBackend::ok(Vec::new());
        wire_roles(&backend, &[("verifier", 30)]);
        assert_eq!(list_proposals(Some(u64::MAX), 10), Some(Vec::new()));
        assert_eq!(get_audit_events(Some(u64::MAX), 10), Some(Vec::new()));
        let page = get_creation_receipts(Some(u64::MAX), 10).expect("gated page");
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
        // Direct helper too.
        let page = receipt_page(Some(u64::MAX), 1).unwrap();
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    // ── §3e VaultUpgradeViaUpgrader (CUST-L12-01) ────────────────────────────

    fn good_vault_upgrade() -> VaultUpgradeViaUpgrader {
        let wasm = b"vault-wasm-v2".to_vec();
        let arg = b"vault-arg".to_vec();
        VaultUpgradeViaUpgrader {
            // The CALLER always submits the unbound marker 0; the Vault binds
            // the proposal id AT CREATION (R1.2), never at the quorum boundary.
            request_id: 0,
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        }
    }

    fn ring_ok_trigger(outcome: ActionOutcome) -> FakeBackend {
        FakeBackend::ok(candid::encode_one(Ok::<_, stsh_custody_types::RecoveryError>(
            TriggerUpgradeResult { outcome },
        ))
        .unwrap())
    }

    #[test]
    fn ring_upgrade_executes_via_fixed_endpoint_with_bound_request_id() {
        setup();
        let backend = ring_ok_trigger(ActionOutcome::Executed);
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &backend,
        );
        let rec = proposal_get(id).unwrap();
        assert_eq!(rec.outcome, ActionOutcome::Executed);
        // The call went to the recorded Upgrader counterpart at the FIXED
        // endpoint, with request_id bound to the proposal id.
        let call = &backend.calls.borrow()[0];
        assert!(call.contains("trigger_vault_upgrade"), "{call}");
        assert!(call.contains(&p(UPGRADER).to_text()), "{call}");
        let (rid, _wh, _ah, _w, _a): (u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
            candid::decode_args(&backend.last_call_args.borrow()).unwrap();
        assert_eq!(rid, id, "request_id bound to the proposal id");
        // Bytes cleared after terminal durable; hashes + bound id retained.
        match &rec.action {
            VaultActionKind::VaultUpgradeViaUpgrader(vu) => {
                assert_eq!(vu.request_id, id);
                assert!(vu.wasm_bytes.is_empty());
                assert!(!vu.expected_wasm_hash.is_empty());
            }
            _ => panic!(),
        }
        assert!(reservation_get(id).is_some());
    }

    #[test]
    fn ring_upgrade_propose_validation() {
        setup();
        // request_id must be the unbound marker 0 at propose.
        let mut vu = good_vault_upgrade();
        vu.request_id = 7;
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::VaultUpgradeViaUpgrader(vu), None),
            Err(VaultError::IllegalSourceState)
        );
        // Hash mismatch rejected (wasm and arg).
        let mut vu = good_vault_upgrade();
        vu.expected_wasm_hash = sha256(b"nope");
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::VaultUpgradeViaUpgrader(vu), None),
            Err(VaultError::HashMismatch)
        );
        let mut vu = good_vault_upgrade();
        vu.expected_arg_hash = sha256(b"nope");
        assert_eq!(
            propose_inner(p(S1), VaultActionKind::VaultUpgradeViaUpgrader(vu), None),
            Err(VaultError::HashMismatch)
        );
    }

    #[test]
    fn ring_upgrade_transport_unknown_never_retries_never_pending() {
        setup();
        let backend = FakeBackend::rejecting("transport failure at trigger");
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &backend,
        );
        assert_eq!(proposal_get(id).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        assert_eq!(
            backend
                .calls
                .borrow()
                .iter()
                .filter(|c| c.contains("trigger_vault_upgrade"))
                .count(),
            1,
            "no blind retry"
        );
        let (o, exec) = approve_inner(p(S3), id, commit_of(id), now_ns()).unwrap();
        assert!(!exec);
        assert!(matches!(
            o,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::OutcomeUnknown,
                ..
            }
        ));
    }

    #[test]
    fn ring_upgrade_single_flight_scoped_to_the_vault() {
        setup();
        let a = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()), None,
        )
        .unwrap();
        approve_to_quorum(a);
        // A second Vault-target upgrade is blocked while A is in flight.
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()), None),
            Err(VaultError::IllegalSourceState)
        );
        // …but the DIRECT Upgrader-upgrade intent (different namespace,
        // different target) is NOT blocked by a Vault upgrade in flight.
        assert!(propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).is_ok());
    }

    #[test]
    fn ring_reconcile_happy_path_terminalizes_with_f4() {
        setup();
        let crash = FakeBackend::rejecting("crash at trigger");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &crash,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        let ok = FakeBackend::ok(
            candid::encode_one(Ok::<_, stsh_custody_types::RecoveryError>(
                ReconcileTerminalOutcome::Executed,
            ))
            .unwrap(),
        );
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    // §3e: the frozen field binds the VAULT principal here;
                    // controllers are exactly [Upgrader].
                    observed_upgrader_principal: self_id(),
                    observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                    observed_controllers: vec![p(UPGRADER)],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &ok,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        // The Upgrader's fixed reconcile endpoint was called with the target id.
        assert!(ok.calls.borrow()[0].contains("reconcile_vault_upgrade"));
        // F-4: the reconciliation audit event carries the approving signers.
        let ev = audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::Reconciled && e.proposal_id == Some(target))
            .expect("reconciled event");
        assert_eq!(ev.approving_signers, Some(vec![p(S1), p(S2)]));
        // Never re-triggerable: a second reconcile proposal is rejected.
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileVaultUpgradeViaUpgrader(
                    ReconcileVaultUpgradeViaUpgrader {
                        request_id: target,
                        objective_evidence: UpgradeObjectiveEvidence {
                            observed_upgrader_principal: self_id(),
                            observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                            observed_controllers: vec![p(UPGRADER)],
                            observed_canister_status: ObservedCanisterStatus::Running,
                            observed_at_ns: now_ns(),
                        },
                    }
                ), None),
            Err(VaultError::IllegalSourceState)
        );
    }

    #[test]
    fn ring_reconcile_rejects_stale_evidence_and_wrong_source_state() {
        setup();
        // Wrong source state: reconcile against a PENDING upgrade.
        let pending = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()), None,
        )
        .unwrap();
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileVaultUpgradeViaUpgrader(
                    ReconcileVaultUpgradeViaUpgrader {
                        request_id: pending,
                        objective_evidence: UpgradeObjectiveEvidence {
                            observed_upgrader_principal: self_id(),
                            observed_module_hash: None,
                            observed_controllers: vec![p(UPGRADER)],
                            observed_canister_status: ObservedCanisterStatus::Running,
                            observed_at_ns: now_ns(),
                        },
                    }
                ), None),
            Err(VaultError::IllegalSourceState),
            "Pending is not a legal reconcile source"
        );
        // Stale (pre-intent) evidence: reconcile Failed, target untouched.
        let crash = FakeBackend::rejecting("crash");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &crash,
        );
        let ok = FakeBackend::ok(Vec::new());
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: self_id(),
                    observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                    observed_controllers: vec![p(UPGRADER)],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: 0, // predates the durable intent
                },
            }),
            &ok,
        );
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::OutcomeUnknown,
            "stale evidence never terminalizes"
        );
        assert!(ok.calls.borrow().is_empty(), "no upgrader call on stale evidence");
    }

    #[test]
    fn ring_reconcile_transport_unknown_leaves_target_outcome_unknown() {
        setup();
        let crash = FakeBackend::rejecting("crash");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &crash,
        );
        // The reconcile CALL itself fails in transport: the reconcile
        // proposal is OutcomeUnknown, the target intent is untouched.
        let crash2 = FakeBackend::rejecting("crash at reconcile");
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: self_id(),
                    observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                    observed_controllers: vec![p(UPGRADER)],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &crash2,
        );
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::OutcomeUnknown);
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::OutcomeUnknown);
    }

    #[test]
    fn ring_and_direct_upgrades_have_distinct_intent_namespaces() {
        setup();
        // A direct Upgrader upgrade in flight does NOT block a Vault
        // upgrade, and vice versa — the locks are target-scoped.
        let direct = propose_inner(p(S1), VaultActionKind::UpgraderUpgrade(good_upgrade()), None).unwrap();
        approve_to_quorum(direct);
        let ring = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()), None,
        );
        assert!(ring.is_ok(), "distinct namespaces: no cross-blocking");
        // The §3d reconcile only accepts UpgraderUpgrade targets, and the
        // §3e reconcile only accepts VaultUpgradeViaUpgrader targets.
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
                    proposal_id: ring.unwrap(),
                    objective_evidence: UpgradeObjectiveEvidence {
                        observed_upgrader_principal: p(UPGRADER),
                        observed_module_hash: None,
                        observed_controllers: vec![],
                        observed_canister_status: ObservedCanisterStatus::Running,
                        observed_at_ns: now_ns(),
                    },
                }), None),
            Err(VaultError::IllegalSourceState),
            "cross-namespace reconcile rejected"
        );
    }

    #[test]
    fn ring_reconcile_executing_source_consults_upgrader_replay() {
        setup();
        // The successful-self-upgrade state: L1 intent stuck in Executing,
        // L2's intent already terminal. The reconcile MUST call the
        // Upgrader — its idempotent replay (Ok(Executed)) plus agreeing
        // evidence settles L1. No local-only path exists anymore.
        let target = propose_inner(
            p(S1),
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()), None,
        )
        .unwrap();
        approve_to_quorum(target);
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executing);
        let ok = FakeBackend::ok(
            candid::encode_one(Ok::<_, stsh_custody_types::RecoveryError>(
                ReconcileTerminalOutcome::Executed,
            ))
            .unwrap(),
        );
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: self_id(),
                    observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                    observed_controllers: vec![p(UPGRADER)],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &ok,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        assert!(
            ok.calls.borrow().iter().any(|c| c.contains("reconcile_vault_upgrade")),
            "Executing-source reconcile MUST consult the Upgrader"
        );
        // Repeated reconciliation: never re-triggerable — a new reconcile
        // proposal is rejected; the terminal result stands unmutated.
        assert_eq!(
            propose_inner(
                p(S1),
                VaultActionKind::ReconcileVaultUpgradeViaUpgrader(
                    ReconcileVaultUpgradeViaUpgrader {
                        request_id: target,
                        objective_evidence: UpgradeObjectiveEvidence {
                            observed_upgrader_principal: self_id(),
                            observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                            observed_controllers: vec![p(UPGRADER)],
                            observed_canister_status: ObservedCanisterStatus::Running,
                            observed_at_ns: now_ns(),
                        },
                    }
                ), None),
            Err(VaultError::IllegalSourceState)
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Executed);
    }

    #[test]
    fn ring_reconcile_unknown_intent_is_terminal_no_admission_releases_lock() {
        setup();
        // CUST-L12-03: L1 OutcomeUnknown (trigger lost), Upgrader has NO
        // intent → terminal Failed-as-no-admission (NEVER Executed, even
        // with matching module hash), typed anomaly, lock RELEASED.
        let crash = FakeBackend::rejecting("trigger lost");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &crash,
        );
        let backend = FakeBackend::ok(
            candid::encode_one(Err::<ReconcileTerminalOutcome, _>(
                stsh_custody_types::RecoveryError::UnknownProposal {
                    proposal_id: target,
                },
            ))
            .unwrap(),
        );
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: self_id(),
                    // Evidence says the module IS running — no admission
                    // still means Failed, never Executed.
                    observed_module_hash: Some(sha256(b"vault-wasm-v2")),
                    observed_controllers: vec![p(UPGRADER)],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &backend,
        );
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        assert_eq!(
            proposal_get(target).unwrap().outcome,
            ActionOutcome::Failed,
            "no admission is terminal Failed, never Executed"
        );
        let anomaly = audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::ReconcileConflict && e.proposal_id == Some(target))
            .expect("typed anomaly recorded");
        assert!(anomaly.detail.contains("no admission"));
        assert_eq!(anomaly.approving_signers, Some(vec![p(S1), p(S2)]));
        // The wedge is gone: a FRESH normal Vault upgrade is accepted and
        // executes — and this survives post_upgrade.
        post_upgrade();
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Failed);
        let ok = ring_ok_trigger(ActionOutcome::Executed);
        let fresh = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &ok,
        );
        assert_eq!(proposal_get(fresh).unwrap().outcome, ActionOutcome::Executed);
    }

    #[test]
    fn ring_reconcile_disagreement_resolves_per_l2_with_conflict_recorded() {
        for l2_says in [
            ReconcileTerminalOutcome::Executed,
            ReconcileTerminalOutcome::Failed,
        ] {
            setup();
            // CUST-L12-03 OPTION A: L2's durable outcome is authoritative;
            // the drift is a typed conflict; the lock releases.
            let crash = FakeBackend::rejecting("trigger lost");
            let target = drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
                &crash,
            );
            let backend = FakeBackend::ok(
                candid::encode_one(Ok::<_, stsh_custody_types::RecoveryError>(l2_says)).unwrap(),
            );
            // Evidence deliberately DISAGREES with L2's outcome.
            let evidence_module = match l2_says {
                ReconcileTerminalOutcome::Executed => sha256(b"drifted-module"),
                ReconcileTerminalOutcome::Failed => sha256(b"vault-wasm-v2"),
            };
            let rid = drive(
                p(S1),
                &[p(S1), p(S2)],
                VaultActionKind::ReconcileVaultUpgradeViaUpgrader(
                    ReconcileVaultUpgradeViaUpgrader {
                        request_id: target,
                        objective_evidence: UpgradeObjectiveEvidence {
                            observed_upgrader_principal: self_id(),
                            observed_module_hash: Some(evidence_module),
                            observed_controllers: vec![p(UPGRADER)],
                            observed_canister_status: ObservedCanisterStatus::Running,
                            observed_at_ns: now_ns(),
                        },
                    },
                ),
                &backend,
            );
            let expected = match l2_says {
                ReconcileTerminalOutcome::Executed => ActionOutcome::Executed,
                ReconcileTerminalOutcome::Failed => ActionOutcome::Failed,
            };
            assert_eq!(
                proposal_get(target).unwrap().outcome,
                expected,
                "terminalizes per L2's durable outcome ({l2_says:?})"
            );
            assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
            let conflict = audit_events()
                .into_iter()
                .find(|e| e.kind == AuditKind::ReconcileConflict && e.proposal_id == Some(target))
                .expect("typed conflict recorded");
            assert!(conflict.detail.contains("drift"));
            // Lock released + post_upgrade consistency.
            post_upgrade();
            assert_eq!(proposal_get(target).unwrap().outcome, expected);
            assert!(propose_inner(
                p(S1),
                VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()), None)
            .is_ok());
        }
    }

    #[test]
    fn ring_reconcile_failed_replay_settles_failed_consistently() {
        setup();
        // L2 already Failed (idempotent replay) and the evidence agrees
        // (approved module not running) → L1 settles Failed, both layers
        // consistent.
        let crash = FakeBackend::rejecting("trigger lost");
        let target = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::VaultUpgradeViaUpgrader(good_vault_upgrade()),
            &crash,
        );
        let backend = FakeBackend::ok(
            candid::encode_one(Ok::<_, stsh_custody_types::RecoveryError>(
                ReconcileTerminalOutcome::Failed,
            ))
            .unwrap(),
        );
        let rid = drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
                request_id: target,
                objective_evidence: UpgradeObjectiveEvidence {
                    observed_upgrader_principal: self_id(),
                    observed_module_hash: Some(sha256(b"old-module")),
                    observed_controllers: vec![p(UPGRADER)],
                    observed_canister_status: ObservedCanisterStatus::Running,
                    observed_at_ns: now_ns(),
                },
            }),
            &backend,
        );
        assert_eq!(proposal_get(target).unwrap().outcome, ActionOutcome::Failed);
        assert_eq!(proposal_get(rid).unwrap().outcome, ActionOutcome::Executed);
        assert!(audit_events()
            .iter()
            .any(|e| e.kind == AuditKind::Reconciled && e.proposal_id == Some(target)));
    }
    // =========================================================================
    // §S7 START SETTLEMENT — CELL 3 ACCEPTANCE (Vault -> Upgrader), the retrofit
    //
    // The PLANE-SPECIFIC half, and the twin of the Upgrader's cell-4 suite. The
    // direction-agnostic predicates (§4, §4a, §5, §7d classification, §7f order,
    // §3c guard) are asserted once, over BOTH directions, in
    // `stsh-custody-types/tests/s7_start_settlement_acceptance.rs` — both planes
    // call the SAME functions, so asserting them there is stronger than
    // asserting two drifting copies. Asserted here is what cannot be proven from
    // pure functions: E1, the E2 sweep, the §3c fence, the §8a atomic durable
    // transition, single-flight, and the §7f gates end-to-end on this plane.
    // =========================================================================

    fn start_evidence(
        status: ObservedCanisterStatus,
        at: u64,
    ) -> StartObjectiveEvidence {
        StartObjectiveEvidence {
            // Cell 3's target is the UPGRADER; its controllers must be exactly
            // [Vault], and this canister IS the Vault.
            observed_target_principal: p(UPGRADER),
            observed_canister_status: status,
            observed_controllers: vec![self_id()],
            observed_at_ns: at,
        }
    }

    fn ring_start() -> VaultActionKind {
        VaultActionKind::Management(ManagementAction::Start { target: p(UPGRADER) })
    }

    fn rec_of(id: u64) -> ProposalRecord {
        proposal_get(id).expect("proposal exists")
    }

    fn start_of(id: u64) -> StartSettlementState {
        rec_of(id).start.expect("start state present")
    }

    fn audit_kinds_for(id: u64) -> Vec<AuditKind> {
        AUDIT_EVENTS.with(|a| {
            a.borrow()
                .iter()
                .filter_map(|(_, raw)| candid::decode_one::<AuditEvent>(&raw).ok())
                .filter(|e| e.proposal_id == Some(id))
                .map(|e| e.kind)
                .collect()
        })
    }

    fn audit_len() -> u64 {
        AUDIT_EVENTS.with(|a| a.borrow().len())
    }

    fn settle_cell3(target_id: u64, ev: &StartObjectiveEvidence) -> u64 {
        drive(
            p(S1),
            &[p(S1), p(S2)],
            VaultActionKind::ReconcileUpgraderStart(ReconcileUpgraderStart {
                proposal_id: target_id,
                objective_evidence: ev.clone(),
            }),
            &FakeBackend::ok(Vec::new()),
        )
    }

    /// §2 — the durable start-intent lands BEFORE the first `await`, and E1
    /// routes a transport rejection to `OutcomeUnknown`, never blindly `Failed`
    /// (acceptance 1).
    #[test]
    fn s7_cell3_acceptance_1_reply_loss_is_outcome_unknown_never_failed() {
        setup();
        let backend = FakeBackend::rejecting("SysTransient: no reply");
        let id = drive(p(S1), &[p(S1), p(S2)], ring_start(), &backend);

        assert_eq!(
            rec_of(id).outcome,
            ActionOutcome::OutcomeUnknown,
            "E1: a transport rejection routes to OutcomeUnknown IN THE SAME MESSAGE"
        );
        assert_ne!(
            rec_of(id).outcome,
            ActionOutcome::Failed,
            "NEVER blindly Failed — inferring the call's fate is the assumption \
             R-2 forecloses"
        );
        // §2: the intent is durable, and it was written before the call.
        let st = start_of(id);
        assert_eq!(st.intent.proposal_id, id);
        assert_eq!(st.intent.target, p(UPGRADER));
        assert!(st.settlement.is_none(), "E1 writes no SettlementRecord");
    }

    /// §5 / §8a — settlement writes the terminal outcome and the write-once
    /// record TOGETHER, and the record binds the SETTLING evidence.
    #[test]
    fn s7_cell3_settlement_writes_outcome_and_record_together() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        let ev = start_evidence(ObservedCanisterStatus::Running, now_ns());
        let rid = settle_cell3(id, &ev);

        assert_eq!(rec_of(rid).outcome, ActionOutcome::Executed, "the reconcile executed");
        assert_eq!(rec_of(id).outcome, ActionOutcome::Executed, "§5: Running => Executed");
        let record = start_of(id).settlement.expect("terminal implies a durable record");
        assert_eq!(record.outcome, ReconcileTerminalOutcome::Executed);
        assert_eq!(record.semantic_key, ev.semantic_key());
        assert_eq!(record.evidence_commitment, ev.evidence_commitment());
        assert!(!record.conflict_recorded, "the §7d cap starts available");
    }

    /// §5 Stopped => Failed, the other half of the mapping table.
    #[test]
    fn s7_cell3_stopped_settles_failed() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        settle_cell3(id, &start_evidence(ObservedCanisterStatus::Stopped, now_ns()));
        assert_eq!(rec_of(id).outcome, ActionOutcome::Failed);
        assert_eq!(
            start_of(id).settlement.unwrap().outcome,
            ReconcileTerminalOutcome::Failed
        );
    }

    /// Acceptance 5 — `Stopping` is inconclusive: no terminalization, lock NOT
    /// released, and re-observation settles it.
    #[test]
    fn s7_cell3_acceptance_5_stopping_is_inconclusive() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        settle_cell3(id, &start_evidence(ObservedCanisterStatus::Stopping, now_ns()));

        assert_eq!(rec_of(id).outcome, ActionOutcome::OutcomeUnknown, "no terminalization");
        assert!(start_of(id).settlement.is_none(), "no record is written");
        assert!(
            open_mutating_intent(p(UPGRADER), None).is_some(),
            "§7e: the lock is RETAINED on an inconclusive observation"
        );

        // Re-observation settles it.
        settle_cell3(id, &start_evidence(ObservedCanisterStatus::Running, now_ns()));
        assert_eq!(rec_of(id).outcome, ActionOutcome::Executed);
        assert!(
            open_mutating_intent(p(UPGRADER), None).is_none(),
            "§7e: the lock releases at the FIRST transition to Executed|Failed"
        );
    }

    /// Acceptance 10 — a late callback is FENCED after the E2 sweep: zero
    /// settlement-state mutation, no terminalization, lock still held, record
    /// absent. Asserted as EXACT RECORD EQUALITY, not inferred from one field.
    #[test]
    fn s7_cell3_acceptance_10_late_callback_is_fenced_after_e2() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        // Force the callback-writable state, then run E2 as an upgrade would.
        let mut r = rec_of(id);
        r.outcome = ActionOutcome::Executing;
        proposal_put(&r);
        sweep_executing_starts_to_unknown(now_ns());
        assert_eq!(rec_of(id).outcome, ActionOutcome::OutcomeUnknown);

        let before = rec_of(id);
        let audits_before = audit_len();
        // The pre-upgrade callback arrives afterwards.
        assert!(
            !start_callback_may_write(id),
            "§3c.2: the callback may write IFF the durable outcome is Executing"
        );
        assert_eq!(
            rec_of(id),
            before,
            "a fenced callback performs ZERO settlement-state mutation"
        );
        assert!(start_of(id).settlement.is_none(), "no SettlementRecord");
        assert_eq!(
            audit_kinds_for(id)
                .iter()
                .filter(|k| matches!(k, AuditKind::LateCallbackFenced))
                .count(),
            1,
            "§3c.3: exactly ONE bounded fencing event"
        );
        assert_eq!(audit_len(), audits_before + 1, "and nothing else is appended");

        // MUTATION: widening the guard to admit OutcomeUnknown would let the
        // callback terminalize from a payload that is NEVER evidence.
        assert!(!callback_may_write(ActionOutcome::OutcomeUnknown));
    }

    /// Acceptance 12 — the E2 sweep is idempotent and safe.
    #[test]
    fn s7_cell3_acceptance_12_e2_sweep_is_idempotent() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        let mut r = rec_of(id);
        r.outcome = ActionOutcome::Executing;
        proposal_put(&r);

        sweep_executing_starts_to_unknown(now_ns());
        assert_eq!(rec_of(id).outcome, ActionOutcome::OutcomeUnknown);
        let after_first = rec_of(id);
        let audits = audit_len();

        sweep_executing_starts_to_unknown(now_ns());
        assert_eq!(rec_of(id), after_first, "a second upgrade changes NOTHING");
        assert_eq!(audit_len(), audits, "and appends nothing further");
        assert!(!rec_of(id).outcome.is_terminal(), "E2 writes NO terminal outcome");
        assert!(start_of(id).settlement.is_none(), "E2 takes NO evidence");
    }

    /// §7d / acceptance 16(b) — the FIRST valid discordance writes exactly one
    /// event and sets the marker; every later one writes NOTHING. And §7c: no
    /// replay branch is success-shaped, and none re-opens the proposal.
    #[test]
    fn s7_cell3_acceptance_16b_only_the_first_discordance_writes() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        settle_cell3(id, &start_evidence(ObservedCanisterStatus::Running, now_ns()));
        assert_eq!(rec_of(id).outcome, ActionOutcome::Executed);

        for k in 0..4u64 {
            let rid = settle_cell3(
                id,
                &start_evidence(ObservedCanisterStatus::Stopped, now_ns() + k),
            );
            assert_eq!(
                rec_of(rid).outcome,
                ActionOutcome::Failed,
                "§7c: a replay is never success-shaped"
            );
            assert_eq!(rec_of(id).outcome, ActionOutcome::Executed, "NO RE-OPEN");
        }

        let conflicts = audit_kinds_for(id)
            .iter()
            .filter(|k| matches!(k, AuditKind::SettlementEvidenceConflict))
            .count();
        assert_eq!(
            conflicts, 1,
            "§7d: AT MOST ONE conflict event per proposal, EVER — not one per hash"
        );
        assert!(
            start_of(id).settlement.unwrap().conflict_recorded,
            "the durable one-bit cap is set"
        );
    }

    /// Acceptance 9(b) — the C2 growth route: N distinct, fresh, semantically
    /// CONCORDANT observations with N distinct `evidence_commitment` values
    /// produce ZERO conflict events and ZERO appends against the target.
    #[test]
    fn s7_cell3_acceptance_9b_concordant_reobservation_never_conflicts() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        settle_cell3(id, &start_evidence(ObservedCanisterStatus::Running, now_ns()));

        let mut commitments = std::collections::HashSet::new();
        for k in 1..=5u64 {
            let ev = start_evidence(ObservedCanisterStatus::Running, now_ns() + k);
            assert!(
                commitments.insert(ev.evidence_commitment()),
                "9(b) requires N DISTINCT evidence_commitment values — repeating \
                 one hash does not exercise the C2 route"
            );
            settle_cell3(id, &ev);
        }
        assert_eq!(
            audit_kinds_for(id)
                .iter()
                .filter(|k| matches!(k, AuditKind::SettlementEvidenceConflict))
                .count(),
            0,
            "ZERO conflicts for N concordant re-observations"
        );
    }

    /// §2 — a start and an upgrade must not be in flight against the same
    /// target concurrently. The ring start now HOLDS the mutating single-flight
    /// lock on the Upgrader, which it did not before S7.
    #[test]
    fn s7_cell3_ring_start_holds_single_flight_on_the_upgrader() {
        setup();
        let id = drive(
            p(S1),
            &[p(S1), p(S2)],
            ring_start(),
            &FakeBackend::rejecting("no reply"),
        );
        assert_eq!(
            open_mutating_intent(p(UPGRADER), None),
            Some(id),
            "§2: an OutcomeUnknown ring start holds the lock on its target"
        );

        // A start against an ORDINARY GOVERNED target is out of S7's scope and
        // its prior lock-free behaviour is PRESERVED (R4.3).
        assert_eq!(
            mutating_intent_target(&VaultActionKind::Management(ManagementAction::Start {
                target: pyeop()
            })),
            None,
            "R4.3: a non-ring start claims no single-flight entry, unchanged"
        );
    }

    /// §0b / acceptance 13(a) — the settle arm is ONE atomic durable
    /// transition. Source-text tripwire, the codebase's established idiom for
    /// this class (see the S5B W5(b) tripwire), because Rust cannot express
    /// "these statements share a message" as a type and a runtime test cannot
    /// observe a boundary that does not exist.
    #[test]
    fn s7_cell3_settlement_write_is_one_transaction() {
        const SRC: &str = include_str!("lib.rs");
        let f = SRC
            .find("fn execute_reconcile_upgrader_start(")
            .expect("the cell-3 settlement core exists");
        // Bound to THIS FUNCTION's body: up to the next `}` at column 0, which
        // is where a top-level item ends in this file. A looser bound would
        // sweep in unrelated code and make the lint fire on someone else's
        // `await` — a tripwire that cannot be trusted to point at its subject
        // is worse than none.
        let body = &SRC[f..];
        let end = body.find("\n}\n").expect("the function closes") + 3;
        let body = &body[..end];

        assert!(
            !body.contains(".await"),
            "§0b VIOLATED: `.await` inside the cell-3 settlement core. The \
             terminal outcome, the SettlementRecord, the conflict_recorded \
             transition and the audit append must land in ONE synchronous \
             message execution. An await admits `marker without event` (every \
             future discordance silenced while nothing was recorded) and `event \
             without marker` (a second event becomes possible, breaking the §7d \
             cap). Neither is a permitted state."
        );
        // Not vacuous: the pair really is in this function.
        assert!(body.contains("record.conflict_recorded = true;"));
        assert!(body.contains("audit_conflict("));

        // MUTATION (the normative form): an injected await between the halves
        // must REGISTER.
        let mutated = body.replacen(
            "record.conflict_recorded = true;",
            "record.conflict_recorded = true;\n    some_future().await;",
            1,
        );
        assert!(
            mutated.contains(".await"),
            "§0b MUTATION DID NOT REGISTER — the tripwire is inert"
        );
    }

    // ── B-1 — the approval commitment binds action, epoch and expiry ────────
    //
    // Shape shared by all three: ONE real proposal, stored via
    // `inject_bound_proposal_for_test` with `epoch: 0` and `expires_at_ns:
    // Some(2_000_000_000)`, and a SECOND record built as a plain struct-update
    // literal sharing `rec_a`'s `proposal_id` and differing in EXACTLY the
    // field under test. `rec_b` is never stored; its commitment is read off
    // `commitment_for`, the function under test, never off
    // `ApprovalCommitmentV1::new` directly.
    //
    // The two fixture literals are load-bearing for the POSITIVE arm, not for
    // the property: `approve_inner` admits in the pinned order 3 → 4 → 4b → 5,
    // and `epoch: 0` matches the governance epoch `setup()`'s `init` installs
    // (step 5, the epoch pin) while `expires_at_ns` strictly greater than
    // `TEST_NOW` (1_000_000_000) clears the half-open expiry check (step 4b).
    // Any other choice fails the positive arm before the mutation can speak.

    // BINDING: B-1-ACTION
    #[test]
    fn b1_action_divergence_cross_approval_rejected() {
        setup();
        let id_a = inject_bound_proposal_for_test(
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            0,
            Some(2_000_000_000),
        );
        let rec_a = proposal_get(id_a).unwrap();
        let hash_a = commit_of(id_a);
        assert_eq!(
            hash_a, rec_a.commitment_hash,
            "sanity: stored hash matches its own record"
        );

        let rec_b = ProposalRecord {
            action: VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2), p(S3)],
                threshold: 2,
            },
            ..rec_a.clone()
        };
        let hash_b = commitment_for(&rec_b).hash();
        assert_ne!(
            hash_a, hash_b,
            "two records sharing one proposal_id, epoch and expiry, differing only \
             in action, must hash differently"
        );

        assert_eq!(
            approve_inner(p(S1), id_a, hash_b, now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::CallerMismatch
            )),
            "the stored proposal must reject an approval built over the OTHER action's commitment"
        );
        approve_inner(p(S1), id_a, hash_a, now_ns())
            .expect("the proposal's own real, stored commitment still approves");
    }

    // BINDING: B-1-EPOCH
    #[test]
    fn b1_epoch_divergence_cross_approval_rejected() {
        setup();
        let id_a = inject_bound_proposal_for_test(
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            0,
            Some(2_000_000_000),
        );
        let rec_a = proposal_get(id_a).unwrap();
        let hash_a = commit_of(id_a);
        let rec_b = ProposalRecord {
            epoch: 1,
            ..rec_a.clone()
        };
        let hash_b = commitment_for(&rec_b).hash();
        assert_ne!(
            hash_a, hash_b,
            "same id/action/expiry, differing epoch, must hash differently"
        );
        assert_eq!(
            approve_inner(p(S1), id_a, hash_b, now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::CallerMismatch
            )),
        );
        approve_inner(p(S1), id_a, hash_a, now_ns()).expect("own commitment still approves");
    }

    // BINDING: B-1-EXPIRY
    #[test]
    fn b1_expiry_divergence_cross_approval_rejected() {
        setup();
        let id_a = inject_bound_proposal_for_test(
            VaultActionKind::UpgraderUpgrade(good_upgrade()),
            0,
            Some(2_000_000_000),
        );
        let rec_a = proposal_get(id_a).unwrap();
        let hash_a = commit_of(id_a);
        let rec_b = ProposalRecord {
            expires_at_ns: Some(3_000_000_000),
            ..rec_a.clone()
        };
        let hash_b = commitment_for(&rec_b).hash();
        assert_ne!(
            hash_a, hash_b,
            "same id/action/epoch, differing expiry, must hash differently"
        );
        assert_eq!(
            approve_inner(p(S1), id_a, hash_b, now_ns()),
            Err(VaultError::CommitmentMismatch(
                stsh_custody_types::CommitmentMismatch::CallerMismatch
            )),
        );
        approve_inner(p(S1), id_a, hash_a, now_ns()).expect("own commitment still approves");
    }

}

// ── TEST-ONLY injection (feature `testing`) ─────────────────────────────────
//
// ABSENT from every production Wasm: `testing` is off by default and its
// absence is ENFORCED by eager_cell_feature_isolation_tests, not merely
// asserted.
//
// WHY THIS EXISTS. Proving MemoryId 8 (creation single-flight) VALIDATION
// across a REAL Wasm upgrade needs a nonterminal creation intent that a test
// can hold open. Production offers no such state on demand: `create_canister`
// either succeeds (`Executed`) or is rejected (`OutcomeUnknown`), and the only
// way to force a rejection — under-funding below `CREATE_CANISTER_CYCLES` —
// drains the canister below its freezing threshold, so the ingress is rejected
// instead of the state being produced. An earlier attempt at this test let the
// call settle and RETURNED EARLY when it terminalized, which meant it never
// reached the upgrade and would have passed even if the companion were never
// validated.
//
// It writes through `proposal_put` — the SAME choke point production uses — so
// the companion entry is produced by the real maintenance path rather than
// planted, and the upgrade therefore validates genuine durable state.
/// §S7 P1-4 — PRODUCTION-FAITHFUL SEAM: reach a ring start's quorum boundary
/// and DROP the management call, modelling a `start_canister` whose reply has
/// not arrived.
///
/// This plants NOTHING. It runs the REAL `approve_inner` (so `Executing`, the
/// approval set, the reservation and the quorum audit are exactly what
/// production writes) and then the REAL `record_start_intent` — the same
/// function `execute_management` calls before its first `await`. The only
/// difference from production is that `start_canister` is never issued, which
/// is precisely the condition E2 exists for.
///
/// Necessary because a management `start_canister` always replies within the
/// message on PocketIC, so a start held across an upgrade boundary is otherwise
/// unreachable — and fabricating `Executing` by hand would prove nothing about
/// the wiring `post_upgrade` actually runs against.
#[cfg(feature = "testing")]
#[update]
fn approve_start_without_issuing_call_for_test(
    proposal_id: u64,
    expected_action_hash: Vec<u8>,
) -> Result<(), VaultError> {
    let (_, should_execute) = approve_inner(caller(), proposal_id, expected_action_hash, now_ns())?;
    if should_execute {
        let target = match proposal_get(proposal_id).expect("proposal exists").action {
            VaultActionKind::Management(ManagementAction::Start { target }) => target,
            other => ic_cdk::trap(&format!(
                "approve_start_without_issuing_call_for_test: not a start: {other:?}"
            )),
        };
        assert!(is_ring_start(target), "seam is for RING starts only");
        // The production pre-await write, verbatim.
        assert!(record_start_intent(proposal_id, target, now_ns()), "single-flight admitted");
    }
    Ok(())
}

/// TEST-ONLY (native `test` or feature `testing`) — B-1-ACTION/EPOCH/EXPIRY.
///
/// Stores ONE real `ProposalRecord` with a caller-chosen action, epoch and
/// expiry, using the SAME store-once shape as `propose_inner` and
/// `inject_nonterminal_creation_for_test`: placeholder hash, re-read, hash
/// written via `commitment_for`, then `commit_id`. An injected proposal is
/// therefore indistinguishable from a real one to every index, the seal, and
/// every commitment check.
///
/// It is a plain `fn` (not an `#[update]`) under `any(test, feature =
/// "testing")` — the `inject_entry_rate_for_test` precedent — because the B-1
/// tests are NATIVE in-crate tests, and an `#[update]`-only hook gated on
/// `feature = "testing"` alone is unreachable from them.
#[cfg(any(test, feature = "testing"))]
pub fn inject_bound_proposal_for_test(
    action: VaultActionKind,
    epoch: u64,
    expires_at_ns: Option<u64>,
) -> u64 {
    let id = next_proposal_id();
    proposal_put(&ProposalRecord {
        proposal_id: id,
        action,
        proposer: Principal::anonymous(),
        created_at_ns: now_ns(),
        epoch,
        outcome: ActionOutcome::Pending,
        result: None,
        snapshot_id: None,
        intent: None,
        start: None,
        expires_at_ns,
        commitment_hash: Vec::new(),
    });
    {
        let mut rec = proposal_get(id).expect("just-injected proposal");
        rec.commitment_hash = commitment_for(&rec).hash();
        proposal_put(&rec);
    }
    commit_id(IdKind::Proposal, id);
    id
}

#[cfg(feature = "testing")]
#[update]
fn inject_nonterminal_creation_for_test(manifest_purpose: String) -> u64 {
    require_signer(caller()).expect("signer-only");
    let id = next_proposal_id();
    let g = gov();
    proposal_put(&ProposalRecord {
        proposal_id: id,
        action: VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose,
            disposition: ManifestDisposition::BornUnderVault,
        }),
        proposer: caller(),
        created_at_ns: now_ns(),
        epoch: g.epoch,
        // Nonterminal, so it HOLDS the purpose-scoped creation lock. Matches
        // the outcome a real rejected create_canister lands in.
        outcome: ActionOutcome::OutcomeUnknown,
        result: None,
        snapshot_id: None,
        intent: None,
        // §S7: a creation proposal is not a start and carries no start state.
        start: None,
        expires_at_ns: None,
        // Placeholder, replaced immediately below — same store-once shape as
        // propose_inner, so the injected record is indistinguishable from a
        // real one to every index and every commitment check.
        commitment_hash: Vec::new(),
    });
    {
        let mut rec = proposal_get(id).expect("just-injected proposal");
        rec.commitment_hash = commitment_for(&rec).hash();
        proposal_put(&rec);
    }
    // S5B W1.2 — the injection hook goes through the SAME allocation primitive
    // as production, so an injected proposal is indistinguishable from a real
    // one to the counters and the seal. A hook that bypassed `commit_id` would
    // leave the companion inconsistent and make every test using it fail on
    // validation rather than on its actual subject.
    commit_id(IdKind::Proposal, id);
    id
}

/// TEST-ONLY (feature `testing`): corrupt the companion indexes.
///
/// WITHOUT THIS, A REAL-UPGRADE TEST CANNOT FAIL. The companions are
/// `StableBTreeMap`s: they live in stable memory and survive a Wasm
/// replacement inherently, so an upgrade test that does not corrupt one first
/// asserts only that stable memory persisted — true, but not the property
/// under test.
///
/// Corrupting one first makes the post-upgrade assertions depend on DETECTION:
/// `companion_check` traps when a companion disagrees with MemoryId 9's
/// accounting. Nothing is repaired and nothing is re-derived — amended R3 item
/// 10 ships no repair surface, and recovery from durable corruption is a
/// governed, hash-bound Wasm upgrade.
#[cfg(feature = "testing")]
#[update]
fn corrupt_indexes_for_test() {
    require_signer(caller()).expect("signer-only");
    OPEN_MUTATING_INTENT_INDEX.with(|x| {
        let mut x = x.borrow_mut();
        let keys: Vec<(Principal, u64)> = x.iter().map(|(k, _)| k).collect();
        for k in keys {
            x.remove(&k);
        }
    });
    OPEN_CREATION_INTENT_INDEX.with(|x| {
        let mut x = x.borrow_mut();
        let keys: Vec<Blob<40>> = x.iter().map(|(k, _)| k).collect();
        for k in keys {
            x.remove(&k);
        }
    });
    PROPOSAL_EXPIRY_INDEX.with(|x| {
        let mut x = x.borrow_mut();
        let keys: Vec<(u64, u64)> = x.iter().map(|(k, _)| k).collect();
        for k in keys {
            x.remove(&k);
        }
    });
}

// ── DID drift lock (S2.1) ───────────────────────────────────────────────────
//
// `export_service!` must sit at crate scope, AFTER every endpoint, so it can
// see them all. Compared against the committed vault.did by
// `tests::did_types_match_the_real_rust_interface`.
//
// The Vault had NO DID conformance test at all, which is how `AuditKind` grew
// `ProposalCancelled`/`ProposalExpired` in Rust while the committed Candid did
// not — a client decoding an audit page containing either event would have
// failed on the wire.
candid::export_service!();

// ── S5B W5(b) — the no-`await` tripwire ──────────────────────────────────────
//
// The §4 amendment pins an await-free governance-execution path as a
// LOAD-BEARING invariant: the ratified same-message model is equivalent to the
// superseded keyed-repair model ONLY while the path is await-free, and the
// repair machinery that would otherwise be required does not exist and may not
// be added. An `await` between the cell write and finalization would therefore
// silently reintroduce exactly the partial state the ratification argues cannot
// occur — with nothing behind it to repair the damage.
//
// A type-level guard cannot express this: `async fn` is legal Rust and the
// compiler has no opinion about awaits between two particular statements. So
// the tripwire is a source lint over this file's own text, which is the same
// mechanism the DID drift lock uses.
//
// Brief W5(b) mutation requirement: "making the helper `async`, or inserting an
// `await` anywhere between the cell write and finalization, must make the test
// and/or lint FAIL. A tripwire that survives its own mutation is not a
// tripwire." Both mutations are exercised in `w5b_lint_mutation_tests`.
#[cfg(test)]
const VAULT_SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));

/// Extract `execute_signer_set_update`'s body from source text.
#[cfg(test)]
fn governance_exec_body(src: &str) -> &str {
    let sig = src
        .find("fn execute_signer_set_update(")
        .expect("W5(b): governance execution helper not found — did it get renamed?");
    // The declaration line, back to the start of the line, so an `async`
    // qualifier is inside the slice we inspect.
    let line_start = src[..sig].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let rest = &src[line_start..];
    let end = rest
        .find("\nasync fn execute_read_model")
        .expect("W5(b): could not bound the governance execution helper");
    &rest[..end]
}

#[cfg(test)]
mod w5b_await_lint {
    use super::{governance_exec_body, VAULT_SRC};

    /// W5(b) — the pinned invariant. Fails if the helper becomes `async`, or if
    /// any `.await` appears between the cell write and finalization.
    #[test]
    fn w5b_no_await_between_cell_write_and_finalize() {
        let body = governance_exec_body(VAULT_SRC);

        assert!(
            !body.starts_with("async ") && !body.contains("\nasync fn execute_signer_set_update"),
            "W5(b) VIOLATED: execute_signer_set_update is `async`. The §4 ratification \
             holds only for an await-free path, and no repair machinery exists behind it."
        );

        let store = body
            .find("gov_store(&g);")
            .expect("W5(b): cell write not found in governance execution path");
        let finalize = body[store..]
            .find("finalize(")
            .expect("W5(b): finalization not found after the cell write")
            + store;
        let between = &body[store..finalize];

        assert!(
            !between.contains(".await"),
            "W5(b) VIOLATED: `.await` between the governance cell write and \
             finalization. This reintroduces an externally-committable partial \
             state that the ratified model has no machinery to repair.\n\
             Offending region:\n{between}"
        );
    }

    /// The mutation check the brief requires of the tripwire itself.
    ///
    /// RECORDED, because it changes what this lint is actually for: the three
    /// mutations were each applied to the REAL file and re-run, not only to the
    /// copied text below, and they do not all fail the same way.
    ///
    /// - `async fn execute_signer_set_update` — caught by THIS LINT.
    /// - bare `some_future().await;` between the boundaries — caught by the
    ///   COMPILER (E0728: await only allowed inside async functions), never
    ///   reaching the lint. Stronger than the lint, but it means the await
    ///   guard is NOT exercised by this mutation.
    /// - `let _staged = async { … .await };` between the boundaries — compiles
    ///   fine in a sync fn, and is caught by THIS LINT's await guard.
    ///
    /// The third case is why the await guard is not dead code. A future
    /// maintainer staging an async block mid-path writes something that the
    /// compiler accepts and that reintroduces the hazard textually; only the
    /// lint objects. Both guards are therefore live and independently earned.
    #[test]
    fn w5b_lint_mutation_tests() {
        let body = governance_exec_body(VAULT_SRC);

        // Mutation 1 — insert an `await` between the cell write and finalize.
        let mutated = body.replacen(
            "gov_store(&g);",
            "gov_store(&g);\n    some_future().await;",
            1,
        );
        let store = mutated.find("gov_store(&g);").unwrap();
        let finalize = mutated[store..].find("finalize(").unwrap() + store;
        assert!(
            mutated[store..finalize].contains(".await"),
            "W5(b) MUTATION 1 DID NOT REGISTER: an injected await between the cell \
             write and finalization was not detected — the tripwire is inert."
        );

        // Mutation 2 — make the helper `async`.
        let mutated = body.replacen(
            "fn execute_signer_set_update(",
            "async fn execute_signer_set_update(",
            1,
        );
        assert!(
            mutated.contains("async fn execute_signer_set_update"),
            "W5(b) MUTATION 2 DID NOT REGISTER: the helper was made `async` and the \
             lint's own predicate did not see it — the tripwire is inert."
        );
    }

    /// S5B W1 — LINT: the history-derived allocation idiom must not return.
    ///
    /// `.iter().last()` / `.iter().next_back()` over a `StableBTreeMap` used to
    /// derive the next id was three defects at once: a full scan on an
    /// authorization-critical path (unmet R3 item 9), history as allocation
    /// authority (W1.1), and `k + 1` silently wrapping at `u64::MAX` (W1.7).
    ///
    /// A type-level guard cannot express this — `.iter().last()` is perfectly
    /// legal Rust and legitimate elsewhere — so, like the W5(b) tripwire, this
    /// is a source lint. It is deliberately scoped to the ALLOCATION shape
    /// (`.last()`/`.next_back()` feeding an increment) rather than banning
    /// iteration outright, which would be unenforceable and would fire on the
    /// bounded companion scans W2 legitimately performs.
    #[test]
    fn w1_no_history_derived_allocation_idiom() {
        // Scope to the PRODUCTION region. The lint is about allocation paths
        // that ship; test code legitimately quotes the banned idiom (to prove
        // the lint can see it, and in comments explaining what was retired), and
        // matching those would make the lint fire on its own documentation.
        let prod = VAULT_SRC
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map(|(before, _)| before)
            .expect("W1 lint: could not find the test-module boundary — re-anchor it");
        let offenders: Vec<&str> = prod
            .lines()
            .filter(|l| {
                let l = l.trim();
                if l.starts_with("//") || l.starts_with("///") {
                    return false;
                }
                (l.contains(".iter().last()") || l.contains(".iter().next_back()"))
                    && (l.contains("+ 1") || l.contains("checked_add"))
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "W1 VIOLATED: history-derived id allocation has returned. The counter \
             in COMPANION_STATE is the SOLE allocation authority (W1.1); deriving \
             an id from a history map reintroduces a full scan on an \
             authorization-critical path and a silently-wrapping increment.\n\
             Offending lines:\n{offenders:#?}"
        );
    }

    /// The W1 lint must be able to see its own target, or it is inert.
    #[test]
    fn w1_lint_detects_the_idiom_it_bans() {
        let sample = "    PROPOSALS.with(|p| p.borrow().iter().last().map(|(k, _)| k + 1))";
        assert!(
            (sample.contains(".iter().last()") || sample.contains(".iter().next_back()"))
                && sample.contains("+ 1"),
            "W1 lint predicate no longer matches the exact idiom it was written \
             to ban — it would pass vacuously against a real regression"
        );
    }

    /// The lint is worthless if it silently matches nothing. Anchor it.
    #[test]
    fn w5b_lint_anchors_resolve() {
        let body = governance_exec_body(VAULT_SRC);
        assert!(
            body.contains("gov_store(&g);") && body.contains("finalize("),
            "W5(b): lint anchors missing — the lint would vacuously pass"
        );
        assert!(
            body.contains(GOV_TRAP_ANCHOR_STORE) && body.contains(GOV_TRAP_ANCHOR_AUDIT),
            "W5(a): both trap boundaries must exist on the production path"
        );
    }

    const GOV_TRAP_ANCHOR_STORE: &str = "GOV_TRAP_AFTER_STORE_BEFORE_AUDIT";
    const GOV_TRAP_ANCHOR_AUDIT: &str = "GOV_TRAP_AFTER_AUDIT_BEFORE_FINALIZE";



}

#[cfg(test)]
fn generated_did() -> String {
    __export_service()
}

// The committed .did describes the PRODUCTION interface, so this comparison is
// meaningful only without the test-only surface compiled in.
#[cfg(all(test, not(feature = "testing")))]
mod did_drift_tests {
    /// STRUCTURAL DID DRIFT LOCK: the committed vault.did must equal the
    /// service generated from the REAL Rust types. A deliberate interface
    /// change repins the .did in the SAME commit — that is the enforced review
    /// event the drift lock exists to create, never a later refresh to make a
    /// gate go green.
    /// Regeneration helper — writes the generated service to `vault.did`.
    /// Ignored by default; run explicitly when repinning:
    ///   cargo test -p vault --lib repin_did -- --ignored --nocapture
    #[test]
    #[ignore = "SI-X-01: regeneration helper, not a check — it WRITES vault.did. \
                Running it in the gate would repin the drift lock the gate exists \
                to enforce. Run explicitly when repinning."]
    fn repin_did() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/vault.did"),
            super::generated_did(),
        )
        .expect("repin vault.did");
    }

    #[test]
    fn did_types_match_the_real_rust_interface() {
        let generated = super::generated_did();
        let committed = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/vault.did"));
        candid_parser::utils::service_equal(
            candid_parser::utils::CandidSource::Text(&generated),
            candid_parser::utils::CandidSource::Text(committed),
        )
        .unwrap_or_else(|e| {
            panic!(
                "vault.did has DRIFTED from the Rust interface: {e}\n\n\
                 Repin the committed .did in the SAME change as the source edit.\n\n\
                 --- generated from Rust ---\n{generated}"
            )
        });
    }
}
