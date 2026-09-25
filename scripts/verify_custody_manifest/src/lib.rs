// =============================================================================
// STSH — custody manifest coverage gate + encoded-message size invariant (L0)
// =============================================================================
//
// Two blocking build-time gates from CUSTODY_VAULT_INTERFACE_FREEZE_V6:
//
// §13.2a COVERAGE CONTRACT (replaces the withdrawn "all derivations agree"):
//   1. every candidate in the union D1∪D2∪D3∪D4∪D5 appears EXACTLY ONCE in
//      deployment/mainnet/custody_manifest.toml with exactly one disposition
//      (BornUnderVault / SetControllerAtCutover / OutOfScope{reason});
//   2. conflicting facts about the same principal FAIL as `FactConflict` —
//      but ONLY within the same semantic field (`observed_current` vs
//      `expected`) and the same gate epoch (RR3-3). Facts from different
//      epochs are never compared.
//   3. same field, same epoch, but differently-timestamped snapshots that
//      disagree (a legitimate controller transition between two snapshots)
//      FAIL as typed `StaleEvidence` — a distinct failure mode, NEVER a pass,
//      never a FactConflict (round-4 R4-H1);
//   4. absence from a source fails ONLY where that source is declared
//      complete for its universe (D2 is not complete — proven by s3tyu);
//   5. D5 receipts must be bijective with Vault-created production entries
//      (vacuously true until receipts exist — an empty pending source is
//      never silently treated as a populated one);
//   6. every manifest entry must be backed by at least one source — the
//      manifest is DERIVED, never authored (freeze §13.2).
//
// §8 SIZE INVARIANT: asserts on COMPLETE encoded Candid messages against the
// smallest applicable platform limit (2 MiB ingress / cross-net
// inter-canister) with a stated safety margin. Exceeding is a gate FAILURE
// forcing a governed artifact-staging redesign — never a chunk-store route
// around; inline-only is a spec invariant.
// =============================================================================

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// Re-export so the gate script and tests read the same constants the
// canisters' error types carry.
pub use stsh_custody_types::{GATE_SIZE_BOUND_BYTES, PLATFORM_MESSAGE_LIMIT_BYTES};

/// §P.2 — the authenticated D5 exporter (ceremony verification root).
pub mod export;

/// §Q — the exporter's finalize+assemble phase (SSA §4C cure).
pub mod finalize;

// ── Manifest model ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub gate_epoch: String,
    pub sources: Sources,
    /// §P.1: the bootstrap ring declaration. REQUIRED — a manifest without it
    /// cannot state the 2+9 partition at all, and a partition that cannot be
    /// stated cannot be checked. Absence is a parse error, never a default.
    pub bootstrap_ring: BootstrapRing,
    #[serde(default)]
    pub facts: Vec<Fact>,
    #[serde(default, rename = "canister")]
    pub canisters: Vec<Entry>,
    #[serde(default, rename = "authority_field")]
    pub authority_fields: Vec<AuthorityField>,
    /// R-3b S1: the deploy-posture declaration. REQUIRED — the
    /// `--deploy-posture` gate stage asserts the DECLARED posture rather than
    /// tolerating an unbounded set of failures, so a manifest that declares
    /// nothing cannot be checked at all.
    pub deploy_gate: DeployGate,
}

/// R-3b S1: what the deploy-time check set is EXPECTED to report right now.
///
/// `posture = "pre-ceremony"` means the listed obligations are legitimately
/// pending; the gate passes iff the observed key set equals `expected_pending`
/// EXACTLY. `posture = "launch"` means zero: the list must be empty (refused at
/// load otherwise) and the gate passes iff nothing is observed.
#[derive(Debug, Deserialize, Clone)]
pub struct DeployGate {
    pub posture: String,
    #[serde(default)]
    pub expected_pending: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Sources {
    pub d1: FileSource,
    pub d2: FileSource,
    pub d3: ListSource,
    pub d4: ListSource,
    pub d5: ReceiptSource,
}

#[derive(Debug, Deserialize)]
pub struct FileSource {
    #[serde(default)]
    pub declared_complete_for: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListSource {
    /// "populated" or "pending". A pending source contributes NO candidates
    /// and its absence never fails coverage — but a pending source carrying
    /// candidates is a contradiction and a hard error (never silently
    /// treating "incomplete" as "empty", freeze §13.2 RR-2).
    pub status: String,
    #[serde(default)]
    pub declared_complete_for: Vec<String>,
    #[serde(default)]
    pub candidates: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptSource {
    pub status: String,
    #[serde(default)]
    pub declared_complete_for: Vec<String>,
    #[serde(default)]
    pub receipts: Vec<Receipt>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Receipt {
    pub principal: String,
    /// Predeclared manifest purpose (freeze §13.3).
    #[serde(default)]
    pub manifest_purpose: String,
    /// §P.1: the receipt's Vault-side custody status, mirroring the Vault's
    /// `CreationReceiptStatus` (canisters/vault/src/lib.rs) — `bound` or
    /// `orphaned_purpose_conflict`. Defaulted EMPTY on purpose: an empty
    /// status on a present receipt is a typed violation, so a transcribed
    /// receipt that omits the field fails closed rather than inheriting
    /// `bound` by default.
    #[serde(default)]
    pub status: String,
    /// The governing proposal id (D5 provenance). Absent is a violation once
    /// receipts exist.
    #[serde(default)]
    pub proposal_id: Option<u64>,
    /// Vault-side creation timestamp (D5 provenance).
    #[serde(default)]
    pub created_at_ns: Option<u64>,
}

/// §P.1 receipt statuses — the exact mirror of the Vault's
/// `CreationReceiptStatus` variants, snake-cased for TOML.
pub const RECEIPT_STATUS_BOUND: &str = "bound";
/// See [`RECEIPT_STATUS_BOUND`]. Present for custody visibility; NEVER
/// satisfies a governed target's binding requirement.
pub const RECEIPT_STATUS_ORPHANED: &str = "orphaned_purpose_conflict";

/// §P.1: the bootstrap-ring declaration.
///
/// WHERE RING EVIDENCE LIVES — the ruled choice is a **separately hashed
/// ceremony input**, not a manifest field, and this section carries only the
/// fail-closed pointer to it.
///
/// WHY. The manifest's founding invariant is DERIVED, NEVER AUTHORED: every
/// entry exists because a candidate-producing derivation (D1–D5) produced it.
/// The ring pair is precisely the pair that NO derivation can produce — the
/// Vault cannot issue a D5 receipt for itself or for the Upgrader, because
/// neither was created by the Vault. Pasting the ring's ceremony observations
/// into this file would therefore make the manifest author the one class of
/// fact it is structurally forbidden to author, and would do it in the file
/// whose whole job is to reject authored entries. The evidence stays a
/// ceremony artifact with its own hash; the manifest records only that the
/// artifact is required, where it lives, and what it must hash to.
///
/// FAIL-CLOSED. `status = "pending"` means the ceremony has not run: ring
/// entries must carry NO principal, and any receipt naming a ring role is a
/// typed violation. `status = "populated"` means the pointer must resolve —
/// the file must exist and its sha256 must equal `evidence_sha256`, else a
/// typed `RingEvidenceUnavailable`. A missing, unreadable, or unpinned
/// artifact is never "no evidence, therefore no finding": it is a failure.
#[derive(Debug, Deserialize)]
pub struct BootstrapRing {
    /// "pending" or "populated" — same strict enum discipline as D3/D4/D5.
    pub status: String,
    /// Repo-relative path to the separately hashed ceremony input.
    pub evidence_path: String,
    /// The ceremony input's pinned sha256. Must be non-empty and must match
    /// the file's bytes whenever `status = "populated"`.
    #[serde(default)]
    pub evidence_sha256: String,
    /// The ring roles this manifest claims, in canonical order. Must equal
    /// [`BOOTSTRAP_RING_ROLES`] exactly.
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Fact {
    pub principal: String,
    pub field: String,
    /// Semantic field: "observed_current" or "expected". Comparison happens
    /// only WITHIN one semantic field (RR3-3).
    pub semantic: String,
    #[serde(default)]
    pub value: Vec<String>,
    pub source: String,
    #[serde(default)]
    pub network: String,
    pub observed_at: String,
    pub collection_run: String,
    pub epoch: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// §P.1: the closed ring itself — Vault and Upgrader. Born at bootstrap,
    /// NOT created by the Vault, therefore never carrying a D5 receipt.
    /// Before §P.1 these two rode `BornUnderVault`, which asserted a
    /// provenance that cannot exist and made the D5 bijection unstatable.
    BootstrapRing,
    BornUnderVault,
    SetControllerAtCutover,
    OutOfScope,
}

/// The only manifest schema this gate reads. §P.1 raised it from 1 to 2.
pub const MANIFEST_SCHEMA_VERSION: u32 = 2;

/// §P.1: the two bootstrap-ring roles, in canonical order.
pub const BOOTSTRAP_RING_ROLES: [&str; 2] = ["vault", "upgrader"];

/// §P.1: the exact nine governed roles the Vault creates. MIRROR of
/// `BORN_UNDER_VAULT_ROLES` in canisters/vault/src/lib.rs — the vault crate
/// cannot be depended on here (that would move the workspace `Cargo.lock`,
/// a production build input, and disarm the release tripwire), so the list is
/// mirrored and locked against source drift by
/// [`vault_born_under_vault_roles`] instead.
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

#[derive(Debug, Deserialize, Clone)]
pub struct Entry {
    /// D1 identity (dfx.json canister name).
    #[serde(default)]
    pub dfx_name: Option<String>,
    /// D2 identity (canister_ids.json name) — matched through a SEPARATE
    /// field because the same string in dfx.json and canister_ids.json need
    /// not denote the same deployment (the old pool proves it).
    #[serde(default)]
    pub ids_name: Option<String>,
    /// D3/D4/D5 identity (and the deployment's actual principal).
    #[serde(default)]
    pub principal: Option<String>,
    pub disposition: Disposition,
    /// §P.1: for `bootstrap_ring` entries, the ring role — exactly one of
    /// [`BOOTSTRAP_RING_ROLES`]. Required there, forbidden elsewhere.
    #[serde(default)]
    pub ring_role: Option<String>,
    #[serde(default)]
    pub out_of_scope_reason: Option<String>,
    #[serde(default)]
    pub domain_bound: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthorityField {
    pub canister: String,
    pub field: String,
    pub storage: String,
    pub writers: Vec<String>,
    pub launch_value: String,
    pub read_back: String,
}

// ── Typed violations ─────────────────────────────────────────────────────────

/// R-3b: which launch-evidence obligation a `LaunchEvidenceIncomplete` names.
///
/// This is TYPED key data, carried on the violation itself. `Violation::key()`
/// reads it directly — it never re-parses `detail`, so a reworded message can
/// never silently change an obligation's identity, and swapping WHICH
/// obligation is pending (same kind, same count) is a detected set difference
/// rather than an invisible substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchObligation {
    /// The manifest declares no born-under-Vault targets at all.
    NoTargets,
    /// Born-under-Vault targets are declared but D5 carries zero receipts.
    D5Receipts,
    /// One declared target principal has no D5 creation receipt.
    Unreceipted(String),
}

/// Every violation is TYPED: StaleEvidence is a distinct failure mode from
/// FactConflict and is NEVER a pass (freeze §13.2a, R4-H1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// Union candidate with NO manifest disposition (negative control).
    MissingDisposition { candidate: String },
    /// Union candidate matched by MORE THAN ONE manifest entry.
    DuplicateDisposition { candidate: String },
    /// Manifest entry backed by NO source — authored, not derived.
    UnderivedEntry { entry: String },
    /// OutOfScope without a reason (freeze §13.4: OutOfScope{reason}).
    MissingOutOfScopeReason { entry: String },
    /// Entry/dfx_name/canister_ids name-principal binding disagreement.
    PrincipalBindingConflict { detail: String },
    /// Same principal, same field, same semantic, same epoch, same
    /// collection run — values disagree. Unexplained conflict.
    FactConflict { detail: String },
    /// Same principal, same field, same semantic, same epoch, DIFFERENT
    /// observation times — values disagree. A legitimate transition between
    /// snapshots; still a FAILURE, typed distinctly.
    StaleEvidence { detail: String },
    /// A source declared complete for a universe is missing a member of
    /// that universe (checked only while the source is populated).
    DeclaredCompleteAbsence { detail: String },
    /// D5 receipt left unbound, duplicated, or mismatched (bijectivity).
    ReceiptViolation { detail: String },
    /// Pending source carrying candidates — a contradiction.
    PendingSourceWithCandidates { source: String },
    /// Axis-2 field missing writers / launch value / read-back.
    AuthorityFieldIncomplete { canister: String, field: String, detail: String },
    /// §8: a complete encoded message exceeds the gate bound.
    SizeViolation { label: String, encoded_bytes: u64, bound_bytes: u64 },
    /// §8: a required payload artifact (Wasm, init-args artifact) is missing
    /// or unparseable. NEVER a zero-arg measurement, never PENDING.
    MissingPayloadArtifact { detail: String },
    /// Axis-2 rows do not exactly equal the frozen set of 20 authority-field
    /// identities (missing / duplicate / unknown).
    AuthoritySetMismatch { detail: String },
    /// Evidence metadata malformed: bad semantic, unknown source, empty
    /// network/observed_at/collection_run, unknown source status.
    InvalidEvidence { detail: String },
    /// A fact's epoch does not equal the manifest gate_epoch — epoch-dodging
    /// a conflict is a FAILURE, never a comparison escape.
    EpochMismatch { detail: String },

    // ── §P.1 partition violations (each with a committed negative test) ──────
    /// A declared bootstrap-ring role has no manifest entry.
    RingMemberMissing { role: String },
    /// A bootstrap-ring role is claimed by more than one manifest entry, or
    /// the ring section lists it twice.
    RingMemberDuplicate { role: String },
    /// A D5 receipt names a bootstrap-ring role/principal — i.e. the ring is
    /// presented as Vault-created. The Vault cannot create the Vault or the
    /// Upgrader; such a receipt is forged or misfiled, never provenance.
    RingReceiptPresentedAsVaultCreated { detail: String },
    /// A governed (born-under-vault) target carries no `Bound` D5 receipt
    /// while D5 is populated. An `orphaned_purpose_conflict` receipt does NOT
    /// satisfy this: orphans are discoverable, not governed.
    GovernedTargetUnbound { detail: String },
    /// A D5 receipt binds no manifest entry at all.
    OrphanReceipt { detail: String },
    /// A receipt's purpose and the entry it binds disagree, or the purpose is
    /// not one of the nine one-shot allowlist roles.
    ReceiptPurposeMismatch { detail: String },
    /// A receipt beyond the governed set: a second receipt for a role that is
    /// already bound, or a `Bound` receipt for a role outside the allowlist.
    ExtraReceipt { detail: String },
    /// The 2+9 partition cardinality drifted: not exactly two ring entries,
    /// not exactly nine governed entries, or the governed role set is not
    /// exactly the allowlist.
    PartitionCardinalityDrift { detail: String },
    /// The separately hashed bootstrap-ring ceremony input is missing,
    /// unreadable, unpinned, or does not match its pinned sha256. Fail-closed:
    /// absent evidence is a failure, never an empty pass.
    RingEvidenceUnavailable { detail: String },
    /// The mirrored [`BORN_UNDER_VAULT_ROLES`] no longer equals the Vault
    /// source's allowlist. The checker's nine-role universe is a mirror, and a
    /// silently drifted mirror would validate the wrong partition.
    RoleAllowlistDrift { detail: String },
    /// A pinned DID fixture no longer equals the COMMITTED target DID
    /// (`git show HEAD:<path>`) — a lane changed a target interface without
    /// deliberately repinning the fixture. Deterministic on the clean tip;
    /// immune to dirty working-tree DID files (SSA L0 round-4 defect 2).
    DidFixtureDrift { detail: String },
    /// The cutover binding broke: Vault REQUIRED_CUTOVER constants ↔ manifest
    /// set_controller_at_cutover rows ↔ the source-derived init fixture.
    /// Proves source↔manifest equality + fixture-construction consistency
    /// only — NOT the real deployment payload (that is the deploy-time
    /// `PendingDeploymentArtifact` gate, INT-02).
    CutoverBindingMismatch { detail: String },
    /// The independent deployment init artifact (deployment/mainnet/
    /// vault_init.did) does not exist yet. DEPLOY-TIME class: the build gate
    /// stays green without it; the deploy gate cannot pass until L4 produces
    /// the artifact (modeled on the genesis _init.did artifacts).
    PendingDeploymentArtifact { path: String, detail: String },
    /// L4-01 (SSA HOLD): the vault init payload's AUTHORITY-CRITICAL fields
    /// (signers / threshold / upgrader) are invalid or do not match the pinned
    /// deployment authority record. A fail-CLOSED deploy gate: a placeholder,
    /// anonymous, management-canister, or sentinel authority — or any drift from
    /// the independently-pinned record — blocks deployment. A warning inside the
    /// artifact is NOT a control; this is.
    AuthorityBindingViolation { detail: String },
    /// R2.3 (CUST-SSA-002, Critical): the Upgrader RECOVERY ROSTER does not
    /// byte-match the pinned record across every machine-verifiable surface.
    /// Distinct from AuthorityBindingViolation, which covers the Vault's own
    /// signer/threshold/upgrader quorum: this variant covers WHO MAY RECOVER.
    /// Fail-closed on absence — `validate_bootstrap_quorum` checks only
    /// structure, so it accepts any structurally valid attacker-selected
    /// roster, and an unverified roster is exactly the Critical.
    RecoveryRosterViolation { detail: String },
    /// R5.3: the release identity is not bound — no committed release record,
    /// or a built artifact whose hash does not equal the pinned hash. Hashes
    /// were reproducible per exact package-set command but DIFFERED across
    /// package selections, so the canonical build invocation is part of release
    /// identity, not merely the Wasm bytes.
    ReleaseIdentityUnbound { detail: String },
    /// B-6 / O-10: a `[wallet_bundle*]` table in the release record is
    /// structurally incomplete, internally inconsistent, or disagrees with its
    /// twin. The two bundle tables pin the ONLY artifact users actually load —
    /// and, before this check existed, the record carried its own
    /// uncovered-ness as a comment ("`verify_custody_manifest` has NO
    /// wallet_bundle coverage") across multiple lanes.
    ///
    /// Reported as its OWN kind rather than folded into
    /// [`Violation::ReleaseIdentityUnbound`] because the wallet bundle is a
    /// different artifact class from the pinned Wasms: it is measured by a
    /// directory manifest, not by a single file hash, it is installed at two
    /// distinct ceremony phases from two distinct tables, and it is NOT part
    /// of the `[deploy_gate].expected_pending` universe. A distinct kind keeps
    /// the two verdicts legible in a log instead of merging them.
    WalletBundleUnbound { detail: String },
    /// S11-5, arming condition superseded by S11-6: the record is well-formed
    /// and authenticated, but a commit since `build.asserts_identity_at` has
    /// touched a production build input ([`BUILD_INPUT_PATHS`]), so the
    /// recorded bytes are no longer claimed to match a build of this tree.
    /// Byte-equality is therefore NOT asserted here — and this is reported as a
    /// TYPED OUTCOME, never as a pass and never as a skip.
    ///
    /// WHY THIS EXISTS. `check_release_identity` previously compared pinned
    /// hashes against built artifacts at ANY head. That binds release identity
    /// to every future head of a branch: any legitimate source change to vault
    /// or upgrader — which correctives are, by SSA direction — makes the check
    /// fail, so the only ways to stay green were to re-pin the record at every
    /// corrective (laundering unreviewed bytes into a "release" record) or to
    /// run a standing-red gate (which trains readers past the VERDICT line).
    /// Both were rejected. The record now says WHERE its claim holds, and the
    /// check binds there with full force and reports a distinct
    /// not-asserting outcome everywhere else.
    ///
    /// THIS IS NOT A WEAKENING. It is strictly more honest than the previous
    /// pass/fail pair: a non-asserting head can no longer produce
    /// byte-equality SUCCESS, which is the outcome that would actually be
    /// dangerous. At an ARMED head every prior assertion still bites —
    /// mutated hash fails, absent artifact fails closed.
    ///
    /// ARMING IS REALIZABLE ON A CLEAN COMMITTED TREE (S11-6). The predecessor
    /// condition, `HEAD == asserts_identity_at`, could not be satisfied by any
    /// committed record — a commit cannot contain its own SHA — so it armed
    /// only on a dirty tree. Quiescence over [`BUILD_INPUT_PATHS`] replaces it:
    /// a record-only or docs-only child of the binding commit arms.
    ReleaseIdentityNotAsserted { package: String, detail: String },
    /// R5.3: deploy-time launch evidence is incomplete — born-under-Vault
    /// targets declared with no creation receipts, or a declared target with no
    /// receipt. The gate must not report GREEN into an irreversible operational
    /// window; removing the bootstrap controller before this evidence exists is
    /// the failure this variant prevents.
    LaunchEvidenceIncomplete { obligation: LaunchObligation, detail: String },
    /// ROT-LEDGER: the identity-rotation ledger in
    /// [`VAULT_AUTHORITY_RECORD`] is missing, unreadable, internally
    /// inconsistent, or breaks its own chain.
    ///
    /// DELIBERATELY NOT DECLARABLE. The ONE legitimately pending pre-rotation
    /// state is a well-formed ledger saying so, which is reported as a
    /// [`Violation::PendingDeploymentArtifact`] and may be declared in
    /// `[deploy_gate].expected_pending`. Everything else this variant covers is
    /// a record that cannot be trusted to mean what it says, and a record that
    /// cannot be trusted must be FIXED, never allowlisted. Because the kind is
    /// absent from [`DECLARABLE_KINDS`] it is refused at LOAD if anyone ever
    /// tries, so it can only ever surface as a SURPLUS key in
    /// `--deploy-posture` — which is exactly why it cannot be silenced.
    ///
    /// PROVENANCE LIMITATION. Every rotation row records an operator-supplied
    /// read-back. This check verifies that the named evidence file exists and
    /// hashes to the recorded sha256, that rows chain on ordered principal
    /// BYTES, and that every declared field is internally consistent and
    /// temporally sane. It CANNOT prove those bytes came from a live query
    /// against the real canister on mainnet. A checked attestation is not a
    /// cryptographic proof of provenance and must never be read as one — the
    /// same limitation `[recovery]`'s surface 4 states for the roster.
    RotationLedgerInconsistent {
        /// TYPED identity of the defect. Fixtures assert on this, never on a
        /// substring of `detail`.
        defect: RotationDefect,
        /// Which part of the ledger: `"[rotation]"`, `"[rotation.bootstrap]"`,
        /// or `"upgrader#<seq>"` / `"vault#<seq>"` for a row.
        row: String,
        detail: String,
    },
}

/// ROT-LEDGER: the TYPED reason a rotation ledger is refused.
///
/// One variant per defect condition rather than one long `detail` string, so a
/// negative fixture can assert the violation's IDENTITY (genesis lockstep rule
/// 4). Nineteen conditions funnelling into one kind would otherwise let a
/// fixture trip a different condition than the one under test and still be
/// scored as a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationDefect {
    /// `[rotation]` absent, or present but not decodable into the schema.
    MalformedTable,
    /// `schema_version` is not [`ROTATION_LEDGER_SCHEMA_VERSION`].
    UnknownSchemaVersion,
    /// `state` is not one of the two accepted words.
    UnknownState,
    /// `state` and the plane arrays contradict each other.
    StateArrayInconsistent,
    /// `[rotation.bootstrap]` does not equal the live install-time pins while
    /// `state = "not-yet-performed"` (the birth check).
    BootstrapMismatch,
    /// A principal string does not parse.
    BadPrincipal,
    /// A required row field is absent or empty.
    RequiredFieldEmpty,
    /// A row carries a placeholder-shaped value or a non-`EXECUTED` status.
    PlaceholderRow,
    /// `sequence` is not dense and strictly increasing from 1.
    SequenceBroken,
    /// A member set has a duplicate, the wrong cardinality, a threshold that
    /// is not 2, or (F-5) an `old_members` that ordered-byte-equals its own
    /// `new_members` — a row that changes nothing is not a rotation.
    SetShapeInvalid,
    /// F-3: `canister` is not the principal the record's OWN pins name for
    /// this plane (`upgrader` for the Upgrader plane, `[recovery].vault` for
    /// the Vault plane), or those pins could not be loaded at all.
    CanisterMismatch,
    /// F-4: two rows of one plane cite the same `proposal_id`. One on-chain
    /// proposal executed one rotation; two rows claiming it means one of them
    /// is not the rotation it says it is.
    ProposalIdNotUnique,
    /// A member set names a [`FORBIDDEN_AUTHORITY_PRINCIPALS`] entry.
    ForbiddenPrincipal,
    /// `old_*` does not ordered-byte-equal the predecessor's `new_*` (or
    /// `[rotation.bootstrap]` for row 1). A REORDER is a chain break.
    ChainBreak,
    /// A Vault row does not strictly advance the governance epoch.
    EpochNotAdvanced,
    /// A Vault row names no EXECUTED Upgrader row, or one observed later.
    PlaneOrdering,
    /// `approvers` is not exactly two distinct members of `old_members`.
    ApproversInvalid,
    /// `read_by` is not a member of `old_members`.
    ReaderNotInOldSet,
    /// `observed_at_utc` does not agree with `observed_at_ns`.
    TimestampDisagrees,
    /// `observed_at_ns` is later than the checked HEAD's commit time.
    TimestampInFuture,
    /// The HEAD commit time could not be read. Fail-closed, never a skip.
    HeadTimeUnavailable,
    /// The named read-back evidence file is missing, or its bytes do not hash
    /// to `readback_output_sha256`.
    EvidenceUnavailable,
}

impl Violation {
    /// R-3b: the STABLE, per-obligation identity of this violation.
    ///
    /// TOTAL — every variant has its own arm; adding a variant without an arm
    /// is a compile error, not a silent fallback. For the four DECLARABLE
    /// kinds the key is built from the TYPED fields only; `detail` is never
    /// read, and no `Debug`-derived discriminant text is used anywhere.
    pub fn key(&self) -> String {
        match self {
            // ── the four declarable kinds — typed fields only ──────────────
            Violation::ReleaseIdentityNotAsserted { package, .. } => {
                format!("ReleaseIdentityNotAsserted:{package}")
            }
            Violation::LaunchEvidenceIncomplete { obligation, .. } => match obligation {
                LaunchObligation::NoTargets => "LaunchEvidenceIncomplete:no-targets".to_string(),
                LaunchObligation::D5Receipts => "LaunchEvidenceIncomplete:d5-receipts".to_string(),
                LaunchObligation::Unreceipted(p) => {
                    format!("LaunchEvidenceIncomplete:unreceipted:{p}")
                }
            },
            Violation::PendingDeploymentArtifact { path, .. } => {
                format!("PendingDeploymentArtifact:{path}")
            }
            Violation::AuthorityFieldIncomplete { canister, field, .. } => {
                format!("AuthorityFieldIncomplete:{canister}.{field}")
            }
            // ── every other kind: its own arm, bare kind name literal ───────
            Violation::MissingDisposition { .. } => "MissingDisposition".to_string(),
            Violation::DuplicateDisposition { .. } => "DuplicateDisposition".to_string(),
            Violation::UnderivedEntry { .. } => "UnderivedEntry".to_string(),
            Violation::MissingOutOfScopeReason { .. } => "MissingOutOfScopeReason".to_string(),
            Violation::PrincipalBindingConflict { .. } => "PrincipalBindingConflict".to_string(),
            Violation::FactConflict { .. } => "FactConflict".to_string(),
            Violation::StaleEvidence { .. } => "StaleEvidence".to_string(),
            Violation::DeclaredCompleteAbsence { .. } => "DeclaredCompleteAbsence".to_string(),
            Violation::ReceiptViolation { .. } => "ReceiptViolation".to_string(),
            Violation::PendingSourceWithCandidates { .. } => {
                "PendingSourceWithCandidates".to_string()
            }
            Violation::SizeViolation { .. } => "SizeViolation".to_string(),
            Violation::MissingPayloadArtifact { .. } => "MissingPayloadArtifact".to_string(),
            Violation::AuthoritySetMismatch { .. } => "AuthoritySetMismatch".to_string(),
            Violation::InvalidEvidence { .. } => "InvalidEvidence".to_string(),
            Violation::EpochMismatch { .. } => "EpochMismatch".to_string(),
            Violation::RingMemberMissing { .. } => "RingMemberMissing".to_string(),
            Violation::RingMemberDuplicate { .. } => "RingMemberDuplicate".to_string(),
            Violation::RingReceiptPresentedAsVaultCreated { .. } => {
                "RingReceiptPresentedAsVaultCreated".to_string()
            }
            Violation::GovernedTargetUnbound { .. } => "GovernedTargetUnbound".to_string(),
            Violation::OrphanReceipt { .. } => "OrphanReceipt".to_string(),
            Violation::ReceiptPurposeMismatch { .. } => "ReceiptPurposeMismatch".to_string(),
            Violation::ExtraReceipt { .. } => "ExtraReceipt".to_string(),
            Violation::PartitionCardinalityDrift { .. } => "PartitionCardinalityDrift".to_string(),
            Violation::RingEvidenceUnavailable { .. } => "RingEvidenceUnavailable".to_string(),
            Violation::RoleAllowlistDrift { .. } => "RoleAllowlistDrift".to_string(),
            Violation::DidFixtureDrift { .. } => "DidFixtureDrift".to_string(),
            Violation::CutoverBindingMismatch { .. } => "CutoverBindingMismatch".to_string(),
            Violation::AuthorityBindingViolation { .. } => "AuthorityBindingViolation".to_string(),
            Violation::RecoveryRosterViolation { .. } => "RecoveryRosterViolation".to_string(),
            Violation::ReleaseIdentityUnbound { .. } => "ReleaseIdentityUnbound".to_string(),
            Violation::WalletBundleUnbound { .. } => "WalletBundleUnbound".to_string(),
            // Bare kind name, like every other NON-declarable kind. The typed
            // `defect`/`row` fields carry the identity fixtures assert on; the
            // key only has to be stable and un-declarable, and collapsing
            // several corrupt rows into one surplus key is the correct
            // behaviour for a set comparison whose job is "this is broken".
            Violation::RotationLedgerInconsistent { .. } => {
                "RotationLedgerInconsistent".to_string()
            }
        }
    }
}

/// The four violation kinds a `[deploy_gate]` declaration may name as pending.
/// Any other kind-prefix in `expected_pending` is refused at LOAD, exit 2 —
/// before any check runs (R-3b S1/S2).
pub const DECLARABLE_KINDS: [&str; 4] = [
    "AuthorityFieldIncomplete",
    "PendingDeploymentArtifact",
    "ReleaseIdentityNotAsserted",
    "LaunchEvidenceIncomplete",
];

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::MissingDisposition { candidate } => write!(
                f,
                "MISSING DISPOSITION: union candidate {candidate} has no manifest entry — \
                 every candidate in D1∪D2∪D3∪D4∪D5 must appear exactly once (freeze §13.2a)"
            ),
            Violation::DuplicateDisposition { candidate } => write!(
                f,
                "DUPLICATE DISPOSITION: union candidate {candidate} matches more than one \
                 manifest entry"
            ),
            Violation::UnderivedEntry { entry } => write!(
                f,
                "UNDERIVED ENTRY: manifest entry {entry} is backed by no candidate source — \
                 the manifest is derived, never authored (freeze §13.2)"
            ),
            Violation::MissingOutOfScopeReason { entry } => write!(
                f,
                "OUT-OF-SCOPE WITHOUT REASON: manifest entry {entry} is out_of_scope but \
                 carries no out_of_scope_reason (freeze §13.4)"
            ),
            Violation::PrincipalBindingConflict { detail } => {
                write!(f, "PRINCIPAL BINDING CONFLICT: {detail}")
            }
            Violation::FactConflict { detail } => write!(f, "FACT CONFLICT: {detail}"),
            Violation::StaleEvidence { detail } => write!(
                f,
                "STALE EVIDENCE: {detail} — a transition between differently-timestamped \
                 snapshots of the same epoch FAILS as StaleEvidence, never a pass, never a \
                 FactConflict (freeze §13.2a)"
            ),
            Violation::DeclaredCompleteAbsence { detail } => {
                write!(f, "DECLARED-COMPLETE SOURCE ABSENCE: {detail}")
            }
            Violation::ReceiptViolation { detail } => write!(f, "D5 RECEIPT VIOLATION: {detail}"),
            Violation::PendingSourceWithCandidates { source } => write!(
                f,
                "PENDING SOURCE WITH CANDIDATES: {source} is declared `pending` but carries \
                 candidates — a pending source contributes nothing, and `incomplete` is never \
                 silently treated as `empty` (freeze §13.2 RR-2)"
            ),
            Violation::AuthorityFieldIncomplete { detail, .. } => {
                write!(f, "AXIS-2 FIELD INCOMPLETE: {detail}")
            }
            Violation::SizeViolation { label, encoded_bytes, bound_bytes } => write!(
                f,
                "SIZE INVARIANT: {label} encodes to {encoded_bytes} bytes, exceeding the gate \
                 bound {bound_bytes} (platform limit {PLATFORM_MESSAGE_LIMIT_BYTES} with the \
                 stated safety margin). Inline-only is a spec invariant — this is a gate \
                 FAILURE to escalate, never a chunk-store route-around (freeze §8)"
            ),
            Violation::MissingPayloadArtifact { detail } => write!(
                f,
                "MISSING PAYLOAD ARTIFACT: {detail} — a required artifact/args value must be \
                 present and parseable; never a zero-arg measurement, never PENDING (§8)"
            ),
            Violation::AuthoritySetMismatch { detail } => write!(
                f,
                "AXIS-2 SET MISMATCH: {detail} — the authority-field rows must equal the \
                 frozen set of 20 identities exactly (freeze §6)"
            ),
            Violation::InvalidEvidence { detail } => write!(f, "INVALID EVIDENCE: {detail}"),
            Violation::EpochMismatch { detail } => write!(
                f,
                "EPOCH MISMATCH: {detail} — every fact's epoch must equal the manifest \
                 gate_epoch; epoch-dodging a conflict is a FAILURE (freeze §13.2a)"
            ),
            Violation::RingMemberMissing { role } => write!(
                f,
                "RING MEMBER MISSING: bootstrap-ring role `{role}` has no manifest entry — the \
                 ring is a closed pair (§P.1); a ring with a missing member is not a ring"
            ),
            Violation::RingMemberDuplicate { role } => write!(
                f,
                "RING MEMBER DUPLICATE: bootstrap-ring role `{role}` is claimed more than once \
                 — ring membership is one-shot per role (§P.1)"
            ),
            Violation::RingReceiptPresentedAsVaultCreated { detail } => write!(
                f,
                "RING RECEIPT PRESENTED AS VAULT-CREATED: {detail} — the Vault cannot create the \
                 Vault or the Upgrader, so no D5 receipt for a ring member can be genuine \
                 provenance (§P.1)"
            ),
            Violation::GovernedTargetUnbound { detail } => write!(
                f,
                "GOVERNED TARGET UNBOUND: {detail} — every one of the nine governed targets must \
                 carry a `{RECEIPT_STATUS_BOUND}` D5 receipt; an \
                 `{RECEIPT_STATUS_ORPHANED}` receipt is discoverable custody, NOT a binding"
            ),
            Violation::OrphanReceipt { detail } => write!(
                f,
                "ORPHAN RECEIPT: {detail} — a receipt that binds no manifest entry is unbound \
                 provenance (freeze §13.2a: no receipt left unbound)"
            ),
            Violation::ReceiptPurposeMismatch { detail } => write!(
                f,
                "RECEIPT PURPOSE MISMATCH: {detail} — a receipt's purpose must name the same \
                 one-shot allowlist role as the entry it binds (§P.1)"
            ),
            Violation::ExtraReceipt { detail } => write!(
                f,
                "EXTRA RECEIPT: {detail} — the D5 bijection admits exactly one `\
                 {RECEIPT_STATUS_BOUND}` receipt per governed role (§P.1)"
            ),
            Violation::PartitionCardinalityDrift { detail } => write!(
                f,
                "PARTITION CARDINALITY DRIFT: {detail} — the custody partition is exactly 2 \
                 bootstrap-ring entries + 9 governed entries (§P.1)"
            ),
            Violation::RingEvidenceUnavailable { detail } => write!(
                f,
                "RING EVIDENCE UNAVAILABLE: {detail} — bootstrap-ring evidence is a separately \
                 hashed ceremony input; a missing, unreadable, unpinned or hash-mismatched \
                 artifact FAILS CLOSED and is never read as an empty pass (§P.1)"
            ),
            Violation::RoleAllowlistDrift { detail } => write!(
                f,
                "ROLE ALLOWLIST DRIFT: {detail} — the checker mirrors the Vault's \
                 BORN_UNDER_VAULT_ROLES; a drifted mirror would validate the wrong partition, so \
                 the mirror is locked to the source (§P.1)"
            ),
            Violation::DidFixtureDrift { detail } => write!(
                f,
                "DID FIXTURE DRIFT: {detail} — the pinned fixture no longer equals the \
                 committed target DID (git show HEAD). A lane changed a target interface; \
                 repin the fixture deliberately (an enforced review event), never silently."
            ),
            Violation::CutoverBindingMismatch { detail } => write!(
                f,
                "CUTOVER BINDING MISMATCH: {detail} — the Vault's REQUIRED_CUTOVER \
                 constants, the manifest's set_controller_at_cutover rows, and the \
                 source-derived init fixture must agree. (This proves source↔manifest \
                 equality and fixture consistency; the real deployment payload is the \
                 deploy-time artifact gate.)"
            ),
            Violation::PendingDeploymentArtifact { detail, .. } => write!(
                f,
                "PENDING DEPLOYMENT ARTIFACT: {detail} — blocking pre-deployment: the \
                 deploy gate cannot pass until this artifact exists and verifies. Not a \
                 build-time failure."
            ),
            Violation::AuthorityBindingViolation { detail } => write!(
                f,
                "AUTHORITY BINDING VIOLATION: {detail} — the vault init payload's \
                 signers/threshold/upgrader must be real, structurally valid, and equal to \
                 the pinned deployment authority record. Fail-closed: no deployment on \
                 placeholder/anonymous/management/sentinel authorities or any record drift."
            ),
            Violation::RecoveryRosterViolation { detail } => write!(
                f,
                "RECOVERY ROSTER VIOLATION: {detail} — the Upgrader recovery roster must equal \
                 the three ruled Vault signer principals as an EXACT ORDERED vector of \
                 principal bytes, at every surface, with duplicates prohibited. Structural \
                 validity is NOT identity: validate_bootstrap_quorum accepts any structurally \
                 valid attacker-selected roster. Any surface absent or unparseable is a \
                 violation, never a skip."
            ),
            Violation::RotationLedgerInconsistent { defect, row, detail } => write!(
                f,
                "ROTATION LEDGER INCONSISTENT [{defect:?} @ {row}]: {detail} — the identity \
                 rotation ledger is the only in-repo statement of WHO governs the live Vault \
                 and Upgrader after the install-time pins stop describing them. A ledger that \
                 is malformed, off-schema, unchained, or self-contradictory is not a partially \
                 usable record; it is one that cannot be trusted to mean what it says. This \
                 kind is NOT declarable: it must be fixed, never allowlisted."
            ),
            Violation::WalletBundleUnbound { detail } => write!(
                f,
                "WALLET BUNDLE PIN UNBOUND: {detail} — the `[wallet_bundle]` and \
                 `[wallet_bundle_transitional]` tables pin the artifact users actually load, \
                 and each field named there is PART of bundle identity, not metadata about it. \
                 A field that is absent, malformed, internally inconsistent, or in conflict \
                 with its twin table leaves the corresponding install unverified — including \
                 the Phase B.1 install, which happens FIRST."
            ),
            Violation::ReleaseIdentityUnbound { detail } => write!(
                f,
                "RELEASE IDENTITY UNBOUND: {detail} — the canonical build invocation, toolchain, \
                 feature set and resulting Wasm SHA-256s are part of release identity and must be \
                 pinned in a committed record and matched by the built artifacts. Reproducibility \
                 per package-set is not release identity."
            ),
            Violation::ReleaseIdentityNotAsserted { detail, .. } => write!(
                f,
                "RELEASE IDENTITY NOT ASSERTED AT THIS HEAD: {detail} — the record pins bytes \
                 built from `build.asserts_identity_at`, and production build inputs have \
                 changed since, so byte-equality is deliberately NOT claimed here. This is a \
                 typed outcome, never a pass and never a skip: a non-asserting head must not \
                 be able to report release-identity SUCCESS. Rebind the record at the release \
                 commit — set asserts_identity_at to that SHA in a commit touching ONLY the \
                 record/docs, which leaves the range quiescent and re-arms the comparison."
            ),
            Violation::LaunchEvidenceIncomplete { detail, .. } => write!(
                f,
                "LAUNCH EVIDENCE INCOMPLETE: {detail} — the deploy gate must not report GREEN \
                 with missing creation receipts or missing born-under-Vault targets. Removing \
                 the bootstrap controller before this evidence exists opens an irreversible \
                 operational failure window (R5.3)."
            ),
        }
    }
}

// ── Loading ──────────────────────────────────────────────────────────────────

pub fn load_manifest(path: &Path) -> Result<Manifest, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let m: Manifest =
        toml::from_str(&raw).map_err(|e| format!("{} is malformed: {e}", path.display()))?;
    // §P.1 raised the schema to 2 (the 2+9 partition). The gate reads exactly
    // one schema version — a checker that accepts an older schema would accept
    // a manifest with no partition at all and report GREEN over it.
    if m.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "{}: unsupported schema_version {} (expected 2) — refusing to pass on a \
             manifest this gate cannot read.",
            path.display(),
            m.schema_version
        ));
    }
    if m.gate_epoch.trim().is_empty() {
        return Err(format!("{}: gate_epoch must be non-empty", path.display()));
    }
    validate_deploy_gate(path, &m.deploy_gate)?;
    Ok(m)
}

/// R-3b S1/S2: refuse a malformed deploy-posture declaration at LOAD (exit 2),
/// before any check runs.
///
/// Three refusals, each closing a way the declaration could otherwise become
/// meaningless: an unknown posture word; a `launch` posture that still carries
/// an allowlist (launch means ZERO — no allowlist survives the flip); and a key
/// whose kind-prefix is not one of the four DECLARABLE kinds (so `key()`'s
/// bare-kind-name arms for the other 30 kinds can never be declared away). A
/// duplicate key is refused for the same reason: `expected_pending` is compared
/// as a SET, so a duplicate is a declaration whose author believed something the
/// comparison cannot express.
pub fn validate_deploy_gate(path: &Path, dg: &DeployGate) -> Result<(), String> {
    match dg.posture.as_str() {
        "pre-ceremony" | "launch" => {}
        other => {
            return Err(format!(
                "{}: [deploy_gate] posture `{other}` is not recognised — expected \
                 `pre-ceremony` or `launch`.",
                path.display()
            ))
        }
    }
    if dg.posture == "launch" && !dg.expected_pending.is_empty() {
        return Err(format!(
            "{}: [deploy_gate] posture = \"launch\" requires expected_pending = [] — launch \
             posture means ZERO deploy-time violations, and no allowlist survives the flip. \
             Declared: {:?}",
            path.display(),
            dg.expected_pending
        ));
    }
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for k in &dg.expected_pending {
        if !seen.insert(k.as_str()) {
            return Err(format!(
                "{}: [deploy_gate] expected_pending declares `{k}` more than once. The \
                 declaration is compared as a SET; a duplicate cannot mean what its author \
                 intended.",
                path.display()
            ));
        }
        let kind = k.split(':').next().unwrap_or("");
        if !DECLARABLE_KINDS.contains(&kind) {
            return Err(format!(
                "{}: [deploy_gate] expected_pending declares `{k}`, whose kind `{kind}` is not \
                 declarable. Only {:?} may ever be declared pending; every other violation kind \
                 is a hard failure that must be FIXED, not allowlisted.",
                path.display(),
                DECLARABLE_KINDS
            ));
        }
    }
    Ok(())
}

/// R-3b S2: the declared pending key set, as a set.
pub fn declared_pending(dg: &DeployGate) -> std::collections::BTreeSet<String> {
    dg.expected_pending.iter().cloned().collect()
}

/// R-3b S2: project a violation list onto its stable key set.
pub fn observed_keys(violations: &[Violation]) -> std::collections::BTreeSet<String> {
    violations.iter().map(Violation::key).collect()
}

/// D1: launch-enabled dfx.json canister entries (names).
pub fn load_d1(dfx_json: &Path) -> Result<BTreeSet<String>, String> {
    let raw = std::fs::read_to_string(dfx_json)
        .map_err(|e| format!("cannot read {}: {e}", dfx_json.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is malformed JSON: {e}", dfx_json.display()))?;
    let canisters = v
        .get("canisters")
        .and_then(|c| c.as_object())
        .ok_or_else(|| format!("{}: no `canisters` object", dfx_json.display()))?;
    if canisters.is_empty() {
        return Err(format!(
            "{}: empty `canisters` — refusing a vacuous D1 derivation",
            dfx_json.display()
        ));
    }
    Ok(canisters.keys().cloned().collect())
}

/// D2: committed production ID records (name → ic principal).
pub fn load_d2(canister_ids: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw = std::fs::read_to_string(canister_ids)
        .map_err(|e| format!("cannot read {}: {e}", canister_ids.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is malformed JSON: {e}", canister_ids.display()))?;
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{}: expected a top-level object", canister_ids.display()))?;
    let mut out = BTreeMap::new();
    for (name, nets) in obj {
        if let Some(ic) = nets.get("ic").and_then(|p| p.as_str()) {
            out.insert(name.clone(), ic.to_string());
        }
    }
    Ok(out)
}

// ── The coverage gate ────────────────────────────────────────────────────────

/// Run the §13.2a coverage contract. Returns EVERY violation found, typed.
pub fn check_coverage(
    manifest: &Manifest,
    d1: &BTreeSet<String>,
    d2: &BTreeMap<String, String>,
) -> Vec<Violation> {
    let mut errors = Vec::new();

    // ── Evidence hygiene (SSA L0 defect 6 — strict enums, no fail-open) ─────
    for (name, status) in [
        ("D3", &manifest.sources.d3.status),
        ("D4", &manifest.sources.d4.status),
        ("D5", &manifest.sources.d5.status),
    ] {
        if status != "pending" && status != "populated" {
            errors.push(Violation::InvalidEvidence {
                detail: format!(
                    "source {name} has status `{status}` — must be exactly `pending` or \
                     `populated`; anything else is rejected, never treated as populated"
                ),
            });
        }
    }
    const VALID_SEMANTICS: [&str; 2] = ["observed_current", "expected"];
    const VALID_FACT_SOURCES: [&str; 5] = ["D1", "D2", "D3", "D4", "D5"];
    for fact in &manifest.facts {
        if !VALID_SEMANTICS.contains(&fact.semantic.as_str()) {
            errors.push(Violation::InvalidEvidence {
                detail: format!(
                    "fact {}.{} has semantic `{}` — must be observed_current or expected",
                    fact.principal, fact.field, fact.semantic
                ),
            });
        }
        if !VALID_FACT_SOURCES.contains(&fact.source.as_str()) {
            errors.push(Violation::InvalidEvidence {
                detail: format!(
                    "fact {}.{} has source `{}` — must be one of D1–D5",
                    fact.principal, fact.field, fact.source
                ),
            });
        }
        for (what, val) in [
            ("network", &fact.network),
            ("observed_at", &fact.observed_at),
            ("collection_run", &fact.collection_run),
        ] {
            if val.trim().is_empty() {
                errors.push(Violation::InvalidEvidence {
                    detail: format!(
                        "fact {}.{} has empty {what} — every observed fact binds source, \
                         network, observation time and collection run (RR3-3)",
                        fact.principal, fact.field
                    ),
                });
            }
        }
        if fact.epoch != manifest.gate_epoch {
            errors.push(Violation::EpochMismatch {
                detail: format!(
                    "fact {}.{} has epoch `{}`, manifest gate_epoch is `{}`",
                    fact.principal, fact.field, fact.epoch, manifest.gate_epoch
                ),
            });
        }
    }

    // ── Pending/populated hygiene ────────────────────────────────────────────
    for (name, src, candidates) in [
        ("D3", &manifest.sources.d3.status, &manifest.sources.d3.candidates),
        ("D4", &manifest.sources.d4.status, &manifest.sources.d4.candidates),
    ] {
        if src == "pending" && !candidates.is_empty() {
            errors.push(Violation::PendingSourceWithCandidates { source: name.into() });
        }
    }
    if manifest.sources.d5.status == "pending" && !manifest.sources.d5.receipts.is_empty() {
        errors.push(Violation::PendingSourceWithCandidates { source: "D5".into() });
    }

    // ── Union coverage: every candidate exactly once ─────────────────────────
    let match_dfx = |name: &str| -> Vec<&Entry> {
        manifest
            .canisters
            .iter()
            .filter(|e| e.dfx_name.as_deref() == Some(name))
            .collect()
    };
    let match_ids = |name: &str| -> Vec<&Entry> {
        manifest
            .canisters
            .iter()
            .filter(|e| e.ids_name.as_deref() == Some(name))
            .collect()
    };
    let match_principal = |p: &str| -> Vec<&Entry> {
        manifest
            .canisters
            .iter()
            .filter(|e| e.principal.as_deref() == Some(p))
            .collect()
    };

    let mut backed: BTreeSet<usize> = BTreeSet::new();
    let entry_index = |e: &Entry| -> usize {
        manifest.canisters.iter().position(|x| std::ptr::eq(x, e)).unwrap()
    };

    let mut cover = |candidate: String, matches: Vec<&Entry>| {
        match matches.len() {
            0 => errors.push(Violation::MissingDisposition { candidate }),
            1 => {
                backed.insert(entry_index(matches[0]));
            }
            _ => errors.push(Violation::DuplicateDisposition { candidate }),
        }
    };

    for name in d1 {
        cover(format!("D1:{name}"), match_dfx(name));
    }
    for (name, principal) in d2 {
        cover(format!("D2:{name} ({principal})"), match_ids(name));
    }
    if manifest.sources.d3.status != "pending" {
        for p in &manifest.sources.d3.candidates {
            cover(format!("D3:{p}"), match_principal(p));
        }
    }
    if manifest.sources.d4.status != "pending" {
        for p in &manifest.sources.d4.candidates {
            cover(format!("D4:{p}"), match_principal(p));
        }
    }
    if manifest.sources.d5.status != "pending" {
        for r in &manifest.sources.d5.receipts {
            cover(format!("D5:{}", r.principal), match_principal(&r.principal));
        }
    }

    // ── Derived, not authored: every entry backed by ≥1 source ───────────────
    for (i, e) in manifest.canisters.iter().enumerate() {
        if !backed.contains(&i) {
            errors.push(Violation::UnderivedEntry {
                entry: describe_entry(e),
            });
        }
        if e.disposition == Disposition::OutOfScope
            && e.out_of_scope_reason.as_deref().map(str::trim).unwrap_or("").is_empty()
        {
            errors.push(Violation::MissingOutOfScopeReason {
                entry: describe_entry(e),
            });
        }
        // An entry naming a dfx.json canister that D1 does not contain is
        // either drift or an authored binding.
        if let Some(n) = &e.dfx_name {
            if !d1.contains(n) {
                errors.push(Violation::PrincipalBindingConflict {
                    detail: format!(
                        "entry {} has dfx_name `{n}` which is absent from dfx.json",
                        describe_entry(e)
                    ),
                });
            }
        }
        // D2 name→principal binding must agree with the entry's principal.
        if let Some(n) = &e.ids_name {
            if let Some(d2p) = d2.get(n) {
                match &e.principal {
                    Some(p) if p != d2p => errors.push(Violation::PrincipalBindingConflict {
                        detail: format!(
                            "entry {} binds ids_name `{n}` to principal {p}, but \
                             canister_ids.json records {d2p}",
                            describe_entry(e)
                        ),
                    }),
                    None => errors.push(Violation::PrincipalBindingConflict {
                        detail: format!(
                            "entry {} binds ids_name `{n}` but carries no principal; \
                             canister_ids.json records {d2p}",
                            describe_entry(e)
                        ),
                    }),
                    _ => {}
                }
            }
        }
    }

    // No two entries may share one principal.
    let mut by_principal: BTreeMap<&str, &Entry> = BTreeMap::new();
    for e in &manifest.canisters {
        if let Some(p) = e.principal.as_deref() {
            if let Some(prev) = by_principal.insert(p, e) {
                errors.push(Violation::PrincipalBindingConflict {
                    detail: format!(
                        "principal {p} is carried by two manifest entries ({} and {})",
                        describe_entry(prev),
                        describe_entry(e)
                    ),
                });
            }
        }
    }

    // ── Fact comparison (RR3-3 temporal semantics) ───────────────────────────
    // Comparison is ONLY between facts of the same semantic field, the same
    // gate epoch, the same principal and the same field. Different epochs are
    // never compared. Within a comparable group:
    //   values agree                                    → fine
    //   values differ, same collection_run+observed_at  → FactConflict
    //   values differ, different observation times/runs → StaleEvidence (FAIL)
    {
        let mut groups: BTreeMap<(&str, &str, &str, &str), Vec<&Fact>> = BTreeMap::new();
        for fact in &manifest.facts {
            groups
                .entry((
                    fact.principal.as_str(),
                    fact.field.as_str(),
                    fact.semantic.as_str(),
                    fact.epoch.as_str(),
                ))
                .or_default()
                .push(fact);
        }
        for ((principal, field, semantic, epoch), facts) in groups {
            for i in 0..facts.len() {
                for j in (i + 1)..facts.len() {
                    let (a, b) = (facts[i], facts[j]);
                    let mut av = a.value.clone();
                    let mut bv = b.value.clone();
                    av.sort();
                    bv.sort();
                    if av == bv {
                        continue;
                    }
                    let detail = format!(
                        "principal {principal} field `{field}` (semantic `{semantic}`, epoch \
                         `{epoch}`): {}@{} ({}) records {:?} vs {}@{} ({}) records {:?}",
                        a.source, a.observed_at, a.collection_run, av,
                        b.source, b.observed_at, b.collection_run, bv,
                    );
                    if a.observed_at == b.observed_at && a.collection_run == b.collection_run {
                        errors.push(Violation::FactConflict { detail });
                    } else {
                        errors.push(Violation::StaleEvidence { detail });
                    }
                }
            }
        }
    }

    // ── Declared-complete source absence (populated sources only) ────────────
    // D1 is complete for repo-declared canisters by construction; the
    // per-entry dfx_name∈D1 check above enforces it. D3: when populated and
    // declared complete for custom-domain-bound canisters, every domain-bound
    // entry must be in D3. D2 is NOT complete for out-of-manifest canisters
    // (proven by s3tyu) — its absence never fails anything.
    if manifest.sources.d3.status != "pending"
        && manifest
            .sources
            .d3
            .declared_complete_for
            .iter()
            .any(|u| u == "custom_domain_bound_canisters")
    {
        for e in manifest.canisters.iter().filter(|e| e.domain_bound) {
            let present = e
                .principal
                .as_deref()
                .map(|p| manifest.sources.d3.candidates.iter().any(|c| c == p))
                .unwrap_or(false);
            if !present {
                errors.push(Violation::DeclaredCompleteAbsence {
                    detail: format!(
                        "domain-bound entry {} is absent from D3, which is declared complete \
                         for custom-domain-bound canisters",
                        describe_entry(e)
                    ),
                });
            }
        }
    }

    // ── D5 bijectivity (vacuously true while pending/empty) ──────────────────
    {
        let receipts = &manifest.sources.d5.receipts;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for r in receipts {
            if !seen.insert(r.principal.as_str()) {
                errors.push(Violation::ReceiptViolation {
                    detail: format!("duplicate receipt for principal {}", r.principal),
                });
            }
            let matches = match_principal(&r.principal);
            match matches.len() {
                1 if matches[0].disposition == Disposition::BornUnderVault => {}
                1 => errors.push(Violation::ReceiptViolation {
                    detail: format!(
                        "receipt {} binds an entry that is not born_under_vault",
                        r.principal
                    ),
                }),
                _ => errors.push(Violation::ReceiptViolation {
                    detail: format!(
                        "receipt {} is unbound — no unique manifest entry (freeze §13.2a: \
                         no receipt left unbound)",
                        r.principal
                    ),
                }),
            }
            if r.manifest_purpose.trim().is_empty() {
                errors.push(Violation::ReceiptViolation {
                    detail: format!(
                        "receipt {} carries no predeclared manifest purpose (freeze §13.3)",
                        r.principal
                    ),
                });
            }
        }
        // When D5 is populated and declared complete for vault-created
        // production canisters, every born_under_vault entry must have a
        // receipt (the other half of the bijection).
        if manifest.sources.d5.status != "pending"
            && manifest
                .sources
                .d5
                .declared_complete_for
                .iter()
                .any(|u| u == "vault_created_production")
        {
            for e in manifest
                .canisters
                .iter()
                .filter(|e| e.disposition == Disposition::BornUnderVault)
            {
                let has_receipt = e
                    .principal
                    .as_deref()
                    .map(|p| receipts.iter().any(|r| r.principal == p))
                    .unwrap_or(false);
                if !has_receipt {
                    errors.push(Violation::ReceiptViolation {
                        detail: format!(
                            "born-under-vault entry {} has no D5 receipt, but D5 is declared \
                             complete for vault-created production canisters",
                            describe_entry(e)
                        ),
                    });
                }
            }
        }
    }

    // ── Axis 2: the rows must EQUAL the frozen set of 20 identities ─────────
    // (freeze §6 builder sweep at 6520185 — SSA L0 defect 5: validating only
    // present rows passes after a deletion; the set is bound exactly.)
    const FROZEN_AUTHORITY_FIELDS: [(&str, &str); 20] = [
        ("shielded_pool", "TOKEN"),
        ("shielded_pool", "NULLIFIER"),
        ("shielded_pool", "MERKLE"),
        ("shielded_pool", "TREASURY"),
        ("shielded_pool", "STAKING"),
        ("shielded_pool", "CONTROLLER"),
        ("shielded_pool", "VERIFIER_CANISTER"),
        ("treasury", "TOKEN"),
        ("treasury", "POOL"),
        ("treasury", "CONTROLLER"),
        ("vesting", "TOKEN"),
        ("vesting", "CONTROLLER"),
        ("nullifier_registry", "POOL_CANISTER"),
        ("verifier", "AUTHORIZED_POOL"),
        ("stsh_token", "TREASURY"),
        ("stsh_token", "FEE_COLLECTOR"),
        ("stsh_token", "STAKING_CANISTER"),
        ("merkle_tree", "POOL_CANISTER"),
        ("shielded_pool", "VETKEYS_CANISTER"),
        ("vetkeys", "DEVICE_CHECK_CALLER"),
    ];
    {
        let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
        for a in &manifest.authority_fields {
            let key = (a.canister.as_str(), a.field.as_str());
            if !FROZEN_AUTHORITY_FIELDS.contains(&key) {
                errors.push(Violation::AuthoritySetMismatch {
                    detail: format!("unknown authority field {}.{}", a.canister, a.field),
                });
            }
            if !seen.insert(key) {
                errors.push(Violation::AuthoritySetMismatch {
                    detail: format!("duplicate authority field {}.{}", a.canister, a.field),
                });
            }
        }
        for (c, f) in FROZEN_AUTHORITY_FIELDS {
            if !seen.contains(&(c, f)) {
                errors.push(Violation::AuthoritySetMismatch {
                    detail: format!("missing authority field {c}.{f} (deleted rows must FAIL)"),
                });
            }
        }
    }
    for a in &manifest.authority_fields {
        if a.storage.trim().is_empty()
            || a.writers.is_empty()
            || a.launch_value.trim().is_empty()
            || a.read_back.trim().is_empty()
        {
            errors.push(Violation::AuthorityFieldIncomplete {
                canister: a.canister.clone(),
                field: a.field.clone(),
                detail: format!(
                    "{}.{} needs storage, a ruled launch value, enumerated writers, and a \
                     read-back (freeze §13.5 build-time gate)",
                    a.canister, a.field
                ),
            });
        }
    }

    errors
}

fn describe_entry(e: &Entry) -> String {
    format!(
        "[dfx_name={:?}, ids_name={:?}, principal={:?}]",
        e.dfx_name, e.ids_name, e.principal
    )
}

// ── §P.1: the 2+9 custody partition ──────────────────────────────────────────
//
// WHAT THIS ADDS. Before §P.1 the manifest gave Vault and Upgrader the
// `born_under_vault` disposition, which asserts Vault provenance for the two
// canisters the Vault demonstrably did not create. The consequence was not
// cosmetic: D5 bijectivity ("every born-under-Vault entry has a receipt") was
// then unsatisfiable in principle, so it could only ever be satisfied
// vacuously — exactly the shape that passes while proving nothing. The
// partition separates the closed ring (2, evidenced by a separately hashed
// ceremony input) from the governed set (9, evidenced by Vault D5 receipts),
// and makes each half's evidence contract statable and checkable.
//
// WHAT IT PRESERVES. Every D1–D5 exactly-once coverage rule, every fact
// comparison rule, and every deploy-time release/size check are untouched:
// this function is additive and reports its own typed violations.

/// Hex sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Source-scan the Vault's `BORN_UNDER_VAULT_ROLES` allowlist.
///
/// The checker cannot depend on the vault crate — that would move the
/// workspace `Cargo.lock`, a production build input, and disarm the release
/// tripwire. It mirrors the constant instead and locks the mirror here, the
/// same way [`vault_required_cutover`] locks the cutover constants. A scan
/// that finds nothing is a hard error, never a vacuous pass.
pub fn vault_born_under_vault_roles(root: &Path) -> Result<Vec<String>, String> {
    let src_path = root.join("canisters/vault/src/lib.rs");
    let src = std::fs::read_to_string(&src_path)
        .map_err(|e| format!("cannot read {}: {e}", src_path.display()))?;
    let start = src
        .find("pub const BORN_UNDER_VAULT_ROLES")
        .ok_or("BORN_UNDER_VAULT_ROLES not found in vault source")?;
    let end = src[start..]
        .find("];")
        .map(|i| start + i)
        .ok_or("BORN_UNDER_VAULT_ROLES unterminated")?;
    let block = &src[start..end];
    // Take only the array body — the declaration head carries the type
    // annotation and no string literals, so splitting at `= [` is exact.
    let body = block.split_once("= [").map(|(_, b)| b).unwrap_or("");
    let mut roles = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        roles.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    if roles.is_empty() {
        return Err("BORN_UNDER_VAULT_ROLES scan found no roles — refusing a vacuous pass".into());
    }
    Ok(roles)
}

/// The §P.1 partition contract. Returns EVERY violation found, typed.
///
/// `root` is the repository root: the ring ceremony input and the vault source
/// (for the allowlist drift lock) are both resolved against it.
pub fn check_partition(root: &Path, manifest: &Manifest) -> Vec<Violation> {
    let mut errors = Vec::new();

    // ── The mirror is locked to the Vault source ─────────────────────────────
    match vault_born_under_vault_roles(root) {
        Ok(source_roles) => {
            if source_roles != BORN_UNDER_VAULT_ROLES.to_vec() {
                errors.push(Violation::RoleAllowlistDrift {
                    detail: format!(
                        "vault source declares {source_roles:?}; the checker mirrors {:?}",
                        BORN_UNDER_VAULT_ROLES
                    ),
                });
            }
        }
        Err(e) => errors.push(Violation::RoleAllowlistDrift {
            detail: format!("cannot read the Vault allowlist: {e}"),
        }),
    }

    // ── Ring section hygiene ─────────────────────────────────────────────────
    let ring = &manifest.bootstrap_ring;
    if ring.status != "pending" && ring.status != "populated" {
        errors.push(Violation::InvalidEvidence {
            detail: format!(
                "bootstrap_ring has status `{}` — must be exactly `pending` or `populated`",
                ring.status
            ),
        });
    }
    if ring.members != BOOTSTRAP_RING_ROLES.to_vec() {
        errors.push(Violation::PartitionCardinalityDrift {
            detail: format!(
                "bootstrap_ring.members is {:?}, must be exactly {:?}",
                ring.members, BOOTSTRAP_RING_ROLES
            ),
        });
    }
    {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for m in &ring.members {
            if !seen.insert(m.as_str()) {
                errors.push(Violation::RingMemberDuplicate { role: m.clone() });
            }
        }
    }

    // ── Ring evidence: separately hashed ceremony input, fail-closed ─────────
    if ring.evidence_path.trim().is_empty() {
        errors.push(Violation::RingEvidenceUnavailable {
            detail: "bootstrap_ring.evidence_path is empty — the ceremony input must be named \
                     even while pending, so the requirement cannot be quietly dropped"
                .into(),
        });
    }
    if ring.status == "populated" {
        if ring.evidence_sha256.trim().is_empty() {
            errors.push(Violation::RingEvidenceUnavailable {
                detail: format!(
                    "bootstrap_ring is populated but evidence_sha256 is empty for `{}` — \
                     unpinned evidence is unverifiable evidence",
                    ring.evidence_path
                ),
            });
        } else {
            let p = root.join(&ring.evidence_path);
            match std::fs::read(&p) {
                Ok(bytes) => {
                    let actual = sha256_hex(&bytes);
                    if actual != ring.evidence_sha256.trim() {
                        errors.push(Violation::RingEvidenceUnavailable {
                            detail: format!(
                                "{} hashes to {actual}, pinned {}",
                                ring.evidence_path,
                                ring.evidence_sha256.trim()
                            ),
                        });
                    }
                }
                Err(e) => errors.push(Violation::RingEvidenceUnavailable {
                    detail: format!("cannot read {}: {e}", p.display()),
                }),
            }
        }
    }

    // ── The 2+9 entry partition ──────────────────────────────────────────────
    let ring_entries: Vec<&Entry> = manifest
        .canisters
        .iter()
        .filter(|e| e.disposition == Disposition::BootstrapRing)
        .collect();
    let governed: Vec<&Entry> = manifest
        .canisters
        .iter()
        .filter(|e| e.disposition == Disposition::BornUnderVault)
        .collect();

    // Ring roles: present exactly once each, and named only by ring entries.
    let mut ring_by_role: BTreeMap<String, usize> = BTreeMap::new();
    for e in &ring_entries {
        match e.ring_role.as_deref() {
            Some(r) if BOOTSTRAP_RING_ROLES.contains(&r) => {
                *ring_by_role.entry(r.to_string()).or_insert(0) += 1;
            }
            Some(r) => errors.push(Violation::PartitionCardinalityDrift {
                detail: format!(
                    "bootstrap-ring entry {} declares ring_role `{r}`, not one of {:?}",
                    describe_entry(e),
                    BOOTSTRAP_RING_ROLES
                ),
            }),
            None => errors.push(Violation::PartitionCardinalityDrift {
                detail: format!(
                    "bootstrap-ring entry {} declares no ring_role",
                    describe_entry(e)
                ),
            }),
        }
        // Pending ceremony ⇒ no ring principal may be claimed.
        if ring.status == "pending" && e.principal.is_some() {
            errors.push(Violation::RingEvidenceUnavailable {
                detail: format!(
                    "bootstrap-ring entry {} carries a principal while the ring ceremony input \
                     is pending — a principal with no hashed ceremony evidence behind it is an \
                     authored fact",
                    describe_entry(e)
                ),
            });
        }
    }
    for role in BOOTSTRAP_RING_ROLES {
        match ring_by_role.get(role).copied().unwrap_or(0) {
            0 => errors.push(Violation::RingMemberMissing { role: role.into() }),
            1 => {}
            _ => errors.push(Violation::RingMemberDuplicate { role: role.into() }),
        }
    }
    if ring_entries.len() != BOOTSTRAP_RING_ROLES.len() {
        errors.push(Violation::PartitionCardinalityDrift {
            detail: format!(
                "{} bootstrap-ring entries, expected exactly {}",
                ring_entries.len(),
                BOOTSTRAP_RING_ROLES.len()
            ),
        });
    }
    // A non-ring entry must not carry a ring_role.
    for e in manifest
        .canisters
        .iter()
        .filter(|e| e.disposition != Disposition::BootstrapRing)
    {
        if let Some(r) = e.ring_role.as_deref() {
            errors.push(Violation::PartitionCardinalityDrift {
                detail: format!(
                    "entry {} is not a bootstrap-ring entry but declares ring_role `{r}`",
                    describe_entry(e)
                ),
            });
        }
    }

    // Governed set: exactly the nine allowlist roles, one entry each.
    let mut governed_by_role: BTreeMap<String, Vec<&Entry>> = BTreeMap::new();
    for e in &governed {
        let role = e.dfx_name.clone().unwrap_or_default();
        if !BORN_UNDER_VAULT_ROLES.contains(&role.as_str()) {
            errors.push(Violation::PartitionCardinalityDrift {
                detail: format!(
                    "born-under-vault entry {} names role `{role}`, which is not one of the nine \
                     one-shot allowlist roles",
                    describe_entry(e)
                ),
            });
            continue;
        }
        governed_by_role.entry(role).or_default().push(e);
    }
    for role in BORN_UNDER_VAULT_ROLES {
        match governed_by_role.get(role).map(|v| v.len()).unwrap_or(0) {
            0 => errors.push(Violation::PartitionCardinalityDrift {
                detail: format!("allowlist role `{role}` has no born-under-vault entry"),
            }),
            1 => {}
            n => errors.push(Violation::PartitionCardinalityDrift {
                detail: format!("allowlist role `{role}` has {n} born-under-vault entries"),
            }),
        }
    }
    if governed.len() != BORN_UNDER_VAULT_ROLES.len() {
        errors.push(Violation::PartitionCardinalityDrift {
            detail: format!(
                "{} born-under-vault entries, expected exactly {}",
                governed.len(),
                BORN_UNDER_VAULT_ROLES.len()
            ),
        });
    }

    // ── Receipt contract ─────────────────────────────────────────────────────
    let ring_principals: BTreeSet<&str> =
        ring_entries.iter().filter_map(|e| e.principal.as_deref()).collect();
    let entry_by_principal = |p: &str| -> Vec<&Entry> {
        manifest
            .canisters
            .iter()
            .filter(|e| e.principal.as_deref() == Some(p))
            .collect()
    };

    let mut bound_by_role: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_principals: BTreeSet<&str> = BTreeSet::new();
    for r in &manifest.sources.d5.receipts {
        // Status is a strict enum; empty or unknown fails closed.
        let bound = match r.status.as_str() {
            RECEIPT_STATUS_BOUND => true,
            RECEIPT_STATUS_ORPHANED => false,
            other => {
                errors.push(Violation::InvalidEvidence {
                    detail: format!(
                        "D5 receipt {} has status `{other}` — must be exactly `{}` or `{}`",
                        r.principal, RECEIPT_STATUS_BOUND, RECEIPT_STATUS_ORPHANED
                    ),
                });
                false
            }
        };
        if r.proposal_id.is_none() || r.created_at_ns.is_none() {
            errors.push(Violation::InvalidEvidence {
                detail: format!(
                    "D5 receipt {} omits proposal_id and/or created_at_ns — a receipt without \
                     its governing proposal and creation time is a transcription, not provenance",
                    r.principal
                ),
            });
        }
        if !seen_principals.insert(r.principal.as_str()) {
            errors.push(Violation::ExtraReceipt {
                detail: format!("duplicate receipt for principal {}", r.principal),
            });
        }

        let purpose = r.manifest_purpose.trim();
        // Ring receipt presented as Vault-created.
        if BOOTSTRAP_RING_ROLES.contains(&purpose)
            || ring_principals.contains(r.principal.as_str())
        {
            errors.push(Violation::RingReceiptPresentedAsVaultCreated {
                detail: format!(
                    "receipt {} claims purpose `{purpose}`",
                    r.principal
                ),
            });
            continue;
        }
        if !BORN_UNDER_VAULT_ROLES.contains(&purpose) {
            errors.push(Violation::ReceiptPurposeMismatch {
                detail: format!(
                    "receipt {} claims purpose `{purpose}`, not one of the nine one-shot \
                     allowlist roles",
                    r.principal
                ),
            });
            continue;
        }

        // Orphan: binds no manifest entry.
        let matches = entry_by_principal(&r.principal);
        match matches.len() {
            0 => {
                errors.push(Violation::OrphanReceipt {
                    detail: format!(
                        "receipt {} (purpose `{purpose}`) matches no manifest entry",
                        r.principal
                    ),
                });
                continue;
            }
            1 => {
                let e = matches[0];
                let entry_role = e.dfx_name.clone().unwrap_or_default();
                if e.disposition != Disposition::BornUnderVault || entry_role != purpose {
                    errors.push(Violation::ReceiptPurposeMismatch {
                        detail: format!(
                            "receipt {} claims purpose `{purpose}` but binds entry {} \
                             ({:?}, role `{entry_role}`)",
                            r.principal,
                            describe_entry(e),
                            e.disposition
                        ),
                    });
                    continue;
                }
            }
            _ => {
                errors.push(Violation::OrphanReceipt {
                    detail: format!(
                        "receipt {} matches {} manifest entries — no unique binding",
                        r.principal,
                        matches.len()
                    ),
                });
                continue;
            }
        }

        if bound {
            *bound_by_role.entry(purpose.to_string()).or_insert(0) += 1;
        }
    }

    // Extra `Bound` receipts per role, and unbound governed targets. Both are
    // only decidable once D5 is populated — while D5 is pending there are no
    // receipts to bind (and a pending source carrying receipts is already a
    // typed PendingSourceWithCandidates).
    for (role, n) in &bound_by_role {
        if *n > 1 {
            errors.push(Violation::ExtraReceipt {
                detail: format!("role `{role}` carries {n} `{RECEIPT_STATUS_BOUND}` receipts"),
            });
        }
    }
    if manifest.sources.d5.status == "populated" {
        for role in BORN_UNDER_VAULT_ROLES {
            if bound_by_role.get(role).copied().unwrap_or(0) == 0 {
                let orphaned_only = manifest
                    .sources
                    .d5
                    .receipts
                    .iter()
                    .any(|r| r.manifest_purpose.trim() == role);
                errors.push(Violation::GovernedTargetUnbound {
                    detail: if orphaned_only {
                        format!(
                            "governed role `{role}` has only non-`{RECEIPT_STATUS_BOUND}` \
                             receipts"
                        )
                    } else {
                        format!("governed role `{role}` has no D5 receipt at all")
                    },
                });
            }
        }
    }

    errors
}

// ── §8 size invariant ────────────────────────────────────────────────────────

/// One measured payload: a COMPLETE encoded Candid message of a named class.
#[derive(Debug, Clone)]
pub struct PayloadMeasurement {
    pub label: String,
    pub encoded_bytes: u64,
}

/// Assert one encoded message against the gate bound (platform limit minus
/// the stated safety margin — see stsh-custody-types).
pub fn assert_size(label: &str, encoded_bytes: u64) -> Result<(), Violation> {
    if encoded_bytes > GATE_SIZE_BOUND_BYTES {
        return Err(Violation::SizeViolation {
            label: label.to_string(),
            encoded_bytes,
            bound_bytes: GATE_SIZE_BOUND_BYTES,
        });
    }
    Ok(())
}

/// A proven maximum-length IC principal: 29-byte self-authenticating form is
/// the longest the platform admits. Used as the conservative maximum wherever
/// a payload carries a principal (SSA L0 defect 4 — `aaaaa-aa` is NOT a
/// conservative maximum).
pub fn max_length_principal(fill: u8) -> candid::Principal {
    candid::Principal::from_slice(&[fill; 29])
}

/// Encode a management `install_code(install)` action EXACTLY as the Vault
/// would carry it (freeze §3f: both hashes bound, inline-only) and measure the
/// complete Candid message. The target is a proven maximum-length principal.
pub fn encode_install_payload(
    target: candid::Principal,
    wasm_bytes: &[u8],
    arg_bytes: &[u8],
) -> Result<u64, String> {
    let action = stsh_custody_types::ManagementAction::InstallCode {
        target,
        expected_wasm_hash: vec![0u8; 32],
        expected_arg_hash: vec![0u8; 32],
        wasm_bytes: wasm_bytes.to_vec(),
        arg_bytes: arg_bytes.to_vec(),
    };
    Ok(candid::encode_one(&action)
        .map_err(|e| format!("candid encode failed: {e}"))?
        .len() as u64)
}

/// Strip `//` line comments (same convention as verify_genesis_manifest).
fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.find("//").map(|i| &l[..i]).unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse a canonical `_init.did` artifact and return the EXACT binary Candid
/// encoding of the actual deployment init value (SSA L0 defect 4 — never a
/// text-length proxy). Missing or unparseable is a hard error.
pub fn encode_init_artifact(path: &Path) -> Result<Vec<u8>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let args = candid_parser::parse_idl_args(&strip_comments(&raw))
        .map_err(|e| format!("{}: candid parse failed: {e}", path.display()))?;
    args.to_bytes()
        .map_err(|e| format!("{}: candid encode failed: {e}", path.display()))
}

/// Conservative maximum init-arg fixtures for born-under-vault canisters
/// without a committed init artifact. Every one of these init shapes is a
/// FIXED-shape record/tuple of principals, fixed-width numbers, one fixed
/// 32-byte hash blob, and one fixed text tag (verified against the .did init
/// signatures), so a field-wise maximum — max-length principals, max-width
/// numbers, the real 32-byte/blob and text values — is PROVABLY conservative:
/// no field is an unbounded vec.
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize, Clone, Debug)]
struct PoolInitMax {
    token_canister: candid::Principal,
    nullifier_canister: candid::Principal,
    merkle_canister: candid::Principal,
    treasury_canister: candid::Principal,
    staking_canister: candid::Principal,
    controller: candid::Principal,
    initial_vk_hash: Vec<u8>,
    initial_proof_system: String,
    /// SSA L0 round-2 defect 4: the REAL InitArgs (shielded-pool/src/lib.rs:2834)
    /// has this Option field — Some(max-length) is larger than omission.
    verifier_canister: Option<candid::Principal>,
}

#[derive(candid::CandidType, serde::Serialize, serde::Deserialize)]
struct MonitorInitMax {
    token_canister: candid::Principal,
    pool_principal: candid::Principal,
    treasury_principal: candid::Principal,
    pool_attestation_source: candid::Principal,
    refresh_interval_ns: u64,
    max_staleness_ns: u64,
    history_capacity: u32,
}

/// Compile-time Candid reflection over the monitor maximal fixture.
pub fn monitor_init_fixture_field_types() -> std::collections::BTreeMap<String, String> {
    use candid::types::{Label, TypeInner};
    match &*<MonitorInitMax as candid::CandidType>::ty() {
        TypeInner::Record(fs) => fs.iter().map(|f| {
            let name = match &*f.id {
                Label::Named(n) => n.clone(),
                other => panic!("unnamed monitor field: {other:?}"),
            };
            let ty = match &*f.ty {
                TypeInner::Principal => "principal",
                TypeInner::Nat64 => "nat64",
                TypeInner::Nat32 => "nat32",
                other => panic!("unexpected monitor type for {name}: {other:?}"),
            };
            (name, ty.to_string())
        }).collect(),
        other => panic!("MonitorInitMax must be a record, got {other:?}"),
    }
}

/// Decode the measured fixture for maximal-principal assertions.
pub fn decode_monitor_init_principal_lengths(bytes: &[u8]) -> Result<[usize; 4], String> {
    let v: MonitorInitMax =
        candid::decode_one(bytes).map_err(|e| format!("monitor fixture decode failed: {e}"))?;
    Ok([
        v.token_canister.as_slice().len(),
        v.pool_principal.as_slice().len(),
        v.treasury_principal.as_slice().len(),
        v.pool_attestation_source.as_slice().len(),
    ])
}

/// Compile-time reflection over the pool maximal fixture: its Candid record
/// field names. Used by the field-coverage test to prove the fixture covers
/// every field of the real InitArgs (SSA L0 round-2 defect 4).
pub fn pool_init_fixture_field_names() -> std::collections::BTreeSet<String> {
    use candid::types::{Label, TypeInner};
    match &*<PoolInitMax as candid::CandidType>::ty() {
        TypeInner::Record(fs) => fs
            .iter()
            .filter_map(|f| match &*f.id {
                Label::Named(n) => Some(n.clone()),
                _ => None,
            })
            .collect(),
        other => panic!("PoolInitMax must be a Candid record, got {other:?}"),
    }
}

/// Decode the pool fixture's encoding back into the fixture type (test hook
/// for the populated-Option assertion).
pub fn decode_pool_init_fixture(bytes: &[u8]) -> Result<Vec<String>, String> {
    let v: PoolInitMax =
        candid::decode_one(bytes).map_err(|e| format!("pool fixture decode failed: {e}"))?;
    Ok(vec![format!(
        "verifier_canister_some={}",
        v.verifier_canister.is_some()
    )])
}

/// The init-args value used for each payload class. `Err` = missing required
/// artifact (a gate FAILURE, never a zero-arg measurement).
pub fn init_args_for(root: &Path, pkg: &str) -> Result<Vec<u8>, String> {
    let p = |b: u8| max_length_principal(b);
    match pkg {
        // The two canisters WITH canonical committed init artifacts: encode
        // the actual deployment values exactly. token's is the largest —
        // it carries the genesis allocation (freeze §8).
        "stsh_token" => encode_init_artifact(&root.join("deployment/mainnet/stsh_token_init.did")),
        "vesting" => encode_init_artifact(&root.join("deployment/mainnet/vesting_init.did")),
        // (principal, principal, principal)
        "treasury" => Ok(candid::encode_args((p(1), p(2), p(3))).unwrap()),
        // (principal)
        "nullifier_registry" | "merkle_tree" => Ok(candid::encode_one(p(1)).unwrap()),
        "stsh-verifier" => Ok(candid::encode_one(p(1)).unwrap()),
        "shielded_pool" => Ok(candid::encode_one(PoolInitMax {
            token_canister: p(1),
            nullifier_canister: p(2),
            merkle_canister: p(3),
            treasury_canister: p(4),
            staking_canister: p(5),
            controller: p(6),
            initial_vk_hash: vec![0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
            verifier_canister: Some(p(7)),
        })
        .unwrap()),
        "smoke_alarm_monitor" => Ok(candid::encode_one(MonitorInitMax {
            token_canister: p(1),
            pool_principal: p(2),
            treasury_principal: p(3),
            pool_attestation_source: p(4),
            refresh_interval_ns: u64::MAX,
            max_staleness_ns: u64::MAX,
            history_capacity: u32::MAX,
        })
        .unwrap()),
        // The ring init records, encoded from the REAL init shapes with
        // distinct max-length principals and the frozen threshold. The vault
        // fixture is the full post-L1 `VaultInit` (quorum + cutover targets)
        // carrying the ruled cutover pairs — the SAME construction the
        // cutover binding assertion extracts from (SSA integration item 6).
        "vault" => encode_vault_init_fixture(root),
        // R2.3 (CUST-SSA-002): READ THE COMMITTED ARTIFACT. This previously
        // SYNTHESISED the Upgrader init from placeholders p(1),p(2),p(3)/p(9),
        // so the gate measured and verified a fiction — a GREEN verdict for an
        // attacker-chosen recovery roster. While synthesis survives anywhere,
        // the gate is checking a file the install never reads (R2.4). A missing
        // or unparseable artifact is a hard error here, never a fallback.
        "upgrader" => encode_init_artifact(&root.join(UPGRADER_INIT_ARTIFACT)),
        other => Err(format!("no init-args rule for `{other}`")),
    }
}

/// The born-under-vault production wasms the §8 gate measures. Every class is
/// REQUIRED: a missing Wasm or init artifact is a gate FAILURE.
pub const INLINE_PAYLOAD_ARTIFACTS: &[(&str, &str)] = &[
    ("stsh_token", "stsh_token.wasm"),
    ("shielded_pool", "shielded_pool.wasm"),
    ("treasury", "treasury.wasm"),
    ("vesting", "vesting.wasm"),
    ("nullifier_registry", "nullifier_registry.wasm"),
    ("merkle_tree", "merkle_tree.wasm"),
    ("stsh-verifier", "stsh_verifier.wasm"),
    ("smoke_alarm_monitor", "smoke_alarm_monitor.wasm"),
    ("vault", "vault.wasm"),
    ("upgrader", "upgrader.wasm"),
];

/// Measure every §8 payload class. Any missing/invalid artifact produces a
/// `MissingPayloadArtifact` violation in the returned error list — PENDING no
/// longer exists.
pub fn measure_payloads(root: &Path) -> (Vec<PayloadMeasurement>, Vec<Violation>) {
    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    let mut measured = Vec::new();
    let mut violations = Vec::new();

    for (pkg, wasm) in INLINE_PAYLOAD_ARTIFACTS {
        let wasm_path = wasm_dir.join(wasm);
        let wasm_bytes = match std::fs::read(&wasm_path) {
            Ok(b) => b,
            Err(e) => {
                violations.push(Violation::MissingPayloadArtifact {
                    detail: format!("{pkg}: cannot read {}: {e}", wasm_path.display()),
                });
                continue;
            }
        };
        let arg_bytes = match init_args_for(root, pkg) {
            Ok(b) => b,
            Err(e) => {
                violations.push(Violation::MissingPayloadArtifact {
                    detail: format!("{pkg}: {e}"),
                });
                continue;
            }
        };

        // Management install_code(install) class — token's is the largest,
        // carrying the genesis allocation (freeze §8). Target: proven
        // maximum-length principal.
        match encode_install_payload(max_length_principal(0xA5), &wasm_bytes, &arg_bytes) {
            Ok(n) => measured.push(PayloadMeasurement {
                label: format!("install_code(install) payload: {pkg}"),
                encoded_bytes: n,
            }),
            Err(e) => violations.push(Violation::MissingPayloadArtifact {
                detail: format!("{pkg}: {e}"),
            }),
        }

        // C1 / recovery classes for the two ring canisters.
        if *pkg == "upgrader" {
            measured.push(PayloadMeasurement {
                label: "UpgraderUpgrade payload (C1)".into(),
                encoded_bytes: encode_upgrader_upgrade_payload(&wasm_bytes, &arg_bytes),
            });
        }
        if *pkg == "vault" {
            measured.push(PayloadMeasurement {
                label: "trigger_vault_upgrade / propose_recovery payload".into(),
                encoded_bytes: encode_trigger_vault_upgrade_payload(&wasm_bytes, &arg_bytes),
            });
            // CUST-L12-01 (§3e): the Vault-originated governed self-upgrade
            // call — same inline wasm+args class, different wire shape (flat
            // 5-arg tuple with request_id, not the recovery variant).
            measured.push(PayloadMeasurement {
                label: "VaultUpgradeViaUpgrader payload (§3e, CUST-L12-01)".into(),
                encoded_bytes: encode_vault_upgrade_via_upgrader_payload(&wasm_bytes, &arg_bytes),
            });
        }
    }

    (measured, violations)
}

/// Encode a C1 `UpgraderUpgrade` payload (freeze §3d/§8) and measure the
/// complete Candid message.
pub fn encode_upgrader_upgrade_payload(wasm_bytes: &[u8], arg_bytes: &[u8]) -> u64 {
    let u = stsh_custody_types::UpgraderUpgrade {
        expected_wasm_hash: vec![0u8; 32],
        expected_arg_hash: vec![0u8; 32],
        wasm_bytes: wasm_bytes.to_vec(),
        arg_bytes: arg_bytes.to_vec(),
    };
    candid::encode_one(&u).expect("UpgraderUpgrade encodes").len() as u64
}

/// Encode a recovery `trigger_vault_upgrade` payload — the propose_recovery
/// ingress class (freeze §8) — and measure the complete Candid message.
pub fn encode_trigger_vault_upgrade_payload(wasm_bytes: &[u8], arg_bytes: &[u8]) -> u64 {
    let a = stsh_custody_types::RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: vec![0u8; 32],
        expected_arg_hash: vec![0u8; 32],
        wasm_bytes: wasm_bytes.to_vec(),
        arg_bytes: arg_bytes.to_vec(),
    };
    candid::encode_one(&a).expect("RecoveryAction encodes").len() as u64
}

/// Encode a §3e `VaultUpgradeViaUpgrader` payload (CUST-L12-01) EXACTLY as the
/// Vault would send it to the Upgrader's fixed `trigger_vault_upgrade`
/// endpoint and measure the complete Candid message. Same inline wasm+args
/// class as the C1/recovery classes; the wire shape differs (flat 5-arg
/// tuple carrying `request_id`), so it is measured as its own class.
pub fn encode_vault_upgrade_via_upgrader_payload(wasm_bytes: &[u8], arg_bytes: &[u8]) -> u64 {
    let u = stsh_custody_types::VaultUpgradeViaUpgrader {
        request_id: u64::MAX,
        expected_wasm_hash: vec![0u8; 32],
        expected_arg_hash: vec![0u8; 32],
        wasm_bytes: wasm_bytes.to_vec(),
        arg_bytes: arg_bytes.to_vec(),
    };
    u.encode().len() as u64
}

/// Run the §8 invariant over everything measured. Every measured payload must
/// be under the gate bound.
pub fn check_sizes(measured: &[PayloadMeasurement]) -> Vec<Violation> {
    measured
        .iter()
        .filter_map(|m| assert_size(&m.label, m.encoded_bytes).err())
        .collect()
}

// ── DID fixture drift lock (SSA L0 round-4 defect 2) ─────────────────────────
//
// The typed-contract conformance suite in stsh-custody-types reads PINNED
// committed-DID fixtures. This check makes the pins honest: every fixture
// must equal the COMMITTED target DID (`git show HEAD:<path>`, byte-exact
// after the provenance header). Deterministic on the clean tip and immune to
// dirty working-tree DID files (e.g. the current RB-SWARM shielded_pool.did)
// because it compares against HEAD, never the working tree. A lane that
// commits a target-DID change without repinning the fixture FAILS the gate —
// the repin is then a deliberate, reviewable event.
//
// Single source of truth: the fixtures live ONLY in
// canisters/custody-types/tests/fixtures/did/; this tool reads that path.
pub const DID_FIXTURES: &[(&str, &str)] = &[
    (
        "canisters/custody-types/tests/fixtures/did/shielded_pool.did",
        "canisters/shielded-pool/shielded_pool.did",
    ),
    (
        "canisters/custody-types/tests/fixtures/did/treasury.did",
        "canisters/treasury/treasury.did",
    ),
    (
        "canisters/custody-types/tests/fixtures/did/vesting.did",
        "canisters/vesting/vesting.did",
    ),
];

/// Fixture format: exactly 4 `//` provenance header lines, then the committed
/// DID bytes verbatim.
pub const PROVENANCE_HEADER_LINES: usize = 4;

/// Strip and validate the provenance header.
pub fn strip_provenance_header(fixture: &str) -> Result<&str, String> {
    let mut pos = 0usize;
    for i in 0..PROVENANCE_HEADER_LINES {
        let line_end = fixture[pos..]
            .find('\n')
            .map(|i| pos + i + 1)
            .ok_or_else(|| format!("fixture truncated in provenance header (line {})", i + 1))?;
        let line = &fixture[pos..line_end];
        if !line.starts_with("//") {
            return Err(format!(
                "provenance header line {} is not a `//` comment: {line:?}",
                i + 1
            ));
        }
        pos = line_end;
    }
    Ok(&fixture[pos..])
}

/// Byte-exact comparison, header stripped.
pub fn fixture_matches_committed(fixture: &str, committed: &str) -> Result<bool, String> {
    Ok(strip_provenance_header(fixture)? == committed)
}

/// The blocking drift check: every pinned fixture vs `git show HEAD:<did>`.
pub fn check_did_fixtures(root: &Path) -> Vec<Violation> {
    let mut errors = Vec::new();
    for (fixture_rel, did_rel) in DID_FIXTURES {
        let fixture_path = root.join(fixture_rel);
        let fixture = match std::fs::read_to_string(&fixture_path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(Violation::DidFixtureDrift {
                    detail: format!("cannot read fixture {}: {e}", fixture_path.display()),
                });
                continue;
            }
        };
        let out = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy(), "show", &format!("HEAD:{did_rel}")])
            .output();
        let committed = match out {
            Ok(o) if o.status.success() => match String::from_utf8(o.stdout) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(Violation::DidFixtureDrift {
                        detail: format!("git show HEAD:{did_rel} is not UTF-8: {e}"),
                    });
                    continue;
                }
            },
            _ => {
                // Fallback: no usable git metadata at `root` (e.g. an
                // isolated checkout-index export of the index, where the
                // on-disk DID IS the committed content). Compare against the
                // on-disk DID — fail-closed, never a silent pass.
                match std::fs::read_to_string(root.join(did_rel)) {
                    Ok(s) => s,
                    Err(e2) => {
                        errors.push(Violation::DidFixtureDrift {
                            detail: format!(
                                "git show HEAD:{did_rel} unavailable AND cannot read \
                                 {did_rel} from disk: {e2}"
                            ),
                        });
                        continue;
                    }
                }
            }
        };
        match fixture_matches_committed(&fixture, &committed) {
            Ok(true) => {}
            Ok(false) => errors.push(Violation::DidFixtureDrift {
                detail: format!(
                    "{fixture_rel} != committed {did_rel} (git show HEAD). A target-DID \
                     change must be followed by a deliberate fixture repin."
                ),
            }),
            Err(e) => errors.push(Violation::DidFixtureDrift {
                detail: format!("{fixture_rel}: {e}"),
            }),
        }
    }
    errors
}


// ── Cutover binding assertion (SSA integration item 6; re-scoped INT-02) ────
//
// What this check PROVES (and all it proves):
//   (a) the Vault's REQUIRED_CUTOVER constants (source-scanned from
//       canisters/vault/src/lib.rs — the code that enforces the cutover set)
//       EQUAL
//   (b) the manifest's set_controller_at_cutover rows,
//   and (c) the source-DERIVED vault init FIXTURE (built from (a)) carries
//   the same pairs — i.e. fixture-construction consistency, proving the §8
//   size gate measures a payload that contains the ruled set.
//
// What it does NOT prove: that any real DEPLOYMENT init payload carries the
// ruled set. No deployment encoder exists at build time (vault deployment is
// L4/runbook territory). The independent third leg is the deploy-time
// artifact check `check_deploy_time` (deployment/mainnet/vault_init.did),
// which is BLOCKING pre-deployment and currently fails with
// PendingDeploymentArtifact until L4 produces the artifact.
// Any mismatch in the proven scope is a typed CutoverBindingMismatch and the
// gate fails.

/// Mirror of the vault's `GovernedTarget` (canisters/vault/src/lib.rs) —
/// field coverage pinned by the cutover tests.
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GovernedTargetMirror {
    pub principal: candid::Principal,
    pub disposition: stsh_custody_types::ManifestDisposition,
    pub purpose: String,
}

/// Mirror of the vault's `VaultInit` (post-L1: quorum + cutover targets).
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultInitMirror {
    pub quorum: stsh_custody_types::VaultInitArgs,
    pub cutover_targets: Vec<GovernedTargetMirror>,
}

/// (a) Source-scan the Vault's REQUIRED_CUTOVER pairs: resolve the
/// `pub const CUTOVER_*: &str = "..."` definitions and the array entries that
/// reference them. A scan that finds no pairs is a hard error, never a
/// vacuous pass.
pub fn vault_required_cutover(root: &Path) -> Result<Vec<(String, String)>, String> {
    let src_path = root.join("canisters/vault/src/lib.rs");
    let src = std::fs::read_to_string(&src_path)
        .map_err(|e| format!("cannot read {}: {e}", src_path.display()))?;
    // Const definitions.
    let mut consts: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in src.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("pub const CUTOVER_") {
            if let Some((name, tail)) = rest.split_once(':') {
                if let Some((_, v)) = tail.split_once('"') {
                    let value: String = v.chars().take_while(|c| *c != '"').collect();
                    // Keyed by the FULL const name as referenced in the array.
                    consts.insert(format!("CUTOVER_{}", name.trim()), value);
                }
            }
        }
    }
    // The REQUIRED_CUTOVER block references the consts by name.
    let start = src
        .find("pub const REQUIRED_CUTOVER")
        .ok_or("REQUIRED_CUTOVER not found in vault source")?;
    let end = src[start..].find("];").map(|i| start + i).ok_or("REQUIRED_CUTOVER unterminated")?;
    let block = &src[start..end];
    let mut pairs = Vec::new();
    for entry in block.split('(').skip(1) {
        let inner = entry.split(')').next().unwrap_or("");
        // Skip the type annotation `[(&str, &str); 2]` and any non-pair text:
        // only const references and quoted literals resolve.
        if inner.contains(['[', ']', ';', ':']) {
            continue;
        }
        let refs: Vec<String> = inner
            .split(',')
            .map(|r| r.trim().trim_end_matches(','))
            .filter(|r| !r.is_empty())
            .filter_map(|r| {
                if let Some(v) = consts.get(r) {
                    Some(v.clone())
                } else if r.starts_with('"') && r.ends_with('"') && r.len() >= 2 {
                    Some(r.trim_matches('"').to_string())
                } else {
                    None
                }
            })
            .collect();
        if refs.len() == 2 {
            pairs.push((refs[0].clone(), refs[1].clone()));
        }
    }
    if pairs.is_empty() {
        return Err("REQUIRED_CUTOVER scan found no pairs — refusing a vacuous pass".into());
    }
    Ok(pairs)
}

/// (b) The manifest's set_controller_at_cutover rows as (purpose, principal)
/// — purpose = dfx_name (falling back to ids_name).
pub fn manifest_cutover_rows(manifest: &Manifest) -> Vec<(String, String)> {
    manifest
        .canisters
        .iter()
        .filter(|e| e.disposition == Disposition::SetControllerAtCutover)
        .map(|e| {
            (
                e.dfx_name.clone().or_else(|| e.ids_name.clone()).unwrap_or_default(),
                e.principal.clone().unwrap_or_default(),
            )
        })
        .collect()
}

/// (c) The cutover pairs present in the encoded vault init payload the size
/// gate measures. Decode-side extraction: proves the targets are actually IN
/// the encoded bytes.
pub fn cutover_pairs_in_vault_init_payload(
    encoded: &[u8],
) -> Result<Vec<(String, String)>, String> {
    let init: VaultInitMirror =
        candid::decode_one(encoded).map_err(|e| format!("vault init payload decode: {e}"))?;
    Ok(init
        .cutover_targets
        .iter()
        .filter(|t| t.disposition == stsh_custody_types::ManifestDisposition::SetControllerAtCutover)
        .map(|t| (t.purpose.clone(), t.principal.to_text()))
        .collect())
}

/// The encoded vault init fixture (real shape, maximal quorum principals,
/// the ruled cutover pairs). Used by BOTH the §8 size gate and the binding
/// assertion — one construction, so the measured payload always carries the
/// checked set.
pub fn encode_vault_init_fixture(root: &Path) -> Result<Vec<u8>, String> {
    let p = |b: u8| max_length_principal(b);
    let required = vault_required_cutover(root)?;
    let cutover_targets = required
        .iter()
        .map(|(purpose, principal)| {
            Ok(GovernedTargetMirror {
                principal: candid::Principal::from_text(principal)
                    .map_err(|e| format!("bad cutover principal `{principal}`: {e}"))?,
                disposition: stsh_custody_types::ManifestDisposition::SetControllerAtCutover,
                purpose: purpose.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(candid::encode_one(VaultInitMirror {
        quorum: stsh_custody_types::VaultInitArgs {
            signers: vec![p(1), p(2), p(3)],
            threshold: stsh_custody_types::INITIAL_THRESHOLD,
            upgrader: p(9),
        },
        cutover_targets,
    })
    .expect("vault init fixture encodes"))
}

/// The blocking three-way comparison. Pure: IO happens in the caller-side
/// helpers so mutations are directly testable.
pub fn check_cutover_sets(
    required: &[(String, String)],
    manifest_rows: &[(String, String)],
    payload_pairs: &[(String, String)],
) -> Vec<Violation> {
    let norm = |v: &[(String, String)]| -> BTreeSet<(String, String)> {
        v.iter().cloned().collect()
    };
    let (r, m, p) = (norm(required), norm(manifest_rows), norm(payload_pairs));
    let mut errors = Vec::new();
    if required.len() != r.len() {
        errors.push(Violation::CutoverBindingMismatch {
            detail: "REQUIRED_CUTOVER contains duplicate pairs".into(),
        });
    }
    if r != m {
        errors.push(Violation::CutoverBindingMismatch {
            detail: format!(
                "Vault REQUIRED_CUTOVER {r:?} != manifest set_controller_at_cutover rows {m:?}"
            ),
        });
    }
    if r != p {
        errors.push(Violation::CutoverBindingMismatch {
            detail: format!(
                "Vault REQUIRED_CUTOVER {r:?} != pairs present in the encoded vault init payload {p:?}"
            ),
        });
    }
    errors
}

/// IO wrapper used by the gate: scan (a), load (b), encode+extract (c).
pub fn check_cutover_binding(root: &Path, manifest: &Manifest) -> Vec<Violation> {
    let required = match vault_required_cutover(root) {
        Ok(r) => r,
        Err(e) => {
            return vec![Violation::CutoverBindingMismatch {
                detail: format!("cannot scan REQUIRED_CUTOVER: {e}"),
            }];
        }
    };
    let manifest_rows = manifest_cutover_rows(manifest);
    let payload_pairs = match encode_vault_init_fixture(root)
        .and_then(|b| cutover_pairs_in_vault_init_payload(&b))
    {
        Ok(p) => p,
        Err(e) => {
            return vec![Violation::CutoverBindingMismatch {
                detail: format!("cannot build/extract the vault init payload: {e}"),
            }];
        }
    };
    check_cutover_sets(&required, &manifest_rows, &payload_pairs)
}

// ── Deploy-time gate (SSA integration INT-02) ────────────────────────────────
//
// The INDEPENDENT third leg of the cutover binding: the real deployment init
// artifact `deployment/mainnet/vault_init.did`, produced at L4/runbook time
// (modeled on the genesis _init.did artifacts — token/vesting exist as files;
// the vault one does not yet).
//
// This check is DEPLOY-TIME class: it is NOT part of the build-time coverage
// run (so ./run_gate.sh stays green while the artifact is legitimately
// pending), and it is BLOCKING pre-deployment — invoked via
// `verify_custody_manifest --deploy-time`, it fails with the typed
// PendingDeploymentArtifact until the artifact exists and verifies against
// REQUIRED_CUTOVER and the manifest cutover rows.

/// Path of the independent vault deployment init artifact (relative to root).
pub const VAULT_INIT_ARTIFACT: &str = "deployment/mainnet/vault_init.did";

/// Deploy-time checks. Currently: the vault init artifact must exist, parse,
/// and its decoded cutover pairs must equal the Vault's REQUIRED_CUTOVER and
/// the manifest's set_controller_at_cutover rows.
pub fn check_deploy_time(root: &Path, manifest: &Manifest) -> Vec<Violation> {
    let artifact = root.join(VAULT_INIT_ARTIFACT);
    if !artifact.is_file() {
        return vec![Violation::PendingDeploymentArtifact {
            path: VAULT_INIT_ARTIFACT.to_string(),
            detail: format!(
                "{VAULT_INIT_ARTIFACT} not yet produced — the independent deployment init \
                 payload does not exist. It must be created at L4/runbook time and verified \
                 here before any deployment."
            ),
        }];
    }
    // Parse + encode the actual artifact value, decode as the vault init
    // shape, extract the cutover pairs, and run the full three-way check.
    let required = match vault_required_cutover(root) {
        Ok(r) => r,
        Err(e) => {
            return vec![Violation::CutoverBindingMismatch {
                detail: format!("cannot scan REQUIRED_CUTOVER: {e}"),
            }];
        }
    };
    let manifest_rows = manifest_cutover_rows(manifest);
    let encoded = match encode_init_artifact(&artifact) {
        Ok(b) => b,
        Err(e) => {
            return vec![Violation::PendingDeploymentArtifact {
                path: VAULT_INIT_ARTIFACT.to_string(),
                detail: format!("{VAULT_INIT_ARTIFACT} exists but does not parse/encode: {e}"),
            }];
        }
    };
    let payload_pairs = match cutover_pairs_in_vault_init_payload(&encoded) {
        Ok(p) => p,
        Err(e) => {
            return vec![Violation::PendingDeploymentArtifact {
                path: VAULT_INIT_ARTIFACT.to_string(),
                detail: format!("{VAULT_INIT_ARTIFACT} exists but does not decode: {e}"),
            }];
        }
    };
    // Cutover binding (unchanged) AND — L4-01 (SSA HOLD) — the authority-critical
    // binding. Both must hold for the deploy gate to pass.
    let mut violations = check_cutover_sets(&required, &manifest_rows, &payload_pairs);
    violations.extend(check_authority_binding(root, &encoded));
    // R2.3 (CUST-SSA-002): WHO MAY RECOVER the Vault — a separate authority
    // surface from the Vault's own quorum, and the one that was entirely
    // ungated. Surface 2 is read from the SAME encoded bytes the authority
    // binding just checked, so the two cannot disagree about what was read.
    violations.extend(check_recovery_roster(root, &encoded));
    // R5.3: never GREEN on incomplete launch evidence or an unbound release.
    // Deploy-time class deliberately. R-3b: these are legitimately pending
    // before the bootstrap ceremony, and ./run_gate.sh stays green by
    // DECLARING which obligations are pending — `[deploy_gate]` in
    // deployment/mainnet/custody_manifest.toml lists the exact set of
    // Violation::key() strings the `--deploy-posture` stage expects, compared
    // for EXACT set equality — not by skipping the check. Every deploy-time
    // check now runs on every gate run; a surplus, a shortfall, or a
    // same-kind swap is a set difference and turns the gate RED.
    violations.extend(check_launch_evidence(manifest));
    violations.extend(check_release_identity(root));
    violations
}

// ── L4-01 (SSA HOLD): authority-critical binding of the vault init payload ────
//
// The pre-fix gate decoded ONLY cutover_targets, so a vault_init.did with
// knowingly-placeholder signers/threshold/upgrader got a GREEN deploy verdict —
// a fail-OPEN deployment gate. This makes the authority-critical portion
// fail-CLOSED: the init quorum must be structurally valid, carry no
// placeholder/anonymous/management/sentinel principal, and EQUAL an independently
// pinned deployment authority record. A warning inside the artifact is not a
// control; this is.

/// The pinned deployment authority record — the INDEPENDENT second source the
/// vault init payload's signers/threshold/upgrader must equal. Kept separate from
/// vault_init.did so a single edited file can never both set the authorities and
/// self-certify them.
pub const VAULT_AUTHORITY_RECORD: &str = "deployment/mainnet/vault_authorities.toml";

/// Principals that may NEVER be a vault authority: the placeholder principals the
/// L4 artifact shipped with (NNS system canisters used as stand-ins), the
/// management canister, and the anonymous principal. A concrete denylist so the
/// exact fail-open case SSA found is caught, on TOP of the record binding.
pub const FORBIDDEN_AUTHORITY_PRINCIPALS: &[&str] = &[
    "ryjl3-tyaaa-aaaaa-aaaba-cai",
    "r7inp-6aaaa-aaaaa-aaabq-cai",
    "rkp4c-7iaaa-aaaaa-aaaca-cai",
    "rrkah-fqaaa-aaaaa-aaaaq-cai",
    "aaaaa-aa",   // management canister
    "2vxsx-fae",  // anonymous
];

/// Decoded pinned authority record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRecord {
    pub signers: Vec<candid::Principal>,
    pub threshold: u32,
    pub upgrader: candid::Principal,
}

#[derive(serde::Deserialize)]
struct AuthorityRecordToml {
    threshold: u32,
    signers: Vec<String>,
    upgrader: String,
}

/// Load + parse the pinned authority record. `Ok(None)` = the record does not
/// exist yet (fail-closed: authorities not pinned). `Err` = present but malformed.
pub fn load_authority_record(root: &Path) -> Result<Option<AuthorityRecord>, String> {
    let path = root.join(VAULT_AUTHORITY_RECORD);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {VAULT_AUTHORITY_RECORD}: {e}"))?;
    let t: AuthorityRecordToml =
        toml::from_str(&raw).map_err(|e| format!("malformed {VAULT_AUTHORITY_RECORD}: {e}"))?;
    let signers = t
        .signers
        .iter()
        .map(|s| candid::Principal::from_text(s).map_err(|e| format!("bad signer `{s}`: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let upgrader = candid::Principal::from_text(&t.upgrader)
        .map_err(|e| format!("bad upgrader `{}`: {e}", t.upgrader))?;
    Ok(Some(AuthorityRecord {
        signers,
        threshold: t.threshold,
        upgrader,
    }))
}

/// Decode the AUTHORITY-CRITICAL quorum from an encoded vault init payload.
pub fn vault_init_quorum(
    encoded: &[u8],
) -> Result<(Vec<candid::Principal>, u32, candid::Principal), String> {
    let init: VaultInitMirror =
        candid::decode_one(encoded).map_err(|e| format!("vault init quorum decode: {e}"))?;
    Ok((init.quorum.signers, init.quorum.threshold, init.quorum.upgrader))
}

/// PURE authority validation (SSA L4-01): structural rules + forbidden-principal
/// denylist + equality with the pinned record. `record == None` ⇒ fail-closed
/// (record not yet pinned). Testable in-memory; the IO happens in the caller.
pub fn authority_violations(
    signers: &[candid::Principal],
    threshold: u32,
    upgrader: &candid::Principal,
    record: Option<&AuthorityRecord>,
) -> Vec<Violation> {
    authority_violations_with_rotation(signers, threshold, upgrader, record, None)
}

/// Q5-A: [`authority_violations`], rotation-aware.
///
/// `lockstep == None`, or a lockstep whose `state` is `not-yet-performed`,
/// reproduces the pre-rotation behaviour EXACTLY: the init payload is compared
/// to the pins. Once `[rotation].state = "rotated"` the pins are no longer the
/// install-time set (ROT-LEDGER-FILL rewrites them to the live roster), so the
/// single comparison splits in two and BOTH must hold:
///
///   * init payload  ↔ `[rotation.bootstrap]`  — what was INSTALLED, which
///     cannot change, against the snapshot taken of it. Marker:
///     `init != bootstrap (vault plane)`.
///   * pins          ↔ the LAST EXECUTED `[[rotation.vault]]` row's
///     `new_members` / `new_threshold` — what is LIVE now, against the ledger
///     of what happened. Marker: `pin != ledger (vault plane)`.
///
/// Equality class is unchanged on both legs (SET equality, as before): the
/// Vault's signer set is a set, and order is not a property of it.
pub fn authority_violations_with_rotation(
    signers: &[candid::Principal],
    threshold: u32,
    upgrader: &candid::Principal,
    record: Option<&AuthorityRecord>,
    lockstep: Option<&RotationLockstep>,
) -> Vec<Violation> {
    let mut v = Vec::new();
    let av = |detail: String| Violation::AuthorityBindingViolation { detail };

    // 1. Structural — the ruled bootstrap validator: threshold == 2, distinct
    //    non-anonymous signers, upgrader non-anonymous & distinct, threshold <=
    //    distinct signer count.
    if let Err(e) = stsh_custody_types::validate_bootstrap_quorum(signers, threshold, upgrader) {
        v.push(av(format!("init quorum fails bootstrap validation: {e}")));
    }
    // 2. Exactly three signers (the ruled set size).
    if signers.len() != 3 {
        v.push(av(format!(
            "expected exactly 3 signers, found {}",
            signers.len()
        )));
    }
    // 3. Forbidden principals: placeholder / management / anonymous / sentinel.
    let forbidden: std::collections::BTreeSet<candid::Principal> = FORBIDDEN_AUTHORITY_PRINCIPALS
        .iter()
        .filter_map(|s| candid::Principal::from_text(s).ok())
        .collect();
    for (role, p) in signers
        .iter()
        .map(|s| ("signer", s))
        .chain(std::iter::once(("upgrader", upgrader)))
    {
        if forbidden.contains(p) {
            v.push(av(format!(
                "{role} {} is a forbidden (placeholder/management/anonymous/sentinel) principal",
                p.to_text()
            )));
        }
    }
    // 4. Equality with the independently-pinned record — Q5-A: through the
    //    rotation ledger once the rotation has happened, directly before.
    match record {
        None => v.push(av(format!(
            "{VAULT_AUTHORITY_RECORD} not pinned — the real signer roster and upgrader must be \
             recorded independently and matched here before deployment"
        ))),
        Some(rec) => {
            let init_set: std::collections::BTreeSet<_> = signers.iter().collect();
            match lockstep.filter(|l| l.rotated) {
                // ── pre-rotation: the pins ARE the install-time set ──────────
                None => {
                    if rec.threshold != threshold {
                        v.push(av(format!(
                            "init threshold {threshold} != pinned record threshold {}",
                            rec.threshold
                        )));
                    }
                    let rec_set: std::collections::BTreeSet<_> = rec.signers.iter().collect();
                    if init_set != rec_set {
                        v.push(av("init signer set != pinned record signer set".into()));
                    }
                }
                // ── post-rotation: two legs, neither against edited history ──
                Some(l) => {
                    if l.bootstrap_vault_threshold != threshold {
                        v.push(av(format!(
                            "init != bootstrap (vault plane): init threshold {threshold} != \
                             [rotation.bootstrap].vault_threshold {}",
                            l.bootstrap_vault_threshold
                        )));
                    }
                    let boot_set: std::collections::BTreeSet<_> =
                        l.bootstrap_vault_signers.iter().collect();
                    if init_set != boot_set {
                        v.push(av(format!(
                            "init != bootstrap (vault plane): {VAULT_INIT_ARTIFACT} signer set \
                             [{}] != [rotation.bootstrap].vault_signers [{}] — the install-time \
                             payload cannot change, so it is judged against the snapshot of it",
                            render(signers),
                            render(&l.bootstrap_vault_signers)
                        )));
                    }
                    if rec.threshold != l.last_vault_new_threshold {
                        v.push(av(format!(
                            "pin != ledger (vault plane): pinned threshold {} != the last \
                             EXECUTED [[rotation.vault]] row's new_threshold {}",
                            rec.threshold, l.last_vault_new_threshold
                        )));
                    }
                    let pin_set: std::collections::BTreeSet<_> = rec.signers.iter().collect();
                    let row_set: std::collections::BTreeSet<_> =
                        l.last_vault_new_members.iter().collect();
                    if pin_set != row_set {
                        v.push(av(format!(
                            "pin != ledger (vault plane): pinned signers [{}] are not the same \
                             SET as the last EXECUTED [[rotation.vault]] row's new_members [{}]",
                            render(&rec.signers),
                            render(&l.last_vault_new_members)
                        )));
                    }
                }
            }
            // The Upgrader CANISTER principal is not rotated by either plane;
            // it is compared to the pin in both states.
            if *upgrader != rec.upgrader {
                v.push(av("init upgrader != pinned record upgrader".into()));
            }
        }
    }
    v
}

/// IO wrapper: decode the artifact's quorum, load the pinned record, run the
/// pure check.
pub fn check_authority_binding(root: &Path, encoded_init: &[u8]) -> Vec<Violation> {
    let (signers, threshold, upgrader) = match vault_init_quorum(encoded_init) {
        Ok(q) => q,
        Err(e) => {
            return vec![Violation::AuthorityBindingViolation {
                detail: format!("cannot decode vault init quorum: {e}"),
            }]
        }
    };
    let record = match load_authority_record(root) {
        Ok(r) => r,
        Err(e) => {
            return vec![Violation::AuthorityBindingViolation {
                detail: format!("cannot load authority record: {e}"),
            }]
        }
    };
    let lockstep = match load_rotation_lockstep(root) {
        Ok(l) => l,
        Err(e) => {
            // Fail closed: without a readable ledger state there is no way to
            // know WHICH comparison is the correct one to make.
            return vec![Violation::AuthorityBindingViolation {
                detail: format!("cannot load the rotation lockstep from {VAULT_AUTHORITY_RECORD}: {e}"),
            }];
        }
    };
    authority_violations_with_rotation(
        &signers,
        threshold,
        &upgrader,
        record.as_ref(),
        Some(&lockstep),
    )
}

// ── R2 (CUST-SSA-002, Critical): Upgrader recovery roster + release identity ──
//
// The Vault authority binding above answers "who governs the Vault". This
// section answers "WHO MAY RECOVER IT" — a separate authority surface that was
// entirely ungated. `validate_bootstrap_quorum` (custody-types) checks only
// STRUCTURE: threshold 2, distinct non-anonymous members, separation from the
// counterpart. Any structurally valid attacker-selected roster passes it. There
// was no `upgrader_init.did` at all, and `init_args_for` synthesised the init
// from placeholders, so the deploy gate reported GREEN for a roster chosen by
// an attacker. Structure is not identity.

/// The canonical committed Upgrader init artifact (R2.1). The install consumes
/// THIS file (R2.4) — the verifier has no synthesis path left.
pub const UPGRADER_INIT_ARTIFACT: &str = "deployment/mainnet/upgrader_init.did";

/// The committed release-identity record (R2.5). Landed at S10; the fail-closed
/// check for its absence lands here (R5.3) so the control exists BEFORE the
/// artifact arrives to satisfy it.
pub const RELEASE_RECORD_ARTIFACT: &str = "deployment/mainnet/release_hashes.toml";

/// The pinned recovery roster — surface 1, the canonical roster artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecord {
    pub members: Vec<candid::Principal>,
    pub threshold: u32,
    pub vault: candid::Principal,
}

#[derive(serde::Deserialize)]
struct RecoveryOuterToml {
    recovery: Option<RecoverySectionToml>,
}

#[derive(serde::Deserialize)]
struct RecoverySectionToml {
    members: Vec<String>,
    threshold: u32,
    vault: String,
}

/// Load the `[recovery]` section of the pinned authority record.
/// `Ok(None)` = not pinned ⇒ the caller fails CLOSED. `Err` = present but
/// malformed, which is also a failure — never a skip.
pub fn load_recovery_record(root: &Path) -> Result<Option<RecoveryRecord>, String> {
    let path = root.join(VAULT_AUTHORITY_RECORD);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {VAULT_AUTHORITY_RECORD}: {e}"))?;
    let outer: RecoveryOuterToml =
        toml::from_str(&raw).map_err(|e| format!("malformed {VAULT_AUTHORITY_RECORD}: {e}"))?;
    let Some(sec) = outer.recovery else {
        return Ok(None);
    };
    let members = sec
        .members
        .iter()
        .map(|s| {
            candid::Principal::from_text(s).map_err(|e| format!("bad recovery member `{s}`: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let vault = candid::Principal::from_text(&sec.vault)
        .map_err(|e| format!("bad recovery vault `{}`: {e}", sec.vault))?;
    Ok(Some(RecoveryRecord {
        members,
        threshold: sec.threshold,
        vault,
    }))
}

/// Decode the roster from an encoded Upgrader init payload — surface 3, the
/// install payload AS ACTUALLY ENCODED.
pub fn upgrader_init_roster(
    encoded: &[u8],
) -> Result<(Vec<candid::Principal>, u32, candid::Principal), String> {
    let init: stsh_custody_types::UpgraderInitArgs =
        candid::decode_one(encoded).map_err(|e| format!("upgrader init decode: {e}"))?;
    Ok((init.recovery_members, init.threshold, init.vault))
}

/// Ordered principal-BYTE equality. Not counts, not textual abbreviations, not
/// hashes alone, not unordered display strings, and deliberately NOT
/// set-equality: a set comparison silently accepts a reordering, and "the same
/// members in a different order" is a required negative fixture.
fn ordered_bytes_equal(a: &[candid::Principal], b: &[candid::Principal]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.as_slice() == y.as_slice())
}

fn render(ps: &[candid::Principal]) -> String {
    ps.iter().map(|p| p.to_text()).collect::<Vec<_>>().join(", ")
}

/// PURE four-surface roster validation (R2.3). Surfaces 1-3 are machine
/// verifiable and checked here. Surface 4 (the live `get_recovery_membership`
/// readback) is OPERATOR-ATTESTED and deliberately absent from this function:
/// the verifier can check recorded bytes against the pin, but it CANNOT prove
/// those bytes came from the live signer-gated query, and a checked attestation
/// must never be allowed to read as a cryptographic proof of provenance.
///
/// `pinned == None` ⇒ fail closed. `upgrader_init == None` ⇒ fail closed (the
/// artifact is missing or unparseable — never skipped).
pub fn recovery_roster_violations(
    pinned: Option<&RecoveryRecord>,
    vault_signers: &[candid::Principal],
    upgrader_init: Option<(&[candid::Principal], u32, &candid::Principal)>,
) -> Vec<Violation> {
    recovery_roster_violations_with_rotation(pinned, vault_signers, upgrader_init, None)
}

/// Q5-A (binding Addendum 1): [`recovery_roster_violations`], rotation-aware.
///
/// `lockstep == None` or `not-yet-performed` reproduces the pre-rotation
/// behaviour EXACTLY. Once `rotated`, the two install-time comparisons that
/// would go RED on a correct record are replaced, and NOTHING is left unchecked:
///
///   * surface 1 ↔ surface 2 (`[recovery].members` ↔ `vault_init.did` signers)
///     carried the intent "the recovery roster is the same three principals, in
///     the same order, as the Vault signers". Post-rotation that intent is
///     checked twice, live-vs-live and install-vs-install:
///     `live cross-plane: upgrader != vault` and
///     `install cross-plane: bootstrap upgrader_members != bootstrap vault_signers`.
///   * surface 3 ↔ surface 1 (`upgrader_init.did` recovery_members ↔ the pin)
///     splits into `init != bootstrap (upgrader plane)` and
///     `pin != ledger (upgrader plane)`.
///
/// Every leg keeps the ORDERED-BYTE equality class the surface it replaces had,
/// and every leg reports the existing [`Violation::RecoveryRosterViolation`]
/// kind with a message naming the two surfaces compared.
pub fn recovery_roster_violations_with_rotation(
    pinned: Option<&RecoveryRecord>,
    vault_signers: &[candid::Principal],
    upgrader_init: Option<(&[candid::Principal], u32, &candid::Principal)>,
    lockstep: Option<&RotationLockstep>,
) -> Vec<Violation> {
    let rotated = lockstep.filter(|l| l.rotated);
    let mut v = Vec::new();
    let rv = |detail: String| Violation::RecoveryRosterViolation { detail };

    let forbidden: std::collections::BTreeSet<candid::Principal> = FORBIDDEN_AUTHORITY_PRINCIPALS
        .iter()
        .filter_map(|s| candid::Principal::from_text(s).ok())
        .collect();

    // Duplicates and forbidden principals are checked at EVERY surface, not
    // only where they would happen to break an equality. Returns rather than
    // captures so each surface can be audited independently.
    let audit_surface = |label: &str, members: &[candid::Principal]| -> Vec<Violation> {
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for m in members {
            if !seen.insert(*m) {
                out.push(rv(format!(
                    "surface {label}: duplicate principal {} — duplicates are prohibited at \
                     every surface (a duplicate inflates apparent roster size while shrinking \
                     the real one)",
                    m.to_text()
                )));
            }
            if forbidden.contains(m) {
                out.push(rv(format!(
                    "surface {label}: {} is a forbidden \
                     (placeholder/management/anonymous/sentinel) principal",
                    m.to_text()
                )));
            }
        }
        out
    };

    let Some(pin) = pinned else {
        v.push(rv(format!(
            "{VAULT_AUTHORITY_RECORD} carries no [recovery] section — the Upgrader recovery \
             roster is NOT pinned. Fail-closed: without an independent pin there is nothing to \
             byte-match the install payload against, which is precisely CUST-SSA-002"
        )));
        return v;
    };

    v.extend(audit_surface("1 (pinned record)", &pin.members));
    v.extend(audit_surface("2 (vault_init.did signers)", vault_signers));

    // Ruled fixed recovery quorum: exactly 2. Never 1 (V7 §4 D4), never
    // contracted (freeze §6). A threshold above the roster size can never reach
    // quorum and is equally a defect.
    if pin.threshold != stsh_custody_types::INITIAL_THRESHOLD {
        v.push(rv(format!(
            "pinned recovery threshold is {}, must be exactly {} (ruled fixed quorum; never 1, \
             never contracted)",
            pin.threshold,
            stsh_custody_types::INITIAL_THRESHOLD
        )));
    }
    if (pin.threshold as usize) > pin.members.len() {
        v.push(rv(format!(
            "pinned recovery threshold {} exceeds roster size {} — unreachable quorum",
            pin.threshold,
            pin.members.len()
        )));
    }

    // Surface 1 ↔ surface 2: the roster IS the three ruled Vault signers.
    // Q5-A: post-rotation the same intent is checked live-vs-live and
    // install-vs-install instead, because the pin and the init payload no
    // longer describe the same moment in time.
    match rotated {
        None => {
            if !ordered_bytes_equal(&pin.members, vault_signers) {
                v.push(rv(format!(
                    "surface 1 != surface 2: pinned recovery members [{}] are not the exact \
                     ordered byte-vector of the ruled Vault signers [{}]",
                    render(&pin.members),
                    render(vault_signers)
                )));
            }
        }
        Some(l) => {
            if !ordered_bytes_equal(&l.last_upgrader_new_members, &l.last_vault_new_members) {
                v.push(rv(format!(
                    "live cross-plane: upgrader != vault: the last EXECUTED \
                     [[rotation.upgrader]] row's new_members [{}] are not the exact ordered \
                     byte-vector of the last EXECUTED [[rotation.vault]] row's new_members [{}]",
                    render(&l.last_upgrader_new_members),
                    render(&l.last_vault_new_members)
                )));
            }
            if l.last_upgrader_new_threshold != l.last_vault_new_threshold {
                v.push(rv(format!(
                    "live cross-plane: upgrader != vault: the last EXECUTED rows' new_threshold \
                     values are {} (upgrader) and {} (vault)",
                    l.last_upgrader_new_threshold, l.last_vault_new_threshold
                )));
            }
            if !ordered_bytes_equal(&l.bootstrap_upgrader_members, &l.bootstrap_vault_signers) {
                v.push(rv(format!(
                    "install cross-plane: bootstrap upgrader_members != bootstrap \
                     vault_signers: [{}] is not the exact ordered byte-vector of [{}]",
                    render(&l.bootstrap_upgrader_members),
                    render(&l.bootstrap_vault_signers)
                )));
            }
            if l.bootstrap_upgrader_threshold != l.bootstrap_vault_threshold {
                v.push(rv(format!(
                    "install cross-plane: bootstrap upgrader_members != bootstrap \
                     vault_signers: thresholds are {} (upgrader) and {} (vault)",
                    l.bootstrap_upgrader_threshold, l.bootstrap_vault_threshold
                )));
            }
        }
    }

    // Surface 3 — the install payload as actually encoded.
    match upgrader_init {
        None => v.push(rv(format!(
            "{UPGRADER_INIT_ARTIFACT} is missing or unparseable — fails CLOSED, never skipped. \
             Without it the gate verifies nothing about the roster that will actually be \
             installed"
        ))),
        Some((members, threshold, vault)) => {
            v.extend(audit_surface("3 (upgrader_init.did)", members));
            match rotated {
                None => {
                    if !ordered_bytes_equal(members, &pin.members) {
                        v.push(rv(format!(
                            "surface 3 != surface 1: {UPGRADER_INIT_ARTIFACT} recovery_members \
                             [{}] are not the exact ordered byte-vector of the pinned roster [{}]",
                            render(members),
                            render(&pin.members)
                        )));
                    }
                    if threshold != pin.threshold {
                        v.push(rv(format!(
                            "surface 3 threshold {threshold} != pinned recovery threshold {}",
                            pin.threshold
                        )));
                    }
                }
                Some(l) => {
                    if !ordered_bytes_equal(members, &l.bootstrap_upgrader_members) {
                        v.push(rv(format!(
                            "init != bootstrap (upgrader plane): {UPGRADER_INIT_ARTIFACT} \
                             recovery_members [{}] are not the exact ordered byte-vector of \
                             [rotation.bootstrap].upgrader_members [{}]",
                            render(members),
                            render(&l.bootstrap_upgrader_members)
                        )));
                    }
                    if threshold != l.bootstrap_upgrader_threshold {
                        v.push(rv(format!(
                            "init != bootstrap (upgrader plane): surface 3 threshold {threshold} \
                             != [rotation.bootstrap].upgrader_threshold {}",
                            l.bootstrap_upgrader_threshold
                        )));
                    }
                    if !ordered_bytes_equal(&pin.members, &l.last_upgrader_new_members) {
                        v.push(rv(format!(
                            "pin != ledger (upgrader plane): pinned recovery members [{}] are \
                             not the exact ordered byte-vector of the last EXECUTED \
                             [[rotation.upgrader]] row's new_members [{}]",
                            render(&pin.members),
                            render(&l.last_upgrader_new_members)
                        )));
                    }
                    if pin.threshold != l.last_upgrader_new_threshold {
                        v.push(rv(format!(
                            "pin != ledger (upgrader plane): pinned recovery threshold {} != the \
                             last EXECUTED [[rotation.upgrader]] row's new_threshold {}",
                            pin.threshold, l.last_upgrader_new_threshold
                        )));
                    }
                }
            }
            if vault.as_slice() != pin.vault.as_slice() {
                v.push(rv(format!(
                    "surface 3 vault {} != pinned vault {} — the Upgrader's fixed target must be \
                     the ruled Vault principal",
                    vault.to_text(),
                    pin.vault.to_text()
                )));
            }
            // Separation: the counterpart must never be a member of the roster
            // that recovers it, and must never be anonymous.
            if *vault == candid::Principal::anonymous() {
                v.push(rv("surface 3 vault is the anonymous principal".into()));
            }
            if members.contains(vault) {
                v.push(rv(format!(
                    "surface 3: vault {} is also a recovery member — the counterpart must be \
                     separate from the roster that recovers it",
                    vault.to_text()
                )));
            }
        }
    }
    v
}

/// IO wrapper for the roster binding. Takes the already-encoded Vault init
/// payload so surface 2 is read from the same bytes the authority binding
/// checked — not re-derived from a different read.
pub fn check_recovery_roster(root: &Path, encoded_vault_init: &[u8]) -> Vec<Violation> {
    let vault_signers = match vault_init_quorum(encoded_vault_init) {
        Ok((s, _, _)) => s,
        Err(e) => {
            return vec![Violation::RecoveryRosterViolation {
                detail: format!("cannot decode vault init quorum for surface 2: {e}"),
            }]
        }
    };
    let pinned = match load_recovery_record(root) {
        Ok(r) => r,
        Err(e) => {
            return vec![Violation::RecoveryRosterViolation {
                detail: format!("cannot load pinned recovery record: {e}"),
            }]
        }
    };
    // Surface 3: encode the committed artifact exactly as the install will.
    let artifact = root.join(UPGRADER_INIT_ARTIFACT);
    let decoded = if artifact.is_file() {
        encode_init_artifact(&artifact)
            .and_then(|enc| upgrader_init_roster(&enc))
            .ok()
    } else {
        None
    };
    let surface3 = decoded
        .as_ref()
        .map(|(m, t, vlt)| (m.as_slice(), *t, vlt));
    let lockstep = match load_rotation_lockstep(root) {
        Ok(l) => l,
        Err(e) => {
            // Fail closed, for the same reason as the authority binding: an
            // unreadable ledger state leaves the checker unable to know which
            // comparison is the correct one.
            return vec![Violation::RecoveryRosterViolation {
                detail: format!(
                    "cannot load the rotation lockstep from {VAULT_AUTHORITY_RECORD}: {e}"
                ),
            }];
        }
    };
    recovery_roster_violations_with_rotation(
        pinned.as_ref(),
        &vault_signers,
        surface3,
        Some(&lockstep),
    )
}

// ── R5.3: the gate must not report GREEN on incomplete launch evidence ───────

/// `build.source_sha` must name a REAL commit in THIS repository's history,
/// at or before the tree being checked.
///
/// ── SEMANTICS CHOSEN: RECORDED-ANCESTOR (not exact-match) ────────────────────
///
/// The S10 adjudication offered exact-match or recorded-ancestor and required
/// the choice be documented. **Exact-match is unsatisfiable by construction**,
/// so recorded-ancestor is the only sound option — this is a forced choice, not
/// a preference:
///
/// The release record is a COMMITTED file. The commit that introduces or
/// refreshes it cannot contain its own SHA — the SHA is a hash over the tree
/// that contains the file, so writing it into that file changes it. Requiring
/// `source_sha == HEAD` would therefore fail on every commit that ever writes
/// the record, including the final integrated commit. That is the S10
/// child-commit self-reference, and it is solved here rather than used as a
/// reason to accept any string.
///
/// The rule enforced instead: `source_sha` must
///   1. resolve to an existing **commit object** in this repository, and
///   2. be an ancestor of — or equal to — the checked `HEAD`.
///
/// Fail-closed properties: a fabricated value (`deadbeef`) has no commit object
/// and is rejected; a real commit from an unrelated branch or repository is not
/// an ancestor and is rejected; a root with no usable git metadata is rejected
/// rather than skipped.
///
/// ── LIMITATION, STATED ───────────────────────────────────────────────────────
/// Ancestry proves the recorded commit is genuinely in the history leading to
/// the tree being checked. It does NOT by itself prove the pinned bytes were
/// produced at that commit — that binding comes from the artifact SHA-256
/// comparison below plus the R2.6 independent reproductions. Ancestry closes
/// fabricated provenance; it is not a substitute for reproduction, and the
/// cross-machine reproduction gap remains a disclosed holistic condition.
pub fn check_source_provenance(root: &Path, sha: &str) -> Vec<Violation> {
    let git = |args: &[&str]| -> Result<std::process::Output, String> {
        std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .map_err(|e| format!("cannot invoke git: {e}"))
    };
    // The value must be a commit object. `<sha>^{commit}` fails for a
    // non-existent object AND for an object that is not a commit.
    match git(&["cat-file", "-e", &format!("{sha}^{{commit}}")]) {
        Err(e) => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "cannot authenticate build.source_sha `{sha}`: {e}. Provenance that cannot \
                     be checked is not bound — this fails closed, never skips"
                ),
            }]
        }
        Ok(o) if !o.status.success() => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "build.source_sha `{sha}` is not a commit object in this repository — the \
                     record names a source that does not exist. Release identity must name a \
                     REAL commit, not an arbitrary string"
                ),
            }]
        }
        Ok(_) => {}
    }
    // …and it must be in the history of the tree being checked.
    match git(&["merge-base", "--is-ancestor", sha, "HEAD"]) {
        Err(e) => vec![Violation::ReleaseIdentityUnbound {
            detail: format!("cannot check ancestry of build.source_sha `{sha}`: {e}"),
        }],
        Ok(o) if !o.status.success() => vec![Violation::ReleaseIdentityUnbound {
            detail: format!(
                "build.source_sha `{sha}` is a commit but is NOT an ancestor of HEAD — the \
                 record names a source outside the history of the tree being checked. \
                 Recorded-ancestor semantics: the pinned source must be at or before HEAD"
            ),
        }],
        Ok(_) => Vec::new(),
    }
}

/// Recorded toolchain versions must equal the ACTIVE toolchain at check time.
///
/// The repository pins no toolchain (no `rust-toolchain.toml`) — a named,
/// still-open gap. That makes this check MORE necessary, not less: with nothing
/// enforcing which compiler runs, a record whose `rust_version` was copied from
/// another machine would otherwise pass while describing a build that did not
/// happen here.
///
/// Normalization: the recorded value is the tool's own version string with the
/// program-name prefix removed — `rustc -V` prints
/// `rustc 1.95.0 (59807616e 2026-04-14)`, and the record holds
/// `1.95.0 (59807616e 2026-04-14)`. Both sides are stripped of a leading
/// program name and whitespace-collapsed, then compared exactly; the commit
/// hash and date are part of the identity and are not discarded.
///
/// Fails closed when the tool cannot be invoked.
pub fn check_tool_version(bin: &str, recorded: &str) -> Vec<Violation> {
    let norm = |s: &str| -> String {
        let s = s.trim();
        let s = s.strip_prefix(bin).unwrap_or(s);
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let out = match std::process::Command::new(bin).arg("-V").output() {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "`{bin} -V` exited {} — the active toolchain cannot be identified, so the \
                     recorded `{recorded}` cannot be authenticated. Fails closed",
                    o.status
                ),
            }]
        }
        Err(e) => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "cannot invoke `{bin} -V`: {e} — the active toolchain cannot be identified, \
                     so the recorded `{recorded}` cannot be authenticated. Fails closed"
                ),
            }]
        }
    };
    let active = match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!("`{bin} -V` output is not UTF-8: {e}"),
            }]
        }
    };
    if norm(&active) != norm(recorded) {
        return vec![Violation::ReleaseIdentityUnbound {
            detail: format!(
                "recorded {bin} version `{}` != active `{}` — the release record describes a \
                 toolchain that is not the one building here. The toolchain is part of release \
                 identity, and this repository pins none, so the recorded value must match the \
                 compiler actually in use",
                norm(recorded),
                norm(&active)
            ),
        }];
    }
    Vec::new()
}

/// Release identity (R2.5/R5.3). The record itself lands at S10 — it must be
/// produced from the FINAL integrated commit, so pinning it earlier guarantees
/// stale hashes. This check exists now so the fail-closed control is in place
/// before the artifact arrives to satisfy it. Until then it reports UNBOUND,
/// which is the intended state: a complete release gate is deliberately not
/// passable before S10.
/// S11-6 — the paths whose modification since `build.asserts_identity_at`
/// disarms the byte-equality claim.
///
/// Committed constant per CTO_ADJUDICATION_S11_RETURN_AND_S11_6_DISPATCH_2026-08-13.md
/// §2 requirement 2, which also fixes this exact list.
///
/// **UNDER-INCLUSION IS FAIL-SAFE, OVER-INCLUSION IS MERELY CONSERVATIVE.** If
/// an unlisted input changes the bytes while the arm fires, byte-equality
/// FAILS RED — the comparison is still made, so the worst case is a loud
/// failure, never a false green. If a listed path changes without affecting the
/// bytes, the claim merely goes non-asserting until the record is rebound.
/// That asymmetry is why the list can be short and readable rather than an
/// exhaustive derivation of the build graph.
pub const BUILD_INPUT_PATHS: [&str; 4] = [
    "canisters/",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
];

/// The commits since `since` that touch any [`BUILD_INPUT_PATHS`] entry.
struct QuiescenceOutcome {
    /// One line per touching commit (`<short sha> <subject>`), for the typed
    /// non-assertion message. Empty means quiescent, i.e. ARMED.
    touching: Vec<String>,
}

/// Enumerate production-build-input changes in `since..HEAD`.
///
/// `Err` on any git failure — the caller turns that into a fail-closed
/// violation rather than treating an unreadable range as quiescent, which would
/// be the fail-open version of this check.
fn production_changes_since(root: &Path, since: &str) -> Result<QuiescenceOutcome, String> {
    let mut args: Vec<String> = vec![
        "-C".into(),
        root.to_string_lossy().into_owned(),
        "log".into(),
        "--oneline".into(),
        "--no-decorate".into(),
        format!("{since}..HEAD"),
        "--".into(),
    ];
    args.extend(BUILD_INPUT_PATHS.iter().map(|p| (*p).to_string()));
    let out = std::process::Command::new("git")
        .args(&args)
        .output()
        .map_err(|e| format!("cannot invoke git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git log {since}..HEAD failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(QuiescenceOutcome {
        touching: String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

pub fn check_release_identity(root: &Path) -> Vec<Violation> {
    let path = root.join(RELEASE_RECORD_ARTIFACT);
    if !path.is_file() {
        return vec![Violation::ReleaseIdentityUnbound {
            detail: format!(
                "{RELEASE_RECORD_ARTIFACT} does not exist — no toolchain, canonical build \
                 invocation, feature set, or Wasm SHA-256 is pinned. Installed Wasm hashes must \
                 derive from the exact reviewed tree; an unbound release is not installable"
            ),
        }];
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!("cannot read {RELEASE_RECORD_ARTIFACT}: {e}"),
            }]
        }
    };
    let doc: toml::Value = match toml::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            return vec![Violation::ReleaseIdentityUnbound {
                detail: format!("malformed {RELEASE_RECORD_ARTIFACT}: {e}"),
            }]
        }
    };
    let mut v = Vec::new();
    let mut require = |key: &str| {
        let present = key
            .split('.')
            .try_fold(&doc, |acc, seg| acc.get(seg))
            .and_then(|x| x.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !present {
            v.push(Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "{RELEASE_RECORD_ARTIFACT} is missing required release-identity field \
                     `{key}` — the canonical build invocation is PART of release identity, not \
                     metadata about it"
                ),
            });
        }
    };
    require("toolchain.rust_version");
    require("toolchain.cargo_version");
    require("build.command");
    require("build.features");
    require("build.source_sha");
    // S11-5: WHERE the byte-equality claim holds. Required like every other
    // release-identity field — a record that does not say where its bytes are
    // claimed to match is not bound, and its absence must not silently mean
    // "everywhere" (the previous behaviour) or "nowhere" (a fail-open skip).
    require("build.asserts_identity_at");

    // ── PROVENANCE AUTHENTICATION (SSA S10-R2) ───────────────────────────────
    //
    // Presence checks alone let a record assert ANY source commit and ANY
    // toolchain and still pass: the `deadbeef` positive fixture passed while
    // naming a commit that does not exist. A gate that calls those fields
    // "release identity" must reject false values, not merely empty ones.
    // Both checks below FAIL CLOSED — an error reading git or invoking the
    // toolchain is a violation, never a skip.
    let get = |key: &str| -> Option<String> {
        key.split('.')
            .try_fold(&doc, |acc, seg| acc.get(seg))
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    if let Some(sha) = get("build.source_sha") {
        v.extend(check_source_provenance(root, &sha));
    }
    if let Some(rec) = get("toolchain.rust_version") {
        v.extend(check_tool_version("rustc", &rec));
    }
    if let Some(rec) = get("toolchain.cargo_version") {
        v.extend(check_tool_version("cargo", &rec));
    }

    // ── S11-6: IS THE BYTE-EQUALITY CLAIM ARMED AT THIS HEAD? ───────────────
    //
    // CTO ruling S11 R5.3 (identity scope, shape (b)) as SUPERSEDED IN PART by
    // CTO_ADJUDICATION_S11_RETURN_AND_S11_6_DISPATCH_2026-08-13.md §2 — the
    // ARMING CONDITION ONLY. Shape (b) itself, its rejection of
    // re-pin-per-head and standing-red, and its fail-closed requirements all
    // remain in force.
    //
    // WHY THE ARMING CONDITION CHANGED. S11-5 armed on `HEAD ==
    // asserts_identity_at`. SSA's landed-diff review found that UNSATISFIABLE
    // in a clean committed record: the record is a committed file, a commit's
    // SHA is a hash over the tree containing it, so no commit can record its
    // own SHA. The arm could therefore only ever fire on a DIRTY tree — which
    // is exactly how the S11-5 positive test passed, and that dependency was
    // the symptom. This is the same self-reference the S10 ratification already
    // solved for `source_sha` by adopting recorded-ancestor semantics.
    //
    // THE REALIZABLE CONDITION: arm on PRODUCTION-SOURCE QUIESCENCE since the
    // binding commit. `asserts_identity_at` keeps its meaning — the commit
    // whose tree the recorded bytes were built from — and the claim binds for
    // as long as nothing since that commit has touched a production build
    // input. A record-only or docs-only child therefore ARMS, which is what
    // makes the release ceremony committable at all.
    //
    // FAIL CLOSED throughout: an unreadable git, a value that is not a commit
    // object, an unresolvable HEAD, or a range that cannot be enumerated is a
    // violation, exactly as `check_source_provenance` treats the same failures.
    let asserts_at = get("build.asserts_identity_at");
    let head = match std::process::Command::new("git")
        .args(["-C", &root.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
    {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(_) | Err(_) => None,
    };
    // The asserting commit must itself be REAL — the same standard
    // `build.source_sha` is held to. A record may not claim identity at an
    // invented commit and thereby become permanently non-asserting, which would
    // be a fail-open disguised as a typed outcome.
    // Requirement 1, first clause: the asserting commit must be REAL and must be
    // IDENTICAL-OR-ANCESTOR of HEAD — the same standard `build.source_sha` is
    // held to, and `check_source_provenance` is exactly that check. A record may
    // not claim identity at an invented commit and thereby become permanently
    // non-asserting, which would be a fail-open disguised as a typed outcome.
    let provenance_ok = match asserts_at.as_deref() {
        Some(a) => {
            let viols: Vec<Violation> = check_source_provenance(root, a)
                .into_iter()
                .map(|viol| match viol {
                    Violation::ReleaseIdentityUnbound { detail } => {
                        Violation::ReleaseIdentityUnbound {
                            detail: detail.replace("build.source_sha", "build.asserts_identity_at"),
                        }
                    }
                    other => other,
                })
                .collect();
            let ok = viols.is_empty();
            v.extend(viols);
            ok
        }
        None => false,
    };
    let mut quiescence: Option<QuiescenceOutcome> = None;
    let asserting_head = match (asserts_at.as_deref(), head.as_deref()) {
        // Missing field is already a violation above; an unresolvable HEAD is
        // one here. Neither may be treated as "asserting".
        (_, None) => {
            v.push(Violation::ReleaseIdentityUnbound {
                detail: "cannot resolve HEAD to compare against \
                         build.asserts_identity_at — release identity that cannot be located \
                         is not bound; this fails closed, never skips"
                    .into(),
            });
            false
        }
        (None, Some(_)) => false,
        // Provenance already failed (not a commit, or not an ancestor). Do not
        // arm, and do not add a second attribution for the same defect.
        (Some(_), Some(_)) if !provenance_ok => false,
        (Some(a), Some(_)) => {
            // Requirement 1, second clause: PRODUCTION-SOURCE QUIESCENCE.
            match production_changes_since(root, a) {
                Err(e) => {
                    v.push(Violation::ReleaseIdentityUnbound {
                        detail: format!(
                            "cannot enumerate production changes since \
                             build.asserts_identity_at `{a}`: {e}. A range that cannot be \
                             read cannot establish quiescence — this fails closed, never skips"
                        ),
                    });
                    false
                }
                Ok(outcome) => {
                    let armed = outcome.touching.is_empty();
                    quiescence = Some(outcome);
                    armed
                }
            }
        }
    };

    // Pinned hashes must equal the built artifacts when those are present —
    // AT THE ASSERTING HEAD. At any other head the hashes are still checked for
    // WELL-FORMEDNESS (present, non-empty, 64 lowercase hex) and the typed
    // non-assertion is reported; they are never compared, and never pass.
    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    for (pkg, file) in crate::INLINE_PAYLOAD_ARTIFACTS {
        let pinned = doc
            .get("wasm")
            .and_then(|w| w.get(pkg))
            .and_then(|p| p.get("sha256"))
            .and_then(|s| s.as_str())
            .map(str::to_ascii_lowercase);
        let Some(pinned) = pinned.filter(|s| !s.trim().is_empty()) else {
            v.push(Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "{RELEASE_RECORD_ARTIFACT} pins no sha256 for `{pkg}` — the production Wasm \
                     hash is unbound"
                ),
            });
            continue;
        };
        // WELL-FORMEDNESS, checked at EVERY head. A pinned value that is not a
        // sha256 is malformed wherever it sits, and catching it only at the
        // release commit would surface it at the worst possible moment.
        if pinned.len() != 64 || !pinned.chars().all(|c| c.is_ascii_hexdigit()) {
            v.push(Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "{RELEASE_RECORD_ARTIFACT} pins a malformed sha256 for `{pkg}` \
                     (`{pinned}`) — expected 64 hex digits"
                ),
            });
            continue;
        }
        if !asserting_head {
            // TYPED NON-ASSERTION. Not a pass: the caller receives a violation
            // and cannot mistake this head for one where the bytes were bound.
            let why = match &quiescence {
                Some(q) if !q.touching.is_empty() => {
                    let shown: Vec<&str> =
                        q.touching.iter().take(5).map(String::as_str).collect();
                    let more = q.touching.len().saturating_sub(shown.len());
                    format!(
                        "{} commit(s) since then touch production build inputs ({}){}: {}",
                        q.touching.len(),
                        BUILD_INPUT_PATHS.join(", "),
                        if more > 0 { format!(", {more} more not shown") } else { String::new() },
                        shown.join(" | "),
                    )
                }
                _ => "the binding commit could not be established as quiescent".to_string(),
            };
            v.push(Violation::ReleaseIdentityNotAsserted {
                package: pkg.to_string(),
                detail: format!(
                    "`{pkg}` sha256 is pinned for commit `{}` (HEAD is `{}`) — {why}. The \
                     pinned bytes are NOT claimed to match a build of this tree, so {file} \
                     was not compared",
                    asserts_at.as_deref().unwrap_or("<unset>"),
                    head.as_deref().unwrap_or("<unresolved>"),
                ),
            });
            continue;
        }
        let built = wasm_dir.join(file);
        if !built.is_file() {
            // FAILS CLOSED. Deferring to the separate §8 size gate was
            // fail-open: `--deploy-time --coverage-only` runs this check while
            // SKIPPING the size gate, so an absent Wasm meant a pinned hash was
            // accepted having never been compared to anything. A release hash
            // that was not checked against a built artifact is not bound.
            v.push(Violation::ReleaseIdentityUnbound {
                detail: format!(
                    "production {file} is not built — a pinned sha256 that is never compared \
                     against a built artifact is UNBOUND. Build it before the deploy gate; \
                     absence is never a skip"
                ),
            });
            continue;
        }
        match std::fs::read(&built) {
            Err(e) => v.push(Violation::ReleaseIdentityUnbound {
                detail: format!("cannot read built {file}: {e}"),
            }),
            Ok(bytes) => {
                use sha2::{Digest, Sha256};
                let actual = format!("{:x}", Sha256::digest(&bytes));
                if actual != pinned {
                    v.push(Violation::ReleaseIdentityUnbound {
                        detail: format!(
                            "built {file} sha256 {actual} != pinned {pinned} — the installed \
                             artifact does not derive from the reviewed tree"
                        ),
                    });
                }
            }
        }
    }
    v
}

/// Creation receipts and born-under-Vault targets (R5.3). The manifest can
/// legitimately carry zero receipts while the Vault does not exist — that is a
/// BUILD-time truth. At DEPLOY time it is a blocker: the gate must not go GREEN
/// into bootstrap-controller removal with no evidence that the targets it
/// declares were actually created by the Vault.
pub fn check_launch_evidence(manifest: &Manifest) -> Vec<Violation> {
    let mut v = Vec::new();
    let born: Vec<&Entry> = manifest
        .canisters
        .iter()
        .filter(|e| e.disposition == Disposition::BornUnderVault)
        .collect();

    if born.is_empty() {
        v.push(Violation::LaunchEvidenceIncomplete {
            obligation: LaunchObligation::NoTargets,
            detail: "the manifest declares NO born-under-Vault targets — at deploy time the ring \
                     and its born-under-Vault set must be declared, not empty"
                .into(),
        });
        return v;
    }
    if manifest.sources.d5.receipts.is_empty() {
        v.push(Violation::LaunchEvidenceIncomplete {
            obligation: LaunchObligation::D5Receipts,
            detail: format!(
                "{} born-under-Vault targets declared, but D5 carries ZERO creation receipts \
                 (status `{}`). Deploy-time evidence that the Vault actually created these \
                 canisters is missing",
                born.len(),
                manifest.sources.d5.status
            ),
        });
    }
    // Every declared target carrying a principal must have its receipt.
    let receipted: std::collections::BTreeSet<&str> = manifest
        .sources
        .d5
        .receipts
        .iter()
        .map(|r| r.principal.as_str())
        .collect();
    for e in &born {
        if let Some(p) = e.principal.as_deref() {
            if !receipted.contains(p) {
                v.push(Violation::LaunchEvidenceIncomplete {
                    obligation: LaunchObligation::Unreceipted(p.to_string()),
                    detail: format!(
                        "born-under-Vault target {p} has no D5 creation receipt — a declared \
                         target with no receipt is unproven provenance"
                    ),
                });
            }
        }
    }
    v
}

// ── R2.3 surface 4: operator-attested live membership readback ───────────────
//
// PROVENANCE, STATED ONCE AND PLAINLY: this validator compares RECORDED BYTES
// against the pin. It CANNOT prove those bytes came from the live signer-gated
// query on the real Upgrader. `get_recovery_membership` is recovery-signer
// gated and returns an indistinguishable `None` to non-members, so the read is
// performable only by the three ruled principals — all Owner's keys, from the
// device, as runbook steps. No custody identity ever enters an agent session or
// CI. A PASS here means "the attested bytes match the pin", never "the live
// Upgrader was observed". Do not let a checked attestation read as a proof.
//
// Validation is PURE and in-memory. Wiring it to the on-disk evidence files
// (`<EVID>/surface4_readback_{1,2,3}.txt`) is BLOCKED on the §10 item 3 ruling
// that fixes the evidence root — there is no committed path to read yet.

/// One operator-attested readback of `get_recovery_membership()`.
///
/// SCHEMA IS INCOMPLETE BY DESIGN until §10 item 3 fixes the evidence root.
/// The fields below are the ones this pure validator can act on. When the IO
/// wiring lands, the on-disk record must ALSO retain, and this struct must
/// carry and check:
///   * the exact command as run,
///   * the complete unedited output,
///   * the SHA-256 of that output.
/// They are omitted here rather than stubbed because an unvalidated field is
/// indistinguishable from a checked one at a glance — which is the failure mode
/// this whole section exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipAttestation {
    /// Which ruled recovery principal performed the read (identity label).
    pub read_by: candid::Principal,
    /// Free-text signer identity label as recorded in the evidence file.
    pub signer_label: String,
    pub network: String,
    pub observed_at: String,
    /// The Upgrader the read was performed against.
    pub upgrader: candid::Principal,
    /// `None` = the query returned `None` (non-member, or not yet installed).
    pub members: Option<Vec<candid::Principal>>,
    pub threshold: Option<u32>,
}

/// PURE surface-4 validation. Per R2.3 the read is repeated from EVERY intended
/// recovery principal — three reads — and any `None`, any disagreement, or any
/// stale/incomplete evidence HALTS cutover.
pub fn attestation_violations(
    pinned: Option<&RecoveryRecord>,
    expected_upgrader: &candid::Principal,
    attestations: &[MembershipAttestation],
) -> Vec<Violation> {
    let mut v = Vec::new();
    let rv = |detail: String| Violation::RecoveryRosterViolation { detail };

    let Some(pin) = pinned else {
        v.push(rv(
            "surface 4: no pinned recovery record to compare the attested membership against"
                .into(),
        ));
        return v;
    };

    if attestations.is_empty() {
        v.push(rv(format!(
            "surface 4: NO membership attestations recorded — the readback must be performed \
             from every intended recovery principal ({} reads) immediately before \
             bootstrap-controller removal. Absence fails closed, never skipped",
            pin.members.len()
        )));
        return v;
    }

    // One read per ruled recovery principal — no more, no fewer, no duplicates.
    let mut readers = std::collections::BTreeSet::new();
    for a in attestations {
        if !readers.insert(a.read_by) {
            v.push(rv(format!(
                "surface 4: duplicate attestation from reader {} — one read per ruled principal",
                a.read_by.to_text()
            )));
        }
        if !pin.members.contains(&a.read_by) {
            v.push(rv(format!(
                "surface 4: attestation from {} which is NOT a pinned recovery member — an \
                 attestation from an unruled reader is not evidence",
                a.read_by.to_text()
            )));
        }
    }
    for m in &pin.members {
        if !readers.contains(m) {
            v.push(rv(format!(
                "surface 4: no attestation from ruled recovery principal {} — the read is \
                 required from EVERY intended recovery principal",
                m.to_text()
            )));
        }
    }

    for a in attestations {
        let who = a.read_by.to_text();
        if a.network.trim().is_empty() {
            v.push(rv(format!("surface 4 ({who}): attestation records no network")));
        }
        if a.observed_at.trim().is_empty() {
            v.push(rv(format!(
                "surface 4 ({who}): attestation records no observation time — undated evidence \
                 cannot be shown to be fresh"
            )));
        }
        if a.signer_label.trim().is_empty() {
            v.push(rv(format!("surface 4 ({who}): attestation records no signer identity label")));
        }
        if a.upgrader.as_slice() != expected_upgrader.as_slice() {
            v.push(rv(format!(
                "surface 4 ({who}): read against {} but the pinned Upgrader is {}",
                a.upgrader.to_text(),
                expected_upgrader.to_text()
            )));
        }
        match (&a.members, a.threshold) {
            // `None` is the gated-query answer for a non-member. From a ruled
            // recovery principal it means the roster is NOT what was pinned.
            (None, _) | (_, None) => v.push(rv(format!(
                "surface 4 ({who}): query returned None — HALTS cutover. From a ruled recovery \
                 principal a `None` means the installed roster does not contain this principal"
            ))),
            (Some(members), Some(threshold)) => {
                if !ordered_bytes_equal(members, &pin.members) {
                    v.push(rv(format!(
                        "surface 4 ({who}): attested membership [{}] != pinned roster [{}] as an \
                         ordered byte-vector",
                        render(members),
                        render(&pin.members)
                    )));
                }
                if threshold != pin.threshold {
                    v.push(rv(format!(
                        "surface 4 ({who}): attested threshold {threshold} != pinned {}",
                        pin.threshold
                    )));
                }
            }
        }
    }
    v
}

// ── B-6 / O-10: WALLET BUNDLE PIN COVERAGE ───────────────────────────────────
//
// THE GAP THIS CLOSES. Until this lane, `grep -rn wallet_bundle
// scripts/verify_custody_manifest/` returned nothing: `check_release_identity`
// parses `release_hashes.toml` as a generic `toml::Value` and requires exactly
// six `toolchain.*` / `build.*` keys. The bundle tables were therefore UNCHECKED
// PINS, and the record said so about itself, repeatedly, in its own comments.
// `[wallet_bundle]` is the only pin the Poseidon wallet-crypto wasm has, and the
// bundle is what a user's browser executes.
//
// THERE ARE TWO TABLES, INSTALLED IN A FIXED ORDER, ONTO THE SAME CANISTER.
// `[wallet_bundle_transitional]` installs at Phase B.1; `[wallet_bundle]`
// supersedes it at Phase D.8. Covering one and not the other would leave the
// install that happens FIRST unverified — and the transitional bundle carries
// the property (`derivationOrigin` ABSENT) that the step-7 signer rotation
// depends on. Getting it backwards is governance-fatal and silent.
//
// WHY THIS IS NOT WIRED INTO THE DEPLOY-TIME GATE (stated, not hidden).
// `--deploy-posture` compares the OBSERVED violation-key set to the DECLARED
// `[deploy_gate].expected_pending` set in `deployment/mainnet/custody_manifest.toml`
// for EXACT set equality. A new kind that fires against the live record would
// therefore turn the gate red unless that record declared it — and editing
// `deployment/mainnet/*` is out of scope for the lane that added this check
// (the record is READ here, never written). So this check is its own CLI mode,
// `--wallet-bundles`, and wiring it into the gate is a follow-up that belongs
// with the record edit, not ahead of it. A checker weakened to fit a wrong
// record would be worse than no checker; so would one that silently re-declared
// the record's own pending set.

/// The two wallet-bundle tables, in RECORD order. The transitional table is
/// the Phase B.1 install and the plain table is the Phase D.8 install; see
/// [`WALLET_BUNDLE_PHASE_ORDER`].
pub const WALLET_BUNDLE_TABLES: [&str; 2] = ["wallet_bundle", "wallet_bundle_transitional"];

/// HARDEN-03 (D-1): the permitted values of `[wallet_bundle_release].variant`,
/// POSITIONALLY paired with [`WALLET_BUNDLE_TABLES`] — `variant[i]` names
/// `WALLET_BUNDLE_TABLES[i]`. The pairing is positional rather than a second
/// literal list of table names so the two cannot drift apart by editing one.
///
/// WHY A NAME AND NOT A SECOND MARKER OR A CLI FLAG. Two markers can disagree
/// (`held` + `releasing`) and nothing in the record would say which wins; a CLI
/// flag is a second source of truth that leaves no trace in the commit, and every
/// other authority in this tool is the record. One bit (`state`) plus one name
/// (`variant`) is sufficient because `check_wallet_bundles` already requires the
/// two recorded digests DISTINCT: a mis-declared variant over a correctly-built
/// `dist` therefore fails on the digest comparison, and a `dist` that is neither
/// bundle already fails today.
pub const WALLET_BUNDLE_VARIANTS: [&str; 2] = ["final", "transitional"];

/// The record table a declared `variant` selects, or `None` for an unrecognised
/// name. Never guesses: an unrecognised variant is refused by the caller for the
/// same reason an unrecognised `state` is.
pub fn wallet_bundle_table_for_variant(variant: &str) -> Option<&'static str> {
    WALLET_BUNDLE_VARIANTS
        .iter()
        .position(|v| *v == variant)
        .map(|i| WALLET_BUNDLE_TABLES[i])
}

/// The OTHER table — the one the declared variant did NOT select. Used only to
/// make a cross-variant failure legible (D-2): a measured digest that equals the
/// other variant's pin means the wrong bundle was built, which is a different
/// mistake from a stale or corrupt one and deserves a different sentence.
fn wallet_bundle_other_table(variant: &str) -> Option<&'static str> {
    WALLET_BUNDLE_VARIANTS
        .iter()
        .position(|v| *v == variant)
        .map(|i| WALLET_BUNDLE_TABLES[1 - i])
}

/// The install phases, in the order the record documents them: the
/// transitional bundle first, superseded by the final bundle. Used to check
/// `install_phase` coherence so a later edit cannot silently swap which bundle
/// installs first.
pub const WALLET_BUNDLE_PHASE_ORDER: [&str; 2] = ["B.1", "D.8"];

/// The toolchain tuple keys both bundle tables must carry, identically. The
/// record documents the failure this guards: an earlier revision paired node
/// 22.23.1 with npm 10.8.2 — the npm that ships with node 20.20.2 — a tuple
/// that never existed on any host.
pub const WALLET_BUNDLE_TOOLCHAIN_KEYS: [&str; 4] = ["node", "npm", "wasm_pack", "rustc"];

/// M-02 (B-ii): the permitted values of `[wallet_bundle_release].state`.
///
/// `held` — no wallet bundle is being released at this head, so the BYTE
/// measurement is not owed. `releasing` — a bundle IS being released here, and
/// the byte measurement must run and pass.
///
/// The marker exists because the two failure modes it stands between are both
/// worse than a declaration. A byte check that SKIPS when `wallet/dist` is absent
/// restores the exact gap it was added to close (`dist` is gitignored, so absent
/// is the normal state on a fresh clone). A byte check that always FAILS when
/// `dist` is absent turns every routine gate run on every host without the wallet
/// toolchain red. So the record says which it is, the record's own coverage check
/// requires it to say so, and "not measured here" becomes a declared, visible
/// state rather than an inference from silence.
pub const WALLET_BUNDLE_RELEASE_STATES: [&str; 2] = ["held", "releasing"];

/// The scalar fields every bundle table must carry. A missing one is a
/// violation, not a comment.
pub const WALLET_BUNDLE_REQUIRED_FIELDS: [&str; 9] = [
    "sha256",
    "method",
    "path",
    "files",
    "bytes",
    "bytes_method",
    "command",
    "command_expands",
    "source_sha",
];

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Check both `[wallet_bundle*]` tables of the release record (B-6 / O-10).
///
/// Every outcome below is a VIOLATION, never a warning:
///
///  1. both tables present, with every scalar field and the `.toolchain` /
///     `.asset_config` sub-tables;
///  2. `sha256` 64 lowercase hex in both, and the two digests DISTINCT — equal
///     digests mean one table was copy-pasted rather than re-measured;
///  3. `files` agrees with the count `bytes_method` states about itself, and
///     `bytes` is a positive integer of at least `files` bytes;
///  4. the four-key toolchain tuple present in both and IDENTICAL between them;
///  5. `source_sha` authenticated by [`check_source_provenance`] — the same
///     recorded-ancestor semantics the Wasm side uses, REUSED, not re-written;
///  6. `install_phase` on the transitional table names B.1 before D.8;
///  7. `asset_config.sha256` well-formed in both and EQUAL between them — the
///     record states the asset config does not vary by variant;
///  8a. `[wallet_bundle_release]` declares a recognised `state` and a `reason`,
///     plus (HARDEN-03 D-1) a recognised `variant` when and only when the state
///     is `releasing` — see [`check_wallet_bundle_release_marker`].
///     This is the M-02 (B-ii) marker, and requiring it HERE — in the half that
///     is mandatory and needs no `wallet/dist` — is what stops a release
///     proceeding with the byte measurement never having run. Without it,
///     "not measured" would be indistinguishable from "measured and passed".
///  8. `launch_config.derivation_origin` on the transitional table records the
///     key as ABSENT, distinguishably from empty. That distinction IS the
///     invariant Phase B.1 depends on: `evaluateSessionPolicy` refuses a
///     present-but-wrong value and PERMITS an absent one, so a bundle that
///     recorded "" instead of absent would read as satisfied here while
///     re-rooting `app.stsh.fi` at install time.
///  9. (WALLET-V13 O-3) the FINAL table's `source_sha` record carries the same
///     `[wasm.*]` pins as this record, or `[wallet_bundle_release].stale_pins`
///     names exactly the differing set — see ARCHITECTURE.md law 7(g).
///
/// Fails closed: an unreadable or malformed record is a violation, never a skip.
pub fn check_wallet_bundles(root: &Path) -> Vec<Violation> {
    let path = root.join(RELEASE_RECORD_ARTIFACT);
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            return vec![Violation::WalletBundleUnbound {
                detail: format!(
                    "cannot read {RELEASE_RECORD_ARTIFACT}: {e} — the wallet bundle pins cannot \
                     be checked, so they are not bound. Fails closed, never skips"
                ),
            }]
        }
    };
    let doc: toml::Value = match toml::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            return vec![Violation::WalletBundleUnbound {
                detail: format!("malformed {RELEASE_RECORD_ARTIFACT}: {e}"),
            }]
        }
    };

    let mut v = Vec::new();
    let mut digests: Vec<(&str, String)> = Vec::new();
    let mut toolchains: Vec<(&str, Vec<(String, String)>)> = Vec::new();
    let mut asset_shas: Vec<(&str, String)> = Vec::new();

    for table in WALLET_BUNDLE_TABLES {
        let t = match doc.get(table) {
            Some(t) => t,
            None => {
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "{RELEASE_RECORD_ARTIFACT} has no `[{table}]` table — the bundle \
                         installed at that phase is pinned by nothing. Both bundles are \
                         installed onto the same canister, so an absent table does not mean \
                         'no install', it means an UNVERIFIED install"
                    ),
                });
                continue;
            }
        };
        let s = |key: &str| -> Option<String> {
            t.get(key).and_then(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty())
        };
        let i = |key: &str| -> Option<i64> { t.get(key).and_then(|x| x.as_integer()) };

        // (1) structural completeness.
        for field in WALLET_BUNDLE_REQUIRED_FIELDS {
            let present = match field {
                "files" | "bytes" => i(field).is_some(),
                _ => s(field).is_some(),
            };
            if !present {
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table}]` is missing required field `{field}` — it is PART of bundle \
                         identity, not metadata about it: a reader cannot reproduce or verify \
                         the installed bytes without it"
                    ),
                });
            }
        }

        // (2) digest well-formedness; distinctness is checked across tables below.
        match s("sha256") {
            Some(d) if is_lower_hex64(&d) => digests.push((table, d)),
            Some(d) => v.push(Violation::WalletBundleUnbound {
                detail: format!(
                    "`[{table}].sha256` = `{d}` is not 64 lowercase hex characters — a pin that \
                     cannot be compared byte-for-byte to a measured manifest is not a pin"
                ),
            }),
            None => {}
        }

        // (3) internal consistency of the counts. `bytes_method` states its own
        //     file count in prose ("sum of the N REGULAR FILE sizes"); that
        //     number and `files` describe the same measurement and must agree.
        //     Parsed from the field's own text, NOT from a literal copied out
        //     of the record — a check whose expected value comes from the
        //     artifact it checks is not independent of it.
        if let (Some(files), Some(method)) = (i("files"), s("bytes_method")) {
            match method
                .split_whitespace()
                .find_map(|w| w.replace(',', "").parse::<i64>().ok())
            {
                Some(stated) if stated != files => v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table}]` is internally inconsistent: `files = {files}` but \
                         `bytes_method` states the byte total is the sum of {stated} files \
                         (`{method}`). The two describe ONE measurement; a disagreement means \
                         one of them was carried forward from a superseded build rather than \
                         re-measured, and a reader cannot tell which"
                    ),
                }),
                Some(_) => {}
                None => v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table}].bytes_method` (`{method}`) states no file count, so \
                         `files = {files}` is cross-checked by nothing. The method must say \
                         what it counted"
                    ),
                }),
            }
        }
        if let (Some(bytes), Some(files)) = (i("bytes"), i("files")) {
            if bytes <= 0 || files <= 0 || bytes < files {
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table}]` records `files = {files}` / `bytes = {bytes}` — not a \
                         possible measurement of a non-empty directory of regular files"
                    ),
                });
            }
        }

        // (4) the paired toolchain tuple.
        let mut tuple: Vec<(String, String)> = Vec::new();
        match t.get("toolchain") {
            None => v.push(Violation::WalletBundleUnbound {
                detail: format!(
                    "`[{table}.toolchain]` is absent — the bundle names no tuple to reproduce \
                     it under, and node/npm/wasm_pack/rustc are part of bundle identity"
                ),
            }),
            Some(tc) => {
                for key in WALLET_BUNDLE_TOOLCHAIN_KEYS {
                    match tc.get(key).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()) {
                        Some(val) => tuple.push((key.to_string(), val.to_string())),
                        None => v.push(Violation::WalletBundleUnbound {
                            detail: format!(
                                "`[{table}.toolchain]` is missing `{key}` — an unpinned tool in \
                                 the build tuple makes the recorded digest unreproducible"
                            ),
                        }),
                    }
                }
                toolchains.push((table, tuple.clone()));
            }
        }

        // (5) recorded-ancestor provenance, REUSING the Wasm-side checker.
        if let Some(sha) = s("source_sha") {
            for viol in check_source_provenance(root, &sha) {
                let detail = match viol {
                    Violation::ReleaseIdentityUnbound { detail } => detail,
                    other => format!("{other}"),
                };
                v.push(Violation::WalletBundleUnbound {
                    detail: format!("`[{table}].source_sha`: {detail}"),
                });
            }
        }

        // (7) the asset config, shipped INTO dist and therefore inside the digest.
        match t.get("asset_config") {
            None => v.push(Violation::WalletBundleUnbound {
                detail: format!(
                    "`[{table}.asset_config]` is absent — the header/CSP/.well-known policy is \
                     shipped inside the measured directory, so an unpinned asset config is an \
                     unpinned part of the bundle"
                ),
            }),
            Some(ac) => match ac.get("sha256").and_then(|x| x.as_str()).map(str::trim) {
                Some(d) if is_lower_hex64(d) => asset_shas.push((table, d.to_string())),
                Some(d) => v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table}.asset_config].sha256` = `{d}` is not 64 lowercase hex"
                    ),
                }),
                None => v.push(Violation::WalletBundleUnbound {
                    detail: format!("`[{table}.asset_config]` pins no sha256"),
                }),
            },
        }
    }

    // (9) WALLET-V13 O-3: the FINAL bundle compiled the record's current
    //     `[wasm.*]` pins (its operator page refuses a Vault Upgrade to any other
    //     hash — record §3y). Content equality of the pin map at
    //     `[wallet_bundle].source_sha` vs this record, over the union of keys;
    //     any difference must be acknowledged EXACTLY in
    //     `[wallet_bundle_release].stale_pins` (an ack that is no longer stale
    //     fires too). `[wallet_bundle_transitional]` is excluded: stale by design.
    let pins = |d: &toml::Value| -> std::collections::BTreeMap<String, String> {
        d.get("wasm").and_then(|w| w.as_table()).map(|w| w.iter().filter_map(|(k, r)|
            r.get("sha256").and_then(|x| x.as_str()).map(|x| (k.clone(), x.to_string()))).collect())
            .unwrap_or_default()
    };
    let now = pins(&doc);
    let sha = doc.get("wallet_bundle").and_then(|t| t.get("source_sha")).and_then(|x| x.as_str());
    if let (Some(sha), false) = (sha.map(str::trim).filter(|x| !x.is_empty()), now.is_empty()) {
        let then = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy(), "show", &format!("{sha}:{RELEASE_RECORD_ARTIFACT}")])
            .output().ok().filter(|o| o.status.success())
            .and_then(|o| toml::from_str::<toml::Value>(&String::from_utf8_lossy(&o.stdout)).ok());
        let stale: std::collections::BTreeSet<String> = match then.as_ref().map(pins) {
            Some(t) => now.keys().chain(t.keys()).filter(|k| now.get(*k) != t.get(*k)).cloned().collect(),
            None => ["<record unreadable at source_sha>".to_string()].into(), // fails closed
        };
        let acked: std::collections::BTreeSet<String> = doc.get("wallet_bundle_release")
            .and_then(|r| r.get("stale_pins")).and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        if stale != acked {
            v.push(Violation::WalletBundleUnbound { detail: format!(
                "`[wallet_bundle]` was built at source_sha `{sha}`, whose [wasm.*] pins differ from \
                 this record's for {stale:?}, but `[wallet_bundle_release].stale_pins` acknowledges \
                 {acked:?}. The operator page compiled into that bundle refuses Vault Upgrades to \
                 the current pins (record §3y). Rebuild the wallet and rebind, or set stale_pins \
                 to exactly that set (ARCHITECTURE.md law 7(g))") });
        }
    }

    // (2, cross-table) two bundles, two artifacts, two digests.
    if digests.len() == 2 && digests[0].1 == digests[1].1 {
        v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "`[{}]` and `[{}]` record the SAME sha256 `{}` — they are different artifacts \
                 installed at different phases (the transitional bundle omits the \
                 `derivationOrigin` key, a 69-byte delta), so equal digests mean one table was \
                 copy-pasted and never re-measured",
                digests[0].0, digests[1].0, digests[0].1
            ),
        });
    }

    // (4, cross-table) the tuples must be IDENTICAL, not merely present.
    if toolchains.len() == 2 && toolchains[0].1 != toolchains[1].1 {
        v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "`[{}.toolchain]` and `[{}.toolchain]` disagree: {:?} vs {:?}. The record \
                 restates the SAME tuple in both tables deliberately, so a reader need not infer \
                 which applied; a divergence is either a spliced tuple (a node↔npm pairing that \
                 never existed on any host — the failure the record documents) or a build the \
                 other table does not describe",
                toolchains[0].0, toolchains[1].0, toolchains[0].1, toolchains[1].1
            ),
        });
    }

    // (7, cross-table) the asset config does not vary by variant.
    if asset_shas.len() == 2 && asset_shas[0].1 != asset_shas[1].1 {
        v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "`[{}.asset_config].sha256` (`{}`) != `[{}.asset_config].sha256` (`{}`) — the \
                 record states the header policy, CSP and `.well-known` rules do NOT vary by \
                 config variant. A divergence means one variant ships a different security \
                 header policy than the one reviewed",
                asset_shas[0].0, asset_shas[0].1, asset_shas[1].0, asset_shas[1].1
            ),
        });
    }

    // (6) install-phase coherence, on the transitional table.
    if let Some(t) = doc.get("wallet_bundle_transitional") {
        match t.get("install_phase").and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()) {
            None => v.push(Violation::WalletBundleUnbound {
                detail: "`[wallet_bundle_transitional].install_phase` is absent — nothing in the \
                         checked record says WHICH install this bundle is, and installing the \
                         final bundle at Phase B.1 breaks the step-7 rotation silently"
                    .to_string(),
            }),
            Some(phase) => {
                let first = phase.find(WALLET_BUNDLE_PHASE_ORDER[0]);
                let second = phase.find(WALLET_BUNDLE_PHASE_ORDER[1]);
                match (first, second) {
                    (Some(a), Some(b)) if a < b => {}
                    _ => v.push(Violation::WalletBundleUnbound {
                        detail: format!(
                            "`[wallet_bundle_transitional].install_phase` = `{phase}` does not \
                             name `{}` and then its supersession at `{}`, in that order. The \
                             order is the invariant: the transitional bundle installs FIRST and \
                             is superseded by the final bundle on the same canister",
                            WALLET_BUNDLE_PHASE_ORDER[0], WALLET_BUNDLE_PHASE_ORDER[1]
                        ),
                    }),
                }
            }
        }

        // (8) derivation_origin recorded ABSENT — distinguishably from empty.
        match t.get("launch_config") {
            None => v.push(Violation::WalletBundleUnbound {
                detail: "`[wallet_bundle_transitional.launch_config]` is absent — the ONE asset \
                         that differs between the two bundles is recorded nowhere, so the \
                         ceremony cannot check the difference by reading one served file"
                    .to_string(),
            }),
            Some(lc) => match lc.get("derivation_origin") {
                None => v.push(Violation::WalletBundleUnbound {
                    detail: "`[wallet_bundle_transitional.launch_config]` records no \
                             `derivation_origin` — the transitional bundle's defining property \
                             is that the key is OMITTED from the emitted config, and a record \
                             that says nothing about it cannot be used to verify the B.1 install"
                        .to_string(),
                }),
                Some(val) => {
                    let text = val.as_str().unwrap_or("").trim().to_string();
                    if !text.to_ascii_uppercase().contains("ABSENT") {
                        v.push(Violation::WalletBundleUnbound {
                            detail: format!(
                                "`[wallet_bundle_transitional.launch_config].derivation_origin` \
                                 is recorded as `{text}` — it must record the key as ABSENT \
                                 (omitted), which is NOT the same as null and NOT the same as \
                                 empty. `evaluateSessionPolicy` refuses a present-but-wrong \
                                 value and PERMITS an absent one, so an empty string here would \
                                 describe a bundle that re-roots app.stsh.fi at Phase B.1: the \
                                 old II principals become unproducible and the step-7 rotation \
                                 can be neither proposed nor approved. Nothing errors and \
                                 nothing on screen says so"
                            ),
                        });
                    }
                }
            },
        }
    }

    // (8a) the release-state marker.
    v.extend(check_wallet_bundle_release_marker(&doc));

    v
}

/// M-02 (B-ii): the release-state marker, checked as part of the MANDATORY half.
///
/// HARDEN-03 (D-1) adds `variant` to this table, with a presence rule tied to
/// `state`:
///
///   * `state = "releasing"` — `variant` is REQUIRED and must be one of
///     [`WALLET_BUNDLE_VARIANTS`]. Without it the byte half has no way to know
///     which of the two bundles is on disk, and both tables record
///     `path = "wallet/dist"`.
///   * `state = "held"` — `variant` must be ABSENT. A held record is not
///     releasing anything, so a variant name there is a leftover from a release
///     pass that was reverted incompletely, and a leftover that reads as
///     harmless today is the thing a later lane acts on.
///
/// The presence rule is checked only when `state` itself is recognised: with an
/// absent or unrecognised `state` there is no rule to apply, and reporting a
/// second, derived violation would bury the first.
fn check_wallet_bundle_release_marker(doc: &toml::Value) -> Vec<Violation> {
    let mut v = Vec::new();
    let Some(t) = doc.get("wallet_bundle_release") else {
        v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "{RELEASE_RECORD_ARTIFACT} has no `[wallet_bundle_release]` table, so the record \
                 does not say whether a wallet bundle is being released at this head. That is \
                 the one fact the BYTE measurement needs in order to be either owed or not \
                 owed: without it, a release could proceed with the measurement never having \
                 run and nothing would distinguish that from a measurement that passed. \
                 Declare `state` as one of {WALLET_BUNDLE_RELEASE_STATES:?}, with a `reason`"
            ),
        });
        return v;
    };
    let declared_variant = t
        .get("variant")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match t.get("state").and_then(|x| x.as_str()).map(str::trim) {
        Some(s) if WALLET_BUNDLE_RELEASE_STATES.contains(&s) => {
            // HARDEN-03 (D-1): the variant presence rule, keyed off the state.
            match (s, declared_variant) {
                ("releasing", None) => v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[wallet_bundle_release].state` is `releasing` but the table declares no \
                         `variant`. Both `{}` and `{}` record `path = \"wallet/dist\"`, so the \
                         byte measurement cannot tell which bundle is on disk and would compare \
                         the built tree against the FINAL pin whatever was built. Declare \
                         `variant` as one of {WALLET_BUNDLE_VARIANTS:?}",
                        WALLET_BUNDLE_TABLES[0], WALLET_BUNDLE_TABLES[1]
                    ),
                }),
                ("releasing", Some(name)) if wallet_bundle_table_for_variant(name).is_none() => {
                    v.push(Violation::WalletBundleUnbound {
                        detail: format!(
                            "`[wallet_bundle_release].variant` = `{name}` is not one of \
                             {WALLET_BUNDLE_VARIANTS:?}. An unrecognised variant is REFUSED rather \
                             than guessed, for the same reason an unrecognised `state` is: \
                             defaulting it to `final` would silently measure a transitional \
                             directory against the final pin"
                        ),
                    })
                }
                ("held", Some(name)) => v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[wallet_bundle_release].state` is `held` but the table declares \
                         `variant = \"{name}\"`. `variant` is meaningful ONLY while a bundle is \
                         being released; a name left behind under `held` is the residue of a \
                         release pass that was reverted incompletely, and the next lane to flip \
                         `state` would inherit a variant nobody chose. Remove the key, or set \
                         `state = \"releasing\"` if a bundle really is being released here"
                    ),
                }),
                _ => {}
            }
        }
        Some(s) => v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "`[wallet_bundle_release].state` = `{s}` is not one of \
                 {WALLET_BUNDLE_RELEASE_STATES:?}. An unrecognised state is refused rather than \
                 guessed: reading it as `held` would silence the byte measurement on a real \
                 release, and reading it as `releasing` would red every routine gate run"
            ),
        }),
        None => v.push(Violation::WalletBundleUnbound {
            detail: "`[wallet_bundle_release]` declares no `state`".to_string(),
        }),
    }
    if t.get("reason")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
    {
        v.push(Violation::WalletBundleUnbound {
            detail: "`[wallet_bundle_release]` declares no `reason`. The state is an operational \
                     assertion about this head, and an assertion with no stated basis is the \
                     thing a reader cannot check"
                .to_string(),
        });
    }
    v
}

/// The measurement of a built bundle directory: the figures `[wallet_bundle]`
/// pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredBundle {
    /// Count of REGULAR files (directories excluded), recursively.
    pub files: i64,
    /// Sum of those files' sizes.
    pub bytes: i64,
    /// The record's digest: sha256 over the LC_ALL=C-sorted per-file
    /// `sha256  relpath` manifest.
    pub sha256: String,
}

/// Measure a bundle directory by the record's OWN documented procedure:
///
/// ```text
/// cd wallet && find dist -type f | sed 's|^dist/||' | LC_ALL=C sort \
///   | while read -r f; do printf "%s  %s\n" \
///       "$(sha256sum "dist/$f" | cut -d' ' -f1)" "$f"; done \
///   | sha256sum
/// ```
///
/// A directory has no canonical hash, so the digest IS this procedure. Two
/// details are load-bearing and easy to get wrong: paths are part of the hashed
/// text, so a rename moves the digest; and the sort is byte-wise over the
/// relative paths, which is what `LC_ALL=C` means and what Rust's `str` ordering
/// already is. Two spaces separate the digest from the path, as `printf` writes it.
///
/// NON-REGULAR ENTRIES ARE REFUSED, NOT IMITATED (HARDEN-03, D-4). The procedure
/// above and this implementation used to disagree about symlinks, and the
/// disagreement was invisible because every fixture was a tree of ordinary files:
///
///   * `find` defaults to `-P` (never dereference), so a symlink to a file is
///     `-type l` and `-type f` OMITS it; `find -L` would be needed to include it.
///     A symlinked DIRECTORY is likewise not descended.
///   * a DANGLING symlink (target absent) is `-type l` too, so the shell skips it
///     silently and still produces a digest.
///
/// Matching either behaviour would be wrong. Imitating `find -P` means a file
/// ships inside the measured tree that no digest covers, and an omitted file is
/// exactly as dangerous as a doubled one. So this walker uses
/// [`std::fs::symlink_metadata`] — which classifies a symlink AS a symlink,
/// dangling or not, rather than failing to stat it — and makes any entry that is
/// not a regular file or a real directory a hard `Err`: symlinks, symlinked
/// directories (which also closes the directory-cycle case), FIFOs, sockets and
/// device nodes. Under `state = "releasing"` that surfaces through the existing
/// fail-closed [`Violation::WalletBundleUnbound`] path as a TREE-SHAPE refusal
/// naming the offending entry, not as an opaque I/O fault.
///
/// The record's published procedure carries the matching guard, run before the
/// hash, so the two remain reproductions of one another rather than two
/// procedures that agree only on trees that happen to be clean. **The digest
/// construction for a clean tree is unchanged by this**: a tree of ordinary files
/// and directories walks, sorts and hashes exactly as before.
pub fn measure_bundle_dir(dir: &Path) -> Result<MeasuredBundle, String> {
    use sha2::{Digest, Sha256};
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, u64, Vec<u8>)>) -> Result<(), String> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read an entry of {}: {e}", dir.display()))?;
            let path = entry.path();
            // `symlink_metadata` does NOT follow the link, which is what makes the
            // refusal below possible at all: `metadata` resolves, so it reports a
            // symlink-to-file as a regular file (indistinguishable, and counted)
            // and ERRORS on a dangling one (indistinguishable from a disk fault).
            // `symlink_metadata` reports both AS symlinks, so both are refused with
            // a message that names the tree shape. See this function's doc comment.
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(format!(
                    "{} is a SYMBOLIC LINK, and the bundle measurement refuses any entry that is \
                     not a regular file or a real directory. Refused rather than resolved or \
                     skipped: the record's published procedure uses `find` in its default `-P` \
                     mode, which OMITS symlinks, so resolving one here would hash a file the \
                     published procedure never sees — and omitting it would ship a file inside \
                     the measured tree that no digest covers. A released bundle directory is \
                     expected to be ordinary files and directories only; if a build tool emitted \
                     this link, materialise its target as a real file and re-measure",
                    path.display()
                ));
            }
            if ft.is_dir() {
                walk(base, &path, out)?;
            } else if ft.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(|_| format!("{} is not under {}", path.display(), base.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                let body = std::fs::read(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                out.push((rel, meta.len(), body));
            } else {
                // FIFO, socket, block or character device. The shell procedure's
                // `-type f` omits these too, and the same argument applies: an
                // entry inside the released tree that no digest covers. A FIFO
                // additionally would BLOCK `fs::read` forever if it were treated
                // as a file, so silence here is not even a safe default.
                return Err(format!(
                    "{} is NOT A REGULAR FILE or a directory (it is a FIFO, socket or device \
                     node), and the bundle measurement refuses it. A released bundle directory \
                     is ordinary files and directories only; anything else is an entry the \
                     recorded digest does not cover and the published `find -type f` procedure \
                     does not see",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut files: Vec<(String, u64, Vec<u8>)> = Vec::new();
    walk(dir, dir, &mut files)?;
    if files.is_empty() {
        return Err(format!("{} contains no regular files", dir.display()));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut manifest = String::new();
    let mut total: u64 = 0;
    for (rel, len, body) in &files {
        let mut h = Sha256::new();
        h.update(body);
        manifest.push_str(&format!("{:x}  {}\n", h.finalize(), rel));
        total += len;
    }
    let mut outer = Sha256::new();
    outer.update(manifest.as_bytes());
    Ok(MeasuredBundle {
        files: files.len() as i64,
        bytes: total as i64,
        sha256: format!("{:x}", outer.finalize()),
    })
}

/// The leading version token of a recorded toolchain value.
///
/// The record states tuples as prose — `"22.23.1 (wallet/.nvmrc)"`, `"0.12.1
/// (wallet/package.json devDependency ^0.12.0, resolved from node_modules/.bin —
/// NOT the 0.13.1 on PATH)"` — because the parenthetical is the part a human
/// needs. The version is always the first token.
fn recorded_version(recorded: &str) -> Option<&str> {
    recorded.trim().split_whitespace().next().filter(|s| !s.is_empty())
}

/// Run a tool and return the first token in its output that looks like a version
/// (`1.2.3`, or `v1.2.3` with the `v` stripped — `node --version` prints `v20.20.2`,
/// `wasm-pack --version` prints `wasm-pack 0.12.1`, `rustc --version` prints
/// `rustc 1.95.0 (…)`).
fn host_version(program: &Path, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", program.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} {args:?} exited {}: {}",
            program.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    text.split_whitespace()
        .map(|t| t.trim_start_matches('v'))
        .find(|t| {
            let mut parts = t.split('.');
            parts.clone().count() >= 2
                && parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        })
        .map(|s| s.to_string())
        .ok_or_else(|| format!("{} {args:?} printed no version-shaped token: {text:?}", program.display()))
}

/// M-02 (B-ii): the BYTE measurement of the released wallet bundle.
///
/// This is the half V1 wanted to make unconditional on the canonical gate path and
/// could not, for five reasons each verified in the tree: `wallet/dist` is
/// gitignored and therefore absent on a fresh clone; the gate BUILDS it after the
/// custody posture stage it would have been folded into; the gate deliberately
/// SKIPS the whole wallet leg when host tools are missing; the gate's build is not
/// the pinned toolchain; and "present" is not "current" — the `dist` on this
/// machine was measured stale.
///
/// So it is a release-evidence step with three properties, and every one of them
/// is a refusal rather than a skip:
///
///  1. **The toolchain tuple is asserted BEFORE measuring, and a mismatch is a
///     VIOLATION.** A digest measured under any other tuple is not evidence about
///     the pinned one — it is a different number that happens to be the same shape.
///     This is the rule the record already states for a human rebinder, applied to
///     the checker so it cannot be forgotten. `wasm-pack` is read from
///     `wallet/node_modules/.bin`, not from PATH, because the record pins 0.12.1
///     there and a different 0.13.1 is commonly on PATH — reading PATH would
///     compare against the wrong binary and pass or fail for the wrong reason.
///  2. **It is bound to the `[wallet_bundle_release]` marker**, so not measuring
///     here is a declared state the record carries and the mandatory half checks,
///     never an inference from an absent file.
///  3. **When the marker says a bundle IS being released, an absent or
///     non-matching `dist` FAILS CLOSED.**
///  4. **(HARDEN-03, D-1) The marker also says WHICH bundle is on disk**, via
///     `variant`, and the measurement runs against THAT table. Before this, the
///     check read `doc.get("wallet_bundle")` unconditionally while both tables
///     recorded `path = "wallet/dist"` — so there was no state in which a Phase
///     B.1 lane could have its transitional `dist` measured: flipping the marker
///     compared the transitional tree against the FINAL digest and failed. An
///     absent or unrecognised `variant` is refused here, never defaulted, because
///     defaulting to `final` restores exactly that mis-comparison.
///
/// What this check still does NOT do, named so it is not mistaken for covered:
/// it runs on a repo tree with no network and no canister, so it cannot verify
/// the target canister, the backend pins a bundle was built against, or what
/// `s3tyu` actually serves after an upload. That is install-time evidence
/// (`BundleEvidenceV1`), owed by the Phase B.1 / install-time lane.
pub fn check_wallet_bundle_bytes(root: &Path) -> (Vec<Violation>, String) {
    let path = root.join(RELEASE_RECORD_ARTIFACT);
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            return (
                vec![Violation::WalletBundleUnbound {
                    detail: format!("cannot read {RELEASE_RECORD_ARTIFACT}: {e}"),
                }],
                String::new(),
            )
        }
    };
    let doc: toml::Value = match toml::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            return (
                vec![Violation::WalletBundleUnbound {
                    detail: format!("malformed {RELEASE_RECORD_ARTIFACT}: {e}"),
                }],
                String::new(),
            )
        }
    };

    // The marker. Its STRUCTURE is the mandatory half's obligation; here it is
    // only read, and an unreadable one is refused rather than defaulted.
    let state = doc
        .get("wallet_bundle_release")
        .and_then(|t| t.get("state"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .unwrap_or("");
    if !WALLET_BUNDLE_RELEASE_STATES.contains(&state) {
        return (
            vec![Violation::WalletBundleUnbound {
                detail: format!(
                    "`[wallet_bundle_release].state` is `{state}`, not one of \
                     {WALLET_BUNDLE_RELEASE_STATES:?}, so this stage cannot tell whether the \
                     byte measurement is owed. Refused rather than assumed in either direction"
                ),
            }],
            String::new(),
        );
    }
    if state == "held" {
        let reason = doc
            .get("wallet_bundle_release")
            .and_then(|t| t.get("reason"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        return (
            Vec::new(),
            format!(
                "NOT OWED AT THIS HEAD — `[wallet_bundle_release].state = \"held\"`, so no \
                 wallet bundle is being released here and the byte measurement is not owed. \
                 This is a DECLARED state read out of the release record, checked \
                 unconditionally by the record-coverage half, and it is not a skip: a missing \
                 or unrecognised marker is a violation, and flipping it to \"releasing\" arms \
                 the measurement below. Recorded reason: {reason}"
            ),
        );
    }

    // state == "releasing": the measurement is owed.
    let mut v = Vec::new();

    // (0) WHICH bundle is on disk (HARDEN-03, D-1). Both tables record
    //     `path = "wallet/dist"`, so without this the measurement would compare
    //     whatever was built against the FINAL pin. Read here, and refused rather
    //     than defaulted, for the same reason `state` is: defaulting to `final`
    //     is precisely the silent mis-comparison this lane exists to remove. The
    //     record-coverage half reports an absent or unrecognised `variant` too;
    //     it is repeated here because this half must not proceed without it.
    let declared_variant = doc
        .get("wallet_bundle_release")
        .and_then(|t| t.get("variant"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(variant) = declared_variant else {
        return (
            vec![Violation::WalletBundleUnbound {
                detail: format!(
                    "`[wallet_bundle_release].state` is `releasing` but no `variant` is declared, \
                     so this stage cannot tell WHICH bundle is on disk. `{}` and `{}` both record \
                     `path = \"wallet/dist\"`; measuring against the final pin regardless would \
                     fail a transitional release for the wrong reason. Declare `variant` as one \
                     of {WALLET_BUNDLE_VARIANTS:?}",
                    WALLET_BUNDLE_TABLES[0], WALLET_BUNDLE_TABLES[1]
                ),
            }],
            String::new(),
        );
    };
    let Some(table_name) = wallet_bundle_table_for_variant(variant) else {
        return (
            vec![Violation::WalletBundleUnbound {
                detail: format!(
                    "`[wallet_bundle_release].variant` is `{variant}`, not one of \
                     {WALLET_BUNDLE_VARIANTS:?}, so this stage cannot tell which table to measure \
                     against. Refused rather than assumed in either direction"
                ),
            }],
            String::new(),
        );
    };
    let mut report = format!(
        "OWED — `[wallet_bundle_release].state = \"releasing\"`, `variant = \"{variant}\"` \
         → measuring against `[{table_name}]`.\n"
    );

    // (1) the toolchain tuple, asserted BEFORE measuring.
    let recorded_tuple = doc
        .get(table_name)
        .and_then(|t| t.get("toolchain"))
        .cloned();
    let Some(tc) = recorded_tuple else {
        v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "`[{table_name}.toolchain]` is absent, so there is no tuple to measure \
                 under. The record-coverage half reports this too; it is repeated here \
                 because measuring anyway would produce a digest attributable to nothing"
            ),
        });
        return (v, report);
    };
    let wasm_pack_bin = root.join("wallet/node_modules/.bin/wasm-pack");
    let probes: [(&str, PathBuf, &[&str]); 4] = [
        ("node", PathBuf::from("node"), &["--version"]),
        ("npm", PathBuf::from("npm"), &["--version"]),
        ("wasm_pack", wasm_pack_bin, &["--version"]),
        ("rustc", PathBuf::from("rustc"), &["--version"]),
    ];
    let mut tuple_ok = true;
    for (key, program, args) in probes {
        let Some(recorded) = tc.get(key).and_then(|x| x.as_str()).and_then(recorded_version) else {
            v.push(Violation::WalletBundleUnbound {
                detail: format!("`[{table_name}.toolchain].{key}` states no version to compare"),
            });
            tuple_ok = false;
            continue;
        };
        match host_version(&program, args) {
            Ok(host) if host == recorded => {
                report.push_str(&format!("  {key:<10} pinned {recorded} == host {host}\n"));
            }
            Ok(host) => {
                tuple_ok = false;
                report.push_str(&format!("  {key:<10} pinned {recorded} != host {host}  MISMATCH\n"));
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "toolchain MISMATCH on `{key}`: the record pins `{recorded}` and this \
                         host has `{host}`. REFUSED, not skipped: a digest measured under a \
                         different tuple is not evidence about the pinned one, and recording it \
                         as though it were is how an unreproducible artifact acquires a \
                         reproducible-looking pin. Either build under the pinned tuple or set \
                         `[wallet_bundle_release].state = \"held\"` and rebind the row in a lane \
                         that can"
                    ),
                });
            }
            Err(e) => {
                tuple_ok = false;
                report.push_str(&format!("  {key:<10} pinned {recorded} != host UNAVAILABLE\n"));
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "toolchain `{key}` could not be measured on this host ({e}), and the \
                         record pins `{recorded}`. An unmeasurable tool is a refusal, not a \
                         pass: the alternative is a digest nobody can attribute to a tuple"
                    ),
                });
            }
        }
    }
    if !tuple_ok {
        report.push_str(
            "  → measurement NOT ATTEMPTED: the tuple assertion failed, and measuring under a \
             mismatched tuple would produce a number that looks like evidence and is not.\n",
        );
        return (v, report);
    }

    // (2) the measurement itself, against the pinned figures of the DECLARED
    //     variant's table.
    let table = doc.get(table_name);
    let dir = root.join(
        table
            .and_then(|t| t.get("path"))
            .and_then(|x| x.as_str())
            .unwrap_or("wallet/dist"),
    );
    match measure_bundle_dir(&dir) {
        Err(e) => v.push(Violation::WalletBundleUnbound {
            detail: format!(
                "`[wallet_bundle_release].state` says the `{variant}` bundle is being released, \
                 but the measured directory is unusable: {e}. FAILS CLOSED — an unmeasurable \
                 release artifact is an unverified install, and `wallet/dist` is gitignored, so \
                 absent is the NORMAL state and must never read as agreement"
            ),
        }),
        Ok(m) => {
            report.push_str(&format!(
                "  measured   files={} bytes={} sha256={}\n",
                m.files, m.bytes, m.sha256
            ));
            let pinned_sha = table.and_then(|t| t.get("sha256")).and_then(|x| x.as_str()).unwrap_or("");
            let pinned_files = table.and_then(|t| t.get("files")).and_then(|x| x.as_integer());
            let pinned_bytes = table.and_then(|t| t.get("bytes")).and_then(|x| x.as_integer());
            if m.sha256 != pinned_sha {
                // D-2: a CROSS-VARIANT miss gets its own sentence. If the measured
                // tree is the OTHER bundle, the mistake is "the wrong variant was
                // built", which is a different thing from a stale or corrupt tree
                // and has a different remedy. Reporting it as a bare sha mismatch
                // is how a future lane loosens a check for the wrong reason — a
                // confusing-but-correct failure invites the wrong fix.
                let other = wallet_bundle_other_table(variant)
                    .and_then(|o| doc.get(o).map(|t| (o, t)))
                    .and_then(|(o, t)| {
                        t.get("sha256")
                            .and_then(|x| x.as_str())
                            .map(|s| (o, s.trim().to_string()))
                    });
                let cross = match &other {
                    Some((other_name, other_sha)) if *other_sha == m.sha256 => Some(
                        format!(
                            " CROSS-VARIANT: the measured digest is EXACTLY `[{other_name}].sha256`, \
                             so the directory on disk is the OTHER bundle — the wrong variant was \
                             built, not a stale or modified one. Note that the canonical gate \
                             builds the FINAL variant only (`run_gate.sh`'s wallet phase runs \
                             `npm run build`); a TRANSITIONAL measurement is a separately-invoked, \
                             OUT-OF-GATE step, so `cd wallet && rm -rf dist && npm run \
                             build:transitional` must be run by hand before flipping this marker. \
                             Rebuild the declared variant; do NOT re-pin either row to make this \
                             comparison agree."
                        ),
                    ),
                    _ => None,
                };
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table_name}].sha256` pins `{pinned_sha}` but the built bundle \
                         measures `{}` (declared `variant = \"{variant}\"`). This is the pin a \
                         verifier reproduces, so a divergence means the record does not describe \
                         the artifact that would be installed.{}",
                        m.sha256,
                        cross.unwrap_or_default()
                    ),
                });
            }
            if pinned_files != Some(m.files) {
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table_name}].files` pins {pinned_files:?} but the built bundle \
                         contains {} regular files",
                        m.files
                    ),
                });
            }
            if pinned_bytes != Some(m.bytes) {
                v.push(Violation::WalletBundleUnbound {
                    detail: format!(
                        "`[{table_name}].bytes` pins {pinned_bytes:?} but the built bundle \
                         measures {} bytes",
                        m.bytes
                    ),
                });
            }
        }
    }
    (v, report)
}

// ── ROT-LEDGER: the identity-rotation ledger ─────────────────────────────────
//
// WHY THIS EXISTS, AND WHY IT LANDS BEFORE THE ARTIFACT IT CHECKS.
//
// `signers` and `[recovery].members` in the authority record are INSTALL-TIME
// pins: they are what was byte-encoded into vault_init.did / upgrader_init.did,
// and `check_authority_binding` / `check_recovery_roster` byte-match them. The
// board step-7 identity rotation moves the LIVE Vault and Upgrader onto
// canister-rooted principals, at which point the pins stop describing the live
// authority set — by design, not by drift. From then on the only in-repo
// statement of who actually governs those canisters is this ledger.
//
// The control is committed BEFORE the rotation produces the artifact that
// satisfies it, exactly as `RELEASE_RECORD_ARTIFACT` was: a control added after
// the fact has already had its window. The pre-rotation state is therefore a
// DECLARED pending obligation (`PendingDeploymentArtifact`, allowlisted once in
// `[deploy_gate].expected_pending`), while every way of getting the ledger
// WRONG is [`Violation::RotationLedgerInconsistent`], which is not declarable
// and can only ever appear as a SURPLUS key.
//
// PROVENANCE LIMITATION, STATED PLAINLY. Every row records an operator-supplied
// read-back. This code verifies that the named evidence file exists and hashes
// to the recorded sha256, that the rows chain on ordered principal BYTES, and
// that each row is internally consistent and temporally sane. It CANNOT prove
// those bytes came from a live signer-gated query against the real canister. A
// checked attestation is not a cryptographic proof of provenance and must never
// be read as one.

/// The ledger schema this reader understands. Lockstep with
/// `[rotation].schema_version` in [`VAULT_AUTHORITY_RECORD`]: any other value is
/// REFUSED, because a ledger written to a schema the reader does not know is not
/// partially readable, it is unreadable.
pub const ROTATION_LEDGER_SCHEMA_VERSION: u32 = 1;

/// The declared-pending key's `path`: the directory the rotation read-back
/// evidence lands in, which does not exist until the rotation has happened.
/// MUST stay byte-identical to the key declared in
/// `[deploy_gate].expected_pending`.
pub const ROTATION_LEDGER_PENDING_PATH: &str = "deployment/mainnet/evidence/identity_rotation";

/// The live install-time facts the ledger is checked AGAINST: the signer /
/// member sets and thresholds for the birth check (C-2), and the two canister
/// principals a row's `canister` field must name (F-3).
///
/// A struct rather than a six-tuple so a caller cannot transpose two arguments
/// of the same type and still compile.
#[derive(Clone, Copy)]
pub struct RotationPins<'a> {
    /// `signers` — the Vault authority set.
    pub signers: &'a [candid::Principal],
    /// `threshold` — the Vault approval threshold.
    pub signer_threshold: u32,
    /// `[recovery].members` — the Upgrader recovery roster.
    pub members: &'a [candid::Principal],
    /// `[recovery].threshold`.
    pub member_threshold: u32,
    /// `[recovery].vault` — the canister a `[[rotation.vault]]` row governs.
    pub vault: candid::Principal,
    /// `upgrader` — the canister a `[[rotation.upgrader]]` row governs.
    pub upgrader: candid::Principal,
}

const ROTATION_STATE_PENDING: &str = "not-yet-performed";
const ROTATION_STATE_ROTATED: &str = "rotated";

#[derive(Deserialize)]
struct RotationOuterToml {
    rotation: Option<RotationToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationToml {
    schema_version: u32,
    state: String,
    #[serde(default)]
    upgrader: Vec<RotationRowToml>,
    #[serde(default)]
    vault: Vec<RotationRowToml>,
    bootstrap: RotationBootstrapToml,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationBootstrapToml {
    vault_signers: Vec<String>,
    vault_threshold: u32,
    upgrader_members: Vec<String>,
    upgrader_threshold: u32,
    vault_epoch: u64,
    snapshot_of_pins_at_commit: String,
}

/// Every field is one the checker acts on. `deny_unknown_fields` is deliberate:
/// an unrecognised field would otherwise be an unvalidated field, and an
/// unvalidated field is indistinguishable from a checked one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRowToml {
    sequence: u32,
    status: String,
    old_members: Vec<String>,
    new_members: Vec<String>,
    old_threshold: u32,
    new_threshold: u32,
    old_epoch: Option<u64>,
    new_epoch: Option<u64>,
    after_upgrader_sequence: Option<u32>,
    proposal_id: u64,
    approvers: Vec<String>,
    observed_at_ns: u64,
    observed_at_utc: String,
    network: String,
    canister: String,
    read_by: String,
    readback_command: String,
    readback_evidence_path: String,
    readback_output_sha256: String,
    predecessor_row_sha256: String,
}

/// Values that look like a row but are not one. A row exists only AFTER a
/// rotation, so any of these in a required field means the ledger is claiming
/// something that did not happen.
const ROTATION_PLACEHOLDER_TOKENS: &[&str] =
    &["tbd", "todo", "placeholder", "pending", "n/a", "xxx", "<fill>", "fixme"];

fn rotation_is_placeholder(s: &str) -> bool {
    let t = s.trim().to_ascii_lowercase();
    ROTATION_PLACEHOLDER_TOKENS.contains(&t.as_str())
}

// ── Q5-A: the rotation-aware lockstep view of the ledger ─────────────────────
//
// The deploy-time checks compare the pins to the IMMUTABLE install payloads.
// ROT-LEDGER-FILL rewrites the pins to the post-rotation roster, so after the
// rotation those comparisons would go RED on a CORRECT record. The repair is
// not to relax them: it is to compare each surface to something that is still
// true of it. This struct is the extract of `[rotation]` that lets the two
// deploy-time checks do that — the install-time snapshot, and the last EXECUTED
// row of each plane.
//
// It carries NO opinion about whether the ledger is internally consistent;
// `rotation_ledger_violations` owns that, and reports it as the non-declarable
// `RotationLedgerInconsistent`. This loader only refuses to hand back a view
// that would let a deploy check pass on nothing.

/// The two fixed points a rotated record is checked against.
#[derive(Clone, Debug)]
pub struct RotationLockstep {
    /// `[rotation].state == "rotated"`. False ⇒ the pre-rotation comparisons.
    pub rotated: bool,
    /// `[rotation.bootstrap].vault_signers` — what `vault_init.did` encoded.
    pub bootstrap_vault_signers: Vec<candid::Principal>,
    /// `[rotation.bootstrap].vault_threshold`.
    pub bootstrap_vault_threshold: u32,
    /// `[rotation.bootstrap].upgrader_members` — what `upgrader_init.did` encoded.
    pub bootstrap_upgrader_members: Vec<candid::Principal>,
    /// `[rotation.bootstrap].upgrader_threshold`.
    pub bootstrap_upgrader_threshold: u32,
    /// `new_members` of the last EXECUTED `[[rotation.vault]]` row — the LIVE
    /// Vault signer set the pinned `signers` must now equal.
    pub last_vault_new_members: Vec<candid::Principal>,
    /// `new_threshold` of that row.
    pub last_vault_new_threshold: u32,
    /// `new_members` of the last EXECUTED `[[rotation.upgrader]]` row.
    pub last_upgrader_new_members: Vec<candid::Principal>,
    /// `new_threshold` of that row.
    pub last_upgrader_new_threshold: u32,
}

impl RotationLockstep {
    /// The view a record with no `[rotation]` table yields: pre-rotation, which
    /// is the STRICTER of the two modes (the pins are compared directly to the
    /// install payloads). A record that is genuinely rotated cannot reach this,
    /// because `rotated` is a word written in that very table.
    fn pending() -> Self {
        Self {
            rotated: false,
            bootstrap_vault_signers: Vec::new(),
            bootstrap_vault_threshold: 0,
            bootstrap_upgrader_members: Vec::new(),
            bootstrap_upgrader_threshold: 0,
            last_vault_new_members: Vec::new(),
            last_vault_new_threshold: 0,
            last_upgrader_new_members: Vec::new(),
            last_upgrader_new_threshold: 0,
        }
    }
}

/// The last EXECUTED row of a plane: the highest `sequence` whose `status` is
/// `EXECUTED`. Selection is by `sequence`, not by position, so a reordered file
/// cannot change which row is "current".
fn rotation_last_executed(rows: &[RotationRowToml]) -> Option<&RotationRowToml> {
    rows.iter()
        .filter(|r| r.status == "EXECUTED")
        .max_by_key(|r| r.sequence)
}

/// Q5-A: build the lockstep view from an authority record's TEXT.
///
/// `Err` on anything that would leave a deploy-time comparison bound to
/// nothing: an unparseable record, an unrecognised `[rotation].state`, a
/// `rotated` record with no EXECUTED row on a plane, or a principal that does
/// not parse. Callers turn that into their own surface's violation kind and
/// fail CLOSED.
pub fn rotation_lockstep_from_record(raw: &str) -> Result<RotationLockstep, String> {
    let outer: RotationOuterToml =
        toml::from_str(raw).map_err(|e| format!("record does not parse: {e}"))?;
    let Some(led) = outer.rotation else {
        return Ok(RotationLockstep::pending());
    };
    let rotated = match led.state.as_str() {
        ROTATION_STATE_PENDING => false,
        ROTATION_STATE_ROTATED => true,
        other => {
            return Err(format!(
                "[rotation].state = `{other}` is not recognised — expected \
                 `{ROTATION_STATE_PENDING}` or `{ROTATION_STATE_ROTATED}`"
            ))
        }
    };
    let parse = |label: &str, v: &[String]| -> Result<Vec<candid::Principal>, String> {
        v.iter()
            .map(|s| {
                candid::Principal::from_text(s)
                    .map_err(|e| format!("{label} carries `{s}`, which is not a principal: {e}"))
            })
            .collect()
    };
    let mut out = RotationLockstep {
        rotated,
        bootstrap_vault_signers: parse(
            "[rotation.bootstrap].vault_signers",
            &led.bootstrap.vault_signers,
        )?,
        bootstrap_vault_threshold: led.bootstrap.vault_threshold,
        bootstrap_upgrader_members: parse(
            "[rotation.bootstrap].upgrader_members",
            &led.bootstrap.upgrader_members,
        )?,
        bootstrap_upgrader_threshold: led.bootstrap.upgrader_threshold,
        ..RotationLockstep::pending()
    };
    if !rotated {
        return Ok(out);
    }
    for (plane, rows) in [("upgrader", &led.upgrader), ("vault", &led.vault)] {
        let Some(r) = rotation_last_executed(rows) else {
            return Err(format!(
                "[rotation].state = `{ROTATION_STATE_ROTATED}` but the {plane} plane carries no \
                 EXECUTED row, so there is nothing for the pins to be checked against. Fail \
                 closed: an unbound pin is an unchecked pin."
            ));
        };
        let members = parse(&format!("[[rotation.{plane}]] new_members"), &r.new_members)?;
        if plane == "vault" {
            out.last_vault_new_members = members;
            out.last_vault_new_threshold = r.new_threshold;
        } else {
            out.last_upgrader_new_members = members;
            out.last_upgrader_new_threshold = r.new_threshold;
        }
    }
    Ok(out)
}

/// IO wrapper for [`rotation_lockstep_from_record`]. A record that is not on
/// disk yields the pre-rotation view: its ABSENCE is already the
/// `AuthorityBindingViolation` / `RecoveryRosterViolation` "not pinned" defect,
/// and this loader must not pre-empt that message with a different one.
pub fn load_rotation_lockstep(root: &Path) -> Result<RotationLockstep, String> {
    let path = root.join(VAULT_AUTHORITY_RECORD);
    match std::fs::read_to_string(&path) {
        Ok(raw) => rotation_lockstep_from_record(&raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RotationLockstep::pending()),
        Err(e) => Err(format!("cannot read {VAULT_AUTHORITY_RECORD}: {e}")),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` → unix seconds. No dependency: Howard Hinnant's
/// days-from-civil. Returns `None` on any shape this does not accept, which the
/// caller turns into a violation rather than a skip.
fn rotation_iso8601_to_unix(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':'
        || b[16] != b':' || b[19] != b'Z'
    {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> { s[a..z].parse::<i64>().ok() };
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Canonical text of a row, for the `predecessor_row_sha256` chain. Fixed field
/// order, defined here rather than by TOML serialisation order, so a reformat of
/// the file cannot break the chain.
fn rotation_row_canonical(plane: &str, r: &RotationRowToml) -> String {
    format!(
        "plane={plane}\nsequence={}\nstatus={}\nold_members={}\nnew_members={}\n\
         old_threshold={}\nnew_threshold={}\nold_epoch={:?}\nnew_epoch={:?}\n\
         after_upgrader_sequence={:?}\nproposal_id={}\napprovers={}\nobserved_at_ns={}\n\
         observed_at_utc={}\nnetwork={}\ncanister={}\nread_by={}\nreadback_command={}\n\
         readback_evidence_path={}\nreadback_output_sha256={}\n",
        r.sequence,
        r.status,
        r.old_members.join(","),
        r.new_members.join(","),
        r.old_threshold,
        r.new_threshold,
        r.old_epoch,
        r.new_epoch,
        r.after_upgrader_sequence,
        r.proposal_id,
        r.approvers.join(","),
        r.observed_at_ns,
        r.observed_at_utc,
        r.network,
        r.canister,
        r.read_by,
        r.readback_command,
        r.readback_evidence_path,
        r.readback_output_sha256,
    )
}

/// F-1: the canonical text of one row, addressed by plane and `sequence` in an
/// authority record's TEXT — i.e. the exact bytes whose sha256 the NEXT row of
/// that plane must record in `predecessor_row_sha256`.
///
/// Public for two reasons. ROT-LEDGER-FILL needs to compute the value it is
/// about to write without re-implementing the field order, and a golden test
/// can pin the canonical form so that changing it is LOUD: a silent reordering
/// or a dropped field would otherwise invalidate every future chain with no
/// test failing.
pub fn rotation_row_canonical_text(
    raw: &str,
    plane: &str,
    sequence: u32,
) -> Result<String, String> {
    let outer: RotationOuterToml =
        toml::from_str(raw).map_err(|e| format!("record does not parse: {e}"))?;
    let led = outer
        .rotation
        .ok_or_else(|| "the record carries no [rotation] table".to_string())?;
    let rows = match plane {
        "upgrader" => &led.upgrader,
        "vault" => &led.vault,
        other => return Err(format!("unknown plane `{other}`")),
    };
    let r = rows
        .iter()
        .find(|r| r.sequence == sequence)
        .ok_or_else(|| format!("no {plane} row with sequence {sequence}"))?;
    Ok(rotation_row_canonical(plane, r))
}

/// F-1: sha256 of [`rotation_row_canonical_text`] — the value the successor row
/// records in `predecessor_row_sha256`.
pub fn rotation_row_sha256(raw: &str, plane: &str, sequence: u32) -> Result<String, String> {
    Ok(sha256_hex(
        rotation_row_canonical_text(raw, plane, sequence)?.as_bytes(),
    ))
}

fn rot(defect: RotationDefect, row: &str, detail: String) -> Violation {
    Violation::RotationLedgerInconsistent {
        defect,
        row: row.to_string(),
        detail,
    }
}

/// The checked HEAD's commit time, in unix seconds.
///
/// `Err` on ANY git failure — including "not a git repository". The caller turns
/// that into [`RotationDefect::HeadTimeUnavailable`], never a skip: an
/// unreadable bound is the fail-open version of a bound.
fn rotation_head_commit_time(root: &Path) -> Result<i64, String> {
    let out = std::process::Command::new("git")
        .args(["-C", &root.to_string_lossy()])
        .args(["log", "-1", "--format=%ct", "HEAD"])
        .output()
        .map_err(|e| format!("cannot invoke git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git log -1 --format=%ct HEAD failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<i64>()
        .map_err(|e| format!("unparseable commit time: {e}"))
}

fn rotation_parse_all(
    row: &str,
    label: &str,
    v: &[String],
) -> Result<Vec<candid::Principal>, Violation> {
    v.iter()
        .map(|s| {
            candid::Principal::from_text(s).map_err(|e| {
                rot(
                    RotationDefect::BadPrincipal,
                    row,
                    format!("{label} carries `{s}`, which is not a principal: {e}"),
                )
            })
        })
        .collect()
}

/// PURE per-row validation, FIRST FAILURE WINS.
///
/// One violation per row, in a fixed order, so a negative fixture that injects
/// exactly one defect observes exactly that defect. A fixture that failed for a
/// second, incidental reason and was still scored "it failed" would discharge
/// nothing.
fn rotation_row_violations(
    root: &Path,
    plane: &str,
    r: &RotationRowToml,
    forbidden: &BTreeSet<candid::Principal>,
    expected_canister: Option<candid::Principal>,
) -> Option<Violation> {
    let row = format!("{plane}#{}", r.sequence);
    let row = row.as_str();

    // 1. status / placeholder-shaped values
    if r.status != "EXECUTED" {
        return Some(rot(
            RotationDefect::PlaceholderRow,
            row,
            format!(
                "status = `{}` — the only accepted row status is EXECUTED. A row exists only \
                 AFTER a rotation; the pending state is [rotation].state with EMPTY arrays.",
                r.status
            ),
        ));
    }
    for (label, val) in [
        ("observed_at_utc", &r.observed_at_utc),
        ("network", &r.network),
        ("canister", &r.canister),
        ("read_by", &r.read_by),
        ("readback_command", &r.readback_command),
        ("readback_evidence_path", &r.readback_evidence_path),
        ("readback_output_sha256", &r.readback_output_sha256),
    ] {
        if rotation_is_placeholder(val) {
            return Some(rot(
                RotationDefect::PlaceholderRow,
                row,
                format!("{label} = `{val}` is a placeholder, not a recorded fact"),
            ));
        }
    }

    // 2. required fields present
    for (label, val) in [
        ("observed_at_utc", r.observed_at_utc.as_str()),
        ("network", r.network.as_str()),
        ("canister", r.canister.as_str()),
        ("read_by", r.read_by.as_str()),
        ("readback_command", r.readback_command.as_str()),
        ("readback_evidence_path", r.readback_evidence_path.as_str()),
        ("readback_output_sha256", r.readback_output_sha256.as_str()),
    ] {
        if val.trim().is_empty() {
            return Some(rot(
                RotationDefect::RequiredFieldEmpty,
                row,
                format!(
                    "{label} is empty on an EXECUTED row — the ceremony input must be named, so \
                     the requirement cannot be quietly dropped"
                ),
            ));
        }
    }
    if r.observed_at_ns == 0 {
        return Some(rot(
            RotationDefect::RequiredFieldEmpty,
            row,
            "observed_at_ns is 0 on an EXECUTED row".into(),
        ));
    }
    if r.proposal_id == 0 {
        return Some(rot(
            RotationDefect::RequiredFieldEmpty,
            row,
            "proposal_id is 0 on an EXECUTED row".into(),
        ));
    }

    // 3. principals parse
    let old = match rotation_parse_all(row, "old_members", &r.old_members) {
        Ok(p) => p,
        Err(e) => return Some(e),
    };
    let new = match rotation_parse_all(row, "new_members", &r.new_members) {
        Ok(p) => p,
        Err(e) => return Some(e),
    };
    let approvers = match rotation_parse_all(row, "approvers", &r.approvers) {
        Ok(p) => p,
        Err(e) => return Some(e),
    };
    let reader = match rotation_parse_all(row, "read_by", std::slice::from_ref(&r.read_by)) {
        Ok(p) => p[0],
        Err(e) => return Some(e),
    };
    if let Err(e) = rotation_parse_all(row, "canister", std::slice::from_ref(&r.canister)) {
        return Some(e);
    }

    // 4. set shape: cardinality, distinctness, thresholds
    for (label, set) in [("old_members", &old), ("new_members", &new)] {
        if set.len() != 3 {
            return Some(rot(
                RotationDefect::SetShapeInvalid,
                row,
                format!("{label} has {} entries, required exactly 3", set.len()),
            ));
        }
        if set.iter().collect::<BTreeSet<_>>().len() != set.len() {
            return Some(rot(
                RotationDefect::SetShapeInvalid,
                row,
                format!("{label} contains a duplicate principal"),
            ));
        }
    }
    if r.old_threshold != 2 || r.new_threshold != 2 {
        return Some(rot(
            RotationDefect::SetShapeInvalid,
            row,
            format!(
                "thresholds are {}→{}; the ruled fixed threshold is 2 and NEVER contracts",
                r.old_threshold, r.new_threshold
            ),
        ));
    }
    // F-5 / G-2: a row that moves the authority set NOWHERE is not a rotation.
    // Such a row chains correctly and satisfies every shape check, so nothing
    // else here would refuse it; it would read as a performed rotation that
    // never changed who governs the canister.
    //
    // THIS ONE COMPARISON IS AS A SET, deliberately, and it is the ONLY place in
    // this module that is. Merely PERMUTING the same three principals changes
    // nobody's authority — order is not a property of a canister's signer set —
    // so an ordered comparison here would accept a re-ordering as a rotation.
    // The CHAIN comparison (`rotation_plane_chain`) stays ORDERED and must: a
    // reorder there means the predecessor's recorded `new_members` and this
    // row's `old_members` are not the same transcription, which is a chain
    // break. Same principals, opposite question.
    //
    // Cardinality (exactly 3) and distinctness are already established above, so
    // set equality here means "the same three principals".
    let old_set: BTreeSet<&candid::Principal> = old.iter().collect();
    let new_set: BTreeSet<&candid::Principal> = new.iter().collect();
    if old_set == new_set {
        return Some(rot(
            RotationDefect::SetShapeInvalid,
            row,
            format!(
                "new_members is the same SET of principals as old_members ([{}] vs [{}]) — a \
                 row that changes nobody's authority is not a rotation, and re-ordering a set \
                 is not a change, so it must not be recorded as one",
                render(&old),
                render(&new)
            ),
        ));
    }

    // 5. forbidden principals — reusing the existing denylist, never a second one
    for (label, set) in [("old_members", &old), ("new_members", &new)] {
        if let Some(p) = set.iter().find(|p| forbidden.contains(p)) {
            return Some(rot(
                RotationDefect::ForbiddenPrincipal,
                row,
                format!("{label} names {} — a FORBIDDEN_AUTHORITY_PRINCIPALS entry", p.to_text()),
            ));
        }
    }

    // 6. plane-shaped fields
    let vault_plane = plane == "vault";
    let vault_only_present =
        r.old_epoch.is_some() || r.new_epoch.is_some() || r.after_upgrader_sequence.is_some();
    if vault_plane {
        if r.old_epoch.is_none() || r.new_epoch.is_none() || r.after_upgrader_sequence.is_none() {
            return Some(rot(
                RotationDefect::MalformedTable,
                row,
                "a vault row requires old_epoch, new_epoch and after_upgrader_sequence".into(),
            ));
        }
    } else if vault_only_present {
        return Some(rot(
            RotationDefect::MalformedTable,
            row,
            "an upgrader row must not carry the vault-only fields old_epoch / new_epoch / \
             after_upgrader_sequence"
                .into(),
        ));
    }

    // 7. approvers: exactly two distinct members of the OLD set. A proposal is
    //    approved by the authority that existed BEFORE the rotation.
    if approvers.len() != 2 || approvers[0] == approvers[1] {
        return Some(rot(
            RotationDefect::ApproversInvalid,
            row,
            format!("approvers must be exactly two DISTINCT principals, got {:?}", r.approvers),
        ));
    }
    if let Some(p) = approvers.iter().find(|p| !old.contains(p)) {
        return Some(rot(
            RotationDefect::ApproversInvalid,
            row,
            format!("approver {} is not a member of old_members", p.to_text()),
        ));
    }

    // 8. read_by is one of the principals that could actually read
    if !old.contains(&reader) {
        return Some(rot(
            RotationDefect::ReaderNotInOldSet,
            row,
            format!(
                "read_by = {} is not in old_members — the gated read-back is only performable \
                 by an authority member",
                reader.to_text()
            ),
        ));
    }

    // 9. network
    if r.network != "ic" {
        return Some(rot(
            RotationDefect::MalformedTable,
            row,
            format!("network = `{}`, expected `ic`", r.network),
        ));
    }

    // 9b. F-3: a row must name the canister its own plane governs, taken from
    //     the record's OWN pins (`upgrader` / `[recovery].vault`) — which sit a
    //     few lines above the ledger, so the expected value is NOT copied from
    //     the artifact under test. Without this the field is parsed and then
    //     discarded, and a vault row could name the Upgrader.
    match expected_canister {
        None => {
            return Some(rot(
                RotationDefect::CanisterMismatch,
                row,
                format!(
                    "the pinned {plane} canister principal could not be loaded, so this row's \
                     `canister` cannot be bound to anything. Fail closed: an unbound row names \
                     nothing checkable."
                ),
            ))
        }
        Some(expected) => {
            // Parsed already in step 3, so this cannot fail here.
            if let Ok(got) = candid::Principal::from_text(&r.canister) {
                if got != expected {
                    return Some(rot(
                        RotationDefect::CanisterMismatch,
                        row,
                        format!(
                            "canister = {} but the record pins the {plane} plane's canister as \
                             {}",
                            got.to_text(),
                            expected.to_text()
                        ),
                    ));
                }
            }
        }
    }

    // 10. the two timestamps must be the SAME instant, stated twice
    let Some(secs) = rotation_iso8601_to_unix(&r.observed_at_utc) else {
        return Some(rot(
            RotationDefect::TimestampDisagrees,
            row,
            format!(
                "observed_at_utc = `{}` is not `YYYY-MM-DDTHH:MM:SSZ`",
                r.observed_at_utc
            ),
        ));
    };
    if (r.observed_at_ns / 1_000_000_000) as i64 != secs {
        return Some(rot(
            RotationDefect::TimestampDisagrees,
            row,
            format!(
                "observed_at_ns {} is {}s, but observed_at_utc `{}` is {}s",
                r.observed_at_ns,
                r.observed_at_ns / 1_000_000_000,
                r.observed_at_utc,
                secs
            ),
        ));
    }

    // 11. the read-back evidence, hashed. Modelled on the bootstrap-ring
    //     evidence pair and its loader: missing or mismatched is a violation.
    let p = root.join(&r.readback_evidence_path);
    match std::fs::read(&p) {
        Ok(bytes) => {
            let actual = sha256_hex(&bytes);
            if actual != r.readback_output_sha256.trim() {
                return Some(rot(
                    RotationDefect::EvidenceUnavailable,
                    row,
                    format!(
                        "{} hashes to {actual}, recorded {}",
                        r.readback_evidence_path,
                        r.readback_output_sha256.trim()
                    ),
                ));
            }
        }
        Err(e) => {
            return Some(rot(
                RotationDefect::EvidenceUnavailable,
                row,
                format!("cannot read {}: {e}", p.display()),
            ))
        }
    }
    None
}

/// Cross-row validation for one plane: sequence, chain, predecessor hash.
fn rotation_plane_chain(
    plane: &str,
    rows: &[RotationRowToml],
    anchor: &[candid::Principal],
) -> Vec<Violation> {
    let mut v = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        let row = format!("{plane}#{}", r.sequence);
        let expected_seq = (i + 1) as u32;
        if r.sequence != expected_seq {
            v.push(rot(
                RotationDefect::SequenceBroken,
                &row,
                format!(
                    "row at position {} declares sequence {}, expected {} — sequences are \
                     1-based, dense and strictly increasing, so a gap or a duplicate is a \
                     MISSING or a REWRITTEN row",
                    i + 1,
                    r.sequence,
                    expected_seq
                ),
            ));
            return v;
        }
    }
    // F-4: `proposal_id` is distinct WITHIN a plane. The lower bound stays
    // where it is (>= 1, as RequiredFieldEmpty) — the ">= 16" in the record's
    // prose is a fact about THIS ceremony, not a schema rule, and hard-coding
    // it would make the checker wrong for the second rotation.
    for (i, r) in rows.iter().enumerate() {
        if let Some(prev) = rows[..i].iter().find(|p| p.proposal_id == r.proposal_id) {
            v.push(rot(
                RotationDefect::ProposalIdNotUnique,
                &format!("{plane}#{}", r.sequence),
                format!(
                    "proposal_id {} is already cited by {plane}#{} — one on-chain proposal \
                     executed one rotation, so two rows claiming it means one of them did not \
                     happen the way it says",
                    r.proposal_id, prev.sequence
                ),
            ));
            return v;
        }
    }
    for (i, r) in rows.iter().enumerate() {
        let row = format!("{plane}#{}", r.sequence);
        let old: Vec<candid::Principal> = r
            .old_members
            .iter()
            .filter_map(|s| candid::Principal::from_text(s).ok())
            .collect();
        let prev_new: Vec<candid::Principal> = if i == 0 {
            anchor.to_vec()
        } else {
            rows[i - 1]
                .new_members
                .iter()
                .filter_map(|s| candid::Principal::from_text(s).ok())
                .collect()
        };
        // ORDERED BYTE equality, deliberately not set equality: "the same
        // members in a different order" is a chain break, and a set comparison
        // would silently accept it.
        if !ordered_bytes_equal(&old, &prev_new) {
            v.push(rot(
                RotationDefect::ChainBreak,
                &row,
                format!(
                    "old_members [{}] does not ordered-byte-equal {} [{}]",
                    render(&old),
                    if i == 0 {
                        "[rotation.bootstrap]".to_string()
                    } else {
                        format!("{plane}#{}'s new_members", rows[i - 1].sequence)
                    },
                    render(&prev_new)
                ),
            ));
            return v;
        }
        let expected_pred = if i == 0 {
            String::new()
        } else {
            sha256_hex(rotation_row_canonical(plane, &rows[i - 1]).as_bytes())
        };
        if r.predecessor_row_sha256.trim() != expected_pred {
            v.push(rot(
                RotationDefect::ChainBreak,
                &row,
                format!(
                    "predecessor_row_sha256 = `{}`, computed `{expected_pred}`",
                    r.predecessor_row_sha256.trim()
                ),
            ));
            return v;
        }
    }
    v
}

/// PURE ledger validation. `raw` is the authority record's text; `pins` is the
/// live install-time pair used ONLY for the birth check.
///
/// Returns the full violation set. The one legitimately pending pre-rotation
/// state is reported as [`Violation::PendingDeploymentArtifact`] so it can be
/// DECLARED once in `[deploy_gate].expected_pending`; everything else is the
/// non-declarable [`Violation::RotationLedgerInconsistent`].
pub fn rotation_ledger_violations(
    root: &Path,
    raw: &str,
    pins: Option<RotationPins<'_>>,
) -> Vec<Violation> {
    let outer: RotationOuterToml = match toml::from_str(raw) {
        Ok(o) => o,
        Err(e) => {
            return vec![rot(
                RotationDefect::MalformedTable,
                "[rotation]",
                format!("{VAULT_AUTHORITY_RECORD} does not parse: {e}"),
            )]
        }
    };
    let Some(led) = outer.rotation else {
        return vec![rot(
            RotationDefect::MalformedTable,
            "[rotation]",
            format!(
                "{VAULT_AUTHORITY_RECORD} carries no [rotation] table. Absence is not a pending \
                 state — the pending state is a well-formed ledger that SAYS it is pending."
            ),
        )];
    };
    if led.schema_version != ROTATION_LEDGER_SCHEMA_VERSION {
        return vec![rot(
            RotationDefect::UnknownSchemaVersion,
            "[rotation]",
            format!(
                "schema_version = {} but this reader understands {ROTATION_LEDGER_SCHEMA_VERSION}. \
                 A ledger written to a schema the reader does not know is not partially readable.",
                led.schema_version
            ),
        )];
    }
    let pending = match led.state.as_str() {
        ROTATION_STATE_PENDING => true,
        ROTATION_STATE_ROTATED => false,
        other => {
            return vec![rot(
                RotationDefect::UnknownState,
                "[rotation]",
                format!(
                    "state = `{other}` is not recognised — expected `{ROTATION_STATE_PENDING}` \
                     or `{ROTATION_STATE_ROTATED}`"
                ),
            )]
        }
    };

    let mut v = Vec::new();
    let empty = led.upgrader.is_empty() && led.vault.is_empty();
    // F-2: `rotated` means BOTH planes carry at least one EXECUTED row. The
    // Upgrader rotates FIRST (I-7), so an upgrader-only ledger is a plausible
    // MID-ceremony state — and the word `rotated` must not cover it. The mirror
    // case (a vault row with no upgrader row) was already caught, by
    // PlaneOrdering; stating the rule here makes it symmetric and puts it in
    // one place instead of leaving one direction to a downstream accident.
    let both_present = !led.upgrader.is_empty() && !led.vault.is_empty();

    // The DECLARED pending state, emitted independently of everything below so
    // that a corrupt ledger shows up as a pure SURPLUS rather than masking
    // itself behind a shortfall.
    if pending && empty {
        v.push(Violation::PendingDeploymentArtifact {
            path: ROTATION_LEDGER_PENDING_PATH.to_string(),
            detail: format!(
                "the identity rotation has not been performed: [rotation].state = \
                 `{ROTATION_STATE_PENDING}` with both plane arrays empty, and \
                 {ROTATION_LEDGER_PENDING_PATH} does not exist. Declared once in \
                 [deploy_gate].expected_pending and removed by ROT-LEDGER-FILL."
            ),
        });
    }
    let consistent = if pending { empty } else { both_present };
    if !consistent {
        v.push(rot(
            RotationDefect::StateArrayInconsistent,
            "[rotation]",
            format!(
                "state = `{}` but the plane arrays hold {} upgrader and {} vault row(s). \
                 `{ROTATION_STATE_PENDING}` requires BOTH arrays EMPTY; \
                 `{ROTATION_STATE_ROTATED}` requires BOTH planes to carry at least one EXECUTED \
                 row, because a half-rotated ledger is a MID-ceremony state, not a rotated one. \
                 The word and the rows must agree; a record that contradicts itself cannot be \
                 read.",
                led.state,
                led.upgrader.len(),
                led.vault.len()
            ),
        ));
        return v;
    }

    // ── the chain root ───────────────────────────────────────────────────────
    let b_vault = match rotation_parse_all(
        "[rotation.bootstrap]",
        "vault_signers",
        &led.bootstrap.vault_signers,
    ) {
        Ok(p) => p,
        Err(e) => {
            v.push(e);
            return v;
        }
    };
    let b_upg = match rotation_parse_all(
        "[rotation.bootstrap]",
        "upgrader_members",
        &led.bootstrap.upgrader_members,
    ) {
        Ok(p) => p,
        Err(e) => {
            v.push(e);
            return v;
        }
    };
    if led.bootstrap.snapshot_of_pins_at_commit.trim().is_empty() {
        v.push(rot(
            RotationDefect::RequiredFieldEmpty,
            "[rotation.bootstrap]",
            "snapshot_of_pins_at_commit is empty — the snapshot must say which commit's pins it \
             copies"
                .into(),
        ));
        return v;
    }

    // BIRTH CHECK (state-conditioned). While the rotation has not happened the
    // snapshot must still equal reality, so a transposed or REORDERED hand-copy
    // cannot become a false chain root. Once `state` flips, ROT-LEDGER-FILL
    // rewrites the pins and this comparison is skipped BY DESIGN — the snapshot
    // is then the sole anchor, which is the whole point of having it.
    if pending {
        match pins {
            None => {
                v.push(rot(
                    RotationDefect::BootstrapMismatch,
                    "[rotation.bootstrap]",
                    "the live install-time pins could not be loaded, so the birth check cannot \
                     be made. Fail closed: an unverifiable chain root is not a chain root."
                        .into(),
                ));
                return v;
            }
            Some(RotationPins {
                signers: sig,
                signer_threshold: sig_t,
                members: mem,
                member_threshold: mem_t,
                ..
            }) => {
                if !ordered_bytes_equal(&b_vault, sig) {
                    v.push(rot(
                        RotationDefect::BootstrapMismatch,
                        "[rotation.bootstrap]",
                        format!(
                            "vault_signers [{}] does not ordered-byte-equal the pinned signers \
                             [{}]",
                            render(&b_vault),
                            render(sig)
                        ),
                    ));
                    return v;
                }
                if !ordered_bytes_equal(&b_upg, mem) {
                    v.push(rot(
                        RotationDefect::BootstrapMismatch,
                        "[rotation.bootstrap]",
                        format!(
                            "upgrader_members [{}] does not ordered-byte-equal the pinned \
                             [recovery].members [{}]",
                            render(&b_upg),
                            render(mem)
                        ),
                    ));
                    return v;
                }
                if led.bootstrap.vault_threshold != sig_t
                    || led.bootstrap.upgrader_threshold != mem_t
                {
                    v.push(rot(
                        RotationDefect::BootstrapMismatch,
                        "[rotation.bootstrap]",
                        format!(
                            "snapshot thresholds {}/{} do not equal the pinned {sig_t}/{mem_t}",
                            led.bootstrap.vault_threshold, led.bootstrap.upgrader_threshold
                        ),
                    ));
                    return v;
                }
            }
        }
    }
    if empty {
        return v;
    }

    // ── per-row, first failure wins ──────────────────────────────────────────
    let forbidden: BTreeSet<candid::Principal> = FORBIDDEN_AUTHORITY_PRINCIPALS
        .iter()
        .filter_map(|s| candid::Principal::from_text(s).ok())
        .collect();
    let mut row_defects = Vec::new();
    for (plane, rows) in [("upgrader", &led.upgrader), ("vault", &led.vault)] {
        let expected_canister = pins.map(|p| if plane == "vault" { p.vault } else { p.upgrader });
        for r in rows.iter() {
            if let Some(d) = rotation_row_violations(root, plane, r, &forbidden, expected_canister)
            {
                row_defects.push(d);
            }
        }
    }
    if !row_defects.is_empty() {
        v.extend(row_defects);
        return v;
    }

    // ── cross-row ────────────────────────────────────────────────────────────
    let mut cross = rotation_plane_chain("upgrader", &led.upgrader, &b_upg);
    cross.extend(rotation_plane_chain("vault", &led.vault, &b_vault));
    if !cross.is_empty() {
        v.extend(cross);
        return v;
    }
    // Vault epoch must strictly advance, rooted on the snapshot.
    let mut prev_epoch = led.bootstrap.vault_epoch;
    for r in &led.vault {
        let row = format!("vault#{}", r.sequence);
        let (oe, ne) = (r.old_epoch.unwrap_or(0), r.new_epoch.unwrap_or(0));
        if oe != prev_epoch || ne <= oe {
            cross.push(rot(
                RotationDefect::EpochNotAdvanced,
                &row,
                format!(
                    "epoch {oe}→{ne} against a predecessor epoch of {prev_epoch}; each vault \
                     rotation must chain onto the previous epoch and STRICTLY advance it"
                ),
            ));
            break;
        }
        prev_epoch = ne;
    }
    // I-7: the Upgrader plane rotates FIRST. A vault row must name an EXECUTED
    // upgrader row, and that row must have been observed no later.
    for r in &led.vault {
        let row = format!("vault#{}", r.sequence);
        let seq = r.after_upgrader_sequence.unwrap_or(0);
        match led.upgrader.iter().find(|u| u.sequence == seq) {
            None => cross.push(rot(
                RotationDefect::PlaneOrdering,
                &row,
                format!(
                    "after_upgrader_sequence = {seq} names no EXECUTED upgrader row — the \
                     Upgrader plane rotates BEFORE the Vault"
                ),
            )),
            Some(u) if u.observed_at_ns > r.observed_at_ns => cross.push(rot(
                RotationDefect::PlaneOrdering,
                &row,
                format!(
                    "upgrader#{seq} was observed at {} but this vault row at {} — the Upgrader \
                     rotation must precede the Vault rotation in TIME, not merely be cited",
                    u.observed_at_ns, r.observed_at_ns
                ),
            )),
            Some(_) => {}
        }
    }
    if !cross.is_empty() {
        v.extend(cross);
        return v;
    }

    // ── the HEAD-time bound, LAST ────────────────────────────────────────────
    //
    // Deliberately the final check: it shells out to git, so a fixture that
    // exercises any earlier defect observes that defect and not a git failure.
    match rotation_head_commit_time(root) {
        Err(e) => v.push(rot(
            RotationDefect::HeadTimeUnavailable,
            "[rotation]",
            format!(
                "cannot read the checked HEAD's commit time: {e}. A record cannot be shown to \
                 predate the commit that carries it, so the check fails closed."
            ),
        )),
        Ok(head_secs) => {
            for (plane, rows) in [("upgrader", &led.upgrader), ("vault", &led.vault)] {
                for r in rows.iter() {
                    if (r.observed_at_ns / 1_000_000_000) as i64 > head_secs {
                        v.push(rot(
                            RotationDefect::TimestampInFuture,
                            &format!("{plane}#{}", r.sequence),
                            format!(
                                "observed_at_ns {} is after the checked HEAD's commit time \
                                 ({head_secs}s) — a read-back cannot have happened after the \
                                 commit that records it",
                                r.observed_at_ns
                            ),
                        ));
                    }
                }
            }
        }
    }
    v
}

/// IO wrapper: read the authority record, load the live pins for the birth
/// check, run the pure validator.
///
/// A missing or unreadable record is a VIOLATION, never a skip — the pending
/// state is a well-formed ledger that says it is pending, not an absent one.
pub fn check_rotation_ledger(root: &Path) -> Vec<Violation> {
    let path = root.join(VAULT_AUTHORITY_RECORD);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            return vec![rot(
                RotationDefect::MalformedTable,
                "[rotation]",
                format!("cannot read {VAULT_AUTHORITY_RECORD}: {e}"),
            )]
        }
    };
    let auth = load_authority_record(root).ok().flatten();
    let rec = load_recovery_record(root).ok().flatten();
    let pins = match (auth.as_ref(), rec.as_ref()) {
        (Some(a), Some(r)) => Some(RotationPins {
            signers: a.signers.as_slice(),
            signer_threshold: a.threshold,
            members: r.members.as_slice(),
            member_threshold: r.threshold,
            vault: r.vault,
            upgrader: a.upgrader,
        }),
        _ => None,
    };
    rotation_ledger_violations(root, &raw, pins)
}
