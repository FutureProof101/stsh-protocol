/**
 * Encrypted-at-rest note cache (wallet-build Commit 5; Campaign B / L4).
 *
 * The scanner (crypto/scanner.ts) recovers the user's notes from public
 * on-chain data every session. Re-scanning the whole tree each login is
 * wasteful, so the decrypted note set + the last scanned leaf index are cached
 * locally. Because that cache reveals the user's balance and note linkage, it
 * is encrypted at rest with AES-256-GCM.
 *
 * L4 (Campaign B) hardens the at-rest model:
 *
 * - KDF v2: Argon2id (hash-wasm, m=65536 KiB, t=3, p=4, 32-byte key, 16-byte
 *   salt). The PBKDF2 path is retained ONLY to decrypt legacy (kdfVersion 1)
 *   records during migration — never for new writes. A KDF failure (e.g. WASM
 *   memory allocation on a low-memory device) surfaces as a typed
 *   KdfUnavailableError; parameters are NEVER silently downgraded.
 * - Principal scoping: v2 records live under `state:<principal>`; the pre-L4
 *   unscoped singleton (`state`) is migrated only when it decrypts under the
 *   presented passphrase AND holds zero notes — otherwise open() stops with a
 *   typed LegacyNoteFormatUnsupportedError, record left untouched. The
 *   singleton is NEVER silently claimed by the first principal to log in, and
 *   the sanctioned empty-record migration resets the scan cursor to 0: the
 *   singleton carries no owner, so its cursor may belong to a different
 *   principal's scanning — inheriting it could skip this principal's notes.
 * - AAD: every v2 ciphertext is bound to (kdfVersion, cache schema version,
 *   owning principal) via AES-GCM additional data — copying a record into
 *   another principal's slot, or flipping the stored version fields, fails
 *   authentication. Unknown runtime version values are rejected before any
 *   crypto runs.
 * - THREE version concepts are deliberately separate and must not be merged:
 *   the KDF record version (`kdfVersion` 1|2), the cache schema version
 *   (`SerializedState.v` 1|2), and the note payload version (0x02, L0-B —
 *   not this module's concern).
 * - Concurrency (§1.1): a PrincipalNoteCache is epoch-bound at construction
 *   (SessionBinding) and every write goes through `update(fn)`, whose revision
 *   CAS executes inside a single IndexedDB read-check-write transaction
 *   (PrincipalCacheStore.compareAndPut) — an in-memory mutex protects one tab
 *   only; two tabs have separate JS mutexes.
 *
 * HARD RULE (W-VETKEYS D-1b v2, 2026-08-27): plaintext vetKey,
 * `masterNoteSecret`, wallet passcode, passphrase, cache key, and every derived
 * secret are NEVER persisted—on this device, in this cache, or canister-side.
 * The sole canister-side secret derivative is the versioned device envelope:
 * an RSA-OAEP-3072/SHA-256 ciphertext of the raw vetKey to a registered
 * device's non-extractable public key, optionally encrypted as a whole under
 * AES-256-GCM with an Argon2id-derived opt-in passcode key. The canister stores
 * only the final opaque envelope. Local persistence is limited to
 * non-extractable WebCrypto `CryptoKey` handles, non-secret KDF/envelope
 * metadata, and the always-encrypted note cache. No raw or wrapped vetKey,
 * master secret, passcode/passphrase, or derived key is written to
 * localStorage, IndexedDB, service-worker caches, logs, telemetry, or crash
 * state. All plaintext key material and operational handles are memory-only
 * and dropped on lock/logout.
 */

import { argon2id } from "hash-wasm";
import { Principal } from "@dfinity/principal";

/** One recovered note as cached — the noteFromBytes fields plus its leaf index. */
export interface ScannedNote {
  leafIndex: bigint;
  value: bigint;
  rho: Uint8Array;
  rseed: Uint8Array;
  recipientPk: Uint8Array;
  // ── L3b additions (additive + optional on cache schema v2 — pre-L3b records
  // simply lack them; see the L3a journal comment below for the evidence) ──
  /** The 16-byte v2 derivation nonce (absent on legacy v1 notes). */
  nonce?: Uint8Array;
  /** The 32-byte inner commitment (recomputed at validation time). */
  commitment?: Uint8Array;
  /** The 32-byte derived nullifier (spent-set classification key). */
  nullifier?: Uint8Array;
  /** Explicit lifecycle — absent on pre-L3b records (see NOTE_STATE_LEGACY). */
  state?: NoteLifecycleState;
  /**
   * WALLET-AUTH Gate 1, cache schema v3 ONLY: this note was produced by a sweep
   * that was anchored to the POOL's accepted root over the replicated (verified)
   * transport, and that sweep completed in full.
   *
   * ABSENT MEANS UNVERIFIED, and that is the whole point of the field being
   * optional rather than a tri-state: every record written before v3, every
   * note carried across the v2→v3 migration, and every note from an ordinary
   * query-path scan all read as unverified without anyone having to remember to
   * write a `false`.
   *
   * It is NEVER read out of a v2 payload (`notesFromPayload` drops it), so a
   * hand-edited v2 blob claiming `verified: true` imports unverified.
   *
   * WHAT IT IS NOT. It is not a statement that the note is spendable, and not a
   * statement that the pool is honest. A dishonest pool signs whatever history
   * it likes; this flag says a boundary node or a network position did not get
   * to choose which history the wallet saw. The pool remains the arbiter of
   * spendability at submission.
   */
  verified?: boolean;
  /**
   * WL-2a, additive + optional on cache schema v2 (same precedent as the L3b
   * fields above): when the scanner FIRST saw this note locally (ns, decimal).
   *
   * This is the limb-B anchor — the only local proxy for "an incoming note
   * arrived", since a note carries no arrival time and the pool exposes none.
   * It is LOCAL ONLY: never sent, never derived from anything an observer
   * supplies, and MONOTONIC — a rescan re-derives the same note and must not
   * reset its first sighting to the rescan's clock (see `mergeScannedNotes`).
   *
   * Absent on every pre-WL-2a record, which classifies as origin "unknown" —
   * an honest "not known here", never a reassurance. `SerializedState.v` does
   * NOT move for this field.
   */
  firstSeenAtNs?: string;
  /**
   * L07-03 (R-7 item 5): HOW this note's `firstSeenAtNs` was established.
   *
   * "live-scan" — it appeared during an INCREMENTAL scan of a device that
   * already held prior cache state, i.e. a genuine new arrival.
   * "recovery-import" — the cache was empty at scan start (fresh install OR
   * recovery); the copy never claims which.
   *
   * Without this, `firstSeenAtNs` on a fresh device is the SCAN clock, not an
   * arrival, and the wallet told the user a note "reached you within the last
   * 24 hours" on the sole evidence of when it happened to scan.
   *
   * Absent on every pre-this-field record, which is treated identically to
   * "recovery-import" — the SAFE direction: unknown provenance is never
   * assumed to mean "just arrived". `SerializedState.v` does NOT move for this
   * field, same precedent as `firstSeenAtNs` above.
   */
  firstSeenVia?: "live-scan" | "recovery-import";
}

// ── L3b: explicit note lifecycle (validated pipeline, §9) ────────────────────
//
// Only `spendable` ever contributes to balance/spend selection. `pending` is
// reserved for L3c's spend journal (a spend in flight — never set by the
// scan pipeline). `dummy` is a zero-value output, classified distinctly from
// spendable notes (never balance). `quarantined` covers both rejected
// on-chain candidates AND legacy pre-L3b cached notes (state absent at
// deserialize → quarantined at read time, never balance).

export type NoteLifecycleState = "spendable" | "pending" | "spent" | "dummy" | "quarantined";

/** Quarantine reason codes (bounded diagnostics — S-29; never the payload). */
export type QuarantineReason =
  | "legacy-v1-payload" // on-chain 104-byte legacy payload
  | "malformed-payload" // decrypted but not a well-formed 0x02/121B note
  | "field-mismatch" // derived rho/rseed/recipientPk != payload fields
  | "leaf-mismatch" // recomputed outer leaf != the mirror/page leaf at index
  | "legacy-v1-note"; // pre-L3b cached note (no v2 nonce), excluded at read time

/** One bounded quarantine diagnostic (ring entry). */
export interface QuarantineEntry {
  leafIndex: bigint;
  reason: QuarantineReason;
}

/**
 * Bounded quarantine diagnostics (S-29): an attacker can spam victim-readable
 * invalid payloads for free, so the wallet NEVER retains quarantined payloads
 * or notes — only a monotonic counter + a small ring of the most recent
 * {leafIndex, reason} entries. The scan cursor advances regardless.
 */
export interface QuarantineState {
  /** Monotonic total of every quarantined candidate ever seen (all scans). */
  total: number;
  /** The most recent entries, oldest first; capped at QUARANTINE_RING_CAP. */
  ring: QuarantineEntry[];
}

/** Cap on the quarantine diagnostics ring (S-29 bound — memory stays flat). */
export const QUARANTINE_RING_CAP = 32;

/** The merkle-tree head observed at the last scan (atomic get_scan_head). */
export interface MirrorHead {
  leafCount: bigint;
  root: Uint8Array;
}

// ── L3c: spend journal (persisted INSIDE the encrypted v2 state) ─────────────
//
// Same ONE-write-path pattern as the L3a shield journal: additive optional
// field on cache schema v2, JSON-safe primitives only. INVARIANT for every
// update(fn) caller: fn MUST spread the state it was given so fields it does
// not own survive a CAS re-apply.

/** Spend-journal entry lifecycle. */
export type SpendEntryStatus =
  /** persisted + input locked, NEVER dispatched — the only status that may be
   * archived + unlocked atomically (pre-wire exits). */
  | "planned"
  /** on the wire (dispatchedAtNs set), outcome uncertain — locked; never
   * resubmitted blindly. */
  | "dispatched"
  /** authoritative completion observed (private_spend Ok / retry Ok). */
  | "finalized"
  /** pool reports a payout obligation — retryPrivateSpendPayout SAME id. */
  | "payout-pending"
  /** terminal (audit only — a pre-wire archive or a pool-terminal failure). */
  | "failed"
  /** fresh-device import WITHOUT local output material (S-15/S-30): retained
   * for reconciliation; never fabricates change, never unlocks the input. */
  | "recovery-required";

/** One spend intent in the encrypted journal (recovery envelope, S-15). */
export interface SpendJournalEntryState {
  /** u64 decimal string — CSPRNG-generated, no JS-number conversion. */
  spendId: string;
  /** Input nullifier (hex) — spent classification + fingerprint field. */
  nullifierHex: string;
  /**
   * Input leaf index (decimal string), or "" when UNKNOWN (a fresh-device
   * recovery import has no local leaf binding). Completion paths MUST treat ""
   * as "no local note to mutate" — never parse it as 0 (BigInt("") === 0n
   * would corrupt leaf 0).
   */
  inputLeafIndex: string;
  /** The two value-bound output Merkle leaves (hex) — output_commitments. */
  outputLeavesHex: string[];
  /** The two output v2 nonces (hex) — change-note derivation material. */
  outNoncesHex: string[];
  /** The two IBE output payloads (hex) — change-note recovery material. */
  encryptedOutputsHex: string[];
  /** The byte-exact serialized PrivateSpendRequest (idempotent resubmission). */
  requestJson: string;
  /** Logical-intent fingerprint (hex): nullifier ‖ output leaves ‖ payout ‖ fee. */
  intentFingerprintHex: string;
  /** The fee basis used at journaling time (e8s, decimal). */
  feeStsh: string;
  /** Public payout (gross public_amount e8s + recipient), if any. */
  publicPayout?: { destinationText: string; subaccountHex?: string; publicAmount: string; recipientNet: string };
  /** The accepted root the witness anchored to (hex). */
  acceptedRootHex: string;
  manifestVersion: number;
  status: SpendEntryStatus;
  createdAtNs: string;
  /** Set ONCE immediately before the first private_spend wire attempt. */
  dispatchedAtNs?: string;
  /**
   * Set when this entry is a FRESH-ID retry of an earlier collided attempt
   * (S-23b): the original spend_id it replaces. A fresh-id attempt that
   * itself collides can NEVER mint another fresh id (no loop).
   */
  collisionOf?: string;
  failureReason?: string;
}

export interface SpendJournalState {
  entries: SpendJournalEntryState[];
}

/**
 * The effective lifecycle of a cached note. A pre-L3b record (no v2 state
 * field) is a legacy note: never spendable — treated as quarantined
 * (`legacy-v1-note`) at read time until a rescan revalidates or replaces it.
 */
export function noteLifecycle(n: ScannedNote): NoteLifecycleState {
  return n.state ?? "quarantined";
}

/** Only spendable notes contribute to balance and spend selection (§9). */
export function spendableNotes(notes: ScannedNote[]): ScannedNote[] {
  return notes.filter((n) => noteLifecycle(n) === "spendable");
}

// ── L3a shield journal (persisted INSIDE the encrypted v2 state) ─────────────
//
// The shield journal reuses the ONE L4 write path (PrincipalNoteCache.update:
// transactional revision CAS, principal scoping, epoch binding, Argon2id/
// AES-GCM at rest) rather than introducing a second store. Its fields are
// deliberately JSON-safe primitives (decimal strings for bigints, hex for
// bytes) so the v2 serializer passes them through unchanged. The field is
// ADDITIVE and OPTIONAL on cache schema v2 — pre-L3a records simply lack it.
// (Pre-release ruling, evidence recorded per the L3a re-review gate: the
// wallet_frontend asset canister is UNBUILT and has never been deployed —
// MAINNET_DEPLOYMENT.md lists it "optional at first launch" and .ai-context.md
// says "skip the unbuilt wallet_frontend asset canister" — so no older v2
// wallet tab can exist in the field to re-serialize a record and drop this
// field. The FIRST deployment ships journal-aware code. Any POST-release
// change to this state bumps the schema to v3.)
//
// INVARIANT for every `update(fn)` caller: fn MUST spread the state it was
// given (`{ ...state, ... }`) so fields it does not own — this journal, or
// future additions — survive a CAS re-apply against another tab's write.

/** One shield intent (one fixed-denomination note) in the encrypted journal. */
export interface ShieldJournalEntryState {
  /** Hex of the 32-byte note commitment — the pool's locator (`get_deposit_status`). */
  commitmentHex: string;
  /** Denomination (e8s, decimal string). The note is credited this FULL amount. */
  denom: string;
  /** Hex of the 16-byte v2 derivation nonce — REQUIRED to re-derive the note. */
  nonceHex: string;
  /** Protocol shielding fee for this denomination (e8s, decimal string). */
  protoFee: string;
  /** Ledger fee snapshotted for this intent (e8s, decimal string). */
  ledgerFee: string;
  /** Hex of the exact IBE ciphertext submitted on-chain (byte-identical resubmit). */
  encryptedPayloadHex: string;
  /**
   * planned   — persisted, NEVER dispatched to the wire (the only status the
   *             reconcile loop may auto-resubmit when no pool record exists)
   * unknown   — DISPATCHED, outcome ambiguous (the pre-wire marker, or a
   *             transport-unknown / record-carrying rejection); NEVER
   *             auto-resubmitted — reconcile via get_deposit_status only
   * deposited — a shield_deposit Ok was observed (NOT terminal — root pending)
   * failed    — definite non-execution (terminal, audit only)
   * accepted  — pool reports CommitmentRootAccepted (terminal success)
   */
  status: "planned" | "deposited" | "unknown" | "failed" | "accepted";
  /** Intent creation time (ns, decimal string). */
  createdAtNs: string;
  /**
   * Set (once, monotonic) IMMEDIATELY BEFORE the first shield_deposit wire
   * attempt. An entry carrying this marker has possibly executed — it is never
   * treated as never-dispatched again.
   */
  dispatchedAtNs?: string;
  /**
   * A shield_deposit Ok was OBSERVED for this commitment. Monotonic — once
   * true, never cleared. (The Ok payload is the pool's `private_balance`, not
   * a ledger block or unique receipt — only this boolean is evidence.)
   */
  successObserved?: boolean;
  /** Last observed pool status kind (reconcile bookkeeping / operator display). */
  poolStatus?: string;
  /** Reason recorded when status is "failed". */
  failureReason?: string;
}

/** The batch ICRC-2 approval intent (one per shield batch). */
export interface ShieldApprovalState {
  /** Absolute allowance the approve sets: Σ(denom + protoFee + ledgerFee). */
  totalAllowance: string;
  /** The CAS guard: allowance observed immediately before approving. */
  expectedAllowance: string;
  /** The ONE stable dedup timestamp (ns) — a retry reuses it byte-for-byte. */
  createdAtTimeNs: string;
  /** Ledger fee for the approve call itself. */
  ledgerFee: string;
  status: "planned" | "approved" | "unknown" | "failed";
  blockIndex?: string;
  failureReason?: string;
}

export interface ShieldJournalState {
  entries: ShieldJournalEntryState[];
  approval: ShieldApprovalState | null;
}

/** The full cached scan state: recovered notes + how far the tree was scanned. */
export interface CachedScanState {
  notes: ScannedNote[];
  /** Exclusive: the next scan resumes from this leaf index. */
  lastScannedIndex: bigint;
  /** L3a shield journal — absent on pre-L3a records (never dropped: see invariant above). */
  shieldJournal?: ShieldJournalState;
  /** L3b: the merkle-tree head observed at the last completed scan (K3-007 indicator). */
  mirrorHead?: MirrorHead;
  /** L3b: bounded quarantine diagnostics (S-29). */
  quarantine?: QuarantineState;
  /** L3c: spend journal — absent on pre-L3c records. */
  spendJournal?: SpendJournalState;
  // ── Cache schema v3 (WALLET-AUTH Gate 1) ──────────────────────────────────
  /** Evidence describing the last COMPLETED verified sweep. Absent = none. */
  verifiedScan?: VerifiedScanMetadata;
  /**
   * The per-deployment monotone floors, keyed by
   * `verifiedFloorKey(config_hash, security_epoch)`.
   *
   * This is the mechanism that detects a coherent rollback — a shorter history
   * that is internally consistent and correctly rooted for its own prefix. The
   * transport cannot detect one, because a canister signs a rollback as happily
   * as it serves one.
   */
  verifiedFloors?: Record<string, VerifiedScanFloor>;
  /** True on a record produced by the one-way v2 → v3 read-path migration. */
  migratedFromV2?: boolean;
}

/**
 * Evidence about ONE completed verified sweep. Field names are the canonical
 * ones from the source they come from (parent brief §5.2) — in particular
 * `config_hash`, which is the pool's own name for the binding. Inventing a
 * `deployment_id` alias for an existing canonical identity is how a second
 * identity concept gets born.
 *
 * Everything here is NON-SECRET and lives INSIDE the encrypted record, so it is
 * covered by the AES-GCM authentication tag over ciphertext + AAD: it cannot be
 * edited in place without the tag check failing at the next open.
 */
export interface VerifiedScanMetadata {
  /** Hex of `DeploymentAttestation.config_hash` — SHA-256 over the immutable wiring. */
  config_hash: string;
  /** Hex of the pool's accepted root at `accepted_leaf_count`. */
  accepted_root: string;
  /** Decimal: the accepted head's leaf count; the sweep's exclusive upper bound. */
  accepted_leaf_count: string;
  /** Decimal: the pool's `get_security_epoch` at validation time. */
  security_epoch: string;
  /** Decimal: the nullifier registry's stable `count` across the sweep. */
  spent_count: string;
  /**
   * Hex of a LOCAL, domain-separated SHA-256 over the spent set (preimage
   * defined at `spentSetDigest` in `crypto/scanner.ts`).
   *
   * It is NOT a canister certificate and must never be described as one. It
   * summarises what THIS wallet downloaded and authenticated, so a later sweep
   * can tell "the same spent set" from "a different one" without re-downloading
   * it. Nothing signed it.
   */
  spent_set_digest: string;
  /** Written by the runtime, never accepted from a caller. */
  evidence_kind: "replicated-replies";
  /**
   * Wall clock at validation — ADVISORY ONLY, for display. Freshness is
   * enforced by monotonic elapsed time within the session plus the rule that a
   * new session needs a fresh verified sweep. A clock moved backwards must not
   * revive old evidence, so nothing gates on this value.
   */
  validated_at_ms: number;
  /** Pinned module constant, never caller-supplied. */
  freshness_budget_ms: number;
}

/**
 * The monotone floor for ONE (deployment, security epoch) pair.
 *
 * KEYED BY `config_hash`, NOT by canister id (parent brief §5.2, SSA C-2): two
 * deployments with the same pool principal but different wiring are different
 * deployments and do not share a floor. The security epoch is in the key too,
 * so a reinstall that bumps the epoch mints a fresh floor with no user action
 * and no lockout (SSA C-2a).
 */
export interface VerifiedScanFloor {
  /** Decimal: the highest accepted leaf count ever verified for this key. */
  highest_accepted_leaf_count: string;
  /** Hex of the accepted root observed AT that count. */
  root_at_count: string;
}

/** The opaque encrypted LEGACY (pre-L4) record — unscoped PBKDF2 singleton. */
export interface StoredRecord {
  /** PBKDF2 salt (public; needed to re-derive the key next session). */
  salt: Uint8Array;
  /** AES-GCM nonce (fresh per write). */
  iv: Uint8Array;
  /** AES-GCM ciphertext of the serialized `CachedScanState`. */
  ciphertext: Uint8Array;
}

/** Legacy persistence backend — the single unscoped record slot. */
export interface NoteStore {
  load(): Promise<StoredRecord | null>;
  save(record: StoredRecord): Promise<void>;
  clear(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Version constants — three SEPARATE version concepts (L4 rule 3)
// ---------------------------------------------------------------------------

/** KDF record version 1: PBKDF2-HMAC-SHA256 (legacy, migration-decrypt only). */
export const KDF_VERSION_LEGACY = 1;
/** KDF record version 2: Argon2id over a user passphrase (legacy after D-1b). */
export const KDF_VERSION_ARGON2ID = 2;
/**
 * KDF record version 3 (W-VETKEYS D-1b v3 §3): the cache key is derived from
 * the user's vetKey under its OWN domain (`stsh-note-cache-unlock-v1`). This is
 * the II-ONLY default — no passphrase, and the cache is still always encrypted.
 */
export const KDF_VERSION_VETKEY_UNLOCK = 3;
/**
 * KDF record version 4 (D-1b v3 §3): the cache key is HKDF-SHA-256 over the
 * ENVELOPE's Argon2id passcode key, under a different `info` string. The
 * Argon2id output is never reused raw, so the cache key and the envelope key
 * are independent.
 */
export const KDF_VERSION_WALLET_PASSCODE = 4;

/**
 * The versions a record may legitimately declare. `salt` is a KDF INPUT only
 * for version 2; for 3 and 4 the key comes from the vetKey or the envelope
 * passcode key, and the stored salt is retained as AAD-bound record metadata so
 * every record has one shape. It is never re-used as a KDF salt for those
 * versions — stated because a field that looks like a KDF salt and is not one
 * is exactly the sort of thing a later reader assumes.
 */
export const KNOWN_KDF_VERSIONS: readonly number[] = [
  KDF_VERSION_ARGON2ID,
  KDF_VERSION_VETKEY_UNLOCK,
  KDF_VERSION_WALLET_PASSCODE,
];

/** Cache schema version of the legacy serialized state. */
const CACHE_FORMAT_VERSION = 1;
/** Cache schema version of v2 (principal-scoped) serialized state. */
export const CACHE_SCHEMA_V2 = 2;
/**
 * Cache schema version 3 (WALLET-AUTH Gate 1).
 *
 * WHY A BUMP AND NOT AN ADDITIVE-OPTIONAL FIELD. `CACHE_SCHEMA_V2` is bound
 * into the AES-GCM associated data (`cacheAad`, used as `additionalData` on
 * both seal and open), so a schema bump NECESSARILY changes the AAD and forces
 * a migration rather than allowing one. The L3a journal comment above
 * pre-committed the rule in terms: "Any POST-release change to this state bumps
 * the schema to v3." This is that change. The cost of bumping when it was not
 * needed is one migration path nobody exercises; the cost of not bumping is
 * inheriting verified-spendable status from a cache written by code with
 * different verification semantics, in the very lane that is establishing the
 * trust anchor.
 *
 * ONE-WAY. v2 records are READ (under the v2 AAD) and rewritten as v3 with
 * every note unverified; v3 records are read and written. Nothing is ever
 * written at v2 again.
 */
export const CACHE_SCHEMA_V3 = 3;
/** The schema versions this build may BIND into an AAD (read side). */
export const READABLE_CACHE_SCHEMAS: readonly number[] = [CACHE_SCHEMA_V2, CACHE_SCHEMA_V3];
/** The schema version this build WRITES. There is exactly one. */
export const WRITE_CACHE_SCHEMA = CACHE_SCHEMA_V3;

// PBKDF2 work factor — OWASP 2023 guidance for PBKDF2-HMAC-SHA256 (legacy).
const PBKDF2_ITERATIONS = 210_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

// Argon2id parameters (L4 §3 — pinned; changing any of these is a KDF-version
// bump, never an in-place edit; the determinism test vector pins them too).
export const ARGON2ID_MEMORY_KIB = 65536;
export const ARGON2ID_ITERATIONS = 3;
export const ARGON2ID_PARALLELISM = 4;
export const ARGON2ID_KEY_BYTES = 32;
export const ARGON2ID_SALT_BYTES = 16;

interface SerializedNote {
  leafIndex: string;
  value: string;
  rho: number[];
  rseed: number[];
  recipientPk: number[];
  /** L3b, additive optional: v2 derivation nonce / commitment / nullifier / state. */
  nonce?: number[];
  commitment?: number[];
  nullifier?: number[];
  state?: string;
  /** v3 ONLY: see `ScannedNote.verified`. Never read from a v2 payload. */
  verified?: boolean;
  /** WL-2a, additive optional: local first-sighting of the note (ns, decimal). */
  firstSeenAtNs?: string;
  /** R-7 item 5, additive optional: how that first sighting was established. */
  firstSeenVia?: string;
}
interface SerializedState {
  v: number;
  lastScannedIndex: string;
  notes: SerializedNote[];
  /** v2-only, additive: the shield journal is already JSON-safe (L3a). */
  shieldJournal?: ShieldJournalState;
  /** L3c, additive: the spend journal is already JSON-safe. */
  spendJournal?: SpendJournalState;
  /** L3b, additive optional: last observed merkle-tree head. */
  mirrorHead?: { leafCount: string; root: number[] };
  /** L3b, additive optional: bounded quarantine diagnostics. */
  quarantine?: { total: number; ring: { leafIndex: string; reason: string }[] };
  /** v3 ONLY. Never read from a v2 payload. */
  verifiedScan?: VerifiedScanMetadata;
  /** v3 ONLY. Never read from a v2 payload. */
  verifiedFloors?: Record<string, VerifiedScanFloor>;
  /** v3 ONLY: set by the one-way migration. */
  migratedFromV2?: boolean;
}

// ---------------------------------------------------------------------------
// Typed errors (L4)
// ---------------------------------------------------------------------------

/** Legacy singleton holds notes: migration is refused, record left untouched. */
export class LegacyNoteFormatUnsupportedError extends Error {
  constructor() {
    super(
      "The pre-L4 note cache on this device contains notes in the legacy format. " +
        "It cannot be migrated or claimed by a signed-in principal; the record was left untouched.",
    );
    this.name = "LegacyNoteFormatUnsupportedError";
  }
}

/** A stored/runtime version field is outside the known set — nothing was tried. */
export class CacheFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CacheFormatError";
  }
}

/** AES-GCM authentication failed: wrong passphrase or a tampered/rebound record. */
export class CacheAuthenticationError extends Error {
  constructor() {
    super(
      "Note-cache decryption failed: wrong passphrase, or the stored record was tampered with " +
        "or bound to a different principal/version.",
    );
    this.name = "CacheAuthenticationError";
  }
}

/** Argon2id could not run (e.g. WASM memory on a low-memory device). NO fallback. */
export class KdfUnavailableError extends Error {
  constructor(cause: unknown) {
    super(
      "Argon2id key derivation failed on this device. The cache stays locked — " +
        "parameters are never downgraded.",
      { cause },
    );
    this.name = "KdfUnavailableError";
  }
}

/** The session epoch advanced (logout/expiry) or the cache was locked. */
export class CacheSessionStaleError extends Error {
  constructor(message = "The note-cache session is no longer current; the cache is locked.") {
    super(message);
    this.name = "CacheSessionStaleError";
  }
}

/** The revision CAS lost repeatedly — give up rather than spin. */
export class CacheWriteConflictError extends Error {
  constructor() {
    super("Note-cache write conflict: another tab kept winning the revision CAS.");
    this.name = "CacheWriteConflictError";
  }
}

/** A record that open() guaranteed to exist is gone — external interference. */
export class CacheIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CacheIntegrityError";
  }
}

// ---------------------------------------------------------------------------
// Legacy (v1) KDF + serialization — retained for scanner.ts (L3b surface) and
// for the migration decrypt path ONLY. New writes never use these.
// ---------------------------------------------------------------------------

/** Derive the AES-256-GCM cache key from a passphrase + salt (PBKDF2-SHA256). */
export async function deriveCacheKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase) as BufferSource,
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"],
  );
}

/** JSON-safe serialization of the scan state (bigints -> strings, bytes -> arrays). */
export function serializeScanState(state: CachedScanState): Uint8Array {
  const payload: SerializedState = {
    v: CACHE_FORMAT_VERSION,
    lastScannedIndex: state.lastScannedIndex.toString(10),
    notes: state.notes.map((n) => ({
      leafIndex: n.leafIndex.toString(10),
      value: n.value.toString(10),
      rho: [...n.rho],
      rseed: [...n.rseed],
      recipientPk: [...n.recipientPk],
    })),
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

/**
 * `allowVerified` is the v2/v3 asymmetry made explicit, and it defaults to the
 * safe side. The v2 reader passes nothing, so a `verified` key sitting in a
 * v2 plaintext — hand-edited, or written by some future code that should not
 * have — is DROPPED on the floor rather than parsed. That is why the v2 half
 * of AC-20 asserts on the resulting note state and not on a parser rejection:
 * there is nothing to reject, the field simply does not exist at v2.
 */
function notesFromPayload(payload: SerializedState, allowVerified = false): CachedScanState {
  return {
    lastScannedIndex: BigInt(payload.lastScannedIndex),
    notes: payload.notes.map((n) => ({
      leafIndex: BigInt(n.leafIndex),
      value: BigInt(n.value),
      rho: Uint8Array.from(n.rho),
      rseed: Uint8Array.from(n.rseed),
      recipientPk: Uint8Array.from(n.recipientPk),
      ...(n.nonce !== undefined ? { nonce: Uint8Array.from(n.nonce) } : {}),
      ...(n.commitment !== undefined ? { commitment: Uint8Array.from(n.commitment) } : {}),
      ...(n.nullifier !== undefined ? { nullifier: Uint8Array.from(n.nullifier) } : {}),
      ...(n.state !== undefined ? { state: parseNoteLifecycleState(n.state) } : {}),
      ...(allowVerified && n.verified === true ? { verified: true as const } : {}),
      ...(n.firstSeenAtNs !== undefined ? { firstSeenAtNs: n.firstSeenAtNs } : {}),
      ...(n.firstSeenVia !== undefined
        ? { firstSeenVia: n.firstSeenVia as "live-scan" | "recovery-import" }
        : {}),
    })),
  };
}

const NOTE_LIFECYCLE_STATES: readonly string[] = ["spendable", "pending", "spent", "dummy", "quarantined"];

function parseNoteLifecycleState(raw: string): NoteLifecycleState {
  if (!NOTE_LIFECYCLE_STATES.includes(raw)) {
    throw new CacheFormatError(`stored note has unknown lifecycle state "${raw}"`);
  }
  return raw as NoteLifecycleState;
}

const QUARANTINE_REASONS: readonly string[] = [
  "legacy-v1-payload",
  "malformed-payload",
  "field-mismatch",
  "leaf-mismatch",
  "legacy-v1-note",
];

/** Light structural check on the L3b additive fields — corrupt shapes fail loudly. */
function validateScanAdditions(state: CachedScanState): void {
  for (const n of state.notes) {
    if (n.nonce !== undefined && n.nonce.length !== 16) {
      throw new CacheFormatError("stored note nonce is not 16 bytes");
    }
  }
  if (state.mirrorHead !== undefined && state.mirrorHead.root.length !== 32) {
    throw new CacheFormatError("stored mirror head root is not 32 bytes");
  }
  if (state.quarantine !== undefined) {
    if (state.quarantine.ring.length > QUARANTINE_RING_CAP) {
      throw new CacheFormatError("stored quarantine ring exceeds its bound");
    }
    for (const e of state.quarantine.ring) {
      if (!QUARANTINE_REASONS.includes(e.reason)) {
        throw new CacheFormatError(`stored quarantine entry has unknown reason "${e.reason}"`);
      }
    }
  }
}

/** Inverse of `serializeScanState`. Throws on an unrecognised format version. */
export function deserializeScanState(bytes: Uint8Array): CachedScanState {
  const payload = JSON.parse(new TextDecoder().decode(bytes)) as SerializedState;
  if (payload.v !== CACHE_FORMAT_VERSION) {
    throw new Error(`unsupported note-cache format version ${payload.v}`);
  }
  return notesFromPayload(payload);
}

// ---------------------------------------------------------------------------
// v2 KDF + serialization + AAD
// ---------------------------------------------------------------------------

/**
 * Derive the AES-256-GCM cache key via Argon2id with the PINNED parameters.
 * Any hash-wasm failure (WASM unavailable, memory allocation on a low-memory
 * device) becomes a typed KdfUnavailableError — there is no PBKDF2 or
 * reduced-parameter fallback (a silent downgrade is the attack).
 */
export async function deriveCacheKeyV2(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (salt.length !== ARGON2ID_SALT_BYTES) {
    throw new CacheFormatError(`v2 salt must be ${ARGON2ID_SALT_BYTES} bytes, got ${salt.length}`);
  }
  let raw: Uint8Array;
  try {
    raw = await argon2id({
      password: passphrase,
      salt,
      memorySize: ARGON2ID_MEMORY_KIB,
      iterations: ARGON2ID_ITERATIONS,
      parallelism: ARGON2ID_PARALLELISM,
      hashLength: ARGON2ID_KEY_BYTES,
      outputType: "binary",
    });
  } catch (cause) {
    throw new KdfUnavailableError(cause);
  }
  try {
    return await crypto.subtle.importKey(
      "raw",
      raw as BufferSource,
      { name: "AES-GCM" },
      false, // non-extractable
      ["encrypt", "decrypt"],
    );
  } finally {
    raw.fill(0); // drop the raw key bytes as soon as the CryptoKey wraps them
  }
}

function serializePayload(state: CachedScanState, schemaVersion: number): SerializedState {
  const payload: SerializedState = {
    v: schemaVersion,
    lastScannedIndex: state.lastScannedIndex.toString(10),
    notes: state.notes.map((n) => ({
      leafIndex: n.leafIndex.toString(10),
      value: n.value.toString(10),
      rho: [...n.rho],
      rseed: [...n.rseed],
      recipientPk: [...n.recipientPk],
      ...(n.nonce !== undefined ? { nonce: [...n.nonce] } : {}),
      ...(n.commitment !== undefined ? { commitment: [...n.commitment] } : {}),
      ...(n.nullifier !== undefined ? { nullifier: [...n.nullifier] } : {}),
      ...(n.state !== undefined ? { state: n.state } : {}),
      ...(schemaVersion >= CACHE_SCHEMA_V3 && n.verified === true ? { verified: true } : {}),
      ...(n.firstSeenAtNs !== undefined ? { firstSeenAtNs: n.firstSeenAtNs } : {}),
      ...(n.firstSeenVia !== undefined ? { firstSeenVia: n.firstSeenVia } : {}),
    })),
  };
  if (state.shieldJournal !== undefined) payload.shieldJournal = state.shieldJournal;
  if (state.spendJournal !== undefined) payload.spendJournal = state.spendJournal;
  if (state.mirrorHead !== undefined) {
    payload.mirrorHead = {
      leafCount: state.mirrorHead.leafCount.toString(10),
      root: [...state.mirrorHead.root],
    };
  }
  if (state.quarantine !== undefined) {
    payload.quarantine = {
      total: state.quarantine.total,
      ring: state.quarantine.ring.map((e) => ({
        leafIndex: e.leafIndex.toString(10),
        reason: e.reason,
      })),
    };
  }
  if (schemaVersion >= CACHE_SCHEMA_V3) {
    if (state.verifiedScan !== undefined) payload.verifiedScan = state.verifiedScan;
    if (state.verifiedFloors !== undefined) payload.verifiedFloors = state.verifiedFloors;
    if (state.migratedFromV2 === true) payload.migratedFromV2 = true;
  }
  return payload;
}

/**
 * v2 serialization (schema version 2). RETAINED FOR READS AND TESTS ONLY — no
 * write path calls it since the v3 bump. It deliberately does NOT emit the v3
 * fields: a v2 payload carrying `verified` would be a v3 record wearing a v2
 * version number, which is exactly the confusion the AAD binding exists to
 * prevent.
 */
export function serializeScanStateV2(state: CachedScanState): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(serializePayload(state, CACHE_SCHEMA_V2)));
}

/** v3 serialization — the ONLY shape this build writes. */
export function serializeScanStateV3(state: CachedScanState): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(serializePayload(state, CACHE_SCHEMA_V3)));
}

/** Light structural check on a stored shield journal — corrupt shapes fail loudly. */
function validateShieldJournal(journal: ShieldJournalState): void {
  if (typeof journal !== "object" || journal === null || !Array.isArray(journal.entries)) {
    throw new CacheFormatError("stored shield journal is malformed");
  }
  for (const entry of journal.entries) {
    if (typeof entry.commitmentHex !== "string" || typeof entry.status !== "string") {
      throw new CacheFormatError("stored shield-journal entry is malformed");
    }
  }
}

const SPEND_ENTRY_STATUSES: readonly string[] = [
  "planned",
  "dispatched",
  "finalized",
  "payout-pending",
  "failed",
  "recovery-required",
];

/** Light structural check on a stored spend journal — corrupt shapes fail loudly. */
function validateSpendJournal(journal: SpendJournalState): void {
  if (typeof journal !== "object" || journal === null || !Array.isArray(journal.entries)) {
    throw new CacheFormatError("stored spend journal is malformed");
  }
  for (const entry of journal.entries) {
    if (
      typeof entry.spendId !== "string" ||
      !SPEND_ENTRY_STATUSES.includes(entry.status) ||
      !Array.isArray(entry.outputLeavesHex) ||
      entry.outputLeavesHex.length !== 2 ||
      !Array.isArray(entry.outNoncesHex) ||
      entry.outNoncesHex.length !== 2 ||
      !Array.isArray(entry.encryptedOutputsHex) ||
      entry.encryptedOutputsHex.length !== 2
    ) {
      throw new CacheFormatError("stored spend-journal entry is malformed");
    }
  }
}

/** Strict v2 parse — accepts schema version 2 ONLY (v1 goes through parseV1). */
export function deserializeScanStateV2(bytes: Uint8Array): CachedScanState {
  const payload = JSON.parse(new TextDecoder().decode(bytes)) as SerializedState;
  if (payload.v !== CACHE_SCHEMA_V2) {
    throw new CacheFormatError(`unsupported v2 note-cache schema version ${payload.v}`);
  }
  const state = notesFromPayload(payload);
  if (payload.shieldJournal !== undefined) {
    validateShieldJournal(payload.shieldJournal);
    state.shieldJournal = payload.shieldJournal;
  }
  if (payload.spendJournal !== undefined) {
    validateSpendJournal(payload.spendJournal);
    state.spendJournal = payload.spendJournal;
  }
  if (payload.mirrorHead !== undefined) {
    state.mirrorHead = {
      leafCount: BigInt(payload.mirrorHead.leafCount),
      root: Uint8Array.from(payload.mirrorHead.root),
    };
  }
  if (payload.quarantine !== undefined) {
    state.quarantine = {
      total: payload.quarantine.total,
      ring: payload.quarantine.ring.map((e) => ({
        leafIndex: BigInt(e.leafIndex),
        reason: e.reason as QuarantineReason,
      })),
    };
  }
  validateScanAdditions(state);
  return state;
}

// ---------------------------------------------------------------------------
// Cache schema v3 — the verified-scan record (WALLET-AUTH Gate 1)
// ---------------------------------------------------------------------------

/** A stored v3 record's verified-scan fields are structurally wrong. */
export class VerifiedScanFormatError extends CacheFormatError {
  constructor(message: string) {
    super(message);
    this.name = "VerifiedScanFormatError";
  }
}

/**
 * A verified sweep observed a history that CONTRADICTS this deployment's floor
 * at the same security epoch: a lower accepted leaf count, or a different
 * accepted root at the same count.
 *
 * NOT a permanent lockout, and not silently repaired either (SSA C-2b). The
 * user is shown this as a possible rollback and can, with an explicit gesture,
 * reset the verified history for this deployment (`resetVerifiedHistory`).
 * Nothing resets it automatically.
 */
export class VerifiedFloorRollbackError extends Error {
  constructor(
    readonly floorKey: string,
    readonly observedLeafCount: bigint,
    readonly floorLeafCount: bigint,
    readonly sameCountDifferentRoot: boolean,
  ) {
    super(
      sameCountDifferentRoot
        ? `verified scan refused: this deployment previously served accepted leaf count ` +
            `${floorLeafCount} with a DIFFERENT root than it serves now. Two mutually ` +
            `inconsistent histories for one deployment is equivocation or a rollback; the ` +
            `wallet will not overwrite what it verified before on the strength of it.`
        : `verified scan refused: this deployment's accepted head has gone BACKWARDS, from ` +
            `leaf count ${floorLeafCount} to ${observedLeafCount}. An accepted root is ` +
            `final; a shorter one is a rollback, however internally consistent it looks.`,
    );
    this.name = "VerifiedFloorRollbackError";
  }
}

/** A v2 blob was presented after this cache had already written v3 (SSA C-7). */
export class CacheSchemaDowngradeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CacheSchemaDowngradeError";
  }
}

/** How long a verified sweep's evidence is treated as fresh. Pinned, never caller-supplied. */
export const VERIFIED_SCAN_FRESHNESS_BUDGET_MS = 15 * 60_000;

function isHexOfBytes(value: unknown, bytes: number): value is string {
  return typeof value === "string" && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
}

function isDecimal(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

/**
 * The floor's key. `config_hash` alone is NOT the key: SSA C-2 established that
 * `config_hash` is SHA-256 over the IMMUTABLE wiring and deliberately excludes
 * mutable security state, so a same-wiring reinstall that resets the tree would
 * collide with the old floor and lock every wallet out of the verified path
 * forever. The security epoch is what distinguishes those two lives of the same
 * wiring, so it is in the key.
 */
export function verifiedFloorKey(configHash: string, securityEpoch: string | bigint): string {
  return `${configHash}:${securityEpoch.toString()}`;
}

/** Structural validation of the v3-only fields. Corrupt shapes fail loudly. */
export function validateVerifiedScanAdditions(state: CachedScanState): void {
  const m = state.verifiedScan;
  if (m !== undefined) {
    if (!isHexOfBytes(m.config_hash, 32)) {
      throw new VerifiedScanFormatError("stored verifiedScan.config_hash is not 32 hex bytes");
    }
    if (!isHexOfBytes(m.accepted_root, 32)) {
      throw new VerifiedScanFormatError("stored verifiedScan.accepted_root is not 32 hex bytes");
    }
    if (!isHexOfBytes(m.spent_set_digest, 32)) {
      throw new VerifiedScanFormatError("stored verifiedScan.spent_set_digest is not 32 hex bytes");
    }
    for (const field of ["accepted_leaf_count", "security_epoch", "spent_count"] as const) {
      if (!isDecimal(m[field])) {
        throw new VerifiedScanFormatError(`stored verifiedScan.${field} is not a decimal string`);
      }
    }
    // `evidence_kind` is written by the runtime and never accepted from a
    // caller; a stored record claiming any other provenance is rejected rather
    // than normalised, because normalising it would invent the provenance.
    if (m.evidence_kind !== "replicated-replies") {
      throw new VerifiedScanFormatError(
        `stored verifiedScan.evidence_kind is "${String(m.evidence_kind)}" — the only ` +
          `provenance this build can write is "replicated-replies"`,
      );
    }
    if (typeof m.validated_at_ms !== "number" || !Number.isFinite(m.validated_at_ms)) {
      throw new VerifiedScanFormatError("stored verifiedScan.validated_at_ms is not a number");
    }
    if (typeof m.freshness_budget_ms !== "number" || !Number.isFinite(m.freshness_budget_ms)) {
      throw new VerifiedScanFormatError("stored verifiedScan.freshness_budget_ms is not a number");
    }
  }
  if (state.verifiedFloors !== undefined) {
    for (const [key, floor] of Object.entries(state.verifiedFloors)) {
      if (!isDecimal(floor?.highest_accepted_leaf_count)) {
        throw new VerifiedScanFormatError(`stored floor "${key}" has a malformed leaf count`);
      }
      if (!isHexOfBytes(floor?.root_at_count, 32)) {
        throw new VerifiedScanFormatError(`stored floor "${key}" root is not 32 hex bytes`);
      }
    }
  }
}

/** Strict v3 parse — accepts schema version 3 ONLY. */
export function deserializeScanStateV3(bytes: Uint8Array): CachedScanState {
  const payload = JSON.parse(new TextDecoder().decode(bytes)) as SerializedState;
  if (payload.v !== CACHE_SCHEMA_V3) {
    throw new CacheFormatError(`unsupported v3 note-cache schema version ${payload.v}`);
  }
  const state = notesFromPayload(payload, true);
  if (payload.shieldJournal !== undefined) {
    validateShieldJournal(payload.shieldJournal);
    state.shieldJournal = payload.shieldJournal;
  }
  if (payload.spendJournal !== undefined) {
    validateSpendJournal(payload.spendJournal);
    state.spendJournal = payload.spendJournal;
  }
  if (payload.mirrorHead !== undefined) {
    state.mirrorHead = {
      leafCount: BigInt(payload.mirrorHead.leafCount),
      root: Uint8Array.from(payload.mirrorHead.root),
    };
  }
  if (payload.quarantine !== undefined) {
    state.quarantine = {
      total: payload.quarantine.total,
      ring: payload.quarantine.ring.map((e) => ({
        leafIndex: BigInt(e.leafIndex),
        reason: e.reason as QuarantineReason,
      })),
    };
  }
  if (payload.verifiedScan !== undefined) state.verifiedScan = payload.verifiedScan;
  if (payload.verifiedFloors !== undefined) state.verifiedFloors = payload.verifiedFloors;
  if (payload.migratedFromV2 === true) state.migratedFromV2 = true;
  validateScanAdditions(state);
  validateVerifiedScanAdditions(state);
  return state;
}

/**
 * The v2 → v3 read-path migration.
 *
 * Key material, note contents, journals, cursor and quarantine are all carried
 * across — the migration is lossless in everything except one thing, and that
 * one thing is the point: NO NOTE IS VERIFIED AFTERWARDS, and NO FLOOR IS
 * INHERITED. A v2 record was written by code with different verification
 * semantics; treating its notes as verified would be trusting a claim that code
 * never made. A fresh verified sweep is the only route back to verified state.
 *
 * `migratedFromV2` is the flag SSA C-7 asks for: once a principal's record has
 * been written at v3, the cache refuses to open a v2 blob for that principal
 * again, so a replayed old v2 blob cannot re-import notes or reset a floor.
 */
export function migrateV2StateToV3(state: CachedScanState): CachedScanState {
  return {
    ...state,
    notes: state.notes.map((n) => {
      const { verified: _dropped, ...rest } = n;
      return rest;
    }),
    verifiedScan: undefined,
    verifiedFloors: undefined,
    migratedFromV2: true,
  };
}

/**
 * The monotone-floor check. Called BEFORE anything is persisted.
 *
 * Returns silently when the observation is consistent with this key's floor
 * (higher count, or the same count with the same root, or no floor at all).
 * Throws `VerifiedFloorRollbackError` otherwise.
 *
 * WHAT THIS DEFEATS, exactly: a boundary node, a network position, or a
 * canister that serves a SHORTER but internally consistent history — the case
 * the transport cannot see, because a signature over a rollback is a valid
 * signature. WHAT IT DOES NOT DEFEAT: a dishonest pool that rotates its
 * `config_hash` or bumps its `security_epoch`, which mints a virgin floor with
 * nothing to contradict. The floor is a defence against a rollback at the
 * boundary or on the network, not against a lying canister (PROT-8 residual).
 */
export function checkVerifiedFloor(state: CachedScanState, meta: VerifiedScanMetadata): void {
  const key = verifiedFloorKey(meta.config_hash, meta.security_epoch);
  const floor = state.verifiedFloors?.[key];
  if (floor === undefined) return;
  const observed = BigInt(meta.accepted_leaf_count);
  const known = BigInt(floor.highest_accepted_leaf_count);
  if (observed < known) {
    throw new VerifiedFloorRollbackError(key, observed, known, false);
  }
  if (observed === known && meta.accepted_root !== floor.root_at_count) {
    throw new VerifiedFloorRollbackError(key, observed, known, true);
  }
}

/**
 * Raise this deployment's floor and record the evidence. PURE — safe to
 * re-apply on a lost CAS.
 *
 * ORDERING IS THE SAFETY PROPERTY (brief G-3): the caller must only reach this
 * after the ENTIRE sweep succeeded — root matched at `n_a`, spent-set digest
 * computed, count stable across the sweep. A floor raised before the sweep
 * completes turns a transient failure into a permanent refusal of every later
 * honest scan.
 */
export function advanceVerifiedFloor(
  state: CachedScanState,
  meta: VerifiedScanMetadata,
): CachedScanState {
  const key = verifiedFloorKey(meta.config_hash, meta.security_epoch);
  const floor = state.verifiedFloors?.[key];
  const observed = BigInt(meta.accepted_leaf_count);
  const known = floor === undefined ? -1n : BigInt(floor.highest_accepted_leaf_count);
  const next: VerifiedScanFloor =
    observed > known
      ? { highest_accepted_leaf_count: meta.accepted_leaf_count, root_at_count: meta.accepted_root }
      : (floor as VerifiedScanFloor);
  return {
    ...state,
    verifiedScan: meta,
    verifiedFloors: { ...(state.verifiedFloors ?? {}), [key]: next },
  };
}

/**
 * The USER-INITIATED reset behind SSA C-2b's explicit warning. Drops exactly
 * one floor, and drops the current evidence if it belonged to that floor.
 *
 * Never called automatically, and never called by a scan. It exists so that a
 * refusal is recoverable by a deliberate human act rather than by a silent
 * mechanism that would make the floor worthless.
 */
export function resetVerifiedHistory(
  state: CachedScanState,
  configHash: string,
  securityEpoch: string | bigint,
): CachedScanState {
  const key = verifiedFloorKey(configHash, securityEpoch);
  const floors = { ...(state.verifiedFloors ?? {}) };
  delete floors[key];
  const current = state.verifiedScan;
  const clearCurrent =
    current !== undefined &&
    verifiedFloorKey(current.config_hash, current.security_epoch) === key;
  return {
    ...state,
    ...(clearCurrent ? { verifiedScan: undefined } : {}),
    verifiedFloors: floors,
  };
}

/** True when this note carries verified provenance from a completed sweep. */
export function noteIsVerified(n: ScannedNote): boolean {
  return n.verified === true;
}

/**
 * Validate a principal for cache scoping: canonical text (round-trips through
 * Principal.fromText) and never anonymous — the cache is a per-user secret.
 */
export function validateCachePrincipal(principalText: string): void {
  let parsed: Principal;
  try {
    parsed = Principal.fromText(principalText);
  } catch {
    throw new CacheFormatError(`invalid cache principal: "${principalText}"`);
  }
  if (parsed.toText() !== principalText) {
    throw new CacheFormatError(`non-canonical cache principal: "${principalText}"`);
  }
  if (parsed.isAnonymous()) {
    throw new CacheFormatError("the anonymous principal cannot own a note cache");
  }
}

const AAD_DOMAIN = "stsh.note-cache.aad.v1";

/**
 * AAD binding (kdfVersion, schema version, owning principal) — length-prefixed
 * canonical bytes. Unknown runtime values are REJECTED here, before any crypto:
 * only (kdfVersion 2, schema 2, valid non-anonymous principal) may be bound.
 */
export function cacheAad(
  kdfVersion: number,
  schemaVersion: number,
  principalText: string,
): Uint8Array {
  if (!KNOWN_KDF_VERSIONS.includes(kdfVersion)) {
    throw new CacheFormatError(`unknown kdfVersion ${kdfVersion} — refusing to bind AAD`);
  }
  // v3 EXTENDS this set; it does not bypass it. A v3 record sealed under the v2
  // AAD (or the reverse) is a defect, not a compatibility shim: the schema
  // version is part of what the authentication tag covers, which is the only
  // reason the bump forces the migration at all.
  if (!READABLE_CACHE_SCHEMAS.includes(schemaVersion)) {
    throw new CacheFormatError(`unknown cache schema version ${schemaVersion} — refusing to bind AAD`);
  }
  validateCachePrincipal(principalText);
  const domain = new TextEncoder().encode(AAD_DOMAIN);
  const principal = new TextEncoder().encode(principalText);
  if (principal.length > 0xff) {
    throw new CacheFormatError("cache principal text exceeds the length-prefix bound");
  }
  const out = new Uint8Array(domain.length + 3 + principal.length);
  out.set(domain, 0);
  out[domain.length] = kdfVersion;
  out[domain.length + 1] = schemaVersion;
  out[domain.length + 2] = principal.length;
  out.set(principal, domain.length + 3);
  return out;
}

// ---------------------------------------------------------------------------
// v2 stored record + principal-scoped CAS store port
// ---------------------------------------------------------------------------

/** The opaque encrypted v2 record persisted under `state:<principal>`. */
export interface StoredCacheRecordV2 {
  /** KDF record version — always 2 (Argon2id). Bound in AAD; a flip fails auth. */
  kdfVersion: number;
  /** Cache schema version of the plaintext — always 2. Bound in AAD. */
  schemaVersion: number;
  /** Argon2id salt (16 bytes; public). */
  salt: Uint8Array;
  /** AES-GCM nonce (12 bytes; fresh per write). */
  iv: Uint8Array;
  /** AES-GCM ciphertext of `serializeScanStateV2(state)`, AAD-bound. */
  ciphertext: Uint8Array;
}

/** A stored slot: the record plus the storage-level CAS revision. */
export interface CacheSlot {
  /** Monotonic per-slot revision; every write CASes on the previous value. */
  revision: number;
  record: StoredCacheRecordV2;
}

/**
 * Principal-scoped persistence port (L4). Every conditional op MUST be atomic
 * with respect to concurrent access from other tabs — the IndexedDB
 * implementation (indexedDbNoteStore.ts) runs each inside a single readwrite
 * transaction; test stores must serialize equivalently. There are deliberately
 * NO unconditional writes: creation expects absence, updates expect the prior
 * revision, and the legacy migration is a single verify-put-delete step.
 */
export interface PrincipalCacheStore {
  /** The v2 slot for `principalText`, or null. */
  get(principalText: string): Promise<CacheSlot | null>;
  /**
   * Write `slot` iff the current slot revision matches `expected`
   * (`null` = the slot must be ABSENT), inside ONE read-check-write
   * transaction. Returns the current occupant on failure.
   */
  compareAndPut(
    principalText: string,
    expected: number | null,
    slot: CacheSlot,
  ): Promise<{ ok: true } | { ok: false; current: CacheSlot | null }>;
  /** The legacy unscoped singleton (`state`), or null. Read-only here. */
  getLegacy(): Promise<StoredRecord | null>;
  /**
   * Sanctioned empty-legacy migration, in ONE transaction: verify the legacy
   * singleton still exists AND is byte-identical to `observedLegacy` (the
   * exact record the caller decrypted and proved empty — L-2: a write landing
   * in the check->migrate window must abort, or a note written by an old
   * wallet tab would be silently destroyed) AND the scoped slot is absent,
   * then write the scoped slot and DELETE the singleton. Any precondition
   * failure changes nothing.
   */
  migrateLegacy(
    principalText: string,
    slot: CacheSlot,
    observedLegacy: StoredRecord,
  ): Promise<
    | { ok: true }
    | { ok: false; reason: "legacy-missing" | "legacy-changed" | "scoped-exists" }
  >;
}

// ---------------------------------------------------------------------------
// Session binding (§1.1 — epoch-bound at construction)
// ---------------------------------------------------------------------------

/**
 * The immutable (principal, sessionEpoch) pair a PrincipalNoteCache is bound
 * to at construction. `assertCurrent()` must throw CacheSessionStaleError once
 * the epoch has advanced (logout/expiry) — session/cacheSession.ts builds
 * bindings over the app's SessionEpoch.
 */
export interface SessionBinding {
  readonly principalText: string;
  readonly epoch: number;
  assertCurrent(): void;
}

// ---------------------------------------------------------------------------
// v2 seal/open helpers
// ---------------------------------------------------------------------------

/**
 * Seal at `WRITE_CACHE_SCHEMA` — v3. The AAD carries the SAME schema version
 * that the record declares and that the plaintext's `v` field declares; those
 * three agreeing is what makes a cross-version splice fail the tag check rather
 * than parse as something plausible.
 */
async function sealRecord(
  key: CryptoKey,
  salt: Uint8Array,
  state: CachedScanState,
  principalText: string,
  kdfVersion: number = KDF_VERSION_ARGON2ID,
): Promise<StoredCacheRecordV2> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const aad = cacheAad(kdfVersion, WRITE_CACHE_SCHEMA, principalText);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
      key,
      serializeScanStateV3(state) as BufferSource,
    ),
  );
  return {
    kdfVersion,
    schemaVersion: WRITE_CACHE_SCHEMA,
    salt,
    iv,
    ciphertext,
  };
}

/**
 * Open a stored record at whichever readable schema it declares, and return v3
 * state either way.
 *
 * A v2 record decrypts under the **v2** AAD — the bytes were sealed with it and
 * nothing else will authenticate them — and is then migrated in memory. The
 * migration is not a formatting step: it drops every note's verified status and
 * every floor (`migrateV2StateToV3`). The next write re-seals at v3.
 *
 * "AAD fails" throughout this module means the AES-GCM authentication tag over
 * ciphertext + AAD did not check out. There is no separate AAD check; the tag
 * is the mechanism.
 */
async function openRecord(
  key: CryptoKey,
  record: StoredCacheRecordV2,
  principalText: string,
): Promise<CachedScanState> {
  // cacheAad re-validates the record's declared versions against the known set
  // (reject-unknown-runtime-values) before any crypto runs.
  const aad = cacheAad(record.kdfVersion, record.schemaVersion, principalText);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: record.iv as BufferSource, additionalData: aad as BufferSource },
      key,
      record.ciphertext as BufferSource,
    );
  } catch {
    throw new CacheAuthenticationError();
  }
  const bytes = new Uint8Array(plaintext);
  if (record.schemaVersion === CACHE_SCHEMA_V3) {
    return deserializeScanStateV3(bytes);
  }
  return migrateV2StateToV3(deserializeScanStateV2(bytes));
}

function emptyScanState(): CachedScanState {
  return { notes: [], lastScannedIndex: 0n };
}

// Bounded retries for open-time creation races and update-time CAS losses.
const MAX_CAS_ATTEMPTS = 10;

// ---------------------------------------------------------------------------
// PrincipalNoteCache (L4)
// ---------------------------------------------------------------------------

/**
 * Principal-scoped, epoch-bound, Argon2id-encrypted view over a
 * PrincipalCacheStore. Construct ONLY with `PrincipalNoteCache.open` — it
 * performs the full L4 migration decision and verifies the passphrase before
 * returning (a wrong passphrase throws AT open(), v1 and v2 alike).
 */
export class PrincipalNoteCache {
  private key: CryptoKey | null;
  private locked = false;
  /**
   * SSA C-7 — the v2 → v3 migration is ONE-WAY per principal.
   *
   * Once this instance has seen or written a v3 record for its principal, a v2
   * blob for the same principal is REFUSED rather than migrated again. Without
   * it, replaying an old v2 blob would re-run the migration, which resets every
   * floor to empty — handing back exactly the rollback the floor exists to
   * refuse.
   *
   * LIMITATION, stated rather than implied, and stated in its GENERAL form
   * (SSA landed-diff F-5 — the narrow version of this paragraph named only v2
   * blobs, which read as though a v3 replay were covered; it is not).
   *
   * This flag is enforced for the life of this INSTANCE, and it discriminates
   * by SCHEMA VERSION, not by age. So:
   *
   *   - a v2 blob presented after a v3 sighting is refused (that is the case
   *     `gateSchema` below exists for, and AC-23 asserts it);
   *   - an OLD v3 blob replayed over a newer v3 record is NOT refused by
   *     anything here. `record.schemaVersion === CACHE_SCHEMA_V3` takes the
   *     early return, and every other check — the AAD, the tag, the revision
   *     counter — is satisfied by the replayed blob because it is all INSIDE
   *     the replayed blob. Such a replay rolls the floor back to whatever it
   *     was when that blob was written.
   *
   * Both cases need the same remedy and neither is in this lane's scope: a
   * durable marker BESIDE the record (a store-schema change), so the check has
   * something to consult that the attacker did not supply. Both also presuppose
   * local write access to the device's IndexedDB, which already defeats the
   * cache by simpler means — which is why this is a disclosed residual and not
   * a hole being left open for convenience.
   */
  private sawV3 = false;

  private constructor(
    private readonly store: PrincipalCacheStore,
    key: CryptoKey,
    private readonly salt: Uint8Array,
    private readonly binding: SessionBinding,
    /**
     * The version this cache's record is SEALED at. Carried on the instance
     * because every write re-seals, and re-sealing a key-based record at the
     * passphrase version would silently make it unopenable by the key that
     * wrote it — a data-loss bug with no error at the time it happens.
     */
    private readonly kdfVersion: number = KDF_VERSION_ARGON2ID,
  ) {
    this.key = key;
  }

  /**
   * Open the cache for `binding.principalText` under `passphrase`.
   *
   * Migration decision (L4 §3):
   * - scoped v2 record        -> Argon2id + verify decrypt (throws on wrong
   *                              passphrase); unknown kdfVersion -> typed error
   * - no scoped record, legacy singleton present
   *     -> PBKDF2 decrypt (THROWS on wrong passphrase — propagated, S-10)
   *     -> parseV1
   *     -> zero notes: migrate (fresh salt+IV, Argon2id, serializeV2, scan
   *        cursor reset to 0, atomic replace + singleton delete)
   *     -> notes present: LegacyNoteFormatUnsupportedError, record untouched
   * - nothing at all          -> fresh salt + Argon2id + empty v2 record
   */
  /**
   * Open a KEY-BASED record (kdfVersion 3 or 4 — D-1b v3 §3).
   *
   * Separate from `open` deliberately: those records have no passphrase, and a
   * single entry point taking `passphrase | key` would make it possible to
   * reach a passphrase derivation for a record that has none. The version check
   * runs BEFORE the key is used, so a passphrase record cannot be opened here
   * either — the two modes stay disjoint in both directions.
   */
  static async openWithKey(
    store: PrincipalCacheStore,
    key: CryptoKey,
    binding: SessionBinding,
  ): Promise<PrincipalNoteCache> {
    binding.assertCurrent();
    validateCachePrincipal(binding.principalText);
    const slot = await store.get(binding.principalText);
    if (slot === null) {
      throw new CacheFormatError("there is no cache record for this principal");
    }
    if (
      slot.record.kdfVersion !== KDF_VERSION_VETKEY_UNLOCK &&
      slot.record.kdfVersion !== KDF_VERSION_WALLET_PASSCODE
    ) {
      throw new CacheFormatError(
        `cache record is at kdfVersion ${slot.record.kdfVersion}, which is not a key-based ` +
          `record — open it with the passphrase path, or migrate it first`,
      );
    }
    await openRecord(key, slot.record, binding.principalText); // authenticate
    binding.assertCurrent();
    return new PrincipalNoteCache(store, key, slot.record.salt, binding, slot.record.kdfVersion);
  }

  /**
   * WALLET-CACHE-II-ONLY (Addendum 3 §3) — open the KEY-BASED record for this
   * principal, or CREATE one sealed under `key` when the slot is empty.
   *
   * This is the fresh-principal twin of `open`'s "nothing stored" branch, and it
   * keeps that branch's safety properties exactly: the key arrives as a
   * non-extractable `CryptoKey` (never bytes), creation is a CAS that expects an
   * ABSENT slot (a lost race re-runs against the winner's record instead of
   * overwriting it), and the epoch is re-checked immediately before the write.
   * It adds one thing `open` does not do on creation: the new record is read
   * back and DECRYPTED under `key` before the cache is handed out, the same
   * discipline `migratePassphraseRecord` applies — a record this function made
   * is proved openable, not assumed to be.
   *
   * A slot that already exists goes through `openWithKey` unchanged, so a
   * passphrase record (kdfVersion 2) is refused here BEFORE any crypto: the
   * modes stay disjoint and nothing can quietly re-seal someone's passphrase
   * record under a key-based version.
   *
   * The pre-L4 unscoped legacy singleton is not consulted: it can only be
   * decrypted with the passphrase it was written under, which this path by
   * construction does not have. It is left exactly as it is.
   *
   * `createVersion` is the version a NEW record is sealed at — 3 (II-only, the
   * default) or 4 (wallet passcode). It never changes an existing record.
   */
  static async openOrCreateWithKey(
    store: PrincipalCacheStore,
    key: CryptoKey,
    binding: SessionBinding,
    createVersion: number = KDF_VERSION_VETKEY_UNLOCK,
  ): Promise<PrincipalNoteCache> {
    if (createVersion !== KDF_VERSION_VETKEY_UNLOCK && createVersion !== KDF_VERSION_WALLET_PASSCODE) {
      throw new CacheFormatError(
        `a key-based cache record is created at kdfVersion ${KDF_VERSION_VETKEY_UNLOCK} or ` +
          `${KDF_VERSION_WALLET_PASSCODE}, not ${createVersion}`,
      );
    }
    binding.assertCurrent();
    validateCachePrincipal(binding.principalText);

    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
      const slot = await store.get(binding.principalText);
      if (slot !== null) {
        return PrincipalNoteCache.openWithKey(store, key, binding);
      }
      // A fresh salt: not a KDF input at these versions (the key is supplied),
      // but every record carries one so all records have one shape.
      const salt = crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
      const record = await sealRecord(key, salt, emptyScanState(), binding.principalText, createVersion);
      binding.assertCurrent();
      const created = await store.compareAndPut(binding.principalText, null, {
        revision: 1,
        record,
      });
      if (!created.ok) continue; // another tab created first — re-run against it

      // Authenticated read-back before the cache is handed out.
      const after = await store.get(binding.principalText);
      if (after === null || after.record.kdfVersion !== createVersion) {
        throw new CacheIntegrityError(
          "the new cache record could not be read back — it was not opened",
        );
      }
      await openRecord(key, after.record, binding.principalText);
      binding.assertCurrent();
      return new PrincipalNoteCache(store, key, after.record.salt, binding, createVersion);
    }
    throw new CacheWriteConflictError();
  }

  static async open(
    store: PrincipalCacheStore,
    passphrase: string,
    binding: SessionBinding,
  ): Promise<PrincipalNoteCache> {
    binding.assertCurrent();
    validateCachePrincipal(binding.principalText);

    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
      const slot = await store.get(binding.principalText);
      if (slot !== null) {
        const record = slot.record;
        if (record.kdfVersion !== KDF_VERSION_ARGON2ID) {
          // Includes a stored-field downgrade to 1/0 and any unknown future
          // value: passPHRASE slots are only ever written at kdfVersion 2, so
          // anything else is tampering, corruption, or — since D-1b — a record
          // that belongs to a key-based mode and must be opened with
          // `openWithKey`, never by deriving from a passphrase.
          throw new CacheFormatError(
            `stored cache record for this principal has kdfVersion ${record.kdfVersion}, which ` +
              `is not a passphrase record (versions ${KDF_VERSION_VETKEY_UNLOCK} and ` +
              `${KDF_VERSION_WALLET_PASSCODE} are opened with openWithKey)`,
          );
        }
        const key = await deriveCacheKeyV2(passphrase, record.salt);
        await openRecord(key, record, binding.principalText); // passphrase/AAD verify
        binding.assertCurrent();
        return new PrincipalNoteCache(store, key, record.salt, binding);
      }

      const legacy = await store.getLegacy();
      if (legacy !== null) {
        // S-10: a wrong passphrase must throw HERE and propagate — the legacy
        // record is never reinterpreted as "no cache".
        const legacyKey = await deriveCacheKey(passphrase, legacy.salt);
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: legacy.iv as BufferSource },
          legacyKey,
          legacy.ciphertext as BufferSource,
        );
        const v1state = deserializeScanState(new Uint8Array(plaintext)); // strict v===1
        if (v1state.notes.length > 0) {
          throw new LegacyNoteFormatUnsupportedError();
        }
        // Sanctioned migration: provably empty + passphrase-verified. Fresh
        // salt + IV, v2 schema, cursor reset (see module comment), and the
        // replace + singleton delete happen in ONE store transaction that
        // re-verifies the singleton is byte-identical to the record proved
        // empty above (L-2 ruling: never overwrite a record that changed in
        // the check->migrate window).
        const salt = crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
        const key = await deriveCacheKeyV2(passphrase, salt);
        const record = await sealRecord(key, salt, emptyScanState(), binding.principalText);
        binding.assertCurrent();
        const migrated = await store.migrateLegacy(
          binding.principalText,
          { revision: 1, record },
          legacy,
        );
        if (!migrated.ok) {
          if (migrated.reason === "legacy-changed") {
            // Something wrote to the singleton mid-window (an old-wallet tab
            // saving notes is the dangerous case). Fail closed on the typed
            // path — the record is untouched; the next open() re-evaluates
            // the fresh content from scratch.
            throw new LegacyNoteFormatUnsupportedError();
          }
          continue; // another tab migrated/created first — re-run
        }
        return new PrincipalNoteCache(store, key, salt, binding);
      }

      // Nothing stored for this principal: mint a fresh empty v2 record.
      const salt = crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
      const key = await deriveCacheKeyV2(passphrase, salt);
      const record = await sealRecord(key, salt, emptyScanState(), binding.principalText);
      binding.assertCurrent();
      const created = await store.compareAndPut(binding.principalText, null, {
        revision: 1,
        record,
      });
      if (!created.ok) continue; // another tab created first — re-run against it
      return new PrincipalNoteCache(store, key, salt, binding);
    }
    throw new CacheWriteConflictError();
  }

  /** The (principal, epoch) pair this instance is bound to. */
  get boundPrincipal(): string {
    return this.binding.principalText;
  }
  get boundEpoch(): number {
    return this.binding.epoch;
  }

  private usableKey(): CryptoKey {
    this.binding.assertCurrent();
    if (this.locked || this.key === null) {
      throw new CacheSessionStaleError("the note cache has been locked");
    }
    return this.key;
  }

  /**
   * Lock the instance: drop the key reference and refuse all further
   * operations. Called by the session layer on logout/expiry (§1.1 rule 1).
   */
  lock(): void {
    this.locked = true;
    this.key = null;
  }

  /**
   * Refuse a v2 blob once this principal has been seen at v3 (SSA C-7), and
   * remember a v3 sighting. Called on EVERY slot read, before any crypto.
   */
  private gateSchema(record: StoredCacheRecordV2): void {
    if (record.schemaVersion === CACHE_SCHEMA_V3) {
      this.sawV3 = true;
      return;
    }
    if (this.sawV3) {
      throw new CacheSchemaDowngradeError(
        `the note-cache record for this principal has already been written at schema ` +
          `${CACHE_SCHEMA_V3}; a schema-${record.schemaVersion} record presented afterwards is a ` +
          `replay of a superseded blob and is refused. Nothing was read from it and no ` +
          `verified-scan history was changed.`,
      );
    }
  }

  /** Decrypt and return the current state (read-only snapshot). */
  async load(): Promise<CachedScanState> {
    const key = this.usableKey();
    const slot = await this.store.get(this.binding.principalText);
    if (slot === null) {
      // open() created/verified this record; its disappearance is external
      // interference — fail closed rather than report an empty (zero-balance)
      // cache as truth.
      throw new CacheIntegrityError("the note-cache record for this principal is missing");
    }
    this.gateSchema(slot.record);
    return openRecord(key, slot.record, this.binding.principalText);
  }

  /**
   * Atomic read-modify-write (§1.1 rule 5). `fn` MUST be a pure function of
   * the state it is given — on a lost CAS it is re-applied to the winner's
   * state, which is how two tabs' logical changes both survive. The revision
   * CAS itself runs inside a single IndexedDB read-check-write transaction in
   * the store; this loop re-reads, re-applies and retries on conflict.
   */
  async update(
    fn: (state: CachedScanState) => CachedScanState | Promise<CachedScanState>,
  ): Promise<CachedScanState> {
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
      const key = this.usableKey();
      const slot = await this.store.get(this.binding.principalText);
      if (slot === null) {
        throw new CacheIntegrityError("the note-cache record for this principal is missing");
      }
      this.gateSchema(slot.record);
      const current = await openRecord(key, slot.record, this.binding.principalText);
      const next = await fn(current);
      const record = await sealRecord(key, this.salt, next, this.binding.principalText, this.kdfVersion);
      // Epoch re-check immediately before the commit (§1.1 rule 2): a logout
      // during fn()/seal must not land a stale write.
      this.binding.assertCurrent();
      const result = await this.store.compareAndPut(this.binding.principalText, slot.revision, {
        revision: slot.revision + 1,
        record,
      });
      if (result.ok) {
        this.sawV3 = true; // the record for this principal is now v3 — one-way.
        return next;
      }
    }
    throw new CacheWriteConflictError();
  }
}

// ---------------------------------------------------------------------------
// Legacy NoteCache (pre-L4) — still constructed by crypto/scanner.ts, which is
// L3b surface; L3b swaps the scanner onto PrincipalNoteCache and retires this.
// ---------------------------------------------------------------------------

/**
 * LEGACY (kdfVersion 1) passphrase-encrypted view over a `NoteStore`.
 * Construct with `NoteCache.open` (async — it reads/creates the salt and
 * derives the key once). New code must use PrincipalNoteCache; this class
 * remains only because the scanner (L3b lane surface) still wires it.
 */
/**
 * Wrap raw 32-byte key material as a non-extractable AES-GCM `CryptoKey`.
 *
 * Exported because the Layer-1 key derivations live in `crypto/layer1.ts` and
 * hand their output here; importing it non-extractable means the cache key,
 * like every other key in this design, cannot be read back out of WebCrypto.
 */
export async function importCacheKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== ARGON2ID_KEY_BYTES) {
    throw new CacheFormatError(`a cache key must be ${ARGON2ID_KEY_BYTES} bytes, got ${raw.length}`);
  }
  const copy = new Uint8Array(new ArrayBuffer(raw.length));
  copy.set(raw);
  return crypto.subtle.importKey("raw", copy, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** What a passphrase record is being migrated TO (D-1b v3 §3). */
export type CacheMigrationTarget =
  | { mode: "ii-only"; key: CryptoKey }
  | { mode: "wallet-passcode"; key: CryptoKey };

/** The outcome of a migration attempt, for UX and for tests. */
export interface CacheMigrationOutcome {
  /** The kdfVersion the record now carries. */
  kdfVersion: number;
  /** Notes carried across — proves the migration was lossless. */
  noteCount: number;
}

/**
 * Migrate an existing PASSPHRASE cache record (kdfVersion 2) to one of the
 * D-1b key-based modes, losslessly (v3 §3).
 *
 * THE ORDER IS THE SAFETY PROPERTY, so it is written out rather than implied:
 *
 *  1. read the slot and detect the version BEFORE any decryption — a record
 *     that is already migrated, or is of an unknown version, is refused here
 *     rather than being decrypted "just to see";
 *  2. authenticate under the OLD key and the EXISTING AAD (principal +
 *     version) — a wrong or absent passphrase throws and nothing moves;
 *  3. re-seal the COMPLETE state (revision-independent: notes, scan head,
 *     mirror head, quarantine, spent set, BOTH journals) under the new key and
 *     the new version — the whole record, never a subset;
 *  4. write it with the STORE'S EXISTING CAS on the revision we read, so a
 *     concurrent writer makes this fail instead of silently losing an update;
 *  5. read the new record back and DECRYPT it under the new key before
 *     reporting success.
 *
 * If any step fails, the OLD record is still there, unchanged and openable with
 * the old passphrase. There is no window in which the old ciphertext is retired
 * before the new one has been proved readable.
 */
export async function migratePassphraseRecord(
  store: PrincipalCacheStore,
  binding: SessionBinding,
  oldPassphrase: string,
  target: CacheMigrationTarget,
): Promise<CacheMigrationOutcome> {
  binding.assertCurrent();
  validateCachePrincipal(binding.principalText);

  const slot = await store.get(binding.principalText);
  if (slot === null) {
    throw new CacheFormatError("there is no cache record for this principal to migrate");
  }
  // (1) version first, before any crypto.
  if (slot.record.kdfVersion !== KDF_VERSION_ARGON2ID) {
    throw new CacheFormatError(
      `cache record is at kdfVersion ${slot.record.kdfVersion}; only a passphrase record ` +
        `(version ${KDF_VERSION_ARGON2ID}) can be migrated`,
    );
  }

  // (2) authenticate under the old key + existing AAD. A wrong passphrase
  // throws out of here and the record is untouched.
  const oldKey = await deriveCacheKeyV2(oldPassphrase, slot.record.salt);
  const state = await openRecord(oldKey, slot.record, binding.principalText);

  const newVersion =
    target.mode === "ii-only" ? KDF_VERSION_VETKEY_UNLOCK : KDF_VERSION_WALLET_PASSCODE;
  // A fresh salt: not a KDF input at these versions, but it is AAD-bound, so a
  // re-seal is never byte-identical to the record it replaces.
  const salt = crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
  // (3) the COMPLETE state — `state` is whatever `openRecord` returned, so
  // nothing can be dropped by listing fields here.
  const record = await sealRecord(target.key, salt, state, binding.principalText, newVersion);

  binding.assertCurrent();
  // (4) CAS on the revision we read.
  const written = await store.compareAndPut(binding.principalText, slot.revision, {
    revision: slot.revision + 1,
    record,
  });
  if (!written.ok) {
    // Another tab wrote in the read→migrate window. Nothing here has changed
    // the stored record, so the old passphrase still opens it and the whole
    // migration is retryable from step (1).
    throw new CacheWriteConflictError();
  }

  // (5) authenticated read-back. Only now is the old ciphertext genuinely
  // retired, and it is retired by having been overwritten by a record we have
  // just proved we can read.
  const after = await store.get(binding.principalText);
  if (after === null || after.record.kdfVersion !== newVersion) {
    throw new CacheIntegrityError(
      "the migrated cache record could not be read back — treat the migration as incomplete",
    );
  }
  const verified = await openRecord(target.key, after.record, binding.principalText);
  return { kdfVersion: newVersion, noteCount: verified.notes.length };
}

/**
 * WALLET-CACHE-II-ONLY O-3 — re-seal a KEY-BASED record between the two
 * key-based modes (II-only v3 ↔ wallet passcode v4), losslessly.
 *
 * `migratePassphraseRecord` accepts only a passphrase (v2) source, so the
 * passcode toggle needs this twin. It follows the SAME five-step order, for the
 * same reasons: version first, authenticate under the OLD key, re-seal the
 * COMPLETE state under the new key and version, CAS on the revision read, then
 * read back and decrypt under the new key before reporting success. If any step
 * fails before the CAS, the old record is untouched and still opens under
 * `fromKey`.
 *
 * IDEMPOTENT ON RETRY: a record already at `toVersion` is not re-sealed — it is
 * AUTHENTICATED under `toKey` and reported. That is the state a toggle that
 * committed but lost its reply leaves behind, and re-running the toggle must
 * finish rather than fail on a version mismatch.
 */
export async function resealKeyRecord(
  store: PrincipalCacheStore,
  binding: SessionBinding,
  fromKey: CryptoKey,
  toKey: CryptoKey,
  toVersion: number,
): Promise<CacheMigrationOutcome> {
  if (toVersion !== KDF_VERSION_VETKEY_UNLOCK && toVersion !== KDF_VERSION_WALLET_PASSCODE) {
    throw new CacheFormatError(`kdfVersion ${toVersion} is not a key-based record version`);
  }
  binding.assertCurrent();
  validateCachePrincipal(binding.principalText);

  const slot = await store.get(binding.principalText);
  if (slot === null) {
    throw new CacheFormatError("there is no cache record for this principal to re-seal");
  }
  // (1) version first, before any crypto.
  if (slot.record.kdfVersion === toVersion) {
    const already = await openRecord(toKey, slot.record, binding.principalText);
    return { kdfVersion: toVersion, noteCount: already.notes.length };
  }
  if (
    slot.record.kdfVersion !== KDF_VERSION_VETKEY_UNLOCK &&
    slot.record.kdfVersion !== KDF_VERSION_WALLET_PASSCODE
  ) {
    throw new CacheFormatError(
      `cache record is at kdfVersion ${slot.record.kdfVersion}; only a key-based record ` +
        `(version ${KDF_VERSION_VETKEY_UNLOCK} or ${KDF_VERSION_WALLET_PASSCODE}) can be re-sealed here`,
    );
  }

  // (2) authenticate under the old key + existing AAD.
  const state = await openRecord(fromKey, slot.record, binding.principalText);

  // (3) the COMPLETE state, fresh salt (AAD-bound record metadata only).
  const salt = crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
  const record = await sealRecord(toKey, salt, state, binding.principalText, toVersion);

  binding.assertCurrent();
  // (4) CAS on the revision we read.
  const written = await store.compareAndPut(binding.principalText, slot.revision, {
    revision: slot.revision + 1,
    record,
  });
  if (!written.ok) throw new CacheWriteConflictError();

  // (5) authenticated read-back.
  const after = await store.get(binding.principalText);
  if (after === null || after.record.kdfVersion !== toVersion) {
    throw new CacheIntegrityError(
      "the re-sealed cache record could not be read back — treat the change as incomplete",
    );
  }
  const verified = await openRecord(toKey, after.record, binding.principalText);
  return { kdfVersion: toVersion, noteCount: verified.notes.length };
}

export class NoteCache {
  private constructor(
    private readonly store: NoteStore,
    private readonly key: CryptoKey,
    private readonly salt: Uint8Array,
  ) {}

  /**
   * Open the cache for `passphrase`. Reuses the stored salt if a record exists
   * (so the same passphrase re-derives the same key across sessions); otherwise
   * mints a fresh salt, persisted on the first `save`.
   */
  static async open(store: NoteStore, passphrase: string): Promise<NoteCache> {
    const existing = await store.load();
    const salt = existing?.salt ?? crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const key = await deriveCacheKey(passphrase, salt);
    return new NoteCache(store, key, salt);
  }

  /** Load the cached scan state; empty state when nothing is stored yet. */
  async load(): Promise<CachedScanState> {
    const record = await this.store.load();
    if (!record) return { notes: [], lastScannedIndex: 0n };
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: record.iv as BufferSource },
      this.key,
      record.ciphertext as BufferSource,
    );
    return deserializeScanState(new Uint8Array(plaintext));
  }

  /** Encrypt and persist the scan state (fresh IV per write). */
  async save(state: CachedScanState): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        this.key,
        serializeScanState(state) as BufferSource,
      ),
    );
    await this.store.save({ salt: this.salt, iv, ciphertext });
  }

  /** Drop the cached record (e.g. on logout / passphrase reset). */
  async clear(): Promise<void> {
    await this.store.clear();
  }
}
