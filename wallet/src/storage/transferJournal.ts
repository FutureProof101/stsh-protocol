/**
 * Durable transfer-intent journal (Campaign A / Wave 1, brief A2.1 — C-A3,
 * A-S1/A-S14/A-S21; corrective lane AC-1/AC-1c).
 *
 * Button-disable is not double-submit protection; the ledger dedup window only
 * helps if the SAME (`created_at_time`, args) envelope is resubmitted. This
 * journal is the wallet-side half of that contract:
 *
 * - FULLY BOUND envelope: owner principal + ledger canister + network/host +
 *   from_subaccount + to + amount + fee + memo + created_at_time, plus a
 *   schema version and an explicit state (`pending` | `unknown` | `frozen`).
 * - ONE stable `created_at_time` per transfer INTENT (never per attempt); a
 *   retry rebuilds the request byte-for-byte from the persisted record.
 * - PERSIST-BEFORE-SUBMIT: `beginIntent` (and every state transition) resolves
 *   only after the store write completes.
 * - ONE atomic unresolved-intent slot per (principal + ledger + network),
 *   claimed under a single IndexedDB readwrite transaction — an atomic CAS
 *   across tabs; an in-memory mutex protects one tab only.
 * - AC-1: EVERY post-claim write is a compare-and-swap on the intent's
 *   immutable identity. Each record carries a CSPRNG `intentId` (minted once
 *   in `beginIntent`) and a `revision` bumped on every state write; the store
 *   exposes only conditional ops (`compareAndPut` / `compareAndRemove` /
 *   `archiveAndRemove`, each ONE readwrite transaction). A stale tab's
 *   `resolve`/`freeze`/`markUnknown`/`abandon` therefore fails closed with a
 *   typed `StaleIntentError` (carrying the current slot) instead of
 *   destroying a newer intent — the double-debit class the SSA found.
 * - CROSS-PRINCIPAL NON-RECOVERY: a record whose binding does not match the
 *   requesting scope is never returned — user B on the same device can neither
 *   see nor submit user A's envelope.
 * - `TooOld` terminal workflow: a frozen intent is never silently deleted;
 *   abandoning requires explicit confirmation after external ledger
 *   reconciliation, and the archive write + slot delete happen in ONE atomic
 *   multi-store transaction (no archived-but-still-live slot, no duplicate
 *   archive on retry).
 * - AC-1c: schema v1 -> v2 is a LOSSLESS migration inside the IndexedDB
 *   versionchange transaction (transactionally exclusive): active records are
 *   re-keyed `v1|...` -> `v2|...` with every field/state/attempt preserved and
 *   `intentId`/`revision` assigned; archived records are migrated in place.
 *   A v1 record is NEVER silently ignored or deleted — one may be an executed
 *   transfer with a lost response.
 *
 * Documented residual (brief A2.1): the journal is device-local. A second
 * device cannot see this device's unresolved intent without a ledger lookup —
 * an honest limitation of the device-local model, not a reason to weaken it.
 */

import { openDB } from "idb";

import { registerDbConnection } from "./dbConnections";
// R-7 item 6: declared once in the registry, imported here — never locally.
import { TRANSFER_JOURNAL_DB_NAME } from "./dbRegistry";

export const TRANSFER_JOURNAL_SCHEMA = 2;
/** IndexedDB database version; v2 = the AC-1 CAS schema (v1 auto-migrates). */
const DB_VERSION = 2;

export type TransferIntentState = "pending" | "unknown" | "frozen";

/** The binding a journal instance operates under (one logged-in principal). */
export interface TransferScope {
  ownerPrincipal: string;
  ledgerCanisterId: string;
  /** The agent host — a testnet envelope must never replay against mainnet. */
  network: string;
}

export interface TransferIntentRecord {
  schema: number;
  /** Immutable CSPRNG identity, minted once in `beginIntent` (AC-1). */
  intentId: string;
  /** Bumped on every state write; all post-claim writes CAS on (id, revision). */
  revision: number;
  state: TransferIntentState;
  ownerPrincipal: string;
  ledgerCanisterId: string;
  network: string;
  fromSubaccountHex: string | null;
  toOwner: string;
  toSubaccountHex: string | null;
  /** Base units as decimal strings — structured-clone-stable across browsers. */
  amount: string;
  fee: string;
  memoHex: string | null;
  /** The ONE stable ledger-dedup timestamp (ns) for this intent (C-A3). */
  createdAtTimeNs: string;
  createdAtMs: number;
  /** Wire attempts recorded so far (markUnknown increments before each). */
  attempts: number;
}

export interface ArchivedTransferIntent {
  record: TransferIntentRecord;
  archivedAtMs: number;
  resolution: "abandoned-after-external-reconcile";
}

/** The identity a conditional store op must find in the slot to proceed. */
export interface IntentExpectation {
  intentId: string;
  revision: number;
}

/**
 * Storage port. Every op MUST be atomic with respect to concurrent access to
 * the same key from other tabs — the IndexedDB implementation below uses a
 * single readwrite transaction per op; test stores must serialize
 * equivalently. There are deliberately NO unconditional post-claim writes.
 */
export interface JournalStore {
  claim(
    key: string,
    record: TransferIntentRecord,
  ): Promise<{ claimed: true } | { claimed: false; existing: TransferIntentRecord }>;
  get(key: string): Promise<TransferIntentRecord | null>;
  /** Write `next` iff the slot currently holds `expected` (one readwrite tx). */
  compareAndPut(
    key: string,
    expected: IntentExpectation,
    next: TransferIntentRecord,
  ): Promise<{ ok: true } | { ok: false; current: TransferIntentRecord | null }>;
  /** Delete the slot iff it currently holds `expected` (one readwrite tx). */
  compareAndRemove(
    key: string,
    expected: IntentExpectation,
  ): Promise<{ ok: true } | { ok: false; current: TransferIntentRecord | null }>;
  /**
   * Archive `entry` AND delete the slot iff it holds `expected`, in ONE
   * readwrite transaction spanning both stores: a crash can never leave an
   * archived record still occupying the live slot, and a stale retry archives
   * nothing (AC-1).
   */
  archiveAndRemove(
    key: string,
    expected: IntentExpectation,
    entry: ArchivedTransferIntent,
  ): Promise<{ ok: true } | { ok: false; current: TransferIntentRecord | null }>;
  listArchive(): Promise<ArchivedTransferIntent[]>;
}

export function scopeKey(scope: TransferScope): string {
  return `v${TRANSFER_JOURNAL_SCHEMA}|${scope.network}|${scope.ledgerCanisterId}|${scope.ownerPrincipal}`;
}

export class IntentSlotBusyError extends Error {
  constructor(readonly existing: TransferIntentRecord) {
    super(
      "An unresolved transfer intent already exists for this account — resolve or reconcile it before starting a new transfer.",
    );
    this.name = "IntentSlotBusyError";
  }
}

/**
 * A post-claim write lost its CAS: the slot no longer holds the expected
 * (intentId, revision). Nothing was written or deleted. `current` is the
 * slot's present occupant (null = empty) so callers can resynchronize.
 */
export class StaleIntentError extends Error {
  constructor(readonly current: TransferIntentRecord | null) {
    super(
      "This transfer intent is stale — the journal slot was updated by another tab or a newer operation. No write was performed.",
    );
    this.name = "StaleIntentError";
  }
}

function mintIntentId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function expectationOf(record: TransferIntentRecord): IntentExpectation {
  return { intentId: record.intentId, revision: record.revision };
}

export interface BeginIntentFields {
  toOwner: string;
  toSubaccountHex: string | null;
  amount: bigint;
  fee: bigint;
  memoHex: string | null;
  fromSubaccountHex: string | null;
  createdAtTimeNs: bigint;
  nowMs?: number;
}

export class TransferJournal {
  constructor(
    private readonly store: JournalStore,
    readonly scope: TransferScope,
  ) {}

  private key(): string {
    return scopeKey(this.scope);
  }

  /**
   * Mint + persist a new fully-bound intent, atomically claiming the single
   * unresolved slot for this scope. Throws IntentSlotBusyError (with the
   * existing record) if the slot is occupied — the existing intent must be
   * resolved or reconciled first; a new intent is NEVER minted over it.
   */
  async beginIntent(fields: BeginIntentFields): Promise<TransferIntentRecord> {
    const record: TransferIntentRecord = {
      schema: TRANSFER_JOURNAL_SCHEMA,
      intentId: mintIntentId(),
      revision: 0,
      state: "pending",
      ownerPrincipal: this.scope.ownerPrincipal,
      ledgerCanisterId: this.scope.ledgerCanisterId,
      network: this.scope.network,
      fromSubaccountHex: fields.fromSubaccountHex,
      toOwner: fields.toOwner,
      toSubaccountHex: fields.toSubaccountHex,
      amount: fields.amount.toString(10),
      fee: fields.fee.toString(10),
      memoHex: fields.memoHex,
      createdAtTimeNs: fields.createdAtTimeNs.toString(10),
      createdAtMs: fields.nowMs ?? Date.now(),
      attempts: 0,
    };
    const result = await this.store.claim(this.key(), record);
    if (!result.claimed) throw new IntentSlotBusyError(result.existing);
    return record;
  }

  /**
   * The unresolved intent for THIS scope, or null. A stored record whose
   * schema or binding (owner/ledger/network) does not match is IGNORED — it
   * belongs to another owner or environment and is not this session's to
   * resolve (A-S14).
   */
  async loadUnresolved(): Promise<TransferIntentRecord | null> {
    const record = await this.store.get(this.key());
    if (record === null) return null;
    if (record.schema !== TRANSFER_JOURNAL_SCHEMA) return null;
    if (
      record.ownerPrincipal !== this.scope.ownerPrincipal ||
      record.ledgerCanisterId !== this.scope.ledgerCanisterId ||
      record.network !== this.scope.network
    ) {
      return null;
    }
    return record;
  }

  /**
   * Record that a wire attempt is about to happen (persisted BEFORE the call):
   * from here on the outcome may be unknown, so the envelope must survive.
   * CAS-guarded: throws StaleIntentError (no write) if `record` no longer
   * owns the slot — the caller must NOT proceed to the wire.
   */
  async markUnknown(record: TransferIntentRecord): Promise<TransferIntentRecord> {
    const next: TransferIntentRecord = {
      ...record,
      state: "unknown",
      attempts: record.attempts + 1,
      revision: record.revision + 1,
    };
    const result = await this.store.compareAndPut(this.key(), expectationOf(record), next);
    if (!result.ok) throw new StaleIntentError(result.current);
    return next;
  }

  /**
   * Clear the slot after a DEFINITE outcome only: executed success, `Duplicate`
   * (confirmed success), or a definite non-executing rejection. CAS-guarded:
   * a stale resolve never deletes a newer intent (throws StaleIntentError).
   */
  async resolve(record: TransferIntentRecord): Promise<void> {
    const result = await this.store.compareAndRemove(this.key(), expectationOf(record));
    if (!result.ok) throw new StaleIntentError(result.current);
  }

  /**
   * Freeze an ambiguous `TooOld` intent for manual reconciliation (A-S21).
   * CAS-guarded: a stale freeze never overwrites a newer intent.
   */
  async freeze(record: TransferIntentRecord): Promise<TransferIntentRecord> {
    const next: TransferIntentRecord = {
      ...record,
      state: "frozen",
      revision: record.revision + 1,
    };
    const result = await this.store.compareAndPut(this.key(), expectationOf(record), next);
    if (!result.ok) throw new StaleIntentError(result.current);
    return next;
  }

  /**
   * Manual abandonment of a frozen intent. Requires the caller to assert the
   * user confirmed AFTER reconciling against the ledger externally. Archive
   * write + slot delete are ONE atomic transaction, conditional on this
   * record still owning the slot — an audit trail remains, a retry can never
   * duplicate it, and a stale abandon touches nothing.
   */
  async abandonFrozen(
    record: TransferIntentRecord,
    opts: { confirmedExternalReconcile: boolean },
  ): Promise<void> {
    if (record.state !== "frozen") {
      throw new Error("only a frozen transfer intent can be abandoned");
    }
    if (opts.confirmedExternalReconcile !== true) {
      throw new Error(
        "abandoning a frozen transfer requires explicit confirmation after checking the ledger externally",
      );
    }
    const result = await this.store.archiveAndRemove(this.key(), expectationOf(record), {
      record,
      archivedAtMs: Date.now(),
      resolution: "abandoned-after-external-reconcile",
    });
    if (!result.ok) throw new StaleIntentError(result.current);
  }
}

// ---------------------------------------------------------------------------
// IndexedDB store (production) + v1 -> v2 migration
// ---------------------------------------------------------------------------

const INTENTS_STORE = "transfer-intents";
const ARCHIVE_STORE = "transfer-archive";

/** The v1 record shape (pre-AC-1): no intentId/revision, schema 1. */
type V1TransferIntentRecord = Omit<TransferIntentRecord, "intentId" | "revision">;

function migrateV1Record(v1: V1TransferIntentRecord): TransferIntentRecord {
  // Lossless: every envelope field, state, and attempt count is preserved;
  // only the CAS identity is assigned (AC-1c).
  return { ...v1, schema: TRANSFER_JOURNAL_SCHEMA, intentId: mintIntentId(), revision: 0 };
}

function slotMatches(
  current: TransferIntentRecord | undefined,
  expected: IntentExpectation,
): current is TransferIntentRecord {
  return (
    current !== undefined &&
    current.intentId === expected.intentId &&
    current.revision === expected.revision
  );
}

export interface OpenJournalStoreOptions {
  /**
   * Fired when an old-version tab holds the database open and blocks the
   * v1 -> v2 migration. Surface an actionable "close or refresh other wallet
   * tabs" message — the open resolves once the old connection closes.
   */
  onBlocked?: () => void;
}

/** Open (creating if needed) the IndexedDB-backed journal store. */
export async function openIndexedDbJournalStore(
  dbName: string = TRANSFER_JOURNAL_DB_NAME,
  opts: OpenJournalStoreOptions = {},
): Promise<JournalStore> {
  const db = await openDB(dbName, DB_VERSION, {
    async upgrade(database, oldVersion, _newVersion, tx) {
      if (oldVersion < 1) {
        database.createObjectStore(INTENTS_STORE);
        database.createObjectStore(ARCHIVE_STORE, { autoIncrement: true });
        return;
      }
      if (oldVersion === 1) {
        // AC-1c lossless migration, inside the versionchange transaction
        // (transactionally exclusive — no other tab can interleave).
        const intents = tx.objectStore(INTENTS_STORE);
        const keys = await intents.getAllKeys();
        const records = (await intents.getAll()) as V1TransferIntentRecord[];
        for (let i = 0; i < keys.length; i += 1) {
          const oldKey = String(keys[i]);
          const migrated = migrateV1Record(records[i]);
          const newKey = oldKey.startsWith("v1|") ? `v2|${oldKey.slice(3)}` : oldKey;
          await intents.delete(keys[i]);
          await intents.put(migrated, newKey);
        }
        const archive = tx.objectStore(ARCHIVE_STORE);
        const archiveKeys = await archive.getAllKeys();
        const archiveEntries = (await archive.getAll()) as Array<
          Omit<ArchivedTransferIntent, "record"> & { record: V1TransferIntentRecord }
        >;
        for (let i = 0; i < archiveKeys.length; i += 1) {
          await archive.put(
            { ...archiveEntries[i], record: migrateV1Record(archiveEntries[i].record) },
            archiveKeys[i],
          );
        }
      }
    },
    blocked() {
      opts.onBlocked?.();
    },
  });
  // A-1b: the panic wipe closes registered handles before deleting, so the
  // app's own connection never blocks its own deletion.
  registerDbConnection(db);

  return {
    async claim(key, record) {
      // One readwrite transaction = the cross-tab atomic CAS (A-S14): two tabs
      // racing this block serialize on the object store; exactly one claims.
      const tx = db.transaction(INTENTS_STORE, "readwrite");
      const existing = (await tx.store.get(key)) as TransferIntentRecord | undefined;
      if (existing !== undefined) {
        await tx.done;
        return { claimed: false, existing };
      }
      await tx.store.put(record, key);
      await tx.done;
      return { claimed: true };
    },
    async get(key) {
      const record = (await db.get(INTENTS_STORE, key)) as TransferIntentRecord | undefined;
      return record ?? null;
    },
    async compareAndPut(key, expected, next) {
      const tx = db.transaction(INTENTS_STORE, "readwrite");
      const current = (await tx.store.get(key)) as TransferIntentRecord | undefined;
      if (!slotMatches(current, expected)) {
        await tx.done;
        return { ok: false, current: current ?? null };
      }
      await tx.store.put(next, key);
      await tx.done;
      return { ok: true };
    },
    async compareAndRemove(key, expected) {
      const tx = db.transaction(INTENTS_STORE, "readwrite");
      const current = (await tx.store.get(key)) as TransferIntentRecord | undefined;
      if (!slotMatches(current, expected)) {
        await tx.done;
        return { ok: false, current: current ?? null };
      }
      await tx.store.delete(key);
      await tx.done;
      return { ok: true };
    },
    async archiveAndRemove(key, expected, entry) {
      // ONE transaction over both stores: archive + delete commit together or
      // not at all (AC-1 corrected abandon failure mode).
      const tx = db.transaction([INTENTS_STORE, ARCHIVE_STORE], "readwrite");
      const intents = tx.objectStore(INTENTS_STORE);
      const current = (await intents.get(key)) as TransferIntentRecord | undefined;
      if (!slotMatches(current, expected)) {
        await tx.done;
        return { ok: false, current: current ?? null };
      }
      await tx.objectStore(ARCHIVE_STORE).add(entry);
      await intents.delete(key);
      await tx.done;
      return { ok: true };
    },
    async listArchive() {
      return (await db.getAll(ARCHIVE_STORE)) as ArchivedTransferIntent[];
    },
  };
}

// ---------------------------------------------------------------------------
// hex helpers (memo / subaccount round-trips through the string envelope)
// ---------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^([0-9a-f]{2})*$/i.test(hex)) throw new Error(`invalid hex payload: "${hex}"`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
