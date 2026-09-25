/**
 * IndexedDB-backed note stores (wallet-build Commit 5; Campaign B / L4).
 *
 * Two ports over the SAME database/object store:
 *
 * - `openIndexedDbNoteStore` — the LEGACY unscoped singleton (`state` key,
 *   PBKDF2 records). Kept only because crypto/scanner.ts (L3b surface) still
 *   wires it; after L4 the singleton is read for migration and deleted by the
 *   sanctioned empty-record migration, never written anew.
 * - `openIndexedDbPrincipalCacheStore` — the L4 principal-scoped CAS store:
 *   one encrypted slot per principal under `state:<principal>`, every
 *   conditional op (create-if-absent, revision compare-and-put, legacy
 *   migrate-replace) executed inside a SINGLE IndexedDB readwrite
 *   transaction. That transaction IS the cross-tab atomicity: two tabs racing
 *   the same slot serialize on the object store, so a revision CAS can never
 *   be split by another tab's write (an in-memory mutex cannot give this —
 *   two tabs have separate JS mutexes, §1.1 rule 5).
 *
 * Only opaque { kdfVersion, schemaVersion, salt, iv, ciphertext } records (plus
 * the storage-level CAS revision) are stored — never the vetKey,
 * masterNoteSecret, passphrase, or any plaintext note (noteCache.ts hard rule).
 */

import { openDB, type IDBPDatabase } from "idb";

import { registerDbConnection } from "./dbConnections";

import type {
  CacheSlot,
  NoteStore,
  PrincipalCacheStore,
  StoredRecord,
} from "./noteCache";
// R-7 item 6: the name is DECLARED in the registry, imported here — never
// declared or aliased locally, so no call site owns its own database name.
import { NOTE_CACHE_DB_NAME } from "./dbRegistry";

const STORE_NAME = "note-cache";
/** The legacy unscoped singleton key (pre-L4). */
const LEGACY_RECORD_KEY = "state";

/** The v2 per-principal slot key. Distinct from the bare legacy `state` key. */
export function principalCacheKey(principalText: string): string {
  return `state:${principalText}`;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Byte-identity of a legacy record — the L-2 in-transaction re-verification. */
function legacyRecordsEqual(a: StoredRecord, b: StoredRecord): boolean {
  return (
    bytesEqual(a.salt, b.salt) && bytesEqual(a.iv, b.iv) && bytesEqual(a.ciphertext, b.ciphertext)
  );
}

async function openCacheDb(dbName: string): Promise<IDBPDatabase> {
  const db = await openDB(dbName, 1, {
    upgrade(database) {
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME);
      }
    },
  });
  // A-1b: the panic wipe must close this handle before deleting the database,
  // or its own connection blocks the deletion.
  registerDbConnection(db);
  return db;
}

/** Open (creating if needed) the LEGACY IndexedDB-backed note store. */
export async function openIndexedDbNoteStore(
  dbName: string = NOTE_CACHE_DB_NAME,
): Promise<NoteStore> {
  const db = await openCacheDb(dbName);

  return {
    async load(): Promise<StoredRecord | null> {
      const rec = (await db.get(STORE_NAME, LEGACY_RECORD_KEY)) as StoredRecord | undefined;
      return rec ?? null;
    },
    async save(record: StoredRecord): Promise<void> {
      await db.put(STORE_NAME, record, LEGACY_RECORD_KEY);
    },
    async clear(): Promise<void> {
      await db.delete(STORE_NAME, LEGACY_RECORD_KEY);
    },
  };
}

/** Open (creating if needed) the L4 principal-scoped CAS cache store. */
export async function openIndexedDbPrincipalCacheStore(
  dbName: string = NOTE_CACHE_DB_NAME,
): Promise<PrincipalCacheStore> {
  const db = await openCacheDb(dbName);

  return {
    async get(principalText: string): Promise<CacheSlot | null> {
      const slot = (await db.get(STORE_NAME, principalCacheKey(principalText))) as
        | CacheSlot
        | undefined;
      return slot ?? null;
    },

    async compareAndPut(principalText, expected, slot) {
      // ONE readwrite transaction = the read-check-write CAS (§1.1 rule 5).
      const tx = db.transaction(STORE_NAME, "readwrite");
      const key = principalCacheKey(principalText);
      const current = (await tx.store.get(key)) as CacheSlot | undefined;
      const matches =
        expected === null ? current === undefined : current !== undefined && current.revision === expected;
      if (!matches) {
        await tx.done;
        return { ok: false, current: current ?? null };
      }
      await tx.store.put(slot, key);
      await tx.done;
      return { ok: true };
    },

    async getLegacy(): Promise<StoredRecord | null> {
      const rec = (await db.get(STORE_NAME, LEGACY_RECORD_KEY)) as StoredRecord | undefined;
      return rec ?? null;
    },

    async migrateLegacy(principalText, slot, observedLegacy) {
      // ONE transaction: verify legacy present AND byte-identical to the
      // record the caller proved empty (L-2 — a write landing in the
      // check->migrate window aborts; never overwrite) + scoped absent, then
      // replace + delete together — a crash or lost race can never leave
      // both records or neither (atomic replace, L4 §3).
      const tx = db.transaction(STORE_NAME, "readwrite");
      const key = principalCacheKey(principalText);
      const legacy = (await tx.store.get(LEGACY_RECORD_KEY)) as StoredRecord | undefined;
      if (legacy === undefined) {
        await tx.done;
        return { ok: false, reason: "legacy-missing" as const };
      }
      if (!legacyRecordsEqual(legacy, observedLegacy)) {
        await tx.done;
        return { ok: false, reason: "legacy-changed" as const };
      }
      const scoped = (await tx.store.get(key)) as CacheSlot | undefined;
      if (scoped !== undefined) {
        await tx.done;
        return { ok: false, reason: "scoped-exists" as const };
      }
      await tx.store.put(slot, key);
      await tx.store.delete(LEGACY_RECORD_KEY);
      await tx.done;
      return { ok: true };
    },
  };
}
