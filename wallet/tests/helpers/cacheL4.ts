/**
 * Shared harness for the L4 note-cache tests: a serialized in-memory
 * PrincipalCacheStore with write-failure injection, a real-IndexedDB harness
 * (fake-indexeddb) over the production store, session-binding and fake-session
 * builders. Test-only — nothing here ships.
 */

import { openDB } from "idb";
import type { Principal } from "@dfinity/principal";

import {
  CacheSessionStaleError,
  NoteCache,
  type CacheSlot,
  type CachedScanState,
  type NoteStore,
  type PrincipalCacheStore,
  type ScannedNote,
  type SessionBinding,
  type StoredRecord,
} from "../../src/storage/noteCache";
import {
  openIndexedDbNoteStore,
  openIndexedDbPrincipalCacheStore,
  principalCacheKey,
} from "../../src/storage/indexedDbNoteStore";
import type { AuthSession } from "../../src/session/auth";

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Byte-identity of a legacy record (mirrors the production L-2 check). */
function legacyEqual(a: StoredRecord, b: StoredRecord): boolean {
  return (
    bytesToHex(a.salt) === bytesToHex(b.salt) &&
    bytesToHex(a.iv) === bytesToHex(b.iv) &&
    bytesToHex(a.ciphertext) === bytesToHex(b.ciphertext)
  );
}

export function note(leafIndex: bigint, tag: number): ScannedNote {
  return {
    leafIndex,
    value: 100n,
    rho: new Uint8Array(32).fill(tag),
    rseed: new Uint8Array(32).fill(tag + 1),
    recipientPk: new Uint8Array(32).fill(tag + 2),
  };
}

export function addNote(n: ScannedNote) {
  // Spread the incoming state (noteCache invariant): fields this fn does not
  // own — e.g. the L3a shield journal — must survive a CAS re-apply.
  return (state: CachedScanState): CachedScanState => ({
    ...state,
    notes: [...state.notes, n],
    lastScannedIndex:
      state.lastScannedIndex > n.leafIndex + 1n ? state.lastScannedIndex : n.leafIndex + 1n,
  });
}

/** A session binding that is always current until `invalidate()` is called. */
export function testBinding(
  principalText: string,
  epoch = 0,
): SessionBinding & { invalidate(): void } {
  let stale = false;
  return {
    principalText,
    epoch,
    assertCurrent(): void {
      if (stale) throw new CacheSessionStaleError("test binding invalidated");
    },
    invalidate(): void {
      stale = true;
    },
  };
}

/** Minimal AuthSession shape; `declaredPrincipal` may deliberately mismatch. */
export function fakeSession(
  identityPrincipal: Principal,
  declaredPrincipal: Principal = identityPrincipal,
): AuthSession {
  return {
    identity: {
      getPrincipal: () => identityPrincipal,
    } as unknown as AuthSession["identity"],
    principal: declaredPrincipal,
  };
}

// ---------------------------------------------------------------------------
// Harness — one interface over the in-memory and real-IndexedDB backends
// ---------------------------------------------------------------------------

export interface CacheHarness {
  store: PrincipalCacheStore;
  /** Write a LEGACY (kdfVersion 1) singleton via the real legacy code path. */
  seedLegacy(passphrase: string, state: CachedScanState): Promise<StoredRecord>;
  readLegacy(): Promise<StoredRecord | null>;
  readSlot(principalText: string): Promise<CacheSlot | null>;
  /** Raw backdoor write for tamper tests. */
  writeSlot(principalText: string, slot: CacheSlot): Promise<void>;
  /** Every stored value, for the S-3 persisted-material audit. */
  allValues(): Promise<unknown[]>;
  /** Memory harness only: make the NEXT conditional write throw atomically. */
  failNextWrite?: (error?: Error) => void;
}

export async function memoryHarness(): Promise<CacheHarness> {
  const slots = new Map<string, CacheSlot>();
  let legacy: StoredRecord | null = null;
  let pendingFailure: Error | null = null;

  const takeFailure = (): Error | null => {
    const failure = pendingFailure;
    pendingFailure = null;
    return failure;
  };

  const store: PrincipalCacheStore = {
    async get(principalText) {
      const slot = slots.get(principalText);
      return slot ? structuredClone(slot) : null;
    },
    async compareAndPut(principalText, expected, slot) {
      const failure = takeFailure();
      if (failure) throw failure; // atomic: nothing written
      const current = slots.get(principalText) ?? null;
      const matches =
        expected === null ? current === null : current !== null && current.revision === expected;
      if (!matches) return { ok: false, current: current ? structuredClone(current) : null };
      slots.set(principalText, structuredClone(slot));
      return { ok: true };
    },
    async getLegacy() {
      return legacy ? structuredClone(legacy) : null;
    },
    async migrateLegacy(principalText, slot, observedLegacy) {
      const failure = takeFailure();
      if (failure) throw failure; // atomic: nothing written, nothing deleted
      if (legacy === null) return { ok: false, reason: "legacy-missing" as const };
      if (!legacyEqual(legacy, observedLegacy)) {
        return { ok: false, reason: "legacy-changed" as const };
      }
      if (slots.has(principalText)) return { ok: false, reason: "scoped-exists" as const };
      slots.set(principalText, structuredClone(slot));
      legacy = null;
      return { ok: true };
    },
  };

  const legacyStore: NoteStore = {
    async load() {
      return legacy ? structuredClone(legacy) : null;
    },
    async save(record) {
      legacy = structuredClone(record);
    },
    async clear() {
      legacy = null;
    },
  };

  return {
    store,
    async seedLegacy(passphrase, state) {
      const cache = await NoteCache.open(legacyStore, passphrase);
      await cache.save(state);
      return structuredClone(legacy!);
    },
    async readLegacy() {
      return legacy ? structuredClone(legacy) : null;
    },
    async readSlot(principalText) {
      const slot = slots.get(principalText);
      return slot ? structuredClone(slot) : null;
    },
    async writeSlot(principalText, slot) {
      slots.set(principalText, structuredClone(slot));
    },
    async allValues() {
      const values: unknown[] = [...slots.values()].map((v) => structuredClone(v));
      if (legacy) values.push(structuredClone(legacy));
      return values;
    },
    failNextWrite(error) {
      pendingFailure = error ?? new Error("injected write failure");
    },
  };
}

const IDB_STORE_NAME = "note-cache";

export async function idbHarness(): Promise<CacheHarness> {
  const dbName = `stsh-l4-${crypto.randomUUID()}`;
  const store = await openIndexedDbPrincipalCacheStore(dbName);
  const legacyStore = await openIndexedDbNoteStore(dbName);

  async function withDb<T>(fn: (db: Awaited<ReturnType<typeof openDB>>) => Promise<T>): Promise<T> {
    const db = await openDB(dbName, 1);
    try {
      return await fn(db);
    } finally {
      db.close();
    }
  }

  return {
    store,
    async seedLegacy(passphrase, state) {
      const cache = await NoteCache.open(legacyStore, passphrase);
      await cache.save(state);
      return (await legacyStore.load())!;
    },
    async readLegacy() {
      return legacyStore.load();
    },
    async readSlot(principalText) {
      return withDb(async (db) => {
        const slot = (await db.get(IDB_STORE_NAME, principalCacheKey(principalText))) as
          | CacheSlot
          | undefined;
        return slot ?? null;
      });
    },
    async writeSlot(principalText, slot) {
      await withDb(async (db) => {
        await db.put(IDB_STORE_NAME, slot, principalCacheKey(principalText));
      });
    },
    async allValues() {
      return withDb(async (db) => (await db.getAll(IDB_STORE_NAME)) as unknown[]);
    },
  };
}
