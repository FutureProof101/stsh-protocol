/**
 * A-1b — panic wipe (R14-2). Local-only erasure of everything this wallet
 * origin stores, on a device the user believes is compromised.
 *
 * The tests are causal, not post-state equality checks: every one of them
 * SEEDS distinguishable data and asserts it was present immediately before the
 * wipe, because a wipe over empty storage passes an "is it empty?" assertion
 * vacuously — the "empty fleet reports health" defect, transplanted.
 *
 *   E1  seeded records in BOTH databases are gone, and re-opening does not
 *       resurrect them
 *   E2  the seeded state was present and non-empty immediately before the wipe
 *   E3  a persist already awaiting when the wipe runs cannot commit afterwards
 *       (the epoch fence, ordered FIRST, is what makes this true)
 *   E4  a deletion that fails is reported as NOT cleared, per surface, and the
 *       overall report is not complete
 *   E6  the wipe is unreachable without the confirmation step
 */

import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { openDB } from "idb";

import { ALL_DB_NAMES } from "../src/storage/dbRegistry";
import {
  type Enumeration,
  runPanicWipe,
  type PanicWipeDeps,
  type WipeReport,
} from "../src/storage/panicWipe";
import { closeAllDbConnections, openDbConnectionCount, registerDbConnection } from "../src/storage/dbConnections";
import { CacheSessionManager } from "../src/session/cacheSession";
import { SessionEpoch } from "../src/session/sessionEpoch";


/** The listed items of a SUCCESSFUL enumeration; a failed read is not an empty one. */
function listed(e: Enumeration): string[] {
  expect(e.kind, `expected a successful enumeration, got ${JSON.stringify(e)}`).toBe("ok");
  return e.kind === "ok" ? e.items : [];
}

const NOTE_DB = "stsh-wallet";
const TRANSFER_DB = "stsh-wallet-transfers";
/**
 * L07-04 (R-7 item 6): the THIRD database. It was declared privately inside
 * `deviceStore.ts` and opened through a raw `indexedDB.open`, so `panicWipe`'s
 * by-name list never held it and the fallback path left it behind.
 */
const DEVICE_DB = "stsh-device-identity";

/** A minimal in-memory Storage, so localStorage/sessionStorage are seedable. */
function memoryStorage(seed: Record<string, string> = {}): Storage {
  const map = new Map<string, string>(Object.entries(seed));
  return {
    get length() {
      return map.size;
    },
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => map.clear(),
  } as Storage;
}

/** Seeds ALL THREE wallet databases with DISTINGUISHABLE records, and closes them. */
async function seedBothDatabases(): Promise<{ noteBytes: number; transferKey: string }> {
  const deviceDb = await openDB(DEVICE_DB, 1, {
    upgrade(db) {
      db.createObjectStore("device");
    },
  });
  await deviceDb.put("device", { deviceId: "device-under-test" }, DEVICE_KEY);
  deviceDb.close();

  const noteDb = await openDB(NOTE_DB, 1, {
    upgrade(db) {
      db.createObjectStore("note-cache");
    },
  });
  const ciphertext = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
  await noteDb.put("note-cache", { kdfVersion: 2, ciphertext }, "state:aaaaa-aa");
  noteDb.close();

  const transferDb = await openDB(TRANSFER_DB, 2, {
    upgrade(db) {
      db.createObjectStore("transfer-intents");
      db.createObjectStore("transfer-archive", { autoIncrement: true });
    },
  });
  const transferKey = "v2|intent-under-test";
  await transferDb.put("transfer-intents", { toOwner: "recipient-under-test", amount: "42" }, transferKey);
  transferDb.close();

  return { noteBytes: ciphertext.length, transferKey };
}

const DEVICE_KEY = "aaaaa-aa";

async function readDeviceRecord(): Promise<unknown> {
  const db = await openDB(DEVICE_DB, 1, { upgrade(d) { d.createObjectStore("device"); } });
  const value = await db.get("device", DEVICE_KEY);
  db.close();
  return value;
}

async function readNoteSlot(): Promise<unknown> {
  const db = await openDB(NOTE_DB, 1, { upgrade(d) { d.createObjectStore("note-cache"); } });
  const value = await db.get("note-cache", "state:aaaaa-aa");
  db.close();
  return value;
}

async function readTransferIntent(key: string): Promise<unknown> {
  const db = await openDB(TRANSFER_DB, 2, {
    upgrade(d) {
      d.createObjectStore("transfer-intents");
      d.createObjectStore("transfer-archive", { autoIncrement: true });
    },
  });
  const value = await db.get("transfer-intents", key);
  db.close();
  return value;
}

async function listDatabaseNames(): Promise<string[]> {
  return (await indexedDB.databases()).map((d) => d.name ?? "").filter((n) => n !== "").sort();
}

function deps(extra: Partial<PanicWipeDeps> = {}): PanicWipeDeps {
  return {
    endSession: () => {},
    logout: async () => {},
    local: memoryStorage(),
    session: memoryStorage(),
    cacheStorage: null,
    ...extra,
  };
}

/** Delete every database left behind by a previous test. */
async function resetOrigin(): Promise<void> {
  closeAllDbConnections();
  for (const name of await listDatabaseNames()) {
    await new Promise<void>((resolve) => {
      const req = indexedDB.deleteDatabase(name);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
      req.onblocked = () => resolve();
    });
  }
}

beforeEach(resetOrigin);

describe("A-1b panic wipe — E1/E2: both databases, seeded then gone", () => {
  it("erases seeded records in stsh-wallet and stsh-wallet-transfers and does not resurrect them", async () => {
    const { transferKey } = await seedBothDatabases();

    // ── E2: the state was really there, immediately before the wipe ─────────
    const noteBefore = await readNoteSlot();
    const transferBefore = await readTransferIntent(transferKey);
    expect(noteBefore, "seeded note slot must exist BEFORE the wipe").toBeDefined();
    expect(transferBefore, "seeded transfer intent must exist BEFORE the wipe").toBeDefined();
    expect(await readDeviceRecord(), "seeded device record must exist BEFORE the wipe").toBeDefined();
    const namesBefore = await listDatabaseNames();
    expect(namesBefore).toEqual(expect.arrayContaining([...ALL_DB_NAMES]));

    const report = await runPanicWipe(deps());

    // ── E1a: the databases are gone from the origin's enumeration ───────────
    expect(report.complete, JSON.stringify(report.surfaces, null, 2)).toBe(true);
    expect(await listDatabaseNames()).toEqual([]);

    // ── E1b: re-opening resurrects nothing (a fresh, empty database) ────────
    expect(await readNoteSlot()).toBeUndefined();
    expect(await readTransferIntent(transferKey)).toBeUndefined();
    // AC-6d: the device-identity database is emptied too — a re-open yields a
    // fresh, empty database, not the seeded record.
    expect(await readDeviceRecord()).toBeUndefined();

    for (const name of ALL_DB_NAMES) {
      const row = report.surfaces.find((s) => s.surface === `indexeddb:${name}`);
      expect(row?.cleared, `${name} must be reported cleared`).toBe(true);
    }
    expect(listed(report.before.indexedDb)).toEqual(expect.arrayContaining([...ALL_DB_NAMES]));
    expect(listed(report.after.indexedDb)).toEqual([]);
  });

  it("clears runtime-discovered key/value storage and lists exactly what it removed", async () => {
    const local = memoryStorage({ "ii-delegation-hint": "x", "wallet-theme": "dark" });
    const session = memoryStorage({ "scan-cursor": "1234" });
    expect(local.length, "localStorage must be non-empty BEFORE the wipe (E2)").toBe(2);
    expect(session.length, "sessionStorage must be non-empty BEFORE the wipe (E2)").toBe(1);

    const report = await runPanicWipe(deps({ local, session }));

    expect(local.length).toBe(0);
    expect(session.length).toBe(0);
    const localRow = report.surfaces.find((s) => s.surface === "localStorage");
    expect(localRow?.cleared).toBe(true);
    // Count AND full list — never a count and a sample.
    expect(localRow?.detail).toContain("ii-delegation-hint");
    expect(localRow?.detail).toContain("wallet-theme");
    expect(listed(report.before.localStorage)).toEqual(["ii-delegation-hint", "wallet-theme"]);
    expect(listed(report.after.localStorage)).toEqual([]);
  });

  it("deletes databases this codebase never names — the library-created surface", async () => {
    // The auth client creates its own database; nothing in wallet/src names it.
    const authDb = await openDB("auth-client-db", 1, { upgrade(d) { d.createObjectStore("ic-keyval"); } });
    await authDb.put("ic-keyval", "a-live-delegation", "delegation");
    authDb.close();
    expect(await listDatabaseNames()).toContain("auth-client-db");

    const report = await runPanicWipe(deps());

    expect(await listDatabaseNames()).toEqual([]);
    expect(report.surfaces.find((s) => s.surface === "indexeddb:auth-client-db")?.cleared).toBe(true);
  });
});

describe("A-1b panic wipe — E3: ordering, the epoch fence fires first", () => {
  it("a persist that resumes AFTER the wipe is refused by the real epoch fence", async () => {
    await seedBothDatabases();

    // The REAL production fence: a CacheSessionManager over a real
    // SessionEpoch. `endSession()` advances the epoch and locks the cache —
    // this test passes the production call itself to the wipe, not a stand-in.
    const epochs = new SessionEpoch();
    const manager = new CacheSessionManager(epochs);

    // An in-flight durable write, captured under the epoch that was current
    // when it started — the same capture-before-await/re-check-after-await
    // discipline every async path in this wallet uses.
    const captured = epochs.current();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const persist = (async (): Promise<"committed" | "refused"> => {
      await gate;
      if (!epochs.isCurrent(captured)) return "refused";
      const db = await openDB(NOTE_DB, 1, { upgrade(d) { d.createObjectStore("note-cache"); } });
      await db.put("note-cache", { kdfVersion: 2, ciphertext: new Uint8Array([1]) }, "state:resurrected");
      db.close();
      return "committed";
    })();

    const report = await runPanicWipe(deps({ endSession: () => manager.endSession() }));
    expect(report.complete).toBe(true);
    expect(await listDatabaseNames()).toEqual([]);

    // Only NOW does the in-flight persist resume — the worst case, strictly
    // after every deletion. With the epoch step removed it writes a brand-new
    // database and the wiped data comes back; with it, the commit is dropped.
    release();
    expect(await persist, "a post-wipe commit must be refused, not written").toBe("refused");
    expect(await listDatabaseNames(), "no database may reappear after the wipe").toEqual([]);
  });

  it("closes the app's own registered connections before deleting", async () => {
    await seedBothDatabases();
    const live = await openDB(NOTE_DB, 1, { upgrade(d) { d.createObjectStore("note-cache"); } });
    registerDbConnection(live);
    expect(openDbConnectionCount()).toBe(1);

    const report = await runPanicWipe(deps());

    expect(openDbConnectionCount()).toBe(0);
    expect(report.surfaces.find((s) => s.surface === `indexeddb:${NOTE_DB}`)?.cleared).toBe(true);
  });
});

describe("A-1b panic wipe — E4: partial failure is reported, never papered over", () => {
  it("reports the failing database as NOT cleared and the wipe as incomplete", async () => {
    await seedBothDatabases();
    const real = indexedDB;
    // Only the transfer database fails; everything else proceeds normally.
    const factory = {
      databases: () => real.databases(),
      deleteDatabase: (name: string) => {
        if (name !== TRANSFER_DB) return real.deleteDatabase(name);
        const request: Record<string, unknown> = {
          error: { message: "simulated deletion failure" },
          onsuccess: null,
          onerror: null,
          onblocked: null,
        };
        queueMicrotask(() => (request.onerror as (() => void) | null)?.());
        return request as unknown as IDBOpenDBRequest;
      },
    } as unknown as IDBFactory;

    const report = await runPanicWipe(deps({ factory }));

    expect(report.complete, "a failed surface must make the whole wipe incomplete").toBe(false);
    const noteRow = report.surfaces.find((s) => s.surface === `indexeddb:${NOTE_DB}`);
    const transferRow = report.surfaces.find((s) => s.surface === `indexeddb:${TRANSFER_DB}`);
    expect(noteRow?.cleared, "the database that DID delete is still reported cleared").toBe(true);
    expect(transferRow?.cleared).toBe(false);
    expect(transferRow?.detail).toContain("simulated deletion failure");
    // And the survivor is named in the post-wipe verification, not implied.
    expect(listed(report.after.indexedDb)).toContain(TRANSFER_DB);
    expect(report.surfaces.find((s) => s.surface === "verification")?.cleared).toBe(false);
  });

  it("reports a BLOCKED deletion as not cleared rather than as success", async () => {
    await seedBothDatabases();
    const real = indexedDB;
    const factory = {
      databases: () => real.databases(),
      deleteDatabase: (name: string) => {
        if (name !== NOTE_DB) return real.deleteDatabase(name);
        const request: Record<string, unknown> = { onsuccess: null, onerror: null, onblocked: null };
        queueMicrotask(() => (request.onblocked as (() => void) | null)?.());
        return request as unknown as IDBOpenDBRequest;
      },
    } as unknown as IDBFactory;

    const report = await runPanicWipe(deps({ factory }));

    const row = report.surfaces.find((s) => s.surface === `indexeddb:${NOTE_DB}`);
    expect(row?.cleared).toBe(false);
    expect(row?.detail).toContain("BLOCKED");
    expect(report.complete).toBe(false);
  });

  it("a database that cannot be DELETED is emptied in place and verified by recount", async () => {
    // The real case this exists for: the auth client keeps its own IndexedDB
    // connection open for the life of the page, so `deleteDatabase` on it is
    // blocked permanently, not transiently. Found by running the built wallet
    // in a real browser (E5) — every unit test passed while the delegation
    // store survived the wipe.
    const authDb = await openDB("auth-client-db", 1, { upgrade(d) { d.createObjectStore("ic-keyval"); } });
    await authDb.put("ic-keyval", "a-live-delegation", "delegation");
    // deliberately left OPEN, exactly as the auth client leaves it
    expect(await authDb.get("ic-keyval", "delegation")).toBe("a-live-delegation");

    const real = indexedDB;
    const factory = {
      databases: () => real.databases(),
      open: (name: string, version?: number) => real.open(name, version),
      deleteDatabase: (name: string) => {
        if (name !== "auth-client-db") return real.deleteDatabase(name);
        const request: Record<string, unknown> = { onsuccess: null, onerror: null, onblocked: null };
        queueMicrotask(() => (request.onblocked as (() => void) | null)?.());
        return request as unknown as IDBOpenDBRequest;
      },
    } as unknown as IDBFactory;

    const report = await runPanicWipe(deps({ factory }));

    const row = report.surfaces.find((s) => s.surface === "indexeddb:auth-client-db");
    expect(row?.cleared, "an emptied database is cleared even though it still exists").toBe(true);
    expect(row?.detail).toContain("0 records");
    expect(await authDb.get("ic-keyval", "delegation"), "the delegation must be gone").toBeUndefined();
    authDb.close();

    // And the wipe as a whole is complete: the surviving database holds nothing.
    expect(listed(report.after.indexedDb)).toContain("auth-client-db");
    expect(report.complete).toBe(true);
    expect(report.surfaces.find((s) => s.surface === "verification")?.cleared).toBe(true);
  });

  it("a failing logout is reported without aborting the deletions", async () => {
    await seedBothDatabases();
    const report = await runPanicWipe(
      deps({
        logout: async () => {
          throw new Error("auth client unavailable");
        },
      }),
    );
    expect(report.surfaces.find((s) => s.surface === "auth")?.cleared).toBe(false);
    expect(report.complete).toBe(false);
    // The databases were still deleted — a broken logout must not leave the
    // note cache on a seized device.
    expect(await listDatabaseNames()).toEqual([]);
  });
});

describe("A-1b panic wipe — D1: an enumeration that FAILS is never reported as empty", () => {
  // SSA D1 (RED V1): every enumerator used to `catch` and return `[]`, so an
  // observation failure was indistinguishable from an empty origin — and the
  // wipe could report `complete` on the strength of a list it never read.

  it("a failing indexedDB.databases() leaves a real survivor UNACCOUNTED FOR, and says so", async () => {
    await seedBothDatabases();
    // A database this codebase does not know by name — exactly what the
    // enumeration exists to find.
    const rogue = await openDB("rogue-library-db", 1, { upgrade(d) { d.createObjectStore("kv"); } });
    await rogue.put("kv", "a-secret-the-wipe-must-not-miss", "k");
    rogue.close();

    const real = indexedDB;
    const factory = {
      databases: () => Promise.reject(new Error("simulated enumeration failure")),
      open: (name: string, version?: number) => real.open(name, version),
      deleteDatabase: (name: string) => real.deleteDatabase(name),
    } as unknown as IDBFactory;

    const report = await runPanicWipe(deps({ factory }));

    const row = report.surfaces.find((s) => s.surface === "indexeddb:enumeration");
    expect(row?.cleared, "an unreadable database list is not a clean one").toBe(false);
    expect(row?.detail).toContain("UNACCOUNTED FOR");
    expect(report.complete).toBe(false);
    expect(report.before.indexedDb.kind).toBe("failed");

    // The survivor is REAL: this is what the fail-open version silently hid.
    const still = await openDB("rogue-library-db", 1, { upgrade(d) { d.createObjectStore("kv"); } });
    expect(await still.get("kv", "k")).toBe("a-secret-the-wipe-must-not-miss");
    still.close();
  });

  it("a browser without indexedDB.databases() cannot claim the origin is clean", async () => {
    await seedBothDatabases();
    const real = indexedDB;
    const factory = {
      open: (name: string, version?: number) => real.open(name, version),
      deleteDatabase: (name: string) => real.deleteDatabase(name),
    } as unknown as IDBFactory; // no `databases` member at all

    const report = await runPanicWipe(deps({ factory }));

    expect(report.surfaces.find((s) => s.surface === "indexeddb:enumeration")?.cleared).toBe(false);
    expect(report.complete).toBe(false);
    // AC-6e: EVERY registered database is still wiped — failing closed is not
    // giving up — and that now includes the device-identity DB, which the
    // fallback path missed entirely before the registry existed.
    for (const name of ALL_DB_NAMES) {
      expect(
        report.surfaces.find((s) => s.surface === `indexeddb:${name}`)?.cleared,
        `${name} must be wiped on the fallback path`,
      ).toBe(true);
    }
    expect(await readNoteSlot()).toBeUndefined();
    expect(await readTransferIntent("v2|intent-under-test")).toBeUndefined();
    expect(await readDeviceRecord()).toBeUndefined();
  });

  it("AC-6e: the UNACCOUNTED FOR line names EVERY registry entry, Oxford-joined", async () => {
    await seedBothDatabases();
    const real = indexedDB;
    const factory = {
      databases: () => Promise.reject(new Error("simulated enumeration failure")),
      open: (name: string, version?: number) => real.open(name, version),
      deleteDatabase: (name: string) => real.deleteDatabase(name),
    } as unknown as IDBFactory;

    const report = await runPanicWipe(deps({ factory }));
    const detail = report.surfaces.find((s) => s.surface === "indexeddb:enumeration")?.detail ?? "";

    expect(detail).toContain("UNACCOUNTED FOR");
    for (const name of ALL_DB_NAMES) expect(detail, `${name} must be named`).toContain(name);
    // Three names read "A, B, and C" — never "A and B and C".
    expect(detail).toContain(
      `${ALL_DB_NAMES.slice(0, -1).join(", ")}, and ${ALL_DB_NAMES[ALL_DB_NAMES.length - 1]}`,
    );
    expect(detail).not.toContain(`${ALL_DB_NAMES[0]} and ${ALL_DB_NAMES[1]} and`);
  });

  it("a failing storage key read is reported UNVERIFIED, not as 'no keys present'", async () => {
    await seedBothDatabases();
    let cleared = false;
    const hostile = {
      get length(): number {
        throw new Error("simulated storage enumeration failure");
      },
      key: () => null,
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
      clear: () => {
        cleared = true;
      },
    } as unknown as Storage;

    const report = await runPanicWipe(deps({ local: hostile }));

    const row = report.surfaces.find((s) => s.surface === "localStorage");
    expect(row?.cleared).toBe(false);
    expect(row?.detail).toContain("UNVERIFIED");
    expect(row?.detail).not.toContain("no keys present");
    expect(cleared, "clear() is still attempted — fail-closed is about the CLAIM").toBe(true);
    expect(report.complete).toBe(false);
  });

  it("a failing caches.keys() is reported as unreadable, not as 'no caches present'", async () => {
    await seedBothDatabases();
    const hostile = {
      keys: () => Promise.reject(new Error("simulated cache enumeration failure")),
      delete: () => Promise.resolve(true),
    } as unknown as CacheStorage;

    const report = await runPanicWipe(deps({ cacheStorage: hostile }));

    const row = report.surfaces.find((s) => s.surface === "cacheStorage");
    expect(row?.cleared).toBe(false);
    expect(row?.detail).toContain("could not be read");
    expect(row?.detail).not.toContain("no caches present");
    expect(report.complete).toBe(false);
  });

  it("a post-wipe re-enumeration that fails blocks the 'no data left' verdict", async () => {
    await seedBothDatabases();
    const real = indexedDB;
    let calls = 0;
    const factory = {
      // succeeds BEFORE the wipe, fails on the verification re-read
      databases: () => (calls++ === 0 ? real.databases() : Promise.reject(new Error("post-wipe read failed"))),
      open: (name: string, version?: number) => real.open(name, version),
      deleteDatabase: (name: string) => real.deleteDatabase(name),
    } as unknown as IDBFactory;

    const report = await runPanicWipe(deps({ factory }));

    // Both databases really were deleted...
    expect(report.surfaces.find((s) => s.surface === `indexeddb:${NOTE_DB}`)?.cleared).toBe(true);
    expect(report.surfaces.find((s) => s.surface === `indexeddb:${TRANSFER_DB}`)?.cleared).toBe(true);
    // ...but the wipe cannot VERIFY it, so it does not claim it.
    const verification = report.surfaces.find((s) => s.surface === "verification");
    expect(verification?.cleared).toBe(false);
    expect(verification?.detail).toContain("CANNOT be reported clean");
    expect(report.complete).toBe(false);
  });
});
