/**
 * Panic wipe (lane A-1b, R14-2) — erase every LOCAL trace this wallet origin
 * holds, on a device the user believes is compromised or is handing on.
 *
 * What this is NOT: it sends no message and changes nothing on chain. Notes,
 * balances, commitments and nullifiers live in the canisters and are restored
 * in full by an Internet Identity login plus a rescan on any device. What is
 * destroyed is the LOCAL journal/provenance — intents, output material, payout
 * destinations, fee and timing history — which exists nowhere else.
 *
 * Ordering is the correctness property, not a preference:
 *
 *   1. end the session — `endSession()` advances the session epoch FIRST and
 *      then locks/disposes the active cache, so an in-flight IC call from the
 *      old session can no longer commit. Deleting first and ending after would
 *      let a persist that is already awaiting RESURRECT the data behind the
 *      deletion.
 *   2. log out — the persisted Internet Identity delegation is a live
 *      credential on a seized device; II login is fully recoverable, so
 *      releasing it is pure upside.
 *   3. close this app's own IndexedDB handles, then delete the databases. An
 *      open handle makes `deleteDatabase` fire `blocked` and wait; a blocked
 *      deletion is reported as NOT cleared, never as success.
 *   4. clear whatever the runtime — not the source — shows at this origin:
 *      any other IndexedDB database (the auth client's own store is created by
 *      a library and named nowhere in this codebase), localStorage,
 *      sessionStorage, CacheStorage.
 *   5. re-enumerate and report per surface. A surface that failed is named as
 *      failed; the report never claims a blanket success it did not verify.
 *
 * Every deletion is scoped to storage this ORIGIN owns — the browser gives a
 * page no access to any other origin's storage, and nothing here enumerates or
 * removes anything outside it.
 */

import { closeAllDbConnections } from "./dbConnections";
import { ALL_DB_NAMES } from "./dbRegistry";

/**
 * L07-04 (R-7 item 6): the by-name list is now the REGISTRY, not a local pair.
 * It previously named two of the three databases this codebase creates —
 * `deviceStore`'s device-identity DB was declared privately in its own module
 * and so was invisible here, and survived the fallback path.
 *
 * The runtime enumeration below is UNIONED with this list, never replaced by
 * it: this is the floor when the browser cannot enumerate, not the ceiling.
 */

/** Oxford-style join, so a three-name list does not read "A and B and C". */
function joinNames(names: readonly string[]): string {
  return names.length <= 2
    ? names.join(" and ")
    : `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
}

/**
 * A full enumeration of the origin's client-side storage at one instant. Each
 * surface is an `Enumeration`, so a FAILED read is carried as a failure all the
 * way into the report rather than flattening to an empty list.
 */
export interface StorageInventory {
  indexedDb: Enumeration;
  localStorage: Enumeration;
  sessionStorage: Enumeration;
  cacheStorage: Enumeration;
}

export interface WipeSurfaceResult {
  /** Stable identifier, e.g. `indexeddb:stsh-wallet`, `localStorage`. */
  surface: string;
  cleared: boolean;
  /** What was found and what happened to it — the audit line for this surface. */
  detail: string;
}

export interface WipeReport {
  /** True only when EVERY attempted surface reported cleared. */
  complete: boolean;
  surfaces: WipeSurfaceResult[];
  before: StorageInventory;
  after: StorageInventory;
}

export interface PanicWipeDeps {
  /** Epoch-first session teardown (`CacheSessionManager.endSession`). */
  endSession: () => void;
  /** Release the persisted Internet Identity delegation. */
  logout: () => Promise<void>;
  factory?: IDBFactory | null;
  local?: Storage | null;
  session?: Storage | null;
  cacheStorage?: CacheStorage | null;
  /** Test seam: close registered `idb` handles. Defaults to the real registry. */
  closeConnections?: () => void;
}

function defaultFactory(): IDBFactory | null {
  return typeof indexedDB === "undefined" ? null : indexedDB;
}

/**
 * An enumeration either SUCCEEDS with a list, or FAILS. It never degrades to an
 * empty list — SSA D1: an observation failure is indistinguishable from an empty
 * origin, and treating one as the other lets the wipe claim "no data left" on the
 * strength of a `catch` block. `absent` is the third, honestly different case: the
 * API does not exist in this environment, so there is nothing it could be hiding.
 */
export type Enumeration =
  | { readonly kind: "ok"; readonly items: string[] }
  | { readonly kind: "absent" }
  | { readonly kind: "failed"; readonly reason: string };

const failed = (e: unknown): Enumeration => ({ kind: "failed", reason: String(e) });

/** Items when the enumeration succeeded; `[]` is NOT used to mean "unknown". */
function itemsOf(e: Enumeration): string[] {
  return e.kind === "ok" ? e.items : [];
}

function describe(e: Enumeration): string {
  switch (e.kind) {
    case "ok":
      return e.items.length === 0 ? "(none)" : e.items.join(", ");
    case "absent":
      return "(not available in this environment)";
    case "failed":
      return `(ENUMERATION FAILED: ${e.reason})`;
  }
}

async function listDatabases(factory: IDBFactory | null): Promise<Enumeration> {
  if (factory === null) return { kind: "absent" };
  if (typeof factory.databases !== "function") {
    // The API exists but cannot be listed: a library-created database outside the
    // two names this codebase knows would be invisible. That is unverifiable, not
    // empty, so it fails closed rather than reporting nothing to do.
    return { kind: "failed", reason: "indexedDB.databases() is unavailable in this browser" };
  }
  try {
    const dbs = await factory.databases();
    return { kind: "ok", items: dbs.map((d) => d.name ?? "").filter((n) => n !== "").sort() };
  } catch (e) {
    return failed(e);
  }
}

function listStorageKeys(storage: Storage | null | undefined): Enumeration {
  if (storage === null || storage === undefined) return { kind: "absent" };
  const keys: string[] = [];
  try {
    for (let i = 0; i < storage.length; i += 1) {
      const key = storage.key(i);
      if (key !== null) keys.push(key);
    }
  } catch (e) {
    return failed(e);
  }
  return { kind: "ok", items: keys.sort() };
}

async function listCaches(caches: CacheStorage | null | undefined): Promise<Enumeration> {
  if (caches === null || caches === undefined) return { kind: "absent" };
  try {
    return { kind: "ok", items: (await caches.keys()).sort() };
  } catch (e) {
    return failed(e);
  }
}

async function inventory(deps: {
  factory: IDBFactory | null;
  local: Storage | null;
  session: Storage | null;
  cacheStorage: CacheStorage | null;
}): Promise<StorageInventory> {
  return {
    indexedDb: await listDatabases(deps.factory),
    localStorage: listStorageKeys(deps.local),
    sessionStorage: listStorageKeys(deps.session),
    cacheStorage: await listCaches(deps.cacheStorage),
  };
}

/**
 * Surfaces whose enumeration did not SUCCEED, named. Any such surface makes the
 * wipe incomplete: we cannot claim an origin is clean using a list we failed to
 * read.
 */
function unreadable(inv: StorageInventory): string[] {
  return (
    [
      ["indexedDB", inv.indexedDb],
      ["localStorage", inv.localStorage],
      ["sessionStorage", inv.sessionStorage],
      ["CacheStorage", inv.cacheStorage],
    ] as const
  )
    .filter(([, e]) => e.kind === "failed")
    .map(([name, e]) => `${name} ${describe(e)}`);
}

/**
 * Delete one database, resolving on whichever of success/error/blocked fires
 * first. `blocked` means another connection (typically a second tab, or a
 * library in this page) is still open: the deletion has NOT happened, and
 * saying so is the whole point.
 */
function deleteDatabase(factory: IDBFactory, name: string): Promise<WipeSurfaceResult> {
  const surface = `indexeddb:${name}`;
  return new Promise<WipeSurfaceResult>((resolve) => {
    let settled = false;
    const settle = (result: WipeSurfaceResult): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    let request: IDBOpenDBRequest;
    try {
      request = factory.deleteDatabase(name);
    } catch (error) {
      settle({ surface, cleared: false, detail: `deleteDatabase threw: ${String(error)}` });
      return;
    }
    request.onsuccess = () => settle({ surface, cleared: true, detail: "database deleted" });
    request.onerror = () =>
      settle({
        surface,
        cleared: false,
        detail: `deletion failed: ${request.error?.message ?? "unknown IndexedDB error"}`,
      });
    request.onblocked = () =>
      settle({
        surface,
        cleared: false,
        detail:
          "deletion BLOCKED by another open connection — either another tab on this wallet, " +
          "or a library in this page that keeps its own handle open (the auth client does)",
      });
  });
}

/**
 * Open a database WITHOUT naming a version, so no `versionchange` is requested
 * and no other connection has to close for this to succeed.
 */
function openAnyVersion(factory: IDBFactory, name: string): Promise<IDBDatabase | null> {
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      request = factory.open(name);
    } catch {
      resolve(null);
      return;
    }
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => resolve(null);
    request.onblocked = () => resolve(null);
  });
}

/**
 * Fallback for a database this page cannot DELETE — in practice the auth
 * client's own store, which the client keeps open for the lifetime of the page
 * and which therefore blocks `deleteDatabase` forever, not transiently.
 *
 * Deleting the file is not the property that matters; leaving no data in it is.
 * Clearing every object store needs no version change and so is not blocked by
 * anyone else's open connection. Returns the number of records still present
 * afterwards, or `null` when the database could not even be opened.
 */
async function clearDatabaseContents(factory: IDBFactory, name: string): Promise<number | null> {
  const db = await openAnyVersion(factory, name);
  if (db === null) return null;
  try {
    const stores = Array.from(db.objectStoreNames);
    if (stores.length === 0) return 0;
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(stores, "readwrite");
      for (const store of stores) tx.objectStore(store).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    let remaining = 0;
    for (const store of stores) {
      remaining += await new Promise<number>((resolve) => {
        const req = db.transaction(store, "readonly").objectStore(store).count();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(1); // unknown ⇒ assume not empty; never assume success
      });
    }
    return remaining;
  } catch {
    return null;
  } finally {
    db.close();
  }
}

/**
 * Run the panic wipe. Never throws: a failing surface becomes a `cleared:
 * false` row, because a wipe that aborts halfway and reports an exception
 * tells the user less than one that names exactly what survived.
 */
export async function runPanicWipe(deps: PanicWipeDeps): Promise<WipeReport> {
  const factory = deps.factory === undefined ? defaultFactory() : deps.factory;
  const local = deps.local === undefined ? (typeof localStorage === "undefined" ? null : localStorage) : deps.local;
  const session =
    deps.session === undefined ? (typeof sessionStorage === "undefined" ? null : sessionStorage) : deps.session;
  const cacheStore =
    deps.cacheStorage === undefined ? (typeof caches === "undefined" ? null : caches) : deps.cacheStorage;
  const closeConnections = deps.closeConnections ?? closeAllDbConnections;

  const before = await inventory({ factory, local, session, cacheStorage: cacheStore });
  const surfaces: WipeSurfaceResult[] = [];
  /** Per-database record count measured immediately after clearing it. */
  const emptied = new Map<string, number | null>();

  // ── 1. epoch first: nothing from the old session may commit after this ──
  try {
    deps.endSession();
    surfaces.push({
      surface: "session",
      cleared: true,
      detail: "session epoch advanced and the in-memory note cache locked and disposed",
    });
  } catch (error) {
    surfaces.push({ surface: "session", cleared: false, detail: `endSession failed: ${String(error)}` });
  }

  // ── 2. release the persisted II delegation ──
  try {
    await deps.logout();
    surfaces.push({ surface: "auth", cleared: true, detail: "Internet Identity delegation released" });
  } catch (error) {
    surfaces.push({ surface: "auth", cleared: false, detail: `logout failed: ${String(error)}` });
  }

  // ── 3. close our own handles, then delete every database at this origin ──
  closeConnections();
  if (factory === null) {
    surfaces.push({
      surface: "indexeddb",
      cleared: false,
      detail: "no IndexedDB in this environment — nothing could be deleted",
    });
  } else {
    if (before.indexedDb.kind === "failed") {
      // SSA D1: we still wipe every database we know by name, but we cannot
      // claim the origin is clean — a library-created database outside those
      // names would be invisible to a failed enumeration, and an unread list is
      // not an empty one.
      surfaces.push({
        surface: "indexeddb:enumeration",
        cleared: false,
        detail:
          `the origin's database list could not be read ${describe(before.indexedDb)} — any ` +
          `database other than ${joinNames(ALL_DB_NAMES)} is UNACCOUNTED FOR`,
      });
    }
    const names = Array.from(new Set([...ALL_DB_NAMES, ...itemsOf(before.indexedDb)]));
    for (const name of names) {
      // CLEAR FIRST, then delete. Order matters for a reason the browser
      // enforces and no unit test sees: a `deleteDatabase` that fires
      // `blocked` stays PENDING, and IndexedDB queues every later open on that
      // database behind it — so a blocked delete makes the in-place fallback
      // (and any verification read) hang forever. Emptying the stores needs no
      // version change and is never blocked, so it goes first and the delete
      // becomes best-effort tidying on top of an already-emptied database.
      const remaining = await clearDatabaseContents(factory, name);
      // Sequential, not concurrent: a parallel delete storm would make
      // `blocked` attributable to our own requests rather than to another tab.
      const deleted = await deleteDatabase(factory, name);
      emptied.set(name, remaining);
      if (deleted.cleared) {
        surfaces.push(deleted);
      } else if (remaining === 0) {
        // The normal path for the auth client's own store: it keeps its
        // connection open for the life of the page, so its database can never
        // be deleted from here — but it can be, and now is, left with no data.
        surfaces.push({
          surface: deleted.surface,
          cleared: true,
          detail:
            `every object store was cleared in place and recounted at 0 records; the database ` +
            `itself still exists because ${deleted.detail}`,
        });
      } else {
        surfaces.push({
          surface: deleted.surface,
          cleared: false,
          detail:
            remaining === null
              ? `${deleted.detail}; the contents could not be cleared either`
              : `${deleted.detail}; clearing the contents left ${remaining} record(s) behind`,
        });
      }
    }
  }

  // ── 4. runtime-discovered key/value and cache storage at this origin ──
  for (const [surface, storage] of [
    ["localStorage", local],
    ["sessionStorage", session],
  ] as const) {
    if (storage === null || storage === undefined) {
      surfaces.push({ surface, cleared: true, detail: "not available in this environment" });
      continue;
    }
    const keys = listStorageKeys(storage);
    try {
      storage.clear();
    } catch (error) {
      surfaces.push({ surface, cleared: false, detail: `clear failed: ${String(error)}` });
      continue;
    }
    if (keys.kind === "failed") {
      // The clear() may well have worked — but we could not read what was there,
      // so we cannot report what was removed, and the post-wipe re-read below is
      // the only thing that could redeem it. Fail closed either way (SSA D1).
      surfaces.push({
        surface,
        cleared: false,
        detail: `clear() was called, but the key list could not be read ${describe(keys)} — the contents are UNVERIFIED`,
      });
      continue;
    }
    surfaces.push({
      surface,
      cleared: true,
      detail:
        itemsOf(keys).length === 0
          ? "no keys present"
          : `cleared ${itemsOf(keys).length} key(s): ${itemsOf(keys).join(", ")}`,
    });
  }

  if (cacheStore === null || cacheStore === undefined) {
    surfaces.push({ surface: "cacheStorage", cleared: true, detail: "not available in this environment" });
  } else {
    const listed = await listCaches(cacheStore);
    if (listed.kind === "failed") {
      // SSA D1: this used to read as a green "no caches present" row.
      surfaces.push({
        surface: "cacheStorage",
        cleared: false,
        detail: `the cache list could not be read ${describe(listed)} — no cache could be deleted and none is accounted for`,
      });
    } else {
      const names = itemsOf(listed);
      const undeleted: string[] = [];
      for (const name of names) {
        try {
          if (!(await cacheStore.delete(name))) undeleted.push(name);
        } catch {
          undeleted.push(name);
        }
      }
      surfaces.push({
        surface: "cacheStorage",
        cleared: undeleted.length === 0,
        detail:
          names.length === 0
            ? "no caches present"
            : undeleted.length === 0
              ? `deleted ${names.length} cache(s): ${names.join(", ")}`
              : `failed to delete: ${undeleted.join(", ")}`,
      });
    }
  }

  // ── 5. verify by re-enumeration, then report ──
  const after = await inventory({ factory, local, session, cacheStorage: cacheStore });

  // A database that still EXISTS but holds no records is not a survivor: the
  // property is "no data left at this origin", not "no database files left".
  // Anything whose record count is unknown counts against us, never for us.
  const holdingData: string[] = [];
  for (const name of itemsOf(after.indexedDb)) {
    // The count measured right after clearing — NOT a fresh open, which would
    // queue behind any still-pending blocked delete and never return.
    const count = emptied.get(name);
    if (count === undefined || count === null || count > 0) {
      holdingData.push(`${name} (${count === null || count === undefined ? "unreadable" : count} record(s))`);
    }
  }
  // An enumeration we could not read is NOT a verified-empty one (SSA D1): the
  // post-wipe re-read has to SUCCEED before this row may say "no data left".
  const unread = unreadable(after);
  const survivors =
    holdingData.length +
    itemsOf(after.localStorage).length +
    itemsOf(after.sessionStorage).length +
    itemsOf(after.cacheStorage).length;
  const verified = survivors === 0 && unread.length === 0;
  const complete = surfaces.every((s) => s.cleared) && verified;
  surfaces.push({
    surface: "verification",
    cleared: verified,
    detail: verified
      ? `no data left: databases still present [${describe(after.indexedDb)}] hold 0 records; ` +
        `localStorage, sessionStorage and CacheStorage are empty`
      : unread.length > 0
        ? `the post-wipe re-enumeration could not be read for: ${unread.join("; ")} — ` +
          `this origin CANNOT be reported clean` +
          (survivors > 0 ? `; and data was still found in indexedDB [${holdingData.join(", ")}]` : "")
        : `still holding data: indexedDB [${holdingData.join(", ")}], ` +
          `localStorage [${describe(after.localStorage)}], sessionStorage [${describe(after.sessionStorage)}], ` +
          `caches [${describe(after.cacheStorage)}]`,
  });

  return { complete, surfaces, before, after };
}
