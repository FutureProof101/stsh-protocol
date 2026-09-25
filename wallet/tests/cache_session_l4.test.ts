/**
 * L4 gate tests — session/cache concurrency (§1.1): epoch binding at
 * construction, logout/expiry locking, stale-epoch commits rejected, offline
 * principal selection from the restored II session, the TWO-TAB revision-CAS
 * race on the REAL IndexedDB store (both logical changes survive — S-22), CAS
 * exhaustion, and the Argon2id on-target benchmark.
 */

import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import { Principal } from "@dfinity/principal";

import { SessionEpoch } from "../src/session/sessionEpoch";
import {
  CacheSessionManager,
  NoCacheSessionError,
  principalForCache,
} from "../src/session/cacheSession";
import { openIndexedDbPrincipalCacheStore } from "../src/storage/indexedDbNoteStore";
import {
  ARGON2ID_SALT_BYTES,
  CacheSessionStaleError,
  CacheWriteConflictError,
  PrincipalNoteCache,
  deriveCacheKeyV2,
  type CachedScanState,
  type PrincipalCacheStore,
} from "../src/storage/noteCache";
import { addNote, fakeSession, memoryHarness, note, testBinding } from "./helpers/cacheL4";

const IDENTITY_A = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(11));
const IDENTITY_B = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(12));
const PRINCIPAL_A = IDENTITY_A.getPrincipal();
const PRINCIPAL_B = IDENTITY_B.getPrincipal();

const PASSPHRASE = "correct horse battery staple";

function deferred<T = void>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("L4 offline principal selection (restored II session)", () => {
  it("derives the cache principal from the session IDENTITY (A-S7), no network involved", () => {
    // Deliberately mismatched declared principal: the identity must win.
    const session = fakeSession(PRINCIPAL_A, Principal.anonymous());
    expect(principalForCache(session)).toBe(PRINCIPAL_A.toText());
  });

  it("refuses an absent session", () => {
    expect(() => principalForCache(null)).toThrow(NoCacheSessionError);
  });

  it("refuses an anonymous session", () => {
    expect(() => principalForCache(fakeSession(Principal.anonymous()))).toThrow(
      NoCacheSessionError,
    );
  });
});

describe("L4 epoch binding + session lifecycle (§1.1)", () => {
  it("a cache is bound to (principal, epoch) at construction and works while current", async () => {
    const h = await memoryHarness();
    const epochs = new SessionEpoch();
    epochs.advance(); // login
    const manager = new CacheSessionManager(epochs);

    const cache = await manager.openForSession(h.store, PASSPHRASE, fakeSession(PRINCIPAL_A));
    expect(cache.boundPrincipal).toBe(PRINCIPAL_A.toText());
    expect(cache.boundEpoch).toBe(epochs.current());
    await cache.update(addNote(note(1n, 20)));
    expect((await cache.load()).notes).toHaveLength(1);
    expect(manager.activeCache).toBe(cache);
  });

  it("endSession advances the epoch, locks and disposes the cache; late ops are rejected", async () => {
    const h = await memoryHarness();
    const epochs = new SessionEpoch();
    epochs.advance();
    const manager = new CacheSessionManager(epochs);
    const cache = await manager.openForSession(h.store, PASSPHRASE, fakeSession(PRINCIPAL_A));
    const epochBefore = epochs.current();

    manager.endSession();

    expect(epochs.current()).toBe(epochBefore + 1);
    expect(manager.activeCache).toBeNull();
    await expect(cache.load()).rejects.toBeInstanceOf(CacheSessionStaleError);
    await expect(cache.update(addNote(note(2n, 21)))).rejects.toBeInstanceOf(
      CacheSessionStaleError,
    );
  });

  it("a logout DURING an update prevents the commit (epoch re-checked before the write)", async () => {
    const h = await memoryHarness();
    const epochs = new SessionEpoch();
    epochs.advance();
    const manager = new CacheSessionManager(epochs);
    const cache = await manager.openForSession(h.store, PASSPHRASE, fakeSession(PRINCIPAL_A));

    const entered = deferred();
    const gate = deferred();
    const pending = cache.update(async (state) => {
      entered.resolve();
      await gate.promise;
      return addNote(note(3n, 22))(state);
    });
    await entered.promise;
    manager.endSession(); // logout while fn is mid-flight
    gate.resolve();

    await expect(pending).rejects.toBeInstanceOf(CacheSessionStaleError);

    // The write never landed: a NEW session sees the cache without the note.
    epochs.advance();
    const manager2 = new CacheSessionManager(epochs);
    const reopened = await manager2.openForSession(h.store, PASSPHRASE, fakeSession(PRINCIPAL_A));
    expect((await reopened.load()).notes).toHaveLength(0);
  });

  it("opening a session for principal B locks A's instance — no cross-principal survival", async () => {
    const h = await memoryHarness();
    const epochs = new SessionEpoch();
    epochs.advance();
    const manager = new CacheSessionManager(epochs);

    const cacheA = await manager.openForSession(h.store, PASSPHRASE, fakeSession(PRINCIPAL_A));
    await cacheA.update(addNote(note(1n, 23)));

    const cacheB = await manager.openForSession(h.store, PASSPHRASE, fakeSession(PRINCIPAL_B));
    await expect(cacheA.load()).rejects.toBeInstanceOf(CacheSessionStaleError); // locked
    expect((await cacheB.load()).notes).toHaveLength(0); // B's own empty cache
    expect(cacheB.boundPrincipal).toBe(PRINCIPAL_B.toText());
  });
});

describe("L4 two-tab CAS race (S-22, real IndexedDB)", () => {
  it("two tabs writing concurrently: BOTH logical changes survive via the transactional CAS", async () => {
    const dbName = `stsh-l4-race-${crypto.randomUUID()}`;
    const principal = PRINCIPAL_A.toText();

    // Two independent connections to the SAME database — two "tabs" with
    // separate JS worlds; only the IndexedDB transaction serializes them.
    const storeA = await openIndexedDbPrincipalCacheStore(dbName);
    const storeBRaw = await openIndexedDbPrincipalCacheStore(dbName);

    // Gate tab B's CAS write so the interleaving is deterministic: B reads the
    // shared revision BEFORE A writes, and commits AFTER — a guaranteed lost
    // CAS that must retry and re-apply B's logical change.
    const gate = deferred();
    let armed = false;
    const storeB: PrincipalCacheStore = {
      get: (p) => storeBRaw.get(p),
      getLegacy: () => storeBRaw.getLegacy(),
      migrateLegacy: (p, s, o) => storeBRaw.migrateLegacy(p, s, o),
      compareAndPut: async (p, expected, slot) => {
        if (armed) {
          armed = false;
          await gate.promise;
        }
        return storeBRaw.compareAndPut(p, expected, slot);
      },
    };

    const tabA = await PrincipalNoteCache.open(storeA, PASSPHRASE, testBinding(principal));
    const tabB = await PrincipalNoteCache.open(storeB, PASSPHRASE, testBinding(principal));

    const noteX = note(10n, 30);
    const noteY = note(11n, 33);

    const bRead = deferred();
    armed = true;
    const pendingB = tabB.update((state) => {
      bRead.resolve(); // B has read (and will write against) the current revision
      return addNote(noteY)(state);
    });
    await bRead.promise;

    await tabA.update(addNote(noteX)); // A commits first
    gate.resolve(); // now B's stale CAS runs, loses, retries, re-applies Y

    const finalFromB = await pendingB;
    expect(finalFromB.notes.map((n) => n.leafIndex).sort()).toEqual([10n, 11n]);

    // A fresh open confirms the durable state holds BOTH changes.
    const verify = await PrincipalNoteCache.open(
      await openIndexedDbPrincipalCacheStore(dbName),
      PASSPHRASE,
      testBinding(principal),
    );
    const state = await verify.load();
    expect(state.notes.map((n) => n.leafIndex).sort()).toEqual([10n, 11n]);
  });

  it("a CAS that never wins gives up with a typed conflict error", async () => {
    const h = await memoryHarness();
    const principal = PRINCIPAL_A.toText();
    const cache = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(principal));

    const liar: PrincipalCacheStore = {
      get: (p) => h.store.get(p),
      getLegacy: () => h.store.getLegacy(),
      migrateLegacy: (p, s, o) => h.store.migrateLegacy(p, s, o),
      // Simulates an always-losing race without mutating anything.
      compareAndPut: async (p) => ({ ok: false, current: await h.store.get(p) }),
    };
    const contended = await PrincipalNoteCache.open(liar, PASSPHRASE, testBinding(principal));
    await expect(contended.update(addNote(note(1n, 35)))).rejects.toBeInstanceOf(
      CacheWriteConflictError,
    );
  });
});

describe("L4 Argon2id benchmark (target-hardware signal)", () => {
  it("derives a key with the pinned parameters within an interactive-unlock budget", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
    const t0 = performance.now();
    await deriveCacheKeyV2("benchmark passphrase", salt);
    const coldMs = performance.now() - t0;
    const t1 = performance.now();
    await deriveCacheKeyV2("benchmark passphrase", salt);
    const warmMs = performance.now() - t1;
    // Signal, not a tight gate: log the numbers, fail only on something
    // pathological (the ruled params take ~0.3s on the dev machine).
    console.info(
      `[L4 benchmark] Argon2id m=64MiB t=3 p=4: cold ${coldMs.toFixed(0)}ms, warm ${warmMs.toFixed(0)}ms`,
    );
    expect(warmMs).toBeLessThan(30_000);
  });
});
