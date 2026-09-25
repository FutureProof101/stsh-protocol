/**
 * L4 gate tests — Argon2id KDF (pinned params + cross-check vector), v2
 * principal-scoped AAD-bound records, and the open()-time migration decision:
 * empty-legacy migrate (fresh salt+IV, singleton deleted, cursor reset),
 * legacy-with-notes typed stop (record untouched), wrong passphrase v1/v2
 * throwing AT open() (S-4/S-10), principal scoping (S-13), AAD tamper /
 * kdfVersion downgrade rejection, atomic write-failure, and the S-3
 * persisted-material audit.
 *
 * Migration/scoping suites run against BOTH the in-memory store and the REAL
 * IndexedDB implementation (fake-indexeddb), like the AC-1 journal tests.
 */

import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { argon2id } from "hash-wasm";
import { Ed25519KeyIdentity } from "@dfinity/identity";

import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_KEY_BYTES,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTES,
  CACHE_SCHEMA_V3,
  CacheAuthenticationError,
  CacheFormatError,
  KDF_VERSION_ARGON2ID,
  LegacyNoteFormatUnsupportedError,
  PrincipalNoteCache,
  deriveCacheKey,
  deriveCacheKeyV2,
  deserializeScanState,
  type CachedScanState,
  type PrincipalCacheStore,
} from "../src/storage/noteCache";
import {
  addNote,
  bytesToHex,
  idbHarness,
  memoryHarness,
  note,
  testBinding,
  type CacheHarness,
} from "./helpers/cacheL4";

const PRINCIPAL_A = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(1))
  .getPrincipal()
  .toText();
const PRINCIPAL_B = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(2))
  .getPrincipal()
  .toText();

const PASSPHRASE = "correct horse battery staple";

/**
 * Argon2id(m=65536 KiB, t=3, p=4, len=32) of PASSPHRASE with salt 00..0f —
 * computed with hash-wasm 4.12.0 at pin time. Pins BOTH the parameter set and
 * the library behavior: any silent parameter change breaks this vector.
 */
const ARGON2ID_PINNED_VECTOR =
  "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e";

function emptyState(lastScannedIndex = 0n): CachedScanState {
  return { notes: [], lastScannedIndex };
}

function stateWithNotes(): CachedScanState {
  return { notes: [note(7n, 40)], lastScannedIndex: 8n };
}

describe("L4 KDF — Argon2id pinned parameters", () => {
  it("parameters are the ruled m=65536 KiB, t=3, p=4, 32-byte key, 16-byte salt", () => {
    expect(ARGON2ID_MEMORY_KIB).toBe(65536);
    expect(ARGON2ID_ITERATIONS).toBe(3);
    expect(ARGON2ID_PARALLELISM).toBe(4);
    expect(ARGON2ID_KEY_BYTES).toBe(32);
    expect(ARGON2ID_SALT_BYTES).toBe(16);
  });

  it("derivation is deterministic and matches the pinned vector", async () => {
    const salt = Uint8Array.from({ length: 16 }, (_, i) => i);
    const run = () =>
      argon2id({
        password: PASSPHRASE,
        salt,
        memorySize: ARGON2ID_MEMORY_KIB,
        iterations: ARGON2ID_ITERATIONS,
        parallelism: ARGON2ID_PARALLELISM,
        hashLength: ARGON2ID_KEY_BYTES,
        outputType: "hex",
      });
    const first = await run();
    const second = await run();
    expect(first).toBe(ARGON2ID_PINNED_VECTOR);
    expect(second).toBe(ARGON2ID_PINNED_VECTOR);
  });

  it("rejects a wrong-length salt before deriving", async () => {
    await expect(deriveCacheKeyV2("x", new Uint8Array(15))).rejects.toBeInstanceOf(
      CacheFormatError,
    );
  });
});

const HARNESSES: Array<[string, () => Promise<CacheHarness>]> = [
  ["in-memory", memoryHarness],
  ["real IndexedDB", idbHarness],
];

describe.each(HARNESSES)("L4 migration + scoping (%s store)", (_label, makeHarness) => {
  it("fresh open creates an empty v3 record and round-trips notes", async () => {
    const h = await makeHarness();
    const cache = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    expect(await cache.load()).toEqual(emptyState());

    const added = note(3n, 10);
    await cache.update(addNote(added));

    const slot = await h.readSlot(PRINCIPAL_A);
    expect(slot).not.toBeNull();
    expect(slot!.revision).toBe(2); // 1 create + 1 update
    expect(slot!.record.kdfVersion).toBe(KDF_VERSION_ARGON2ID);
    // WALLET-AUTH Gate 1: a FRESH record is minted at v3, not v2. The KDF
    // version is a separate concept and does NOT move with the schema (L4 rule
    // 3 — kdfVersion, SerializedState.v and the note payload version stay
    // independent), which is why only the second assertion changes here.
    // v2 remains READABLE; `cache_v3_migration.test.ts` covers that path.
    expect(slot!.record.schemaVersion).toBe(CACHE_SCHEMA_V3);
    expect(slot!.record.salt.length).toBe(ARGON2ID_SALT_BYTES);
    expect(slot!.record.iv.length).toBe(12);

    // A second open (same principal + passphrase) decrypts the same state.
    const reopened = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    const state = await reopened.load();
    expect(state.notes).toHaveLength(1);
    expect(state.notes[0].leafIndex).toBe(3n);
    expect(state.notes[0].value).toBe(100n);
    expect([...state.notes[0].rho]).toEqual([...added.rho]);
    expect(state.lastScannedIndex).toBe(4n);
  });

  it("empty legacy singleton migrates: fresh salt+IV, singleton deleted, cursor reset", async () => {
    const h = await makeHarness();
    // Legacy empty record with a non-zero cursor: the cursor must NOT carry
    // over (the unscoped singleton has no owner — an inherited cursor could
    // skip this principal's notes).
    const legacy = await h.seedLegacy(PASSPHRASE, emptyState(42n));

    const cache = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));

    expect(await h.readLegacy()).toBeNull(); // singleton deleted
    const slot = await h.readSlot(PRINCIPAL_A);
    expect(slot).not.toBeNull();
    expect(slot!.record.kdfVersion).toBe(KDF_VERSION_ARGON2ID);
    expect(bytesToHex(slot!.record.salt)).not.toBe(bytesToHex(legacy.salt)); // fresh salt
    expect(bytesToHex(slot!.record.iv)).not.toBe(bytesToHex(legacy.iv)); // fresh IV
    expect(await cache.load()).toEqual(emptyState(0n)); // cursor reset
  });

  it("legacy singleton WITH notes: typed stop, record byte-untouched, nothing claimed", async () => {
    const h = await makeHarness();
    const before = await h.seedLegacy(PASSPHRASE, stateWithNotes());

    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(LegacyNoteFormatUnsupportedError);
    // A second principal fares no better — the singleton is never first-claimed.
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_B)),
    ).rejects.toBeInstanceOf(LegacyNoteFormatUnsupportedError);

    const after = await h.readLegacy();
    expect(after).not.toBeNull();
    expect(bytesToHex(after!.salt)).toBe(bytesToHex(before.salt));
    expect(bytesToHex(after!.iv)).toBe(bytesToHex(before.iv));
    expect(bytesToHex(after!.ciphertext)).toBe(bytesToHex(before.ciphertext));
    expect(await h.readSlot(PRINCIPAL_A)).toBeNull();
    expect(await h.readSlot(PRINCIPAL_B)).toBeNull();
  });

  it("wrong passphrase on a LEGACY record throws at open() and migrates nothing (S-10)", async () => {
    const h = await makeHarness();
    const before = await h.seedLegacy(PASSPHRASE, emptyState(5n));

    const failure = await PrincipalNoteCache.open(
      h.store,
      "not the passphrase",
      testBinding(PRINCIPAL_A),
    ).then(
      () => null,
      (e: unknown) => e,
    );
    expect(failure).not.toBeNull();
    // The propagated decrypt failure — NOT the typed migration stop, and NOT
    // a silent empty cache.
    expect(failure).not.toBeInstanceOf(LegacyNoteFormatUnsupportedError);

    expect(await h.readSlot(PRINCIPAL_A)).toBeNull(); // no migration happened
    const after = await h.readLegacy();
    expect(bytesToHex(after!.ciphertext)).toBe(bytesToHex(before.ciphertext)); // untouched
  });

  it("a note written into the singleton MID-MIGRATION is never dropped (L-2 regression)", async () => {
    const h = await makeHarness();
    await h.seedLegacy(PASSPHRASE, emptyState(0n));

    // Simulate an old-wallet tab saving a REAL note into the singleton inside
    // the check->migrate window: the wrapper injects the write right before
    // the migration transaction runs. The in-transaction byte-identity check
    // must abort the migration — never overwrite.
    let interleaved = false;
    const racingStore: PrincipalCacheStore = {
      get: (p) => h.store.get(p),
      getLegacy: () => h.store.getLegacy(),
      compareAndPut: (p, e, s) => h.store.compareAndPut(p, e, s),
      migrateLegacy: async (p, s, observed) => {
        if (!interleaved) {
          interleaved = true;
          await h.seedLegacy(PASSPHRASE, stateWithNotes()); // the old tab's write
        }
        return h.store.migrateLegacy(p, s, observed);
      },
    };

    await expect(
      PrincipalNoteCache.open(racingStore, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(LegacyNoteFormatUnsupportedError);

    // Zero notes dropped: no scoped record was created, the singleton is
    // intact, and it still decrypts to the interleaved note.
    expect(await h.readSlot(PRINCIPAL_A)).toBeNull();
    const legacy = await h.readLegacy();
    expect(legacy).not.toBeNull();
    const key = await deriveCacheKey(PASSPHRASE, legacy!.salt);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: legacy!.iv as BufferSource },
      key,
      legacy!.ciphertext as BufferSource,
    );
    const state = deserializeScanState(new Uint8Array(plain));
    expect(state.notes).toHaveLength(1);
    expect(state.notes[0].leafIndex).toBe(7n);
  });

  it("wrong passphrase on a v2 record throws at open() (S-4)", async () => {
    const h = await makeHarness();
    await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    await expect(
      PrincipalNoteCache.open(h.store, "not the passphrase", testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(CacheAuthenticationError);
  });

  it("principal scoping: B gets a fresh cache and never sees A's notes (S-13)", async () => {
    const h = await makeHarness();
    const cacheA = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    await cacheA.update(addNote(note(1n, 20)));

    // SAME passphrase on purpose: isolation must come from principal scoping
    // and AAD, not from the passphrase differing.
    const cacheB = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_B));
    expect(await cacheB.load()).toEqual(emptyState());
    await cacheB.update(addNote(note(9n, 30)));

    const stateA = await cacheA.load();
    expect(stateA.notes).toHaveLength(1);
    expect(stateA.notes[0].leafIndex).toBe(1n);
    const slotA = await h.readSlot(PRINCIPAL_A);
    const slotB = await h.readSlot(PRINCIPAL_B);
    expect(slotA).not.toBeNull();
    expect(slotB).not.toBeNull();
    expect(bytesToHex(slotA!.record.ciphertext)).not.toBe(bytesToHex(slotB!.record.ciphertext));
  });
});

describe("L4 AAD binding + tamper rejection", () => {
  async function seededHarness() {
    const h = await memoryHarness();
    const cache = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    await cache.update(addNote(note(2n, 50)));
    return h;
  }

  it("a record copied into another principal's slot fails authentication (AAD binds principal)", async () => {
    const h = await seededHarness();
    const slotA = await h.readSlot(PRINCIPAL_A);
    await h.writeSlot(PRINCIPAL_B, slotA!);
    // Same passphrase AND same salt -> same key. Decryption must still fail:
    // only the AAD principal binding distinguishes the records.
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_B)),
    ).rejects.toBeInstanceOf(CacheAuthenticationError);
  });

  it("a stored kdfVersion downgraded to 1 is rejected, never routed to PBKDF2", async () => {
    const h = await seededHarness();
    const slot = await h.readSlot(PRINCIPAL_A);
    slot!.record.kdfVersion = 1;
    await h.writeSlot(PRINCIPAL_A, slot!);
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(CacheFormatError);
  });

  it("an unknown future kdfVersion is rejected before any crypto", async () => {
    const h = await seededHarness();
    const slot = await h.readSlot(PRINCIPAL_A);
    slot!.record.kdfVersion = 3;
    await h.writeSlot(PRINCIPAL_A, slot!);
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(CacheFormatError);
  });

  it("an unknown schemaVersion is rejected before any crypto", async () => {
    const h = await seededHarness();
    const slot = await h.readSlot(PRINCIPAL_A);
    slot!.record.schemaVersion = 1;
    await h.writeSlot(PRINCIPAL_A, slot!);
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(CacheFormatError);
  });

  it("a flipped ciphertext byte fails authentication", async () => {
    const h = await seededHarness();
    const slot = await h.readSlot(PRINCIPAL_A);
    slot!.record.ciphertext[0] ^= 0x01;
    await h.writeSlot(PRINCIPAL_A, slot!);
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(CacheAuthenticationError);
  });

  it("a flipped IV byte fails authentication", async () => {
    const h = await seededHarness();
    const slot = await h.readSlot(PRINCIPAL_A);
    slot!.record.iv[0] ^= 0x01;
    await h.writeSlot(PRINCIPAL_A, slot!);
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toBeInstanceOf(CacheAuthenticationError);
  });
});

describe("L4 atomic write failure keeps prior state", () => {
  it("a failing update write leaves the previous record and revision intact", async () => {
    const h = await memoryHarness();
    const cache = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    await cache.update(addNote(note(1n, 60)));
    const before = await h.readSlot(PRINCIPAL_A);

    h.failNextWrite!();
    await expect(cache.update(addNote(note(2n, 61)))).rejects.toThrow("injected write failure");

    const after = await h.readSlot(PRINCIPAL_A);
    expect(after!.revision).toBe(before!.revision);
    expect(bytesToHex(after!.record.ciphertext)).toBe(bytesToHex(before!.record.ciphertext));
    const state = await cache.load();
    expect(state.notes).toHaveLength(1); // only the first note
  });

  it("a failing create leaves no partial record", async () => {
    const h = await memoryHarness();
    h.failNextWrite!();
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toThrow("injected write failure");
    expect(await h.readSlot(PRINCIPAL_A)).toBeNull();
  });

  it("a failing migration leaves the legacy singleton in place and no scoped record", async () => {
    const h = await memoryHarness();
    await h.seedLegacy(PASSPHRASE, emptyState());
    h.failNextWrite!();
    await expect(
      PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A)),
    ).rejects.toThrow("injected write failure");
    expect(await h.readLegacy()).not.toBeNull();
    expect(await h.readSlot(PRINCIPAL_A)).toBeNull();
  });
});

describe("L4 S-3 — persisted material audit", () => {
  it("stores only opaque records: no passphrase, no key material, no extra fields", async () => {
    const h = await memoryHarness();
    await h.seedLegacy(PASSPHRASE, emptyState(3n)); // gets migrated below
    const cache = await PrincipalNoteCache.open(h.store, PASSPHRASE, testBinding(PRINCIPAL_A));
    await cache.update(addNote(note(1n, 70)));

    const values = await h.allValues();
    expect(values.length).toBeGreaterThan(0);
    const passphraseBytes = new TextEncoder().encode(PASSPHRASE);

    const containsSubsequence = (haystack: Uint8Array, needle: Uint8Array): boolean => {
      outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
        for (let j = 0; j < needle.length; j += 1) {
          if (haystack[i + j] !== needle[j]) continue outer;
        }
        return true;
      }
      return false;
    };

    for (const value of values) {
      const slot = value as { revision: number; record: Record<string, unknown> };
      expect(Object.keys(slot).sort()).toEqual(["record", "revision"]);
      expect(Object.keys(slot.record).sort()).toEqual([
        "ciphertext",
        "iv",
        "kdfVersion",
        "salt",
        "schemaVersion",
      ]);
      for (const field of ["salt", "iv", "ciphertext"] as const) {
        const bytes = slot.record[field] as Uint8Array;
        // structuredClone under jsdom yields another realm's Uint8Array, so
        // instanceof would false-negative; isView is cross-realm safe.
        expect(ArrayBuffer.isView(bytes)).toBe(true);
        expect(containsSubsequence(bytes, passphraseBytes)).toBe(false);
      }
      // No CryptoKey (or anything non-clonable-opaque) ever reaches storage.
      expect(JSON.stringify(slot)).not.toContain(PASSPHRASE);
    }
  });
});
