// @vitest-environment node
/**
 * WALLET-AUTH Gate 1 — the cache v2 → v3 bump and its one-way migration.
 *
 * TERMINOLOGY, once, because the mechanism is easy to describe wrongly (SSA
 * C-6): the note cache is AES-GCM, and what protects a record is the
 * AUTHENTICATION TAG computed over the ciphertext AND the associated data.
 * "the AAD fails" throughout this suite means the tag check fails. There is no
 * separate AAD comparison step to pass or fail; the schema version, the KDF
 * version and the owning principal are simply inside what the tag covers.
 *
 * That is also why the v2 half of AC-20 is written as a BEHAVIOURAL assertion
 * about the resulting notes rather than as a parser rejection. A v2 plaintext
 * carrying a forged `verified` flag is not malformed — a v2 record's author
 * could legitimately have written any JSON it liked. It is simply not read:
 * the v2 reader has no `verified` field, so the flag lands on the floor and
 * every migrated note comes through unverified. Asserting "it throws" would be
 * asserting a mechanism that does not exist.
 */

import { describe, expect, it } from "vitest";

import {
  CACHE_SCHEMA_V2,
  CACHE_SCHEMA_V3,
  CacheAuthenticationError,
  CacheFormatError,
  CacheSchemaDowngradeError,
  KDF_VERSION_ARGON2ID,
  PrincipalNoteCache,
  READABLE_CACHE_SCHEMAS,
  VerifiedScanFormatError,
  WRITE_CACHE_SCHEMA,
  advanceVerifiedFloor,
  cacheAad,
  deriveCacheKeyV2,
  deserializeScanStateV3,
  migrateV2StateToV3,
  noteIsVerified,
  serializeScanStateV2,
  serializeScanStateV3,
  verifiedFloorKey,
  type CachedScanState,
  type StoredCacheRecordV2,
  type VerifiedScanMetadata,
} from "../src/storage/noteCache";
import { memoryHarness, note, testBinding } from "./helpers/cacheL4";

const PRINCIPAL = "aaaaa-aa";
const PASSPHRASE = "correct horse battery staple";

function metaOf(over: Partial<VerifiedScanMetadata> = {}): VerifiedScanMetadata {
  return {
    config_hash: "01".repeat(32),
    accepted_root: "aa".repeat(32),
    accepted_leaf_count: "10",
    security_epoch: "7",
    spent_count: "0",
    spent_set_digest: "bb".repeat(32),
    evidence_kind: "replicated-replies",
    validated_at_ms: 1_700_000_000_000,
    freshness_budget_ms: 900_000,
    ...over,
  };
}

/**
 * Seal a record at schema v2, the way the PREVIOUS build did — real key, real
 * v2 AAD, real v2 serializer. Nothing in the shipping code writes v2 any more,
 * which is exactly why the fixture has to be built here: the migration is only
 * meaningful against bytes the old code would actually have produced.
 */
async function sealAtV2(
  state: CachedScanState,
  payloadOverride?: Uint8Array,
): Promise<{ record: StoredCacheRecordV2; key: CryptoKey }> {
  const salt = new Uint8Array(16).fill(0x33);
  const key = await deriveCacheKeyV2(PASSPHRASE, salt);
  const iv = new Uint8Array(12).fill(0x44);
  const aad = cacheAad(KDF_VERSION_ARGON2ID, CACHE_SCHEMA_V2, PRINCIPAL);
  const plaintext = payloadOverride ?? serializeScanStateV2(state);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
      key,
      plaintext as BufferSource,
    ),
  );
  return {
    record: { kdfVersion: KDF_VERSION_ARGON2ID, schemaVersion: CACHE_SCHEMA_V2, salt, iv, ciphertext },
    key,
  };
}

// ── The AAD binding ──────────────────────────────────────────────────────────

describe("the schema version is bound into the AAD, and v3 extends the accepted set", () => {
  it("binds 2 and 3 and nothing else", () => {
    expect(READABLE_CACHE_SCHEMAS).toEqual([CACHE_SCHEMA_V2, CACHE_SCHEMA_V3]);
    expect(() => cacheAad(KDF_VERSION_ARGON2ID, CACHE_SCHEMA_V2, PRINCIPAL)).not.toThrow();
    expect(() => cacheAad(KDF_VERSION_ARGON2ID, CACHE_SCHEMA_V3, PRINCIPAL)).not.toThrow();
    expect(() => cacheAad(KDF_VERSION_ARGON2ID, 4, PRINCIPAL)).toThrow(CacheFormatError);
    expect(() => cacheAad(KDF_VERSION_ARGON2ID, 1, PRINCIPAL)).toThrow(CacheFormatError);
  });

  it("the v2 and v3 AADs are DIFFERENT bytes — which is what forces the migration", () => {
    const v2 = cacheAad(KDF_VERSION_ARGON2ID, CACHE_SCHEMA_V2, PRINCIPAL);
    const v3 = cacheAad(KDF_VERSION_ARGON2ID, CACHE_SCHEMA_V3, PRINCIPAL);
    expect([...v2]).not.toEqual([...v3]);
  });

  it("this build writes exactly one schema, and it is v3", () => {
    expect(WRITE_CACHE_SCHEMA).toBe(CACHE_SCHEMA_V3);
  });
});

// ── AC-9 / AC-20: the migration ──────────────────────────────────────────────

describe("AC-9 — a v2 record opened by v3 code", () => {
  it("decrypts under the v2 AAD, carries the notes, and marks every one unverified", async () => {
    const harness = await memoryHarness();
    const v2state: CachedScanState = {
      notes: [note(0n, 1), note(1n, 5)],
      lastScannedIndex: 2n,
      mirrorHead: { leafCount: 2n, root: new Uint8Array(32).fill(0x09) },
    };
    const { record } = await sealAtV2(v2state);
    await harness.writeSlot(PRINCIPAL, { revision: 1, record });

    const cache = await PrincipalNoteCache.open(
      harness.store,
      PASSPHRASE,
      testBinding(PRINCIPAL, 1),
    );
    const state = await cache.load();

    // Lossless in everything except verification status.
    expect(state.notes.map((n) => n.leafIndex)).toEqual([0n, 1n]);
    expect(state.lastScannedIndex).toBe(2n);
    expect(state.mirrorHead?.leafCount).toBe(2n);
    // The point of the migration.
    expect(state.notes.every((n) => !noteIsVerified(n))).toBe(true);
    expect(state.verifiedScan).toBeUndefined();
    expect(state.verifiedFloors).toBeUndefined();
    expect(state.migratedFromV2).toBe(true);
  });

  it("AC-20 (v2 half, SSA C-6): a forged `verified` flag in a v2 plaintext imports UNVERIFIED", async () => {
    const harness = await memoryHarness();
    // Hand-built v2 JSON with the flag the v2 writer never emitted.
    const forged = JSON.parse(
      new TextDecoder().decode(serializeScanStateV2({ notes: [note(0n, 3)], lastScannedIndex: 1n })),
    );
    forged.notes[0].verified = true;
    forged.verifiedScan = metaOf();
    forged.verifiedFloors = { [verifiedFloorKey("01".repeat(32), "7")]: { highest_accepted_leaf_count: "99", root_at_count: "aa".repeat(32) } };
    const bytes = new TextEncoder().encode(JSON.stringify(forged));

    const { record } = await sealAtV2({ notes: [], lastScannedIndex: 0n }, bytes);
    await harness.writeSlot(PRINCIPAL, { revision: 1, record });

    const cache = await PrincipalNoteCache.open(harness.store, PASSPHRASE, testBinding(PRINCIPAL, 1));
    const state = await cache.load();

    // The assertion is on the resulting NOTE STATE, not on a parser rejection.
    expect(state.notes).toHaveLength(1);
    expect(noteIsVerified(state.notes[0])).toBe(false);
    // And the forged floor did not become this wallet's floor, which is the
    // consequence that would actually have mattered: a 99-leaf floor injected
    // from a blob would refuse every honest scan of a smaller real tree.
    expect(state.verifiedFloors).toBeUndefined();
    expect(state.verifiedScan).toBeUndefined();
  });

  it("migrateV2StateToV3 is pure and strips verification, leaving everything else alone", () => {
    const before: CachedScanState = {
      notes: [{ ...note(0n, 1), verified: true }],
      lastScannedIndex: 4n,
      shieldJournal: { entries: [], approval: null },
    };
    const after = migrateV2StateToV3(before);
    expect(after.notes[0].verified).toBeUndefined();
    expect(after.lastScannedIndex).toBe(4n);
    expect(after.shieldJournal).toEqual({ entries: [], approval: null });
    expect(after.migratedFromV2).toBe(true);
    // Pure: the input is untouched.
    expect(before.notes[0].verified).toBe(true);
  });
});

// ── AC-10: a v3 record whose metadata was edited ─────────────────────────────

describe("AC-10 — a v3 record with corrupted verifiedScan metadata", () => {
  it("fails the AES-GCM tag check and is rejected outright", async () => {
    const harness = await memoryHarness();
    const cache = await PrincipalNoteCache.open(harness.store, PASSPHRASE, testBinding(PRINCIPAL, 1));
    await cache.update((s) => advanceVerifiedFloor({ ...s, notes: [note(0n, 2)] }, metaOf()));

    const slot = await harness.readSlot(PRINCIPAL);
    expect(slot?.record.schemaVersion).toBe(CACHE_SCHEMA_V3);
    // Flip one ciphertext byte. There is no "edit the metadata" that is not
    // this: the metadata lives inside the authenticated ciphertext.
    const tampered = Uint8Array.from(slot!.record.ciphertext);
    tampered[tampered.length - 20] ^= 0x01;
    await harness.writeSlot(PRINCIPAL, {
      revision: 2,
      record: { ...slot!.record, ciphertext: tampered },
    });

    await expect(cache.load()).rejects.toBeInstanceOf(CacheAuthenticationError);
  });

  it("a structurally invalid verifiedScan is rejected at parse, not normalised", () => {
    const bad = serializeScanStateV3({
      notes: [],
      lastScannedIndex: 0n,
      verifiedScan: { ...metaOf(), accepted_root: "short" },
    });
    expect(() => deserializeScanStateV3(bad)).toThrow(VerifiedScanFormatError);

    const forgedProvenance = serializeScanStateV3({
      notes: [],
      lastScannedIndex: 0n,
      verifiedScan: { ...metaOf(), evidence_kind: "certified" as unknown as "replicated-replies" },
    });
    expect(() => deserializeScanStateV3(forgedProvenance)).toThrow(VerifiedScanFormatError);
  });

  it("v3 round-trips the verified fields and the note flag", () => {
    const state: CachedScanState = {
      notes: [{ ...note(0n, 1), verified: true }, note(1n, 2)],
      lastScannedIndex: 2n,
      verifiedScan: metaOf(),
      verifiedFloors: { [verifiedFloorKey("01".repeat(32), "7")]: { highest_accepted_leaf_count: "10", root_at_count: "aa".repeat(32) } },
    };
    const back = deserializeScanStateV3(serializeScanStateV3(state));
    expect(back.notes[0].verified).toBe(true);
    expect(back.notes[1].verified).toBeUndefined();
    expect(back.verifiedScan).toEqual(metaOf());
    expect(back.verifiedFloors).toEqual(state.verifiedFloors);
  });

  it("the v2 serializer refuses to emit v3 fields, so a v2 payload can never carry them", () => {
    const payload = JSON.parse(
      new TextDecoder().decode(
        serializeScanStateV2({
          notes: [{ ...note(0n, 1), verified: true }],
          lastScannedIndex: 1n,
          verifiedScan: metaOf(),
        }),
      ),
    );
    expect(payload.v).toBe(CACHE_SCHEMA_V2);
    expect(payload.notes[0].verified).toBeUndefined();
    expect(payload.verifiedScan).toBeUndefined();
  });
});

// ── AC-23: the migration is one-way ──────────────────────────────────────────

describe("AC-23 / SSA C-7 — a v2 blob replayed after a v3 write is refused", () => {
  it("refuses the replay and leaves the floor exactly where it was", async () => {
    const harness = await memoryHarness();
    const cache = await PrincipalNoteCache.open(harness.store, PASSPHRASE, testBinding(PRINCIPAL, 1));
    await cache.update((s) => advanceVerifiedFloor({ ...s, notes: [note(0n, 2)] }, metaOf()));

    const v3slot = await harness.readSlot(PRINCIPAL);
    const key = verifiedFloorKey("01".repeat(32), "7");
    expect((await cache.load()).verifiedFloors?.[key]?.highest_accepted_leaf_count).toBe("10");

    // The attacker restores a superseded v2 blob for this principal. Migrating
    // it again would produce a record with NO floors, which is the outcome the
    // one-way rule exists to refuse.
    const { record: v2record } = await sealAtV2({ notes: [note(0n, 2)], lastScannedIndex: 1n });
    await harness.writeSlot(PRINCIPAL, { revision: 3, record: v2record });

    await expect(cache.load()).rejects.toBeInstanceOf(CacheSchemaDowngradeError);
    await expect(cache.update((s) => s)).rejects.toBeInstanceOf(CacheSchemaDowngradeError);

    // Nothing the refusal touched: the v2 blob is still sitting there, unread
    // and unmigrated, and no floor was rewritten in either direction.
    const still = await harness.readSlot(PRINCIPAL);
    expect(still?.record.schemaVersion).toBe(CACHE_SCHEMA_V2);
    expect(v3slot?.record.schemaVersion).toBe(CACHE_SCHEMA_V3);
  });

  it("a FIRST open at v2 still migrates — the rule is one-way, not v2-hostile", async () => {
    const harness = await memoryHarness();
    const { record } = await sealAtV2({ notes: [note(0n, 2)], lastScannedIndex: 1n });
    await harness.writeSlot(PRINCIPAL, { revision: 1, record });
    const cache = await PrincipalNoteCache.open(harness.store, PASSPHRASE, testBinding(PRINCIPAL, 1));
    const state = await cache.load();
    expect(state.notes).toHaveLength(1);
    expect(state.migratedFromV2).toBe(true);
  });

  it("the first WRITE after a v2 open re-seals at v3", async () => {
    const harness = await memoryHarness();
    const { record } = await sealAtV2({ notes: [note(0n, 2)], lastScannedIndex: 1n });
    await harness.writeSlot(PRINCIPAL, { revision: 1, record });
    const cache = await PrincipalNoteCache.open(harness.store, PASSPHRASE, testBinding(PRINCIPAL, 1));
    await cache.update((s) => ({ ...s, lastScannedIndex: 5n }));
    const slot = await harness.readSlot(PRINCIPAL);
    expect(slot?.record.schemaVersion).toBe(CACHE_SCHEMA_V3);
  });
});
