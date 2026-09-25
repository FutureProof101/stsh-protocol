// @vitest-environment node
/**
 * WALLET-AUTH Gate 1 — the per-deployment monotone floor.
 *
 * THE FLOOR IS WHAT CLOSES THE HEADLINE DEFECT, and the transport is not.
 * `new5_forged_scan_head.test.ts` records the case: a canister that serves a
 * SHORTER but internally consistent history — correct root for its own prefix —
 * satisfies every check the wallet can make from one snapshot. Authenticating
 * the replies does not help, because a canister signs a rollback exactly as
 * happily as it serves one. What detects it is memory: the highest accepted
 * leaf count this wallet has ever verified for this deployment, and the root
 * at it.
 *
 * WHAT THE FLOOR DOES NOT DO (SSA C-9, and it belongs in the test file because
 * this is where an over-claim would be believed): it defeats a rollback at the
 * BOUNDARY or on the NETWORK, and a canister replaying its own older state
 * under the same identity. It does NOT defeat a lying canister. A dishonest
 * pool that rotates its `config_hash`, or bumps its `security_epoch`, mints a
 * virgin floor with no history to contradict — by design, because those are
 * also exactly what a legitimate reinstall does, and the wallet cannot tell the
 * two apart from outside. That residual is PROT-8 / H-02.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "fake-indexeddb/auto";

import { initPoseidon } from "../src/crypto/poseidon";
import { runVerifiedScan, type RunVerifiedScanDeps } from "../src/crypto/scanner";
import {
  PrincipalNoteCache,
  VerifiedFloorRollbackError,
  advanceVerifiedFloor,
  checkVerifiedFloor,
  resetVerifiedHistory,
  verifiedFloorKey,
  type CachedScanState,
  type VerifiedScanMetadata,
} from "../src/storage/noteCache";
import { openIndexedDbPrincipalCacheStore } from "../src/storage/indexedDbNoteStore";
import {
  BINDING,
  DENOMINATIONS,
  MASTER,
  entryOf,
  hex,
  makeCandidate,
  verifiedChain,
} from "./helpers/verifiedScanHarness";

const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

const decryptSelf = (bytes: Uint8Array): Uint8Array | null => bytes;
const CACHE_BINDING = { principalText: "aaaaa-aa", epoch: 1, assertCurrent(): void {} };

async function openTestCache(): Promise<PrincipalNoteCache> {
  const store = await openIndexedDbPrincipalCacheStore(`stsh-floor-${crypto.randomUUID()}`);
  return PrincipalNoteCache.open(store, "pw", CACHE_BINDING);
}

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

const EMPTY: CachedScanState = { notes: [], lastScannedIndex: 0n };

// ── The mechanism, in isolation ──────────────────────────────────────────────

describe("the floor mechanism", () => {
  it("accepts a first observation, then any observation that grows", () => {
    const first = metaOf({ accepted_leaf_count: "10" });
    expect(() => checkVerifiedFloor(EMPTY, first)).not.toThrow();
    const afterFirst = advanceVerifiedFloor(EMPTY, first);
    expect(() =>
      checkVerifiedFloor(afterFirst, metaOf({ accepted_leaf_count: "11", accepted_root: "cc".repeat(32) })),
    ).not.toThrow();
  });

  it("AC-1 / AC-21: a LOWER count is refused, and the refusal says which violation it is", () => {
    const state = advanceVerifiedFloor(EMPTY, metaOf({ accepted_leaf_count: "10" }));
    const err = (() => {
      try {
        checkVerifiedFloor(state, metaOf({ accepted_leaf_count: "9" }));
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(VerifiedFloorRollbackError);
    const typed = err as VerifiedFloorRollbackError;
    expect(typed.observedLeafCount).toBe(9n);
    expect(typed.floorLeafCount).toBe(10n);
    expect(typed.sameCountDifferentRoot).toBe(false);
  });

  it("AC-21: the SAME count with a DIFFERENT root is a distinct, named violation", () => {
    const state = advanceVerifiedFloor(EMPTY, metaOf({ accepted_leaf_count: "10" }));
    const err = (() => {
      try {
        checkVerifiedFloor(state, metaOf({ accepted_leaf_count: "10", accepted_root: "ff".repeat(32) }));
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(VerifiedFloorRollbackError);
    expect((err as VerifiedFloorRollbackError).sameCountDifferentRoot).toBe(true);
  });

  it("re-observing the same head at the same root is not a rollback", () => {
    const meta = metaOf();
    const state = advanceVerifiedFloor(EMPTY, meta);
    expect(() => checkVerifiedFloor(state, meta)).not.toThrow();
  });

  it("AC-17: two config_hashes with IDENTICAL canister ids keep independent floors", () => {
    const a = metaOf({ config_hash: "01".repeat(32), accepted_leaf_count: "10" });
    const b = metaOf({ config_hash: "02".repeat(32), accepted_leaf_count: "3" });
    // The canister ids are not in the key at all; the wiring hash is.
    let state = advanceVerifiedFloor(EMPTY, a);
    expect(() => checkVerifiedFloor(state, b)).not.toThrow();
    state = advanceVerifiedFloor(state, b);

    expect(Object.keys(state.verifiedFloors ?? {})).toHaveLength(2);
    // A rollback on B leaves A's floor untouched, and vice versa.
    expect(() => checkVerifiedFloor(state, metaOf({ config_hash: "02".repeat(32), accepted_leaf_count: "2" }))).toThrow(
      VerifiedFloorRollbackError,
    );
    expect(() => checkVerifiedFloor(state, metaOf({ config_hash: "01".repeat(32), accepted_leaf_count: "11" }))).not.toThrow();
    expect(state.verifiedFloors?.[verifiedFloorKey("01".repeat(32), "7")]?.highest_accepted_leaf_count).toBe("10");
  });

  it("AC-4 / SSA C-2a: a bumped security_epoch retires the old floor with NO user action", () => {
    const state = advanceVerifiedFloor(EMPTY, metaOf({ accepted_leaf_count: "10", security_epoch: "7" }));
    // Same wiring, tree reset, epoch bumped — a legitimate reinstall.
    const afterReinstall = metaOf({ accepted_leaf_count: "1", security_epoch: "8" });
    expect(() => checkVerifiedFloor(state, afterReinstall)).not.toThrow();

    const next = advanceVerifiedFloor(state, afterReinstall);
    // The OLD floor is still there and still protects its own epoch.
    expect(Object.keys(next.verifiedFloors ?? {})).toHaveLength(2);
    expect(() => checkVerifiedFloor(next, metaOf({ accepted_leaf_count: "9", security_epoch: "7" }))).toThrow(
      VerifiedFloorRollbackError,
    );
    // And the evidence record carries the epoch that was observed.
    expect(next.verifiedScan?.security_epoch).toBe("8");
  });

  it("AC-22 / SSA C-2b: a same-epoch reinstall REFUSES, and the manual reset is the only way out", () => {
    const state = advanceVerifiedFloor(EMPTY, metaOf({ accepted_leaf_count: "10", security_epoch: "7" }));
    const afterReset1 = metaOf({ accepted_leaf_count: "1", security_epoch: "7", accepted_root: "dd".repeat(32) });

    // (a) Refusal, not a silent reset and not a permanent dead end.
    expect(() => checkVerifiedFloor(state, afterReset1)).toThrow(VerifiedFloorRollbackError);

    // (b) The user resets the verified history for THIS deployment, explicitly.
    const reset = resetVerifiedHistory(state, "01".repeat(32), "7");
    expect(reset.verifiedFloors?.[verifiedFloorKey("01".repeat(32), "7")]).toBeUndefined();
    // The evidence record for that floor is cleared with it — leaving it would
    // show the user a "verified" state backed by a floor that no longer exists.
    expect(reset.verifiedScan).toBeUndefined();

    // (c) After the reset the OLD floor is not consulted: the short history is
    //     accepted, and becomes the new floor.
    expect(() => checkVerifiedFloor(reset, afterReset1)).not.toThrow();
    const rebuilt = advanceVerifiedFloor(reset, afterReset1);
    expect(rebuilt.verifiedFloors?.[verifiedFloorKey("01".repeat(32), "7")]?.highest_accepted_leaf_count).toBe("1");
  });

  it("resetting ONE deployment does not touch another's floor", () => {
    let state = advanceVerifiedFloor(EMPTY, metaOf({ config_hash: "01".repeat(32) }));
    state = advanceVerifiedFloor(state, metaOf({ config_hash: "02".repeat(32) }));
    const reset = resetVerifiedHistory(state, "01".repeat(32), "7");
    expect(reset.verifiedFloors?.[verifiedFloorKey("02".repeat(32), "7")]).toBeDefined();
  });

  it("the floor never regresses when a LOWER-but-legal observation is recorded", () => {
    // advanceVerifiedFloor keeps the maximum. Recording an equal head must not
    // rewrite the floor downwards through some later refactor.
    const state = advanceVerifiedFloor(EMPTY, metaOf({ accepted_leaf_count: "10" }));
    const same = advanceVerifiedFloor(state, metaOf({ accepted_leaf_count: "10" }));
    expect(same.verifiedFloors?.[verifiedFloorKey("01".repeat(32), "7")]?.highest_accepted_leaf_count).toBe("10");
  });
});

// ── End to end, against the real encrypted cache ─────────────────────────────

describe("runVerifiedScan — the floor under the one atomic cache update", () => {
  async function deps(actors: Awaited<ReturnType<typeof verifiedChain>>, cache: PrincipalNoteCache): Promise<RunVerifiedScanDeps> {
    return {
      ...actors,
      binding: BINDING,
      tryDecrypt: decryptSelf,
      masterNoteSecret: MASTER,
      cache,
      nowMs: () => 1_700_000_000_000,
    };
  }

  it("AC-1 HEADLINE: a coherent rollback is DETECTED and refused", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 60);
    const c1 = await makeCandidate(DENOMINATIONS[1], 61);
    const full = [entryOf(c0), entryOf(c1)];
    const cache = await openTestCache();

    const honest = await verifiedChain({ acceptedEntries: full });
    const first = await runVerifiedScan(await deps(honest, cache));
    expect(first.status).toBe("verified");

    // The SAME deployment (same config_hash, same epoch) now serves a
    // one-leaf history that is perfectly self-consistent: its accepted root is
    // the honest root of its own prefix. Nothing inside a single snapshot can
    // tell this from the truth.
    const rolledBack = await verifiedChain({ acceptedEntries: [entryOf(c0)] });
    await expect(runVerifiedScan(await deps(rolledBack, cache))).rejects.toBeInstanceOf(
      VerifiedFloorRollbackError,
    );

    // Nothing about the rollback was written.
    const state = await cache.load();
    expect(state.verifiedScan?.accepted_leaf_count).toBe("2");
    expect(state.verifiedFloors?.[verifiedFloorKey(state.verifiedScan!.config_hash, "7")]?.highest_accepted_leaf_count).toBe("2");
  });

  it("AC-16: a sweep that dies AFTER the root match and BEFORE the digest leaves the floor unchanged", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 62);
    const c1 = await makeCandidate(DENOMINATIONS[1], 63);
    const full = [entryOf(c0), entryOf(c1)];
    const cache = await openTestCache();

    const honest = await verifiedChain({ acceptedEntries: full });
    await runVerifiedScan(await deps(honest, cache));
    const before = await cache.load();
    const key = verifiedFloorKey(before.verifiedScan!.config_hash, "7");
    expect(before.verifiedFloors?.[key]?.highest_accepted_leaf_count).toBe("2");

    // A LARGER honest history, but the spent-set download dies. The anchor has
    // already matched at this point — the failure is strictly between the root
    // match and the digest, which is the window AC-16 names.
    const c2 = await makeCandidate(DENOMINATIONS[2], 64);
    const grown = await verifiedChain({
      acceptedEntries: [...full, entryOf(c2)],
      onCall: (name) => {
        if (name === "getNullifiersPage") throw new Error("registry unreachable mid-sweep");
      },
    });
    await expect(runVerifiedScan(await deps(grown, cache))).rejects.toThrow(/registry unreachable/);

    const after = await cache.load();
    expect(after.verifiedFloors?.[key]?.highest_accepted_leaf_count).toBe("2");
    expect(after.verifiedScan?.accepted_leaf_count).toBe("2");
  });

  it("a verified scan stamps its notes verified, and records the evidence in ONE update", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 65);
    const cache = await openTestCache();
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)], securityEpoch: 11n });
    const result = await runVerifiedScan(await deps(actors, cache));
    expect(result.status).toBe("verified");

    const state = await cache.load();
    expect(state.notes).toHaveLength(1);
    expect(state.notes[0].verified).toBe(true);
    expect(state.verifiedScan?.security_epoch).toBe("11");
    expect(state.verifiedScan?.evidence_kind).toBe("replicated-replies");
    expect(state.verifiedFloors?.[verifiedFloorKey(state.verifiedScan!.config_hash, "11")]).toEqual({
      highest_accepted_leaf_count: "1",
      root_at_count: state.verifiedScan!.accepted_root,
    });
  });

  it("a pre-genesis pool reports no-accepted-root and writes NOTHING", async () => {
    const cache = await openTestCache();
    const actors = await verifiedChain({ acceptedEntries: [], acceptedLeafCount: 0n });
    await expect(runVerifiedScan(await deps(actors, cache))).resolves.toEqual({
      status: "no-accepted-root",
    });
    const state = await cache.load();
    expect(state.verifiedScan).toBeUndefined();
    expect(state.verifiedFloors).toBeUndefined();
    expect(state.notes).toHaveLength(0);
  });

  it("the floor survives a reload of the encrypted record — it is DURABLE, not session state", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 66);
    const dbName = `stsh-floor-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", CACHE_BINDING);
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)] });
    await runVerifiedScan(await deps(actors, cache));

    const store2 = await openIndexedDbPrincipalCacheStore(dbName);
    const reopened = await PrincipalNoteCache.open(store2, "pw", CACHE_BINDING);
    const state = await reopened.load();
    expect(state.verifiedFloors).toBeDefined();
    expect(hex(new Uint8Array(32).fill(0x01))).toBe(state.verifiedScan?.config_hash);
  });
});
