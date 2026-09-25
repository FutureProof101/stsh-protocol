// @vitest-environment jsdom
/**
 * WALLET-AUTH G1b — the verified path has ONE entry, and the UI uses it.
 *
 * WHY THIS FILE EXISTS. At G1 the floor was real, the anchor was real, and
 * AC-1 was closed — on `runVerifiedScan`, which had no caller anywhere in
 * `src/`. The route a button would actually take is the WORKER route
 * (`runScannerWorker` -> the `scanNotes` seam -> `scanAndValidateVerified` in
 * the worker -> metadata posted back), and on that route the metadata was
 * handed to an optional callback and the main thread merged the outcome with
 * `mergeScanOutcome` alone. `checkVerifiedFloor` and `advanceVerifiedFloor`
 * were never called. The notes still carried `verified: true`. So the cheapest
 * way to wire the UI would have produced verified-stamped notes with no
 * rollback protection at all, and AC-1 would have been closed on the function
 * nobody calls (SSA landed-diff F-1, MEDIUM).
 *
 * WHAT IS ASSERTED HERE is therefore deliberately NOT the floor mechanism —
 * `verified_scan_floor.test.ts` owns that. It is that the ROUTE USERS HIT
 * reaches it. The headline test below runs the same coherent rollback as
 * `verified_scan_floor.test.ts`'s "AC-1 HEADLINE", but delivers it through the
 * `scanNotes` seam, which is the seam `runScannerWorker` fills in production.
 *
 * THE SEAM IS EMULATED FAITHFULLY, not stubbed convenient: `workerSeam` runs
 * the REAL `scanAndValidateVerified` against the real harness actors and posts
 * the outcome and the metadata back through the same two fields the worker's
 * `postMessage` uses. A seam that returned a canned outcome would prove
 * nothing about the route.
 *
 * RESIDUAL, so this file does not read as more than it is: nothing here
 * constructs a real `Worker`. The boundary between `runScannerWorker` and the
 * worker module is exercised by the AC-18 tests and by the static scans in
 * `verified_scan_snapshot.test.ts`; what this file owns is everything from the
 * seam inward to the cache write.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "fake-indexeddb/auto";

import { initPoseidon } from "../src/crypto/poseidon";
import {
  VerifiedEvidenceMissingError,
  scanAndValidateVerified,
  type ScanOutcome,
} from "../src/crypto/scanner";
import {
  runVerifiedSweepViaWorker,
  type ScanWorkerInput,
} from "../src/ui/app";
// WALLET-UX: the sweep moved from the scan page to Settings > Advanced recovery;
// the component under test is the same one both pages render.
import { renderVerifiedSweep } from "../src/ui/pages/scan";
import { VERIFIED_SCAN_STRINGS } from "../src/ui/verifiedScanCopy";
import {
  ActionNotAuthorizedError,
  createAuthorizationAuthority,
} from "../src/actors/authorization";
import {
  PrincipalNoteCache,
  VerifiedFloorRollbackError,
  verifiedFloorKey,
} from "../src/storage/noteCache";
import { openIndexedDbPrincipalCacheStore } from "../src/storage/indexedDbNoteStore";
import type { AppContext } from "../src/ui/context";
import {
  BINDING,
  DENOMINATIONS,
  MASTER,
  entryOf,
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
  const store = await openIndexedDbPrincipalCacheStore(`stsh-g1b-${crypto.randomUUID()}`);
  return PrincipalNoteCache.open(store, "pw", CACHE_BINDING);
}

/** Every `ScanWorkerInput` the seam was handed, so the route's pins are checkable. */
interface SeamLog {
  requests: ScanWorkerInput[];
}

/**
 * The worker, as a function. Runs the real verified sweep and posts back the
 * same `{ outcome, verified }` pair the worker's `postMessage` carries.
 *
 * `dropEvidence` emulates the one failure this route must refuse: a reply that
 * carries the notes and loses the metadata.
 */
function workerSeam(
  actors: Awaited<ReturnType<typeof verifiedChain>>,
  log: SeamLog,
  opts: { dropEvidence?: boolean } = {},
): (input: ScanWorkerInput) => Promise<ScanOutcome> {
  return async (input) => {
    log.requests.push(input);
    const result = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER, {
      fromIndex: input.fromIndex,
      pageSize: input.pageSize,
      nowMs: () => 1_700_000_000_000,
    });
    if (result.status === "no-accepted-root") throw new Error("no accepted root");
    if (opts.dropEvidence !== true) input.onVerified?.(result.metadata);
    return result.outcome;
  };
}

function leaseFor(): ReturnType<ReturnType<typeof createAuthorizationAuthority>["mintLease"]> {
  return createAuthorizationAuthority({ now: () => 0 }).mintLease(["verifiedScan"]);
}

function sweepInput(
  actors: Awaited<ReturnType<typeof verifiedChain>>,
  cache: PrincipalNoteCache,
  log: SeamLog,
  opts: { dropEvidence?: boolean } = {},
): Parameters<typeof runVerifiedSweepViaWorker>[0] {
  return {
    scanNotes: workerSeam(actors, log, opts),
    cache,
    lease: leaseFor(),
    merkleCanisterId: BINDING.merkleCanisterId,
    nullifierCanisterId: BINDING.nullifierCanisterId,
    poolCanisterId: BINDING.poolCanisterId,
    host: "http://127.0.0.1:4943",
    vetKeySerialized: new Uint8Array(48),
    masterNoteSecret: MASTER,
    nowNs: () => 1_700_000_000_000_000_000n,
  };
}

// ── F-1: the route users hit reaches the floor ───────────────────────────────

describe("F-1 — the WORKER route goes through the one floor check", () => {
  it("F-1 HEADLINE / AC-1 via the UI route: a coherent rollback delivered through the WORKER seam is refused by the floor", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 80);
    const c1 = await makeCandidate(DENOMINATIONS[1], 81);
    const full = [entryOf(c0), entryOf(c1)];
    const cache = await openTestCache();
    const log: SeamLog = { requests: [] };

    // Sweep one, through the seam: two accepted leaves, verified.
    const honest = await verifiedChain({ acceptedEntries: full });
    const first = await runVerifiedSweepViaWorker(sweepInput(honest, cache, log));
    expect(first.metadata.accepted_leaf_count).toBe("2");
    const key = verifiedFloorKey(first.metadata.config_hash, first.metadata.security_epoch);
    expect((await cache.load()).verifiedFloors?.[key]?.highest_accepted_leaf_count).toBe("2");

    // The SAME deployment (same config_hash, same epoch) now serves a one-leaf
    // history that is perfectly self-consistent: its accepted root is the
    // honest root of its own prefix. Nothing inside a single snapshot can tell
    // this from the truth — only the floor can, and at G1 this route never
    // consulted it.
    const rolledBack = await verifiedChain({ acceptedEntries: [entryOf(c0)] });
    const err = await runVerifiedSweepViaWorker(sweepInput(rolledBack, cache, log)).catch((e) => e);
    expect(err).toBeInstanceOf(VerifiedFloorRollbackError);
    expect((err as VerifiedFloorRollbackError).observedLeafCount).toBe(1n);
    expect((err as VerifiedFloorRollbackError).floorLeafCount).toBe(2n);
    expect((err as VerifiedFloorRollbackError).sameCountDifferentRoot).toBe(false);

    // And nothing about the rollback was written: not the floor, not the
    // evidence, not the (shorter) note set.
    const after = await cache.load();
    expect(after.verifiedFloors?.[key]?.highest_accepted_leaf_count).toBe("2");
    expect(after.verifiedScan?.accepted_leaf_count).toBe("2");
    expect(after.notes).toHaveLength(2);
  });

  it("a first sweep through the seam writes the floor AND the evidence, in one update", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 82);
    const cache = await openTestCache();
    const log: SeamLog = { requests: [] };
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)], securityEpoch: 11n });

    const { state, metadata } = await runVerifiedSweepViaWorker(sweepInput(actors, cache, log));
    expect(metadata.security_epoch).toBe("11");
    expect(state.verifiedScan?.accepted_root).toBe(metadata.accepted_root);
    const key = verifiedFloorKey(metadata.config_hash, "11");
    expect(state.verifiedFloors?.[key]?.root_at_count).toBe(metadata.accepted_root);
    // The notes the route commits carry the provenance the route claims.
    expect(state.notes.every((n) => n.verified === true)).toBe(true);
  });

  it("F-1 second divergence: the route pins fromIndex to 0, whatever the caller wanted", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 83);
    const cache = await openTestCache();
    const log: SeamLog = { requests: [] };
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)] });
    await runVerifiedSweepViaWorker(sweepInput(actors, cache, log));
    expect(log.requests).toHaveLength(1);
    // A non-zero fromIndex would yield a PARTIAL note set stamped verified
    // against a FULL-prefix anchor — evidence for more than was checked.
    expect(log.requests[0].fromIndex).toBe(0n);
    expect(log.requests[0].poolCanisterId).toBe(BINDING.poolCanisterId);
  });

  it("the route draws a single-use verifiedScan token from the gesture's lease", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 84);
    const cache = await openTestCache();
    const log: SeamLog = { requests: [] };
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)] });
    await runVerifiedSweepViaWorker(sweepInput(actors, cache, log));
    expect(log.requests[0].authToken?.action).toBe("verifiedScan");

    // A lease that does not name the action cannot furnish one.
    const spendOnly = createAuthorizationAuthority({ now: () => 0 }).mintLease(["privateSpend"]);
    const err = await runVerifiedSweepViaWorker({
      ...sweepInput(actors, cache, log),
      lease: spendOnly,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(ActionNotAuthorizedError);
    // Refused before the seam was called a second time.
    expect(log.requests).toHaveLength(1);
  });

  it("a seam that resolves WITHOUT evidence is refused, and nothing is persisted", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 85);
    const cache = await openTestCache();
    const log: SeamLog = { requests: [] };
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)] });

    const err = await runVerifiedSweepViaWorker(
      sweepInput(actors, cache, log, { dropEvidence: true }),
    ).catch((e) => e);
    expect(err).toBeInstanceOf(VerifiedEvidenceMissingError);

    // The outcome's notes are stamped verified. Committing them with no
    // evidence is the floorless write this lane exists to make impossible.
    const after = await cache.load();
    expect(after.verifiedScan).toBeUndefined();
    expect(after.verifiedFloors).toBeUndefined();
    expect(after.notes).toHaveLength(0);
  });

  it("the verified request pin is in the boundary source too, not only in this seam", () => {
    // `runScannerWorker` builds the real `ScannerRequest` inside a Promise that
    // constructs a Worker, which node cannot run. This reads the shipped source
    // instead of claiming the property, and names what it is: a source scan.
    const src = readFileSync(resolve(here, "../src/ui/app.ts"), "utf8");
    expect(src).toContain("fromIndex: isVerifiedRequest ? 0n : input.fromIndex");
    // And the fail-closed evidence check on the same boundary.
    expect(src).toContain("if (isVerifiedRequest && msg.verified === undefined)");
  });
});

// ── D-6: the button, and only a button ───────────────────────────────────────

function scanCtx(over: Partial<AppContext["state"]> = {}, calls: string[] = []): AppContext {
  return {
    state: {
      scanning: false,
      busy: false,
      scanProgress: null,
      notes: [],
      quarantineTotal: 0,
      mirrorHead: null,
      verifiedScan: null,
      verifiedRollback: null,
      verifiedScanning: false,
      ...over,
    },
    scan: async () => {
      calls.push("scan");
    },
    verifiedScan: async () => {
      calls.push("verifiedScan");
    },
    resetVerifiedHistory: async (input: { confirmed: boolean }) => {
      calls.push(`reset:${input.confirmed}`);
    },
  } as unknown as AppContext;
}

function renderInto(ctx: AppContext): HTMLElement {
  const root = document.createElement("div");
  document.body.append(root);
  renderVerifiedSweep(root, ctx);
  return root;
}

describe("D-6 — the verified sweep action (Settings > Advanced recovery)", () => {
  it("offers the sweep as a user action, with the lease copy stated BEFORE the press", () => {
    const calls: string[] = [];
    const root = renderInto(scanCtx({}, calls));
    const btn = root.querySelector<HTMLButtonElement>("[data-testid=verified-sweep-button]");
    expect(btn).not.toBeNull();
    expect(root.querySelector("[data-testid=verified-sweep-lease]")?.textContent).toBe(
      VERIFIED_SCAN_STRINGS.lease,
    );
    // RENDERING TRIGGERS NOTHING. Parent §8 forbids automatic or periodic
    // verified scanning, and the way that is kept is that the only path to the
    // sweep is a click handler.
    expect(calls).toEqual([]);
    btn!.click();
    expect(calls).toEqual(["verifiedScan"]);
  });

  it("renders the observation with its residual in the same paragraph, never a badge", () => {
    const root = renderInto(
      scanCtx({
        verifiedScan: {
          config_hash: "01".repeat(32),
          accepted_root: "ab".repeat(32),
          accepted_leaf_count: "2",
          security_epoch: "7",
          spent_count: "0",
          spent_set_digest: "cd".repeat(32),
          evidence_kind: "replicated-replies",
          validated_at_ms: 1_700_000_000_000,
          freshness_budget_ms: 900_000,
        },
      }),
    );
    const text = root.querySelector("[data-testid=verified-sweep-observation]")?.textContent ?? "";
    expect(text).toBe(VERIFIED_SCAN_STRINGS.observation);
    // The two halves that make it an observation rather than a guarantee.
    expect(text).toMatch(/observation, not a guarantee/);
    expect(text).toMatch(/dishonest pool/);
    expect(root.querySelector("[data-testid=verified-sweep-evidence]")?.textContent).toContain(
      "Accepted prefix: 2 leaf/leaves",
    );
  });

  it("renders the rollback refusal and its reset, and the reset carries the user's confirmation", () => {
    const calls: string[] = [];
    const root = renderInto(
      scanCtx(
        {
          verifiedRollback: {
            configHash: "01".repeat(32),
            securityEpoch: "7",
            observedLeafCount: "1",
            floorLeafCount: "2",
            sameCountDifferentRoot: false,
          },
        },
        calls,
      ),
    );
    expect(root.querySelector("[data-testid=verified-sweep-rollback]")?.textContent).toBe(
      VERIFIED_SCAN_STRINGS.rollbackRefused,
    );
    expect(root.querySelector("[data-testid=verified-sweep-rollback-detail]")?.textContent).toBe(
      "Previously 2 accepted leaf/leaves; now 1.",
    );

    // Declining the warning does NOT reset. The wallet keeps the only record it
    // can recognise the rollback by.
    const reset = root.querySelector<HTMLButtonElement>("[data-testid=verified-sweep-reset]")!;
    const realConfirm = globalThis.confirm;
    try {
      globalThis.confirm = () => false;
      reset.click();
      expect(calls).toEqual(["reset:false"]);
      globalThis.confirm = () => true;
      reset.click();
      expect(calls).toEqual(["reset:false", "reset:true"]);
    } finally {
      globalThis.confirm = realConfirm;
    }
  });

  it("the ceiling refusal and the unavailable refusal have their own registered words", () => {
    // Mapped by TYPE in `verifiedScanMessage`; asserted here so the page's
    // three failure modes are not silently collapsed into one message.
    expect(VERIFIED_SCAN_STRINGS.treeTooLarge).toMatch(/too large for a verified sweep/);
    expect(VERIFIED_SCAN_STRINGS.treeTooLarge).toMatch(/needs a different design, not a longer wait/);
    expect(VERIFIED_SCAN_STRINGS.unavailable).toMatch(/has not recorded one/);
    expect(VERIFIED_SCAN_STRINGS.rollbackRefused).not.toBe(VERIFIED_SCAN_STRINGS.unavailable);
  });

  it("the sweep button is disabled while any scan is in flight", () => {
    for (const busyState of [{ scanning: true }, { verifiedScanning: true }, { busy: true }]) {
      const root = renderInto(scanCtx(busyState));
      const btn = root.querySelector<HTMLButtonElement>("[data-testid=verified-sweep-button]");
      expect(btn?.disabled).toBe(true);
    }
  });
});
