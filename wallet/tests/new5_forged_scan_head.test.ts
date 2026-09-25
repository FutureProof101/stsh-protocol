// @vitest-environment node
/**
 * NEW-5 (HARDEN-01, lane TEST-T1 §3.4) — the merkle canister is UNTRUSTED.
 *
 * WHY THIS SUITE EXISTS. `get_scan_head` serves UNCERTIFIED data today:
 * `canisters/merkle-tree/src/lib.rs:14` records "get_root_at_height returns IC
 * certified data response (TODO: M2)" and the `set_certified_data` call at
 * :271-272 is commented out ("TODO: M2 — enables certified queries").
 * Certification is PROT-8 and is deferred with a trigger, so the wallet's ONLY
 * compensating control is the local mirror: it re-derives the Merkle root from
 * the downloaded leaves and refuses any scan whose mirror root does not equal
 * the head root (`wallet/src/crypto/scanner.ts`, scanAndValidateOnce — "local
 * mirror root does not match the atomic get_scan_head root").
 *
 * The external-review triage asked the adversarial question directly: can a
 * lying merkle canister steer this wallet? These tests answer it by serving
 * DELIBERATELY FORGED head/page combinations and asserting the wallet fails
 * closed, persists nothing, and hands nothing spend-eligible onward.
 *
 * Relationship to the existing suites (brief §2 invariant 3 — extend, do not
 * duplicate): `scanner.test.ts` already covers a single tampered page leaf and
 * the page-SHAPE rules (density, over-length, out-of-snapshot index, leaf
 * length). Nothing there forges the HEAD, forges a page into a *well-formed
 * attacker note*, or asserts the spend-side consequence. Those are the four
 * outcomes below. No existing test is modified, renamed or weakened.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "fake-indexeddb/auto";

import { initPoseidon } from "../src/crypto/poseidon";
import {
  DENOMINATIONS,
  createShieldNote,
  deriveNoteSecretsV2,
  merkleLeaf,
  noteToBytesV2,
  type Note,
} from "../src/crypto/notes";
import {
  LocalMerkleMirror,
  ctEqual,
  runScan,
  runVerifiedScan,
  scanAndValidate,
  syncMirror,
  type ScanActors,
} from "../src/crypto/scanner";
import type { ScanPageEntry } from "../src/actors/merkle";
import {
  PrincipalNoteCache,
  VerifiedFloorRollbackError,
  spendableNotes,
  verifiedFloorKey,
} from "../src/storage/noteCache";
import {
  BINDING as DEPLOYMENT_BINDING,
  verifiedChain,
} from "./helpers/verifiedScanHarness";
import { openIndexedDbPrincipalCacheStore } from "../src/storage/indexedDbNoteStore";

const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

const MASTER = new Uint8Array(32).fill(0x11);
/** A second wallet's master secret — the "attacker" whose notes we are NOT. */
const OTHER_MASTER = new Uint8Array(32).fill(0x77);
const BINDING = { principalText: "aaaaa-aa", epoch: 1, assertCurrent(): void {} };

// ── Candidate factory (REAL note crypto, same shape as scanner.test.ts) ───────

interface Candidate {
  note: Note;
  plaintext: Uint8Array;
  leaf: Uint8Array;
}

async function makeCandidate(
  value: bigint,
  nonceSeed: number,
  master: Uint8Array = MASTER,
): Promise<Candidate> {
  const nonce = new Uint8Array(16).fill(nonceSeed);
  const secrets = await deriveNoteSecretsV2(master, nonce);
  const note = await createShieldNote(value, secrets);
  return { note, plaintext: noteToBytesV2(note, nonce), leaf: await merkleLeaf(value, note.commitment) };
}

interface Entry {
  payload: Uint8Array;
  leaf: Uint8Array;
}

function entryOf(c: Candidate): Entry {
  return { payload: c.plaintext, leaf: c.leaf };
}

async function rootOf(entries: Entry[]): Promise<Uint8Array> {
  const m = new LocalMerkleMirror();
  entries.forEach((e, i) => m.addLeaf(BigInt(i), e.leaf));
  return m.root(BigInt(entries.length));
}

/**
 * A merkle canister that answers HEAD and PAGES from two INDEPENDENT sources,
 * so a test can make them disagree in exactly one way. `headEntries` decides
 * what the head claims (leafCount + honest root over those leaves, unless
 * `headRoot` overrides); `pageEntries` decides what get_scan_page actually
 * serves. An honest canister is the case headEntries === pageEntries.
 */
async function forgeableChain(opts: {
  headEntries: Entry[];
  pageEntries: Entry[];
  headRoot?: Uint8Array;
  headLeafCount?: bigint;
  spent?: Uint8Array[];
}): Promise<ScanActors> {
  const headRoot = opts.headRoot ?? (await rootOf(opts.headEntries));
  const headLeafCount = opts.headLeafCount ?? BigInt(opts.headEntries.length);
  const spent = opts.spent ?? [];
  return {
    async getScanHead() {
      return { leafCount: headLeafCount, root: headRoot };
    },
    async getScanPage(from: bigint, limit: bigint): Promise<ScanPageEntry[]> {
      return opts.pageEntries
        .slice(Number(from), Number(from) + Number(limit))
        .map((e, i) => ({ index: from + BigInt(i), leaf: e.leaf, encryptedPayload: e.payload }));
    },
    async getNullifiersPage(startAfter: Uint8Array | null, limit: bigint) {
      const sorted = [...spent].sort((a, b) => {
        for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
        return 0;
      });
      let idx = 0;
      if (startAfter !== null) {
        idx = sorted.findIndex((v) => {
          for (let i = 0; i < 32; i++) if (v[i] !== startAfter[i]) return v[i] > startAfter[i];
          return false;
        });
        if (idx === -1) idx = sorted.length;
      }
      return sorted.slice(idx, idx + Number(limit));
    },
    async count() {
      return BigInt(spent.length);
    },
  };
}

const decryptSelf = (bytes: Uint8Array): Uint8Array | null => bytes;

async function openTestCache(dbName: string): Promise<PrincipalNoteCache> {
  const store = await openIndexedDbPrincipalCacheStore(dbName);
  return PrincipalNoteCache.open(store, "pw", BINDING);
}

/** The value `spendFlow.ts:346-352` compares before it will build a witness:
 * the root the mirror re-derives from the served pages, and the root the head
 * claims. Returns whether they agree. This computes the flow's INPUT from the
 * real `syncMirror`; it deliberately does not restate the flow's decision —
 * that half is drift-locked against the source below. */
async function spendSideMirrorAgrees(actors: ScanActors): Promise<boolean> {
  const { head, mirror } = await syncMirror(actors);
  return ctEqual(await mirror.root(head.leafCount), head.root);
}

// ── §3.4(1) forged head ───────────────────────────────────────────────────────

describe("NEW-5 §3.4(1) — a forged HEAD the pages cannot reconstruct fails closed", () => {
  it("a head root the honest pages do not hash to is rejected; nothing is persisted and no scan is reported complete", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 21);
    const honest = [entryOf(c)];
    const lie = await rootOf(honest);
    lie[0] ^= 0x01; // one bit — the canister claims a tree it cannot show us
    const actors = await forgeableChain({ headEntries: honest, pageEntries: honest, headRoot: lie });

    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /local mirror root does not match/,
    );

    // Fail-closed means fail-closed: runScan throws, so the caller never
    // receives a CachedScanState and the UI is never told the scan completed.
    const cache = await openTestCache(`stsh-new5-${crypto.randomUUID()}`);
    await expect(
      runScan({ ...actors, tryDecrypt: decryptSelf, masterNoteSecret: MASTER, cache }),
    ).rejects.toThrow(/local mirror root does not match/);
    const after = await cache.load();
    expect(after.notes).toHaveLength(0);
    expect(after.mirrorHead).toBeUndefined();
    expect(after.lastScannedIndex).toBe(0n);
  });

  it("a head claiming MORE leaves than the canister will serve is rejected (withheld pages)", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 22);
    const c1 = await makeCandidate(DENOMINATIONS[1], 23);
    const full = [entryOf(c0), entryOf(c1)];
    // Head advertises the full two-leaf tree; pages serve only leaf 0.
    const actors = await forgeableChain({ headEntries: full, pageEntries: [entryOf(c0)] });

    // Fails closed one step EARLIER than the root comparison: the mirror knows
    // it never received leaf 1 and refuses to hash a hole. Asserted on the
    // message so a future change that silently substitutes a zero value for a
    // withheld leaf — and then matches a forged root — is visible here.
    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /local mirror is incomplete: leaf 1 missing \(of 2\)/,
    );
  });

  it("a head claiming FEWER leaves than the pages describe truncates the snapshot and is rejected", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 24);
    const c1 = await makeCandidate(DENOMINATIONS[1], 25);
    const full = [entryOf(c0), entryOf(c1)];
    // The head root is the honest TWO-leaf root, but leafCount says one: the
    // sweep can only ever download leaf 0, so the mirror cannot reach it.
    const actors = await forgeableChain({
      headEntries: full,
      pageEntries: full,
      headLeafCount: 1n,
    });

    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /local mirror root does not match/,
    );
  });
});

// ── §3.4(2) forged pages ──────────────────────────────────────────────────────

describe("NEW-5 §3.4(2) — PAGES inconsistent with an honest head are rejected by the mirror", () => {
  it("a substituted commitment that is a WELL-FORMED note for us is still refused — an attacker cannot mint us balance", async () => {
    // The honest tree holds one leaf. The canister serves a DIFFERENT leaf that
    // decrypts for this wallet and passes EVERY per-candidate check (v2 parse,
    // constant-time field compare, leaf recompute against the served page
    // leaf). Only the mirror root stops it. This is the case that distinguishes
    // "the page is garbage" from "the page is a plausible gift".
    const honestNote = await makeCandidate(DENOMINATIONS[0], 26);
    const gift = await makeCandidate(DENOMINATIONS[4], 27); // the largest denomination
    const actors = await forgeableChain({
      headEntries: [entryOf(honestNote)],
      pageEntries: [entryOf(gift)],
    });

    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /local mirror root does not match/,
    );

    const cache = await openTestCache(`stsh-new5-${crypto.randomUUID()}`);
    await expect(
      runScan({ ...actors, tryDecrypt: decryptSelf, masterNoteSecret: MASTER, cache }),
    ).rejects.toThrow(/local mirror root does not match/);
    // The gift never becomes balance.
    expect(spendableNotes((await cache.load()).notes)).toHaveLength(0);
  });

  it("pages that are self-consistent for a DIFFERENT tree (right shape, wrong root) are rejected", async () => {
    // Every page the canister serves is internally perfect — dense, in range,
    // 32-byte leaves, and it is a real tree. It is simply not the tree the head
    // describes. Page-shape validation cannot see this; the mirror root can.
    const mine = [entryOf(await makeCandidate(DENOMINATIONS[0], 28))];
    const theirs = [entryOf(await makeCandidate(DENOMINATIONS[0], 29, OTHER_MASTER))];
    const actors = await forgeableChain({ headEntries: mine, pageEntries: theirs });

    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /local mirror root does not match/,
    );
  });

  it("control: the SAME harness with head and pages agreeing scans clean — the rejections above are not vacuous", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 30);
    const honest = [entryOf(c)];
    const actors = await forgeableChain({ headEntries: honest, pageEntries: honest });

    const outcome = await scanAndValidate(actors, decryptSelf, MASTER);
    expect(outcome.notes).toHaveLength(1);
    expect(outcome.notes[0].state).toBe("spendable");
  });
});

// ── §3.4(3) matching-but-wrong (rollback / equivocation) ──────────────────────

describe("NEW-5 §3.4(3) — matching-but-wrong: a SHORTER self-consistent history", () => {
  /**
   * WHAT CHANGED HERE, AND WHY — read this before the assertions.
   *
   * This test used to be named "is NOT detected today" and asserted PRESENT
   * BEHAVIOUR: a mutually consistent rollback was accepted, the cached
   * mirrorHead regressed to the shorter history, and the recorded acceptances
   * said so deliberately rather than papering over the gap. That was the
   * honest thing to write at the time, and the test said explicitly that when
   * the fix landed, THIS test was the one to revisit.
   *
   * WALLET-AUTH Gate 1 is that revisit, under its own brief line (AC-1). The
   * three acceptances are now inverted on the VERIFIED path.
   *
   * WHAT ACTUALLY CLOSED IT — and it is not what the old comment predicted.
   * The old text named PROT-8 (certified head data) as the fix. The mechanism
   * that lands here is NOT certification and NOT the authenticated transport:
   * it is a per-deployment MONOTONE FLOOR, keyed on
   * (config_hash, security_epoch), that remembers the highest accepted leaf
   * count this wallet has ever verified. Certification would not have closed
   * this case on its own, because a canister signs a rollback exactly as
   * happily as it serves one — a certified shorter history is still a valid
   * certificate. Only memory across scans detects it.
   *
   * PROT-8 IS STILL DEFERRED. `canisters/merkle-tree/src/lib.rs`'s
   * `set_certified_data` is still commented out; nothing in this lane touched
   * any canister. What this lane changed is the wallet.
   *
   * THE UNVERIFIED PATH IS UNCHANGED, and the second test below keeps asserting
   * its old behaviour verbatim. That is deliberate: it shows the reader that
   * the floor, not the transport and not some general hardening, is what moved
   * — and it keeps the old evidence available if the verified path is ever
   * disabled.
   */
  it("AC-1: a mutually consistent rollback IS detected on the verified path, by the monotone floor", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 31);
    const c1 = await makeCandidate(DENOMINATIONS[1], 32);
    const full = [entryOf(c0), entryOf(c1)];
    const dbName = `stsh-new5-${crypto.randomUUID()}`;
    const cache = await openTestCache(dbName);

    const honest = await verifiedChain({ acceptedEntries: full });
    const first = await runVerifiedScan({
      ...honest,
      binding: DEPLOYMENT_BINDING,
      tryDecrypt: decryptSelf,
      masterNoteSecret: MASTER,
      cache,
    });
    expect(first.status).toBe("verified");

    // The SAME deployment — same config_hash, same security_epoch — now serves
    // a one-leaf history whose accepted root is the correct root of its own
    // prefix. Internally consistent; a single snapshot cannot fault it.
    const rolledBack = await verifiedChain({ acceptedEntries: [entryOf(c0)] });

    await expect(
      runVerifiedScan({
        ...rolledBack,
        binding: DEPLOYMENT_BINDING,
        tryDecrypt: decryptSelf,
        masterNoteSecret: MASTER,
        cache,
      }),
    ).rejects.toBeInstanceOf(VerifiedFloorRollbackError);

    // The three old acceptances, INVERTED:
    //  (a) the scan is REJECTED — a named equivocation/rollback error is raised;
    //  (b) the cached evidence does NOT regress to the shorter history;
    //  (c) the floor still stands at the longer history, so a later honest
    //      scan of the real tree is unaffected.
    const after = await cache.load();
    expect(after.verifiedScan?.accepted_leaf_count).toBe("2");
    const key = verifiedFloorKey(after.verifiedScan!.config_hash, after.verifiedScan!.security_epoch);
    expect(after.verifiedFloors?.[key]?.highest_accepted_leaf_count).toBe("2");
    expect(spendableNotes(after.notes)).toHaveLength(2);
  });

  it("the ORDINARY (unverified) path still behaves exactly as it did — the floor is what changed, not the scan", async () => {
    // Unchanged from the original assertions, kept so the delta is visible.
    const c0 = await makeCandidate(DENOMINATIONS[0], 131);
    const c1 = await makeCandidate(DENOMINATIONS[1], 132);
    const full = [entryOf(c0), entryOf(c1)];
    const dbName = `stsh-new5-${crypto.randomUUID()}`;
    const cache = await openTestCache(dbName);

    const honest = await forgeableChain({ headEntries: full, pageEntries: full });
    const first = await runScan({ ...honest, tryDecrypt: decryptSelf, masterNoteSecret: MASTER, cache });
    expect(first.mirrorHead?.leafCount).toBe(2n);
    expect(first.notes).toHaveLength(2);

    const rolledBack = await forgeableChain({ headEntries: [entryOf(c0)], pageEntries: [entryOf(c0)] });
    const second = await runScan({
      ...rolledBack,
      tryDecrypt: decryptSelf,
      masterNoteSecret: MASTER,
      cache,
    });

    // PRESENT BEHAVIOUR of the unverified path, recorded exactly as before:
    //  (a) the scan is accepted — no equivocation error is raised;
    //  (b) the cached mirrorHead REGRESSES to the shorter history;
    //  (c) lastScannedIndex does NOT regress (it is a max);
    //  (d) the note from the disappeared leaf SURVIVES, still spendable.
    expect(second.mirrorHead?.leafCount).toBe(1n);
    expect(second.lastScannedIndex).toBe(2n);
    expect(second.notes.map((n) => n.leafIndex)).toEqual([0n, 1n]);
    expect(spendableNotes(second.notes)).toHaveLength(2);
    // And it carries NO verified provenance — an ordinary scan never claims any.
    expect(second.notes.every((n) => n.verified !== true)).toBe(true);
  });
});

// ── §3.4(4) no spend on unverified state ──────────────────────────────────────

describe("NEW-5 §3.4(4) — nothing from a rejected scan reaches the spend path", () => {
  it("a rejected scan leaves ZERO spend-eligible notes for spendFlow's `notes` input", async () => {
    const c = await makeCandidate(DENOMINATIONS[2], 33);
    const honest = [entryOf(c)];
    const lie = await rootOf(honest);
    lie[31] ^= 0x80;
    const actors = await forgeableChain({ headEntries: honest, pageEntries: honest, headRoot: lie });

    const cache = await openTestCache(`stsh-new5-${crypto.randomUUID()}`);
    await expect(
      runScan({ ...actors, tryDecrypt: decryptSelf, masterNoteSecret: MASTER, cache }),
    ).rejects.toThrow(/local mirror root does not match/);

    // spendFlow is constructed with `notes: ScannedNote[]` taken from this
    // cache (SpendFlowDeps.notes, "the session's cached notes (validated by
    // L3b)"). After a rejected scan there is nothing to hand it.
    const state = await cache.load();
    expect(state.notes).toHaveLength(0);
    expect(spendableNotes(state.notes)).toHaveLength(0);
  });

  it("the spend path re-derives the mirror itself, and the forged canister fails ITS root comparison too", async () => {
    // Defence in depth: even if a spendable note reached the flow by another
    // route, spendFlow re-syncs the mirror from `deps.scan` and compares its
    // root to the head before building any witness. Two halves, asserted
    // separately so neither inherits its expectation from the other:
    //   (a) BEHAVIOUR — the real syncMirror, driven by the forged canister,
    //       produces a mirror root that does NOT equal the head root (and does
    //       equal it for an honest one). That is the flow's decision input.
    //   (b) SOURCE — the flow actually turns that input into a refusal.
    const c = await makeCandidate(DENOMINATIONS[2], 34);
    const honest = [entryOf(c)];
    const lie = await rootOf(honest);
    lie[7] ^= 0x0f;
    const forged = await forgeableChain({ headEntries: honest, pageEntries: honest, headRoot: lie });

    expect(await spendSideMirrorAgrees(forged)).toBe(false);
    expect(await spendSideMirrorAgrees(await forgeableChain({ headEntries: honest, pageEntries: honest }))).toBe(true);

    // (b) Drift-lock on the guard itself. Not a restatement of the check — a
    // read of the shipped source, so deleting or weakening the guard reddens
    // this test rather than silently removing the spend-side defence.
    const flowSrc = readFileSync(resolve(here, "../src/ui/spendFlow.ts"), "utf8");
    expect(flowSrc).toContain("const { head, mirror } = await syncMirror(deps.scan");
    expect(flowSrc).toContain(
      'throw new SpendFlowError("witness", "local mirror root does not match the scan head")',
    );
  });
});
