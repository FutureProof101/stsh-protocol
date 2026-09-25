// @vitest-environment node
/**
 * L3b validated scan pipeline tests (§9).
 *
 * Drives the REAL pipeline end-to-end with REAL note crypto (Poseidon WASM):
 * derivation → constant-time field compare → inner commitment + outer leaf
 * recompute vs the local mirror → nullifier classification via the strictly
 * downloaded spent set → explicit lifecycle states → ONE atomic cache update.
 * The local Merkle mirror recomputes the tree root with the canister's
 * zero-value convention and must equal the atomic get_scan_head root.
 *
 * Gate coverage: QC-2 (spend → rescan: spent input absent from spendable,
 * change present once) · QC-3 (crafted victim-readable payload quarantined,
 * never balance) · every spendable rebuilds spendKey + valid witness material
 * · no dup · high-water not past a failed page · vetKey/master never
 * persisted (S-3) · high-volume invalid payloads → bounded storage (S-29) ·
 * no targeted owned-leaf request (DEF-073/S-28) · advisory pool-commitment
 * label (K3-007/S-47) · spent-set strict download (S-20): ordering, length,
 * count drift, fail-closed exhaustion.
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
  createSpendOutputNote,
  deriveNoteSecretsV2,
  freshNoteNonce,
  merkleLeaf,
  noteToBytesV2,
  type Note,
} from "../src/crypto/notes";
import {
  LocalMerkleMirror,
  StaleSnapshotError,
  ctEqual,
  downloadSpentSet,
  mergeQuarantine,
  mergeScannedNotes,
  runScan,
  scanAndValidate,
  syncMirror,
  type ScanActors,
} from "../src/crypto/scanner";
import {
  PrincipalNoteCache,
  QUARANTINE_RING_CAP,
  noteLifecycle,
  spendableNotes,
  type ScannedNote,
} from "../src/storage/noteCache";
import { openIndexedDbPrincipalCacheStore } from "../src/storage/indexedDbNoteStore";
import { advisoryPoolCommitmentLine } from "../src/ui/pages/scan";

// Poseidon is a wasm-pack `--target web` module; node has no fetch for its
// file: URL, so initialize it from the .wasm bytes before the first hash.
const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

const MASTER = new Uint8Array(32).fill(0x11);
const BINDING = {
  principalText: "aaaaa-aa",
  epoch: 1,
  assertCurrent(): void {},
};

// ── Candidate factory (REAL note crypto) ─────────────────────────────────────

interface Candidate {
  note: Note;
  nonce: Uint8Array;
  plaintext: Uint8Array;
  leaf: Uint8Array;
}

async function makeCandidate(value: bigint, nonceSeed: number): Promise<Candidate> {
  const nonce = new Uint8Array(16).fill(nonceSeed);
  const secrets = await deriveNoteSecretsV2(MASTER, nonce);
  const note =
    value === 0n
      ? await createSpendOutputNote(0n, secrets)
      : await createShieldNote(value, secrets);
  return {
    note,
    nonce,
    plaintext: noteToBytesV2(note, nonce),
    leaf: await merkleLeaf(value, note.commitment),
  };
}

// ── Fake canisters ────────────────────────────────────────────────────────────

interface FakeChain {
  actors: ScanActors;
  setSpent(nullifiers: Uint8Array[]): void;
  headRoot: Uint8Array;
}

/** A chain of `entries` (index → {plaintext-as-payload, leaf}); head root is
 * recomputed from the same leaves by the mirror itself (self-consistent). */
async function fakeChain(
  entries: Array<{ payload: Uint8Array; leaf: Uint8Array }>,
): Promise<FakeChain> {
  const mirror = new LocalMerkleMirror();
  entries.forEach((e, i) => mirror.addLeaf(BigInt(i), e.leaf));
  const headRoot = await mirror.root(BigInt(entries.length));
  let spent: Uint8Array[] = [];
  const chain: FakeChain = {
    headRoot,
    setSpent(n) {
      spent = n;
    },
    actors: {
      async getScanHead() {
        return { leafCount: BigInt(entries.length), root: headRoot };
      },
      async getScanPage(from: bigint, limit: bigint) {
        return entries
          .slice(Number(from), Number(from) + Number(limit))
          .map((e, i) => ({
            index: from + BigInt(i),
            leaf: e.leaf,
            encryptedPayload: e.payload,
          }));
      },
      async getNullifiersPage(startAfter: Uint8Array | null, limit: bigint) {
        const sorted = [...spent].sort((a, b) => {
          for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
          return 0;
        });
        // Exclusive range: first element strictly greater than startAfter.
        let idx = 0;
        if (startAfter !== null) {
          idx = sorted.findIndex((v) => {
            for (let i = 0; i < 32; i++) {
              if (v[i] !== startAfter[i]) return v[i] > startAfter[i];
            }
            return false;
          });
          if (idx === -1) idx = sorted.length;
        }
        return sorted.slice(idx, idx + Number(limit));
      },
      async count() {
        return BigInt(spent.length);
      },
    },
  };
  return chain;
}

/** tryDecrypt that returns the payload itself when it "decrypts for us". */
const decryptSelf = (bytes: Uint8Array): Uint8Array | null => bytes;

function pageEntryOf(c: Candidate): { payload: Uint8Array; leaf: Uint8Array } {
  return { payload: c.plaintext, leaf: c.leaf };
}

// ── The validated pipeline ────────────────────────────────────────────────────

describe("scanAndValidate — validated pipeline (§9)", () => {
  it("a fully valid candidate validates to spendable with all derived material", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 1);
    const chain = await fakeChain([pageEntryOf(c)]);
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);

    expect(outcome.notes).toHaveLength(1);
    const n = outcome.notes[0];
    expect(n.state).toBe("spendable");
    expect(n.value).toBe(DENOMINATIONS[1]);
    expect([...n.nonce!]).toEqual([...c.nonce]);
    expect([...n.commitment!]).toEqual([...c.note.commitment]);
    expect([...n.nullifier!]).toEqual([...c.note.nullifier]);
    expect(n.leafIndex).toBe(0n);
    expect(outcome.quarantine.total).toBe(0);
    expect(outcome.mirrorHead.leafCount).toBe(1n);
  });

  it("QC-2: deposit → spend → fresh rescan — spent input ABSENT from spendable, change present once", async () => {
    const input = await makeCandidate(DENOMINATIONS[2], 2);
    const change = await makeCandidate(DENOMINATIONS[0], 3);
    const chain = await fakeChain([pageEntryOf(input), pageEntryOf(change)]);

    // Scan 1 (fresh device): both notes spendable.
    const first = await scanAndValidate(chain.actors, decryptSelf, MASTER);
    expect(spendableNotes(first.notes).map((n) => n.leafIndex)).toEqual([0n, 1n]);

    // The input is spent (its nullifier lands in the registry); rescan.
    chain.setSpent([input.note.nullifier]);
    const second = await scanAndValidate(chain.actors, decryptSelf, MASTER);

    const spendable = spendableNotes(second.notes);
    expect(spendable.map((n) => n.leafIndex)).toEqual([1n]); // spent input absent
    expect(second.notes.find((n) => n.leafIndex === 0n)?.state).toBe("spent");
    // The change note is present exactly once (no duplicates on rescan).
    const merged = mergeScannedNotes(first.notes, second.notes);
    expect(merged.filter((n) => n.leafIndex === 1n)).toHaveLength(1);
  });

  it("QC-3: a crafted victim-readable payload with a WRONG mirror leaf is quarantined, never balance", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 4);
    // A canonical-but-wrong leaf (the Poseidon boundary accepts it; the leaf
    // comparison is what must reject it).
    const wrongLeaf = new Uint8Array(32).fill(0x01);
    const chain = await fakeChain([{ payload: c.plaintext, leaf: wrongLeaf }]);
    // The crafted payload decrypts and parses, but its recomputed leaf differs.
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);
    expect(outcome.notes).toHaveLength(0);
    expect(outcome.quarantine.total).toBe(1);
    expect(outcome.quarantine.ring[0].reason).toBe("leaf-mismatch");
    expect(spendableNotes(outcome.notes)).toHaveLength(0);
  });

  it("QC-3: a payload whose rho was replaced fails the constant-time field compare", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 5);
    const tampered = new Uint8Array(c.plaintext);
    tampered[25] ^= 0xff; // first rho byte (layout: 1 version + 16 nonce + 8 value)
    const chain = await fakeChain([{ payload: tampered, leaf: c.leaf }]);
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);
    expect(outcome.notes).toHaveLength(0);
    expect(outcome.quarantine.ring[0].reason).toBe("field-mismatch");
  });

  it("legacy 104B and malformed payloads are quarantined distinctly; cursor advances", async () => {
    const legacy = new Uint8Array(104).fill(0x07);
    const malformed = new Uint8Array(121).fill(0x09); // wrong version byte
    const valid = await makeCandidate(DENOMINATIONS[0], 6);
    const dummyLeaf = new Uint8Array(32).fill(1);
    const chain = await fakeChain([
      { payload: legacy, leaf: dummyLeaf },
      { payload: malformed, leaf: dummyLeaf },
      pageEntryOf(valid),
    ]);
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);
    expect(outcome.notes.map((n) => n.leafIndex)).toEqual([2n]);
    expect(outcome.quarantine.total).toBe(2);
    expect(outcome.quarantine.ring.map((e) => e.reason)).toEqual([
      "legacy-v1-payload",
      "malformed-payload",
    ]);
    expect(outcome.scannedUpTo).toBe(3n); // cursor advanced past the quarantined entries
  });

  it("a zero-value dummy is classified distinctly — never spendable, never balance", async () => {
    const dummy = await makeCandidate(0n, 7);
    const chain = await fakeChain([pageEntryOf(dummy)]);
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);
    expect(outcome.notes[0].state).toBe("dummy");
    expect(spendableNotes(outcome.notes)).toHaveLength(0);
  });

  it("S-29: high-volume invalid payloads stay BOUNDED — counter grows, ring caps at 32, cursor advances", async () => {
    const VOLUME = 100;
    const dummyLeaf = new Uint8Array(32).fill(2);
    const entries = Array.from({ length: VOLUME }, (_, i) => ({
      payload: (() => {
        const p = new Uint8Array(121).fill(0x02);
        p[0] = 0x02;
        return p;
      })(),
      leaf: dummyLeaf,
    }));
    const chain = await fakeChain(entries);
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);

    expect(outcome.notes).toHaveLength(0);
    expect(outcome.quarantine.total).toBe(VOLUME); // every one counted
    expect(outcome.quarantine.ring.length).toBe(QUARANTINE_RING_CAP); // ring BOUNDED at 32
    // The ring holds the MOST RECENT entries (the 33rd+ evicted the oldest).
    expect(outcome.quarantine.ring[0].leafIndex).toBe(BigInt(VOLUME - QUARANTINE_RING_CAP));
    expect(outcome.scannedUpTo).toBe(BigInt(VOLUME)); // cursor advanced past all of them
  });

  it("DEF-073/S-28: the pipeline issues NO targeted owned-leaf request (get_leaf does not exist on the actor surface)", async () => {
    const c = await makeCandidate(DENOMINATIONS[0], 8);
    const chain = await fakeChain([pageEntryOf(c)]);
    // ScanActors has no getLeaf/getRootAtIndex member — a pipeline needing one
    // cannot compile. Runtime proof: swapping in a surface whose only leaf
    // source is the scan page still validates fully.
    expect("getLeaf" in chain.actors).toBe(false);
    const outcome = await scanAndValidate(chain.actors, decryptSelf, MASTER);
    expect(outcome.notes).toHaveLength(1);
  });

  it("mirror integrity: a tampered page leaf fails the scan BEFORE persistence", async () => {
    const c = await makeCandidate(DENOMINATIONS[0], 9);
    const chain = await fakeChain([pageEntryOf(c)]);
    // The page now carries a DIFFERENT (forged but canonical) leaf at index 0
    // — the mirror root can never match the honest head root.
    const forged = {
      ...chain.actors,
      getScanPage: async (from: bigint, limit: bigint) => [
        { index: 0n, leaf: new Uint8Array(32).fill(0x01), encryptedPayload: c.plaintext },
      ].slice(Number(from), Number(from) + Number(limit)),
    };
    await expect(scanAndValidate(forged, decryptSelf, MASTER)).rejects.toThrow(/mirror root/i);
  });

  it("high-water does NOT advance past a failed page — nothing is returned for persistence", async () => {    const c0 = await makeCandidate(DENOMINATIONS[0], 10);
    const c1 = await makeCandidate(DENOMINATIONS[1], 11);
    const chain = await fakeChain([pageEntryOf(c0), pageEntryOf(c1)]);
    let calls = 0;
    const failing = {
      ...chain.actors,
      getScanPage: async (from: bigint, limit: bigint) => {
        calls += 1;
        if (calls === 2) throw new Error("simulated page fetch failure");
        return chain.actors.getScanPage(from, limit);
      },
    };
    await expect(
      scanAndValidate(failing, decryptSelf, MASTER, { pageSize: 1n }),
    ).rejects.toThrow(/simulated page fetch failure/);
    // No outcome exists at all — the caller persists nothing (cursor stays).
  });
});

// ── R5 regressions: snapshot expiry, page shape, stale reconcile ─────────────

describe("R5 — end-of-scan spent-snapshot freshness", () => {
  it("a nullifier inserted MID-SWEEP discards the scan; the retry classifies it spent — never persisted spendable", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 20);
    const chain = await fakeChain([pageEntryOf(c)]);
    let swept = false;
    const actors: ScanActors = {
      ...chain.actors,
      getScanPage: async (from: bigint, limit: bigint) => {
        if (!swept) {
          swept = true;
          // Concurrent insert DURING the Merkle sweep (after the spent-set
          // download stabilized at 0).
          chain.setSpent([c.note.nullifier]);
        }
        return chain.actors.getScanPage(from, limit);
      },
    };
    const outcome = await scanAndValidate(actors, decryptSelf, MASTER);
    // Attempt 1 classified it spendable on a stale snapshot and was DISCARDED
    // by the end-of-scan count check; attempt 2 sees the spent nullifier.
    expect(outcome.notes).toHaveLength(1);
    expect(outcome.notes[0].state).toBe("spent");
    expect(spendableNotes(outcome.notes)).toHaveLength(0);
  });

  it("a perpetually changing registry FAILS CLOSED (StaleSnapshotError) after the bounded retries", async () => {
    const c = await makeCandidate(DENOMINATIONS[0], 21);
    const chain = await fakeChain([pageEntryOf(c)]);
    const growing: Uint8Array[] = [];
    const mutate = () => {
      const extra = new Uint8Array(32);
      extra[0] = 0x40 + growing.length;
      growing.push(extra);
      chain.setSpent([...growing]);
    };
    const actors: ScanActors = {
      ...chain.actors,
      getScanPage: async (from: bigint, limit: bigint) => {
        mutate(); // the registry GROWS during the sweep…
        return chain.actors.getScanPage(from, limit);
      },
      getNullifiersPage: async (startAfter: Uint8Array | null, limit: bigint) => {
        mutate(); // …AND during the spent-set download — never stabilizes.
        return chain.actors.getNullifiersPage(startAfter, limit);
      },
    };
    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toBeInstanceOf(
      StaleSnapshotError,
    );
  });
});

describe("R5 — scan page shape validation (fail closed)", () => {
  const good = async () => {
    const c = await makeCandidate(DENOMINATIONS[0], 22);
    const chain = await fakeChain([pageEntryOf(c)]);
    return { c, chain };
  };
  const mutatePage =
    (chain: FakeChain, mutate: (entries: any[]) => any[]): ScanActors => ({
      ...chain.actors,
      getScanPage: async (from: bigint, limit: bigint) =>
        mutate(await chain.actors.getScanPage(from, limit)),
    });

  it("rejects an entry smuggled past the captured head (concurrent append) — length and density checks fire first", async () => {
    const { chain } = await good();
    const actors = mutatePage(chain, (entries) => [
      ...entries,
      { index: 99n, leaf: new Uint8Array(32).fill(1), encryptedPayload: new Uint8Array(0) },
    ]);
    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /more than the requested|not dense|beyond the captured head/,
    );
  });

  it("rejects a non-dense page (skipped index)", async () => {
    const { chain } = await good();
    const actors = mutatePage(chain, (entries) => entries.map((e: any) => ({ ...e, index: 5n })));
    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(/not dense/);
  });

  it("rejects a page longer than the request", async () => {
    const { chain } = await good();
    const actors = mutatePage(chain, (entries) => [...entries, entries[0]]);
    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(
      /more than the requested|not dense/,
    );
  });

  it("rejects a wrong-length leaf", async () => {
    const { chain } = await good();
    const actors = mutatePage(chain, (entries) =>
      entries.map((e: any) => ({ ...e, leaf: new Uint8Array(31).fill(1) })),
    );
    await expect(scanAndValidate(actors, decryptSelf, MASTER)).rejects.toThrow(/-byte leaf/);
  });
});

describe("R5 — stale cached-state reconciliation", () => {
  it("a cached spendable note ABSENT from the new outcome and spent is marked spent — never silently spendable", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 23);
    const chain1 = await fakeChain([pageEntryOf(c)]);
    const dbName = `stsh-l3b-${crypto.randomUUID()}`;
    const cache = await openTestCache(dbName);

    // Scan 1: the note validates spendable and persists.
    const first = await runScan({
      ...chain1.actors,
      tryDecrypt: decryptSelf,
      masterNoteSecret: MASTER,
      cache,
    });
    expect(first.notes[0].state).toBe("spendable");

    // Scan 2: the same leaf remains, but its payload is now UNREADABLE (the
    // candidate is absent from the outcome) AND its nullifier is spent.
    const chain2 = await fakeChain([{ payload: new Uint8Array([1, 2, 3]), leaf: c.leaf }]);
    chain2.setSpent([c.note.nullifier]);
    const second = await runScan({
      ...chain2.actors,
      tryDecrypt: () => null, // payload no longer decrypts for us
      masterNoteSecret: MASTER,
      cache,
    });

    expect(second.notes).toHaveLength(1);
    expect(second.notes[0].leafIndex).toBe(0n);
    expect(second.notes[0].state).toBe("spent");
    expect(spendableNotes(second.notes)).toHaveLength(0);
  });

  it("a cached spendable note absent from the outcome but NOT spent keeps its state (never made more spendable)", async () => {
    const c = await makeCandidate(DENOMINATIONS[0], 24);
    const chain1 = await fakeChain([pageEntryOf(c)]);
    const dbName = `stsh-l3b-${crypto.randomUUID()}`;
    const cache = await openTestCache(dbName);
    await runScan({ ...chain1.actors, tryDecrypt: decryptSelf, masterNoteSecret: MASTER, cache });

    // Scan 2: payload unreadable, nullifier NOT spent — state preserved.
    const chain2 = await fakeChain([{ payload: new Uint8Array([9]), leaf: c.leaf }]);
    const second = await runScan({
      ...chain2.actors,
      tryDecrypt: () => null,
      masterNoteSecret: MASTER,
      cache,
    });
    expect(second.notes[0].state).toBe("spendable");
  });
});

// ── Spent-set strict download (S-20) ─────────────────────────────────────────

function spentDeps(pages: Uint8Array[][], countSeries: bigint[]) {
  let pageCall = 0;
  let countCall = 0;
  return {
    async getNullifiersPage(_c: Uint8Array | null, _l: bigint) {
      return pages[Math.min(pageCall++, pages.length - 1)];
    },
    async count() {
      return countSeries[Math.min(countCall++, countSeries.length - 1)];
    },
  };
}

const nf = (n: number): Uint8Array => new Uint8Array(32).fill(n);

describe("downloadSpentSet — strict walk (L0-F/S-20)", () => {
  it("happy path: ordered, 32-byte, unique, length == count", async () => {
    const set = await downloadSpentSet(spentDeps([[nf(1), nf(2), nf(3)]], [3n, 3n]));
    expect(set.size).toBe(3);
  });

  it("rejects an out-of-order page", async () => {
    await expect(downloadSpentSet(spentDeps([[nf(2), nf(1)]], [2n, 2n]))).rejects.toThrow(
      /strictly increasing/,
    );
  });

  it("rejects a duplicate element", async () => {
    await expect(downloadSpentSet(spentDeps([[nf(1), nf(1)]], [2n, 2n]))).rejects.toThrow(
      /strictly increasing/,
    );
  });

  it("rejects a non-32-byte element", async () => {
    await expect(
      downloadSpentSet(spentDeps([[nf(1), new Uint8Array(31)]], [2n, 2n])),
    ).rejects.toThrow(/not 32 bytes/);
  });

  it("count drift mid-walk: first snapshot discarded, retry succeeds fresh", async () => {
    // Attempt 1: count changes (3 -> 4); attempt 2: stable at 4.
    const pages = [[nf(1), nf(2)], [nf(1), nf(2), nf(3), nf(4)]];
    const set = await downloadSpentSet(spentDeps(pages, [3n, 4n, 4n, 4n]));
    expect(set.size).toBe(4);
  });

  it("perpetual drift FAILS CLOSED (StaleSnapshotError) — never a partial set", async () => {
    const pages = [[nf(1)], [nf(1)], [nf(1)], [nf(1)]];
    await expect(
      downloadSpentSet(spentDeps(pages, [1n, 2n, 2n, 3n, 3n, 4n])),
    ).rejects.toBeInstanceOf(StaleSnapshotError);
  });

  it("length != count despite a stable count is a hard failure", async () => {
    await expect(downloadSpentSet(spentDeps([[nf(1), nf(2)]], [5n, 5n]))).rejects.toThrow(
      /!= count/,
    );
  });
});

// ── runScan (atomic cache composition) ───────────────────────────────────────

async function openTestCache(dbName: string): Promise<PrincipalNoteCache> {
  const store = await openIndexedDbPrincipalCacheStore(dbName);
  return PrincipalNoteCache.open(store, "pw", BINDING);
}

describe("runScan — atomic persistence (S-3, §1.1)", () => {
  it("persists validated notes + mirrorHead + quarantine in ONE update; master/vetKey never persisted", async () => {
    const c = await makeCandidate(DENOMINATIONS[1], 12);
    const legacy = new Uint8Array(104).fill(0x07);
    const chain = await fakeChain([
      pageEntryOf(c),
      { payload: legacy, leaf: new Uint8Array(32).fill(3) },
    ]);
    const dbName = `stsh-l3b-${crypto.randomUUID()}`;
    const cache = await openTestCache(dbName);

    const state = await runScan({
      ...chain.actors,
      tryDecrypt: decryptSelf,
      masterNoteSecret: MASTER,
      cache,
    });

    expect(state.notes).toHaveLength(1);
    expect(state.notes[0].state).toBe("spendable");
    expect(state.lastScannedIndex).toBe(2n);
    expect(state.mirrorHead?.leafCount).toBe(2n);
    expect(state.quarantine?.total).toBe(1);

    // A fresh open of the same DB sees exactly the persisted state.
    const reopened = await openTestCache(dbName);
    const loaded = await reopened.load();
    expect(loaded.notes).toHaveLength(1);
    expect(loaded.mirrorHead?.leafCount).toBe(2n);

    // S-3: the serialized record contains neither the master secret nor any
    // vetKey bytes — only encrypted state.
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const slot = await store.get(BINDING.principalText);
    expect(slot).not.toBeNull();
    const hay = slot!.record.ciphertext;
    const needle = MASTER;
    let found = false;
    for (let i = 0; i + needle.length <= hay.length && !found; i++) {
      found = needle.every((b, j) => hay[i + j] === b);
    }
    expect(found).toBe(false);
  });

  it("a second scan after new leaves is idempotent (dedup by index, no double-count)", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 13);
    const c1 = await makeCandidate(DENOMINATIONS[1], 14);
    const chain1 = await fakeChain([pageEntryOf(c0)]);
    const dbName = `stsh-l3b-${crypto.randomUUID()}`;
    const cache = await openTestCache(dbName);

    await runScan({ ...chain1.actors, tryDecrypt: decryptSelf, masterNoteSecret: MASTER, cache });

    // The tree grows by one leaf; rescan from scratch (full sweep).
    const chain2 = await fakeChain([pageEntryOf(c0), pageEntryOf(c1)]);
    const state = await runScan({
      ...chain2.actors,
      tryDecrypt: decryptSelf,
      masterNoteSecret: MASTER,
      cache,
    });

    expect(state.notes.map((n) => n.leafIndex)).toEqual([0n, 1n]);
    expect(state.lastScannedIndex).toBe(2n);
  });
});

// ── Merge helpers + lifecycle + advisory label ────────────────────────────────

describe("merge helpers + lifecycle + K3-007 label", () => {
  const mk = (i: bigint, state?: ScannedNote["state"]): ScannedNote => ({
    leafIndex: i,
    value: DENOMINATIONS[0],
    rho: new Uint8Array(32),
    rseed: new Uint8Array(32),
    recipientPk: new Uint8Array(32),
    ...(state !== undefined ? { state } : {}),
  });

  it("mergeScannedNotes dedupes by index and sorts", () => {
    const merged = mergeScannedNotes([mk(2n), mk(0n)], [mk(0n), mk(1n)]);
    expect(merged.map((n) => n.leafIndex)).toEqual([0n, 1n, 2n]);
  });

  it("mergeQuarantine adds totals and keeps the most recent ring entries", () => {
    const prev = {
      total: 30,
      ring: Array.from({ length: 30 }, (_, i) => ({ leafIndex: BigInt(i), reason: "malformed-payload" as const })),
    };
    const delta = {
      total: 5,
      ring: Array.from({ length: 5 }, (_, i) => ({ leafIndex: BigInt(100 + i), reason: "field-mismatch" as const })),
    };
    const merged = mergeQuarantine(prev, delta);
    expect(merged.total).toBe(35);
    expect(merged.ring.length).toBe(QUARANTINE_RING_CAP);
    // 35 entries capped to 32: the 3 oldest are evicted, newest always kept.
    expect(merged.ring[0].leafIndex).toBe(3n);
    expect(merged.ring[merged.ring.length - 1].leafIndex).toBe(104n);
  });

  it("legacy notes (no v2 state) are lifecycle-quarantined, never spendable", () => {
    expect(noteLifecycle(mk(0n))).toBe("quarantined");
    expect(spendableNotes([mk(0n), mk(1n, "spendable")])).toHaveLength(1);
  });

  it("K3-007 advisory label is EXACTLY the ruled wording", () => {
    expect(advisoryPoolCommitmentLine(1234n)).toBe(
      "Historical pool commitments: 1234 — advisory; includes spent, dummy and " +
        "repeated/self-churn outputs; not an anonymity guarantee.",
    );
  });

  it("ctEqual is constant-time-shaped: length-sensitive, byte-exact", () => {
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(1);
    const c = new Uint8Array(32).fill(1);
    c[31] = 2;
    expect(ctEqual(a, b)).toBe(true);
    expect(ctEqual(a, c)).toBe(false);
    expect(ctEqual(a, new Uint8Array(31))).toBe(false);
  });
});


describe("L10 mirror cancellation request fencing", () => {
  it("rejects an already-aborted signal without creating a head request", async () => {
    const controller = new AbortController();
    controller.abort();
    let heads = 0;
    await expect(syncMirror({
      getScanHead: async () => {
        heads += 1;
        return { leafCount: 0n, root: new Uint8Array(32) };
      },
      getScanPage: async () => [],
    }, { signal: controller.signal })).rejects.toThrow(/cancel/i);
    expect(heads).toBe(0);
  });

  it("does not create another page request after onProgress aborts", async () => {
    const controller = new AbortController();
    let pages = 0;
    await expect(syncMirror({
      getScanHead: async () => ({ leafCount: 2n, root: new Uint8Array(32) }),
      getScanPage: async (from) => {
        pages += 1;
        return [{ index: from, leaf: new Uint8Array(32), encryptedPayload: new Uint8Array() }];
      },
    }, {
      pageSize: 1n,
      signal: controller.signal,
      onProgress: () => controller.abort(),
    })).rejects.toThrow(/cancel/i);
    expect(pages).toBe(1);
  });
});
