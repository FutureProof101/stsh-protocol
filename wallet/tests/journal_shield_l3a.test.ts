/**
 * L3a encrypted shield-journal tests — the ShieldJournal API over the REAL
 * PrincipalNoteCache (Argon2id + AES-GCM + transactional revision CAS), on the
 * shared in-memory L4 harness. Proves the journal reuses the ONE L4 write path
 * (no second store): atomic batch persistence, guarded transitions, cross-tab
 * CAS survival, lock/epoch refusal, and pre-L3a record compatibility.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import {
  PrincipalNoteCache,
  deserializeScanStateV2,
  serializeScanStateV2,
  CacheSessionStaleError,
  type CachedScanState,
} from "../src/storage/noteCache";
import {
  ShieldJournal,
  ShieldJournalBusyError,
  ShieldJournalStateError,
  hasActiveShieldIntent,
  type NewShieldApproval,
  type NewShieldEntry,
} from "../src/storage/journal";
import { addNote, memoryHarness, note, testBinding } from "./helpers/cacheL4";

const PRINCIPAL = Principal.fromUint8Array(new Uint8Array(10).fill(0x42)).toText();

function entry(tag: string): NewShieldEntry {
  return {
    commitmentHex: tag.repeat(64 / tag.length),
    denom: "100000000",
    nonceHex: "ab".repeat(16),
    protoFee: "0",
    ledgerFee: "10",
    encryptedPayloadHex: "cd".repeat(40),
    createdAtNs: "1000",
  };
}

const approval: NewShieldApproval = {
  totalAllowance: "100000010",
  expectedAllowance: "0",
  createdAtTimeNs: "999",
  ledgerFee: "10",
};

async function openJournal() {
  const h = await memoryHarness();
  const binding = testBinding(PRINCIPAL);
  const cache = await PrincipalNoteCache.open(h.store, "pass", binding);
  return { h, binding, cache, journal: new ShieldJournal(cache) };
}

describe("ShieldJournal.beginBatch", () => {
  it("persists all entries (planned) + the approval envelope in one atomic write", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a"), entry("b")], approval);
    const state = await journal.read();
    expect(state.entries.map((e) => e.status)).toEqual(["planned", "planned"]);
    expect(state.approval).toMatchObject({ ...approval, status: "planned" });
    expect(hasActiveShieldIntent(state)).toBe(true);
  });

  it("refuses a new batch while an unresolved intent exists (busy)", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a")], approval);
    await expect(journal.beginBatch([entry("b")], approval)).rejects.toBeInstanceOf(
      ShieldJournalBusyError,
    );
    // Nothing was written by the refused batch.
    expect((await journal.read()).entries).toHaveLength(1);
  });

  it("allows a new batch once every prior intent is terminal, keeping history", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a")], approval);
    await journal.transitionEntry(entry("a").commitmentHex, ["planned"], "failed", {
      failureReason: "test",
    });
    await journal.setApprovalStatus(["planned"], "failed", { failureReason: "test" });
    await journal.beginBatch([entry("b")], approval);
    const state = await journal.read();
    expect(state.entries).toHaveLength(2); // terminal history retained (audit)
    expect(state.entries[1].status).toBe("planned");
  });

  it("refuses a duplicate commitment and an empty batch", async () => {
    const { journal } = await openJournal();
    await expect(journal.beginBatch([], approval)).rejects.toBeInstanceOf(ShieldJournalStateError);
    await expect(journal.beginBatch([entry("a"), entry("a")], approval)).rejects.toBeInstanceOf(
      ShieldJournalStateError,
    );
  });
});

describe("ShieldJournal transitions", () => {
  it("guards the from-status, is idempotent on the to-status, rejects unknown entries", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a")], approval);
    const hex = entry("a").commitmentHex;
    await journal.transitionEntry(hex, ["planned"], "deposited", { poolStatus: "appended" });
    // Idempotent re-apply (CAS re-run shape): no error, state unchanged.
    await journal.transitionEntry(hex, ["planned"], "deposited", { poolStatus: "appended" });
    // Wrong from-status is a typed error.
    await expect(journal.transitionEntry(hex, ["planned"], "failed")).rejects.toBeInstanceOf(
      ShieldJournalStateError,
    );
    await expect(
      journal.transitionEntry("ff".repeat(32), ["planned"], "deposited"),
    ).rejects.toBeInstanceOf(ShieldJournalStateError);
    const state = await journal.read();
    expect(state.entries[0]).toMatchObject({ status: "deposited", poolStatus: "appended" });
  });

  it("claimEntryDispatch is EXCLUSIVE: planned+unmarked only; every later claimant gets false", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a")], approval);
    const hex = entry("a").commitmentHex;
    // First claim wins: planned -> unknown + the dispatch timestamp.
    expect(await journal.claimEntryDispatch(hex, "111")).toBe(true);
    let state = await journal.read();
    expect(state.entries[0]).toMatchObject({ status: "unknown", dispatchedAtNs: "111" });
    // A second claim is REFUSED (false) and changes nothing — no wire call may
    // follow a false claim.
    expect(await journal.claimEntryDispatch(hex, "222")).toBe(false);
    state = await journal.read();
    expect(state.entries[0].dispatchedAtNs).toBe("111");
    // Non-claimable states (terminal included) also report false, untouched.
    await journal.transitionEntry(hex, ["unknown"], "failed", { failureReason: "t" });
    expect(await journal.claimEntryDispatch(hex, "333")).toBe(false);
    expect((await journal.read()).entries[0].status).toBe("failed");
    // An unknown commitment is a typed error.
    await expect(journal.claimEntryDispatch("ff".repeat(32), "1")).rejects.toBeInstanceOf(
      ShieldJournalStateError,
    );
  });

  it("two tabs racing the dispatch claim: exactly one wins (CAS arbiter)", async () => {
    const h = await memoryHarness();
    const tabA = await PrincipalNoteCache.open(h.store, "pass", testBinding(PRINCIPAL));
    const tabB = await PrincipalNoteCache.open(h.store, "pass", testBinding(PRINCIPAL));
    const journalA = new ShieldJournal(tabA);
    const journalB = new ShieldJournal(tabB);
    await journalA.beginBatch([entry("a")], approval);
    const hex = entry("a").commitmentHex;
    const [a, b] = await Promise.all([
      journalA.claimEntryDispatch(hex, "1"),
      journalB.claimEntryDispatch(hex, "2"),
    ]);
    expect([a, b].filter(Boolean)).toHaveLength(1);
    const state = await journalA.read();
    expect(state.entries[0].status).toBe("unknown");
    expect(["1", "2"]).toContain(state.entries[0].dispatchedAtNs);
  });

  it("recordDepositSuccess: monotonic merge — upgrades to deposited, never downgrades, conflicts throw", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a"), entry("b")], approval);
    const a = entry("a").commitmentHex;
    const b = entry("b").commitmentHex;
    // planned -> deposited with the marker.
    await journal.recordDepositSuccess(a);
    expect((await journal.read()).entries[0]).toMatchObject({
      status: "deposited",
      successObserved: true,
    });
    // A concurrent promotion to accepted is NOT downgraded; the marker merges.
    await journal.transitionEntry(a, ["deposited"], "accepted", { poolStatus: "root-accepted" });
    await journal.recordDepositSuccess(a); // late CAS re-apply
    expect((await journal.read()).entries[0]).toMatchObject({
      status: "accepted",
      successObserved: true,
    });
    // A conflicting definite-failure record rejects the merge loudly.
    await journal.transitionEntry(b, ["planned"], "failed", { failureReason: "t" });
    await expect(journal.recordDepositSuccess(b)).rejects.toBeInstanceOf(ShieldJournalStateError);
  });

  it("notePoolStatus records bookkeeping without changing status", async () => {
    const { journal } = await openJournal();
    await journal.beginBatch([entry("a")], approval);
    await journal.notePoolStatus(entry("a").commitmentHex, "append-in-flight");
    const state = await journal.read();
    expect(state.entries[0]).toMatchObject({ status: "planned", poolStatus: "append-in-flight" });
  });

  it("importEntry merges a fresh-device record once and no-ops on duplicates", async () => {
    const { journal } = await openJournal();
    const imported = { ...entry("d"), status: "deposited" as const, poolStatus: "appended" };
    expect(await journal.importEntry(imported)).toBe(true);
    expect(await journal.importEntry(imported)).toBe(false);
    expect((await journal.read()).entries).toHaveLength(1);
  });
});

describe("§1.1 concurrency + session binding", () => {
  it("two tabs: a scan write and a journal write both survive the revision CAS", async () => {
    const h = await memoryHarness();
    const tabA = await PrincipalNoteCache.open(h.store, "pass", testBinding(PRINCIPAL));
    const tabB = await PrincipalNoteCache.open(h.store, "pass", testBinding(PRINCIPAL));
    const journalB = new ShieldJournal(tabB);
    // Interleave: A writes a scanned note, B begins a shield batch. Whatever
    // order the CAS settles, BOTH logical changes must survive (the update fns
    // spread the state — the noteCache invariant).
    await Promise.all([tabA.update(addNote(note(0n, 1))), journalB.beginBatch([entry("a")], approval)]);
    const finalA = await tabA.load();
    expect(finalA.notes).toHaveLength(1);
    expect(finalA.shieldJournal?.entries).toHaveLength(1);
  });

  it("a locked cache refuses journal reads and writes (logout/epoch)", async () => {
    const { binding, cache, journal } = await openJournal();
    await journal.beginBatch([entry("a")], approval);
    binding.invalidate(); // session epoch advanced (logout)
    await expect(journal.read()).rejects.toBeInstanceOf(CacheSessionStaleError);
    await expect(
      journal.transitionEntry(entry("a").commitmentHex, ["planned"], "deposited"),
    ).rejects.toBeInstanceOf(CacheSessionStaleError);
    cache.lock();
  });

  it("the journal is durable across cache re-opens (same store, same passphrase)", async () => {
    const h = await memoryHarness();
    const first = await PrincipalNoteCache.open(h.store, "pass", testBinding(PRINCIPAL));
    await new ShieldJournal(first).beginBatch([entry("a")], approval);
    first.lock();
    const second = await PrincipalNoteCache.open(h.store, "pass", testBinding(PRINCIPAL, 1));
    const state = await new ShieldJournal(second).read();
    expect(state.entries).toHaveLength(1);
    expect(state.approval?.createdAtTimeNs).toBe("999");
  });
});

describe("v2 schema compatibility (additive field)", () => {
  it("a pre-L3a state round-trips without growing a journal field", () => {
    const pre: CachedScanState = { notes: [], lastScannedIndex: 5n };
    const decoded = deserializeScanStateV2(serializeScanStateV2(pre));
    expect(decoded.shieldJournal).toBeUndefined();
    expect(decoded.lastScannedIndex).toBe(5n);
  });

  it("a journal-carrying state round-trips byte-stable through v2 serialization", () => {
    const state: CachedScanState = {
      notes: [],
      lastScannedIndex: 0n,
      shieldJournal: {
        entries: [{ ...entry("a"), status: "planned" }],
        approval: { ...approval, status: "approved", blockIndex: "3" },
      },
    };
    const decoded = deserializeScanStateV2(serializeScanStateV2(state));
    expect(decoded.shieldJournal).toEqual(state.shieldJournal);
  });
});
