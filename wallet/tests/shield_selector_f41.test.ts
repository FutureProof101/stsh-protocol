/**
 * F4-1 — selector-MINIMISED status polls at `shieldFlow.ts:572`.
 *
 * The property under test is *the selector call is not made* (Rule 11), so every
 * assertion counts ACTUAL calls on the pool actor rather than inspecting state
 * that merely correlates with them. The journal is the REAL `ShieldJournal` over
 * the REAL `PrincipalNoteCache`; only the canister actor is mocked, and it logs
 * every wire call it receives.
 *
 * This is minimisation, NOT selector-freedom: a commitment is still sent once per
 * disappearance episode, plus once per page reload, and the four one-shot sites
 * (:544, :673, :748, :1085) are deliberately unchanged and still send theirs.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import type {
  ActiveDepositsPageView,
  PoolCanister,
  PoolDepositStatus,
  PoolPendingDeposit,
} from "../src/actors/pool";
import { ShieldJournal } from "../src/storage/journal";
import { PrincipalNoteCache, type ShieldJournalEntryState } from "../src/storage/noteCache";
import {
  pollJournalStatuses,
  resetAbsenceProbeMarkersForReload,
  type ShieldFlowDeps,
} from "../src/ui/shieldFlow";
import { memoryHarness, testBinding } from "./helpers/cacheL4";

const USER = Principal.fromText("aaaaa-aa");

function hexToBytesLocal(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A distinct 32-byte commitment per tag, and its hex. */
function commitment(tag: number): { bytes: Uint8Array; hex: string } {
  const bytes = new Uint8Array(32).fill(tag);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { bytes, hex };
}

function seedEntry(hex: string, status: ShieldJournalEntryState["status"]): ShieldJournalEntryState {
  return {
    commitmentHex: hex,
    denom: "100000000",
    nonceHex: "00".repeat(12),
    protoFee: "0",
    ledgerFee: "10000",
    encryptedPayloadHex: "aa".repeat(16),
    status,
    createdAtNs: "1000000000",
    // Everything reaching :572 was dispatched — `planned` is filtered out before
    // the call, so these markers are what the site actually sees.
    dispatchedAtNs: "1000000000",
    successObserved: status === "deposited",
  };
}

function record(bytes: Uint8Array, kind: PoolDepositStatus["kind"]): PoolPendingDeposit {
  return {
    noteCommitment: bytes,
    status: { kind } as PoolDepositStatus,
    depositor: USER,
    encryptedPayload: new Uint8Array(16),
    privateBalance: 0n,
    createdAtNs: 0n,
  };
}

interface Harness {
  deps: ShieldFlowDeps;
  log: string[];
  journal: ShieldJournal;
  /** Pages returned by `list_my_active_deposits`, in cursor order. */
  pages: ActiveDepositsPageView[];
  /** Scripted `get_deposit_status` answer. */
  depositStatus: (c: Uint8Array) => Promise<PoolPendingDeposit | null>;
  probeCount(): number;
  listCount(): number;
}

async function makeHarness(): Promise<Harness> {
  const log: string[] = [];
  const store = (await memoryHarness()).store;
  const cache = await PrincipalNoteCache.open(store, "pass", testBinding(USER.toText()));
  const journal = new ShieldJournal(cache);

  const h: Partial<Harness> = { pages: [{ deposits: [], nextCursor: null }] };
  h.depositStatus = async () => null;

  const pool = {
    // The one call the steady-state pass may make. Paged by cursor position so a
    // multi-page listing is exercised the way the canister actually serves it.
    listMyActiveDeposits: async (
      startAfter: Uint8Array | null,
      _limit: bigint,
    ): Promise<ActiveDepositsPageView> => {
      log.push("wire:list_my_active_deposits");
      const pages = h.pages as ActiveDepositsPageView[];
      if (startAfter === null) return pages[0];
      const hex = [...startAfter].map((b) => b.toString(16).padStart(2, "0")).join("");
      const index = pages.findIndex(
        (p) =>
          p.nextCursor !== null &&
          [...p.nextCursor].map((b) => b.toString(16).padStart(2, "0")).join("") === hex,
      );
      if (index === -1) throw new Error("unscripted cursor");
      return pages[index + 1];
    },
    // The SELECTOR. Every call is logged with the commitment it named.
    getDepositStatus: async (c: Uint8Array): Promise<PoolPendingDeposit | null> => {
      log.push(`wire:get_deposit_status:${[...c].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 8)}`);
      return (h.depositStatus as Harness["depositStatus"])(c);
    },
  } as unknown as PoolCanister;

  const deps = {
    principal: USER,
    pool,
    journal,
    nowNs: () => 1_000_000_000n,
  } as unknown as ShieldFlowDeps;

  h.deps = deps;
  h.log = log;
  h.journal = journal;
  h.probeCount = () => log.filter((l) => l.startsWith("wire:get_deposit_status")).length;
  h.listCount = () => log.filter((l) => l === "wire:list_my_active_deposits").length;
  return h as Harness;
}

// Each test gets FRESH commitments. Module-scoped markers persist across tests in
// a file, so reusing a commitment would let one test pre-seed another's state and
// silently weaken it — the transition-requiring mutation went undetected until
// these were made unique.
let tag = 0x10;
let C1 = commitment(tag);
let C2 = commitment(tag + 1);

beforeEach(() => {
  // Each test starts from a fresh page load, with commitments no earlier test saw.
  resetAbsenceProbeMarkersForReload();
  tag += 2;
  C1 = commitment(tag);
  C2 = commitment(tag + 1);
});

describe("F4-1 — the steady-state pass names no commitment", () => {
  it("E6: entries PRESENT in the listing produce ZERO get_deposit_status calls", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    await h.journal.importEntry(seedEntry(C2.hex, "unknown"));
    h.pages = [
      { deposits: [record(C1.bytes, "appended"), record(C2.bytes, "appended")], nextCursor: null },
    ];

    await pollJournalStatuses(h.deps);
    await pollJournalStatuses(h.deps);
    await pollJournalStatuses(h.deps);

    expect(h.probeCount()).toBe(0); // the property: no selector, ever, while present
    expect(h.listCount()).toBe(3); // and the listing IS what it used instead
    // Rule 4 anchor: the log is genuinely populated, so a zero is a real zero.
    expect(h.log.length).toBeGreaterThan(0);
  });

  it("E6-anchor: the same harness DOES record a probe when one is made", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    h.pages = [{ deposits: [], nextCursor: null }]; // absent => one probe
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);
  });
});

describe("F4-1 — one probe per disappearance episode", () => {
  it("E7: disappearance fires EXACTLY one probe, and a second absent cycle fires none", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    h.pages = [{ deposits: [record(C1.bytes, "appended")], nextCursor: null }];
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(0);

    h.pages = [{ deposits: [], nextCursor: null }]; // gone
    h.depositStatus = async () => null;
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);

    await pollJournalStatuses(h.deps); // still absent, still marked
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1); // not one per poll
  });

  it("E7b: the marker clears ONLY on observed presence or Some(pending)", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));

    // absent -> probe (None leaves the marker SET) -> still absent -> no probe
    h.pages = [{ deposits: [], nextCursor: null }];
    h.depositStatus = async () => null;
    await pollJournalStatuses(h.deps);
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);

    // observed presence clears it
    h.pages = [{ deposits: [record(C1.bytes, "appended")], nextCursor: null }];
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);

    // ...so a fresh disappearance probes again
    h.pages = [{ deposits: [], nextCursor: null }];
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(2);
  });

  it("E7b-terminal: Some(terminal) leaves the marker set — a final answer is not re-probed", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    h.pages = [{ deposits: [], nextCursor: null }];
    h.depositStatus = async (c) => record(c, "root-accepted");

    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);
    expect((await h.journal.read()).entries[0].status).toBe("accepted");

    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);
  });

  it("E7c: after a RELOAD an already-absent entry fires exactly one probe", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    h.pages = [{ deposits: [], nextCursor: null }];
    h.depositStatus = async () => null;

    await pollJournalStatuses(h.deps);
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);

    resetAbsenceProbeMarkersForReload(); // the page reload
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(2); // exactly one more — the per-reload cost
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(2);
  });
});

describe("F4-1 — absence is never read as acceptance", () => {
  it("E8-terminal: only Some(root-accepted) promotes to accepted", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    h.pages = [{ deposits: [], nextCursor: null }];
    h.depositStatus = async (c) => record(c, "root-accepted");
    await pollJournalStatuses(h.deps);
    expect((await h.journal.read()).entries[0].status).toBe("accepted");
  });

  it("E8-none: None NEVER yields accepted (and never silently failed)", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "unknown"));
    h.pages = [{ deposits: [], nextCursor: null }];
    h.depositStatus = async () => null;
    await pollJournalStatuses(h.deps);
    const entry = (await h.journal.read()).entries[0];
    expect(entry.status).not.toBe("accepted");
    expect(entry.status).not.toBe("failed");
    expect(entry.status).toBe("unknown");
    expect(entry.poolStatus).toBe("no-record");
  });

  it("E8b: a FALSE disappearance resolves via the probe and polling RESUMES", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "unknown"));
    h.pages = [{ deposits: [], nextCursor: null }];
    h.depositStatus = async (c) => record(c, "appended"); // still in flight

    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(1);
    // not abandoned: it is credited, and the marker was re-armed
    expect((await h.journal.read()).entries[0].status).toBe("deposited");

    h.pages = [{ deposits: [], nextCursor: null }]; // a genuine later disappearance
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(2); // probes again, because Some(pending) cleared it
  });
});

describe("F4-1-pagination — absence is a property of a COMPLETED listing", () => {
  it("an entry on PAGE TWO is found, so no probe and no classification occur", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    const cursor = new Uint8Array(32).fill(0x99);
    h.pages = [
      { deposits: [record(C2.bytes, "appended")], nextCursor: cursor },
      { deposits: [record(C1.bytes, "appended")], nextCursor: null },
    ];

    await pollJournalStatuses(h.deps);

    expect(h.listCount()).toBe(2); // paged to exhaustion
    expect(h.probeCount()).toBe(0); // a single-page read would have probed here
    expect((await h.journal.read()).entries[0].status).toBe("deposited");
  });

  it("a listing that TERMINATES EARLY classifies nothing and leaves the marker untouched", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    const cursor = new Uint8Array(32).fill(0x99);
    let failPageTwo = true;
    const pages: ActiveDepositsPageView[] = [
      { deposits: [], nextCursor: cursor },
      { deposits: [record(C1.bytes, "appended")], nextCursor: null },
    ];
    h.pages = pages;
    const realList = h.deps.pool.listMyActiveDeposits.bind(h.deps.pool);
    (h.deps.pool as { listMyActiveDeposits: PoolCanister["listMyActiveDeposits"] })
      .listMyActiveDeposits = async (startAfter, limit) => {
      if (startAfter !== null && failPageTwo) throw new Error("page two unavailable");
      return realList(startAfter, limit);
    };

    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(0); // absent-on-a-partial-listing is not absence
    expect((await h.journal.read()).entries[0].status).toBe("deposited");

    // and once the listing completes, the entry is simply found — still no probe
    failPageTwo = false;
    await pollJournalStatuses(h.deps);
    expect(h.probeCount()).toBe(0);
  });

  it("a NON-ADVANCING cursor is treated as incomplete rather than paged forever", async () => {
    const h = await makeHarness();
    await h.journal.importEntry(seedEntry(C1.hex, "deposited"));
    const cursor = new Uint8Array(32).fill(0x99);
    (h.deps.pool as { listMyActiveDeposits: PoolCanister["listMyActiveDeposits"] })
      .listMyActiveDeposits = async () => {
      h.log.push("wire:list_my_active_deposits");
      return { deposits: [], nextCursor: cursor }; // same cursor, forever
    };

    await pollJournalStatuses(h.deps);

    expect(h.listCount()).toBeLessThan(5); // it stopped, it did not spin
    expect(h.probeCount()).toBe(0); // and classified nothing
    expect((await h.journal.read()).entries[0].status).toBe("deposited");
  });
});
