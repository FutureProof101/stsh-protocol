/**
 * WL-2a — the rapid-roundtrip warning, both limbs.
 *
 * The leak is timing: an unshield that follows the note's arrival closely is
 * linkable to it on public data alone. Two arrivals can start that clock and
 * they need different local anchors — a shield this wallet performed (the
 * journal), and a note that simply appeared (the scanner's first sighting).
 *
 * Each limb is tested on BOTH sides of the window independently, because a
 * single shared assertion would let one limb be missing entirely.
 */

import { describe, expect, it } from "vitest";

import {
  classifyNoteOrigin,
  privacyWarnings,
  shieldJournalAnchorNs,
  ROUNDTRIP_WINDOW_MS,
} from "../src/ui/privacyWarnings";
import { mergeScanOutcome, mergeScannedNotes } from "../src/crypto/scanner";
import { serializeScanStateV2, CACHE_SCHEMA_V2 } from "../src/storage/noteCache";
import type { CachedScanState, ScannedNote } from "../src/storage/noteCache";
import type { ScanOutcome } from "../src/crypto/scanner";
import { renderSpend } from "../src/ui/pages/spend";
import type { AppContext } from "../src/ui/context";

const MS = 1_000_000n; // ns per ms
const NOW = 1_000_000_000_000n * MS;
// ABSOLUTE ages, not `ROUNDTRIP_WINDOW_MS ± 1`. A relative fixture moves WITH
// the constant, so halving the window would move these inputs too and the row
// would pass on a window that had silently changed — the mutation must bite.
const HOUR_MS = 60 * 60 * 1000;
const insideMs = 23 * HOUR_MS;
const outsideMs = 25 * HOUR_MS;
const ago = (ms: number) => (NOW - BigInt(ms) * MS).toString(10);

const warn = (input: Parameters<typeof privacyWarnings>[0]) =>
  privacyWarnings(input).map((w) => w.msg).join(" | ");

describe("WL-2a — the window itself", () => {
  it("is TWENTY-FOUR HOURS, pinned to the value the wallet already ships", () => {
    // The shipped `DAY_MS` warning uses the same window; two different numbers
    // would tell the user two different stories about the same risk.
    expect(ROUNDTRIP_WINDOW_MS).toBe(24 * HOUR_MS);
    expect(insideMs).toBeLessThan(ROUNDTRIP_WINDOW_MS);
    expect(outsideMs).toBeGreaterThan(ROUNDTRIP_WINDOW_MS);
  });
});

describe("WL-2a limb A — shield -> unshield", () => {
  it("warns INSIDE the window and not outside it (both sides pinned)", () => {
    const inside = classifyNoteOrigin({ journalAnchorNs: ago(insideMs), nowNs: NOW });
    const outside = classifyNoteOrigin({ journalAnchorNs: ago(outsideMs), nowNs: NOW });
    expect(inside.kind).toBe("self-shield");
    expect(outside.kind).toBe("self-shield");
    expect(warn({ amountKind: "fixed-denomination", publicPayout: true, noteOrigin: inside })).toMatch(
      /you shielded this note within the last 24 hours/i,
    );
    expect(
      warn({ amountKind: "fixed-denomination", publicPayout: true, noteOrigin: outside }),
    ).not.toMatch(/you shielded this note within the last 24 hours/i);
  });

  it("takes the DISPATCH time when the entry has one, else the creation time", () => {
    const entries = [
      { commitmentHex: "aa", createdAtNs: "100", dispatchedAtNs: "500" },
      { commitmentHex: "bb", createdAtNs: "200" },
    ];
    expect(shieldJournalAnchorNs(entries, "aa")).toBe("500");
    expect(shieldJournalAnchorNs(entries, "bb")).toBe("200");
    expect(shieldJournalAnchorNs(entries, "cc")).toBeUndefined();
    expect(shieldJournalAnchorNs(entries, undefined)).toBeUndefined();
  });
});

describe("WL-2a limb B — receipt -> unshield", () => {
  // R-7 item 5 (L07-03): `firstSeenAtNs` alone is no longer evidence of an
  // arrival — a fresh-device stamp is just the scan clock. These fixtures now
  // say what they always MEANT: a genuine live incremental sighting.
  it("warns INSIDE the window and not outside it, given a live-scan firstSeenAtNs", () => {
    const inside = classifyNoteOrigin({
      firstSeenAtNs: ago(insideMs),
      firstSeenVia: "live-scan",
      nowNs: NOW,
    });
    const outside = classifyNoteOrigin({
      firstSeenAtNs: ago(outsideMs),
      firstSeenVia: "live-scan",
      nowNs: NOW,
    });
    expect(inside.kind).toBe("incoming-receipt");
    expect(warn({ amountKind: "fixed-denomination", publicPayout: true, noteOrigin: inside })).toMatch(
      /this note reached you within the last 24 hours/i,
    );
    expect(
      warn({ amountKind: "fixed-denomination", publicPayout: true, noteOrigin: outside }),
    ).not.toMatch(/this note reached you within the last 24 hours/i);
  });
});

describe("WL-2a §3.7 — the three cases are mutually exclusive", () => {
  it("case 1: journal provenance WINS — a self-shield never also reads as a receipt", () => {
    const both = classifyNoteOrigin({
      journalAnchorNs: ago(insideMs),
      firstSeenAtNs: ago(insideMs),
      nowNs: NOW,
    });
    expect(both.kind).toBe("self-shield");
    const msg = warn({ amountKind: "fixed-denomination", publicPayout: true, noteOrigin: both });
    expect(msg).toMatch(/you shielded this note/i);
    // One arrival, one warning — never two.
    expect(msg).not.toMatch(/this note reached you/i);
  });

  it("case 2: no journal match + a sighting = limb B only", () => {
    expect(
      classifyNoteOrigin({
        firstSeenAtNs: ago(insideMs),
        firstSeenVia: "live-scan",
        nowNs: NOW,
      }).kind,
    ).toBe("incoming-receipt");
  });

  it("case 3: neither anchor = UNKNOWN, and it never reads as reassurance", () => {
    const unknown = classifyNoteOrigin({ nowNs: NOW });
    expect(unknown.kind).toBe("unknown");
    expect(unknown.msSinceArrival).toBeUndefined();
    const msg = warn({ amountKind: "fixed-denomination", publicPayout: true, noteOrigin: unknown });
    expect(msg).toMatch(/CANNOT tell you whether this is a rapid roundtrip/i);
    expect(msg).toMatch(/not as safe/i);
    // The thing a reassurance would say, and this must never say:
    expect(msg).not.toMatch(/not a rapid roundtrip\b(?!.*CANNOT)/i);
  });
});

describe("WL-2a — the firstSeenAtNs anchor", () => {
  const note = (leafIndex: bigint, firstSeenAtNs?: string): ScannedNote => ({
    leafIndex,
    value: 100n,
    rho: new Uint8Array(32),
    rseed: new Uint8Array(32),
    recipientPk: new Uint8Array(32),
    state: "spendable",
    ...(firstSeenAtNs !== undefined ? { firstSeenAtNs } : {}),
  });
  const outcome = (notes: ScannedNote[]): ScanOutcome => ({
    notes,
    scannedUpTo: 10n,
    mirrorHead: { leafCount: 10n, root: new Uint8Array(32) },
    quarantine: { total: 0, ring: [] },
    spentSet: new Set<string>(),
  });
  const empty: CachedScanState = { lastScannedIndex: 0n, notes: [] };

  it("is stamped from the INJECTED clock on first sighting", () => {
    const merged = mergeScanOutcome(empty, outcome([note(1n)]), 12345n);
    expect(merged.notes[0].firstSeenAtNs).toBe("12345");
  });

  it("is MONOTONIC across a rescan — a later sweep never resets it", () => {
    const first = mergeScanOutcome(empty, outcome([note(1n)]), 1_000n);
    const second = mergeScanOutcome(first, outcome([note(1n)]), 9_999_999n);
    expect(second.notes[0].firstSeenAtNs).toBe("1000");
    // ...and directly at the merge primitive, which is where a naive
    // last-writer-wins overwrite would silently move it forward.
    expect(mergeScannedNotes([note(1n, "1000")], [note(1n, "9999999")])[0].firstSeenAtNs).toBe("1000");
    expect(mergeScannedNotes([note(1n, "1000")], [note(1n)])[0].firstSeenAtNs).toBe("1000");
  });

  it("keeps mergeScanOutcome PURE — re-applying with the same clock is byte-identical", () => {
    const o = outcome([note(1n), note(2n)]);
    const a = serializeScanStateV2(mergeScanOutcome(empty, o, 777n));
    const b = serializeScanStateV2(mergeScanOutcome(empty, o, 777n));
    expect([...a]).toEqual([...b]);
  });

  it("is additive-optional on schema v2 — the version does NOT move either way", () => {
    const withField = JSON.parse(
      new TextDecoder().decode(serializeScanStateV2({ lastScannedIndex: 0n, notes: [note(1n, "42")] })),
    );
    const without = JSON.parse(
      new TextDecoder().decode(serializeScanStateV2({ lastScannedIndex: 0n, notes: [note(1n)] })),
    );
    expect(withField.v).toBe(CACHE_SCHEMA_V2);
    expect(without.v).toBe(CACHE_SCHEMA_V2);
    expect(withField.notes[0].firstSeenAtNs).toBe("42");
    expect("firstSeenAtNs" in without.notes[0]).toBe(false);
  });
});

describe("WL-2a — through the RENDERED spend page (the wiring gap)", () => {
  const noteWith = (over: Partial<ScannedNote>): ScannedNote => ({
    leafIndex: 3n,
    value: 100_000_000_000n,
    rho: new Uint8Array(32),
    rseed: new Uint8Array(32),
    recipientPk: new Uint8Array(32),
    commitment: new Uint8Array(32).fill(0xab),
    state: "spendable",
    ...over,
  });
  const commitmentHex = "ab".repeat(32);

  const render = (note: ScannedNote, shieldEntries: unknown[]): HTMLElement => {
    const ctx = {
      state: {
        notes: [note],
        shieldEntries,
        busy: false,
        status: null,
        spendFeeBasis: null,
        submissionDelayEnabled: false,
        pendingDelay: null,
        pendingRecovery: [],
      },
      refresh: () => {},
      navigate: () => {},
      loadSpendFeeBasis: async () => {},
      spend: async () => {},
    } as unknown as AppContext;
    const root = document.createElement("div");
    renderSpend(root, ctx);
    const toggle = root.querySelector("#payout-toggle") as HTMLInputElement;
    toggle.checked = true;
    toggle.dispatchEvent(new Event("change"));
    return root;
  };

  const nowNs = BigInt(Date.now()) * MS;
  const recentNs = (nowNs - 60n * 1000n * MS).toString(10);

  it("renders limb A for a self-shielded note, and NOT the incoming-receipt wording", () => {
    const root = render(noteWith({ firstSeenAtNs: recentNs }), [
      { commitmentHex, createdAtNs: recentNs, dispatchedAtNs: recentNs },
    ]);
    const text = (root.querySelector(".warnings") as HTMLElement).textContent ?? "";
    expect(text).toMatch(/you shielded this note within the last 24 hours/i);
    expect(text).not.toMatch(/this note reached you within the last 24 hours/i);
  });

  it("renders limb B for an incoming note with no journal entry", () => {
    const root = render(noteWith({ firstSeenAtNs: recentNs, firstSeenVia: "live-scan" }), []);
    const text = (root.querySelector(".warnings") as HTMLElement).textContent ?? "";
    expect(text).toMatch(/this note reached you within the last 24 hours/i);
  });

  it("renders the UNKNOWN advisory when neither anchor exists", () => {
    const root = render(noteWith({}), []);
    const text = (root.querySelector(".warnings") as HTMLElement).textContent ?? "";
    expect(text).toMatch(/CANNOT tell you whether this is a rapid roundtrip/i);
  });
});
