/**
 * R-7 item 5 (L07-03) — the fresh-device "within 24 hours" claim.
 *
 * `firstSeenAtNs` is stamped with the SCAN clock on first local sighting. On a
 * fresh install or a post-panic-wipe recovery, every recovered note therefore
 * gets `firstSeenAtNs = now`, and limb B told the user "this note reached you
 * within the last 24 hours" on the strength of when the wallet happened to
 * scan. Nothing measured that claim.
 *
 * The fix is a second stored field, `firstSeenVia`, set by the layer that
 * knows (the scan handler, which can see whether the cache was empty before
 * the sweep), and a `classifyNoteOrigin` that only reaches `incoming-receipt`
 * when the sighting can be vouched for as a live incremental scan.
 *
 * INDEPENDENT EXPECTED SIDE. Every warning regex here is a literal written
 * from the finding, never imported from `privacyWarnings.ts`.
 */

import { describe, expect, it } from "vitest";

import { classifyNoteOrigin } from "../src/ui/privacyWarnings";
import { mergeScanOutcome, mergeScannedNotes, type ScanOutcome } from "../src/crypto/scanner";
import { renderSpend } from "../src/ui/pages/spend";
import type { AppContext } from "../src/ui/context";
import {
  CACHE_SCHEMA_V2,
  deserializeScanStateV2,
  serializeScanStateV2,
} from "../src/storage/noteCache";
import type { CachedScanState, ScannedNote } from "../src/storage/noteCache";

const MS = 1_000_000n;
const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = BigInt(Date.now()) * MS;
/** ns-string for `ms` milliseconds ago. */
const ago = (ms: number): string => (NOW - BigInt(ms) * MS).toString(10);

const ARRIVAL_WARNING = /this note reached you within the last 24 hours/i;
const UNKNOWN_ADVISORY = /arrival time is not known on this device/i;
const TIMING_CORRELATION = /reveals a timing correlation/i;

// ── AC-5a / AC-5b: the classifier ────────────────────────────────────────────

describe("R-7 AC-5a — an unvouched first sighting is never an arrival", () => {
  it("AC-5a: `recovery-import` classifies as unknown, however recent the stamp", () => {
    for (const ms of [0, 60_000, DAY_MS / 24, 90 * 60 * 60 * 1000]) {
      const o = classifyNoteOrigin({
        firstSeenAtNs: ago(ms),
        firstSeenVia: "recovery-import",
        nowNs: NOW,
      });
      expect(o.kind, `recovery-import at ${ms}ms ago`).toBe("unknown");
      expect(o.msSinceArrival).toBeUndefined();
    }
  });

  it("AC-5a: an ABSENT `firstSeenVia` (pre-migration record) classifies identically", () => {
    const o = classifyNoteOrigin({ firstSeenAtNs: ago(60_000), nowNs: NOW });
    expect(o.kind).toBe("unknown");
    expect(o.msSinceArrival).toBeUndefined();
  });
});

describe("R-7 AC-5b — a genuine live sighting keeps its real, useful warning", () => {
  it("AC-5b: `live-scan` inside the window still classifies and still warns", () => {
    const o = classifyNoteOrigin({
      firstSeenAtNs: ago(60_000),
      firstSeenVia: "live-scan",
      nowNs: NOW,
    });
    expect(o.kind).toBe("incoming-receipt");
    expect(o.msSinceArrival).toBeGreaterThanOrEqual(60_000 - 5_000);
    expect(o.msSinceArrival).toBeLessThan(DAY_MS);
  });

  it("AC-5b: `live-scan` OUTSIDE the window classifies but is not fresh", () => {
    const o = classifyNoteOrigin({
      firstSeenAtNs: ago(90 * 60 * 60 * 1000),
      firstSeenVia: "live-scan",
      nowNs: NOW,
    });
    expect(o.kind).toBe("incoming-receipt");
    expect(o.msSinceArrival).toBeGreaterThan(DAY_MS);
  });
});

describe("R-7 AC-5c — the honest `unknown` copy is PINNED", () => {
  it("says arrival is not known here, and does not read as reassurance", () => {
    const t = renderWarnings({ firstSeenAtNs: ago(60_000) }, []);
    expect(t).toMatch(UNKNOWN_ADVISORY);
    expect(t).toMatch(/treat this as unchecked, not as safe/i);
    expect(t).not.toMatch(ARRIVAL_WARNING);
  });
});

// ── AC-5a extended half: msSinceDeposit comes from the JOURNAL anchor only ───

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
const COMMITMENT_HEX = "ab".repeat(32);

/** Renders the spend page with the payout toggle ON and returns its warnings. */
function renderWarnings(over: Partial<ScannedNote>, shieldEntries: unknown[]): string {
  const ctx = {
    state: {
      notes: [noteWith(over)],
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
  return (root.querySelector(".warnings") as HTMLElement).textContent ?? "";
}

describe("R-7 AC-5a extended — the deposit-timing warning rides the journal anchor", () => {
  it("case (i): a TRUE recent deposit still warns, even with a stale cache stamp", () => {
    // Two disjoint numbers on the SAME note: shielded ≈1h ago (the anchor,
    // inside the window), first cached ≈90h ago (outside it). Backfilling
    // `msSinceDeposit` from `firstSeenAtNs` would answer 90h and silently drop
    // a warning this wallet has real evidence for.
    const anchorNs = ago(DAY_MS / 24);
    const t = renderWarnings({ firstSeenAtNs: ago(3.75 * DAY_MS) }, [
      { commitmentHex: COMMITMENT_HEX, createdAtNs: anchorNs, dispatchedAtNs: anchorNs },
    ]);
    expect(t).toMatch(TIMING_CORRELATION);
  });

  it("case (ii): no journal anchor means NO deposit-timing claim, however recent the stamp", () => {
    // The mirror of case (i): `firstSeenAtNs` ≈1h ago (well inside the
    // window), no journal entry. The wallet never shielded this note, so it
    // has no deposit time for it — the honest output is silence, not a guess
    // manufactured from the scan clock.
    const t = renderWarnings(
      { firstSeenAtNs: ago(DAY_MS / 24), firstSeenVia: "recovery-import" },
      [],
    );
    expect(t).not.toMatch(TIMING_CORRELATION);
    expect(t).toMatch(UNKNOWN_ADVISORY);
  });
});

// ── AC-5d / AC-5e: stamping and monotonicity ─────────────────────────────────

const scanNote = (leafIndex: bigint, over: Partial<ScannedNote> = {}): ScannedNote => ({
  leafIndex,
  value: 100n,
  rho: new Uint8Array(32),
  rseed: new Uint8Array(32),
  recipientPk: new Uint8Array(32),
  state: "spendable",
  ...over,
});
const outcome = (notes: ScannedNote[]): ScanOutcome => ({
  notes,
  scannedUpTo: 10n,
  mirrorHead: { leafCount: 10n, root: new Uint8Array(32) },
  quarantine: { total: 0, ring: [] },
  spentSet: new Set<string>(),
});
const EMPTY: CachedScanState = { lastScannedIndex: 0n, notes: [] };

describe("R-7 AC-5d — `mergeScanOutcome` stamps the provenance it is given", () => {
  it("AC-5d: a bootstrap scan of an empty cache stamps every note recovery-import", () => {
    const merged = mergeScanOutcome(
      EMPTY,
      outcome([scanNote(1n), scanNote(2n)]),
      12_345n,
      "recovery-import",
    );
    expect(merged.notes.map((n) => n.firstSeenVia)).toEqual([
      "recovery-import",
      "recovery-import",
    ]);
    expect(merged.notes.map((n) => n.firstSeenAtNs)).toEqual(["12345", "12345"]);
  });

  it("AC-5d: an incremental scan stamps ONLY the genuinely new note, as live-scan", () => {
    const prior = mergeScanOutcome(EMPTY, outcome([scanNote(1n)]), 1_000n, "recovery-import");
    const merged = mergeScanOutcome(
      prior,
      outcome([scanNote(1n), scanNote(2n)]),
      2_000n,
      "live-scan",
    );
    const byIndex = new Map(merged.notes.map((n) => [n.leafIndex, n]));
    // The pre-existing note keeps its ORIGINAL stamp and provenance...
    expect(byIndex.get(1n)?.firstSeenAtNs).toBe("1000");
    expect(byIndex.get(1n)?.firstSeenVia).toBe("recovery-import");
    // ...and only the new arrival gets this scan's.
    expect(byIndex.get(2n)?.firstSeenAtNs).toBe("2000");
    expect(byIndex.get(2n)?.firstSeenVia).toBe("live-scan");
  });

  it("omitting the parameter stamps the timestamp with NO provenance (absent = unvouched)", () => {
    const merged = mergeScanOutcome(EMPTY, outcome([scanNote(1n)]), 7n);
    expect(merged.notes[0].firstSeenAtNs).toBe("7");
    expect(merged.notes[0].firstSeenVia).toBeUndefined();
  });
});

describe("R-7 AC-5e — the provenance is MONOTONIC across a rescan", () => {
  it("AC-5e: a recovery-import note stays recovery-import when a plain rescan re-derives it", () => {
    const prev = [scanNote(1n, { firstSeenAtNs: "1000", firstSeenVia: "recovery-import" })];
    const next = [scanNote(1n)];
    const merged = mergeScannedNotes(prev, next);
    expect(merged[0].firstSeenAtNs).toBe("1000");
    expect(merged[0].firstSeenVia).toBe("recovery-import");
  });

  it("AC-5e: it survives repeated rescans, not just the first", () => {
    let notes = [scanNote(1n, { firstSeenAtNs: "1000", firstSeenVia: "recovery-import" })];
    for (let i = 0; i < 5; i += 1) notes = mergeScannedNotes(notes, [scanNote(1n)]);
    expect(notes[0].firstSeenVia).toBe("recovery-import");
  });

  it("the provenance travels with the timestamp that WINS, never separately", () => {
    // Both sides stamped: the earlier timestamp is authoritative, and it is
    // that sighting's own provenance that describes it.
    const earlierIsPrev = mergeScannedNotes(
      [scanNote(1n, { firstSeenAtNs: "1000", firstSeenVia: "recovery-import" })],
      [scanNote(1n, { firstSeenAtNs: "9000", firstSeenVia: "live-scan" })],
    );
    expect(earlierIsPrev[0].firstSeenAtNs).toBe("1000");
    expect(earlierIsPrev[0].firstSeenVia).toBe("recovery-import");

    const earlierIsNext = mergeScannedNotes(
      [scanNote(1n, { firstSeenAtNs: "9000", firstSeenVia: "recovery-import" })],
      [scanNote(1n, { firstSeenAtNs: "1000", firstSeenVia: "live-scan" })],
    );
    expect(earlierIsNext[0].firstSeenAtNs).toBe("1000");
    expect(earlierIsNext[0].firstSeenVia).toBe("live-scan");
  });
});

// ── Migration: the field is additive-optional, the schema version does NOT move ─

describe("R-7 item 5 — a pre-this-change cache deserializes cleanly", () => {
  it("a record with no `firstSeenVia` key reads back as undefined, not a default or a throw", () => {
    // Serialize WITHOUT the field, exactly as every record written before this
    // change looks on disk, then read it back through the shipped reader.
    const before = serializeScanStateV2({
      lastScannedIndex: 0n,
      notes: [scanNote(1n, { firstSeenAtNs: "42" })],
    });
    const payload = JSON.parse(new TextDecoder().decode(before));
    expect("firstSeenVia" in payload.notes[0], "absent field must not be written").toBe(false);
    expect(payload.v).toBe(CACHE_SCHEMA_V2);

    const read = deserializeScanStateV2(before);
    expect(read.notes[0].firstSeenAtNs).toBe("42");
    expect(read.notes[0].firstSeenVia).toBeUndefined();
  });

  it("a record WITH the field round-trips it", () => {
    const bytes = serializeScanStateV2({
      lastScannedIndex: 0n,
      notes: [scanNote(1n, { firstSeenAtNs: "42", firstSeenVia: "recovery-import" })],
    });
    expect(deserializeScanStateV2(bytes).notes[0].firstSeenVia).toBe("recovery-import");
  });
});
