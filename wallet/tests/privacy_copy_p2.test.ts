/**
 * AR2-P2-01 / AR2-P2-02 — the wallet must not tell the user something untrue
 * about a public payout, and must surface the countermeasure it already ships.
 *
 * INDEPENDENT EXPECTED SIDE (HARNESS_DELTA §1). Every expected string below is
 * a LITERAL written here. Nothing is imported from `privacyWarnings.ts` and
 * compared against itself — importing the constant under test proves only that
 * it equals itself. The one import from the shipped tree is `renderSpend`,
 * which is the surface under test, not the expected value.
 */

import { describe, expect, it } from "vitest";

import { privacyWarnings } from "../src/ui/privacyWarnings";
import { renderSpend } from "../src/ui/pages/spend";
import type { AppContext } from "../src/ui/context";
import type { ScannedNote } from "../src/storage/noteCache";

const MS = 1_000_000n;
const HOUR_MS = 60 * 60 * 1000;

/** The claim AR2-P2-01 found false. It must not survive in any form. */
const OLD_FALSE_CLAIM = /only the sender note stays private/i;
/** Independently written, from the finding — not read from the module. */
const SUBMITTER_DISCLOSURE = /the account that submits this spend/i;
const PERMANENCE = /recorded permanently|cannot be deleted/i;
const STILL_PRIVATE = /nobody learns which note funded this payout/i;
const COUNTERMEASURE = /random period of up to 2 minutes/i;
const COUNTERMEASURE_BOUNDS = /OFF unless you turn it on/i;

const text = (input: Parameters<typeof privacyWarnings>[0]) =>
  privacyWarnings(input).map((w) => w.msg).join(" | ");

describe("T-1 — the submitter disclosure is UNCONDITIONAL on a public payout", () => {
  // The matrix is built here, not derived from the module's own branches: every
  // amountKind, with and without a classified origin, and on both sides of the
  // timing window. A disclosure that appeared only on some of these would be
  // exactly the conditional warning the finding rejects.
  const origins = [
    undefined,
    { kind: "self-shield", msSinceArrival: 1 * HOUR_MS },
    { kind: "self-shield", msSinceArrival: 90 * HOUR_MS },
    { kind: "incoming-receipt", msSinceArrival: 1 * HOUR_MS },
    { kind: "incoming-receipt", msSinceArrival: 90 * HOUR_MS },
    { kind: "unknown" },
  ] as const;

  for (const amountKind of ["fixed-denomination", "specific-amount"] as const) {
    for (const [i, origin] of origins.entries()) {
      for (const msSinceDeposit of [undefined, 60_000, 90 * HOUR_MS]) {
        it(`discloses the submitter for ${amountKind}, origin #${i}, age ${String(msSinceDeposit)}`, () => {
          const t = text({
            amountKind,
            publicPayout: true,
            ...(origin !== undefined ? { noteOrigin: origin } : {}),
            ...(msSinceDeposit !== undefined ? { msSinceDeposit } : {}),
          });
          expect(t).toMatch(SUBMITTER_DISCLOSURE);
          expect(t).toMatch(PERMANENCE);
          // ...and says what REMAINS private, so it is not wrong in the other
          // direction (a "nothing is private" warning is also a false record).
          expect(t).toMatch(STILL_PRIVATE);
        });
      }
    }
  }

  it("says nothing about the submitter when there is NO public payout", () => {
    // The negative arm that makes the positive one mean something: if the
    // disclosure were unconditional across the whole function rather than the
    // public-payout branch, this would fail.
    const t = text({ amountKind: "fixed-denomination", publicPayout: false, msSinceDeposit: 90 * HOUR_MS });
    expect(t).toBe("");
  });
});

describe("T-2 — the old false claim is gone from every rendered path", () => {
  it("never appears, on any input in the T-1 matrix", () => {
    for (const amountKind of ["fixed-denomination", "specific-amount"] as const) {
      for (const publicPayout of [true, false]) {
        for (const msSinceDeposit of [undefined, 60_000, 90 * HOUR_MS]) {
          expect(
            text({
              amountKind,
              publicPayout,
              ...(msSinceDeposit !== undefined ? { msSinceDeposit } : {}),
            }),
          ).not.toMatch(OLD_FALSE_CLAIM);
        }
      }
    }
  });
});

describe("T-3 — a timing warning arrives with the countermeasure that answers it", () => {
  it("discloses the delay when the deposit-timing warning fires", () => {
    const t = text({ amountKind: "fixed-denomination", publicPayout: true, msSinceDeposit: 60_000 });
    expect(t).toMatch(/timing correlation/i);
    expect(t).toMatch(COUNTERMEASURE);
    expect(t).toMatch(COUNTERMEASURE_BOUNDS);
    // Bounded claim: the delay is NOT anonymisation. The disclosure must say so
    // in the same breath, because a user who reads it as "this hides me" is
    // worse off than one who never saw it.
    expect(t).toMatch(/does not hide the account/i);
  });

  it("discloses the delay on the rapid-roundtrip limb too", () => {
    const t = text({
      amountKind: "fixed-denomination",
      publicPayout: true,
      noteOrigin: { kind: "self-shield", msSinceArrival: 1 * HOUR_MS },
    });
    expect(t).toMatch(/rapid roundtrip/i);
    expect(t).toMatch(COUNTERMEASURE);
  });

  it("does NOT offer the delay when no timing warning fired", () => {
    // A timing countermeasure attached to a non-timing risk is noise that
    // teaches users to ignore the whole box. The specific-amount warning is
    // `high` and a delay does nothing for it — so level is not the trigger.
    const t = text({ amountKind: "specific-amount", publicPayout: false });
    expect(t).toMatch(/fingerprint/i);
    expect(t).not.toMatch(COUNTERMEASURE);
  });
});

describe("T-3b — the countermeasure is coupled to the REASON, not to the wording", () => {
  // SSA-B checkpoint 2026-08-24T17:20:54Z. The first version of this fix chose
  // the countermeasure by matching the rendered prose, which put control flow
  // downstream of user-facing copy — a PM wording change could disconnect it
  // while every timing condition still fired. These arms assert the structural
  // coupling directly. The reason string is a literal here, written from the
  // finding, not imported from the module.
  const TIMING_REASON = "timing-correlation";

  it("tags every timing branch with the reason, and tags nothing else with it", () => {
    const timingInputs: Parameters<typeof privacyWarnings>[0][] = [
      { amountKind: "fixed-denomination", publicPayout: true, msSinceDeposit: 60_000 },
      { amountKind: "fixed-denomination", publicPayout: true, noteOrigin: { kind: "self-shield", msSinceArrival: 1 * HOUR_MS } },
      { amountKind: "fixed-denomination", publicPayout: true, noteOrigin: { kind: "incoming-receipt", msSinceArrival: 1 * HOUR_MS } },
      { amountKind: "fixed-denomination", publicPayout: true, noteOrigin: { kind: "unknown" } },
    ];
    for (const input of timingInputs) {
      expect(privacyWarnings(input).some((w) => w.reason === TIMING_REASON)).toBe(true);
    }
    // The specific-amount warning is `high` and a submission delay does nothing
    // for it: severity is not the trigger, and neither is prose.
    const nonTiming = privacyWarnings({ amountKind: "specific-amount", publicPayout: true });
    expect(nonTiming.some((w) => w.reason === TIMING_REASON)).toBe(false);
  });

  it("renders the countermeasure exactly when a reason-tagged warning is present", () => {
    for (const input of [
      { amountKind: "fixed-denomination", publicPayout: true, msSinceDeposit: 60_000 },
      { amountKind: "specific-amount", publicPayout: true },
      { amountKind: "fixed-denomination", publicPayout: false, msSinceDeposit: 90 * HOUR_MS },
    ] as Parameters<typeof privacyWarnings>[0][]) {
      const ws = privacyWarnings(input);
      const tagged = ws.some((w) => w.reason === "timing-correlation");
      const offered = ws.map((w) => w.msg).join(" | ").match(COUNTERMEASURE) !== null;
      expect(offered).toBe(tagged);
    }
  });
});

describe("T-4 — the strings reach the RENDERED spend page", () => {
  // F-8's gap is that `spend.ts` and the warning library drifted apart, so the
  // page — not the library's return value — is the surface that has to be
  // asserted. Harness mirrored from `wl2a_roundtrip.test.ts`, which pinned the
  // same wiring gap the last time it was found.
  const render = (over: Partial<ScannedNote>, shieldEntries: unknown[]): string => {
    const note: ScannedNote = {
      leafIndex: 3n,
      value: 100_000_000_000n,
      rho: new Uint8Array(32),
      rseed: new Uint8Array(32),
      recipientPk: new Uint8Array(32),
      commitment: new Uint8Array(32).fill(0xab),
      state: "spendable",
      ...over,
    };
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
    return (root.querySelector(".warnings") as HTMLElement).textContent ?? "";
  };

  const recentNs = (BigInt(Date.now()) * MS - 60n * 1000n * MS).toString(10);
  const commitmentHex = "ab".repeat(32);

  it("renders the submitter disclosure, not the old claim", () => {
    const t = render({ firstSeenAtNs: recentNs }, []);
    expect(t).toMatch(SUBMITTER_DISCLOSURE);
    expect(t).toMatch(PERMANENCE);
    expect(t).toMatch(STILL_PRIVATE);
    expect(t).not.toMatch(OLD_FALSE_CLAIM);
  });

  it("renders the countermeasure disclosure alongside a timing warning", () => {
    const t = render({ firstSeenAtNs: recentNs }, [
      { commitmentHex, createdAtNs: recentNs, dispatchedAtNs: recentNs },
    ]);
    expect(t).toMatch(/you shielded this note within the last 24 hours/i);
    expect(t).toMatch(COUNTERMEASURE);
    expect(t).toMatch(COUNTERMEASURE_BOUNDS);
  });
});
