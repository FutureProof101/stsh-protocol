/**
 * R-7 item 1 (L07-01) — `spend.ts` must pass the REAL amount kind, and the
 * payout-path advice must be achievable on that path.
 *
 * INDEPENDENT EXPECTED SIDE. Every expected string below is a literal regex
 * written here from the finding, never imported from `privacyWarnings.ts`.
 * The only imports from the shipped tree are the surfaces under test
 * (`renderSpend`, `privacyWarnings`).
 */

import { describe, expect, it } from "vitest";

import { privacyWarnings } from "../src/ui/privacyWarnings";
import { renderSpend } from "../src/ui/pages/spend";
import type { AppContext } from "../src/ui/context";
import type { ScannedNote } from "../src/storage/noteCache";

/** The specific-amount warning, in either branch's wording. */
const SPECIFIC_AMOUNT = /exact amount is published on-chain/i;
/** The payout branch's achievable advice. */
const PAYOUT_ADVICE = /no fixed-denomination option on this payout path/i;
/** The non-payout branch's preserved advice. */
const NON_PAYOUT_ADVICE = /fixed-denomination withdrawals all look identical/i;

const renderWarnings = (payoutOn: boolean): string => {
  const note: ScannedNote = {
    leafIndex: 3n,
    value: 100_000_000_000n,
    rho: new Uint8Array(32),
    rseed: new Uint8Array(32),
    recipientPk: new Uint8Array(32),
    commitment: new Uint8Array(32).fill(0xab),
    state: "spendable",
  };
  const ctx = {
    state: {
      notes: [note],
      shieldEntries: [],
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
  toggle.checked = payoutOn;
  toggle.dispatchEvent(new Event("change"));
  if (payoutOn) {
    // A valid net figure, entered the way a user would. The warning does not
    // depend on the figure's value — only on the fact that one is published.
    const net = root.querySelector(
      'input[placeholder="Recipient net amount (STSH)"]',
    ) as HTMLInputElement;
    net.value = "5";
    net.dispatchEvent(new Event("input"));
  }
  return (root.querySelector(".warnings") as HTMLElement).textContent ?? "";
};

describe("R-7 AC-1 — the rendered spend page reports the amount kind it actually publishes", () => {
  it("AC-1a: payout ON renders the specific-amount warning", () => {
    expect(renderWarnings(true)).toMatch(SPECIFIC_AMOUNT);
  });

  it("AC-1b: payout OFF renders NO specific-amount warning", () => {
    expect(renderWarnings(false)).not.toMatch(SPECIFIC_AMOUNT);
  });
});

describe("R-7 AC-1d/1e — the two specific-amount branches say different, true things", () => {
  const msgs = (publicPayout: boolean): string =>
    privacyWarnings({ amountKind: "specific-amount", publicPayout })
      .filter((w) => w.level === "high")
      .map((w) => w.msg)
      .join(" | ");

  it("AC-1d: the payout branch gives advice reachable on the payout path", () => {
    const t = msgs(true);
    expect(t).toMatch(PAYOUT_ADVICE);
    expect(t).not.toMatch(NON_PAYOUT_ADVICE);
  });

  it("AC-1e: the non-payout branch keeps its original advice, verbatim", () => {
    const t = msgs(false);
    expect(t).toMatch(NON_PAYOUT_ADVICE);
    expect(t).not.toMatch(PAYOUT_ADVICE);
  });

  it("AC-1e: `publicPayout` omitted behaves as the non-payout branch", () => {
    const t = privacyWarnings({ amountKind: "specific-amount" })
      .map((w) => w.msg)
      .join(" | ");
    expect(t).toMatch(NON_PAYOUT_ADVICE);
  });
});
