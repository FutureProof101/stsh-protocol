/**
 * WL-3 — the max-spendable figure tells the fee-funded-from-note truth.
 *
 * The shipped defect: the spend page bounded a payout by `net < note.value`,
 * so a top-rung note looked able to exit its full face value. It cannot — the
 * exit protocol fee is funded FROM the note, so on the A6.6 top rung
 * (10,000,000 STSH) the largest gross that clears is ~9,975,062.344 STSH, and
 * the recipient sees one ledger fee less than that again.
 *
 * The ~9,975,062.344 figure is never written into production code, and it is not
 * written into the ASSERTIONS from memory either: the parameters come out of
 * the A-7 fixture, whose rows are the CANISTER's own answers, and the expected
 * maximum is the fixture row the pool itself produced.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  FeeModelUnsupportedError,
  maxPublicAmount,
  maxRecipientNet,
  unshieldProtocolFee,
} from "../src/crypto/fees";
import { renderSpend } from "../src/ui/pages/spend";
import type { AppContext } from "../src/ui/context";
import type { ShieldFeeParams } from "../src/actors/pool";
import type { ScannedNote } from "../src/storage/noteCache";

interface FeeTable {
  unshield_fee_bps: number;
  flat_minimum_e8s: string;
  rows: Array<{ public_amount_e8s: string; fee_e8s: string }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const table = JSON.parse(
  readFileSync(join(here, "fixtures/a7_exit_fee_table.json"), "utf8"),
) as FeeTable;

const params: ShieldFeeParams = {
  shieldFeeBps: table.unshield_fee_bps,
  shieldFlatMinimumFeeE8s: BigInt(table.flat_minimum_e8s),
  minimumPrivateCredit: 0n,
  feeModelVersion: 1,
  paramsEpoch: 0n,
  protocolPrivateSpendFeeStsh: 250_000_000n, // 2.5 STSH (A6.6, OWNER_RULING_FEE_FLOOR_2_5_STSH)
  unshieldFeeBps: table.unshield_fee_bps,
  unshieldFlatMinimumFeeE8s: BigInt(table.flat_minimum_e8s),
};

/** The 10,000,000-STSH top-rung note the disclosure row is about (A6.6 ladder). */
const NOTE_VALUE = 1_000_000_000_000_000n;
/** The largest gross, as the CANISTER stated it in the A-7 fixture. */
const FIXTURE_MAX = BigInt(
  table.rows.find((r) => BigInt(r.public_amount_e8s) + BigInt(r.fee_e8s) === NOTE_VALUE)
    ?.public_amount_e8s ?? "0",
);

// A non-zero ledger fee is MANDATORY for the boundary rows: the net-vs-gross
// defect is exactly one ledger fee wide, so at fee 0 it is invisible.
const LEDGER_FEE = 10_000n;

const note = (value: bigint): ScannedNote => ({
  leafIndex: 7n,
  value,
  rho: new Uint8Array(32),
  rseed: new Uint8Array(32),
  recipientPk: new Uint8Array(32),
  nonce: new Uint8Array(16),
  commitment: new Uint8Array(32).fill(9),
  nullifier: new Uint8Array(32).fill(8),
  state: "spendable",
});

function stubCtx(over: {
  notes: ScannedNote[];
  basis: { params: ShieldFeeParams; ledgerFee: bigint } | null;
  onSpend?: (input: unknown) => void;
}): AppContext {
  const state = {
    principal: null,
    balance: null,
    busy: false,
    status: null as { kind: string; msg: string } | null,
    cacheUnlocked: true,
    shieldEntries: [],
    notes: over.notes,
    scanning: false,
    scanProgress: null,
    mirrorHead: null,
    quarantineTotal: 0,
    wipeReport: null,
    submissionDelayEnabled: false,
    pendingDelay: null,
    spendFeeBasis: over.basis,
    pendingRecovery: [],
  };
  return {
    state,
    refresh: () => {},
    navigate: () => {},
    loadSpendFeeBasis: async () => {},
    spend: async (input: unknown) => {
      over.onSpend?.(input);
    },
  } as unknown as AppContext;
}

const setPayout = (root: HTMLElement, netText: string) => {
  const toggle = root.querySelector("#payout-toggle") as HTMLInputElement;
  toggle.checked = true;
  toggle.dispatchEvent(new Event("change"));
  // WALLET-SHIELD-LAYER1 (Addendum A item 7): "Whole note" is now the default
  // amount mode, which fills and locks the amount at the note's maximum. These
  // arms type a SPECIFIC net figure, so they choose "Custom amount" first, as
  // a user would. Setup only — every assertion below is unchanged.
  const custom = Array.from(root.querySelectorAll<HTMLButtonElement>(".segmented .seg")).find(
    (b) => b.textContent === "Custom amount",
  );
  if (custom === undefined) throw new Error("no 'Custom amount' segment rendered");
  custom.click();
  const inputs = Array.from(root.querySelectorAll("input.amount")) as HTMLInputElement[];
  inputs[0].value = "aaaaa-aa";
  inputs[1].value = netText;
  inputs[1].dispatchEvent(new Event("input"));
};

describe("WL-3 — the derived maximum", () => {
  it("has a non-vacuous fixture row to check against", () => {
    expect(FIXTURE_MAX).toBeGreaterThan(0n);
    expect(table.unshield_fee_bps).toBe(25);
  });

  it("is EXACTLY the canister's own boundary row for the top-rung note", () => {
    const max = maxPublicAmount(NOTE_VALUE, params);
    expect(max).toBe(FIXTURE_MAX);
    // ...and it is genuinely maximal: the gross fits, one e8s more does not.
    expect(max + unshieldProtocolFee(max, params)).toBeLessThanOrEqual(NOTE_VALUE);
    expect(max + 1n + unshieldProtocolFee(max + 1n, params)).toBeGreaterThan(NOTE_VALUE);
    // ...and strictly below the note's face value — the disclosure this row exists for.
    expect(max).toBeLessThan(NOTE_VALUE);
  });

  it("holds on the FLAT arm too (a small note is bounded by the flat minimum)", () => {
    const small = 10_000_000_000n; // 100 STSH — below the 1,000-STSH crossover (A6.6)
    const max = maxPublicAmount(small, params);
    expect(max + unshieldProtocolFee(max, params)).toBeLessThanOrEqual(small);
    expect(max + 1n + unshieldProtocolFee(max + 1n, params)).toBeGreaterThan(small);
    expect(max).toBe(small - BigInt(table.flat_minimum_e8s));
  });

  it("is ZERO when the flat minimum alone exceeds the note (never negative, never the value)", () => {
    const tiny = BigInt(table.flat_minimum_e8s) - 1n;
    expect(maxPublicAmount(tiny, params)).toBe(0n);
  });

  it("FAILS CLOSED on an unpriceable fee model — it never falls back to the note value", () => {
    const future = { ...params, feeModelVersion: 2 };
    expect(() => maxPublicAmount(NOTE_VALUE, future)).toThrow(FeeModelUnsupportedError);
    expect(() => maxRecipientNet(NOTE_VALUE, LEDGER_FEE, future)).toThrow(FeeModelUnsupportedError);
  });

  it("distinguishes the displayed recipient maximum from the gross maximum", () => {
    const gross = maxPublicAmount(NOTE_VALUE, params);
    const net = maxRecipientNet(NOTE_VALUE, LEDGER_FEE, params);
    expect(net).toBe(gross - LEDGER_FEE);
    // The whole point of two names: at a non-zero ledger fee they DIFFER, and
    // a UI that showed the gross as a recipient maximum would be one fee wrong.
    expect(net).not.toBe(gross);
  });
});

describe("WL-3 — through the RENDERED spend page", () => {
  it("quotes the recipient maximum and the gross, and says the fee comes from the note", () => {
    const root = document.createElement("div");
    renderSpend(root, stubCtx({ notes: [note(NOTE_VALUE)], basis: { params, ledgerFee: LEDGER_FEE } }));
    setPayout(root, "1");
    const text = (root.querySelector(".max-exit") as HTMLElement).textContent ?? "";
    expect(text).toContain("9,975,062.34413966"); // the recipient maximum, formatted
    expect(text).toMatch(/paid FROM the note/i);
    // The RAW note value must not be presented as what can be sent.
    expect(text).not.toMatch(/Most this note can send: 10,000,000 STSH/);
  });

  it("ACCEPTS a payout whose GROSS equals the maximum and REJECTS one e8s more", () => {
    const maxNet = maxRecipientNet(NOTE_VALUE, LEDGER_FEE, params);
    for (const [netUnits, shouldSubmit] of [
      [maxNet, true],
      [maxNet + 1n, false],
    ] as const) {
      const submitted: unknown[] = [];
      const ctx = stubCtx({
        notes: [note(NOTE_VALUE)],
        basis: { params, ledgerFee: LEDGER_FEE },
        onSpend: (i) => submitted.push(i),
      });
      const root = document.createElement("div");
      renderSpend(root, ctx);
      // Feed the exact base units through the page's own parser path.
      const whole = netUnits / 100_000_000n;
      const frac = (netUnits % 100_000_000n).toString(10).padStart(8, "0");
      setPayout(root, `${whole}.${frac}`);
      (root.querySelector("button.primary") as HTMLButtonElement).click();
      expect(submitted.length).toBe(shouldSubmit ? 1 : 0);
      if (!shouldSubmit) {
        expect(ctx.state.status?.msg ?? "").toMatch(/at most/i);
      }
    }
  });

  it("refuses to quote or submit a payout while the live basis is unknown (fail closed)", () => {
    const submitted: unknown[] = [];
    const ctx = stubCtx({ notes: [note(NOTE_VALUE)], basis: null, onSpend: (i) => submitted.push(i) });
    const root = document.createElement("div");
    renderSpend(root, ctx);
    setPayout(root, "1");
    expect((root.querySelector(".max-exit") as HTMLElement).textContent ?? "").toMatch(
      /will not quote a maximum/i,
    );
    (root.querySelector("button.primary") as HTMLButtonElement).click();
    expect(submitted.length).toBe(0);
  });
});
