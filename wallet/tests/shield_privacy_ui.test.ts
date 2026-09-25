/**
 * R-7 items 3 (U-2) and 4 (L07-02 / CC-02) — the SHIELD page's privacy copy.
 *
 * INDEPENDENT EXPECTED SIDE. Every regex below is written here from the
 * finding; nothing is imported from `privacyWarnings.ts` and compared against
 * itself. The imports from the shipped tree are the surfaces under test.
 *
 * SURFACE. `mountShield()` ATTACHES `root` to `document.body` (precedent:
 * `shield_app_l3a.test.ts`, `scan_app_l3b.test.ts`, `journal_cas_ac1.test.ts`),
 * so the item-4 assertions against `document.body.textContent` read the real
 * combined page text a user sees — not `""`. An unattached harness would make
 * them vacuous.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { renderShield } from "../src/ui/pages/shield";
import { shieldPrivacyWarnings } from "../src/ui/privacyWarnings";
import type { AppContext } from "../src/ui/context";

/**
 * The allowance disclosure (item 3, warning ii), on the V1a literal.
 *
 * V1a (CTO ruling `cto-ruling-r7-landed-diff-ambers-2026-09-06`, item 1): the
 * V1 copy claimed the approved total was "permanently-readable ... whether or
 * not the deposit itself has completed". Both halves are false against this
 * ledger — `icrc2_transfer_from` DECREMENTS the allowance record as it is
 * spent and `icrc2_allowance` returns zero once it is consumed or expired
 * (`canisters/token/src/lib.rs`), and the hand-rolled ledger publishes no
 * ICRC-3 block/transaction history at all (`grep -c icrc3
 * canisters/token/stsh_token.did` -> 0), so nothing retains the figure after
 * the approval ends. The disclosure now bounds the window instead.
 */
const ALLOWANCE = /publicly readable through\s+icrc2_allowance/i;
/** The window bound the disclosure must state, not just imply. */
const ALLOWANCE_WINDOW = /until the approval is spent or expires/i;
/** No ICRC-3 history — the reason the figure is not retained afterwards. */
const NO_HISTORY = /no public transaction history/i;
/**
 * The permanence overclaim V1a removes. It must not survive in any form, in
 * the copy module's source, the shield page's source, or the rendered DOM.
 */
const PERMANENCE_OVERCLAIM = /permanently[- ]readable|permanently readable|whether or not the deposit/i;
/** The decomposition-shape disclosure (item 3, warning i). */
const SHAPE = /distinct denomination/i;
/** The false claim item 4 removes. It must not survive in any form. */
const OLD_FALSE_CLAIM = /every deposit looks identical on-chain/i;
/** The true claim that replaces it. */
const SAME_DENOMINATION = /same denomination/i;
/** Any restatement of cross-denomination identity. */
const CROSS_DENOMINATION_IDENTITY = /every deposit .* identical/i;

const noop = async (): Promise<void> => undefined;

/** Deposit-side context: only what `renderShield` actually reads. */
function shieldCtx(): AppContext {
  return {
    state: {
      principal: { toText: () => "aaaaa-aa" },
      notes: [],
      shieldEntries: [],
      busy: false,
      status: null,
    },
    shield: noop,
    reconcileShieldJournal: noop,
    revokeShieldAllowance: noop,
    cancelPlannedShield: noop,
    abandonAmbiguousShieldEntry: noop,
    refresh: () => {},
    navigate: () => {},
  } as unknown as AppContext;
}

/** Mounts the shield page into the LIVE document and returns its root. */
function mountShield(): HTMLElement {
  const root = document.createElement("div");
  document.body.append(root);
  renderShield(root, shieldCtx());
  return root;
}

/** Types an amount the way a user would, and returns the page root. */
function mountWithAmount(amount: string): HTMLElement {
  const root = mountShield();
  const input = root.querySelector("input.amount") as HTMLInputElement;
  input.value = amount;
  input.dispatchEvent(new Event("input"));
  return root;
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("R-7 AC-3 — the shield page discloses what a deposit publishes", () => {
  it("AC-3d: the harness mounts the real page and it renders something", () => {
    const root = mountShield();
    expect(() => renderShield(root, shieldCtx())).not.toThrow();
    expect((root.textContent ?? "").length).toBeGreaterThan(0);
    // ...and it is genuinely in the document, which items 3/4 assert against.
    expect(document.body.contains(root)).toBe(true);
  });

  it("AC-3a: a valid amount renders BOTH the shape and the allowance disclosure", () => {
    const t = mountWithAmount("123000").textContent ?? "";
    expect(t).toMatch(ALLOWANCE);
    expect(t).toMatch(SHAPE);
  });

  it("AC-3e (V1a): the allowance disclosure BOUNDS the window and states why", () => {
    const t = mountWithAmount("123000").textContent ?? "";
    expect(t, "the disclosure must say when public readability ends").toMatch(ALLOWANCE_WINDOW);
    expect(t, "the disclosure must say the ledger keeps no ICRC-3 history").toMatch(NO_HISTORY);
  });

  it("AC-3a: no amount entered renders neither (nothing to disclose yet)", () => {
    const t = mountShield().textContent ?? "";
    expect(t).not.toMatch(ALLOWANCE);
    expect(t).not.toMatch(SHAPE);
  });

  it("AC-3c: the allowance warning is UNCONDITIONAL across every bucket shape", () => {
    for (const amount of ["1000", "11000", "111000", "1111000"]) {
      document.body.innerHTML = "";
      const t = mountWithAmount(amount).textContent ?? "";
      expect(t, `allowance disclosure missing for ${amount} STSH`).toMatch(ALLOWANCE);
    }
  });

  it("AC-3b: `shieldPrivacyWarnings` is pure — identical input, identical output", () => {
    const input = { bucketCount: 4, totalDenominations: 3 };
    const a = JSON.stringify(shieldPrivacyWarnings(input));
    const b = JSON.stringify(shieldPrivacyWarnings(input));
    const c = JSON.stringify(shieldPrivacyWarnings({ ...input }));
    expect(a).toBe(b);
    expect(a).toBe(c);
  });

  it("AC-3b: no plan (bucketCount 0) returns no warnings at all", () => {
    expect(shieldPrivacyWarnings({ bucketCount: 0, totalDenominations: 0 })).toEqual([]);
  });

  it("AC-3c: the allowance warning is present for every bucket count, at the function", () => {
    for (const bucketCount of [1, 2, 3, 4]) {
      const msgs = shieldPrivacyWarnings({ bucketCount, totalDenominations: 1 }).map((w) => w.msg);
      expect(msgs.join(" | "), `bucketCount=${bucketCount}`).toMatch(ALLOWANCE);
    }
  });
});

describe("R-7 AC-4 — the shield page no longer claims deposits are identical", () => {
  it("AC-4c (V1a): no permanence overclaim survives, in either source or the DOM", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const f of ["../src/ui/pages/shield.ts", "../src/ui/privacyWarnings.ts"]) {
      const src = readFileSync(resolve(here, f), "utf8");
      // Only the STRING content is under test. Comments are stripped first:
      // the JSDoc above each site explains why permanence is false and so
      // legitimately names the phrase it forbids in user-facing copy.
      const code = src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
      const strings = [...code.matchAll(/"([^"\\]*)"/g)].map((m) => m[1] as string).join(" ");
      expect(strings, `permanence overclaim survives in ${f}`).not.toMatch(PERMANENCE_OVERCLAIM);
    }
    mountWithAmount("123000");
    expect(document.body.textContent ?? "").not.toMatch(PERMANENCE_OVERCLAIM);
  });

  it("AC-4a: the old false sentence is absent from the source AND the rendered DOM", () => {
    const src = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), "../src/ui/pages/shield.ts"),
      "utf8",
    );
    expect(src).not.toMatch(OLD_FALSE_CLAIM);
    mountWithAmount("123000");
    expect(document.body.textContent ?? "").not.toMatch(OLD_FALSE_CLAIM);
  });

  it("AC-4b: the page claims same-denomination identity, never cross-denomination", () => {
    mountWithAmount("123000");
    const t = document.body.textContent ?? "";
    expect(t).toMatch(SAME_DENOMINATION);
    expect(t).not.toMatch(CROSS_DENOMINATION_IDENTITY);
  });
});
