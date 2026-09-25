/**
 * WALLET-UI (Owner 2026-09-23) — plain-language copy: spend mode helpers,
 * shield exit disclosure, Settings "How it works". Literals written here.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { renderSettings } from "../src/ui/pages/settings";
import { renderShield } from "../src/ui/pages/shield";
import { renderSpend, SPEND_STAGES } from "../src/ui/pages/spend";
import { shieldAmountErrorLines } from "../src/ui/format";
import type { ShieldFeeParams } from "../src/actors/pool";
import { resolveConfig } from "../src/session/config";
import type { AppContext } from "../src/ui/context";
import type { Enumeration } from "../src/storage/panicWipe";

const NONE: Enumeration = { kind: "ok", items: [] };
const EMPTY_INVENTORY = { indexedDb: NONE, localStorage: NONE, sessionStorage: NONE, cacheStorage: NONE };
const noop = async (): Promise<void> => undefined;

function settingsCtx(): AppContext {
  return {
    config: resolveConfig({}),
    policy: { kind: "production", iiUrl: undefined, derivationOrigin: undefined },
    state: {
      principal: Principal.fromText("aaaaa-aa"),
      balance: null,
      busy: false,
      status: null,
      cacheUnlocked: false,
      shieldEntries: null,
      notes: [],
      scanning: false,
      scanProgress: null,
      mirrorHead: null,
      quarantineTotal: 0,
      wipeReport: null,
    },
    readActors: {
      token: {
        balanceOf: async () => 0n,
        metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
        fee: async () => 0n,
      },
      staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
      vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
    },
    mutationActors: null,
    shieldedActors: null,
    pendingIntent: null,
    navigate: () => undefined,
    refresh: () => undefined,
    login: noop,
    logout: noop,
    refreshBalance: noop,
    transfer: noop,
    retryPendingIntent: noop,
    abandonFrozenIntent: noop,
    unlockNoteCache: noop,
    shield: noop,
    reconcileShieldJournal: noop,
    revokeShieldAllowance: noop,
    cancelPlannedShield: noop,
    abandonAmbiguousShieldEntry: noop,
    scan: noop,
    spend: noop,
    recoverSpends: noop,
    panicWipe: async () => ({ complete: true, surfaces: [], before: EMPTY_INVENTORY, after: EMPTY_INVENTORY }),
  } as unknown as AppContext;
}

describe("WALLET-UI plain-language copy", () => {
  it("Settings shows the three How-it-works lines", () => {
    const root = document.createElement("div");
    renderSettings(root, settingsCtx());
    const t = root.textContent ?? "";
    expect(t).toContain("How it works");
    // WALLET-UI fix: "Breaks" overclaimed (SSA Q2 class, privacyWarnings:253).
    // WALLET-CACHE-II-ONLY: DS-55 / DS-56 (disclosure sweep d6b6632b) replace
    // the re-shield and withdraw lines verbatim — "weakens the timing link"
    // and "the sending account is hidden too" both overclaimed. O-6 splits the
    // payout line into one idea per line.
    expect(t).toContain("Re-shield: your note becomes a new note. Your account signs it. It does not unlink you.");
    expect(t).not.toContain("Breaks the timing link");
    expect(t).not.toContain("Weakens the timing link");
    expect(t).toContain("Public payout: part of a note goes to a public account.");
    expect(t).toContain("Recipient and amount are public. Your account signs the call.");
    expect(t).toContain("Withdraw is not built. Whether it can hide the sending account is not yet decided.");
  });

  it("Shield shows the exit disclosure", () => {
    const root = document.createElement("div");
    renderShield(root, {
      state: { principal: { toText: () => "aaaaa-aa" }, notes: [], shieldEntries: [], busy: false, status: null },
      shield: noop,
      reconcileShieldJournal: noop,
      revokeShieldAllowance: noop,
      cancelPlannedShield: noop,
      abandonAmbiguousShieldEntry: noop,
      refresh: () => {},
      navigate: () => {},
    } as unknown as AppContext);
    // O-6: one idea per line — the same three facts, three lines.
    const exitLines = Array.from(root.querySelectorAll('[data-testid="shield-exit-disclosure"] p')).map((p) => p.textContent);
    expect(exitLines).toEqual([
      "Shielded funds leave only by public payout.",
      "Recipient, amount and your account are visible when they do.",
      "Private withdraw: later release.",
    ]);
    // Addendum 2 item 7: visible without scrolling — it is the first thing
    // after the page head, before the amount field and before Shield.
    const exit = root.querySelector('[data-testid="shield-exit-disclosure"]')!;
    const amount = root.querySelector('input[aria-label="Amount in STSH (e.g. 123)"]')!;
    expect(exit).not.toBeNull();
    expect(exit.compareDocumentPosition(amount) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("Spend shows both mode helper lines", () => {
    const root = document.createElement("div");
    renderSpend(root, {
      state: {
        notes: [
          {
            leafIndex: 3n,
            value: 100_000_000_000n,
            rho: new Uint8Array(32),
            rseed: new Uint8Array(32),
            recipientPk: new Uint8Array(32),
            commitment: new Uint8Array(32).fill(0xab),
            state: "spendable",
          },
        ],
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
    } as unknown as AppContext);
    const t = root.textContent ?? "";
    expect(t).toContain("This note becomes a new note. Nothing leaves the pool. Nobody is paid.");
    expect(t).toContain("Your account signs it. The note amount is not shown.");
    // Law 5: no fee figure until the LIVE basis is present.
    expect(root.querySelector('[data-testid="mode-helper-self-fee"]')?.textContent).toBe(
      "Fee: loading the live fee.",
    );
    expect(t).not.toContain("2.5 STSH");
    // DS-54 (disclosure sweep d6b6632b): the single-deposit sentence is APPENDED.
    expect(t).toContain(
      "Pay a public account. Recipient, amount and your account are visible on-chain. Which note paid is hidden. " +
        "If you deposited only once, the payout is linkable to that deposit.",
    );
  });

  it("Re-shield fee is the live protocol spend fee, not a constant", () => {
    const render = (fee: bigint) => {
      const root = document.createElement("div");
      renderSpend(root, spendCtx({ params: { ...PARAMS, protocolPrivateSpendFeeStsh: fee }, ledgerFee: 0n }));
      return root.querySelector('[data-testid="mode-helper-self-fee"]')?.textContent;
    };
    expect(render(250_000_000n)).toBe("Fee 2.5 STSH, taken from the note.");
    expect(render(300_000_000n)).toBe("Fee 3 STSH, taken from the note.");
  });

  it("the page title makes no identity claim and states the II-signer qualifier", () => {
    const root = document.createElement("div");
    renderSpend(root, spendCtx(null));
    const t = root.textContent ?? "";
    expect(t).not.toContain("Send privately");
    expect(t).not.toMatch(/who (paid|sent)[^.]*stays private/i);
    // DS-53 (disclosure sweep d6b6632b, verbatim).
    expect(t).toContain(
      "Your Internet Identity signs every spend, publicly and permanently. One deposit means your spend is linkable.",
    );
  });

  it("the spend action is in the sticky action bar, after the warnings", () => {
    const root = document.createElement("div");
    renderSpend(root, spendCtx(null));
    const bar = root.querySelector('[data-testid="spend-actions"]')!;
    expect(bar).not.toBeNull();
    expect(bar.classList.contains("sticky-actions")).toBe(true);
    expect(bar.querySelector("button.primary")).not.toBeNull();
    const warnings = root.querySelector(".warnings")!;
    expect(warnings.compareDocumentPosition(bar) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("an in-flight spend shows stages with durations, not a bare greyed button", () => {
    const local = document.createElement("div");
    renderSpend(local, spendCtx(null, { busy: true, spendLocallyCancellable: true }));
    const stagesLocal = local.querySelector('[data-testid="spend-stages"]')!;
    expect(stagesLocal).not.toBeNull();
    expect(stagesLocal.textContent).toContain(SPEND_STAGES.prove);
    expect(stagesLocal.textContent).toContain(SPEND_STAGES.submit);
    expect(stagesLocal.textContent).not.toContain(SPEND_STAGES.delay);
    const nowLocal = stagesLocal.querySelector('[data-stage-state="now"]');
    expect(nowLocal?.textContent).toBe(SPEND_STAGES.prove);
    // The stages sit in the sticky bar with the button, so they are on screen.
    expect(local.querySelector('[data-testid="spend-actions"] [data-testid="spend-stages"]')).not.toBeNull();

    const sent = document.createElement("div");
    renderSpend(sent, spendCtx(null, { busy: true, spendLocallyCancellable: false, submissionDelayEnabled: true }));
    const stagesSent = sent.querySelector('[data-testid="spend-stages"]')!;
    expect(stagesSent.textContent).toContain(SPEND_STAGES.delay);
    expect(stagesSent.querySelector('[data-stage-state="now"]')?.textContent).toBe(SPEND_STAGES.submit);
    expect(sent.textContent).not.toContain("Cancel local work");
  });

  it("the shield decomposition refusal is in STSH and names what fits", () => {
    const lines = shieldAmountErrorLines("Amount 150000000000 is not decomposable into fixed denominations");
    expect(lines).toEqual([
      "1,500 STSH can't be split into notes.",
      "Notes come in 1,000 / 10,000 / 100,000 / 1,000,000 / 10,000,000 STSH.",
      "Nearest that fits: 1,000 STSH (1 × 1,000).",
    ]);
    expect(lines!.join(" ")).not.toContain("150000000000");
    expect(shieldAmountErrorLines("Amount 50000000000 is not decomposable into fixed denominations")).toEqual([
      "500 STSH can't be split into notes.",
      "Notes come in 1,000 / 10,000 / 100,000 / 1,000,000 / 10,000,000 STSH.",
      "Smallest amount: 1,000 STSH.",
    ]);
    expect(shieldAmountErrorLines("some other failure")).toBeNull();
  });

  it("Settings discloses every automatic call and offers the operator check only on a press", async () => {
    const calls: string[] = [];
    const ctx = settingsCtx();
    (ctx as unknown as { checkOperatorAccess: () => Promise<void> }).checkOperatorAccess = async () => {
      calls.push("checkOperatorAccess");
    };
    const root = document.createElement("div");
    renderSettings(root, ctx);
    const auto = root.querySelector('[data-testid="settings-automatic-calls"]')?.textContent ?? "";
    expect(auto).toContain("Sign-in: reads your public balance.");
    expect(auto).toContain("one key request, to start the wallet's preparation clock.");
    // WALLET-CACHE-II-ONLY: the cache now opens at sign-in, so the lookup is
    // disclosed against the open, and the open itself is disclosed (SSA B3).
    expect(auto).toContain(
      "Opening your private balance: looks up interrupted spends. Read only; any repair waits for you.",
    );
    expect(auto).toContain("Sign-in: fetches this device's encrypted key and opens your private balance. No new key request.");
    expect(auto).not.toMatch(/Nothing else reads/);
    // Rendering Settings makes no signer call; only the press does.
    expect(calls).toEqual([]);
    const btn = root.querySelector('[data-testid="check-operator-access"]') as HTMLButtonElement;
    expect(btn).not.toBeNull();
    btn.click();
    expect(calls).toEqual(["checkOperatorAccess"]);
  });
});

const PARAMS: ShieldFeeParams = {
  shieldFeeBps: 25,
  shieldFlatMinimumFeeE8s: 250_000_000n,
  minimumPrivateCredit: 0n,
  feeModelVersion: 1,
  paramsEpoch: 0n,
  protocolPrivateSpendFeeStsh: 250_000_000n,
  unshieldFeeBps: 25,
  unshieldFlatMinimumFeeE8s: 250_000_000n,
};

function spendCtx(
  basis: { params: ShieldFeeParams; ledgerFee: bigint } | null,
  over: { busy?: boolean; spendLocallyCancellable?: boolean; submissionDelayEnabled?: boolean } = {},
): AppContext {
  return {
    state: {
      notes: [
        {
          leafIndex: 3n,
          value: 100_000_000_000n,
          rho: new Uint8Array(32),
          rseed: new Uint8Array(32),
          recipientPk: new Uint8Array(32),
          commitment: new Uint8Array(32).fill(0xab),
          state: "spendable",
        },
      ],
      shieldEntries: [],
      busy: over.busy ?? false,
      spendLocallyCancellable: over.spendLocallyCancellable ?? false,
      status: null,
      spendFeeBasis: basis,
      submissionDelayEnabled: over.submissionDelayEnabled ?? false,
      pendingDelay: null,
      pendingRecovery: [],
    },
    refresh: () => {},
    navigate: () => {},
    loadSpendFeeBasis: async () => {},
    spend: async () => {},
  } as unknown as AppContext;
}
