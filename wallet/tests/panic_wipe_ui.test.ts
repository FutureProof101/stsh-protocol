/**
 * A-1b — E6: the panic wipe's consent gate.
 *
 * The destructive action must never be one click away. The entry button only
 * REVEALS the consequences; the wipe itself stays disabled until the user
 * types the confirmation phrase. These tests drive the real account page, so
 * the gate is asserted on the rendered DOM rather than on the intent of the
 * code that builds it.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { WIPE_CONFIRM_PHRASE } from "../src/ui/pages/account";
// WALLET-UX: the wipe moved from the account page to Settings > Security and recovery.
import { renderSettings } from "../src/ui/pages/settings";
import { resolveConfig } from "../src/session/config";
import type { AppContext } from "../src/ui/context";
import type { Enumeration, WipeReport } from "../src/storage/panicWipe";

const NONE: Enumeration = { kind: "ok", items: [] };
const EMPTY_INVENTORY = { indexedDb: NONE, localStorage: NONE, sessionStorage: NONE, cacheStorage: NONE };

function ctxWith(opts: { wipeReport?: WipeReport | null; onWipe?: () => void; loggedIn?: boolean } = {}): AppContext {
  const noop = async (): Promise<void> => undefined;
  return {
    config: resolveConfig({}),
    policy: { kind: "production", iiUrl: undefined, derivationOrigin: undefined },
    state: {
      principal: opts.loggedIn === false ? null : Principal.fromText("aaaaa-aa"),
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
      wipeReport: opts.wipeReport ?? null,
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
    panicWipe: async (): Promise<WipeReport> => {
      opts.onWipe?.();
      return { complete: true, surfaces: [], before: EMPTY_INVENTORY, after: EMPTY_INVENTORY };
    },
  } as unknown as AppContext;
}

function render(ctx: AppContext): HTMLElement {
  const root = document.createElement("div");
  renderSettings(root, ctx);
  return root;
}

const pick = <T extends HTMLElement>(root: HTMLElement, id: string): T =>
  root.querySelector(`[data-testid="${id}"]`) as T;

describe("A-1b E6 — the wipe cannot run without confirmation", () => {
  it("clicking the entry point only reveals the panel; nothing is wiped", () => {
    let wiped = 0;
    const root = render(ctxWith({ onWipe: () => (wiped += 1) }));

    const open = pick<HTMLButtonElement>(root, "panic-wipe-open");
    const panel = pick<HTMLElement>(root, "panic-wipe-panel");
    expect(panel.hasAttribute("hidden"), "the consequences panel starts hidden").toBe(true);

    open.click();

    expect(panel.hasAttribute("hidden")).toBe(false);
    expect(wiped, "the entry button must not perform the wipe").toBe(0);
  });

  it("the confirm button stays disabled until the exact phrase is typed", () => {
    let wiped = 0;
    const root = render(ctxWith({ onWipe: () => (wiped += 1) }));
    pick<HTMLButtonElement>(root, "panic-wipe-open").click();

    const phrase = pick<HTMLInputElement>(root, "panic-wipe-phrase");
    const confirm = pick<HTMLButtonElement>(root, "panic-wipe-confirm");
    expect(confirm.disabled).toBe(true);

    phrase.value = "wipe"; // wrong case — not the phrase
    phrase.dispatchEvent(new Event("input"));
    expect(confirm.disabled, "a near-miss must not enable the wipe").toBe(true);

    phrase.value = WIPE_CONFIRM_PHRASE;
    phrase.dispatchEvent(new Event("input"));
    expect(confirm.disabled).toBe(false);

    confirm.click();
    expect(wiped, "the wipe runs only after the deliberate confirmation").toBe(1);
  });

  it("states what survives, what is destroyed, and the in-flight-spend caveat", () => {
    const root = render(ctxWith());
    pick<HTMLButtonElement>(root, "panic-wipe-open").click();

    expect(pick(root, "wipe-recoverable").textContent).toMatch(/note set/i);
    expect(pick(root, "wipe-destroyed").textContent).toMatch(/intent records/i);
    expect(pick(root, "wipe-liveness-caveat").textContent).toMatch(/cannot be completed/i);
  });

  // WALLET-V13 O-1 (Addendum 1 E-1, revised): moved behind login — same
  // assertion, logged-in fixture. The logged-out absence is asserted in
  // wallet_v13_logged_out_gating.test.ts.
  it("is reachable once logged in (WALLET-V13: gated behind login)", () => {
    const root = render(ctxWith({ loggedIn: true }));
    expect(pick(root, "panic-wipe-open")).not.toBeNull();
  });

  it("renders a partial result per surface instead of a blanket success", () => {
    const report: WipeReport = {
      complete: false,
      surfaces: [
        { surface: "indexeddb:stsh-wallet", cleared: true, detail: "database deleted" },
        { surface: "indexeddb:stsh-wallet-transfers", cleared: false, detail: "deletion BLOCKED by another open connection" },
      ],
      before: { ...EMPTY_INVENTORY, indexedDb: { kind: "ok", items: ["stsh-wallet", "stsh-wallet-transfers"] } },
      after: { ...EMPTY_INVENTORY, indexedDb: { kind: "ok", items: ["stsh-wallet-transfers"] } },
    };
    const root = render(ctxWith({ wipeReport: report }));

    expect(pick(root, "wipe-outcome").textContent).toMatch(/did NOT complete/);
    expect(pick(root, "wipe-surface-indexeddb:stsh-wallet").textContent).toMatch(/cleared/);
    expect(pick(root, "wipe-surface-indexeddb:stsh-wallet-transfers").textContent).toMatch(/NOT CLEARED/);
  });
});
