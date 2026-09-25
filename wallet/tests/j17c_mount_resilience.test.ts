/**
 * J-17c — the mount must reach `router.start()` when the app canisters do not
 * exist yet.
 *
 * Bundle f53f21b4, live at app.stsh.fi on 2026-09-11, threw
 * `InputError: Canister ID is required` out of `buildReadActors` BEFORE
 * `router.start()`, so NO route resolved — including `#/operator`, the one
 * surface that has to work before the token/staking/vesting canisters are born
 * at J-18 and installed at A-7.
 *
 * These arms drive the real `mountApp` (the function `main.ts` calls), not a
 * component. Reverting any of the three pre-router guards fails one of them.
 *
 * Arm (d) is the anti-vacuous half: (a) alone still passes if every OTHER page
 * throws, and it says nothing about whether a missing ledger renders as a
 * refusal or as a fabricated zero. (d) asserts the refusal testid AND the
 * absence of any amount text.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { mountApp, type AppDeps } from "../src/ui/app";
import { READ_SERVICES_UNAVAILABLE } from "../src/ui/context";
import { memoryJournalStore } from "./helpers/memoryJournalStore";

const PRODUCTION_ORIGIN = "https://app.stsh.fi";

/** The three ids that are `""` in the shipped config until J-18/A-7. */
const UNCONFIGURED_ENV: Record<string, string | undefined> = {};

const workingAuth = {
  restore: async () => null,
  login: async () => {
    throw new Error("not scripted");
  },
  logout: async () => {},
  verify: () => "valid" as const,
};

const workingReadActors = {
  token: {
    balanceOf: async () => 0n,
    metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
    fee: async () => 0n,
  },
  staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
  vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
};

function deps(over: Partial<AppDeps> = {}): AppDeps {
  return {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () => workingReadActors as never,
    buildMutationActors: async () => ({}) as never,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => workingAuth,
    ...over,
  } as AppDeps;
}

/**
 * The REAL production failure, reproduced at the dep boundary: this is exactly
 * what `createTokenActor("")` throws inside `createReadActors`.
 */
function throwingReadActors(): AppDeps["buildReadActors"] {
  return async () => {
    throw new Error("Canister ID is required, but received string instead");
  };
}

function container(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

beforeEach(() => {
  window.location.hash = "";
  document.body.innerHTML = "";
});

describe("J-17c — mount survives unconfigured read services", () => {
  // ── (a) the reported bug ────────────────────────────────────────────────
  it("starts the router and renders #/operator when read-actor construction throws", async () => {
    window.location.hash = "#/operator";
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildReadActors: throwingReadActors(),
    }));

    // The router ran: the operator section exists at all. Before this lane the
    // mount rejected here and the container held the pre-router Account paint.
    const operator = root.querySelector('[data-testid="operator"]');
    expect(operator).not.toBeNull();
    // Anonymous, so the page is in its "log in to sign" branch — with a button.
    expect(root.querySelector('[data-testid="operator-session-required"]')).not.toBeNull();
    const buttons = Array.from(root.querySelectorAll("button")).map((b) => b.textContent);
    expect(buttons).toContain("Log in");

    // Refusal recorded, not papered over.
    expect(ctx.readActors).toBeNull();
    expect(root.querySelector('[data-testid="read-services-notice"]')?.textContent).toBe(
      READ_SERVICES_UNAVAILABLE,
    );
  });

  // ── (b) SSA R-1: the second un-guarded pre-router await ─────────────────
  it("starts the router when createAuth rejects (blocked IndexedDB / private mode)", async () => {
    window.location.hash = "#/operator";
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildReadActors: throwingReadActors(),
      createAuth: (async () => {
        throw new Error("indexedDB is not available in this context");
      }) as never,
    }));

    expect(root.querySelector('[data-testid="operator"]')).not.toBeNull();
    expect(ctx.state.principal).toBeNull();
    // The user is told login is unavailable rather than seeing a dead page.
    expect(root.textContent).toContain("Login is unavailable");
    expect(root.querySelector('[data-testid="read-services-notice"]')).not.toBeNull();
  });

  it("starts the router when buildPoolIdentityReader rejects", async () => {
    window.location.hash = "#/operator";
    const root = container();
    await mountApp(root, UNCONFIGURED_ENV, deps({
      buildPoolIdentityReader: (async () => {
        throw new Error("agent could not reach the boundary node");
      }) as never,
    }));
    expect(root.querySelector('[data-testid="operator"]')).not.toBeNull();
  });

  // ── (c) no behaviour change when the ids ARE configured ─────────────────
  it("keeps readActors non-null and shows NO notice when construction succeeds", async () => {
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps());
    expect(ctx.readActors).not.toBeNull();
    expect(root.querySelector('[data-testid="read-services-notice"]')).toBeNull();
    expect(root.textContent ?? "").not.toContain(READ_SERVICES_UNAVAILABLE);
  });

  // ── (d) anti-vacuous: refusal, NOT a zero ───────────────────────────────
  it.each([
    ["#/staking", "staking-unavailable", "staking-load", "staking-holder"],
    ["#/vesting", "vesting-unavailable", "vesting-load", "vesting-beneficiary"],
  ])(
    "%s refuses with copy and renders no amount when readActors is null",
    async (hash, refusalId, loadId, inputId) => {
      window.location.hash = hash;
      const root = container();
      const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
        buildReadActors: throwingReadActors(),
      }));
      expect(ctx.readActors).toBeNull();

      // A valid principal, so the refusal cannot be mistaken for input rejection.
      const input = root.querySelector<HTMLInputElement>(`[data-testid="${inputId}"]`);
      expect(input).not.toBeNull();
      input!.value = "aaaaa-aa";
      root.querySelector<HTMLButtonElement>(`[data-testid="${loadId}"]`)!.click();
      await Promise.resolve();
      await Promise.resolve();

      const refusal = root.querySelector(`[data-testid="${refusalId}"]`);
      expect(refusal).not.toBeNull();
      expect(refusal!.textContent).toBe(READ_SERVICES_UNAVAILABLE);

      // THE fail-open assertion: no figure of any kind reached the page. A
      // `?? 0n` default, a stub reader, or an empty-positions render would put
      // a digit followed by STSH here; a refusal does not.
      expect(root.textContent ?? "").not.toMatch(/\d[\d,.]*\s*STSH/);
    },
  );
});
