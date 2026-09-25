/**
 * WALLET-UX — the verified note sweep is offered at most once per hour per
 * signed-in principal (UI courtesy; the canister window is the real limit).
 */

import { afterEach, describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { renderVerifiedSweep } from "../src/ui/pages/scan";
import type { AppContext } from "../src/ui/context";
import {
  SWEEP_COOLDOWN_MS,
  recordSweepStarted,
  sweepCooldownRemainingMs,
} from "../src/ui/sweepCooldown";

const ME = Principal.fromUint8Array(new Uint8Array(10).fill(0x31));

function ctxFor(principal: Principal | null, calls: string[]): AppContext {
  return {
    state: {
      principal,
      cacheUnlocked: true,
      scanning: false,
      busy: false,
      verifiedScan: null,
      verifiedRollback: null,
      verifiedScanning: false,
    },
    verifiedScan: async () => {
      calls.push("verifiedScan");
    },
  } as unknown as AppContext;
}

const button = (root: HTMLElement) =>
  root.querySelector<HTMLButtonElement>("[data-testid=verified-sweep-button]")!;

afterEach(() => window.localStorage.clear());

describe("WALLET-UX — one verified note sweep per hour", () => {
  it("states the limit before the press", () => {
    const root = document.createElement("div");
    renderVerifiedSweep(root, ctxFor(ME, []));
    expect(root.querySelector("[data-testid=verified-sweep-limit]")?.textContent).toBe(
      "One verified note sweep per hour in this wallet.",
    );
  });

  it("a press starts the hour; the button is disabled with the wait shown", () => {
    const calls: string[] = [];
    const first = document.createElement("div");
    renderVerifiedSweep(first, ctxFor(ME, calls));
    expect(button(first).disabled).toBe(false);
    button(first).click();
    expect(calls).toEqual(["verifiedScan"]);

    const again = document.createElement("div");
    renderVerifiedSweep(again, ctxFor(ME, calls));
    expect(button(again).disabled).toBe(true);
    expect(button(again).textContent).toMatch(/^Available again in \d+ min$/);
  });

  // AC-4: a second click within the hour must not re-invoke the actor, and
  // the cooldown must survive a reload (a fresh mount, same localStorage),
  // not just a re-render of the same component instance.
  it("AC-4: a second click within the hour never calls the actor", () => {
    const calls: string[] = [];
    const first = document.createElement("div");
    renderVerifiedSweep(first, ctxFor(ME, calls));
    button(first).click();
    expect(calls).toEqual(["verifiedScan"]);

    const again = document.createElement("div");
    renderVerifiedSweep(again, ctxFor(ME, calls));
    expect(button(again).disabled).toBe(true);
    // jsdom does not dispatch click on a disabled button, matching the
    // browser — this is the actual enforcement mechanism, so assert it holds.
    button(again).click();
    expect(calls).toEqual(["verifiedScan"]);
  });

  it("AC-4: the cooldown survives a reload (fresh mount, same localStorage)", () => {
    const calls: string[] = [];
    const before = document.createElement("div");
    renderVerifiedSweep(before, ctxFor(ME, calls));
    button(before).click();
    expect(calls).toEqual(["verifiedScan"]);

    // Simulate a reload: a brand new root and a brand new context object,
    // nothing carried over except what localStorage persisted.
    const afterReload = document.createElement("div");
    renderVerifiedSweep(afterReload, ctxFor(ME, calls));
    expect(button(afterReload).disabled).toBe(true);
    expect(button(afterReload).textContent).toMatch(/^Available again in \d+ min$/);
    button(afterReload).click();
    expect(calls).toEqual(["verifiedScan"]);
  });

  it("the window is per principal and ends after 60 minutes", () => {
    const t0 = 1_800_000_000_000;
    recordSweepStarted(ME.toText(), t0);
    expect(sweepCooldownRemainingMs(ME.toText(), t0 + 1)).toBe(SWEEP_COOLDOWN_MS - 1);
    expect(sweepCooldownRemainingMs(ME.toText(), t0 + SWEEP_COOLDOWN_MS)).toBe(0);
    expect(sweepCooldownRemainingMs("aaaaa-aa", t0 + 1)).toBe(0);
  });

  it("a stored time in the future waits at most one window", () => {
    recordSweepStarted(ME.toText(), 2_000_000_000_000);
    expect(sweepCooldownRemainingMs(ME.toText(), 1_000_000_000_000)).toBe(SWEEP_COOLDOWN_MS);
  });

  it("the button stays disabled while the private balance is locked", () => {
    const ctx = ctxFor(ME, []);
    (ctx.state as { cacheUnlocked: boolean }).cacheUnlocked = false;
    const root = document.createElement("div");
    renderVerifiedSweep(root, ctx);
    expect(button(root).disabled).toBe(true);
  });
});
