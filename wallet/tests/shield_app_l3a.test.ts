/**
 * L3a app-shell wiring tests — the shield surface preconditions in mountApp:
 * anonymous/locked refusals, the unlock lifecycle (real Argon2id cache over
 * the memory harness), logout teardown (§1.1), and the shield route gate.
 * The flow internals are covered in shield_flow_l3a.test.ts; here the subject
 * is the ctx wiring around them.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { mountApp, type AppDeps } from "../src/ui/app";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x21));

function fakeSession(): AuthSession {
  return {
    identity: { getPrincipal: () => USER } as unknown as AuthSession["identity"],
    principal: USER,
  };
}

const token: TokenCanister = {
  balanceOf: async () => 0n,
  metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
  fee: async () => 0n,
};

const stubShielded: ShieldedActors = {
  pool: {} as ShieldedActors["pool"],
  vetkeys: {} as ShieldedActors["vetkeys"],
};

function harness(opts: {
  restored?: boolean;
  buildShieldedActors?: AppDeps["buildShieldedActors"];
}): { deps: AppDeps } {
  const deps: AppDeps = {
    origin: PRODUCTION_ORIGIN,
    // S1-02: the launch origin is runtime-loaded; this harness supplies the ruled
    // value so the policy sees the same origin it is evaluated against.
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () =>
      ({
        token,
        staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      }) satisfies ReadActors,
    buildMutationActors: async () =>
      ({
        token: {
          transfer: async () => {
            throw new Error("not scripted");
          },
          ...unusedIcrc2,
        },
      }) satisfies MutationActors,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      const auth: WalletAuth = {
        restore: async () => (opts.restored === false ? null : fakeSession()),
        login: async () => fakeSession(),
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    buildShieldedActors: opts.buildShieldedActors ?? (async () => stubShielded),
    createCacheStore: async () => (await memoryHarness()).store,
  };
  return { deps };
}

function mountContainer(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

describe("mountApp shield wiring (L3a)", () => {
  it("shield refuses while anonymous", async () => {
    const h = harness({ restored: false });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.shield(100_000_000n);
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/log in to shield/i);
  });

  it("shield refuses while the note cache is locked (journal lives there)", async () => {
    const h = harness({});
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    expect(ctx.state.principal?.toText()).toBe(USER.toText());
    await ctx.shield(100_000_000n);
    // WALLET-CACHE-II-ONLY O-6: "note cache" is no longer user-facing copy.
    expect(ctx.state.status?.msg).toMatch(/open your private balance first/i);
  });

  it("shield explains when the shielded actors could not be built", async () => {
    const h = harness({
      buildShieldedActors: async () => {
        throw new Error("pool canister id is empty");
      },
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    expect(ctx.shieldedActors).toBeNull();
    await ctx.shield(100_000_000n);
    expect(ctx.state.status?.msg).toMatch(/unavailable/i);
    expect(ctx.state.status?.msg).toMatch(/pool canister id is empty/);
  });

  it("unlockNoteCache opens the L4 cache (real Argon2id), loads the journal, and logout locks it again", async () => {
    const h = harness({});
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    expect(ctx.state.cacheUnlocked).toBe(false);
    await ctx.unlockNoteCache("correct horse");
    expect(ctx.state.cacheUnlocked).toBe(true);
    expect(ctx.state.shieldEntries).toEqual([]);
    expect(ctx.state.status?.msg).toMatch(/unlocked/i);

    await ctx.logout();
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.shieldEntries).toBeNull();
    // A fresh unlock now requires a session again.
    await ctx.unlockNoteCache("correct horse");
    expect(ctx.state.status?.msg).toMatch(/log in before unlocking/i);
  }, 30_000);

  it("a failed re-unlock (wrong passphrase) drops the unlocked state — no locked-cache limbo", async () => {
    const h = harness({});
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.unlockNoteCache("correct horse");
    expect(ctx.state.cacheUnlocked).toBe(true);
    // openForSession locks the previous instance before failing — the state
    // must reflect that, not point at a dead cache.
    await ctx.unlockNoteCache("wrong pass");
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.status?.msg).toMatch(/could not unlock/i);
    // Recoverable: the correct passphrase opens it again.
    await ctx.unlockNoteCache("correct horse");
    expect(ctx.state.cacheUnlocked).toBe(true);
  }, 60_000);

  it("unlockNoteCache refuses an empty passphrase", async () => {
    const h = harness({});
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.unlockNoteCache("");
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.status?.msg).toMatch(/passphrase/i);
  });

  it("the shield route gates: NO passphrase form after login, shield form once the cache is open", async () => {
    window.location.hash = "#/shield";
    const container = mountContainer();
    const h = harness({});
    const ctx = await mountApp(container, {}, h.deps);
    // WALLET-CACHE-II-ONLY (AC-1/AC-4): the mandatory passphrase card is
    // retired. Before the cache opens the route is still gated — no shield
    // form — and nothing on it asks for a passphrase.
    await new Promise((r) => setTimeout(r, 0));
    expect(container.querySelector('[data-testid="cache-passphrase"]')).toBeNull();
    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(container.textContent).not.toMatch(/fixed denominations/i);
    await ctx.unlockNoteCache("correct horse");
    expect(container.querySelector('[data-testid="cache-passphrase"]')).toBeNull();
    expect(container.textContent).toMatch(/fixed denominations/i);
    window.location.hash = "";
  }, 30_000);
});
