// @vitest-environment jsdom
/**
 * WALLET-SHIELD-LAYER1 Addendum A (Owner, first look at final-v9) — items 5-9,
 * copy/presentation only. Literals are written here from the brief, not
 * imported from the code under test.
 *
 *   5  Shield: amount > public balance -> button disabled + one line, BEFORE
 *      the click; amount+fees > balance -> a non-blocking warning.
 *   6  The last action's banner has a × and clears on a route change.
 *   7  Spend: "Whole note" is the default amount mode.
 *   8  The selected segment is copper (--accent) with --on-accent text.
 *   9  The daily key limit reads "Daily key limit reached. Try again in 7 h 0 m."
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

vi.mock("../src/storage/deviceStore", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/storage/deviceStore")>();
  return { ...real, loadDeviceIdentity: async () => null, saveDeviceIdentity: async () => undefined };
});
vi.mock("../src/session/domainGuard", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/session/domainGuard")>();
  return {
    ...real,
    assertDeploymentBinding: async () => ({ hash: new Uint8Array(32), wiring: {} as never }),
  };
});

import { mountApp, type AppDeps } from "../src/ui/app";
import { renderShield } from "../src/ui/pages/shield";
import { renderSpend } from "../src/ui/pages/spend";
import { formatHoursMinutes, humanizeWait } from "../src/ui/quotaCopy";
import { VetkeysCallError, type VetkeysCanister } from "../src/crypto/vetkeys";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { ShieldFeeParams } from "../src/actors/pool";
import type { AppContext } from "../src/ui/context";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const WALLET = join(dirname(fileURLToPath(import.meta.url)), "..");
const E8S = 100_000_000n;
const noop = async (): Promise<void> => undefined;

// ── Item 5 — shield over-balance guard ──────────────────────────────────────

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

function shieldPage(balance: bigint | null, basis: { params: ShieldFeeParams; ledgerFee: bigint } | null) {
  const root = document.createElement("div");
  const shield = vi.fn(noop);
  renderShield(root, {
    state: {
      principal: { toText: () => "aaaaa-aa" },
      notes: [],
      shieldEntries: [],
      busy: false,
      status: null,
      balance,
      spendFeeBasis: basis,
    },
    shield,
    reconcileShieldJournal: noop,
    revokeShieldAllowance: noop,
    cancelPlannedShield: noop,
    abandonAmbiguousShieldEntry: noop,
    refresh: () => {},
    navigate: () => {},
  } as unknown as AppContext);
  const input = root.querySelector<HTMLInputElement>('input[aria-label="Amount in STSH (e.g. 123)"]')!;
  const submit = Array.from(root.querySelectorAll<HTMLButtonElement>("button.primary")).find((b) =>
    (b.textContent ?? "").startsWith("Shield"),
  )!;
  const enter = (stsh: string) => {
    input.value = stsh;
    input.dispatchEvent(new Event("input"));
  };
  return { root, submit, enter, shield };
}

describe("item 5 — the shield button refuses an amount over the public balance", () => {
  it("amount > balance: disabled before any click, one line, and a click does nothing", () => {
    const { root, submit, enter, shield } = shieldPage(5_000n * E8S, null);
    enter("10000");
    expect(submit.disabled).toBe(true);
    expect(root.querySelector('[data-testid="shield-over-balance"]')?.textContent).toBe(
      "More than your public balance.",
    );
    submit.click();
    expect(shield).not.toHaveBeenCalled();
  });

  it("amount <= balance: enabled, no over-balance line", () => {
    const { root, submit, enter } = shieldPage(10_000n * E8S, null);
    enter("10000");
    expect(submit.disabled).toBe(false);
    expect(root.querySelector('[data-testid="shield-over-balance"]')).toBeNull();
  });

  it("an unknown balance (null, not loaded yet) never blocks", () => {
    const { root, submit, enter } = shieldPage(null, null);
    enter("10000");
    expect(submit.disabled).toBe(false);
    expect(root.querySelector('[data-testid="shield-over-balance"]')).toBeNull();
  });

  it("amount fits but amount+fees may not: a WARNING, and the button stays enabled", () => {
    const { root, submit, enter } = shieldPage(10_000n * E8S, { params: PARAMS, ledgerFee: 10_000n });
    enter("10000");
    expect(submit.disabled).toBe(false);
    expect(root.querySelector('[data-testid="shield-over-balance"]')).toBeNull();
    const warn = root.querySelector('[data-testid="shield-fee-over-balance"]');
    expect(warn?.className).toContain("warning");
    expect(warn?.textContent).toMatch(/with fees this may be more than your public balance/i);
  });

  it("no fee warning when amount+fees fits", () => {
    const { root, enter } = shieldPage(20_000n * E8S, { params: PARAMS, ledgerFee: 10_000n });
    enter("10000");
    expect(root.querySelector('[data-testid="shield-fee-over-balance"]')).toBeNull();
  });
});

// ── Item 7 — Whole note is the default ──────────────────────────────────────

describe("item 7 — Spend defaults to Whole note", () => {
  it("the selected Amount segment is 'Whole note'; 'Custom amount' is the option", () => {
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
    const group = root.querySelector('[role="radiogroup"][aria-label="Amount"]')!;
    const on = group.querySelector('[aria-checked="true"]');
    expect(on?.textContent).toBe("Whole note");
    expect(on?.className).toContain("is-on");
    const labels = Array.from(group.querySelectorAll("button")).map((b) => b.textContent);
    expect(labels).toEqual(["Whole note", "Custom amount"]);
  });
});

// ── Item 8 — copper selected segment ────────────────────────────────────────

describe("item 8 — the selected segment uses the copper accent", () => {
  const css = readFileSync(join(WALLET, "src/styles.css"), "utf8");
  const rule = (selector: string): string => {
    const idx = css.indexOf(selector);
    expect(idx, `${selector} rule present`).toBeGreaterThanOrEqual(0);
    return css.slice(idx, css.indexOf("}", idx));
  };

  it("background --accent, text --on-accent — and the hover state keeps both", () => {
    const body = rule(".segmented .seg.is-on,\n.segmented .seg.is-on:hover:not(:disabled) {");
    expect(body).toMatch(/background:\s*var\(--accent\)/);
    expect(body).toMatch(/color:\s*var\(--on-accent\)/);
    expect(body).not.toMatch(/var\(--panel-2\)/);
  });

  it("the accent tokens are the near-black-on-copper pair the contrast note relies on", () => {
    expect(css).toMatch(/--accent:\s*oklch\(0\.75 0\.098 65\);/);
    expect(css).toMatch(/--on-accent:\s*oklch\(0\.14 0 0\);/);
  });
});

// ── Item 9 — human-time daily key limit ─────────────────────────────────────

describe("item 9 — the daily key limit in hours and minutes", () => {
  it("formats h/m, rounding UP to the minute", () => {
    expect(formatHoursMinutes(25_200)).toBe("7 h 0 m");
    expect(formatHoursMinutes(25_244)).toBe("7 h 1 m");
    expect(formatHoursMinutes(3_600)).toBe("1 h 0 m");
    expect(formatHoursMinutes(2_700)).toBe("45 m");
    expect(formatHoursMinutes(1)).toBe("1 m");
    expect(formatHoursMinutes(86_400)).toBe("24 h 0 m");
  });

  it("leaves humanizeWait (shared with the preparation copy) unchanged", () => {
    expect(humanizeWait(120)).toBe("2 minutes");
    expect(humanizeWait(25_244)).toBe("8 hours");
  });
});

// ── App-level: items 6 and 9 ────────────────────────────────────────────────

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x44));

function vetkeys(): VetkeysCanister {
  return {
    getConfig: async () => ["stsh.wallet.notes.v1", "key_1"],
    getVetkeyVerificationKey: async () => new Uint8Array(96),
    getEncryptedVetkey: async () => {
      throw new Error("not scripted");
    },
    listDevices: async () => [],
  } as unknown as VetkeysCanister;
}

function appDeps(fetchKeys?: AppDeps["fetchKeys"]): AppDeps {
  const session: AuthSession = {
    identity: { getPrincipal: () => USER } as unknown as AuthSession["identity"],
    principal: USER,
  };
  return {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () =>
      ({
        token: {
          balanceOf: async () => 0n,
          metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
          fee: async () => 0n,
        },
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
    buildShieldedActors: async () =>
      ({ pool: {} as ShieldedActors["pool"], vetkeys: vetkeys() }) satisfies ShieldedActors,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      const auth: WalletAuth = {
        restore: async () => null,
        login: async () => session,
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    createCacheStore: async () => (await memoryHarness()).store,
    sleep: async () => undefined,
    ...(fetchKeys !== undefined ? { fetchKeys } : {}),
  };
}

async function mounted(deps: AppDeps): Promise<{ ctx: AppContext; node: HTMLElement }> {
  window.location.hash = "#/account";
  const node = document.createElement("div");
  document.body.append(node);
  const ctx = await mountApp(node, {}, deps);
  return { ctx, node };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("item 6 — the status banner is dismissable and route-scoped", () => {
  it("× clears the banner", async () => {
    const { ctx, node } = await mounted(appDeps());
    await ctx.shield(1_000n * E8S); // logged out: refused with an error status
    expect(ctx.state.status?.kind).toBe("error");
    const msg = node.querySelector('[data-testid="status-msg"]');
    expect(msg).not.toBeNull();
    node.querySelector<HTMLButtonElement>('[data-testid="status-dismiss"]')!.click();
    expect(ctx.state.status).toBeNull();
    expect(node.querySelector('[data-testid="status-msg"]')).toBeNull();
  });

  it("a real route change clears it", async () => {
    const { ctx, node } = await mounted(appDeps());
    await ctx.shield(1_000n * E8S);
    expect(ctx.state.status).not.toBeNull();
    ctx.navigate("settings");
    await tick();
    await tick();
    expect(ctx.state.status).toBeNull();
    expect(node.querySelector('[data-testid="status-msg"]')).toBeNull();
  });
});

describe("item 9 — shield on an exhausted daily key limit", () => {
  it("renders 'Daily key limit reached. Try again in 7 h 0 m.' — not raw seconds", async () => {
    const { ctx } = await mounted(
      appDeps(async () => {
        throw new VetkeysCallError("get_encrypted_vetkey", {
          DerivationQuotaExceeded: { retry_after_ns: 25_200_000_000_000n },
        } as never);
      }),
    );
    await ctx.login();
    await ctx.unlockNoteCache("pw");
    await ctx.shield(1_000n * E8S);
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toBe("Daily key limit reached. Try again in 7 h 0 m.");
    expect(ctx.state.status?.msg).not.toMatch(/\d+ s\b/);
  });
});
