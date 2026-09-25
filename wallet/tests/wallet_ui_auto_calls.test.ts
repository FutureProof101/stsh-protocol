/**
 * WALLET-UI — automatic calls (Addendum 1 ruling 2; SSA pre-review Q4).
 *
 * The pre-review found the branch starting an ordinary scan, fire-and-forget,
 * right before post-unlock recovery. `performScan` set `state.scanning`
 * synchronously, so `recoverSpends` returned early and fresh-device recovery
 * was skipped on every production unlock — hidden from tests because only the
 * production deps turned the background reads on.
 *
 * The production/harness split no longer exists (`backgroundReads` is gone),
 * so these arms drive the SAME composed path production runs:
 *
 *   1. unlock → recovery actually runs (the pool's recovery index is paged and
 *      the repair is surfaced), and NO scan starts on its own;
 *   2. navigating to Settings makes NO Vault `get_signers` call; only the
 *      explicit "Check operator access" press does, once.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import type { VetKey } from "@dfinity/vetkeys";

import { mountApp, type AppDeps } from "../src/ui/app";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import { walletAuthorizationAuthority } from "../src/actors/authorization";
import { wrapPoolActor } from "../src/actors/pool";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, OperatorActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import type { VetkeysCanister } from "../src/crypto/vetkeys";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x33));
const SPEND_ID = 77n;

interface Counters {
  listActiveSpends: number;
  scanNotes: number;
  getSigners: number;
}

function poolService(c: Counters): unknown {
  const record = {
    spend_id: SPEND_ID,
    status: { PayoutPending: { reason: "ledger unavailable" } },
    nullifiers: [new Uint8Array(32).fill(0x3a)],
    output_commitments: [new Uint8Array(32).fill(0x3b), new Uint8Array(32).fill(0x3c)],
    submitter: [USER],
    created_at_ns: 1n,
  };
  return {
    list_my_active_spends: async () => {
      c.listActiveSpends += 1;
      return { spends: [record], next_cursor: [] };
    },
    get_spend_status: async () => [record],
    retry_private_spend_payout: async () => {
      throw new Error("must not be called by an automatic pass");
    },
  };
}

const token: TokenCanister = {
  balanceOf: async () => 0n,
  metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
  fee: async () => 0n,
};

const FAKE_VETKEY = {
  serialize: () => new Uint8Array(48).fill(9),
  deriveSymmetricKey: () => new Uint8Array(32).fill(7),
} as unknown as VetKey;

const notScripted = async (): Promise<never> => {
  throw new Error("not scripted by this test");
};

const vetkeys: VetkeysCanister = {
  getConfig: async () => ["stsh.wallet.notes.v1", "key_1"],
  getVetkeyVerificationKey: async () => new Uint8Array(96),
  getEncryptedVetkey: async () => ({ encryptedKey: new Uint8Array(192), remaining: 4 }),
  registerDevice: notScripted,
  revokeDevice: notScripted,
  getWrappedSecret: notScripted,
  listDevices: notScripted,
  replaceEnvelope: notScripted,
};

function harness(c: Counters): AppDeps {
  const pool = wrapPoolActor(poolService(c) as never, walletAuthorizationAuthority);
  return {
    origin: PRODUCTION_ORIGIN,
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
    buildOperatorActors: async () =>
      ({
        vault: {
          getSigners: async () => {
            c.getSigners += 1;
            return [USER];
          },
        },
        upgrader: {},
      }) as unknown as OperatorActors,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      const session: AuthSession = {
        identity: { getPrincipal: () => USER } as unknown as AuthSession["identity"],
        principal: USER,
      };
      const auth: WalletAuth = {
        restore: async () => session,
        login: async () => session,
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    buildShieldedActors: async () => ({ pool, vetkeys }) satisfies ShieldedActors,
    createCacheStore: async () => (await memoryHarness()).store,
    scanNotes: async () => {
      c.scanNotes += 1;
      return {
        notes: [],
        scannedUpTo: 0n,
        mirrorHead: { leafCount: 0n, root: new Uint8Array(32) },
        quarantine: { total: 0, ring: [] },
        spentSet: new Set<string>(),
      };
    },
    fetchKeys: async () => ({ vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 4 }),
  };
}

function container(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("WALLET-UI — no automatic scan; recovery runs on unlock (SSA Q4)", () => {
  it("unlock runs recovery to completion and starts no scan of its own", async () => {
    const c: Counters = { listActiveSpends: 0, scanNotes: 0, getSigners: 0 };
    const ctx = await mountApp(container(), {}, harness(c));
    await ctx.unlockNoteCache("pw");
    await settle();
    // Recovery ran: the identity-bound index was paged and the repair surfaced.
    expect(c.listActiveSpends).toBeGreaterThanOrEqual(1);
    expect(ctx.state.pendingRecovery).toEqual([{ spendId: SPEND_ID.toString(10), action: "retry-payout" }]);
    // And nothing scanned on its own.
    expect(c.scanNotes).toBe(0);
    expect(ctx.state.scanning).toBe(false);
    // ANTI-VACUITY: the scan seam is live — an explicit Sync reaches it.
    await ctx.scan();
    expect(c.scanNotes).toBe(1);
  });
});

describe("WALLET-UI — Vault get_signers only on an explicit press (Addendum 1 ruling 2)", () => {
  it("opening Settings makes no signer call; the press makes exactly one", async () => {
    const c: Counters = { listActiveSpends: 0, scanNotes: 0, getSigners: 0 };
    const root = container();
    const ctx = await mountApp(root, {}, harness(c));
    expect(ctx.state.principal?.toText()).toBe(USER.toText());
    for (const route of ["#/settings", "#/scan", "#/balance", "#/settings"]) {
      window.location.hash = route;
      window.dispatchEvent(new HashChangeEvent("hashchange"));
      await settle();
    }
    expect(c.getSigners).toBe(0);
    expect(ctx.state.isAdmin === true).toBe(false);

    const btn = root.querySelector('[data-testid="check-operator-access"]') as HTMLButtonElement | null;
    expect(btn).not.toBeNull();
    btn!.click();
    await settle();
    await settle();
    expect(c.getSigners).toBe(1);
    expect(ctx.state.isAdmin).toBe(true);
    // Admin now shows; the check button is gone; a second check is a no-op.
    expect(root.querySelector('[data-testid="settings-admin"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="check-operator-access"]')).toBeNull();
    await ctx.checkOperatorAccess?.();
    expect(c.getSigners).toBe(1);
  });
});
