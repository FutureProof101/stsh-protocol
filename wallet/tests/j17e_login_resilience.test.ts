/**
 * J-17e — LOGIN and RESTORE must survive unconfigured mutation services and a
 * device whose storage is blocked.
 *
 * The bundle live at app.stsh.fi on 2026-09-12 (after J-17d fixed II login
 * itself) showed "Could not restore the previous session: Canister ID is
 * required, but received string instead" and no session. Cause: three
 * UNGUARDED awaits inside `applySession` — `buildMutationActors` (the reported
 * one), `createJournalStore` and `loadUnresolved` (SSA F-1) — each of which
 * rejects out of `applySession` and drops the whole session, at login and at
 * restore alike.
 *
 * These arms drive the real `mountApp`. Reverting any of the three guards
 * fails one of them.
 *
 * Arm (d) is the anti-vacuous half: (a) says a session exists, but says
 * nothing about whether a transfer surface with no actors behind it renders as
 * a refusal or as an enabled Send button over a fabricated figure.
 *
 * The epoch race is NOT re-tested here. `session_a1.test.ts` already owns it
 * ("logout during an in-flight balance read discards the stale result",
 * "a generic error never logs out (A-S10)", "only a VERIFIED delegation expiry
 * logs out") and those tests are unchanged by this lane — which is the
 * evidence that the new catches fall through rather than commit or return.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { DelegationChain, DelegationIdentity, Ed25519KeyIdentity } from "@dfinity/identity";

import { mountApp, type AppDeps } from "../src/ui/app";
import type { AuthSession, DelegationIdentityLike } from "../src/session/auth";
import {
  DEVICE_STORAGE_UNAVAILABLE,
  TRANSFER_SERVICES_UNCONFIGURED,
} from "../src/ui/context";
import { memoryJournalStore } from "./helpers/memoryJournalStore";

const PRODUCTION_ORIGIN = "https://app.stsh.fi";

/** The ids that are `""` in the shipped config until J-18/A-7. */
/**
 * The UNCONFIGURED deployment, stated EXPLICITLY.
 *
 * WT-1 Addendum A made `{}` mean the opposite of what this constant is named
 * for: `resolveConfig({})` now yields the live mainnet token principal from a
 * hardcoded `DEFAULT_*`, because six ids silently resolving to `""` was the
 * defect that lane fixed. An empty env is therefore a CONFIGURED deployment,
 * and these arms would have quietly started exercising the transient
 * `transferServicesUnavailable` branch instead of the unconfigured one they are
 * named for — still green, testing something else. The empty id is spelled out
 * here so the arms keep meaning what they say.
 */
const UNCONFIGURED_ENV: Record<string, string | undefined> = { VITE_TOKEN_CANISTER_ID: "" };

async function fakeSession(): Promise<AuthSession> {
  const root = Ed25519KeyIdentity.generate();
  const session = Ed25519KeyIdentity.generate();
  const chain = await DelegationChain.create(
    root,
    session.getPublicKey(),
    new Date(Date.now() + 4 * 60 * 60 * 1000),
  );
  const identity = DelegationIdentity.fromDelegation(session, chain);
  return {
    identity: identity as unknown as DelegationIdentityLike,
    principal: identity.getPrincipal(),
  };
}

const workingReadActors = {
  token: {
    balanceOf: async () => 0n,
    metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
    fee: async () => 0n,
  },
  staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
  vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
};

function deps(over: Partial<AppDeps> = {}, session: AuthSession | null = null): AppDeps {
  return {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () => workingReadActors as never,
    buildMutationActors: async () => ({}) as never,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => ({
      restore: async () => session,
      login: async () => {
        throw new Error("not scripted");
      },
      logout: async () => {},
      verify: () => "valid" as const,
    }),
    ...over,
  } as AppDeps;
}

/**
 * The REAL production failure at the dep boundary: exactly what
 * `createTokenMutationActor("")` throws inside `createMutationActors`.
 * Modelled on `throwingReadActors` in the J-17c harness, whose absence here
 * would have made every new arm vacuous (SSA F-8).
 */
function throwingMutationActors(): AppDeps["buildMutationActors"] {
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

describe("J-17e — login survives unconfigured mutation services", () => {
  // ── (a) the reported bug, at LOGIN/restore ──────────────────────────────
  it("commits the session with NULL actors when mutation-actor construction throws", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildMutationActors: throwingMutationActors(),
    }, session));

    // The session exists...
    expect(ctx.state.principal).not.toBeNull();
    expect(ctx.state.principal!.toText()).toBe(session.principal.toText());
    // ...WITHOUT the actors. Both halves matter: a session with actors would
    // mean the harness never threw, and a principal-less ctx is the old bug.
    expect(ctx.mutationActors).toBeNull();
    expect(root.querySelector('[data-testid="principal"]')?.textContent).toBe(
      session.principal.toText(),
    );
    // The refusal is recorded persistently, not flashed.
    expect(
      root.querySelector('[data-testid="transfer-services-notice"]')?.textContent,
    ).toBe(TRANSFER_SERVICES_UNCONFIGURED);
  });

  it("renders the operator route for that same actor-less session", async () => {
    window.location.hash = "#/operator";
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildMutationActors: throwingMutationActors(),
    }, session));
    expect(ctx.state.principal).not.toBeNull();
    // The session reached the page. This harness supplies no
    // `buildOperatorActors`, so the page takes its ring-unconfigured branch —
    // but it is the LOGGED-IN half of that branch, not the anonymous one.
    // Before this lane the session was dropped and the anonymous half showed.
    // Signer-set gating itself is J-17b's, and is not re-tested here.
    const gate = root.querySelector('[data-testid="operator-session-required"]');
    expect(gate).not.toBeNull();
    expect(gate!.textContent).toContain("unavailable for this session");
    expect(gate!.textContent ?? "").not.toContain("never started");
  });

  // ── (b) RESTORE says nothing about a failure that is not one ────────────
  it("restores without the 'Could not restore' error when the ids are empty", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildMutationActors: throwingMutationActors(),
    }, session));

    expect(ctx.state.principal).not.toBeNull();
    // The LITERAL, not merely `status.kind !== "error"` (SSA F-8): the string
    // the Owner saw must be absent from the page and from the status.
    expect(root.textContent ?? "").not.toContain("Could not restore");
    expect(ctx.state.status?.msg ?? "").not.toContain("Could not restore");
  });

  // ── SSA F-1: the other two unguarded awaits, same symptom ───────────────
  it("commits the session when createJournalStore rejects (blocked IndexedDB)", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      createJournalStore: (async () => {
        throw new Error("indexedDB is not available in this context");
      }) as never,
    }, session));

    expect(ctx.state.principal).not.toBeNull();
    expect(ctx.journalAvailable).toBe(false);
    expect(root.textContent ?? "").not.toContain("Could not restore");
    expect(
      root.querySelector('[data-testid="device-storage-notice"]')?.textContent,
    ).toBe(DEVICE_STORAGE_UNAVAILABLE);
  });

  it("commits the session when loadUnresolved rejects", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      createJournalStore: (async () => {
        const store = memoryJournalStore();
        return {
          ...store,
          get: async () => {
            throw new Error("UnknownError: the database connection is closing");
          },
        };
      }) as never,
    }, session));

    expect(ctx.state.principal).not.toBeNull();
    expect(ctx.journalAvailable).toBe(false);
    expect(root.textContent ?? "").not.toContain("Could not restore");
    expect(root.querySelector('[data-testid="device-storage-notice"]')).not.toBeNull();
  });

  // ── (c) no behaviour change when everything IS configured ───────────────
  it("keeps actors non-null and shows NO notice when construction succeeds", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({}, session));
    expect(ctx.mutationActors).not.toBeNull();
    expect(ctx.journalAvailable).toBe(true);
    expect(root.querySelector('[data-testid="transfer-services-notice"]')).toBeNull();
    expect(root.querySelector('[data-testid="device-storage-notice"]')).toBeNull();
    expect(root.querySelector('[data-testid="transfer-unavailable"]')).toBeNull();
  });

  // ── (d) anti-vacuous: the transfer surface REFUSES, it does not offer ───
  it.each([
    [
      "null mutation actors",
      { buildMutationActors: throwingMutationActors() },
      TRANSFER_SERVICES_UNCONFIGURED,
    ],
    [
      "blocked device storage",
      {
        createJournalStore: (async () => {
          throw new Error("indexedDB is not available in this context");
        }) as never,
      },
      DEVICE_STORAGE_UNAVAILABLE,
    ],
  ])(
    "the account page refuses to offer a transfer with %s",
    async (_label, over, copy) => {
      window.location.hash = "#/account";
      const session = await fakeSession();
      const root = container();
      await mountApp(root, UNCONFIGURED_ENV, deps(over as Partial<AppDeps>, session));

      const refusal = root.querySelector('[data-testid="transfer-unavailable"]');
      expect(refusal).not.toBeNull();
      expect(refusal!.textContent).toBe(copy);
      // No form at all: no inputs, and above all no enabled Send.
      expect(root.querySelector('[data-testid="send"]')).toBeNull();
      expect(root.querySelector('[data-testid="amount-input"]')).toBeNull();
      expect(root.querySelector('[data-testid="to-input"]')).toBeNull();
      // THE fail-open assertion: no figure reached the TRANSFER SURFACE (the
      // "Send STSH" heading and its refusal). Scoped to that surface since
      // VETKEYS-AGE-2MIN (Blocker-3 ruling 2026-09-23): session restore now
      // OBSERVES the real balance, so the page's balance line legitimately
      // shows a figure — the guard is that the refused transfer surface does not.
      // WALLET-UI (rebase onto VETKEYS-AGE-2MIN): the transfer surface now
      // lives in the "Send public STSH" fold on Home, so its heading is that
      // fold's <summary>, not the refusal's previous sibling. Same surface,
      // same no-figure assertion; only the locator and the heading text moved.
      const heading =
        refusal!.closest('[data-testid="public-send"]')?.querySelector(":scope > summary") ?? null;
      expect(heading).not.toBeNull();
      expect(heading?.textContent).toBe("Send public STSH");
      const surface = `${heading?.textContent ?? ""} ${refusal!.textContent ?? ""}`;
      expect(surface).not.toMatch(/\d[\d,.]*\s*STSH/);
    },
  );

  // ── SSA F-5: the copy must not call a logged-in user anonymous ──────────
  it("does not tell a logged-in user that mutations are refused while anonymous", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildMutationActors: throwingMutationActors(),
    }, session));

    await ctx.transfer({ toText: "aaaaa-aa", amountText: "1" });
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toBe(TRANSFER_SERVICES_UNCONFIGURED);
    expect(ctx.state.status?.msg ?? "").not.toContain("while anonymous");
  });

  // ── SSA F-4: the retry button refuses out loud, never silently ──────────
  it("retryPendingIntent surfaces a refusal instead of a silent no-op", async () => {
    const session = await fakeSession();
    const root = container();
    const ctx = await mountApp(root, UNCONFIGURED_ENV, deps({
      buildMutationActors: throwingMutationActors(),
    }, session));

    ctx.pendingIntent = {
      schema: 2,
      intentId: "intent-1",
      revision: 1,
      state: "unknown",
      ownerPrincipal: session.principal.toText(),
      ledgerCanisterId: "",
      network: ctx.config.host,
      fromSubaccountHex: null,
      toOwner: "aaaaa-aa",
      toSubaccountHex: null,
      amount: "100000000",
      fee: "10000",
      memoHex: null,
      createdAtTimeNs: "1",
      createdAtMs: 1,
      attempts: 1,
    };
    await ctx.retryPendingIntent();
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toBe(TRANSFER_SERVICES_UNCONFIGURED);
  });
});
