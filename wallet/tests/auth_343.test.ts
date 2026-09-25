/**
 * AC-2 gate tests — REAL @dfinity/auth-client@3.4.3 behavior (not mocks).
 *
 * The A1 auth assertions were written against 2.4.1; this file re-establishes
 * them against the aligned 3.4.3 runtime with a real AuthClient over seeded
 * storage:
 *
 * - stored VALID delegation restores; stored EXPIRED delegation does not —
 *   3.4.3's isAuthenticated() validates expiry itself (the old "isAuthenticated
 *   ignores expiry" claim is dead and gone from source).
 * - the 8-hour ceiling is INDEPENDENT app policy (ruling: retained): a 9-hour
 *   delegation the SDK considers live is still rejected by our verify.
 * - the ~10-minute idle callback fires (real IdleManager, fake timers).
 * - the default provider is https://identity.internetcomputer.org with
 *   `#authorize` (real login() URL, window.open intercepted).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthClient } from "@dfinity/auth-client";
import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@dfinity/identity";

import {
  createWalletAuth,
  verifyIdentity,
  IDLE_TIMEOUT_MS,
  MAX_DELEGATION_TTL_NS,
} from "../src/session/auth";
import { evaluateSessionPolicy, resolveConfig, PRODUCTION_ORIGIN } from "../src/session/config";

/**
 * S1-02: the session policy now reads a RUNTIME-loaded launch origin, so a test
 * config must supply one. It is written here as the ruled literal rather than
 * imported from the config module's default, so the arm still fails if the
 * shipped value drifts.
 */
function productionConfig() {
  return { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
}


const HOUR_MS = 60 * 60 * 1000;

/** Minimal in-memory AuthClientStorage. */
function memoryAuthStorage() {
  const map = new Map<string, string | CryptoKeyPair>();
  return {
    async get(key: string): Promise<string | CryptoKeyPair | null> {
      return map.get(key) ?? null;
    },
    async set(key: string, value: string | CryptoKeyPair): Promise<void> {
      map.set(key, value);
    },
    async remove(key: string): Promise<void> {
      map.delete(key);
    },
  };
}

/** Seed storage with a real Ed25519 session key + delegation chain. */
async function seededClient(expiresInMs: number, idleOptions?: Record<string, unknown>) {
  const root = Ed25519KeyIdentity.generate();
  const session = Ed25519KeyIdentity.generate();
  const chain = await DelegationChain.create(
    root,
    session.getPublicKey(),
    new Date(Date.now() + expiresInMs),
  );
  const storage = memoryAuthStorage();
  await storage.set("identity", JSON.stringify(session.toJSON()));
  await storage.set("delegation", JSON.stringify(chain.toJSON()));
  const client = await AuthClient.create({
    storage,
    keyType: "Ed25519",
    idleOptions: idleOptions ?? { disableIdle: true },
  });
  return { client, root, session, chain };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("real 3.4.3 AuthClient: stored delegations", () => {
  it("restores a stored VALID delegation (isAuthenticated true, principal preserved)", async () => {
    const { client, chain } = await seededClient(4 * HOUR_MS);
    expect(await client.isAuthenticated()).toBe(true);
    const identity = client.getIdentity();
    expect(identity.getPrincipal().isAnonymous()).toBe(false);
    expect(identity).toBeInstanceOf(DelegationIdentity);
    expect(
      (identity as DelegationIdentity).getDelegation().delegations[0].delegation.expiration,
    ).toBe(chain.delegations[0].delegation.expiration);
    expect(verifyIdentity(identity)).toBe("valid");
  });

  it("does NOT restore a stored EXPIRED delegation — 3.4.3 validates expiry itself", async () => {
    const { client } = await seededClient(-1000);
    expect(await client.isAuthenticated()).toBe(false);
  });

  it("the 8h ceiling is app policy on TOP of the SDK's own validity check", async () => {
    // A 9-hour delegation: live as far as the SDK is concerned...
    const { client } = await seededClient(9 * HOUR_MS);
    expect(await client.isAuthenticated()).toBe(true);
    // ...but beyond anything this app's login (MAX_DELEGATION_TTL_NS) ever
    // requests, so OUR verify rejects it and restore() discards the session.
    expect(verifyIdentity(client.getIdentity())).toBe("expired");
    const auth = await createWalletAuth(
      evaluateSessionPolicy(productionConfig(), PRODUCTION_ORIGIN),
      () => undefined,
      { createClient: async () => client },
    );
    expect(await auth.restore()).toBeNull();
    expect(await client.isAuthenticated()).toBe(false); // dead session dropped
  });
});

describe("real 3.4.3 AuthClient: idle manager", () => {
  it("fires the custom onIdle callback after the explicit 10-minute timeout", async () => {
    vi.useFakeTimers();
    let idleFired = 0;
    await seededClient(4 * HOUR_MS, {
      idleTimeout: IDLE_TIMEOUT_MS,
      onIdle: () => {
        idleFired += 1;
      },
    });
    vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 1000);
    expect(idleFired).toBe(1);
  });
});

describe("real 3.4.3 AuthClient: login provider", () => {
  it("defaults to https://identity.internetcomputer.org with #authorize and our 8h TTL", async () => {
    const { client } = await seededClient(-1000); // start unauthenticated
    const openSpy = vi.spyOn(window, "open").mockReturnValue(null);
    const loginCall = client.login({
      maxTimeToLive: MAX_DELEGATION_TTL_NS,
      onError: () => undefined,
    });
    loginCall.catch(() => undefined); // popup blocked in jsdom — expected
    await vi.waitFor(() => expect(openSpy).toHaveBeenCalled());
    const url = String(openSpy.mock.calls[0][0]);
    expect(url.startsWith("https://identity.internetcomputer.org/")).toBe(true);
    expect(url).toContain("#authorize");
    expect(url).not.toContain("/authorize?");
  });
});
