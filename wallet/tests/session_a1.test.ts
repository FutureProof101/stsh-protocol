/**
 * Lane A1 gate tests (Campaign A / Wave 1).
 *
 * Covers the brief's §2 gate: origin policy before actor construction,
 * loopback-only root key, verified-delegation-expiry-only logout, failed-login
 * atomicity, logout epoch semantics, anonymous reads without identity, and the
 * A->B mid-flight epoch race. Auth checks run against REAL Ed25519 delegation
 * chains (no mocked isDelegationValid).
 */

import { describe, expect, it } from "vitest";

import { unusedIcrc2 } from "./helpers/tokenStubs";
import { Principal } from "@dfinity/principal";
import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@dfinity/identity";
import type { Identity } from "@dfinity/agent";

import {
  evaluateSessionPolicy,
  isLocalHost,
  resolveConfig,
  PRODUCTION_ORIGIN,
} from "../src/session/config";
import { shouldFetchRootKey } from "../src/session/session";
import { SessionEpoch } from "../src/session/sessionEpoch";
import {
  createWalletAuth,
  verifyIdentity,
  MAX_DELEGATION_TTL_NS,
  type AuthClientLike,
  type AuthSession,
  type DelegationIdentityLike,
  type SessionVerdict,
  type WalletAuth,
} from "../src/session/auth";
import { mountApp, type AppDeps } from "../src/ui/app";
import type { MutationActors, ReadActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import { memoryJournalStore } from "./helpers/memoryJournalStore";

/**
 * S1-02: the session policy now reads a RUNTIME-loaded launch origin, so a test
 * config must supply one. It is written here as the ruled literal rather than
 * imported from the config module's default, so the arm still fails if the
 * shipped value drifts.
 */
function productionConfig() {
  return { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
}


// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const HOUR_MS = 60 * 60 * 1000;

async function makeDelegationIdentity(expiresInMs: number): Promise<DelegationIdentity> {
  const root = Ed25519KeyIdentity.generate();
  const session = Ed25519KeyIdentity.generate();
  const chain = await DelegationChain.create(
    root,
    session.getPublicKey(),
    new Date(Date.now() + expiresInMs),
  );
  return DelegationIdentity.fromDelegation(session, chain);
}

function anonymousIdentity(): Identity {
  return { getPrincipal: () => Principal.anonymous() } as unknown as Identity;
}

interface MockClientScript {
  identity: Identity;
  authenticated?: boolean;
  loginError?: string;
  /** Identity to expose after a successful login (defaults to `identity`). */
  loginIdentity?: Identity;
}

interface MockClient extends AuthClientLike {
  logoutCalls: number;
  lastLoginOptions: Record<string, unknown> | null;
}

function mockClient(script: MockClientScript): MockClient {
  let current = script.authenticated ? script.identity : anonymousIdentity();
  const client: MockClient = {
    logoutCalls: 0,
    lastLoginOptions: null,
    isAuthenticated: async () => script.authenticated === true,
    getIdentity: () => current,
    async login(options) {
      // 3.4.3 shape: returns a Promise; callbacks signal completion.
      client.lastLoginOptions = options as Record<string, unknown>;
      if (script.loginError !== undefined) {
        options.onError?.(script.loginError);
        return;
      }
      current = script.loginIdentity ?? script.identity;
      options.onSuccess?.();
    },
    logout: async () => {
      client.logoutCalls += 1;
      current = anonymousIdentity();
    },
  };
  return client;
}

function authFromClient(client: AuthClientLike, policy = evaluateSessionPolicy(productionConfig(), PRODUCTION_ORIGIN)) {
  return createWalletAuth(policy, () => undefined, { createClient: async () => client });
}

// ---------------------------------------------------------------------------
// config: loopback detection, root key, origin policy
// ---------------------------------------------------------------------------

describe("config.isLocalHost", () => {
  it("accepts explicit loopback hosts only", () => {
    expect(isLocalHost("http://localhost:5173")).toBe(true);
    expect(isLocalHost("http://sub.localhost:5173")).toBe(true);
    expect(isLocalHost("http://127.0.0.1:8080")).toBe(true);
    expect(isLocalHost("http://127.42.0.7")).toBe(true);
    expect(isLocalHost("http://[::1]:4943")).toBe(true);
  });

  it("treats every non-loopback host as production", () => {
    expect(isLocalHost("https://icp-api.io")).toBe(false);
    expect(isLocalHost("https://app.stsh.fi")).toBe(false);
    expect(isLocalHost("https://localhost.evil.com")).toBe(false);
    expect(isLocalHost("https://127.0.0.1.evil.com")).toBe(false);
    expect(isLocalHost("not a url")).toBe(false);
    expect(isLocalHost("")).toBe(false);
  });
});

describe("session.shouldFetchRootKey", () => {
  it("never fetches the root key for a mainnet host, whatever the env says", () => {
    const cfg = resolveConfig({ VITE_IC_HOST: "https://icp-api.io", VITE_FETCH_ROOT_KEY: "true" });
    expect(shouldFetchRootKey(cfg)).toBe(false);
  });

  it("fetches only for an explicitly requested loopback host", () => {
    expect(
      shouldFetchRootKey(
        resolveConfig({ VITE_IC_HOST: "http://127.0.0.1:8080", VITE_FETCH_ROOT_KEY: "true" }),
      ),
    ).toBe(true);
    expect(
      shouldFetchRootKey(resolveConfig({ VITE_IC_HOST: "http://127.0.0.1:8080" })),
    ).toBe(false);
  });
});

describe("config.evaluateSessionPolicy", () => {
  it("honours the II-URL override on loopback origins only", () => {
    const cfg = resolveConfig({ VITE_II_URL: "http://localhost:4943/?canisterId=abc" });
    const local = evaluateSessionPolicy(cfg, "http://localhost:5173");
    expect(local).toEqual({
      kind: "local",
      iiUrl: "http://localhost:4943/?canisterId=abc",
      derivationOrigin: undefined,
    });
  });

  it("accepts exactly the production origin with no overrides", () => {
    const policy = evaluateSessionPolicy(productionConfig(), PRODUCTION_ORIGIN);
    expect(policy.kind).toBe("production");
    if (policy.kind === "production") expect(policy.iiUrl).toBeUndefined();
  });

  it("blocks every other production origin", () => {
    for (const origin of [
      "https://evil.example.com",
      "https://app.stsh.fi.evil.com",
      "http://app.stsh.fi", // wrong scheme
      "https://stsh.fi",
    ]) {
      const policy = evaluateSessionPolicy(productionConfig(), origin);
      expect(policy.kind, origin).toBe("blocked");
    }
  });

  it("rejects a production II-URL override (A-S20)", () => {
    const policy = evaluateSessionPolicy(
      // S1-02: supply the runtime-loaded launch origin so this arm still tests
      // the OVERRIDE refusal and not the missing-config refusal.
      { ...resolveConfig({ VITE_II_URL: "https://rogue-ii.example" }), launchOrigin: PRODUCTION_ORIGIN },
      PRODUCTION_ORIGIN,
    );
    expect(policy.kind).toBe("blocked");
    if (policy.kind === "blocked") expect(policy.reason).toMatch(/identity-provider override/i);
  });

  it("rejects an UNRECOGNISED derivationOrigin (WT-1: the guard is inverted, not removed)", () => {
    // A-S8 refused ANY derivationOrigin under C-19(b); WT-1 reverses that to a
    // positive assertion against the pinned wallet-canister origin. What did NOT
    // change, and what this arm holds: an origin nobody authorised is refused.
    const policy = evaluateSessionPolicy(
      // S1-02: supply the runtime-loaded launch origin so this arm still tests
      // the OVERRIDE refusal and not the missing-config refusal.
      { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN, derivationOrigin: "https://other.stsh.fi" },
      PRODUCTION_ORIGIN,
    );
    expect(policy.kind).toBe("blocked");
    if (policy.kind === "blocked") expect(policy.reason).toMatch(/derivationOrigin/);
  });
});

// ---------------------------------------------------------------------------
// session epoch
// ---------------------------------------------------------------------------

describe("sessionEpoch", () => {
  it("commits only under the captured epoch", () => {
    const epoch = new SessionEpoch();
    const captured = epoch.current();
    let committed = 0;
    expect(epoch.commit(captured, () => committed++)).toBe(true);
    epoch.advance();
    expect(epoch.commit(captured, () => committed++)).toBe(false);
    expect(committed).toBe(1);
    expect(epoch.isCurrent(captured)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// auth: verified expiry via real delegation chains
// ---------------------------------------------------------------------------

describe("auth.verifyIdentity", () => {
  it("accepts a live delegation inside the 8h ceiling", async () => {
    expect(verifyIdentity(await makeDelegationIdentity(4 * HOUR_MS))).toBe("valid");
  });

  it("flags an expired delegation as expired (isDelegationValid)", async () => {
    expect(verifyIdentity(await makeDelegationIdentity(-1000))).toBe("expired");
  });

  it("flags a delegation beyond the 8h ceiling as expired", async () => {
    expect(verifyIdentity(await makeDelegationIdentity(9 * HOUR_MS))).toBe("expired");
  });

  it("treats an anonymous or delegation-less identity as anonymous", async () => {
    expect(verifyIdentity(anonymousIdentity())).toBe("anonymous");
    const plain = { getPrincipal: () => Principal.fromText("aaaaa-aa") } as unknown as Identity;
    expect(verifyIdentity(plain)).toBe("anonymous");
  });
});

describe("auth.createWalletAuth", () => {
  it("refuses to construct under a blocked policy", async () => {
    await expect(
      createWalletAuth({ kind: "blocked", reason: "wrong origin" }, () => undefined, {
        createClient: async () => mockClient({ identity: anonymousIdentity() }),
      }),
    ).rejects.toThrow(/blocked session policy/);
  });

  it("restores a stored, verified session", async () => {
    const identity = await makeDelegationIdentity(4 * HOUR_MS);
    const client = mockClient({ identity, authenticated: true });
    const auth = await authFromClient(client);
    const session = await auth.restore();
    expect(session).not.toBeNull();
    expect(session?.principal.toText()).toBe(identity.getPrincipal().toText());
    expect(client.logoutCalls).toBe(0);
  });

  it("discards a stored session ONLY on verified expiry", async () => {
    const client = mockClient({
      identity: await makeDelegationIdentity(-1000),
      authenticated: true,
    });
    const auth = await authFromClient(client);
    expect(await auth.restore()).toBeNull();
    expect(client.logoutCalls).toBe(1); // the dead session is dropped from storage
  });

  it("returns null (no logout) when nothing is stored", async () => {
    const client = mockClient({ identity: anonymousIdentity(), authenticated: false });
    const auth = await authFromClient(client);
    expect(await auth.restore()).toBeNull();
    expect(client.logoutCalls).toBe(0);
  });

  it("logs in via the reviewed default provider with the 8h ceiling", async () => {
    const identity = await makeDelegationIdentity(4 * HOUR_MS);
    const client = mockClient({ identity: anonymousIdentity(), loginIdentity: identity });
    const auth = await authFromClient(client); // production policy
    const session = await auth.login();
    expect(session.principal.isAnonymous()).toBe(false);
    // Production: identityProvider undefined -> AuthClient 3.4.3 reviewed default.
    expect(client.lastLoginOptions?.identityProvider).toBeUndefined();
    expect(client.lastLoginOptions?.maxTimeToLive).toBe(MAX_DELEGATION_TTL_NS);
    // WT-1: `productionConfig()` carries no derivationOrigin — the TRANSITIONAL
    // deployment — and in that case the key must be ABSENT from the options
    // object, not present as `undefined`. This is the pre-WT-1 wire behaviour,
    // asserted unchanged. The forwarding case is covered in
    // `wt1_canister_rooted_identity.test.ts`.
    expect("derivationOrigin" in (client.lastLoginOptions ?? {})).toBe(false);
  });

  it("honours the loopback II-URL override in the local policy", async () => {
    const identity = await makeDelegationIdentity(HOUR_MS);
    const client = mockClient({ identity: anonymousIdentity(), loginIdentity: identity });
    const cfg = resolveConfig({ VITE_II_URL: "http://localhost:4943/ii" });
    const auth = await createWalletAuth(
      evaluateSessionPolicy(cfg, "http://localhost:5173"),
      () => undefined,
      { createClient: async () => client },
    );
    await auth.login();
    expect(client.lastLoginOptions?.identityProvider).toBe("http://localhost:4943/ii");
  });

  it("failed login rejects without minting any session state", async () => {
    const client = mockClient({ identity: anonymousIdentity(), loginError: "UserInterrupt" });
    const auth = await authFromClient(client);
    await expect(auth.login()).rejects.toThrow(/UserInterrupt/);
    expect(client.logoutCalls).toBe(0);
    expect(await auth.restore()).toBeNull();
  });

  it("a login that lands with an already-invalid delegation is discarded", async () => {
    const client = mockClient({
      identity: anonymousIdentity(),
      loginIdentity: await makeDelegationIdentity(-1000),
    });
    const auth = await authFromClient(client);
    await expect(auth.login()).rejects.toThrow(/invalid or expired/);
    expect(client.logoutCalls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// app shell: origin guard, epoch races, error discipline
// ---------------------------------------------------------------------------

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void };
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function fakeToken(balanceOf: TokenCanister["balanceOf"]): TokenCanister {
  return {
    balanceOf,
    metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
    fee: async () => 0n,
  };
}

const failingMutationToken = {
  transfer: async () => {
    throw new Error("transfer must not be called in A1 tests");
  },
  ...unusedIcrc2,
};

const emptyStaking = {
  getStakePositions: async () => [],
  getPendingRewards: async () => 0n,
};

const emptyVesting = {
  getSchedule: async () => null,
  claimableAmount: async () => 0n,
};

interface Harness {
  deps: AppDeps;
  counters: { readBuilt: number; mutationBuilt: number; authCreated: number };
}

function harness(opts: {
  origin?: string;
  balanceOf?: TokenCanister["balanceOf"];
  restore?: () => Promise<AuthSession | null>;
  login?: () => Promise<AuthSession>;
  verify?: () => SessionVerdict;
  onAuthLogout?: () => void;
}): Harness {
  const counters = { readBuilt: 0, mutationBuilt: 0, authCreated: 0 };
  const token = fakeToken(opts.balanceOf ?? (async () => 0n));
  const deps: AppDeps = {
    origin: opts.origin ?? PRODUCTION_ORIGIN,
    // S1-02: the launch origin is runtime-loaded; this harness supplies the ruled
    // value so the policy sees the same origin it is evaluated against.
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () => {
      counters.readBuilt += 1;
      return { token, staking: emptyStaking, vesting: emptyVesting } satisfies ReadActors;
    },
    buildMutationActors: async () => {
      counters.mutationBuilt += 1;
      return { token: failingMutationToken } satisfies MutationActors;
    },
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      counters.authCreated += 1;
      const auth: WalletAuth = {
        restore: opts.restore ?? (async () => null),
        login:
          opts.login ??
          (async () => {
            throw new Error("login not scripted");
          }),
        logout: async () => opts.onAuthLogout?.(),
        verify: opts.verify ?? (() => "valid"),
      };
      return auth;
    },
  };
  return { deps, counters };
}

async function fakeSession(): Promise<AuthSession> {
  const identity = await makeDelegationIdentity(4 * HOUR_MS);
  return {
    identity: identity as unknown as DelegationIdentityLike,
    principal: identity.getPrincipal(),
  };
}

function mountContainer(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

describe("app shell (mountApp)", () => {
  it("boots anonymous: reads available, no mutation actors, login enabled", async () => {
    window.location.hash = "";
    const h = harness({});
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    expect(ctx.state.principal).toBeNull();
    expect(ctx.mutationActors).toBeNull();
    expect(h.counters.readBuilt).toBe(1);
    expect(h.counters.mutationBuilt).toBe(0);
    // J-17c: `readActors` is nullable now. This harness supplies valid ids, so
    // a null here is a regression in the fail-soft path, not a config fact.
    expect(ctx.readActors).not.toBeNull();
    const balance = await ctx.readActors!.token.balanceOf(Principal.fromText("aaaaa-aa"));
    expect(balance).toBe(0n); // anonymous reads work with no identity
  });

  it("restores a stored session and builds mutation actors after the policy gate", async () => {
    window.location.hash = "";
    const session = await fakeSession();
    const container = mountContainer();
    const h = harness({ restore: async () => session });
    const ctx = await mountApp(container, {}, h.deps);
    expect(ctx.state.principal?.toText()).toBe(session.principal.toText());
    expect(ctx.mutationActors).not.toBeNull();
    expect(h.counters.mutationBuilt).toBe(1);
    expect(
      container.querySelector('[data-testid="principal"]')?.textContent,
    ).toBe(session.principal.toText());
  });

  it("blocked origin: no auth client, no mutation actors, login refused — reads still work", async () => {
    window.location.hash = "";
    const session = await fakeSession();
    const container = mountContainer();
    const h = harness({ origin: "https://evil.example.com", restore: async () => session });
    const ctx = await mountApp(container, {}, h.deps);
    // Origin guard fired BEFORE any auth/mutation construction (A-S8).
    expect(h.counters.authCreated).toBe(0);
    expect(h.counters.mutationBuilt).toBe(0);
    expect(h.counters.readBuilt).toBe(1);
    expect(ctx.policy.kind).toBe("blocked");
    const loginBtn = container.querySelector<HTMLButtonElement>('[data-testid="login"]');
    expect(loginBtn?.disabled).toBe(true);
    await ctx.login();
    expect(ctx.state.principal).toBeNull();
    expect(ctx.mutationActors).toBeNull();
    expect(ctx.state.status?.kind).toBe("error");
  });

  it("login success commits under a fresh epoch; failed login mutates nothing", async () => {
    window.location.hash = "";
    const session = await fakeSession();
    let attempt = 0;
    const h = harness({
      login: async () => {
        attempt += 1;
        if (attempt === 1) throw new Error("Internet Identity login failed: UserInterrupt");
        return session;
      },
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);

    await ctx.login(); // attempt 1 fails
    expect(ctx.state.principal).toBeNull();
    expect(ctx.mutationActors).toBeNull();
    expect(h.counters.mutationBuilt).toBe(0);
    expect(ctx.state.status?.kind).toBe("error");

    await ctx.login(); // attempt 2 succeeds
    expect(ctx.state.principal?.toText()).toBe(session.principal.toText());
    expect(ctx.mutationActors).not.toBeNull();
    expect(ctx.state.status).toEqual({ kind: "success", msg: "Logged in." });
  });

  it("logout advances the epoch before clearing, and a stale balance result is discarded", async () => {
    window.location.hash = "";
    const session = await fakeSession();
    const gate = deferred<bigint>();
    let authLogouts = 0;
    const h = harness({
      restore: async () => session,
      balanceOf: () => gate.promise,
      onAuthLogout: () => {
        authLogouts += 1;
      },
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    expect(ctx.state.principal).not.toBeNull();

    const inflight = ctx.refreshBalance(); // captures the pre-logout epoch
    await ctx.logout();
    expect(ctx.state.principal).toBeNull();
    expect(ctx.state.balance).toBeNull();
    expect(ctx.mutationActors).toBeNull();
    expect(authLogouts).toBe(1);

    gate.resolve(999n); // stale epoch -> must NOT commit into the new session
    await inflight;
    expect(ctx.state.balance).toBeNull();
  });

  it("a generic error never logs out (A-S10)", async () => {
    window.location.hash = "";
    const session = await fakeSession();
    const h = harness({
      restore: async () => session,
      balanceOf: async () => {
        throw new Error("transport unreachable");
      },
      verify: () => "valid",
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.refreshBalance();
    expect(ctx.state.principal?.toText()).toBe(session.principal.toText());
    expect(ctx.mutationActors).not.toBeNull();
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/Balance refresh failed/);
  });

  it("only a VERIFIED delegation expiry logs out", async () => {
    window.location.hash = "";
    const session = await fakeSession();
    const h = harness({
      restore: async () => session,
      balanceOf: async () => {
        throw new Error("certificate rejected");
      },
      verify: () => "expired",
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.refreshBalance();
    expect(ctx.state.principal).toBeNull();
    expect(ctx.mutationActors).toBeNull();
    expect(ctx.state.status?.msg).toMatch(/Session expired/);
  });

  it("the spend deep link renders the spend gate — login prompt while anonymous (L3c)", async () => {
    window.location.hash = "#/spend";
    const container = mountContainer();
    const h = harness({});
    await mountApp(container, {}, h.deps);
    expect(container.querySelector('[data-testid="not-available"]')).toBeNull();
    expect(container.textContent).toMatch(/Log in with Internet Identity/i);
    window.location.hash = "";
  });

  it("the shield deep link renders the shield gate — login prompt while anonymous (L3a)", async () => {
    window.location.hash = "#/shield";
    const container = mountContainer();
    const h = harness({});
    await mountApp(container, {}, h.deps);
    expect(container.querySelector('[data-testid="not-available"]')).toBeNull();
    expect(container.textContent).toMatch(/Log in with Internet Identity to shield/i);
    window.location.hash = "";
  });
});
