/**
 * WALLET-READ-ACTORS (V1 + BINDING Addendum 1, 2026-09-22) — staking is NOT
 * INSTALLED at launch (D1), so the shipped config carries
 * `stakingCanisterId: ""`. Before this lane `createReadActors` built the
 * staking actor unconditionally; `Actor.createActor({ canisterId: "" })` threw,
 * and the J-17c boot catch nulled ALL THREE readers — the mainnet wallet could
 * not read the ledger at all (balance, transfer, spend, fee basis, shield,
 * vesting).
 *
 * Harness rules (Addendum 1 §2), binding for every arm below:
 * - H-1 the REAL `createReadActors` over configs produced by the REAL
 *   `resolveConfig`; mount arms hand `mountApp` the real factory, so the config
 *   is the one the mount itself resolved. No hand-built reader object.
 * - H-2 no module mocks of the agent, principal, actor or session modules.
 * - H-3 no network: `HttpAgent.createSync` (no time sync) and methods replaced
 *   on the REAL constructed objects only AFTER construction. The agent's
 *   `query`/`call` transport is additionally pre-spied to REJECT, so an
 *   accidental network read fails loudly instead of leaving the process.
 * - H-4 every expected value is a literal owned by this file.
 * - H-5 a restored session built from a real delegation chain, non-blocked
 *   policy (origin and launch origin both https://app.stsh.fi).
 * - H-6 the only staking principal used is the test-only `rrkah-…-cai`.
 * - H-8 every failure arm runs beside a healthy twin that differs ONLY in the
 *   targeted canister id, through the same harness and the same real factory.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { HttpAgent } from "@dfinity/agent";
import { DelegationChain, DelegationIdentity, Ed25519KeyIdentity } from "@dfinity/identity";

import type { AuthSession, DelegationIdentityLike, WalletAuth } from "../src/session/auth";
import { resolveConfig, type WalletConfig } from "../src/session/config";
import { createReadActors, type ReadActors, type ShieldedActors } from "../src/session/session";
import { mountApp, type AppDeps } from "../src/ui/app";
import { READ_SERVICES_UNAVAILABLE, type AppContext } from "../src/ui/context";
import { memoryJournalStore } from "./helpers/memoryJournalStore";

// ── test-owned literals (H-4) ──────────────────────────────────────────────

const LAUNCH_ORIGIN = "https://app.stsh.fi";

/** The global J-17c notice, written out here — never read back from the code. */
const GLOBAL_NOTICE_LITERAL =
  "Ledger read services not configured — token, staking and vesting views are unavailable.";

/** P-2(b): the staking page's own D1 refusal (U+2014 EM DASH, spaced). */
const D1_LITERAL = "Staking is not deployed at launch (D1) — staking views are unavailable.";

/** H-6: the ONLY staking principal this lane may use. Implies no deployment. */
const STAKING_FIXTURE = "rrkah-fqaaa-aaaaa-aaaaq-cai";

/** A distinctive balance, and its rendering at 8 decimals. */
const FIXTURE_BALANCE = 123_456_789n;
const FIXTURE_BALANCE_TEXT = "1.23456789 STSH";

/** A distinctive ledger fee for the spend fee basis (AC-6). */
const FIXTURE_FEE = 7_777n;

/**
 * The restored session's root key is derived from a FIXED seed, so the
 * logged-in principal is a test constant. The literal is asserted against the
 * derived identity in `fixtureSession()`, so a drift in either fails here.
 */
const FIXTURE_SEED = new Uint8Array(32).fill(0x5a);
const FIXTURE_PRINCIPAL = "uuaya-2w433-mkssv-yiekm-pjvyn-ac4f4-qcyua-mxxz3-mqam2-heg53-pqe";

/**
 * Governance fee params the spend page can price — the exit-arm fixture from
 * tests/spend_flow_l3c.test.ts (`EXIT_PARAMS`), copied as a literal.
 */
const FEE_PARAMS = {
  shieldFeeBps: 25,
  shieldFlatMinimumFeeE8s: 10_000_000n,
  minimumPrivateCredit: 0n,
  feeModelVersion: 1,
  paramsEpoch: 0n,
  protocolPrivateSpendFeeStsh: 1_000_000n,
  unshieldFeeBps: 25,
  unshieldFlatMinimumFeeE8s: 250_000_000n,
};

/** The healthy configured-staking twin (AC-4 / AC-5 C-H). */
const ENV_STAKING_CONFIGURED = { VITE_STAKING_CANISTER_ID: STAKING_FIXTURE };
/** The shipped env: nothing set, so staking is "" (D1). */
const ENV_SHIPPED: Record<string, string | undefined> = {};

// ── harness ────────────────────────────────────────────────────────────────

const HOUR_MS = 60 * 60 * 1000;

async function fixtureSession(): Promise<AuthSession> {
  const root = Ed25519KeyIdentity.generate(FIXTURE_SEED);
  const sessionKey = Ed25519KeyIdentity.generate();
  const chain = await DelegationChain.create(
    root,
    sessionKey.getPublicKey(),
    new Date(Date.now() + 4 * HOUR_MS),
  );
  const identity = DelegationIdentity.fromDelegation(sessionKey, chain);
  expect(identity.getPrincipal().toText()).toBe(FIXTURE_PRINCIPAL);
  return {
    identity: identity as unknown as DelegationIdentityLike,
    principal: identity.getPrincipal(),
  };
}

/** A no-network agent whose transport REJECTS if anything reaches it (H-3). */
function isolatedAgent(host: string): {
  agent: HttpAgent;
  query: ReturnType<typeof vi.fn>;
  call: ReturnType<typeof vi.fn>;
} {
  const agent = HttpAgent.createSync({ host });
  const query = vi
    .spyOn(agent, "query")
    .mockRejectedValue(new Error("H-3: network query forbidden in this suite"));
  const call = vi
    .spyOn(agent, "call")
    .mockRejectedValue(new Error("H-3: network call forbidden in this suite"));
  return { agent, query: query as never, call: call as never };
}

const balanceSpy = () => vi.fn(async (..._args: unknown[]) => FIXTURE_BALANCE);
const feeSpy = () => vi.fn(async () => FIXTURE_FEE);

interface FactoryProbe {
  /** Every config the mount handed the factory (exactly one per mount). */
  configs: WalletConfig[];
  /** The real object `createReadActors` returned (after method replacement). */
  built: ReadActors | null;
  query: ReturnType<typeof vi.fn> | null;
  call: ReturnType<typeof vi.fn> | null;
  balanceOf: ReturnType<typeof balanceSpy>;
  fee: ReturnType<typeof feeSpy>;
}

/**
 * H-1: the REAL factory, on the config the mount resolved. Methods are replaced
 * on the real constructed `token` only AFTER `createReadActors` returned — a
 * construction failure therefore propagates exactly as in production.
 */
function realFactory(): { build: AppDeps["buildReadActors"]; probe: FactoryProbe } {
  const probe: FactoryProbe = {
    configs: [],
    built: null,
    query: null,
    call: null,
    balanceOf: balanceSpy(),
    fee: feeSpy(),
  };
  const build = async (cfg: WalletConfig): Promise<ReadActors> => {
    probe.configs.push(cfg);
    const { agent, query, call } = isolatedAgent(cfg.host);
    probe.query = query;
    probe.call = call;
    const real = createReadActors(agent, cfg);
    // Guarded so the HARNESS can never be what nulls the readers: if a future
    // factory returned a null token, the mount would see it as-is (and the
    // AC-5 mount arms would fail on `readActors !== null`), rather than this
    // replacement throwing and standing in for the real construction failure.
    if (real.token !== null && typeof real.token === "object") {
      real.token.balanceOf = probe.balanceOf as never;
      real.token.fee = probe.fee as never;
    }
    probe.built = real;
    return real;
  };
  return { build, probe };
}

function authFor(session: AuthSession | null): WalletAuth {
  return {
    restore: async () => session,
    login: async () => {
      throw new Error("login not scripted");
    },
    logout: async () => {},
    verify: () => "valid",
  };
}

function shieldedWithFeeParams(): ShieldedActors {
  return {
    pool: { getGovernanceFeeParams: async () => FEE_PARAMS },
    vetkeys: {},
  } as unknown as ShieldedActors;
}

async function mountWith(opts: {
  env: Record<string, string | undefined>;
  hash: string;
  session: AuthSession | null;
  shielded?: boolean;
}): Promise<{ ctx: AppContext; root: HTMLElement; probe: FactoryProbe }> {
  document.body.innerHTML = "";
  window.location.hash = opts.hash;
  const root = document.createElement("div");
  document.body.append(root);
  const { build, probe } = realFactory();
  const deps: AppDeps = {
    origin: LAUNCH_ORIGIN,
    loadLaunchOrigin: async () => LAUNCH_ORIGIN,
    loadDerivationOrigin: async () => undefined,
    buildReadActors: build,
    buildMutationActors: async () => ({}) as never,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => authFor(opts.session),
    ...(opts.shielded === true
      ? { buildShieldedActors: async () => shieldedWithFeeParams() }
      : {}),
  };
  const ctx = await mountApp(root, opts.env, deps);
  // H-1: the factory saw exactly one config, the one the mount resolved.
  expect(probe.configs).toHaveLength(1);
  return { ctx, root, probe };
}

function pageContent(root: HTMLElement): HTMLElement {
  const main = root.querySelector<HTMLElement>("main.content");
  expect(main).not.toBeNull();
  return main!;
}

function byTestId(root: ParentNode, id: string): Element | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function construct(cfg: WalletConfig): ReadActors {
  return createReadActors(isolatedAgent(cfg.host).agent, cfg);
}

beforeEach(() => {
  window.location.hash = "";
  document.body.innerHTML = "";
});

// ── AC-1 ───────────────────────────────────────────────────────────────────

describe("AC-1 — the shipped config constructs the read actors (staking absent, D1)", () => {
  it("createReadActors(resolveConfig({})) returns token + vesting, and staking === null", () => {
    const cfg = resolveConfig({});
    expect(cfg.stakingCanisterId).toBe("");
    expect(() => construct(cfg)).not.toThrow();
    const actors = construct(cfg);
    expect(actors.token).not.toBeNull();
    expect(actors.vesting).not.toBeNull();
    expect(actors.staking).toBeNull();
  });
});

// ── AC-2 ───────────────────────────────────────────────────────────────────

describe("AC-2 — the shipped config mounts with a working balance", () => {
  it("#/account: no global notice, readActors live, balanceOf queried for the session principal", async () => {
    const session = await fixtureSession();
    const { ctx, root, probe } = await mountWith({
      env: ENV_SHIPPED,
      hash: "#/account",
      session,
    });
    expect(ctx.state.principal?.toText()).toBe(session.principal.toText());
    expect(ctx.state.principal?.toText()).toBe(FIXTURE_PRINCIPAL);

    // Soft, so a red run reports EVERY semantic symptom, not just the first.
    expect.soft(byTestId(root, "read-services-notice")?.textContent ?? null).toBeNull();
    expect.soft(root.textContent ?? "").not.toContain(GLOBAL_NOTICE_LITERAL);
    expect.soft(ctx.readActors).not.toBeNull();
    expect.soft(ctx.readActors?.staking).toBeNull();

    await ctx.refreshBalance();

    // VETKEYS-AGE-2MIN (C-1, Blocker-3 ruling 2026-09-23): session restore now
    // observes the balance itself, so the ledger is read TWICE — once by the
    // restore observation, once by this explicit refresh.
    expect.soft(probe.balanceOf).toHaveBeenCalledTimes(2);
    const args = probe.balanceOf.mock.calls[0] ?? [];
    expect.soft(args).toHaveLength(1);
    expect.soft((args[0] as { toText(): string } | undefined)?.toText()).toBe(FIXTURE_PRINCIPAL);
    expect.soft(ctx.state.balance).toBe(FIXTURE_BALANCE);
    const balance = byTestId(root, "balance");
    expect.soft(balance).not.toBeNull();
    expect.soft(balance?.textContent).toBe(FIXTURE_BALANCE_TEXT);
    expect.soft(probe.query?.mock.calls.length ?? -1).toBe(0);
  });
});

// ── AC-3 ───────────────────────────────────────────────────────────────────

describe("AC-3 — #/staking refuses at mount with the D1 copy when staking is absent", () => {
  it.each([
    ["anonymous", false],
    ["restored session", true],
  ])("%s: D1 refusal only, no controls, no figures, no global notice", async (_label, withSession) => {
    const session = withSession ? await fixtureSession() : null;
    const { ctx, root } = await mountWith({ env: ENV_SHIPPED, hash: "#/staking", session });
    if (session !== null) expect(ctx.state.principal?.toText()).toBe(FIXTURE_PRINCIPAL);
    else expect(ctx.state.principal).toBeNull();

    expect(ctx.readActors).not.toBeNull();
    expect(ctx.readActors?.staking).toBeNull();

    const page = pageContent(root);
    const refusal = byTestId(page, "staking-not-deployed");
    expect(refusal).not.toBeNull();
    expect(refusal!.textContent).toBe(D1_LITERAL);
    expect(refusal!.getAttribute("class")).toBe("status-msg error");

    for (const absent of [
      "staking-holder",
      "staking-load",
      "staking-unavailable",
      "staking-holder-shown",
      "pending-rewards",
    ]) {
      expect(byTestId(page, absent)).toBeNull();
    }
    expect(page.textContent ?? "").not.toContain("Loading…");
    expect(page.textContent ?? "").not.toMatch(/\d[\d,.]*\s*STSH/);
    // Nothing else of the staking page: a heading and the refusal.
    expect(Array.from(page.children).map((c) => c.tagName)).toEqual(["H2", "P"]);
    expect(page.querySelector("h2")?.textContent).toBe("Staking");

    // The shell-wide J-17c notice is NOT the staking-absent signal.
    expect(byTestId(root, "read-services-notice")).toBeNull();
    expect(root.textContent ?? "").not.toContain(GLOBAL_NOTICE_LITERAL);

    // P-2(f): the D1 copy is staking-page-only.
    ctx.navigate("account");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(window.location.hash).toBe("#/account");
    // Non-vacuous: the account page actually rendered in place of staking.
    expect(byTestId(root, withSession ? "principal" : "login")).not.toBeNull();
    expect(root.textContent ?? "").not.toContain(D1_LITERAL);
    expect(byTestId(root, "staking-not-deployed")).toBeNull();
  });
});

// ── AC-4 ───────────────────────────────────────────────────────────────────

describe("AC-4 — a configured staking id is preserved", () => {
  it("resolveConfig({ VITE_STAKING_CANISTER_ID: rrkah }) → token, staking, vesting all non-null", () => {
    const cfg = resolveConfig(ENV_STAKING_CONFIGURED);
    expect(cfg.stakingCanisterId).toBe(STAKING_FIXTURE);
    const actors = construct(cfg);
    expect(actors.token).not.toBeNull();
    expect(actors.staking).not.toBeNull();
    expect(actors.vesting).not.toBeNull();
    expect(typeof actors.staking?.getStakePositions).toBe("function");
  });

  it("a malformed NON-EMPTY staking id still throws (P-1(d))", () => {
    const cfg = resolveConfig({ VITE_STAKING_CANISTER_ID: "not-a-principal" });
    expect(() => construct(cfg)).toThrow();
    // Paired control: the same factory on a well-formed staking id constructs.
    expect(() => construct(resolveConfig(ENV_STAKING_CONFIGURED))).not.toThrow();
  });
});

// ── AC-5 ───────────────────────────────────────────────────────────────────

describe("AC-5 — fail-closed preserved for BOTH required readers, with isolated causes", () => {
  const ARMS: Array<{
    name: string;
    failing: Record<string, string | undefined>;
    twin: Record<string, string | undefined>;
    target: "tokenCanisterId" | "vestingCanisterId";
  }> = [
    {
      name: "5a token id empty (staking configured)",
      failing: { ...ENV_STAKING_CONFIGURED, VITE_TOKEN_CANISTER_ID: "" },
      twin: ENV_STAKING_CONFIGURED,
      target: "tokenCanisterId",
    },
    {
      name: "5b vesting id empty (staking configured)",
      failing: { ...ENV_STAKING_CONFIGURED, VITE_VESTING_CANISTER_ID: "" },
      twin: ENV_STAKING_CONFIGURED,
      target: "vestingCanisterId",
    },
    {
      name: "5c vesting id empty (shipped staking-absent)",
      failing: { VITE_VESTING_CANISTER_ID: "" },
      twin: ENV_SHIPPED,
      target: "vestingCanisterId",
    },
  ];

  it("healthy twin C-H constructs all three readers", () => {
    const actors = construct(resolveConfig(ENV_STAKING_CONFIGURED));
    expect(actors.token).not.toBeNull();
    expect(actors.staking).not.toBeNull();
    expect(actors.vesting).not.toBeNull();
  });

  it.each(ARMS)("$name — (i) constructor level: arm throws, twin does not", ({ failing, twin, target }) => {
    const bad = resolveConfig(failing);
    const good = resolveConfig(twin);
    // H-8: the two configs differ ONLY in the targeted id.
    const diff = (Object.keys(good) as Array<keyof WalletConfig>).filter(
      (k) => good[k] !== bad[k],
    );
    expect(diff).toEqual([target]);
    expect(bad[target]).toBe("");
    expect(() => construct(bad)).toThrow();
    expect(() => construct(good)).not.toThrow();
  });

  it.each(ARMS)(
    "$name — (ii)-(iv) mount level: twin healthy, arm refuses with the notice and no figure",
    async ({ failing, twin }) => {
      const session = await fixtureSession();

      // The healthy twin, through the SAME harness and the SAME real factory.
      const healthy = await mountWith({ env: twin, hash: "#/account", session });
      expect(healthy.ctx.state.principal?.toText()).toBe(FIXTURE_PRINCIPAL);
      expect(healthy.ctx.readActors).not.toBeNull();
      expect(byTestId(healthy.root, "read-services-notice")).toBeNull();
      await healthy.ctx.refreshBalance();
      // VETKEYS-AGE-2MIN (C-1, Blocker-3 ruling 2026-09-23): one read from the
      // restore observation, one from this explicit refresh.
      expect(healthy.probe.balanceOf).toHaveBeenCalledTimes(2);
      expect(healthy.ctx.state.balance).toBe(FIXTURE_BALANCE);
      expect(byTestId(healthy.root, "balance")?.textContent).toBe(FIXTURE_BALANCE_TEXT);

      // The failing arm.
      const { ctx, root, probe } = await mountWith({ env: failing, hash: "#/account", session });
      // (ii) logged in before any refresh.
      expect(ctx.state.principal?.toText()).toBe(FIXTURE_PRINCIPAL);
      // (iii) all readers null, and the global notice with the literal text.
      expect(ctx.readActors).toBeNull();
      expect(probe.built).toBeNull();
      const notice = byTestId(root, "read-services-notice");
      expect(notice).not.toBeNull();
      expect(notice!.textContent).toBe(GLOBAL_NOTICE_LITERAL);
      expect(notice!.textContent).toBe(READ_SERVICES_UNAVAILABLE);
      // (iv) a refresh refuses rather than fabricating a figure.
      await ctx.refreshBalance();
      expect(ctx.state.status).toEqual({ kind: "error", msg: GLOBAL_NOTICE_LITERAL });
      expect(ctx.state.balance).toBeNull();
      const balance = byTestId(root, "balance");
      expect(balance).not.toBeNull();
      expect(balance!.textContent).toBe("—");
      expect(probe.balanceOf).not.toHaveBeenCalled();
      expect(probe.query?.mock.calls.length ?? 0).toBe(0);
    },
  );
});

// ── AC-6 ───────────────────────────────────────────────────────────────────

describe("AC-6 — the spend fee basis loads with staking absent", () => {
  it("ctx.loadSpendFeeBasis() reads token.fee and stores the basis", async () => {
    const session = await fixtureSession();
    const { ctx, root, probe } = await mountWith({
      env: ENV_SHIPPED,
      hash: "#/account",
      session,
      shielded: true,
    });
    expect(ctx.state.principal?.toText()).toBe(FIXTURE_PRINCIPAL);
    // Preconditions — without these the arm would be vacuous.
    expect(ctx.shieldedActors).not.toBeNull();
    expect(ctx.readActors).not.toBeNull();
    expect(ctx.readActors?.staking).toBeNull();
    expect(ctx.state.spendFeeBasis).toBeNull();

    await ctx.loadSpendFeeBasis();

    expect(probe.fee).toHaveBeenCalledTimes(1);
    expect(ctx.state.spendFeeBasis).not.toBeNull();
    expect(ctx.state.spendFeeBasis?.ledgerFee).toBe(FIXTURE_FEE);
    expect(ctx.state.spendFeeBasis?.params).toEqual(FEE_PARAMS);
    expect(byTestId(root, "read-services-notice")).toBeNull();
    expect(probe.query?.mock.calls.length ?? -1).toBe(0);
  });
});
