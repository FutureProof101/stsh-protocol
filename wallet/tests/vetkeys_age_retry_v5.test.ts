// @vitest-environment jsdom
/**
 * A1 fix brief V5 §6.6, arm 43 (SSA RED-4 closure) — THE RETRY DISCIPLINE.
 *
 * The on-ramp is hands-off, so a first-time wait retries by itself. But
 * POLLING IS ACTIVELY HARMFUL: the A-2 meter charges every attempt at five per
 * hour, so a client polling through the age-in (T, now 2 minutes) can exhaust the
 * caller at the exact instant T is reached — turning the wait into a refusal.
 *
 * So the contract is EXACTLY ONE automatic retry, at the deadline the canister
 * named, on the injected monotonic clock and injected scheduler the re-pin lane
 * already built. This file proves that CAUSALLY, by counting attempts AT THE
 * CANISTER BOUNDARY — not by counting timer fires, which the brief expressly
 * rejects as evidence: a timer that fires proves a timer fired, not that a
 * canister was called.
 */

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

// VETKEYS-AGE-2MIN (A1 notes v3 §A.12/§A.13 item 12) — two PASS-THROUGH seams.
// Since WALLET-SHIELD-LAYER1, shield gets `fetchKeys` from the app exactly as
// scan and spend do (`deps.fetchKeys ?? sessionFetchKeys`), so EVERY arm in this
// file — scan and shield alike — takes the harness's `deps.fetchKeys`
// pass-through (one `getEncryptedVetkey` per attempt) and never reaches the
// `fetchUserVetKey` mock below. That mock is kept as a backstop with the same
// count shape (verification key, then the derive — so an attempt is still
// counted at the canister) and a fixture vetKey, because real BLS decryption
// needs a real vetKD reply. The deployment binding is stubbed because the pool
// here is a fake; the shield flow's own C-DOM-2 guard is covered by
// shield_flow_l3a.
vi.mock("../src/crypto/vetkeys", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/crypto/vetkeys")>();
  const { VetKey } = await import("@dfinity/vetkeys");
  return {
    ...real,
    fetchUserVetKey: async (canister: import("../src/crypto/vetkeys").VetkeysCanister) => {
      await canister.getVetkeyVerificationKey();
      const derived = await canister.getEncryptedVetkey(new Uint8Array(48).fill(2));
      const hex =
        "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
      const bytes = new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
      return { vetKey: VetKey.deserialize(bytes), verificationKey: {} as never, remaining: derived.remaining };
    },
  };
});
// jsdom has no IndexedDB: "this browser has no device yet" for the priming
// helper, and no persistence (these arms never reach enrolment).
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
import type { VetKey } from "@dfinity/vetkeys";

import { mountApp, type AppDeps, type ScanWorkerInput } from "../src/ui/app";
import { VetkeysCallError } from "../src/crypto/vetkeys";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import type { VetkeysCanister } from "../src/crypto/vetkeys";
import type { ScanOutcome } from "../src/crypto/scanner";
import type { AppContext } from "../src/ui/context";
import type { VetkeysError } from "../../src/declarations/vetkeys/vetkeys.did";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x21));
// The PRODUCTION key name: the app resolves the authoritative name and refuses
// anything else (the C-VK-3 sandwich), so the fake canister must present the
// one a production origin expects or the scan aborts before any fetch.
const CONFIG: [string, string] = ["stsh.wallet.notes.v1", "key_1"];
/** T = 2 minutes (559b411e…), in the units each surface uses. */
const T_NS = 120_000_000_000n;
const T_SECONDS = 120;

const FAKE_VETKEY = {
  serialize: () => new Uint8Array(48).fill(9),
  deriveSymmetricKey: () => new Uint8Array(32).fill(7),
} as unknown as VetKey;

const EMPTY_OUTCOME: ScanOutcome = {
  notes: [],
  scannedUpTo: 0n,
  mirrorHead: { leafCount: 0n, root: new Uint8Array(32) },
  quarantine: { total: 0, ring: [] },
  spentSet: new Set(),
};

const token: TokenCanister = {
  balanceOf: async () => 0n,
  metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
  fee: async () => 0n,
};

function fakeSession(): AuthSession {
  return {
    identity: { getPrincipal: () => USER } as unknown as AuthSession["identity"],
    principal: USER,
  };
}

const ageRefusal = (ns: bigint): VetkeysError =>
  ({ EligibilityAgeNotMet: { retry_after_ns: ns } }) as VetkeysError;

/**
 * A canister that counts EVERY key-derivation attempt that reaches it.
 *
 * `script` decides what each attempt returns, by attempt number. This is the
 * boundary at which an attempt becomes a canister call, so a count here is the
 * causal quantity arm 43 asks for.
 */
function countingVetkeys(script: (attempt: number) => "age-refuse" | "succeed"): {
  canister: VetkeysCanister;
  attempts: () => number;
} {
  let attempts = 0;
  const canister: VetkeysCanister = {
    async getConfig() {
      return CONFIG;
    },
    async getVetkeyVerificationKey(): Promise<Uint8Array> {
      return new Uint8Array(96).fill(3);
    },
    async getEncryptedVetkey(): Promise<{ encryptedKey: Uint8Array; remaining: number }> {
      attempts += 1;
      if (script(attempts) === "age-refuse") {
        throw new VetkeysCallError("get_encrypted_vetkey", ageRefusal(T_NS));
      }
      return { encryptedKey: new Uint8Array(192).fill(1), remaining: 4 };
    },
    async registerDevice(): Promise<never> {
      throw new Error("registerDevice not scripted");
    },
    async revokeDevice(): Promise<never> {
      throw new Error("revokeDevice not scripted");
    },
    async getWrappedSecret(): Promise<never> {
      throw new Error("getWrappedSecret not scripted");
    },
    async listDevices() {
      return [];
    },
    async replaceEnvelope(): Promise<never> {
      throw new Error("replaceEnvelope not scripted");
    },
  } as unknown as VetkeysCanister;
  return { canister, attempts: () => attempts };
}

/** A controllable monotonic clock and a one-slot scheduler. */
function fakeTime() {
  let nowMs = 1_000_000;
  const ticks: Array<{ fn: () => void; cancelled: boolean }> = [];
  return {
    now: () => nowMs,
    /** Move the clock, then let every live ticker observe the new time. */
    advanceSeconds(seconds: number): void {
      nowMs += seconds * 1_000;
      for (const t of ticks) if (!t.cancelled) t.fn();
    },
    /** Fire the tickers WITHOUT moving the clock. */
    tickOnly(): void {
      for (const t of ticks) if (!t.cancelled) t.fn();
    },
    liveTickers: () => ticks.filter((t) => !t.cancelled).length,
    scheduleTick(fn: () => void): () => void {
      const entry = { fn, cancelled: false };
      ticks.push(entry);
      return () => {
        entry.cancelled = true;
      };
    },
  };
}

function harness(opts: {
  vetkeys: VetkeysCanister;
  clock: ReturnType<typeof fakeTime>;
  scanNotes?: (input: ScanWorkerInput) => Promise<ScanOutcome>;
}): AppDeps {
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
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      const auth: WalletAuth = {
        restore: async () => fakeSession(),
        login: async () => fakeSession(),
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    buildShieldedActors: async () =>
      ({ pool: {} as ShieldedActors["pool"], vetkeys: opts.vetkeys }) satisfies ShieldedActors,
    createCacheStore: async () => (await memoryHarness()).store,
    scanNotes: opts.scanNotes ?? (async () => EMPTY_OUTCOME),
    // THE FETCH SEAM IS A PASS-THROUGH, not a substitute: it calls the canister
    // object, so every attempt is counted where an attempt actually becomes a
    // canister call. Replacing this with a canned reply would make the count a
    // count of the seam instead.
    fetchKeys: async (vetkeys) => {
      await vetkeys.getEncryptedVetkey(new Uint8Array(48).fill(2));
      return { vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 4 };
    },
    now: opts.clock.now,
    scheduleTick: opts.clock.scheduleTick,
  };
}

async function mounted(deps: AppDeps): Promise<AppContext> {
  // RESET THE HASH. jsdom shares one `window` across every arm in a file, so a
  // route an earlier arm navigated to is still the current one here — and
  // `navigate` to the route you are already on fires no hashchange, which would
  // make a cancellation arm pass by doing nothing at all.
  window.location.hash = "#/account";
  const node = document.createElement("div");
  document.body.append(node);
  const ctx = await mountApp(node, {}, deps);
  await ctx.unlockNoteCache("pw");
  return ctx;
}

describe("§6.6 arm 43 — exactly one automatic retry, at the deadline", () => {
  it("makes EXACTLY TWO canister attempts: the refusal and ONE retry", async () => {
    const { canister, attempts } = countingVetkeys((n) => (n === 1 ? "age-refuse" : "succeed"));
    const clock = fakeTime();
    const ctx = await mounted(harness({ vetkeys: canister, clock }));

    await ctx.scan();
    expect(attempts(), "the first attempt is the refusal").toBe(1);

    // ZERO ATTEMPTS BEFORE T. The ticker may run — it is a clock watch, not a
    // request loop — but nothing may reach the canister early. This is the
    // half that fails if the retry were an INTERVAL of network calls.
    clock.advanceSeconds(T_SECONDS - 1);
    await Promise.resolve();
    expect(attempts(), "no attempt may be made before the deadline").toBe(1);

    // At the deadline: exactly one more.
    clock.advanceSeconds(1);
    await new Promise((r) => setTimeout(r, 0));
    expect(attempts(), "the retry fires at the deadline").toBe(2);

    // AND NEVER A THIRD, however long the clock runs on.
    clock.advanceSeconds(T_SECONDS * 10);
    await new Promise((r) => setTimeout(r, 0));
    expect(attempts(), "one retry means ONE — the ticker must not re-arm").toBe(2);
  });

  /**
   * SSA GREEN-4, the explicit one-shot budget: a retry that is ITSELF
   * age-refused must not arm a third attempt.
   *
   * Without the budget the refusal handler re-enters itself and "one retry"
   * becomes an unbounded chain with a fifteen-minute period — the polling loop
   * the design exists to avoid, reached by recursion instead of by a timer.
   */
  it("a retry that is refused again does NOT arm a third attempt", async () => {
    const { canister, attempts } = countingVetkeys(() => "age-refuse");
    const clock = fakeTime();
    const ctx = await mounted(harness({ vetkeys: canister, clock }));

    await ctx.scan();
    expect(attempts()).toBe(1);

    clock.advanceSeconds(T_SECONDS);
    await new Promise((r) => setTimeout(r, 0));
    expect(attempts(), "the one armed retry fires").toBe(2);

    // The retry was refused too. Nothing may be armed off the back of it.
    for (let i = 0; i < 5; i += 1) {
      clock.advanceSeconds(T_SECONDS);
      await new Promise((r) => setTimeout(r, 0));
    }
    expect(attempts(), "a repeated refusal REPLACES the deadline, it never adds one").toBe(2);
  });

  it("a route change cancels the pending retry — no late call", async () => {
    const { canister, attempts } = countingVetkeys((n) => (n === 1 ? "age-refuse" : "succeed"));
    const clock = fakeTime();
    const ctx = await mounted(harness({ vetkeys: canister, clock }));

    await ctx.scan();
    expect(attempts()).toBe(1);

    // The user navigates AWAY — to a genuinely different route, since the app
    // boots on "account" and a no-op navigation is not a route change. The wait
    // they were shown is gone, and a call made now would spend their meter
    // allowance for a message nobody is reading.
    ctx.navigate("staking");
    // `navigate` sets `location.hash`; the route change lands on the hashchange
    // event, so give the event loop a turn before asserting on it.
    await new Promise((r) => setTimeout(r, 0));
    clock.advanceSeconds(T_SECONDS * 3);
    await new Promise((r) => setTimeout(r, 0));
    expect(attempts(), "a cancelled retry must make NO late call").toBe(1);
  });

  /**
   * Status replacement and session teardown cancel through the SAME seam the
   * route change exercises — `stopPreparationRetry()`, called from `setStatus`
   * when the status actually changes and from `renderRoute` on a real route
   * change. This arm drives several transitions in a row and asserts the only
   * thing that matters after each: NO CANISTER CALL.
   *
   * IT DELIBERATELY DOES NOT ASSERT A TIMER COUNT. The brief rejects
   * timer-count assertions as evidence for this arm, and it is right to: a
   * cancelled-or-not ticker is a fact about the harness's own registry, while
   * the contract is about attempts that reach the canister. Counting tickers
   * here would be asserting the very proxy that was ruled insufficient.
   */
  it("no transition can produce a late canister call", async () => {
    const { canister, attempts } = countingVetkeys((n) => (n === 1 ? "age-refuse" : "succeed"));
    const clock = fakeTime();
    const ctx = await mounted(harness({ vetkeys: canister, clock }));

    await ctx.scan();
    expect(attempts()).toBe(1);

    for (const route of ["staking", "vesting", "account"] as const) {
      ctx.navigate(route);
      // `navigate` sets `location.hash`; jsdom delivers the hashchange on a
      // later turn, so give the event loop room before driving the clock.
      await new Promise((r) => setTimeout(r, 0));
      await new Promise((r) => setTimeout(r, 0));
      clock.advanceSeconds(T_SECONDS * 2);
      await new Promise((r) => setTimeout(r, 0));
      expect(attempts(), `no late call after navigating to ${route}`).toBe(1);
    }
  });

  it("the countdown ticker alone proves nothing — the count is at the canister", async () => {
    const { canister, attempts } = countingVetkeys((n) => (n === 1 ? "age-refuse" : "succeed"));
    const clock = fakeTime();
    const ctx = await mounted(harness({ vetkeys: canister, clock }));

    await ctx.scan();
    // Fire the ticker MANY times without moving the clock. A timer-count
    // assertion would see plenty of activity here; the causal count sees none,
    // which is exactly why the brief rejects the former as evidence.
    for (let i = 0; i < 50; i += 1) clock.tickOnly();
    await new Promise((r) => setTimeout(r, 0));
    expect(attempts(), "ticks are not attempts").toBe(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// VETKEYS-AGE-2MIN AD-7 / AC-3 (A1 notes v3 §A.12, §A.13 item 12, SSA C-3) —
// the SHIELD path. Counted at the canister, like every arm above.
// ═════════════════════════════════════════════════════════════════════════════

/** 1_000 STSH — the smallest fixed denomination (anti-drift law 1), in e8s. */
const SHIELD_AMOUNT = 100_000_000_000n;
const FUNDED = 5_000_000_000n;

function shieldHarness(opts: {
  vetkeys: VetkeysCanister;
  clock: ReturnType<typeof fakeTime>;
  balance: bigint;
}): { deps: AppDeps; feeParamsCalls: () => number; approveCalls: () => number } {
  let feeParamsCalls = 0;
  let approveCalls = 0;
  const base = harness({ vetkeys: opts.vetkeys, clock: opts.clock });
  const deps: AppDeps = {
    ...base,
    buildReadActors: async () =>
      ({
        token: { ...token, balanceOf: async () => opts.balance },
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
          approve: async () => {
            approveCalls += 1;
            throw new Error("approve reached (counted)");
          },
        },
      }) satisfies MutationActors,
    // The first thing the flow does AFTER key acquisition is the fee snapshot:
    // a call here is the proof that shield() went past the vetKey, not merely
    // "did not throw". It then aborts cleanly, before any approve.
    buildShieldedActors: async () =>
      ({
        pool: {
          getGovernanceFeeParams: async () => {
            feeParamsCalls += 1;
            throw new Error("fee params reached (counted)");
          },
        } as unknown as ShieldedActors["pool"],
        vetkeys: opts.vetkeys,
      }) satisfies ShieldedActors,
    // Start anonymous; `login()` supplies the session. No submission-delay wait.
    createAuth: async () => {
      const auth: WalletAuth = {
        restore: async () => null,
        login: async () => fakeSession(),
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    sleep: async () => undefined,
  };
  return { deps, feeParamsCalls: () => feeParamsCalls, approveCalls: () => approveCalls };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 25; i += 1) await new Promise((r) => setTimeout(r, 0));
}

describe("VETKEYS-AGE-2MIN AD-7 — shield under a live preparation deadline", () => {
  it("(a)+(b) ZERO calls and ZERO mutation before the deadline; the real flow runs at deadline+1s", async () => {
    // Funded: the login-time priming attempt is the refusal that stores the
    // deadline — the ONLY attempt before the deadline.
    const { canister, attempts } = countingVetkeys((n) => (n === 1 ? "age-refuse" : "succeed"));
    const clock = fakeTime();
    const h = shieldHarness({ vetkeys: canister, clock, balance: FUNDED });
    window.location.hash = "#/account";
    const node = document.createElement("div");
    document.body.append(node);
    const ctx = await mountApp(node, {}, h.deps);
    await ctx.login();
    await settle();
    expect(attempts(), "the priming attempt is the one refusal").toBe(1);
    await ctx.unlockNoteCache("pw");
    const entriesBefore = ctx.state.shieldEntries;
    expect(entriesBefore).toEqual([]);

    // (b) Before the deadline: a click makes NO canister call and mutates nothing.
    await ctx.shield(SHIELD_AMOUNT);
    clock.advanceSeconds(T_SECONDS - 1);
    await settle();
    await ctx.shield(SHIELD_AMOUNT);
    expect(attempts(), "no derive before the deadline").toBe(1);
    expect(h.feeParamsCalls(), "the flow never started").toBe(0);
    expect(h.approveCalls()).toBe(0);
    expect(ctx.state.pendingDelay).toBeNull();
    expect(ctx.state.shieldEntries, "no journal row was written").toEqual([]);
    expect(ctx.state.busy).toBe(false);
    expect(ctx.state.status?.kind).toBe("info");
    expect(ctx.state.status?.msg).toMatch(
      /^Your wallet is being prepared — first use is available in \d+ s$/,
    );

    // (a) Deadline + 1 s: the re-click runs the REAL flow — one more derive at
    // the canister, then on past the key to the fee snapshot.
    clock.advanceSeconds(2);
    await settle();
    await ctx.shield(SHIELD_AMOUNT);
    expect(attempts(), "exactly one derive at deadline+1s").toBe(2);
    expect(h.feeParamsCalls(), "shield() went past key acquisition").toBe(1);
    expect(ctx.state.status?.msg).not.toMatch(/being prepared/);
  });

  it("(c1) a REAL first shield attempt, age-refused, stores the deadline; a second login adds none", async () => {
    // Unfunded at login, so priming never fires and the shield click IS the
    // first attempt — the baseline C-3 requires before the negative claim.
    const { canister, attempts } = countingVetkeys(() => "age-refuse");
    const clock = fakeTime();
    const h = shieldHarness({ vetkeys: canister, clock, balance: 0n });
    window.location.hash = "#/account";
    const node = document.createElement("div");
    document.body.append(node);
    const ctx = await mountApp(node, {}, h.deps);
    await ctx.login();
    await settle();
    expect(attempts()).toBe(0);
    await ctx.unlockNoteCache("pw");

    await ctx.shield(SHIELD_AMOUNT);
    expect(attempts(), "the first shield click made one real attempt").toBe(1);
    expect(ctx.state.status?.kind, "an expected wait, not a failure").toBe("info");
    expect(ctx.state.status?.msg).toBe("Your wallet is being prepared — first use unlocks in 2 minutes.");

    await ctx.login(); // same principal again
    await settle();
    expect(attempts(), "a second login adds no attempt").toBe(1);

    await ctx.shield(SHIELD_AMOUNT); // re-click inside the stored deadline
    expect(attempts(), "the stored deadline holds the re-click").toBe(1);
    expect(ctx.state.status?.msg).toMatch(/first use is available in \d+ s$/);
    // No retry arm on the shield path: the clock alone never calls.
    clock.advanceSeconds(T_SECONDS * 3);
    await settle();
    expect(attempts()).toBe(1);
  });

  it("(c2) funded: the priming attempt is real (1), and a second login adds none", async () => {
    const { canister, attempts } = countingVetkeys(() => "age-refuse");
    const clock = fakeTime();
    const h = shieldHarness({ vetkeys: canister, clock, balance: FUNDED });
    window.location.hash = "#/account";
    const node = document.createElement("div");
    document.body.append(node);
    const ctx = await mountApp(node, {}, h.deps);
    await ctx.login();
    await settle();
    expect(attempts(), "a real first attempt").toBe(1);
    await ctx.login();
    await settle();
    expect(attempts(), "a second login for the same principal adds none").toBe(1);
  });
});
