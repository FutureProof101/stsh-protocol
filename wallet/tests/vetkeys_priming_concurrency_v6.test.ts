// @vitest-environment jsdom
/**
 * VETKEYS-AGE-2MIN — the login-time priming attempt (A1 notes v3 §A.10/§A.13,
 * SSA C-1/C-2; Blocker-3 ruling 2026-09-23: login/restore observe the balance
 * NON-BLOCKINGLY, then prime).
 *
 * Every count here is taken AT THE CANISTER BOUNDARY (`getEncryptedVetkey`,
 * `listDevices`, `registerDevice`) — the rule `vetkeys_age_retry_v5` set: a
 * timer or a helper call proves nothing about what reached the canister.
 *
 * THE TWO SEAMS, AND WHY THEY ARE PASS-THROUGHS:
 *  - `fetchUserVetKey` is replaced by a function that makes the SAME two
 *    canister calls in the same order (verification key, then the derive) and
 *    returns a fixture vetKey. Real BLS decryption would need a real vetKD
 *    reply; the dispatch — the thing under test — is untouched.
 *  - `deviceStore` is replaced by an in-memory counter so "this browser has no
 *    device yet", a save failure, and the number of local lookups are all
 *    observable. jsdom has no IndexedDB.
 *
 * RESIDUAL NOT TESTED HERE BECAUSE IT CANNOT BE CLOSED IN ONE TAB: two TABS are
 * two module instances with two latches, so both can observe `listDevices() ===
 * []` and both can dispatch (A.10.3 item 1). That is disclosed in the packet.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

const seams = vi.hoisted(() => ({
  stored: null as unknown,
  loads: 0,
  saves: 0,
  saveFails: false,
}));

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

vi.mock("../src/storage/deviceStore", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/storage/deviceStore")>();
  return {
    ...real,
    loadDeviceIdentity: async () => {
      seams.loads += 1;
      return seams.stored;
    },
    saveDeviceIdentity: async () => {
      seams.saves += 1;
      if (seams.saveFails) throw new Error("device store write failed (scripted)");
    },
  };
});

import { mountApp, type AppDeps } from "../src/ui/app";
import { VetkeysCallError, WALLET_ELIGIBILITY_MIN_BALANCE_E8S } from "../src/crypto/vetkeys";
import type { VetkeysCanister } from "../src/crypto/vetkeys";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { AppContext } from "../src/ui/context";
import type { VetkeysError } from "../../src/declarations/vetkeys/vetkeys.did";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const P1 = Principal.fromUint8Array(new Uint8Array(10).fill(0x31));
const P2 = Principal.fromUint8Array(new Uint8Array(10).fill(0x32));
/**
 * WALLET-CACHE-II-ONLY (O-1, Addendum 3): every session commit now runs ONE
 * derive-free sign-in open, which reads this browser's device identity once
 * (`loadDeviceIdentity`) before anything else. `seams.loads` counts every local
 * lookup, so each session adds exactly this many to the priming counts below.
 * The priming claims themselves are unchanged and still pinned by `lists` and
 * `derives`; only the local-lookup tallies carry this term.
 */
const SIGN_IN_OPEN_LOOKUPS = 1;
/** Funded: comfortably above the §D floor. Literal, not derived from the constant. */
const FUNDED = 5_000_000_000n;
/** T = 2 minutes (559b411e…), in the canister's unit. */
const T_NS = 120_000_000_000n;
const T_SECONDS = 120;

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Let every chained microtask and zero-delay timer run. */
async function flush(): Promise<void> {
  for (let i = 0; i < 25; i += 1) await new Promise((r) => setTimeout(r, 0));
}

const session = (p: Principal): AuthSession => ({
  identity: { getPrincipal: () => p } as unknown as AuthSession["identity"],
  principal: p,
});

type DeriveStep = "age-refuse" | "succeed" | Promise<{ encryptedKey: Uint8Array; remaining: number }>;

/** A canister that counts every call that reaches it. */
function countingVetkeys(opts: {
  derive?: (attempt: number) => DeriveStep;
  listDevices?: (call: number) => Promise<unknown[]>;
}) {
  const counts = { derives: 0, lists: 0, registers: 0 };
  const canister = {
    async getConfig() {
      return ["stsh.wallet.notes.v1", "key_1"];
    },
    async getVetkeyVerificationKey(): Promise<Uint8Array> {
      return new Uint8Array(96).fill(3);
    },
    async getEncryptedVetkey(): Promise<{ encryptedKey: Uint8Array; remaining: number }> {
      counts.derives += 1;
      const step = (opts.derive ?? (() => "age-refuse"))(counts.derives);
      if (step === "age-refuse") {
        throw new VetkeysCallError("get_encrypted_vetkey", {
          EligibilityAgeNotMet: { retry_after_ns: T_NS },
        } as VetkeysError);
      }
      if (step === "succeed") return { encryptedKey: new Uint8Array(192).fill(1), remaining: 4 };
      return step;
    },
    async registerDevice(): Promise<void> {
      counts.registers += 1;
    },
    async listDevices() {
      counts.lists += 1;
      return opts.listDevices ? opts.listDevices(counts.lists) : [];
    },
    async revokeDevice(): Promise<never> {
      throw new Error("revokeDevice not scripted");
    },
    async getWrappedSecret(): Promise<never> {
      throw new Error("getWrappedSecret not scripted");
    },
    async replaceEnvelope(): Promise<never> {
      throw new Error("replaceEnvelope not scripted");
    },
  } as unknown as VetkeysCanister;
  return { canister, counts };
}

/** A controllable monotonic clock and scheduler (the `vetkeys_age_retry_v5` shape). */
function fakeTime() {
  let nowMs = 1_000_000;
  const ticks: Array<{ fn: () => void; cancelled: boolean }> = [];
  return {
    now: () => nowMs,
    advanceSeconds(seconds: number): void {
      nowMs += seconds * 1_000;
      for (const t of ticks) if (!t.cancelled) t.fn();
    },
    tickOnly(): void {
      for (const t of ticks) if (!t.cancelled) t.fn();
    },
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
  /** The session `restore()` returns; null = start anonymous. */
  restored: Principal | null;
  /** Sessions `login()` returns, in order. */
  logins?: Principal[];
  balanceOf: (owner: Principal) => Promise<bigint>;
  readActorsFail?: boolean;
}): { deps: AppDeps; balanceCalls: Principal[] } {
  const balanceCalls: Principal[] = [];
  const logins = [...(opts.logins ?? [])];
  const deps: AppDeps = {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () => {
      if (opts.readActorsFail === true) throw new Error("Canister ID is required (scripted)");
      return {
        token: {
          balanceOf: (owner: Principal) => {
            balanceCalls.push(owner);
            return opts.balanceOf(owner);
          },
          metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
          fee: async () => 0n,
        },
        staking: null,
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      } satisfies ReadActors;
    },
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
        restore: async () => (opts.restored === null ? null : session(opts.restored)),
        login: async () => {
          const next = logins.shift();
          if (next === undefined) throw new Error("login not scripted");
          return session(next);
        },
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    buildShieldedActors: async () =>
      ({ pool: {} as ShieldedActors["pool"], vetkeys: opts.vetkeys }) satisfies ShieldedActors,
    createCacheStore: async () => (await memoryHarness()).store,
    now: opts.clock.now,
    scheduleTick: opts.clock.scheduleTick,
  };
  return { deps, balanceCalls };
}

async function mounted(deps: AppDeps): Promise<AppContext> {
  window.location.hash = "#/account";
  const node = document.createElement("div");
  document.body.append(node);
  return mountApp(node, {}, deps);
}

beforeEach(() => {
  seams.stored = null;
  seams.loads = 0;
  seams.saves = 0;
  seams.saveFails = false;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("VETKEYS-AGE-2MIN priming — C-1: the balance is observed, then priming fires", () => {
  it("sanity: the funded fixture is above the wallet floor", () => {
    expect(FUNDED >= WALLET_ELIGIBILITY_MIN_BALANCE_E8S).toBe(true);
  });

  it("(1) fresh funded LOGIN: balance starts null, is read once, and ONE derive is dispatched", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: null, logins: [P1], balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    expect(ctx.state.principal).toBeNull();
    expect(ctx.state.balance).toBeNull();
    expect(counts.derives).toBe(0);

    await ctx.login();
    await flush();

    // No manual balance view anywhere in this arm: the login itself observed it.
    expect(h.balanceCalls.map((p) => p.toText())).toEqual([P1.toText()]);
    expect(ctx.state.balance).toBe(FUNDED);
    expect(counts.derives, "exactly one priming dispatch").toBe(1);
    // The expected age refusal is NOT a failure: no error surfaces.
    expect(ctx.state.status?.kind).not.toBe("error");
  });

  it("(2) session RESTORE: same — balance read by the restore itself, ONE derive", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    await flush();
    expect(ctx.state.principal?.toText()).toBe(P1.toText());
    expect(h.balanceCalls).toHaveLength(1);
    expect(ctx.state.balance).toBe(FUNDED);
    expect(counts.derives).toBe(1);
    expect(ctx.state.status?.kind).not.toBe("error");
  });

  it("(3) unfunded → funded: no dispatch while unfunded, exactly ONE after the refresh that sees funding", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    let balance = 0n;
    const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => balance });
    const ctx = await mounted(h.deps);
    await flush();
    expect(ctx.state.balance).toBe(0n);
    expect(counts.derives, "an unfunded principal is never primed").toBe(0);

    balance = FUNDED;
    await ctx.refreshBalance();
    await flush();
    expect(counts.derives, "the refresh that first observes funding primes once").toBe(1);

    await ctx.refreshBalance();
    await flush();
    expect(counts.derives, "and never again this mount").toBe(1);
  });

  it("(4a) balance READ FAILURE: balance stays null and no attempt is consumed", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({
      vetkeys: canister,
      clock,
      restored: P1,
      balanceOf: async () => {
        throw new Error("ledger unreachable");
      },
    });
    const ctx = await mounted(h.deps);
    await flush();
    expect(h.balanceCalls).toHaveLength(1);
    expect(ctx.state.balance).toBeNull();
    expect(counts.derives).toBe(0);
    expect(counts.lists).toBe(0);
    expect(seams.loads, "not even a local device lookup by priming").toBe(0 + SIGN_IN_OPEN_LOOKUPS);
  });

  it("(4b) read actors UNAVAILABLE: balance stays null and no attempt is consumed", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => FUNDED, readActorsFail: true });
    const ctx = await mounted(h.deps);
    await flush();
    expect(ctx.readActors).toBeNull();
    expect(ctx.state.balance).toBeNull();
    expect(counts.derives).toBe(0);
    expect(seams.loads).toBe(0 + SIGN_IN_OPEN_LOOKUPS);
  });

  it("(5) identity switch WITHOUT logout: P1's balance never opens P2's gate", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const p2Balance = deferred<bigint>();
    const h = harness({
      vetkeys: canister,
      clock,
      restored: null,
      logins: [P1, P2],
      balanceOf: (owner) => (owner.toText() === P1.toText() ? Promise.resolve(FUNDED) : p2Balance.promise),
    });
    const ctx = await mounted(h.deps);
    await ctx.login();
    await flush();
    expect(counts.derives, "P1 primed once").toBe(1);
    expect(ctx.state.balance).toBe(FUNDED);

    await ctx.login(); // no logout in between
    // The second commit reset the balance, and P2's read is still pending.
    expect(ctx.state.principal?.toText()).toBe(P2.toText());
    expect(ctx.state.balance, "the session commit nulls the previous principal's balance").toBeNull();
    await flush();
    expect(counts.derives, "no dispatch for P2 on P1's stale funded balance").toBe(1);

    p2Balance.resolve(0n); // P2 is unfunded
    await flush();
    expect(ctx.state.balance).toBe(0n);
    expect(counts.derives, "one dispatch total — P1's").toBe(1);
  });
});

describe("VETKEYS-AGE-2MIN priming — C-2: one dispatch per principal per mount", () => {
  it("(6) overlapping login + manual refresh, replies out of order: AT MOST one dispatch", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const replies = [deferred<bigint>(), deferred<bigint>()];
    let call = 0;
    const h = harness({
      vetkeys: canister,
      clock,
      restored: null,
      logins: [P1],
      balanceOf: () => replies[call++]!.promise,
    });
    const ctx = await mounted(h.deps);
    const login = ctx.login();
    await login; // login no longer waits for the balance (Blocker 3)
    const manual = ctx.refreshBalance();
    expect(h.balanceCalls).toHaveLength(2);

    replies[1]!.resolve(FUNDED); // the manual refresh answers FIRST
    await manual;
    replies[0]!.resolve(FUNDED);
    await flush();
    expect(ctx.state.principal?.toText()).toBe(P1.toText());
    expect(counts.derives, "the latch admits exactly one").toBe(1);
  });

  it("(7) renders, ticks and the passing deadline never produce a second dispatch", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: P1, logins: [P1], balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    await flush();
    expect(counts.derives, "the one age-refused priming attempt").toBe(1);

    for (const route of ["staking", "vesting", "account", "shield"] as const) {
      ctx.navigate(route);
      await flush();
    }
    for (let i = 0; i < 50; i += 1) clock.tickOnly();
    await flush();
    expect(counts.derives).toBe(1);

    // PAST the stored deadline, via explicit triggers — still no second
    // dispatch: an age refusal counts as the attempt (retry is shield's job).
    clock.advanceSeconds(T_SECONDS + 1);
    await ctx.refreshBalance();
    await flush();
    await ctx.login();
    await flush();
    expect(counts.derives, "primingAttempted holds for the whole mount").toBe(1);
  });

  it("(8) a second trigger while listDevices() is pending returns at the latch — no second lookup", async () => {
    const list = deferred<unknown[]>();
    const { canister, counts } = countingVetkeys({ listDevices: () => list.promise });
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: null, logins: [P1], balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    await ctx.login();
    await flush();
    expect(counts.lists, "the first attempt is parked on listDevices()").toBe(1);
    expect(seams.loads).toBe(1 + SIGN_IN_OPEN_LOOKUPS);

    await ctx.refreshBalance(); // a second funded observation, same principal
    await flush();
    expect(seams.loads, "the second invocation never reached loadDeviceIdentity").toBe(1 + SIGN_IN_OPEN_LOOKUPS);
    expect(counts.lists, "…nor listDevices").toBe(1);

    list.resolve([]);
    await flush();
    expect(counts.derives, "exactly one full dispatch").toBe(1);
  });

  it("(8b) identity switch while P1's attempt is parked: the latch holds P2 off, P1 aborts, P2 primes later", async () => {
    const list = deferred<unknown[]>();
    const { canister, counts } = countingVetkeys({
      listDevices: (call) => (call === 1 ? list.promise : Promise.resolve([])),
    });
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: null, logins: [P1, P2], balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    await ctx.login();
    await flush();
    expect(counts.lists, "P1's attempt is parked on listDevices()").toBe(1);
    expect(seams.loads).toBe(1 + SIGN_IN_OPEN_LOOKUPS);

    await ctx.login(); // P2, no logout
    await flush();
    expect(ctx.state.principal?.toText()).toBe(P2.toText());
    expect(seams.loads, "P2 returned at the in-flight latch (P1's dispatch is still running)").toBe(
      1 + 2 * SIGN_IN_OPEN_LOOKUPS,
    );

    list.resolve([]); // P1's observation lands AFTER the switch
    await flush();
    expect(counts.derives, "P1's stale attempt aborts at the post-await re-check — no derive").toBe(0);

    await ctx.refreshBalance(); // latch released; P2 was never marked attempted
    await flush();
    // 3 = P1's gate lookup + P2's gate lookup + the Layer-1 provider's own
    // `loadDevice` inside P2's dispatch — plus one sign-in open per session.
    expect(seams.loads).toBe(3 + 2 * SIGN_IN_OPEN_LOOKUPS);
    expect(counts.derives, "P2 primes exactly once, on its own observation").toBe(1);
  });

  it("(9) a derive that resolves AFTER logout commits nothing to the UI", async () => {
    const derive = deferred<{ encryptedKey: Uint8Array; remaining: number }>();
    const { canister, counts } = countingVetkeys({ derive: () => derive.promise });
    const clock = fakeTime();
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const unhandled: unknown[] = [];
    const onUnhandled = (e: PromiseRejectionEvent | unknown) => unhandled.push(e);
    process.on("unhandledRejection", onUnhandled);
    try {
      const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => FUNDED });
      const ctx = await mounted(h.deps);
      await flush();
      expect(counts.derives, "the derive is in flight").toBe(1);

      await ctx.logout();
      expect(ctx.state.principal).toBeNull();
      expect(ctx.shieldedActors).toBeNull();

      // `remaining: 1` WOULD raise a standing quota warning if it committed.
      derive.resolve({ encryptedKey: new Uint8Array(192).fill(1), remaining: 1 });
      await flush();
      expect(ctx.state.quotaNotice, "no stale quota report").toBeNull();
      expect(ctx.state.principal).toBeNull();
      expect(ctx.shieldedActors, "logout's teardown is not clobbered back").toBeNull();
      // Disclosed residual, OBSERVED rather than asserted away: the ceremony
      // (register + local save) is not recallable once dispatched — only the
      // UI commit is gated. Wait for it to finish so it cannot bleed into the
      // next arm's counters.
      await vi.waitFor(
        () => {
          if (seams.saves < 1) throw new Error("residual ceremony still running");
        },
        { timeout: 20_000, interval: 50 },
      );
      await flush();
      expect(counts.registers).toBe(1);
      expect(ctx.state.quotaNotice, "still no stale quota report").toBeNull();
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      errors.mockRestore();
    }
  }, 30_000);

  it("(10) enrolment SAVE failure after a successful derive: swallowed, attempted stays marked, no retry", async () => {
    seams.saveFails = true;
    const { canister, counts } = countingVetkeys({ derive: () => "succeed" });
    const clock = fakeTime();
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const h = harness({ vetkeys: canister, clock, restored: P1, logins: [P1], balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    // Enrolment generates a real RSA-3072 device key pair — wait for the
    // ceremony to reach the (failing) save rather than for a fixed turn count.
    await vi.waitFor(
      () => {
        if (seams.saves < 1) throw new Error(`save not reached (errors: ${JSON.stringify(errors.mock.calls)})`);
      },
      { timeout: 20_000, interval: 50 },
    );
    await flush();
    expect(counts.derives).toBe(1);
    expect(counts.registers, "the derive enrolled the device canister-side").toBe(1);
    expect(seams.saves, "and the local save was attempted — and failed").toBe(1);
    expect(errors.mock.calls.some((c) => c[0] === "primeFirstDeriveSighting:")).toBe(true);
    expect(ctx.state.status?.kind, "a background attempt never toasts").not.toBe("error");

    await ctx.refreshBalance();
    await flush();
    await ctx.login();
    await flush();
    expect(counts.derives, "no retry this mount, even after a failure").toBe(1);
    errors.mockRestore();
  }, 30_000);

  it("(11) deadline EXPIRY alone never calls the network — priming owns no timer", async () => {
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => FUNDED });
    const ctx = await mounted(h.deps);
    await flush();
    expect(counts.derives).toBe(1);
    const balanceReads = h.balanceCalls.length;

    clock.advanceSeconds(T_SECONDS * 5);
    for (let i = 0; i < 20; i += 1) clock.tickOnly();
    await flush();
    expect(counts.derives, "no dispatch without an explicit trigger").toBe(1);
    expect(counts.lists).toBe(1);
    expect(h.balanceCalls.length, "and no balance polling either").toBe(balanceReads);
    expect(ctx.state.principal?.toText()).toBe(P1.toText());
  });

  it("an already-enrolled browser is never primed (the local device short-circuits)", async () => {
    seams.stored = { deviceId: "x" };
    const { canister, counts } = countingVetkeys({});
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => FUNDED });
    await mounted(h.deps);
    await flush();
    expect(seams.loads).toBe(1 + SIGN_IN_OPEN_LOOKUPS);
    expect(counts.lists).toBe(0);
    expect(counts.derives).toBe(0);
  });

  it("a principal with devices elsewhere is never primed (listDevices non-empty)", async () => {
    const { canister, counts } = countingVetkeys({ listDevices: async () => [{ device_id: "other" }] });
    const clock = fakeTime();
    const h = harness({ vetkeys: canister, clock, restored: P1, balanceOf: async () => FUNDED });
    await mounted(h.deps);
    await flush();
    expect(counts.lists).toBe(1);
    expect(counts.derives).toBe(0);
  });
});
