// @vitest-environment jsdom
/**
 * L3b app-shell scan wiring tests — the ctx.scan() orchestration:
 *
 * - C-VK-3 sandwich (Critical, S-43): resolve the authoritative key name →
 *   assertCanisterConfig BEFORE fetch → fetch → assert AGAIN after → require
 *   both observed configs equal. Mismatch-before, drift-during, wrong key
 *   name — in every failure the worker is NEVER dispatched.
 * - Request fencing (Medium): progress/success/error/cleanup are fenced by
 *   the session epoch — a stale scan cannot touch a successor scan's UI or
 *   cache state after logout/login.
 *
 * The validated pipeline itself is covered in scanner.test.ts; here the
 * subject is the app-shell orchestration around it (fake scanNotes seam).
 */

import { describe, expect, it, vi } from "vitest";

const controlledSpend = vi.hoisted(() => ({
  impl: null as null | ((deps: any) => Promise<any>),
}));

vi.mock("../src/ui/spendFlow", async (loadOriginal) => {
  const original = await loadOriginal<typeof import("../src/ui/spendFlow")>();
  return {
    ...original,
    runSpendFlow: (deps: any, input: any) =>
      controlledSpend.impl === null ? original.runSpendFlow(deps, input) : controlledSpend.impl(deps),
  };
});

vi.mock("../src/session/session", async (loadOriginal) => ({
  ...(await loadOriginal<typeof import("../src/session/session")>()),
  createReadAgent: async () => ({}),
}));
import { Principal } from "@dfinity/principal";
import type { VetKey } from "@dfinity/vetkeys";

import { mountApp, type AppDeps, type ScanWorkerInput } from "../src/ui/app";
import { VetkeysCallError } from "../src/crypto/vetkeys";
import { raceSessionTask } from "../src/session/taskOwner";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import type { VetkeysCanister } from "../src/crypto/vetkeys";
import type { ScanOutcome } from "../src/crypto/scanner";
import type { AppContext } from "../src/ui/context";
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

function fakeVetkeys(configSeries: Array<[string, string]>): VetkeysCanister & { calls: number } {
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    async getConfig(): Promise<[string, string]> {
      const c = configSeries[Math.min(calls, configSeries.length - 1)];
      calls += 1;
      return c;
    },
    async getVetkeyVerificationKey(): Promise<Uint8Array> {
      throw new Error("not scripted (fetchKeys seam used)");
    },
    async getEncryptedVetkey(): Promise<{ encryptedKey: Uint8Array; remaining: number }> {
      throw new Error("not scripted (fetchKeys seam used)");
    },
    // W-VETKEYS Layer 1 — not exercised by this suite; each throws with its own
    // name so a test that unexpectedly reaches one fails saying which.
    async registerDevice(): Promise<never> {
      throw new Error("registerDevice not scripted by this test");
    },
    async revokeDevice(): Promise<never> {
      throw new Error("revokeDevice not scripted by this test");
    },
    async getWrappedSecret(): Promise<never> {
      throw new Error("getWrappedSecret not scripted by this test");
    },
    async listDevices(): Promise<never> {
      throw new Error("listDevices not scripted by this test");
    },
    async replaceEnvelope(): Promise<never> {
      throw new Error("replaceEnvelope not scripted by this test");
    },
  };
}

function harness(opts: {
  vetkeys: VetkeysCanister;
  scanNotes?: (input: ScanWorkerInput) => Promise<ScanOutcome>;
  pool?: ShieldedActors["pool"];
  /** D-1 clause 4: lets an arm script the reported key-recovery allowance. */
  fetchKeys?: AppDeps["fetchKeys"];
  /** V4 §5.4: the countdown's injected monotonic clock and ticker. */
  now?: AppDeps["now"];
  scheduleTick?: AppDeps["scheduleTick"];
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
        restore: async () => fakeSession(),
        login: async () => fakeSession(),
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    buildShieldedActors: async () =>
      ({ pool: opts.pool ?? ({} as ShieldedActors["pool"]), vetkeys: opts.vetkeys }) satisfies ShieldedActors,
    createCacheStore: async () => (await memoryHarness()).store,
    scanNotes: opts.scanNotes ?? (async () => EMPTY_OUTCOME),
    fetchKeys:
      opts.fetchKeys ??
      (async () => ({ vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 4 })),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.scheduleTick !== undefined ? { scheduleTick: opts.scheduleTick } : {}),
  };
  return { deps };
}

function mountContainer(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

async function mountedUnlocked(deps: AppDeps): Promise<AppContext> {
  const ctx = await mountApp(mountContainer(), {}, deps);
  await ctx.unlockNoteCache("pw");
  return ctx;
}

describe("ctx.scan — C-VK-3 sandwich (S-43, Critical)", () => {
  it("config mismatch BEFORE the fetch aborts; the worker is never dispatched", async () => {
    let dispatched = 0;
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "WRONG_KEY"]]),
      scanNotes: async () => {
        dispatched += 1;
        return EMPTY_OUTCOME;
      },
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/key-name mismatch/i);
    expect(dispatched).toBe(0);
  });

  it("config DRIFT during the fetch aborts; the worker is never dispatched", async () => {
    let dispatched = 0;
    const h = harness({
      // assert#1 ok, configBefore ok, assert#2 DRIFTED.
      vetkeys: fakeVetkeys([
        ["stsh.wallet.notes.v1", "key_1"],
        ["stsh.wallet.notes.v1", "key_1"],
        ["stsh.wallet.notes.v1", "evil_key"],
      ]),
      scanNotes: async () => {
        dispatched += 1;
        return EMPTY_OUTCOME;
      },
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/changed during key fetch/i);
    expect(dispatched).toBe(0);
  });

  it("wrong key name entirely (test key on production) aborts; never dispatched", async () => {
    let dispatched = 0;
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "test_key_1"]]),
      scanNotes: async () => {
        dispatched += 1;
        return EMPTY_OUTCOME;
      },
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(ctx.state.status?.msg).toMatch(/key-name mismatch/i);
    expect(dispatched).toBe(0);
  });

  it("unchanged configuration succeeds end to end (worker dispatched once)", async () => {
    let dispatched = 0;
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]),
      scanNotes: async () => {
        dispatched += 1;
        return EMPTY_OUTCOME;
      },
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(dispatched).toBe(1);
    expect(ctx.state.status?.kind).toBe("success");
  });
});

describe("ctx.scan — request fencing (epoch)", () => {
  it("a stale scan's progress/completion/cleanup cannot touch a successor scan's state", async () => {
    let aResolveDone: ((outcome: ScanOutcome) => void) | null = null;
    let aProgress: ((upTo: bigint, found: number) => void) | null = null;
    let call = 0;
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]),
      scanNotes: (input) => {
        call += 1;
        if (call === 1) {
          // Scan A: fully controllable.
          aProgress = input.onProgress ?? null;
          return new Promise<ScanOutcome>((resolve) => {
            aResolveDone = resolve;
          });
        }
        // Scan B (successor): resolves immediately.
        return Promise.resolve(EMPTY_OUTCOME);
      },
    });
    const ctx = await mountedUnlocked(h.deps);

    // Scan A starts (does not await — it stays in flight).
    const scanA = ctx.scan();
    await new Promise((r) => setTimeout(r, 0));
    expect(ctx.state.scanning).toBe(true);

    // Logout + login: the epoch advances; A is now stale.
    await ctx.logout();
    await ctx.login();
    await ctx.unlockNoteCache("pw");

    // Scan B starts and completes.
    await ctx.scan();
    expect(ctx.state.scanning).toBe(false);
    expect(ctx.state.status?.kind).toBe("success");
    const progressAfterB = ctx.state.scanProgress;

    // A emits progress late — must NOT touch the successor's UI state.
    (aProgress as unknown as (upTo: bigint, found: number) => void)(50n, 3);
    expect(ctx.state.scanProgress).toBe(progressAfterB);

    // A completes late — must NOT touch the successor's state or cache.
    (aResolveDone as unknown as (outcome: ScanOutcome) => void)({
      ...EMPTY_OUTCOME,
      notes: [
        {
          leafIndex: 0n,
          value: 1n,
          rho: new Uint8Array(32),
          rseed: new Uint8Array(32),
          recipientPk: new Uint8Array(32),
          state: "spendable",
        },
      ],
    });
    await scanA;
    expect(ctx.state.scanning).toBe(false); // B's completed state intact
    expect(ctx.state.notes).toEqual([]); // A never reached the cache
    expect(ctx.state.status?.kind).toBe("success"); // B's status intact
  });
});

describe("ctx unlock — fresh-device spend recovery (L3c, §10 gate)", () => {
  it("destroy cache → unlock fresh → the unlock auto-recovery imports pool-index spends as recovery-required", async () => {
    const record = {
      spendId: 42n,
      status: { kind: "in-flight" as const },
      nullifiers: [new Uint8Array(32).fill(0x2a)],
      outputCommitments: [new Uint8Array(32).fill(0x2b), new Uint8Array(32).fill(0x2c)],
      submitter: USER,
      createdAtNs: 1n,
    };
    const recoveryPool = {
      listMyActiveSpends: async () => ({ spends: [record], nextCursor: null }),
      getSpendStatus: async () => null,
    } as unknown as ShieldedActors["pool"];
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]),
      pool: recoveryPool,
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    // Fresh device: unlock creates an empty cache; the unlock's auto-recovery
    // imports the pool-index record (typed recovery-required — no fabricated
    // change, no unlocked input).
    await ctx.unlockNoteCache("pw");
    expect(ctx.state.status?.kind).toBe("info");
    // WALLET-CACHE-II-ONLY O-6: plain wording ("imported from the pool index"
    // -> "found"); the count it pins is unchanged.
    expect(ctx.state.status?.msg ?? "").toMatch(/Interrupted sends: 1 found/);
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// D-1 clause 4 / brief V1 §6 — the key-recovery quota is surfaced BY THE APP
// ─────────────────────────────────────────────────────────────────────────────
//
// The copy itself is unit-tested in w_vetkeys_ux_d1b; these arms prove the app
// actually SHOWS it, which is the part a user experiences.

describe("ctx.scan — key-recovery quota UX", () => {
  const green = () => fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]);

  it("warns when the allowance reaches the pinned threshold", async () => {
    const h = harness({
      vetkeys: green(),
      fetchKeys: async () => ({ vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 3 }),
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    // Its own surface, so the "Scan complete" status does not wipe it.
    expect(ctx.state.quotaNotice?.level).toBe("warning");
    expect(ctx.state.quotaNotice?.message).toMatch(/3 key recoveries left today/i);
    expect(ctx.state.status?.msg).toMatch(/Scan complete/i);
  });

  it("says nothing about the quota on a comfortable allowance", async () => {
    const h = harness({
      vetkeys: green(),
      fetchKeys: async () => ({ vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 5 }),
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(ctx.state.quotaNotice).toBeNull();
  });

  it("says nothing on the ZERO-DERIVE fast path — the canister reported no allowance", async () => {
    const h = harness({
      vetkeys: green(),
      fetchKeys: async () => ({
        vetKey: FAKE_VETKEY,
        verificationKey: {} as never,
        remaining: null,
      }),
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(ctx.state.quotaNotice).toBeNull();
  });

  it("VK-M1 — a fast-path scan does NOT clear the standing warning a real derive set", async () => {
    // The reviewer's transition arm: derive reports remaining=1, then an
    // ordinary scan rides the Layer-1 fast path (remaining=null, no derive).
    // The fast path carries NO quota verdict, so the "1 left" warning must
    // still be standing — before this fix, reportQuota(null) wiped it.
    const answers: (number | null)[] = [1, null];
    const h = harness({
      vetkeys: green(),
      fetchKeys: async () => ({
        vetKey: FAKE_VETKEY,
        verificationKey: {} as never,
        remaining: answers.shift() ?? null,
      }),
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan(); // real derive: sets the warning at 1
    expect(ctx.state.quotaNotice?.level).toBe("warning");
    expect(ctx.state.quotaNotice?.message).toMatch(/1 key recovery left/i);
    await ctx.scan(); // fast path: no verdict — the warning stands
    expect(ctx.state.quotaNotice?.level).toBe("warning");
    expect(ctx.state.quotaNotice?.message).toMatch(/1 key recovery left/i);
    // And a later REAL derive with a recovered allowance clears it.
    answers.push(5);
    await ctx.scan();
    expect(ctx.state.quotaNotice).toBeNull();
  });

  it("renders the WAIT when the quota is exhausted, instead of a generic failure", async () => {
    const h = harness({
      vetkeys: green(),
      fetchKeys: async () => {
        throw new VetkeysCallError("get_encrypted_vetkey", {
          DerivationQuotaExceeded: { retry_after_ns: 7_200_000_000_000n },
        });
      },
    });
    const ctx = await mountedUnlocked(h.deps);
    await ctx.scan();
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/try again in 2 hours/i);
    // NOT the generic path — two messages for one failure would be worse than
    // one good one.
    expect(ctx.state.status?.msg).not.toMatch(/Scan failed/i);
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// Brief V4 §9.3(14)/(16) — the fleet refusal renders as a WAITLIST, and counts
// down on an injected clock
// ─────────────────────────────────────────────────────────────────────────────

/** A controllable monotonic clock and ticker — no real wall-clock anywhere. */
function fakeClock() {
  let ms = 0;
  const ticks: Array<{ fn: () => void; everyMs: number; cancelled: boolean }> = [];
  return {
    now: () => ms,
    scheduleTick: (fn: () => void, everyMs: number) => {
      const entry = { fn, everyMs, cancelled: false };
      ticks.push(entry);
      return () => {
        entry.cancelled = true;
      };
    },
    /** Advance the clock and fire every live ticker once per interval. */
    advance(byMs: number): void {
      const steps = Math.floor(byMs / 1_000);
      for (let i = 0; i < steps; i += 1) {
        ms += 1_000;
        for (const t of ticks) if (!t.cancelled) t.fn();
      }
    },
    liveTickers: () => ticks.filter((t) => !t.cancelled).length,
  };
}

function statusTexts(container: HTMLElement): Array<{ cls: string; text: string }> {
  return Array.from(container.querySelectorAll(".status-msg")).map((n) => ({
    cls: n.className,
    text: n.textContent ?? "",
  }));
}

async function mountWith(deps: AppDeps): Promise<{ ctx: AppContext; container: HTMLElement }> {
  const container = mountContainer();
  const ctx = await mountApp(container, {}, deps);
  await ctx.unlockNoteCache("pw");
  return { ctx, container };
}

const greenVetkeys = () => fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]);

const refuseWith = (error: unknown): AppDeps["fetchKeys"] => async () => {
  throw new VetkeysCallError("get_encrypted_vetkey", error as never);
};

describe("§9.3(14) — the render path paints the fleet refusal NON-error", () => {
  it("renders status-msg INFO for fleet capacity, through reportQuotaRefusal → renderStatus", async () => {
    const clock = fakeClock();
    const h = harness({
      vetkeys: greenVetkeys(),
      fetchKeys: refuseWith({
        GlobalDerivationBudgetExceeded: { retry_after_ns: 1_800_000_000_000n },
      }),
      now: clock.now,
      scheduleTick: clock.scheduleTick,
    });
    const { ctx, container } = await mountWith(h.deps);
    await ctx.scan();

    // The REAL rendered DOM, not the notice object: reverting the level
    // mapping to a hardcoded "error" must fail here.
    const rendered = statusTexts(container);
    const refusal = rendered.find((n) => /capacity/i.test(n.text));
    expect(refusal, `no capacity message rendered: ${JSON.stringify(rendered)}`).toBeDefined();
    expect(refusal!.cls).toContain("info");
    expect(refusal!.cls).not.toContain("error");
    expect(ctx.state.status?.kind).toBe("info");
  });

  it("still renders the user's OWN exhausted allowance as an ERROR", async () => {
    const h = harness({
      vetkeys: greenVetkeys(),
      fetchKeys: refuseWith({ DerivationQuotaExceeded: { retry_after_ns: 60_000_000_000n } }),
    });
    const { ctx, container } = await mountWith(h.deps);
    await ctx.scan();
    expect(ctx.state.status?.kind).toBe("error");
    const rendered = statusTexts(container);
    expect(rendered.some((n) => n.cls.includes("error"))).toBe(true);
  });
});

describe("§9.3(16) — the waitlist countdown, on an injected clock", () => {
  const fleetRefusal = (ns: bigint) => ({ GlobalDerivationBudgetExceeded: { retry_after_ns: ns } });

  async function refusedApp(seconds: number) {
    const clock = fakeClock();
    const h = harness({
      vetkeys: greenVetkeys(),
      fetchKeys: refuseWith(fleetRefusal(BigInt(seconds) * 1_000_000_000n)),
      now: clock.now,
      scheduleTick: clock.scheduleTick,
    });
    const mounted = await mountWith(h.deps);
    await mounted.ctx.scan();
    return { ...mounted, clock };
  }

  it("DECREASES as the clock advances", async () => {
    const { ctx, clock } = await refusedApp(10);
    expect(ctx.state.capacityCountdownSeconds).toBe(10);
    clock.advance(3_000);
    expect(ctx.state.capacityCountdownSeconds).toBe(7);
    clock.advance(4_000);
    expect(ctx.state.capacityCountdownSeconds).toBe(3);
  });

  it("REACHES ZERO, never goes negative, and stops there", async () => {
    const { ctx, clock } = await refusedApp(5);
    clock.advance(5_000);
    // Reaching zero clears the countdown — zero is an exit, not a resting
    // state, so nothing keeps ticking against a deadline already passed.
    expect(ctx.state.capacityCountdownSeconds).toBeNull();
    expect(clock.liveTickers()).toBe(0);

    // Advancing far past it cannot produce a negative value, because the timer
    // is gone.
    clock.advance(60_000);
    expect(ctx.state.capacityCountdownSeconds).toBeNull();
  });

  it("is CANCELLED when another status replaces the refusal", async () => {
    // Refuse ONCE, then succeed: the second scan's "Scan complete" status is a
    // genuine replacement, which must end the countdown the refusal started.
    const clock = fakeClock();
    let attempt = 0;
    const h = harness({
      vetkeys: greenVetkeys(),
      fetchKeys: async () => {
        attempt += 1;
        if (attempt === 1) {
          throw new VetkeysCallError("get_encrypted_vetkey", {
            GlobalDerivationBudgetExceeded: { retry_after_ns: 600_000_000_000n },
          } as never);
        }
        return { vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 4 };
      },
      now: clock.now,
      scheduleTick: clock.scheduleTick,
    });
    const { ctx } = await mountWith(h.deps);

    await ctx.scan();
    expect(ctx.state.capacityCountdownSeconds).toBe(600);
    expect(clock.liveTickers()).toBe(1);

    await ctx.scan(); // succeeds → replaces the status
    expect(ctx.state.status?.msg).toMatch(/Scan complete/i);
    expect(ctx.state.capacityCountdownSeconds).toBeNull();
    expect(clock.liveTickers()).toBe(0);
  });

  it("is CANCELLED on a route change", async () => {
    const { ctx, clock } = await refusedApp(600);
    expect(clock.liveTickers()).toBe(1);
    ctx.navigate("shield");
    // `navigate` sets `window.location.hash`; jsdom delivers `hashchange` on a
    // later task, so the route change (and its cancellation) lands after a
    // macrotask — awaited here rather than asserted optimistically.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(clock.liveTickers()).toBe(0);
    expect(ctx.state.capacityCountdownSeconds).toBeNull();
  });

  it("asserts against NO real elapsed wall-clock time", async () => {
    // The clock is fully injected: a countdown arm that used the real clock
    // would be flaky under load, which is exactly why `sleep` was injected
    // before it (app.ts:149-153).
    const { ctx, clock } = await refusedApp(2);
    const before = Date.now();
    clock.advance(2_000);
    expect(Date.now() - before).toBeLessThan(1_000);
    expect(ctx.state.capacityCountdownSeconds).toBeNull();
  });
});

describe("L10 explicit local-work cancellation", () => {
  it("aborts the active generation, keeps the principal, and a new scan works immediately", async () => {
    let firstSignal: AbortSignal | undefined;
    let calls = 0;
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]),
      scanNotes: (input) => {
        calls += 1;
        if (calls === 1) {
          firstSignal = input.signal;
          return new Promise<ScanOutcome>(() => undefined);
        }
        return Promise.resolve(EMPTY_OUTCOME);
      },
    });
    const ctx = await mountedUnlocked(h.deps);
    const first = ctx.scan();
    await vi.waitFor(() => expect(firstSignal).toBeDefined());

    ctx.cancelSessionTasks!();
    await first;
    expect(firstSignal!.aborted).toBe(true);
    expect(ctx.state.principal?.toText()).toBe(USER.toText());
    expect(ctx.state.scanning).toBe(false);

    await ctx.scan();
    expect(calls).toBe(2);
    expect(ctx.state.status?.kind).toBe("success");
  });

  it("renders a reachable cancel control while a scan is active", async () => {
    const h = harness({
      vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]),
      scanNotes: async () => await new Promise<ScanOutcome>(() => undefined),
    });
    const container = mountContainer();
    const ctx = await mountApp(container, {}, h.deps);
    await ctx.unlockNoteCache("pw");
    const pending = ctx.scan();
    ctx.navigate("scan");
    await vi.waitFor(() => {
      expect(Array.from(container.querySelectorAll("button")).some((b) => b.textContent === "Cancel scan")).toBe(true);
    });
    const button = Array.from(container.querySelectorAll("button")).find((b) => b.textContent === "Cancel scan")!;
    button.click();
    await pending;
    expect(ctx.state.principal).not.toBeNull();
  });
});


describe("L10 app-context preparation and teardown races", () => {
  it("settles a scan held before worker creation and a new scan works", async () => {
    let entered = false;
    let release!: (value: [string, string]) => void;
    const held = new Promise<[string, string]>((resolve) => {
      release = resolve;
    });
    const vetkeys = fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]);
    vetkeys.getConfig = async () => {
      entered = true;
      return held;
    };
    const h = harness({ vetkeys });
    const ctx = await mountedUnlocked(h.deps);
    let settled = false;
    const pending = ctx.scan().then(() => {
      settled = true;
    });
    await vi.waitFor(() => expect(entered).toBe(true));

    ctx.cancelSessionTasks!();
    await vi.waitFor(() => expect(settled).toBe(true));
    expect(ctx.state.scanning).toBe(false);
    expect(ctx.state.principal?.toText()).toBe(USER.toText());

    release(["stsh.wallet.notes.v1", "key_1"]);
    await pending;
    await ctx.scan();
    expect(ctx.state.status?.kind).toBe("success");
  });

  it.each(["binding", "read-agent"] as const)(
    "settles ctx.spend while outer %s preparation is held without entering the flow or minting a lease",
    async (phase) => {
      let entered = false;
      let flowCalls = 0;
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      controlledSpend.impl = async () => {
        flowCalls += 1;
        return { spendId: "1", changeValue: 0n, publicAmount: 0n, fee: 0n };
      };
      try {
        const h = harness({ vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]) });
        if (phase === "binding") {
          h.deps.assertDeploymentBinding = async () => {
            entered = true;
            await gate;
            return { hash: new Uint8Array(32), wiring: {} as never };
          };
        } else {
          h.deps.createReadAgent = async () => {
            entered = true;
            await gate;
            return {} as never;
          };
        }
        const ctx = await mountApp(mountContainer(), {
          VITE_TOKEN_CANISTER_ID: USER.toText(),
          VITE_MERKLE_CANISTER_ID: USER.toText(),
          VITE_NULLIFIER_CANISTER_ID: USER.toText(),
        }, h.deps);
        await ctx.unlockNoteCache("pw");
        let settled = false;
        const pending = ctx.spend({ inputLeafIndex: 0n }).then(() => {
          settled = true;
        });
        await vi.waitFor(() => expect(entered).toBe(true));

        ctx.cancelSessionTasks!();
        await vi.waitFor(() => expect(settled).toBe(true), { timeout: 200 });
        expect(ctx.state.busy).toBe(false);
        expect(flowCalls).toBe(0);
        expect(ctx.state.principal?.toText()).toBe(USER.toText());

        release();
        await pending;
        await Promise.resolve();
        expect(flowCalls).toBe(0);
      } finally {
        controlledSpend.impl = null;
        release!();
      }
    },
  );

  it("cancels a held pre-marker spend before journal work while keeping the session authenticated", async () => {
    let entered = false;
    let journalStarts = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    controlledSpend.impl = async (deps) => {
      entered = true;
      await raceSessionTask(gate, deps.signal);
      journalStarts += 1;
      return { spendId: "1", changeValue: 0n, publicAmount: 0n, fee: 0n };
    };
    try {
      const h = harness({ vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]) });
      const ctx = await mountApp(mountContainer(), {
        VITE_TOKEN_CANISTER_ID: USER.toText(),
        VITE_MERKLE_CANISTER_ID: USER.toText(),
        VITE_NULLIFIER_CANISTER_ID: USER.toText(),
      }, h.deps);
      await ctx.unlockNoteCache("pw");
      const pending = ctx.spend({ inputLeafIndex: 0n });
      await vi.waitFor(() => expect(entered).toBe(true));

      ctx.cancelSessionTasks!();
      await pending;
      expect(journalStarts).toBe(0);
      expect(ctx.state.busy).toBe(false);
      expect(ctx.state.principal?.toText()).toBe(USER.toText());

      release();
      await Promise.resolve();
      expect(journalStarts).toBe(0);
    } finally {
      controlledSpend.impl = null;
      release!();
    }
  });

  it("logout closes a committed lease, clears old busy state, and permits the next login", async () => {
    let entered = false;
    let lease: any;
    let release!: () => void;
    controlledSpend.impl = async (deps) => {
      lease = deps.lease;
      deps.onDispatchBoundary();
      entered = true;
      await new Promise<void>((_resolve, reject) => {
        release = () => reject(new Error("held committed flow ended"));
      });
    };
    try {
      const h = harness({ vetkeys: fakeVetkeys([["stsh.wallet.notes.v1", "key_1"]]) });
      const ctx = await mountApp(mountContainer(), {
        VITE_TOKEN_CANISTER_ID: USER.toText(),
        VITE_MERKLE_CANISTER_ID: USER.toText(),
        VITE_NULLIFIER_CANISTER_ID: USER.toText(),
      }, h.deps);
      await ctx.unlockNoteCache("pw");
      const pending = ctx.spend({ inputLeafIndex: 0n });
      await vi.waitFor(() => expect(entered).toBe(true));
      expect(ctx.state.busy).toBe(true);

      ctx.cancelSessionTasks!();
      expect(ctx.state.busy).toBe(true);
      await ctx.logout();
      expect(ctx.state.busy).toBe(false);
      expect(() => lease.draw("privateSpend")).toThrow();

      release();
      await pending;
      expect(ctx.state.busy).toBe(false);
      await ctx.login();
      expect(ctx.state.principal?.toText()).toBe(USER.toText());
    } finally {
      controlledSpend.impl = null;
      release!();
    }
  });
});
