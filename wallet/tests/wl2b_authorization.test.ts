/**
 * WL-2b — no private event may trigger a public action.
 *
 * Three things are proved here, at three different levels, because they are
 * three different claims:
 *
 *   §4a  the operation note cap, enforced at `decomposeAmount` and rejecting
 *        before any wire call;
 *   §4.2 the lease and its single-use per-call tokens — non-ambient, bound to
 *        one operation, expiring on BOTH draw and consume;
 *   §4.4 the two defences, each with its OWN causal probe: P1 drives the
 *        composed post-unlock path and asserts the trigger defers; P2 drives
 *        the WRAPPER directly and asserts the guard refuses.
 *
 * P2 is deliberately NOT driven through the moved trigger. Defence-in-depth
 * making one defence unobservable through the composed path is the expected
 * geometry, not a defect — each layer gets its own probe, and the alternative
 * (restoring auto-fire so the guard becomes observable) would weaken production
 * to make a test work.
 *
 * Every assertion is a RAW candid invocation count. "It returned an error" is
 * consistent with the call having been made and having failed, which is the
 * outcome this item exists to rule out.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import type { VetKey } from "@dfinity/vetkeys";

import { mountApp, type AppDeps } from "../src/ui/app";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import {
  ActionNotAuthorizedError,
  LeaseExpiredError,
  LEASE_DEADLINE_MS,
  MAX_OPERATION_CALLS,
  PER_CALL_BUDGET_MS,
  createAuthorizationAuthority,
  walletAuthorizationAuthority,
} from "../src/actors/authorization";
import { decomposeAmount, MAX_NOTES_PER_OPERATION } from "../src/crypto/notes";
import { planShield } from "../src/ui/format";
import { wrapPoolActor } from "../src/actors/pool";
import { wrapTokenMutationActor } from "../src/actors/token";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import type { VetkeysCanister } from "../src/crypto/vetkeys";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x21));
const SPEND_ID = 42n;
const STSH = 100_000_000n;
const asService = <T>(mock: Record<string, unknown>): T => mock as unknown as T;

// ── §4a — the ruled operation note cap ───────────────────────────────────────

describe("WL-2b §4a — MAX_NOTES_PER_OPERATION", () => {
  it("is the ruled value, and bounds the operation's wire calls at 1 + cap", () => {
    expect(MAX_NOTES_PER_OPERATION).toBe(16);
    expect(MAX_OPERATION_CALLS).toBe(1 + MAX_NOTES_PER_OPERATION);
  });

  it("accepts exactly the cap and REJECTS one note more", () => {
    expect(decomposeAmount(97_000n * STSH)).toHaveLength(16);
    expect(() => decomposeAmount(98_000n * STSH)).toThrow(/17 fixed-denomination notes/);
  });

  it("is a cap on COUNT, not on amount — and the message must not say otherwise", () => {
    // A6.6 five-tier ladder (1k/10k/100k/1M/10M): 97,000 STSH is 9x10k + 7x1k
    // = 16 notes and fits; 9,999,000 STSH is 9x1M + 9x100k + 9x10k + 9x1k = 36
    // notes and does not.
    // A message saying "amounts above X" would be false in both directions.
    expect(() => decomposeAmount(9_999_000n * STSH)).toThrow(/36 fixed-denomination notes/);
    expect(decomposeAmount(97_000n * STSH)).toHaveLength(16);
    let message = "";
    try {
      decomposeAmount(9_999_000n * STSH);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toMatch(/16 one shield may create/); // the cap
    expect(message).toMatch(/Split it into separate shields/); // the remedy
    expect(message).toMatch(/NUMBER of notes, not the amount/); // not an amount ceiling
    expect(message).not.toMatch(/amounts? (above|over|greater)/i);
  });

  it("is enforced at the DEFINITION, so the display caller inherits it too", () => {
    // `planShield` is the shield page's preview path — a second, independent
    // caller. Enforcement at a call site would leave it uncapped.
    expect(() => planShield(98_000n * STSH)).toThrow(/17 fixed-denomination notes/);
    expect(planShield(97_000n * STSH).notes).toHaveLength(16);
  });
});

// ── §4.2 — the lease and its single-use tokens ───────────────────────────────

function authorityAt(clock: { ms: number }, deadlineMs?: number) {
  return createAuthorizationAuthority({
    now: () => clock.ms,
    ...(deadlineMs !== undefined ? { deadlineMs } : {}),
  });
}

describe("WL-2b §4.2 — the lease issues single-use, non-ambient tokens", () => {
  it("refuses a call with NO token — there is no 'is anything open' fallback", async () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    let raw = 0;
    const pool = wrapPoolActor(
      asService({
        retry_private_spend_payout: async () => {
          raw += 1;
          return { Ok: 1n };
        },
      }),
      authority,
    );
    // A lease for this very action is open — and it still refuses, because the
    // caller was not HANDED a token. That is the whole difference from ambient.
    authority.mintLease(["retryPrivateSpendPayout"]);
    await expect(pool.retryPrivateSpendPayout(1n)).rejects.toBeInstanceOf(ActionNotAuthorizedError);
    expect(raw).toBe(0);
  });

  it("spends a token exactly ONCE — a replayed token is refused", async () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    let raw = 0;
    const pool = wrapPoolActor(
      asService({
        retry_private_spend_payout: async () => {
          raw += 1;
          return { Ok: 1n };
        },
      }),
      authority,
    );
    const lease = authority.mintLease(["retryPrivateSpendPayout"]);
    const token = lease.draw("retryPrivateSpendPayout");
    await pool.retryPrivateSpendPayout(1n, token);
    expect(raw).toBe(1);
    await expect(pool.retryPrivateSpendPayout(1n, token)).rejects.toBeInstanceOf(
      ActionNotAuthorizedError,
    );
    expect(raw).toBe(1); // the replay never reached the wire
  });

  it("refuses a token drawn for a different action", async () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const lease = authority.mintLease(["approve", "shieldDeposit"]);
    const approveToken = lease.draw("approve");
    let raw = 0;
    const pool = wrapPoolActor(
      asService({
        shield_deposit: async () => {
          raw += 1;
          return { Ok: 1n };
        },
      }),
      authority,
    );
    await expect(
      pool.shieldDeposit(
        { noteCommitment: new Uint8Array(32), encryptedPayload: new Uint8Array(1), publicAmount: 1n },
        approveToken,
      ),
    ).rejects.toBeInstanceOf(ActionNotAuthorizedError);
    expect(raw).toBe(0);
  });

  it("refuses a FORGED token and a token from ANOTHER authority", async () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const foreign = authorityAt(clock);
    let raw = 0;
    const pool = wrapPoolActor(
      asService({
        private_spend: async () => {
          raw += 1;
          return { Ok: null };
        },
      }),
      authority,
    );
    const forged = { action: "privateSpend" as const };
    await expect(pool.privateSpend({} as never, forged)).rejects.toBeInstanceOf(
      ActionNotAuthorizedError,
    );
    const foreignToken = foreign.mintLease(["privateSpend"]).draw("privateSpend");
    await expect(pool.privateSpend({} as never, foreignToken)).rejects.toBeInstanceOf(
      ActionNotAuthorizedError,
    );
    expect(raw).toBe(0);
  });

  it("is bound to ONE operation — a closed lease draws nothing", () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const a = authority.mintLease(["approve"]);
    const b = authority.mintLease(["approve"]);
    a.close();
    expect(() => a.draw("approve")).toThrow(ActionNotAuthorizedError);
    expect(() => b.draw("approve")).not.toThrow(); // the other lease is unaffected
  });

  it("refuses an action its lease does not name", () => {
    const authority = authorityAt({ ms: 0 });
    const lease = authority.mintLease(["approve"]);
    expect(() => lease.draw("privateSpend")).toThrow(ActionNotAuthorizedError);
  });

  it("guards all six state-changing methods and NO read", async () => {
    const authority = authorityAt({ ms: 0 });
    const pool = wrapPoolActor(
      asService({
        shield_deposit: async () => ({ Ok: 1n }),
        retry_deposit_commitment: async () => ({ Ok: 1n }),
        private_spend: async () => ({ Ok: null }),
        retry_private_spend_payout: async () => ({ Ok: 1n }),
        get_denominations: async () => [1n],
        is_deposits_paused: async () => false,
      }),
      authority,
    );
    const token = wrapTokenMutationActor(
      asService({
        icrc1_transfer: async () => ({ Ok: 1n }),
        icrc2_approve: async () => ({ Ok: 1n }),
        icrc2_allowance: async () => ({ allowance: 0n, expires_at: [] }),
      }),
      authority,
    );
    const guarded: Array<[string, () => Promise<unknown>]> = [
      ["shieldDeposit", () => pool.shieldDeposit({ noteCommitment: new Uint8Array(32), encryptedPayload: new Uint8Array(1), publicAmount: 1n })],
      ["retryDepositCommitment", () => pool.retryDepositCommitment(new Uint8Array(32))],
      ["privateSpend", () => pool.privateSpend({} as never)],
      ["retryPrivateSpendPayout", () => pool.retryPrivateSpendPayout(1n)],
      ["transfer", () => token.transfer({ to: { owner: USER, subaccount: null }, amount: 1n, fee: 0n, createdAtTime: 0n } as never)],
      ["approve", () => token.approve({ spender: USER, amount: 1n, expectedAllowance: 0n, createdAtTime: 0n, fee: 0n })],
    ];
    let guardedCount = 0;
    for (const [name, call] of guarded) {
      await expect(call(), `${name} must be guarded`).rejects.toBeInstanceOf(ActionNotAuthorizedError);
      guardedCount += 1;
    }
    expect(guardedCount).toBe(6);
    await expect(pool.getDenominations()).resolves.toEqual([1n]);
    await expect(pool.isDepositsPaused()).resolves.toBe(false);
    await expect(token.allowance(USER, USER)).resolves.toEqual({ allowance: 0n, expiresAt: null });
  });
});

// ── §4.2c — the deadline, T1–T4 (T5 lives in the shield harness below) ───────

describe("WL-2b §4.2c — the lease deadline, at the shipped magnitude", () => {
  it("is DERIVED from its four declared components, never a literal", () => {
    // 120_000 delay + 10_000 proof + 6_000 x 17 calls + 30_000 slack.
    expect(LEASE_DEADLINE_MS).toBe(120_000 + 10_000 + PER_CALL_BUDGET_MS * MAX_OPERATION_CALLS + 30_000);
    expect(LEASE_DEADLINE_MS).toBe(262_000);
  });

  it("T1 — one millisecond BEFORE the deadline, draw and consume both succeed", async () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const lease = authority.mintLease(["approve"]);
    clock.ms = LEASE_DEADLINE_MS - 1;
    const token = lease.draw("approve");
    expect(() => authority.consume(token, "approve")).not.toThrow();
  });

  it("T2 — at EXACTLY the deadline both throw (the boundary is inclusive)", () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const lease = authority.mintLease(["approve"]);
    const preDrawn = lease.draw("approve");
    clock.ms = LEASE_DEADLINE_MS;
    expect(() => lease.draw("approve")).toThrow(LeaseExpiredError);
    expect(() => authority.consume(preDrawn, "approve")).toThrow(LeaseExpiredError);
  });

  it("T3 — past the deadline both throw", () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const lease = authority.mintLease(["approve"]);
    const preDrawn = lease.draw("approve");
    clock.ms = LEASE_DEADLINE_MS + 1;
    expect(() => lease.draw("approve")).toThrow(LeaseExpiredError);
    expect(() => authority.consume(preDrawn, "approve")).toThrow(LeaseExpiredError);
  });

  it("T4 — a token drawn BEFORE the deadline does not outlive its lease", async () => {
    // The forgotten-lease hazard: a stalled operation must not resume and fire
    // a public call arbitrarily later. Expiry is therefore checked on CONSUME,
    // not only on draw.
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const lease = authority.mintLease(["shieldDeposit"]);
    clock.ms = LEASE_DEADLINE_MS - 1;
    const token = lease.draw("shieldDeposit");
    let raw = 0;
    const pool = wrapPoolActor(
      asService({
        shield_deposit: async () => {
          raw += 1;
          return { Ok: 1n };
        },
      }),
      authority,
    );
    clock.ms = LEASE_DEADLINE_MS + 1;
    await expect(
      pool.shieldDeposit(
        { noteCommitment: new Uint8Array(32), encryptedPayload: new Uint8Array(1), publicAmount: 1n },
        token,
      ),
    ).rejects.toBeInstanceOf(LeaseExpiredError);
    expect(raw).toBe(0);
  });
});

// ── §4.4 P1 — the composed-path trigger proof ────────────────────────────────

interface RawSpy {
  retryCalls: number;
  service: unknown;
}

function rawPoolSpy(): RawSpy {
  const spy: RawSpy = { retryCalls: 0, service: null };
  const record = {
    spend_id: SPEND_ID,
    status: { PayoutPending: { reason: "ledger unavailable" } },
    nullifiers: [new Uint8Array(32).fill(0x2a)],
    output_commitments: [new Uint8Array(32).fill(0x2b), new Uint8Array(32).fill(0x2c)],
    submitter: [USER],
    created_at_ns: 1n,
  };
  spy.service = {
    list_my_active_spends: async () => ({ spends: [record], next_cursor: [] }),
    get_spend_status: async () => [record],
    retry_private_spend_payout: async () => {
      spy.retryCalls += 1;
      return { Ok: 7n };
    },
  };
  return spy;
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

const vetkeys: VetkeysCanister = {
  getConfig: async () => ["stsh.wallet.notes.v1", "key_1"],
  getVetkeyVerificationKey: async () => new Uint8Array(96),
  getEncryptedVetkey: async () => ({ encryptedKey: new Uint8Array(192), remaining: 4 }),
  // W-VETKEYS Layer 1 — not exercised by this suite.
  registerDevice: async () => {
    throw new Error("registerDevice not scripted by this test");
  },
  revokeDevice: async () => {
    throw new Error("revokeDevice not scripted by this test");
  },
  getWrappedSecret: async () => {
    throw new Error("getWrappedSecret not scripted by this test");
  },
  listDevices: async () => {
    throw new Error("listDevices not scripted by this test");
  },
  replaceEnvelope: async () => {
    throw new Error("replaceEnvelope not scripted by this test");
  },
};

function harness(pool: ShieldedActors["pool"], scanNotes?: AppDeps["scanNotes"]): AppDeps {
  return {
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
    scanNotes:
      scanNotes ??
      (async () => ({
        notes: [],
        scannedUpTo: 0n,
        mirrorHead: { leafCount: 0n, root: new Uint8Array(32) },
        quarantine: { total: 0, ring: [] },
        spentSet: new Set<string>(),
      })),
    fetchKeys: async () => ({ vetKey: FAKE_VETKEY, verificationKey: {} as never, remaining: 4 }),
  };
}

function container(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

describe("WL-2b §4.4 P1 — the trigger proof, on the composed post-unlock path", () => {
  it("a cache unlock drives recovery and makes ZERO wire calls; the repair is surfaced", async () => {
    const spy = rawPoolSpy();
    const pool = wrapPoolActor(spy.service as never, walletAuthorizationAuthority);
    const ctx = await mountApp(container(), {}, harness(pool));
    await ctx.unlockNoteCache("pw");
    expect(spy.retryCalls).toBe(0);
    expect(ctx.state.pendingRecovery).toEqual([
      { spendId: SPEND_ID.toString(10), action: "retry-payout" },
    ]);
    expect(ctx.state.status?.msg ?? "").toMatch(/awaiting confirmation/i);
  });

  it("ANTI-VACUITY — the user confirms and the SAME fixture retries exactly once", async () => {
    const spy = rawPoolSpy();
    const pool = wrapPoolActor(spy.service as never, walletAuthorizationAuthority);
    const ctx = await mountApp(container(), {}, harness(pool));
    await ctx.unlockNoteCache("pw");
    expect(spy.retryCalls).toBe(0);
    await ctx.applySpendRecovery();
    expect(spy.retryCalls).toBe(1);
  });
});

describe("WL-2b — a lease expiring mid-operation says only what it knows", () => {
  it("BEFORE any call: nothing was submitted, start again (ruling condition 4)", () => {
    const err = new LeaseExpiredError("shieldDeposit", "the lease deadline passed", false);
    expect(err.partial).toBe(false);
    expect(err.message).toMatch(/Nothing was submitted/i);
    expect(err.message).toMatch(/start the action again/i);
  });

  it("AFTER a call: it must NOT promise nothing was submitted, and must route to reconcile", () => {
    const err = new LeaseExpiredError("shieldDeposit", "the lease deadline passed", true);
    expect(err.partial).toBe(true);
    // The false claim, explicitly excluded — this is the D5 defect as an assertion.
    expect(err.message).not.toMatch(/Nothing was submitted/i);
    expect(err.message).toMatch(/ALREADY submitted/i);
    expect(err.message).toMatch(/may be incomplete/i);
    expect(err.message).toMatch(/Reconcile/i);
    expect(err.message).not.toMatch(/start the action again/i);
  });

  it("CAUSAL — expiry after a successful call reports PARTIAL, and the next call never fires", async () => {
    // The clock is advanced only AFTER at least one raw call has succeeded, so
    // this drives the exact reachable state D5 named: a multi-call operation
    // that dies between its calls.
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    let rawDeposits = 0;
    const pool = wrapPoolActor(
      asService({
        shield_deposit: async () => {
          rawDeposits += 1;
          return { Ok: 1n };
        },
      }),
      authority,
    );
    const lease = authority.mintLease(["shieldDeposit"]);
    const req = {
      noteCommitment: new Uint8Array(32),
      encryptedPayload: new Uint8Array(1),
      publicAmount: STSH,
    };

    // Call 1 succeeds and IS dispatched.
    await pool.shieldDeposit(req, lease.draw("shieldDeposit"));
    expect(rawDeposits).toBe(1);

    // Only now does the lease run out, between calls.
    clock.ms = LEASE_DEADLINE_MS;

    let caught: unknown;
    try {
      await pool.shieldDeposit(req, lease.draw("shieldDeposit"));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(LeaseExpiredError);
    expect((caught as LeaseExpiredError).partial).toBe(true);
    expect((caught as LeaseExpiredError).message).not.toMatch(/Nothing was submitted/i);
    expect((caught as LeaseExpiredError).message).toMatch(/Reconcile/i);
    // The second call never reached the wire — the count is still the first one.
    expect(rawDeposits).toBe(1);
  });

  it("ANTI-VACUITY — the same lease, expiring with NOTHING consumed, still says nothing was sent", () => {
    const clock = { ms: 0 };
    const authority = authorityAt(clock);
    const lease = authority.mintLease(["shieldDeposit"]);
    clock.ms = LEASE_DEADLINE_MS;
    try {
      lease.draw("shieldDeposit");
      expect.unreachable("the draw must throw");
    } catch (err) {
      expect(err).toBeInstanceOf(LeaseExpiredError);
      expect((err as LeaseExpiredError).partial).toBe(false);
      expect((err as LeaseExpiredError).message).toMatch(/Nothing was submitted/i);
    }
  });
});

// ── §4.4 P2 + §7.4 — the wrapper proof, over every private-event kind ────────

describe("WL-2b §4.4 P2 — the guard proof, driven at the WRAPPER", () => {
  /**
   * §4.1's private-event kinds, enumerated: 4 defined, 4 driven. Each drives a
   * real local-only operation and then attempts the public call the way that
   * kind's code path would — with no gesture, therefore with no token.
   */
  const PRIVATE_EVENTS: Array<{ kind: string; drive: () => Promise<void> }> = [
    {
      kind: "scanner discovery/validation",
      drive: async () => {
        const { mergeScanOutcome } = await import("../src/crypto/scanner");
        mergeScanOutcome(
          { lastScannedIndex: 0n, notes: [] },
          {
            notes: [
              {
                leafIndex: 1n,
                value: STSH,
                rho: new Uint8Array(32),
                rseed: new Uint8Array(32),
                recipientPk: new Uint8Array(32),
                state: "spendable",
              },
            ],
            scannedUpTo: 1n,
            mirrorHead: { leafCount: 1n, root: new Uint8Array(32) },
            quarantine: { total: 0, ring: [] },
            spentSet: new Set<string>(),
          },
          1_000n,
        );
      },
    },
    {
      kind: "note-cache read / balance recomputation",
      drive: async () => {
        const { spendableNotes } = await import("../src/storage/noteCache");
        spendableNotes([]);
      },
    },
    {
      kind: "journal read",
      drive: async () => {
        const { recoveryActionForAdvisory } = await import("../src/ui/spendFlow");
        recoveryActionForAdvisory({ kind: "payout-pending" }, "recovery-required");
      },
    },
    {
      kind: "cache unlock",
      drive: async () => {
        const spy = rawPoolSpy();
        const pool = wrapPoolActor(spy.service as never, walletAuthorizationAuthority);
        const ctx = await mountApp(container(), {}, harness(pool));
        await ctx.unlockNoteCache("pw");
        expect(spy.retryCalls).toBe(0);
      },
    },
  ];

  it.each(PRIVATE_EVENTS)(
    "a private event ($kind) cannot reach ANY of the six update methods",
    async ({ drive }) => {
      await drive();
      // Whatever the private event learned, it holds no token — so every
      // state-changing wrapper method refuses, and the raw count stays zero.
      const authority = authorityAt({ ms: 0 });
      const raw: Record<string, number> = {};
      const bump = (k: string) => {
        raw[k] = (raw[k] ?? 0) + 1;
      };
      const pool = wrapPoolActor(
        asService({
          shield_deposit: async () => (bump("shield_deposit"), { Ok: 1n }),
          retry_deposit_commitment: async () => (bump("retry_deposit_commitment"), { Ok: 1n }),
          private_spend: async () => (bump("private_spend"), { Ok: null }),
          retry_private_spend_payout: async () => (bump("retry_private_spend_payout"), { Ok: 1n }),
        }),
        authority,
      );
      const tokenActor = wrapTokenMutationActor(
        asService({
          icrc1_transfer: async () => (bump("icrc1_transfer"), { Ok: 1n }),
          icrc2_approve: async () => (bump("icrc2_approve"), { Ok: 1n }),
        }),
        authority,
      );
      const attempts = [
        pool.shieldDeposit({ noteCommitment: new Uint8Array(32), encryptedPayload: new Uint8Array(1), publicAmount: 1n }),
        pool.retryDepositCommitment(new Uint8Array(32)),
        pool.privateSpend({} as never),
        pool.retryPrivateSpendPayout(1n),
        tokenActor.transfer({ to: { owner: USER, subaccount: null }, amount: 1n, fee: 0n, createdAtTime: 0n } as never),
        tokenActor.approve({ spender: USER, amount: 1n, expectedAllowance: 0n, createdAtTime: 0n, fee: 0n }),
      ].map((p) => p.then(() => "called" as const, () => "refused" as const));
      expect(await Promise.all(attempts)).toEqual(Array(6).fill("refused"));
      expect(raw).toEqual({}); // no raw candid call was made, by any of the six
    },
  );

  it("ANTI-VACUITY — the same wrapper, handed a token, does call exactly once", async () => {
    const authority = authorityAt({ ms: 0 });
    let raw = 0;
    const pool = wrapPoolActor(
      asService({
        private_spend: async () => {
          raw += 1;
          return { Ok: null };
        },
      }),
      authority,
    );
    const lease = authority.mintLease(["privateSpend"]);
    await pool.privateSpend(
      { publicPayout: null, nullifiers: [], outputCommitments: [], encryptedOutputs: [], inputAmounts: [], outputAmounts: [] } as never,
      lease.draw("privateSpend"),
    );
    expect(raw).toBe(1);
  });
});
