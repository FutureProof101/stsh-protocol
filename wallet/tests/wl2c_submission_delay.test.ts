/**
 * WL-2c — the optional randomised submission delay.
 *
 * Two things have to be true and they are proved separately.
 *
 * THE DRAW is uniform over an inclusive range, from a CSPRNG, with the modulo
 * bias explicitly rejected rather than ignored. Both endpoints and the
 * rejection arm are driven from an injected byte source.
 *
 * THE ORDERING is the part D8 was about. The unit of delay is the OPERATION,
 * not the method: the shield's FIRST state-changing public call is the ICRC-2
 * approve, not the deposit, so a delay that only covers the deposit leaves the
 * operation's first public signal at the user's real action time. Every
 * ordering row therefore spies BOTH actors and asserts BOTH counts — a probe
 * that only watched `shield_deposit` would pass on exactly the broken design.
 *
 * NOTHING here asserts against real elapsed time: the wait is an injected
 * promise the test resolves by hand.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { bls12_381 } from "@noble/curves/bls12-381";
import { augmentedHashToG1, DerivedPublicKey, VetKey } from "@dfinity/vetkeys";

import { initPoseidon } from "../src/crypto/poseidon";
import { vetkdInput, type VetkeysCanister } from "../src/crypto/vetkeys";
import type { PoolCanister, ShieldFeeParams } from "../src/actors/pool";
import type { ApproveRequest, TokenCanister, TokenMutationCanister } from "../src/actors/token";
import { resolveConfig } from "../src/session/config";
import {
  SUBMISSION_DELAY_DEFAULT,
  SUBMISSION_DELAY_STORAGE_KEY,
  readSubmissionDelayEnabled,
  writeSubmissionDelayEnabled,
} from "../src/session/config";
import { ShieldJournal } from "../src/storage/journal";
import { PrincipalNoteCache } from "../src/storage/noteCache";
import { runShieldFlow, type ShieldFlowDeps } from "../src/ui/shieldFlow";
import {
  DELAY_MAX_MS,
  SubmissionAbandonedError,
  createSubmissionDelay,
  drawDelayMs,
} from "../src/ui/submissionDelay";
import { memoryHarness, testBinding } from "./helpers/cacheL4";

const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  await initPoseidon(readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm")));
});

// ── the draw ─────────────────────────────────────────────────────────────────

const be32 = (v: number): Uint8Array =>
  Uint8Array.from([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);

describe("WL-2c — the delay draw", () => {
  const n = DELAY_MAX_MS + 1;
  const limit = Math.floor(0x1_0000_0000 / n) * n;

  it("is bounded at TWO MINUTES — the shipped value, pinned", () => {
    // Named and pinned rather than inferred: every other assertion in this file
    // is relative to `DELAY_MAX_MS`, so without this row the bound could be
    // raised to any value and nothing would notice.
    expect(DELAY_MAX_MS).toBe(120_000);
  });

  it("reaches BOTH endpoints of the inclusive range — zero is a legal draw", () => {
    expect(drawDelayMs(() => be32(0))).toBe(0);
    expect(drawDelayMs(() => be32(DELAY_MAX_MS))).toBe(DELAY_MAX_MS);
  });

  it("never exceeds the bound, over a wide sweep of raw draws", () => {
    // Every value here is BELOW `limit` — a constant source at or above it is
    // rejected forever by construction, which is the point of the arm below.
    for (const raw of [1, 7, n - 1, n, n + 1, limit - 1, 0x7fff_ffff]) {
      const drawn = drawDelayMs(() => be32(raw >>> 0));
      expect(drawn).toBeGreaterThanOrEqual(0);
      expect(drawn).toBeLessThanOrEqual(DELAY_MAX_MS);
    }
  });

  it("REJECTS a biased draw and re-draws instead of reducing it", () => {
    // The first draw lands in the short final partial block — reducing it would
    // over-represent the low residues, so it must be discarded, not used.
    const series = [limit, 5];
    let i = 0;
    const drawn = drawDelayMs(() => be32(series[i++] >>> 0));
    expect(i).toBe(2); // it really did draw twice
    expect(drawn).toBe(5); // ...and used the SECOND draw
  });
});

describe("WL-2c — the toggle", () => {
  it("defaults to OFF, and an absent or garbled value reads as the default", () => {
    expect(SUBMISSION_DELAY_DEFAULT).toBe(false);
    expect(readSubmissionDelayEnabled({ getItem: () => null })).toBe(false);
    expect(readSubmissionDelayEnabled({ getItem: () => "yes-please" })).toBe(false);
    expect(readSubmissionDelayEnabled({ getItem: () => "on" })).toBe(true);
  });

  it("round-trips through the ONE key a panic wipe clears", () => {
    const store = new Map<string, string>();
    const api = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
    };
    writeSubmissionDelayEnabled(true, api);
    expect(store.get(SUBMISSION_DELAY_STORAGE_KEY)).toBe("on");
    expect(readSubmissionDelayEnabled(api)).toBe(true);
    // A wipe empties localStorage; the next read is the fail-safe default.
    store.clear();
    expect(readSubmissionDelayEnabled(api)).toBe(false);
  });
});

// ── the shield harness (compact: real crypto + journal, scripted actors) ─────

const MASTER_X = 0x517f0da4cf3d70b1n;
const DPK = DerivedPublicKey.deserialize(
  bls12_381.G2.ProjectivePoint.BASE.multiply(MASTER_X).toRawBytes(true),
);
const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x11));
const POOL = Principal.fromUint8Array(new Uint8Array(10).fill(0xab));
const TOKEN = Principal.fromUint8Array(new Uint8Array(10).fill(0xcd));
const MERKLE = Principal.fromUint8Array(new Uint8Array(10).fill(0xef));
const NULLIFIER = Principal.fromUint8Array(new Uint8Array(10).fill(0x01));
const STSH = 100_000_000n;
/// A6.6: the launch ladder's floor rung, 1,000 STSH — the smallest shieldable
/// amount. Every amount in this suite is a multiple of it.
const RUNG = 1_000n * STSH;
const LEDGER_FEE = 10_000n;

const ZERO_FEES: ShieldFeeParams = {
  shieldFeeBps: 0,
  shieldFlatMinimumFeeE8s: 0n,
  minimumPrivateCredit: 0n,
  feeModelVersion: 1,
  paramsEpoch: 0n,
  protocolPrivateSpendFeeStsh: 0n,
  unshieldFeeBps: 0,
  unshieldFlatMinimumFeeE8s: 0n,
};

interface Spies {
  /** RAW invocation counts — the causal observable, not a returned error. */
  approve: number;
  deposit: number;
  approves: ApproveRequest[];
}

async function shieldHarness(over: {
  feeParams?: () => Promise<ShieldFeeParams>;
  nowNs?: () => bigint;
}): Promise<{ deps: Omit<ShieldFlowDeps, "submissionDelay">; spies: Spies }> {
  const spies: Spies = { approve: 0, deposit: 0, approves: [] };
  const config = resolveConfig({
    VITE_POOL_CANISTER_ID: POOL.toText(),
    VITE_TOKEN_CANISTER_ID: TOKEN.toText(),
    VITE_MERKLE_CANISTER_ID: MERKLE.toText(),
    VITE_NULLIFIER_CANISTER_ID: NULLIFIER.toText(),
    VITE_FROZEN_POOL_CANISTER_ID: POOL.toText(),
    VITE_VETKD_KEY_NAME: "test_key_1",
  });
  const tokenRead: TokenCanister = {
    balanceOf: async () => 0n,
    metadata: async () => ({ symbol: "STSH", decimals: 8, fee: LEDGER_FEE }),
    fee: async () => LEDGER_FEE,
  };
  const tokenMutation: TokenMutationCanister = {
    transfer: async () => {
      throw new Error("not scripted");
    },
    approve: async (req) => {
      spies.approve += 1;
      spies.approves.push(req);
      return { kind: "ok", blockIndex: 1n };
    },
    allowance: async () => ({ allowance: 0n, expiresAt: null }),
  };
  const feeParams = over.feeParams ?? (async () => ZERO_FEES);
  const pool = {
    shieldDeposit: async () => {
      spies.deposit += 1;
      return 1n;
    },
    isDepositsPaused: async () => false,
    getGovernanceFeeParams: () => feeParams(),
    getDepositStatus: async () => null,
  } as unknown as PoolCanister;
  const vetkeys: VetkeysCanister = {
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
    getConfig: async () => ["stsh.wallet.notes.v1", "test_key_1"],
  };
  const store = (await memoryHarness()).store;
  const cache = await PrincipalNoteCache.open(store, "pass", testBinding(USER.toText()));
  return {
    spies,
    deps: {
      policyKind: "local",
      config,
      principal: USER,
      tokenRead,
      tokenMutation,
      pool,
      vetkeys,
      journal: new ShieldJournal(cache),
      nowNs: over.nowNs ?? (() => 1_000n),
      fetchKeys: async () => ({
        vetKey: new VetKey(augmentedHashToG1(DPK, vetkdInput(USER)).multiply(MASTER_X)),
        verificationKey: DPK, remaining: 4 }),
    },
  };
}

/**
 * Pump microtasks until `cond` holds. Used INSTEAD of a fixed number of
 * `await Promise.resolve()` hops: an ordering assertion must be made at the
 * moment the operation is actually parked on the delay, not at whatever point
 * a guessed number of hops happens to land — otherwise a delay placed LATER in
 * the flow would read as "nothing has been called yet" and the row would pass
 * on exactly the design it exists to reject.
 */
async function until(cond: () => boolean): Promise<void> {
  for (let i = 0; i < 10_000 && !cond(); i += 1) await Promise.resolve();
  if (!cond()) throw new Error("condition never held while pumping microtasks");
}

/** A wait the test releases by hand — no wall clock anywhere. */
function manualSleep() {
  let release: (() => void) | undefined;
  return {
    sleep: () =>
      new Promise<void>((resolve) => {
        release = resolve;
      }),
    release: () => release?.(),
    armed: () => release !== undefined,
  };
}

describe("WL-2c — the shield operation's ORDERING (both actors spied)", () => {
  it("T1: before the delay releases, approve count is 0 AND deposit count is 0", async () => {
    const { deps, spies } = await shieldHarness({});
    const wait = manualSleep();
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    // Asserted AT the moment the operation is parked on its delay: the FIRST
    // public call of a shield is the approve, and it must not have happened.
    expect(spies.approve).toBe(0);
    expect(spies.deposit).toBe(0);
    wait.release();
    await flow;
  });

  it("T2: the session ends during the wait — both counts stay 0, the operation is abandoned", async () => {
    const { deps, spies } = await shieldHarness({});
    const wait = manualSleep();
    let live = true;
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {
            if (!live) throw new Error("the session ended");
          },
          randomBytes: () => be32(60_000),
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    live = false; // lock / logout / epoch change under the wait
    wait.release();
    await expect(flow).rejects.toBeInstanceOf(SubmissionAbandonedError);
    expect(spies.approve).toBe(0);
    expect(spies.deposit).toBe(0);
  });

  it("T3a: a basis that drifts DURING the wait is NOT stale — the snapshot is taken after it", async () => {
    // This is the D3 fix, stated as a measurement rather than as reassurance:
    // because the wait is at the TOP, no live value has been read when the
    // basis moves, so the operation prices the CURRENT basis and proceeds. If
    // the delay were moved after the fee snapshot, this same mutation would
    // strand a stale basis and the flow would abort — which is mutation M7.
    let epoch = 0n;
    const seen: bigint[] = [];
    const { deps, spies } = await shieldHarness({
      feeParams: async () => {
        seen.push(epoch);
        return { ...ZERO_FEES, paramsEpoch: epoch };
      },
    });
    const wait = manualSleep();
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    expect(seen).toEqual([]); // nothing live has been read yet — that is the claim
    expect(spies.approve).toBe(0);
    expect(spies.deposit).toBe(0);
    epoch = 1n; // the basis moves while the user waits
    wait.release();
    await flow;
    // Every read saw the CURRENT basis; none saw the pre-delay one.
    expect(seen.length).toBeGreaterThanOrEqual(1);
    expect(seen.every((e) => e === 1n)).toBe(true);
    expect(spies.approve).toBe(1);
  });

  it("T3b: a basis that drifts AFTER the snapshot still aborts before any deposit", async () => {
    // The fail-closed re-check is untouched by WL-2c: the irreversible half of
    // the operation — the deposit — never fires on a drifted basis. The
    // observable is the CALL COUNT, not the returned error.
    let calls = 0;
    const { deps, spies } = await shieldHarness({
      feeParams: async () => {
        calls += 1;
        return { ...ZERO_FEES, paramsEpoch: calls === 1 ? 0n : 1n };
      },
    });
    const wait = manualSleep();
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    wait.release();
    await expect(flow).rejects.toThrow(/fee|basis|stale/i);
    expect(spies.deposit).toBe(0);
  });

  it("T4 ANTI-VACUITY: nothing changed — the approve fires once and every note deposits", async () => {
    const { deps, spies } = await shieldHarness({});
    const wait = manualSleep();
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
        }),
      },
      3n * RUNG,
    );
    await until(wait.armed);
    wait.release();
    await flow;
    expect(spies.approve).toBe(1);
    expect(spies.deposit).toBeGreaterThanOrEqual(1);
  });

  it("the dedup timestamp is captured AFTER the delay, never before it", async () => {
    // `created_at_time` is the ONE stable ICRC-2 dedup timestamp. Reading it
    // before a delay of up to two minutes would age it toward the ledger's
    // TooOld window; with the wait at the top of the operation it is read
    // after, so the window is unchanged.
    let clock = 1_000n;
    const { deps, spies } = await shieldHarness({ nowNs: () => clock });
    const wait = manualSleep();
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    clock = 999_000n; // time passes DURING the wait
    wait.release();
    await flow;
    expect(spies.approves[0].createdAtTime).toBe(999_000n);
    expect(spies.approves[0].createdAtTime).not.toBe(1_000n);
  });

  it("with the toggle OFF nothing waits and the operation runs straight through", async () => {
    const { deps, spies } = await shieldHarness({});
    let slept = 0;
    await runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => false,
          sleep: async () => {
            slept += 1;
          },
          assertSessionCurrent: () => {},
        }),
      },
      RUNG,
    );
    expect(slept).toBe(0);
    expect(spies.approve).toBe(1);
  });

  it("the user can cancel the wait — nothing is submitted on either actor", async () => {
    const { deps, spies } = await shieldHarness({});
    const wait = manualSleep();
    let view: { cancel(): void } | null = null;
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
          onPending: (v) => {
            if (v !== null) view = v;
          },
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    expect(view).not.toBeNull();
    view!.cancel();
    await expect(flow).rejects.toBeInstanceOf(SubmissionAbandonedError);
    expect(spies.approve).toBe(0);
    expect(spies.deposit).toBe(0);
  });

  it("the user can submit early — the wait ends and the operation proceeds", async () => {
    const { deps, spies } = await shieldHarness({});
    const wait = manualSleep();
    let view: { submitNow(): void } | null = null;
    const flow = runShieldFlow(
      {
        ...deps,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
          onPending: (v) => {
            if (v !== null) view = v;
          },
        }),
      },
      RUNG,
    );
    await until(wait.armed);
    view!.submitNow();
    await flow;
    expect(spies.approve).toBe(1);
  });
});

describe("WL-2c — the spend operation, and the operations that are NOT delayed", () => {
  it("T5: the spend's delay is at the TOP — nothing downstream runs until it releases", async () => {
    // Driving a full `runSpendFlow` would mean a real proving run; the ordering
    // claim does not need one. The first thing after the delay is the input
    // check, and this input is deliberately invalid — so if the delay were NOT
    // first, the call would reject immediately. It must not.
    const { runSpendFlow } = await import("../src/ui/spendFlow");
    const wait = manualSleep();
    let privateSpendCalls = 0;
    const deps = {
      policyKind: "local" as const,
      principal: USER,
      notes: [],
      pool: {
        privateSpend: async () => {
          privateSpendCalls += 1;
        },
      },
      submissionDelay: createSubmissionDelay({
        enabled: () => true,
        sleep: wait.sleep,
        assertSessionCurrent: () => {},
        randomBytes: () => be32(60_000),
      }),
    } as never;
    const flow = runSpendFlow(deps, { inputLeafIndex: 99n });
    const settled = flow.then(
      () => "resolved" as const,
      () => "rejected" as const,
    );
    let outcome: string | null = null;
    void settled.then((o) => {
      outcome = o;
    });
    await until(wait.armed);
    // Still waiting: the invalid input has NOT been looked at yet.
    expect(outcome).toBeNull();
    expect(privateSpendCalls).toBe(0);
    wait.release();
    expect(await settled).toBe("rejected"); // ...and now the input check runs
    expect(privateSpendCalls).toBe(0);
  });

  it("the three NOT-DELAYED operations fire immediately, even with the toggle ON", async () => {
    // Rows 2, 4 and 5 of the operation table are decisions, not omissions:
    // a deposit retry and a payout retry repair something ALREADY public, and
    // a plain account transfer is public on both ends. Delaying any of them
    // buys no unlinkability and risks the ledger's TooOld window.
    const { createAuthorizationAuthority } = await import("../src/actors/authorization");
    const { wrapPoolActor } = await import("../src/actors/pool");
    const { wrapTokenMutationActor } = await import("../src/actors/token");
    let slept = 0;
    const sleepSpy = async () => {
      slept += 1;
    };
    // A delay controller exists and is ENABLED — if any of these three routed
    // through it, `slept` would move.
    createSubmissionDelay({ enabled: () => true, sleep: sleepSpy, assertSessionCurrent: () => {} });
    const authority = createAuthorizationAuthority({ now: () => 0 });
    const raw: Record<string, number> = { retryDeposit: 0, retryPayout: 0, transfer: 0 };
    const pool = wrapPoolActor(
      {
        retry_deposit_commitment: async () => {
          raw.retryDeposit += 1;
          return { Ok: 1n };
        },
        retry_private_spend_payout: async () => {
          raw.retryPayout += 1;
          return { Ok: 1n };
        },
      } as never,
      authority,
    );
    const tokenActor = wrapTokenMutationActor(
      {
        icrc1_transfer: async () => {
          raw.transfer += 1;
          return { Ok: 1n };
        },
      } as never,
      authority,
    );
    const lease = authority.mintLease([
      "retryDepositCommitment",
      "retryPrivateSpendPayout",
      "transfer",
    ]);
    await pool.retryDepositCommitment(new Uint8Array(32), lease.draw("retryDepositCommitment"));
    await pool.retryPrivateSpendPayout(1n, lease.draw("retryPrivateSpendPayout"));
    await tokenActor.transfer(
      { to: { owner: USER, subaccount: null }, amount: 1n, fee: 0n, createdAtTime: 0n } as never,
      lease.draw("transfer"),
    );
    expect(raw).toEqual({ retryDeposit: 1, retryPayout: 1, transfer: 1 });
    expect(slept).toBe(0);
  });
});

// ── WL-2b §4.2b (concurrency bite) and §4.2c T5 (deadline anti-vacuity) ──────
//
// Both need a real shield operation, so they live beside the shield harness
// above rather than in the WL-2b file.

describe("WL-2b §4.2b — a private event cannot ride an open operation's lease", () => {
  it("mid-operation, an interleaved same-action attempt makes ZERO wire calls", async () => {
    const { createAuthorizationAuthority } = await import("../src/actors/authorization");
    const { wrapPoolActor } = await import("../src/actors/pool");
    const authority = createAuthorizationAuthority({ now: () => 0 });

    // The operation's OWN deposits go through a wrapped, authority-backed pool,
    // so both the legitimate calls and the interloper are measured on the same
    // raw surface.
    let rawDeposits = 0;
    const rawPool = {
      shield_deposit: async () => {
        rawDeposits += 1;
        return { Ok: 1n };
      },
    } as never;
    const guardedPool = wrapPoolActor(rawPool, authority);

    const { deps } = await shieldHarness({});
    const wait = manualSleep();
    const lease = authority.mintLease(["approve", "shieldDeposit"]);
    const flow = runShieldFlow(
      {
        ...deps,
        pool: { ...deps.pool, shieldDeposit: guardedPool.shieldDeposit } as typeof deps.pool,
        lease,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          sleep: wait.sleep,
          assertSessionCurrent: () => {},
          randomBytes: () => be32(60_000),
        }),
      },
      RUNG,
    );
    // The operation is authorized and in flight, parked on an await.
    await until(wait.armed);

    // A PRIVATE EVENT now attempts the very same action. It has no token — and
    // there is no ambient "is a shield lease open?" question it could win.
    await expect(
      guardedPool.shieldDeposit({
        noteCommitment: new Uint8Array(32),
        encryptedPayload: new Uint8Array(1),
        publicAmount: RUNG,
      }),
    ).rejects.toThrow(/must be authorised by an explicit user gesture/);
    expect(rawDeposits).toBe(0); // attributable to the private event: zero

    wait.release();
    await flow;
    // Anti-vacuity: the legitimate operation's own deposit DID go through, so
    // the zero above is a refusal, not an inert wrapper.
    expect(rawDeposits).toBe(1);
  });
});

describe("WL-2b §4.2c T5 — the deadline is not self-defeating", () => {
  it("a MAXIMUM shield — full delay draw, cap-many notes — completes inside the deadline", async () => {
    // The anti-vacuity row for the whole derivation: a deadline set too tight
    // passes T1–T4 and breaks the shipped feature. The clock advances by the
    // budgeted amounts — the delay's full bound, then PER_CALL_BUDGET_MS per
    // wire call — so this measures the DERIVATION, not this machine's speed.
    const { createAuthorizationAuthority, PER_CALL_BUDGET_MS } = await import(
      "../src/actors/authorization"
    );
    const { MAX_NOTES_PER_OPERATION } = await import("../src/crypto/notes");
    const clock = { ms: 0 };
    const authority = createAuthorizationAuthority({ now: () => clock.ms });
    const { deps, spies } = await shieldHarness({});
    const charged = {
      ...deps,
      tokenMutation: {
        ...deps.tokenMutation,
        approve: async (req: Parameters<typeof deps.tokenMutation.approve>[0], t?: unknown) => {
          clock.ms += PER_CALL_BUDGET_MS;
          return deps.tokenMutation.approve(req, t as never);
        },
      },
      pool: {
        ...deps.pool,
        shieldDeposit: async (req: unknown, t?: unknown) => {
          clock.ms += PER_CALL_BUDGET_MS;
          return (deps.pool.shieldDeposit as (a: unknown, b?: unknown) => Promise<bigint>)(req, t);
        },
      },
    } as typeof deps;
    const lease = authority.mintLease(["approve", "shieldDeposit"]);
    await runShieldFlow(
      {
        ...charged,
        lease,
        submissionDelay: createSubmissionDelay({
          enabled: () => true,
          // The worst legal draw: the user waits the entire bound.
          randomBytes: () => be32(DELAY_MAX_MS),
          sleep: async (ms: number) => {
            clock.ms += ms;
          },
          assertSessionCurrent: () => {},
        }),
      },
      // N notes of the TOP rung: derived from the ladder, so it stays exactly
      // MAX_NOTES_PER_OPERATION notes whatever the rungs below it are (A6.6).
      BigInt(MAX_NOTES_PER_OPERATION) * 10_000_000n * STSH,
    );
    expect(spies.approve).toBe(1);
    expect(spies.deposit).toBe(MAX_NOTES_PER_OPERATION);
    // It fitted — and the margin is real rather than accidental. (The flow
    // itself is the sharper assertion: a deadline reduced below this
    // configuration's need makes the draws throw and this test RED.)
    const { LEASE_DEADLINE_MS } = await import("../src/actors/authorization");
    expect(clock.ms).toBeLessThan(LEASE_DEADLINE_MS);
  });
});
