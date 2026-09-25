/**
 * AC-3 gate tests — request-identity fencing on the read-only pages (brief §3).
 *
 * Overlapping loads: a slow response (success OR error) for principal A must
 * never replace or wipe principal B's rendered results, and the rendered data
 * is labelled with the principal it was RESOLVED for.
 */

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";
import { Ed25519KeyIdentity } from "@dfinity/identity";

import type { StakePositionView, StakingReadCanister } from "../src/actors/staking";
import type { VestingReadCanister, VestingScheduleView } from "../src/actors/vesting";
import { resolveConfig } from "../src/session/config";
import type { Enumeration } from "../src/storage/panicWipe";
import type { AppContext } from "../src/ui/context";
import { renderStaking } from "../src/ui/pages/staking";
import { renderVesting } from "../src/ui/pages/vesting";

const PRINCIPAL_A = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(41)).getPrincipal();
const PRINCIPAL_B = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(42)).getPrincipal();
const PRINCIPAL_C = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(43)).getPrincipal();

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

async function settleMicrotasks(): Promise<void> {
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
}

function pageCtx(overrides: {
  staking?: StakingReadCanister;
  vesting?: VestingReadCanister;
}): AppContext {
  const noop = async (): Promise<void> => undefined;
  return {
    config: resolveConfig({}),
    policy: { kind: "production", iiUrl: undefined, derivationOrigin: undefined },
    state: {
      principal: null,
      balance: null,
      busy: false,
      spendLocallyCancellable: false,
      status: null,
      cacheUnlocked: false,
      shieldEntries: null,
      notes: [],
      scanning: false,
      lastScanOk: null,
      scanProgress: null,
      mirrorHead: null,
      quarantineTotal: 0,
    verifiedScan: null,
    verifiedRollback: null,
    verifiedScanning: false,
      wipeReport: null,
    submissionDelayEnabled: false,
    pendingDelay: null,
    quotaNotice: null,
    capacityCountdownSeconds: null,
    spendFeeBasis: null,
    pendingRecovery: [],
    },
    readActors: {
      token: {
        balanceOf: async () => 0n,
        metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
        fee: async () => 0n,
      },
      staking:
        overrides.staking ??
        ({
          getStakePositions: async () => [],
          getPendingRewards: async () => 0n,
        } satisfies StakingReadCanister),
      vesting:
        overrides.vesting ??
        ({ getSchedule: async () => null, claimableAmount: async () => 0n } satisfies VestingReadCanister),
    },
    mutationActors: null,
    journalAvailable: true,
    operatorActors: null,
    shieldedActors: null,
    pendingIntent: null,
    navigate: () => undefined,
    refresh: () => undefined,
    login: noop,
    logout: noop,
    refreshBalance: noop,
    transfer: noop,
    retryPendingIntent: noop,
    abandonFrozenIntent: noop,
    unlockNoteCache: noop,
    shield: noop,
    reconcileShieldJournal: noop,
    revokeShieldAllowance: noop,
    cancelPlannedShield: noop,
    abandonAmbiguousShieldEntry: noop,
    scan: noop,
    spend: noop,
    recoverSpends: noop,
    // A-1b: the wipe is never exercised by these read-fencing tests; the stub
    // exists so the context still satisfies AppContext.
    panicWipe: async () => {
      const none: Enumeration = { kind: "ok", items: [] };
      const inv = { indexedDb: none, localStorage: none, sessionStorage: none, cacheStorage: none };
      return { complete: true, surfaces: [], before: inv, after: inv };
    },
    setSubmissionDelayEnabled: () => undefined,
    loadSpendFeeBasis: noop,
    applySpendRecovery: noop,
  };
}

function position(holder: Principal, amountStsh: bigint): StakePositionView {
  return {
    positionId: 1n,
    holder,
    amount: amountStsh * 100_000_000n,
    lockDays: 30,
    lockEndNs: 1_800_000_000_000_000_000n,
    votingWeight: amountStsh * 100_000_000n,
    rewardsClaimed: 0n,
    createdAtNs: 1_700_000_000_000_000_000n,
    closed: false,
    opId: null,
  };
}

function loadFor(root: HTMLElement, inputTestId: string, loadTestId: string, principal: Principal): void {
  const input = root.querySelector<HTMLInputElement>(`[data-testid="${inputTestId}"]`);
  input!.value = principal.toText();
  root.querySelector<HTMLButtonElement>(`[data-testid="${loadTestId}"]`)!.click();
}

describe("AC-3 staking page fencing", () => {
  function gatedStaking(): {
    actor: StakingReadCanister;
    gates: Map<string, Deferred<StakePositionView[]>>;
  } {
    const gates = new Map<string, Deferred<StakePositionView[]>>();
    return {
      gates,
      actor: {
        getStakePositions: (holder) => {
          const gate = deferred<StakePositionView[]>();
          gates.set(holder.toText(), gate);
          return gate.promise;
        },
        getPendingRewards: async () => 0n,
      },
    };
  }

  it("a slow load(A) success cannot replace a faster load(B); the shown principal is B", async () => {
    const { actor, gates } = gatedStaking();
    const root = document.createElement("div");
    renderStaking(root, pageCtx({ staking: actor }));

    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_A); // slow
    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_B); // fast

    gates.get(PRINCIPAL_B.toText())!.resolve([position(PRINCIPAL_B, 10n)]);
    await vi.waitFor(() => {
      expect(root.querySelector('[data-testid="staking-holder-shown"]')).not.toBeNull();
    });
    expect(root.querySelector('[data-testid="staking-holder-shown"]')?.textContent).toContain(
      PRINCIPAL_B.toText(),
    );

    // A's LATE success must be discarded outright.
    gates.get(PRINCIPAL_A.toText())!.resolve([position(PRINCIPAL_A, 999n)]);
    await settleMicrotasks();
    expect(root.querySelector('[data-testid="staking-holder-shown"]')?.textContent).toContain(
      PRINCIPAL_B.toText(),
    );
    expect(root.textContent).toContain("10 STSH");
    expect(root.textContent).not.toContain("999 STSH");
  });

  it("a stale load(A) ERROR does not wipe load(B)'s rendered results", async () => {
    const { actor, gates } = gatedStaking();
    const root = document.createElement("div");
    renderStaking(root, pageCtx({ staking: actor }));

    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_A); // will fail late
    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_B); // succeeds first

    gates.get(PRINCIPAL_B.toText())!.resolve([position(PRINCIPAL_B, 10n)]);
    await vi.waitFor(() => {
      expect(root.querySelector('[data-testid="staking-holder-shown"]')).not.toBeNull();
    });

    gates.get(PRINCIPAL_A.toText())!.reject(new Error("slow backend failure"));
    await settleMicrotasks();
    expect(root.textContent).not.toContain("Could not load staking data");
    expect(root.querySelector('[data-testid="staking-holder-shown"]')?.textContent).toContain(
      PRINCIPAL_B.toText(),
    );
    expect(root.textContent).toContain("10 STSH");
  });

  it("token monotonicity: only the LATEST of three overlapping loads renders", async () => {
    const { actor, gates } = gatedStaking();
    const root = document.createElement("div");
    renderStaking(root, pageCtx({ staking: actor }));

    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_A);
    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_B);
    loadFor(root, "staking-holder", "staking-load", PRINCIPAL_C);

    gates.get(PRINCIPAL_C.toText())!.resolve([position(PRINCIPAL_C, 7n)]);
    await vi.waitFor(() => {
      expect(root.querySelector('[data-testid="staking-holder-shown"]')).not.toBeNull();
    });

    // The two older loads settle late, one success + one error: both discarded.
    gates.get(PRINCIPAL_A.toText())!.resolve([position(PRINCIPAL_A, 111n)]);
    gates.get(PRINCIPAL_B.toText())!.reject(new Error("late failure"));
    await settleMicrotasks();
    expect(root.querySelector('[data-testid="staking-holder-shown"]')?.textContent).toContain(
      PRINCIPAL_C.toText(),
    );
    expect(root.textContent).toContain("7 STSH");
    expect(root.textContent).not.toContain("111 STSH");
    expect(root.textContent).not.toContain("Could not load staking data");
  });
});

describe("AC-3 vesting page fencing", () => {
  function schedule(beneficiary: Principal, totalStsh: bigint): VestingScheduleView {
    return {
      beneficiary,
      totalAmount: totalStsh * 100_000_000n,
      claimed: 0n,
      startNs: 1_700_000_000_000_000_000n,
      cliffEndNs: 1_750_000_000_000_000_000n,
      vestingEndNs: 1_900_000_000_000_000_000n,
    };
  }

  it("a stale success or error never replaces the latest result; shown principal is the resolved one", async () => {
    const gates = new Map<string, Deferred<VestingScheduleView | null>>();
    const actor: VestingReadCanister = {
      getSchedule: (beneficiary) => {
        const gate = deferred<VestingScheduleView | null>();
        gates.set(beneficiary.toText(), gate);
        return gate.promise;
      },
      claimableAmount: async () => 0n,
    };
    const root = document.createElement("div");
    renderVesting(root, pageCtx({ vesting: actor }));

    loadFor(root, "vesting-beneficiary", "vesting-load", PRINCIPAL_A); // stale, errors late
    loadFor(root, "vesting-beneficiary", "vesting-load", PRINCIPAL_B); // latest

    gates.get(PRINCIPAL_B.toText())!.resolve(schedule(PRINCIPAL_B, 1_000n));
    await vi.waitFor(() => {
      expect(root.querySelector('[data-testid="vesting-beneficiary-shown"]')).not.toBeNull();
    });
    expect(
      root.querySelector('[data-testid="vesting-beneficiary-shown"]')?.textContent,
    ).toContain(PRINCIPAL_B.toText());
    expect(root.textContent).toContain("1,000 STSH");

    gates.get(PRINCIPAL_A.toText())!.reject(new Error("slow backend failure"));
    await settleMicrotasks();
    expect(root.textContent).not.toContain("Could not load vesting data");
    expect(
      root.querySelector('[data-testid="vesting-beneficiary-shown"]')?.textContent,
    ).toContain(PRINCIPAL_B.toText());
    expect(root.textContent).toContain("1,000 STSH");
  });
});
