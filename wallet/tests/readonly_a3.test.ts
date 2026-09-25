/**
 * Lane A3 gate tests — read-only staking + vesting display (brief §4).
 *
 * Covers: adapter mapping (incl. `op_id` -> `opId`), anonymous reads with no
 * identity, NO mutation controls on either page, the `op_id != null`
 * "pending operator reconciliation" state, the aggregate-rewards
 * "claiming not yet enabled" note (H-A1), and the vesting
 * claimable-is-not-settlement-proof wording (C-A4 / A-S15).
 */

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";
import { Ed25519KeyIdentity } from "@dfinity/identity";

import { wrapStakingReadActor, type StakePositionView, type StakingReadCanister } from "../src/actors/staking";
import { wrapVestingReadActor, type VestingReadCanister } from "../src/actors/vesting";
import { resolveConfig } from "../src/session/config";
import type { Enumeration } from "../src/storage/panicWipe";
import type { AppContext } from "../src/ui/context";
import { renderStaking } from "../src/ui/pages/staking";
import { renderVesting } from "../src/ui/pages/vesting";

const asService = <T>(mock: Record<string, unknown>): T => mock as unknown as T;

const HOLDER = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(21)).getPrincipal();

// ---------------------------------------------------------------------------
// adapters
// ---------------------------------------------------------------------------

describe("actors.wrapStakingReadActor", () => {
  it("maps positions including op_id (opt nat64) -> opId | null", async () => {
    const raw = {
      get_stake_positions: async (holder: Principal) => {
        expect(holder.toText()).toBe(HOLDER.toText());
        return [
          {
            position_id: 1n,
            holder: HOLDER,
            amount: 100_00000000n,
            lock_days: 30,
            lock_end_ns: 1_800_000_000_000_000_000n,
            voting_weight: 100_00000000n,
            rewards_claimed: 0n,
            last_claim_ns: 0n,
            created_at_ns: 1_700_000_000_000_000_000n,
            closed: false,
            op_id: [] as [] | [bigint],
          },
          {
            position_id: 2n,
            holder: HOLDER,
            amount: 10_00000000n,
            lock_days: 90,
            lock_end_ns: 1_900_000_000_000_000_000n,
            voting_weight: 15_00000000n,
            rewards_claimed: 0n,
            last_claim_ns: 0n,
            created_at_ns: 1_700_000_000_000_000_000n,
            closed: false,
            op_id: [42n] as [] | [bigint],
          },
        ];
      },
      get_pending_rewards: async () => 5_00000000n,
    };
    const actor = wrapStakingReadActor(asService(raw));
    const positions = await actor.getStakePositions(HOLDER);
    expect(positions).toHaveLength(2);
    expect(positions[0].opId).toBeNull();
    expect(positions[0].amount).toBe(100_00000000n);
    expect(positions[0].lockDays).toBe(30);
    expect(positions[1].opId).toBe(42n);
    expect(await actor.getPendingRewards(HOLDER)).toBe(5_00000000n);
  });
});

describe("actors.wrapVestingReadActor", () => {
  it("maps an absent schedule to null and a present one to the view", async () => {
    const schedule = {
      beneficiary: HOLDER,
      total_amount: 1_000_00000000n,
      claimed: 250_00000000n,
      start_ns: 1_700_000_000_000_000_000n,
      cliff_end_ns: 1_750_000_000_000_000_000n,
      vesting_end_ns: 1_900_000_000_000_000_000n,
    };
    const present = wrapVestingReadActor(
      asService({
        get_schedule: async () => [schedule],
        claimable_amount: async () => 125_00000000n,
      }),
    );
    const view = await present.getSchedule(HOLDER);
    expect(view?.totalAmount).toBe(1_000_00000000n);
    expect(view?.claimed).toBe(250_00000000n);
    expect(await present.claimableAmount(HOLDER)).toBe(125_00000000n);

    const absent = wrapVestingReadActor(
      asService({ get_schedule: async () => [], claimable_amount: async () => 0n }),
    );
    expect(await absent.getSchedule(HOLDER)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// pages
// ---------------------------------------------------------------------------

function pageCtx(overrides: {
  staking?: StakingReadCanister;
  vesting?: VestingReadCanister;
  principal?: Principal | null;
}): AppContext {
  const noop = async (): Promise<void> => undefined;
  return {
    config: resolveConfig({}),
    policy: { kind: "production", iiUrl: undefined, derivationOrigin: undefined },
    state: {
      principal: overrides.principal ?? null,
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
        ({ getStakePositions: async () => [], getPendingRewards: async () => 0n } satisfies StakingReadCanister),
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

function position(overrides: Partial<StakePositionView>): StakePositionView {
  return {
    positionId: 1n,
    holder: HOLDER,
    amount: 100_00000000n,
    lockDays: 30,
    lockEndNs: 1_800_000_000_000_000_000n,
    votingWeight: 100_00000000n,
    rewardsClaimed: 0n,
    createdAtNs: 1_700_000_000_000_000_000n,
    closed: false,
    opId: null,
    ...overrides,
  };
}

describe("staking page (read-only)", () => {
  it("renders positions anonymously with op_id shown as pending reconciliation, no mutation controls", async () => {
    const ctx = pageCtx({
      principal: null, // anonymous read
      staking: {
        getStakePositions: async () => [
          position({ positionId: 1n }),
          position({ positionId: 2n, opId: 42n }),
          position({ positionId: 3n, closed: true }),
        ],
        getPendingRewards: async () => 5_00000000n,
      },
    });
    const root = document.createElement("div");
    renderStaking(root, ctx);

    // Anonymous: the holder input starts empty; any principal can be viewed.
    const input = root.querySelector<HTMLInputElement>('[data-testid="staking-holder"]');
    expect(input?.value).toBe("");
    input!.value = HOLDER.toText();
    root.querySelector<HTMLButtonElement>('[data-testid="staking-load"]')!.click();

    await vi.waitFor(() => {
      expect(root.querySelector('[data-testid="position-status-2"]')).not.toBeNull();
    });

    // op_id != null is visibly a reconciliation state, NOT an ordinary position.
    expect(root.querySelector('[data-testid="position-status-2"]')?.textContent).toMatch(
      /pending operator reconciliation/i,
    );
    expect(root.querySelector('[data-testid="position-status-2"]')?.textContent).not.toMatch(
      /^Active$/,
    );
    expect(root.querySelector('[data-testid="position-status-1"]')?.textContent).toBe("Active");
    expect(root.querySelector('[data-testid="position-status-3"]')?.textContent).toBe("Closed");

    // Aggregate rewards are display-only (H-A1).
    expect(root.querySelector('[data-testid="pending-rewards"]')?.textContent).toMatch(
      /claiming is not yet enabled/i,
    );

    // No mutation controls anywhere: the only button is the read-only loader.
    const buttons = Array.from(root.querySelectorAll("button")).map((b) => b.textContent ?? "");
    expect(buttons).toEqual(["Load positions"]);
    expect(buttons.some((t) => /stake|unstake|claim/i.test(t))).toBe(false);
  });

  it("prefills the logged-in principal for convenience", () => {
    const ctx = pageCtx({ principal: HOLDER });
    const root = document.createElement("div");
    renderStaking(root, ctx);
    expect(root.querySelector<HTMLInputElement>('[data-testid="staking-holder"]')?.value).toBe(
      HOLDER.toText(),
    );
  });
});

describe("vesting page (read-only)", () => {
  it("shows the schedule with claimable NOT presented as settlement proof, and no claim control", async () => {
    const ctx = pageCtx({
      principal: HOLDER,
      vesting: {
        getSchedule: async () => ({
          beneficiary: HOLDER,
          totalAmount: 1_000_00000000n,
          claimed: 250_00000000n,
          startNs: 1_700_000_000_000_000_000n,
          cliffEndNs: 1_750_000_000_000_000_000n,
          vestingEndNs: 1_900_000_000_000_000_000n,
        }),
        claimableAmount: async () => 0n,
      },
    });
    const root = document.createElement("div");
    renderVesting(root, ctx);
    root.querySelector<HTMLButtonElement>('[data-testid="vesting-load"]')!.click();

    await vi.waitFor(() => {
      expect(root.querySelector('[data-testid="vesting-claimable"]')).not.toBeNull();
    });

    // A zero claimable figure explains itself (C-A4): not settlement proof.
    const claimable = root.querySelector('[data-testid="vesting-claimable"]')?.textContent ?? "";
    expect(claimable).toMatch(/canister-reported/i);
    expect(claimable).toMatch(/does not confirm prior payout settlement/i);

    // No claim control; the only button is the read-only loader.
    const buttons = Array.from(root.querySelectorAll("button")).map((b) => b.textContent ?? "");
    expect(buttons).toEqual(["Load schedule"]);
  });

  it("says so plainly when there is no schedule", async () => {
    const ctx = pageCtx({ principal: HOLDER });
    const root = document.createElement("div");
    renderVesting(root, ctx);
    root.querySelector<HTMLButtonElement>('[data-testid="vesting-load"]')!.click();
    await vi.waitFor(() => {
      expect(root.textContent).toMatch(/No vesting schedule for this principal/);
    });
  });
});
