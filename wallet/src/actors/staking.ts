/**
 * Staking canister actor — READ METHODS ONLY (Campaign A / Wave 1, Lane A3).
 *
 * Wave 1 ships a read-only staking display: positions + aggregate pending
 * rewards. The `stake`/`unstake` mutations are Lane A4, HELD behind the
 * reviewed P-STK canister pre-lane (C-A1/C-A2/C-A5) — do NOT add mutation
 * wrappers here before P-STK lands. Reward claiming is disabled at source
 * (H-A1); there is deliberately no per-position `claimable` field (it does
 * not exist on the canister).
 *
 * `op_id` is surfaced on purpose (A-S15): a position with a pending
 * lock/unlock reconciliation (DEF-052) must be visibly distinct from an
 * ordinary active position. Source: canisters/staking/staking.did.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

import { idlFactory } from "../../../src/declarations/staking/staking.did.js";
import type { StakePosition, _SERVICE } from "../../../src/declarations/staking/staking.did";

export interface StakePositionView {
  positionId: bigint;
  holder: Principal;
  amount: bigint;
  lockDays: number;
  lockEndNs: bigint;
  votingWeight: bigint;
  rewardsClaimed: bigint;
  createdAtNs: bigint;
  closed: boolean;
  /** Non-null while a lock/unlock op awaits operator reconciliation (DEF-052). */
  opId: bigint | null;
}

export interface StakingReadCanister {
  getStakePositions(holder: Principal): Promise<StakePositionView[]>;
  /** Aggregate pending rewards for `holder` — display-only in Wave 1 (H-A1). */
  getPendingRewards(holder: Principal): Promise<bigint>;
}

/** Pure adapter: raw candid actor -> `StakingReadCanister`. Mock-testable. */
export function wrapStakingReadActor(raw: _SERVICE): StakingReadCanister {
  return {
    async getStakePositions(holder: Principal): Promise<StakePositionView[]> {
      const positions = await raw.get_stake_positions(holder);
      return positions.map((p: StakePosition) => ({
        positionId: p.position_id,
        holder: p.holder,
        amount: p.amount,
        lockDays: p.lock_days,
        lockEndNs: p.lock_end_ns,
        votingWeight: p.voting_weight,
        rewardsClaimed: p.rewards_claimed,
        createdAtNs: p.created_at_ns,
        closed: p.closed,
        opId: p.op_id.length === 1 ? p.op_id[0] : null,
      }));
    },
    async getPendingRewards(holder: Principal): Promise<bigint> {
      return raw.get_pending_rewards(holder);
    },
  };
}

/** Build a live read actor bound to `agent` and adapt it. */
export function createStakingReadActor(
  canisterId: string,
  agent: HttpAgent,
): StakingReadCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapStakingReadActor(raw);
}
