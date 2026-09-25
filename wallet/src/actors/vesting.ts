/**
 * Vesting canister actor — READ METHODS ONLY (Campaign A / Wave 1, Lane A3).
 *
 * Vesting is read-only in Wave 1 (C-A4): `claim` pre-increments before its
 * await and `claimable_amount` returns 0 for both paid and stuck-unknown
 * claims, so a wallet cannot distinguish them without a public claim-status
 * query. NO claim wrapper here until that query exists — and the UI must not
 * present `claimableAmount == 0` as proof a prior payout settled (A-S15).
 * Source: canisters/vesting/vesting.did.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

import { idlFactory } from "../../../src/declarations/vesting/vesting.did.js";
import type { _SERVICE } from "../../../src/declarations/vesting/vesting.did";

export interface VestingScheduleView {
  beneficiary: Principal;
  totalAmount: bigint;
  claimed: bigint;
  startNs: bigint;
  cliffEndNs: bigint;
  vestingEndNs: bigint;
}

export interface VestingReadCanister {
  getSchedule(beneficiary: Principal): Promise<VestingScheduleView | null>;
  /**
   * The canister-reported currently-claimable amount. NOT settlement proof: a
   * stuck-unknown claim also reports 0 (C-A4).
   */
  claimableAmount(beneficiary: Principal): Promise<bigint>;
}

/** Pure adapter: raw candid actor -> `VestingReadCanister`. Mock-testable. */
export function wrapVestingReadActor(raw: _SERVICE): VestingReadCanister {
  return {
    async getSchedule(beneficiary: Principal): Promise<VestingScheduleView | null> {
      const schedule = await raw.get_schedule(beneficiary);
      if (schedule.length !== 1) return null;
      const s = schedule[0];
      return {
        beneficiary: s.beneficiary,
        totalAmount: s.total_amount,
        claimed: s.claimed,
        startNs: s.start_ns,
        cliffEndNs: s.cliff_end_ns,
        vestingEndNs: s.vesting_end_ns,
      };
    },
    async claimableAmount(beneficiary: Principal): Promise<bigint> {
      return raw.claimable_amount(beneficiary);
    },
  };
}

/** Build a live read actor bound to `agent` and adapt it. */
export function createVestingReadActor(
  canisterId: string,
  agent: HttpAgent,
): VestingReadCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapVestingReadActor(raw);
}
