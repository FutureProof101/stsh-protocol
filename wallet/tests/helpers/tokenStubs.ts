/**
 * Shared stubs for the ICRC-2 half of `TokenMutationCanister` (L3a). The
 * Campaign-A transfer tests fake only `transfer`; these throwing stubs keep
 * those fakes honest — if a transfer-path test ever reaches approve/allowance,
 * that is a wiring bug and must fail loudly, not silently succeed.
 */

import type { AllowanceView, ApproveOutcome } from "../../src/actors/token";

export const unusedIcrc2 = {
  async approve(): Promise<ApproveOutcome> {
    throw new Error("icrc2_approve is not exercised in this test");
  },
  async allowance(): Promise<AllowanceView> {
    throw new Error("icrc2_allowance is not exercised in this test");
  },
};
