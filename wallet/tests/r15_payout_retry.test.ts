// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import { IDL } from "@dfinity/candid";
import { idlFactory } from "../../src/declarations/shielded_pool/shielded_pool.did.js";
import type { _SERVICE, PoolError } from "../../src/declarations/shielded_pool/shielded_pool.did";
import { wrapPoolActor, PoolCallError } from "../src/actors/pool";
import { reconcileSpendEntry } from "../src/ui/spendFlow";
import type { SpendJournal } from "../src/storage/spendJournal";
import type { SpendJournalEntryState } from "../src/storage/noteCache";

const errors: PoolError[] = [
  { PayoutOutcomePrivate: null },
  { PayoutExecutorBusy: null },
  { PayoutMemoKeyNotReady: null },
  { PayoutLegacyHold: null },
  { PayoutStateInvalid: null },
];
const service: IDL.ServiceClass = idlFactory({ IDL });
const retryType = service._fields.find(([name]) => name === "retry_private_spend_payout")![1];
const responseTypes = retryType.retTypes;
const entry = { spendId: "77", status: "payout-pending", inputLeafIndex: "0" } as SpendJournalEntryState;

function actorWithReply(reply: { Ok: bigint } | { Err: PoolError }) {
  // Encode/decode using the SHIPPED wallet IDL before exercising the real actor.
  const decoded = IDL.decode(responseTypes, IDL.encode(responseTypes, [reply]))[0];
  return wrapPoolActor({
    retry_private_spend_payout: vi.fn(async () => decoded),
    get_spend_status: vi.fn(async () => [{
      spend_id: 77n, status: { PayoutPending: { reason: "pending" } },
      nullifiers: [], output_commitments: [], submitter: [], created_at_ns: 1n,
    }]),
  } as unknown as _SERVICE);
}

describe("R-15 shipped payout responses and wallet journal", () => {
  it.each(errors)("decodes %j as an error and never finalizes the journal", async (error) => {
    const pool = actorWithReply({ Err: error });
    const finalizeFromSpendOk = vi.fn();
    const journal = { finalizeFromSpendOk } as unknown as SpendJournal;
    await expect(reconcileSpendEntry({ pool, journal }, entry)).rejects.toBeInstanceOf(PoolCallError);
    expect(finalizeFromSpendOk).not.toHaveBeenCalled();
  });

  it.each([0n, 987654321n])("preserves genuine owner block %s and finalizes only after update Ok", async (block) => {
    const pool = actorWithReply({ Ok: block });
    await expect(pool.retryPrivateSpendPayout(77n)).resolves.toBe(block);
    const finalizeFromSpendOk = vi.fn();
    const journal = { finalizeFromSpendOk } as unknown as SpendJournal;
    await expect(reconcileSpendEntry({ pool, journal }, entry)).resolves.toEqual({ kind: "retry-payout" });
    expect(finalizeFromSpendOk).toHaveBeenCalledTimes(1);
    expect(finalizeFromSpendOk).toHaveBeenCalledWith("77", 0n);
  });
});
