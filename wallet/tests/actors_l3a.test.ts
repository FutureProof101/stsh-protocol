/**
 * L3a actor adapter tests — the ICRC-2 approve/allowance half of the token
 * mutation actor and the pool's fee/status/recovery methods. Pure `wrap*Actor`
 * adapters over mock `_SERVICE` objects (no agent, no replica).
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { wrapTokenMutationActor, type ApproveRequest } from "../src/actors/token";
import { wrapPoolActor, PoolCallError } from "../src/actors/pool";

const asService = <T,>(mock: Record<string, unknown>): T => mock as unknown as T;

const OWNER = Principal.fromUint8Array(new Uint8Array(10).fill(7));
const POOL = Principal.fromUint8Array(new Uint8Array(10).fill(9));

describe("wrapTokenMutationActor.approve (L3a)", () => {
  const req: ApproveRequest = {
    spender: POOL,
    amount: 1_000n,
    expectedAllowance: 0n,
    createdAtTime: 111_222n,
    fee: 10n,
  };

  it("always sends expected_allowance ([CAS]) and created_at_time — never []", async () => {
    let captured: Record<string, unknown> = {};
    const t = wrapTokenMutationActor(
      asService({
        icrc2_approve: async (a: Record<string, unknown>) => {
          captured = a;
          return { Ok: 5n };
        },
      }),
    );
    expect(await t.approve(req)).toEqual({ kind: "ok", blockIndex: 5n });
    expect(captured.expected_allowance).toEqual([0n]);
    expect(captured.created_at_time).toEqual([111_222n]);
    expect(captured.fee).toEqual([10n]);
    expect(captured.amount).toBe(1_000n);
    expect((captured.spender as { owner: Principal }).owner.toText()).toBe(POOL.toText());
  });

  it("maps AllowanceChanged to the CAS-lost outcome with the live allowance", async () => {
    const t = wrapTokenMutationActor(
      asService({
        icrc2_approve: async () => ({ Err: { AllowanceChanged: { current_allowance: 77n } } }),
      }),
    );
    expect(await t.approve(req)).toEqual({ kind: "allowance-changed", currentAllowance: 77n });
  });

  it("maps Duplicate to confirmed success and TooOld to its own outcome", async () => {
    const dup = wrapTokenMutationActor(
      asService({ icrc2_approve: async () => ({ Err: { Duplicate: { duplicate_of: 3n } } }) }),
    );
    expect(await dup.approve(req)).toEqual({ kind: "duplicate", duplicateOf: 3n });
    const old = wrapTokenMutationActor(
      asService({ icrc2_approve: async () => ({ Err: { TooOld: null } }) }),
    );
    expect(await old.approve(req)).toEqual({ kind: "too-old" });
  });

  it("maps other rejections (BadFee, InsufficientFunds, Expired) to rejected+reason", async () => {
    const t = wrapTokenMutationActor(
      asService({ icrc2_approve: async () => ({ Err: { BadFee: { expected_fee: 20n } } }) }),
    );
    const outcome = await t.approve(req);
    expect(outcome.kind).toBe("rejected");
    expect((outcome as { reason: string }).reason).toMatch(/BadFee/);
  });

  it("allowance maps (owner -> spender) accounts and the opt expiry", async () => {
    let captured: Record<string, unknown> = {};
    const t = wrapTokenMutationActor(
      asService({
        icrc2_allowance: async (a: Record<string, unknown>) => {
          captured = a;
          return { allowance: 42n, expires_at: [9n] };
        },
      }),
    );
    expect(await t.allowance(OWNER, POOL)).toEqual({ allowance: 42n, expiresAt: 9n });
    expect((captured.account as { owner: Principal }).owner.toText()).toBe(OWNER.toText());
    expect((captured.spender as { owner: Principal }).owner.toText()).toBe(POOL.toText());
    const none = wrapTokenMutationActor(
      asService({ icrc2_allowance: async () => ({ allowance: 0n, expires_at: [] }) }),
    );
    expect(await none.allowance(OWNER, POOL)).toEqual({ allowance: 0n, expiresAt: null });
  });
});

describe("wrapPoolActor L3a reads", () => {
  it("resolves fee-param opts to the Rust launch defaults ([] -> 0 / 0 / 1 / 0)", async () => {
    const p = wrapPoolActor(
      asService({
        get_governance_fee_params: async () => ({
          shield_fee_bps: [],
          shield_flat_minimum_fee_e8s: [],
          minimum_private_credit: 0n,
          fee_model_version: [],
          params_epoch: [],
          // A-7: the exit arm of the same value-fee model. Absent opts resolve
          // to the Rust launch defaults exactly as the shield fields do.
          protocol_private_spend_fee_stsh: 0n,
          unshield_fee_bps: [],
          unshield_flat_minimum_fee_e8s: [],
        }),
      }),
    );
    expect(await p.getGovernanceFeeParams()).toEqual({
      shieldFeeBps: 0,
      shieldFlatMinimumFeeE8s: 0n,
      minimumPrivateCredit: 0n,
      feeModelVersion: 1,
      paramsEpoch: 0n,
      protocolPrivateSpendFeeStsh: 0n,
      unshieldFeeBps: 0,
      unshieldFlatMinimumFeeE8s: 0n,
    });
  });

  it("passes configured fee params through (mainnet launch shape)", async () => {
    const p = wrapPoolActor(
      asService({
        get_governance_fee_params: async () => ({
          shield_fee_bps: [25],
          shield_flat_minimum_fee_e8s: [5n],
          minimum_private_credit: 100n,
          fee_model_version: [1],
          params_epoch: [3n],
          // A-7: DISTINCT values from the shield side, so a mapping that reads
          // the wrong field — or stops reading these at all — cannot pass.
          protocol_private_spend_fee_stsh: 7n,
          unshield_fee_bps: [30],
          unshield_flat_minimum_fee_e8s: [11n],
        }),
      }),
    );
    expect(await p.getGovernanceFeeParams()).toEqual({
      shieldFeeBps: 25,
      shieldFlatMinimumFeeE8s: 5n,
      minimumPrivateCredit: 100n,
      feeModelVersion: 1,
      paramsEpoch: 3n,
      protocolPrivateSpendFeeStsh: 7n,
      // The exit arm is carried off the DID, and is NOT the shield arm: the pool
      // publishes these two fields separately and governance may move them
      // independently. A wallet that stopped reading them would fall back to 0,
      // compute a zero exit fee, and build a proof the pool refuses.
      unshieldFeeBps: 30,
      unshieldFlatMinimumFeeE8s: 11n,
    });
  });

  it("maps get_deposit_status: opt None -> null; statuses to typed kinds", async () => {
    const record = (status: Record<string, unknown>) => ({
      note_commitment: new Uint8Array(32).fill(1),
      status,
      depositor: [OWNER],
      encrypted_payload: [9, 9],
      private_balance: 100n,
      created_at_ns: 1n,
      ops_amount: 0n,
      insurance_amount: 0n,
      expected_leaf_index: [],
      finalized_at_ns: [],
    });
    const gone = wrapPoolActor(asService({ get_deposit_status: async () => [] }));
    expect(await gone.getDepositStatus(new Uint8Array(32))).toBeNull();

    const appended = wrapPoolActor(
      asService({
        get_deposit_status: async () => [record({ CommitmentAppended: { leaf_index: 4n } })],
      }),
    );
    const view = await appended.getDepositStatus(new Uint8Array(32));
    expect(view?.status).toEqual({ kind: "appended", leafIndex: 4n });
    expect(view?.encryptedPayload).toBeInstanceOf(Uint8Array);

    const accepted = wrapPoolActor(
      asService({
        get_deposit_status: async () => [
          record({ CommitmentRootAccepted: { leaf_index: 4n, root: [7, 8] } }),
        ],
      }),
    );
    const acceptedView = await accepted.getDepositStatus(new Uint8Array(32));
    expect(acceptedView?.status.kind).toBe("root-accepted");

    const pendingKinds: Array<[Record<string, unknown>, string]> = [
      [{ TransferPending: null }, "transfer-pending"],
      [{ TransferConfirmedCommitmentPending: null }, "commitment-pending"],
      [{ CommitmentPending: null }, "commitment-pending"],
      [{ CommitmentAppendInFlight: null }, "append-in-flight"],
      [{ CommitmentReconcileInFlight: null }, "append-in-flight"],
      [{ CommitmentAppendUnknown: null }, "append-unknown"],
    ];
    for (const [status, kind] of pendingKinds) {
      const p = wrapPoolActor(asService({ get_deposit_status: async () => [record(status)] }));
      expect((await p.getDepositStatus(new Uint8Array(32)))?.status.kind).toBe(kind);
    }
  });

  it("retryDepositCommitment unwraps Ok and throws PoolCallError on Err", async () => {
    const ok = wrapPoolActor(asService({ retry_deposit_commitment: async () => ({ Ok: 9n }) }));
    expect(await ok.retryDepositCommitment(new Uint8Array(32))).toBe(9n);
    const err = wrapPoolActor(
      asService({ retry_deposit_commitment: async () => ({ Err: { DepositAppendUnknown: null } }) }),
    );
    await expect(err.retryDepositCommitment(new Uint8Array(32))).rejects.toBeInstanceOf(
      PoolCallError,
    );
  });

  it("listMyActiveDeposits maps the page + exclusive cursor and encodes opt args", async () => {
    const calls: Array<[unknown, bigint]> = [];
    const record = {
      note_commitment: new Uint8Array(32).fill(2),
      status: { TransferPending: null },
      depositor: [OWNER],
      encrypted_payload: new Uint8Array([1]),
      private_balance: 100n,
      created_at_ns: 1n,
      ops_amount: 0n,
      insurance_amount: 0n,
      expected_leaf_index: [],
      finalized_at_ns: [],
    };
    const p = wrapPoolActor(
      asService({
        list_my_active_deposits: async (cursor: unknown, limit: bigint) => {
          calls.push([cursor, limit]);
          return { deposits: [record], next_cursor: [[3, 3, 3]] };
        },
      }),
    );
    const page = await p.listMyActiveDeposits(null, 100n);
    expect(calls[0][0]).toEqual([]); // opt None cursor
    expect(page.deposits[0].status.kind).toBe("transfer-pending");
    expect([...(page.nextCursor as Uint8Array)]).toEqual([3, 3, 3]);
    await p.listMyActiveDeposits(new Uint8Array([1, 2]), 50n);
    expect(calls[1][0]).toEqual([new Uint8Array([1, 2])]);
  });
});
