/**
 * Actor adapter tests (wallet-build Commit 4).
 *
 * Commit 4 is structural wiring: these drive the pure `wrap*Actor` adapters
 * with plain mock `_SERVICE` objects (no agent, no replica) — asserting result
 * envelopes are unwrapped, `PoolError` variants surface as thrown errors, blob
 * outputs normalise to `Uint8Array`, and the merkle wrapper feeds `scanPayloads`
 * unchanged. The `create*Actor` factories (which need a live agent) are only
 * smoke-checked for shape here.
 */

import { describe, expect, it } from "vitest";

import { formatVariant, toBytes } from "../src/actors/common";
import { createVetkeysActor, wrapVetkeysActor } from "../src/actors/vetkeys";
import { createMerkleActor, wrapMerkleActor } from "../src/actors/merkle";
import {
  createPoolActor,
  PoolCallError,
  wrapPoolActor,
  type ShieldDepositRequest,
} from "../src/actors/pool";
import { scanPayloads } from "../src/crypto/vetkeys";

// esbuild strips the cast; the mocks only implement the methods each wrapper calls.
const asService = <T>(mock: Record<string, unknown>): T => mock as unknown as T;

describe("common.formatVariant", () => {
  it("renders a tag-only variant as the tag", () => {
    expect(formatVariant({ Paused: null })).toBe("Paused");
  });
  it("renders a payload variant as tag + JSON with bigints as strings", () => {
    expect(formatVariant({ EscrowUnderfunded: { required: 10n, available: 2n } })).toBe(
      'EscrowUnderfunded: {"required":"10","available":"2"}',
    );
  });
});

describe("wrapVetkeysActor", () => {
  it("passes get_config through as a [domainSeparator, keyName] tuple", async () => {
    const v = wrapVetkeysActor(
      asService({ get_config: async () => ["stsh.wallet.notes.v1", "notes"] }),
    );
    expect(await v.getConfig()).toEqual(["stsh.wallet.notes.v1", "notes"]);
  });

  it("normalises the verification key (number[] -> Uint8Array)", async () => {
    const v = wrapVetkeysActor(
      asService({ get_vetkey_verification_key: async () => [1, 2, 3] }),
    );
    const key = await v.getVetkeyVerificationKey();
    expect(key).toBeInstanceOf(Uint8Array);
    expect([...key]).toEqual([1, 2, 3]);
  });

  it("unwraps get_encrypted_vetkey Ok", async () => {
    const v = wrapVetkeysActor(
      asService({
        get_encrypted_vetkey: async () => ({
          Ok: { encrypted_key: new Uint8Array([9]), remaining: 4 },
        }),
      }),
    );
    const derived = await v.getEncryptedVetkey(new Uint8Array(48));
    expect([...derived.encryptedKey]).toEqual([9]);
    // `remaining` is the §H′ allowance the canister reports; the adapter must
    // pass it through rather than dropping it on the floor.
    expect(derived.remaining).toBe(4);
  });

  it("throws on get_encrypted_vetkey Err", async () => {
    const v = wrapVetkeysActor(
      asService({ get_encrypted_vetkey: async () => ({ Err: { AnonymousCaller: null } }) }),
    );
    // The refusal is TYPED now, so the adapter must surface the variant, not a
    // string it happened to be handed: `VetkeysCallError` carries `.error` for
    // callers that branch on it, and renders human text for the message.
    await expect(v.getEncryptedVetkey(new Uint8Array(48))).rejects.toThrow(
      /Internet Identity/,
    );
  });
});

describe("wrapMerkleActor", () => {
  it("normalises get_payloads tuples and preserves leaf indices", async () => {
    const m = wrapMerkleActor(
      asService({
        get_payloads: async () => [
          [0n, [1, 2]],
          [1n, new Uint8Array([3, 4])],
        ],
      }),
    );
    const page = await m.getPayloads(0n, 500n);
    expect(page.map(([i]) => i)).toEqual([0n, 1n]);
    expect(page.every(([, b]) => b instanceof Uint8Array)).toBe(true);
    expect([...page[0][1]]).toEqual([1, 2]);
  });

  it("feeds scanPayloads unchanged (pages until a short page)", async () => {
    // Two full-ish pages then empty: mark even-indexed payloads as 'ours'.
    const pages: Array<Array<[bigint, Uint8Array]>> = [
      [
        [0n, new Uint8Array([0])],
        [1n, new Uint8Array([1])],
      ],
      [[2n, new Uint8Array([2])]],
    ];
    let call = 0;
    const m = wrapMerkleActor(
      asService({ get_payloads: async () => pages[call++] ?? [] }),
    );
    const recovered = await scanPayloads(
      (from, limit) => m.getPayloads(from, limit),
      (b) => (b[0] % 2 === 0 ? b : null),
      undefined,
      2n,
    );
    expect(recovered.map((r) => r.leafIndex)).toEqual([0n, 2n]);
  });

  it("maps opt blob (get_leaf / get_root_at_index) to Uint8Array | null", async () => {
    const present = wrapMerkleActor(
      asService({
        get_leaf: async () => [new Uint8Array([7])],
        get_root_at_index: async () => [[8]],
      }),
    );
    const absent = wrapMerkleActor(
      asService({ get_leaf: async () => [], get_root_at_index: async () => [] }),
    );
    expect([...(await present.getLeaf(0n))!]).toEqual([7]);
    expect([...(await present.getRootAtIndex(0n))!]).toEqual([8]);
    expect(await absent.getLeaf(0n)).toBeNull();
    expect(await absent.getRootAtIndex(0n)).toBeNull();
  });

  it("passes leaf_count / is_valid_anchor / get_root through", async () => {
    const m = wrapMerkleActor(
      asService({
        leaf_count: async () => 42n,
        is_valid_anchor: async () => true,
        get_root: async () => new Uint8Array([5]),
      }),
    );
    expect(await m.leafCount()).toBe(42n);
    expect(await m.isValidAnchor(new Uint8Array(32))).toBe(true);
    expect([...(await m.getRoot())]).toEqual([5]);
  });
});

describe("wrapPoolActor", () => {
  // A real 32-byte P-DOM deployment-config hash (the wallet always supplies
  // one in production — session/domainGuard.ts computes it).
  const deploymentConfigHash = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const req: ShieldDepositRequest = {
    noteCommitment: new Uint8Array(32).fill(1),
    encryptedPayload: new Uint8Array([9, 9]),
    publicAmount: 100n,
    expectedDeploymentConfigHash: deploymentConfigHash,
  };

  it("maps the camelCase request to the candid record (P-DOM hash as [hash]) and returns Ok", async () => {
    let captured: unknown;
    const p = wrapPoolActor(
      asService({
        shield_deposit: async (a: unknown) => {
          captured = a;
          return { Ok: 42n };
        },
      }),
    );
    expect(await p.shieldDeposit(req)).toBe(42n);
    expect(captured).toEqual({
      note_commitment: req.noteCommitment,
      encrypted_payload: req.encryptedPayload,
      public_amount: 100n,
      // opt blob Some(hash): the gate value the pool verifies before any await.
      expected_deployment_config_hash: [deploymentConfigHash],
    });
  });

  it("omitting the P-DOM hash encodes opt None ([]) — decode-compat skip", async () => {
    let captured: unknown;
    const p = wrapPoolActor(
      asService({
        shield_deposit: async (a: unknown) => {
          captured = a;
          return { Ok: 1n };
        },
      }),
    );
    const { expectedDeploymentConfigHash: _omitted, ...bare } = req;
    await p.shieldDeposit(bare);
    expect((captured as { expected_deployment_config_hash: unknown }).expected_deployment_config_hash).toEqual([]);
  });

  it("throws PoolCallError carrying the decoded variant on Err", async () => {
    const p = wrapPoolActor(
      asService({ shield_deposit: async () => ({ Err: { InvalidDenomination: null } }) }),
    );
    await expect(p.shieldDeposit(req)).rejects.toBeInstanceOf(PoolCallError);
    await expect(p.shieldDeposit(req)).rejects.toThrow(/InvalidDenomination/);
  });

  it("formats a payload-carrying PoolError variant", async () => {
    const p = wrapPoolActor(
      asService({
        shield_deposit: async () => ({
          Err: { BelowMinimumDeposit: { public_amount: 1n, minimum: 10n } },
        }),
      }),
    );
    await expect(p.shieldDeposit(req)).rejects.toThrow(
      /BelowMinimumDeposit: \{"public_amount":"1","minimum":"10"\}/,
    );
  });

  it("passes read queries through with normalisation", async () => {
    const p = wrapPoolActor(
      asService({
        get_denominations: async () => [1n, 10n, 100n, 1000n],
        get_pinned_vk_hash: async () => [1, 2, 3],
        get_circuit_version: async () => 3,
        get_pool_version: async () => 1,
        is_deposits_paused: async () => false,
        is_spends_paused: async () => false,
      }),
    );
    expect(await p.getDenominations()).toEqual([1n, 10n, 100n, 1000n]);
    expect(await p.getPinnedVkHash()).toBeInstanceOf(Uint8Array);
    expect(await p.getCircuitVersion()).toBe(3);
    expect(await p.getPoolVersion()).toBe(1);
    expect(await p.isDepositsPaused()).toBe(false);
    expect(await p.isSpendsPaused()).toBe(false);
  });
});

describe("common.toBytes", () => {
  it("is identity for Uint8Array and converts number[]", () => {
    const u = new Uint8Array([1]);
    expect(toBytes(u)).toBe(u);
    expect([...toBytes([2, 3])]).toEqual([2, 3]);
  });
});

describe("actor factories", () => {
  it("expose create*Actor functions", () => {
    expect(typeof createVetkeysActor).toBe("function");
    expect(typeof createMerkleActor).toBe("function");
    expect(typeof createPoolActor).toBe("function");
  });
});
