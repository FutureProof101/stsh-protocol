/**
 * L3a shield-flow tests (brief §6) — the orchestration battery.
 *
 * Real components: note crypto (Poseidon WASM), IBE payload crypto (an offline
 * vetKD fixture — master scalar x, dpk = x·G2, vetKey = x·H1(dpk, identity) —
 * round-tripping through the REAL @dfinity/vetkeys IBE), the encrypted shield
 * journal over the REAL PrincipalNoteCache (Argon2id + CAS), and the real
 * deployment-config hash. Mocked: the canister actors (scripted outcomes +
 * call logs) and the raw key fetch (the `fetchKeys` seam INSIDE the C-VK-3
 * guard sandwich).
 *
 * Every lane non-negotiable is asserted here:
 *  - journal persisted before the first effectful call
 *  - fee snapshot fail-closed (query failure aborts; a valid 0 proceeds;
 *    unknown fee-model version aborts; post-approve staleness aborts)
 *  - icrc2_approve uses the expected-allowance CAS, never blind
 *  - allowance covers Σ(value + shield_fee + ledger_fee) exactly
 *  - C-VK-3 binding guard runs pre AND post key fetch
 *  - reconcile checks pool status before resubmitting (no double-deposit)
 *  - shield enforces fixed denominations
 *  - fresh-device recovery from the P-REC index (L0-G)
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { bls12_381 } from "@noble/curves/bls12-381";
import { augmentedHashToG1, DerivedPublicKey, VetKey } from "@dfinity/vetkeys";

import { initPoseidon } from "../src/crypto/poseidon";
import {
  createShieldNote,
  deriveNoteSecretsV2,
  noteToBytesV2,
} from "../src/crypto/notes";
import { FeeModelUnsupportedError, ShieldPrecheckError } from "../src/crypto/fees";
import {
  encryptNotePayload,
  masterNoteSecret,
  vetkdInput,
  type VetkeysCanister,
} from "../src/crypto/vetkeys";
import type {
  ActiveDepositsPageView,
  PoolCanister,
  PoolPendingDeposit,
  ShieldFeeParams,
} from "../src/actors/pool";
import { PoolCallError } from "../src/actors/pool";
import type {
  AllowanceView,
  ApproveOutcome,
  ApproveRequest,
  TokenCanister,
  TokenMutationCanister,
} from "../src/actors/token";
import { resolveConfig } from "../src/session/config";
import { computeDeploymentConfigHash } from "../src/session/domainGuard";
import { ShieldJournal, type ShieldJournalApi } from "../src/storage/journal";
import {
  PrincipalNoteCache,
  CacheSessionStaleError,
  type PrincipalCacheStore,
} from "../src/storage/noteCache";
import { bytesToHex } from "../src/storage/transferJournal";
import {
  abandonAmbiguousEntry,
  cancelPlannedShield,
  reconcileShieldJournal,
  revokeShieldAllowance,
  runShieldFlow,
  ShieldAbortError,
  type ShieldFlowDeps,
} from "../src/ui/shieldFlow";
import { memoryHarness, testBinding } from "./helpers/cacheL4";

// ── Poseidon (wasm) init ─────────────────────────────────────────────────────

const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

// ── Offline vetKD fixture (REAL BLS/IBE crypto, test-only master scalar) ─────

const MASTER_X = 0x517f0da4cf3d70b1n;
const DPK = DerivedPublicKey.deserialize(
  bls12_381.G2.ProjectivePoint.BASE.multiply(MASTER_X).toRawBytes(true),
);
function vetKeyFor(principal: Principal): VetKey {
  return new VetKey(augmentedHashToG1(DPK, vetkdInput(principal)).multiply(MASTER_X));
}

// ── Principals + config ──────────────────────────────────────────────────────

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x11));
const POOL = Principal.fromUint8Array(new Uint8Array(10).fill(0xab));
const TOKEN = Principal.fromUint8Array(new Uint8Array(10).fill(0xcd));
const MERKLE = Principal.fromUint8Array(new Uint8Array(10).fill(0xef));
const NULLIFIER = Principal.fromUint8Array(new Uint8Array(10).fill(0x01));

function testConfig(overrides: Record<string, string | undefined> = {}) {
  return resolveConfig({
    VITE_POOL_CANISTER_ID: POOL.toText(),
    VITE_TOKEN_CANISTER_ID: TOKEN.toText(),
    VITE_MERKLE_CANISTER_ID: MERKLE.toText(),
    VITE_NULLIFIER_CANISTER_ID: NULLIFIER.toText(),
    VITE_FROZEN_POOL_CANISTER_ID: POOL.toText(),
    VITE_VETKD_KEY_NAME: "test_key_1",
    ...overrides,
  });
}

const ZERO_FEES: ShieldFeeParams = {
  shieldFeeBps: 0,
  shieldFlatMinimumFeeE8s: 0n,
  minimumPrivateCredit: 0n,
  feeModelVersion: 1,
  paramsEpoch: 0n,
  protocolPrivateSpendFeeStsh: 0n,
  // A-7: the exit arm of the same value-fee model; zero here keeps these
  // shield-side fixtures at their existing behaviour.
  unshieldFeeBps: 0,
  unshieldFlatMinimumFeeE8s: 0n,
};

const STSH = 100_000_000n;
/// A6.6: the launch ladder's floor rung is 1,000 STSH, so every shieldable
/// amount in this suite is a multiple of it. The test shapes (1 / 10 / 11 /
/// 100 / 101 / 111 rungs) are unchanged — only the unit of account moved.
const RUNG = 1_000n * STSH;
const LEDGER_FEE = 10_000n;

// ── Scripted actors with call logs ───────────────────────────────────────────

interface Harness {
  deps: ShieldFlowDeps;
  log: string[];
  journal: ShieldJournalApi;
  binding: ReturnType<typeof testBinding>;
  approves: ApproveRequest[];
  deposits: Array<{
    noteCommitment: Uint8Array;
    encryptedPayload: Uint8Array;
    publicAmount: bigint;
    expectedDeploymentConfigHash?: Uint8Array;
  }>;
  /** Mutable behaviour knobs the tests flip mid-flow. */
  knobs: {
    ledgerFee: () => Promise<bigint>;
    feeParams: () => Promise<ShieldFeeParams>;
    approve: (req: ApproveRequest) => Promise<ApproveOutcome>;
    allowance: () => Promise<AllowanceView>;
    shieldDeposit: (index: number) => Promise<bigint>;
    depositStatus: (commitment: Uint8Array) => Promise<PoolPendingDeposit | null>;
    retryDeposit: (commitment: Uint8Array) => Promise<bigint>;
    listActive: () => Promise<ActiveDepositsPageView>;
    vetkdConfig: () => Promise<[string, string]>;
  };
}

function unimplemented(name: string): never {
  throw new Error(`${name} is not scripted in this test`);
}

async function makeHarness(
  policyKind: "local" | "production" = "local",
  config = testConfig(),
  sharedStore?: PrincipalCacheStore,
): Promise<Harness> {
  const log: string[] = [];
  const approves: ApproveRequest[] = [];
  const deposits: Harness["deposits"] = [];

  const knobs: Harness["knobs"] = {
    ledgerFee: async () => LEDGER_FEE,
    feeParams: async () => ZERO_FEES,
    approve: async () => ({ kind: "ok", blockIndex: 1n }),
    allowance: async () => ({ allowance: 0n, expiresAt: null }),
    shieldDeposit: async (i) => BigInt(100 + i),
    depositStatus: async () => null,
    retryDeposit: async () => unimplemented("retryDepositCommitment"),
    listActive: async () => ({ deposits: [], nextCursor: null }),
    vetkdConfig: async () => ["stsh.wallet.notes.v1", "test_key_1"],
  };

  const tokenRead: TokenCanister = {
    balanceOf: async () => 0n,
    metadata: async () => ({ symbol: "STSH", decimals: 8, fee: LEDGER_FEE }),
    fee: async () => {
      log.push("wire:icrc1_fee");
      return knobs.ledgerFee();
    },
  };
  const tokenMutation: TokenMutationCanister = {
    transfer: async () => unimplemented("transfer"),
    approve: async (req) => {
      log.push("wire:icrc2_approve");
      approves.push(req);
      return knobs.approve(req);
    },
    allowance: async () => {
      log.push("wire:icrc2_allowance");
      return knobs.allowance();
    },
  };
  const pool: PoolCanister = {
    shieldDeposit: async (req) => {
      log.push("wire:shield_deposit");
      deposits.push(req);
      return knobs.shieldDeposit(deposits.length - 1);
    },
    getDenominations: async () => unimplemented("getDenominations"),
    getPinnedVkHash: async () => unimplemented("getPinnedVkHash"),
    getCircuitVersion: async () => unimplemented("getCircuitVersion"),
    getPoolVersion: async () => unimplemented("getPoolVersion"),
    isDepositsPaused: async () => false,
    isSpendsPaused: async () => false,
    getGovernanceFeeParams: async () => {
      log.push("wire:get_governance_fee_params");
      return knobs.feeParams();
    },
    getDepositStatus: async (c) => {
      log.push(`wire:get_deposit_status:${bytesToHex(c).slice(0, 8)}`);
      return knobs.depositStatus(c);
    },
    retryDepositCommitment: async (c) => {
      log.push("wire:retry_deposit_commitment");
      return knobs.retryDeposit(c);
    },
    listMyActiveDeposits: async () => {
      log.push("wire:list_my_active_deposits");
      return knobs.listActive();
    },
    privateSpend: async () => unimplemented("privateSpend"),
    retryPrivateSpendPayout: async () => unimplemented("retryPrivateSpendPayout"),
    getSpendStatus: async () => unimplemented("getSpendStatus"),
    getAcceptedRootHead: async () => unimplemented("getAcceptedRootHead"),
    getDeploymentAttestation: async () => unimplemented("getDeploymentAttestation"),
    getSecurityEpoch: async () => unimplemented("getSecurityEpoch"),
    listMyActiveSpends: async () => unimplemented("listMyActiveSpends"),
  };
  const vetkeys: VetkeysCanister = {
    getVetkeyVerificationKey: async () => unimplemented("getVetkeyVerificationKey"),
    getEncryptedVetkey: async () => unimplemented("getEncryptedVetkey"),
    registerDevice: async () => unimplemented("registerDevice"),
    revokeDevice: async () => unimplemented("revokeDevice"),
    getWrappedSecret: async () => unimplemented("getWrappedSecret"),
    listDevices: async () => unimplemented("listDevices"),
    replaceEnvelope: async () => unimplemented("replaceEnvelope"),
    getConfig: async () => {
      log.push("wire:vetkd_get_config");
      return knobs.vetkdConfig();
    },
  };

  const store = sharedStore ?? (await memoryHarness()).store;
  const binding = testBinding(USER.toText());
  const cache = await PrincipalNoteCache.open(store, "pass", binding);
  const realJournal = new ShieldJournal(cache);
  // Delegating wrapper so the call log can prove the persisted-BEFORE-wire
  // orderings (journal-before-submit, pre-wire approve/dispatch markers) —
  // each entry is logged AFTER its durable write resolved.
  const journal: ShieldJournalApi = {
    read: () => realJournal.read(),
    beginBatch: async (entries, approval) => {
      await realJournal.beginBatch(entries, approval);
      log.push("journal:beginBatch");
    },
    setApprovalStatus: async (f, t, p) => {
      await realJournal.setApprovalStatus(f, t, p);
      log.push(`journal:approval:${t}`);
    },
    transitionEntry: (c, f, t, p) => realJournal.transitionEntry(c, f, t, p),
    claimEntryDispatch: async (c, atNs) => {
      const claimed = await realJournal.claimEntryDispatch(c, atNs);
      if (claimed) log.push("journal:dispatch-claimed");
      return claimed;
    },
    recordDepositSuccess: (c) => realJournal.recordDepositSuccess(c),
    notePoolStatus: (c, s) => realJournal.notePoolStatus(c, s),
    importEntry: (e) => realJournal.importEntry(e),
  };

  const deps: ShieldFlowDeps = {
    policyKind,
    config,
    principal: USER,
    tokenRead,
    tokenMutation,
    pool,
    vetkeys,
    journal,
    nowNs: () => 1_000_000_000n,
    fetchKeys: async (_canister, principal) => {
      log.push("fetch:vetkey");
      return { vetKey: vetKeyFor(principal), verificationKey: DPK, remaining: 4 };
    },
  };
  return { deps, log, journal, binding, approves, deposits, knobs };
}

const EXPECTED_HASH = computeDeploymentConfigHash({
  pool: POOL,
  token: TOKEN,
  merkle: MERKLE,
  nullifier: NULLIFIER,
});

// ── The flow ─────────────────────────────────────────────────────────────────

describe("runShieldFlow — happy path (zero launch fees)", () => {
  it("decomposes, journals before submitting, CAS-approves the exact Σ, deposits with the P-DOM hash", async () => {
    const h = await makeHarness();
    // Pool reports root-accepted on the post-batch poll — terminal success.
    h.knobs.depositStatus = async (c) => acceptedRecord(c);

    const summary = await runShieldFlow(h.deps, 11n * RUNG); // -> [10, 1] rungs (10,000 + 1,000 STSH)

    // Journal-before-submit: the atomic batch write resolves BEFORE any
    // effectful wire call (approve/deposit).
    const journalAt = h.log.indexOf("journal:beginBatch");
    const approveAt = h.log.indexOf("wire:icrc2_approve");
    const depositAt = h.log.indexOf("wire:shield_deposit");
    expect(journalAt).toBeGreaterThan(-1);
    expect(approveAt).toBeGreaterThan(journalAt);
    expect(depositAt).toBeGreaterThan(approveAt);

    // Pre-wire attempt markers (finding 2): the approval's ambiguity marker is
    // durably persisted BEFORE the approve wire call, and each entry's
    // dispatch marker BEFORE its shield_deposit wire call.
    const approvalUnknownAt = h.log.indexOf("journal:approval:unknown");
    expect(approvalUnknownAt).toBeGreaterThan(-1);
    expect(approvalUnknownAt).toBeLessThan(approveAt);
    const dispatchedAt = h.log.indexOf("journal:dispatch-claimed");
    expect(dispatchedAt).toBeGreaterThan(-1);
    expect(dispatchedAt).toBeLessThan(depositAt);

    // C-VK-3 sandwich: config asserted before AND after the key fetch.
    const fetchAt = h.log.indexOf("fetch:vetkey");
    const configCalls = h.log
      .map((entry, i) => [entry, i] as const)
      .filter(([entry]) => entry === "wire:vetkd_get_config")
      .map(([, i]) => i);
    expect(configCalls.length).toBeGreaterThanOrEqual(2);
    expect(configCalls[0]).toBeLessThan(fetchAt);
    expect(configCalls[1]).toBeGreaterThan(fetchAt);

    // Exact allowance: Σ(denom + protoFee(0) + ledgerFee) with the CAS guard.
    expect(h.approves).toHaveLength(1);
    expect(h.approves[0].amount).toBe(10n * RUNG + RUNG + 2n * LEDGER_FEE);
    expect(h.approves[0].expectedAllowance).toBe(0n);
    expect(h.approves[0].createdAtTime).toBe(1_000_000_000n);
    expect(h.approves[0].spender.toText()).toBe(POOL.toText());

    // Each deposit carries the exact wallet-computed deployment-config hash.
    const expectedHash = await EXPECTED_HASH;
    expect(h.deposits).toHaveLength(2);
    for (const d of h.deposits) {
      expect(bytesToHex(d.expectedDeploymentConfigHash as Uint8Array)).toBe(
        bytesToHex(expectedHash),
      );
    }
    expect(h.deposits.map((d) => d.publicAmount)).toEqual([10n * RUNG, RUNG]);

    // Terminal: the poll saw root-accepted.
    expect(summary).toMatchObject({ accepted: 2, deposited: 0, unknown: 0, planned: 0, failed: 0 });
  });

  it("a bare shield_deposit Ok is NOT terminal — appended stays 'deposited'", async () => {
    const h = await makeHarness();
    h.knobs.depositStatus = async (c) => appendedRecord(c);
    const summary = await runShieldFlow(h.deps, RUNG);
    expect(summary).toMatchObject({ accepted: 0, deposited: 1 });
    const state = await h.journal.read();
    expect(state.entries[0]).toMatchObject({ status: "deposited", poolStatus: "appended" });
    // The status WAS queried after the Ok (never trusted bare).
    expect(h.log.some((l) => l.startsWith("wire:get_deposit_status"))).toBe(true);
  });

  it("computes nonzero per-denomination fees exactly (25 bps + flat floor)", async () => {
    const h = await makeHarness();
    const params: ShieldFeeParams = {
      shieldFeeBps: 25,
      shieldFlatMinimumFeeE8s: 500_000n,
      minimumPrivateCredit: 0n,
      feeModelVersion: 1,
      paramsEpoch: 1n,
      protocolPrivateSpendFeeStsh: 0n,
      unshieldFeeBps: 0,
      unshieldFlatMinimumFeeE8s: 0n,
    };
    h.knobs.feeParams = async () => params;
    h.knobs.depositStatus = async (c) => acceptedRecord(c);
    await runShieldFlow(h.deps, 101n * RUNG); // -> [100, 1] rungs (100,000 + 1,000 STSH)
    // fee(100,000 STSH) = max(0.005, 100_000*25/10000 = 250) = 250 STSH = 25_000_000_000
    // fee(1,000 STSH)   = max(0.005, 1_000*25/10000 = 2.5) = 2.5 STSH = 250_000_000
    const expected =
      100n * RUNG + 25_000_000_000n + LEDGER_FEE + (RUNG + 250_000_000n + LEDGER_FEE);
    expect(h.approves[0].amount).toBe(expected);
  });
});

describe("runShieldFlow — fail-closed guards", () => {
  it("rejects a non-decomposable amount before any guard, journal write or wire call", async () => {
    const h = await makeHarness();
    await expect(runShieldFlow(h.deps, STSH / 2n)).rejects.toThrow(/not decomposable/);
    expect(h.log).toEqual([]);
    expect((await h.journal.read()).entries).toEqual([]);
  });

  it("fee-query failure aborts (stage fee-snapshot) with nothing persisted or approved", async () => {
    const h = await makeHarness();
    h.knobs.ledgerFee = async () => {
      throw new Error("ledger unreachable");
    };
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("fee-snapshot");
    expect(h.approves).toHaveLength(0);
    expect(h.deposits).toHaveLength(0);
    expect((await h.journal.read()).entries).toEqual([]);
  });

  it("an unknown fee-model version aborts — the wallet never guesses a fee", async () => {
    const h = await makeHarness();
    h.knobs.feeParams = async () => ({ ...ZERO_FEES, feeModelVersion: 2 });
    await expect(runShieldFlow(h.deps, RUNG)).rejects.toBeInstanceOf(FeeModelUnsupportedError);
    expect(h.approves).toHaveLength(0);
    expect((await h.journal.read()).entries).toEqual([]);
  });

  it("a denomination below minimum_private_credit aborts locally (typed)", async () => {
    const h = await makeHarness();
    h.knobs.feeParams = async () => ({ ...ZERO_FEES, minimumPrivateCredit: 2n * RUNG });
    await expect(runShieldFlow(h.deps, RUNG)).rejects.toBeInstanceOf(ShieldPrecheckError);
    expect(h.approves).toHaveLength(0);
  });

  it("fee drift between snapshot and submission aborts AFTER approve, BEFORE any deposit", async () => {
    const h = await makeHarness();
    let feeCalls = 0;
    h.knobs.feeParams = async () => {
      feeCalls += 1;
      return feeCalls === 1 ? ZERO_FEES : { ...ZERO_FEES, paramsEpoch: 9n };
    };
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("fee-stale");
    expect(h.approves).toHaveLength(1); // approve happened
    expect(h.deposits).toHaveLength(0); // no deposit submitted on a stale basis
    const state = await h.journal.read();
    expect(state.entries[0].status).toBe("planned"); // resubmittable
    expect(state.approval?.status).toBe("approved");
  });

  it("C-VK-3 pre-fetch config mismatch hard-aborts: no key fetch, no journal, no wire", async () => {
    const h = await makeHarness();
    h.knobs.vetkdConfig = async () => ["stsh.wallet.notes.v1", "key_1"]; // wrong for a local test build
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("vetkd-config");
    expect(h.log).not.toContain("fetch:vetkey");
    expect(h.approves).toHaveLength(0);
    expect((await h.journal.read()).entries).toEqual([]);
  });

  it("C-VK-3 post-fetch config change hard-aborts before any derived material is used", async () => {
    const h = await makeHarness();
    let calls = 0;
    h.knobs.vetkdConfig = async () => {
      calls += 1;
      return calls === 1
        ? ["stsh.wallet.notes.v1", "test_key_1"]
        : ["stsh.wallet.notes.v1", "key_1"]; // swapped mid-fetch
    };
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("vetkd-config");
    expect(h.log).toContain("fetch:vetkey"); // fetched, then failed closed
    expect(h.approves).toHaveLength(0);
    expect((await h.journal.read()).entries).toEqual([]);
  });

  it("a local build without an explicit vetKD key name refuses to derive keys", async () => {
    const h = await makeHarness("local", testConfig({ VITE_VETKD_KEY_NAME: undefined }));
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("vetkd-config");
    expect(h.log).not.toContain("fetch:vetkey");
  });

  it("incomplete wiring (no nullifier id) fails the deployment binding closed", async () => {
    const h = await makeHarness("local", testConfig({ VITE_NULLIFIER_CANISTER_ID: "" }));
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("deployment-binding");
    expect(h.approves).toHaveLength(0);
  });

  it("production: a runtime pool differing from the ceremony-frozen pool disables shield", async () => {
    const other = Principal.fromUint8Array(new Uint8Array(10).fill(0x77));
    const h = await makeHarness(
      "production",
      testConfig({ VITE_FROZEN_POOL_CANISTER_ID: other.toText() }),
    );
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("deployment-binding");
    expect((err as ShieldAbortError).message).toMatch(/ceremony-frozen/);
  });

  it("a locked cache blocks the shield before any effectful call (§1.1)", async () => {
    const h = await makeHarness();
    h.binding.invalidate(); // logout/expiry
    await expect(runShieldFlow(h.deps, RUNG)).rejects.toBeInstanceOf(CacheSessionStaleError);
    expect(h.approves).toHaveLength(0);
    expect(h.deposits).toHaveLength(0);
  });
});

describe("runShieldFlow — approve outcomes", () => {
  it("AllowanceChanged (CAS lost) fails the batch definitively — nothing submitted", async () => {
    const h = await makeHarness();
    h.knobs.approve = async () => ({ kind: "allowance-changed", currentAllowance: 55n });
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("approve");
    expect(h.deposits).toHaveLength(0);
    const state = await h.journal.read();
    expect(state.approval?.status).toBe("failed");
    expect(state.entries[0].status).toBe("failed");
  });

  it("a transport-unknown approve leaves the persisted envelope retryable, marker written pre-wire", async () => {
    const h = await makeHarness();
    h.knobs.approve = async () => {
      throw new Error("connection reset");
    };
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("approve-unknown");
    const state = await h.journal.read();
    expect(state.approval?.status).toBe("unknown");
    expect(state.entries[0].status).toBe("planned");
    // Required regression (finding 2): the ambiguity marker was persisted
    // BEFORE the wire dispatch — a crash mid-call cannot leave a live
    // allowance recorded as merely 'planned'.
    expect(h.log.indexOf("journal:approval:unknown")).toBeLessThan(
      h.log.indexOf("wire:icrc2_approve"),
    );
  });

  it("required regression: an approval crash AFTER dispatch is recoverable AND revocable", async () => {
    // The crash shape: the wire call went out, the response never came back,
    // the app died. On restart the journal holds approval 'unknown' with the
    // full envelope. The original approve DID execute on the ledger.
    const h = await makeHarness();
    h.knobs.approve = async () => {
      throw new Error("crashed mid-call");
    };
    await runShieldFlow(h.deps, RUNG).catch(() => {});
    expect((await h.journal.read()).approval?.status).toBe("unknown");

    // Recovery: the byte-identical retry dedups to Duplicate -> approved.
    const total = BigInt((await h.journal.read()).approval!.totalAllowance);
    h.knobs.approve = async () => ({ kind: "duplicate", duplicateOf: 7n });
    h.knobs.depositStatus = async (c) => acceptedRecord(c);
    h.knobs.shieldDeposit = async () => 1n;
    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(report.summary.accepted).toBe(1);

    // Revocable: with every intent settled, the leftover allowance revokes.
    h.knobs.allowance = async () => ({ allowance: total, expiresAt: null });
    h.knobs.approve = async (req) => {
      expect(req.amount).toBe(0n);
      expect(req.expectedAllowance).toBe(total);
      return { kind: "ok", blockIndex: 9n };
    };
    expect(await revokeShieldAllowance(h.deps)).toEqual({ kind: "revoked" });
  });
});

describe("runShieldFlow — mid-batch failures", () => {
  it("Ok, transport-throw, (stop): deposited / unknown(dispatched) / planned — reconcile resubmits ONLY the never-dispatched entry", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async (i) => {
      if (i === 1) throw new Error("connection lost mid-call");
      return BigInt(200 + i);
    };
    const summary = await runShieldFlow(h.deps, 111n * RUNG); // -> [100, 10, 1] rungs
    expect(summary).toMatchObject({ deposited: 1, unknown: 1, planned: 1 });
    expect(h.deposits).toHaveLength(2); // the third was never submitted
    const midState = await h.journal.read();
    // The transport-lost entry carries the pre-wire dispatch marker; the
    // stopped third entry was never dispatched.
    expect(midState.entries[1]).toMatchObject({ status: "unknown" });
    expect(midState.entries[1].dispatchedAtNs).toBeDefined();
    expect(midState.entries[2].dispatchedAtNs).toBeUndefined();

    // Reconcile with resubmission + no pool records: ONLY the never-dispatched
    // planned entry is submitted (fund-safety finding 1) — the dispatched
    // ambiguous entry is surfaced, never re-pulled.
    h.knobs.shieldDeposit = async () => 300n;
    h.knobs.depositStatus = async () => null;
    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(h.deposits).toHaveLength(3); // exactly ONE more (the planned entry)
    expect(report.summary.deposited).toBe(2);
    expect(report.summary.planned).toBe(0);
    expect(report.summary.unknown).toBe(1); // the ambiguous entry remains
    expect(report.attention.some((a) => /NEVER auto-resubmitted/.test(a))).toBe(true);
  });

  it("a decoded rejection with a live pool record goes to 'unknown' (funds may have moved)", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new PoolCallError("shield_deposit", { Paused: null } as never);
    };
    h.knobs.depositStatus = async (c) => transferPendingRecord(c);
    const summary = await runShieldFlow(h.deps, RUNG);
    expect(summary).toMatchObject({ unknown: 1 });
    const state = await h.journal.read();
    expect(state.entries[0]).toMatchObject({ status: "unknown", poolStatus: "transfer-pending" });
  });

  it("a decoded rejection with NO pool record is a definite failure", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new PoolCallError("shield_deposit", { InvalidDenomination: null } as never);
    };
    h.knobs.depositStatus = async () => null;
    const summary = await runShieldFlow(h.deps, RUNG);
    expect(summary).toMatchObject({ failed: 1 });
  });
});

describe("reconcileShieldJournal", () => {
  it("does NOT resubmit when a pool record exists — the status check is the gate", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new Error("connection lost");
    };
    await runShieldFlow(h.deps, RUNG); // -> one 'unknown' entry
    expect(h.deposits).toHaveLength(1);

    // The pool DID record the deposit (the lost call landed): reconcile must
    // not submit a second time.
    h.knobs.depositStatus = async (c) => appendedRecord(c);
    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(h.deposits).toHaveLength(1); // NO second shield_deposit
    expect(report.summary.deposited).toBe(1);
  });

  it("NEVER resubmits an entry that received an Ok, even when its pool record vanished (pruned)", async () => {
    const h = await makeHarness();
    h.knobs.depositStatus = async (c) => acceptedRecord(c);
    await runShieldFlow(h.deps, RUNG); // Ok + root-accepted -> terminal
    // Force a non-terminal shape with a blockIndex: re-run with only Ok.
    const h2 = await makeHarness();
    await runShieldFlow(h2.deps, RUNG); // depositStatus null -> stays 'deposited'
    expect((await h2.journal.read()).entries[0]).toMatchObject({ status: "deposited" });
    expect(h2.deposits).toHaveLength(1);

    // The record now reads as GONE (e.g. pruned after acceptance): reconcile
    // with resubmission must NOT re-pull — the entry has a blockIndex.
    h2.knobs.depositStatus = async () => null;
    const report = await reconcileShieldJournal(h2.deps, { resubmit: true });
    expect(h2.deposits).toHaveLength(1); // no second shield_deposit, ever
    expect(report.attention.some((a) => /never resubmitted/.test(a))).toBe(true);
    expect((await h2.journal.read()).entries[0].status).toBe("deposited");
  });

  it("rolls a definite approve failure forward onto stranded planned entries", async () => {
    // Reproduce the crash window between failBatchAtApprove's approval write
    // and its per-entry writes: approval 'failed', entries still 'planned'.
    const h = await makeHarness();
    h.knobs.approve = async () => {
      throw new Error("connection reset");
    };
    await runShieldFlow(h.deps, RUNG).catch(() => {}); // approval -> unknown, entry planned
    await h.journal.setApprovalStatus(["unknown"], "failed", { failureReason: "test" });
    expect((await h.journal.read()).entries[0].status).toBe("planned");

    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(report.summary.failed).toBe(1);
    expect(report.summary.planned).toBe(0);
    // The batch slot is free again: a new shield may begin.
    h.knobs.approve = async () => ({ kind: "ok", blockIndex: 2n });
    h.knobs.depositStatus = async (c) => acceptedRecord(c);
    await expect(runShieldFlow(h.deps, RUNG)).resolves.toMatchObject({ accepted: 1 });
  });

  it("drives commitment-pending through retry_deposit_commitment (§6 table)", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new Error("connection lost");
    };
    await runShieldFlow(h.deps, RUNG);

    let retried = false;
    h.knobs.depositStatus = async (c) =>
      retried ? appendedRecord(c) : commitmentPendingRecord(c);
    h.knobs.retryDeposit = async () => {
      retried = true;
      return 100n;
    };
    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(retried).toBe(true);
    expect(report.summary.deposited).toBe(1);
  });

  it("retries an unknown approve byte-for-byte and accepts Duplicate as confirmation", async () => {
    const h = await makeHarness();
    h.knobs.approve = async () => {
      throw new Error("connection reset");
    };
    await runShieldFlow(h.deps, RUNG).catch(() => {});
    expect((await h.journal.read()).approval?.status).toBe("unknown");
    const firstEnvelope = h.approves[0];

    h.knobs.approve = async () => ({ kind: "duplicate", duplicateOf: 4n });
    h.knobs.depositStatus = async () => null;
    h.knobs.shieldDeposit = async () => 300n;
    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(h.approves).toHaveLength(2);
    // Byte-identical retry: same amount, same CAS guard, same created_at_time.
    expect(h.approves[1].amount).toBe(firstEnvelope.amount);
    expect(h.approves[1].expectedAllowance).toBe(firstEnvelope.expectedAllowance);
    expect(h.approves[1].createdAtTime).toBe(firstEnvelope.createdAtTime);
    expect(report.summary.deposited).toBe(1); // then the deposit went through
  });

  it("fresh device (L0-G): rebuilds a pending deposit from the P-REC index + payload", async () => {
    const h = await makeHarness();
    // Build a REAL on-chain-shaped record: derive the note from the fixture
    // vetKey exactly as a lost device would have.
    const vetKey = vetKeyFor(USER);
    const master = masterNoteSecret(vetKey);
    const nonce = new Uint8Array(16).fill(0x5a);
    const secrets = await deriveNoteSecretsV2(master, nonce);
    const note = await createShieldNote(10n * RUNG, secrets);
    const payload = encryptNotePayload(DPK, USER, noteToBytesV2(note, nonce));
    h.knobs.listActive = async () => ({
      deposits: [
        {
          noteCommitment: note.commitment,
          status: { kind: "appended", leafIndex: 7n },
          depositor: USER,
          encryptedPayload: payload,
          privateBalance: 10n * RUNG,
          createdAtNs: 42n,
        },
      ],
      nextCursor: null,
    });
    const report = await reconcileShieldJournal(h.deps, { resubmit: false });
    expect(report.importedFromPool).toBe(1);
    const state = await h.journal.read();
    expect(state.entries[0]).toMatchObject({
      commitmentHex: bytesToHex(note.commitment),
      nonceHex: bytesToHex(nonce),
      denom: (10n * RUNG).toString(10),
      status: "deposited",
      poolStatus: "appended",
    });
  });

  it("fresh device: a payload that re-derives a DIFFERENT commitment is NOT imported", async () => {
    const h = await makeHarness();
    const vetKey = vetKeyFor(USER);
    const master = masterNoteSecret(vetKey);
    const nonce = new Uint8Array(16).fill(0x5b);
    const secrets = await deriveNoteSecretsV2(master, nonce);
    const note = await createShieldNote(RUNG, secrets);
    const payload = encryptNotePayload(DPK, USER, noteToBytesV2(note, nonce));
    h.knobs.listActive = async () => ({
      deposits: [
        {
          // Index claims a DIFFERENT commitment than the payload re-derives.
          noteCommitment: new Uint8Array(32).fill(0xee),
          status: { kind: "appended", leafIndex: 7n },
          depositor: USER,
          encryptedPayload: payload,
          privateBalance: STSH,
          createdAtNs: 42n,
        },
      ],
      nextCursor: null,
    });
    const report = await reconcileShieldJournal(h.deps, { resubmit: false });
    expect(report.importedFromPool).toBe(0);
    expect(report.attention.some((a) => /DIFFERENT commitment/.test(a))).toBe(true);
    expect((await h.journal.read()).entries).toEqual([]);
  });
});

describe("re-review required regressions (fund safety)", () => {
  it("lost SUCCESSFUL response -> pool record pruned -> NEVER a second debit", async () => {
    // The exact finding-1 shape: shield_deposit EXECUTED on the pool, but the
    // response was lost in transport. The wallet holds a dispatched 'unknown'
    // entry with no success marker. The deposit later finalizes and its
    // terminal record is PRUNED — so get_deposit_status now returns null.
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new Error("response lost (the call executed server-side)");
    };
    await runShieldFlow(h.deps, RUNG);
    const state = await h.journal.read();
    expect(state.entries[0].status).toBe("unknown");
    expect(state.entries[0].dispatchedAtNs).toBeDefined();
    expect(h.deposits).toHaveLength(1);

    // Record pruned: every probe answers null. Reconcile with resubmission —
    // repeatedly — must NEVER dispatch a second shield_deposit.
    h.knobs.depositStatus = async () => null;
    h.knobs.shieldDeposit = async () => 999n;
    for (let round = 0; round < 3; round += 1) {
      const report = await reconcileShieldJournal(h.deps, { resubmit: true });
      expect(report.attention.some((a) => /NEVER auto-resubmitted/.test(a))).toBe(true);
    }
    expect(h.deposits).toHaveLength(1); // the one original dispatch, ever
    expect((await h.journal.read()).entries[0].status).toBe("unknown");

    // The only exit is the MANUAL, explicitly-confirmed abandon (A-S21 shape).
    await expect(
      abandonAmbiguousEntry(h.deps, state.entries[0].commitmentHex, {
        confirmedExternalReconcile: false,
      }),
    ).rejects.toBeInstanceOf(ShieldAbortError);
    await abandonAmbiguousEntry(h.deps, state.entries[0].commitmentHex, {
      confirmedExternalReconcile: true,
    });
    expect((await h.journal.read()).entries[0].status).toBe("failed");
    expect(h.deposits).toHaveLength(1); // still no second debit
  });

  it("two-tab promotion during the deposit await retains the success marker (monotonic CAS)", async () => {
    const h = await makeHarness();
    // While tab A's shield_deposit call is in flight, tab B's reconcile
    // observes the pool record and promotes the entry unknown -> deposited.
    // Tab A's Ok must still merge its success marker — not fail, not lose it.
    h.knobs.shieldDeposit = async (i) => {
      const entries = (await h.journal.read()).entries;
      await h.journal.transitionEntry(entries[i].commitmentHex, ["unknown"], "deposited", {
        poolStatus: "appended",
      });
      return 1n;
    };
    const summary = await runShieldFlow(h.deps, RUNG);
    expect(summary.deposited).toBe(1);
    const entry = (await h.journal.read()).entries[0];
    expect(entry).toMatchObject({ status: "deposited", successObserved: true });
  });

  it("ledger-fee drift aborts after approve, BEFORE any deposit; cancel fails planned + revokes", async () => {
    const h = await makeHarness();
    let feeCalls = 0;
    h.knobs.ledgerFee = async () => {
      feeCalls += 1;
      return feeCalls === 1 ? LEDGER_FEE : LEDGER_FEE * 2n; // drift at the recheck
    };
    const err = await runShieldFlow(h.deps, RUNG).catch((e) => e);
    expect(err).toBeInstanceOf(ShieldAbortError);
    expect((err as ShieldAbortError).stage).toBe("fee-stale");
    expect(h.approves).toHaveLength(1);
    expect(h.deposits).toHaveLength(0);
    const total = BigInt((await h.journal.read()).approval!.totalAllowance);

    // The safe exit: cancel fails the never-dispatched entries, then revokes
    // the allowance under the CAS.
    h.knobs.allowance = async () => ({ allowance: total, expiresAt: null });
    const revokes: bigint[] = [];
    h.knobs.approve = async (req) => {
      revokes.push(req.amount);
      expect(req.expectedAllowance).toBe(total);
      return { kind: "ok", blockIndex: 3n };
    };
    const report = await cancelPlannedShield(h.deps);
    expect(report.cancelled).toBe(1);
    expect(report.ambiguousRemaining).toBe(0);
    expect(report.revoke).toEqual({ kind: "revoked" });
    expect(revokes).toEqual([0n]);
    expect(h.deposits).toHaveLength(0); // nothing was ever submitted

    // The slot is free: a fresh batch under the NEW fee basis succeeds.
    h.knobs.ledgerFee = async () => LEDGER_FEE * 2n;
    h.knobs.allowance = async () => ({ allowance: 0n, expiresAt: null });
    h.knobs.approve = async () => ({ kind: "ok", blockIndex: 4n });
    h.knobs.depositStatus = async (c) => acceptedRecord(c);
    await expect(runShieldFlow(h.deps, RUNG)).resolves.toMatchObject({ accepted: 1 });
  });

  it("required regression: two reconcilers racing ONE planned entry -> exactly ONE dispatch", async () => {
    // Shared store = two tabs over the same encrypted journal. Tab A leaves a
    // stopped batch: [10 STSH -> dispatched-unknown, 1 STSH -> planned].
    const store = (await memoryHarness()).store;
    const tabA = await makeHarness("local", testConfig(), store);
    tabA.knobs.shieldDeposit = async (i) => {
      if (i === 0) throw new Error("connection lost");
      return 1n;
    };
    await runShieldFlow(tabA.deps, 11n * RUNG);

    const tabB = await makeHarness("local", testConfig(), store);
    // Both tabs reconcile CONCURRENTLY with no pool records: the planned entry
    // must be dispatched by exactly one of them — the exclusive claim CAS is
    // the arbiter, whatever the interleaving (the loser either loses the
    // claim, or arrives later and sees a dispatched entry it may never
    // resubmit). The dispatched-unknown entry is never resubmitted by either.
    let wireCalls = 0;
    const countingDeposit = async () => {
      wireCalls += 1;
      return 2n;
    };
    for (const tab of [tabA, tabB]) {
      tab.knobs.shieldDeposit = countingDeposit;
      tab.knobs.depositStatus = async () => null;
    }
    await Promise.all([
      reconcileShieldJournal(tabA.deps, { resubmit: true }),
      reconcileShieldJournal(tabB.deps, { resubmit: true }),
    ]);
    expect(wireCalls).toBe(1);

    // And the journal converged: no planned entries remain, one deposited
    // (the raced entry), one dispatched-ambiguous (tab A's original).
    const final = await tabA.journal.read();
    expect(final.entries.filter((e) => e.status === "planned")).toHaveLength(0);
    expect(final.entries.filter((e) => e.status === "deposited")).toHaveLength(1);
    expect(final.entries.filter((e) => e.status === "unknown")).toHaveLength(1);
  });

  it("required regression: abandon refuses while the pool still holds a record", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new Error("connection lost");
    };
    await runShieldFlow(h.deps, RUNG); // -> dispatched 'unknown' entry
    const hex = (await h.journal.read()).entries[0].commitmentHex;

    // An ACTIVE pool record (e.g. TransferPending) makes the entry
    // non-abandonable — the user is directed to reconciliation instead.
    h.knobs.depositStatus = async (c) => transferPendingRecord(c);
    await expect(
      abandonAmbiguousEntry(h.deps, hex, { confirmedExternalReconcile: true }),
    ).rejects.toThrow(/not abandonable|reconciliation/);
    expect((await h.journal.read()).entries[0].status).toBe("unknown");

    // A FAILED status query refuses too — never archive blind.
    h.knobs.depositStatus = async () => {
      throw new Error("boundary unreachable");
    };
    await expect(
      abandonAmbiguousEntry(h.deps, hex, { confirmedExternalReconcile: true }),
    ).rejects.toThrow(/could not verify/);
    expect((await h.journal.read()).entries[0].status).toBe("unknown");

    // Only a live-verified NULL record + explicit confirmation archives.
    h.knobs.depositStatus = async () => null;
    await abandonAmbiguousEntry(h.deps, hex, { confirmedExternalReconcile: true });
    expect((await h.journal.read()).entries[0].status).toBe("failed");
  });

  it("cancel refuses to revoke while an ambiguous dispatched intent remains", async () => {
    const h = await makeHarness();
    h.knobs.shieldDeposit = async () => {
      throw new Error("connection lost");
    };
    await runShieldFlow(h.deps, RUNG); // -> one dispatched 'unknown' entry
    const report = await cancelPlannedShield(h.deps);
    expect(report.ambiguousRemaining).toBe(1);
    expect(report.revoke.kind).toBe("blocked");
  });

  it("reconcile resubmission rechecks the persisted fee basis and refuses under drift", async () => {
    // Build a stopped batch: entry 2 stays planned (never dispatched).
    const h = await makeHarness();
    h.knobs.shieldDeposit = async (i) => {
      if (i === 0) throw new Error("connection lost");
      return 1n;
    };
    await runShieldFlow(h.deps, 11n * RUNG); // [10 -> unknown, 1 -> planned]

    // The pool's fee params drift before the reconcile: the planned entry's
    // persisted basis no longer holds -> it must NOT be submitted.
    h.knobs.feeParams = async () => ({ ...ZERO_FEES, shieldFeeBps: 25, paramsEpoch: 2n });
    h.knobs.depositStatus = async () => null;
    h.knobs.shieldDeposit = async () => 2n;
    const report = await reconcileShieldJournal(h.deps, { resubmit: true });
    expect(h.deposits).toHaveLength(1); // no new submission
    expect(report.attention.some((a) => /fee basis changed/.test(a))).toBe(true);
    expect(report.summary.planned).toBe(1); // still planned — cancel is the exit
  });
});

describe("revokeShieldAllowance", () => {
  it("no-ops at zero and revokes under the same CAS discipline otherwise", async () => {
    const h = await makeHarness();
    expect(await revokeShieldAllowance(h.deps)).toEqual({ kind: "none" });
    h.knobs.allowance = async () => ({ allowance: 500n, expiresAt: null });
    h.knobs.approve = async (req) => {
      expect(req.amount).toBe(0n);
      expect(req.expectedAllowance).toBe(500n);
      return { kind: "ok", blockIndex: 9n };
    };
    expect(await revokeShieldAllowance(h.deps)).toEqual({ kind: "revoked" });
  });
});

// ── Record builders ──────────────────────────────────────────────────────────

function baseRecord(commitment: Uint8Array): Omit<PoolPendingDeposit, "status"> {
  return {
    noteCommitment: commitment,
    depositor: USER,
    encryptedPayload: new Uint8Array([1]),
    privateBalance: STSH,
    createdAtNs: 1n,
  };
}
function acceptedRecord(c: Uint8Array): PoolPendingDeposit {
  return {
    ...baseRecord(c),
    status: { kind: "root-accepted", leafIndex: 1n, root: new Uint8Array(32) },
  };
}
function appendedRecord(c: Uint8Array): PoolPendingDeposit {
  return { ...baseRecord(c), status: { kind: "appended", leafIndex: 1n } };
}
function transferPendingRecord(c: Uint8Array): PoolPendingDeposit {
  return { ...baseRecord(c), status: { kind: "transfer-pending" } };
}
function commitmentPendingRecord(c: Uint8Array): PoolPendingDeposit {
  return { ...baseRecord(c), status: { kind: "commitment-pending" } };
}
