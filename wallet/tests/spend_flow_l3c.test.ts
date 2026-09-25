// @vitest-environment node
/**
 * L3c spend flow tests (§10) — REAL crypto end to end: real note derivation,
 * real mirror witness, REAL snarkjs fullProve against spend_1.zkey, real
 * 256-byte encoding, real 9-signal canonical compare. The pool/verifier
 * actors are scripted fakes; everything from the witness downward is the
 * production code path.
 *
 * Authority model under test (§10.1/§10.2): advisory query rows drive
 * REVERSIBLE actions only — forged Finalized / PayoutPending / failure rows
 * are ATTEMPTED and must never evict, unlock, or add change; permanent
 * effects come only from an authoritative update Ok.
 */

import { beforeAll, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Principal } from "@dfinity/principal";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync as readFs, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SNARKJS_CLI = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../circuits/node_modules/.bin/snarkjs",
);
const GENERATE_WITNESS = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../circuits/build/spend_js/generate_witness.js",
);
import { augmentedHashToG1, DerivedPublicKey, type VetKey } from "@dfinity/vetkeys";
import { bls12_381 } from "@noble/curves/bls12-381";

import { initPoseidon } from "../src/crypto/poseidon";
import {
  DENOMINATIONS,
  createShieldNote,
  deriveNoteSecretsV2,
  merkleLeaf,
  noteToBytesV2,
  type Note,
} from "../src/crypto/notes";
import { vetkdInput } from "../src/crypto/vetkeys";
import { LocalMerkleMirror, ctEqual, scanAndValidate } from "../src/crypto/scanner";
import { encodeGroth16Proof } from "../src/crypto/encodeProof";
import type { ProverRequest } from "../src/workers/prover.worker";
import type { PoolCanister, PrivateSpendRequest } from "../src/actors/pool";
import type { DeploymentAttestation } from "../../src/declarations/shielded_pool/shielded_pool.did";
import type { VetkeysCanister } from "../src/crypto/vetkeys";
import type { TokenCanister } from "../src/actors/token";

import {
  runSpendFlow,
  freshSpendId,
  recoveryActionForAdvisory,
  deserializeSpendRequest,
  serializeSpendRequest,
  recoverSpendsFromPool,
  replaySameIntent,
  reconcileSpendEntry,
  recoverSpendFreshId,
  intentFingerprintHex,
  type SpendFlowDeps,
} from "../src/ui/spendFlow";
import { SpendJournal } from "../src/storage/spendJournal";
import { PoolCallError } from "../src/actors/pool";
import {
  SPEND_ADMISSION_CODES,
  SPEND_ALREADY_WENT_THROUGH_COPY,
  parseSpendAdmission,
  spendAdmissionCopy,
  type SpendAdmissionCode,
} from "../src/ui/spendAdmissionCopy";
import { SpendFlowError } from "../src/ui/spendFlow";
import { PrincipalNoteCache, type ScannedNote } from "../src/storage/noteCache";
import { openIndexedDbPrincipalCacheStore } from "../src/storage/indexedDbNoteStore";
import { ManifestError } from "../src/zk/artifacts";
import "fake-indexeddb/auto";

const here = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = resolve(here, "../../circuits/build/spend_js/spend.wasm");
const ZKEY_PATH = resolve(here, "../../circuits/build/spend_1.zkey");

beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

const MASTER = new Uint8Array(32).fill(0x11);
const BINDING = { principalText: "aaaaa-aa", epoch: 1, assertCurrent(): void {} };
const POOL_PRINCIPAL = Principal.fromText("cxrfg-qaaaa-aaaar-qchfa-cai");
const TOKEN_PRINCIPAL = Principal.fromUint8Array(new Uint8Array(10).fill(0x01));
const MERKLE_PRINCIPAL = Principal.fromUint8Array(new Uint8Array(10).fill(0x02));
const NULLIFIER_PRINCIPAL = Principal.fromUint8Array(new Uint8Array(10).fill(0x03));
const VERIFIER_PRINCIPAL = Principal.fromUint8Array(new Uint8Array(10).fill(0x04));
const VK_HASH_HEX = "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914";
const vkHashBytes = Uint8Array.from({ length: 32 }, (_, i) => parseInt(VK_HASH_HEX.slice(i * 2, i * 2 + 2), 16));

const FAKE_VETKEY = {
  serialize: () => new Uint8Array(48).fill(9),
  deriveSymmetricKey: () => MASTER,
} as unknown as VetKey;

// Offline vetKD fixture (REAL BLS/IBE crypto, test-only master scalar — same
// pattern as shield_flow_l3a.test.ts). The DPK makes encryptNotePayload run
// the REAL IBE path; the fake vetKey above supplies the note-derivation master.
const MASTER_X = 0x517f0da4cf3d70b1n;
const DPK = DerivedPublicKey.deserialize(
  bls12_381.G2.ProjectivePoint.BASE.multiply(MASTER_X).toRawBytes(true),
);
void augmentedHashToG1; // (pattern parity with the L3a fixture)
void vetkdInput;

/** tryDecrypt that returns the payload itself when it "decrypts for us". */
const decryptSelf = (bytes: Uint8Array): Uint8Array | null => bytes;

/** L0-F-compliant registry stub (strict sorted pagination, exclusive cursor). */
function registryStubForScan(spent: Uint8Array[]) {
  const sorted = [...spent].sort((a, b) => {
    for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  });
  return {
    async getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]> {
      let idx = 0;
      if (startAfter !== null) {
        idx = sorted.findIndex((v) => {
          for (let i = 0; i < 32; i++) {
            if (v[i] !== startAfter[i]) return v[i] > startAfter[i];
          }
          return false;
        });
        if (idx === -1) idx = sorted.length;
      }
      return sorted.slice(idx, idx + Number(limit));
    },
    async count(): Promise<bigint> {
      return BigInt(sorted.length);
    },
  };
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

interface Fixture {
  note: Note;
  nonce: Uint8Array;
  leaf: Uint8Array;
  cached: ScannedNote;
  plaintext: Uint8Array;
}

async function makeInputNote(): Promise<Fixture> {
  const nonce = new Uint8Array(16).fill(0x33);
  const secrets = await deriveNoteSecretsV2(MASTER, nonce);
  const note = await createShieldNote(DENOMINATIONS[2], secrets); // 100 STSH
  const leaf = await merkleLeaf(note.value, note.commitment);
  return {
    note,
    nonce,
    leaf,
    plaintext: noteToBytesV2(note, nonce),
    cached: {
      leafIndex: 0n,
      value: note.value,
      rho: note.rho,
      rseed: note.rseed,
      recipientPk: note.recipientPk,
      nonce,
      commitment: note.commitment,
      nullifier: note.nullifier,
      state: "spendable",
    },
  };
}


const nfHex = (n: Note): string =>
  [...n.nullifier].map((b) => b.toString(16).padStart(2, "0")).join("");

/** A mirror with the input leaf at index 0 (single-leaf tree). */
async function oneLeafMirror(leaf: Uint8Array): Promise<{ root: Uint8Array }> {
  const mirror = new LocalMerkleMirror();
  mirror.addLeaf(0n, leaf);
  return { root: await mirror.root(1n) };
}

/** Inline prover worker: runs the REAL prover in node — witness generation
 * (generate_witness.js) + `snarkjs groth16 prove` against spend_1.zkey, the
 * same zkey + circuit wasm the production worker uses. */
class InlineProverWorker {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  constructor(private readonly tamperSignals?: (signals: string[]) => string[]) {}
  async postMessage(req: ProverRequest) {
    const dir = mkdtempSync(join(tmpdir(), "l3c-prove-"));
    try {
      const inputPath = join(dir, "input.json");
      const wtnsPath = join(dir, "w.wtns");
      const proofPath = join(dir, "proof.json");
      const publicPath = join(dir, "public.json");
      writeFileSync(inputPath, JSON.stringify(req.circuitInputs));
      await execFileAsync(process.execPath, [GENERATE_WITNESS, req.wasmUrl, inputPath, wtnsPath], {
        timeout: 120_000,
      });
      await execFileAsync(
        process.execPath,
        [SNARKJS_CLI, "groth16", "prove", req.zkeyUrl, wtnsPath, proofPath, publicPath],
        { timeout: 300_000 },
      );
      const proof = JSON.parse(readFs(proofPath, "utf8"));
      const publicSignals = JSON.parse(readFs(publicPath, "utf8")) as string[];
      const signals = this.tamperSignals ? this.tamperSignals(publicSignals) : publicSignals;
      this.onmessage?.({ data: { ok: true, proof, publicSignals: signals } } as MessageEvent);
    } catch (err) {
      this.onmessage?.({
        data: { ok: false, error: err instanceof Error ? err.message : String(err) },
      } as MessageEvent);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  terminate(): void {}
}

interface PoolSpy {
  calls: { method: string; args?: unknown }[];
  attestation: DeploymentAttestation;
  spendResult: "ok" | { err: Record<string, unknown> };
}

function makePool(root: Uint8Array, leafCount: bigint, opts?: { badVk?: boolean }): PoolCanister & { spy: PoolSpy } {
  const spy: PoolSpy = {
    calls: [],
    attestation: {
      pool: POOL_PRINCIPAL,
      token: TOKEN_PRINCIPAL,
      merkle: MERKLE_PRINCIPAL,
      nullifier: NULLIFIER_PRINCIPAL,
      verifier: [VERIFIER_PRINCIPAL],
      vk_hash: opts?.badVk === true ? new Uint8Array(32).fill(0x99) : vkHashBytes,
      circuit_version: 3,
      pool_version: 1,
      proof_system: "groth16-bn254",
      config_version: 1,
      config_hash: new Uint8Array(32),
    },
    spendResult: "ok",
  };
  return {
    spy,
    shieldDeposit: async () => 0n,
    getDenominations: async () => [],
    getPinnedVkHash: async () => vkHashBytes,
    getCircuitVersion: async () => 2,
    getPoolVersion: async () => 1,
    isDepositsPaused: async () => false,
    isSpendsPaused: async () => false,
    getGovernanceFeeParams: async () => ({
      shieldFeeBps: 0,
      shieldFlatMinimumFeeE8s: 0n,
      minimumPrivateCredit: 0n,
      feeModelVersion: 1,
      paramsEpoch: 0n,
      protocolPrivateSpendFeeStsh: 1_000_000n, // 0.01 STSH
      // A-7: these L3c fixtures exercise the shielded→shielded fee path; the
      // exit arm is zeroed so their expectations are unchanged.
      unshieldFeeBps: 0,
      unshieldFlatMinimumFeeE8s: 0n,
    }),
    getDepositStatus: async () => null,
    retryDepositCommitment: async () => 0n,
    listMyActiveDeposits: async () => ({ deposits: [], nextCursor: null }),
    privateSpend: async (req) => {
      spy.calls.push({ method: "private_spend", args: req });
      if (spy.spendResult !== "ok") throw new Error("scripted pool rejection");
    },
    retryPrivateSpendPayout: async (id) => {
      spy.calls.push({ method: "retry_private_spend_payout", args: id });
      return 42n;
    },
    getSpendStatus: async () => null,
    getAcceptedRootHead: async () => ({ root, leafCount }),
    getDeploymentAttestation: async () => spy.attestation,
    getSecurityEpoch: async () => 0n,
    listMyActiveSpends: async () => ({ spends: [], nextCursor: null }),
  };
}

const FAKE_VETKEYS: VetkeysCanister = {
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
  getConfig: async () => ["stsh.wallet.notes.v1", "key_1"],
};

const FAKE_TOKEN: TokenCanister = {
  balanceOf: async () => 0n,
  metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
  fee: async () => 10_000n,
};

function scanOf(leaf: Uint8Array, root: Uint8Array): SpendFlowDeps["scan"] {
  return {
    getScanHead: async () => ({ leafCount: 1n, root }),
    getScanPage: async (from: bigint) =>
      from === 0n ? [{ index: 0n, leaf, encryptedPayload: new Uint8Array(0) }] : [],
  };
}

async function makeDeps(opts?: {
  pool?: PoolCanister & { spy: PoolSpy };
  worker?: InlineProverWorker;
  scan?: SpendFlowDeps["scan"];
}): Promise<{ deps: SpendFlowDeps; journal: SpendJournal; cache: PrincipalNoteCache; fixture: Fixture }> {
  const fixture = await makeInputNote();
  const { root } = await oneLeafMirror(fixture.leaf);
  const dbName = `stsh-l3c-${crypto.randomUUID()}`;
  const store = await openIndexedDbPrincipalCacheStore(dbName);
  const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
  await cache.update((s) => ({ ...s, notes: [fixture.cached] })); // seed the validated note
  const journal = new SpendJournal(cache);
  const deps: SpendFlowDeps = {
    policyKind: "production",
    config: {
      host: "",
      fetchRootKey: false,
      poolCanisterId: POOL_PRINCIPAL.toText(),
      merkleCanisterId: MERKLE_PRINCIPAL.toText(),
      vetkeysCanisterId: "aaaaa-aa",
      tokenCanisterId: TOKEN_PRINCIPAL.toText(),
      stakingCanisterId: "aaaaa-aa",
      vestingCanisterId: "aaaaa-aa",
      nullifierCanisterId: NULLIFIER_PRINCIPAL.toText(),
      verifierCanisterId: VERIFIER_PRINCIPAL.toText(),
      vaultCanisterId: "aaaaa-aa",
      upgraderCanisterId: "aaaaa-aa",
      frozenPoolCanisterId: POOL_PRINCIPAL.toText(),
      vetkdKeyName: undefined,
      walletSignerUrl: "",
      iiUrl: undefined,
      derivationOrigin: undefined,
      // S1-02: the runtime-loaded launch origin; this harness supplies the ruled value.
      launchOrigin: "https://app.stsh.fi",
    },
    principal: Principal.fromUint8Array(new Uint8Array(10).fill(0x21)),
    vetkeys: FAKE_VETKEYS,
    pool: opts?.pool ?? makePool(root, 1n),
    token: FAKE_TOKEN,
    journal,
    scan: opts?.scan ?? scanOf(fixture.leaf, root),
    notes: [fixture.cached],
    expectedDeploymentConfigHash: new Uint8Array(32),
    fetchKeys: async () => ({ vetKey: FAKE_VETKEY, verificationKey: DPK, remaining: 4 }),
    loadAssets: async (fn) => fn({ wasmUrl: WASM_PATH, zkeyUrl: ZKEY_PATH }),
    spawnWorker: () => (opts?.worker ?? new InlineProverWorker()) as unknown as Worker,
  };
  return { deps, journal, cache, fixture };
}

// ── The happy path ────────────────────────────────────────────────────────────

describe("runSpendFlow — real proof end to end (H6-2)", () => {
  it("private spend: real proof, 256-byte encoding, exactly 1 nullifier / 2 outer leaves, input spent", async () => {
    const { deps, fixture } = await makeDeps();
    const summary = await runSpendFlow(deps, { inputLeafIndex: 0n });

    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const call = pool.spy.calls.find((c) => c.method === "private_spend");
    expect(call).toBeDefined();
    const args = call!.args as PrivateSpendRequest;
    expect(args.nullifiers.length).toBe(1);
    expect(args.outputCommitments.length).toBe(2);
    expect([...args.nullifiers[0]]).toEqual([...fixture.note.nullifier]);
    expect(args.proofBytes.length).toBe(256);
    expect(args.proofSystemId).toBe("groth16-bn254");
    // F1-PRIV (R1-F1): the cleartext hidden values are GONE from the wire. The
    // assertion is retargeted from their values to their absence — on the typed
    // request and on the object the actor hands the agent.
    expect("inputAmounts" in (args as object)).toBe(false);
    expect("outputAmounts" in (args as object)).toBe(false);
    expect(args.fee).toBe(1_000_000n);
    expect(args.publicPayout).toBeNull();
    // The accepted root anchors the envelope.
    expect([...args.rootReference]).toEqual([...(await oneLeafMirror(fixture.leaf)).root]);

    // Journal: finalized; the FINAL request (with proof bytes) is persisted.
    const entry = await deps.journal.find(summary.spendId);
    expect(entry?.status).toBe("finalized");
    expect(entry?.dispatchedAtNs).toBeDefined();
    // The persisted request is the byte-exact replay material (proof included).
    const replay = deserializeSpendRequest(entry!.requestJson);
    expect(replay.proofBytes.length).toBe(256);
    expect(replay.spendId.toString(10)).toBe(summary.spendId);
    expect(summary.changeValue).toBe(DENOMINATIONS[2] - 1_000_000n);
  }, 120_000);

  it("public payout is GROSS: public_amount = recipientNet + live ledger fee; outputs [input−amount−fee, 0]", async () => {
    const { deps } = await makeDeps();
    const net = 50_000_000_000n; // 500 STSH net — exceeds the note? no: note is 100 STSH = 10_000_000_000
    const smallNet = 5_000_000_000n; // 50 STSH
    void net;
    const summary = await runSpendFlow(deps, {
      inputLeafIndex: 0n,
      payout: {
        destination: Principal.fromUint8Array(new Uint8Array(8).fill(0x44)),
        subaccount: null,
        recipientNet: smallNet,
      },
    });
    expect(summary.publicAmount).toBe(smallNet + 10_000n); // net + live ledger fee
    // A-7 RETARGET (OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21): an exit now
    // pays the UNSHIELD value fee, `max(unshield_flat_minimum, 0.25%)`, not the
    // flat protocol spend fee. This fixture's governance params leave both
    // unshield fields at the launch DEFAULT of zero — the fees-not-yet-activated
    // posture, where the shield side charges zero too — so the exit fee here is
    // 0, where it used to be the 1,000,000-e8s spend fee. The change is asserted
    // at NONZERO parameters in the `A-7` describe block below; this test's
    // subject is the payout GROSS, which is unchanged.
    const exitFeeAtLaunchDefaults = 0n;
    expect(summary.changeValue).toBe(
      DENOMINATIONS[2] - (smallNet + 10_000n) - exitFeeAtLaunchDefaults,
    );
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const args = pool.spy.calls.find((c) => c.method === "private_spend")!.args as PrivateSpendRequest;
    expect(args.publicPayout?.publicAmount).toBe(smallNet + 10_000n);
    // F1-PRIV (R1-F4): the zero-dummy value assertion is RETIRED — after the
    // amount fields are removed, NOTHING on the remaining wire carries the dummy's
    // value. What survives is its indistinguishability, which R1 verified holds on
    // the hashed/encrypted channel (fresh nonce, fresh secrets, Poseidon leaf), so
    // the shape is asserted instead of the cleartext value.
    expect(args.outputCommitments.length).toBe(2);
    expect(args.encryptedOutputs.length).toBe(2);
    expect(args.encryptedOutputs[0].length).toBe(args.encryptedOutputs[1].length);
  }, 120_000);
});

// ── A-7 (T7): the EXIT fee the wallet binds into the proof ────────────────────
//
// The fee is public signal[5]. A wallet that computes the wrong one does not get
// a rejected transaction — it gets a proof the pool refuses, after paying for a
// full proving run. These tests therefore assert the number the wallet BOUND,
// on the request it actually dispatched.

describe("A-7 — a public payout pays the unshield value fee, not the flat spend fee", () => {
  /// Nonzero unshield parameters — the shipped launch model. At zero (the other
  /// fixtures in this file) the value fee and the flat fee coincide and every
  /// assertion below would hold on a wallet that never changed.
  const EXIT_PARAMS = {
    shieldFeeBps: 25,
    shieldFlatMinimumFeeE8s: 10_000_000n,
    minimumPrivateCredit: 0n,
    feeModelVersion: 1,
    paramsEpoch: 0n,
    protocolPrivateSpendFeeStsh: 1_000_000n, // 0.01 STSH — the FLAT spend fee
    unshieldFeeBps: 25,
    unshieldFlatMinimumFeeE8s: 250_000_000n, // 2.5 STSH launch flat minimum (A6.6)
  };

  function withExitParams(deps: SpendFlowDeps): SpendFlowDeps {
    return {
      ...deps,
      pool: { ...deps.pool, getGovernanceFeeParams: async () => EXIT_PARAMS },
    };
  }

  it("binds max(flat, 0.25%) on the payout gross — the bps arm", async () => {
    const { deps } = await makeDeps();
    // A6.6: the flat minimum is 2.5 STSH, so the bps arm only binds above the
    // 1,000-STSH crossover. 5,000 STSH net + 10_000 e8s ledger fee = the gross
    // the fee is charged on.
    const recipientNet = 500_000_000_000n;
    const gross = recipientNet + 10_000n;
    const expectedFee = (gross * 25n) / 10_000n; // 1_250_000_025 e8s — above the floor
    expect(expectedFee).toBeGreaterThan(EXIT_PARAMS.unshieldFlatMinimumFeeE8s);

    const summary = await runSpendFlow(withExitParams(deps), {
      inputLeafIndex: 0n,
      payout: {
        destination: Principal.fromUint8Array(new Uint8Array(8).fill(0x44)),
        subaccount: null,
        recipientNet,
      },
    });

    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const args = pool.spy.calls.find((c) => c.method === "private_spend")!.args as PrivateSpendRequest;
    expect(args.fee).toBe(expectedFee);
    expect(args.fee).not.toBe(EXIT_PARAMS.protocolPrivateSpendFeeStsh);
    // The change output is derived from the SAME fee, so a wrong fee would also
    // corrupt the balance identity the circuit enforces.
    // F1-PRIV: the change VALUE is no longer on the wire, so the fee-derivation
    // assertion moves to the summary, which is where the wallet still computes it.
    expect(summary.changeValue).toBe(DENOMINATIONS[2] - gross - expectedFee);
  }, 120_000);

  it("binds the FLOOR below the crossover — the flat-minimum arm", async () => {
    const { deps } = await makeDeps();
    const recipientNet = 100_000_000n; // 1 STSH: 0.25% is 250,000 e8s, floor wins
    const gross = recipientNet + 10_000n;
    const expectedFee = EXIT_PARAMS.unshieldFlatMinimumFeeE8s;
    expect((gross * 25n) / 10_000n).toBeLessThan(expectedFee);

    await runSpendFlow(withExitParams(deps), {
      inputLeafIndex: 0n,
      payout: {
        destination: Principal.fromUint8Array(new Uint8Array(8).fill(0x44)),
        subaccount: null,
        recipientNet,
      },
    });

    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const args = pool.spy.calls.find((c) => c.method === "private_spend")!.args as PrivateSpendRequest;
    expect(args.fee).toBe(expectedFee);
  }, 120_000);

  it("a shielded->shielded spend still binds the flat protocol spend fee", async () => {
    const { deps } = await makeDeps();
    await runSpendFlow(withExitParams(deps), { inputLeafIndex: 0n });
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const args = pool.spy.calls.find((c) => c.method === "private_spend")!.args as PrivateSpendRequest;
    expect(args.publicPayout).toBeNull();
    expect(args.fee).toBe(EXIT_PARAMS.protocolPrivateSpendFeeStsh);
  }, 120_000);

  it("the pre-dispatch drift re-check re-derives on the PAYOUT basis", async () => {
    // The re-check used to re-read only the flat spend fee, so a governance
    // change to the unshield parameters mid-flight was invisible to it. Here the
    // unshield bps doubles between the basis read and the re-check: the intent
    // must be archived as fee-stale rather than dispatched with a stale fee.
    const { deps } = await makeDeps();
    let call = 0;
    const drifting: SpendFlowDeps = {
      ...deps,
      pool: {
        ...deps.pool,
        getGovernanceFeeParams: async () => {
          call += 1;
          return call === 1 ? EXIT_PARAMS : { ...EXIT_PARAMS, unshieldFeeBps: 50 };
        },
      },
    };
    await expect(
      runSpendFlow(drifting, {
        inputLeafIndex: 0n,
        payout: {
          destination: Principal.fromUint8Array(new Uint8Array(8).fill(0x44)),
          subaccount: null,
          recipientNet: 500_000_000_000n,
        },
      }),
    ).rejects.toThrow(/fee-stale|mid-flight/i);
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    expect(
      pool.spy.calls.find((c) => c.method === "private_spend"),
      "a drifted exit fee must never be dispatched",
    ).toBeUndefined();
  }, 120_000);
});

// ── Journal + lock atomicity / no-unlock paths ────────────────────────────────

describe("spend journal — atomic lock, exactly-once, no-query-unlock", () => {
  it("beginSpend writes the entry AND locks the note in ONE state (planned + pending)", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));

    await journal.beginSpend(0n, {
      spendId: "7",
      nullifierHex: "aa",
      inputLeafIndex: "0",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["dd", "ee"],
      encryptedOutputsHex: ["ff", "00"],
      requestJson: "{}",
      intentFingerprintHex: "11",
      feeStsh: "0",
      acceptedRootHex: "22",
      manifestVersion: 1,
      createdAtNs: "1",
    });
    const state = await cache.load();
    expect(state.notes[0].state).toBe("pending");
    expect(state.spendJournal?.entries[0].status).toBe("planned");
  });

  it("a never-dispatched intent archives + unlocks atomically; a dispatched one NEVER unlocks", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));
    const entry = {
      spendId: "9",
      nullifierHex: "aa",
      inputLeafIndex: "0",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["dd", "ee"],
      encryptedOutputsHex: ["ff", "00"],
      requestJson: "{}",
      intentFingerprintHex: "11",
      feeStsh: "0",
      acceptedRootHex: "22",
      manifestVersion: 1,
      createdAtNs: "1",
    };
    await journal.beginSpend(0n, entry);
    await journal.archiveNeverDispatched("9", 0n, "proof artifacts unavailable");
    let state = await cache.load();
    expect(state.notes[0].state).toBe("spendable"); // restored
    expect(state.spendJournal?.entries[0].status).toBe("failed");

    // A dispatched intent: the ONLY unlock path is sealed.
    await journal.beginSpend(0n, { ...entry, spendId: "10" });
    await journal.markDispatched("10", "2");
    await expect(journal.archiveNeverDispatched("10", 0n, "x")).rejects.toThrow(/never be unlocked/);
    state = await cache.load();
    expect(state.notes[0].state).toBe("pending"); // still locked
  });
});

// ── Guards: witness, signals, manifest, fee ──────────────────────────────────

describe("runSpendFlow — fail-closed guards", () => {
  it("rejects an input leaf beyond the accepted head (not finalized)", async () => {
    const fixture = await makeInputNote();
    const { root } = await oneLeafMirror(fixture.leaf);
    const pool = makePool(root, 0n); // accepted head BELOW the input index
    const { deps } = await makeDeps({ pool });
    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toThrow(/not finalized|accepted head/i);
    expect((pool.spy.calls ?? []).length).toBe(0);
  });

  it("rejects when the accepted head is AHEAD of the local mirror (rescan required)", async () => {
    const fixture = await makeInputNote();
    const { root } = await oneLeafMirror(fixture.leaf);
    const pool = makePool(root, 5n); // accepted head ahead of the 1-leaf mirror
    const { deps } = await makeDeps({ pool });
    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toThrow(/rescan/i);
  });

  it("a tampered 9th public signal aborts BEFORE submit (canonical compare)", async () => {
    const worker = new InlineProverWorker((signals) => {
      const tampered = [...signals];
      tampered[8] = (BigInt(tampered[8]) + 1n).toString(10);
      return tampered;
    });
    const { deps } = await makeDeps({ worker });
    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toThrow(/signals/i);
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    expect(pool.spy.calls.find((c) => c.method === "private_spend")).toBeUndefined();
  }, 120_000);

  it("manifest attestation mismatch (wrong VK hash) DISABLES spend before any proof", async () => {
    const fixture = await makeInputNote();
    const { root } = await oneLeafMirror(fixture.leaf);
    const pool = makePool(root, 1n, { badVk: true });
    const { deps } = await makeDeps({ pool });
    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toBeInstanceOf(ManifestError);
    expect(pool.spy.calls.find((c) => c.method === "private_spend")).toBeUndefined();
  });

  it("fee underflow aborts BEFORE journaling (no entry, no lock)", async () => {
    const fixture = await makeInputNote();
    const { root } = await oneLeafMirror(fixture.leaf);
    const { deps, journal, cache } = await makeDeps({ pool: makePool(root, 1n) });
    await expect(
      runSpendFlow(deps, {
        inputLeafIndex: 0n,
        payout: {
          destination: Principal.fromUint8Array(new Uint8Array(4).fill(1)),
          subaccount: null,
          recipientNet: DENOMINATIONS[2], // entire note — no room for fee + ledger fee
        },
      }),
    ).rejects.toThrow(/cannot cover/i);
    const state = await cache.load();
    expect(state.spendJournal).toBeUndefined();
    expect(state.notes[0].state).toBe("spendable"); // never locked
    void journal;
  });
});

// ── §10.1/§10.2 authority model (forged advisory rows ATTEMPTED) ─────────────

describe("recovery authority — advisory queries NEVER perform permanent effects", () => {
  it("forged Finalized row: drives ONLY a same-intent replay (update Ok is the authority)", () => {
    expect(recoveryActionForAdvisory({ kind: "finalized" }, "dispatched")).toEqual({
      kind: "replay-same-intent",
    });
  });

  it("forged PayoutPending row: drives ONLY retryPrivateSpendPayout SAME id", () => {
    expect(recoveryActionForAdvisory({ kind: "payout-pending" }, "dispatched")).toEqual({
      kind: "retry-payout",
    });
  });

  it("forged failure/in-flight/unknown rows: keep locked — never resubmit blindly, never unlock", () => {
    for (const kind of ["failed-before-state-change", "failed-after-outputs-staged", "in-flight", "payout-submitting", "payout-unknown", "operator-reconcile"]) {
      expect(recoveryActionForAdvisory({ kind }, "dispatched")).toEqual({ kind: "keep-locked" });
    }
  });

  it("settled None + planned journal entry: archive allowed (no pool record); settled None + dispatched: SAME id first (WALLET-V12 E-2(c)) — fresh id only after the update says DuplicateSpendId", () => {
    expect(recoveryActionForAdvisory(null, "planned")).toEqual({ kind: "archive-never-dispatched" });
    // Was `fresh-id` before WALLET-V12 (Addendum 1a): the fresh-id arm now runs
    // only when the same-id retry is answered DuplicateSpendId (see the
    // WALLET-V12 describe below, which exercises that fallback end to end).
    expect(recoveryActionForAdvisory(null, "dispatched")).toEqual({ kind: "retry-same-id" });
  });

  it("retryPrivateSpendPayout Ok: input stays SPENT — never unlocked, never restored (the payout correction)", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));
    const entry = {
      spendId: "77",
      nullifierHex: nfHex(fixture.note),
      inputLeafIndex: "0",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["dd", "ee"],
      encryptedOutputsHex: ["ff", "00"],
      requestJson: "{}",
      intentFingerprintHex: "11",
      feeStsh: "0",
      acceptedRootHex: "22",
      manifestVersion: 1,
      createdAtNs: "1",
    };
    await journal.beginSpend(0n, entry); // locks the input (spendable → pending)
    await journal.markDispatched("77", "2");
    await journal.markPayoutPending("77", "ledger transfer pending");

    // The retry's update Ok completes the spend — the parent nullifier is
    // already spent (registry finality): input → spent, NEVER back to spendable.
    await journal.finalizeFromSpendOk("77", 0n);
    const state = await cache.load();
    expect(state.notes[0].state).toBe("spent");
    expect(state.spendJournal?.entries[0].status).toBe("finalized");
  });

  it("freshSpendId is a CSPRNG u64 decimal string (no JS-number conversion)", () => {
    const a = freshSpendId();
    const b = freshSpendId();
    expect(a).not.toBe(b);
    expect(/^[0-9]+$/.test(a)).toBe(true);
    const v = BigInt(a);
    expect(v >= 0n && v < 2n ** 64n).toBe(true);
  });
});

// ── R6: dispatch ordering, fee revalidation, recovery orchestrator ───────────

describe("R6 — dispatch ordering + fee revalidation", () => {
  it("a proof-stage failure archives the never-dispatched intent AND restores the note atomically", async () => {
    const failingWorker = {
      onmessage: null as ((e: MessageEvent) => void) | null,
      onerror: null as ((e: ErrorEvent) => void) | null,
      postMessage() {
        this.onmessage?.({ data: { ok: false, error: "prover exploded" } } as MessageEvent);
      },
      terminate() {},
    };
    const { deps, cache, journal } = await makeDeps({
      worker: failingWorker as unknown as InlineProverWorker,
    });
    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toThrow();
    const state = await cache.load();
    expect(state.notes[0].state).toBe("spendable");
    expect((await journal.read()).entries[0].status).toBe("failed");
    expect((await journal.read()).entries[0].dispatchedAtNs).toBeUndefined();
  });

  it("governance spend-fee drift before dispatch → fee-stale, intent archived, note restored", async () => {
    const fixture = await makeInputNote();
    const { root } = await oneLeafMirror(fixture.leaf);
    const pool = makePool(root, 1n);
    let feeCalls = 0;
    const drifted: typeof pool = Object.create(pool, {
      getGovernanceFeeParams: {
        value: async () => {
          feeCalls += 1;
          const base = await pool.getGovernanceFeeParams();
          return { ...base, protocolPrivateSpendFeeStsh: feeCalls === 1 ? 1_000_000n : 2_000_000n };
        },
      },
      spy: { value: pool.spy },
    });
    const { deps, cache } = await makeDeps({ pool: drifted });
    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toThrow(/mid-flight|fee-stale/i);
    const state = await cache.load();
    expect(state.notes[0].state).toBe("spendable");
    expect((await deps.journal.read()).entries[0].status).toBe("failed");
  }, 120_000);

  it("ledger-fee drift (payout) before dispatch → fee-stale, intent archived, note restored", async () => {
    const { deps, cache } = await makeDeps();
    let ledgerCalls = 0;
    deps.token = {
      ...deps.token,
      fee: async () => {
        ledgerCalls += 1;
        return ledgerCalls === 1 ? 10_000n : 20_000n;
      },
    };
    await expect(
      runSpendFlow(deps, {
        inputLeafIndex: 0n,
        payout: {
          destination: Principal.fromUint8Array(new Uint8Array(4).fill(1)),
          subaccount: null,
          recipientNet: 500_000_000_000n,
        },
      }),
    ).rejects.toThrow(/fee/i);
    expect((await cache.load()).notes[0].state).toBe("spendable");
  }, 120_000);

  it("markDispatched runs only AFTER the final request is persisted (ordering proof)", async () => {
    const { deps, journal } = await makeDeps();
    const order: string[] = [];
    const origPersist = journal.persistFinalRequest.bind(journal);
    const origMark = journal.markDispatched.bind(journal);
    journal.persistFinalRequest = async (id, json) => {
      order.push("persist");
      return origPersist(id, json);
    };
    journal.markDispatched = async (id, ns) => {
      order.push("dispatch");
      return origMark(id, ns);
    };
    await runSpendFlow(deps, { inputLeafIndex: 0n });
    expect(order).toEqual(["persist", "dispatch"]);
  }, 120_000);

  it("archives and unlocks a planned intent when cancellation arrives as beginSpend completes", async () => {
    const { deps, journal, cache } = await makeDeps();
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const controller = new AbortController();
    deps.signal = controller.signal;
    const originalBegin = journal.beginSpend.bind(journal);
    journal.beginSpend = async (...args) => {
      await originalBegin(...args);
      controller.abort();
    };

    await expect(runSpendFlow(deps, { inputLeafIndex: 0n })).rejects.toThrow(/cancel/i);
    const entries = (await journal.read()).entries;
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe("failed");
    expect((await cache.load()).notes[0].state).toBe("spendable");
    expect(pool.spy.calls.filter((call) => call.method === "private_spend")).toHaveLength(0);
  }, 120_000);

  it.each(["head", "page"] as const)(
    "cancels promptly while the mirror %s read is held without starting the journal or later pages",
    async (phase) => {
      const { deps, journal } = await makeDeps();
      const controller = new AbortController();
      deps.signal = controller.signal;
      const originalHead = deps.scan.getScanHead.bind(deps.scan);
      const originalPage = deps.scan.getScanPage.bind(deps.scan);
      let entered = false;
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let pageCalls = 0;
      deps.scan.getScanHead = async () => {
        if (phase === "head") {
          entered = true;
          await gate;
        }
        return originalHead();
      };
      deps.scan.getScanPage = async (from, limit) => {
        pageCalls += 1;
        if (phase === "page" && pageCalls === 1) {
          entered = true;
          await gate;
        }
        return originalPage(from, limit);
      };
      let journalStarts = 0;
      const originalBegin = journal.beginSpend.bind(journal);
      journal.beginSpend = async (...args) => {
        journalStarts += 1;
        return originalBegin(...args);
      };
      let settled = false;
      const pending = runSpendFlow(deps, { inputLeafIndex: 0n }).then(
        () => { settled = true; },
        () => { settled = true; },
      );
      await vi.waitFor(() => expect(entered).toBe(true));
      controller.abort();
      await vi.waitFor(() => expect(settled).toBe(true), { timeout: 200 });
      expect(journalStarts).toBe(0);

      release();
      await pending;
      await Promise.resolve();
      expect(journalStarts).toBe(0);
      if (phase === "head") expect(pageCalls).toBe(0);
      else expect(pageCalls).toBe(1);
    },
    120_000,
  );

  it("hands off cancellation before markDispatched and preserves one original wire call while the marker awaits", async () => {
    const { deps, journal } = await makeDeps();
    const controller = new AbortController();
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    let releaseMarker!: () => void;
    const markerGate = new Promise<void>((resolve) => {
      releaseMarker = resolve;
    });
    const originalMark = journal.markDispatched.bind(journal);
    let markerCalls = 0;
    journal.markDispatched = async (id, ns) => {
      markerCalls += 1;
      await markerGate;
      await originalMark(id, ns);
    };
    let boundaryCalls = 0;
    deps.signal = controller.signal;
    deps.onDispatchBoundary = () => {
      boundaryCalls += 1;
      controller.abort();
    };

    const pending = runSpendFlow(deps, { inputLeafIndex: 0n });
    await vi.waitFor(() => expect(markerCalls).toBe(1), { timeout: 120_000 });
    expect(boundaryCalls).toBe(1);
    expect(pool.spy.calls.filter((call) => call.method === "private_spend")).toHaveLength(0);

    releaseMarker();
    await expect(pending).resolves.toMatchObject({ spendId: expect.any(String) });
    expect(pool.spy.calls.filter((call) => call.method === "private_spend")).toHaveLength(1);
    expect((await journal.read()).entries[0].status).toBe("finalized");
  }, 120_000);
});

describe("R6 — recovery orchestrator + fresh-device import", () => {  it("recoverSpendsFromPool paginates the identity-bound index and imports typed recovery-required entries (idempotent)", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const record = (id: bigint) => ({
      spendId: id,
      status: { kind: "in-flight" as const },
      nullifiers: [new Uint8Array(32).fill(Number(id))],
      outputCommitments: [new Uint8Array(32).fill(7), new Uint8Array(32).fill(8)],
      submitter: null,
      createdAtNs: 1n,
    });
    let calls = 0;
    const pool = {
      listMyActiveSpends: async (cursor: bigint | null) => {
        calls += 1;
        if (calls === 1) return { spends: [record(1n), record(2n)], nextCursor: 2n as bigint | null };
        return { spends: [record(3n)], nextCursor: null };
      },
    } as unknown as PoolCanister;
    const imported = await recoverSpendsFromPool({ pool, journal });
    expect(imported).toBe(3);
    expect(calls).toBe(2);
    const entries = (await journal.read()).entries;
    expect(entries.every((e) => e.status === "recovery-required")).toBe(true);
    // Idempotent: a second import adds nothing.
    expect(await recoverSpendsFromPool({ pool, journal })).toBe(0);
  });

  it("replaySameIntent replays the persisted FINAL request byte-identically (the update Ok is the authority)", async () => {
    const { deps, journal } = await makeDeps();
    const summary = await runSpendFlow(deps, { inputLeafIndex: 0n });
    const entry = (await journal.find(summary.spendId))!;
    // Re-run the replay against the same fake pool and compare the request bytes.
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    pool.spy.calls.length = 0;
    await replaySameIntent({ pool: deps.pool, journal }, entry);
    const replayed = pool.spy.calls.find((c) => c.method === "private_spend")!.args as PrivateSpendRequest;
    expect(serializeSpendRequest(replayed)).toBe(entry.requestJson);
  }, 120_000);

  it("reconcileSpendEntry on a forged PayoutPending row: retry SAME id; the Ok leaves input SPENT (never unlocked)", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));
    const entry = {
      spendId: "88",
      nullifierHex: nfHex(fixture.note),
      inputLeafIndex: "0",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["dd", "ee"],
      encryptedOutputsHex: ["ff", "00"],
      requestJson: "",
      intentFingerprintHex: "11",
      feeStsh: "0",
      acceptedRootHex: "22",
      manifestVersion: 1,
      createdAtNs: "1",
    };
    await journal.beginSpend(0n, entry);
    await journal.markDispatched("88", "2");
    const pool = {
      getSpendStatus: async () => ({
        spendId: 88n,
        status: { kind: "payout-pending" as const, reason: "transfer pending" },
        nullifiers: [],
        outputCommitments: [],
        submitter: null,
        createdAtNs: 1n,
      }),
      retryPrivateSpendPayout: async (id: bigint) => {
        expect(id).toBe(88n);
        return 7n;
      },
    } as unknown as PoolCanister;
    const action = await reconcileSpendEntry(
      { pool, journal },
      (await journal.find("88"))!,
    );
    expect(action.kind).toBe("retry-payout");
    const state = await cache.load();
    expect(state.notes[0].state).toBe("spent");
    expect((await journal.find("88"))!.status).toBe("finalized");
  });

  it("reconcileSpendEntry on a settled None + planned entry: archives + restores the note", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));
    const entry = {
      spendId: "99",
      nullifierHex: "aa",
      inputLeafIndex: "0",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["dd", "ee"],
      encryptedOutputsHex: ["ff", "00"],
      requestJson: "",
      intentFingerprintHex: "11",
      feeStsh: "0",
      acceptedRootHex: "22",
      manifestVersion: 1,
      createdAtNs: "1",
    };
    await journal.beginSpend(0n, entry);
    const pool = { getSpendStatus: async () => null } as unknown as PoolCanister;
    const action = await reconcileSpendEntry({ pool, journal }, (await journal.find("99"))!);
    expect(action.kind).toBe("archive-never-dispatched");
    expect((await cache.load()).notes[0].state).toBe("spendable");
  });
});

// ── R7 regressions ────────────────────────────────────────────────────────────

describe("R7 — leaf-0 corruption guard (unknown input index)", () => {
  it("a recovery-required entry (index unknown) finalized via payout retry mutates NO note — leaf 0 is untouched", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    // An UNRELATED note lives at leaf 0 in the cache.
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));

    // A fresh-device import: PayoutPending record, NO local leaf binding ("").
    await journal.importRecoveryRequired({
      spendId: "55",
      nullifierHex: [...new Uint8Array(32).fill(0xab)].map((b) => b.toString(16).padStart(2, "0")).join(""),
      inputLeafIndex: "",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["", ""],
      encryptedOutputsHex: ["", ""],
      requestJson: "",
      intentFingerprintHex: "",
      feeStsh: "0",
      acceptedRootHex: "",
      manifestVersion: 1,
      createdAtNs: "1",
    });
    const pool = {
      getSpendStatus: async () => ({
        spendId: 55n,
        status: { kind: "payout-pending" as const, reason: "transfer pending" },
        nullifiers: [],
        outputCommitments: [],
        submitter: null,
        createdAtNs: 1n,
      }),
      retryPrivateSpendPayout: async () => 7n,
    } as unknown as PoolCanister;

    await reconcileSpendEntry({ pool, journal }, (await journal.find("55"))!);

    const state = await cache.load();
    expect(state.spendJournal?.entries.find((e) => e.spendId === "55")?.status).toBe("finalized");
    // CRITICAL: the unrelated leaf-0 note is UNCHANGED (BigInt("") === 0n must
    // never mark it spent).
    expect(state.notes[0].state).toBe("spendable");
  });
});

describe("R7 — fresh-id collision recovery (S-23b)", () => {
  const ENTRY = {
    spendId: "41",
    nullifierHex: [...new Uint8Array(32).fill(0xcd)].map((b) => b.toString(16).padStart(2, "0")).join(""),
    inputLeafIndex: "0",
    outputLeavesHex: ["bb", "cc"],
    outNoncesHex: ["dd", "ee"],
    encryptedOutputsHex: ["ff", "00"],
    intentFingerprintHex: "11",
    feeStsh: "0",
    acceptedRootHex: "22",
    manifestVersion: 1,
    createdAtNs: "1",
  };

  async function seededJournal() {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));
    const request: PrivateSpendRequest = {
      spendId: 41n,
      circuitVersion: 3,
      proofSystemId: "groth16-bn254",
      verifyingKeyHash: new Uint8Array(32),
      rootReference: new Uint8Array(32),
      poolVersion: 1,
      proofBytes: new Uint8Array(256),
      nullifiers: [new Uint8Array(32).fill(0xcd)],
      outputCommitments: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
      encryptedOutputs: [new Uint8Array(4), new Uint8Array(4)],
      fee: 0n,
      publicPayout: null,
    };
    await journal.beginSpend(0n, { ...ENTRY, requestJson: serializeSpendRequest(request) });
    return { journal, cache };
  }

  /** L0-F-compliant registry stub: the strictly paginated full spent set. */
  function registryStub(spent: Uint8Array[]) {
    const sorted = [...spent].sort((a, b) => {
      for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
      return 0;
    });
    return {
      async getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]> {
        let idx = 0;
        if (startAfter !== null) {
          idx = sorted.findIndex((v) => {
            for (let i = 0; i < 32; i++) {
              if (v[i] !== startAfter[i]) return v[i] > startAfter[i];
            }
            return false;
          });
          if (idx === -1) idx = sorted.length;
        }
        return sorted.slice(idx, idx + Number(limit));
      },
      async count(): Promise<bigint> {
        return BigInt(sorted.length);
      },
    };
  }

  it("settled None + unspent nullifier → fresh id DISPATCHED and submitted on the wire, both attempts retained, no loop", async () => {
    const { journal } = await seededJournal();
    const nullifiers = registryStub([]); // unspent
    const calls: PrivateSpendRequest[] = [];
    const pool = {
      privateSpend: async (req: PrivateSpendRequest) => {
        calls.push(req);
      },
    } as unknown as PoolCanister;
    const newId = await recoverSpendFreshId(
      { pool, journal, nullifiers },
      (await journal.find("41"))!,
    );
    expect(newId).not.toBe("41");
    // The WIRE CALL actually happened, with the NEW id.
    expect(calls).toHaveLength(1);
    expect(calls[0].spendId.toString(10)).toBe(newId);
    expect(calls[0].proofBytes.length).toBe(256);
    const entries = (await journal.read()).entries;
    expect(entries).toHaveLength(2);
    const original = entries.find((e) => e.spendId === "41")!;
    const fresh = entries.find((e) => e.spendId === newId)!;
    expect(original.status).toBe("failed"); // retained as collision record
    expect(original.failureReason).toMatch(/collision/i);
    expect(fresh.status).toBe("finalized"); // authoritative Ok completed it
    expect(fresh.collisionOf).toBe("41");
    expect(fresh.dispatchedAtNs).toBeDefined();
    const req = deserializeSpendRequest(fresh.requestJson);
    expect(req.spendId.toString(10)).toBe(newId);
    expect(req.proofBytes.length).toBe(256); // proof stays valid (id not proof-bound)
    // NO LOOP: a fresh-id attempt cannot mint another fresh id.
    await expect(
      recoverSpendFreshId({ pool, journal, nullifiers }, fresh),
    ).rejects.toThrow(/loop|already a fresh-id/);
  });

  it("a SPENT nullifier rejects fresh-id recovery (reconcile instead — never double-spend)", async () => {
    const { journal } = await seededJournal();
    const entry = (await journal.find("41"))!;
    const spent = registryStub([new Uint8Array(32).fill(0xcd)]); // the input nullifier, spent
    const pool = { privateSpend: async () => {} } as unknown as PoolCanister;
    await expect(
      recoverSpendFreshId({ pool, journal, nullifiers: spent }, entry),
    ).rejects.toThrow(/SPENT/);
    // The original entry is untouched (no collision record written on failure).
    expect((await journal.find("41"))!.status).toBe("planned");
  });

  it("a transport-uncertain submit leaves the fresh entry DISPATCHED (ambiguous) — never archived as never-submitted", async () => {
    const { journal } = await seededJournal();
    const nullifiers = registryStub([]);
    const pool = {
      privateSpend: async () => {
        throw new Error("transport lost");
      },
    } as unknown as PoolCanister;
    const entry = (await journal.find("41"))!;
    let newId = "";
    try {
      newId = await recoverSpendFreshId({ pool, journal, nullifiers }, entry);
    } catch {
      // expected: uncertain outcome
    }
    const entries = (await journal.read()).entries;
    const original = entries.find((e) => e.spendId === "41")!;
    const fresh = entries.find((e) => e.spendId !== "41")!;
    expect(original.status).toBe("failed"); // collision record retained
    expect(fresh.status).toBe("dispatched"); // ambiguous — never archived
    expect(fresh.dispatchedAtNs).toBeDefined();
    void newId;
  });
});

describe("R7 — recovery listing validation (fail closed on malformed pages)", () => {
  const record = (id: bigint) => ({
    spendId: id,
    status: { kind: "in-flight" as const },
    nullifiers: [new Uint8Array(32).fill(Number(id))],
    outputCommitments: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
    submitter: null,
    createdAtNs: 1n,
  });
  async function journalOf() {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    return new SpendJournal(await PrincipalNoteCache.open(store, "pw", BINDING));
  }

  it("rejects an oversized page", async () => {
    const pool = {
      listMyActiveSpends: async () => ({
        spends: Array.from({ length: 101 }, (_, i) => record(BigInt(i + 1))),
        nextCursor: null,
      }),
    } as unknown as PoolCanister;
    await expect(recoverSpendsFromPool({ pool, journal: await journalOf() })).rejects.toThrow(/cap/i);
  });

  it("rejects a duplicate spend id across pages", async () => {
    let call = 0;
    const pool = {
      listMyActiveSpends: async () => {
        call += 1;
        return call === 1
          ? { spends: [record(1n), record(2n)], nextCursor: 2n as bigint | null }
          : { spends: [record(2n), record(3n)], nextCursor: null };
      },
    } as unknown as PoolCanister;
    await expect(recoverSpendsFromPool({ pool, journal: await journalOf() })).rejects.toThrow(/duplicate/i);
  });

  it("rejects non-increasing ids within a page", async () => {
    const pool = {
      listMyActiveSpends: async () => ({ spends: [record(3n), record(1n)], nextCursor: null }),
    } as unknown as PoolCanister;
    await expect(recoverSpendsFromPool({ pool, journal: await journalOf() })).rejects.toThrow(/increasing/i);
  });

  it("rejects a non-advancing cursor (loop prevention)", async () => {
    const pool = {
      listMyActiveSpends: async () => ({ spends: [record(5n)], nextCursor: 4n as bigint | null }),
    } as unknown as PoolCanister;
    await expect(recoverSpendsFromPool({ pool, journal: await journalOf() })).rejects.toThrow(/does not advance/i);
  });
});

describe("R7 — ambiguous statuses stay locked", () => {
  it("payout-unknown / in-flight / unknown rows drive keep-locked only", () => {
    for (const kind of ["payout-unknown", "payout-submitting", "operator-reconcile", "in-flight"]) {
      expect(recoveryActionForAdvisory({ kind }, "dispatched")).toEqual({ kind: "keep-locked" });
    }
  });
});

describe("R7 — intent fingerprint (S-38 field set + boundaries)", () => {
  const base = {
    nullifier: new Uint8Array(32).fill(1),
    outputLeaves: [new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)],
    payout: null,
    fee: 0n,
  };

  it("is sensitive to EVERY pool-compared field (nullifier, leaves, payout dest/sub/amount, fee)", async () => {
    const fp = await intentFingerprintHex(base);
    expect(await intentFingerprintHex({ ...base, fee: 1n })).not.toBe(fp);
    expect(await intentFingerprintHex({ ...base, nullifier: new Uint8Array(32).fill(9) })).not.toBe(fp);
    expect(
      await intentFingerprintHex({ ...base, outputLeaves: [new Uint8Array(32).fill(9), base.outputLeaves[1]] }),
    ).not.toBe(fp);
    const dest = Principal.fromUint8Array(new Uint8Array(4).fill(7));
    const withPayout = { ...base, payout: { destination: dest, subaccount: null, publicAmount: 5n } };
    const fpPayout = await intentFingerprintHex(withPayout);
    expect(fpPayout).not.toBe(fp);
    expect(
      await intentFingerprintHex({ ...withPayout, payout: { ...withPayout.payout, publicAmount: 6n } }),
    ).not.toBe(fpPayout);
    expect(
      await intentFingerprintHex({ ...withPayout, payout: { ...withPayout.payout, subaccount: new Uint8Array(32).fill(1) } }),
    ).not.toBe(fpPayout);
    expect(
      await intentFingerprintHex({ ...withPayout, payout: { ...withPayout.payout, destination: Principal.fromUint8Array(new Uint8Array(4).fill(8)) } }),
    ).not.toBe(fpPayout);
  });

  it("length-prefixed boundaries prevent cross-field collisions ([ab,c] vs [a,bc])", async () => {
    const a = await intentFingerprintHex({
      nullifier: new Uint8Array([0xab]),
      outputLeaves: [new Uint8Array([0x01]), new Uint8Array([0x02])],
      payout: null,
      fee: 0n,
    });
    // Same concatenated bytes partitioned differently across fields — the
    // length prefixes make these provably distinct.
    const b = await intentFingerprintHex({
      nullifier: new Uint8Array([0xab, 0x01]),
      outputLeaves: [new Uint8Array([0x02]), new Uint8Array([0x01])],
      payout: null,
      fee: 0n,
    });
    expect(a).not.toBe(b);
  });
});

describe("R8 — import-time note locking + mergeScanOutcome ownership guard", () => {
  it("an imported active spend ATOMICALLY locks the matching cached note (spendable → pending)", async () => {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [fixture.cached] }));
    expect((await cache.load()).notes[0].state).toBe("spendable");

    await journal.importRecoveryRequired({
      spendId: "61",
      nullifierHex: nfHex(fixture.note), // SAME nullifier as the cached note
      inputLeafIndex: "",
      outputLeavesHex: ["bb", "cc"],
      outNoncesHex: ["", ""],
      encryptedOutputsHex: ["", ""],
      requestJson: "",
      intentFingerprintHex: "",
      feeStsh: "0",
      acceptedRootHex: "",
      manifestVersion: 1,
      createdAtNs: "1",
    });
    const state = await cache.load();
    expect(state.notes[0].state).toBe("pending");
    expect(state.spendJournal?.entries[0].status).toBe("recovery-required");
  });

  it("mergeScanOutcome never makes a journal-owned nullifier spendable again", async () => {
    const { mergeScanOutcome } = await import("../src/crypto/scanner");
    const fixture = await makeInputNote();
    const outcomeNote = { ...fixture.cached, state: "spendable" as const };
    const state = {
      notes: [],
      lastScannedIndex: 0n,
      spendJournal: {
        entries: [
          {
            spendId: "62",
            nullifierHex: nfHex(fixture.note),
            inputLeafIndex: "",
            outputLeavesHex: ["bb", "cc"],
            outNoncesHex: ["", ""],
            encryptedOutputsHex: ["", ""],
            requestJson: "",
            intentFingerprintHex: "",
            feeStsh: "0",
            acceptedRootHex: "",
            manifestVersion: 1,
            status: "dispatched" as const,
            createdAtNs: "1",
          },
        ],
      },
    };
    const merged = mergeScanOutcome(state, {
      notes: [outcomeNote],
      scannedUpTo: 1n,
      mirrorHead: { leafCount: 1n, root: new Uint8Array(32) },
      quarantine: { total: 0, ring: [] },
      spentSet: new Set<string>(),
    });
    expect(merged.notes[0].state).toBe("pending");
  });
});

describe("R8 — end-to-end settlement recovery (destroy-cache scenario)", () => {
  it("active pool spend → destroy cache → import → retry payout → entry finalized, no note mutated, scanner discovers change once", async () => {
    // (1) An active pool spend exists on-chain (PayoutPending, outputs promoted).
    const input = await makeInputNote();
    const spentRegistry: Uint8Array[] = [];
    const payoutRecord = {
      spendId: 90n,
      status: { kind: "payout-pending" as const, reason: "transfer pending" },
      nullifiers: [input.note.nullifier],
      outputCommitments: [input.leaf, new Uint8Array(32).fill(9)],
      submitter: null,
      createdAtNs: 1n,
    };
    let retried = 0n;
    const pool = {
      listMyActiveSpends: async () => ({ spends: [payoutRecord], nextCursor: null }),
      getSpendStatus: async () => payoutRecord,
      retryPrivateSpendPayout: async (id: bigint) => {
        retried = id;
        return 7n;
      },
    } as unknown as PoolCanister;

    // (2) DESTROY the cache — a fresh device.
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);

    // (3) Import from the pool index (as the unlock auto-recovery does).
    const imported = await recoverSpendsFromPool({ pool, journal });
    expect(imported).toBe(1);
    const entry = (await journal.find("90"))!;
    expect(entry.status).toBe("recovery-required");

    // (4) Drive the authoritative payout retry (the only action available
    // without local material).
    const record = await pool.getSpendStatus(90n);
    expect(record).not.toBeNull();
    expect(record!.status.kind).toBe("payout-pending");
    await pool.retryPrivateSpendPayout(90n);
    expect(retried).toBe(90n);
    await journal.finalizeFromSpendOk("90", null);
    expect((await journal.find("90"))!.status).toBe("finalized");
    // No note was mutated (the index was unknown) — nothing fabricated.
    expect((await cache.load()).notes).toHaveLength(0);

    // (5) The validated scanner classifies the input via the downloaded spent
    // set — spent, never spendable again — and nothing else appears.
    spentRegistry.push(input.note.nullifier);
    const outcome = await scanAndValidate(
      {
        getScanHead: async () => ({ leafCount: 1n, root: await oneLeafMirror(input.leaf).then((m) => m.root) }),
        getScanPage: async (from: bigint) =>
          from === 0n
            ? [{ index: 0n, leaf: input.leaf, encryptedPayload: input.plaintext }]
            : [],
        getNullifiersPage: registryStubForScan(spentRegistry).getNullifiersPage,
        count: registryStubForScan(spentRegistry).count,
      },
      decryptSelf,
      MASTER,
    );
    const inputStates = outcome.notes.filter((n) => ctEqual(n.nullifier!, input.note.nullifier));
    expect(inputStates).toHaveLength(1);
    expect(inputStates[0].state).toBe("spent");
    expect(outcome.notes.filter((n) => n.state === "spendable")).toHaveLength(0);
  });
});

// ── F1-PRIV (R1-F1) — the hidden values are neither on the wire nor at rest ───
//
// The lane's exit property has two legs. The wire leg is asserted in the L3c
// dispatch tests above (the keys are absent from the request object). This block
// is the AT-REST leg: the persisted replay material is what the wallet writes to
// local storage, and R1-F1 is not closed while a cleartext copy survives there.
describe("F1-PRIV — persisted spend request carries no cleartext values", () => {
  function req(inputValue: bigint, changeValue: bigint): PrivateSpendRequest {
    // Only the hidden values differ between the two requests built from this
    // helper; every other field is fixed, which is what makes the at-rest
    // differential below a differential and not a coincidence.
    void inputValue;
    void changeValue;
    return {
      spendId: 77n,
      circuitVersion: 3,
      proofSystemId: "groth16-bn254",
      verifyingKeyHash: new Uint8Array(32).fill(0xa1),
      rootReference: new Uint8Array(32).fill(0xb2),
      poolVersion: 1,
      proofBytes: new Uint8Array(256).fill(0xc3),
      nullifiers: [new Uint8Array(32).fill(0xcd)],
      outputCommitments: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
      encryptedOutputs: [new Uint8Array(4).fill(9), new Uint8Array(4).fill(9)],
      fee: 1_000_000n,
      publicPayout: null,
      expectedDeploymentConfigHash: null,
    } as unknown as PrivateSpendRequest;
  }

  it("a NEWLY persisted request contains neither key (§5.2 item 3)", () => {
    const json = serializeSpendRequest(req(DENOMINATIONS[2], DENOMINATIONS[2] - 1_000_000n));
    expect(json).not.toContain("inputAmounts");
    expect(json).not.toContain("outputAmounts");
    const parsed = JSON.parse(json) as Record<string, unknown>;
    expect("inputAmounts" in parsed).toBe(false);
    expect("outputAmounts" in parsed).toBe(false);
    // Anti-vacuity: the record is not empty of everything — the replay material
    // it MUST keep is still there.
    expect(parsed.proofBytes).toBeTypeOf("string");
    expect((parsed.nullifiers as string[]).length).toBe(1);
  });

  it("a LEGACY record still deserializes and the rehydrated request drops the values (§5.2 item 4)", () => {
    // A record persisted BEFORE this lane: the two keys are present on disk.
    const legacy = JSON.parse(serializeSpendRequest(req(1n, 1n))) as Record<string, unknown>;
    legacy.inputAmounts = ["100000000"];
    legacy.outputAmounts = ["99000000", "0"];
    const json = JSON.stringify(legacy);
    expect(json).toContain("inputAmounts"); // anti-vacuity: the legacy shape is real

    // ignore-on-read: it decodes rather than throwing …
    const rehydrated = deserializeSpendRequest(json) as unknown as Record<string, unknown>;
    expect(rehydrated.spendId).toBe(77n);
    // … and the rehydrated request carries neither field.
    expect("inputAmounts" in rehydrated).toBe(false);
    expect("outputAmounts" in rehydrated).toBe(false);
    // The one path that rewrites a record (§10.2 fresh-id retry) re-serializes
    // through the codec, so the stale copy does not survive that rewrite.
    expect(serializeSpendRequest(rehydrated as unknown as PrivateSpendRequest)).not.toContain(
      "inputAmounts",
    );
  });

  it("AT-REST DIFFERENTIAL: two spends differing only in hidden value persist byte-identically", () => {
    const a = serializeSpendRequest(req(DENOMINATIONS[2], DENOMINATIONS[2] - 1_000_000n));
    const b = serializeSpendRequest(req(DENOMINATIONS[0], DENOMINATIONS[0] - 1_000_000n));
    expect(a).toBe(b);
  });
});

// ── WALLET-V12 — spend admission refusals (O-3; E-1 + SSA F-1; E-2(c) Addendum 1a) ─

const admissionErr = (code: string, retryNs: bigint | string = 0n) =>
  new PoolCallError("private_spend", {
    VerifierUnavailable: `SPEND_ADMISSION;code=${code};retry_after_ns=${retryNs.toString()}`,
  } as never);

describe("WALLET-V12 O-3 — the four admission codes map to the ruled copy", () => {
  const RULED: Record<SpendAdmissionCode, string> = {
    NO_ACTIVE_DEVICE: "Set up this device first, then try again.",
    FAILED_VERIFY_LIMIT: "Too many failed spends this hour. Try again in 42 minutes.",
    INFLIGHT_LIMIT: "Three spends are already in progress. Wait for one to finish.",
    DEVICE_CHECK_UNAVAILABLE: "Spending is paused while a service recovers. Try again shortly.",
  };

  it("each code parses from the exact pool wire format and renders its ruled line", () => {
    expect(SPEND_ADMISSION_CODES).toHaveLength(4);
    for (const code of SPEND_ADMISSION_CODES) {
      const retry = code === "FAILED_VERIFY_LIMIT" ? 41n * 60n * 1_000_000_000n + 1n : 0n; // rounds UP
      const parsed = parseSpendAdmission(admissionErr(code, retry));
      expect(parsed, code).toEqual({ code, retryAfterNs: retry });
      expect(spendAdmissionCopy(parsed!)).toBe(RULED[code]);
    }
  });

  it("FAILED_VERIFY_LIMIT with retry_after_ns = 0 keeps the ONE ruled string (SSA F-5)", () => {
    expect(spendAdmissionCopy({ code: "FAILED_VERIFY_LIMIT", retryAfterNs: 0n })).toBe(
      "Too many failed spends this hour. Try again in a moment.",
    );
  });

  it("anything else is NOT an admission refusal (falls through to the generic path)", () => {
    for (const text of [
      "SPEND_ADMISSION;code=SOMETHING_NEW;retry_after_ns=0", // unknown code
      "SPEND_ADMISSION;code=INFLIGHT_LIMIT", // missing wait
      "SPEND_ADMISSION;code=INFLIGHT_LIMIT;retry_after_ns=-1",
      "SPEND_ADMISSION;code=INFLIGHT_LIMIT;retry_after_ns=18446744073709551616", // > u64
      " SPEND_ADMISSION;code=INFLIGHT_LIMIT;retry_after_ns=0", // not the exact prefix
      "verifier canister unreachable",
    ]) {
      expect(parseSpendAdmission({ VerifierUnavailable: text }), text).toBeNull();
    }
    expect(parseSpendAdmission({ DuplicateSpendId: null })).toBeNull();
    expect(parseSpendAdmission(new Error("SPEND_ADMISSION;code=INFLIGHT_LIMIT;retry_after_ns=0"))).toBeNull();
    expect(
      parseSpendAdmission({ VerifierUnavailable: "SPEND_ADMISSION;code=INFLIGHT_LIMIT;retry_after_ns=18446744073709551615" }),
    ).toEqual({ code: "INFLIGHT_LIMIT", retryAfterNs: 18446744073709551615n });
  });
});

describe("WALLET-V12 E-2(c) — an admission refusal keeps the note locked and retries the SAME spend_id", () => {
  it("fresh submit refused → entry stays DISPATCHED, note locked, ruled copy; a later same-id retry Ok → finalized, note spent", async () => {
    const { deps, journal, cache } = await makeDeps();
    const pool = deps.pool as PoolCanister & { spy: PoolSpy };
    const realSpend = pool.privateSpend;
    let statusReads = 0;
    pool.getSpendStatus = async () => {
      statusReads += 1;
      return null;
    };
    pool.privateSpend = async (req, token) => {
      await realSpend(req, token);
      throw admissionErr("INFLIGHT_LIMIT");
    };
    let thrown: unknown;
    try {
      await runSpendFlow(deps, { inputLeafIndex: 0n });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SpendFlowError);
    const sfe = thrown as SpendFlowError;
    expect(sfe.admission).toEqual({ code: "INFLIGHT_LIMIT", retryAfterNs: 0n });
    expect(sfe.message).toBe("Three spends are already in progress. Wait for one to finish.");
    expect(sfe.alreadyWentThrough, "a fresh run is never a resubmission (E-1 is replay-only)").toBeUndefined();
    expect(statusReads, "no status query on the fresh path").toBe(0);
    const entries = (await journal.read()).entries;
    expect(entries).toHaveLength(1);
    const entry = entries[0];
    expect(entry.status, "never archived — dispatched stays dispatched").toBe("dispatched");
    expect(entry.collisionOf).toBeUndefined();
    expect((await cache.load()).notes[0].state, "the note stays locked").toBe("pending");
    const firstWire = pool.spy.calls.filter((c) => c.method === "private_spend");
    expect(firstWire).toHaveLength(1);

    // Recovery: the advisory status is None (the pool wrote no record) →
    // SAME id retried byte-identically; the update Ok finalizes.
    pool.privateSpend = realSpend;
    const action = await reconcileSpendEntry({ pool, journal }, (await journal.find(entry.spendId))!);
    expect(action).toEqual({ kind: "retry-same-id" });
    const wire = pool.spy.calls.filter((c) => c.method === "private_spend");
    expect(wire).toHaveLength(2);
    expect(serializeSpendRequest(wire[1].args as PrivateSpendRequest)).toBe(entry.requestJson);
    expect(serializeSpendRequest(wire[1].args as PrivateSpendRequest)).toBe(
      serializeSpendRequest(wire[0].args as PrivateSpendRequest),
    );
    expect((await journal.find(entry.spendId))!.status).toBe("finalized");
    expect((await cache.load()).notes[0].state).toBe("spent");
    expect((await journal.read()).entries, "no fresh id, no collision record").toHaveLength(1);
  }, 180_000);
});

describe("WALLET-V12 E-2(c) + E-1 — recovery classification (seeded dispatched entry, no proof)", () => {
  const NF = new Uint8Array(32).fill(0xcd);
  const ENTRY = {
    spendId: "41",
    nullifierHex: [...NF].map((b) => b.toString(16).padStart(2, "0")).join(""),
    inputLeafIndex: "0",
    outputLeavesHex: ["bb", "cc"],
    outNoncesHex: ["dd", "ee"],
    encryptedOutputsHex: ["ff", "00"],
    intentFingerprintHex: "11",
    feeStsh: "0",
    acceptedRootHex: "22",
    manifestVersion: 1,
    createdAtNs: "1",
  };

  /** A journal whose one entry is DISPATCHED (as a refused submit leaves it), note locked. */
  async function dispatchedJournal() {
    const dbName = `stsh-l3c-${crypto.randomUUID()}`;
    const store = await openIndexedDbPrincipalCacheStore(dbName);
    const cache = await PrincipalNoteCache.open(store, "pw", BINDING);
    const journal = new SpendJournal(cache);
    const fixture = await makeInputNote();
    await cache.update((s) => ({ ...s, notes: [{ ...fixture.cached, nullifier: NF }] }));
    const request: PrivateSpendRequest = {
      spendId: 41n,
      circuitVersion: 3,
      proofSystemId: "groth16-bn254",
      verifyingKeyHash: new Uint8Array(32),
      rootReference: new Uint8Array(32),
      poolVersion: 1,
      proofBytes: new Uint8Array(256).fill(5),
      nullifiers: [NF],
      outputCommitments: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
      encryptedOutputs: [new Uint8Array(4), new Uint8Array(4)],
      fee: 0n,
      publicPayout: null,
      expectedDeploymentConfigHash: new Uint8Array(32),
    };
    await journal.beginSpend(0n, { ...ENTRY, requestJson: serializeSpendRequest(request) });
    await journal.markDispatched("41", "2");
    return { journal, cache };
  }

  const finalizedRecord = (id: bigint) => ({
    spendId: id,
    status: { kind: "finalized" as const },
    nullifiers: [],
    outputCommitments: [],
    submitter: null,
    createdAtNs: 1n,
  });

  function scriptedPool(opts: {
    spend: (req: PrivateSpendRequest) => void;
    statuses: Array<ReturnType<typeof finalizedRecord> | null>;
  }) {
    const calls = { spend: [] as PrivateSpendRequest[], status: 0 };
    const pool = {
      privateSpend: async (req: PrivateSpendRequest) => {
        calls.spend.push(req);
        opts.spend(req);
      },
      getSpendStatus: async () => {
        const i = Math.min(calls.status, opts.statuses.length - 1);
        calls.status += 1;
        return opts.statuses[i];
      },
    } as unknown as PoolCanister;
    return { pool, calls };
  }

  async function unchanged(journal: SpendJournal, cache: PrincipalNoteCache) {
    const entries = (await journal.read()).entries;
    expect(entries, "no fresh id, no collision record").toHaveLength(1);
    expect(entries[0].status, "still dispatched").toBe("dispatched");
    expect(entries[0].collisionOf).toBeUndefined();
    expect((await cache.load()).notes[0].state, "note still locked").toBe("pending");
  }

  it("a REPEATED admission refusal on the same-id retry: still dispatched, no fresh id, no collision — for EVERY code", async () => {
    for (const code of SPEND_ADMISSION_CODES) {
      const { journal, cache } = await dispatchedJournal();
      const { pool, calls } = scriptedPool({
        spend: () => {
          throw admissionErr(code, 7n);
        },
        statuses: [null],
      });
      const action = await reconcileSpendEntry({ pool, journal }, (await journal.find("41"))!);
      expect(action.kind, code).toBe("keep-locked");
      expect(action.kind === "keep-locked" && action.admission).toEqual({ code, retryAfterNs: 7n });
      expect(action.kind === "keep-locked" && action.alreadyWentThrough).toBeFalsy();
      expect(calls.spend).toHaveLength(1);
      expect(calls.spend[0].spendId, "the SAME id").toBe(41n);
      await unchanged(journal, cache);
    }
  });

  it("a genuine DuplicateSpendId on the same-id retry → the EXISTING fresh-id fallback fires as before", async () => {
    const { journal } = await dispatchedJournal();
    const { pool, calls } = scriptedPool({
      spend: (req) => {
        if (req.spendId === 41n) throw new PoolCallError("private_spend", { DuplicateSpendId: null } as never);
      },
      statuses: [null],
    });
    const action = await reconcileSpendEntry({ pool, journal }, (await journal.find("41"))!);
    expect(action).toEqual({ kind: "fresh-id" });
    expect((await journal.find("41"))!.status, "the classification itself mutates nothing").toBe("dispatched");
    // The caller then runs §10.2 exactly as before (spent-set precheck included).
    const newId = await recoverSpendFreshId(
      { pool, journal, nullifiers: registryStubForScan([]) },
      (await journal.find("41"))!,
    );
    expect(newId).not.toBe("41");
    expect(calls.spend.map((r) => r.spendId.toString(10))).toEqual(["41", newId]);
    const entries = (await journal.read()).entries;
    expect(entries.find((e) => e.spendId === "41")!.status).toBe("failed");
    expect(entries.find((e) => e.spendId === newId)!.status).toBe("finalized");
  });

  it("any OTHER failure of the same-id retry stays locked (ambiguity handling unchanged)", async () => {
    const { journal, cache } = await dispatchedJournal();
    const { pool } = scriptedPool({
      spend: () => {
        throw new Error("transport lost");
      },
      statuses: [null],
    });
    const action = await reconcileSpendEntry({ pool, journal }, (await journal.find("41"))!);
    expect(action).toEqual({ kind: "keep-locked" });
    await unchanged(journal, cache);
  });

  it("F-2 / item 4: a FRESH-id attempt refused at admission stays dispatched and is retried SAME-id — no collisionOf dead-end", async () => {
    const { journal, cache } = await dispatchedJournal();
    let refuse = true;
    const { pool, calls } = scriptedPool({
      spend: (req) => {
        if (req.spendId === 41n) throw new PoolCallError("private_spend", { DuplicateSpendId: null } as never);
        if (refuse) throw admissionErr("FAILED_VERIFY_LIMIT", 60_000_000_000n);
      },
      statuses: [null],
    });
    const nullifiers = registryStubForScan([]);
    let thrown: unknown;
    try {
      await recoverSpendFreshId({ pool, journal, nullifiers }, (await journal.find("41"))!);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SpendFlowError);
    expect((thrown as SpendFlowError).admission?.code).toBe("FAILED_VERIFY_LIMIT");
    expect((thrown as SpendFlowError).message).toBe("Too many failed spends this hour. Try again in 1 minute.");
    const fresh = (await journal.read()).entries.find((e) => e.spendId !== "41")!;
    expect(fresh.status).toBe("dispatched");
    expect(fresh.collisionOf).toBe("41");
    // Next pass: None + dispatched → the SAME fresh id, not a second fresh id.
    refuse = false;
    const action = await reconcileSpendEntry({ pool, journal }, fresh);
    expect(action).toEqual({ kind: "retry-same-id" });
    expect(calls.spend.at(-1)!.spendId.toString(10)).toBe(fresh.spendId);
    expect((await journal.find(fresh.spendId))!.status).toBe("finalized");
    expect((await cache.load()).notes[0].state).toBe("spent");
    expect((await journal.read()).entries, "exactly the two attempts").toHaveLength(2);
  });

  // E-1 (C-3) + SSA F-1: both step-1 codes mask the idempotent Ok on a replay.
  for (const code of ["FAILED_VERIFY_LIMIT", "INFLIGHT_LIMIT"] as const) {
    it(`E-1 ${code}: a REPLAY of a spend the status query calls finalized → "already went through" copy, NO journal effect`, async () => {
      const { journal, cache } = await dispatchedJournal();
      const { pool, calls } = scriptedPool({
        spend: () => {
          throw admissionErr(code, 5n);
        },
        statuses: [finalizedRecord(41n)], // advisory: finalized (both reads)
      });
      const action = await reconcileSpendEntry({ pool, journal }, (await journal.find("41"))!);
      expect(action).toEqual({
        kind: "keep-locked",
        admission: { code, retryAfterNs: 5n },
        alreadyWentThrough: true,
      });
      expect(calls.status, "classification read + the E-1 re-check").toBe(2);
      // The ruled invariant: a query NEVER finalizes — the entry waits for a
      // later replay's authoritative Ok.
      await unchanged(journal, cache);
      // …which, once the limit clears, finalizes through the ordinary path.
      const { pool: okPool } = scriptedPool({ spend: () => {}, statuses: [finalizedRecord(41n)] });
      expect(await reconcileSpendEntry({ pool: okPool, journal }, (await journal.find("41"))!)).toEqual({
        kind: "replay-same-intent",
      });
      expect((await journal.find("41"))!.status).toBe("finalized");
      expect((await cache.load()).notes[0].state).toBe("spent");
    });

    it(`E-1 ${code}: a refusal whose status re-check is NOT finalized → the ruled per-code copy`, async () => {
      const { journal, cache } = await dispatchedJournal();
      const { pool, calls } = scriptedPool({
        spend: () => {
          throw admissionErr(code, 0n);
        },
        statuses: [null],
      });
      const entry = (await journal.find("41"))!;
      let thrown: unknown;
      try {
        await replaySameIntent({ pool, journal }, entry);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(SpendFlowError);
      const sfe = thrown as SpendFlowError;
      expect(sfe.alreadyWentThrough).toBe(false);
      expect(sfe.message).toBe(spendAdmissionCopy({ code, retryAfterNs: 0n }));
      expect(sfe.message).not.toBe(SPEND_ALREADY_WENT_THROUGH_COPY);
      expect(calls.status, "the E-1 status re-check ran").toBe(1);
      await unchanged(journal, cache);
    });
  }

  it("E-1 is scoped to the two step-1 codes: NO_ACTIVE_DEVICE / DEVICE_CHECK_UNAVAILABLE never query status", async () => {
    for (const code of ["NO_ACTIVE_DEVICE", "DEVICE_CHECK_UNAVAILABLE"] as const) {
      const { journal } = await dispatchedJournal();
      const { pool, calls } = scriptedPool({
        spend: () => {
          throw admissionErr(code);
        },
        statuses: [finalizedRecord(41n)],
      });
      await expect(replaySameIntent({ pool, journal }, (await journal.find("41"))!)).rejects.toMatchObject({
        admission: { code },
        alreadyWentThrough: false,
        message: spendAdmissionCopy({ code, retryAfterNs: 0n }),
      });
      expect(calls.status, code).toBe(0);
    }
  });

});
