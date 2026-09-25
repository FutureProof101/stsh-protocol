/**
 * Shared harness for the WALLET-AUTH Gate 1 verified-scan suites.
 *
 * It lives here rather than being copied into three test files because the
 * three suites must agree on what an honest deployment looks like — a harness
 * that drifts between them would let a test pass against a world the other
 * tests do not believe in.
 *
 * Everything here is a MOCK in the parent brief §7 sense: a plain object
 * satisfying `ScanActors`, no agent and no replica. It models a canister that
 * ANSWERS; it does not model the transport. That distinction is load-bearing
 * for reading the results: these suites prove the wallet's anchor, floor and
 * cache logic, and they deliberately cannot prove anything about certificate
 * verification, which is Gate 0's replica evidence.
 */
import { Principal } from "@dfinity/principal";

import {
  DENOMINATIONS,
  createShieldNote,
  deriveNoteSecretsV2,
  merkleLeaf,
  noteToBytesV2,
  type Note,
} from "../../src/crypto/notes";
import { LocalMerkleMirror, type ScanActors } from "../../src/crypto/scanner";
import type { ScanPageEntry } from "../../src/actors/merkle";
import type { AcceptedRootHeadView } from "../../src/actors/pool";
import type { DeploymentAttestation } from "../../../src/declarations/shielded_pool/shielded_pool.did";

export const MASTER = new Uint8Array(32).fill(0x11);
export const OTHER_MASTER = new Uint8Array(32).fill(0x77);
export { DENOMINATIONS };

export const POOL_ID = "cxrfg-qaaaa-aaaar-qchfa-cai";
export const MERKLE_ID = "cmuzd-kyaaa-aaaar-qchhq-cai";
export const NULLIFIER_ID = "ccwul-riaaa-aaaar-qchgq-cai";

export const BINDING = { poolCanisterId: POOL_ID, merkleCanisterId: MERKLE_ID, nullifierCanisterId: NULLIFIER_ID };

export interface Candidate {
  note: Note;
  plaintext: Uint8Array;
  leaf: Uint8Array;
}

export async function makeCandidate(
  value: bigint,
  nonceSeed: number,
  master: Uint8Array = MASTER,
): Promise<Candidate> {
  const nonce = new Uint8Array(16).fill(nonceSeed);
  const secrets = await deriveNoteSecretsV2(master, nonce);
  const note = await createShieldNote(value, secrets);
  return { note, plaintext: noteToBytesV2(note, nonce), leaf: await merkleLeaf(value, note.commitment) };
}

export interface Entry {
  payload: Uint8Array;
  leaf: Uint8Array;
}

export function entryOf(c: Candidate): Entry {
  return { payload: c.plaintext, leaf: c.leaf };
}

export async function rootOf(entries: Entry[]): Promise<Uint8Array> {
  const m = new LocalMerkleMirror();
  entries.forEach((e, i) => m.addLeaf(BigInt(i), e.leaf));
  return m.root(BigInt(entries.length));
}

export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function attestationFor(configHash: Uint8Array, ids = BINDING): DeploymentAttestation {
  return {
    circuit_version: 1,
    merkle: Principal.fromText(ids.merkleCanisterId),
    verifier: [],
    token: Principal.fromText(POOL_ID),
    proof_system: "groth16-bn254",
    nullifier: Principal.fromText(ids.nullifierCanisterId),
    pool: Principal.fromText(ids.poolCanisterId),
    config_version: 1,
    pool_version: 1,
    config_hash: configHash,
    vk_hash: new Uint8Array(32).fill(0xaa),
  };
}

/** Every wire call this harness served, in order — AC-12 and AC-18 count these. */
export interface CallLog {
  calls: string[];
}

export interface VerifiedChainOptions {
  /** What the pool's accepted head claims. */
  acceptedEntries?: Entry[];
  acceptedRoot?: Uint8Array;
  acceptedLeafCount?: bigint | null;
  /** What get_scan_head claims (defaults to the accepted entries). */
  headEntries?: Entry[];
  headLeafCount?: bigint;
  /** What get_scan_page actually serves (defaults to the accepted entries). */
  pageEntries?: Entry[];
  spent?: Uint8Array[];
  configHash?: Uint8Array;
  securityEpoch?: bigint;
  attestation?: DeploymentAttestation;
  /** Throw instead of answering get_deployment_attestation (SSA C-10). */
  attestationFails?: boolean;
  /** Called after each named wire call; throw from it to fail mid-sweep. */
  onCall?: (name: string, log: CallLog) => void;
}

/**
 * A deployment whose four answer sources are INDEPENDENT, so a test can make
 * exactly one of them lie: the pool's accepted head, the merkle head, the
 * pages, and the spent set. An honest deployment is the case where the first
 * three describe the same leaves.
 */
export async function verifiedChain(
  opts: VerifiedChainOptions = {},
): Promise<ScanActors & { log: CallLog }> {
  const accepted = opts.acceptedEntries ?? [];
  const pages = opts.pageEntries ?? accepted;
  const headEntries = opts.headEntries ?? accepted;
  const acceptedRoot = opts.acceptedRoot ?? (await rootOf(accepted));
  const acceptedLeafCount =
    opts.acceptedLeafCount === undefined ? BigInt(accepted.length) : opts.acceptedLeafCount;
  const headRoot = await rootOf(headEntries);
  const headLeafCount = opts.headLeafCount ?? BigInt(headEntries.length);
  const spent = opts.spent ?? [];
  const configHash = opts.configHash ?? new Uint8Array(32).fill(0x01);
  const log: CallLog = { calls: [] };

  const note = (name: string) => {
    log.calls.push(name);
    opts.onCall?.(name, log);
  };

  return {
    log,
    async getScanHead() {
      note("getScanHead");
      return { leafCount: headLeafCount, root: headRoot };
    },
    async getScanPage(from: bigint, limit: bigint): Promise<ScanPageEntry[]> {
      note("getScanPage");
      return pages
        .slice(Number(from), Number(from) + Number(limit))
        .map((e, i) => ({ index: from + BigInt(i), leaf: e.leaf, encryptedPayload: e.payload }));
    },
    async getNullifiersPage(startAfter: Uint8Array | null, limit: bigint) {
      note("getNullifiersPage");
      const sorted = [...spent].sort((a, b) => {
        for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
        return 0;
      });
      const start =
        startAfter === null
          ? 0
          : sorted.findIndex((v) => {
              for (let i = 0; i < 32; i++) if (v[i] !== startAfter[i]) return false;
              return true;
            }) + 1;
      return sorted.slice(start, start + Number(limit));
    },
    async count() {
      note("count");
      return BigInt(spent.length);
    },
    async getAcceptedRootHead(): Promise<AcceptedRootHeadView | null> {
      note("getAcceptedRootHead");
      if (acceptedLeafCount === null) return null;
      return { root: acceptedRoot, leafCount: acceptedLeafCount };
    },
    async getSecurityEpoch(): Promise<bigint> {
      note("getSecurityEpoch");
      return opts.securityEpoch ?? 7n;
    },
    async getDeploymentAttestation(): Promise<DeploymentAttestation> {
      note("getDeploymentAttestation");
      if (opts.attestationFails === true) {
        throw new Error("get_deployment_attestation: PoolPaused");
      }
      return opts.attestation ?? attestationFor(configHash);
    },
  };
}
