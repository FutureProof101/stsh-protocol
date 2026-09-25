/**
 * STSH note-scanner Web Worker (Campaign B / L3b — §9 validated pipeline).
 *
 * Runs the I/O + CPU-heavy scan off the main thread: builds an anonymous
 * agent + merkle/nullifier-registry actors, reconstructs the session vetKey
 * from its serialized bytes, and runs `scanAndValidate` (crypto/scanner.ts)
 * end to end — strict spent-set download, full public sweep, per-candidate
 * validation, mirror-root integrity. Only the validated outcome is posted
 * back; the main thread merges it into the encrypted PrincipalNoteCache in
 * ONE atomic update (the vetKey and cache key never touch persistent
 * storage).
 *
 * Root key: decided by the loopback host classifier (session/config.ts
 * `isLocalHost`) — never by a caller-supplied boolean, so a production host
 * can never be talked into fetching it (S-12/S-25).
 */

import { HttpAgent } from "@dfinity/agent";
import { VetKey } from "@dfinity/vetkeys";

import { createMerkleActor } from "../actors/merkle";
import { createNullifierRegistryActor } from "../actors/nullifierRegistry";
import {
  createReplicatedMerkleActor,
  createReplicatedNullifierActor,
  createReplicatedPoolActor,
} from "../actors/replicated";
import { tryDecryptNotePayload } from "../crypto/vetkeys";
import {
  scanAndValidate,
  scanAndValidateVerified,
  type ScanActors,
  type ScanOutcome,
  type VerifiedScanResult,
} from "../crypto/scanner";
import { isLocalHost } from "../session/config";
import type { VerifiedScanMetadata } from "../storage/noteCache";
import type { ScanPageEntry as ScanPageEntryRaw } from "../../../src/declarations/merkle_tree/merkle_tree.did";

export interface ScannerRequest {
  merkleCanisterId: string;
  nullifierCanisterId: string;
  host: string;
  /**
   * WALLET-AUTH Gate 1 (parent AC-3). PRESENT means: run the VERIFIED sweep —
   * build the three actors over the replicated transport and anchor on the
   * pool's accepted root. ABSENT means the ordinary query-path scan.
   *
   * Presence is the mode selector precisely so that no boolean is added to this
   * message. S-25 removed a caller-supplied root-key boolean from this
   * boundary; the lane adds nothing that could grow back into one, and there is
   * no root-key input here of any kind — the root-key decision stays with the
   * loopback host classifier below and with `assertReplicatedTransportAllowed`
   * at the point of use.
   */
  poolCanisterId?: string;
  /** VetKey.serialize() bytes — the 48-byte BLS signature (re-derived, not stored). */
  vetKeySerialized: Uint8Array;
  /** The 32-byte master note secret (re-derived per session, never stored). */
  masterNoteSecret: Uint8Array;
  fromIndex: bigint;
  pageSize?: bigint;
}

export type ScannerResponse =
  | { ok: true; outcome: ScanOutcome; verified?: VerifiedScanMetadata }
  | { ok: true; noAcceptedRoot: true }
  | { ok: false; error: string }
  | { progress: { scannedUpTo: bigint; found: number } };

const post = (msg: ScannerResponse) => (self as unknown as Worker).postMessage(msg);

/**
 * The agent factory, named and exported so the anonymity property is TESTABLE
 * (SSA C-5) rather than asserted about code nobody can call.
 *
 * `HttpAgent.create({ host })` and nothing else: there is no `identity` option
 * here, and adding one would attach the user's principal to every scan request
 * at ingress, in the clear — which is a bigger privacy loss than the one the
 * verified transport buys back. Under replicated reads the requests are
 * attributable ingress messages, which is exactly why the agent must stay
 * anonymous.
 */
export type ScanAgentFactory = (opts: { host: string }) => Promise<HttpAgent>;

export const defaultScanAgentFactory: ScanAgentFactory = (opts) => HttpAgent.create(opts);

/**
 * Build the scan agent for a request. The root key is fetched only for a
 * loopback host, decided by the host classifier and never by anything in the
 * request (S-12 / S-25).
 */
export async function buildScanAgent(
  host: string,
  createAgent: ScanAgentFactory = defaultScanAgentFactory,
): Promise<HttpAgent> {
  const agent = await createAgent({ host });
  if (isLocalHost(host)) await agent.fetchRootKey();
  return agent;
}

/**
 * Assemble `ScanActors` for a request.
 *
 * With a pool id: all four transport methods come from the REPLICATED actors,
 * plus the three pool reads. Mixing transports would be the worst of both — the
 * anchor verified and the pages not. Without a pool id: the ordinary query
 * actors and no pool reads at all, so `assertVerifiedActors` refuses and the
 * verified path is unreachable by construction (AC-3).
 */
export function buildScanActors(req: ScannerRequest, agent: HttpAgent): ScanActors {
  if (req.poolCanisterId !== undefined && req.poolCanisterId !== "") {
    const merkle = createReplicatedMerkleActor(req.merkleCanisterId, agent);
    const nullifier = createReplicatedNullifierActor(req.nullifierCanisterId, agent);
    const pool = createReplicatedPoolActor(req.poolCanisterId, agent);
    return {
      getScanHead: async () => {
        const head = await merkle.get_scan_head();
        return { leafCount: head.leaf_count, root: Uint8Array.from(head.root) };
      },
      getScanPage: async (from, limit) => {
        const res = await merkle.get_scan_page(from, limit);
        if ("Err" in res) throw new Error(`get_scan_page: ${res.Err}`);
        return res.Ok.map((e: ScanPageEntryRaw) => ({
          index: e.index,
          leaf: Uint8Array.from(e.leaf),
          encryptedPayload: Uint8Array.from(e.encrypted_payload),
        }));
      },
      getNullifiersPage: async (startAfter, limit) => {
        const res = await nullifier.get_nullifiers_page(
          startAfter === null ? [] : [startAfter],
          limit,
        );
        if ("Err" in res) throw new Error(`get_nullifiers_page: ${res.Err}`);
        return res.Ok.map((n: Uint8Array | number[]) => Uint8Array.from(n));
      },
      count: () => nullifier.count(),
      getAcceptedRootHead: async () => {
        const res = await pool.get_accepted_root_head();
        if (res.length === 0) return null;
        return { root: Uint8Array.from(res[0].root), leafCount: res[0].leaf_count };
      },
      getSecurityEpoch: () => pool.get_security_epoch(),
      getDeploymentAttestation: async () => {
        const res = await pool.get_deployment_attestation();
        if ("Err" in res) {
          throw new Error(`get_deployment_attestation: ${JSON.stringify(res.Err)}`);
        }
        return res.Ok;
      },
    };
  }
  const merkle = createMerkleActor(req.merkleCanisterId, agent);
  const nullifierRegistry = createNullifierRegistryActor(req.nullifierCanisterId, agent);
  return {
    getScanHead: () => merkle.getScanHead(),
    getScanPage: (from, limit) => merkle.getScanPage(from, limit),
    getNullifiersPage: (startAfter, limit) =>
      nullifierRegistry.getNullifiersPage(startAfter, limit),
    count: () => nullifierRegistry.count(),
  };
}

self.onmessage = async (e: MessageEvent<ScannerRequest>) => {
  const req = e.data;
  const { host, vetKeySerialized, masterNoteSecret, fromIndex, pageSize } = req;
  try {
    const agent = await buildScanAgent(host);
    const actors = buildScanActors(req, agent);
    const vetKey = VetKey.deserialize(vetKeySerialized);
    const tryDecrypt = (bytes: Uint8Array) => tryDecryptNotePayload(vetKey, bytes);
    const options = {
      fromIndex,
      pageSize,
      onProgress: (upTo: bigint, found: number) =>
        post({ progress: { scannedUpTo: upTo, found } }),
    };

    if (req.poolCanisterId !== undefined && req.poolCanisterId !== "") {
      const result: VerifiedScanResult = await scanAndValidateVerified(
        actors,
        {
          poolCanisterId: req.poolCanisterId,
          merkleCanisterId: req.merkleCanisterId,
          nullifierCanisterId: req.nullifierCanisterId,
        },
        tryDecrypt,
        masterNoteSecret,
        options,
      );
      if (result.status === "no-accepted-root") {
        post({ ok: true, noAcceptedRoot: true });
        return;
      }
      post({ ok: true, outcome: result.outcome, verified: result.metadata });
      return;
    }

    const outcome = await scanAndValidate(actors, tryDecrypt, masterNoteSecret, options);
    post({ ok: true, outcome });
  } catch (err) {
    post({ ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};
