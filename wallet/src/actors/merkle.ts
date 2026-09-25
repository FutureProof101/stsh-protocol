/**
 * Merkle-tree canister actor (wallet-build Commit 4).
 *
 * The wallet reads the commitment tree; it never appends (append_commitment /
 * append_commitments are pool/controller paths). Wrapped here are the query
 * methods the wallet needs:
 *   get_payloads      : (nat64, nat64) -> (vec record { nat64; blob }) query
 *     — the cross-device scan source (crypto/vetkeys.ts `scanPayloads`).
 *   get_root / get_root_at_index / is_valid_anchor — spend anchor selection.
 *   leaf_count / get_leaf — shield-append confirmation.
 * Source: canisters/merkle-tree/merkle_tree.did.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";

import { idlFactory } from "../../../src/declarations/merkle_tree/merkle_tree.did.js";
import type { _SERVICE } from "../../../src/declarations/merkle_tree/merkle_tree.did";
import type { PayloadPage } from "../crypto/vetkeys";
import { toBytes } from "./common";

export interface MerkleCanister {
  /** One page of `get_payloads(fromIndex, limit)` — `[leafIndex, payloadBytes]`. */
  getPayloads(fromIndex: bigint, limit: bigint): Promise<PayloadPage>;
  /** Current tree root (32-byte Fr, LE). */
  getRoot(): Promise<Uint8Array>;
  /** Historical root at a leaf-count index, or null if out of range. */
  getRootAtIndex(index: bigint): Promise<Uint8Array | null>;
  /** True iff `root` is an accepted anchor in the tree's recent-root window. */
  isValidAnchor(root: Uint8Array): Promise<boolean>;
  /** Number of leaves currently in the tree. */
  leafCount(): Promise<bigint>;
  /** Leaf at `index`, or null if out of range. */
  getLeaf(index: bigint): Promise<Uint8Array | null>;
  /** P-MRK: atomic head snapshot (leaf_count + root in ONE query). */
  getScanHead(): Promise<ScanHead>;
  /** P-MRK: dense capped page of {index, leaf, encrypted_payload}. Throws on Err. */
  getScanPage(fromIndex: bigint, limit: bigint): Promise<ScanPageEntry[]>;
}

/** P-MRK `get_scan_head` — atomic (leaf_count, root) snapshot. */
export interface ScanHead {
  leafCount: bigint;
  root: Uint8Array;
}

/** P-MRK `get_scan_page` entry — a leaf and its payload at one dense index. */
export interface ScanPageEntry {
  index: bigint;
  leaf: Uint8Array;
  encryptedPayload: Uint8Array;
}

/** candid `opt blob` (`[] | [bytes]`) -> `Uint8Array | null`. */
function optBytes(opt: [] | [Uint8Array | number[]]): Uint8Array | null {
  return opt.length === 0 ? null : toBytes(opt[0]);
}

/** Pure adapter: raw candid actor -> `MerkleCanister`. Mock-testable. */
export function wrapMerkleActor(raw: _SERVICE): MerkleCanister {
  return {
    async getPayloads(fromIndex: bigint, limit: bigint): Promise<PayloadPage> {
      const page = await raw.get_payloads(fromIndex, limit);
      return page.map(
        ([leafIndex, bytes]: [bigint, Uint8Array | number[]]): [bigint, Uint8Array] => [
          leafIndex,
          toBytes(bytes),
        ],
      );
    },

    async getRoot(): Promise<Uint8Array> {
      return toBytes(await raw.get_root());
    },

    async getRootAtIndex(index: bigint): Promise<Uint8Array | null> {
      return optBytes(await raw.get_root_at_index(index));
    },

    async isValidAnchor(root: Uint8Array): Promise<boolean> {
      return raw.is_valid_anchor(root);
    },

    async leafCount(): Promise<bigint> {
      return raw.leaf_count();
    },

    async getLeaf(index: bigint): Promise<Uint8Array | null> {
      return optBytes(await raw.get_leaf(index));
    },

    async getScanHead(): Promise<ScanHead> {
      const head = await raw.get_scan_head();
      return { leafCount: head.leaf_count, root: toBytes(head.root) };
    },

    async getScanPage(fromIndex: bigint, limit: bigint): Promise<ScanPageEntry[]> {
      const result = await raw.get_scan_page(fromIndex, limit);
      if ("Err" in result) {
        throw new Error(`get_scan_page(${fromIndex}, ${limit}) rejected: ${result.Err}`);
      }
      return result.Ok.map(
        (e: { index: bigint; leaf: Uint8Array | number[]; encrypted_payload: Uint8Array | number[] }) => ({
          index: e.index,
          leaf: toBytes(e.leaf),
          encryptedPayload: toBytes(e.encrypted_payload),
        }),
      );
    },
  };
}

/** Build a live merkle-tree actor bound to `agent` and adapt it. */
export function createMerkleActor(canisterId: string, agent: HttpAgent): MerkleCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapMerkleActor(raw);
}
