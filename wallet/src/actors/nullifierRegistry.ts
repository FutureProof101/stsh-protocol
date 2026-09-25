/**
 * Nullifier-registry canister actor (Campaign B / L3b).
 *
 * The wallet's spent-set source (L0-F): `get_nullifiers_page` exact full-set
 * pagination + `count` for the count-before/after integrity check. Public
 * queries — bound to the ANONYMOUS read agent (DEF-073: the spent set is
 * public; the wallet never transmits an unspent nullifier).
 * Source: canisters/nullifier-registry/nullifier_registry.did.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";

import { idlFactory } from "../../../src/declarations/nullifier_registry/nullifier_registry.did.js";
import type { _SERVICE } from "../../../src/declarations/nullifier_registry/nullifier_registry.did";
import { toBytes } from "./common";

export interface NullifierRegistryCanister {
  /** One page of `get_nullifiers_page(startAfter, limit)`. Throws on Err. */
  getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]>;
  /** Total nullifiers stored (count-before/after integrity anchor). */
  count(): Promise<bigint>;
  /** Point membership check (public query). */
  containsNullifier(nullifier: Uint8Array): Promise<boolean>;
}

/** Pure adapter: raw candid actor -> `NullifierRegistryCanister`. Mock-testable. */
export function wrapNullifierRegistryActor(raw: _SERVICE): NullifierRegistryCanister {
  return {
    async getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]> {
      const result = await raw.get_nullifiers_page(
        startAfter === null ? [] : [startAfter],
        limit,
      );
      if ("Err" in result) {
        throw new Error(`get_nullifiers_page rejected: ${result.Err}`);
      }
      return result.Ok.map((bytes: Uint8Array | number[]) => toBytes(bytes));
    },

    async count(): Promise<bigint> {
      return raw.count();
    },

    async containsNullifier(nullifier: Uint8Array): Promise<boolean> {
      return raw.contains_nullifier(nullifier);
    },
  };
}

/** Build a live nullifier-registry actor bound to `agent` and adapt it. */
export function createNullifierRegistryActor(
  canisterId: string,
  agent: HttpAgent,
): NullifierRegistryCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapNullifierRegistryActor(raw);
}
