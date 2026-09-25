/**
 * Replicated (update-path) read transport — HARDEN-03-WALLET-AUTH, Gate 0,
 * Route A (brief V2 §3.2, ESC-1 CONFIRMED).
 *
 * WHAT THIS IS. `@dfinity/agent` 3.4.3 chooses its transport purely from the
 * IDL annotation (`node_modules/@dfinity/agent/lib/esm/actor.js:170`):
 *
 *     if (func.annotations.includes('query') || func.annotations.includes('composite_query'))
 *
 * No option on an individual call, and no `queryTransform` return value, moves a
 * call off the query path — `queryTransform` only merges into `options`, and
 * `options` is never consulted for dispatch. So the only way to obtain a reply
 * the agent itself verified (request-ID matching, `pollForResponse`, certificate
 * validation, BLS) is to hand `Actor.createActor` a service in which the target
 * methods carry no `query` annotation. This module builds exactly that, AT
 * RUNTIME, from the checked-in generated `idlFactory`.
 *
 * WHAT THIS IS NOT. It is not a second source of truth for any canister
 * interface, and it is not a hand-rolled certificate verifier. The argument and
 * return types are the GENERATED objects, reused by reference and never
 * re-declared here; only the client-side dispatch hint is dropped. The IC — not
 * the wallet — decides whether a replicated invocation of a `query` method is
 * legal. `wallet/tests/replicated_read_transport.test.ts` carries the DL-2 /
 * G0-5 drift-lock that fails if the runtime copy and the generated declarations
 * diverge in either direction.
 *
 * GUARDRAILS (brief §3.2, all five):
 *   1. The checked-in generated declaration files are NEVER modified. The
 *      transformation is in-memory and dies with the process.
 *   2. Generated-from + drift-locked (DL-2 / G0-5).
 *   3. A CLOSED allowlist of method names, declared as a literal below. A name
 *      that is not on the list is a TYPE error (the returned actor is a `Pick<>`
 *      over the allowlist) and, at runtime, simply absent from the actor.
 *   4. The Candid argument/return types are the generated ones, unchanged.
 *   5. The transport carries its OWN host-classifier gate at the point of use
 *      (AC-8b) — see `assertReplicatedTransportAllowed`.
 *
 * ROOT KEY (S-12 / S-25 / A-S9). Under replicated reads the root key IS the
 * trust anchor, so this module re-derives the decision itself rather than
 * trusting whoever built the agent it was handed. It does so from the agent's
 * OWN destination (`agent.host` — the value that determines where the requests
 * actually go) and the agent's OWN observable root-key state. It introduces NO
 * new boolean, NO new flag, and NOTHING that crosses the scanner worker's
 * postMessage boundary: S-25 removed a caller-supplied root-key boolean from
 * that path and it stays removed.
 */

import { Actor, IC_ROOT_KEY, type HttpAgent } from "@dfinity/agent";
import type { IDL } from "@dfinity/candid";

import { idlFactory as merkleIdlFactory } from "../../../src/declarations/merkle_tree/merkle_tree.did.js";
import type { _SERVICE as MerkleService } from "../../../src/declarations/merkle_tree/merkle_tree.did";
import { idlFactory as nullifierIdlFactory } from "../../../src/declarations/nullifier_registry/nullifier_registry.did.js";
import type { _SERVICE as NullifierService } from "../../../src/declarations/nullifier_registry/nullifier_registry.did";
import { idlFactory as poolIdlFactory } from "../../../src/declarations/shielded_pool/shielded_pool.did.js";
import type { _SERVICE as PoolService } from "../../../src/declarations/shielded_pool/shielded_pool.did";
import { isLocalHost } from "../session/config";

// ---------------------------------------------------------------------------
// The closed allowlist (guardrail 3)
// ---------------------------------------------------------------------------

/**
 * The SEVEN methods the verified read path needs (brief §7 G0-1), grouped by
 * canister. Deliberately minimal: `get_payloads` and `leaf_count` are NOT here
 * even though brief §3.1 lists them among the lane's plain-`query` methods —
 * `get_scan_page` supersedes `get_payloads` for the verified sweep (it carries
 * the leaf alongside the payload as one authenticated tuple) and `get_scan_head`
 * supersedes `leaf_count` (atomic count+root in one reply). An allowlist that is
 * wider than the path it authorises is not a closed allowlist.
 *
 * Every entry is a plain `query` in the generated declarations — there is no
 * `composite_query` anywhere in `canisters/*.did`, which is what makes Route A
 * possible at all (a composite query genuinely cannot be invoked in replicated
 * mode).
 */
export const REPLICATED_METHODS = {
  merkle_tree: ["get_scan_head", "get_scan_page"],
  nullifier_registry: ["count", "get_nullifiers_page"],
  shielded_pool: [
    "get_accepted_root_head",
    "get_security_epoch",
    "get_deployment_attestation",
  ],
} as const;

export type ReplicatedMerkleMethod = (typeof REPLICATED_METHODS.merkle_tree)[number];
export type ReplicatedNullifierMethod =
  (typeof REPLICATED_METHODS.nullifier_registry)[number];
export type ReplicatedPoolMethod = (typeof REPLICATED_METHODS.shielded_pool)[number];

/** The merkle-tree surface reachable over the verified transport. */
export type ReplicatedMerkleService = Pick<MerkleService, ReplicatedMerkleMethod>;
/** The nullifier-registry surface reachable over the verified transport. */
export type ReplicatedNullifierService = Pick<NullifierService, ReplicatedNullifierMethod>;
/** The pool surface reachable over the verified transport. */
export type ReplicatedPoolService = Pick<PoolService, ReplicatedPoolMethod>;

/**
 * The annotations agent 3.4.3 dispatches the QUERY branch on (`actor.js:170`).
 * Dropping these — and only these — is the whole transformation.
 */
const QUERY_DISPATCH_ANNOTATIONS: readonly string[] = ["query", "composite_query"];

// ---------------------------------------------------------------------------
// Refusal
// ---------------------------------------------------------------------------

/**
 * Thrown when a verified read is attempted over an agent this module will not
 * vouch for. Distinct from a network/canister error on purpose: the caller must
 * report "verified read unavailable" and persist nothing (brief §2 invariant 6),
 * never silently demote to ordinary-query trust.
 */
export class ReplicatedTransportRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReplicatedTransportRefused";
  }
}

/** Thrown when the allowlist names a method the generated declarations lack. */
export class ReplicatedMethodNotDeclared extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReplicatedMethodNotDeclared";
  }
}

// ---------------------------------------------------------------------------
// The IDL transformation (Route A)
// ---------------------------------------------------------------------------

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Wrap a GENERATED `idlFactory` into one that yields an annotation-stripped
 * service containing exactly `allowlist`.
 *
 * The factory is re-invoked on every call (as `Actor.createActorClass` does), so
 * the generated `FuncClass` objects are never mutated and never shared with a
 * previously-built actor — `createActorClass` pushes onto `func.annotations` for
 * its `httpDetails`/`certificate` options, and a shared array would leak that
 * mutation back into the declarations' own objects.
 *
 * Throws `ReplicatedMethodNotDeclared` if a name on the allowlist is not a
 * method of the generated service (G0-3, and the drift-lock's first direction).
 */
export function replicatedInterfaceFactory(
  generated: IDL.InterfaceFactory,
  allowlist: readonly string[],
): IDL.InterfaceFactory {
  return (idl) => {
    const service = generated(idl) as unknown as IDL.ServiceClass;
    const declared = new Map<string, IDL.FuncClass>(service._fields);
    const fields: Record<string, IDL.FuncClass> = {};

    for (const name of allowlist) {
      const func = declared.get(name);
      if (func === undefined) {
        throw new ReplicatedMethodNotDeclared(
          `replicated transport: "${name}" is on the allowlist but is not a method of the ` +
            `generated declarations. The runtime copy is GENERATED FROM the declarations — ` +
            `regenerate or correct the allowlist; never hand-transcribe a signature here.`,
        );
      }
      // Guardrail 4: argTypes/retTypes are the GENERATED objects, by reference.
      // Only the client-side dispatch hint is dropped.
      fields[name] = idl.IDL.Func(
        func.argTypes,
        func.retTypes,
        func.annotations.filter((a) => !QUERY_DISPATCH_ANNOTATIONS.includes(a)),
      );
    }

    return idl.IDL.Service(fields);
  };
}

// ---------------------------------------------------------------------------
// The host-classifier gate at the point of use (AC-8b)
// ---------------------------------------------------------------------------

/** The minimum an agent must expose for the gate to classify it. */
export type GatedAgent = Pick<HttpAgent, "host" | "rootKey">;

/**
 * AC-8b — refuse a verified read over an agent whose root-key state is not
 * coherent with where its requests actually go.
 *
 * The rule, derived at the point of use from the agent's OWN destination:
 *
 *  - loopback destination  -> allowed. A local replica's root key is fetched by
 *    design; that is what `isLocalHost` authorises on both existing paths
 *    (`scanner.worker.ts:51`, `session.ts:86`).
 *  - any other destination -> the agent MUST be carrying the pinned IC mainnet
 *    root key, byte for byte. A fetched replica key, or a null key awaiting a
 *    lazy fetch, means certificates would be checked against a key an attacker
 *    on the path could have supplied — which is precisely the outcome S-12
 *    exists to prevent, and precisely what becomes load-bearing the moment
 *    replies are actually verified.
 *
 * This deliberately does NOT take a `host` argument. Classifying on the agent's
 * own `host` is stronger than classifying on a string the caller passes
 * alongside it: it cannot be told one destination while sending to another, and
 * it adds no parameter that could cross a worker postMessage boundary (S-25).
 */
export function assertReplicatedTransportAllowed(agent: GatedAgent): void {
  const destination = agent.host?.toString() ?? "";

  if (isLocalHost(destination)) return;

  const rootKey = agent.rootKey;
  if (rootKey === null || rootKey === undefined) {
    throw new ReplicatedTransportRefused(
      `verified read refused: agent for non-loopback host "${destination}" carries no root key ` +
        `(a lazy fetch would take the trust anchor from the network). S-12.`,
    );
  }
  if (toHex(rootKey) !== IC_ROOT_KEY.toLowerCase()) {
    throw new ReplicatedTransportRefused(
      `verified read refused: agent for non-loopback host "${destination}" is not carrying the ` +
        `pinned IC root key — a root key was fetched on a production host, so certificate ` +
        `verification would prove nothing. S-12.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Actor construction
// ---------------------------------------------------------------------------

/**
 * Build a replicated-read actor over `agent`, exposing exactly `allowlist`.
 *
 * The gate runs at construction AND on every call. Construction alone is not
 * enough: `agent.fetchRootKey()` can be called after the actor exists, so the
 * only honest place for AC-8b's check is immediately before each request leaves.
 */
function createReplicatedActor<S, K extends keyof S & string>(
  generated: IDL.InterfaceFactory,
  allowlist: readonly K[],
  canisterId: string,
  agent: HttpAgent,
): Pick<S, K> {
  assertReplicatedTransportAllowed(agent);

  const raw = Actor.createActor<Pick<S, K>>(
    replicatedInterfaceFactory(generated, allowlist),
    { agent, canisterId },
  );

  const gated = {} as Pick<S, K>;
  for (const name of allowlist) {
    const method = raw[name] as unknown as (...args: unknown[]) => Promise<unknown>;
    gated[name] = (async (...args: unknown[]) => {
      assertReplicatedTransportAllowed(agent);
      return method(...args);
    }) as unknown as S[K];
  }
  return gated;
}

/** Merkle-tree reads over the verified (replicated) transport. */
export function createReplicatedMerkleActor(
  canisterId: string,
  agent: HttpAgent,
): ReplicatedMerkleService {
  return createReplicatedActor<MerkleService, ReplicatedMerkleMethod>(
    merkleIdlFactory,
    REPLICATED_METHODS.merkle_tree,
    canisterId,
    agent,
  );
}

/** Nullifier-registry reads over the verified (replicated) transport. */
export function createReplicatedNullifierActor(
  canisterId: string,
  agent: HttpAgent,
): ReplicatedNullifierService {
  return createReplicatedActor<NullifierService, ReplicatedNullifierMethod>(
    nullifierIdlFactory,
    REPLICATED_METHODS.nullifier_registry,
    canisterId,
    agent,
  );
}

/** Shielded-pool metadata reads over the verified (replicated) transport. */
export function createReplicatedPoolActor(
  canisterId: string,
  agent: HttpAgent,
): ReplicatedPoolService {
  return createReplicatedActor<PoolService, ReplicatedPoolMethod>(
    poolIdlFactory,
    REPLICATED_METHODS.shielded_pool,
    canisterId,
    agent,
  );
}

/** The generated factories the runtime copy is derived from — DL-2 reads these. */
export const GENERATED_IDL_FACTORIES: Readonly<Record<string, IDL.InterfaceFactory>> = {
  merkle_tree: merkleIdlFactory,
  nullifier_registry: nullifierIdlFactory,
  shielded_pool: poolIdlFactory,
};
