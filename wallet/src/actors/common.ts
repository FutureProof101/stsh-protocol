/**
 * Shared actor helpers (wallet-build Commit 4).
 *
 * The `wallet/src/actors/*` modules wrap the dfx-generated canister
 * declarations (repo-root `src/declarations/<canister>/`) into small, typed,
 * camelCase interfaces the rest of the wallet consumes — so nothing outside
 * this directory imports raw candid `_SERVICE` shapes or the `{ Ok } | { Err }`
 * result envelopes.
 *
 * Every wrapper is split in two: a pure `wrap<Name>Actor(raw)` adapter that
 * takes an already-constructed candid actor (mock-testable with a plain object,
 * no agent/replica) and a `create<Name>Actor(canisterId, agent)` that builds
 * the real `Actor` and hands it to the adapter.
 */

/**
 * Candid decodes `blob` / `vec nat8` to `Uint8Array` at runtime, but the
 * generated `.d.ts` widens the type to `Uint8Array | number[]`. Normalise
 * defensively so downstream code (and tests, which may pass `number[]`) always
 * see a `Uint8Array`.
 */
export function toBytes(b: Uint8Array | number[]): Uint8Array {
  return b instanceof Uint8Array ? b : Uint8Array.from(b);
}

/**
 * `JSON.stringify` replacer that renders `bigint` as a decimal string — candid
 * `nat`/`nat64` payloads inside error variants are bigints and would otherwise
 * throw "Do not know how to serialize a BigInt".
 */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString(10) : value;
}

/**
 * Render a single-key candid variant (`{ Tag: null }` or `{ Tag: payload }`) as
 * a readable string: the variant tag, plus the JSON payload when present. Used
 * to turn a rejected canister result into a thrown `Error` message without
 * hand-enumerating every variant arm.
 */
export function formatVariant(variant: Record<string, unknown>): string {
  const tag = Object.keys(variant)[0];
  if (tag === undefined) return "(empty variant)";
  const payload = variant[tag];
  return payload === null || payload === undefined
    ? tag
    : `${tag}: ${JSON.stringify(payload, bigintReplacer)}`;
}
