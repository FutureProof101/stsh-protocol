/**
 * J-25 — the session-cached, anonymous pool identity observation (addendum E).
 *
 * Discipline this module enforces, all of it required by addendum E:
 *   * ONE shared in-flight request and ONE cached result per session and per
 *     configured (pool canister id + host) key. Rerenders reuse it; they never
 *     multiply requests.
 *   * A configuration change INVALIDATES the observation — the next read starts
 *     a new request under the new key.
 *   * A response that arrives for an obsolete key is DISCARDED, never written
 *     over current state.
 *   * No identity, no login prerequisite, no timing telemetry. The caller
 *     supplies an anonymous read actor.
 *
 * It is presentation state (I3): a failure here shows "unverified against
 * pool" and changes nothing about proving or spending.
 */

/** What one anonymous observation of the pool's identity values yielded. */
export type PoolIdentityObservation =
  | { kind: "ok"; circuitVersion: number; vkHash: string }
  | { kind: "unconfigured" }
  | { kind: "failed"; detail: string };

/** The two anonymous queries the panel makes. Nothing else is called. */
export interface PoolIdentityReader {
  getCircuitVersion(): Promise<number>;
  getPinnedVkHash(): Promise<Uint8Array>;
}

const HEX = "0123456789abcdef";

/** Lowercase hex of the pinned VK hash — the FULL value, never truncated. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += HEX[(b >> 4) & 0xf] + HEX[b & 0xf];
  return out;
}

/**
 * A malformed or partial result is a FAILURE, not a value. The pool returns a
 * 32-byte hash and a non-negative integer version; anything else means the
 * observation cannot be compared and must read "unverified against pool".
 */
function validate(circuitVersion: unknown, vkHash: unknown): PoolIdentityObservation {
  if (typeof circuitVersion !== "number" || !Number.isInteger(circuitVersion) || circuitVersion < 0) {
    return { kind: "failed", detail: "pool returned a malformed circuit version" };
  }
  if (!(vkHash instanceof Uint8Array) || vkHash.length !== 32) {
    return { kind: "failed", detail: "pool returned a malformed verifying-key hash" };
  }
  return { kind: "ok", circuitVersion, vkHash: toHex(vkHash) };
}

export class PoolIdentityCache {
  /** The key the cached/in-flight observation belongs to; null when empty. */
  private key: string | null = null;
  private settled: PoolIdentityObservation | null = null;
  private inFlight: Promise<PoolIdentityObservation> | null = null;
  /**
   * The monotonic REQUEST GENERATION (RED-2, SSA landed-diff 2026-09-09).
   *
   * Key equality alone cannot distinguish an old request for A from the current
   * one after `A -> B -> A` or after `reset()` and a reuse of A: both compare
   * `this.key === forKey` and both pass, so the stale response overwrites the
   * newer settled value. The generation is captured when a request STARTS and
   * compared when it settles; it is bumped by every key change, every
   * `reset()`, and every newly started request. Concurrent callers that share
   * one in-flight request share its generation, so sharing still works.
   */
  private gen = 0;

  /**
   * The current request/session generation. Callers that paint an observation
   * asynchronously capture this immediately after `observe()` and re-check it
   * at settle, so a late paint for an obsolete request is dropped.
   */
  generation(): number {
    return this.gen;
  }

  /** The observation for `key`, if one has already settled for it. */
  peek(key: string): PoolIdentityObservation | null {
    return this.key === key ? this.settled : null;
  }

  /**
   * Observe once per key. Concurrent callers with the same key share the SAME
   * promise; a different key invalidates everything and starts one new request.
   */
  observe(key: string, reader: PoolIdentityReader | null): Promise<PoolIdentityObservation> {
    if (this.key !== key) {
      // Configuration changed: drop the cached result AND disown the in-flight
      // request, whose late resolution is discarded by the generation check
      // below. Bumping the generation here is what makes A -> B -> A safe: the
      // first A's request can never again match the live generation.
      this.key = key;
      this.settled = null;
      this.inFlight = null;
      this.gen += 1;
    }
    if (this.settled !== null) return Promise.resolve(this.settled);
    if (this.inFlight !== null) return this.inFlight;

    if (reader === null) {
      this.settled = { kind: "unconfigured" };
      return Promise.resolve(this.settled);
    }

    const forKey = key;
    const forGen = (this.gen += 1);
    const run = (async (): Promise<PoolIdentityObservation> => {
      let observation: PoolIdentityObservation;
      try {
        const [circuitVersion, vkHash] = await Promise.all([
          reader.getCircuitVersion(),
          reader.getPinnedVkHash(),
        ]);
        observation = validate(circuitVersion, vkHash);
      } catch (e) {
        observation = { kind: "failed", detail: (e as Error).message };
      }
      // Obsolete response: the configuration moved, the session was reset, or a
      // NEWER request for this same key was started while this one was in
      // flight. Return the value to THIS caller but never commit it
      // (addendum E + RED-2). The generation check is the load-bearing half:
      // key equality alone cannot see A -> B -> A or reset-then-reuse.
      if (this.key === forKey && this.gen === forGen) {
        this.settled = observation;
        this.inFlight = null;
      }
      return observation;
    })();
    this.inFlight = run;
    return run;
  }

  /**
   * Explicit invalidation (logout/boot), leaving no key attached. Bumping the
   * generation is what stops a request that was in flight ACROSS the reset from
   * committing over the observation of the session that followed it.
   */
  reset(): void {
    this.key = null;
    this.settled = null;
    this.inFlight = null;
    this.gen += 1;
  }
}

/** The cache key: the observation is per configured pool AND network host. */
export function poolIdentityKey(config: { poolCanisterId: string; host: string }): string {
  return `${config.poolCanisterId}@${config.host}`;
}
