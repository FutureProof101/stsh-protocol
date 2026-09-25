/**
 * STSH — no-store transport invariants for envelope traffic
 * (brief V1 §6, adopting a prior published no-cache discipline).
 *
 * WHAT THIS PROTECTS. A device envelope is an RSA-OAEP ciphertext of the user's
 * RAW vetKey. It is opaque without that device's private key, so caching it is
 * not an immediate disclosure — but a cached copy OUTLIVES revocation, and the
 * combined-compromise clause (D-1b v3 §1) is precisely about an attacker who
 * holds a copied envelope and later reaches the device key. A response that
 * lingers in an HTTP cache, a service-worker cache or a proxy is exactly that
 * copy, made without the user ever knowing.
 *
 * So: envelope traffic is fetched with `cache: "no-store"`, it is never routed
 * through a service worker, and nothing about it is written to storage. The
 * third of those is enforced by the HARD RULE in ../storage/noteCache.ts; the
 * first two are enforced here.
 */

/**
 * Canister methods whose responses must NEVER be cached, in any layer.
 *
 * `get_wrapped_secret` and `replace_envelope` carry the envelope itself;
 * `get_encrypted_vetkey` carries a transport-encrypted vetKey; `register_device`
 * carries the envelope on the way IN. Listed by name so a reviewer can check
 * the set against the .did rather than infer it.
 */
export const NEVER_CACHED_METHODS: readonly string[] = [
  "get_encrypted_vetkey",
  "get_wrapped_secret",
  "register_device",
  "replace_envelope",
];

/**
 * Wrap `fetch` so every request it makes is uncacheable.
 *
 * APPLIED TO THE WHOLE AGENT, not just envelope calls, deliberately: agent-js
 * batches and routes calls through one transport, and a per-method exemption
 * would have to reach inside it. Making the identity-bound agent uncacheable
 * costs nothing (IC replica responses are not cacheable anyway) and removes the
 * question of whether the exemption list is complete at every call site.
 *
 * BOTH mechanisms are set, because they cover different layers: the RequestInit
 * `cache` mode governs the browser's HTTP cache, while the `Cache-Control`
 * request header is what an intermediary sees.
 */
export function noStoreFetch(base: typeof fetch = globalThis.fetch): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers ?? {});
    headers.set("Cache-Control", "no-store");
    return base(input, { ...init, cache: "no-store", headers });
  };
}

/**
 * Assert that no service worker is in a position to cache envelope traffic.
 *
 * The wallet registers no service worker today, and this is the check that says
 * so at runtime rather than in a comment: if one is ever added — by this app or
 * by something sharing the origin — it must explicitly exclude the methods
 * above, and until it does, this throws.
 *
 * Returns silently in environments with no service-worker support at all.
 */
export async function assertNoServiceWorkerIntercept(
  scope: { navigator?: { serviceWorker?: ServiceWorkerContainer } } = globalThis,
): Promise<void> {
  const container = scope.navigator?.serviceWorker;
  if (container === undefined) return;
  const registrations = await container.getRegistrations();
  if (registrations.length === 0) return;
  throw new Error(
    "a service worker is registered on this origin: envelope endpoints " +
      `(${NEVER_CACHED_METHODS.join(", ")}) must be excluded from its fetch handler before ` +
      "the wallet may use it — a cached envelope outlives revocation",
  );
}
