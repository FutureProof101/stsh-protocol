/**
 * S1-02 — the launch origin as a RUNTIME-loaded value.
 *
 * `PRODUCTION_ORIGIN` was a compile-time constant, so changing the wallet's
 * launch origin meant a rebuild. This module fetches it from a JSON asset served
 * SAME-ORIGIN by the wallet's own asset canister.
 *
 * Two properties are load-bearing and are the reason this is not simply "read a
 * config file":
 *
 * 1. **Same-origin only.** The origin check must not depend on a resource
 *    outside the origin being checked, so the path is relative and no host is
 *    ever named. A config fetched from a third party would let that third party
 *    decide which origin may hold user funds.
 *
 * 2. **Fails closed, with no compiled-in fallback.** Absent, unreachable,
 *    malformed, empty, or wrong-shaped config all produce `undefined`, and the
 *    session policy refuses exactly as it refuses a non-matching origin. A
 *    fallback to a baked-in default is precisely what would mask a missing or
 *    tampered config, so there is none.
 *
 * SCOPE, stated where it is implemented (justification-scope rule): this removes
 * the REBUILD, not the REDEPLOY. The asset still ships through the wallet's
 * asset canister, and an operator changing the origin still deploys. It is also
 * NOT a reduction in the drift-lock's strength — the policy refuses a
 * non-matching origin exactly as before; only the provenance of the expected
 * value changes.
 *
 * Never user-settable: not read from `localStorage`, a query string, or any
 * client-supplied input. Its writer is whoever controls the wallet asset
 * canister — the cutover controller set.
 */

/** Same-origin, relative by construction: no host may be named here. */
export const LAUNCH_CONFIG_PATH = "wallet-config.json";

export interface LaunchConfig {
  /** The origin this wallet deployment is allowed to serve from. */
  launchOrigin: string;
  /**
   * WT-1 — the II derivation origin this deployment forwards to the auth
   * client, or absent for the transitional (Phase B.1) deployment. Validated by
   * the SESSION POLICY against the pinned native origin, never here: this module
   * only decides whether the value is a well-formed bare https origin, and
   * `config.ts` decides whether it is the RIGHT one. Keeping shape and identity
   * separate is what stops a well-formed but wrong origin from being accepted
   * because it parsed.
   */
  derivationOrigin?: string;
}

/**
 * Validate a candidate launch origin. It must be a BARE `https:` origin.
 *
 * SSA-B landed-diff RED-1 (W-WALLET-ORIGIN V1): the first version of this
 * function canonicalised — it accepted `https://app.stsh.fi/wallet?x=1#y` and
 * returned the bare origin — while this docstring and the package both said
 * path-bearing input was rejected. Same subject, two contracts. The contract is
 * now REJECTION, chosen deliberately over canonicalisation:
 *
 * this asset is a security control, and silently repairing an operator's value
 * means the deployed config and the enforced value can differ without anyone
 * being told. A config that does not say exactly what is enforced must fail
 * closed and be fixed at the source, not normalised in flight.
 *
 * Returns the origin, or `undefined` for anything else: a non-string, empty or
 * whitespace, an unparseable URL, a non-`https:` scheme, embedded credentials,
 * any path other than the root, or any query or fragment. `undefined` refuses.
 */
export function normaliseLaunchOrigin(value: unknown): string | undefined {
  if (typeof value !== "string" || value.trim() !== value || value === "") return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:") return undefined;
  // Credentials in a launch-origin value are never meaningful and would be a
  // strong signal the asset was tampered with.
  if (url.username !== "" || url.password !== "") return undefined;
  // `new URL("https://app.stsh.fi")` normalises pathname to "/", so the root
  // slash is the only path accepted; "/wallet" and "/" + anything are refused.
  if (url.pathname !== "/") return undefined;
  if (url.search !== "" || url.hash !== "") return undefined;
  // Reconstructed from the parsed parts, so a trailing-slash spelling and its
  // bare form yield one canonical value without ACCEPTING anything more.
  return url.origin;
}

/**
 * Load the launch origin from the same-origin config asset.
 *
 * Returns `undefined` on every failure path — network error, non-2xx, unparseable
 * body, missing field, wrong type, empty string, non-https. The caller refuses.
 */
export async function loadLaunchOrigin(
  fetchImpl: typeof fetch = fetch,
  path: string = LAUNCH_CONFIG_PATH,
): Promise<string | undefined> {
  let body: unknown;
  try {
    const res = await fetchImpl(path);
    if (!res.ok) return undefined;
    body = await res.json();
  } catch {
    return undefined;
  }
  if (typeof body !== "object" || body === null) return undefined;
  return normaliseLaunchOrigin((body as Record<string, unknown>).launchOrigin);
}

/**
 * WT-1 — load the DERIVATION origin from the same-origin config asset.
 *
 * Same asset, same loader discipline, same rejection contract as
 * `loadLaunchOrigin`: same-origin relative path, no host ever named, every
 * failure path yields `undefined`.
 *
 * `undefined` here is NOT a refusal. It means "this deployment forwards no
 * derivation origin", which is the TRANSITIONAL (Phase B.1) bundle and is
 * identical to the wallet's pre-WT-1 behaviour. The final (Phase D.8) bundle
 * ships the asset with the field present. A value that IS present but is not the
 * pinned native origin is refused by `evaluateSessionPolicy`, not here.
 */
export async function loadDerivationOrigin(
  fetchImpl: typeof fetch = fetch,
  path: string = LAUNCH_CONFIG_PATH,
): Promise<string | undefined> {
  let body: unknown;
  try {
    const res = await fetchImpl(path);
    if (!res.ok) return undefined;
    body = await res.json();
  } catch {
    return undefined;
  }
  if (typeof body !== "object" || body === null) return undefined;
  const raw = (body as Record<string, unknown>).derivationOrigin;
  if (raw === undefined) return undefined;
  return normaliseLaunchOrigin(raw);
}
