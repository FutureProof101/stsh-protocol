/**
 * Wallet runtime configuration (Campaign A / Wave 1, brief A1.4/A1.5).
 *
 * Canister IDs + hosts come from Vite env vars at build time (VITE_*).
 * `resolveConfig` stays pure (takes a plain env record) so it is unit-testable;
 * origin-dependent policy lives in `evaluateSessionPolicy`, which the app MUST
 * consult before constructing any auth client or mutation actor (A-S8).
 *
 * The Campaign-B fields (pool/merkle/vetkeys/wallet-signer) are retained as
 * plain configuration data for Wave 2 — carrying an ID string is not a module
 * import; the H-A3 isolation gate is about the import graph and bundle.
 */

export interface WalletConfig {
  /** IC agent host (mainnet gateway, or a local replica). */
  host: string;
  /**
   * Root-key fetch REQUESTED via env. The session layer additionally requires a
   * loopback `host` (see `shouldFetchRootKey`) — a production host never
   * fetches the root key, whatever this flag says (A-S9).
   */
  fetchRootKey: boolean;
  poolCanisterId: string;
  merkleCanisterId: string;
  vetkeysCanisterId: string;
  tokenCanisterId: string;
  stakingCanisterId: string;
  vestingCanisterId: string;
  /** Nullifier-registry principal — part of the C-DOM-2 wiring hash (L3a). */
  nullifierCanisterId: string;
  /**
   * Verifier canister principal — part of the L3c deployment-wiring tuple the
   * manifest attestation check compares against the pool's OWN attestation
   * (L0-C complete tuple). No default: an unset value disables spend
   * fail-closed.
   */
  verifierCanisterId: string;
  /**
   * The ceremony-frozen pool principal the note crypto is domain-bound to
   * (C-DOM-2). Production fails closed unless the runtime pool principal
   * equals this; defaults to the pinned D2 pool principal.
   */
  frozenPoolCanisterId: string;
  /**
   * vetKD key name for a LOCAL/TEST build (C-VK-3): must be explicitly
   * configured (VITE_VETKD_KEY_NAME) — never defaulted, never inferred. A
   * production build ignores this and pins PRODUCTION_VETKD_KEY_NAME.
   */
  vetkdKeyName: string | undefined;
  /** OISY (or compatible ICRC-25 signer) relying-party URL (Campaign B). */
  walletSignerUrl: string;
  /**
   * Internet Identity provider override (VITE_II_URL) — honored on loopback
   * origins ONLY. In production the reviewed AuthClient 3.4.3 default provider
   * is used and an override is a policy violation (A-S20).
   */
  iiUrl: string | undefined;
  /**
   * WT-1 — the II **derivation origin**: the origin II derives principals from,
   * which is now DELIBERATELY NOT the origin the wallet is served from.
   *
   * C-19(b) REVERSAL (ruling record
   * `reviews/RULING_RECORD_SSOT_V91_AND_D1_D5_2026-09-14.md`). C-19(b) ruled a
   * single wallet domain and this field was consequently refused outright. That
   * ruling is reversed: principals are now rooted at the wallet canister's OWN
   * native origin (`NATIVE_WALLET_ORIGIN`), and `https://app.stsh.fi` is a mere
   * alias vouched for by a certified `.well-known/ii-alternative-origins` asset
   * served by that same canister. Rooting at the canister origin means the
   * principals survive the loss, expiry or hijack of the DNS name — the domain
   * can no longer mint or move anyone's identity.
   *
   * The guard is NOT removed, it is INVERTED into a POSITIVE assertion: a
   * configured value must EQUAL `NATIVE_WALLET_ORIGIN`; any other value is
   * refused exactly as before.
   *
   * PROVENANCE: runtime-loaded from the same-origin `wallet-config.json`
   * (`launchConfig.ts`), NOT from `import.meta.env`. Deliberate — Addendum A
   * (F-1) rules that no build-time env may alter the pinned bundle, and the two
   * `s3tyu` installs this lane schedules differ ONLY by this asset:
   *   - TRANSITIONAL bundle (Phase B.1): asset carries NO `derivationOrigin`,
   *     so logins yield the OLD (app.stsh.fi-derived) principals, which is what
   *     the rotation is executed with.
   *   - FINAL bundle (Phase D.8): asset carries the native origin, so logins
   *     yield the NEW canister-rooted principals.
   * One source head, two deployments, no source fork.
   */
  derivationOrigin: string | undefined;
  /**
   * J-17b — the custody Vault (signing plane) and the Upgrader (recovery
   * plane). Configuration data only; the operator route is the sole consumer.
   * Both default to the PINNED mainnet principals so an operator opening
   * `#/operator` on the shipped bundle is talking to the real ring without an
   * env var to get wrong. Overridable for a local replica dry run.
   */
  vaultCanisterId: string;
  upgraderCanisterId: string;
  /**
   * S1-02: the PRIMARY origin this deployment may serve from, loaded at RUNTIME
   * from the same-origin config asset — never from `import.meta.env`, which is
   * build-time. `undefined` means the config was absent, unreachable or
   * malformed, and the policy REFUSES; there is no compiled-in fallback.
   *
   * WT-1: this is no longer the WHOLE serving policy. One string used to mean
   * both "where we may be served" and "where principals come from" — that
   * conflation is the defect behind C-19(b). The two are now split: the
   * permitted SERVING set is `permittedServingOrigins()` (this value plus the
   * canister's own native origin), and the single pinned DERIVATION origin is
   * `derivationOrigin`.
   */
  launchOrigin: string | undefined;
}

/**
 * The pinned mainnet custody ring (deployment/mainnet/custody_manifest.toml).
 * The Vault is the ONLY canister the operator page ever sends an update to.
 */
export const DEFAULT_VAULT_CANISTER_ID = "cpdab-saaaa-aaaar-qca2q-cai";
export const DEFAULT_UPGRADER_CANISTER_ID = "cgal5-eiaaa-aaaar-qca3a-cai";

/** The deployed shielded-pool principal (mainnet-v2 domain id, anti-drift-pinned). */
export const DEFAULT_POOL_CANISTER_ID = "cxrfg-qaaaa-aaaar-qchfa-cai";

/**
 * WT-1 ADDENDUM A (a) — the remaining six mainnet principals, HARDCODED.
 *
 * WHY HARDCODED, and why NOT an env var (CTO ruling 2026-09-14, Addendum A F-1,
 * BINDING). Six of the nine ids previously defaulted to `""`, and an empty id is
 * not caught anywhere: it degrades only at the action site
 * (`ui/app.ts` `TRANSFER_SERVICES_UNCONFIGURED`), long after the user believed
 * the wallet was configured. Env could not fix it either — the pinned release
 * build `[wallet_bundle].command` is a bare `cd wallet && npm run build`
 * (`deployment/mainnet/release_hashes.toml:519`), `run_gate.sh` sets no `VITE_*`,
 * and `vite.config.ts` injects ONLY `[build].source_sha` (J-25 I1/I2). An
 * env-supplied id would therefore be invisible to the measured bundle, while a
 * stray operator-local `wallet/.env*` WOULD be auto-loaded by Vite and silently
 * change it — reproducibility from `source_sha` broken either way. Compiled-in
 * constants consumed through the existing `??` fallback are this tree's own
 * precedent (vault/upgrader/pool above).
 *
 * PROVENANCE — every value is the `target` row of the corresponding install
 * record in `deployment/mainnet/a7_install_kit.toml`, read from the record and
 * never hand-copied from chat or memory:
 *   verifier   a7_install_kit.toml:95    merkle     a7_install_kit.toml:115
 *   nullifier  a7_install_kit.toml:133   vetkeys    a7_install_kit.toml:184
 *   token      a7_install_kit.toml:216   vesting    a7_install_kit.toml:247
 *   pool       a7_install_kit.toml:277 (= DEFAULT_POOL_CANISTER_ID above)
 * Vault (`cpdab-…`) and Upgrader (`cgal5-…`) come from
 * `deployment/mainnet/custody_manifest.toml` and were already pinned above.
 *
 * `stakingCanisterId` is deliberately NOT given a default: staking is NOT
 * INSTALLED at launch (D1, 2026-08-14) and has no mainnet principal to pin.
 */
export const DEFAULT_MERKLE_CANISTER_ID = "cmuzd-kyaaa-aaaar-qchhq-cai";
export const DEFAULT_NULLIFIER_CANISTER_ID = "ccwul-riaaa-aaaar-qchgq-cai";
export const DEFAULT_VETKEYS_CANISTER_ID = "a7l2d-caaaa-aaaar-qchja-cai";
export const DEFAULT_TOKEN_CANISTER_ID = "clv7x-haaaa-aaaar-qchha-cai";
export const DEFAULT_VESTING_CANISTER_ID = "cfxs7-4qaaa-aaaar-qchga-cai";
export const DEFAULT_VERIFIER_CANISTER_ID = "arjxl-zqaaa-aaaar-qchia-cai";

/**
 * WT-1 — the wallet's OWN asset canister, and the origin II principals are
 * rooted at.
 *
 * `deployment/mainnet/custody_manifest.toml:241` and
 * `deployment/mainnet/vault_init.did:75` both name `s3tyu-aaaaa-aaaab-qhdjq-cai`
 * as `wallet_frontend`. The native origin is that id under the boundary-node
 * domain — the origin a browser sees when it loads the wallet directly from the
 * canister, with no DNS alias in the path.
 *
 * THIS IS THE ROOT OF IDENTITY. Every II principal the wallet uses derives from
 * this string. Changing it is not a config change: it silently re-derives every
 * user's principal, and their notes become unreachable. It is pinned here and
 * asserted against a literal in `tests/wt1_canister_rooted_identity.test.ts`.
 */
export const WALLET_FRONTEND_CANISTER_ID = "s3tyu-aaaaa-aaaab-qhdjq-cai";
export const NATIVE_WALLET_ORIGIN = "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io";

const MAINNET_HOST = "https://icp-api.io";
const DEFAULT_WALLET_URL = "https://oisy.com/sign";

/**
 * The ruled launch origin (C-19(b), Owner: single wallet domain `app.stsh.fi`).
 *
 * S1-02: this is NO LONGER what the session policy compares against — the policy
 * reads `config.launchOrigin`, loaded at runtime from the same-origin
 * `wallet-config.json` (see `launchConfig.ts`). This constant is retained as the
 * RULED VALUE that the shipped config asset must carry, and as the reference a
 * test pins against; it is deliberately NOT consulted by `evaluateSessionPolicy`,
 * because a compiled-in fallback is exactly what would mask a missing or tampered
 * config. Do not reintroduce it as a default — `O-3`/`O-8` fail if you do.
 */
export const PRODUCTION_ORIGIN = "https://app.stsh.fi";

/**
 * The vetKD curve key a PRODUCTION build asserts via `assertCanisterConfig`
 * (C-VK-3): pinned here, never configurable — a mainnet canister accidentally
 * left on a test key must fail closed, not be configured around.
 */
export const PRODUCTION_VETKD_KEY_NAME = "key_1";

export function resolveConfig(env: Record<string, string | undefined> = {}): WalletConfig {
  const host = env.VITE_IC_HOST ?? MAINNET_HOST;
  const fetchRootKey = env.VITE_FETCH_ROOT_KEY === "true";
  return {
    host,
    fetchRootKey,
    poolCanisterId: env.VITE_POOL_CANISTER_ID ?? DEFAULT_POOL_CANISTER_ID,
    merkleCanisterId: env.VITE_MERKLE_CANISTER_ID ?? DEFAULT_MERKLE_CANISTER_ID,
    vetkeysCanisterId: env.VITE_VETKEYS_CANISTER_ID ?? DEFAULT_VETKEYS_CANISTER_ID,
    tokenCanisterId: env.VITE_TOKEN_CANISTER_ID ?? DEFAULT_TOKEN_CANISTER_ID,
    // D1: staking is not installed at launch — no principal exists to default to.
    stakingCanisterId: env.VITE_STAKING_CANISTER_ID ?? "",
    vestingCanisterId: env.VITE_VESTING_CANISTER_ID ?? DEFAULT_VESTING_CANISTER_ID,
    nullifierCanisterId: env.VITE_NULLIFIER_CANISTER_ID ?? DEFAULT_NULLIFIER_CANISTER_ID,
    verifierCanisterId: env.VITE_VERIFIER_CANISTER_ID ?? DEFAULT_VERIFIER_CANISTER_ID,
    vaultCanisterId: env.VITE_VAULT_CANISTER_ID ?? DEFAULT_VAULT_CANISTER_ID,
    upgraderCanisterId: env.VITE_UPGRADER_CANISTER_ID ?? DEFAULT_UPGRADER_CANISTER_ID,
    frozenPoolCanisterId: env.VITE_FROZEN_POOL_CANISTER_ID ?? DEFAULT_POOL_CANISTER_ID,
    vetkdKeyName: env.VITE_VETKD_KEY_NAME,
    walletSignerUrl: env.VITE_WALLET_SIGNER_URL ?? DEFAULT_WALLET_URL,
    iiUrl: env.VITE_II_URL,
    // WT-1: BOTH of the next two are runtime-loaded (launchConfig.ts) and
    // injected by the caller; env cannot supply either, by design. For
    // `launchOrigin` that is S1-02 removing a build-time value; for
    // `derivationOrigin` it is Addendum A (F-1) keeping the pinned bundle free
    // of any env-dependent input, so the two `s3tyu` installs this lane
    // schedules differ by a deployed ASSET and not by a rebuild.
    derivationOrigin: undefined,
    launchOrigin: undefined,
  };
}

/**
 * Loopback test (brief A1.4). Accepts a full URL or an origin; anything that
 * does not parse, or does not resolve to an explicit loopback hostname, is NOT
 * local — i.e. every non-loopback host is treated as production.
 */
export function isLocalHost(host: string): boolean {
  try {
    const h = new URL(host).hostname;
    return (
      h === "localhost" ||
      h.endsWith(".localhost") ||
      h === "::1" ||
      h === "[::1]" ||
      /^127\.\d+\.\d+\.\d+$/.test(h)
    );
  } catch {
    return false;
  }
}

/**
 * The session policy for the RUNNING origin, decided BEFORE any auth-client or
 * mutation-actor construction (A-S8):
 *
 * - `local`      — loopback origin: II-URL override honored, root key allowed.
 * - `production` — the origin is IN the permitted serving set (WT-1: the native
 *                  wallet-canister origin or the runtime-loaded launch origin),
 *                  no identity-provider override is present, and any configured
 *                  derivation origin is exactly the pinned native origin:
 *                  reviewed AuthClient 3.4.3 default provider. The policy
 *                  CARRIES the derivation origin forward — it is the only thing
 *                  authorised to tell the auth layer what to send.
 * - `blocked`    — anything else: login and ALL mutations are refused
 *                  (anonymous reads still work). A stale delegation restored on
 *                  a wrong origin must never reach a mutation actor.
 */
export type SessionPolicy =
  | { kind: "local"; iiUrl: string | undefined; derivationOrigin: undefined }
  | { kind: "production"; iiUrl: undefined; derivationOrigin: string | undefined }
  | { kind: "blocked"; reason: string };

/**
 * WT-1 — the PERMITTED SERVING ORIGIN SET.
 *
 * The same bundle is served from two places, and both are legitimate: the
 * canister's own native origin (`NATIVE_WALLET_ORIGIN`, which is also the
 * derivation root) and the human-facing DNS alias carried in the runtime launch
 * config (`https://app.stsh.fi`). Serving from the alias is safe ONLY because
 * identity no longer depends on it — the alias is vouched for by the certified
 * `.well-known/ii-alternative-origins` asset the native origin serves, and every
 * principal derives from the native origin either way.
 *
 * Membership is CLOSED: exactly these two, and a missing launch config
 * contributes nothing (the policy refuses upstream on that path anyway). A third
 * origin — a staging host, a mirror, a phishing lookalike — is not in the set and
 * is blocked, which is the S1-02 guarantee, unweakened.
 */
export function permittedServingOrigins(config: WalletConfig): readonly string[] {
  const permitted = [NATIVE_WALLET_ORIGIN];
  if (config.launchOrigin !== undefined && config.launchOrigin !== "") {
    permitted.push(config.launchOrigin);
  }
  return permitted;
}

export function evaluateSessionPolicy(config: WalletConfig, origin: string): SessionPolicy {
  if (isLocalHost(origin)) {
    // Loopback dev: II-URL override permitted. derivationOrigin is still never
    // forwarded to the auth client (alternative origins are out of campaign).
    return { kind: "local", iiUrl: config.iiUrl, derivationOrigin: undefined };
  }
  // S1-02: no launch config, no login. This branch comes FIRST and names the
  // missing config in its reason, so a refusal caused by absent configuration is
  // distinguishable from a refusal caused by a wrong origin — an arm asserting
  // "it refused" could otherwise pass for the wrong reason.
  if (config.launchOrigin === undefined || config.launchOrigin === "") {
    return {
      kind: "blocked",
      reason:
        "The wallet launch configuration (wallet-config.json) is missing or unreadable, " +
        "so the origin this build may serve from cannot be established. Login and transfers are disabled.",
    };
  }
  // WT-1: membership in the permitted SERVING set, not equality with one string.
  // The refusal wording still names the origin mismatch, so an arm asserting
  // "it refused" cannot pass on the missing-config refusal by accident.
  if (!permittedServingOrigins(config).includes(origin)) {
    return {
      kind: "blocked",
      reason:
        `This origin (${origin}) is not the production wallet origin ` +
        `(permitted: ${permittedServingOrigins(config).join(", ")}). Login and transfers are disabled.`,
    };
  }
  // WT-1: the derivationOrigin guard, INVERTED from "refuse any" to "require
  // exactly the pinned native origin". C-19(b) refused this field outright; that
  // ruling is reversed (see the field's docstring). What has NOT changed is that
  // an unrecognised value is refused — forwarding an origin nobody authorised
  // hands the user a different principal with their notes unreachable, which is
  // precisely the failure the original guard existed to prevent.
  //
  // `undefined` is PERMITTED and means the transitional (Phase B.1) deployment:
  // no derivationOrigin is forwarded and II derives from the serving origin,
  // exactly as it did before this lane. It is the pre-WT-1 behaviour, not a
  // weakening, and it is what the rotation is executed under.
  if (config.derivationOrigin !== undefined && config.derivationOrigin !== NATIVE_WALLET_ORIGIN) {
    return {
      kind: "blocked",
      reason:
        `A derivationOrigin override (${config.derivationOrigin}) is configured that is not the ` +
        `pinned wallet-canister origin (${NATIVE_WALLET_ORIGIN}); login and transfers are disabled.`,
    };
  }
  if (config.iiUrl !== undefined) {
    return {
      kind: "blocked",
      reason: "An identity-provider override (VITE_II_URL) is configured; production uses the reviewed default provider only.",
    };
  }
  return { kind: "production", iiUrl: undefined, derivationOrigin: config.derivationOrigin };
}

// ── WL-2c: the randomised-submission-delay preference ────────────────────────
//
// STORAGE CHOICE, and why it is the safe one: this lives in `localStorage`,
// which the panic wipe clears (`panicWipe.ts` enumerates and empties it, and
// asserts it empty afterwards). So a wiped device comes back with the delay
// OFF — the DEFAULT, and the fail-safe direction: the user is never silently
// left with a setting they cannot see, and the wipe contract is not relaxed to
// accommodate a preference. Nothing here is secret: it is a boolean about this
// browser's UX, holds no note, key or principal, and is never sent anywhere.

/** The one key the preference is stored under. */
export const SUBMISSION_DELAY_STORAGE_KEY = "stsh.wallet.submissionDelay";

/** Default OFF — a delay the user did not ask for is a surprise, not a feature. */
export const SUBMISSION_DELAY_DEFAULT = false;

/** Read the preference. Any unreadable/absent/garbled value reads as the default. */
export function readSubmissionDelayEnabled(store?: Pick<Storage, "getItem">): boolean {
  const local = store ?? (typeof localStorage === "undefined" ? null : localStorage);
  if (local === null) return SUBMISSION_DELAY_DEFAULT;
  try {
    const raw = local.getItem(SUBMISSION_DELAY_STORAGE_KEY);
    if (raw === null) return SUBMISSION_DELAY_DEFAULT;
    return raw === "on";
  } catch {
    return SUBMISSION_DELAY_DEFAULT;
  }
}

/** Persist the preference; a storage failure is swallowed (the toggle is advisory). */
export function writeSubmissionDelayEnabled(
  enabled: boolean,
  store?: Pick<Storage, "setItem">,
): void {
  const local = store ?? (typeof localStorage === "undefined" ? null : localStorage);
  if (local === null) return;
  try {
    local.setItem(SUBMISSION_DELAY_STORAGE_KEY, enabled ? "on" : "off");
  } catch {
    // A browser refusing storage must not break the spend/shield path.
  }
}
