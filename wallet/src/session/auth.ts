/**
 * Internet Identity auth wrapper (Campaign A / Wave 1, brief A1.1/A1.4;
 * corrective lane AC-2 — aligned on @dfinity/auth-client@3.4.3).
 *
 * 3.4.3 facts this module is written against, verified in tests/auth_343:
 *
 * - The client replaces the provider URL hash with `#authorize` (NOT
 *   `/authorize`) and defaults `identityProvider` to the reviewed
 *   `https://identity.internetcomputer.org`. Production uses that default;
 *   an override is honored on loopback origins only (policy-enforced upstream).
 * - `isAuthenticated()` on 3.4.3 DOES validate delegation expiry itself
 *   (`isDelegationValid` runs inside the client). `verifyIdentity` below is
 *   NOT redundant with it: the independent 8-hour delegation ceiling is THIS
 *   APP'S policy (Owner-ruled, retained) — a delegation the SDK considers
 *   live but that outlives anything this app ever requests is still rejected.
 * - `login()` returns a Promise<void>; the completion callbacks remain the
 *   authentication-completion signal, with rejection handling attached to the
 *   returned promise so an SDK-side failure can neither go unhandled nor
 *   bypass the callback contract.
 * - The ~10-minute idle logout ships enabled by default; we configure it
 *   explicitly (timeout + callback) so the behavior is pinned, not implicit.
 *
 * `derivationOrigin` (WT-1, C-19(b) REVERSED — ruling record
 * `reviews/RULING_RECORD_SSOT_V91_AND_D1_D5_2026-09-14.md`). It WAS deliberately
 * never passed to the client, because C-19(b) ruled a single wallet domain and
 * an unauthorised alternative origin would hand the user a different principal
 * with their notes unreachable. That ruling is reversed: II principals are now
 * rooted at the wallet canister's OWN native origin so that they survive the
 * loss or hijack of the `app.stsh.fi` DNS name, and reaching that root from the
 * alias REQUIRES forwarding the value.
 *
 * The safety property is preserved by WHERE the value comes from: this module
 * forwards ONLY `policy.derivationOrigin`, and a `production` policy carries
 * that field only after `evaluateSessionPolicy` has asserted it equals the
 * pinned `NATIVE_WALLET_ORIGIN`. There is no path from env, storage, a query
 * string or any caller-supplied string to `login()`. When the policy carries
 * `undefined` (the transitional deployment) the key is OMITTED from the options
 * object entirely, not sent as `undefined` — so the pre-WT-1 wire behaviour is
 * byte-identical.
 *
 * OUT OF SCOPE here, unchanged: II `targets` / scoped delegations. The scoped
 * chain predicates and `SCOPED_DELEGATION_REFUSAL` below are untouched by WT-1.
 */

import type { Identity } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { isDelegationValid, type DelegationChain } from "@dfinity/identity";
import type { Principal } from "@dfinity/principal";

import type { SessionPolicy } from "./config";

/** 8-hour delegation ceiling (A1.4), requested at login AND re-checked on restore. */
export const MAX_DELEGATION_TTL_NS = 8n * 60n * 60n * 1_000_000_000n;
/** Allowed clock skew when checking the ceiling against a fresh delegation. */
const TTL_CHECK_SKEW_NS = 5n * 60n * 1_000_000_000n;
/** The auth-client default ~10-minute idle logout, configured explicitly (A-S20). */
export const IDLE_TIMEOUT_MS = 10 * 60 * 1000;

export type SessionVerdict = "valid" | "expired" | "anonymous";

/** Structural view of DelegationIdentity — duck-typed so tests can substitute. */
export interface DelegationIdentityLike extends Identity {
  getDelegation(): DelegationChain;
}

function hasDelegation(identity: Identity): identity is DelegationIdentityLike {
  return typeof (identity as Partial<DelegationIdentityLike>).getDelegation === "function";
}

/**
 * Verified-expiry check (A-S10/A-S13). Only this — never a transport or
 * canister error — may declare a session dead:
 *
 * - anonymous principal, or no delegation chain at all -> "anonymous"
 * - an EMPTY delegation chain -> "anonymous" (decided before any reduce, so an
 *   empty chain can never fall through to a fail-open verdict; SSA B-1)
 * - `isDelegationValid()` false -> "expired" (the ONLY logout-worthy verdict)
 * - any delegation carrying non-null `targets` -> "expired": a scoped
 *   delegation would silently fail Vault calls, so it is refused up front
 *   (absent is `undefined`; `targets: []` is scoped-to-nothing and also
 *   refused; SSA B-2)
 * - an EFFECTIVE session lifetime — the MINIMUM expiration across the chain —
 *   further out than the 8-hour ceiling this app ever requests (plus skew)
 *   -> "expired"
 *
 * J-17d: the ceiling is applied to the chain minimum, not to every link.
 * Internet Identity 2.0 returns a three-delegation chain whose leaf honours the
 * requested 8h `maxTimeToLive` while the two upstream delegations are II's own
 * 30-day internal ones. Those upstream delegations are not something this app
 * requested, and they do not extend the session: the chain is usable only until
 * its earliest expiration. Applying the ceiling per-link rejected every real II
 * login. The SDK's `isDelegationValid` still requires EVERY delegation to be
 * unexpired, so the minimum is a ceiling test, not a weakened validity test.
 *
 * The ceiling is deliberately independent of 3.4.3's own `isAuthenticated()`
 * validity check: the SDK verifies the delegation is live; this verifies it is
 * one OURS could have granted (application policy, retained per ruling).
 */
export function verifyIdentity(identity: Identity, nowMs: () => number = Date.now): SessionVerdict {
  if (identity.getPrincipal().isAnonymous()) return "anonymous";
  if (!hasDelegation(identity)) return "anonymous";
  const chain = identity.getDelegation();
  // B-1: an empty chain is decided here, before any reduction over delegations.
  if (chain.delegations.length === 0) return "anonymous";
  if (!isDelegationValid(chain)) return "expired";
  if (isScopedChain(chain)) return "expired";
  let minExpiration = chain.delegations[0].delegation.expiration;
  for (const signed of chain.delegations) {
    if (signed.delegation.expiration < minExpiration) minExpiration = signed.delegation.expiration;
  }
  const ceiling = BigInt(nowMs()) * 1_000_000n + MAX_DELEGATION_TTL_NS + TTL_CHECK_SKEW_NS;
  if (minExpiration > ceiling) return "expired";
  return "valid";
}

/**
 * True when ANY delegation in the chain is scoped to targets. `targets` is
 * absent (`undefined`) on an unscoped delegation, so the predicate is a
 * non-null test: `targets: []` and `targets: [canister]` both refuse.
 */
function isScopedChain(chain: DelegationChain): boolean {
  return chain.delegations.some((signed) => signed.delegation.targets != null);
}

/** True when the identity carries a scoped delegation chain (see above). */
export function hasScopedDelegation(identity: Identity): boolean {
  if (!hasDelegation(identity)) return false;
  return isScopedChain(identity.getDelegation());
}

/** Refusal copy for a scoped delegation, surfaced where login errors are shown. */
export const SCOPED_DELEGATION_REFUSAL =
  "Internet Identity returned a scoped delegation: scoped delegation not supported.";

/** The subset of AuthClient this module uses — injectable for tests. */
export interface AuthClientLike {
  isAuthenticated(): Promise<boolean>;
  getIdentity(): Identity;
  /** 3.4.3: returns a Promise; the callbacks remain the completion signal. */
  login(options: {
    identityProvider?: string;
    /** WT-1: the pinned native wallet-canister origin, or absent. */
    derivationOrigin?: string;
    maxTimeToLive?: bigint;
    onSuccess?: () => void;
    onError?: (error?: string) => void;
  }): Promise<void>;
  logout(): Promise<void>;
}

export interface AuthSession {
  identity: DelegationIdentityLike;
  /** Sourced ONLY from identity.getPrincipal() (A-S7). */
  principal: Principal;
}

export interface WalletAuth {
  /**
   * Restore a stored session. Returns null when there is none, or when the
   * stored delegation fails VERIFIED expiry (in which case the dead session is
   * discarded from client storage). Never logs out for any other reason.
   */
  restore(): Promise<AuthSession | null>;
  /**
   * Interactive II login. Resolves to a verified session, or rejects leaving
   * no session behind (failed-login atomicity): an error/cancel mutates
   * nothing, and a login that produced an invalid delegation is discarded.
   */
  login(): Promise<AuthSession>;
  logout(): Promise<void>;
  /** Verified-expiry verdict for the client's CURRENT identity. */
  verify(): SessionVerdict;
}

export interface WalletAuthDeps {
  /** Test seam; production builds a real AuthClient with explicit idle config. */
  createClient?: (onIdle: () => void) => Promise<AuthClientLike>;
  nowMs?: () => number;
}

async function defaultCreateClient(onIdle: () => void): Promise<AuthClientLike> {
  return AuthClient.create({
    idleOptions: { idleTimeout: IDLE_TIMEOUT_MS, onIdle },
  });
}

/**
 * Build the wallet's auth port for an ALLOWED policy. A "blocked" policy must
 * never reach this constructor — the app refuses login upstream (A-S8).
 */
export async function createWalletAuth(
  policy: SessionPolicy,
  onIdle: () => void,
  deps: WalletAuthDeps = {},
): Promise<WalletAuth> {
  if (policy.kind === "blocked") {
    throw new Error(`createWalletAuth called under a blocked session policy: ${policy.reason}`);
  }
  const createClient = deps.createClient ?? defaultCreateClient;
  const nowMs = deps.nowMs ?? (() => Date.now());
  const client = await createClient(onIdle);
  // undefined -> the reviewed AuthClient 3.4.3 default provider (A-S11/A-S20).
  const identityProvider = policy.kind === "local" ? policy.iiUrl : undefined;
  // WT-1: sourced ONLY from the policy, which has already asserted it equals the
  // pinned native origin. `undefined` => the key is omitted below.
  const derivationOrigin = policy.derivationOrigin;

  function sessionFromVerifiedIdentity(): AuthSession | null {
    const identity = client.getIdentity();
    if (verifyIdentity(identity, nowMs) !== "valid") return null;
    return {
      identity: identity as DelegationIdentityLike,
      principal: identity.getPrincipal(),
    };
  }

  return {
    verify(): SessionVerdict {
      return verifyIdentity(client.getIdentity(), nowMs);
    },

    async restore(): Promise<AuthSession | null> {
      if (!(await client.isAuthenticated())) return null;
      const session = sessionFromVerifiedIdentity();
      if (session === null) {
        // VERIFIED expiry (or an unusable identity) on a stored session: drop
        // it from client storage. Transport/canister errors never reach here.
        await client.logout();
        return null;
      }
      return session;
    },

    async login(): Promise<AuthSession> {
      await new Promise<void>((resolve, reject) => {
        // The onSuccess/onError callbacks are the authentication-completion
        // signal; the promise login() returns on 3.4.3 gets rejection handling
        // attached so an SDK-side failure is neither unhandled nor silent.
        const loginCall = client.login({
          identityProvider,
          // Spread, not `derivationOrigin: undefined`: the transitional
          // deployment must send an options object with NO such key, so its wire
          // behaviour is byte-identical to the pre-WT-1 client.
          ...(derivationOrigin === undefined ? {} : { derivationOrigin }),
          maxTimeToLive: MAX_DELEGATION_TTL_NS,
          onSuccess: () => resolve(),
          onError: (error) =>
            reject(new Error(`Internet Identity login failed: ${error ?? "unknown error"}`)),
        });
        loginCall.catch((error: unknown) =>
          reject(
            error instanceof Error
              ? error
              : new Error(`Internet Identity login failed: ${String(error)}`),
          ),
        );
      });
      const landed = client.getIdentity();
      const session = sessionFromVerifiedIdentity();
      if (session === null) {
        // Read the refusal reason BEFORE logout drops the identity.
        const scoped = hasScopedDelegation(landed);
        await client.logout();
        throw new Error(
          scoped
            ? SCOPED_DELEGATION_REFUSAL
            : "Internet Identity login produced an invalid or expired delegation.",
        );
      }
      return session;
    },

    async logout(): Promise<void> {
      await client.logout();
    },
  };
}
