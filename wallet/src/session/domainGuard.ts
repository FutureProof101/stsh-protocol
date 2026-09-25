/**
 * Deployment-binding guard (C-DOM-2 wallet companion, L3a).
 *
 * The pool's P-DOM gate (canisters/shielded-pool assert_deployment_config)
 * authoritatively rejects a shield/spend whose expected deployment-config hash
 * does not match the pool's live wiring. This module is the wallet half:
 *
 *  1. `computeDeploymentConfigHash` derives the SAME hash the pool computes,
 *     byte-for-byte, so the wallet can pass it into shield_deposit /
 *     private_spend. A pinned TS↔Rust interop vector guards the encoding.
 *  2. `assertDeploymentBinding` is the wallet-side pre-flight fail-closed check:
 *     the runtime pool principal must equal the ceremony-frozen one, and every
 *     configured actor (pool/token/merkle/nullifier) must be present — so the
 *     wallet never even attempts to shield to a pool it is not domain-bound to.
 *     The pool gate is the authority; this is defence-in-depth (and produces the
 *     hash the pool gate checks).
 *
 * Canonical encoding — IDENTICAL to canisters/shielded-pool compute_deployment_config_hash:
 *   SHA-256( "stsh.deployment-config.v1"
 *            || u32_be(DEPLOYMENT_CONFIG_VERSION)
 *            || P(pool) || P(token) || P(merkle) || P(nullifier) )
 *   P(x) = u8(len) || raw principal bytes    (principals are <=29 bytes)
 *   pool = the pool's OWN principal, bound FIRST.
 */

import { Principal } from "@dfinity/principal";

/** Domain separator — must equal the pool's DEPLOYMENT_CONFIG_DOMAIN. */
export const DEPLOYMENT_CONFIG_DOMAIN = "stsh.deployment-config.v1";
/** Fixed schema version — must equal the pool's DEPLOYMENT_CONFIG_VERSION. */
export const DEPLOYMENT_CONFIG_VERSION = 1;

/** The four immutable-wiring principals bound into the hash (pool FIRST). */
export interface DeploymentWiring {
  pool: Principal;
  token: Principal;
  merkle: Principal;
  nullifier: Principal;
}

function lengthPrefixed(p: Principal): Uint8Array {
  const bytes = p.toUint8Array();
  if (bytes.length > 29) {
    throw new Error(`principal is ${bytes.length} bytes; the length prefix expects <=29`);
  }
  const out = new Uint8Array(1 + bytes.length);
  out[0] = bytes.length;
  out.set(bytes, 1);
  return out;
}

/**
 * Compute the deployment-config hash the pool's P-DOM gate checks. Byte-for-byte
 * identical to the pool's `compute_deployment_config_hash` (pinned interop
 * vector in tests). Async because it uses the WebCrypto SHA-256.
 */
export async function computeDeploymentConfigHash(wiring: DeploymentWiring): Promise<Uint8Array> {
  const domain = new TextEncoder().encode(DEPLOYMENT_CONFIG_DOMAIN);
  const version = new Uint8Array(4);
  new DataView(version.buffer).setUint32(0, DEPLOYMENT_CONFIG_VERSION, false); // u32 big-endian

  // pool FIRST, then the immutable dependency wiring, each length-prefixed.
  const parts = [
    domain,
    version,
    lengthPrefixed(wiring.pool),
    lengthPrefixed(wiring.token),
    lengthPrefixed(wiring.merkle),
    lengthPrefixed(wiring.nullifier),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const preimage = new Uint8Array(total);
  let off = 0;
  for (const part of parts) {
    preimage.set(part, off);
    off += part.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", preimage as BufferSource);
  return new Uint8Array(digest);
}

/** A deployment-binding pre-flight failure — shield/spend must NOT proceed. */
export class DeploymentBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeploymentBindingError";
  }
}

export interface DeploymentGuardConfig {
  /** Runtime-configured principals (from VITE_* env). */
  poolCanisterId: string;
  tokenCanisterId: string;
  merkleCanisterId: string;
  nullifierCanisterId: string;
  /**
   * The ceremony-frozen pool principal the wallet's note crypto is bound to. On
   * a production build the runtime pool principal MUST equal this; on a
   * local/loopback build the caller passes the runtime pool principal itself to
   * relax the check (the pool gate still authoritatively enforces the wiring).
   */
  frozenPoolCanisterId: string;
  /** Production builds fail closed on a frozen-principal mismatch; local does not. */
  enforceFrozenPool: boolean;
}

function parsePrincipal(text: string, label: string): Principal {
  if (text.trim() === "") {
    throw new DeploymentBindingError(`${label} is not configured (empty) — refusing to shield/spend`);
  }
  try {
    return Principal.fromText(text);
  } catch {
    throw new DeploymentBindingError(`${label} is not a valid principal: "${text}"`);
  }
}

/**
 * Wallet-side pre-flight (C-DOM-2). Fails closed if the wiring is incomplete or
 * (on production) the runtime pool principal differs from the ceremony-frozen
 * one the notes are bound to. Returns the deployment-config hash to pass into
 * shield_deposit / private_spend so the pool gate can authoritatively confirm.
 */
export async function assertDeploymentBinding(
  config: DeploymentGuardConfig,
): Promise<{ hash: Uint8Array; wiring: DeploymentWiring }> {
  const pool = parsePrincipal(config.poolCanisterId, "pool canister id");
  const token = parsePrincipal(config.tokenCanisterId, "token canister id");
  const merkle = parsePrincipal(config.merkleCanisterId, "merkle canister id");
  const nullifier = parsePrincipal(config.nullifierCanisterId, "nullifier canister id");

  if (config.enforceFrozenPool) {
    const frozen = parsePrincipal(config.frozenPoolCanisterId, "frozen pool canister id");
    if (pool.toText() !== frozen.toText()) {
      throw new DeploymentBindingError(
        `runtime pool principal (${pool.toText()}) does not match the ceremony-frozen pool ` +
          `principal (${frozen.toText()}) the notes are bound to — refusing to shield/spend`,
      );
    }
  }

  const wiring: DeploymentWiring = { pool, token, merkle, nullifier };
  const hash = await computeDeploymentConfigHash(wiring);
  return { hash, wiring };
}
