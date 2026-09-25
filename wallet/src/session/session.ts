/**
 * Session + actor assembly (Campaign A / Wave 1, brief A1.2/A1.4).
 *
 * Two actor sets (H-A2/A-S7):
 *
 * - READ actors: typed wrappers over an ANONYMOUS agent. Public reads (token
 *   balance, staking positions, vesting schedule) work before/without login —
 *   actors are not gated on auth.
 * - MUTATION actors: constructed only after login, over an agent bound to the
 *   II identity. The app holds `null` until a session exists and refuses
 *   mutations while anonymous.
 *
 * Root key (A-S9): fetched only when the env requests it AND the host is an
 * explicit loopback — a production/mainnet host never fetches the root key.
 *
 * Campaign-B integration (L3a): the SHIELDED actor set (pool + vetkeys) joins
 * the identity-bound side. S-44 (V3.6.5 correction 1): the pool's owned reads
 * (`get_deposit_status`, `list_my_active_deposits`) are depositor-gated and
 * `get_encrypted_vetkey` derives for the caller — so these actors are built
 * ONLY over the II-bound agent, never the anonymous one. The former Wave-1
 * "no Campaign-B module in this graph" rule is superseded by the L3a
 * isolation gate (tests/isolation.test.ts): merkle/prover/scanner/OISY remain
 * out until their lanes (L3b/L3c) land.
 */

import { HttpAgent, type Identity } from "@dfinity/agent";

import { noStoreFetch } from "../net/noStore";
import type { AuthorizationAuthority } from "../actors/authorization";
import { createPoolActor, type PoolCanister } from "../actors/pool";
import { createStakingReadActor, type StakingReadCanister } from "../actors/staking";
import {
  createTokenActor,
  createTokenMutationActor,
  type TokenCanister,
  type TokenMutationCanister,
} from "../actors/token";
import { createVestingReadActor, type VestingReadCanister } from "../actors/vesting";
import { createUpgraderActor, type UpgraderCanister } from "../actors/upgrader";
import { createVaultActor, type VaultCanister } from "../actors/vault";
import { createVetkeysActor } from "../actors/vetkeys";
import type { VetkeysCanister } from "../crypto/vetkeys";
import { isLocalHost, type WalletConfig } from "./config";

export interface ReadActors {
  token: TokenCanister;
  /**
   * WALLET-READ-ACTORS: `null` when no staking canister is configured. Staking
   * is NOT INSTALLED at launch (D1, 2026-08-14), so the shipped config carries
   * `stakingCanisterId: ""` and this is `null` on mainnet.
   */
  staking: StakingReadCanister | null;
  vesting: VestingReadCanister;
}

export interface MutationActors {
  token: TokenMutationCanister;
}

/**
 * The shielded (Campaign-B) actor set — identity-bound ONLY (S-44). Built
 * after login alongside the mutation actors; `null` while anonymous. The pool
 * actor carries both the shield mutation and the depositor-gated owned reads;
 * the vetkeys actor's `get_encrypted_vetkey` derives for the caller.
 */
export interface ShieldedActors {
  pool: PoolCanister;
  vetkeys: VetkeysCanister;
}

/**
 * The J-17b operator (custody) actor set — identity-bound ONLY.
 *
 * The Vault's signing plane needs the II identity to be the caller, and EVERY
 * signer-gated query answers an unauthorized caller with an indistinguishable
 * `None` — so an anonymous operator actor could not even list proposals. Built
 * alongside the mutation actors and dropped on logout, which is what makes an
 * operator action after session revocation impossible rather than merely
 * refused by the canister.
 *
 * The Upgrader actor is read-only (see actors/upgrader.ts); it is identity-bound
 * so the recovery-member-gated reads work for an operator who is one.
 */
export interface OperatorActors {
  vault: VaultCanister;
  upgrader: UpgraderCanister;
}

/** Root key ONLY on an explicit loopback host (A-S9), whatever the env says. */
export function shouldFetchRootKey(config: WalletConfig): boolean {
  return config.fetchRootKey && isLocalHost(config.host);
}

/** Anonymous agent for the read actor set. */
export async function createReadAgent(config: WalletConfig): Promise<HttpAgent> {
  const agent = await HttpAgent.create({ host: config.host });
  if (shouldFetchRootKey(config)) await agent.fetchRootKey();
  return agent;
}

/**
 * Identity-bound agent for the mutation actor set — only called post-login.
 *
 * Uses the NO-STORE transport (brief V1 §6): this agent carries the vetKeys
 * envelope traffic, and a cached envelope outlives revocation. See
 * ../net/noStore.ts for why the whole agent is uncacheable rather than a
 * per-method exemption list.
 */
export async function createMutationAgent(
  config: WalletConfig,
  identity: Identity,
): Promise<HttpAgent> {
  const agent = await HttpAgent.create({
    host: config.host,
    identity,
    fetch: noStoreFetch(),
  });
  if (shouldFetchRootKey(config)) await agent.fetchRootKey();
  return agent;
}

/**
 * Build the anonymous read actor set.
 *
 * WALLET-READ-ACTORS: token and vesting are REQUIRED and built unconditionally —
 * a construction failure there (an empty or malformed id) throws, and the
 * caller's J-17c boot catch nulls every reader and shows the global notice.
 * Staking is built ONLY when an id is configured: an empty id is the D1
 * launch posture (staking not installed), not a fault, so it yields
 * `staking: null` with no throw. A NON-empty staking id is still constructed,
 * so a malformed one still throws. No try/catch here, no fallback principal.
 */
export function createReadActors(agent: HttpAgent, config: WalletConfig): ReadActors {
  return {
    token: createTokenActor(config.tokenCanisterId, agent),
    staking:
      config.stakingCanisterId !== ""
        ? createStakingReadActor(config.stakingCanisterId, agent)
        : null,
    vesting: createVestingReadActor(config.vestingCanisterId, agent),
  };
}

export function createMutationActors(
  agent: HttpAgent,
  config: WalletConfig,
  /** WL-2b authority — required: a production mutation actor is never unguarded. */
  authority: AuthorizationAuthority,
): MutationActors {
  return {
    token: createTokenMutationActor(config.tokenCanisterId, agent, authority),
  };
}

/**
 * Build the shielded actor set over the IDENTITY-BOUND agent (S-44). Throws if
 * the pool/vetkeys canister ids are unconfigured or invalid — the caller
 * treats that as "shielded features unavailable", never as a silent skip.
 */
export function createShieldedActors(
  agent: HttpAgent,
  config: WalletConfig,
  /** WL-2b authority — required: a production pool actor is never unguarded. */
  authority: AuthorizationAuthority,
): ShieldedActors {
  return {
    pool: createPoolActor(config.poolCanisterId, agent, authority),
    vetkeys: createVetkeysActor(config.vetkeysCanisterId, agent),
  };
}

/**
 * Build the operator actor set over the IDENTITY-BOUND agent. Throws if the
 * vault/upgrader ids are unconfigured or invalid — the caller records that as
 * "the operator surface is unavailable" and the page says why, rather than
 * rendering an empty proposal list that looks like "no proposals".
 */
export function createOperatorActors(agent: HttpAgent, config: WalletConfig): OperatorActors {
  return {
    vault: createVaultActor(config.vaultCanisterId, agent),
    upgrader: createUpgraderActor(config.upgraderCanisterId, agent),
  };
}
