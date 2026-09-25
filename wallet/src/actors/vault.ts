/**
 * Custody Vault actor (J-17b — the operator signing surface).
 *
 * Unlike the other wrappers in this directory this one stays CLOSE to the
 * candid shapes: the operator page's whole job is to show a signer exactly what
 * is on chain and exactly what it is about to send, so a camelCase re-modelling
 * would put a translation layer between the signer and the bytes. What the
 * wrapper does add is the two things a raw actor gets wrong for this use:
 *
 * - `opt` unwrapping to `null`. Every signer-gated query answers an
 *   unauthorized caller with an INDISTINGUISHABLE `None` (vault.did freeze §4)
 *   — anonymous, removed, stale-epoch and unknown are one observable, and the
 *   page must render that as "not a signer (or not authorized)", never as
 *   "empty".
 * - `{Ok}|{Err}` splitting into a typed result, so an `Err` is surfaced
 *   verbatim rather than thrown away into a generic failure string.
 *
 * NOTHING here retries. An update that returns a transport error is reported as
 * exactly that and left for the operator to decide about: `propose` and
 * `approve` are not idempotent from the caller's side, and a silent retry of a
 * quorum action is the last thing this surface should invent.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

import { idlFactory } from "../../../src/declarations/vault/vault.did.js";
import type {
  ApprovalOutcome,
  AuditEvent,
  CreationReceiptPage,
  GovernanceSummary,
  GovernedTarget,
  ProposalView,
  VaultActionKind,
  VaultError,
  VaultTargets,
  _SERVICE,
} from "../../../src/declarations/vault/vault.did";

/** `{ Ok } | { Err }` flattened. Never thrown — the page renders both. */
export type VaultResult<T> = { ok: T } | { err: VaultError };

function flatten<T>(raw: { Ok: T } | { Err: VaultError }): VaultResult<T> {
  return "Ok" in raw ? { ok: raw.Ok } : { err: raw.Err };
}

/** `opt T` -> `T | null`. `null` on a signer-gated query means UNAUTHORIZED. */
function opt<T>(value: [] | [T]): T | null {
  return value.length === 1 ? value[0] : null;
}

export interface VaultCanister {
  // ── Quorum plane (updates) ────────────────────────────────────────────────
  /**
   * `lifetime_ns` is deliberately absent from this signature: the page sends
   * `null` (the ruled default) and V1 exposes no custom-lifetime field
   * (SSA F-04). Adding one means ruling the §10.5 bounds first — until then an
   * explicit lifetime is refused by the canister as `BoundsNotRuled`.
   */
  propose(kind: VaultActionKind): Promise<VaultResult<bigint>>;
  /** R1.5: `commitmentHash` is read from the proposal view, never from a form. */
  approve(proposalId: bigint, commitmentHash: Uint8Array): Promise<VaultResult<ApprovalOutcome>>;
  cancelProposal(proposalId: bigint): Promise<VaultResult<null>>;
  /** The Vault clamps `limit` to 12; the page sends 12 (SSA G-07). */
  sweepExpiredProposals(limit: number): Promise<VaultResult<bigint[]>>;

  // ── Signer-gated queries (null === unauthorized, indistinguishably) ───────
  listProposals(cursor: bigint | null, limit: number): Promise<ProposalView[] | null>;
  getProposal(proposalId: bigint): Promise<ProposalView | null>;
  getSigners(): Promise<Principal[] | null>;
  getGovernedTargets(): Promise<{ targets: VaultTargets; governed: GovernedTarget[] } | null>;
  getCreationReceipts(cursor: bigint | null, limit: number): Promise<CreationReceiptPage | null>;
  getAuditEvents(cursor: bigint | null, limit: number): Promise<AuditEvent[] | null>;

  // ── Public queries ────────────────────────────────────────────────────────
  getGovernanceSummary(): Promise<GovernanceSummary>;
  getActionCatalogue(): Promise<string[]>;
  getBuildInfo(): Promise<string>;
}

/** Pure adapter over an already-constructed candid actor (mock-testable). */
export function wrapVaultActor(raw: _SERVICE): VaultCanister {
  return {
    async propose(kind) {
      return flatten(await raw.propose(kind, []));
    },
    async approve(proposalId, commitmentHash) {
      return flatten(await raw.approve(proposalId, commitmentHash));
    },
    async cancelProposal(proposalId) {
      return flatten(await raw.cancel_proposal(proposalId));
    },
    async sweepExpiredProposals(limit) {
      return flatten(await raw.sweep_expired_proposals(limit));
    },
    async listProposals(cursor, limit) {
      return opt(await raw.list_proposals(cursor === null ? [] : [cursor], limit));
    },
    async getProposal(proposalId) {
      return opt(await raw.get_proposal(proposalId));
    },
    async getSigners() {
      return opt(await raw.get_signers());
    },
    async getGovernedTargets() {
      const wrapped = await raw.get_governed_targets();
      if (wrapped.length !== 1) return null;
      const [targets, governed] = wrapped[0];
      return { targets, governed };
    },
    async getCreationReceipts(cursor, limit) {
      return opt(await raw.get_creation_receipts(cursor === null ? [] : [cursor], limit));
    },
    async getAuditEvents(cursor, limit) {
      return opt(await raw.get_audit_events(cursor === null ? [] : [cursor], limit));
    },
    async getGovernanceSummary() {
      return raw.get_governance_summary();
    },
    async getActionCatalogue() {
      return raw.get_action_catalogue();
    },
    async getBuildInfo() {
      return raw.get_build_info();
    },
  };
}

/** Build a live Vault actor bound to `agent` and adapt it. */
export function createVaultActor(canisterId: string, agent: HttpAgent): VaultCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapVaultActor(raw);
}
