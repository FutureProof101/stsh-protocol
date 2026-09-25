/**
 * Upgrader (recovery plane) actor — READS, PLUS THE ROTATION PLANE ONLY.
 *
 * BOUNDARY (UPG-ROT-UI V1 + Addendum 1, 2026-09-21; supersedes the J-17b
 * "READ QUERIES ONLY" boundary). The wrapper offers the five J-17b reads plus
 * exactly THREE methods — `proposeMembershipRotation`, `approveRecovery` and
 * `getRotationProposal`: two updates and one query. Nothing else on the
 * recovery plane is wrapped, and the page therefore cannot reach it.
 *
 * WHY THE BOUNDARY MOVED. Board step 7 rotates the Upgrader recovery roster
 * under the OLD roster, whose threshold is 2 and two of whose three members are
 * Internet Identity principals. dfx cannot sign as II, so with a read-only
 * wrapper the plane was reachable only as the single machine identity — 1 of a
 * threshold of 2, and quorum was unreachable. This wrapper is the II half of
 * that quorum and nothing more.
 *
 * STILL DELIBERATELY ABSENT, and each for its own reason:
 *   - `trigger_vault_upgrade` / `reconcile_vault_upgrade` — Vault-caller only,
 *     unreachable from a browser by construction.
 *   - `propose_recovery` — the recovery-ACTION plane is a separate ceremony and
 *     is out of scope (V1's "do not build a generic dispatcher" rule). Note
 *     that `approve_recovery` is shared between both planes on the wire; the
 *     rotation-only boundary is enforced by the PAGE, which reaches approval
 *     solely from a successfully fetched `get_rotation_proposal` view.
 *   - `cancel_recovery_proposal` / `sweep_expired_recovery_proposals` — adding
 *     a cancel or sweep control would widen the surface past what step 7 needs
 *     (SSA C-5).
 *   - `refresh_controller_invariant_now` — a rate-limited permissionless
 *     update: putting a button on it in a page whose only job is signing is an
 *     invitation to spend the durable allowance for nothing.
 *
 * FRESHNESS (SSA F-09). `get_controller_invariant` is NON-AUTHORITATIVE — it is
 * retained historical evidence that carries no freshness (upgrader.did S11-2).
 * `get_controller_invariant_proof` is the authoritative one and the only one
 * this wrapper offers: `current_proof_ok` is the answer to "is the
 * no-human-controller property PROVEN right now?". The legacy read is not
 * wrapped, so it cannot be shown next to the proof and mistaken for it.
 *
 * NOTHING here retries. `propose_membership_rotation` and `approve_recovery`
 * are not idempotent from the caller's side, and a silent retry of a quorum
 * action is exactly the wrong reflex (`ui/pages/operator.ts:31-35`).
  */

import { Actor, type HttpAgent } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

import { idlFactory } from "../../../src/declarations/upgrader/upgrader.did.js";
import type {
  AuditEventsPage,
  ControllerInvariantProof,
  RecoveryError,
  RecoverySummary,
  RotationProposalView,
  _SERVICE,
} from "../../../src/declarations/upgrader/upgrader.did";

/** `{ Ok } | { Err }` flattened, exactly as `VaultResult` — never thrown. */
export type UpgraderResult<T> = { ok: T } | { err: RecoveryError };

function flatten<T>(raw: { Ok: T } | { Err: RecoveryError }): UpgraderResult<T> {
  return "Ok" in raw ? { ok: raw.Ok } : { err: raw.Err };
}

function opt<T>(value: [] | [T]): T | null {
  return value.length === 1 ? value[0] : null;
}

export interface UpgraderCanister {
  /** THE authoritative controller-invariant answer (S11-2 / CUST-SSA-006). */
  getControllerInvariantProof(): Promise<ControllerInvariantProof>;
  getRecoverySummary(): Promise<RecoverySummary>;
  getBuildInfo(): Promise<string>;
  /** Recovery-member-gated: `null` is the indistinguishable unauthorized answer. */
  getRecoveryMembership(): Promise<Principal[] | null>;
  getAuditEvents(cursor: bigint | null, limit: number): Promise<AuditEventsPage | null>;

  // ── Rotation plane (UPG-ROT-UI) — two updates and one query ───────────────
  /**
   * `propose_membership_rotation(new_members, null)`.
   *
   * The lifetime is deliberately absent from this signature: the page sends
   * `null`, which is the canister's RULED DEFAULT (currently the 30-day
   * maximum, `custody-types` C3/C4) — not "no expiry" (SSA C-5).
   */
  proposeMembershipRotation(newMembers: Principal[]): Promise<UpgraderResult<bigint>>;
  /**
   * `approve_recovery(id, expected_action_hash)`.
   *
   * The bytes sent are ALWAYS the ones on the fetched view. The canister
   * rejects a caller-supplied hash that differs from the stored commitment as
   * `CommitmentMismatch(CallerMismatch)` before any approval write; the page's
   * own byte-for-byte check refuses earlier still, without a wire call.
   */
  approveRecovery(proposalId: bigint, expectedActionHash: Uint8Array): Promise<UpgraderResult<null>>;
  /** `null` = no rotation proposal with that id (including a wrong-kind id). */
  getRotationProposal(proposalId: bigint): Promise<RotationProposalView | null>;
}

/** Pure adapter over an already-constructed candid actor (mock-testable). */
export function wrapUpgraderActor(raw: _SERVICE): UpgraderCanister {
  return {
    async getControllerInvariantProof() {
      return raw.get_controller_invariant_proof();
    },
    async getRecoverySummary() {
      return raw.get_recovery_summary();
    },
    async getBuildInfo() {
      return raw.get_build_info();
    },
    async getRecoveryMembership() {
      return opt(await raw.get_recovery_membership());
    },
    async getAuditEvents(cursor, limit) {
      return opt(await raw.get_upgrader_audit_events(cursor === null ? [] : [cursor], limit));
    },
    async proposeMembershipRotation(newMembers) {
      // `[]` is candid `null` for `opt nat64` — the ruled default lifetime.
      return flatten(await raw.propose_membership_rotation(newMembers, []));
    },
    async approveRecovery(proposalId, expectedActionHash) {
      return flatten(await raw.approve_recovery(proposalId, expectedActionHash));
    },
    async getRotationProposal(proposalId) {
      return opt(await raw.get_rotation_proposal(proposalId));
    },
  };
}

/** Build a live Upgrader actor bound to `agent` and adapt it. */
export function createUpgraderActor(canisterId: string, agent: HttpAgent): UpgraderCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapUpgraderActor(raw);
}
