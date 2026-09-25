/**
 * Shielded-pool canister actor (wallet-build Commit 4).
 *
 * Wraps the one mutating call the wallet makes at shield time plus the read
 * queries the shield/spend UI needs to build a request and an OISY consent
 * message. Source: canisters/shielded-pool/shielded_pool.did.
 *
 *   shield_deposit : (ShieldDepositArgs) -> (variant { Ok: nat; Err: PoolError })
 *   get_denominations / is_deposits_paused / is_spends_paused
 *   get_pinned_vk_hash / get_circuit_version / get_pool_version
 *
 * private_spend / withdraw are deliberately NOT wired here — they carry a full
 * ProofEnvelope and belong with the spend UI (Commit 6), not the shield path.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

import { idlFactory } from "../../../src/declarations/shielded_pool/shielded_pool.did.js";
import type {
  _SERVICE,
  DeploymentAttestation,
  DepositStatus,
  GovernanceFeeParams,
  PendingDeposit,
  PendingSpend,
  PoolError,
  PrivateSpendArgs,
  ShieldDepositArgs,
  SpendStatus,
} from "../../../src/declarations/shielded_pool/shielded_pool.did";
import type { AuthorizationAuthority, CallToken } from "./authorization";
import { formatVariant, toBytes } from "./common";

/** camelCase shield request — mapped to the candid `ShieldDepositArgs` record. */
export interface ShieldDepositRequest {
  /** Poseidon note commitment (32-byte Fr, LE). */
  noteCommitment: Uint8Array;
  /** IBE-encrypted note payload (crypto/vetkeys.ts `encryptNotePayload`). */
  encryptedPayload: Uint8Array;
  /** Deposit amount — must be one of DENOMINATIONS. */
  publicAmount: bigint;
  /**
   * P-DOM (C-DOM-2): the wallet-computed deployment-config hash the pool gate
   * verifies against its live wiring before any await. The production wallet
   * ALWAYS supplies it (session/domainGuard.ts `assertDeploymentBinding`);
   * omitting it sends `None`, which the pool treats as decode-compat skip.
   */
  expectedDeploymentConfigHash?: Uint8Array;
}

/**
 * Wallet view of the pool's shield-relevant `GovernanceFeeParams` fields, with
 * the Candid opts RESOLVED to the same launch defaults the Rust fee-policy
 * crate uses (`shield_fee_bps: None -> 0`, `shield_flat_minimum_fee_e8s: None
 * -> 0`, `fee_model_version: None -> 1`, `params_epoch: None -> 0`). The raw
 * opt-resolution happening HERE (one place) keeps the fee math pure.
 */
export interface ShieldFeeParams {
  shieldFeeBps: number;
  shieldFlatMinimumFeeE8s: bigint;
  minimumPrivateCredit: bigint;
  feeModelVersion: number;
  paramsEpoch: bigint;
  /** The governance-quoted private-spend fee (e8s) — args.fee must EQUAL it. */
  protocolPrivateSpendFeeStsh: bigint;
  // ── A-7: the UNSHIELD (exit) arm of the same value-fee model ───────────────
  //
  // A `private_spend` carrying a public payout is an EXIT and pays
  // `max(unshieldFlatMinimumFeeE8s, public_amount * unshieldFeeBps / 10_000)`,
  // not the flat spend fee. These two fields have always been in the pool's DID;
  // the wallet simply never read them, which is why the exit fee could diverge.
  unshieldFeeBps: number;
  unshieldFlatMinimumFeeE8s: bigint;
}

// ── L3c: spend surface ────────────────────────────────────────────────────────

/** Wallet view of the pool's advisory `SpendStatus` (§10.1 table rows). */
export type PoolSpendStatus =
  | { kind: "finalized" }
  | { kind: "failed-before-state-change"; reason: string }
  | { kind: "failed-after-outputs-staged"; reason: string }
  | { kind: "in-flight" } // Requested / VerificationPending / NullifierReserved / OutputsStaged
  | { kind: "payout-pending"; reason: string }
  | { kind: "payout-submitting" }
  | { kind: "payout-unknown"; reason: string }
  | { kind: "operator-reconcile" }; // nullifier insert/reconcile unknown, append/root-pending, root accepted

/** Wallet view of one pool `PendingSpend` record (advisory — L0-H). */
export interface PoolSpendRecord {
  spendId: bigint;
  status: PoolSpendStatus;
  nullifiers: Uint8Array[];
  outputCommitments: Uint8Array[];
  submitter: Principal | null;
  createdAtNs: bigint;
}

/** One page of the P-REC caller-scoped active-spend recovery index. */
export interface ActiveSpendsPageView {
  spends: PoolSpendRecord[];
  nextCursor: bigint | null;
}

/** The P-ROOT finality-bound accepted-root head (spend anchor source). */
export interface AcceptedRootHeadView {
  root: Uint8Array;
  leafCount: bigint;
}

/** camelCase spend request — mapped to the candid `PrivateSpendArgs` record. */
export interface PrivateSpendRequest {
  spendId: bigint;
  circuitVersion: number;
  proofSystemId: string;
  verifyingKeyHash: Uint8Array;
  rootReference: Uint8Array;
  poolVersion: number;
  proofBytes: Uint8Array;
  nullifiers: Uint8Array[];
  outputCommitments: Uint8Array[];
  encryptedOutputs: Uint8Array[];
  fee: bigint;
  publicPayout: {
    destination: Principal;
    destinationSubaccount: Uint8Array | null;
    publicAmount: bigint;
  } | null;
  expectedDeploymentConfigHash?: Uint8Array;
}

function mapSpendStatus(status: SpendStatus): PoolSpendStatus {
  if ("Finalized" in status) return { kind: "finalized" };
  if ("FailedBeforeStateChange" in status) {
    return { kind: "failed-before-state-change", reason: status.FailedBeforeStateChange.reason };
  }
  if ("FailedAfterOutputsStaged" in status) {
    return { kind: "failed-after-outputs-staged", reason: status.FailedAfterOutputsStaged.reason };
  }
  if ("PayoutPending" in status) {
    return { kind: "payout-pending", reason: status.PayoutPending.reason };
  }
  if ("PayoutSubmitting" in status) return { kind: "payout-submitting" };
  if ("PayoutUnknown" in status) {
    return { kind: "payout-unknown", reason: status.PayoutUnknown.reason };
  }
  if (
    "Requested" in status ||
    "VerificationPending" in status ||
    "NullifierReserved" in status ||
    "OutputsStaged" in status
  ) {
    return { kind: "in-flight" };
  }
  return { kind: "operator-reconcile" };
}

function mapPendingSpend(record: PendingSpend): PoolSpendRecord {
  return {
    spendId: record.spend_id,
    status: mapSpendStatus(record.status),
    nullifiers: record.nullifiers.map(toBytes),
    outputCommitments: record.output_commitments.map(toBytes),
    submitter: record.submitter.length === 1 ? record.submitter[0] : null,
    createdAtNs: record.created_at_ns,
  };
}

/** Typed wallet view of the pool's `DepositStatus` variant (§6 reconcile table). */
export type PoolDepositStatus =
  | { kind: "transfer-pending" }
  | { kind: "commitment-pending" } // TransferConfirmedCommitmentPending or legacy CommitmentPending
  | { kind: "append-in-flight" } // CommitmentAppendInFlight or CommitmentReconcileInFlight
  | { kind: "append-unknown" }
  | { kind: "appended"; leafIndex: bigint } // credited, root pending — NOT terminal
  | { kind: "root-accepted"; leafIndex: bigint; root: Uint8Array }; // terminal success

/** Wallet view of one pool `PendingDeposit` record. */
export interface PoolPendingDeposit {
  noteCommitment: Uint8Array;
  status: PoolDepositStatus;
  /**
   * The principal that opened the deposit, or `null` once the pool has REDACTED
   * the record (F2-REDACT / R1-F2: the identity is stripped 7 days after the
   * record becomes terminal, before the record itself is destroyed at 30 days).
   *
   * `null` means REDACTED — never "unknown" and never "anyone". A redacted
   * record is controller-only on the pool side, so a wallet that sees one is
   * either a controller or looking at its own historical record through a path
   * that no longer names it.
   */
  depositor: Principal | null;
  encryptedPayload: Uint8Array;
  privateBalance: bigint;
  createdAtNs: bigint;
}

/** One page of the P-REC caller-scoped recovery index (L0-G). */
export interface ActiveDepositsPageView {
  deposits: PoolPendingDeposit[];
  /** Exclusive cursor for the next page, or null when this page was the last. */
  nextCursor: Uint8Array | null;
}

function mapDepositStatus(status: DepositStatus): PoolDepositStatus {
  if ("TransferPending" in status) return { kind: "transfer-pending" };
  if ("TransferConfirmedCommitmentPending" in status || "CommitmentPending" in status) {
    return { kind: "commitment-pending" };
  }
  if ("CommitmentAppendInFlight" in status || "CommitmentReconcileInFlight" in status) {
    return { kind: "append-in-flight" };
  }
  if ("CommitmentAppendUnknown" in status) return { kind: "append-unknown" };
  if ("CommitmentAppended" in status) {
    return { kind: "appended", leafIndex: status.CommitmentAppended.leaf_index };
  }
  return {
    kind: "root-accepted",
    leafIndex: status.CommitmentRootAccepted.leaf_index,
    root: toBytes(status.CommitmentRootAccepted.root),
  };
}

function mapPendingDeposit(record: PendingDeposit): PoolPendingDeposit {
  return {
    noteCommitment: toBytes(record.note_commitment),
    status: mapDepositStatus(record.status),
    // opt principal: [] = redacted (or a pre-F2-REDACT record that decoded as
    // absent), [p] = present.
    depositor: record.depositor.length === 1 ? record.depositor[0] : null,
    encryptedPayload: toBytes(record.encrypted_payload),
    privateBalance: record.private_balance,
    createdAtNs: record.created_at_ns,
  };
}

function mapShieldFeeParams(params: GovernanceFeeParams): ShieldFeeParams {
  // Resolve opts to the SAME launch defaults as the Rust fee-policy resolver
  // accessors (LAUNCH_SHIELD_FEE_BPS = 0, LAUNCH_SHIELD_FLAT_MINIMUM_FEE_E8S = 0,
  // FEE_MODEL_VERSION = 1, params_epoch None -> 0).
  return {
    shieldFeeBps: params.shield_fee_bps.length === 1 ? params.shield_fee_bps[0] : 0,
    shieldFlatMinimumFeeE8s:
      params.shield_flat_minimum_fee_e8s.length === 1 ? params.shield_flat_minimum_fee_e8s[0] : 0n,
    minimumPrivateCredit: params.minimum_private_credit,
    feeModelVersion: params.fee_model_version.length === 1 ? params.fee_model_version[0] : 1,
    paramsEpoch: params.params_epoch.length === 1 ? params.params_epoch[0] : 0n,
    protocolPrivateSpendFeeStsh: params.protocol_private_spend_fee_stsh,
    // A-7: same opt-resolution discipline as the shield fields — absent decodes
    // to the launch default (0), never to a guessed value.
    unshieldFeeBps: params.unshield_fee_bps.length === 1 ? params.unshield_fee_bps[0] : 0,
    unshieldFlatMinimumFeeE8s:
      params.unshield_flat_minimum_fee_e8s.length === 1
        ? params.unshield_flat_minimum_fee_e8s[0]
        : 0n,
  };
}

/** A rejected `shield_deposit` — carries the decoded `PoolError` variant. */
export class PoolCallError extends Error {
  constructor(
    readonly method: string,
    readonly poolError: PoolError,
  ) {
    super(`${method} rejected: ${formatVariant(poolError as Record<string, unknown>)}`);
    this.name = "PoolCallError";
  }
}

export interface PoolCanister {
  /**
   * Shield a deposit; resolves to the block index, throws `PoolCallError`.
   * `token` is the single-use WL-2b permit for THIS call, drawn from the
   * operation's lease by the flow immediately before calling.
   */
  shieldDeposit(req: ShieldDepositRequest, token?: CallToken): Promise<bigint>;
  /** Accepted fixed denominations, in ascending order. */
  getDenominations(): Promise<bigint[]>;
  /** Pinned Groth16 VK hash (32 bytes) — proof-envelope construction. */
  getPinnedVkHash(): Promise<Uint8Array>;
  /** Active circuit version. */
  getCircuitVersion(): Promise<number>;
  /** Active pool version. */
  getPoolVersion(): Promise<number>;
  /** Whether deposits are currently paused. */
  isDepositsPaused(): Promise<boolean>;
  /** Whether private spends are currently paused. */
  isSpendsPaused(): Promise<boolean>;
  /** Shield-relevant governance fee params, opts resolved to launch defaults. */
  getGovernanceFeeParams(): Promise<ShieldFeeParams>;
  /**
   * Depositor-gated deposit record (DEF-070): the pool returns None for any
   * caller other than the depositor or a controller — so this MUST be called
   * on the identity-bound actor set (S-44); over an anonymous agent "null"
   * is indistinguishable from record-not-found.
   */
  getDepositStatus(noteCommitment: Uint8Array): Promise<PoolPendingDeposit | null>;
  /**
   * Re-drive a transfer-confirmed deposit whose commitment append never
   * finished. Idempotent: an already-appended deposit returns Ok. Maps the §6
   * reconcile-table row for `TransferConfirmedCommitmentPending`.
   */
  retryDepositCommitment(noteCommitment: Uint8Array, token?: CallToken): Promise<bigint>;
  /**
   * P-REC caller-scoped recovery index page (L0-G). Caller-gated — anonymous
   * callers get an empty page, so identity-bound actor set only (S-44).
   */
  listMyActiveDeposits(startAfter: Uint8Array | null, limit: bigint): Promise<ActiveDepositsPageView>;
  // ── L3c: spend surface ─────────────────────────────────────────────────────
  /** Submit a private spend; resolves on the authoritative Ok, throws PoolCallError. */
  privateSpend(req: PrivateSpendRequest, token?: CallToken): Promise<void>;
  /** Retry a spend's public payout (SAME spend_id); returns the block index. */
  retryPrivateSpendPayout(spendId: bigint, token?: CallToken): Promise<bigint>;
  /**
   * Advisory spend record (L0-H — a query; NEVER an authority for permanent
   * effects, §10.1). Identity-bound: other callers get null (S-23b collision
   * indistinguishability).
   */
  getSpendStatus(spendId: bigint): Promise<PoolSpendRecord | null>;
  /** The P-ROOT accepted-root head — the spend anchor source (H6-1). */
  getAcceptedRootHead(): Promise<AcceptedRootHeadView | null>;
  /** P-DOM advisory deployment attestation (manifest comparison input). */
  getDeploymentAttestation(): Promise<DeploymentAttestation>;
  /**
   * WALLET-AUTH Gate 1 (brief §5 item 1). The pool's security epoch — a plain
   * `query` in the generated declarations; the replicated copy in
   * `actors/replicated.ts` strips that annotation so the same method can be
   * read over the verified transport. The verified scan keys its per-deployment
   * floor on `(config_hash, security_epoch)`, so a reinstall that bumps the
   * epoch retires the old floor without a user gesture (SSA C-2a).
   */
  getSecurityEpoch(): Promise<bigint>;
  /** P-REC active-spend recovery index page (fresh-device recovery). Identity-bound. */
  listMyActiveSpends(startAfter: bigint | null, limit: bigint): Promise<ActiveSpendsPageView>;
}

/**
 * Pure adapter: raw candid actor -> `PoolCanister`. Mock-testable.
 *
 * WL-2b: the four state-changing methods each consume ONE single-use token,
 * handed in by the flow that drew it from the operation's lease, before the
 * wire call. An unauthorised caller never reaches the network. Every read is
 * untouched.
 *
 * `authority` is optional ONLY as a mock seam for the pre-WL-2b adapter unit
 * tests, which exercise argument and error mapping with no authorization in
 * sight. The PRODUCTION path cannot omit it: `createPoolActor` requires it.
 */
export function wrapPoolActor(raw: _SERVICE, authority?: AuthorizationAuthority): PoolCanister {
  return {
    async shieldDeposit(req: ShieldDepositRequest, token?: CallToken): Promise<bigint> {
      // WL-2b: the token is consumed FIRST, before any work — an unauthorised
      // call does not even get its arguments built. The wrapper consumes the
      // token it was HANDED; it never asks whether anything is open.
      authority?.consume(token, "shieldDeposit");
      const args: ShieldDepositArgs = {
        note_commitment: req.noteCommitment,
        encrypted_payload: req.encryptedPayload,
        public_amount: req.publicAmount,
        // opt blob: [] = None (decode-compat skip), [hash] = the P-DOM gate value.
        expected_deployment_config_hash: req.expectedDeploymentConfigHash
          ? [req.expectedDeploymentConfigHash]
          : [],
      };
      const res = await raw.shield_deposit(args);
      if ("Err" in res) throw new PoolCallError("shield_deposit", res.Err);
      return res.Ok;
    },

    async getDenominations(): Promise<bigint[]> {
      return raw.get_denominations();
    },

    async getPinnedVkHash(): Promise<Uint8Array> {
      return toBytes(await raw.get_pinned_vk_hash());
    },

    async getCircuitVersion(): Promise<number> {
      return raw.get_circuit_version();
    },

    async getPoolVersion(): Promise<number> {
      return raw.get_pool_version();
    },

    async isDepositsPaused(): Promise<boolean> {
      return raw.is_deposits_paused();
    },

    async isSpendsPaused(): Promise<boolean> {
      return raw.is_spends_paused();
    },

    async getGovernanceFeeParams(): Promise<ShieldFeeParams> {
      return mapShieldFeeParams(await raw.get_governance_fee_params());
    },

    async getDepositStatus(noteCommitment: Uint8Array): Promise<PoolPendingDeposit | null> {
      const res = await raw.get_deposit_status(noteCommitment);
      return res.length === 1 ? mapPendingDeposit(res[0]) : null;
    },

    async retryDepositCommitment(noteCommitment: Uint8Array, token?: CallToken): Promise<bigint> {
      authority?.consume(token, "retryDepositCommitment");
      const res = await raw.retry_deposit_commitment(noteCommitment);
      if ("Err" in res) throw new PoolCallError("retry_deposit_commitment", res.Err);
      return res.Ok;
    },

    async listMyActiveDeposits(
      startAfter: Uint8Array | null,
      limit: bigint,
    ): Promise<ActiveDepositsPageView> {
      const page = await raw.list_my_active_deposits(startAfter ? [startAfter] : [], limit);
      return {
        deposits: page.deposits.map(mapPendingDeposit),
        nextCursor: page.next_cursor.length === 1 ? toBytes(page.next_cursor[0]) : null,
      };
    },

    async privateSpend(req: PrivateSpendRequest, token?: CallToken): Promise<void> {
      authority?.consume(token, "privateSpend");
      const args: PrivateSpendArgs = {
        spend_id: req.spendId,
        envelope: {
          circuit_version: req.circuitVersion,
          proof_system_id: req.proofSystemId,
          verifying_key_hash: req.verifyingKeyHash,
          root_reference: req.rootReference,
          pool_version: req.poolVersion,
          proof_bytes: req.proofBytes,
        },
        nullifiers: req.nullifiers,
        output_commitments: req.outputCommitments,
        encrypted_outputs: req.encryptedOutputs,
        fee: req.fee,
        public_payout:
          req.publicPayout === null
            ? []
            : [
                {
                  destination: req.publicPayout.destination,
                  destination_subaccount:
                    req.publicPayout.destinationSubaccount === null
                      ? []
                      : [req.publicPayout.destinationSubaccount],
                  public_amount: req.publicPayout.publicAmount,
                },
              ],
        expected_deployment_config_hash: req.expectedDeploymentConfigHash
          ? [req.expectedDeploymentConfigHash]
          : [],
      };
      const res = await raw.private_spend(args);
      if ("Err" in res) throw new PoolCallError("private_spend", res.Err);
    },

    async retryPrivateSpendPayout(spendId: bigint, token?: CallToken): Promise<bigint> {
      authority?.consume(token, "retryPrivateSpendPayout");
      const res = await raw.retry_private_spend_payout(spendId);
      if ("Err" in res) throw new PoolCallError("retry_private_spend_payout", res.Err);
      return res.Ok;
    },

    async getSpendStatus(spendId: bigint): Promise<PoolSpendRecord | null> {
      const res = await raw.get_spend_status(spendId);
      return res.length === 1 ? mapPendingSpend(res[0]) : null;
    },

    async getAcceptedRootHead(): Promise<AcceptedRootHeadView | null> {
      const res = await raw.get_accepted_root_head();
      if (res.length === 0) return null;
      return { root: toBytes(res[0].root), leafCount: res[0].leaf_count };
    },

    async getDeploymentAttestation(): Promise<DeploymentAttestation> {
      const res = await raw.get_deployment_attestation();
      if ("Err" in res) throw new PoolCallError("get_deployment_attestation", res.Err);
      return res.Ok;
    },

    async getSecurityEpoch(): Promise<bigint> {
      return raw.get_security_epoch();
    },

    async listMyActiveSpends(
      startAfter: bigint | null,
      limit: bigint,
    ): Promise<ActiveSpendsPageView> {
      const page = await raw.list_my_active_spends(
        startAfter !== null ? [startAfter] : [],
        limit,
      );
      return {
        spends: page.spends.map(mapPendingSpend),
        nextCursor: page.next_cursor.length === 1 ? page.next_cursor[0] : null,
      };
    },
  };
}

/**
 * Build a live shielded-pool actor bound to `agent` and adapt it. The WL-2b
 * gate is REQUIRED here — a production actor with no gate would be an
 * unguarded path to the four update methods, so it is unrepresentable.
 */
export function createPoolActor(
  canisterId: string,
  agent: HttpAgent,
  authority: AuthorizationAuthority,
): PoolCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapPoolActor(raw, authority);
}

/**
 * J-25 — the ANONYMOUS pool identity read actor (addendum E).
 *
 * Deliberately narrow: it exposes the two display queries and NOTHING else, so
 * there is no update method for a WL-2b authority to guard and no way for this
 * actor to become an unguarded mutation path. Built over the anonymous read
 * agent, never over a mutation/shielded identity-bound one.
 */
export interface PoolIdentityReadCanister {
  getCircuitVersion(): Promise<number>;
  getPinnedVkHash(): Promise<Uint8Array>;
}

export function createPoolIdentityReadActor(
  canisterId: string,
  agent: HttpAgent,
): PoolIdentityReadCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return {
    async getCircuitVersion(): Promise<number> {
      return raw.get_circuit_version();
    },
    async getPinnedVkHash(): Promise<Uint8Array> {
      return toBytes(await raw.get_pinned_vk_hash());
    },
  };
}
