/**
 * STSH token (ICRC-1/2 ledger) actor (Campaign A / Wave 1).
 *
 * Split read vs mutation (H-A2/A-S7): `TokenCanister` is the read wrapper used
 * over the ANONYMOUS agent (balance/metadata/fee); `TokenMutationCanister`
 * carries `icrc1_transfer` and is only ever constructed over the identity-bound
 * agent after login.
 *
 * Transfer idempotency contract (C-A3/A-S1): `created_at_time` is REQUIRED on
 * every transfer — `[]`/None would skip the ledger's dedup window (token
 * lib.rs:741) and make a lost-response retry a double debit. `Duplicate` maps
 * to a distinct CONFIRMED-SUCCESS outcome; `TooOld` maps to its own outcome so
 * the journal can freeze an ambiguous intent instead of re-minting it. A
 * transport-unknown failure THROWS, leaving the persisted envelope for a
 * byte-for-byte retry. Source: canisters/token/stsh_token.did.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

import { idlFactory } from "../../../src/declarations/stsh_token/stsh_token.did.js";
import type { Account, _SERVICE } from "../../../src/declarations/stsh_token/stsh_token.did";
import type { AuthorizationAuthority, CallToken } from "./authorization";
import { formatVariant } from "./common";

export interface TokenMeta {
  symbol: string;
  decimals: number;
  fee: bigint;
}

export interface TokenCanister {
  balanceOf(owner: Principal, subaccount?: Uint8Array): Promise<bigint>;
  metadata(): Promise<TokenMeta>;
  fee(): Promise<bigint>;
}

function toAccount(owner: Principal, subaccount?: Uint8Array): Account {
  return { owner, subaccount: subaccount ? [subaccount] : [] };
}

/** Pure adapter: raw candid actor -> `TokenCanister`. Mock-testable. */
export function wrapTokenActor(raw: _SERVICE): TokenCanister {
  return {
    async balanceOf(owner: Principal, subaccount?: Uint8Array): Promise<bigint> {
      return raw.icrc1_balance_of(toAccount(owner, subaccount));
    },
    async metadata(): Promise<TokenMeta> {
      const [symbol, decimals, fee] = await Promise.all([
        raw.icrc1_symbol(),
        raw.icrc1_decimals(),
        raw.icrc1_fee(),
      ]);
      return { symbol, decimals, fee };
    },
    async fee(): Promise<bigint> {
      return raw.icrc1_fee();
    },
  };
}

/** Build a live token actor bound to `agent` and adapt it. */
export function createTokenActor(canisterId: string, agent: HttpAgent): TokenCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapTokenActor(raw);
}

// ---------------------------------------------------------------------------
// mutation actor (identity-bound; Lane A2)
// ---------------------------------------------------------------------------

export interface TransferRequest {
  to: { owner: Principal; subaccount?: Uint8Array };
  amount: bigint;
  fee: bigint;
  memo?: Uint8Array;
  fromSubaccount?: Uint8Array;
  /**
   * REQUIRED — the intent's single stable dedup timestamp (ns). Never omitted:
   * `created_at_time: []` skips the ledger dedup and re-opens the C-A3
   * lost-response double debit.
   */
  createdAtTime: bigint;
}

export type TransferOutcome =
  /** Executed; `blockIndex` is the ledger block. */
  | { kind: "ok"; blockIndex: bigint }
  /** The SAME envelope already executed — confirmed success, no second debit. */
  | { kind: "duplicate"; duplicateOf: bigint }
  /** Dedup window passed — ambiguous if any earlier attempt may have landed. */
  | { kind: "too-old" }
  /** Definite non-executing rejection (BadFee, InsufficientFunds, ...). */
  | { kind: "rejected"; reason: string };

// ── ICRC-2 approve/allowance (Campaign B / L3a shield path) ─────────────────

export interface ApproveRequest {
  /** The spender (the shielded pool's principal; default account, no subaccount). */
  spender: Principal;
  /** Absolute allowance to set (ICRC-2 approve is absolute, not additive). */
  amount: bigint;
  /**
   * REQUIRED compare-and-set guard (L3a non-negotiable): the allowance the
   * caller observed immediately before approving. The ledger rejects with
   * `AllowanceChanged` if the live allowance differs — a blind approve could
   * silently stack on a concurrent flow's allowance.
   */
  expectedAllowance: bigint;
  /**
   * REQUIRED — the intent's single stable dedup timestamp (ns), same C-A3
   * contract as transfers: a lost-response retry MUST reuse it byte-for-byte
   * so the ledger dedup collapses it to `Duplicate`, never a second approve.
   */
  createdAtTime: bigint;
  /** Expected ledger fee for the approve itself (BadFee instead of overcharge). */
  fee: bigint;
}

/**
 * WT-1 — the lifetime of a shield approval, in nanoseconds (15 minutes).
 *
 * WHY AN EXPIRY AT ALL. `icrc2_approve` with `expires_at = []` grants the
 * shielded pool a PERMANENT allowance over the user's ledger balance. Every
 * shield that is abandoned, interrupted, or fails after the approve but before
 * the deposit leaves that standing allowance behind — invisible to the user, and
 * live for as long as the account exists. The CAS guard does not help: it stops
 * a blind approve from STACKING, it does not stop a granted one from LINGERING.
 * A bound converts an unbounded grant into one that dies on its own.
 *
 * WHY 15 MINUTES. It must outlast a real shield — the user reads and confirms a
 * consent prompt, then a deposit round-trips to mainnet — and must not outlast
 * the user's attention on it. Fifteen minutes is comfortably longer than the
 * first and shorter than the second. A shield that somehow takes longer fails
 * with an allowance error and is retried, which is the correct direction to
 * fail: a refused shield is recoverable, a permanent allowance is not.
 *
 * Measured from the intent's `createdAtTime` — the SAME stable timestamp the
 * ledger dedups on — and not from `Date.now()` at the call site. That matters
 * for the C-A3 retry contract: a lost-response retry must reproduce the approve
 * argument BYTE-FOR-BYTE or the ledger sees a second, different approve instead
 * of a `Duplicate`. Deriving the expiry from a wall clock read per attempt would
 * break dedup precisely on the retry path it exists to protect.
 */
export const APPROVAL_TTL_NS = 15n * 60n * 1_000_000_000n;

/** The absolute `expires_at` for an approval created at `createdAtTime` (ns). */
export function approvalExpiresAt(createdAtTime: bigint): bigint {
  return createdAtTime + APPROVAL_TTL_NS;
}

export type ApproveOutcome =
  /** Approved; `blockIndex` is the ledger block. */
  | { kind: "ok"; blockIndex: bigint }
  /** The SAME envelope already executed — confirmed, allowance is set. */
  | { kind: "duplicate"; duplicateOf: bigint }
  /** The CAS lost: live allowance differs from `expectedAllowance`. */
  | { kind: "allowance-changed"; currentAllowance: bigint }
  /** Dedup window passed — ambiguous if any earlier attempt may have landed. */
  | { kind: "too-old" }
  /** Definite non-executing rejection (BadFee, InsufficientFunds, Expired, ...). */
  | { kind: "rejected"; reason: string };

export interface AllowanceView {
  allowance: bigint;
  expiresAt: bigint | null;
}

export interface TokenMutationCanister {
  /** `token` is the single-use WL-2b permit for THIS call (see authorization.ts). */
  transfer(req: TransferRequest, token?: CallToken): Promise<TransferOutcome>;
  /** ICRC-2 approve with the mandatory expected-allowance CAS (L3a). */
  approve(req: ApproveRequest, token?: CallToken): Promise<ApproveOutcome>;
  /**
   * ICRC-2 allowance for (owner -> spender), default accounts. An owned read —
   * lives on the identity-bound actor set (S-44), never the anonymous one.
   */
  allowance(owner: Principal, spender: Principal): Promise<AllowanceView>;
}

/**
 * Pure adapter: raw candid actor -> `TokenMutationCanister`. Mock-testable.
 *
 * WL-2b: `transfer` and `approve` each consume ONE single-use token before
 * the wire call; `allowance` (a read) is untouched. `authority` is optional
 * here as a mock seam only — `createTokenMutationActor`, the production path,
 * requires it.
 */
export function wrapTokenMutationActor(
  raw: _SERVICE,
  authority?: AuthorizationAuthority,
): TokenMutationCanister {
  return {
    async transfer(req: TransferRequest, token?: CallToken): Promise<TransferOutcome> {
      // WL-2b: the handed-in token is consumed FIRST, before any argument is built.
      authority?.consume(token, "transfer");
      const result = await raw.icrc1_transfer({
        to: toAccount(req.to.owner, req.to.subaccount),
        amount: req.amount,
        fee: [req.fee],
        memo: req.memo ? [req.memo] : [],
        from_subaccount: req.fromSubaccount ? [req.fromSubaccount] : [],
        created_at_time: [req.createdAtTime],
      });
      if ("Ok" in result) return { kind: "ok", blockIndex: result.Ok };
      const err = result.Err;
      if ("Duplicate" in err) {
        return { kind: "duplicate", duplicateOf: err.Duplicate.duplicate_of };
      }
      if ("TooOld" in err) return { kind: "too-old" };
      return { kind: "rejected", reason: formatVariant(err as Record<string, unknown>) };
    },

    async approve(req: ApproveRequest, token?: CallToken): Promise<ApproveOutcome> {
      authority?.consume(token, "approve");
      const result = await raw.icrc2_approve({
        spender: toAccount(req.spender),
        amount: req.amount,
        // The CAS guard and dedup timestamp are REQUIRED fields of the request
        // type — they are always sent, never `[]` (a blind approve or an
        // undeduped retry are the two failure modes this wrapper exists to
        // make unrepresentable).
        expected_allowance: [req.expectedAllowance],
        created_at_time: [req.createdAtTime],
        fee: [req.fee],
        memo: [],
        from_subaccount: [],
        // WT-1: bounded. See APPROVAL_TTL_NS — an approval sent with no expiry
        // outlives every abandoned or failed shield. Derived from the dedup
        // timestamp so a retry reproduces this argument byte-for-byte.
        expires_at: [approvalExpiresAt(req.createdAtTime)],
      });
      if ("Ok" in result) return { kind: "ok", blockIndex: result.Ok };
      const err = result.Err;
      if ("Duplicate" in err) {
        return { kind: "duplicate", duplicateOf: err.Duplicate.duplicate_of };
      }
      if ("AllowanceChanged" in err) {
        return {
          kind: "allowance-changed",
          currentAllowance: err.AllowanceChanged.current_allowance,
        };
      }
      if ("TooOld" in err) return { kind: "too-old" };
      return { kind: "rejected", reason: formatVariant(err as Record<string, unknown>) };
    },

    async allowance(owner: Principal, spender: Principal): Promise<AllowanceView> {
      const res = await raw.icrc2_allowance({
        account: toAccount(owner),
        spender: toAccount(spender),
      });
      return {
        allowance: res.allowance,
        expiresAt: res.expires_at.length === 1 ? res.expires_at[0] : null,
      };
    },
  };
}

/**
 * Build a live mutation actor bound to the identity `agent` and adapt it. The
 * WL-2b gate is REQUIRED — a production mutation actor with no gate would be
 * an unguarded path to `transfer`/`approve`.
 */
export function createTokenMutationActor(
  canisterId: string,
  agent: HttpAgent,
  authority: AuthorizationAuthority,
): TokenMutationCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapTokenMutationActor(raw, authority);
}
