/**
 * STSH — spend admission refusals (WALLET-V12 O-3; LAUNCH-HARDEN-04 O-1).
 *
 * The pool refuses a `private_spend` BEFORE writing any record when one of its
 * four admission limits bites. The refusal rides the existing
 * `PoolError::VerifierUnavailable(String)` channel with an exact wire format
 * (`canisters/shielded-pool/src/lib.rs`, `spend_admission_error`):
 *
 *   `SPEND_ADMISSION;code=<CODE>;retry_after_ns=<u64>`
 *
 * The pool's own contract for this refusal: explicit, retryable, no
 * nullifier/Merkle/accounting mutation, and NO record written — so the SAME
 * spend_id may be retried byte-identically (WALLET-V12 Addendum 1a, E-2(c)).
 *
 * This module is pure: a strict parser (exact prefix, known code, u64 wait —
 * anything else is NOT an admission refusal and falls through to the generic
 * error path) and the ruled one-line copy per code. Copy is advisory (copper,
 * O-7), one idea, no engineering nouns (O-6).
 */

import { PoolCallError } from "../actors/pool";
import type { PoolError } from "../../../src/declarations/shielded_pool/shielded_pool.did";
import { humanizeWait } from "./quotaCopy";

export type SpendAdmissionCode =
  | "NO_ACTIVE_DEVICE"
  | "FAILED_VERIFY_LIMIT"
  | "INFLIGHT_LIMIT"
  | "DEVICE_CHECK_UNAVAILABLE";

export const SPEND_ADMISSION_CODES: readonly SpendAdmissionCode[] = [
  "NO_ACTIVE_DEVICE",
  "FAILED_VERIFY_LIMIT",
  "INFLIGHT_LIMIT",
  "DEVICE_CHECK_UNAVAILABLE",
];

export interface SpendAdmission {
  code: SpendAdmissionCode;
  retryAfterNs: bigint;
}

const U64_MAX = (1n << 64n) - 1n;
const WIRE = /^SPEND_ADMISSION;code=([A-Z_]+);retry_after_ns=(0|[1-9][0-9]{0,19})$/;

/**
 * Parse a pool refusal into a typed admission refusal, or `null` when it is
 * not one. Accepts a `PoolCallError` (what the pool actor throws) or a raw
 * `PoolError` variant. Only `VerifierUnavailable` with the exact wire format
 * and a KNOWN code parses; an unknown code is deliberately `null` so a future
 * pool code can never be rendered with the wrong copy.
 */
export function parseSpendAdmission(err: unknown): SpendAdmission | null {
  const poolError: unknown = err instanceof PoolCallError ? err.poolError : err;
  if (typeof poolError !== "object" || poolError === null) return null;
  if (!("VerifierUnavailable" in poolError)) return null;
  const text = (poolError as { VerifierUnavailable: unknown }).VerifierUnavailable;
  if (typeof text !== "string") return null;
  const m = WIRE.exec(text);
  if (m === null) return null;
  const code = m[1] as SpendAdmissionCode;
  if (!SPEND_ADMISSION_CODES.includes(code)) return null;
  const retryAfterNs = BigInt(m[2]);
  if (retryAfterNs > U64_MAX) return null;
  return { code, retryAfterNs };
}

/** The two admission codes the pool checks BEFORE its idempotency read (SSA
 * F-1): on a same-id replay of an already-finalized spend they can mask the
 * idempotent `Ok`, so the replay path asks `get_spend_status` (E-1). */
export function masksIdempotentOk(code: SpendAdmissionCode): boolean {
  return code === "FAILED_VERIFY_LIMIT" || code === "INFLIGHT_LIMIT";
}

/** Whole seconds from the pool's wait, rounded UP (never send a user back early). */
function waitSeconds(retryAfterNs: bigint): number {
  if (retryAfterNs <= 0n) return 0;
  return Number((retryAfterNs + 999_999_999n) / 1_000_000_000n);
}

/** The ruled O-3 copy, one line per code. */
export function spendAdmissionCopy(a: SpendAdmission): string {
  switch (a.code) {
    case "NO_ACTIVE_DEVICE":
      return "Set up this device first, then try again.";
    case "FAILED_VERIFY_LIMIT":
      // SSA F-5: one string for every FAILED_VERIFY_LIMIT case; a zero wait
      // renders "a moment" (humanizeWait), which is truthful.
      return `Too many failed spends this hour. Try again in ${humanizeWait(waitSeconds(a.retryAfterNs))}.`;
    case "INFLIGHT_LIMIT":
      return "Three spends are already in progress. Wait for one to finish.";
    case "DEVICE_CHECK_UNAVAILABLE":
      return "Spending is paused while a service recovers. Try again shortly.";
  }
}

/**
 * E-1 (C-3): a same-id replay was refused at admission, but the ADVISORY
 * status query says the spend is finalized. Deliberately says nothing about
 * the local balance — the journal is not finalized from a query
 * (`spendJournal.ts` authority model); the next replay's authoritative `Ok`
 * does that.
 */
export const SPEND_ALREADY_WENT_THROUGH_COPY = "This spend already went through.";

/** Addendum 1: the one line on a locked note so the wait does not look broken. */
export const SPEND_WAITING_NOTE_COPY = "Waiting for the last spend to settle.";
