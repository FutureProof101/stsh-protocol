/**
 * STSH — key-recovery quota UX (D-1 ruling clause 4, brief V1 §6).
 *
 * A Layer-2 derive is metered and quota-bound: 5 per principal per rolling
 * 24 h. The ruling requires the wallet to SHOW the remaining allowance, warn at
 * three or fewer, and render the wait when it is exhausted — so a user who is
 * about to lose access to key recovery finds out before they need it, not after.
 *
 * A NOTE ON `remaining === null`: that is the Layer-1 fast path, which performs
 * no derive at all and therefore has no allowance to report. It is deliberately
 * NOT rendered as "5 of 5 left" — the canister said nothing about the quota,
 * and inventing a number would be the wallet asserting something it does not
 * know.
 */

import { QUOTA_WARN_REMAINING, retryAfterSeconds } from "../crypto/vetkeys";
import type { VetkeysError } from "../../../src/declarations/vetkeys/vetkeys.did";

export type QuotaNoticeLevel = "info" | "warning" | "error";

export interface QuotaNotice {
  level: QuotaNoticeLevel;
  message: string;
}

/**
 * Round a wait UP to a human unit. Rounding up is deliberate: telling a user
 * "1 hour" when 61 minutes remain sends them back too early, and a retry that
 * fails again is worse than a slightly pessimistic number.
 */
export function humanizeWait(seconds: number): string {
  if (seconds <= 0) return "a moment";
  if (seconds < 60) return `${Math.ceil(seconds)} seconds`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.ceil(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"}`;
  const days = Math.ceil(hours / 24);
  return `${days} day${days === 1 ? "" : "s"}`;
}

/**
 * A wait as hours and minutes — "7 h 0 m", "45 m" — for the daily key limit
 * (WALLET-SHIELD-LAYER1, Owner Addendum A item 9). A NEW formatter on purpose:
 * `humanizeWait` above rounds to the largest whole unit and is shared with the
 * first-use preparation copy, whose wording an existing arm pins.
 *
 * Rounds UP to the whole minute, for the same reason `humanizeWait` rounds up:
 * a wait shown shorter than it is sends the user back too early. `seconds` is
 * already whole (the canister's `retry_after_ns`, ceiling-rounded by
 * `retryAfterSeconds`).
 */
export function formatHoursMinutes(seconds: number): string {
  const totalMinutes = Math.max(1, Math.ceil(seconds / 60));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return hours === 0 ? `${minutes} m` : `${hours} h ${minutes} m`;
}

/**
 * The daily key-limit copy (`DerivationQuotaExceeded`) for every path that does
 * NOT render quota refusals through `quotaRefusalNotice` — shield, reconcile,
 * spend — instead of the raw "limit reached — try again in 25244 s" text that
 * `describeVetkeysError` bakes into the error. Scan keeps its own ruled copy.
 */
export function dailyKeyLimitMessage(seconds: number): string {
  return `Daily key limit reached. Try again in ${formatHoursMinutes(seconds)}.`;
}

/**
 * What to tell the user after a key acquisition, given the reported allowance.
 *
 * `null` (fast path) and a comfortable allowance both produce NOTHING: a
 * warning that fires when nothing is wrong is a warning users learn to ignore,
 * and the whole point of the threshold is that it still means something when it
 * appears.
 */
export function quotaNotice(remaining: number | null): QuotaNotice | null {
  if (remaining === null) return null;
  if (remaining <= 0) {
    return {
      level: "error",
      message:
        "You have used all of your key recoveries for today. This device still works " +
        "normally; only setting up a NEW device or recovering after losing all of them " +
        "needs one.",
    };
  }
  if (remaining <= QUOTA_WARN_REMAINING) {
    return {
      level: "warning",
      message:
        `${remaining} key ${remaining === 1 ? "recovery" : "recoveries"} left today. ` +
        "Each new-device setup or all-devices-lost recovery uses one; they come back over " +
        "the next 24 hours.",
    };
  }
  return null;
}

/**
 * The message for a refused acquisition. Only the two rate limits carry a wait;
 * everything else is rendered by `describeVetkeysError`, which this defers to
 * rather than duplicating.
 */
export function quotaRefusalNotice(error: VetkeysError): QuotaNotice | null {
  const seconds = retryAfterSeconds(error);
  if (seconds === null) return null;

  // FLEET CAPACITY — not a statement about this user at all.
  //
  // LEVEL "info", NOT "error" (brief V4 §5.3): the user did nothing wrong and
  // has nothing to fix; they are in a queue that moves on its own. Painting a
  // waitlist red tells them something false about their own account.
  //
  // COPY IS RULED (eb847fd1…, Owner: "yes, use the hourly copy — no 'today'").
  // The budget is a rolling HOUR, so the refusal describes the wait to the next
  // spot and never a daily bucket. 480/day exists only as the throughput
  // implied by 20/hour; it does not appear here as a quota.
  if ("GlobalDerivationBudgetExceeded" in error) {
    return {
      level: "info",
      message: `Launch capacity is currently full — your next spot opens in ${humanizeWait(
        seconds,
      )}.`,
    };
  }

  // V5 §6.6 — FIRST-TIME PREPARATION. Ruled copy: VETKEYS-AGE-2MIN C-4,
  // Option 1 (CTO, RULING_VETKEYS_ENVELOPE_CAP_MECHANISM 2026-09-23 addendum)
  // — ground truth only, NO time-of-event promise. The canister clocks age from
  // its first sighting of a funded balance, not from sign-in, and saturation
  // can stretch it, so the only honest number is the wait THIS refusal
  // returned. Supersedes the fixed "up to 15 minutes" copy of D-2 (6b60d432…).
  //
  // LEVEL "info", NOT "error": the user is already funded and has nothing to
  // fix. They are waiting for a one-time setup, and painting that red tells
  // them something false about their own account.
  //
  // DELIBERATELY NOT THE WAITLIST COPY. That one is about FLEET capacity and
  // belongs to `GlobalDerivationBudgetExceeded` alone; this is about this
  // user's own first-time preparation. The two strings must stay distinct, and
  // an arm asserts it — if they ever converged, an operator reading a support
  // ticket could not tell which control the user hit.
  //
  // The stated wait is the canister's own `retry_after_ns`, rounded up by
  // `retryAfterSeconds` and humanized — a drift-locked arm binds it to the pin.
  if ("EligibilityAgeNotMet" in error) {
    return {
      level: "info",
      message: `Your wallet is being prepared — first use unlocks in ${humanizeWait(seconds)}.`,
    };
  }

  // The user's OWN allowance. Stays "error", exactly as before: this one is
  // about them, and there is a decision for them to make about it.
  if ("DerivationQuotaExceeded" in error) {
    return {
      level: "error",
      message:
        "You have used all of your key recoveries for now — try again in " +
        `${humanizeWait(seconds)}. Devices you have already set up keep working in the ` +
        "meantime.",
    };
  }
  return {
    level: "error",
    message: `Too many device changes recently — try again in ${humanizeWait(seconds)}.`,
  };
}
