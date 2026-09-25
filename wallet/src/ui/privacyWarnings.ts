/**
 * Privacy UX safety checks (wallet-build Commit 6, BUILD_PLAN §3.6).
 *
 * Surfaced in the spend UI BEFORE proof generation starts. Pure + unit-tested.
 *
 * The load-bearing one is the specific-amount warning: a custom-amount private
 * spend publishes that exact figure on-chain, so it is a traceable withdrawal
 * fingerprint (anti-drift law #1 — fixed-denomination withdrawals all look
 * identical on-chain; a custom amount leaves the identity private but the figure
 * visible, which can be correlated back to a deposit and shrinks the anonymity
 * set). The wallet must say this plainly.
 */

import { DELAY_MAX_MS } from "./submissionDelay";

export type WarningLevel = "high" | "medium" | "low";

/**
 * Why a warning fired, as structured data.
 *
 * AR2-P2-02 (SSA-B checkpoint). The countermeasure disclosure below must attach
 * to the timing family, and the first version of this fix decided that by
 * matching the rendered PROSE. That put control flow downstream of user-facing
 * copy: a harmless PM wording change would silently disconnect the
 * countermeasure again while every timing condition still fired — recreating,
 * inside the fix, exactly the doc/control drift the lane exists to close. The
 * reason is set by the branch that fires, so wording and behaviour are
 * independent.
 */
export type WarningReason = "timing-correlation";

export interface Warning {
  level: WarningLevel;
  /**
   * The full disclosure. WALLET-CACHE-II-ONLY O-6: rendered behind "More",
   * never deleted — every sentence here is still on the page.
   */
  msg: string;
  /**
   * O-6: what the page shows FIRST — one idea per line, each at most fifteen
   * words. It must keep every qualifier that makes the full text true (SSA C4:
   * a short line that drops one is the AR-2 overclaim in a smaller font).
   */
  short: readonly string[];
  /** Set by the branch that raised the warning; never inferred from `msg`. */
  reason?: WarningReason;
}

/** Whether the spend uses a fixed denomination or an arbitrary custom amount. */
export type SpendAmountKind = "fixed-denomination" | "specific-amount";

export interface SpendPrivacyInput {
  amountKind: SpendAmountKind;
  /** Milliseconds since the input note was deposited (undefined = unknown). */
  msSinceDeposit?: number;
  /** True if this spend pays out to a transparent (public) recipient/withdrawal. */
  publicPayout?: boolean;
  /**
   * WL-2a: where the input note came from and how long ago, as classified by
   * `classifyNoteOrigin`. Undefined means the caller did not classify at all —
   * which is NOT the same as `kind: "unknown"` (that is a classified result
   * and carries its own advisory).
   */
  noteOrigin?: NoteOrigin;
}

const DAY_MS = 24 * 60 * 60 * 1000;


// ── WL-2a: the rapid-roundtrip warning ───────────────────────────────────────
//
// The leak: an unshield that follows the note's arrival closely enough is
// linkable to it by timing alone, on public data, with no wallet cooperation.
// Two arrivals can start that clock and they need different local anchors:
//
//   limb A  shield -> unshield   anchored on the LOCAL shield journal
//   limb B  receipt -> unshield  anchored on local DISCOVERY of the note
//
// Neither anchor is ever sent anywhere; both are read out of state the wallet
// already keeps for other reasons.

/**
 * The linkability window both limbs use.
 *
 * 24 hours, chosen and held for three reasons rather than picked as a round
 * number: (1) it is the window the wallet ALREADY ships and pins — the
 * `msSinceDeposit` warning below uses `DAY_MS`, and `ui.test.ts` pins it, so a
 * second, different window would tell the user two different stories about the
 * same risk; (2) the threshold is ADVISORY, and its error is asymmetric — a
 * warning the user did not strictly need costs a moment's thought, a missing
 * one costs the linkage, so the wider value is the safe one; (3) no principled
 * narrower value is derivable, because the honest input (how much unrelated
 * traffic shares the window) is exactly the crowd-size estimate K3-007 forbids
 * the wallet from inventing (see the removed anonymity-set warning above).
 *
 * It is a named export precisely so a test can halve it and watch the
 * outside-the-window rows fail.
 */
export const ROUNDTRIP_WINDOW_MS = 24 * 60 * 60 * 1000;

/** How the input note entered this wallet — mutually exclusive by construction. */
export type NoteOriginKind =
  /** This wallet shielded it: the local shield journal has its commitment. */
  | "self-shield"
  /** No journal entry, but the scanner recorded when it first saw the note. */
  | "incoming-receipt"
  /** Neither anchor exists — the arrival time is genuinely not known here. */
  | "unknown";

export interface NoteOrigin {
  kind: NoteOriginKind;
  /** Milliseconds since the arrival the `kind` names; absent iff kind is "unknown". */
  msSinceArrival?: number;
}

/**
 * Classify one input note's origin and age. PURE — every input is local, and
 * the caller supplies `nowNs`, so the same inputs always give the same answer.
 *
 * Journal provenance ALWAYS wins and is checked FIRST, so a note this wallet
 * shielded can never also be reported as an incoming receipt and one arrival
 * can never warn twice.
 *
 * KNOWN AND DISCLOSED (not a bug to be patched with a second stored field):
 * on a fresh device the shield journal is gone, so the user's OWN old shield
 * classifies as an incoming receipt. That mislabels the ORIGIN while keeping
 * the timing advisory itself conservative — it is an over-warning, in the safe
 * direction; B-1 carries the caveat.
 *
 * L07-03 (R-7 item 5): `firstSeenAtNs` ALONE is not evidence of an arrival. On
 * a fresh device or a post-wipe recovery every note is stamped with the scan's
 * own clock, so limb B fired "this note reached you within the last 24 hours"
 * on the strength of when the wallet happened to scan — a claim with nothing
 * behind it. Only a first sighting the scanner can vouch for as a LIVE
 * incremental scan (`firstSeenVia === "live-scan"`) reaches the
 * `incoming-receipt` branch now. Everything else — "recovery-import", or the
 * field absent on a pre-this-change record — falls through to the honest
 * `unknown` branch, which already says the true thing ("arrival time is not
 * known on this device... treat this as unchecked, not as safe").
 */
export function classifyNoteOrigin(input: {
  /** Anchor from the shield journal for this note's commitment (ns, decimal). */
  journalAnchorNs?: string;
  /** Local first-sighting of the note by the scanner (ns, decimal). */
  firstSeenAtNs?: string;
  /**
   * How that first sighting was established. Only "live-scan" makes
   * `firstSeenAtNs` evidence of an ARRIVAL; absent or "recovery-import" means
   * the wallet cannot vouch for it (L07-03).
   */
  firstSeenVia?: "live-scan" | "recovery-import";
  /** Current time (ns). */
  nowNs: bigint;
}): NoteOrigin {
  if (input.journalAnchorNs !== undefined) {
    return { kind: "self-shield", msSinceArrival: elapsedMs(input.journalAnchorNs, input.nowNs) };
  }
  if (input.firstSeenAtNs !== undefined && input.firstSeenVia === "live-scan") {
    return {
      kind: "incoming-receipt",
      msSinceArrival: elapsedMs(input.firstSeenAtNs, input.nowNs),
    };
  }
  return { kind: "unknown" };
}

/**
 * ns-string -> elapsed ms, floored at 0 (a future anchor is never negative age).
 *
 * EXPORTED (R-7 item 5) so `spend.ts` can measure the deposit-timing warning
 * against the shield-journal anchor with the same arithmetic, rather than
 * duplicating this body or re-deriving the figure from a value that was never
 * a deposit time.
 */
export function elapsedMs(anchorNs: string, nowNs: bigint): number {
  const elapsed = nowNs - BigInt(anchorNs);
  return elapsed <= 0n ? 0 : Number(elapsed / 1_000_000n);
}

/**
 * The shield-journal anchor for a commitment: the DISPATCH time when the entry
 * has one, else the intent's creation time.
 *
 * The dispatch marker is written immediately before the first `shield_deposit`
 * wire attempt, so it is the closest local proxy for the moment the deposit
 * became PUBLIC — which is the event an observer correlates against. Falling
 * back to `createdAtNs` only widens the measured age slightly, in the
 * over-warning direction.
 */
export function shieldJournalAnchorNs(
  entries: readonly { commitmentHex: string; createdAtNs: string; dispatchedAtNs?: string }[],
  commitmentHex: string | undefined,
): string | undefined {
  if (commitmentHex === undefined) return undefined;
  const entry = entries.find((e) => e.commitmentHex === commitmentHex);
  if (entry === undefined) return undefined;
  return entry.dispatchedAtNs ?? entry.createdAtNs;
}

/**
 * Compute the privacy warnings to show before a spend, most-severe first.
 * `specific-amount` is `high`; a fresh deposit adds a timing-correlation
 * `high`; a public payout adds a `medium`.
 *
 * K3-007 (L3b): the old small-anonymity-set warning is REMOVED. It was fed
 * the user's OWN note count (inverted — your notes say nothing about the
 * crowd), and the pool's leaf_count is NOT an anonymity-set estimate (it
 * includes spent notes, zero dummies, self-churn, and attacker-inflated
 * commitments, with no per-denomination refinement possible). A wrong
 * small/large signal is worse than none; the honest advisory count lives on
 * the balance/scan pages instead.
 */
export function privacyWarnings(input: SpendPrivacyInput): Warning[] {
  const warnings: Warning[] = [];

  if (input.amountKind === "specific-amount") {
    // R-7 item 1 part B: the advice must be achievable ON THE PATH THAT
    // REACHES IT. On the `private_spend` public-payout path there is no
    // fixed-denomination payout option to prefer (Law 1 governs deposits and
    // the separate `withdraw` entrypoint, not this one), so telling the user
    // to "prefer fixed-denomination withdrawals" is advice they cannot take.
    // Keyed on the STRUCTURAL `publicPayout` field, never on prose (AR2-P2-02).
    warnings.push({
      level: "high",
      short: ["The exact amount is published on-chain. It can be traced to your deposit."],
      msg: input.publicPayout
        ? "Specific-amount payout: the exact amount is published on-chain. This is a " +
          "traceable spend fingerprint — it can be correlated back to your deposit and " +
          "shrinks your anonymity set. There is no fixed-denomination option on this " +
          "payout path; if the exact figure is not required, spend without a public " +
          "payout (self-change only) instead."
        : "Specific-amount spend: the exact amount is published on-chain. This is a " +
          "traceable withdrawal fingerprint — it can be correlated back to your deposit " +
          "and shrinks your anonymity set. Fixed-denomination withdrawals all look " +
          "identical on-chain; prefer them unless you specifically need an exact figure.",
    });
  }

  if (input.msSinceDeposit !== undefined && input.msSinceDeposit < DAY_MS) {
    warnings.push({
      level: "high",
      short: ["Spending within 24 hours of shielding links the two by timing."],
      msg: "Spending within 24h of deposit reveals a timing correlation between your deposit and this spend.",
      reason: "timing-correlation",
    });
  }

  // WL-2a — the two roundtrip limbs. Both are about an UNSHIELD following an
  // arrival, so both are scoped to a public payout; a shielded->shielded spend
  // publishes no exit to correlate the arrival against.
  const origin = input.noteOrigin;
  if (input.publicPayout === true && origin !== undefined) {
    if (
      origin.kind === "self-shield" &&
      origin.msSinceArrival !== undefined &&
      origin.msSinceArrival < ROUNDTRIP_WINDOW_MS
    ) {
      warnings.push({
        level: "high",
        short: ["Shielded in the last 24 hours. Both events are public; timing links them."],
        msg:
          "Rapid roundtrip: you shielded this note within the last 24 hours and are now " +
          "unshielding it. Both the deposit and the withdrawal are public events; their " +
          "closeness in time links them to each other on-chain, whoever holds the note. " +
          "Waiting longer, and letting unrelated deposits and withdrawals happen in " +
          "between, is what breaks that link.",
        reason: "timing-correlation",
      });
    }
    if (
      origin.kind === "incoming-receipt" &&
      origin.msSinceArrival !== undefined &&
      origin.msSinceArrival < ROUNDTRIP_WINDOW_MS
    ) {
      warnings.push({
        level: "high",
        short: ["Received in the last 24 hours. Timing links your public payout to it."],
        msg:
          "Rapid roundtrip: this note reached you within the last 24 hours and you are now " +
          "unshielding it. The withdrawal is public; unshielding a freshly received note " +
          "links your withdrawal to the deposit that funded it by timing alone.",
        reason: "timing-correlation",
      });
    }
    if (origin.kind === "unknown") {
      warnings.push({
        level: "medium",
        short: ["This device doesn't know when this note arrived. Treat timing as unchecked, not safe."],
        msg:
          "This note's arrival time is not known on this device, so the wallet CANNOT tell " +
          "you whether this is a rapid roundtrip. Treat this as unchecked, not as safe — " +
          "if you received or shielded this note recently, the timing link still exists.",
        reason: "timing-correlation",
      });
    }
  }

  // AR2-P2-01. The claim this replaced — "only the sender note stays private" —
  // was false in the direction that makes a user LESS careful. `private_spend`
  // rejects the anonymous principal (shielded-pool `lib.rs`, DEF-069), so the
  // wallet submits under the user's Internet Identity and the signed ingress
  // naming that principal, the pool and the method is permanent CONSENSUS
  // history. That is outside the reach of the submitter redaction, which clears
  // canister STATE only. The note graph is genuinely unaffected — this is a
  // disclosure defect, not a break in the cryptography — so the warning has to
  // say BOTH halves. "Nothing is private" would be wrong in the other
  // direction and would drive users off a feature that works.
  //
  // WALLET-CACHE-II-ONLY: the original two halves are kept verbatim (SSA C4),
  // and the single-deposit limit is APPENDED in the disclosure sweep's own
  // approved wording (DS-54, d6b6632b): with one deposit ever, the signed
  // spend has only one candidate note, so "which note funded this payout"
  // stays private only across more than one deposit. Short lines keep both
  // halves and the limit.
  if (input.publicPayout) {
    warnings.push({
      level: "high",
      short: [
        "Recipient and amount are public. Your signing account is public and permanent.",
        "Which of your own notes paid stays private.",
        "If you deposited only once, the payout is linkable to that deposit.",
      ],
      msg:
        "Public payout: the recipient account and the amount are visible on-chain — and so " +
        "is the account that submits this spend. That submission is signed by your wallet " +
        "identity and is recorded permanently; it cannot be deleted later. What stays " +
        "private is your notes and how they connect: nobody learns which note funded this " +
        "payout, or what else you hold. If you deposited only once, the payout is linkable " +
        "to that deposit.",
    });
  }

  // AR2-P2-02. Every warning above this point describes a TIMING correlation,
  // and the wallet already ships a countermeasure for exactly that — the
  // optional randomised submission delay (WL-2c) — which no string ever
  // mentioned. A warning the user cannot act on is half a warning.
  //
  // The trigger is the structured `reason`, NOT the wording (see WarningReason).
  //
  // Scope, stated where the string is written: the delay blurs WHEN the
  // submission lands. It does not anonymise the submitter (see the public-payout
  // warning above), and it is off unless the user turns it on. `DELAY_MAX_MS` is
  // read from the shipped module rather than restated, so the copy cannot drift
  // from the bound the code actually uses.
  if (warnings.some((w) => w.reason === "timing-correlation")) {
    warnings.push({
      level: "low",
      short: [
        `Optional random wait (up to ${Math.round(DELAY_MAX_MS / 60_000)} min) blurs timing, not who signs. Off by default.`,
      ],
      msg:
        `You can blur this timing link: the wallet can wait a random period of up to ` +
        `${Math.round(DELAY_MAX_MS / 60_000)} minutes before submitting, so the moment you ` +
        `act and the moment the network sees it are not the same. It is OFF unless you turn ` +
        `it on in settings, and it changes only the timing — it does not hide the account ` +
        `that submits the spend.`,
    });
  }

  return warnings;
}

/**
 * U-2 (R-7 item 3) — the DEPOSIT side's privacy disclosures.
 *
 * The shield page never called this module at all, so the one place a user
 * makes an irreversible, publicly-readable commitment said nothing true about
 * what it publishes. Two facts, both observable by anyone:
 *
 *   1. The decomposition SHAPE. Fixed denominations do not make deposits
 *      interchangeable — they make deposits of the same SHAPE
 *      interchangeable. An observer sees how many notes of each size this
 *      deposit produced.
 *   2. The allowance. `icrc2_approve` publishes the exact total, and
 *      `icrc2_allowance` is an unauthenticated query on the ledger
 *      (`canisters/token/stsh_token.did`), so the figure is readable by anyone
 *      for as long as the approval stands. It is NOT permanent: the record is
 *      decremented as it is spent (`icrc2_transfer_from`) and reads zero once
 *      consumed or expired, and this hand-rolled ledger exposes no ICRC-3
 *      block or transaction history, so nothing republishes the figure after
 *      that. The disclosure says "while the approval stands", not "forever".
 *
 * PURE, on the same contract as `privacyWarnings` (invariant 3): no I/O, no
 * canister call, no clock, no randomness. Same inputs, same output, always.
 */
export function shieldPrivacyWarnings(input: {
  /** How many fixed-denomination notes the deposit decomposes into. */
  bucketCount: number;
  /** How many DISTINCT denominations those notes span. */
  totalDenominations: number;
}): Warning[] {
  // No plan yet (no amount entered, or an unparseable one) — say nothing
  // rather than guess, matching the decomposition preview's own gating.
  if (input.bucketCount <= 0) return [];

  return [
    {
      level: "medium",
      short: [
        `Public: this deposit's shape — ${input.bucketCount} note${input.bucketCount === 1 ? "" : "s"}, ` +
          `${input.totalDenominations} size${input.totalDenominations === 1 ? "" : "s"}.`,
      ],
      msg:
        `This deposit decomposes into ${input.bucketCount} note` +
        `${input.bucketCount === 1 ? "" : "s"} across ${input.totalDenominations} distinct ` +
        `denomination${input.totalDenominations === 1 ? "" : "s"} — that shape (how many of ` +
        "each size) is visible on-chain and is what makes it identical to other deposits of " +
        "the SAME shape, not to deposits of a different total.",
    },
    {
      level: "high",
      short: ["The total you approve is publicly readable while the approval stands."],
      msg:
        "The exact total you approve for this deposit is publicly readable through " +
        "icrc2_allowance, an unauthenticated ledger query, from the moment you approve " +
        "until the approval is spent or expires. The ledger keeps no public transaction " +
        "history (no ICRC-3), so the figure is not retained afterwards — but anyone " +
        "watching while the approval stands can read and record it.",
    },
  ];
}
