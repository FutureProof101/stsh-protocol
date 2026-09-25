/**
 * Verified-scan UI copy (WALLET-AUTH Gate 1 brief §5 item 8; moved here at G1b
 * so the scan page can render it without importing the app shell).
 *
 * REGISTERED STRINGS. These are the only user-facing words the verified sweep
 * adds, and they are here — as data, in one place — so the packet can quote
 * them verbatim and a reviewer can check the claim each one makes against what
 * the mechanism actually does.
 *
 * THE WORDING DISCIPLINE is AR-2's: this project has a hold-launch finding in
 * its history from a wallet that told users something its mechanism did not
 * deliver. So none of these strings says a scan is safe, trustworthy, or
 * proven. They say what was observed and what was not closed.
 */

import { MAX_VERIFIED_SWEEP_LEAVES, NoAcceptedRootYetError } from "../crypto/scanner";
import { VerifiedFloorRollbackError } from "../storage/noteCache";

export const VERIFIED_SCAN_STRINGS = {
  /**
   * R-1: the copy that names the read lease. This is the string the lease
   * exists to point at — the user is agreeing to an action with a different
   * observable footprint, and saying so is the point of asking.
   */
  lease:
    "Run a verified sweep? A verified sweep asks the canisters for replies they sign, " +
    "which means each request is an ordinary message on the Internet Computer rather " +
    "than a lookup. Your wallet still asks anonymously — no identity is attached — but " +
    "the requests are visible to the network as activity, and the canisters pay for " +
    "answering them. Nothing is submitted and nothing is spent from your balance.",

  /**
   * §5 item 8 + SSA C-9: the verified state, stated as an observation, with the
   * residual named in the same breath rather than in a footnote.
   */
  observation:
    "Verified against the pool's accepted root. Your wallet rebuilt this history from " +
    "signed replies and checked it against the root the pool has accepted, so the " +
    "network path between you and the canisters had no say in what you saw. This is an " +
    "observation, not a guarantee: a dishonest pool could sign a history that is not " +
    "the real one, and that case is not closed here. The pool decides whether a note " +
    "can be spent when you spend it.",

  /**
   * SSA C-2b: a refusal the user can act on, with the reset behind an explicit
   * warning. No automatic reset, and no permanent dead end.
   */
  rollbackRefused:
    "This deployment is showing you a shorter history than it showed you before. That " +
    "is what a rollback looks like, and your wallet will not overwrite what it already " +
    "verified on the strength of it. If you know why — the deployment was rebuilt, or " +
    "you are connecting to a different one — you can reset this wallet's verified " +
    "history for it. Resetting discards the record your wallet is comparing against, " +
    "so a genuine rollback would stop being visible to you afterwards.",

  /**
   * SSA C-3/C-12: the PROT-8 trigger, said plainly. A bigger ceiling is not
   * offered, because a bigger ceiling is not the remedy.
   */
  treeTooLarge:
    "This tree is too large for a verified sweep on this device. Verifying a history " +
    "means rebuilding all of it here, and this one has grown past what a browser can " +
    "do in a sitting. Your ordinary balance still works. Device-side verification of a " +
    "tree this size needs a different design, not a longer wait.",

  /** A legitimate pre-genesis state, said as one. */
  noAcceptedRoot:
    "This pool has not accepted a root yet, so there is no verified history to check " +
    "against. Nothing is wrong — a deployment before its first accepted root has an " +
    "empty history by definition.",

  /** Fail-closed, never a silent demotion to the ordinary answer. */
  unavailable:
    "A verified sweep could not be completed, so your wallet has not recorded one. " +
    "Nothing was saved and your existing balance is unchanged. Your ordinary scan " +
    "still works; it just does not carry the same evidence.",
} as const;

/** Map a verified-scan failure onto its registered string. */
export function verifiedScanMessage(error: unknown): string {
  if (error instanceof NoAcceptedRootYetError) return VERIFIED_SCAN_STRINGS.noAcceptedRoot;
  if (error instanceof VerifiedFloorRollbackError) return VERIFIED_SCAN_STRINGS.rollbackRefused;
  if (error instanceof Error && error.name === "VerifiedSweepTooLargeError") {
    return VERIFIED_SCAN_STRINGS.treeTooLarge;
  }
  return VERIFIED_SCAN_STRINGS.unavailable;
}

/** The pinned ceiling, re-exported for the UI and the packet. */
export const VERIFIED_SCAN_LEAF_CEILING = MAX_VERIFIED_SWEEP_LEAVES;
