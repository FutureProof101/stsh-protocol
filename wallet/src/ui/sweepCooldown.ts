/**
 * WALLET-UX — one verified note sweep per hour, per signed-in principal, in
 * this browser.
 *
 * A UI courtesy, NOT a control: a script can call the canisters directly, so
 * the real limit is a per-caller window on the pool's replicated-query
 * allowlist (a pool change, scheduled for the first post-launch wave). This
 * only stops the wallet itself from offering a sweep more often than that.
 *
 * It keeps its own timestamp, taken when the user presses the button, rather
 * than reading `VerifiedScanMetadata.validated_at_ms`: that field is advisory
 * display data and nothing may gate on it. A clock moved backwards can only
 * shorten or lengthen this wait, never revive evidence.
 */

export const SWEEP_COOLDOWN_MS = 60 * 60 * 1000;

const key = (principalText: string): string => `stsh.wallet.verifiedSweepAt.${principalText}`;

/** Milliseconds until the next sweep is offered; 0 when available. */
export function sweepCooldownRemainingMs(principalText: string | null | undefined, nowMs: number = Date.now()): number {
  if (principalText === null || principalText === undefined) return 0;
  let last: number;
  try {
    const raw = window.localStorage.getItem(key(principalText));
    if (raw === null) return 0;
    last = Number(raw);
  } catch {
    return 0;
  }
  if (!Number.isFinite(last)) return 0;
  const elapsed = nowMs - last;
  // A stored time in the future (clock moved back): wait at most one window.
  if (elapsed < 0) return SWEEP_COOLDOWN_MS;
  return elapsed >= SWEEP_COOLDOWN_MS ? 0 : SWEEP_COOLDOWN_MS - elapsed;
}

/** Record that a sweep was started now. */
export function recordSweepStarted(principalText: string | null | undefined, nowMs: number = Date.now()): void {
  if (principalText === null || principalText === undefined) return;
  try {
    window.localStorage.setItem(key(principalText), String(nowMs));
  } catch {
    // Storage blocked: the cooldown simply does not persist.
  }
}

/** "about 42 min" style wording for the remaining wait. */
export function cooldownWords(ms: number): string {
  const min = Math.max(1, Math.ceil(ms / 60_000));
  return `${min} min`;
}
