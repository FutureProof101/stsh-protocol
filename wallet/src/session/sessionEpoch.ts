/**
 * Session epoch (H-A2 / A-S6).
 *
 * A monotonically increasing counter that fences EVERY async operation in the
 * app: capture the epoch before the first await, re-check it after every await
 * before committing any UI/state change, and discard the result if it is
 * stale. Logout advances the epoch BEFORE clearing state, so an in-flight
 * login/refresh/transfer callback from the previous session can never write
 * into the next one (including a user-A -> user-B handover on one device).
 */
export class SessionEpoch {
  private epoch = 0;

  current(): number {
    return this.epoch;
  }

  /** Start a new session era (login success, logout). Returns the new epoch. */
  advance(): number {
    this.epoch += 1;
    return this.epoch;
  }

  isCurrent(captured: number): boolean {
    return captured === this.epoch;
  }

  /**
   * Epoch-checked commit: run `apply` only if `captured` is still the active
   * epoch. Returns whether the commit happened, so callers can drop follow-up
   * work (renders, chained requests) for stale results.
   */
  commit(captured: number, apply: () => void): boolean {
    if (!this.isCurrent(captured)) return false;
    apply();
    return true;
  }
}
