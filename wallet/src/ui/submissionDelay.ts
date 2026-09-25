/**
 * WL-2c — the optional randomised submission delay.
 *
 * WHAT IT IS FOR
 *
 * Even with amounts and identities hidden, a submission that lands the instant
 * the user clicks is correlated with everything else that happened at that
 * instant — a page load, a session, a device coming online. A random wait in
 * front of the operation decouples "when the user acted" from "when the chain
 * saw it". It is OPTIONAL and OFF by default: it costs latency, and a user who
 * does not want it must not silently get it.
 *
 * THE UNIT IS THE OPERATION
 *
 * The delay precedes the operation's FIRST state-changing public call, and
 * every live precondition is evaluated after it. Delaying a later call inside
 * an operation would be worse than not delaying at all: the first public
 * signal would still fire at the user's real action time, and the gap it
 * manufactured between the operation's own calls would be a new signal.
 *
 * Concretely, `runShieldFlow`'s first public call is the ICRC-2 approve, not
 * the deposit, and its `created_at_time` dedup timestamp is read a few lines
 * before it — so the delay goes in FRONT of the whole flow, where nothing live
 * has been read yet and the dedup timestamp stays as fresh as it is today.
 *
 * NO WALL CLOCK ANYWHERE
 *
 * The wait itself is an injected `sleep`, and the randomness is an injected
 * byte source. Tests drive both, so nothing here asserts against real elapsed
 * time.
 */

/** Upper bound of the delay. Named and exported so a test can bind it. */
export const DELAY_MAX_MS = 120_000;

/** The operations that carry a delay (see the WL-2c operation table). */
export type DelayedOperationKind = "shield" | "spend";

/** Why a delayed operation was abandoned instead of submitted. */
export type AbandonReason =
  /** The user pressed cancel while the delay was running. */
  | "cancelled"
  /** The session ended (lock, logout, epoch change) during the delay. */
  | "session";

/**
 * A delayed operation was abandoned. It is thrown BEFORE the operation body
 * runs, so nothing was submitted — that is the whole point of the type.
 */
export class SubmissionAbandonedError extends Error {
  constructor(readonly reason: AbandonReason, message: string) {
    super(message);
    this.name = "SubmissionAbandonedError";
  }
}

/** What the UI needs to show, and the two controls it must offer (§6.1). */
export interface PendingDelayView {
  kind: DelayedOperationKind;
  delayMs: number;
  /** Abandon the operation now — nothing is submitted. */
  cancel(): void;
  /** Skip the remaining wait and submit immediately. */
  submitNow(): void;
}

export interface SubmissionDelayDeps {
  /** The user's toggle. Read per operation, so flipping it takes effect at once. */
  enabled(): boolean;
  /** Wait `ms`. Injected — production passes a `setTimeout` wrapper. */
  sleep(ms: number): Promise<void>;
  /**
   * Throws if the session is no longer the one that started the operation
   * (lock, logout, epoch change). Called BEFORE and AFTER the wait.
   */
  assertSessionCurrent(): void;
  /** CSPRNG bytes. Injected only by tests; production uses `crypto`. */
  randomBytes?(n: number): Uint8Array;
  /** UI hook: called with a view while a delay runs, and with null when it ends. */
  onPending?(view: PendingDelayView | null): void;
}

export interface SubmissionDelay {
  /** Wait, if enabled, then return. Throws `SubmissionAbandonedError` instead of returning if abandoned. */
  run(kind: DelayedOperationKind): Promise<void>;
}

function defaultRandomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * A uniform integer over the INCLUSIVE range `[0, DELAY_MAX_MS]`.
 *
 * Zero is a legal draw — the interval is closed at both ends, and excluding it
 * would be a bias of exactly the kind this function exists to avoid.
 *
 * `% N` on a raw 32-bit draw is NOT uniform unless `N` divides 2^32, which
 * 120_001 does not: the low residues would come up marginally more often. So
 * the draw is rejected whenever it falls in the short final partial block and
 * re-drawn; only the `limit`-sized prefix, which is an exact multiple of `N`,
 * is reduced. The rejection probability is under 0.003%, so this terminates
 * immediately in practice, but the loop is unbounded on purpose — a bounded
 * fallback would reintroduce the bias it just refused.
 */
export function drawDelayMs(randomBytes: (n: number) => Uint8Array = defaultRandomBytes): number {
  const n = DELAY_MAX_MS + 1;
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  for (;;) {
    const b = randomBytes(4);
    const v = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
    if (v < limit) return v % n;
  }
}

export function createSubmissionDelay(deps: SubmissionDelayDeps): SubmissionDelay {
  return {
    async run(kind: DelayedOperationKind): Promise<void> {
      // Pre-check: an operation started on a session that has already ended is
      // abandoned without waiting at all.
      deps.assertSessionCurrent();
      if (!deps.enabled()) return;

      const delayMs = drawDelayMs(deps.randomBytes ?? defaultRandomBytes);
      let settle: ((outcome: "submit-now" | "cancel") => void) | undefined;
      const interrupted = new Promise<"submit-now" | "cancel">((resolve) => {
        settle = resolve;
      });
      deps.onPending?.({
        kind,
        delayMs,
        cancel: () => settle?.("cancel"),
        submitNow: () => settle?.("submit-now"),
      });
      let outcome: "elapsed" | "submit-now" | "cancel";
      try {
        outcome = await Promise.race([deps.sleep(delayMs).then(() => "elapsed" as const), interrupted]);
      } finally {
        deps.onPending?.(null);
      }
      if (outcome === "cancel") {
        throw new SubmissionAbandonedError(
          "cancelled",
          "the delayed submission was cancelled before anything was sent — nothing was submitted",
        );
      }
      // Post-check: the wait is exactly the window in which a session can end
      // under the operation. Re-assert it, and let the session error abandon
      // the operation, BEFORE any live value is read or any call is made.
      try {
        deps.assertSessionCurrent();
      } catch (err) {
        throw new SubmissionAbandonedError(
          "session",
          `the session ended during the submission delay — the operation was abandoned and ` +
            `nothing was submitted: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    },
  };
}

/** Production wait: a plain `setTimeout`, isolated here so nothing else uses one. */
export function timerSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
