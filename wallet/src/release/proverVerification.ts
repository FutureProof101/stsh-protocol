/**
 * J-25 — the prover-asset verification EVENT of this session.
 *
 * SSA addendum A.3 / AMBER-1: importing `spendManifest` is not proof that
 * anything was verified. The panel may only claim verification when a real
 * byte-verification of BOTH pinned artifacts completed in this session, so the
 * event is recorded by `withVerifiedProverAssets` at the point both artifacts
 * have passed their length + SHA-256 checks — not at import, not on entry.
 *
 * This is presentation state (I3). It grants nothing: the fail-closed checks in
 * `loadVerifiedArtifact` and the per-spend deployment validation in
 * `ui/spendFlow.ts` run on their own paths regardless of what is recorded here.
 *
 * RED-1 (SSA landed-diff 2026-09-09): recording the event must NOTIFY, not just
 * assign. The footer paints at mount and when the pool observation settles;
 * both of those happen long before the first spend verifies the artifacts, so a
 * mounted panel that only READS this module keeps saying "not yet verified this
 * session" forever. Subscribers are called synchronously on record — the footer
 * subscribes, it never polls.
 */

let verifiedAtMs: number | null = null;

type Listener = (atMs: number) => void;

const listeners = new Set<Listener>();

/**
 * Observe verification events for the life of the caller. Returns the
 * unsubscribe function; the mounted footer holds it so a torn-down panel stops
 * repainting. Subscribing does NOT replay an event that already happened —
 * callers read `proverAssetVerificationAt()` for the current state and use this
 * only for the transition.
 */
export function subscribeProverAssetVerification(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Record a completed byte-verification of both pinned proving artifacts. */
export function recordProverAssetVerification(atMs: number = Date.now()): void {
  verifiedAtMs = atMs;
  // A throwing listener is a PRESENTATION failure; it must never propagate back
  // into `withVerifiedProverAssets` and abort a spend that verified correctly.
  for (const listener of [...listeners]) {
    try {
      listener(atMs);
    } catch {
      /* presentation only (I3) */
    }
  }
}

/** The time of this session's verification event, or `null` if none occurred. */
export function proverAssetVerificationAt(): number | null {
  return verifiedAtMs;
}

/** Test-only reset; also used by the panel's own suite between cases. */
export function resetProverAssetVerification(): void {
  verifiedAtMs = null;
}
