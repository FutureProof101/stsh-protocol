/**
 * Cache-session lifecycle (Campaign B / L4 — §1.1 concurrency invariants).
 *
 * Binds every PrincipalNoteCache to an immutable (principal, sessionEpoch)
 * pair at construction, on top of Campaign A's SessionEpoch:
 *
 * - The owning principal comes from the restored II session's IDENTITY
 *   (`identity.getPrincipal()`, A-S7) — which AuthClient restores from local
 *   storage without any network round-trip, so the same selection works
 *   OFFLINE. Anonymous or absent sessions never open a cache.
 * - `endSession()` (logout / verified expiry) increments the epoch FIRST, then
 *   locks + disposes the active cache: an in-flight IC call from the old
 *   session cannot be cancelled, but its result can no longer commit — every
 *   cache operation re-checks the captured epoch before touching state, and
 *   the locked instance refuses everything (§1.1 rules 1–3).
 * - Opening a cache for a new session locks any previously issued instance:
 *   no cache instance ever survives into another principal's session.
 *
 * This module is the L4 mechanism only; wiring it into the app's login/logout
 * flow arrives with the shielded pages (L3a/L3b), not here.
 */

import type { SessionEpoch } from "./sessionEpoch";
import type { AuthSession } from "./auth";
import {
  CacheSessionStaleError,
  PrincipalNoteCache,
  type PrincipalCacheStore,
  type SessionBinding,
} from "../storage/noteCache";

/** No restored II session (or an anonymous one) — the cache stays closed. */
export class NoCacheSessionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoCacheSessionError";
  }
}

/**
 * The principal a cache is scoped to, from a restored II session. Derives from
 * the session's IDENTITY (A-S7), works offline (AuthClient session restore is
 * local), and refuses anonymous/absent sessions.
 */
export function principalForCache(session: AuthSession | null): string {
  if (session === null) {
    throw new NoCacheSessionError(
      "no restored Internet Identity session — the note cache cannot be opened",
    );
  }
  const principal = session.identity.getPrincipal();
  if (principal.isAnonymous()) {
    throw new NoCacheSessionError("an anonymous session cannot own a note cache");
  }
  return principal.toText();
}

/**
 * Issues epoch-bound caches and tears them down on session end. One manager
 * per app instance, sharing the app's SessionEpoch.
 */
export class CacheSessionManager {
  private active: PrincipalNoteCache | null = null;

  constructor(private readonly epochs: SessionEpoch) {}

  /** The currently issued cache, if any (locked instances are not returned). */
  get activeCache(): PrincipalNoteCache | null {
    return this.active;
  }

  /**
   * Open the note cache for the CURRENT session. Captures the epoch at entry;
   * if the session ends while the KDF/migration runs, the open itself throws
   * (the binding is re-checked before every store mutation and on return).
   */
  async openForSession(
    store: PrincipalCacheStore,
    passphrase: string,
    session: AuthSession | null,
  ): Promise<PrincipalNoteCache> {
    principalForCache(session);
    // A previously issued instance (any principal) is dead the moment a new
    // session opens — no instance survives into another principal (§1.1).
    this.active?.lock();
    this.active = null;

    const binding = this.bindingFor(session);
    const cache = await PrincipalNoteCache.open(store, passphrase, binding);
    this.active = cache;
    return cache;
  }

  /**
   * WALLET-CACHE-II-ONLY — the KEY-BASED twin of `openForSession`: opens this
   * principal's v3/v4 record under `key`. With `create` set to a key-based
   * version, an EMPTY slot gets a new record at that version
   * (`PrincipalNoteCache.openOrCreateWithKey`); with `create: false` an empty
   * slot is an error (`openWithKey`) — used wherever a record is known to
   * exist and silently minting an empty one would hide its loss. Same session
   * discipline as the passphrase path: any previously issued instance is
   * locked first, and the binding is to the CURRENT epoch.
   */
  async openForSessionWithKey(
    store: PrincipalCacheStore,
    key: CryptoKey,
    session: AuthSession | null,
    opts: { create: number | false },
  ): Promise<PrincipalNoteCache> {
    principalForCache(session);
    this.active?.lock();
    this.active = null;

    const binding = this.bindingFor(session);
    const cache =
      opts.create === false
        ? await PrincipalNoteCache.openWithKey(store, key, binding)
        : await PrincipalNoteCache.openOrCreateWithKey(store, key, binding, opts.create);
    this.active = cache;
    return cache;
  }

  /**
   * The (principal, current epoch) binding for `session` — what the storage
   * layer's migration/re-seal functions take. Refuses anonymous/absent sessions
   * exactly as `openForSession` does.
   */
  bindingFor(session: AuthSession | null): SessionBinding {
    const principalText = principalForCache(session);
    const epochs = this.epochs;
    const epoch = epochs.current();
    return {
      principalText,
      epoch,
      assertCurrent(): void {
        if (!epochs.isCurrent(epoch)) {
          throw new CacheSessionStaleError(
            "the session epoch advanced (logout/expiry) — this note cache is no longer valid",
          );
        }
      },
    };
  }

  /**
   * Session teardown (logout or verified expiry): advance the epoch, then lock
   * + dispose the active cache. Safe to call when no cache is open; extra
   * epoch advances only strengthen invalidation.
   */
  endSession(): void {
    this.epochs.advance();
    this.active?.lock();
    this.active = null;
  }
}
