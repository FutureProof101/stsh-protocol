/**
 * L07-04 (R-7 item 6) — the ONE place a wallet IndexedDB name is declared.
 *
 * `panicWipe` knew two of the three databases this codebase creates: the note
 * cache and the transfer journal. The third, `deviceStore`'s device-identity
 * database, was declared privately inside its own module and opened through a
 * raw `indexedDB.open` rather than `idb`'s `openDB`, so it appeared in no
 * list. On a browser that supports `IDBFactory.databases()` the runtime
 * enumeration wiped it anyway; on one that does not, the fallback path — which
 * has nothing but this list to go on — left it behind and reported the gap as
 * UNACCOUNTED FOR.
 *
 * The fix is structural rather than a third import: every name is DECLARED
 * here and imported by the module that opens it, so "which databases does this
 * wallet create" has exactly one answer, and `db_registry_census.test.ts` can
 * verify it: three syntactic conditions over the source (no call-graph
 * resolution, no alias chase) plus one that imports this module and checks
 * every exported name is a member of `ALL_DB_NAMES`.
 *
 * A new database means: add its constant here, add it to `ALL_DB_NAMES`, and
 * import the constant at the call site that opens it. The census fails loudly
 * if any of the three is skipped.
 */

/** The note cache (encrypted note set + shield/spend journals). */
export const NOTE_CACHE_DB_NAME = "stsh-wallet";
/** The public-transfer intent journal. */
export const TRANSFER_JOURNAL_DB_NAME = "stsh-wallet-transfers";
/** The per-browser device identity (Layer-1 fast path). */
export const DEVICE_STORE_DB_NAME = "stsh-device-identity";

/**
 * Every database this codebase creates by name — the panic wipe's fallback
 * list when the browser cannot enumerate the origin's databases for itself.
 * The runtime enumeration is UNIONED with this, never replaced by it.
 */
export const ALL_DB_NAMES = [
  NOTE_CACHE_DB_NAME,
  TRANSFER_JOURNAL_DB_NAME,
  DEVICE_STORE_DB_NAME,
] as const;
