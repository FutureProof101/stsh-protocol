/**
 * Open IndexedDB connection registry (lane A-1b, R14-2 panic-wipe).
 *
 * `indexedDB.deleteDatabase` does not force-close live connections: an open
 * handle makes the delete request fire `blocked` and wait. The stores in this
 * folder each hold their own long-lived `idb` connection, so the panic wipe
 * needs a way to close them BEFORE it deletes — otherwise the wipe reports a
 * blocked deletion on the app's own handle, not on a second tab.
 *
 * Every store factory registers its connection here at open time. Nothing else
 * reads this registry; the wipe is its only consumer.
 */

/** The subset of a live connection the registry needs. */
export interface ClosableDb {
  close(): void;
}

const open = new Set<ClosableDb>();

/** Record a freshly opened connection. Idempotent per handle. */
export function registerDbConnection(db: ClosableDb): void {
  open.add(db);
}

/** Forget a connection the caller has already closed. */
export function unregisterDbConnection(db: ClosableDb): void {
  open.delete(db);
}

/** How many connections the registry currently holds (evidence, and tests). */
export function openDbConnectionCount(): number {
  return open.size;
}

/**
 * Close every registered connection and empty the registry. A handle that
 * throws on close is still dropped — the wipe must not abort because one
 * connection was already dead.
 */
export function closeAllDbConnections(): void {
  for (const db of open) {
    try {
      db.close();
    } catch {
      // already closed / closing — nothing to do, and nothing to report.
    }
  }
  open.clear();
}
