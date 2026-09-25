/**
 * In-memory JournalStore for tests (Lane A2; AC-1 CAS interface).
 *
 * Mirrors the IndexedDB store's contract, including per-op atomicity: all
 * operations are serialized through a single promise queue, so two concurrent
 * `claim`s for one key resolve exactly one winner and every conditional op
 * observes a consistent slot — the same guarantee the production store gets
 * from one IndexedDB readwrite transaction per op.
 */

import type {
  ArchivedTransferIntent,
  IntentExpectation,
  JournalStore,
  TransferIntentRecord,
} from "../../src/storage/transferJournal";

export interface MemoryJournalStore extends JournalStore {
  /** Direct inspection for assertions. */
  intents: Map<string, TransferIntentRecord>;
  archive: ArchivedTransferIntent[];
}

function matches(
  current: TransferIntentRecord | undefined,
  expected: IntentExpectation,
): current is TransferIntentRecord {
  return (
    current !== undefined &&
    current.intentId === expected.intentId &&
    current.revision === expected.revision
  );
}

export function memoryJournalStore(): MemoryJournalStore {
  const intents = new Map<string, TransferIntentRecord>();
  const archive: ArchivedTransferIntent[] = [];
  let queue: Promise<unknown> = Promise.resolve();

  function serialized<T>(op: () => T): Promise<T> {
    const next = queue.then(op);
    queue = next.catch(() => undefined);
    return next;
  }

  return {
    intents,
    archive,
    claim(key, record) {
      return serialized(() => {
        const existing = intents.get(key);
        if (existing !== undefined) return { claimed: false as const, existing };
        intents.set(key, record);
        return { claimed: true as const };
      });
    },
    get(key) {
      return serialized(() => intents.get(key) ?? null);
    },
    compareAndPut(key, expected, next) {
      return serialized(() => {
        const current = intents.get(key);
        if (!matches(current, expected)) return { ok: false as const, current: current ?? null };
        intents.set(key, next);
        return { ok: true as const };
      });
    },
    compareAndRemove(key, expected) {
      return serialized(() => {
        const current = intents.get(key);
        if (!matches(current, expected)) return { ok: false as const, current: current ?? null };
        intents.delete(key);
        return { ok: true as const };
      });
    },
    archiveAndRemove(key, expected, entry) {
      return serialized(() => {
        const current = intents.get(key);
        if (!matches(current, expected)) return { ok: false as const, current: current ?? null };
        // Archive + delete together — atomic, like the multi-store IDB tx.
        archive.push(entry);
        intents.delete(key);
        return { ok: true as const };
      });
    },
    listArchive() {
      return serialized(() => [...archive]);
    },
  };
}
