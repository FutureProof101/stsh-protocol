/**
 * Encrypted shield journal (Campaign B / L3a — brief §6, H6-3).
 *
 * The durable local record of every shield intent, persisted BEFORE the first
 * effectful call (approve/deposit) so an interrupted flow is always
 * recoverable from this device (§1.1 rule 4); the pool's P-REC recovery index
 * (L0-G) covers the fresh-device case.
 *
 * This module deliberately owns NO storage/crypto machinery: every write goes
 * through the ONE L4 write path — `PrincipalNoteCache.update(fn)` — inheriting
 * the transactional revision CAS (one IndexedDB read-check-write transaction),
 * principal scoping, epoch binding and Argon2id/AES-GCM encryption at rest.
 * Journal mutations are pure state->state functions that SPREAD the incoming
 * state (noteCache invariant), so a CAS re-apply against another tab's write
 * preserves both sides' changes.
 *
 * Status model (see noteCache.ts `ShieldJournalEntryState`): `planned`,
 * `deposited` and `unknown` are ACTIVE; `failed` and `accepted` are terminal
 * (retained as an audit trail — never deleted here; L3b may prune `accepted`
 * entries once the scanner owns them).
 */

import type {
  CachedScanState,
  PrincipalNoteCache,
  ShieldApprovalState,
  ShieldJournalEntryState,
  ShieldJournalState,
} from "./noteCache";

/** A new shield batch was requested while an unresolved one exists. */
export class ShieldJournalBusyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShieldJournalBusyError";
  }
}

/** An illegal journal transition (unknown entry, or a from-status mismatch). */
export class ShieldJournalStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShieldJournalStateError";
  }
}

export type ShieldEntryStatus = ShieldJournalEntryState["status"];
export type ShieldApprovalStatus = ShieldApprovalState["status"];

const ACTIVE_ENTRY_STATUSES: readonly ShieldEntryStatus[] = ["planned", "deposited", "unknown"];
const ACTIVE_APPROVAL_STATUSES: readonly ShieldApprovalStatus[] = ["planned", "unknown"];

/** A shield-journal state with no history. */
export function emptyShieldJournal(): ShieldJournalState {
  return { entries: [], approval: null };
}

/** Whether any entry (or the approval) is still unresolved. */
export function hasActiveShieldIntent(journal: ShieldJournalState): boolean {
  return (
    journal.entries.some((e) => ACTIVE_ENTRY_STATUSES.includes(e.status)) ||
    (journal.approval !== null && ACTIVE_APPROVAL_STATUSES.includes(journal.approval.status))
  );
}

/** The active (non-terminal) entries, in insertion order. */
export function activeShieldEntries(journal: ShieldJournalState): ShieldJournalEntryState[] {
  return journal.entries.filter((e) => ACTIVE_ENTRY_STATUSES.includes(e.status));
}

/** Fields of a fresh batch entry — status is forced to `planned` on insert. */
export type NewShieldEntry = Omit<
  ShieldJournalEntryState,
  "status" | "dispatchedAtNs" | "successObserved" | "poolStatus" | "failureReason"
>;

/** Fields of a fresh approval intent — status is forced to `planned` on insert. */
export type NewShieldApproval = Omit<ShieldApprovalState, "status" | "blockIndex" | "failureReason">;

export interface EntryPatch {
  poolStatus?: string;
  failureReason?: string;
}

function journalOf(state: CachedScanState): ShieldJournalState {
  return state.shieldJournal ?? emptyShieldJournal();
}

function withJournal(state: CachedScanState, journal: ShieldJournalState): CachedScanState {
  // Spread: preserve notes/lastScannedIndex/future fields (noteCache invariant).
  return { ...state, shieldJournal: journal };
}

/** The journal surface the shield flow consumes (mock-testable). */
export interface ShieldJournalApi {
  read(): Promise<ShieldJournalState>;
  beginBatch(entries: NewShieldEntry[], approval: NewShieldApproval): Promise<void>;
  setApprovalStatus(
    from: readonly ShieldApprovalStatus[],
    to: ShieldApprovalStatus,
    patch?: { blockIndex?: string; failureReason?: string },
  ): Promise<void>;
  transitionEntry(
    commitmentHex: string,
    from: readonly ShieldEntryStatus[],
    to: ShieldEntryStatus,
    patch?: EntryPatch,
  ): Promise<void>;
  claimEntryDispatch(commitmentHex: string, atNs: string): Promise<boolean>;
  recordDepositSuccess(commitmentHex: string): Promise<void>;
  notePoolStatus(commitmentHex: string, poolStatus: string): Promise<void>;
  importEntry(entry: ShieldJournalEntryState): Promise<boolean>;
}

/**
 * Typed shield-journal API over an UNLOCKED, session-bound PrincipalNoteCache.
 * Construction does not touch storage; every method call re-checks the cache's
 * lock/epoch state via the cache itself (a locked or stale cache throws
 * CacheSessionStaleError from `update`/`load`).
 */
export class ShieldJournal implements ShieldJournalApi {
  constructor(private readonly cache: PrincipalNoteCache) {}

  /** Decrypt and return the current journal (read-only snapshot). */
  async read(): Promise<ShieldJournalState> {
    return journalOf(await this.cache.load());
  }

  /**
   * Persist a fresh batch: all entries (status `planned`) AND the approval
   * intent, in ONE atomic write — the caller may treat its resolution as
   * "persisted and confirmed written" (§1.1 rule 4) and only then submit.
   *
   * Refuses (ShieldJournalBusyError) while ANY previous intent is unresolved:
   * concurrent batches would race one ICRC-2 allowance. Refuses a duplicate
   * commitment outright (fresh CSPRNG nonces make one a derivation bug).
   */
  async beginBatch(entries: NewShieldEntry[], approval: NewShieldApproval): Promise<void> {
    if (entries.length === 0) {
      throw new ShieldJournalStateError("refusing to begin an empty shield batch");
    }
    await this.cache.update((state) => {
      const journal = journalOf(state);
      if (hasActiveShieldIntent(journal)) {
        throw new ShieldJournalBusyError(
          "an unresolved shield intent exists for this account — reconcile it before starting a new shield",
        );
      }
      const known = new Set(journal.entries.map((e) => e.commitmentHex));
      for (const entry of entries) {
        if (known.has(entry.commitmentHex)) {
          throw new ShieldJournalStateError(
            `duplicate note commitment in shield journal: ${entry.commitmentHex}`,
          );
        }
        known.add(entry.commitmentHex);
      }
      return withJournal(state, {
        entries: [...journal.entries, ...entries.map((e) => ({ ...e, status: "planned" as const }))],
        approval: { ...approval, status: "planned" as const },
      });
    });
  }

  /**
   * Guarded approval transition. Idempotent when the approval already carries
   * `to` (a CAS re-apply or a concurrent settle); otherwise the current status
   * must be in `from`.
   */
  async setApprovalStatus(
    from: readonly ShieldApprovalStatus[],
    to: ShieldApprovalStatus,
    patch: { blockIndex?: string; failureReason?: string } = {},
  ): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      if (journal.approval === null) {
        throw new ShieldJournalStateError("no approval intent exists to transition");
      }
      if (journal.approval.status === to) return state; // idempotent
      if (!from.includes(journal.approval.status)) {
        throw new ShieldJournalStateError(
          `approval is '${journal.approval.status}', expected one of [${from.join(", ")}] -> '${to}'`,
        );
      }
      return withJournal(state, {
        ...journal,
        approval: { ...journal.approval, ...patch, status: to },
      });
    });
  }

  /**
   * Guarded entry transition by commitment. Idempotent when the entry already
   * carries `to`; otherwise the current status must be in `from`.
   */
  async transitionEntry(
    commitmentHex: string,
    from: readonly ShieldEntryStatus[],
    to: ShieldEntryStatus,
    patch: EntryPatch = {},
  ): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.commitmentHex === commitmentHex);
      if (index === -1) {
        throw new ShieldJournalStateError(`unknown shield-journal entry: ${commitmentHex}`);
      }
      const entry = journal.entries[index];
      if (entry.status === to) return state; // idempotent
      if (!from.includes(entry.status)) {
        throw new ShieldJournalStateError(
          `entry ${commitmentHex} is '${entry.status}', expected one of [${from.join(", ")}] -> '${to}'`,
        );
      }
      const entries = [...journal.entries];
      entries[index] = { ...entry, ...patch, status: to };
      return withJournal(state, { ...journal, entries });
    });
  }

  /**
   * The EXCLUSIVE pre-wire dispatch claim (re-review round-2 Critical): a
   * caller may put a shield_deposit on the wire ONLY if this returns true.
   * The claim succeeds solely for a `planned` entry with NO dispatch marker —
   * it transitions `planned -> unknown` and stamps `dispatchedAtNs` in the
   * same atomic CAS write. Any already-dispatched (or otherwise
   * non-claimable) entry returns FALSE with the state untouched, so two tabs
   * racing the same planned entry resolve to exactly ONE dispatcher — the
   * transactional revision CAS is the arbiter. (A lost CAS re-applies the
   * closure against the winner's state, where the marker is already present,
   * and correctly reports false.)
   */
  async claimEntryDispatch(commitmentHex: string, atNs: string): Promise<boolean> {
    let claimed = false;
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.commitmentHex === commitmentHex);
      if (index === -1) {
        throw new ShieldJournalStateError(`unknown shield-journal entry: ${commitmentHex}`);
      }
      const entry = journal.entries[index];
      if (entry.status !== "planned" || entry.dispatchedAtNs !== undefined) {
        claimed = false; // someone else holds (or held) the dispatch claim
        return state;
      }
      claimed = true;
      const entries = [...journal.entries];
      entries[index] = { ...entry, status: "unknown" as const, dispatchedAtNs: atNs };
      return withJournal(state, { ...journal, entries });
    });
    return claimed;
  }

  /**
   * Monotonic deposit-success CAS (finding 3): merge the `successObserved`
   * marker whatever concurrent settlement did to the status. Upgrades
   * planned/unknown -> deposited; leaves deposited/accepted alone (NEVER
   * downgrades a terminal/later state); REJECTS a conflicting `failed` entry
   * (a definite-failure record receiving an Ok is an invariant violation).
   * The marker itself is never cleared once set.
   */
  async recordDepositSuccess(commitmentHex: string): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.commitmentHex === commitmentHex);
      if (index === -1) {
        throw new ShieldJournalStateError(`unknown shield-journal entry: ${commitmentHex}`);
      }
      const entry = journal.entries[index];
      if (entry.status === "failed") {
        throw new ShieldJournalStateError(
          `entry ${commitmentHex} is 'failed' but a shield_deposit Ok was observed — ` +
            "conflicting settlement; refusing to merge (operator attention)",
        );
      }
      const nextStatus =
        entry.status === "planned" || entry.status === "unknown"
          ? ("deposited" as const)
          : entry.status; // deposited stays; accepted is never downgraded
      if (entry.successObserved === true && entry.status === nextStatus) {
        return state; // fully applied already — idempotent
      }
      const entries = [...journal.entries];
      entries[index] = { ...entry, status: nextStatus, successObserved: true };
      return withJournal(state, { ...journal, entries });
    });
  }

  /** Record the last observed pool status without changing the entry status. */
  async notePoolStatus(commitmentHex: string, poolStatus: string): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.commitmentHex === commitmentHex);
      if (index === -1) {
        throw new ShieldJournalStateError(`unknown shield-journal entry: ${commitmentHex}`);
      }
      if (journal.entries[index].poolStatus === poolStatus) return state;
      const entries = [...journal.entries];
      entries[index] = { ...entries[index], poolStatus };
      return withJournal(state, { ...journal, entries });
    });
  }

  /**
   * Fresh-device merge (L0-G): import an entry rebuilt from the pool's
   * recovery index + decrypted payload. No-op (returns false) when the
   * commitment is already journaled on this device.
   */
  async importEntry(entry: ShieldJournalEntryState): Promise<boolean> {
    let imported = false;
    await this.cache.update((state) => {
      const journal = journalOf(state);
      if (journal.entries.some((e) => e.commitmentHex === entry.commitmentHex)) {
        imported = false;
        return state;
      }
      imported = true;
      return withJournal(state, { ...journal, entries: [...journal.entries, { ...entry }] });
    });
    return imported;
  }
}
