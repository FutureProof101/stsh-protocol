/**
 * Encrypted spend journal (Campaign B / L3c — §10, H6-3).
 *
 * The durable local record of every spend intent, written atomically WITH the
 * input-note lock (spendable → pending) in ONE `PrincipalNoteCache.update`
 * BEFORE proof generation or any wire call — no interval exists where a
 * durable intent exists without the note locked, or the note is locked
 * without its recovery envelope. The pool inserts its OWN recovery entry
 * (H6-3); this journal is the wallet-side record (§10.1/§10.2 recovery).
 *
 * Authority model (ruled): a QUERY result (advisory get_spend_status) NEVER
 * archives, unlocks, evicts, or adds change — it only drives the
 * update-validated path. Only an authoritative UPDATE Ok (private_spend /
 * retry_private_spend_payout / reconciliation) performs the permanent
 * transition:
 *   - private_spend Ok (fresh or same-intent replay): input → spent, entry →
 *     finalized (idempotent transitions). CHANGE ACTIVATION IS EXCLUSIVELY
 *     THE L3b VALIDATED SCANNER'S JOB — the scanner re-derives and validates
 *     the output from the tree (deduped by leaf index); nothing is ever
 *     inserted from a query, a replay, or this journal directly.
 *   - retry_private_spend_payout Ok: the parent nullifier is ALREADY spent
 *     (registry finality) — the input is marked/retained spent, never
 *     unlocked; change inserted exactly once when local output material
 *     exists; on a fresh device without it, the entry records completion and
 *     the SCANNER recovers the encrypted output from the tree (never
 *     fabricated).
 *   - A never-dispatched intent (status planned, no dispatchedAtNs) may be
 *     archived + the note restored — the ONLY unlock path.
 *   - A pool ADMISSION refusal (`VerifierUnavailable("SPEND_ADMISSION;…")`,
 *     WALLET-V12 E-2(c), Addendum 1a) is an update Err that wrote NO pool
 *     record. It performs NO journal transition: the entry stays `dispatched`
 *     with the note locked, and recovery retries the SAME spend_id
 *     byte-identically (`replaySameIntent`) after retry_after_ns — never a
 *     fresh id for this refusal class, never an archive/unlock. A fresh id
 *     (§10.2, `recordCollisionRetry`) is minted only after a same-id retry is
 *     answered `DuplicateSpendId`. E-1: when such a refusal masks an
 *     already-finalized replay, the advisory `get_spend_status` may change the
 *     COPY shown, never this state.
 *
 * Every mutation is a pure state->state function that SPREADS the incoming
 * state (noteCache invariant) so a CAS re-apply preserves both sides.
 */

import type {
  CachedScanState,
  PrincipalNoteCache,
  SpendEntryStatus,
  SpendJournalEntryState,
  SpendJournalState,
} from "./noteCache";
import { noteLifecycle } from "./noteCache";

export type { SpendEntryStatus, SpendJournalEntryState } from "./noteCache";

/** An illegal spend-journal transition (unknown entry, or a from-status mismatch). */
export class SpendJournalStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpendJournalStateError";
  }
}

export function emptySpendJournal(): SpendJournalState {
  return { entries: [] };
}

function journalOf(state: CachedScanState): SpendJournalState {
  return state.spendJournal ?? emptySpendJournal();
}

function withJournal(state: CachedScanState, journal: SpendJournalState): CachedScanState {
  return { ...state, spendJournal: journal };
}

export type NewSpendEntry = Omit<SpendJournalEntryState, "status" | "dispatchedAtNs" | "failureReason">;

/** The typed spend-journal surface (mock-testable). */
export class SpendJournal {
  constructor(private readonly cache: PrincipalNoteCache) {}

  async read(): Promise<SpendJournalState> {
    return journalOf(await this.cache.load());
  }

  async find(spendId: string): Promise<SpendJournalEntryState | null> {
    const journal = await this.read();
    return journal.entries.find((e) => e.spendId === spendId) ?? null;
  }

  /**
   * THE atomic journal-plus-lock transition (Critical contract): in ONE
   * cache update, persist the spend intent (status `planned`) AND transition
   * the input note spendable → pending. The CAS resolution is "persisted and
   * confirmed written" — only then may proof generation or any wire call run.
   * The input must be `spendable` with complete v2 material (nonce,
   * commitment, nullifier present).
   */
  async beginSpend(inputLeafIndex: bigint, entry: NewSpendEntry): Promise<void> {
    await this.cache.update((state) => {
      const noteIndex = state.notes.findIndex((n) => n.leafIndex === inputLeafIndex);
      if (noteIndex === -1) {
        throw new SpendJournalStateError(`spend input note at leaf ${inputLeafIndex} is not in the cache`);
      }
      const note = state.notes[noteIndex];
      if (noteLifecycle(note) !== "spendable") {
        throw new SpendJournalStateError(
          `spend input note at leaf ${inputLeafIndex} is '${noteLifecycle(note)}', not spendable`,
        );
      }
      if (note.nonce === undefined || note.commitment === undefined || note.nullifier === undefined) {
        throw new SpendJournalStateError(
          `spend input note at leaf ${inputLeafIndex} has incomplete v2 material`,
        );
      }
      const journal = journalOf(state);
      if (journal.entries.some((e) => e.spendId === entry.spendId)) {
        throw new SpendJournalStateError(`duplicate spend_id in journal: ${entry.spendId}`);
      }
      const notes = [...state.notes];
      notes[noteIndex] = { ...note, state: "pending" };
      return withJournal(
        { ...state, notes },
        { entries: [...journal.entries, { ...entry, status: "planned" as const }] },
      );
    });
  }

  /**
   * Mark the intent dispatched (sets dispatchedAtNs ONCE, immediately before
   * the first private_spend wire attempt). planned-only transition.
   */
  async markDispatched(spendId: string, atNs: string): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.spendId === spendId);
      if (index === -1) throw new SpendJournalStateError(`unknown spend-journal entry: ${spendId}`);
      const entry = journal.entries[index];
      if (entry.status !== "planned") {
        throw new SpendJournalStateError(
          `entry ${spendId} is '${entry.status}', expected 'planned' before dispatch`,
        );
      }
      const entries = [...journal.entries];
      entries[index] = { ...entry, status: "dispatched" as const, dispatchedAtNs: atNs };
      return withJournal(state, { ...journal, entries });
    });
  }

  /**
   * The ONLY unlock path: archive a NEVER-DISPATCHED intent and restore the
   * input note to spendable (when its index is known), atomically. Refuses a
   * dispatched intent — once dispatched, no local transition may unlock
   * (recovery is update-validated). A null index (recovery import) archives
   * the entry without touching any note.
   */
  async archiveNeverDispatched(spendId: string, inputLeafIndex: bigint | null, reason: string): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.spendId === spendId);
      if (index === -1) throw new SpendJournalStateError(`unknown spend-journal entry: ${spendId}`);
      const entry = journal.entries[index];
      if (entry.status !== "planned") {
        throw new SpendJournalStateError(
          `entry ${spendId} is '${entry.status}' — a dispatched intent can never be unlocked locally`,
        );
      }
      const entries = [...journal.entries];
      entries[index] = { ...entry, status: "failed" as const, failureReason: reason };
      const notes = [...state.notes];
      if (inputLeafIndex !== null) {
        const noteIndex = state.notes.findIndex((n) => n.leafIndex === inputLeafIndex);
        if (noteIndex !== -1 && state.notes[noteIndex].state === "pending") {
          notes[noteIndex] = { ...state.notes[noteIndex], state: "spendable" };
        }
      }
      return withJournal({ ...state, notes }, { ...journal, entries });
    });
  }

  /**
   * Persist the COMPLETE final request (with proof bytes) into a planned
   * entry — the byte-identical replay material for §10.1 recovery. Only a
   * never-dispatched entry may be updated (the dispatched request is frozen).
   */
  async persistFinalRequest(spendId: string, requestJson: string): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.spendId === spendId);
      if (index === -1) throw new SpendJournalStateError(`unknown spend-journal entry: ${spendId}`);
      const entry = journal.entries[index];
      if (entry.status !== "planned") {
        throw new SpendJournalStateError(
          `entry ${spendId} is '${entry.status}' — the final request can only be persisted while never-dispatched`,
        );
      }
      const entries = [...journal.entries];
      entries[index] = { ...entry, requestJson };
      return withJournal(state, { ...journal, entries });
    });
  }

  /**
   * Authoritative completion (private_spend Ok — fresh or same-intent replay):
   * entry → finalized, and — ONLY when the input leaf index is KNOWN and the
   * cached note at that index carries THIS entry's nullifier — the input →
   * spent (atomically). An unknown index (fresh-device import) mutates NO note:
   * recovery material is retained; the scanner owns note-state changes.
   */
  async finalizeFromSpendOk(spendId: string, inputLeafIndex: bigint | null): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.spendId === spendId);
      if (index === -1) throw new SpendJournalStateError(`unknown spend-journal entry: ${spendId}`);
      const entry = journal.entries[index];
      const entries = [...journal.entries];
      entries[index] = { ...entry, status: "finalized" as const };
      const notes = [...state.notes];
      if (inputLeafIndex !== null) {
        const noteIndex = state.notes.findIndex((n) => n.leafIndex === inputLeafIndex);
        if (noteIndex !== -1) {
          const note = state.notes[noteIndex];
          const expectedNullifier = entry.nullifierHex;
          const noteNullifier =
            note.nullifier !== undefined
              ? [...note.nullifier].map((b) => b.toString(16).padStart(2, "0")).join("")
              : "";
          // STRICT binding: a non-empty 32-byte (64-hex) nullifier AND exact
          // equality are both required — unknown or nullifierless records
          // mutate NO note.
          if (
            expectedNullifier.length === 64 &&
            noteNullifier !== "" &&
            noteNullifier === expectedNullifier
          ) {
            notes[noteIndex] = { ...note, state: "spent" };
          }
        }
      }
      return withJournal({ ...state, notes }, { ...journal, entries });
    });
  }

  /**
   * Record a pool-observed payout obligation (advisory input — the status
   * change only; the input stays locked until the retry's UPDATE Ok).
   */
  async markPayoutPending(spendId: string, reason: string): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.spendId === spendId);
      if (index === -1) throw new SpendJournalStateError(`unknown spend-journal entry: ${spendId}`);
      const entries = [...journal.entries];
      entries[index] = { ...entries[index], status: "payout-pending" as const, failureReason: reason };
      return withJournal(state, { ...journal, entries });
    });
  }

  /**
   * Fresh-device import (P-REC, §10 gate): register a pool-reported active
   * spend with NO local output material. Typed `recovery-required` — the
   * input is NOT restored, change is NOT fabricated, and only the
   * update-validated path can complete it (the scanner recovers encrypted
   * outputs from the tree once they land). ATOMICALLY with the registration,
   * any cached note carrying the SAME nullifier is locked (spendable →
   * pending) — an active pool spend and a locally spendable input can never
   * coexist.
   */
  async importRecoveryRequired(entry: NewSpendEntry): Promise<boolean> {
    let imported = false;
    await this.cache.update((state) => {
      const journal = journalOf(state);
      if (journal.entries.some((e) => e.spendId === entry.spendId)) return state; // idempotent
      imported = true;
      // Lock any matching cached note (same nullifier) in the SAME update.
      const notes = entry.nullifierHex
        ? state.notes.map((n) => {
            const hex =
              n.nullifier !== undefined
                ? [...n.nullifier].map((b) => b.toString(16).padStart(2, "0")).join("")
                : "";
            return hex === entry.nullifierHex && n.state === "spendable"
              ? { ...n, state: "pending" as const }
              : n;
          })
        : state.notes;
      return withJournal(
        { ...state, notes },
        {
          entries: [...journal.entries, { ...entry, status: "recovery-required" as const }],
        },
      );
    });
    return imported;
  }

  /**
   * Id-collision bookkeeping (S-23b): mark the ORIGINAL entry as a failed
   * collision (retained, never erased) and register the FRESH-id attempt as a
   * new planned entry carrying the same intent under the new id. Both
   * attempts are retained; the fresh attempt carries `collisionOf` so a
   * second collision can NEVER loop into another fresh id.
   */
  async recordCollisionRetry(
    originalSpendId: string,
    newEntry: NewSpendEntry & { collisionOf: string },
  ): Promise<void> {
    await this.cache.update((state) => {
      const journal = journalOf(state);
      const index = journal.entries.findIndex((e) => e.spendId === originalSpendId);
      if (index === -1) throw new SpendJournalStateError(`unknown spend-journal entry: ${originalSpendId}`);
      if (journal.entries.some((e) => e.spendId === newEntry.spendId)) {
        throw new SpendJournalStateError(`collision-retry id already in journal: ${newEntry.spendId}`);
      }
      const entries = [...journal.entries];
      entries[index] = {
        ...entries[index],
        status: "failed" as const,
        failureReason: `spend_id collision — retried as ${newEntry.spendId}`,
      };
      entries.push({ ...newEntry, status: "planned" as const });
      return withJournal(state, { ...journal, entries });
    });
  }
}
