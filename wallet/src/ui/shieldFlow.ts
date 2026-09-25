/**
 * Shield flow orchestration (Campaign B / L3a — brief §6).
 *
 * `runShieldFlow` drives one shield batch end-to-end; `reconcileShieldJournal`
 * resolves interrupted batches (this device via the encrypted journal, a fresh
 * device via the pool's P-REC recovery index, L0-G); `revokeShieldAllowance`
 * clears a leftover ICRC-2 allowance.
 *
 * Load-bearing ordering (each is a lane non-negotiable, tested):
 *  1. C-VK-3: `assertCanisterConfig` runs BEFORE `fetchUserVetKey` and again
 *     AFTER it, before any derived material is used. Failure hard-aborts.
 *  2. C-DOM-2: `assertDeploymentBinding` fails closed pre-flight and yields
 *     the deployment-config hash every `shield_deposit` carries; the pool's
 *     update-side gate is the authority.
 *  3. Fee snapshot fails CLOSED on query failure or an unknown fee-model
 *     version (a valid 0 fee proceeds); it is re-checked after the approve and
 *     any drift ABORTS the batch before a deposit submits — never guess.
 *  4. The journal batch (all entries + the approval envelope) is persisted and
 *     confirmed in ONE atomic write BEFORE the first effectful call.
 *  5. `icrc2_approve` always carries `expected_allowance` (CAS) and a stable
 *     `created_at_time` persisted in the journal, so a lost response retries
 *     byte-for-byte and dedups — never a blind or double approve.
 *  6. Reconcile checks the pool's deposit record BEFORE any resubmission; a
 *     resubmit of the same commitment cannot double-pull (the pool writes the
 *     commitment-keyed record before its first await and rejects duplicates).
 *
 * Session semantics (§1.1): journal writes go through the epoch-bound cache —
 * after logout they throw CacheSessionStaleError and the flow dies without
 * committing; the pool record + recovery index keep the operation recoverable.
 */

import { Principal } from "@dfinity/principal";

import type {
  PoolCanister,
  PoolDepositStatus,
  PoolPendingDeposit,
  ShieldFeeParams,
} from "../actors/pool";
import { PoolCallError } from "../actors/pool";
import type { TokenCanister, TokenMutationCanister } from "../actors/token";
import {
  sameShieldFeeBasis,
  shieldDepositPreview,
  type ShieldDepositPreview,
} from "../crypto/fees";
import {
  createShieldNote,
  decomposeAmount,
  deriveNoteSecretsV2,
  freshNoteNonce,
  noteFromBytesV2,
  noteToBytesV2,
  LegacyNoteFormatUnsupportedError,
} from "../crypto/notes";
import type { FetchKeys } from "../crypto/vetkeys";
import {
  assertCanisterConfig,
  encryptNotePayload,
  fetchUserVetKey,
  masterNoteSecret,
  tryDecryptNotePayload,
  type VetkeysCanister,
} from "../crypto/vetkeys";
import { PRODUCTION_VETKD_KEY_NAME, type WalletConfig } from "../session/config";
import { assertDeploymentBinding, type DeploymentGuardConfig } from "../session/domainGuard";
import type { ShieldJournalApi } from "../storage/journal";
import type { SubmissionDelay } from "./submissionDelay";
import type { OperationLease } from "../actors/authorization";
import type { ShieldJournalEntryState } from "../storage/noteCache";
import { bytesToHex, hexToBytes } from "../storage/transferJournal";

// ── Typed failure ────────────────────────────────────────────────────────────

export type ShieldAbortStage =
  | "vetkd-config"
  | "deployment-binding"
  | "fee-snapshot"
  | "fee-stale"
  | "approve"
  | "approve-unknown"
  | "manual-resolution";

/** A shield abort with the stage that failed closed (for status + tests). */
export class ShieldAbortError extends Error {
  constructor(
    readonly stage: ShieldAbortStage,
    message: string,
  ) {
    super(message);
    this.name = "ShieldAbortError";
  }
}

// ── Dependencies ─────────────────────────────────────────────────────────────

export interface ShieldFlowDeps {
  /** "production" pins the vetKD key name; "local" requires an explicit one. */
  policyKind: "local" | "production";
  config: WalletConfig;
  principal: Principal;
  /** Anonymous read actor — public `icrc1_fee` only. */
  tokenRead: TokenCanister;
  /** Identity-bound: `icrc2_approve` + the owned `icrc2_allowance` read (S-44). */
  tokenMutation: TokenMutationCanister;
  /** Identity-bound pool actor: shield mutation + depositor-gated reads (S-44). */
  pool: PoolCanister;
  /** Identity-bound vetkeys actor (`get_encrypted_vetkey` derives for caller). */
  vetkeys: VetkeysCanister;
  journal: ShieldJournalApi;
  nowNs(): bigint;
  /**
   * WL-2c, optional: the randomised submission delay. It runs at the TOP of
   * the operation, in front of step 0 — before the deployment binding, the
   * vetKey guard, the fee snapshot, the allowance read and the dedup
   * timestamp, so every one of them is evaluated AFTER the wait and none is
   * aged by it. Undefined (and the toggle OFF) means no wait at all.
   */
  submissionDelay?: SubmissionDelay;
  /**
   * WL-2b: the operation lease minted by the user gesture that started this
   * flow. The flow DRAWS a single-use token from it immediately before each
   * wire call — the count is known here, not at the gesture. Undefined only in
   * the pre-WL-2b unit harnesses.
   */
  lease?: OperationLease;
  onProgress?(message: string): void;
  /**
   * TEST SEAM ONLY — overrides the raw key fetch INSIDE the C-VK-3 guard
   * sandwich (config-before -> fetch -> config-after; the sandwich itself is
   * not bypassable). Production leaves this undefined = the real
   * `fetchUserVetKey` (transport-key + decrypt-and-verify).
   */
  fetchKeys?: FetchKeys;
}

/**
 * C-VK-3 key-name resolution: production pins `"key_1"`; a local/test build
 * must configure its test key EXPLICITLY (VITE_VETKD_KEY_NAME) — never a
 * default, never inferred.
 */
export function resolveExpectedVetkdKeyName(deps: {
  policyKind: "local" | "production";
  config: Pick<WalletConfig, "vetkdKeyName">;
}): string {
  if (deps.policyKind === "production") return PRODUCTION_VETKD_KEY_NAME;
  const configured = deps.config.vetkdKeyName?.trim();
  if (configured === undefined || configured === "") {
    throw new ShieldAbortError(
      "vetkd-config",
      "no vetKD key name is configured for this local build (VITE_VETKD_KEY_NAME) — " +
        "the C-VK-3 guard requires an explicit key name; refusing to derive keys",
    );
  }
  return configured;
}

function guardConfig(deps: Pick<ShieldFlowDeps, "policyKind" | "config">): DeploymentGuardConfig {
  return {
    poolCanisterId: deps.config.poolCanisterId,
    tokenCanisterId: deps.config.tokenCanisterId,
    merkleCanisterId: deps.config.merkleCanisterId,
    nullifierCanisterId: deps.config.nullifierCanisterId,
    frozenPoolCanisterId: deps.config.frozenPoolCanisterId,
    enforceFrozenPool: deps.policyKind === "production",
  };
}

// ── Fee snapshot ─────────────────────────────────────────────────────────────

export interface ShieldFeeSnapshot {
  ledgerFee: bigint;
  params: ShieldFeeParams;
}

/**
 * Snapshot the live fee basis. Fails CLOSED on either query failing — a fee is
 * never substituted or guessed. A valid 0 from a healthy query is fine.
 * (`shieldDepositPreview` separately rejects an unknown fee-model version.)
 */
async function snapshotShieldFees(deps: ShieldFlowDeps): Promise<ShieldFeeSnapshot> {
  try {
    const [ledgerFee, params] = await Promise.all([
      deps.tokenRead.fee(),
      deps.pool.getGovernanceFeeParams(),
    ]);
    return { ledgerFee, params };
  } catch (err) {
    throw new ShieldAbortError(
      "fee-snapshot",
      `fee snapshot failed — aborting shield (fees are never guessed): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

// ── The C-VK-3-guarded key session ───────────────────────────────────────────

/**
 * The one sanctioned way this flow obtains key material: config guard BEFORE
 * the fetch, fetch, config guard AFTER — a mismatch at either point hard-aborts
 * before any derived material is used (C-VK-3).
 */
async function fetchGuardedVetKey(deps: ShieldFlowDeps) {
  const keyName = resolveExpectedVetkdKeyName(deps);
  try {
    await assertCanisterConfig(deps.vetkeys, keyName);
  } catch (err) {
    throw new ShieldAbortError(
      "vetkd-config",
      err instanceof Error ? err.message : String(err),
    );
  }
  const keys = await (deps.fetchKeys ?? fetchUserVetKey)(deps.vetkeys, deps.principal);
  try {
    await assertCanisterConfig(deps.vetkeys, keyName);
  } catch (err) {
    throw new ShieldAbortError(
      "vetkd-config",
      `vetkeys canister config changed during key fetch: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  return keys;
}

// ── Shield batch ─────────────────────────────────────────────────────────────

interface PreparedNote {
  commitment: Uint8Array;
  commitmentHex: string;
  nonce: Uint8Array;
  encryptedPayload: Uint8Array;
  preview: ShieldDepositPreview;
}

export interface ShieldFlowSummary {
  /** Entries whose covering root the pool accepted (terminal success). */
  accepted: number;
  /** Entries submitted and credited-or-pending (not yet root-accepted). */
  deposited: number;
  /** Entries needing reconciliation (ambiguous outcome). */
  unknown: number;
  /** Entries persisted but not submitted (resubmittable via reconcile). */
  planned: number;
  /** Entries that definitively failed. */
  failed: number;
  totalAllowance: bigint;
}

function summarize(entries: ShieldJournalEntryState[], totalAllowance: bigint): ShieldFlowSummary {
  const count = (status: ShieldJournalEntryState["status"]) =>
    entries.filter((e) => e.status === status).length;
  return {
    accepted: count("accepted"),
    deposited: count("deposited"),
    unknown: count("unknown"),
    planned: count("planned"),
    failed: count("failed"),
    totalAllowance,
  };
}

/** Map a live pool status onto the §6 reconcile table's journal consequence. */
function entryStatusForPool(status: PoolDepositStatus): ShieldJournalEntryState["status"] {
  switch (status.kind) {
    case "root-accepted":
      return "accepted";
    case "appended":
      return "deposited"; // credited, root pending — NOT terminal (§6)
    default:
      return "unknown"; // pre-append states need reconciliation/operator action
  }
}

export async function runShieldFlow(deps: ShieldFlowDeps, amount: bigint): Promise<ShieldFlowSummary> {
  const progress = deps.onProgress ?? (() => {});

  // WL-2c. The randomised submission delay, in FRONT of the whole operation.
  //
  // The shield's first STATE-CHANGING PUBLIC call is the ICRC-2 approve at
  // step 6 — not the deposit at step 8. Delaying only the deposit would leave
  // the operation's first public signal at the user's real action time and
  // would manufacture a cleaner approve->deposit pair than exists today, so
  // the wait goes here, where nothing live has been read yet:
  //
  //   * no precondition is aged, because none has run (steps 1-3, 5);
  //   * `createdAtTimeNs` — the ONE stable ICRC-2 dedup timestamp — is read at
  //     step 5, AFTER this wait, so it is exactly as fresh as it is today and
  //     the ledger's TooOld window is unchanged, not merely "acceptable";
  //   * steps 0-9 keep their order; this is a wait in front of the state
  //     machine, never an insertion into it.
  //
  // It throws (abandoning the operation) rather than returning if the user
  // cancels or the session ends during the wait — nothing has been submitted
  // at that point, by construction.
  await deps.submissionDelay?.run("shield");

  // 0. Fixed denominations only (anti-drift law #1) — throws before anything.
  const denominations = decomposeAmount(amount);

  // 1-2. C-VK-3 (pre + post around the fetch) and C-DOM-2 fail-closed guards.
  progress("Verifying deployment and key configuration…");
  const { hash } = await bindingOrAbort(deps);
  const { vetKey, verificationKey } = await fetchGuardedVetKey(deps);
  const master = masterNoteSecret(vetKey);

  // 3. Fee snapshot — fail closed, never guess.
  const fees = await snapshotShieldFees(deps);

  // 4. Derive + encrypt every note locally (no network, no state).
  progress(`Preparing ${denominations.length} note${denominations.length === 1 ? "" : "s"}…`);
  const prepared: PreparedNote[] = [];
  for (const denom of denominations) {
    const nonce = freshNoteNonce();
    const secrets = await deriveNoteSecretsV2(master, nonce);
    const note = await createShieldNote(denom, secrets);
    const preview = shieldDepositPreview(denom, fees.ledgerFee, fees.params);
    const encryptedPayload = encryptNotePayload(
      verificationKey,
      deps.principal,
      noteToBytesV2(note, nonce),
    );
    prepared.push({
      commitment: note.commitment,
      commitmentHex: bytesToHex(note.commitment),
      nonce,
      encryptedPayload,
      preview,
    });
  }
  const totalAllowance = prepared.reduce((sum, p) => sum + p.preview.totalPublicDebit, 0n);

  // 5. Journal EVERYTHING before the first effectful call (§1.1 rule 4). The
  //    approval envelope (CAS guard + stable dedup timestamp) is part of the
  //    same atomic write so a crashed approve can retry byte-for-byte.
  const poolPrincipal = principalOfPool(deps);
  const observed = await deps.tokenMutation.allowance(deps.principal, poolPrincipal);
  const createdAtTimeNs = deps.nowNs();
  await deps.journal.beginBatch(
    prepared.map((p) => ({
      commitmentHex: p.commitmentHex,
      denom: p.preview.denom.toString(10),
      nonceHex: bytesToHex(p.nonce),
      protoFee: p.preview.protocolFee.toString(10),
      ledgerFee: fees.ledgerFee.toString(10),
      encryptedPayloadHex: bytesToHex(p.encryptedPayload),
      createdAtNs: createdAtTimeNs.toString(10),
    })),
    {
      totalAllowance: totalAllowance.toString(10),
      expectedAllowance: observed.allowance.toString(10),
      createdAtTimeNs: createdAtTimeNs.toString(10),
      ledgerFee: fees.ledgerFee.toString(10),
    },
  );

  // 6. Approve — expected-allowance CAS + stable created_at_time (never blind).
  progress("Approving the exact batch allowance…");
  await performApprove(deps, {
    amount: totalAllowance,
    expectedAllowance: observed.allowance,
    createdAtTime: createdAtTimeNs,
    fee: fees.ledgerFee,
    spender: poolPrincipal,
  });

  // 7. Fee-staleness re-check (BOTH bases: ledger fee + governance params) —
  //    any drift between snapshot and submission aborts BEFORE a deposit is
  //    submitted (fail closed, never guess).
  await recheckFeeBasisOrAbort(deps, fees);

  // 8. Submit deposits sequentially; stop at the first non-Ok (remaining stay
  //    `planned` — resubmittable through reconcile after a status check).
  for (const [index, note] of prepared.entries()) {
    progress(`Shielding note ${index + 1} of ${prepared.length}…`);
    const proceed = await submitDeposit(deps, hash, {
      commitmentHex: note.commitmentHex,
      noteCommitment: note.commitment,
      encryptedPayload: note.encryptedPayload,
      publicAmount: note.preview.denom,
    });
    if (!proceed) break;
  }

  // 9. One post-batch reconcile pass: poll statuses (a bare shield_deposit Ok
  //    is NEVER treated as root-accepted — §6), no resubmissions.
  await pollJournalStatuses(deps);

  const journal = await deps.journal.read();
  return summarize(journal.entries, totalAllowance);
}

async function bindingOrAbort(deps: ShieldFlowDeps): Promise<{ hash: Uint8Array }> {
  try {
    const { hash } = await assertDeploymentBinding(guardConfig(deps));
    return { hash };
  } catch (err) {
    throw new ShieldAbortError(
      "deployment-binding",
      err instanceof Error ? err.message : String(err),
    );
  }
}

function principalOfPool(deps: Pick<ShieldFlowDeps, "config">): Principal {
  // assertDeploymentBinding already validated this principal; parse is cheap.
  return Principal.fromText(deps.config.poolCanisterId);
}

interface ApproveIntent {
  amount: bigint;
  expectedAllowance: bigint;
  createdAtTime: bigint;
  fee: bigint;
  spender: Principal;
}

/**
 * Wire the approve and settle the journal's approval record. The attempt
 * marker is persisted BEFORE the wire call (finding 2): a crash after dispatch
 * leaves the approval durably `unknown` — never a live allowance masquerading
 * as `planned`. Definite non-execution fails the whole batch (entries ->
 * failed); a transport-unknown leaves the persisted envelope for a
 * byte-identical retry in reconcile.
 */
async function performApprove(deps: ShieldFlowDeps, intent: ApproveIntent): Promise<void> {
  // Pre-wire: from here the outcome may be ambiguous and must survive a crash.
  await deps.journal.setApprovalStatus(["planned"], "unknown");
  let outcome;
  try {
    outcome = await deps.tokenMutation.approve(
      {
        spender: intent.spender,
        amount: intent.amount,
        expectedAllowance: intent.expectedAllowance,
        createdAtTime: intent.createdAtTime,
        fee: intent.fee,
      },
      // WL-2b: one single-use token, drawn HERE — immediately before the wire
      // call, which is where this operation knows it is about to make one.
      deps.lease?.draw("approve"),
    );
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    // The pre-wire marker already persisted the ambiguity; just annotate.
    throw new ShieldAbortError(
      "approve-unknown",
      "the approve outcome is unknown (connection lost mid-call). The saved envelope will be " +
        "retried byte-for-byte on reconcile — it cannot double-approve. " +
        `(${reason})`,
    );
  }
  switch (outcome.kind) {
    case "ok":
      await deps.journal.setApprovalStatus(["unknown"], "approved", {
        blockIndex: outcome.blockIndex.toString(10),
      });
      return;
    case "duplicate":
      await deps.journal.setApprovalStatus(["unknown"], "approved", {
        blockIndex: outcome.duplicateOf.toString(10),
      });
      return;
    case "allowance-changed":
      await failBatchAtApprove(
        deps,
        `the allowance changed concurrently (live: ${outcome.currentAllowance}); the CAS ` +
          "protected against approving over it — nothing was approved",
      );
      return; // unreachable (failBatchAtApprove throws)
    case "too-old":
      await failBatchAtApprove(
        deps,
        "the ledger rejected the approve as too old before it executed (check this device's clock)",
      );
      return;
    case "rejected":
      await failBatchAtApprove(deps, `the ledger rejected the approve: ${outcome.reason}`);
      return;
  }
}

/** Definite approve failure: nothing executed — fail the approval + all planned entries. */
async function failBatchAtApprove(deps: ShieldFlowDeps, reason: string): Promise<never> {
  // The pre-wire marker moved the approval to `unknown`; a definite ledger
  // rejection settles it as failed.
  await deps.journal.setApprovalStatus(["unknown", "planned"], "failed", { failureReason: reason });
  const journal = await deps.journal.read();
  for (const entry of journal.entries) {
    if (entry.status === "planned") {
      await deps.journal.transitionEntry(entry.commitmentHex, ["planned"], "failed", {
        failureReason: `approve failed: ${reason}`,
      });
    }
  }
  throw new ShieldAbortError("approve", `shield aborted — ${reason}`);
}

/**
 * Post-approve staleness gate (finding 4): re-verify BOTH fee bases — the
 * governance parameters AND the live ledger fee — before any deposit submits.
 * Any drift or query failure aborts; the safe exit is `cancelPlannedShield`
 * (fail the never-dispatched entries, then revoke under CAS).
 */
async function recheckFeeBasisOrAbort(deps: ShieldFlowDeps, snapshot: ShieldFeeSnapshot): Promise<void> {
  let live: ShieldFeeSnapshot;
  try {
    const [ledgerFee, params] = await Promise.all([
      deps.tokenRead.fee(),
      deps.pool.getGovernanceFeeParams(),
    ]);
    live = { ledgerFee, params };
  } catch (err) {
    throw new ShieldAbortError(
      "fee-stale",
      "could not re-verify the fee basis after approval — aborting before any deposit " +
        `(entries stay planned; use "cancel shield" to fail them and revoke the allowance): ${
          err instanceof Error ? err.message : String(err)
        }`,
    );
  }
  if (!sameShieldFeeBasis(snapshot.params, live.params) || snapshot.ledgerFee !== live.ledgerFee) {
    throw new ShieldAbortError(
      "fee-stale",
      "the fee basis (ledger fee or pool fee parameters) changed between the snapshot and " +
        "submission — aborting before any deposit (fail closed, never guess). Entries stay " +
        'planned; use "cancel shield" to fail them and revoke the allowance, then re-plan.',
    );
  }
}

interface DepositSubmission {
  commitmentHex: string;
  noteCommitment: Uint8Array;
  encryptedPayload: Uint8Array;
  publicAmount: bigint;
}

/**
 * Submit one deposit and settle its journal entry. Returns whether the batch
 * should continue to the next note.
 *
 * Ordering (finding 1/2 discipline, round-2 exclusivity): the DISPATCH CLAIM
 * is an EXCLUSIVE CAS acquired before the wire call — no claim, no wire, so
 * two tabs racing the same planned entry produce exactly one shield_deposit
 * dispatch. From the claim write on, the entry is `unknown` (dispatched,
 * possibly executed) and is never auto-resubmitted. An observed Ok is merged
 * via the monotonic success CAS (finding 3), which survives a concurrent
 * tab's promotion of the same entry. The Ok payload is the pool's credited
 * `private_balance` — evidence of success, NOT a ledger block/receipt
 * (finding 6) — so only `successObserved` is recorded.
 */
async function submitDeposit(
  deps: ShieldFlowDeps,
  deploymentConfigHash: Uint8Array,
  submission: DepositSubmission,
): Promise<boolean> {
  const claimed = await deps.journal.claimEntryDispatch(
    submission.commitmentHex,
    deps.nowNs().toString(10),
  );
  if (!claimed) {
    // Another actor (tab/reconciler) holds the dispatch claim for this entry
    // — its outcome belongs to that dispatcher; putting a second call on the
    // wire is forbidden.
    return false;
  }
  try {
    await deps.pool.shieldDeposit(
      {
        noteCommitment: submission.noteCommitment,
        encryptedPayload: submission.encryptedPayload,
        publicAmount: submission.publicAmount,
        expectedDeploymentConfigHash: deploymentConfigHash,
      },
      // One token per deposit, drawn inside the loop: the note count is known
      // here, not at the gesture that minted the lease.
      deps.lease?.draw("shieldDeposit"),
    );
    await deps.journal.recordDepositSuccess(submission.commitmentHex);
    return true;
  } catch (err) {
    if (err instanceof PoolCallError) {
      // A decoded rejection is NOT always "nothing happened" (the pool may
      // have pulled the transfer and failed later) — probe the record before
      // deciding between definite failure and reconcile-needed.
      let record: PoolPendingDeposit | null;
      try {
        record = await deps.pool.getDepositStatus(submission.noteCommitment);
      } catch {
        return false; // stays 'unknown' via the pre-wire marker
      }
      if (record === null) {
        // A decoded Err with no record is definitive non-execution: the pool
        // writes its record BEFORE any transfer, so nothing was pulled.
        await deps.journal.transitionEntry(submission.commitmentHex, ["unknown"], "failed", {
          failureReason: err.message,
        });
      } else {
        await deps.journal.notePoolStatus(submission.commitmentHex, record.status.kind);
      }
      return false;
    }
    // Transport-unknown: the deposit may have executed — the pre-wire marker
    // already persisted the ambiguity; reconcile resolves it via the record.
    return false;
  }
}

/**
 * F4-1 absence-probe markers — the commitment hexes for which the single
 * `get_deposit_status` disambiguation has ALREADY fired while the entry was
 * absent from the caller-scoped listing.
 *
 * In-memory and module-scoped by design: no timer, no expiry, no persistence.
 * A page reload re-instantiates this module and so clears every marker, and
 * that is the intended cost rather than a leak — after a reload the wallet does
 * not know the outcome, so exactly one probe per absent entry is correct.
 */
const absenceProbed = new Set<string>();

/**
 * Model a page reload, which is the only thing that clears these markers in the
 * browser. Exists so the reload cost can be COUNTED in tests rather than argued.
 */
export function resetAbsenceProbeMarkersForReload(): void {
  absenceProbed.clear();
}

/** Page limit for the caller-scoped listing — matches the P-REC pager at :915. */
const ACTIVE_LISTING_PAGE_LIMIT = 100n;
/** Backstop so a pathological pager cannot spin forever; hitting it is INCOMPLETE. */
const ACTIVE_LISTING_MAX_PAGES = 1_000;

interface ActiveListing {
  /** commitmentHex → record, for the active deposits this caller holds. */
  readonly byCommitment: Map<string, PoolPendingDeposit>;
  /**
   * True ONLY when the listing was paged to cursor exhaustion. Absence is a
   * property of a COMPLETED listing, not of a partial one: a paging run that stopped
   * early (error, page cap, non-advancing cursor) cannot tell "not there" from
   * "not read far enough", so it classifies nothing.
   */
  readonly complete: boolean;
}

/** Page `list_my_active_deposits` to exhaustion. Sends NO commitment. */
async function readActiveDeposits(deps: ShieldFlowDeps): Promise<ActiveListing> {
  const byCommitment = new Map<string, PoolPendingDeposit>();
  let cursor: Uint8Array | null = null;
  let pages = 0;
  try {
    do {
      const page = await deps.pool.listMyActiveDeposits(cursor, ACTIVE_LISTING_PAGE_LIMIT);
      for (const record of page.deposits) {
        byCommitment.set(bytesToHex(record.noteCommitment), record);
      }
      const next = page.nextCursor;
      if (next !== null && cursor !== null && bytesToHex(next) === bytesToHex(cursor)) {
        return { byCommitment, complete: false }; // cursor did not advance
      }
      cursor = next;
      pages += 1;
    } while (cursor !== null && pages < ACTIVE_LISTING_MAX_PAGES);
  } catch {
    return { byCommitment, complete: false }; // advisory poll only
  }
  return { byCommitment, complete: cursor === null };
}

/**
 * Poll pool statuses for submitted entries; promote per the §6 table. No resubmits.
 *
 * F4-1 (selector-MINIMISED, not selector-free): the steady-state pass names no
 * commitment — it reads the depositor-gated listing and matches locally. A
 * commitment is sent only when a tracked entry is absent from a COMPLETE listing
 * and has not already been probed: one call per disappearance episode, plus one
 * per page reload. The four one-shot sites (:544, :673, :748, :1085) are
 * deliberately unchanged and still send their selector.
 *
 * Exported so the E6/E7/E7b/E7c call counts are measured against the real loop.
 */
export async function pollJournalStatuses(deps: ShieldFlowDeps): Promise<void> {
  const journal = await deps.journal.read();
  const listing = await readActiveDeposits(deps);
  for (const entry of journal.entries) {
    if (entry.status !== "deposited" && entry.status !== "unknown") continue;

    const listed = listing.byCommitment.get(entry.commitmentHex);
    if (listed !== undefined) {
      absenceProbed.delete(entry.commitmentHex); // observed presence clears the marker
      await applyPoolStatus(deps, entry, listed.status);
      continue;
    }

    if (!listing.complete) continue; // partial listing classifies nothing
    if (absenceProbed.has(entry.commitmentHex)) continue; // already disambiguated

    let record: PoolPendingDeposit | null;
    try {
      record = await deps.pool.getDepositStatus(hexToBytes(entry.commitmentHex));
    } catch {
      continue; // no answer, so no marker — a later cycle retries the probe
    }
    absenceProbed.add(entry.commitmentHex);

    if (record === null) {
      // Not present, and NOT self-disambiguating: never-recorded and pruned both
      // produce `None`. Every entry reaching here was dispatched (`planned` is
      // filtered above), so the disposition is the conservative one: record the
      // observation and PROMOTE NOTHING. NEVER `accepted`; never silently
      // `failed`; and never a DEMOTION either — a `deposited` entry carries an
      // observed `shield_deposit` Ok plus a block index, and an absent record
      // (the expected shape after a terminal deposit is pruned) is not evidence
      // against it. Erasing that success marker is what the monotonic-CAS and
      // "never resubmits a vanished Ok" invariants exist to forbid. The
      // ambiguity is resolved through the manual `:1085` path.
      await deps.journal.notePoolStatus(entry.commitmentHex, "no-record");
      continue;
    }

    if (entryStatusForPool(record.status) !== "accepted") {
      // Still in flight: the absence was a false disappearance, so re-arm, and a
      // later genuine disappearance probes again.
      absenceProbed.delete(entry.commitmentHex);
    }
    await applyPoolStatus(deps, entry, record.status);
  }
}

async function applyPoolStatus(
  deps: ShieldFlowDeps,
  entry: ShieldJournalEntryState,
  status: PoolDepositStatus,
): Promise<void> {
  const target = entryStatusForPool(status);
  if (target === "accepted") {
    await deps.journal.transitionEntry(
      entry.commitmentHex,
      ["planned", "deposited", "unknown"],
      "accepted",
      { poolStatus: status.kind },
    );
  } else if (target === "deposited") {
    if (entry.status === "deposited") {
      await deps.journal.notePoolStatus(entry.commitmentHex, status.kind);
    } else {
      await deps.journal.transitionEntry(
        entry.commitmentHex,
        ["planned", "unknown"],
        "deposited",
        { poolStatus: status.kind },
      );
    }
  } else {
    // Pre-append states: keep/enter `unknown` with the observed status noted.
    if (entry.status === "unknown") {
      await deps.journal.notePoolStatus(entry.commitmentHex, status.kind);
    } else {
      await deps.journal.transitionEntry(
        entry.commitmentHex,
        ["planned", "deposited"],
        "unknown",
        { poolStatus: status.kind },
      );
    }
  }
}

// ── Reconcile ────────────────────────────────────────────────────────────────

export interface ReconcileOptions {
  /**
   * Whether reconcile may take effectful actions (resubmit a checked
   * commitment, retry the approve envelope, retry a pending commitment
   * append). False = observe/promote only.
   */
  resubmit: boolean;
}

export interface ReconcileReport {
  summary: ShieldFlowSummary;
  /** Human-readable notes for states needing operator/user attention. */
  attention: string[];
  /** Entries imported from the pool's recovery index (fresh device, L0-G). */
  importedFromPool: number;
}

export async function reconcileShieldJournal(
  deps: ShieldFlowDeps,
  options: ReconcileOptions,
): Promise<ReconcileReport> {
  const attention: string[] = [];

  // 1. Resolve an unknown approve first — deposits need the allowance.
  await reconcileApproval(deps, options, attention);

  // 2. Fresh-device import BEFORE per-entry work so imported entries get the
  //    same treatment (L0-G: the pool index is the cross-device locator).
  const importedFromPool = await importFromRecoveryIndex(deps, attention);

  // 3. Per-entry reconciliation from the authoritative pool record (§6 table).
  const journal = await deps.journal.read();
  const approvalApproved = journal.approval?.status === "approved";
  const approvalFailed = journal.approval?.status === "failed";
  let deploymentHash: Uint8Array | null = null;
  let liveFees: ShieldFeeSnapshot | null = null;
  for (const entry of journal.entries) {
    if (entry.status === "failed" || entry.status === "accepted") continue;

    // Roll a definite approve failure forward onto its planned entries — a
    // crash between the approval-failed write and the per-entry writes must
    // not strand a batch as forever-busy planned intents.
    if (entry.status === "planned" && approvalFailed) {
      await deps.journal.transitionEntry(entry.commitmentHex, ["planned"], "failed", {
        failureReason: "approve failed: rolled forward by reconcile",
      });
      continue;
    }

    let record: PoolPendingDeposit | null;
    try {
      record = await deps.pool.getDepositStatus(hexToBytes(entry.commitmentHex));
    } catch (err) {
      attention.push(
        `note ${shortHex(entry.commitmentHex)}: status query failed (${
          err instanceof Error ? err.message : String(err)
        }) — will retry on the next reconcile`,
      );
      continue;
    }

    if (record === null) {
      // FUND-SAFETY GATE (re-review finding 1): only an entry that was NEVER
      // DISPATCHED (`planned`, no dispatch marker) may be auto-resubmitted. A
      // dispatched entry with no record is genuinely ambiguous — the lost call
      // may have executed and its terminal record may since have been PRUNED,
      // in which case a resubmission would pull the tokens a second time (the
      // pruned record no longer blocks the pool's duplicate check). Ambiguity
      // is surfaced, never auto-resolved by re-pulling.
      // (terminal `accepted`/`failed` entries were skipped above)
      if (entry.successObserved === true || entry.status === "deposited") {
        attention.push(
          `note ${shortHex(entry.commitmentHex)}: a successful shield was observed but the pool ` +
            "record is gone — most likely pruned after acceptance; verify on-chain (never resubmitted)",
        );
        continue;
      }
      if (entry.dispatchedAtNs !== undefined || entry.status === "unknown") {
        attention.push(
          `note ${shortHex(entry.commitmentHex)}: dispatched with an ambiguous outcome and no ` +
            "pool record — NEVER auto-resubmitted (the lost call may have executed and been " +
            "pruned). Verify externally; resolve manually via abandon.",
        );
        continue;
      }
      // `planned` + never dispatched: this device never sent the call, so a
      // first submission is safe. Requires the approve to be settled AND the
      // PERSISTED fee basis to still hold live (finding 4 — a reconcile must
      // not submit under changed fees).
      if (!options.resubmit || !approvalApproved) continue;
      if (liveFees === null) {
        liveFees = await snapshotLiveFeesOrNote(deps, attention);
        if (liveFees === null) continue;
      }
      if (!feeBasisMatchesEntry(entry, liveFees)) {
        attention.push(
          `note ${shortHex(entry.commitmentHex)}: the fee basis changed since this intent was ` +
            'planned — not submitting. Use "cancel shield" to fail the planned intents and ' +
            "revoke the allowance, then re-plan.",
        );
        continue;
      }
      if (deploymentHash === null) {
        deploymentHash = (await bindingOrAbort(deps)).hash; // fresh C-DOM-2 gate
      }
      await submitDeposit(deps, deploymentHash, {
        commitmentHex: entry.commitmentHex,
        noteCommitment: hexToBytes(entry.commitmentHex),
        encryptedPayload: hexToBytes(entry.encryptedPayloadHex),
        publicAmount: BigInt(entry.denom),
      });
      continue;
    }

    // A record exists — drive the §6 status table.
    switch (record.status.kind) {
      case "transfer-pending":
        attention.push(
          `note ${shortHex(entry.commitmentHex)}: transfer outcome pending operator reconciliation`,
        );
        await applyPoolStatus(deps, entry, record.status);
        break;
      case "commitment-pending": {
        if (options.resubmit) {
          try {
            await deps.pool.retryDepositCommitment(
              hexToBytes(entry.commitmentHex),
              deps.lease?.draw("retryDepositCommitment"),
            );
            const after = await deps.pool.getDepositStatus(hexToBytes(entry.commitmentHex));
            if (after !== null) {
              await applyPoolStatus(deps, entry, after.status);
              break;
            }
          } catch (err) {
            attention.push(
              `note ${shortHex(entry.commitmentHex)}: commitment retry failed (${
                err instanceof Error ? err.message : String(err)
              })`,
            );
          }
        }
        await applyPoolStatus(deps, entry, record.status);
        break;
      }
      case "append-unknown":
        attention.push(
          `note ${shortHex(entry.commitmentHex)}: Merkle append outcome unknown — operator reconciliation required`,
        );
        await applyPoolStatus(deps, entry, record.status);
        break;
      default:
        // append-in-flight (wait + re-query later), appended (credited, root
        // pending — NOT terminal), root-accepted (terminal success).
        await applyPoolStatus(deps, entry, record.status);
        break;
    }
  }

  const final = await deps.journal.read();
  const totalAllowance = final.approval ? BigInt(final.approval.totalAllowance) : 0n;
  return { summary: summarize(final.entries, totalAllowance), attention, importedFromPool };
}

/** Snapshot the live fee basis for reconcile resubmission; note failures. */
async function snapshotLiveFeesOrNote(
  deps: ShieldFlowDeps,
  attention: string[],
): Promise<ShieldFeeSnapshot | null> {
  try {
    const [ledgerFee, params] = await Promise.all([
      deps.tokenRead.fee(),
      deps.pool.getGovernanceFeeParams(),
    ]);
    return { ledgerFee, params };
  } catch (err) {
    attention.push(
      `could not verify the live fee basis (${
        err instanceof Error ? err.message : String(err)
      }) — planned intents were not submitted (fail closed)`,
    );
    return null;
  }
}

/** Does the live fee basis still price this entry exactly as persisted? */
function feeBasisMatchesEntry(entry: ShieldJournalEntryState, live: ShieldFeeSnapshot): boolean {
  if (live.ledgerFee.toString(10) !== entry.ledgerFee) return false;
  try {
    const preview = shieldDepositPreview(BigInt(entry.denom), live.ledgerFee, live.params);
    return preview.protocolFee.toString(10) === entry.protoFee;
  } catch {
    return false; // unsupported fee model / precheck failure -> never submit
  }
}

async function reconcileApproval(
  deps: ShieldFlowDeps,
  options: ReconcileOptions,
  attention: string[],
): Promise<void> {
  const journal = await deps.journal.read();
  const approval = journal.approval;
  if (approval === null) return;
  if (approval.status === "planned") {
    // Crash BEFORE the wire dispatch (the pre-wire marker had not landed):
    // nothing was approved. Dispatch the persisted envelope now (CAS + dedup
    // protect it), or surface it.
    if (!options.resubmit) {
      attention.push("the batch approval was never dispatched — run reconcile with resubmission");
      return;
    }
    await deps.journal.setApprovalStatus(["planned"], "unknown"); // pre-wire marker
  } else if (approval.status !== "unknown") {
    return;
  }
  if (!options.resubmit) {
    attention.push("the batch approval outcome is unknown — run reconcile with resubmission");
    return;
  }
  // Byte-identical retry of the persisted envelope: same amount, same CAS
  // guard, same created_at_time — the ledger dedup collapses a landed original
  // to Duplicate; a landed original also makes the CAS fail with the live
  // allowance equal to the approved total, which confirms execution.
  try {
    const outcome = await deps.tokenMutation.approve(
      {
        spender: Principal.fromText(deps.config.poolCanisterId),
        amount: BigInt(approval.totalAllowance),
        expectedAllowance: BigInt(approval.expectedAllowance),
        createdAtTime: BigInt(approval.createdAtTimeNs),
        fee: BigInt(approval.ledgerFee),
      },
      deps.lease?.draw("approve"),
    );
    switch (outcome.kind) {
      case "ok":
        await deps.journal.setApprovalStatus(["unknown"], "approved", {
          blockIndex: outcome.blockIndex.toString(10),
        });
        return;
      case "duplicate":
        await deps.journal.setApprovalStatus(["unknown"], "approved", {
          blockIndex: outcome.duplicateOf.toString(10),
        });
        return;
      case "allowance-changed":
        if (outcome.currentAllowance === BigInt(approval.totalAllowance)) {
          // The original executed: the live allowance IS the approved total.
          await deps.journal.setApprovalStatus(["unknown"], "approved");
        } else {
          await deps.journal.setApprovalStatus(["unknown"], "failed", {
            failureReason: `allowance changed to ${outcome.currentAllowance} — external interference; not retrying`,
          });
          attention.push(
            "the approve retry found an unexpected allowance — verify externally before shielding again",
          );
        }
        return;
      case "too-old": {
        // The dedup window passed. The live allowance is the ground truth.
        const live = await deps.tokenMutation.allowance(
          deps.principal,
          Principal.fromText(deps.config.poolCanisterId),
        );
        if (live.allowance === BigInt(approval.totalAllowance)) {
          await deps.journal.setApprovalStatus(["unknown"], "approved");
        } else {
          await deps.journal.setApprovalStatus(["unknown"], "failed", {
            failureReason: "approve envelope aged out unexecuted (TooOld)",
          });
        }
        return;
      }
      case "rejected":
        await deps.journal.setApprovalStatus(["unknown"], "failed", {
          failureReason: outcome.reason,
        });
        return;
    }
  } catch (err) {
    attention.push(
      `the approve retry could not reach the ledger (${
        err instanceof Error ? err.message : String(err)
      }) — the envelope remains retryable`,
    );
  }
}

/** Page the P-REC index and import records this device's journal doesn't know. */
async function importFromRecoveryIndex(
  deps: ShieldFlowDeps,
  attention: string[],
): Promise<number> {
  const known = new Set((await deps.journal.read()).entries.map((e) => e.commitmentHex));
  const unindexed: PoolPendingDeposit[] = [];
  let cursor: Uint8Array | null = null;
  try {
    do {
      const page = await deps.pool.listMyActiveDeposits(cursor, 100n);
      for (const record of page.deposits) {
        if (!known.has(bytesToHex(record.noteCommitment))) unindexed.push(record);
      }
      cursor = page.nextCursor;
    } while (cursor !== null);
  } catch (err) {
    attention.push(
      `could not page the pool recovery index (${
        err instanceof Error ? err.message : String(err)
      }) — fresh-device recovery deferred`,
    );
    return 0;
  }
  if (unindexed.length === 0) return 0;

  // Key material only when actually needed, under the full C-VK-3 guard.
  const { vetKey } = await fetchGuardedVetKey(deps);
  const master = masterNoteSecret(vetKey);
  let imported = 0;
  for (const record of unindexed) {
    const commitmentHex = bytesToHex(record.noteCommitment);
    const plaintext = tryDecryptNotePayload(vetKey, record.encryptedPayload);
    if (plaintext === null) {
      attention.push(
        `recovery index lists note ${shortHex(commitmentHex)} but its payload does not decrypt ` +
          "for this identity — operator attention",
      );
      continue;
    }
    let fields;
    try {
      fields = noteFromBytesV2(plaintext);
    } catch (err) {
      if (err instanceof LegacyNoteFormatUnsupportedError) {
        // Quarantine-and-continue for an on-chain candidate (L0-B).
        attention.push(
          `recovery index lists a LEGACY-format note ${shortHex(commitmentHex)} — quarantined, not imported`,
        );
        continue;
      }
      throw err;
    }
    if (fields === null) {
      attention.push(
        `recovery index payload for ${shortHex(commitmentHex)} is not a v2 note — skipped`,
      );
      continue;
    }
    // Binding check: the payload must re-derive EXACTLY the indexed commitment.
    let rebuilt;
    try {
      const secrets = await deriveNoteSecretsV2(master, fields.nonce);
      rebuilt = await createShieldNote(fields.value, secrets);
    } catch (err) {
      // e.g. a hostile/corrupt payload carrying a non-denomination value —
      // skip it rather than aborting the whole reconcile.
      attention.push(
        `recovery payload for ${shortHex(commitmentHex)} does not re-derive a valid shield note ` +
          `(${err instanceof Error ? err.message : String(err)}) — not imported`,
      );
      continue;
    }
    if (bytesToHex(rebuilt.commitment) !== commitmentHex) {
      attention.push(
        `recovery payload for ${shortHex(commitmentHex)} re-derives a DIFFERENT commitment — ` +
          "not imported (possible tampering); operator attention",
      );
      continue;
    }
    const status = entryStatusForPool(record.status);
    const ok = await deps.journal.importEntry({
      commitmentHex,
      denom: fields.value.toString(10),
      nonceHex: bytesToHex(fields.nonce),
      protoFee: "0", // not recoverable from the record; only used when planning NEW batches
      ledgerFee: "0",
      encryptedPayloadHex: bytesToHex(record.encryptedPayload),
      status,
      createdAtNs: record.createdAtNs.toString(10),
      poolStatus: record.status.kind,
    });
    if (ok) imported += 1;
  }
  return imported;
}

function shortHex(hex: string): string {
  return `${hex.slice(0, 8)}…`;
}

// ── Cancel / manual resolution ───────────────────────────────────────────────

export interface CancelPlannedReport {
  /** Never-dispatched entries failed by this cancel. */
  cancelled: number;
  /** Dispatched-ambiguous entries left untouched (must resolve via reconcile/abandon). */
  ambiguousRemaining: number;
  /** What happened to the allowance. */
  revoke: RevokeOutcome | { kind: "blocked"; reason: string };
}

/**
 * Safe cancel after a fee-drift (or any) abort (re-review finding 4): fail
 * every NEVER-DISPATCHED (`planned`) entry, settle a never-dispatched
 * (`planned`) approval as failed, then — if nothing ambiguous remains that
 * could still legitimately consume it — revoke the allowance under the CAS
 * discipline. Dispatched-ambiguous (`unknown`) and credited (`deposited`)
 * entries are NEVER touched here.
 */
export async function cancelPlannedShield(deps: ShieldFlowDeps): Promise<CancelPlannedReport> {
  const journal = await deps.journal.read();
  let cancelled = 0;
  for (const entry of journal.entries) {
    if (entry.status === "planned" && entry.dispatchedAtNs === undefined) {
      await deps.journal.transitionEntry(entry.commitmentHex, ["planned"], "failed", {
        failureReason: "cancelled by the user (never dispatched)",
      });
      cancelled += 1;
    }
  }
  if (journal.approval?.status === "planned") {
    // Never dispatched — nothing was approved; settle the record.
    await deps.journal.setApprovalStatus(["planned"], "failed", {
      failureReason: "cancelled by the user (never dispatched)",
    });
  }
  const after = await deps.journal.read();
  const ambiguousRemaining = after.entries.filter((e) => e.status === "unknown").length;
  const approvalAmbiguous = after.approval?.status === "unknown";
  if (ambiguousRemaining > 0 || approvalAmbiguous) {
    return {
      cancelled,
      ambiguousRemaining,
      revoke: {
        kind: "blocked",
        reason:
          "ambiguous dispatched intents remain — reconcile (or abandon) them before revoking " +
          "the allowance",
      },
    };
  }
  return { cancelled, ambiguousRemaining: 0, revoke: await revokeShieldAllowance(deps) };
}

/**
 * Manual resolution of a dispatched-ambiguous (`unknown`, no pool record)
 * entry, mirroring the A-S21 frozen-transfer workflow: requires the user's
 * explicit confirmation that they verified against the chain externally, AND
 * (round-2 correction) a live authoritative status check proving the pool
 * genuinely holds NO record for the commitment — an entry with an active
 * record (TransferPending, appended, …) is refused and directed to
 * reconciliation; a failed status query refuses too (never archive blind).
 * The entry is archived as failed (audit trail retained) — never erased,
 * never auto-resubmitted.
 */
export async function abandonAmbiguousEntry(
  deps: ShieldFlowDeps,
  commitmentHex: string,
  input: { confirmedExternalReconcile: boolean },
): Promise<void> {
  if (!input.confirmedExternalReconcile) {
    throw new ShieldAbortError(
      "manual-resolution",
      "abandoning an ambiguous shield intent requires explicit confirmation that the outcome " +
        "was verified externally",
    );
  }
  let record: PoolPendingDeposit | null;
  try {
    record = await deps.pool.getDepositStatus(hexToBytes(commitmentHex));
  } catch (err) {
    throw new ShieldAbortError(
      "manual-resolution",
      `could not verify the pool holds no record for this intent (${
        err instanceof Error ? err.message : String(err)
      }) — refusing to archive; retry when the status query succeeds`,
    );
  }
  if (record !== null) {
    throw new ShieldAbortError(
      "manual-resolution",
      `the pool holds an active record for this intent (status: ${record.status.kind}) — ` +
        "it is not abandonable; run shield reconciliation instead",
    );
  }
  await deps.journal.transitionEntry(commitmentHex, ["unknown"], "failed", {
    failureReason: "abandoned after external reconciliation (user-confirmed, no pool record)",
  });
}

// ── Allowance cleanup ────────────────────────────────────────────────────────

export type RevokeOutcome =
  | { kind: "none" } // nothing to revoke
  | { kind: "revoked" }
  | { kind: "raced"; currentAllowance: bigint }
  | { kind: "failed"; reason: string };

/** Revoke a leftover pool allowance (approve 0 under the same CAS discipline). */
export async function revokeShieldAllowance(deps: ShieldFlowDeps): Promise<RevokeOutcome> {
  const poolPrincipal = principalOfPool(deps);
  const current = await deps.tokenMutation.allowance(deps.principal, poolPrincipal);
  if (current.allowance === 0n) return { kind: "none" };
  const fee = await deps.tokenRead.fee();
  const outcome = await deps.tokenMutation.approve(
    {
      spender: poolPrincipal,
      amount: 0n,
      expectedAllowance: current.allowance,
      createdAtTime: deps.nowNs(),
      fee,
    },
    deps.lease?.draw("approve"),
  );
  switch (outcome.kind) {
    case "ok":
    case "duplicate":
      return { kind: "revoked" };
    case "allowance-changed":
      return { kind: "raced", currentAllowance: outcome.currentAllowance };
    case "too-old":
      return { kind: "failed", reason: "revoke rejected as too old — retry" };
    case "rejected":
      return { kind: "failed", reason: outcome.reason };
  }
}
