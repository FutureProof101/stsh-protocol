/**
 * App context + state shared by the wallet pages (Campaign A A1/A2 base;
 * Campaign B L3a adds the shielded surface — note-cache session + shield).
 */

import type { Principal } from "@dfinity/principal";

import type { SessionPolicy, WalletConfig } from "../session/config";
import type { MutationActors, OperatorActors, ReadActors, ShieldedActors } from "../session/session";
import type { ReleaseFooterHandle } from "./releaseFooter";
import type {
  MirrorHead,
  ScannedNote,
  ShieldJournalEntryState,
  SpendJournalEntryState,
  VerifiedScanMetadata,
} from "../storage/noteCache";
import type { WipeReport } from "../storage/panicWipe";
import type { TransferIntentRecord } from "../storage/transferJournal";
import type { ShieldFeeParams } from "../actors/pool";
import type { SpendInput } from "./spendFlow";
import type { PendingDelayView } from "./submissionDelay";
import type { OperationLease } from "../actors/authorization";
import type { Route } from "./router";
import type { DeviceApprovalState } from "./deviceApprovalCopy";

export interface AppStatus {
  /** `advisory` = O-7 copper: a caution the user should read, not a failure. */
  kind: "info" | "error" | "success" | "advisory";
  msg: string;
  /** Optional one-idea-per-line rendering of `msg` (O-6); `msg` stays the plain text. */
  lines?: string[];
  /** Optional single action offered with the message. */
  action?: { label: string; run(): void };
}

export interface AppState {
  /** Sourced ONLY from identity.getPrincipal() (A-S7); null while anonymous. */
  principal: Principal | null;
  /** Public token balance of `principal` (base units); null until fetched. */
  balance: bigint | null;
  /** A session/transfer operation is in flight (buttons disable, no re-entry). */
  busy: boolean;
  status: AppStatus | null;
  /**
   * Whether the L4 encrypted note cache is open for THIS session (L3a). The
   * shield journal lives inside it, so shield/reconcile refuse while false.
   */
  cacheUnlocked: boolean;
  /**
   * WALLET-CACHE-II-ONLY — WHY the private balance is (not) open, so the pages
   * render the right thing instead of one generic "locked" card.
   *
   *   "none"      signed out, or no Layer-1 key service in this build;
   *   "opening"   the sign-in open is running (an envelope read, no derive);
   *   "open"      the cache is open (`cacheUnlocked` is true);
   *   "preparing" this device has no key envelope yet — the first shield or
   *               sync opens it (Addendum 3: sign-in NEVER derives to open it);
   *   "passcode"  this device's envelope needs the opt-in passcode;
   *   "migrate"   an old passphrase record needs the one-time move (O-2);
   *   "error"     the sign-in open failed for another reason — retryable, and
   *               retrying is again derive-free.
   *
   * Optional so page tests that build a bare state need not supply it; absent
   * reads as "none".
   */
  cacheGate?: "none" | "opening" | "open" | "preparing" | "passcode" | "migrate" | "error";
  /**
   * Whether THIS device's key envelope is passcode-protected (O-3), as last
   * observed; null when not known (no envelope read yet this session). Drives
   * the Settings toggle, which must show the real setting (Addendum 1).
   */
  passcodeRequired?: boolean | null;
  /**
   * WALLET-V12 O-4 — the "Approve new devices" setting as last READ from the
   * vetkeys canister (`device_approval_policy` + `list_devices`), or null while
   * unknown. Non-secret, canister-side, never persisted (I-3).
   */
  deviceApproval?: {
    state: DeviceApprovalState;
    /** This browser holds an ACTIVE enrolled device for this principal. */
    thisDeviceActive: boolean;
    /** Active devices on the principal (0 → the canister refuses ON). */
    activeDevices: number;
  } | null;
  /** Shield-journal entries for display; null until the cache is unlocked. */
  shieldEntries: ShieldJournalEntryState[] | null;
  // ── L3b scan surface ──────────────────────────────────────────────────────
  /** Validated notes from the last completed scan (all lifecycle states). */
  notes: ScannedNote[];
  /** A scan is in flight (the scan button disables, no re-entry). */
  scanning: boolean;
  /**
   * Whether the last completed ORDINARY scan (not verified sweep) actually
   * succeeded. `null` = none has completed yet this session. `false` covers
   * a failed OR cancelled scan — "not currently scanning" is not evidence of
   * freshness, so the "Up to date" badge must read this, not `scanning`.
   */
  lastScanOk: boolean | null;
  /** Last scan progress event; null when idle. */
  scanProgress: { scannedUpTo: bigint; found: number } | null;
  /** The merkle-tree head from the last completed scan (K3-007 indicator). */
  mirrorHead: MirrorHead | null;
  /** Total quarantined candidates across all scans (bounded diagnostics). */
  quarantineTotal: number;
  /**
   * WALLET-AUTH G1b (D-6) — the evidence record of the last COMPLETED verified
   * sweep for this cache, or null when none has been recorded.
   *
   * Null is the ordinary state and says nothing bad: it means this wallet holds
   * no verified observation for this deployment, not that anything failed. The
   * page renders it as an observation with its residual named, never as a badge
   * that a balance is trustworthy.
   */
  verifiedScan: VerifiedScanMetadata | null;
  /**
   * WALLET-AUTH G1b / SSA C-2b — a verified sweep that the monotone floor
   * REFUSED, held so the page can offer the explicit, user-initiated reset.
   *
   * Carries the refused sweep's own `config_hash`/`security_epoch`, because the
   * reset must drop exactly the floor that refused and no other. Cleared by a
   * successful sweep, by the reset, and on logout.
   */
  verifiedRollback: {
    configHash: string;
    securityEpoch: string;
    observedLeafCount: string;
    floorLeafCount: string;
    sameCountDifferentRoot: boolean;
  } | null;
  /** A verified sweep is in flight (distinct from an ordinary `scanning`). */
  verifiedScanning: boolean;
  /**
   * Result of the last panic wipe (A-1b / R14-2); null until one is run. Held
   * so the account page can show the PER-SURFACE outcome — a wipe that only
   * partly succeeded must say which surfaces survived, never a blanket
   * "all local data deleted".
   */
  wipeReport: WipeReport | null;

  /** True only before the current spend enters its durable dispatch transition. */
  spendLocallyCancellable: boolean;
  // ── WL-2c: the optional randomised submission delay ───────────────────────
  /** The user's toggle. Default OFF; persisted per browser, cleared by a wipe. */
  submissionDelayEnabled: boolean;
  /**
   * The delay currently running, or null. Non-null means an operation is
   * waiting and NOTHING has been submitted for it yet — the view carries the
   * two controls the user must always have: cancel, and submit now.
   */
  pendingDelay: PendingDelayView | null;
  /**
   * D-1 clause 4 — the key-recovery allowance notice, when there is one.
   *
   * Its OWN field rather than a transient status: the warning matters most
   * right when the user is doing something else (a scan, a shield), and a
   * status line is overwritten by whatever finishes next. A user who is one
   * recovery from lockout should not lose the warning because a scan completed
   * a second later. `null` means nothing to say — including on the zero-derive
   * fast path, where the canister reported no allowance at all.
   */
  quotaNotice: { level: "info" | "warning" | "error"; message: string } | null;
  /**
   * V4 §5.4 — seconds until the next launch-capacity spot, or `null` when no
   * countdown is running.
   *
   * Held in memory only and derived from a MONOTONIC deadline captured when the
   * refusal arrived. Never persisted: a stored wall-clock deadline outlives the
   * session it belonged to and would be counted against a clock that has moved.
   */
  capacityCountdownSeconds: number | null;

  // ── WL-3: the max-exit basis ──────────────────────────────────────────────
  /**
   * The live basis the spend page needs to tell the exit truth: governance fee
   * params plus the live ledger fee. Null until loaded — and while it is null
   * the page must NOT quote a maximum or accept a payout (fail closed, never
   * fall back to the note value).
   */
  spendFeeBasis: { params: ShieldFeeParams; ledgerFee: bigint } | null;

  // ── WL-2b: recovery actions awaiting an explicit confirmation ─────────────
  /**
   * Spend-recovery entries whose repair would put a transaction on chain.
   * A cache unlock is a gesture for UNLOCKING, not for submitting a payout
   * retry, so the automatic pass only ever CLASSIFIES these and lists them
   * here; the user's confirmation is what performs them.
   */
  pendingRecovery: { spendId: string; action: string }[];

  // ── WALLET-UX (display only) ──────────────────────────────────────────────
  /**
   * Whether the signed-in principal is in the Vault's signer set. Decides only
   * whether admin/system surfaces SHOW; it authorises nothing. Fail-closed:
   * false until the signer set is read and contains this principal.
   */
  isAdmin?: boolean;
  /** Spend-journal entries for Activity; null until the cache is unlocked. */
  spendEntries?: SpendJournalEntryState[] | null;
}

export interface AppContext {
  config: WalletConfig;
  /**
   * J-25 RED-1: the mounted release panel. `mountApp` KEEPS this handle instead
   * of discarding it, so the panel's subscription to the real prover-asset
   * verification event has an owner and an explicit `dispose`. Optional because
   * it is assigned after the shell is built; presentation only (I3).
   */
  releasePanel?: ReleaseFooterHandle;
  /** Origin policy, evaluated BEFORE any actor construction (A-S8). */
  policy: SessionPolicy;
  state: AppState;
  /**
   * Anonymous read actors — constructed at boot, never gated on auth (A-S7).
   *
   * J-17c: NULLABLE. The token/staking/vesting canisters do not exist until
   * J-18/A-7, so their ids are `""` in the shipped config and actor
   * construction THROWS. That rejection used to escape `mountApp` before
   * `router.start()` ran, so no route rendered at all. It is now caught: the
   * field records `null` and every use site REFUSES with
   * `READ_SERVICES_UNAVAILABLE`. A null read actor must never be replaced by a
   * stub, a cached value, or a numeric default — a refusal, never a zero.
   */
  readActors: ReadActors | null;
  /** Identity-bound actors; null until login. Mutations refuse while null. */
  mutationActors: MutationActors | null;
  /**
   * J-17e — whether THIS session has a usable durable transfer journal. False
   * when device storage (IndexedDB) is blocked: the session still exists and
   * still shows a principal, but a transfer cannot be journalled before its
   * wire call, so it is refused at the page rather than attempted unrecorded.
   * True while anonymous — the account page only consults it when logged in.
   */
  journalAvailable: boolean;
  /**
   * Identity-bound shielded actors (pool + vetkeys, S-44); null until login or
   * when the shielded canister ids are unconfigured. Shield refuses while null.
   */
  shieldedActors: ShieldedActors | null;
  /**
   * J-17b — identity-bound Vault/Upgrader actors for the `#/operator` route;
   * null while anonymous, and dropped on logout BEFORE any other session state
   * (the epoch advances first). That is what makes an operator action after
   * session revocation impossible rather than merely refused: there is no
   * actor left to call with.
   */
  operatorActors: OperatorActors | null;
  /**
   * The unresolved (`pending`/`unknown`) or frozen transfer intent for the
   * CURRENT session's (principal + ledger + network) scope; null when the slot
   * is free. While non-null, no new transfer intent may be minted (A-S14).
   */
  pendingIntent: TransferIntentRecord | null;
  navigate(route: Route): void;
  /** Re-render the active route. */
  refresh(): void;
  login(): Promise<void>;
  logout(): Promise<void>;
  /** Refresh `state.balance` for the logged-in principal (read actor). */
  refreshBalance(): Promise<void>;
  /**
   * WALLET-UI: read the Vault signer set (`get_signers`, a query) ONCE, on an
   * explicit user press in Settings, to decide whether operator surfaces show.
   * Never called automatically (Addendum 1 ruling 2). Presentation only.
   */
  checkOperatorAccess?(): Promise<void>;
  /**
   * Start a NEW transfer intent (validates recipient/amount, queries the live
   * ledger fee, persists the fully-bound envelope, then submits). Refused
   * while anonymous or while an unresolved intent exists.
   */
  transfer(input: { toText: string; amountText: string }): Promise<void>;
  /** Byte-for-byte resubmit of the persisted unresolved intent (C-A3). */
  retryPendingIntent(): Promise<void>;
  /**
   * Manual abandonment of a FROZEN (`TooOld`-ambiguous) intent. Requires the
   * user's explicit confirmation that they reconciled against the ledger
   * externally; the record is archived, never erased (A-S21).
   */
  abandonFrozenIntent(input: { confirmedExternalReconcile: boolean }): Promise<void>;

  // ── Campaign B / L3a — shielded surface ────────────────────────────────────

  /**
   * Open the note cache with a TYPED secret. WALLET-CACHE-II-ONLY: sign-in
   * opens the cache on its own (no secret), so this is reached only when a
   * secret is genuinely needed — it routes to the passcode unlock while
   * `cacheGate === "passcode"`, to the one-time move while `"migrate"`, is a
   * no-op once a key-based cache is open, and otherwise runs the legacy
   * Argon2id passphrase open (a programmatic path no page offers a control for).
   */
  unlockNoteCache(passphrase: string): Promise<void>;
  /**
   * Shield `amount` (base units) into fixed-denomination notes (§6): C-VK-3 +
   * C-DOM-2 guards, fail-closed fee snapshot, journal-before-submit, ICRC-2
   * approve with allowance CAS, per-note shield_deposit with the P-DOM hash,
   * then a status reconcile pass. Refused while anonymous, locked, or while an
   * unresolved shield intent exists.
   */
  shield(amount: bigint): Promise<void>;
  /**
   * Reconcile the shield journal against the pool (§6 status table + the
   * L0-G fresh-device recovery index). `resubmit` allows effectful repairs
   * (checked resubmission, approve retry, commitment-append retry).
   */
  reconcileShieldJournal(input: { resubmit: boolean }): Promise<void>;
  /** Revoke a leftover pool allowance (approve 0 under the same CAS discipline). */
  revokeShieldAllowance(): Promise<void>;
  /**
   * Safe cancel (fee-drift exit): fail every NEVER-DISPATCHED planned intent,
   * then revoke the allowance if no ambiguous dispatched intent remains.
   */
  cancelPlannedShield(): Promise<void>;
  /**
   * Manual resolution of a dispatched-ambiguous intent with no pool record
   * (A-S21 pattern): requires explicit confirmation of external verification;
   * archives the entry as failed — never erased, never auto-resubmitted.
   */
  abandonAmbiguousShieldEntry(input: {
    commitmentHex: string;
    confirmedExternalReconcile: boolean;
  }): Promise<void>;
  /**
   * Scan the merkle tree for new notes (§9 validated pipeline): strict
   * spent-set download, full public sweep into the local mirror, per-candidate
   * derivation/leaf/spent-state validation, ONE atomic cache update. Refused
   * while anonymous, locked, or already scanning.
   */
  scan(): Promise<void>;
  /**
   * WALLET-AUTH G1b (D-6) — the USER-INITIATED verified sweep.
   *
   * Anchors the sweep on the POOL's accepted root over the replicated
   * transport, then commits through the one floor check + floor advance
   * (`commitVerifiedScan`). Refused while anonymous, locked, already scanning,
   * or when no pool is configured. Optional so a build without a wired scanner
   * simply does not offer it.
   *
   * NEVER called on a timer, on a route change, or by any private event: a
   * verified sweep is ingress the user pays for in visibility, so the gesture
   * that mints its lease is the whole authorisation (parent brief §8).
   */
  verifiedScan?(): Promise<void>;
  /**
   * WALLET-AUTH G1b / SSA C-2b — drop this deployment's verified floor after a
   * refusal, on an explicit confirmation the page obtains behind a warning.
   *
   * It discards the record the wallet compares against, so a genuine rollback
   * stops being visible afterwards. That is said in the UI copy, and it is why
   * nothing calls this automatically.
   */
  resetVerifiedHistory?(input: { confirmed: boolean }): Promise<void>;
  /**
   * Spend a note (§10): self-change + optional public payout. Accepted-root
   * witness, journal+lock BEFORE proof, 256-byte compact proof, 9-signal
   * canonical compare, exactly 1 nullifier / 2 outer leaves. Refused while
   * anonymous, locked, or busy.
   */
  /**
   * Cancel session-owned local scan/proof/artifact work. It sends no canister
   * mutation and does not alter durable recovery records.
   */
  cancelSessionTasks?(): void;

  spend(input: SpendInput): Promise<void>;
  /**
   * Spend recovery (§10.1/§10.2 + P-REC): import active spends from the pool's
   * identity-bound recovery index (fresh-device path), then reconcile every
   * journal entry through the update-validated table. Advisory queries drive
   * reversible actions only; permanent effects come only from update Oks.
   * `quietOnError` (post-unlock auto-run): a failure never overwrites the
   * unlock's success — recovery is retried on the next unlock or manual call.
   */
  recoverSpends(input?: {
    quietOnError?: boolean;
    effectful?: boolean;
    /** WL-2b: the gesture lease that authorises the effectful pass. */
    lease?: OperationLease;
  }): Promise<void>;

  // ── Lane A-1b — panic wipe (R14-2) ────────────────────────────────────────

  /**
   * Destroy every LOCAL trace at this origin: end the session (epoch first),
   * release the II delegation, close and delete the wallet databases, and
   * clear runtime-discovered key/value and cache storage. Sends no message and
   * changes nothing on chain — the note set is recoverable by II login plus a
   * rescan; the local journal/provenance is not. Resolves with the per-surface
   * report rather than throwing, so a partial wipe can be shown honestly.
   */
  panicWipe(): Promise<WipeReport>;

  // ── WL-2c / WL-3 / WL-2b surfaces ─────────────────────────────────────────

  /** Turn the randomised submission delay on or off (persisted, default OFF). */
  setSubmissionDelayEnabled(enabled: boolean): void;
  /**
   * Load the live fee basis the spend page needs (governance params + ledger
   * fee). Fails closed: on error `spendFeeBasis` stays null and the page
   * refuses to quote a maximum rather than quoting a wrong one.
   */
  loadSpendFeeBasis(): Promise<void>;
  /**
   * Perform the spend-recovery repairs listed in `state.pendingRecovery`. This
   * is a USER GESTURE — it is the only path by which recovery may put a
   * transaction on chain (WL-2b §4.3).
   */
  applySpendRecovery(): Promise<void>;

  // ── WALLET-CACHE-II-ONLY ──────────────────────────────────────────────────

  /**
   * Open the private balance with this device's opt-in PASSCODE (O-3). Reads
   * the envelope (a query) and opens it locally — zero derives. Only meaningful
   * while `state.cacheGate === "passcode"`.
   */
  unlockWithPasscode?(passcode: string): Promise<void>;
  /**
   * The one-time move of an old passphrase record (O-2): authenticate under
   * the old passphrase, then re-seal to sign-in-only unlock (default) or keep
   * the passphrase as this device's passcode. The target key comes ONLY from
   * this device's envelope (the no-derive path); it never derives.
   */
  migrateNoteCache?(input: { passphrase: string; keepAsPasscode: boolean }): Promise<void>;
  /** Re-run the derive-free sign-in open after an `"error"` gate. */
  retryPrivateOpen?(): Promise<void>;
  /**
   * The opt-in passcode for THIS device (O-3, D-1b v3 §2). Supplied by the app
   * once the envelope mode is known, so Settings shows the REAL setting
   * (Addendum 1) and offers a working control rather than a disabled one.
   * `enable` sets a new passcode; `disable` needs the current one.
   */
  passcode?: {
    enabled: boolean;
    enable(passcode: string): Promise<void>;
    disable(currentPasscode: string): Promise<void>;
  };
  /**
   * WALLET-V12 O-4 — "Approve new devices" (Owner O-8). Default OFF.
   * `load` reads the setting (two queries); `turnOn` is device-signed;
   * `turnOff` is device-signed and immediate from an active device here, and
   * otherwise the II-only 24 h request (`requestClear`).
   */
  deviceApprovalControl?: {
    load(): Promise<void>;
    turnOn(): Promise<void>;
    turnOff(): Promise<void>;
    requestClear(): Promise<void>;
  };
}

/**
 * J-17c — the one refusal string for a null `ctx.readActors`. Shared by the
 * shell and by the staking/vesting pages so the wallet says the same thing
 * everywhere, and so a grep for it finds every refusal site.
 */
export const READ_SERVICES_UNAVAILABLE =
  "Ledger read services not configured — token, staking and vesting views are unavailable.";

/**
 * J-17e — the refusal copy for a null `ctx.mutationActors`. Two strings, not
 * one, because the two causes are not the same fact and the user acts on them
 * differently: an empty canister id is a property of the deployment (nothing
 * to retry, the ledger is not born yet), while a rejected agent/actor
 * construction is a transient boot/network failure whose real message the user
 * needs. Attributing the second to the first would tell the user something
 * false (SSA F-2).
 */
export const TRANSFER_SERVICES_UNCONFIGURED =
  "Token transfer services not configured — transfers are unavailable in this deployment.";

/** The transient half of the pair: carries the real reason, never invents one. */
export function transferServicesUnavailable(reason: string): string {
  return `Token transfer services unavailable: ${reason}`;
}

/**
 * J-17e / SSA F-1 — the transfer journal is durable device storage, and a
 * transfer that cannot be journalled before the wire call is refused, never
 * attempted. Blocked IndexedDB (private mode, partitioned storage) is the
 * cause here, not configuration.
 */
export const DEVICE_STORAGE_UNAVAILABLE =
  "Device storage is unavailable — transfers are unavailable because this device cannot journal them.";
