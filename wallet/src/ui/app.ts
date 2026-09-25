/**
 * App shell (Campaign A / Wave 1) — II auth, hardened session/actor model, and
 * the account/staking/vesting routes ONLY (H-A3).
 *
 * Boot order is load-bearing (A-S8): resolve config -> evaluate the session
 * policy for the RUNNING origin -> only then construct the auth client or any
 * mutation actor. A blocked origin gets anonymous reads and nothing else — a
 * stale delegation restored on a wrong origin never reaches actor
 * construction.
 *
 * Epoch discipline (A-S6): every async operation captures the session epoch
 * before its first await and re-checks it after EVERY await before committing
 * state. Logout advances the epoch BEFORE clearing state.
 *
 * Error discipline (A-S10): only a VERIFIED delegation expiry
 * (auth.verify() === "expired") ends the session. A transport error or
 * canister reject surfaces as a status message and never drops to anonymous.
 */

import type { Identity } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

import {
  LeaseExpiredError,
  walletAuthorizationAuthority,
  type AuthorizationAuthority,
  type AuthorizedAction,
  type CallToken,
  type OperationLease,
} from "../actors/authorization";
import type { TransferOutcome, TransferRequest } from "../actors/token";
import { createWalletAuth, type AuthSession, type WalletAuth } from "../session/auth";
import { CacheSessionManager } from "../session/cacheSession";
import {
  evaluateSessionPolicy,
  readSubmissionDelayEnabled,
  resolveConfig,
  writeSubmissionDelayEnabled,
  type SessionPolicy,
  type WalletConfig,
} from "../session/config";
import {
  createMutationActors,
  createMutationAgent,
  createReadActors,
  createReadAgent,
  createOperatorActors,
  createShieldedActors,
  type MutationActors,
  type OperatorActors,
  type ReadActors,
  type ShieldedActors,
} from "../session/session";
import { loadDerivationOrigin, loadLaunchOrigin } from "../session/launchConfig";
import { SessionEpoch } from "../session/sessionEpoch";
import { raceSessionTask, SessionCancelledError, SessionTaskOwner, throwIfAborted } from "../session/taskOwner";
import { ShieldJournal } from "../storage/journal";
import { openIndexedDbPrincipalCacheStore } from "../storage/indexedDbNoteStore";
import { runPanicWipe, type WipeReport } from "../storage/panicWipe";
import type { PrincipalCacheStore } from "../storage/noteCache";
import {
  hexToBytes,
  IntentSlotBusyError,
  openIndexedDbJournalStore,
  StaleIntentError,
  TransferJournal,
  type JournalStore,
  type TransferIntentRecord,
} from "../storage/transferJournal";
import type { AppContext, AppState, AppStatus } from "./context";
import {
  DEVICE_STORAGE_UNAVAILABLE,
  READ_SERVICES_UNAVAILABLE,
  TRANSFER_SERVICES_UNCONFIGURED,
  transferServicesUnavailable,
} from "./context";
import { clear, el } from "./dom";
import { HashRouter, NAV_ROUTES, routeHref, type Route } from "./router";
import {
  abandonAmbiguousEntry as runShieldAbandon,
  cancelPlannedShield as runShieldCancel,
  reconcileShieldJournal as runShieldReconcile,
  resolveExpectedVetkdKeyName,
  revokeShieldAllowance as runShieldRevoke,
  runShieldFlow,
  ShieldAbortError,
  type ShieldFlowDeps,
} from "./shieldFlow";
import { createPoolIdentityReadActor } from "../actors/pool";
import { PoolIdentityCache, type PoolIdentityReader } from "../release/poolIdentity";
import { mountReleaseFooter } from "./releaseFooter";
import { parseStsh, formatStsh } from "./tokenFormat";
import { renderAccount } from "./pages/account";
import { renderShield } from "./pages/shield";
import { renderScan } from "./pages/scan";
import { renderBalance } from "./pages/balance";
import { renderSpend } from "./pages/spend";
import { renderStaking } from "./pages/staking";
import { renderVesting } from "./pages/vesting";
import { renderOperator } from "./pages/operator";
import { renderActivity } from "./pages/activity";
import { renderSettings } from "./pages/settings";
import { copyButton, shortPrincipal } from "./components";
import {
  MAX_VERIFIED_SWEEP_LEAVES,
  NoAcceptedRootYetError,
  VerifiedEvidenceMissingError,
  VerifiedPathUnavailableError,
  commitVerifiedScan,
  mergeScanOutcome,
  type ScanOutcome,
} from "../crypto/scanner";
import type { FetchKeys } from "../crypto/vetkeys";
import { VetkeysCallError, WALLET_ELIGIBILITY_MIN_BALANCE_E8S } from "../crypto/vetkeys";
import { dailyKeyLimitMessage, quotaNotice, quotaRefusalNotice } from "./quotaCopy";
import {
  DEVICE_APPROVAL_REFUSAL_LINES,
  DEVICE_APPROVAL_REQUEST_CLEAR_BUTTON,
  classifyDeviceApprovalPolicy,
  deviceApprovalBlocksEnrolment,
  deviceApprovalPendingLine,
} from "./deviceApprovalCopy";
import { VERIFIED_SCAN_STRINGS, verifiedScanMessage } from "./verifiedScanCopy";
import { retryAfterSeconds } from "../crypto/vetkeys";
import {
  createSessionFetchKeys,
  Layer1Unavailable,
  openThisDevicesEnvelope,
  openThisDevicesVetKey,
  setDeviceApprovalPolicyFromDevice,
  setEnvelopePasscode,
  singleFlightFetchKeys,
  type DeviceIdentity,
  type Layer1Config,
} from "../crypto/vetkeyAccess";
import { decodeEnvelope, EnvelopeFormatError } from "../crypto/envelope";
import { cacheUnlockKeyFromPasscode, cacheUnlockKeyIiOnly, envelopeIsPasscodeProtected } from "../crypto/layer1";
import type { VetKey } from "@dfinity/vetkeys";
import { exportDevicePublicKeys, generateDeviceKeys, randomDeviceId } from "../crypto/devices";
import { loadDeviceIdentity, saveDeviceIdentity } from "../storage/deviceStore";
import { assertCanisterConfig, fetchUserVetKey, masterNoteSecret } from "../crypto/vetkeys";
import {
  CacheAuthenticationError,
  CacheWriteConflictError,
  KDF_VERSION_ARGON2ID,
  KDF_VERSION_VETKEY_UNLOCK,
  KDF_VERSION_WALLET_PASSCODE,
  PrincipalNoteCache,
  VerifiedFloorRollbackError,
  importCacheKey,
  migratePassphraseRecord,
  resealKeyRecord,
  resetVerifiedHistory,
  spendableNotes,
  type CacheMigrationTarget,
  type CachedScanState,
  type VerifiedScanMetadata,
} from "../storage/noteCache";
import { SpendJournal } from "../storage/spendJournal";
import {
  SPEND_ALREADY_WENT_THROUGH_COPY,
  spendAdmissionCopy,
} from "./spendAdmissionCopy";
import { runSpendFlow, SpendFlowError, recoverSpendsFromPool, reconcileSpendEntry, recoverSpendFreshId, recoveryActionForAdvisory, type SpendInput } from "./spendFlow";
import {
  createSubmissionDelay,
  timerSleep,
  SubmissionAbandonedError,
  type SubmissionDelay,
} from "./submissionDelay";
import { maxPublicAmount } from "../crypto/fees";
import { assertDeploymentBinding } from "../session/domainGuard";
import { createMerkleActor } from "../actors/merkle";
import { createNullifierRegistryActor } from "../actors/nullifierRegistry";
import type { ScannerRequest, ScannerResponse } from "../workers/scanner.worker";

const ROUTE_LABELS: Record<Route, string> = {
  account: "Home",
  activity: "Activity",
  settings: "Settings",
  staking: "Staking",
  vesting: "Vesting",
  shield: "Shield",
  scan: "Scan",
  balance: "Balance",
  spend: "Spend",
  operator: "Vault operator",
  "not-available": "Not available",
};


/** Construction seams so tests drive the app with fake actors/auth. */
export interface AppDeps {
  /** The running origin the session policy is evaluated against. */
  origin: string;
  /**
   * S1-02: loads the launch origin from the same-origin config asset. Optional
   * so existing harnesses inject a value directly; production omits it and the
   * real fetch is used. Returning `undefined` REFUSES — never defaults.
   */
  loadLaunchOrigin?(): Promise<string | undefined>;
  /**
   * WT-1 — the II derivation origin, from the same runtime asset. Separate seam
   * from `loadLaunchOrigin` so an existing harness that stubs only the launch
   * origin keeps its meaning: it gets no derivation origin, i.e. the
   * transitional deployment, which is the pre-WT-1 behaviour.
   */
  loadDerivationOrigin?(): Promise<string | undefined>;
  buildReadActors(config: WalletConfig): Promise<ReadActors>;
  /**
   * J-25: the ANONYMOUS reader behind the release panel's two display queries.
   * Optional so existing harnesses need no change; omitting it uses the
   * production builder, which returns `null` when no pool id is configured.
   */
  buildPoolIdentityReader?(config: WalletConfig): Promise<PoolIdentityReader | null>;
  buildMutationActors(config: WalletConfig, identity: Identity): Promise<MutationActors>;
  createAuth(policy: SessionPolicy, onIdle: () => void): Promise<WalletAuth>;
  /**
   * Durable transfer-journal store (IndexedDB in production). `onBlocked`
   * fires when an old-version tab blocks the journal's v1 -> v2 migration
   * (AC-1c) — the app surfaces an actionable close/refresh message.
   */
  createJournalStore(opts: { onBlocked: () => void }): Promise<JournalStore>;
  /**
   * L3a: identity-bound shielded actors (pool + vetkeys, S-44). Optional so
   * Campaign-A test harnesses need no change; defaults to the production
   * builder. May throw when the shielded canister ids are unconfigured — the
   * app records `shieldedActors: null` and shield refuses with the reason.
   */
  buildShieldedActors?(config: WalletConfig, identity: Identity): Promise<ShieldedActors>;
  /**
   * J-17b: identity-bound Vault/Upgrader actors for the `#/operator` route.
   * Optional on the same reasoning as the shielded builder — an unconfigured
   * or invalid ring id records `operatorActors: null` and the page says the
   * surface is unavailable rather than rendering an empty proposal list.
   */
  buildOperatorActors?(config: WalletConfig, identity: Identity): Promise<OperatorActors>;
  /** L3a: the principal-scoped encrypted note-cache store (IndexedDB in prod). */
  createCacheStore?(): Promise<PrincipalCacheStore>;
  /**
   * WL-2c: the wait behind the randomised submission delay. Production omits
   * it (a `setTimeout` wrapper); tests inject a controllable one so NOTHING
   * anywhere asserts against real elapsed wall-clock time.
   */
  sleep?(ms: number): Promise<void>;
  /**
   * V4 §5.4 — the countdown's MONOTONIC clock, in milliseconds.
   *
   * Its own seam rather than reusing `sleep`, for the reason `sleep` exists:
   * NOTHING anywhere may assert against real elapsed wall-clock time. `sleep`
   * is one-shot and cannot drive a repeating countdown, so the countdown gets
   * an injected `now()` and an injected scheduler of its own. Production
   * supplies `performance.now()`, which is monotonic — a wall clock that a user
   * or NTP moves backwards would make a countdown jump.
   */
  now?(): number;
  /**
   * V4 §5.4 — the countdown's ticker. Returns its own CANCEL function, so a
   * caller can stop it without knowing what kind of timer it was. Production
   * wraps `setInterval`.
   */
  scheduleTick?(fn: () => void, everyMs: number): () => void;
  /**
   * L3b: run the validated scan (production dispatches scanner.worker.ts;
   * tests inject a fake). Receives the I/O inputs only — the vetKey/master
   * secret never touch persistent storage on either side.
   */
  scanNotes?(input: ScanWorkerInput): Promise<ScanOutcome>;
  /**
   * L3b: key-fetch seam for the C-VK-3 sandwich (same pattern as L3a's
   * ShieldFlowDeps.fetchKeys) — production uses fetchUserVetKey; tests stub it
   * so the sandwich's ordering/failure paths are exercisable without vetKD
   * cryptography.
   */
  fetchKeys?: FetchKeys;
  /** L3c: prover-worker spawn seam — production spawns prover.worker.ts; tests inject. */
  spawnProverWorker?: () => Worker;
  /** L10 test seams for cancellable spend preparation; production uses the named imports. */
  assertDeploymentBinding?: typeof assertDeploymentBinding;
  createReadAgent?: typeof createReadAgent;
}

/** The input the scanner worker (or a test fake) consumes. */
export interface ScanWorkerInput {
  merkleCanisterId: string;
  nullifierCanisterId: string;
  host: string;
  /**
   * WALLET-AUTH Gate 1. PRESENT selects the VERIFIED sweep (parent AC-3); the
   * value is `config.poolCanisterId`. Absent runs the ordinary query-path scan.
   */
  poolCanisterId?: string;
  /**
   * R-1: the single-use `"verifiedScan"` token drawn from the user's gesture
   * lease. REQUIRED whenever `poolCanisterId` is present, and consumed BEFORE
   * the worker is constructed, so an unauthorised verified sweep makes zero
   * wire calls rather than being cancelled part-way through one.
   */
  authToken?: CallToken;
  /** Receives the sweep's evidence record on success. */
  onVerified?: (metadata: VerifiedScanMetadata) => void;
  vetKeySerialized: Uint8Array;
  masterNoteSecret: Uint8Array;
  fromIndex: bigint;
  pageSize?: bigint;
  onProgress?: (scannedUpTo: bigint, found: number) => void;
  signal?: AbortSignal;
}

/**
 * Dispatch the validated scan to the scanner Web Worker. Only the validated
 * outcome returns; the main thread owns the (atomic) cache update.
 */
export function runScannerWorker(
  input: ScanWorkerInput,
  authority: AuthorizationAuthority = walletAuthorizationAuthority,
): Promise<ScanOutcome> {
  throwIfAborted(input.signal);
  const isVerifiedRequest = input.poolCanisterId !== undefined && input.poolCanisterId !== "";
  // R-1, AC-18: the lease is checked BEFORE anything is constructed or posted.
  // A refusal here has made no wire call, built no worker and read no cache.
  if (isVerifiedRequest) {
    authority.consume(input.authToken, "verifiedScan");
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let worker: Worker | null = null;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      input.signal?.removeEventListener("abort", onAbort);
      if (worker !== null) {
        worker.onmessage = null;
        worker.onerror = null;
        worker.terminate();
      }
      fn();
    };
    const onAbort = () =>
      settle(() => reject(new SessionCancelledError("note scan was cancelled")));
    input.signal?.addEventListener("abort", onAbort, { once: true });
    if (input.signal?.aborted) {
      onAbort();
      return;
    }

    try {
      worker = new Worker(new URL("../workers/scanner.worker.ts", import.meta.url), {
        type: "module",
      });
    } catch (error) {
      settle(() => reject(error));
      return;
    }
    worker.onmessage = (e: MessageEvent<ScannerResponse>) => {
      const msg = e.data;
      if ("progress" in msg) {
        if (!input.signal?.aborted) {
          input.onProgress?.(msg.progress.scannedUpTo, msg.progress.found);
        }
      } else if (msg.ok) {
        if ("noAcceptedRoot" in msg) {
          settle(() => reject(new NoAcceptedRootYetError()));
          return;
        }
        // G1b / SSA F-1: on the verified route the evidence is not optional.
        // The notes in `msg.outcome` are stamped verified; resolving without
        // the metadata would hand the caller a verified-stamped outcome that no
        // floor can be checked against.
        if (isVerifiedRequest && msg.verified === undefined) {
          settle(() => reject(new VerifiedEvidenceMissingError()));
          return;
        }
        if (msg.verified !== undefined) input.onVerified?.(msg.verified);
        settle(() => resolve(msg.outcome));
      } else {
        settle(() => reject(new Error(msg.error)));
      }
    };
    worker.onerror = (e) => settle(() => reject(new Error(e.message)));
    const request: ScannerRequest = {
      merkleCanisterId: input.merkleCanisterId,
      nullifierCanisterId: input.nullifierCanisterId,
      host: input.host,
      ...(input.poolCanisterId !== undefined && input.poolCanisterId !== ""
        ? { poolCanisterId: input.poolCanisterId }
        : {}),
      vetKeySerialized: input.vetKeySerialized,
      masterNoteSecret: input.masterNoteSecret,
      // G1b / SSA F-1, second divergence: the verified route pins `fromIndex`
      // to 0 HERE, at the boundary, exactly as `runVerifiedScan` pins it for
      // the in-process route. `scanAndValidateVerified` also pins it internally
      // when it validates candidates, and both pins stay: a partial note set
      // stamped verified against a FULL-prefix anchor is a lie about what was
      // checked, and it should be impossible to express, not merely unused.
      fromIndex: isVerifiedRequest ? 0n : input.fromIndex,
      pageSize: input.pageSize,
    };
    try {
      worker.postMessage(request);
    } catch (error) {
      settle(() => reject(error));
    }
  });
}

/**
 * THE verified sweep, as the UI performs it (WALLET-AUTH G1b, SSA F-1).
 *
 * This is the route a user's button press actually takes, and it is the reason
 * this function exists at all. At G1 the wallet had two ways into the verified
 * path: `runVerifiedScan` (in-process, floor checked, no caller in `src/`) and
 * the worker route (`runScannerWorker` -> `scanNotes` seam), which returned
 * verified-STAMPED notes and never consulted the floor. Wiring a button to the
 * cheap seam would have closed AC-1 on the function nobody calls. So the worker
 * route now ends where the in-process route ends — in `commitVerifiedScan`,
 * the one function that does the floor check and the floor advance, inside one
 * `cache.update`.
 *
 * WHY THE COMMIT IS INSIDE `update(fn)` and not before it: `fn` runs against
 * the state about to be committed, under the revision CAS. A floor read taken
 * any earlier is a check-then-act window another tab can walk through, which is
 * the one window a monotone floor must not have.
 *
 * WHY THE LEASE IS DRAWN HERE: `runScannerWorker` consumes the token before it
 * constructs the Worker (AC-18), so an unauthorised sweep makes zero wire
 * calls. Drawing it at the top of this function keeps the gesture, the draw and
 * the consume in one visible line rather than spread across the UI.
 *
 * NOT AUTOMATIC. Nothing in this module schedules it; it has exactly one
 * caller, the scan page's button (parent §8: a verified sweep is
 * user-initiated, and periodic verified scanning stays forbidden).
 */
export interface VerifiedSweepInput {
  /** The worker seam — production passes `runScannerWorker`. */
  scanNotes: (input: ScanWorkerInput) => Promise<ScanOutcome>;
  cache: PrincipalNoteCache;
  /** The gesture's lease. Must name `"verifiedScan"`; the token is single-use. */
  lease: OperationLease;
  merkleCanisterId: string;
  nullifierCanisterId: string;
  /** REQUIRED and non-empty: without a pool there is nothing to anchor to. */
  poolCanisterId: string;
  host: string;
  vetKeySerialized: Uint8Array;
  masterNoteSecret: Uint8Array;
  pageSize?: bigint;
  onProgress?: (scannedUpTo: bigint, found: number) => void;
  signal?: AbortSignal;
  /** WL-2a: ONE clock read for the whole merge. Injected so the merge is pure. */
  nowNs?: () => bigint;
  firstSeenVia?: "live-scan" | "recovery-import";
}

export async function runVerifiedSweepViaWorker(
  input: VerifiedSweepInput,
): Promise<{ state: CachedScanState; metadata: VerifiedScanMetadata }> {
  if (input.poolCanisterId === "") {
    throw new VerifiedPathUnavailableError(["poolCanisterId"]);
  }
  const authToken = input.lease.draw("verifiedScan");
  let metadata: VerifiedScanMetadata | undefined;
  const outcome = await input.scanNotes({
    merkleCanisterId: input.merkleCanisterId,
    nullifierCanisterId: input.nullifierCanisterId,
    poolCanisterId: input.poolCanisterId,
    host: input.host,
    authToken,
    onVerified: (m) => {
      metadata = m;
    },
    vetKeySerialized: input.vetKeySerialized,
    masterNoteSecret: input.masterNoteSecret,
    // Pinned here as well as inside `runScannerWorker` and
    // `scanAndValidateVerified`. Three pins is not redundancy for its own sake:
    // this is the layer a future caller would be tempted to parameterise.
    fromIndex: 0n,
    pageSize: input.pageSize,
    onProgress: input.onProgress,
    signal: input.signal,
  });
  // Fail closed. A `scanNotes` seam that resolves without evidence — a stub, a
  // mock, or a future worker reply that loses the field — must not be able to
  // land verified-stamped notes past the floor.
  if (metadata === undefined) throw new VerifiedEvidenceMissingError();
  const seenAtNs = (input.nowNs ?? (() => BigInt(Date.now()) * 1_000_000n))();
  const evidence = metadata;
  const state = await input.cache.update((current) =>
    commitVerifiedScan(current, outcome, evidence, seenAtNs, input.firstSeenVia),
  );
  return { state, metadata: evidence };
}

// ── Verified-scan UI copy ────────────────────────────────────────────────────
//
// G1b: the registered strings moved to `./verifiedScanCopy` so the scan PAGE
// can render them. Pages do not import this module (it imports them), and a
// cycle to fetch six string constants would be a silly way to acquire one.
// Re-exported here UNCHANGED so the registered names, and every existing
// import of them, keep working.
export {
  VERIFIED_SCAN_STRINGS,
  VERIFIED_SCAN_LEAF_CEILING,
  verifiedScanMessage,
} from "./verifiedScanCopy";

export function defaultAppDeps(): AppDeps {
  return {
    origin: window.location.origin,
    buildReadActors: async (config) => createReadActors(await createReadAgent(config), config),
    buildMutationActors: async (config, identity) =>
      createMutationActors(await createMutationAgent(config, identity), config, walletAuthorizationAuthority),
    createAuth: (policy, onIdle) => createWalletAuth(policy, onIdle),
    createJournalStore: (opts) => openIndexedDbJournalStore(undefined, opts),
    buildShieldedActors: async (config, identity) =>
      createShieldedActors(await createMutationAgent(config, identity), config, walletAuthorizationAuthority),
    buildOperatorActors: async (config, identity) =>
      createOperatorActors(await createMutationAgent(config, identity), config),
    createCacheStore: () => openIndexedDbPrincipalCacheStore(),
    now: () => performance.now(),
    scheduleTick: (fn, everyMs) => {
      const handle = setInterval(fn, everyMs);
      return () => clearInterval(handle);
    },
    scanNotes: (input) => runScannerWorker(input),
    // J-25: the ANONYMOUS reader for the release panel's two display queries.
    // Built over `createReadAgent` — the same anonymous agent the read actors
    // use — never over a mutation or shielded identity-bound agent.
    buildPoolIdentityReader: async (config) =>
      config.poolCanisterId === ""
        ? null
        : createPoolIdentityReadActor(config.poolCanisterId, await createReadAgent(config)),
  };
}

/**
 * Mount the wallet. Renders the shell synchronously, then boots actors/auth.
 * The resolved AppContext is returned for tests; production ignores it.
 */
export async function mountApp(
  container: HTMLElement,
  env: Record<string, string | undefined>,
  deps: AppDeps = defaultAppDeps(),
): Promise<AppContext> {
  const resolved = resolveConfig(env);
  // S1-02: the launch origin is loaded BEFORE the policy runs, and a failed load
  // leaves it undefined so the policy refuses. No fallback to a compiled value.
  const config: WalletConfig = {
    ...resolved,
    launchOrigin: await (deps.loadLaunchOrigin ?? (() => loadLaunchOrigin()))(),
    // WT-1: the derivation origin comes from the SAME runtime asset, and is
    // validated by the policy below against the pinned native origin.
    derivationOrigin: await (deps.loadDerivationOrigin ?? (() => loadDerivationOrigin()))(),
  };
  // Origin policy BEFORE any actor/auth construction (A-S8).
  const policy = evaluateSessionPolicy(config, deps.origin);

  const epoch = new SessionEpoch();
  const sessionTasks = new SessionTaskOwner();
  const activeLeases = new Set<OperationLease>();
  const state: AppState = {
    principal: null,
    balance: null,
    busy: false,
    spendLocallyCancellable: false,
    status: null,
    cacheUnlocked: false,
    cacheGate: "none",
    passcodeRequired: null,
    shieldEntries: null,
    notes: [],
    scanning: false,
    lastScanOk: null,
    scanProgress: null,
    mirrorHead: null,
    quarantineTotal: 0,
    // G1b: no verified observation until one is recorded, and no refusal to
    // act on. Both null is the ordinary state, not a failure state.
    verifiedScan: null,
    verifiedRollback: null,
    verifiedScanning: false,
    wipeReport: null,
    submissionDelayEnabled: readSubmissionDelayEnabled(),
    pendingDelay: null,
    quotaNotice: null,
    capacityCountdownSeconds: null,
    spendFeeBasis: null,
    pendingRecovery: [],
    isAdmin: false,
    spendEntries: null,
  };
  let auth: WalletAuth | null = null;
  let journalStore: JournalStore | null = null;
  /** The logged-in principal's journal; null while anonymous. */
  let journal: TransferJournal | null = null;
  /**
   * The session's Layer-1-first key provider (W-VETKEYS). Set when a session is
   * established and cleared on logout, so a stale provider can never serve a
   * different principal's device envelope.
   */
  let sessionFetchKeys: FetchKeys | null = null;
  /**
   * WALLET-CACHE-II-ONLY — the Layer-1 envelope binding for THIS session (the
   * vetkeys canister + owner), so the derive-free sign-in open can call
   * `openThisDevicesVetKey` directly, never the Layer-2-capable provider above.
   * Null when no Layer-1 provider exists; set and cleared with the session.
   */
  let sessionLayer1: { canisterId: Principal; owner: Principal } | null = null;
  /**
   * The opt-in passcode (O-3) the user typed THIS session, held so the session
   * provider can reopen this device's passcode envelope for scan/spend/shield.
   * MEMORY ONLY, never persisted (HARD RULE, noteCache.ts), and dropped with
   * every other session secret in `clearSessionState` and on a session switch.
   */
  let sessionPasscode: string | null = null;
  /** Which key opened the current cache: decides what Settings and unlock do. */
  let cacheKeyMode: "passphrase" | "ii-only" | "passcode" | null = null;
  /**
   * The in-flight derive-free sign-in open, so callers can wait for it. Keyed
   * by the session epoch it serves: a run left over from an ended session must
   * never stand in for the open of the NEXT one (it bails at its first epoch
   * check and would leave the new session's gate at "opening").
   */
  let signInOpenRun: { epoch: number; run: Promise<void> } | null = null;
  /** The current session's in-flight sign-in open, or null. */
  const signInOpenFor = (captured: number): Promise<void> | null =>
    signInOpenRun !== null && signInOpenRun.epoch === captured ? signInOpenRun.run : null;
  /**
   * Every cache OPEN (sign-in, first action, passcode, migration, toggle) runs
   * one at a time: `openForSession*` locks the previously issued instance, so
   * two overlapping opens would each lock the other's cache out from under it.
   */
  let cacheOpenChain: Promise<unknown> = Promise.resolve();
  // ── L3a shielded session state ────────────────────────────────────────────
  const cacheManager = new CacheSessionManager(epoch);
  /** The restored/logged-in II session — needed to open the note cache. */
  let currentSession: AuthSession | null = null;
  let cacheStore: PrincipalCacheStore | null = null;
  /** The unlocked session's encrypted shield journal; null until unlock. */
  let shieldJournal: ShieldJournal | null = null;
  /** Why the shielded actors could not be built (unconfigured ids), if so. */
  let shieldedActorsError: string | null = null;
  /**
   * J-17c — why the anonymous read actors could not be built, or null if they
   * were. Drives the PERSISTENT status-bar notice: it sits beside the transient
   * status so a later message cannot wipe it, because the condition it reports
   * does not go away for the life of the mount.
   */
  let readActorsError: string | null = null;
  /**
   * J-17e — why the identity-bound MUTATION actors could not be built, or null
   * if they were. Persistent for the same reason `readActorsError` is: an
   * unconfigured ledger is a property of the deployment, and a transient boot
   * failure has no retry path within the session either. A transient status
   * line would be wiped by the next event (see `AppState.quotaNotice`).
   */
  let mutationActorsError: string | null = null;
  /** J-17e — why this session has no transfer journal (blocked device storage). */
  let journalStoreError: string | null = null;

  const content = el("main", { class: "content" });
  const statusBar = el("div", { class: "status" });
  const navLinks = NAV_ROUTES.map((route) =>
    el("a", { href: routeHref(route), "data-route": route }, [ROUTE_LABELS[route]]),
  );
  // WALLET-UI: a header indicator of the session state, repainted with the route.
  // WALLET-UX: the header account control. Signed in, it opens a menu with the
  // principal (copyable) and Log out; signed out, it is a Log in button.
  const sessionPill = el(
    "button",
    {
      type: "button",
      class: "session-pill",
      "data-testid": "session-pill",
      "aria-haspopup": "true",
      "aria-expanded": "false",
    },
    ["Log in"],
  ) as HTMLButtonElement;
  const sessionMenu = el("div", { class: "session-menu", role: "menu", "data-testid": "session-menu", hidden: true });
  const sessionBox = el("div", { class: "session" }, [sessionPill, sessionMenu]);
  const closeSessionMenu = () => {
    sessionMenu.hidden = true;
    sessionPill.setAttribute("aria-expanded", "false");
  };
  sessionPill.addEventListener("click", () => {
    if (state.principal === null) {
      void ctx.login();
      return;
    }
    const opening = sessionMenu.hidden;
    sessionMenu.hidden = !opening;
    sessionPill.setAttribute("aria-expanded", opening ? "true" : "false");
  });
  document.addEventListener("click", (e) => {
    if (!sessionBox.contains(e.target as Node)) closeSessionMenu();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeSessionMenu();
  });
  window.addEventListener("hashchange", closeSessionMenu);
  function paintSessionMenu(): void {
    clear(sessionMenu);
    const principal = state.principal;
    if (principal === null) {
      closeSessionMenu();
      return;
    }
    const text = principal.toText();
    sessionMenu.append(
      el("div", { class: "session-menu-label" }, ["Signed in as"]),
      el("div", { class: "session-menu-principal", title: text }, [shortPrincipal(text)]),
      el("div", { class: "session-menu-actions" }, [
        copyButton(text, "Copy address"),
        el(
          "button",
          {
            type: "button",
            class: "small",
            role: "menuitem",
            "data-testid": "header-logout",
            disabled: state.busy,
            onclick: () => {
              closeSessionMenu();
              void ctx.logout();
            },
          },
          ["Log out"],
        ),
      ]),
    );
  }
  let current: Route = "account";
  /** Whether `renderRoute` has run once — see the route-change clear there. */
  let routeRendered = false;

  function setStatus(status: AppStatus | null): void {
    // A status REPLACING the capacity refusal ends the countdown (V4 §5.4):
    // the message it was counting for is gone. The countdown's own re-render
    // passes `state.status` back unchanged and is exempt.
    if (status !== state.status) {
      stopCapacityCountdown();
      // V5 §6.6: a status replacing the preparation notice cancels its retry —
      // the message it was waiting for is gone, and a call made after the user
      // has moved on spends their meter allowance for nothing.
      stopPreparationRetry();
    }
    state.status = status;
  }

  /**
   * Show the key-recovery allowance when it is worth showing (D-1 clause 4).
   *
   * Only ever REPLACES a status the user is not otherwise reading: it fires
   * after a successful acquisition, so there is no error on screen to stomp.
   */
  function reportQuota(remaining: number | null): void {
    // VK-M1: `null` is the Layer-1 fast path — NO derive happened, so the
    // canister said nothing about the quota and this call carries NO verdict.
    // A standing warning ("N left today") set by a real derive must survive
    // ordinary scans/logins that ride the fast path; clearing it here is how
    // the warning used to vanish before the user ever acted on it.
    if (remaining === null) return;
    // Stored, not flashed: see AppState.quotaNotice for why this cannot be a
    // status line. Only a REAL derive updates the notice — and a recovered
    // allowance (above the warn threshold) maps to `null` here, so it stops
    // warning without the user having to reload.
    state.quotaNotice = quotaNotice(remaining);
  }

  /** Cancels the live capacity countdown, if any. Idempotent. */
  let cancelCountdown: (() => void) | null = null;

  /**
   * Stop the countdown and clear what it was showing.
   *
   * Called on every exit the brief names: reaching zero, a status replacing the
   * refusal, a route change, and teardown. A countdown that outlived its
   * message would keep ticking against a deadline nothing on screen mentions.
   */
  function stopCapacityCountdown(): void {
    if (cancelCountdown !== null) {
      cancelCountdown();
      cancelCountdown = null;
    }
    if (state.capacityCountdownSeconds !== null) {
      state.capacityCountdownSeconds = null;
    }
  }

  /**
   * Start the waitlist countdown for a fleet-capacity refusal (V4 §5.4).
   *
   * The deadline is captured IN MEMORY as `now() + retry_after_ms` on a
   * MONOTONIC clock and is never persisted: a stored wall-clock deadline
   * survives into a session where it means nothing, and would show a user a
   * countdown computed against a clock that has since moved.
   */
  function startCapacityCountdown(seconds: number): void {
    stopCapacityCountdown();
    const clock = deps.now ?? (() => performance.now());
    const schedule =
      deps.scheduleTick ??
      ((fn: () => void, everyMs: number) => {
        const handle = setInterval(fn, everyMs);
        return () => clearInterval(handle);
      });
    const deadline = clock() + seconds * 1_000;
    const remaining = (): number => Math.max(0, Math.ceil((deadline - clock()) / 1_000));
    state.capacityCountdownSeconds = remaining();
    cancelCountdown = schedule(() => {
      const left = remaining();
      state.capacityCountdownSeconds = left;
      if (left <= 0) {
        // Zero is an exit, not a resting state: stop the timer, then render
        // once more so the final value is what the user sees.
        stopCapacityCountdown();
      }
      renderStatus();
    }, 1_000);
  }

  // ── V5 §6.6 — the ONE automatic retry at the age deadline ────────────────
  //
  // WHY AUTOMATIC, AND WHY EXACTLY ONE. The on-ramp is hands-off: a user who
  // has funded their wallet should not have to come back and press a button
  // fifteen minutes later. But POLLING IS ACTIVELY HARMFUL here — the A-2 meter
  // charges every attempt at five per hour, so a client polling through a
  // fifteen-minute wait can exhaust its own allowance at the exact instant the
  // wait ends, turning the wait into a refusal. So: one shot, at the deadline
  // the canister named, and never an interval of network calls.
  let cancelPreparationRetry: (() => void) | null = null;
  /**
   * THE ONE-SHOT BUDGET, EXPLICIT (SSA GREEN-4).
   *
   * A retry that is itself age-refused must NOT arm a third attempt. Left
   * implicit, the refusal handler would re-enter itself and the "one retry"
   * would become an unbounded chain with a fifteen-minute period — the polling
   * loop this design exists to avoid, arrived at by recursion instead of by a
   * timer. This counter is what makes that impossible rather than unlikely.
   */
  let preparationRetriesArmed = 0;

  // ── VETKEYS-AGE-2MIN — login-time priming (A1 notes v3 AD-4 / A.10.2) ────
  //
  // Per-principal preparation deadlines on the injected MONOTONIC clock (ms):
  // `now + ceil(retry_after_ns / 1e9) * 1000`. In memory only — NEVER persisted
  // and NOT cleared by logout, like the latch state below — and deleted on a
  // successful key acquisition. Separate from `preparationRetriesArmed`, which
  // is the scan path's own one-shot retry budget and is never touched here.
  const preparationDeadlines = new Map<string, number>();
  /**
   * Principal (`toText()`) of the ONE priming dispatch in flight in THIS tab,
   * or null. Acquired synchronously before the first await; released only by
   * its owner. A SECOND TAB is a separate module instance with its own latch —
   * the cross-tab race is a disclosed residual, not closed here.
   */
  let primingInFlightFor: string | null = null;
  /**
   * Principals attempted at least once this page mount. Marked BEFORE
   * dispatch and NEVER cleared — not by any outcome, not by
   * `clearSessionState`: one priming dispatch per principal per mount.
   */
  const primingAttempted = new Set<string>();

  /** Cancel any outstanding preparation retry. Idempotent. */
  function stopPreparationRetry(): void {
    if (cancelPreparationRetry !== null) {
      cancelPreparationRetry();
      cancelPreparationRetry = null;
    }
  }

  /**
   * Arm EXACTLY ONE retry at `now + seconds` on the injected monotonic clock
   * and the injected scheduler — the same pair the capacity countdown uses,
   * reused rather than duplicated.
   *
   * A repeated age refusal REPLACES the single outstanding deadline; it never
   * adds a second. And once the budget is spent, nothing re-arms.
   */
  function armPreparationRetry(seconds: number, retry: () => void): void {
    if (preparationRetriesArmed >= 1) return;
    preparationRetriesArmed += 1;
    stopPreparationRetry();
    const clock = deps.now ?? (() => performance.now());
    const schedule =
      deps.scheduleTick ??
      ((fn: () => void, everyMs: number) => {
        const handle = setInterval(fn, everyMs);
        return () => clearInterval(handle);
      });
    const deadline = clock() + seconds * 1_000;
    // The ticker is a CLOCK WATCH, not a request loop: it fires no network call
    // until the deadline, then cancels itself and makes exactly one.
    cancelPreparationRetry = schedule(() => {
      if (clock() < deadline) return;
      stopPreparationRetry();
      retry();
    }, 1_000);
  }

  /**
   * Render a REFUSED key acquisition. Returns true when the error was a rate
   * limit and has been shown with its wait, so callers can skip their generic
   * message rather than printing two.
   *
   * THE LEVEL IS MAPPED, NOT HARDCODED (V4 §5.3). A fleet-capacity refusal is
   * `"info"`: the user did nothing wrong and has nothing to fix. Their OWN
   * allowance running out stays `"error"`, exactly as before. `"warning"` maps
   * to `"info"` explicitly rather than falling through by accident, because
   * `AppStatus.kind` has no warning level.
   */
  function reportQuotaRefusal(err: unknown, retry?: () => void): boolean {
    if (!(err instanceof VetkeysCallError)) return false;
    const notice = quotaRefusalNotice(err.error);
    if (notice === null) return false;
    const kind: AppStatus["kind"] = notice.level === "error" ? "error" : "info";
    setStatus({ kind, msg: notice.message });
    // The waitlist countdown accompanies ONLY the fleet refusal — the other
    // refusals are statements about this user, not a queue they are waiting in.
    if ("GlobalDerivationBudgetExceeded" in err.error) {
      const seconds = retryAfterSeconds(err.error);
      if (seconds !== null) startCapacityCountdown(seconds);
    }
    // V5 §6.6 — the first-time preparation wait arms ONE automatic retry.
    if ("EligibilityAgeNotMet" in err.error && retry !== undefined) {
      const seconds = retryAfterSeconds(err.error);
      if (seconds !== null) armPreparationRetry(seconds, retry);
    }
    return true;
  }

  /**
   * J-17e / SSA F-5 — why a mutation is refused RIGHT NOW.
   *
   * Before this lane the only reachable reason was "while anonymous", so both
   * refusal sites hardcoded it. A logged-in session with null mutation actors
   * or no journal is now reachable, and telling that user they are anonymous
   * while their own principal is on screen is a false statement. Order matters:
   * the anonymous case is checked first because it is the only one the user can
   * act on by logging in.
   */
  function mutationRefusalReason(verb: "transfer" | "shield"): string {
    if (state.principal === null) {
      return `Log in to ${verb} — mutations are refused while anonymous.`;
    }
    if (ctx.mutationActors === null) {
      return mutationActorsError ?? TRANSFER_SERVICES_UNCONFIGURED;
    }
    if (journal === null) return DEVICE_STORAGE_UNAVAILABLE;
    return TRANSFER_SERVICES_UNCONFIGURED;
  }

  function renderStatus(): void {
    clear(statusBar);
    if (state.status) {
      // WALLET-SHIELD-LAYER1 (Owner Addendum A item 6): the last action's
      // banner is dismissable. Only `state.status` gets the ×; the persistent
      // service notices below describe the deployment, not an action, and stay.
      const dismiss = el(
        "button",
        {
          type: "button",
          class: "status-dismiss",
          "aria-label": "Dismiss message",
          "data-testid": "status-dismiss",
        },
        ["×"],
      );
      dismiss.addEventListener("click", () => {
        setStatus(null);
        renderStatus();
      });
      const { lines, action } = state.status;
      const text =
        lines !== undefined && lines.length > 0
          ? el("div", { class: "status-text" }, lines.map((line) => el("p", {}, [line])))
          : el("span", { class: "status-text" }, [state.status.msg]);
      const actionBtn =
        action !== undefined
          ? [
              el("button", { type: "button", "data-testid": "status-action", onclick: () => action.run() }, [
                action.label,
              ]),
            ]
          : [];
      statusBar.append(
        el("div", { class: `status-msg ${state.status.kind} dismissable`, "data-testid": "status-msg" }, [
          text,
          ...actionBtn,
          dismiss,
        ]),
      );
    }
    // J-17c: the read-services notice. Persistent, because the missing
    // canisters are a property of the deployment, not of the last action.
    if (readActorsError !== null) {
      statusBar.append(
        el(
          "div",
          { class: "status-msg error read-services", "data-testid": "read-services-notice" },
          [READ_SERVICES_UNAVAILABLE],
        ),
      );
    }
    // J-17e: the transfer-services notices, on the same persistence reasoning.
    // Two fields, not one, because the two causes are different facts and a
    // session can hit both at once.
    if (mutationActorsError !== null) {
      statusBar.append(
        el(
          "div",
          { class: "status-msg error transfer-services", "data-testid": "transfer-services-notice" },
          [mutationActorsError],
        ),
      );
    }
    if (journalStoreError !== null) {
      statusBar.append(
        el(
          "div",
          { class: "status-msg error device-storage", "data-testid": "device-storage-notice" },
          [DEVICE_STORAGE_UNAVAILABLE],
        ),
      );
    }
    // The waitlist countdown, beneath the refusal it belongs to.
    if (state.capacityCountdownSeconds !== null) {
      statusBar.append(
        el("div", { class: "status-msg capacity-countdown info" }, [
          `Next spot in ${state.capacityCountdownSeconds}s`,
        ]),
      );
    }
    // The key-recovery allowance sits BESIDE the transient status, so a scan
    // completing does not wipe a warning the user needs (D-1 clause 4).
    if (state.quotaNotice !== null) {
      statusBar.append(
        el("div", { class: `status-msg quota ${state.quotaNotice.level}` }, [
          state.quotaNotice.message,
        ]),
      );
    }
    // WL-2c: a delay the user cannot see or stop is a hang, not a feature.
    // This banner lives in the shell, not on one page, because the wait spans
    // whatever the user does next.
    const pending = state.pendingDelay;
    if (pending !== null) {
      const cancelBtn = el("button", { class: "delay-cancel" }, ["Cancel"]);
      cancelBtn.addEventListener("click", () => pending.cancel());
      const nowBtn = el("button", { class: "delay-now" }, ["Submit now"]);
      nowBtn.addEventListener("click", () => pending.submitNow());
      statusBar.append(
        el("div", { class: "status-msg info pending-delay" }, [
          `Holding this ${pending.kind} for ${Math.round(pending.delayMs / 1000)}s before ` +
            `submitting, so its timing is not tied to your action. Nothing has been sent yet.`,
          cancelBtn,
          nowBtn,
        ]),
      );
    }
    // WL-2b §4.3: recovery repairs that would go on chain are listed, never
    // performed, until the user says so.
    if (state.pendingRecovery.length > 0) {
      const applyBtn = el("button", { class: "recovery-apply" }, [
        `Submit ${state.pendingRecovery.length} recovery action${
          state.pendingRecovery.length === 1 ? "" : "s"
        }`,
      ]);
      applyBtn.addEventListener("click", () => {
        void ctx.applySpendRecovery();
      });
      statusBar.append(
        el("div", { class: "status-msg info pending-recovery" }, [
          `${state.pendingRecovery.length} interrupted send${
            state.pendingRecovery.length === 1 ? "" : "s"
          } can be finished on chain (${state.pendingRecovery
            .map((r) => `${r.spendId}: ${r.action}`)
            .join(", ")}). Nothing is sent until you confirm.`,
          applyBtn,
        ]),
      );
    }
    // WALLET-UX: the delay toggle lives in Settings > Privacy and on the send
    // review; the pending-delay banner above stays here because the wait spans
    // whatever the user does next.
  }

  function renderRoute(route: Route): void {
    // A route change ends the countdown (V4 §5.4) — the refusal it belongs to
    // is no longer on screen.
    if (route !== current) {
      stopCapacityCountdown();
      stopPreparationRetry();
      // WALLET-SHIELD-LAYER1 (Addendum A item 6): the last action's banner
      // belongs to the page it was raised on, so a real route change clears it.
      // Not before the first route has rendered (a boot-time status must reach
      // the user whatever page the URL opens on), and not while an operation
      // is running (its progress line is live and will be repainted).
      if (routeRendered && !state.busy) setStatus(null);
    }
    routeRendered = true;
    current = route;
    for (const link of navLinks) {
      // WALLET-UX: task pages light up the destination they belong to.
      const owner: Route =
        route === "shield" || route === "spend" || route === "scan" || route === "balance"
          ? "account"
          : route === "staking" || route === "vesting" || route === "operator"
            ? "settings"
            : route;
      link.className = link.getAttribute("data-route") === owner ? "active" : "";
      if (link.className === "active") link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    const loggedIn = state.principal !== null;
    sessionPill.className = loggedIn ? "session-pill is-in" : "session-pill is-out";
    sessionPill.textContent = loggedIn ? "Logged in" : "Log in";
    sessionPill.disabled = !loggedIn && (policy.kind === "blocked" || state.busy);
    paintSessionMenu();
    content.setAttribute("data-route", route);
    // WALLET-UI addendum 1: the J-25 release panel (pool circuit/VK agreement,
    // including the "disagrees" state) is a user-facing supply-chain signal,
    // not an admin diagnostic — every logged-in user sees it on Settings.
    // O-6 (Owner 2026-09-23): kept, under Settings → "Verify this build",
    // collapsed by default, and never on Home.
    const verifyEl = container.querySelector<HTMLElement>('[data-testid="verify-build"]');
    if (verifyEl !== null) verifyEl.hidden = !(loggedIn && route === "settings");
    // WALLET-UI fix (Addendum 1 ruling 2): NO automatic Vault `get_signers`.
    // Nobody can be known to be an operator without asking the Vault, so any
    // automatic lookup is a lookup for non-operators too. The signer check
    // runs only when the user presses "Check operator access" in Settings
    // (`ctx.checkOperatorAccess`).
    clear(content);
    switch (route) {
      case "activity":
        renderActivity(content, ctx);
        void loadActivity();
        break;
      case "settings":
        renderSettings(content, ctx);
        break;
      case "account":
        renderAccount(content, ctx);
        break;
      case "staking":
        renderStaking(content, ctx);
        break;
      case "vesting":
        renderVesting(content, ctx);
        break;
      case "shield":
        renderShieldGate();
        break;
      case "scan":
        renderScanGate();
        break;
      case "balance":
        renderBalanceGate();
        break;
      case "spend":
        renderSpendGate();
        break;
      case "operator":
        // No gate wrapper: the page owns BOTH refusals itself (the origin hard
        // block and the session requirement), so the reasons stay next to the
        // custody copy that explains them.
        renderOperator(content, ctx);
        break;
      case "not-available":
        renderNotAvailable();
        break;
    }
    renderStatus();
  }

  function renderSpendGate(): void {
    if (shieldedRouteGate("Send")) {
      renderSpend(content, ctx);
    }
  }

  /**
   * WALLET-CACHE-II-ONLY Addendum 3 §6 — the ruled copy for a device with no key
   * envelope yet. "About N s" only while a preparation deadline is live (SSA
   * B1); otherwise the first line stands alone.
   */
  function preparingCopy(): string {
    const principal = state.principal;
    const seconds = principal === null ? null : livePreparationSeconds(principal.toText());
    return seconds === null
      ? "Your wallet is getting ready. First shield or sync opens it."
      : `Your wallet is getting ready. First shield or sync opens it. About ${seconds} s.`;
  }

  function preparingNote(): HTMLElement {
    return el("p", { class: "gate-note", "data-testid": "cache-gate-preparing" }, [preparingCopy()]);
  }

  /**
   * WALLET-CACHE-II-ONLY — what a private route shows while the private balance
   * is not open. There is NO passphrase input here in any state but the two
   * that genuinely need a typed secret: this device's opt-in PASSCODE, and the
   * one-time move of an OLD passphrase record (O-2). A device without a key
   * envelope is never offered a passphrase as a way round (AC-4): it waits for
   * the first shield or sync, which is the one sanctioned key request.
   */
  function renderPrivateGate(title: string): void {
    content.append(el("a", { class: "back-link", href: "#/account" }, ["← Home"]), el("h2", {}, [title]));
    switch (state.cacheGate ?? "none") {
      case "passcode":
        renderPasscodeCard();
        return;
      case "migrate":
        renderMigrationCard();
        return;
      case "opening":
        content.append(
          el("p", { class: "muted", "data-testid": "cache-gate-opening" }, ["Opening your private balance…"]),
        );
        return;
      case "error":
        content.append(
          el("p", { class: "gate-note", "data-testid": "cache-gate-error" }, ["Couldn't open your private balance."]),
          el("div", { class: "row" }, [
            el(
              "button",
              {
                class: "primary",
                "data-testid": "cache-gate-retry",
                disabled: state.busy,
                onclick: () => void ctx.retryPrivateOpen?.(),
              },
              ["Try again"],
            ),
          ]),
        );
        return;
      default:
        content.append(
          preparingNote(),
          el("div", { class: "row" }, [
            el(
              "button",
              { class: "primary", "data-testid": "gate-sync", disabled: state.busy, onclick: () => void ctx.scan() },
              ["Sync now"],
            ),
          ]),
        );
    }
  }

  /** O-3: this device's opt-in passcode. The only unlock card with an input. */
  function renderPasscodeCard(): void {
    const pass = el("input", {
      type: "password",
      placeholder: "Passcode",
      "aria-label": "Passcode",
      autocomplete: "current-password",
      class: "amount",
      "data-testid": "cache-passcode",
    }) as HTMLInputElement;
    const unlock = el("button", { class: "primary wide", disabled: state.busy }, ["Unlock"]);
    const go = () => void ctx.unlockWithPasscode?.(pass.value);
    unlock.addEventListener("click", go);
    pass.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") go();
    });
    content.append(
      el("p", { class: "page-sub" }, ["Enter your passcode for this device."]),
      pass,
      unlock,
      el("p", { class: "muted" }, [
        "Forgot it? ",
        el("a", { href: "#/settings" }, ["Wipe this device"]),
        ", then sign in again. Your balance comes back from the chain.",
      ]),
    );
  }

  /**
   * O-2: the ONE-TIME move of an old passphrase record. Shown only when this
   * principal's record on this device is still a passphrase record; it never
   * reappears once the move lands (the record is no longer version 2).
   */
  function renderMigrationCard(): void {
    const pass = el("input", {
      type: "password",
      placeholder: "Old passphrase",
      "aria-label": "Old passphrase",
      autocomplete: "current-password",
      class: "amount",
      "data-testid": "migrate-passphrase",
    }) as HTMLInputElement;
    const keep = el("input", { type: "checkbox", "data-testid": "migrate-keep" }) as HTMLInputElement;
    const go = el(
      "button",
      { class: "primary wide", "data-testid": "migrate-submit", disabled: state.busy },
      ["Move my notes"],
    );
    go.addEventListener("click", () => {
      void ctx.migrateNoteCache?.({ passphrase: pass.value, keepAsPasscode: keep.checked });
    });
    content.append(
      el("div", { "data-testid": "cache-migrate" }, [
        el("p", { class: "page-sub" }, ["Enter your old passphrase once."]),
        el("p", { class: "muted" }, ["After that, signing in opens your wallet."]),
        pass,
        el("label", { class: "radio" }, [keep, " Keep it as a passcode for this device"]),
        go,
      ]),
    );
  }

  /** Shared login/private-balance gate for the private routes. */
  function shieldedRouteGate(title: string): boolean {
    if (policy.kind === "blocked") {
      content.append(el("p", { class: "muted" }, [policy.reason]));
      return false;
    }
    if (state.principal === null) {
      content.append(
        el("h2", {}, [title]),
        el("p", { class: "muted" }, ["Log in with Internet Identity to continue."]),
        el("div", { class: "row" }, [
          el("button", { class: "primary", onclick: () => void ctx.login() }, ["Log in"]),
        ]),
      );
      return false;
    }
    if (!state.cacheUnlocked) {
      renderPrivateGate(title);
      return false;
    }
    return true;
  }

  function renderScanGate(): void {
    if (shieldedRouteGate("Sync")) {
      renderScan(content, ctx);
    }
  }

  function renderBalanceGate(): void {
    if (shieldedRouteGate("Private balance")) {
      renderBalance(content, ctx);
    }
  }

  /**
   * Shield route preconditions (L3a): logged in, then the private balance open
   * — the encrypted shield journal lives in the cache, and journal-before-submit
   * (§1.1 rule 4) is impossible while it is closed. On a device with no key
   * envelope yet the form still renders: the first shield IS the action that
   * opens it (Addendum 3), so the page says so above the form.
   */
  function renderShieldGate(): void {
    if (policy.kind === "blocked") {
      content.append(el("p", { class: "muted" }, [policy.reason]));
      return;
    }
    if (state.principal === null) {
      content.append(
        el("h2", {}, ["Shield a deposit"]),
        el("p", { class: "muted" }, ["Log in with Internet Identity to shield STSH."]),
        el("div", { class: "row" }, [
          el("button", { class: "primary", onclick: () => void ctx.login() }, ["Log in"]),
        ]),
      );
      return;
    }
    if (!state.cacheUnlocked) {
      if ((state.cacheGate ?? "none") === "preparing") {
        renderShield(content, ctx);
        const anchor = content.querySelector(".exit-disclosure");
        const note = preparingNote();
        if (anchor !== null) anchor.before(note);
        else content.prepend(note);
        return;
      }
      renderPrivateGate("Shield STSH");
      return;
    }
    renderShield(content, ctx);
  }

  function renderNotAvailable(): void {
    content.append(
      el("h2", {}, ["Not available in this build"]),
      el("p", { class: "muted", "data-testid": "not-available" }, [
        "This build includes the account, staking and vesting views only. " +
          "Shielded-pool features (shield / spend / scan) are not part of this release.",
      ]),
      el("div", { class: "row" }, [
        el("button", { class: "primary", onclick: () => ctx.navigate("account") }, ["Go to account"]),
      ]),
    );
  }

  const router = new HashRouter(renderRoute);

  async function applySession(
    session: AuthSession,
    captured: number,
  ): Promise<boolean> {
    const identity = session.identity;
    const principal = session.principal;
    // Build the identity-bound actors AND the principal-scoped journal BEFORE
    // committing, then commit atomically under the epoch check — a logout or
    // competing login that raced us discards the whole result.
    // J-17e: the reported crash. `createMutationActors` calls
    // `createTokenMutationActor(config.tokenCanisterId, …)`, which throws
    // `Canister ID is required` while the ledger id is "" (until J-18/A-7).
    // This await was UNGUARDED, unlike the shielded and operator blocks below,
    // so the rejection dropped the whole session — at login AND, through the
    // restore catch, as "Could not restore the previous session: …".
    //
    // The catch records null and FALLS THROUGH. It must never `return false`
    // or rethrow: that is the original bug. The epoch check stays AFTER it,
    // and `epoch.commit` below remains the sole commit point (SSA F-7).
    let actors: MutationActors | null = null;
    let mutationUnavailable: string | null = null;
    try {
      actors = await deps.buildMutationActors(config, identity);
    } catch (err) {
      actors = null;
      mutationUnavailable =
        config.tokenCanisterId === ""
          ? TRANSFER_SERVICES_UNCONFIGURED
          : transferServicesUnavailable(err instanceof Error ? err.message : String(err));
    }
    if (!epoch.isCurrent(captured)) return false;
    // L3a: shielded actors are best-effort at session start — a missing or
    // invalid pool/vetkeys configuration records null and shield() surfaces
    // the reason on use (fail closed at the action, not at login).
    let shielded: ShieldedActors | null = null;
    let shieldedUnavailable: string | null = null;
    if (deps.buildShieldedActors !== undefined) {
      try {
        shielded = await deps.buildShieldedActors(config, identity);
      } catch (err) {
        shieldedUnavailable = err instanceof Error ? err.message : String(err);
      }
    }
    // J-17b: same best-effort treatment — a misconfigured custody ring must not
    // fail LOGIN, it must make the operator route say so on use.
    let operator: OperatorActors | null = null;
    if (deps.buildOperatorActors !== undefined) {
      try {
        operator = await deps.buildOperatorActors(config, identity);
      } catch {
        operator = null;
      }
    }
    if (!epoch.isCurrent(captured)) return false;
    // J-17e / SSA F-1: the same class of unguarded await, twice more. Both
    // `createJournalStore` and `loadUnresolved` are IndexedDB operations that
    // reject on a device with blocked or partitioned storage, and both landed
    // in the same restore catch with the same dropped session. Guarded as one
    // block because a journal store with no readable journal is not usable
    // either. Falls through on failure — never `return false` (SSA F-7b).
    let sessionJournal: TransferJournal | null = null;
    let pending: TransferIntentRecord | null = null;
    let journalUnavailable: string | null = null;
    try {
      if (journalStore === null) {
        journalStore = await deps.createJournalStore({
          onBlocked: () => {
            // AC-1c: an old-version tab is blocking the storage upgrade — say so
            // actionably instead of hanging in a silent loading state.
            setStatus({
              kind: "error",
              msg: "Another STSH wallet tab (an older version) is blocking a storage upgrade — close or refresh your other wallet tabs, then reload this page.",
            });
            renderRoute(current);
          },
        });
      }
      if (!epoch.isCurrent(captured)) return false;
      sessionJournal = new TransferJournal(journalStore, {
        ownerPrincipal: principal.toText(),
        ledgerCanisterId: config.tokenCanisterId,
        network: config.host,
      });
      // Recover THIS principal's unresolved intent only — another owner's
      // envelope on the same device is invisible here (A-S14).
      pending = await sessionJournal.loadUnresolved();
    } catch (err) {
      journalStore = null;
      sessionJournal = null;
      pending = null;
      journalUnavailable = err instanceof Error ? err.message : String(err);
    }
    // W-VETKEYS Layer 1: from here on, THIS session acquires the vetKey by
    // opening this device's envelope — zero derives — and only falls back to a
    // Layer-2 ceremony (which immediately enrols the device) if this browser is
    // not yet a registered device for this principal.
    // A malformed or absent vetkeys canister id must not break LOGIN: the
    // envelope binding needs a real principal, so without one we simply have no
    // Layer-1 provider and the existing Layer-2 path stands. Failing the whole
    // session over a key-service misconfiguration would be a worse outcome than
    // paying for a derive.
    let vetkeysPrincipal: Principal | null = null;
    try {
      vetkeysPrincipal = Principal.fromText(config.vetkeysCanisterId);
    } catch {
      vetkeysPrincipal = null;
    }
    // WALLET-CACHE-II-ONLY SSA C1: the provider is wrapped SINGLE-FLIGHT, so the
    // login-time priming attempt and a first shield/sync can never run two
    // Layer-2 ceremonies at once — the second caller awaits the first
    // (`singleFlightFetchKeys`, vetkeyAccess.ts). `requestPasscode` hands back
    // the passcode typed THIS session, or null (fail closed, never a derive).
    const layer1 = vetkeysPrincipal === null ? null : singleFlightFetchKeys(createSessionFetchKeys({
      canisterId: vetkeysPrincipal,
      owner: principal,
      loadDevice: () => loadSessionDevice(principal.toText()),
      requestPasscode: async () => sessionPasscode,
      saveDevice: async (identity) =>
        saveDeviceIdentity(principal.toText(), {
          deviceId: identity.deviceId,
          encSpki: identity.encSpki,
          signSpki: identity.signSpki,
          encPrivate: identity.keys.encryption.privateKey,
          encPublic: identity.keys.encryption.publicKey,
          signPrivate: identity.keys.signing.privateKey,
          signPublic: identity.keys.signing.publicKey,
        }),
      createDevice: async () => {
        const keys = await generateDeviceKeys();
        const pub = await exportDevicePublicKeys(keys);
        return {
          deviceId: randomDeviceId(),
          keys,
          encSpki: pub.encSpki,
          signSpki: pub.signSpki,
        };
      },
    }));

    const applied = epoch.commit(captured, () => {
      ctx.mutationActors = actors;
      ctx.shieldedActors = shielded;
      ctx.operatorActors = operator;
      shieldedActorsError = shieldedUnavailable;
      mutationActorsError = mutationUnavailable;
      journalStoreError = journalUnavailable;
      ctx.journalAvailable = sessionJournal !== null;
      currentSession = session;
      state.principal = principal;
      // VETKEYS-AGE-2MIN (C-1): every session commit — first login, restore,
      // OR a re-login over an existing session without an intervening logout —
      // starts from a clean, unknown balance, so a previous principal's
      // observed balance can never open the priming gate for this one.
      state.balance = null;
      journal = sessionJournal;
      ctx.pendingIntent = pending;
      sessionFetchKeys = layer1;
      // WALLET-CACHE-II-ONLY: a new session starts with no passcode, no open
      // cache and an unknown envelope mode. A cache opened under an EARLIER
      // epoch is unusable from here on (its binding is stale), so it is not
      // reported as open either.
      sessionLayer1 = vetkeysPrincipal === null ? null : { canisterId: vetkeysPrincipal, owner: principal };
      sessionPasscode = null;
      cacheKeyMode = null;
      shieldJournal = null;
      state.cacheUnlocked = false;
      state.cacheGate = sessionLayer1 === null ? "none" : "opening";
      state.passcodeRequired = null;
    });
    // WALLET-UI (rebase onto VETKEYS-AGE-2MIN): the automatic post-login
    // balance refresh is OWNED by the login/restore paths
    // (`refreshBalance().then(primeFirstDeriveSighting)`); this lane no longer
    // adds a second one here (Addendum 1 ruling 2: do not duplicate).
    return applied;
  }

  // WALLET-UI: guards `ensureAdminChecked` (user-initiated only, via
  // `ctx.checkOperatorAccess`) so repeated presses make at most one Vault call
  // per session, until a failure, which allows a retry on the next press.
  let adminLookupStarted = false;

  async function ensureAdminChecked(captured: number): Promise<void> {
    if (adminLookupStarted) return;
    const principal = state.principal;
    const operator = ctx.operatorActors;
    if (principal === null || operator === null) return;
    adminLookupStarted = true;
    try {
      const signers = await operator.vault.getSigners();
      const isAdmin = signers !== null && signers.some((p) => p.toText() === principal.toText());
      if (epoch.commit(captured, () => {
        state.isAdmin = isAdmin;
      })) renderRoute(current);
    } catch {
      // Fail closed: an unread signer set is not a signer. Allow a retry on
      // the next press rather than sticking on a transient read failure.
      adminLookupStarted = false;
      if (epoch.isCurrent(captured)) {
        setStatus({ kind: "error", msg: "Could not read the Vault signer set. Try again." });
        renderRoute(current);
      }
    }
  }

  /** Refresh the journals Activity shows (epoch-checked; re-render on change). */
  let activityLoading = false;
  async function loadActivity(): Promise<void> {
    const cache = cacheManager.activeCache;
    if (activityLoading || cache === null || !state.cacheUnlocked) return;
    activityLoading = true;
    const captured = epoch.current();
    try {
      const spend = (await new SpendJournal(cache).read()).entries;
      const shield = shieldJournal === null ? null : (await shieldJournal.read()).entries;
      const before = JSON.stringify([state.spendEntries, state.shieldEntries]);
      const changed = epoch.commit(captured, () => {
        state.spendEntries = spend;
        if (shield !== null) state.shieldEntries = shield;
      }) && JSON.stringify([state.spendEntries, state.shieldEntries]) !== before;
      if (changed && current === "activity") renderRoute(current);
    } catch {
      // Activity shows what it already has.
    } finally {
      activityLoading = false;
    }
  }

  /**
   * The SYNCHRONOUS half of logout: advance the epoch, lock/dispose the cache,
   * and drop every piece of session state. Extracted so the panic wipe (A-1b)
   * runs exactly this teardown, in exactly this order, before it deletes any
   * database — a deletion that raced an in-flight persist would be resurrected.
   */
  function clearSessionState(message: string): void {
    // Epoch FIRST (A-S6): in-flight ops from this session can no longer commit.
    epoch.advance();
    for (const lease of activeLeases) lease.close();
    activeLeases.clear();
    sessionTasks.cancel();
    // endSession also advances the monotonic epoch and locks/disposes the note
    // cache; no cache instance survives into another principal's session.
    cacheManager.endSession();
    ctx.mutationActors = null;
    ctx.shieldedActors = null;
    // J-17b: the operator actors go with the session. A revoked session leaves
    // NOTHING to sign a Vault action with (hardening 10 invariant).
    ctx.operatorActors = null;
    shieldedActorsError = null;
    mutationActorsError = null;
    journalStoreError = null;
    currentSession = null;
    // Drop the Layer-1 provider with the session: it closes over this
    // principal's device handles, and a stale one must never serve the next.
    sessionFetchKeys = null;
    // WALLET-CACHE-II-ONLY: the session passcode is a session secret — it goes
    // with the session, like the provider that would have used it.
    sessionLayer1 = null;
    sessionPasscode = null;
    cacheKeyMode = null;
    state.cacheGate = "none";
    state.passcodeRequired = null;
    state.deviceApproval = undefined;
    shieldJournal = null;
    state.busy = false;
    state.cacheUnlocked = false;
    state.shieldEntries = null;
    state.notes = [];
    state.scanning = false;
    state.spendLocallyCancellable = false;
    state.scanProgress = null;
    state.mirrorHead = null;
    state.quarantineTotal = 0;
    // The verified observation belongs to the cache it was read from, so it
    // dies with the session rather than lingering over the next principal's.
    state.verifiedScan = null;
    state.verifiedRollback = null;
    state.verifiedScanning = false;
    state.principal = null;
    state.balance = null;
    state.isAdmin = false;
    adminLookupStarted = false;
    state.spendEntries = null;
    journal = null;
    ctx.journalAvailable = true;
    ctx.pendingIntent = null; // the durable record stays with its owner's scope
    setStatus({ kind: "info", msg: message });
    renderRoute(current);
  }

  /**
   * VETKEYS-AGE-2MIN (ruling 559b411e…, A1 notes v3 A.10.2) — ONE background
   * first-derive attempt, so the canister's T=120s sighting clock starts while
   * the user funds/types instead of at their first shield.
   *
   * Fire-and-forget; never toasts. Fires only for a current session with a
   * Layer-1 provider, shielded actors, an OBSERVED balance at or above the §D
   * floor, no live deadline, no dispatch already in flight in this tab, and no
   * earlier attempt for this principal this mount. No timer, no retry: it runs
   * only from an explicit login/restore/refresh call site.
   *
   * `listDevices()` is a point-in-time observation, not a lock: another tab
   * can register a device between it and the dispatch, so a
   * `BootstrapNotAuthorized` after a paid derive remains possible (disclosed
   * residual). An already-dispatched call cannot be recalled; the post-await
   * checks gate only what is committed to UI state.
   */
  async function primeFirstDeriveSighting(captured: number): Promise<void> {
    // ── FULLY SYNCHRONOUS GATE — zero awaits above the latch acquisition ────
    if (!epoch.isCurrent(captured)) return;
    const principal = state.principal;
    if (principal === null) return;
    const key = principal.toText();
    if (sessionFetchKeys === null) return;
    if (ctx.shieldedActors === null) return;
    if (state.balance === null || state.balance < WALLET_ELIGIBILITY_MIN_BALANCE_E8S) return;
    const deadline = preparationDeadlines.get(key);
    const now = (deps.now ?? (() => performance.now()))();
    if (deadline !== undefined && deadline > now) return;
    if (primingInFlightFor !== null) return;
    if (primingAttempted.has(key)) return;

    // ── LATCH ACQUIRED — synchronously, before the first await ──────────────
    primingInFlightFor = key;
    primingAttempted.add(key); // marked BEFORE dispatch; never reset on ANY outcome

    try {
      const stored = await loadDeviceIdentity(key);
      if (!epoch.isCurrent(captured) || state.principal?.toText() !== key) return;
      if (sessionFetchKeys === null || ctx.shieldedActors === null) return;
      if (stored !== null) return; // already enrolled on this device — nothing to prime

      const devices = await ctx.shieldedActors.vetkeys.listDevices();
      // A POINT-IN-TIME OBSERVATION, NOT A LOCK — see the doc comment.
      if (devices.length !== 0) return;
      if (!epoch.isCurrent(captured) || state.principal?.toText() !== key) return;
      if (sessionFetchKeys === null || ctx.shieldedActors === null) return;

      const result = await sessionFetchKeys(ctx.shieldedActors.vetkeys, principal);
      if (!epoch.isCurrent(captured) || state.principal?.toText() !== key) return;
      preparationDeadlines.delete(key);
      reportQuota(result.remaining);
      // WALLET-CACHE-II-ONLY SSA C1: this derive just ENROLLED the device, so
      // the private balance can now open through the derive-free sign-in path
      // (an envelope read + local unwrap). The derived vetKey itself is not
      // carried further — it is not needed, and holding it would outlive the
      // acquisition that produced it. A concurrent first shield/sync shared
      // THIS derive through the single-flight provider rather than making its
      // own, so the two together cost exactly one derive.
      if (!state.cacheUnlocked && (state.cacheGate ?? "none") === "preparing") {
        void openCacheAtSignIn(captured);
      }
    } catch (err) {
      if (!epoch.isCurrent(captured) || state.principal?.toText() !== key) return;
      if (err instanceof VetkeysCallError && "EligibilityAgeNotMet" in err.error) {
        const retryMs = Math.ceil(Number(err.error.EligibilityAgeNotMet.retry_after_ns) / 1e9) * 1_000;
        preparationDeadlines.set(key, (deps.now ?? (() => performance.now()))() + retryMs);
      } else {
        // Swallowed — a background attempt never surfaces a toast.
        console.error("primeFirstDeriveSighting:", err);
      }
    } finally {
      // Release ONLY if it is still ours: a stale finally must never clear a
      // newer call's latch.
      if (primingInFlightFor === key) primingInFlightFor = null;
    }
  }

  /** Seconds left on this principal's live preparation deadline, or null. */
  function livePreparationSeconds(key: string): number | null {
    const deadline = preparationDeadlines.get(key);
    if (deadline === undefined) return null;
    const left = deadline - (deps.now ?? (() => performance.now()))();
    return left > 0 ? Math.ceil(left / 1_000) : null;
  }

  // ── WALLET-CACHE-II-ONLY — the private balance opens with sign-in ─────────
  //
  // THE RULE THIS SECTION EXISTS TO KEEP (brief I-3, Addendum 3): opening the
  // note cache NEVER causes a vetKD derive beyond what login or a genuine
  // action already produces. So:
  //   · sign-in opens it ONLY through `openThisDevicesVetKey` — one envelope
  //     QUERY and a local unwrap — never through the session provider, whose
  //     Layer-2 fallback derives;
  //   · a device with no envelope stays gated ("preparing") until the first
  //     shield or sync, which is the one acquisition that was always going to
  //     derive — and that acquisition is single-flight with priming (C1);
  //   · the cache key is `cacheUnlockKeyIiOnly(vetKey)` (its own domain), never
  //     `masterNoteSecret`, imported NON-EXTRACTABLE, raw bytes zeroed at once.
  //     The vetKey is not kept past the open.

  /** This browser's device identity for `principalText`, as Layer 1 needs it. */
  async function loadSessionDevice(principalText: string): Promise<DeviceIdentity | null> {
    const stored = await loadDeviceIdentity(principalText);
    if (stored === null) return null;
    return {
      deviceId: stored.deviceId,
      encSpki: stored.encSpki,
      signSpki: stored.signSpki,
      keys: {
        encryption: { privateKey: stored.encPrivate, publicKey: stored.encPublic },
        signing: { privateKey: stored.signPrivate, publicKey: stored.signPublic },
      },
    };
  }

  function layer1ConfigFor(
    binding: { canisterId: Principal; owner: Principal },
    device: DeviceIdentity,
    requestPasscode?: () => Promise<string | null>,
  ): Layer1Config {
    return {
      canisterId: binding.canisterId,
      owner: binding.owner,
      device,
      ...(requestPasscode !== undefined ? { requestPasscode } : {}),
    };
  }

  /** The II-only cache key. Raw bytes are zeroed before this returns. */
  async function iiOnlyCacheKey(vetKey: VetKey): Promise<CryptoKey> {
    const raw = cacheUnlockKeyIiOnly(vetKey);
    try {
      return await importCacheKey(raw);
    } finally {
      raw.fill(0);
    }
  }

  /** The passcode-mode cache key over THIS envelope's salt. Raw bytes zeroed. */
  async function passcodeCacheKey(passcode: string, envelope: Uint8Array): Promise<CryptoKey> {
    const raw = await cacheUnlockKeyFromPasscode(passcode, decodeEnvelope(envelope).header.salt);
    try {
      return await importCacheKey(raw);
    } finally {
      raw.fill(0);
    }
  }

  async function ensureCacheStore(): Promise<PrincipalCacheStore> {
    if (cacheStore === null) {
      cacheStore = await (deps.createCacheStore ? deps.createCacheStore() : openIndexedDbPrincipalCacheStore());
    }
    return cacheStore;
  }

  /** Run one cache open at a time (see `cacheOpenChain`). */
  function serializeCacheOpen<T>(fn: () => Promise<T>): Promise<T> {
    const run = cacheOpenChain.then(fn, fn);
    cacheOpenChain = run.catch(() => undefined);
    return run;
  }

  /** An ~10-minute validity for a device-signed envelope replacement. */
  function approvalExpiryNs(): bigint {
    return BigInt(Date.now()) * 1_000_000n + 600_000_000_000n;
  }

  /**
   * Publish an opened cache to the session — the ONE place `cacheUnlocked`
   * becomes true on the key-based paths, and only after the open succeeded
   * (AC-5). Epoch-checked: a logout during the reads commits nothing.
   */
  async function commitOpenedCache(
    cache: PrincipalNoteCache,
    captured: number,
    mode: "ii-only" | "passcode",
    message: string | null,
  ): Promise<boolean> {
    const journalApi = new ShieldJournal(cache);
    const entries = (await journalApi.read()).entries;
    const spendEntries = (await new SpendJournal(cache).read()).entries;
    const cached = await cache.load();
    return epoch.commit(captured, () => {
      shieldJournal = journalApi;
      cacheKeyMode = mode;
      state.cacheUnlocked = true;
      state.cacheGate = "open";
      state.shieldEntries = entries;
      state.spendEntries = spendEntries;
      state.notes = cached.notes;
      state.mirrorHead = cached.mirrorHead ?? null;
      state.quarantineTotal = cached.quarantine?.total ?? 0;
      state.verifiedScan = cached.verifiedScan ?? null;
      if (message !== null) setStatus({ kind: "success", msg: message });
    });
  }

  /** Set the gate, epoch-checked. */
  function setGate(captured: number, gate: NonNullable<AppState["cacheGate"]>): void {
    epoch.commit(captured, () => {
      state.cacheGate = gate;
    });
  }

  /**
   * Open (or create) the II-only cache from a vetKey ALREADY IN HAND. Makes no
   * key request of its own. A passphrase record is NOT opened here — it routes
   * to the one-time move (O-2); a passcode record routes to the passcode card.
   */
  async function openCacheFromVetKey(
    vetKey: VetKey,
    captured: number,
  ): Promise<"open" | "migrate" | "passcode" | "stale"> {
    return serializeCacheOpen(async () => {
      if (!epoch.isCurrent(captured) || currentSession === null || state.principal === null) return "stale";
      if (state.cacheUnlocked) return "open";
      const store = await ensureCacheStore();
      const slot = await store.get(state.principal.toText());
      if (!epoch.isCurrent(captured)) return "stale";
      if (slot !== null && slot.record.kdfVersion === KDF_VERSION_ARGON2ID) {
        setGate(captured, "migrate");
        return "migrate";
      }
      if (slot !== null && slot.record.kdfVersion === KDF_VERSION_WALLET_PASSCODE) {
        setGate(captured, "passcode");
        return "passcode";
      }
      const key = await iiOnlyCacheKey(vetKey);
      const cache = await cacheManager.openForSessionWithKey(store, key, currentSession, {
        create: KDF_VERSION_VETKEY_UNLOCK,
      });
      return (await commitOpenedCache(cache, captured, "ii-only", null)) ? "open" : "stale";
    });
  }

  /** Recovery after a key-based open, exactly as after the passphrase unlock. */
  async function recoverAfterOpen(): Promise<void> {
    if (!state.cacheUnlocked) return;
    try {
      await ctx.recoverSpends({ quietOnError: true });
    } catch {
      // recoverSpends records its own status; a failure never blocks the open.
    }
  }

  /**
   * O-1 (Addendum 3): open the private balance at sign-in through the
   * NO-DERIVE path only. Quiet: it never raises an error toast over "Logged
   * in." — a failure leaves the retryable `"error"` gate instead.
   */
  function openCacheAtSignIn(captured: number): Promise<void> {
    const running = signInOpenFor(captured);
    if (running !== null) return running;
    const run = (async () => {
      if (!epoch.isCurrent(captured) || state.cacheUnlocked) return;
      const principal = state.principal;
      const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
      const binding = sessionLayer1;
      if (principal === null || currentSession === null) return;
      if (binding === null || vetkeys === null) {
        setGate(captured, "none");
        return;
      }
      // No render here: on the restore path this runs BEFORE `router.start()`,
      // and an early render would count as "the first route rendered" and let
      // the router's first real render clear a boot-time status. The commit
      // already set "opening"; the `finally` below renders the outcome.
      setGate(captured, "opening");
      try {
        const device = await loadSessionDevice(principal.toText());
        if (!epoch.isCurrent(captured)) return;
        if (device === null) {
          // No envelope on this device: stay gated. NOTHING is called.
          setGate(captured, "preparing");
          return;
        }
        let passcodeAsked = false;
        let vetKey: VetKey;
        try {
          vetKey = await openThisDevicesVetKey(
            vetkeys,
            layer1ConfigFor(binding, device, async () => {
              // Report the need; never supply a passcode from here.
              passcodeAsked = true;
              return null;
            }),
          );
        } catch (err) {
          if (!epoch.isCurrent(captured)) return;
          if (err instanceof Layer1Unavailable) {
            // Unknown/revoked envelope: gated, and NO fall-through to a derive.
            setGate(captured, "preparing");
            return;
          }
          if (passcodeAsked && err instanceof EnvelopeFormatError) {
            // O-3 / SSA B2: a passcode envelope goes to the passcode card —
            // never to the countdown gate and never to a derive.
            epoch.commit(captured, () => {
              state.cacheGate = "passcode";
              state.passcodeRequired = true;
            });
            return;
          }
          throw err;
        }
        epoch.commit(captured, () => {
          state.passcodeRequired = false;
        });
        const outcome = await openCacheFromVetKey(vetKey, captured);
        if (outcome === "open") void recoverAfterOpen();
      } catch (err) {
        if (!epoch.isCurrent(captured)) return;
        console.error("openCacheAtSignIn:", err);
        setGate(captured, "error");
      } finally {
        if (epoch.isCurrent(captured)) renderRoute(current);
      }
    })();
    const entry = { epoch: captured, run };
    signInOpenRun = entry;
    const release = () => {
      if (signInOpenRun === entry) signInOpenRun = null;
    };
    run.then(release, release);
    return run;
  }

  /**
   * The FIRST genuine action on a device with no envelope (Addendum 3): the
   * one sanctioned acquisition. It goes through the session provider — which
   * is single-flight with priming (C1) — inside the same C-VK-3 config
   * sandwich the scan path uses, then opens the cache from THAT vetKey.
   * Returns true when the private balance is now open.
   */
  async function openCacheForFirstAction(): Promise<boolean> {
    if (state.cacheUnlocked) return true;
    if (policy.kind === "blocked" || currentSession === null || state.principal === null) return false;
    if (sessionFetchKeys === null || ctx.shieldedActors === null) {
      setStatus({
        kind: "error",
        msg: shieldedActorsError ?? "Private features aren't available in this build.",
      });
      renderRoute(current);
      return false;
    }
    const principal = state.principal;
    const key = principal.toText();
    // VETKEYS-AGE-2MIN (AD-7): a live deadline means the canister would refuse
    // — say so and make NO call.
    const waitSeconds = livePreparationSeconds(key);
    if (waitSeconds !== null) {
      setStatus({
        kind: "info",
        msg: `Your wallet is being prepared — first use is available in ${waitSeconds} s`,
      });
      renderRoute(current);
      return false;
    }
    if (state.busy) return false;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    const vetkeys = ctx.shieldedActors.vetkeys;
    const fetchKeys = sessionFetchKeys;
    try {
      const keyName = resolveExpectedVetkdKeyName({
        policyKind: policy.kind === "local" ? "local" : "production",
        config,
      });
      try {
        await assertCanisterConfig(vetkeys, keyName);
      } catch (err) {
        throw new ShieldAbortError("vetkd-config", err instanceof Error ? err.message : String(err));
      }
      const before = await vetkeys.getConfig();
      const acquired = await fetchKeys(vetkeys, principal);
      if (!epoch.isCurrent(captured)) return false;
      try {
        await assertCanisterConfig(vetkeys, keyName);
      } catch (err) {
        throw new ShieldAbortError(
          "vetkd-config",
          `vetkeys canister config changed during key fetch: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      const after = await vetkeys.getConfig();
      if (before[0] !== after[0] || before[1] !== after[1]) {
        throw new ShieldAbortError(
          "vetkd-config",
          "vetkeys canister config drifted during key fetch — refusing to use the key",
        );
      }
      reportQuota(acquired.remaining);
      preparationDeadlines.delete(key);
      if (state.passcodeRequired === null) {
        epoch.commit(captured, () => {
          state.passcodeRequired = false;
        });
      }
      return (await openCacheFromVetKey(acquired.vetKey, captured)) === "open";
    } catch (err) {
      if (!epoch.isCurrent(captured)) return false;
      if (err instanceof VetkeysCallError && "EligibilityAgeNotMet" in err.error) {
        const retryMs = Math.ceil(Number(err.error.EligibilityAgeNotMet.retry_after_ns) / 1e9) * 1_000;
        preparationDeadlines.set(key, (deps.now ?? (() => performance.now()))() + retryMs);
        const notice = quotaRefusalNotice(err.error);
        setStatus({ kind: "info", msg: notice?.message ?? err.message });
      } else if (!reportQuotaRefusal(err)) {
        await handleAsyncError(captured, "Couldn't open your private balance", err);
      }
      return false;
    } finally {
      if (epoch.isCurrent(captured)) {
        state.busy = false;
        renderRoute(current);
      }
    }
  }

  /**
   * Before a shield or sync: let a running sign-in open finish, then — on a
   * device with no envelope — run the first-action open. Anything else (an
   * open cache, a passcode or migration gate, the legacy path) is left to the
   * action's own checks.
   */
  async function ensureOpenForAction(): Promise<"already" | "opened" | "refused"> {
    await signInOpenFor(epoch.current());
    if (state.cacheUnlocked) return "already";
    const gate = state.cacheGate ?? "none";
    if (gate !== "preparing" && gate !== "none") return "already";
    if (gate === "none" && sessionLayer1 === null) return "already";
    // No provider or no shielded actors: the action's own refusal says why.
    if (sessionFetchKeys === null || ctx.shieldedActors === null) return "already";
    return (await openCacheForFirstAction()) ? "opened" : "refused";
  }

  /** O-3: open this device's passcode envelope and the cache under it. */
  async function unlockWithPasscode(passcode: string): Promise<void> {
    await signInOpenFor(epoch.current());
    if (policy.kind === "blocked" || currentSession === null || state.principal === null) return;
    if (passcode === "") {
      setStatus({ kind: "error", msg: "Enter your passcode." });
      renderRoute(current);
      return;
    }
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    const binding = sessionLayer1;
    if (vetkeys === null || binding === null) {
      setStatus({ kind: "error", msg: shieldedActorsError ?? "Private features aren't available in this build." });
      renderRoute(current);
      return;
    }
    if (state.busy) return;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    let opened = false;
    try {
      const device = await loadSessionDevice(state.principal.toText());
      if (device === null) throw new Layer1Unavailable("this device has no key yet");
      const { vetKey, envelope } = await openThisDevicesEnvelope(
        vetkeys,
        layer1ConfigFor(binding, device, async () => passcode),
      );
      if (!epoch.isCurrent(captured)) return;
      opened = await serializeCacheOpen(async () => {
        if (!epoch.isCurrent(captured) || currentSession === null || state.principal === null) return false;
        const store = await ensureCacheStore();
        const slot = await store.get(state.principal.toText());
        if (slot !== null && slot.record.kdfVersion === KDF_VERSION_ARGON2ID) {
          setGate(captured, "migrate");
          return false;
        }
        let cache: PrincipalNoteCache;
        let mode: "ii-only" | "passcode";
        if (slot !== null && slot.record.kdfVersion === KDF_VERSION_VETKEY_UNLOCK) {
          // A passcode switch that replaced the envelope but not yet this
          // record: the record still opens under the sign-in key. Nothing is
          // lost and nothing is re-sealed behind the user's back.
          cache = await cacheManager.openForSessionWithKey(store, await iiOnlyCacheKey(vetKey), currentSession, {
            create: false,
          });
          mode = "ii-only";
        } else {
          if (!envelopeIsPasscodeProtected(envelope)) {
            throw new EnvelopeFormatError("this device has no passcode set");
          }
          cache = await cacheManager.openForSessionWithKey(
            store,
            await passcodeCacheKey(passcode, envelope),
            currentSession,
            { create: KDF_VERSION_WALLET_PASSCODE },
          );
          mode = "passcode";
        }
        const committed = await commitOpenedCache(cache, captured, mode, "Unlocked.");
        if (committed) {
          sessionPasscode = passcode;
          state.passcodeRequired = envelopeIsPasscodeProtected(envelope);
        }
        return committed;
      });
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      setStatus({
        kind: "error",
        msg:
          err instanceof EnvelopeFormatError
            ? "That passcode didn't match."
            : `Couldn't open your private balance: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      if (epoch.isCurrent(captured)) {
        state.busy = false;
        renderRoute(current);
      }
    }
    if (opened) await recoverAfterOpen();
  }

  /**
   * O-2: the one-time move of an old passphrase record, with SSA C3.
   *
   * The target key comes ONLY from this device's envelope — the no-derive path.
   * The old passphrase is authenticated by `migratePassphraseRecord` itself;
   * in keep-as-passcode mode it is ALSO verified before the envelope is
   * touched, so a typo can never become the device's new passcode.
   *
   * C3: if the migration throws after its CAS committed (a read-back that
   * failed on a transient store error), the NEW record is already valid under
   * the target key and the old passphrase no longer opens anything. So on ANY
   * failure, once a target key exists, the cache is first probed with THAT key
   * (`openWithKey`, which refuses a still-v2 record before any crypto). Only if
   * the probe fails is the failure the user's to act on — and only then might
   * re-entering the old passphrase help.
   */
  async function migrateNoteCache(input: { passphrase: string; keepAsPasscode: boolean }): Promise<void> {
    await signInOpenFor(epoch.current());
    if (policy.kind === "blocked" || currentSession === null || state.principal === null) return;
    if ((state.cacheGate ?? "none") !== "migrate") return;
    if (input.passphrase === "") {
      setStatus({ kind: "error", msg: "Enter your old passphrase." });
      renderRoute(current);
      return;
    }
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    const binding = sessionLayer1;
    if (vetkeys === null || binding === null) {
      setStatus({ kind: "error", msg: shieldedActorsError ?? "Private features aren't available in this build." });
      renderRoute(current);
      return;
    }
    if (state.busy) return;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    const session = currentSession;
    const principalText = state.principal.toText();
    let target: CacheMigrationTarget | null = null;
    let passcodeOn = false;
    let opened = false;
    try {
      const store = await ensureCacheStore();
      const device = await loadSessionDevice(principalText);
      if (device === null) throw new Layer1Unavailable("this device has no key yet");
      const config = layer1ConfigFor(binding, device, async () =>
        input.keepAsPasscode ? input.passphrase : null,
      );
      const { vetKey, envelope } = await openThisDevicesEnvelope(vetkeys, config);
      if (!epoch.isCurrent(captured)) return;
      if (!input.keepAsPasscode) {
        target = { mode: "ii-only", key: await iiOnlyCacheKey(vetKey) };
      } else {
        // Verify the old passphrase FIRST (a read-only open of the existing v2
        // record — `open` writes nothing when the record exists).
        const slot = await store.get(principalText);
        if (slot === null || slot.record.kdfVersion !== KDF_VERSION_ARGON2ID) {
          throw new CacheWriteConflictError();
        }
        const probe = await PrincipalNoteCache.open(store, input.passphrase, cacheManager.bindingFor(session));
        probe.lock();
        const next = envelopeIsPasscodeProtected(envelope)
          ? envelope
          : await setEnvelopePasscode(vetkeys, config, vetKey, input.passphrase, approvalExpiryNs());
        passcodeOn = true;
        target = { mode: "wallet-passcode", key: await passcodeCacheKey(input.passphrase, next) };
      }
      await migratePassphraseRecord(store, cacheManager.bindingFor(session), input.passphrase, target);
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      let recovered = false;
      if (target !== null) {
        try {
          const store = await ensureCacheStore();
          const probe = await PrincipalNoteCache.openWithKey(store, target.key, cacheManager.bindingFor(session));
          probe.lock();
          recovered = true; // C3: the move landed; the read-back is what failed.
        } catch {
          recovered = false;
        }
      }
      if (!recovered) {
        target = null;
        setStatus({
          kind: "error",
          msg:
            err instanceof CacheAuthenticationError
              ? "That passphrase didn't match. Nothing changed."
              : err instanceof CacheWriteConflictError
                ? "Your wallet changed in another tab. Nothing changed here. Try again."
                : err instanceof EnvelopeFormatError
                  ? "This device has a passcode. Tick keep and use that passcode."
                  : `Couldn't move your notes: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
    try {
      if (target !== null && epoch.isCurrent(captured)) {
        const key = target.key;
        const mode = target.mode === "ii-only" ? "ii-only" : "passcode";
        opened = await serializeCacheOpen(async () => {
          const store = await ensureCacheStore();
          const cache = await cacheManager.openForSessionWithKey(store, key, session, { create: false });
          const count = spendableNotes((await cache.load()).notes).length;
          const committed = await commitOpenedCache(
            cache,
            captured,
            mode,
            `Moved ${count} note${count === 1 ? "" : "s"}. Signing in now opens your wallet.`,
          );
          if (committed) {
            sessionPasscode = passcodeOn ? input.passphrase : null;
            state.passcodeRequired = passcodeOn;
          }
          return committed;
        });
      }
    } catch (err) {
      if (epoch.isCurrent(captured)) {
        setStatus({
          kind: "error",
          msg: `Couldn't open your private balance: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    } finally {
      if (epoch.isCurrent(captured)) {
        state.busy = false;
        renderRoute(current);
      }
    }
    if (opened) await recoverAfterOpen();
  }

  /**
   * O-3 ON: II-only → passcode. Envelope FIRST, then the record: if the record
   * step fails, the next sign-in finds a passcode envelope over a v3 record,
   * which the passcode card opens under the sign-in key — nothing is lost.
   */
  async function enablePasscode(passcode: string): Promise<void> {
    if (passcode.length < 8) {
      setStatus({ kind: "error", msg: "Use at least 8 characters." });
      renderRoute(current);
      return;
    }
    await changePasscode(async (vetkeys, binding, device, captured) => {
      // `sessionPasscode` only matters for the one inconsistent state a failed
      // earlier switch can leave (passcode envelope over a v3 record, opened
      // under the sign-in key); otherwise the envelope is II-only and it is
      // never asked for.
      const config = layer1ConfigFor(binding, device, async () => sessionPasscode);
      const { vetKey } = await openThisDevicesEnvelope(vetkeys, config);
      const fromKey = await iiOnlyCacheKey(vetKey);
      const next = await setEnvelopePasscode(vetkeys, config, vetKey, passcode, approvalExpiryNs());
      const toKey = await passcodeCacheKey(passcode, next);
      await reseal(captured, fromKey, toKey, KDF_VERSION_WALLET_PASSCODE, "passcode");
      sessionPasscode = passcode;
      state.passcodeRequired = true;
      setStatus({ kind: "success", msg: "Passcode on. You'll enter it when you sign in here." });
    });
  }

  /**
   * O-3 OFF: passcode → II-only. Record FIRST, then the envelope: the state
   * this ordering can leave behind on a failure (passcode envelope, v3 record)
   * is the same recoverable one as above. The reverse order could leave an
   * II-only envelope over a passcode record, whose key would be gone.
   */
  async function disablePasscode(currentPasscode: string): Promise<void> {
    if (currentPasscode === "") {
      setStatus({ kind: "error", msg: "Enter your current passcode." });
      renderRoute(current);
      return;
    }
    await changePasscode(async (vetkeys, binding, device, captured) => {
      const config = layer1ConfigFor(binding, device, async () => currentPasscode);
      const { vetKey, envelope } = await openThisDevicesEnvelope(vetkeys, config);
      const toKey = await iiOnlyCacheKey(vetKey);
      const fromKey = cacheKeyMode === "passcode" ? await passcodeCacheKey(currentPasscode, envelope) : toKey;
      await reseal(captured, fromKey, toKey, KDF_VERSION_VETKEY_UNLOCK, "ii-only");
      if (envelopeIsPasscodeProtected(envelope)) {
        await setEnvelopePasscode(vetkeys, config, vetKey, undefined, approvalExpiryNs());
      }
      sessionPasscode = null;
      state.passcodeRequired = false;
      setStatus({ kind: "success", msg: "Passcode off. Signing in opens your wallet." });
    });
  }

  // ── WALLET-V12 O-4 — "Approve new devices" (LAUNCH-HARDEN-04 O-8) ────────

  function nowNs(): bigint {
    return BigInt(Date.now()) * 1_000_000n;
  }

  let deviceApprovalLoading = false;

  /** Read the setting + device inventory (two queries). Never persisted. */
  async function loadDeviceApproval(): Promise<void> {
    if (deviceApprovalLoading) return;
    deviceApprovalLoading = true;
    try {
      await readDeviceApproval();
    } finally {
      deviceApprovalLoading = false;
    }
  }

  async function readDeviceApproval(): Promise<void> {
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    const principal = state.principal;
    if (
      vetkeys === null ||
      principal === null ||
      vetkeys.deviceApprovalPolicy === undefined ||
      vetkeys.setDeviceApprovalPolicy === undefined ||
      vetkeys.requestDeviceApprovalPolicyClear === undefined
    ) {
      state.deviceApproval = null;
      return;
    }
    const captured = epoch.current();
    try {
      const [view, devices, stored] = await Promise.all([
        vetkeys.deviceApprovalPolicy(),
        vetkeys.listDevices(),
        loadDeviceIdentity(principal.toText()),
      ]);
      if (!epoch.isCurrent(captured)) return;
      const active = devices.filter((d) => d.active);
      state.deviceApproval = {
        state: classifyDeviceApprovalPolicy(view, nowNs()),
        thisDeviceActive: stored !== null && active.some((d) => d.device_id === stored.deviceId),
        activeDevices: active.length,
      };
    } catch {
      if (!epoch.isCurrent(captured)) return;
      state.deviceApproval = null; // unknown: the control stays disabled
    }
    renderRoute(current);
  }

  /** Is new-device enrolment gated by the flag right now? False when unreadable. */
  async function deviceApprovalGatesEnrolment(): Promise<boolean> {
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    if (vetkeys === null || vetkeys.deviceApprovalPolicy === undefined) return false;
    try {
      const view = await vetkeys.deviceApprovalPolicy();
      return deviceApprovalBlocksEnrolment(classifyDeviceApprovalPolicy(view, nowNs()));
    } catch {
      return false;
    }
  }

  /** Device-signed set/clear from THIS (active, enrolled) device. */
  async function setDeviceApprovalFromThisDevice(requireApproval: boolean): Promise<void> {
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    const binding = sessionLayer1;
    if (policy.kind === "blocked" || state.principal === null || vetkeys === null || binding === null) {
      setStatus({ kind: "error", msg: "Sign in on a set-up device first." });
      renderRoute(current);
      return;
    }
    if (state.busy) return;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    try {
      const device = await loadSessionDevice(state.principal.toText());
      if (device === null) throw new Layer1Unavailable("this device has no key yet");
      await setDeviceApprovalPolicyFromDevice(
        vetkeys,
        layer1ConfigFor(binding, device),
        requireApproval,
        approvalExpiryNs(),
      );
      if (!epoch.isCurrent(captured)) return;
      setStatus({
        kind: "success",
        msg: requireApproval ? "Approve new devices: on." : "Approve new devices: off.",
      });
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      setStatus({
        kind: "error",
        msg: `Couldn't change this setting: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      if (epoch.isCurrent(captured)) {
        state.busy = false;
        state.deviceApproval = undefined; // re-read the canister's answer
        renderRoute(current);
      }
    }
  }

  /** The II-only path: no device signature; takes effect 24 h later. */
  async function requestDeviceApprovalClear(): Promise<void> {
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    if (policy.kind === "blocked" || state.principal === null || vetkeys === null) return;
    if (vetkeys.requestDeviceApprovalPolicyClear === undefined) return;
    if (state.busy) return;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    try {
      const effectiveAtNs = await vetkeys.requestDeviceApprovalPolicyClear();
      if (!epoch.isCurrent(captured)) return;
      setStatus({ kind: "advisory", msg: deviceApprovalPendingLine(effectiveAtNs) });
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      setStatus({
        kind: "error",
        msg: `Couldn't request turn-off: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      if (epoch.isCurrent(captured)) {
        state.busy = false;
        state.deviceApproval = undefined;
        renderRoute(current);
      }
    }
  }

  async function reseal(
    captured: number,
    fromKey: CryptoKey,
    toKey: CryptoKey,
    toVersion: number,
    mode: "ii-only" | "passcode",
  ): Promise<void> {
    const session = currentSession;
    await serializeCacheOpen(async () => {
      const store = await ensureCacheStore();
      await resealKeyRecord(store, cacheManager.bindingFor(session), fromKey, toKey, toVersion);
      const cache = await cacheManager.openForSessionWithKey(store, toKey, session, { create: false });
      await commitOpenedCache(cache, captured, mode, null);
    });
  }

  async function changePasscode(
    step: (
      vetkeys: ShieldedActors["vetkeys"],
      binding: { canisterId: Principal; owner: Principal },
      device: DeviceIdentity,
      captured: number,
    ) => Promise<void>,
  ): Promise<void> {
    if (policy.kind === "blocked" || currentSession === null || state.principal === null) return;
    const vetkeys = ctx.shieldedActors?.vetkeys ?? null;
    const binding = sessionLayer1;
    if (!state.cacheUnlocked || cacheKeyMode === "passphrase" || vetkeys === null || binding === null) {
      setStatus({ kind: "error", msg: "Open your private balance first." });
      renderRoute(current);
      return;
    }
    if (state.busy) return;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    try {
      const device = await loadSessionDevice(state.principal.toText());
      if (device === null) throw new Layer1Unavailable("this device has no key yet");
      await step(vetkeys, binding, device, captured);
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      setStatus({
        kind: "error",
        msg:
          err instanceof EnvelopeFormatError
            ? "That passcode didn't match."
            : `Couldn't change the passcode: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      if (epoch.isCurrent(captured)) {
        state.busy = false;
        renderRoute(current);
      }
    }
  }

  async function doLogout(message: string): Promise<void> {
    clearSessionState(message);
    try {
      await auth?.logout();
    } catch {
      // Client-storage cleanup failure does not resurrect the session.
    }
  }

  function intentToRequest(intent: TransferIntentRecord): TransferRequest {
    // Rebuilt from the PERSISTED envelope: the byte-for-byte retry guarantee
    // (same created_at_time, same args) comes from here, never from form state.
    return {
      to: {
        owner: Principal.fromText(intent.toOwner),
        subaccount:
          intent.toSubaccountHex !== null ? hexToBytes(intent.toSubaccountHex) : undefined,
      },
      amount: BigInt(intent.amount),
      fee: BigInt(intent.fee),
      memo: intent.memoHex !== null ? hexToBytes(intent.memoHex) : undefined,
      fromSubaccount:
        intent.fromSubaccountHex !== null ? hexToBytes(intent.fromSubaccountHex) : undefined,
      createdAtTime: BigInt(intent.createdAtTimeNs),
    };
  }

  async function settleIntent(
    sessionJournal: TransferJournal,
    intent: TransferIntentRecord,
    outcome: TransferOutcome,
    firstWireAttempt: boolean,
  ): Promise<TransferIntentRecord | null> {
    // Journal settlement is owed to the OWNING principal even when the session
    // changed mid-flight — the slot is keyed to the owner, not the UI session.
    switch (outcome.kind) {
      case "ok":
      case "duplicate":
      case "rejected":
        // Definite outcomes are the ONLY slot-clearing paths (A-S1).
        await sessionJournal.resolve(intent);
        return null;
      case "too-old":
        if (firstWireAttempt) {
          // Direct response to this intent's FIRST wire attempt: no earlier
          // attempt exists that could have executed -> definite non-execution
          // (device clock skew), safe to clear.
          await sessionJournal.resolve(intent);
          return null;
        }
        // An earlier attempt may have executed and left the dedup window:
        // ambiguous -> FREEZE for manual reconciliation; never re-mint (A-S21).
        return sessionJournal.freeze(intent);
    }
  }

  /**
   * Load the current successor slot during stale recovery. Prefers a fresh
   * read; if that READ fails, falls back to the slot content the failed CAS
   * transaction itself observed (`err.current`) — the known pending state is
   * never cleared to null because a reload failed (SSA AC-1b correction).
   */
  async function loadSuccessorSlot(
    sessionJournal: TransferJournal,
    observedByCas: TransferIntentRecord | null,
  ): Promise<TransferIntentRecord | null> {
    try {
      return await sessionJournal.loadUnresolved();
    } catch {
      return observedByCas;
    }
  }

  /**
   * AC-1b, PRE-WIRE only: the CAS failed BEFORE any ledger call (markUnknown,
   * or abandoning a frozen intent) — "nothing was submitted" is genuinely true
   * on this path. Reload the successor slot and resynchronize, so the UI never
   * keeps retrying a superseded intent.
   */
  async function recoverPreWireStale(
    sessionJournal: TransferJournal,
    captured: number,
    err: StaleIntentError,
    msg: string,
  ): Promise<void> {
    const successor = await loadSuccessorSlot(sessionJournal, err.current);
    epoch.commit(captured, () => {
      ctx.pendingIntent = successor;
      setStatus({ kind: "error", msg });
    });
  }

  /**
   * AC-1b, POST-WIRE (SSA Critical correction): the settle CAS failed but the
   * wire call already happened and its outcome is REAL — e.g. two tabs retried
   * the same envelope and the other tab settled the slot first. The ACTUAL
   * outcome must be preserved and reported; claiming "nothing was submitted"
   * here would invite the user to mint a fresh intent and debit again — the
   * one path the ledger dedup cannot protect. The successor slot (if any) is
   * reloaded and shown separately via the pending-intent panel.
   */
  async function reportPostWireStale(
    sessionJournal: TransferJournal,
    captured: number,
    err: StaleIntentError,
    outcome: TransferOutcome,
    firstWireAttempt: boolean,
  ): Promise<void> {
    const successor = await loadSuccessorSlot(sessionJournal, err.current);
    if (!epoch.isCurrent(captured)) return;
    ctx.pendingIntent = successor;
    const note =
      " (Another tab settled this intent concurrently; the result shown is this submission's real ledger response.)";
    switch (outcome.kind) {
      case "ok":
        setStatus({
          kind: "success",
          msg: `Transfer executed (block ${outcome.blockIndex}) — confirmed by the ledger.${note}`,
        });
        await ctx.refreshBalance(); // definite executed result
        break;
      case "duplicate":
        setStatus({
          kind: "success",
          msg: `Transfer already executed (block ${outcome.duplicateOf}) — confirmed success, no second debit.${note}`,
        });
        await ctx.refreshBalance();
        break;
      case "rejected":
        setStatus({
          kind: "error",
          msg: `Transfer rejected by the ledger (not executed): ${outcome.reason}${note}`,
        });
        break;
      case "too-old":
        // Retain the definite/ambiguous TooOld distinction (SSA correction).
        setStatus({
          kind: "error",
          msg: firstWireAttempt
            ? `The ledger rejected the transfer as too old before any attempt executed (check this device's clock). Nothing was debited.${note}`
            : "The ledger can no longer confirm whether an earlier attempt of this transfer executed (TooOld), and another tab updated the intent concurrently. Check the ledger externally before starting any new transfer; the current intent state is shown below.",
        });
        break;
    }
  }

  async function submitIntent(
    intent: TransferIntentRecord,
    captured: number,
    freshIntent: boolean,
    /** WL-2b: the gesture's lease; one token is drawn for the transfer call. */
    lease?: OperationLease,
  ): Promise<void> {
    const sessionJournal = journal;
    const actors = ctx.mutationActors;
    // SSA F-4: INTERNAL invariant, deliberately silent. Every caller of
    // `submitIntent` (transfer, retryPendingIntent) has already refused with
    // copy on this exact condition; a second message here would double up.
    if (sessionJournal === null || actors === null) return;
    // Persist the attempt marker BEFORE the wire call: from here the outcome
    // may be unknown and the envelope must survive a crash.
    let marked: TransferIntentRecord;
    try {
      marked = await sessionJournal.markUnknown(intent);
    } catch (err) {
      if (err instanceof StaleIntentError) {
        // PRE-WIRE CAS failure: no ledger call has happened (AC-1b).
        await recoverPreWireStale(
          sessionJournal,
          captured,
          err,
          "This transfer intent was updated by another tab before anything was submitted — nothing went to the ledger. Reloaded the current transfer state.",
        );
        return;
      }
      throw err;
    }
    epoch.commit(captured, () => {
      ctx.pendingIntent = marked;
    });
    const firstWireAttempt = freshIntent && marked.attempts === 1;
    let outcome: TransferOutcome;
    try {
      outcome = await actors.token.transfer(intentToRequest(marked), lease?.draw("transfer"));
    } catch (err) {
      // Transport-unknown: the intent stays "unknown"; a retry reuses the SAME
      // envelope byte-for-byte, so it cannot double-debit (C-A3).
      epoch.commit(captured, () =>
        setStatus({
          kind: "error",
          msg:
            "Transfer outcome unknown (connection lost mid-call). The saved intent will be " +
            "retried byte-for-byte — it cannot double-debit. " +
            `(${err instanceof Error ? err.message : String(err)})`,
        }),
      );
      return;
    }
    let settled: TransferIntentRecord | null;
    try {
      settled = await settleIntent(sessionJournal, marked, outcome, firstWireAttempt);
    } catch (err) {
      if (err instanceof StaleIntentError) {
        // POST-WIRE stale CAS: the outcome above is REAL and must be reported
        // as such (SSA Critical) — never as "nothing was submitted". If the
        // session era changed mid-flight, the owning tab reports it instead.
        if (epoch.isCurrent(captured)) {
          await reportPostWireStale(sessionJournal, captured, err, outcome, firstWireAttempt);
        }
        return;
      }
      throw err;
    }
    if (!epoch.isCurrent(captured)) return; // stale era: journal settled, UI untouched
    ctx.pendingIntent = settled;
    switch (outcome.kind) {
      case "ok":
        setStatus({ kind: "success", msg: `Transfer executed (block ${outcome.blockIndex}).` });
        await ctx.refreshBalance(); // definite result only
        break;
      case "duplicate":
        setStatus({
          kind: "success",
          msg: `Transfer already executed (block ${outcome.duplicateOf}) — confirmed success, no second debit.`,
        });
        await ctx.refreshBalance();
        break;
      case "rejected":
        setStatus({
          kind: "error",
          msg: `Transfer rejected by the ledger (not executed): ${outcome.reason}`,
        });
        break;
      case "too-old":
        setStatus(
          firstWireAttempt
            ? {
                kind: "error",
                msg: "The ledger rejected the transfer as too old before any attempt executed (check this device's clock). Nothing was debited.",
              }
            : {
                kind: "error",
                msg:
                  "The ledger can no longer confirm whether an earlier attempt of this transfer executed (TooOld). " +
                  "The intent is FROZEN — verify against the ledger externally, then abandon it from this page.",
              },
        );
        break;
    }
  }

  async function handleAsyncError(captured: number, prefix: string, err: unknown): Promise<void> {
    if (auth?.verify() === "expired") {
      // The ONLY logout-worthy failure: verified delegation expiry (A-S10).
      await doLogout("Session expired — logged out.");
      return;
    }
    // WALLET-SHIELD-LAYER1 (Owner Addendum A item 9): the daily key limit reads
    // in hours and minutes, not the raw seconds baked into the error text.
    // Scan renders it earlier, through `reportQuotaRefusal`, and never gets here
    // with it; every other flow (shield, reconcile, spend) does.
    // WALLET-V12 O-4 (SSA E-3): a new-device enrolment refused while "Approve
    // new devices" is on. Discriminated by READING the setting — never by the
    // refusal's reason text, which is shared with the L04-07 re-bootstrap case.
    if (err instanceof VetkeysCallError && "BootstrapNotAuthorized" in err.error) {
      if (await deviceApprovalGatesEnrolment()) {
        epoch.commit(captured, () =>
          setStatus({
            kind: "advisory",
            msg: DEVICE_APPROVAL_REFUSAL_LINES.join(" "),
            lines: [...DEVICE_APPROVAL_REFUSAL_LINES],
            action: {
              label: DEVICE_APPROVAL_REQUEST_CLEAR_BUTTON,
              run: () => void requestDeviceApprovalClear(),
            },
          }),
        );
        return;
      }
    }
    const quotaSeconds =
      err instanceof VetkeysCallError && "DerivationQuotaExceeded" in err.error
        ? retryAfterSeconds(err.error)
        : null;
    epoch.commit(captured, () =>
      setStatus({
        kind: "error",
        msg:
          quotaSeconds !== null
            ? dailyKeyLimitMessage(quotaSeconds)
            : `${prefix}: ${err instanceof Error ? err.message : String(err)}`,
      }),
    );
  }

  const ctx: AppContext = {
    config,
    policy,
    state,
    // Anonymous read actors are constructed at boot below; reads never wait on
    // auth. J-17c: `null`, not an `undefined as unknown as` lie — construction
    // is fail-soft and may legitimately leave this null forever.
    readActors: null,
    mutationActors: null,
    journalAvailable: true,
    operatorActors: null,
    shieldedActors: null,
    pendingIntent: null,
    navigate: (route) => router.navigate(route),
    refresh: () => renderRoute(current),

    async login(): Promise<void> {
      if (policy.kind === "blocked" || auth === null) {
        setStatus({
          kind: "error",
          msg: policy.kind === "blocked" ? policy.reason : "Login is not available.",
        });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        const session = await auth.login();
        if (!epoch.isCurrent(captured)) {
          // A logout (or competing login) raced this one: discard the fresh
          // session rather than writing into the new era.
          await auth.logout();
          return;
        }
        // New authenticated era — anything still in flight from the anonymous
        // phase can no longer commit.
        const era = epoch.advance();
        for (const lease of activeLeases) lease.close();
        activeLeases.clear();
        sessionTasks.renew();
        const applied = await applySession(session, era);
        if (applied) {
          setStatus({ kind: "success", msg: "Logged in." });
          // WALLET-CACHE-II-ONLY O-1: open the private balance through the
          // derive-free path. NOT awaited, for the same reason as the balance
          // read below: a slow key service must never hold `state.busy`.
          void openCacheAtSignIn(era);
          // VETKEYS-AGE-2MIN (C-1): observe the balance, then prime — NOT
          // awaited (Blocker-3 ruling 2026-09-23): a slow ledger must never
          // hold `state.busy`, and the order balance → prime is kept by the
          // chain.
          void ctx.refreshBalance().then(() => primeFirstDeriveSighting(era));
        }
      } catch (err) {
        // Failed-login atomicity: nothing above mutated state on this path.
        epoch.commit(captured, () =>
          setStatus({
            kind: "error",
            msg: err instanceof Error ? err.message : String(err),
          }),
        );
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async logout(): Promise<void> {
      await doLogout("Logged out.");
    },

    cancelSessionTasks(): void {
      if (state.busy && !state.spendLocallyCancellable) {
        setStatus({
          kind: "info",
          msg: "Sending has started. Keep this page open until it finishes.",
        });
        renderRoute(current);
        return;
      }
      sessionTasks.renew();
      setStatus({ kind: "info", msg: "Local scan/proof work cancelled." });
      renderRoute(current);
    },

    async panicWipe(): Promise<WipeReport> {
      state.busy = true;
      renderRoute(current);
      try {
        const report = await runPanicWipe({
          // Step 1 is the app's own epoch-first teardown, unchanged and shared
          // with logout — the wipe does not invent a second session fence.
          endSession: () => clearSessionState("Wiping local data…"),
          logout: async () => {
            await auth?.logout();
          },
        });
        state.wipeReport = report;
        setStatus(
          report.complete
            ? {
                kind: "success",
                msg:
                  "Local data wiped. Your notes and balance are on chain — log in with " +
                  "Internet Identity and rescan to restore them on any device.",
              }
            : {
                kind: "error",
                msg: "Wipe INCOMPLETE — some local data survived. See the per-surface list below.",
              },
        );
        return report;
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async checkOperatorAccess(): Promise<void> {
      await ensureAdminChecked(epoch.current());
    },

    async refreshBalance(): Promise<void> {
      const captured = epoch.current();
      const owner = state.principal;
      if (owner === null) return;
      if (ctx.readActors === null) {
        // Refusal, NOT a zero: `state.balance` is left exactly as it was so the
        // UI never shows a fabricated figure for an unreachable ledger.
        setStatus({ kind: "error", msg: READ_SERVICES_UNAVAILABLE });
        renderRoute(current);
        return;
      }
      try {
        const balance = await ctx.readActors.token.balanceOf(owner);
        epoch.commit(captured, () => {
          state.balance = balance;
        });
        // VETKEYS-AGE-2MIN (C-1): a refresh that first observes funding may
        // prime; the helper's own gate makes this a no-op otherwise.
        void primeFirstDeriveSighting(captured);
      } catch (err) {
        if (auth?.verify() === "expired") {
          // The ONLY logout-worthy failure: verified delegation expiry.
          await doLogout("Session expired — logged out.");
          return;
        }
        epoch.commit(captured, () =>
          setStatus({
            kind: "error",
            msg: `Balance refresh failed: ${err instanceof Error ? err.message : String(err)}`,
          }),
        );
      }
      renderRoute(current);
    },

    async transfer(input): Promise<void> {
      if (ctx.mutationActors === null || state.principal === null || journal === null) {
        setStatus({ kind: "error", msg: mutationRefusalReason("transfer") });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      if (ctx.pendingIntent !== null) {
        setStatus({
          kind: "error",
          msg: "An unresolved transfer intent exists for this account — resolve it before starting a new one.",
        });
        renderRoute(current);
        return;
      }
      // Validate BEFORE any await or persistence: a malformed recipient or
      // amount never mints an intent (A-S12).
      let to: Principal;
      try {
        to = Principal.fromText(input.toText.trim());
      } catch {
        setStatus({ kind: "error", msg: `Invalid recipient principal: "${input.toText}"` });
        renderRoute(current);
        return;
      }
      let amount: bigint;
      try {
        amount = parseStsh(input.amountText);
        if (amount <= 0n) throw new Error("amount must be greater than zero");
      } catch (err) {
        setStatus({ kind: "error", msg: err instanceof Error ? err.message : String(err) });
        renderRoute(current);
        return;
      }
      if (ctx.readActors === null) {
        // The transfer is BLOCKED. There is no `?? 0n` fee here and there must
        // never be one: an intent minted against a guessed fee is a wrong
        // transfer, not a degraded one (J-17c R-2).
        setStatus({ kind: "error", msg: READ_SERVICES_UNAVAILABLE });
        renderRoute(current);
        return;
      }
      const tokenRead = ctx.readActors.token;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        // Live ledger fee at intent time — no hardcoded fee assumptions.
        const fee = await tokenRead.fee();
        if (!epoch.isCurrent(captured)) return;
        let intent: TransferIntentRecord;
        try {
          intent = await journal.beginIntent({
            toOwner: to.toText(),
            toSubaccountHex: null,
            amount,
            fee,
            memoHex: null,
            fromSubaccountHex: null,
            // The ONE stable created_at_time for this intent (C-A3).
            createdAtTimeNs: BigInt(Date.now()) * 1_000_000n,
          });
        } catch (err) {
          if (err instanceof IntentSlotBusyError) {
            // Another tab won the atomic slot: surface ITS intent, mint nothing.
            epoch.commit(captured, () => {
              ctx.pendingIntent = err.existing;
              setStatus({ kind: "error", msg: err.message });
            });
            return;
          }
          throw err;
        }
        if (!epoch.isCurrent(captured)) return; // persisted; the owner resumes it next session
        ctx.pendingIntent = intent;
        await underGesture(["transfer"], captured, (lease) => submitIntent(intent, captured, true, lease));
      } catch (err) {
        await handleAsyncError(captured, "Transfer failed", err);
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async retryPendingIntent(): Promise<void> {
      const intent = ctx.pendingIntent;
      if (intent === null) return;
      // J-17e / SSA F-4: a null-actor or journal-less session is reachable
      // WHILE LOGGED IN now, so the account page's "Retry transfer" button is
      // reachable with nothing behind it. A silent return is a dead button:
      // refuse out loud with the real reason.
      if (journal === null || ctx.mutationActors === null) {
        setStatus({ kind: "error", msg: mutationRefusalReason("transfer") });
        renderRoute(current);
        return;
      }
      if (intent.state === "frozen") return; // frozen resolves via the manual workflow only
      if (state.busy) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        await underGesture(["transfer"], captured, (lease) => submitIntent(intent, captured, false, lease));
      } catch (err) {
        await handleAsyncError(captured, "Transfer retry failed", err);
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async abandonFrozenIntent(input): Promise<void> {
      const intent = ctx.pendingIntent;
      const sessionJournal = journal;
      if (intent === null || sessionJournal === null) return;
      const captured = epoch.current();
      try {
        // Throws unless the user confirmed after external ledger reconcile;
        // the archive write + slot delete are one atomic CAS-guarded
        // transaction (AC-1) — an audit trail remains.
        await sessionJournal.abandonFrozen(intent, input);
        epoch.commit(captured, () => {
          ctx.pendingIntent = null;
          setStatus({
            kind: "info",
            msg: "Transfer archived. You can send again. The record stays on this device.",
          });
        });
      } catch (err) {
        if (err instanceof StaleIntentError) {
          // Abandoning involves no wire call — pre-wire semantics (AC-1b).
          await recoverPreWireStale(
            sessionJournal,
            captured,
            err,
            "This frozen intent was already settled or superseded by another tab — nothing was archived. Reloaded the current transfer state.",
          );
        } else {
          epoch.commit(captured, () =>
            setStatus({
              kind: "error",
              msg: err instanceof Error ? err.message : String(err),
            }),
          );
        }
      }
      renderRoute(current);
    },

    // ── Campaign B / L3a — shielded surface ──────────────────────────────────

    async unlockNoteCache(passphrase: string): Promise<void> {
      // WALLET-CACHE-II-ONLY: a sign-in open still running decides what a typed
      // secret means, so it finishes first.
      await signInOpenFor(epoch.current());
      const gate = state.cacheGate ?? "none";
      if (gate === "passcode") {
        await unlockWithPasscode(passphrase);
        return;
      }
      if (gate === "migrate") {
        await migrateNoteCache({ passphrase, keepAsPasscode: false });
        return;
      }
      // Already open under the sign-in key or the passcode: nothing to unlock.
      if (state.cacheUnlocked && (cacheKeyMode === "ii-only" || cacheKeyMode === "passcode")) return;
      // Below: the LEGACY passphrase open, unchanged. No page renders a control
      // for it any more (every gate above is key-based, and a device with no
      // envelope is never offered a passphrase — AC-4); it remains the
      // programmatic entry the pre-existing app-level suites drive the cache
      // through. Disclosed in the lane packet.
      if (policy.kind === "blocked") {
        setStatus({ kind: "error", msg: policy.reason });
        renderRoute(current);
        return;
      }
      if (currentSession === null || state.principal === null) {
        setStatus({ kind: "error", msg: "Log in before unlocking your private balance." });
        renderRoute(current);
        return;
      }
      if (passphrase === "") {
        setStatus({ kind: "error", msg: "Enter your passphrase." });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        if (cacheStore === null) {
          cacheStore = await (deps.createCacheStore
            ? deps.createCacheStore()
            : openIndexedDbPrincipalCacheStore());
        }
        if (!epoch.isCurrent(captured)) return;
        // openForSession binds the cache to (principal, current epoch); the
        // Argon2id KDF + migration decision + passphrase verify all run here.
        const cache = await cacheManager.openForSession(cacheStore, passphrase, currentSession);
        const journalApi = new ShieldJournal(cache);
        const entries = (await journalApi.read()).entries;
        const spendEntries = (await new SpendJournal(cache).read()).entries;
        // L3b: surface the cached scan state immediately (no rescan needed).
        const cached = await cache.load();
        epoch.commit(captured, () => {
          shieldJournal = journalApi;
          cacheKeyMode = "passphrase";
          state.cacheUnlocked = true;
          state.cacheGate = "open";
          state.shieldEntries = entries;
          state.spendEntries = spendEntries;
          state.notes = cached.notes;
          state.mirrorHead = cached.mirrorHead ?? null;
          state.quarantineTotal = cached.quarantine?.total ?? 0;
          // Surface any verified evidence the cache already holds, exactly as
          // the notes are surfaced: read back, never re-derived or assumed.
          state.verifiedScan = cached.verifiedScan ?? null;
          setStatus({ kind: "success", msg: "Unlocked." });
        });
      } catch (err) {
        epoch.commit(captured, () => {
          // openForSession locks any previously issued cache BEFORE trying to
          // open — after a failed attempt there is no usable instance, so the
          // unlocked state must not linger (it would point at a locked cache).
          shieldJournal = null;
          cacheKeyMode = null;
          state.cacheUnlocked = false;
          state.shieldEntries = null;
          setStatus({
            kind: "error",
            msg: `Could not unlock your private balance: ${
              err instanceof Error ? err.message : String(err)
            }`,
          });
        });
      } finally {
        state.busy = false;
        renderRoute(current);
      }
      // L3c: fresh-device spend recovery follows every successful unlock
      // (P-REC index import + update-validated reconciliation; it no-ops
      // quietly when the cache is locked/anonymous and never re-locks).
      //
      // WALLET-UI addendum 1 (SSA Q4): an automatic scan used to fire here too
      // (fire-and-forget, before this line). It set `state.scanning = true`
      // synchronously, which made `recoverSpends` below see scanning-in-progress
      // and return without running — silently skipping fresh-device recovery on
      // every ordinary unlock. Automatic scan-on-unlock is not a ruled-allowed
      // automatic call; the user's own "Sync now" / verified sweep remain the
      // ways to scan. Recovery alone runs automatically, and now actually runs.
      if (state.cacheUnlocked) {
        try {
          await ctx.recoverSpends({ quietOnError: true });
        } catch {
          // recoverSpends records its own status; a failure never blocks unlock.
        }
      }
    },

    async shield(amount: bigint): Promise<void> {
      // WALLET-CACHE-II-ONLY (Addendum 3): on a device with no key envelope the
      // first shield is what opens the private balance — through the ONE
      // acquisition it was always going to make (single-flight with priming).
      const opened = await ensureOpenForAction();
      if (opened === "refused") return;
      await shieldAfterOpen(amount);
      if (opened === "opened") await recoverAfterOpen();
    },

    async unlockWithPasscode(passcode: string): Promise<void> {
      await unlockWithPasscode(passcode);
    },

    async migrateNoteCache(input): Promise<void> {
      await migrateNoteCache(input);
    },

    async retryPrivateOpen(): Promise<void> {
      if ((state.cacheGate ?? "none") !== "error") return;
      await openCacheAtSignIn(epoch.current());
    },

    get deviceApprovalControl(): AppContext["deviceApprovalControl"] {
      if (ctx.shieldedActors === null || state.principal === null) return undefined;
      return {
        load: () => loadDeviceApproval(),
        turnOn: () => setDeviceApprovalFromThisDevice(true),
        // SSA F-3: OFF from an ACTIVE device here is device-signed and
        // immediate; without one it is the II-only 24 h request.
        turnOff: () =>
          state.deviceApproval?.thisDeviceActive === true
            ? setDeviceApprovalFromThisDevice(false)
            : requestDeviceApprovalClear(),
        requestClear: () => requestDeviceApprovalClear(),
      };
    },

    get passcode(): AppContext["passcode"] {
      if (state.passcodeRequired === null || state.passcodeRequired === undefined) return undefined;
      return {
        enabled: state.passcodeRequired,
        enable: (passcode: string) => enablePasscode(passcode),
        disable: (currentPasscode: string) => disablePasscode(currentPasscode),
      };
    },

    async reconcileShieldJournal(input: { resubmit: boolean }): Promise<void> {
      const flowDeps = shieldDepsOrExplain();
      if (typeof flowDeps === "string") {
        setStatus({ kind: "error", msg: flowDeps });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        // Only a resubmitting reconcile may act publicly; the read-only pass
        // is authorised for nothing, and the gate refuses it if it tries.
        const report = input.resubmit
          ? await underGesture(["approve", "shieldDeposit", "retryDepositCommitment"], captured, (lease) =>
              runShieldReconcile({ ...flowDeps, lease }, { resubmit: true }),
            )
          : await runShieldReconcile(flowDeps, { resubmit: false });
        if (!epoch.isCurrent(captured)) return;
        const s = report.summary;
        const head =
          `Status: ${s.accepted} done, ${s.deposited} confirming, ` +
          `${s.unknown} need a check, ${s.planned} not sent, ${s.failed} failed` +
          (report.importedFromPool > 0
            ? `; ${report.importedFromPool} found from another device`
            : "");
        setStatus({
          kind: s.unknown > 0 || report.attention.length > 0 ? "info" : "success",
          msg: report.attention.length > 0 ? `${head}. ${report.attention.join(" | ")}` : `${head}.`,
        });
        await refreshShieldEntries(captured);
      } catch (err) {
        if (!epoch.isCurrent(captured)) return;
        if (err instanceof ShieldAbortError) {
          setStatus({ kind: "error", msg: err.message });
        } else {
          await handleAsyncError(captured, "Status check failed", err);
        }
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async revokeShieldAllowance(): Promise<void> {
      const flowDeps = shieldDepsOrExplain();
      if (typeof flowDeps === "string") {
        setStatus({ kind: "error", msg: flowDeps });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      state.busy = true; // set BEFORE the first await — no re-entrancy window
      renderRoute(current);
      const captured = epoch.current();
      try {
        // A planned/unknown intent may still legitimately consume the
        // allowance — reconcile first rather than yanking it from a retry.
        const journalState = await flowDeps.journal.read();
        const blocking = journalState.entries.some(
          (e) => e.status === "planned" || e.status === "unknown",
        );
        if (blocking || journalState.approval?.status === "unknown") {
          epoch.commit(captured, () =>
            setStatus({
              kind: "error",
              msg: "Some shields haven't finished. Check their status before cancelling the approval.",
            }),
          );
          return;
        }
        const outcome = await underGesture(["approve"], captured, (lease) =>
          runShieldRevoke({ ...flowDeps, lease }),
        );
        if (!epoch.isCurrent(captured)) return;
        switch (outcome.kind) {
          case "none":
            setStatus({ kind: "info", msg: "No leftover pool allowance to revoke." });
            break;
          case "revoked":
            setStatus({ kind: "success", msg: "Leftover pool allowance revoked." });
            break;
          case "raced":
            setStatus({
              kind: "error",
              msg: `The allowance changed concurrently (now ${outcome.currentAllowance}) — nothing was revoked; retry.`,
            });
            break;
          case "failed":
            setStatus({ kind: "error", msg: `Revoke failed: ${outcome.reason}` });
            break;
        }
      } catch (err) {
        await handleAsyncError(captured, "Revoke failed", err);
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async cancelPlannedShield(): Promise<void> {
      const flowDeps = shieldDepsOrExplain();
      if (typeof flowDeps === "string") {
        setStatus({ kind: "error", msg: flowDeps });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        const report = await underGesture(["approve"], captured, (lease) =>
          runShieldCancel({ ...flowDeps, lease }),
        );
        if (!epoch.isCurrent(captured)) return;
        const revokeMsg =
          report.revoke.kind === "revoked"
            ? "allowance revoked"
            : report.revoke.kind === "none"
              ? "no allowance to revoke"
              : report.revoke.kind === "blocked"
                ? `allowance NOT revoked (${report.revoke.reason})`
                : report.revoke.kind === "raced"
                  ? "allowance changed concurrently — retry the revoke"
                  : `revoke failed: ${report.revoke.reason}`;
        setStatus({
          kind: report.revoke.kind === "revoked" || report.revoke.kind === "none" ? "success" : "info",
          msg: `Cancelled ${report.cancelled} planned intent${report.cancelled === 1 ? "" : "s"}; ${revokeMsg}.`,
        });
        await refreshShieldEntries(captured);
      } catch (err) {
        await handleAsyncError(captured, "Cancel failed", err);
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    async abandonAmbiguousShieldEntry(input): Promise<void> {
      const flowDeps = shieldDepsOrExplain();
      if (typeof flowDeps === "string") {
        setStatus({ kind: "error", msg: flowDeps });
        renderRoute(current);
        return;
      }
      if (state.busy) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        await runShieldAbandon(flowDeps, input.commitmentHex, {
          confirmedExternalReconcile: input.confirmedExternalReconcile,
        });
        if (!epoch.isCurrent(captured)) return;
        setStatus({
          kind: "info",
          msg: "Shield archived. The record stays on this device.",
        });
        await refreshShieldEntries(captured);
      } catch (err) {
        if (!epoch.isCurrent(captured)) return;
        if (err instanceof ShieldAbortError) {
          setStatus({ kind: "error", msg: err.message });
        } else {
          await handleAsyncError(captured, "Abandon failed", err);
        }
      } finally {
        state.busy = false;
        renderRoute(current);
      }
    },

    // ── Campaign B / L3b — scan (§9 validated pipeline) ──────────────────────

    async scan(): Promise<void> {
      // WALLET-CACHE-II-ONLY (Addendum 3): "First shield or sync opens it."
      const opened = await ensureOpenForAction();
      if (opened === "refused") return;
      await performScan("ordinary");
      if (opened === "opened") await recoverAfterOpen();
    },

    /**
     * D-6: the user-initiated verified sweep. ONE route, shared with the
     * ordinary scan up to the dispatch, and ending in `commitVerifiedScan`.
     */
    async verifiedScan(): Promise<void> {
      await performScan("verified");
    },

    /**
     * SSA C-2b: drop this deployment's floor, on an explicit confirmation.
     *
     * `confirmed` is not ceremony. The reset discards the only thing the wallet
     * can recognise a rollback by, so a caller that has not put that in front
     * of the user is refused rather than obeyed.
     */
    async resetVerifiedHistory(input: { confirmed: boolean }): Promise<void> {
      const refused = state.verifiedRollback;
      if (refused === null) return;
      if (!input.confirmed) {
        setStatus({
          kind: "error",
          msg: "Resetting this wallet's verified history needs your explicit confirmation.",
        });
        renderRoute(current);
        return;
      }
      const cache = cacheManager.activeCache;
      if (!state.cacheUnlocked || cache === null) {
        setStatus({ kind: "error", msg: "Open your private balance first." });
        renderRoute(current);
        return;
      }
      const captured = epoch.current();
      try {
        const next = await cache.update((cur) =>
          resetVerifiedHistory(cur, refused.configHash, refused.securityEpoch),
        );
        if (!epoch.isCurrent(captured)) return;
        state.verifiedRollback = null;
        state.verifiedScan = next.verifiedScan ?? null;
        setStatus({
          kind: "info",
          msg:
            "Verified history reset for this deployment. A verified sweep can run again; " +
            "it now has nothing earlier to compare against.",
        });
        renderRoute(current);
      } catch (err) {
        await handleAsyncError(captured, "Reset failed", err);
      }
    },

    // ── Campaign B / L3c — spend (§10) ───────────────────────────────────────

    async spend(input: SpendInput): Promise<void> {
      if (policy.kind === "blocked") {
        setStatus({ kind: "error", msg: policy.reason });
        renderRoute(current);
        return;
      }
      if (currentSession === null || state.principal === null) {
        setStatus({ kind: "error", msg: "Log in before spending." });
        renderRoute(current);
        return;
      }
      const cache = cacheManager.activeCache;
      if (!state.cacheUnlocked || cache === null) {
        setStatus({ kind: "error", msg: "Open your private balance first." });
        renderRoute(current);
        return;
      }
      if (ctx.shieldedActors === null) {
        setStatus({
          kind: "error",
          msg: shieldedActorsError ?? "Shielded features are unavailable in this build.",
        });
        renderRoute(current);
        return;
      }
      if (ctx.readActors === null) {
        // The spend flow prices its fee off the ledger reader. No reader, no
        // spend — refuse before any lease is minted (J-17c R-2).
        setStatus({ kind: "error", msg: READ_SERVICES_UNAVAILABLE });
        renderRoute(current);
        return;
      }
      const spendTokenRead = ctx.readActors.token;
      if (state.busy || state.scanning) return;
      state.busy = true;
      state.spendLocallyCancellable = true;
      renderRoute(current);
      const captured = epoch.current();
      const taskSignal = sessionTasks.signal;
      try {
        const { hash } = await raceSessionTask((deps.assertDeploymentBinding ?? assertDeploymentBinding)({
          poolCanisterId: config.poolCanisterId,
          tokenCanisterId: config.tokenCanisterId,
          merkleCanisterId: config.merkleCanisterId,
          nullifierCanisterId: config.nullifierCanisterId,
          frozenPoolCanisterId: config.frozenPoolCanisterId,
          enforceFrozenPool: policy.kind === "production",
        }), taskSignal, "spend deployment binding was cancelled");
        const merkle = createMerkleActor(
          config.merkleCanisterId,
          await raceSessionTask(
            (deps.createReadAgent ?? createReadAgent)(config),
            taskSignal,
            "spend read-agent preparation was cancelled",
          ),
        );
        // Bind the narrowed values before the authorization closure: inside an
        // arrow the null-checks above no longer narrow the mutable fields.
        const spendPrincipal = state.principal;
        const spendActors = ctx.shieldedActors;
        throwIfAborted(taskSignal);
        const summary = await underGesture(["privateSpend"], captured, (lease) =>
          runSpendFlow(
          {
            policyKind: policy.kind === "local" ? "local" : "production",
            config,
            principal: spendPrincipal,
            vetkeys: spendActors.vetkeys,
            pool: spendActors.pool,
            token: spendTokenRead,
            journal: new SpendJournal(cache),
            scan: merkle,
            notes: state.notes,
            expectedDeploymentConfigHash: hash,
            ...(deps.fetchKeys ?? sessionFetchKeys) !== undefined
              ? { fetchKeys: (deps.fetchKeys ?? sessionFetchKeys) as FetchKeys }
              : {},
            spawnWorker:
              deps.spawnProverWorker ??
              (() =>
                new Worker(new URL("../workers/prover.worker.ts", import.meta.url), {
                  type: "module",
                })),
            submissionDelay: makeSubmissionDelay(),
            lease,
            signal: taskSignal,
            onDispatchBoundary: () => {
              if (!epoch.isCurrent(captured)) return;
              state.spendLocallyCancellable = false;
              setStatus({
                kind: "info",
                msg: "Sending has started. Keep this page open until it finishes.",
              });
              renderRoute(current);
            },
          },
          input,
          ),
        );
        if (!epoch.isCurrent(captured)) return;
        // Refresh the notes view from the journal/cache (input → spent).
        const refreshed = await cache.load();
        state.notes = refreshed.notes;
        setStatus({
          kind: "success",
          msg:
            `Spend finalized (id ${summary.spendId}): ${formatStsh(summary.changeValue)} STSH ` +
            `change${input.payout !== undefined ? `, ${formatStsh(summary.publicAmount)} STSH public payout (gross)` : ""}.`,
        });
      } catch (err) {
        if (!epoch.isCurrent(captured)) return;
        if (err instanceof LeaseExpiredError) {
          setStatus({
            kind: "error",
            msg: err.partial
              ? `Spend may be incomplete — ${err.message}`
              : `Spend not sent — ${err.message}`,
          });
        } else if (err instanceof SubmissionAbandonedError) {
          setStatus({ kind: "info", msg: `Spend abandoned: ${err.message}` });
        } else if (err instanceof SpendFlowError && err.admission !== undefined) {
          // WALLET-V12 O-3: refused at admission — nothing ran; the note stays
          // locked and the SAME spend is retried later (E-2(c)). Copper, not red.
          try {
            const refreshed = await cache.load();
            if (!epoch.isCurrent(captured)) return;
            state.notes = refreshed.notes; // the input shows as locked
          } catch {
            // Display refresh only; the journal already holds the lock.
          }
          setStatus({ kind: "advisory", msg: err.message });
        } else if (err instanceof SpendFlowError) {
          setStatus({ kind: "error", msg: `Spend failed (${err.stage}): ${err.message}` });
        } else {
          await handleAsyncError(captured, "Spend failed", err);
        }
      } finally {
        if (epoch.isCurrent(captured)) {
          state.spendLocallyCancellable = false;
          state.busy = false;
          renderRoute(current);
        }
      }
    },

    // ── Campaign B / L3c — spend recovery (§10.1/§10.2 + P-REC) ─────────────

    async recoverSpends(input?: {
      quietOnError?: boolean;
      effectful?: boolean;
      lease?: OperationLease;
    }): Promise<void> {
      const quiet = input?.quietOnError === true;
      // WL-2b §4.3. `effectful` defaults to FALSE, and that default is the
      // whole fix: this method is auto-run after every successful cache unlock
      // — a private event. In that pass it may READ the pool freely and write
      // the LOCAL journal, but every repair that would put a transaction on
      // chain is only CLASSIFIED and listed in `state.pendingRecovery`. The
      // user's explicit confirmation (`applySpendRecovery`) is what mints the
      // authorization and runs this same pass with `effectful: true`. Even if
      // this default were wrong, the actor gate refuses the call — the trigger
      // moving and the guard biting are two independent lines of defence.
      const effectful = input?.effectful === true;
      if (policy.kind === "blocked" || currentSession === null || state.principal === null) return;
      const cache = cacheManager.activeCache;
      if (!state.cacheUnlocked || cache === null || ctx.shieldedActors === null) return;
      if (state.busy || state.scanning) return;
      state.busy = true;
      renderRoute(current);
      const captured = epoch.current();
      try {
        const journal = new SpendJournal(cache);
        // (1) Fresh-device import: page the identity-bound recovery index.
        const imported = await recoverSpendsFromPool({
          pool: ctx.shieldedActors.pool,
          journal,
        });
        if (!epoch.isCurrent(captured)) return;
        // (2) Reconcile every active entry through the update-validated table.
        // The nullifier actor is created LAZILY — only a fresh-id action needs it.
        let nullifiers: ReturnType<typeof createNullifierRegistryActor> | null = null;
        const actions: string[] = [];
        const deferred: { spendId: string; action: string }[] = [];
        // WALLET-V12 O-3 / E-1: the copy of the first admission refusal met
        // while retrying (same id), shown advisory instead of the plain list.
        let admissionNotice: string | null = null;
        for (const entry of (await journal.read()).entries) {
          if (entry.status === "finalized" || entry.status === "failed") continue;
          if (entry.status === "recovery-required") {
            // Imported entries have no local request — the ONLY action
            // available without local material is the payout retry (pool-side
            // endpoint, no proof needed). Everything else stays locked until
            // the scanner binds output material locally.
            const record = await ctx.shieldedActors.pool.getSpendStatus(BigInt(entry.spendId));
            if (record?.status.kind === "payout-pending" && !effectful) {
              // Surfaced, NOT submitted: a cache unlock authorises unlocking.
              deferred.push({ spendId: entry.spendId, action: "retry-payout" });
              actions.push(`${entry.spendId}:retry-payout(awaiting confirmation)`);
              continue;
            }
            if (record?.status.kind === "payout-pending") {
              await ctx.shieldedActors.pool.retryPrivateSpendPayout(
                BigInt(entry.spendId),
                input?.lease?.draw("retryPrivateSpendPayout"),
              );
              // Authoritative Ok: entry finalized; NO note is mutated (index
              // unknown) and NO change fabricated — the validated scanner
              // recovers the encrypted output from the tree.
              await journal.finalizeFromSpendOk(entry.spendId, null);
              actions.push(`${entry.spendId}:retry-payout`);
            } else {
              actions.push(`${entry.spendId}:recovery-required(locked)`);
            }
            continue;
          }
          if (!effectful) {
            // Classify from the ADVISORY query only — `reconcileSpendEntry`
            // would perform the repair, and no gesture authorised one.
            const record = await ctx.shieldedActors.pool.getSpendStatus(BigInt(entry.spendId));
            const planned = recoveryActionForAdvisory(record?.status ?? null, entry.status);
            if (
              planned.kind === "replay-same-intent" ||
              planned.kind === "retry-same-id" ||
              planned.kind === "retry-payout" ||
              planned.kind === "fresh-id"
            ) {
              deferred.push({ spendId: entry.spendId, action: planned.kind });
              actions.push(`${entry.spendId}:${planned.kind}(awaiting confirmation)`);
            } else {
              actions.push(`${entry.spendId}:${planned.kind}`);
            }
            continue;
          }
          const action = await reconcileSpendEntry(
            { pool: ctx.shieldedActors.pool, journal, ...(input?.lease !== undefined ? { lease: input.lease } : {}) },
            entry,
          );
          if (action.kind === "fresh-id") {
            // §10.2: a same-id retry answered DuplicateSpendId + unspent →
            // fresh id, both attempts retained.
            nullifiers ??= createNullifierRegistryActor(
              config.nullifierCanisterId,
              await createReadAgent(config),
            );
            try {
              const newId = await recoverSpendFreshId(
                {
                  pool: ctx.shieldedActors.pool,
                  journal,
                  nullifiers,
                  ...(input?.lease !== undefined ? { lease: input.lease } : {}),
                },
                entry,
              );
              actions.push(`${entry.spendId}:fresh-id→${newId}`);
            } catch (err) {
              // E-2(c) item 4: the fresh attempt refused at admission stays
              // dispatched; the next pass retries THAT id same-id.
              if (!(err instanceof SpendFlowError) || err.admission === undefined) throw err;
              admissionNotice ??= err.message;
              actions.push(`${entry.spendId}:fresh-id(waiting)`);
            }
          } else if (action.kind === "keep-locked" && action.admission !== undefined) {
            admissionNotice ??= action.alreadyWentThrough === true
              ? SPEND_ALREADY_WENT_THROUGH_COPY
              : spendAdmissionCopy(action.admission);
            actions.push(`${entry.spendId}:keep-locked(waiting)`);
          } else {
            actions.push(`${entry.spendId}:${action.kind}`);
          }
        }
        if (!epoch.isCurrent(captured)) return;
        const refreshed = await cache.load();
        state.notes = refreshed.notes;
        state.pendingRecovery = deferred;
        // O-6: say something only when there is something to say — this pass
        // now runs at every sign-in, and "nothing found" is not news.
        if (admissionNotice !== null) {
          setStatus({ kind: "advisory", msg: admissionNotice });
        } else if (imported > 0 || actions.length > 0) {
          setStatus({
            kind: "info",
            msg:
              `Interrupted sends: ${imported} found` +
              (actions.length > 0 ? `; ${actions.length} checked (${actions.join(", ")})` : "") +
              ".",
          });
        }
      } catch (err) {
        if (!epoch.isCurrent(captured)) return;
        // Auto-run (post-unlock): a recovery failure never overwrites the
        // unlock's success — it is retried on the next unlock or manual call.
        if (!quiet) {
          await handleAsyncError(captured, "Checking interrupted sends failed", err);
        }
      } finally {
        if (epoch.isCurrent(captured)) {
          state.busy = false;
          renderRoute(current);
        }
      }
    },

    // ── WL-2c: the submission-delay toggle ────────────────────────────────

    setSubmissionDelayEnabled(enabled: boolean): void {
      state.submissionDelayEnabled = enabled;
      writeSubmissionDelayEnabled(enabled);
      renderRoute(current);
    },

    // ── WL-3: the live basis the exit maximum is derived from ─────────────

    async loadSpendFeeBasis(): Promise<void> {
      if (ctx.shieldedActors === null) return;
      if (ctx.readActors === null) {
        // No basis at all, rather than a basis with a guessed ledger fee: the
        // page then quotes NO maximum instead of a wrong one.
        state.spendFeeBasis = null;
        setStatus({ kind: "error", msg: READ_SERVICES_UNAVAILABLE });
        renderRoute(current);
        return;
      }
      const basisTokenRead = ctx.readActors.token;
      const captured = epoch.current();
      try {
        const params = await ctx.shieldedActors.pool.getGovernanceFeeParams();
        const ledgerFee = await basisTokenRead.fee();
        // Reject a basis this wallet cannot price BEFORE storing it, so the
        // page never has a basis it would have to guess with.
        maxPublicAmount(1n, params);
        epoch.commit(captured, () => {
          state.spendFeeBasis = { params, ledgerFee };
        });
      } catch (err) {
        epoch.commit(captured, () => {
          state.spendFeeBasis = null;
          setStatus({
            kind: "error",
            msg:
              `Cannot price an exit right now, so the wallet will not quote a maximum: ` +
              `${err instanceof Error ? err.message : String(err)}`,
          });
        });
      }
      renderRoute(current);
    },

    // ── WL-2b §4.3: the confirmed (never automatic) recovery repair ────────

    async applySpendRecovery(): Promise<void> {
      if (state.pendingRecovery.length === 0) return;
      const captured = epoch.current();
      await underGesture(["privateSpend", "retryPrivateSpendPayout"], captured, (lease) =>
        ctx.recoverSpends({ effectful: true, lease }),
      );
    },
  };

  /** The shield action proper (unchanged), once the private balance is open. */
  async function shieldAfterOpen(amount: bigint): Promise<void> {
    const flowDeps = shieldDepsOrExplain();
    if (typeof flowDeps === "string") {
      setStatus({ kind: "error", msg: flowDeps });
      renderRoute(current);
      return;
    }
    // VETKEYS-AGE-2MIN (AD-7): a live preparation deadline means the canister
    // would refuse the derive — say so and make NO canister call. Shield is
    // gesture-leased, so there is no retry arm: the user re-clicks.
    const waitSeconds = livePreparationSeconds(flowDeps.principal.toText());
    if (waitSeconds !== null) {
      setStatus({
        kind: "info",
        msg: `Your wallet is being prepared — first use is available in ${waitSeconds} s`,
      });
      renderRoute(current);
      return;
    }
    if (state.busy) return;
    state.busy = true;
    renderRoute(current);
    const captured = epoch.current();
    try {
      // WL-2b: the shield operation's two update methods, authorised by
      // THIS click and by nothing else.
      const summary = await underGesture(["approve", "shieldDeposit"], captured, (lease) =>
        runShieldFlow({ ...flowDeps, lease }, amount),
      );
      if (!epoch.isCurrent(captured)) return;
      const parts = [
        summary.accepted > 0 ? `${summary.accepted} done` : null,
        summary.deposited > 0 ? `${summary.deposited} confirming` : null,
        summary.unknown > 0 ? `${summary.unknown} need a check` : null,
        summary.planned > 0 ? `${summary.planned} not sent` : null,
        summary.failed > 0 ? `${summary.failed} failed` : null,
      ].filter((p): p is string => p !== null);
      // O-7: red is a FAILED action only. Unsent or unconfirmed notes are
      // unfinished, not failed — they are finished from Activity.
      setStatus({
        kind: summary.failed > 0 ? "error" : summary.unknown > 0 || summary.planned > 0 ? "info" : "success",
        msg: `Shield: ${parts.join(", ")}.`,
      });
      preparationDeadlines.delete(flowDeps.principal.toText());
      await refreshShieldEntries(captured);
      await ctx.refreshBalance();
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      if (err instanceof VetkeysCallError && "EligibilityAgeNotMet" in err.error) {
        // VETKEYS-AGE-2MIN (AD-7): an expected wait, not a failure. Store the
        // deadline and show the ruled copy (info); no retry is armed.
        const retryMs =
          Math.ceil(Number(err.error.EligibilityAgeNotMet.retry_after_ns) / 1e9) * 1_000;
        preparationDeadlines.set(
          flowDeps.principal.toText(),
          (deps.now ?? (() => performance.now()))() + retryMs,
        );
        const notice = quotaRefusalNotice(err.error);
        setStatus({ kind: "info", msg: notice?.message ?? err.message });
      } else if (err instanceof LeaseExpiredError) {
        // Ruling condition 4: an expired lease must read as a clean
        // re-authorize, never as a silent stall — and it must not claim more
        // than it knows. A shield is up to 17 calls, so expiry AFTER the
        // approve or after some deposits leaves a partial operation, and the
        // honest route for that is reconcile, not restart. The journal
        // already holds what was dispatched.
        setStatus({
          kind: "error",
          msg: err.partial
            ? `Shield may be incomplete — ${err.message}`
            : `Shield not sent — ${err.message}`,
        });
        if (err.partial) await refreshShieldEntries(captured).catch(() => {});
      } else if (err instanceof SubmissionAbandonedError) {
        setStatus({ kind: "info", msg: `Shield abandoned: ${err.message}` });
      } else if (err instanceof ShieldAbortError) {
        setStatus({ kind: "error", msg: err.message });
        await refreshShieldEntries(captured).catch(() => {});
      } else {
        await handleAsyncError(captured, "Shield failed", err);
      }
    } finally {
      state.busy = false;
      renderRoute(current);
    }
  }

  /**
   * WL-2c: one delay controller per OPERATION. It captures the session epoch on
   * its first check, so the post-wait check compares against the epoch the
   * operation started under — a lock, logout or expiry during the wait abandons
   * the operation instead of submitting it.
   */
  function makeSubmissionDelay(): SubmissionDelay {
    let captured: number | null = null;
    return createSubmissionDelay({
      enabled: () => state.submissionDelayEnabled,
      sleep: deps.sleep ?? timerSleep,
      assertSessionCurrent: () => {
        captured ??= epoch.current();
        if (!epoch.isCurrent(captured)) {
          throw new Error("the wallet session ended (lock, logout or expiry)");
        }
        if (!state.cacheUnlocked) throw new Error("your private balance was locked");
      },
      onPending: (view) => {
        state.pendingDelay = view;
        renderRoute(current);
      },
    });
  }

  /**
   * The scan pipeline, ONE body, two modes (WALLET-AUTH G1b, D-6 + SSA F-1).
   *
   * `"ordinary"` is the query-path scan the wallet has always run.
   * `"verified"` is the user-initiated sweep anchored on the pool's accepted
   * root. They are one function rather than two because everything before the
   * dispatch — the origin policy, the session and cache preconditions, the
   * C-VK-3 config sandwich, the fresh per-scan vetKey, the quota notice — is a
   * precondition of BOTH, and a second copy of it would drift. The modes differ
   * only in what is dispatched and what is written back.
   *
   * The verified arm is reached from a button press and nothing else. It mints
   * its lease through `underGesture`, which is the wallet's standing marker for
   * "a user asked for this" (WL-2b), and there is no timer, no route hook and
   * no post-unlock trigger anywhere that calls it.
   */
  async function performScan(mode: "ordinary" | "verified"): Promise<void> {
    const verified = mode === "verified";
    if (policy.kind === "blocked") {
      setStatus({ kind: "error", msg: policy.reason });
      renderRoute(current);
      return;
    }
    if (currentSession === null || state.principal === null) {
      setStatus({ kind: "error", msg: "Log in before scanning for notes." });
      renderRoute(current);
      return;
    }
    const cache = cacheManager.activeCache;
    if (!state.cacheUnlocked || cache === null) {
      setStatus({ kind: "error", msg: "Open your private balance first." });
      renderRoute(current);
      return;
    }
    if (ctx.shieldedActors === null) {
      setStatus({
        kind: "error",
        msg: shieldedActorsError ?? "Shielded features are unavailable in this build.",
      });
      renderRoute(current);
      return;
    }
    if (deps.scanNotes === undefined) {
      setStatus({ kind: "error", msg: "Scan is not wired in this build." });
      renderRoute(current);
      return;
    }
    // G-2: without a pool there is no accepted root and no attestation, so the
    // verified path is unreachable BY CONSTRUCTION rather than by a check that
    // could be forgotten. This says so to the user instead of failing later.
    if (verified && config.poolCanisterId === "") {
      setStatus({ kind: "error", msg: VERIFIED_SCAN_STRINGS.unavailable });
      renderRoute(current);
      return;
    }
    if (state.busy || state.scanning || state.verifiedScanning) return;
    if (verified) state.verifiedScanning = true;
    else state.scanning = true;
    state.scanProgress = null;
    renderRoute(current);
    const captured = epoch.current();
    const taskSignal = sessionTasks.signal;
    try {
      // C-VK-3 (S-43): resolve the authoritative key name, assert the
      // canister config BEFORE the fetch, fetch, assert AGAIN after, and
      // require both observed configurations equal — a mismatch or drift
      // hard-aborts before any derived material is used, and the worker is
      // NEVER dispatched on failure (mirrors the L3a shield sandwich).
      const keyName = resolveExpectedVetkdKeyName({
        policyKind: policy.kind === "local" ? "local" : "production",
        config,
      });
      const vetkeys = ctx.shieldedActors.vetkeys;
      try {
        await raceSessionTask(assertCanisterConfig(vetkeys, keyName), taskSignal, "scan preparation was cancelled");
      } catch (err) {
        throw new ShieldAbortError(
          "vetkd-config",
          err instanceof Error ? err.message : String(err),
        );
      }
      const configBefore = await raceSessionTask(vetkeys.getConfig(), taskSignal, "scan preparation was cancelled");
      // Fresh vetKey per scan (S-3: never persisted — the worker gets the
      // serialized bytes and the master secret, both memory-only).
      // Layer 1 first (zero derives); `deps.fetchKeys` remains the test seam
      // and `fetchUserVetKey` the last resort before a session exists.
      const acquired = await raceSessionTask(
        (deps.fetchKeys ?? sessionFetchKeys ?? fetchUserVetKey)(vetkeys, state.principal),
        taskSignal,
        "scan key acquisition was cancelled",
      );
      const { vetKey } = acquired;
      // D-1 clause 4 / brief V1 §6: surface the remaining key-recovery
      // allowance and warn at the pinned threshold. `remaining === null` is
      // the fast path — no derive, no verdict, and the STANDING notice from
      // the last real derive is left intact (VK-M1).
      reportQuota(acquired.remaining);
      try {
        await raceSessionTask(assertCanisterConfig(vetkeys, keyName), taskSignal, "scan preparation was cancelled");
      } catch (err) {
        throw new ShieldAbortError(
          "vetkd-config",
          `vetkeys canister config changed during key fetch: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
      const configAfter = await raceSessionTask(vetkeys.getConfig(), taskSignal, "scan preparation was cancelled");
      if (configBefore[0] !== configAfter[0] || configBefore[1] !== configAfter[1]) {
        throw new ShieldAbortError(
          "vetkd-config",
          "vetkeys canister config drifted during key fetch — refusing to use the key",
        );
      }
      // R-7 item 5 (L07-03): whether this device held ANY cached note for
      // this principal before the sweep. Captured BEFORE the scan, because
      // it is the only moment the answer is still knowable. An empty cache
      // is the fresh-install / post-wipe-recovery case, where every note is
      // stamped with this scan's clock and none of those stamps is evidence
      // of an arrival. `fromIndex: 0n` makes every sweep a full
      // re-derivation, so the SWEEP RANGE says nothing here — the CACHE does.
      const isBootstrapScan = state.notes.length === 0;
      const firstSeenVia = isBootstrapScan ? "recovery-import" : "live-scan";
      const onProgress = (scannedUpTo: bigint, found: number, signal: AbortSignal) => {
        // Request-fenced (M): a stale scan's progress may never touch a
        // successor session's UI state.
        if (epoch.isCurrent(captured) && !signal.aborted) {
          state.scanProgress = { scannedUpTo, found };
          renderRoute(current);
        }
      };

      if (verified) {
        // THE ONE verified route: gesture -> lease -> worker -> the shared
        // `commitVerifiedScan`. The floor check and the floor advance happen
        // inside `runVerifiedSweepViaWorker`'s single `cache.update`, so there
        // is no window here in which this function could write around them.
        const swept = await underGesture(["verifiedScan"], captured, (lease) =>
          sessionTasks.run(
            (signal) =>
              runVerifiedSweepViaWorker({
                scanNotes: deps.scanNotes!,
                cache,
                lease,
                merkleCanisterId: config.merkleCanisterId,
                nullifierCanisterId: config.nullifierCanisterId,
                poolCanisterId: config.poolCanisterId,
                host: config.host,
                vetKeySerialized: vetKey.serialize(),
                masterNoteSecret: masterNoteSecret(vetKey),
                signal,
                onProgress: (upTo, found) => onProgress(upTo, found, signal),
                firstSeenVia,
              }),
            taskSignal,
          ),
        );
        if (!epoch.isCurrent(captured)) return;
        state.notes = swept.state.notes;
        state.mirrorHead = swept.state.mirrorHead ?? null;
        state.quarantineTotal = swept.state.quarantine?.total ?? 0;
        state.verifiedScan = swept.metadata;
        state.verifiedRollback = null;
        setStatus({
          kind: "success",
          msg:
            `Verified sweep complete: ${spendableNotes(swept.state.notes).length} spendable ` +
            `note(s) over an accepted prefix of ${swept.metadata.accepted_leaf_count} leaf/leaves.`,
        });
      } else {
        const outcome = await sessionTasks.run((signal) => deps.scanNotes!({
          merkleCanisterId: config.merkleCanisterId,
          nullifierCanisterId: config.nullifierCanisterId,
          host: config.host,
          vetKeySerialized: vetKey.serialize(),
          masterNoteSecret: masterNoteSecret(vetKey),
          fromIndex: 0n, // full sweep — the mirror-root check covers [0, head)
          signal,
          onProgress: (scannedUpTo, found) => onProgress(scannedUpTo, found, signal),
        }), taskSignal);
        if (!epoch.isCurrent(captured)) return;
        // ONE atomic cache update (CAS; re-checks the session epoch before
        // committing). The merge is pure (incl. stale-state reconciliation),
        // so a lost CAS re-applies cleanly.
        // WL-2a: ONE clock read for the whole merge, taken before the CAS loop
        // so a lost CAS re-applies the same pure merge with the same instant.
        const seenAtNs = BigInt(Date.now()) * 1_000_000n;
        const merged = await cache.update((s) =>
          mergeScanOutcome(s, outcome, seenAtNs, firstSeenVia),
        );
        state.notes = merged.notes;
        state.mirrorHead = merged.mirrorHead ?? null;
        state.quarantineTotal = merged.quarantine?.total ?? 0;
        state.lastScanOk = true;
        setStatus({
          kind: "success",
          msg: `Scan complete: ${spendableNotes(merged.notes).length} spendable note(s) validated.`,
        });
      }
    } catch (err) {
      if (!epoch.isCurrent(captured)) return;
      // WALLET-UI addendum 1 (SSA Q9): "not currently scanning" is not evidence
      // of freshness. A failed or cancelled ordinary scan must not leave the
      // last-known-good "Up to date" badge showing — flip it here, for every
      // error path below, before any of them decide how to report the failure.
      if (!verified) state.lastScanOk = false;
      // SSA C-2b: a refused rollback is not a generic failure. It is held, with
      // the floor key it refused against, so the page can offer the explicit
      // reset — and ONLY the explicit reset.
      if (verified && err instanceof VerifiedFloorRollbackError) {
        const sep = err.floorKey.lastIndexOf(":");
        state.verifiedRollback = {
          configHash: err.floorKey.slice(0, sep),
          securityEpoch: err.floorKey.slice(sep + 1),
          observedLeafCount: err.observedLeafCount.toString(10),
          floorLeafCount: err.floorLeafCount.toString(10),
          sameCountDifferentRoot: err.sameCountDifferentRoot,
        };
        setStatus({ kind: "error", msg: VERIFIED_SCAN_STRINGS.rollbackRefused });
        renderRoute(current);
        return;
      }
      // A rate-limited key acquisition gets its OWN message, with the wait
      // (D-1 clause 4). Anything else takes the generic path — two messages
      // for one failure would be worse than one good one.
      // The retry action is the scan ITSELF — the real path, including the
      // real key acquisition. Arming a narrower "just fetch the key" retry
      // would prove nothing about what the user actually experiences.
      if (reportQuotaRefusal(err, () => void performScan(mode))) {
        renderRoute(current);
      } else if (verified && !(err instanceof SessionCancelledError)) {
        // The registered strings, mapped by TYPE. Nothing here invents wording
        // for a failure, and nothing downgrades a failed sweep into an
        // ordinary result wearing the word "verified".
        setStatus({ kind: "error", msg: verifiedScanMessage(err) });
        renderRoute(current);
      } else {
        await handleAsyncError(captured, verified ? "Verified sweep failed" : "Scan failed", err);
      }
    } finally {
      // Request-fenced cleanup (M): a stale scan's finally must not clear a
      // successor scan's in-flight state.
      if (epoch.isCurrent(captured)) {
        if (verified) state.verifiedScanning = false;
        else state.scanning = false;
        state.scanProgress = null;
        renderRoute(current);
      }
    }
  }

  /**
   * WL-2b: run one operation under a freshly minted authorization. Every call
   * site of this function is a USER-GESTURE handler — that is the invariant.
   * Nothing driven by a private event (a scan, a cache unlock, a journal read)
   * may call it.
   */
  async function underGesture<T>(
    actions: readonly AuthorizedAction[],
    capturedEpoch: number,
    fn: (lease: OperationLease) => Promise<T>,
  ): Promise<T> {
    if (!epoch.isCurrent(capturedEpoch)) {
      throw new LeaseExpiredError(null, "the wallet session ended before authorization was minted");
    }
    const lease = walletAuthorizationAuthority.mintLease(actions);
    activeLeases.add(lease);
    try {
      return await fn(lease);
    } finally {
      activeLeases.delete(lease);
      // The lease dies with the operation: no token can be drawn afterwards,
      // and any token drawn but never spent is dead too.
      lease.close();
    }
  }

  /** Assemble the shield-flow deps, or explain why shielding is unavailable. */
  function shieldDepsOrExplain(): ShieldFlowDeps | string {
    if (policy.kind === "blocked") return policy.reason;
    if (state.principal === null || ctx.mutationActors === null) {
      return mutationRefusalReason("shield");
    }
    if (ctx.shieldedActors === null) {
      return `Shielded features are unavailable: ${
        shieldedActorsError ?? "the pool/vetkeys canisters are not configured"
      }`;
    }
    if (ctx.readActors === null) {
      return READ_SERVICES_UNAVAILABLE;
    }
    if (shieldJournal === null || !state.cacheUnlocked) {
      return "Open your private balance first.";
    }
    return {
      policyKind: policy.kind,
      config,
      principal: state.principal,
      tokenRead: ctx.readActors.token,
      tokenMutation: ctx.mutationActors.token,
      pool: ctx.shieldedActors.pool,
      vetkeys: ctx.shieldedActors.vetkeys,
      journal: shieldJournal,
      fetchKeys: deps.fetchKeys ?? sessionFetchKeys ?? undefined,
      nowNs: () => BigInt(Date.now()) * 1_000_000n,
      submissionDelay: makeSubmissionDelay(),
      onProgress: (msg) => {
        setStatus({ kind: "info", msg });
        renderStatus();
      },
    };
  }

  /** Reload the journal entries for display (epoch-checked commit). */
  async function refreshShieldEntries(captured: number): Promise<void> {
    if (shieldJournal === null) return;
    const journalState = await shieldJournal.read();
    const cache = cacheManager.activeCache;
    const spendState = cache === null ? null : await new SpendJournal(cache).read();
    epoch.commit(captured, () => {
      state.shieldEntries = journalState.entries;
      if (spendState !== null) state.spendEntries = spendState.entries;
    });
  }

  const header = el("header", { class: "app-header" }, [
    el("div", { class: "brand-row" }, [
      el("a", { class: "brand", href: routeHref("account"), "aria-label": "STSH Wallet" }, [
        el("span", { class: "brand-mark" }, ["STSH"]),
        el("span", { class: "brand-tag" }, ["Wallet"]),
      ]),
      sessionBox,
    ]),
    el("nav", { class: "nav", "aria-label": "Wallet" }, navLinks),
  ]);
  container.append(header, statusBar, content);

  // J-25: the release panel. Anonymous, session-cached, presentation only — it
  // is mounted before the auth boot below precisely because it must work with
  // no session at all. `createPoolIdentityReadActor` exposes the two display
  // queries and no update method, so this is not a mutation path.
  // RED-1 (SSA landed-diff 2026-09-09): the handle is KEPT, not discarded. The
  // footer subscribes to the real `recordProverAssetVerification` event, so the
  // prover row repaints when a spend actually verifies both artifacts — long
  // after the mount paint and the settled-observation paint. `dispose` is the
  // explicit teardown.
  // J-17c R-1: `buildPoolIdentityReader` awaits `HttpAgent.create` (and
  // `fetchRootKey` on local), which can reject on a dead boundary node. That
  // await sat outside any try, so a rejection here stopped the mount before
  // `router.start()` exactly like the read-actor bug. Fail soft: no reader, the
  // panel says "unverified against pool", and the router still starts.
  let poolIdentityReader:
    | Awaited<ReturnType<NonNullable<AppDeps["buildPoolIdentityReader"]>>>
    | null = null;
  if (deps.buildPoolIdentityReader !== undefined) {
    try {
      poolIdentityReader = await deps.buildPoolIdentityReader(config);
    } catch (err) {
      poolIdentityReader = null;
      setStatus({
        kind: "error",
        msg: `Release verification is unavailable: ${
          err instanceof Error ? err.message : String(err)
        }`,
      });
    }
  }

  // O-6: the panel mounts into a collapsed "Verify this build" fold that sits
  // after the page and is shown only on Settings (see renderRoute). The panel
  // itself — its rows, its one observation, its subscription — is unchanged.
  const verifyBuild = el("details", { class: "fold verify-build", "data-testid": "verify-build", hidden: true }, [
    el("summary", {}, ["Verify this build"]),
  ]);
  container.append(verifyBuild);
  ctx.releasePanel = mountReleaseFooter(verifyBuild, {
    config,
    // A harness that supplies no reader gets NO pool query — the panel then
    // says "unverified against pool", which is the honest state for a test
    // that never contacted one. Production supplies it (defaultAppDeps), and
    // `j25_release_wiring.test.ts` asserts that it does.
    reader: poolIdentityReader,
    // ONE observation per SESSION (addendum E): the cache belongs to this
    // mount, so it outlives every rerender and dies with the session. A
    // module-level cache would additionally leak one session's observation
    // into the next mount at a different configuration.
    cache: new PoolIdentityCache(),
  });

  // Anonymous READ actors: attempted at boot, never gated on auth (A-S7).
  // J-17c: FAIL-SOFT. An empty or malformed token/vesting id makes
  // `createReadActors` throw (`Canister ID is required`); that rejection once
  // escaped `mountApp` BEFORE `router.start()`, so no route rendered. Staking
  // is NOT a cause: it is not installed at launch (D1), `createReadActors`
  // returns `staking: null` for its empty id (WALLET-READ-ACTORS), and only
  // the staking page refuses. No retry loop: the condition is the deployment's.
  try {
    ctx.readActors = await deps.buildReadActors(config);
    readActorsError = null;
  } catch (err) {
    ctx.readActors = null;
    readActorsError = err instanceof Error ? err.message : String(err);
  }

  if (policy.kind !== "blocked") {
    // J-17c R-1: `AuthClient.create` rejects when IndexedDB is blocked
    // (private mode, partitioned storage). This await was OUTSIDE the try that
    // guards `restore()`, so it had the same pre-router blast radius. Login
    // then refuses with an explanation (`ctx.login` already handles a null
    // `auth`) instead of taking the whole app down.
    try {
      auth = await deps.createAuth(policy, () => {
        void doLogout("Logged out after inactivity.");
      });
    } catch (err) {
      auth = null;
      setStatus({
        kind: "error",
        msg:
          `Login is unavailable: ${err instanceof Error ? err.message : String(err)}. ` +
          `Browser storage may be blocked — try a normal (non-private) window.`,
      });
    }
    try {
      const restored = auth === null ? null : await auth.restore();
      if (restored !== null) {
        const restoreEra = epoch.current();
        const applied = await applySession(restored, restoreEra);
        if (applied) {
          // WALLET-CACHE-II-ONLY O-1: the derive-free open, not awaited — an
          // await here would put a key-service query ahead of `router.start()`.
          void openCacheAtSignIn(restoreEra);
          // VETKEYS-AGE-2MIN (C-1): observe the balance, then prime — NOT
          // awaited (Blocker-3 ruling 2026-09-23): awaiting a ledger read here
          // would block `router.start()` below, the J-17c pre-router blast
          // radius. The chain keeps the order balance → prime.
          void ctx.refreshBalance().then(() => primeFirstDeriveSighting(restoreEra));
        }
      }
    } catch (err) {
      // A transport/storage error during restore does NOT log anything out
      // (A-S10) — the app simply starts anonymous and says so.
      setStatus({
        kind: "error",
        msg: `Could not restore the previous session: ${
          err instanceof Error ? err.message : String(err)
        }`,
      });
    }
  } else {
    setStatus({ kind: "info", msg: policy.reason });
  }

  router.start();
  return ctx;
}
