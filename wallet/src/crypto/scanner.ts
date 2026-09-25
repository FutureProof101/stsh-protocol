/**
 * Note scan orchestration (Campaign B / L3b — §9 validated pipeline).
 *
 * CORE INVARIANT: no candidate reaches cache state or balance before
 * derivation + leaf + spent-state + epoch validation ALL complete.
 *
 * The pipeline (per §9):
 *   1. Atomic head (get_scan_head) + strict spent-set download (L0-F:
 *      count-before/after, strictly-increasing, bounded retry, FAIL CLOSED).
 *   2. Full public sweep (DEF-073): get_scan_page pages feed the local Merkle
 *      mirror — leaves accumulate and the recomputed root MUST equal the
 *      head root, or the scan fails without persisting (forged-page
 *      acceptance is impossible).
 *   3. Per decrypted candidate (index, plaintext): STRICT v2 parse → derive
 *      v2 secrets from (master, nonce) → CONSTANT-TIME rho/rseed/recipientPk
 *      compare → recompute inner commitment + outer merkleLeaf == the page
 *      leaf at index (LOCAL — never a targeted get_leaf) → derive nullifier →
 *      classify via the DOWNLOADED spent set. Only then does the note enter
 *      the merge set with an explicit state.
 *   4. Quarantine is BOUNDED (S-29): a monotonic counter + a small ring of
 *      {leafIndex, reason}; the payload itself is never retained, and the
 *      scan cursor advances regardless.
 *   5. Persistence is ONE atomic cache update (PrincipalNoteCache.update CAS,
 *      which re-checks the session epoch before committing — the "epoch
 *      validation" of the invariant). The high-water mark only advances past
 *      fully-processed pages.
 *
 * `scanAndValidate` is the I/O + crypto core (worker-runnable — it never
 * touches the cache); `runScan` composes it with the encrypted
 * PrincipalNoteCache on the main thread. Both take injected deps so the
 * logic is unit-testable without a live chain or IndexedDB.
 */

import { raceSessionTask, throwIfAborted } from "../session/taskOwner";
import { poseidon2, poseidon4, poseidon6 } from "./poseidon";
import {
  deriveNoteSecretsV2,
  derivePk,
  domainSep,
  merkleLeaf,
  noteFromBytesV2,
  LegacyNoteFormatUnsupportedError,
  bigintToFieldLe,
  COMMITMENT_DOMAIN,
  NULLIFIER_DOMAIN,
  type NoteV2Fields,
} from "./notes";
import type { ScanHead, ScanPageEntry } from "../actors/merkle";
import {
  PrincipalNoteCache,
  QUARANTINE_RING_CAP,
  VERIFIED_SCAN_FRESHNESS_BUDGET_MS,
  advanceVerifiedFloor,
  checkVerifiedFloor,
  type CachedScanState,
  type MirrorHead,
  type NoteLifecycleState,
  type QuarantineReason,
  type QuarantineState,
  type ScannedNote,
  type VerifiedScanMetadata,
} from "../storage/noteCache";
import {
  PER_PAGE_BUDGET_MS,
  VERIFIED_SWEEP_DEADLINE_MS,
} from "../actors/authorization";
import type { AcceptedRootHeadView } from "../actors/pool";
import type { DeploymentAttestation } from "../../../src/declarations/shielded_pool/shielded_pool.did";

// ── Local Merkle mirror (L0-E) ────────────────────────────────────────────────
//
// The mirror accumulates the downloaded leaves and recomputes the tree root
// with the canister's exact zero-value convention (merkle-tree/src/lib.rs):
//   ZERO_VALUES[0] = Poseidon(0, 0)  (canonical empty leaf)
//   ZERO_VALUES[i] = Poseidon(ZERO_VALUES[i-1], ZERO_VALUES[i-1])
// depth 32. The recomputed root over ALL downloaded leaves must equal the
// atomic get_scan_head root — a forged or withheld page can never satisfy it.

const TREE_DEPTH = 32;
const FR_ZERO = new Uint8Array(32);

let zeroValuesPromise: Promise<Uint8Array[]> | null = null;

/** The 33 canonical zero values (cached — constants within a deployment). */
function zeroValues(): Promise<Uint8Array[]> {
  if (!zeroValuesPromise) {
    zeroValuesPromise = (async () => {
      const zs: Uint8Array[] = [await poseidon2(FR_ZERO, FR_ZERO)];
      for (let i = 1; i <= TREE_DEPTH; i++) zs.push(await poseidon2(zs[i - 1], zs[i - 1]));
      return zs;
    })();
  }
  return zeroValuesPromise;
}

export class LocalMerkleMirror {
  /** Dense leaves, index → 32-byte leaf (insertion order irrelevant). */
  private readonly leaves = new Map<bigint, Uint8Array>();

  /** Record one downloaded leaf. */
  addLeaf(index: bigint, leaf: Uint8Array): void {
    this.leaves.set(index, leaf);
  }

  get size(): bigint {
    return BigInt(this.leaves.size);
  }

  /** The downloaded leaf at `index`, if present. */
  leafAt(index: bigint): Uint8Array | null {
    return this.leaves.get(index) ?? null;
  }

  /**
   * Recompute the tree root over exactly `leafCount` leaves. FAILS if any
   * index in [0, leafCount) is missing — a withheld page makes the mirror
   * incomplete, and an incomplete mirror must never be trusted.
   */
  async root(leafCount: bigint): Promise<Uint8Array> {
    const zs = await zeroValues();
    let level: Uint8Array[] = [];
    for (let i = 0n; i < leafCount; i++) {
      const leaf = this.leaves.get(i);
      if (leaf === undefined) {
        throw new Error(`local mirror is incomplete: leaf ${i} missing (of ${leafCount})`);
      }
      level.push(leaf);
    }
    for (let depth = 0; depth < TREE_DEPTH; depth++) {
      const next: Uint8Array[] = [];
      const pairs = Math.max(Math.ceil(level.length / 2), 1);
      for (let i = 0; i < pairs; i++) {
        const left = level[2 * i] ?? zs[depth];
        const right = level[2 * i + 1] ?? zs[depth];
        next.push(await poseidon2(left, right));
      }
      level = next;
    }
    return level[0];
  }

  /**
   * L3c (S-19): the Merkle witness for `leafIndex` at a tree of `leafCount`
   * leaves — 32 sibling elements + direction bits (0 = the running hash is the
   * LEFT node, matching the canister/circuit convention), with the
   * reconstructed root returned for the caller's accepted-root check. Fails on
   * an incomplete mirror or an out-of-range index. Requires leafIndex <
   * leafCount.
   */
  async witness(
    leafIndex: bigint,
    leafCount: bigint,
  ): Promise<{ elements: Uint8Array[]; indices: number[]; root: Uint8Array }> {
    if (leafIndex < 0n || leafIndex >= leafCount) {
      throw new Error(`witness index ${leafIndex} out of range [0, ${leafCount})`);
    }
    const zs = await zeroValues();
    // Materialize the dense leaf row (fails on any gap, same as root()).
    let level: Uint8Array[] = [];
    for (let i = 0n; i < leafCount; i++) {
      const leaf = this.leaves.get(i);
      if (leaf === undefined) {
        throw new Error(`local mirror is incomplete: leaf ${i} missing (of ${leafCount})`);
      }
      level.push(leaf);
    }
    const elements: Uint8Array[] = [];
    const indices: number[] = [];
    let position = Number(leafIndex);
    for (let depth = 0; depth < TREE_DEPTH; depth++) {
      const siblingPos = position ^ 1;
      const sibling = level[siblingPos] ?? zs[depth];
      elements.push(sibling);
      indices.push(position % 2 === 0 ? 0 : 1);
      // Fold one level up (identical padding rule to root()).
      const next: Uint8Array[] = [];
      const pairs = Math.max(Math.ceil(level.length / 2), 1);
      for (let i = 0; i < pairs; i++) {
        const left = level[2 * i] ?? zs[depth];
        const right = level[2 * i + 1] ?? zs[depth];
        next.push(await poseidon2(left, right));
      }
      level = next;
      position = Math.floor(position / 2);
    }
    return { elements, indices, root: level[0] };
  }
}

/**
 * L3c (S-19/S-32): verify a witness locally — fold the leaf up the path and
 * require the reconstruction to equal the expected (accepted) root. Used
 * before any proof generation: the wallet never proves against an unverified
 * witness.
 */
export async function verifyMerkleWitness(
  leaf: Uint8Array,
  witness: { elements: Uint8Array[]; indices: number[] },
  expectedRoot: Uint8Array,
): Promise<boolean> {
  if (witness.elements.length !== TREE_DEPTH || witness.indices.length !== TREE_DEPTH) {
    return false;
  }
  let current = leaf;
  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    const sibling = witness.elements[depth];
    current =
      witness.indices[depth] === 0
        ? await poseidon2(current, sibling)
        : await poseidon2(sibling, current);
  }
  return ctEqual(current, expectedRoot);
}

// ── Constant-time field compare (S-21) ───────────────────────────────────────

/** Length-independent-time equality for 32-byte field elements. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── Strict spent-set download (L0-F / S-20) ───────────────────────────────────
//
// The wallet-side strict walk (mirrors the P-NUL reference algorithm proven
// in integration-tests/tests/pnul_pagination_tests.rs): count BEFORE → walk
// get_nullifiers_page with strict per-element checks (exactly 32 bytes,
// strictly increasing, no duplicates) → count AFTER → a mismatch means a
// concurrent insert: DISCARD everything and retry from scratch. Bounded
// retries; exhaustion FAILS CLOSED (StaleSnapshotError) — a partial spent
// set can never mark a spent note spendable.

/** The canister's page cap (MAX_NULLIFIERS_PAGE_SIZE). */
const SPENT_PAGE_LIMIT = 500n;
/** Bounded whole-download retries on a perpetually-changing snapshot. */
const MAX_SPENT_DOWNLOAD_RETRIES = 3;

/** The spent snapshot never stabilized within the retry bound. */
export class StaleSnapshotError extends Error {
  constructor() {
    super(
      "the nullifier spent-set kept changing across bounded retries — failing closed " +
        "(no note is marked spendable from a stale snapshot)",
    );
    this.name = "StaleSnapshotError";
  }
}

// ── Verified-path typed failures (WALLET-AUTH Gate 1) ────────────────────────
//
// Every one of these is a REFUSAL, not a downgrade. The verified path never
// answers "I could not verify, so here is the ordinary-query answer": it
// reports unavailable and persists nothing (parent §2 invariant 6).
//
// They carry identity, not just a message, because AC-21 asks the negatives to
// assert WHICH violation occurred — a test that only asserts "throws" passes
// for the wrong reason as readily as the right one.

/** The verified path was requested without the three pool reads (AC-3). */
export class VerifiedPathUnavailableError extends Error {
  constructor(readonly missing: readonly string[]) {
    super(
      `a verified scan was requested but the pool reads [${missing.join(", ")}] were not ` +
        `supplied. There is no default and no fallback to the merkle-only anchor: without the ` +
        `pool's accepted root there is nothing to anchor to, and answering anyway would be ` +
        `the ordinary scan wearing the word "verified".`,
    );
    this.name = "VerifiedPathUnavailableError";
  }
}

/** `n_m < n_a` — the merkle canister is behind the pool's own accepted root (AC-2). */
export class MerkleBehindAcceptedRootError extends Error {
  constructor(readonly merkleLeafCount: bigint, readonly acceptedLeafCount: bigint) {
    super(
      `merkle head is at ${merkleLeafCount} leaves but the pool has already accepted a root ` +
        `at ${acceptedLeafCount}. The tree cannot be behind an accepted root of its own ` +
        `deployment: this is a forked or inconsistent wiring, not a transient lag. Failing ` +
        `closed; nothing persisted.`,
    );
    this.name = "MerkleBehindAcceptedRootError";
  }
}

/** The attestation names canisters other than the configured ones (AC-11). */
export class WrongDeploymentError extends Error {
  constructor(readonly mismatches: readonly string[]) {
    super(
      `the pool's deployment attestation does not describe the configured deployment ` +
        `(${mismatches.join("; ")}). Aborting: a scan anchored to another deployment's ` +
        `accepted root would be meaningless, and its floor is left untouched.`,
    );
    this.name = "WrongDeploymentError";
  }
}

/** `get_deployment_attestation` returned Err or failed (SSA C-10). */
export class DeploymentAttestationUnavailableError extends Error {
  constructor(readonly cause: unknown) {
    super(
      `the pool would not attest its deployment, so there is no config_hash to key a floor ` +
        `on and no wiring to check. The verified path is unreachable this session; nothing ` +
        `was persisted and no floor was touched.`,
    );
    this.name = "DeploymentAttestationUnavailableError";
  }
}

/** The local mirror at `n_a` does not reproduce the pool's accepted root. */
export class VerifiedAnchorMismatchError extends Error {
  constructor(readonly acceptedLeafCount: bigint) {
    super(
      `the local mirror rebuilt over [0, ${acceptedLeafCount}) does not reproduce the pool's ` +
        `accepted root. The pages served do not describe the history the pool accepted; ` +
        `refusing to trust this scan.`,
    );
    this.name = "VerifiedAnchorMismatchError";
  }
}

/**
 * The pool has no accepted root yet.
 *
 * A LEGITIMATE pre-genesis state, not a failure of anything — carried as a
 * typed value so the worker boundary, whose success channel is shaped for a
 * `ScanOutcome`, can report it without fabricating an empty scan. The UI shows
 * "no accepted root yet", persists nothing, and touches no floor.
 */
export class NoAcceptedRootYetError extends Error {
  constructor() {
    super(
      "this pool has not accepted a root yet, so there is no verified prefix to scan. " +
        "Nothing is wrong: a deployment before its first accepted root has an empty " +
        "verified history by definition.",
    );
    this.name = "NoAcceptedRootYetError";
  }
}

/** The accepted prefix exceeds `MAX_VERIFIED_SWEEP_LEAVES` (AC-14, PROT-8 trigger). */
/**
 * A verified sweep returned an outcome but no evidence record (G1b, SSA F-1).
 *
 * On the Web Worker route the sweep runs in the worker and the evidence is
 * posted back beside the outcome. Those are two fields of one message, so a
 * reply carrying the notes without the metadata is not a partial success to
 * paper over: the notes on that route are STAMPED verified, and committing them
 * with nothing to check the floor against is precisely the floorless write this
 * lane exists to make impossible. Fail closed, persist nothing.
 */
export class VerifiedEvidenceMissingError extends Error {
  constructor() {
    super(
      "a verified sweep returned notes but no evidence record, so there is nothing to check " +
        "this deployment's rollback floor against. Nothing was saved. A verified-stamped " +
        "result without its evidence is refused rather than downgraded, because downgrading " +
        "it silently is how the word \"verified\" stops meaning anything.",
    );
    this.name = "VerifiedEvidenceMissingError";
  }
}

export class VerifiedSweepTooLargeError extends Error {
  constructor(readonly acceptedLeafCount: bigint, readonly ceiling: bigint) {
    super(
      `the accepted prefix is ${acceptedLeafCount} leaves, above this device's verified-sweep ` +
        `ceiling of ${ceiling}. Refusing rather than falling back to the merkle-only anchor. ` +
        `This is the PROT-8 trigger: the tree has outgrown device-side verification, and a ` +
        `larger ceiling is not the answer to it.`,
    );
    this.name = "VerifiedSweepTooLargeError";
  }
}

export interface SpentSetDeps {
  getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]>;
  count(): Promise<bigint>;
}

function hexKey(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Download the exact spent set with full strict checks. Throws StaleSnapshotError. */
export async function downloadSpentSet(deps: SpentSetDeps): Promise<Set<string>> {
  for (let attempt = 0; attempt < MAX_SPENT_DOWNLOAD_RETRIES; attempt++) {
    const countBefore = await deps.count();    const all: Uint8Array[] = [];
    let cursor: Uint8Array | null = null;
    for (;;) {
      const page = await deps.getNullifiersPage(cursor, SPENT_PAGE_LIMIT);
      for (const v of page) {
        if (v.length !== 32) {
          throw new Error(`spent-set element is not 32 bytes (${v.length})`);
        }
        const prev = all[all.length - 1];
        if (prev !== undefined) {
          let cmp = 0;
          for (let i = 0; i < 32 && cmp === 0; i++) cmp = v[i] - prev[i];
          if (cmp <= 0) {
            throw new Error("spent-set page is not strictly increasing (duplicate or out-of-order element)");
          }
        }
        all.push(v);
      }
      if (BigInt(page.length) < SPENT_PAGE_LIMIT) break;
      cursor = all[all.length - 1];
    }
    const countAfter = await deps.count();
    if (countBefore === countAfter) {
      if (BigInt(all.length) !== countAfter) {
        throw new Error(
          `spent-set length ${all.length} != count ${countAfter} despite a stable count — incomplete download`,
        );
      }
      return new Set(all.map(hexKey));
    }
    // Stale snapshot — discard and retry from scratch.
  }
  throw new StaleSnapshotError();
}

// ── The validated pipeline (§9) ───────────────────────────────────────────────

export interface ScanActors {
  getScanHead(): Promise<ScanHead>;
  getScanPage(fromIndex: bigint, limit: bigint): Promise<ScanPageEntry[]>;
  getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]>;
  count(): Promise<bigint>;
  // ── The verified path's three POOL reads (WALLET-AUTH Gate 1) ─────────────
  //
  // OPTIONAL, and that is the mechanism behind AC-3 rather than an accident of
  // typing. The worker only builds these when it was given a pool canister id,
  // so "no pool id" makes the verified path UNREACHABLE by construction — there
  // is no default to fall back to and no merkle-only anchor to silently demote
  // to. `ui/spendFlow.ts` takes `Pick<ScanActors, "getScanHead" | "getScanPage">`
  // and is untouched by the widening.
  /** Pool `get_accepted_root_head` — the sole scan bound of the verified path. */
  getAcceptedRootHead?(): Promise<AcceptedRootHeadView | null>;
  /** Pool `get_security_epoch` — half of the floor key. */
  getSecurityEpoch?(): Promise<bigint>;
  /** Pool `get_deployment_attestation` — `config_hash` and the wiring check. */
  getDeploymentAttestation?(): Promise<DeploymentAttestation>;
}

/** `ScanActors` narrowed to the shape the verified sweep actually requires. */
export type VerifiedScanActors = ScanActors &
  Required<Pick<ScanActors, "getAcceptedRootHead" | "getSecurityEpoch" | "getDeploymentAttestation">>;

export interface ScanOutcome {
  /** Newly validated notes (spendable | spent | dummy), deduped by index. */
  notes: ScannedNote[];
  /** Exclusive high-water mark: the next scan resumes here. */
  scannedUpTo: bigint;
  /** The atomic head this scan validated its mirror against. */
  mirrorHead: MirrorHead;
  /** Quarantine DELTA for this scan (merged into the persisted state by the caller). */
  quarantine: QuarantineState;
  /** The validated spent set this scan classified against (hex keys) — used by
   * the merge step to reconcile previously cached notes (a cached note absent
   * from this outcome can never silently retain `spendable` while its
   * nullifier is spent). */
  spentSet: Set<string>;
}

export interface ScanAndValidateOptions {
  fromIndex?: bigint;
  pageSize?: bigint;
  onProgress?: (scannedUpTo: bigint, found: number) => void;
}

export const DEFAULT_PAGE_SIZE = 500n;

/**
 * The verified sweep's leaf ceiling (R-3, as amended by SSA C-3/C-12).
 *
 * DERIVED, never a literal:
 *
 *   MAX_VERIFIED_SWEEP_LEAVES
 *     = floor(VERIFIED_SWEEP_DEADLINE_MS / PER_PAGE_BUDGET_MS) * DEFAULT_PAGE_SIZE
 *     = floor(600,000 / 3,235) * 500
 *     = 185 * 500
 *     = 92,500 leaves
 *
 * with `PER_PAGE_BUDGET_MS = ceil(1,244 * 2.6) = 3,235` — Gate 0's measured
 * mean of 1,244 ms per replicated call (11,194 ms for the nine-call sweep of a
 * 2,000-leaf tree at page size 500, on a single-node dfx 0.28.0 replica;
 * `reviews/PACKET_HARDEN03_WALLET_AUTH_GATE0_563f8a4_2026-09-17.md` §G0-4)
 * scaled by the 34-node mainnet subnet factor the same packet records as ≈2.6×.
 * Both inputs live in `actors/authorization.ts` beside the deadline they budget.
 *
 * Above this bound the verified path REFUSES, fail-closed, with
 * `VerifiedSweepTooLargeError`. It does not quietly fall back to the
 * merkle-only anchor; a silent fallback would be the one outcome that makes the
 * word "verified" mean nothing.
 *
 * Hitting it is the PROT-8 TRIGGER (H-02, deferred-with-trigger): the tree has
 * outgrown device-side verification and the certified-index redesign is what
 * replaces this, not a bigger constant. The packet asks the CTO to log the
 * trigger in the SSoT.
 */
export const MAX_VERIFIED_SWEEP_LEAVES =
  BigInt(Math.floor(VERIFIED_SWEEP_DEADLINE_MS / PER_PAGE_BUDGET_MS)) * DEFAULT_PAGE_SIZE;
/**
 * Bounded FULL-scan retries: a spent-set change detected between the initial
 * download and the end of the Merkle sweep discards the ENTIRE scan and
 * restarts (fresh head + fresh spent set). Exhaustion fails closed
 * (StaleSnapshotError) — nothing is ever persisted from a stale snapshot.
 */
const MAX_FULL_SCAN_ATTEMPTS = 2;

function pushQuarantine(q: QuarantineState, leafIndex: bigint, reason: QuarantineReason): void {
  q.total += 1;
  q.ring.push({ leafIndex, reason });
  if (q.ring.length > QUARANTINE_RING_CAP) q.ring.shift(); // evict oldest — bounded (S-29)
}

/** Page shape validation (fail closed): the page must be a DENSE run starting
 * exactly at `from`, within the captured head's leaf range, at most the
 * requested limit, with 32-byte leaves. A concurrent append cannot smuggle an
 * out-of-snapshot index into the mirror (it would be processed into notes but
 * ignored by the root check). */
function validateScanPage(
  page: ScanPageEntry[],
  from: bigint,
  requestLimit: bigint,
  head: ScanHead,
  /** The sweep's exclusive upper bound — `head.leafCount` unless bounded. */
  bound: bigint = head.leafCount,
): void {
  if (BigInt(page.length) > requestLimit) {
    throw new Error(
      `scan page holds ${page.length} entries, more than the requested ${requestLimit}`,
    );
  }
  page.forEach((entry, i) => {
    const expected = from + BigInt(i);
    if (entry.index !== expected) {
      throw new Error(
        `scan page is not dense from ${from}: entry ${i} has index ${entry.index} (expected ${expected})`,
      );
    }
    if (entry.index >= bound) {
      throw new Error(
        `scan page entry ${entry.index} is beyond the sweep bound (${bound}) — ` +
          "appended after the head snapshot; refusing to mix snapshots",
      );
    }
    if (entry.leaf.length !== 32) {
      throw new Error(`scan page entry ${entry.index} has a ${entry.leaf.length}-byte leaf`);
    }
  });
}

/**
 * The ONE authoritative mirror synchronization (L3b R5 + L3c): atomic head +
 * full public sweep with page-shape validation on EVERY page (dense from the
 * requested index, every index < head.leafCount, 32-byte leaves, request
 * capped to the remaining snapshot range). Fails closed on any violation.
 * Used by both the scan pipeline and the spend witness build — no weaker
 * copies anywhere.
 */
export async function syncMirror(
  actors: Pick<ScanActors, "getScanHead" | "getScanPage">,
  options: {
    pageSize?: bigint;
    onProgress?: (scannedUpTo: bigint) => void;
    signal?: AbortSignal;
    /**
     * WALLET-AUTH Gate 1: sweep `[0, bound)` instead of `[0, head.leafCount)`.
     *
     * The verified path passes the POOL's accepted leaf count here. `n_a` is
     * the immutable prefix and the only thing that is spend authority;
     * `[n_a, n_m)` is not, and is not swept. A `bound` ABOVE the head is
     * refused rather than clamped — the caller asked for leaves the head does
     * not claim to have, which is the `n_m < n_a` inconsistency, and clamping
     * it would turn a forked deployment into a short scan.
     *
     * This keeps ONE authoritative mirror synchronization (parent §2 invariant
     * 2) rather than forking a second sweep for the verified path.
     */
    bound?: bigint;
  } = {},
): Promise<{ head: ScanHead; mirror: LocalMerkleMirror; entries: ScanPageEntry[] }> {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  throwIfAborted(options.signal);
  const head = await raceSessionTask(actors.getScanHead(), options.signal, "mirror head read was cancelled");
  const bound = options.bound ?? head.leafCount;
  if (bound > head.leafCount) {
    throw new MerkleBehindAcceptedRootError(head.leafCount, bound);
  }
  const mirror = new LocalMerkleMirror();
  const entries: ScanPageEntry[] = [];
  let from = 0n;
  while (from < bound) {
    throwIfAborted(options.signal);
    const remaining = bound - from;
    const requestLimit = pageSize < remaining ? pageSize : remaining;
    const page = await raceSessionTask(
      actors.getScanPage(from, requestLimit),
      options.signal,
      "mirror page read was cancelled",
    );
    throwIfAborted(options.signal);
    validateScanPage(page, from, requestLimit, head, bound);
    for (const entry of page) {
      mirror.addLeaf(entry.index, entry.leaf);
      entries.push(entry);
    }
    if (page.length === 0) break;
    from += BigInt(page.length);
    options.onProgress?.(from);
    throwIfAborted(options.signal);
    if (BigInt(page.length) < requestLimit) break;
  }
  return { head, mirror, entries };
}

/**
 * The full validated scan. Rejects (throws) on: spent-set instability, a
 * failed page fetch, a malformed page (non-dense / out-of-snapshot / wrong
 * leaf length), an incomplete mirror, or a mirror root that does not match
 * the atomic head — in every case NOTHING is persisted by the caller.
 *
 * Stale-snapshot discipline: the spent set is stabilized BEFORE the sweep,
 * and its count is re-checked AFTER it. A change discards the ENTIRE scan and
 * restarts (bounded — MAX_FULL_SCAN_ATTEMPTS); exhaustion throws
 * StaleSnapshotError. A nullifier inserted mid-sweep can therefore never be
 * persisted as spendable.
 */
export async function scanAndValidate(
  actors: ScanActors,
  tryDecrypt: (bytes: Uint8Array) => Uint8Array | null,
  masterNoteSecret: Uint8Array,
  options: ScanAndValidateOptions = {},
): Promise<ScanOutcome> {
  for (let attempt = 0; attempt < MAX_FULL_SCAN_ATTEMPTS; attempt++) {
    const outcome = await scanAndValidateOnce(actors, tryDecrypt, masterNoteSecret, options);
    // End-of-scan freshness check (H: spent snapshot could have expired
    // during the potentially long Merkle sweep).
    const countNow = await actors.count();
    if (countNow === BigInt(outcome.spentSet.size)) {
      return outcome;
    }
    // The registry changed mid-scan — discard EVERYTHING and restart from
    // scratch (fresh head + fresh spent set) or fail closed below.
  }
  throw new StaleSnapshotError();
}

/**
 * The per-candidate validation loop, shared by BOTH paths.
 *
 * Extracted so the verified sweep reuses the ordinary path's validation rather
 * than growing a second copy of it — a weaker copy of this loop is the failure
 * mode parent §2 invariant 2 is about. `markVerified` stamps
 * `ScannedNote.verified` and is the ONLY behavioural difference: the crypto,
 * the constant-time compares, the leaf recomputation and the quarantine
 * discipline are identical, because a verified sweep is a claim about the
 * TRANSPORT and the ANCHOR, never a weaker or stronger note validation.
 */
async function validateCandidates(
  entries: ScanPageEntry[],
  spentSet: Set<string>,
  tryDecrypt: (bytes: Uint8Array) => Uint8Array | null,
  masterNoteSecret: Uint8Array,
  options: ScanAndValidateOptions,
  markVerified: boolean,
): Promise<{ notes: ScannedNote[]; quarantine: QuarantineState; scannedUpTo: bigint }> {
  const notes: ScannedNote[] = [];
  const quarantine: QuarantineState = { total: 0, ring: [] };
  const ds = await domainSep();
  const fromIndex = options.fromIndex ?? 0n;
  let scannedUpTo = fromIndex;

  // Per-candidate validation (§9) over the synced entries — the high-water
  // mark only advances past fully-processed entries.
  for (const entry of entries) {
    const { index, leaf, encryptedPayload } = entry;
    if (index < fromIndex) continue;

    const plaintext = tryDecrypt(encryptedPayload);
    if (plaintext === null) {
      scannedUpTo = index + 1n;
      continue; // not ours — opaque to us by design
    }

    // 1. STRICT v2 parse. Legacy 104B / malformed → quarantine + continue.
    let fields: NoteV2Fields | null;
    try {
      fields = noteFromBytesV2(plaintext);
    } catch (err) {
      if (err instanceof LegacyNoteFormatUnsupportedError) {
        pushQuarantine(quarantine, index, "legacy-v1-payload");
        scannedUpTo = index + 1n;
        continue;
      }
      throw err;
    }
    if (fields === null) {
      pushQuarantine(quarantine, index, "malformed-payload");
      scannedUpTo = index + 1n;
      continue;
    }

    // 2. Derive v2 secrets from (master, nonce); 3. CONSTANT-TIME compare.
    const secrets = await deriveNoteSecretsV2(masterNoteSecret, fields.nonce);
    const recipientPkDerived = await derivePk(secrets.spendKey);
    if (
      !ctEqual(secrets.rho, fields.rho) ||
      !ctEqual(secrets.rseed, fields.rseed) ||
      !ctEqual(recipientPkDerived, fields.recipientPk)
    ) {
      pushQuarantine(quarantine, index, "field-mismatch");
      scannedUpTo = index + 1n;
      continue;
    }

    // 4. Recompute inner commitment + outer leaf; require == the page leaf
    //    at this index (LOCAL — never a targeted get_leaf).
    const commitment = await poseidon6(
      ds,
      bigintToFieldLe(fields.value, "note value"),
      fields.recipientPk,
      fields.rho,
      fields.rseed,
      bigintToFieldLe(COMMITMENT_DOMAIN, "COMMITMENT_DOMAIN"),
    );
    const recomputedLeaf = await merkleLeaf(fields.value, commitment);
    if (!ctEqual(recomputedLeaf, leaf)) {
      pushQuarantine(quarantine, index, "leaf-mismatch");
      scannedUpTo = index + 1n;
      continue;
    }

    // 5. Derive the nullifier; classify via the DOWNLOADED spent set.
    const nullifier = await poseidon4(
      ds,
      secrets.spendKey,
      commitment,
      bigintToFieldLe(NULLIFIER_DOMAIN, "NULLIFIER_DOMAIN"),
    );
    // 6. Explicit state; zero-dummy classified distinctly (never balance).
    const state: NoteLifecycleState =
      fields.value === 0n ? "dummy" : spentSet.has(hexKey(nullifier)) ? "spent" : "spendable";

    notes.push({
      ...(markVerified ? { verified: true as const } : {}),
      leafIndex: index,
      value: fields.value,
      rho: fields.rho,
      rseed: fields.rseed,
      recipientPk: fields.recipientPk,
      nonce: fields.nonce,
      commitment,
      nullifier,
      state,
    });
    scannedUpTo = index + 1n;
    options.onProgress?.(scannedUpTo, notes.length);
  }

  return { notes, quarantine, scannedUpTo };
}

/** One full scan attempt (mirror sync → spent set → candidates → mirror check). */
async function scanAndValidateOnce(
  actors: ScanActors,
  tryDecrypt: (bytes: Uint8Array) => Uint8Array | null,
  masterNoteSecret: Uint8Array,
  options: ScanAndValidateOptions,
): Promise<ScanOutcome> {
  // (1) The ONE authoritative mirror sync (head + validated full sweep).
  const { head, mirror, entries } = await syncMirror(actors, { pageSize: options.pageSize });

  // (2) Strict spent-set download (L0-F, fail closed).
  const spentSet = await downloadSpentSet(actors);

  const { notes, quarantine, scannedUpTo } = await validateCandidates(
    entries,
    spentSet,
    tryDecrypt,
    masterNoteSecret,
    options,
    false,
  );

  // Mirror integrity: the recomputed root over the downloaded leaves must
  // equal the atomic head root — a forged/withheld page fails the scan here,
  // BEFORE anything is persisted. runScan always sweeps from index 0, so the
  // mirror covers the full [0, head.leafCount) range at this point.
  const mirrorRoot = await mirror.root(head.leafCount);
  if (!ctEqual(mirrorRoot, head.root)) {
    throw new Error(
      "local mirror root does not match the atomic get_scan_head root — the downloaded " +
        "pages are forged, withheld, or out of date; refusing to trust this scan",
    );
  }

  return {
    notes,
    scannedUpTo,
    mirrorHead: { leafCount: head.leafCount, root: head.root },
    quarantine,
    spentSet,
  };
}

// ── The verified sweep (WALLET-AUTH Gate 1) ──────────────────────────────────

/** Hex of a byte string, lowercase, no separators. */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The domain separator of the spent-set digest. Changing it changes the digest. */
export const SPENT_SET_DIGEST_DOMAIN = "stsh.verified-scan.spent-set.v1";

/**
 * A LOCAL summary of the spent set this wallet downloaded and authenticated.
 *
 * THE PREIMAGE, stated exactly, because a digest whose preimage is only implied
 * is a digest nobody can reproduce:
 *
 *   SHA-256(
 *     utf8("stsh.verified-scan.spent-set.v1")      // 31 bytes, no length prefix
 *     || u64_le(count)                              // 8 bytes
 *     || n_0 || n_1 || ... || n_{count-1}           // 32 bytes each, ASCENDING
 *   )
 *
 * The elements are in the strictly ascending byte order the registry guarantees
 * and `downloadSpentSet` independently enforces, so the digest is a function of
 * the SET, not of the order it happened to arrive in. The count is bound
 * explicitly so a truncated set cannot collide with a shorter honest one.
 *
 * THIS IS NOT A CERTIFICATE and must never be described as one. Nothing signed
 * it; no canister has ever seen it. It exists so a later sweep can tell "the
 * same spent set" from "a different one" without re-downloading it, and so the
 * evidence record says which set the notes were classified against.
 */
export async function spentSetDigest(spentSet: Set<string>): Promise<Uint8Array> {
  const sorted = [...spentSet].sort();
  const domain = new TextEncoder().encode(SPENT_SET_DIGEST_DOMAIN);
  const preimage = new Uint8Array(domain.length + 8 + sorted.length * 32);
  preimage.set(domain, 0);
  const view = new DataView(preimage.buffer, preimage.byteOffset + domain.length, 8);
  view.setBigUint64(0, BigInt(sorted.length), true); // u64 little-endian
  sorted.forEach((hex, i) => preimage.set(fromHex(hex), domain.length + 8 + i * 32));
  return new Uint8Array(await crypto.subtle.digest("SHA-256", preimage as BufferSource));
}

/** The configured deployment the attestation is checked against (AC-11). */
export interface DeploymentBinding {
  poolCanisterId: string;
  merkleCanisterId: string;
  nullifierCanisterId: string;
}

/**
 * The verified sweep's result.
 *
 * `no-accepted-root` is a RESULT, not an error: a pool with no accepted root
 * yet is a legitimate pre-genesis state (parent §5.1). It reports a well-formed
 * EMPTY verified prefix, persists nothing, and leaves every floor untouched.
 */
export type VerifiedScanResult =
  | { status: "verified"; outcome: ScanOutcome; metadata: VerifiedScanMetadata }
  | { status: "no-accepted-root" };

export interface VerifiedScanOptions extends ScanAndValidateOptions {
  /** Injected so a test can bind the advisory timestamp; ADVISORY ONLY. */
  nowMs?: () => number;
  /** Test seam for the ceiling. Production uses `MAX_VERIFIED_SWEEP_LEAVES`. */
  maxLeaves?: bigint;
}

/** Which of the three pool reads a given `ScanActors` is missing. */
export function missingVerifiedActors(actors: ScanActors): string[] {
  const missing: string[] = [];
  if (typeof actors.getAcceptedRootHead !== "function") missing.push("getAcceptedRootHead");
  if (typeof actors.getSecurityEpoch !== "function") missing.push("getSecurityEpoch");
  if (typeof actors.getDeploymentAttestation !== "function") missing.push("getDeploymentAttestation");
  return missing;
}

/** Narrow to `VerifiedScanActors` or refuse. The ONLY way into the verified path. */
export function assertVerifiedActors(actors: ScanActors): VerifiedScanActors {
  const missing = missingVerifiedActors(actors);
  if (missing.length > 0) throw new VerifiedPathUnavailableError(missing);
  return actors as VerifiedScanActors;
}

/**
 * The verified sweep, anchored to the POOL's accepted root.
 *
 * ORDER IS LOAD-BEARING, so it is written out rather than implied:
 *
 *   1. attestation  — Err or throw is fail-closed (SSA C-10); nothing persisted.
 *   2. wiring check — the attestation must describe the CONFIGURED deployment.
 *   3. security epoch — half the floor key; read before the sweep so the floor
 *      the sweep is judged against is the one the sweep belongs to.
 *   4. accepted head A = (root_a, n_a) — the SOLE scan bound. Empty / n_a = 0 is
 *      `no-accepted-root`, a legitimate pre-genesis state.
 *   5. ceiling — n_a above `MAX_VERIFIED_SWEEP_LEAVES` refuses (AC-14).
 *   6. bounded sweep of [0, n_a) through the ONE `syncMirror`; n_m < n_a fails
 *      closed inside it (AC-2).
 *   7. anchor — mirror.root(n_a) == root_a. THIS is the anchor. The merkle-only
 *      root == head.root check still runs as an EXTRA assertion inside
 *      `scanAndValidateOnce`'s sibling path, but it is not what the verified
 *      path relies on: it would let the merkle canister be its own auditor.
 *   8. spent set, with count before and after; digest computed.
 *   9. candidate validation, notes stamped verified.
 *  10. end-of-scan count re-check, retry bounded by `MAX_FULL_SCAN_ATTEMPTS`.
 *
 * Nothing is written to the cache here. The metadata is RETURNED; the caller
 * checks the floor and advances it in ONE atomic cache update, and only after
 * every step above succeeded (brief G-3).
 *
 * THE RESIDUAL, named rather than left for the reader to infer: this closes the
 * transport-level and boundary-level attacks — a network position or boundary
 * node cannot strip, swap or roll back what the canister signed — and the floor
 * closes a coherent rollback at the same security epoch. It does NOT close the
 * dishonest-canister case. A lying pool signs a fabricated accepted root as
 * readily as a true one, and a pool that rotates its `config_hash` or bumps its
 * `security_epoch` mints a virgin floor with nothing to contradict. That
 * residual is PROT-8 / H-02, deferred with a trigger, and release qualification's
 * job — not something this function should be read as having closed.
 */
export async function scanAndValidateVerified(
  actors: ScanActors,
  binding: DeploymentBinding,
  tryDecrypt: (bytes: Uint8Array) => Uint8Array | null,
  masterNoteSecret: Uint8Array,
  options: VerifiedScanOptions = {},
): Promise<VerifiedScanResult> {
  const verified = assertVerifiedActors(actors);
  const ceiling = options.maxLeaves ?? MAX_VERIFIED_SWEEP_LEAVES;

  // (1) Attestation — fail closed on Err/throw (SSA C-10).
  let attestation: DeploymentAttestation;
  try {
    attestation = await verified.getDeploymentAttestation();
  } catch (cause) {
    throw new DeploymentAttestationUnavailableError(cause);
  }

  // (2) Wiring check (AC-11). The floor for this config_hash is untouched.
  const mismatches: string[] = [];
  const check = (label: string, attested: { toText(): string }, configured: string) => {
    const text = attested.toText();
    if (text !== configured) mismatches.push(`${label}: attested ${text}, configured ${configured}`);
  };
  check("pool", attestation.pool, binding.poolCanisterId);
  check("merkle", attestation.merkle, binding.merkleCanisterId);
  check("nullifier", attestation.nullifier, binding.nullifierCanisterId);
  if (mismatches.length > 0) throw new WrongDeploymentError(mismatches);

  const configHash = toHex(Uint8Array.from(attestation.config_hash));

  // (3) Security epoch — the other half of the floor key.
  const securityEpoch = await verified.getSecurityEpoch();

  // (4) The accepted head: the SOLE scan bound.
  const acceptedHead: AcceptedRootHeadView | null = await verified.getAcceptedRootHead();
  if (acceptedHead === null || acceptedHead.leafCount === 0n) {
    return { status: "no-accepted-root" };
  }
  const acceptedLeafCount = acceptedHead.leafCount;

  // (5) The ceiling (AC-14) — refuse, never fall back.
  if (acceptedLeafCount > ceiling) {
    throw new VerifiedSweepTooLargeError(acceptedLeafCount, ceiling);
  }

  for (let attempt = 0; attempt < MAX_FULL_SCAN_ATTEMPTS; attempt++) {
    // (6) The ONE authoritative sweep, bounded to the accepted prefix.
    const { mirror, entries } = await syncMirror(verified, {
      pageSize: options.pageSize,
      bound: acceptedLeafCount,
      onProgress: options.onProgress === undefined ? undefined : (upTo) => options.onProgress?.(upTo, 0),
    });

    // (7) THE ANCHOR: the local mirror over [0, n_a) must reproduce root_a.
    const mirrorRoot = await mirror.root(acceptedLeafCount);
    if (!ctEqual(mirrorRoot, acceptedHead.root)) {
      throw new VerifiedAnchorMismatchError(acceptedLeafCount);
    }

    // (8) Spent set over the verified transport: count before, pages, count
    //     after — `downloadSpentSet` enforces the stability itself.
    const spentSet = await downloadSpentSet(verified);
    const digest = await spentSetDigest(spentSet);

    // (9) Candidate validation; these notes carry verified provenance.
    const { notes, quarantine, scannedUpTo } = await validateCandidates(
      entries,
      spentSet,
      tryDecrypt,
      masterNoteSecret,
      { ...options, fromIndex: 0n },
      true,
    );

    // (10) End-of-scan freshness (AC-7) — same discipline as the ordinary path.
    const countNow = await verified.count();
    if (countNow !== BigInt(spentSet.size)) continue;

    const nowMs = (options.nowMs ?? (() => Date.now()))();
    return {
      status: "verified",
      outcome: {
        notes,
        scannedUpTo,
        mirrorHead: { leafCount: acceptedLeafCount, root: acceptedHead.root },
        quarantine,
        spentSet,
      },
      metadata: {
        config_hash: configHash,
        accepted_root: toHex(acceptedHead.root),
        accepted_leaf_count: acceptedLeafCount.toString(10),
        security_epoch: securityEpoch.toString(10),
        spent_count: BigInt(spentSet.size).toString(10),
        spent_set_digest: toHex(digest),
        evidence_kind: "replicated-replies",
        validated_at_ms: nowMs,
        freshness_budget_ms: VERIFIED_SCAN_FRESHNESS_BUDGET_MS,
      },
    };
  }
  throw new StaleSnapshotError();
}

// ── Cache-aware composition (main thread) ─────────────────────────────────────

export interface RunScanDeps extends ScanActors {
  tryDecrypt: (bytes: Uint8Array) => Uint8Array | null;
  masterNoteSecret: Uint8Array;
  cache: PrincipalNoteCache;
  pageSize?: bigint;
  onProgress?: (scannedUpTo: bigint, found: number) => void;
  /** WL-2a first-sighting clock (ns). Injected so `mergeScanOutcome` stays pure. */
  nowNs?: () => bigint;
}

/**
 * Merge validated notes into the cached set, deduped by leaf index, sorted.
 *
 * WL-2a: `firstSeenAtNs` and `firstSeenVia` are the fields that survive the
 * overwrite (R-7 item 5 added the second — the provenance travels with the
 * timestamp it qualifies, or a rescan would silently drop it). Every
 * other field is re-derived from the chain each sweep and the fresh value is
 * authoritative, but a first sighting is by definition the EARLIEST one — a
 * plain overwrite would move it forward on every rescan and quietly turn a
 * week-old note into a brand-new one, which is precisely the direction that
 * suppresses a rapid-roundtrip warning.
 */
export function mergeScannedNotes(prev: ScannedNote[], next: ScannedNote[]): ScannedNote[] {
  const byIndex = new Map<bigint, ScannedNote>();
  for (const n of prev) byIndex.set(n.leafIndex, n);
  for (const n of next) {
    const before = byIndex.get(n.leafIndex);
    // R-7 item 5: `firstSeenVia` travels WITH the timestamp that wins, never
    // separately — whichever sighting is authoritative, its provenance is the
    // one that describes it.
    const carry = (from: ScannedNote): ScannedNote => ({
      ...n,
      firstSeenAtNs: from.firstSeenAtNs,
      ...(from.firstSeenVia !== undefined ? { firstSeenVia: from.firstSeenVia } : {}),
    });
    byIndex.set(
      n.leafIndex,
      before?.firstSeenAtNs !== undefined && n.firstSeenAtNs === undefined
        ? carry(before)
        : before?.firstSeenAtNs !== undefined && n.firstSeenAtNs !== undefined
          ? BigInt(before.firstSeenAtNs) <= BigInt(n.firstSeenAtNs)
            ? carry(before)
            : carry(n)
          : n,
    );
  }
  return [...byIndex.values()].sort((a, b) => (a.leafIndex < b.leafIndex ? -1 : a.leafIndex > b.leafIndex ? 1 : 0));
}

/** Merge a quarantine delta: totals add; the ring keeps the most recent entries. */
export function mergeQuarantine(prev: QuarantineState | undefined, delta: QuarantineState): QuarantineState {
  const ring = [...(prev?.ring ?? []), ...delta.ring];
  return {
    total: (prev?.total ?? 0) + delta.total,
    ring: ring.slice(-QUARANTINE_RING_CAP),
  };
}

/**
 * Merge a completed scan outcome into the cached state (PURE — safe to
 * re-apply on a lost CAS). Stale-state reconciliation, fail closed:
 *
 * - Notes present in the outcome take their freshly validated state.
 * - A previously cached note ABSENT from the outcome is reconciled against
 *   the outcome's stable spent snapshot: if it was `spendable` and its
 *   nullifier is now spent, it is marked `spent` (fields preserved) — an
 *   unobserved old entry can never silently retain `spendable`.
 * - A cached note absent from the outcome whose nullifier is NOT spent keeps
 *   its prior state (it may be temporarily unreadable this sweep — it is
 *   never made MORE spendable than before). Legacy notes (no nullifier) are
 *   unchanged — they are never spendable anyway.
 */
export function mergeScanOutcome(
  state: CachedScanState,
  outcome: ScanOutcome,
  /**
   * WL-2a: the clock used to stamp `firstSeenAtNs` on notes this device has
   * not seen before. INJECTED, never read from `Date`, so this function stays
   * PURE — re-applying the same outcome after a lost CAS with the same clock
   * produces byte-identical state, which §1.1 rule 5 requires. Omitted (the
   * pre-WL-2a callers) means no stamping at all.
   */
  nowNs?: bigint,
  /**
   * R-7 item 5: HOW this scan's first sightings were established — supplied by
   * the caller, which is the only layer that knows whether this device already
   * held cache state before the sweep. Omitted (pre-this-change callers)
   * stamps `firstSeenAtNs` exactly as before with no provenance, which reads
   * as absent — the conservative "we cannot vouch this was a live scan".
   */
  firstSeenVia?: "live-scan" | "recovery-import",
): CachedScanState {
  const outcomeIndices = new Set(outcome.notes.map((n) => n.leafIndex));
  // JOURNAL OWNERSHIP GUARD (L3c): nullifiers owned by an ACTIVE spend-journal
  // entry can never be spendable after the merge.
  const journalOwnedNullifiers = new Set(
    (state.spendJournal?.entries ?? [])
      .filter((e) =>
        ["planned", "dispatched", "payout-pending", "recovery-required"].includes(e.status),
      )
      .map((e) => e.nullifierHex)
      .filter((h) => h.length === 64),
  );
  const stamped =
    nowNs === undefined
      ? outcome.notes
      : outcome.notes.map((n) =>
          n.firstSeenAtNs === undefined
            ? {
                ...n,
                firstSeenAtNs: nowNs.toString(10),
                ...(firstSeenVia !== undefined ? { firstSeenVia } : {}),
              }
            : n,
        );
  const notes = mergeScannedNotes(state.notes, stamped).map((n) => {
    if (
      !outcomeIndices.has(n.leafIndex) &&
      n.state === "spendable" &&
      n.nullifier !== undefined &&
      outcome.spentSet.has(hexKey(n.nullifier))
    ) {
      return { ...n, state: "spent" as const };
    }
    // Journal-ownership guard — after all other reconciliation.
    if (
      n.nullifier !== undefined &&
      n.state === "spendable" &&
      journalOwnedNullifiers.has(hexKey(n.nullifier))
    ) {
      return { ...n, state: "pending" as const };
    }
    return n;
  });
  return {
    ...state,
    notes,
    lastScannedIndex:
      state.lastScannedIndex > outcome.scannedUpTo ? state.lastScannedIndex : outcome.scannedUpTo,
    mirrorHead: outcome.mirrorHead,
    quarantine: mergeQuarantine(state.quarantine, outcome.quarantine),
  };
}

/**
 * Full cache-aware scan: strict spent-set download + validated sweep + ONE
 * atomic cache update (PrincipalNoteCache.update CAS — re-checks the session
 * epoch immediately before committing). The merge function is pure, so a
 * lost CAS re-applies cleanly against the winner's state (§1.1 rule 5).
 *
 * The mirror-root integrity check requires a full sweep from index 0 (the
 * mirror is rebuilt from downloaded pages each scan), so runScan always
 * scans from 0; the merge dedups by leaf index, so a rescan is idempotent.
 */
export async function runScan(deps: RunScanDeps): Promise<CachedScanState> {
  const outcome = await scanAndValidate(
    deps,
    deps.tryDecrypt,
    deps.masterNoteSecret,
    { fromIndex: 0n, pageSize: deps.pageSize, onProgress: deps.onProgress },
  );
  // One clock read for the whole merge, taken BEFORE the CAS loop: a lost CAS
  // re-applies the same pure merge with the same instant, never a later one.
  const seenAtNs = (deps.nowNs ?? (() => BigInt(Date.now()) * 1_000_000n))();
  return deps.cache.update((state) => mergeScanOutcome(state, outcome, seenAtNs));
}

/** What `runVerifiedScan` reports back to the UI. */
export type RunVerifiedScanResult =
  | { status: "verified"; state: CachedScanState; metadata: VerifiedScanMetadata }
  | { status: "no-accepted-root" };

export interface RunVerifiedScanDeps extends RunScanDeps {
  /** The CONFIGURED deployment the attestation is checked against (AC-11). */
  binding: DeploymentBinding;
  /** Advisory wall clock for the evidence record. Injected for tests. */
  nowMs?: () => number;
  /** Test seam for the sweep ceiling. */
  maxLeaves?: bigint;
}

/**
 * THE ONE verified commit (WALLET-AUTH G1b, SSA F-1).
 *
 * Every route that turns a completed verified sweep into cache state goes
 * through this function and no other. That is not tidiness: a verified sweep
 * has TWO entry points by construction — the in-process `runVerifiedScan` and
 * the Web Worker route (`runScannerWorker` -> `scanAndValidateVerified` in the
 * worker, metadata posted back) — and at G1 only the first of them checked the
 * floor. The second one is the route a UI button reaches, so the rollback
 * defence existed on the function nobody called. A second, weaker copy of the
 * check is the exact failure the parent brief's invariant 2 forbids for
 * `syncMirror`, and it applies here for the same reason.
 *
 * So the check and the advance are welded together here, and the two routes
 * differ only in HOW the sweep was run, never in what is required of its
 * result.
 *
 * PURE and re-appliable: `checkVerifiedFloor` throws or returns, and
 * `advanceVerifiedFloor` is pure, so a lost CAS re-runs this identically. It is
 * meant to be called INSIDE `cache.update(fn)` — see `runVerifiedScan` for why
 * that placement, not an earlier read, is the load-bearing part.
 */
export function commitVerifiedScan(
  state: CachedScanState,
  outcome: ScanOutcome,
  metadata: VerifiedScanMetadata,
  seenAtNs: bigint,
  firstSeenVia?: "live-scan" | "recovery-import",
): CachedScanState {
  // Refuse a rollback BEFORE anything about this sweep is recorded.
  checkVerifiedFloor(state, metadata);
  return advanceVerifiedFloor(
    mergeScanOutcome(state, outcome, seenAtNs, firstSeenVia),
    metadata,
  );
}

/**
 * Cache-aware verified scan: sweep, then ONE atomic cache update that does the
 * floor check and the floor advance together.
 *
 * WHY BOTH INSIDE `update(fn)`. `fn` runs against the state that is about to be
 * committed, under the revision CAS. Checking the floor anywhere earlier would
 * read a state another tab could replace before the write lands, which is
 * exactly the check-then-act window a monotone floor must not have. A throw
 * from `fn` propagates out of `update` having written nothing.
 *
 * ORDERING (brief G-3, AC-16): `fn` is not reached at all unless the ENTIRE
 * sweep succeeded — anchor matched, spent set stable, digest computed. A sweep
 * that dies after the root match and before the digest leaves the floor exactly
 * where it was, because nothing was called.
 */
export async function runVerifiedScan(deps: RunVerifiedScanDeps): Promise<RunVerifiedScanResult> {
  const result = await scanAndValidateVerified(deps, deps.binding, deps.tryDecrypt, deps.masterNoteSecret, {
    fromIndex: 0n,
    pageSize: deps.pageSize,
    onProgress: deps.onProgress,
    nowMs: deps.nowMs,
    maxLeaves: deps.maxLeaves,
  });
  if (result.status === "no-accepted-root") return result;

  const seenAtNs = (deps.nowNs ?? (() => BigInt(Date.now()) * 1_000_000n))();
  const state = await deps.cache.update((current) =>
    // THE ONE verified commit — shared verbatim with the worker route (F-1).
    commitVerifiedScan(current, result.outcome, result.metadata, seenAtNs),
  );
  return { status: "verified", state, metadata: result.metadata };
}
