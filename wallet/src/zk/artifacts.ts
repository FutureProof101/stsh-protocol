/**
 * Proof-artifact manifest + verified loader (Campaign B / L3c — L0-C).
 *
 * The manifest (`./spendManifest.json`) is BUILD-BUNDLED and immutable: it
 * pins the proof-system id, circuit/pool versions, the exported-VK hash
 * (84dba305…, the mainnet-v2 launch VK and the pool pin — A-4, 2026-09-12),
 * and the two proving artifacts with their own
 * SHA-256 + byte length. Hash discipline (ruled): the zkey-file hash and the
 * witness-wasm-file hash are DISTINCT fields — never substituted for the VK
 * hash, which is checked against the pool's live attestation instead.
 *
 * The loader streams each artifact with a byte cap (never Content-Length),
 * fetches ONCE, hashes the exact bytes, verifies length + SHA-256, and only
 * then hands a Blob to the prover worker as an OBJECT URL. The worker never
 * sees a network URL; every Blob URL is revoked in `finally`.
 *
 * The handler (`assertManifestAttestation`) compares the pool's live
 * deployment attestation against the manifest: versions, proof-system id, and
 * VK hash are ALWAYS enforced; deployment principals are enforced wherever
 * the manifest pins them (the mainnet wiring tuple is a release-gate value —
 * until then the P-DOM update-side hash + domainGuard is the principal
 * authority; an empty manifest field is "unpinned at this build", documented,
 * never silently skipped when present).
 */

import manifestJson from "./spendManifest.json";
import { SessionCancelledError } from "../session/taskOwner";
import { Principal } from "@dfinity/principal";
import { recordProverAssetVerification } from "../release/proverVerification";

// ── Types ────────────────────────────────────────────────────────────────────

export interface ArtifactPin {
  id: string;
  path: string;
  sha256: string;
  bytes: number;
}

export interface SpendManifest {
  manifestVersion: number;
  proofSystemId: string;
  circuitVersion: number;
  poolVersion: number;
  networkId: number;
  assetId: number;
  vkHash: string;
  frozenPoolPrincipal: string;
  artifacts: ArtifactPin[];
}

export const spendManifest: SpendManifest = manifestJson as SpendManifest;

/**
 * The deployment-wiring tuple the attestation is compared against. Resolved
 * per environment (VITE_* — the SAME wiring the P-DOM binding enforces).
 * EVERY field is mandatory: an empty or malformed principal is a manifest
 * error at resolution time, NEVER an optional runtime skip.
 */
export interface DeploymentTuple {
  pool: string;
  token: string;
  merkle: string;
  nullifier: string;
  verifier: string;
}

/** The pool's live deployment attestation (P-DOM, advisory getter). */
export interface DeploymentAttestationView {
  pool: string;
  token: string;
  merkle: string;
  nullifier: string;
  verifier: string | null;
  vkHash: string;
  circuitVersion: number;
  poolVersion: number;
  proofSystem: string;
}

export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestError";
  }
}

const HEX64 = /^[0-9a-f]{64}$/i;

/** Build-time structural validation of the bundled manifest itself. */
export function assertManifestStructure(m: SpendManifest = spendManifest): void {
  if (!Number.isInteger(m.manifestVersion) || m.manifestVersion < 1) {
    throw new ManifestError("manifest has no valid manifestVersion");
  }
  if (m.proofSystemId !== "groth16-bn254") {
    throw new ManifestError(`manifest proofSystemId must be "groth16-bn254", got "${m.proofSystemId}"`);
  }
  if (!HEX64.test(m.vkHash)) {
    throw new ManifestError("manifest vkHash is not a 32-byte hex value");
  }
  if (m.frozenPoolPrincipal.trim() === "") {
    throw new ManifestError("manifest frozenPoolPrincipal is empty");
  }
  if (!Array.isArray(m.artifacts) || m.artifacts.length !== 2) {
    throw new ManifestError("manifest must pin exactly two proving artifacts");
  }
  for (const a of m.artifacts) {
    if (a.path.trim() === "" || !HEX64.test(a.sha256) || !(a.bytes > 0)) {
      throw new ManifestError(`manifest artifact pin for "${a.id}" is incomplete`);
    }
  }
}

/**
 * Validate the environment-resolved deployment tuple: EVERY principal must be
 * present and non-empty — a missing one is a manifest error (spend disabled),
 * never an optional runtime skip (L0-C).
 */
export function assertDeploymentTuple(tuple: DeploymentTuple): void {
  for (const [key, value] of Object.entries(tuple)) {
    if (typeof value !== "string" || value.trim() === "") {
      throw new ManifestError(
        `deployment tuple field "${key}" is empty — the wiring manifest is not fully ` +
          "populated for this environment; spend is disabled (no optional pins)",
      );
    }
    try {
      Principal.fromText(value);
    } catch {
      throw new ManifestError(
        `deployment tuple field "${key}" is not a valid principal: "${value}" — spend is disabled`,
      );
    }
  }
  // tuple.pool must equal the manifest's frozen pool (a wallet configured for
  // pool X must not accept an attestation for frozen pool Y, even when every
  // other dependency matches).
  if (tuple.pool !== spendManifest.frozenPoolPrincipal) {
    throw new ManifestError(
      `runtime pool "${tuple.pool}" does not equal the frozen manifest pool ` +
        `"${spendManifest.frozenPoolPrincipal}" — spend is disabled`,
    );
  }
}

/**
 * Fail-closed manifest↔attestation comparison (COMPLETE C-DOM tuple, L0-C):
 * versions, proof-system id, VK hash, the frozen pool principal, and ALL FIVE
 * deployment-wiring principals (token / merkle / nullifier / verifier must
 * match the pool's OWN attestation — the pool's real dependencies, not just
 * wallet config). A mismatch DISABLES spend (never a warning).
 */
export function assertManifestAttestation(
  att: DeploymentAttestationView,
  tuple: DeploymentTuple,
): void {
  assertManifestStructure();
  assertDeploymentTuple(tuple);
  const m = spendManifest;
  if (att.circuitVersion !== m.circuitVersion) {
    throw new ManifestError(
      `circuit version mismatch: pool ${att.circuitVersion} vs manifest ${m.circuitVersion}`,
    );
  }
  if (att.poolVersion !== m.poolVersion) {
    throw new ManifestError(
      `pool version mismatch: pool ${att.poolVersion} vs manifest ${m.poolVersion}`,
    );
  }
  if (att.proofSystem !== m.proofSystemId) {
    throw new ManifestError(
      `proof system mismatch: pool "${att.proofSystem}" vs manifest "${m.proofSystemId}"`,
    );
  }
  if (att.vkHash.toLowerCase() !== m.vkHash.toLowerCase()) {
    throw new ManifestError("VK hash mismatch: pool attestation does not match the bundled manifest");
  }
  if (att.pool !== m.frozenPoolPrincipal) {
    throw new ManifestError("pool principal mismatch: attestation does not match the frozen manifest pool");
  }
  if (att.token !== tuple.token) {
    throw new ManifestError("deployment wiring mismatch on token principal");
  }
  if (att.merkle !== tuple.merkle) {
    throw new ManifestError("deployment wiring mismatch on merkle principal");
  }
  if (att.nullifier !== tuple.nullifier) {
    throw new ManifestError("deployment wiring mismatch on nullifier principal");
  }
  if (att.verifier !== tuple.verifier) {
    throw new ManifestError("deployment wiring mismatch on verifier principal");
  }
}

// ── Streaming verified loader (L0-C) ─────────────────────────────────────────

/** Hard cap on an artifact stream — independent of the pinned length. */
const MAX_ARTIFACT_STREAM_BYTES = 16 * 1024 * 1024;

function hexLower(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return hexLower(new Uint8Array(digest));
}
function abortable<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
  message: string,
): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) {
    void promise.catch(() => undefined);
    return Promise.reject(new SessionCancelledError(message));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      fn();
    };
    const onAbort = () =>
      settle(() => reject(new SessionCancelledError(message)));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    promise.then(
      (value) => settle(() => resolve(value)),
      (error: unknown) => settle(() => reject(error)),
    );
  });
}

/** Fetch one artifact ONCE with a streaming byte cap and return its exact bytes. */
export async function fetchCapped(
  path: string,
  cap: number = MAX_ARTIFACT_STREAM_BYTES,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  if (signal?.aborted) {
    throw new SessionCancelledError("artifact fetch was cancelled");
  }
  const res = await abortable(fetch(path, { signal }), signal, "artifact fetch was cancelled");
  if (!res.ok) {
    throw new ManifestError(`artifact fetch failed (${res.status}) for ${path}`);
  }
  const reader = res.body?.getReader();
  if (reader === undefined) {
    throw new ManifestError(`artifact stream unavailable for ${path}`);
  }
  let readerCancelled = false;
  const cancelReader = () => {
    if (readerCancelled) return;
    readerCancelled = true;
    try {
      void reader.cancel().catch(() => undefined);
    } catch {
      // A broken source cannot keep the session task alive during cleanup.
    }
  };
  signal?.addEventListener("abort", cancelReader, { once: true });
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      if (signal?.aborted) {
        throw new SessionCancelledError("artifact read was cancelled");
      }
      const { done, value } = await abortable(reader.read(), signal, "artifact read was cancelled");
      if (done) break;
      total += value.length;
      if (total > cap) {
        throw new ManifestError(`artifact stream for ${path} exceeds the ${cap}-byte cap`);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  } finally {
    signal?.removeEventListener("abort", cancelReader);
    cancelReader();
    reader.releaseLock();
  }
}

/** Load + verify one pinned artifact; returns an object URL for the worker. */
export async function loadVerifiedArtifact(pin: ArtifactPin, signal?: AbortSignal): Promise<string> {
  // AR2-S1-06. This was `Math.max`, which meant the cap was never the binding
  // one: every pinned artifact is smaller than the 16 MiB ceiling, so the bound
  // was always 16 MiB — and a pin LARGER than the ceiling would have RAISED it,
  // which is the opposite of a cap. The exact length is known here, so the
  // stream stops at the pinned length, and the ceiling stays the absolute
  // upper bound it was named for.
  //
  // Scope: this is a RESOURCE bound and nothing more. What makes a wrong
  // artifact fail closed is the SHA-256 check below, which already did that and
  // is untouched by this change.
  const bytes = await fetchCapped(pin.path, Math.min(pin.bytes, MAX_ARTIFACT_STREAM_BYTES), signal);
  if (bytes.length !== pin.bytes) {
    throw new ManifestError(
      `artifact ${pin.id} length mismatch: ${bytes.length} vs pinned ${pin.bytes}`,
    );
  }
  if (signal?.aborted) {
    throw new SessionCancelledError("artifact hash was cancelled");
  }
  const hash = await abortable(sha256Hex(bytes), signal, "artifact hash was cancelled");
  if (hash !== pin.sha256.toLowerCase()) {
    throw new ManifestError(`artifact ${pin.id} SHA-256 mismatch: ${hash} vs pinned ${pin.sha256}`);
  }
  return URL.createObjectURL(new Blob([bytes as unknown as BlobPart]));
}

export interface ProverAssetUrls {
  wasmUrl: string;
  zkeyUrl: string;
}

/**
 * Load BOTH proving artifacts verified (fetch-once, streaming cap, exact
 * hash) and run `fn` with their object URLs. Every URL is revoked in
 * `finally` — the worker never re-fetches and never sees a network URL (S-16).
 */
export async function withVerifiedProverAssets<T>(
  fn: (assets: ProverAssetUrls) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const urls: string[] = [];
  try {
    const byId = new Map(spendManifest.artifacts.map((a) => [a.id, a]));
    const wasm = byId.get("spend.wasm");
    const zkey = byId.get("spend_1.zkey");
    if (wasm === undefined || zkey === undefined) {
      throw new ManifestError("the bundled manifest does not pin both proving artifacts");
    }
    const wasmUrl = await loadVerifiedArtifact(wasm, signal);
    urls.push(wasmUrl);
    const zkeyUrl = await loadVerifiedArtifact(zkey, signal);
    urls.push(zkeyUrl);
    // J-25 (SSA addendum A.3): BOTH artifacts have now passed their length and
    // SHA-256 checks, so a verification event has actually occurred and the
    // release panel may say so. Recorded here and nowhere else — never at
    // import, never before the second hash matches. Purely descriptive: it
    // gates nothing and the checks above are unchanged.
    recordProverAssetVerification();
    return await abortable(fn({ wasmUrl, zkeyUrl }), signal, "proof work was cancelled");
  } finally {
    // Abort listeners terminate consumers synchronously; revoke on the next
    // microtask so those listeners always run before their URLs disappear.
    await Promise.resolve();
    for (const url of urls) URL.revokeObjectURL(url);
  }
}
