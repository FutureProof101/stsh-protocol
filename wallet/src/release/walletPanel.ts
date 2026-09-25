/**
 * J-25 — the wallet's release panel ROWS (brief V3 §1, source matrix).
 *
 * Pure: it turns the four inputs (injected build source, the bundled spend
 * manifest, this session's anonymous pool observation, this session's
 * prover-asset verification event) into the exact rows the footer renders.
 * Every row names its SOURCE and its TRUST STATE; nothing is typed by hand and
 * nothing is called verified unless a verification event occurred.
 *
 * Copy rules held here (SSA addendum A, brief I3):
 *   * "committed release record" — never "signed".
 *   * the build-source row says it is the CANISTER build source, not the UI
 *     commit.
 *   * manifest figures are "manifest-declared"; agreement with the pool is a
 *     SEPARATE, per-value trust state, decided independently for the circuit
 *     version and the VK hash.
 *   * a disagreement shows BOTH values prominently.
 *   * an ordinary pool query is never described as an attestation.
 */

import type { PoolIdentityObservation } from "./poolIdentity";

export interface ReleaseRow {
  /** Row label, e.g. "Canister build source". */
  label: string;
  /** The value shown, or null when there is none to show. */
  value: string | null;
  /** Where the value came from, in the user's words. */
  source: string;
  /** The trust state sentence. Never "verified" without an event. */
  trust: string;
  /** Machine-readable state, for tests and styling. */
  state: "informational" | "agrees" | "disagrees" | "unverified" | "unavailable";
  /** Render `value` as selectable monospace (the full VK hash). */
  monospace?: boolean;
  /** On a disagreement, the value the pool reported. */
  poolValue?: string;
}

export interface WalletManifestView {
  circuitVersion: number;
  vkHash: string;
}

export interface WalletPanelInput {
  /** `[build].source_sha`, injected at build time; null if absent. */
  buildSource: string | null;
  manifest: WalletManifestView;
  /** This session's observation, or null while it is still in flight. */
  observation: PoolIdentityObservation | null;
  /** Epoch ms of this session's prover-asset verification, or null. */
  proverVerifiedAtMs: number | null;
  /** Injected so the rendered string is deterministic under test. */
  formatTime?: (atMs: number) => string;
}

const BUILD_SOURCE_TRUST =
  "from the committed release record; this is the canister build source, not the UI commit";

/** The four trust states a manifest value can be in against the pool. */
function agreementRow(
  label: string,
  manifestValue: string,
  observation: PoolIdentityObservation | null,
  poolValueOf: (o: Extract<PoolIdentityObservation, { kind: "ok" }>) => string,
  monospace: boolean,
): ReleaseRow {
  const base = { label, value: manifestValue, source: "wallet spend manifest", monospace };
  if (observation === null) {
    return {
      ...base,
      trust: "manifest-declared — unverified against pool (query in progress)",
      state: "unverified",
    };
  }
  if (observation.kind === "unconfigured") {
    return {
      ...base,
      trust: "manifest-declared — unverified against pool (no pool configured)",
      state: "unverified",
    };
  }
  if (observation.kind === "failed") {
    return {
      ...base,
      trust: `manifest-declared — unverified against pool (${observation.detail})`,
      state: "unverified",
    };
  }
  const poolValue = poolValueOf(observation);
  if (poolValue === manifestValue) {
    return { ...base, trust: "manifest-declared — agrees with pool", state: "agrees" };
  }
  return {
    ...base,
    trust: `DISAGREES: manifest ${manifestValue}, pool ${poolValue}`,
    state: "disagrees",
    poolValue,
  };
}

function defaultFormatTime(atMs: number): string {
  return new Date(atMs).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/** Build the wallet's five rows, in the order the brief's matrix lists them. */
export function buildWalletReleaseRows(input: WalletPanelInput): ReleaseRow[] {
  const fmt = input.formatTime ?? defaultFormatTime;
  const rows: ReleaseRow[] = [];

  rows.push(
    input.buildSource === null
      ? {
          label: "Canister build source",
          value: null,
          source: "committed release record",
          trust: "not available from this build",
          state: "unavailable",
          monospace: true,
        }
      : {
          label: "Canister build source",
          value: input.buildSource,
          source: "committed release record",
          trust: BUILD_SOURCE_TRUST,
          state: "informational",
          monospace: true,
        },
  );

  rows.push(
    agreementRow(
      "Circuit version",
      String(input.manifest.circuitVersion),
      input.observation,
      (o) => String(o.circuitVersion),
      false,
    ),
  );

  rows.push(
    agreementRow(
      "Verifying-key hash",
      input.manifest.vkHash.toLowerCase(),
      input.observation,
      (o) => o.vkHash.toLowerCase(),
      true,
    ),
  );

  rows.push(
    input.proverVerifiedAtMs === null
      ? {
          label: "Prover-asset verification",
          value: null,
          source: "this browser session",
          trust: "not yet verified this session",
          state: "unverified",
        }
      : {
          label: "Prover-asset verification",
          value: null,
          source: "this browser session",
          trust: `verified this session at ${fmt(input.proverVerifiedAtMs)}`,
          state: "agrees",
        },
  );

  rows.push({
    label: "Attestation schema",
    value: null,
    source: "—",
    trust: "not available from this source",
    state: "unavailable",
  });

  return rows;
}
