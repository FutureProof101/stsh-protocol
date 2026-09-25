/**
 * J-25 — the wallet's "Release" footer: mount, render and the one anonymous
 * session-cached observation that feeds two of its rows.
 *
 * The production shell calls `mountReleaseFooter` exactly once. Deleting that
 * call, or replacing its source with a constant, fails the integration suite
 * (D-5) — a panel nothing mounts is not a panel.
 */

import { spendManifest } from "../zk/artifacts";
import { canisterBuildSource } from "../release/buildSource";
import {
  PoolIdentityCache,
  poolIdentityKey,
  type PoolIdentityObservation,
  type PoolIdentityReader,
} from "../release/poolIdentity";
import {
  proverAssetVerificationAt,
  subscribeProverAssetVerification,
} from "../release/proverVerification";
import { buildWalletReleaseRows, type ReleaseRow } from "../release/walletPanel";
import { el } from "./dom";

/** Render the rows into `panel`, replacing whatever was there. */
export function renderReleaseRows(panel: HTMLElement, rows: ReleaseRow[]): void {
  const items = rows.map((row) => {
    const children: Array<Node | string> = [
      el("span", { class: "release-label" }, [row.label]),
    ];
    if (row.value !== null) {
      children.push(
        el(
          "span",
          { class: row.monospace === true ? "release-value mono" : "release-value" },
          [row.value],
        ),
      );
    }
    if (row.poolValue !== undefined) {
      children.push(
        el(
          "span",
          { class: row.monospace === true ? "release-pool-value mono" : "release-pool-value" },
          [row.poolValue],
        ),
      );
    }
    children.push(el("span", { class: "release-source" }, [row.source]));
    children.push(el("span", { class: "release-trust" }, [row.trust]));
    return el(
      "li",
      { class: `release-row release-${row.state}`, "data-release-row": row.label },
      children,
    );
  });
  panel.replaceChildren(
    el("h2", { class: "release-heading" }, ["Release"]),
    el("ul", { class: "release-rows" }, items),
  );
}

/**
 * The mounted panel. `mountApp` KEEPS this handle: `dispose` unsubscribes the
 * verification listener, and holding it is what makes the panel's lifecycle
 * explicit rather than a fire-and-forget side effect (RED-1).
 */
export interface ReleaseFooterHandle {
  footer: HTMLElement;
  /** Resolves with the settled observation, so the suite can await paint 2. */
  observed: Promise<PoolIdentityObservation>;
  /** Stop listening for verification events; the panel stops repainting. */
  dispose: () => void;
}

export interface ReleaseFooterDeps {
  /** The configured pool + host; supplies the observation's cache key. */
  config: { poolCanisterId: string; host: string };
  /** The ANONYMOUS reader, or null when no pool is configured. */
  reader: PoolIdentityReader | null;
  /** Shared across the session so rerenders never multiply requests. */
  cache: PoolIdentityCache;
  /** Overridable only for tests. */
  proverVerifiedAt?: () => number | null;
  formatTime?: (atMs: number) => string;
}

/**
 * Mount the footer into `container` and start its single observation.
 *
 * The panel paints IMMEDIATELY with `observation: null` — an offline start
 * shows the build source and the manifest-declared values as "unverified
 * against pool", never as a match. When the observation settles the panel
 * repaints. Returns the footer element and the settled observation, so the
 * suite can await the second paint.
 */
export function mountReleaseFooter(
  container: HTMLElement,
  deps: ReleaseFooterDeps,
): ReleaseFooterHandle {
  const footer = el("footer", { class: "release-panel", "data-release-panel": "wallet" });
  const proverVerifiedAt = deps.proverVerifiedAt ?? proverAssetVerificationAt;

  // The most recent observation this footer has painted. The verification
  // repaint (RED-1) must not regress the pool rows back to "query in progress",
  // so it repaints with what is already known rather than with null.
  let latest: PoolIdentityObservation | null = null;

  const paint = (observation: PoolIdentityObservation | null): void => {
    latest = observation;
    renderReleaseRows(
      footer,
      buildWalletReleaseRows({
        // Read from the injected define at paint time; there is no other source
        // and no constant in this module (D-1 / D-5).
        buildSource: canisterBuildSource(),
        manifest: {
          circuitVersion: spendManifest.circuitVersion,
          vkHash: spendManifest.vkHash,
        },
        observation,
        proverVerifiedAtMs: proverVerifiedAt(),
        formatTime: deps.formatTime,
      }),
    );
  };

  paint(null);
  container.append(footer);

  // RED-1: the verification event happens during a spend, long after both
  // paints above. Subscribe to the REAL recorder so the row transitions when it
  // actually fires; polling would be a second source of truth for the same
  // event. The handle's `dispose` drops the subscription with the panel.
  const unsubscribe = subscribeProverAssetVerification(() => {
    paint(latest);
  });

  const key = poolIdentityKey(deps.config);
  const startedAt = deps.cache.observe(key, deps.reader);
  // RED-2: captured AFTER observe() so it names the request this mount started
  // (or the in-flight one it joined). `peek(key) !== null` alone cannot tell an
  // obsolete A response from the current one after A -> B -> A or a reset.
  const generation = deps.cache.generation();
  const observed = startedAt.then((observation) => {
    // A late response whose configuration or session has moved on must not
    // paint (addendum E + RED-2).
    if (deps.cache.generation() === generation && deps.cache.peek(key) !== null) {
      paint(observation);
    }
    return observation;
  });

  return { footer, observed, dispose: unsubscribe };
}
