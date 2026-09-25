// =============================================================================
// STSH Public Solvency Signals — page bootstrap + rendering.
//
// Honest scope: with the pool-side get_solvency_attestation landed (D-2 + D-4,
// docs/SOLVENCY_ATTESTATION_SPEC.md) this page proves token supply integrity +
// pool holdings + freshness + THE FULL SOLVENCY DELTA.
//
// What it still does NOT prove, and the copy says so: that a healthy delta is
// informative. The published value is clamped to min(delta, 0), so healthy
// always reads 0 by construction — the clamp is a privacy measure, not a
// measurement, and a reader must not take "0" as "we checked the exact float".
// Treasury stray funds are YELLOW and never affect backing.
// =============================================================================

import { fetchCertifiedSnapshot, MonitorConfig } from './canister';
import {
  buildReleaseRows,
  canisterBuildSource,
  renderReleaseRows,
  type VerifiedSchemaInput,
} from './releasePanel';
import {
  deriveDisplayState,
  DisplayState,
  formatStsh,
  SnapshotStatus,
  SourceReadStatus,
  TreasuryDisplay,
} from './verify';

const REFRESH_PAGE_MS = 60_000;

function config(): MonitorConfig {
  const params = new URLSearchParams(window.location.search);
  const monitorCanisterId = params.get('monitor') ?? import.meta.env.VITE_MONITOR_CANISTER_ID ?? '';
  const host = params.get('host') ?? import.meta.env.VITE_IC_HOST ?? 'https://icp-api.io';
  // Local-dev root key fetch: explicit opt-in only; never the default.
  const devFetchRootKey = import.meta.env.DEV && params.get('devroot') === '1';
  return { monitorCanisterId, host, devFetchRootKey };
}

/** The only DOM surface the detail renderer needs. Narrowed to exactly this so
 *  the renderer is unit-testable without a full DOM implementation — the
 *  package has no jsdom/happy-dom dependency and the gate installs from the
 *  committed lockfile only (`npm ci`), so a DOM-library dependency is not
 *  available to add. See R-4 packet. */
export interface Cell {
  textContent: string;
  className: string;
}

export type CellLookup = (id: string) => Cell;

function el(id: string): HTMLElement {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing element #${id}`);
  return e;
}

/** Three states, not two (R-4 S-c): the invariant HOLDS, is VIOLATED, or could
 *  not be COMPUTED. Rendering "VIOLATED" for a state that is actually "we could
 *  not add it up" is a false accusation against the ledger. */
export function supplyInvariantText(snapshot: {
  supplyInvariantHolds: boolean;
  supplyInvariantUnavailable: boolean;
}): string {
  if (snapshot.supplyInvariantUnavailable) return 'UNAVAILABLE — could not compute';
  return snapshot.supplyInvariantHolds ? 'HOLDS ✓' : 'VIOLATED ✗';
}

/** The YELLOW row (L08-01). Returns the cell text and the row class — `yellow`
 *  for both `stray` and `unknown`, none for `none`. This function never sees
 *  `reasons` or `light`, by construction. */
export function treasuryRowContent(
  treasury: TreasuryDisplay,
  readStatus: SourceReadStatus,
): { text: string; className: string } {
  switch (treasury.kind) {
    case 'stray':
      return {
        text: `${formatStsh(treasury.amountE8s ?? 0n)} STSH`,
        className: 'yellow',
      };
    case 'unknown':
      return {
        text: `UNKNOWN — treasury read failed (${SourceReadStatus[readStatus]})`,
        className: 'yellow',
      };
    case 'none':
    default:
      return { text: '0 STSH', className: '' };
  }
}

/** Renders the detail table from a derived state. Pure with respect to its
 *  `lookup`: `main` passes the real DOM, tests pass a stub. */
export function renderDetailRows(state: DisplayState, lookup: CellLookup): void {
  const s = state.snapshot;
  if (!s) return;
  lookup('supply-invariant').textContent = supplyInvariantText(s);
  lookup('fixed-max-supply').textContent = `${formatStsh(s.fixedMaxSupplyE8s)} STSH`;
  lookup('sum-balances').textContent = `${formatStsh(s.sumAllBalancesE8s)} STSH`;
  lookup('pool-balance').textContent = `${formatStsh(s.poolBalanceE8s)} STSH`;
  const treasuryCell = lookup('treasury-stray');
  const treasuryRow = treasuryRowContent(state.treasury, s.treasuryReadStatus);
  treasuryCell.textContent = treasuryRow.text;
  treasuryCell.className = treasuryRow.className;
  lookup('monitor-status').textContent = SnapshotStatus[s.status];
}

function fmtAge(ageNs: bigint): string {
  const secs = Number(ageNs / 1_000_000_000n);
  if (secs < 120) return `${secs}s ago`;
  if (secs < 7200) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

/** The live page update: read the monitor, derive, and paint EVERY surface —
 *  badge, reasons, the detail rows and the age line. Exported solely so
 *  `page.test.ts` can drive this exact function over a fake DOM.
 *
 *  It is exported because AC-3's helper tests call `renderDetailRows` directly,
 *  which leaves the CALL SITE below unbound: removing `renderDetailRows(state,
 *  el)` from this function left all 60 tests green while the production page
 *  could no longer populate a single detail row (SSA landed-diff round-1
 *  RED-2). A helper is not a seam if nothing asserts that the page invokes it. */
export async function refresh(): Promise<void> {
  const cfg = config();
  const badge = el('badge');
  const detail = el('detail');
  const reasons = el('reasons');

  // J-25: the release panel is repainted on EVERY pass, including the failure
  // paths, so a schema label left by an earlier success is cleared rather than
  // surviving as a current claim (D-4 / SSA addendum B).
  const paintRelease = (verifiedSchema: VerifiedSchemaInput | null): void => {
    renderReleaseRows(
      buildReleaseRows({ buildSource: canisterBuildSource(), verifiedSchema }),
      el,
    );
  };

  if (!cfg.monitorCanisterId) {
    paintRelease(null);
    badge.className = 'badge unknown';
    badge.textContent = 'NOT CONFIGURED';
    reasons.textContent =
      'No monitor canister id configured (set ?monitor=<canister-id> or VITE_MONITOR_CANISTER_ID).';
    return;
  }

  badge.className = 'badge unknown';
  badge.textContent = 'CHECKING…';

  let read;
  try {
    read = await fetchCertifiedSnapshot(cfg);
  } catch (e) {
    read = {
      certificateVerified: false,
      canonicalBytes: null,
      certTimeNs: null,
      failureDetail: `monitor unreachable: ${(e as Error).message}`,
    };
  }

  const state = deriveDisplayState(read);

  badge.className = `badge ${state.light}`;
  badge.textContent =
    state.light === 'green'
      ? 'SIGNALS HEALTHY'
      : state.light === 'red'
        ? 'ALERT'
        : 'UNKNOWN / UNVERIFIED';

  const allReasons = [...state.reasons];
  if (read.failureDetail) allReasons.push(read.failureDetail);
  reasons.innerHTML = '';
  for (const r of allReasons) {
    const li = document.createElement('li');
    li.textContent = r;
    reasons.appendChild(li);
  }

  // The schema row's ONLY source is a snapshot that came back through
  // `deriveDisplayState` with a verified certificate and a clean parse; that is
  // exactly `state.snapshot !== null`. Staleness is the same comparison the
  // derivation itself makes, so the row cannot say "current" about a snapshot
  // the page is already calling stale.
  paintRelease(
    state.snapshot === null
      ? null
      : {
          schemaVersion: state.snapshot.schemaVersion,
          stale: state.ageNs !== null && state.ageNs > state.snapshot.maxStalenessNs,
        },
  );

  if (state.snapshot) {
    renderDetailRows(state, el);
    el('last-updated').textContent =
      state.ageNs !== null
        ? `${fmtAge(state.ageNs)} (certificate-verified)`
        : 'unknown';
    detail.hidden = false;
  } else {
    detail.hidden = true;
  }
}

// Browser-only bootstrap. Guarded so the render helpers above can be imported
// by the (node-environment) vitest suite without the module starting a poll
// loop on import.
if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  void refresh();
  setInterval(() => void refresh(), REFRESH_PAGE_MS);
}
