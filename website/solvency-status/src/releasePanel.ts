// =============================================================================
// J-25 — the reserves.stsh.fi "Release" panel.
//
// Brief V3 §1 source matrix for this site, three rows:
//   Canister build source     — the injected [build].source_sha
//   Monitor snapshot schema   — the schema_version of the snapshot that PASSED
//                               certificate verification, and only that
//   Circuit version / VK hash — present, explicitly not attested here
//
// The schema row is bound to the VERIFIED path (SSA addendum B / D-4): a
// failed or unavailable read has NO currently-verified schema, and any label a
// previous success left behind is CLEARED. A stale-but-verified snapshot shows
// its schema carrying the stale status it already has — never a bare number
// that reads as current.
// =============================================================================

declare const __STSH_CANISTER_BUILD_SOURCE__: string | undefined;

const FULL_COMMIT_ID = /^[0-9a-f]{40}$/;

/** The injected canister build source, or null if the bundle carries none. */
export function canisterBuildSource(): string | null {
  const v =
    typeof __STSH_CANISTER_BUILD_SOURCE__ === 'string' ? __STSH_CANISTER_BUILD_SOURCE__ : null;
  if (v === null || !FULL_COMMIT_ID.test(v)) return null;
  return v;
}

export interface ReleaseRow {
  label: string;
  value: string | null;
  source: string;
  trust: string;
  state: 'informational' | 'verified' | 'stale' | 'unavailable';
}

/** Exactly what the schema row is allowed to see: the verified snapshot's
 *  schema and whether that verified snapshot is stale. `null` means there is
 *  no currently-verified snapshot at all. */
export interface VerifiedSchemaInput {
  schemaVersion: number;
  stale: boolean;
}

export function buildReleaseRows(input: {
  buildSource: string | null;
  verifiedSchema: VerifiedSchemaInput | null;
}): ReleaseRow[] {
  const rows: ReleaseRow[] = [];

  rows.push(
    input.buildSource === null
      ? {
          label: 'Canister build source',
          value: null,
          source: 'committed release record',
          trust: 'not available from this build',
          state: 'unavailable',
        }
      : {
          label: 'Canister build source',
          value: input.buildSource,
          source: 'committed release record',
          trust:
            'from the committed release record; this is the canister build source, ' +
            'not the UI commit',
          state: 'informational',
        },
  );

  rows.push(
    input.verifiedSchema === null
      ? {
          label: 'Monitor snapshot schema',
          value: null,
          source: 'certificate-verified monitor snapshot',
          trust: 'no currently verified snapshot — no schema to report',
          state: 'unavailable',
        }
      : {
          label: 'Monitor snapshot schema',
          value: String(input.verifiedSchema.schemaVersion),
          source: 'certificate-verified monitor snapshot',
          trust: input.verifiedSchema.stale
            ? 'from the verified monitor snapshot — STALE, see the status above'
            : 'from the verified monitor snapshot',
          state: input.verifiedSchema.stale ? 'stale' : 'verified',
        },
  );

  rows.push({
    label: 'Circuit version / VK hash',
    value: null,
    source: '—',
    trust: 'not attested by this snapshot; see app.stsh.fi',
    state: 'unavailable',
  });

  return rows;
}

/** The only DOM surface the panel renderer needs — same narrowing rationale as
 *  `CellLookup` in main.ts: this package has no jsdom dependency and cannot
 *  add one (the gate installs from the committed lockfile only). */
export interface PanelSurface {
  textContent: string;
  className: string;
}

export type PanelLookup = (id: string) => PanelSurface;

/** Paint the three rows. Every row is repainted on every call, which is what
 *  CLEARS a stale label after a verification failure (D-4). */
export function renderReleaseRows(rows: ReleaseRow[], lookup: PanelLookup): void {
  const byLabel = new Map(rows.map((r) => [r.label, r]));
  const paint = (id: string, label: string): void => {
    const row = byLabel.get(label);
    const cell = lookup(id);
    if (!row) {
      cell.textContent = '—';
      cell.className = '';
      return;
    }
    cell.textContent = row.value === null ? row.trust : `${row.value} — ${row.trust}`;
    cell.className = `release-${row.state}`;
  };
  paint('release-build-source', 'Canister build source');
  paint('release-snapshot-schema', 'Monitor snapshot schema');
  paint('release-circuit', 'Circuit version / VK hash');
}
