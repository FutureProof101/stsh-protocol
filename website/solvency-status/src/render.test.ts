// =============================================================================
// R-4 S-b / AC-3 + AC-9 — the treasury row renders, in yellow, on its own
// channel; and the page's COPY agrees with what the page actually renders.
//
// DOM NOTE (brief §8 gotcha, answered): this package has no `jsdom` or
// `happy-dom` devDependency, and the gate provisions the website leg with
// `npm ci` from the committed lockfile — never `npm install` — so a DOM
// implementation is not available to add here. `main.ts`'s detail renderer was
// therefore narrowed to a `CellLookup` seam: it writes `textContent` and
// `className` on cells it looks up by id, and nothing else. The stub below IS
// that surface, exactly. The assertions are on the rendered text and the row
// class — the same two things a jsdom assertion would read — so removing the
// treasury row from the renderer still turns this suite RED (M3a).
// =============================================================================

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  Cell,
  renderDetailRows,
  supplyInvariantText,
  treasuryRowContent,
} from './main';
import {
  DisplayState,
  SnapshotStatus,
  SourceReadStatus,
} from './verify';

/** Minimal cell store standing in for the detail table's <td> elements. */
function stubTable(): { cells: Map<string, Cell>; lookup: (id: string) => Cell } {
  const cells = new Map<string, Cell>();
  const lookup = (id: string): Cell => {
    let c = cells.get(id);
    if (!c) {
      c = { textContent: '', className: '' };
      cells.set(id, c);
    }
    return c;
  };
  return { cells, lookup };
}

function stateWith(overrides: Partial<DisplayState['snapshot'] & object>, treasury: DisplayState['treasury']): DisplayState {
  const snapshot = {
    schemaVersion: 3,
    status: SnapshotStatus.Fresh,
    supplyInvariantHolds: true,
    healthy: true,
    fixedMaxSupplyE8s: 100_000_000_000_000_000n,
    sumAllBalancesE8s: 100_000_000_000_000_000n,
    poolBalanceE8s: 123_456_789n,
    refreshedAtNs: 0n,
    maxStalenessNs: 900_000_000_000n,
    poolAttestationSourceStatus: SourceReadStatus.Ok,
    poolDeltaHealthy: true,
    poolPublicDeltaE8s: 0n,
    poolAttestedAtNs: 0n,
    treasuryReadStatus: SourceReadStatus.Ok,
    treasuryStrayFundsE8s: 0n,
    supplyInvariantUnavailable: false,
    ...overrides,
  };
  return { light: 'green', reasons: [], snapshot, ageNs: 0n, treasury };
}

describe('treasury row (AC-3) — yellow, row-level, never the badge', () => {
  it('renders STRAY funds as the amount, in yellow', () => {
    const { lookup, cells } = stubTable();
    renderDetailRows(
      stateWith({ treasuryStrayFundsE8s: 777_000_000n }, { kind: 'stray', amountE8s: 777_000_000n }),
      lookup,
    );
    const cell = cells.get('treasury-stray')!;
    expect(cell.textContent).toContain('7.77');
    expect(cell.textContent).toContain('STSH');
    expect(cell.className).toBe('yellow');
  });

  it('renders an UNKNOWN treasury read in yellow, naming the read status', () => {
    const { lookup, cells } = stubTable();
    renderDetailRows(
      stateWith(
        { treasuryReadStatus: SourceReadStatus.CallFailed },
        { kind: 'unknown', amountE8s: null },
      ),
      lookup,
    );
    const cell = cells.get('treasury-stray')!;
    expect(cell.textContent).toContain('UNKNOWN');
    expect(cell.textContent).toContain('CallFailed');
    expect(cell.className).toBe('yellow');
  });

  it('renders NONE as a plain 0 STSH with no yellow class', () => {
    const { lookup, cells } = stubTable();
    renderDetailRows(stateWith({}, { kind: 'none', amountE8s: 0n }), lookup);
    const cell = cells.get('treasury-stray')!;
    expect(cell.textContent).toBe('0 STSH');
    expect(cell.className).toBe('');
  });

  it('the treasury cell content function never sees reasons or light (AC-4, M3b)', () => {
    // Structural: `treasuryRowContent` takes only the treasury channel and the
    // read status. There is no parameter through which `reasons` could arrive.
    expect(treasuryRowContent({ kind: 'stray', amountE8s: 1n }, SourceReadStatus.Ok).className)
      .toBe('yellow');
    expect(treasuryRowContent({ kind: 'none', amountE8s: 0n }, SourceReadStatus.Ok).className)
      .toBe('');
  });
});

describe('supply invariant cell (AC-5) — three states, not two', () => {
  it('HOLDS', () => {
    expect(supplyInvariantText({ supplyInvariantHolds: true, supplyInvariantUnavailable: false }))
      .toBe('HOLDS ✓');
  });
  it('VIOLATED', () => {
    expect(supplyInvariantText({ supplyInvariantHolds: false, supplyInvariantUnavailable: false }))
      .toBe('VIOLATED ✗');
  });
  it('UNAVAILABLE — and it must NOT read VIOLATED', () => {
    const text = supplyInvariantText({
      supplyInvariantHolds: false,
      supplyInvariantUnavailable: true,
    });
    expect(text).toBe('UNAVAILABLE — could not compute');
    expect(text).not.toContain('VIOLATED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AC-9 — the copy must describe what the page actually does. Reading the served
// HTML is the only way to bind prose to behaviour; a comment cannot.
// ─────────────────────────────────────────────────────────────────────────────
describe('index.html copy agrees with the render (AC-9)', () => {
  const html = readFileSync(
    fileURLToPath(new URL('../index.html', import.meta.url)),
    'utf8',
  );

  it('promises yellow ONLY if a yellow row style actually exists', () => {
    if (/shown in yellow/.test(html)) {
      expect(html).toMatch(/td\.yellow\s*\{/);
    }
    // The row the copy refers to must exist in the table.
    expect(html).toContain('id="treasury-stray"');
    expect(html).toMatch(/td\.yellow\s*\{/);
  });

  it('states that a FAILED treasury read shows UNKNOWN in yellow', () => {
    expect(html).toMatch(/UNKNOWN in yellow/);
  });

  it('states that neither treasury outcome affects the badge', () => {
    expect(html).toMatch(/none of those three outcomes changes the badge/i);
  });

  it('distinguishes VIOLATED from UNAVAILABLE', () => {
    expect(html).toMatch(/VIOLATED is not the same as UNAVAILABLE/i);
    expect(html).toContain('UNAVAILABLE');
  });

  it('states the dual-accept transition window is deployed PAGE-FIRST', () => {
    expect(html).toMatch(/accepts both[\s\S]{0,120}schema 2 and schema 3/i);
    expect(html).toMatch(/page-first/);
    expect(html).toMatch(/schema 2 has no[\s\S]{0,80}UNAVAILABLE/i);
  });
});
