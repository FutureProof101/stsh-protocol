// =============================================================================
// AC-3 (SSA landed-diff round-1 RED-2) — the LIVE render seam.
//
// render.test.ts calls `renderDetailRows` directly with a stub lookup. That
// binds the helper's behaviour, not the page's use of it: the SSA removed ONLY
// the `renderDetailRows(state, el)` call from `refresh()` — leaving the real
// reserves.stsh.fi page unable to populate a single detail row — and all 60
// tests stayed green.
//
// These tests drive `refresh()` itself. The package has no jsdom/happy-dom and
// the gate installs from the committed lockfile with `npm ci`, so a DOM library
// cannot be added; instead the minimum `document`/`window` surface `refresh`
// actually touches is supplied here, and the ids it asks for are checked
// against the REAL index.html so the seam cannot drift to ids that do not
// exist on the page.
//
// Globals are installed INSIDE the tests, never before the import of `./main`:
// the module's bootstrap guard starts a 60 s poll loop when `document` and
// `window` are already defined at import time.
// =============================================================================

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type VerifiedRead } from './canister';
import { canonical, type FixtureFields, T0 } from './canonicalFixture';

const nextRead: { value: VerifiedRead | null; throws: Error | null } = {
  value: null,
  throws: null,
};

vi.mock('./canister', () => ({
  fetchCertifiedSnapshot: async () => {
    if (nextRead.throws) throw nextRead.throws;
    return nextRead.value;
  },
}));

// Imported AFTER the mock declaration (vi.mock is hoisted) and while
// document/window are still undefined, so the poll loop never starts.
const { refresh } = await import('./main');

const INDEX_HTML = readFileSync(
  fileURLToPath(new URL('../index.html', import.meta.url)),
  'utf8',
);

// ── the minimum DOM `refresh` touches ────────────────────────────────────────

interface FakeEl {
  id: string;
  textContent: string;
  className: string;
  innerHTML: string;
  hidden: boolean;
  children: FakeEl[];
  appendChild(c: FakeEl): void;
}

function fakeEl(id: string): FakeEl {
  return {
    id,
    textContent: '',
    className: '',
    innerHTML: '',
    hidden: true,
    children: [],
    appendChild(c: FakeEl) {
      this.children.push(c);
    },
  };
}

let cells: Map<string, FakeEl>;
/** Every id `refresh()` asked the document for, in order. */
let requested: string[];

function installDom(search = '?monitor=aaaaa-aa'): void {
  cells = new Map();
  requested = [];
  (globalThis as Record<string, unknown>).document = {
    getElementById(id: string) {
      requested.push(id);
      let c = cells.get(id);
      if (!c) {
        c = fakeEl(id);
        cells.set(id, c);
      }
      return c;
    },
    createElement: (_tag: string) => fakeEl('<li>'),
  };
  (globalThis as Record<string, unknown>).window = { location: { search } };
}

function cell(id: string): FakeEl {
  const c = cells.get(id);
  if (!c) throw new Error(`refresh() never touched #${id}`);
  return c;
}

// ── the read the mocked canister module returns ──────────────────────────────

/** A healthy schema-3 leaf, built by the SHARED canonical fixture — the same
 *  builder verify.test.ts uses, so this suite can never drift onto a private
 *  copy of the layout. */
function okRead(fields: FixtureFields = {}, certOffsetNs = 1_000_000_000n): VerifiedRead {
  return {
    certificateVerified: true,
    canonicalBytes: canonical({ schemaVersion: 3, ...fields }),
    certTimeNs: T0 + certOffsetNs,
    failureDetail: null,
  } as VerifiedRead;
}

beforeEach(() => {
  nextRead.value = okRead();
  nextRead.throws = null;
  installDom();
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>).document;
  delete (globalThis as Record<string, unknown>).window;
});

// ── the tests ────────────────────────────────────────────────────────────────

describe('AC-3 live render seam — refresh() paints the real page', () => {
  // THE RED-2 TEST. Deleting `renderDetailRows(state, el)` from refresh() makes
  // every one of these assertions fail, because the cells keep their initial ''.
  it('populates every detail row on a successful read', async () => {
    await refresh();

    expect(cell('supply-invariant').textContent).toBe('HOLDS ✓');
    expect(cell('fixed-max-supply').textContent).toBe('1,000,000,000 STSH');
    expect(cell('sum-balances').textContent).toBe('1,000,000,000 STSH');
    expect(cell('pool-balance').textContent).toBe('1.23456789 STSH');
    expect(cell('treasury-stray').textContent).toBe('0 STSH');
    expect(cell('monitor-status').textContent).toBe('Fresh');

    // Not one of them may be left at its initial empty value.
    for (const id of [
      'supply-invariant',
      'fixed-max-supply',
      'sum-balances',
      'pool-balance',
      'treasury-stray',
      'monitor-status',
    ]) {
      expect(cell(id).textContent, `#${id} was never written by refresh()`).not.toBe('');
    }
  });

  it('reveals the detail table and writes the age line', async () => {
    await refresh();
    expect(cell('detail').hidden).toBe(false);
    expect(cell('last-updated').textContent).toMatch(/certificate-verified/);
  });

  it('renders the badge and the reasons list from the derived state', async () => {
    await refresh();
    expect(cell('badge').className).toBe('badge green');
    expect(cell('badge').textContent).toBe('SIGNALS HEALTHY');
    expect(cell('reasons').children).toHaveLength(0);
  });

  it('paints the YELLOW treasury row through the live call, not just the helper', async () => {
    nextRead.value = okRead({ treasuryStrayFundsE8s: 4_200_000_000n });

    await refresh();
    expect(cell('treasury-stray').textContent).toBe('42 STSH');
    expect(cell('treasury-stray').className).toBe('yellow');
    // YELLOW never moves the badge (S-b): backing is unaffected.
    expect(cell('badge').className).toBe('badge green');
  });

  it('renders the exact stale-age boundary as current', async () => {
    nextRead.value = okRead({}, 900_000_000_000n);
    await refresh();
    expect(cell('badge').className).toBe('badge green');
    expect(cell('last-updated').textContent).toMatch(/certificate-verified/);
  });

  it('renders one nanosecond past the stale-age boundary as unknown', async () => {
    nextRead.value = okRead({}, 900_000_000_001n);
    await refresh();
    expect(cell('badge').className).toBe('badge unknown');
    expect(cell('badge').textContent).not.toBe('SIGNALS HEALTHY');
    expect(cell('reasons').children.some((c) => /stale/.test(c.textContent))).toBe(true);
  });

  it('surfaces an UNAVAILABLE invariant through the live call', async () => {
    nextRead.value = okRead({
      supplyInvariantHolds: false,
      supplyInvariantUnavailable: true,
      healthy: false,
    });

    await refresh();
    expect(cell('supply-invariant').textContent).toBe('UNAVAILABLE — could not compute');
    expect(cell('badge').className).toBe('badge red');
  });

  it('hides the detail table and reports the failure when the monitor is unreachable', async () => {
    nextRead.throws = new Error('boom');
    await refresh();
    expect(cell('detail').hidden).toBe(true);
    expect(cell('badge').textContent).not.toBe('SIGNALS HEALTHY');
    expect(cell('reasons').children.length).toBeGreaterThan(0);
    expect(
      cell('reasons').children.some((c) => /monitor unreachable: boom/.test(c.textContent)),
    ).toBe(true);
  });

  it('fails closed with NOT CONFIGURED when no monitor id is supplied', async () => {
    installDom('');
    await refresh();
    expect(cell('badge').textContent).toBe('NOT CONFIGURED');
    expect(cell('badge').className).toBe('badge unknown');
  });
});

describe('AC-3/AC-9 — the ids the live page asks for exist in index.html', () => {
  it('every id requested by refresh() is present in the served markup', async () => {
    await refresh();
    expect(requested.length).toBeGreaterThan(0);
    for (const id of new Set(requested)) {
      expect(INDEX_HTML, `refresh() reads #${id}, which index.html does not define`).toContain(
        `id="${id}"`,
      );
    }
  });

  it('requests the six detail rows plus the badge, reasons, detail and age surfaces', async () => {
    await refresh();
    const seen = new Set(requested);
    for (const id of [
      'badge',
      'detail',
      'reasons',
      'last-updated',
      'supply-invariant',
      'fixed-max-supply',
      'sum-balances',
      'pool-balance',
      'treasury-stray',
      'monitor-status',
    ]) {
      expect(seen.has(id), `refresh() never looked up #${id}`).toBe(true);
    }
  });
});
