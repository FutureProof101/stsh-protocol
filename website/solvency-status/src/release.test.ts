// =============================================================================
// J-25 — release identity labelling on reserves.stsh.fi.
//
// Covers, for this site: D-1 (build identity, adversarial), D-2 (pin
// independence), D-4 (schema rows through the VERIFIED path only) and the
// website half of D-5 (production wiring in `refresh()`, not just the helper).
//
// The live-page tests reuse page.test.ts's construction — a mocked canister
// module plus the minimum DOM surface — for the same reason it exists: a green
// helper suite is not evidence that the deployed page renders anything.
// =============================================================================

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type VerifiedRead } from './canister';
import { canonical, type FixtureFields, T0 } from './canonicalFixture';
import { RELEASE_RECORD_PATH, REPO_ROOT, releaseDefines } from './loadReleaseRecord';
import {
  buildReleaseRows,
  canisterBuildSource,
  renderReleaseRows,
  type PanelSurface,
} from './releasePanel';
import { ReleaseRecordError, selectBuildSourceSha } from './releaseRecord';

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

const { refresh } = await import('./main');

const RECORD = readFileSync(RELEASE_RECORD_PATH, 'utf8');
const INDEX_HTML = readFileSync(fileURLToPath(new URL('../index.html', import.meta.url)), 'utf8');

// ─────────────────────────────────────────────────────────────────────────────
// D-1 — build identity: the emitted value is the RECORD's, not HEAD, not a
// constant, and not a similarly named key from another section.
// ─────────────────────────────────────────────────────────────────────────────

describe('J-25 D-1 — [build].source_sha selection', () => {
  it('selects the [build] value, not the [wallet_bundle] one', () => {
    const toml = [
      '[build]',
      'source_sha = "1111111111111111111111111111111111111111"',
      '',
      '[wallet_bundle]',
      'source_sha = "2222222222222222222222222222222222222222"',
    ].join('\n');
    expect(selectBuildSourceSha(toml)).toBe('1111111111111111111111111111111111111111');
  });

  it('ignores decoy keys in other sections that appear BEFORE [build]', () => {
    const toml = [
      '[toolchain]',
      'source_sha = "3333333333333333333333333333333333333333"',
      '[wasm.vault]',
      'source_sha = "4444444444444444444444444444444444444444"',
      '[build]',
      'source_sha = "5555555555555555555555555555555555555555"',
    ].join('\n');
    expect(selectBuildSourceSha(toml)).toBe('5555555555555555555555555555555555555555');
  });

  it('ignores a commented-out [build].source_sha', () => {
    const toml = [
      '[build]',
      '#source_sha = "6666666666666666666666666666666666666666"',
      'source_sha = "7777777777777777777777777777777777777777"',
    ].join('\n');
    expect(selectBuildSourceSha(toml)).toBe('7777777777777777777777777777777777777777');
  });

  it('does not select a key merely CONTAINING source_sha', () => {
    const toml = ['[build]', 'command_source_sha = "8888888888888888888888888888888888888888"'].join(
      '\n',
    );
    expect(() => selectBuildSourceSha(toml)).toThrow(ReleaseRecordError);
  });

  it('FAILS on a missing [build] section', () => {
    expect(() =>
      selectBuildSourceSha('[wallet_bundle]\nsource_sha = "9999999999999999999999999999999999999999"'),
    ).toThrow(/no \[build\]\.source_sha/);
  });

  it('FAILS on a malformed value — short, uppercase, or non-hex', () => {
    for (const bad of ['abc123', 'AAAA111111111111111111111111111111111111', 'z'.repeat(40), '']) {
      expect(() => selectBuildSourceSha(`[build]\nsource_sha = "${bad}"`), bad).toThrow(
        /not a full 40-hex commit id/,
      );
    }
  });

  it('FAILS rather than guessing when [build].source_sha appears twice', () => {
    const toml = [
      '[build]',
      'source_sha = "1111111111111111111111111111111111111111"',
      'source_sha = "2222222222222222222222222222222222222222"',
    ].join('\n');
    expect(() => selectBuildSourceSha(toml)).toThrow(/more than once/);
  });

  it('FAILS the build when the record cannot be read at all', () => {
    expect(() => releaseDefines('/nonexistent/release_hashes.toml')).toThrow(ReleaseRecordError);
  });

  // THE ANTI-HEAD TEST. The record's build source is the frozen commit F; the
  // commit under test is a later one, so an implementation that emitted HEAD
  // would emit a different value. This asserts the injected value tracks the
  // RECORD.
  it('the INJECTED value equals the real record, and is not this checkout HEAD', async () => {
    const recorded = selectBuildSourceSha(RECORD);
    expect(canisterBuildSource()).toBe(recorded);

    const { execFileSync } = await import('node:child_process');
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    }).trim();
    // If these were ever equal the assertion above would not distinguish a
    // record-sourced value from a HEAD-sourced one; the fixture must differ.
    expect(head, 'fixture precondition: HEAD must differ from [build].source_sha').not.toBe(
      recorded,
    );
    expect(canisterBuildSource()).not.toBe(head);
  });

  it('a second valid record value is selected too — the value is not hardcoded', () => {
    const other = 'a'.repeat(40);
    const perturbed = RECORD.replace(
      /^source_sha = "[0-9a-f]{40}"/m,
      `source_sha = "${other}"`,
    );
    expect(selectBuildSourceSha(perturbed)).toBe(other);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D-2 — pin independence: perturbing [wallet_bundle] cannot move a byte.
// ─────────────────────────────────────────────────────────────────────────────

/** Section-aware perturbation of every [wallet_bundle] key. Not a literal
 *  match: the recorded values move whenever the pin is re-measured, and a test
 *  bound to one of them would break on the very commit it exists to vindicate. */
function perturbWalletBundle(toml: string): string {
  let section = '';
  return toml
    .split('\n')
    .map((line) => {
      const sec = /^\[\s*([^\]]+?)\s*\]/.exec(line.trim());
      if (sec !== null) {
        section = sec[1];
        return line;
      }
      if (!(section === 'wallet_bundle' || section.startsWith('wallet_bundle.'))) return line;
      const kv = /^(\s*)([A-Za-z0-9_-]+)(\s*)=(\s*)(.*)$/.exec(line);
      if (kv === null) return line;
      const [, indent, key, sp1, sp2, value] = kv;
      const next = /^"/.test(value)
        ? `"PERTURBED-${key}"`
        : /^(true|false)\b/.test(value)
          ? (value.startsWith('true') ? 'false' : 'true')
          : '987654321';
      return `${indent}${key}${sp1}=${sp2}${next}`;
    })
    .join('\n');
}

describe('J-25 D-2 — the wallet pin cannot change what this site emits', () => {
  it('the selected build source is identical across a perturbed [wallet_bundle]', () => {
    const perturbed = perturbWalletBundle(RECORD);
    expect(perturbed).not.toBe(RECORD);
    expect(perturbed).toContain('"PERTURBED-sha256"');
    expect(perturbed).toContain('"PERTURBED-source_sha"');
    expect(selectBuildSourceSha(perturbed)).toBe(selectBuildSourceSha(RECORD));
  });

  it('moving [build].source_sha DOES move the selection (the test is not vacuous)', () => {
    const moved = RECORD.replace(
      /^source_sha = "[0-9a-f]{40}"/m,
      'source_sha = "' + 'd'.repeat(40) + '"',
    );
    expect(selectBuildSourceSha(moved)).not.toBe(selectBuildSourceSha(RECORD));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D-4 — the schema row comes from the VERIFIED snapshot, or from nothing.
// ─────────────────────────────────────────────────────────────────────────────

function surfaces(): { lookup: (id: string) => PanelSurface; get: (id: string) => PanelSurface } {
  const map = new Map<string, PanelSurface>();
  const lookup = (id: string): PanelSurface => {
    let s = map.get(id);
    if (!s) {
      s = { textContent: '', className: '' };
      map.set(id, s);
    }
    return s;
  };
  return { lookup, get: lookup };
}

describe('J-25 D-4 — monitor snapshot schema row', () => {
  it('renders schema 2 from a verified snapshot', () => {
    const { lookup, get } = surfaces();
    renderReleaseRows(
      buildReleaseRows({ buildSource: 'c'.repeat(40), verifiedSchema: { schemaVersion: 2, stale: false } }),
      lookup,
    );
    expect(get('release-snapshot-schema').textContent).toBe(
      '2 — from the verified monitor snapshot',
    );
    expect(get('release-snapshot-schema').className).toBe('release-verified');
  });

  it('renders schema 3 from a verified snapshot', () => {
    const { lookup, get } = surfaces();
    renderReleaseRows(
      buildReleaseRows({ buildSource: 'c'.repeat(40), verifiedSchema: { schemaVersion: 3, stale: false } }),
      lookup,
    );
    expect(get('release-snapshot-schema').textContent).toBe(
      '3 — from the verified monitor snapshot',
    );
  });

  it('a STALE verified snapshot shows its schema carrying the stale status', () => {
    const { lookup, get } = surfaces();
    renderReleaseRows(
      buildReleaseRows({ buildSource: 'c'.repeat(40), verifiedSchema: { schemaVersion: 3, stale: true } }),
      lookup,
    );
    expect(get('release-snapshot-schema').textContent).toMatch(/^3 — .*STALE/);
    expect(get('release-snapshot-schema').className).toBe('release-stale');
  });

  it('no verified snapshot means NO schema label', () => {
    const { lookup, get } = surfaces();
    renderReleaseRows(buildReleaseRows({ buildSource: 'c'.repeat(40), verifiedSchema: null }), lookup);
    expect(get('release-snapshot-schema').textContent).toBe(
      'no currently verified snapshot — no schema to report',
    );
    expect(get('release-snapshot-schema').className).toBe('release-unavailable');
  });

  it('circuit version / VK hash is PRESENT and explicitly not attested here', () => {
    const { lookup, get } = surfaces();
    renderReleaseRows(buildReleaseRows({ buildSource: 'c'.repeat(40), verifiedSchema: null }), lookup);
    expect(get('release-circuit').textContent).toBe(
      'not attested by this snapshot; see app.stsh.fi',
    );
  });

  it('the build source row never says "signed"', () => {
    const rows = buildReleaseRows({ buildSource: 'c'.repeat(40), verifiedSchema: null });
    const row = rows.find((r) => r.label === 'Canister build source');
    expect(row?.trust).toContain('committed release record');
    expect(JSON.stringify(rows)).not.toMatch(/signed/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D-5 (website half) — the LIVE page, through refresh().
// ─────────────────────────────────────────────────────────────────────────────

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

function installDom(search = '?monitor=aaaaa-aa'): void {
  cells = new Map();
  (globalThis as Record<string, unknown>).document = {
    getElementById(id: string) {
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

function okRead(fields: FixtureFields = {}): VerifiedRead {
  return {
    certificateVerified: true,
    canonicalBytes: canonical({ schemaVersion: 3, ...fields }),
    certTimeNs: T0 + 1_000_000_000n,
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

describe('J-25 D-5 — the deployed page paints the release panel', () => {
  // Removing `paintRelease(...)` from refresh() leaves every one of these cells
  // at its initial '' and fails here.
  it('paints all three rows on a successful read', async () => {
    await refresh();
    expect(cell('release-build-source').textContent).toBe(
      `${selectBuildSourceSha(RECORD)} — from the committed release record; ` +
        'this is the canister build source, not the UI commit',
    );
    expect(cell('release-snapshot-schema').textContent).toBe(
      '3 — from the verified monitor snapshot',
    );
    expect(cell('release-circuit').textContent).toBe(
      'not attested by this snapshot; see app.stsh.fi',
    );
  });

  it('reports schema 2 when the monitor still emits schema 2', async () => {
    nextRead.value = okRead({ schemaVersion: 2 });
    await refresh();
    expect(cell('release-snapshot-schema').textContent).toBe(
      '2 — from the verified monitor snapshot',
    );
  });

  it('an unknown schema is rejected and leaves NO schema label', async () => {
    nextRead.value = okRead({ schemaVersion: 4 });
    await refresh();
    expect(cell('release-snapshot-schema').textContent).toBe(
      'no currently verified snapshot — no schema to report',
    );
    expect(cell('badge').className).toBe('badge unknown');
  });

  // THE CLEARING TEST (SSA addendum B / D). A success followed by a certificate
  // failure must not leave the earlier schema standing as a current claim.
  it('CLEARS a previously verified schema when the certificate then fails', async () => {
    await refresh();
    expect(cell('release-snapshot-schema').textContent).toBe(
      '3 — from the verified monitor snapshot',
    );

    nextRead.value = {
      certificateVerified: false,
      canonicalBytes: null,
      certTimeNs: null,
      failureDetail: 'certificate did not verify',
    } as VerifiedRead;
    await refresh();
    expect(cell('release-snapshot-schema').textContent).toBe(
      'no currently verified snapshot — no schema to report',
    );
  });

  it('CLEARS the schema when the monitor becomes unreachable', async () => {
    await refresh();
    nextRead.throws = new Error('monitor unreachable');
    await refresh();
    expect(cell('release-snapshot-schema').textContent).toBe(
      'no currently verified snapshot — no schema to report',
    );
  });

  it('a STALE but verified snapshot keeps its schema WITH the stale status', async () => {
    nextRead.value = {
      certificateVerified: true,
      canonicalBytes: canonical({ schemaVersion: 3, maxStalenessNs: 1n }),
      certTimeNs: T0 + 1_000_000_000n,
      failureDetail: null,
    } as VerifiedRead;
    await refresh();
    expect(cell('release-snapshot-schema').textContent).toMatch(/^3 — .*STALE/);
    expect(cell('release-snapshot-schema').className).toBe('release-stale');
  });

  it('paints the build source even with NO monitor configured', async () => {
    installDom('');
    await refresh();
    expect(cell('badge').textContent).toBe('NOT CONFIGURED');
    expect(cell('release-build-source').textContent).toContain(selectBuildSourceSha(RECORD));
    expect(cell('release-snapshot-schema').textContent).toBe(
      'no currently verified snapshot — no schema to report',
    );
  });

  // The seam cannot drift onto ids the deployed page does not have.
  it('every id the panel writes exists in the real index.html', () => {
    for (const id of ['release-build-source', 'release-snapshot-schema', 'release-circuit']) {
      expect(INDEX_HTML, `#${id} missing from index.html`).toContain(`id="${id}"`);
    }
  });
});
