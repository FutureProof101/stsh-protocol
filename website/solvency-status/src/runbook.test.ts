// =============================================================================
// R-4 AC-10 — the page-first deploy-state table lives in the IN-REPO runbook.
//
// PORTABILITY IS THE POINT (brief §0.2 RED-1, the Owner's rule): this test
// reads `MAINNET_DEPLOYMENT.md` and NOTHING ELSE. No packet, no review, no
// office path, absolute or relative. It runs in a clean checkout on a host with
// no office mount. The packet's separate deployment-time attestation — what the
// LIVE page's accepted set actually was at each step — is human-verified prose
// and is deliberately not an input here.
// =============================================================================

import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ANCHOR = '## Solvency surface: schema-3 transition (R-4)';

/** src/ -> package -> website/ -> repo root */
const RUNBOOK_PATH = fileURLToPath(new URL('../../../MAINNET_DEPLOYMENT.md', import.meta.url));

let runbook: string;
let section: string;

beforeAll(() => {
  runbook = readFileSync(RUNBOOK_PATH, 'utf8');
  const start = runbook.indexOf(ANCHOR);
  // Section runs to the next top-level heading, or to EOF.
  const rest = start >= 0 ? runbook.slice(start + ANCHOR.length) : '';
  const next = rest.indexOf('\n## ');
  section = next >= 0 ? rest.slice(0, next) : rest;
});

describe('MAINNET_DEPLOYMENT.md — schema-3 transition table (AC-10)', () => {
  it('carries the anchor heading verbatim (M10)', () => {
    expect(runbook).toContain(ANCHOR);
  });

  // Row label -> the EXACT accepted-schema literal that row must carry.
  // These are value assertions, not presence assertions: swapping the first two
  // rows' values (M10c) must fail, not merely look different.
  const ROWS: Array<[label: string, accepts: string]> = [
    ['before (today)', '`{2}`'],
    ['after page deploy, before monitor cutover', '`{2,3}`'],
    ['after monitor deploy (cutover)', '`{2,3}`'],
    ['after v2-retirement cleanup', '`{3}`'],
  ];

  for (const [label, accepts] of ROWS) {
    it(`row "${label}" states live page accepts ${accepts} (M10c)`, () => {
      const row = section
        .split('\n')
        .find((line) => line.startsWith('|') && line.includes(label));
      expect(row, `no table row labelled "${label}"`).toBeTruthy();
      // Cell 2 of | label | accepts | emits | outcome |
      const cells = row!.split('|').map((c) => c.trim());
      expect(cells[2]).toContain(accepts);
      // ...and the "before" row must NOT claim the dual-accept set, nor the
      // "after page deploy" row the v2-only set. Guards the exact swap M10c
      // performs, which a `toContain` on `{2}` alone would not catch, since
      // `{2,3}` contains no `{2}` substring but a sloppier assertion might.
      if (accepts === '`{2}`') expect(cells[2]).not.toContain('{2,3}');
      if (accepts === '`{3}`') expect(cells[2]).not.toContain('{2');
    });
  }

  it('all four rows are present, and only those four', () => {
    const dataRows = section
      .split('\n')
      .filter((l) => l.startsWith('|') && !l.includes('---') && !l.includes('deploy step'));
    expect(dataRows).toHaveLength(4);
  });

  it("the section's prose states the order is page-first (M10b)", () => {
    expect(section).toContain('page-first');
    // The reverse must not be asserted anywhere in the section.
    expect(section).not.toMatch(/monitor-first(?![^.]*never| cutover therefore)/);
  });

  it('names the reason (a v2-only page rejects v3 bytes structurally)', () => {
    expect(section).toMatch(/v2[- ]only page rejects/i);
    expect(section).toContain('verify.test.ts');
  });

  it('names the follow-up cleanup lane that retires v2 acceptance', () => {
    expect(section).toMatch(/v2-acceptance retirement/i);
  });

  it('reads no file outside the repository', () => {
    // The only path this module opens, asserted as a repository-relative fact.
    expect(RUNBOOK_PATH.endsWith('/MAINNET_DEPLOYMENT.md')).toBe(true);
    const source = readFileSync(fileURLToPath(import.meta.url), 'utf8');
    expect(source).not.toMatch(/\/mnt\/|Documents\/|reviews\/|Briefs\//);
  });
});
