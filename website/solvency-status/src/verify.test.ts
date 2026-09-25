// Unit tests for the pure verification module — the fail-closed rules are the
// load-bearing part of the page. The byte fixtures mirror the canister's
// canonical encoding EXACTLY (see CERTIFIED_SNAPSHOT_ENCODING.md); the same
// layout is independently asserted against the live canister in
// integration-tests/tests/smoke_alarm_monitor_tests.rs (test_sam_02).

import { describe, expect, it } from 'vitest';
import {
  decodeLeb128,
  deriveDisplayState,
  formatStsh,
  parseCanonicalSnapshot,
  SnapshotStatus,
  SourceReadStatus,
} from './verify';
import { canonical, type FixtureFields, E8S_1E17, T0 } from './canonicalFixture';

describe('parseCanonicalSnapshot', () => {
  it('round-trips a healthy snapshot', () => {
    const s = parseCanonicalSnapshot(canonical());
    expect(s.schemaVersion).toBe(2);
    expect(s.status).toBe(SnapshotStatus.Fresh);
    expect(s.supplyInvariantHolds).toBe(true);
    expect(s.healthy).toBe(true);
    expect(s.fixedMaxSupplyE8s).toBe(E8S_1E17);
    expect(s.sumAllBalancesE8s).toBe(E8S_1E17);
    expect(s.poolBalanceE8s).toBe(123_456_789n);
    expect(s.refreshedAtNs).toBe(T0);
    expect(s.maxStalenessNs).toBe(900_000_000_000n);
    // v2 fields round-trip too.
    expect(s.poolAttestationSourceStatus).toBe(SourceReadStatus.Ok);
    expect(s.poolDeltaHealthy).toBe(true);
    expect(s.poolPublicDeltaE8s).toBe(0n);
    expect(s.poolAttestedAtNs % 300_000_000_000n).toBe(0n);
    expect(s.treasuryReadStatus).toBe(SourceReadStatus.Ok);
    expect(s.treasuryStrayFundsE8s).toBe(0n);
  });

  it('decodes a negative pool delta as two\'s complement', () => {
    const s = parseCanonicalSnapshot(canonical({ poolDeltaHealthy: false, poolPublicDeltaE8s: -4_242n }));
    expect(s.poolPublicDeltaE8s).toBe(-4_242n);
    expect(s.poolDeltaHealthy).toBe(false);
  });

  it('rejects a POSITIVE pool delta — the clamp guarantees <= 0', () => {
    expect(() => parseCanonicalSnapshot(canonical({ poolPublicDeltaE8s: 1n }))).toThrow(
      /never be positive/,
    );
  });

  it('rejects an unknown source read status', () => {
    expect(() => parseCanonicalSnapshot(canonical({ poolAttestationSourceStatus: 9 }))).toThrow(
      /unknown source read status/,
    );
  });

  it('REJECTS v1 bytes — both length and schema_version fail closed', () => {
    // A v1 leaf is 89 bytes: the length check fires first, and a v1-length
    // buffer padded to 131 still carries schema_version 1.
    const v1 = canonical().subarray(0, 89);
    expect(() => parseCanonicalSnapshot(v1)).toThrow(/131 bytes/);
    expect(() => parseCanonicalSnapshot(canonical({ schemaVersion: 1 }))).toThrow(
      /unsupported schema_version 1/,
    );
  });

  it('rejects wrong length', () => {
    expect(() => parseCanonicalSnapshot(canonical().subarray(0, 130))).toThrow(/131 bytes/);
  });

  it('rejects a wrong domain tag', () => {
    const bytes = canonical();
    bytes[0] ^= 0xff;
    expect(() => parseCanonicalSnapshot(bytes)).toThrow(/domain tag/);
  });

  it('rejects an unknown schema version — 4 and above, unconditionally', () => {
    // AC-7 M7a/M7c: schema 3 is now ACCEPTED, so this assertion moves to 4.
    // There is no v4 encoding defined; accepting one would silently parse an
    // unknown future layout under v3's rules.
    expect(() => parseCanonicalSnapshot(canonical({ schemaVersion: 4 }))).toThrow(
      /schema_version/,
    );
    expect(() => parseCanonicalSnapshot(canonical({ schemaVersion: 99 }))).toThrow(
      /schema_version/,
    );
  });

  it('rejects an unknown status byte', () => {
    const bytes = canonical();
    bytes[23] = 9;
    expect(() => parseCanonicalSnapshot(bytes)).toThrow(/status/);
  });

  it('rejects reserved flag bits', () => {
    // AC-8 M8a: under SCHEMA 2 the first reserved bit is still bit 4.
    const bytes = canonical();
    // v2 claimed bits 2 and 3 (pool_delta_healthy, stray-funds present), so the
    // first genuinely reserved bit is now bit 4. Probing 0b100 here would test
    // nothing — it is a real field.
    bytes[24] |= 0b10000;
    expect(() => parseCanonicalSnapshot(bytes)).toThrow(/flag/);
  });
});

describe('deriveDisplayState — fail-closed rules', () => {
  const freshInput = (fields: FixtureFields = {}, certOffsetNs = 60_000_000_000n) => ({
    certificateVerified: true,
    canonicalBytes: canonical(fields),
    certTimeNs: T0 + certOffsetNs,
  });

  it('green only when everything holds', () => {
    const state = deriveDisplayState(freshInput());
    expect(state.light).toBe('green');
    expect(state.reasons).toEqual([]);
    expect(state.ageNs).toBe(60_000_000_000n);
  });

  it('unknown when the certificate did not verify — never trust bare data', () => {
    const state = deriveDisplayState({
      certificateVerified: false,
      canonicalBytes: canonical(),
      certTimeNs: T0,
    });
    expect(state.light).toBe('unknown');
    expect(state.snapshot).toBeNull();
  });

  it('unknown when the snapshot is stale relative to the SIGNED cert time', () => {
    // cert time 16 minutes after refresh, staleness bound 15 minutes.
    const state = deriveDisplayState(freshInput({}, 960_000_000_000n));
    expect(state.light).toBe('unknown');
    expect(state.reasons.join(' ')).toMatch(/stale/);
  });

  it('red when the supply invariant is violated', () => {
    const state = deriveDisplayState(
      freshInput({ supplyInvariantHolds: false, healthy: false }),
    );
    expect(state.light).toBe('red');
    expect(state.reasons.join(' ')).toMatch(/invariant/);
  });

  it('red when the monitor could not read its sources', () => {
    const state = deriveDisplayState(
      freshInput({ status: SnapshotStatus.SourceCallFailed, supplyInvariantHolds: false, healthy: false }),
    );
    expect(state.light).toBe('red');
    expect(state.reasons.join(' ')).toMatch(/SourceCallFailed/);
  });

  it('red when the healthy flag contradicts its own definition', () => {
    const state = deriveDisplayState(
      freshInput({ status: SnapshotStatus.RefreshFailed, healthy: true }),
    );
    expect(state.light).toBe('red');
    expect(state.reasons.join(' ')).toMatch(/inconsistent/);
  });

  it('unknown when verified data is incomplete', () => {
    const state = deriveDisplayState({
      certificateVerified: true,
      canonicalBytes: null,
      certTimeNs: T0,
    });
    expect(state.light).toBe('unknown');
  });

  // ── S-a (CC-04): the two RED branches the page exists for ────────────────
  //
  // These were UNBOUND at base: deleting verify.ts's entire pool block left the
  // suite green, because the only test in the neighbourhood exercised the
  // SnapshotStatus branch instead. Assertions below are on the REASON TEXT and
  // the light — never on `reasons.length` — so a different reason firing for a
  // different cause cannot satisfy them.

  it('red, naming the reason, when the pool attestation is not proven (AC-1)', () => {
    // Everything else healthy; ONE field varied.
    const state = deriveDisplayState(
      freshInput({ poolAttestationSourceStatus: SourceReadStatus.CallFailed }),
    );
    expect(state.light).toBe('red');
    expect(state.reasons.join(' | ')).toMatch(/attestation not proven/);
    expect(state.reasons.join(' | ')).toMatch(/CallFailed/);
  });

  it('red, naming the SHORTFALL AMOUNT, when the pool backing is broken (AC-2)', () => {
    const shortfallE8s = 4_200_000_000n; // 42 STSH
    const state = deriveDisplayState(
      freshInput({
        poolAttestationSourceStatus: SourceReadStatus.Ok,
        poolDeltaHealthy: false,
        poolPublicDeltaE8s: -shortfallE8s,
      }),
    );
    expect(state.light).toBe('red');
    const joined = state.reasons.join(' | ');
    expect(joined).toMatch(/POOL BACKING BROKEN — shortfall/);
    // VALUE-LEVEL (M2b): the magnitude must actually be in the text. A reason
    // that says only "backing broken" tells a reader nothing they can check.
    expect(joined).toContain(formatStsh(shortfallE8s));
  });

  // ── S-b / AC-4: the YELLOW channel never moves the badge ─────────────────

  it('stays GREEN with stray treasury funds — yellow is not a badge state (AC-4)', () => {
    const state = deriveDisplayState(freshInput({ treasuryStrayFundsE8s: 777_000_000n }));
    expect(state.light).toBe('green');
    expect(state.reasons).toEqual([]);
    expect(state.treasury).toEqual({ kind: 'stray', amountE8s: 777_000_000n });
  });

  it('stays GREEN when the treasury read FAILED — unknown is yellow too (AC-4)', () => {
    const state = deriveDisplayState(
      freshInput({ treasuryReadStatus: SourceReadStatus.CallFailed }),
    );
    expect(state.light).toBe('green');
    expect(state.reasons).toEqual([]);
    // null, never 0 — a zero standing in for "could not tell" is the exact
    // conflation D-4 forbids.
    expect(state.treasury).toEqual({ kind: 'unknown', amountE8s: null });
  });

  it('derives treasury `none` from an Ok read of zero', () => {
    const state = deriveDisplayState(freshInput());
    expect(state.treasury).toEqual({ kind: 'none', amountE8s: 0n });
  });

  it('reports treasury `unknown` when there is no parsed snapshot at all', () => {
    const state = deriveDisplayState({
      certificateVerified: false,
      canonicalBytes: canonical(),
      certTimeNs: T0,
    });
    expect(state.treasury).toEqual({ kind: 'unknown', amountE8s: null });
  });

  // ── S-c / AC-5: UNAVAILABLE is a DIFFERENT claim from VIOLATED ───────────

  it('red with the UNAVAILABLE reason when bit 4 is set under schema 3 (AC-5)', () => {
    const state = deriveDisplayState(
      freshInput({
        schemaVersion: 3,
        supplyInvariantUnavailable: true,
        supplyInvariantHolds: false,
        healthy: false,
      }),
    );
    expect(state.light).toBe('red');
    const joined = state.reasons.join(' | ');
    expect(joined).toMatch(/could not be computed/);
    // The two claims are mutually exclusive: saying both would be incoherent.
    expect(joined).not.toMatch(/NOT proven to hold/);
  });

  it('red with the VIOLATED reason when bit 4 is CLEAR and the invariant is false (AC-5)', () => {
    const state = deriveDisplayState(
      freshInput({
        schemaVersion: 3,
        supplyInvariantUnavailable: false,
        supplyInvariantHolds: false,
        healthy: false,
      }),
    );
    expect(state.light).toBe('red');
    const joined = state.reasons.join(' | ');
    expect(joined).toMatch(/NOT proven to hold/);
    expect(joined).not.toMatch(/could not be computed/);
  });

  it('UNAVAILABLE is RED, never green and never unknown — fail closed', () => {
    // Fresh, in-bound, certificate-verified: the ONLY thing wrong is bit 4.
    const state = deriveDisplayState(
      freshInput({ schemaVersion: 3, supplyInvariantUnavailable: true }),
    );
    expect(state.light).toBe('red');
  });

  it('unknown when the canonical bytes fail to parse', () => {
    const bytes = canonical();
    bytes[0] ^= 0xff;
    const state = deriveDisplayState({
      certificateVerified: true,
      canonicalBytes: bytes,
      certTimeNs: T0,
    });
    expect(state.light).toBe('unknown');
    expect(state.reasons.join(' ')).toMatch(/parse/);
  });
});

describe('decodeLeb128', () => {
  it('decodes single-byte values', () => {
    expect(decodeLeb128(new Uint8Array([0x00]))).toBe(0n);
    expect(decodeLeb128(new Uint8Array([0x7f]))).toBe(127n);
  });

  it('decodes multi-byte values', () => {
    expect(decodeLeb128(new Uint8Array([0xe5, 0x8e, 0x26]))).toBe(624485n);
  });

  it('rejects unterminated encodings', () => {
    expect(() => decodeLeb128(new Uint8Array([0x80, 0x80]))).toThrow(/unterminated/);
  });
});

describe('formatStsh', () => {
  it('formats whole and fractional amounts', () => {
    expect(formatStsh(100_000_000n)).toBe('1');
    expect(formatStsh(E8S_1E17)).toBe('1,000,000,000');
    expect(formatStsh(123_456_789n)).toBe('1.23456789');
    expect(formatStsh(150_000_000n)).toBe('1.5');
    expect(formatStsh(0n)).toBe('0');
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// AC-7 / AC-8 — the schema-2 → schema-3 transition, both directions
//
// The page DUAL-ACCEPTS 2 and 3 so the deploy can be PAGE-FIRST: the new page
// goes live, then the monitor cuts over. Each version carries its OWN reserved
// mask, so a schema-2 header with a schema-3 flag byte (an inconsistent monitor
// build) is still refused.
// ─────────────────────────────────────────────────────────────────────────────
describe('schema transition — dual-accept, page-first', () => {
  it('parses SCHEMA 2 bytes with supplyInvariantUnavailable hard-set false (AC-7)', () => {
    const s = parseCanonicalSnapshot(canonical({ schemaVersion: 2 }));
    expect(s.schemaVersion).toBe(2);
    // Not "unknown": at schema 2 the field does not exist and is not
    // reportable. This is the one narrowing the transition accepts, and the
    // reason the v2-retirement cleanup lane exists.
    expect(s.supplyInvariantUnavailable).toBe(false);
  });

  it('parses SCHEMA 3 bytes WITH bit 4 as unavailable === true (AC-7)', () => {
    const s = parseCanonicalSnapshot(
      canonical({ schemaVersion: 3, supplyInvariantUnavailable: true }),
    );
    expect(s.schemaVersion).toBe(3);
    expect(s.supplyInvariantUnavailable).toBe(true);
  });

  it('parses SCHEMA 3 bytes WITHOUT bit 4 as unavailable === false (AC-7)', () => {
    const s = parseCanonicalSnapshot(
      canonical({ schemaVersion: 3, supplyInvariantUnavailable: false }),
    );
    expect(s.schemaVersion).toBe(3);
    expect(s.supplyInvariantUnavailable).toBe(false);
  });

  it('REFUSES bit 4 under a schema-2 header — inconsistent monitor build (AC-7 M7b)', () => {
    // A monitor that sets the new flag but forgets to bump its schema byte.
    // The v2 mask is still load-bearing: the bump is real, not cosmetic.
    expect(() =>
      parseCanonicalSnapshot(canonical({ schemaVersion: 2, supplyInvariantUnavailable: true })),
    ).toThrow(/flag/);
  });

  it('rejects reserved bit 5 under SCHEMA 3 (AC-8 M8b)', () => {
    const bytes = canonical({ schemaVersion: 3 });
    bytes[24] |= 0b100000;
    expect(() => parseCanonicalSnapshot(bytes)).toThrow(/flag/);
  });

  it('accepts bit 4 under SCHEMA 3 — the v3 mask must NOT reject its own bit', () => {
    const bytes = canonical({ schemaVersion: 3, supplyInvariantUnavailable: true });
    expect(() => parseCanonicalSnapshot(bytes)).not.toThrow();
  });

  it('a FROZEN v2-shape parser rejects v3 bytes — why the deploy is page-first (AC-7)', () => {
    // This is the CURRENTLY-LIVE page's behaviour, reproduced here as a frozen
    // fixture rather than described in prose: mask = reject any of bits 4-7,
    // accepted schema = {2} only. Run against a schema-3 leaf with bit 4 set it
    // THROWS, naming the version or the flag.
    //
    // That is exactly what every reader of reserves.stsh.fi would see if the
    // monitor were switched to schema 3 before this page was redeployed — which
    // is why MAINNET_DEPLOYMENT.md's transition table is page-first.
    const frozenV2Parse = (bytes: Uint8Array): void => {
      const version =
        (bytes[19] << 24) | (bytes[20] << 16) | (bytes[21] << 8) | bytes[22];
      if (version !== 2) throw new Error(`unsupported schema_version ${version}`);
      if ((bytes[24] & ~0b1111) !== 0) throw new Error(`reserved flag bits set: ${bytes[24]}`);
    };
    const v3Bytes = canonical({ schemaVersion: 3, supplyInvariantUnavailable: true });
    expect(() => frozenV2Parse(v3Bytes)).toThrow(/schema_version|flag/);
    // ...and it still accepts the schema-2 leaf the monitor emits today, so the
    // page-deploy step alone is safe in both directions.
    expect(() => frozenV2Parse(canonical({ schemaVersion: 2 }))).not.toThrow();
  });
});
